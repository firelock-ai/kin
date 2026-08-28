// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kin_blobs::{BlobError, BlobStore};
use kin_core::KinLayout;
use kin_db::{
    LocalFileBackend, LocalRepositoryAuthorityFreeze, RepositoryAuthorityManager, StorageBackend,
};
use kin_model::ChangeStore;
use kin_model::{
    EntityId, EntityStore, FilePathId, Hash256, OperationId, RepoPath, RepositoryCommitReceipt,
    RepositoryId, ResolvedTree, SemanticChange, SemanticChangeId, TransactionDelta, TreeEntry,
    WorkspaceId,
};
use kin_projection::ProjectionState;
use kin_reconcile::Reconciler;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::error::{DaemonError, Result};
use crate::session_registry::SessionCoordinator;

/// Borrowed immutable history used to materialize a hosted repository ref.
///
/// Repository-v6 snapshots intentionally leave their top-level graph domains
/// empty. `ChangeStore::resolve_graph_at` needs only `get_change`, so borrowing
/// the admitted change map avoids cloning the payload-heavy history into a
/// throwaway graph before every hosted load.
struct HostedAuthorityHistory<'a> {
    changes: &'a HashMap<SemanticChangeId, SemanticChange>,
}

impl HostedAuthorityHistory<'_> {
    fn unsupported(operation: &str) -> kin_db::KinDbError {
        kin_db::KinDbError::StorageError(format!(
            "{operation} is unavailable through a hosted authority materialization view"
        ))
    }
}

impl ChangeStore for HostedAuthorityHistory<'_> {
    type Error = kin_db::KinDbError;

    fn get_change(
        &self,
        id: &SemanticChangeId,
    ) -> std::result::Result<Option<SemanticChange>, Self::Error> {
        Ok(self.changes.get(id).cloned())
    }

    fn get_entity_history(
        &self,
        _id: &EntityId,
    ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
        Err(Self::unsupported("entity history"))
    }

    fn find_merge_bases(
        &self,
        _a: &SemanticChangeId,
        _b: &SemanticChangeId,
    ) -> std::result::Result<Vec<SemanticChangeId>, Self::Error> {
        Err(Self::unsupported("merge-base search"))
    }

    fn create_change(&self, _change: &SemanticChange) -> std::result::Result<(), Self::Error> {
        Err(Self::unsupported("change creation"))
    }

    fn get_changes_since(
        &self,
        _base: &SemanticChangeId,
        _head: &SemanticChangeId,
    ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
        Err(Self::unsupported("change-range listing"))
    }
}

fn hosted_materialization_error(detail: impl Into<String>) -> kin_db::KinDbError {
    kin_db::KinDbError::StorageError(detail.into())
}

/// Choose the replicated query view for a hosted repository.
///
/// Hosted replicas do not transfer a source workspace. The explicit default
/// ref is the one repository-scoped view every replica does share. An unborn
/// repository has no refs and materializes empty; once any ref exists, missing
/// or dangling default-ref authority is refused rather than replaced with an
/// invented branch choice.
pub(crate) fn select_repository_default_ref(
    metadata: &kin_db::PersistedRepositoryAuthority,
) -> std::result::Result<Option<&kin_model::RepositoryRef>, kin_db::KinDbError> {
    if metadata.ref_state.refs.is_empty() {
        return Ok(None);
    }
    let default_ref = metadata.ref_state.default_ref.as_ref().ok_or_else(|| {
        hosted_materialization_error(format!(
            "repository {} has refs but no persisted default ref",
            metadata.repository_id
        ))
    })?;
    metadata
        .ref_state
        .refs
        .iter()
        .find(|repository_ref| &repository_ref.name == default_ref)
        .map(Some)
        .ok_or_else(|| {
            hosted_materialization_error(format!(
                "repository {} default ref {} is absent from persisted refs",
                metadata.repository_id, default_ref
            ))
        })
}

/// Resolve a persisted ref target using only the authority envelope admitted
/// with the snapshot. No Git checkout, object directory, or file projection is
/// consulted.
pub(crate) fn resolve_repository_target(
    metadata: &kin_db::PersistedRepositoryAuthority,
    target: &kin_model::RefTarget,
) -> std::result::Result<SemanticChangeId, kin_db::KinDbError> {
    let mut target = target.clone();
    let mut seen_refs = HashSet::new();
    loop {
        match target {
            kin_model::RefTarget::Change { change_id } => return Ok(change_id),
            kin_model::RefTarget::Symbolic { target: name } => {
                if !seen_refs.insert(name.clone()) {
                    return Err(hosted_materialization_error(format!(
                        "hosted repository ref cycle reaches {name}"
                    )));
                }
                target = metadata
                    .ref_state
                    .refs
                    .iter()
                    .find(|repository_ref| repository_ref.name == name)
                    .map(|repository_ref| repository_ref.target.clone())
                    .ok_or_else(|| {
                        hosted_materialization_error(format!(
                            "hosted symbolic repository ref target {name} is missing"
                        ))
                    })?;
            }
            kin_model::RefTarget::ExternalObject { object } => {
                let mut current = object;
                let mut seen_objects = HashSet::new();
                while current.kind == kin_model::ExternalObjectKind::Tag {
                    if !seen_objects.insert(current) {
                        return Err(hosted_materialization_error(format!(
                            "hosted Git authority contains an annotated-tag cycle through {}",
                            current.oid
                        )));
                    }
                    let authority = metadata.git_external_authority.as_ref().ok_or_else(|| {
                        hosted_materialization_error(format!(
                            "hosted external tag {} has no persisted Git authority for exact peeling",
                            current.oid
                        ))
                    })?;
                    let entry = authority
                        .closure
                        .objects
                        .iter()
                        .find(|entry| entry.record.object == current)
                        .ok_or_else(|| {
                            hosted_materialization_error(format!(
                                "hosted external tag {} is absent from persisted Git authority",
                                current.oid
                            ))
                        })?;
                    let mut targets = entry.dependencies.iter().filter_map(|dependency| {
                        (dependency.kind == kin_model::GitObjectDependencyKind::TagTarget)
                            .then_some(dependency.target)
                    });
                    current = targets.next().ok_or_else(|| {
                        hosted_materialization_error(format!(
                            "hosted external tag {} has no exact target",
                            entry.record.object.oid
                        ))
                    })?;
                    if targets.next().is_some() {
                        return Err(hosted_materialization_error(format!(
                            "hosted external tag {} has multiple exact targets",
                            entry.record.object.oid
                        )));
                    }
                }
                if current.kind != kin_model::ExternalObjectKind::Commit {
                    return Err(hosted_materialization_error(format!(
                        "hosted repository ref target {:?} {} does not peel to a commit",
                        current.kind, current.oid
                    )));
                }
                return metadata
                    .aliases
                    .iter()
                    .find(|alias| alias.oid == current.oid)
                    .map(|alias| alias.change_id)
                    .ok_or_else(|| {
                        hosted_materialization_error(format!(
                            "hosted external commit {} has no semantic change alias",
                            current.oid
                        ))
                    });
            }
        }
    }
}

/// Convert one raw repository-v6 authority snapshot into the non-authoritative
/// graph its default ref names.
///
/// The durable authority keeps immutable semantic history and deliberately
/// requires its top-level entity, relation, tree, and revision caches to be
/// empty. Every hosted authority-to-query conversion must pass through this
/// helper, or a valid transfer presents as a zero-entity repository.
fn materialize_hosted_repository_snapshot(
    mut snapshot: kin_db::GraphSnapshot,
) -> Result<(kin_db::GraphSnapshot, Option<SemanticChangeId>)> {
    let Some(metadata) = snapshot.repository_authority.as_ref() else {
        // Envelope-free hosted snapshots predate repository-v6 and own their
        // top-level graph directly. Preserve that compatibility path exactly.
        return Ok((snapshot, None));
    };

    let selected = select_repository_default_ref(metadata)
        .map_err(DaemonError::Graph)?
        .cloned();
    let (resolved, head) = match selected {
        Some(repository_ref) => {
            let head = resolve_repository_target(metadata, &repository_ref.target)
                .map_err(DaemonError::Graph)?;
            let resolved = HostedAuthorityHistory {
                changes: &snapshot.changes,
            }
            .resolve_graph_at(&head)
            .map_err(DaemonError::Graph)?;
            (Some(resolved), Some(head))
        }
        None => (None, None),
    };

    match resolved {
        Some(resolved) => {
            snapshot.entities = resolved.entities;
            snapshot.relations = resolved.relations;
            snapshot.entity_revisions = resolved.entity_revisions;
            snapshot.resolved_tree = resolved.tree;
            snapshot.external_references = resolved.external_references;
        }
        None => {
            snapshot.entities.clear();
            snapshot.relations.clear();
            snapshot.entity_revisions.clear();
            snapshot.resolved_tree = ResolvedTree::default();
            snapshot.external_references.clear();
        }
    }
    snapshot.outgoing.clear();
    snapshot.incoming.clear();
    // This is a derived ref view. Publication authority remains owned by the
    // storage manager and must never be serialized back out of the query graph.
    snapshot.repository_authority = None;
    Ok((snapshot, head))
}

/// Read-only overlay used to resolve the complete source tree an incoming
/// change would create without first inserting that change into graph
/// authority. The default `ChangeStore` replay then applies the same
/// topological and merge-parent semantics as a committed change.
#[cfg(test)]
struct ProspectiveChangeStore<'a> {
    graph: &'a kin_db::InMemoryGraph,
    incoming: &'a SemanticChange,
}

#[cfg(test)]
impl ChangeStore for ProspectiveChangeStore<'_> {
    type Error = kin_db::KinDbError;

    fn get_entity_history(
        &self,
        id: &EntityId,
    ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
        self.graph.get_entity_history(id)
    }

    fn find_merge_bases(
        &self,
        a: &SemanticChangeId,
        b: &SemanticChangeId,
    ) -> std::result::Result<Vec<SemanticChangeId>, Self::Error> {
        self.graph.find_merge_bases(a, b)
    }

    fn create_change(&self, _change: &SemanticChange) -> std::result::Result<(), Self::Error> {
        Err(kin_db::KinDbError::StorageError(
            "prospective exact-source replay is read-only".to_string(),
        ))
    }

    fn get_change(
        &self,
        id: &SemanticChangeId,
    ) -> std::result::Result<Option<SemanticChange>, Self::Error> {
        if *id == self.incoming.id {
            Ok(Some(self.incoming.clone()))
        } else {
            self.graph.get_change(id)
        }
    }

    fn get_changes_since(
        &self,
        base: &SemanticChangeId,
        head: &SemanticChangeId,
    ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
        self.graph.get_changes_since(base, head)
    }
}

/// Reconciliation loop status values.
pub const RECON_IDLE: u8 = 0;
pub const RECON_PROCESSING: u8 = 1;
/// The background-work supervisor stopped the reconcile pass and the loop is
/// parked: no admission runs until a daemon restart, while the daemon itself
/// keeps serving. Distinct from `RECON_IDLE` so status surfaces report the
/// stop instead of describing a stopped loop as merely quiet.
pub const RECON_PARKED: u8 = 2;

/// Flush a directory entry after an atomic namespace update where the host
/// supports opening directories as files. Windows rejects
/// `std::fs::File::open(directory)` with ERROR_ACCESS_DENIED, so attempting the
/// Unix durability primitive there prevents an otherwise healthy persisted
/// graph from reopening at all. The file payload is still flushed before its
/// atomic rename on every platform; only the stronger parent-directory power-
/// loss guarantee is Unix-specific.
#[cfg(unix)]
fn sync_directory_metadata(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::File::open(path).and_then(|directory| directory.sync_all())
}

#[cfg(not(unix))]
fn sync_directory_metadata(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// On-disk home for in-flight MCP transactions.
///
/// Lives under `.kin/` (not the working tree), so it is never reconciled or
/// committed. The in-memory `DaemonState::mcp_transactions` is the live copy;
/// this file is its durable mirror so a daemon restart mid-transaction does not
/// silently drop staged-but-uncommitted work — stdio-MCP and HTTP-MCP then
/// behave identically across a restart, not just across HTTP calls.
pub(crate) fn mcp_transactions_disk_path(layout: &KinLayout) -> std::path::PathBuf {
    layout.root().join("mcp_transactions.json")
}

/// Wall-clock cost of each blocking phase of a daemon open.
///
/// The API listener does not bind until `open` returns, so this window is the
/// one stretch of a daemon's life in which a client can observe nothing at all
/// and can only wait. Recording the split is what lets a slow open be
/// attributed from a persisted log, on a machine that has since stopped
/// reproducing it, instead of requiring a profiler at the moment it happens.
pub(crate) struct OpenPhases {
    started: Instant,
    phases: Vec<(&'static str, Duration)>,
}

impl OpenPhases {
    pub(crate) fn begin() -> Self {
        Self {
            started: Instant::now(),
            phases: Vec::new(),
        }
    }

    /// Run one phase and retain what it cost. Phases are recorded in completion
    /// order, which is also the order they block startup in.
    pub(crate) fn record<T>(&mut self, phase: &'static str, work: impl FnOnce() -> T) -> T {
        let started = Instant::now();
        let outcome = work();
        self.phases.push((phase, started.elapsed()));
        outcome
    }

    /// Note a phase that was skipped, and why. A skip is as diagnostic as a
    /// cost: an operator comparing two opens of the same repository needs to
    /// see that a phase did not run, not infer it from a missing field.
    pub(crate) fn skipped(&mut self, phase: &'static str) {
        self.phases.push((phase, Duration::ZERO));
    }

    fn breakdown(&self) -> String {
        self.phases
            .iter()
            .map(|(phase, elapsed)| format!("{phase}={}ms", elapsed.as_millis()))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Log what this open cost, and leave the total in the store for the next
    /// spawn to size its idle window against.
    ///
    /// Both from one elapsed reading. Taking the total twice would let the log
    /// and the record disagree by however long the write took, and a persisted
    /// number that does not match the line above it is worse than no number.
    ///
    /// The record is a lifecycle hint, not retrieval authority: it is written
    /// once per open at the end of one, and nothing reads it to answer a query.
    fn emit(&self, repository: &str, layout: &KinLayout) {
        let total_ms = self.started.elapsed().as_millis() as u64;
        info!(
            repository = repository,
            total_ms = total_ms,
            phases = %self.breakdown(),
            "daemon startup phases completed"
        );
        kin_daemon_spawn::record_boot_cost(layout.root(), total_ms);
    }
}

/// Load persisted in-flight MCP transactions on daemon startup. A missing file
/// (clean start) or an unreadable/corrupt one yields an empty set — startup must
/// never fail on transaction-state recovery — but corruption is surfaced loudly
/// in the log so the loss is never silent.
pub(crate) fn load_persisted_mcp_transactions(
    layout: &KinLayout,
) -> HashMap<String, kin_mcp::McpTransaction> {
    let path = mcp_transactions_disk_path(layout);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return HashMap::new(),
        Err(err) => {
            warn!(path = %path.display(), error = %err, "failed to read persisted MCP transactions; starting with none");
            return HashMap::new();
        }
    };
    match serde_json::from_slice::<HashMap<String, kin_mcp::McpTransaction>>(&bytes) {
        Ok(store) => {
            if !store.is_empty() {
                info!(
                    count = store.len(),
                    "restored in-flight MCP transactions from disk across daemon restart"
                );
            }
            store
        }
        Err(err) => {
            warn!(path = %path.display(), error = %err, "persisted MCP transactions are corrupt; starting with none");
            HashMap::new()
        }
    }
}

/// Durably mirror the in-memory MCP transaction store to disk. Writes via a
/// temp file + atomic rename so a crash mid-write can never leave a torn file.
/// Best-effort: a write failure is logged, never propagated — the in-memory
/// store remains authoritative for the running daemon.
pub(crate) fn write_persisted_mcp_transactions(
    layout: &KinLayout,
    store: &HashMap<String, kin_mcp::McpTransaction>,
) {
    if let Err(error) = write_persisted_mcp_transactions_checked(layout, store) {
        warn!(
            path = %mcp_transactions_disk_path(layout).display(),
            error = %error,
            "failed to durably persist MCP transactions"
        );
    }
}

/// Durably mirror MCP transaction state or fail before repository authority is
/// allowed to move.
///
/// The ordinary non-publication lifecycle wrapper above remains best-effort,
/// but exact repository commits use this checked boundary for their non-terminal
/// `committing` fence. The file and containing directory are flushed so a
/// successful return survives process and power loss on hosts that expose
/// directory fsync.
pub(crate) fn write_persisted_mcp_transactions_checked(
    layout: &KinLayout,
    store: &HashMap<String, kin_mcp::McpTransaction>,
) -> Result<()> {
    let path = mcp_transactions_disk_path(layout);
    let bytes = serde_json::to_vec(store).map_err(|error| {
        DaemonError::Io(std::io::Error::other(format!(
            "serialize MCP transactions: {error}"
        )))
    })?;
    let tmp = path.with_extension("json.tmp");
    let write_result = (|| -> std::io::Result<()> {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, &path)?;
        if let Some(parent) = path.parent() {
            sync_directory_metadata(parent)?;
        }
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(DaemonError::Io(error));
    }
    Ok(())
}

/// One append-only, release-attributed coordination event. This is the durable
/// collector boundary used by citable multi-agent metrics; every record names
/// its exact enforcement mode and scopes instead of implying unsupported
/// contract coverage.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoordinationEventEnvelope {
    pub schema: String,
    pub sequence: u64,
    pub timestamp: String,
    pub event: String,
    pub outcome: String,
    pub repo_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_id: Option<String>,
    #[serde(default)]
    pub intent_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub enforcement_mode: String,
    #[serde(default)]
    pub blocking_intent_ids: Vec<String>,
    pub kin_version: String,
    pub kin_commit: String,
    pub kin_dirty: bool,
}

#[derive(Debug, Clone)]
pub struct CoordinationEventDraft {
    pub event: &'static str,
    pub outcome: String,
    pub session_id: Option<String>,
    pub intent_id: Option<String>,
    pub intent_ids: Vec<String>,
    pub transaction_id: Option<String>,
    pub scopes: Vec<String>,
    pub enforcement_mode: String,
    pub blocking_intent_ids: Vec<String>,
}

/// Append-only JSONL writer with a monotonic sequence recovered from disk on
/// daemon restart. Appends are serialized and `sync_data` is called before an
/// event is broadcast, so live consumers never observe an event the durable
/// collector failed to record.
pub struct CoordinationEventLog {
    path: std::path::PathBuf,
    failure_marker: std::path::PathBuf,
    repo_id: String,
    next_sequence: Mutex<u64>,
    poisoned: AtomicBool,
}

impl CoordinationEventLog {
    pub fn open(layout: &KinLayout, repo_id: &str) -> std::io::Result<Self> {
        let path = layout.root().join("coordination_events.jsonl");
        let failure_marker = layout.root().join("coordination_events.failed");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if !path.exists() {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?
                .sync_data()?;
            if let Some(parent) = path.parent() {
                sync_directory_metadata(parent)?;
            }
        }

        let mut bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error),
        };
        let mut repaired_tail = false;
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            let repaired_len = bytes
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(0, |index| index + 1);
            let file = std::fs::OpenOptions::new().write(true).open(&path)?;
            file.set_len(repaired_len as u64)?;
            file.sync_data()?;
            bytes.truncate(repaired_len);
            repaired_tail = true;
        }

        let mut previous_sequence = None;
        let mut pending_reservations: HashMap<String, usize> = HashMap::new();
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            let event: CoordinationEventEnvelope =
                serde_json::from_slice(line).map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid coordination event JSONL record: {error}"),
                    )
                })?;
            if previous_sequence.is_some_and(|previous| event.sequence <= previous) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "coordination event sequence is not strictly increasing: {}",
                        event.sequence
                    ),
                ));
            }
            let reservation_key = serde_json::to_string(&(
                &event.event,
                &event.session_id,
                &event.transaction_id,
                &event.scopes,
            ))
            .map_err(std::io::Error::other)?;
            if event.outcome.starts_with("pending:") {
                *pending_reservations.entry(reservation_key).or_default() += 1;
            } else if let Some(count) = pending_reservations.get_mut(&reservation_key) {
                *count -= 1;
                if *count == 0 {
                    pending_reservations.remove(&reservation_key);
                }
            }
            previous_sequence = Some(event.sequence);
        }
        let next_sequence = previous_sequence.unwrap_or(0).saturating_add(1);
        let log = Self {
            path,
            failure_marker,
            repo_id: repo_id.to_string(),
            next_sequence: Mutex::new(next_sequence),
            poisoned: AtomicBool::new(false),
        };
        if repaired_tail || !pending_reservations.is_empty() {
            let failures = log.persisted_failure_count().max(1);
            log.persist_failure_count(failures);
        }
        Ok(log)
    }

    pub fn append(
        &self,
        draft: CoordinationEventDraft,
    ) -> std::io::Result<CoordinationEventEnvelope> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(std::io::Error::other(
                "coordination event log is poisoned after a prior append failure",
            ));
        }
        let mut next = self
            .next_sequence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.poisoned.load(Ordering::Acquire) {
            return Err(std::io::Error::other(
                "coordination event log is poisoned after a prior append failure",
            ));
        }
        let build = kin_buildinfo::get();
        let mut intent_ids = draft.intent_ids;
        intent_ids.sort();
        intent_ids.dedup();
        let mut scopes = draft.scopes;
        scopes.sort();
        scopes.dedup();
        let mut blocking_intent_ids = draft.blocking_intent_ids;
        blocking_intent_ids.sort();
        blocking_intent_ids.dedup();
        let envelope = CoordinationEventEnvelope {
            schema: "kin.coordination-event.v1".to_string(),
            sequence: *next,
            timestamp: kin_model::Timestamp::now().to_string(),
            event: draft.event.to_string(),
            outcome: draft.outcome,
            repo_id: self.repo_id.clone(),
            session_id: draft.session_id,
            intent_id: draft.intent_id,
            intent_ids,
            transaction_id: draft.transaction_id,
            scopes,
            enforcement_mode: draft.enforcement_mode,
            blocking_intent_ids,
            kin_version: kin_buildinfo::version().to_string(),
            kin_commit: build.sha.to_string(),
            kin_dirty: build.dirty,
        };
        let mut bytes = serde_json::to_vec(&envelope).map_err(std::io::Error::other)?;
        bytes.push(b'\n');
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let path_existed = self.path.exists();
        let original_len = std::fs::metadata(&self.path).map_or(0, |metadata| metadata.len());
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let persist_result = (|| -> std::io::Result<()> {
            file.write_all(&bytes)?;
            file.sync_data()?;
            if !path_existed {
                if let Some(parent) = self.path.parent() {
                    sync_directory_metadata(parent)?;
                }
            }
            Ok(())
        })();
        if let Err(error) = persist_result {
            self.poisoned.store(true, Ordering::Release);
            let _ = file.set_len(original_len);
            let _ = file.sync_data();
            return Err(error);
        }
        *next = next.saturating_add(1);
        Ok(envelope)
    }

    pub fn persisted_failure_count(&self) -> u64 {
        std::fs::read_to_string(&self.failure_marker)
            .ok()
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0)
    }

    fn persist_failure_count(&self, count: u64) {
        let temp = self.failure_marker.with_extension("failed.tmp");
        let result = (|| -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp)?;
            file.write_all(format!("{count}\n").as_bytes())?;
            file.sync_data()?;
            drop(file);
            std::fs::rename(&temp, &self.failure_marker)?;
            if let Some(parent) = self.failure_marker.parent() {
                sync_directory_metadata(parent)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            warn!(error = %error, "failed to persist coordination event failure marker");
            let _ = std::fs::remove_file(temp);
        }
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }
}

/// SSE invalidation events pushed to subscribers (VFS daemon, spine, KinLab).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum DaemonEvent {
    /// An entity was created, modified, or deleted.
    EntityChanged {
        entity_id: EntityId,
        change_type: ChangeType,
        file_path: Option<String>,
        /// Originating session, when the change came from a request that carried
        /// one (the VFS `/vfs/file-changed` and `/vfs/write-notify` handlers).
        /// `None` for anonymous FS-reconcile-loop changes. Additive: `serde`
        /// default keeps existing payloads and consumers working unchanged.
        #[serde(default)]
        session_id: Option<String>,
    },
    /// Files were added or removed from the tracked tree.
    TreeChanged {
        paths_added: Vec<String>,
        paths_removed: Vec<String>,
    },
    /// The graph root hash changed (commit happened).
    GraphRootChanged {
        old_root_hash: Option<String>,
        new_root_hash: String,
    },
    /// Repository-v6 authority advanced, even when the derived graph root did
    /// not (for example, a ref-only create/delete).
    RepositoryAuthorityChanged {
        repository_id: String,
        operation_id: OperationId,
        previous_generation: u64,
        new_generation: u64,
    },
    /// Durable coordination lifecycle event, appended before broadcast.
    Coordination { event: CoordinationEventEnvelope },
}

/// Authority owning the graph selected for a daemon request.
///
/// HEAD mutations participate in the daemon's durable snapshot/version/event
/// contract. Session-scope mutations are intentionally private and ephemeral:
/// publishing them as a HEAD change would invalidate unrelated readers while
/// persisting a different graph than the one that actually changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestGraphAuthority {
    Head,
    SessionScope,
}

/// Type of entity change for SSE events.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeType {
    Created,
    Modified,
    Deleted,
}

/// Request sent from the reconcile loop to the LSP enrichment worker.
#[derive(Debug)]
pub struct LspEnrichmentRequest {
    /// Graph-owned repository path of the changed file. The LSP worker may
    /// derive a compatibility URI from this identity, but must load didOpen
    /// bytes from repository authority rather than the working filesystem.
    pub file_id: FilePathId,
    /// Entity IDs that were added or modified — only these get queried via LSP.
    pub changed_entity_ids: Vec<kin_model::EntityId>,
}

/// Reusable graph/CAS source view for daemon-side enrichment.
///
/// The authority manager is opened once per worker rather than once per file.
/// Source bodies are immutable and addressed by the live graph entry hash, so
/// later workspace admissions remain visible through the same manager without
/// trusting a stale metadata snapshot.
pub(crate) struct GraphOwnedSourceView {
    graph: Arc<kin_db::InMemoryGraph>,
    authority: RepositoryAuthorityManager<LocalFileBackend>,
}

impl GraphOwnedSourceView {
    pub(crate) fn load_text(&self, file_id: &FilePathId) -> Result<String> {
        let path = RepoPath::from_utf8(file_id.0.clone()).map_err(|error| {
            exact_source_storage_error(format!(
                "LSP source path {file_id} is not an exact repository path: {error}"
            ))
        })?;
        let entry = self
            .graph
            .get_tree_entry(file_id)
            .map_err(DaemonError::from)?
            .ok_or_else(|| {
                exact_source_storage_error(format!(
                    "LSP source path {file_id} has no graph-owned tree entry"
                ))
            })?;
        let TreeEntry::Blob { hash, .. } = entry else {
            return Err(exact_source_storage_error(format!(
                "LSP source path {file_id} is not a source blob"
            )));
        };
        let data = self
            .authority
            .load_source_blob(hash)
            .map_err(DaemonError::from)?
            .ok_or_else(|| {
                exact_source_storage_error(format!(
                    "graph-owned LSP source {file_id} references body {hash} absent from repository authority"
                ))
            })?;
        validate_exact_source_bytes(&path, entry, hash, &data, "repository")?;
        String::from_utf8(data).map_err(|error| {
            exact_source_storage_error(format!(
                "graph-owned LSP source {file_id} at {hash} is not UTF-8: {error}"
            ))
        })
    }
}

#[derive(Debug, Default)]
pub struct ProjectionChangedSet {
    pub upserted: HashSet<FilePathId>,
    pub removed: HashSet<FilePathId>,
}

impl ProjectionChangedSet {
    pub fn is_empty(&self) -> bool {
        self.upserted.is_empty() && self.removed.is_empty()
    }

    pub fn record_reconcile_outcome(&mut self, outcome: &kin_reconcile::ReconcileOutcome) {
        match outcome {
            kin_reconcile::ReconcileOutcome::Updated { file_id, .. } => {
                self.upsert(file_id.clone());
            }
            kin_reconcile::ReconcileOutcome::FileRemoved { file_id, .. } => {
                self.remove(file_id.clone());
            }
            _ => {}
        }
    }

    pub fn upsert(&mut self, file_id: FilePathId) {
        self.removed.remove(&file_id);
        self.upserted.insert(file_id);
    }

    pub fn remove(&mut self, file_id: FilePathId) {
        self.upserted.remove(&file_id);
        self.removed.insert(file_id);
    }
}

/// Messages sent to the LSP enrichment worker.
#[derive(Debug)]
pub enum LspEnrichmentMessage {
    /// Incremental: enrich only these specific changed entities.
    Incremental(LspEnrichmentRequest),
    /// Cold sweep: enrich ALL entities in the graph, file by file.
    Sweep,
}

/// Maximum number of concurrent temporal scopes before LRU eviction.
const MAX_CONCURRENT_SCOPES: usize = 5;

/// Default TTL for temporal scopes (30 minutes).
pub const DEFAULT_SCOPE_TTL: Duration = Duration::from_secs(30 * 60);

/// A temporal scope pins a session to a specific historical ref.
/// All queries for this session use the cached historical graph
/// instead of the live HEAD graph.
pub struct TemporalScope {
    /// Original ref string (e.g., "git:abc123", "main", "HEAD~5")
    pub ref_string: String,
    /// Resolved semantic change ID
    pub head: kin_model::SemanticChangeId,
    /// Cached reconstructed historical graph
    pub cached_graph: Arc<kin_db::InMemoryGraph>,
    /// When the scope was created
    pub created_at: Instant,
    /// Time-to-live — scope auto-expires after this duration
    pub ttl: Duration,
}

impl TemporalScope {
    /// Check whether this scope has expired.
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }
}

/// Maximum attempts to capture one repo's entity/relation authority without
/// straddling a graph mutation.
const SPINE_GRAPH_CAPTURE_ATTEMPTS: usize = 3;

/// One internally coherent repo domain prepared for spine publication.
///
/// Entities, relations, entries, and `root_hash` are all derived from the same
/// detached graph snapshot. `graph_authority_epoch` is populated only for this
/// daemon's mutable primary graph; storage-loaded siblings are immutable cache
/// entries and are validated by exact live-root agreement instead.
struct SpineGraphCapture {
    repo_id: String,
    graph: Arc<kin_db::InMemoryGraph>,
    graph_authority_epoch: Option<u64>,
    root_hash: String,
    entries: Vec<kin_spine::EntityEntry>,
    entities: Vec<kin_model::Entity>,
    relations: Vec<kin_model::Relation>,
}

use crate::lifecycle::without_blocking_runtime_worker;

/// Holds the "spine is warming" signal up for exactly as long as sibling loads
/// are in flight, clearing it on every exit path including an unwind.
struct SpineWarmGuard<'a> {
    flag: &'a AtomicBool,
}

impl<'a> SpineWarmGuard<'a> {
    fn arm(flag: &'a AtomicBool) -> Self {
        flag.store(true, Ordering::Relaxed);
        Self { flag }
    }
}

impl Drop for SpineWarmGuard<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Relaxed);
    }
}

/// One local sibling repository capability frozen while the daemon starts.
///
/// Lazy spine initialization may load graph bytes later, but it must never
/// rediscover a mutable registry path, manifest, or storage root from a request
/// handler. The binding retains the exact backend root identity observed here.
#[derive(Clone)]
struct RegisteredLocalRepositoryAuthority {
    repo_id: String,
    binding: kin_core::LocalRepositoryAuthorityBinding,
}

/// Maximum number of per-row registry pin failures emitted during one daemon
/// startup. The aggregate warning below still reports every refusal exactly;
/// this bound keeps one stale registry from turning a routine start into
/// thousands of repeated log records.
const STARTUP_PIN_FAILURE_DETAIL_LIMIT: usize = 8;

#[derive(Debug, Default)]
struct StartupPinFailures {
    refused: usize,
    duplicate_identities: usize,
    detailed: usize,
}

impl StartupPinFailures {
    fn record_binding_failure(
        &mut self,
        repo_id: &str,
        path: &std::path::Path,
        error: &dyn std::fmt::Display,
    ) {
        self.refused += 1;
        if self.detailed >= STARTUP_PIN_FAILURE_DETAIL_LIMIT {
            return;
        }
        self.detailed += 1;
        warn!(
            repo_id = %repo_id,
            path = %path.display(),
            error = %error,
            "sibling repository authority could not be pinned at daemon startup"
        );
    }

    fn record_duplicate_identity(
        &mut self,
        repo_id: &str,
        path: &std::path::Path,
        manifest_repo_id: &str,
    ) {
        self.refused += 1;
        self.duplicate_identities += 1;
        if self.detailed >= STARTUP_PIN_FAILURE_DETAIL_LIMIT {
            return;
        }
        self.detailed += 1;
        warn!(
            repo_id = %repo_id,
            path = %path.display(),
            manifest_repo_id = %manifest_repo_id,
            already_pinned_as = %manifest_repo_id,
            "two registry paths hold one repository identity; the later one is not pinned"
        );
    }

    fn emit_summary(&self, registry_rows: usize, self_rows_skipped: usize, pinned: usize) {
        if self.refused == 0 {
            return;
        }
        warn!(
            registry_rows,
            self_rows_skipped,
            pinned,
            refused = self.refused,
            duplicate_identities = self.duplicate_identities,
            detailed = self.detailed,
            suppressed = self.refused.saturating_sub(self.detailed),
            remediation = "run `kin registry clean` to remove rows whose paths no longer contain .kin; review incompatible stores separately",
            "sibling repository authority pinning was incomplete"
        );
    }
}

/// Outcome of ingesting one repo's graph into the spine from durable storage.
///
/// Returned by [`DaemonState::ingest_repo_into_spine`] and surfaced by the
/// `POST /spine/repos/{repo_id}/ingest` route so the hosted control plane can
/// gate the cross-repo org graph on real, graph-derived counts.
#[derive(Debug, Clone)]
pub struct SpineIngestOutcome {
    /// The repo that was ingested.
    pub repo_id: String,
    /// Graph root hash of the ingested snapshot (cache-coherence key).
    pub root_hash: String,
    /// Entities registered into the spine for this repo.
    pub entity_count: usize,
    /// `Calls`/`References` relations scanned for cross-repo candidates.
    pub relation_count: usize,
    /// Relations the cross-repo resolver can bind into xref edges (out-of-repo
    /// target carrying an `import_source` + imported-symbol token). The org
    /// graph's real cross-repo edges come from these.
    pub resolvable_relations: usize,
}

/// Outcome of refreshing cross-repo edges across every registered repo.
///
/// Operator lever for how many siblings the spine loads eagerly. Registered in
/// `kin-core`'s env registry, which is the surface that decides whether a
/// `KIN_*` name is a lever or an unrecognized read.
/// What the spine's sibling capture actually did, kept rather than only logged.
///
/// A log line discloses to an operator reading logs. This discloses to the
/// process: a test can assert it, and a health surface can report it, which is
/// what makes "bounded" a claim the product carries rather than a sentence it
/// once printed.
///
/// `bounded` and `authority_incomplete` are deliberately separate booleans over
/// one inequality. A capture the bound stopped is expected and its captures are
/// sound; a sibling that failed to load is neither. Collapsing them into one
/// flag is what would let a real failure hide behind a configured cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SiblingCaptureReport {
    pub bounded: bool,
    pub captured: usize,
    pub registered: usize,
    pub bound: usize,
    pub authority_incomplete: bool,
}

pub(crate) const EAGER_SIBLING_BOUND_ENV: &str = "KIN_SPINE_MAX_EAGER_SIBLINGS";

/// Returned by [`DaemonState::refresh_all_cross_repo_edges`] and surfaced by the
/// `POST /spine/refresh-cross-repo-edges` route. The hosted import orchestrator
/// runs this final pass once every repo is registered so cross-repo edges
/// emanate from every repo (kin-db→kin-search, kin-model→kin-vector, …), not
/// only the anchor.
#[derive(Debug, Clone)]
pub struct SpineRefreshOutcome {
    /// Repos whose outgoing cross-repo edges were re-resolved.
    pub repos_refreshed: usize,
    /// Total cross-repo edges in the spine after the refresh pass.
    pub cross_repo_edges: usize,
}

/// One detached graph mutation batch that has not yet been acknowledged by
/// durable backend authority. Dropping the guard before `complete` forces the
/// next save through a full snapshot, so an error cannot silently discard the
/// batch while mutations arriving during backend I/O remain independently
/// pending.
struct GraphPersistenceAttempt<'a> {
    graph: &'a kin_db::InMemoryGraph,
    epoch: Option<kin_db::PersistenceEpoch>,
}

impl<'a> GraphPersistenceAttempt<'a> {
    fn new(graph: &'a kin_db::InMemoryGraph, epoch: kin_db::PersistenceEpoch) -> Self {
        Self {
            graph,
            epoch: Some(epoch),
        }
    }

    fn complete(mut self) {
        if let Some(epoch) = self.epoch.take() {
            let completed = self.graph.complete_persistence(epoch);
            debug_assert!(completed, "persistence epoch must still be in flight");
        }
    }
}

impl Drop for GraphPersistenceAttempt<'_> {
    fn drop(&mut self) {
        if let Some(epoch) = self.epoch.take() {
            self.graph.fail_persistence(epoch);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotSaveMode {
    Incremental,
    Full,
}

fn authority_holds_entity(
    authority: &kin_db::GraphSnapshot,
    node: &kin_model::GraphNodeId,
) -> bool {
    match node {
        kin_model::GraphNodeId::Entity(entity_id) => authority.entities.contains_key(entity_id),
        _ => false,
    }
}

fn exact_source_storage_error(message: impl Into<String>) -> DaemonError {
    DaemonError::Graph(kin_db::KinDbError::StorageError(message.into()))
}

fn exact_source_objects<'a>(
    changes: impl IntoIterator<Item = &'a SemanticChange>,
) -> Result<Vec<(Hash256, RepoPath, SemanticChangeId, TreeEntry)>> {
    let mut objects = Vec::new();
    for change in changes {
        for delta in &change.tree_deltas {
            let Some(located) = delta.new_state() else {
                continue;
            };
            let Some(hash) = located.entry.blob_identity() else {
                continue;
            };
            objects.push((hash, located.path.clone(), change.id, located.entry));
        }
    }
    objects.sort_by(|left, right| {
        left.0
            .as_bytes()
            .cmp(right.0.as_bytes())
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2 .0.as_bytes().cmp(right.2 .0.as_bytes()))
    });
    Ok(objects)
}

fn validate_exact_source_bytes(
    path: &RepoPath,
    entry: TreeEntry,
    expected: Hash256,
    data: &[u8],
    authority: &str,
) -> Result<()> {
    let actual = kin_blobs::digest_bytes(data);
    if actual != *expected.as_bytes() {
        return Err(exact_source_storage_error(format!(
            "{authority} exact source bytes for {path} do not match {expected}: found {}",
            hex::encode(actual)
        )));
    }
    kin_core::validate_source_entry(path, entry, data).map_err(|error| {
        exact_source_storage_error(format!(
            "{authority} exact source entry {path} at {expected} is not materializable: {error}"
        ))
    })
}

#[derive(Default)]
struct GraphAuthorityClock {
    /// Serializes writer publication with the one-time spine visibility edge.
    /// Held only while a writer announces itself or initialization performs its
    /// final authority check and publishes OnceLock.
    publication_gate: Mutex<()>,
    active_writers: AtomicUsize,
    epoch: AtomicU64,
}

/// Marks one entity/relation mutation batch as in flight.
///
/// Writers publish both edges of the batch through a shared clock. Xref readers
/// accept a detached snapshot only when no writer is active and this epoch is
/// unchanged through their final authority validation. A writer count (rather
/// than an odd/even bit) keeps overlapping background and request mutations
/// fail-closed until the last batch finishes.
pub(crate) struct GraphAuthorityMutationGuard {
    clock: Arc<GraphAuthorityClock>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalRepositoryFinalization {
    pub graph_changed: bool,
    pub generation_advanced: bool,
}

impl Drop for GraphAuthorityMutationGuard {
    fn drop(&mut self) {
        self.clock.epoch.fetch_add(1, Ordering::SeqCst);
        self.clock
            .active_writers
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |active| {
                active.checked_sub(1)
            })
            .expect("graph authority writer count underflow");
    }
}

/// The `(generation, live exact tree)` pair whose match against committed
/// workspace authority has already been derived for a vector checkpoint.
///
/// A vector checkpoint is refused when the live exact tree diverges from
/// committed authority. Deriving that answer costs a full authority reopen,
/// which recovers the snapshot, revalidates every semantic change id, and
/// re-verifies every stored body against its content address. That cost is
/// linear in store size rather than in the batch being checkpointed, so paid
/// once per embed batch it dominates a long embed. On a 2 GB store it is
/// minutes of reopen for seconds of inference, re-deriving a conclusion about
/// bytes that have not moved.
///
/// Both inputs to the conclusion are exact and cheap to compare. Committed
/// authority is immutable at a generation, so the authority side is a function
/// of `generation` alone, and the live side is the tree itself. A generation
/// bump or any live-tree mutation misses the retained pair and reopens
/// authority in full, with the same refusal.
///
/// What the retained pair does narrow is the incidental tripwire a reopen
/// carried. The on-disk generation assertion and the content-address
/// re-verification of every authority body ran once per batch as a side effect
/// of opening authority, and while the pair holds they run at the next real
/// reopen instead, which is the next generation change, the next live-tree
/// change, or the next daemon open. The vector index is a pure derived sidecar
/// that is not in the merkle root, and the stamp it carries is re-verified
/// wherever it is reused, so nothing downstream accepts a checkpoint on weaker
/// evidence than before.
#[cfg(feature = "embeddings")]
#[derive(Debug, Default)]
struct VectorCheckpointAuthorityMatch {
    derived: Mutex<Option<(u64, ResolvedTree)>>,
}

#[cfg(feature = "embeddings")]
impl VectorCheckpointAuthorityMatch {
    /// True when this exact pair has already been derived. A poisoned lock
    /// answers false, so the caller reopens authority rather than trusting an
    /// unreadable record.
    fn holds(&self, generation: u64, live_tree: &ResolvedTree) -> bool {
        self.derived.lock().is_ok_and(|derived| {
            derived
                .as_ref()
                .is_some_and(|(derived_generation, derived_tree)| {
                    *derived_generation == generation && derived_tree == live_tree
                })
        })
    }

    /// Retain a freshly derived pair, replacing any earlier one.
    fn record(&self, generation: u64, live_tree: ResolvedTree) {
        if let Ok(mut derived) = self.derived.lock() {
            *derived = Some((generation, live_tree));
        }
    }
}

/// The longest idle window an attached client may ask this daemon to hold.
///
/// A client stating what it needs is not a client deciding this daemon should
/// live forever: an agent process that dies without withdrawing would otherwise
/// pin the graph in memory indefinitely. Twenty-four hours is far beyond any
/// real interactive session and still expires.
pub const MAX_ATTACHED_IDLE_TIMEOUT_SECS: u64 = 86_400;

/// What a request to grow the idle window did to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdleTimeoutRaise {
    /// The window now in force. `None` means the daemon never idles out.
    pub effective: Option<Duration>,
    /// The window this replaced, or `None` when nothing changed.
    pub raised_from: Option<Duration>,
}

impl IdleTimeoutRaise {
    /// The window now in force in whole seconds, with 0 meaning "never idles
    /// out" — the shape the HTTP surface and the daemon's own env var speak in.
    pub fn effective_secs(&self) -> u64 {
        self.effective.map_or(0, |window| window.as_secs())
    }

    pub fn raised(&self) -> bool {
        self.raised_from.is_some()
    }
}

/// Resolve a requested idle floor against the window currently in force,
/// returning the new window when one is warranted and `None` when the current
/// window already covers the request.
///
/// This is the whole decision the idle floor exists to make. The idle window is
/// fixed by whichever process spawns the daemon, and on a developer machine
/// that is almost always an ordinary CLI command taking the short CLI default.
/// A later client with a much longer session — an MCP agent loop that goes quiet
/// between tool calls — used to inherit that short window silently and have the
/// daemon expire underneath it mid-session.
///
/// Three cases, each deliberate:
/// - a daemon that never idles out already outlasts every finite request, so it
///   is never given a finite window here;
/// - a request for "never" (zero) is refused rather than honoured, because a
///   floor of forever is not a floor;
/// - anything above [`MAX_ATTACHED_IDLE_TIMEOUT_SECS`] is clamped to it.
pub fn resolve_idle_timeout_floor(
    current: Option<Duration>,
    requested: Duration,
) -> Option<Duration> {
    let current = current?;
    if requested.is_zero() {
        return None;
    }
    let requested = requested.min(Duration::from_secs(MAX_ATTACHED_IDLE_TIMEOUT_SECS));
    (requested > current).then_some(requested)
}

/// Shared daemon state. All mutable state is behind RwLock for
/// concurrent access from the reconciliation loop and API handlers.
/// What opening a store's vector sidecar did, as the surfaces need to report it.
///
/// Two independent facts rather than one enum, because they answer different
/// questions and a reader needs both: `discarded` says an index was on disk and
/// is NOT attached, `salvage` says one IS attached after retiring keys. At most
/// one is ever set, but folding them into a single field would invite a caller
/// to treat "no discard" as "nothing was lost", which is precisely the reading
/// that made a salvaged store render as a first fill (FIR-2562).
#[derive(Debug, Clone, Default)]
struct VectorSidecarOpen {
    discarded: Option<String>,
    salvage: Option<crate::VectorSalvage>,
}

/// Read kin-db's sidecar load outcome as the salvage fact the surfaces report,
/// or `None` when nothing was retired at open.
///
/// Only a stamp-drift salvage produces a record. An exact load can still drop
/// orphaned generations, and reporting that as lost coverage would fire on
/// ordinary re-inits; the ticket's whole point is that "loaded whole" and
/// "loaded partially" have to stay distinguishable (FIR-2562).
///
/// The kept count is a subtraction rather than a field, because
/// `vectors_loaded` is what the sidecar held BEFORE reconciliation ran, not
/// what survived it (kin-db 0.7.49
/// `crates/kin-db/src/storage/snapshot.rs:1460`). Passing it through as "kept"
/// would print the sidecar's whole size beside a retired count already inside
/// it, so a store that kept 1770 of 2112 would read as keeping 2112 and
/// retiring 342 at the same time.
fn salvage_from_sidecar_outcome(
    outcome: &kin_db::VectorSidecarLoadOutcome,
) -> Option<crate::VectorSalvage> {
    matches!(
        outcome.disposition,
        kin_db::VectorSidecarDisposition::SalvagedAfterStampDrift
    )
    .then(|| crate::VectorSalvage {
        kept: outcome
            .vectors_loaded
            .saturating_sub(outcome.vectors_dropped),
        dropped: outcome.vectors_dropped,
    })
}

pub struct DaemonState {
    pub layout: KinLayout,
    pub graph: Arc<kin_db::InMemoryGraph>,
    /// Entities durable repository authority carried the last time this daemon
    /// levelled its query graph with authority, or `u64::MAX` when it never
    /// has (FIR-2421).
    ///
    /// The live graph above admits host content continuously and records none
    /// of it: an ambient admission publishes the exact workspace tree and then
    /// writes derived entities into the live graph alone, so the entity layer
    /// is rebuilt from zero on the next open. Serving a populated
    /// `entity_count` without this to compare against is what let a real agent
    /// read `entity_count: 14`, locate a class it had just written, and
    /// conclude its work was in the graph.
    ///
    /// Recorded where the levelling actually happens and nowhere else: at open,
    /// from the durable workspace snapshot the query graph is built out of, and
    /// after a commit installs authority onto the live graph. A path that
    /// levels without recording leaves this BELOW the live count, which reads
    /// as uncommitted work that is in fact recorded. That direction is a false
    /// alarm; the reverse, reporting recorded work that is not, is the defect
    /// being fixed, and [`kin_mcp::Durability::observe`] refuses to derive a
    /// count at all once this rises above the live count.
    ///
    /// `u64::MAX` rather than an `Option` so the sentinel and the counter share
    /// one atomic read; [`Self::durable_entity_count`] is the only reader.
    durable_entity_count: AtomicU64,
    pub blobs: Arc<BlobStore>,
    /// Why the derived ingestion CAS could not be hydrated from graph
    /// authority when this state was opened, if it could not.
    ///
    /// Projection reads name this instead of surfacing a bare missing-blob
    /// error, so an un-hydrated store is reported as the authority gap it is
    /// rather than as a mysteriously absent object.
    ingest_cas_hydration_gap: Option<String>,
    /// Why the persisted vector index on disk was not installed when this state
    /// was opened, when one was there and was not.
    ///
    /// A discarded index is re-derived from scratch, which is minutes to hours
    /// of embedding on a real repository, so it is stated rather than left to
    /// be inferred from a coverage counter that silently restarted at zero.
    /// `None` means either that the index loaded or that there was none to
    /// load, which are the two states that need no explanation.
    vector_index_discarded: Option<String>,
    /// What a per-key salvage retired at open, when one happened. Separate from
    /// the discard reason above because a salvage ATTACHES an index: the two
    /// describe different stores and only one of them can be true at a time.
    vector_index_salvage: Option<crate::VectorSalvage>,
    pub reconciler: RwLock<Reconciler>,
    /// Cached FileLayouts for all tracked files.
    /// Populated on init, updated on commits.
    pub projection: RwLock<ProjectionState>,
    /// Session and intent coordinator (Phase 7).
    pub coordinator: SessionCoordinator,
    /// Serializes daemon intent lifecycle mutations with MCP transaction
    /// preflight+apply so those two authority paths have one ordering.
    pub coordination_gate: tokio::sync::Mutex<()>,
    /// Shared entity/relation mutation clock. Every authority writer brackets
    /// its complete batch so detached xref reads cannot certify an intermediate
    /// graph state before the writer publishes its normal version/root update.
    graph_authority_clock: Arc<GraphAuthorityClock>,
    /// Mode captured when the daemon state is created. Requests use this
    /// stable value instead of re-reading process-global environment mid-run.
    pub coordination_mode: std::sync::RwLock<kin_mcp::CoordinationEnforcementMode>,
    /// Durable, release-attributed coordination event collector.
    pub coordination_events: CoordinationEventLog,
    /// Runtime completeness signal for the durable collector. Citable runs
    /// must require zero; an append failure never masquerades as a recorded
    /// event merely because the product action itself completed.
    pub coordination_event_persist_failures: AtomicU64,
    /// When the daemon was started (for uptime reporting).
    pub started_at: Instant,
    /// Whether the daemon has been initialized (snapshot loaded or first reconciliation done).
    pub is_initialized: AtomicBool,
    /// Current reconciliation status (RECON_IDLE or RECON_PROCESSING).
    pub reconciliation_status: AtomicU8,
    /// Pluggable storage backend for snapshot persistence.
    /// `None` = local repository-v6 authority.
    /// `Some` = hosted StorageBackend (GCS or an isolated backend fixture).
    pub storage_backend: Option<Arc<dyn StorageBackend>>,
    /// Whether the backend this daemon opened against already holds a
    /// repository-authority envelope.
    ///
    /// Captured at open from the loaded snapshot, because it cannot be read
    /// back cheaply later: `load_snapshot_authority` defaults to pulling the
    /// whole object, and the periodic flush is not a place to download the
    /// graph. Captured rather than recomputed is also correct rather than
    /// merely cheap: nothing this daemon can do creates an envelope, since
    /// `record_repository_authority_commit` refuses a storage-backend daemon
    /// outright, so the only way one appears is a transfer, and a transfer
    /// advances the generation the daemon's CAS is pinned to.
    hosted_authority_envelope: bool,
    /// How many flushes have been refused the backend authority write.
    ///
    /// Exists so the healthy path can assert zero rather than merely not
    /// asserting anything: a guard that fires where it should not is invisible
    /// from the outside, because a refused flush and a flush with nothing to do
    /// both return `Ok` and both leave the object alone.
    hosted_authority_flush_refusals: AtomicU64,
    /// Startup-opened local storage capability. Reusing this exact backend
    /// preserves KinDB's device/inode root pin across every local authority
    /// request; constructing a new backend from the mutable path would bless a
    /// swapped `.kin/kindb` namespace.
    local_repository_backend: Option<Arc<LocalFileBackend>>,
    /// One repository-v6 authority shared by the projection (VFS) routes,
    /// revalidated against the durable publication record before every use so
    /// a commit from this daemon or from a separate process is served as soon
    /// as it is published.
    pub(crate) projection_authority: crate::api::ProjectionAuthorityCache,
    /// Local sibling capabilities captured from registry configuration at
    /// startup. The lazy spine loader may open only these retained bindings.
    registered_local_repository_authorities: Vec<RegisteredLocalRepositoryAuthority>,
    /// Startup registry/binding gaps prevent a complete local spine claim even
    /// when every retained sibling that remains can be loaded.
    registered_local_repository_authority_incomplete: bool,
    /// Whether the federation layer was disabled when this daemon state was
    /// constructed. Captured once so startup pinning and request-time spine
    /// access cannot read different process environments.
    spine_disabled: bool,
    /// Resolved once, here, rather than read inside the capture loop.
    ///
    /// A daemon captures its levers at process start; reading the environment
    /// per pass would also make this untestable without mutating process-global
    /// state that every other test in this binary shares, which is a race
    /// rather than a fixture.
    eager_sibling_bound: usize,
    /// Set once, when the spine publishes. Absent until then, which is itself
    /// the honest answer to "what did the capture do" before it has run.
    sibling_capture: std::sync::OnceLock<SiblingCaptureReport>,
    /// Frozen startup policy for deployments whose graph backend is the only
    /// write authority. When true, no filesystem/session/VFS compatibility
    /// surface may reconcile bytes back into graph truth.
    pub(crate) filesystem_reconcile_disabled: AtomicBool,
    /// Generation from the last snapshot load (for CAS on save).
    pub snapshot_generation: AtomicU64,
    /// A graph authority commit advanced, but its local generation marker and
    /// read index have not both been durably finalized yet. A save with no new
    /// graph mutations still retries this work.
    post_commit_finalization_pending: AtomicBool,
    #[cfg(test)]
    finalization_fail_once: AtomicBool,
    /// Deterministic crash seam after exact MCP repository authority commits
    /// but before the derived graph and terminal transaction state install.
    #[cfg(test)]
    pub(crate) mcp_fail_after_authority_once: AtomicBool,
    /// Deterministic crash seam after a branch repository CAS but before the
    /// daemon installs its derived graph/generation cursor.
    #[cfg(test)]
    pub(crate) repository_command_fail_after_authority_once: AtomicBool,
    /// Deterministic enrichment seam in the same window: the asynchronous LSP
    /// worker writes derived relations into the live graph without taking the
    /// coordination gate or the persistence lock, so it can land between a
    /// command's plan and its finalization.
    #[cfg(test)]
    pub(crate) repository_command_enrich_after_authority_once: AtomicBool,
    /// Monotonically increasing version counter for VFS cache invalidation.
    /// Incremented on every graph mutation (reconcile, commit, overlay update).
    /// Unlike entity_count, this never decreases on deletions.
    pub vfs_version: AtomicU64,
    /// Broadcast channel for SSE invalidation events.
    /// Subscribers (VFS daemon, spine, KinLab) receive real-time notifications.
    pub event_tx: tokio::sync::broadcast::Sender<DaemonEvent>,
    /// Per-session temporal scopes. When a session has an active scope,
    /// all queries see the cached historical graph instead of the live graph.
    /// Max MAX_CONCURRENT_SCOPES sessions can have active scopes simultaneously.
    pub session_scopes: RwLock<HashMap<kin_model::SessionId, TemporalScope>>,
    /// Cross-repo federation spine. Initialized lazily on first access via
    /// `ensure_spine()` to avoid blocking daemon startup.
    ///
    /// Uses the `SpineBackend` trait to abstract over storage:
    /// - `InMemorySpineBackend`: local dev / single daemon (default)
    /// - `FirestoreSpineBackend`: cloud / stateless daemon pool (when GOOGLE_CLOUD_PROJECT is set)
    pub spine: std::sync::OnceLock<Arc<dyn kin_spine::SpineBackend>>,
    /// Serializes the complete lazy initialization pass. `OnceLock` serializes
    /// publication only; without this gate, multiple callers can concurrently
    /// perform the full O(graph) capture/load/build pass and one warm guard can
    /// clear the shared signal while another initializer is still running.
    spine_initialization: Mutex<()>,
    /// True throughout the complete lazy spine initialization pass, including
    /// primary capture, sibling loading, edge construction, and publication.
    /// This is the daemon's honest "busy warming" signal: the process is alive
    /// and its own repo is served, but a cross-repo surface is materializing.
    /// Clients must treat it as alive-and-waiting, never as a dead endpoint.
    spine_warming: AtomicBool,
    /// Deterministic blocking seam for concurrency and runtime-starvation
    /// regression tests. Production initialization has no injected hook.
    #[cfg(test)]
    spine_initialization_test_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Deterministic seam inside the vector-checkpoint authority reopen, fired
    /// at the last moment that window is still open. The reopen takes no lock
    /// on the live graph, so a mutation can land while it runs; a test hook
    /// here reproduces that arrival without racing it, and also counts how many
    /// reopens a sequence of flushes actually paid for. Production installs no
    /// hook.
    #[cfg(all(test, feature = "embeddings"))]
    vector_checkpoint_reopen_test_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Serializes hosted repo registration and all-repo edge refresh passes.
    /// The backend independently keeps a pass-wide incomplete lease; this gate
    /// prevents daemon request paths from racing that lease with a new ingest.
    spine_refresh_gate: tokio::sync::Mutex<()>,
    /// Maps repo_id to a lazily-loaded graph. Graphs are loaded from the
    /// storage backend on first access. Only active when `storage_backend`
    /// is `Some` (cloud / multi-repo mode).
    pub repo_graphs: RwLock<HashMap<String, Arc<kin_db::InMemoryGraph>>>,
    /// Optional allowlist for cloud repo discovery. When present, only these
    /// repo IDs are visible through the multi-repo HTTP API.
    pub allowed_repo_ids: Option<HashSet<String>>,
    /// True when the in-memory graph has been mutated since the last save.
    /// The background persistence task checks this to decide when to flush.
    pub dirty: AtomicBool,
    /// Monotonic acknowledgement fence for `dirty`. A mutation increments this
    /// before a later `mark_clean` can clear the flag, so a save finishing at
    /// the same time as a new mutation cannot erase that mutation's wakeup.
    mutation_epoch: AtomicU64,
    /// Serializes explicit `/embed` requests with the background embedding
    /// worker so they cannot drain queues and mutate the vector index
    /// concurrently.
    pub embedding_work: Mutex<()>,
    /// Batch size the background embedding queue is actually running with,
    /// published by the daemon's own startup once it has resolved the operator's
    /// environment, this repository's `[resources]` config, and its built-in
    /// default (FIR-2504).
    ///
    /// Reported by `kin resources inspect` because without it there is no way to
    /// see whether a knob took. The ticket's whole mechanism was a flag that
    /// looked like it worked, so a surface that cannot show the effective value
    /// cannot answer the question an operator is actually asking. Zero means the
    /// daemon has not published one yet, which is not a batch size of zero.
    embed_batch_size: AtomicUsize,
    /// Last settled `kin_graph_status` reading per selected-graph scope, so a
    /// status call whose live sample loses every bounded attempt answers with
    /// that reading marked stale instead of a bare retry instruction
    /// (FIR-2135). Two fixed slots holding one already-computed observation
    /// each; it costs no lock the embed path needs and no work proportional to
    /// the graph, which is the constraint FIR-2416 put on this surface.
    pub(crate) graph_status_settled: crate::api::GraphStatusSettledCache,
    /// Consecutive `kin_graph_status` calls that could not complete a live
    /// sample of the selected graph, reset by the first one that does.
    ///
    /// FIR-2136. A daemon can enter a state where the tool that exists to
    /// report ill health is the one that stops answering, and before this the
    /// health surface could not see it: a daemon serving nothing but stale
    /// replays for hours reported `status: "ok"`.
    ///
    /// Consecutive, rather than a lifetime total or the age of the last settled
    /// reading, because only a consecutive count reset on success separates the
    /// three states that matter. A daemon nobody has asked reads zero, which is
    /// the same as a daemon whose samples all succeed, and both are healthy. A
    /// lifetime total cannot tell a store that recovered from one that never
    /// did, and an age-of-last-settled cannot tell a wedged daemon from one no
    /// caller has ever queried, since neither holds a settled reading.
    pub graph_status_live_sample_failures: AtomicU64,
    /// Serializes derived-index and hosted snapshot persistence so the
    /// persistence loop, idle-shutdown flush, and embedding worker can never
    /// interleave writes. Local repository-v6 authority is committed before
    /// entering this derived finalization path. Held only for the synchronous
    /// critical section — never across an `.await` or another lock.
    pub persist_lock: Mutex<()>,
    /// Last `(generation, live exact tree)` pair proved to match committed
    /// workspace authority for a vector checkpoint. Read under `persist_lock`.
    #[cfg(feature = "embeddings")]
    vector_checkpoint_authority_match: VectorCheckpointAuthorityMatch,
    /// Why the last vector checkpoint was refused, held until a later
    /// checkpoint lands.
    ///
    /// A refusal is transient by construction. It says the live exact tree had
    /// moved away from committed workspace authority, which is exactly what a
    /// commit in flight does to it, and the divergence closes when that commit
    /// settles. The vectors are unharmed either way: they stay in the live
    /// index, so the coverage a reader sees is true about this process.
    ///
    /// What was not true is that the coverage was durable. The refusal used to
    /// be logged once at ERROR and abandoned. Nothing else in the daemon writes
    /// the vector sidecar (`checkpoint_vector_index_for_graph` has exactly one
    /// caller, `flush_embed_progress`), and the embed worker only reaches that
    /// caller after a batch embeds something, so a refusal on the last batch of
    /// a draining queue had nothing left to retry it. Every vector embedded
    /// since the previous successful checkpoint then died with the process, and
    /// the next open reported the shortfall as ordinary pending work. That is
    /// the coverage regression a user reads as embedding going backwards after
    /// a commit.
    ///
    /// Recording the refusal is what gives the retry something to fire on and
    /// gives every embedding surface a cause to name while the gap is open.
    #[cfg(feature = "embeddings")]
    deferred_vector_checkpoint: std::sync::Mutex<Option<String>>,
    /// When the last successful background save completed.
    pub last_save: std::sync::Mutex<Instant>,
    /// When the graph was last mutated (`mark_dirty`). The background
    /// persistence task debounces its idle flush on this clock — quiet since
    /// the last MUTATION — which is distinct from `last_save` (how long dirty
    /// state has sat unpersisted, the periodic durability bound).
    pub last_mutation: std::sync::Mutex<Instant>,
    /// Number of daemon-side embed passes (`POST /embed`) currently in
    /// flight. While nonzero the background idle flush stays suppressed: the
    /// embed handler persists its own progress (pre-pass snapshot, per-batch
    /// kvec, post-pass snapshot), and a full-graph flush on every starved
    /// feed gap multiplies FS events that starve the feed further.
    pub active_embed_passes: AtomicU32,
    /// True after a bounded explicit embed pass has claimed the embed resource.
    /// The background worker stays paused so a time-limited foreground command
    /// cannot return while the daemon keeps draining the same large backfill.
    pub background_embed_paused: AtomicBool,
    /// Last externally visible daemon activity, measured as milliseconds since
    /// `started_at`. Used by opt-in idle shutdown for CLI-autostarted daemons.
    pub last_activity_ms: AtomicU64,
    /// The live idle window in milliseconds, or 0 when this daemon never idles
    /// out.
    ///
    /// Seeded from startup configuration and readable by attached clients whose
    /// session outlives it. It is here rather than captured by the idle monitor
    /// because the window has to be able to grow after the process started: the
    /// spawner fixes it at spawn time, and whoever spawns first is frequently
    /// not who ends up depending on it.
    ///
    /// Milliseconds, not the seconds the env var and HTTP surface speak in, so
    /// a sub-second window cannot round down into the sentinel and turn "expire
    /// quickly" into "never expire".
    idle_timeout_ms: AtomicU64,
    /// Number of API requests currently being handled.
    pub active_requests: AtomicU64,
    /// Channel for LSP enrichment messages (incremental or sweep).
    /// None if LSP enrichment is disabled (no servers found).
    pub lsp_enrichment_tx: Option<tokio::sync::mpsc::Sender<LspEnrichmentMessage>>,
    /// Whether enrichment was switched ON for this daemon at all, apart from
    /// whether any server was then found.
    ///
    /// Kept because the channel being closed collapses three different causes
    /// into one boolean, and a caller that reads only the channel cannot tell a
    /// deliberately disabled daemon from a host with no server. `kin init` used
    /// to assert the second whenever it saw the boolean, which was false on
    /// every gcs-backed or KIN_DAEMON_DISABLE_LSP daemon.
    pub lsp_enrichment_enabled: bool,
    /// How far the running cold sweep has got, and how many have finished.
    ///
    /// A sweep is asynchronous and takes minutes on a real repository, and until
    /// this existed nothing could tell a converged graph from one still being
    /// enriched: `POST /lsp/sweep` answered `sweep_queued` and never spoke
    /// again. A caller that must not query a half-enriched graph, which is every
    /// conversion, had no signal to wait on. These are the signal.
    pub lsp_sweep_files_done: AtomicU64,
    pub lsp_sweep_files_total: AtomicU64,
    /// Files the last cold sweep walked past without being able to enrich.
    ///
    /// Served beside `files_done` so a caller can tell a converged sweep from
    /// one that could not run. `files_done` alone cannot: both report zero.
    pub lsp_sweep_files_blocked: AtomicU64,
    /// Incremented when a sweep finishes, so a waiter can tell "the sweep I
    /// asked for has completed" from "a sweep is not running yet". A bare
    /// running/idle flag cannot: a waiter that polls before the worker picks the
    /// message up reads idle and concludes it is done.
    pub lsp_sweeps_completed: AtomicU64,
    /// Set while a sweep is in flight.
    pub lsp_sweep_running: AtomicBool,
    /// Files a sweep has finished enriching, so a later pass can skip them.
    ///
    /// An explicit marker rather than an inference from the graph. Two attempts
    /// to infer it from relation origin failed, both silently and both on the
    /// files that matter: asking whether a file's entities carry an Lsp-origin
    /// relation counts edges pointing INTO them, and narrowing to edges they are
    /// the SOURCE of still skipped `sessions.py`, `auth.py` and `adapters.py`,
    /// because enrichment writes source-side edges from more than one direction.
    /// A marker the sweep writes when it finishes a file cannot be confused by
    /// any of that: it records what the sweep DID, which is the only thing a
    /// skip is entitled to act on.
    pub lsp_enriched_files: std::sync::Mutex<std::collections::HashSet<String>>,

    /// Repo-relative paths this daemon derived entities for that durable
    /// authority is not known to hold.
    ///
    /// Entity derivation is not durable on its own. A tree admission publishes
    /// an artifact into repository authority the moment the watcher sees the
    /// write, while the entities the same tick derives live in this graph until
    /// a commit publishes them, and a daemon that ends first takes them with
    /// it. What it leaves behind is a file admitted at exactly the bytes on
    /// disk, so no later watcher event fires for it and the startup catch-up,
    /// keyed on host modification time since the last complete admission,
    /// cannot see it either: the admission that recorded the artifact is later
    /// than the write. The path is then permanently admitted and permanently
    /// unqueryable (FIR-2606).
    ///
    /// This names those paths and nothing else, which is the whole point. The
    /// first repair written for FIR-2606 asked the graph which admitted source
    /// paths carried no entity, and on a freshly converted store that is most
    /// of the working copy at the moment the conversion answers its first
    /// queries; the acceptance gate caught it and the approach came out. A
    /// record of what this daemon actually derived cannot make that mistake.
    ///
    /// Operational state beside the pid and port files, never semantic
    /// authority: nothing answers a query from it, and the next daemon checks
    /// every entry against the graph before acting on it.
    pub unpublished_enrichment: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Repo ID resolved once at construction. Cached to avoid re-reading
    /// `.kin/manifest.json` on every snapshot save — under high host
    /// concurrency those reads contend and surface as opaque "Core error"
    /// shutdown-save failures (SP-20).
    pub cached_repo_id: String,
    /// Exact local workspace bound by the manifest at startup. Hosted
    /// storage-backend daemons currently expose repository snapshots rather
    /// than repository-v6 workspace authority and therefore carry `None`.
    cached_workspace_id: Option<WorkspaceId>,
    /// True when the daemon is shutting down.
    pub is_shutdown: AtomicBool,
    /// Entity count of the last graph snapshot successfully written to disk,
    /// seeded from the snapshot loaded at startup. The shutdown flush compares
    /// the live in-memory entity count against this baseline and refuses to
    /// overwrite a large on-disk snapshot with a drastically-collapsed in-memory
    /// graph (the graph-wipe-on-kill class — e.g. a transient empty/bare checkout
    /// reconciled as all-deleted). Keyed on the GRAPH, independent of the vector
    /// index, which self-heals on load. Updated after every successful save.
    pub persisted_entity_count: AtomicU64,
    /// True when the last filesystem-sync tick refused to apply its deletions
    /// because they would have wiped most of the graph-known files (a transient
    /// empty/incomplete checkout misread as "delete everything"). Surfaced as a
    /// daemon-health signal; cleared on the next tick whose deletions are within
    /// the anti-wipe threshold.
    pub mass_deletion_blocked: AtomicBool,
    /// Repository paths that were graph-only members until a transition dropped
    /// them. Host content beneath one was on disk while the member still stood,
    /// so it is pre-existing content rather than something ambient observation
    /// saw arrive, however late the watcher event naming it drains.
    pub retired_graph_only_members: crate::graph_only_members::RetiredGraphOnlyMembers,
    /// Commits inside this daemon right now. The ambient reconcile tick reads it
    /// to avoid publishing a repository-authority successor for a working copy a
    /// commit is already on its way to admit and publish itself.
    pub(crate) pending_commits: crate::pending_commits::PendingCommits,
    /// How long this daemon's last exact-tree publication took, in microseconds,
    /// or zero when it has not published one yet.
    ///
    /// Read by the reconcile tick to size how long it is worth holding off for
    /// an imminent commit: the wait is only ever worth a fraction of the
    /// publication it might save, and that publication is O(store), so its cost
    /// is measured rather than assumed.
    last_authority_publication_micros: AtomicU64,
    /// True when the background embedding worker has permanently stopped (it
    /// exhausted its consecutive-panic budget). The graph/locate/reconcile
    /// surfaces keep serving — embeddings are a DERIVED index — but the vector
    /// index will not advance until the daemon restarts. Surfaced as a
    /// daemon-health signal so this degraded state is LOUD, never silent (the
    /// worker dying must NOT take the whole daemon down).
    pub embed_worker_failed: AtomicBool,
    /// Watches every pass this daemon runs on its own initiative and stops the
    /// ones spending the machine without advancing. The daemon is the only Kin
    /// process on a user's box, so nothing outside it can notice a wedged pass;
    /// this is where that noticing lives.
    pub background_work: Arc<crate::background_work::BackgroundWorkSupervisor>,
    /// The requested complete exact-tree admission this daemon currently has in
    /// flight, if any. Such a pass runs detached from the request that asked for
    /// it, so it needs a home that outlives that request, and a second request
    /// needs somewhere to find it rather than starting a competing pass.
    pub(crate) admission_runs: crate::repository_admit::AdmissionRuns,
    /// Why the views this daemon derives from repository authority stopped
    /// matching it, or `None` when they match.
    ///
    /// Set when an admitted repository transfer became durable and the refresh
    /// of everything derived from it then failed. Authority is the truth and it
    /// moved, so that is not a failed transfer and must not be reported as one.
    /// It is also not nothing: retrieval served from these views is behind
    /// authority until they are rebuilt. Surfaced as a daemon-health signal so
    /// the gap is loud rather than inferred from stale answers.
    pub derived_views_stale: RwLock<Option<String>>,
    /// Durable store for in-flight MCP transactions, keyed by transaction id.
    ///
    /// Each `/mcp/tools/call` rebuilds a fresh `SessionRegistry` for the request,
    /// so transaction state (begin → stage → validate → commit issued across
    /// separate HTTP calls) must live here to survive between calls; sessions and
    /// intents persist through the graph, but transactions have no graph backing.
    pub mcp_transactions: Mutex<HashMap<String, kin_mcp::McpTransaction>>,
    /// Cached locate entity-rankings keyed by paging-cursor key, so `kin locate
    /// --next` (and `semantic_locate` cursors) page a held ranking without
    /// re-running retrieval. Bounded by [`LOCATE_RANKING_CACHE_CAP`].
    pub locate_rankings: Mutex<HashMap<String, CachedLocateRanking>>,
    /// Cached `semantic_locate` result pages keyed by paging-cursor key.
    pub semantic_locate_pages: Mutex<HashMap<String, CachedSemanticPage>>,
}

/// Cached full locate entity-ranking for cursor paging. The daemon caches the
/// FULL ranked entity list once per (query, ref/scope, graph-version, body-mode)
/// so a follow-up page (`kin locate --next`) windows the next slice with no
/// retrieval re-run. `graph_version` is checked on lookup so a stale page (the
/// graph moved under the cursor) is rejected rather than served.
pub struct CachedLocateRanking {
    pub entities: Vec<kin_cli::commands::locate::LocateEntity>,
    /// The fused query variants this ranking was built from, primary first, or
    /// empty when nothing was fused.
    ///
    /// Held with the ranking because a cursor page runs no retrieval and has no
    /// other way back to them. Without it a paged fused response dropped the
    /// variant echo while its hits still named variants one by one, which is why
    /// per-hit attribution could not simply index the response's own list.
    pub queries: Vec<String>,
    pub graph_version: u64,
    /// Which entity projection this ranking was built in
    /// ([`kin_cli::commands::locate::projection_mode`]).
    ///
    /// Checked on lookup, because a cursor token carries the cache KEY and the
    /// client hands it back verbatim: folding the mode into the key stops two
    /// modes from overwriting each other's slot, but it cannot stop a caller from
    /// presenting another mode's key. Without this check, paging a
    /// bodies-carrying ranking with bodies declined returns source the caller
    /// asked not to receive, paging a bodies-less ranking with bodies requested
    /// returns hits with no snippet at all, and paging any ranking with the
    /// no-projection mode returns an empty page.
    ///
    /// A full mode token rather than a bool: `bodies` is false for BOTH the
    /// coordinates-only agent projection and the no-projection legacy path, so a
    /// bool cannot tell a real ranking from an empty one.
    pub mode: &'static str,
    pub created: Instant,
}

/// Cached full `semantic_locate` result rows for cursor paging — the entity-
/// granularity analogue of [`CachedLocateRanking`], holding the already-projected
/// per-entity JSON rows so a follow-up page is a pure window.
pub struct CachedSemanticPage {
    pub rows: Vec<serde_json::Value>,
    pub graph_version: u64,
    /// Which projection these rows were built in. Same reason as
    /// [`CachedLocateRanking::mode`]: the cursor supplies the key, so the mode has
    /// to be verified on lookup rather than only keyed. This arm always projects
    /// rows, so only the two body modes occur here, but it carries the same token
    /// so both caches answer the question the same way.
    pub mode: &'static str,
    pub created: Instant,
}

/// Soft cap on distinct rankings retained for paging; the oldest is evicted past
/// this bound. Paging is a short-lived read-after-read, so a small cache covers
/// the realistic concurrent-cursor count without unbounded growth.
pub const LOCATE_RANKING_CACHE_CAP: usize = 64;

/// Minimum baseline count before an anti-wipe guard can fire. Below this, the
/// set is small enough that a collapse is not catastrophic (and fresh-init /
/// tiny-repo states would false-positive).
pub(crate) const WIPE_GUARD_MIN_BASELINE: u64 = 16;

/// Shared anti-wipe predicate: does dropping from a `baseline` count to a
/// `current` count constitute a drastic collapse (more than ~75% vanished) that
/// a guard should refuse? Returns false for trivially small baselines. Kept pure
/// so the threshold is unit-testable, and shared by both the shutdown graph
/// flush (entity counts) and the fs-sync mass-deletion guard (file counts) so
/// the two stay consistent.
pub(crate) fn graph_collapse_is_wipe(current: u64, baseline: u64) -> bool {
    if baseline < WIPE_GUARD_MIN_BASELINE {
        return false;
    }
    current.saturating_mul(4) < baseline
}

impl DaemonState {
    /// Workspace identity pinned when this local daemon opened repository
    /// authority. Mutation routes must use this instead of reparsing a mutable
    /// working-copy manifest.
    pub(crate) fn local_repository_workspace_id(&self) -> Option<WorkspaceId> {
        self.cached_workspace_id
    }

    /// Clone the startup-pinned local storage capability.
    pub(crate) fn local_repository_backend(&self) -> Option<Arc<LocalFileBackend>> {
        self.local_repository_backend.as_ref().map(Arc::clone)
    }

    /// Clone the complete repository identity/storage capability pinned when
    /// this local daemon started. Daemon-owned CLI and MCP helpers must receive
    /// this binding explicitly instead of rediscovering mutable control files.
    pub(crate) fn local_repository_authority_binding(
        &self,
    ) -> std::result::Result<kin_core::LocalRepositoryAuthorityBinding, DaemonError> {
        let repository_id = RepositoryId::new(self.cached_repo_id.clone()).map_err(|error| {
            DaemonError::Graph(kin_db::KinDbError::StorageError(format!(
                "daemon startup repository identity is invalid: {error}"
            )))
        })?;
        let workspace_id = self.local_repository_workspace_id().ok_or_else(|| {
            DaemonError::Graph(kin_db::KinDbError::StorageError(
                "local daemon is missing its startup workspace binding".to_string(),
            ))
        })?;
        let backend = self.local_repository_backend().ok_or_else(|| {
            DaemonError::Graph(kin_db::KinDbError::StorageError(
                "local daemon is missing its startup storage capability".to_string(),
            ))
        })?;
        Ok(kin_core::LocalRepositoryAuthorityBinding::from_parts(
            repository_id,
            workspace_id,
            backend,
        ))
    }

    /// Open a reusable UTF-8 source view for graph-backed LSP enrichment.
    ///
    /// The live graph selects the exact tree entry; repository-v6 immutable CAS
    /// supplies and verifies its bytes. The working filesystem and the derived
    /// ingestion CAS are never consulted, so a checkout drift or cache loss
    /// cannot silently become semantic-relation authority. The manager is
    /// opened through the startup-pinned storage capability, which refuses a
    /// hosted daemon and preserves KinDB's device/inode root pin.
    pub(crate) fn graph_owned_source_view(&self) -> Result<GraphOwnedSourceView> {
        let authority =
            crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(self)?
                .open()
                .map_err(DaemonError::from)?;
        Ok(GraphOwnedSourceView {
            graph: Arc::clone(&self.graph),
            authority,
        })
    }

    /// Begin one entity/relation authority mutation batch.
    ///
    /// The first epoch edge is published before callers touch the graph; the
    /// guard publishes the closing edge only after their version/root update.
    pub(crate) fn begin_graph_authority_mutation(&self) -> GraphAuthorityMutationGuard {
        let _publication = self
            .graph_authority_clock
            .publication_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.graph_authority_clock
            .active_writers
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |active| {
                active.checked_add(1)
            })
            .expect("graph authority writer count exhausted");
        self.graph_authority_clock
            .epoch
            .fetch_add(1, Ordering::SeqCst);
        // If initialization already crossed its visibility edge, revoke spine
        // completeness before the caller can mutate graph truth. If the spine
        // is not published yet, the same publication gate forces initialization
        // to observe this writer/epoch before it can expose the prepared backend.
        if let Some(spine) = self.spine.get() {
            spine.invalidate_cross_repo_edges(&self.cached_repo_id);
        }
        GraphAuthorityMutationGuard {
            clock: Arc::clone(&self.graph_authority_clock),
        }
    }

    /// Return a stable graph-authority epoch only when no mutation batch spans
    /// the sample. The second writer-count read closes the begin/read race.
    pub(crate) fn stable_graph_authority_epoch(&self) -> Option<u64> {
        if self
            .graph_authority_clock
            .active_writers
            .load(Ordering::SeqCst)
            != 0
        {
            return None;
        }
        let epoch = self.graph_authority_clock.epoch.load(Ordering::SeqCst);
        (self
            .graph_authority_clock
            .active_writers
            .load(Ordering::SeqCst)
            == 0)
            .then_some(epoch)
    }

    /// Revalidate a reader's epoch, including the fast writer that can begin
    /// and finish between two active-writer samples.
    pub(crate) fn graph_authority_epoch_is_current(&self, expected: u64) -> bool {
        if self
            .graph_authority_clock
            .active_writers
            .load(Ordering::SeqCst)
            != 0
        {
            return false;
        }
        let epoch = self.graph_authority_clock.epoch.load(Ordering::SeqCst);
        epoch == expected
            && self
                .graph_authority_clock
                .active_writers
                .load(Ordering::SeqCst)
                == 0
            && self.graph_authority_clock.epoch.load(Ordering::SeqCst) == expected
    }

    pub fn coordination_mode(&self) -> kin_mcp::CoordinationEnforcementMode {
        *self
            .coordination_mode
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn record_coordination_event(
        &self,
        draft: CoordinationEventDraft,
    ) -> std::io::Result<CoordinationEventEnvelope> {
        match self.coordination_events.append(draft) {
            Ok(event) => {
                self.emit_event(DaemonEvent::Coordination {
                    event: event.clone(),
                });
                Ok(event)
            }
            Err(error) => {
                self.mark_coordination_evidence_incomplete(&error);
                Err(error)
            }
        }
    }

    /// Permanently disqualify the current coordination evidence stream after
    /// a reserved mutation cannot be paired with a trustworthy terminal event.
    /// The marker survives daemon restart and is surfaced by `/health`.
    pub(crate) fn mark_coordination_evidence_incomplete(&self, reason: impl std::fmt::Display) {
        let count = self
            .coordination_event_persist_failures
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.coordination_events.persist_failure_count(count);
        warn!(reason = %reason, "coordination evidence is incomplete; stream is not claim-eligible");
    }

    /// Record that a status call completed a live sample, clearing any streak.
    ///
    /// Called at the one site that records a settled reading, so the reset and
    /// the success are the same event and cannot drift apart.
    pub(crate) fn graph_status_live_sample_settled(&self) {
        self.graph_status_live_sample_failures
            .store(0, Ordering::Relaxed);
    }

    /// Record that a status call gave up on a live sample, and return the
    /// streak length including this one.
    pub(crate) fn graph_status_live_sample_abandoned(&self) -> u64 {
        self.graph_status_live_sample_failures
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1)
    }

    /// Whether this daemon can still answer a live question about itself.
    ///
    /// False once the streak crosses the bound, which is what puts the repo
    /// health surface into `attention` while the condition lasts.
    pub fn graph_status_is_answerable(&self) -> bool {
        self.graph_status_live_sample_failures
            .load(Ordering::Relaxed)
            < crate::api::GRAPH_STATUS_UNANSWERABLE_STREAK
    }

    /// Load a persisted vector-index sidecar into a graph that was NOT built
    /// through `SnapshotManager` (the storage-backend path uses
    /// `InMemoryGraph::from_snapshot_with_text_index`, which does not load the
    /// sidecar). Uses kin-db's sanctioned validated entry point, which checks the
    /// sidecar against the graph root hash + live embedder before installing —
    /// never a raw `load_vector_index`, which would install a stale-dimension
    /// index and trigger the embed-worker reset loop. Safely no-ops when there is
    /// no sidecar, a stale one, or no recorded root hash to validate against.
    ///
    /// The `SnapshotManager::open` / `open_read_only_for_locate` path already
    /// performs this validated load during construction, so it does not call this.
    ///
    /// # Reuse is keyed on format, not on the product version
    ///
    /// No build identity is pinned here. Whether previously derived vectors are
    /// reusable is decided entirely by keys that describe the vectors and the
    /// graph, all of which kin-db compares on its own: the sidecar envelope
    /// version, the on-disk index format version, the embedding
    /// provider/model/revision/pipeline-epoch/dimensions, the index's own
    /// self-described model, and the retrieval-authority hash binding it to
    /// graph truth. None of those move when Kin's version does.
    ///
    /// Passing the daemon's build SHA as the expected producer identity made
    /// every upgrade reject the whole index and re-embed the repository from
    /// zero, because that SHA changes on every commit whether or not anything
    /// about embedding did. It is deliberately absent, and the same call in
    /// `require_complete_prepared_embeddings` pins nothing either. Invalidating
    /// deliberately is still available and belongs on the key that describes
    /// the pipeline (kin-db's embedding pipeline epoch), which every persisted
    /// sidecar already carries and every load already checks.
    ///
    /// Returns what the sidecar did, in the two facts the surfaces report: a
    /// discard reason when an index was on disk and was not installed, and a
    /// salvage record when one WAS installed after retiring keys.
    ///
    /// Those two are not alternatives and neither implies the other. A discard
    /// leaves nothing attached and the counters read structurally zero. A
    /// salvage attaches an index and the counters read partial, with no discard
    /// to record, which is exactly the state that used to render identically to
    /// a first fill (FIR-2562).
    fn load_validated_vector_index(
        layout: &KinLayout,
        graph: &kin_db::InMemoryGraph,
    ) -> VectorSidecarOpen {
        let snapshot_path = layout.kindb_snapshot_path();
        let vector_path = layout.kindb_vector_index_path();
        // Sampled BEFORE the load so a discard can be told apart from a repo
        // that simply has no index yet. kin-db reports both as not attached,
        // and announcing the second would fire this on every fresh repository.
        let had_persisted_index = vector_path.exists();
        let outcome = kin_db::SnapshotManager::load_vector_index_into_graph_if_valid(
            graph,
            &snapshot_path,
            None,
        );
        let discarded = match outcome {
            Ok(outcome) if outcome.attached => {
                // Attached, so nothing was discarded. What matters now is
                // whether it attached WHOLE or after retiring keys, because
                // only the second explains a shortfall the counters are about
                // to show. The counts come from kin-db's own reconcile rather
                // than being recomputed here.
                let salvage = salvage_from_sidecar_outcome(&outcome);
                if let Some(record) = salvage {
                    // Loud, because this is coverage a user had and no longer
                    // has. The cause is stated as what was observed, a stamp
                    // that drifted from graph authority, and no further cause
                    // is asserted: an ordinary commit between flush and reopen
                    // drifts the same stamp with nothing wrong.
                    warn!(
                        path = %vector_path.display(),
                        kept = record.kept,
                        dropped = record.dropped,
                        "the persisted vector index no longer matched this repository's graph \
                         authority, so it was salvaged per key rather than rebuilt; the retired \
                         keys re-embed in the background"
                    );
                } else {
                    debug!(path = %snapshot_path.display(), "loaded validated persisted vector index");
                }
                return VectorSidecarOpen {
                    discarded: None,
                    salvage,
                };
            }
            Ok(_) if !had_persisted_index => return VectorSidecarOpen::default(),
            Ok(_) => format!(
                "the persisted vector index at {} no longer matches this repository's graph or \
                 embedding model, so it was not loaded",
                vector_path.display()
            ),
            Err(error) => format!(
                "the persisted vector index at {} could not be read ({error}), so it was not loaded",
                vector_path.display()
            ),
        };
        // Not "embedded again from scratch": the sidecar is preserved on disk,
        // and the recovery pass answers unchanged texts from the embedder's
        // persistent EmbeddingCache, forwarding only misses. A dirty-restart
        // repro on v0.5.23 watched a discarded index restore full coverage
        // with zero embed dispatches, so promising a full GPU rebuild here
        // overstated the cost and sent operators to run an embed pass nobody
        // needed.
        warn!(
            path = %vector_path.display(),
            "{discarded}; the daemon restores coverage in the background and reuses prior \
             vectors where they still apply. Run `kin health` to watch coverage recover, or \
             `kin embed` to force a rebuild now."
        );
        VectorSidecarOpen {
            discarded: Some(discarded),
            salvage: None,
        }
    }

    /// Why the persisted vector index retired coverage at open, when it did.
    ///
    /// Reported beside `vector_index_discarded` rather than folded into it,
    /// because the two describe different stores: a discard leaves nothing
    /// attached, a salvage leaves a partial index attached with no discard to
    /// record. Collapsing them is the defect FIR-2562 names.
    pub fn vector_index_salvage(&self) -> Option<crate::VectorSalvage> {
        self.vector_index_salvage
    }

    /// Why the persisted vector index was not installed at open, when it was
    /// there and was not. Reported by `/health` and by semantic-query readiness
    /// so a coverage counter that restarted at zero comes with its reason.
    pub fn vector_index_discarded(&self) -> Option<&str> {
        self.vector_index_discarded.as_deref()
    }

    /// Whether this store's embedding coverage has ever been whole.
    ///
    /// A first fill and a top-up after a completed fill produce the same
    /// partial coverage counters, and only the second means the semantic
    /// surface was ready and stopped being ready. Readiness reporting has to
    /// tell them apart, so the daemon publishes a marker where coverage
    /// completes and this reads it back.
    ///
    /// Read from disk rather than latched in memory, so a daemon that restarts
    /// part-way through a fill still knows what earlier runs of this store
    /// finished. The cost is one stat on a path taken once per embed interval
    /// and once per readiness probe.
    pub fn embedding_coverage_ever_complete(&self) -> bool {
        self.layout.kindb_embedding_coverage_marker_path().exists()
    }

    /// Publish the batch size the background embedding queue will run with.
    /// Called once by the daemon runtime after it resolves its configuration.
    pub fn publish_embed_batch_size(&self, size: usize) {
        self.embed_batch_size.store(size, Ordering::Relaxed);
    }

    /// The background embedding queue's batch size, or `None` when the daemon
    /// has not published one yet. Absent and zero are different answers.
    pub fn embed_batch_size(&self) -> Option<usize> {
        match self.embed_batch_size.load(Ordering::Relaxed) {
            0 => None,
            size => Some(size),
        }
    }

    /// Publish the has-ever-completed marker if embedding coverage is now whole.
    ///
    /// Called where the background embedding queue drains. The write is
    /// idempotent, and a failure is deliberately not fatal: without the marker
    /// a store that lost coverage reads as one still filling for the first
    /// time, which understates a recoverable state instead of reporting a
    /// working install as broken. The state that must stay loud — a discarded
    /// vector index — is keyed on the discard reason rather than on this
    /// marker, so it is unaffected either way.
    pub fn record_embedding_coverage_complete(&self) {
        let status = self.graph.embedding_status();
        if !Self::coverage_is_whole(status.indexed, status.pending, status.total) {
            return;
        }
        let marker = self.layout.kindb_embedding_coverage_marker_path();
        if marker.exists() {
            return;
        }
        if let Err(error) = Self::write_embedding_coverage_marker(&marker) {
            debug!(
                path = %marker.display(),
                %error,
                "could not publish the embedding-coverage marker; readiness will keep reporting a first fill"
            );
        }
    }

    /// Publish the has-ever-completed marker for an explicit pass that drained
    /// its queue.
    ///
    /// The re-read in `record_embedding_coverage_complete` is a snapshot taken
    /// after the fact, and on a working copy that is still being written to,
    /// new files can be admitted between a pass draining and the marker being
    /// written. The snapshot then reads partial, no marker is published, and a
    /// store whose fill demonstrably finished goes on reporting a first fill
    /// forever. The pass's own report is the durable evidence, so a caller that
    /// holds it records the completion directly rather than asking the counters
    /// again and losing the race.
    pub fn record_embedding_pass_drained(&self) {
        let marker = self.layout.kindb_embedding_coverage_marker_path();
        if marker.exists() {
            return;
        }
        if let Err(error) = Self::write_embedding_coverage_marker(&marker) {
            debug!(
                path = %marker.display(),
                %error,
                "could not publish the embedding-coverage marker; readiness will keep reporting a first fill"
            );
        }
    }

    /// Whether a coverage snapshot describes a fill that actually finished.
    ///
    /// An empty store is excluded deliberately: it has not finished a fill, it
    /// has never had one to finish, and treating it as covered would let a
    /// store claim ground it never held the moment its first entity arrives.
    /// This is the exact complement of the whole-coverage arm readiness reports
    /// as healthy, so the marker cannot disagree with the counters beside it.
    fn coverage_is_whole(indexed: usize, pending: usize, total: usize) -> bool {
        total > 0 && pending == 0 && indexed == total
    }

    fn write_embedding_coverage_marker(marker: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;

        let parent = marker.parent().ok_or_else(|| {
            std::io::Error::other("embedding-coverage marker path has no parent directory")
        })?;
        std::fs::create_dir_all(parent)?;
        let tmp_path = marker.with_extension(format!("tmp-{}", std::process::id()));
        {
            let mut file = std::fs::File::create(&tmp_path)?;
            file.write_all(b"complete\n")?;
            file.sync_all()?;
        }
        if let Err(error) = std::fs::rename(&tmp_path, marker) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(error);
        }
        sync_directory_metadata(parent)
    }

    fn spine_disabled_from_env() -> bool {
        std::env::var("KIN_DISABLE_SPINE")
            .ok()
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    }

    fn locate_only_snapshot_mode() -> bool {
        std::env::var("KIN_DAEMON_LOCATE_ONLY")
            .ok()
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    }

    /// Load the persisted VFS version counter from `.kin/vfs_version`.
    /// Returns 0 if the file doesn't exist or can't be parsed.
    fn load_persisted_vfs_version(layout: &KinLayout) -> u64 {
        let path = layout.root().join("vfs_version");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0)
    }

    /// Open an existing .kin/ directory and create daemon state.
    pub fn open(layout: KinLayout) -> Result<Self> {
        let explicit_repo_id = std::env::var("KIN_REPO_ID")
            .ok()
            .or_else(|| std::env::var("KIN_PRIMARY_REPO_ID").ok());
        Self::open_with_repo_id(layout, explicit_repo_id.as_deref())
    }

    /// Hydrate the daemon's non-authoritative ingestion/projection CAS from one
    /// exact graph-owned workspace tree.
    ///
    /// Repository CAS remains the only source authority. This cache is rebuilt
    /// exclusively from verified repository bytes; it never repairs from Git,
    /// a checkout, or the working filesystem.
    fn hydrate_ingest_cas<B: StorageBackend + ?Sized + 'static>(
        authority: &RepositoryAuthorityManager<B>,
        tree: &ResolvedTree,
        blobs: &BlobStore,
    ) -> Result<usize> {
        let mut hydrated = HashSet::new();
        for artifact in tree.artifacts() {
            let Some(hash) = artifact.entry.blob_identity() else {
                // Gitlinks identify another repository commit and deliberately
                // carry no local source body.
                continue;
            };
            if !hydrated.insert(hash) {
                continue;
            }
            // Consult the local cache before reaching for authority. Both sides
            // verify content addresses -- `BlobStore::read` re-digests what it
            // read and `load_source_blob` verifies what it fetched -- so a
            // successful local read already proves the cached bytes are the
            // authoritative bytes, and comparing them would only be comparing a
            // value to itself.
            //
            // The ordering is not a micro-optimization. On a hosted backend
            // every `load_source_blob` is a HEAD plus a GET, serialized, and
            // this runs before the listener binds, so fetching first cost two
            // round trips per blob on every open even when the cache was
            // already complete. At ten thousand bodies that is long enough for
            // a readiness probe to kill a daemon that is working correctly, and
            // the restart repeats it: a crash loop that never converges.
            match blobs.read(&hash) {
                Ok(_) => continue,
                Err(BlobError::NotFound { .. } | BlobError::HashMismatch { .. }) => {
                    // HashMismatch quarantines the corrupt derived object, so
                    // the write below can atomically heal it from authority.
                }
                Err(error) => return Err(DaemonError::Blob(error)),
            }

            let authoritative = authority.load_source_blob(hash)?.ok_or_else(|| {
                DaemonError::Graph(kin_db::KinDbError::StorageError(format!(
                    "workspace artifact {} references source body {} absent from repository authority",
                    artifact.path, hash
                )))
            })?;

            let installed_hash = blobs.write(&authoritative)?;
            if installed_hash != hash {
                return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                    format!(
                        "repository authority body {} hydrated under unexpected derived CAS identity {}",
                        hash, installed_hash
                    ),
                )));
            }
            let installed = blobs.read(&hash)?;
            if installed != authoritative {
                return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                    format!(
                        "derived ingestion CAS did not retain exact repository authority body {}",
                        hash
                    ),
                )));
            }
        }
        // Hydration is a bulk import: the store defers each blob's directory
        // barrier and amortizes them across shards, so one commit point here
        // makes every name it just installed durable for the cost of at most
        // one barrier per shard touched.
        blobs.sync().map_err(DaemonError::from)?;
        Ok(hydrated.len())
    }

    /// Hydrate the derived ingestion CAS for a graph opened through a storage
    /// backend.
    ///
    /// The local path hydrates from repository authority so every blob the
    /// projection later reads is present before the daemon serves anything.
    /// The backend path reads the same store through `rebuild_projection` and
    /// `refresh_projection` but used to open against whatever happened to be
    /// on local disk, which on a fresh hosted instance is nothing.
    ///
    /// Returns the number of source bodies hydrated, or the reason the hosted
    /// backend could not supply them. A graph with no resolved artifacts needs
    /// no authority at all, which is the ordinary empty-hosted-graph case.
    ///
    /// Opening the authority is itself expensive on a hosted backend: it
    /// re-downloads the repository snapshot that `open_with_backend` has
    /// already loaded, and kin-db may replay the whole history to validate it.
    /// So the cheap local question is asked first, and an instance whose
    /// derived cache already covers the tree never opens authority at all.
    fn hydrate_backend_ingest_cas(
        repo_id: &str,
        backend: &Arc<dyn StorageBackend>,
        graph: &kin_db::InMemoryGraph,
        blobs: &BlobStore,
    ) -> std::result::Result<usize, String> {
        let tree = graph.resolved_tree();
        if tree.is_empty() {
            return Ok(0);
        }
        if Self::ingest_cas_covers_tree(&tree, blobs).map_err(|error| error.to_string())? {
            return Ok(0);
        }
        let repository_id = RepositoryId::new(repo_id.to_string())
            .map_err(|error| format!("invalid repository identity {repo_id}: {error}"))?;
        let authority = RepositoryAuthorityManager::open(repository_id, Arc::clone(backend))
            .map_err(|error| {
                format!("hosted backend carries no usable repository authority: {error}")
            })?;
        Self::hydrate_ingest_cas(&authority, &tree, blobs).map_err(|error| error.to_string())
    }

    /// Whether every source body the tree names is already readable from the
    /// derived cache. Purely local: `BlobStore::read` verifies what it read
    /// against the requested content address, so a clean pass is proof the
    /// cache holds the authoritative bodies and no authority is needed.
    fn ingest_cas_covers_tree(tree: &ResolvedTree, blobs: &BlobStore) -> Result<bool> {
        for artifact in tree.artifacts() {
            let Some(hash) = artifact.entry.blob_identity() else {
                continue;
            };
            match blobs.read(&hash) {
                Ok(_) => {}
                Err(BlobError::NotFound { .. } | BlobError::HashMismatch { .. }) => {
                    return Ok(false)
                }
                Err(error) => return Err(DaemonError::Blob(error)),
            }
        }
        Ok(true)
    }

    /// Whether every registry row naming a live local repository was pinned at
    /// startup.
    ///
    /// A distinct question from the spine's own edge-authority completeness, and
    /// the two must be reported side by side rather than collapsed. The spine's
    /// reading goes false for a refresh in flight as readily as for an authority
    /// that is short; this one is false only when the startup pass could not
    /// bind a repository the registry named, which is the condition that leaves
    /// cross-repo answers empty for the rest of the process's life.
    pub fn startup_authority_complete(&self) -> bool {
        !self.registered_local_repository_authority_incomplete
    }

    /// Freeze local sibling authority capabilities before the daemon becomes
    /// externally visible.
    ///
    /// Registry and manifest reads are startup configuration IO. Request-time
    /// spine initialization receives only retained identity/storage bindings,
    /// so a registry edit or storage-root replacement cannot silently change
    /// the daemon's authority set.
    ///
    /// **The manifest names the repository; the registry only points at it.**
    /// This used to refuse a sibling whose registry id differed from its
    /// manifest's `repo_id`. The two are written by different producers in
    /// different alphabets: the manifest mints a UUID (`KinManifest::new`) and
    /// the registry records the directory name (`kin_migrate::update_registry`,
    /// which is what `kin init` calls). A UUID is never a directory name, so the
    /// comparison could not pass for any repository on any host, and cross-repo
    /// spine authority has been empty since it landed. One refused sibling also
    /// sets `incomplete`, which invalidates the cross-repo edges of every
    /// registered repo including the primary, so the cost was the whole edge set
    /// rather than one absent sibling.
    ///
    /// Reading the manifest is strictly the safer of the two. The registry is a
    /// file a user can edit and a stale row can point at a path holding a
    /// different repository entirely; the manifest is read from the path that is
    /// actually there, so the identity always describes what was actually
    /// opened. The registry id is kept only to name the row in a log.
    ///
    /// Two rows resolving to one repository identity is the one case this still
    /// refuses. It means two registry paths hold the same repository, a copied
    /// checkout being the usual cause, and registering both would silently let
    /// one overwrite the other's graph authority under the same spine key.
    fn pin_registered_local_repository_authorities(
        layout: &KinLayout,
    ) -> (Vec<RegisteredLocalRepositoryAuthority>, bool) {
        let registry = match kin_core::registry::KinRegistry::load() {
            Ok(registry) => registry,
            Err(error) => {
                error!(
                    error = %error,
                    "registry authority refused at daemon startup; local spine authority will remain incomplete"
                );
                return (Vec::new(), true);
            }
        };
        let registry_rows = registry.repos.len();
        let current_kin_root = layout
            .root()
            .canonicalize()
            .unwrap_or_else(|_| layout.root().to_path_buf());
        let mut pinned: Vec<RegisteredLocalRepositoryAuthority> = Vec::new();
        let mut pinned_identities = HashSet::new();
        let mut failures = StartupPinFailures::default();
        let mut self_rows_skipped = 0usize;
        let mut adopted_identities = 0usize;

        for repo in registry.repos {
            let repo_root = repo
                .path
                .canonicalize()
                .unwrap_or_else(|_| repo.path.clone());
            if repo_root == current_kin_root || current_kin_root.starts_with(&repo_root) {
                self_rows_skipped += 1;
                continue;
            }

            let sibling_layout = KinLayout::new(repo.path.join(".kin"));
            let binding =
                match kin_core::LocalRepositoryAuthorityBinding::from_layout(&sibling_layout) {
                    Ok(binding) => binding,
                    Err(error) => {
                        failures.record_binding_failure(&repo.id, &repo.path, &error);
                        continue;
                    }
                };
            let manifest_repo_id = binding.repository_id().as_str().to_string();
            if !pinned_identities.insert(manifest_repo_id.clone()) {
                failures.record_duplicate_identity(&repo.id, &repo.path, &manifest_repo_id);
                continue;
            }
            if manifest_repo_id != repo.id {
                adopted_identities += 1;
                debug!(
                    registry_id = %repo.id,
                    path = %repo.path.display(),
                    manifest_repo_id = %manifest_repo_id,
                    "registry row names the repository by a label; pinning its manifest identity"
                );
            }
            pinned.push(RegisteredLocalRepositoryAuthority {
                repo_id: manifest_repo_id,
                binding,
            });
        }

        if adopted_identities > 0 {
            info!(
                adopted = adopted_identities,
                pinned = pinned.len(),
                "pinned sibling authorities under their manifest identities"
            );
        }

        failures.emit_summary(registry_rows, self_rows_skipped, pinned.len());

        (pinned, failures.refused > 0)
    }

    /// Open local daemon state with a repository identity already resolved by
    /// the process entrypoint. Local overrides must name the manifest's exact
    /// authority; they cannot rebind one workspace to another repository.
    pub fn open_with_repo_id(layout: KinLayout, explicit_repo_id: Option<&str>) -> Result<Self> {
        let mut phases = OpenPhases::begin();

        // Layout gate first. A pre-v2 `.kin/` (file/branch-authority era) must
        // be refused before any manifest or storage parsing runs: its manifest
        // may predate required fields and its storage holds no repository
        // namespace, so letting either path speak first buries the real story
        // under a serde or storage error instead of the version gap.
        if let Err(error) = layout.check_version() {
            // The remedy has to be one `kin init` will actually honor. Sending
            // the reader to a fresh checkout read as sound advice and was not:
            // `kin init` refuses over an existing store, so the instruction
            // dead-ended in the working tree the reader was standing in.
            return Err(DaemonError::IncompatibleRepo(format!(
                "{error}. This repository was created before the \
                 repository-authority layout change and there is no in-place \
                 upgrade. Remove .kin/ and run `kin init` to rebuild the store \
                 from the repository's Git history, or open it with a matching \
                 older kin."
            )));
        }

        // Up-front compatibility gate. A repo created by a pre-0.2 kin carries
        // an on-disk graph/index that this build's post-load embed/readiness
        // path cannot serve. Without this gate the daemon loads the snapshot,
        // then readiness never arrives and the CLI supervisor kills the process
        // with a bare SIGTERM — opaque to the user. Refuse here, before opening
        // kin-db or starting the embed worker, with an actionable error naming
        // the version gap and the rebuild commands.
        match kin_core::manifest::check_manifest_compatibility(&layout.manifest_path())
            .map_err(DaemonError::from)?
        {
            kin_core::manifest::ManifestCompatibility::Compatible => {}
            incompatible => {
                if let Some(message) = incompatible.incompatibility_message() {
                    return Err(DaemonError::IncompatibleRepo(message));
                }
            }
        }

        // Reclaim stale daemon/runtime locks left by a dead process. Acts only
        // on a recorded owner that is present and dead, so a live daemon's
        // locks are never touched; every declining outcome is logged by the
        // reclaim itself rather than silently swallowed here.
        let _ = crate::lifecycle::reclaim_stale_locks(layout.root());

        // Resolve repository identity before opening any graph state. The
        // repository-v6 envelope is the only local startup authority; the old
        // standalone graph.kndb snapshot is not a fallback.
        let cached_repo_id = kin_core::manifest::resolve_repo_id(&layout, explicit_repo_id)
            .map_err(DaemonError::from)?;
        let mut manifest = kin_core::manifest::KinManifest::load(&layout.manifest_path())
            .map_err(DaemonError::from)?;
        if manifest.repo_id != cached_repo_id {
            return Err(DaemonError::Core(kin_core::KinError::Config(format!(
                "local repository override {} does not match manifest authority {}; open the matching repository instead",
                cached_repo_id, manifest.repo_id
            ))));
        }
        // A manifest that lost its `workspace_id` (or predates the field on a
        // current layout) is healed after authority opens, by recovering the
        // identity the storage authority already registered at admission.
        // Minting a fresh one here would diverge from that registration and be
        // refused downstream, so an absent identity defers resolution.
        let manifest_workspace_id = match manifest.workspace_id.trim() {
            "" => None,
            recorded => Some(
                uuid::Uuid::parse_str(recorded)
                    .map(WorkspaceId::from_uuid)
                    .map_err(|error| {
                        DaemonError::Core(kin_core::KinError::Config(format!(
                            "invalid workspace identity in manifest: {error}"
                        )))
                    })?,
            ),
        };
        let repository_id = RepositoryId::new(cached_repo_id.clone()).map_err(|error| {
            DaemonError::Core(kin_core::KinError::Config(format!(
                "invalid repository identity in manifest: {error}"
            )))
        })?;
        let local_repository_backend = Arc::new(LocalFileBackend::new(layout.kindb_dir()));
        let spine_disabled = Self::spine_disabled_from_env();
        let (
            registered_local_repository_authorities,
            registered_local_repository_authority_incomplete,
        ) = if spine_disabled {
            (Vec::new(), false)
        } else {
            Self::pin_registered_local_repository_authorities(&layout)
        };
        // Startup is a reopen of an initialized repository, never construction
        // of an unpersisted generation-zero authority. Use the receipt from
        // this same recovery to refuse an intact namespace whose authority
        // record disappeared without paying for a second load or lock.
        let (authority, _authority_payload_stats) = phases
            .record("authority_open", || {
                kin_core::open_persisted_local_repository_authority(
                    repository_id.clone(),
                    Arc::clone(&local_repository_backend),
                )
            })
            .map_err(DaemonError::Graph)?;
        // Startup latency on a large repository is dominated by whether this
        // open replayed the whole history or trusted a durable validation of
        // the exact bytes it loaded. Record which path ran so an operator can
        // diagnose a slow reopen from persisted logs.
        info!(
            repository = %repository_id,
            by_history_validation = authority.opened_by_history_validation(),
            "opened repository authority"
        );
        // Opening authority above is what retains the per-repository storage
        // capability on this backend. Prove the pin took before serving any
        // request from it: a daemon that cannot revalidate its own namespace
        // must refuse to start rather than run unpinned, because every later
        // authority bind treats whatever is retained as the baseline.
        kin_core::revalidate_pinned_local_namespace(&local_repository_backend, &repository_id)
            .map_err(|refusal| DaemonError::Graph(refusal.into_error()))?;
        let lease = authority.read_authority();
        let workspace_id = match manifest_workspace_id {
            Some(recorded) => recorded,
            None => {
                // Recover the identity the authority registered at admission.
                // Exactly one registered workspace names it unambiguously;
                // anything else cannot be disambiguated and must be refused.
                let registered = &lease.metadata().workspaces;
                match registered.as_slice() {
                    [only] => {
                        let recovered = only.workspace_id;
                        manifest.workspace_id = recovered.to_string();
                        manifest
                            .save(&layout.manifest_path())
                            .map_err(DaemonError::from)?;
                        info!(
                            repository = %cached_repo_id,
                            workspace = %recovered,
                            "restored missing manifest workspace identity from repository authority"
                        );
                        recovered
                    }
                    [] => {
                        return Err(DaemonError::IncompatibleRepo(format!(
                            "manifest for repository {cached_repo_id} carries no workspace \
                             identity and the repository authority holds no registered \
                             workspace to recover it from; re-create the repository with \
                             `kin clone` or `kin init`, or restore .kin/manifest.json from \
                             a backup"
                        )));
                    }
                    many => {
                        return Err(DaemonError::IncompatibleRepo(format!(
                            "manifest for repository {cached_repo_id} carries no workspace \
                             identity and the repository authority holds {} registered \
                             workspaces; restore .kin/manifest.json from a backup so the \
                             identity is unambiguous",
                            many.len()
                        )));
                    }
                }
            }
        };
        let workspace_snapshot = phases
            .record("workspace_snapshot", || {
                lease.workspace_graph_snapshot(&workspace_id)
            })
            .map_err(DaemonError::Graph)?
            .ok_or_else(|| {
                DaemonError::Graph(kin_db::KinDbError::StorageError(format!(
                    "repository {} authority has no manifest workspace {}",
                    repository_id, workspace_id
                )))
            })?;
        let text_index_path = layout.text_index_dir();
        let locate_only = Self::locate_only_snapshot_mode();
        let generation = lease.roots().generation;
        let loaded_snapshot = generation > 0;
        let workspace_artifact_count = workspace_snapshot.resolved_tree.len();
        let blobs = BlobStore::new(layout.ingest_cas_dir()).map_err(DaemonError::from)?;
        let hydrated_source_bodies = phases.record("cas_hydrate", || {
            Self::hydrate_ingest_cas(&authority, &workspace_snapshot.resolved_tree, &blobs)
        })?;
        let graph = phases
            .record("graph_text_index", || {
                if locate_only {
                    kin_db::InMemoryGraph::from_snapshot_with_text_index_read_only(
                        workspace_snapshot,
                        text_index_path.clone(),
                    )
                } else {
                    kin_db::InMemoryGraph::from_snapshot_with_text_index(
                        workspace_snapshot,
                        text_index_path.clone(),
                    )
                }
            })
            .map(Arc::new)
            .map_err(DaemonError::Graph)?;
        info!(
            repository = %cached_repo_id,
            workspace = %workspace_id,
            generation,
            locate_only,
            workspace_artifacts = workspace_artifact_count,
            hydrated_source_bodies,
            "loaded daemon query graph from workspace-scoped repository-v6 authority"
        );
        drop(lease);
        drop(authority);

        // The repository snapshot above is authoritative. Vector/text
        // structures built from it are derived query surfaces only.
        //
        // `from_snapshot_with_text_index` restores the text index but not the
        // vector sidecar, so without this the reopened repository reports every
        // entity as unembedded and re-derives an index it already has on disk.
        let sidecar_open = phases.record("vector_index", || {
            Self::load_validated_vector_index(&layout, graph.as_ref())
        });

        let mut reconciler = Reconciler::new(layout.working_dir().to_path_buf());
        // Seed LKG from persisted graph so the first reconcile after daemon
        // startup only reports truly changed entities, not all of them.
        phases.record("lkg_seed", || {
            reconciler.seed_lkg_entities_from_graph(graph.as_ref())
        });
        // Index the cross-file linker's entity universe from the same snapshot.
        // Without it every live reconcile resolves against an empty universe,
        // reports every destination missing, and the graph keeps intra-file
        // edges only. One pass here; every write after it is bounded by the
        // edited file rather than by repository size.
        phases.record("cross_file_seed", || {
            reconciler.seed_cross_file_linker_from_graph(graph.as_ref())
        });

        // Wire the traffic checker so reconcile mutations are gated by active
        // intents/leases. Without this, check_scopes() in the reconciler
        // returns empty warnings and all mutations proceed unchecked.
        let traffic_checker =
            crate::traffic_adapter::CoordinatorTrafficChecker::new(Arc::clone(&graph));
        reconciler.set_traffic_checker(Box::new(traffic_checker));

        let coordinator = SessionCoordinator::new(Arc::clone(&graph));

        // Resume from the last persisted VFS version so kin-vfs clients
        // don't see a reset after daemon restart.
        let persisted_vfs_version = Self::load_persisted_vfs_version(&layout);

        // Baseline for the shutdown anti-wipe guard: the entity count loaded
        // from the on-disk snapshot. Read before `graph` is moved into the state.
        let loaded_entity_count = graph.entity_count();

        let coordination_events = CoordinationEventLog::open(&layout, &cached_repo_id)?;
        let coordination_event_persist_failures = coordination_events.persisted_failure_count();
        let mut state = Self {
            layout,
            graph,
            blobs: Arc::new(blobs),
            ingest_cas_hydration_gap: None,
            vector_index_discarded: sidecar_open.discarded,
            vector_index_salvage: sidecar_open.salvage,
            reconciler: RwLock::new(reconciler),
            projection: RwLock::new(ProjectionState::new()),
            coordinator,
            coordination_gate: tokio::sync::Mutex::new(()),
            graph_authority_clock: Arc::new(GraphAuthorityClock::default()),
            coordination_mode: std::sync::RwLock::new(
                kin_mcp::CoordinationEnforcementMode::from_env(),
            ),
            coordination_events,
            coordination_event_persist_failures: AtomicU64::new(
                coordination_event_persist_failures,
            ),
            started_at: Instant::now(),
            is_initialized: AtomicBool::new(loaded_snapshot),
            reconciliation_status: AtomicU8::new(RECON_IDLE),
            storage_backend: None,
            hosted_authority_envelope: false,
            hosted_authority_flush_refusals: AtomicU64::new(0),
            local_repository_backend: Some(local_repository_backend),
            projection_authority: crate::api::ProjectionAuthorityCache::default(),
            registered_local_repository_authorities,
            registered_local_repository_authority_incomplete,
            spine_disabled,
            eager_sibling_bound: Self::eager_sibling_load_bound(),
            sibling_capture: std::sync::OnceLock::new(),
            filesystem_reconcile_disabled: AtomicBool::new(
                crate::loop_runner::filesystem_reconcile_disabled_at_startup(false),
            ),
            snapshot_generation: AtomicU64::new(generation),
            post_commit_finalization_pending: AtomicBool::new(false),
            #[cfg(test)]
            finalization_fail_once: AtomicBool::new(false),
            #[cfg(test)]
            mcp_fail_after_authority_once: AtomicBool::new(false),
            #[cfg(test)]
            repository_command_fail_after_authority_once: AtomicBool::new(false),
            #[cfg(test)]
            repository_command_enrich_after_authority_once: AtomicBool::new(false),
            vfs_version: AtomicU64::new(persisted_vfs_version),
            event_tx: tokio::sync::broadcast::channel(256).0,
            session_scopes: RwLock::new(HashMap::new()),
            spine: std::sync::OnceLock::new(),
            spine_initialization: Mutex::new(()),
            spine_warming: AtomicBool::new(false),
            background_work: Arc::new(crate::background_work::BackgroundWorkSupervisor::default()),
            admission_runs: crate::repository_admit::AdmissionRuns::default(),
            #[cfg(test)]
            spine_initialization_test_hook: Mutex::new(None),
            #[cfg(all(test, feature = "embeddings"))]
            vector_checkpoint_reopen_test_hook: Mutex::new(None),
            spine_refresh_gate: tokio::sync::Mutex::new(()),
            repo_graphs: RwLock::new(HashMap::new()),
            allowed_repo_ids: None,
            dirty: AtomicBool::new(false),
            mutation_epoch: AtomicU64::new(0),
            embedding_work: Mutex::new(()),
            embed_batch_size: AtomicUsize::new(0),
            graph_status_settled: crate::api::GraphStatusSettledCache::default(),
            graph_status_live_sample_failures: AtomicU64::new(0),
            persist_lock: Mutex::new(()),
            #[cfg(feature = "embeddings")]
            vector_checkpoint_authority_match: VectorCheckpointAuthorityMatch::default(),
            #[cfg(feature = "embeddings")]
            deferred_vector_checkpoint: std::sync::Mutex::new(None),
            last_save: std::sync::Mutex::new(Instant::now()),
            last_mutation: std::sync::Mutex::new(Instant::now()),
            active_embed_passes: AtomicU32::new(0),
            background_embed_paused: AtomicBool::new(false),
            last_activity_ms: AtomicU64::new(0),
            idle_timeout_ms: AtomicU64::new(0),
            active_requests: AtomicU64::new(0),
            lsp_enrichment_tx: None,
            lsp_enrichment_enabled: false,
            lsp_sweep_files_done: AtomicU64::new(0),
            lsp_sweep_files_total: AtomicU64::new(0),
            lsp_sweep_files_blocked: AtomicU64::new(0),
            lsp_sweeps_completed: AtomicU64::new(0),
            lsp_sweep_running: AtomicBool::new(false),
            lsp_enriched_files: std::sync::Mutex::new(std::collections::HashSet::new()),
            unpublished_enrichment: std::sync::Mutex::new(std::collections::HashSet::new()),
            cached_repo_id,
            cached_workspace_id: Some(workspace_id),
            is_shutdown: AtomicBool::new(false),
            durable_entity_count: AtomicU64::new(loaded_entity_count as u64),
            persisted_entity_count: AtomicU64::new(loaded_entity_count as u64),
            mass_deletion_blocked: AtomicBool::new(false),
            retired_graph_only_members: Default::default(),
            pending_commits: Default::default(),
            last_authority_publication_micros: AtomicU64::new(0),
            embed_worker_failed: AtomicBool::new(false),
            derived_views_stale: RwLock::new(None),
            mcp_transactions: Mutex::new(HashMap::new()),
            locate_rankings: Mutex::new(HashMap::new()),
            semantic_locate_pages: Mutex::new(HashMap::new()),
        };
        // Restore in-flight MCP transactions persisted before a restart
        // so staged-but-uncommitted work is not silently dropped across a daemon
        // bounce — stdio-MCP and HTTP-MCP behave identically across a restart.
        *state
            .mcp_transactions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            load_persisted_mcp_transactions(&state.layout);
        state
            .repo_graphs
            .get_mut()
            .insert(state.cached_repo_id.clone(), Arc::clone(&state.graph));

        // The loaded graph is the validated durable generation and the state
        // is not externally visible yet. Heal derived artifacts directly from
        // it; reopening would duplicate the full graph at peak startup memory.
        // Locate-only graphs deliberately omit non-locate relations, so they
        // may advance the freshness marker but must never replace the canonical
        // general-purpose read index with a partial one.
        if loaded_snapshot {
            if locate_only {
                phases.record("read_index", || {
                    state.finalize_loaded_locate_generation(generation)
                })?;
            } else if Self::durable_read_index_matches_generation(&state.layout, generation) {
                // The durable index and marker already describe this exact
                // generation, so rebuilding them would write the same bytes
                // back. `persisted_entity_count` was constructed from the same
                // graph the rebuild would have counted and
                // `post_commit_finalization_pending` is already false, so the
                // skip leaves state identical to a successful finalize.
                phases.skipped("read_index");
            } else {
                state
                    .post_commit_finalization_pending
                    .store(true, Ordering::SeqCst);
                phases.record("read_index", || {
                    state.finalize_loaded_generation(generation)
                })?;
            }
        }
        state.register_daemon_system_session();
        phases.emit(&state.cached_repo_id, &state.layout);
        Ok(state)
    }

    /// Open with a pluggable storage backend (GCS, local files, etc.).
    ///
    /// Loads hosted graph authority from `backend.load_snapshot(repo_id)`.
    /// Local repositories use repository-v6 through [`Self::open`]; this path
    /// is reserved for cloud deployments whose snapshots live in GCS.
    pub fn open_with_backend(
        layout: KinLayout,
        backend: Box<dyn StorageBackend>,
        repo_id: &str,
        allowed_repo_ids: Option<HashSet<String>>,
    ) -> Result<Self> {
        let text_index_path = layout.text_index_dir();
        let (graph, generation, loaded_snapshot, hosted_authority_envelope) =
            match kin_db::load_recovered_snapshot(backend.as_ref(), repo_id)
                .map_err(DaemonError::from)?
            {
                Some(recovered) => {
                    // Read before the move: `from_snapshot_with_text_index`
                    // discards this field by design, because the envelope is
                    // owned by the publication manager and never by the
                    // in-place mutable graph. This is the last point at which
                    // the daemon can see whether the object it opened is one
                    // an envelope-free write would erase.
                    let hosted_authority_envelope =
                        recovered.snapshot.repository_authority.is_some();
                    let (query_snapshot, materialized_head) =
                        materialize_hosted_repository_snapshot(recovered.snapshot)?;
                    let g = kin_db::InMemoryGraph::from_snapshot_with_text_index(
                        query_snapshot,
                        text_index_path.clone(),
                    )
                    .map_err(DaemonError::from)?;
                    info!(
                        repo_id,
                        generation = recovered.generation,
                        deltas_replayed = recovered.deltas_applied,
                        hosted_authority_envelope,
                        materialized_head = ?materialized_head,
                        "loaded graph from storage backend"
                    );
                    (
                        Arc::new(g),
                        recovered.generation,
                        true,
                        hosted_authority_envelope,
                    )
                }
                None => {
                    info!(repo_id, "no snapshot found, starting with empty graph");
                    // In cloud mode, an empty graph IS the valid initial state.
                    // Mark as initialized so the readiness probe passes.
                    (
                        Arc::new(kin_db::InMemoryGraph::with_text_index(
                            text_index_path.clone(),
                        )),
                        0,
                        true,
                        false,
                    )
                }
            };

        let blobs = BlobStore::new(layout.ingest_cas_dir()).map_err(DaemonError::from)?;
        let backend: Arc<dyn StorageBackend> = Arc::from(backend);
        // Rehydrating the derived CAS on every open is what makes it safe to
        // treat as a cache. That was true of the local path only; a hosted
        // instance opened against an empty local disk and every projection read
        // failed on a blob nothing had put there.
        let ingest_cas_hydration_gap =
            match Self::hydrate_backend_ingest_cas(repo_id, &backend, graph.as_ref(), &blobs) {
                Ok(hydrated_source_bodies) => {
                    info!(
                        repo_id,
                        hydrated_source_bodies,
                        "hydrated derived ingestion CAS from hosted repository authority"
                    );
                    None
                }
                Err(reason) => {
                    // Not fatal: a hosted graph whose backend carries no
                    // repository authority still serves every query that does
                    // not need source bodies. Recorded so the reads that DO
                    // need them report this instead of a bare missing blob.
                    warn!(
                        repo_id,
                        reason, "derived ingestion CAS was not hydrated on the backend open path"
                    );
                    Some(reason)
                }
            };
        // The backend path builds the graph via `from_snapshot_with_text_index`,
        // which does NOT load the vector-index sidecar — do the validated load
        // here (no-ops if no/stale sidecar).
        let sidecar_open = Self::load_validated_vector_index(&layout, graph.as_ref());
        let mut reconciler = Reconciler::new(layout.working_dir().to_path_buf());
        reconciler.seed_lkg_entities_from_graph(graph.as_ref());
        reconciler.seed_cross_file_linker_from_graph(graph.as_ref());

        let traffic_checker =
            crate::traffic_adapter::CoordinatorTrafficChecker::new(Arc::clone(&graph));
        reconciler.set_traffic_checker(Box::new(traffic_checker));

        let coordinator = SessionCoordinator::new(Arc::clone(&graph));

        let persisted_vfs_version = Self::load_persisted_vfs_version(&layout);

        // Baseline for the shutdown anti-wipe guard (entity count loaded from
        // the backend snapshot).
        let loaded_entity_count = graph.entity_count();
        let spine_disabled = Self::spine_disabled_from_env();

        let coordination_events = CoordinationEventLog::open(&layout, repo_id)?;
        let coordination_event_persist_failures = coordination_events.persisted_failure_count();
        let mut state = Self {
            layout,
            graph: Arc::clone(&graph),
            blobs: Arc::new(blobs),
            ingest_cas_hydration_gap,
            vector_index_discarded: sidecar_open.discarded,
            vector_index_salvage: sidecar_open.salvage,
            reconciler: RwLock::new(reconciler),
            projection: RwLock::new(ProjectionState::new()),
            coordinator,
            coordination_gate: tokio::sync::Mutex::new(()),
            graph_authority_clock: Arc::new(GraphAuthorityClock::default()),
            coordination_mode: std::sync::RwLock::new(
                kin_mcp::CoordinationEnforcementMode::from_env(),
            ),
            coordination_events,
            coordination_event_persist_failures: AtomicU64::new(
                coordination_event_persist_failures,
            ),
            started_at: Instant::now(),
            is_initialized: AtomicBool::new(loaded_snapshot),
            reconciliation_status: AtomicU8::new(RECON_IDLE),
            storage_backend: Some(backend),
            hosted_authority_envelope,
            hosted_authority_flush_refusals: AtomicU64::new(0),
            local_repository_backend: None,
            projection_authority: crate::api::ProjectionAuthorityCache::default(),
            registered_local_repository_authorities: Vec::new(),
            registered_local_repository_authority_incomplete: false,
            spine_disabled,
            eager_sibling_bound: Self::eager_sibling_load_bound(),
            sibling_capture: std::sync::OnceLock::new(),
            filesystem_reconcile_disabled: AtomicBool::new(
                crate::loop_runner::filesystem_reconcile_disabled_at_startup(true),
            ),
            snapshot_generation: AtomicU64::new(generation),
            post_commit_finalization_pending: AtomicBool::new(false),
            #[cfg(test)]
            finalization_fail_once: AtomicBool::new(false),
            #[cfg(test)]
            mcp_fail_after_authority_once: AtomicBool::new(false),
            #[cfg(test)]
            repository_command_fail_after_authority_once: AtomicBool::new(false),
            #[cfg(test)]
            repository_command_enrich_after_authority_once: AtomicBool::new(false),
            vfs_version: AtomicU64::new(persisted_vfs_version),
            event_tx: tokio::sync::broadcast::channel(256).0,
            session_scopes: RwLock::new(HashMap::new()),
            spine: std::sync::OnceLock::new(),
            spine_initialization: Mutex::new(()),
            spine_warming: AtomicBool::new(false),
            background_work: Arc::new(crate::background_work::BackgroundWorkSupervisor::default()),
            admission_runs: crate::repository_admit::AdmissionRuns::default(),
            #[cfg(test)]
            spine_initialization_test_hook: Mutex::new(None),
            #[cfg(all(test, feature = "embeddings"))]
            vector_checkpoint_reopen_test_hook: Mutex::new(None),
            spine_refresh_gate: tokio::sync::Mutex::new(()),
            repo_graphs: RwLock::new(HashMap::new()), // populated below
            allowed_repo_ids,
            dirty: AtomicBool::new(false),
            mutation_epoch: AtomicU64::new(0),
            embedding_work: Mutex::new(()),
            embed_batch_size: AtomicUsize::new(0),
            graph_status_settled: crate::api::GraphStatusSettledCache::default(),
            graph_status_live_sample_failures: AtomicU64::new(0),
            persist_lock: Mutex::new(()),
            #[cfg(feature = "embeddings")]
            vector_checkpoint_authority_match: VectorCheckpointAuthorityMatch::default(),
            #[cfg(feature = "embeddings")]
            deferred_vector_checkpoint: std::sync::Mutex::new(None),
            last_save: std::sync::Mutex::new(Instant::now()),
            last_mutation: std::sync::Mutex::new(Instant::now()),
            active_embed_passes: AtomicU32::new(0),
            background_embed_paused: AtomicBool::new(false),
            last_activity_ms: AtomicU64::new(0),
            idle_timeout_ms: AtomicU64::new(0),
            active_requests: AtomicU64::new(0),
            lsp_enrichment_tx: None,
            lsp_enrichment_enabled: false,
            lsp_sweep_files_done: AtomicU64::new(0),
            lsp_sweep_files_total: AtomicU64::new(0),
            lsp_sweep_files_blocked: AtomicU64::new(0),
            lsp_sweeps_completed: AtomicU64::new(0),
            lsp_sweep_running: AtomicBool::new(false),
            lsp_enriched_files: std::sync::Mutex::new(std::collections::HashSet::new()),
            unpublished_enrichment: std::sync::Mutex::new(std::collections::HashSet::new()),
            cached_repo_id: repo_id.to_string(),
            cached_workspace_id: None,
            is_shutdown: AtomicBool::new(false),
            durable_entity_count: AtomicU64::new(loaded_entity_count as u64),
            persisted_entity_count: AtomicU64::new(loaded_entity_count as u64),
            mass_deletion_blocked: AtomicBool::new(false),
            retired_graph_only_members: Default::default(),
            pending_commits: Default::default(),
            last_authority_publication_micros: AtomicU64::new(0),
            embed_worker_failed: AtomicBool::new(false),
            derived_views_stale: RwLock::new(None),
            mcp_transactions: Mutex::new(HashMap::new()),
            locate_rankings: Mutex::new(HashMap::new()),
            semantic_locate_pages: Mutex::new(HashMap::new()),
        };

        // Restore in-flight MCP transactions persisted before a restart.
        *state
            .mcp_transactions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            load_persisted_mcp_transactions(&state.layout);

        // Pre-load repos into the map BEFORE any async context.
        // We use get_mut() since no one else has a reference yet.
        let graphs = state.repo_graphs.get_mut();
        graphs.insert(repo_id.to_string(), graph);

        // The recovered graph is already the exact validated authority view
        // and the state is not externally visible yet. Reuse it for startup
        // artifacts instead of downloading and decoding the backend twice.
        state
            .post_commit_finalization_pending
            .store(true, Ordering::SeqCst);
        state.finalize_loaded_generation(generation)?;
        state.register_daemon_system_session();

        Ok(state)
    }

    /// Register the daemon-owned reconcile session only after startup-derived
    /// artifacts have been built from the exact loaded authority graph.
    fn register_daemon_system_session(&mut self) {
        let daemon_session_id = self
            .coordinator
            .register_session(
                "kin-daemon",
                "reconcile-loop",
                kin_model::session::SessionTransport::Cli,
                None,
                self.layout.working_dir().to_path_buf(),
                kin_model::session::SessionCapabilities::default(),
            )
            .unwrap_or_else(|error| {
                tracing::warn!("failed to register daemon session: {error}");
                kin_model::SessionId::new()
            });
        self.reconciler.get_mut().set_session_id(daemon_session_id);
    }

    /// Returns a reference to the spine backend, if already initialized.
    /// Returns `None` until `ensure_spine()` has been called.
    pub fn spine(&self) -> Option<&dyn kin_spine::SpineBackend> {
        self.spine.get().map(|s| s.as_ref())
    }

    /// Lazily initialize the spine and return a reference to it.
    /// Returns `None` if spine is disabled or if the mutable primary graph could
    /// not be captured stably yet; the latter leaves OnceLock empty for retry.
    ///
    /// Registration is published once, but the graph it describes keeps moving.
    /// Every caller therefore re-resolves the primary watermark here rather than
    /// reading whatever root the daemon happened to start with.
    pub fn ensure_spine(&self) -> Option<&dyn kin_spine::SpineBackend> {
        if self.spine_disabled {
            return None;
        }
        if self.spine.get().is_none() {
            // The entire synchronous O(graph) pass belongs inside the Tokio
            // blocking handoff, not only the sibling thread join buried within
            // it. The mutex is acquired there too so a contending initializer
            // cannot park another async worker.
            without_blocking_runtime_worker(|| {
                let _initialization = self
                    .spine_initialization
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if self.spine.get().is_none() {
                    self.initialize_spine_lazy();
                }
            });
        }
        let spine = self.spine.get()?;
        self.reregister_primary_at_current_root(spine.as_ref());
        Some(spine.as_ref())
    }

    /// Whether the spine's registered primary watermark is the live graph root.
    fn primary_spine_registration_is_current(&self, spine: &dyn kin_spine::SpineBackend) -> bool {
        let live_root = hex::encode(self.graph.compute_root_hash());
        spine.root_hash(&self.cached_repo_id).as_deref() == Some(live_root.as_str())
    }

    /// Re-capture and re-register the primary repository once graph authority
    /// has moved past the spine's registered watermark.
    ///
    /// The registered root and the registered entity metadata are one fact. A
    /// watermark advanced on its own would certify a cross-repo answer that was
    /// read out of the pre-mutation index, so the whole capture is replaced and
    /// this repo's outgoing edges are re-resolved against it. A capture that
    /// cannot stabilize leaves the repo explicitly dirty for the next caller
    /// instead of publishing a root its entity set does not back.
    fn reregister_primary_at_current_root(&self, spine: &dyn kin_spine::SpineBackend) {
        if self.primary_spine_registration_is_current(spine) {
            return;
        }
        without_blocking_runtime_worker(|| {
            let _initialization = self
                .spine_initialization
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.primary_spine_registration_is_current(spine) {
                return;
            }
            let primary_repo_id = self.cached_repo_id.as_str();
            let mut capture =
                match self.capture_spine_repo(primary_repo_id, Arc::clone(&self.graph)) {
                    Ok(capture) => capture,
                    Err(capture_error) => {
                        spine.invalidate_cross_repo_edges(primary_repo_id);
                        warn!(
                            repo_id = primary_repo_id,
                            error = %capture_error,
                            "spine re-registration deferred until primary graph authority is stable"
                        );
                        return;
                    }
                };
            let entity_count = capture.entries.len();
            spine.register_repo(
                primary_repo_id,
                std::mem::take(&mut capture.entries),
                &capture.root_hash,
            );
            let registry_ids = spine.registered_repo_ids().into_iter().collect::<Vec<_>>();
            spine.refresh_cross_repo_edges(
                primary_repo_id,
                &capture.entities,
                &capture.relations,
                &registry_ids,
            );
            if !self.spine_capture_is_current(&capture) {
                spine.invalidate_cross_repo_edges(primary_repo_id);
                warn!(
                    repo_id = primary_repo_id,
                    "primary graph authority advanced during spine re-registration; retry"
                );
                return;
            }
            info!(
                repo_id = primary_repo_id,
                entities = entity_count,
                root_hash = %capture.root_hash,
                cross_repo_edges = spine.edge_count(),
                "re-registered primary graph authority in spine"
            );
        });
    }

    fn spine_capture_is_current(&self, capture: &SpineGraphCapture) -> bool {
        if capture
            .graph_authority_epoch
            .is_some_and(|epoch| !self.graph_authority_epoch_is_current(epoch))
        {
            return false;
        }
        if hex::encode(capture.graph.compute_root_hash()) != capture.root_hash {
            return false;
        }
        capture
            .graph_authority_epoch
            .is_none_or(|epoch| self.graph_authority_epoch_is_current(epoch))
    }

    fn capture_spine_repo(
        &self,
        repo_id: &str,
        graph: Arc<kin_db::InMemoryGraph>,
    ) -> std::result::Result<SpineGraphCapture, String> {
        self.capture_spine_repo_with_hook(repo_id, graph, |_| {})
    }

    /// Capture one exact entity/relation/root domain, retrying when a writer
    /// overlaps the detached snapshot. The hook is a deterministic race seam
    /// used by regression tests; production callers pass the no-op wrapper.
    fn capture_spine_repo_with_hook<F>(
        &self,
        repo_id: &str,
        graph: Arc<kin_db::InMemoryGraph>,
        mut after_snapshot: F,
    ) -> std::result::Result<SpineGraphCapture, String>
    where
        F: FnMut(usize),
    {
        let mutable_primary = Arc::ptr_eq(&graph, &self.graph);
        let mut last_reason = "graph authority did not stabilize".to_string();

        for attempt in 0..SPINE_GRAPH_CAPTURE_ATTEMPTS {
            let graph_authority_epoch = if mutable_primary {
                let Some(epoch) = self.stable_graph_authority_epoch() else {
                    last_reason = "primary graph has an active authority writer".to_string();
                    continue;
                };
                Some(epoch)
            } else {
                None
            };

            let snapshot = graph.to_snapshot();
            let root_hash = hex::encode(kin_db::compute_graph_root_hash(&snapshot));
            let entity_ids = snapshot.entities.keys().copied().collect::<HashSet<_>>();
            let mut entities = snapshot.entities.into_values().collect::<Vec<_>>();
            entities.sort_by_key(|entity| entity.id);
            let mut relations = snapshot
                .relations
                .into_values()
                .filter(|relation| {
                    matches!(
                        relation.kind,
                        kin_model::RelationKind::Calls | kin_model::RelationKind::References
                    ) && relation
                        .src
                        .as_entity()
                        .is_some_and(|source| entity_ids.contains(&source))
                })
                .collect::<Vec<_>>();
            relations.sort_by_key(|relation| relation.id.to_string());
            let entries = Self::entities_to_spine_entries(repo_id, &entities);
            let capture = SpineGraphCapture {
                repo_id: repo_id.to_string(),
                graph: Arc::clone(&graph),
                graph_authority_epoch,
                root_hash,
                entries,
                entities,
                relations,
            };

            after_snapshot(attempt);
            if self.spine_capture_is_current(&capture) {
                return Ok(capture);
            }
            last_reason = "graph changed while its detached spine domain was captured".to_string();
        }

        Err(format!(
            "could not capture stable spine authority for repo {repo_id} after {SPINE_GRAPH_CAPTURE_ATTEMPTS} attempts: {last_reason}"
        ))
    }

    /// Lazily initialize the spine from the loaded graph and startup-pinned
    /// sibling authority capabilities.
    /// Called by `ensure_spine()` on first access while holding
    /// `spine_initialization`; `OnceLock` remains the publication edge.
    ///
    /// Backend selection:
    /// - If `GOOGLE_CLOUD_PROJECT` is set AND the `firestore` feature is enabled
    ///   on kin-spine: uses `FirestoreSpineBackend` (write-through to Firestore,
    ///   reads from local cache). This enables the stateless daemon pool.
    /// - Otherwise: uses `InMemorySpineBackend` (current behavior, no external deps).
    fn initialize_spine_lazy(&self) {
        self.initialize_spine_lazy_with_publication_hook(|| {});
    }

    /// Whether a complete lazy spine initialization pass is in progress.
    pub fn spine_warming(&self) -> bool {
        self.spine_warming.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn set_spine_initialization_test_hook(
        &self,
        hook: Option<Arc<dyn Fn() + Send + Sync>>,
    ) {
        *self
            .spine_initialization_test_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    #[cfg(all(test, feature = "embeddings"))]
    pub(crate) fn set_vector_checkpoint_reopen_test_hook(
        &self,
        hook: Option<Arc<dyn Fn() + Send + Sync>>,
    ) {
        *self
            .vector_checkpoint_reopen_test_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    #[cfg(all(test, feature = "embeddings"))]
    fn run_vector_checkpoint_reopen_hook(&self) {
        let hook = self
            .vector_checkpoint_reopen_test_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    fn load_registered_workspace_graph(
        binding: &kin_core::LocalRepositoryAuthorityBinding,
    ) -> std::result::Result<Arc<kin_db::InMemoryGraph>, String> {
        let authority = binding.open_manager().map_err(|error| {
            format!("open startup-pinned sibling repository authority: {error}")
        })?;
        let lease = authority.read_authority();
        let snapshot = lease
            .workspace_graph_snapshot(&binding.workspace_id())
            .map_err(|error| format!("materialize sibling workspace authority: {error}"))?
            .ok_or_else(|| {
                format!(
                    "sibling repository {} authority has no startup-pinned workspace {}",
                    binding.repository_id(),
                    binding.workspace_id()
                )
            })?;
        kin_db::InMemoryGraph::from_snapshot(snapshot)
            .map(Arc::new)
            .map_err(|error| format!("open sibling workspace graph: {error}"))
    }

    /// Prepare and publish the lazy spine behind the graph-authority visibility
    /// handshake. The hook is a deterministic seam for the final-validation to
    /// publication race regression; production callers use the no-op wrapper.
    fn initialize_spine_lazy_with_publication_hook<F>(&self, mut before_publication: F)
    where
        F: FnMut(),
    {
        if self.spine.get().is_some() {
            return;
        }

        // Announce the warm-up before any O(graph) capture or construction so
        // liveness surfaces remain honest for the complete blocking pass. The
        // serialization gate around this method guarantees only one guard can
        // exist, and Drop clears it on every exit path including a panic.
        let _warming = SpineWarmGuard::arm(&self.spine_warming);
        #[cfg(test)]
        if let Some(hook) = self
            .spine_initialization_test_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            hook();
        }

        // Capture the mutable primary before constructing or publishing the
        // OnceLock value. A busy writer therefore leaves the spine uninitialized
        // and the next request retries instead of permanently caching an empty
        // or mismatched backend.
        let primary_repo_id = self.cached_repo_id.as_str();
        let primary = match self.capture_spine_repo(primary_repo_id, Arc::clone(&self.graph)) {
            Ok(capture) => capture,
            Err(capture_error) => {
                warn!(
                    repo_id = primary_repo_id,
                    error = %capture_error,
                    "spine initialization deferred until primary graph authority is stable"
                );
                return;
            }
        };
        let mut captures = vec![primary];
        let mut authority_incomplete = self.registered_local_repository_authority_incomplete;

        // Capture only sibling capabilities frozen during startup. Lazy
        // initialization may load graph bytes, but cannot rediscover registry
        // paths, manifests, or storage roots from a request.
        //
        // Bounded, because each iteration opens that sibling's whole workspace
        // graph and joins before the next one starts. This host carries 81
        // registered siblings over 70.67 GiB, so an unbounded pass is the
        // startup cost, and the identity fix in this branch is what re-arms it.
        let eager_bound = self.eager_sibling_bound;
        let registered_sibling_count = self.registered_local_repository_authorities.len();
        let mut bounded_out = 0_usize;
        for (position, registered) in self
            .registered_local_repository_authorities
            .iter()
            .enumerate()
        {
            if position >= eager_bound {
                bounded_out += 1;
                continue;
            }
            let sibling_id = registered.repo_id.clone();
            let binding = registered.binding.clone();
            let loaded = std::thread::Builder::new()
                .name(format!("spine-load-{sibling_id}"))
                .spawn(move || Self::load_registered_workspace_graph(&binding))
                .map_err(|error| format!("spawn sibling authority load: {error}"))
                .and_then(|handle| {
                    // `ensure_spine` handed off the complete initialization pass
                    // before reaching this join, so no nested runtime blocking
                    // handoff is needed here.
                    handle
                        .join()
                        .map_err(|_| "sibling authority loader panicked".to_string())
                })
                .and_then(|result| result);

            let sibling_graph = match loaded {
                Ok(graph) => graph,
                Err(load_error) => {
                    authority_incomplete = true;
                    warn!(
                        repo_id = %registered.repo_id,
                        error = %load_error,
                        "startup-pinned sibling workspace authority could not be loaded; spine authority will remain incomplete"
                    );
                    continue;
                }
            };
            match self.capture_spine_repo(&registered.repo_id, sibling_graph) {
                Ok(capture) => captures.push(capture),
                Err(capture_error) => {
                    authority_incomplete = true;
                    warn!(
                        repo_id = %registered.repo_id,
                        error = %capture_error,
                        "sibling graph capture failed; spine authority will remain incomplete"
                    );
                }
            }
        }

        // A captured graph may advance while a later sibling is loading. Never
        // publish a backend containing a stale capture; leave OnceLock empty so
        // the next request can retry the whole authority set.
        if captures
            .iter()
            .any(|capture| !self.spine_capture_is_current(capture))
        {
            warn!("spine initialization deferred because a captured graph advanced");
            return;
        }
        if self.spine.get().is_some() {
            return;
        }

        let backend: Arc<dyn kin_spine::SpineBackend> = self.create_spine_backend();
        for capture in &mut captures {
            let entity_count = capture.entries.len();
            backend.register_repo(
                &capture.repo_id,
                std::mem::take(&mut capture.entries),
                &capture.root_hash,
            );
            info!(
                repo_id = %capture.repo_id,
                entities = entity_count,
                root_hash = %capture.root_hash,
                "registered exact graph snapshot in spine"
            );
        }

        let registry_ids = backend
            .registered_repo_ids()
            .into_iter()
            .collect::<Vec<_>>();
        for capture in &captures {
            backend.refresh_cross_repo_edges(
                &capture.repo_id,
                &capture.entities,
                &capture.relations,
                &registry_ids,
            );
        }

        if captures
            .iter()
            .any(|capture| !self.spine_capture_is_current(capture))
        {
            for repo_id in backend.registered_repo_ids() {
                backend.invalidate_cross_repo_edges(&repo_id);
            }
            warn!(
                "spine initialization discarded because a captured graph advanced during publication"
            );
            return;
        }

        let captured_repo_ids = captures
            .iter()
            .map(|capture| capture.repo_id.clone())
            .collect::<HashSet<_>>();
        let registered_repo_ids = backend.registered_repo_ids();
        // Two different states share one inequality, and conflating them is what
        // this branch has to avoid. A capture the configured bound stopped is
        // BOUNDED: deliberate, disclosed, and the captures it did take are
        // sound. A sibling that failed to load is INCOMPLETE: an answer whose
        // shape nobody chose. Only the second is a reason to distrust anything.
        let uncaptured = registered_repo_ids
            .difference(&captured_repo_ids)
            .cloned()
            .collect::<Vec<_>>();
        if !uncaptured.is_empty() {
            authority_incomplete = true;
            warn!(
                captured = captured_repo_ids.len(),
                registered = registered_repo_ids.len(),
                "spine contains durable advisory repos without a current graph capture"
            );
        }
        // Scoped, where this used to invalidate every registered repo including
        // the primary. Edges between captured repos were recomputed from those
        // captures moments ago and are valid; only edges into a repo this pass
        // did not capture can be stale. One sibling failing used to mark the
        // whole cross-repo edge set dirty, which is a far larger blast radius
        // than the fact that produced it.
        for repo_id in &uncaptured {
            backend.invalidate_cross_repo_edges(repo_id);
        }

        // A writer announcing itself after the preparation checks but before
        // OnceLock publication used to leave a stale backend visibly complete:
        // the writer could not invalidate a value that was not published yet.
        // Serialize that visibility edge with writer announcement, then repeat
        // the authority check while the gate prevents a new writer from
        // starting. The next writer can only proceed after publication and will
        // invalidate the visible primary repo before touching graph truth.
        before_publication();
        let _publication = self
            .graph_authority_clock
            .publication_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if captures
            .iter()
            .any(|capture| !self.spine_capture_is_current(capture))
        {
            for repo_id in backend.registered_repo_ids() {
                backend.invalidate_cross_repo_edges(&repo_id);
            }
            warn!(
                "spine initialization discarded because graph authority advanced before visibility"
            );
            return;
        }

        // `capture_set_complete` keeps meaning what it meant: nothing failed.
        // The bounded fields are a separate claim, that a deliberate cap left
        // siblings unconsulted, and they carry the counts so a reader can size
        // the gap rather than guess at it. A silent cap would be the worse bug:
        // a complete-looking answer over a subset nobody was told about.
        info!(
            cross_repo_edges = backend.edge_count(),
            capture_set_complete = !authority_incomplete,
            sibling_capture_bounded = bounded_out > 0,
            siblings_captured = registered_sibling_count.saturating_sub(bounded_out),
            siblings_registered = registered_sibling_count,
            eager_sibling_bound = eager_bound,
            "spine index initialized"
        );
        if bounded_out > 0 {
            info!(
                captured = registered_sibling_count.saturating_sub(bounded_out),
                registered = registered_sibling_count,
                bound = eager_bound,
                var = EAGER_SIBLING_BOUND_ENV,
                "sibling graph capture stopped at its configured bound; the spine \
                 answers over a bounded capture set, not an incomplete one"
            );
        }
        let _ = self.sibling_capture.set(SiblingCaptureReport {
            bounded: bounded_out > 0,
            captured: registered_sibling_count.saturating_sub(bounded_out),
            registered: registered_sibling_count,
            bound: eager_bound,
            authority_incomplete,
        });
        let _ = self.spine.get_or_init(move || backend);
    }

    /// Create the appropriate spine backend based on environment.
    /// How many registered siblings the spine loads eagerly at startup.
    ///
    /// Each one opens that sibling's whole workspace graph and is joined before
    /// the next starts, so this number is the startup cost of cross-repo
    /// authority. It is deliberately conservative: this host carries 81
    /// registered siblings over 70.67 GiB, and 16 bounds the eager pass to
    /// roughly a fifth of that while still covering an umbrella of ordinary
    /// size.
    ///
    /// Zero disables eager sibling loading and the spine answers over the
    /// primary alone, which is a supported operator choice rather than a
    /// failure. An unparseable value keeps the default and warns, because a
    /// daemon that will not start is a worse failure than one that starts
    /// conservatively.
    fn eager_sibling_load_bound() -> usize {
        const DEFAULT: usize = 16;
        let Ok(raw) = std::env::var(EAGER_SIBLING_BOUND_ENV) else {
            return DEFAULT;
        };
        match raw.trim().parse::<usize>() {
            Ok(bound) => bound,
            Err(_) => {
                warn!(
                    var = EAGER_SIBLING_BOUND_ENV,
                    value = %raw,
                    "ignoring an unparseable eager sibling load bound; using the default"
                );
                DEFAULT
            }
        }
    }

    /// What the spine's sibling capture did, once it has run.
    ///
    /// `None` before the spine publishes, which is not the same claim as a
    /// complete capture and is deliberately not collapsed into one.
    pub(crate) fn sibling_capture_report(&self) -> Option<SiblingCaptureReport> {
        self.sibling_capture.get().copied()
    }

    fn create_spine_backend(&self) -> Arc<dyn kin_spine::SpineBackend> {
        #[cfg(feature = "firestore")]
        {
            if let Ok(project_id) = std::env::var("GOOGLE_CLOUD_PROJECT") {
                let database_id = std::env::var("FIRESTORE_DATABASE_ID").ok();
                info!(
                    project = %project_id,
                    database = database_id.as_deref().unwrap_or("(default)"),
                    "using Firestore spine backend for stateless daemon pool"
                );
                let backend = kin_spine::FirestoreSpineBackend::new(project_id, database_id);
                // Hydrate cache from Firestore (best-effort on startup).
                if let Err(e) = backend.hydrate() {
                    warn!(error = %e, "Firestore hydration failed, starting with empty cache");
                }
                return Arc::new(backend);
            }
        }

        info!("using in-memory spine backend (local dev mode)");
        Arc::new(kin_spine::InMemorySpineBackend::new())
    }

    /// Project a repo's graph entities into the metadata-only `EntityEntry`
    /// rows the spine indexes. The spine never stores entity bodies — just
    /// enough (name, kind, signature, fingerprint, role) to resolve cross-repo
    /// references — so this is the single mapping used by both the local
    /// sibling-scan path and the cloud ingest path.
    fn entities_to_spine_entries(
        repo_id: &str,
        entities: &[kin_model::Entity],
    ) -> Vec<kin_spine::EntityEntry> {
        entities
            .iter()
            .map(|e| kin_spine::EntityEntry {
                repo_id: repo_id.to_string(),
                entity_id: e.id,
                name: e.name.clone(),
                kind: e.kind,
                signature: e.signature.clone(),
                fingerprint: e.fingerprint.clone(),
                file_path: e.file_origin.as_ref().map(|f| f.0.clone()),
                role: Some(e.role),
            })
            .collect()
    }

    /// Ingest a repo's graph into the spine from durable storage — the
    /// production multi-repo write path.
    ///
    /// Unlike `initialize_spine_lazy`, which only discovers siblings from the
    /// local `registry.toml` + on-disk `.kndb` files (absent in a hosted pod),
    /// this loads the named repo's graph through the configured
    /// [`StorageBackend`](kin_db::StorageBackend) — the GCS blob store in
    /// cloud — and registers its entity metadata (write-through to the durable
    /// spine store). This is what lets a single-repo pod build a spine holding
    /// ≥2 repos so `/spine/xref` returns non-empty cross-repo edges.
    ///
    /// `refresh_cross_repo_edges`: when `true` (the cross-repo anchor, e.g.
    /// `kin`), re-resolve this repo's unresolved imports against the now
    /// multi-repo spine and materialize the cross-repo edges. Sibling repos are
    /// ingested with `false` (metadata only); the anchor pass binds the edges.
    ///
    /// `get_repo_graph` enforces the `allowed_repo_ids` (`KIN_REPO_IDS`) gate and
    /// caches the loaded graph, so repeated ingests of the same repo reuse it.
    pub async fn ingest_repo_into_spine(
        &self,
        repo_id: &str,
        refresh_cross_repo_edges: bool,
    ) -> Result<SpineIngestOutcome> {
        self.ingest_repo_into_spine_with_capture_hook(repo_id, refresh_cross_repo_edges, |_| {})
            .await
    }

    async fn ingest_repo_into_spine_with_capture_hook<F>(
        &self,
        repo_id: &str,
        refresh_cross_repo_edges: bool,
        capture_hook: F,
    ) -> Result<SpineIngestOutcome>
    where
        F: FnMut(usize),
    {
        let Some(spine) = self.ensure_spine() else {
            let reason = if self.spine_disabled {
                "spine disabled via KIN_DISABLE_SPINE"
            } else {
                "spine initialization could not capture stable primary graph authority; retry"
            };
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                reason.to_string(),
            )));
        };
        let _spine_refresh = self.spine_refresh_gate.lock().await;

        // Load the repo's graph from durable storage (GCS in cloud). This is the
        // blob-store read boundary that replaces the local-disk `.kndb` lookup.
        let graph = self.get_repo_graph(repo_id).await?;
        let mut capture = match self.capture_spine_repo_with_hook(repo_id, graph, capture_hook) {
            Ok(capture) => capture,
            Err(capture_error) => {
                spine.invalidate_cross_repo_edges(repo_id);
                return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                    capture_error,
                )));
            }
        };
        let entity_count = capture.entries.len();
        let relation_count = capture.relations.len();
        let root_hash = capture.root_hash.clone();

        // Write-through: register this repo's metadata into the spine store so a
        // freshly started (stateless) pod can hydrate it and resolve against it.
        spine.register_repo(repo_id, std::mem::take(&mut capture.entries), &root_hash);
        if !self.spine_capture_is_current(&capture) {
            spine.invalidate_cross_repo_edges(repo_id);
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                format!("repo {repo_id} graph authority changed during spine registration; retry"),
            )));
        }

        // Count the relations the resolver can actually bind into cross-repo
        // edges, against the spine's current registered-repo set. This is the
        // honest "can this materialize edges" signal the control plane gates on
        // — it is derived from graph truth, never a heuristic.
        let registry_ids: Vec<String> = spine.registered_repo_ids().into_iter().collect();
        let resolvable_relations = kin_spine::collect_unresolved_imports(
            &capture.entities,
            &capture.relations,
            repo_id,
            &registry_ids,
        )
        .len();

        if refresh_cross_repo_edges {
            // Re-resolve this repo's imports now that the sibling metadata is in
            // the spine, materializing (and write-through persisting) the
            // cross-repo edges that back `/spine/xref`.
            spine.refresh_cross_repo_edges(
                repo_id,
                &capture.entities,
                &capture.relations,
                &registry_ids,
            );
            if !self.spine_capture_is_current(&capture) {
                spine.invalidate_cross_repo_edges(repo_id);
                return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                    format!(
                        "repo {repo_id} graph authority changed during cross-repo refresh; retry"
                    ),
                )));
            }
        }

        info!(
            repo_id,
            entities = entity_count,
            relations = relation_count,
            resolvable_relations,
            refreshed = refresh_cross_repo_edges,
            cross_repo_edges = spine.edge_count(),
            "ingested repo into spine from storage"
        );

        Ok(SpineIngestOutcome {
            repo_id: repo_id.to_string(),
            root_hash,
            entity_count,
            relation_count,
            resolvable_relations,
        })
    }

    /// Refresh cross-repo edges for EVERY registered repo, mirroring the local
    /// [`Self::initialize_spine_lazy`] "register all, then resolve all" pass.
    ///
    /// The per-repo ingest path only materializes the anchor repo's edges, so a
    /// repo ingested before its dependency was registered never forms its
    /// outgoing edges. This final pass — run by the hosted orchestrator once
    /// every repo is registered — loads each registered repo's graph from
    /// durable storage (the blob store, never on-disk siblings) and re-resolves
    /// its imports against the now-complete spine. It is idempotent: each repo's
    /// existing edges are removed and re-materialized.
    pub async fn refresh_all_cross_repo_edges(&self) -> Result<SpineRefreshOutcome> {
        let Some(spine) = self.ensure_spine() else {
            let reason = if self.spine_disabled {
                "spine disabled via KIN_DISABLE_SPINE"
            } else {
                "spine initialization could not capture stable primary graph authority; retry"
            };
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                reason.to_string(),
            )));
        };
        let _spine_refresh = self.spine_refresh_gate.lock().await;

        // Resolve against the full registered-repo set, sorted for a
        // deterministic pass order.
        let mut registry_ids: Vec<String> = spine.registered_repo_ids().into_iter().collect();
        registry_ids.sort();

        // Invalidate the whole pass up front. A graph-load or stable-capture
        // failure therefore leaves the shared topology explicitly incomplete
        // instead of serving the previous complete watermark after a skipped
        // repo.
        for repo_id in &registry_ids {
            spine.invalidate_cross_repo_edges(repo_id);
        }
        let Some(graph_authority_epoch) = self.stable_graph_authority_epoch() else {
            warn!("cross-repo refresh remains incomplete while graph authority is mutating");
            return Ok(SpineRefreshOutcome {
                repos_refreshed: 0,
                cross_repo_edges: spine.edge_count(),
            });
        };

        struct PreparedSpineRepo {
            repo_id: String,
            graph: Arc<kin_db::InMemoryGraph>,
            root_hash: String,
            entries: Vec<kin_spine::EntityEntry>,
            entities: Vec<kin_model::Entity>,
            relations: Vec<kin_model::Relation>,
        }

        // Phase 1: capture each entity/relation domain through one detached
        // graph snapshot. Computing the registered root from that same snapshot
        // prevents per-entity reads from straddling a reconcile. No spine state
        // is updated unless every repo in the pass has a stable capture.
        let mut prepared = Vec::with_capacity(registry_ids.len());
        for repo_id in &registry_ids {
            let graph = match self.get_repo_graph(repo_id).await {
                Ok(graph) => graph,
                Err(e) => {
                    warn!(repo_id, error = %e, "skipping cross-repo refresh: graph load failed");
                    continue;
                }
            };

            let snapshot = graph.to_snapshot();
            let root_hash = hex::encode(kin_db::compute_graph_root_hash(&snapshot));
            let live_root = hex::encode(graph.compute_root_hash());
            if root_hash != live_root {
                warn!(
                    repo_id,
                    snapshot_root = %root_hash,
                    live_root = %live_root,
                    "skipping cross-repo refresh: graph changed while its detached state was captured"
                );
                continue;
            }

            let entity_ids = snapshot.entities.keys().copied().collect::<HashSet<_>>();
            let mut entities = snapshot.entities.into_values().collect::<Vec<_>>();
            entities.sort_by_key(|entity| entity.id);
            let mut relations = snapshot
                .relations
                .into_values()
                .filter(|relation| {
                    matches!(
                        relation.kind,
                        kin_model::RelationKind::Calls | kin_model::RelationKind::References
                    ) && relation
                        .src
                        .as_entity()
                        .is_some_and(|source| entity_ids.contains(&source))
                })
                .collect::<Vec<_>>();
            relations.sort_by_key(|relation| relation.id.to_string());
            let entries = Self::entities_to_spine_entries(repo_id, &entities);
            prepared.push(PreparedSpineRepo {
                repo_id: repo_id.clone(),
                graph,
                root_hash,
                entries,
                entities,
                relations,
            });
        }

        if prepared.len() != registry_ids.len() {
            warn!(
                prepared = prepared.len(),
                expected = registry_ids.len(),
                "cross-repo refresh remains incomplete because not every registered repo had a stable graph capture"
            );
            return Ok(SpineRefreshOutcome {
                repos_refreshed: 0,
                cross_repo_edges: spine.edge_count(),
            });
        }

        // A graph may have changed while a later repo was loading. Revalidate
        // the full captured set before exposing any of its roots or entries.
        if !self.graph_authority_epoch_is_current(graph_authority_epoch)
            || prepared
                .iter()
                .any(|repo| hex::encode(repo.graph.compute_root_hash()) != repo.root_hash)
        {
            warn!(
                "cross-repo refresh remains incomplete because a graph changed before registration"
            );
            return Ok(SpineRefreshOutcome {
                repos_refreshed: 0,
                cross_repo_edges: spine.edge_count(),
            });
        }

        // Phase 2a: publish every repo's entries and exact captured root before
        // resolving any source. Each registration dirties the shared topology;
        // only the following all-source pass may clear it again.
        for repo in &mut prepared {
            spine.register_repo(
                &repo.repo_id,
                std::mem::take(&mut repo.entries),
                &repo.root_hash,
            );
        }

        if !self.graph_authority_epoch_is_current(graph_authority_epoch)
            || prepared
                .iter()
                .any(|repo| hex::encode(repo.graph.compute_root_hash()) != repo.root_hash)
        {
            for repo_id in &registry_ids {
                spine.invalidate_cross_repo_edges(repo_id);
            }
            warn!(
                "cross-repo refresh remains incomplete because a graph changed during registration"
            );
            return Ok(SpineRefreshOutcome {
                repos_refreshed: 0,
                cross_repo_edges: spine.edge_count(),
            });
        }

        let authority_roots = prepared
            .iter()
            .map(|repo| (repo.repo_id.clone(), repo.root_hash.clone()))
            .collect::<BTreeMap<_, _>>();
        let Some(pass_token) = spine.begin_cross_repo_refresh_pass(&authority_roots) else {
            warn!(
                "cross-repo refresh remains incomplete because another pass or authority change won the lease"
            );
            return Ok(SpineRefreshOutcome {
                repos_refreshed: 0,
                cross_repo_edges: spine.edge_count(),
            });
        };

        struct SpineRefreshLease<'a> {
            spine: &'a dyn kin_spine::SpineBackend,
            token: u64,
            authority_roots: &'a BTreeMap<String, String>,
            finished: bool,
        }

        impl SpineRefreshLease<'_> {
            fn finish(mut self, success: bool) -> bool {
                let committed = self.spine.finish_cross_repo_refresh_pass(
                    self.token,
                    self.authority_roots,
                    success,
                );
                self.finished = true;
                committed
            }
        }

        impl Drop for SpineRefreshLease<'_> {
            fn drop(&mut self) {
                if !self.finished {
                    let _ = self.spine.finish_cross_repo_refresh_pass(
                        self.token,
                        self.authority_roots,
                        false,
                    );
                }
            }
        }

        let pass = SpineRefreshLease {
            spine,
            token: pass_token,
            authority_roots: &authority_roots,
            finished: false,
        };

        // Phase 2b: now every resolver sees one coherent current registry.
        for repo in &prepared {
            spine.refresh_cross_repo_edges(
                &repo.repo_id,
                &repo.entities,
                &repo.relations,
                &registry_ids,
            );
        }

        let registry_unchanged =
            spine.registered_repo_ids() == registry_ids.iter().cloned().collect::<HashSet<_>>();
        let roots_unchanged = prepared
            .iter()
            .all(|repo| hex::encode(repo.graph.compute_root_hash()) == repo.root_hash);
        let spine_roots_unchanged = authority_roots
            .iter()
            .all(|(repo_id, root)| spine.root_hash(repo_id).as_ref() == Some(root));
        let graph_authority_unchanged =
            self.graph_authority_epoch_is_current(graph_authority_epoch);
        let pass_committed = pass.finish(
            registry_unchanged
                && roots_unchanged
                && spine_roots_unchanged
                && graph_authority_unchanged,
        );
        if !pass_committed {
            warn!(
                registry_unchanged,
                roots_unchanged,
                spine_roots_unchanged,
                graph_authority_unchanged,
                "cross-repo refresh completed against unstable authority; leaving every repo incomplete"
            );
            return Ok(SpineRefreshOutcome {
                repos_refreshed: 0,
                cross_repo_edges: spine.edge_count(),
            });
        }

        let repos_refreshed = prepared.len();

        info!(
            repos_refreshed,
            cross_repo_edges = spine.edge_count(),
            "refreshed cross-repo edges across all registered repos"
        );

        Ok(SpineRefreshOutcome {
            repos_refreshed,
            cross_repo_edges: spine.edge_count(),
        })
    }

    /// Load a repo's graph from the storage backend (synchronous).
    /// Used internally for pre-loading and by `get_repo_graph`.
    ///
    /// The absent case is typed as
    /// [`DaemonError::RepoAbsentFromStorage`] rather than folded into the
    /// fault arms. `load_recovered_snapshot` returns `Ok(None)` only when the
    /// backend read succeeded and found neither snapshot authority nor
    /// deltas, so absence here is a complete answer and callers may route it
    /// as a missing repository instead of a broken daemon.
    fn load_repo_graph(&self, repo_id: &str) -> Result<Arc<kin_db::InMemoryGraph>> {
        let Some(backend) = &self.storage_backend else {
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                "no storage backend configured for multi-repo mode".to_string(),
            )));
        };
        match kin_db::load_recovered_snapshot(backend.as_ref(), repo_id)
            .map_err(DaemonError::from)?
        {
            Some(recovered) => {
                let text_index_path = self.layout.text_index_dir();
                let (query_snapshot, materialized_head) =
                    materialize_hosted_repository_snapshot(recovered.snapshot)?;
                let graph = Arc::new(
                    kin_db::InMemoryGraph::from_snapshot_with_text_index(
                        query_snapshot,
                        text_index_path,
                    )
                    .map_err(DaemonError::from)?,
                );
                info!(
                    repo_id,
                    generation = recovered.generation,
                    deltas_replayed = recovered.deltas_applied,
                    materialized_head = ?materialized_head,
                    "loaded repo graph from storage backend"
                );
                Ok(graph)
            }
            None => Err(DaemonError::RepoAbsentFromStorage(repo_id.to_string())),
        }
    }

    fn cache_loaded_repo_graph(
        graphs: &mut HashMap<String, Arc<kin_db::InMemoryGraph>>,
        repo_id: &str,
        loaded: Arc<kin_db::InMemoryGraph>,
    ) -> Arc<kin_db::InMemoryGraph> {
        Arc::clone(graphs.entry(repo_id.to_string()).or_insert(loaded))
    }

    /// Whether `repo_id` belongs to the key space this daemon serves.
    ///
    /// Addressability is a separate question from whether a load succeeds, and
    /// only this one can be answered without touching storage. When an
    /// allowlist is configured it *is* the served key space, which is why
    /// [`Self::list_available_repos`] filters by the same set. Without one, a
    /// storage backend serves every repository it can load, and a local daemon
    /// serves exactly the repository authority it opened.
    ///
    /// Callers decide addressability with this before attempting a load so a
    /// backend fault on a served repository is never reported as a request
    /// addressed to the wrong repository.
    pub fn serves_repo_id(&self, repo_id: &str) -> bool {
        match &self.allowed_repo_ids {
            Some(allowed_repo_ids) => allowed_repo_ids.contains(repo_id),
            None => self.storage_backend.is_some() || repo_id == self.cached_repo_id,
        }
    }

    /// Get or lazy-load a repo's graph from the storage backend.
    ///
    /// Returns the cached graph if already loaded, otherwise loads from
    /// the storage backend and caches it. Only usable when a storage
    /// backend is configured (cloud / multi-repo mode).
    ///
    /// Three outcomes leave here and they are all typed, so a caller routes on
    /// what happened rather than on how it was worded. An id outside the
    /// configured key space is [`DaemonError::RepoNotServed`], decided before
    /// any load. A key space that admits the id but a backend holding nothing
    /// under it is [`DaemonError::RepoAbsentFromStorage`]. Anything else is a
    /// genuine fault carrying its underlying error.
    ///
    /// The refusal used to flatten into
    /// [`Graph`](DaemonError::Graph)`(StorageError(..))`, which made an
    /// addressing answer indistinguishable from a storage failure at every
    /// route that did not pre-empt it with [`Self::serves_repo_id`], and left
    /// the ingest path reporting a request sent to the wrong pod as a broken
    /// daemon.
    pub async fn get_repo_graph(&self, repo_id: &str) -> Result<Arc<kin_db::InMemoryGraph>> {
        if let Some(allowed_repo_ids) = &self.allowed_repo_ids {
            if !allowed_repo_ids.contains(repo_id) {
                return Err(DaemonError::RepoNotServed {
                    served: self.cached_repo_id.clone(),
                    requested: repo_id.to_string(),
                });
            }
        }
        // Fast path: check if already loaded.
        {
            let graphs = self.repo_graphs.read().await;
            if let Some(g) = graphs.get(repo_id) {
                return Ok(Arc::clone(g));
            }
        }
        // Slow path: load from backend.
        let graph = self.load_repo_graph(repo_id)?;
        let mut graphs = self.repo_graphs.write().await;
        // Double-check: another task may have loaded it while we were loading.
        // Return that task's cached winner, not this task's losing generation.
        Ok(Self::cache_loaded_repo_graph(&mut graphs, repo_id, graph))
    }

    /// List repo IDs that are currently loaded in the multi-repo cache.
    pub async fn list_loaded_repos(&self) -> Vec<String> {
        let graphs = self.repo_graphs.read().await;
        graphs.keys().cloned().collect()
    }

    /// List all repos available in storage (GCS bucket listing).
    ///
    /// When a storage backend is configured, discovers repos directly from
    /// storage — no env vars needed. Falls back to loaded repo keys in
    /// local mode.
    pub async fn list_available_repos(&self) -> Result<Vec<String>> {
        let mut repos = if let Some(backend) = &self.storage_backend {
            backend.list_repos().map_err(DaemonError::from)?
        } else {
            // Local mode: return the loaded repo_graphs keys. This awaits the
            // read rather than falling back to an empty listing on a contended
            // lock, which reported "this daemon serves no repositories" for
            // what was only a concurrent writer.
            self.repo_graphs.read().await.keys().cloned().collect()
        };
        if let Some(allowed_repo_ids) = &self.allowed_repo_ids {
            repos.retain(|repo_id| allowed_repo_ids.contains(repo_id));
        }
        repos.sort();
        repos.dedup();
        Ok(repos)
    }

    /// Persist the latest projection truth for a reconcile outcome into the graph
    /// before snapshot save so restart-time rebuild stays graph-backed.
    pub fn persist_projection_truth_from_reconcile(
        &self,
        reconciler: &Reconciler,
        outcome: &kin_reconcile::ReconcileOutcome,
    ) -> Result<()> {
        match outcome {
            kin_reconcile::ReconcileOutcome::Updated { file_id, .. } => {
                let layout = reconciler
                    .projection()
                    .get_layout(file_id)
                    .cloned()
                    .ok_or_else(|| {
                        DaemonError::Io(std::io::Error::other(format!(
                            "projection layout missing for {}",
                            file_id
                        )))
                    })?;
                let content = reconciler
                    .projection()
                    .get_content(file_id)
                    .ok_or_else(|| {
                        DaemonError::Io(std::io::Error::other(format!(
                            "projection content missing for {}",
                            file_id
                        )))
                    })?;
                let entry = self
                    .graph
                    .get_tree_entry(file_id)
                    .map_err(DaemonError::from)?
                    .ok_or_else(|| {
                        exact_source_storage_error(format!(
                            "semantic enrichment for {file_id} preceded exact working-tree admission"
                        ))
                    })?;
                let expected = entry.blob_identity().ok_or_else(|| {
                    exact_source_storage_error(format!(
                        "semantic enrichment for {file_id} cannot target a gitlink"
                    ))
                })?;
                let actual = kin_blobs::digest_bytes(content);
                if actual != *expected.as_bytes() {
                    return Err(exact_source_storage_error(format!(
                        "semantic enrichment bytes for {file_id} do not match graph-owned tree entry {}",
                        expected
                    )));
                }
                // Content identity is the precondition for publishing the
                // query-facing layout. Mutating first would leave a stale
                // same-path layout behind when this check fails.
                self.graph
                    .upsert_file_layout(&layout)
                    .map_err(DaemonError::from)?;
            }
            kin_reconcile::ReconcileOutcome::FileRemoved { file_id, .. } => {
                self.graph
                    .delete_file_layout(file_id)
                    .map_err(DaemonError::from)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Bump the monotonic VFS version counter. Call after every graph mutation.
    ///
    /// Persists the new value to `.kin/vfs_version` so that the counter survives
    /// daemon restarts and kin-vfs clients don't see a reset to 0.
    /// Also marks the graph as dirty for background persistence.
    pub fn bump_version(&self) {
        self.advance_vfs_version(true);
    }

    /// Invalidate projection/VFS readers without claiming graph mutation.
    ///
    /// Projection-only checkout repair changes the physical compatibility view
    /// while repository authority and the derived graph remain byte-for-byte
    /// identical. It still retires cached VFS materialization, but must not arm
    /// graph persistence or emit a synthetic graph-root change.
    pub(crate) fn invalidate_projection(&self) {
        self.advance_vfs_version(false);
    }

    fn advance_vfs_version(&self, graph_mutated: bool) {
        let v = self.vfs_version.fetch_add(1, Ordering::SeqCst) + 1;
        if graph_mutated {
            self.mark_dirty();
        }
        // Persist asynchronously — don't block the mutation path.
        let path = self.layout.root().join("vfs_version");
        let _ = std::fs::write(&path, v.to_string());
    }

    /// Set a temporal scope for a session. If max concurrent scopes reached,
    /// evict the oldest expired scope, or the oldest scope overall.
    pub async fn set_session_scope(
        &self,
        session_id: &kin_model::SessionId,
        ref_string: String,
        head: kin_model::SemanticChangeId,
        cached_graph: Arc<kin_db::InMemoryGraph>,
    ) {
        let mut scopes = self.session_scopes.write().await;

        // Evict expired scopes first
        scopes.retain(|_, scope| !scope.is_expired());

        // If still at capacity and this is a new session, evict oldest
        if scopes.len() >= MAX_CONCURRENT_SCOPES && !scopes.contains_key(session_id) {
            if let Some(oldest_id) = scopes
                .iter()
                .min_by_key(|(_, s)| s.created_at)
                .map(|(id, _)| *id)
            {
                scopes.remove(&oldest_id);
                info!(evicted = %oldest_id, "evicted oldest scope to make room");
            }
        }

        scopes.insert(
            *session_id,
            TemporalScope {
                ref_string,
                head,
                cached_graph,
                created_at: Instant::now(),
                ttl: DEFAULT_SCOPE_TTL,
            },
        );
    }

    /// Clear a session's temporal scope.
    pub async fn clear_session_scope(&self, session_id: &kin_model::SessionId) {
        let mut scopes = self.session_scopes.write().await;
        scopes.remove(session_id);
    }

    /// Get the temporal scope for a session, if any and not expired.
    pub async fn get_session_scope(
        &self,
        session_id: &kin_model::SessionId,
    ) -> Option<(String, kin_model::SemanticChangeId, Instant, Duration)> {
        let scopes = self.session_scopes.read().await;
        scopes.get(session_id).and_then(|scope| {
            if scope.is_expired() {
                None
            } else {
                Some((
                    scope.ref_string.clone(),
                    scope.head,
                    scope.created_at,
                    scope.ttl,
                ))
            }
        })
    }

    /// Get the graph for a session: scoped historical graph if session has
    /// an active scope, otherwise the live HEAD graph.
    pub async fn graph_for_session(
        &self,
        session_id: &kin_model::SessionId,
    ) -> Arc<kin_db::InMemoryGraph> {
        self.graph_for_request_with_authority(Some(session_id))
            .await
            .0
    }

    /// Scoped graph for a WRITE (reconcile). Returns the session's private
    /// scoped graph ONLY if a live (non-expired) scope exists, refreshing its
    /// TTL so an in-use session cannot expire mid-task. Returns `None` when no
    /// live scope exists — callers MUST treat `None` as an error and MUST NOT
    /// fall back to the shared HEAD graph for a write. Falling back would leak
    /// one session's workspace edits into every other session's HEAD reads and
    /// silently diverge in-memory HEAD from the durable snapshot.
    pub async fn scoped_graph_for_write(
        &self,
        session_id: &kin_model::SessionId,
    ) -> Option<Arc<kin_db::InMemoryGraph>> {
        let mut scopes = self.session_scopes.write().await;
        scopes.retain(|_, scope| !scope.is_expired());
        let scope = scopes.get_mut(session_id)?;
        scope.created_at = Instant::now();
        Some(Arc::clone(&scope.cached_graph))
    }

    /// Resolve the graph for a request: scoped historical graph when the
    /// session has an active temporal scope, otherwise the live HEAD graph.
    /// When `session_id` is `None`, always returns HEAD.
    pub async fn graph_for_request(
        &self,
        session_id: Option<&kin_model::SessionId>,
    ) -> Arc<kin_db::InMemoryGraph> {
        self.graph_for_request_with_authority(session_id).await.0
    }

    /// Resolve both the graph and the authority that owns mutations made to it.
    /// The pair is chosen under one scope read lock so a caller never mistakes a
    /// scoped graph for HEAD (or vice versa) because it separately probed scope
    /// state before resolving the graph.
    pub(crate) async fn graph_for_request_with_authority(
        &self,
        session_id: Option<&kin_model::SessionId>,
    ) -> (Arc<kin_db::InMemoryGraph>, RequestGraphAuthority) {
        if let Some(session_id) = session_id {
            let scopes = self.session_scopes.read().await;
            if let Some(scope) = scopes.get(session_id) {
                if !scope.is_expired() {
                    return (
                        Arc::clone(&scope.cached_graph),
                        RequestGraphAuthority::SessionScope,
                    );
                }
            }
        }

        (Arc::clone(&self.graph), RequestGraphAuthority::Head)
    }

    /// Revalidate that a selected request graph is still owned by the same
    /// authority. Session scopes may expire or be replaced during a long read;
    /// HEAD ownership is stable for the daemon lifetime.
    pub(crate) async fn graph_authority_is_current(
        &self,
        session_id: Option<&kin_model::SessionId>,
        graph: &Arc<kin_db::InMemoryGraph>,
        authority: RequestGraphAuthority,
    ) -> bool {
        match authority {
            RequestGraphAuthority::Head => Arc::ptr_eq(graph, &self.graph),
            RequestGraphAuthority::SessionScope => {
                let Some(session_id) = session_id else {
                    return false;
                };
                let scopes = self.session_scopes.read().await;
                scopes.get(session_id).is_some_and(|scope| {
                    !scope.is_expired() && Arc::ptr_eq(graph, &scope.cached_graph)
                })
            }
        }
    }

    /// Emit an SSE event to all subscribers. Non-blocking — if no subscribers, the event is dropped.
    pub fn emit_event(&self, event: DaemonEvent) {
        match self.event_tx.send(event) {
            Ok(_) => {}
            Err(_) => {
                debug!("broadcast event dropped, no active subscribers");
            }
        }
    }

    /// Save the current graph via the storage backend (CAS write).
    ///
    /// Returns the new generation on success. Fails if another writer
    /// committed since our last load (generation mismatch).
    ///
    /// After a successful save, writes the new generation number to
    /// `.kin/kindb/head-generation` so CLI and MCP processes can detect
    /// when their loaded snapshot is stale (P2-2.7).
    pub fn save_snapshot(&self) -> Result<()> {
        self.save_snapshot_impl(SnapshotSaveMode::Incremental)
    }

    /// How many flushes this daemon has refused the backend authority write.
    ///
    /// Zero is the assertion that matters on a healthy path.
    pub fn hosted_authority_flush_refusals(&self) -> u64 {
        self.hosted_authority_flush_refusals.load(Ordering::SeqCst)
    }

    pub fn save_snapshot_full(&self) -> Result<()> {
        self.save_snapshot_impl(SnapshotSaveMode::Full)
    }

    /// Whether derived embedding progress may be checkpointed in a local
    /// vector sidecar.
    ///
    /// A configured `StorageBackend` owns a distinct generation cursor (GCS in
    /// hosted deployments). Until that backend has an explicit vector-sidecar
    /// persistence contract, writing a local sidecar against its remote graph
    /// generation is unsafe and must fail loud.
    pub(crate) fn can_persist_embed_progress_locally(&self) -> bool {
        self.storage_backend.is_none()
    }

    /// Persist every exact-mode source object referenced by `changes` before
    /// the graph authority that names those objects is committed.
    ///
    /// Exact deltas fail closed when neither the local content-addressed store
    /// nor the backend already has the named bytes. Durable source objects may
    /// safely precede a failed graph CAS because they are immutable and
    /// content-addressed, while committing the graph first would create an
    /// irreparable authority gap.
    fn persist_exact_source_objects<'a>(
        &self,
        backend: &dyn StorageBackend,
        repo_id: &str,
        changes: impl IntoIterator<Item = &'a SemanticChange>,
    ) -> Result<()> {
        let objects = exact_source_objects(changes)?;
        // Reject path aliases/prefix conflicts before reading or publishing
        // any source object. This metadata-only pass borrows paths from the
        // object list and therefore does not duplicate repository bytes.
        {
            let mut paths = objects
                .iter()
                .map(|(_, path, change_id, _)| (*change_id, path))
                .collect::<Vec<_>>();
            paths.sort_by(|left, right| {
                left.0
                     .0
                    .as_bytes()
                    .cmp(right.0 .0.as_bytes())
                    .then_with(|| left.1.cmp(right.1))
            });
            let mut start = 0;
            while start < paths.len() {
                let change_id = paths[start].0;
                let mut end = start + 1;
                while end < paths.len() && paths[end].0 == change_id {
                    end += 1;
                }
                kin_core::validate_source_paths(paths[start..end].iter().map(|(_, path)| *path))
                    .map_err(|error| {
                        exact_source_storage_error(format!(
                            "exact source change {change_id} is not materializable: {error}"
                        ))
                    })?;
                start = end;
            }
        }

        let mut start = 0;
        while start < objects.len() {
            let hash = objects[start].0;
            let mut end = start + 1;
            while end < objects.len() && objects[end].0 == hash {
                end += 1;
            }
            let digest = *hash.as_bytes();
            match self.blobs.read(&kin_blobs::Hash256(digest)) {
                Ok(data) => {
                    for (_, path, _, entry) in &objects[start..end] {
                        validate_exact_source_bytes(path, *entry, hash, &data, "local")?;
                    }
                    backend
                        .save_source_blob(repo_id, digest, &data)
                        .map_err(DaemonError::from)?;
                }
                Err(local_error) => match backend
                    .load_source_blob(repo_id, digest)
                    .map_err(DaemonError::from)?
                {
                    Some(data) => {
                        for (_, path, _, entry) in &objects[start..end] {
                            validate_exact_source_bytes(path, *entry, hash, &data, "backend")?;
                        }
                        let (_, first_path, first_change_id, _) = &objects[start];
                        warn!(
                            repo_id,
                            file = %first_path,
                            change = %first_change_id,
                            hash = %hash,
                            references = end - start,
                            error = %local_error,
                            "local source object unavailable; retained verified backend authority"
                        );
                    }
                    None => {
                        let (_, path, change_id, _) = &objects[start];
                        return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                            format!(
                                "exact source bytes for {} in change {} at {} are absent from both local and backend authority: {local_error}",
                                path, change_id, hash
                            ),
                        )));
                    }
                },
            };
            start = end;
        }
        Ok(())
    }

    /// Preflight one incoming semantic change before mutating the live graph.
    /// Hosted graph commits do not share the caller's local object directory;
    /// an exact change whose bytes are unavailable must therefore fail before
    /// its entities, relations, change record, or branch head become visible.
    #[cfg(test)]
    pub(crate) fn preflight_exact_source_change(
        &self,
        graph: &kin_db::InMemoryGraph,
        change: &SemanticChange,
    ) -> Result<()> {
        if let Some(backend) = &self.storage_backend {
            self.persist_exact_source_objects(
                backend.as_ref(),
                self.cached_repo_id.as_str(),
                std::iter::once(change),
            )?;
        }

        let prospective = ProspectiveChangeStore {
            graph,
            incoming: change,
        };
        let entries = prospective
            .resolve_tree_at(&change.id)
            .map_err(DaemonError::from)?;
        self.preflight_materializable_source_entries(entries, "incoming exact")
    }

    #[cfg(test)]
    fn preflight_materializable_source_entries(
        &self,
        entries: ResolvedTree,
        purpose: &str,
    ) -> Result<()> {
        let mut entries = entries.into_artifacts().collect::<Vec<_>>();
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        kin_core::validate_source_paths(entries.iter().map(|artifact| &artifact.path)).map_err(
            |error| {
                exact_source_storage_error(format!(
                    "{purpose} source tree is not materializable: {error}"
                ))
            },
        )?;
        entries.sort_by(|left, right| {
            left.entry
                .blob_identity()
                .cmp(&right.entry.blob_identity())
                .then_with(|| left.path.cmp(&right.path))
        });
        let mut start = 0;
        while start < entries.len() {
            let Some(source_hash) = entries[start].entry.blob_identity() else {
                // Gitlinks have no repository-owned source body.
                start += 1;
                continue;
            };
            let mut end = start + 1;
            while end < entries.len() && entries[end].entry.blob_identity() == Some(source_hash) {
                end += 1;
            }
            let digest = *source_hash.as_bytes();
            let (data, authority) = if let Some(backend) = &self.storage_backend {
                let data = backend
                    .load_source_blob(self.cached_repo_id.as_str(), digest)
                    .map_err(DaemonError::from)?
                    .ok_or_else(|| {
                        exact_source_storage_error(format!(
                            "{purpose} source bytes for {} at {} are absent from backend authority",
                            entries[start].path, source_hash
                        ))
                    })?;
                (data, "backend")
            } else {
                let data = self
                    .blobs
                    .read(&kin_blobs::Hash256(digest))
                    .map_err(|error| {
                        exact_source_storage_error(format!(
                            "{purpose} source bytes for {} at {} are absent or corrupt in local authority: {error}",
                            entries[start].path, source_hash
                        ))
                    })?;
                (data, "local")
            };
            for artifact in &entries[start..end] {
                validate_exact_source_bytes(
                    &artifact.path,
                    artifact.entry,
                    source_hash,
                    &data,
                    authority,
                )?;
            }
            start = end;
        }
        Ok(())
    }

    /// Whether filesystem-to-graph compatibility ingestion is disabled for
    /// this daemon. The value is captured when state opens so runtime behavior
    /// cannot drift if the process environment later changes.
    pub(crate) fn filesystem_reconcile_disabled(&self) -> bool {
        self.filesystem_reconcile_disabled.load(Ordering::Relaxed)
    }

    /// Advance this process's repository-authority cursor after a successful
    /// local repository-v6 compare-and-swap.
    ///
    /// The repository transaction is already durable at this point. Derived
    /// query indexes and the cross-process generation marker are finalized by
    /// the normal serialized persistence pass; a crash before then is healed
    /// from repository authority during the next open.
    pub(crate) fn record_repository_authority_commit(&self, generation: u64) -> Result<()> {
        if self.storage_backend.is_some() {
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                "local repository-v6 generation cannot be installed on a storage-backend daemon"
                    .to_string(),
            )));
        }
        let previous = self.snapshot_generation.load(Ordering::SeqCst);
        if generation <= previous {
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                format!(
                    "repository authority generation must advance beyond {previous}, got {generation}"
                ),
            )));
        }
        self.snapshot_generation.store(generation, Ordering::SeqCst);
        self.post_commit_finalization_pending
            .store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Write derived semantics into the live query graph the way the LSP
    /// enrichment worker does: additive upserts under nothing but the graph
    /// authority epoch, holding neither the coordination gate nor the
    /// persistence lock. Used to place an enrichment tick at an exact point
    /// inside a repository command rather than waiting for a real worker to
    /// race one in.
    #[cfg(test)]
    pub(crate) fn install_derived_enrichment(&self) {
        use kin_model::EntityStore;
        let anchor = kin_model::Entity {
            id: kin_model::EntityId::new(),
            kind: kin_model::EntityKind::Function,
            name: "enriched_inside_the_command_window".to_string(),
            language: kin_model::LanguageId::Rust,
            fingerprint: kin_model::SemanticFingerprint {
                algorithm: kin_model::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: kin_model::Hash256::from_bytes([11; 32]),
                signature_hash: kin_model::Hash256::from_bytes([12; 32]),
                behavior_hash: kin_model::Hash256::from_bytes([13; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: "fn enriched_inside_the_command_window()".to_string(),
            visibility: kin_model::Visibility::Public,
            role: kin_model::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };
        let relation = kin_model::Relation {
            id: kin_model::RelationId::new(),
            kind: kin_model::RelationKind::Calls,
            src: kin_model::GraphNodeId::Entity(anchor.id),
            dst: kin_model::GraphNodeId::Entity(anchor.id),
            confidence: 0.95,
            origin: kin_model::RelationOrigin::Lsp,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        let _guard = self.begin_graph_authority_mutation();
        self.graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![kin_model::EntityDelta::Added { new: anchor }],
                ..TransactionDelta::default()
            })
            .expect("derived enrichment entity must reach the live graph");
        self.graph
            .upsert_relation(&relation)
            .expect("derived enrichment relation must reach the live graph");
        self.bump_version();
    }

    /// Install one already-durable local repository receipt into the daemon's
    /// derived graph and generation cursor.
    ///
    /// Callers must hold `coordination_gate`, `persist_lock`, and one
    /// `GraphAuthorityMutationGuard` across both the repository CAS and this
    /// method. The complete delta must have been constructed and preflighted
    /// before that irreversible CAS. This method revalidates the transition
    /// against the still-live graph so a replay heals the authority/daemon crash
    /// gap without absorbing an unrelated later generation.
    ///
    /// The daemon-side semantic and tree transition is planned here rather than
    /// taken from `planned_delta`. Between planning and this call the authority
    /// transaction committed and the projection was materialized, and the
    /// asynchronous LSP enrichment worker writes into the live graph without
    /// taking either the coordination gate or the persistence lock. A plan-time
    /// delta can therefore no longer describe the transition the live graph
    /// needs, and applying it would leave the daemon short of the exact
    /// authority graph after authority had already advanced. Only the admission
    /// policy transition, which no derived writer produces, is carried over from
    /// the plan.
    ///
    /// One consequence is worth naming: because the target is the exact
    /// authority graph, every finalization discards whatever derived enrichment
    /// the live graph is holding beyond authority. That lead is derived, and the
    /// enrichment worker recomputes it.
    pub(crate) fn finalize_local_repository_commit(
        &self,
        receipt: &RepositoryCommitReceipt,
        authority_freeze: &LocalRepositoryAuthorityFreeze,
        planned_delta: &TransactionDelta,
        expected_previous_tree: &ResolvedTree,
        desired_tree: &ResolvedTree,
    ) -> Result<LocalRepositoryFinalization> {
        receipt.validate().map_err(DaemonError::from)?;
        if self.storage_backend.is_some() {
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                "local repository receipt cannot finalize on hosted graph authority".to_string(),
            )));
        }
        if receipt.repository_id.as_str() != self.cached_repo_id {
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                format!(
                    "repository receipt belongs to {}, not daemon repository {}",
                    receipt.repository_id, self.cached_repo_id
                ),
            )));
        }

        if authority_freeze.roots() != &receipt.roots_after {
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                "repository finalization freeze is not bound to the committed receipt roots"
                    .to_string(),
            )));
        }
        let workspace_id = self.cached_workspace_id.ok_or_else(|| {
            DaemonError::Graph(kin_db::KinDbError::StorageError(
                "local daemon is missing its startup workspace binding".to_string(),
            ))
        })?;
        let authority_snapshot = authority_freeze
            .authority()
            .workspace_graph_snapshot(&workspace_id)
            .map_err(DaemonError::from)?
            .ok_or_else(|| {
                DaemonError::Graph(kin_db::KinDbError::StorageError(format!(
                    "frozen repository authority has no workspace {workspace_id}"
                )))
            })?;
        let authority_graph =
            kin_db::InMemoryGraph::from_snapshot(authority_snapshot).map_err(DaemonError::from)?;
        if authority_graph.resolved_tree() != *desired_tree {
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                format!(
                    "repository receipt generation {} does not resolve to the desired tree",
                    receipt.generation
                ),
            )));
        }

        let live_generation = self.snapshot_generation.load(Ordering::SeqCst);
        if live_generation != receipt.roots_before.generation
            && live_generation != receipt.roots_after.generation
        {
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                format!(
                    "daemon generation {live_generation} matches neither repository receipt base {} nor result {}; reopen from repository authority",
                    receipt.roots_before.generation, receipt.roots_after.generation
                ),
            )));
        }
        let live_tree = self.graph.resolved_tree();
        if live_tree != *expected_previous_tree && live_tree != *desired_tree {
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                "daemon query tree matches neither repository receipt base nor result; reopen from repository authority"
                    .to_string(),
            )));
        }

        // Record what this transition does to graph-only membership before the
        // query tree moves. Every repository transition seam finalizes here, so
        // this is the one place that sees both sides of one, and taking the
        // verdict from the transition rather than from the tree afterwards is
        // what makes it independent of when a watcher event drains: until the
        // apply below, a member is live and ambient observation drops events
        // beneath it; from here on it is retired and the host content under it
        // is reported untracked instead of admitted as something newly written.
        let previous_members = crate::graph_only_members::members_of(expected_previous_tree)
            .map_err(|error| {
                DaemonError::Graph(kin_db::KinDbError::StorageError(format!(
                    "cannot read graph-only members of the repository transition base: {error}"
                )))
            })?;
        let desired_members =
            crate::graph_only_members::members_of(desired_tree).map_err(|error| {
                DaemonError::Graph(kin_db::KinDbError::StorageError(format!(
                    "cannot read graph-only members of the repository transition result: {error}"
                )))
            })?;
        self.retired_graph_only_members
            .retire(previous_members.difference(&desired_members));

        let authority_snapshot = authority_graph.to_snapshot();
        let live_snapshot = self.graph.to_snapshot();
        let semantics = kin_core::diff_workspace_semantics(
            &live_snapshot.entities,
            &live_snapshot.relations,
            &authority_snapshot.entities,
            &authority_snapshot.relations,
        )?;
        let tree_deltas =
            kin_core::exact_tree_correction(&live_snapshot.resolved_tree, desired_tree)?;
        let finalization_delta = TransactionDelta {
            entity_deltas: semantics.entity_deltas().to_vec(),
            relation_deltas: semantics.relation_deltas().to_vec(),
            tree_deltas,
            admission_policy_delta: planned_delta.admission_policy_delta.clone(),
            external_reference_deltas: Vec::new(),
        };
        let graph_changed = finalization_delta != TransactionDelta::default();
        if graph_changed {
            let preflight =
                kin_db::InMemoryGraph::from_snapshot(live_snapshot).map_err(DaemonError::from)?;
            preflight
                .apply_transaction_delta(&finalization_delta)
                .map_err(DaemonError::from)?;
            let preflight_snapshot = preflight.to_snapshot();
            if preflight_snapshot.resolved_tree != *desired_tree
                || preflight_snapshot.entities != authority_snapshot.entities
                || preflight_snapshot.relations != authority_snapshot.relations
            {
                return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                    "preflighted repository delta does not produce the durable workspace graph"
                        .to_string(),
                )));
            }
            self.graph
                .apply_transaction_delta(&finalization_delta)
                .map_err(DaemonError::from)?;
        }
        let live_snapshot = self.graph.to_snapshot();
        if live_snapshot.resolved_tree != *desired_tree
            || live_snapshot.entities != authority_snapshot.entities
            || live_snapshot.relations != authority_snapshot.relations
        {
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                "repository graph finalization did not install the durable workspace graph"
                    .to_string(),
            )));
        }
        // A path this transition restored as a graph-only member is covered by
        // the live rule again from here on, so its retirement has nothing left
        // to do. Dropped after the apply rather than before it, so the two rules
        // never hand off through a gap.
        self.retired_graph_only_members
            .forget_live_members(&desired_members);

        let generation_advanced = live_generation == receipt.roots_before.generation;
        if generation_advanced {
            self.record_repository_authority_commit(receipt.generation)?;
        }
        Ok(LocalRepositoryFinalization {
            graph_changed,
            generation_advanced,
        })
    }

    #[cfg(any(feature = "embeddings", feature = "vector"))]
    fn reject_remote_backend_embed_persistence(&self, operation: &str) -> Result<()> {
        if self.can_persist_embed_progress_locally() {
            return Ok(());
        }
        let generation = self.snapshot_generation.load(Ordering::SeqCst);
        Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
            format!(
                "{operation} skipped: storage-backend graph authority is at generation {generation}, and no backend vector-sidecar persistence contract exists; refusing a local derived checkpoint against remote authority"
            ),
        )))
    }

    fn save_snapshot_impl(&self, mode: SnapshotSaveMode) -> Result<()> {
        // Serialize the whole kndb + generation-marker + kidx write sequence
        // against any other save (persist loop, idle flush, embed worker).
        // Without this, two concurrent saves race on the shared tmp paths and
        // can leave a torn kndb/kidx pair. Held only for this synchronous body
        // (no `.await` inside), so a std Mutex is sound.
        let _persist_guard = self
            .persist_lock
            .lock()
            .map_err(|_| DaemonError::Io(std::io::Error::other("persist lock poisoned")))?;

        // Make the derived CAS names durable before persisting a graph that
        // references them.
        //
        // kin-blobs defers the directory barrier that makes a blob's *name*
        // durable and amortizes it across shards, so a write returning Ok does
        // not yet mean the rename survives a crash. Its contract puts the
        // obligation on the caller: sync is the commit point for anyone about
        // to record those names somewhere that outlives a crash. This is that
        // point. Skipping it would let a snapshot name bodies whose renames are
        // still only in the page cache.
        //
        // Cheap in the steady state: sync returns immediately when nothing is
        // pending, and otherwise costs one fsync per shard directory touched
        // since the last barrier, which two-hex sharding caps at 256 no matter
        // how many blobs were written.
        self.blobs.sync().map_err(DaemonError::from)?;

        let force_full = mode == SnapshotSaveMode::Full;

        let repo_id = self.cached_repo_id.as_str();
        let expected_gen = self.snapshot_generation.load(Ordering::SeqCst);
        let mut committed = false;

        let new_gen = if let Some(backend) = &self.storage_backend {
            if self.hosted_authority_envelope {
                // The derived flush must never write this backend's authority
                // object, and this is the one place all four callers reach:
                // the periodic loop, the shutdown flush, the pre-idle flush and
                // the LSP sweep. Guarding the wall-clock trigger instead would
                // leave the other three writing.
                //
                // Both backend writes are barred here, for two different
                // reasons that happen to land on the same branch. A full
                // snapshot is serialized from the in-place mutable graph, which
                // does not own the authority envelope and writes an explicit
                // null in its place, so committing one erases refs, receipts,
                // workspaces, aliases and admission state. An incremental delta
                // is barred by the format's own rule: once the envelope is
                // present, every root moves only through a full repository
                // transaction, and a storage-backend daemon cannot run one
                // because `record_repository_authority_commit` refuses it.
                //
                // So there is nothing here this daemon is entitled to commit,
                // and the honest flush is the local half. The text index is
                // derived from the live graph and rebuildable from it, which is
                // why it can be made durable without an authority commit
                // behind it.
                //
                // Deliberately not a graph-persistence epoch. Detaching a batch
                // and completing it would acknowledge work no durable object
                // holds, and the next open would come back without it. That is
                // the exact failure the local arm below documents having made
                // once already, and it is worse than not flushing, because it
                // is silent.
                self.graph.flush_text_index().map_err(DaemonError::from)?;
                let refusals = self
                    .hosted_authority_flush_refusals
                    .fetch_add(1, Ordering::SeqCst)
                    + 1;
                debug!(
                    repo_id,
                    generation = expected_gen,
                    refusals,
                    "flushed derived text index only; the backend authority envelope is not this daemon's to rewrite"
                );
                // Deliberately `Ok`, not an error. The periodic loop marks the
                // state clean on success and only then stops flushing until the
                // next mutation; an error would instead climb
                // `consecutive_failures`, back off, and log "persistence
                // unhealthy" on a daemon behaving exactly as designed. A
                // refusal that is normal must not be reported as a fault.
                expected_gen
            } else if force_full
                || expected_gen == kin_db::GENERATION_INIT
                || self.graph.full_snapshot_required()
                || !backend.supports_incremental_deltas()
            {
                let (bytes, graph_root_hash, retrieval_authority_hash, persistence_epoch) = self
                    .graph
                    .begin_snapshot_persistence_with_retrieval_hash(None)
                    .map_err(DaemonError::from)?;
                let persistence_attempt =
                    GraphPersistenceAttempt::new(self.graph.as_ref(), persistence_epoch);
                let detached_snapshot =
                    kin_db::GraphSnapshot::from_bytes(&bytes).map_err(DaemonError::from)?;
                self.persist_exact_source_objects(
                    backend.as_ref(),
                    repo_id,
                    detached_snapshot.changes.values(),
                )?;
                // Keep every fallible derived-index operation before the
                // authority commit. If it fails, the RAII attempt forces a full
                // retry and the backend generation remains unchanged.
                kin_db::SnapshotManager::persist_snapshot_sidecars_for_epoch(
                    self.layout.kindb_snapshot_path().as_path(),
                    self.graph.as_ref(),
                    graph_root_hash,
                    retrieval_authority_hash,
                    persistence_epoch,
                )
                .map_err(DaemonError::from)?;
                let generation = backend
                    .save_snapshot(repo_id, &bytes, expected_gen)
                    .map_err(DaemonError::from)?;
                // From this point on the authority commit is irreversible.
                // Advance the CAS cursor and acknowledge only this detached
                // batch before attempting cleanup or local finalization.
                self.snapshot_generation.store(generation, Ordering::SeqCst);
                persistence_attempt.complete();
                self.post_commit_finalization_pending
                    .store(true, Ordering::SeqCst);
                committed = true;
                if let Err(error) = backend.clear_deltas(repo_id) {
                    warn!(
                        repo_id,
                        generation,
                        error = %error,
                        "snapshot committed; deferred stale delta cleanup"
                    );
                }
                generation
            } else if let Some((delta, persistence_epoch)) =
                self.graph.begin_delta_persistence(expected_gen)
            {
                let persistence_attempt =
                    GraphPersistenceAttempt::new(self.graph.as_ref(), persistence_epoch);
                self.persist_exact_source_objects(
                    backend.as_ref(),
                    repo_id,
                    delta
                        .changes
                        .added
                        .iter()
                        .chain(delta.changes.modified.iter())
                        .map(|(_, change)| change),
                )?;
                let bytes = delta.to_bytes().map_err(DaemonError::from)?;
                // A text-index failure must precede the durable delta commit.
                // The index is derived and root-stamped; the authority write is
                // the point after which this method must not lose its cursor.
                kin_db::SnapshotManager::invalidate_derived_sidecars(
                    self.layout.kindb_snapshot_path(),
                    self.graph.as_ref(),
                )
                .map_err(DaemonError::from)?;
                let generation = backend
                    .save_delta(repo_id, &bytes, expected_gen)
                    .map_err(DaemonError::from)?;
                self.snapshot_generation.store(generation, Ordering::SeqCst);
                persistence_attempt.complete();
                self.post_commit_finalization_pending
                    .store(true, Ordering::SeqCst);
                committed = true;
                generation
            } else {
                self.graph.flush_text_index().map_err(DaemonError::from)?;
                expected_gen
            }
        } else {
            // Local repository-v6 transactions are the only authority commit.
            // Exact tree admission and explicit commit publication move that
            // authority before mutating this derived runtime graph. Detach the
            // current derived batch, prove its exact tree matches the persisted
            // workspace at this generation, publish the language-server
            // relations that authority does not hold yet, then acknowledge the
            // batch after flushing query text. Never recreate graph.kndb as a
            // second local truth.
            //
            // The acknowledgement sits after the publication on purpose. This
            // arm used to detach a batch, discard it, and complete the epoch
            // regardless, so every language-server relation the sweep had just
            // installed was reported as persisted and was gone on the next
            // open. A failure now returns before `complete`, the RAII attempt
            // drops into `fail_persistence`, and nothing claims a batch it did
            // not write.
            let persistence_attempt = self
                .graph
                .begin_delta_persistence(expected_gen)
                .map(|(_, epoch)| GraphPersistenceAttempt::new(self.graph.as_ref(), epoch));
            // Publishing moves the authority generation, so it must not land
            // inside a repository command. That command planned against the
            // generation it read, and `require_fresh_daemon_workspace` compares
            // the two, so a publication between its plan and its commit makes it
            // refuse itself and tell the user to reopen. Taking the gate the
            // mutation routes take closes that window rather than narrowing it.
            //
            // A try, never a wait: this runs on the persist path, which may not
            // block on an async gate, and a flush is periodic anyway. When a
            // command holds it, the whole arm defers. Nothing is acknowledged,
            // the relations stay in the live graph, and the next flush derives
            // the same write set from there. The tree proof defers with it,
            // which is the point: an acknowledgement is worth nothing without
            // the proof beside it.
            let Ok(_coordinated) = self.coordination_gate.try_lock() else {
                debug!(
                    generation = expected_gen,
                    "deferred enrichment publication while a repository command holds the coordination gate"
                );
                return Ok(());
            };
            let published_generation = self.publish_local_workspace_enrichment(expected_gen)?;
            self.graph.flush_text_index().map_err(DaemonError::from)?;
            if let Some(attempt) = persistence_attempt {
                attempt.complete();
            }
            self.graph.clear_full_snapshot_required();
            published_generation
        };

        // Backend saves advance their own authority here. Local authority was
        // already advanced by the repository-v6 transaction and recorded by
        // `record_repository_authority_commit`; never overwrite a newer local
        // receipt that may arrive while derived-index I/O is finishing.
        if self.storage_backend.is_some() {
            self.snapshot_generation.store(new_gen, Ordering::SeqCst);
        }

        if committed {
            self.post_commit_finalization_pending
                .store(true, Ordering::SeqCst);
        }
        if self.post_commit_finalization_pending.load(Ordering::SeqCst) {
            self.finalize_committed_generation(new_gen)?;
        }

        info!(
            repo_id,
            generation = new_gen,
            committed,
            "saved snapshot to storage backend"
        );
        Ok(())
    }

    /// Incremental per-batch embed-progress flush for the background
    /// embed worker.
    ///
    /// Persists only the derived vector sidecar. Repository-v6 remains the sole
    /// graph/workspace authority; concurrent semantic or tree changes stay
    /// pending for the normal authority-aware persistence path rather than
    /// recreating a local graph.kndb checkpoint.
    #[cfg(feature = "embeddings")]
    pub fn flush_embed_progress(&self) -> Result<usize> {
        self.reject_remote_backend_embed_persistence("embed progress persistence")?;
        let _persist_guard = self
            .persist_lock
            .lock()
            .map_err(|_| DaemonError::Io(std::io::Error::other("persist lock poisoned")))?;
        let generation = self.snapshot_generation.load(Ordering::SeqCst);
        let live_tree = self.graph.resolved_tree();
        if !self
            .vector_checkpoint_authority_match
            .holds(generation, &live_tree)
        {
            let authority_graph = self.load_committed_authority_graph(generation)?;
            // The reopen is linear in store size, and this path holds only
            // `persist_lock` while commit and reconcile exclude on the
            // coordination gate, so the live graph can move while it runs.
            // Sample again after it, so the tree proved against authority is
            // the tree this call goes on to retain and checkpoint.
            #[cfg(test)]
            self.run_vector_checkpoint_reopen_hook();
            let live_tree = self.graph.resolved_tree();
            if live_tree != authority_graph.resolved_tree() {
                let refusal = format!(
                    "refusing vector checkpoint at repository generation {generation}: live exact tree does not match workspace authority"
                );
                // Record before returning. The caller logs this error and moves
                // on, and nothing downstream of that log would remember the
                // vectors were left undurable; the retry and every embedding
                // surface both read the record instead.
                self.record_deferred_vector_checkpoint(refusal.clone());
                return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                    refusal,
                )));
            }
            self.vector_checkpoint_authority_match
                .record(generation, live_tree);
        }
        // No producer identity: kin-db stamps the embedding runtime's own
        // provider/model/revision/epoch, which is what decides on reload
        // whether these vectors are still usable. Stamping this binary's build
        // SHA instead made the sidecar unloadable by the next release.
        kin_db::SnapshotManager::checkpoint_vector_index_for_graph(
            self.layout.kindb_snapshot_path(),
            self.graph.as_ref(),
            None,
        )
        .map_err(DaemonError::from)?;
        // Cleared only after the sidecar write returns. Clearing on entry, or
        // beside the authority proof above, would retire the record while the
        // work it describes was still undurable, which is the state the record
        // exists to keep visible.
        self.clear_deferred_vector_checkpoint();
        if self.post_commit_finalization_pending.load(Ordering::SeqCst) {
            self.finalize_committed_generation(generation)?;
        }
        Ok(self.graph.embedding_status().pending)
    }

    /// Remember that a vector checkpoint was refused, so the work it left in
    /// memory can be retried and named rather than silently abandoned.
    #[cfg(feature = "embeddings")]
    fn record_deferred_vector_checkpoint(&self, reason: String) {
        if let Ok(mut deferred) = self.deferred_vector_checkpoint.lock() {
            *deferred = Some(reason);
        }
    }

    /// Retire the record once a checkpoint has actually written the sidecar.
    #[cfg(feature = "embeddings")]
    fn clear_deferred_vector_checkpoint(&self) {
        if let Ok(mut deferred) = self.deferred_vector_checkpoint.lock() {
            *deferred = None;
        }
    }

    /// Why the last vector checkpoint was refused, while that refusal still
    /// stands.
    ///
    /// `Some` means this daemon holds embedded vectors the sidecar does not,
    /// so the coverage every counter reports is real for this process and would
    /// not survive its exit. Embedding surfaces read this to say so instead of
    /// rendering the shortfall as ordinary pending work on the next open. A
    /// poisoned lock answers `None`: an unreadable record is not evidence of a
    /// deferral, and the retry below is what closes the gap either way.
    #[cfg(feature = "embeddings")]
    pub fn deferred_vector_checkpoint(&self) -> Option<String> {
        self.deferred_vector_checkpoint
            .lock()
            .ok()
            .and_then(|deferred| deferred.clone())
    }

    #[cfg(not(feature = "embeddings"))]
    pub fn deferred_vector_checkpoint(&self) -> Option<String> {
        None
    }

    /// Re-attempt a checkpoint that was refused, and report what happened.
    ///
    /// `None` means nothing was deferred and no work was done, which is the
    /// answer on every tick of an ordinary daemon. `Some(Ok(pending))` means
    /// the sidecar was written and the vectors held since the refusal are now
    /// durable. `Some(Err(_))` means the tree still disagrees with authority
    /// and the record still stands, so a caller can back off rather than
    /// reopening authority every tick.
    ///
    /// Deliberately a retry of the same call rather than a weaker second path:
    /// the authority proof is the whole reason the first attempt refused, so a
    /// retry that skipped it would checkpoint exactly the state the refusal was
    /// protecting against.
    #[cfg(feature = "embeddings")]
    pub fn retry_deferred_vector_checkpoint(&self) -> Option<Result<usize>> {
        self.deferred_vector_checkpoint()?;
        Some(self.flush_embed_progress())
    }

    #[cfg(not(feature = "embeddings"))]
    pub fn retry_deferred_vector_checkpoint(&self) -> Option<Result<usize>> {
        None
    }

    #[cfg(not(feature = "embeddings"))]
    pub fn flush_embed_progress(&self) -> Result<usize> {
        Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
            "this Kin build does not include embedding support".to_string(),
        )))
    }

    /// Force the derived vector sidecar to disk regardless of the in-run flush
    /// throttle.
    ///
    /// While an embed drains, `flush_embed_progress` checkpoints the sidecar on a
    /// throttle rather than every batch, so a pass that ends time-limited (queue
    /// not yet drained) can leave the vectors embedded since the last throttle
    /// tick in memory only. Calling this at a pass boundary lands them durably,
    /// so a graceful daemon exit before the next pass resumes with the full pass
    /// persisted instead of re-deriving that last window. The vector index is a
    /// pure sidecar (not in the merkle root), so this never advances the graph
    /// generation. Cost is one index serialize per time-limited pass, not per
    /// batch.
    #[cfg(feature = "vector")]
    pub fn persist_vector_sidecar(&self) -> Result<()> {
        self.reject_remote_backend_embed_persistence("vector sidecar persistence")?;
        let _persist_guard = self
            .persist_lock
            .lock()
            .map_err(|_| DaemonError::Io(std::io::Error::other("persist lock poisoned")))?;
        // See `flush_embed_progress`: the sidecar carries the embedding
        // runtime's identity, never this binary's build SHA.
        kin_db::SnapshotManager::save_vector_index_for_graph(
            self.layout.kindb_snapshot_path(),
            self.graph.as_ref(),
            None,
        )
        .map_err(DaemonError::from)
    }

    #[cfg(not(feature = "vector"))]
    pub fn persist_vector_sidecar(&self) -> Result<()> {
        Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
            "this Kin build does not include vector support".to_string(),
        )))
    }

    /// Finish local artifacts for one already-committed authority generation.
    ///
    /// The read index is rebuilt from reopened durable authority, not the live
    /// graph, which may already contain mutations that arrived after the
    /// committed batch. It is staged off-path, the old canonical index is
    /// removed, the generation marker is durably published, and only then is
    /// the staged index promoted. Every crash point therefore leaves either the
    /// old generation or a missing derived index, never a stale canonical index
    /// presented as current authority.
    fn finalize_committed_generation(&self, generation: u64) -> Result<()> {
        #[cfg(test)]
        if self.finalization_fail_once.swap(false, Ordering::SeqCst) {
            return Err(DaemonError::Io(std::io::Error::other(
                "injected post-commit finalization failure",
            )));
        }

        let authority_graph = self.load_committed_authority_graph(generation)?;
        self.finalize_generation_from_graph(generation, authority_graph.as_ref())?;
        Ok(())
    }

    // The only caller is the #[cfg(unix)] test at api.rs, so on Windows this
    // wrapper has no callers and -D dead-code fails the lib test build. Gate it
    // to match its caller exactly rather than widening the private method it wraps.
    #[cfg(all(test, unix))]
    pub(crate) fn finalize_committed_generation_for_test(&self, generation: u64) -> Result<()> {
        self.finalize_committed_generation(generation)
    }

    /// Finish startup artifacts from the graph that was just loaded and
    /// validated before the state is exposed to any request or mutator.
    /// Reopening the same authority here doubles graph memory and repeats
    /// remote snapshot I/O on every healthy restart.
    fn finalize_loaded_generation(&self, generation: u64) -> Result<()> {
        self.finalize_generation_from_graph(generation, self.graph.as_ref())
    }

    /// A locate-only graph is intentionally incomplete for general-purpose
    /// references and traces, so it cannot rebuild the canonical read index.
    /// Remove any older index before publishing the loaded authority head;
    /// a missing derived index is fail-safe, while an old index paired with a
    /// new marker would advertise a mixed-generation state.
    fn finalize_loaded_locate_generation(&self, generation: u64) -> Result<()> {
        self.invalidate_canonical_read_index()?;
        self.write_generation_marker(generation)
    }

    fn finalize_generation_from_graph(
        &self,
        generation: u64,
        authority_graph: &kin_db::InMemoryGraph,
    ) -> Result<()> {
        let (staged_index, persisted_entity_count) =
            self.stage_read_index_from_graph(generation, authority_graph)?;
        let index_path = self.invalidate_canonical_read_index()?;
        self.write_generation_marker(generation)?;
        if let Err(error) = std::fs::rename(&staged_index, &index_path) {
            return Err(DaemonError::Io(error));
        }
        if let Some(parent) = index_path.parent() {
            sync_directory_metadata(parent).map_err(DaemonError::Io)?;
        }
        self.persisted_entity_count
            .store(persisted_entity_count, Ordering::SeqCst);
        self.post_commit_finalization_pending
            .store(false, Ordering::SeqCst);
        Ok(())
    }

    fn invalidate_canonical_read_index(&self) -> Result<std::path::PathBuf> {
        let index_path = self.layout.kindb_snapshot_path().with_extension("kidx");
        match std::fs::remove_file(&index_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(DaemonError::Io(error)),
        }
        if let Some(parent) = index_path.parent() {
            sync_directory_metadata(parent).map_err(DaemonError::Io)?;
        }
        Ok(index_path)
    }

    /// Prove the derived graph still matches workspace authority at this
    /// generation, publish the language-server relations authority does not
    /// hold yet, and report the generation the workspace ends at.
    ///
    /// Language-server relations are the one part of this derived graph that
    /// nothing rebuilds. Parser reconciliation re-derives its own output from
    /// the exact tree, and authority owns that tree. An enrichment edge exists
    /// only while a language server was running, and the sweep records the file
    /// it finished, so a reopen that finds those edges missing does not go
    /// looking again and the loss is permanent. Writing them into the workspace
    /// semantic overlay is what makes them survive: `workspace_graph_snapshot`
    /// replays that overlay on every open, which is the same path a daemon
    /// loads its graph through at startup.
    ///
    /// The write set comes from the live graph rather than from the detached
    /// persistence batch. A batch is swapped out of the pending buffer before
    /// anything writes it, so a failed write loses its contents while the
    /// relations themselves stay live, and no later batch carries them again.
    /// Diffing live against authority is idempotent instead: it republishes
    /// whatever an earlier attempt failed to land, and it does not care which
    /// batch an edge arrived in.
    ///
    /// One authority open serves the whole pass. An open is O(store) rather
    /// than a cheap handle, because kin-db decodes the complete persisted
    /// authority and then re-verifies every body in repository CAS against its
    /// content address, so the tree proof, the diff, and the commit all run
    /// against this one lease.
    fn publish_local_workspace_enrichment(&self, expected_generation: u64) -> Result<u64> {
        let binding = self.local_repository_authority_binding()?;
        let authority = binding.open_manager().map_err(DaemonError::from)?;
        let workspace_id = binding.workspace_id();
        let lease = authority.read_authority();
        let observed_generation = lease.roots().generation;
        if observed_generation != expected_generation {
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                format!(
                    "post-commit authority moved for repo {}: expected generation {expected_generation}, recovered {observed_generation}; reopen before finalizing derived indexes",
                    self.cached_repo_id
                ),
            )));
        }
        // One expression on one line, because the zero-file-search guard pins
        // this authority accessor by its exact source text: it shares a name
        // with the filesystem metadata probe in the shared deny set and is
        // otherwise indistinguishable from one.
        let authority_metadata = lease.metadata();
        let workspace = authority_metadata
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == workspace_id)
            .cloned()
            .ok_or_else(|| {
                DaemonError::Graph(kin_db::KinDbError::StorageError(format!(
                    "local repository {} authority has no startup-pinned workspace {workspace_id}",
                    self.cached_repo_id
                )))
            })?;
        let authority_snapshot = lease
            .workspace_graph_snapshot(&workspace_id)
            .map_err(DaemonError::from)?
            .ok_or_else(|| {
                DaemonError::Graph(kin_db::KinDbError::StorageError(format!(
                    "local repository {} authority has no graph for workspace {workspace_id}",
                    self.cached_repo_id
                )))
            })?;
        let roots = lease.roots().clone();
        // The lease is a read of this authority and the commit below goes
        // through the authority itself, so the read ends here and the open
        // does not.
        drop(lease);

        let live_tree = self.graph.resolved_tree();
        if live_tree != authority_snapshot.resolved_tree {
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                format!(
                    "refusing to acknowledge derived graph state at repository generation {expected_generation}: live exact tree does not match workspace authority"
                ),
            )));
        }

        let live_snapshot = self.graph.to_snapshot();
        let (semantic_delta, unpublishable) =
            Self::language_server_enrichment_delta(&live_snapshot, &authority_snapshot)?;
        if unpublishable > 0 {
            debug!(
                unpublishable,
                "language-server relations name a node this workspace authority does not hold and were not published"
            );
        }
        if semantic_delta.is_empty() {
            return Ok(expected_generation);
        }
        let published = semantic_delta.relation_deltas().len();

        let new_generation = workspace.generation.checked_add(1).ok_or_else(|| {
            DaemonError::Graph(kin_db::KinDbError::StorageError(format!(
                "workspace {workspace_id} is at generation {}, the highest kin can record, so language-server enrichment cannot be published",
                workspace.generation
            )))
        })?;
        let transaction = kin_model::RepositoryTransaction {
            schema_version: kin_model::REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id: binding.repository_id().clone(),
            expected_generation,
            expected_roots: roots,
            actor: kin_model::AuthorId::new("kin"),
            reason: "publish language-server reference enrichment".to_string(),
            external_objects: Vec::new(),
            changes: Vec::new(),
            aliases: Vec::new(),
            git_authority_delta: None,
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: Some(kin_model::WorkspaceMutation {
                workspace_id,
                expected: kin_model::WorkspaceExpectation::MustEqual {
                    generation: workspace.generation,
                    head: workspace.head.clone(),
                    base_target: workspace.base_target.clone(),
                    base_tree_hash: workspace.base_tree_hash,
                    tree_hash: workspace.tree_hash,
                    semantic_overlay_hash: workspace.semantic_overlay_hash,
                    admission_policy: workspace.admission_policy,
                },
                new_generation,
                new_head: workspace.head.clone(),
                new_base_target: workspace.base_target.clone(),
                new_base_tree_hash: workspace.base_tree_hash,
                // Enrichment changes what kin knows about the tree, never the
                // tree. Restating the exact tree hash unchanged is what keeps
                // this a semantic publication rather than a tree admission.
                tree_deltas: Vec::new(),
                new_tree_hash: workspace.tree_hash,
                semantic_delta,
                new_shared_admission_policy: workspace.shared_admission_policy.clone(),
                new_admission_policy: workspace.admission_policy,
            }),
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        let receipt = authority
            .commit_repository_transaction(transaction)
            .map_err(DaemonError::from)?;
        self.record_repository_authority_commit(receipt.generation)?;
        info!(
            repo_id = self.cached_repo_id.as_str(),
            published,
            generation = receipt.generation,
            "published language-server enrichment into workspace authority"
        );
        Ok(receipt.generation)
    }

    /// The canonical workspace semantic transition that publishes every
    /// language-server relation the live graph holds and authority does not,
    /// paired with the count this workspace cannot carry.
    ///
    /// Only `RelationOrigin::Lsp` edges are published. The rest of the derived
    /// graph is reproducible from the exact tree authority already owns, so
    /// promoting it here would turn a derived view into authority rather than
    /// repair a loss.
    ///
    /// The desired set starts from what authority already holds, so this can
    /// only add or refine. Enrichment never retracts an authority relation:
    /// a language server that is absent this run, or slower than the last one,
    /// would otherwise delete durable truth by failing to reproduce it.
    ///
    /// An edge is skipped unless authority holds both of its endpoints as
    /// entities. A relation is not a place to introduce an entity, and the
    /// endpoint an enrichment edge names may be an artifact, a test, or a
    /// symbol owned outside this repository; publishing one of those here would
    /// ask authority to accept a relation into a node it cannot resolve.
    fn language_server_enrichment_delta(
        live: &kin_db::GraphSnapshot,
        authority: &kin_db::GraphSnapshot,
    ) -> Result<(kin_model::WorkspaceSemanticDelta, usize)> {
        let mut desired = authority.relations.clone();
        let mut unpublishable = 0usize;
        for (relation_id, relation) in &live.relations {
            if relation.origin != kin_model::RelationOrigin::Lsp {
                continue;
            }
            if !authority_holds_entity(authority, &relation.src)
                || !authority_holds_entity(authority, &relation.dst)
            {
                unpublishable += 1;
                continue;
            }
            desired.insert(*relation_id, relation.clone());
        }
        let delta = kin_core::diff_workspace_semantics(
            &authority.entities,
            &authority.relations,
            &authority.entities,
            &desired,
        )
        .map_err(|error| {
            DaemonError::Graph(kin_db::KinDbError::StorageError(format!(
                "canonicalize language-server enrichment transition: {error}"
            )))
        })?;
        Ok((delta, unpublishable))
    }

    fn load_committed_authority_graph(
        &self,
        generation: u64,
    ) -> Result<Arc<kin_db::InMemoryGraph>> {
        let authority_graph = if let Some(backend) = &self.storage_backend {
            match kin_db::load_recovered_snapshot(backend.as_ref(), &self.cached_repo_id)
                .map_err(DaemonError::from)?
            {
                Some(recovered) => {
                    if recovered.generation != generation {
                        return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                            format!(
                                "post-commit authority moved for repo {}: expected generation {generation}, recovered {}; reopen before finalizing derived indexes",
                                self.cached_repo_id, recovered.generation
                            ),
                        )));
                    }
                    let (query_snapshot, _) =
                        materialize_hosted_repository_snapshot(recovered.snapshot)?;
                    Arc::new(
                        kin_db::InMemoryGraph::from_snapshot(query_snapshot)
                            .map_err(DaemonError::from)?,
                    )
                }
                None if generation == kin_db::GENERATION_INIT => Arc::clone(&self.graph),
                None => {
                    return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                        format!(
                            "committed generation {generation} for repo {} is missing during read-index finalization",
                            self.cached_repo_id
                        ),
                    )))
                }
            }
        } else {
            let binding = self.local_repository_authority_binding()?;
            let authority = binding.open_manager().map_err(DaemonError::from)?;
            let lease = authority.read_authority();
            let observed_generation = lease.roots().generation;
            if observed_generation != generation {
                return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                    format!(
                        "post-commit authority moved for repo {}: expected generation {generation}, recovered {observed_generation}; reopen before finalizing derived indexes",
                        self.cached_repo_id
                    ),
                )));
            }
            let snapshot = lease
                .workspace_graph_snapshot(&binding.workspace_id())
                .map_err(DaemonError::from)?
                .ok_or_else(|| {
                    DaemonError::Graph(kin_db::KinDbError::StorageError(format!(
                        "repository {} authority has no manifest workspace {} during read-index finalization",
                        self.cached_repo_id,
                        binding.workspace_id()
                    )))
                })?;
            Arc::new(kin_db::InMemoryGraph::from_snapshot(snapshot).map_err(DaemonError::from)?)
        };
        Ok(authority_graph)
    }

    fn stage_read_index_from_graph(
        &self,
        generation: u64,
        authority_graph: &kin_db::InMemoryGraph,
    ) -> Result<(std::path::PathBuf, u64)> {
        let index = kin_db::ReadIndex::from_graph(authority_graph).map_err(DaemonError::from)?;
        let idx_path = self.layout.kindb_snapshot_path().with_extension("kidx");
        if let Some(parent) = idx_path.parent() {
            std::fs::create_dir_all(parent).map_err(DaemonError::Io)?;
        }
        let mut staged_name = std::ffi::OsString::from(idx_path.as_os_str());
        staged_name.push(format!(".pending-{generation}-{}", std::process::id()));
        let staged_path = std::path::PathBuf::from(staged_name);
        index.save(&staged_path).map_err(DaemonError::from)?;
        Ok((staged_path, authority_graph.entity_count() as u64))
    }

    /// Write the durable authority head to `.kin/kindb/head-generation`.
    ///
    /// CLI and MCP processes compare this derived notification marker to their
    /// loaded repository-v6 generation. A mismatch means repository authority
    /// moved and the reader must acquire a new exact lease before answering.
    fn write_generation_marker(&self, generation: u64) -> Result<()> {
        use std::io::Write;

        let gen_path = self.layout.kindb_head_generation_path();
        let tmp_path = gen_path.with_extension(format!("tmp-{}", std::process::id()));
        let parent = gen_path.parent().ok_or_else(|| {
            DaemonError::Io(std::io::Error::other(
                "generation marker path has no parent directory",
            ))
        })?;
        std::fs::create_dir_all(parent).map_err(DaemonError::Io)?;
        {
            let mut file = std::fs::File::create(&tmp_path).map_err(DaemonError::Io)?;
            file.write_all(generation.to_string().as_bytes())
                .map_err(DaemonError::Io)?;
            file.sync_all().map_err(DaemonError::Io)?;
        }
        if let Err(error) = std::fs::rename(&tmp_path, &gen_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(DaemonError::Io(error));
        }
        sync_directory_metadata(parent).map_err(DaemonError::Io)?;
        Ok(())
    }

    /// How many entities durable repository authority carried when this daemon
    /// last levelled its query graph with authority, or `None` when it never
    /// has (FIR-2421).
    ///
    /// `None` is a real answer and must not be collapsed to zero. A daemon that
    /// never levelled cannot say how much of its live graph is recorded, and
    /// zero would report all of it as uncommitted.
    pub fn durable_entity_count(&self) -> Option<u64> {
        match self.durable_entity_count.load(Ordering::Relaxed) {
            u64::MAX => None,
            count => Some(count),
        }
    }

    /// Record that the live query graph now carries everything durable
    /// authority carries, and how much that is.
    ///
    /// Called from the paths that actually level the two: opening a graph out
    /// of a durable workspace snapshot, and installing a committed authority
    /// graph onto the live one. It takes the count rather than reading it back
    /// off the live graph so the number is the durable side's, not a live side
    /// an ambient admission may already have moved.
    pub fn record_durable_entity_count(&self, count: u64) {
        // The sentinel is a value the counter can never legitimately reach, so
        // clamping is the only way a real store could ever be read as "never
        // levelled". A repository with `u64::MAX` entities does not exist.
        self.durable_entity_count
            .store(count.min(u64::MAX - 1), Ordering::Relaxed);
    }

    /// Read the current durable authority head from
    /// `.kin/kindb/head-generation`.
    ///
    /// Returns 0 if the file doesn't exist. CLI and MCP can call this
    /// before queries to check if the daemon has committed a newer snapshot
    /// than what they have loaded in memory.
    pub fn read_generation_marker(layout: &KinLayout) -> u64 {
        let gen_path = layout.kindb_head_generation_path();
        std::fs::read_to_string(&gen_path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0)
    }

    /// Whether the durable read index already describes exactly this generation.
    ///
    /// [`Self::finalize_generation_from_graph`] stages the new index off-path,
    /// removes the canonical index, publishes the marker, and only then promotes
    /// the staged file. Every crash point in that order therefore leaves the
    /// index either absent or matching the marker beside it, never stale. A
    /// marker naming this generation with an index present is consequently proof
    /// the two were published together, and a crash mid-sequence leaves no index
    /// and declines here.
    ///
    /// Startup is what this buys. Reopening a repository whose derived index is
    /// already current otherwise rebuilds that index from the whole graph and
    /// fsyncs it before the API listener binds, so the cost lands entirely
    /// inside the window where a client cannot reach the daemon at all.
    fn durable_read_index_matches_generation(layout: &KinLayout, generation: u64) -> bool {
        Self::read_generation_marker(layout) == generation
            && layout
                .kindb_snapshot_path()
                .with_extension("kidx")
                .is_file()
    }

    /// Name the open-path hydration gap on an error that a hydrated ingestion
    /// CAS would not have produced.
    ///
    /// Without this a hosted daemon reports "cannot load graph-owned blob X",
    /// which reads as graph corruption. The blob is fine; nothing ever put it
    /// in this instance's derived store, and that is a different problem with a
    /// different fix.
    fn attribute_ingest_cas_gap(&self, error: DaemonError) -> DaemonError {
        match &self.ingest_cas_hydration_gap {
            Some(reason) => exact_source_storage_error(format!(
                "{error}; the derived ingestion CAS was never hydrated on this open path: {reason}"
            )),
            None => error,
        }
    }

    /// Issue the derived ingestion CAS's deferred directory barriers.
    ///
    /// The store defers the barrier that makes a blob's *name* durable and
    /// amortizes it across shard directories, with three commit points:
    /// an explicit sync, `Drop`, and a self-drain once enough renames pile up.
    /// The daemon ends in `process::exit`, which runs no destructor, so without
    /// an explicit call the only operative barrier is the self-drain — leaving
    /// up to a full drain threshold of un-barriered renames behind every
    /// shutdown, including clean ones.
    pub fn sync_blob_store(&self) -> Result<()> {
        self.blobs.sync().map_err(DaemonError::from)
    }

    /// Rebuild projection state from the current graph.
    ///
    /// Loads every persisted [`FileLayout`] and its blob-backed base content
    /// from the graph's exact resolved tree. Missing entries or blobs are
    /// authority gaps and fail loudly; runtime projection never repairs graph
    /// truth from raw filesystem contents.
    ///
    /// Called after graph init, snapshot load, or a write-notify reconcile.
    pub async fn rebuild_projection(&self) -> Result<()> {
        let mut projection = self.projection.write().await;

        let tree = self.graph.resolved_tree();
        let state =
            ProjectionState::from_resolved_tree(self.graph.as_ref(), self.blobs.as_ref(), &tree)
                .map_err(|error| self.attribute_ingest_cas_gap(DaemonError::from(error)))?;
        let registered = state.file_ids().len();
        *projection = state;
        info!(
            files = registered,
            "rebuilt projection state from persisted graph truth"
        );
        Ok(())
    }

    /// Refresh projection state for a touched-file set.
    ///
    /// This is the warm path after reconcile/VFS writes: removed files are
    /// evicted from the projection cache, and added/modified files are loaded
    /// from graph-owned layout + blob content. Missing entries or blobs fail
    /// loudly instead of being repaired from the filesystem.
    pub async fn refresh_projection(&self, changed: &ProjectionChangedSet) -> Result<()> {
        if changed.is_empty() {
            return Ok(());
        }

        let mut projection = self.projection.write().await;
        let mut loaded = 0usize;
        let mut removed = 0usize;
        let mut skipped = 0usize;

        for file_id in &changed.removed {
            projection.remove_file(file_id);
            removed += 1;
        }

        for file_id in &changed.upserted {
            let Some(layout) = self
                .graph
                .get_file_layout(file_id)
                .map_err(DaemonError::from)?
            else {
                projection.remove_file(file_id);
                skipped += 1;
                continue;
            };

            let entry = self
                .graph
                .get_tree_entry(file_id)
                .map_err(DaemonError::from)?
                .ok_or_else(|| {
                    exact_source_storage_error(format!(
                        "projection refresh for {file_id} has no graph-owned tree entry"
                    ))
                })?;
            let TreeEntry::Blob { hash, .. } = entry else {
                return Err(exact_source_storage_error(format!(
                    "projection refresh for {file_id} has a layout attached to a non-blob tree entry"
                )));
            };
            let content = self
                .blobs
                .read(&kin_blobs::Hash256(*hash.as_bytes()))
                .map_err(|error| {
                    self.attribute_ingest_cas_gap(exact_source_storage_error(format!(
                        "projection refresh for {file_id} cannot load graph-owned blob {}: {error}",
                        hash
                    )))
                })?;
            projection.register_file(layout, content);
            loaded += 1;
        }

        info!(
            upserted = loaded,
            graph_backed = loaded,
            removed,
            skipped,
            "refreshed projection state for changed files"
        );
        Ok(())
    }

    /// Mark the graph as dirty (mutated since last save).
    /// Called after any graph mutation. The background persistence task
    /// will flush to disk when it sees this flag.
    pub fn mark_dirty(&self) {
        self.mutation_epoch.fetch_add(1, Ordering::SeqCst);
        self.dirty.store(true, Ordering::SeqCst);
        if let Ok(mut last) = self.last_mutation.lock() {
            *last = Instant::now();
        }
    }

    /// Mark the graph as clean (just saved). Records the save timestamp.
    pub fn mark_clean(&self) {
        let observed_epoch = self.mutation_epoch.load(Ordering::SeqCst);
        self.dirty.store(false, Ordering::SeqCst);
        // A detached backend batch, a later active delta, or a mutation epoch
        // that changed across the clear all mean this save did not acknowledge
        // the latest graph truth. Re-arm the persistence wakeup instead of
        // losing the concurrent mutation.
        if self.mutation_epoch.load(Ordering::SeqCst) != observed_epoch
            || self.graph.has_unpersisted_changes()
            || self.post_commit_finalization_pending.load(Ordering::SeqCst)
        {
            self.dirty.store(true, Ordering::SeqCst);
            return;
        }
        if let Ok(mut last) = self.last_save.lock() {
            *last = Instant::now();
        }
    }

    /// Check if the graph has unsaved mutations.
    pub fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::SeqCst)
    }

    /// Whether persisting the current in-memory graph on shutdown would overwrite
    /// a substantially larger on-disk snapshot with a drastically-collapsed one.
    ///
    /// This is the GRAPH-level anti-wipe guard (mirrors loop_runner's
    /// mass-deletion principle): if the live entity count has collapsed to less
    /// than a quarter of the last persisted count, the in-memory graph is most
    /// likely the victim of a transient wipe (e.g. an empty/bare checkout
    /// reconciled as all-deleted) rather than a real edit, so the shutdown flush
    /// must be skipped. It is deliberately independent of the vector index: a
    /// stale kvec self-heals on load and is not a reason to block the graph flush.
    ///
    /// The asymmetry favors skipping: a false positive is cheap (the larger
    /// snapshot reloads and re-reconciles against the filesystem next startup),
    /// while a false negative is expensive (a full re-index/re-embed from an
    /// emptied graph).
    pub fn shutdown_flush_would_wipe_graph(&self) -> bool {
        graph_collapse_is_wipe(
            self.graph.entity_count() as u64,
            self.persisted_entity_count.load(Ordering::SeqCst),
        )
    }

    /// Record that the on-disk snapshot now holds the current graph's entity
    /// count. Called after every successful save so the anti-wipe baseline
    /// tracks what is actually persisted.
    pub fn record_persisted_entity_count(&self) {
        self.persisted_entity_count
            .store(self.graph.entity_count() as u64, Ordering::SeqCst);
    }

    /// True when the most recent filesystem-sync tick refused a mass deletion
    /// (its removals would have wiped most of the graph-known files). Surfaced
    /// as a daemon-health signal.
    pub fn is_mass_deletion_blocked(&self) -> bool {
        self.mass_deletion_blocked.load(Ordering::Relaxed)
    }

    /// Record what one exact-tree publication cost.
    ///
    /// Microseconds rather than milliseconds because a publication on a small
    /// repository is well under a millisecond, and the reading that matters
    /// most is the cheap one: it is what tells the reconcile tick that holding
    /// off for an imminent commit would cost more than the publication it could
    /// save.
    pub(crate) fn record_authority_publication(&self, elapsed: Duration) {
        self.last_authority_publication_micros.store(
            u64::try_from(elapsed.as_micros())
                .unwrap_or(u64::MAX)
                .max(1),
            Ordering::Relaxed,
        );
    }

    /// What this daemon's last exact-tree publication cost, or `None` when it
    /// has not published one yet.
    pub(crate) fn last_authority_publication(&self) -> Option<Duration> {
        match self
            .last_authority_publication_micros
            .load(Ordering::Relaxed)
        {
            0 => None,
            micros => Some(Duration::from_micros(micros)),
        }
    }

    /// Duration since the last successful save.
    pub fn time_since_save(&self) -> Duration {
        self.last_save
            .lock()
            .map(|last| last.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// Duration since the last graph mutation (`mark_dirty`).
    pub fn time_since_mutation(&self) -> Duration {
        self.last_mutation
            .lock()
            .map(|last| last.elapsed())
            .unwrap_or(Duration::ZERO)
    }

    /// True while at least one daemon-side embed pass is in flight.
    pub fn embed_pass_active(&self) -> bool {
        self.active_embed_passes.load(Ordering::SeqCst) > 0
    }

    /// True when the background embedding worker should stand down.
    pub fn background_embed_paused(&self) -> bool {
        self.background_embed_paused.load(Ordering::SeqCst)
    }

    /// Pause background embedding. Explicit `kin embed` requests can still run.
    pub fn pause_background_embed(&self) {
        self.background_embed_paused.store(true, Ordering::SeqCst);
    }

    /// Resume background embedding after unbounded or fully completed embed work.
    pub fn resume_background_embed(&self) {
        self.background_embed_paused.store(false, Ordering::SeqCst);
    }

    /// True when the background embedding worker will still consume whatever is
    /// queued. Mirrors the three conditions under which the worker stands down:
    /// a storage-backend graph has no durable vector-sidecar contract so the
    /// worker never starts, a permanently failed worker has already exited, and
    /// a paused worker leaves the queue alone until an explicit embed resumes it.
    ///
    /// Callers that treat a queued backlog as live work must gate on this.
    /// A backlog nobody will drain is not work in progress, and counting it as
    /// such keeps a daemon alive that has nothing left to do.
    pub fn background_embed_worker_can_drain(&self) -> bool {
        self.can_persist_embed_progress_locally()
            && !self.embed_worker_failed.load(Ordering::Relaxed)
            && !self.background_embed_paused()
    }

    /// Mark a daemon-side embed pass as in flight for the lifetime of the
    /// returned guard. Counter-based so overlapping callers compose; the
    /// guard decrements on drop, including error returns and panic unwinds
    /// out of the embed handler.
    pub fn begin_embed_pass(&self) -> EmbedPassGuard<'_> {
        self.active_embed_passes.fetch_add(1, Ordering::SeqCst);
        EmbedPassGuard(self)
    }

    /// Record externally visible daemon activity.
    pub fn touch_activity(&self) {
        let elapsed_ms = self
            .started_at
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        self.last_activity_ms.store(elapsed_ms, Ordering::SeqCst);
    }

    /// Track the start of an API request.
    pub fn begin_request(&self) {
        self.active_requests.fetch_add(1, Ordering::SeqCst);
        self.touch_activity();
    }

    /// Track the end of an API request.
    pub fn end_request(&self) {
        self.touch_activity();
        let _ = self
            .active_requests
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                Some(current.saturating_sub(1))
            });
    }

    /// Number of API requests currently in flight.
    pub fn active_request_count(&self) -> u64 {
        self.active_requests.load(Ordering::SeqCst)
    }

    /// Duration since the last recorded external activity.
    pub fn idle_duration(&self) -> Duration {
        let now_ms = self
            .started_at
            .elapsed()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        let last_ms = self.last_activity_ms.load(Ordering::SeqCst);
        Duration::from_millis(now_ms.saturating_sub(last_ms))
    }

    /// The live idle window, or `None` when this daemon never idles out.
    pub fn idle_timeout(&self) -> Option<Duration> {
        Self::window_from_millis(self.idle_timeout_ms.load(Ordering::SeqCst))
    }

    fn window_from_millis(millis: u64) -> Option<Duration> {
        (millis > 0).then(|| Duration::from_millis(millis))
    }

    /// Install the startup idle window. Called once by the daemon entrypoint
    /// before the idle monitor starts.
    pub fn install_idle_timeout(&self, timeout: Option<Duration>) {
        let millis = timeout.map_or(0, |timeout| {
            timeout.as_millis().min(u128::from(u64::MAX)) as u64
        });
        self.idle_timeout_ms.store(millis, Ordering::SeqCst);
    }

    /// Grow the idle window to cover an attached client that needs longer than
    /// the window this daemon was started with, and report what happened.
    ///
    /// Only ever grows. A client stating what it needs must not be able to
    /// shorten the window another client is relying on, and must not be able to
    /// switch off idle shutdown for a daemon that was configured to have one.
    pub fn raise_idle_timeout(&self, at_least: Duration) -> IdleTimeoutRaise {
        loop {
            let current_ms = self.idle_timeout_ms.load(Ordering::SeqCst);
            let current = Self::window_from_millis(current_ms);
            let Some(raised) = resolve_idle_timeout_floor(current, at_least) else {
                return IdleTimeoutRaise {
                    effective: current,
                    raised_from: None,
                };
            };
            let raised_ms = raised.as_millis().min(u128::from(u64::MAX)) as u64;
            if self
                .idle_timeout_ms
                .compare_exchange(current_ms, raised_ms, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return IdleTimeoutRaise {
                    effective: Some(raised),
                    raised_from: current,
                };
            }
        }
    }

    /// Whether an agent/user session is currently active. The daemon's own
    /// reconcile-loop session is intentionally ignored.
    pub fn has_external_sessions(&self) -> bool {
        self.coordinator
            .list_sessions()
            .map(|sessions| {
                sessions
                    .iter()
                    .any(|session| session.vendor != "kin-daemon")
            })
            .unwrap_or(true)
    }

    /// Queue changed entities for background LSP enrichment (non-blocking).
    /// No-op if LSP enrichment is not available.
    pub fn queue_lsp_enrichment(&self, request: LspEnrichmentRequest) {
        if self.filesystem_reconcile_disabled() {
            return;
        }
        if let Some(ref tx) = self.lsp_enrichment_tx {
            if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) =
                tx.try_send(LspEnrichmentMessage::Incremental(request))
            {
                warn!("LSP enrichment channel full, incremental request dropped");
            }
        }
    }

    /// Queue a cold sweep that enriches ALL entities in the graph via LSP.
    ///
    /// No-op if LSP enrichment is not available. This used to claim it was
    /// "triggered after init/migrate/reconcile" and none of those triggered it:
    /// the only caller was `POST /lsp/sweep`, so on a freshly converted
    /// repository the enrichment worker sat blocked on a channel nothing fed and
    /// no cross-file reference edge was ever produced. The daemon now queues one
    /// at startup when servers are present and the graph holds files with no
    /// language-server evidence yet.
    pub fn queue_lsp_sweep(&self) -> bool {
        if self.filesystem_reconcile_disabled() {
            return false;
        }
        // One sweep at a time. The daemon queues one at startup and a caller may
        // queue another, and two sweeps over one graph is not merely wasteful:
        // a waiter that captured its baseline before the second was queued sees
        // the FIRST one finish, returns, and hands back a graph the second is
        // still mutating. That is what left `kin init` reporting a converged
        // repository while a sweep ran on underneath it.
        if self
            .lsp_sweep_running
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return false;
        }
        if let Some(ref tx) = self.lsp_enrichment_tx {
            if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) =
                tx.try_send(LspEnrichmentMessage::Sweep)
            {
                warn!("LSP enrichment channel full, sweep request dropped");
                return false;
            }
            return true;
        }
        false
    }

    /// Return the current reconciliation status as a human-readable string.
    pub fn reconciliation_status_str(&self) -> &'static str {
        match self.reconciliation_status.load(Ordering::Relaxed) {
            RECON_PROCESSING => "processing",
            RECON_PARKED => "parked-by-supervisor",
            _ => "idle",
        }
    }
}

/// RAII marker for an in-flight daemon-side embed pass. Decrements the pass
/// counter on drop so the background idle flush resumes even when the embed
/// handler exits early.
pub struct EmbedPassGuard<'a>(&'a DaemonState);

impl Drop for EmbedPassGuard<'_> {
    fn drop(&mut self) {
        self.0.active_embed_passes.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        ArtifactId, ChangeOrigin, Entity, EntityKind, EntityMetadata, FileLayout, FilePathId,
        FingerprintAlgorithm, Hash256, ImportSection, LanguageId, LocatedEntry, ParseCompleteness,
        RepoPath, ResolvedArtifact, ResolvedTree, SemanticFingerprint, TreeDelta, Visibility,
    };
    use kin_reconcile::ReconcileOutcome;
    use serde_json::json;

    #[test]
    fn directory_metadata_sync_is_portable() {
        let directory = tempfile::tempdir().unwrap();
        sync_directory_metadata(directory.path())
            .expect("directory metadata sync must not reject a valid host directory");
    }

    fn empty_repository_metadata(label: &str) -> kin_db::PersistedRepositoryAuthority {
        let storage = tempfile::tempdir().unwrap();
        let repository_id =
            RepositoryId::new(format!("{label}-{}", uuid::Uuid::new_v4().simple())).unwrap();
        let authority = RepositoryAuthorityManager::open(
            repository_id,
            Arc::new(LocalFileBackend::new(storage.path().to_path_buf())),
        )
        .unwrap();
        authority.read_authority().metadata().clone()
    }

    #[test]
    fn hosted_authority_materialization_accepts_only_a_valid_unborn_repository() {
        let mut metadata = empty_repository_metadata("unborn-default");
        metadata.ref_state.default_ref = Some(kin_model::RefName::branch(b"main").unwrap());
        assert!(
            select_repository_default_ref(&metadata).unwrap().is_none(),
            "an unborn default names no graph and materializes empty"
        );
    }

    #[test]
    fn hosted_authority_materialization_refuses_missing_or_dangling_default_ref() {
        let mut metadata = empty_repository_metadata("invalid-default");
        let repository_id = metadata.repository_id.clone();
        let main = kin_model::RefName::branch(b"main").unwrap();
        let head = SemanticChangeId::from_hash(Hash256::from_bytes([7; 32]));
        metadata.ref_state.refs.push(kin_model::RepositoryRef {
            repository_id,
            name: main.clone(),
            target: kin_model::RefTarget::change(head),
        });

        let missing = select_repository_default_ref(&metadata)
            .expect_err("refs without an explicit default must fail closed");
        assert!(missing.to_string().contains("no persisted default ref"));

        metadata.ref_state.default_ref = Some(kin_model::RefName::branch(b"absent").unwrap());
        let dangling = select_repository_default_ref(&metadata)
            .expect_err("a default name absent from the ref set must fail closed");
        assert!(dangling.to_string().contains("absent from persisted refs"));
    }

    #[test]
    fn hosted_authority_materialization_resolves_a_symbolic_chain_exactly() {
        let mut metadata = empty_repository_metadata("symbolic-default");
        let repository_id = metadata.repository_id.clone();
        let main = kin_model::RefName::branch(b"main").unwrap();
        let selected = kin_model::RefName::branch(b"selected").unwrap();
        let head = SemanticChangeId::from_hash(Hash256::from_bytes([9; 32]));
        metadata.ref_state.refs = vec![
            kin_model::RepositoryRef {
                repository_id: repository_id.clone(),
                name: main.clone(),
                target: kin_model::RefTarget::symbolic(selected.clone()),
            },
            kin_model::RepositoryRef {
                repository_id,
                name: selected,
                target: kin_model::RefTarget::change(head),
            },
        ];
        metadata.ref_state.default_ref = Some(main);

        let repository_ref = select_repository_default_ref(&metadata)
            .unwrap()
            .expect("the explicit default ref must be selected");
        assert_eq!(
            resolve_repository_target(&metadata, &repository_ref.target).unwrap(),
            head
        );
    }

    /// Both sides at the resolution layer. A client whose session outlasts the
    /// window this daemon was spawned with grows it; a client that already fits
    /// inside it changes nothing.
    #[test]
    fn an_idle_floor_grows_a_short_window_and_leaves_a_long_one_alone() {
        let secs = Duration::from_secs;
        // The exact case: a CLI-spawned daemon at 60s, an MCP session at 1800s.
        assert_eq!(
            resolve_idle_timeout_floor(Some(secs(60)), secs(1800)),
            Some(secs(1800))
        );
        // The same session attaching to a daemon that already outlasts it.
        assert_eq!(
            resolve_idle_timeout_floor(Some(secs(3600)), secs(1800)),
            None
        );
        assert_eq!(
            resolve_idle_timeout_floor(Some(secs(1800)), secs(1800)),
            None
        );
    }

    /// Growth only, in both directions it could go wrong: a client must not be
    /// able to shorten a window another client relies on, and must not be able
    /// to switch idle shutdown off for a daemon configured to have one.
    #[test]
    fn an_idle_floor_can_neither_shorten_a_window_nor_abolish_one() {
        let secs = Duration::from_secs;
        assert_eq!(
            resolve_idle_timeout_floor(Some(secs(1800)), secs(60)),
            None,
            "a shorter request must not shorten the window"
        );
        assert_eq!(
            resolve_idle_timeout_floor(Some(secs(60)), Duration::ZERO),
            None,
            "a request for 'never' is not a floor and must be refused"
        );
        assert_eq!(
            resolve_idle_timeout_floor(None, secs(1800)),
            None,
            "a daemon that never idles out already outlasts every finite request"
        );
    }

    /// An attached client cannot pin the graph in memory indefinitely by asking
    /// for an absurd window; the request is clamped and still expires.
    #[test]
    fn an_idle_floor_is_clamped_to_the_attached_maximum() {
        let max = Duration::from_secs(MAX_ATTACHED_IDLE_TIMEOUT_SECS);
        assert_eq!(
            resolve_idle_timeout_floor(Some(Duration::from_secs(60)), Duration::MAX),
            Some(max)
        );
        assert_eq!(resolve_idle_timeout_floor(Some(max), Duration::MAX), None);
    }

    /// A sub-second window is a real window, not "never idles out". Storing
    /// whole seconds rounded one into the sentinel, which turned "expire
    /// quickly" into "expire never" and left the monitor circling forever.
    #[test]
    fn a_sub_second_window_survives_the_round_trip_through_state() {
        assert_eq!(
            DaemonState::window_from_millis(200),
            Some(Duration::from_millis(200))
        );
        assert_eq!(DaemonState::window_from_millis(0), None);
    }

    #[cfg(feature = "embeddings")]
    fn tree_with_path(path: &str) -> ResolvedTree {
        ResolvedTree::from_artifacts([ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8(path).unwrap(),
            TreeEntry::blob(Hash256::from_bytes([7u8; 32]), false),
        )])
        .unwrap()
    }

    /// The retained authority match must skip re-derivation for the exact pair
    /// it derived, and for nothing else. An embed batch that changes neither the
    /// committed generation nor the live exact tree is the whole reason a long
    /// embed is not dominated by authority reopens; a batch that changes either
    /// must still pay for a full reopen, because the retained answer is no
    /// longer about the state being checkpointed.
    #[cfg(feature = "embeddings")]
    #[test]
    fn vector_checkpoint_authority_match_holds_only_for_the_derived_pair() {
        let tree = tree_with_path("src/lib.rs");
        let other_tree = tree_with_path("src/main.rs");
        let retained = VectorCheckpointAuthorityMatch::default();

        // Nothing derived yet: every pair reopens.
        assert!(!retained.holds(1, &tree));

        retained.record(1, tree.clone());
        assert!(retained.holds(1, &tree));

        // A generation bump invalidates: committed authority moved.
        assert!(!retained.holds(2, &tree));
        // A live-tree mutation invalidates: the checkpointed state moved.
        assert!(!retained.holds(1, &other_tree));

        // Re-deriving replaces rather than accumulates, so the superseded pair
        // never keeps answering for a state that has moved on.
        retained.record(2, other_tree.clone());
        assert!(retained.holds(2, &other_tree));
        assert!(!retained.holds(1, &tree));
    }

    /// An empty tree is a real repository state (a workspace with no admitted
    /// artifacts), not a "nothing derived yet" sentinel, so it must be told
    /// apart from the un-derived state above.
    #[cfg(feature = "embeddings")]
    #[test]
    fn vector_checkpoint_authority_match_distinguishes_empty_tree_from_no_record() {
        let retained = VectorCheckpointAuthorityMatch::default();
        let empty = ResolvedTree::default();

        assert!(!retained.holds(0, &empty));
        retained.record(0, empty.clone());
        assert!(retained.holds(0, &empty));
        assert!(!retained.holds(0, &tree_with_path("src/lib.rs")));
    }

    /// The two tests above prove the retained pair's algebra in isolation, and
    /// prove nothing about whether the flush consults it. Drive the real flush
    /// against a real workspace-authority store: the first call has nothing
    /// retained and must derive the answer by reopening authority, and the next
    /// call over an unchanged batch must answer from the retained pair without
    /// reopening at all. Reuse across unchanged batches is the entire mechanism,
    /// so a flush that quietly kept reopening would be indistinguishable from
    /// the unfixed path by any test of the type alone.
    #[cfg(feature = "embeddings")]
    #[test]
    fn flush_embed_progress_derives_the_authority_match_once_and_then_reuses_it() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        let reopens = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&reopens);
        state.set_vector_checkpoint_reopen_test_hook(Some(Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        })));

        let generation = state.snapshot_generation.load(Ordering::SeqCst);
        state
            .flush_embed_progress()
            .expect("a live tree matching committed authority must checkpoint");
        assert_eq!(
            reopens.load(Ordering::SeqCst),
            1,
            "the first flush has nothing retained, so it must reopen authority"
        );
        assert!(
            state
                .vector_checkpoint_authority_match
                .holds(generation, &state.graph.resolved_tree()),
            "the retained pair must cover the tree this flush actually checkpointed"
        );

        state
            .flush_embed_progress()
            .expect("an unchanged batch must still checkpoint");
        assert_eq!(
            reopens.load(Ordering::SeqCst),
            1,
            "an unchanged batch must answer from the retained pair, not a second reopen"
        );
    }

    /// The reopen is linear in store size and this path holds only
    /// `persist_lock`, while commit and reconcile exclude on the coordination
    /// gate, so the live graph can move while the reopen runs. A tree sampled
    /// before the reopen is therefore a statement about a repository state the
    /// checkpoint may no longer be writing. What the flush proves against
    /// authority, retains, and then serializes must all be the same tree, so a
    /// mutation landing inside that window has to be refused and has to leave
    /// nothing retained.
    #[cfg(feature = "embeddings")]
    #[test]
    fn flush_embed_progress_refuses_a_live_tree_that_moved_during_the_reopen() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        let generation = state.snapshot_generation.load(Ordering::SeqCst);
        let tree_before = state.graph.resolved_tree();

        let moving_graph = Arc::clone(&state.graph);
        state.set_vector_checkpoint_reopen_test_hook(Some(Arc::new(move || {
            moving_graph
                .apply_transaction_delta(&kin_model::TransactionDelta {
                    tree_deltas: vec![TreeDelta::Added {
                        artifact_id: ArtifactId::new(),
                        new: LocatedEntry::new(
                            RepoPath::from_utf8("src/arrived_during_reopen.rs").unwrap(),
                            TreeEntry::blob(Hash256::from_bytes([9u8; 32]), false),
                        ),
                    }],
                    ..Default::default()
                })
                .expect("the live graph must accept the concurrent mutation under test");
        })));

        let error = state
            .flush_embed_progress()
            .expect_err("a live tree that moved away from authority must be refused");
        assert!(
            error
                .to_string()
                .contains("live exact tree does not match workspace authority"),
            "expected the authority-mismatch refusal, got: {error}"
        );

        let tree_after = state.graph.resolved_tree();
        assert_ne!(
            tree_before, tree_after,
            "the seam must actually have moved the live tree"
        );
        assert!(
            !state
                .vector_checkpoint_authority_match
                .holds(generation, &tree_before),
            "a tree the checkpoint is no longer writing must not be retained as proved"
        );
        assert!(
            !state
                .vector_checkpoint_authority_match
                .holds(generation, &tree_after),
            "a refused flush must retain nothing"
        );
    }

    /// The whole lifecycle the coverage regression was found in, driven end to
    /// end: vectors are embedded, a change moves the live tree while the
    /// checkpoint is being proved, the checkpoint is refused, and the
    /// divergence then closes.
    ///
    /// The test above proves the refusal is correct and retains nothing. It
    /// proves nothing about what happens to the vectors afterwards, and that is
    /// where the work was going. `checkpoint_vector_index_for_graph` has one
    /// caller in this daemon, and the embed worker only reaches it after a
    /// batch embeds something, so a refusal on the last batch of a draining
    /// queue had nothing left to retry it: the vectors stayed in memory, the
    /// sidecar kept its older content, and the next open reported the shortfall
    /// as ordinary pending work. On the rc0545c brown arm that read as a store
    /// at 2112/2112 with zero pending, then 1770/2112 with 342 pending three
    /// minutes later.
    ///
    /// So the assertions here are about durability rather than about the
    /// refusal: the sidecar must be absent while the refusal stands, the
    /// refusal must be recorded with its cause, and the retry must land the
    /// vectors once the divergence closes, with the count intact on both sides.
    #[cfg(feature = "embeddings")]
    #[test]
    fn a_refused_vector_checkpoint_is_retried_and_its_vectors_survive() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        // Stage completed work the product's own counter can see: vectors keyed
        // to entities that are in graph truth, so `embedding_status().indexed`
        // counts them rather than a raw index length that means nothing to a
        // reader. Removing the sidecar afterwards is what makes "did this
        // checkpoint land" answerable by existence.
        const STAGED_VECTORS: usize = 3;
        let vector_path = state.layout.kindb_vector_index_path();
        let descriptor = kin_db::vector::IndexDescriptor {
            model_id: Some("fixture-embedder-v1".to_string()),
            graph_root: Some("fixture-root".to_string()),
        };
        let vectors = kin_db::VectorIndex::new(4).unwrap();
        vectors.set_descriptor(descriptor.clone());
        for slot in 0..STAGED_VECTORS {
            let entity = test_entity(&format!("embedded_{slot}"), "src/lib.rs");
            state.graph.upsert_entity(&entity).unwrap();
            let mut embedding = [0.0f32; 4];
            embedding[slot] = 1.0;
            vectors
                .upsert_retrievable(kin_db::RetrievalKey::Entity(entity.id), &embedding)
                .expect("the fixture index must accept a staged vector");
        }
        vectors.save(&vector_path).unwrap();
        assert!(matches!(
            state
                .graph
                .load_vector_index_compatible(&vector_path, &descriptor),
            kin_db::vector::VectorIndexLoad::Loaded(STAGED_VECTORS)
        ));
        std::fs::remove_file(&vector_path).unwrap();
        let staged = state.graph.embedding_status();
        assert_eq!(
            staged.indexed, STAGED_VECTORS,
            "the counter every surface reads must see the staged coverage before anything is \
             refused, or this test is about a number nobody renders"
        );
        assert!(
            state.deferred_vector_checkpoint().is_none(),
            "nothing is deferred before the first refusal"
        );

        // A change lands while the checkpoint is proving the tree, which is what
        // a commit in flight does to it.
        let arriving = ArtifactId::new();
        let arrived = LocatedEntry::new(
            RepoPath::from_utf8("src/arrived_during_reopen.rs").unwrap(),
            TreeEntry::blob(Hash256::from_bytes([9u8; 32]), false),
        );
        let moving_graph = Arc::clone(&state.graph);
        let moved = Arc::new(AtomicBool::new(false));
        let moved_seam = Arc::clone(&moved);
        let arrived_seam = arrived.clone();
        state.set_vector_checkpoint_reopen_test_hook(Some(Arc::new(move || {
            // Once only. A seam that moved the tree on every reopen would model
            // a repository nobody can ever checkpoint, not a commit that lands.
            if moved_seam.swap(true, Ordering::SeqCst) {
                return;
            }
            moving_graph
                .apply_transaction_delta(&kin_model::TransactionDelta {
                    tree_deltas: vec![TreeDelta::Added {
                        artifact_id: arriving,
                        new: arrived_seam.clone(),
                    }],
                    ..Default::default()
                })
                .expect("the live graph must accept the concurrent mutation under test");
        })));

        let error = state
            .flush_embed_progress()
            .expect_err("a live tree that moved away from authority must be refused");
        assert!(
            moved.load(Ordering::SeqCst),
            "the seam must actually have fired, or the refusal under test never happened"
        );
        assert!(
            !vector_path.exists(),
            "a refused checkpoint must write nothing, which is why the work needs retrying"
        );
        let deferred = state
            .deferred_vector_checkpoint()
            .expect("a refused checkpoint must be recorded, not logged once and abandoned");
        assert!(
            error.to_string().ends_with(&deferred),
            "the record must carry the refusal's own cause, so every surface names why; \
             recorded {deferred:?} against error {error}"
        );
        assert!(
            deferred.contains("live exact tree does not match workspace authority"),
            "expected the authority-mismatch refusal, got: {deferred}"
        );
        assert_eq!(
            state.graph.embedding_status().indexed,
            STAGED_VECTORS,
            "the refusal must not cost the vectors it declined to write"
        );

        // The divergence closes, the way it closes in a real store once the
        // commit that opened it has settled.
        state
            .graph
            .apply_transaction_delta(&kin_model::TransactionDelta {
                tree_deltas: vec![TreeDelta::Removed {
                    artifact_id: arriving,
                    old: arrived,
                }],
                ..Default::default()
            })
            .expect("the live graph must accept the settling transition");

        let pending = state
            .retry_deferred_vector_checkpoint()
            .expect("a standing refusal must give the retry something to do")
            .expect("a settled tree must checkpoint");
        assert!(
            vector_path.exists(),
            "the retry is the whole fix: the vectors must reach the sidecar (pending {pending})"
        );
        assert!(
            state.deferred_vector_checkpoint().is_none(),
            "a checkpoint that landed must retire the record it closed"
        );
        assert_eq!(
            state.graph.embedding_status().indexed,
            STAGED_VECTORS,
            "the staged vectors must still be indexed and counted after the whole lifecycle"
        );

        // And they are on disk rather than merely still in memory. Dropping the
        // live index and re-reading the sidecar through the exact call
        // `load_validated_vector_index` makes at open is what a restart does to
        // this count, so the assertion after it is about bytes that survived
        // rather than about a process that has not ended yet.
        state.graph.reset_vector_index();
        assert_eq!(
            state.graph.embedding_status().indexed,
            0,
            "the control: with the live index dropped the count must come from disk alone"
        );
        assert!(
            kin_db::SnapshotManager::load_vector_index_into_graph_if_valid(
                state.graph.as_ref(),
                &state.layout.kindb_snapshot_path(),
                None,
            )
            .expect("the checkpointed sidecar must be readable")
            .attached,
            "the checkpointed sidecar must install through the daemon's own open-time path"
        );
        assert_eq!(
            state.graph.embedding_status().indexed,
            STAGED_VECTORS,
            "a restart must read back every vector the retry checkpointed"
        );

        // And with nothing outstanding, the retry is a no-op rather than a
        // standing authority reopen on every tick of the worker that calls it.
        assert!(
            state.retry_deferred_vector_checkpoint().is_none(),
            "an unrefused daemon must not pay for a retry it does not need"
        );
    }

    #[test]
    fn concurrent_repo_graph_load_returns_the_cached_winner() {
        let winner = Arc::new(kin_db::InMemoryGraph::new());
        let winner_entity = test_entity("winner", "src/winner.rs");
        winner.upsert_entity(&winner_entity).unwrap();

        let losing_load = Arc::new(kin_db::InMemoryGraph::new());
        let losing_entity = test_entity("loser", "src/loser.rs");
        losing_load.upsert_entity(&losing_entity).unwrap();

        // Deterministically model two slow-path loads that both missed the
        // read cache: the first task has acquired the write lock and installed
        // its generation before the second task reaches the entry operation.
        let mut graphs = HashMap::new();
        graphs.insert("shared".to_string(), Arc::clone(&winner));
        let returned = DaemonState::cache_loaded_repo_graph(&mut graphs, "shared", losing_load);

        assert!(Arc::ptr_eq(&returned, &winner));
        assert!(returned.get_entity(&winner_entity.id).unwrap().is_some());
        assert!(returned.get_entity(&losing_entity.id).unwrap().is_none());
    }

    struct CleanupFailOnceBackend {
        inner: kin_db::LocalFileBackend,
        fail_cleanup: AtomicBool,
        delta_block: Option<DeltaSaveBlock>,
        recovery_loads: Option<Arc<AtomicU64>>,
    }

    struct DeltaSaveBlock {
        reached_backend: Arc<std::sync::Barrier>,
        resume_backend: Arc<std::sync::Barrier>,
        block_once: AtomicBool,
    }

    impl CleanupFailOnceBackend {
        fn new(path: &std::path::Path, fail_cleanup: bool) -> Self {
            Self {
                inner: kin_db::LocalFileBackend::new(path),
                fail_cleanup: AtomicBool::new(fail_cleanup),
                delta_block: None,
                recovery_loads: None,
            }
        }

        fn blocking_delta(
            path: &std::path::Path,
            reached_backend: Arc<std::sync::Barrier>,
            resume_backend: Arc<std::sync::Barrier>,
        ) -> Self {
            Self {
                inner: kin_db::LocalFileBackend::new(path),
                fail_cleanup: AtomicBool::new(false),
                delta_block: Some(DeltaSaveBlock {
                    reached_backend,
                    resume_backend,
                    block_once: AtomicBool::new(true),
                }),
                recovery_loads: None,
            }
        }

        fn counting_load(path: &std::path::Path, recovery_loads: Arc<AtomicU64>) -> Self {
            Self {
                inner: kin_db::LocalFileBackend::new(path),
                fail_cleanup: AtomicBool::new(false),
                delta_block: None,
                recovery_loads: Some(recovery_loads),
            }
        }
    }

    impl kin_db::StorageBackend for CleanupFailOnceBackend {
        fn supports_incremental_deltas(&self) -> bool {
            true
        }

        fn load_snapshot(
            &self,
            repo_id: &str,
        ) -> std::result::Result<Option<(Vec<u8>, kin_db::Generation)>, kin_db::KinDbError>
        {
            self.inner.load_snapshot(repo_id)
        }

        fn load_snapshot_authority(
            &self,
            repo_id: &str,
        ) -> std::result::Result<Option<kin_db::SnapshotAuthority>, kin_db::KinDbError> {
            self.inner.load_snapshot_authority(repo_id)
        }

        fn load_recovery_state(
            &self,
            repo_id: &str,
        ) -> std::result::Result<kin_db::SnapshotRecoveryState, kin_db::KinDbError> {
            if let Some(loads) = &self.recovery_loads {
                loads.fetch_add(1, Ordering::SeqCst);
            }
            self.inner.load_recovery_state(repo_id)
        }

        fn save_snapshot(
            &self,
            repo_id: &str,
            data: &[u8],
            expected_gen: kin_db::Generation,
        ) -> std::result::Result<kin_db::Generation, kin_db::KinDbError> {
            self.inner.save_snapshot(repo_id, data, expected_gen)
        }

        fn save_delta(
            &self,
            repo_id: &str,
            delta_data: &[u8],
            base_gen: kin_db::Generation,
        ) -> std::result::Result<kin_db::Generation, kin_db::KinDbError> {
            if let Some(block) = &self.delta_block {
                if block.block_once.swap(false, Ordering::SeqCst) {
                    block.reached_backend.wait();
                    block.resume_backend.wait();
                }
            }
            self.inner.save_delta(repo_id, delta_data, base_gen)
        }

        fn load_deltas_since(
            &self,
            repo_id: &str,
            since_gen: kin_db::Generation,
        ) -> std::result::Result<Vec<(Vec<u8>, kin_db::Generation)>, kin_db::KinDbError> {
            self.inner.load_deltas_since(repo_id, since_gen)
        }

        fn clear_deltas(&self, repo_id: &str) -> std::result::Result<(), kin_db::KinDbError> {
            if self.fail_cleanup.swap(false, Ordering::SeqCst) {
                return Err(kin_db::KinDbError::StorageError(
                    "injected delta cleanup failure".to_string(),
                ));
            }
            self.inner.clear_deltas(repo_id)
        }

        fn save_overlay(
            &self,
            repo_id: &str,
            session_id: &str,
            data: &[u8],
        ) -> std::result::Result<(), kin_db::KinDbError> {
            self.inner.save_overlay(repo_id, session_id, data)
        }

        fn load_overlay(
            &self,
            repo_id: &str,
            session_id: &str,
        ) -> std::result::Result<Option<Vec<u8>>, kin_db::KinDbError> {
            self.inner.load_overlay(repo_id, session_id)
        }

        fn delete_overlay(
            &self,
            repo_id: &str,
            session_id: &str,
        ) -> std::result::Result<(), kin_db::KinDbError> {
            self.inner.delete_overlay(repo_id, session_id)
        }

        fn list_repos(&self) -> std::result::Result<Vec<String>, kin_db::KinDbError> {
            self.inner.list_repos()
        }
    }

    fn simple_layout(file_id: &FilePathId) -> FileLayout {
        FileLayout {
            file_id: file_id.clone(),
            parse_completeness: ParseCompleteness::Full,
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![],
        }
    }

    fn exact_source_change(path: &str, entry: TreeEntry) -> kin_model::SemanticChange {
        let mut change = kin_model::SemanticChange {
            id: kin_model::SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: vec![],
            author: kin_model::AuthorId::new("exact-source-preflight-test"),
            message: "exact source preflight fixture".to_string(),
            timestamp: kin_model::Timestamp::now(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            tree_deltas: vec![TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(RepoPath::from_utf8(path).unwrap(), entry),
            }],
            admission_policy_delta: None,
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            external_reference_deltas: Vec::new(),
        };
        change.id = kin_core::compute_semantic_change_id(&change).unwrap();
        change
    }

    fn local_object_path(layout: &KinLayout, hash: Hash256) -> std::path::PathBuf {
        let encoded = hash.to_string();
        layout
            .ingest_cas_dir()
            .join(&encoded[..2])
            .join(&encoded[2..])
    }

    fn test_state(layout: KinLayout, working_dir: &std::path::Path) -> DaemonState {
        let canonical_working_dir = working_dir
            .canonicalize()
            .expect("daemon fixture working directory must canonicalize");
        assert_eq!(layout.working_dir(), canonical_working_dir.as_path());
        DaemonState::open(layout)
            .expect("daemon test fixtures must open through repository-v6 workspace authority")
    }

    // ── The warming signal must be exact ──────────────────────────────────
    //
    // "Busy warming" is what lets a client tell a live daemon from a dead one.
    // A signal that leaks true after a warm-up ends would make every later
    // command think the daemon is still busy; one that fails to rise makes a
    // warming daemon indistinguishable from an idle one.

    #[test]
    fn warm_guard_raises_the_signal_and_clears_it_on_drop() {
        let flag = AtomicBool::new(false);
        assert!(!flag.load(Ordering::Relaxed));
        {
            let _guard = SpineWarmGuard::arm(&flag);
            assert!(flag.load(Ordering::Relaxed), "the warm-up must be visible");
        }
        assert!(
            !flag.load(Ordering::Relaxed),
            "the signal must not outlive the warm-up"
        );
    }

    #[test]
    fn warm_guard_clears_the_signal_on_unwind() {
        // A sibling load that panics must not leave the daemon permanently
        // claiming to be warming.
        let flag = std::sync::Arc::new(AtomicBool::new(false));
        let panicking = std::sync::Arc::clone(&flag);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = SpineWarmGuard::arm(&panicking);
            panic!("sibling authority loader panicked");
        }));
        assert!(outcome.is_err(), "the fixture must actually panic");
        assert!(
            !flag.load(Ordering::Relaxed),
            "an unwinding warm-up must still clear its signal"
        );
    }

    fn test_entity(name: &str, file_path: &str) -> Entity {
        Entity {
            id: kin_model::EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file_path)),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: kin_model::EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn entity_changed_serializes_session_attribution() {
        // An attributed change carries the originating session on the SSE wire,
        // so Mission Control can render "<session> -> entity <id>".
        let event = DaemonEvent::EntityChanged {
            entity_id: kin_model::EntityId::new(),
            change_type: ChangeType::Modified,
            file_path: Some("crates/kin-daemon/src/api.rs".to_string()),
            session_id: Some("mission-ctl-7".to_string()),
        };
        let v = serde_json::to_value(&event).unwrap();
        assert_eq!(v["type"], json!("EntityChanged"));
        assert_eq!(v["session_id"], json!("mission-ctl-7"));
    }

    #[test]
    fn coordination_event_log_is_durable_and_sequence_resumes() {
        let dir = tempfile::tempdir().unwrap();
        let layout = KinLayout::new(dir.path().join(".kin"));
        std::fs::create_dir_all(layout.root()).unwrap();
        let log = CoordinationEventLog::open(&layout, "test-repo").expect("open coordination log");
        let first = log
            .append(CoordinationEventDraft {
                event: "intent_registration",
                outcome: "registered".to_string(),
                session_id: Some("session-1".to_string()),
                intent_id: Some("intent-1".to_string()),
                intent_ids: vec!["intent-1".to_string()],
                transaction_id: None,
                scopes: vec!["entity:e1".to_string()],
                enforcement_mode: "warn".to_string(),
                blocking_intent_ids: vec![],
            })
            .unwrap();
        assert_eq!(first.sequence, 1);
        assert_eq!(first.schema, "kin.coordination-event.v1");

        let reopened =
            CoordinationEventLog::open(&layout, "test-repo").expect("reopen coordination log");
        let second = reopened
            .append(CoordinationEventDraft {
                event: "transaction_outcome",
                outcome: "committed".to_string(),
                session_id: Some("session-1".to_string()),
                intent_id: None,
                intent_ids: Vec::new(),
                transaction_id: Some("tx-1".to_string()),
                scopes: vec!["artifact:src/lib.rs".to_string()],
                enforcement_mode: "enforce".to_string(),
                blocking_intent_ids: vec![],
            })
            .unwrap();
        assert_eq!(second.sequence, 2);

        let lines = std::fs::read_to_string(reopened.path()).unwrap();
        let records: Vec<CoordinationEventEnvelope> = lines
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].repo_id, "test-repo");
        assert_eq!(records[1].transaction_id.as_deref(), Some("tx-1"));
        assert!(!records[1].kin_commit.is_empty());
    }

    #[test]
    fn coordination_event_log_repairs_partial_tail_and_marks_stream_ineligible() {
        let dir = tempfile::tempdir().unwrap();
        let layout = KinLayout::new(dir.path().join(".kin"));
        let log = CoordinationEventLog::open(&layout, "test-repo").unwrap();
        log.append(CoordinationEventDraft {
            event: "intent_registration",
            outcome: "registered".to_string(),
            session_id: Some("session-1".to_string()),
            intent_id: Some("intent-1".to_string()),
            intent_ids: vec!["intent-1".to_string()],
            transaction_id: None,
            scopes: vec!["entity:e1".to_string()],
            enforcement_mode: "warn".to_string(),
            blocking_intent_ids: Vec::new(),
        })
        .unwrap();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(log.path())
            .unwrap();
        file.write_all(b"{\"schema\":\"partial").unwrap();
        file.sync_data().unwrap();
        drop(file);

        let reopened = CoordinationEventLog::open(&layout, "test-repo").unwrap();
        assert_eq!(reopened.persisted_failure_count(), 1);
        let next = reopened
            .append(CoordinationEventDraft {
                event: "transaction_outcome",
                outcome: "committed".to_string(),
                session_id: Some("session-1".to_string()),
                intent_id: None,
                intent_ids: Vec::new(),
                transaction_id: Some("tx-1".to_string()),
                scopes: vec!["entity:e1".to_string()],
                enforcement_mode: "warn".to_string(),
                blocking_intent_ids: Vec::new(),
            })
            .unwrap();
        assert_eq!(next.sequence, 2);
        let records = std::fs::read_to_string(reopened.path()).unwrap();
        assert_eq!(records.lines().count(), 2);
        assert!(records
            .lines()
            .all(|line| serde_json::from_str::<CoordinationEventEnvelope>(line).is_ok()));
    }

    #[test]
    fn coordination_event_log_marks_unresolved_reservation_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let layout = KinLayout::new(dir.path().join(".kin"));
        let log = CoordinationEventLog::open(&layout, "test-repo").unwrap();
        log.append(CoordinationEventDraft {
            event: "intent_release",
            outcome: "pending:released".to_string(),
            session_id: Some("session-1".to_string()),
            intent_id: Some("intent-1".to_string()),
            intent_ids: vec!["intent-1".to_string()],
            transaction_id: None,
            scopes: vec!["entity:e1".to_string()],
            enforcement_mode: "enforce".to_string(),
            blocking_intent_ids: Vec::new(),
        })
        .unwrap();
        drop(log);

        let reopened = CoordinationEventLog::open(&layout, "test-repo").unwrap();
        assert_eq!(reopened.persisted_failure_count(), 1);
    }

    #[test]
    fn coordination_event_log_rejects_duplicate_sequences() {
        let dir = tempfile::tempdir().unwrap();
        let layout = KinLayout::new(dir.path().join(".kin"));
        let log = CoordinationEventLog::open(&layout, "test-repo").unwrap();
        log.append(CoordinationEventDraft {
            event: "transaction_outcome",
            outcome: "committed".to_string(),
            session_id: Some("session-1".to_string()),
            intent_id: None,
            intent_ids: Vec::new(),
            transaction_id: Some("tx-1".to_string()),
            scopes: vec!["entity:e1".to_string()],
            enforcement_mode: "enforce".to_string(),
            blocking_intent_ids: Vec::new(),
        })
        .unwrap();
        let existing = std::fs::read(log.path()).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(log.path())
            .unwrap();
        file.write_all(&existing).unwrap();
        file.sync_data().unwrap();
        drop(file);
        drop(log);

        let error = CoordinationEventLog::open(&layout, "test-repo")
            .err()
            .expect("duplicate sequence must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn entity_changed_anonymous_session_is_null() {
        // FS-reconcile changes have no owning agent: session_id renders null, which
        // Mission Control reads as "unattributed" (never a fabricated guess).
        let event = DaemonEvent::EntityChanged {
            entity_id: kin_model::EntityId::new(),
            change_type: ChangeType::Created,
            file_path: Some("src/lib.rs".to_string()),
            session_id: None,
        };
        let v = serde_json::to_value(&event).unwrap();
        assert_eq!(v["session_id"], serde_json::Value::Null);
    }

    #[test]
    fn entity_changed_legacy_payload_without_session_defaults_to_none() {
        // Backward compatibility: a pre-attribution payload (no session_id field)
        // must still deserialize, defaulting session_id to None. This is the
        // `#[serde(default)]` additive contract the change relies on.
        let mut payload = serde_json::to_value(DaemonEvent::EntityChanged {
            entity_id: kin_model::EntityId::new(),
            change_type: ChangeType::Modified,
            file_path: Some("api.rs".to_string()),
            session_id: Some("dropme".to_string()),
        })
        .unwrap();
        payload.as_object_mut().unwrap().remove("session_id");
        let event: DaemonEvent = serde_json::from_value(payload).unwrap();
        match event {
            DaemonEvent::EntityChanged { session_id, .. } => assert!(session_id.is_none()),
            other => panic!("expected EntityChanged, got {other:?}"),
        }
    }

    #[test]
    fn emit_event_delivers_session_attribution_to_subscriber() {
        // The real /events emit path: emit_event -> broadcast -> SSE subscriber.
        // An attributed event reaches a subscriber with its session intact.
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());
        let mut rx = state.event_tx.subscribe();
        state.emit_event(DaemonEvent::EntityChanged {
            entity_id: kin_model::EntityId::new(),
            change_type: ChangeType::Modified,
            file_path: Some("crates/kin-daemon/src/api.rs".to_string()),
            session_id: Some("mission-ctl-7".to_string()),
        });
        match rx.try_recv().expect("event delivered to SSE subscriber") {
            DaemonEvent::EntityChanged { session_id, .. } => {
                assert_eq!(session_id.as_deref(), Some("mission-ctl-7"));
            }
            other => panic!("expected EntityChanged, got {other:?}"),
        }
    }

    #[test]
    fn embed_pass_guard_tracks_in_flight_passes() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());
        assert!(!state.embed_pass_active());

        let outer = state.begin_embed_pass();
        let inner = state.begin_embed_pass();
        assert!(state.embed_pass_active());

        drop(inner);
        assert!(
            state.embed_pass_active(),
            "outer pass still in flight after inner guard drops"
        );

        drop(outer);
        assert!(!state.embed_pass_active());
    }

    #[test]
    fn background_embed_pause_latch_round_trips() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());
        assert!(!state.background_embed_paused());

        state.pause_background_embed();
        assert!(state.background_embed_paused());

        state.resume_background_embed();
        assert!(!state.background_embed_paused());
    }

    #[test]
    fn mark_dirty_advances_the_mutation_clock() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());
        let seeded = *state
            .last_mutation
            .lock()
            .expect("a fresh daemon state has an unpoisoned mutation clock");
        let epoch_before = state.mutation_epoch.load(Ordering::SeqCst);

        std::thread::sleep(Duration::from_millis(25));
        let before = state.time_since_mutation();
        assert!(
            before >= Duration::from_millis(20),
            "the mutation clock must count from construction until the first mark_dirty, got {before:?}"
        );

        let t0 = Instant::now();
        state.mark_dirty();
        let t1 = Instant::now();

        let advanced = *state
            .last_mutation
            .lock()
            .expect("a fresh daemon state has an unpoisoned mutation clock");
        assert!(
            advanced > seeded,
            "mark_dirty must advance the mutation clock: seeded={seeded:?} advanced={advanced:?}"
        );
        assert!(
            advanced >= t0 && advanced <= t1,
            "mark_dirty must restart the quiescence window from the moment of the call, not from an older instant: the call spanned {:?}",
            t1 - t0
        );
        assert_eq!(
            state.mutation_epoch.load(Ordering::SeqCst),
            epoch_before + 1,
            "mark_dirty must record exactly one mutation"
        );

        let since = state.time_since_mutation();
        let stamp_age = advanced.elapsed();
        assert!(
            since <= stamp_age,
            "time_since_mutation must be measured from the advanced stamp, not an earlier clock: since={since:?} stamp_age={stamp_age:?}"
        );
    }

    #[test]
    fn persist_projection_truth_stores_layout_and_hash() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());
        let mut reconciler = Reconciler::new(repo_dir.path().to_path_buf());
        let file_id = FilePathId::new("src/lib.rs");
        let content = b"fn persisted() {}\n".to_vec();
        let content_hash = Hash256::from_bytes(kin_blobs::digest_bytes(&content));
        state.blobs.write(&content).unwrap();
        state
            .graph
            .apply_transaction_delta(&kin_model::TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: ArtifactId::new(),
                    new: LocatedEntry::new(
                        RepoPath::from_utf8(&file_id.0).unwrap(),
                        TreeEntry::blob(content_hash, false),
                    ),
                }],
                ..Default::default()
            })
            .unwrap();

        reconciler
            .projection_mut()
            .register_file(simple_layout(&file_id), content.clone());

        state
            .persist_projection_truth_from_reconcile(
                &reconciler,
                &ReconcileOutcome::Updated {
                    file_id: file_id.clone(),
                    added: vec![],
                    modified: vec![],
                    removed: vec![],
                    collision_warnings: vec![],
                },
            )
            .unwrap();

        let persisted_layout = state.graph.get_file_layout(&file_id).unwrap().unwrap();
        assert_eq!(persisted_layout.file_id, file_id);
        assert_eq!(
            state.graph.get_tree_entry(&file_id).unwrap(),
            Some(TreeEntry::blob(content_hash, false))
        );
    }

    #[test]
    fn persist_projection_truth_rejects_wrong_bytes_before_publishing_layout() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());
        let mut reconciler = Reconciler::new(repo_dir.path().to_path_buf());
        let file_id = FilePathId::new("src/lib.rs");
        let admitted = b"fn admitted() {}\n".to_vec();
        let stale = b"fn stale() {}\n".to_vec();
        let admitted_hash = Hash256::from_bytes(kin_blobs::digest_bytes(&admitted));
        state
            .graph
            .apply_transaction_delta(&kin_model::TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: ArtifactId::new(),
                    new: LocatedEntry::new(
                        RepoPath::from_utf8(&file_id.0).unwrap(),
                        TreeEntry::blob(admitted_hash, false),
                    ),
                }],
                ..Default::default()
            })
            .unwrap();
        reconciler
            .projection_mut()
            .register_file(simple_layout(&file_id), stale);

        let error = state
            .persist_projection_truth_from_reconcile(
                &reconciler,
                &ReconcileOutcome::Updated {
                    file_id: file_id.clone(),
                    added: vec![],
                    modified: vec![],
                    removed: vec![],
                    collision_warnings: vec![],
                },
            )
            .expect_err("wrong projection bytes must fail before publishing a layout");

        assert!(error.to_string().contains("do not match graph-owned tree"));
        assert!(
            state.graph.get_file_layout(&file_id).unwrap().is_none(),
            "a failed content precondition must leave no query-facing layout"
        );
    }

    #[test]
    fn spine_capture_retries_after_primary_mutates_between_snapshot_and_validation() {
        use kin_model::{GraphNodeId, Relation, RelationId, RelationKind, RelationOrigin};

        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = Arc::new(test_state(init.layout, repo_dir.path()));
        let original = test_entity("original", "src/original.rs");
        state.graph.upsert_entity(&original).unwrap();
        let old_root = hex::encode(state.graph.compute_root_hash());

        let captured = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        let worker_state = Arc::clone(&state);
        let worker_graph = Arc::clone(&state.graph);
        let worker_captured = Arc::clone(&captured);
        let worker_resume = Arc::clone(&resume);
        let worker = std::thread::spawn(move || {
            worker_state.capture_spine_repo_with_hook("test-repo", worker_graph, move |attempt| {
                if attempt == 0 {
                    worker_captured.wait();
                    worker_resume.wait();
                }
            })
        });

        captured.wait();
        let raced = test_entity("raced", "src/raced.rs");
        let raced_relation = Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(original.id),
            dst: GraphNodeId::Entity(raced.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        let mutation = state.begin_graph_authority_mutation();
        state.graph.upsert_entity(&raced).unwrap();
        state.graph.upsert_relation(&raced_relation).unwrap();
        drop(mutation);
        resume.wait();

        let capture = worker
            .join()
            .unwrap()
            .expect("capture retries onto stable primary authority");
        let current_root = hex::encode(state.graph.compute_root_hash());
        assert_ne!(old_root, current_root);
        assert_eq!(capture.root_hash, current_root);
        assert!(capture
            .entries
            .iter()
            .any(|entry| entry.entity_id == raced.id));
        assert!(capture
            .relations
            .iter()
            .any(|relation| relation.id == raced_relation.id));
        assert_eq!(capture.entries.len(), capture.entities.len());
    }

    #[test]
    #[serial_test::serial]
    fn spine_initialization_retries_after_busy_primary_authority() {
        let registry_dir = tempfile::tempdir().unwrap();
        let registry_path = registry_dir.path().join("registry.toml");
        kin_core::registry::KinRegistry { repos: Vec::new() }
            .save_to(&registry_path)
            .unwrap();
        let _spine_env = kin_core::test_env::EnvVarGuard::set("KIN_REGISTRY_PATH", &registry_path)
            .without("KIN_DISABLE_SPINE");

        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());
        let primary_repo_id = state.cached_repo_id.clone();
        let entity = test_entity("stable_after_writer", "src/lib.rs");
        state.graph.upsert_entity(&entity).unwrap();

        let writer = state.begin_graph_authority_mutation();
        let deferred = state.ensure_spine().is_none();
        let once_lock_unpublished = state.spine.get().is_none();
        drop(writer);
        let expected_root = hex::encode(state.graph.compute_root_hash());
        let (retried, registered_root, registered_entity) = match state.ensure_spine() {
            Some(spine) => (
                true,
                spine.root_hash(&primary_repo_id),
                spine.lookup_by_id(&primary_repo_id, &entity.id).is_some(),
            ),
            None => (false, None, false),
        };

        assert!(deferred, "an active writer must defer spine initialization");
        assert!(
            once_lock_unpublished,
            "a failed primary capture must not permanently publish OnceLock"
        );
        assert!(retried, "the next request must retry initialization");
        assert_eq!(registered_root.as_deref(), Some(expected_root.as_str()));
        assert!(registered_entity);
    }

    #[test]
    #[serial_test::serial]
    fn concurrent_spine_callers_share_one_truthful_initialization() {
        use std::sync::{mpsc, Condvar};

        let registry_dir = tempfile::tempdir().unwrap();
        let registry_path = registry_dir.path().join("registry.toml");
        kin_core::registry::KinRegistry { repos: Vec::new() }
            .save_to(&registry_path)
            .unwrap();
        let _spine_env = kin_core::test_env::EnvVarGuard::set("KIN_REGISTRY_PATH", &registry_path)
            .without("KIN_DISABLE_SPINE");

        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = Arc::new(test_state(init.layout, repo_dir.path()));
        let hook_calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (entered_tx, entered_rx) = mpsc::channel();
        let hook_calls_for_hook = Arc::clone(&hook_calls);
        let release_for_hook = Arc::clone(&release);
        state.set_spine_initialization_test_hook(Some(Arc::new(move || {
            hook_calls_for_hook.fetch_add(1, Ordering::SeqCst);
            let _ = entered_tx.send(());
            let (released, wake) = &*release_for_hook;
            let released = released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = wake
                .wait_timeout_while(released, Duration::from_secs(120), |released| !*released)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        })));

        let first_state = Arc::clone(&state);
        let first = std::thread::spawn(move || first_state.ensure_spine().is_some());
        entered_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("first initializer must enter the blocking seam");
        assert!(
            state.spine_warming(),
            "the daemon must report warming for the blocked initialization"
        );

        let second_state = Arc::clone(&state);
        let second = std::thread::spawn(move || second_state.ensure_spine().is_some());
        std::thread::sleep(Duration::from_millis(250));
        let calls_while_blocked = hook_calls.load(Ordering::SeqCst);

        let (released, wake) = &*release;
        *released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        wake.notify_all();
        assert!(first.join().unwrap(), "first caller must publish the spine");
        assert!(
            second.join().unwrap(),
            "second caller must reuse the published spine"
        );

        assert_eq!(
            calls_while_blocked, 1,
            "OnceLock publication alone must not allow duplicate O(graph) initializers"
        );
        assert_eq!(hook_calls.load(Ordering::SeqCst), 1);
        assert!(
            !state.spine_warming(),
            "warming must clear only after the sole initializer exits"
        );
    }

    #[test]
    #[serial_test::serial]
    fn spine_initialization_revalidates_at_the_publication_edge() {
        let registry_dir = tempfile::tempdir().unwrap();
        let registry_path = registry_dir.path().join("registry.toml");
        kin_core::registry::KinRegistry { repos: Vec::new() }
            .save_to(&registry_path)
            .unwrap();
        let _spine_env = kin_core::test_env::EnvVarGuard::set("KIN_REGISTRY_PATH", &registry_path)
            .without("KIN_DISABLE_SPINE");

        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = Arc::new(test_state(init.layout, repo_dir.path()));
        let primary_repo_id = state.cached_repo_id.clone();
        let original = test_entity("before_publication", "src/original.rs");
        state.graph.upsert_entity(&original).unwrap();

        let prepared = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        let worker_state = Arc::clone(&state);
        let worker_prepared = Arc::clone(&prepared);
        let worker_resume = Arc::clone(&resume);
        let worker = std::thread::spawn(move || {
            worker_state.initialize_spine_lazy_with_publication_hook(|| {
                worker_prepared.wait();
                worker_resume.wait();
            });
        });

        // Advance graph authority after the prepared backend's ordinary final
        // validation but before it can cross the OnceLock visibility edge.
        prepared.wait();
        let raced = test_entity("at_publication", "src/raced.rs");
        let mutation = state.begin_graph_authority_mutation();
        state.graph.upsert_entity(&raced).unwrap();
        drop(mutation);
        resume.wait();
        worker.join().unwrap();

        let stale_backend_unpublished = state.spine.get().is_none();
        let expected_root = hex::encode(state.graph.compute_root_hash());
        let (retried, registered_root, raced_entity) = match state.ensure_spine() {
            Some(spine) => (
                true,
                spine.root_hash(&primary_repo_id),
                spine.lookup_by_id(&primary_repo_id, &raced.id).is_some(),
            ),
            None => (false, None, false),
        };

        assert!(
            stale_backend_unpublished,
            "a graph advance before OnceLock publication must discard the prepared backend"
        );
        assert!(
            retried,
            "the next request must rebuild from current authority"
        );
        assert_eq!(registered_root.as_deref(), Some(expected_root.as_str()));
        assert!(
            raced_entity,
            "the rebuilt backend must include raced authority"
        );
    }

    // ── Cross-repo authority must follow graph truth for a daemon's whole life ──
    //
    // Registration happens once behind a OnceLock, so a watermark that is not
    // re-resolved after a mutation leaves every later `find_references` reading
    // its own repository as stale authority until the daemon is restarted.

    #[test]
    #[serial_test::serial]
    fn spine_registration_follows_graph_authority_after_a_mutation() {
        let registry_dir = tempfile::tempdir().unwrap();
        let registry_path = registry_dir.path().join("registry.toml");
        kin_core::registry::KinRegistry { repos: Vec::new() }
            .save_to(&registry_path)
            .unwrap();
        let _spine_env = kin_core::test_env::EnvVarGuard::set("KIN_REGISTRY_PATH", &registry_path)
            .without("KIN_DISABLE_SPINE");

        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = Arc::new(test_state(init.layout, repo_dir.path()));
        let primary_repo_id = state.cached_repo_id.clone();

        let before = test_entity("before_mutation", "src/before.rs");
        state.graph.upsert_entity(&before).unwrap();
        let root_at_registration = hex::encode(state.graph.compute_root_hash());
        let registered_at_startup = state
            .ensure_spine()
            .expect("the fixture must publish a spine")
            .root_hash(&primary_repo_id);
        assert_eq!(
            registered_at_startup.as_deref(),
            Some(root_at_registration.as_str()),
            "the first registration must record the live graph root"
        );

        let after = test_entity("after_mutation", "src/after.rs");
        let mutation = state.begin_graph_authority_mutation();
        state.graph.upsert_entity(&after).unwrap();
        drop(mutation);
        let live_root = hex::encode(state.graph.compute_root_hash());
        assert_ne!(
            live_root, root_at_registration,
            "the fixture mutation must actually move the graph root"
        );

        let spine = state
            .ensure_spine()
            .expect("a mutation must not cost the daemon its spine");
        assert_eq!(
            spine.root_hash(&primary_repo_id).as_deref(),
            Some(live_root.as_str()),
            "registered cross-repo authority must follow the mutated graph root"
        );
        assert!(
            spine.lookup_by_id(&primary_repo_id, &after.id).is_some(),
            "the re-registered watermark must describe the entity set it was captured with"
        );

        let response = spine.cross_repo_xref_response(&primary_repo_id, &after.id);
        assert!(
            response.authority_root_matches(&primary_repo_id, &live_root),
            "find_references must not read its own repository as stale after a mutation"
        );
        assert!(
            response.authority_complete_for(&primary_repo_id, &after.id),
            "a single-repo daemon must still certify its own absence after a mutation"
        );
    }

    #[test]
    #[serial_test::serial]
    fn spine_init_materializes_cross_repo_edges() {
        use kin_db::InMemoryGraph;
        use kin_model::{
            GraphNodeId, Relation, RelationEvidence, RelationId, RelationKind, RelationOrigin,
        };

        // A sibling repo whose persisted graph exposes the entity the primary
        // repo references across the repo boundary. The spine resolves a
        // cross-repo reference by matching the imported-symbol evidence on the
        // primary's relation against an indexed entity name, so the sibling
        // entity is named with the real symbol the reference imports.
        let external_id = kin_model::EntityId::new();
        let imported_symbol = "remote_call";

        let sibling_dir = tempfile::tempdir().unwrap();
        let sibling_init = kin_core::init(sibling_dir.path()).unwrap();
        let sibling_id = sibling_init.repository_id.as_str().to_string();
        let sibling_graph = InMemoryGraph::new();
        let sibling_blobs =
            kin_blobs::BlobStore::new(sibling_init.layout.ingest_cas_dir()).unwrap();
        let sibling_source = b"pub fn remote_call() {}\n";
        let sibling_digest = sibling_blobs.write(sibling_source).unwrap();
        sibling_graph
            .apply_transaction_delta(&kin_model::TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: ArtifactId::new(),
                    new: LocatedEntry::new(
                        RepoPath::from_bytes(b"src/lib.rs".to_vec()).unwrap(),
                        kin_model::TreeEntry::blob(Hash256::from_bytes(sibling_digest.0), false),
                    ),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();
        sibling_graph
            .batch_upsert_entities(&[test_entity(imported_symbol, "src/lib.rs")])
            .unwrap();
        let plan = crate::repository_commit::plan_native_commit(
            &sibling_graph,
            &sibling_blobs,
            &crate::local_repository_authority::LocalRepositoryAuthorityContext::from_layout_for_test(
                &sibling_init.layout,
            )
            .unwrap(),
            kin_model::OperationId::new(),
            kin_model::Timestamp::now(),
            kin_model::AuthorId::new("spine-fixture"),
            "publish sibling semantic authority".to_string(),
        )
        .unwrap();
        crate::repository_commit::commit_native_plan(
            &sibling_blobs,
            &crate::local_repository_authority::LocalRepositoryAuthorityContext::from_layout_for_test(
                &sibling_init.layout,
            )
            .unwrap(),
            plan,
        )
        .unwrap();
        let sibling_binding =
            kin_core::LocalRepositoryAuthorityBinding::from_layout(&sibling_init.layout).unwrap();
        let expected_sibling_root = hex::encode(
            DaemonState::load_registered_workspace_graph(&sibling_binding)
                .unwrap()
                .compute_root_hash(),
        );

        // Pin the sibling through startup registry configuration before the
        // primary daemon state becomes externally visible.
        let registry_dir = tempfile::tempdir().unwrap();
        let registry_path = registry_dir.path().join("registry.toml");
        kin_core::registry::KinRegistry {
            repos: vec![kin_core::registry::RegisteredRepo {
                id: sibling_id.clone(),
                path: sibling_dir.path().to_path_buf(),
                entities: 1,
                last_commit: String::new(),
                dependencies: vec![],
            }],
        }
        .save_to(&registry_path)
        .unwrap();
        let _spine_env = kin_core::test_env::EnvVarGuard::set("KIN_REGISTRY_PATH", &registry_path)
            .without("KIN_DISABLE_SPINE");

        // The primary repo: a caller entity plus an unresolved cross-repo call
        // tagged with the sibling repo as its import source.
        let primary_dir = tempfile::tempdir().unwrap();
        let primary_init = kin_core::init(primary_dir.path()).unwrap();
        let state = test_state(primary_init.layout, primary_dir.path());
        let caller = test_entity("caller", "src/main.rs");
        state
            .graph
            .batch_upsert_entities(std::slice::from_ref(&caller))
            .unwrap();
        state
            .graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(caller.id),
                dst: GraphNodeId::Entity(external_id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: Some(sibling_id.clone()),
                evidence: vec![RelationEvidence {
                    token: Some(imported_symbol.to_string()),
                    ..RelationEvidence::default()
                }],
            })
            .unwrap();

        let (repo_count, edge_count, sibling_root) = {
            let spine = state.ensure_spine().expect("spine must be enabled");
            (
                spine.repo_count(),
                spine.edge_count(),
                spine.root_hash(&sibling_id),
            )
        };

        // Restore the process-global env before asserting so a failure can never
        // leak the override into other tests.

        assert!(
            repo_count >= 2,
            "primary and sibling repos must both be indexed (got {repo_count})"
        );
        assert!(
            edge_count > 0,
            "cross-repo edges must materialize after spine init (got {edge_count})"
        );
        assert_eq!(
            sibling_root.as_deref(),
            Some(expected_sibling_root.as_str()),
            "sibling registration must carry its exact nonempty snapshot root"
        );
    }

    /// The join between the two producers of repository identity, over the real
    /// set rather than over two strings a fixture wrote itself.
    ///
    /// `spine_init_materializes_cross_repo_edges` above registers its sibling by
    /// hand, taking the id from `kin_core::init`'s minted manifest identity. That
    /// makes both sides of the daemon's startup identity comparison agree because
    /// one fixture wrote both, so the test passes on a tree where the two real
    /// producers disagree and no sibling can ever be pinned.
    ///
    /// This test registers the sibling the way `kin init` registers it, by
    /// calling the same `kin_migrate::update_registry` that `kin init` calls, and
    /// then asks for the consequence: cross-repo edges. No repository identity is
    /// written twice here, so the assertion is about the agreement between the
    /// registry writer and the daemon's startup check rather than about either
    /// one alone.
    /// One registered sibling, registered through the production writer, so both
    /// checks below start from a state a real install produces.
    #[cfg(test)]
    struct SiblingFixture {
        _sibling_parent: tempfile::TempDir,
        _registry_dir: tempfile::TempDir,
        sibling_root: std::path::PathBuf,
        _spine_env: kin_core::test_env::EnvVarGuard,
    }

    #[derive(Default)]
    struct CapturedPinEvents {
        rendered: Vec<String>,
    }

    struct PinCaptureLayer(Arc<Mutex<CapturedPinEvents>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for PinCaptureLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Render<'a>(&'a mut String);

            impl tracing::field::Visit for Render<'_> {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    use std::fmt::Write;
                    let _ = write!(self.0, "{}={value:?} ", field.name());
                }
            }

            let mut rendered = String::new();
            event.record(&mut Render(&mut rendered));
            self.0.lock().unwrap().rendered.push(rendered);
        }
    }

    fn capture_pin_events<T>(run: impl FnOnce() -> T) -> (T, Vec<String>) {
        use tracing_subscriber::layer::SubscriberExt;

        let captured = Arc::new(Mutex::new(CapturedPinEvents::default()));
        let subscriber =
            tracing_subscriber::registry().with(PinCaptureLayer(Arc::clone(&captured)));
        let result = {
            let _capture = crate::capture_events_on_this_thread(subscriber);
            run()
        };
        let events = std::mem::take(&mut captured.lock().unwrap().rendered);
        (result, events)
    }

    /// One registered sibling, registered through the production writer, so both
    /// checks below start from a state a real install produces.
    ///
    /// The registry guard is installed BEFORE `update_registry` runs and is
    /// returned so it outlives the fixture. Setting it afterwards writes the
    /// entry to this host's real registry and pins nothing, which is how the
    /// first draft of these checks failed: at their own precondition, which is
    /// what that precondition is for.
    #[cfg(test)]
    fn registered_sibling_fixture() -> SiblingFixture {
        let sibling_parent = tempfile::tempdir().unwrap();
        let sibling_root = sibling_parent.path().join("sibling-checkout");
        std::fs::create_dir_all(&sibling_root).unwrap();
        kin_core::init(&sibling_root).unwrap();
        let registry_dir = tempfile::tempdir().unwrap();
        let registry_path = registry_dir.path().join("registry.toml");
        let spine_env = kin_core::test_env::EnvVarGuard::set("KIN_REGISTRY_PATH", &registry_path)
            .without("KIN_DISABLE_SPINE");
        kin_migrate::update_registry(&sibling_root, 1).unwrap();
        SiblingFixture {
            _sibling_parent: sibling_parent,
            _registry_dir: registry_dir,
            sibling_root,
            _spine_env: spine_env,
        }
    }

    #[test]
    #[serial_test::serial]
    fn startup_pin_failures_emit_bounded_detail_and_complete_counts() {
        let primary_dir = tempfile::tempdir().unwrap();
        let primary_init = kin_core::init(primary_dir.path()).unwrap();
        let registry_dir = tempfile::tempdir().unwrap();
        let registry_path = registry_dir.path().join("registry.toml");
        let failure_count = STARTUP_PIN_FAILURE_DETAIL_LIMIT + 5;
        let mut repos = Vec::new();
        for index in 0..failure_count {
            let root = registry_dir.path().join(format!("stale-{index:02}"));
            std::fs::create_dir_all(root.join(".kin")).unwrap();
            std::fs::write(root.join(".kin/VERSION"), b"1").unwrap();
            repos.push(kin_core::registry::RegisteredRepo {
                id: format!("stale-{index:02}"),
                path: root,
                entities: 0,
                last_commit: String::new(),
                dependencies: vec![],
            });
        }
        kin_core::registry::KinRegistry { repos }
            .save_to(&registry_path)
            .unwrap();
        let _spine_env = kin_core::test_env::EnvVarGuard::set("KIN_REGISTRY_PATH", &registry_path)
            .without("KIN_DISABLE_SPINE");

        let ((pinned, incomplete), events) = capture_pin_events(|| {
            DaemonState::pin_registered_local_repository_authorities(&primary_init.layout)
        });
        let detailed = events
            .iter()
            .filter(|event| {
                event.contains("sibling repository authority could not be pinned at daemon startup")
            })
            .count();
        let summaries = events
            .iter()
            .filter(|event| event.contains("sibling repository authority pinning was incomplete"))
            .collect::<Vec<_>>();

        assert!(pinned.is_empty());
        assert!(
            incomplete,
            "suppressed detail must not suppress incompleteness"
        );
        assert_eq!(
            detailed, STARTUP_PIN_FAILURE_DETAIL_LIMIT,
            "one stale registry must not emit one detailed warning per row: {events:?}"
        );
        assert_eq!(
            summaries.len(),
            1,
            "one startup gets one aggregate: {events:?}"
        );
        let summary = summaries[0];
        for field in [
            format!("registry_rows={failure_count}"),
            "pinned=0".to_string(),
            format!("refused={failure_count}"),
            format!("detailed={STARTUP_PIN_FAILURE_DETAIL_LIMIT}"),
            format!(
                "suppressed={}",
                failure_count - STARTUP_PIN_FAILURE_DETAIL_LIMIT
            ),
        ] {
            assert!(
                summary.contains(&field),
                "aggregate warning must carry {field}: {summary}"
            );
        }
    }

    #[test]
    #[serial_test::serial]
    fn a_clean_sibling_pin_emits_no_failure_diagnostics() {
        let _fixture = registered_sibling_fixture();
        let primary_dir = tempfile::tempdir().unwrap();
        let primary_init = kin_core::init(primary_dir.path()).unwrap();

        let ((pinned, incomplete), events) = capture_pin_events(|| {
            DaemonState::pin_registered_local_repository_authorities(&primary_init.layout)
        });

        assert_eq!(pinned.len(), 1);
        assert!(!incomplete);
        assert!(
            events
                .iter()
                .all(|event| !event.contains("sibling repository authority")),
            "a clean registry must not emit failure diagnostics: {events:?}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn disabling_the_spine_skips_the_registry_pin_pass_at_construction() {
        let primary_dir = tempfile::tempdir().unwrap();
        let primary_init = kin_core::init(primary_dir.path()).unwrap();
        let registry_dir = tempfile::tempdir().unwrap();
        let registry_path = registry_dir.path().join("registry.toml");
        let stale_root = registry_dir.path().join("stale-sibling");
        std::fs::create_dir_all(stale_root.join(".kin")).unwrap();
        std::fs::write(stale_root.join(".kin/VERSION"), b"1").unwrap();
        kin_core::registry::KinRegistry {
            repos: vec![kin_core::registry::RegisteredRepo {
                id: "stale-sibling".to_string(),
                path: stale_root,
                entities: 0,
                last_commit: String::new(),
                dependencies: vec![],
            }],
        }
        .save_to(&registry_path)
        .unwrap();
        let mut spine_env =
            kin_core::test_env::EnvVarGuard::set("KIN_REGISTRY_PATH", &registry_path)
                .with("KIN_DISABLE_SPINE", "1");

        let (disabled, disabled_events) =
            capture_pin_events(|| test_state(primary_init.layout.clone(), primary_dir.path()));
        assert!(disabled.registered_local_repository_authorities.is_empty());
        assert!(disabled.startup_authority_complete());
        assert!(
            disabled_events
                .iter()
                .all(|event| !event.contains("sibling repository authority")),
            "a disabled subsystem must not inspect or warn about sibling authority: {disabled_events:?}"
        );

        // The process environment is not request scoped. Changing it after
        // construction must not re-enable a state whose startup skipped the
        // authority pass, or that state could publish a spine from a different
        // scope than the one it captured.
        spine_env.apply::<_, &str>("KIN_DISABLE_SPINE", None);
        assert!(
            disabled.ensure_spine().is_none(),
            "spine disable must be captured once at daemon-state construction"
        );
        drop(disabled);

        // Falsification control: the same registry with federation enabled must
        // still be inspected and must still report the unbindable row.
        let (enabled, enabled_events) =
            capture_pin_events(|| test_state(primary_init.layout.clone(), primary_dir.path()));
        assert!(!enabled.startup_authority_complete());
        assert!(enabled_events.iter().any(|event| {
            event.contains("sibling repository authority could not be pinned at daemon startup")
        }));
        assert!(enabled_events.iter().any(|event| {
            event.contains("sibling repository authority pinning was incomplete")
        }));
    }

    /// FIR-2763's remaining acceptance: what the eager sibling pass costs on a
    /// REAL populated registry, measured rather than argued.
    ///
    /// `#[ignore]` because it opens this host's own registry and loads whole
    /// sibling workspace graphs. `KIN_SPINE_MEASURE_BOUNDS` names the bounds to
    /// sweep, smallest first, so the curve can be stopped before the box is.
    /// Each arm is a fresh `DaemonState`, because the capture happens once per
    /// process and a second call would measure a `OnceLock` read.
    ///
    /// It reports the bound, the wall clock, and what the capture actually did,
    /// so a row can be read against the work it describes rather than against
    /// an assumption about how many siblings that bound reached.
    #[test]
    #[serial_test::serial]
    #[ignore = "measurement against this host's real registry, not a guard"]
    fn measure_eager_sibling_capture_against_the_real_registry() {
        let bounds =
            std::env::var("KIN_SPINE_MEASURE_BOUNDS").unwrap_or_else(|_| "0,1,2,4,8".to_string());
        let primary_dir = tempfile::tempdir().unwrap();
        let primary_init = kin_core::init(primary_dir.path()).unwrap();

        eprintln!("FIR2763 MEASURE bound | seconds | captured/registered | bounded | incomplete");
        for raw in bounds.split(',') {
            let bound: usize = raw.trim().parse().expect("bounds must be integers");
            // A fresh state per arm: `ensure_spine` publishes once, so reusing
            // one would time a OnceLock read rather than a capture.
            let mut state = test_state(primary_init.layout.clone(), primary_dir.path());
            let registered = state.registered_local_repository_authorities.len();
            state.eager_sibling_bound = bound;

            let started = std::time::Instant::now();
            let _ = state.ensure_spine();
            let seconds = started.elapsed().as_secs_f64();

            let report = state.sibling_capture_report();
            eprintln!(
                "FIR2763 MEASURE {bound:>5} | {seconds:>7.2} | {:>19} | {:>7} | {:>10}",
                report
                    .map(|r| format!("{}/{}", r.captured, r.registered))
                    .unwrap_or_else(|| format!("-/{registered}")),
                report.map(|r| r.bounded.to_string()).unwrap_or("-".into()),
                report
                    .map(|r| r.authority_incomplete.to_string())
                    .unwrap_or("-".into()),
            );
        }
    }

    /// Which sibling the eager pass actually spends its time on.
    ///
    /// The bound sweep showed a large first-sibling cost and a small marginal
    /// one, which fits two different worlds: a one-time initialization on first
    /// load, or one pathological sibling that happens to be first. The sweep
    /// already argues against the first, because a second fresh `DaemonState`
    /// in the same process paid the cost again. This settles it by timing each
    /// sibling load separately and naming them.
    #[test]
    #[serial_test::serial]
    #[ignore = "measurement against this host's real registry, not a guard"]
    fn attribute_the_eager_sibling_cost_per_sibling() {
        let primary_dir = tempfile::tempdir().unwrap();
        let primary_init = kin_core::init(primary_dir.path()).unwrap();
        let state = test_state(primary_init.layout, primary_dir.path());

        eprintln!("FIR2763 ATTRIBUTE seconds | repo_id");
        let mut total = 0.0_f64;
        // The discriminator. A first sibling is slow under BOTH hypotheses, so
        // the order is reversed here: if the new first sibling is also slow the
        // cost is one-time initialization paid by whoever goes first, and if it
        // is fast the cost belongs to one pathological repository.
        let reverse = std::env::var("KIN_SPINE_ATTRIBUTE_REVERSE").is_ok();
        let mut order: Vec<_> = state
            .registered_local_repository_authorities
            .iter()
            .collect();
        if reverse {
            order.reverse();
        }
        eprintln!("FIR2763 ATTRIBUTE order reversed: {reverse}");
        for registered in order {
            let binding = registered.binding.clone();
            let started = std::time::Instant::now();
            let loaded = DaemonState::load_registered_workspace_graph(&binding);
            let seconds = started.elapsed().as_secs_f64();
            total += seconds;
            eprintln!(
                "FIR2763 ATTRIBUTE {seconds:>7.2} | {} {}",
                registered.repo_id,
                if loaded.is_ok() { "" } else { "(load failed)" }
            );
        }
        eprintln!(
            "FIR2763 ATTRIBUTE total {total:.2}s over {} siblings",
            state.registered_local_repository_authorities.len()
        );
    }

    /// FIR-2763's bound, and FIR-2772's scoping, from the BOUNDED side.
    ///
    /// A capture the configured bound stopped is not an incomplete authority. It
    /// is a deliberate partial whose captures are sound, and the two are
    /// different claims about the same inequality. This pins that a cap
    /// discloses itself, leaves `authority_incomplete` alone, and does not cost
    /// the primary its own registration.
    ///
    /// Falsified by the other state's mechanism: make the sibling FAIL to load
    /// instead of capping it, and `bounded` must go false while
    /// `authority_incomplete` goes true. Two producers of one inequality is the
    /// trap class this defect came from, so neither arm may assert on the
    /// inequality itself.
    #[test]
    #[serial_test::serial]
    fn a_capture_stopped_at_its_bound_is_bounded_rather_than_incomplete() {
        // Held, not dropped: the fixture owns the registry guard, and dropping it
        // early would unset KIN_REGISTRY_PATH before the daemon reads it.
        let _fixture = registered_sibling_fixture();

        let primary_dir = tempfile::tempdir().unwrap();
        let primary_init = kin_core::init(primary_dir.path()).unwrap();
        let mut state = test_state(primary_init.layout, primary_dir.path());
        assert_eq!(
            state.registered_local_repository_authorities.len(),
            1,
            "the fixture must pin exactly one sibling before the bound can mean anything"
        );

        // Injected, not set through the environment. The lever is resolved once
        // at construction precisely so a test can do this without mutating
        // process-global state every other test in this binary shares.
        state.eager_sibling_bound = 0;

        let repo_count = {
            let spine = state.ensure_spine().expect("spine must be enabled");
            spine.repo_count()
        };
        let report = state
            .sibling_capture_report()
            .expect("a published spine must report what its sibling capture did");

        assert!(
            report.bounded,
            "a capture stopped at its bound must say so: {report:?}"
        );
        assert_eq!(
            report.captured, 0,
            "bound of zero captures no sibling: {report:?}"
        );
        assert_eq!(
            report.registered, 1,
            "one sibling was registered: {report:?}"
        );
        assert!(
            !report.authority_incomplete,
            "a deliberate cap is not an incomplete authority; conflating them is what \
             lets a real failure hide behind a configured bound: {report:?}"
        );
        assert_eq!(
            repo_count, 1,
            "the primary must still be captured and registered when siblings are capped: {report:?}"
        );
    }

    /// The same inequality from the INCOMPLETE side, which is the falsification
    /// of the check above and is why both live here rather than one.
    ///
    /// A sibling that pinned at startup and then could not be loaded is a shape
    /// nobody chose. It must report incomplete and must NOT report bounded, or a
    /// real failure reads as a configured cap.
    #[test]
    #[serial_test::serial]
    fn a_sibling_that_fails_to_load_is_incomplete_and_never_bounded() {
        let fixture = registered_sibling_fixture();

        let primary_dir = tempfile::tempdir().unwrap();
        let primary_init = kin_core::init(primary_dir.path()).unwrap();
        let mut state = test_state(primary_init.layout, primary_dir.path());
        assert_eq!(
            state.registered_local_repository_authorities.len(),
            1,
            "the sibling must pin at startup, so that what fails below is the LOAD \
             rather than the pin; otherwise this arm tests the wrong layer"
        );

        // A bound high enough that the sibling is attempted. The failure has to
        // come from the load, not from the cap, or this arm proves nothing about
        // the difference between them.
        state.eager_sibling_bound = 16;

        // Break the sibling AFTER it pinned. Pinning reads the manifest at
        // startup; loading reads the graph later, and only the second happens
        // inside the capture loop.
        std::fs::remove_dir_all(fixture.sibling_root.join(".kin")).unwrap();

        let _ = state.ensure_spine();
        let report = state
            .sibling_capture_report()
            .expect("a published spine must report what its sibling capture did");

        assert!(
            !report.bounded,
            "a sibling that failed to load was not capped, and must not claim it was: {report:?}"
        );
        assert!(
            report.authority_incomplete,
            "a sibling that pinned and then failed to load leaves the authority incomplete: {report:?}"
        );
        assert_eq!(
            report.registered, 1,
            "the sibling was registered whether or not it loaded: {report:?}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn spine_pins_the_sibling_that_kin_init_actually_registered() {
        use kin_db::InMemoryGraph;
        use kin_model::{
            GraphNodeId, Relation, RelationEvidence, RelationId, RelationKind, RelationOrigin,
        };

        let external_id = kin_model::EntityId::new();
        let imported_symbol = "remote_call";

        // A sibling under a directory whose name is deliberately NOT the shape of
        // a minted repository identity, so a check that compares the two
        // identities cannot pass by coincidence of naming.
        let sibling_parent = tempfile::tempdir().unwrap();
        let sibling_root = sibling_parent.path().join("sibling-checkout");
        std::fs::create_dir_all(&sibling_root).unwrap();
        let sibling_init = kin_core::init(&sibling_root).unwrap();
        let sibling_graph = InMemoryGraph::new();
        let sibling_blobs =
            kin_blobs::BlobStore::new(sibling_init.layout.ingest_cas_dir()).unwrap();
        let sibling_source = b"pub fn remote_call() {}\n";
        let sibling_digest = sibling_blobs.write(sibling_source).unwrap();
        sibling_graph
            .apply_transaction_delta(&kin_model::TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: ArtifactId::new(),
                    new: LocatedEntry::new(
                        RepoPath::from_bytes(b"src/lib.rs".to_vec()).unwrap(),
                        kin_model::TreeEntry::blob(Hash256::from_bytes(sibling_digest.0), false),
                    ),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();
        sibling_graph
            .batch_upsert_entities(&[test_entity(imported_symbol, "src/lib.rs")])
            .unwrap();
        let plan = crate::repository_commit::plan_native_commit(
            &sibling_graph,
            &sibling_blobs,
            &crate::local_repository_authority::LocalRepositoryAuthorityContext::from_layout_for_test(
                &sibling_init.layout,
            )
            .unwrap(),
            kin_model::OperationId::new(),
            kin_model::Timestamp::now(),
            kin_model::AuthorId::new("spine-fixture"),
            "publish sibling semantic authority".to_string(),
        )
        .unwrap();
        crate::repository_commit::commit_native_plan(
            &sibling_blobs,
            &crate::local_repository_authority::LocalRepositoryAuthorityContext::from_layout_for_test(
                &sibling_init.layout,
            )
            .unwrap(),
            plan,
        )
        .unwrap();

        // Register through the production writer. `kin init` calls exactly this
        // (kin-cli `commands/init.rs`), so whatever identity the registry ends up
        // carrying is the identity a real install carries.
        let registry_dir = tempfile::tempdir().unwrap();
        let registry_path = registry_dir.path().join("registry.toml");
        let _spine_env = kin_core::test_env::EnvVarGuard::set("KIN_REGISTRY_PATH", &registry_path)
            .without("KIN_DISABLE_SPINE");
        kin_migrate::update_registry(&sibling_root, 1).unwrap();

        // The sibling id the spine will key on is whatever the production writer
        // just recorded. Reading it back rather than restating it is what keeps
        // this test honest about the join: nothing here asserts what that string
        // should be.
        let registered = kin_core::registry::KinRegistry::load_from(&registry_path).unwrap();
        let sibling_entry = registered
            .repos
            .iter()
            .find(|repo| {
                repo.path
                    .canonicalize()
                    .ok()
                    .zip(sibling_root.canonicalize().ok())
                    .is_some_and(|(registered, expected)| registered == expected)
            })
            .expect("the production registry writer must record the sibling it was given")
            .clone();
        let sibling_id = sibling_entry.id.clone();

        // The primary repo: a caller entity plus an unresolved cross-repo call
        // tagged with the registered sibling as its import source.
        let primary_dir = tempfile::tempdir().unwrap();
        let primary_init = kin_core::init(primary_dir.path()).unwrap();
        let state = test_state(primary_init.layout, primary_dir.path());
        let caller = test_entity("caller", "src/main.rs");
        state
            .graph
            .batch_upsert_entities(std::slice::from_ref(&caller))
            .unwrap();
        state
            .graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(caller.id),
                dst: GraphNodeId::Entity(external_id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: Some(sibling_id.clone()),
                evidence: vec![RelationEvidence {
                    token: Some(imported_symbol.to_string()),
                    ..RelationEvidence::default()
                }],
            })
            .unwrap();

        let primary_repo_id = state.cached_repo_id.clone();
        let (repo_count, edge_count, spine_ids, sibling_roots) = {
            let spine = state.ensure_spine().expect("spine must be enabled");
            let ids = spine.registered_repo_ids();
            let roots = ids
                .iter()
                .filter(|id| *id != &primary_repo_id)
                .filter_map(|id| spine.root_hash(id).map(|root| (id.clone(), root)))
                .collect::<Vec<_>>();
            (spine.repo_count(), spine.edge_count(), ids, roots)
        };

        // Deliberately says nothing about WHICH identity the spine keys on. That
        // is the open design question this check must outlive: it pins the
        // consequence, that a sibling `kin init` registered is pinned and its
        // edges materialize, so an identity change can move the key without
        // moving this check, and cannot silently zero the spine.
        assert_eq!(
            repo_count, 2,
            "the sibling `kin init` registered must be pinned beside the primary \
             (registry id {sibling_id:?}, spine ids {spine_ids:?}); a repo_count of 1 \
             means the daemon refused it at startup"
        );
        assert_eq!(
            sibling_roots.len(),
            1,
            "exactly one non-primary repository must carry a registered root \
             (got {sibling_roots:?})"
        );
        assert!(
            !sibling_roots[0].1.is_empty(),
            "the pinned sibling's registered root must be its real graph root, not empty \
             (got {sibling_roots:?})"
        );
        assert!(
            edge_count > 0,
            "cross-repo edges must materialize for a sibling registered the way `kin init` \
             registers one (got {edge_count}, spine ids {spine_ids:?})"
        );
    }

    /// The one case pinning still refuses: two registry rows resolving to one
    /// repository identity.
    ///
    /// Two paths holding the same repository, a copied checkout being the usual
    /// cause, would register twice under one spine key and let the second
    /// overwrite the first's graph authority. Refusing the later row and marking
    /// the authority set incomplete is the conservative answer, and it is the
    /// only refusal left in a pass that used to refuse everything.
    ///
    /// Exercised against `pin_registered_local_repository_authorities` directly
    /// rather than through the spine, because both halves of what it decides,
    /// which rows pinned and whether the set is complete, are its return value
    /// and nothing downstream reports the second one on its own.
    #[test]
    #[serial_test::serial]
    fn two_registry_rows_for_one_repository_pin_once_and_report_incomplete() {
        let sibling_parent = tempfile::tempdir().unwrap();
        let sibling_root = sibling_parent.path().join("sibling-checkout");
        std::fs::create_dir_all(&sibling_root).unwrap();
        kin_core::init(&sibling_root).unwrap();

        let registry_dir = tempfile::tempdir().unwrap();
        let registry_path = registry_dir.path().join("registry.toml");
        let _registry_env =
            kin_core::test_env::EnvVarGuard::set("KIN_REGISTRY_PATH", &registry_path);
        // One repository, two rows. Distinct ids on purpose: `upsert` dedupes on
        // id, so this is the shape a registry actually reaches when the same
        // repository is registered from two paths.
        kin_core::registry::KinRegistry {
            repos: vec![
                kin_core::registry::RegisteredRepo {
                    id: "sibling-checkout".to_string(),
                    path: sibling_root.clone(),
                    entities: 1,
                    last_commit: String::new(),
                    dependencies: vec![],
                },
                kin_core::registry::RegisteredRepo {
                    id: "sibling-checkout-copy".to_string(),
                    path: sibling_root.clone(),
                    entities: 1,
                    last_commit: String::new(),
                    dependencies: vec![],
                },
            ],
        }
        .save_to(&registry_path)
        .unwrap();

        let primary_dir = tempfile::tempdir().unwrap();
        let primary_init = kin_core::init(primary_dir.path()).unwrap();
        let (pinned, incomplete) =
            DaemonState::pin_registered_local_repository_authorities(&primary_init.layout);

        assert_eq!(
            pinned.len(),
            1,
            "one repository must pin once however many registry rows point at it: {:?}",
            pinned.iter().map(|p| p.repo_id.clone()).collect::<Vec<_>>()
        );
        assert!(
            incomplete,
            "a refused duplicate row must leave the authority set reported incomplete"
        );
    }

    /// The healthy control for the refusal above: two rows naming two genuinely
    /// different repositories both pin, and the set reports complete.
    ///
    /// Without it the refusal could be tightened into refusing every second
    /// sibling and nothing would notice, because the test above only ever asserts
    /// that fewer than two pinned.
    #[test]
    #[serial_test::serial]
    fn two_registry_rows_for_two_repositories_both_pin_and_report_complete() {
        let parent = tempfile::tempdir().unwrap();
        let mut roots = Vec::new();
        for name in ["sibling-one", "sibling-two"] {
            let root = parent.path().join(name);
            std::fs::create_dir_all(&root).unwrap();
            kin_core::init(&root).unwrap();
            roots.push(root);
        }

        let registry_dir = tempfile::tempdir().unwrap();
        let registry_path = registry_dir.path().join("registry.toml");
        let _registry_env =
            kin_core::test_env::EnvVarGuard::set("KIN_REGISTRY_PATH", &registry_path);
        kin_core::registry::KinRegistry {
            repos: roots
                .iter()
                .map(|root| kin_core::registry::RegisteredRepo {
                    id: root.file_name().unwrap().to_string_lossy().to_string(),
                    path: root.clone(),
                    entities: 1,
                    last_commit: String::new(),
                    dependencies: vec![],
                })
                .collect(),
        }
        .save_to(&registry_path)
        .unwrap();

        let primary_dir = tempfile::tempdir().unwrap();
        let primary_init = kin_core::init(primary_dir.path()).unwrap();
        let (pinned, incomplete) =
            DaemonState::pin_registered_local_repository_authorities(&primary_init.layout);

        assert_eq!(
            pinned.len(),
            2,
            "two distinct repositories must both pin: {:?}",
            pinned.iter().map(|p| p.repo_id.clone()).collect::<Vec<_>>()
        );
        assert!(
            !incomplete,
            "two distinct repositories pinning cleanly must not report the set incomplete"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn ingest_repo_into_spine_serves_non_empty_xref_from_storage_only() {
        // Hosted org-graph demo in miniature, against the PRODUCTION ingest
        // write path. A hosted pod runs one repo and owns no local sibling
        // checkouts and no `registry.toml`: the cross-repo index must be built
        // by loading sibling graphs from the durable StorageBackend (GCS in
        // cloud, a `LocalFileBackend` rooted at `v2/` here) via
        // `ingest_repo_into_spine`, not from local registry workspace
        // authorities.
        //
        // Two repos land in storage the way cloud ingestion sees them: the
        // sibling `kin-db` (which exports `InMemoryGraph`) and the primary
        // `kin`, whose caller references `kin_db::InMemoryGraph` across the repo
        // boundary. After ingesting both, `/spine/xref` for the primary caller
        // must return a non-empty cross-repo edge bound to the store-resident
        // sibling entity.
        use kin_db::{InMemoryGraph, LocalFileBackend, StorageBackend, GENERATION_INIT};
        use kin_model::{
            GraphNodeId, Relation, RelationEvidence, RelationId, RelationKind, RelationOrigin,
        };

        let sibling_id = "kin-db";
        let primary_id = "kin";
        let imported_symbol = "InMemoryGraph";

        // The durable store, standing in for the GCS bucket (no local-disk
        // siblings, no registry).
        let storage = tempfile::tempdir().unwrap();
        let v2_root = storage.path().join("v2");
        std::fs::create_dir(&v2_root)
            .expect("storage fixture must create its existing-only backend root");

        // ── Ingestion source: seed the sibling graph into storage ─────────
        // Only the sibling's serialized graph reaches storage — never a local
        // `.kndb` next to the pod's repo.
        let sibling_entity = test_entity(imported_symbol, "src/lib.rs");
        let sibling_graph = InMemoryGraph::new();
        sibling_graph
            .batch_upsert_entities(std::slice::from_ref(&sibling_entity))
            .unwrap();
        {
            let seed_backend = LocalFileBackend::new(&v2_root);
            let bytes = sibling_graph.to_snapshot().to_bytes().unwrap();
            seed_backend
                .save_snapshot(sibling_id, &bytes, GENERATION_INIT)
                .unwrap();
        }

        // ── The hosted pod: serves `kin`, knows `kin`+`kin-db` via KIN_REPO_IDS
        // The pod is opened over the same storage backend; `allowed_repo_ids`
        // mirrors `KIN_REPO_IDS=kin,kin-db` so the daemon may load the sibling
        // graph from storage on demand.
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let allowed: HashSet<String> = [primary_id.to_string(), sibling_id.to_string()]
            .into_iter()
            .collect();

        // Spine must be enabled for this test regardless of ambient env. The
        // state captures that choice at construction, so the guard belongs
        // before the open. Point discovery at an explicitly empty registry:
        // this hosted path proves storage-only sibling ingestion and must never
        // scan a user's real global registry.
        let registry_dir = tempfile::tempdir().unwrap();
        let registry_path = registry_dir.path().join("registry.toml");
        kin_core::registry::KinRegistry { repos: Vec::new() }
            .save_to(&registry_path)
            .unwrap();
        let _spine_env = kin_core::test_env::EnvVarGuard::set("KIN_REGISTRY_PATH", &registry_path)
            .without("KIN_DISABLE_SPINE");

        let state = DaemonState::open_with_backend(
            init.layout,
            Box::new(LocalFileBackend::new(&v2_root)),
            primary_id,
            Some(allowed),
        )
        .unwrap();

        // Build the primary repo's served graph: a caller plus an unresolved
        // cross-repo `Calls` to `kin_db::InMemoryGraph`, carrying the
        // `import_source` and the imported-symbol token the resolver binds on.
        let caller = test_entity("open_graph", "src/graph.rs");
        state
            .graph
            .batch_upsert_entities(std::slice::from_ref(&caller))
            .unwrap();
        state
            .graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(caller.id),
                dst: GraphNodeId::Entity(kin_model::EntityId::new()),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: Some(sibling_id.to_string()),
                evidence: vec![RelationEvidence {
                    token: Some(format!("kin_db::{imported_symbol}")),
                    ..RelationEvidence::default()
                }],
            })
            .unwrap();

        // ── Drive the production ingest route logic ───────────────────────
        // Sibling first (metadata only), then the anchor with edge refresh —
        // exactly the order the control-plane orchestrator POSTs.
        let sibling_outcome = state
            .ingest_repo_into_spine(sibling_id, false)
            .await
            .expect("sibling ingest from storage");
        let ingest_race_entity = test_entity("ingest_race", "src/ingest_race.rs");
        let primary_outcome = state
            .ingest_repo_into_spine_with_capture_hook(primary_id, true, |attempt| {
                if attempt == 0 {
                    let mutation = state.begin_graph_authority_mutation();
                    state.graph.upsert_entity(&ingest_race_entity).unwrap();
                    drop(mutation);
                }
            })
            .await
            .expect("primary ingest retries onto stable capture + cross-repo edge refresh");

        // Restore env before asserting so a failure cannot leak the override.

        // The sibling was loaded purely from storage (it has no local `.kndb`).
        assert_eq!(
            sibling_outcome.entity_count, 1,
            "sibling entity metadata must load from the storage backend"
        );
        // The anchor reports a resolvable relation — the honest "this can
        // materialize a cross-repo edge" signal the control plane gates on.
        assert_eq!(
            primary_outcome.resolvable_relations, 1,
            "the primary's cross-repo call must be classified resolvable"
        );
        assert_eq!(
            primary_outcome.root_hash,
            hex::encode(state.graph.compute_root_hash()),
            "ingest must never publish the pre-race entity set under the post-race root"
        );

        let spine = state.spine().expect("spine initialized by ingest");
        assert!(
            spine.repo_count() >= 2,
            "primary and sibling must both be registered (got {})",
            spine.repo_count()
        );
        assert!(
            spine
                .lookup_by_id(primary_id, &ingest_race_entity.id)
                .is_some(),
            "ingest retry must register the entity added between capture and validation"
        );

        // ── The contract the demo needs: non-empty cross-repo xref ────────
        // This is exactly what `GET /spine/xref?repo=kin&entity=<caller>` reads.
        assert!(
            spine.edge_count() >= 1,
            "spine must hold a cross-repo edge after ingest (got {})",
            spine.edge_count()
        );
        let xref = spine.cross_repo_edges_for(primary_id, &caller.id);
        assert!(
            !xref.is_empty(),
            "/spine/xref for the primary caller must be non-empty with storage-only siblings"
        );
        let edge = &xref[0];
        assert_eq!(edge.src_repo, primary_id);
        assert_eq!(
            edge.dst_repo, sibling_id,
            "edge must cross into the sibling repo loaded from storage"
        );
        assert_eq!(
            edge.dst_entity, sibling_entity.id,
            "edge must bind to the storage-resident sibling entity, not a local guess"
        );

        // The boundary is crossable from the sibling side too — the federated
        // reachability the org graph renders.
        let impact = spine.federated_impact(sibling_id, &sibling_entity.id, 5);
        assert!(
            impact.repos_involved.contains(&primary_id.to_string()),
            "changing the sibling entity must impact the primary repo across the boundary"
        );

        // Regression: the primary graph can advance after its explicit ingest
        // but before the orchestrator's all-repo refresh. The refresh must
        // re-register current entries and R1 before resolving; certifying the
        // captured R1 topology under the old ingested R0 root is unsound.
        let ingested_root = spine
            .root_hash(primary_id)
            .expect("primary ingest registered a root");
        let post_ingest_entity = test_entity("post_ingest", "src/new.rs");
        state.graph.upsert_entity(&post_ingest_entity).unwrap();
        let current_root = hex::encode(state.graph.compute_root_hash());
        assert_ne!(current_root, ingested_root);

        let refreshed = state
            .refresh_all_cross_repo_edges()
            .await
            .expect("all-repo refresh after graph mutation");
        assert_eq!(refreshed.repos_refreshed, 2);
        assert_eq!(
            spine.root_hash(primary_id).as_deref(),
            Some(current_root.as_str())
        );
        assert!(
            spine
                .lookup_by_id(primary_id, &post_ingest_entity.id)
                .is_some(),
            "phase 2 must publish current R1 entries before resolving any source"
        );
        assert!(
            spine.cross_repo_edges_snapshot().complete,
            "a stable two-phase pass over both repos should certify completeness"
        );
    }

    #[test]
    fn open_fails_when_persisted_snapshot_is_corrupt() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let manifest = kin_core::manifest::KinManifest::load(&layout.manifest_path()).unwrap();
        let repository_dir = layout.kindb_dir().join(&manifest.repo_id);
        let authority: serde_json::Value =
            serde_json::from_slice(&std::fs::read(repository_dir.join("authority.json")).unwrap())
                .unwrap();
        let snapshot_file = authority["snapshot_file"].as_str().unwrap();
        let authoritative_snapshot = repository_dir.join("snapshots").join(snapshot_file);
        std::fs::write(authoritative_snapshot, b"not-a-valid-kndb").unwrap();

        let err = match DaemonState::open(layout) {
            Ok(_) => panic!("expected corrupt snapshot open to fail"),
            Err(err) => err,
        };
        let message = err.to_string();
        assert!(
            message.contains("snapshot digest mismatch"),
            "unexpected repository authority corruption error: {message}"
        );
        assert!(
            message.contains(&manifest.repo_id),
            "corruption error must identify the repository namespace: {message}"
        );
    }

    #[test]
    fn open_fails_when_persisted_authority_record_is_missing() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let manifest = kin_core::manifest::KinManifest::load(&layout.manifest_path()).unwrap();
        let repository_dir = layout.kindb_dir().join(&manifest.repo_id);
        assert!(
            std::fs::read_dir(repository_dir.join("snapshots"))
                .unwrap()
                .any(|entry| entry.unwrap().file_type().unwrap().is_file()),
            "fixture must retain the repository's persisted snapshot material"
        );
        std::fs::remove_file(repository_dir.join("authority.json")).unwrap();

        let error = match DaemonState::open(layout) {
            Ok(_) => panic!("startup must fail closed without persisted authority.json"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            message.contains("has no persisted authority record"),
            "unexpected missing-authority startup error: {message}"
        );
        assert!(
            message.contains(&manifest.repo_id),
            "missing-authority error must identify the repository namespace: {message}"
        );
    }

    #[test]
    fn open_refuses_pre_v2_layout_before_manifest_parsing() {
        // A pre-v2 `.kin/` (no version marker, or v1) must be refused by the
        // layout gate in its own voice, before manifest parsing runs. The
        // manifest here is the exact field set released 0.3.6 wrote — no
        // `workspace_id` — so if manifest parsing ran first this would fail
        // with a serde error instead of the version gap.
        let repo_dir = tempfile::tempdir().unwrap();
        let kin_dir = repo_dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        std::fs::write(
            kin_dir.join("manifest.json"),
            r#"{"kin_version":"0.3.6","languages":[],"adapters":[],"repo_id":"54c48711-e6f0-4950-b00d-5585b59188fe","created_at":"2026-07-28T03:10:45Z"}"#,
        )
        .unwrap();
        let layout = kin_core::KinLayout::new(kin_dir);

        let err = match DaemonState::open(layout) {
            Ok(_) => panic!("expected pre-v2 layout open to be refused"),
            Err(err) => err,
        };
        assert!(
            matches!(err, DaemonError::IncompatibleRepo(_)),
            "expected IncompatibleRepo, got {err:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("found v1") && message.contains("requires v2"),
            "message must name the layout gap: {message}"
        );
        assert!(
            message.contains("Remove .kin/ and run `kin init`"),
            "message must name a remediation path: {message}"
        );
        assert!(
            !message.contains("fresh checkout"),
            "the remedy must be one `kin init` honors in the tree the reader is in, and `kin \
             init` refuses over an existing store: {message}"
        );
        assert!(
            !message.contains("missing field"),
            "layout refusal must not surface as a serde error: {message}"
        );
    }

    #[test]
    fn open_rejects_pre_0_2_repo_with_actionable_error() {
        // A repo created by a pre-0.2 kin must be refused UP FRONT with
        // a clear, actionable error — never loaded into a daemon that then fails
        // readiness and gets SIGTERM-killed by the supervisor. The gate fires
        // before the graph snapshot is touched, so a tiny manifest fixture (just
        // the version field) is enough to reproduce it. The layout marker is
        // stamped current so the version gate, not the layout gate, speaks.
        let repo_dir = tempfile::tempdir().unwrap();
        let kin_dir = repo_dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        std::fs::write(
            kin_dir.join("version"),
            kin_core::layout::KIN_LAYOUT_VERSION.to_string(),
        )
        .unwrap();
        std::fs::write(kin_dir.join("manifest.json"), r#"{"kin_version":"0.1.0"}"#).unwrap();
        let layout = kin_core::KinLayout::new(kin_dir);

        let err = match DaemonState::open(layout) {
            Ok(_) => panic!("expected pre-0.2 repo open to be refused"),
            Err(err) => err,
        };
        assert!(
            matches!(err, DaemonError::IncompatibleRepo(_)),
            "expected IncompatibleRepo, got {err:?}"
        );
        let message = err.to_string();
        assert!(
            message.contains("0.1.0"),
            "message must name the found version: {message}"
        );
        assert!(
            message.contains("0.2"),
            "message must name the required floor: {message}"
        );
        assert!(
            message.contains("kin migrate") && message.contains("kin embed --rebuild"),
            "message must name the rebuild commands: {message}"
        );
    }

    #[test]
    fn open_accepts_current_version_repo() {
        // The complement to the gate test: a repo stamped at the current build
        // version opens cleanly (the gate must not false-positive on fresh repos).
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        DaemonState::open(init.layout).expect("current-version repo must open");
    }

    /// FIR-2426. The daemon that pays an open is the only process that can
    /// measure it, and the next CLI spawn is the process that needs the number.
    /// Nothing but a record in the store carries it across that boundary, so an
    /// open that logs its cost and persists nothing leaves the next spawn
    /// guessing exactly as before.
    #[test]
    fn open_records_what_it_cost_for_the_next_spawn_to_size_its_idle_window() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let kin_root = init.layout.root().to_path_buf();
        assert_eq!(
            kin_daemon_spawn::read_boot_cost(&kin_root),
            None,
            "a store nothing has opened carries no cost"
        );

        DaemonState::open(init.layout).expect("current-version repo must open");

        let recorded = kin_daemon_spawn::read_boot_cost(&kin_root)
            .expect("an open must leave its cost in the store it opened");
        assert!(
            kin_daemon_spawn::cli_idle_window(Some(recorded.total_ms)).secs
                >= kin_daemon_spawn::CLI_IDLE_FLOOR_SECS,
            "a recorded cost must produce a usable window"
        );
    }

    #[test]
    fn open_materializes_exact_workspace_tree_and_bodies_from_repository_authority() {
        let repo_dir = tempfile::tempdir().unwrap();
        let compose = b"services:\n  api:\n    image: kin:dev\n";
        let binary = [0_u8, 0xff, 0x80, b'\n'];
        let init = kin_core::init(repo_dir.path()).unwrap();
        let blobs = BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let compose_hash = Hash256::from_bytes(blobs.write(compose).unwrap().0);
        let binary_hash = Hash256::from_bytes(blobs.write(&binary).unwrap().0);
        let blob_artifacts = vec![
            ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8("compose.yaml").unwrap(),
                TreeEntry::blob(compose_hash, false),
            ),
            ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8("assets/data.bin").unwrap(),
                TreeEntry::blob(binary_hash, false),
            ),
        ];
        // Only Unix materializes symlinks, so only Unix admits one here.
        #[cfg(unix)]
        let artifacts = {
            let mut artifacts = blob_artifacts;
            let symlink_hash = Hash256::from_bytes(blobs.write(b"compose.yaml").unwrap().0);
            artifacts.push(ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8("compose-current").unwrap(),
                TreeEntry::symlink(symlink_hash),
            ));
            artifacts
        };
        #[cfg(not(unix))]
        let artifacts = blob_artifacts;
        let desired = ResolvedTree::from_artifacts(artifacts).unwrap();
        let context =
            crate::local_repository_authority::LocalRepositoryAuthorityContext::from_layout_for_test(
                &init.layout,
            )
            .unwrap();
        let admitted = crate::repository_commit::admitted_workspace_tree_for_test(
            init.layout.working_dir(),
            context.open().unwrap().read_authority().roots().clone(),
            ResolvedTree::default(),
            desired.clone(),
        );
        crate::repository_commit::publish_workspace_tree(
            &blobs,
            &context,
            &admitted,
            kin_model::OperationId::new(),
            kin_model::AuthorId::new("authority-open-test"),
        )
        .unwrap()
        .expect("exact workspace admission must advance authority");

        let state = DaemonState::open(init.layout)
            .expect("repository-v6 workspace authority must materialize directly");
        let tree = state.graph.resolved_tree();
        let compose_artifact = tree
            .artifact_at_path(&RepoPath::from_utf8("compose.yaml").unwrap())
            .expect("Compose is exact repository-tree authority");
        let compose_hash = compose_artifact
            .entry
            .blob_identity()
            .expect("Compose is a blob");
        assert_eq!(state.blobs.read(&compose_hash).unwrap(), compose);

        let binary_artifact = tree
            .artifact_at_path(&RepoPath::from_utf8("assets/data.bin").unwrap())
            .expect("binary assets are exact repository-tree authority");
        let binary_hash = binary_artifact
            .entry
            .blob_identity()
            .expect("binary asset is a blob");
        assert_eq!(state.blobs.read(&binary_hash).unwrap(), binary);

        #[cfg(unix)]
        {
            let symlink_artifact = tree
                .artifact_at_path(&RepoPath::from_utf8("compose-current").unwrap())
                .expect("symlinks are exact repository-tree authority");
            assert!(matches!(symlink_artifact.entry, TreeEntry::Symlink { .. }));
            let target_hash = symlink_artifact.entry.blob_identity().unwrap();
            assert_eq!(state.blobs.read(&target_hash).unwrap(), b"compose.yaml");
        }
    }

    #[test]
    fn open_with_repo_id_rejects_identity_other_than_manifest_authority() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let error = match DaemonState::open_with_repo_id(init.layout, Some("entrypoint-repo")) {
            Ok(_) => panic!("local workspace authority cannot be rebound to another repository"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("does not match manifest authority"),
            "unexpected identity mismatch error: {error}"
        );
    }

    #[test]
    fn lsp_source_text_uses_graph_and_repository_cas_not_checkout_or_ingest_cache() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let blobs = BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let authority_bytes = b"pub fn authority_owned() {}\n";
        let hash = Hash256::from_bytes(blobs.write(authority_bytes).unwrap().0);
        let desired = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8("src/lib.rs").unwrap(),
            TreeEntry::blob(hash, false),
        )])
        .unwrap();
        let context =
            crate::local_repository_authority::LocalRepositoryAuthorityContext::from_layout_for_test(
                &init.layout,
            )
            .unwrap();
        let admitted = crate::repository_commit::admitted_workspace_tree_for_test(
            init.layout.working_dir(),
            context.open().unwrap().read_authority().roots().clone(),
            ResolvedTree::default(),
            desired.clone(),
        );
        crate::repository_commit::publish_workspace_tree(
            &blobs,
            &context,
            &admitted,
            kin_model::OperationId::new(),
            kin_model::AuthorId::new("lsp-authority-test"),
        )
        .unwrap()
        .expect("exact source admission must advance authority");

        let state = DaemonState::open(init.layout).unwrap();
        // Drift the checkout and destroy the derived ingestion cache. Neither
        // may answer, and neither may repair, a graph-owned source read.
        std::fs::create_dir_all(repo_dir.path().join("src")).unwrap();
        std::fs::write(
            repo_dir.path().join("src/lib.rs"),
            b"pub fn unadmitted_checkout_drift() {}\n",
        )
        .unwrap();
        std::fs::remove_file(local_object_path(&state.layout, hash)).unwrap();

        assert_eq!(
            state
                .graph_owned_source_view()
                .unwrap()
                .load_text(&FilePathId::new("src/lib.rs"))
                .unwrap(),
            std::str::from_utf8(authority_bytes).unwrap()
        );
    }

    #[test]
    fn lsp_source_text_refuses_a_path_absent_from_graph_authority() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = DaemonState::open(init.layout).unwrap();
        // A file that exists only in the checkout has no graph-owned tree
        // entry, so enrichment must fail loudly instead of reading it.
        std::fs::create_dir_all(repo_dir.path().join("src")).unwrap();
        std::fs::write(
            repo_dir.path().join("src/lib.rs"),
            b"pub fn never_admitted() {}\n",
        )
        .unwrap();

        let error = state
            .graph_owned_source_view()
            .unwrap()
            .load_text(&FilePathId::new("src/lib.rs"))
            .expect_err("an unadmitted checkout file must not become LSP source authority");
        assert!(
            error.to_string().contains("no graph-owned tree entry"),
            "unexpected graph-miss error: {error}"
        );
    }

    #[test]
    fn local_exact_source_preflight_accepts_verified_cas_bytes() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());
        let bytes = b"verified local source\n";
        let blob_hash = state.blobs.write(bytes).unwrap();
        let hash = Hash256::from_bytes(blob_hash.0);
        let change = exact_source_change("src/lib.rs", TreeEntry::blob(hash, false));

        state
            .preflight_exact_source_change(&state.graph, &change)
            .expect("verified local CAS bytes must satisfy exact-source preflight");
    }

    #[test]
    fn local_exact_source_preflight_rejects_missing_and_corrupt_bytes_without_mutation() {
        for corrupt in [false, true] {
            let repo_dir = tempfile::tempdir().unwrap();
            let init = kin_core::init(repo_dir.path()).unwrap();
            let state = test_state(init.layout, repo_dir.path());
            let expected = b"expected local source\n";
            let hash = if corrupt {
                let blob_hash = state.blobs.write(expected).unwrap();
                let hash = Hash256::from_bytes(blob_hash.0);
                std::fs::write(local_object_path(&state.layout, hash), b"corrupt bytes").unwrap();
                hash
            } else {
                Hash256::from_bytes(kin_blobs::digest_bytes(expected))
            };
            let change = exact_source_change("src/lib.rs", TreeEntry::blob(hash, false));
            let root_before = state.graph.compute_root_hash();
            let generation_before = state.snapshot_generation.load(Ordering::SeqCst);

            let error = state
                .preflight_exact_source_change(&state.graph, &change)
                .expect_err("unavailable local CAS authority must fail closed");

            assert!(error.to_string().contains("absent or corrupt"));
            assert!(state.graph.get_change(&change.id).unwrap().is_none());
            assert_eq!(state.graph.compute_root_hash(), root_before);
            assert_eq!(
                state.snapshot_generation.load(Ordering::SeqCst),
                generation_before
            );
        }
    }

    #[test]
    fn local_exact_source_preflight_rejects_unmaterializable_path_and_symlink() {
        let cases = [
            (
                ".kin/authority",
                false,
                b"must not enter control state".as_slice(),
            ),
            ("src/escape", true, b"../../outside".as_slice()),
        ];

        for (file_id, symlink, bytes) in cases {
            let repo_dir = tempfile::tempdir().unwrap();
            let init = kin_core::init(repo_dir.path()).unwrap();
            let state = test_state(init.layout, repo_dir.path());
            let blob_hash = state.blobs.write(bytes).unwrap();
            let change = exact_source_change(
                file_id,
                if symlink {
                    TreeEntry::symlink(Hash256::from_bytes(blob_hash.0))
                } else {
                    TreeEntry::blob(Hash256::from_bytes(blob_hash.0), false)
                },
            );
            let root_before = state.graph.compute_root_hash();
            let generation_before = state.snapshot_generation.load(Ordering::SeqCst);

            let error = state
                .preflight_exact_source_change(&state.graph, &change)
                .expect_err("unsafe exact-source entries must fail before graph mutation");

            assert!(error.to_string().contains("not materializable"));
            assert!(state.graph.get_change(&change.id).unwrap().is_none());
            assert_eq!(state.graph.compute_root_hash(), root_before);
            assert_eq!(
                state.snapshot_generation.load(Ordering::SeqCst),
                generation_before
            );
        }
    }

    #[test]
    fn local_exact_source_preflight_rejects_file_directory_collision() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());
        let file_hash = Hash256::from_bytes(state.blobs.write(b"file bytes").unwrap().0);
        let child_hash = Hash256::from_bytes(state.blobs.write(b"child bytes").unwrap().0);
        let mut change = exact_source_change("pkg", TreeEntry::blob(file_hash, false));
        change.tree_deltas.push(TreeDelta::Added {
            artifact_id: ArtifactId::new(),
            new: LocatedEntry::new(
                RepoPath::from_utf8("pkg/lib.rs").unwrap(),
                TreeEntry::blob(child_hash, false),
            ),
        });
        change.id = kin_core::compute_semantic_change_id(&change).unwrap();
        let root_before = state.graph.compute_root_hash();
        let generation_before = state.snapshot_generation.load(Ordering::SeqCst);

        let error = state
            .preflight_exact_source_change(&state.graph, &change)
            .expect_err("a file and its descendant cannot form one materializable tree");

        assert!(error.to_string().contains("not materializable"));
        assert!(state.graph.get_change(&change.id).unwrap().is_none());
        assert_eq!(state.graph.compute_root_hash(), root_before);
        assert_eq!(
            state.snapshot_generation.load(Ordering::SeqCst),
            generation_before
        );
    }

    #[test]
    fn local_exact_source_preflight_rejects_parent_delta_tree_collision() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());
        let child_hash = Hash256::from_bytes(state.blobs.write(b"parent child bytes").unwrap().0);
        let parent = exact_source_change("pkg/lib.rs", TreeEntry::blob(child_hash, false));
        state.graph.create_change(&parent).unwrap();

        let file_hash = Hash256::from_bytes(state.blobs.write(b"incoming file bytes").unwrap().0);
        let mut incoming = exact_source_change("pkg", TreeEntry::blob(file_hash, false));
        incoming.parents = vec![parent.id];
        incoming.id = kin_core::compute_semantic_change_id(&incoming).unwrap();
        let root_before = state.graph.compute_root_hash();

        let error = state
            .preflight_exact_source_change(&state.graph, &incoming)
            .expect_err("the complete parent plus delta tree must be materializable");

        assert!(error.to_string().contains("not materializable"));
        assert!(state.graph.get_change(&incoming.id).unwrap().is_none());
        assert_eq!(state.graph.compute_root_hash(), root_before);
    }

    #[test]
    fn local_exact_source_preflight_uses_explicit_first_parent_merge_tree() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());
        let child_hash = Hash256::from_bytes(state.blobs.write(b"left child bytes").unwrap().0);
        let left = exact_source_change("pkg/lib.rs", TreeEntry::blob(child_hash, false));
        let file_hash = Hash256::from_bytes(state.blobs.write(b"right file bytes").unwrap().0);
        let right = exact_source_change("pkg", TreeEntry::blob(file_hash, false));
        state.graph.create_change(&left).unwrap();
        state.graph.create_change(&right).unwrap();

        let mut merge = exact_source_change(
            "merge-marker.txt",
            TreeEntry::blob(
                Hash256::from_bytes(state.blobs.write(b"merge marker").unwrap().0),
                false,
            ),
        );
        merge.parents = vec![left.id, right.id];
        merge.id = kin_core::compute_semantic_change_id(&merge).unwrap();
        let root_before = state.graph.compute_root_hash();

        state
            .preflight_exact_source_change(&state.graph, &merge)
            .expect("the explicit first-parent merge result is the exact repository tree");

        assert!(state.graph.get_change(&merge.id).unwrap().is_none());
        assert_eq!(state.graph.compute_root_hash(), root_before);
    }

    #[test]
    fn backend_acknowledgement_preserves_mutation_arriving_during_delta_io() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let storage = tempfile::tempdir().unwrap();
        let repo_id = "concurrent-delta-ack";
        let reached_backend = Arc::new(std::sync::Barrier::new(2));
        let resume_backend = Arc::new(std::sync::Barrier::new(2));

        let state = Arc::new(
            DaemonState::open_with_backend(
                layout.clone(),
                Box::new(CleanupFailOnceBackend::blocking_delta(
                    storage.path(),
                    Arc::clone(&reached_backend),
                    Arc::clone(&resume_backend),
                )),
                repo_id,
                None,
            )
            .unwrap(),
        );
        state
            .graph
            .upsert_entity(&test_entity("base_entity", "src/base.rs"))
            .unwrap();
        state.mark_dirty();
        state.save_snapshot().expect("persist full base");
        state.mark_clean();
        assert!(!state.is_dirty());

        state
            .graph
            .upsert_entity(&test_entity("first_delta", "src/first.rs"))
            .unwrap();
        state.mark_dirty();
        let save_state = Arc::clone(&state);
        let save_thread = std::thread::spawn(move || save_state.save_snapshot());
        reached_backend.wait();

        // This mutation lands after the first delta was detached but before its
        // backend authority commit. Acknowledging the first batch must not clear
        // this second mutation.
        state
            .graph
            .upsert_entity(&test_entity("during_io", "src/during.rs"))
            .unwrap();
        state.mark_dirty();
        resume_backend.wait();
        save_thread.join().unwrap().expect("persist first delta");
        // Production callers mark clean after a successful save. The later
        // mutation must keep the background persistence wakeup armed.
        state.mark_clean();
        assert!(state.is_dirty());
        assert_eq!(state.snapshot_generation.load(Ordering::SeqCst), 2);

        state
            .save_snapshot()
            .expect("later mutation must remain pending for the next delta");
        state.mark_clean();
        assert!(!state.is_dirty());
        assert_eq!(state.snapshot_generation.load(Ordering::SeqCst), 3);
        drop(state);

        let reopened = DaemonState::open_with_backend(
            layout,
            Box::new(kin_db::LocalFileBackend::new(storage.path())),
            repo_id,
            None,
        )
        .expect("both detached batches must reopen exactly");
        let names: HashSet<_> = reopened
            .graph
            .list_all_entities()
            .unwrap()
            .into_iter()
            .map(|entity| entity.name)
            .collect();
        assert_eq!(reopened.snapshot_generation.load(Ordering::SeqCst), 3);
        assert_eq!(names.len(), 3);
        assert!(names.contains("base_entity"));
        assert!(names.contains("first_delta"));
        assert!(names.contains("during_io"));
    }

    #[test]
    fn post_commit_finalization_retries_without_recommitting_graph() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let storage = tempfile::tempdir().unwrap();
        let repo_id = "finalization-retry";
        let state = DaemonState::open_with_backend(
            layout.clone(),
            Box::new(kin_db::LocalFileBackend::new(storage.path())),
            repo_id,
            None,
        )
        .unwrap();

        state
            .graph
            .upsert_entity(&test_entity("committed", "src/committed.rs"))
            .unwrap();
        state.finalization_fail_once.store(true, Ordering::SeqCst);
        let error = state
            .save_snapshot()
            .expect_err("injected local finalization must surface after commit");
        assert!(error
            .to_string()
            .contains("injected post-commit finalization failure"));
        assert_eq!(state.snapshot_generation.load(Ordering::SeqCst), 1);
        assert_eq!(DaemonState::read_generation_marker(&layout), 0);
        assert!(state
            .post_commit_finalization_pending
            .load(Ordering::SeqCst));

        let idx_path = layout.kindb_snapshot_path().with_extension("kidx");
        assert_eq!(kin_db::ReadIndex::load(&idx_path).unwrap().entity_count, 0);
        state
            .save_snapshot()
            .expect("no-op save must retry local finalization");
        assert_eq!(state.snapshot_generation.load(Ordering::SeqCst), 1);
        assert_eq!(DaemonState::read_generation_marker(&layout), 1);
        assert!(!state
            .post_commit_finalization_pending
            .load(Ordering::SeqCst));
        assert_eq!(kin_db::ReadIndex::load(&idx_path).unwrap().entity_count, 1);
    }

    #[test]
    fn backend_reopen_heals_stale_generation_marker_and_read_index() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let storage = tempfile::tempdir().unwrap();
        let repo_id = "marker-heal";

        let state = DaemonState::open_with_backend(
            layout.clone(),
            Box::new(kin_db::LocalFileBackend::new(storage.path())),
            repo_id,
            None,
        )
        .unwrap();
        state
            .graph
            .upsert_entity(&test_entity("persisted", "src/persisted.rs"))
            .unwrap();
        state.save_snapshot().unwrap();
        drop(state);

        let marker = layout.kindb_head_generation_path();
        std::fs::write(&marker, "0").unwrap();
        let idx_path = layout.kindb_snapshot_path().with_extension("kidx");
        std::fs::remove_file(&idx_path).unwrap();

        let reopened = DaemonState::open_with_backend(
            layout.clone(),
            Box::new(kin_db::LocalFileBackend::new(storage.path())),
            repo_id,
            None,
        )
        .expect("reopen must heal artifacts from durable authority");
        assert_eq!(reopened.snapshot_generation.load(Ordering::SeqCst), 1);
        assert_eq!(DaemonState::read_generation_marker(&layout), 1);
        assert_eq!(kin_db::ReadIndex::load(&idx_path).unwrap().entity_count, 1);
    }

    /// The reuse predicate must answer from evidence that only a completed
    /// publication can produce. Each arm here is a crash point of
    /// `finalize_generation_from_graph`, and every one of them must decline.
    #[test]
    fn durable_read_index_is_current_only_when_marker_and_index_agree() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;

        let state = DaemonState::open(layout.clone()).expect("an initialized repo must open");
        let generation = state.snapshot_generation.load(Ordering::SeqCst);
        assert!(
            generation > 0,
            "the reuse branch only runs for a persisted generation; this fixture must have one"
        );
        drop(state);

        let index_path = layout.kindb_snapshot_path().with_extension("kidx");
        assert!(
            index_path.is_file(),
            "the first open must publish a read index"
        );
        assert!(
            DaemonState::durable_read_index_matches_generation(&layout, generation),
            "a marker and index published together must be reusable"
        );
        assert!(
            !DaemonState::durable_read_index_matches_generation(&layout, generation + 1),
            "a marker naming another generation is not evidence about this one"
        );

        // The crash window between publishing the marker and promoting the
        // staged index leaves the marker current and no index behind it.
        std::fs::remove_file(&index_path).unwrap();
        assert!(
            !DaemonState::durable_read_index_matches_generation(&layout, generation),
            "a missing index must never be reported as current"
        );
    }

    /// Two-sided: a reopen whose derived index is already current must not
    /// rewrite it, and a reopen whose index is gone must rebuild it. Both must
    /// serve the same graph, because reuse is only sound if it is invisible.
    #[test]
    fn reopen_reuses_a_current_read_index_and_rebuilds_a_missing_one() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let blobs = BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let body = b"pub fn reused() {}\n";
        let body_hash = Hash256::from_bytes(blobs.write(body).unwrap().0);
        let desired = ResolvedTree::from_artifacts(vec![ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8("src/reused.rs").unwrap(),
            TreeEntry::blob(body_hash, false),
        )])
        .unwrap();
        let context =
            crate::local_repository_authority::LocalRepositoryAuthorityContext::from_layout_for_test(
                &init.layout,
            )
            .unwrap();
        let admitted = crate::repository_commit::admitted_workspace_tree_for_test(
            init.layout.working_dir(),
            context.open().unwrap().read_authority().roots().clone(),
            ResolvedTree::default(),
            desired,
        );
        crate::repository_commit::publish_workspace_tree(
            &blobs,
            &context,
            &admitted,
            kin_model::OperationId::new(),
            kin_model::AuthorId::new("read-index-reuse-test"),
        )
        .unwrap()
        .expect("exact workspace admission must advance authority");

        let layout = init.layout;
        let first = DaemonState::open(layout.clone()).expect("an admitted repo must open");
        let generation = first.snapshot_generation.load(Ordering::SeqCst);
        let entity_count = first.graph.entity_count();
        let artifact_count = first.graph.resolved_tree().len();
        assert!(
            generation > 0,
            "the fixture must carry a persisted generation"
        );
        assert!(
            artifact_count > 0,
            "the fixture must carry admitted graph content"
        );
        drop(first);

        let index_path = layout.kindb_snapshot_path().with_extension("kidx");
        let published = std::fs::metadata(&index_path).unwrap().modified().unwrap();

        let reopened = DaemonState::open(layout.clone()).expect("reopen must succeed");
        assert_eq!(
            reopened.snapshot_generation.load(Ordering::SeqCst),
            generation
        );
        assert_eq!(
            reopened.graph.resolved_tree().len(),
            artifact_count,
            "reusing the index must not change what the daemon serves"
        );
        assert_eq!(reopened.graph.entity_count(), entity_count);
        assert_eq!(DaemonState::read_generation_marker(&layout), generation);
        assert_eq!(
            std::fs::metadata(&index_path).unwrap().modified().unwrap(),
            published,
            "a read index already describing this generation must be reused, not rewritten"
        );
        drop(reopened);

        std::fs::remove_file(&index_path).unwrap();
        let healed =
            DaemonState::open(layout.clone()).expect("reopen must heal a missing read index");
        assert_eq!(
            healed.graph.resolved_tree().len(),
            artifact_count,
            "a cold restart must load the same graph"
        );
        assert_eq!(
            kin_db::ReadIndex::load(&index_path).unwrap().entity_count as usize,
            healed.graph.entity_count(),
            "the rebuilt index must describe the loaded graph"
        );
    }

    #[test]
    fn backend_startup_reuses_the_single_recovered_graph() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let storage = tempfile::tempdir().unwrap();
        let repo_id = "single-startup-load";

        let seeded_graph = kin_db::InMemoryGraph::new();
        seeded_graph
            .upsert_entity(&test_entity("loaded_once", "src/loaded.rs"))
            .unwrap();
        let seed_backend = kin_db::LocalFileBackend::new(storage.path());
        seed_backend
            .save_snapshot(
                repo_id,
                &seeded_graph.to_snapshot().to_bytes().unwrap(),
                kin_db::GENERATION_INIT,
            )
            .unwrap();

        let recovery_loads = Arc::new(AtomicU64::new(0));
        let state = DaemonState::open_with_backend(
            layout.clone(),
            Box::new(CleanupFailOnceBackend::counting_load(
                storage.path(),
                Arc::clone(&recovery_loads),
            )),
            repo_id,
            None,
        )
        .expect("startup must finalize from the graph it already recovered");

        assert_eq!(recovery_loads.load(Ordering::SeqCst), 1);
        assert_eq!(state.graph.entity_count(), 1);
        assert_eq!(DaemonState::read_generation_marker(&layout), 1);
        assert_eq!(
            kin_db::ReadIndex::load(&layout.kindb_snapshot_path().with_extension("kidx"))
                .unwrap()
                .entity_count,
            1
        );
    }

    #[test]
    fn local_derived_save_never_creates_a_second_graph_authority() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let state = DaemonState::open(layout.clone()).unwrap();
        let repository_generation = state.snapshot_generation.load(Ordering::SeqCst);

        state
            .graph
            .upsert_entity(&test_entity("derived_only", "src/derived.rs"))
            .unwrap();
        state.save_snapshot().unwrap();

        assert_eq!(
            state.snapshot_generation.load(Ordering::SeqCst),
            repository_generation
        );
        assert!(!state.graph.has_unpersisted_changes());
        assert!(
            !layout.kindb_snapshot_path().exists(),
            "local derived persistence must never recreate graph.kndb authority"
        );
        assert_eq!(
            RepositoryAuthorityManager::open(
                init.repository_id,
                Arc::new(LocalFileBackend::new(layout.kindb_dir())),
            )
            .unwrap()
            .read_authority()
            .roots()
            .generation,
            repository_generation
        );
    }

    #[test]
    fn local_derived_save_rejects_an_unadmitted_exact_tree() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let state = DaemonState::open(layout.clone()).unwrap();
        let body_hash = Hash256::from_bytes(state.blobs.write(b"services: {}\n").unwrap().0);
        state
            .graph
            .apply_transaction_delta(&kin_model::TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: ArtifactId::new(),
                    new: LocatedEntry::new(
                        RepoPath::from_utf8("compose.yaml").unwrap(),
                        TreeEntry::blob(body_hash, false),
                    ),
                }],
                ..kin_model::TransactionDelta::default()
            })
            .unwrap();

        let error = state
            .save_snapshot()
            .expect_err("derived persistence cannot admit file truth implicitly");
        assert!(error
            .to_string()
            .contains("live exact tree does not match workspace authority"));
        assert!(state.graph.has_unpersisted_changes());
        assert!(!layout.kindb_snapshot_path().exists());
    }

    #[test]
    fn local_repository_receipt_finalizes_without_graph_kndb() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let state = DaemonState::open(layout.clone()).unwrap();
        let body_hash = Hash256::from_bytes(state.blobs.write(b"services: {}\n").unwrap().0);
        let artifact = ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8("compose.yaml").unwrap(),
            TreeEntry::blob(body_hash, false),
        );
        let desired = ResolvedTree::from_artifacts([artifact.clone()]).unwrap();
        let context =
            crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(&state)
                .unwrap();
        let admitted = crate::repository_commit::admitted_workspace_tree_for_test(
            layout.working_dir(),
            context.open().unwrap().read_authority().roots().clone(),
            state.graph.resolved_tree(),
            desired.clone(),
        );
        let admission = crate::repository_commit::publish_workspace_tree(
            state.blobs.as_ref(),
            &context,
            &admitted,
            kin_model::OperationId::new(),
            kin_model::AuthorId::new("dogfood"),
        )
        .unwrap()
        .unwrap();
        state
            .record_repository_authority_commit(admission.receipt.generation)
            .unwrap();
        state
            .graph
            .apply_transaction_delta(&kin_model::TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: artifact.artifact_id,
                    new: artifact.located_entry(),
                }],
                ..kin_model::TransactionDelta::default()
            })
            .unwrap();
        state.save_snapshot().unwrap();

        assert_eq!(
            state.snapshot_generation.load(Ordering::SeqCst),
            admission.receipt.generation
        );
        assert_eq!(
            DaemonState::read_generation_marker(&layout),
            admission.receipt.generation
        );
        assert!(!layout.kindb_snapshot_path().exists());
        drop(state);

        let reopened = DaemonState::open(layout).unwrap();
        assert_eq!(reopened.graph.resolved_tree(), desired);
        assert_eq!(
            reopened.snapshot_generation.load(Ordering::SeqCst),
            admission.receipt.generation
        );
    }

    #[test]
    fn committed_full_snapshot_cleanup_failure_does_not_wedge_next_cas() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let storage = tempfile::tempdir().unwrap();
        let repo_id = "cleanup-retry";

        let state = DaemonState::open_with_backend(
            layout.clone(),
            Box::new(CleanupFailOnceBackend::new(storage.path(), true)),
            repo_id,
            None,
        )
        .unwrap();
        state
            .graph
            .upsert_entity(&test_entity("base_entity", "src/base.rs"))
            .unwrap();
        state
            .save_snapshot()
            .expect("committed snapshot survives cleanup failure");
        assert_eq!(state.snapshot_generation.load(Ordering::SeqCst), 1);

        state
            .graph
            .upsert_entity(&test_entity("next_entity", "src/next.rs"))
            .unwrap();
        state
            .save_snapshot()
            .expect("next delta CAS uses committed generation, not stale cursor");
        assert_eq!(state.snapshot_generation.load(Ordering::SeqCst), 2);
        drop(state);

        let reopened = DaemonState::open_with_backend(
            layout,
            Box::new(CleanupFailOnceBackend::new(storage.path(), false)),
            repo_id,
            None,
        )
        .expect("snapshot plus next delta reopens after cleanup failure");
        assert_eq!(reopened.snapshot_generation.load(Ordering::SeqCst), 2);
        assert_eq!(reopened.graph.entity_count(), 2);
    }

    fn make_scoped_graph_with_entity(name: &str, file_path: &str) -> Arc<kin_db::InMemoryGraph> {
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        graph.upsert_entity(&test_entity(name, file_path)).unwrap();
        graph
    }

    #[tokio::test]
    async fn graph_for_request_returns_head_when_session_is_none() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        let resolved = state.graph_for_request(None).await;
        assert!(Arc::ptr_eq(&resolved, &state.graph));
    }

    #[tokio::test]
    async fn graph_for_request_returns_head_when_session_has_no_scope() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        let session_id = kin_model::SessionId::new();
        let resolved = state.graph_for_request(Some(&session_id)).await;
        assert!(Arc::ptr_eq(&resolved, &state.graph));
    }

    #[tokio::test]
    async fn graph_for_request_returns_scoped_graph_when_session_has_active_scope() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        // Plant a different entity in HEAD vs. the scoped historical graph
        // so we can detect which graph routing returned.
        state
            .graph
            .upsert_entity(&test_entity("head_only_fn", "src/head.rs"))
            .unwrap();
        let scoped_graph = make_scoped_graph_with_entity("historical_fn", "src/old.rs");

        let session_id = kin_model::SessionId::new();
        let head = kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([7; 32]));
        state
            .set_session_scope(
                &session_id,
                "git:abc123".to_string(),
                head,
                Arc::clone(&scoped_graph),
            )
            .await;

        let resolved = state.graph_for_request(Some(&session_id)).await;
        // Routed graph must be the scoped one, not HEAD.
        assert!(Arc::ptr_eq(&resolved, &scoped_graph));
        assert!(!Arc::ptr_eq(&resolved, &state.graph));

        // And the routed graph must see historical entities and NOT HEAD-only ones.
        let entities = resolved.list_all_entities().unwrap();
        assert!(
            entities.iter().any(|e| e.name == "historical_fn"),
            "scoped graph should expose historical entity"
        );
        assert!(
            entities.iter().all(|e| e.name != "head_only_fn"),
            "scoped graph must not leak HEAD-only entity"
        );
    }

    #[tokio::test]
    async fn graph_for_request_falls_back_to_head_after_scope_cleared() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        let scoped_graph = make_scoped_graph_with_entity("historical_fn", "src/old.rs");
        let session_id = kin_model::SessionId::new();
        let head = kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([9; 32]));
        state
            .set_session_scope(
                &session_id,
                "git:def456".to_string(),
                head,
                Arc::clone(&scoped_graph),
            )
            .await;
        state.clear_session_scope(&session_id).await;

        let resolved = state.graph_for_request(Some(&session_id)).await;
        assert!(Arc::ptr_eq(&resolved, &state.graph));
    }

    #[tokio::test]
    async fn touch_activity_resets_idle_clock() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        // `last_activity_ms` is seeded to 0, so before any activity the idle
        // clock counts from `started_at`. Let real time pass, then confirm the
        // idle duration has grown.
        assert_eq!(
            state.last_activity_ms.load(Ordering::SeqCst),
            0,
            "the activity marker must start unset so the idle clock counts from startup"
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
        let before = state.idle_duration();
        assert!(
            before >= Duration::from_millis(20),
            "idle clock should count from startup until first activity, got {before:?}"
        );

        // The idle monitor calls touch_activity() when it starts so the idle
        // window begins from readiness, not process construction.
        state.touch_activity();
        let credited_ms = state.last_activity_ms.load(Ordering::SeqCst);
        assert!(
            credited_ms >= 20,
            "touch_activity must stamp the marker with the uptime it observed, got {credited_ms}ms"
        );
        let after = state.idle_duration();
        assert!(
            after + Duration::from_millis(credited_ms) <= state.started_at.elapsed(),
            "idle_duration must count from the activity marker, not from startup: after={after:?} credited={credited_ms}ms"
        );
    }

    #[tokio::test]
    async fn scoped_graph_for_write_returns_none_without_scope() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        let session_id = kin_model::SessionId::new();
        // No scope was ever opened for this session: a write must NOT silently
        // fall back to the shared HEAD graph.
        assert!(state.scoped_graph_for_write(&session_id).await.is_none());
    }

    #[tokio::test]
    async fn scoped_graph_for_write_returns_private_scope_not_head() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        state
            .graph
            .upsert_entity(&test_entity("head_only_fn", "src/head.rs"))
            .unwrap();
        let scoped_graph = make_scoped_graph_with_entity("scoped_fn", "src/scoped.rs");

        let session_id = kin_model::SessionId::new();
        let head = kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([3; 32]));
        state
            .set_session_scope(
                &session_id,
                "git:abc123".to_string(),
                head,
                Arc::clone(&scoped_graph),
            )
            .await;

        let resolved = state
            .scoped_graph_for_write(&session_id)
            .await
            .expect("live scope should yield a write graph");
        // Must be the session's private scoped graph, never the shared HEAD.
        assert!(Arc::ptr_eq(&resolved, &scoped_graph));
        assert!(!Arc::ptr_eq(&resolved, &state.graph));
    }

    #[tokio::test]
    async fn scoped_graph_for_write_returns_none_when_scope_expired() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        let scoped_graph = make_scoped_graph_with_entity("scoped_fn", "src/scoped.rs");
        let session_id = kin_model::SessionId::new();
        let head = kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([4; 32]));
        {
            let mut scopes = state.session_scopes.write().await;
            scopes.insert(
                session_id,
                TemporalScope {
                    ref_string: "git:abc123".to_string(),
                    head,
                    cached_graph: Arc::clone(&scoped_graph),
                    // Already expired: created in the past with a zero TTL.
                    created_at: Instant::now() - Duration::from_secs(60),
                    ttl: Duration::from_secs(0),
                },
            );
        }

        // An expired scope is not a live scope; a write must not fall through
        // to HEAD just because a stale entry lingers in the map.
        assert!(state.scoped_graph_for_write(&session_id).await.is_none());
    }

    #[tokio::test]
    async fn scoped_graph_for_write_refreshes_ttl() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        let scoped_graph = make_scoped_graph_with_entity("scoped_fn", "src/scoped.rs");
        let session_id = kin_model::SessionId::new();
        let head = kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([5; 32]));
        // Plant a live scope whose original expiry is well clear of ordinary
        // test and coverage-instrumentation latency. The refresh contract is
        // proven from the timestamps themselves instead of racing a tiny TTL.
        let ttl = Duration::from_secs(60 * 60);
        let original_created_at = Instant::now() - Duration::from_secs(60);
        let original_expires_at = original_created_at + ttl;
        {
            let mut scopes = state.session_scopes.write().await;
            scopes.insert(
                session_id,
                TemporalScope {
                    ref_string: "git:abc123".to_string(),
                    head,
                    cached_graph: Arc::clone(&scoped_graph),
                    created_at: original_created_at,
                    ttl,
                },
            );
        }

        // The write must return the private graph and reset created_at during
        // this call, which moves the absolute expiry beyond its old deadline.
        let before_refresh = Instant::now();
        let resolved = state
            .scoped_graph_for_write(&session_id)
            .await
            .expect("live scope should yield a write graph");
        let after_refresh = Instant::now();
        assert!(Arc::ptr_eq(&resolved, &scoped_graph));

        let (refreshed_created_at, refreshed_ttl) = {
            let scopes = state.session_scopes.read().await;
            let scope = scopes
                .get(&session_id)
                .expect("write refresh must retain the live scope");
            (scope.created_at, scope.ttl)
        };
        assert!(
            (before_refresh..=after_refresh).contains(&refreshed_created_at),
            "write must reset created_at inside the call boundary: before={before_refresh:?} refreshed={refreshed_created_at:?} after={after_refresh:?}"
        );
        assert_eq!(refreshed_ttl, ttl, "refresh must preserve the scope TTL");
        assert!(
            refreshed_created_at + refreshed_ttl > original_expires_at,
            "write must slide the scope's expiry beyond its original deadline"
        );
    }

    #[test]
    fn persist_lock_serializes_concurrent_saves() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = Arc::new(test_state(init.layout, repo_dir.path()));
        state
            .graph
            .upsert_entity(&test_entity("locked_fn", "src/lib.rs"))
            .unwrap();

        // Hold the persist lock to mimic an in-flight save, then launch a
        // second save on another thread. It must NOT complete until we release
        // the guard — proving the two saves can never interleave.
        let guard = state.persist_lock.lock().unwrap();
        let completed = Arc::new(AtomicBool::new(false));

        let saver_state = Arc::clone(&state);
        let saver_completed = Arc::clone(&completed);
        let handle = std::thread::spawn(move || {
            saver_state.save_snapshot().unwrap();
            saver_completed.store(true, Ordering::SeqCst);
        });

        // Give the spawned save ample time to run if it were NOT blocked.
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            !completed.load(Ordering::SeqCst),
            "save_snapshot must block while the persist lock is held"
        );

        // Release the lock; the blocked save now proceeds to completion.
        drop(guard);
        handle.join().unwrap();
        assert!(
            completed.load(Ordering::SeqCst),
            "save_snapshot must complete once the persist lock is released"
        );
    }

    #[test]
    fn locate_only_finalization_invalidates_canonical_index_before_head_marker() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let index_path = layout.kindb_snapshot_path().with_extension("kidx");
        std::fs::write(&index_path, b"stale canonical index").unwrap();
        let state = test_state(layout.clone(), repo_dir.path());

        state.finalize_loaded_locate_generation(7).unwrap();

        assert!(
            !index_path.exists(),
            "a partial locate graph must never replace or retain a canonical full read index"
        );
        assert_eq!(DaemonState::read_generation_marker(&layout), 7);
    }

    #[test]
    fn graph_collapse_is_wipe_threshold() {
        // Below the min baseline: never a wipe, even at total collapse.
        assert!(!graph_collapse_is_wipe(0, WIPE_GUARD_MIN_BASELINE - 1));
        // At/above baseline with a >75% collapse → wipe.
        assert!(graph_collapse_is_wipe(0, 1000)); // total wipe
        assert!(graph_collapse_is_wipe(100, 1000)); // 90% gone
        assert!(graph_collapse_is_wipe(249, 1000)); // just over 75% gone (249*4=996<1000)
                                                    // Exactly a quarter remaining is NOT a wipe (250*4=1000, not < 1000).
        assert!(!graph_collapse_is_wipe(250, 1000));
        // Growth or steady state is never a wipe.
        assert!(!graph_collapse_is_wipe(1000, 1000));
        assert!(!graph_collapse_is_wipe(2000, 1000));
    }

    #[tokio::test]
    async fn shutdown_wipe_guard_blocks_drastic_graph_collapse() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        // Populate a non-trivial graph and record it as the persisted baseline.
        for i in 0..20 {
            state
                .graph
                .upsert_entity(&test_entity(&format!("fn_{i}"), &format!("src/f{i}.rs")))
                .unwrap();
        }
        let n = state.graph.entity_count() as u64;
        assert!(
            n >= WIPE_GUARD_MIN_BASELINE,
            "test needs a non-trivial graph (got {n})"
        );
        state.record_persisted_entity_count();
        assert_eq!(state.persisted_entity_count.load(Ordering::SeqCst), n);

        // current == baseline → no collapse, flush allowed.
        assert!(!state.shutdown_flush_would_wipe_graph());

        // A much larger prior on-disk snapshot vs the live graph (>75% collapse)
        // → guard fires and the flush is skipped.
        state.persisted_entity_count.store(n * 5, Ordering::SeqCst);
        assert!(state.shutdown_flush_would_wipe_graph());

        // A moderate drop (50%) is a legitimate edit, NOT a wipe.
        state.persisted_entity_count.store(n * 2, Ordering::SeqCst);
        assert!(!state.shutdown_flush_would_wipe_graph());
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn flush_embed_progress_persists_only_vector_sidecar_and_reports_pending() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = Arc::new(test_state(init.layout, repo_dir.path()));
        state
            .graph
            .upsert_entity(&test_entity("embed_me", "src/lib.rs"))
            .unwrap();
        let vector_path = state.layout.kindb_vector_index_path();
        let descriptor = kin_db::vector::IndexDescriptor {
            model_id: Some("fixture-embedder-v1".to_string()),
            graph_root: Some("fixture-root".to_string()),
        };
        let vectors = kin_db::VectorIndex::new(4).unwrap();
        vectors.set_descriptor(descriptor.clone());
        vectors.save(&vector_path).unwrap();
        assert!(matches!(
            state
                .graph
                .load_vector_index_compatible(&vector_path, &descriptor),
            kin_db::vector::VectorIndexLoad::Loaded(0)
        ));
        std::fs::remove_file(&vector_path).unwrap();
        state.graph.queue_missing_for_embedding();

        let pending = state.flush_embed_progress().expect("flush must succeed");
        assert!(
            !state.layout.kindb_snapshot_path().exists(),
            "vector progress must not recreate graph.kndb authority"
        );
        assert!(
            state.layout.kindb_vector_index_path().exists(),
            "flush must persist the derived vector sidecar"
        );
        assert!(
            pending >= 1,
            "the unembedded entity must remain pending (no embedder ran); got {pending}"
        );
    }

    /// The publish decision, on every shape the counters can take. A store that
    /// has not finished a fill must never claim it has, because that claim is
    /// what turns a fresh install's ordinary progress into a reported failure.
    #[test]
    fn only_whole_coverage_counts_as_a_finished_fill() {
        assert!(DaemonState::coverage_is_whole(41, 0, 41));
        assert!(
            !DaemonState::coverage_is_whole(0, 0, 0),
            "an empty store has not finished a fill it never started"
        );
        assert!(
            !DaemonState::coverage_is_whole(40, 1, 41),
            "work still queued is a fill in progress"
        );
        assert!(
            !DaemonState::coverage_is_whole(40, 0, 41),
            "an entity nothing is queued for is still an entity with no vector"
        );
    }

    /// The marker is the only thing separating a store filling for the first
    /// time from one that lost coverage it held, so it has to be withheld until
    /// a fill finishes and it has to outlive the daemon that published it.
    #[test]
    fn embedding_coverage_marker_is_withheld_until_a_fill_finishes_and_then_persists() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        state
            .graph
            .upsert_entity(&test_entity("embed_me", "src/lib.rs"))
            .unwrap();
        let status = state.graph.embedding_status();
        assert!(
            !DaemonState::coverage_is_whole(status.indexed, status.pending, status.total),
            "fixture precondition: this store must not be fully covered, got \
             {}/{} indexed, {} pending",
            status.indexed,
            status.total,
            status.pending
        );

        state.record_embedding_coverage_complete();
        assert!(
            !state.embedding_coverage_ever_complete(),
            "an unfinished fill must not publish the has-ever-completed marker"
        );

        DaemonState::write_embedding_coverage_marker(
            &state.layout.kindb_embedding_coverage_marker_path(),
        )
        .expect("publishing the marker must succeed on a local store");
        assert!(state.embedding_coverage_ever_complete());

        // Published into the store rather than held in memory, so the next
        // daemon to open this repository does not mistake it for a fresh one.
        let reopened_layout = kin_core::KinLayout::discover(repo_dir.path())
            .expect("the fixture store must be found");
        assert!(
            reopened_layout
                .kindb_embedding_coverage_marker_path()
                .exists(),
            "the claim must live in the store, not in the process that made it"
        );
    }

    /// The race the counter re-read loses. A pass drains its queue, and before
    /// the counters can be read back a working copy admits another file, so the
    /// re-read reports partial coverage and publishes nothing. The store then
    /// reports a first fill forever despite having finished one, which is what
    /// left the v0.5.18 install proof reading `pending` on a store whose embed
    /// had just reported no pending work at all.
    #[test]
    fn a_drained_pass_records_completion_even_when_new_work_already_arrived() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());

        state
            .graph
            .upsert_entity(&test_entity("arrived_after_the_pass", "src/late.rs"))
            .unwrap();
        let status = state.graph.embedding_status();
        assert!(
            !DaemonState::coverage_is_whole(status.indexed, status.pending, status.total),
            "fixture precondition: work arriving after the pass must already have made the \
             counters partial, got {}/{} indexed, {} pending",
            status.indexed,
            status.total,
            status.pending
        );

        state.record_embedding_coverage_complete();
        assert!(
            !state.embedding_coverage_ever_complete(),
            "fixture precondition: recording from a re-read of these counters publishes nothing, \
             which is the bug this fixture exists to hold still"
        );

        state.record_embedding_pass_drained();
        assert!(
            state.embedding_coverage_ever_complete(),
            "a pass that drained its own queue is the evidence a fill finished, and it cannot be \
             invalidated by a later write growing the corpus"
        );
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn storage_backend_embed_progress_fails_before_local_snapshot_write() {
        use kin_db::LocalFileBackend;

        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout;
        let snapshot_path = layout.kindb_snapshot_path();
        let storage = tempfile::tempdir().unwrap();
        let state = DaemonState::open_with_backend(
            layout,
            Box::new(LocalFileBackend::new(storage.path())),
            "remote-embed-authority",
            None,
        )
        .unwrap();
        state
            .graph
            .upsert_entity(&test_entity("embed_me", "src/lib.rs"))
            .unwrap();
        state
            .save_snapshot_full()
            .expect("seed remote authority at the local authority generation");
        state.graph.queue_missing_for_embedding();

        let vector_path = snapshot_path.with_extension("kvec");
        let vector_before = std::fs::read(&vector_path).ok();
        let generation_before = state.snapshot_generation.load(Ordering::SeqCst);
        let error = state
            .flush_embed_progress()
            .expect_err("remote authority must reject local embed checkpoints");
        let message = error.to_string();
        assert!(
            message.contains("storage-backend graph authority"),
            "{message}"
        );
        assert!(
            message.contains("refusing a local derived checkpoint"),
            "{message}"
        );
        assert_eq!(
            state.snapshot_generation.load(Ordering::SeqCst),
            generation_before
        );
        assert!(!snapshot_path.exists());
        assert_eq!(std::fs::read(vector_path).ok(), vector_before);
    }

    #[test]
    fn persisted_mcp_transactions_missing_file_loads_empty() {
        // A clean start (no mcp_transactions.json) yields an empty set,
        // never an error — startup must not fail on transaction recovery.
        let dir = tempfile::tempdir().unwrap();
        let layout = KinLayout::new(dir.path().to_path_buf());
        assert!(load_persisted_mcp_transactions(&layout).is_empty());
    }

    #[test]
    fn persisted_mcp_transactions_round_trip_through_disk() {
        // A staged transaction written to the durable mirror reloads
        // intact — the mechanism that lets begin/stage survive a daemon restart.
        let dir = tempfile::tempdir().unwrap();
        let layout = KinLayout::new(dir.path().to_path_buf());
        let mut store = HashMap::new();
        store.insert(
            "tx-1".to_string(),
            kin_mcp::McpTransaction {
                transaction_id: "tx-1".to_string(),
                session_id: "sess".to_string(),
                scope: "file:src/lib.rs".to_string(),
                state: "active".to_string(),
                staged_operations: Vec::new(),
                commit_payload_hash: None,
            },
        );
        write_persisted_mcp_transactions(&layout, &store);
        assert!(mcp_transactions_disk_path(&layout).exists());

        let restored = load_persisted_mcp_transactions(&layout);
        assert_eq!(restored.len(), 1);
        assert_eq!(
            restored.get("tx-1").map(|t| t.scope.as_str()),
            Some("file:src/lib.rs")
        );
    }

    #[test]
    fn persisted_mcp_transactions_corrupt_file_degrades_to_empty() {
        // A torn/corrupt mirror degrades to empty (logged loud, never a
        // startup crash) rather than poisoning daemon boot.
        let dir = tempfile::tempdir().unwrap();
        let layout = KinLayout::new(dir.path().to_path_buf());
        std::fs::write(mcp_transactions_disk_path(&layout), b"{not valid json").unwrap();
        assert!(load_persisted_mcp_transactions(&layout).is_empty());
    }

    /// Publish one blob as the repository's exact workspace tree and return its
    /// content address. The published body lives in repository authority, which
    /// is the only source an ingest-CAS hydration is allowed to read from.
    fn publish_single_blob_workspace(layout: &KinLayout, body: &[u8]) -> Hash256 {
        let blobs = BlobStore::new(layout.ingest_cas_dir()).unwrap();
        let hash = Hash256::from_bytes(blobs.write(body).unwrap().0);
        let desired = ResolvedTree::from_artifacts(vec![ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8("service.yaml").unwrap(),
            TreeEntry::blob(hash, false),
        )])
        .unwrap();
        let context =
            crate::local_repository_authority::LocalRepositoryAuthorityContext::from_layout_for_test(
                layout,
            )
            .unwrap();
        let admitted = crate::repository_commit::admitted_workspace_tree_for_test(
            layout.working_dir(),
            context.open().unwrap().read_authority().roots().clone(),
            ResolvedTree::default(),
            desired,
        );
        crate::repository_commit::publish_workspace_tree(
            &blobs,
            &context,
            &admitted,
            kin_model::OperationId::new(),
            kin_model::AuthorId::new("ingest-cas-hydration-test"),
        )
        .unwrap()
        .expect("exact workspace admission must advance authority");
        hash
    }

    #[test]
    fn backend_hydration_installs_every_body_the_graph_names() {
        // "Rehydrated on every daemon open" used to be true of the local path
        // only. The backend path reads the same derived store through
        // `rebuild_projection`, keyed on exactly this resolved tree, and used to
        // open against whatever happened to be on local disk.
        let repo_dir = tempfile::tempdir().unwrap();
        let body = b"services:\n  api:\n    image: kin:dev\n";
        let init = kin_core::init(repo_dir.path()).unwrap();
        let hash = publish_single_blob_workspace(&init.layout, body);

        let ingest_cas = init.layout.ingest_cas_dir();
        let kindb_dir = init.layout.kindb_dir();
        let repo_id = kin_core::manifest::resolve_repo_id(&init.layout, None).unwrap();
        // Take the graph a hosted snapshot of this repository would carry, then
        // release every local authority handle before hydrating through the
        // backend seam.
        let graph = {
            let local = DaemonState::open(init.layout).expect("local open");
            Arc::clone(&local.graph)
        };
        assert!(
            !graph.resolved_tree().is_empty(),
            "the fixture must carry the tree the projection would read"
        );

        std::fs::remove_dir_all(&ingest_cas).unwrap();
        let blobs = BlobStore::new(ingest_cas).unwrap();
        let backend: Arc<dyn StorageBackend> = Arc::new(LocalFileBackend::new(kindb_dir));

        let hydrated =
            DaemonState::hydrate_backend_ingest_cas(&repo_id, &backend, graph.as_ref(), &blobs)
                .expect("repository authority must supply every body the graph names");

        assert_eq!(hydrated, 1);
        assert_eq!(
            blobs.read(&hash).unwrap(),
            body,
            "hydration must install the exact repository-authority body"
        );
    }

    #[test]
    fn a_covered_cache_needs_no_authority_at_all() {
        // The hosted cost this closes: opening authority re-downloads the
        // repository snapshot and can replay the whole history, and the old
        // ordering fetched every body before consulting the cache, so a warm
        // instance paid the full price on every open. Point the backend at a
        // directory holding no authority whatsoever: hydration must still
        // succeed, which is only possible if it never opened one.
        let repo_dir = tempfile::tempdir().unwrap();
        let body = b"already cached\n";
        let init = kin_core::init(repo_dir.path()).unwrap();
        publish_single_blob_workspace(&init.layout, body);

        let repo_id = kin_core::manifest::resolve_repo_id(&init.layout, None).unwrap();
        let graph = {
            let local = DaemonState::open(init.layout).expect("local open");
            Arc::clone(&local.graph)
        };
        let cache_dir = tempfile::tempdir().unwrap();
        let blobs = BlobStore::new(cache_dir.path().to_path_buf()).unwrap();
        blobs.write(body).unwrap();

        let empty = tempfile::tempdir().unwrap();
        let backend: Arc<dyn StorageBackend> =
            Arc::new(LocalFileBackend::new(empty.path().to_path_buf()));

        assert_eq!(
            DaemonState::hydrate_backend_ingest_cas(&repo_id, &backend, graph.as_ref(), &blobs),
            Ok(0),
            "a cache that already covers the tree must not open repository authority"
        );
    }

    #[test]
    fn the_local_open_path_hydrates_the_ingest_cas() {
        let repo_dir = tempfile::tempdir().unwrap();
        let body = b"local authority body\n";
        let init = kin_core::init(repo_dir.path()).unwrap();
        let hash = publish_single_blob_workspace(&init.layout, body);
        std::fs::remove_dir_all(init.layout.ingest_cas_dir()).unwrap();

        let state = DaemonState::open(init.layout).expect("local open");

        assert_eq!(state.blobs.read(&hash).unwrap(), body);
        assert!(state.ingest_cas_hydration_gap.is_none());
    }

    #[test]
    fn an_empty_hosted_graph_needs_no_repository_authority() {
        // A graph with no resolved artifacts references no source bodies, so
        // there is nothing to hydrate and no authority to demand. This is the
        // ordinary first-boot hosted case and must not be reported as a gap.
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let kindb_dir = init.layout.kindb_dir();
        let repo_id = kin_core::manifest::resolve_repo_id(&init.layout, None).unwrap();

        let state = DaemonState::open_with_backend(
            init.layout,
            Box::new(LocalFileBackend::new(kindb_dir)),
            &repo_id,
            None,
        )
        .expect("backend open");

        assert!(
            state.ingest_cas_hydration_gap.is_none(),
            "an empty tree is not an authority gap: {:?}",
            state.ingest_cas_hydration_gap
        );
    }

    #[test]
    fn a_recorded_hydration_gap_is_named_in_projection_errors() {
        // A hosted graph whose backend carries no repository authority still
        // serves every query that needs no source body, so an un-hydratable
        // store is recorded rather than fatal. The reads that DO need one must
        // then report the authority gap instead of a bare missing blob, which
        // reads as graph corruption.
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let mut state = DaemonState::open(init.layout).expect("local open");
        state.ingest_cas_hydration_gap = Some("hosted backend carries no authority".to_string());

        let reported = state
            .attribute_ingest_cas_gap(exact_source_storage_error("cannot load graph-owned blob"))
            .to_string();
        assert!(
            reported.contains("never hydrated on this open path")
                && reported.contains("hosted backend carries no authority"),
            "the error must name the hydration gap: {reported}"
        );
    }

    /// Build a store carrying one entity and a persisted vector index, and
    /// stamp the sidecar with `producer` as its producing-artifact identity.
    ///
    /// The index is four synthetic dimensions written straight into a
    /// `VectorIndex`, so no embedding model is loaded and no inference runs.
    /// That is enough to exercise every gate a real index passes through on
    /// reopen, because those gates read the sidecar's metadata and the graph's
    /// authority hash, never the vectors themselves.
    #[cfg(feature = "vector")]
    fn store_with_persisted_vector_index(
        layout: &KinLayout,
        producer: Option<&str>,
    ) -> Arc<kin_db::InMemoryGraph> {
        std::fs::create_dir_all(layout.kindb_dir()).unwrap();
        let snapshot_path = layout.kindb_snapshot_path();
        let manager = kin_db::SnapshotManager::new(&snapshot_path);
        let graph = manager.graph();
        let entity = test_entity("semantic_query_target", "src/lib.rs");
        graph.upsert_entity(&entity).unwrap();

        // The placeholder binding only has to let the index install; the
        // `save_vector_index_for_graph` below re-stamps it with the exact model
        // identity and authority hash, which is what a reopen checks.
        let placeholder = kin_db::IndexDescriptor {
            model_id: Some("fixture-model".to_string()),
            graph_root: Some("fixture-root".to_string()),
        };
        let index = kin_db::VectorIndex::new(4).unwrap();
        index.upsert(entity.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        index.set_descriptor(placeholder.clone());
        index.save(&layout.kindb_vector_index_path()).unwrap();
        assert!(
            matches!(
                graph.load_vector_index_compatible(&layout.kindb_vector_index_path(), &placeholder),
                kin_db::VectorIndexLoad::Loaded(_)
            ),
            "fixture index must install before the store is persisted"
        );

        manager.save().unwrap();
        kin_db::SnapshotManager::save_vector_index_for_graph(
            &snapshot_path,
            graph.as_ref(),
            producer,
        )
        .unwrap();
        graph
    }

    /// The daemon's real open path builds its graph with
    /// `from_snapshot_with_text_index`, which restores no vector index. Clear
    /// the fixture's index to reproduce that state exactly.
    #[cfg(feature = "vector")]
    fn as_reopened_by_the_daemon(graph: &kin_db::InMemoryGraph) {
        graph.reset_vector_index();
        assert_eq!(
            graph.embedding_status().indexed,
            0,
            "a daemon reopen starts with no vector index installed"
        );
    }

    /// A Kin upgrade must not throw the user's embeddings away.
    ///
    /// Releases before this one pinned index reuse to the daemon's own build
    /// SHA, which changes on every commit, so moving between any two versions
    /// rejected the whole index and re-embedded the repository from zero. The
    /// sidecar here is stamped with a foreign build SHA exactly as an older
    /// release would have left it, and it must still load: nothing about the
    /// format, the model, or the graph moved.
    #[test]
    #[cfg(feature = "vector")]
    fn an_index_written_by_a_different_build_survives_the_upgrade() {
        let repo_dir = tempfile::tempdir().unwrap();
        let layout = KinLayout::new(repo_dir.path().join(".kin"));
        let graph = store_with_persisted_vector_index(
            &layout,
            Some("6c1f0a9d3b74e25a8f0c1d6e4b93a27f5d8e0c14"),
        );
        as_reopened_by_the_daemon(graph.as_ref());

        let discarded = DaemonState::load_validated_vector_index(&layout, graph.as_ref());

        assert_eq!(
            discarded.discarded, None,
            "an index from another build is not a discard: {discarded:?}"
        );
        assert_eq!(
            graph.embedding_status().indexed,
            1,
            "the persisted index must survive a version change, not be re-derived"
        );
    }

    /// The other side of the same contract: a sidecar this build genuinely
    /// cannot use is still refused, and now says so.
    ///
    /// A metadata envelope version this build does not know is the real format
    /// change the old build-SHA pin was standing in for. It must reject, and
    /// the rejection must name what was discarded rather than land in a debug
    /// log nobody reads.
    #[test]
    #[cfg(feature = "vector")]
    fn a_sidecar_in_an_unknown_format_is_refused_and_announced() {
        let repo_dir = tempfile::tempdir().unwrap();
        let layout = KinLayout::new(repo_dir.path().join(".kin"));
        let graph = store_with_persisted_vector_index(&layout, None);
        as_reopened_by_the_daemon(graph.as_ref());

        let metadata_path = layout.kindb_dir().join("graph.kvec.meta.json");
        let mut metadata: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&metadata_path).unwrap()).unwrap();
        metadata["version"] = json!(u32::MAX);
        std::fs::write(&metadata_path, serde_json::to_vec(&metadata).unwrap()).unwrap();

        let discarded = DaemonState::load_validated_vector_index(&layout, graph.as_ref());

        let reason = discarded
            .discarded
            .expect("a refused sidecar must be announced, not dropped silently");
        assert!(
            reason.contains("graph.kvec") && reason.contains("could not be read"),
            "the announcement must name what was discarded and why: {reason}"
        );
        assert_eq!(
            graph.embedding_status().indexed,
            0,
            "an unreadable sidecar must not be installed"
        );
    }

    /// A sidecar bound to a graph that has since moved on is salvaged per
    /// key: every vector whose entity truth is unchanged is reused, only the
    /// genuinely new key is missing, and nothing is announced as discarded.
    /// The whole-index refusal this test used to pin was the FIR-2325 defect;
    /// kin-db 0.7.24 replaced it with per-key salvage, and the corrupted-format
    /// case above still proves a real refusal stays loud.
    ///
    /// It now also pins the half FIR-2562 was about. "Not discarded" was the
    /// only thing this path could say about a salvage, and a caller reading it
    /// learned that an index attached and nothing else. A salvage has to arrive
    /// as its own fact, with the counts kin-db already computed, or the
    /// shortfall it leaves renders as a first fill.
    #[test]
    #[cfg(feature = "vector")]
    fn an_index_bound_to_drifted_graph_truth_is_salvaged_per_key() {
        let repo_dir = tempfile::tempdir().unwrap();
        let layout = KinLayout::new(repo_dir.path().join(".kin"));
        let graph = store_with_persisted_vector_index(&layout, None);
        as_reopened_by_the_daemon(graph.as_ref());
        graph
            .upsert_entity(&test_entity("added_after_the_index", "src/added.rs"))
            .unwrap();

        let opened = DaemonState::load_validated_vector_index(&layout, graph.as_ref());

        assert_eq!(
            opened.discarded, None,
            "a salvageable sidecar must be reused, not announced as discarded"
        );
        let salvage = opened
            .salvage
            .expect("a per-key salvage must reach the caller as a salvage, not as silence");
        assert!(
            salvage.kept > 0,
            "the salvage must report what it kept, which is what makes it a salvage \
             rather than a discard: {salvage:?}"
        );
        let status = graph.embedding_status();
        assert_eq!(
            salvage.kept, status.indexed,
            "the reported kept count must be the coverage actually attached: {salvage:?} \
             against {status:?}"
        );
        assert_eq!(
            status.indexed, 1,
            "the persisted vector whose entity truth is unchanged must survive the reopen"
        );
        assert!(
            status.total >= 2,
            "graph truth must still owe a vector for the entity added after the index"
        );
    }

    /// The control that makes the arm above capable of failing: an exact load
    /// reports NO salvage.
    ///
    /// Loaded whole and loaded partially are different facts, and a reader that
    /// cannot tell them apart is back where FIR-2562 started. Without this arm
    /// a `load_validated_vector_index` that reported a salvage on every attach
    /// would satisfy the test above completely.
    #[test]
    #[cfg(feature = "vector")]
    fn an_index_that_still_matches_its_graph_reports_no_salvage() {
        let repo_dir = tempfile::tempdir().unwrap();
        let layout = KinLayout::new(repo_dir.path().join(".kin"));
        let graph = store_with_persisted_vector_index(&layout, None);
        as_reopened_by_the_daemon(graph.as_ref());
        // No entity added, so graph truth has not moved and the stamp still
        // matches. This is the same fixture as the salvage arm minus the one
        // change that causes the drift.

        let opened = DaemonState::load_validated_vector_index(&layout, graph.as_ref());

        assert_eq!(
            opened.discarded, None,
            "an index that still matches its graph is not a discard"
        );
        assert_eq!(
            opened.salvage, None,
            "an exact load must not report a salvage: nothing was retired"
        );
        assert_eq!(
            graph.embedding_status().indexed,
            1,
            "the control must actually have attached an index, or it proves nothing"
        );
    }

    /// The kept count is what survived reconciliation, not what the sidecar
    /// held before it ran.
    ///
    /// kin-db's `vectors_loaded` is sampled before the per-key reconcile
    /// (`crates/kin-db/src/storage/snapshot.rs:1460` in 0.7.49), so the retired
    /// count it reports beside it is already inside that number. Passing
    /// `vectors_loaded` straight through as "kept" would have printed
    /// `2112 vectors were kept and 342 were retired` for the store FIR-2562 was
    /// filed on, which reads 1770/2112 indexed: two numbers that cannot both be
    /// true, on the one line the ticket exists to make trustworthy.
    ///
    /// The store fixtures cannot catch this on their own. They install a single
    /// vector and retire nothing, so kept and loaded are the same number there
    /// and the subtraction is invisible. This drives the mapping directly with
    /// a drop that is bigger than zero.
    #[test]
    fn a_salvage_reports_what_survived_reconciliation_not_what_the_sidecar_held() {
        let salvaged = kin_db::VectorSidecarLoadOutcome {
            attached: true,
            vectors_loaded: 2112,
            vectors_dropped: 342,
            disposition: kin_db::VectorSidecarDisposition::SalvagedAfterStampDrift,
            durable_coverage_before_load: true,
        };

        let record = salvage_from_sidecar_outcome(&salvaged)
            .expect("a stamp-drift salvage is the case this record exists for");
        assert_eq!(
            record,
            crate::VectorSalvage {
                kept: 1770,
                dropped: 342,
            },
            "kept must be the survivors, and kept plus retired must be the sidecar: {record:?}"
        );

        // An exact load reports no salvage even when it evicted orphaned
        // generations, because a re-init dropping stale keys is not a store
        // losing ground and rendering it as one would fire on ordinary work.
        assert_eq!(
            salvage_from_sidecar_outcome(&kin_db::VectorSidecarLoadOutcome {
                attached: true,
                vectors_loaded: 2112,
                vectors_dropped: 7,
                disposition: kin_db::VectorSidecarDisposition::LoadedExact,
                durable_coverage_before_load: true,
            }),
            None,
            "an exact load is not a salvage, whatever it pruned"
        );
        assert_eq!(
            salvage_from_sidecar_outcome(&kin_db::VectorSidecarLoadOutcome::default()),
            None,
            "a store with no sidecar has retired nothing"
        );
    }

    /// The announcement must distinguish "your index was thrown away" from
    /// "you have not built one yet". Every repository is in the second state
    /// until its first embed, and an announcement that fires there is noise
    /// that trains people to ignore the one that matters.
    #[test]
    #[cfg(feature = "vector")]
    fn a_repository_with_no_persisted_index_announces_nothing() {
        let repo_dir = tempfile::tempdir().unwrap();
        let layout = KinLayout::new(repo_dir.path().join(".kin"));
        std::fs::create_dir_all(layout.kindb_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();

        let opened = DaemonState::load_validated_vector_index(&layout, &graph);
        assert_eq!(
            opened.discarded, None,
            "a repository that never had an index has had nothing discarded"
        );
        assert_eq!(
            opened.salvage, None,
            "and nothing was salvaged either, since there was nothing to salvage"
        );
    }

    #[test]
    fn a_hydrated_state_reports_blob_errors_unchanged() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = DaemonState::open(init.layout).expect("local open");

        let reported = state
            .attribute_ingest_cas_gap(exact_source_storage_error("cannot load graph-owned blob"))
            .to_string();
        assert!(
            !reported.contains("never hydrated"),
            "a hydrated store must not blame a gap it does not have: {reported}"
        );
    }

    #[test]
    fn syncing_the_blob_store_commits_pending_barriers() {
        // The store defers each blob's directory barrier and commits it on an
        // explicit sync, on Drop, or on a self-drain. The daemon exits through
        // `process::exit`, so this is the only commit point it can actually
        // reach on a clean shutdown.
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = DaemonState::open(init.layout).expect("local open");

        let hash = state.blobs.write(b"pending rename\n").unwrap();
        state
            .sync_blob_store()
            .expect("the shutdown commit point must succeed on a healthy store");
        assert_eq!(state.blobs.read(&hash).unwrap(), b"pending rename\n");
        state
            .sync_blob_store()
            .expect("a second barrier with nothing pending is a no-op, not an error");
    }

    // ── Language-server enrichment must outlive the process that found it ──
    //
    // The daemon's local arm used to detach the pending batch, discard it, and
    // acknowledge it anyway, so every enrichment edge was reported persisted
    // and was absent on the next open. These pin both halves: what may be
    // published, and that it comes back.

    fn language_server_relation(
        src: &Entity,
        dst: &Entity,
        origin: kin_model::RelationOrigin,
    ) -> kin_model::Relation {
        kin_model::Relation {
            id: kin_model::RelationId::new(),
            kind: kin_model::RelationKind::Calls,
            src: kin_model::GraphNodeId::Entity(src.id),
            dst: kin_model::GraphNodeId::Entity(dst.id),
            confidence: 1.0,
            origin,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    fn snapshot_of(
        entities: &[Entity],
        relations: &[kin_model::Relation],
    ) -> kin_db::GraphSnapshot {
        let graph = kin_db::InMemoryGraph::new();
        for entity in entities {
            graph.upsert_entity(entity).unwrap();
        }
        for relation in relations {
            graph.upsert_relation(relation).unwrap();
        }
        graph.to_snapshot()
    }

    #[test]
    fn enrichment_publishes_language_server_edges_and_leaves_the_rest_derived() {
        let caller = test_entity("send", "src/sessions.rs");
        let callee = test_entity("adapter_send", "src/adapters.rs");
        let enriched = language_server_relation(&caller, &callee, kin_model::RelationOrigin::Lsp);
        let parsed = language_server_relation(&caller, &callee, kin_model::RelationOrigin::Parsed);
        let authority = snapshot_of(&[caller.clone(), callee.clone()], &[]);
        let live = snapshot_of(
            &[caller, callee],
            std::slice::from_ref(&enriched)
                .iter()
                .chain(std::slice::from_ref(&parsed))
                .cloned()
                .collect::<Vec<_>>()
                .as_slice(),
        );

        let (delta, unpublishable) =
            DaemonState::language_server_enrichment_delta(&live, &authority).unwrap();

        assert_eq!(unpublishable, 0);
        let published = delta
            .relation_deltas()
            .iter()
            .map(|delta| match delta {
                kin_model::RelationDelta::Added { new } => new.id,
                other => panic!("enrichment publishes additions only, got {other:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            published,
            vec![enriched.id],
            "only the language-server edge is authority's to keep; the parsed one is rebuilt \
             from the exact tree authority already owns"
        );
    }

    #[test]
    fn enrichment_never_retracts_a_relation_authority_holds() {
        // A language server that is absent this run, or slower than the last
        // one, must not delete durable truth by failing to reproduce it.
        let caller = test_entity("send", "src/sessions.rs");
        let callee = test_entity("adapter_send", "src/adapters.rs");
        let already_durable =
            language_server_relation(&caller, &callee, kin_model::RelationOrigin::Lsp);
        let authority = snapshot_of(
            &[caller.clone(), callee.clone()],
            std::slice::from_ref(&already_durable),
        );
        let live = snapshot_of(&[caller, callee], &[]);

        let (delta, _) = DaemonState::language_server_enrichment_delta(&live, &authority).unwrap();

        assert!(
            delta.is_empty(),
            "a live graph missing an authority relation must publish nothing, not a removal: {:?}",
            delta.relation_deltas()
        );
    }

    #[test]
    fn enrichment_skips_an_endpoint_authority_does_not_hold() {
        // A relation is not a place to introduce an entity. Publishing an edge
        // into a node authority cannot resolve would ask it to admit one.
        let caller = test_entity("send", "src/sessions.rs");
        let stranger = test_entity("not_admitted", "src/vendored.rs");
        let dangling = language_server_relation(&caller, &stranger, kin_model::RelationOrigin::Lsp);
        let authority = snapshot_of(std::slice::from_ref(&caller), &[]);
        let live = snapshot_of(&[caller, stranger], std::slice::from_ref(&dangling));

        let (delta, unpublishable) =
            DaemonState::language_server_enrichment_delta(&live, &authority).unwrap();

        assert!(delta.is_empty(), "a dangling edge is not published");
        assert_eq!(
            unpublishable, 1,
            "and the skip is counted rather than silent"
        );
    }

    /// Admit entities and the files they live in into workspace authority the
    /// way a commit does, so an enrichment edge between them has endpoints
    /// authority holds.
    ///
    /// The files are not decoration. Authority refuses a transaction that
    /// leaves an entity on a repository path its staged tree does not carry, so
    /// an entity-only admission cannot be built at all. The same deltas are
    /// applied to the live graph, which is what leaves the live tree equal to
    /// authority's and lets a flush proceed.
    fn publish_authority_entities(state: &DaemonState, entities: &[Entity]) {
        let binding = state.local_repository_authority_binding().unwrap();
        let authority = binding.open_manager().unwrap();
        let workspace_id = binding.workspace_id();
        let lease = authority.read_authority();
        let roots = lease.roots().clone();
        let expected_generation = roots.generation;
        let authority_metadata = lease.metadata();
        let workspace = authority_metadata
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == workspace_id)
            .cloned()
            .expect("the fixture workspace exists");
        drop(lease);

        let mut tree_deltas = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for entity in entities {
            let Some(file) = entity.file_origin.as_ref() else {
                continue;
            };
            if !seen.insert(file.0.clone()) {
                continue;
            }
            let body = format!("// {}\n", file.0).into_bytes();
            let hash = Hash256::from_bytes(kin_blobs::digest_bytes(&body));
            authority.save_source_blob(hash, &body).unwrap();
            state.blobs.write(&body).unwrap();
            tree_deltas.push(TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(
                    RepoPath::from_utf8(&file.0).unwrap(),
                    TreeEntry::blob(hash, false),
                ),
            });
        }
        let next_tree = workspace.tree.apply(&tree_deltas).unwrap();
        let next_tree_hash = kin_model::compute_resolved_tree_hash(&next_tree).unwrap();

        let entity_deltas = entities
            .iter()
            .map(|entity| kin_model::EntityDelta::Added {
                new: entity.clone(),
            })
            .collect::<Vec<_>>();
        let semantic_delta =
            kin_model::WorkspaceSemanticDelta::new(entity_deltas.clone(), Vec::new()).unwrap();
        let transaction = kin_model::RepositoryTransaction {
            schema_version: kin_model::REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id: binding.repository_id().clone(),
            expected_generation,
            expected_roots: roots,
            actor: kin_model::AuthorId::new("kin"),
            reason: "admit fixture entities".to_string(),
            external_objects: Vec::new(),
            changes: Vec::new(),
            aliases: Vec::new(),
            git_authority_delta: None,
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: Some(kin_model::WorkspaceMutation {
                workspace_id,
                expected: kin_model::WorkspaceExpectation::MustEqual {
                    generation: workspace.generation,
                    head: workspace.head.clone(),
                    base_target: workspace.base_target.clone(),
                    base_tree_hash: workspace.base_tree_hash,
                    tree_hash: workspace.tree_hash,
                    semantic_overlay_hash: workspace.semantic_overlay_hash,
                    admission_policy: workspace.admission_policy,
                },
                new_generation: workspace.generation + 1,
                new_head: workspace.head.clone(),
                new_base_target: workspace.base_target.clone(),
                new_base_tree_hash: workspace.base_tree_hash,
                tree_deltas: tree_deltas.clone(),
                new_tree_hash: next_tree_hash,
                semantic_delta,
                new_shared_admission_policy: workspace.shared_admission_policy.clone(),
                new_admission_policy: workspace.admission_policy,
            }),
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        let receipt = authority
            .commit_repository_transaction(transaction)
            .expect("the fixture entity admission commits");
        state
            .record_repository_authority_commit(receipt.generation)
            .expect("the daemon cursor follows its own authority commit");
        state
            .graph
            .apply_transaction_delta(&kin_model::TransactionDelta {
                tree_deltas,
                entity_deltas,
                ..Default::default()
            })
            .unwrap();
    }

    #[test]
    fn language_server_relations_survive_a_daemon_restart() {
        // The whole defect in one assertion. Before the fix this relation was
        // installed, counted, acknowledged as persisted, and absent here.
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let layout = init.layout.clone();
        let caller = test_entity("send", "src/sessions.rs");
        let callee = test_entity("adapter_send", "src/adapters.rs");
        let enriched = language_server_relation(&caller, &callee, kin_model::RelationOrigin::Lsp);

        {
            let state = test_state(layout.clone(), repo_dir.path());
            publish_authority_entities(&state, &[caller.clone(), callee.clone()]);
            state.graph.upsert_entity(&caller).unwrap();
            state.graph.upsert_entity(&callee).unwrap();
            state.graph.upsert_relation(&enriched).unwrap();
            state
                .save_snapshot()
                .expect("a flush that publishes enrichment succeeds");
            assert!(
                state
                    .graph
                    .to_snapshot()
                    .relations
                    .contains_key(&enriched.id),
                "the fixture must actually hold the edge before the restart"
            );
        }

        let reopened = test_state(layout, repo_dir.path());
        assert!(
            reopened
                .graph
                .to_snapshot()
                .relations
                .contains_key(&enriched.id),
            "a language-server relation must be graph-owned durable truth, not runtime state \
             the next process does not inherit"
        );
    }

    #[test]
    fn a_flush_defers_while_a_repository_command_holds_the_gate() {
        // Publishing moves the authority generation. A command that already
        // read that generation and has not committed yet would then refuse
        // itself, so a flush waits its turn instead of taking it.
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());
        let caller = test_entity("send", "src/sessions.rs");
        let callee = test_entity("adapter_send", "src/adapters.rs");
        publish_authority_entities(&state, &[caller.clone(), callee.clone()]);
        state
            .graph
            .upsert_relation(&language_server_relation(
                &caller,
                &callee,
                kin_model::RelationOrigin::Lsp,
            ))
            .unwrap();
        let before = state.snapshot_generation.load(Ordering::SeqCst);

        let held = state
            .coordination_gate
            .try_lock()
            .expect("the fixture gate is free until this test takes it");
        state
            .save_snapshot()
            .expect("a deferred flush is a deferral, not a failure");
        assert_eq!(
            state.snapshot_generation.load(Ordering::SeqCst),
            before,
            "a flush must publish nothing while a repository command holds the gate"
        );

        drop(held);
        state.save_snapshot().expect("the deferred flush publishes");
        assert!(
            state.snapshot_generation.load(Ordering::SeqCst) > before,
            "and the deferral must be a delay rather than a loss"
        );
    }

    #[test]
    fn a_flush_that_cannot_publish_does_not_acknowledge_the_batch() {
        // The non-negotiable: the local arm must never complete a persistence
        // epoch for a batch nothing wrote. A live tree ahead of authority is
        // refused before publication, and the RAII attempt must retire the
        // batch rather than acknowledge it.
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = test_state(init.layout, repo_dir.path());
        let caller = test_entity("send", "src/sessions.rs");
        let callee = test_entity("adapter_send", "src/adapters.rs");
        publish_authority_entities(&state, &[caller.clone(), callee.clone()]);
        state.graph.upsert_entity(&caller).unwrap();
        state.graph.upsert_entity(&callee).unwrap();
        state
            .graph
            .upsert_relation(&language_server_relation(
                &caller,
                &callee,
                kin_model::RelationOrigin::Lsp,
            ))
            .unwrap();
        let content = b"fn only_live() {}\n".to_vec();
        let content_hash = Hash256::from_bytes(kin_blobs::digest_bytes(&content));
        state.blobs.write(&content).unwrap();
        state
            .graph
            .apply_transaction_delta(&kin_model::TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: ArtifactId::new(),
                    new: LocatedEntry::new(
                        RepoPath::from_utf8("src/only_live.rs").unwrap(),
                        TreeEntry::blob(content_hash, false),
                    ),
                }],
                ..Default::default()
            })
            .unwrap();
        state.graph.clear_full_snapshot_required();

        let refused = state.save_snapshot();

        assert!(
            refused.is_err(),
            "a live tree authority has not admitted must refuse the flush"
        );
        assert!(
            state.graph.full_snapshot_required(),
            "a refused flush must retire its batch, which is what makes the next attempt \
             serialize the live graph instead of trusting an acknowledgement nothing earned"
        );
    }
}
