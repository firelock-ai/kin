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
#[cfg(test)]
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
    /// Triggered after init/migrate/reconcile.
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

/// Shared daemon state. All mutable state is behind RwLock for
/// concurrent access from the reconciliation loop and API handlers.
pub struct DaemonState {
    pub layout: KinLayout,
    pub graph: Arc<kin_db::InMemoryGraph>,
    pub blobs: Arc<BlobStore>,
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
    /// Startup-opened local storage capability. Reusing this exact backend
    /// preserves KinDB's device/inode root pin across every local authority
    /// request; constructing a new backend from the mutable path would bless a
    /// swapped `.kin/kindb` namespace.
    local_repository_backend: Option<Arc<LocalFileBackend>>,
    /// Local sibling capabilities captured from registry configuration at
    /// startup. The lazy spine loader may open only these retained bindings.
    registered_local_repository_authorities: Vec<RegisteredLocalRepositoryAuthority>,
    /// Startup registry/binding gaps prevent a complete local spine claim even
    /// when every retained sibling that remains can be loaded.
    registered_local_repository_authority_incomplete: bool,
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
    /// Serializes derived-index and hosted snapshot persistence so the
    /// persistence loop, idle-shutdown flush, and embedding worker can never
    /// interleave writes. Local repository-v6 authority is committed before
    /// entering this derived finalization path. Held only for the synchronous
    /// critical section — never across an `.await` or another lock.
    pub persist_lock: Mutex<()>,
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
    /// Number of API requests currently being handled.
    pub active_requests: AtomicU64,
    /// Channel for LSP enrichment messages (incremental or sweep).
    /// None if LSP enrichment is disabled (no servers found).
    pub lsp_enrichment_tx: Option<tokio::sync::mpsc::Sender<LspEnrichmentMessage>>,
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
    /// True when the background embedding worker has permanently stopped (it
    /// exhausted its consecutive-panic budget). The graph/locate/reconcile
    /// surfaces keep serving — embeddings are a DERIVED index — but the vector
    /// index will not advance until the daemon restarts. Surfaced as a
    /// daemon-health signal so this degraded state is LOUD, never silent (the
    /// worker dying must NOT take the whole daemon down).
    pub embed_worker_failed: AtomicBool,
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
/// FULL ranked entity list once per (query, ref/scope, graph-version) so a
/// follow-up page (`kin locate --next`) windows the next slice with no retrieval
/// re-run. `graph_version` is checked on lookup so a stale page (the graph moved
/// under the cursor) is rejected rather than served.
pub struct CachedLocateRanking {
    pub entities: Vec<kin_cli::commands::locate::LocateEntity>,
    pub graph_version: u64,
    pub created: Instant,
}

/// Cached full `semantic_locate` result rows for cursor paging — the entity-
/// granularity analogue of [`CachedLocateRanking`], holding the already-projected
/// per-entity JSON rows so a follow-up page is a pure window.
pub struct CachedSemanticPage {
    pub rows: Vec<serde_json::Value>,
    pub graph_version: u64,
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
    fn load_validated_vector_index(layout: &KinLayout, graph: &kin_db::InMemoryGraph) {
        let snapshot_path = layout.kindb_snapshot_path();
        let expected_embedder_identity = kin_buildinfo::sha_with_dirty(kin_buildinfo::get());
        match kin_db::SnapshotManager::load_vector_index_into_graph_if_valid(
            graph,
            &snapshot_path,
            Some(expected_embedder_identity.as_str()),
        ) {
            Ok(true) => {
                debug!(path = %snapshot_path.display(), "loaded validated persisted vector index");
            }
            Ok(false) => {}
            Err(error) => {
                debug!(
                    error = %error,
                    path = %snapshot_path.display(),
                    "failed to load persisted vector index"
                );
            }
        }
    }

    fn spine_disabled() -> bool {
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
            let authoritative = authority.load_source_blob(hash)?.ok_or_else(|| {
                DaemonError::Graph(kin_db::KinDbError::StorageError(format!(
                    "workspace artifact {} references source body {} absent from repository authority",
                    artifact.path, hash
                )))
            })?;

            match blobs.read(&hash) {
                Ok(cached) if cached == authoritative => continue,
                Ok(_) => {
                    return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                        format!(
                            "derived ingestion CAS body {} differs from repository authority despite matching its content address",
                            hash
                        ),
                    )))
                }
                Err(BlobError::NotFound { .. } | BlobError::HashMismatch { .. }) => {
                    // HashMismatch quarantines the corrupt derived object, so
                    // this write can atomically heal it from authority.
                }
                Err(error) => return Err(DaemonError::Blob(error)),
            }

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
        Ok(hydrated.len())
    }

    /// Freeze local sibling authority capabilities before the daemon becomes
    /// externally visible.
    ///
    /// Registry and manifest reads are startup configuration IO. Request-time
    /// spine initialization receives only retained identity/storage bindings,
    /// so a registry edit or storage-root replacement cannot silently change
    /// the daemon's authority set.
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
        let current_kin_root = layout
            .root()
            .canonicalize()
            .unwrap_or_else(|_| layout.root().to_path_buf());
        let mut pinned = Vec::new();
        let mut incomplete = false;

        for repo in registry.repos {
            let repo_root = repo
                .path
                .canonicalize()
                .unwrap_or_else(|_| repo.path.clone());
            if repo_root == current_kin_root || current_kin_root.starts_with(&repo_root) {
                continue;
            }

            let sibling_layout = KinLayout::new(repo.path.join(".kin"));
            let binding =
                match kin_core::LocalRepositoryAuthorityBinding::from_layout(&sibling_layout) {
                    Ok(binding) => binding,
                    Err(error) => {
                        incomplete = true;
                        warn!(
                            repo_id = %repo.id,
                            path = %repo.path.display(),
                            error = %error,
                            "sibling repository authority could not be pinned at daemon startup"
                        );
                        continue;
                    }
                };
            if binding.repository_id().as_str() != repo.id {
                incomplete = true;
                warn!(
                    repo_id = %repo.id,
                    path = %repo.path.display(),
                    manifest_repo_id = %binding.repository_id(),
                    "registry repository identity does not match startup-pinned manifest authority"
                );
                continue;
            }
            pinned.push(RegisteredLocalRepositoryAuthority {
                repo_id: repo.id,
                binding,
            });
        }

        (pinned, incomplete)
    }

    /// Open local daemon state with a repository identity already resolved by
    /// the process entrypoint. Local overrides must name the manifest's exact
    /// authority; they cannot rebind one workspace to another repository.
    pub fn open_with_repo_id(layout: KinLayout, explicit_repo_id: Option<&str>) -> Result<Self> {
        // Layout gate first. A pre-v2 `.kin/` (file/branch-authority era) must
        // be refused before any manifest or storage parsing runs: its manifest
        // may predate required fields and its storage holds no repository
        // namespace, so letting either path speak first buries the real story
        // under a serde or storage error instead of the version gap.
        if let Err(error) = layout.check_version() {
            return Err(DaemonError::IncompatibleRepo(format!(
                "{error}. This repository was created before the \
                 repository-authority layout change; re-create it with this \
                 build (`kin clone` or `kin init` in a fresh checkout), or \
                 open it with a matching older kin."
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
        let (
            registered_local_repository_authorities,
            registered_local_repository_authority_incomplete,
        ) = Self::pin_registered_local_repository_authorities(&layout);
        let authority = RepositoryAuthorityManager::open(
            repository_id.clone(),
            Arc::clone(&local_repository_backend),
        )
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
            .map_err(DaemonError::Graph)?;
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
        let workspace_snapshot = lease
            .workspace_graph_snapshot(&workspace_id)
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
        let hydrated_source_bodies =
            Self::hydrate_ingest_cas(&authority, &workspace_snapshot.resolved_tree, &blobs)?;
        let graph = if locate_only {
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
        Self::load_validated_vector_index(&layout, graph.as_ref());

        let mut reconciler = Reconciler::new(layout.working_dir().to_path_buf());
        // Seed LKG from persisted graph so the first reconcile after daemon
        // startup only reports truly changed entities, not all of them.
        reconciler.seed_lkg_entities_from_graph(graph.as_ref());

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
            local_repository_backend: Some(local_repository_backend),
            registered_local_repository_authorities,
            registered_local_repository_authority_incomplete,
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
            #[cfg(test)]
            spine_initialization_test_hook: Mutex::new(None),
            spine_refresh_gate: tokio::sync::Mutex::new(()),
            repo_graphs: RwLock::new(HashMap::new()),
            allowed_repo_ids: None,
            dirty: AtomicBool::new(false),
            mutation_epoch: AtomicU64::new(0),
            embedding_work: Mutex::new(()),
            persist_lock: Mutex::new(()),
            last_save: std::sync::Mutex::new(Instant::now()),
            last_mutation: std::sync::Mutex::new(Instant::now()),
            active_embed_passes: AtomicU32::new(0),
            background_embed_paused: AtomicBool::new(false),
            last_activity_ms: AtomicU64::new(0),
            active_requests: AtomicU64::new(0),
            lsp_enrichment_tx: None,
            cached_repo_id,
            cached_workspace_id: Some(workspace_id),
            is_shutdown: AtomicBool::new(false),
            persisted_entity_count: AtomicU64::new(loaded_entity_count as u64),
            mass_deletion_blocked: AtomicBool::new(false),
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
                state.finalize_loaded_locate_generation(generation)?;
            } else {
                state
                    .post_commit_finalization_pending
                    .store(true, Ordering::SeqCst);
                state.finalize_loaded_generation(generation)?;
            }
        }
        state.register_daemon_system_session();
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
        let (graph, generation, loaded_snapshot) =
            match kin_db::load_recovered_snapshot(backend.as_ref(), repo_id)
                .map_err(DaemonError::from)?
            {
                Some(recovered) => {
                    let g = kin_db::InMemoryGraph::from_snapshot_with_text_index(
                        recovered.snapshot,
                        text_index_path.clone(),
                    )
                    .map_err(DaemonError::from)?;
                    info!(
                        repo_id,
                        generation = recovered.generation,
                        deltas_replayed = recovered.deltas_applied,
                        "loaded graph from storage backend"
                    );
                    (Arc::new(g), recovered.generation, true)
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
                    )
                }
            };

        let blobs = BlobStore::new(layout.ingest_cas_dir()).map_err(DaemonError::from)?;
        // The backend path builds the graph via `from_snapshot_with_text_index`,
        // which does NOT load the vector-index sidecar — do the validated load
        // here (no-ops if no/stale sidecar).
        Self::load_validated_vector_index(&layout, graph.as_ref());
        let mut reconciler = Reconciler::new(layout.working_dir().to_path_buf());
        reconciler.seed_lkg_entities_from_graph(graph.as_ref());

        let traffic_checker =
            crate::traffic_adapter::CoordinatorTrafficChecker::new(Arc::clone(&graph));
        reconciler.set_traffic_checker(Box::new(traffic_checker));

        let coordinator = SessionCoordinator::new(Arc::clone(&graph));

        let persisted_vfs_version = Self::load_persisted_vfs_version(&layout);

        // Baseline for the shutdown anti-wipe guard (entity count loaded from
        // the backend snapshot).
        let loaded_entity_count = graph.entity_count();

        let coordination_events = CoordinationEventLog::open(&layout, repo_id)?;
        let coordination_event_persist_failures = coordination_events.persisted_failure_count();
        let mut state = Self {
            layout,
            graph: Arc::clone(&graph),
            blobs: Arc::new(blobs),
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
            storage_backend: Some(Arc::from(backend)),
            local_repository_backend: None,
            registered_local_repository_authorities: Vec::new(),
            registered_local_repository_authority_incomplete: false,
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
            #[cfg(test)]
            spine_initialization_test_hook: Mutex::new(None),
            spine_refresh_gate: tokio::sync::Mutex::new(()),
            repo_graphs: RwLock::new(HashMap::new()), // populated below
            allowed_repo_ids,
            dirty: AtomicBool::new(false),
            mutation_epoch: AtomicU64::new(0),
            embedding_work: Mutex::new(()),
            persist_lock: Mutex::new(()),
            last_save: std::sync::Mutex::new(Instant::now()),
            last_mutation: std::sync::Mutex::new(Instant::now()),
            active_embed_passes: AtomicU32::new(0),
            background_embed_paused: AtomicBool::new(false),
            last_activity_ms: AtomicU64::new(0),
            active_requests: AtomicU64::new(0),
            lsp_enrichment_tx: None,
            cached_repo_id: repo_id.to_string(),
            cached_workspace_id: None,
            is_shutdown: AtomicBool::new(false),
            persisted_entity_count: AtomicU64::new(loaded_entity_count as u64),
            mass_deletion_blocked: AtomicBool::new(false),
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
    pub fn ensure_spine(&self) -> Option<&dyn kin_spine::SpineBackend> {
        if Self::spine_disabled() {
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
        self.spine.get().map(|s| s.as_ref())
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
        for registered in &self.registered_local_repository_authorities {
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
        if registered_repo_ids != captured_repo_ids {
            authority_incomplete = true;
            warn!(
                captured = captured_repo_ids.len(),
                registered = registered_repo_ids.len(),
                "spine contains durable advisory repos without a current graph capture"
            );
        }
        if authority_incomplete {
            for repo_id in &registered_repo_ids {
                backend.invalidate_cross_repo_edges(repo_id);
            }
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

        info!(
            cross_repo_edges = backend.edge_count(),
            capture_set_complete = !authority_incomplete,
            "spine index initialized"
        );
        let _ = self.spine.get_or_init(move || backend);
    }

    /// Create the appropriate spine backend based on environment.
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
            let reason = if Self::spine_disabled() {
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
            let reason = if Self::spine_disabled() {
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
                let graph = Arc::new(
                    kin_db::InMemoryGraph::from_snapshot_with_text_index(
                        recovered.snapshot,
                        text_index_path,
                    )
                    .map_err(DaemonError::from)?,
                );
                info!(
                    repo_id,
                    generation = recovered.generation,
                    deltas_replayed = recovered.deltas_applied,
                    "loaded repo graph from storage backend"
                );
                Ok(graph)
            }
            None => Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                format!("repo '{}' not found in storage", repo_id),
            ))),
        }
    }

    fn cache_loaded_repo_graph(
        graphs: &mut HashMap<String, Arc<kin_db::InMemoryGraph>>,
        repo_id: &str,
        loaded: Arc<kin_db::InMemoryGraph>,
    ) -> Arc<kin_db::InMemoryGraph> {
        Arc::clone(graphs.entry(repo_id.to_string()).or_insert(loaded))
    }

    /// Get or lazy-load a repo's graph from the storage backend.
    ///
    /// Returns the cached graph if already loaded, otherwise loads from
    /// the storage backend and caches it. Only usable when a storage
    /// backend is configured (cloud / multi-repo mode).
    pub async fn get_repo_graph(&self, repo_id: &str) -> Result<Arc<kin_db::InMemoryGraph>> {
        if let Some(allowed_repo_ids) = &self.allowed_repo_ids {
            if !allowed_repo_ids.contains(repo_id) {
                return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                    format!("repo '{}' is not configured for this daemon", repo_id),
                )));
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
    pub fn list_available_repos(&self) -> Result<Vec<String>> {
        let mut repos = if let Some(backend) = &self.storage_backend {
            backend.list_repos().map_err(DaemonError::from)?
        } else {
            // Local mode: return the loaded repo_graphs keys.
            let graphs = self
                .repo_graphs
                .try_read()
                .map(|g| g.keys().cloned().collect())
                .unwrap_or_default();
            graphs
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

        let force_full = mode == SnapshotSaveMode::Full;

        let repo_id = self.cached_repo_id.as_str();
        let expected_gen = self.snapshot_generation.load(Ordering::SeqCst);
        let mut committed = false;

        let new_gen = if let Some(backend) = &self.storage_backend {
            if force_full
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
            // workspace at this generation, then acknowledge it after flushing
            // query text. Never recreate graph.kndb as a second local truth.
            let persistence_attempt = self
                .graph
                .begin_delta_persistence(expected_gen)
                .map(|(_, epoch)| GraphPersistenceAttempt::new(self.graph.as_ref(), epoch));
            let authority_graph = self.load_committed_authority_graph(expected_gen)?;
            let authority_tree = authority_graph.resolved_tree();
            let live_tree = self.graph.resolved_tree();
            if live_tree != authority_tree {
                return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                    format!(
                        "refusing to acknowledge derived graph state at repository generation {expected_gen}: live exact tree does not match workspace authority"
                    ),
                )));
            }
            self.graph.flush_text_index().map_err(DaemonError::from)?;
            if let Some(attempt) = persistence_attempt {
                attempt.complete();
            }
            self.graph.clear_full_snapshot_required();
            expected_gen
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
        let authority_graph = self.load_committed_authority_graph(generation)?;
        if self.graph.resolved_tree() != authority_graph.resolved_tree() {
            return Err(DaemonError::Graph(kin_db::KinDbError::StorageError(
                format!(
                    "refusing vector checkpoint at repository generation {generation}: live exact tree does not match workspace authority"
                ),
            )));
        }
        let embedder_identity = kin_buildinfo::sha_with_dirty(kin_buildinfo::get());
        kin_db::SnapshotManager::checkpoint_vector_index_for_graph(
            self.layout.kindb_snapshot_path(),
            self.graph.as_ref(),
            Some(embedder_identity.as_str()),
        )
        .map_err(DaemonError::from)?;
        if self.post_commit_finalization_pending.load(Ordering::SeqCst) {
            self.finalize_committed_generation(generation)?;
        }
        Ok(self.graph.embedding_status().pending)
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
        let embedder_identity = kin_buildinfo::sha_with_dirty(kin_buildinfo::get());
        kin_db::SnapshotManager::save_vector_index_for_graph(
            self.layout.kindb_snapshot_path(),
            self.graph.as_ref(),
            Some(embedder_identity.as_str()),
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
                    Arc::new(
                        kin_db::InMemoryGraph::from_snapshot(recovered.snapshot)
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
                .map_err(DaemonError::from)?;
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
                    exact_source_storage_error(format!(
                        "projection refresh for {file_id} cannot load graph-owned blob {}: {error}",
                        hash
                    ))
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
    /// Triggered after init/migrate/reconcile. No-op if LSP enrichment is not available.
    pub fn queue_lsp_sweep(&self) {
        if self.filesystem_reconcile_disabled() {
            return;
        }
        if let Some(ref tx) = self.lsp_enrichment_tx {
            if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) =
                tx.try_send(LspEnrichmentMessage::Sweep)
            {
                warn!("LSP enrichment channel full, sweep request dropped");
            }
        }
    }

    /// Return the current reconciliation status as a human-readable string.
    pub fn reconciliation_status_str(&self) -> &'static str {
        match self.reconciliation_status.load(Ordering::Relaxed) {
            RECON_PROCESSING => "processing",
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
        std::thread::sleep(Duration::from_millis(25));
        assert!(state.time_since_mutation() >= Duration::from_millis(20));
        state.mark_dirty();
        assert!(state.time_since_mutation() < Duration::from_millis(20));
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
        let prev_registry = std::env::var_os("KIN_REGISTRY_PATH");
        let prev_disable = std::env::var_os("KIN_DISABLE_SPINE");
        std::env::set_var("KIN_REGISTRY_PATH", &registry_path);
        std::env::remove_var("KIN_DISABLE_SPINE");

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

        match prev_registry {
            Some(value) => std::env::set_var("KIN_REGISTRY_PATH", value),
            None => std::env::remove_var("KIN_REGISTRY_PATH"),
        }
        match prev_disable {
            Some(value) => std::env::set_var("KIN_DISABLE_SPINE", value),
            None => std::env::remove_var("KIN_DISABLE_SPINE"),
        }

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
        let prev_registry = std::env::var_os("KIN_REGISTRY_PATH");
        let prev_disable = std::env::var_os("KIN_DISABLE_SPINE");
        std::env::set_var("KIN_REGISTRY_PATH", &registry_path);
        std::env::remove_var("KIN_DISABLE_SPINE");

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

        match prev_registry {
            Some(value) => std::env::set_var("KIN_REGISTRY_PATH", value),
            None => std::env::remove_var("KIN_REGISTRY_PATH"),
        }
        match prev_disable {
            Some(value) => std::env::set_var("KIN_DISABLE_SPINE", value),
            None => std::env::remove_var("KIN_DISABLE_SPINE"),
        }

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
        let prev_registry = std::env::var_os("KIN_REGISTRY_PATH");
        let prev_disable = std::env::var_os("KIN_DISABLE_SPINE");
        std::env::set_var("KIN_REGISTRY_PATH", &registry_path);
        std::env::remove_var("KIN_DISABLE_SPINE");

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

        match prev_registry {
            Some(value) => std::env::set_var("KIN_REGISTRY_PATH", value),
            None => std::env::remove_var("KIN_REGISTRY_PATH"),
        }
        match prev_disable {
            Some(value) => std::env::set_var("KIN_DISABLE_SPINE", value),
            None => std::env::remove_var("KIN_DISABLE_SPINE"),
        }

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
        let prev_registry = std::env::var_os("KIN_REGISTRY_PATH");
        let prev_disable = std::env::var_os("KIN_DISABLE_SPINE");
        std::env::set_var("KIN_REGISTRY_PATH", &registry_path);
        std::env::remove_var("KIN_DISABLE_SPINE");

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
        match prev_registry {
            Some(v) => std::env::set_var("KIN_REGISTRY_PATH", v),
            None => std::env::remove_var("KIN_REGISTRY_PATH"),
        }
        if let Some(v) = prev_disable {
            std::env::set_var("KIN_DISABLE_SPINE", v);
        }

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

        // Spine must be enabled for this test regardless of ambient env.
        // Point discovery at an explicitly empty registry: this hosted path is
        // proving storage-only sibling ingestion and must never scan a user's
        // real global registry (which can contain multi-gigabyte graphs).
        let registry_dir = tempfile::tempdir().unwrap();
        let registry_path = registry_dir.path().join("registry.toml");
        kin_core::registry::KinRegistry { repos: Vec::new() }
            .save_to(&registry_path)
            .unwrap();
        let prev_registry = std::env::var_os("KIN_REGISTRY_PATH");
        let prev_disable = std::env::var_os("KIN_DISABLE_SPINE");
        std::env::set_var("KIN_REGISTRY_PATH", &registry_path);
        std::env::remove_var("KIN_DISABLE_SPINE");

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
        if let Some(v) = prev_disable {
            std::env::set_var("KIN_DISABLE_SPINE", v);
        }
        match prev_registry {
            Some(v) => std::env::set_var("KIN_REGISTRY_PATH", v),
            None => std::env::remove_var("KIN_REGISTRY_PATH"),
        }

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
            message.contains("kin clone") || message.contains("kin init"),
            "message must name a remediation path: {message}"
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
        tokio::time::sleep(Duration::from_millis(30)).await;
        let before = state.idle_duration();
        assert!(
            before >= Duration::from_millis(20),
            "idle clock should count from startup until first activity, got {before:?}"
        );

        // The idle monitor calls touch_activity() when it starts so the idle
        // window begins from readiness, not process construction. Confirm the
        // clock resets back toward zero.
        state.touch_activity();
        let after = state.idle_duration();
        assert!(
            after < before,
            "touch_activity must reset the idle clock: before={before:?} after={after:?}"
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
}
