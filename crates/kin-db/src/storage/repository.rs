// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Atomic repository authority over one immutable graph snapshot envelope.
//!
//! Raw bodies are written to the immutable source CAS before a transaction,
//! but they are not repository authority by themselves. A transaction first
//! validates every referenced body and complete successor state, then persists
//! one full snapshot with backend CAS, and only after durable acknowledgement
//! publishes one new `Arc` to readers.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use parking_lot::Mutex;

use kin_model::{
    ArtifactId, AuthorId, AuthorityRoot, ChangeStore, DefaultRefExpectation, DefaultRefMutation,
    EntityDelta, EntityStore, ExternalChangeAlias, ExternalObjectId, ExternalObjectKind,
    ExternalObjectRecord, ExternalReferenceDelta, FrozenLocalOverlay, GitExternalAuthority,
    GitObjectBodyLoader, GitObjectDependencyKind, GitObjectId, GitTreeEntryMode, Hash256,
    LocalAdmissionRuleSourceKind, MergeEntryResolution, MergeResolutionPayload,
    MergeTransactionRecord, ModelError, OperationId, RefExpectation, RefMutation, RefName,
    RefTarget, RefUpdatePolicy, RelationDelta, RepoPath, RepositoryAuthorityStore,
    RepositoryCommitOutcome, RepositoryCommitReceipt, RepositoryId, RepositoryOperationRecord,
    RepositoryRef, RepositoryRefState, RepositoryTransaction, ResolvedArtifact, ResolvedTree,
    RootBundle, SemanticChangeId, SensitiveArtifactKind, SharedAdmissionPolicy, Timestamp,
    TreeDelta, TreeEntry, WorkspaceHead, WorkspaceId, WorkspaceSemanticOverlay,
    WorkspaceSnapshotBinding, WorkspaceState, WorkspaceTreeArtifact, WorkspaceTreeSnapshot,
    REPOSITORY_ROOT_SCHEMA_VERSION,
};

use crate::admission::{
    enforce_sensitive_admission, AdmissionRuleSource as ResolvedAdmissionRuleSource,
    ResolvedAdmissionMatcher, ResolvedAdmissionRuleSet,
};
use crate::engine::InMemoryGraph;
use crate::error::KinDbError;
use crate::storage::authority::{
    AuthorityCommitDecision, AuthorityPublication, AuthorityReadLease, DurableAuthorityPersistence,
    PersistOutcome, RetainedPersistOutcome, VersionedAuthorityState,
};
use crate::storage::backend::{
    load_recovered_repository_authority, validate_source_blob_size, verify_source_blob_digest,
    AuthorityPayloadStats, Generation, LocalAuthorityFreezeLock, LocalFileBackend,
    RecoveredSnapshot, SnapshotCursor, SnapshotSaveOutcome, SourceBlobValidationRequest,
    StorageBackend, VerifiedSourceBlobBatch, MAX_SOURCE_BLOB_BYTES,
};
use crate::storage::format::GraphSnapshot;

/// Persisted repository-envelope schema.
pub const REPOSITORY_AUTHORITY_SCHEMA_VERSION: u32 = 3;

/// Version of the complete open-time validation a durable history-validation
/// record stands for.
///
/// Bump this whenever anything reachable from `open`'s full validation path
/// changes what it accepts or rejects. Every record minted by an earlier
/// version is then refused, and one full validation re-establishes the proof.
/// The envelope schema is folded in so an envelope change cannot silently
/// inherit a proof minted against the old shape.
pub const HISTORY_VALIDATION_VERSION: u32 = 1_000 + REPOSITORY_AUTHORITY_SCHEMA_VERSION;

/// Shared admission policy resolved at one exact semantic change.
///
/// Policy is branch-versioned. Persisting a single "current" policy would
/// silently collapse divergent refs, so the envelope carries the resolved
/// state for every change instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeAdmissionPolicy {
    pub change_id: SemanticChangeId,
    pub policy: Option<SharedAdmissionPolicy>,
}

/// One coherent workspace authority binding and its exact compiled admission
/// behavior.
///
/// `binding.admission_policy` is the shared-plus-local policy stamp carried by
/// the same authority lease that selected `case` and `matcher`. Rule bodies
/// are loaded only from repository-owned immutable CAS and verified against
/// the pinned shared policy and frozen local overlay before this value is
/// returned.
#[derive(Debug, Clone)]
pub struct WorkspaceAdmissionSnapshot {
    pub binding: WorkspaceSnapshotBinding,
    pub case: crate::admission::AdmissionCase,
    pub matcher: ResolvedAdmissionMatcher,
}

/// Complete repository-authority metadata stored inside one graph snapshot.
///
/// Every vector with set semantics is kept in canonical sorted order.
/// `operation_log` alone is append-ordered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedRepositoryAuthority {
    pub schema_version: u32,
    pub repository_id: RepositoryId,
    pub roots: RootBundle,
    pub external_objects: Vec<ExternalObjectRecord>,
    pub git_external_authority: Option<GitExternalAuthority>,
    pub aliases: Vec<ExternalChangeAlias>,
    pub ref_state: RepositoryRefState,
    pub operation_log: Vec<RepositoryOperationRecord>,
    pub workspaces: Vec<WorkspaceState>,
    pub admission_policies: Vec<ChangeAdmissionPolicy>,
    pub local_overlays: Vec<FrozenLocalOverlay>,
    pub receipts: Vec<RepositoryCommitReceipt>,
    /// Durable merge state, at most one record per workspace.
    ///
    /// Deliberately last, and omitted when empty. The envelope is persisted
    /// inside a MessagePack snapshot, where a struct is an array and position
    /// decides the mapping, so a new collection is only additive at the end: an
    /// already-written envelope runs out of elements and takes the default.
    /// A repository that has never had a conflicting merge therefore keeps the
    /// exact bytes and the exact local authority root it already had, and needs
    /// no re-import.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub merge_transactions: Vec<MergeTransactionRecord>,
}

impl PersistedRepositoryAuthority {
    fn empty(repository_id: RepositoryId, snapshot: &GraphSnapshot) -> Result<Self, KinDbError> {
        let mut authority = Self {
            schema_version: REPOSITORY_AUTHORITY_SCHEMA_VERSION,
            repository_id,
            roots: placeholder_roots(0),
            external_objects: Vec::new(),
            git_external_authority: None,
            aliases: Vec::new(),
            ref_state: RepositoryRefState::default(),
            operation_log: Vec::new(),
            workspaces: Vec::new(),
            admission_policies: Vec::new(),
            local_overlays: Vec::new(),
            receipts: Vec::new(),
            merge_transactions: Vec::new(),
        };
        authority.roots = compute_roots(snapshot, &authority, 0)?;
        Ok(authority)
    }

    /// Fail closed on malformed, non-canonical, or root-inconsistent metadata.
    pub fn validate_against_snapshot(&self, snapshot: &GraphSnapshot) -> Result<(), KinDbError> {
        if self.schema_version != REPOSITORY_AUTHORITY_SCHEMA_VERSION {
            return Err(storage(format!(
                "unsupported repository authority schema {}; expected {}",
                self.schema_version, REPOSITORY_AUTHORITY_SCHEMA_VERSION
            )));
        }
        self.roots.validate()?;
        self.ref_state.validate()?;

        require_sorted_unique(
            &self.external_objects,
            |record| record.object,
            "external object",
        )?;
        require_sorted_unique(&self.aliases, |alias| alias.oid, "external alias")?;
        require_sorted_unique(
            &self.ref_state.refs,
            |repository_ref| repository_ref.name.clone(),
            "repository ref",
        )?;
        require_sorted_unique(
            &self.workspaces,
            |workspace| workspace.workspace_id,
            "workspace",
        )?;
        require_sorted_unique(
            &self.admission_policies,
            |policy| policy.change_id,
            "change admission policy",
        )?;
        require_sorted_unique(
            &self.local_overlays,
            |overlay| overlay.workspace_id,
            "local overlay",
        )?;
        require_sorted_unique(
            &self.merge_transactions,
            |record| record.workspace_id,
            "merge transaction",
        )?;
        require_sorted_unique(
            &self.receipts,
            |receipt| receipt.operation_id,
            "operation receipt",
        )?;

        for repository_ref in &self.ref_state.refs {
            if repository_ref.repository_id != self.repository_id {
                return Err(storage(format!(
                    "ref {} belongs to repository {}, not {}",
                    repository_ref.name, repository_ref.repository_id, self.repository_id
                )));
            }
        }
        for alias in &self.aliases {
            if alias.repository_id != self.repository_id {
                return Err(storage(format!(
                    "alias {} belongs to repository {}, not {}",
                    alias.oid, alias.repository_id, self.repository_id
                )));
            }
        }
        validate_git_authority_shape_and_projection(snapshot, self)?;
        for workspace in &self.workspaces {
            workspace.validate()?;
            if workspace.repository_id != self.repository_id {
                return Err(storage(format!(
                    "workspace {} belongs to repository {}, not {}",
                    workspace.workspace_id, workspace.repository_id, self.repository_id
                )));
            }
            workspace_projection_mtime(self, workspace)?;
        }
        for overlay in &self.local_overlays {
            overlay.validate()?;
        }
        for record in &self.merge_transactions {
            record.validate()?;
            if record.repository_id != self.repository_id {
                return Err(storage(format!(
                    "merge transaction for workspace {} belongs to repository {}, not {}",
                    record.workspace_id, record.repository_id, self.repository_id
                )));
            }
            if !self
                .workspaces
                .iter()
                .any(|workspace| workspace.workspace_id == record.workspace_id)
            {
                return Err(storage(format!(
                    "merge transaction names workspace {}, which this repository does not have",
                    record.workspace_id
                )));
            }
        }

        if self.operation_log.len() != self.receipts.len() {
            return Err(storage(format!(
                "operation log has {} entries but receipt index has {}",
                self.operation_log.len(),
                self.receipts.len()
            )));
        }
        let receipts: BTreeMap<OperationId, &RepositoryCommitReceipt> = self
            .receipts
            .iter()
            .map(|receipt| (receipt.operation_id, receipt))
            .collect();
        let mut expected_before = initial_roots_for_log(&self.operation_log, &self.roots);
        for operation in &self.operation_log {
            operation.validate()?;
            if operation.repository_id != self.repository_id {
                return Err(storage(format!(
                    "operation {} belongs to repository {}, not {}",
                    operation.operation_id, operation.repository_id, self.repository_id
                )));
            }
            if operation.roots_before != expected_before {
                return Err(storage(format!(
                    "operation {} does not continue the exact root chain",
                    operation.operation_id
                )));
            }
            let receipt = receipts.get(&operation.operation_id).ok_or_else(|| {
                storage(format!(
                    "operation {} has no durable receipt",
                    operation.operation_id
                ))
            })?;
            receipt.validate()?;
            if receipt.outcome != RepositoryCommitOutcome::Committed
                || receipt.operation != *operation
            {
                return Err(storage(format!(
                    "receipt {} does not match its committed operation",
                    operation.operation_id
                )));
            }
            expected_before = operation.roots_after.clone();
        }
        if let Some(last) = self.operation_log.last() {
            if last.roots_after != self.roots {
                return Err(storage(
                    "repository root bundle does not match the last operation".to_string(),
                ));
            }
        } else if self.roots.generation != 0 {
            return Err(storage(
                "repository without operations must remain at generation zero".to_string(),
            ));
        }

        let derived_policies = derive_admission_policies(&snapshot.changes)?;
        if derived_policies != self.admission_policies {
            return Err(storage(
                "persisted per-change admission state does not match semantic history".to_string(),
            ));
        }
        validate_unscoped_history_caches(snapshot)?;
        validate_ref_targets(snapshot, self)?;
        validate_workspace_authority(snapshot, self)?;

        let computed = compute_roots(snapshot, self, self.roots.generation)?;
        if computed != self.roots {
            return Err(storage(
                "repository root bundle does not recompute from the persisted envelope".to_string(),
            ));
        }
        Ok(())
    }
}

fn initial_roots_for_log(
    operations: &[RepositoryOperationRecord],
    current: &RootBundle,
) -> RootBundle {
    operations.first().map_or_else(
        || current.clone(),
        |operation| operation.roots_before.clone(),
    )
}

fn require_sorted_unique<T, K: Ord>(
    values: &[T],
    key: impl Fn(&T) -> K,
    label: &str,
) -> Result<(), KinDbError> {
    let mut previous = None;
    for value in values {
        let current = key(value);
        if previous.as_ref().is_some_and(|old| old >= &current) {
            return Err(storage(format!(
                "{label} authority is not in canonical unique order"
            )));
        }
        previous = Some(current);
    }
    Ok(())
}

/// One immutable state published to all repository readers.
#[derive(Debug, Clone)]
pub struct RepositoryAuthorityState {
    snapshot: GraphSnapshot,
    /// Derived acceleration over immutable, externally authenticated Git
    /// history. This is never serialized or accepted from a transaction.
    authenticated_gitlinks: Arc<BTreeSet<(ArtifactId, GitObjectId)>>,
}

impl RepositoryAuthorityState {
    /// Build the read state after the enclosing snapshot has passed complete
    /// repository-authority and history validation.
    fn from_validated_snapshot(snapshot: GraphSnapshot) -> Self {
        let mut authenticated_gitlinks = BTreeSet::new();
        extend_authenticated_gitlinks(&mut authenticated_gitlinks, snapshot.changes.values());
        Self {
            snapshot,
            authenticated_gitlinks: Arc::new(authenticated_gitlinks),
        }
    }

    /// Carry the immutable authority index forward and add only Git-origin
    /// changes from the already-validated successor transaction.
    fn from_validated_successor(
        current: &Self,
        snapshot: GraphSnapshot,
        incoming: &[kin_model::SemanticChange],
    ) -> Self {
        let mut authenticated_gitlinks = Arc::clone(&current.authenticated_gitlinks);
        let mut incoming_gitlinks = BTreeSet::new();
        extend_authenticated_gitlinks(&mut incoming_gitlinks, incoming);
        if !incoming_gitlinks.is_empty() {
            Arc::make_mut(&mut authenticated_gitlinks).extend(incoming_gitlinks);
        }
        Self {
            snapshot,
            authenticated_gitlinks,
        }
    }

    pub fn snapshot(&self) -> &GraphSnapshot {
        &self.snapshot
    }

    pub fn metadata(&self) -> &PersistedRepositoryAuthority {
        self.snapshot
            .repository_authority
            .as_ref()
            .expect("repository authority state always carries metadata")
    }

    pub fn roots(&self) -> &RootBundle {
        &self.metadata().roots
    }

    fn authenticated_gitlinks(&self) -> &BTreeSet<(ArtifactId, GitObjectId)> {
        &self.authenticated_gitlinks
    }

    /// Resolve one repository ref against this exact authority generation.
    ///
    /// Symbolic refs are followed only through the persisted ref state carried
    /// by this lease. Missing refs remain missing and cycles fail closed.
    pub fn resolve_ref_target(&self, name: &RefName) -> Result<Option<RefTarget>, KinDbError> {
        resolve_symbolic_ref_target(self.metadata(), name)
    }

    /// Resolve one already-read target to its native semantic change.
    ///
    /// External annotated tags peel through the CAS-validated Git authority
    /// closure stored in this same lease; this never consults a Git checkout,
    /// object directory, or filesystem projection.
    pub fn resolve_target_change_id(
        &self,
        target: &RefTarget,
    ) -> Result<SemanticChangeId, KinDbError> {
        target_change_id(self.metadata(), target)
    }

    /// Materialize one workspace-scoped, non-authoritative query snapshot from
    /// this exact authority generation.
    ///
    /// Repository-v6 authority deliberately persists immutable semantic
    /// history plus exact per-workspace trees and semantic overlays without a
    /// global "current" graph: divergent refs and dirty workspaces make such a
    /// cache ambiguous. This method resolves the workspace base from this
    /// coherent read lease, then atomically applies its cumulative semantic
    /// overlay and exact graph-owned tree. The result has no repository
    /// authority envelope and is safe to hand to
    /// [`InMemoryGraph`] for daemon, MCP, editor, benchmark, or VFS reads.
    ///
    /// Unsupported languages, configuration, binary artifacts, symlinks, and
    /// gitlinks are preserved through `WorkspaceState::tree`; no filesystem or
    /// Git fallback participates in materialization.
    pub fn workspace_graph_snapshot(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<GraphSnapshot>, KinDbError> {
        let Some(workspace) = self
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| &workspace.workspace_id == workspace_id)
        else {
            return Ok(None);
        };

        materialize_workspace_graph_snapshot(self.snapshot(), self.metadata(), workspace).map(Some)
    }
}

fn extend_authenticated_gitlinks<'a>(
    authenticated: &mut BTreeSet<(ArtifactId, GitObjectId)>,
    changes: impl IntoIterator<Item = &'a kin_model::SemanticChange>,
) {
    for change in changes {
        if !matches!(change.origin, kin_model::ChangeOrigin::GitCommit { .. }) {
            continue;
        }
        authenticated.extend(change.tree_deltas.iter().filter_map(|delta| {
            let new = delta.new_state()?;
            let TreeEntry::Gitlink { target } = new.entry else {
                return None;
            };
            Some((delta.artifact_id(), target))
        }));
    }
}

impl VersionedAuthorityState for RepositoryAuthorityState {
    fn generation(&self) -> Generation {
        self.metadata().roots.generation
    }
}

struct RepositorySnapshotPersistence<B: StorageBackend + ?Sized> {
    backend: Arc<B>,
    repository_id: RepositoryId,
    /// Backend CAS cursor, not the logical repository generation.
    ///
    /// GCS object generations are provider-assigned opaque versions (for
    /// example 100, 101, ...), while `RootBundle::generation` is Kin's
    /// contiguous logical sequence (0, 1, ...). They must never be compared
    /// or substituted for one another.
    backend_cursor: Mutex<SnapshotCursor>,
}

impl<B: StorageBackend + ?Sized> RepositorySnapshotPersistence<B> {
    fn record_save_outcome(
        cursor: &mut SnapshotCursor,
        outcome: SnapshotSaveOutcome,
    ) -> PersistOutcome {
        match outcome {
            SnapshotSaveOutcome::Committed {
                cursor: committed_cursor,
            } if committed_cursor != *cursor => {
                *cursor = committed_cursor;
                PersistOutcome::Committed
            }
            SnapshotSaveOutcome::Committed {
                cursor: committed_cursor,
            } => PersistOutcome::Indeterminate(KinDbError::StorageError(format!(
                "snapshot backend acknowledged authority without advancing its CAS cursor from {}",
                committed_cursor.backend_generation()
            ))),
            SnapshotSaveOutcome::NotCommitted(error) => PersistOutcome::NotCommitted(error),
            SnapshotSaveOutcome::Indeterminate(error) => PersistOutcome::Indeterminate(error),
        }
    }

    /// Every successor persisted here descends from an open that established
    /// complete history validity, and carries its own new changes through
    /// `validate_history_replay` in `prepare_successor`. So the bytes being
    /// written are validated bytes, and the durable record says exactly that.
    fn persist_bytes(&self, bytes: &[u8], cursor: &mut SnapshotCursor) -> PersistOutcome {
        let outcome = self.backend.save_snapshot_validated(
            self.repository_id.as_str(),
            bytes,
            *cursor,
            Some(HISTORY_VALIDATION_VERSION),
        );
        Self::record_save_outcome(cursor, outcome)
    }
}

impl RepositorySnapshotPersistence<LocalFileBackend> {
    fn persist_and_freeze(
        &self,
        next: &RepositoryAuthorityState,
    ) -> RetainedPersistOutcome<LocalAuthorityFreezeLock> {
        let bytes = match next.snapshot.to_bytes() {
            Ok(bytes) => bytes,
            Err(error) => return RetainedPersistOutcome::NotCommitted(error),
        };
        let mut cursor = self.backend_cursor.lock();
        match self.backend.save_snapshot_and_freeze(
            self.repository_id.as_str(),
            &bytes,
            *cursor,
            Some(HISTORY_VALIDATION_VERSION),
        ) {
            Ok((committed_cursor, retained)) if committed_cursor != *cursor => {
                *cursor = committed_cursor;
                RetainedPersistOutcome::Committed { retained }
            }
            Ok((committed_cursor, _)) => RetainedPersistOutcome::Indeterminate(storage(format!(
                "snapshot backend acknowledged authority without advancing its CAS cursor from {}",
                committed_cursor.backend_generation()
            ))),
            Err(error @ KinDbError::SnapshotPersistenceIndeterminate(_)) => {
                RetainedPersistOutcome::Indeterminate(error)
            }
            Err(error) => RetainedPersistOutcome::NotCommitted(error),
        }
    }
}

impl<B: StorageBackend + ?Sized + 'static> DurableAuthorityPersistence<RepositoryAuthorityState>
    for RepositorySnapshotPersistence<B>
{
    fn persist(
        &self,
        _expected_logical_generation: Generation,
        next: &RepositoryAuthorityState,
    ) -> PersistOutcome {
        let bytes = match next.snapshot.to_bytes() {
            Ok(bytes) => bytes,
            Err(error) => return PersistOutcome::NotCommitted(error),
        };
        let mut cursor = self.backend_cursor.lock();
        self.persist_bytes(&bytes, &mut cursor)
    }

    fn reconcile(
        &self,
        _expected_logical_generation: Generation,
        next: &RepositoryAuthorityState,
    ) -> PersistOutcome {
        let bytes = match next.snapshot.to_bytes() {
            Ok(bytes) => bytes,
            Err(error) => return PersistOutcome::NotCommitted(error),
        };
        let mut cursor = self.backend_cursor.lock();
        let installed = match self
            .backend
            .load_snapshot_authority(self.repository_id.as_str())
        {
            Ok(installed) => installed,
            Err(error) => return PersistOutcome::Indeterminate(error),
        };

        match installed {
            Some(authority)
                if authority.snapshot_generation != authority.head_generation =>
            {
                PersistOutcome::NotCommitted(storage(format!(
                    "repository {} authority advanced through an incremental journal while an exact full-snapshot commit was indeterminate",
                    self.repository_id
                )))
            }
            Some(authority) if authority.snapshot_bytes == bytes => {
                let installed_cursor = authority.cursor();
                if installed_cursor == *cursor {
                    return PersistOutcome::Indeterminate(storage(format!(
                        "repository {} exposes the pending successor bytes without advancing backend cursor {}",
                        self.repository_id,
                        cursor.backend_generation()
                    )));
                }
                *cursor = installed_cursor;
                PersistOutcome::Committed
            }
            Some(authority) if authority.cursor() != *cursor => {
                PersistOutcome::NotCommitted(storage(format!(
                    "repository {} backend authority advanced from cursor {} to {} with different snapshot bytes while a commit was indeterminate",
                    self.repository_id,
                    cursor.backend_generation(),
                    authority.cursor().backend_generation()
                )))
            }
            Some(_) => self.persist_bytes(&bytes, &mut cursor),
            None if *cursor == SnapshotCursor::INITIAL => self.persist_bytes(&bytes, &mut cursor),
            None => PersistOutcome::Indeterminate(storage(format!(
                "repository {} backend authority disappeared while reconciling cursor {}",
                self.repository_id,
                cursor.backend_generation()
            ))),
        }
    }
}

/// Durable graph-first repository authority.
///
/// This is the only public mutation surface for an authority-bearing v13
/// snapshot. Mutable `InMemoryGraph` remains available for derived query
/// preparation and legacy non-authority graphs, but is never stored inside
/// this publication cell.
pub struct RepositoryAuthorityManager<B: StorageBackend + ?Sized + 'static> {
    repository_id: RepositoryId,
    backend: Arc<B>,
    publication: AuthorityPublication<RepositoryAuthorityState, RepositorySnapshotPersistence<B>>,
    /// Whether the open that produced this manager trusted a durable history
    /// validation rather than replaying the whole history.
    opened_by_history_validation: bool,
}

/// Exclusive, cross-process lease over one fully revalidated local repository
/// authority generation.
///
/// The existing per-repository storage lock remains held until this value is
/// dropped. Namespace transitions such as exact export/eject must keep the
/// guard alive through their final projection check and atomic metadata move.
/// The guard cannot be created for an unpersisted repository or a stale root
/// bundle.
#[must_use = "dropping the guard releases the local repository authority freeze"]
#[derive(Debug)]
pub struct LocalRepositoryAuthorityFreeze {
    state: RepositoryAuthorityState,
    _lock: LocalAuthorityFreezeLock,
}

impl LocalRepositoryAuthorityFreeze {
    /// Exact persisted authority reloaded after the exclusive lock was held.
    pub fn authority(&self) -> &RepositoryAuthorityState {
        &self.state
    }

    /// Cryptographic root bundle protected by this freeze.
    pub fn roots(&self) -> &RootBundle {
        self.state.roots()
    }
}

struct FrozenLocalBodyBackend<'a> {
    backend: &'a LocalFileBackend,
    freeze: &'a LocalAuthorityFreezeLock,
}

impl FrozenLocalBodyBackend<'_> {
    fn unsupported(operation: &str) -> KinDbError {
        storage(format!(
            "{operation} is unavailable through a frozen local body-validation view"
        ))
    }
}

impl StorageBackend for FrozenLocalBodyBackend<'_> {
    fn load_snapshot(&self, _repo_id: &str) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
        Err(Self::unsupported("snapshot load"))
    }

    fn load_source_blob(
        &self,
        repo_id: &str,
        digest: [u8; 32],
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        self.load_source_blob_bounded(repo_id, digest, MAX_SOURCE_BLOB_BYTES)
    }

    fn load_source_blob_bounded(
        &self,
        repo_id: &str,
        digest: [u8; 32],
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        self.backend
            .load_source_blob_bounded_while_frozen(self.freeze, repo_id, digest, max_bytes)
    }

    fn with_verified_source_blob_batch(
        &self,
        repo_id: &str,
        operation: &mut dyn FnMut(&dyn VerifiedSourceBlobBatch) -> Result<(), KinDbError>,
    ) -> Result<(), KinDbError> {
        self.backend
            .with_verified_source_blob_batch_while_frozen(self.freeze, repo_id, operation)
    }

    fn save_snapshot(
        &self,
        _repo_id: &str,
        _data: &[u8],
        _expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        Err(Self::unsupported("snapshot save"))
    }

    fn save_delta(
        &self,
        _repo_id: &str,
        _delta_data: &[u8],
        _base_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        Err(Self::unsupported("delta save"))
    }

    fn load_deltas_since(
        &self,
        _repo_id: &str,
        _since_gen: Generation,
    ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
        Err(Self::unsupported("delta load"))
    }

    fn clear_deltas(&self, _repo_id: &str) -> Result<(), KinDbError> {
        Err(Self::unsupported("delta cleanup"))
    }

    fn save_overlay(
        &self,
        _repo_id: &str,
        _session_id: &str,
        _data: &[u8],
    ) -> Result<(), KinDbError> {
        Err(Self::unsupported("overlay save"))
    }

    fn load_overlay(
        &self,
        _repo_id: &str,
        _session_id: &str,
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        Err(Self::unsupported("overlay load"))
    }

    fn delete_overlay(&self, _repo_id: &str, _session_id: &str) -> Result<(), KinDbError> {
        Err(Self::unsupported("overlay delete"))
    }

    fn list_repos(&self) -> Result<Vec<String>, KinDbError> {
        Err(Self::unsupported("repository listing"))
    }
}

impl<B: StorageBackend + ?Sized + 'static> RepositoryAuthorityManager<B> {
    /// Open existing authority or prepare an unpersisted generation-zero repo.
    ///
    /// Full history validation is the default and the fallback. It is skipped
    /// only for a reopen that carries a durable validation record naming the
    /// exact bytes being opened; see [`verified_history_validation`].
    pub fn open(repository_id: RepositoryId, backend: Arc<B>) -> Result<Self, KinDbError> {
        Self::open_with_payload_stats(repository_id, backend).map(|(manager, _receipt)| manager)
    }

    /// Open authority and return the immutable payload receipt from that open.
    ///
    /// `Some` describes the exact persisted snapshot and acknowledged deltas
    /// selected by the same coherent recovery that built the manager. `None`
    /// means no persisted snapshot existed and generation zero was constructed
    /// only in memory. The receipt does not update after later commits.
    pub fn open_with_payload_stats(
        repository_id: RepositoryId,
        backend: Arc<B>,
    ) -> Result<(Self, Option<AuthorityPayloadStats>), KinDbError> {
        let started = std::time::Instant::now();
        let recovered = load_recovered_repository_authority(
            backend.as_ref(),
            repository_id.as_str(),
            HISTORY_VALIDATION_VERSION,
        )?;
        let payload_stats = recovered.as_ref().map(|recovered| recovered.payload_stats);
        let recovered_authority = recovered.is_some();
        let recovered_at = started.elapsed();
        let reopen_proof = recovered
            .as_ref()
            .filter(|recovered| recovered.reused_complete_validation)
            .and_then(|recovered| {
                verified_history_validation(&repository_id, &recovered.recovered)
            });
        // The digest of the bytes that were actually loaded. Binding a record
        // must never re-serialize the snapshot to obtain one: the persist path
        // deliberately writes the original bytes rather than re-serialized ones,
        // so a round-trip digest is not guaranteed to be the persisted digest.
        let loaded_digest = recovered
            .as_ref()
            .filter(|recovered| recovered.recovered.deltas_applied == 0)
            .map(|recovered| recovered.recovered.snapshot_sha256.clone());
        let (snapshot, backend_cursor) = if let Some(recovered) = recovered {
            let recovered = recovered.recovered;
            if recovered.deltas_seen != 0 {
                return Err(storage(format!(
                    "repository {} has an incremental graph journal; repository authority requires full-snapshot CAS only",
                    repository_id
                )));
            }
            let metadata = recovered
                .snapshot
                .repository_authority
                .as_ref()
                .ok_or_else(|| {
                    storage(format!(
                        "repository {} snapshot has no v13 authority envelope",
                        repository_id
                    ))
                })?;
            if metadata.repository_id != repository_id {
                return Err(storage(format!(
                    "snapshot authority belongs to {}, not {}",
                    metadata.repository_id, repository_id
                )));
            }
            (
                recovered.snapshot,
                SnapshotCursor::from_backend_generation(recovered.generation),
            )
        } else {
            let mut snapshot = GraphSnapshot::empty();
            snapshot.repository_authority = Some(PersistedRepositoryAuthority::empty(
                repository_id.clone(),
                &snapshot,
            )?);
            (snapshot, SnapshotCursor::INITIAL)
        };

        // Recovery either performed storage admission itself or proved that
        // these exact, journal-free bytes already passed this validator
        // version. Validate only the generation-zero authority constructed
        // here; validating recovered authority again would repeat the same
        // root-bundle and envelope checks over identical bytes.
        if !recovered_authority {
            snapshot.validate_storage_admission()?;
        }
        let structural_at = started.elapsed();

        // Whole-history replay is the one step a validation record buys back.
        // It resolves the complete graph at every change, so it grows with
        // history length times resolved graph size, and at real repository
        // scale it is minutes of work to re-derive a conclusion already
        // reached about these exact bytes.
        if reopen_proof.is_none() {
            let all_changes: Vec<_> = snapshot.changes.values().cloned().collect();
            validate_history_replay(&snapshot, &all_changes)?;
        }
        let replay_at = started.elapsed();

        // Every persisted body is re-verified against its content address on
        // every open, proof or no proof. This is linear in stored bytes rather
        // than superlinear in history, and keeping it unconditional is what
        // keeps "a tampered store still refuses" true of the fast path and not
        // only of the fallback.
        validate_all_authority_bodies(backend.as_ref(), &repository_id, &snapshot)?;
        let bodies_at = started.elapsed();
        // Reopen latency at real repository scale is a standing concern, and it
        // is not obvious from outside which phase dominates. Report the split
        // rather than leaving it to be inferred from a stopwatch.
        tracing::debug!(
            repository = %repository_id,
            by_history_validation = reopen_proof.is_some(),
            recover_ms = recovered_at.as_millis(),
            structural_ms = (structural_at - recovered_at).as_millis(),
            replay_ms = (replay_at - structural_at).as_millis(),
            bodies_ms = (bodies_at - replay_at).as_millis(),
            total_ms = bodies_at.as_millis(),
            "repository authority open"
        );

        let initial = RepositoryAuthorityState::from_validated_snapshot(snapshot);
        let persistence = RepositorySnapshotPersistence {
            backend: Arc::clone(&backend),
            repository_id: repository_id.clone(),
            backend_cursor: Mutex::new(backend_cursor),
        };
        let manager = Self {
            repository_id,
            backend,
            publication: AuthorityPublication::new(initial, persistence),
            opened_by_history_validation: reopen_proof.is_some(),
        };
        if let Some(generation) = reopen_proof {
            tracing::debug!(
                repository = %manager.repository_id,
                generation,
                "repository authority reopened against a durable history validation"
            );
        } else if let Some(digest) = loaded_digest {
            manager.bind_history_validation(backend_cursor, &digest);
        }
        Ok((manager, payload_stats))
    }

    /// Whether this open trusted a durable history validation instead of
    /// replaying the whole history.
    ///
    /// Surfaced so operators and tests can tell the fast path from the slow one
    /// directly, rather than inferring it from how long an open took.
    pub const fn opened_by_history_validation(&self) -> bool {
        self.opened_by_history_validation
    }

    /// Record that the state just validated in full is durably validated, so
    /// the next open of these exact bytes does not repeat the work.
    ///
    /// `digest` must be the digest of the bytes this open actually loaded, not
    /// a digest of a re-serialized snapshot. Persistence writes the original
    /// bytes rather than re-serialized ones precisely because a round trip is
    /// not promised to be byte-identical, and a record that named
    /// re-serialized bytes would silently never verify.
    ///
    /// Best effort by construction: a repository that cannot record this is
    /// still correct, it is only slow again next time. Failing an open that
    /// passed complete validation because a cache write lost a race would be
    /// strictly worse than revalidating.
    fn bind_history_validation(&self, backend_cursor: SnapshotCursor, digest: &str) {
        let generation = backend_cursor.backend_generation();
        if generation == SnapshotCursor::INITIAL.backend_generation() {
            return;
        }
        match self.backend.record_history_validation(
            self.repository_id.as_str(),
            generation,
            digest,
            HISTORY_VALIDATION_VERSION,
        ) {
            Ok(true) => tracing::debug!(
                repository = %self.repository_id,
                generation,
                "recorded a durable history validation for the opened authority"
            ),
            Ok(false) => {}
            Err(error) => tracing::debug!(
                repository = %self.repository_id,
                generation,
                error = %error,
                "could not record a durable history validation; the next open revalidates in full"
            ),
        }
    }

    /// Load one coherent authority generation for an entire request.
    pub fn read_authority(&self) -> AuthorityReadLease<RepositoryAuthorityState> {
        self.publication.read()
    }

    /// Persist exact bytes in the immutable CAS without granting authority.
    pub fn save_source_blob(&self, digest: Hash256, data: &[u8]) -> Result<(), KinDbError> {
        self.backend
            .save_source_blob(self.repository_id.as_str(), *digest.as_bytes(), data)
    }

    /// Load exact immutable source bytes from repository-owned CAS authority.
    ///
    /// This is intentionally bounded and re-verifies the returned bytes at
    /// the manager boundary even when a backend already promises integrity.
    /// Missing bodies remain missing: authority paths never repair from Git
    /// or a filesystem object directory.
    pub fn load_source_blob(&self, digest: Hash256) -> Result<Option<Vec<u8>>, KinDbError> {
        let Some(data) = self.backend.load_source_blob_bounded(
            self.repository_id.as_str(),
            *digest.as_bytes(),
            MAX_SOURCE_BLOB_BYTES,
        )?
        else {
            return Ok(None);
        };
        let byte_len = u64::try_from(data.len()).map_err(|_| {
            storage(format!(
                "immutable source blob {} length does not fit u64",
                digest
            ))
        })?;
        validate_source_blob_size(
            byte_len,
            &format!("repository authority {}", self.repository_id),
        )?;
        verify_source_blob_digest(
            *digest.as_bytes(),
            &data,
            &format!("repository authority {}", self.repository_id),
        )?;
        Ok(Some(data))
    }

    /// Resolve one workspace's exact graph-owned admission policy from one
    /// coherent authority lease.
    ///
    /// This is the read-only authority boundary for daemon, VFS, editor, and
    /// agent admission previews. It does not inspect Git configuration or raw
    /// filesystem ignore files, and it never silently repairs missing or
    /// tampered policy bodies.
    pub fn workspace_admission_snapshot(
        &self,
        repository_id: &RepositoryId,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<WorkspaceAdmissionSnapshot>, KinDbError> {
        self.require_repository(repository_id)?;
        let lease = self.read_authority();
        let Some(workspace) = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| &workspace.workspace_id == workspace_id)
        else {
            return Ok(None);
        };
        let binding = workspace.snapshot_binding(lease.roots().clone())?;
        let overlay = local_overlay_for_workspace(lease.metadata(), workspace)?;
        let matcher = resolve_admission_matcher(
            self.backend.as_ref(),
            repository_id,
            &workspace.shared_admission_policy,
            overlay,
        )?;
        Ok(Some(WorkspaceAdmissionSnapshot {
            binding,
            case: overlay.case,
            matcher,
        }))
    }

    /// Build one daemon/VFS wire snapshot from one coherent authority lease.
    ///
    /// Blob and symlink sizes come from the immutable source CAS. Gitlinks
    /// have no local body and advertise zero. Each artifact uses a durable
    /// monotonic logical second derived only from workspace operations that
    /// touched its stable artifact identity. Unchanged files therefore retain
    /// stat identity while same-second edits still invalidate build tools.
    pub fn workspace_tree_snapshot(
        &self,
        repository_id: &RepositoryId,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<WorkspaceTreeSnapshot>, KinDbError> {
        self.require_repository(repository_id)?;
        let lease = self.read_authority();
        let Some(workspace) = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| &workspace.workspace_id == workspace_id)
        else {
            return Ok(None);
        };
        let binding = workspace.snapshot_binding(lease.roots().clone())?;
        let artifacts = workspace
            .tree
            .artifacts()
            .map(|artifact| {
                let mtime = workspace_artifact_projection_mtime(
                    lease.metadata(),
                    workspace,
                    artifact.artifact_id,
                )?;
                let size = match artifact.entry {
                    TreeEntry::Gitlink { .. } => 0,
                    entry => {
                        let digest = entry
                            .blob_identity()
                            .expect("blob and symlink entries carry CAS identity");
                        self.backend
                            .source_blob_len(repository_id.as_str(), *digest.as_bytes())?
                            .ok_or_else(|| {
                                storage(format!(
                                    "workspace projection artifact {} body {} is absent from immutable source CAS",
                                    artifact.path, digest
                                ))
                            })?
                    }
                };
                Ok(WorkspaceTreeArtifact {
                    artifact_id: artifact.artifact_id,
                    path: artifact.path.clone(),
                    entry: artifact.entry,
                    size,
                    mtime,
                })
            })
            .collect::<Result<Vec<_>, KinDbError>>()?;
        WorkspaceTreeSnapshot::new(binding, artifacts)
            .map(Some)
            .map_err(Into::into)
    }

    /// Materialize one workspace query snapshot from one coherent read lease.
    pub fn workspace_graph_snapshot(
        &self,
        repository_id: &RepositoryId,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<GraphSnapshot>, KinDbError> {
        self.require_repository(repository_id)?;
        self.read_authority().workspace_graph_snapshot(workspace_id)
    }

    /// Commit one complete repository transaction.
    pub fn commit_repository_transaction(
        &self,
        transaction: RepositoryTransaction,
    ) -> Result<RepositoryCommitReceipt, KinDbError> {
        transaction.validate()?;
        let transaction_hash = transaction.transaction_hash()?;
        let repository_id = self.repository_id.clone();
        let backend = Arc::clone(&self.backend);

        self.publication.commit(|current| {
            prepare_repository_commit_decision(
                current,
                &transaction,
                transaction_hash,
                &repository_id,
                backend.as_ref(),
            )
        })
    }
}

impl RepositoryAuthorityManager<LocalFileBackend> {
    /// Commit one complete local repository transaction and return a freeze
    /// that still holds the exact backend lock used for its durable CAS.
    ///
    /// A successful new commit has no release/reacquire window: the local
    /// authority record is installed, the immutable in-memory successor is
    /// published, and the guard is returned while the same OS lock remains
    /// held. An idempotent replay acquires the lock and reloads the exact
    /// current authority before returning its guard.
    pub fn commit_repository_transaction_and_freeze(
        &self,
        transaction: RepositoryTransaction,
    ) -> Result<(RepositoryCommitReceipt, LocalRepositoryAuthorityFreeze), KinDbError> {
        transaction.validate()?;
        let transaction_hash = transaction.transaction_hash()?;
        let repository_id = self.repository_id.clone();
        let backend = Arc::clone(&self.backend);

        self.publication.commit_and_retain(
            |current| {
                prepare_repository_commit_decision(
                    current,
                    &transaction,
                    transaction_hash,
                    &repository_id,
                    backend.as_ref(),
                )
            },
            |_, current| self.freeze_exact_state(current),
            |persistence, _, next| match persistence.persist_and_freeze(next) {
                RetainedPersistOutcome::Committed { retained } => {
                    RetainedPersistOutcome::Committed {
                        retained: LocalRepositoryAuthorityFreeze {
                            state: next.clone(),
                            _lock: retained,
                        },
                    }
                }
                RetainedPersistOutcome::NotCommitted(error) => {
                    RetainedPersistOutcome::NotCommitted(error)
                }
                RetainedPersistOutcome::Indeterminate(error) => {
                    RetainedPersistOutcome::Indeterminate(error)
                }
            },
        )
    }

    /// Freeze one expected local authority generation for a namespace
    /// transition.
    ///
    /// This acquires the already-existing per-repository OS lock without
    /// creating storage, reloads the full persisted snapshot while holding
    /// that lock, repeats every repository-v6 structural/history/body
    /// validation performed by [`RepositoryAuthorityManager::open`], and
    /// requires its roots to match both the caller's expectation and this
    /// manager's published state. Competing local writers remain blocked until
    /// the returned guard is dropped.
    pub fn freeze_current_authority(
        &self,
        expected_roots: &RootBundle,
    ) -> Result<LocalRepositoryAuthorityFreeze, KinDbError> {
        let published = self.read_authority();
        if published.roots() != expected_roots {
            return Err(ModelError::Conflict(format!(
                "repository {} published authority moved from the expected root bundle before local freeze",
                self.repository_id
            ))
            .into());
        }
        self.freeze_exact_state(&published)
    }

    fn freeze_exact_state(
        &self,
        expected: &RepositoryAuthorityState,
    ) -> Result<LocalRepositoryAuthorityFreeze, KinDbError> {
        let locked = self
            .backend
            .freeze_existing_authority(self.repository_id.as_str())?;
        let snapshot = GraphSnapshot::from_bytes(&locked.authority().snapshot_bytes)?;
        let metadata = snapshot.repository_authority.as_ref().ok_or_else(|| {
            storage(format!(
                "repository {} frozen snapshot has no v13 authority envelope",
                self.repository_id
            ))
        })?;
        if metadata.repository_id != self.repository_id {
            return Err(storage(format!(
                "frozen snapshot authority belongs to {}, not {}",
                metadata.repository_id, self.repository_id
            )));
        }
        snapshot.validate_storage_admission()?;
        let all_changes: Vec<_> = snapshot.changes.values().cloned().collect();
        validate_history_replay(&snapshot, &all_changes)?;
        let body_backend = FrozenLocalBodyBackend {
            backend: self.backend.as_ref(),
            freeze: &locked,
        };
        validate_all_authority_bodies(&body_backend, &self.repository_id, &snapshot)?;

        let state = RepositoryAuthorityState::from_validated_snapshot(snapshot);
        if state.roots() != expected.roots() {
            return Err(ModelError::Conflict(format!(
                "repository {} persisted authority moved from the expected root bundle while local freeze was acquired",
                self.repository_id
            ))
            .into());
        }
        Ok(LocalRepositoryAuthorityFreeze {
            state,
            _lock: locked,
        })
    }
}

impl<B: StorageBackend + ?Sized + 'static> RepositoryAuthorityStore
    for RepositoryAuthorityManager<B>
{
    type Error = KinDbError;

    fn commit_repository_transaction(
        &self,
        transaction: RepositoryTransaction,
    ) -> Result<RepositoryCommitReceipt, Self::Error> {
        RepositoryAuthorityManager::commit_repository_transaction(self, transaction)
    }

    fn get_repository_ref(
        &self,
        repository_id: &RepositoryId,
        name: &RefName,
    ) -> Result<Option<RepositoryRef>, Self::Error> {
        self.require_repository(repository_id)?;
        Ok(self
            .read_authority()
            .metadata()
            .ref_state
            .refs
            .iter()
            .find(|repository_ref| &repository_ref.name == name)
            .cloned())
    }

    fn list_repository_refs(
        &self,
        repository_id: &RepositoryId,
    ) -> Result<Vec<RepositoryRef>, Self::Error> {
        self.require_repository(repository_id)?;
        Ok(self.read_authority().metadata().ref_state.refs.clone())
    }

    fn resolve_external_alias(
        &self,
        repository_id: &RepositoryId,
        oid: &GitObjectId,
    ) -> Result<Option<SemanticChangeId>, Self::Error> {
        self.require_repository(repository_id)?;
        Ok(self
            .read_authority()
            .metadata()
            .aliases
            .iter()
            .find(|alias| &alias.oid == oid)
            .map(|alias| alias.change_id))
    }

    fn workspace_snapshot_binding(
        &self,
        repository_id: &RepositoryId,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<WorkspaceSnapshotBinding>, Self::Error> {
        self.require_repository(repository_id)?;
        let lease = self.read_authority();
        lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| &workspace.workspace_id == workspace_id)
            .map(|workspace| workspace.snapshot_binding(lease.roots().clone()))
            .transpose()
            .map_err(Into::into)
    }

    fn get_workspace_state(
        &self,
        repository_id: &RepositoryId,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<WorkspaceState>, Self::Error> {
        self.require_repository(repository_id)?;
        Ok(self
            .read_authority()
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| &workspace.workspace_id == workspace_id)
            .cloned())
    }
}

impl<B: StorageBackend + ?Sized + 'static> RepositoryAuthorityManager<B> {
    fn require_repository(&self, repository_id: &RepositoryId) -> Result<(), KinDbError> {
        if repository_id == &self.repository_id {
            Ok(())
        } else {
            Err(ModelError::InvalidOperation(format!(
                "requested repository {} from authority for {}",
                repository_id, self.repository_id
            ))
            .into())
        }
    }
}

fn prepare_repository_commit_decision<B: StorageBackend + ?Sized>(
    current: &RepositoryAuthorityState,
    transaction: &RepositoryTransaction,
    transaction_hash: Hash256,
    repository_id: &RepositoryId,
    backend: &B,
) -> Result<AuthorityCommitDecision<RepositoryAuthorityState, RepositoryCommitReceipt>, KinDbError>
{
    let metadata = current.metadata();
    if &transaction.repository_id != repository_id {
        return Err(ModelError::InvalidOperation(format!(
            "transaction repository {} does not match authority repository {}",
            transaction.repository_id, repository_id
        ))
        .into());
    }

    if let Some(receipt) = metadata
        .receipts
        .iter()
        .find(|receipt| receipt.operation_id == transaction.operation_id)
    {
        if receipt.transaction_hash != transaction_hash {
            return Err(ModelError::Conflict(format!(
                "operation {} was already committed with a different transaction hash",
                transaction.operation_id
            ))
            .into());
        }
        let mut replay = receipt.clone();
        replay.outcome = RepositoryCommitOutcome::IdempotentReplay;
        return Ok(AuthorityCommitDecision::IdempotentReplay { output: replay });
    }

    if transaction.expected_generation != current.generation()
        || transaction.expected_roots != *current.roots()
    {
        return Err(ModelError::Conflict(format!(
            "repository {} authority moved from expected generation/root bundle",
            repository_id
        ))
        .into());
    }

    let (next, receipt) = prepare_successor(current, transaction, transaction_hash, backend)?;
    Ok(AuthorityCommitDecision::Publish {
        next,
        output: receipt,
    })
}

fn prepare_successor<B: StorageBackend + ?Sized>(
    current: &RepositoryAuthorityState,
    transaction: &RepositoryTransaction,
    transaction_hash: Hash256,
    backend: &B,
) -> Result<(RepositoryAuthorityState, RepositoryCommitReceipt), KinDbError> {
    let mut snapshot = current.snapshot.clone();
    let mut metadata = snapshot
        .repository_authority
        .take()
        .expect("repository authority state always carries metadata");

    admit_external_objects(
        backend,
        &transaction.repository_id,
        &mut metadata,
        &transaction.external_objects,
    )?;
    admit_changes(&mut snapshot, &transaction.changes)?;
    admit_aliases(&snapshot, &mut metadata, &transaction.aliases)?;
    apply_git_authority(backend, &snapshot, &mut metadata, transaction)?;
    metadata.admission_policies = derive_admission_policies(&snapshot.changes)?;

    apply_ref_mutations(&snapshot, &mut metadata, transaction)?;
    apply_local_overlay(&mut metadata, transaction)?;
    validate_new_local_overlay_bodies(
        backend,
        &transaction.repository_id,
        transaction.local_overlay_delta.as_ref(),
    )?;
    apply_workspace(backend, &snapshot, &mut metadata, transaction)?;
    apply_merge_transaction(&mut metadata, transaction)?;
    validate_merge_transaction_delta_bodies(
        backend,
        &transaction.repository_id,
        transaction.merge_transaction_delta.as_ref(),
    )?;
    verify_transaction_admission(backend, current, &snapshot, &metadata, transaction)?;
    validate_new_change_bodies(
        backend,
        &transaction.repository_id,
        &transaction.changes,
        &metadata.admission_policies,
    )?;
    validate_history_replay(&snapshot, &transaction.changes)?;

    let next_generation = current
        .generation()
        .checked_add(1)
        .ok_or_else(|| storage("repository generation exhausted".to_string()))?;
    let roots_before = current.roots().clone();
    let mut operation = RepositoryOperationRecord {
        operation_id: transaction.operation_id,
        repository_id: transaction.repository_id.clone(),
        transaction_hash,
        actor: transaction.actor.clone(),
        committed_at: Timestamp::now(),
        git_authority_delta: transaction.git_authority_delta.clone(),
        ref_mutations: transaction.ref_mutations.clone(),
        default_ref_mutation: transaction.default_ref_mutation.clone(),
        workspace_mutation: transaction.workspace_mutation.clone(),
        local_overlay_delta: transaction.local_overlay_delta.clone(),
        merge_transaction_delta: transaction.merge_transaction_delta.clone(),
        roots_before: roots_before.clone(),
        roots_after: placeholder_roots(next_generation),
    };
    operation.validate()?;
    metadata.operation_log.push(operation.clone());
    metadata.roots = compute_roots(&snapshot, &metadata, next_generation)?;
    operation.roots_after = metadata.roots.clone();
    *metadata
        .operation_log
        .last_mut()
        .expect("operation was just appended") = operation.clone();

    let receipt = RepositoryCommitReceipt {
        operation_id: transaction.operation_id,
        repository_id: transaction.repository_id.clone(),
        transaction_hash,
        outcome: RepositoryCommitOutcome::Committed,
        generation: next_generation,
        roots_before,
        roots_after: metadata.roots.clone(),
        operation,
    };
    receipt.validate()?;
    metadata.receipts.push(receipt.clone());
    metadata
        .receipts
        .sort_by_key(|persisted| persisted.operation_id);
    snapshot.repository_authority = Some(metadata);
    snapshot.validate_storage_admission()?;

    Ok((
        RepositoryAuthorityState::from_validated_successor(current, snapshot, &transaction.changes),
        receipt,
    ))
}

fn admit_external_objects<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    metadata: &mut PersistedRepositoryAuthority,
    incoming: &[ExternalObjectRecord],
) -> Result<(), KinDbError> {
    let mut objects: BTreeMap<ExternalObjectId, ExternalObjectRecord> = metadata
        .external_objects
        .iter()
        .cloned()
        .map(|record| (record.object, record))
        .collect();
    for record in incoming {
        let body = load_exact_body(
            backend,
            repository_id,
            record.body_hash,
            record.body_len,
            &format!("external object {}", record.object.oid),
        )?;
        record.validate_raw(&body)?;
        if let Some(existing) = objects.get(&record.object) {
            if existing != record {
                return Err(ModelError::Conflict(format!(
                    "external object {} already has a different descriptor",
                    record.object.oid
                ))
                .into());
            }
        } else {
            objects.insert(record.object, record.clone());
        }
    }
    metadata.external_objects = objects.into_values().collect();
    Ok(())
}

fn admit_changes(
    snapshot: &mut GraphSnapshot,
    incoming: &[kin_model::SemanticChange],
) -> Result<(), KinDbError> {
    for change in incoming {
        if let Some(existing) = snapshot.changes.get(&change.id) {
            if existing != change {
                return Err(KinDbError::DuplicateChange(change.id.to_string()));
            }
        } else {
            snapshot.changes.insert(change.id, change.clone());
        }
    }

    // Rebuild the inverse index from canonical history. Ordered and repeated
    // parent identity stays in each change; this derived lookup needs each
    // parent→child edge only once.
    let mut children: BTreeMap<SemanticChangeId, BTreeSet<SemanticChangeId>> = BTreeMap::new();
    for change in snapshot.changes.values() {
        for parent in &change.parents {
            children.entry(*parent).or_default().insert(change.id);
        }
    }
    snapshot.change_children = children
        .into_iter()
        .map(|(parent, children)| (parent, children.into_iter().collect()))
        .collect();

    // A repository with multiple refs has no single current entity/relation
    // revision view. Exact target replay derives revisions from the immutable
    // change DAG; persisting a global revision cache would silently choose an
    // ordering across divergent histories.
    snapshot.entity_revisions.clear();
    Ok(())
}

fn validate_unscoped_history_caches(snapshot: &GraphSnapshot) -> Result<(), KinDbError> {
    let mut expected_children: HashMap<SemanticChangeId, Vec<SemanticChangeId>> = HashMap::new();
    let mut children: BTreeMap<SemanticChangeId, BTreeSet<SemanticChangeId>> = BTreeMap::new();
    for change in snapshot.changes.values() {
        for parent in &change.parents {
            children.entry(*parent).or_default().insert(change.id);
        }
    }
    expected_children.extend(
        children
            .into_iter()
            .map(|(parent, children)| (parent, children.into_iter().collect())),
    );
    if snapshot.change_children != expected_children {
        return Err(storage(
            "repository change-child index does not derive exactly from immutable history"
                .to_string(),
        ));
    }

    if !snapshot.entities.is_empty()
        || !snapshot.relations.is_empty()
        || !snapshot.outgoing.is_empty()
        || !snapshot.incoming.is_empty()
        || !snapshot.external_references.is_empty()
        || !snapshot.resolved_tree.is_empty()
        || !snapshot.entity_revisions.is_empty()
        || !snapshot.shallow_files.is_empty()
        || !snapshot.file_layouts.is_empty()
        || !snapshot.structured_artifacts.is_empty()
        || !snapshot.opaque_artifacts.is_empty()
    {
        return Err(storage(
            "repository authority snapshot contains an unscoped prepared graph/tree view; resolve an explicit ref or workspace instead"
                .to_string(),
        ));
    }
    Ok(())
}

fn admit_aliases(
    snapshot: &GraphSnapshot,
    metadata: &mut PersistedRepositoryAuthority,
    incoming: &[ExternalChangeAlias],
) -> Result<(), KinDbError> {
    let mut aliases: BTreeMap<GitObjectId, ExternalChangeAlias> = metadata
        .aliases
        .iter()
        .cloned()
        .map(|alias| (alias.oid, alias))
        .collect();
    for alias in incoming {
        let change = snapshot
            .changes
            .get(&alias.change_id)
            .ok_or_else(|| ModelError::ChangeNotFound(alias.change_id.to_string()))?;
        alias.validate_change(change)?;
        alias.validate_binding(aliases.get(&alias.oid).map(|existing| existing.change_id))?;
        aliases.entry(alias.oid).or_insert_with(|| alias.clone());
    }
    metadata.aliases = aliases.into_values().collect();
    Ok(())
}

fn apply_git_authority<B: StorageBackend + ?Sized>(
    backend: &B,
    snapshot: &GraphSnapshot,
    metadata: &mut PersistedRepositoryAuthority,
    transaction: &RepositoryTransaction,
) -> Result<(), KinDbError> {
    if let Some(delta) = &transaction.git_authority_delta {
        if metadata.git_external_authority.as_ref() != delta.old.as_ref() {
            return Err(ModelError::Conflict(format!(
                "Git external authority for repository {} no longer matches its exact old-state lease",
                transaction.repository_id
            ))
            .into());
        }
        metadata.git_external_authority = delta.new.clone();
    }

    validate_transaction_git_projection_membership(
        transaction,
        metadata.git_external_authority.as_ref(),
    )?;
    validate_git_authority_shape_and_projection(snapshot, metadata)?;
    if transaction.git_authority_delta.is_some() {
        validate_git_authority_bodies(
            backend,
            &transaction.repository_id,
            metadata.git_external_authority.as_ref(),
        )?;
    }
    Ok(())
}

fn validate_transaction_git_projection_membership(
    transaction: &RepositoryTransaction,
    authority: Option<&GitExternalAuthority>,
) -> Result<(), KinDbError> {
    let projected_oids = authority
        .into_iter()
        .flat_map(|authority| {
            authority
                .commit_projections
                .iter()
                .map(|projection| projection.commit_oid)
        })
        .collect::<BTreeSet<_>>();

    for alias in &transaction.aliases {
        if !projected_oids.contains(&alias.oid) {
            return Err(ModelError::InvalidOperation(format!(
                "transaction alias {} has no commit projection in the resulting Git external authority",
                alias.oid
            ))
            .into());
        }
    }
    for change in &transaction.changes {
        if let kin_model::ChangeOrigin::GitCommit { oid } = change.origin {
            if !projected_oids.contains(&oid) {
                return Err(ModelError::InvalidOperation(format!(
                    "Git-origin change {} for {} has no commit projection in the resulting Git external authority",
                    change.id, oid
                ))
                .into());
            }
        }
    }
    Ok(())
}

fn validate_git_authority_shape_and_projection(
    snapshot: &GraphSnapshot,
    metadata: &PersistedRepositoryAuthority,
) -> Result<(), KinDbError> {
    let Some(authority) = &metadata.git_external_authority else {
        return validate_persisted_git_alias_coverage(snapshot, metadata);
    };
    if authority.repository_id != metadata.repository_id {
        return Err(ModelError::InvalidOperation(format!(
            "Git external authority belongs to repository {}, not {}",
            authority.repository_id, metadata.repository_id
        ))
        .into());
    }
    authority.validate_shape().map_err(|error| {
        ModelError::InvalidOperation(format!("invalid Git external authority shape: {error}"))
    })?;
    let closure_entries = authority
        .closure
        .objects
        .iter()
        .map(|entry| (entry.record.object, entry))
        .collect::<BTreeMap<_, _>>();

    let records = metadata
        .external_objects
        .iter()
        .map(|record| (record.object, record))
        .collect::<BTreeMap<_, _>>();
    for entry in &authority.closure.objects {
        match records.get(&entry.record.object) {
            Some(record) if **record == entry.record => {}
            Some(_) => {
                return Err(ModelError::Conflict(format!(
                    "Git authority closure object {} does not match its persisted external-object descriptor",
                    entry.record.object.oid
                ))
                .into())
            }
            None => {
                return Err(ModelError::InvalidOperation(format!(
                    "Git authority closure object {} is absent from persisted external objects",
                    entry.record.object.oid
                ))
                .into())
            }
        }
    }

    let aliases = metadata
        .aliases
        .iter()
        .map(|alias| (alias.oid, alias))
        .collect::<BTreeMap<_, _>>();
    let mut tree_targets = BTreeMap::new();
    for projection in &authority.commit_projections {
        let alias = aliases.get(&projection.commit_oid).ok_or_else(|| {
            ModelError::InvalidOperation(format!(
                "Git commit projection {} has no repository-scoped semantic alias",
                projection.commit_oid
            ))
        })?;
        let change = snapshot
            .changes
            .get(&alias.change_id)
            .ok_or_else(|| ModelError::ChangeNotFound(alias.change_id.to_string()))?;
        match change.origin {
            kin_model::ChangeOrigin::GitCommit { oid } if oid == projection.commit_oid => {}
            kin_model::ChangeOrigin::GitCommit { oid } => {
                return Err(ModelError::Conflict(format!(
                    "Git commit projection {} aliases change {} whose origin names {}",
                    projection.commit_oid, change.id, oid
                ))
                .into())
            }
            kin_model::ChangeOrigin::Native => {
                return Err(ModelError::InvalidOperation(format!(
                    "Git commit projection {} aliases native change {}",
                    projection.commit_oid, change.id
                ))
                .into())
            }
        }

        let expected_parents = projection
            .parent_oids
            .iter()
            .map(|parent_oid| {
                aliases
                    .get(parent_oid)
                    .map(|alias| alias.change_id)
                    .ok_or_else(|| {
                        ModelError::InvalidOperation(format!(
                            "Git commit projection {} parent {} has no repository-scoped semantic alias",
                            projection.commit_oid, parent_oid
                        ))
                    })
            })
            .collect::<kin_model::Result<Vec<_>>>()?;
        if change.parents != expected_parents {
            return Err(ModelError::Conflict(format!(
                "Git commit projection {} ordered parent aliases do not match semantic change {}",
                projection.commit_oid, change.id
            ))
            .into());
        }

        if tree_targets
            .insert(
                change.id,
                GitProjectionTreeTarget {
                    commit_oid: projection.commit_oid,
                    raw_tree_oid: projection.raw_tree_oid,
                },
            )
            .is_some()
        {
            return Err(ModelError::Conflict(format!(
                "more than one Git commit projection aliases semantic change {}",
                change.id
            ))
            .into());
        }
    }
    validate_git_projection_tree_replay(snapshot, &tree_targets, |raw_tree_oid| {
        materialize_git_tree(&closure_entries, raw_tree_oid)
    })?;
    validate_persisted_git_alias_coverage(snapshot, metadata)
}

#[derive(Debug, Clone, Copy)]
struct GitProjectionTreeTarget {
    commit_oid: GitObjectId,
    raw_tree_oid: GitObjectId,
}

enum GitProjectionTreeFrame {
    Enter(SemanticChangeId),
    Exit(SemanticChangeId),
}

/// Cross-check every Git projection against semantic tree identity in one
/// first-parent traversal.
///
/// Resolving each projection independently walks from that commit to genesis,
/// making a linear history quadratic and repeatedly cloning complete semantic
/// changes. Git material state has exactly one parent: the first ordered
/// parent. Walk that forest once, carry one exact [`ResolvedTree`], and invert
/// each change while backtracking between branches. Every forward and inverse
/// step still passes through `ResolvedTree::apply`, so stable artifact
/// identity, old-side equality, path occupancy, and rename-cycle semantics
/// remain the same fail-closed contract as ordinary graph replay. Exit frames
/// retain only change identities; inverse deltas are built one change at a
/// time so a deep history does not duplicate its whole delta chain on-stack.
fn validate_git_projection_tree_replay<F>(
    snapshot: &GraphSnapshot,
    targets: &BTreeMap<SemanticChangeId, GitProjectionTreeTarget>,
    mut materialize: F,
) -> Result<(), KinDbError>
where
    F: FnMut(GitObjectId) -> Result<BTreeMap<RepoPath, TreeEntry>, KinDbError>,
{
    let mut roots = BTreeSet::new();
    let mut children: BTreeMap<SemanticChangeId, BTreeSet<SemanticChangeId>> = BTreeMap::new();
    for change_id in targets.keys() {
        let change = snapshot
            .changes
            .get(change_id)
            .ok_or_else(|| ModelError::ChangeNotFound(change_id.to_string()))?;
        if let Some(first_parent) = change.parents.first() {
            if !targets.contains_key(first_parent) {
                return Err(ModelError::ChangeNotFound(first_parent.to_string()).into());
            }
            children
                .entry(*first_parent)
                .or_default()
                .insert(*change_id);
        } else {
            roots.insert(*change_id);
        }
    }

    let mut frames = Vec::with_capacity(targets.len().saturating_mul(2));
    for root in roots.iter().rev() {
        frames.push(GitProjectionTreeFrame::Enter(*root));
    }
    let mut visited = BTreeSet::new();
    let mut semantic_tree = ResolvedTree::default();
    while let Some(frame) = frames.pop() {
        match frame {
            GitProjectionTreeFrame::Enter(change_id) => {
                if !visited.insert(change_id) {
                    return Err(ModelError::Conflict(format!(
                        "cycle in first-parent Git projection history at change {change_id}"
                    ))
                    .into());
                }
                let change = snapshot
                    .changes
                    .get(&change_id)
                    .ok_or_else(|| ModelError::ChangeNotFound(change_id.to_string()))?;
                let target = targets
                    .get(&change_id)
                    .expect("projection traversal only enters collected targets");
                semantic_tree = semantic_tree.apply(&change.tree_deltas).map_err(|error| {
                    ModelError::Conflict(format!(
                        "Git commit projection {} has an invalid semantic tree transition for change {}: {error}",
                        target.commit_oid, change.id
                    ))
                })?;
                let raw_tree = materialize(target.raw_tree_oid)?;
                let exact_match = semantic_tree.len() == raw_tree.len()
                    && semantic_tree
                        .artifacts()
                        .all(|artifact| raw_tree.get(&artifact.path) == Some(&artifact.entry));
                if !exact_match {
                    return Err(ModelError::Conflict(format!(
                        "Git commit projection {} raw tree {} does not match the deterministic semantic tree for change {}",
                        target.commit_oid, target.raw_tree_oid, change.id
                    ))
                    .into());
                }

                frames.push(GitProjectionTreeFrame::Exit(change_id));
                if let Some(next) = children.get(&change_id) {
                    for child in next.iter().rev() {
                        frames.push(GitProjectionTreeFrame::Enter(*child));
                    }
                }
            }
            GitProjectionTreeFrame::Exit(change_id) => {
                let change = snapshot
                    .changes
                    .get(&change_id)
                    .ok_or_else(|| ModelError::ChangeNotFound(change_id.to_string()))?;
                let inverse = change
                    .tree_deltas
                    .iter()
                    .map(TreeDelta::inverse)
                    .collect::<Vec<_>>();
                semantic_tree = semantic_tree.apply(&inverse).map_err(|error| {
                    storage(format!(
                        "failed to rewind validated Git projection tree at change {change_id}: {error}"
                    ))
                })?;
            }
        }
    }

    if visited.len() != targets.len() {
        let change_id = targets
            .keys()
            .find(|change_id| !visited.contains(change_id))
            .expect("unequal projection counts have an unvisited target");
        return Err(ModelError::Conflict(format!(
            "cycle in first-parent Git projection history at change {change_id}"
        ))
        .into());
    }
    if !semantic_tree.is_empty() {
        return Err(storage(
            "Git projection tree traversal did not restore the empty root state".to_string(),
        ));
    }
    Ok(())
}

fn validate_persisted_git_alias_coverage(
    snapshot: &GraphSnapshot,
    metadata: &PersistedRepositoryAuthority,
) -> Result<(), KinDbError> {
    let mut projected_oids = BTreeSet::new();
    let mut collect = |authority: &GitExternalAuthority| {
        projected_oids.extend(
            authority
                .commit_projections
                .iter()
                .map(|projection| projection.commit_oid),
        );
    };
    if let Some(authority) = &metadata.git_external_authority {
        collect(authority);
    }
    for operation in &metadata.operation_log {
        let Some(delta) = &operation.git_authority_delta else {
            continue;
        };
        if let Some(authority) = &delta.old {
            collect(authority);
        }
        if let Some(authority) = &delta.new {
            collect(authority);
        }
    }

    let aliases = metadata
        .aliases
        .iter()
        .map(|alias| (alias.oid, alias))
        .collect::<BTreeMap<_, _>>();
    for alias in &metadata.aliases {
        if !projected_oids.contains(&alias.oid) {
            return Err(ModelError::InvalidOperation(format!(
                "persisted alias {} has no current or recorded Git authority commit projection",
                alias.oid
            ))
            .into());
        }
        let change = snapshot
            .changes
            .get(&alias.change_id)
            .ok_or_else(|| ModelError::ChangeNotFound(alias.change_id.to_string()))?;
        alias.validate_change(change)?;
    }
    for change in snapshot.changes.values() {
        let kin_model::ChangeOrigin::GitCommit { oid } = change.origin else {
            continue;
        };
        if !projected_oids.contains(&oid) {
            return Err(ModelError::InvalidOperation(format!(
                "persisted Git-origin change {} for {} has no current or recorded authority commit projection",
                change.id, oid
            ))
            .into());
        }
        if aliases.get(&oid).map(|alias| alias.change_id) != Some(change.id) {
            return Err(ModelError::InvalidOperation(format!(
                "persisted Git-origin change {} for {} lacks its exact repository-scoped alias",
                change.id, oid
            ))
            .into());
        }
    }
    Ok(())
}

fn materialize_git_tree(
    entries: &BTreeMap<ExternalObjectId, &kin_model::GitObjectClosureEntry>,
    root_oid: GitObjectId,
) -> Result<BTreeMap<RepoPath, TreeEntry>, KinDbError> {
    let root = ExternalObjectId::new(ExternalObjectKind::Tree, root_oid);
    if !entries.contains_key(&root) {
        return Err(ModelError::InvalidOperation(format!(
            "Git commit tree {} is absent from the authority closure",
            root_oid
        ))
        .into());
    }

    let mut material = BTreeMap::new();
    let mut pending = vec![(root, Vec::<u8>::new(), Vec::<ExternalObjectId>::new())];
    while let Some((tree_id, prefix, mut ancestry)) = pending.pop() {
        if ancestry.contains(&tree_id) {
            return Err(ModelError::InvalidOperation(format!(
                "Git tree closure contains a cycle through {}",
                tree_id.oid
            ))
            .into());
        }
        ancestry.push(tree_id);
        let tree = entries.get(&tree_id).ok_or_else(|| {
            ModelError::InvalidOperation(format!(
                "Git tree {} is absent from the authority closure",
                tree_id.oid
            ))
        })?;
        for dependency in tree.dependencies.iter().rev() {
            let GitObjectDependencyKind::TreeEntry { mode, name, .. } = &dependency.kind else {
                return Err(ModelError::InvalidOperation(format!(
                    "Git tree {} contains a non-tree-entry dependency",
                    tree_id.oid
                ))
                .into());
            };
            let mut path = prefix.clone();
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(name.as_bytes());
            match mode {
                GitTreeEntryMode::Tree => {
                    pending.push((dependency.target, path, ancestry.clone()));
                }
                GitTreeEntryMode::Blob
                | GitTreeEntryMode::BlobExecutable
                | GitTreeEntryMode::Symlink => {
                    let record = entries.get(&dependency.target).ok_or_else(|| {
                        ModelError::InvalidOperation(format!(
                            "Git tree entry {} targets object {} absent from the authority closure",
                            RepoPath::from_bytes(path.clone())
                                .map_or_else(|_| hex::encode(&path), |path| path.to_string()),
                            dependency.target.oid
                        ))
                    })?;
                    let entry = match mode {
                        GitTreeEntryMode::Blob => TreeEntry::blob(record.record.body_hash, false),
                        GitTreeEntryMode::BlobExecutable => {
                            TreeEntry::blob(record.record.body_hash, true)
                        }
                        GitTreeEntryMode::Symlink => TreeEntry::symlink(record.record.body_hash),
                        GitTreeEntryMode::Tree | GitTreeEntryMode::Gitlink => unreachable!(),
                    };
                    insert_git_tree_entry(&mut material, path, entry)?;
                }
                GitTreeEntryMode::Gitlink => {
                    insert_git_tree_entry(
                        &mut material,
                        path,
                        TreeEntry::gitlink(dependency.target.oid),
                    )?;
                }
            }
        }
    }
    Ok(material)
}

fn insert_git_tree_entry(
    material: &mut BTreeMap<RepoPath, TreeEntry>,
    path: Vec<u8>,
    entry: TreeEntry,
) -> Result<(), KinDbError> {
    let path = RepoPath::from_bytes(path).map_err(|error| {
        ModelError::InvalidOperation(format!(
            "Git tree projects an invalid repository path: {error}"
        ))
    })?;
    if material.insert(path.clone(), entry).is_some() {
        return Err(ModelError::InvalidOperation(format!(
            "Git tree projects repository path {path} more than once"
        ))
        .into());
    }
    Ok(())
}

struct RepositoryGitObjectBodyLoader<'a, B: StorageBackend + ?Sized> {
    backend: &'a B,
    repository_id: &'a RepositoryId,
    body_lengths: BTreeMap<Hash256, u64>,
}

impl<'a, B: StorageBackend + ?Sized> RepositoryGitObjectBodyLoader<'a, B> {
    fn new(
        backend: &'a B,
        repository_id: &'a RepositoryId,
        authority: &GitExternalAuthority,
    ) -> Result<Self, KinDbError> {
        let mut body_lengths = BTreeMap::new();
        for entry in &authority.closure.objects {
            if let Some(previous) =
                body_lengths.insert(entry.record.body_hash, entry.record.body_len)
            {
                if previous != entry.record.body_len {
                    return Err(ModelError::InvalidOperation(format!(
                        "Git authority body {} is declared with both length {} and {}",
                        entry.record.body_hash, previous, entry.record.body_len
                    ))
                    .into());
                }
            }
        }
        Ok(Self {
            backend,
            repository_id,
            body_lengths,
        })
    }
}

impl<B: StorageBackend + ?Sized> GitObjectBodyLoader for RepositoryGitObjectBodyLoader<'_, B> {
    type Error = KinDbError;

    fn load_body(
        &mut self,
        body_hash: &Hash256,
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
        let Some(body_len) = self.body_lengths.get(body_hash).copied() else {
            return Ok(None);
        };
        self.backend.load_source_blob_bounded(
            self.repository_id.as_str(),
            *body_hash.as_bytes(),
            body_len,
        )
    }
}

fn validate_git_authority_bodies<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    authority: Option<&GitExternalAuthority>,
) -> Result<(), KinDbError> {
    let Some(authority) = authority else {
        return Ok(());
    };
    let mut loader = RepositoryGitObjectBodyLoader::new(backend, repository_id, authority)?;
    authority
        .validate_with_body_loader(&mut loader)
        .map_err(|error| {
            ModelError::InvalidOperation(format!(
                "Git external authority body validation failed: {error}"
            ))
            .into()
        })
}

fn apply_ref_mutations(
    snapshot: &GraphSnapshot,
    metadata: &mut PersistedRepositoryAuthority,
    transaction: &RepositoryTransaction,
) -> Result<(), KinDbError> {
    let mut refs: BTreeMap<RefName, RepositoryRef> = metadata
        .ref_state
        .refs
        .iter()
        .cloned()
        .map(|repository_ref| (repository_ref.name.clone(), repository_ref))
        .collect();

    for mutation in &transaction.ref_mutations {
        let current = refs.get(&mutation.name).map(|reference| &reference.target);
        match (&mutation.expected, current) {
            (RefExpectation::MustNotExist, None) => {}
            (RefExpectation::MustNotExist, Some(_)) => {
                return Err(
                    ModelError::Conflict(format!("ref {} already exists", mutation.name)).into(),
                );
            }
            (RefExpectation::MustEqual { target }, Some(current)) if target == current => {}
            (RefExpectation::MustEqual { .. }, _) => {
                return Err(ModelError::Conflict(format!(
                    "ref {} no longer matches its lease",
                    mutation.name
                ))
                .into());
            }
        }
        if current == mutation.new_target.as_ref() {
            return Err(ModelError::InvalidOperation(format!(
                "ref {} mutation is a no-op",
                mutation.name
            ))
            .into());
        }
        if mutation.policy == RefUpdatePolicy::FastForwardOnly {
            let old_change = current
                .map(|target| ref_target_change_id(metadata, target))
                .transpose()?
                .flatten();
            let new_change = mutation
                .new_target
                .as_ref()
                .map(|target| ref_target_change_id(metadata, target))
                .transpose()?
                .flatten();
            if let (Some(old), Some(new)) = (old_change, new_change) {
                if !is_ancestor(snapshot, &old, &new)? {
                    return Err(ModelError::Conflict(format!(
                        "ref {} update is not a semantic fast-forward",
                        mutation.name
                    ))
                    .into());
                }
            } else if current.is_some() {
                return Err(ModelError::Conflict(format!(
                    "ref {} requires force-with-lease for non-change targets",
                    mutation.name
                ))
                .into());
            }
        }

        if let Some(target) = &mutation.new_target {
            validate_target_exists(snapshot, metadata, target)?;
            refs.insert(
                mutation.name.clone(),
                RepositoryRef {
                    repository_id: transaction.repository_id.clone(),
                    name: mutation.name.clone(),
                    target: target.clone(),
                },
            );
        } else {
            refs.remove(&mutation.name);
        }
    }

    if let Some(default_mutation) = &transaction.default_ref_mutation {
        match (&default_mutation.expected, &metadata.ref_state.default_ref) {
            (DefaultRefExpectation::MustBeUnset, None) => {}
            (DefaultRefExpectation::MustEqual { name }, Some(current)) if name == current => {}
            _ => {
                return Err(ModelError::Conflict(
                    "default ref no longer matches its lease".to_string(),
                )
                .into());
            }
        }
        // An unborn default ref is valid and preserves exact Git init state.
        metadata.ref_state.default_ref = default_mutation.new_default.clone();
    }

    metadata.ref_state.refs = refs.into_values().collect();
    validate_symbolic_ref_cycles(&metadata.ref_state.refs)?;
    Ok(())
}

fn ref_target_change_id(
    metadata: &PersistedRepositoryAuthority,
    target: &RefTarget,
) -> Result<Option<SemanticChangeId>, KinDbError> {
    match target {
        RefTarget::Change { change_id } => Ok(Some(*change_id)),
        RefTarget::ExternalObject { object } => {
            let Some(commit_oid) = peel_authority_external_target(metadata, *object)? else {
                return Ok(None);
            };
            Ok(metadata
                .aliases
                .iter()
                .find(|alias| alias.oid == commit_oid)
                .map(|alias| alias.change_id))
        }
        RefTarget::Symbolic { .. } => Ok(None),
    }
}

fn apply_local_overlay(
    metadata: &mut PersistedRepositoryAuthority,
    transaction: &RepositoryTransaction,
) -> Result<(), KinDbError> {
    let Some(delta) = &transaction.local_overlay_delta else {
        return Ok(());
    };
    let workspace_id = delta.workspace_id().ok_or_else(|| {
        ModelError::InvalidOperation("local overlay delta has no workspace identity".to_string())
    })?;
    let mut overlays: BTreeMap<WorkspaceId, FrozenLocalOverlay> = metadata
        .local_overlays
        .iter()
        .cloned()
        .map(|overlay| (overlay.workspace_id, overlay))
        .collect();
    if overlays.get(&workspace_id) != delta.old.as_ref() {
        return Err(ModelError::Conflict(format!(
            "local overlay for workspace {workspace_id} no longer matches its lease"
        ))
        .into());
    }
    let next = delta.new.clone().ok_or_else(|| {
        ModelError::InvalidOperation(
            "repository transaction cannot remove a required local overlay".to_string(),
        )
    })?;
    overlays.insert(workspace_id, next);
    metadata.local_overlays = overlays.into_values().collect();
    Ok(())
}

/// Compare-and-swap one workspace's durable merge record.
///
/// The lease discipline matches [`apply_local_overlay`]: the delta's `old` must
/// be exactly what is stored, so two sessions cannot both advance a merge from
/// the same view of it.
///
/// The citation check is what makes the record non-fabricable. A resolution
/// names the operation that settled it, and any citation this delta introduces
/// must be the transaction being committed right now. A caller therefore cannot
/// author provenance pointing at some other transaction, or at one that never
/// happened. Citations the previous record already carried were proven the same
/// way when they were applied, so they are not rechecked here, which also keeps
/// this sound across operation-log compaction.
fn apply_merge_transaction(
    metadata: &mut PersistedRepositoryAuthority,
    transaction: &RepositoryTransaction,
) -> Result<(), KinDbError> {
    let Some(delta) = &transaction.merge_transaction_delta else {
        return Ok(());
    };
    let workspace_id = delta.workspace_id().ok_or_else(|| {
        ModelError::InvalidOperation(
            "merge transaction delta has no workspace identity".to_string(),
        )
    })?;
    let mut records: BTreeMap<WorkspaceId, MergeTransactionRecord> = metadata
        .merge_transactions
        .iter()
        .cloned()
        .map(|record| (record.workspace_id, record))
        .collect();
    if records.get(&workspace_id) != delta.old.as_ref() {
        return Err(ModelError::Conflict(format!(
            "merge transaction for workspace {workspace_id} no longer matches its lease"
        ))
        .into());
    }

    let previously_cited: BTreeSet<OperationId> = delta
        .old
        .as_ref()
        .map(|old| {
            kin_model::MergeTransactionDelta::open(old.clone())
                .referenced_operations()
                .into_iter()
                .collect()
        })
        .unwrap_or_default();
    if let Some(new) = &delta.new {
        for cited in kin_model::MergeTransactionDelta::open(new.clone()).referenced_operations() {
            if !previously_cited.contains(&cited) && cited != transaction.operation_id {
                return Err(ModelError::InvalidOperation(format!(
                    "merge transaction cites operation {cited}, which is neither already recorded \
                     nor the operation committing it"
                ))
                .into());
            }
        }
        records.insert(workspace_id, new.clone());
    } else {
        records.remove(&workspace_id);
    }
    metadata.merge_transactions = records.into_values().collect();
    Ok(())
}

fn apply_workspace<B: StorageBackend + ?Sized>(
    backend: &B,
    snapshot: &GraphSnapshot,
    metadata: &mut PersistedRepositoryAuthority,
    transaction: &RepositoryTransaction,
) -> Result<(), KinDbError> {
    let Some(mutation) = &transaction.workspace_mutation else {
        return Ok(());
    };
    let mut workspaces: BTreeMap<WorkspaceId, WorkspaceState> = metadata
        .workspaces
        .iter()
        .cloned()
        .map(|workspace| (workspace.workspace_id, workspace))
        .collect();
    let current = workspaces.get(&mutation.workspace_id);
    let current_graph = match current {
        Some(workspace) => materialize_workspace_graph_snapshot(snapshot, metadata, workspace)?,
        None => resolve_workspace_base_graph_snapshot(snapshot, metadata, None)?,
    };
    let mut incremental_delta = mutation.semantic_delta.transaction_delta();
    incremental_delta.tree_deltas = mutation.tree_deltas.clone();
    let desired_graph = InMemoryGraph::from_snapshot(current_graph)?;
    desired_graph.apply_transaction_delta(&incremental_delta)?;
    let desired = desired_graph.to_snapshot();

    let next_base = resolve_workspace_base_graph_snapshot(
        snapshot,
        metadata,
        mutation.new_base_target.as_ref(),
    )?;
    let derived_semantic_overlay = derive_workspace_semantic_overlay(&next_base, &desired)?;
    let next = mutation.validate_against(
        &transaction.repository_id,
        current,
        derived_semantic_overlay,
    )?;
    validate_workspace_state(snapshot, metadata, &next)?;
    let rematerialized = materialize_workspace_graph_snapshot(snapshot, metadata, &next)?;
    validate_exact_workspace_graph(&desired, &rematerialized, &next)?;
    validate_workspace_symbolic_head_at_mutation(metadata, &next)?;
    validate_shared_policy_bodies(
        backend,
        &transaction.repository_id,
        &next.shared_admission_policy,
    )?;
    validate_tree_bodies(
        backend,
        &transaction.repository_id,
        &next.tree,
        "workspace tree",
    )?;
    workspaces.insert(mutation.workspace_id, next);
    metadata.workspaces = workspaces.into_values().collect();
    Ok(())
}

/// Recompute repository admission from the successor authority itself.
///
/// A transaction contains desired state, never a trusted scan verdict. This
/// verifier consumes only immutable CAS bodies plus the exact policy, overlay,
/// history, Git authority, and workspace state that would be published.
fn verify_transaction_admission<B: StorageBackend + ?Sized>(
    backend: &B,
    current: &RepositoryAuthorityState,
    snapshot: &GraphSnapshot,
    metadata: &PersistedRepositoryAuthority,
    transaction: &RepositoryTransaction,
) -> Result<(), KinDbError> {
    verify_workspace_admission(backend, current, snapshot, metadata, transaction)?;
    verify_native_change_admission(
        backend,
        current.authenticated_gitlinks(),
        snapshot,
        metadata,
        transaction,
    )
}

fn verify_workspace_admission<B: StorageBackend + ?Sized>(
    backend: &B,
    current: &RepositoryAuthorityState,
    snapshot: &GraphSnapshot,
    metadata: &PersistedRepositoryAuthority,
    transaction: &RepositoryTransaction,
) -> Result<(), KinDbError> {
    let Some(mutation) = &transaction.workspace_mutation else {
        return Ok(());
    };
    let workspace = metadata
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == mutation.workspace_id)
        .ok_or_else(|| {
            storage(format!(
                "successor workspace {} is absent during admission verification",
                mutation.workspace_id
            ))
        })?;
    let overlay = local_overlay_for_workspace(metadata, workspace)?;
    let matcher = resolve_admission_matcher(
        backend,
        &transaction.repository_id,
        &workspace.shared_admission_policy,
        overlay,
    )?;

    let mut tracked = BTreeSet::<ArtifactId>::new();
    // Exact Gitlinks that appeared in previously persisted, raw-tree-verified
    // Git history are repository authority even when the current workspace or
    // base no longer contains them. The derived index is built only from the
    // pre-transaction state, so raw objects or Native changes in this
    // transaction cannot authorize an arbitrary target.
    let authenticated_gitlinks = current.authenticated_gitlinks();
    let mut contextual_gitlinks = BTreeSet::new();
    if let Some(previous) = current
        .metadata()
        .workspaces
        .iter()
        .find(|candidate| candidate.workspace_id == workspace.workspace_id)
    {
        tracked.extend(
            previous
                .tree
                .artifacts()
                .map(|artifact| artifact.artifact_id),
        );
        contextual_gitlinks.extend(previous.tree.artifacts().filter_map(|artifact| {
            let TreeEntry::Gitlink { target } = artifact.entry else {
                return None;
            };
            Some((artifact.artifact_id, target))
        }));
    }

    // A previously admitted commit is already repository authority. A new
    // Git-origin base is also tracked, but only after the exact raw-object
    // authority/projection checks above succeeded. A new Native base is not
    // self-authorizing and is scanned as new input below.
    if let Some(base_target) = &workspace.base_target {
        let change_id = target_change_id(metadata, base_target)?;
        let change = snapshot
            .changes
            .get(&change_id)
            .ok_or_else(|| ModelError::ChangeNotFound(change_id.to_string()))?;
        let was_already_admitted = current.snapshot.changes.contains_key(&change_id);
        let is_verified_git = matches!(change.origin, kin_model::ChangeOrigin::GitCommit { .. });
        if was_already_admitted || is_verified_git {
            let base = resolve_change_tree(snapshot, change_id)?;
            tracked.extend(base.artifacts().map(|artifact| artifact.artifact_id));
            contextual_gitlinks.extend(base.artifacts().filter_map(|artifact| {
                let TreeEntry::Gitlink { target } = artifact.entry else {
                    return None;
                };
                Some((artifact.artifact_id, target))
            }));
        }
    }

    for artifact in workspace.tree.artifacts_by_path() {
        let gitlink_is_admitted = match artifact.entry {
            TreeEntry::Gitlink { target } => {
                authenticated_gitlinks.contains(&(artifact.artifact_id, target))
                    || contextual_gitlinks.contains(&(artifact.artifact_id, target))
            }
            TreeEntry::Blob { .. } | TreeEntry::Symlink { .. } => false,
        };
        verify_artifact_admission(
            backend,
            &transaction.repository_id,
            &matcher,
            artifact,
            ArtifactAdmissionContext {
                policy: &workspace.shared_admission_policy,
                tracked: tracked.contains(&artifact.artifact_id),
                gitlink_is_admitted,
                label: "workspace",
            },
        )?;
    }
    Ok(())
}

fn verify_native_change_admission<B: StorageBackend + ?Sized>(
    backend: &B,
    authenticated_gitlinks: &BTreeSet<(ArtifactId, GitObjectId)>,
    snapshot: &GraphSnapshot,
    metadata: &PersistedRepositoryAuthority,
    transaction: &RepositoryTransaction,
) -> Result<(), KinDbError> {
    let native_changes = transaction
        .changes
        .iter()
        .filter(|change| matches!(change.origin, kin_model::ChangeOrigin::Native));
    for change in native_changes {
        let candidate = resolve_change_tree(snapshot, change.id)?;
        let mut parent_artifacts = BTreeSet::<ArtifactId>::new();
        for parent in &change.parents {
            let parent_tree = resolve_change_tree(snapshot, *parent)?;
            parent_artifacts.extend(parent_tree.artifacts().map(|artifact| artifact.artifact_id));
        }
        for artifact in candidate.artifacts() {
            let TreeEntry::Gitlink { target } = artifact.entry else {
                continue;
            };
            if !authenticated_gitlinks.contains(&(artifact.artifact_id, target)) {
                return Err(ModelError::InvalidOperation(format!(
                    "native change {} introduces gitlink {} at {} without verified Git external authority",
                    change.id, target, artifact.path
                ))
                .into());
            }
        }
        let introduced = candidate
            .artifacts_by_path()
            .filter(|artifact| !parent_artifacts.contains(&artifact.artifact_id))
            .collect::<Vec<_>>();
        if introduced.is_empty() {
            continue;
        }

        // The current v3 contract binds one Native admission to the workspace
        // that publishes it. History-only Native imports and multi-change
        // synthetic batches have no trustworthy local case/overlay context and
        // therefore fail closed until they gain an explicit graph-native
        // admission context.
        let mutation = transaction.workspace_mutation.as_ref().ok_or_else(|| {
            ModelError::InvalidOperation(format!(
                "native change {} introduces artifacts without a bound workspace admission context",
                change.id
            ))
        })?;
        let workspace = metadata
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == mutation.workspace_id)
            .ok_or_else(|| {
                storage(format!(
                    "successor workspace {} is absent during Native admission verification",
                    mutation.workspace_id
                ))
            })?;
        let base_change = workspace
            .base_target
            .as_ref()
            .map(|target| target_change_id(metadata, target))
            .transpose()?;
        if base_change != Some(change.id) {
            return Err(ModelError::InvalidOperation(format!(
                "native change {} introduces artifacts but successor workspace {} is not based on that exact change",
                change.id, workspace.workspace_id
            ))
            .into());
        }
        for artifact in &introduced {
            if workspace.tree.get(&artifact.artifact_id) != Some(*artifact) {
                return Err(ModelError::InvalidOperation(format!(
                    "native change {} artifact {} is not present exactly in successor workspace {}",
                    change.id, artifact.path, workspace.workspace_id
                ))
                .into());
            }
        }

        let policy = metadata
            .admission_policies
            .iter()
            .find(|resolved| resolved.change_id == change.id)
            .and_then(|resolved| resolved.policy.as_ref())
            .ok_or_else(|| {
                ModelError::InvalidOperation(format!(
                    "native change {} introduces artifacts without a resolved shared admission policy",
                    change.id
                ))
            })?;
        let overlay = local_overlay_for_workspace(metadata, workspace)?;
        let matcher =
            resolve_admission_matcher(backend, &transaction.repository_id, policy, overlay)?;
        for artifact in introduced {
            let gitlink_is_admitted = match artifact.entry {
                TreeEntry::Gitlink { target } => {
                    authenticated_gitlinks.contains(&(artifact.artifact_id, target))
                }
                TreeEntry::Blob { .. } | TreeEntry::Symlink { .. } => false,
            };
            verify_artifact_admission(
                backend,
                &transaction.repository_id,
                &matcher,
                artifact,
                ArtifactAdmissionContext {
                    policy,
                    tracked: false,
                    gitlink_is_admitted,
                    label: &format!("native change {}", change.id),
                },
            )?;
        }
    }
    Ok(())
}

fn local_overlay_for_workspace<'a>(
    metadata: &'a PersistedRepositoryAuthority,
    workspace: &WorkspaceState,
) -> Result<&'a FrozenLocalOverlay, KinDbError> {
    metadata
        .local_overlays
        .iter()
        .find(|overlay| {
            overlay.workspace_id == workspace.workspace_id
                && overlay.stamp() == workspace.admission_policy.local
        })
        .ok_or_else(|| {
            ModelError::Conflict(format!(
                "workspace {} admission overlay is absent from successor authority",
                workspace.workspace_id
            ))
            .into()
        })
}

fn resolve_admission_matcher<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    shared: &SharedAdmissionPolicy,
    overlay: &FrozenLocalOverlay,
) -> Result<ResolvedAdmissionMatcher, KinDbError> {
    shared.validate()?;
    overlay.validate()?;

    let mut low_local = Vec::new();
    let mut high_local = Vec::new();
    let mut prior_tier = 0_u8;
    for source in &overlay.sources {
        let tier = match source.kind {
            LocalAdmissionRuleSourceKind::GitGlobalExclude => 0,
            LocalAdmissionRuleSourceKind::GitInfoExclude => 1,
            LocalAdmissionRuleSourceKind::KinLocal => 2,
        };
        if tier < prior_tier {
            return Err(ModelError::InvalidOperation(format!(
                "workspace {} local admission sources are not ordered global, info, then Kin-local",
                overlay.workspace_id
            ))
            .into());
        }
        prior_tier = tier;
        let body = load_exact_body(
            backend,
            repository_id,
            source.body_hash,
            source.body_len,
            "local admission rule source",
        )?;
        let resolved_source = match source.kind {
            LocalAdmissionRuleSourceKind::GitGlobalExclude => {
                ResolvedAdmissionRuleSource::GlobalExclude
            }
            LocalAdmissionRuleSourceKind::GitInfoExclude => {
                ResolvedAdmissionRuleSource::InfoExclude
            }
            LocalAdmissionRuleSourceKind::KinLocal => ResolvedAdmissionRuleSource::KinLocal {
                ordinal: source.precedence,
            },
        };
        let entry = (
            resolved_source,
            None,
            source.body_hash,
            source.body_len,
            body,
        );
        if source.kind == LocalAdmissionRuleSourceKind::KinLocal {
            high_local.push(entry);
        } else {
            low_local.push(entry);
        }
    }

    let mut rule_sets = Vec::new();
    for (source, base_directory, content_hash, content_len, contents) in low_local {
        push_resolved_rule(
            &mut rule_sets,
            source,
            base_directory,
            content_hash,
            content_len,
            contents,
        )?;
    }
    for source in &shared.sources {
        let body = load_exact_body(
            backend,
            repository_id,
            source.body_hash,
            source.body_len,
            &format!("shared admission source {}", source.path),
        )?;
        push_resolved_rule(
            &mut rule_sets,
            ResolvedAdmissionRuleSource::Shared {
                source_path: source.path.clone(),
            },
            source.base_directory.clone(),
            source.body_hash,
            source.body_len,
            body,
        )?;
    }
    for (source, base_directory, content_hash, content_len, contents) in high_local {
        push_resolved_rule(
            &mut rule_sets,
            source,
            base_directory,
            content_hash,
            content_len,
            contents,
        )?;
    }
    ResolvedAdmissionMatcher::compile(overlay.case, rule_sets)
        .map_err(|error| storage(format!("compile graph-owned admission policy: {error}")))
}

fn push_resolved_rule(
    rule_sets: &mut Vec<ResolvedAdmissionRuleSet>,
    source: ResolvedAdmissionRuleSource,
    base_directory: Option<RepoPath>,
    content_hash: Hash256,
    content_len: u64,
    contents: Vec<u8>,
) -> Result<(), KinDbError> {
    let precedence = u32::try_from(rule_sets.len())
        .map_err(|_| storage("resolved admission source count exceeds u32".to_string()))?;
    rule_sets.push(ResolvedAdmissionRuleSet::new(
        source,
        precedence,
        base_directory,
        content_hash,
        content_len,
        contents,
    ));
    Ok(())
}

struct ArtifactAdmissionContext<'a> {
    policy: &'a SharedAdmissionPolicy,
    tracked: bool,
    gitlink_is_admitted: bool,
    label: &'a str,
}

fn verify_artifact_admission<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    matcher: &ResolvedAdmissionMatcher,
    artifact: &ResolvedArtifact,
    context: ArtifactAdmissionContext<'_>,
) -> Result<(), KinDbError> {
    let decision = matcher.decide(&artifact.path, false, context.tracked);
    if decision.is_ignored() {
        return Err(ModelError::InvalidOperation(format!(
            "{} artifact {} is excluded by the exact graph-owned admission policy",
            context.label, artifact.path
        ))
        .into());
    }
    let (content_hash, kind) = match artifact.entry {
        TreeEntry::Blob { hash, executable } => (hash, SensitiveArtifactKind::Blob { executable }),
        TreeEntry::Symlink { target_blob } => (target_blob, SensitiveArtifactKind::Symlink),
        TreeEntry::Gitlink { .. } if context.gitlink_is_admitted => return Ok(()),
        TreeEntry::Gitlink { target } => {
            return Err(ModelError::InvalidOperation(format!(
                "{} introduces gitlink {} at {} without verified Git external authority",
                context.label, target, artifact.path
            ))
            .into())
        }
    };
    if context.tracked {
        return Ok(());
    }
    let body = load_unbounded_body(
        backend,
        repository_id,
        content_hash,
        &format!("{} artifact {}", context.label, artifact.path),
    )?;
    enforce_sensitive_admission(
        &artifact.path,
        content_hash,
        kind,
        &body,
        false,
        &context.policy.sensitive_allowances,
    )
    .map_err(|error| ModelError::InvalidOperation(error.to_string()).into())
}

fn resolve_change_tree(
    snapshot: &GraphSnapshot,
    change_id: SemanticChangeId,
) -> Result<ResolvedTree, KinDbError> {
    let mut replay = snapshot.clone();
    replay.repository_authority = None;
    let graph = InMemoryGraph::from_snapshot(replay)?;
    graph.resolve_tree_at(&change_id)
}

/// Decide whether a recovered repository carries a durable record that these
/// exact bytes already passed complete open-time validation.
///
/// Every field has to agree with what was actually loaded, and the digest is
/// the one this process recomputed over the deserialized bytes, never the one
/// the record claims for itself. So the record can only ever vouch for the
/// content it is stored beside: edit a persisted snapshot and the digest moves,
/// the record stops applying, and the open falls back to full validation, which
/// is the check that refuses the edit. A record is likewise refused when it was
/// minted by a different validator version, names a different repository, names
/// a different generation, or when any delta was replayed on top of the base
/// snapshot it describes.
///
/// What this does not claim: a writer who can rewrite kin-db's own authority
/// record alongside the snapshot can mint a record for bytes nobody validated.
/// That writer already holds the repository's control plane. The guarantee here
/// is content binding, not authentication against such a writer.
fn verified_history_validation(
    repository_id: &RepositoryId,
    recovered: &RecoveredSnapshot,
) -> Option<Generation> {
    let proof = recovered.history_validation.as_ref()?;
    let matches = proof.validator_version == HISTORY_VALIDATION_VERSION
        && proof.repository_id == repository_id.as_str()
        && proof.generation == recovered.generation
        && proof.snapshot_sha256 == recovered.snapshot_sha256
        && recovered.deltas_applied == 0;
    matches.then_some(recovered.generation)
}

fn validate_history_replay(
    snapshot: &GraphSnapshot,
    new_changes: &[kin_model::SemanticChange],
) -> Result<(), KinDbError> {
    topological_change_order(&snapshot.changes)?;
    let mut replay_snapshot = snapshot.clone();
    replay_snapshot.repository_authority = None;
    let graph = InMemoryGraph::from_snapshot(replay_snapshot)?;

    // New transactions validate every admitted tip directly. Reopen has no
    // trusted prior process state, so replay every DAG leaf; together their
    // reachable histories cover every persisted change, including unreachable
    // history that is not currently named by a ref. This is graph replay only:
    // an invalid history never falls back to Git or the filesystem.
    let mut validation_targets: Vec<_> = if new_changes.is_empty() {
        snapshot
            .changes
            .keys()
            .filter(|change_id| {
                snapshot
                    .change_children
                    .get(change_id)
                    .is_none_or(Vec::is_empty)
            })
            .copied()
            .collect()
    } else {
        new_changes.iter().map(|change| change.id).collect()
    };
    validation_targets.sort_unstable();
    validation_targets.dedup();
    for change_id in validation_targets {
        graph.build_change_order_at(&change_id)?;
        graph.resolve_graph_at(&change_id)?;
    }
    Ok(())
}

fn topological_change_order(
    changes: &HashMap<SemanticChangeId, kin_model::SemanticChange>,
) -> Result<Vec<SemanticChangeId>, KinDbError> {
    let mut indegree = BTreeMap::new();
    let mut children: BTreeMap<SemanticChangeId, BTreeSet<SemanticChangeId>> = BTreeMap::new();
    for change in changes.values() {
        let unique_parents: BTreeSet<_> = change.parents.iter().copied().collect();
        for parent in &unique_parents {
            if !changes.contains_key(parent) {
                return Err(ModelError::ChangeNotFound(parent.to_string()).into());
            }
            children.entry(*parent).or_default().insert(change.id);
        }
        indegree.insert(change.id, unique_parents.len());
    }
    let mut ready: BTreeSet<_> = indegree
        .iter()
        .filter_map(|(id, degree)| (*degree == 0).then_some(*id))
        .collect();
    let mut order = Vec::with_capacity(changes.len());
    while let Some(change_id) = ready.pop_first() {
        order.push(change_id);
        for child in children.get(&change_id).into_iter().flatten() {
            let degree = indegree
                .get_mut(child)
                .expect("child was collected from the same change map");
            *degree -= 1;
            if *degree == 0 {
                ready.insert(*child);
            }
        }
    }
    if order.len() != changes.len() {
        return Err(
            ModelError::Conflict("semantic change DAG contains a cycle".to_string()).into(),
        );
    }
    Ok(order)
}

fn derive_admission_policies(
    changes: &HashMap<SemanticChangeId, kin_model::SemanticChange>,
) -> Result<Vec<ChangeAdmissionPolicy>, KinDbError> {
    let order = topological_change_order(changes)?;
    let mut states: HashMap<SemanticChangeId, Option<SharedAdmissionPolicy>> = HashMap::new();
    for change_id in order {
        let change = &changes[&change_id];
        let inherited = change
            .parents
            .first()
            .and_then(|parent| states.get(parent))
            .cloned()
            .unwrap_or(None);
        let policy = if let Some(delta) = &change.admission_policy_delta {
            delta.validate()?;
            if delta.old != inherited {
                return Err(ModelError::Conflict(format!(
                    "change {} admission policy old-state does not match its first parent",
                    change.id
                ))
                .into());
            }
            delta.new.clone()
        } else {
            inherited
        };
        states.insert(change_id, policy);
    }
    let mut policies: Vec<_> = states
        .into_iter()
        .map(|(change_id, policy)| ChangeAdmissionPolicy { change_id, policy })
        .collect();
    policies.sort_by_key(|policy| policy.change_id);
    Ok(policies)
}

fn validate_ref_targets(
    snapshot: &GraphSnapshot,
    metadata: &PersistedRepositoryAuthority,
) -> Result<(), KinDbError> {
    for repository_ref in &metadata.ref_state.refs {
        validate_target_exists(snapshot, metadata, &repository_ref.target)?;
    }
    validate_symbolic_ref_cycles(&metadata.ref_state.refs)
}

fn validate_target_exists(
    snapshot: &GraphSnapshot,
    metadata: &PersistedRepositoryAuthority,
    target: &RefTarget,
) -> Result<(), KinDbError> {
    match target {
        RefTarget::Change { change_id } if !snapshot.changes.contains_key(change_id) => {
            Err(ModelError::ChangeNotFound(change_id.to_string()).into())
        }
        RefTarget::ExternalObject { object }
            if !metadata
                .external_objects
                .iter()
                .any(|record| record.object == *object) =>
        {
            Err(ModelError::InvalidOperation(format!(
                "ref targets missing external object {}",
                object.oid
            ))
            .into())
        }
        // A symbolic ref may intentionally point at an unborn name.
        _ => Ok(()),
    }
}

fn validate_symbolic_ref_cycles(refs: &[RepositoryRef]) -> Result<(), KinDbError> {
    let targets: BTreeMap<RefName, RefName> = refs
        .iter()
        .filter_map(|repository_ref| match &repository_ref.target {
            RefTarget::Symbolic { target } => Some((repository_ref.name.clone(), target.clone())),
            _ => None,
        })
        .collect();
    for start in targets.keys() {
        let mut seen = BTreeSet::new();
        let mut current = start;
        while let Some(next) = targets.get(current) {
            if !seen.insert(current.clone()) {
                return Err(
                    ModelError::Conflict(format!("symbolic ref cycle reaches {current}")).into(),
                );
            }
            current = next;
        }
    }
    Ok(())
}

fn is_ancestor(
    snapshot: &GraphSnapshot,
    ancestor: &SemanticChangeId,
    descendant: &SemanticChangeId,
) -> Result<bool, KinDbError> {
    if !snapshot.changes.contains_key(ancestor) {
        return Err(ModelError::ChangeNotFound(ancestor.to_string()).into());
    }
    let mut stack = vec![*descendant];
    let mut visited = HashSet::new();
    while let Some(change_id) = stack.pop() {
        if change_id == *ancestor {
            return Ok(true);
        }
        if !visited.insert(change_id) {
            continue;
        }
        let change = snapshot
            .changes
            .get(&change_id)
            .ok_or_else(|| ModelError::ChangeNotFound(change_id.to_string()))?;
        stack.extend(change.parents.iter().copied());
    }
    Ok(false)
}

/// Resolve one complete workspace graph strictly from repository authority.
///
/// Immutable history supplies the base graph, the persisted semantic overlay
/// supplies uncommitted entity/relation state, and the independently
/// authoritative workspace tree supplies every repository member. Applying
/// all three as one `TransactionDelta` preserves the graph engine's atomic
/// validation: an entity can never be restored onto an absent artifact and a
/// relation can never point at a missing entity.
fn materialize_workspace_graph_snapshot(
    authority_snapshot: &GraphSnapshot,
    metadata: &PersistedRepositoryAuthority,
    workspace: &WorkspaceState,
) -> Result<GraphSnapshot, KinDbError> {
    let base = resolve_workspace_base_graph_snapshot(
        authority_snapshot,
        metadata,
        workspace.base_target.as_ref(),
    )?;
    let base_tree = base.resolved_tree.clone();
    let mut delta = workspace.semantic_overlay.transaction_delta();
    delta.tree_deltas = exact_tree_transition(&base_tree, &workspace.tree);
    let graph = InMemoryGraph::from_snapshot(base)?;
    graph.apply_transaction_delta(&delta)?;
    let materialized = graph.to_snapshot();
    if materialized.resolved_tree != workspace.tree {
        return Err(storage(format!(
            "workspace {} semantic overlay did not resolve its exact persisted tree",
            workspace.workspace_id
        )));
    }
    materialized.validate_storage_admission()?;
    Ok(materialized)
}

fn resolve_workspace_base_graph_snapshot(
    authority_snapshot: &GraphSnapshot,
    metadata: &PersistedRepositoryAuthority,
    base_target: Option<&RefTarget>,
) -> Result<GraphSnapshot, KinDbError> {
    let mut base = authority_snapshot.clone();
    base.repository_authority = None;

    if let Some(target) = base_target {
        let change_id = target_change_id(metadata, target)?;
        let expected_root_hash = crate::storage::merkle::compute_graph_root_hash(&base);
        let history = InMemoryGraph::from_snapshot_without_text_index_with_root_hash(
            base.clone(),
            expected_root_hash,
        )?;
        let resolved = history.resolve_graph_at(&change_id)?;
        base.entities = resolved.entities;
        base.relations = resolved.relations;
        base.entity_revisions = resolved.entity_revisions;
        base.resolved_tree = resolved.tree;
        base.external_references = resolved.external_references;
    } else {
        base.entities.clear();
        base.relations.clear();
        base.entity_revisions.clear();
        base.resolved_tree = ResolvedTree::default();
        base.external_references.clear();
    }
    rebuild_snapshot_adjacency(&mut base);
    base.validate_storage_admission()?;
    Ok(base)
}

fn derive_workspace_semantic_overlay(
    base: &GraphSnapshot,
    desired: &GraphSnapshot,
) -> Result<WorkspaceSemanticOverlay, KinDbError> {
    let entity_deltas = base
        .entities
        .keys()
        .chain(desired.entities.keys())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|entity_id| {
            match (
                base.entities.get(&entity_id),
                desired.entities.get(&entity_id),
            ) {
                (None, Some(new)) => Some(EntityDelta::Added { new: new.clone() }),
                (Some(old), Some(new)) if old != new => Some(EntityDelta::Modified {
                    old: old.clone(),
                    new: new.clone(),
                }),
                (Some(old), None) => Some(EntityDelta::Removed { old: old.clone() }),
                (Some(_), Some(_)) | (None, None) => None,
            }
        })
        .collect();
    let relation_deltas = base
        .relations
        .keys()
        .chain(desired.relations.keys())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|relation_id| {
            match (
                base.relations.get(&relation_id),
                desired.relations.get(&relation_id),
            ) {
                (None, Some(new)) => Some(RelationDelta::Added { new: new.clone() }),
                (Some(old), Some(new)) if old != new => Some(RelationDelta::Modified {
                    old: old.clone(),
                    new: new.clone(),
                }),
                (Some(old), None) => Some(RelationDelta::Removed { old: old.clone() }),
                (Some(_), Some(_)) | (None, None) => None,
            }
        })
        .collect();
    let external_reference_deltas = base
        .external_references
        .keys()
        .chain(desired.external_references.keys())
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|external_reference_id| {
            match (
                base.external_references.get(&external_reference_id),
                desired.external_references.get(&external_reference_id),
            ) {
                (None, Some(new)) => Ok(Some(ExternalReferenceDelta::Added { new: new.clone() })),
                (Some(old), Some(new)) if old != new => Err(storage(format!(
                    "workspace cumulative semantic overlay cannot modify immutable external \
                     reference {external_reference_id}; remove the old coordinate and add a new \
                     identity"
                ))),
                (Some(old), None) => Ok(Some(ExternalReferenceDelta::Removed { old: old.clone() })),
                (Some(_), Some(_)) | (None, None) => Ok(None),
            }
        })
        .collect::<Result<Vec<_>, KinDbError>>()?
        .into_iter()
        .flatten()
        .collect();
    WorkspaceSemanticOverlay::new_with_external_references(
        entity_deltas,
        relation_deltas,
        external_reference_deltas,
    )
    .map_err(Into::into)
}

fn validate_exact_workspace_graph(
    desired: &GraphSnapshot,
    rematerialized: &GraphSnapshot,
    workspace: &WorkspaceState,
) -> Result<(), KinDbError> {
    if desired.entities != rematerialized.entities {
        return Err(storage(format!(
            "workspace {} cumulative semantic overlay did not reproduce the desired entities",
            workspace.workspace_id
        )));
    }
    if desired.relations != rematerialized.relations {
        return Err(storage(format!(
            "workspace {} cumulative semantic overlay did not reproduce the desired relations",
            workspace.workspace_id
        )));
    }
    if desired.external_references != rematerialized.external_references {
        return Err(storage(format!(
            "workspace {} cumulative semantic overlay did not reproduce the desired external references",
            workspace.workspace_id
        )));
    }
    if desired.resolved_tree != rematerialized.resolved_tree
        || rematerialized.resolved_tree != workspace.tree
    {
        return Err(storage(format!(
            "workspace {} cumulative semantic overlay did not reproduce the desired exact tree",
            workspace.workspace_id
        )));
    }
    Ok(())
}

fn exact_tree_transition(base: &ResolvedTree, desired: &ResolvedTree) -> Vec<TreeDelta> {
    base.artifacts()
        .map(|artifact| artifact.artifact_id)
        .chain(desired.artifacts().map(|artifact| artifact.artifact_id))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(
            |artifact_id| match (base.get(&artifact_id), desired.get(&artifact_id)) {
                (None, Some(new)) => Some(TreeDelta::Added {
                    artifact_id,
                    new: new.located_entry(),
                }),
                (Some(old), Some(new)) if old != new => Some(TreeDelta::Updated {
                    artifact_id,
                    old: old.located_entry(),
                    new: new.located_entry(),
                }),
                (Some(old), None) => Some(TreeDelta::Removed {
                    artifact_id,
                    old: old.located_entry(),
                }),
                (Some(_), Some(_)) | (None, None) => None,
            },
        )
        .collect()
}

fn rebuild_snapshot_adjacency(snapshot: &mut GraphSnapshot) {
    snapshot.outgoing.clear();
    snapshot.incoming.clear();
    for relation in snapshot.relations.values() {
        if let Some(source) = relation.src.as_entity() {
            snapshot
                .outgoing
                .entry(source)
                .or_default()
                .push(relation.id);
        }
        if let Some(target) = relation.dst.as_entity() {
            snapshot
                .incoming
                .entry(target)
                .or_default()
                .push(relation.id);
        }
    }
    for relations in snapshot.outgoing.values_mut() {
        relations.sort_unstable();
    }
    for relations in snapshot.incoming.values_mut() {
        relations.sort_unstable();
    }
}

fn validate_workspace_authority(
    snapshot: &GraphSnapshot,
    metadata: &PersistedRepositoryAuthority,
) -> Result<(), KinDbError> {
    for workspace in &metadata.workspaces {
        validate_workspace_state(snapshot, metadata, workspace)?;
        for artifact in workspace.tree.artifacts() {
            workspace_artifact_projection_mtime(metadata, workspace, artifact.artifact_id)?;
        }
    }
    Ok(())
}

fn validate_workspace_state(
    snapshot: &GraphSnapshot,
    metadata: &PersistedRepositoryAuthority,
    workspace: &WorkspaceState,
) -> Result<(), KinDbError> {
    workspace.validate()?;
    validate_workspace_head(snapshot, metadata, &workspace.head)?;
    // `base_target` is the exact baseline this workspace tree was last
    // materialized against. A symbolic ref may advance independently after
    // that point; rewriting every workspace as a side effect of a ref update
    // would collapse independent sessions and make multi-workspace dogfood
    // impossible. A workspace mutation itself is checked against the current
    // symbolic resolution by `validate_workspace_symbolic_head_at_mutation`.
    if let Some(base) = &workspace.base_target {
        validate_target_exists(snapshot, metadata, base)?;
        let expected_tree = resolve_target_tree_hash(snapshot, metadata, base)?;
        if workspace.base_tree_hash != Some(expected_tree) {
            return Err(ModelError::Conflict(format!(
                "workspace {} base tree does not match its exact target",
                workspace.workspace_id
            ))
            .into());
        }
        if workspace.tree_hash == expected_tree && workspace.semantic_overlay.is_empty() {
            let change_id = target_change_id(metadata, base)?;
            let resolved_policy = metadata
                .admission_policies
                .iter()
                .find(|resolved| resolved.change_id == change_id)
                .ok_or_else(|| {
                    storage(format!(
                        "workspace {} base change {} has no resolved admission-policy record",
                        workspace.workspace_id, change_id
                    ))
                })?
                .policy
                .as_ref()
                .ok_or_else(|| {
                    ModelError::Conflict(format!(
                        "clean workspace {} cannot anchor to change {} without resolved shared admission policy",
                        workspace.workspace_id, change_id
                    ))
                })?;
            if &workspace.shared_admission_policy != resolved_policy {
                return Err(ModelError::Conflict(format!(
                    "clean workspace {} shared admission policy does not equal base change {} policy",
                    workspace.workspace_id, change_id
                ))
                .into());
            }
        }
    } else {
        // An unborn workspace has no semantic base change from which to
        // derive policy. Its complete policy remains self-contained workspace
        // authority until the first semantic change records that state.
    }

    workspace.shared_admission_policy.validate()?;
    if workspace.shared_admission_policy.stamp() != workspace.admission_policy.shared {
        return Err(ModelError::Conflict(format!(
            "workspace {} full shared admission policy does not match its effective stamp",
            workspace.workspace_id
        ))
        .into());
    }
    let local_matches = metadata.local_overlays.iter().any(|overlay| {
        overlay.workspace_id == workspace.workspace_id
            && overlay.stamp() == workspace.admission_policy.local
    });
    if !local_matches {
        return Err(ModelError::Conflict(format!(
            "workspace {} names a local overlay absent from authority",
            workspace.workspace_id
        ))
        .into());
    }
    materialize_workspace_graph_snapshot(snapshot, metadata, workspace)?;
    Ok(())
}

fn validate_workspace_symbolic_head_at_mutation(
    metadata: &PersistedRepositoryAuthority,
    workspace: &WorkspaceState,
) -> Result<(), KinDbError> {
    let WorkspaceHead::Symbolic { target } = &workspace.head else {
        return Ok(());
    };
    let resolved = resolve_symbolic_ref_target(metadata, target)?;
    if workspace.base_target != resolved {
        return Err(ModelError::Conflict(format!(
            "workspace {} mutation base target does not resolve from symbolic HEAD {}",
            workspace.workspace_id, target
        ))
        .into());
    }
    Ok(())
}

fn workspace_projection_mtime(
    metadata: &PersistedRepositoryAuthority,
    workspace: &WorkspaceState,
) -> Result<u64, KinDbError> {
    let operation = metadata
        .operation_log
        .iter()
        .rev()
        .find(|operation| {
            operation
                .workspace_mutation
                .as_ref()
                .is_some_and(|mutation| {
                    mutation.workspace_id == workspace.workspace_id
                        && mutation.new_generation == workspace.generation
                })
        })
        .ok_or_else(|| {
            storage(format!(
                "workspace {} generation {} has no durable producing operation",
                workspace.workspace_id, workspace.generation
            ))
        })?;
    u64::try_from(operation.committed_at.0.timestamp()).map_err(|_| {
        storage(format!(
            "workspace {} producing operation predates the Unix epoch",
            workspace.workspace_id
        ))
    })
}

fn workspace_artifact_projection_mtime(
    metadata: &PersistedRepositoryAuthority,
    workspace: &WorkspaceState,
    artifact_id: kin_model::ArtifactId,
) -> Result<u64, KinDbError> {
    let mut logical_second: Option<u64> = None;
    for operation in &metadata.operation_log {
        let Some(mutation) = operation.workspace_mutation.as_ref().filter(|mutation| {
            mutation.workspace_id == workspace.workspace_id
                && mutation
                    .tree_deltas
                    .iter()
                    .any(|delta| delta.artifact_id() == artifact_id)
        }) else {
            continue;
        };
        let committed_second =
            u64::try_from(operation.committed_at.0.timestamp()).map_err(|_| {
                storage(format!(
                    "workspace {} artifact {:?} producing operation predates the Unix epoch",
                    workspace.workspace_id, artifact_id
                ))
            })?;
        logical_second = Some(match logical_second {
            None => committed_second,
            Some(previous) => committed_second.max(previous.checked_add(1).ok_or_else(|| {
                storage(format!(
                    "workspace {} artifact {:?} projection mtime overflow",
                    workspace.workspace_id, artifact_id
                ))
            })?),
        });
        debug_assert!(
            mutation
                .tree_deltas
                .iter()
                .any(|delta| delta.artifact_id() == artifact_id),
            "filtered mutation must touch artifact"
        );
    }
    logical_second.ok_or_else(|| {
        storage(format!(
            "workspace {} live artifact {:?} has no durable producing operation",
            workspace.workspace_id, artifact_id
        ))
    })
}

fn resolve_symbolic_ref_target(
    metadata: &PersistedRepositoryAuthority,
    name: &RefName,
) -> Result<Option<RefTarget>, KinDbError> {
    let refs: BTreeMap<_, _> = metadata
        .ref_state
        .refs
        .iter()
        .map(|repository_ref| (&repository_ref.name, &repository_ref.target))
        .collect();
    let mut current = name;
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(current.clone()) {
            return Err(
                ModelError::Conflict(format!("symbolic ref cycle reaches {current}")).into(),
            );
        }
        match refs.get(current) {
            None => return Ok(None),
            Some(RefTarget::Symbolic { target }) => current = target,
            Some(target) => return Ok(Some((*target).clone())),
        }
    }
}

fn target_change_id(
    metadata: &PersistedRepositoryAuthority,
    target: &RefTarget,
) -> Result<SemanticChangeId, KinDbError> {
    match target {
        RefTarget::Change { change_id } => Ok(*change_id),
        RefTarget::ExternalObject { object } => {
            let commit_oid =
                peel_authority_external_target(metadata, *object)?.ok_or_else(|| {
                    ModelError::InvalidOperation(format!(
                        "workspace base target {} does not peel to a commit",
                        object.oid
                    ))
                })?;
            metadata
                .aliases
                .iter()
                .find(|alias| alias.oid == commit_oid)
                .map(|alias| alias.change_id)
                .ok_or_else(|| {
                    ModelError::InvalidOperation(format!(
                        "external commit {} peeled from workspace target {} has no semantic change alias",
                        commit_oid, object.oid
                    ))
                    .into()
                })
        }
        RefTarget::Symbolic { .. } => Err(ModelError::InvalidOperation(
            "workspace base target must be resolved".to_string(),
        )
        .into()),
    }
}

/// Peel a persisted external target using only the CAS-validated Git authority
/// closure already admitted into repository state.
///
/// No Git repository or checkout is consulted. `GitExternalAuthority` was
/// constructed from exact object bodies and is revalidated against immutable
/// source CAS on open and on every authority update, so its single
/// `TagTarget` dependency is the trusted, graph-owned peeling edge.
fn peel_authority_external_target(
    metadata: &PersistedRepositoryAuthority,
    object: ExternalObjectId,
) -> Result<Option<GitObjectId>, KinDbError> {
    let Some(authority) = metadata.git_external_authority.as_ref() else {
        if object.kind == ExternalObjectKind::Commit {
            return Ok(Some(object.oid));
        }
        return Err(ModelError::InvalidOperation(format!(
            "external tag {} has no persisted Git authority for exact peeling",
            object.oid
        ))
        .into());
    };
    let entries = authority
        .closure
        .objects
        .iter()
        .map(|entry| (entry.record.object, entry))
        .collect::<BTreeMap<_, _>>();
    let mut current = object;
    let mut seen = BTreeSet::new();
    while current.kind == ExternalObjectKind::Tag {
        let tag = current;
        if !seen.insert(current) {
            return Err(ModelError::Conflict(format!(
                "persisted Git authority contains an annotated-tag cycle through {}",
                current.oid
            ))
            .into());
        }
        let entry = entries.get(&current).ok_or_else(|| {
            ModelError::InvalidOperation(format!(
                "external tag {} is absent from the persisted Git authority closure",
                current.oid
            ))
        })?;
        let mut targets = entry.dependencies.iter().filter_map(|dependency| {
            (dependency.kind == GitObjectDependencyKind::TagTarget).then_some(dependency.target)
        });
        current = targets.next().ok_or_else(|| {
            ModelError::InvalidOperation(format!(
                "external tag {} has no exact target in persisted Git authority",
                tag.oid
            ))
        })?;
        if targets.next().is_some() {
            return Err(ModelError::InvalidOperation(format!(
                "external tag {} has multiple exact targets in persisted Git authority",
                entry.record.object.oid
            ))
            .into());
        }
    }
    Ok((current.kind == ExternalObjectKind::Commit).then_some(current.oid))
}

fn validate_workspace_head(
    snapshot: &GraphSnapshot,
    metadata: &PersistedRepositoryAuthority,
    head: &WorkspaceHead,
) -> Result<(), KinDbError> {
    match head {
        WorkspaceHead::Symbolic { .. } => Ok(()),
        WorkspaceHead::Detached { target } => validate_target_exists(snapshot, metadata, target),
    }
}

fn resolve_target_tree_hash(
    snapshot: &GraphSnapshot,
    metadata: &PersistedRepositoryAuthority,
    target: &RefTarget,
) -> Result<Hash256, KinDbError> {
    let change_id = target_change_id(metadata, target)?;
    let mut replay = snapshot.clone();
    replay.repository_authority = None;
    let graph = InMemoryGraph::from_snapshot(replay)?;
    let tree = graph.resolve_tree_at(&change_id)?;
    kin_model::compute_resolved_tree_hash(&tree).map_err(Into::into)
}

fn validate_new_local_overlay_bodies<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    delta: Option<&kin_model::FrozenLocalOverlayDelta>,
) -> Result<(), KinDbError> {
    let Some(overlay) = delta.and_then(|delta| delta.new.as_ref()) else {
        return Ok(());
    };
    for source in &overlay.sources {
        load_exact_body(
            backend,
            repository_id,
            source.body_hash,
            source.body_len,
            "local admission rule source",
        )?;
    }
    Ok(())
}

fn validate_new_change_bodies<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    changes: &[kin_model::SemanticChange],
    policies: &[ChangeAdmissionPolicy],
) -> Result<(), KinDbError> {
    validate_change_tree_bodies(backend, repository_id, changes)?;
    let changed_ids: BTreeSet<_> = changes.iter().map(|change| change.id).collect();
    for resolved in policies
        .iter()
        .filter(|resolved| changed_ids.contains(&resolved.change_id))
    {
        if let Some(policy) = &resolved.policy {
            validate_shared_policy_bodies(backend, repository_id, policy)?;
        }
    }
    Ok(())
}

fn validate_merge_transaction_delta_bodies<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    delta: Option<&kin_model::MergeTransactionDelta>,
) -> Result<(), KinDbError> {
    let Some(delta) = delta else {
        return Ok(());
    };
    let mut validated = BTreeSet::new();
    for record in [delta.old.as_ref(), delta.new.as_ref()]
        .into_iter()
        .flatten()
    {
        for entry in &record.entries {
            let MergeEntryResolution::Payload {
                payload: MergeResolutionPayload::Artifact(artifact),
                ..
            } = &entry.resolution
            else {
                continue;
            };
            let Some(digest) = artifact.entry.blob_identity() else {
                continue;
            };
            if validated.insert(digest) {
                load_unbounded_body(
                    backend,
                    repository_id,
                    digest,
                    &format!(
                        "merge transaction {} authored artifact {}",
                        record.workspace_id, artifact.path
                    ),
                )?;
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
struct AuthorityBodyRequirement {
    expected_len: Option<u64>,
    label: String,
}

fn require_authority_body(
    requirements: &mut BTreeMap<Hash256, AuthorityBodyRequirement>,
    digest: Hash256,
    expected_len: Option<u64>,
    label: impl Into<String>,
) -> Result<(), KinDbError> {
    let label = label.into();
    match requirements.entry(digest) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(AuthorityBodyRequirement {
                expected_len,
                label,
            });
        }
        std::collections::btree_map::Entry::Occupied(mut entry) => {
            let requirement = entry.get_mut();
            match (requirement.expected_len, expected_len) {
                (Some(previous), Some(current)) if previous != current => {
                    return Err(storage(format!(
                        "immutable body {digest} is declared with both length {previous} by {} and length {current} by {label}",
                        requirement.label
                    )));
                }
                (None, Some(current)) => requirement.expected_len = Some(current),
                (Some(_), Some(_)) | (Some(_), None) | (None, None) => {}
            }
        }
    }
    Ok(())
}

fn collect_tree_body_requirements(
    requirements: &mut BTreeMap<Hash256, AuthorityBodyRequirement>,
    tree: &ResolvedTree,
    label: &str,
) -> Result<(), KinDbError> {
    for artifact in tree.artifacts() {
        if let Some(digest) = artifact.entry.blob_identity() {
            require_authority_body(
                requirements,
                digest,
                None,
                format!("{label} {}", artifact.path),
            )?;
        }
    }
    Ok(())
}

fn collect_shared_policy_body_requirements(
    requirements: &mut BTreeMap<Hash256, AuthorityBodyRequirement>,
    policy: &SharedAdmissionPolicy,
) -> Result<(), KinDbError> {
    policy.validate()?;
    for source in &policy.sources {
        require_authority_body(
            requirements,
            source.body_hash,
            Some(source.body_len),
            format!("shared admission source {}", source.path),
        )?;
    }
    for allowance in &policy.sensitive_allowances {
        require_authority_body(
            requirements,
            allowance.content_hash,
            None,
            format!("sensitive admitted artifact {}", allowance.path),
        )?;
    }
    Ok(())
}

fn collect_git_authority_body_requirements(
    requirements: &mut BTreeMap<Hash256, AuthorityBodyRequirement>,
    authority: &GitExternalAuthority,
    label: &str,
) -> Result<(), KinDbError> {
    for entry in &authority.closure.objects {
        require_authority_body(
            requirements,
            entry.record.body_hash,
            Some(entry.record.body_len),
            format!("{label} {}", entry.record.object.oid),
        )?;
    }
    Ok(())
}

fn collect_tree_delta_body_requirements(
    requirements: &mut BTreeMap<Hash256, AuthorityBodyRequirement>,
    deltas: &[TreeDelta],
    label: &str,
) -> Result<(), KinDbError> {
    for delta in deltas {
        for (state, side) in [(delta.old_state(), "old"), (delta.new_state(), "new")] {
            let Some(state) = state else {
                continue;
            };
            if let Some(digest) = state.entry.blob_identity() {
                require_authority_body(
                    requirements,
                    digest,
                    None,
                    format!("{label} {side} artifact {}", state.path),
                )?;
            }
        }
    }
    Ok(())
}

fn collect_local_overlay_body_requirements(
    requirements: &mut BTreeMap<Hash256, AuthorityBodyRequirement>,
    overlay: &FrozenLocalOverlay,
    label: &str,
) -> Result<(), KinDbError> {
    for source in &overlay.sources {
        require_authority_body(
            requirements,
            source.body_hash,
            Some(source.body_len),
            format!("{label} {:?} precedence {}", source.kind, source.precedence),
        )?;
    }
    Ok(())
}

fn collect_merge_transaction_body_requirements(
    requirements: &mut BTreeMap<Hash256, AuthorityBodyRequirement>,
    record: &MergeTransactionRecord,
) -> Result<(), KinDbError> {
    for entry in &record.entries {
        let MergeEntryResolution::Payload {
            payload: MergeResolutionPayload::Artifact(artifact),
            ..
        } = &entry.resolution
        else {
            continue;
        };
        if let Some(digest) = artifact.entry.blob_identity() {
            require_authority_body(
                requirements,
                digest,
                None,
                format!(
                    "merge transaction {} authored artifact {}",
                    record.workspace_id, artifact.path
                ),
            )?;
        }
    }
    Ok(())
}

fn collect_operation_body_requirements(
    requirements: &mut BTreeMap<Hash256, AuthorityBodyRequirement>,
    operation: &RepositoryOperationRecord,
) -> Result<(), KinDbError> {
    if let Some(delta) = &operation.git_authority_delta {
        for (authority, state) in [(delta.old.as_ref(), "old"), (delta.new.as_ref(), "new")] {
            if let Some(authority) = authority {
                collect_git_authority_body_requirements(
                    requirements,
                    authority,
                    &format!("operation {} {state} Git object", operation.operation_id),
                )?;
            }
        }
    }
    if let Some(mutation) = &operation.workspace_mutation {
        collect_tree_delta_body_requirements(
            requirements,
            &mutation.tree_deltas,
            &format!(
                "operation {} workspace {}",
                operation.operation_id, mutation.workspace_id
            ),
        )?;
        collect_shared_policy_body_requirements(
            requirements,
            &mutation.new_shared_admission_policy,
        )?;
    }
    if let Some(delta) = &operation.local_overlay_delta {
        for (overlay, state) in [(delta.old.as_ref(), "old"), (delta.new.as_ref(), "new")] {
            if let Some(overlay) = overlay {
                collect_local_overlay_body_requirements(
                    requirements,
                    overlay,
                    &format!(
                        "operation {} {state} local admission source",
                        operation.operation_id
                    ),
                )?;
            }
        }
    }
    if let Some(delta) = &operation.merge_transaction_delta {
        for record in [delta.old.as_ref(), delta.new.as_ref()]
            .into_iter()
            .flatten()
        {
            collect_merge_transaction_body_requirements(requirements, record)?;
        }
    }
    Ok(())
}

fn collect_all_authority_body_requirements(
    snapshot: &GraphSnapshot,
) -> Result<BTreeMap<Hash256, AuthorityBodyRequirement>, KinDbError> {
    let metadata = snapshot
        .repository_authority
        .as_ref()
        .expect("validated authority snapshot has metadata");
    let mut requirements = BTreeMap::new();
    for record in &metadata.external_objects {
        require_authority_body(
            &mut requirements,
            record.body_hash,
            Some(record.body_len),
            format!("external object {}", record.object.oid),
        )?;
    }
    if let Some(authority) = &metadata.git_external_authority {
        collect_git_authority_body_requirements(
            &mut requirements,
            authority,
            "Git external object",
        )?;
    }
    for change in snapshot.changes.values() {
        collect_tree_delta_body_requirements(
            &mut requirements,
            &change.tree_deltas,
            &format!("change {}", change.id),
        )?;
    }
    for workspace in &metadata.workspaces {
        collect_tree_body_requirements(
            &mut requirements,
            &workspace.tree,
            "persisted workspace tree",
        )?;
        collect_shared_policy_body_requirements(
            &mut requirements,
            &workspace.shared_admission_policy,
        )?;
    }
    for policy in &metadata.admission_policies {
        if let Some(policy) = &policy.policy {
            collect_shared_policy_body_requirements(&mut requirements, policy)?;
        }
    }
    for overlay in &metadata.local_overlays {
        collect_local_overlay_body_requirements(
            &mut requirements,
            overlay,
            "local admission rule source",
        )?;
    }
    for record in &metadata.merge_transactions {
        collect_merge_transaction_body_requirements(&mut requirements, record)?;
    }
    for operation in &metadata.operation_log {
        collect_operation_body_requirements(&mut requirements, operation)?;
    }
    Ok(requirements)
}

fn load_verified_authority_body(
    batch: &dyn VerifiedSourceBlobBatch,
    digest: Hash256,
    requirement: &AuthorityBodyRequirement,
) -> Result<Option<Vec<u8>>, KinDbError> {
    let Some(body) = batch.load_verified(SourceBlobValidationRequest {
        digest: *digest.as_bytes(),
        max_bytes: requirement.expected_len.unwrap_or(MAX_SOURCE_BLOB_BYTES),
    })?
    else {
        return Ok(None);
    };
    if body.digest() != *digest.as_bytes() {
        return Err(storage(format!(
            "backend returned immutable body {} for requested {digest}",
            hex::encode(body.digest())
        )));
    }
    let body_len = u64::try_from(body.bytes().len()).map_err(|_| {
        storage(format!(
            "{} body length does not fit u64",
            requirement.label
        ))
    })?;
    validate_source_blob_size(body_len, &requirement.label)?;
    if requirement
        .expected_len
        .is_some_and(|expected| expected != body_len)
    {
        return Err(storage(format!(
            "{} body {digest} has length {body_len}, expected {}",
            requirement.label,
            requirement
                .expected_len
                .expect("checked exact length above")
        )));
    }
    Ok(Some(body.into_bytes()))
}

fn validate_external_records_for_body(
    metadata: &PersistedRepositoryAuthority,
    indexes: &BTreeMap<Hash256, Vec<usize>>,
    digest: Hash256,
    body: &[u8],
) -> Result<(), KinDbError> {
    if let Some(indexes) = indexes.get(&digest) {
        for index in indexes {
            metadata.external_objects[*index].validate_raw(body)?;
        }
    }
    Ok(())
}

struct StreamingRepositoryGitObjectBodyLoader<'a> {
    batch: &'a dyn VerifiedSourceBlobBatch,
    metadata: &'a PersistedRepositoryAuthority,
    requirements: &'a BTreeMap<Hash256, AuthorityBodyRequirement>,
    external_record_indexes: &'a BTreeMap<Hash256, Vec<usize>>,
    validated_digests: &'a mut BTreeSet<Hash256>,
    verified_bytes: &'a mut u64,
}

impl GitObjectBodyLoader for StreamingRepositoryGitObjectBodyLoader<'_> {
    type Error = KinDbError;

    fn load_body(
        &mut self,
        body_hash: &Hash256,
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
        let Some(requirement) = self.requirements.get(body_hash) else {
            return Ok(None);
        };
        let Some(body) = load_verified_authority_body(self.batch, *body_hash, requirement)? else {
            return Ok(None);
        };
        // Git object identity includes the object kind while Kin's source CAS
        // identity does not. The same raw bytes can therefore back (for
        // example) both a blob and a tag. The model loader asks once per Git
        // object; re-read that rare cross-kind duplicate instead of retaining
        // an unbounded aggregate cache. All other authority surfaces remain
        // globally de-duplicated by `requirements`.
        if self.validated_digests.insert(*body_hash) {
            validate_external_records_for_body(
                self.metadata,
                self.external_record_indexes,
                *body_hash,
                &body,
            )?;
            *self.verified_bytes = self
                .verified_bytes
                .checked_add(body.len() as u64)
                .ok_or_else(|| {
                    storage("verified authority body byte count overflowed".to_string())
                })?;
        }
        Ok(Some(body))
    }
}

fn validate_all_authority_bodies<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    snapshot: &GraphSnapshot,
) -> Result<(), KinDbError> {
    let metadata = snapshot
        .repository_authority
        .as_ref()
        .expect("validated authority snapshot has metadata");
    let requirements = {
        let _span =
            tracing::info_span!("kindb.repository.collect_authority_body_requirements").entered();
        collect_all_authority_body_requirements(snapshot)?
    };
    if requirements.is_empty() {
        return Ok(());
    }
    let mut external_record_indexes = BTreeMap::<Hash256, Vec<usize>>::new();
    for (index, record) in metadata.external_objects.iter().enumerate() {
        external_record_indexes
            .entry(record.body_hash)
            .or_default()
            .push(index);
    }
    let mut git_digests = BTreeSet::new();
    if let Some(authority) = metadata.git_external_authority.as_ref() {
        for entry in &authority.closure.objects {
            git_digests.insert(entry.record.body_hash);
        }
    }
    let mut validated_digests = BTreeSet::new();
    let mut verified_bytes = 0u64;
    let mut validation_invocations = 0usize;
    let mut validation_completed = false;
    let backend_result = {
        let mut validate_batch = |batch: &dyn VerifiedSourceBlobBatch| {
            validation_invocations = validation_invocations.checked_add(1).ok_or_else(|| {
                storage("authority body batch invocation count overflowed".to_string())
            })?;
            if validation_invocations != 1 {
                return Err(storage(
                    "storage backend invoked the authority body batch more than once".to_string(),
                ));
            }
            for (digest, requirement) in &requirements {
                if git_digests.contains(digest) {
                    continue;
                }
                let body = load_verified_authority_body(batch, *digest, requirement)?.ok_or_else(
                    || {
                        storage(format!(
                            "{} body {digest} is absent from immutable source CAS",
                            requirement.label
                        ))
                    },
                )?;
                validate_external_records_for_body(
                    metadata,
                    &external_record_indexes,
                    *digest,
                    &body,
                )?;
                validated_digests.insert(*digest);
                verified_bytes =
                    verified_bytes
                        .checked_add(body.len() as u64)
                        .ok_or_else(|| {
                            storage("verified authority body byte count overflowed".to_string())
                        })?;
            }
            if let Some(authority) = metadata.git_external_authority.as_ref() {
                let mut loader = StreamingRepositoryGitObjectBodyLoader {
                    batch,
                    metadata,
                    requirements: &requirements,
                    external_record_indexes: &external_record_indexes,
                    validated_digests: &mut validated_digests,
                    verified_bytes: &mut verified_bytes,
                };
                authority
                    .validate_with_body_loader(&mut loader)
                    .map_err(|error| {
                        KinDbError::from(ModelError::InvalidOperation(format!(
                            "Git external authority body validation failed: {error}"
                        )))
                    })?;
            }
            validation_completed = true;
            Ok(())
        };
        let _span = tracing::info_span!("kindb.repository.load_authority_body_batch").entered();
        backend.with_verified_source_blob_batch(repository_id.as_str(), &mut validate_batch)
    };
    backend_result?;
    if validation_invocations != 1 {
        return Err(storage(format!(
            "storage backend invoked the authority body batch {validation_invocations} times; expected exactly once"
        )));
    }
    if !validation_completed {
        return Err(storage(
            "storage backend returned success after authority body validation failed".to_string(),
        ));
    }
    if validated_digests.len() != requirements.len() {
        let missing = requirements
            .keys()
            .find(|digest| !validated_digests.contains(digest))
            .expect("different set lengths imply a missing requirement");
        return Err(storage(format!(
            "{} body {missing} is absent from immutable source CAS",
            requirements
                .get(missing)
                .expect("missing digest came from requirements")
                .label
        )));
    }
    tracing::debug!(
        repository = %repository_id,
        distinct_bodies = requirements.len(),
        verified_bytes,
        "loaded distinct repository authority bodies"
    );
    Ok(())
}

fn validate_change_tree_bodies<'a, B, I>(
    backend: &B,
    repository_id: &RepositoryId,
    changes: I,
) -> Result<(), KinDbError>
where
    B: StorageBackend + ?Sized,
    I: IntoIterator<Item = &'a kin_model::SemanticChange>,
{
    let mut validated = BTreeSet::new();
    for change in changes {
        for delta in &change.tree_deltas {
            for (state, side) in [(delta.old_state(), "old"), (delta.new_state(), "new")] {
                let Some(state) = state else {
                    continue;
                };
                let Some(digest) = state.entry.blob_identity() else {
                    continue;
                };
                if validated.insert(digest) {
                    validate_tree_entry_body(
                        backend,
                        repository_id,
                        state.entry,
                        &format!("change {} {side} artifact {}", change.id, state.path),
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn validate_shared_policy_bodies<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    policy: &SharedAdmissionPolicy,
) -> Result<(), KinDbError> {
    policy.validate()?;
    for source in &policy.sources {
        load_exact_body(
            backend,
            repository_id,
            source.body_hash,
            source.body_len,
            &format!("shared admission source {}", source.path),
        )?;
    }
    for allowance in &policy.sensitive_allowances {
        load_unbounded_body(
            backend,
            repository_id,
            allowance.content_hash,
            &format!("sensitive admitted artifact {}", allowance.path),
        )?;
    }
    Ok(())
}

fn validate_tree_bodies<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    tree: &kin_model::ResolvedTree,
    label: &str,
) -> Result<(), KinDbError> {
    for artifact in tree.artifacts() {
        validate_tree_entry_body(
            backend,
            repository_id,
            artifact.entry,
            &format!("{label} {}", artifact.path),
        )?;
    }
    Ok(())
}

fn validate_tree_entry_body<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    entry: TreeEntry,
    label: &str,
) -> Result<(), KinDbError> {
    if let Some(digest) = entry.blob_identity() {
        load_unbounded_body(backend, repository_id, digest, label)?;
    }
    Ok(())
}

fn load_exact_body<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    digest: Hash256,
    body_len: u64,
    label: &str,
) -> Result<Vec<u8>, KinDbError> {
    let body = backend
        .load_source_blob_bounded(repository_id.as_str(), *digest.as_bytes(), body_len)?
        .ok_or_else(|| {
            storage(format!(
                "{label} body {} is absent from immutable source CAS",
                digest
            ))
        })?;
    if u64::try_from(body.len()).ok() != Some(body_len) {
        return Err(storage(format!(
            "{label} body {} has length {}, expected {}",
            digest,
            body.len(),
            body_len
        )));
    }
    verify_source_blob_digest(*digest.as_bytes(), &body, label)?;
    Ok(body)
}

fn load_unbounded_body<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    digest: Hash256,
    label: &str,
) -> Result<Vec<u8>, KinDbError> {
    let body = backend
        .load_source_blob_bounded(
            repository_id.as_str(),
            *digest.as_bytes(),
            MAX_SOURCE_BLOB_BYTES,
        )?
        .ok_or_else(|| {
            storage(format!(
                "{label} body {} is absent from immutable source CAS",
                digest
            ))
        })?;
    let body_len = u64::try_from(body.len())
        .map_err(|_| storage(format!("{label} body length does not fit u64")))?;
    validate_source_blob_size(body_len, label)?;
    verify_source_blob_digest(*digest.as_bytes(), &body, label)?;
    Ok(body)
}

fn placeholder_roots(generation: u64) -> RootBundle {
    let zero = AuthorityRoot::new(REPOSITORY_ROOT_SCHEMA_VERSION, Hash256::from_bytes([0; 32]));
    RootBundle {
        version: REPOSITORY_ROOT_SCHEMA_VERSION,
        generation,
        history: zero,
        ref_state: zero,
        ref_log: zero,
        collaboration: zero,
        replication: zero,
        local_state: zero,
    }
}

fn compute_roots(
    snapshot: &GraphSnapshot,
    authority: &PersistedRepositoryAuthority,
    generation: u64,
) -> Result<RootBundle, KinDbError> {
    Ok(RootBundle {
        version: REPOSITORY_ROOT_SCHEMA_VERSION,
        generation,
        history: AuthorityRoot::new(
            REPOSITORY_ROOT_SCHEMA_VERSION,
            history_root(snapshot, authority)?,
        ),
        ref_state: AuthorityRoot::new(REPOSITORY_ROOT_SCHEMA_VERSION, ref_state_root(authority)?),
        ref_log: AuthorityRoot::new(REPOSITORY_ROOT_SCHEMA_VERSION, ref_log_root(authority)?),
        collaboration: AuthorityRoot::new(
            REPOSITORY_ROOT_SCHEMA_VERSION,
            collaboration_root(snapshot)?,
        ),
        replication: AuthorityRoot::new(
            REPOSITORY_ROOT_SCHEMA_VERSION,
            replication_root(authority)?,
        ),
        local_state: AuthorityRoot::new(
            REPOSITORY_ROOT_SCHEMA_VERSION,
            local_state_root(snapshot, authority)?,
        ),
    })
}

fn history_root(
    snapshot: &GraphSnapshot,
    authority: &PersistedRepositoryAuthority,
) -> Result<Hash256, KinDbError> {
    let mut root = DomainRoot::new(b"kin-repository-history-root-v1\0");
    root.unordered("changes", &snapshot.changes.iter().collect::<Vec<_>>())?;
    root.unordered("admission_policies", &authority.admission_policies)?;
    Ok(root.finish())
}

fn ref_state_root(authority: &PersistedRepositoryAuthority) -> Result<Hash256, KinDbError> {
    let mut root = DomainRoot::new(b"kin-repository-ref-state-root-v1\0");
    root.ordered("refs", &authority.ref_state.refs)?;
    root.ordered(
        "default_ref",
        &authority.ref_state.default_ref.iter().collect::<Vec<_>>(),
    )?;
    Ok(root.finish())
}

fn ref_log_root(authority: &PersistedRepositoryAuthority) -> Result<Hash256, KinDbError> {
    let entries = authority
        .operation_log
        .iter()
        .filter(|operation| {
            !operation.ref_mutations.is_empty() || operation.default_ref_mutation.is_some()
        })
        .map(RefLogProjection::from_operation)
        .collect::<Vec<_>>();
    let mut root = DomainRoot::new(b"kin-repository-ref-log-root-v1\0");
    root.ordered("ref_operations", &entries)?;
    Ok(root.finish())
}

/// Replicated ref-log entry. Repository transactions may also carry local
/// workspace and overlay mutations, but those must not perturb a replicated
/// root. The full operation identity remains bound under `local_state`.
#[derive(Serialize)]
struct RefLogProjection {
    operation_id: OperationId,
    repository_id: RepositoryId,
    actor: AuthorId,
    committed_at: Timestamp,
    ref_mutations: Vec<RefMutation>,
    default_ref_mutation: Option<DefaultRefMutation>,
}

impl RefLogProjection {
    fn from_operation(operation: &RepositoryOperationRecord) -> Self {
        let mut ref_mutations = operation.ref_mutations.clone();
        ref_mutations.sort_by(|left, right| left.name.cmp(&right.name));
        Self {
            operation_id: operation.operation_id,
            repository_id: operation.repository_id.clone(),
            actor: operation.actor.clone(),
            committed_at: operation.committed_at.clone(),
            ref_mutations,
            default_ref_mutation: operation.default_ref_mutation.clone(),
        }
    }
}

fn collaboration_root(snapshot: &GraphSnapshot) -> Result<Hash256, KinDbError> {
    let mut root = DomainRoot::new(b"kin-repository-collaboration-root-v1\0");
    root.unordered(
        "work_items",
        &snapshot.work_items.iter().collect::<Vec<_>>(),
    )?;
    root.unordered(
        "annotations",
        &snapshot.annotations.iter().collect::<Vec<_>>(),
    )?;
    root.unordered("work_links", &snapshot.work_links)?;
    root.unordered("reviews", &snapshot.reviews.iter().collect::<Vec<_>>())?;
    root.unordered(
        "review_decisions",
        &snapshot.review_decisions.iter().collect::<Vec<_>>(),
    )?;
    root.unordered("review_notes", &snapshot.review_notes)?;
    root.unordered("review_discussions", &snapshot.review_discussions)?;
    root.unordered(
        "review_assignments",
        &snapshot.review_assignments.iter().collect::<Vec<_>>(),
    )?;
    root.unordered(
        "test_cases",
        &snapshot.test_cases.iter().collect::<Vec<_>>(),
    )?;
    root.unordered(
        "assertions",
        &snapshot.assertions.iter().collect::<Vec<_>>(),
    )?;
    root.unordered(
        "verification_runs",
        &snapshot.verification_runs.iter().collect::<Vec<_>>(),
    )?;
    root.unordered("mock_hints", &snapshot.mock_hints)?;
    root.unordered("contracts", &snapshot.contracts.iter().collect::<Vec<_>>())?;
    root.unordered("actors", &snapshot.actors.iter().collect::<Vec<_>>())?;
    root.unordered("delegations", &snapshot.delegations)?;
    root.unordered("approvals", &snapshot.approvals)?;
    root.unordered("audit_events", &snapshot.audit_events)?;
    Ok(root.finish())
}

fn replication_root(authority: &PersistedRepositoryAuthority) -> Result<Hash256, KinDbError> {
    let mut root = DomainRoot::new(b"kin-repository-replication-root-v2\0");
    root.ordered("external_objects", &authority.external_objects)?;
    root.ordered(
        "git_external_authority",
        &authority.git_external_authority.iter().collect::<Vec<_>>(),
    )?;
    root.ordered("aliases", &authority.aliases)?;
    Ok(root.finish())
}

fn local_state_root(
    snapshot: &GraphSnapshot,
    authority: &PersistedRepositoryAuthority,
) -> Result<Hash256, KinDbError> {
    let operation_identities = authority
        .operation_log
        .iter()
        .map(RepositoryOperationRecord::identity_hash)
        .collect::<kin_model::Result<Vec<_>>>()?;
    let mut root = DomainRoot::new(b"kin-repository-local-root-v2\0");
    root.unordered("sessions", &snapshot.sessions.iter().collect::<Vec<_>>())?;
    root.unordered("intents", &snapshot.intents.iter().collect::<Vec<_>>())?;
    root.unordered("downstream_warnings", &snapshot.downstream_warnings)?;
    root.ordered("workspaces", &authority.workspaces)?;
    root.ordered("local_overlays", &authority.local_overlays)?;
    // Folded only when a merge record exists. An empty list contributes
    // nothing, so every repository that predates durable merge state keeps the
    // local root it already had and needs no re-import. There is no ambiguity
    // between the two states: absent contributes nothing at all, and no
    // non-empty list can fold to nothing.
    if !authority.merge_transactions.is_empty() {
        root.ordered("merge_transactions", &authority.merge_transactions)?;
    }
    root.ordered("operation_identities", &operation_identities)?;
    Ok(root.finish())
}

struct DomainRoot(Sha256);

impl DomainRoot {
    fn new(domain: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        Self(hasher)
    }

    fn unordered<T: Serialize + Sync>(
        &mut self,
        domain: &str,
        values: &[T],
    ) -> Result<(), KinDbError> {
        let mut hashes = values
            .iter()
            .map(|value| canonical_leaf_hash(domain, value))
            .collect::<Result<Vec<_>, _>>()?;
        hashes.sort_unstable();
        self.fold(domain, &hashes);
        Ok(())
    }

    fn ordered<T: Serialize>(&mut self, domain: &str, values: &[T]) -> Result<(), KinDbError> {
        let hashes = values
            .iter()
            .map(|value| canonical_leaf_hash(domain, value))
            .collect::<Result<Vec<_>, _>>()?;
        self.fold(domain, &hashes);
        Ok(())
    }

    fn fold(&mut self, domain: &str, hashes: &[[u8; 32]]) {
        self.0.update((domain.len() as u64).to_le_bytes());
        self.0.update(domain.as_bytes());
        self.0.update((hashes.len() as u64).to_le_bytes());
        for hash in hashes {
            self.0.update(hash);
        }
    }

    fn finish(self) -> Hash256 {
        let digest: [u8; 32] = self.0.finalize().into();
        Hash256::from_bytes(digest)
    }
}

fn canonical_leaf_hash<T: Serialize>(domain: &str, value: &T) -> Result<[u8; 32], KinDbError> {
    let value = serde_json::to_value(value)?;
    let mut hasher = Sha256::new();
    hasher.update(b"kin-repository-root-leaf-v1\0");
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain.as_bytes());
    hash_canonical_json(&mut hasher, &value);
    Ok(hasher.finalize().into())
}

fn hash_canonical_json(hasher: &mut Sha256, value: &serde_json::Value) {
    match value {
        serde_json::Value::Null => hasher.update([0]),
        serde_json::Value::Bool(value) => hasher.update([1, u8::from(*value)]),
        serde_json::Value::Number(value) => {
            hasher.update([2]);
            hash_bytes(hasher, value.to_string().as_bytes());
        }
        serde_json::Value::String(value) => {
            hasher.update([3]);
            hash_bytes(hasher, value.as_bytes());
        }
        serde_json::Value::Array(values) => {
            hasher.update([4]);
            hasher.update((values.len() as u64).to_le_bytes());
            for value in values {
                hash_canonical_json(hasher, value);
            }
        }
        serde_json::Value::Object(values) => {
            hasher.update([5]);
            hasher.update((values.len() as u64).to_le_bytes());
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_unstable();
            for key in keys {
                hash_bytes(hasher, key.as_bytes());
                hash_canonical_json(hasher, &values[key]);
            }
        }
    }
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn storage(message: String) -> KinDbError {
    KinDbError::StorageError(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::backend::{HistoryValidationProof, VerifiedSourceBlob};
    use kin_model::{
        compute_resolved_tree_hash, compute_semantic_change_id, AdmissionCase,
        AdmissionPolicyDelta, AdmissionRuleSource, AdmissionRuleSourceKind, ArtifactId, AuthorId,
        ChangeOrigin, DefaultRefMutation, EffectiveAdmissionPolicyStamp, Entity, EntityDelta,
        EntityId, EntityKind, EntityMetadata, EntityRole, ExternalReference,
        ExternalReferenceDelta, FilePathId, FingerprintAlgorithm, FrozenLocalOverlayDelta,
        GitExternalAuthorityDelta, GitObjectFormat, GitRawRef, GitRawTarget, GraphNodeId,
        LanguageId, LocalAdmissionRuleSource, LocatedEntry, MergeConflictEntry,
        MergeConflictSubject, MergeDivergence, MergeEntryResolution, MergeOpening,
        MergeParentBinding, MergeResolutionProvenance, MergeSide, MergeSideValue,
        MergeTransactionDelta, MergeTransactionState, MergeWorkspaceRestorePoint, RefMutation,
        Relation, RelationDelta, RelationId, RelationKind, RelationOrigin, RepoPath, ResolvedTree,
        SemanticChange, SemanticFingerprint, SensitiveArtifactAllowance, SensitiveArtifactKind,
        TreeDelta, Visibility, WorkspaceExpectation, WorkspaceMutation, WorkspaceSemanticDelta,
        REPOSITORY_TRANSACTION_SCHEMA_VERSION,
    };
    use parking_lot::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tempfile::TempDir;
    use uuid::Uuid;

    use crate::storage::LocalFileBackend;

    #[derive(Default)]
    struct MemoryBackend {
        snapshot: Mutex<Option<(Vec<u8>, Generation)>>,
        blobs: Mutex<HashMap<[u8; 32], Vec<u8>>>,
        fail_next_snapshot: AtomicBool,
        source_load_count: AtomicUsize,
        verified_batch_behavior: AtomicUsize,
        source_load_hook: Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    }

    struct MemoryVerifiedSourceBlobBatch<'a> {
        backend: &'a MemoryBackend,
        repo_id: &'a str,
    }

    impl VerifiedSourceBlobBatch for MemoryVerifiedSourceBlobBatch<'_> {
        fn load_verified(
            &self,
            request: SourceBlobValidationRequest,
        ) -> Result<Option<VerifiedSourceBlob>, KinDbError> {
            self.backend
                .load_source_blob_bounded(self.repo_id, request.digest, request.max_bytes)?
                .map(|bytes| VerifiedSourceBlob::from_verified_bytes(request.digest, bytes))
                .transpose()
        }
    }

    impl StorageBackend for MemoryBackend {
        fn load_snapshot(
            &self,
            _repo_id: &str,
        ) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
            Ok(self.snapshot.lock().clone())
        }

        fn save_source_blob(
            &self,
            _repo_id: &str,
            digest: [u8; 32],
            data: &[u8],
        ) -> Result<(), KinDbError> {
            let actual: [u8; 32] = Sha256::digest(data).into();
            if actual != digest {
                return Err(storage("test source digest mismatch".to_string()));
            }
            let mut blobs = self.blobs.lock();
            if let Some(existing) = blobs.get(&digest) {
                if existing != data {
                    return Err(storage("test source collision".to_string()));
                }
            } else {
                blobs.insert(digest, data.to_vec());
            }
            Ok(())
        }

        fn load_source_blob(
            &self,
            repo_id: &str,
            digest: [u8; 32],
        ) -> Result<Option<Vec<u8>>, KinDbError> {
            self.load_source_blob_bounded(repo_id, digest, MAX_SOURCE_BLOB_BYTES)
        }

        fn load_source_blob_bounded(
            &self,
            _repo_id: &str,
            digest: [u8; 32],
            max_bytes: u64,
        ) -> Result<Option<Vec<u8>>, KinDbError> {
            self.source_load_count.fetch_add(1, Ordering::SeqCst);
            let value = self.blobs.lock().get(&digest).cloned();
            let hook = self.source_load_hook.lock().take();
            if let Some(hook) = hook {
                hook();
            }
            if value
                .as_ref()
                .is_some_and(|value| value.len() as u64 > max_bytes)
            {
                return Err(KinDbError::SourceBlobReadLimitExceeded {
                    actual_bytes: value.expect("checked as present").len() as u64,
                    max_bytes,
                });
            }
            Ok(value)
        }

        fn with_verified_source_blob_batch(
            &self,
            repo_id: &str,
            operation: &mut dyn FnMut(&dyn VerifiedSourceBlobBatch) -> Result<(), KinDbError>,
        ) -> Result<(), KinDbError> {
            let batch = MemoryVerifiedSourceBlobBatch {
                backend: self,
                repo_id,
            };
            match self.verified_batch_behavior.load(Ordering::SeqCst) {
                1 => Ok(()),
                2 => {
                    let _ = operation(&batch);
                    Ok(())
                }
                3 => {
                    operation(&batch)?;
                    let _ = operation(&batch);
                    Ok(())
                }
                _ => operation(&batch),
            }
        }

        fn save_snapshot(
            &self,
            _repo_id: &str,
            data: &[u8],
            expected_gen: Generation,
        ) -> Result<Generation, KinDbError> {
            if self.fail_next_snapshot.swap(false, Ordering::SeqCst) {
                return Err(storage(
                    "injected concrete envelope persistence failure".to_string(),
                ));
            }
            GraphSnapshot::from_bytes(data)?;
            let mut current = self.snapshot.lock();
            let generation = current.as_ref().map_or(0, |(_, generation)| *generation);
            if generation != expected_gen {
                return Err(storage(format!(
                    "test backend generation mismatch: expected {expected_gen}, found {generation}"
                )));
            }
            let next = generation + 1;
            *current = Some((data.to_vec(), next));
            Ok(next)
        }

        fn save_snapshot_classified(
            &self,
            repo_id: &str,
            data: &[u8],
            expected_cursor: SnapshotCursor,
        ) -> SnapshotSaveOutcome {
            match self.save_snapshot(repo_id, data, expected_cursor.backend_generation()) {
                Ok(generation) => SnapshotSaveOutcome::Committed {
                    cursor: SnapshotCursor::from_backend_generation(generation),
                },
                Err(error) => SnapshotSaveOutcome::NotCommitted(error),
            }
        }

        fn save_delta(
            &self,
            _repo_id: &str,
            _delta_data: &[u8],
            _base_gen: Generation,
        ) -> Result<Generation, KinDbError> {
            Err(storage(
                "repository authority test backend forbids deltas".to_string(),
            ))
        }

        fn load_deltas_since(
            &self,
            _repo_id: &str,
            _since_gen: Generation,
        ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
            Ok(Vec::new())
        }

        fn clear_deltas(&self, _repo_id: &str) -> Result<(), KinDbError> {
            Ok(())
        }

        fn save_overlay(
            &self,
            _repo_id: &str,
            _session_id: &str,
            _data: &[u8],
        ) -> Result<(), KinDbError> {
            Ok(())
        }

        fn load_overlay(
            &self,
            _repo_id: &str,
            _session_id: &str,
        ) -> Result<Option<Vec<u8>>, KinDbError> {
            Ok(None)
        }

        fn delete_overlay(&self, _repo_id: &str, _session_id: &str) -> Result<(), KinDbError> {
            Ok(())
        }

        fn list_repos(&self) -> Result<Vec<String>, KinDbError> {
            Ok(Vec::new())
        }
    }

    fn repository_id() -> RepositoryId {
        RepositoryId::new("authority-v12-test").unwrap()
    }

    fn digest(body: &[u8]) -> Hash256 {
        Hash256::from_bytes(Sha256::digest(body).into())
    }

    fn semantic_test_entity(
        path: &str,
        name: &str,
        language: LanguageId,
        fingerprint_byte: u8,
    ) -> Entity {
        Entity {
            id: EntityId::from_content(path, name, "function", 1),
            kind: EntityKind::Function,
            name: name.to_string(),
            language,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([fingerprint_byte; 32]),
                signature_hash: Hash256::from_bytes([fingerprint_byte.wrapping_add(1); 32]),
                behavior_hash: Hash256::from_bytes([fingerprint_byte.wrapping_add(2); 32]),
                equivalence_hash: Hash256::from_bytes([fingerprint_byte.wrapping_add(3); 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(path)),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[derive(Clone, Default)]
    struct TestGitBodies(BTreeMap<Hash256, Vec<u8>>);

    impl GitObjectBodyLoader for TestGitBodies {
        type Error = std::convert::Infallible;

        fn load_body(
            &mut self,
            body_hash: &Hash256,
        ) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.0.get(body_hash).cloned())
        }
    }

    fn git_record(
        kind: ExternalObjectKind,
        oid: &str,
        body: impl Into<Vec<u8>>,
    ) -> (ExternalObjectRecord, Vec<u8>) {
        let body = body.into();
        let oid = GitObjectId::sha1(hex::decode(oid).unwrap().try_into().unwrap());
        let record = ExternalObjectRecord::from_raw(kind, oid, &body).unwrap();
        (record, body)
    }

    fn git_tree_body(entries: &[(&[u8], &[u8], GitObjectId)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (name, mode, oid) in entries {
            body.extend_from_slice(mode);
            body.push(b' ');
            body.extend_from_slice(name);
            body.push(0);
            body.extend_from_slice(oid.as_bytes());
        }
        body
    }

    fn git_commit_body(tree: GitObjectId, parents: &[GitObjectId], message: &[u8]) -> Vec<u8> {
        let mut body = format!("tree {tree}\n").into_bytes();
        for parent in parents {
            body.extend_from_slice(format!("parent {parent}\n").as_bytes());
        }
        body.extend_from_slice(
            b"author Kin <kin@example.com> 1700000000 +0000\n\
              committer Kin <kin@example.com> 1700000000 +0000\n\n",
        );
        body.extend_from_slice(message);
        body
    }

    fn git_tag_body(target: ExternalObjectId, name: &[u8]) -> Vec<u8> {
        let mut body = format!(
            "object {}\ntype {}\ntag ",
            target.oid,
            std::str::from_utf8(target.kind.git_header()).unwrap()
        )
        .into_bytes();
        body.extend_from_slice(name);
        body.extend_from_slice(
            b"\ntagger Kin <kin@example.com> 1700000000 +0000\n\nexact annotated tag",
        );
        body
    }

    fn initial_manager(backend: Arc<MemoryBackend>) -> RepositoryAuthorityManager<MemoryBackend> {
        RepositoryAuthorityManager::open(repository_id(), backend).unwrap()
    }

    #[test]
    fn open_payload_receipt_is_none_for_memory_only_state_and_exact_after_persistence() {
        let backend = Arc::new(MemoryBackend::default());
        let (manager, initial_receipt) = RepositoryAuthorityManager::open_with_payload_stats(
            repository_id(),
            Arc::clone(&backend),
        )
        .unwrap();
        assert!(
            initial_receipt.is_none(),
            "generation zero constructed only in memory has no serialized authority payload"
        );

        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();
        drop(manager);
        let (persisted_bytes, generation) = backend
            .snapshot
            .lock()
            .clone()
            .expect("the transaction persisted one exact snapshot");

        let (reopened, receipt) = RepositoryAuthorityManager::open_with_payload_stats(
            repository_id(),
            Arc::clone(&backend),
        )
        .unwrap();
        let receipt = receipt.expect("persisted recovery returns an immutable open receipt");
        assert_eq!(receipt.snapshot_generation(), generation);
        assert_eq!(receipt.head_generation(), generation);
        assert_eq!(receipt.snapshot_bytes(), persisted_bytes.len() as u64);
        assert_eq!(receipt.acknowledged_delta_count(), 0);
        assert_eq!(receipt.acknowledged_delta_bytes(), 0);
        assert_eq!(receipt.total_payload_bytes(), persisted_bytes.len() as u64);
        assert_eq!(reopened.read_authority().generation(), 1);

        let _source_compatible =
            RepositoryAuthorityManager::open(repository_id(), backend).unwrap();
    }

    fn transaction_shell<B: StorageBackend + ?Sized + 'static>(
        manager: &RepositoryAuthorityManager<B>,
        operation: u128,
    ) -> RepositoryTransaction {
        let lease = manager.read_authority();
        RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::from_uuid(Uuid::from_u128(operation)),
            repository_id: repository_id(),
            expected_generation: lease.generation(),
            expected_roots: lease.roots().clone(),
            actor: AuthorId::new("authority-test"),
            reason: "atomic repository authority fixture".to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: Vec::new(),
            aliases: Vec::new(),
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        }
    }

    fn semantic_workspace_transaction<B: StorageBackend + ?Sized + 'static>(
        manager: &RepositoryAuthorityManager<B>,
        operation: u128,
        semantic_delta: WorkspaceSemanticDelta,
    ) -> RepositoryTransaction {
        let current = manager.read_authority().metadata().workspaces[0].clone();
        let mutation = WorkspaceMutation {
            workspace_id: current.workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: current.generation,
                head: current.head.clone(),
                base_target: current.base_target.clone(),
                base_tree_hash: current.base_tree_hash,
                tree_hash: current.tree_hash,
                semantic_overlay_hash: current.semantic_overlay_hash,
                admission_policy: current.admission_policy,
            },
            new_generation: current.generation + 1,
            new_head: current.head,
            new_base_target: current.base_target,
            new_base_tree_hash: current.base_tree_hash,
            tree_deltas: Vec::new(),
            new_tree_hash: current.tree_hash,
            semantic_delta,
            new_shared_admission_policy: current.shared_admission_policy,
            new_admission_policy: current.admission_policy,
        };
        let mut transaction = transaction_shell(manager, operation);
        transaction.workspace_mutation = Some(mutation);
        transaction
    }

    fn arbitrary_repository_transaction<B: StorageBackend + ?Sized + 'static>(
        manager: &RepositoryAuthorityManager<B>,
    ) -> RepositoryTransaction {
        let fixtures: Vec<(u128, Vec<u8>, Vec<u8>, TreeEntry)> = vec![
            (
                11,
                b"compose.yaml".to_vec(),
                b"services:\n  api:\n    build: .\n".to_vec(),
                TreeEntry::blob(digest(b"services:\n  api:\n    build: .\n"), false),
            ),
            (
                12,
                b"src/lib.rs".to_vec(),
                b"pub fn kin() {}\n".to_vec(),
                TreeEntry::blob(digest(b"pub fn kin() {}\n"), false),
            ),
            (
                13,
                b"tools/check.py".to_vec(),
                b"print('kin')\n".to_vec(),
                TreeEntry::blob(digest(b"print('kin')\n"), false),
            ),
            (
                14,
                b"unsupported/module.zig".to_vec(),
                b"pub fn main() void {}\n".to_vec(),
                TreeEntry::blob(digest(b"pub fn main() void {}\n"), false),
            ),
            (
                15,
                b"assets/data-\xff.bin".to_vec(),
                vec![0, 1, 2, 0xff],
                TreeEntry::blob(digest(&[0, 1, 2, 0xff]), false),
            ),
            (
                16,
                b"compose-current".to_vec(),
                b"compose.yaml".to_vec(),
                TreeEntry::symlink(digest(b"compose.yaml")),
            ),
        ];
        for (_, _, body, _) in &fixtures {
            manager.save_source_blob(digest(body), body).unwrap();
        }

        let tree_deltas: Vec<_> = fixtures
            .iter()
            .map(|(artifact, path, _, entry)| TreeDelta::Added {
                artifact_id: ArtifactId(Uuid::from_u128(*artifact)),
                new: LocatedEntry::new(RepoPath::from_bytes(path.clone()).unwrap(), *entry),
            })
            .collect();
        let tree = ResolvedTree::default().apply(&tree_deltas).unwrap();
        let tree_hash = compute_resolved_tree_hash(&tree).unwrap();
        let shared = SharedAdmissionPolicy::empty(0);
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: Vec::new(),
            timestamp: Timestamp(
                chrono::DateTime::parse_from_rfc3339("2026-07-26T12:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            author: AuthorId::new("authority-test"),
            message: "capture polyglot and arbitrary repository files".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: tree_deltas.clone(),
            admission_policy_delta: Some(AdmissionPolicyDelta::initialize(shared.clone())),
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        change.id = compute_semantic_change_id(&change).unwrap();

        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(20));
        let overlay =
            FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::Sensitive, Vec::new()).unwrap();
        let policy = EffectiveAdmissionPolicyStamp {
            shared: shared.stamp(),
            local: overlay.stamp(),
        };
        let main = RefName::branch(b"main").unwrap();
        let target = RefTarget::change(change.id);
        let workspace_mutation = WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustNotExist,
            new_generation: 0,
            new_head: WorkspaceHead::Symbolic {
                target: main.clone(),
            },
            new_base_target: Some(target.clone()),
            new_base_tree_hash: Some(tree_hash),
            tree_deltas,
            new_tree_hash: tree_hash,
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: shared,
            new_admission_policy: policy,
        };

        let mut transaction = transaction_shell(manager, 21);
        transaction.changes.push(change);
        transaction.ref_mutations.push(RefMutation {
            name: main.clone(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(target),
            policy: RefUpdatePolicy::FastForwardOnly,
        });
        transaction.default_ref_mutation = Some(DefaultRefMutation {
            expected: DefaultRefExpectation::MustBeUnset,
            new_default: Some(main),
        });
        transaction.workspace_mutation = Some(workspace_mutation);
        transaction.local_overlay_delta = Some(FrozenLocalOverlayDelta::initialize(overlay));
        transaction
    }

    /// Both parents of a conflicting merge, plus the base they share.
    ///
    /// The changes are named rather than published: what the record binds is
    /// which change each side's value came from, and the persistence layer
    /// checks the record's own shape, not history reachability.
    fn merge_binding(ours_target: RefTarget) -> MergeParentBinding {
        MergeParentBinding {
            target_ref: RefName::branch(b"main").unwrap(),
            source_ref: RefName::branch(b"feature").unwrap(),
            base_change: SemanticChangeId::from_hash(Hash256::from_bytes([0xa1; 32])),
            ours_change: SemanticChangeId::from_hash(Hash256::from_bytes([0xa2; 32])),
            theirs_change: SemanticChangeId::from_hash(Hash256::from_bytes([0xa3; 32])),
            ours_target,
            theirs_target: RefTarget::change(SemanticChangeId::from_hash(Hash256::from_bytes(
                [0xa3; 32],
            ))),
        }
    }

    fn merge_entry() -> MergeConflictEntry {
        MergeConflictEntry {
            subject: MergeConflictSubject::Artifact {
                artifact: ArtifactId(Uuid::from_u128(12)),
            },
            divergence: MergeDivergence::ChangedBothSides,
            base: MergeSideValue::Present {
                content: Hash256::from_bytes([0xb0; 32]),
            },
            ours: MergeSideValue::Present {
                content: Hash256::from_bytes([0xb1; 32]),
            },
            theirs: MergeSideValue::Present {
                content: Hash256::from_bytes([0xb2; 32]),
            },
            label: Some("src/lib.rs".to_string()),
            resolution: MergeEntryResolution::Unresolved,
        }
    }

    /// `MergeConflictEntry` is nested in KinDB's positional repository
    /// authority. An absent optional label must still occupy its array slot
    /// because the resolution follows it.
    #[test]
    fn an_unlabelled_merge_entry_keeps_its_positional_label_slot() {
        let mut entry = merge_entry();
        entry.label = None;

        let bytes = rmp_serde::to_vec(&entry).unwrap();
        assert_eq!(
            bytes.first(),
            Some(&0x97),
            "the MessagePack struct must retain all seven positional fields"
        );

        let decoded: MergeConflictEntry = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded, entry);
        assert_eq!(decoded.resolution, MergeEntryResolution::Unresolved);
    }

    /// Open a merge on the workspace the arbitrary fixture repository has,
    /// citing `operation` as the transaction that opened it.
    fn open_merge_record<B: StorageBackend + ?Sized + 'static>(
        manager: &RepositoryAuthorityManager<B>,
        operation: u128,
    ) -> MergeTransactionRecord {
        let workspace = manager.read_authority().metadata().workspaces[0].clone();
        MergeTransactionRecord::open(
            repository_id(),
            workspace.workspace_id,
            MergeOpening {
                operation_id: OperationId::from_uuid(Uuid::from_u128(operation)),
                actor: AuthorId::new("authority-test"),
                opened_at: Timestamp(
                    chrono::DateTime::parse_from_rfc3339("2026-07-28T12:00:00Z")
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                ),
            },
            merge_binding(workspace.base_target.clone().unwrap()),
            MergeWorkspaceRestorePoint {
                generation: workspace.generation,
                head: workspace.head.clone(),
                base_target: workspace.base_target.clone(),
                base_tree_hash: workspace.base_tree_hash,
                tree_hash: workspace.tree_hash,
                semantic_overlay_hash: workspace.semantic_overlay_hash,
                admission_policy: workspace.admission_policy,
            },
            vec![merge_entry()],
        )
        .unwrap()
    }

    fn merge_provenance(operation: u128) -> MergeResolutionProvenance {
        MergeResolutionProvenance {
            actor: AuthorId::new("authority-test"),
            operation_id: OperationId::from_uuid(Uuid::from_u128(operation)),
            resolved_at: Timestamp(
                chrono::DateTime::parse_from_rfc3339("2026-07-28T12:05:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
        }
    }

    /// A repository that has never had a conflicting merge must be bit-for-bit
    /// what it was before durable merge state existed.
    ///
    /// The pinned digest was measured on the commit that introduced this test,
    /// before `merge_transactions` was added. It is what makes the field
    /// additive in fact: an empty collection is not folded into the local root
    /// at all, so every repository already on disk keeps its authority roots
    /// and needs no re-import. If this moves, the change owes a schema version.
    #[test]
    fn a_repository_without_a_merge_keeps_its_genesis_local_root() {
        let snapshot = GraphSnapshot::empty();
        let authority = PersistedRepositoryAuthority::empty(repository_id(), &snapshot).unwrap();
        assert!(authority.merge_transactions.is_empty());
        assert_eq!(
            authority.roots.local_state.hash.to_string(),
            "02a48df3559f359253d12baf60c3ae2df791ad77b267397af162018b3193c6f2",
            "an empty merge collection must not perturb the local authority root"
        );

        // The envelope is persisted positionally, so an empty collection must
        // also encode to the arity a pre-merge binary wrote.
        let bytes = rmp_serde::to_vec(&authority).unwrap();
        let decoded: PersistedRepositoryAuthority = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded, authority);
    }

    /// The durability requirement behind `kin conflicts`: a parked merge is in
    /// the persisted snapshot, not in daemon memory or a `.kin` sidecar, so it
    /// is still there after a restart.
    #[test]
    fn a_parked_merge_survives_commit_and_reopen() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();

        let record = open_merge_record(&manager, 40);
        let mut transaction = transaction_shell(&manager, 40);
        transaction.merge_transaction_delta = Some(MergeTransactionDelta::open(record.clone()));
        let receipt = manager.commit_repository_transaction(transaction).unwrap();
        assert_eq!(
            receipt
                .operation
                .merge_transaction_delta
                .as_ref()
                .unwrap()
                .new,
            Some(record.clone()),
            "the operation log carries the transition, not just the outcome"
        );

        let reopened = initial_manager(backend);
        let lease = reopened.read_authority();
        let persisted = &lease.metadata().merge_transactions;
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0], record);
        assert_eq!(persisted[0].unresolved().count(), 1);
        assert!(persisted[0].state.is_in_progress());
    }

    /// An in-progress merge is workspace-local. It must move the local root, so
    /// it cannot be forged outside the compare-and-swap commit path, and must
    /// leave replicated truth alone, so a replica does not look divergent
    /// because someone locally started a merge.
    #[test]
    fn a_parked_merge_moves_local_authority_but_not_replicated_truth() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();
        let before = manager.read_authority().roots().clone();

        let mut transaction = transaction_shell(&manager, 41);
        transaction.merge_transaction_delta =
            Some(MergeTransactionDelta::open(open_merge_record(&manager, 41)));
        manager.commit_repository_transaction(transaction).unwrap();

        let after = manager.read_authority().roots().clone();
        assert_ne!(after.local_state, before.local_state);
        assert!(before.has_same_replicated_truth(&after));
        assert_eq!(after.history, before.history);
        assert_eq!(after.ref_state, before.ref_state);
    }

    /// The lease discipline the local overlay already has: two sessions cannot
    /// both advance a merge from the same view of it.
    #[test]
    fn a_stale_merge_lease_is_refused() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();

        let record = open_merge_record(&manager, 42);
        let mut opening = transaction_shell(&manager, 42);
        opening.merge_transaction_delta = Some(MergeTransactionDelta::open(record.clone()));
        manager.commit_repository_transaction(opening).unwrap();

        // A second opener still holding the pre-merge view of the workspace.
        let mut racing = transaction_shell(&manager, 43);
        racing.merge_transaction_delta =
            Some(MergeTransactionDelta::open(open_merge_record(&manager, 43)));
        let error = manager
            .commit_repository_transaction(racing)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("no longer matches its lease"),
            "unexpected refusal: {error}"
        );

        // And the resolution path is held to the same lease.
        let settled = record
            .resolve_entry(
                &record.entries[0].subject,
                MergeEntryResolution::Side {
                    side: MergeSide::Theirs,
                    provenance: merge_provenance(44),
                },
            )
            .unwrap();
        let mut resolving = transaction_shell(&manager, 44);
        resolving.merge_transaction_delta = Some(MergeTransactionDelta::update(record, settled));
        manager.commit_repository_transaction(resolving).unwrap();
    }

    /// A resolution names the operation that settled it. Any citation a delta
    /// introduces must be the transaction committing it, so provenance cannot
    /// be authored pointing at some other transaction or at one that never
    /// happened.
    #[test]
    fn a_merge_resolution_cannot_cite_a_foreign_operation() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();

        let record = open_merge_record(&manager, 45);
        let mut opening = transaction_shell(&manager, 45);
        opening.merge_transaction_delta = Some(MergeTransactionDelta::open(record.clone()));
        manager.commit_repository_transaction(opening).unwrap();

        let laundered = record
            .resolve_entry(
                &record.entries[0].subject,
                MergeEntryResolution::Side {
                    side: MergeSide::Ours,
                    // Not the operation this transaction commits.
                    provenance: merge_provenance(999),
                },
            )
            .unwrap();
        let mut resolving = transaction_shell(&manager, 46);
        resolving.merge_transaction_delta =
            Some(MergeTransactionDelta::update(record.clone(), laundered));
        let error = manager
            .commit_repository_transaction(resolving)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("neither already recorded nor the operation committing it"),
            "unexpected refusal: {error}"
        );

        // The same resolution, citing the transaction that actually carries it.
        let honest = record
            .resolve_entry(
                &record.entries[0].subject,
                MergeEntryResolution::Side {
                    side: MergeSide::Ours,
                    provenance: merge_provenance(47),
                },
            )
            .unwrap();
        let mut resolving = transaction_shell(&manager, 47);
        resolving.merge_transaction_delta =
            Some(MergeTransactionDelta::update(record, honest.clone()));
        manager.commit_repository_transaction(resolving).unwrap();

        // A later transaction may carry the citation forward untouched: it was
        // proven when it was first applied.
        let committed = honest
            .terminate(MergeTransactionState::Committed {
                merge_change: SemanticChangeId::from_hash(Hash256::from_bytes([0xc4; 32])),
                operation_id: OperationId::from_uuid(Uuid::from_u128(48)),
                committed_at: Timestamp(
                    chrono::DateTime::parse_from_rfc3339("2026-07-28T12:10:00Z")
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                ),
            })
            .unwrap();
        let mut publishing = transaction_shell(&manager, 48);
        publishing.merge_transaction_delta = Some(MergeTransactionDelta::update(honest, committed));
        manager.commit_repository_transaction(publishing).unwrap();

        let lease = manager.read_authority();
        assert!(lease.metadata().merge_transactions[0].state.is_terminal());
    }

    #[test]
    fn authored_merge_artifact_requires_exact_cas_on_commit_and_reopen() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();

        let record = open_merge_record(&manager, 0xb000);
        let mut opening = transaction_shell(&manager, 0xb000);
        opening.merge_transaction_delta = Some(MergeTransactionDelta::open(record.clone()));
        manager.commit_repository_transaction(opening).unwrap();

        let authored_body = b"authored merge resolution\n";
        let authored_hash = digest(authored_body);
        let settled = record
            .resolve_entry(
                &record.entries[0].subject,
                MergeEntryResolution::Payload {
                    payload: MergeResolutionPayload::Artifact(LocatedEntry::new(
                        RepoPath::from_utf8("src/lib.rs").unwrap(),
                        TreeEntry::blob(authored_hash, false),
                    )),
                    provenance: merge_provenance(0xb001),
                },
            )
            .unwrap();
        let mut resolving = transaction_shell(&manager, 0xb001);
        resolving.merge_transaction_delta =
            Some(MergeTransactionDelta::update(record, settled.clone()));

        let error = manager
            .commit_repository_transaction(resolving.clone())
            .expect_err("an authored merge payload cannot name absent immutable bytes");
        assert!(
            error.to_string().contains("merge transaction")
                && error
                    .to_string()
                    .contains("absent from immutable source CAS"),
            "unexpected missing merge-body error: {error}"
        );

        manager
            .save_source_blob(authored_hash, authored_body)
            .unwrap();
        manager.commit_repository_transaction(resolving).unwrap();

        let mut dropping = transaction_shell(&manager, 0xb002);
        dropping.merge_transaction_delta =
            Some(MergeTransactionDelta::drop_record(settled.clone()));
        backend.blobs.lock().insert(
            *authored_hash.as_bytes(),
            b"tampered before merge drop\n".to_vec(),
        );
        let error = manager
            .commit_repository_transaction(dropping.clone())
            .expect_err("dropping a merge must revalidate its historical old body");
        assert!(
            error.to_string().contains("digest mismatch"),
            "unexpected pre-drop tamper result: {error}"
        );
        backend
            .blobs
            .lock()
            .insert(*authored_hash.as_bytes(), authored_body.to_vec());
        manager.commit_repository_transaction(dropping).unwrap();
        assert!(
            manager
                .read_authority()
                .metadata()
                .merge_transactions
                .is_empty(),
            "the authored body must now be referenced only by historical operation authority"
        );
        backend.blobs.lock().insert(
            *authored_hash.as_bytes(),
            b"tampered merge resolution\n".to_vec(),
        );

        let error = match RepositoryAuthorityManager::open(repository_id(), backend) {
            Ok(_) => panic!("reopen must reject a tampered historical merge payload"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("digest mismatch"),
            "unexpected tampered merge-body error: {error}"
        );
    }

    /// A merge record is workspace authority, so it cannot name a workspace the
    /// repository does not have.
    #[test]
    fn a_merge_record_must_name_a_workspace_this_repository_has() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();

        let mut orphan = open_merge_record(&manager, 49);
        orphan.workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(777));
        orphan.hash = orphan.identity_hash().unwrap();
        let mut transaction = transaction_shell(&manager, 49);
        transaction.merge_transaction_delta = Some(MergeTransactionDelta::open(orphan));
        let error = manager
            .commit_repository_transaction(transaction)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("which this repository does not have"),
            "unexpected refusal: {error}"
        );
    }

    /// Dropping the record clears the workspace's merge state, and the drop is
    /// itself a recorded transition rather than a silent erasure.
    ///
    /// The local root deliberately does not return to its pre-merge value: it
    /// also folds every operation identity, and two operations have since been
    /// committed. What must hold is that the merge collection contributes
    /// nothing once empty, which the genesis pin proves against a digest
    /// measured before the field existed.
    #[test]
    fn dropping_a_merge_record_clears_it_and_is_itself_recorded() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();
        let before = manager.read_authority().roots().local_state;

        let record = open_merge_record(&manager, 50);
        let mut opening = transaction_shell(&manager, 50);
        opening.merge_transaction_delta = Some(MergeTransactionDelta::open(record.clone()));
        manager.commit_repository_transaction(opening).unwrap();
        let parked = manager.read_authority().roots().local_state;
        assert_ne!(parked, before);

        let mut dropping = transaction_shell(&manager, 51);
        dropping.merge_transaction_delta = Some(MergeTransactionDelta::drop_record(record.clone()));
        let receipt = manager.commit_repository_transaction(dropping).unwrap();

        let lease = manager.read_authority();
        assert!(lease.metadata().merge_transactions.is_empty());
        assert_ne!(lease.roots().local_state, parked);
        let delta = receipt.operation.merge_transaction_delta.as_ref().unwrap();
        assert_eq!(delta.old, Some(record));
        assert!(delta.new.is_none());
    }

    fn native_root_with_policy(
        manager: &RepositoryAuthorityManager<MemoryBackend>,
        case: AdmissionCase,
        path: &str,
        body: &[u8],
        ignore_body: Option<&[u8]>,
        allow_sensitive: bool,
    ) -> RepositoryTransaction {
        let mut transaction = arbitrary_repository_transaction(manager);
        manager.save_source_blob(digest(body), body).unwrap();

        let mut sources = Vec::new();
        let mut additions = Vec::new();
        if let Some(ignore_body) = ignore_body {
            let ignore_hash = digest(ignore_body);
            manager.save_source_blob(ignore_hash, ignore_body).unwrap();
            sources.push(AdmissionRuleSource {
                kind: AdmissionRuleSourceKind::GitIgnore,
                path: RepoPath::from_utf8(".gitignore").unwrap(),
                base_directory: None,
                body_hash: ignore_hash,
                body_len: ignore_body.len() as u64,
                precedence: 0,
            });
            additions.push(TreeDelta::Added {
                artifact_id: ArtifactId(Uuid::from_u128(30)),
                new: LocatedEntry::new(
                    RepoPath::from_utf8(".gitignore").unwrap(),
                    TreeEntry::blob(ignore_hash, false),
                ),
            });
        }

        let path = RepoPath::from_utf8(path).unwrap();
        let body_hash = digest(body);
        additions.push(TreeDelta::Added {
            artifact_id: ArtifactId(Uuid::from_u128(31)),
            new: LocatedEntry::new(path.clone(), TreeEntry::blob(body_hash, false)),
        });
        let allowances = allow_sensitive
            .then(|| SensitiveArtifactAllowance {
                path,
                content_hash: body_hash,
                kind: SensitiveArtifactKind::Blob { executable: false },
                approved_by: AuthorId::new("authority-test"),
                reason: "explicit exact test allowance".to_string(),
            })
            .into_iter()
            .collect();
        let shared = SharedAdmissionPolicy::new(0, sources, allowances).unwrap();

        let change = transaction.changes.first_mut().unwrap();
        change.tree_deltas.extend(additions);
        change.admission_policy_delta = Some(AdmissionPolicyDelta::initialize(shared.clone()));
        change.id = SemanticChangeId::from_hash(Hash256::from_bytes([0; 32]));
        change.id = compute_semantic_change_id(change).unwrap();
        let change_id = change.id;
        let tree_deltas = change.tree_deltas.clone();
        let tree = ResolvedTree::default().apply(&tree_deltas).unwrap();
        let tree_hash = compute_resolved_tree_hash(&tree).unwrap();

        let workspace_id = transaction
            .workspace_mutation
            .as_ref()
            .unwrap()
            .workspace_id;
        let overlay = FrozenLocalOverlay::new(workspace_id, 0, case, Vec::new()).unwrap();
        let effective = EffectiveAdmissionPolicyStamp {
            shared: shared.stamp(),
            local: overlay.stamp(),
        };
        let workspace = transaction.workspace_mutation.as_mut().unwrap();
        workspace.new_base_target = Some(RefTarget::change(change_id));
        workspace.new_base_tree_hash = Some(tree_hash);
        workspace.tree_deltas = tree_deltas;
        workspace.new_tree_hash = tree_hash;
        workspace.new_shared_admission_policy = shared;
        workspace.new_admission_policy = effective;
        transaction.ref_mutations[0].new_target = Some(RefTarget::change(change_id));
        transaction.local_overlay_delta = Some(FrozenLocalOverlayDelta::initialize(overlay));
        transaction
    }

    fn refresh_workspace_admission_case(
        manager: &RepositoryAuthorityManager<MemoryBackend>,
        operation: u128,
        case: AdmissionCase,
    ) -> RepositoryTransaction {
        let lease = manager.read_authority();
        let current = lease.metadata().workspaces[0].clone();
        let old_overlay = local_overlay_for_workspace(lease.metadata(), &current)
            .unwrap()
            .clone();
        drop(lease);

        let next_overlay = FrozenLocalOverlay::new(
            current.workspace_id,
            old_overlay.generation + 1,
            case,
            old_overlay.sources.clone(),
        )
        .unwrap();
        let next_policy = EffectiveAdmissionPolicyStamp {
            shared: current.shared_admission_policy.stamp(),
            local: next_overlay.stamp(),
        };
        let mutation = WorkspaceMutation {
            workspace_id: current.workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: current.generation,
                head: current.head.clone(),
                base_target: current.base_target.clone(),
                base_tree_hash: current.base_tree_hash,
                tree_hash: current.tree_hash,
                semantic_overlay_hash: current.semantic_overlay_hash,
                admission_policy: current.admission_policy,
            },
            new_generation: current.generation + 1,
            new_head: current.head,
            new_base_target: current.base_target,
            new_base_tree_hash: current.base_tree_hash,
            tree_deltas: Vec::new(),
            new_tree_hash: current.tree_hash,
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: current.shared_admission_policy,
            new_admission_policy: next_policy,
        };
        let mut transaction = transaction_shell(manager, operation);
        transaction.workspace_mutation = Some(mutation);
        transaction.local_overlay_delta =
            Some(FrozenLocalOverlayDelta::update(old_overlay, next_overlay));
        transaction
    }

    fn unborn_workspace_transaction<B: StorageBackend + ?Sized + 'static>(
        manager: &RepositoryAuthorityManager<B>,
        operation: u128,
        workspace: u128,
        head: &[u8],
    ) -> RepositoryTransaction {
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(workspace));
        let shared = SharedAdmissionPolicy::empty(0);
        let overlay =
            FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::Sensitive, Vec::new()).unwrap();
        let policy = EffectiveAdmissionPolicyStamp {
            shared: shared.stamp(),
            local: overlay.stamp(),
        };
        let head = WorkspaceHead::Symbolic {
            target: RefName::branch(head).unwrap(),
        };
        let empty_tree_hash = compute_resolved_tree_hash(&ResolvedTree::default()).unwrap();
        let workspace_mutation = WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustNotExist,
            new_generation: 0,
            new_head: head.clone(),
            new_base_target: None,
            new_base_tree_hash: None,
            tree_deltas: Vec::new(),
            new_tree_hash: empty_tree_hash,
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: shared,
            new_admission_policy: policy,
        };

        let mut transaction = transaction_shell(manager, operation);
        transaction.workspace_mutation = Some(workspace_mutation);
        transaction.local_overlay_delta = Some(FrozenLocalOverlayDelta::initialize(overlay));
        transaction
    }

    fn raw_blob_record() -> (ExternalObjectRecord, Vec<u8>) {
        let body = b"test".to_vec();
        let oid = GitObjectId::sha1(
            hex::decode("30d74d258442c7c65512eafab474568dd706c430")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        (
            ExternalObjectRecord::from_raw(ExternalObjectKind::Blob, oid, &body).unwrap(),
            body,
        )
    }

    #[derive(Clone)]
    struct GitAuthorityTransactionFixture {
        transaction: RepositoryTransaction,
        authority: GitExternalAuthority,
        direct_authority: GitExternalAuthority,
        head: ExternalObjectRecord,
        compose: ExternalObjectRecord,
        previous_gitlink_target: GitObjectId,
        gitlink_target: GitObjectId,
    }

    fn git_authority_transaction_fixture(
        manager: &RepositoryAuthorityManager<MemoryBackend>,
        operation: u128,
    ) -> GitAuthorityTransactionFixture {
        let mut bodies = TestGitBodies::default();
        let mut admit = |kind, oid, body| {
            let (record, body) = git_record(kind, oid, body);
            bodies.0.insert(record.body_hash, body);
            record
        };
        let compose = admit(
            ExternalObjectKind::Blob,
            "97fdbc5b507fdfce49b8b073bc6df3a73ea78c8e",
            b"services:\n  api:\n    build: .\n".to_vec(),
        );
        let binary = admit(
            ExternalObjectKind::Blob,
            "dd729764d359d78852d453b4508d1f127eb9c61a",
            vec![0_u8, 0xff, 0x80, b'\n'],
        );
        let symlink = admit(
            ExternalObjectKind::Blob,
            "577ffa642a989094abc1349fefc893cf2491da59",
            b"compose.yaml".to_vec(),
        );
        let previous_gitlink_target = GitObjectId::sha1([0x44; 20]);
        let parent_tree = admit(
            ExternalObjectKind::Tree,
            "3dd825f26d527ac4220a7822c48c1caf2d8ef66e",
            git_tree_body(&[(b"submodule", b"160000", previous_gitlink_target)]),
        );
        let gitlink_target = GitObjectId::sha1([0x55; 20]);
        let root_tree = admit(
            ExternalObjectKind::Tree,
            "3f3403f8214e9230bfa80d259e26c32bf6086d39",
            git_tree_body(&[
                (b"compose.yaml", b"100644", compose.object.oid),
                (b"payload.bin", b"100755", binary.object.oid),
                (b"submodule", b"160000", gitlink_target),
                (&[0xff], b"120000", symlink.object.oid),
            ]),
        );
        let parent = admit(
            ExternalObjectKind::Commit,
            "31ee15780998c760b25b08b6ab65cd981be6fbbc",
            git_commit_body(parent_tree.object.oid, &[], b"parent"),
        );
        let head = admit(
            ExternalObjectKind::Commit,
            "dffe8495f21f28be8fddab5a6e94ee1a8202fd54",
            git_commit_body(root_tree.object.oid, &[parent.object.oid], b"head"),
        );
        let records = vec![
            compose.clone(),
            binary.clone(),
            symlink.clone(),
            parent_tree,
            root_tree,
            parent.clone(),
            head.clone(),
        ];
        for record in &records {
            manager
                .save_source_blob(
                    record.body_hash,
                    bodies
                        .0
                        .get(&record.body_hash)
                        .expect("fixture retains every exact Git body"),
                )
                .unwrap();
        }

        let main = RefName::branch(b"main").unwrap();
        let raw_refs = vec![GitRawRef {
            name: main.clone(),
            target: GitRawTarget::Direct {
                object: head.object,
            },
        }];
        let mut loader = bodies.clone();
        let authority = GitExternalAuthority::from_raw_parts(
            repository_id(),
            GitObjectFormat::Sha1,
            raw_refs.clone(),
            GitRawTarget::Symbolic {
                target: main.clone(),
            },
            records.clone(),
            &mut loader,
        )
        .unwrap();
        let direct_authority = GitExternalAuthority::from_raw_parts(
            repository_id(),
            GitObjectFormat::Sha1,
            raw_refs,
            GitRawTarget::Direct {
                object: head.object,
            },
            records.clone(),
            &mut loader,
        )
        .unwrap();

        let timestamp = Timestamp(
            chrono::DateTime::parse_from_rfc3339("2026-07-26T14:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        let mut parent_change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::GitCommit {
                oid: parent.object.oid,
            },
            parents: Vec::new(),
            timestamp: timestamp.clone(),
            author: AuthorId::new("authority-test"),
            message: "import exact Git parent".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: vec![TreeDelta::Added {
                artifact_id: ArtifactId(Uuid::from_u128(0xa4)),
                new: LocatedEntry::new(
                    RepoPath::from_utf8("submodule").unwrap(),
                    TreeEntry::gitlink(previous_gitlink_target),
                ),
            }],
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        parent_change.id = compute_semantic_change_id(&parent_change).unwrap();
        let mut head_change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::GitCommit {
                oid: head.object.oid,
            },
            parents: vec![parent_change.id],
            timestamp,
            author: AuthorId::new("authority-test"),
            message: "import Compose, binary, symlink, and byte path".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: vec![
                TreeDelta::Added {
                    artifact_id: ArtifactId(Uuid::from_u128(0xa1)),
                    new: LocatedEntry::new(
                        RepoPath::from_utf8("compose.yaml").unwrap(),
                        TreeEntry::blob(compose.body_hash, false),
                    ),
                },
                TreeDelta::Added {
                    artifact_id: ArtifactId(Uuid::from_u128(0xa2)),
                    new: LocatedEntry::new(
                        RepoPath::from_utf8("payload.bin").unwrap(),
                        TreeEntry::blob(binary.body_hash, true),
                    ),
                },
                TreeDelta::Added {
                    artifact_id: ArtifactId(Uuid::from_u128(0xa3)),
                    new: LocatedEntry::new(
                        RepoPath::from_bytes(vec![0xff]).unwrap(),
                        TreeEntry::symlink(symlink.body_hash),
                    ),
                },
                TreeDelta::Updated {
                    artifact_id: ArtifactId(Uuid::from_u128(0xa4)),
                    old: LocatedEntry::new(
                        RepoPath::from_utf8("submodule").unwrap(),
                        TreeEntry::gitlink(previous_gitlink_target),
                    ),
                    new: LocatedEntry::new(
                        RepoPath::from_utf8("submodule").unwrap(),
                        TreeEntry::gitlink(gitlink_target),
                    ),
                },
            ],
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        head_change.id = compute_semantic_change_id(&head_change).unwrap();

        let mut transaction = transaction_shell(manager, operation);
        transaction.external_objects = records.clone();
        transaction.git_authority_delta =
            Some(GitExternalAuthorityDelta::initialize(authority.clone()));
        transaction.aliases = vec![
            ExternalChangeAlias::new(repository_id(), parent.object.oid, parent_change.id),
            ExternalChangeAlias::new(repository_id(), head.object.oid, head_change.id),
        ];
        transaction.changes = vec![parent_change, head_change];

        GitAuthorityTransactionFixture {
            transaction,
            authority,
            direct_authority,
            head,
            compose,
            previous_gitlink_target,
            gitlink_target,
        }
    }

    fn unborn_gitlink_workspace_transaction(
        manager: &RepositoryAuthorityManager<MemoryBackend>,
        operation: u128,
        workspace: u128,
        artifact_id: ArtifactId,
        target: GitObjectId,
    ) -> RepositoryTransaction {
        let delta = TreeDelta::Added {
            artifact_id,
            new: LocatedEntry::new(
                RepoPath::from_utf8("submodule").unwrap(),
                TreeEntry::gitlink(target),
            ),
        };
        let tree = ResolvedTree::default()
            .apply(std::slice::from_ref(&delta))
            .unwrap();
        let mut transaction =
            unborn_workspace_transaction(manager, operation, workspace, b"scratch");
        let mutation = transaction.workspace_mutation.as_mut().unwrap();
        mutation.tree_deltas = vec![delta];
        mutation.new_tree_hash = compute_resolved_tree_hash(&tree).unwrap();
        transaction
    }

    fn native_gitlink_transaction(
        manager: &RepositoryAuthorityManager<MemoryBackend>,
        operation: u128,
        workspace: u128,
        artifact_id: ArtifactId,
        target: GitObjectId,
    ) -> RepositoryTransaction {
        let mut transaction = unborn_gitlink_workspace_transaction(
            manager,
            operation,
            workspace,
            artifact_id,
            target,
        );
        let mutation = transaction.workspace_mutation.as_mut().unwrap();
        let shared = mutation.new_shared_admission_policy.clone();
        let tree_hash = mutation.new_tree_hash;
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: Vec::new(),
            timestamp: Timestamp(
                chrono::DateTime::parse_from_rfc3339("2026-07-26T15:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            author: AuthorId::new("authority-test"),
            message: "admit an exact previously authenticated gitlink".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: mutation.tree_deltas.clone(),
            admission_policy_delta: Some(AdmissionPolicyDelta::initialize(shared)),
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        change.id = compute_semantic_change_id(&change).unwrap();
        mutation.new_base_target = Some(RefTarget::change(change.id));
        mutation.new_base_tree_hash = Some(tree_hash);
        mutation.new_head = WorkspaceHead::Symbolic {
            target: RefName::branch(b"main").unwrap(),
        };
        transaction.ref_mutations.push(RefMutation {
            name: RefName::branch(b"main").unwrap(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(RefTarget::change(change.id)),
            policy: RefUpdatePolicy::FastForwardOnly,
        });
        transaction.changes.push(change);
        transaction
    }

    fn imported_repository_transaction(
        manager: &RepositoryAuthorityManager<MemoryBackend>,
    ) -> (RepositoryTransaction, SemanticChangeId, RefTarget) {
        let fixture = git_authority_transaction_fixture(manager, 21);
        let mut transaction = fixture.transaction;
        let parent = transaction.changes.remove(0);
        let mut head = transaction.changes.remove(0);
        let shared = SharedAdmissionPolicy::empty(0);
        head.admission_policy_delta = Some(AdmissionPolicyDelta::initialize(shared.clone()));
        head.id = compute_semantic_change_id(&head).unwrap();
        let change_id = head.id;
        let parent_tree = ResolvedTree::default().apply(&parent.tree_deltas).unwrap();
        let tree = parent_tree.apply(&head.tree_deltas).unwrap();
        let tree_hash = compute_resolved_tree_hash(&tree).unwrap();
        let workspace_deltas = tree
            .artifacts()
            .map(|artifact| TreeDelta::Added {
                artifact_id: artifact.artifact_id,
                new: artifact.located_entry(),
            })
            .collect();

        transaction.changes = vec![head.clone(), parent.clone()];
        transaction.aliases = vec![
            ExternalChangeAlias::new(repository_id(), fixture.head.object.oid, head.id),
            ExternalChangeAlias::new(
                repository_id(),
                match parent.origin {
                    ChangeOrigin::GitCommit { oid } => oid,
                    ChangeOrigin::Native => unreachable!(),
                },
                parent.id,
            ),
        ];
        let target = RefTarget::external_object(fixture.head.object);
        let main = RefName::branch(b"main").unwrap();
        transaction.ref_mutations.push(RefMutation {
            name: main.clone(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(target.clone()),
            policy: RefUpdatePolicy::FastForwardOnly,
        });
        transaction.default_ref_mutation = Some(DefaultRefMutation {
            expected: DefaultRefExpectation::MustBeUnset,
            new_default: Some(main.clone()),
        });

        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(20));
        let overlay =
            FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::Sensitive, Vec::new()).unwrap();
        let policy = EffectiveAdmissionPolicyStamp {
            shared: shared.stamp(),
            local: overlay.stamp(),
        };
        let head_state = WorkspaceHead::Symbolic { target: main };
        transaction.workspace_mutation = Some(WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustNotExist,
            new_generation: 0,
            new_head: head_state.clone(),
            new_base_target: Some(target.clone()),
            new_base_tree_hash: Some(tree_hash),
            tree_deltas: workspace_deltas,
            new_tree_hash: tree_hash,
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: shared,
            new_admission_policy: policy,
        });
        transaction.local_overlay_delta = Some(FrozenLocalOverlayDelta::initialize(overlay));
        (transaction, change_id, target)
    }

    fn detached_tag_import_transaction(
        manager: &RepositoryAuthorityManager<MemoryBackend>,
    ) -> (RepositoryTransaction, SemanticChangeId, ExternalObjectId) {
        let fixture = git_authority_transaction_fixture(manager, 0xa00a);
        let mut transaction = fixture.transaction;
        let parent = transaction.changes.remove(0);
        let mut head = transaction.changes.remove(0);
        let shared = SharedAdmissionPolicy::empty(0);
        head.admission_policy_delta = Some(AdmissionPolicyDelta::initialize(shared.clone()));
        head.id = compute_semantic_change_id(&head).unwrap();
        let change_id = head.id;
        let parent_tree = ResolvedTree::default().apply(&parent.tree_deltas).unwrap();
        let tree = parent_tree.apply(&head.tree_deltas).unwrap();
        let tree_hash = compute_resolved_tree_hash(&tree).unwrap();
        let workspace_deltas = tree
            .artifacts()
            .map(|artifact| TreeDelta::Added {
                artifact_id: artifact.artifact_id,
                new: artifact.located_entry(),
            })
            .collect();

        transaction.changes = vec![head.clone(), parent.clone()];
        transaction.aliases = vec![
            ExternalChangeAlias::new(repository_id(), fixture.head.object.oid, head.id),
            ExternalChangeAlias::new(
                repository_id(),
                match parent.origin {
                    ChangeOrigin::GitCommit { oid } => oid,
                    ChangeOrigin::Native => unreachable!(),
                },
                parent.id,
            ),
        ];

        let (inner, inner_body) = git_record(
            ExternalObjectKind::Tag,
            "6ca553ef57cb7ac1bb1ba68d4d8964ea72a592d0",
            git_tag_body(fixture.head.object, b"inner"),
        );
        let (outer, outer_body) = git_record(
            ExternalObjectKind::Tag,
            "de8b7164024b99ed8bcbe45d6580d215248e7644",
            git_tag_body(inner.object, b"outer"),
        );
        manager
            .save_source_blob(inner.body_hash, &inner_body)
            .unwrap();
        manager
            .save_source_blob(outer.body_hash, &outer_body)
            .unwrap();
        transaction
            .external_objects
            .extend([inner.clone(), outer.clone()]);

        let mut bodies = TestGitBodies::default();
        for record in &transaction.external_objects {
            bodies.0.insert(
                record.body_hash,
                manager
                    .load_source_blob(record.body_hash)
                    .unwrap()
                    .expect("fixture installed every exact Git body"),
            );
        }
        let mut loader = bodies;
        let authority = GitExternalAuthority::from_raw_parts(
            repository_id(),
            GitObjectFormat::Sha1,
            Vec::new(),
            GitRawTarget::Direct {
                object: outer.object,
            },
            transaction.external_objects.clone(),
            &mut loader,
        )
        .unwrap();
        transaction.git_authority_delta = Some(GitExternalAuthorityDelta::initialize(authority));

        let target = RefTarget::external_object(outer.object);
        transaction.ref_mutations.push(RefMutation {
            name: RefName::tag(b"release").unwrap(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(target.clone()),
            policy: RefUpdatePolicy::FastForwardOnly,
        });
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xa00b));
        let overlay =
            FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::Sensitive, Vec::new()).unwrap();
        let policy = EffectiveAdmissionPolicyStamp {
            shared: shared.stamp(),
            local: overlay.stamp(),
        };
        transaction.workspace_mutation = Some(WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustNotExist,
            new_generation: 0,
            new_head: WorkspaceHead::Detached {
                target: target.clone(),
            },
            new_base_target: Some(target),
            new_base_tree_hash: Some(tree_hash),
            tree_deltas: workspace_deltas,
            new_tree_hash: tree_hash,
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: shared,
            new_admission_policy: policy,
        });
        transaction.local_overlay_delta = Some(FrozenLocalOverlayDelta::initialize(overlay));
        (transaction, change_id, outer.object)
    }

    fn remove_compose_transaction(
        manager: &RepositoryAuthorityManager<MemoryBackend>,
        operation: u128,
    ) -> (RepositoryTransaction, Hash256) {
        let lease = manager.read_authority();
        let old_target = lease.metadata().ref_state.refs[0].target.clone();
        let old_change = target_change_id(lease.metadata(), &old_target).unwrap();
        let compose = lease.metadata().workspaces[0]
            .tree
            .artifact_at_path(&RepoPath::from_utf8("compose.yaml").unwrap())
            .unwrap();
        let old_body = compose
            .entry
            .blob_identity()
            .expect("compose fixture has a source body");
        let removal = TreeDelta::Removed {
            artifact_id: compose.artifact_id,
            old: compose.located_entry(),
        };
        drop(lease);

        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: vec![old_change],
            timestamp: Timestamp::now(),
            author: AuthorId::new("authority-test"),
            message: "remove compose while retaining exact history".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: vec![removal],
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        change.id = compute_semantic_change_id(&change).unwrap();

        let mut transaction = transaction_shell(manager, operation);
        transaction.changes.push(change.clone());
        transaction.ref_mutations.push(RefMutation {
            name: RefName::branch(b"main").unwrap(),
            expected: RefExpectation::MustEqual { target: old_target },
            new_target: Some(RefTarget::change(change.id)),
            policy: RefUpdatePolicy::FastForwardOnly,
        });
        (transaction, old_body)
    }

    #[test]
    fn git_authority_commits_atomically_reopens_and_binds_replication_identity() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let before = manager.read_authority().roots().clone();
        let fixture = git_authority_transaction_fixture(&manager, 0xa001);
        let expected_delta = fixture.transaction.git_authority_delta.clone();

        let receipt = manager
            .commit_repository_transaction(fixture.transaction)
            .unwrap();
        let committed = manager.read_authority();
        assert_eq!(
            committed.metadata().schema_version,
            REPOSITORY_AUTHORITY_SCHEMA_VERSION
        );
        assert_eq!(
            committed.metadata().git_external_authority.as_ref(),
            Some(&fixture.authority)
        );
        assert_eq!(receipt.operation.git_authority_delta, expected_delta);
        assert_ne!(before.replication, committed.roots().replication);
        let initial_roots = committed.roots().clone();
        drop(committed);

        let reopened =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        assert_eq!(
            reopened
                .read_authority()
                .metadata()
                .git_external_authority
                .as_ref(),
            Some(&fixture.authority)
        );
        assert_eq!(reopened.read_authority().roots(), &initial_roots);

        let mut update = transaction_shell(&reopened, 0xa002);
        update.git_authority_delta = Some(GitExternalAuthorityDelta::update(
            fixture.authority.clone(),
            fixture.direct_authority.clone(),
        ));
        let before_update = reopened.read_authority().roots().clone();
        let receipt = reopened.commit_repository_transaction(update).unwrap();
        let after_update = reopened.read_authority();
        assert_eq!(
            after_update.metadata().git_external_authority.as_ref(),
            Some(&fixture.direct_authority)
        );
        assert_eq!(before_update.history, after_update.roots().history);
        assert_ne!(before_update.replication, after_update.roots().replication);
        assert!(receipt.operation.git_authority_delta.is_some());
        let final_roots = after_update.roots().clone();
        drop(after_update);

        let reopened =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        assert_eq!(
            reopened
                .read_authority()
                .metadata()
                .git_external_authority
                .as_ref(),
            Some(&fixture.direct_authority)
        );
        assert_eq!(reopened.read_authority().roots(), &final_roots);

        let mut removal = transaction_shell(&reopened, 0xa003);
        removal.git_authority_delta =
            Some(GitExternalAuthorityDelta::remove(fixture.direct_authority));
        let before_removal = reopened.read_authority().roots().clone();
        let receipt = reopened.commit_repository_transaction(removal).unwrap();
        let removed = reopened.read_authority();
        assert!(removed.metadata().git_external_authority.is_none());
        assert!(!removed.metadata().aliases.is_empty());
        assert!(!removed.snapshot().changes.is_empty());
        assert_eq!(before_removal.history, removed.roots().history);
        assert_ne!(before_removal.replication, removed.roots().replication);
        assert!(receipt.operation.git_authority_delta.is_some());
        let removed_roots = removed.roots().clone();
        drop(removed);

        let reopened =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        assert!(reopened
            .read_authority()
            .metadata()
            .git_external_authority
            .is_none());
        assert_eq!(reopened.read_authority().roots(), &removed_roots);
    }

    #[test]
    fn persisted_authenticated_gitlink_can_seed_a_new_workspace_after_reopen() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let fixture = git_authority_transaction_fixture(&manager, 0xa101);
        let artifact_id = ArtifactId(Uuid::from_u128(0xa4));
        let target = fixture.gitlink_target;
        let authority = fixture.authority.clone();
        manager
            .commit_repository_transaction(fixture.transaction)
            .unwrap();
        let mut removal = transaction_shell(&manager, 0xa102);
        removal.git_authority_delta = Some(GitExternalAuthorityDelta::remove(authority));
        manager.commit_repository_transaction(removal).unwrap();
        drop(manager);

        let reopened =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        assert!(
            reopened
                .read_authority()
                .metadata()
                .git_external_authority
                .is_none(),
            "the exact pair must survive through recorded history, not current Git state"
        );
        assert!(
            reopened
                .read_authority()
                .authenticated_gitlinks()
                .contains(&(artifact_id, target)),
            "reopen must derive Gitlink authority from immutable Git-origin history"
        );
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xa104));
        let transaction =
            unborn_gitlink_workspace_transaction(&reopened, 0xa103, 0xa104, artifact_id, target);
        reopened.commit_repository_transaction(transaction).unwrap();

        let lease = reopened.read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == workspace_id)
            .unwrap();
        assert_eq!(
            workspace
                .tree
                .artifact_at_path(&RepoPath::from_utf8("submodule").unwrap())
                .unwrap()
                .entry,
            TreeEntry::gitlink(target)
        );
    }

    #[test]
    fn persisted_authenticated_gitlink_can_seed_a_native_change() {
        let manager = initial_manager(Arc::new(MemoryBackend::default()));
        let fixture = git_authority_transaction_fixture(&manager, 0xa111);
        let artifact_id = ArtifactId(Uuid::from_u128(0xa4));
        let target = fixture.gitlink_target;
        manager
            .commit_repository_transaction(fixture.transaction)
            .unwrap();

        let transaction = native_gitlink_transaction(&manager, 0xa112, 0xa113, artifact_id, target);
        manager.commit_repository_transaction(transaction).unwrap();

        let lease = manager.read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| {
                workspace.workspace_id == WorkspaceId::from_uuid(Uuid::from_u128(0xa113))
            })
            .unwrap();
        let base = workspace
            .base_target
            .as_ref()
            .map(|target| target_change_id(lease.metadata(), target).unwrap())
            .unwrap();
        assert!(matches!(
            lease.snapshot().changes.get(&base).unwrap().origin,
            ChangeOrigin::Native
        ));
        assert_eq!(
            workspace
                .tree
                .artifact_at_path(&RepoPath::from_utf8("submodule").unwrap())
                .unwrap()
                .entry,
            TreeEntry::gitlink(target)
        );
    }

    #[test]
    fn persisted_authenticated_gitlink_can_retarget_the_same_artifact() {
        let manager = initial_manager(Arc::new(MemoryBackend::default()));
        let fixture = git_authority_transaction_fixture(&manager, 0xa118);
        let artifact_id = ArtifactId(Uuid::from_u128(0xa4));
        let old_target = fixture.previous_gitlink_target;
        let new_target = fixture.gitlink_target;
        manager
            .commit_repository_transaction(fixture.transaction)
            .unwrap();

        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xa11a));
        manager
            .commit_repository_transaction(unborn_gitlink_workspace_transaction(
                &manager,
                0xa119,
                0xa11a,
                artifact_id,
                old_target,
            ))
            .unwrap();

        let current = manager
            .read_authority()
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == workspace_id)
            .unwrap()
            .clone();
        let path = RepoPath::from_utf8("submodule").unwrap();
        let delta = TreeDelta::Updated {
            artifact_id,
            old: LocatedEntry::new(path.clone(), TreeEntry::gitlink(old_target)),
            new: LocatedEntry::new(path.clone(), TreeEntry::gitlink(new_target)),
        };
        let next_tree = current.tree.apply(std::slice::from_ref(&delta)).unwrap();
        let mutation = WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: current.generation,
                head: current.head.clone(),
                base_target: current.base_target.clone(),
                base_tree_hash: current.base_tree_hash,
                tree_hash: current.tree_hash,
                semantic_overlay_hash: current.semantic_overlay_hash,
                admission_policy: current.admission_policy,
            },
            new_generation: current.generation + 1,
            new_head: current.head.clone(),
            new_base_target: current.base_target.clone(),
            new_base_tree_hash: current.base_tree_hash,
            tree_deltas: vec![delta],
            new_tree_hash: compute_resolved_tree_hash(&next_tree).unwrap(),
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: current.shared_admission_policy,
            new_admission_policy: current.admission_policy,
        };
        let mut transaction = transaction_shell(&manager, 0xa11b);
        transaction.workspace_mutation = Some(mutation);
        manager.commit_repository_transaction(transaction).unwrap();

        assert_eq!(
            manager.read_authority().metadata().workspaces[0]
                .tree
                .artifact_at_path(&path)
                .unwrap()
                .entry,
            TreeEntry::gitlink(new_target)
        );
    }

    #[test]
    fn persisted_gitlink_authority_is_exact_in_artifact_and_target() {
        let manager = initial_manager(Arc::new(MemoryBackend::default()));
        let fixture = git_authority_transaction_fixture(&manager, 0xa121);
        let artifact_id = ArtifactId(Uuid::from_u128(0xa4));
        let target = fixture.gitlink_target;
        manager
            .commit_repository_transaction(fixture.transaction)
            .unwrap();

        let wrong_target = unborn_gitlink_workspace_transaction(
            &manager,
            0xa122,
            0xa123,
            artifact_id,
            GitObjectId::sha1([0x66; 20]),
        );
        let error = manager
            .commit_repository_transaction(wrong_target)
            .expect_err("a different Gitlink target must not inherit authority");
        assert!(
            error
                .to_string()
                .contains("without verified Git external authority"),
            "unexpected wrong-target error: {error}"
        );

        let wrong_artifact = unborn_gitlink_workspace_transaction(
            &manager,
            0xa124,
            0xa125,
            ArtifactId(Uuid::from_u128(0xb4)),
            target,
        );
        let error = manager
            .commit_repository_transaction(wrong_artifact)
            .expect_err("a copied ArtifactId must not inherit Gitlink authority");
        assert!(
            error
                .to_string()
                .contains("without verified Git external authority"),
            "unexpected wrong-artifact error: {error}"
        );
        assert_eq!(manager.read_authority().generation(), 1);
    }

    #[test]
    fn same_transaction_git_import_cannot_authorize_an_unrelated_workspace_splice() {
        let manager = initial_manager(Arc::new(MemoryBackend::default()));
        let mut fixture = git_authority_transaction_fixture(&manager, 0xa131);
        let workspace = unborn_gitlink_workspace_transaction(
            &manager,
            0xa132,
            0xa133,
            ArtifactId(Uuid::from_u128(0xa4)),
            fixture.gitlink_target,
        );
        fixture.transaction.workspace_mutation = workspace.workspace_mutation;
        fixture.transaction.local_overlay_delta = workspace.local_overlay_delta;

        let error = manager
            .commit_repository_transaction(fixture.transaction)
            .expect_err("successor Git history must not authorize an unrelated workspace splice");
        assert!(
            error
                .to_string()
                .contains("without verified Git external authority"),
            "unexpected same-transaction workspace error: {error}"
        );
        assert_eq!(manager.read_authority().generation(), 0);
    }

    #[test]
    fn same_transaction_git_parent_cannot_authorize_a_native_gitlink() {
        let manager = initial_manager(Arc::new(MemoryBackend::default()));
        let mut fixture = git_authority_transaction_fixture(&manager, 0xa141);
        let parent = fixture
            .transaction
            .changes
            .iter()
            .find(|change| {
                matches!(
                    change.origin,
                    ChangeOrigin::GitCommit { oid } if oid == fixture.head.object.oid
                )
            })
            .unwrap()
            .id;
        let mut native = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: vec![parent],
            timestamp: Timestamp::now(),
            author: AuthorId::new("authority-test"),
            message: "attempt to inherit uncommitted Gitlink authority".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        native.id = compute_semantic_change_id(&native).unwrap();
        fixture.transaction.changes.push(native);

        let error = manager
            .commit_repository_transaction(fixture.transaction)
            .expect_err("a Native child must wait for Git authority to become persisted");
        assert!(
            error
                .to_string()
                .contains("without verified Git external authority"),
            "unexpected same-transaction Native error: {error}"
        );
        assert_eq!(manager.read_authority().generation(), 0);
    }

    #[test]
    fn git_authority_publication_failure_leaves_no_partial_semantic_or_external_truth() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let fixture = git_authority_transaction_fixture(&manager, 0xa010);
        backend.fail_next_snapshot.store(true, Ordering::SeqCst);

        manager
            .commit_repository_transaction(fixture.transaction)
            .expect_err("failed durable publication must not expose Git authority");

        let lease = manager.read_authority();
        assert_eq!(lease.generation(), 0);
        assert!(
            lease.authenticated_gitlinks().is_empty(),
            "an unpersisted Git transaction must not contaminate the derived authority index"
        );
        assert!(lease.metadata().git_external_authority.is_none());
        assert!(lease.metadata().external_objects.is_empty());
        assert!(lease.metadata().aliases.is_empty());
        assert!(lease.snapshot().changes.is_empty());
    }

    #[test]
    fn detached_annotated_tag_workspace_peels_only_through_persisted_git_authority() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let (transaction, expected_change, outer_tag) = detached_tag_import_transaction(&manager);

        manager.commit_repository_transaction(transaction).unwrap();
        let committed = manager.read_authority();
        let workspace = committed.metadata().workspaces.first().unwrap();
        let exact_target = RefTarget::external_object(outer_tag);
        assert_eq!(
            workspace.head,
            WorkspaceHead::Detached {
                target: exact_target.clone()
            }
        );
        assert_eq!(workspace.base_target, Some(exact_target.clone()));
        assert_eq!(committed.metadata().ref_state.refs[0].target, exact_target);
        assert_eq!(
            committed.resolve_target_change_id(&exact_target).unwrap(),
            expected_change
        );
        assert_eq!(
            committed
                .resolve_ref_target(&RefName::tag(b"release").unwrap())
                .unwrap(),
            Some(exact_target.clone())
        );
        assert_eq!(
            resolve_target_tree_hash(committed.snapshot(), committed.metadata(), &exact_target)
                .unwrap(),
            workspace.tree_hash
        );
        assert_eq!(
            committed
                .metadata()
                .admission_policies
                .iter()
                .find(|policy| policy.change_id == expected_change)
                .and_then(|policy| policy.policy.as_ref()),
            Some(&workspace.shared_admission_policy)
        );
        let roots = committed.roots().clone();
        drop(committed);

        let reopened =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let reopened_authority = reopened.read_authority();
        assert_eq!(reopened_authority.roots(), &roots);
        assert_eq!(
            reopened_authority
                .resolve_target_change_id(&exact_target)
                .unwrap(),
            expected_change
        );
    }

    #[test]
    fn git_authority_exact_old_state_cas_rejects_stale_authority() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(backend);
        let fixture = git_authority_transaction_fixture(&manager, 0xa020);
        manager
            .commit_repository_transaction(fixture.transaction)
            .unwrap();
        let stable_generation = manager.read_authority().generation();

        let mut stale = transaction_shell(&manager, 0xa021);
        stale.git_authority_delta = Some(GitExternalAuthorityDelta::update(
            fixture.direct_authority,
            fixture.authority,
        ));
        let error = manager
            .commit_repository_transaction(stale)
            .expect_err("wrong old authority must lose the exact compare-and-swap");
        assert!(
            error.to_string().contains("exact old-state lease"),
            "unexpected exact-old error: {error}"
        );
        assert_eq!(manager.read_authority().generation(), stable_generation);
    }

    #[test]
    fn git_authority_closure_requires_exact_persisted_descriptors() {
        let missing_backend = Arc::new(MemoryBackend::default());
        let missing_manager = initial_manager(missing_backend);
        let mut missing = git_authority_transaction_fixture(&missing_manager, 0xa030);
        missing
            .transaction
            .external_objects
            .retain(|record| record.object != missing.compose.object);
        let error = missing_manager
            .commit_repository_transaction(missing.transaction)
            .expect_err("closure records absent from the external-object union must fail");
        assert!(
            error
                .to_string()
                .contains("absent from persisted external objects"),
            "unexpected missing closure error: {error}"
        );
        assert_eq!(missing_manager.read_authority().generation(), 0);

        let wrong_backend = Arc::new(MemoryBackend::default());
        let wrong_manager = initial_manager(wrong_backend);
        let mut wrong = git_authority_transaction_fixture(&wrong_manager, 0xa031);
        let mut authority = wrong.authority.clone();
        authority
            .closure
            .objects
            .iter_mut()
            .find(|entry| entry.record.object == wrong.compose.object)
            .unwrap()
            .record
            .body_hash = Hash256::from_bytes([0xee; 32]);
        authority.validate_shape().unwrap();
        wrong.transaction.git_authority_delta =
            Some(GitExternalAuthorityDelta::initialize(authority));
        let error = wrong_manager
            .commit_repository_transaction(wrong.transaction)
            .expect_err("closure descriptors must match the external-object union exactly");
        assert!(
            error
                .to_string()
                .contains("does not match its persisted external-object descriptor"),
            "unexpected wrong descriptor error: {error}"
        );
        assert_eq!(wrong_manager.read_authority().generation(), 0);
    }

    #[test]
    fn git_authority_update_reloads_every_body_and_rejects_missing_or_tampered_cas() {
        let missing_backend = Arc::new(MemoryBackend::default());
        let missing_manager = initial_manager(Arc::clone(&missing_backend));
        let missing = git_authority_transaction_fixture(&missing_manager, 0xa040);
        missing_manager
            .commit_repository_transaction(missing.transaction)
            .unwrap();
        missing_backend
            .blobs
            .lock()
            .remove(missing.head.body_hash.as_bytes());
        let mut update = transaction_shell(&missing_manager, 0xa041);
        update.git_authority_delta = Some(GitExternalAuthorityDelta::update(
            missing.authority,
            missing.direct_authority,
        ));
        let error = missing_manager
            .commit_repository_transaction(update)
            .expect_err("authority update must reload inherited closure bodies");
        assert!(
            error.to_string().contains("body for"),
            "unexpected missing body error: {error}"
        );
        assert_eq!(missing_manager.read_authority().generation(), 1);

        let tampered_backend = Arc::new(MemoryBackend::default());
        let tampered_manager = initial_manager(Arc::clone(&tampered_backend));
        let tampered = git_authority_transaction_fixture(&tampered_manager, 0xa042);
        tampered_manager
            .commit_repository_transaction(tampered.transaction)
            .unwrap();
        tampered_backend.blobs.lock().insert(
            *tampered.compose.body_hash.as_bytes(),
            b"descriptor-tamper".to_vec(),
        );
        let mut update = transaction_shell(&tampered_manager, 0xa043);
        update.git_authority_delta = Some(GitExternalAuthorityDelta::update(
            tampered.authority,
            tampered.direct_authority,
        ));
        let error = tampered_manager
            .commit_repository_transaction(update)
            .expect_err("authority update must reject tampered inherited bodies");
        assert!(
            error.to_string().contains("body validation failed"),
            "unexpected tampered body error: {error}"
        );
        assert_eq!(tampered_manager.read_authority().generation(), 1);
        assert!(
            RepositoryAuthorityManager::open(repository_id(), tampered_backend).is_err(),
            "reopen must independently reject tampered authority bodies"
        );
    }

    fn projection_test_oid(seed: u64) -> GitObjectId {
        let mut bytes = [0_u8; 20];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        GitObjectId::sha1(bytes)
    }

    fn projection_test_change(
        commit_oid: GitObjectId,
        parents: Vec<SemanticChangeId>,
        tree_deltas: Vec<TreeDelta>,
        message: impl Into<String>,
    ) -> SemanticChange {
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::GitCommit { oid: commit_oid },
            parents,
            timestamp: Timestamp::now(),
            author: AuthorId::new("projection-replay-test"),
            message: message.into(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        change.id = compute_semantic_change_id(&change).unwrap();
        change
    }

    fn projection_test_raw_tree(
        entries: impl IntoIterator<Item = (&'static str, TreeEntry)>,
    ) -> BTreeMap<RepoPath, TreeEntry> {
        entries
            .into_iter()
            .map(|(path, entry)| (RepoPath::from_utf8(path).unwrap(), entry))
            .collect()
    }

    #[test]
    fn git_projection_tree_replay_materializes_every_commit_exactly_once() {
        const DEPTH: usize = 128;

        let mut snapshot = GraphSnapshot::empty();
        let mut targets = BTreeMap::new();
        let mut raw_trees = BTreeMap::new();
        let mut expected_paths = BTreeMap::new();
        let mut parent = None;
        for index in 0..DEPTH {
            let commit_oid = projection_test_oid(index as u64 + 1);
            let raw_tree_oid = projection_test_oid(index as u64 + 10_000);
            let path = RepoPath::from_utf8(format!("src/file-{index}.rs")).unwrap();
            let entry = TreeEntry::blob(Hash256::from_bytes([index as u8; 32]), false);
            let change = projection_test_change(
                commit_oid,
                parent.into_iter().collect(),
                vec![TreeDelta::Added {
                    artifact_id: ArtifactId(Uuid::from_u128(index as u128 + 1)),
                    new: LocatedEntry::new(path.clone(), entry),
                }],
                format!("add file {index}"),
            );
            expected_paths.insert(path, entry);
            raw_trees.insert(raw_tree_oid, expected_paths.clone());
            targets.insert(
                change.id,
                GitProjectionTreeTarget {
                    commit_oid,
                    raw_tree_oid,
                },
            );
            parent = Some(change.id);
            snapshot.changes.insert(change.id, change);
        }

        let mut materializations = BTreeMap::new();
        validate_git_projection_tree_replay(&snapshot, &targets, |raw_tree_oid| {
            *materializations.entry(raw_tree_oid).or_insert(0_usize) += 1;
            Ok(raw_trees
                .get(&raw_tree_oid)
                .expect("every projection has one exact raw tree")
                .clone())
        })
        .unwrap();

        assert_eq!(materializations.len(), DEPTH);
        assert!(
            materializations.values().all(|count| *count == 1),
            "projection replay must not re-walk or re-materialize prior commits: {materializations:?}"
        );
    }

    #[test]
    fn git_projection_tree_replay_handles_branches_swaps_and_merge_first_parent() {
        let artifact_a = ArtifactId(Uuid::from_u128(0xa1));
        let artifact_b = ArtifactId(Uuid::from_u128(0xb1));
        let artifact_c = ArtifactId(Uuid::from_u128(0xc1));
        let entry_a = TreeEntry::blob(Hash256::from_bytes([0xa1; 32]), false);
        let entry_b = TreeEntry::blob(Hash256::from_bytes([0xb1; 32]), false);
        let entry_c = TreeEntry::blob(Hash256::from_bytes([0xc1; 32]), false);

        let root_oid = projection_test_oid(1);
        let root_tree_oid = projection_test_oid(101);
        let root = projection_test_change(
            root_oid,
            Vec::new(),
            vec![
                TreeDelta::Added {
                    artifact_id: artifact_a,
                    new: LocatedEntry::new(RepoPath::from_utf8("a").unwrap(), entry_a),
                },
                TreeDelta::Added {
                    artifact_id: artifact_b,
                    new: LocatedEntry::new(RepoPath::from_utf8("b").unwrap(), entry_b),
                },
            ],
            "root",
        );

        let swap_oid = projection_test_oid(2);
        let swap_tree_oid = projection_test_oid(102);
        let swap = projection_test_change(
            swap_oid,
            vec![root.id],
            vec![
                TreeDelta::Updated {
                    artifact_id: artifact_a,
                    old: LocatedEntry::new(RepoPath::from_utf8("a").unwrap(), entry_a),
                    new: LocatedEntry::new(RepoPath::from_utf8("b").unwrap(), entry_a),
                },
                TreeDelta::Updated {
                    artifact_id: artifact_b,
                    old: LocatedEntry::new(RepoPath::from_utf8("b").unwrap(), entry_b),
                    new: LocatedEntry::new(RepoPath::from_utf8("a").unwrap(), entry_b),
                },
            ],
            "swap paths",
        );

        let side_oid = projection_test_oid(3);
        let side_tree_oid = projection_test_oid(103);
        let side = projection_test_change(
            side_oid,
            vec![root.id],
            vec![
                TreeDelta::Removed {
                    artifact_id: artifact_a,
                    old: LocatedEntry::new(RepoPath::from_utf8("a").unwrap(), entry_a),
                },
                TreeDelta::Added {
                    artifact_id: artifact_c,
                    new: LocatedEntry::new(RepoPath::from_utf8("c").unwrap(), entry_c),
                },
            ],
            "side branch",
        );

        let merge_oid = projection_test_oid(4);
        let merge_tree_oid = projection_test_oid(104);
        let merge = projection_test_change(
            merge_oid,
            vec![swap.id, side.id],
            vec![TreeDelta::Updated {
                artifact_id: artifact_a,
                old: LocatedEntry::new(RepoPath::from_utf8("b").unwrap(), entry_a),
                new: LocatedEntry::new(RepoPath::from_utf8("d").unwrap(), entry_a),
            }],
            "merge from swap material parent",
        );

        let mut snapshot = GraphSnapshot::empty();
        let mut targets = BTreeMap::new();
        for (change, raw_tree_oid) in [
            (&root, root_tree_oid),
            (&swap, swap_tree_oid),
            (&side, side_tree_oid),
            (&merge, merge_tree_oid),
        ] {
            snapshot.changes.insert(change.id, change.clone());
            let ChangeOrigin::GitCommit { oid } = change.origin else {
                unreachable!()
            };
            targets.insert(
                change.id,
                GitProjectionTreeTarget {
                    commit_oid: oid,
                    raw_tree_oid,
                },
            );
        }
        let mut raw_trees = BTreeMap::from([
            (
                root_tree_oid,
                projection_test_raw_tree([("a", entry_a), ("b", entry_b)]),
            ),
            (
                swap_tree_oid,
                projection_test_raw_tree([("a", entry_b), ("b", entry_a)]),
            ),
            (
                side_tree_oid,
                projection_test_raw_tree([("b", entry_b), ("c", entry_c)]),
            ),
            (
                merge_tree_oid,
                projection_test_raw_tree([("a", entry_b), ("d", entry_a)]),
            ),
        ]);

        validate_git_projection_tree_replay(&snapshot, &targets, |raw_tree_oid| {
            Ok(raw_trees[&raw_tree_oid].clone())
        })
        .unwrap();

        raw_trees
            .get_mut(&merge_tree_oid)
            .unwrap()
            .insert(RepoPath::from_utf8("a").unwrap(), entry_c);
        let error = validate_git_projection_tree_replay(&snapshot, &targets, |raw_tree_oid| {
            Ok(raw_trees[&raw_tree_oid].clone())
        })
        .expect_err(
            "an untouched raw-tree entry must not diverge from semantic first-parent state",
        );
        assert!(
            error
                .to_string()
                .contains("does not match the deterministic semantic tree"),
            "unexpected untouched-entry error: {error}"
        );
    }

    #[test]
    fn git_projection_tree_replay_rejects_missing_first_parent_and_cycles() {
        let missing_parent = SemanticChangeId::from_hash(Hash256::from_bytes([0x99; 32]));
        let missing_oid = projection_test_oid(201);
        let missing = projection_test_change(
            missing_oid,
            vec![missing_parent],
            Vec::new(),
            "missing first parent",
        );
        let missing_targets = BTreeMap::from([(
            missing.id,
            GitProjectionTreeTarget {
                commit_oid: missing_oid,
                raw_tree_oid: projection_test_oid(301),
            },
        )]);
        let mut missing_snapshot = GraphSnapshot::empty();
        missing_snapshot.changes.insert(missing.id, missing);
        let error =
            validate_git_projection_tree_replay(&missing_snapshot, &missing_targets, |_| {
                panic!("a structurally incomplete projection must fail before materialization")
            })
            .expect_err("a projected first parent must also have an exact tree target");
        assert!(
            error.to_string().contains(&missing_parent.to_string()),
            "unexpected missing-parent error: {error}"
        );

        let left_oid = projection_test_oid(202);
        let right_oid = projection_test_oid(203);
        let mut left = projection_test_change(left_oid, Vec::new(), Vec::new(), "cycle left");
        let mut right = projection_test_change(right_oid, Vec::new(), Vec::new(), "cycle right");
        left.parents = vec![right.id];
        right.parents = vec![left.id];
        let cycle_targets = BTreeMap::from([
            (
                left.id,
                GitProjectionTreeTarget {
                    commit_oid: left_oid,
                    raw_tree_oid: projection_test_oid(302),
                },
            ),
            (
                right.id,
                GitProjectionTreeTarget {
                    commit_oid: right_oid,
                    raw_tree_oid: projection_test_oid(303),
                },
            ),
        ]);
        let mut cycle_snapshot = GraphSnapshot::empty();
        cycle_snapshot.changes.insert(left.id, left);
        cycle_snapshot.changes.insert(right.id, right);
        let error = validate_git_projection_tree_replay(&cycle_snapshot, &cycle_targets, |_| {
            panic!("a cyclic projection forest must fail before materialization")
        })
        .expect_err("a first-parent projection cycle must fail closed");
        assert!(
            error
                .to_string()
                .contains("cycle in first-parent Git projection history"),
            "unexpected cycle error: {error}"
        );
    }

    #[test]
    fn git_authority_requires_projection_alias_ordered_parents_and_exact_tree_plan() {
        let alias_backend = Arc::new(MemoryBackend::default());
        let alias_manager = initial_manager(alias_backend);
        let mut missing_alias = git_authority_transaction_fixture(&alias_manager, 0xa050);
        missing_alias.transaction.changes.retain(|change| {
            !matches!(
                change.origin,
                ChangeOrigin::GitCommit { oid } if oid == missing_alias.head.object.oid
            )
        });
        missing_alias
            .transaction
            .aliases
            .retain(|alias| alias.oid != missing_alias.head.object.oid);
        let error = alias_manager
            .commit_repository_transaction(missing_alias.transaction)
            .expect_err("every commit projection requires an exact semantic alias");
        assert!(
            error
                .to_string()
                .contains("has no repository-scoped semantic alias"),
            "unexpected alias error: {error}"
        );

        let parent_backend = Arc::new(MemoryBackend::default());
        let parent_manager = initial_manager(parent_backend);
        let mut wrong_parent = git_authority_transaction_fixture(&parent_manager, 0xa051);
        let head_change = wrong_parent
            .transaction
            .changes
            .iter_mut()
            .find(|change| {
                matches!(
                    change.origin,
                    ChangeOrigin::GitCommit { oid } if oid == wrong_parent.head.object.oid
                )
            })
            .unwrap();
        head_change.parents.clear();
        head_change.id = compute_semantic_change_id(head_change).unwrap();
        wrong_parent
            .transaction
            .aliases
            .iter_mut()
            .find(|alias| alias.oid == wrong_parent.head.object.oid)
            .unwrap()
            .change_id = head_change.id;
        let error = parent_manager
            .commit_repository_transaction(wrong_parent.transaction)
            .expect_err("raw ordered parents must map exactly through aliases");
        assert!(
            error.to_string().contains("ordered parent aliases"),
            "unexpected parent projection error: {error}"
        );

        let tree_backend = Arc::new(MemoryBackend::default());
        let tree_manager = initial_manager(tree_backend);
        let mut wrong_tree = git_authority_transaction_fixture(&tree_manager, 0xa052);
        let head_change = wrong_tree
            .transaction
            .changes
            .iter_mut()
            .find(|change| {
                matches!(
                    change.origin,
                    ChangeOrigin::GitCommit { oid } if oid == wrong_tree.head.object.oid
                )
            })
            .unwrap();
        let TreeDelta::Added { new, .. } = head_change
            .tree_deltas
            .iter_mut()
            .find(|delta| {
                delta
                    .new_state()
                    .is_some_and(|entry| entry.path.as_bytes() == b"compose.yaml")
            })
            .unwrap()
        else {
            unreachable!()
        };
        new.entry = TreeEntry::blob(wrong_tree.compose.body_hash, true);
        head_change.id = compute_semantic_change_id(head_change).unwrap();
        wrong_tree
            .transaction
            .aliases
            .iter_mut()
            .find(|alias| alias.oid == wrong_tree.head.object.oid)
            .unwrap()
            .change_id = head_change.id;
        let error = tree_manager
            .commit_repository_transaction(wrong_tree.transaction)
            .expect_err("raw Git tree identity must match semantic replay exactly");
        assert!(
            error
                .to_string()
                .contains("does not match the deterministic semantic tree"),
            "unexpected tree projection error: {error}"
        );
    }

    #[test]
    fn reopen_replays_unreferenced_history_leaves_fail_closed() {
        let artifact_id = ArtifactId(Uuid::from_u128(0xdead));
        let original = LocatedEntry::new(
            RepoPath::from_utf8("compose.yaml").unwrap(),
            TreeEntry::blob(Hash256::from_bytes([0x11; 32]), false),
        );
        let mut genesis = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: Vec::new(),
            timestamp: Timestamp::now(),
            author: AuthorId::new("authority-test"),
            message: "unreferenced genesis".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: vec![TreeDelta::Added {
                artifact_id,
                new: original.clone(),
            }],
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        genesis.id = compute_semantic_change_id(&genesis).unwrap();

        let mut invalid_child = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: vec![genesis.id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("authority-test"),
            message: "stale unreferenced transition".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: vec![TreeDelta::Updated {
                artifact_id,
                old: LocatedEntry::new(RepoPath::from_utf8("wrong.yaml").unwrap(), original.entry),
                new: LocatedEntry::new(
                    RepoPath::from_utf8("compose.yaml").unwrap(),
                    TreeEntry::blob(Hash256::from_bytes([0x12; 32]), false),
                ),
            }],
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        invalid_child.id = compute_semantic_change_id(&invalid_child).unwrap();

        let mut snapshot = GraphSnapshot::empty();
        snapshot.changes.insert(genesis.id, genesis);
        snapshot
            .changes
            .insert(invalid_child.id, invalid_child.clone());
        snapshot
            .change_children
            .insert(invalid_child.parents[0], vec![invalid_child.id]);

        let error = validate_history_replay(&snapshot, &[])
            .expect_err("reopen must replay even history not named by a ref");
        assert!(
            error.to_string().contains("tree"),
            "unexpected replay error: {error}"
        );
    }

    fn merge_history_fixture(
        merge_old: Entity,
        merge_new: Entity,
    ) -> (GraphSnapshot, Vec<kin_model::SemanticChange>) {
        let original = semantic_test_entity("src/lib.rs", "kin", LanguageId::Rust, 0x61);
        let mut revised = original.clone();
        revised.signature = "fn kin(value: i32)".to_string();
        revised.fingerprint.signature_hash = Hash256::from_bytes([0x62; 32]);

        let mut genesis = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: Vec::new(),
            timestamp: Timestamp::now(),
            author: AuthorId::new("authority-test"),
            message: "introduce kin".to_string(),
            entity_deltas: vec![EntityDelta::Added {
                new: original.clone(),
            }],
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        genesis.id = compute_semantic_change_id(&genesis).unwrap();

        let mut branch = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: vec![genesis.id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("authority-test"),
            message: "revise kin on a side branch".to_string(),
            entity_deltas: vec![EntityDelta::Modified {
                old: original.clone(),
                new: revised.clone(),
            }],
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        branch.id = compute_semantic_change_id(&branch).unwrap();

        let mut merge = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: vec![genesis.id, branch.id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("authority-test"),
            message: "merge the side branch".to_string(),
            entity_deltas: vec![EntityDelta::Modified {
                old: merge_old,
                new: merge_new,
            }],
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        merge.id = compute_semantic_change_id(&merge).unwrap();

        let mut snapshot = GraphSnapshot::empty();
        snapshot.changes.insert(genesis.id, genesis.clone());
        snapshot.changes.insert(branch.id, branch.clone());
        snapshot.changes.insert(merge.id, merge.clone());
        let mut genesis_children = vec![branch.id, merge.id];
        genesis_children.sort_unstable();
        snapshot
            .change_children
            .insert(genesis.id, genesis_children);
        snapshot.change_children.insert(branch.id, vec![merge.id]);

        (snapshot, vec![genesis, branch, merge])
    }

    /// A merge restates the edit its second parent published. Entity revisions
    /// derived along first-parent lineage alone never saw that payload, so
    /// replay read the merge's old payload as stale and refused the history.
    ///
    /// Upstream trigger: fd 10ea476e3174350860ef3a32c61c4c8d6e74ab55, its 91st
    /// commit, the first merge in fd whose second parent carries a source edit
    /// (src/main.rs) that the first-parent lineage never published.
    #[test]
    fn history_replay_admits_a_merge_that_carries_its_second_parent_edits() {
        let original = semantic_test_entity("src/lib.rs", "kin", LanguageId::Rust, 0x61);
        let mut revised = original.clone();
        revised.signature = "fn kin(value: i32)".to_string();
        revised.fingerprint.signature_hash = Hash256::from_bytes([0x62; 32]);

        // A Git merge whose result is its second parent's content is authored
        // against the merge's first parent, so it restates the transition the
        // side branch already published. Both readings are the same history.
        let (snapshot, changes) = merge_history_fixture(original, revised);

        validate_history_replay(&snapshot, &changes)
            .expect("a merge restating its second parent's edit is not a stale payload");
        validate_history_replay(&snapshot, &[])
            .expect("reopen must replay the same merge history it admitted");
    }

    #[test]
    fn history_replay_refuses_a_merge_whose_old_payload_no_parent_published() {
        let mut unpublished = semantic_test_entity("src/lib.rs", "kin", LanguageId::Rust, 0x61);
        unpublished.signature = "fn kin(value: u64)".to_string();
        unpublished.fingerprint.signature_hash = Hash256::from_bytes([0x63; 32]);
        let mut replacement = unpublished.clone();
        replacement.signature = "fn kin(value: u128)".to_string();
        replacement.fingerprint.signature_hash = Hash256::from_bytes([0x64; 32]);

        let (snapshot, changes) = merge_history_fixture(unpublished, replacement);

        for (label, new_changes) in [("admission", changes.as_slice()), ("reopen", &[][..])] {
            let error = validate_history_replay(&snapshot, new_changes)
                .expect_err("an old payload no parent ever published must be refused");
            assert!(
                error.to_string().contains("stale old payload for entity"),
                "unexpected {label} replay error: {error}"
            );
        }
    }

    #[test]
    fn removal_rejects_a_missing_old_body_before_publication() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();
        let (transaction, old_body) = remove_compose_transaction(&manager, 0x0d1);
        backend.blobs.lock().remove(old_body.as_bytes());

        let error = manager
            .commit_repository_transaction(transaction)
            .expect_err("removed historical bytes must remain reconstructable");
        assert!(
            error.to_string().contains("old artifact")
                && error
                    .to_string()
                    .contains("absent from immutable source CAS"),
            "unexpected missing-old-body error: {error}"
        );
        assert_eq!(manager.read_authority().generation(), 1);
    }

    #[test]
    fn reopen_rejects_tampered_bytes_retained_by_a_removal_delta() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();
        let (transaction, old_body) = remove_compose_transaction(&manager, 0x0d2);
        manager.commit_repository_transaction(transaction).unwrap();
        backend
            .blobs
            .lock()
            .insert(*old_body.as_bytes(), b"tampered historical bytes".to_vec());

        let error = match RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)) {
            Ok(_) => panic!("tampered historical bytes must fail authority reopen"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("digest mismatch"),
            "unexpected tampered-old-body error: {error}"
        );
    }

    #[test]
    fn one_envelope_commits_polyglot_arbitrary_files_refs_workspace_and_receipt() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let old = manager.read_authority();
        let transaction = arbitrary_repository_transaction(&manager);

        let receipt = manager
            .commit_repository_transaction(transaction.clone())
            .unwrap();

        assert_eq!(receipt.outcome, RepositoryCommitOutcome::Committed);
        assert_eq!(receipt.generation, 1);
        assert_eq!(old.generation(), 0);
        assert!(old.metadata().ref_state.refs.is_empty());
        assert!(old.metadata().receipts.is_empty());

        let current = manager.read_authority();
        assert_eq!(current.generation(), 1);
        assert_eq!(current.metadata().operation_log.len(), 1);
        assert_eq!(current.metadata().receipts.len(), 1);
        assert_eq!(current.metadata().ref_state.refs.len(), 1);
        let workspace = &current.metadata().workspaces[0];
        assert_eq!(workspace.tree.len(), 6);
        let non_utf8 =
            RepoPath::from_bytes(b"assets/data-\xff.bin".to_vec()).expect("valid exact path");
        assert_eq!(
            workspace.tree.artifact_at_path(&non_utf8).unwrap().entry,
            TreeEntry::blob(digest(&[0, 1, 2, 0xff]), false)
        );
        assert!(matches!(
            workspace
                .tree
                .artifact_at_path(&RepoPath::from_utf8("compose-current").unwrap())
                .unwrap()
                .entry,
            TreeEntry::Symlink { .. }
        ));
        let projection = manager
            .workspace_tree_snapshot(&repository_id(), &workspace.workspace_id)
            .unwrap()
            .expect("workspace tree projection");
        projection.validate().unwrap();
        assert_eq!(
            projection
                .artifacts
                .iter()
                .find(|artifact| artifact.path.as_bytes() == b"compose.yaml")
                .unwrap()
                .size,
            b"services:\n  api:\n    build: .\n".len() as u64
        );
        assert_eq!(
            projection
                .artifacts
                .iter()
                .find(|artifact| artifact.path.as_bytes() == b"compose-current")
                .unwrap()
                .size,
            b"compose.yaml".len() as u64
        );
        assert_eq!(
            projection.identity().unwrap(),
            manager
                .workspace_tree_snapshot(&repository_id(), &workspace.workspace_id)
                .unwrap()
                .unwrap()
                .identity()
                .unwrap(),
            "one authority generation must produce a deterministic VFS snapshot"
        );

        let replay = manager.commit_repository_transaction(transaction).unwrap();
        assert_eq!(replay.outcome, RepositoryCommitOutcome::IdempotentReplay);
        assert_eq!(manager.read_authority().generation(), 1);

        let reopened =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        assert_eq!(reopened.read_authority().generation(), 1);
        assert_eq!(reopened.read_authority().metadata().receipts.len(), 1);
    }

    #[test]
    fn repository_open_rejects_v11_tree_only_workspace_authority() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();
        drop(manager);

        let mut persisted = backend.snapshot.lock();
        let (bytes, _) = persisted
            .as_mut()
            .expect("authority snapshot was persisted");
        bytes[4..8].copy_from_slice(&11u32.to_le_bytes());
        drop(persisted);

        let error = match RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)) {
            Ok(_) => panic!("v11 tree-only workspace authority must not reopen"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            KinDbError::IncompatibleSnapshotVersion { found: 11, .. }
        ));
        assert!(
            error.to_string().contains("workspace semantics"),
            "unexpected v11 authority rejection: {error}"
        );
    }

    fn assert_workspace_external_reference_authority<B>(backend: Arc<B>)
    where
        B: StorageBackend + ?Sized + 'static,
    {
        let manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let mut entity =
            semantic_test_entity("src/lib.rs", "imports_requests", LanguageId::Rust, 0x71);
        entity.file_origin = None;
        let base_reference =
            ExternalReference::new_resolved("python-module-v1", "requests", "get").unwrap();
        let base_relation = Relation {
            id: RelationId::from_content(
                &entity.id.to_string(),
                &base_reference.id.to_string(),
                "imports",
            ),
            kind: RelationKind::Imports,
            src: GraphNodeId::Entity(entity.id),
            dst: GraphNodeId::ExternalReference(base_reference.id),
            confidence: 1.0,
            origin: RelationOrigin::Lsp,
            created_in: None,
            import_source: Some("requests.get".to_string()),
            evidence: Vec::new(),
        };

        let shared = SharedAdmissionPolicy::empty(0);
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: Vec::new(),
            timestamp: Timestamp(
                chrono::DateTime::parse_from_rfc3339("2026-07-28T16:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            author: AuthorId::new("authority-test"),
            message: "persist external-reference repository authority".to_string(),
            entity_deltas: vec![EntityDelta::Added {
                new: entity.clone(),
            }],
            relation_deltas: vec![RelationDelta::Added {
                new: base_relation.clone(),
            }],
            tree_deltas: Vec::new(),
            admission_policy_delta: Some(AdmissionPolicyDelta::initialize(shared.clone())),
            external_reference_deltas: vec![ExternalReferenceDelta::Added {
                new: base_reference.clone(),
            }],
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        change.id = compute_semantic_change_id(&change).unwrap();
        let base_target = RefTarget::change(change.id);
        let tree_hash = compute_resolved_tree_hash(&ResolvedTree::default()).unwrap();
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0x5e2f));
        let frozen_overlay =
            FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::Sensitive, Vec::new()).unwrap();
        let effective_policy = EffectiveAdmissionPolicyStamp {
            shared: shared.stamp(),
            local: frozen_overlay.stamp(),
        };
        let main = RefName::branch(b"main").unwrap();
        let mut initial = transaction_shell(&manager, 0x5e2f);
        initial.changes.push(change);
        initial.ref_mutations.push(RefMutation {
            name: main.clone(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(base_target.clone()),
            policy: RefUpdatePolicy::FastForwardOnly,
        });
        initial.default_ref_mutation = Some(DefaultRefMutation {
            expected: DefaultRefExpectation::MustBeUnset,
            new_default: Some(main.clone()),
        });
        initial.workspace_mutation = Some(WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustNotExist,
            new_generation: 0,
            new_head: WorkspaceHead::Symbolic { target: main },
            new_base_target: Some(base_target),
            new_base_tree_hash: Some(tree_hash),
            tree_deltas: Vec::new(),
            new_tree_hash: tree_hash,
            semantic_delta: WorkspaceSemanticDelta::new_with_external_references(
                vec![EntityDelta::Added {
                    new: entity.clone(),
                }],
                vec![RelationDelta::Added {
                    new: base_relation.clone(),
                }],
                vec![ExternalReferenceDelta::Added {
                    new: base_reference.clone(),
                }],
            )
            .unwrap(),
            new_shared_admission_policy: shared,
            new_admission_policy: effective_policy,
        });
        initial.local_overlay_delta = Some(FrozenLocalOverlayDelta::initialize(frozen_overlay));

        manager.commit_repository_transaction(initial).unwrap();
        let workspace = manager.read_authority().metadata().workspaces[0].clone();
        assert!(
            workspace.semantic_overlay.is_empty(),
            "a workspace matching its committed base must not persist a compensating overlay"
        );
        let committed_base = manager
            .workspace_graph_snapshot(&repository_id(), &workspace.workspace_id)
            .unwrap()
            .expect("committed external-reference base materializes");
        assert_eq!(
            committed_base.external_references.get(&base_reference.id),
            Some(&base_reference)
        );
        assert_eq!(
            committed_base.relations.get(&base_relation.id),
            Some(&base_relation)
        );

        let standalone =
            ExternalReference::new_resolved("npm-package-v1", "@mui/utils", "merge").unwrap();
        let workspace_reference =
            ExternalReference::new_resolved("python-module-v1", "urllib", "open").unwrap();
        let workspace_relation = Relation {
            id: RelationId::from_content(
                &entity.id.to_string(),
                &workspace_reference.id.to_string(),
                "imports",
            ),
            kind: RelationKind::Imports,
            src: GraphNodeId::Entity(entity.id),
            dst: GraphNodeId::ExternalReference(workspace_reference.id),
            confidence: 1.0,
            origin: RelationOrigin::Manual,
            created_in: None,
            import_source: Some("urllib.open".to_string()),
            evidence: Vec::new(),
        };
        let addition = WorkspaceSemanticDelta::new_with_external_references(
            Vec::new(),
            vec![RelationDelta::Added {
                new: workspace_relation.clone(),
            }],
            vec![
                ExternalReferenceDelta::Added {
                    new: standalone.clone(),
                },
                ExternalReferenceDelta::Added {
                    new: workspace_reference.clone(),
                },
            ],
        )
        .unwrap();
        manager
            .commit_repository_transaction(semantic_workspace_transaction(
                &manager, 0x5e30, addition,
            ))
            .unwrap();

        let added_workspace = manager.read_authority().metadata().workspaces[0].clone();
        assert_eq!(
            added_workspace
                .semantic_overlay
                .external_reference_deltas()
                .len(),
            2,
            "the cumulative overlay must retain both standalone and relation-bound additions"
        );
        let added = manager
            .workspace_graph_snapshot(&repository_id(), &added_workspace.workspace_id)
            .unwrap()
            .expect("workspace external-reference additions materialize");
        for reference in [&base_reference, &standalone, &workspace_reference] {
            assert_eq!(
                added.external_references.get(&reference.id),
                Some(reference)
            );
        }
        assert_eq!(
            added.relations.get(&workspace_relation.id),
            Some(&workspace_relation)
        );

        let reopened =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let reopened_added = reopened
            .workspace_graph_snapshot(&repository_id(), &added_workspace.workspace_id)
            .unwrap()
            .expect("workspace external-reference additions survive reopen");
        assert_eq!(reopened_added.external_references.len(), 3);
        assert_eq!(
            reopened_added.relations.get(&workspace_relation.id),
            Some(&workspace_relation)
        );

        let removal = WorkspaceSemanticDelta::new_with_external_references(
            Vec::new(),
            vec![
                RelationDelta::Removed {
                    old: base_relation.clone(),
                },
                RelationDelta::Removed {
                    old: workspace_relation.clone(),
                },
            ],
            vec![
                ExternalReferenceDelta::Removed {
                    old: base_reference.clone(),
                },
                ExternalReferenceDelta::Removed {
                    old: standalone.clone(),
                },
                ExternalReferenceDelta::Removed {
                    old: workspace_reference.clone(),
                },
            ],
        )
        .unwrap();
        reopened
            .commit_repository_transaction(semantic_workspace_transaction(
                &reopened, 0x5e31, removal,
            ))
            .unwrap();

        let removed_workspace = reopened.read_authority().metadata().workspaces[0].clone();
        assert_eq!(
            removed_workspace
                .semantic_overlay
                .external_reference_deltas(),
            &[ExternalReferenceDelta::Removed {
                old: base_reference.clone(),
            }],
            "the cumulative overlay must retain the exact removal relative to committed base"
        );
        let removed = reopened
            .workspace_graph_snapshot(&repository_id(), &removed_workspace.workspace_id)
            .unwrap()
            .expect("workspace external-reference removals materialize");
        assert!(removed.external_references.is_empty());
        assert!(!removed.relations.contains_key(&base_relation.id));
        assert!(!removed.relations.contains_key(&workspace_relation.id));

        let final_reopen = RepositoryAuthorityManager::open(repository_id(), backend).unwrap();
        let final_snapshot = final_reopen
            .workspace_graph_snapshot(&repository_id(), &removed_workspace.workspace_id)
            .unwrap()
            .expect("workspace external-reference removals survive reopen");
        assert!(final_snapshot.external_references.is_empty());
        assert!(!final_snapshot.relations.contains_key(&base_relation.id));
        assert!(!final_snapshot
            .relations
            .contains_key(&workspace_relation.id));
    }

    #[test]
    fn workspace_external_reference_authority_is_backend_generic_in_memory() {
        assert_workspace_external_reference_authority(Arc::new(MemoryBackend::default()));
    }

    #[test]
    fn workspace_external_reference_authority_is_backend_generic_on_local_storage() {
        let directory = TempDir::new().unwrap();
        assert_workspace_external_reference_authority(Arc::new(LocalFileBackend::new(
            directory.path(),
        )));
    }

    #[cfg(feature = "sql")]
    #[test]
    fn workspace_external_reference_authority_is_backend_generic_on_sqlite() {
        assert_workspace_external_reference_authority(Arc::new(
            crate::storage::SqliteBackend::in_memory().unwrap(),
        ));
    }

    #[cfg(feature = "gcs")]
    #[test]
    fn workspace_external_reference_authority_is_backend_generic_on_gcs_object_store() {
        assert_workspace_external_reference_authority(Arc::new(
            crate::storage::GcsBackend::from_store(
                Box::new(crate::storage::gcs::tests::VersionedMemoryStore::new()),
                "workspace-external-reference",
            ),
        ));
    }

    #[test]
    fn workspace_graph_snapshot_resolves_base_semantics_and_exact_arbitrary_tree() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let mut transaction = arbitrary_repository_transaction(&manager);
        let entity_id = EntityId::from_content("src/lib.rs", "kin", "function", 1);
        let entity = Entity {
            id: entity_id,
            kind: EntityKind::Function,
            name: "kin".to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0x11; 32]),
                signature_hash: Hash256::from_bytes([0x12; 32]),
                behavior_hash: Hash256::from_bytes([0x13; 32]),
                equivalence_hash: Hash256::from_bytes([0x14; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/lib.rs")),
            span: None,
            signature: "pub fn kin()".to_string(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };
        let change = transaction.changes.first_mut().unwrap();
        change.entity_deltas.push(EntityDelta::Added {
            new: entity.clone(),
        });
        change.id = SemanticChangeId::from_hash(Hash256::from_bytes([0; 32]));
        change.id = compute_semantic_change_id(change).unwrap();
        let change_id = change.id;
        transaction.ref_mutations[0].new_target = Some(RefTarget::change(change_id));
        let workspace_mutation = transaction.workspace_mutation.as_mut().unwrap();
        workspace_mutation.new_base_target = Some(RefTarget::change(change_id));
        workspace_mutation.semantic_delta = WorkspaceSemanticDelta::new(
            vec![EntityDelta::Added {
                new: entity.clone(),
            }],
            Vec::new(),
        )
        .unwrap();

        manager.commit_repository_transaction(transaction).unwrap();
        let authority = manager.read_authority();
        let workspace = authority.metadata().workspaces[0].clone();
        let roots_before = authority.roots().clone();
        assert!(
            authority.snapshot().entities.is_empty()
                && authority.snapshot().resolved_tree.is_empty(),
            "repository authority must remain an unscoped history envelope"
        );
        drop(authority);

        let prepared = manager
            .workspace_graph_snapshot(&repository_id(), &workspace.workspace_id)
            .unwrap()
            .expect("workspace exists");
        assert!(
            prepared.repository_authority.is_none(),
            "prepared query state must not become a second authority envelope"
        );
        assert_eq!(prepared.entities.get(&entity_id), Some(&entity));
        assert_eq!(prepared.resolved_tree, workspace.tree);
        assert!(prepared
            .resolved_tree
            .artifact_at_path(&RepoPath::from_utf8("compose.yaml").unwrap())
            .is_some());
        assert!(prepared
            .resolved_tree
            .artifact_at_path(&RepoPath::from_bytes(b"assets/data-\xff.bin".to_vec()).unwrap())
            .is_some());
        InMemoryGraph::from_snapshot(prepared)
            .expect("workspace query snapshot must open as a derived graph");
        assert_eq!(manager.read_authority().roots(), &roots_before);

        let reopened =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let reopened_prepared = reopened
            .workspace_graph_snapshot(&repository_id(), &workspace.workspace_id)
            .unwrap()
            .expect("workspace survives reopen");
        assert_eq!(reopened_prepared.entities.get(&entity_id), Some(&entity));
        assert_eq!(reopened_prepared.resolved_tree, workspace.tree);
    }

    #[test]
    fn same_tree_polyglot_semantics_and_cross_language_relation_survive_reopen() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let base_rust = semantic_test_entity("src/lib.rs", "kin", LanguageId::Rust, 0x30);
        let mut initial = arbitrary_repository_transaction(&manager);
        let change = initial.changes.first_mut().unwrap();
        change.entity_deltas.push(EntityDelta::Added {
            new: base_rust.clone(),
        });
        change.id = SemanticChangeId::from_hash(Hash256::from_bytes([0; 32]));
        change.id = compute_semantic_change_id(change).unwrap();
        let base_target = RefTarget::change(change.id);
        initial.ref_mutations[0].new_target = Some(base_target.clone());
        let initial_workspace = initial.workspace_mutation.as_mut().unwrap();
        initial_workspace.new_base_target = Some(base_target);
        initial_workspace.semantic_delta = WorkspaceSemanticDelta::new(
            vec![EntityDelta::Added {
                new: base_rust.clone(),
            }],
            Vec::new(),
        )
        .unwrap();
        manager.commit_repository_transaction(initial).unwrap();

        let rust = semantic_test_entity("src/lib.rs", "kin", LanguageId::Rust, 0x31);
        assert_eq!(rust.id, base_rust.id);
        let python = semantic_test_entity("tools/check.py", "check_kin", LanguageId::Python, 0x41);
        let relation = Relation {
            id: RelationId::from_content(&rust.id.to_string(), &python.id.to_string(), "calls"),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(rust.id),
            dst: GraphNodeId::Entity(python.id),
            confidence: 1.0,
            origin: RelationOrigin::Manual,
            created_in: None,
            import_source: Some("tools.check".to_string()),
            evidence: Vec::new(),
        };
        let semantic_delta = WorkspaceSemanticDelta::new(
            vec![
                EntityDelta::Modified {
                    old: base_rust,
                    new: rust.clone(),
                },
                EntityDelta::Added {
                    new: python.clone(),
                },
            ],
            vec![RelationDelta::Added {
                new: relation.clone(),
            }],
        )
        .unwrap();
        let roots_before = manager.read_authority().roots().clone();
        let tree_before = manager.read_authority().metadata().workspaces[0]
            .tree
            .clone();
        assert_eq!(tree_before.len(), 6);
        for path in [
            "compose.yaml",
            "src/lib.rs",
            "tools/check.py",
            "unsupported/module.zig",
            "compose-current",
        ] {
            assert!(
                tree_before
                    .artifact_at_path(&RepoPath::from_utf8(path).unwrap())
                    .is_some(),
                "polyglot exact-tree fixture is missing {path}"
            );
        }
        assert!(tree_before
            .artifact_at_path(&RepoPath::from_bytes(b"assets/data-\xff.bin".to_vec()).unwrap())
            .is_some());

        let receipt = manager
            .commit_repository_transaction(semantic_workspace_transaction(
                &manager,
                0x5e01,
                semantic_delta,
            ))
            .unwrap();

        assert!(
            roots_before.has_same_replicated_truth(&receipt.roots_after),
            "same-tree workspace semantics must remain local authority"
        );
        assert_ne!(roots_before.local_state, receipt.roots_after.local_state);
        let workspace = manager.read_authority().metadata().workspaces[0].clone();
        assert_eq!(workspace.tree, tree_before);
        assert!(!workspace.semantic_overlay.is_empty());

        let prepared = manager
            .workspace_graph_snapshot(&repository_id(), &workspace.workspace_id)
            .unwrap()
            .expect("semantic workspace exists");
        assert_eq!(prepared.entities.get(&rust.id), Some(&rust));
        assert_eq!(prepared.entities.get(&python.id), Some(&python));
        assert_eq!(prepared.relations.get(&relation.id), Some(&relation));
        assert_eq!(prepared.resolved_tree, tree_before);

        let reopened =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let reopened_prepared = reopened
            .workspace_graph_snapshot(&repository_id(), &workspace.workspace_id)
            .unwrap()
            .expect("semantic workspace survives reopen");
        assert_eq!(reopened_prepared.entities.get(&rust.id), Some(&rust));
        assert_eq!(reopened_prepared.entities.get(&python.id), Some(&python));
        assert_eq!(
            reopened_prepared.relations.get(&relation.id),
            Some(&relation)
        );
        assert_eq!(reopened_prepared.resolved_tree, tree_before);
    }

    #[test]
    fn advancing_the_base_rederives_a_clean_semantic_overlay_and_survives_reopen() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let base_rust = semantic_test_entity("src/lib.rs", "kin", LanguageId::Rust, 0x61);
        let mut initial = arbitrary_repository_transaction(&manager);
        let base_change = initial.changes.first_mut().unwrap();
        base_change.entity_deltas.push(EntityDelta::Added {
            new: base_rust.clone(),
        });
        base_change.id = SemanticChangeId::from_hash(Hash256::from_bytes([0; 32]));
        base_change.id = compute_semantic_change_id(base_change).unwrap();
        let base_change_id = base_change.id;
        let base_target = RefTarget::change(base_change_id);
        initial.ref_mutations[0].new_target = Some(base_target.clone());
        let initial_workspace = initial.workspace_mutation.as_mut().unwrap();
        initial_workspace.new_base_target = Some(base_target.clone());
        initial_workspace.semantic_delta = WorkspaceSemanticDelta::new(
            vec![EntityDelta::Added {
                new: base_rust.clone(),
            }],
            Vec::new(),
        )
        .unwrap();
        manager.commit_repository_transaction(initial).unwrap();

        let current = manager.read_authority().metadata().workspaces[0].clone();
        assert!(current.semantic_overlay.is_empty());
        let tree_before = current.tree.clone();
        let next_rust = semantic_test_entity("src/lib.rs", "kin", LanguageId::Rust, 0x62);
        assert_eq!(next_rust.id, base_rust.id);
        let mut next_change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: vec![base_change_id],
            timestamp: Timestamp(
                chrono::DateTime::parse_from_rfc3339("2026-07-26T12:01:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            author: AuthorId::new("authority-test"),
            message: "advance the exact semantic base".to_string(),
            entity_deltas: vec![EntityDelta::Modified {
                old: base_rust.clone(),
                new: next_rust.clone(),
            }],
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        next_change.id = compute_semantic_change_id(&next_change).unwrap();
        let next_target = RefTarget::change(next_change.id);
        let main = RefName::branch(b"main").unwrap();
        let mutation = WorkspaceMutation {
            workspace_id: current.workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: current.generation,
                head: current.head.clone(),
                base_target: current.base_target.clone(),
                base_tree_hash: current.base_tree_hash,
                tree_hash: current.tree_hash,
                semantic_overlay_hash: current.semantic_overlay_hash,
                admission_policy: current.admission_policy,
            },
            new_generation: current.generation + 1,
            new_head: current.head,
            new_base_target: Some(next_target.clone()),
            new_base_tree_hash: current.base_tree_hash,
            tree_deltas: Vec::new(),
            new_tree_hash: current.tree_hash,
            semantic_delta: WorkspaceSemanticDelta::new(
                vec![EntityDelta::Modified {
                    old: base_rust,
                    new: next_rust.clone(),
                }],
                Vec::new(),
            )
            .unwrap(),
            new_shared_admission_policy: current.shared_admission_policy,
            new_admission_policy: current.admission_policy,
        };
        let mut transaction = transaction_shell(&manager, 0x5e02);
        transaction.changes.push(next_change);
        transaction.ref_mutations.push(RefMutation {
            name: main,
            expected: RefExpectation::MustEqual {
                target: base_target,
            },
            new_target: Some(next_target.clone()),
            policy: RefUpdatePolicy::FastForwardOnly,
        });
        transaction.workspace_mutation = Some(mutation);
        manager.commit_repository_transaction(transaction).unwrap();

        let advanced = manager.read_authority().metadata().workspaces[0].clone();
        assert_eq!(advanced.base_target, Some(next_target));
        assert_eq!(advanced.tree, tree_before);
        assert!(advanced.semantic_overlay.is_empty());
        assert!(!advanced.is_dirty());
        let prepared = manager
            .workspace_graph_snapshot(&repository_id(), &advanced.workspace_id)
            .unwrap()
            .expect("advanced workspace exists");
        assert_eq!(prepared.entities.get(&next_rust.id), Some(&next_rust));
        assert_eq!(prepared.resolved_tree, tree_before);

        let reopened =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let reopened_prepared = reopened
            .workspace_graph_snapshot(&repository_id(), &advanced.workspace_id)
            .unwrap()
            .expect("advanced workspace survives reopen");
        assert_eq!(
            reopened_prepared.entities.get(&next_rust.id),
            Some(&next_rust)
        );
        assert_eq!(reopened_prepared.resolved_tree, tree_before);
    }

    #[test]
    fn workspace_semantic_mutation_rejects_a_stale_old_entity_payload() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();

        let entity = semantic_test_entity("src/lib.rs", "kin", LanguageId::Rust, 0x51);
        manager
            .commit_repository_transaction(semantic_workspace_transaction(
                &manager,
                0x5e10,
                WorkspaceSemanticDelta::new(
                    vec![EntityDelta::Added {
                        new: entity.clone(),
                    }],
                    Vec::new(),
                )
                .unwrap(),
            ))
            .unwrap();

        let generation_before = manager.read_authority().generation();
        let workspace_before = manager.read_authority().metadata().workspaces[0].clone();
        let mut stale = entity.clone();
        stale.signature = "fn stale_kin()".to_string();
        let mut replacement = entity.clone();
        replacement.signature = "fn replacement_kin()".to_string();
        let transaction = semantic_workspace_transaction(
            &manager,
            0x5e11,
            WorkspaceSemanticDelta::new(
                vec![EntityDelta::Modified {
                    old: stale,
                    new: replacement,
                }],
                Vec::new(),
            )
            .unwrap(),
        );

        let error = manager
            .commit_repository_transaction(transaction)
            .expect_err("a stale semantic old payload must not acquire authority");
        assert!(
            error.to_string().contains("stale old payload for entity"),
            "unexpected stale-semantic error: {error}"
        );
        assert_eq!(manager.read_authority().generation(), generation_before);
        assert_eq!(
            manager.read_authority().metadata().workspaces[0],
            workspace_before
        );
        let prepared = manager
            .workspace_graph_snapshot(&repository_id(), &workspace_before.workspace_id)
            .unwrap()
            .expect("previous workspace remains authoritative");
        assert_eq!(prepared.entities.get(&entity.id), Some(&entity));
    }

    #[test]
    fn unborn_workspace_graph_snapshot_preserves_non_code_tree_without_fake_history() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let body = b"services:\n  api:\n    image: kin:dev\n";
        let body_hash = digest(body);
        manager.save_source_blob(body_hash, body).unwrap();
        let artifact_id = ArtifactId(Uuid::from_u128(0xb011));
        let tree_delta = TreeDelta::Added {
            artifact_id,
            new: LocatedEntry::new(
                RepoPath::from_utf8("compose.yaml").unwrap(),
                TreeEntry::blob(body_hash, false),
            ),
        };
        let tree = ResolvedTree::default()
            .apply(std::slice::from_ref(&tree_delta))
            .unwrap();
        let mut transaction = unborn_workspace_transaction(&manager, 0xb012, 0xb013, b"main");
        let workspace_mutation = transaction.workspace_mutation.as_mut().unwrap();
        workspace_mutation.tree_deltas = vec![tree_delta];
        workspace_mutation.new_tree_hash = compute_resolved_tree_hash(&tree).unwrap();
        let workspace_id = workspace_mutation.workspace_id;

        manager.commit_repository_transaction(transaction).unwrap();
        let prepared = manager
            .workspace_graph_snapshot(&repository_id(), &workspace_id)
            .unwrap()
            .expect("unborn workspace exists");
        assert!(prepared.repository_authority.is_none());
        assert!(prepared.changes.is_empty());
        assert!(prepared.entities.is_empty());
        assert_eq!(prepared.resolved_tree, tree);
        assert_eq!(
            prepared
                .resolved_tree
                .artifact_at_path(&RepoPath::from_utf8("compose.yaml").unwrap())
                .unwrap()
                .artifact_id,
            artifact_id
        );
        let authority = manager.read_authority();
        assert!(authority.snapshot().resolved_tree.is_empty());
        assert!(authority.snapshot().entities.is_empty());
    }

    #[test]
    fn caller_admission_claim_is_not_part_of_the_clean_slate_transaction_contract() {
        let manager = initial_manager(Arc::new(MemoryBackend::default()));
        let transaction = arbitrary_repository_transaction(&manager);
        let mut encoded = serde_json::to_value(transaction).unwrap();
        encoded.as_object_mut().unwrap().insert(
            "admission_scan_token".to_string(),
            serde_json::json!({"caller_claimed_safe": true}),
        );

        let error = serde_json::from_value::<RepositoryTransaction>(encoded)
            .expect_err("caller admission claims must be rejected as unknown authority input");
        assert!(
            error.to_string().contains("unknown field"),
            "unexpected forged-claim error: {error}"
        );
    }

    #[test]
    fn authority_rejects_ignored_and_sensitive_native_additions_atomically() {
        let ignored_manager = initial_manager(Arc::new(MemoryBackend::default()));
        let ignored = native_root_with_policy(
            &ignored_manager,
            AdmissionCase::Sensitive,
            "build/output.bin",
            b"harmless output\n",
            Some(b"build/\n"),
            false,
        );
        let error = ignored_manager
            .commit_repository_transaction(ignored)
            .expect_err("an ignored Native addition must not acquire authority");
        assert!(
            error
                .to_string()
                .contains("excluded by the exact graph-owned admission policy"),
            "unexpected ignored-addition error: {error}"
        );
        assert_eq!(ignored_manager.read_authority().generation(), 0);

        let sensitive_manager = initial_manager(Arc::new(MemoryBackend::default()));
        let sensitive = native_root_with_policy(
            &sensitive_manager,
            AdmissionCase::Sensitive,
            ".env",
            b"TOKEN=supersecret123\n",
            None,
            false,
        );
        let error = sensitive_manager
            .commit_repository_transaction(sensitive)
            .expect_err("an unapproved sensitive Native addition must not acquire authority");
        assert!(
            error.to_string().contains("untracked sensitive content"),
            "unexpected sensitive-addition error: {error}"
        );
        assert_eq!(sensitive_manager.read_authority().generation(), 0);
    }

    #[test]
    fn authority_uses_the_frozen_case_behavior_for_ignore_matching() {
        let sensitive_manager = initial_manager(Arc::new(MemoryBackend::default()));
        let case_sensitive = native_root_with_policy(
            &sensitive_manager,
            AdmissionCase::Sensitive,
            "secrets/value.txt",
            b"harmless\n",
            Some(b"SECRETS/\n"),
            false,
        );
        sensitive_manager
            .commit_repository_transaction(case_sensitive)
            .unwrap();

        let folded_manager = initial_manager(Arc::new(MemoryBackend::default()));
        let folded = native_root_with_policy(
            &folded_manager,
            AdmissionCase::FoldAscii,
            "secrets/value.txt",
            b"harmless\n",
            Some(b"SECRETS/\n"),
            false,
        );
        let error = folded_manager
            .commit_repository_transaction(folded)
            .expect_err("ASCII-folded matching must reject the case alias");
        assert!(
            error
                .to_string()
                .contains("excluded by the exact graph-owned admission policy"),
            "unexpected folded-case error: {error}"
        );
        assert_eq!(folded_manager.read_authority().generation(), 0);
    }

    #[test]
    fn workspace_admission_snapshot_is_one_exact_reopenable_case_frozen_lease() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let transaction = native_root_with_policy(
            &manager,
            AdmissionCase::Sensitive,
            "src/main.rs",
            b"fn main() {}\n",
            Some(b"SECRETS/*\n"),
            false,
        );
        let workspace_id = transaction
            .workspace_mutation
            .as_ref()
            .unwrap()
            .workspace_id;
        manager.commit_repository_transaction(transaction).unwrap();

        assert!(
            manager
                .workspace_admission_snapshot(
                    &repository_id(),
                    &WorkspaceId::from_uuid(Uuid::from_u128(0xdead)),
                )
                .unwrap()
                .is_none(),
            "an absent workspace must remain explicitly absent"
        );

        let lease = manager.read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == workspace_id)
            .unwrap();
        let expected_binding = workspace.snapshot_binding(lease.roots().clone()).unwrap();
        drop(lease);

        let prepared = manager
            .workspace_admission_snapshot(&repository_id(), &workspace_id)
            .unwrap()
            .expect("workspace admission authority exists");
        assert_eq!(prepared.binding, expected_binding);
        assert_eq!(
            prepared.binding.admission_policy,
            expected_binding.admission_policy
        );
        assert_eq!(prepared.case, AdmissionCase::Sensitive);
        assert!(
            prepared
                .matcher
                .decide(
                    &RepoPath::from_utf8("secrets/value.txt").unwrap(),
                    false,
                    false,
                )
                .admitted,
            "the frozen sensitive matcher must not fold ASCII case"
        );
        assert!(
            prepared
                .matcher
                .decide(
                    &RepoPath::from_utf8("SECRETS/value.txt").unwrap(),
                    false,
                    false,
                )
                .is_ignored(),
            "the exact frozen pattern must remain active"
        );

        let reopened = RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend))
            .expect("persisted authority reopens");
        let reopened_prepared = reopened
            .workspace_admission_snapshot(&repository_id(), &workspace_id)
            .unwrap()
            .expect("reopened workspace admission authority exists");
        assert_eq!(reopened_prepared.binding, prepared.binding);
        assert_eq!(reopened_prepared.case, prepared.case);
        assert_eq!(
            reopened_prepared.matcher.generation(),
            prepared.matcher.generation()
        );
        assert_eq!(
            reopened_prepared
                .matcher
                .decide(
                    &RepoPath::from_utf8("secrets/value.txt").unwrap(),
                    false,
                    false,
                )
                .admitted,
            prepared
                .matcher
                .decide(
                    &RepoPath::from_utf8("secrets/value.txt").unwrap(),
                    false,
                    false,
                )
                .admitted
        );

        let folded_manager = initial_manager(Arc::new(MemoryBackend::default()));
        let folded = native_root_with_policy(
            &folded_manager,
            AdmissionCase::FoldAscii,
            "src/main.rs",
            b"fn main() {}\n",
            Some(b"SECRETS/*\n"),
            false,
        );
        let folded_workspace = folded.workspace_mutation.as_ref().unwrap().workspace_id;
        folded_manager
            .commit_repository_transaction(folded)
            .unwrap();
        let folded_prepared = folded_manager
            .workspace_admission_snapshot(&repository_id(), &folded_workspace)
            .unwrap()
            .expect("folded workspace admission authority exists");
        assert_eq!(folded_prepared.case, AdmissionCase::FoldAscii);
        assert!(
            folded_prepared
                .matcher
                .decide(
                    &RepoPath::from_utf8("secrets/value.txt").unwrap(),
                    false,
                    false,
                )
                .is_ignored(),
            "the frozen folded matcher must preserve ASCII-folded behavior"
        );
    }

    #[test]
    fn workspace_admission_snapshot_preserves_global_shared_and_kin_local_precedence() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let shared_body = b"!global/keep.txt\nshared/*\n";
        let mut transaction = native_root_with_policy(
            &manager,
            AdmissionCase::Sensitive,
            "src/main.rs",
            b"fn main() {}\n",
            Some(shared_body),
            false,
        );
        let workspace_id = transaction
            .workspace_mutation
            .as_ref()
            .unwrap()
            .workspace_id;
        let global_body = b"global/*\n";
        let kin_local_body = b"!shared/keep.txt\nhigh/*\n";
        let global_hash = digest(global_body);
        let kin_local_hash = digest(kin_local_body);
        manager.save_source_blob(global_hash, global_body).unwrap();
        manager
            .save_source_blob(kin_local_hash, kin_local_body)
            .unwrap();
        let overlay = FrozenLocalOverlay::new(
            workspace_id,
            0,
            AdmissionCase::Sensitive,
            vec![
                LocalAdmissionRuleSource {
                    kind: LocalAdmissionRuleSourceKind::GitGlobalExclude,
                    body_hash: global_hash,
                    body_len: global_body.len() as u64,
                    precedence: 0,
                },
                LocalAdmissionRuleSource {
                    kind: LocalAdmissionRuleSourceKind::KinLocal,
                    body_hash: kin_local_hash,
                    body_len: kin_local_body.len() as u64,
                    precedence: 1,
                },
            ],
        )
        .unwrap();
        transaction
            .workspace_mutation
            .as_mut()
            .unwrap()
            .new_admission_policy
            .local = overlay.stamp();
        transaction.local_overlay_delta = Some(FrozenLocalOverlayDelta::initialize(overlay));
        manager.commit_repository_transaction(transaction).unwrap();

        let prepared = manager
            .workspace_admission_snapshot(&repository_id(), &workspace_id)
            .unwrap()
            .expect("workspace admission authority exists");
        let decide = |path: &str| {
            prepared
                .matcher
                .decide(&RepoPath::from_utf8(path).unwrap(), false, false)
        };

        let global_drop = decide("global/drop.txt");
        assert!(global_drop.is_ignored());
        assert!(matches!(
            global_drop.reason,
            crate::admission::AdmissionDecisionReason::Rule(
                crate::admission::AdmissionRuleProvenance {
                    source: ResolvedAdmissionRuleSource::GlobalExclude,
                    ..
                }
            )
        ));

        let shared_override = decide("global/keep.txt");
        assert!(shared_override.admitted);
        assert!(matches!(
            shared_override.reason,
            crate::admission::AdmissionDecisionReason::Rule(
                crate::admission::AdmissionRuleProvenance {
                    source: ResolvedAdmissionRuleSource::Shared { .. },
                    ..
                }
            )
        ));

        let shared_drop = decide("shared/drop.txt");
        assert!(shared_drop.is_ignored());
        assert!(matches!(
            shared_drop.reason,
            crate::admission::AdmissionDecisionReason::Rule(
                crate::admission::AdmissionRuleProvenance {
                    source: ResolvedAdmissionRuleSource::Shared { .. },
                    ..
                }
            )
        ));

        let kin_override = decide("shared/keep.txt");
        assert!(kin_override.admitted);
        assert!(matches!(
            kin_override.reason,
            crate::admission::AdmissionDecisionReason::Rule(
                crate::admission::AdmissionRuleProvenance {
                    source: ResolvedAdmissionRuleSource::KinLocal { ordinal: 1 },
                    ..
                }
            )
        ));

        let kin_drop = decide("high/drop.txt");
        assert!(kin_drop.is_ignored());
        assert!(matches!(
            kin_drop.reason,
            crate::admission::AdmissionDecisionReason::Rule(
                crate::admission::AdmissionRuleProvenance {
                    source: ResolvedAdmissionRuleSource::KinLocal { ordinal: 1 },
                    ..
                }
            )
        ));
    }

    #[test]
    fn workspace_admission_snapshot_fails_closed_on_missing_tampered_or_wrong_length_cas() {
        fn committed_policy_fixture() -> (
            Arc<MemoryBackend>,
            RepositoryAuthorityManager<MemoryBackend>,
            WorkspaceId,
            Hash256,
        ) {
            let backend = Arc::new(MemoryBackend::default());
            let manager = initial_manager(Arc::clone(&backend));
            let transaction = native_root_with_policy(
                &manager,
                AdmissionCase::Sensitive,
                "src/main.rs",
                b"fn main() {}\n",
                Some(b"target/\n"),
                false,
            );
            let workspace = transaction
                .workspace_mutation
                .as_ref()
                .unwrap()
                .workspace_id;
            let body_hash = transaction
                .workspace_mutation
                .as_ref()
                .unwrap()
                .new_shared_admission_policy
                .sources[0]
                .body_hash;
            manager.commit_repository_transaction(transaction).unwrap();
            (backend, manager, workspace, body_hash)
        }

        let (missing_backend, missing_manager, missing_workspace, missing_hash) =
            committed_policy_fixture();
        missing_backend.blobs.lock().remove(missing_hash.as_bytes());
        let error = missing_manager
            .workspace_admission_snapshot(&repository_id(), &missing_workspace)
            .expect_err("missing policy CAS bytes must fail closed at the read API");
        assert!(
            error
                .to_string()
                .contains("absent from immutable source CAS"),
            "unexpected missing policy error: {error}"
        );

        let (tampered_backend, tampered_manager, tampered_workspace, tampered_hash) =
            committed_policy_fixture();
        tampered_backend
            .blobs
            .lock()
            .insert(*tampered_hash.as_bytes(), b"tamper!\n".to_vec());
        let error = tampered_manager
            .workspace_admission_snapshot(&repository_id(), &tampered_workspace)
            .expect_err("same-length tampered policy CAS bytes must fail closed");
        assert!(
            error.to_string().contains("digest mismatch"),
            "unexpected tampered policy error: {error}"
        );

        let (short_backend, short_manager, short_workspace, short_hash) =
            committed_policy_fixture();
        short_backend
            .blobs
            .lock()
            .insert(*short_hash.as_bytes(), b"x".to_vec());
        let error = short_manager
            .workspace_admission_snapshot(&repository_id(), &short_workspace)
            .expect_err("wrong-length policy CAS bytes must fail closed");
        assert!(
            error.to_string().contains("has length 1, expected 8"),
            "unexpected wrong-length policy error: {error}"
        );
    }

    #[test]
    fn workspace_admission_snapshot_cannot_mix_authority_generations_during_cas_load() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = Arc::new(initial_manager(Arc::clone(&backend)));
        let transaction = native_root_with_policy(
            manager.as_ref(),
            AdmissionCase::Sensitive,
            "src/main.rs",
            b"fn main() {}\n",
            Some(b"SECRETS/*\n"),
            false,
        );
        let workspace_id = transaction
            .workspace_mutation
            .as_ref()
            .unwrap()
            .workspace_id;
        manager.commit_repository_transaction(transaction).unwrap();

        let old_lease = manager.read_authority();
        let old_workspace = old_lease.metadata().workspaces[0].clone();
        let old_binding = old_workspace
            .snapshot_binding(old_lease.roots().clone())
            .unwrap();
        let old_repository_generation = old_lease.generation();
        drop(old_lease);
        let refresh =
            refresh_workspace_admission_case(manager.as_ref(), 0xad10, AdmissionCase::FoldAscii);
        let hook_manager = Arc::clone(&manager);
        *backend.source_load_hook.lock() = Some(Box::new(move || {
            hook_manager
                .commit_repository_transaction(refresh)
                .expect("concurrent local-overlay refresh commits");
        }));

        let raced = manager
            .workspace_admission_snapshot(&repository_id(), &workspace_id)
            .unwrap()
            .expect("old leased workspace remains resolvable");
        assert_eq!(raced.binding, old_binding);
        assert_eq!(raced.case, AdmissionCase::Sensitive);
        assert!(
            raced
                .matcher
                .decide(
                    &RepoPath::from_utf8("secrets/value.txt").unwrap(),
                    false,
                    false,
                )
                .admitted,
            "the old binding must carry the old case and old matcher together"
        );

        let current = manager.read_authority();
        assert!(current.generation() > old_repository_generation);
        assert!(
            current.metadata().workspaces[0].generation > old_workspace.generation,
            "the hook must actually advance workspace authority"
        );
        drop(current);
        let refreshed = manager
            .workspace_admission_snapshot(&repository_id(), &workspace_id)
            .unwrap()
            .expect("refreshed workspace admission authority exists");
        assert_eq!(refreshed.case, AdmissionCase::FoldAscii);
        assert_ne!(refreshed.binding, old_binding);
        assert!(
            refreshed
                .matcher
                .decide(
                    &RepoPath::from_utf8("secrets/value.txt").unwrap(),
                    false,
                    false,
                )
                .is_ignored(),
            "a subsequent lease must see the complete refreshed matcher"
        );
    }

    #[test]
    fn tracked_sensitive_artifact_remains_admitted_without_a_new_allowance() {
        let manager = initial_manager(Arc::new(MemoryBackend::default()));
        let initial = native_root_with_policy(
            &manager,
            AdmissionCase::Sensitive,
            ".env",
            b"TOKEN=initial-secret\n",
            None,
            true,
        );
        manager.commit_repository_transaction(initial).unwrap();

        let current = manager.read_authority().metadata().workspaces[0].clone();
        let path = RepoPath::from_utf8(".env").unwrap();
        let artifact = current.tree.artifact_at_path(&path).unwrap();
        let next_body = b"TOKEN=rotated-secret\n";
        let next_hash = digest(next_body);
        manager.save_source_blob(next_hash, next_body).unwrap();
        let delta = TreeDelta::Updated {
            artifact_id: artifact.artifact_id,
            old: artifact.located_entry(),
            new: LocatedEntry::new(path, TreeEntry::blob(next_hash, false)),
        };
        let next_tree = current.tree.apply(std::slice::from_ref(&delta)).unwrap();
        let next_policy = SharedAdmissionPolicy::new(1, Vec::new(), Vec::new()).unwrap();
        let next_effective = EffectiveAdmissionPolicyStamp {
            shared: next_policy.stamp(),
            local: current.admission_policy.local,
        };
        let mutation = WorkspaceMutation {
            workspace_id: current.workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: current.generation,
                head: current.head.clone(),
                base_target: current.base_target.clone(),
                base_tree_hash: current.base_tree_hash,
                tree_hash: current.tree_hash,
                semantic_overlay_hash: current.semantic_overlay_hash,
                admission_policy: current.admission_policy,
            },
            new_generation: current.generation + 1,
            new_head: current.head.clone(),
            new_base_target: current.base_target.clone(),
            new_base_tree_hash: current.base_tree_hash,
            tree_deltas: vec![delta],
            new_tree_hash: compute_resolved_tree_hash(&next_tree).unwrap(),
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: next_policy,
            new_admission_policy: next_effective,
        };
        let mut transaction = transaction_shell(&manager, 0xad01);
        transaction.workspace_mutation = Some(mutation);
        manager.commit_repository_transaction(transaction).unwrap();

        let retained = manager.read_authority().metadata().workspaces[0]
            .tree
            .artifact_at_path(&RepoPath::from_utf8(".env").unwrap())
            .unwrap()
            .entry;
        assert_eq!(retained, TreeEntry::blob(next_hash, false));
    }

    #[test]
    fn admission_policy_bodies_must_be_present_and_digest_exact() {
        let missing_backend = Arc::new(MemoryBackend::default());
        let missing_manager = initial_manager(Arc::clone(&missing_backend));
        let missing = native_root_with_policy(
            &missing_manager,
            AdmissionCase::Sensitive,
            "src/main.rs",
            b"fn main() {}\n",
            Some(b"target/\n"),
            false,
        );
        let policy_hash = missing
            .workspace_mutation
            .as_ref()
            .unwrap()
            .new_shared_admission_policy
            .sources[0]
            .body_hash;
        missing_backend.blobs.lock().remove(policy_hash.as_bytes());
        let error = missing_manager
            .commit_repository_transaction(missing)
            .expect_err("missing matcher bytes must fail closed");
        assert!(
            error
                .to_string()
                .contains("absent from immutable source CAS"),
            "unexpected missing-policy error: {error}"
        );
        assert_eq!(missing_manager.read_authority().generation(), 0);

        let tampered_backend = Arc::new(MemoryBackend::default());
        let tampered_manager = initial_manager(Arc::clone(&tampered_backend));
        let tampered = native_root_with_policy(
            &tampered_manager,
            AdmissionCase::Sensitive,
            "src/main.rs",
            b"fn main() {}\n",
            Some(b"target/\n"),
            false,
        );
        let policy_hash = tampered
            .workspace_mutation
            .as_ref()
            .unwrap()
            .new_shared_admission_policy
            .sources[0]
            .body_hash;
        tampered_backend
            .blobs
            .lock()
            .insert(*policy_hash.as_bytes(), b"tamper!\n".to_vec());
        let error = tampered_manager
            .commit_repository_transaction(tampered)
            .expect_err("tampered matcher bytes must fail closed");
        assert!(
            error.to_string().contains("digest mismatch"),
            "unexpected tampered-policy error: {error}"
        );
        assert_eq!(tampered_manager.read_authority().generation(), 0);
    }

    #[test]
    fn raw_external_objects_cannot_self_authorize_a_native_gitlink() {
        let manager = initial_manager(Arc::new(MemoryBackend::default()));
        let fixture = git_authority_transaction_fixture(&manager, 0xad00);
        let raw_commit_target = fixture.head.object.oid;
        let mut transaction = arbitrary_repository_transaction(&manager);
        transaction.external_objects = fixture.transaction.external_objects;
        let gitlink = TreeDelta::Added {
            artifact_id: ArtifactId(Uuid::from_u128(17)),
            new: LocatedEntry::new(
                RepoPath::from_utf8("vendor/semantic-runtime").unwrap(),
                TreeEntry::gitlink(raw_commit_target),
            ),
        };
        let change = transaction.changes.first_mut().unwrap();
        change.tree_deltas.push(gitlink);
        change.id = SemanticChangeId::from_hash(Hash256::from_bytes([0; 32]));
        change.id = compute_semantic_change_id(change).unwrap();
        let change_id = change.id;
        let tree_deltas = change.tree_deltas.clone();
        let tree = ResolvedTree::default().apply(&tree_deltas).unwrap();
        let tree_hash = compute_resolved_tree_hash(&tree).unwrap();
        let workspace = transaction.workspace_mutation.as_mut().unwrap();
        workspace.new_base_target = Some(RefTarget::change(change_id));
        workspace.new_base_tree_hash = Some(tree_hash);
        workspace.tree_deltas = tree_deltas;
        workspace.new_tree_hash = tree_hash;
        transaction.ref_mutations[0].new_target = Some(RefTarget::change(change_id));

        let error = manager
            .commit_repository_transaction(transaction)
            .expect_err("raw external-object records are not Gitlink authority");
        assert!(
            error
                .to_string()
                .contains("without verified Git external authority"),
            "unexpected Native gitlink error: {error}"
        );
        assert_eq!(manager.read_authority().generation(), 0);
    }

    #[test]
    fn artifact_mtime_changes_only_on_touch_and_advances_within_one_second() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();

        let before_workspace = manager.read_authority().metadata().workspaces[0].clone();
        let before = manager
            .workspace_tree_snapshot(&repository_id(), &before_workspace.workspace_id)
            .unwrap()
            .unwrap();
        let compose_before = before
            .artifacts
            .iter()
            .find(|artifact| artifact.path.as_bytes() == b"compose.yaml")
            .unwrap();
        let binary_before = before
            .artifacts
            .iter()
            .find(|artifact| artifact.path.as_bytes() == b"assets/data-\xff.bin")
            .unwrap();
        let compose_mtime = compose_before.mtime;
        let binary_mtime = binary_before.mtime;
        let compose_size = compose_before.size;

        let compose_path = RepoPath::from_utf8("compose.yaml").unwrap();
        let old = before_workspace
            .tree
            .artifact_at_path(&compose_path)
            .unwrap();
        let new_body = b"services:\n  api:\n    build: x\n";
        assert_eq!(new_body.len() as u64, compose_size);
        let new_hash = digest(new_body);
        manager.save_source_blob(new_hash, new_body).unwrap();
        let tree_delta = TreeDelta::Updated {
            artifact_id: old.artifact_id,
            old: old.located_entry(),
            new: LocatedEntry::new(compose_path, TreeEntry::blob(new_hash, false)),
        };
        let next_tree = before_workspace
            .tree
            .apply(std::slice::from_ref(&tree_delta))
            .unwrap();
        let next_tree_hash = compute_resolved_tree_hash(&next_tree).unwrap();
        let mutation = WorkspaceMutation {
            workspace_id: before_workspace.workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: before_workspace.generation,
                head: before_workspace.head.clone(),
                base_target: before_workspace.base_target.clone(),
                base_tree_hash: before_workspace.base_tree_hash,
                tree_hash: before_workspace.tree_hash,
                semantic_overlay_hash: before_workspace.semantic_overlay_hash,
                admission_policy: before_workspace.admission_policy,
            },
            new_generation: before_workspace.generation + 1,
            new_head: before_workspace.head.clone(),
            new_base_target: before_workspace.base_target.clone(),
            new_base_tree_hash: before_workspace.base_tree_hash,
            tree_deltas: vec![tree_delta],
            new_tree_hash: next_tree_hash,
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: before_workspace.shared_admission_policy.clone(),
            new_admission_policy: before_workspace.admission_policy,
        };
        let mut transaction = transaction_shell(&manager, 0xa11);
        transaction.workspace_mutation = Some(mutation);
        manager.commit_repository_transaction(transaction).unwrap();

        let after = manager
            .workspace_tree_snapshot(&repository_id(), &before_workspace.workspace_id)
            .unwrap()
            .unwrap();
        let compose_after = after
            .artifacts
            .iter()
            .find(|artifact| artifact.path.as_bytes() == b"compose.yaml")
            .unwrap();
        let binary_after = after
            .artifacts
            .iter()
            .find(|artifact| artifact.path.as_bytes() == b"assets/data-\xff.bin")
            .unwrap();
        assert_eq!(compose_after.size, compose_size);
        assert!(
            compose_after.mtime > compose_mtime,
            "same-size edits must advance the artifact stat tuple even within one wall-clock second"
        );
        assert_eq!(
            binary_after.mtime, binary_mtime,
            "untouched arbitrary binary must retain its durable artifact mtime"
        );

        let reopened =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let reopened_projection = reopened
            .workspace_tree_snapshot(&repository_id(), &before_workspace.workspace_id)
            .unwrap()
            .unwrap();
        assert_eq!(reopened_projection, after);
    }

    #[test]
    fn ref_advance_preserves_each_workspace_pinned_baseline() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();

        let before = manager.read_authority();
        let workspace_before = before.metadata().workspaces[0].clone();
        let main = RefName::branch(b"main").unwrap();
        let old_target = before.metadata().ref_state.refs[0].target.clone();
        let old_change = target_change_id(before.metadata(), &old_target).unwrap();
        drop(before);

        let mut next_change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: vec![old_change],
            timestamp: Timestamp::now(),
            author: AuthorId::new("authority-test"),
            message: "advance the shared ref without rewriting workspace state".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        next_change.id = compute_semantic_change_id(&next_change).unwrap();
        let new_target = RefTarget::change(next_change.id);
        let mut transaction = transaction_shell(&manager, 0xbeef);
        transaction.changes.push(next_change);
        transaction.ref_mutations.push(RefMutation {
            name: main,
            expected: RefExpectation::MustEqual { target: old_target },
            new_target: Some(new_target.clone()),
            policy: RefUpdatePolicy::FastForwardOnly,
        });

        manager.commit_repository_transaction(transaction).unwrap();

        let after = manager.read_authority();
        assert_eq!(after.metadata().ref_state.refs[0].target, new_target);
        assert_eq!(after.metadata().workspaces[0], workspace_before);
        drop(after);
        let reopened =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        assert_eq!(
            reopened.read_authority().metadata().workspaces[0],
            workspace_before
        );
    }

    #[test]
    fn empty_unborn_workspace_is_self_contained_authority() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let transaction = unborn_workspace_transaction(&manager, 22, 23, b"unborn");

        manager.commit_repository_transaction(transaction).unwrap();

        let workspace = manager.read_authority().metadata().workspaces[0].clone();
        assert!(workspace.base_target.is_none());
        assert!(workspace.base_tree_hash.is_none());
        assert!(workspace.tree.is_empty());
        assert_eq!(
            workspace.shared_admission_policy,
            SharedAdmissionPolicy::empty(0)
        );
        assert_eq!(
            workspace.shared_admission_policy.stamp(),
            workspace.admission_policy.shared
        );

        let reopened =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        assert_eq!(
            reopened.read_authority().metadata().workspaces[0],
            workspace
        );
    }

    #[test]
    fn complete_authority_body_validation_loads_each_distinct_digest_once() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let (transaction, _, _) = imported_repository_transaction(&manager);
        manager.commit_repository_transaction(transaction).unwrap();

        let lease = manager.read_authority();
        let requirements = collect_all_authority_body_requirements(lease.snapshot()).unwrap();
        assert_eq!(
            requirements.len(),
            7,
            "the fixture has seven distinct Git bodies despite repeated authority references"
        );
        let metadata = lease.metadata();
        let repeated_record_references = metadata.external_objects.len()
            + metadata
                .git_external_authority
                .as_ref()
                .unwrap()
                .closure
                .objects
                .len();
        assert!(
            repeated_record_references > requirements.len(),
            "the fixture must exercise global de-duplication across authority surfaces"
        );

        backend.source_load_count.store(0, Ordering::SeqCst);
        validate_all_authority_bodies(backend.as_ref(), &repository_id(), lease.snapshot())
            .unwrap();
        assert_eq!(
            backend.source_load_count.load(Ordering::SeqCst),
            requirements.len(),
            "complete validation must perform one backend read per distinct content identity"
        );
    }

    #[test]
    fn verified_authority_body_batch_preserves_digest_tamper_refusal() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let (transaction, _, _) = imported_repository_transaction(&manager);
        manager.commit_repository_transaction(transaction).unwrap();

        let lease = manager.read_authority();
        let digest = *collect_all_authority_body_requirements(lease.snapshot())
            .unwrap()
            .keys()
            .next()
            .expect("the imported fixture has immutable bodies")
            .as_bytes();
        backend
            .blobs
            .lock()
            .get_mut(&digest)
            .expect("the body was persisted")[0] ^= 0x01;

        let error =
            validate_all_authority_bodies(backend.as_ref(), &repository_id(), lease.snapshot())
                .expect_err("a batch backend must not promote bytes with the wrong digest");
        assert!(
            error.to_string().contains("digest mismatch"),
            "unexpected tampered-batch error: {error}"
        );
    }

    #[test]
    fn authority_body_validation_requires_backend_to_invoke_batch_once() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let (transaction, _, _) = imported_repository_transaction(&manager);
        manager.commit_repository_transaction(transaction).unwrap();
        let lease = manager.read_authority();

        backend.verified_batch_behavior.store(1, Ordering::SeqCst);
        let error =
            validate_all_authority_bodies(backend.as_ref(), &repository_id(), lease.snapshot())
                .expect_err("a backend cannot omit the validation callback");
        assert!(
            error.to_string().contains("0 times; expected exactly once"),
            "unexpected omitted-callback error: {error}"
        );

        backend.verified_batch_behavior.store(3, Ordering::SeqCst);
        let error =
            validate_all_authority_bodies(backend.as_ref(), &repository_id(), lease.snapshot())
                .expect_err("a backend cannot invoke the validation callback twice");
        assert!(
            error.to_string().contains("more than once")
                || error.to_string().contains("2 times; expected exactly once"),
            "unexpected repeated-callback error: {error}"
        );
    }

    #[test]
    fn authority_body_validation_refuses_swallowed_backend_error() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let (transaction, _, _) = imported_repository_transaction(&manager);
        manager.commit_repository_transaction(transaction).unwrap();
        let lease = manager.read_authority();
        let digest = *collect_all_authority_body_requirements(lease.snapshot())
            .unwrap()
            .keys()
            .next()
            .expect("the imported fixture has immutable bodies")
            .as_bytes();
        backend
            .blobs
            .lock()
            .get_mut(&digest)
            .expect("the body was persisted")[0] ^= 0x01;
        backend.verified_batch_behavior.store(2, Ordering::SeqCst);

        let error =
            validate_all_authority_bodies(backend.as_ref(), &repository_id(), lease.snapshot())
                .expect_err("a backend cannot swallow validation failure");
        assert!(
            error
                .to_string()
                .contains("returned success after authority body validation failed"),
            "unexpected swallowed-error result: {error}"
        );
    }

    #[test]
    fn authority_body_collection_rejects_conflicting_exact_lengths() {
        let digest = digest(b"one immutable body");
        let mut requirements = BTreeMap::new();
        require_authority_body(&mut requirements, digest, Some(18), "first authority").unwrap();

        let error =
            require_authority_body(&mut requirements, digest, Some(19), "conflicting authority")
                .expect_err("one content identity cannot carry two exact lengths");
        assert!(
            error.to_string().contains("both length 18") && error.to_string().contains("length 19"),
            "unexpected conflicting-length error: {error}"
        );
    }

    #[test]
    fn clean_workspace_requires_the_exact_policy_at_its_external_base_alias() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(backend);
        let (mut transaction, _, _) = imported_repository_transaction(&manager);
        let unrelated = SharedAdmissionPolicy::empty(1);
        let workspace = transaction.workspace_mutation.as_mut().unwrap();
        workspace.new_shared_admission_policy = unrelated.clone();
        workspace.new_admission_policy.shared = unrelated.stamp();
        let error = manager
            .commit_repository_transaction(transaction)
            .expect_err("clean policy drift must not acquire repository authority");
        assert!(
            error
                .to_string()
                .contains("shared admission policy does not equal base change"),
            "unexpected clean-policy error: {error}"
        );
        assert_eq!(manager.read_authority().generation(), 0);
    }

    #[test]
    fn clean_workspace_fails_closed_when_base_history_has_no_policy() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(backend);
        let (mut transaction, _, _) = imported_repository_transaction(&manager);
        transaction.changes[0].admission_policy_delta = None;
        transaction.changes[0].id = compute_semantic_change_id(&transaction.changes[0]).unwrap();
        transaction.aliases[0].change_id = transaction.changes[0].id;

        let error = manager
            .commit_repository_transaction(transaction)
            .expect_err("policy-free imported history must not back a clean workspace");
        assert!(
            error
                .to_string()
                .contains("without resolved shared admission policy"),
            "unexpected missing-policy error: {error}"
        );
        assert_eq!(manager.read_authority().generation(), 0);
    }

    #[test]
    fn repository_manager_accepts_a_daemon_owned_backend_trait_object() {
        let backend: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::default());
        let manager = RepositoryAuthorityManager::open(repository_id(), backend).unwrap();

        assert_eq!(manager.read_authority().generation(), 0);
    }

    #[test]
    fn dirty_workspace_policy_can_diverge_from_its_base_history() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();

        let current = manager.read_authority().metadata().workspaces[0].clone();
        let ignore_body = b"target/\n";
        let ignore_hash = digest(ignore_body);
        manager.save_source_blob(ignore_hash, ignore_body).unwrap();
        let dirty_policy = SharedAdmissionPolicy::new(
            1,
            vec![AdmissionRuleSource {
                kind: AdmissionRuleSourceKind::GitIgnore,
                path: RepoPath::from_utf8(".gitignore").unwrap(),
                base_directory: None,
                body_hash: ignore_hash,
                body_len: ignore_body.len() as u64,
                precedence: 0,
            }],
            Vec::new(),
        )
        .unwrap();
        let tree_delta = TreeDelta::Added {
            artifact_id: ArtifactId(Uuid::from_u128(24)),
            new: LocatedEntry::new(
                RepoPath::from_utf8(".gitignore").unwrap(),
                TreeEntry::blob(ignore_hash, false),
            ),
        };
        let tree = current
            .tree
            .apply(std::slice::from_ref(&tree_delta))
            .unwrap();
        let tree_hash = compute_resolved_tree_hash(&tree).unwrap();
        let effective = EffectiveAdmissionPolicyStamp {
            shared: dirty_policy.stamp(),
            local: current.admission_policy.local,
        };
        let mutation = WorkspaceMutation {
            workspace_id: current.workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: current.generation,
                head: current.head.clone(),
                base_target: current.base_target.clone(),
                base_tree_hash: current.base_tree_hash,
                tree_hash: current.tree_hash,
                semantic_overlay_hash: current.semantic_overlay_hash,
                admission_policy: current.admission_policy,
            },
            new_generation: current.generation + 1,
            new_head: current.head.clone(),
            new_base_target: current.base_target.clone(),
            new_base_tree_hash: current.base_tree_hash,
            tree_deltas: vec![tree_delta],
            new_tree_hash: tree_hash,
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: dirty_policy.clone(),
            new_admission_policy: effective,
        };
        let mut transaction = transaction_shell(&manager, 25);
        transaction.workspace_mutation = Some(mutation);

        manager.commit_repository_transaction(transaction).unwrap();

        let lease = manager.read_authority();
        let dirty = &lease.metadata().workspaces[0];
        assert_eq!(dirty.shared_admission_policy, dirty_policy);
        assert_ne!(
            dirty.shared_admission_policy.stamp(),
            lease.metadata().admission_policies[0]
                .policy
                .as_ref()
                .unwrap()
                .stamp()
        );
        assert_eq!(dirty.base_target, current.base_target);
        assert_ne!(dirty.tree_hash, dirty.base_tree_hash.unwrap());

        let reopened =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        assert_eq!(
            reopened.read_authority().metadata().workspaces[0].shared_admission_policy,
            dirty_policy
        );
    }

    #[test]
    fn semantic_fast_forward_crosses_imported_aliases_but_not_unauthorized_objects() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(backend);
        let (import, imported_id, imported_target) = imported_repository_transaction(&manager);
        manager.commit_repository_transaction(import).unwrap();

        let mut native = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: vec![imported_id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("authority-test"),
            message: "first native change after Git import".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        native.id = compute_semantic_change_id(&native).unwrap();
        let native_id = native.id;
        let native_target = RefTarget::change(native_id);
        let mut to_native = transaction_shell(&manager, 0xf001);
        to_native.changes.push(native);
        to_native.ref_mutations.push(RefMutation {
            name: RefName::branch(b"main").unwrap(),
            expected: RefExpectation::MustEqual {
                target: imported_target,
            },
            new_target: Some(native_target.clone()),
            policy: RefUpdatePolicy::FastForwardOnly,
        });
        manager.commit_repository_transaction(to_native).unwrap();
        let stable_generation = manager.read_authority().generation();

        let unaliased_body = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor Kin <kin@example.com> 0 +0000\ncommitter Kin <kin@example.com> 0 +0000\n\nunaliased\n".to_vec();
        let unaliased_oid = GitObjectId::sha1(
            hex::decode("0716f7a55699d073f01fbe064e25c6b026c82577")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let unaliased_record = ExternalObjectRecord::from_raw(
            ExternalObjectKind::Commit,
            unaliased_oid,
            &unaliased_body,
        )
        .unwrap();
        manager
            .save_source_blob(unaliased_record.body_hash, &unaliased_body)
            .unwrap();
        let mut unaliased = transaction_shell(&manager, 0xf003);
        unaliased.external_objects.push(unaliased_record.clone());
        unaliased.ref_mutations.push(RefMutation {
            name: RefName::branch(b"main").unwrap(),
            expected: RefExpectation::MustEqual {
                target: native_target.clone(),
            },
            new_target: Some(RefTarget::external_object(unaliased_record.object)),
            policy: RefUpdatePolicy::FastForwardOnly,
        });
        let error = manager
            .commit_repository_transaction(unaliased)
            .expect_err("unaliased external commit must not imply ancestry");
        assert!(error.to_string().contains("requires force-with-lease"));

        let (blob_record, blob_body) = raw_blob_record();
        manager
            .save_source_blob(blob_record.body_hash, &blob_body)
            .unwrap();
        let mut non_commit = transaction_shell(&manager, 0xf004);
        non_commit.external_objects.push(blob_record.clone());
        non_commit.ref_mutations.push(RefMutation {
            name: RefName::branch(b"main").unwrap(),
            expected: RefExpectation::MustEqual {
                target: native_target,
            },
            new_target: Some(RefTarget::external_object(blob_record.object)),
            policy: RefUpdatePolicy::FastForwardOnly,
        });
        let error = manager
            .commit_repository_transaction(non_commit)
            .expect_err("non-commit object must not imply ancestry");
        assert!(error.to_string().contains("requires force-with-lease"));
        assert_eq!(manager.read_authority().generation(), stable_generation);
    }

    #[test]
    fn local_only_operations_do_not_perturb_replicated_roots() {
        let backend_a = Arc::new(MemoryBackend::default());
        let backend_b = Arc::new(MemoryBackend::default());
        let manager_a = initial_manager(backend_a);
        let manager_b = initial_manager(backend_b);

        manager_a
            .commit_repository_transaction(unborn_workspace_transaction(
                &manager_a, 60, 61, b"main",
            ))
            .unwrap();
        manager_b
            .commit_repository_transaction(unborn_workspace_transaction(
                &manager_b,
                60,
                62,
                b"alternate",
            ))
            .unwrap();

        let roots_a = manager_a.read_authority().roots().clone();
        let roots_b = manager_b.read_authority().roots().clone();
        assert!(roots_a.has_same_replicated_truth(&roots_b));
        assert_ne!(roots_a.local_state, roots_b.local_state);

        let before_ref = roots_a;
        let mut ref_transaction = transaction_shell(&manager_a, 63);
        ref_transaction.ref_mutations.push(RefMutation {
            name: RefName::branch(b"main").unwrap(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(RefTarget::symbolic(RefName::branch(b"upstream").unwrap())),
            policy: RefUpdatePolicy::FastForwardOnly,
        });
        manager_a
            .commit_repository_transaction(ref_transaction)
            .unwrap();
        let after_ref = manager_a.read_authority().roots().clone();
        assert_ne!(before_ref.ref_state, after_ref.ref_state);
        assert_ne!(before_ref.ref_log, after_ref.ref_log);
        assert_eq!(before_ref.history, after_ref.history);
        assert_eq!(before_ref.collaboration, after_ref.collaboration);
        assert_eq!(before_ref.replication, after_ref.replication);
        assert!(!before_ref.has_same_replicated_truth(&after_ref));
    }

    #[test]
    fn divergent_refs_resolve_exact_trees_without_a_global_head_view() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();
        let lease = manager.read_authority();
        let old_target = lease.metadata().ref_state.refs[0].target.clone();
        let old_change = target_change_id(lease.metadata(), &old_target).unwrap();
        let path = RepoPath::from_utf8("compose.yaml").unwrap();
        let old_artifact = lease.metadata().workspaces[0]
            .tree
            .artifact_at_path(&path)
            .unwrap()
            .clone();
        drop(lease);

        let fixtures = [
            (b"main body\n".as_slice(), "main"),
            (b"alternate body\n".as_slice(), "alternate"),
        ];
        let timestamp = Timestamp(
            chrono::DateTime::parse_from_rfc3339("2026-07-26T13:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        let mut changes = Vec::new();
        for (body, message) in fixtures {
            let body_hash = digest(body);
            manager.save_source_blob(body_hash, body).unwrap();
            let mut change = SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
                origin: ChangeOrigin::Native,
                parents: vec![old_change],
                timestamp: timestamp.clone(),
                author: AuthorId::new("authority-test"),
                message: message.to_string(),
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id: old_artifact.artifact_id,
                    old: old_artifact.located_entry(),
                    new: LocatedEntry::new(path.clone(), TreeEntry::blob(body_hash, false)),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
                projected_files: Vec::new(),
                spec_link: None,
                evidence: Vec::new(),
                risk_summary: None,
            };
            change.id = compute_semantic_change_id(&change).unwrap();
            changes.push(change);
        }

        let main_id = changes[0].id;
        let alternate_id = changes[1].id;
        let mut transaction = transaction_shell(&manager, 71);
        transaction.changes = changes;
        transaction.ref_mutations = vec![
            RefMutation {
                name: RefName::branch(b"main").unwrap(),
                expected: RefExpectation::MustEqual { target: old_target },
                new_target: Some(RefTarget::change(main_id)),
                policy: RefUpdatePolicy::FastForwardOnly,
            },
            RefMutation {
                name: RefName::branch(b"alternate").unwrap(),
                expected: RefExpectation::MustNotExist,
                new_target: Some(RefTarget::change(alternate_id)),
                policy: RefUpdatePolicy::FastForwardOnly,
            },
        ];
        manager.commit_repository_transaction(transaction).unwrap();

        let lease = manager.read_authority();
        assert!(lease.snapshot().resolved_tree.is_empty());
        assert!(lease.snapshot().entities.is_empty());
        assert!(lease.snapshot().relations.is_empty());
        let mut history = lease.snapshot().clone();
        history.repository_authority = None;
        let graph = InMemoryGraph::from_snapshot(history).unwrap();
        let main = graph.resolve_tree_at(&main_id).unwrap();
        let alternate = graph.resolve_tree_at(&alternate_id).unwrap();
        assert_ne!(
            main.artifact_at_path(&path).unwrap().entry,
            alternate.artifact_at_path(&path).unwrap().entry
        );

        let roots = lease.roots().clone();
        drop(lease);
        let reopened =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        assert_eq!(reopened.read_authority().roots().history, roots.history);
        assert!(reopened
            .read_authority()
            .metadata()
            .ref_state
            .default_ref
            .as_ref()
            .is_some_and(|name| name == &RefName::branch(b"main").unwrap()));
    }

    #[test]
    fn preexisting_raw_body_has_no_authority_until_envelope_commit() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let (record, body) = raw_blob_record();
        manager.save_source_blob(record.body_hash, &body).unwrap();
        assert!(manager
            .read_authority()
            .metadata()
            .external_objects
            .is_empty());

        let mut transaction = transaction_shell(&manager, 30);
        transaction.external_objects.push(record.clone());
        manager.commit_repository_transaction(transaction).unwrap();

        assert_eq!(
            manager.read_authority().metadata().external_objects,
            vec![record]
        );
    }

    #[test]
    fn authority_blob_reads_preserve_missing_and_reject_backend_tampering() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let body = b"daemon projection body";
        let body_hash = digest(body);

        assert_eq!(manager.load_source_blob(body_hash).unwrap(), None);
        manager.save_source_blob(body_hash, body).unwrap();
        assert_eq!(
            manager.load_source_blob(body_hash).unwrap(),
            Some(body.to_vec())
        );

        backend
            .blobs
            .lock()
            .insert(*body_hash.as_bytes(), b"tampered backend bytes".to_vec());
        let error = manager
            .load_source_blob(body_hash)
            .expect_err("manager boundary must rebind bytes to the requested digest");
        assert!(
            error.to_string().contains("digest mismatch"),
            "unexpected tamper error: {error}"
        );
    }

    #[test]
    fn exact_length_authority_body_reads_reject_same_length_tampering() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let body = b"policy=allow\n";
        let body_hash = digest(body);
        manager.save_source_blob(body_hash, body).unwrap();
        backend
            .blobs
            .lock()
            .insert(*body_hash.as_bytes(), b"policy=block\n".to_vec());

        let error = load_exact_body(
            backend.as_ref(),
            &repository_id(),
            body_hash,
            body.len() as u64,
            "shared policy source",
        )
        .expect_err("same-length tampering must not satisfy an exact authority read");
        assert!(
            error.to_string().contains("digest mismatch"),
            "unexpected exact-body tamper error: {error}"
        );
    }

    #[test]
    fn missing_raw_body_and_stale_roots_publish_nothing() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(backend);
        let (record, _) = raw_blob_record();
        let mut missing = transaction_shell(&manager, 40);
        missing.external_objects.push(record);
        assert!(manager.commit_repository_transaction(missing).is_err());
        assert_eq!(manager.read_authority().generation(), 0);

        let mut stale = transaction_shell(&manager, 41);
        let (record, body) = raw_blob_record();
        manager.save_source_blob(record.body_hash, &body).unwrap();
        stale.external_objects.push(record);
        stale.expected_generation = 1;
        stale.expected_roots.generation = 1;
        assert!(manager.commit_repository_transaction(stale).is_err());
        assert_eq!(manager.read_authority().generation(), 0);
    }

    #[test]
    fn backend_failure_and_operation_id_conflict_leave_one_coherent_generation() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let (record, body) = raw_blob_record();
        manager.save_source_blob(record.body_hash, &body).unwrap();
        let mut transaction = transaction_shell(&manager, 50);
        transaction.external_objects.push(record);
        backend.fail_next_snapshot.store(true, Ordering::SeqCst);

        assert!(manager
            .commit_repository_transaction(transaction.clone())
            .is_err());
        assert_eq!(manager.read_authority().generation(), 0);
        assert!(manager
            .read_authority()
            .metadata()
            .external_objects
            .is_empty());

        manager
            .commit_repository_transaction(transaction.clone())
            .unwrap();
        let mut conflicting = transaction;
        conflicting.reason = "different payload under the same operation id".to_string();
        assert!(manager.commit_repository_transaction(conflicting).is_err());
        assert_eq!(manager.read_authority().generation(), 1);
        assert_eq!(manager.read_authority().metadata().operation_log.len(), 1);
    }

    #[test]
    fn local_indeterminate_install_recovers_exact_candidate_live_and_after_reopen() {
        let directory = TempDir::new().unwrap();
        let backend = Arc::new(LocalFileBackend::new(directory.path()));
        let manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let transaction = unborn_workspace_transaction(&manager, 0x5100, 0x5101, b"main");

        backend.fail_next_snapshot_parent_sync_after_install();
        let error = manager
            .commit_repository_transaction(transaction.clone())
            .expect_err("installed authority with a lost durability acknowledgement must fail");
        assert!(matches!(
            error,
            KinDbError::SnapshotPersistenceIndeterminate(_)
        ));
        assert_eq!(manager.read_authority().generation(), 0);

        let installed_bytes = backend
            .load_snapshot_authority(repository_id().as_str())
            .unwrap()
            .expect("the exact candidate was installed")
            .snapshot_bytes;

        let reopened_backend = Arc::new(LocalFileBackend::new(directory.path()));
        let reopened =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&reopened_backend))
                .unwrap();
        assert_eq!(reopened.read_authority().generation(), 1);
        let reopened_receipt = reopened
            .commit_repository_transaction(transaction.clone())
            .expect("process reopen must expose the installed operation as idempotent");
        assert_eq!(reopened_receipt.operation_id, transaction.operation_id);

        let live_receipt = manager
            .commit_repository_transaction(transaction)
            .expect("live manager must reconcile its retained exact candidate");
        assert_eq!(live_receipt, reopened_receipt);
        assert_eq!(manager.read_authority().generation(), 1);
        assert_eq!(
            backend
                .load_snapshot_authority(repository_id().as_str())
                .unwrap()
                .unwrap()
                .snapshot_bytes,
            installed_bytes,
            "retry must confirm the installed candidate, not rebuild it"
        );
    }

    #[test]
    fn local_definite_preinstall_failure_retains_no_candidate() {
        let directory = TempDir::new().unwrap();
        let backend = Arc::new(LocalFileBackend::new(directory.path()));
        let manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let rejected = unborn_workspace_transaction(&manager, 0x5200, 0x5201, b"rejected");
        let replacement = unborn_workspace_transaction(&manager, 0x5202, 0x5203, b"replacement");

        backend.fail_next_snapshot_before_authority_commit();
        manager
            .commit_repository_transaction(rejected.clone())
            .expect_err("injected failure is before authority installation");
        assert_eq!(manager.read_authority().generation(), 0);
        assert!(
            backend
                .load_snapshot_authority(repository_id().as_str())
                .unwrap()
                .is_none(),
            "a staged file is not repository authority"
        );

        let receipt = manager
            .commit_repository_transaction(replacement.clone())
            .expect("a different generation-zero operation may proceed immediately");
        assert_eq!(receipt.operation_id, replacement.operation_id);
        let authority = manager.read_authority();
        assert_eq!(authority.generation(), 1);
        assert!(authority
            .metadata()
            .receipts
            .iter()
            .all(|receipt| receipt.operation_id != rejected.operation_id));
    }

    #[test]
    fn local_stale_manager_cannot_replace_concurrent_authority() {
        let directory = TempDir::new().unwrap();
        let backend = Arc::new(LocalFileBackend::new(directory.path()));
        let stale_backend = Arc::new(LocalFileBackend::new(directory.path()));
        let manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let stale =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&stale_backend)).unwrap();
        let winner = unborn_workspace_transaction(&manager, 0x5300, 0x5301, b"winner");
        let loser = unborn_workspace_transaction(&stale, 0x5302, 0x5303, b"loser");

        manager.commit_repository_transaction(winner).unwrap();
        stale
            .commit_repository_transaction(loser)
            .expect_err("stale local manager must lose backend CAS");
        assert_eq!(stale.read_authority().generation(), 0);

        let reopened = RepositoryAuthorityManager::open(
            repository_id(),
            Arc::new(LocalFileBackend::new(directory.path())),
        )
        .unwrap();
        assert_eq!(reopened.read_authority().generation(), 1);
    }

    #[test]
    fn local_authority_freeze_reloads_expected_roots_and_blocks_a_writer() {
        let directory = TempDir::new().unwrap();
        let backend = Arc::new(LocalFileBackend::new(directory.path()));
        let stale_backend = Arc::new(LocalFileBackend::new(directory.path()));
        let manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let stale =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&stale_backend)).unwrap();
        let stale_roots = stale.read_authority().roots().clone();

        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();
        let error = stale
            .freeze_current_authority(&stale_roots)
            .expect_err("a stale in-memory manager must not freeze newer persisted authority");
        assert!(error
            .to_string()
            .contains("persisted authority moved from the expected root bundle"));

        let expected_roots = manager.read_authority().roots().clone();
        let competing_backend = Arc::new(LocalFileBackend::new(directory.path()));
        let competing =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&competing_backend))
                .unwrap();
        let transaction = unborn_workspace_transaction(&competing, 0x5402, 0x5403, b"release");
        let freeze = manager
            .freeze_current_authority(&expected_roots)
            .expect("current persisted authority must freeze");
        assert_eq!(freeze.roots(), &expected_roots);
        assert_eq!(freeze.authority().roots(), &expected_roots);

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = competing.commit_repository_transaction(transaction);
            finished_tx.send(result).unwrap();
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert!(
            finished_rx
                .recv_timeout(std::time::Duration::from_millis(200))
                .is_err(),
            "a competing repository writer must remain blocked while the freeze guard lives"
        );

        drop(freeze);
        finished_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("writer must resume after freeze release")
            .expect("writer must commit against the unchanged frozen parent");
        writer.join().unwrap();

        let reopened = RepositoryAuthorityManager::open(
            repository_id(),
            Arc::new(LocalFileBackend::new(directory.path())),
        )
        .unwrap();
        assert_eq!(reopened.read_authority().generation(), 2);
    }

    #[test]
    fn local_commit_returns_successor_freeze_without_releasing_writer_lock() {
        let directory = TempDir::new().unwrap();
        let backend = Arc::new(LocalFileBackend::new(directory.path()));
        let manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();

        let competing = RepositoryAuthorityManager::open(
            repository_id(),
            Arc::new(LocalFileBackend::new(directory.path())),
        )
        .unwrap();
        let successor = unborn_workspace_transaction(&manager, 0x5410, 0x5411, b"successor");
        let stale_competitor =
            unborn_workspace_transaction(&competing, 0x5412, 0x5413, b"competitor");

        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let finished_rx = Arc::new(std::sync::Mutex::new(finished_rx));
        let writer = std::thread::spawn(move || {
            release_rx.recv().unwrap();
            started_tx.send(()).unwrap();
            finished_tx
                .send(competing.commit_repository_transaction(stale_competitor))
                .unwrap();
        });
        let hook_finished_rx = Arc::clone(&finished_rx);
        backend.set_snapshot_before_authority_commit_hook(move || {
            release_tx.send(()).unwrap();
            started_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap();
            assert!(
                hook_finished_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_millis(200))
                    .is_err(),
                "the competing writer must wait behind the commit-point lock"
            );
        });

        let (receipt, freeze) = manager
            .commit_repository_transaction_and_freeze(successor)
            .expect("local commit must return its still-held successor lock");
        assert_eq!(receipt.generation, 2);
        assert_eq!(freeze.roots(), &receipt.roots_after);
        assert_eq!(freeze.authority().roots(), &receipt.roots_after);
        assert!(
            finished_rx
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_millis(200))
                .is_err(),
            "the successor freeze must retain the commit-point lock"
        );

        drop(freeze);
        let error = finished_rx
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("the blocked writer must resume after freeze release")
            .expect_err("the blocked stale writer must lose successor CAS");
        assert!(
            error.to_string().contains("generation mismatch"),
            "unexpected stale-writer error: {error}"
        );
        writer.join().unwrap();

        let reopened = RepositoryAuthorityManager::open(
            repository_id(),
            Arc::new(LocalFileBackend::new(directory.path())),
        )
        .unwrap();
        assert_eq!(reopened.read_authority().generation(), receipt.generation);
        assert_eq!(reopened.read_authority().roots(), &receipt.roots_after);
    }

    #[test]
    fn local_idempotent_commit_replay_returns_exact_held_freeze() {
        let directory = TempDir::new().unwrap();
        let backend = Arc::new(LocalFileBackend::new(directory.path()));
        let manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let transaction = arbitrary_repository_transaction(&manager);
        let (receipt, initial_freeze) = manager
            .commit_repository_transaction_and_freeze(transaction.clone())
            .expect("initial local commit must return its successor freeze");
        drop(initial_freeze);

        let competing = RepositoryAuthorityManager::open(
            repository_id(),
            Arc::new(LocalFileBackend::new(directory.path())),
        )
        .unwrap();
        let competing_transaction =
            unborn_workspace_transaction(&competing, 0x5420, 0x5421, b"after-replay");
        let (replay, replay_freeze) = manager
            .commit_repository_transaction_and_freeze(transaction)
            .expect("idempotent replay must freeze the exact installed successor");
        assert_eq!(replay.operation_id, receipt.operation_id);
        assert_eq!(replay.roots_after, receipt.roots_after);
        assert_eq!(replay.outcome, RepositoryCommitOutcome::IdempotentReplay);
        assert_eq!(replay_freeze.roots(), &receipt.roots_after);
        assert_eq!(replay_freeze.authority().roots(), &receipt.roots_after);

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            finished_tx
                .send(competing.commit_repository_transaction(competing_transaction))
                .unwrap();
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert!(
            finished_rx
                .recv_timeout(std::time::Duration::from_millis(200))
                .is_err(),
            "an idempotent replay freeze must retain the installed authority lock"
        );

        drop(replay_freeze);
        finished_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("the competing writer must resume after replay freeze release")
            .expect("the competing writer must commit against the unchanged replayed parent");
        writer.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn local_authority_freeze_revokes_a_blocked_writer_after_namespace_detach() {
        let directory = TempDir::new().unwrap();
        let base = directory.path().join("kindb");
        std::fs::create_dir(&base).unwrap();
        let backend = Arc::new(LocalFileBackend::new(&base));
        let manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        manager
            .commit_repository_transaction(unborn_workspace_transaction(
                &manager, 0x5500, 0x5501, b"main",
            ))
            .unwrap();

        let competing = RepositoryAuthorityManager::open(
            repository_id(),
            Arc::new(LocalFileBackend::new(&base)),
        )
        .unwrap();
        let transaction = unborn_workspace_transaction(&competing, 0x5502, 0x5503, b"release");
        let expected = manager.read_authority().roots().clone();
        let freeze = manager.freeze_current_authority(&expected).unwrap();

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            finished_tx
                .send(competing.commit_repository_transaction(transaction))
                .unwrap();
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert!(
            finished_rx
                .recv_timeout(std::time::Duration::from_millis(200))
                .is_err(),
            "writer must be waiting behind the held repository lock"
        );

        let detached = directory.path().join("detached-kindb");
        std::fs::rename(&base, &detached).unwrap();
        drop(freeze);
        let error = finished_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("blocked writer must wake after freeze release")
            .expect_err("a writer pinned before detach must not resurrect authority");
        let message = error.to_string();
        assert!(
            message.contains("namespace changed")
                || message.contains("was detached after this backend opened")
                || message.contains("unavailable for existing-authority access"),
            "unexpected post-detach writer error: {error}"
        );
        writer.join().unwrap();
        assert!(
            !base.exists(),
            "the blocked writer must not recreate the detached local storage root"
        );
        assert!(
            detached.exists(),
            "the exact detached authority namespace must remain recoverable"
        );
    }

    #[test]
    fn local_authority_freeze_rejects_an_unpersisted_repository() {
        let directory = TempDir::new().unwrap();
        let manager = RepositoryAuthorityManager::open(
            repository_id(),
            Arc::new(LocalFileBackend::new(directory.path())),
        )
        .unwrap();
        let expected = manager.read_authority().roots().clone();

        let error = manager
            .freeze_current_authority(&expected)
            .expect_err("generation-zero memory state is not persisted local authority");
        assert!(
            error
                .to_string()
                .contains("unavailable for existing-authority access")
                || error
                    .to_string()
                    .contains("has no existing local snapshot authority to freeze")
        );
    }

    #[test]
    fn repository_authority_cannot_use_incremental_graph_delta() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(backend);
        let mut snapshot = manager.read_authority().snapshot().clone();
        let delta = crate::storage::GraphSnapshotDelta::empty(0);
        let error = crate::storage::apply_graph_delta(&mut snapshot, &delta).unwrap_err();
        assert!(error
            .to_string()
            .contains("cannot be mutated through incremental graph deltas"));
    }

    fn authority_json_path(base: &std::path::Path) -> std::path::PathBuf {
        base.join(repository_id().as_str()).join("authority.json")
    }

    fn read_authority_json(base: &std::path::Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(authority_json_path(base)).unwrap()).unwrap()
    }

    fn write_authority_json(base: &std::path::Path, record: &serde_json::Value) {
        std::fs::write(
            authority_json_path(base),
            serde_json::to_vec(record).unwrap(),
        )
        .unwrap();
    }

    fn reopen(directory: &TempDir) -> RepositoryAuthorityManager<LocalFileBackend> {
        RepositoryAuthorityManager::open(
            repository_id(),
            Arc::new(LocalFileBackend::new(directory.path())),
        )
        .expect("a valid store reopens")
    }

    fn committed_local_repository(directory: &TempDir) -> Arc<LocalFileBackend> {
        let backend = Arc::new(LocalFileBackend::new(directory.path()));
        let manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();
        backend
    }

    #[test]
    fn commit_binds_a_history_validation_record_to_the_exact_persisted_bytes() {
        let directory = TempDir::new().unwrap();
        let backend = committed_local_repository(&directory);

        let authority = backend
            .load_snapshot_authority(repository_id().as_str())
            .unwrap()
            .unwrap();
        let proof = authority
            .history_validation
            .expect("a committed local repository carries a history validation record");
        assert_eq!(proof.validator_version, HISTORY_VALIDATION_VERSION);
        assert_eq!(proof.repository_id, repository_id().as_str());
        assert_eq!(proof.generation, authority.head_generation);
        assert_eq!(
            proof.snapshot_sha256,
            hex::encode(Sha256::digest(&authority.snapshot_bytes)),
            "the record must name the exact bytes it was minted beside"
        );
    }

    #[test]
    fn reopen_with_a_verified_record_skips_whole_history_replay() {
        let directory = TempDir::new().unwrap();
        drop(committed_local_repository(&directory));

        let reopened = reopen(&directory);

        assert_eq!(reopened.read_authority().generation(), 1);
        assert!(
            reopened.opened_by_history_validation(),
            "a verified record must make the reopen skip whole-history replay"
        );
    }

    #[test]
    fn repository_recovery_skip_path_requires_every_exact_proof_field() {
        let directory = TempDir::new().unwrap();
        drop(committed_local_repository(&directory));
        let original = read_authority_json(directory.path());

        let recovered = load_recovered_repository_authority(
            &LocalFileBackend::new(directory.path()),
            repository_id().as_str(),
            HISTORY_VALIDATION_VERSION,
        )
        .unwrap()
        .unwrap();
        assert!(
            recovered.reused_complete_validation,
            "the exact proof must select the validation-reuse decoder"
        );

        for (field, mismatch) in [
            (
                "validator_version",
                serde_json::json!(HISTORY_VALIDATION_VERSION + 1),
            ),
            ("repository_id", serde_json::json!("another-repository")),
            (
                "generation",
                serde_json::json!(
                    original["history_validation"]["generation"]
                        .as_u64()
                        .unwrap()
                        + 1
                ),
            ),
            (
                "snapshot_sha256",
                serde_json::json!(hex::encode(Sha256::digest(b"other snapshot bytes"))),
            ),
        ] {
            let mut mismatched = original.clone();
            mismatched["history_validation"][field] = mismatch;
            write_authority_json(directory.path(), &mismatched);

            let recovered = load_recovered_repository_authority(
                &LocalFileBackend::new(directory.path()),
                repository_id().as_str(),
                HISTORY_VALIDATION_VERSION,
            )
            .unwrap()
            .unwrap();
            assert!(
                !recovered.reused_complete_validation,
                "a mismatched {field} must take the full storage-admission decoder"
            );
        }
        write_authority_json(directory.path(), &original);
    }

    #[test]
    fn reopen_without_a_record_replays_in_full_and_then_binds_one() {
        let directory = TempDir::new().unwrap();
        drop(committed_local_repository(&directory));

        // A store written by a build that had no validation record at all, or
        // by one whose validator has since changed. Both reach open the same
        // way: nothing to verify, so validate everything.
        let mut record = read_authority_json(directory.path());
        record
            .as_object_mut()
            .unwrap()
            .remove("history_validation")
            .expect("the committed record carried a validation to remove");
        write_authority_json(directory.path(), &record);

        assert!(
            !reopen(&directory).opened_by_history_validation(),
            "no record means the open pays full validation"
        );

        let rebound = read_authority_json(directory.path());
        assert!(
            rebound.get("history_validation").is_some(),
            "an open that validated in full must leave a record behind"
        );
        assert!(
            reopen(&directory).opened_by_history_validation(),
            "the record minted by the previous open must make this one fast"
        );
    }

    #[test]
    fn reopen_refuses_a_record_minted_by_a_different_validator() {
        let directory = TempDir::new().unwrap();
        drop(committed_local_repository(&directory));

        let mut record = read_authority_json(directory.path());
        record["history_validation"]["validator_version"] =
            serde_json::json!(HISTORY_VALIDATION_VERSION + 1);
        write_authority_json(directory.path(), &record);

        assert!(
            !reopen(&directory).opened_by_history_validation(),
            "a record from another validator version proves nothing about this one"
        );
    }

    #[test]
    fn reopen_refuses_a_record_that_names_other_bytes_or_another_repository() {
        let directory = TempDir::new().unwrap();
        let backend = committed_local_repository(&directory);
        let authority = backend
            .load_snapshot_authority(repository_id().as_str())
            .unwrap()
            .unwrap();
        let recovered = |proof: HistoryValidationProof| RecoveredSnapshot {
            snapshot: GraphSnapshot::empty(),
            generation: authority.head_generation,
            deltas_applied: 0,
            deltas_seen: 0,
            snapshot_sha256: hex::encode(Sha256::digest(&authority.snapshot_bytes)),
            history_validation: Some(proof),
        };
        let honest = authority.history_validation.clone().unwrap();
        assert!(
            verified_history_validation(&repository_id(), &recovered(honest.clone())).is_some(),
            "the record minted for these bytes must verify"
        );

        let other_bytes = HistoryValidationProof {
            snapshot_sha256: hex::encode(Sha256::digest(b"other bytes")),
            ..honest.clone()
        };
        let other_repository = HistoryValidationProof {
            repository_id: "some-other-repository".to_string(),
            ..honest.clone()
        };
        let other_generation = HistoryValidationProof {
            generation: honest.generation + 1,
            ..honest.clone()
        };
        for forged in [other_bytes, other_repository, other_generation] {
            assert!(
                verified_history_validation(&repository_id(), &recovered(forged)).is_none(),
                "a record that disagrees with what was loaded must not be honored"
            );
        }

        let replayed_delta = RecoveredSnapshot {
            deltas_applied: 1,
            ..recovered(honest)
        };
        assert!(
            verified_history_validation(&repository_id(), &replayed_delta).is_none(),
            "a record about base bytes cannot describe a delta-replayed state"
        );
    }

    #[test]
    fn reopen_refuses_a_tampered_snapshot_even_with_its_record_present() {
        let directory = TempDir::new().unwrap();
        let backend = committed_local_repository(&directory);
        let generation = backend
            .load_snapshot_authority(repository_id().as_str())
            .unwrap()
            .unwrap()
            .head_generation;
        drop(backend);

        let snapshot_path = directory
            .path()
            .join(repository_id().as_str())
            .join("snapshots")
            .join(format!("{generation:020}.kndb"));
        let mut bytes = std::fs::read(&snapshot_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&snapshot_path, &bytes).unwrap();

        let error = match RepositoryAuthorityManager::open(
            repository_id(),
            Arc::new(LocalFileBackend::new(directory.path())),
        ) {
            Ok(_) => panic!("a flipped byte in the persisted snapshot must refuse the open"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("digest mismatch") || error.to_string().contains("invalid"),
            "unexpected tampered-snapshot error: {error}"
        );
    }

    #[test]
    fn binding_a_record_refuses_a_generation_or_digest_that_moved() {
        let directory = TempDir::new().unwrap();
        let backend = committed_local_repository(&directory);
        let authority = backend
            .load_snapshot_authority(repository_id().as_str())
            .unwrap()
            .unwrap();
        let digest = hex::encode(Sha256::digest(&authority.snapshot_bytes));

        let moved_generation = backend
            .record_history_validation(
                repository_id().as_str(),
                authority.head_generation + 1,
                &digest,
                HISTORY_VALIDATION_VERSION,
            )
            .expect_err("a record must never be bound to a generation that is not durable");
        assert!(
            moved_generation.to_string().contains("authority moved"),
            "unexpected moved-generation error: {moved_generation}"
        );

        let other_digest = backend
            .record_history_validation(
                repository_id().as_str(),
                authority.head_generation,
                &hex::encode(Sha256::digest(b"bytes nobody validated")),
                HISTORY_VALIDATION_VERSION,
            )
            .expect_err("a record must never be bound to bytes that are not durable");
        assert!(
            other_digest.to_string().contains("authority moved"),
            "unexpected other-digest error: {other_digest}"
        );
    }
}
