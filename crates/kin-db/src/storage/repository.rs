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
    AuthorId, AuthorityRoot, ChangeStore, DefaultRefExpectation, DefaultRefMutation,
    ExternalChangeAlias, ExternalObjectId, ExternalObjectKind, ExternalObjectRecord,
    FrozenLocalOverlay, GitExternalAuthority, GitObjectBodyLoader, GitObjectDependencyKind,
    GitObjectId, GitTreeEntryMode, Hash256, ModelError, OperationId, RefExpectation, RefMutation,
    RefName, RefTarget, RefUpdatePolicy, RepoPath, RepositoryAuthorityStore,
    RepositoryCommitOutcome, RepositoryCommitReceipt, RepositoryId, RepositoryOperationRecord,
    RepositoryRef, RepositoryRefState, RepositoryTransaction, RootBundle, SemanticChangeId,
    SharedAdmissionPolicy, Timestamp, TreeEntry, WorkspaceHead, WorkspaceId,
    WorkspaceSnapshotBinding, WorkspaceState, WorkspaceTreeArtifact, WorkspaceTreeSnapshot,
    REPOSITORY_ROOT_SCHEMA_VERSION,
};

use crate::engine::InMemoryGraph;
use crate::error::KinDbError;
use crate::storage::authority::{
    AuthorityCommitDecision, AuthorityPublication, AuthorityReadLease, DurableAuthorityPersistence,
    PersistOutcome, VersionedAuthorityState,
};
use crate::storage::backend::{
    load_recovered_snapshot, validate_source_blob_size, verify_source_blob_digest, Generation,
    SnapshotCursor, SnapshotSaveOutcome, StorageBackend, MAX_SOURCE_BLOB_BYTES,
};
use crate::storage::format::GraphSnapshot;

/// Persisted repository-envelope schema.
pub const REPOSITORY_AUTHORITY_SCHEMA_VERSION: u32 = 2;

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

/// Complete repository-authority metadata stored inside one graph snapshot.
///
/// Every vector with set semantics is kept in canonical sorted order.
/// `operation_log` alone is append-ordered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}

impl RepositoryAuthorityState {
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

    fn persist_bytes(&self, bytes: &[u8], cursor: &mut SnapshotCursor) -> PersistOutcome {
        let outcome =
            self.backend
                .save_snapshot_classified(self.repository_id.as_str(), bytes, *cursor);
        Self::record_save_outcome(cursor, outcome)
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
/// This is the only public mutation surface for an authority-bearing v11
/// snapshot. Mutable `InMemoryGraph` remains available for derived query
/// preparation and legacy non-authority graphs, but is never stored inside
/// this publication cell.
pub struct RepositoryAuthorityManager<B: StorageBackend + ?Sized + 'static> {
    repository_id: RepositoryId,
    backend: Arc<B>,
    publication: AuthorityPublication<RepositoryAuthorityState, RepositorySnapshotPersistence<B>>,
}

impl<B: StorageBackend + ?Sized + 'static> RepositoryAuthorityManager<B> {
    /// Open existing authority or prepare an unpersisted generation-zero repo.
    pub fn open(repository_id: RepositoryId, backend: Arc<B>) -> Result<Self, KinDbError> {
        let recovered = load_recovered_snapshot(backend.as_ref(), repository_id.as_str())?;
        let (snapshot, backend_cursor) = if let Some(recovered) = recovered {
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
                        "repository {} snapshot has no v11 authority envelope",
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

        snapshot.validate_storage_admission()?;
        let all_changes: Vec<_> = snapshot.changes.values().cloned().collect();
        validate_history_replay(&snapshot, &all_changes)?;
        validate_all_authority_bodies(backend.as_ref(), &repository_id, &snapshot)?;

        let initial = RepositoryAuthorityState { snapshot };
        let persistence = RepositorySnapshotPersistence {
            backend: Arc::clone(&backend),
            repository_id: repository_id.clone(),
            backend_cursor: Mutex::new(backend_cursor),
        };
        Ok(Self {
            repository_id,
            backend,
            publication: AuthorityPublication::new(initial, persistence),
        })
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
            let metadata = current.metadata();
            if transaction.repository_id != repository_id {
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

            let (next, receipt) =
                prepare_successor(current, &transaction, transaction_hash, backend.as_ref())?;
            Ok(AuthorityCommitDecision::Publish {
                next,
                output: receipt,
            })
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

    Ok((RepositoryAuthorityState { snapshot }, receipt))
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
    let mut replay = snapshot.clone();
    replay.repository_authority = None;
    let graph = InMemoryGraph::from_snapshot(replay)?;
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

        let raw_tree = materialize_git_tree(authority, projection.raw_tree_oid)?;
        let semantic_tree = graph
            .resolve_tree_at(&change.id)?
            .artifacts()
            .map(|artifact| (artifact.path.clone(), artifact.entry))
            .collect::<BTreeMap<_, _>>();
        if semantic_tree != raw_tree {
            return Err(ModelError::Conflict(format!(
                "Git commit projection {} raw tree {} does not match the deterministic semantic tree for change {}",
                projection.commit_oid, projection.raw_tree_oid, change.id
            ))
            .into());
        }
    }
    validate_persisted_git_alias_coverage(snapshot, metadata)
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
    authority: &GitExternalAuthority,
    root_oid: GitObjectId,
) -> Result<BTreeMap<RepoPath, TreeEntry>, KinDbError> {
    let entries = authority
        .closure
        .objects
        .iter()
        .map(|entry| (entry.record.object, entry))
        .collect::<BTreeMap<_, _>>();
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
        RefTarget::ExternalObject { object } if object.kind == ExternalObjectKind::Commit => {
            Ok(metadata
                .aliases
                .iter()
                .find(|alias| alias.oid == object.oid)
                .map(|alias| alias.change_id))
        }
        RefTarget::ExternalObject { .. } | RefTarget::Symbolic { .. } => Ok(None),
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
    let next = mutation.validate_against(
        &transaction.repository_id,
        workspaces.get(&mutation.workspace_id),
    )?;
    validate_workspace_state(snapshot, metadata, &next)?;
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
        if workspace.tree_hash == expected_tree {
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
        RefTarget::ExternalObject { object } if object.kind == ExternalObjectKind::Commit => {
            metadata
                .aliases
                .iter()
                .find(|alias| alias.oid == object.oid)
                .map(|alias| alias.change_id)
                .ok_or_else(|| {
                    ModelError::InvalidOperation(format!(
                        "external commit {} has no semantic change alias",
                        object.oid
                    ))
                    .into()
                })
        }
        RefTarget::ExternalObject { object } => Err(ModelError::InvalidOperation(format!(
            "workspace base target {} is not a commit",
            object.oid
        ))
        .into()),
        RefTarget::Symbolic { .. } => Err(ModelError::InvalidOperation(
            "workspace base target must be resolved".to_string(),
        )
        .into()),
    }
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

fn validate_all_authority_bodies<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    snapshot: &GraphSnapshot,
) -> Result<(), KinDbError> {
    let metadata = snapshot
        .repository_authority
        .as_ref()
        .expect("validated authority snapshot has metadata");
    for record in &metadata.external_objects {
        let body = load_exact_body(
            backend,
            repository_id,
            record.body_hash,
            record.body_len,
            &format!("external object {}", record.object.oid),
        )?;
        record.validate_raw(&body)?;
    }
    validate_git_authority_bodies(
        backend,
        repository_id,
        metadata.git_external_authority.as_ref(),
    )?;
    validate_change_tree_bodies(backend, repository_id, snapshot.changes.values())?;
    for workspace in &metadata.workspaces {
        validate_tree_bodies(
            backend,
            repository_id,
            &workspace.tree,
            "persisted workspace tree",
        )?;
        validate_shared_policy_bodies(backend, repository_id, &workspace.shared_admission_policy)?;
    }
    for policy in &metadata.admission_policies {
        if let Some(policy) = &policy.policy {
            validate_shared_policy_bodies(backend, repository_id, policy)?;
        }
    }
    for overlay in &metadata.local_overlays {
        for source in &overlay.sources {
            load_exact_body(
                backend,
                repository_id,
                source.body_hash,
                source.body_len,
                "local admission rule source",
            )?;
        }
    }
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
    let mut root = DomainRoot::new(b"kin-repository-local-root-v1\0");
    root.unordered("sessions", &snapshot.sessions.iter().collect::<Vec<_>>())?;
    root.unordered("intents", &snapshot.intents.iter().collect::<Vec<_>>())?;
    root.unordered("downstream_warnings", &snapshot.downstream_warnings)?;
    root.ordered("workspaces", &authority.workspaces)?;
    root.ordered("local_overlays", &authority.local_overlays)?;
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
    use kin_model::{
        compute_resolved_tree_hash, compute_semantic_change_id, AdmissionCase,
        AdmissionPolicyDelta, AdmissionRuleSource, AdmissionRuleSourceKind, AdmissionScanToken,
        ArtifactId, AuthorId, ChangeOrigin, DefaultRefMutation, EffectiveAdmissionPolicyStamp,
        FrozenLocalOverlayDelta, GitExternalAuthorityDelta, GitObjectFormat, GitRawRef,
        GitRawTarget, LocatedEntry, RefMutation, RepoPath, ResolvedTree, SemanticChange, TreeDelta,
        WorkspaceExpectation, WorkspaceMutation, ADMISSION_POLICY_SEMANTICS_VERSION,
        REPOSITORY_TRANSACTION_SCHEMA_VERSION,
    };
    use parking_lot::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tempfile::TempDir;
    use uuid::Uuid;

    use crate::storage::LocalFileBackend;

    #[derive(Default)]
    struct MemoryBackend {
        snapshot: Mutex<Option<(Vec<u8>, Generation)>>,
        blobs: Mutex<HashMap<[u8; 32], Vec<u8>>>,
        fail_next_snapshot: AtomicBool,
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
            let value = self.blobs.lock().get(&digest).cloned();
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
        RepositoryId::new("authority-v11-test").unwrap()
    }

    fn digest(body: &[u8]) -> Hash256 {
        Hash256::from_bytes(Sha256::digest(body).into())
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

    fn initial_manager(backend: Arc<MemoryBackend>) -> RepositoryAuthorityManager<MemoryBackend> {
        RepositoryAuthorityManager::open(repository_id(), backend).unwrap()
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
            admission_scan_token: None,
        }
    }

    fn arbitrary_repository_transaction(
        manager: &RepositoryAuthorityManager<MemoryBackend>,
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

        let mut tree_deltas: Vec<_> = fixtures
            .iter()
            .map(|(artifact, path, _, entry)| TreeDelta::Added {
                artifact_id: ArtifactId(Uuid::from_u128(*artifact)),
                new: LocatedEntry::new(RepoPath::from_bytes(path.clone()).unwrap(), *entry),
            })
            .collect();
        tree_deltas.push(TreeDelta::Added {
            artifact_id: ArtifactId(Uuid::from_u128(17)),
            new: LocatedEntry::new(
                RepoPath::from_utf8("vendor/semantic-runtime").unwrap(),
                TreeEntry::gitlink(GitObjectId::sha1(
                    hex::decode("1111111111111111111111111111111111111111")
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )),
            ),
        });
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
        transaction.admission_scan_token = Some(AdmissionScanToken {
            repository_id: repository_id(),
            workspace_id,
            workspace_generation: 0,
            workspace_head: workspace_mutation.new_head.clone(),
            baseline_tree_hash: compute_resolved_tree_hash(&ResolvedTree::default()).unwrap(),
            observed_tree_hash: tree_hash,
            matcher_semantics_version: ADMISSION_POLICY_SEMANTICS_VERSION,
            shared_policy: policy.shared,
            local_overlay: policy.local,
        });
        transaction.workspace_mutation = Some(workspace_mutation);
        transaction.local_overlay_delta = Some(FrozenLocalOverlayDelta::initialize(overlay));
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
            new_shared_admission_policy: shared,
            new_admission_policy: policy,
        };

        let mut transaction = transaction_shell(manager, operation);
        transaction.admission_scan_token = Some(AdmissionScanToken {
            repository_id: repository_id(),
            workspace_id,
            workspace_generation: 0,
            workspace_head: head,
            baseline_tree_hash: empty_tree_hash,
            observed_tree_hash: empty_tree_hash,
            matcher_semantics_version: ADMISSION_POLICY_SEMANTICS_VERSION,
            shared_policy: policy.shared,
            local_overlay: policy.local,
        });
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
        let empty_tree = admit(
            ExternalObjectKind::Tree,
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            Vec::<u8>::new(),
        );
        let root_tree = admit(
            ExternalObjectKind::Tree,
            "f8ca0030cfaa2d892be162947852de7804729814",
            git_tree_body(&[
                (b"compose.yaml", b"100644", compose.object.oid),
                (b"payload.bin", b"100755", binary.object.oid),
                (&[0xff], b"120000", symlink.object.oid),
            ]),
        );
        let parent = admit(
            ExternalObjectKind::Commit,
            "a5663401dd8ebb94c317008e6a8cd2f01183a940",
            git_commit_body(empty_tree.object.oid, &[], b"parent"),
        );
        let head = admit(
            ExternalObjectKind::Commit,
            "72d6709f04432f9711c9c0f9100caf54ba2d9927",
            git_commit_body(root_tree.object.oid, &[parent.object.oid], b"head"),
        );
        let records = vec![
            compose.clone(),
            binary.clone(),
            symlink.clone(),
            empty_tree,
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
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
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
            ],
            admission_policy_delta: None,
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
        }
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
        let tree = ResolvedTree::default().apply(&head.tree_deltas).unwrap();
        let tree_hash = compute_resolved_tree_hash(&tree).unwrap();

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
            tree_deltas: head.tree_deltas,
            new_tree_hash: tree_hash,
            new_shared_admission_policy: shared,
            new_admission_policy: policy,
        });
        transaction.local_overlay_delta = Some(FrozenLocalOverlayDelta::initialize(overlay));
        transaction.admission_scan_token = Some(AdmissionScanToken {
            repository_id: repository_id(),
            workspace_id,
            workspace_generation: 0,
            workspace_head: head_state,
            baseline_tree_hash: compute_resolved_tree_hash(&ResolvedTree::default()).unwrap(),
            observed_tree_hash: tree_hash,
            matcher_semantics_version: ADMISSION_POLICY_SEMANTICS_VERSION,
            shared_policy: policy.shared,
            local_overlay: policy.local,
        });
        (transaction, change_id, target)
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
        assert!(lease.metadata().git_external_authority.is_none());
        assert!(lease.metadata().external_objects.is_empty());
        assert!(lease.metadata().aliases.is_empty());
        assert!(lease.snapshot().changes.is_empty());
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
        assert_eq!(workspace.tree.len(), 7);
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
            projection
                .artifacts
                .iter()
                .find(|artifact| artifact.path.as_bytes() == b"vendor/semantic-runtime")
                .unwrap()
                .size,
            0
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
                admission_policy: before_workspace.admission_policy,
            },
            new_generation: before_workspace.generation + 1,
            new_head: before_workspace.head.clone(),
            new_base_target: before_workspace.base_target.clone(),
            new_base_tree_hash: before_workspace.base_tree_hash,
            tree_deltas: vec![tree_delta],
            new_tree_hash: next_tree_hash,
            new_shared_admission_policy: before_workspace.shared_admission_policy.clone(),
            new_admission_policy: before_workspace.admission_policy,
        };
        let mut transaction = transaction_shell(&manager, 0xa11);
        transaction.admission_scan_token = Some(AdmissionScanToken {
            repository_id: repository_id(),
            workspace_id: before_workspace.workspace_id,
            workspace_generation: before_workspace.generation,
            workspace_head: before_workspace.head.clone(),
            baseline_tree_hash: before_workspace.tree_hash,
            observed_tree_hash: next_tree_hash,
            matcher_semantics_version: ADMISSION_POLICY_SEMANTICS_VERSION,
            shared_policy: before_workspace.admission_policy.shared,
            local_overlay: before_workspace.admission_policy.local,
        });
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
    fn clean_workspace_requires_the_exact_policy_at_its_external_base_alias() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(backend);
        let (mut transaction, _, _) = imported_repository_transaction(&manager);
        let unrelated = SharedAdmissionPolicy::empty(1);
        let workspace = transaction.workspace_mutation.as_mut().unwrap();
        workspace.new_shared_admission_policy = unrelated.clone();
        workspace.new_admission_policy.shared = unrelated.stamp();
        transaction
            .admission_scan_token
            .as_mut()
            .unwrap()
            .shared_policy = unrelated.stamp();

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
                admission_policy: current.admission_policy,
            },
            new_generation: current.generation + 1,
            new_head: current.head.clone(),
            new_base_target: current.base_target.clone(),
            new_base_tree_hash: current.base_tree_hash,
            tree_deltas: vec![tree_delta],
            new_tree_hash: tree_hash,
            new_shared_admission_policy: dirty_policy.clone(),
            new_admission_policy: effective,
        };
        let mut transaction = transaction_shell(&manager, 25);
        transaction.admission_scan_token = Some(AdmissionScanToken {
            repository_id: repository_id(),
            workspace_id: current.workspace_id,
            workspace_generation: current.generation,
            workspace_head: current.head.clone(),
            baseline_tree_hash: current.tree_hash,
            observed_tree_hash: tree_hash,
            matcher_semantics_version: ADMISSION_POLICY_SEMANTICS_VERSION,
            shared_policy: effective.shared,
            local_overlay: effective.local,
        });
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
        let artifact_id = ArtifactId(Uuid::from_u128(70));
        let fixtures = [
            (b"main body\n".as_slice(), "main", b"main".as_slice()),
            (
                b"alternate body\n".as_slice(),
                "alternate",
                b"alternate".as_slice(),
            ),
        ];
        let timestamp = Timestamp(
            chrono::DateTime::parse_from_rfc3339("2026-07-26T13:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        let mut changes = Vec::new();
        for (body, message, _) in fixtures {
            let body_hash = digest(body);
            manager.save_source_blob(body_hash, body).unwrap();
            let mut change = SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
                origin: ChangeOrigin::Native,
                parents: Vec::new(),
                timestamp: timestamp.clone(),
                author: AuthorId::new("authority-test"),
                message: message.to_string(),
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: LocatedEntry::new(
                        RepoPath::from_utf8("README.md").unwrap(),
                        TreeEntry::blob(body_hash, false),
                    ),
                }],
                admission_policy_delta: None,
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
                expected: RefExpectation::MustNotExist,
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
        let path = RepoPath::from_utf8("README.md").unwrap();
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
            .is_none());
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
}
