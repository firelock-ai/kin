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
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;

use parking_lot::Mutex;

use kin_model::{
    ArtifactId, AuthorId, AuthorityRoot, ChangeStore, DefaultRefExpectation, DefaultRefMutation,
    EntityDelta, EntityId, EntityStore, ExternalChangeAlias, ExternalObjectId, ExternalObjectKind,
    ExternalObjectRecord, ExternalReferenceDelta, FrozenLocalOverlay, GitExternalAuthority,
    GitObjectBodyLoader, GitObjectDependencyKind, GitObjectId, GitTreeEntryMode, Hash256,
    LocalAdmissionRuleSourceKind, MergeEntryResolution, MergeResolutionPayload,
    MergeTransactionRecord, ModelError, OperationId, RefExpectation, RefMutation, RefName,
    RefTarget, RefUpdatePolicy, RelationDelta, RepoPath, RepositoryAuthorityStore,
    RepositoryCommitOutcome, RepositoryCommitReceipt, RepositoryId, RepositoryOperationRecord,
    RepositoryRef, RepositoryRefState, RepositoryTransaction, ResolvedArtifact, ResolvedTree,
    RootBundle, SemanticChange, SemanticChangeId, SensitiveArtifactKind, SharedAdmissionPolicy,
    Timestamp, TreeDelta, TreeEntry, WorkspaceHead, WorkspaceId, WorkspaceSemanticOverlay,
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
    AuthorityCommitDecision, AuthorityPublication, AuthorityReadLease, AuthorityRewriteDecision,
    DurableAuthorityPersistence, PersistOutcome, RetainedPersistOutcome, VersionedAuthorityState,
};
#[cfg(test)]
use crate::storage::backend::load_recovered_repository_authority;
use crate::storage::backend::{
    load_recovered_repository_authority_streaming, validate_source_blob_size,
    verify_source_blob_digest, AuthorityPayloadStats, Generation, LocalAuthorityFreezeLock,
    LocalFileBackend, PreparedWorkspaceGraphArtifact, RecoveredSnapshot, SnapshotCursor,
    SnapshotSaveOutcome, SourceBlobValidationRequest, SourceBlobWriteBatch, StorageBackend,
    VerifiedSourceBlobBatch, MAX_SOURCE_BLOB_BYTES,
};
use crate::storage::canonical_hash::canonical_hash_into;
use crate::storage::change_map::ChangeMap;
use crate::storage::change_validation::AdmittedChangeMap;
use crate::storage::format::{
    GraphSnapshot, MaterializedGraphRefusal, MaterializedGraphSection, WorkspaceGraphFacts,
};
use crate::storage::history_replay::{validate_first_parent_history, ReplayProgress};
use crate::types::ResolvedGraphState;

/// Persisted repository-envelope schema this binary WRITES.
///
/// Moved 3 to 4 when commit receipts stopped repeating their operation records
/// (FIR-3064). The snapshot version ladder is what refuses an older BINARY at
/// the frame header, before it decodes anything; this constant is what a new
/// envelope declares, and what makes [`HISTORY_VALIDATION_VERSION`] refuse
/// every durable validation proof minted against the shape that came before,
/// so an already-written store revalidates in full on its first open here.
pub const REPOSITORY_AUTHORITY_SCHEMA_VERSION: u32 = 4;

/// The oldest persisted envelope schema this binary READS.
///
/// Reading has to be a range and writing a point, and conflating them is a
/// migration nobody asked for. A schema-3 envelope differs from a schema-4 one
/// only in that its receipts still carry the operation record the log already
/// holds, which the receipt's own trailing `serde(default)` reads either way
/// and which `validate_against` still checks against the log. Refusing it would
/// have made every store on disk unopenable by this binary; an equality check
/// here did exactly that, and the daemon-attribution run is what caught it:
/// `unsupported repository authority schema 3; expected 4` on a real store.
pub const MIN_REPOSITORY_AUTHORITY_SCHEMA_VERSION: u32 = 3;

/// Revision of what `open`'s full validation path accepts and rejects.
///
/// This has to move independently of the envelope schema, because coverage
/// changes without the persisted shape changing. A durable record binds the
/// exact bytes that were validated, not the set of questions that was asked
/// about them, so a store can be byte-identical under two validators that
/// disagree about whether it is admissible. Deriving the record's version from
/// the envelope schema alone made every such change invisible: the schema stayed
/// at 3 while external-reference entry admission and Git projection tree replay
/// were added to the skipped path, and records minted before either check
/// existed still verified against the validator that added them.
///
/// Bump this when a check reachable from `open`'s full validation path is added,
/// removed, or changes what it admits. Records minted by an earlier revision are
/// then refused, each affected store pays one full validation, and that open
/// rebinds a record at the current revision.
///
/// The rule tracks the **accept/reject set**, not the shape of the code that
/// computes it. What a record has to stand for is the verdict a validator would
/// reach about those exact bytes, so a change that reorganizes, consolidates, or
/// speeds up the checks without changing which histories are admitted does
/// **not** bump this, and bumping it anyway costs every existing store a full
/// revalidation for no integrity gain.
///
/// Read literally, "added, removed, or changes what it admits" invites the wrong
/// answer for a refactor that deletes call sites: replacing a per-target replay
/// loop with one equivalent pass removes calls while removing no check. That is
/// not a coverage change. The test to apply is whether some history's verdict
/// moves, and the standard of evidence is a differential harness showing the old
/// and new paths accept and refuse the same inputs.
///
/// One caveat, because this constant also gates a validator *implementation*: a
/// value must never be minted by two binaries whose validation differs. If a
/// coverage-neutral rewrite of that path lands **after** a release already
/// minting this revision, records from the earlier binary are honored by the
/// later one, so the two must land in the order that keeps each value
/// unambiguous, or the revision must move to separate them.
const HISTORY_VALIDATION_COVERAGE_REVISION: u32 = 3;

/// Version of the complete open-time validation a durable history-validation
/// record stands for.
///
/// Composed from the envelope schema and the coverage revision so that either
/// moving refuses every earlier record. The schema is folded in so an envelope
/// change cannot silently inherit a proof minted against the old shape, and the
/// coverage revision is folded in so a validation change cannot silently inherit
/// a proof minted against weaker checks.
pub const HISTORY_VALIDATION_VERSION: u32 = 1_000
    + REPOSITORY_AUTHORITY_SCHEMA_VERSION * HISTORY_VALIDATION_SCHEMA_STRIDE
    + HISTORY_VALIDATION_COVERAGE_REVISION;

/// Spacing between envelope schemas in [`HISTORY_VALIDATION_VERSION`].
const HISTORY_VALIDATION_SCHEMA_STRIDE: u32 = 100;

// Keep the two terms in distinct decimal ranges. If the coverage revision could
// reach the stride, a coverage bump and a schema bump would compose to the same
// version, and a record minted under one would verify under the other.
const _: () = assert!(
    HISTORY_VALIDATION_COVERAGE_REVISION < HISTORY_VALIDATION_SCHEMA_STRIDE,
    "the coverage revision must stay inside its slot so it cannot alias a schema bump"
);

/// Envelope revision of a durable prepared workspace query-graph artifact.
///
/// This names what the payload and its binding record mean, so bumping it
/// refuses every artifact written before the bump. Move it whenever the
/// binding gains or loses a field, whenever what materialization returns for
/// the same inputs changes, or whenever an artifact written by an earlier
/// build could otherwise be served as if this build had produced it. The cost
/// of a bump is one materialization per workspace per store, which is exactly
/// the cost of not having the artifact at all.
pub const PREPARED_WORKSPACE_GRAPH_VERSION: u32 = 1;

/// Binding record stored beside one prepared workspace query-graph payload.
///
/// Every field is a question the reader must answer the same way the writer
/// did, and the two that carry the weight are `authority_snapshot_sha256` and
/// `payload_sha256`. The first binds the artifact to the exact authority bytes
/// it was derived from: workspace trees and semantic overlays live inside the
/// authority snapshot, so any commit, ref move, overlay edit, or tree change
/// moves those bytes, moves their digest, and refuses the artifact. The second
/// binds the record to the exact payload beside it, so a payload swapped for
/// another perfectly valid frame is refused too.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PreparedWorkspaceGraphBinding {
    prepared_version: u32,
    history_validation_version: u32,
    snapshot_version: u32,
    repository_id: String,
    workspace_id: String,
    generation: Generation,
    authority_snapshot_sha256: String,
    payload_sha256: String,
}

/// What one repository's prepared query-graph state did since it was opened.
///
/// Surfaced so an operator can tell a prepared serve from a materialization
/// directly rather than inferring it from how long an open took, and so a
/// refusal names the binding field that failed instead of disappearing into a
/// silently slower path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreparedWorkspaceGraphStats {
    /// Workspace snapshots answered from a validated durable artifact.
    pub serves: u64,
    /// Artifacts written after a materialization.
    pub writes: u64,
    /// Artifacts refused, each of which fell back to materialization.
    pub refusals: u64,
    /// Binding field that failed on the most recent refusal.
    pub last_refusal: Option<String>,
}

/// Durable prepared-state surface for one repository, captured at open.
///
/// This exists so the published authority state can reach durable prepared
/// bytes without carrying the backend's type parameter through every reader.
trait PreparedWorkspaceGraphStore: Send + Sync {
    fn load(
        &self,
        workspace_id: &str,
    ) -> Result<Option<PreparedWorkspaceGraphArtifact>, KinDbError>;

    fn record(
        &self,
        workspace_id: &str,
        artifact: &PreparedWorkspaceGraphArtifact,
    ) -> Result<bool, KinDbError>;
}

struct BackendPreparedWorkspaceGraphStore<B: StorageBackend + ?Sized + 'static> {
    backend: Arc<B>,
    repository_id: RepositoryId,
}

impl<B: StorageBackend + ?Sized + 'static> PreparedWorkspaceGraphStore
    for BackendPreparedWorkspaceGraphStore<B>
{
    fn load(
        &self,
        workspace_id: &str,
    ) -> Result<Option<PreparedWorkspaceGraphArtifact>, KinDbError> {
        self.backend
            .load_prepared_workspace_graph(self.repository_id.as_str(), workspace_id)
    }

    fn record(
        &self,
        workspace_id: &str,
        artifact: &PreparedWorkspaceGraphArtifact,
    ) -> Result<bool, KinDbError> {
        self.backend.record_prepared_workspace_graph(
            self.repository_id.as_str(),
            workspace_id,
            artifact,
        )
    }
}

/// Prepared workspace query-graph state bound to the exact authority bytes one
/// open loaded.
///
/// A serve is allowed only while the reading lease still names the generation
/// this binding was captured at, and only when every binding field agrees with
/// what this process is holding. Anything else is a refusal reported by the
/// name of the field that failed, and a refusal falls back to the real
/// graph-native materialization and rewrites the artifact. There is no
/// heuristic repair and no filesystem answer anywhere on this path: the
/// artifact is graph-derived state cryptographically bound to graph authority,
/// and on any doubt the answer comes from graph truth instead.
struct PreparedWorkspaceGraphCache {
    store: Arc<dyn PreparedWorkspaceGraphStore>,
    repository_id: RepositoryId,
    generation: Generation,
    authority_snapshot_sha256: String,
    serves: AtomicU64,
    writes: AtomicU64,
    refusals: AtomicU64,
    last_refusal: Mutex<Option<String>>,
}

impl std::fmt::Debug for PreparedWorkspaceGraphCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedWorkspaceGraphCache")
            .field("repository_id", &self.repository_id)
            .field("generation", &self.generation)
            .field("authority_snapshot_sha256", &self.authority_snapshot_sha256)
            .finish_non_exhaustive()
    }
}

impl PreparedWorkspaceGraphCache {
    fn new(
        store: Arc<dyn PreparedWorkspaceGraphStore>,
        repository_id: RepositoryId,
        generation: Generation,
        authority_snapshot_sha256: String,
    ) -> Self {
        Self {
            store,
            repository_id,
            generation,
            authority_snapshot_sha256,
            serves: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            refusals: AtomicU64::new(0),
            last_refusal: Mutex::new(None),
        }
    }

    fn stats(&self) -> PreparedWorkspaceGraphStats {
        PreparedWorkspaceGraphStats {
            serves: self.serves.load(AtomicOrdering::SeqCst),
            writes: self.writes.load(AtomicOrdering::SeqCst),
            refusals: self.refusals.load(AtomicOrdering::SeqCst),
            last_refusal: self.last_refusal.lock().clone(),
        }
    }

    /// Report one refusal by the name of the binding field that failed.
    fn refuse(&self, workspace_id: &WorkspaceId, field: &str, detail: &str) {
        self.refusals.fetch_add(1, AtomicOrdering::SeqCst);
        *self.last_refusal.lock() = Some(field.to_string());
        tracing::warn!(
            repository = %self.repository_id,
            workspace = %workspace_id,
            field,
            detail,
            "refused prepared workspace query state; materializing from graph authority instead"
        );
    }

    fn expected_binding(
        &self,
        workspace_id: &WorkspaceId,
        payload_sha256: String,
    ) -> PreparedWorkspaceGraphBinding {
        PreparedWorkspaceGraphBinding {
            prepared_version: PREPARED_WORKSPACE_GRAPH_VERSION,
            history_validation_version: HISTORY_VALIDATION_VERSION,
            snapshot_version: GraphSnapshot::CURRENT_VERSION,
            repository_id: self.repository_id.to_string(),
            workspace_id: workspace_id.to_string(),
            generation: self.generation,
            authority_snapshot_sha256: self.authority_snapshot_sha256.clone(),
            payload_sha256,
        }
    }

    /// Answer one workspace snapshot from durable prepared bytes, or refuse.
    ///
    /// `None` is never an error the caller has to handle: it means the caller
    /// materializes, which is what it would have done anyway.
    fn serve(&self, generation: Generation, workspace: &WorkspaceState) -> Option<GraphSnapshot> {
        let workspace_id = &workspace.workspace_id;
        if generation != self.generation {
            self.refuse(
                workspace_id,
                "generation",
                &format!(
                    "lease names generation {generation}, prepared state was bound at {}",
                    self.generation
                ),
            );
            return None;
        }
        let artifact = match self.store.load(&workspace_id.to_string()) {
            Ok(Some(artifact)) => artifact,
            // No artifact yet is an ordinary first open, not a refusal.
            Ok(None) => return None,
            Err(error) => {
                self.refuse(workspace_id, "artifact", &error.to_string());
                return None;
            }
        };
        let binding: PreparedWorkspaceGraphBinding = match serde_json::from_slice(&artifact.binding)
        {
            Ok(binding) => binding,
            Err(error) => {
                self.refuse(workspace_id, "binding", &error.to_string());
                return None;
            }
        };
        let expected =
            self.expected_binding(workspace_id, hex::encode(Sha256::digest(&artifact.payload)));
        // Named one at a time so a refusal is a diagnosis rather than a shrug.
        for (field, held, found) in [
            (
                "prepared_version",
                expected.prepared_version.to_string(),
                binding.prepared_version.to_string(),
            ),
            (
                "history_validation_version",
                expected.history_validation_version.to_string(),
                binding.history_validation_version.to_string(),
            ),
            (
                "snapshot_version",
                expected.snapshot_version.to_string(),
                binding.snapshot_version.to_string(),
            ),
            (
                "repository_id",
                expected.repository_id.clone(),
                binding.repository_id.clone(),
            ),
            (
                "workspace_id",
                expected.workspace_id.clone(),
                binding.workspace_id.clone(),
            ),
            (
                "generation",
                expected.generation.to_string(),
                binding.generation.to_string(),
            ),
            (
                "authority_snapshot_sha256",
                expected.authority_snapshot_sha256.clone(),
                binding.authority_snapshot_sha256.clone(),
            ),
            (
                "payload_sha256",
                expected.payload_sha256.clone(),
                binding.payload_sha256.clone(),
            ),
        ] {
            if held != found {
                self.refuse(
                    workspace_id,
                    field,
                    &format!("holding {held}, artifact names {found}"),
                );
                return None;
            }
        }
        // The frame carries its own checksum over its own body, so this
        // refuses bytes the binding record vouches for but the encoder never
        // produced, and it revalidates storage admission over the payload.
        let snapshot = match GraphSnapshot::from_bytes(&artifact.payload) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.refuse(workspace_id, "payload_frame", &error.to_string());
                return None;
            }
        };
        if snapshot.repository_authority.is_some() {
            self.refuse(
                workspace_id,
                "repository_authority",
                "prepared query state must not carry a second authority envelope",
            );
            return None;
        }
        // The invariant materialization asserts about its own output. A
        // prepared serve has to clear the same bar or it is not the same
        // answer.
        if snapshot.resolved_tree != workspace.tree {
            self.refuse(
                workspace_id,
                "resolved_tree",
                "prepared state does not resolve the workspace's exact persisted tree",
            );
            return None;
        }
        self.serves.fetch_add(1, AtomicOrdering::SeqCst);
        tracing::debug!(
            repository = %self.repository_id,
            workspace = %workspace_id,
            generation,
            "served workspace query state from validated durable bytes"
        );
        Some(snapshot)
    }

    /// Record what materialization just produced, best effort.
    ///
    /// A store that cannot record this is correct and slow, never wrong, so
    /// nothing here can fail a materialization that already succeeded.
    fn record(&self, generation: Generation, workspace: &WorkspaceState, snapshot: &GraphSnapshot) {
        let workspace_id = &workspace.workspace_id;
        if generation != self.generation {
            return;
        }
        // Materialization validated exactly this object on the way out, on
        // both its clean and its dirty path, so serialization does not walk it
        // again to reach the same verdict.
        let payload = match snapshot.to_bytes_pre_validated() {
            Ok(payload) => payload,
            Err(error) => {
                tracing::debug!(
                    repository = %self.repository_id,
                    workspace = %workspace_id,
                    error = %error,
                    "could not encode prepared workspace query state; the next open materializes again"
                );
                return;
            }
        };
        let binding = self.expected_binding(workspace_id, hex::encode(Sha256::digest(&payload)));
        let binding = match serde_json::to_vec(&binding) {
            Ok(binding) => binding,
            Err(error) => {
                tracing::debug!(
                    repository = %self.repository_id,
                    workspace = %workspace_id,
                    error = %error,
                    "could not encode a prepared workspace binding; the next open materializes again"
                );
                return;
            }
        };
        let artifact = PreparedWorkspaceGraphArtifact { binding, payload };
        match self.store.record(&workspace_id.to_string(), &artifact) {
            Ok(true) => {
                self.writes.fetch_add(1, AtomicOrdering::SeqCst);
                tracing::debug!(
                    repository = %self.repository_id,
                    workspace = %workspace_id,
                    generation,
                    "recorded prepared workspace query state for the opened authority"
                );
            }
            Ok(false) => {}
            Err(error) => tracing::debug!(
                repository = %self.repository_id,
                workspace = %workspace_id,
                error = %error,
                "could not record prepared workspace query state; the next open materializes again"
            ),
        }
    }
}

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

/// One durable commit receipt, as this repository persists it.
///
/// Everything [`RepositoryCommitReceipt`] carries except the operation record,
/// which `operation_log` already holds under the same `operation_id`. The
/// repository wrote both, and they are the same record: measured on a full VS
/// Code tree, `operation_log[0]` is 800,755,477 bytes and `receipts[0]` is
/// 800,756,236, together 41.8 percent of a 3,859,076,152-byte store, and the
/// envelope holding them decodes to 4,854,246,200 bytes in memory, 125.8
/// percent of the whole store on disk (FIR-3064).
///
/// So the receipt names its operation rather than repeating it. Every check the
/// pairing rested on still runs: a receipt's own `operation_id`,
/// `repository_id`, `transaction_hash`, `roots_before` and `roots_after` are
/// still compared against the log entry it names, which is exactly what
/// `RepositoryCommitReceipt::validate` compared them against when the record
/// was embedded. What is gone is the comparison of a copy against its original,
/// which has no meaning once there is one record.
///
/// `operation` is `Some` only in a store written before this change. rmp_serde
/// writes a struct as a positional array, and this field is last, so an
/// eight-element receipt from an older store decodes with it present and a
/// seven-element one takes the default. Those older stores are still validated
/// against their embedded copy, and the open drops it once that check passes,
/// so a legacy store pays the duplicate as a transient rather than as resident
/// memory, and stops paying it entirely at its next commit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedCommitReceipt {
    pub operation_id: OperationId,
    pub repository_id: RepositoryId,
    pub transaction_hash: Hash256,
    pub outcome: RepositoryCommitOutcome,
    pub generation: u64,
    pub roots_before: RootBundle,
    pub roots_after: RootBundle,
    /// The embedded operation record a pre-v15 store carries. Never written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<RepositoryOperationRecord>,
}

impl PersistedCommitReceipt {
    /// The receipt without its operation record.
    pub fn trimmed(receipt: &RepositoryCommitReceipt) -> Self {
        Self {
            operation_id: receipt.operation_id,
            repository_id: receipt.repository_id.clone(),
            transaction_hash: receipt.transaction_hash,
            outcome: receipt.outcome,
            generation: receipt.generation,
            roots_before: receipt.roots_before.clone(),
            roots_after: receipt.roots_after.clone(),
            operation: None,
        }
    }

    /// The whole receipt again, with the operation this one names.
    ///
    /// The caller supplies the record from the operation log. Refuses a record
    /// that is not the one this receipt names, because a receipt reunited with
    /// the wrong operation is worse than one with none.
    pub fn rejoin(
        &self,
        operation: &RepositoryOperationRecord,
    ) -> Result<RepositoryCommitReceipt, KinDbError> {
        if operation.operation_id != self.operation_id {
            return Err(storage(format!(
                "receipt {} cannot be rejoined with operation {}",
                self.operation_id, operation.operation_id
            )));
        }
        let receipt = RepositoryCommitReceipt {
            operation_id: self.operation_id,
            repository_id: self.repository_id.clone(),
            transaction_hash: self.transaction_hash,
            outcome: self.outcome,
            generation: self.generation,
            roots_before: self.roots_before.clone(),
            roots_after: self.roots_after.clone(),
            operation: operation.clone(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// The checks `RepositoryCommitReceipt::validate` made, against the log
    /// entry this receipt names rather than against an embedded copy of it.
    ///
    /// This is where the duplication paid for itself and where it stops needing
    /// to: every field compared here was compared before, and the record on the
    /// other side of the comparison is now the log's rather than the receipt's
    /// own copy of the log's.
    pub fn validate_against(
        &self,
        operation: &RepositoryOperationRecord,
    ) -> Result<(), KinDbError> {
        if self.operation_id != operation.operation_id
            || self.repository_id != operation.repository_id
            || self.transaction_hash != operation.transaction_hash
            || self.roots_before != operation.roots_before
            || self.roots_after != operation.roots_after
        {
            return Err(storage(format!(
                "receipt {} does not match its committed operation",
                self.operation_id
            )));
        }
        if self.generation != self.roots_after.generation {
            return Err(storage(format!(
                "repository receipt generation {} does not match roots-after generation {}",
                self.generation, self.roots_after.generation
            )));
        }
        // A pre-v15 store still carries its embedded copy, and while it is here
        // it is still checked. Dropping the check with the field would retire a
        // guarantee for stores that have not been rewritten yet.
        if let Some(embedded) = &self.operation {
            if embedded != operation {
                return Err(storage(format!(
                    "receipt {} embeds an operation record that is not the one the log holds",
                    self.operation_id
                )));
            }
        }
        Ok(())
    }
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
    pub receipts: Vec<PersistedCommitReceipt>,
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
    pub(crate) fn empty(
        repository_id: RepositoryId,
        snapshot: &GraphSnapshot,
    ) -> Result<Self, KinDbError> {
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
        let admitted = AdmittedChangeMap::admit(&snapshot.changes, "snapshot")?;
        self.validate_against_snapshot_with(
            snapshot,
            GitProjectionTreeReplay::Required,
            RootRecomputation::Required,
            &admitted,
        )
    }

    pub(crate) fn validate_against_snapshot_with(
        &self,
        snapshot: &GraphSnapshot,
        replay: GitProjectionTreeReplay,
        roots: RootRecomputation,
        admitted: &AdmittedChangeMap<'_>,
    ) -> Result<(), KinDbError> {
        let mut timer = PublicationPhaseTimer::start();
        if !(MIN_REPOSITORY_AUTHORITY_SCHEMA_VERSION..=REPOSITORY_AUTHORITY_SCHEMA_VERSION)
            .contains(&self.schema_version)
        {
            return Err(storage(format!(
                "unsupported repository authority schema {}; this binary reads {} through {} \
                 and writes {}",
                self.schema_version,
                MIN_REPOSITORY_AUTHORITY_SCHEMA_VERSION,
                REPOSITORY_AUTHORITY_SCHEMA_VERSION,
                REPOSITORY_AUTHORITY_SCHEMA_VERSION
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
        let shape_ms = timer.lap_ms();
        validate_git_authority_shape_and_projection(snapshot, self, replay)?;
        let git_projection_ms = timer.lap_ms();
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
        let receipts: BTreeMap<OperationId, &PersistedCommitReceipt> = self
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
            receipt.validate_against(operation)?;
            if receipt.outcome != RepositoryCommitOutcome::Committed {
                return Err(storage(format!(
                    "receipt {} does not record a committed operation",
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

        let operation_log_ms = timer.lap_ms();
        let derived_policies = derive_admission_policies(&snapshot.changes)?;
        if derived_policies != self.admission_policies {
            return Err(storage(
                "persisted per-change admission state does not match semantic history".to_string(),
            ));
        }
        let admission_policies_ms = timer.lap_ms();
        validate_unscoped_history_caches(snapshot)?;
        let history_caches_ms = timer.lap_ms();
        validate_ref_targets(snapshot, self)?;
        let ref_targets_ms = timer.lap_ms();
        validate_workspace_authority(snapshot, self, Some(admitted))?;
        let workspace_authority_ms = timer.lap_ms();

        // Skipped only on an exact obligation the caller discharged over this
        // same snapshot and envelope; see `RootRecomputation`. Every caller
        // that reads a bundle it did not just compute still passes `Required`,
        // so a store whose bundle does not derive from its contents is still
        // refused, just not once per commit as well.
        if roots == RootRecomputation::Required {
            let computed = compute_roots(snapshot, self, self.roots.generation)?;
            if computed != self.roots {
                return Err(storage(
                    "repository root bundle does not recompute from the persisted envelope"
                        .to_string(),
                ));
            }
        }
        let compute_roots_ms = timer.lap_ms();
        tracing::debug!(
            target: "kin_db::admission",
            shape_ms,
            git_projection_ms,
            operation_log_ms,
            admission_policies_ms,
            history_caches_ms,
            ref_targets_ms,
            workspace_authority_ms,
            compute_roots_ms,
            "repository authority validated against snapshot"
        );
        #[cfg(test)]
        record_preparation_phase(
            "authority_against_snapshot",
            vec![
                ("shape_ms", shape_ms),
                ("git_projection_ms", git_projection_ms),
                ("operation_log_ms", operation_log_ms),
                ("admission_policies_ms", admission_policies_ms),
                ("history_caches_ms", history_caches_ms),
                ("ref_targets_ms", ref_targets_ms),
                ("workspace_authority_ms", workspace_authority_ms),
                ("compute_roots_ms", compute_roots_ms),
            ],
        );
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
    /// Durable prepared query-graph state bound to the exact authority bytes
    /// this process opened. Present only on the state that open published.
    prepared: Option<Arc<PreparedWorkspaceGraphCache>>,
}

impl RepositoryAuthorityState {
    /// Build the read state after the enclosing snapshot has passed complete
    /// repository-authority and history validation.
    fn from_validated_snapshot(snapshot: GraphSnapshot) -> Self {
        let mut authenticated_gitlinks = BTreeSet::new();
        extend_authenticated_gitlinks(&mut authenticated_gitlinks, snapshot.changes.values());
        Self::from_validated_snapshot_with_gitlinks(snapshot, authenticated_gitlinks)
    }

    /// [`from_validated_snapshot`](Self::from_validated_snapshot) for an open
    /// that already walked every change once and carries the index it built,
    /// so the change map is not decoded a second time to rebuild it.
    fn from_validated_snapshot_with_gitlinks(
        snapshot: GraphSnapshot,
        authenticated_gitlinks: BTreeSet<(ArtifactId, GitObjectId)>,
    ) -> Self {
        Self {
            snapshot,
            authenticated_gitlinks: Arc::new(authenticated_gitlinks),
            prepared: None,
        }
    }

    /// Attach the prepared query-graph state open bound to these exact bytes.
    fn with_prepared_workspace_graphs(
        mut self,
        prepared: Arc<PreparedWorkspaceGraphCache>,
    ) -> Self {
        self.prepared = Some(prepared);
        self
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
            // A commit rewrote the authority bytes, so the digest the open
            // bound its prepared state to no longer describes this
            // repository. The successor carries no binding at all rather than
            // one that could only ever refuse.
            prepared: None,
        }
    }

    /// Replace only the durable representation of this exact authority.
    ///
    /// The section is derived state and changes neither semantic roots nor the
    /// logical generation. The authenticated Gitlink index therefore remains
    /// exact. Prepared state does not: its binding names the old authority
    /// bytes, so a rewrite drops it rather than carrying a cache that can only
    /// refuse.
    fn from_validated_equivalent(current: &Self, snapshot: GraphSnapshot) -> Self {
        debug_assert_eq!(
            snapshot.repository_authority.as_ref().map(|m| &m.roots),
            Some(current.roots())
        );
        Self {
            snapshot,
            authenticated_gitlinks: Arc::clone(&current.authenticated_gitlinks),
            prepared: None,
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
    ///
    /// A reopen of unchanged state may answer from durable prepared bytes
    /// instead, but only after every field of that artifact's binding record
    /// agrees with the authority this lease holds. A refusal is reported by
    /// the name of the field that failed and materializes from graph truth,
    /// which then rewrites the artifact.
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

        let prepared = self
            .prepared
            .as_ref()
            .filter(|_| prepared_workspace_state_pays_for_itself(workspace));
        if let Some(prepared) = prepared {
            if let Some(snapshot) = prepared.serve(self.generation(), workspace) {
                return Ok(Some(snapshot));
            }
        }
        let materialized = materialize_workspace_graph_snapshot(
            self.snapshot(),
            self.metadata(),
            workspace,
            None,
        )?;
        if let Some(prepared) = prepared {
            prepared.record(self.generation(), workspace, &materialized);
        }
        Ok(Some(materialized))
    }
}

/// Whether a durable prepared artifact can pay for itself for this workspace.
///
/// Materialization has two very different costs, and only one of them is worth
/// buying back at this layer. A workspace with no semantic overlay returns its
/// resolved base directly: one replay, no graph build, no export. A workspace
/// carrying an overlay cannot take that path at all, and pays a graph build, a
/// delta application, a full snapshot export, and a validation pass on top of
/// the same replay. Serving a prepared payload costs one decode of a
/// history-bearing frame plus its admission validation, which sits between the
/// two.
///
/// Measured on the synthetic 20k-entity, 61-change store in release (local,
/// non-citable): clean materialize 212 ms against a 247 ms serve, so serving a
/// clean workspace would be a 16% regression; dirty materialize 612 ms against
/// a 279 ms serve, a 2.2x win. So the overlay is the gate. It is decided from
/// persisted workspace metadata alone, with no resolution and no IO, and it is
/// deliberately conservative in the safe direction: an empty overlay whose tree
/// still diverges from its base does take the expensive path and is passed
/// over here, which costs a win rather than causing a regression.
///
/// This is a cost rule, not a correctness rule. Nothing about whether an
/// artifact may be TRUSTED lives here; that is the binding, and it is checked
/// in full on every serve. Relax this when the payload can replace the
/// authority decode as well (FIR-2333) or becomes a page-parkable mmap layout,
/// because the clean-path arithmetic changes then, and re-measure before doing
/// it.
fn prepared_workspace_state_pays_for_itself(workspace: &WorkspaceState) -> bool {
    !workspace.semantic_overlay.is_empty()
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

/// The Gitlinks one transaction's admission verifier may treat as authority.
///
/// The persisted index plus the Gitlinks carried by the Git-origin changes
/// this transaction publishes. Reading only the persisted half refused every
/// bootstrap that installs Git authority and native history together, and one
/// transaction must do both: `validate_transaction_git_projection_membership`
/// requires a Git-origin change's commit projection to arrive in the same
/// transaction as the change, so authority and history cannot be split across
/// two commits and the pre-transaction index can never hold the first one's
/// Gitlinks.
///
/// A change contributes only when the SUCCESSOR authority projects its commit.
/// That is what makes reading the transaction safe rather than credulous.
/// `apply_git_authority` runs before every admission verifier, and for each
/// projected commit it compares the authority against its exact old-state
/// lease, requires every closure object to match its persisted descriptor,
/// replays the raw Git tree against the deterministic semantic tree so an
/// artifact's entry must equal the raw one exactly, and validates the raw
/// bodies against immutable CAS. A Native change and a bare external-object
/// record pass none of that and contribute nothing, which
/// `extend_authenticated_gitlinks` enforces by origin.
///
/// The projection filter is also what keeps the rule fail-closed if a verifier
/// is ever moved ahead of `apply_git_authority`: an authority that has not been
/// applied projects none of this transaction's commits, so the successor set is
/// exactly the persisted one and the caller refuses precisely as it did before.
fn successor_authenticated_gitlinks(
    current: &RepositoryAuthorityState,
    metadata: &PersistedRepositoryAuthority,
    transaction: &RepositoryTransaction,
) -> BTreeSet<(ArtifactId, GitObjectId)> {
    let projected = metadata
        .git_external_authority
        .iter()
        .flat_map(|authority| {
            authority
                .commit_projections
                .iter()
                .map(|projection| projection.commit_oid)
        })
        .collect::<BTreeSet<_>>();
    let mut authenticated = current.authenticated_gitlinks().clone();
    extend_authenticated_gitlinks(
        &mut authenticated,
        transaction.changes.iter().filter(|change| {
            matches!(
                change.origin,
                kin_model::ChangeOrigin::GitCommit { oid } if projected.contains(&oid)
            )
        }),
    );
    authenticated
}

impl VersionedAuthorityState for RepositoryAuthorityState {
    fn generation(&self) -> Generation {
        self.metadata().roots.generation
    }
}

/// Journal shape of one repository's durable authority, as the writer sees it.
///
/// The three byte counts are what the frame-versus-full decision reads. They
/// start from the payload receipt of the open that built the manager and move
/// with every acknowledged write, so the writer never re-reads storage to
/// decide, and they are reset by every full snapshot promotion because that is
/// what a promotion does to the journal.
#[derive(Debug, Clone)]
struct PersistenceState {
    /// Backend CAS cursor, not the logical repository generation.
    ///
    /// GCS object generations are provider-assigned opaque versions (for
    /// example 100, 101, ...), while `RootBundle::generation` is Kin's
    /// contiguous logical sequence (0, 1, ...). They must never be compared
    /// or substituted for one another.
    cursor: SnapshotCursor,
    /// Serialized length of the full snapshot the acknowledged journal extends.
    base_bytes: u64,
    /// Number of acknowledged authority frames since that snapshot.
    journal_frames: u64,
    /// Serialized length of those frames together.
    journal_bytes: u64,
    /// The frame of a candidate whose append returned indeterminate, retained
    /// so reconciliation compares the exact bytes it tried to install rather
    /// than re-encoding them.
    pending_frame: Option<PendingFrame>,
}

/// A retained frame candidate, bound to the exact successor it was encoded
/// for.
///
/// Reconciliation consults it only for the candidate whose roots these are.
/// A generation alone would not do: after a reconciliation proves the frame
/// was not committed the publication drops that candidate, and a later
/// successor at the same generation is a different state whose own persist
/// outcome must not be read through this frame.
#[derive(Debug, Clone)]
struct PendingFrame {
    /// `roots_after` of the successor the frame produces.
    roots: RootBundle,
    bytes: Vec<u8>,
}

/// How many authority frames may follow one full snapshot before the next
/// publication rewrites the snapshot.
///
/// The bound is what keeps recovery time and disk bounded: an open decodes at
/// most one full snapshot and applies at most this many frames, and the
/// journal never exceeds the snapshot it extends because a frame that would
/// carry it past that size forces the rewrite instead. `KINDB_AUTHORITY_JOURNAL_MAX_FRAMES`
/// overrides the count for operators and benches; `0` makes every publication
/// a full snapshot, which is also how a store is compacted back to a shape
/// that readers predating frames can open.
const AUTHORITY_JOURNAL_MAX_FRAMES: u64 = 32;

fn authority_journal_max_frames() -> u64 {
    static LIMIT: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *LIMIT.get_or_init(
        || match std::env::var("KINDB_AUTHORITY_JOURNAL_MAX_FRAMES") {
            Ok(value) => match value.trim().parse::<u64>() {
                Ok(limit) => limit,
                Err(error) => {
                    tracing::warn!(
                        value,
                        error = %error,
                        "ignoring KINDB_AUTHORITY_JOURNAL_MAX_FRAMES; using the default bound"
                    );
                    AUTHORITY_JOURNAL_MAX_FRAMES
                }
            },
            Err(_) => AUTHORITY_JOURNAL_MAX_FRAMES,
        },
    )
}

/// Which durable shape one publication takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicationShape {
    /// Append one authority frame to the acknowledged journal.
    Frame,
    /// Rewrite the full snapshot, which also retires the journal.
    FullSnapshot,
}

struct RepositorySnapshotPersistence<B: StorageBackend + ?Sized> {
    backend: Arc<B>,
    repository_id: RepositoryId,
    state: Mutex<PersistenceState>,
    /// Frame bound in force for this repository. Read once from the process
    /// environment at open; tests lower it to exercise the promotion.
    max_journal_frames: std::sync::atomic::AtomicU64,
    /// Test-only replacement for the base byte length the journal may grow
    /// to, so a small fixture can exercise frames without a large base.
    #[cfg(test)]
    journal_byte_bound_for_test: Mutex<Option<u64>>,
}

impl<B: StorageBackend + ?Sized> RepositorySnapshotPersistence<B> {
    fn new(
        backend: Arc<B>,
        repository_id: RepositoryId,
        cursor: SnapshotCursor,
        payload_stats: Option<AuthorityPayloadStats>,
    ) -> Self {
        let (base_bytes, journal_frames, journal_bytes) =
            payload_stats.map_or((0, 0, 0), |stats| {
                (
                    stats.snapshot_bytes(),
                    stats.acknowledged_delta_count(),
                    stats.acknowledged_delta_bytes(),
                )
            });
        Self {
            backend,
            repository_id,
            state: Mutex::new(PersistenceState {
                cursor,
                base_bytes,
                journal_frames,
                journal_bytes,
                pending_frame: None,
            }),
            max_journal_frames: std::sync::atomic::AtomicU64::new(authority_journal_max_frames()),
            #[cfg(test)]
            journal_byte_bound_for_test: Mutex::new(None),
        }
    }

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
    fn persist_bytes(&self, bytes: &[u8], state: &mut PersistenceState) -> PersistOutcome {
        let outcome = self.backend.save_snapshot_validated(
            self.repository_id.as_str(),
            bytes,
            state.cursor,
            Some(HISTORY_VALIDATION_VERSION),
        );
        let outcome = Self::record_save_outcome(&mut state.cursor, outcome);
        if matches!(outcome, PersistOutcome::Committed) {
            let retired = self.note_full_snapshot_committed(state, bytes.len());
            self.clear_retired_frames(retired);
        }
        outcome
    }

    /// [`persist_bytes`](Self::persist_bytes) for a frame nobody holds.
    ///
    /// The bytes are written straight into the backend's staging file as they
    /// are serialized, so no contiguous copy of the repository ever exists. The
    /// same validity argument applies: every successor persisted here descends
    /// from an open that established complete history validity and carries its
    /// own new changes through `validate_history_replay`, so the durable record
    /// still says these are validated bytes.
    ///
    /// Returns the frame's length beside the outcome, because a caller that
    /// never held the bytes cannot ask how long they were.
    fn persist_streamed(
        &self,
        snapshot: &GraphSnapshot,
        state: &mut PersistenceState,
    ) -> (PersistOutcome, usize) {
        // A `Cell` rather than a captured `&mut`, so the closure borrows this
        // immutably and the length is readable the moment the call returns.
        let written = std::cell::Cell::new(0u64);
        let outcome = {
            let mut produce = |out: &mut dyn std::io::Write| {
                let shape = snapshot.stream_pre_validated(out)?;
                written.set(shape.byte_len);
                Ok((shape.byte_len, shape.sha256))
            };
            self.backend.save_snapshot_streamed(
                self.repository_id.as_str(),
                &mut produce,
                state.cursor,
                Some(HISTORY_VALIDATION_VERSION),
            )
        };
        let snapshot_bytes = written.get() as usize;
        let outcome = Self::record_save_outcome(&mut state.cursor, outcome);
        if matches!(outcome, PersistOutcome::Committed) {
            let retired = self.note_full_snapshot_committed(state, snapshot_bytes);
            self.clear_retired_frames(retired);
        }
        (outcome, snapshot_bytes)
    }

    /// A full snapshot is durable at `state.cursor`: the journal it retired is
    /// gone from the writer's view. Returns how many frames it retired, so the
    /// caller can ask storage to drop their bytes in whichever way its lock
    /// discipline allows.
    fn note_full_snapshot_committed(
        &self,
        state: &mut PersistenceState,
        snapshot_bytes: usize,
    ) -> u64 {
        let retired_frames = state.journal_frames;
        state.base_bytes = snapshot_bytes as u64;
        state.journal_frames = 0;
        state.journal_bytes = 0;
        state.pending_frame = None;
        retired_frames
    }

    /// Ask storage to drop the bytes of frames a promotion retired.
    ///
    /// The promotion already retired every acknowledged frame in the same
    /// record write that installed the snapshot; only their bytes remain, and
    /// recovery ignores retired bytes by name. Cleanup is therefore best
    /// effort, and a failure here costs disk until the next open finalizes it,
    /// never correctness.
    fn clear_retired_frames(&self, retired_frames: u64) {
        if retired_frames == 0 {
            return;
        }
        if let Err(error) = self.backend.clear_deltas(self.repository_id.as_str()) {
            tracing::warn!(
                repository = %self.repository_id,
                retired_frames,
                error = %error,
                "full snapshot committed; deferred retired authority frame cleanup"
            );
        }
    }

    /// Whether a frame is even a candidate for the next publication, judged
    /// on what the writer knows before encoding one: backend support, a base
    /// to extend, and the frame count bound.
    fn frame_is_candidate(&self, state: &PersistenceState) -> bool {
        if !self.backend.supports_authority_frames() || state.base_bytes == 0 {
            return false;
        }
        let max_frames = self
            .max_journal_frames
            .load(std::sync::atomic::Ordering::Relaxed);
        state.journal_frames < max_frames
    }

    /// Choose the durable shape of one publication whose frame is encoded,
    /// under the journal byte bound.
    fn publication_shape(&self, state: &PersistenceState, frame_bytes: u64) -> PublicationShape {
        if !self.frame_is_candidate(state) {
            return PublicationShape::FullSnapshot;
        }
        #[allow(unused_mut)]
        let mut byte_bound = state.base_bytes;
        #[cfg(test)]
        if let Some(bound) = *self.journal_byte_bound_for_test.lock() {
            byte_bound = bound;
        }
        match state.journal_bytes.checked_add(frame_bytes) {
            Some(total) if total <= byte_bound => PublicationShape::Frame,
            _ => PublicationShape::FullSnapshot,
        }
    }

    /// Encode the frame that carries `current` to `next`, proven from its own
    /// wire bytes, or say why the publication must be a full snapshot instead.
    fn encode_frame(
        &self,
        current: &RepositoryAuthorityState,
        next: &RepositoryAuthorityState,
    ) -> Result<crate::storage::authority_frame::ProvenFrame, KinDbError> {
        crate::storage::authority_frame::AuthorityFrame::encode_proven(
            &current.snapshot,
            &next.snapshot,
        )
    }

    /// Append one validated authority frame at the current cursor.
    fn persist_frame_bytes(&self, frame: &[u8], state: &mut PersistenceState) -> PersistOutcome {
        let outcome = self.backend.save_authority_frame(
            self.repository_id.as_str(),
            frame,
            state.cursor,
            Some(HISTORY_VALIDATION_VERSION),
        );
        let outcome = Self::record_save_outcome(&mut state.cursor, outcome);
        if matches!(outcome, PersistOutcome::Committed) {
            state.journal_frames = state.journal_frames.saturating_add(1);
            state.journal_bytes = state.journal_bytes.saturating_add(frame.len() as u64);
        }
        outcome
    }

    /// Persist `next` as the successor of `current` in whichever shape the
    /// bound allows, recording the phase split either way.
    fn persist_successor(
        &self,
        current: &RepositoryAuthorityState,
        next: &RepositoryAuthorityState,
    ) -> PersistOutcome {
        // The persist runs after the decision closure returns, so it sits inside
        // the caller's commit phase and outside every preparation lap. Without a
        // span of its own it was charged to the caller as self time, which is
        // half of why a bootstrap commit could not be attributed (FIR-2579).
        let _persist_span = tracing::info_span!("kindb.commit.persist_successor").entered();
        let mut timer = PublicationPhaseTimer::start();
        let mut state = self.state.lock();
        // A persist call means the publication holds no retained candidate:
        // an earlier one was either reconciled as committed or dropped, and a
        // frame retained for it must not outlive that decision.
        state.pending_frame = None;
        let frame = if self.frame_is_candidate(&state) {
            match self.encode_frame(current, next) {
                Ok(frame) => Some(frame),
                Err(error) => {
                    // The writer refusing its own frame is a kin-db defect,
                    // never a durability question: the successor is still
                    // fully validated, so it is persisted whole and the defect
                    // is reported where an operator will see it.
                    tracing::error!(
                        repository = %self.repository_id,
                        generation = next.generation(),
                        error = %error,
                        "authority frame encoding refused; persisting this publication as a full snapshot"
                    );
                    None
                }
            }
        } else {
            None
        };
        let shape = match &frame {
            Some(frame) => self.publication_shape(&state, frame.bytes().len() as u64),
            None => PublicationShape::FullSnapshot,
        };
        match (shape, frame) {
            (PublicationShape::Frame, Some(frame)) => {
                let encode_ms = frame.drain_ms();
                let self_check_ms = frame.self_check_ms();
                let serialize_ms = frame.serialize_ms();
                timer.lap_ms();
                let frame_bytes = frame.bytes().len();
                let outcome = self.persist_frame_bytes(frame.bytes(), &mut state);
                if let PersistOutcome::Indeterminate(_) = &outcome {
                    state.pending_frame = Some(PendingFrame {
                        roots: next.roots().clone(),
                        bytes: frame.bytes().to_vec(),
                    });
                }
                let write_ms = timer.lap_ms();
                record_frame_persistence_phases(
                    encode_ms,
                    self_check_ms,
                    serialize_ms,
                    write_ms,
                    frame_bytes,
                );
                outcome
            }
            _ => {
                // `next` passed the successor's own storage-admission gate under
                // the single writer permit and is immutable from that gate to
                // this write.
                //
                // Streamed, so the frame is never assembled: on a full VS Code
                // tree it is 2.24 GiB here, and this is the phase a conversion
                // peaks in (FIR-3064). Serializing and writing are now one pass,
                // so there is no separate serialize lap to report and the fused
                // time is reported as the write.
                let (outcome, snapshot_bytes) = self.persist_streamed(&next.snapshot, &mut state);
                let write_ms = timer.lap_ms();
                record_snapshot_persistence_phases(0, write_ms, snapshot_bytes);
                outcome
            }
        }
    }

    /// Reconcile one exact full-snapshot candidate, whether it was a logical
    /// successor or an equivalent representation rewrite.
    fn reconcile_full_snapshot(&self, next: &RepositoryAuthorityState) -> PersistOutcome {
        // The retained candidate is the exact `Arc` a persist attempt already
        // serialized, so its admission gate still stands.
        let bytes = match next.snapshot.to_bytes_pre_validated() {
            Ok(bytes) => bytes,
            Err(error) => return PersistOutcome::NotCommitted(error),
        };
        let mut state = self.state.lock();
        let (installed, _journal) = match self
            .backend
            .load_recovery_state(self.repository_id.as_str())
        {
            Ok(installed) => installed,
            Err(error) => return PersistOutcome::Indeterminate(error),
        };

        match installed {
            Some(authority)
                if authority.snapshot_generation != authority.head_generation =>
            {
                PersistOutcome::NotCommitted(storage(format!(
                    "repository {} authority advanced through an incremental journal while an exact full-snapshot write was indeterminate",
                    self.repository_id
                )))
            }
            Some(authority) if *authority.snapshot_bytes == bytes[..] => {
                let installed_cursor = authority.cursor();
                if installed_cursor == state.cursor {
                    return PersistOutcome::Indeterminate(storage(format!(
                        "repository {} exposes the pending full-snapshot bytes without advancing backend cursor {}",
                        self.repository_id,
                        state.cursor.backend_generation()
                    )));
                }
                state.cursor = installed_cursor;
                let retired = self.note_full_snapshot_committed(&mut state, bytes.len());
                self.clear_retired_frames(retired);
                PersistOutcome::Committed
            }
            Some(authority) if authority.cursor() != state.cursor => {
                PersistOutcome::NotCommitted(storage(format!(
                    "repository {} backend authority advanced from cursor {} to {} with different snapshot bytes while a full-snapshot write was indeterminate",
                    self.repository_id,
                    state.cursor.backend_generation(),
                    authority.cursor().backend_generation()
                )))
            }
            Some(_) => self.persist_bytes(&bytes, &mut state),
            None if state.cursor == SnapshotCursor::INITIAL => {
                self.persist_bytes(&bytes, &mut state)
            }
            None => PersistOutcome::Indeterminate(storage(format!(
                "repository {} backend authority disappeared while reconciling cursor {}",
                self.repository_id,
                state.cursor.backend_generation()
            ))),
        }
    }

    /// Reconcile a retained frame candidate whose append was indeterminate.
    ///
    /// The record and the acknowledged frame bytes are read under the backend
    /// lock; the frame either is the head, is not there, or was displaced.
    fn reconcile_frame(
        &self,
        state: &mut PersistenceState,
        frame: &[u8],
    ) -> Result<PersistOutcome, KinDbError> {
        let (installed, journal) = self
            .backend
            .load_recovery_state(self.repository_id.as_str())?;
        let Some(installed) = installed else {
            return Ok(PersistOutcome::Indeterminate(storage(format!(
                "repository {} backend authority disappeared while reconciling cursor {}",
                self.repository_id,
                state.cursor.backend_generation()
            ))));
        };
        let installed_cursor = installed.cursor();
        let expected_next = SnapshotCursor::from_backend_generation(
            state.cursor.backend_generation().saturating_add(1),
        );
        if installed_cursor == state.cursor {
            // Nothing landed, so the writer's journal counts are still what
            // they were when the frame shape was chosen; the exact candidate
            // is retried at the same cursor.
            return Ok(self.persist_frame_bytes(frame, state));
        }
        let head_frame = journal
            .iter()
            .filter(|(_, generation)| *generation <= installed.head_generation)
            .max_by_key(|(_, generation)| *generation);
        if installed_cursor == expected_next
            && installed.snapshot_generation < installed.head_generation
            && head_frame.is_some_and(|(bytes, _)| bytes.as_slice() == frame)
        {
            state.cursor = installed_cursor;
            state.journal_frames = state.journal_frames.saturating_add(1);
            state.journal_bytes = state.journal_bytes.saturating_add(frame.len() as u64);
            return Ok(PersistOutcome::Committed);
        }
        Ok(PersistOutcome::NotCommitted(storage(format!(
            "repository {} backend authority advanced from cursor {} to {} without installing the pending authority frame",
            self.repository_id,
            state.cursor.backend_generation(),
            installed_cursor.backend_generation()
        ))))
    }

    #[cfg(test)]
    fn set_max_journal_frames_for_test(&self, max_frames: u64) {
        self.max_journal_frames
            .store(max_frames, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(test)]
    fn set_journal_byte_bound_for_test(&self, bound: Option<u64>) {
        *self.journal_byte_bound_for_test.lock() = bound;
    }

    #[cfg(test)]
    fn journal_state_for_test(&self) -> (u64, u64, u64) {
        let state = self.state.lock();
        (state.base_bytes, state.journal_frames, state.journal_bytes)
    }
}

/// The phase split of the most recent publication persisted on this thread.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PersistencePhases {
    /// Frame publications only: draining the mutation into a frame.
    encode_ms: u128,
    /// Frame publications only: decoding the frame bytes back, applying them
    /// to a copy of the base, and comparing the result with the successor.
    self_check_ms: u128,
    serialize_ms: u128,
    write_ms: u128,
    payload_bytes: usize,
}

#[cfg(test)]
thread_local! {
    static LAST_PERSISTENCE_PHASES: std::cell::Cell<Option<PersistencePhases>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn last_persistence_phases() -> Option<PersistencePhases> {
    LAST_PERSISTENCE_PHASES.with(std::cell::Cell::get)
}

/// Name the two persistence phases of one snapshot publication.
///
/// Serialization and the durable backend write live behind one persist call,
/// so a slow publication could not previously say which side cost the time.
fn record_snapshot_persistence_phases(serialize_ms: u128, write_ms: u128, snapshot_bytes: usize) {
    #[cfg(test)]
    LAST_PERSISTENCE_PHASES.with(|phases| {
        phases.set(Some(PersistencePhases {
            encode_ms: 0,
            self_check_ms: 0,
            serialize_ms,
            write_ms,
            payload_bytes: snapshot_bytes,
        }))
    });
    if serialize_ms + write_ms >= SLOW_PUBLICATION_PHASE.as_millis() {
        tracing::info!(
            serialize_ms,
            write_ms,
            snapshot_bytes,
            "slow repository authority snapshot persistence"
        );
    } else {
        tracing::debug!(
            serialize_ms,
            write_ms,
            snapshot_bytes,
            "repository authority snapshot persistence"
        );
    }
}

/// Name the phases of one frame publication.
///
/// The writer-side work is split so a slow frame publication can say whether
/// draining the mutation, serializing the frame, proving that the decoded
/// bytes reproduce the successor, or the durable write cost the time.
fn record_frame_persistence_phases(
    encode_ms: u128,
    self_check_ms: u128,
    serialize_ms: u128,
    write_ms: u128,
    frame_bytes: usize,
) {
    #[cfg(test)]
    LAST_PERSISTENCE_PHASES.with(|phases| {
        phases.set(Some(PersistencePhases {
            encode_ms,
            self_check_ms,
            serialize_ms,
            write_ms,
            payload_bytes: frame_bytes,
        }))
    });
    if encode_ms + self_check_ms + serialize_ms + write_ms >= SLOW_PUBLICATION_PHASE.as_millis() {
        tracing::info!(
            encode_ms,
            self_check_ms,
            serialize_ms,
            write_ms,
            frame_bytes,
            "slow repository authority frame persistence"
        );
    } else {
        tracing::debug!(
            encode_ms,
            self_check_ms,
            serialize_ms,
            write_ms,
            frame_bytes,
            "repository authority frame persistence"
        );
    }
}

impl RepositorySnapshotPersistence<LocalFileBackend> {
    /// Persist a full snapshot and keep the backend lock that committed it.
    ///
    /// The freezing publication is the branch, tag, stash, merge-state, and
    /// replay-recovery path; it stays a full snapshot in this revision, which
    /// also compacts whatever journal the commit path built up.
    fn persist_and_freeze(
        &self,
        next: &RepositoryAuthorityState,
    ) -> RetainedPersistOutcome<LocalAuthorityFreezeLock> {
        let mut timer = PublicationPhaseTimer::start();
        // `next` passed the successor's own storage-admission gate under the
        // single writer permit and is immutable from that gate to this write.
        let bytes = match next.snapshot.to_bytes_pre_validated() {
            Ok(bytes) => bytes,
            Err(error) => return RetainedPersistOutcome::NotCommitted(error),
        };
        let serialize_ms = timer.lap_ms();
        let snapshot_bytes = bytes.len();
        let mut state = self.state.lock();
        let outcome = match self.backend.save_snapshot_and_freeze(
            self.repository_id.as_str(),
            &bytes,
            state.cursor,
            Some(HISTORY_VALIDATION_VERSION),
        ) {
            Ok((committed_cursor, retained)) if committed_cursor != state.cursor => {
                state.cursor = committed_cursor;
                let retired = self.note_full_snapshot_committed(&mut state, snapshot_bytes);
                // The lock stays with the caller, so cleanup goes through it
                // rather than through a second acquisition of the same lock.
                if retired != 0 {
                    if let Err(error) = self.backend.clear_retired_deltas_while_frozen(&retained) {
                        tracing::warn!(
                            repository = %self.repository_id,
                            retired_frames = retired,
                            error = %error,
                            "full snapshot committed under freeze; deferred retired authority frame cleanup"
                        );
                    }
                }
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
        };
        let write_ms = timer.lap_ms();
        record_snapshot_persistence_phases(serialize_ms, write_ms, snapshot_bytes);
        outcome
    }
}

impl<B: StorageBackend + ?Sized + 'static> DurableAuthorityPersistence<RepositoryAuthorityState>
    for RepositorySnapshotPersistence<B>
{
    fn persist(
        &self,
        current: &RepositoryAuthorityState,
        next: &RepositoryAuthorityState,
    ) -> PersistOutcome {
        self.persist_successor(current, next)
    }

    fn reconcile(
        &self,
        current: &RepositoryAuthorityState,
        next: &RepositoryAuthorityState,
    ) -> PersistOutcome {
        {
            let mut state = self.state.lock();
            // A retained frame candidate is reconciled against the exact bytes the
            // append tried to install, and only for the successor it was encoded
            // for. It stays retained only while its outcome is still unknown; a
            // committed or refused frame is dropped with the candidate.
            if let Some(pending) = state.pending_frame.take() {
                if pending.roots == *next.roots() {
                    let outcome = match self.reconcile_frame(&mut state, &pending.bytes) {
                        Ok(outcome) => outcome,
                        Err(error) => PersistOutcome::Indeterminate(error),
                    };
                    if matches!(outcome, PersistOutcome::Indeterminate(_)) {
                        state.pending_frame = Some(pending);
                    }
                    return outcome;
                }
            }
        }
        let _ = current;
        self.reconcile_full_snapshot(next)
    }

    fn persist_equivalent(
        &self,
        current: &RepositoryAuthorityState,
        next: &RepositoryAuthorityState,
    ) -> PersistOutcome {
        if current.roots() != next.roots() {
            return PersistOutcome::NotCommitted(storage(format!(
                "repository {} equivalent representation rewrite changed semantic roots",
                self.repository_id
            )));
        }

        // A representation rewrite is always a complete snapshot CAS. An
        // authority frame represents a logical operation and is deliberately
        // unavailable to this path.
        let _persist_span = tracing::info_span!("kindb.commit.persist_equivalent").entered();
        let mut timer = PublicationPhaseTimer::start();
        let mut state = self.state.lock();
        state.pending_frame = None;
        // Streamed for the same reason the successor persist is, and it matters
        // more here: this is where a `kin init` reaches its whole-run peak,
        // because the post-init graph-section rewrite serializes the store with
        // the section in it, 3.59 GiB on a full VS Code tree.
        let (outcome, snapshot_bytes) = self.persist_streamed(&next.snapshot, &mut state);
        let write_ms = timer.lap_ms();
        record_snapshot_persistence_phases(0, write_ms, snapshot_bytes);
        outcome
    }

    fn reconcile_equivalent(
        &self,
        current: &RepositoryAuthorityState,
        next: &RepositoryAuthorityState,
    ) -> PersistOutcome {
        if current.roots() != next.roots() {
            return PersistOutcome::NotCommitted(storage(format!(
                "repository {} equivalent representation rewrite changed semantic roots",
                self.repository_id
            )));
        }
        self.reconcile_full_snapshot(next)
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
    /// Prepared query-graph state bound to the exact authority bytes this open
    /// loaded. Retained here so its counters outlive the published state a
    /// later commit replaces.
    prepared: Option<Arc<PreparedWorkspaceGraphCache>>,
}

/// Result of explicitly persisting one workspace base graph section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializedGraphSectionOutcome {
    /// A complete section was durably written.
    Persisted {
        resolved_at: SemanticChangeId,
        authority_generation: Generation,
    },
    /// The current snapshot already carries a usable section for this base.
    AlreadyCurrent {
        resolved_at: SemanticChangeId,
        authority_generation: Generation,
    },
    /// The workspace exists but has no committed base to resolve yet.
    NoBaseTarget { authority_generation: Generation },
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

/// Walk the acknowledged journal forward onto an envelope read on its own.
///
/// An authority whose acknowledged head is past its snapshot base has an
/// envelope that lives partly in frames, and reading the base alone would serve
/// a superseded envelope as current. The frames are where that is cheap to fix:
/// on a converted psf/requests store the base snapshot is 1051.5 MiB and one
/// frame is about a megabyte, so replaying the journal onto the envelope costs
/// a thousandth of what decoding the base again costs.
///
/// `Ok(None)` means this journal cannot be walked cheaply and correctly, and
/// the caller must open in full. Each such case is named in a log line rather
/// than silently declined, because an unexplained fallback is indistinguishable
/// from a fallback that never happens.
///
/// The chain rules are the ones recovery applies to the same journal: strictly
/// ordered generations, no gaps between the base and the head, and entries
/// staged past the head skipped rather than attached, since a writer that died
/// before its record rename leaves exactly that. On top of them,
/// [`AuthorityFrame::apply_to_envelope`] refuses any frame whose `roots_before`
/// is not the envelope it is being applied to, so a frame walked onto the wrong
/// base cannot produce a plausible wrong envelope; it refuses.
fn advance_envelope_over_journal(
    repository_id: &RepositoryId,
    mut envelope: PersistedRepositoryAuthority,
    journal: &[crate::storage::backend::PersistedDelta],
    base_generation: Generation,
    head_generation: Generation,
) -> Result<Option<PersistedRepositoryAuthority>, KinDbError> {
    if base_generation == head_generation {
        return Ok(Some(envelope));
    }
    if base_generation > head_generation {
        return Err(storage(format!(
            "repository {repository_id} snapshot base generation {base_generation} exceeds acknowledged head {head_generation}"
        )));
    }

    let mut acknowledged: Vec<(&[u8], Generation)> = Vec::new();
    let mut expected = base_generation.checked_add(1).ok_or_else(|| {
        storage(format!(
            "repository {repository_id} generation counter overflowed walking its journal"
        ))
    })?;
    let mut previous: Option<Generation> = None;
    for (bytes, generation) in journal {
        let generation = *generation;
        if previous.is_some_and(|prev| generation <= prev) {
            tracing::debug!(
                repository = %repository_id,
                generation,
                "authority envelope read declined: the journal is not strictly ordered"
            );
            return Ok(None);
        }
        previous = Some(generation);
        if generation <= base_generation {
            continue;
        }
        if generation > head_generation {
            // Staged past the head by a writer that did not commit. Recovery
            // warns and ignores it; so does this.
            continue;
        }
        if generation != expected {
            tracing::debug!(
                repository = %repository_id,
                expected,
                found = generation,
                "authority envelope read declined: the journal has a gap"
            );
            return Ok(None);
        }
        expected = generation.saturating_add(1);
        acknowledged.push((bytes.as_slice(), generation));
    }

    let reached = acknowledged
        .last()
        .map_or(base_generation, |(_, generation)| *generation);
    if reached != head_generation {
        tracing::debug!(
            repository = %repository_id,
            reached,
            head = head_generation,
            "authority envelope read declined: the journal does not reach the acknowledged head"
        );
        return Ok(None);
    }

    for (bytes, generation) in &acknowledged {
        if !crate::storage::authority_frame::AuthorityFrame::is_frame_bytes(bytes) {
            // An envelope-bearing authority advances only through frames, and
            // recovery refuses the mixed case outright. Declining here hands
            // that refusal to the full open rather than duplicating it.
            tracing::debug!(
                repository = %repository_id,
                generation,
                "authority envelope read declined: the journal carries an entry that is not an authority frame"
            );
            return Ok(None);
        }
        let frame = crate::storage::authority_frame::AuthorityFrame::from_bytes(bytes)
            .map_err(|error| {
                storage(format!(
                    "repository {repository_id} authority frame at generation {generation} is unreadable: {error}"
                ))
            })?;
        envelope = frame.apply_to_envelope(envelope).map_err(|error| {
            storage(format!(
                "repository {repository_id} authority frame at generation {generation} does not apply to the envelope: {error}"
            ))
        })?;
    }
    Ok(Some(envelope))
}

/// The repository-authority envelope, opened without materializing the history.
///
/// A full [`RepositoryAuthorityManager::open`] decodes every domain the
/// snapshot carries, replays history when no durable validation record covers
/// the exact bytes, and re-verifies every persisted body against its content
/// address. On a converted repository that is the whole store: 6493 commits of
/// psf/requests produce a 1051 MiB snapshot whose `changes` map dominates it.
///
/// A caller that reads the envelope and then loads a few bodies by content
/// address needs none of that. `kin graph status` is the case that forced this
/// open: it takes one workspace tree out of the envelope and loads the bodies
/// its structured facets name, and it was paying a whole-store open per cold
/// request to do it.
///
/// What this still proves, so nobody reads it as a weakened boundary:
///
/// - The snapshot frame and its checksum are verified exactly as a full decode
///   verifies them, so tampered or truncated bytes refuse here too.
/// - The authority digest is checked against the durable authority record by
///   the backend load this is built on.
/// - Every body [`Self::load_source_blob`] returns is re-verified against its
///   own content address at this boundary, byte for byte, by the same code the
///   manager uses.
///
/// What it deliberately does not do is re-verify the bodies nobody asked for.
/// That sweep is a whole-store integrity audit; it belongs to an open that
/// intends to serve the store, not to a read of two fields. `open` keeps it,
/// unconditionally, and so does the freeze path.
///
/// This refuses rather than guesses in the one case it cannot answer: an
/// authority whose acknowledged journal head is past its snapshot base has an
/// envelope that lives partly in unapplied frames, and reading the base alone
/// would serve a superseded envelope as current. That returns `None`, which
/// means "take the full open", never a wrong answer.
pub struct RepositoryAuthorityMetadata<B: StorageBackend + ?Sized> {
    repository_id: RepositoryId,
    backend: Arc<B>,
    metadata: PersistedRepositoryAuthority,
    generation: Generation,
    /// The resolved graph the base snapshot carried, if any.
    ///
    /// This is where the two halves of the fix meet. The envelope read already
    /// reaches field 33 without allocating the change map; a section at field
    /// 35 rides along on the same walk. Together they answer a workspace graph
    /// with neither a whole-store decode nor a fold over history, which is what
    /// makes an open cost what the graph costs rather than what the history
    /// costs.
    ///
    /// It is read from the BASE snapshot and journal frames do not carry one,
    /// so an envelope advanced over frames serves the base's section. That is
    /// correct rather than merely tolerable: a change id names its whole
    /// ancestry, so an older section is either exactly the right answer for the
    /// change being asked about or is refused by name.
    materialized_graph: Option<MaterializedGraphSection>,
}

impl<B: StorageBackend + ?Sized + 'static> RepositoryAuthorityMetadata<B> {
    /// Read the envelope for `repository_id`, or `None` when a full open is
    /// required to answer correctly.
    ///
    /// `None` has exactly three producers and each is a "cannot answer cheaply"
    /// rather than an error: no persisted authority exists yet, the acknowledged
    /// journal head is past the snapshot base, or the snapshot carries no v13
    /// envelope. A caller treats all three the same way, by opening in full.
    pub fn open(repository_id: RepositoryId, backend: Arc<B>) -> Result<Option<Self>, KinDbError> {
        let started = std::time::Instant::now();
        let (Some(authority), journal) = backend.load_recovery_state(repository_id.as_str())?
        else {
            return Ok(None);
        };
        let read_at = started.elapsed();
        let envelope = crate::storage::format::AuthorityEnvelopeSnapshot::from_bytes(
            &authority.snapshot_bytes,
        )?;
        // The base bytes are the largest thing this function ever holds and
        // nothing below reads them, so they go here rather than at the end of
        // the scope. The journal is kept: it is about a megabyte where the base
        // is about a gigabyte.
        let base_generation = authority.snapshot_generation;
        let head_generation = authority.head_generation;
        drop(authority);
        let decode_at = started.elapsed();
        let crate::storage::format::AuthorityEnvelopeSnapshot {
            version: _,
            repository_authority,
            materialized_graph,
        } = envelope;
        let Some(metadata) = repository_authority else {
            return Ok(None);
        };
        if metadata.repository_id != repository_id {
            return Err(storage(format!(
                "snapshot authority belongs to {}, not {}",
                metadata.repository_id, repository_id
            )));
        }

        let Some(metadata) = advance_envelope_over_journal(
            &repository_id,
            metadata,
            &journal,
            base_generation,
            head_generation,
        )?
        else {
            return Ok(None);
        };
        let frames_at = started.elapsed();

        // The backend cursor fences physical writes. The roots generation is
        // the logical repository generation. A representation-only full
        // snapshot rewrite advances the first while deliberately preserving
        // the second, so equality between them is not an authority invariant.
        let logical_generation = metadata.roots.generation;
        tracing::debug!(
            repository = %repository_id,
            logical_generation,
            backend_base_generation = base_generation,
            backend_head_generation = head_generation,
            backend_frames = head_generation.saturating_sub(base_generation),
            read_ms = read_at.as_millis(),
            decode_ms = (decode_at - read_at).as_millis(),
            frames_ms = (frames_at - decode_at).as_millis(),
            "repository authority envelope read"
        );
        Ok(Some(Self {
            repository_id,
            backend,
            metadata,
            generation: logical_generation,
            materialized_graph,
        }))
    }

    /// The envelope this read resolved.
    pub const fn metadata(&self) -> &PersistedRepositoryAuthority {
        &self.metadata
    }

    /// The persisted graph at `change_id`, or the reason it cannot answer.
    ///
    /// A caller that gets `Ok` has the resolved entities, relations, revisions
    /// and tree at that change without this read having decoded a single change
    /// or folded any history. A caller that gets `Err` falls back to a full
    /// open, which is what it would have done anyway.
    pub fn materialized_graph_for(
        &self,
        change_id: &SemanticChangeId,
    ) -> Result<&MaterializedGraphSection, MaterializedGraphRefusal> {
        let section = self
            .materialized_graph
            .as_ref()
            .ok_or(MaterializedGraphRefusal::Absent)?;
        section.validate_for(change_id)?;
        Ok(section)
    }

    /// The authority generation the envelope names.
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// Load exact immutable source bytes from repository-owned CAS authority.
    ///
    /// Byte for byte the manager's own boundary: bounded, size-validated, and
    /// re-verified against the requested content address before it returns.
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
        // Everything the open needs from every change is gathered here, once,
        // while recovery streams the change map past. When the base can be
        // decoded that way the map stays on disk, and the two walks below that
        // used to read it whole, the body sweep's requirement collection and
        // the Gitlink index, read this instead.
        let mut sweep = HistorySweep::default();
        let recovered = load_recovered_repository_authority_streaming(
            backend.as_ref(),
            repository_id.as_str(),
            HISTORY_VALIDATION_VERSION,
            &mut |change| sweep.visit(change),
        )?;
        let history_streamed = recovered
            .as_ref()
            .is_some_and(|recovered| recovered.history_streamed);
        let payload_stats = recovered.as_ref().map(|recovered| recovered.payload_stats);
        let recovered_authority = recovered.is_some();
        let recovered_at = started.elapsed();
        let reopen_proof = recovered
            .as_ref()
            .filter(|recovered| recovered.reused_complete_validation)
            .and_then(|recovered| {
                verified_history_validation(&repository_id, &recovered.recovered)
            });
        // The digest of the durable authority that was actually loaded: the
        // base bytes for journal-free authority, the base plus the acknowledged
        // frame chain otherwise. Binding a record must never re-serialize the
        // snapshot to obtain one: the persist path deliberately writes the
        // original bytes rather than re-serialized ones, so a round-trip digest
        // is not guaranteed to be the persisted digest.
        let loaded_digest = recovered.as_ref().map(|recovered| {
            (
                recovered.recovered.snapshot_sha256.clone(),
                recovered.recovered.journal_sha256.clone(),
            )
        });
        let (snapshot, backend_cursor) = if let Some(recovered) = recovered {
            let recovered = recovered.recovered;
            // Recovery already refused an incremental graph delta over an
            // authority base and applied every acknowledged authority frame.
            // What can remain is a frame staged past the head by a writer that
            // died before its record rename; recovery reported it and the next
            // writer replaces or discards it, so it does not refuse the open.
            if recovered.deltas_seen != recovered.deltas_applied {
                tracing::warn!(
                    repository = %repository_id,
                    seen = recovered.deltas_seen,
                    applied = recovered.deltas_applied,
                    "repository authority opened past unacknowledged journal entries"
                );
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
        // only of the fallback. What the streamed open changes is only where
        // the change-derived requirements come from: the sweep that already
        // saw every change, rather than a second walk over a decoded map.
        let change_bodies = if history_streamed {
            if sweep.changes_seen != snapshot.changes.len() {
                return Err(storage(format!(
                    "repository {} history stream visited {} changes where the snapshot declares {}",
                    repository_id,
                    sweep.changes_seen,
                    snapshot.changes.len()
                )));
            }
            ChangeBodyRequirements::Collected(std::mem::take(&mut sweep.body_requirements))
        } else {
            ChangeBodyRequirements::Walk(&snapshot.changes)
        };
        validate_all_authority_bodies_with(
            backend.as_ref(),
            &repository_id,
            &snapshot,
            change_bodies,
        )?;
        let bodies_at = started.elapsed();
        // Reopen latency at real repository scale is a standing concern, and it
        // is not obvious from outside which phase dominates. Report the split
        // rather than leaving it to be inferred from a stopwatch.
        tracing::debug!(
            repository = %repository_id,
            by_history_validation = reopen_proof.is_some(),
            history_streamed,
            changes_streamed = sweep.changes_seen,
            change_map_decoded = snapshot.changes.is_decoded(),
            recover_ms = recovered_at.as_millis(),
            structural_ms = (structural_at - recovered_at).as_millis(),
            replay_ms = (replay_at - structural_at).as_millis(),
            bodies_ms = (bodies_at - replay_at).as_millis(),
            total_ms = bodies_at.as_millis(),
            "repository authority open"
        );

        let mut initial = if history_streamed {
            RepositoryAuthorityState::from_validated_snapshot_with_gitlinks(
                snapshot,
                std::mem::take(&mut sweep.authenticated_gitlinks),
            )
        } else {
            RepositoryAuthorityState::from_validated_snapshot(snapshot)
        };
        // Prepared state binds to the digest of the durable authority this open
        // actually loaded, so a repository with no persisted authority yet has
        // nothing to bind to and gets no cache at all.
        let prepared = loaded_digest
            .as_ref()
            .map(|(snapshot_sha256, journal_sha256)| {
                Arc::new(PreparedWorkspaceGraphCache::new(
                    Arc::new(BackendPreparedWorkspaceGraphStore {
                        backend: Arc::clone(&backend),
                        repository_id: repository_id.clone(),
                    }),
                    repository_id.clone(),
                    initial.generation(),
                    journal_sha256
                        .clone()
                        .unwrap_or_else(|| snapshot_sha256.clone()),
                ))
            });
        if let Some(prepared) = &prepared {
            initial = initial.with_prepared_workspace_graphs(Arc::clone(prepared));
        }
        let persistence = RepositorySnapshotPersistence::new(
            Arc::clone(&backend),
            repository_id.clone(),
            backend_cursor,
            payload_stats,
        );
        let manager = Self {
            repository_id,
            backend,
            publication: AuthorityPublication::new(initial, persistence),
            opened_by_history_validation: reopen_proof.is_some(),
            prepared,
        };
        if let Some(generation) = reopen_proof {
            tracing::debug!(
                repository = %manager.repository_id,
                generation,
                "repository authority reopened against a durable history validation"
            );
        } else if let Some((snapshot_sha256, journal_sha256)) = loaded_digest {
            manager.bind_history_validation(
                backend_cursor,
                &snapshot_sha256,
                journal_sha256.as_deref(),
            );
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

    #[cfg(test)]
    fn persistence(&self) -> &RepositorySnapshotPersistence<B> {
        self.publication.persistence()
    }

    /// What prepared workspace query-graph state did since this open.
    ///
    /// A repository whose backend keeps no prepared state reports zeros, which
    /// is also what a repository that has only ever materialized reports. The
    /// two are distinguished by `writes`: a backend with nowhere to record
    /// never accumulates any.
    pub fn prepared_workspace_graph_stats(&self) -> PreparedWorkspaceGraphStats {
        self.prepared
            .as_ref()
            .map(|prepared| prepared.stats())
            .unwrap_or_default()
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
    fn bind_history_validation(
        &self,
        backend_cursor: SnapshotCursor,
        snapshot_sha256: &str,
        journal_sha256: Option<&str>,
    ) {
        let generation = backend_cursor.backend_generation();
        if generation == SnapshotCursor::INITIAL.backend_generation() {
            return;
        }
        let bound = match journal_sha256 {
            Some(journal_sha256) => self.backend.record_journal_history_validation(
                self.repository_id.as_str(),
                generation,
                snapshot_sha256,
                journal_sha256,
                HISTORY_VALIDATION_VERSION,
            ),
            None => self.backend.record_history_validation(
                self.repository_id.as_str(),
                generation,
                snapshot_sha256,
                HISTORY_VALIDATION_VERSION,
            ),
        };
        match bound {
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

    /// Persist many exact bodies under one repository authority envelope.
    ///
    /// This is the bulk form of [`save_source_blob`](Self::save_source_blob)
    /// and it persists exactly the same bodies. It grants no authority either:
    /// a later transaction still has to name every digest through exact tree
    /// and history authority before the repository publishes. Bodies are
    /// durable when this call returns `Ok`, which is why a caller that is
    /// about to cross an authority boundary can run its whole ingest inside
    /// one session and cross afterwards.
    pub fn with_source_blob_write_batch(
        &self,
        operation: &mut dyn FnMut(&dyn SourceBlobWriteBatch) -> Result<(), KinDbError>,
    ) -> Result<(), KinDbError> {
        self.backend
            .with_source_blob_write_batch(self.repository_id.as_str(), operation)
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

    /// Persist the complete resolved graph at one workspace's committed base.
    ///
    /// This is an explicit representation rewrite, not a repository operation:
    /// it advances the backend's fenced write cursor while preserving the exact
    /// logical roots and generation. Ordinary publish deliberately does not pay
    /// this capture's memory cost. A caller may invoke this after initialization
    /// or as an operator-requested refresh. Repeating it for an already-valid
    /// section is idempotent and performs no durable write.
    ///
    /// `Ok(None)` means the workspace does not exist. An unborn workspace is
    /// reported distinctly and performs no write.
    pub fn materialize_workspace_base_graph_section(
        &self,
        repository_id: &RepositoryId,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<MaterializedGraphSectionOutcome>, KinDbError> {
        self.require_repository(repository_id)?;

        self.publication.rewrite_equivalent(|current| {
            let Some(workspace) = current
                .metadata()
                .workspaces
                .iter()
                .find(|workspace| &workspace.workspace_id == workspace_id)
            else {
                return Ok(AuthorityRewriteDecision::Unchanged { output: None });
            };
            let authority_generation = current.generation();
            let Some(resolved_at) =
                workspace_base_change_id(current.metadata(), workspace.base_target.as_ref())?
            else {
                return Ok(AuthorityRewriteDecision::Unchanged {
                    output: Some(MaterializedGraphSectionOutcome::NoBaseTarget {
                        authority_generation,
                    }),
                });
            };

            if current
                .snapshot
                .materialized_graph
                .as_ref()
                .is_some_and(|section| section.validate_for(&resolved_at).is_ok())
            {
                return Ok(AuthorityRewriteDecision::Unchanged {
                    output: Some(MaterializedGraphSectionOutcome::AlreadyCurrent {
                        resolved_at,
                        authority_generation,
                    }),
                });
            }

            // Resolve directly from history. The read path may trust a section
            // by schema and target, but the writer must prove its memo by
            // computing the call it memoizes. The complete state stays whole
            // through `CapturedBaseGraph`, including both tombstone maps and
            // the fold's entity revision timelines.
            let state = AuthorityHistoryView {
                changes: &current.snapshot.changes,
            }
            .resolve_graph_at(&resolved_at)?;
            let mut snapshot = current.snapshot.clone();
            snapshot.materialized_graph = Some(Arc::new(
                CapturedBaseGraph::capture(resolved_at, state).into_section(),
            ));
            snapshot.version = snapshot.wire_version();
            if snapshot
                .repository_authority
                .as_ref()
                .map(|metadata| &metadata.roots)
                != Some(current.roots())
            {
                return Err(storage(
                    "materialized graph representation rewrite changed semantic roots".to_string(),
                ));
            }
            if let Some(field) =
                crate::storage::authority_frame::first_difference(current.snapshot(), &snapshot)
            {
                return Err(storage(format!(
                    "materialized graph representation rewrite changed {field}"
                )));
            }

            let next = RepositoryAuthorityState::from_validated_equivalent(current, snapshot);
            Ok(AuthorityRewriteDecision::Rewrite {
                next,
                output: Some(MaterializedGraphSectionOutcome::Persisted {
                    resolved_at,
                    authority_generation,
                }),
            })
        })
    }

    /// Commit one complete repository transaction.
    pub fn commit_repository_transaction(
        &self,
        transaction: RepositoryTransaction,
    ) -> Result<RepositoryCommitReceipt, KinDbError> {
        // `transaction_hash` opens with `self.validate()` as part of its
        // contract, so validating here first proved nothing and walked every
        // change and every delta a second time. A bootstrap commit carries the
        // whole converted history in one transaction, which is where that
        // second walk stops being free.
        let transaction_hash = {
            let _hash_span = tracing::info_span!("kindb.commit.transaction_hash").entered();
            transaction.transaction_hash()?
        };
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

    /// Commit one complete local repository transaction and return a freeze
    /// that still holds the exact backend lock used for its durable CAS.
    ///
    /// A successful new commit has no release/reacquire window: the local
    /// authority record is installed, the immutable in-memory successor is
    /// published, and the guard is returned while the same OS lock remains
    /// held. An idempotent replay acquires the lock and reloads the exact
    /// current authority before returning its guard.
    /// Commit a transaction admitted from another replica by exact
    /// repository-v6 transfer.
    ///
    /// Same durable path as `commit_repository_transaction`; the one difference
    /// is what the Native admission check asks for. A local publish must name
    /// the workspace it published from, prove that workspace is based on the
    /// exact change, and prove it holds every introduced artifact. A replica
    /// admitting a transfer performed no publication, so it is asked for none of
    /// that, and is held instead to what it can verify for itself: the shared
    /// admission policy, resolved from the transferred history, applied to every
    /// introduced artifact with the full sensitive-content check and nothing
    /// skipped as already-tracked.
    ///
    /// `case` is the publisher's matcher semantics. This layer never invents
    /// one: `resolve_admission_matcher` compiles the SHARED policy under it, so
    /// a fabricated case would judge another replica's policy by rules this one
    /// made up. `None` is accepted only where it cannot matter, which is a
    /// shared policy carrying no rule sources, and is refused by name otherwise.
    pub fn commit_transferred_repository_transaction(
        &self,
        transaction: RepositoryTransaction,
        case: Option<crate::admission::AdmissionCase>,
    ) -> Result<RepositoryCommitReceipt, KinDbError> {
        let transaction_hash = {
            let _hash_span =
                tracing::info_span!("kindb.commit.transaction_hash.transferred").entered();
            transaction.transaction_hash()?
        };
        let repository_id = self.repository_id.clone();
        let backend = Arc::clone(&self.backend);
        let source = NativeAdmissionSource::Transfer { case };

        self.publication.commit(|current| {
            prepare_repository_commit_decision_from(
                current,
                &transaction,
                transaction_hash,
                &repository_id,
                backend.as_ref(),
                source,
            )
        })
    }
}

impl RepositoryAuthorityManager<LocalFileBackend> {
    pub fn commit_repository_transaction_and_freeze(
        &self,
        transaction: RepositoryTransaction,
    ) -> Result<(RepositoryCommitReceipt, LocalRepositoryAuthorityFreeze), KinDbError> {
        // `transaction_hash` opens with `self.validate()` as part of its
        // contract, so validating here first proved nothing and walked every
        // change and every delta a second time. A bootstrap commit carries the
        // whole converted history in one transaction, which is where that
        // second walk stops being free.
        let transaction_hash = {
            let _hash_span = tracing::info_span!("kindb.commit.transaction_hash").entered();
            transaction.transaction_hash()?
        };
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
        // The frozen head is the base plus every acknowledged frame the lock
        // captured, put back together by the same recovery core an open uses,
        // and validated in full here regardless of any durable proof: a freeze
        // is the gate a namespace transition trusts.
        let snapshot = crate::storage::backend::recover_snapshot_from_state(
            self.repository_id.as_str(),
            locked.authority(),
            locked.frames(),
            None,
            crate::storage::backend::HistoryDecode::Eager,
        )?
        .recovered
        .snapshot;
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
    prepare_repository_commit_decision_from(
        current,
        transaction,
        transaction_hash,
        repository_id,
        backend,
        NativeAdmissionSource::LocalWorkspace,
    )
}

fn prepare_repository_commit_decision_from<B: StorageBackend + ?Sized>(
    current: &RepositoryAuthorityState,
    transaction: &RepositoryTransaction,
    transaction_hash: Hash256,
    repository_id: &RepositoryId,
    backend: &B,
    source: NativeAdmissionSource,
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
        // The receipt names its operation rather than carrying it, so the
        // replay reads that record from the log this same envelope holds.
        let operation = metadata
            .operation_log
            .iter()
            .find(|operation| operation.operation_id == receipt.operation_id)
            .ok_or_else(|| {
                storage(format!(
                    "operation {} has a receipt and no log entry",
                    receipt.operation_id
                ))
            })?;
        let mut replay = receipt.rejoin(operation)?;
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
        prepare_successor(current, transaction, transaction_hash, backend, source)?;
    Ok(AuthorityCommitDecision::Publish {
        next,
        output: receipt,
    })
}

// Per-phase lap record collected during one preparation, for attribution.
// Production reads these numbers off the `tracing` events the same call sites
// emit; a test harness cannot install a subscriber without a new dependency,
// so the same laps are also appended here in call order.
#[cfg(test)]
thread_local! {
    pub(crate) static PREPARATION_PHASE_LOG: std::cell::RefCell<
        Vec<(&'static str, Vec<(&'static str, u128)>)>,
    > = const { std::cell::RefCell::new(Vec::new()) };
}

/// Append one phase breakdown to the attribution log.
#[cfg(test)]
pub(crate) fn record_preparation_phase(name: &'static str, laps: Vec<(&'static str, u128)>) {
    PREPARATION_PHASE_LOG.with(|log| log.borrow_mut().push((name, laps)));
}

/// Lap timer for the publication phase breakdown.
///
/// Each lap returns whole milliseconds since the previous lap, so the summary
/// event carries one field per phase and the fields sum to the prepare wall
/// clock within rounding.
pub(crate) struct PublicationPhaseTimer {
    last: std::time::Instant,
}

impl PublicationPhaseTimer {
    pub(crate) fn start() -> Self {
        Self {
            last: std::time::Instant::now(),
        }
    }

    pub(crate) fn lap_ms(&mut self) -> u128 {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_millis();
        self.last = now;
        elapsed
    }
}

/// One prepared successor is slow enough to name its phase breakdown loudly.
const SLOW_PUBLICATION_PHASE: std::time::Duration = std::time::Duration::from_millis(500);

/// Prepare the successor authority state for one transaction.
///
/// `source` says whether the Native changes were published by a workspace on
/// this replica or admitted from another by transfer, which is the only thing
/// the admission check treats differently.
fn prepare_successor<B: StorageBackend + ?Sized>(
    current: &RepositoryAuthorityState,
    transaction: &RepositoryTransaction,
    transaction_hash: Hash256,
    backend: &B,
    source: NativeAdmissionSource,
) -> Result<(RepositoryAuthorityState, RepositoryCommitReceipt), KinDbError> {
    // Every lap below runs inside its own span as well as reporting its
    // milliseconds, and the two must not drift apart: a profiler reads spans and
    // an operator reads the summary event, and a lap that exists in one split
    // and not the other makes the two accounts irreconcilable. The whole
    // preparation was a single unattributed stretch of a caller's self time
    // before this (FIR-2579), which is why a conversion could name none of it.
    //
    // A lap's guard is dropped before the next lap's span is created,
    // deliberately: a span created while another is entered becomes its child,
    // and these laps are siblings that each carry their own self time.
    let prepare_span = tracing::info_span!("kindb.commit.prepare_successor").entered();
    let prepare_started = std::time::Instant::now();
    let mut timer = PublicationPhaseTimer::start();
    let lap = tracing::info_span!("kindb.prepare.clone").entered();
    let mut snapshot = current.snapshot.clone();
    let mut metadata = snapshot
        .repository_authority
        .take()
        .expect("repository authority state always carries metadata");
    let clone_ms = timer.lap_ms();
    drop(lap);

    let lap = tracing::info_span!("kindb.prepare.admit").entered();
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
    let admit_ms = timer.lap_ms();
    drop(lap);

    let lap = tracing::info_span!("kindb.prepare.refs_overlay").entered();
    apply_ref_mutations(&snapshot, &mut metadata, transaction)?;
    apply_local_overlay(&mut metadata, transaction)?;
    validate_new_local_overlay_bodies(
        backend,
        &transaction.repository_id,
        transaction.local_overlay_delta.as_ref(),
    )?;
    let refs_overlay_ms = timer.lap_ms();
    drop(lap);

    let lap = tracing::info_span!("kindb.prepare.workspace").entered();
    // Every remaining validation reads the same authority-free payload:
    // `changes` is final once admission above returns, and the steps below
    // mutate only the detached metadata. One shared decode serves them all.
    let replay = SharedReplayGraph::new(&snapshot);
    apply_workspace(backend, &replay, &snapshot, &mut metadata, transaction)?;
    let workspace_ms = timer.lap_ms();
    drop(lap);

    let lap = tracing::info_span!("kindb.prepare.merge").entered();
    apply_merge_transaction(&mut metadata, transaction)?;
    validate_merge_transaction_delta_bodies(
        backend,
        &transaction.repository_id,
        transaction.merge_transaction_delta.as_ref(),
    )?;
    let merge_ms = timer.lap_ms();
    drop(lap);

    let lap = tracing::info_span!("kindb.prepare.admission_verify").entered();
    verify_transaction_admission(
        backend,
        current,
        &replay,
        &snapshot,
        &metadata,
        transaction,
        source,
    )?;
    let admission_verify_ms = timer.lap_ms();
    drop(lap);

    let lap = tracing::info_span!("kindb.prepare.change_bodies").entered();
    validate_new_change_bodies(
        backend,
        &transaction.repository_id,
        &transaction.changes,
        &metadata.admission_policies,
    )?;
    let change_bodies_ms = timer.lap_ms();
    drop(lap);

    let lap = tracing::info_span!("kindb.prepare.history_replay").entered();
    validate_history_replay_with(&replay, &snapshot, &transaction.changes)?;
    let history_replay_ms = timer.lap_ms();
    drop(lap);
    // The shared proof is charged to whichever lap first forced it rather than
    // to a lap of its own, so `replay_decode_ms` is a part of the laps above and
    // not a thirteenth alongside them.
    //
    // This used to `drop(replay)` here, and that drop was load-bearing: the
    // replay owned a decoded copy of the whole snapshot and this was where it
    // was released. It owns nothing now, so there is nothing to release and the
    // borrow simply ends at its last read, which is the line above.
    let replay_decode_ms = replay.build_ms();

    let lap = tracing::info_span!("kindb.prepare.roots").entered();
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
    let roots_ms = timer.lap_ms();
    drop(lap);

    let lap = tracing::info_span!("kindb.prepare.storage_admission").entered();
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
    // Trimmed, because `metadata.operation_log` already holds this exact
    // record: the two together were 41.8 percent of a full VS Code store and
    // 2.43 GB of the envelope's 4.85 GB in memory (FIR-3064).
    metadata
        .receipts
        .push(PersistedCommitReceipt::trimmed(&receipt));
    metadata
        .receipts
        .sort_by_key(|persisted| persisted.operation_id);
    snapshot.repository_authority = Some(metadata);
    // A publish carries whatever section its base already had, or none, and
    // never writes one: see the note in `apply_workspace`. The version still
    // has to follow the contents, because a successor built from a base that
    // carried a section is itself a v14 snapshot and `to_bytes` refuses any
    // snapshot whose declared version disagrees with what it holds.
    //
    // AFTER the authority is put back, not before. The version now reads two
    // facts, and the second of them is whether the receipts name their
    // operations, which is not knowable until the receipt written above is in
    // the snapshot. Setting it earlier declared v13 on a body that serializes
    // as v15 and `to_bytes` refused every publish.
    snapshot.version = snapshot.wire_version();
    // Every input to the Git projection tree replay is final by the time
    // `apply_git_authority` proves it above: `snapshot.changes` after
    // `admit_changes`, the external objects after `admit_external_objects`, the
    // aliases after `admit_aliases`, and the authority itself after the delta is
    // applied. A write to any of them between that call and this line restores
    // this caller's obligation to `GitProjectionTreeReplay::Required`.
    //
    // The root bundle is proven on the same terms. `metadata.roots` was set
    // from `compute_roots` over this exact snapshot and this exact envelope in
    // the `kindb.prepare.roots` lap above, and the only write between that call
    // and this line is `roots_after` on the operation record appended there,
    // which no root reads: `RepositoryOperationRecord::identity_hash` excludes
    // both root bundles by construction, and `RefLogProjection::from_operation`
    // names neither. Any other write to a root's inputs between those two
    // points restores this caller's obligation to
    // `RootRecomputation::Required`. This is the ONE caller entitled to state
    // it, because it is the only one holding a bundle it folded itself.
    snapshot.validate_storage_admission_with_proven_roots(GitProjectionTreeReplay::Proven)?;
    let storage_admission_ms = timer.lap_ms();
    drop(lap);

    let lap = tracing::info_span!("kindb.prepare.successor_index").entered();
    let state =
        RepositoryAuthorityState::from_validated_successor(current, snapshot, &transaction.changes);
    let successor_index_ms = timer.lap_ms();
    drop(lap);
    let elapsed = prepare_started.elapsed();
    let elapsed_ms = elapsed.as_millis();
    if elapsed >= SLOW_PUBLICATION_PHASE {
        tracing::info!(
            elapsed_ms,
            clone_ms,
            admit_ms,
            refs_overlay_ms,
            workspace_ms,
            merge_ms,
            admission_verify_ms,
            change_bodies_ms,
            history_replay_ms,
            replay_decode_ms,
            roots_ms,
            storage_admission_ms,
            successor_index_ms,
            "slow repository authority successor preparation"
        );
    } else {
        tracing::debug!(
            elapsed_ms,
            clone_ms,
            admit_ms,
            refs_overlay_ms,
            workspace_ms,
            merge_ms,
            admission_verify_ms,
            change_bodies_ms,
            history_replay_ms,
            replay_decode_ms,
            roots_ms,
            storage_admission_ms,
            successor_index_ms,
            "repository authority successor preparation"
        );
    }
    #[cfg(test)]
    record_preparation_phase(
        "prepare_successor",
        vec![
            ("clone_ms", clone_ms),
            ("admit_ms", admit_ms),
            ("refs_overlay_ms", refs_overlay_ms),
            ("workspace_ms", workspace_ms),
            ("merge_ms", merge_ms),
            ("admission_verify_ms", admission_verify_ms),
            ("change_bodies_ms", change_bodies_ms),
            ("history_replay_ms", history_replay_ms),
            ("roots_ms", roots_ms),
            ("storage_admission_ms", storage_admission_ms),
            ("successor_index_ms", successor_index_ms),
        ],
    );
    drop(prepare_span);
    Ok((state, receipt))
}

fn admit_external_objects<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    metadata: &mut PersistedRepositoryAuthority,
    incoming: &[ExternalObjectRecord],
) -> Result<(), KinDbError> {
    let mut progress =
        ReplayProgress::new("external_object_admission", "Git objects", incoming.len());
    match admitted_external_objects(
        backend,
        repository_id,
        &metadata.external_objects,
        incoming,
        &mut progress,
    ) {
        Ok(objects) => {
            progress.finish();
            metadata.external_objects = objects;
            Ok(())
        }
        Err(error) => {
            progress.abandon();
            Err(error)
        }
    }
}

fn admitted_external_objects<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    persisted: &[ExternalObjectRecord],
    incoming: &[ExternalObjectRecord],
    progress: &mut ReplayProgress,
) -> Result<Vec<ExternalObjectRecord>, KinDbError> {
    let mut objects: BTreeMap<ExternalObjectId, ExternalObjectRecord> = persisted
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
        progress.record();
    }
    Ok(objects.into_values().collect())
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
    snapshot.change_children = derive_change_children(&snapshot.changes);

    // A repository with multiple refs has no single current entity/relation
    // revision view. Exact target replay derives revisions from the immutable
    // change DAG; persisting a global revision cache would silently choose an
    // ordering across divergent histories.
    snapshot.entity_revisions.clear();
    Ok(())
}

/// The parent-to-children index exactly as immutable history implies it.
///
/// Successor preparation and authority-frame recovery both derive it from the
/// same function, so a reconstructed head carries the index its writer carried.
pub(crate) fn derive_change_children(
    changes: &HashMap<SemanticChangeId, kin_model::SemanticChange>,
) -> HashMap<SemanticChangeId, Vec<SemanticChangeId>> {
    let mut children: BTreeMap<SemanticChangeId, BTreeSet<SemanticChangeId>> = BTreeMap::new();
    for change in changes.values() {
        for parent in &change.parents {
            children.entry(*parent).or_default().insert(change.id);
        }
    }
    children
        .into_iter()
        .map(|(parent, children)| (parent, children.into_iter().collect()))
        .collect()
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
    validate_git_authority_shape_and_projection(
        snapshot,
        metadata,
        GitProjectionTreeReplay::Required,
    )?;
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

/// Whether a caller still owes the Git projection tree replay.
///
/// The replay is a pure function of four inputs: the authority's object
/// closure, its commit projections, the repository-scoped aliases, and
/// `snapshot.changes`. Every other check in
/// [`validate_git_authority_shape_and_projection`] costs one pass over
/// already-decoded metadata, while the replay materializes a full recursive
/// Git tree per projected commit, so a repository imported from Git pays it
/// once per commit in its history.
///
/// [`GitProjectionTreeReplay::Proven`] therefore states an exact obligation
/// rather than a preference: the caller has already run the replay against
/// byte-identical inputs and no write to any of the four has intervened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GitProjectionTreeReplay {
    Required,
    Proven,
}

/// Whether a caller still owes the root-bundle recomputation.
///
/// [`compute_roots`] folds every leaf of every domain into six SHA-256 roots
/// through [`canonical_leaf_hash`], which buffers one copy of the canonical
/// payload of each leaf it hashes (see `canonical_hash`'s module header). The
/// change map is ONE leaf, not one leaf per change, so the buffer is the size
/// of the whole history: measured by walking the persisted frames of two real
/// stores, that leaf is 85,429,663 bytes on a converted VS Code tree and
/// 410,546,852 bytes on a converted Linux subtree, in bodies of 420,187,160
/// and 2,043,051,848 bytes.
///
/// A commit paid that twice over identical content. `prepare_successor`
/// computes the bundle in its `kindb.prepare.roots` lap and stores it as
/// `metadata.roots`, and the storage-admission gate it runs a few statements
/// later recomputed the same bundle from the same snapshot to compare it with
/// itself.
///
/// Recomputation is what proves a snapshot READ from disk agrees with the
/// envelope beside it, and it stays on every path that has no durable
/// history-validation record to trust instead: a first open, a recovery, a
/// record that does not verify, and
/// [`PersistedRepositoryAuthority::validate_against_snapshot`] itself. It is
/// worth being exact about the path that does NOT recompute, because it is not
/// this change's doing: a reopen carrying a valid record folds nothing, since
/// that record is this validator's own verdict on those exact bytes (FIR-3064).
/// So the recomputation guards precisely the openings where the bytes cannot be
/// taken on trust, and a commit's own fresh arithmetic was never one of them.
///
/// [`RootRecomputation::Proven`] therefore states an exact obligation rather
/// than a preference: the caller has already run [`compute_roots`] over this
/// exact snapshot and this exact envelope, stored the result as the envelope's
/// `roots`, and written nothing since to any input a root reads. Filling in
/// `roots_after` on the appended operation record does not break it, because
/// `RepositoryOperationRecord::identity_hash` excludes `roots_before` and
/// `roots_after` by construction and `RefLogProjection::from_operation` reads
/// neither.
///
/// The failure mode if an obligation is ever stated wrongly is loud and it is
/// at the next open, not at the write: an open passes
/// [`RootRecomputation::Required`], recomputes, and refuses a store whose
/// bundle does not derive from its own contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootRecomputation {
    Required,
    Proven,
}

fn validate_git_authority_shape_and_projection(
    snapshot: &GraphSnapshot,
    metadata: &PersistedRepositoryAuthority,
    replay: GitProjectionTreeReplay,
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
    if replay == GitProjectionTreeReplay::Required {
        let closure_entries = authority
            .closure
            .objects
            .iter()
            .map(|entry| (entry.record.object, entry))
            .collect::<BTreeMap<_, _>>();
        validate_git_projection_tree_replay(snapshot, &tree_targets, |raw_tree_oid| {
            materialize_git_tree(&closure_entries, raw_tree_oid)
        })?;
    }
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

    let mut progress = ReplayProgress::new("git_projection_replay", "Git commits", targets.len());
    match walk_git_projection_forest(
        snapshot,
        targets,
        &children,
        &roots,
        &mut materialize,
        &mut progress,
    ) {
        Ok(()) => {
            progress.finish();
            Ok(())
        }
        Err(error) => {
            progress.abandon();
            Err(error)
        }
    }
}

/// Enter and unwind every projected change once, carrying one resolved tree.
fn walk_git_projection_forest<F>(
    snapshot: &GraphSnapshot,
    targets: &BTreeMap<SemanticChangeId, GitProjectionTreeTarget>,
    children: &BTreeMap<SemanticChangeId, BTreeSet<SemanticChangeId>>,
    roots: &BTreeSet<SemanticChangeId>,
    materialize: &mut F,
    progress: &mut ReplayProgress,
) -> Result<(), KinDbError>
where
    F: FnMut(GitObjectId) -> Result<BTreeMap<RepoPath, TreeEntry>, KinDbError>,
{
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

                progress.record();
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

#[cfg(test)]
thread_local! {
    /// Recursive tree walks performed on this thread.
    ///
    /// A projected commit needs exactly one. The count is the only surface that
    /// separates one walk per projection from a repeated one, because both
    /// admit the identical transaction and persist identical bytes.
    static MATERIALIZED_GIT_TREES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_materialized_git_trees() {
    MATERIALIZED_GIT_TREES.with(|count| count.set(0));
}

#[cfg(test)]
fn materialized_git_trees() -> usize {
    MATERIALIZED_GIT_TREES.with(std::cell::Cell::get)
}

fn materialize_git_tree(
    entries: &BTreeMap<ExternalObjectId, &kin_model::GitObjectClosureEntry>,
    root_oid: GitObjectId,
) -> Result<BTreeMap<RepoPath, TreeEntry>, KinDbError> {
    #[cfg(test)]
    MATERIALIZED_GIT_TREES.with(|count| count.set(count.get() + 1));

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
    replay: &SharedReplayGraph<'_>,
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
    #[cfg(test)]
    let resolutions_before = WORKSPACE_BASE_RESOLUTIONS.with(|count| count.get());
    #[cfg(test)]
    let base_changes_before = WORKSPACE_BASE_CHANGES.with(|count| count.get());

    // One workspace mutation reached for a resolved base graph four times: for
    // the workspace it starts from, for the overlay it derives against the
    // base it ends at, for the validation pass that materialized the successor
    // only to drop it, and for the successor materialization that is actually
    // compared. Resolving one replays the whole reachable history and then
    // reassembles the store, and it reads nothing but the immutable authority
    // snapshot and the change its target names, so resolving one target twice
    // can only reach the conclusion the first resolution already reached. The
    // successor's target is `new_base_target` by construction, and a mutation
    // that leaves the base where it was makes the starting workspace's target
    // that same target again, which is the shape every forced tree admission
    // takes.
    // Each holder below opens its own span so the heap attribution probe
    // charges the transient to the structure that caused it rather than to
    // this whole lap. The lap is the largest single term in a full-history
    // conversion and which of these produces it was never measured.
    let next_base_change = workspace_base_change_id(metadata, mutation.new_base_target.as_ref())?;
    // Deliberately NOT capturing here, and the reason is measured rather than
    // stylistic. This resolution is at exactly the change a section names, so
    // capturing it is tempting and was tried; it holds the resolved state as a
    // second copy for the rest of the mutation, and
    // `a_workspace_mutation_does_not_hold_the_whole_history_four_times` read
    // 7.17 copies of the history against a ceiling of 4.4 and an intact reading
    // of 4.08. That guard is calibrated and its ceiling is not the thing to
    // move: the section is 185 MiB on a converted store, of which
    // `entity_revisions` is 173.8 MiB, and it cannot be narrowed because a base
    // with empty revisions is a DIFFERENT answer (FIR-3048).
    //
    // So a publish does not write sections. An explicit materialize operation
    // does, where paying one graph copy is the point of the command rather than
    // a tax on every commit, and where a store that never runs it simply keeps
    // folding.
    let next_base = {
        let _holder = tracing::info_span!("kindb.prepare.workspace.next_base").entered();
        resolve_workspace_base_graph_snapshot(
            snapshot,
            metadata,
            mutation.new_base_target.as_ref(),
            WorkspaceBaseHistory::Omitted,
        )?
    };

    let current_base_target = current.and_then(|workspace| workspace.base_target.as_ref());
    let current_base = {
        let _holder = tracing::info_span!("kindb.prepare.workspace.current_base").entered();
        if workspace_base_change_id(metadata, current_base_target)? == next_base_change {
            next_base.clone()
        } else {
            resolve_workspace_base_graph_snapshot(
                snapshot,
                metadata,
                current_base_target,
                WorkspaceBaseHistory::Omitted,
            )?
        }
    };
    let current_graph = match current {
        Some(workspace) => {
            materialize_workspace_graph_snapshot_from_base(current_base, workspace, None)?
        }
        None => current_base,
    };
    let mut incremental_delta = mutation.semantic_delta.transaction_delta();
    incremental_delta.tree_deltas = mutation.tree_deltas.clone();
    // Only the four compared domains leave this graph, and the export
    // consumes it. Exporting a whole snapshot here copied the entire change
    // map to be read by nobody, because the two steps below consult entities,
    // relations, external references and the resolved tree and no other
    // domain, and it then left the graph itself bound for the rest of a
    // function whose last reader of it is that export.
    let desired = {
        let _holder = tracing::info_span!("kindb.prepare.workspace.desired_graph").entered();
        let desired_graph = InMemoryGraph::from_snapshot_without_text_index(current_graph)?;
        desired_graph.apply_transaction_delta(&incremental_delta)?;
        // The delta is the mutation's own semantic delta plus a copy of its
        // tree deltas, and the graph has absorbed both. On a conversion that
        // is the whole published state a second time, held for the rest of a
        // function that never reads it again.
        drop(incremental_delta);
        desired_graph.into_workspace_graph_facts()
    };

    let derived_semantic_overlay = {
        let _holder = tracing::info_span!("kindb.prepare.workspace.semantic_overlay").entered();
        derive_workspace_semantic_overlay(&next_base, &desired)?
    };
    let next = mutation.validate_against(
        &transaction.repository_id,
        current,
        derived_semantic_overlay,
    )?;
    // The successor's own materialization follows immediately and is compared
    // against the desired graph, which subsumes the materialize-and-discard
    // check the validating entry point ends with.
    {
        let _holder = tracing::info_span!("kindb.prepare.workspace.validate_successor").entered();
        validate_workspace_state_without_materialization(replay, snapshot, metadata, &next)?;
    }
    // The successor takes its base target from the mutation, so the base
    // resolved above is the one it materializes over. Reuse is refused rather
    // than assumed: a successor pointing somewhere else must resolve its own
    // base or fail, never silently materialize over a base that is not its.
    if next.base_target != mutation.new_base_target {
        return Err(storage(format!(
            "workspace {} successor bases at a target the mutation that produced it did not name",
            next.workspace_id
        )));
    }
    // Narrowed at the call for the same reason the desired graph is: the exact
    // comparison below reads four domains, and holding the rest of a
    // whole-history snapshot beside them buys nothing.
    let rematerialized = {
        let _holder = tracing::info_span!("kindb.prepare.workspace.rematerialize").entered();
        WorkspaceGraphFacts::from_snapshot(materialize_workspace_graph_snapshot_from_base(
            next_base, &next, None,
        )?)
    };
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
        current.map(|workspace| &workspace.tree),
        "workspace tree",
    )?;
    workspaces.insert(mutation.workspace_id, next);
    metadata.workspaces = workspaces.into_values().collect();
    #[cfg(test)]
    WORKSPACE_MUTATION_BASE_RESOLUTIONS.with(|count| {
        count.set(WORKSPACE_BASE_RESOLUTIONS.with(|total| total.get()) - resolutions_before)
    });
    #[cfg(test)]
    WORKSPACE_MUTATION_BASE_CHANGES.with(|count| {
        count.set(WORKSPACE_BASE_CHANGES.with(|total| total.get()) - base_changes_before)
    });
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
    replay: &SharedReplayGraph<'_>,
    snapshot: &GraphSnapshot,
    metadata: &PersistedRepositoryAuthority,
    transaction: &RepositoryTransaction,
    source: NativeAdmissionSource,
) -> Result<(), KinDbError> {
    verify_workspace_admission(backend, current, replay, snapshot, metadata, transaction)?;
    verify_native_change_admission(backend, current, replay, metadata, transaction, source)
}

/// The exclusion-rule generation that judges what a transaction introduces.
///
/// Exclusion rules apply forward. Newly proposed artifacts are judged by the
/// policy generation that was already in force, never by the generation the
/// same transaction publishes, because that successor policy is derived from
/// the very tree it would be judging: `SharedAdmissionPolicy::derive_from_tree`
/// reads the desired tree's own `.gitignore` and `.kinignore` blobs. A
/// transaction that introduces a rule beside the untracked content that rule
/// newly excludes therefore refuted itself, and refuted itself identically on
/// every retry, because the rule file could never land. That is a livelock
/// rather than a refusal, and it is what judging by the predecessor resolves.
/// It is also what Git does: a new ignore rule does not reach back into what a
/// repository already holds.
///
/// The generation in force before a workspace mutation is the pre-transaction
/// state of that same workspace. A workspace this transaction creates has no
/// earlier generation at all, so the policy it publishes is the only one that
/// has ever applied to its content, and that policy judges it.
///
/// Two things deliberately stay at the successor generation. The frozen local
/// overlay is host configuration the caller records rather than anything
/// derived from the tree being judged, so it carries none of the circularity
/// above. Sensitive-artifact allowances stay on
/// `ArtifactAdmissionContext::policy`, because an allowance is an explicit
/// per-path grant naming an exact content hash and the transaction that records
/// one means to admit the artifact it approves.
///
/// Fail-loud is intact under the judging generation: content the rules already
/// in force exclude still fails the whole transaction, and every later proposal
/// is judged by the rule that just landed.
fn judging_shared_policy<'a>(
    previous_workspace: Option<&'a WorkspaceState>,
    published: &'a SharedAdmissionPolicy,
) -> &'a SharedAdmissionPolicy {
    previous_workspace
        .map(|previous| &previous.shared_admission_policy)
        .unwrap_or(published)
}

fn verify_workspace_admission<B: StorageBackend + ?Sized>(
    backend: &B,
    current: &RepositoryAuthorityState,
    replay: &SharedReplayGraph<'_>,
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
    let previous_workspace = current
        .metadata()
        .workspaces
        .iter()
        .find(|candidate| candidate.workspace_id == workspace.workspace_id);
    let overlay = local_overlay_for_workspace(metadata, workspace)?;
    let matcher = resolve_admission_matcher(
        backend,
        &transaction.repository_id,
        judging_shared_policy(previous_workspace, &workspace.shared_admission_policy),
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
    if let Some(previous) = previous_workspace {
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
            let base = replay.resolve_tree(change_id)?;
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
                case: overlay.case,
            },
        )?;
    }
    Ok(())
}

/// How a Native change that introduces artifacts reached this replica.
///
/// The v3 contract binds one Native admission to the workspace that publishes
/// it, and that binding is right for a local publish: it is what proves an
/// artifact entering repository authority is exactly what a real workspace held,
/// judged by the policy in force and that workspace's overlay.
///
/// A replica admitting a transfer performed no such publication. It has no
/// successor workspace, and asking it to produce one would have it vouch for an
/// admission it did not make. So a transfer is a distinct source rather than a
/// missing workspace, and it is checked by what a receiver can actually verify:
/// the shared policy, resolved from the transferred history, applied to every
/// introduced artifact with the full sensitive-content check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeAdmissionSource {
    /// Published by a workspace on this replica. Every leg of the v3 binding
    /// applies.
    LocalWorkspace,
    /// Admitted from another replica by exact repository-v6 transfer.
    ///
    /// `case` is the publisher's matcher semantics. `AdmissionCase` is authority
    /// and not a host hint: the same policy bytes decide differently under
    /// case-sensitive and ASCII-folded matching, so a receiver that invented one
    /// would be judging another replica's policy by rules it made up.
    ///
    /// It is optional, and the rule for when it is required is exact rather than
    /// cautious. `resolve_admission_matcher` compiles the case together with
    /// `rule_sets`, and on this path `rule_sets` comes from the shared policy's
    /// sources alone, because a transfer contributes no local sources. A shared
    /// policy with NO sources therefore compiles a matcher that matches nothing,
    /// and a matcher that matches nothing decides identically under either case.
    /// So a repository with no shared admission rules needs no case and `None`
    /// invents nothing there; a repository that has them is refused by name until
    /// the publisher's case travels with the transfer.
    Transfer {
        case: Option<crate::admission::AdmissionCase>,
    },
}

fn verify_native_change_admission<B: StorageBackend + ?Sized>(
    backend: &B,
    current: &RepositoryAuthorityState,
    replay: &SharedReplayGraph<'_>,
    metadata: &PersistedRepositoryAuthority,
    transaction: &RepositoryTransaction,
    source: NativeAdmissionSource,
) -> Result<(), KinDbError> {
    let native_changes = transaction
        .changes
        .iter()
        .filter(|change| matches!(change.origin, kin_model::ChangeOrigin::Native))
        .collect::<Vec<_>>();
    // A transaction with no Native change reaches no lineage at all, which is
    // what a Git import is: kin-git refuses a native-origin change inside a
    // semantic Git import, so every change it commits is Git-origin.
    if native_changes.is_empty() {
        return Ok(());
    }
    let authenticated_gitlinks = successor_authenticated_gitlinks(current, metadata, transaction);
    // Every tree this loop reads comes out of one pass over the changes'
    // shared first-parent lineage. Resolving them one at a time inside the
    // loop below walked that lineage once per change AND once per parent, so
    // an ordinary single-change commit re-derived the whole repository history
    // twice and a multi-change Native transaction was quadratic in its own
    // change count.
    let mut lineage_targets = Vec::with_capacity(native_changes.len() * 2);
    for change in &native_changes {
        lineage_targets.push(change.id);
        lineage_targets.extend(change.parents.iter().copied());
    }
    let resolved = replay.resolve_trees(&lineage_targets)?;
    let resolved_tree = |change_id: &SemanticChangeId| -> Result<&ResolvedTree, KinDbError> {
        resolved.get(change_id).ok_or_else(|| {
            storage(format!(
                "native admission resolved no tree for change {change_id}"
            ))
        })
    };
    for change in native_changes {
        let candidate = resolved_tree(&change.id)?;
        let mut parent_artifacts = BTreeSet::<ArtifactId>::new();
        for parent in &change.parents {
            let parent_tree = resolved_tree(parent)?;
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

        // The shared policy is the half a receiver can always resolve, because
        // `admission_policy_delta` rides inside the change itself and
        // `derive_admission_policies` re-derives it here. Both sources need it.
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

        // Held outside the match so the transfer arm's overlay outlives it.
        let transfer_overlay;
        let (workspace, overlay) = match source {
            NativeAdmissionSource::LocalWorkspace => {
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
                let overlay = local_overlay_for_workspace(metadata, workspace)?;
                (Some(workspace), overlay)
            }
            NativeAdmissionSource::Transfer { case } => {
                // A transfer performed no publication here, so the three
                // workspace legs above are not merely unavailable, they are not
                // this replica's to attest. What IS this replica's to decide is
                // whether the shared policy admits each artifact, and that is
                // checked in full below.
                //
                // The overlay carries no local rule sources, because the
                // publisher's personal excludes are already spent: a change
                // cannot exist on the sender unless it passed this same check
                // under them, and they are the sender's own file, so they never
                // bounded a hostile sender in the first place.
                //
                // The case is a different thing wearing the same struct.
                // `resolve_admission_matcher` ends in
                // `ResolvedAdmissionMatcher::compile(overlay.case, rule_sets)`
                // where `rule_sets` includes the SHARED sources, so the case
                // decides how the repository's own policy matches every path.
                //
                // The RECEIVER supplies it, and it is its own: every other
                // admission decision this replica makes already runs under that
                // case, and a transfer deciding differently would leave one
                // store enforcing two rules depending on whether content
                // arrived locally or over the wire. There is no safe default to
                // pick on its behalf either, because folding makes exclusion
                // rules match more paths AND makes their negations match more,
                // so neither case is uniformly stricter; the test
                // `a_negation_makes_folding_permissive_where_the_tidy_story_says_strict`
                // is that pair.
                //
                // Required exactly when it can change an answer, which is when
                // the shared policy has sources for the matcher to compile.
                let case = match (case, policy.sources.is_empty()) {
                    (Some(case), _) => case,
                    // No shared rules, so the matcher matches nothing and both
                    // cases decide alike. Picking one invents nothing.
                    (None, true) => crate::admission::AdmissionCase::Sensitive,
                    (None, false) => {
                        return Err(ModelError::InvalidOperation(format!(
                            "native change {} arrived by transfer against a shared admission \
                             policy with {} rule source(s), and its receiver named no admission \
                             case to decide under; the same policy bytes admit different paths \
                             under case-sensitive and ASCII-folded matching, and neither is \
                             uniformly stricter, so a receiver that cannot name its own case \
                             cannot admit this",
                            change.id,
                            policy.sources.len()
                        ))
                        .into());
                    }
                };
                transfer_overlay =
                    FrozenLocalOverlay::new(WorkspaceId(uuid::Uuid::nil()), 0, case, Vec::new())
                        .map_err(KinDbError::from)?;
                (None, &transfer_overlay)
            }
        };
        // A transfer has no workspace here, so it has no previous workspace
        // either. Everything below reads that as "nothing was tracked", which
        // is what makes the receiver run the FULL sensitive-content check on
        // every introduced artifact rather than skipping the ones a local
        // publish would have already had.
        let previous_workspace = workspace.and_then(|workspace| {
            current
                .metadata()
                .workspaces
                .iter()
                .find(|candidate| candidate.workspace_id == workspace.workspace_id)
        });
        // The generation in force before this change is its first parent's, and
        // a root change has no parent, so the workspace it is bound to supplies
        // the one that was in force. See `judging_shared_policy`: a change that
        // carries a new rule file is derived from the same tree the rule would
        // judge, so judging it by its own generation is the FIR-2348 livelock.
        let judging = change
            .parents
            .first()
            .and_then(|parent| {
                metadata
                    .admission_policies
                    .iter()
                    .find(|resolved| resolved.change_id == *parent)
            })
            .and_then(|resolved| resolved.policy.as_ref())
            .unwrap_or_else(|| judging_shared_policy(previous_workspace, policy));
        let matcher =
            resolve_admission_matcher(backend, &transaction.repository_id, judging, overlay)?;
        // An artifact the pre-transaction workspace already carried is already
        // repository authority, exactly as `verify_workspace_admission` treats
        // it. The parent comparison above cannot see that on its own: a change
        // publishing an already-admitted workspace tree introduces every path
        // its parent lacks, including paths an earlier generation admitted
        // under the rules that were in force then.
        let workspace_tracked = previous_workspace
            .map(|previous| {
                previous
                    .tree
                    .artifacts()
                    .map(|artifact| artifact.artifact_id)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
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
                    tracked: workspace_tracked.contains(&artifact.artifact_id),
                    gitlink_is_admitted,
                    label: &format!("native change {}", change.id),
                    case: overlay.case,
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
    /// The case the matcher was compiled under, carried so a refusal can name
    /// it. `ResolvedAdmissionMatcher` keeps its own copy private and lives in
    /// another crate, and the overlay that supplied it is in scope at both call
    /// sites, so this reads it from there rather than widening kin-model's API.
    case: crate::admission::AdmissionCase,
}

/// Name the rule that decided an exclusion.
///
/// A refusal that says only "excluded by the exact graph-owned admission policy"
/// tells a reader that something matched and not what, so the next step is to
/// guess. `AdmissionDecisionReason` already carries the source, the line, the
/// pattern and whether it was negated; this renders them.
fn describe_admission_exclusion(reason: &crate::admission::AdmissionDecisionReason) -> String {
    fn source_name(source: &ResolvedAdmissionRuleSource) -> String {
        match source {
            ResolvedAdmissionRuleSource::Shared { source_path } => source_path.to_string(),
            ResolvedAdmissionRuleSource::GlobalExclude => "the global excludes".to_string(),
            ResolvedAdmissionRuleSource::InfoExclude => "the info excludes".to_string(),
            ResolvedAdmissionRuleSource::KinLocal { ordinal } => {
                format!("local rule set {ordinal}")
            }
            ResolvedAdmissionRuleSource::CommandLine { ordinal } => {
                format!("command-line rule set {ordinal}")
            }
        }
    }
    fn rule(provenance: &crate::admission::AdmissionRuleProvenance) -> String {
        format!(
            "{}pattern {:?} at {} line {}",
            if provenance.negated { "negated " } else { "" },
            String::from_utf8_lossy(&provenance.pattern),
            source_name(&provenance.source),
            provenance.line
        )
    }
    match reason {
        crate::admission::AdmissionDecisionReason::Rule(provenance) => rule(provenance),
        crate::admission::AdmissionDecisionReason::IgnoredAncestor {
            ancestor,
            rule: provenance,
        } => format!("ancestor {ancestor} excluded by {}", rule(provenance)),
        // These three ADMIT, so reaching them behind `is_ignored()` means the
        // decision and its reason disagree. Say that rather than invent a rule.
        other => format!("no rule recorded, which disagrees with the decision: {other:?}"),
    }
}

/// Judge one proposed artifact against the exact rules that bind it.
///
/// The two halves answer to different generations on purpose. `matcher` carries
/// the exclusion rules that were in force BEFORE this transaction, which is the
/// contract `judging_shared_policy` states and the reason a transaction can
/// introduce an ignore rule at all. `context.policy` carries the successor's
/// sensitive-artifact allowances, so a transaction that records an allowance
/// admits the artifact it approves. Neither half is skipped: an artifact the
/// standing rules exclude, and untracked sensitive content with no allowance,
/// each fail the whole transaction.
fn verify_artifact_admission<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    matcher: &ResolvedAdmissionMatcher,
    artifact: &ResolvedArtifact,
    context: ArtifactAdmissionContext<'_>,
) -> Result<(), KinDbError> {
    let decision = matcher.decide(&artifact.path, false, context.tracked);
    if decision.is_ignored() {
        let (applied, other) = match context.case {
            crate::admission::AdmissionCase::Sensitive => ("case-sensitive", "ASCII-folded"),
            crate::admission::AdmissionCase::FoldAscii => ("ASCII-folded", "case-sensitive"),
        };
        return Err(ModelError::InvalidOperation(format!(
            "{} artifact {} is excluded by the exact graph-owned admission policy: {}, matched \
             under {} matching, which is the case this replica admits under; {} matching can \
             decide the same policy bytes differently",
            context.label,
            artifact.path,
            describe_admission_exclusion(&decision.reason),
            applied,
            other
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

/// One shared replay decode of an immutable authority-free snapshot payload.
///
/// Successor preparation needs the same decoded graph several times: admission
/// verification resolves base and candidate trees, workspace validation hashes
/// target trees, and history replay proves the whole payload decodes into a
/// coherent graph. Each of those callers used to clone the entire snapshot and
/// rebuild the graph from scratch, so one commit paid for the whole store four
/// or more times over, and every rebuild repeated the same canonical content
/// hashing. The payload cannot change underneath the sharing: `changes` is
/// final once `admit_changes` returns, every later preparation step mutates
/// only the detached authority metadata, and the single-writer permit
/// serializes the whole preparation.
///
/// The proof that remains is the history-coherence proof itself: storage
/// admission over the authority-free payload, and the derivation of every
/// entity revision timeline, exactly as each discarded rebuild did. Both are
/// fail-closed and both read the snapshot, so neither needs to own it, and
/// neither result was ever read: the decoded graph was only ever asked to
/// resolve trees, which reads the change map alone.
///
/// So this holds the borrowed snapshot rather than a decoded copy of it.
/// Building an `InMemoryGraph` here meant cloning the whole snapshot in order
/// to null `repository_authority` and then rebuilding every index, adjacency
/// map and Merkle root from the clone, and keeping all of it alive until the
/// preparation ended. On a full-history brownfield conversion that is a second
/// copy of the entire repository, retained across the phase where the peak is
/// reached, to answer a question the snapshot itself already answers. The field
/// this cloned to null is, in `prepare_successor`, already `None`: the caller
/// takes the authority out before the replay is created.
struct SharedReplayGraph<'a> {
    snapshot: &'a GraphSnapshot,
    admitted: Option<AdmittedChangeMap<'a>>,
    proven: std::cell::OnceCell<()>,
    proof_runs: std::cell::Cell<u32>,
    build_ms: std::cell::Cell<u128>,
}

impl<'a> SharedReplayGraph<'a> {
    fn new(snapshot: &'a GraphSnapshot) -> Self {
        Self::new_with_admission(snapshot, None)
    }

    /// Build a replay view whose proof may carry an existing admission of
    /// `snapshot`'s change map instead of repeating the pass.
    ///
    /// `None` validates exactly as `new` does, so a caller without a witness
    /// is slower and never less safe.
    fn new_with_admission(
        snapshot: &'a GraphSnapshot,
        admitted: Option<&AdmittedChangeMap<'a>>,
    ) -> Self {
        Self {
            snapshot,
            admitted: admitted.copied(),
            proven: std::cell::OnceCell::new(),
            proof_runs: std::cell::Cell::new(0),
            build_ms: std::cell::Cell::new(0),
        }
    }

    /// Prove the payload decodes, once, and remember that it did.
    ///
    /// Every query below runs this first, so a payload that fails the proof
    /// never answers a tree question, which is the order the decode enforced
    /// when it owned the query surface.
    fn prove(&self) -> Result<(), KinDbError> {
        if self.proven.get().is_none() {
            let started = std::time::Instant::now();
            self.proof_runs.set(self.proof_runs.get() + 1);
            // The witness, when there is one, was minted for this very map:
            // nothing is cloned here, so the pointer identity `describes`
            // checks holds outright instead of being carried onto a copy.
            InMemoryGraph::prove_authority_free_snapshot_decode(
                self.snapshot,
                self.admitted.as_ref(),
            )?;
            self.build_ms.set(started.elapsed().as_millis());
            let _ = self.proven.set(());
        }
        Ok(())
    }

    /// Milliseconds spent proving the payload, zero when it was never needed.
    fn build_ms(&self) -> u128 {
        self.build_ms.get()
    }

    /// How many times the proof actually ran. Instrumentation for the test that
    /// asserts the sharing works; nothing in the engine reads it.
    #[cfg(test)]
    fn proof_runs(&self) -> u32 {
        self.proof_runs.get()
    }

    fn resolve_tree(&self, change_id: SemanticChangeId) -> Result<ResolvedTree, KinDbError> {
        self.resolve_trees(&[change_id])?
            .remove(&change_id)
            .ok_or_else(|| {
                storage(format!(
                    "shared replay resolved no tree for change {change_id}"
                ))
            })
    }

    /// Resolve several changes' trees in one pass over their shared lineage.
    ///
    /// Asking for each tree separately re-walks the same first-parent history
    /// once per request, so a caller holding `M` changes over a history of
    /// depth `D` pays `M * D` steps for a fold that is `D` steps long. One
    /// batch pays the lineage once and copies a tree only where one was asked
    /// for.
    ///
    /// The fold reads the change map and nothing else, which is why the graph
    /// this used to decode was never needed. It went through the graph's own
    /// batch resolver, whose whole body was this same call against a change map
    /// cloned out of this same snapshot; that resolver had no other caller and
    /// is gone with the decode.
    fn resolve_trees(
        &self,
        change_ids: &[SemanticChangeId],
    ) -> Result<BTreeMap<SemanticChangeId, ResolvedTree>, KinDbError> {
        self.prove()?;
        crate::storage::history_replay::resolve_first_parent_trees(
            &self.snapshot.changes,
            change_ids,
        )
    }
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
    // A journal-free proof describes exactly the base bytes; a proof that also
    // names an acknowledged frame chain describes exactly the base plus that
    // chain, and neither describes the other.
    let journal_matches = match (&proof.journal_sha256, &recovered.journal_sha256) {
        (None, None) => recovered.deltas_applied == 0,
        (Some(claimed), Some(applied)) => recovered.deltas_applied != 0 && claimed == applied,
        _ => false,
    };
    let matches = proof.validator_version == HISTORY_VALIDATION_VERSION
        && proof.repository_id == repository_id.as_str()
        && proof.generation == recovered.generation
        && proof.snapshot_sha256 == recovered.snapshot_sha256
        && journal_matches;
    matches.then_some(recovered.generation)
}

fn validate_history_replay(
    snapshot: &GraphSnapshot,
    new_changes: &[kin_model::SemanticChange],
) -> Result<(), KinDbError> {
    validate_history_replay_with(&SharedReplayGraph::new(snapshot), snapshot, new_changes)
}

fn validate_history_replay_with(
    replay: &SharedReplayGraph<'_>,
    snapshot: &GraphSnapshot,
    new_changes: &[kin_model::SemanticChange],
) -> Result<(), KinDbError> {
    // One Kahn pass over the whole change map proves the DAG is acyclic and
    // that every declared parent is persisted. Resolving each change's reachable
    // order separately re-derives exactly that, so the per-change traversal the
    // replay below replaces carried no proof this does not already hold.
    topological_change_order(&snapshot.changes)?;

    // Proving the snapshot decodes into a coherent graph is part of the proof
    // rather than a convenience: it revalidates storage admission over the
    // authority-free payload and derives every entity revision timeline, both
    // of which fail closed. It is one pass over the snapshot, not per change,
    // and it proves graph truth rather than serving queries, so it needs
    // neither a text index nor a decoded copy of the payload to keep. The
    // shared proof is that exact pass: an earlier preparation step may already
    // have paid for it, and asking for it here proves it.
    replay.prove()?;

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
    validate_first_parent_history(&snapshot.changes, &validation_targets)
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
    admitted: Option<&AdmittedChangeMap<'_>>,
) -> Result<GraphSnapshot, KinDbError> {
    let base = resolve_workspace_base_graph_snapshot(
        authority_snapshot,
        metadata,
        workspace.base_target.as_ref(),
        WorkspaceBaseHistory::Carried(admitted),
    )?;
    materialize_workspace_graph_snapshot_from_base(base, workspace, admitted)
}

/// Materialize a workspace over a base graph the caller already resolved.
///
/// The base a workspace materializes over is a pure function of its
/// `base_target`, so a caller holding the exact base for this workspace's
/// target may hand it in rather than replaying the same history again. Every
/// check below is the one the resolving entry point runs; nothing is skipped
/// because the base arrived by argument.
fn materialize_workspace_graph_snapshot_from_base(
    base: GraphSnapshot,
    workspace: &WorkspaceState,
    admitted: Option<&AdmittedChangeMap<'_>>,
) -> Result<GraphSnapshot, KinDbError> {
    let mut delta = workspace.semantic_overlay.transaction_delta();
    delta.tree_deltas = exact_tree_transition(&base.resolved_tree, &workspace.tree);
    // A clean workspace, based at its exact tree with an empty semantic
    // overlay, IS its resolved base. Pushing an empty transaction through a
    // full graph build only copies every domain it was handed: the build
    // re-validates admission, re-derives relation and entity indexes, clones
    // the entity map to stage nothing, and exports a copy of its own input.
    // A daemon reopening after a commit holds exactly this workspace shape,
    // which made that copy a dominant term of cold open at repository scale.
    // The base was admission-validated when it was resolved; a second pass
    // over the same object would re-hash every change to conclude nothing.
    if delta.entity_deltas.is_empty()
        && delta.relation_deltas.is_empty()
        && delta.tree_deltas.is_empty()
        && delta.external_reference_deltas.is_empty()
        && delta.admission_policy_delta.is_none()
    {
        if base.resolved_tree != workspace.tree {
            return Err(storage(format!(
                "workspace {} semantic overlay did not resolve its exact persisted tree",
                workspace.workspace_id
            )));
        }
        return Ok(base);
    }
    // Materialization consumes this graph as a snapshot and drops it. Building a
    // text index for it would index every entity to answer no query: the caller
    // holding the workspace open builds its own against the persistent index.
    let mut timer = PublicationPhaseTimer::start();
    // CARRY SITE: `base.changes` came from `resolve_workspace_base_graph_snapshot`,
    // which clones it from the map `admitted` witnesses.
    let graph = match admitted {
        Some(admitted) => InMemoryGraph::from_admitted_snapshot_without_text_index(base, admitted)?,
        None => InMemoryGraph::from_snapshot_without_text_index(base)?,
    };
    let build_graph_ms = timer.lap_ms();
    graph.apply_transaction_delta(&delta)?;
    let apply_delta_ms = timer.lap_ms();
    // The delta is absorbed and only its shape is reported below, so hold the
    // three counts and free the payload rather than carrying a second copy of
    // the workspace's whole overlay through the export and the admission pass.
    let (entity_delta_count, relation_delta_count, tree_delta_count) = (
        delta.entity_deltas.len(),
        delta.relation_deltas.len(),
        delta.tree_deltas.len(),
    );
    drop(delta);
    // The export is the graph's last reader, so it consumes the graph. Copying
    // it out instead held a whole second copy of everything `materialized`
    // carries across the admission pass below, which at repository scale is
    // one more whole history.
    let materialized = graph.into_snapshot();
    let to_snapshot_ms = timer.lap_ms();
    if materialized.resolved_tree != workspace.tree {
        return Err(storage(format!(
            "workspace {} semantic overlay did not resolve its exact persisted tree",
            workspace.workspace_id
        )));
    }
    // CARRY SITE: the graph took its change map from `base` and a workspace
    // transaction delta carries entity, relation, tree and external-reference
    // deltas only, so `materialized.changes` is that same map.
    match admitted {
        Some(admitted) => {
            let carried = AdmittedChangeMap::carried_from_clone(&materialized.changes, admitted);
            materialized
                .validate_storage_admission_carrying(GitProjectionTreeReplay::Required, &carried)?;
        }
        None => materialized.validate_storage_admission()?,
    }
    let admission_ms = timer.lap_ms();
    tracing::debug!(
        target: "kin_db::admission",
        build_graph_ms,
        apply_delta_ms,
        to_snapshot_ms,
        admission_ms,
        entity_deltas = entity_delta_count,
        relation_deltas = relation_delta_count,
        tree_deltas = tree_delta_count,
        "workspace graph materialization"
    );
    #[cfg(test)]
    record_preparation_phase(
        "workspace_materialization",
        vec![
            ("build_graph_ms", build_graph_ms),
            ("apply_delta_ms", apply_delta_ms),
            ("to_snapshot_ms", to_snapshot_ms),
            ("admission_ms", admission_ms),
        ],
    );
    Ok(materialized)
}

/// Borrowed change-history view for whole-graph replay during workspace base
/// resolution.
///
/// `ChangeStore::resolve_graph_at` is a kin-model default method whose only
/// store dependency is `get_change`. Base resolution used to reach it by
/// cloning the entire authority snapshot into a throwaway `InMemoryGraph`,
/// paying a second full-snapshot copy, an admission validation, relation and
/// entity index builds, and a Merkle cache, all discarded after one replay.
/// This view serves the identical replay from borrowed authority changes.
///
/// The store methods replay never reads fail closed: nothing on the
/// materialization path can reach them, and a future caller that does must be
/// refused rather than silently served an empty answer.
struct AuthorityHistoryView<'a> {
    changes: &'a HashMap<SemanticChangeId, SemanticChange>,
}

impl AuthorityHistoryView<'_> {
    fn unsupported(operation: &str) -> KinDbError {
        storage(format!(
            "{operation} is unavailable through a workspace materialization history view"
        ))
    }
}

impl ChangeStore for AuthorityHistoryView<'_> {
    type Error = KinDbError;

    fn get_change(&self, id: &SemanticChangeId) -> Result<Option<SemanticChange>, KinDbError> {
        Ok(self.changes.get(id).cloned())
    }

    fn get_entity_history(&self, _id: &EntityId) -> Result<Vec<SemanticChange>, KinDbError> {
        Err(Self::unsupported("entity history"))
    }

    fn find_merge_bases(
        &self,
        _a: &SemanticChangeId,
        _b: &SemanticChangeId,
    ) -> Result<Vec<SemanticChangeId>, KinDbError> {
        Err(Self::unsupported("merge-base search"))
    }

    fn create_change(&self, _change: &SemanticChange) -> Result<(), KinDbError> {
        Err(Self::unsupported("change creation"))
    }

    fn get_changes_since(
        &self,
        _base: &SemanticChangeId,
        _head: &SemanticChangeId,
    ) -> Result<Vec<SemanticChange>, KinDbError> {
        Err(Self::unsupported("change-range listing"))
    }
}

/// Name the change a workspace base target resolves to.
///
/// `resolve_workspace_base_graph_snapshot` consumes `base_target` only to reach
/// this change id, so two targets that name the same change resolve to the same
/// base graph and one resolution serves both. Comparing resolved ids rather
/// than targets is what makes that true for a branch and an explicit change
/// that currently agree.
fn workspace_base_change_id(
    metadata: &PersistedRepositoryAuthority,
    base_target: Option<&RefTarget>,
) -> Result<Option<SemanticChangeId>, KinDbError> {
    match base_target {
        Some(target) => Ok(Some(target_change_id(metadata, target)?)),
        None => Ok(None),
    }
}

#[cfg(test)]
thread_local! {
    /// Base-graph resolutions performed on this thread, ever.
    ///
    /// Read only as the endpoints of a span; the running total is meaningless
    /// on its own because open-time and storage-admission validation resolve
    /// bases too.
    static WORKSPACE_BASE_RESOLUTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };

    /// Base graphs resolved by the last workspace mutation to complete on this
    /// thread.
    ///
    /// Resolution is the expensive half of a workspace mutation, and the
    /// mutation's own contract fixes how many distinct bases it names, so this
    /// is a contract worth pinning rather than a timing observation. Each test
    /// runs on its own thread, so a test reads this without another test's
    /// transactions reaching it.
    static WORKSPACE_MUTATION_BASE_RESOLUTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };

    /// Base graphs answered from a persisted materialized graph section.
    static BASE_GRAPHS_SERVED_FROM_SECTION: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };

    /// Base graphs folded out of history because no section answered.
    ///
    /// Counted separately from the serves rather than derived by subtraction.
    /// A test asserting "no replay happened" needs a zero it can read directly,
    /// and a zero computed as `total - served` is satisfied by an instrument
    /// that counts nothing at all.
    static BASE_GRAPHS_RESOLVED_FROM_HISTORY: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };

    /// Changes carried by every base graph resolved on this thread, summed.
    ///
    /// Read only as the endpoints of a span, for the same reason the
    /// resolution total is.
    static WORKSPACE_BASE_CHANGES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };

    /// Changes carried by the base graphs the last workspace mutation to
    /// complete on this thread resolved, summed.
    ///
    /// A workspace mutation compares entities, relations, external references
    /// and the resolved tree, and reaches no change through a base, so this is
    /// zero. It sums the maps that were actually built rather than flagging
    /// what was asked for, so it moves both when a call site asks for the
    /// history back and when the resolver starts carrying it whatever it was
    /// asked. Each test runs on its own thread, so a test reads this without
    /// another test's transactions reaching it.
    static WORKSPACE_MUTATION_BASE_CHANGES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Whether a resolved workspace base carries the repository's change map.
///
/// A base is read two ways. A daemon serving a workspace graph queries it, so
/// it needs every domain the repository has. A workspace mutation compares four
/// domains, entities, relations, external references and the resolved tree, and
/// reads no change through its base at all: `derive_workspace_semantic_overlay`
/// consults three of those four, `WorkspaceGraphFacts` keeps exactly those four,
/// and `apply_transaction_delta` touches no history domain.
///
/// Carrying the map into the second kind costs a whole copy of it per
/// resolution, and on a full-history conversion the change map IS the
/// repository. It costs a second time through the graph built over that base,
/// which derives an entity revision timeline across the entire history because
/// the derivation is gated on the map being non-empty, and then drops every one
/// of them at the export that keeps four domains.
///
/// Omitting it removes no proof. A base sets `repository_authority` to `None`,
/// and the envelope is the only part of storage admission that reads the change
/// map for anything beyond admitting the map itself, so a base's copy re-proves
/// a map this same preparation admitted at `kindb.prepare.admit` and proves
/// again over the authority's own map at `kindb.prepare.history_replay`. A
/// relation endpoint is an entity, artifact, test, contract, work item,
/// verification run or external reference and never a change, so the endpoint
/// pass cannot weaken either.
/// A resolved base graph captured for persistence, and the guard that it is
/// complete.
///
/// Its own module for one reason, and the reason is the whole point: the fields
/// are private, and the single constructor takes a `ResolvedGraphState` whole.
/// Nothing outside can assemble one from a base snapshot's fields, which is the
/// mistake that would otherwise be easy to make and impossible to see, because
/// `resolve_workspace_base_graph_snapshot` moves five of the seven domains into
/// the base it returns and drops the two tombstone maps. A section built from
/// that reassembly would carry empty tombstones and look exactly like a
/// complete one.
///
/// So the writer has two states and no third: it holds a capture taken before
/// anything was destructured, or it holds nothing and writes `None`. A partial
/// section is unrepresentable rather than merely discouraged.
mod captured_base_graph {
    use crate::storage::format::{MaterializedGraphSection, MATERIALIZED_GRAPH_SCHEMA_VERSION};
    use crate::types::{ResolvedGraphState, SemanticChangeId};

    /// The complete resolution at one change, and the change it resolves at.
    #[derive(Debug, Clone)]
    pub(super) struct CapturedBaseGraph {
        resolved_at: SemanticChangeId,
        state: ResolvedGraphState,
    }

    impl CapturedBaseGraph {
        /// Take a capture from a state no field has left yet.
        ///
        /// The only way to build one. It takes the state by value, so a caller
        /// that has already moved a domain out cannot reach here.
        pub(super) fn capture(resolved_at: SemanticChangeId, state: ResolvedGraphState) -> Self {
            Self { resolved_at, state }
        }

        /// The section these bytes become.
        pub(super) fn into_section(self) -> MaterializedGraphSection {
            MaterializedGraphSection {
                schema_version: MATERIALIZED_GRAPH_SCHEMA_VERSION,
                resolved_at: self.resolved_at,
                state: self.state,
            }
        }
    }
}

use captured_base_graph::CapturedBaseGraph;

/// Whether a base resolution keeps its resolved state for persistence.
///
/// Every resolution already computes the state; almost every caller wants only
/// the base snapshot built from it. `Retain` costs one clone of the resolved
/// graph, which is O(entities plus relations) and not another fold over
/// history. That distinction is the whole reason this is a parameter rather
/// than an unconditional capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkspaceBaseCapture {
    Discard,
    Retain,
}

enum WorkspaceBaseHistory<'a> {
    /// Carry the change map, with a witness when the caller holds one this
    /// base's copy can carry instead of repeating.
    Carried(Option<&'a AdmittedChangeMap<'a>>),
    /// Leave the change map out. A witness is unrepresentable here on purpose:
    /// carrying one onto an empty map would satisfy pointer identity while
    /// attesting nothing.
    Omitted,
}

/// The resolved graph at `change_id` from a persisted section, or why not.
///
/// Every refusal falls back to folding the history, which is always available
/// in the same file, so this can only ever cost time. That is the whole reason
/// a stale section is not fatal: nothing here is authority, and the thing it
/// memoizes is still sitting beside it.
///
/// What is deliberately NOT here is a re-derivation of the section to check it.
/// Recomputing `resolve_graph_at` to decide whether to use a memo of
/// `resolve_graph_at` would pay the entire cost this exists to avoid, every
/// time, and conclude what the change id already proves. The writer's own
/// obligation is checked where it can be acted on, on the write path.
fn resolved_graph_from_section(
    authority_snapshot: &GraphSnapshot,
    change_id: &SemanticChangeId,
) -> Result<ResolvedGraphState, MaterializedGraphRefusal> {
    let section = authority_snapshot
        .materialized_graph
        .as_ref()
        .ok_or(MaterializedGraphRefusal::Absent)?;
    section.validate_for(change_id)?;
    Ok(section.state.clone())
}

fn resolve_workspace_base_graph_snapshot(
    authority_snapshot: &GraphSnapshot,
    metadata: &PersistedRepositoryAuthority,
    base_target: Option<&RefTarget>,
    history: WorkspaceBaseHistory<'_>,
) -> Result<GraphSnapshot, KinDbError> {
    resolve_workspace_base_graph_snapshot_capturing(
        authority_snapshot,
        metadata,
        base_target,
        history,
        WorkspaceBaseCapture::Discard,
    )
    .map(|(base, _)| base)
}

/// Resolve a workspace base, optionally keeping the resolved state.
///
/// The capture is taken from the state `resolve_graph_at` returned, BEFORE the
/// base below moves five of its seven domains out. Taking it afterwards is what
/// would silently lose the tombstones.
fn resolve_workspace_base_graph_snapshot_capturing(
    authority_snapshot: &GraphSnapshot,
    metadata: &PersistedRepositoryAuthority,
    base_target: Option<&RefTarget>,
    history: WorkspaceBaseHistory<'_>,
    capture: WorkspaceBaseCapture,
) -> Result<(GraphSnapshot, Option<CapturedBaseGraph>), KinDbError> {
    #[cfg(test)]
    WORKSPACE_BASE_RESOLUTIONS.with(|count| count.set(count.get() + 1));
    // Replay-derived domains first. The whole-snapshot clone this function
    // used to start from copied every one of them only to overwrite or clear
    // them, and fed a second full clone into a throwaway `InMemoryGraph`
    // whose admission pass, relation and entity indexes, and Merkle cache
    // were discarded after one history replay.
    let mut timer = PublicationPhaseTimer::start();
    let mut captured: Option<CapturedBaseGraph> = None;
    // Resolved once and reused: the capture below names the same change the
    // section is the resolution at, and computing it twice would let the two
    // drift.
    let base_change = base_target
        .map(|target| target_change_id(metadata, target))
        .transpose()?;
    let resolved = match base_change {
        Some(change_id) => {
            Some(
                match resolved_graph_from_section(authority_snapshot, &change_id) {
                    Ok(state) => {
                        #[cfg(test)]
                        BASE_GRAPHS_SERVED_FROM_SECTION.with(|count| count.set(count.get() + 1));
                        // Both paths are timed by the same `history_resolve_ms`
                        // below, and a served base makes it small. Without a
                        // line here a reader sees a small number and no way to
                        // tell whether the fold got faster or never ran, which
                        // is a measurement surface that cannot be read. Every
                        // outcome now says which path produced the timing.
                        tracing::debug!(
                            change = %change_id,
                            entities = state.entities.len(),
                            relations = state.relations.len(),
                            "served the workspace base from a materialized graph section"
                        );
                        state
                    }
                    Err(refusal) => {
                        #[cfg(test)]
                        BASE_GRAPHS_RESOLVED_FROM_HISTORY.with(|count| count.set(count.get() + 1));
                        // Absent is the ordinary case on every store written
                        // before v14 and on every workspace whose base has
                        // moved since the last full snapshot, so it is not a
                        // warning. The other reasons are, because each of them
                        // means a section was written and is not being used.
                        if matches!(refusal, MaterializedGraphRefusal::Absent) {
                            tracing::trace!(
                                change = %change_id,
                                "no materialized graph section for this base; folding it from history"
                            );
                        } else {
                            tracing::warn!(
                                refusal = %refusal,
                                change = %change_id,
                                "refused the materialized graph section; folding the base from history instead"
                            );
                        }
                        let view = AuthorityHistoryView {
                            changes: &authority_snapshot.changes,
                        };
                        view.resolve_graph_at(&change_id)?
                    }
                },
            )
        }
        None => None,
    };
    let history_resolve_ms = timer.lap_ms();
    // Taken here and nowhere else. Below, five of this state's seven domains
    // move into the base and the two tombstone maps are dropped, so a capture
    // taken after this point could only ever be a reassembly carrying empty
    // tombstones. `CapturedBaseGraph::capture` takes the state whole, and its
    // module gives it no other constructor.
    if capture == WorkspaceBaseCapture::Retain {
        if let (Some(state), Some(change_id)) = (resolved.as_ref(), base_change) {
            captured = Some(CapturedBaseGraph::capture(change_id, state.clone()));
        }
    }
    let (entities, relations, entity_revisions, resolved_tree, external_references) = match resolved
    {
        Some(state) => (
            state.entities,
            state.relations,
            state.entity_revisions,
            state.tree,
            state.external_references,
        ),
        None => (
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            ResolvedTree::default(),
            HashMap::new(),
        ),
    };
    // Every field is named so that a new snapshot domain refuses to compile
    // here until someone decides whether a workspace base carries it. The
    // carried domains are cloned exactly as the whole-snapshot clone carried
    // them; adjacency is rebuilt below from the resolved relations, so the
    // persisted authority adjacency is never copied at all.
    let mut base = GraphSnapshot {
        version: authority_snapshot.version,
        entities,
        relations,
        outgoing: HashMap::new(),
        incoming: HashMap::new(),
        changes: match history {
            WorkspaceBaseHistory::Carried(_) => authority_snapshot.changes.clone(),
            WorkspaceBaseHistory::Omitted => ChangeMap::new(),
        },
        change_children: match history {
            WorkspaceBaseHistory::Carried(_) => authority_snapshot.change_children.clone(),
            WorkspaceBaseHistory::Omitted => HashMap::new(),
        },
        work_items: authority_snapshot.work_items.clone(),
        annotations: authority_snapshot.annotations.clone(),
        work_links: authority_snapshot.work_links.clone(),
        reviews: authority_snapshot.reviews.clone(),
        review_decisions: authority_snapshot.review_decisions.clone(),
        review_notes: authority_snapshot.review_notes.clone(),
        review_discussions: authority_snapshot.review_discussions.clone(),
        review_assignments: authority_snapshot.review_assignments.clone(),
        test_cases: authority_snapshot.test_cases.clone(),
        assertions: authority_snapshot.assertions.clone(),
        verification_runs: authority_snapshot.verification_runs.clone(),
        mock_hints: authority_snapshot.mock_hints.clone(),
        contracts: authority_snapshot.contracts.clone(),
        actors: authority_snapshot.actors.clone(),
        delegations: authority_snapshot.delegations.clone(),
        approvals: authority_snapshot.approvals.clone(),
        audit_events: authority_snapshot.audit_events.clone(),
        shallow_files: authority_snapshot.shallow_files.clone(),
        file_layouts: authority_snapshot.file_layouts.clone(),
        structured_artifacts: authority_snapshot.structured_artifacts.clone(),
        opaque_artifacts: authority_snapshot.opaque_artifacts.clone(),
        resolved_tree,
        sessions: authority_snapshot.sessions.clone(),
        intents: authority_snapshot.intents.clone(),
        downstream_warnings: authority_snapshot.downstream_warnings.clone(),
        entity_revisions,
        repository_authority: None,
        external_references,
        // A workspace base is not a published authority snapshot: it carries no
        // envelope, so there is no change it can claim to be the resolution at
        // and nothing a reader could validate a section against.
        materialized_graph: None,
    };
    let domain_clone_ms = timer.lap_ms();
    rebuild_snapshot_adjacency(&mut base);
    let adjacency_ms = timer.lap_ms();
    // CARRY SITE: `base.changes` is `authority_snapshot.changes.clone()`, made
    // in the struct literal above, and `admitted` witnesses that same map. It
    // is reachable only under `Carried`, where that clone happened.
    match history {
        WorkspaceBaseHistory::Carried(Some(admitted)) => {
            let carried = AdmittedChangeMap::carried_from_clone(&base.changes, admitted);
            base.validate_storage_admission_carrying(GitProjectionTreeReplay::Required, &carried)?;
        }
        WorkspaceBaseHistory::Carried(None) | WorkspaceBaseHistory::Omitted => {
            base.validate_storage_admission()?
        }
    }
    let admission_ms = timer.lap_ms();
    tracing::debug!(
        target: "kin_db::admission",
        history_resolve_ms,
        domain_clone_ms,
        adjacency_ms,
        admission_ms,
        "workspace base graph resolution"
    );
    #[cfg(test)]
    record_preparation_phase(
        "workspace_base_resolution",
        vec![
            ("history_resolve_ms", history_resolve_ms),
            ("domain_clone_ms", domain_clone_ms),
            ("adjacency_ms", adjacency_ms),
            ("admission_ms", admission_ms),
        ],
    );
    #[cfg(test)]
    WORKSPACE_BASE_CHANGES.with(|count| count.set(count.get() + base.changes.len()));
    Ok((base, captured))
}

fn derive_workspace_semantic_overlay(
    base: &GraphSnapshot,
    desired: &WorkspaceGraphFacts,
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
    desired: &WorkspaceGraphFacts,
    rematerialized: &WorkspaceGraphFacts,
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
    admitted: Option<&AdmittedChangeMap<'_>>,
) -> Result<(), KinDbError> {
    // One decode serves every workspace's base-tree check instead of one
    // rebuild per workspace.
    let replay = SharedReplayGraph::new_with_admission(snapshot, admitted);
    for workspace in &metadata.workspaces {
        validate_workspace_state(&replay, snapshot, metadata, workspace, admitted)?;
        for artifact in workspace.tree.artifacts() {
            workspace_artifact_projection_mtime(metadata, workspace, artifact.artifact_id)?;
        }
    }
    Ok(())
}

/// Validate one persisted workspace, including that it still materializes.
///
/// The materialization at the end is the check that the persisted head, base,
/// tree, overlay and policy still resolve to a coherent graph. A caller that
/// materializes this workspace itself proves that and more, and calls
/// [`validate_workspace_state_without_materialization`] instead of paying for a
/// second one it discards.
fn validate_workspace_state(
    replay: &SharedReplayGraph<'_>,
    snapshot: &GraphSnapshot,
    metadata: &PersistedRepositoryAuthority,
    workspace: &WorkspaceState,
    admitted: Option<&AdmittedChangeMap<'_>>,
) -> Result<(), KinDbError> {
    validate_workspace_state_without_materialization(replay, snapshot, metadata, workspace)?;
    materialize_workspace_graph_snapshot(snapshot, metadata, workspace, admitted)?;
    Ok(())
}

fn validate_workspace_state_without_materialization(
    replay: &SharedReplayGraph<'_>,
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
        let expected_tree = resolve_target_tree_hash(replay, metadata, base)?;
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
    replay: &SharedReplayGraph<'_>,
    metadata: &PersistedRepositoryAuthority,
    target: &RefTarget,
) -> Result<Hash256, KinDbError> {
    let change_id = target_change_id(metadata, target)?;
    let tree = replay.resolve_tree(change_id)?;
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
#[cfg_attr(test, derive(PartialEq, Eq))]
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

#[cfg(test)]
thread_local! {
    /// The `(digest, expected length)` set the last body sweep on this thread
    /// verified, so a test can check that a streamed open verified exactly
    /// what an eager walk of the same store would have.
    static LAST_BODY_SWEEP_REQUIREMENTS: std::cell::RefCell<BTreeMap<Hash256, Option<u64>>> =
        const { std::cell::RefCell::new(BTreeMap::new()) };
}

/// What an open needs from every change, gathered once while recovery streams
/// the change map past so the map itself can stay on disk.
#[derive(Default)]
struct HistorySweep {
    body_requirements: BTreeMap<Hash256, AuthorityBodyRequirement>,
    authenticated_gitlinks: BTreeSet<(ArtifactId, GitObjectId)>,
    changes_seen: usize,
}

impl HistorySweep {
    fn visit(&mut self, change: &kin_model::SemanticChange) -> Result<(), KinDbError> {
        collect_tree_delta_body_requirements(
            &mut self.body_requirements,
            &change.tree_deltas,
            &format!("change {}", change.id),
        )?;
        extend_authenticated_gitlinks(&mut self.authenticated_gitlinks, std::iter::once(change));
        self.changes_seen += 1;
        Ok(())
    }
}

/// Where the change-derived half of the body requirements comes from.
enum ChangeBodyRequirements<'a> {
    /// Walk the decoded map, which decodes it if it was left on disk.
    Walk(&'a ChangeMap),
    /// Take what a [`HistorySweep`] already collected over every change.
    Collected(BTreeMap<Hash256, AuthorityBodyRequirement>),
}

#[cfg(test)]
fn collect_all_authority_body_requirements(
    snapshot: &GraphSnapshot,
) -> Result<BTreeMap<Hash256, AuthorityBodyRequirement>, KinDbError> {
    collect_all_authority_body_requirements_with(
        snapshot,
        ChangeBodyRequirements::Walk(&snapshot.changes),
    )
}

fn collect_all_authority_body_requirements_with(
    snapshot: &GraphSnapshot,
    changes: ChangeBodyRequirements<'_>,
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
    match changes {
        ChangeBodyRequirements::Walk(changes) => {
            for change in changes.values() {
                collect_tree_delta_body_requirements(
                    &mut requirements,
                    &change.tree_deltas,
                    &format!("change {}", change.id),
                )?;
            }
        }
        ChangeBodyRequirements::Collected(collected) => {
            for (digest, requirement) in collected {
                require_authority_body(
                    &mut requirements,
                    digest,
                    requirement.expected_len,
                    requirement.label,
                )?;
            }
        }
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
    validate_all_authority_bodies_with(
        backend,
        repository_id,
        snapshot,
        ChangeBodyRequirements::Walk(&snapshot.changes),
    )
}

fn validate_all_authority_bodies_with<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    snapshot: &GraphSnapshot,
    changes: ChangeBodyRequirements<'_>,
) -> Result<(), KinDbError> {
    let metadata = snapshot
        .repository_authority
        .as_ref()
        .expect("validated authority snapshot has metadata");
    let requirements = {
        let _span =
            tracing::info_span!("kindb.repository.collect_authority_body_requirements").entered();
        collect_all_authority_body_requirements_with(snapshot, changes)?
    };
    #[cfg(test)]
    LAST_BODY_SWEEP_REQUIREMENTS.with(|last| {
        *last.borrow_mut() = requirements
            .iter()
            .map(|(digest, requirement)| (*digest, requirement.expected_len))
            .collect();
    });
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

/// Prove every artifact body `tree` names is present in the immutable source
/// CAS and hashes to the identity the entry claims.
///
/// `already_admitted` names a tree this repository proved earlier, normally the
/// workspace state this mutation supersedes. Bodies are content-addressed, so
/// an entry carried across unchanged names the same immutable body it named
/// then, and reading it again can only reach the conclusion its own admission
/// already reached. Skipping those is what makes a commit's body cost follow
/// the edit instead of the repository's file count: a converted repository
/// tracks thousands of files, and recording a one-line edit used to read and
/// re-hash every one of them (FIR-2291).
///
/// This narrows what a commit re-proves; it does not widen what a commit
/// trusts. An entry that is new, or whose blob identity moved, is proven here
/// exactly as before, so a transaction naming a body the CAS does not hold
/// still fails closed. A body that decays after its own admission is a
/// repository-integrity fault rather than an admission fault, and
/// `validate_all_authority_bodies` is what finds it, on open and on freeze.
fn validate_tree_bodies<B: StorageBackend + ?Sized>(
    backend: &B,
    repository_id: &RepositoryId,
    tree: &kin_model::ResolvedTree,
    already_admitted: Option<&kin_model::ResolvedTree>,
    label: &str,
) -> Result<(), KinDbError> {
    // Proven content identities, seeded from the superseded tree and grown as
    // this tree's own entries are proven, so a body shared by several paths is
    // read once rather than once per path.
    let mut proven: BTreeSet<Hash256> = already_admitted
        .into_iter()
        .flat_map(|admitted| admitted.artifacts())
        .filter_map(|artifact| artifact.entry.blob_identity())
        .collect();
    for artifact in tree.artifacts() {
        if let Some(digest) = artifact.entry.blob_identity() {
            if !proven.insert(digest) {
                continue;
            }
        }
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

#[cfg(test)]
thread_local! {
    static ROOT_BUNDLES_FOLDED_ON_THIS_THREAD: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// How many root bundles this thread folded out of a snapshot.
///
/// This is the instrument behind "a commit folds its roots once": a test that
/// commits and then reads the counter can tell one fold from two directly,
/// rather than inferring it from a duration or a resident set. Counted at the
/// one place a fold happens, so a recomputation re-enabled anywhere upstream is
/// visible here. Per thread, because the test suite runs in parallel and a fold
/// on another thread is another test's.
#[cfg(test)]
pub(crate) fn root_bundles_folded_on_this_thread() -> usize {
    ROOT_BUNDLES_FOLDED_ON_THIS_THREAD.with(|count| count.get())
}

fn compute_roots(
    snapshot: &GraphSnapshot,
    authority: &PersistedRepositoryAuthority,
    generation: u64,
) -> Result<RootBundle, KinDbError> {
    #[cfg(test)]
    ROOT_BUNDLES_FOLDED_ON_THIS_THREAD.with(|count| count.set(count.get() + 1));
    // One span per root, for the reason `prepare_successor`'s laps carry one:
    // a root that costs a conversion real memory must be nameable by whatever
    // reads spans, and `kindb.roots.replication` is what the memory guard in
    // `tests/git_bootstrap_root_hash_memory.rs` reads.
    let history = {
        let _s = tracing::info_span!("kindb.roots.history").entered();
        history_root(snapshot, authority)?
    };
    let ref_state = {
        let _s = tracing::info_span!("kindb.roots.ref_state").entered();
        ref_state_root(authority)?
    };
    let ref_log = {
        let _s = tracing::info_span!("kindb.roots.ref_log").entered();
        ref_log_root(authority)?
    };
    let collaboration = {
        let _s = tracing::info_span!("kindb.roots.collaboration").entered();
        collaboration_root(snapshot)?
    };
    let replication = {
        let _s = tracing::info_span!("kindb.roots.replication").entered();
        replication_root(authority)?
    };
    let local_state = {
        let _s = tracing::info_span!("kindb.roots.local_state").entered();
        local_state_root(snapshot, authority)?
    };
    Ok(RootBundle {
        version: REPOSITORY_ROOT_SCHEMA_VERSION,
        generation,
        history: AuthorityRoot::new(REPOSITORY_ROOT_SCHEMA_VERSION, history),
        ref_state: AuthorityRoot::new(REPOSITORY_ROOT_SCHEMA_VERSION, ref_state),
        ref_log: AuthorityRoot::new(REPOSITORY_ROOT_SCHEMA_VERSION, ref_log),
        collaboration: AuthorityRoot::new(REPOSITORY_ROOT_SCHEMA_VERSION, collaboration),
        replication: AuthorityRoot::new(REPOSITORY_ROOT_SCHEMA_VERSION, replication),
        local_state: AuthorityRoot::new(REPOSITORY_ROOT_SCHEMA_VERSION, local_state),
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

/// Receiver-local ref receipt entry. Its destination operation identity,
/// actor, and commit time are local to the authority that accepted it, so this
/// is not portable ref history and must not override replicated `ref_state`.
/// The full operation identity remains bound under `local_state`.
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
    // One leaf carrying the entire Git object closure. This is the largest
    // single value the roots hash, and the reason `canonical_leaf_hash` may not
    // build a tree of what it hashes (FIR-2665).
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

/// Hash one leaf of a repository root.
///
/// The encoding is unchanged and may not change: these digests are persisted
/// authority roots. What changed is that it is written straight out of
/// `Serialize` rather than out of a `serde_json::Value` tree built for the
/// purpose. On a whole-repository leaf the tree cost fifteen times the bytes it
/// produced, and a bootstrap hands this function the entire Git object closure
/// as a single leaf (FIR-2665).
fn canonical_leaf_hash<T: Serialize>(domain: &str, value: &T) -> Result<[u8; 32], KinDbError> {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-repository-root-leaf-v1\0");
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain.as_bytes());
    canonical_hash_into(&mut hasher, value)
        .map_err(|error| storage(format!("canonical root leaf {domain} refused: {error}")))?;
    Ok(hasher.finalize().into())
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
        prepared: Mutex<HashMap<String, PreparedWorkspaceGraphArtifact>>,
        fail_next_snapshot: AtomicBool,
        source_load_count: AtomicUsize,
        verified_batch_behavior: AtomicUsize,
        source_load_hook: Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    }

    impl MemoryBackend {
        fn prepared_artifact(&self, workspace_id: &WorkspaceId) -> PreparedWorkspaceGraphArtifact {
            self.prepared
                .lock()
                .get(&workspace_id.to_string())
                .cloned()
                .expect("a prepared artifact was recorded for this workspace")
        }

        fn install_prepared_artifact(
            &self,
            workspace_id: &WorkspaceId,
            artifact: PreparedWorkspaceGraphArtifact,
        ) {
            self.prepared
                .lock()
                .insert(workspace_id.to_string(), artifact);
        }

        /// Rewrite one field of a stored binding record, leaving every other
        /// field and the payload exactly as they were written.
        fn corrupt_prepared_binding_field(
            &self,
            workspace_id: &WorkspaceId,
            field: &str,
            value: serde_json::Value,
        ) {
            let mut artifact = self.prepared_artifact(workspace_id);
            let mut binding: serde_json::Value =
                serde_json::from_slice(&artifact.binding).expect("stored binding decodes");
            let object = binding.as_object_mut().expect("bindings are JSON objects");
            assert!(
                object.contains_key(field),
                "binding has no field {field} to corrupt"
            );
            object.insert(field.to_string(), value);
            artifact.binding = serde_json::to_vec(&binding).expect("binding re-encodes");
            self.install_prepared_artifact(workspace_id, artifact);
        }
    }

    /// A backend that never implements the prepared-state methods, so it takes
    /// the default no-op surface every foreign backend takes.
    struct PreparedBlindBackend(Arc<MemoryBackend>);

    impl StorageBackend for PreparedBlindBackend {
        fn load_snapshot(
            &self,
            repo_id: &str,
        ) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
            self.0.load_snapshot(repo_id)
        }

        fn save_source_blob(
            &self,
            repo_id: &str,
            digest: [u8; 32],
            data: &[u8],
        ) -> Result<(), KinDbError> {
            self.0.save_source_blob(repo_id, digest, data)
        }

        fn load_source_blob(
            &self,
            repo_id: &str,
            digest: [u8; 32],
        ) -> Result<Option<Vec<u8>>, KinDbError> {
            self.0.load_source_blob(repo_id, digest)
        }

        fn load_source_blob_bounded(
            &self,
            repo_id: &str,
            digest: [u8; 32],
            max_bytes: u64,
        ) -> Result<Option<Vec<u8>>, KinDbError> {
            self.0.load_source_blob_bounded(repo_id, digest, max_bytes)
        }

        fn with_verified_source_blob_batch(
            &self,
            repo_id: &str,
            operation: &mut dyn FnMut(&dyn VerifiedSourceBlobBatch) -> Result<(), KinDbError>,
        ) -> Result<(), KinDbError> {
            self.0.with_verified_source_blob_batch(repo_id, operation)
        }

        fn save_snapshot(
            &self,
            repo_id: &str,
            data: &[u8],
            expected_gen: Generation,
        ) -> Result<Generation, KinDbError> {
            self.0.save_snapshot(repo_id, data, expected_gen)
        }

        fn save_snapshot_classified(
            &self,
            repo_id: &str,
            data: &[u8],
            expected_cursor: SnapshotCursor,
        ) -> SnapshotSaveOutcome {
            self.0
                .save_snapshot_classified(repo_id, data, expected_cursor)
        }

        fn save_delta(
            &self,
            repo_id: &str,
            delta_data: &[u8],
            base_gen: Generation,
        ) -> Result<Generation, KinDbError> {
            self.0.save_delta(repo_id, delta_data, base_gen)
        }

        fn load_deltas_since(
            &self,
            repo_id: &str,
            since_gen: Generation,
        ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
            self.0.load_deltas_since(repo_id, since_gen)
        }

        fn clear_deltas(&self, repo_id: &str) -> Result<(), KinDbError> {
            self.0.clear_deltas(repo_id)
        }

        fn save_overlay(
            &self,
            repo_id: &str,
            session_id: &str,
            data: &[u8],
        ) -> Result<(), KinDbError> {
            self.0.save_overlay(repo_id, session_id, data)
        }

        fn load_overlay(
            &self,
            repo_id: &str,
            session_id: &str,
        ) -> Result<Option<Vec<u8>>, KinDbError> {
            self.0.load_overlay(repo_id, session_id)
        }

        fn delete_overlay(&self, repo_id: &str, session_id: &str) -> Result<(), KinDbError> {
            self.0.delete_overlay(repo_id, session_id)
        }

        fn list_repos(&self) -> Result<Vec<String>, KinDbError> {
            self.0.list_repos()
        }
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

        fn load_prepared_workspace_graph(
            &self,
            _repo_id: &str,
            workspace_id: &str,
        ) -> Result<Option<PreparedWorkspaceGraphArtifact>, KinDbError> {
            Ok(self.prepared.lock().get(workspace_id).cloned())
        }

        fn record_prepared_workspace_graph(
            &self,
            _repo_id: &str,
            workspace_id: &str,
            artifact: &PreparedWorkspaceGraphArtifact,
        ) -> Result<bool, KinDbError> {
            self.prepared
                .lock()
                .insert(workspace_id.to_string(), artifact.clone());
            Ok(true)
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

    /// The spans one commit opens, and the span each was opened under.
    ///
    /// kin-db depends on `tracing` and not on `tracing-subscriber`, and a
    /// profiler is exactly a subscriber that keeps span metadata, so this
    /// records what a profiling layer would record rather than asserting
    /// against the summary event's fields. Keeping each span's parent is what
    /// makes the assertion say more than "a span with this name exists
    /// somewhere": a lap that does not hang under the preparation span leaves a
    /// profile unable to split the preparation's self time, which is the defect
    /// this instrumentation exists to close.
    ///
    /// The entered stack is kept per thread, the way `tracing`'s own registry
    /// keeps it. One shared stack would let any other thread that ever reached
    /// this subscriber decide what the next span's contextual parent is, and
    /// that is a wrong answer which only appears under load.
    #[derive(Clone, Default)]
    struct SpanRecorder(Arc<Mutex<SpanRecorderState>>);

    #[derive(Default)]
    struct SpanRecorderState {
        next_id: u64,
        names: std::collections::HashMap<u64, &'static str>,
        entered: std::collections::HashMap<std::thread::ThreadId, Vec<u64>>,
        opened: Vec<(&'static str, Option<&'static str>)>,
    }

    impl SpanRecorder {
        fn opened_span_names(&self) -> Vec<&'static str> {
            self.0.lock().opened.iter().map(|(name, _)| *name).collect()
        }

        /// Every span opened directly under `parent`, deduplicated and sorted.
        ///
        /// Deduplicated rather than counted because a publication may prepare a
        /// successor more than once: its decision closure is retried, and a
        /// count would then read twenty two where the set still reads eleven.
        /// The set is the property worth asserting and the one a loaded runner
        /// cannot perturb.
        fn distinct_children_of(&self, parent: &str) -> Vec<&'static str> {
            let mut children: Vec<&'static str> = self
                .0
                .lock()
                .opened
                .iter()
                .filter(|(_, opened_under)| *opened_under == Some(parent))
                .map(|(name, _)| *name)
                .collect();
            children.sort_unstable();
            children.dedup();
            children
        }

        /// Every span opened, with its parent, for a failure to report.
        fn opened_with_parents(&self) -> Vec<(&'static str, Option<&'static str>)> {
            self.0.lock().opened.clone()
        }
    }

    impl tracing::Subscriber for SpanRecorder {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            let thread = std::thread::current().id();
            let mut state = self.0.lock();
            state.next_id += 1;
            let id = state.next_id;
            let name = span.metadata().name();
            let parent = if span.is_root() {
                None
            } else if let Some(explicit) = span.parent() {
                state.names.get(&explicit.into_u64()).copied()
            } else {
                state
                    .entered
                    .get(&thread)
                    .and_then(|stack| stack.last().copied())
                    .and_then(|entered| state.names.get(&entered).copied())
            };
            state.names.insert(id, name);
            state.opened.push((name, parent));
            tracing::span::Id::from_u64(id)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, _event: &tracing::Event<'_>) {}

        fn enter(&self, span: &tracing::span::Id) {
            let thread = std::thread::current().id();
            self.0
                .lock()
                .entered
                .entry(thread)
                .or_default()
                .push(span.into_u64());
        }

        fn exit(&self, span: &tracing::span::Id) {
            let thread = std::thread::current().id();
            let leaving = span.into_u64();
            let mut state = self.0.lock();
            if let Some(stack) = state.entered.get_mut(&thread) {
                if let Some(position) = stack.iter().rposition(|entered| *entered == leaving) {
                    stack.remove(position);
                }
            }
        }
    }

    /// Keep every `tracing` callsite dynamically evaluated for this test binary.
    ///
    /// `tracing` caches one `Interest` per callsite for the whole PROCESS, and a
    /// thread with no subscriber answers `Interest::never` through
    /// `NoSubscriber`. Under `cargo test` every test shares one process, so
    /// whichever thread reaches a callsite first decides for all of them: a
    /// concurrent test committing with no subscriber cached `never` on five of
    /// the preparation laps, and the test below then saw six laps where the code
    /// had opened eleven. It failed that way inside a merge group, passed at PR
    /// level on the same commit, and never failed under nextest, which gives
    /// each test its own process.
    ///
    /// A global default that is interested in every callsite and enables none of
    /// them removes that in both directions. Installing it rebuilds the interest
    /// of every callsite already registered, and a callsite first reached
    /// afterwards resolves through this dispatcher too, because a thread with no
    /// scoped subscriber falls back to the global one. What each span then does
    /// is still decided per thread by whatever `with_default` installed, which
    /// is the thing under test.
    fn keep_callsites_dynamic() {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            struct InterestedInEverythingEnablingNothing;

            impl tracing::Subscriber for InterestedInEverythingEnablingNothing {
                fn register_callsite(
                    &self,
                    _metadata: &'static tracing::Metadata<'static>,
                ) -> tracing::subscriber::Interest {
                    tracing::subscriber::Interest::sometimes()
                }

                fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
                    false
                }

                fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                    tracing::span::Id::from_u64(1)
                }

                fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

                fn record_follows_from(
                    &self,
                    _span: &tracing::span::Id,
                    _follows: &tracing::span::Id,
                ) {
                }

                fn event(&self, _event: &tracing::Event<'_>) {}

                fn enter(&self, _span: &tracing::span::Id) {}

                fn exit(&self, _span: &tracing::span::Id) {}
            }

            // A global default already in place means someone else made the
            // same guarantee or a stronger one, and this test's own scoped
            // subscriber decides what it records either way.
            let _ = tracing::subscriber::set_global_default(InterestedInEverythingEnablingNothing);
        });
    }

    /// A commit reports every preparation lap and every commit phase as a span.
    ///
    /// The preparation reported its laps as `tracing` event fields only, so a
    /// profiler attributed the whole of it to the caller as self time and could
    /// name none of it: on one 3,111 s conversion that left 940 s on no span at
    /// all (FIR-2579). Fields alone are not enough, because the tool an operator
    /// reaches for on a slow run reads spans.
    ///
    /// The expected lap names are derived from the laps the summary event
    /// carries rather than restated here, so a lap added to one split and not
    /// the other fails this test instead of quietly making the two accounts
    /// disagree. What is asserted is a SET of names and a parent-child shape,
    /// never a count and never an order: a publication may retry its decision
    /// closure, which prepares a successor twice and would double any count
    /// while leaving the set exactly as it is.
    #[test]
    fn a_commit_reports_its_preparation_laps_as_spans() {
        keep_callsites_dynamic();
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let transaction = arbitrary_repository_transaction(&manager);
        PREPARATION_PHASE_LOG.with(|log| log.borrow_mut().clear());

        let recorder = SpanRecorder::default();
        tracing::subscriber::with_default(recorder.clone(), || {
            manager.commit_repository_transaction(transaction).unwrap();
        });

        let opened = recorder.opened_span_names();
        for phase in [
            "kindb.commit.transaction_hash",
            "kindb.commit.prepare_successor",
            "kindb.commit.persist_successor",
        ] {
            assert!(
                opened.contains(&phase),
                "commit phase {phase} must reach a profiler as a span; every span opened, with its parent: {:?}",
                recorder.opened_with_parents()
            );
        }

        let recorded = PREPARATION_PHASE_LOG.with(|log| log.borrow().clone());
        let laps = recorded
            .iter()
            .find(|(phase, _)| *phase == "prepare_successor")
            .map(|(_, laps)| laps.clone())
            .expect("the preparation records its own laps");
        assert!(
            laps.len() >= 11,
            "the preparation reports eleven laps; recorded {laps:?}"
        );
        let mut expected: Vec<String> = laps
            .iter()
            .map(|(field, _)| format!("kindb.prepare.{}", field.trim_end_matches("_ms")))
            .collect();
        expected.sort();
        expected.dedup();

        let children = recorder.distinct_children_of("kindb.commit.prepare_successor");
        for lap in &expected {
            assert!(
                children.iter().any(|child| child == lap),
                "lap {lap} must open under the preparation span; children {children:?}; every span opened, with its parent: {:?}",
                recorder.opened_with_parents()
            );
        }
        assert_eq!(
            children, expected,
            "every span opened directly inside the preparation belongs to a lap; every span opened, with its parent: {:?}",
            recorder.opened_with_parents()
        );
    }

    #[test]
    fn shared_replay_graph_proves_once_and_matches_fresh_resolution() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let (transaction, expected_change, _outer_tag) = detached_tag_import_transaction(&manager);
        manager.commit_repository_transaction(transaction).unwrap();
        let committed = manager.read_authority();

        let replay = SharedReplayGraph::new(committed.snapshot());
        assert_eq!(
            replay.proof_runs(),
            0,
            "the proof is lazy and must not run before it is asked for"
        );
        replay.prove().unwrap();
        replay.prove().unwrap();
        let shared_tree = replay.resolve_tree(expected_change).unwrap();
        assert_eq!(
            replay.proof_runs(),
            1,
            "the proof must run once and be shared by every later caller"
        );

        let mut fresh = committed.snapshot().clone();
        fresh.repository_authority = None;
        let fresh_tree = InMemoryGraph::from_snapshot_without_text_index(fresh)
            .unwrap()
            .resolve_tree_at(&expected_change)
            .unwrap();
        assert_eq!(
            shared_tree, fresh_tree,
            "a shared resolution must answer exactly what a fresh decode answers"
        );
    }

    /// The proof runs before any query answers, so a payload that fails
    /// admission never resolves a tree. The decode enforced that ordering by
    /// owning the query surface; borrowing the snapshot means the ordering has
    /// to be asserted instead of inherited.
    #[test]
    fn shared_replay_refuses_a_query_over_a_payload_that_fails_its_proof() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let (transaction, expected_change, _outer_tag) = detached_tag_import_transaction(&manager);
        manager.commit_repository_transaction(transaction).unwrap();
        let committed = manager.read_authority();

        // A change whose declared id no longer matches its payload is exactly
        // what the admission pass exists to refuse.
        let mut corrupt = committed.snapshot().clone();
        corrupt.repository_authority = None;
        let victim = *corrupt
            .changes
            .keys()
            .next()
            .expect("the committed history has at least one change");
        corrupt
            .changes
            .get_mut(&victim)
            .expect("the change was just read out of this map")
            .message
            .push_str(" tampered");

        let replay = SharedReplayGraph::new(&corrupt);
        let error = replay
            .resolve_tree(expected_change)
            .expect_err("a tampered payload must not answer a tree query");
        assert_eq!(
            replay.proof_runs(),
            1,
            "the refusal must come from the proof, which must have run"
        );
        // The same refusal a fresh decode of the same bytes raises.
        let fresh = InMemoryGraph::from_snapshot_without_text_index(corrupt)
            .expect_err("a fresh decode must refuse the same payload");
        assert_eq!(
            error.to_string(),
            fresh.to_string(),
            "the borrowed proof must refuse with the message the decode refused with"
        );
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

    fn receiver_ref_transaction<B: StorageBackend + ?Sized + 'static>(
        manager: &RepositoryAuthorityManager<B>,
        operation: u128,
        actor: &str,
    ) -> RepositoryTransaction {
        let main = RefName::branch(b"main").unwrap();
        let mut transaction = transaction_shell(manager, operation);
        transaction.actor = AuthorId::new(actor);
        transaction.reason = "apply equivalent transferred ref authority".to_string();
        transaction.ref_mutations.push(RefMutation {
            name: main.clone(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(RefTarget::symbolic(RefName::branch(b"upstream").unwrap())),
            policy: RefUpdatePolicy::FastForwardOnly,
        });
        transaction.default_ref_mutation = Some(DefaultRefMutation {
            expected: DefaultRefExpectation::MustBeUnset,
            new_default: Some(main),
        });
        transaction
    }

    fn perturb_root(root: &mut AuthorityRoot) {
        let mut bytes = *root.hash.as_bytes();
        bytes[0] ^= 1;
        root.hash = Hash256::from_bytes(bytes);
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

    fn git_authority_transaction_fixture<B: StorageBackend + ?Sized + 'static>(
        manager: &RepositoryAuthorityManager<B>,
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

    fn detached_tag_import_transaction<B: StorageBackend + ?Sized + 'static>(
        manager: &RepositoryAuthorityManager<B>,
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

    fn remove_compose_transaction<B: StorageBackend + ?Sized + 'static>(
        manager: &RepositoryAuthorityManager<B>,
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

    /// One admitted transaction must walk each projected commit's Git tree once.
    ///
    /// Cost is the whole observable difference. A repeated walk over the
    /// identical closure admits the identical transaction and persists identical
    /// bytes, so no assertion on the committed authority can separate one walk
    /// from two, while an imported repository pays the repeat as a full
    /// recursive materialization per commit in its history.
    ///
    /// The backend is the local file one on purpose. The in-memory test double
    /// re-decodes every persisted snapshot through the full storage-admission
    /// gate, which is a walk per projection that no shipped backend performs.
    #[test]
    fn a_git_authority_commit_walks_each_projected_tree_once() {
        let directory = TempDir::new().unwrap();
        let backend = Arc::new(LocalFileBackend::new(directory.path()));
        let manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let fixture = git_authority_transaction_fixture(&manager, 0xa060);
        let projections = fixture.authority.commit_projections.len();
        assert!(
            projections > 1,
            "a single-projection fixture cannot separate per-commit cost from per-commit walks"
        );

        reset_materialized_git_trees();
        manager
            .commit_repository_transaction(fixture.transaction)
            .unwrap();

        assert_eq!(
            materialized_git_trees(),
            projections,
            "admitting {projections} Git commit projections must materialize {projections} trees"
        );
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
    fn a_same_transaction_git_import_authenticates_a_native_child_over_its_gitlink() {
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
            message: "native history over an imported Gitlink".to_string(),
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
        fixture.transaction.changes.push(native);

        manager
            .commit_repository_transaction(fixture.transaction)
            .expect("a Native child inherits a Gitlink its own transaction authenticates");

        // Generation alone would also read 1 for a transaction that admitted
        // the Git half and dropped the Native change, so the child itself is
        // what the assertions name.
        let lease = manager.read_authority();
        assert_eq!(lease.generation(), 1);
        assert!(
            lease.snapshot().changes.contains_key(&native_id),
            "the Native child must be persisted, not merely tolerated"
        );
        assert!(lease.metadata().git_external_authority.is_some());
        assert!(
            lease
                .authenticated_gitlinks()
                .contains(&(ArtifactId(Uuid::from_u128(0xa4)), fixture.gitlink_target)),
            "the committed authority index must carry the Gitlink the child inherited"
        );
    }

    /// The successor authority authenticates its own exact Gitlinks and no
    /// others, so the bootstrap allowance cannot be widened into "any Gitlink
    /// inside a transaction that happens to carry Git authority".
    #[test]
    fn a_same_transaction_git_import_authenticates_only_its_exact_gitlink_target() {
        let manager = initial_manager(Arc::new(MemoryBackend::default()));
        let mut fixture = git_authority_transaction_fixture(&manager, 0xa151);
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
        let submodule = RepoPath::from_utf8("submodule").unwrap();
        let unauthenticated = GitObjectId::sha1([0x66; 20]);
        let mut native = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: vec![parent],
            timestamp: Timestamp::now(),
            author: AuthorId::new("authority-test"),
            message: "retarget an imported Gitlink to an unauthenticated commit".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: vec![TreeDelta::Updated {
                artifact_id: ArtifactId(Uuid::from_u128(0xa4)),
                old: LocatedEntry::new(
                    submodule.clone(),
                    TreeEntry::gitlink(fixture.gitlink_target),
                ),
                new: LocatedEntry::new(submodule, TreeEntry::gitlink(unauthenticated)),
            }],
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
            .expect_err("a retargeted Gitlink has no authority in the imported history");
        assert!(
            error
                .to_string()
                .contains("without verified Git external authority"),
            "unexpected retargeted-gitlink error: {error}"
        );
        assert_eq!(manager.read_authority().generation(), 0);
    }

    /// The successor allowance is bound to the authority actually applied, so
    /// moving a verifier ahead of `apply_git_authority` refuses rather than
    /// admits. Nothing in the commit path can reach that ordering today, which
    /// is exactly why the property is asserted on the function instead.
    #[test]
    fn successor_gitlinks_carry_only_what_the_applied_authority_projects() {
        let manager = initial_manager(Arc::new(MemoryBackend::default()));
        let fixture = git_authority_transaction_fixture(&manager, 0xa161);
        let artifact = ArtifactId(Uuid::from_u128(0xa4));
        let lease = manager.read_authority();
        let current: &RepositoryAuthorityState = &lease;

        let unapplied =
            successor_authenticated_gitlinks(current, lease.metadata(), &fixture.transaction);
        assert!(
            unapplied.is_empty(),
            "an authority this metadata has not applied projects nothing: {unapplied:?}"
        );

        let mut metadata = lease.metadata().clone();
        metadata.git_external_authority = Some(fixture.authority.clone());
        let applied = successor_authenticated_gitlinks(current, &metadata, &fixture.transaction);
        assert_eq!(
            applied,
            BTreeSet::from([
                (artifact, fixture.previous_gitlink_target),
                (artifact, fixture.gitlink_target),
            ]),
            "an applied authority carries exactly its own projected Gitlinks"
        );

        let mut with_native = fixture.transaction.clone();
        let mut native = with_native.changes[0].clone();
        native.origin = ChangeOrigin::Native;
        native.id = SemanticChangeId::from_hash(Hash256::from_bytes([9; 32]));
        native.tree_deltas = vec![TreeDelta::Added {
            artifact_id: ArtifactId(Uuid::from_u128(0xbe)),
            new: LocatedEntry::new(
                RepoPath::from_utf8("vendor/forged").unwrap(),
                TreeEntry::gitlink(GitObjectId::sha1([0x77; 20])),
            ),
        }];
        with_native.changes.push(native);
        let with_native_set = successor_authenticated_gitlinks(current, &metadata, &with_native);
        assert_eq!(
            with_native_set, applied,
            "a Native change contributes no Gitlink authority"
        );
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
            resolve_target_tree_hash(
                &SharedReplayGraph::new(committed.snapshot()),
                committed.metadata(),
                &exact_target
            )
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

    /// One repository whose workspace is only ever advanced by host passes, the
    /// way the daemon advances it.
    ///
    /// Every pass derives the successor shared policy from the desired tree
    /// through the same `SharedAdmissionPolicy::derive_from_tree` the daemon
    /// calls, so a pass that admits a `.gitignore` really does carry that rule
    /// into the successor generation. Nothing here filters the proposal: the
    /// caller-side prune lives in kin's walker, and what these tests are about
    /// is what authority does with a proposal that still carries the paths a
    /// brand-new rule names.
    struct AmbientWorkspace {
        manager: RepositoryAuthorityManager<MemoryBackend>,
        lengths: BTreeMap<Hash256, u64>,
        next_artifact: u128,
    }

    impl AmbientWorkspace {
        fn start(operation: u128) -> Self {
            let manager = initial_manager(Arc::new(MemoryBackend::default()));
            let transaction = unborn_workspace_transaction(&manager, operation, 0x20, b"main");
            manager.commit_repository_transaction(transaction).unwrap();
            Self {
                manager,
                lengths: BTreeMap::new(),
                next_artifact: 0x100,
            }
        }

        fn workspace(&self) -> WorkspaceState {
            self.manager.read_authority().metadata().workspaces[0].clone()
        }

        fn tree(&self) -> ResolvedTree {
            self.workspace().tree
        }

        fn holds(&self, path: &str) -> bool {
            self.tree()
                .artifact_at_path(&RepoPath::from_utf8(path).unwrap())
                .is_some()
        }

        fn rule_source_paths(&self) -> Vec<String> {
            self.workspace()
                .shared_admission_policy
                .sources
                .iter()
                .map(|source| source.path.to_string())
                .collect()
        }

        fn blob(&mut self, body: &[u8]) -> TreeEntry {
            let hash = digest(body);
            self.manager.save_source_blob(hash, body).unwrap();
            self.lengths.insert(hash, body.len() as u64);
            TreeEntry::blob(hash, false)
        }

        fn deltas(&mut self, paths: &[(&str, &[u8])]) -> Vec<TreeDelta> {
            let tree = self.tree();
            let mut deltas = Vec::new();
            for (path, body) in paths {
                let path = RepoPath::from_utf8(*path).unwrap();
                let entry = self.blob(body);
                match tree.artifact_at_path(&path) {
                    Some(existing) => deltas.push(TreeDelta::Updated {
                        artifact_id: existing.artifact_id,
                        old: existing.located_entry(),
                        new: LocatedEntry::new(path, entry),
                    }),
                    None => {
                        self.next_artifact += 1;
                        deltas.push(TreeDelta::Added {
                            artifact_id: ArtifactId(Uuid::from_u128(self.next_artifact)),
                            new: LocatedEntry::new(path, entry),
                        });
                    }
                }
            }
            deltas
        }

        fn derive(
            &self,
            parent: Option<&SharedAdmissionPolicy>,
            tree: &ResolvedTree,
        ) -> (SharedAdmissionPolicy, Option<AdmissionPolicyDelta>) {
            let lengths = self.lengths.clone();
            SharedAdmissionPolicy::derive_from_tree(parent, tree, |hash| {
                lengths.get(&hash).copied().ok_or_else(|| {
                    ModelError::InvalidOperation(format!("fixture has no body length for {hash}"))
                })
            })
            .unwrap()
        }

        /// One ambient pass: admit these host paths into the workspace tree.
        fn pass(&mut self, operation: u128, paths: &[(&str, &[u8])]) -> Result<(), KinDbError> {
            let current = self.workspace();
            let deltas = self.deltas(paths);
            let next_tree = current.tree.apply(&deltas).unwrap();
            let (policy, _) = self.derive(Some(&current.shared_admission_policy), &next_tree);
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
                tree_deltas: deltas,
                new_tree_hash: compute_resolved_tree_hash(&next_tree).unwrap(),
                semantic_delta: WorkspaceSemanticDelta::default(),
                new_shared_admission_policy: policy.clone(),
                new_admission_policy: EffectiveAdmissionPolicyStamp {
                    shared: policy.stamp(),
                    local: current.admission_policy.local,
                },
            };
            let mut transaction = transaction_shell(&self.manager, operation);
            transaction.workspace_mutation = Some(mutation);
            self.manager
                .commit_repository_transaction(transaction)
                .map(|_| ())
        }

        /// Publish the workspace tree as one Native change, admitting `paths` in
        /// the same transaction the way a commit carrying its own tree admission
        /// does.
        fn commit(
            &mut self,
            operation: u128,
            message: &str,
            paths: &[(&str, &[u8])],
        ) -> Result<(), KinDbError> {
            let current = self.workspace();
            let lease = self.manager.read_authority();
            let parent = current
                .base_target
                .as_ref()
                .map(|target| target_change_id(lease.metadata(), target).unwrap());
            let parent_policy = parent.and_then(|change| {
                lease
                    .metadata()
                    .admission_policies
                    .iter()
                    .find(|resolved| resolved.change_id == change)
                    .and_then(|resolved| resolved.policy.clone())
            });
            let parent_tree = parent
                .map(|change| {
                    let mut replay = lease.snapshot().clone();
                    replay.repository_authority = None;
                    InMemoryGraph::from_snapshot_without_text_index(replay)
                        .unwrap()
                        .resolve_tree_at(&change)
                        .unwrap()
                })
                .unwrap_or_default();
            drop(lease);

            let deltas = self.deltas(paths);
            let next_tree = current.tree.apply(&deltas).unwrap();
            let (policy, policy_delta) = self.derive(parent_policy.as_ref(), &next_tree);
            let change_deltas = next_tree
                .artifacts_by_path()
                .filter(|artifact| parent_tree.get(&artifact.artifact_id) != Some(*artifact))
                .map(|artifact| match parent_tree.get(&artifact.artifact_id) {
                    Some(old) => TreeDelta::Updated {
                        artifact_id: artifact.artifact_id,
                        old: old.located_entry(),
                        new: artifact.located_entry(),
                    },
                    None => TreeDelta::Added {
                        artifact_id: artifact.artifact_id,
                        new: artifact.located_entry(),
                    },
                })
                .collect::<Vec<_>>();
            let mut change = SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
                origin: ChangeOrigin::Native,
                parents: parent.into_iter().collect(),
                timestamp: Timestamp::now(),
                author: AuthorId::new("authority-test"),
                message: message.to_string(),
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: change_deltas,
                admission_policy_delta: policy_delta,
                external_reference_deltas: Vec::new(),
                projected_files: Vec::new(),
                spec_link: None,
                evidence: Vec::new(),
                risk_summary: None,
            };
            change.id = compute_semantic_change_id(&change).unwrap();
            let target = RefTarget::change(change.id);
            let tree_hash = compute_resolved_tree_hash(&next_tree).unwrap();
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
                new_base_target: Some(target.clone()),
                new_base_tree_hash: Some(tree_hash),
                tree_deltas: deltas,
                new_tree_hash: tree_hash,
                semantic_delta: WorkspaceSemanticDelta::default(),
                new_shared_admission_policy: policy.clone(),
                new_admission_policy: EffectiveAdmissionPolicyStamp {
                    shared: policy.stamp(),
                    local: current.admission_policy.local,
                },
            };
            let mut transaction = transaction_shell(&self.manager, operation);
            transaction.changes.push(change);
            transaction.ref_mutations.push(RefMutation {
                name: RefName::branch(b"main").unwrap(),
                expected: match current.base_target.clone() {
                    Some(target) => RefExpectation::MustEqual { target },
                    None => RefExpectation::MustNotExist,
                },
                new_target: Some(target),
                policy: RefUpdatePolicy::FastForwardOnly,
            });
            transaction.workspace_mutation = Some(mutation);
            self.manager
                .commit_repository_transaction(transaction)
                .map(|_| ())
        }
    }

    fn assert_policy_exclusion(error: &KinDbError, path: &str) {
        let message = error.to_string();
        assert!(
            message.contains("excluded by the exact graph-owned admission policy")
                && message.contains(path),
            "expected a policy exclusion naming {path}, got: {message}"
        );
    }

    /// The regression FIR-2346 found and deliberately did not pin, now asserting
    /// the fixed outcome: one pass carries a new `.gitignore` and the untracked
    /// content that rule newly excludes, and authority admits the whole pass.
    #[test]
    fn a_pass_that_introduces_an_ignore_rule_admits_what_the_rule_newly_excludes() {
        let mut repo = AmbientWorkspace::start(0xa100);
        repo.pass(0xa101, &[("src/lib.rs", b"pub fn kin() {}\n")])
            .unwrap();
        assert!(repo.rule_source_paths().is_empty());

        repo.pass(
            0xa102,
            &[
                (".gitignore", b".claude/\n"),
                (".claude/lock", b"held\n"),
                ("src/main.rs", b"fn main() {}\n"),
            ],
        )
        .expect("a pass that introduces an ignore rule must not be judged by that rule");

        assert!(repo.holds(".gitignore"), "the rule file itself must land");
        assert!(
            repo.holds(".claude/lock"),
            "content the new rule newly excludes lands with the rule that excludes it"
        );
        assert!(
            repo.holds("src/main.rs") && repo.holds("src/lib.rs"),
            "every other file in the same pass lands too"
        );
        assert_eq!(
            repo.rule_source_paths(),
            vec![".gitignore".to_string()],
            "the rule is in force from the next generation on"
        );

        // The rule is in force now, so a path it excludes that this generation
        // never admitted fails loudly rather than silently. That is what kin's
        // walker prunes before proposing, which is why the following pass
        // proposes nothing under the new rule.
        let error = repo
            .pass(0xa103, &[(".claude/settings.json", b"{}\n")])
            .expect_err("a newly proposed excluded path must still fail loudly");
        assert_policy_exclusion(&error, ".claude/settings.json");

        // And the pass the pruned walker actually produces admits, with the
        // previously admitted excluded path still in the tree it re-verifies.
        repo.pass(0xa104, &[("src/other.rs", b"pub fn other() {}\n")])
            .expect("a pass proposing nothing under the new rule admits");
        assert!(repo.holds(".claude/lock") && repo.holds("src/other.rs"));
    }

    /// The same forward reading in the other direction: removing a rule takes
    /// effect from the next generation, so the pass that removes it lands and
    /// the pass after that admits what the rule used to exclude.
    #[test]
    fn removing_an_ignore_rule_un_excludes_content_for_the_next_pass() {
        let mut repo = AmbientWorkspace::start(0xb100);
        repo.pass(
            0xb101,
            &[
                (".gitignore", b"build/\n"),
                ("src/lib.rs", b"pub fn kin() {}\n"),
            ],
        )
        .unwrap();

        let error = repo
            .pass(0xb102, &[("build/output.bin", b"binary\n")])
            .expect_err("the rule in force must exclude a newly proposed path under it");
        assert_policy_exclusion(&error, "build/output.bin");

        // Dropping the rule and admitting the content it excluded in one pass is
        // judged by the rule still in force. kin's walker never proposes that
        // pair, because it prunes against the same generation authority judges
        // by, so the removal lands on its own first.
        let error = repo
            .pass(
                0xb103,
                &[
                    (".gitignore", b"# nothing ignored\n"),
                    ("build/output.bin", b"binary\n"),
                ],
            )
            .expect_err("a rule removal does not retroactively admit in its own pass");
        assert_policy_exclusion(&error, "build/output.bin");

        repo.pass(0xb104, &[(".gitignore", b"# nothing ignored\n")])
            .expect("the rule removal lands on its own");
        repo.pass(0xb105, &[("build/output.bin", b"binary\n")])
            .expect("the next pass admits what the removed rule used to exclude");
        assert!(repo.holds("build/output.bin"));
    }

    /// A commit is judged the same way, or the workspace would admit a tree no
    /// change could ever publish.
    #[test]
    fn a_native_change_is_judged_by_the_generation_in_force_before_it() {
        let mut repo = AmbientWorkspace::start(0xc100);
        repo.pass(
            0xc101,
            &[
                (".gitignore", b".claude/\n"),
                (".claude/lock", b"held\n"),
                ("src/lib.rs", b"pub fn kin() {}\n"),
            ],
        )
        .unwrap();

        // A root change publishing the admitted workspace tree introduces every
        // path its absent parent lacks. Those paths are already repository
        // authority, so the rule the workspace now carries does not re-judge
        // them.
        repo.commit(0xc102, "publish the admitted workspace tree", &[])
            .expect("a change may publish a tree an earlier generation admitted");
        assert!(repo.holds(".claude/lock") && repo.holds(".gitignore"));

        // A commit that admits its own tree carries the same shape as a pass: a
        // new rule beside the content it newly excludes, judged by the parent
        // generation.
        repo.commit(
            0xc103,
            "ignore logs while admitting one",
            &[
                (".gitignore", b".claude/\nlogs/\n"),
                ("logs/today.log", b"line\n"),
            ],
        )
        .expect("a change that introduces an ignore rule must not be judged by that rule");
        assert!(repo.holds("logs/today.log"));

        // Fail-loud survives: the rule is in force for the next commit.
        let error = repo
            .commit(
                0xc104,
                "admit an excluded log",
                &[("logs/old.log", b"line\n")],
            )
            .expect_err("a newly introduced excluded path must still fail the change");
        assert_policy_exclusion(&error, "logs/old.log");
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
    fn replicated_truth_classifies_every_root_bundle_field() {
        let manager = initial_manager(Arc::new(MemoryBackend::default()));
        let expected = manager.read_authority().roots().clone();

        type Case = (&'static str, bool, fn(&mut RootBundle));
        let cases: [Case; 8] = [
            ("version", false, |bundle| bundle.version += 1),
            ("generation", true, |bundle| bundle.generation += 1),
            ("history", false, |bundle| perturb_root(&mut bundle.history)),
            ("ref_state", false, |bundle| {
                perturb_root(&mut bundle.ref_state)
            }),
            ("ref_log", true, |bundle| perturb_root(&mut bundle.ref_log)),
            ("collaboration", false, |bundle| {
                perturb_root(&mut bundle.collaboration)
            }),
            ("replication", false, |bundle| {
                perturb_root(&mut bundle.replication)
            }),
            ("local_state", true, |bundle| {
                perturb_root(&mut bundle.local_state)
            }),
        ];

        expected.validate().unwrap();
        let expected_wire = rmp_serde::to_vec(&expected).unwrap();
        assert_eq!(
            expected_wire.first(),
            Some(&0x98),
            "RootBundle gained or lost a field; classify every field explicitly"
        );

        for (field, expects_same_replicated_truth, mutate) in cases {
            let mut changed = expected.clone();
            mutate(&mut changed);
            assert_ne!(changed, expected, "{field} must remain in full equality");
            assert_ne!(
                rmp_serde::to_vec(&changed).unwrap(),
                expected_wire,
                "{field} must remain in the complete serialized bundle"
            );
            assert_eq!(
                expected.has_same_replicated_truth(&changed),
                expects_same_replicated_truth,
                "{field} has the wrong replicated-truth classification"
            );
        }

        let mut invalid_local_root = expected;
        invalid_local_root.ref_log.version += 1;
        assert!(
            invalid_local_root.validate().is_err(),
            "receiver-local roots remain version-validated"
        );
    }

    #[test]
    fn equivalent_receivers_reopen_with_the_same_replicated_truth() {
        let source_backend = Arc::new(MemoryBackend::default());
        let receiver_backend = Arc::new(MemoryBackend::default());
        let source = initial_manager(Arc::clone(&source_backend));
        let receiver = initial_manager(Arc::clone(&receiver_backend));

        let source_receipt = source
            .commit_repository_transaction(receiver_ref_transaction(
                &source,
                0xfa01,
                "transfer-source-receiver",
            ))
            .unwrap();
        let receiver_receipt = receiver
            .commit_repository_transaction(receiver_ref_transaction(
                &receiver,
                0xfa02,
                "transfer-destination-receiver",
            ))
            .unwrap();

        assert_ne!(
            source_receipt.operation.operation_id,
            receiver_receipt.operation.operation_id
        );
        assert_ne!(
            source_receipt.operation.actor,
            receiver_receipt.operation.actor
        );
        assert_ne!(
            source_receipt, receiver_receipt,
            "each receiver must preserve its own exact durable receipt"
        );

        let source_roots = source.read_authority().roots().clone();
        let receiver_roots = receiver.read_authority().roots().clone();
        source_roots.validate().unwrap();
        receiver_roots.validate().unwrap();
        assert_eq!(source_roots.history, receiver_roots.history);
        assert_eq!(source_roots.ref_state, receiver_roots.ref_state);
        assert_eq!(source_roots.collaboration, receiver_roots.collaboration);
        assert_eq!(source_roots.replication, receiver_roots.replication);
        assert_ne!(source_roots.ref_log, receiver_roots.ref_log);
        assert_ne!(source_roots.local_state, receiver_roots.local_state);
        assert_ne!(source_roots, receiver_roots);
        assert!(source_roots.has_same_replicated_truth(&receiver_roots));

        let source_snapshot = source_backend
            .snapshot
            .lock()
            .as_ref()
            .expect("source commit persisted a snapshot")
            .0
            .clone();
        let receiver_snapshot = receiver_backend
            .snapshot
            .lock()
            .as_ref()
            .expect("receiver commit persisted a snapshot")
            .0
            .clone();
        assert_ne!(
            source_snapshot, receiver_snapshot,
            "receiver-local receipts remain in exact persisted snapshot identity"
        );

        drop(source);
        drop(receiver);
        let reopened_source = initial_manager(source_backend);
        let reopened_receiver = initial_manager(receiver_backend);
        let reopened_source_roots = reopened_source.read_authority().roots().clone();
        let reopened_receiver_roots = reopened_receiver.read_authority().roots().clone();
        assert_eq!(reopened_source_roots, source_roots);
        assert_eq!(reopened_receiver_roots, receiver_roots);
        assert!(reopened_source_roots.has_same_replicated_truth(&reopened_receiver_roots));

        let mut moved_ref = reopened_receiver_roots;
        perturb_root(&mut moved_ref.ref_state);
        assert!(
            !reopened_source_roots.has_same_replicated_truth(&moved_ref),
            "receiver-local receipt differences must not hide a replicated ref-state move"
        );
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
            .snapshot_bytes
            .to_vec();

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
                .snapshot_bytes
                .to_vec(),
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

    /// The envelope read answers what the full open answers.
    ///
    /// The assertion is the JOIN rather than either endpoint. Comparing the
    /// envelope against a hardcoded expectation would pass with both sides
    /// wrong; comparing it against what the full open produces is the property
    /// that matters, and it cannot be satisfied by writing the same value
    /// twice.
    ///
    /// **This fixture is the journal-FREE arm, and it says so rather than
    /// pretending otherwise.** One commit on this backend writes a full
    /// snapshot base, so base and head are equal and the read takes
    /// `advance_envelope_over_journal`'s early return. Two attempts to make it
    /// carry a frame failed in CI on the fixture rather than on the code, first
    /// on a duplicate operation id and then on `ref refs/heads/main already
    /// exists`, because the helper builds a bootstrap-shaped transaction that
    /// applies once. A second valid transaction is real work and no test in
    /// this file does it.
    ///
    /// The frame WALK is held by
    /// `native_admission_lineage::the_envelope_walk_reaches_the_envelope_a_full_open_reaches`,
    /// which lives in that module because its `transaction_shell` can build a
    /// valid second transaction and this module's bootstrap helper cannot. The
    /// two tests are the two arms of the same read and neither covers the
    /// other's.
    #[test]
    fn the_envelope_read_answers_what_the_full_open_answers() {
        let directory = TempDir::new().unwrap();
        let backend = Arc::new(LocalFileBackend::new(directory.path()));
        let manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .expect("the fixture commit must land");

        // Not a control on the walk, a statement of which arm this is. If a
        // future fixture makes this fail, the test is finally on the journal
        // path and the doc comment above is stale.
        let persisted = backend
            .load_snapshot_authority(repository_id().as_str())
            .unwrap()
            .expect("the fixture wrote an authority");
        assert_eq!(
            persisted.snapshot_generation, persisted.head_generation,
            "this fixture is the journal-free arm; if it grew a journal, rewrite the doc \
             comment above, because the walk is then under test"
        );

        let envelope = RepositoryAuthorityMetadata::open(repository_id(), Arc::clone(&backend))
            .expect("the envelope read must not error")
            .expect("a persisted authority must answer");
        assert_eq!(
            envelope.generation(),
            manager.read_authority().generation(),
            "the envelope must reach the generation the full open reaches"
        );
        assert_eq!(
            envelope.metadata(),
            manager.read_authority().metadata(),
            "the envelope read must produce the envelope the full open produces, field for field"
        );
    }

    /// A repository with no persisted authority declines rather than inventing
    /// an empty envelope.
    ///
    /// The third branch of the read, and the one whose failure mode is quiet:
    /// an envelope-shaped answer for a repository that has never committed
    /// would report a real store as empty. `None` sends the caller to the full
    /// open, which is the only thing that can decide what an uncommitted
    /// repository is.
    #[test]
    fn the_envelope_read_declines_a_repository_with_no_persisted_authority() {
        let directory = TempDir::new().unwrap();
        let backend = Arc::new(LocalFileBackend::new(directory.path()));
        let _manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        assert!(
            backend
                .load_snapshot_authority(repository_id().as_str())
                .unwrap()
                .is_none(),
            "this fixture must have no persisted authority, or it is a different branch"
        );
        assert!(
            RepositoryAuthorityMetadata::open(repository_id(), Arc::clone(&backend))
                .expect("the envelope read must not error")
                .is_none(),
            "a repository with no persisted authority must decline, not answer empty"
        );
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
    fn history_validation_version_moves_with_coverage_and_not_only_with_the_schema() {
        // Pinned so a change to what open's full validation path accepts cannot
        // reuse a version that stood for weaker checks. If a check reachable
        // from that path was added, removed, or retightened, bump
        // HISTORY_VALIDATION_COVERAGE_REVISION and update this expectation
        // together; if nothing about coverage moved, leave both alone.
        assert_eq!(
            HISTORY_VALIDATION_VERSION, 1_403,
            "envelope schema 4 and coverage revision 3 compose to 1403"
        );
        // That literal is the whole test. The rest of this comment exists so
        // nobody reads the test as stronger than it is, or pads it with
        // assertions that cannot fail.
        //
        // Restating the composition here, or adding one to a single term of it,
        // asserts nothing: both restate arithmetic the compiler already did, and
        // neither can fail while the constants are referenced at all. Sweeping
        // (schema, coverage) pairs for collisions is the same trap one level up,
        // because `1_000 + schema * STRIDE + coverage` over `coverage < STRIDE` is
        // positional encoding and cannot collide by construction. The property
        // those reach for, that neither term can alias the other, is enforced
        // where it belongs: a compile-time assertion beside the constants.
        //
        // What this test does catch is a revert to schema-only derivation, and
        // either constant moving without this expectation moving with it.
        //
        // What it cannot catch is the failure that motivated the change:
        // validation coverage moving while the revision stays put. The version is
        // then still 1302, this assertion still passes, and stores reopen against
        // checks their record never stood for. Closing that needs the covered
        // checks enumerated or dispatched so that adding one fails to compile,
        // not another assertion here.
    }

    #[test]
    fn reopen_refuses_a_record_minted_before_the_current_validation_coverage() {
        let directory = TempDir::new().unwrap();
        drop(committed_local_repository(&directory));

        // The exact version stores admitted by the build that introduced these
        // records carry. Its validator did not yet admit external-reference
        // entries or replay the Git projection tree, so its record cannot vouch
        // for a store against the checks that came after it. This is a literal
        // rather than a computed value on purpose: it is a historical fact about
        // bytes already on disk, and it must keep failing to verify even after
        // the composition of the current version changes again.
        const PRE_COVERAGE_VALIDATOR_VERSION: u32 = 1_003;
        assert_ne!(
            PRE_COVERAGE_VALIDATOR_VERSION, HISTORY_VALIDATION_VERSION,
            "a record minted before the current coverage must not verify against it"
        );

        let mut record = read_authority_json(directory.path());
        record["history_validation"]["validator_version"] =
            serde_json::json!(PRE_COVERAGE_VALIDATOR_VERSION);
        write_authority_json(directory.path(), &record);

        assert!(
            !reopen(&directory).opened_by_history_validation(),
            "a record minted by an earlier validation coverage must pay full validation"
        );

        // One full validation, not full validation forever: the open that paid
        // it rebinds the record at the current version so the next open is fast
        // again.
        let rebound = read_authority_json(directory.path());
        assert_eq!(
            rebound["history_validation"]["validator_version"]
                .as_u64()
                .expect("the rebound record carries a validator version"),
            u64::from(HISTORY_VALIDATION_VERSION),
            "the open that revalidated must rebind at the current version"
        );
        assert!(
            reopen(&directory).opened_by_history_validation(),
            "the rebound record must make the next open fast"
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
            journal_sha256: None,
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
            journal_sha256: Some(hex::encode(Sha256::digest(b"some frame chain"))),
            ..recovered(honest.clone())
        };
        assert!(
            verified_history_validation(&repository_id(), &replayed_delta).is_none(),
            "a record about base bytes cannot describe a frame-replayed state"
        );
        let journal_proof = HistoryValidationProof {
            journal_sha256: Some(hex::encode(Sha256::digest(b"some frame chain"))),
            ..honest
        };
        let replayed_frames = RecoveredSnapshot {
            deltas_applied: 1,
            journal_sha256: Some(hex::encode(Sha256::digest(b"some frame chain"))),
            ..recovered(journal_proof.clone())
        };
        assert!(
            verified_history_validation(&repository_id(), &replayed_frames).is_some(),
            "a record naming exactly this base and this chain describes the replayed state"
        );
        let other_chain = RecoveredSnapshot {
            deltas_applied: 1,
            journal_sha256: Some(hex::encode(Sha256::digest(b"another chain"))),
            ..recovered(journal_proof)
        };
        assert!(
            verified_history_validation(&repository_id(), &other_chain).is_none(),
            "a record naming another chain must not be honored"
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

    /// One authority store carrying a deep synthetic history and one clean
    /// workspace based at its head, committed through the real transaction
    /// surface so every materialization input (refs, workspace authority,
    /// overlay derivation) is exactly what a product store carries.
    ///
    /// Entities deliberately have no file origin, so the fixture needs no
    /// repository tree and no source bodies; the costs under measurement
    /// (history replay, snapshot copying, admission passes) involve neither.
    struct SyntheticHistoryStore {
        backend: Arc<MemoryBackend>,
        manager: RepositoryAuthorityManager<MemoryBackend>,
        workspace_id: WorkspaceId,
        change_count: usize,
        entity_count: usize,
        relation_count: usize,
        modified_entity: EntityId,
        final_signature: String,
        chain_source: EntityId,
        chain_target: EntityId,
    }

    /// Documentation bytes the receipt guard puts in its one modified entity,
    /// so the operation record it commits has mass worth not repeating.
    const RECEIPT_GUARD_PAYLOAD_BYTES: usize = 64 * 1024;

    /// How much smaller than the operation log the receipts index has to be.
    ///
    /// Repeating the record makes the two the same size, so anything above one
    /// fails the regression. Ten leaves room for the receipt's own seven fields
    /// on a fixture whose log is only 64 KB, and shrinks toward nothing as the
    /// log grows, which is the direction that matters.
    const RECEIPT_INDEX_SHARE_DIVISOR: usize = 10;

    fn build_synthetic_history_store(
        add_changes: usize,
        adds_per_change: usize,
        modify_changes: usize,
        modifies_per_change: usize,
    ) -> SyntheticHistoryStore {
        assert!(add_changes >= 1 && adds_per_change >= 2 && modify_changes >= 1);
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));

        let shared = SharedAdmissionPolicy::empty(0);
        let base_time = chrono::DateTime::parse_from_rfc3339("2026-07-28T16:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let new_change =
            |parents: Vec<SemanticChangeId>,
             sequence: usize,
             entity_deltas: Vec<EntityDelta>,
             relation_deltas: Vec<RelationDelta>,
             admission_policy_delta: Option<AdmissionPolicyDelta>| {
                let mut change = SemanticChange {
                    id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
                    origin: ChangeOrigin::Native,
                    parents,
                    timestamp: Timestamp(base_time + chrono::Duration::seconds(sequence as i64)),
                    author: AuthorId::new("synthetic-history"),
                    message: format!("synthetic change {sequence}"),
                    entity_deltas,
                    relation_deltas,
                    tree_deltas: Vec::new(),
                    admission_policy_delta,
                    external_reference_deltas: Vec::new(),
                    projected_files: Vec::new(),
                    spec_link: None,
                    evidence: Vec::new(),
                    risk_summary: None,
                };
                change.id = compute_semantic_change_id(&change).unwrap();
                change
            };

        let mut current_entities: BTreeMap<EntityId, Entity> = BTreeMap::new();
        let mut relations: Vec<Relation> = Vec::new();
        let mut changes: Vec<SemanticChange> = Vec::new();

        let mut seed = semantic_test_entity("src/seed.rs", "seed", LanguageId::Rust, 0x01);
        seed.file_origin = None;
        current_entities.insert(seed.id, seed.clone());
        changes.push(new_change(
            Vec::new(),
            0,
            vec![EntityDelta::Added { new: seed }],
            Vec::new(),
            Some(AdmissionPolicyDelta::initialize(shared.clone())),
        ));

        let mut chain_endpoints = None;
        for c in 0..add_changes {
            let mut entity_deltas = Vec::with_capacity(adds_per_change);
            let mut relation_deltas = Vec::new();
            let mut previous: Option<EntityId> = None;
            for i in 0..adds_per_change {
                let mut entity = semantic_test_entity(
                    &format!("src/mod_{c}.rs"),
                    &format!("fn_{c}_{i}"),
                    LanguageId::Rust,
                    (c % 251) as u8,
                );
                entity.file_origin = None;
                if let Some(source) = previous {
                    let relation = Relation {
                        id: RelationId::from_content(
                            &source.to_string(),
                            &entity.id.to_string(),
                            "calls",
                        ),
                        kind: RelationKind::Calls,
                        src: GraphNodeId::Entity(source),
                        dst: GraphNodeId::Entity(entity.id),
                        confidence: 1.0,
                        origin: RelationOrigin::Manual,
                        created_in: None,
                        import_source: None,
                        evidence: Vec::new(),
                    };
                    if chain_endpoints.is_none() {
                        chain_endpoints = Some((source, entity.id));
                    }
                    relations.push(relation.clone());
                    relation_deltas.push(RelationDelta::Added { new: relation });
                }
                previous = Some(entity.id);
                current_entities.insert(entity.id, entity.clone());
                entity_deltas.push(EntityDelta::Added { new: entity });
            }
            let parent = changes.last().expect("genesis exists").id;
            changes.push(new_change(
                vec![parent],
                1 + c,
                entity_deltas,
                relation_deltas,
                None,
            ));
        }
        let (chain_source, chain_target) = chain_endpoints.expect("adds_per_change >= 2");

        let mut modified_entity = None;
        for m in 0..modify_changes {
            let victims: Vec<EntityId> = current_entities
                .keys()
                .skip((m * modifies_per_change) % current_entities.len())
                .take(modifies_per_change.max(1))
                .copied()
                .collect();
            let mut entity_deltas = Vec::with_capacity(victims.len());
            for id in victims {
                let old = current_entities.get(&id).expect("victim exists").clone();
                let mut new = old.clone();
                new.signature = format!("{} /* rev {m} */", old.signature);
                modified_entity = Some(id);
                current_entities.insert(id, new.clone());
                entity_deltas.push(EntityDelta::Modified { old, new });
            }
            let parent = changes.last().expect("chain exists").id;
            changes.push(new_change(
                vec![parent],
                1 + add_changes + m,
                entity_deltas,
                Vec::new(),
                None,
            ));
        }
        let modified_entity = modified_entity.expect("modify_changes >= 1");
        let final_signature = current_entities
            .get(&modified_entity)
            .expect("modified entity exists")
            .signature
            .clone();

        let head = changes.last().expect("chain exists").id;
        let base_target = RefTarget::change(head);
        let tree_hash = compute_resolved_tree_hash(&ResolvedTree::default()).unwrap();
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xf1_2322));
        let frozen_overlay =
            FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::Sensitive, Vec::new()).unwrap();
        let effective_policy = EffectiveAdmissionPolicyStamp {
            shared: shared.stamp(),
            local: frozen_overlay.stamp(),
        };
        let main = RefName::branch(b"main").unwrap();
        let mut initial = transaction_shell(&manager, 0xf1_2322);
        let change_count = changes.len();
        initial.changes = changes;
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
                current_entities
                    .values()
                    .cloned()
                    .map(|new| EntityDelta::Added { new })
                    .collect(),
                relations
                    .iter()
                    .cloned()
                    .map(|new| RelationDelta::Added { new })
                    .collect(),
                Vec::new(),
            )
            .unwrap(),
            new_shared_admission_policy: shared,
            new_admission_policy: effective_policy,
        });
        initial.local_overlay_delta = Some(FrozenLocalOverlayDelta::initialize(frozen_overlay));
        manager.commit_repository_transaction(initial).unwrap();

        SyntheticHistoryStore {
            backend,
            manager,
            workspace_id,
            change_count,
            entity_count: current_entities.len(),
            relation_count: relations.len(),
            modified_entity,
            final_signature,
            chain_source,
            chain_target,
        }
    }

    /// The uncommitted relation the dirty-workspace variant stages.
    fn synthetic_overlay_relation(store: &SyntheticHistoryStore) -> Relation {
        Relation {
            id: RelationId::from_content(
                &store.chain_target.to_string(),
                &store.chain_source.to_string(),
                "overlay-calls",
            ),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(store.chain_target),
            dst: GraphNodeId::Entity(store.chain_source),
            confidence: 1.0,
            origin: RelationOrigin::Manual,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    fn stage_synthetic_overlay(store: &SyntheticHistoryStore) -> Relation {
        stage_overlay_relation(store, 0xf1_2323, synthetic_overlay_relation(store))
    }

    fn stage_overlay_relation(
        store: &SyntheticHistoryStore,
        operation: u128,
        relation: Relation,
    ) -> Relation {
        store
            .manager
            .commit_repository_transaction(semantic_workspace_transaction(
                &store.manager,
                operation,
                WorkspaceSemanticDelta::new_with_external_references(
                    Vec::new(),
                    vec![RelationDelta::Added {
                        new: relation.clone(),
                    }],
                    Vec::new(),
                )
                .unwrap(),
            ))
            .unwrap();
        relation
    }

    /// Assert the materialized workspace snapshot is exactly the replayed
    /// head state plus carried history, independent of how materialization is
    /// implemented. These assertions pin the contract FIR-2322's restructure
    /// must preserve.
    fn assert_synthetic_materialization(
        store: &SyntheticHistoryStore,
        materialized: &GraphSnapshot,
        staged: Option<&Relation>,
    ) {
        assert_eq!(materialized.entities.len(), store.entity_count);
        assert_eq!(
            materialized.relations.len(),
            store.relation_count + usize::from(staged.is_some())
        );
        assert_eq!(materialized.changes.len(), store.change_count);
        assert!(
            materialized.repository_authority.is_none(),
            "workspace query snapshots never carry the authority envelope"
        );
        assert_eq!(materialized.resolved_tree.len(), 0);
        let modified = materialized
            .entities
            .get(&store.modified_entity)
            .expect("modified entity present");
        assert_eq!(modified.signature, store.final_signature);
        let revisions = materialized
            .entity_revisions
            .get(&store.modified_entity)
            .expect("modified entity carries a revision timeline");
        assert!(
            revisions.len() >= 2,
            "a modified entity must retain more than one revision, found {}",
            revisions.len()
        );
        let outgoing = materialized
            .outgoing
            .get(&store.chain_source)
            .expect("chain source has outgoing adjacency");
        let expected_relation = RelationId::from_content(
            &store.chain_source.to_string(),
            &store.chain_target.to_string(),
            "calls",
        );
        assert!(outgoing.contains(&expected_relation));
        assert!(
            outgoing.windows(2).all(|pair| pair[0] <= pair[1]),
            "persisted adjacency lists stay sorted"
        );
        match staged {
            Some(relation) => {
                assert_eq!(materialized.relations.get(&relation.id), Some(relation));
            }
            None => {
                let staged_id = synthetic_overlay_relation(store).id;
                assert!(
                    !materialized.relations.contains_key(&staged_id),
                    "a clean workspace must not carry the staged overlay relation"
                );
            }
        }
    }

    fn materialize_synthetic(store: &SyntheticHistoryStore) -> GraphSnapshot {
        store
            .manager
            .workspace_graph_snapshot(&repository_id(), &store.workspace_id)
            .unwrap()
            .expect("synthetic workspace materializes")
    }

    #[test]
    fn synthetic_history_store_materializes_replayed_state_clean_and_dirty() {
        let store = build_synthetic_history_store(3, 12, 2, 4);
        assert!(
            store.manager.read_authority().metadata().workspaces[0]
                .semantic_overlay
                .is_empty(),
            "a workspace matching its committed base must not persist a compensating overlay"
        );
        let clean = materialize_synthetic(&store);
        assert_synthetic_materialization(&store, &clean, None);

        let staged = stage_synthetic_overlay(&store);
        assert!(
            !store.manager.read_authority().metadata().workspaces[0]
                .semantic_overlay
                .is_empty(),
            "the staged relation must persist as a workspace overlay"
        );
        let dirty = materialize_synthetic(&store);
        assert_synthetic_materialization(&store, &dirty, Some(&staged));
        assert_eq!(clean.entities, dirty.entities);
        assert_eq!(clean.entity_revisions, dirty.entity_revisions);
    }

    #[test]
    fn authority_history_view_replays_identically_to_a_full_graph_build() {
        let store = build_synthetic_history_store(2, 8, 1, 3);
        let lease = store.manager.read_authority();
        let snapshot = lease.snapshot();
        let head = lease
            .resolve_target_change_id(
                lease.metadata().workspaces[0]
                    .base_target
                    .as_ref()
                    .expect("synthetic workspace bases at head"),
            )
            .unwrap();

        let view = AuthorityHistoryView {
            changes: &snapshot.changes,
        };
        let viewed = view.resolve_graph_at(&head).unwrap();

        let mut graph_input = snapshot.clone();
        graph_input.repository_authority = None;
        let graph = InMemoryGraph::from_snapshot_without_text_index(graph_input).unwrap();
        let replayed = graph.resolve_graph_at(&head).unwrap();

        assert_eq!(viewed.entities, replayed.entities);
        assert_eq!(viewed.relations, replayed.relations);
        assert_eq!(viewed.entity_revisions, replayed.entity_revisions);
        assert_eq!(viewed.tree, replayed.tree);
        assert_eq!(viewed.external_references, replayed.external_references);
    }

    use crate::storage::format::MATERIALIZED_GRAPH_SCHEMA_VERSION;

    /// Resolve one workspace base and report which arm answered.
    ///
    /// The counters are read as the endpoints of a span rather than as running
    /// totals, because open-time and admission validation resolve bases too.
    fn resolve_base_counting_arms(
        snapshot: &GraphSnapshot,
        metadata: &PersistedRepositoryAuthority,
        workspace: &WorkspaceState,
    ) -> (GraphSnapshot, usize, usize) {
        let served_before = BASE_GRAPHS_SERVED_FROM_SECTION.with(|count| count.get());
        let folded_before = BASE_GRAPHS_RESOLVED_FROM_HISTORY.with(|count| count.get());
        let base = resolve_workspace_base_graph_snapshot(
            snapshot,
            metadata,
            workspace.base_target.as_ref(),
            WorkspaceBaseHistory::Carried(None),
        )
        .expect("a synthetic workspace base resolves");
        let served = BASE_GRAPHS_SERVED_FROM_SECTION.with(|count| count.get()) - served_before;
        let folded = BASE_GRAPHS_RESOLVED_FROM_HISTORY.with(|count| count.get()) - folded_before;
        (base, served, folded)
    }

    /// Compare two resolved bases over the REAL SET rather than by counting.
    ///
    /// Counting entities would pass for a section that answered the right
    /// number of the wrong ones, so this reads what one side actually produced
    /// and requires the other to hold each of those, by id and by value.
    fn assert_same_resolved_graph(left: &GraphSnapshot, right: &GraphSnapshot) {
        assert_eq!(
            left.entities.keys().collect::<BTreeSet<_>>(),
            right.entities.keys().collect::<BTreeSet<_>>(),
            "the two paths must resolve the same entity ids"
        );
        for (id, entity) in &left.entities {
            assert_eq!(
                Some(entity),
                right.entities.get(id),
                "entity {id} differs between the section and the fold"
            );
        }
        assert_eq!(
            left.relations.keys().collect::<BTreeSet<_>>(),
            right.relations.keys().collect::<BTreeSet<_>>(),
            "the two paths must resolve the same relation ids"
        );
        for (id, relation) in &left.relations {
            assert_eq!(
                Some(relation),
                right.relations.get(id),
                "relation {id} differs between the section and the fold"
            );
        }
        assert_eq!(left.entity_revisions, right.entity_revisions);
        assert_eq!(left.resolved_tree, right.resolved_tree);
        assert_eq!(left.external_references, right.external_references);
        assert_eq!(left.outgoing, right.outgoing);
        assert_eq!(left.incoming, right.incoming);
    }

    /// A synthetic store, its workspace, and the change its base names.
    fn synthetic_base_fixture() -> (
        GraphSnapshot,
        PersistedRepositoryAuthority,
        WorkspaceState,
        SemanticChangeId,
    ) {
        let store = build_synthetic_history_store(2, 8, 1, 3);
        let lease = store.manager.read_authority();
        let snapshot = lease.snapshot().clone();
        let metadata = lease.metadata().clone();
        let workspace = metadata.workspaces[0].clone();
        let change_id = lease
            .resolve_target_change_id(
                workspace
                    .base_target
                    .as_ref()
                    .expect("a synthetic workspace bases at head"),
            )
            .expect("the base target names a change");
        drop(lease);
        (snapshot, metadata, workspace, change_id)
    }

    #[test]
    fn the_capture_carries_tombstones_the_base_would_have_dropped() {
        // The reason the capture is a type with one constructor rather than a
        // convention. `resolve_workspace_base_graph_snapshot` moves five of the
        // seven domains into the base it returns and DROPS both tombstone maps,
        // so a section reassembled from that base would carry empty tombstones
        // and look exactly like a complete one.
        //
        // Built by hand rather than from a store, deliberately: the synthetic
        // fixture commits no removals, so its tombstones are empty and an
        // equality over them would be two empty maps agreeing. This arm is
        // where a NON-empty pair is exercised.
        let removed = semantic_test_entity("src/gone.rs", "gone", LanguageId::Rust, 0x5e);
        let removing_change = SemanticChangeId::from_hash(Hash256::from_bytes([0x77; 32]));
        let mut state = ResolvedGraphState::default();
        state
            .entity_tombstones
            .insert(removed.id, (removed.clone(), removing_change));
        assert_eq!(state.entity_tombstones.len(), 1, "the fixture is not empty");

        let at = SemanticChangeId::from_hash(Hash256::from_bytes([0x11; 32]));
        let section = CapturedBaseGraph::capture(at, state).into_section();

        assert_eq!(section.resolved_at, at);
        assert_eq!(
            section.state.entity_tombstones.len(),
            1,
            "a capture that dropped tombstones would look complete and be wrong"
        );
        let (carried, by_change) = section
            .state
            .entity_tombstones
            .get(&removed.id)
            .expect("the tombstone survives by id");
        assert_eq!(carried, &removed);
        assert_eq!(by_change, &removing_change);
    }

    #[test]
    fn a_publish_writes_no_section_and_that_is_deliberate() {
        // A guard on a decision, not on an accident. Capturing the resolved
        // state at `next_base` costs a second copy for the rest of a workspace
        // mutation, and `a_workspace_mutation_does_not_hold_the_whole_history_four_times`
        // read 7.17 copies of the history against a 4.4 ceiling when it was
        // tried. Sections are written by an explicit operation instead, so this
        // test exists to make a future re-introduction on the publish path
        // visible rather than merely slow.
        let (snapshot, _, _, _) = synthetic_base_fixture();
        assert!(
            snapshot.materialized_graph.is_none(),
            "a publish must not write a materialized graph section; see the note in \
             apply_workspace and the memory guard it names"
        );
    }

    #[test]
    fn an_explicit_materialize_operation_stamps_the_workspace_base_once() {
        let store = build_synthetic_history_store(2, 8, 1, 3);
        let roots_before = store.manager.read_authority().roots().clone();
        let backend_before = store
            .backend
            .load_snapshot_authority(repository_id().as_str())
            .unwrap()
            .expect("the fixture wrote authority")
            .head_generation;

        let outcome = store
            .manager
            .materialize_workspace_base_graph_section(&repository_id(), &store.workspace_id)
            .unwrap()
            .expect("the synthetic workspace has a committed base");
        let MaterializedGraphSectionOutcome::Persisted {
            resolved_at,
            authority_generation,
        } = outcome
        else {
            panic!("the first explicit materialization must persist")
        };
        assert_eq!(authority_generation, roots_before.generation);

        let lease = store.manager.read_authority();
        assert_eq!(lease.roots(), &roots_before);
        assert_eq!(lease.generation(), roots_before.generation);
        let section = lease
            .snapshot()
            .materialized_graph
            .as_ref()
            .expect("the explicit operation writes a section");
        section
            .validate_for(&resolved_at)
            .expect("the written section names the workspace base and current schema");
        assert_eq!(lease.snapshot().version, lease.snapshot().wire_version());
        drop(lease);

        let backend_after = store
            .backend
            .load_snapshot_authority(repository_id().as_str())
            .unwrap()
            .expect("the rewrite remained durable")
            .head_generation;
        assert_eq!(
            backend_after,
            backend_before + 1,
            "the equivalent full snapshot must advance its fenced backend cursor"
        );

        assert_eq!(
            store
                .manager
                .materialize_workspace_base_graph_section(&repository_id(), &store.workspace_id)
                .unwrap(),
            Some(MaterializedGraphSectionOutcome::AlreadyCurrent {
                resolved_at,
                authority_generation: roots_before.generation,
            })
        );
        assert_eq!(
            store
                .backend
                .load_snapshot_authority(repository_id().as_str())
                .unwrap()
                .unwrap()
                .head_generation,
            backend_after,
            "an already-valid section must not perform another durable write"
        );
    }

    #[test]
    fn materialize_distinguishes_a_missing_workspace_from_an_unborn_one() {
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xf1_2955));
        manager
            .commit_repository_transaction(unborn_workspace_transaction(
                &manager, 0xf1_2956, 0xf1_2955, b"unborn",
            ))
            .unwrap();
        let backend_before = backend
            .load_snapshot_authority(repository_id().as_str())
            .unwrap()
            .unwrap()
            .head_generation;

        assert_eq!(
            manager
                .materialize_workspace_base_graph_section(&repository_id(), &workspace_id)
                .unwrap(),
            Some(MaterializedGraphSectionOutcome::NoBaseTarget {
                authority_generation: manager.read_authority().generation(),
            })
        );
        assert_eq!(
            manager
                .materialize_workspace_base_graph_section(
                    &repository_id(),
                    &WorkspaceId::from_uuid(Uuid::from_u128(0xf1_ffff)),
                )
                .unwrap(),
            None
        );
        assert_eq!(
            backend
                .load_snapshot_authority(repository_id().as_str())
                .unwrap()
                .unwrap()
                .head_generation,
            backend_before,
            "neither no-op result may advance the backend cursor"
        );
    }

    #[test]
    fn the_explicitly_materialized_section_is_the_complete_history_fold() {
        let store = build_synthetic_history_store(2, 8, 1, 3);
        let outcome = store
            .manager
            .materialize_workspace_base_graph_section(&repository_id(), &store.workspace_id)
            .unwrap()
            .unwrap();
        let MaterializedGraphSectionOutcome::Persisted { resolved_at, .. } = outcome else {
            panic!("the first explicit materialization must persist")
        };
        let lease = store.manager.read_authority();
        let section = lease
            .snapshot()
            .materialized_graph
            .as_ref()
            .expect("the explicit operation writes a section");
        let folded = AuthorityHistoryView {
            changes: &lease.snapshot().changes,
        }
        .resolve_graph_at(&resolved_at)
        .expect("the workspace base folds from admitted history");

        assert!(!section.state.entities.is_empty());
        assert!(!section.state.entity_revisions.is_empty());
        assert_eq!(section.state.entities, folded.entities);
        assert_eq!(section.state.relations, folded.relations);
        assert_eq!(section.state.entity_revisions, folded.entity_revisions);
        assert_eq!(section.state.tree, folded.tree);
        assert_eq!(
            section.state.external_references,
            folded.external_references
        );
        assert_eq!(section.state.entity_tombstones, folded.entity_tombstones);
        assert_eq!(
            section.state.relation_tombstones,
            folded.relation_tombstones
        );
    }

    #[test]
    fn a_successor_shares_the_materialized_section_instead_of_copying_it() {
        let store = build_synthetic_history_store(2, 8, 1, 3);
        store
            .manager
            .materialize_workspace_base_graph_section(&repository_id(), &store.workspace_id)
            .unwrap()
            .unwrap();
        let before = Arc::clone(
            store
                .manager
                .read_authority()
                .snapshot()
                .materialized_graph
                .as_ref()
                .expect("materialize writes a section"),
        );

        stage_synthetic_overlay(&store);

        let after = Arc::clone(
            store
                .manager
                .read_authority()
                .snapshot()
                .materialized_graph
                .as_ref()
                .expect("an ordinary successor retains the base section"),
        );
        assert!(
            Arc::ptr_eq(&before, &after),
            "later publishes must share the immutable section allocation"
        );
    }

    #[test]
    fn a_logical_generation_survives_materialize_then_a_frame_and_both_reopens() {
        let synthetic = build_synthetic_history_store(2, 8, 1, 3);
        let (seed_bytes, _) = synthetic
            .backend
            .snapshot
            .lock()
            .clone()
            .expect("the synthetic fixture persisted its authority");
        let directory = TempDir::new().unwrap();
        let backend = Arc::new(LocalFileBackend::new(directory.path()));
        backend
            .save_snapshot(repository_id().as_str(), &seed_bytes, 0)
            .expect("seed the local backend from the admitted synthetic authority");
        let manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let roots_before = manager.read_authority().roots().clone();

        let outcome = manager
            .materialize_workspace_base_graph_section(&repository_id(), &synthetic.workspace_id)
            .unwrap()
            .unwrap();
        let MaterializedGraphSectionOutcome::Persisted { resolved_at, .. } = outcome else {
            panic!("the first explicit materialization must persist")
        };
        let materialized_backend = backend
            .load_snapshot_authority(repository_id().as_str())
            .unwrap()
            .unwrap();
        assert_eq!(
            materialized_backend.snapshot_generation, materialized_backend.head_generation,
            "an equivalent rewrite is a complete snapshot, never a frame"
        );
        assert!(materialized_backend.head_generation > roots_before.generation);

        let metadata = RepositoryAuthorityMetadata::open(repository_id(), Arc::clone(&backend))
            .unwrap()
            .expect("metadata-only open must accept distinct backend and logical generations");
        assert_eq!(metadata.generation(), roots_before.generation);
        assert_eq!(metadata.metadata().roots, roots_before);
        metadata
            .materialized_graph_for(&resolved_at)
            .expect("metadata-only open carries the new section");
        let full = RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        assert_eq!(full.read_authority().roots(), &roots_before);
        full.read_authority()
            .snapshot()
            .materialized_graph
            .as_ref()
            .expect("full open carries the new section")
            .validate_for(&resolved_at)
            .unwrap();

        let relation = synthetic_overlay_relation(&synthetic);
        let transaction = semantic_workspace_transaction(
            &manager,
            0xf1_2324,
            WorkspaceSemanticDelta::new_with_external_references(
                Vec::new(),
                vec![RelationDelta::Added {
                    new: relation.clone(),
                }],
                Vec::new(),
            )
            .unwrap(),
        );
        manager
            .commit_repository_transaction(transaction)
            .expect("an ordinary successor must commit after the equivalent rewrite");
        let framed = backend
            .load_snapshot_authority(repository_id().as_str())
            .unwrap()
            .unwrap();
        assert!(
            framed.snapshot_generation < framed.head_generation,
            "the control must carry a frame after the materialized base"
        );
        assert_eq!(
            manager.read_authority().generation(),
            roots_before.generation + 1
        );

        let metadata_after =
            RepositoryAuthorityMetadata::open(repository_id(), Arc::clone(&backend))
                .unwrap()
                .expect("metadata-only open must walk the frame after a representation rewrite");
        let full_after =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        assert_eq!(
            metadata_after.generation(),
            full_after.read_authority().generation()
        );
        assert_eq!(
            metadata_after.metadata(),
            full_after.read_authority().metadata()
        );
        metadata_after
            .materialized_graph_for(&resolved_at)
            .expect("the unchanged workspace base still accepts the section after a frame");
        assert_eq!(
            full_after
                .workspace_graph_snapshot(&repository_id(), &synthetic.workspace_id)
                .unwrap()
                .unwrap()
                .relations
                .get(&relation.id),
            Some(&relation),
            "the full reopen must apply the successor workspace overlay"
        );
    }

    #[test]
    fn an_indeterminate_materialize_reconciles_the_exact_installed_snapshot() {
        let synthetic = build_synthetic_history_store(2, 8, 1, 3);
        let (seed_bytes, _) = synthetic
            .backend
            .snapshot
            .lock()
            .clone()
            .expect("the synthetic fixture persisted its authority");
        let directory = TempDir::new().unwrap();
        let backend = Arc::new(LocalFileBackend::new(directory.path()));
        backend
            .save_snapshot(repository_id().as_str(), &seed_bytes, 0)
            .unwrap();
        let manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let logical_generation = manager.read_authority().generation();

        backend.fail_next_snapshot_parent_sync_after_install();
        let error = manager
            .materialize_workspace_base_graph_section(&repository_id(), &synthetic.workspace_id)
            .expect_err("lost post-install acknowledgement must remain indeterminate");
        assert!(matches!(
            error,
            KinDbError::SnapshotPersistenceIndeterminate(_)
        ));
        assert!(manager
            .read_authority()
            .snapshot()
            .materialized_graph
            .is_none());
        let installed_cursor = backend
            .load_snapshot_authority(repository_id().as_str())
            .unwrap()
            .expect("the exact materialized candidate was installed")
            .head_generation;

        let reconciled = manager
            .materialize_workspace_base_graph_section(&repository_id(), &synthetic.workspace_id)
            .expect("the next writer reconciles before preparing")
            .expect("the workspace still exists");
        assert!(matches!(
            reconciled,
            MaterializedGraphSectionOutcome::AlreadyCurrent {
                authority_generation,
                ..
            } if authority_generation == logical_generation
        ));
        assert!(manager
            .read_authority()
            .snapshot()
            .materialized_graph
            .is_some());
        assert_eq!(
            backend
                .load_snapshot_authority(repository_id().as_str())
                .unwrap()
                .unwrap()
                .head_generation,
            installed_cursor,
            "reconciliation adopts the installed bytes without allocating another cursor"
        );
    }

    /// A section stamped by hand, standing in for what the materialize
    /// operation will write.
    ///
    /// Built through `CapturedBaseGraph` rather than by assembling a
    /// `MaterializedGraphSection` literal, so these tests exercise the same
    /// one-constructor path the real writer uses and cannot accidentally build
    /// a section no producer could.
    fn stamp_a_section(snapshot: &mut GraphSnapshot, change_id: SemanticChangeId) {
        let state = AuthorityHistoryView {
            changes: &snapshot.changes,
        }
        .resolve_graph_at(&change_id)
        .expect("the head resolves");
        snapshot.materialized_graph = Some(Arc::new(
            CapturedBaseGraph::capture(change_id, state).into_section(),
        ));
        snapshot.version = snapshot.wire_version();
    }

    #[test]
    fn a_stamped_section_is_what_the_history_folds_to() {
        // The writer's obligation, and the one no read-time check can make
        // cheaply: the memo equals the call. Compared over the real set rather
        // than by counting, because the right number of the wrong entities
        // passes a count.
        let (mut snapshot, _, _, change_id) = synthetic_base_fixture();
        stamp_a_section(&mut snapshot, change_id);
        let section = snapshot
            .materialized_graph
            .as_ref()
            .expect("the stamp put one there");
        let folded = AuthorityHistoryView {
            changes: &snapshot.changes,
        }
        .resolve_graph_at(&change_id)
        .expect("the head resolves");

        assert_eq!(section.resolved_at, change_id);
        assert_eq!(
            section.state.entities.keys().collect::<BTreeSet<_>>(),
            folded.entities.keys().collect::<BTreeSet<_>>()
        );
        for (id, entity) in &folded.entities {
            assert_eq!(Some(entity), section.state.entities.get(id));
        }
        assert_eq!(
            section.state.relations.keys().collect::<BTreeSet<_>>(),
            folded.relations.keys().collect::<BTreeSet<_>>()
        );
        for (id, relation) in &folded.relations {
            assert_eq!(Some(relation), section.state.relations.get(id));
        }
        assert_eq!(section.state.entity_revisions, folded.entity_revisions);
        assert_eq!(section.state.tree, folded.tree);
        assert_eq!(
            section.state.external_references,
            folded.external_references
        );
        assert!(
            !section.state.entities.is_empty(),
            "an empty section would make every comparison above vacuous"
        );
    }

    #[test]
    fn a_store_with_no_section_folds_its_base_out_of_history() {
        // The control for every arm below.
        let (snapshot, metadata, workspace, _) = synthetic_base_fixture();
        assert!(snapshot.materialized_graph.is_none());

        let (base, served, folded) = resolve_base_counting_arms(&snapshot, &metadata, &workspace);
        assert_eq!(served, 0, "there is no section to serve");
        assert_eq!(folded, 1, "so the base must be folded out of history");
        assert!(
            !base.entities.is_empty(),
            "the fixture must resolve a non-empty graph, or every comparison below is vacuous"
        );
    }

    #[test]
    fn a_store_with_a_section_serves_its_base_without_folding_history() {
        let (mut snapshot, metadata, workspace, change_id) = synthetic_base_fixture();
        let (folded_base, _, folded_first) =
            resolve_base_counting_arms(&snapshot, &metadata, &workspace);
        assert_eq!(folded_first, 1, "the first pass must be the fold");

        stamp_a_section(&mut snapshot, change_id);
        let (served_base, served, folded) =
            resolve_base_counting_arms(&snapshot, &metadata, &workspace);
        assert_eq!(served, 1, "the section must answer");
        assert_eq!(
            folded, 0,
            "and nothing may fold the history behind its back"
        );
        assert_same_resolved_graph(&served_base, &folded_base);
    }

    #[test]
    fn a_section_resolving_at_another_change_is_refused_and_the_history_answers() {
        // The mutation this catches is a reader that uses the section without
        // validating it. That reader passes the test above, because there the
        // section is correct; only a WRONG section separates the two.
        let (mut snapshot, metadata, workspace, change_id) = synthetic_base_fixture();
        let (folded_base, _, _) = resolve_base_counting_arms(&snapshot, &metadata, &workspace);

        stamp_a_section(&mut snapshot, change_id);
        let mut wrong = snapshot
            .materialized_graph
            .as_deref()
            .cloned()
            .expect("the stamp put one there");
        // Emptied, so a reader that serves without checking gives an answer
        // that cannot be mistaken for the right one.
        wrong.state.entities.clear();
        wrong.state.relations.clear();
        wrong.resolved_at = SemanticChangeId::from_hash(Hash256::from_bytes([0x5a; 32]));
        snapshot.materialized_graph = Some(Arc::new(wrong));

        let (base, served, folded) = resolve_base_counting_arms(&snapshot, &metadata, &workspace);
        assert_eq!(served, 0, "a section for another change must not answer");
        assert_eq!(folded, 1, "the history must answer instead");
        assert_same_resolved_graph(&base, &folded_base);
    }

    #[test]
    fn a_section_of_an_unknown_schema_is_refused_and_the_history_answers() {
        // Separate from the target arm because the two can hide each other. A
        // validator that dropped the schema check entirely would still pass
        // the target test.
        let (mut snapshot, metadata, workspace, change_id) = synthetic_base_fixture();
        let (folded_base, _, _) = resolve_base_counting_arms(&snapshot, &metadata, &workspace);

        stamp_a_section(&mut snapshot, change_id);
        let mut wrong = snapshot
            .materialized_graph
            .as_deref()
            .cloned()
            .expect("the stamp put one there");
        wrong.state.entities.clear();
        wrong.state.relations.clear();
        wrong.schema_version = MATERIALIZED_GRAPH_SCHEMA_VERSION + 1;
        snapshot.materialized_graph = Some(Arc::new(wrong));

        let (base, served, folded) = resolve_base_counting_arms(&snapshot, &metadata, &workspace);
        assert_eq!(served, 0, "an unknown schema must not answer");
        assert_eq!(folded, 1, "the history must answer instead");
        assert_same_resolved_graph(&base, &folded_base);
    }

    #[test]
    fn authority_history_view_fails_closed_outside_replay() {
        let changes = HashMap::new();
        let view = AuthorityHistoryView { changes: &changes };

        let missing_head = SemanticChangeId::from_hash(Hash256::from_bytes([7; 32]));
        let absent = view
            .resolve_graph_at(&missing_head)
            .expect_err("replaying an absent head must fail closed");
        assert!(
            absent.to_string().contains(&missing_head.to_string()),
            "unexpected absent-head error: {absent}"
        );

        for (label, error) in [
            (
                "entity history",
                view.get_entity_history(&EntityId::from_content("src/a.rs", "a", "function", 1))
                    .expect_err("entity history is not served"),
            ),
            (
                "merge-base search",
                view.find_merge_bases(&missing_head, &missing_head)
                    .expect_err("merge bases are not served"),
            ),
            (
                "change-range listing",
                view.get_changes_since(&missing_head, &missing_head)
                    .expect_err("change ranges are not served"),
            ),
        ] {
            assert!(
                error
                    .to_string()
                    .contains("workspace materialization history view"),
                "{label} must refuse by name, got: {error}"
            );
        }
    }

    /// Compare two workspace query snapshots domain by domain.
    ///
    /// Destructured rather than field-selected so a new snapshot domain fails
    /// to compile here until someone decides whether a prepared serve has to
    /// reproduce it. Counting entities would pass for a serve that dropped
    /// every review, session, or revision the materialization carried.
    fn assert_workspace_snapshots_identical(served: &GraphSnapshot, fresh: &GraphSnapshot) {
        let GraphSnapshot {
            version,
            entities,
            relations,
            outgoing,
            incoming,
            changes,
            change_children,
            work_items,
            annotations,
            work_links,
            reviews,
            review_decisions,
            review_notes,
            review_discussions,
            review_assignments,
            test_cases,
            assertions,
            verification_runs,
            mock_hints,
            contracts,
            actors,
            delegations,
            approvals,
            audit_events,
            shallow_files,
            file_layouts,
            structured_artifacts,
            opaque_artifacts,
            resolved_tree,
            sessions,
            intents,
            downstream_warnings,
            entity_revisions,
            repository_authority,
            external_references,
            materialized_graph,
        } = served;
        assert_eq!(*version, fresh.version);
        // `ResolvedGraphState` carries no `PartialEq`, so the two sections are
        // compared through the exact MessagePack form they persist in.
        assert_eq!(
            rmp_serde::to_vec(materialized_graph).expect("a section encodes"),
            rmp_serde::to_vec(&fresh.materialized_graph).expect("a section encodes"),
        );
        assert_eq!(*entities, fresh.entities);
        assert_eq!(*relations, fresh.relations);
        assert_eq!(*outgoing, fresh.outgoing);
        assert_eq!(*incoming, fresh.incoming);
        assert_eq!(*changes, fresh.changes);
        assert_eq!(*change_children, fresh.change_children);
        assert_eq!(*resolved_tree, fresh.resolved_tree);
        assert_eq!(*entity_revisions, fresh.entity_revisions);
        assert_eq!(*external_references, fresh.external_references);
        assert!(
            repository_authority.is_none() && fresh.repository_authority.is_none(),
            "a workspace query snapshot never carries an authority envelope"
        );
        // The remaining domains carry kin-model types with no `PartialEq`, so
        // they are compared as canonically ordered encodings instead. None of
        // them contains a `HashMap`, so each entry's encoding is stable and
        // only the order two maps happen to iterate in has to be removed.
        assert_eq!(canonical_map(work_items), canonical_map(&fresh.work_items));
        assert_eq!(
            canonical_map(annotations),
            canonical_map(&fresh.annotations)
        );
        assert_eq!(
            canonical_value(work_links),
            canonical_value(&fresh.work_links)
        );
        assert_eq!(canonical_map(reviews), canonical_map(&fresh.reviews));
        assert_eq!(
            canonical_map(review_decisions),
            canonical_map(&fresh.review_decisions)
        );
        assert_eq!(
            canonical_value(review_notes),
            canonical_value(&fresh.review_notes)
        );
        assert_eq!(
            canonical_value(review_discussions),
            canonical_value(&fresh.review_discussions)
        );
        assert_eq!(
            canonical_map(review_assignments),
            canonical_map(&fresh.review_assignments)
        );
        assert_eq!(canonical_map(test_cases), canonical_map(&fresh.test_cases));
        assert_eq!(canonical_map(assertions), canonical_map(&fresh.assertions));
        assert_eq!(
            canonical_map(verification_runs),
            canonical_map(&fresh.verification_runs)
        );
        assert_eq!(
            canonical_value(mock_hints),
            canonical_value(&fresh.mock_hints)
        );
        assert_eq!(canonical_map(contracts), canonical_map(&fresh.contracts));
        assert_eq!(canonical_map(actors), canonical_map(&fresh.actors));
        assert_eq!(
            canonical_value(delegations),
            canonical_value(&fresh.delegations)
        );
        assert_eq!(
            canonical_value(approvals),
            canonical_value(&fresh.approvals)
        );
        assert_eq!(
            canonical_value(audit_events),
            canonical_value(&fresh.audit_events)
        );
        assert_eq!(
            canonical_value(shallow_files),
            canonical_value(&fresh.shallow_files)
        );
        assert_eq!(
            canonical_value(file_layouts),
            canonical_value(&fresh.file_layouts)
        );
        assert_eq!(
            canonical_value(structured_artifacts),
            canonical_value(&fresh.structured_artifacts)
        );
        assert_eq!(
            canonical_value(opaque_artifacts),
            canonical_value(&fresh.opaque_artifacts)
        );
        assert_eq!(canonical_map(sessions), canonical_map(&fresh.sessions));
        assert_eq!(canonical_map(intents), canonical_map(&fresh.intents));
        assert_eq!(
            canonical_value(downstream_warnings),
            canonical_value(&fresh.downstream_warnings)
        );
    }

    fn canonical_value<T: Serialize>(value: &T) -> Vec<u8> {
        rmp_serde::to_vec(value).expect("a snapshot domain encodes")
    }

    fn canonical_map<K: Serialize, V: Serialize>(map: &HashMap<K, V>) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut entries: Vec<_> = map
            .iter()
            .map(|(key, value)| (canonical_value(key), canonical_value(value)))
            .collect();
        entries.sort();
        entries
    }

    /// Reopen the synthetic store the way a cold process would, so the open
    /// binds prepared state to the exact durable authority bytes.
    fn reopen_synthetic(
        store: &SyntheticHistoryStore,
    ) -> RepositoryAuthorityManager<MemoryBackend> {
        RepositoryAuthorityManager::open(repository_id(), Arc::clone(&store.backend)).unwrap()
    }

    /// The synthetic store with a staged overlay, which is the workspace shape
    /// a prepared artifact is admitted for: materializing it cannot take the
    /// clean fast path, so it pays a graph build, a delta application, a full
    /// export, and a validation pass on top of the replay.
    fn build_overlaid_history_store(
        add_changes: usize,
        adds_per_change: usize,
        modify_changes: usize,
        modifies_per_change: usize,
    ) -> (SyntheticHistoryStore, Relation) {
        let store = build_synthetic_history_store(
            add_changes,
            adds_per_change,
            modify_changes,
            modifies_per_change,
        );
        let staged = stage_synthetic_overlay(&store);
        (store, staged)
    }

    fn stored_prepared_binding(store: &SyntheticHistoryStore) -> PreparedWorkspaceGraphBinding {
        serde_json::from_slice(&store.backend.prepared_artifact(&store.workspace_id).binding)
            .expect("a recorded binding decodes")
    }

    fn materialize_through(
        manager: &RepositoryAuthorityManager<MemoryBackend>,
        workspace_id: &WorkspaceId,
    ) -> GraphSnapshot {
        manager
            .workspace_graph_snapshot(&repository_id(), workspace_id)
            .unwrap()
            .expect("the synthetic workspace exists")
    }

    #[test]
    fn prepared_workspace_state_is_written_on_a_miss_and_served_on_the_next_open() {
        let (store, _staged) = build_overlaid_history_store(3, 12, 2, 4);
        let fresh = materialize_synthetic(&store);

        let first = reopen_synthetic(&store);
        assert_eq!(
            first.prepared_workspace_graph_stats(),
            PreparedWorkspaceGraphStats::default(),
            "an open that has answered nothing yet has done nothing"
        );
        let materialized = materialize_through(&first, &store.workspace_id);
        assert_eq!(
            first.prepared_workspace_graph_stats(),
            PreparedWorkspaceGraphStats {
                serves: 0,
                writes: 1,
                refusals: 0,
                last_refusal: None,
            },
            "the first open of a store with no artifact materializes and records one"
        );
        assert_workspace_snapshots_identical(&materialized, &fresh);

        let second = reopen_synthetic(&store);
        let served = materialize_through(&second, &store.workspace_id);
        assert_eq!(
            second.prepared_workspace_graph_stats(),
            PreparedWorkspaceGraphStats {
                serves: 1,
                writes: 0,
                refusals: 0,
                last_refusal: None,
            },
            "an identical reopen answers from the artifact and writes nothing"
        );
        assert_workspace_snapshots_identical(&served, &fresh);
    }

    #[test]
    fn prepared_workspace_state_refuses_every_mismatched_binding_field() {
        let (store, _staged) = build_overlaid_history_store(2, 8, 1, 3);
        let fresh = materialize_synthetic(&store);
        materialize_through(&reopen_synthetic(&store), &store.workspace_id);
        let recorded = store.backend.prepared_artifact(&store.workspace_id);

        for (field, corruption) in [
            (
                "prepared_version",
                serde_json::json!(PREPARED_WORKSPACE_GRAPH_VERSION + 1),
            ),
            (
                "history_validation_version",
                serde_json::json!(HISTORY_VALIDATION_VERSION + 1),
            ),
            (
                "snapshot_version",
                serde_json::json!(GraphSnapshot::CURRENT_VERSION + 1),
            ),
            ("repository_id", serde_json::json!("some-other-repository")),
            (
                "workspace_id",
                serde_json::json!(WorkspaceId::from_uuid(Uuid::from_u128(0x2334)).to_string()),
            ),
            ("generation", serde_json::json!(4_242u64)),
            (
                "authority_snapshot_sha256",
                serde_json::json!(hex::encode(Sha256::digest(b"different authority bytes"))),
            ),
            (
                "payload_sha256",
                serde_json::json!(hex::encode(Sha256::digest(b"different payload bytes"))),
            ),
        ] {
            store
                .backend
                .install_prepared_artifact(&store.workspace_id, recorded.clone());
            store
                .backend
                .corrupt_prepared_binding_field(&store.workspace_id, field, corruption);

            let manager = reopen_synthetic(&store);
            let materialized = materialize_through(&manager, &store.workspace_id);
            assert_eq!(
                manager.prepared_workspace_graph_stats(),
                PreparedWorkspaceGraphStats {
                    serves: 0,
                    writes: 1,
                    refusals: 1,
                    last_refusal: Some(field.to_string()),
                },
                "a mismatched {field} must refuse by name, materialize, and rewrite"
            );
            assert_workspace_snapshots_identical(&materialized, &fresh);

            let rewritten = reopen_synthetic(&store);
            let served = materialize_through(&rewritten, &store.workspace_id);
            assert_eq!(
                rewritten.prepared_workspace_graph_stats().serves,
                1,
                "the rewrite after a {field} refusal must be servable"
            );
            assert_workspace_snapshots_identical(&served, &fresh);
        }
    }

    #[test]
    fn prepared_workspace_state_refuses_a_payload_its_binding_does_not_name() {
        let (store, _staged) = build_overlaid_history_store(2, 8, 1, 3);
        let fresh = materialize_synthetic(&store);
        materialize_through(&reopen_synthetic(&store), &store.workspace_id);

        let mut artifact = store.backend.prepared_artifact(&store.workspace_id);
        let last = artifact.payload.len() - 1;
        artifact.payload[last] ^= 0xff;
        store
            .backend
            .install_prepared_artifact(&store.workspace_id, artifact);

        let manager = reopen_synthetic(&store);
        let materialized = materialize_through(&manager, &store.workspace_id);
        assert_eq!(
            manager.prepared_workspace_graph_stats(),
            PreparedWorkspaceGraphStats {
                serves: 0,
                writes: 1,
                refusals: 1,
                last_refusal: Some("payload_sha256".to_string()),
            },
            "payload bytes the binding does not name are refused before they are decoded"
        );
        assert_workspace_snapshots_identical(&materialized, &fresh);
    }

    #[test]
    fn prepared_workspace_state_refuses_a_payload_whose_own_frame_is_corrupt() {
        let (store, _staged) = build_overlaid_history_store(2, 8, 1, 3);
        let fresh = materialize_synthetic(&store);
        materialize_through(&reopen_synthetic(&store), &store.workspace_id);

        // Break the frame's body under its own checksum trailer, then restamp
        // the binding so the artifact agrees with itself. Only the frame's own
        // integrity is left to catch this.
        let mut artifact = store.backend.prepared_artifact(&store.workspace_id);
        artifact.payload[20] ^= 0xff;
        store
            .backend
            .install_prepared_artifact(&store.workspace_id, artifact.clone());
        store.backend.corrupt_prepared_binding_field(
            &store.workspace_id,
            "payload_sha256",
            serde_json::json!(hex::encode(Sha256::digest(&artifact.payload))),
        );

        let manager = reopen_synthetic(&store);
        let materialized = materialize_through(&manager, &store.workspace_id);
        assert_eq!(
            manager.prepared_workspace_graph_stats(),
            PreparedWorkspaceGraphStats {
                serves: 0,
                writes: 1,
                refusals: 1,
                last_refusal: Some("payload_frame".to_string()),
            },
            "a frame that fails its own checksum is refused even when its binding agrees"
        );
        assert_workspace_snapshots_identical(&materialized, &fresh);
    }

    #[test]
    fn prepared_workspace_state_refuses_a_stale_artifact_after_a_workspace_mutation() {
        let (store, first) = build_overlaid_history_store(2, 8, 1, 3);
        let before = materialize_synthetic(&store);
        let opened = reopen_synthetic(&store);
        materialize_through(&opened, &store.workspace_id);
        assert_eq!(opened.prepared_workspace_graph_stats().writes, 1);
        let stale_binding = stored_prepared_binding(&store);

        // A second overlay relation committed through the real transaction
        // surface, so the authority bytes move and the artifact stops applying.
        let second = stage_overlay_relation(
            &store,
            0xf1_2334,
            Relation {
                id: RelationId::from_content(
                    &store.modified_entity.to_string(),
                    &store.chain_source.to_string(),
                    "overlay-calls",
                ),
                src: GraphNodeId::Entity(store.modified_entity),
                dst: GraphNodeId::Entity(store.chain_source),
                ..first
            },
        );
        let mutated = materialize_synthetic(&store);
        assert!(
            !before.relations.contains_key(&second.id)
                && mutated.relations.contains_key(&second.id),
            "the second overlay relation must actually change what the workspace resolves"
        );

        let after_mutation = reopen_synthetic(&store);
        let materialized = materialize_through(&after_mutation, &store.workspace_id);
        // The mutation moved the logical generation too, and that is the
        // cheaper mismatch, so it is the one reported. The authority digest is
        // what makes the refusal sound rather than incidental, so assert it
        // moved as well: a change that somehow held the generation still would
        // still have to clear that field.
        assert_eq!(
            after_mutation.prepared_workspace_graph_stats(),
            PreparedWorkspaceGraphStats {
                serves: 0,
                writes: 1,
                refusals: 1,
                last_refusal: Some("generation".to_string()),
            },
            "an artifact bound to superseded authority is refused by name"
        );
        let fresh_binding = stored_prepared_binding(&store);
        assert_ne!(
            stale_binding.authority_snapshot_sha256, fresh_binding.authority_snapshot_sha256,
            "a workspace mutation must produce different authority bytes and a different digest"
        );
        assert_ne!(stale_binding.generation, fresh_binding.generation);
        assert_workspace_snapshots_identical(&materialized, &mutated);

        let rewritten = reopen_synthetic(&store);
        let served = materialize_through(&rewritten, &store.workspace_id);
        assert_eq!(
            rewritten.prepared_workspace_graph_stats().serves,
            1,
            "the rewrite after the mutation must serve the new state"
        );
        assert_workspace_snapshots_identical(&served, &mutated);
    }

    #[test]
    fn a_backend_without_prepared_state_materializes_and_serves_nothing() {
        let (store, _staged) = build_overlaid_history_store(2, 8, 1, 3);
        let fresh = materialize_synthetic(&store);
        let blind = Arc::new(PreparedBlindBackend(Arc::clone(&store.backend)));

        for round in 0..2 {
            let manager =
                RepositoryAuthorityManager::open(repository_id(), Arc::clone(&blind)).unwrap();
            let materialized = manager
                .workspace_graph_snapshot(&repository_id(), &store.workspace_id)
                .unwrap()
                .expect("the synthetic workspace exists");
            assert_workspace_snapshots_identical(&materialized, &fresh);
            assert_eq!(
                manager.prepared_workspace_graph_stats(),
                PreparedWorkspaceGraphStats::default(),
                "round {round} on a backend with nowhere to record must serve and record nothing"
            );
        }
        assert!(
            store
                .backend
                .load_prepared_workspace_graph(
                    repository_id().as_str(),
                    &store.workspace_id.to_string(),
                )
                .unwrap()
                .is_none(),
            "a default no-op backend must not have reached durable prepared state"
        );
    }

    #[test]
    fn prepared_workspace_state_is_skipped_where_materializing_is_already_cheaper() {
        let store = build_synthetic_history_store(2, 8, 1, 3);
        assert!(
            store.manager.read_authority().metadata().workspaces[0]
                .semantic_overlay
                .is_empty(),
            "a workspace matching its committed base carries no overlay"
        );
        let fresh = materialize_synthetic(&store);

        for round in 0..2 {
            let manager = reopen_synthetic(&store);
            let materialized = materialize_through(&manager, &store.workspace_id);
            assert_workspace_snapshots_identical(&materialized, &fresh);
            assert_eq!(
                manager.prepared_workspace_graph_stats(),
                PreparedWorkspaceGraphStats::default(),
                "round {round}: a workspace whose materialization takes the clean fast path must \
                 neither look for an artifact nor pay to write one"
            );
        }
        assert!(
            store
                .backend
                .load_prepared_workspace_graph(
                    repository_id().as_str(),
                    &store.workspace_id.to_string(),
                )
                .unwrap()
                .is_none(),
            "no artifact may reach durable storage for a workspace that will never be served one"
        );
    }

    #[test]
    fn prepared_workspace_state_survives_a_local_backend_reopen() {
        let directory = TempDir::new().unwrap();
        let backend = Arc::new(LocalFileBackend::new(directory.path()));
        let manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let transaction = unborn_workspace_transaction(&manager, 0x2334, 0x2335, b"main");
        manager.commit_repository_transaction(transaction).unwrap();
        // Prepared state is admitted only for a workspace carrying an overlay,
        // so stage one through the real transaction surface.
        let mut staged = semantic_test_entity("src/local.rs", "local", LanguageId::Rust, 0x77);
        staged.file_origin = None;
        manager
            .commit_repository_transaction(semantic_workspace_transaction(
                &manager,
                0x2337,
                WorkspaceSemanticDelta::new(
                    vec![EntityDelta::Added {
                        new: staged.clone(),
                    }],
                    Vec::new(),
                )
                .unwrap(),
            ))
            .unwrap();
        let workspace_id = manager.read_authority().metadata().workspaces[0].workspace_id;

        let first =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let materialized = first
            .workspace_graph_snapshot(&repository_id(), &workspace_id)
            .unwrap()
            .expect("the committed workspace exists");
        assert_eq!(first.prepared_workspace_graph_stats().writes, 1);
        assert!(
            backend
                .load_prepared_workspace_graph(repository_id().as_str(), &workspace_id.to_string())
                .unwrap()
                .is_some(),
            "the local backend must hold a durable artifact after a materialization miss"
        );

        let second =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let served = second
            .workspace_graph_snapshot(&repository_id(), &workspace_id)
            .unwrap()
            .expect("the committed workspace exists");
        assert_eq!(
            second.prepared_workspace_graph_stats(),
            PreparedWorkspaceGraphStats {
                serves: 1,
                writes: 0,
                refusals: 0,
                last_refusal: None,
            },
            "a local reopen of unchanged state answers from durable bytes"
        );
        assert_workspace_snapshots_identical(&served, &materialized);
    }

    /// Local, non-citable cold-open materialization wall-clock probe for
    /// FIR-2322. Run explicitly in release mode:
    ///
    /// ```text
    /// cargo test -p kin-db --release \
    ///     workspace_materialization_cold_open_bench -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "wall-clock bench; run explicitly in release mode"]
    fn workspace_materialization_cold_open_bench() {
        let build_started = std::time::Instant::now();
        let store = build_synthetic_history_store(40, 500, 20, 100);
        eprintln!(
            "store: {} entities, {} relations, {} changes, built in {:.1}s",
            store.entity_count,
            store.relation_count,
            store.change_count,
            build_started.elapsed().as_secs_f64()
        );

        let time_rounds = |label: &str| {
            let mut samples = Vec::new();
            let mut latest = None;
            for _ in 0..5 {
                let started = std::time::Instant::now();
                latest = Some(materialize_synthetic(&store));
                samples.push(started.elapsed().as_secs_f64() * 1000.0);
            }
            samples.sort_by(f64::total_cmp);
            eprintln!(
                "{label}: median {:.1} ms, min {:.1} ms, max {:.1} ms",
                samples[samples.len() / 2],
                samples[0],
                samples[samples.len() - 1]
            );
            latest.expect("at least one round ran")
        };

        let clean = time_rounds("clean-workspace materialize");
        assert_synthetic_materialization(&store, &clean, None);

        let staged = stage_synthetic_overlay(&store);
        let dirty = time_rounds("dirty-workspace materialize");
        assert_synthetic_materialization(&store, &dirty, Some(&staged));
    }

    /// Local, non-citable probe of what a prepared serve costs against what
    /// materializing the same workspace costs, on the same store, in the same
    /// process. Run explicitly in release mode:
    ///
    /// ```text
    /// cargo test -p kin-db --release \
    ///     prepared_workspace_state_cold_open_bench -- --ignored --nocapture
    /// ```
    ///
    /// The backend is in memory, so these numbers isolate encode, decode, and
    /// validation and exclude filesystem IO. A serve that loses here loses on
    /// decode cost alone and would only lose harder on a real disk.
    #[test]
    #[ignore = "wall-clock bench; run explicitly in release mode"]
    fn prepared_workspace_state_cold_open_bench() {
        fn report(label: &str, mut samples: Vec<f64>) {
            samples.sort_by(f64::total_cmp);
            eprintln!(
                "{label}: median {:.1} ms, min {:.1} ms, max {:.1} ms",
                samples[samples.len() / 2],
                samples[0],
                samples[samples.len() - 1]
            );
        }

        let build_started = std::time::Instant::now();
        let store = build_synthetic_history_store(40, 500, 20, 100);
        eprintln!(
            "store: {} entities, {} relations, {} changes, built in {:.1}s",
            store.entity_count,
            store.relation_count,
            store.change_count,
            build_started.elapsed().as_secs_f64()
        );

        // `serve` measures a reopen that finds a valid artifact. `materialize`
        // clears the artifact before every round, because otherwise the first
        // round rewrites it and every round after it measures a serve.
        let time_rounds = |label: &str, serve: bool| {
            let mut samples = Vec::new();
            let mut latest = None;
            for _ in 0..5 {
                if !serve {
                    store.backend.prepared.lock().clear();
                }
                // One fresh open per round, because that is the shape the
                // artifact exists for: a cold process asking once.
                let manager = reopen_synthetic(&store);
                let started = std::time::Instant::now();
                latest = Some(materialize_through(&manager, &store.workspace_id));
                samples.push(started.elapsed().as_secs_f64() * 1000.0);
                let stats = manager.prepared_workspace_graph_stats();
                assert_eq!(
                    (stats.serves, stats.writes),
                    if serve { (1, 0) } else { (0, 1) },
                    "{label} did not take the path it is measuring, got {stats:?}"
                );
            }
            report(label, samples);
            latest.expect("at least one round ran")
        };

        // The baseline every arm is judged against: the same materialization
        // through a backend that keeps no prepared state, so it pays neither a
        // lookup nor a write.
        let blind = Arc::new(PreparedBlindBackend(Arc::clone(&store.backend)));
        let time_blind_rounds = |label: &str| {
            let mut samples = Vec::new();
            for _ in 0..5 {
                let manager =
                    RepositoryAuthorityManager::open(repository_id(), Arc::clone(&blind)).unwrap();
                let started = std::time::Instant::now();
                let materialized = manager
                    .workspace_graph_snapshot(&repository_id(), &store.workspace_id)
                    .unwrap()
                    .expect("the synthetic workspace exists");
                samples.push(started.elapsed().as_secs_f64() * 1000.0);
                assert_eq!(
                    manager.prepared_workspace_graph_stats(),
                    PreparedWorkspaceGraphStats::default(),
                    "{label} must touch no prepared state at all"
                );
                std::hint::black_box(materialized);
            }
            report(label, samples);
        };

        // Clean workspace. `prepared_workspace_state_pays_for_itself` refuses
        // to admit an artifact here, so the two arms below must come out the
        // same: enabling prepared state costs a clean workspace nothing.
        time_blind_rounds("clean materialize, backend without prepared state");
        let mut clean = None;
        {
            let mut samples = Vec::new();
            for _ in 0..5 {
                let manager = reopen_synthetic(&store);
                let started = std::time::Instant::now();
                let materialized = materialize_through(&manager, &store.workspace_id);
                samples.push(started.elapsed().as_secs_f64() * 1000.0);
                assert_eq!(
                    manager.prepared_workspace_graph_stats(),
                    PreparedWorkspaceGraphStats::default(),
                    "a clean workspace must be passed over by the cost rule"
                );
                clean = Some(materialized);
            }
            report("clean materialize, prepared state available", samples);
        }
        let clean = clean.expect("at least one round ran");
        assert_synthetic_materialization(&store, &clean, None);

        // The number the cost rule rests on, and the reason it exists. This is
        // NOT a shipped path: the gate is bypassed here so a later reader can
        // re-measure whether serving a clean workspace is still a loss.
        {
            let manager = reopen_synthetic(&store);
            let lease = manager.read_authority();
            let generation = lease.generation();
            let workspace = lease.metadata().workspaces[0].clone();
            drop(lease);
            let cache = manager
                .prepared
                .as_ref()
                .expect("a reopen with persisted authority binds prepared state");
            cache.record(generation, &workspace, &clean);
            let mut samples = Vec::new();
            for _ in 0..5 {
                let started = std::time::Instant::now();
                let served = cache
                    .serve(generation, &workspace)
                    .expect("the artifact just recorded must serve");
                samples.push(started.elapsed().as_secs_f64() * 1000.0);
                std::hint::black_box(served);
            }
            report(
                "clean prepared serve (gate bypassed, NOT a shipped path)",
                samples,
            );
            store.backend.prepared.lock().clear();
        }

        // Dirty workspace, where materialization cannot take its fast path.
        let staged = stage_synthetic_overlay(&store);
        time_blind_rounds("dirty materialize, backend without prepared state");
        let dirty_materialized = time_rounds("dirty materialize and record", false);
        assert_synthetic_materialization(&store, &dirty_materialized, Some(&staged));
        let dirty_served = time_rounds("dirty prepared serve", true);
        assert_synthetic_materialization(&store, &dirty_served, Some(&staged));
        assert_workspace_snapshots_identical(&dirty_served, &dirty_materialized);
    }

    /// The overlay relation staged by round `round` of the successor bench.
    fn indexed_overlay_relation(store: &SyntheticHistoryStore, round: usize) -> Relation {
        let kind = format!("overlay-calls-{round}");
        Relation {
            id: RelationId::from_content(
                &store.chain_target.to_string(),
                &store.chain_source.to_string(),
                &kind,
            ),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(store.chain_target),
            dst: GraphNodeId::Entity(store.chain_source),
            confidence: 1.0,
            origin: RelationOrigin::Manual,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    /// Run `work`, reporting how many base graphs its workspace mutation
    /// resolved. Bases resolved outside the mutation, by the successor's
    /// storage-admission gate or by a backend that revalidates what it saves,
    /// are deliberately not counted: they are their own contract.
    fn mutation_base_resolutions_during<T>(work: impl FnOnce() -> T) -> (T, usize) {
        WORKSPACE_MUTATION_BASE_RESOLUTIONS.with(|count| count.set(0));
        let value = work();
        (
            value,
            WORKSPACE_MUTATION_BASE_RESOLUTIONS.with(|count| count.get()),
        )
    }

    /// Bases resolved by one workspace mutation, and the changes they carried.
    fn mutation_base_resolutions_and_changes_during<T>(
        work: impl FnOnce() -> T,
    ) -> (T, usize, usize) {
        WORKSPACE_MUTATION_BASE_RESOLUTIONS.with(|count| count.set(0));
        WORKSPACE_MUTATION_BASE_CHANGES.with(|count| count.set(0));
        let value = work();
        (
            value,
            WORKSPACE_MUTATION_BASE_RESOLUTIONS.with(|count| count.get()),
            WORKSPACE_MUTATION_BASE_CHANGES.with(|count| count.get()),
        )
    }

    /// One workspace overlay staged on top of the synthetic head, leaving the
    /// base where it is.
    fn overlay_transaction_at_unchanged_base(
        store: &SyntheticHistoryStore,
        operation: u128,
        round: usize,
    ) -> RepositoryTransaction {
        semantic_workspace_transaction(
            &store.manager,
            operation,
            WorkspaceSemanticDelta::new_with_external_references(
                Vec::new(),
                vec![RelationDelta::Added {
                    new: indexed_overlay_relation(store, round),
                }],
                Vec::new(),
            )
            .unwrap(),
        )
    }

    /// A workspace mutation is three materialization steps over a base graph
    /// that costs a whole history replay to resolve, and the mutation's own
    /// contract fixes which base each step wants. Resolving a base per step
    /// replayed the same history two extra times on every forced tree
    /// admission, which is the shape both publications of one `kin commit`
    /// take. This pins the resolution count so it cannot drift back.
    #[test]
    fn one_workspace_mutation_resolves_each_distinct_base_exactly_once() {
        let store = build_synthetic_history_store(2, 8, 1, 3);

        let unchanged_base = overlay_transaction_at_unchanged_base(&store, 0xf2_2347_0001, 0);
        let (receipt, resolutions) = mutation_base_resolutions_during(|| {
            store
                .manager
                .commit_repository_transaction(unchanged_base)
                .unwrap()
        });
        receipt.validate().unwrap();
        assert_eq!(
            resolutions, 1,
            "a mutation that leaves its base where it was names one base graph, \
             so it must resolve one, not one per materialization"
        );

        let advanced = advance_synthetic_base(&store);
        let (advanced_receipt, advanced_resolutions) = mutation_base_resolutions_during(|| {
            store.manager.commit_repository_transaction(advanced)
        });
        advanced_receipt.unwrap().validate().unwrap();
        assert_eq!(
            advanced_resolutions, 2,
            "a mutation that advances its base names two distinct base graphs and must \
             resolve both, never fewer"
        );
    }

    /// A workspace mutation compares four domains and reads no change through
    /// the bases it compares over, so the bases it resolves carry no change
    /// map. On a full-history conversion that map IS the repository, and each
    /// base carrying one was a whole extra copy of it live at the point where
    /// the preparation reaches its peak.
    ///
    /// This counts the changes the resolutions actually built rather than the
    /// mode they were asked for, so it goes red three separate ways: a call
    /// site asking for the history back, either one of them independently, and
    /// a resolver that starts carrying the map whatever it was asked. The
    /// peak-ratio guard in `tests/workspace_prepare_memory.rs` cannot do that
    /// job: on its fixture one of the two copies fits entirely under a mark
    /// another term has already set, so restoring that copy alone moves the
    /// ratio by nothing at all.
    ///
    /// The resolution counts are asserted beside the change counts because zero
    /// changes across zero resolutions is what a mutation that stopped resolving
    /// anything would also report, and that is a different bug wearing this
    /// one's passing costume. Those two lines are defensive rather than proven,
    /// and that is worth saying rather than leaving someone to assume otherwise.
    /// Every mutation tried against them, forcing one base to serve for two and
    /// returning from `apply_workspace` before it resolves anything, is refused
    /// by the product at the fixture's own bootstrap commit, so the test fails
    /// on that `unwrap` and never reaches its own assertions. The change counts
    /// below are the part of this test that has been shown to fail on demand.
    #[test]
    fn a_workspace_mutation_resolves_no_base_carrying_the_history() {
        let store = build_synthetic_history_store(2, 8, 1, 3);
        let history_changes = {
            let lease = store.manager.read_authority();
            let count = lease.snapshot().changes.len();
            drop(lease);
            count
        };
        assert!(
            history_changes > 1,
            "the fixture must carry a history worth not copying, got {history_changes} changes"
        );

        let unchanged_base = overlay_transaction_at_unchanged_base(&store, 0xf2_6510_0001, 0);
        let (receipt, resolutions, base_changes) =
            mutation_base_resolutions_and_changes_during(|| {
                store
                    .manager
                    .commit_repository_transaction(unchanged_base)
                    .unwrap()
            });
        receipt.validate().unwrap();
        assert_eq!(
            resolutions, 1,
            "a mutation that leaves its base where it was resolves one base"
        );
        assert_eq!(
            base_changes, 0,
            "the base this mutation resolved carried {base_changes} changes out of the              repository's {history_changes}, which a workspace comparison never reads"
        );

        let advanced = advance_synthetic_base(&store);
        let (advanced_receipt, advanced_resolutions, advanced_base_changes) =
            mutation_base_resolutions_and_changes_during(|| {
                store.manager.commit_repository_transaction(advanced)
            });
        advanced_receipt.unwrap().validate().unwrap();
        assert_eq!(
            advanced_resolutions, 2,
            "a mutation that advances its base resolves two"
        );
        assert_eq!(
            advanced_base_changes, 0,
            "the two bases this mutation resolved carried {advanced_base_changes} changes              between them out of the repository's {history_changes}"
        );
    }

    /// A store written before the receipts were trimmed still opens.
    ///
    /// This is the migration this change must not require, and an equality
    /// check on the envelope schema silently created one: every store on disk
    /// declares schema 3, and a binary that accepted only 4 refused all of
    /// them with `unsupported repository authority schema 3; expected 4`. The
    /// PR body said no migration was needed while the code required one, and
    /// nothing in the suite disagreed, because every fixture writes the schema
    /// the binary writes.
    ///
    /// So the fixture is aged deliberately: a real committed store, put back to
    /// the shape it had before, with its receipt carrying the operation record
    /// again and its envelope declaring schema 3. Reading has to be a range and
    /// writing a point.
    #[test]
    fn a_store_from_before_the_receipts_were_trimmed_still_opens() {
        let store = build_synthetic_history_store(2, 4, 1, 2);
        let lease = store.manager.read_authority();
        let mut snapshot = lease.snapshot().clone();
        drop(lease);

        let metadata = snapshot
            .repository_authority
            .as_mut()
            .expect("the committed store carries an envelope");
        assert_eq!(
            metadata.schema_version, REPOSITORY_AUTHORITY_SCHEMA_VERSION,
            "the fixture must start at the schema this binary writes"
        );
        assert!(
            metadata
                .receipts
                .iter()
                .all(|receipt| receipt.operation.is_none()),
            "the fixture must start trimmed, or ageing it below proves nothing"
        );

        // Age it: every receipt carries its operation record again, and the
        // envelope declares the schema that shape was written under.
        let log: std::collections::BTreeMap<_, _> = metadata
            .operation_log
            .iter()
            .map(|operation| (operation.operation_id, operation.clone()))
            .collect();
        for receipt in &mut metadata.receipts {
            receipt.operation = Some(
                log.get(&receipt.operation_id)
                    .expect("every receipt names a logged operation")
                    .clone(),
            );
        }
        metadata.schema_version = MIN_REPOSITORY_AUTHORITY_SCHEMA_VERSION;
        snapshot.version = snapshot.wire_version();

        // The aged store round-trips through the persisted format and validates
        // on the way back, which is what an open does.
        let bytes = snapshot.to_bytes().expect("the aged snapshot serializes");
        let reopened = GraphSnapshot::from_bytes(&bytes).expect("the aged snapshot decodes");
        let aged = reopened
            .repository_authority
            .as_ref()
            .expect("the aged envelope survives the round trip");
        assert_eq!(aged.schema_version, MIN_REPOSITORY_AUTHORITY_SCHEMA_VERSION);
        assert!(
            aged.receipts
                .iter()
                .all(|receipt| receipt.operation.is_some()),
            "the aged receipts must still carry their operation records"
        );
        for operation in &aged.operation_log {
            let receipt = aged
                .receipts
                .iter()
                .find(|receipt| receipt.operation_id == operation.operation_id)
                .expect("every aged operation has a receipt");
            receipt
                .validate_against(operation)
                .expect("an aged receipt is still checked against its embedded copy");
        }

        // The negative controls, so the range is a range and not an acceptance
        // of anything.
        let mut too_old = reopened.clone();
        too_old
            .repository_authority
            .as_mut()
            .expect("envelope")
            .schema_version = MIN_REPOSITORY_AUTHORITY_SCHEMA_VERSION - 1;
        assert!(
            too_old.validate_storage_admission().is_err(),
            "a schema below the readable range must be refused"
        );
        let mut too_new = reopened.clone();
        too_new
            .repository_authority
            .as_mut()
            .expect("envelope")
            .schema_version = REPOSITORY_AUTHORITY_SCHEMA_VERSION + 1;
        assert!(
            too_new.validate_storage_admission().is_err(),
            "a schema above the readable range must be refused"
        );
    }

    /// A persisted receipt names its operation record rather than repeating it.
    ///
    /// The two were the same record and the store held both. Measured on a full
    /// VS Code tree, `operation_log[0]` is 800,755,477 bytes and `receipts[0]`
    /// is 800,756,236, together 41.8 percent of a 3,859,076,152-byte store, and
    /// the envelope decodes to 4,854,246,200 bytes in memory, of which half is
    /// the copy (FIR-3064).
    ///
    /// Asserted on the store's shape rather than on a resident-set number,
    /// because the shape is what changed: the envelope in memory is decoded
    /// from these bytes, so a receipts index that no longer carries the
    /// mutation cannot decode into a second copy of it.
    #[test]
    fn a_persisted_receipt_names_its_operation_rather_than_repeating_it() {
        let store = build_synthetic_history_store(2, 4, 1, 2);
        let old = materialize_synthetic(&store)
            .entities
            .get(&store.modified_entity)
            .expect("modified entity resolves in the workspace graph")
            .clone();
        let mut new = old.clone();
        // Mass, so the operation record is worth not repeating. Without it both
        // sides of the comparison below are small and their ratio says nothing,
        // which the log-size assertion is the control for.
        new.doc_summary = Some("fir3064 ".repeat(RECEIPT_GUARD_PAYLOAD_BYTES / 8));
        let delta =
            WorkspaceSemanticDelta::new(vec![EntityDelta::Modified { old, new }], Vec::new())
                .expect("the fat semantic delta is well formed");
        let transaction = semantic_workspace_transaction(&store.manager, 0xfa_3064_0001, delta);
        store
            .manager
            .commit_repository_transaction(transaction)
            .expect("the workspace transaction commits");

        let lease = store.manager.read_authority();
        let metadata = lease.metadata();
        assert!(
            !metadata.receipts.is_empty(),
            "the commit must have written a receipt, or this asserts nothing"
        );
        assert!(
            metadata
                .receipts
                .iter()
                .all(|receipt| receipt.operation.is_none()),
            "a receipt this binary wrote must name its operation, not carry it"
        );

        let log_bytes = encoded_len(&metadata.operation_log);
        let receipt_bytes = encoded_len(&metadata.receipts);
        // The positive control on the comparison. A log with no mass would make
        // the ratio below hold for a store that still repeated everything.
        assert!(
            log_bytes > RECEIPT_GUARD_PAYLOAD_BYTES,
            "the operation log must carry the fixture's mass, got {log_bytes} bytes"
        );
        assert!(
            receipt_bytes * RECEIPT_INDEX_SHARE_DIVISOR < log_bytes,
            "the receipts index is {receipt_bytes} bytes against a {log_bytes}-byte operation \
             log, so it is still repeating what the log already holds"
        );

        // The body says so at its header, which is what makes an older binary
        // refuse it rather than fail inside the envelope.
        assert!(
            lease.snapshot().wire_version() >= GraphSnapshot::TRIMMED_RECEIPT_VERSION,
            "a body with trimmed receipts must declare a version that says so, got v{}",
            lease.snapshot().wire_version()
        );
    }

    /// A transaction advancing `main` and the workspace base onto one new
    /// change, leaving the workspace tree and overlay where they are.
    fn advance_synthetic_base(store: &SyntheticHistoryStore) -> RepositoryTransaction {
        let lease = store.manager.read_authority();
        let current = lease.metadata().workspaces[0].clone();
        let base_target = current
            .base_target
            .clone()
            .expect("synthetic workspace bases at head");
        let base_change_id = target_change_id(lease.metadata(), &base_target).unwrap();
        drop(lease);
        // Repository authority persists immutable history, not a materialized
        // entity map, so the entity to modify comes from the workspace graph
        // the history resolves to.
        let old = materialize_synthetic(store)
            .entities
            .get(&store.modified_entity)
            .expect("modified entity resolves in the workspace graph")
            .clone();

        let mut new = old.clone();
        new.signature = format!("{} /* advanced base */", old.signature);
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: vec![base_change_id],
            timestamp: Timestamp(
                chrono::DateTime::parse_from_rfc3339("2026-07-28T17:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            author: AuthorId::new("synthetic-history"),
            message: "advance the synthetic base".to_string(),
            entity_deltas: vec![EntityDelta::Modified {
                old: old.clone(),
                new: new.clone(),
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
        change.id = compute_semantic_change_id(&change).unwrap();
        let next_target = RefTarget::change(change.id);

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
                vec![EntityDelta::Modified { old, new }],
                Vec::new(),
            )
            .unwrap(),
            new_shared_admission_policy: current.shared_admission_policy,
            new_admission_policy: current.admission_policy,
        };

        let mut transaction = transaction_shell(&store.manager, 0xf2_2347_0002);
        transaction.changes.push(change);
        transaction.ref_mutations.push(RefMutation {
            name: RefName::branch(b"main").unwrap(),
            expected: RefExpectation::MustEqual {
                target: base_target,
            },
            new_target: Some(next_target),
            policy: RefUpdatePolicy::FastForwardOnly,
        });
        transaction.workspace_mutation = Some(mutation);
        transaction
    }

    /// Local, non-citable successor-preparation wall-clock probe for FIR-2347.
    /// Each round publishes one workspace-scoped transaction through the real
    /// repository transaction surface, which is the shape both publications of
    /// a `kin commit` take. Run explicitly in release mode:
    ///
    /// ```text
    /// cargo test -p kin-db --release \
    ///     repository_successor_preparation_bench -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "wall-clock bench; run explicitly in release mode"]
    fn repository_successor_preparation_bench() {
        let build_started = std::time::Instant::now();
        let store = build_synthetic_history_store(40, 500, 20, 100);
        eprintln!(
            "store: {} entities, {} relations, {} changes, built in {:.1}s",
            store.entity_count,
            store.relation_count,
            store.change_count,
            build_started.elapsed().as_secs_f64()
        );

        let mut samples = Vec::new();
        for round in 0..5 {
            let relation = indexed_overlay_relation(&store, round);
            let transaction = semantic_workspace_transaction(
                &store.manager,
                0xf2_2347_0000 + round as u128,
                WorkspaceSemanticDelta::new_with_external_references(
                    Vec::new(),
                    vec![RelationDelta::Added { new: relation }],
                    Vec::new(),
                )
                .unwrap(),
            );
            let started = std::time::Instant::now();
            store
                .manager
                .commit_repository_transaction(transaction)
                .unwrap();
            samples.push(started.elapsed().as_secs_f64() * 1000.0);
        }
        samples.sort_by(f64::total_cmp);
        eprintln!(
            "workspace-scoped transaction: median {:.1} ms, min {:.1} ms, max {:.1} ms",
            samples[samples.len() / 2],
            samples[0],
            samples[samples.len() - 1]
        );
    }

    fn directory_bytes(path: &std::path::Path) -> u64 {
        let mut total = 0;
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let metadata = match entry.metadata() {
                    Ok(metadata) => metadata,
                    Err(_) => continue,
                };
                if metadata.is_dir() {
                    total += directory_bytes(&entry.path());
                } else {
                    total += metadata.len();
                }
            }
        }
        total
    }

    fn encoded_len<T: Serialize>(value: &T) -> usize {
        rmp_serde::to_vec(value)
            .map(|bytes| bytes.len())
            .unwrap_or(0)
    }

    /// Local, non-citable persistence probe for FIR-2347: what one
    /// workspace-scoped publication writes through the real local backend, and
    /// how long the durable write takes, on the same synthetic 20k-entity store
    /// the preparation bench uses. Run explicitly in release mode:
    ///
    /// ```text
    /// cargo test -p kin-db --release \
    ///     repository_authority_publication_write_bench -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "wall-clock bench; run explicitly in release mode"]
    fn repository_authority_publication_write_bench() {
        let build_started = std::time::Instant::now();
        let store = build_synthetic_history_store(40, 500, 20, 100);
        let (seed_bytes, _) = store
            .backend
            .snapshot
            .lock()
            .clone()
            .expect("the synthetic store persisted its head");
        eprintln!(
            "store: {} entities, {} relations, {} changes, {} snapshot bytes, built in {:.1}s",
            store.entity_count,
            store.relation_count,
            store.change_count,
            seed_bytes.len(),
            build_started.elapsed().as_secs_f64()
        );
        {
            let head = GraphSnapshot::from_bytes(&seed_bytes).unwrap();
            let envelope = head.repository_authority.as_ref().unwrap();
            eprintln!(
                "composition: changes {} bytes, envelope {} bytes (workspaces {} bytes, operation_log {} bytes, receipts {} bytes, admission_policies {} bytes)",
                encoded_len(&head.changes),
                encoded_len(envelope),
                encoded_len(&envelope.workspaces),
                encoded_len(&envelope.operation_log),
                encoded_len(&envelope.receipts),
                encoded_len(&envelope.admission_policies),
            );
        }

        let dir = TempDir::new().unwrap();
        let backend = Arc::new(LocalFileBackend::new(dir.path()));
        backend
            .save_snapshot(
                repository_id().as_str(),
                &seed_bytes,
                crate::storage::GENERATION_INIT,
            )
            .unwrap();
        let manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let namespace = dir.path().join(repository_id().as_str());

        let rounds = 8usize;
        let mut wall = Vec::with_capacity(rounds);
        let mut encode = Vec::with_capacity(rounds);
        let mut self_check = Vec::with_capacity(rounds);
        let mut write = Vec::with_capacity(rounds);
        let mut serialize = Vec::with_capacity(rounds);
        let mut payload = Vec::with_capacity(rounds);
        let mut disk = Vec::with_capacity(rounds);
        for round in 0..rounds {
            let relation = indexed_overlay_relation(&store, round);
            let transaction = semantic_workspace_transaction(
                &manager,
                0xf2_2347_1000 + round as u128,
                WorkspaceSemanticDelta::new_with_external_references(
                    Vec::new(),
                    vec![RelationDelta::Added { new: relation }],
                    Vec::new(),
                )
                .unwrap(),
            );
            let before = directory_bytes(&namespace);
            let started = std::time::Instant::now();
            manager.commit_repository_transaction(transaction).unwrap();
            let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
            let phases = last_persistence_phases().expect("the publication recorded its phases");
            let after = directory_bytes(&namespace);
            eprintln!(
                "round {round}: commit {elapsed_ms:.1} ms, encode {} ms, self-check {} ms, serialize {} ms, write {} ms, payload {} bytes, namespace grew {} bytes",
                phases.encode_ms,
                phases.self_check_ms,
                phases.serialize_ms,
                phases.write_ms,
                phases.payload_bytes,
                after.saturating_sub(before)
            );
            wall.push(elapsed_ms);
            encode.push(phases.encode_ms as f64);
            self_check.push(phases.self_check_ms as f64);
            write.push(phases.write_ms as f64);
            serialize.push(phases.serialize_ms as f64);
            payload.push(phases.payload_bytes as f64);
            disk.push(after.saturating_sub(before) as f64);
        }
        let median = |samples: &mut Vec<f64>| {
            samples.sort_by(f64::total_cmp);
            samples[samples.len() / 2]
        };
        eprintln!(
            "medians over {rounds} publications: commit {:.1} ms, encode {:.1} ms, self-check {:.1} ms, serialize {:.1} ms, write {:.1} ms, payload {:.0} bytes, namespace growth {:.0} bytes",
            median(&mut wall),
            median(&mut encode),
            median(&mut self_check),
            median(&mut serialize),
            median(&mut write),
            median(&mut payload),
            median(&mut disk),
        );

        let reopen_started = std::time::Instant::now();
        let reopened =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        eprintln!(
            "reopen after {rounds} publications: {:.1} ms, generation {}, by history validation {}",
            reopen_started.elapsed().as_secs_f64() * 1000.0,
            reopened.read_authority().generation(),
            reopened.opened_by_history_validation()
        );
    }

    // ---------------------------------------------------------------------
    // Authority frames: the O(change) publication shape.
    // ---------------------------------------------------------------------

    /// One local store past its first full snapshot, with the journal byte
    /// bound lifted so the small fixture exercises frames the way a large
    /// store does under the production rule.
    fn framed_local_repository(
        directory: &TempDir,
    ) -> (
        Arc<LocalFileBackend>,
        RepositoryAuthorityManager<LocalFileBackend>,
    ) {
        let backend = Arc::new(LocalFileBackend::new(directory.path()));
        let manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();
        manager
            .persistence()
            .set_journal_byte_bound_for_test(Some(u64::MAX));
        (backend, manager)
    }

    fn deltas_dir(directory: &TempDir) -> std::path::PathBuf {
        directory
            .path()
            .join(repository_id().as_str())
            .join("deltas")
    }

    fn frame_path(directory: &TempDir, generation: Generation) -> std::path::PathBuf {
        deltas_dir(directory).join(format!("{generation:020}.kndd"))
    }

    fn acknowledged_frame_count(directory: &TempDir) -> usize {
        read_authority_json(directory.path())["acknowledged_deltas"]
            .as_array()
            .map_or(0, Vec::len)
    }

    fn record_version(directory: &TempDir) -> u64 {
        read_authority_json(directory.path())["version"]
            .as_u64()
            .expect("the record carries a version")
    }

    /// One workspace-scoped publication that adds a fresh entity to the
    /// overlay; the shape every forced tree admission and ambient tick takes.
    fn overlay_publication<B: StorageBackend + ?Sized + 'static>(
        manager: &RepositoryAuthorityManager<B>,
        operation: u128,
        fingerprint_seed: u8,
    ) -> RepositoryTransaction {
        semantic_workspace_transaction(
            manager,
            operation,
            WorkspaceSemanticDelta::new_with_external_references(
                vec![EntityDelta::Added {
                    new: semantic_test_entity(
                        "src/lib.rs",
                        &format!("kin_{fingerprint_seed}"),
                        LanguageId::Rust,
                        fingerprint_seed,
                    ),
                }],
                Vec::new(),
                Vec::new(),
            )
            .unwrap(),
        )
    }

    fn assert_same_authority(
        left: &RepositoryAuthorityState,
        right: &RepositoryAuthorityState,
        context: &str,
    ) {
        assert_eq!(left.metadata(), right.metadata(), "{context}: envelope");
        assert_eq!(
            left.snapshot().changes,
            right.snapshot().changes,
            "{context}: changes"
        );
        assert_eq!(
            left.snapshot().change_children,
            right.snapshot().change_children,
            "{context}: change children"
        );
        assert!(
            right.snapshot().entity_revisions.is_empty(),
            "{context}: authority never persists entity revisions"
        );
    }

    /// Publish one of every mutation shape the envelope knows, and check
    /// after each that the frame journal grew and that a fresh open puts the
    /// exact published state back together.
    #[test]
    fn authority_frames_carry_every_mutation_shape_and_reopen_exactly() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        assert_eq!(
            record_version(&directory),
            3,
            "the first publication is a full snapshot"
        );
        assert_eq!(acknowledged_frame_count(&directory), 0);

        // Each transaction is built against the lease it extends, so they are
        // constructed one publication at a time.
        let publications: Vec<(
            &str,
            Box<dyn Fn(&RepositoryAuthorityManager<LocalFileBackend>) -> RepositoryTransaction>,
        )> = vec![
            (
                "workspace overlay",
                Box::new(|manager| {
                    semantic_workspace_transaction(
                        manager,
                        0xf2_2347_2001,
                        WorkspaceSemanticDelta::new_with_external_references(
                            vec![EntityDelta::Added {
                                new: semantic_test_entity(
                                    "src/lib.rs",
                                    "kin",
                                    LanguageId::Rust,
                                    0x21,
                                ),
                            }],
                            Vec::new(),
                            Vec::new(),
                        )
                        .unwrap(),
                    )
                }),
            ),
            (
                "change and ref move",
                Box::new(|manager| remove_compose_transaction(manager, 0xf2_2347_2002).0),
            ),
        ];

        let mut expected_frames = 0;
        for (label, build) in publications {
            manager
                .commit_repository_transaction(build(&manager))
                .unwrap();
            expected_frames += 1;
            assert_eq!(
                record_version(&directory),
                4,
                "{label}: frame journal record"
            );
            assert_eq!(
                acknowledged_frame_count(&directory),
                expected_frames,
                "{label}: acknowledged frames"
            );
            let reopened = reopen(&directory);
            assert_same_authority(&manager.read_authority(), &reopened.read_authority(), label);
            assert!(
                reopened.opened_by_history_validation(),
                "{label}: a frame publication binds a journal-aware proof, so the reopen is fast"
            );
        }

        // Git authority lifecycle: an import initializes it (external objects,
        // aliases, imported changes, and the authority itself), an update
        // replaces it, and a removal clears it. The removal is the one shape
        // whose envelope value is an absence, so a frame has to carry it as an
        // explicit patch rather than as a missing value.
        let fixture = git_authority_transaction_fixture(&manager, 0xf2_2347_2005);
        manager
            .commit_repository_transaction(fixture.transaction.clone())
            .unwrap();
        expected_frames += 1;
        assert_eq!(acknowledged_frame_count(&directory), expected_frames);
        assert_same_authority(
            &manager.read_authority(),
            &reopen(&directory).read_authority(),
            "git import",
        );

        let mut update = transaction_shell(&manager, 0xf2_2347_2006);
        update.git_authority_delta = Some(GitExternalAuthorityDelta::update(
            fixture.authority.clone(),
            fixture.direct_authority.clone(),
        ));
        manager.commit_repository_transaction(update).unwrap();
        expected_frames += 1;
        assert_eq!(acknowledged_frame_count(&directory), expected_frames);
        assert_same_authority(
            &manager.read_authority(),
            &reopen(&directory).read_authority(),
            "git authority update",
        );

        let mut removal = transaction_shell(&manager, 0xf2_2347_2007);
        removal.git_authority_delta = Some(GitExternalAuthorityDelta::remove(
            fixture.direct_authority.clone(),
        ));
        manager.commit_repository_transaction(removal).unwrap();
        expected_frames += 1;
        assert_eq!(acknowledged_frame_count(&directory), expected_frames);
        assert!(
            manager
                .read_authority()
                .metadata()
                .git_external_authority
                .is_none(),
            "the removal published"
        );
        let reopened = reopen(&directory);
        assert!(
            reopened
                .read_authority()
                .metadata()
                .git_external_authority
                .is_none(),
            "a reopened store must not serve a Git authority the repository removed"
        );
        assert_same_authority(
            &manager.read_authority(),
            &reopened.read_authority(),
            "git authority removal",
        );

        // Merge record open and drop: upsert then removal in the envelope.
        let record = open_merge_record(&manager, 0xf2_2347_2003);
        let mut opening = transaction_shell(&manager, 0xf2_2347_2003);
        opening.merge_transaction_delta = Some(MergeTransactionDelta::open(record.clone()));
        manager.commit_repository_transaction(opening).unwrap();
        let mut dropping = transaction_shell(&manager, 0xf2_2347_2004);
        dropping.merge_transaction_delta = Some(MergeTransactionDelta::drop_record(record));
        manager.commit_repository_transaction(dropping).unwrap();
        expected_frames += 2;
        assert_eq!(acknowledged_frame_count(&directory), expected_frames);
        assert!(manager
            .read_authority()
            .metadata()
            .merge_transactions
            .is_empty());
        let (reopened, receipt) = RepositoryAuthorityManager::open_with_payload_stats(
            repository_id(),
            Arc::new(LocalFileBackend::new(directory.path())),
        )
        .unwrap();
        assert_same_authority(
            &manager.read_authority(),
            &reopened.read_authority(),
            "merge",
        );
        let receipt = receipt.expect("a persisted store receipts its payload");
        assert_eq!(receipt.acknowledged_delta_count(), expected_frames as u64);
        assert_eq!(
            receipt.head_generation() - receipt.snapshot_generation(),
            expected_frames as u64
        );
        assert!(receipt.acknowledged_delta_bytes() > 0);
        assert_eq!(
            receipt.total_payload_bytes(),
            receipt.snapshot_bytes() + receipt.acknowledged_delta_bytes()
        );
    }

    /// The detached-tag import is the frame shape that carries a tag ref, a
    /// detached workspace, a second local overlay, and an imported change
    /// with its own admission policy delta in one publication.
    #[test]
    fn authority_frames_carry_a_detached_tag_import_and_reopen_exactly() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        let (import, change_id, tag) = detached_tag_import_transaction(&manager);
        manager.commit_repository_transaction(import).unwrap();
        assert_eq!(record_version(&directory), 4);
        assert_eq!(acknowledged_frame_count(&directory), 1);
        let frame = crate::storage::AuthorityFrame::from_bytes(
            &std::fs::read(frame_path(&directory, 2)).unwrap(),
        )
        .unwrap();
        assert!(frame.changes.iter().any(|change| change.id == change_id));
        assert!(frame
            .external_objects
            .iter()
            .any(|record| record.object == tag));
        assert!(matches!(
            frame.git_external_authority,
            crate::storage::authority_frame::GitExternalAuthorityPatch::Set(_)
        ));
        assert_eq!(frame.local_overlays.len(), 2, "the import added an overlay");
        let reopened = reopen(&directory);
        assert_same_authority(
            &manager.read_authority(),
            &reopened.read_authority(),
            "detached tag import",
        );
        assert!(reopened.opened_by_history_validation());
    }

    /// Every variant of the Git authority patch has its own wire shape and
    /// comes back from the frame bytes as itself. Version 1 carried the patch
    /// as `Option<Option<_>>`, whose removal shape encoded like an absence and
    /// decoded as unchanged.
    #[test]
    fn every_git_authority_patch_variant_survives_the_frame_wire() {
        use crate::storage::authority_frame::GitExternalAuthorityPatch;
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        manager
            .commit_repository_transaction(overlay_publication(&manager, 0xf2_2347_2101, 0x21))
            .unwrap();
        let fixture = git_authority_transaction_fixture(&manager, 0xf2_2347_2102);
        manager
            .commit_repository_transaction(fixture.transaction.clone())
            .unwrap();
        let mut removal = transaction_shell(&manager, 0xf2_2347_2103);
        removal.git_authority_delta =
            Some(GitExternalAuthorityDelta::remove(fixture.authority.clone()));
        manager.commit_repository_transaction(removal).unwrap();
        assert_eq!(acknowledged_frame_count(&directory), 3);

        let persisted = |generation: Generation| {
            let bytes = std::fs::read(frame_path(&directory, generation)).unwrap();
            let frame = crate::storage::AuthorityFrame::from_bytes(&bytes).unwrap();
            assert_eq!(
                frame.to_bytes().unwrap(),
                bytes,
                "generation {generation}: re-encoding the decoded frame yields the persisted bytes"
            );
            frame
        };
        assert_eq!(
            persisted(2).git_external_authority,
            GitExternalAuthorityPatch::Unchanged
        );
        assert_eq!(
            persisted(3).git_external_authority,
            GitExternalAuthorityPatch::Set(fixture.authority.clone())
        );
        assert_eq!(
            persisted(4).git_external_authority,
            GitExternalAuthorityPatch::Cleared
        );

        // Each variant on the same frame round-trips as itself, and no two
        // variants share bytes.
        let template = persisted(2);
        let mut encodings = Vec::new();
        for patch in [
            GitExternalAuthorityPatch::Unchanged,
            GitExternalAuthorityPatch::Set(fixture.authority.clone()),
            GitExternalAuthorityPatch::Cleared,
        ] {
            let mut frame = template.clone();
            frame.git_external_authority = patch.clone();
            let bytes = frame.to_bytes().unwrap();
            let decoded = crate::storage::AuthorityFrame::from_bytes(&bytes).unwrap();
            assert_eq!(decoded, frame, "{patch:?} survives the wire");
            assert_eq!(decoded.git_external_authority, patch);
            encodings.push(bytes);
        }
        assert_ne!(encodings[0], encodings[1]);
        assert_ne!(encodings[0], encodings[2]);
        assert_ne!(encodings[1], encodings[2]);
    }

    #[test]
    fn a_frame_publication_writes_only_the_frame() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        let full = last_persistence_phases().expect("the full snapshot recorded its phases");

        manager
            .commit_repository_transaction(semantic_workspace_transaction(
                &manager,
                0xf2_2347_2101,
                WorkspaceSemanticDelta::new_with_external_references(
                    vec![EntityDelta::Added {
                        new: semantic_test_entity("src/lib.rs", "kin", LanguageId::Rust, 0x21),
                    }],
                    Vec::new(),
                    Vec::new(),
                )
                .unwrap(),
            ))
            .unwrap();
        let frame = last_persistence_phases().expect("the frame recorded its phases");
        assert!(
            frame.payload_bytes < full.payload_bytes,
            "a frame publication must persist fewer bytes than the full snapshot: {} against {}",
            frame.payload_bytes,
            full.payload_bytes
        );
        assert_eq!(
            std::fs::metadata(frame_path(&directory, 2)).unwrap().len(),
            frame.payload_bytes as u64,
            "the recorded payload is the frame file"
        );
        let (base_bytes, frames, journal_bytes) = manager.persistence().journal_state_for_test();
        assert_eq!(base_bytes as usize, full.payload_bytes);
        assert_eq!(frames, 1);
        assert_eq!(journal_bytes as usize, frame.payload_bytes);
    }

    #[test]
    fn a_journal_head_without_a_proof_validates_in_full_and_rebinds_a_journal_proof() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        let (removal, _) = remove_compose_transaction(&manager, 0xf2_2347_2201);
        manager.commit_repository_transaction(removal).unwrap();
        let bound = read_authority_json(directory.path());
        assert!(
            bound["history_validation"]["journal_sha256"].is_string(),
            "a frame append binds a proof naming the journal: {bound}"
        );

        let mut record = bound.clone();
        record.as_object_mut().unwrap().remove("history_validation");
        write_authority_json(directory.path(), &record);

        let reopened = reopen(&directory);
        assert!(
            !reopened.opened_by_history_validation(),
            "with no proof the head validates in full"
        );
        assert_same_authority(
            &manager.read_authority(),
            &reopened.read_authority(),
            "unproven",
        );
        let rebound = read_authority_json(directory.path());
        assert_eq!(
            rebound["history_validation"], bound["history_validation"],
            "the full validation rebinds exactly the proof the writer minted"
        );
        assert!(reopen(&directory).opened_by_history_validation());
    }

    #[test]
    fn a_proof_naming_another_journal_is_not_honored() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        let (removal, _) = remove_compose_transaction(&manager, 0xf2_2347_2251);
        manager.commit_repository_transaction(removal).unwrap();
        let mut record = read_authority_json(directory.path());
        record["history_validation"]["journal_sha256"] =
            serde_json::json!(hex::encode(Sha256::digest(b"another chain")));
        write_authority_json(directory.path(), &record);
        // Recovery itself must not reuse the forged proof, because reuse is
        // what skips the head's admission pass; the manager's own check is a
        // second gate, not the only one.
        let recovered = load_recovered_repository_authority(
            &LocalFileBackend::new(directory.path()),
            repository_id().as_str(),
            HISTORY_VALIDATION_VERSION,
        )
        .unwrap()
        .unwrap();
        assert!(
            !recovered.reused_complete_validation,
            "a proof naming another chain must not skip head validation"
        );
        assert!(recovered.recovered.history_validation.is_none());
        let reopened = reopen(&directory);
        assert!(!reopened.opened_by_history_validation());
        assert_same_authority(
            &manager.read_authority(),
            &reopened.read_authority(),
            "forged",
        );
    }

    fn corrupt_frame(
        directory: &TempDir,
        generation: Generation,
        corrupt: impl FnOnce(&mut Vec<u8>),
    ) {
        let path = frame_path(directory, generation);
        let mut bytes = std::fs::read(&path).unwrap();
        corrupt(&mut bytes);
        std::fs::write(&path, &bytes).unwrap();
    }

    fn reopen_error(directory: &TempDir) -> String {
        match RepositoryAuthorityManager::open(
            repository_id(),
            Arc::new(LocalFileBackend::new(directory.path())),
        ) {
            Ok(_) => panic!("a corrupted journal must refuse to open"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn a_flipped_byte_in_an_acknowledged_frame_refuses_the_open() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        let (removal, _) = remove_compose_transaction(&manager, 0xf2_2347_2301);
        manager.commit_repository_transaction(removal).unwrap();
        drop(manager);
        corrupt_frame(&directory, 2, |bytes| {
            let middle = bytes.len() / 2;
            bytes[middle] ^= 0x01;
        });
        let error = reopen_error(&directory);
        assert!(
            error.contains("digest mismatch"),
            "a changed acknowledged frame must be named as such: {error}"
        );
    }

    #[test]
    fn a_truncated_acknowledged_frame_refuses_the_open() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        let (removal, _) = remove_compose_transaction(&manager, 0xf2_2347_2302);
        manager.commit_repository_transaction(removal).unwrap();
        drop(manager);
        corrupt_frame(&directory, 2, |bytes| {
            let keep = bytes.len() / 2;
            bytes.truncate(keep);
        });
        let error = reopen_error(&directory);
        assert!(
            error.contains("digest mismatch"),
            "a torn acknowledged frame must be named as such: {error}"
        );
        // The frame decoder itself refuses the torn bytes independently of the
        // record binding.
        let torn = std::fs::read(frame_path(&directory, 2)).unwrap();
        let decode = crate::storage::AuthorityFrame::from_bytes(&torn)
            .expect_err("a torn frame must not decode");
        assert!(decode.to_string().contains("truncated"), "{decode}");
    }

    #[test]
    fn a_missing_acknowledged_frame_refuses_the_open() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        let (removal, _) = remove_compose_transaction(&manager, 0xf2_2347_2303);
        manager.commit_repository_transaction(removal).unwrap();
        drop(manager);
        std::fs::remove_file(frame_path(&directory, 2)).unwrap();
        let error = reopen_error(&directory);
        assert!(
            error.contains("delta chain ended") || error.contains("delta chain is incomplete"),
            "a missing acknowledged frame must be named as such: {error}"
        );
    }

    #[test]
    fn a_frame_acknowledged_over_the_wrong_base_refuses_the_open() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        // A workspace-only publication carries no change, so the duplicated
        // frame below is not caught by the change re-add check and the open
        // is decided by the roots binding alone.
        manager
            .commit_repository_transaction(overlay_publication(&manager, 0xf2_2347_2304, 0x74))
            .unwrap();
        let frame = crate::storage::AuthorityFrame::from_bytes(
            &std::fs::read(frame_path(&directory, 2)).unwrap(),
        )
        .unwrap();
        assert!(
            frame.changes.is_empty(),
            "the fixture frame carries no change"
        );
        drop(manager);
        // Acknowledge the same frame a second time at the next generation: its
        // bytes are intact and its digest binds, but it names the roots of the
        // state before it, not after it, so it does not extend the head.
        let bytes = std::fs::read(frame_path(&directory, 2)).unwrap();
        std::fs::write(frame_path(&directory, 3), &bytes).unwrap();
        let mut record = read_authority_json(directory.path());
        record["head_generation"] = serde_json::json!(3);
        record["acknowledged_deltas"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "generation": 3,
                "sha256": hex::encode(Sha256::digest(&bytes)),
            }));
        record.as_object_mut().unwrap().remove("history_validation");
        write_authority_json(directory.path(), &record);
        let error = reopen_error(&directory);
        assert!(
            error.contains("does not extend the base"),
            "a frame over the wrong base must be refused by the roots binding: {error}"
        );
    }

    /// Recursively copy one store directory so a second writer can extend the
    /// same base independently.
    fn copy_store(from: &std::path::Path, to: &std::path::Path) {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let target = to.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_store(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    /// The two digest-binding tests above corrupt frame bytes, which the
    /// frame's own checksum also refuses. This one swaps in a frame that is
    /// well formed, checksums, decodes, and would apply cleanly over the same
    /// base, so the record's acknowledged digest is the only thing that can
    /// refuse it.
    #[test]
    fn a_well_formed_frame_swapped_in_at_an_acknowledged_generation_is_refused_by_the_record_digest_alone(
    ) {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        drop(manager);
        // Two writers extend the same base with different publications.
        let sibling = TempDir::new().unwrap();
        copy_store(directory.path(), sibling.path());
        let manager = reopen(&directory);
        manager
            .persistence()
            .set_journal_byte_bound_for_test(Some(u64::MAX));
        manager
            .commit_repository_transaction(overlay_publication(&manager, 0xf2_2347_2307, 0x75))
            .unwrap();
        let other = reopen(&sibling);
        other
            .persistence()
            .set_journal_byte_bound_for_test(Some(u64::MAX));
        other
            .commit_repository_transaction(overlay_publication(&other, 0xf2_2347_2308, 0x76))
            .unwrap();
        drop(manager);
        let acknowledged = std::fs::read(frame_path(&directory, 2)).unwrap();
        let swapped = std::fs::read(frame_path(&sibling, 2)).unwrap();
        assert_ne!(
            acknowledged, swapped,
            "the two writers built different frames"
        );
        crate::storage::AuthorityFrame::from_bytes(&swapped)
            .expect("the swapped frame is well formed and checksums");

        // Swap the frame file without touching the record.
        std::fs::write(frame_path(&directory, 2), &swapped).unwrap();
        let error = reopen_error(&directory);
        assert!(
            error.contains("acknowledged delta digest mismatch"),
            "a swapped well-formed frame must be refused by the record digest: {error}"
        );

        // The same bytes named by the record are served, which is what proves
        // the digest was the only guard between the swapped frame and the
        // reader: the frame extends this base, and only the record said no.
        let mut record = read_authority_json(directory.path());
        record["acknowledged_deltas"] = serde_json::json!([{
            "generation": 2,
            "sha256": hex::encode(Sha256::digest(&swapped)),
        }]);
        record.as_object_mut().unwrap().remove("history_validation");
        write_authority_json(directory.path(), &record);
        let reopened = reopen(&directory);
        assert_same_authority(
            &other.read_authority(),
            &reopened.read_authority(),
            "the swapped frame's own state",
        );
    }

    #[test]
    fn a_frame_from_another_repository_refuses_to_apply() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        let mut base = manager.read_authority().snapshot().clone();
        let (removal, _) = remove_compose_transaction(&manager, 0xf2_2347_2305);
        manager.commit_repository_transaction(removal).unwrap();
        let bytes = std::fs::read(frame_path(&directory, 2)).unwrap();
        let mut frame = crate::storage::AuthorityFrame::from_bytes(&bytes).unwrap();
        frame.repository_id = RepositoryId::new("some-other-repository").unwrap();
        frame.operation.repository_id = frame.repository_id.clone();
        let error = frame
            .apply(&mut base)
            .expect_err("a frame of another repository must not apply");
        assert!(
            error.to_string().contains("belongs to repository"),
            "{error}"
        );
        assert!(
            base.repository_authority.as_ref().unwrap().roots.generation == 1,
            "nothing is applied when a frame is refused"
        );
    }

    #[test]
    fn an_incremental_graph_delta_in_an_authority_journal_refuses_the_open() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        drop(manager);
        let delta = crate::storage::delta::GraphSnapshotDelta::empty(1)
            .to_bytes()
            .unwrap();
        std::fs::create_dir_all(deltas_dir(&directory)).unwrap();
        std::fs::write(frame_path(&directory, 2), &delta).unwrap();
        let mut record = read_authority_json(directory.path());
        record["head_generation"] = serde_json::json!(2);
        record["acknowledged_deltas"] = serde_json::json!([{
            "generation": 2,
            "sha256": hex::encode(Sha256::digest(&delta)),
        }]);
        record.as_object_mut().unwrap().remove("history_validation");
        write_authority_json(directory.path(), &record);
        let error = reopen_error(&directory);
        assert!(
            error.contains("followed by an incremental graph delta"),
            "a graph delta over authority must be refused by name: {error}"
        );
    }

    #[test]
    fn an_authority_frame_over_a_plain_graph_journal_is_refused() {
        let directory = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(directory.path());
        let base = GraphSnapshot::empty().to_bytes().unwrap();
        let generation = backend
            .save_snapshot("plain-graph", &base, crate::storage::GENERATION_INIT)
            .unwrap();
        // Any well-formed frame bytes will do: the base is a plain graph, so
        // the journal kind is wrong before the frame body matters.
        let (frames_dir, frame_bytes) = {
            let framed = TempDir::new().unwrap();
            let (_backend, manager) = framed_local_repository(&framed);
            let (removal, _) = remove_compose_transaction(&manager, 0xf2_2347_2306);
            manager.commit_repository_transaction(removal).unwrap();
            (
                directory.path().join("plain-graph").join("deltas"),
                std::fs::read(frame_path(&framed, 2)).unwrap(),
            )
        };
        std::fs::create_dir_all(&frames_dir).unwrap();
        std::fs::write(
            frames_dir.join(format!("{:020}.kndd", generation + 1)),
            &frame_bytes,
        )
        .unwrap();
        let record_path = directory.path().join("plain-graph").join("authority.json");
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
        record["version"] = serde_json::json!(4);
        record["head_generation"] = serde_json::json!(generation + 1);
        record["acknowledged_deltas"] = serde_json::json!([{
            "generation": generation + 1,
            "sha256": hex::encode(Sha256::digest(&frame_bytes)),
        }]);
        std::fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
        let error = crate::storage::load_recovered_snapshot(&backend, "plain-graph")
            .expect_err("a frame over a plain graph base must refuse");
        assert!(
            error.to_string().contains("followed by an authority frame"),
            "{error}"
        );
    }

    /// The reader that predates frames is still in this tree: the graph delta
    /// decoder refuses the frame magic, and the record version it accepts is
    /// exactly the one a frame journal moves away from.
    #[test]
    fn readers_that_predate_frames_refuse_a_frame_journal_and_accept_a_compacted_one() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        manager
            .commit_repository_transaction(overlay_publication(&manager, 0xf2_2347_2401, 0x21))
            .unwrap();
        assert_eq!(
            record_version(&directory),
            4,
            "an acknowledged frame journal is recorded at a version older readers do not accept"
        );
        assert_eq!(
            crate::storage::backend::LOCAL_AUTHORITY_VERSION,
            3,
            "the version every reader before frames requires is the journal-free one"
        );
        assert_eq!(
            crate::storage::backend::LOCAL_AUTHORITY_FRAME_JOURNAL_VERSION,
            u32::try_from(record_version(&directory)).unwrap()
        );
        let bytes = std::fs::read(frame_path(&directory, 2)).unwrap();
        let old_decoder = crate::storage::delta::GraphSnapshotDelta::from_bytes(&bytes)
            .expect_err("the incremental delta decoder must refuse a frame");
        assert!(
            old_decoder
                .to_string()
                .contains("invalid delta magic bytes"),
            "{old_decoder}"
        );

        // Compaction: the count bound at zero makes the next publication a
        // full snapshot, which retires the journal and restores the record
        // version older readers accept.
        manager.persistence().set_max_journal_frames_for_test(0);
        manager
            .commit_repository_transaction(overlay_publication(&manager, 0xf2_2347_2402, 0x22))
            .unwrap();
        assert_eq!(record_version(&directory), 3);
        assert_eq!(acknowledged_frame_count(&directory), 0);
        let record = read_authority_json(directory.path());
        assert_eq!(record["snapshot_generation"], record["head_generation"]);
        assert!(
            record["history_validation"]["journal_sha256"].is_null(),
            "a compacted head is journal-free again: {record}"
        );
        let (_, frames, journal_bytes) = manager.persistence().journal_state_for_test();
        assert_eq!((frames, journal_bytes), (0, 0));
        assert!(
            !frame_path(&directory, 2).exists(),
            "the retired frame is cleared after the promotion"
        );
        assert_same_authority(
            &manager.read_authority(),
            &reopen(&directory).read_authority(),
            "compacted",
        );
    }

    #[test]
    fn the_frame_count_bound_forces_a_full_snapshot_that_retires_the_journal() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        manager.persistence().set_max_journal_frames_for_test(2);
        for round in 0..5u32 {
            manager
                .commit_repository_transaction(overlay_publication(
                    &manager,
                    0xf2_2347_2500 + u128::from(round),
                    0x30 + round as u8,
                ))
                .unwrap();
            let expected_frames = match round {
                0 => 1,
                1 => 2,
                2 => 0,
                3 => 1,
                4 => 2,
                _ => unreachable!(),
            };
            assert_eq!(
                acknowledged_frame_count(&directory),
                expected_frames,
                "round {round}: the third publication after a snapshot rewrites it"
            );
            let reopened = reopen(&directory);
            assert_same_authority(
                &manager.read_authority(),
                &reopened.read_authority(),
                &format!("round {round}"),
            );
            assert!(reopened.opened_by_history_validation(), "round {round}");
        }
    }

    #[test]
    fn a_frame_larger_than_the_journal_byte_bound_forces_a_full_snapshot() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        manager
            .persistence()
            .set_journal_byte_bound_for_test(Some(1));
        let (removal, _) = remove_compose_transaction(&manager, 0xf2_2347_2601);
        manager.commit_repository_transaction(removal).unwrap();
        assert_eq!(record_version(&directory), 3);
        assert_eq!(acknowledged_frame_count(&directory), 0);
        let phases = last_persistence_phases().unwrap();
        let (base_bytes, frames, _) = manager.persistence().journal_state_for_test();
        assert_eq!(base_bytes as usize, phases.payload_bytes);
        assert_eq!(frames, 0);
    }

    #[test]
    fn a_frame_staged_past_head_is_ignored_replaced_and_discarded() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        manager
            .commit_repository_transaction(overlay_publication(&manager, 0xf2_2347_2701, 0x40))
            .unwrap();
        // A writer that died between installing its frame and renaming its
        // record leaves exactly this behind.
        let orphan = std::fs::read(frame_path(&directory, 2)).unwrap();
        std::fs::write(frame_path(&directory, 3), &orphan).unwrap();

        let (reopened, receipt) = RepositoryAuthorityManager::open_with_payload_stats(
            repository_id(),
            Arc::new(LocalFileBackend::new(directory.path())),
        )
        .unwrap();
        assert_eq!(
            reopened.read_authority().generation(),
            2,
            "the orphan is not authority"
        );
        assert_eq!(receipt.unwrap().acknowledged_delta_count(), 1);
        drop(reopened);

        // The next append lands at the orphan's generation and replaces it.
        manager
            .commit_repository_transaction(overlay_publication(&manager, 0xf2_2347_2702, 0x41))
            .unwrap();
        assert_ne!(std::fs::read(frame_path(&directory, 3)).unwrap(), orphan);
        assert_eq!(acknowledged_frame_count(&directory), 2);
        assert_same_authority(
            &manager.read_authority(),
            &reopen(&directory).read_authority(),
            "replaced orphan",
        );

        // A full promotion with an orphan past head discards it rather than
        // refusing forever.
        std::fs::write(frame_path(&directory, 4), &orphan).unwrap();
        manager.persistence().set_max_journal_frames_for_test(0);
        manager
            .commit_repository_transaction(overlay_publication(&manager, 0xf2_2347_2703, 0x42))
            .expect("a stale frame past head must not wedge a full promotion");
        assert_eq!(record_version(&directory), 3);
        assert!(
            !frame_path(&directory, 4).exists(),
            "the orphan is discarded"
        );
        assert_same_authority(
            &manager.read_authority(),
            &reopen(&directory).read_authority(),
            "promoted past orphan",
        );
    }

    /// The production writer's proof is what keeps a frame that decodes and
    /// applies cleanly, but rebuilds a different head, out of the journal.
    /// The fault here tampers with the drained frame inside the production
    /// path, after the drain and before the bytes are proven, so a writer that
    /// stopped proving would persist it as a frame and this test would see a
    /// frame journal instead of a full snapshot.
    #[test]
    fn the_production_writer_refuses_a_frame_that_does_not_reproduce_the_successor() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        manager
            .commit_repository_transaction(overlay_publication(&manager, 0xf2_2347_2801, 0x50))
            .unwrap();
        assert_eq!(acknowledged_frame_count(&directory), 1);
        let current = manager.read_authority().snapshot().clone();

        crate::storage::authority_frame::tamper_with_next_drained_frame(|frame| {
            frame.workspaces.clear();
        });
        manager
            .commit_repository_transaction(overlay_publication(&manager, 0xf2_2347_2802, 0x51))
            .expect("a refused frame costs a full snapshot, never the publication");
        assert_eq!(
            record_version(&directory),
            3,
            "the publication landed as a full snapshot"
        );
        assert_eq!(acknowledged_frame_count(&directory), 0);
        assert!(
            !frame_path(&directory, 3).exists(),
            "no frame was written for the refused publication"
        );
        let next = manager.read_authority().snapshot().clone();
        assert_same_authority(
            &manager.read_authority(),
            &reopen(&directory).read_authority(),
            "fallback",
        );

        // Only the proof stood between the tampered frame and the journal: the
        // same tampering produces bytes that verify, decode, and apply.
        let mut tampered = crate::storage::AuthorityFrame::encode(&current, &next)
            .expect("the honest frame proves");
        tampered.workspaces.clear();
        let decoded =
            crate::storage::AuthorityFrame::from_bytes(&tampered.to_bytes().unwrap()).unwrap();
        let mut applied = current.clone();
        decoded
            .apply(&mut applied)
            .expect("the tampered frame applies without complaint");
        assert_ne!(
            applied.repository_authority, next.repository_authority,
            "and rebuilds a head that is not the successor"
        );
    }

    #[test]
    fn a_head_rebuilt_from_a_hand_built_frame_that_lost_a_change_fails_admission() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        let current = manager.read_authority().snapshot().clone();
        let (removal, _) = remove_compose_transaction(&manager, 0xf2_2347_2851);
        manager.commit_repository_transaction(removal).unwrap();
        let next = manager.read_authority().snapshot().clone();

        let honest = crate::storage::AuthorityFrame::encode(&current, &next)
            .expect("the writer's frame reproduces the successor");
        let mut applied = current.clone();
        honest.apply(&mut applied).unwrap();
        assert_eq!(applied.repository_authority, next.repository_authority);
        assert_eq!(applied.changes, next.changes);

        // A frame that dropped its new change still applies as a patch, and
        // the head it builds is not the successor. Two things keep that from
        // ever being served: the writer proves reproduction before persisting
        // (which is why `encode` and not a hand-built frame is the only path
        // to a durable frame), and a head that does not recompute to the roots
        // the frame acknowledged fails admission on any open that has no
        // proof for it.
        let mut without_change = honest.clone();
        without_change.changes.clear();
        without_change.admission_policies.clear();
        let mut crippled = current.clone();
        without_change.apply(&mut crippled).unwrap();
        assert_ne!(crippled.changes, next.changes);
        let error = crippled
            .validate_storage_admission()
            .expect_err("a head that lost a change cannot pass admission");
        assert!(
            error.to_string().contains("change not found")
                || error.to_string().contains("root bundle")
                || error.to_string().contains("policy"),
            "{error}"
        );
    }

    #[test]
    fn a_frame_whose_operation_names_other_base_roots_does_not_apply() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        let base = manager.read_authority().snapshot().clone();
        manager
            .commit_repository_transaction(overlay_publication(&manager, 0xf2_2347_2951, 0x70))
            .unwrap();
        let bytes = std::fs::read(frame_path(&directory, 2)).unwrap();
        let mut frame = crate::storage::AuthorityFrame::from_bytes(&bytes).unwrap();
        // Same generation, same operation, but the predecessor it claims is a
        // state that never existed: only the roots binding can tell.
        frame.operation.roots_before.history.hash =
            Hash256::from_bytes(*Sha256::digest(b"another history").as_ref());
        let mut applied = base.clone();
        let error = frame
            .apply(&mut applied)
            .expect_err("a frame that names other base roots must not apply");
        assert!(
            error.to_string().contains("does not extend the base"),
            "{error}"
        );
        assert_eq!(
            applied.repository_authority, base.repository_authority,
            "nothing is applied when a frame is refused"
        );
    }

    #[test]
    fn the_writer_refuses_a_frame_that_would_not_reproduce_the_successor() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        let current = manager.read_authority().snapshot().clone();
        manager
            .commit_repository_transaction(overlay_publication(&manager, 0xf2_2347_2961, 0x71))
            .unwrap();
        let next = manager.read_authority().snapshot().clone();
        crate::storage::AuthorityFrame::encode(&current, &next)
            .expect("the real successor encodes");

        // A successor whose base-inherited receipt moved is not something a
        // patch over the base can express, and the writer says so instead of
        // persisting a frame that rebuilds a different head.
        let mut drifted = next.clone();
        drifted.repository_authority.as_mut().unwrap().receipts[0]
            .roots_before
            .generation += 1;
        let error = crate::storage::AuthorityFrame::encode(&current, &drifted)
            .expect_err("a frame that cannot reproduce the successor is refused by the writer");
        assert!(
            error.to_string().contains(
                "does not reproduce the successor: repository authority envelopes differ"
            ),
            "{error}"
        );

        // So is a successor that dropped a change the base carried, because a
        // frame only ever adds history.
        let mut shrunk = next.clone();
        let some_change = *shrunk.changes.keys().next().unwrap();
        shrunk.changes.remove(&some_change);
        let error = crate::storage::AuthorityFrame::encode(&current, &shrunk)
            .expect_err("a successor with fewer changes than its base cannot be a frame");
        assert!(
            error
                .to_string()
                .contains("does not reproduce the successor: changes differ"),
            "{error}"
        );

        // A mutation in a collection no frame patches is refused too, because
        // the proof compares the whole snapshot, not the patched fields.
        let mut annotated = next.clone();
        annotated
            .work_links
            .push(kin_model::WorkLink::DecomposesTo {
                parent: kin_model::WorkId::new(),
                child: kin_model::WorkId::new(),
            });
        let error = crate::storage::AuthorityFrame::encode(&current, &annotated)
            .expect_err("a successor that moved an unpatched collection is not a frame");
        assert!(
            error
                .to_string()
                .contains("does not reproduce the successor: work links differ"),
            "{error}"
        );
    }

    #[test]
    fn an_indeterminate_frame_append_is_reconciled_by_the_next_commit() {
        let directory = TempDir::new().unwrap();
        let (backend, manager) = framed_local_repository(&directory);
        let (removal, _) = remove_compose_transaction(&manager, 0xf2_2347_2901);

        backend.set_delta_before_authority_commit_hook(|| {
            // The record write claims and promotes its candidate through two
            // parent syncs; failing the third leaves the record installed but
            // its durability unconfirmed.
            crate::storage::mmap::fail_parent_sync_after(2);
        });
        let error = manager
            .commit_repository_transaction(removal.clone())
            .expect_err("an installed frame with a lost durability acknowledgement must fail");
        assert!(
            matches!(error, KinDbError::SnapshotPersistenceIndeterminate(_)),
            "{error}"
        );
        assert_eq!(manager.read_authority().generation(), 1);
        assert_eq!(
            acknowledged_frame_count(&directory),
            1,
            "the frame was installed"
        );

        let receipt = manager
            .commit_repository_transaction(removal)
            .expect("the retained frame candidate reconciles as committed");
        assert_eq!(receipt.generation, 2);
        assert_eq!(manager.read_authority().generation(), 2);
        assert_eq!(
            acknowledged_frame_count(&directory),
            1,
            "no second frame was appended"
        );
        assert_same_authority(
            &manager.read_authority(),
            &reopen(&directory).read_authority(),
            "reconciled",
        );
    }

    #[derive(Clone, Copy, Debug)]
    enum InjectedOutcome {
        Indeterminate,
        NotCommitted,
    }

    impl InjectedOutcome {
        fn outcome(self, what: &str) -> SnapshotSaveOutcome {
            match self {
                Self::Indeterminate => SnapshotSaveOutcome::Indeterminate(
                    KinDbError::SnapshotPersistenceIndeterminate(format!(
                        "injected: the {what} outcome is unknown"
                    )),
                ),
                Self::NotCommitted => {
                    SnapshotSaveOutcome::NotCommitted(storage(format!("injected: the {what} lost")))
                }
            }
        }
    }

    /// The local backend behind a fault script.
    ///
    /// The local backend's own indeterminacy always comes after its record
    /// rename, so it can never report a frame append or a snapshot write as
    /// indeterminate while nothing landed. A backend with real indeterminacy
    /// can, and this wrapper answers the next scripted write with the scripted
    /// outcome without touching storage; every other call is the real backend.
    struct FaultScriptedBackend {
        inner: Arc<LocalFileBackend>,
        frame_faults: Mutex<std::collections::VecDeque<InjectedOutcome>>,
        snapshot_faults: Mutex<std::collections::VecDeque<InjectedOutcome>>,
    }

    impl FaultScriptedBackend {
        fn new(inner: Arc<LocalFileBackend>) -> Self {
            Self {
                inner,
                frame_faults: Mutex::new(std::collections::VecDeque::new()),
                snapshot_faults: Mutex::new(std::collections::VecDeque::new()),
            }
        }

        fn script_frame_append(&self, outcome: InjectedOutcome) {
            self.frame_faults.lock().push_back(outcome);
        }

        fn script_snapshot_write(&self, outcome: InjectedOutcome) {
            self.snapshot_faults.lock().push_back(outcome);
        }
    }

    impl StorageBackend for FaultScriptedBackend {
        fn supports_incremental_deltas(&self) -> bool {
            self.inner.supports_incremental_deltas()
        }

        fn load_snapshot(
            &self,
            repo_id: &str,
        ) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
            self.inner.load_snapshot(repo_id)
        }

        fn save_source_blob(
            &self,
            repo_id: &str,
            digest: [u8; 32],
            data: &[u8],
        ) -> Result<(), KinDbError> {
            self.inner.save_source_blob(repo_id, digest, data)
        }

        fn with_source_blob_write_batch(
            &self,
            repo_id: &str,
            operation: &mut dyn FnMut(&dyn SourceBlobWriteBatch) -> Result<(), KinDbError>,
        ) -> Result<(), KinDbError> {
            self.inner.with_source_blob_write_batch(repo_id, operation)
        }

        fn load_source_blob(
            &self,
            repo_id: &str,
            digest: [u8; 32],
        ) -> Result<Option<Vec<u8>>, KinDbError> {
            self.inner.load_source_blob(repo_id, digest)
        }

        fn load_source_blob_bounded(
            &self,
            repo_id: &str,
            digest: [u8; 32],
            max_bytes: u64,
        ) -> Result<Option<Vec<u8>>, KinDbError> {
            self.inner
                .load_source_blob_bounded(repo_id, digest, max_bytes)
        }

        fn with_verified_source_blob_batch(
            &self,
            repo_id: &str,
            operation: &mut dyn FnMut(&dyn VerifiedSourceBlobBatch) -> Result<(), KinDbError>,
        ) -> Result<(), KinDbError> {
            self.inner
                .with_verified_source_blob_batch(repo_id, operation)
        }

        fn source_blob_len(
            &self,
            repo_id: &str,
            digest: [u8; 32],
        ) -> Result<Option<u64>, KinDbError> {
            self.inner.source_blob_len(repo_id, digest)
        }

        fn load_snapshot_authority(
            &self,
            repo_id: &str,
        ) -> Result<Option<crate::storage::backend::SnapshotAuthority>, KinDbError> {
            self.inner.load_snapshot_authority(repo_id)
        }

        fn load_recovery_state(
            &self,
            repo_id: &str,
        ) -> Result<crate::storage::backend::SnapshotRecoveryState, KinDbError> {
            self.inner.load_recovery_state(repo_id)
        }

        fn save_snapshot(
            &self,
            repo_id: &str,
            data: &[u8],
            expected_gen: Generation,
        ) -> Result<Generation, KinDbError> {
            self.inner.save_snapshot(repo_id, data, expected_gen)
        }

        fn save_snapshot_classified(
            &self,
            repo_id: &str,
            data: &[u8],
            expected_cursor: SnapshotCursor,
        ) -> SnapshotSaveOutcome {
            self.inner
                .save_snapshot_classified(repo_id, data, expected_cursor)
        }

        fn save_snapshot_validated(
            &self,
            repo_id: &str,
            data: &[u8],
            expected: SnapshotCursor,
            history_validator_version: Option<u32>,
        ) -> SnapshotSaveOutcome {
            if let Some(fault) = self.snapshot_faults.lock().pop_front() {
                return fault.outcome("snapshot write");
            }
            self.inner
                .save_snapshot_validated(repo_id, data, expected, history_validator_version)
        }

        fn record_history_validation(
            &self,
            repo_id: &str,
            generation: Generation,
            snapshot_sha256: &str,
            validator_version: u32,
        ) -> Result<bool, KinDbError> {
            self.inner.record_history_validation(
                repo_id,
                generation,
                snapshot_sha256,
                validator_version,
            )
        }

        fn supports_authority_frames(&self) -> bool {
            self.inner.supports_authority_frames()
        }

        fn save_authority_frame(
            &self,
            repo_id: &str,
            frame: &[u8],
            expected: SnapshotCursor,
            history_validator_version: Option<u32>,
        ) -> SnapshotSaveOutcome {
            if let Some(fault) = self.frame_faults.lock().pop_front() {
                return fault.outcome("frame append");
            }
            self.inner
                .save_authority_frame(repo_id, frame, expected, history_validator_version)
        }

        fn record_journal_history_validation(
            &self,
            repo_id: &str,
            head_generation: Generation,
            snapshot_sha256: &str,
            journal_sha256: &str,
            validator_version: u32,
        ) -> Result<bool, KinDbError> {
            self.inner.record_journal_history_validation(
                repo_id,
                head_generation,
                snapshot_sha256,
                journal_sha256,
                validator_version,
            )
        }

        fn save_delta(
            &self,
            repo_id: &str,
            delta_data: &[u8],
            base_gen: Generation,
        ) -> Result<Generation, KinDbError> {
            self.inner.save_delta(repo_id, delta_data, base_gen)
        }

        fn load_deltas_since(
            &self,
            repo_id: &str,
            since_gen: Generation,
        ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
            self.inner.load_deltas_since(repo_id, since_gen)
        }

        fn clear_deltas(&self, repo_id: &str) -> Result<(), KinDbError> {
            self.inner.clear_deltas(repo_id)
        }

        fn save_overlay(
            &self,
            repo_id: &str,
            session_id: &str,
            data: &[u8],
        ) -> Result<(), KinDbError> {
            self.inner.save_overlay(repo_id, session_id, data)
        }

        fn load_overlay(
            &self,
            repo_id: &str,
            session_id: &str,
        ) -> Result<Option<Vec<u8>>, KinDbError> {
            self.inner.load_overlay(repo_id, session_id)
        }

        fn load_prepared_workspace_graph(
            &self,
            repo_id: &str,
            workspace_id: &str,
        ) -> Result<Option<PreparedWorkspaceGraphArtifact>, KinDbError> {
            self.inner
                .load_prepared_workspace_graph(repo_id, workspace_id)
        }

        fn record_prepared_workspace_graph(
            &self,
            repo_id: &str,
            workspace_id: &str,
            artifact: &PreparedWorkspaceGraphArtifact,
        ) -> Result<bool, KinDbError> {
            self.inner
                .record_prepared_workspace_graph(repo_id, workspace_id, artifact)
        }

        fn delete_overlay(&self, repo_id: &str, session_id: &str) -> Result<(), KinDbError> {
            self.inner.delete_overlay(repo_id, session_id)
        }

        fn list_repos(&self) -> Result<Vec<String>, KinDbError> {
            self.inner.list_repos()
        }
    }

    /// `framed_local_repository` behind the fault script: one committed
    /// generation, frames admitted by size, and no fault scripted yet.
    fn fault_scripted_repository(
        directory: &TempDir,
    ) -> (
        Arc<FaultScriptedBackend>,
        RepositoryAuthorityManager<FaultScriptedBackend>,
    ) {
        let backend = Arc::new(FaultScriptedBackend::new(Arc::new(LocalFileBackend::new(
            directory.path(),
        ))));
        let manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        manager
            .commit_repository_transaction(arbitrary_repository_transaction(&manager))
            .unwrap();
        manager
            .persistence()
            .set_journal_byte_bound_for_test(Some(u64::MAX));
        assert_eq!(manager.read_authority().generation(), 1);
        (backend, manager)
    }

    /// A frame retained after an indeterminate append belongs to exactly one
    /// candidate. Once a reconciliation proves that candidate was not
    /// committed, the publication drops it, and a later successor at the same
    /// generation is a different state: its own indeterminate outcome must be
    /// reconciled through its own bytes, never through the dropped frame.
    ///
    /// On the local backend this cannot happen today, because every
    /// indeterminate outcome it reports comes after the record rename, so the
    /// retry branch never runs after one; the scripted backend supplies the
    /// indeterminacy a remote backend can produce before its commit point.
    #[test]
    fn a_dropped_frame_candidate_is_not_reconciled_against_a_later_successor() {
        let directory = TempDir::new().unwrap();
        let (backend, manager) = fault_scripted_repository(&directory);

        // Candidate A: a frame append whose outcome is unknown and which
        // installed nothing.
        backend.script_frame_append(InjectedOutcome::Indeterminate);
        let error = manager
            .commit_repository_transaction(overlay_publication(&manager, 0xf2_2347_2911, 0x81))
            .expect_err("an indeterminate append fails the commit");
        assert!(
            matches!(error, KinDbError::SnapshotPersistenceIndeterminate(_)),
            "{error}"
        );
        assert_eq!(acknowledged_frame_count(&directory), 0);

        // The next commit reconciles A: nothing landed, the exact frame is
        // retried, and the retry is refused. A is dropped for good.
        backend.script_frame_append(InjectedOutcome::NotCommitted);
        let error = manager
            .commit_repository_transaction(overlay_publication(&manager, 0xf2_2347_2912, 0x82))
            .expect_err("a refused reconciliation fails the commit that triggered it");
        assert!(
            error
                .to_string()
                .contains("injected: the frame append lost"),
            "{error}"
        );
        assert_eq!(manager.read_authority().generation(), 1);
        assert_eq!(acknowledged_frame_count(&directory), 0);

        // Candidate B at the same generation takes the full-snapshot path and
        // is left indeterminate too, with nothing installed.
        manager.persistence().set_max_journal_frames_for_test(0);
        backend.script_snapshot_write(InjectedOutcome::Indeterminate);
        let candidate_b = overlay_publication(&manager, 0xf2_2347_2913, 0x83);
        let error = manager
            .commit_repository_transaction(candidate_b.clone())
            .expect_err("an indeterminate snapshot write fails the commit");
        assert!(
            matches!(error, KinDbError::SnapshotPersistenceIndeterminate(_)),
            "{error}"
        );
        assert_eq!(manager.read_authority().generation(), 1);

        // The retry of B reconciles it through B's own bytes and then replays
        // it idempotently. A writer that still held A's frame would retry that
        // frame here instead, commit it, and publish B in memory over a store
        // that says A.
        let receipt = manager
            .commit_repository_transaction(candidate_b)
            .expect("B reconciles as committed and replays");
        assert_eq!(receipt.generation, 2);
        assert_eq!(manager.read_authority().generation(), 2);
        assert_eq!(
            record_version(&directory),
            3,
            "B landed as the full snapshot it was persisted as, not as A's frame"
        );
        assert_eq!(acknowledged_frame_count(&directory), 0);
        assert!(
            !frame_path(&directory, 2).exists(),
            "A's frame was never installed"
        );
        let overlay_names = |state: &RepositoryAuthorityState| -> Vec<String> {
            state.metadata().workspaces[0]
                .semantic_overlay
                .entity_deltas()
                .iter()
                .filter_map(|delta| match delta {
                    EntityDelta::Added { new } => Some(new.name.clone()),
                    _ => None,
                })
                .collect()
        };
        let names = overlay_names(&manager.read_authority());
        assert!(
            names.iter().any(|name| name == "kin_131"),
            "B (seed 0x83) is the published state at generation 2: {names:?}"
        );
        assert!(
            !names.iter().any(|name| name == "kin_129"),
            "A (seed 0x81) was dropped and never published: {names:?}"
        );
        assert_same_authority(
            &manager.read_authority(),
            &reopen(&directory).read_authority(),
            "after the dropped candidate",
        );
    }

    /// The first half of the rule above, watched from inside the persistence
    /// state: the frame retained after an indeterminate append is dropped the
    /// moment a reconciliation refuses it, not kept until some later commit
    /// happens to overwrite it.
    #[test]
    fn a_refused_frame_reconciliation_drops_the_retained_frame() {
        let directory = TempDir::new().unwrap();
        let (backend, manager) = fault_scripted_repository(&directory);

        backend.script_frame_append(InjectedOutcome::Indeterminate);
        let error = manager
            .commit_repository_transaction(overlay_publication(&manager, 0xf2_2347_2921, 0x84))
            .expect_err("an indeterminate append fails the commit");
        assert!(
            matches!(error, KinDbError::SnapshotPersistenceIndeterminate(_)),
            "{error}"
        );
        {
            let state = manager.persistence().state.lock();
            let retained = state
                .pending_frame
                .as_ref()
                .expect("an indeterminate append retains its frame for reconciliation");
            assert_eq!(retained.roots.generation, 2);
        }

        backend.script_frame_append(InjectedOutcome::NotCommitted);
        let error = manager
            .commit_repository_transaction(overlay_publication(&manager, 0xf2_2347_2922, 0x85))
            .expect_err("a refused reconciliation fails the commit that triggered it");
        assert!(
            error
                .to_string()
                .contains("injected: the frame append lost"),
            "{error}"
        );
        assert!(
            manager.persistence().state.lock().pending_frame.is_none(),
            "a refused reconciliation must drop the retained frame"
        );
        assert_eq!(manager.read_authority().generation(), 1);
        assert_eq!(acknowledged_frame_count(&directory), 0);
    }

    /// The second half on its own: a retained frame is consulted only for the
    /// successor whose roots it carries. One that names other roots at the
    /// same generation is dropped rather than retried, even when the candidate
    /// being reconciled is the very one whose append retained it.
    #[test]
    fn a_retained_frame_naming_other_roots_at_the_same_generation_is_dropped_not_retried() {
        let directory = TempDir::new().unwrap();
        let (backend, manager) = fault_scripted_repository(&directory);

        backend.script_frame_append(InjectedOutcome::Indeterminate);
        let candidate = overlay_publication(&manager, 0xf2_2347_2931, 0x86);
        let error = manager
            .commit_repository_transaction(candidate.clone())
            .expect_err("an indeterminate append fails the commit");
        assert!(
            matches!(error, KinDbError::SnapshotPersistenceIndeterminate(_)),
            "{error}"
        );
        assert_eq!(acknowledged_frame_count(&directory), 0);

        // The retained frame now claims a history root the candidate does not
        // have. Its generation still matches, so a writer keyed on generation
        // alone would retry these bytes for the candidate.
        {
            let mut state = manager.persistence().state.lock();
            let retained = state
                .pending_frame
                .as_mut()
                .expect("an indeterminate append retains its frame for reconciliation");
            assert_eq!(retained.roots.generation, 2);
            retained.roots.history.hash =
                Hash256::from_bytes(*Sha256::digest(b"another candidate at generation 2").as_ref());
        }

        let receipt = manager
            .commit_repository_transaction(candidate)
            .expect("the candidate reconciles as committed and replays");
        assert_eq!(receipt.generation, 2);
        assert_eq!(manager.read_authority().generation(), 2);
        assert_eq!(
            record_version(&directory),
            3,
            "the candidate landed whole, not through the foreign frame"
        );
        assert_eq!(acknowledged_frame_count(&directory), 0);
        assert!(
            !frame_path(&directory, 2).exists(),
            "the foreign frame was never installed"
        );
        assert!(manager.persistence().state.lock().pending_frame.is_none());
        assert_same_authority(
            &manager.read_authority(),
            &reopen(&directory).read_authority(),
            "after the foreign frame was dropped",
        );
    }

    #[test]
    fn freezes_reconstruct_a_journal_head_and_a_freezing_commit_compacts_it() {
        let directory = TempDir::new().unwrap();
        let (_backend, manager) = framed_local_repository(&directory);
        manager
            .commit_repository_transaction(overlay_publication(&manager, 0xf2_2347_3001, 0x60))
            .unwrap();
        assert_eq!(acknowledged_frame_count(&directory), 1);

        let expected_roots = manager.read_authority().roots().clone();
        let frozen = manager
            .freeze_current_authority(&expected_roots)
            .expect("a journal head freezes");
        assert_eq!(frozen.roots(), &expected_roots);
        assert_same_authority(&manager.read_authority(), frozen.authority(), "frozen");
        drop(frozen);

        let (receipt, freeze) = manager
            .commit_repository_transaction_and_freeze(overlay_publication(
                &manager,
                0xf2_2347_3002,
                0x61,
            ))
            .unwrap();
        assert_eq!(receipt.generation, 3);
        assert_eq!(
            record_version(&directory),
            3,
            "a freezing commit writes a full snapshot"
        );
        assert_eq!(acknowledged_frame_count(&directory), 0);
        drop(freeze);
        assert_same_authority(
            &manager.read_authority(),
            &reopen(&directory).read_authority(),
            "after freezing commit",
        );
    }

    // FIR-2291: what a commit spends on tree bodies, and whether that spend
    // follows the edit or the store.
    //
    // Every fixture above this point carries an empty workspace tree, so none
    // of them can see this cost at all. A converted repository is mostly tree:
    // psf/requests tracks 130 files, expressjs/express more, and a commit used
    // to read and re-hash every one of them to record a one-line edit.

    /// A repository whose workspace tree carries `files` artifacts, each backed
    /// by its own distinct body in the immutable source CAS.
    struct SyntheticTreeStore {
        backend: Arc<MemoryBackend>,
        manager: RepositoryAuthorityManager<MemoryBackend>,
        files: usize,
        body_bytes: usize,
    }

    /// Body bytes for tree artifact `index`, padded out to `body_bytes` so a
    /// store's byte size is a knob independent of its file count.
    fn synthetic_tree_body(index: usize, body_bytes: usize) -> Vec<u8> {
        let mut body = format!("// synthetic tree artifact {index}\n").into_bytes();
        if body.len() < body_bytes {
            body.resize(body_bytes, b'x');
        }
        body
    }

    fn synthetic_tree_path(index: usize) -> RepoPath {
        RepoPath::from_bytes(format!("src/generated/artifact_{index:05}.rs").into_bytes())
            .expect("a synthetic tree path is valid")
    }

    /// Seed a repository whose first change introduces `files` artifacts and
    /// whose workspace is admitted at that exact tree.
    fn build_synthetic_tree_store(files: usize, body_bytes: usize) -> SyntheticTreeStore {
        assert!(
            files >= 2,
            "a tree store needs one file to edit and at least one to leave alone"
        );
        let backend = Arc::new(MemoryBackend::default());
        let manager = initial_manager(Arc::clone(&backend));

        let mut tree_deltas = Vec::with_capacity(files);
        for index in 0..files {
            let body = synthetic_tree_body(index, body_bytes);
            let hash = digest(&body);
            manager.save_source_blob(hash, &body).unwrap();
            tree_deltas.push(TreeDelta::Added {
                artifact_id: ArtifactId(Uuid::from_u128(1_000_000 + index as u128)),
                new: LocatedEntry::new(synthetic_tree_path(index), TreeEntry::blob(hash, false)),
            });
        }
        let tree = ResolvedTree::default().apply(&tree_deltas).unwrap();
        let tree_hash = compute_resolved_tree_hash(&tree).unwrap();
        let shared = SharedAdmissionPolicy::empty(0);
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: Vec::new(),
            timestamp: Timestamp(
                chrono::DateTime::parse_from_rfc3339("2026-08-22T12:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            author: AuthorId::new("fir2291-tree-store"),
            message: format!("introduce {files} synthetic artifacts"),
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

        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(2291));
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

        let mut transaction = transaction_shell(&manager, 0xf2_2291_0001);
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
        manager.commit_repository_transaction(transaction).unwrap();

        SyntheticTreeStore {
            backend,
            manager,
            files,
            body_bytes,
        }
    }

    /// The transaction for one edit to one file: the shape `kin commit` takes
    /// after a one-line change. Generic over the backend so the same edit can
    /// be timed against the in-memory fixture and against real disk.
    fn one_file_edit_transaction<B: StorageBackend + ?Sized + 'static>(
        manager: &RepositoryAuthorityManager<B>,
        body_bytes: usize,
        round: usize,
    ) -> RepositoryTransaction {
        let workspace = manager.read_authority().metadata().workspaces[0].clone();
        let path = synthetic_tree_path(0);
        let old = workspace
            .tree
            .artifact_at_path(&path)
            .expect("artifact zero is in the seeded tree")
            .clone();
        let mut body = synthetic_tree_body(0, body_bytes);
        body.extend_from_slice(format!("// edit {round}\n").as_bytes());
        let hash = digest(&body);
        manager.save_source_blob(hash, &body).unwrap();
        let tree_delta = TreeDelta::Updated {
            artifact_id: old.artifact_id,
            old: old.located_entry(),
            new: LocatedEntry::new(path, TreeEntry::blob(hash, false)),
        };
        let next_tree = workspace
            .tree
            .apply(std::slice::from_ref(&tree_delta))
            .unwrap();
        let mutation = WorkspaceMutation {
            workspace_id: workspace.workspace_id,
            expected: WorkspaceExpectation::MustEqual {
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
            tree_deltas: vec![tree_delta],
            new_tree_hash: compute_resolved_tree_hash(&next_tree).unwrap(),
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: workspace.shared_admission_policy.clone(),
            new_admission_policy: workspace.admission_policy,
        };
        let mut transaction = transaction_shell(manager, 0xf2_2291_1000 + round as u128);
        transaction.workspace_mutation = Some(mutation);
        transaction
    }

    /// Commit one file edit against the in-memory fixture, returning the
    /// source-blob reads the commit itself made. That count is the
    /// machine-independent half of this ticket's measurement: it does not move
    /// with host load, and it is what the whole-tree walk inflated.
    fn commit_one_file_edit(store: &SyntheticTreeStore, round: usize) -> usize {
        let transaction = one_file_edit_transaction(&store.manager, store.body_bytes, round);
        store.backend.source_load_count.store(0, Ordering::SeqCst);
        store
            .manager
            .commit_repository_transaction(transaction)
            .unwrap();
        store.backend.source_load_count.load(Ordering::SeqCst)
    }

    /// FIR-2291's acceptance, in the form the mechanism actually takes.
    ///
    /// The ticket's original acceptance named history depth as the multiplier.
    /// The b1lat control disproved that (commit time was flat from depth 5 to
    /// 17) and named store bytes instead, so this asserts the thing that is
    /// true: the bodies a commit reads are set by what the commit changed, not
    /// by how many files the repository tracks.
    ///
    /// Falsifiable in both directions. Restore the whole-tree walk and the
    /// eight-file store reads 8 and the sixty-four-file store reads 64, so the
    /// equality fails on the store size alone.
    #[test]
    fn a_commit_reads_bodies_for_its_edit_not_for_the_whole_store() {
        let small = build_synthetic_tree_store(8, 256);
        let mid = build_synthetic_tree_store(64, 256);
        assert_eq!(small.files * 8, mid.files, "the two stores must differ 8x");

        let small_loads = commit_one_file_edit(&small, 1);
        let mid_loads = commit_one_file_edit(&mid, 1);

        assert_eq!(
            small_loads, mid_loads,
            "a one-file commit read {small_loads} bodies on an {}-file store and {mid_loads} on a \
             {}-file store, so its cost still follows the store rather than the edit",
            small.files, mid.files
        );
        assert!(
            mid_loads < mid.files,
            "a one-file commit read {mid_loads} bodies from a {}-file store, which is the \
             whole-store walk this ticket is about",
            mid.files
        );
    }

    /// The budget the acceptance check in `scripts/acceptance` mirrors: a
    /// one-file commit's body reads are bounded by the edit's own entry count,
    /// with a small fixed allowance for the admission surfaces every commit
    /// reads regardless of size.
    #[test]
    fn a_one_file_commit_stays_inside_its_edit_size_budget() {
        const EDIT_ENTRIES: usize = 1;
        const FIXED_ADMISSION_ALLOWANCE: usize = 4;
        let store = build_synthetic_tree_store(64, 256);
        let loads = commit_one_file_edit(&store, 1);
        assert!(
            loads <= EDIT_ENTRIES + FIXED_ADMISSION_ALLOWANCE,
            "a one-entry edit read {loads} bodies, over the {} the edit size class allows",
            EDIT_ENTRIES + FIXED_ADMISSION_ALLOWANCE
        );
    }

    /// A body this commit newly introduces is still proven present and intact.
    /// Scoping the walk to the edit must not become trusting the edit.
    #[test]
    fn a_commit_still_refuses_an_edit_whose_new_body_is_absent() {
        let store = build_synthetic_tree_store(8, 256);
        let workspace = store.manager.read_authority().metadata().workspaces[0].clone();
        let path = synthetic_tree_path(0);
        let old = workspace
            .tree
            .artifact_at_path(&path)
            .expect("artifact zero is in the seeded tree")
            .clone();
        // The body is never saved, so the CAS has nothing under this digest.
        let hash = digest(b"a body that was never admitted\n");
        let tree_delta = TreeDelta::Updated {
            artifact_id: old.artifact_id,
            old: old.located_entry(),
            new: LocatedEntry::new(path, TreeEntry::blob(hash, false)),
        };
        let next_tree = workspace
            .tree
            .apply(std::slice::from_ref(&tree_delta))
            .unwrap();
        let mutation = WorkspaceMutation {
            workspace_id: workspace.workspace_id,
            expected: WorkspaceExpectation::MustEqual {
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
            tree_deltas: vec![tree_delta],
            new_tree_hash: compute_resolved_tree_hash(&next_tree).unwrap(),
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: workspace.shared_admission_policy.clone(),
            new_admission_policy: workspace.admission_policy,
        };
        let mut transaction = transaction_shell(&store.manager, 0xf2_2291_2001);
        transaction.workspace_mutation = Some(mutation);
        let error = store
            .manager
            .commit_repository_transaction(transaction)
            .expect_err("an edit naming an unadmitted body must fail closed")
            .to_string();
        assert!(
            error.contains("absent from immutable source CAS"),
            "the refusal must name the missing body: {error}"
        );
        assert_eq!(store.manager.read_authority().generation(), 1);
    }

    /// A body already in the tree that goes missing from the CAS is a
    /// repository-integrity fault, not a commit-admission fault, and it is
    /// `kin doctor`'s to find. This pins that boundary deliberately: the commit
    /// path no longer re-reads bodies it already admitted, so it no longer
    /// notices. Delete this test the day commit is meant to catch it again.
    #[test]
    fn a_commit_no_longer_re_reads_bodies_it_already_admitted() {
        let store = build_synthetic_tree_store(8, 256);
        // Evict every seeded body except the one the edit will introduce.
        let untouched = synthetic_tree_body(7, 256);
        store
            .backend
            .blobs
            .lock()
            .remove(digest(&untouched).as_bytes());
        let loads = commit_one_file_edit(&store, 1);
        assert!(
            loads <= 5,
            "the commit read {loads} bodies, so it is still walking the whole tree"
        );
        assert_eq!(
            store.manager.read_authority().generation(),
            2,
            "a commit that touches neither the evicted artifact nor its body still lands"
        );
    }

    /// Copy a synthetic tree store onto a real `LocalFileBackend`, so a commit
    /// pays the lock acquisition, namespace re-confirmation and file read that
    /// every body proof costs on disk. The in-memory fixture is a `HashMap`
    /// lookup per body and hides exactly the cost this ticket is about.
    fn seed_local_backend_from(
        store: &SyntheticTreeStore,
        dir: &TempDir,
    ) -> RepositoryAuthorityManager<LocalFileBackend> {
        let (seed_bytes, _) = store
            .backend
            .snapshot
            .lock()
            .clone()
            .expect("the synthetic store persisted its head");
        let backend = Arc::new(LocalFileBackend::new(dir.path()));
        backend
            .save_snapshot(
                repository_id().as_str(),
                &seed_bytes,
                crate::storage::GENERATION_INIT,
            )
            .unwrap();
        let bodies = store.backend.blobs.lock().clone();
        backend
            .with_source_blob_write_batch(repository_id().as_str(), &mut |batch| {
                for (digest, body) in &bodies {
                    batch.save(*digest, body)?;
                }
                Ok(())
            })
            .unwrap();
        RepositoryAuthorityManager::open(repository_id(), backend).unwrap()
    }

    /// Local, non-citable wall-clock and body-read probe for FIR-2291.
    ///
    /// Reports, for a small and a mid store, what one one-file commit costs on
    /// a real local backend and how many bodies it reads. Run:
    ///
    /// ```text
    /// cargo test -p kin-db --release \
    ///     fir2291_commit_body_cost_bench -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "wall-clock bench; run explicitly in release mode"]
    fn fir2291_commit_body_cost_bench() {
        for (label, files, body_bytes) in [
            ("small", 128usize, 4_096usize),
            ("mid", 2_048usize, 4_096usize),
        ] {
            let store = build_synthetic_tree_store(files, body_bytes);
            let loads = commit_one_file_edit(&store, 0);

            let dir = TempDir::new().unwrap();
            let manager = seed_local_backend_from(&store, &dir);
            let mut samples = Vec::new();
            for round in 1..=3 {
                let transaction = one_file_edit_transaction(&manager, body_bytes, round);
                let started = std::time::Instant::now();
                manager.commit_repository_transaction(transaction).unwrap();
                samples.push(started.elapsed().as_secs_f64() * 1000.0);
            }
            samples.sort_by(f64::total_cmp);
            eprintln!(
                "{label}: {files} files x {body_bytes} B = {:.1} MiB of bodies | one-file commit on \
                 disk median {:.1} ms (min {:.1}, max {:.1}) | body reads {loads}",
                (files * body_bytes) as f64 / (1024.0 * 1024.0),
                samples[samples.len() / 2],
                samples[0],
                samples[samples.len() - 1],
            );
        }
    }

    // FIR-3064: an open leaves the change map on disk.

    fn snapshot_file(directory: &TempDir, generation: Generation) -> std::path::PathBuf {
        directory
            .path()
            .join(repository_id().as_str())
            .join("snapshots")
            .join(format!("{generation:020}.kndb"))
    }

    fn decoded_on_this_thread() -> usize {
        crate::storage::change_map::change_maps_decoded_on_this_thread()
    }

    fn root_folds_on_this_thread() -> usize {
        super::root_bundles_folded_on_this_thread()
    }

    /// FIR-3064: a commit folds its root bundle once, not twice.
    ///
    /// `prepare_successor` folds it in the `kindb.prepare.roots` lap, and the
    /// storage-admission gate a few statements later used to fold it again from
    /// the same snapshot and the same envelope in order to compare it with
    /// itself. `history_root` hands the change map to `canonical_leaf_hash` as
    /// ONE leaf rather than one leaf per change, and `canonical_hash` buffers a
    /// copy of the canonical payload of every leaf it hashes, so the second
    /// fold serialized the whole history again: measured by walking the
    /// persisted frames, that leaf is 85,429,663 bytes on a converted VS Code
    /// tree and 410,546,852 bytes on a converted Linux subtree.
    ///
    /// The controls are the half that must not move. Recomputation is what
    /// proves a snapshot READ from disk agrees with the envelope beside it, so
    /// this test asserts the recomputation is still wired AND still bites. A
    /// change that bought the commit's fold by making the check unreachable, or
    /// reachable but toothless, fails here.
    ///
    /// The controls deliberately do NOT assert that a reopen folds. Measured on
    /// CI while writing this: a reopen of a store carrying a valid durable
    /// history-validation record folds ZERO bundles, because that record is the
    /// validator's own verdict on those exact bytes and the open trusts it
    /// rather than re-deriving it (FIR-3064, PR 265). So the recomputation's
    /// live callers are the paths with no such record to trust, which is
    /// exactly when the bytes cannot be taken on trust, and those are what the
    /// controls below exercise.
    #[test]
    fn a_commit_folds_its_root_bundle_once_and_the_recomputation_still_bites() {
        let directory = TempDir::new().unwrap();
        let backend = Arc::new(LocalFileBackend::new(directory.path()));
        let manager =
            RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
        let transaction = arbitrary_repository_transaction(&manager);

        let before_commit = root_folds_on_this_thread();
        manager
            .commit_repository_transaction(transaction)
            .expect("the fixture commits");
        let commit_folds = root_folds_on_this_thread() - before_commit;
        assert_eq!(
            commit_folds, 1,
            "a commit folds the root bundle once; this one folded it {commit_folds} times"
        );
        assert_eq!(
            manager.read_authority().roots().generation,
            1,
            "the control: the store this graded is the one the commit produced"
        );

        let committed = load_recovered_repository_authority(
            &LocalFileBackend::new(directory.path()),
            repository_id().as_str(),
            HISTORY_VALIDATION_VERSION,
        )
        .unwrap()
        .expect("the committed store recovers")
        .recovered
        .snapshot;
        let envelope = committed
            .repository_authority
            .clone()
            .expect("a committed store carries its envelope");

        // Control one: the recomputation is still reachable and still runs.
        let before_check = root_folds_on_this_thread();
        envelope
            .validate_against_snapshot(&committed)
            .expect("a committed store validates against its own envelope");
        let check_folds = root_folds_on_this_thread() - before_check;
        assert_eq!(
            check_folds, 1,
            "the control: validating a snapshot against its envelope still folds the bundle, and \
             this folded {check_folds}"
        );

        // Control two: and it still refuses a bundle that does not derive from
        // the contents. A check that runs and cannot fail is not a check.
        //
        // The tamper has to leave the envelope INTERNALLY consistent or an
        // earlier check catches it and this control grades that check instead.
        // Moving `roots.history` alone was refused with "repository root bundle
        // does not match the last operation", which is the operation-record
        // match three checks upstream. So the wrong root goes everywhere the
        // envelope repeats it, and then the only thing left that can notice is
        // folding the contents again.
        assert_eq!(
            envelope.operation_log.len(),
            1,
            "the tamper below rewrites every roots_after, which only preserves the root chain \
             while the log holds one operation"
        );
        let mut tampered = envelope.clone();
        let wrong = AuthorityRoot::new(
            REPOSITORY_ROOT_SCHEMA_VERSION,
            Hash256::from_bytes([0xAB; 32]),
        );
        tampered.roots.history = wrong;
        for operation in &mut tampered.operation_log {
            operation.roots_after.history = wrong;
        }
        for receipt in &mut tampered.receipts {
            receipt.roots_after.history = wrong;
        }
        let refusal = tampered
            .validate_against_snapshot(&committed)
            .expect_err("a tampered root bundle must be refused");
        assert!(
            refusal.to_string().contains("does not recompute"),
            "the control: the refusal must be the root recomputation's own, got {refusal}"
        );
    }

    #[test]
    fn an_open_with_a_verified_record_leaves_the_change_map_on_disk() {
        let directory = TempDir::new().unwrap();
        drop(committed_local_repository(&directory));
        // What an eager walk of this store verifies, read before the open
        // under test so the comparison does not depend on it.
        let eager = load_recovered_repository_authority(
            &LocalFileBackend::new(directory.path()),
            repository_id().as_str(),
            HISTORY_VALIDATION_VERSION,
        )
        .unwrap()
        .expect("the committed store recovers")
        .recovered
        .snapshot;
        let eager_bodies: BTreeMap<Hash256, Option<u64>> =
            collect_all_authority_body_requirements(&eager)
                .unwrap()
                .into_iter()
                .map(|(digest, requirement)| (digest, requirement.expected_len))
                .collect();
        assert!(
            !eager_bodies.is_empty(),
            "the control: the fixture commits bodies"
        );

        let decodes_before = decoded_on_this_thread();
        let reopened = reopen(&directory);
        assert!(reopened.opened_by_history_validation());
        let lease = reopened.read_authority();
        let snapshot = lease.snapshot();
        assert!(
            !snapshot.changes.is_decoded(),
            "an open with a verified record must leave the change map on disk"
        );
        assert_eq!(
            snapshot.changes.len(),
            1,
            "the length is read from the map header"
        );
        assert_eq!(
            decoded_on_this_thread(),
            decodes_before,
            "nothing on the open path decoded the change map"
        );
        let swept = LAST_BODY_SWEEP_REQUIREMENTS.with(|last| last.borrow().clone());
        assert_eq!(
            swept, eager_bodies,
            "the streamed open verifies exactly the bodies an eager walk verifies"
        );
        let mut eager_gitlinks = BTreeSet::new();
        extend_authenticated_gitlinks(&mut eager_gitlinks, eager.changes.values());
        assert_eq!(*lease.authenticated_gitlinks, eager_gitlinks);
    }

    #[test]
    fn the_first_history_read_after_a_lazy_open_decodes_the_map_the_eager_open_holds() {
        let directory = TempDir::new().unwrap();
        drop(committed_local_repository(&directory));
        let eager = load_recovered_repository_authority(
            &LocalFileBackend::new(directory.path()),
            repository_id().as_str(),
            HISTORY_VALIDATION_VERSION,
        )
        .unwrap()
        .expect("the committed store recovers")
        .recovered
        .snapshot;
        assert!(
            eager.changes.is_decoded(),
            "the control: the eager entry point decodes"
        );

        let reopened = reopen(&directory);
        let lease = reopened.read_authority();
        assert!(!lease.snapshot().changes.is_decoded());
        let decodes_before = decoded_on_this_thread();
        assert_eq!(lease.snapshot().changes, eager.changes);
        assert!(lease.snapshot().changes.is_decoded());
        assert_eq!(decoded_on_this_thread(), decodes_before + 1);
        // A second read costs nothing further.
        assert_eq!(lease.snapshot().changes.len(), 1);
        assert_eq!(decoded_on_this_thread(), decodes_before + 1);
    }

    /// A committed store whose history carries one entity.
    ///
    /// [`committed_local_repository`] commits files and no entities, so the
    /// graph resolved at its base has no entity revisions and a graph build
    /// over it DERIVES them across the whole history, which reads the change
    /// map by definition. A daemon's store is not that shape: its materialized
    /// section carries the revisions, so the derivation is skipped. Every
    /// assertion about what a build reads needs this shape or it grades the
    /// derivation instead of the code under test.
    fn committed_local_repository_with_an_entity(directory: &TempDir) {
        let backend = Arc::new(LocalFileBackend::new(directory.path()));
        let manager = RepositoryAuthorityManager::open(repository_id(), backend).unwrap();
        let mut transaction = arbitrary_repository_transaction(&manager);
        let entity = Entity {
            id: EntityId::from_content("src/lib.rs", "kin", "function", 1),
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
        change.id = compute_semantic_change_id(change).unwrap();
        let change_id = change.id;
        transaction.ref_mutations[0].new_target = Some(RefTarget::change(change_id));
        let workspace_mutation = transaction.workspace_mutation.as_mut().unwrap();
        workspace_mutation.new_base_target = Some(RefTarget::change(change_id));
        workspace_mutation.semantic_delta =
            WorkspaceSemanticDelta::new(vec![EntityDelta::Added { new: entity }], Vec::new())
                .unwrap();
        manager
            .commit_repository_transaction(transaction)
            .expect("the fixture transaction commits");
    }

    /// Give the fixture store the shape a daemon's store has.
    ///
    /// A base folded from history reads the change map by definition, so a
    /// fixture with no materialized graph section cannot grade any of the
    /// assertions below: they would be red for a reason that has nothing to do
    /// with the code under test.
    fn persist_a_materialized_graph_section(directory: &TempDir) {
        let seeding = reopen(directory);
        let workspace_id = seeding.read_authority().metadata().workspaces[0].workspace_id;
        let outcome = seeding
            .materialize_workspace_base_graph_section(&repository_id(), &workspace_id)
            .unwrap()
            .expect("the fixture workspace exists");
        let MaterializedGraphSectionOutcome::Persisted { .. } = outcome else {
            panic!("the first explicit materialization must persist a section")
        };
    }

    /// A base resolved from a proven open, with its history still on disk.
    fn on_disk_history_base(
        lease: &AuthorityReadLease<RepositoryAuthorityState>,
    ) -> crate::storage::format::GraphSnapshot {
        let workspace_id = lease.metadata().workspaces[0].workspace_id;
        let base = lease
            .workspace_graph_snapshot(&workspace_id)
            .expect("the workspace base resolves")
            .expect("the fixture workspace exists");
        assert!(
            !base.changes.is_decoded(),
            "the control: this base carries its history on disk"
        );
        assert_eq!(
            base.changes.len(),
            1,
            "the control: there is a history here to decode"
        );
        assert!(
            !base.entity_revisions.is_empty(),
            "the control: this base carries its own entity revisions, so a \
             graph build over it does not derive them across the history, \
             which would read the map whatever this code does"
        );
        base
    }

    /// The currency digest no longer reads the history at all.
    ///
    /// It used to fold the whole change map in, which decoded a map the open
    /// had left on disk. Two things are asserted over a real store's base: the
    /// digest does not depend on whether the history is resident, and taking it
    /// does not decode a history that is not.
    #[test]
    fn taking_the_currency_digest_does_not_read_the_history() {
        let directory = TempDir::new().unwrap();
        committed_local_repository_with_an_entity(&directory);
        persist_a_materialized_graph_section(&directory);

        let reopened = reopen(&directory);
        let lease = reopened.read_authority();
        let mut base = on_disk_history_base(&lease);

        let decodes_before = decoded_on_this_thread();
        let from_disk = crate::storage::merkle::compute_retrieval_authority_hash(&base);
        assert_eq!(
            decoded_on_this_thread(),
            decodes_before,
            "taking the currency digest must not read the history at all"
        );
        assert!(!base.changes.is_decoded(), "and it must not have kept one");

        // Decode it deliberately, and take the same digest over the same map in
        // memory. Byte equality between the two is the whole claim.
        base.changes = base.changes.clone().into_inner().into();
        assert!(
            base.changes.is_decoded(),
            "the control: this arm is the in-memory one"
        );
        let from_memory = crate::storage::merkle::compute_retrieval_authority_hash(&base);
        assert_eq!(
            from_disk, from_memory,
            "the digest must not depend on whether the history was resident"
        );
    }

    /// The other half of the same property. The base keeps its history on disk
    /// only until something folds it in, and a graph build does exactly that,
    /// so without this the saving above would be handed straight back one call
    /// later, which is how it was found in the first place.
    #[test]
    fn a_graph_built_over_an_on_disk_history_leaves_it_on_disk() {
        let directory = TempDir::new().unwrap();
        committed_local_repository_with_an_entity(&directory);
        persist_a_materialized_graph_section(&directory);

        let reopened = reopen(&directory);
        let lease = reopened.read_authority();
        let base = on_disk_history_base(&lease);
        let changes = base.changes.len();

        let graph = crate::engine::InMemoryGraph::from_snapshot_without_text_index(base)
            .expect("the served graph builds");

        assert!(
            !graph.history_is_decoded(),
            "a graph built over an on-disk history must leave it on disk"
        );
        assert_eq!(
            graph.history_len(),
            changes,
            "the control: the graph still holds that history, counted from the \
             map header rather than by decoding it"
        );
        assert!(
            !lease.snapshot().changes.is_decoded(),
            "and the authority's own map is untouched by the build"
        );
    }

    /// The guard for the term this change removes.
    ///
    /// Resolving a workspace base used to re-run the change-map admission pass
    /// over a clone of the authority's map, which decoded the history the open
    /// had just left on disk and held it for the life of the process. Measured
    /// on a full VS Code store, that decode was 1,418,929,338 bytes, 41.1
    /// percent of the served workspace snapshot, against a store whose whole
    /// history is one change.
    ///
    /// The assertion is the decode counter rather than a size, because the
    /// counter fails on the first byte and a size threshold has to be tuned to
    /// the fixture.
    #[test]
    fn a_workspace_base_does_not_decode_the_history_the_open_left_on_disk() {
        let directory = TempDir::new().unwrap();
        drop(committed_local_repository(&directory));

        persist_a_materialized_graph_section(&directory);

        let reopened = reopen(&directory);
        assert!(
            reopened.opened_by_history_validation(),
            "the control: only a proven open leaves the map on disk, so an \
             unproven one would make every assertion below vacuous"
        );
        let lease = reopened.read_authority();
        assert!(
            lease.snapshot().materialized_graph.is_some(),
            "the control: the base below is served from a section"
        );
        assert!(
            !lease.snapshot().changes.is_decoded(),
            "the control: the open left the change map on disk"
        );
        assert_eq!(
            lease.snapshot().changes.len(),
            1,
            "the control: there is a history here to decode"
        );

        let workspace_id = lease.metadata().workspaces[0].workspace_id;
        let decodes_before = decoded_on_this_thread();
        let resolutions_before = WORKSPACE_BASE_RESOLUTIONS.with(|count| count.get());
        let served_before = BASE_GRAPHS_SERVED_FROM_SECTION.with(|count| count.get());
        let base = lease
            .workspace_graph_snapshot(&workspace_id)
            .expect("the workspace base resolves")
            .expect("the fixture workspace exists");

        assert_eq!(
            WORKSPACE_BASE_RESOLUTIONS.with(|count| count.get()),
            resolutions_before + 1,
            "the control: a base was actually resolved rather than served from \
             a prepared artifact, so the assertions below grade this code"
        );
        assert_eq!(
            BASE_GRAPHS_SERVED_FROM_SECTION.with(|count| count.get()),
            served_before + 1,
            "the control: it was served from the section rather than folded \
             from history, which is the shape a daemon's open has"
        );
        assert_eq!(
            decoded_on_this_thread(),
            decodes_before,
            "resolving a workspace base must not decode the history the open \
             left on disk"
        );
        assert!(
            !base.changes.is_decoded(),
            "the base carries the authority's encoded map, not a decode of it"
        );
        assert_eq!(
            base.changes.len(),
            1,
            "and it is the same history, read from the map header"
        );
        assert!(
            !lease.snapshot().changes.is_decoded(),
            "the authority's own map is untouched by the resolution"
        );
    }

    /// The other side of the same rule: a base whose history is in memory takes
    /// the ordinary pass. Without this, the change above could have been a
    /// blanket skip that never validates a change map again.
    #[test]
    fn a_workspace_base_over_a_decoded_history_still_takes_the_admission_pass() {
        let directory = TempDir::new().unwrap();
        drop(committed_local_repository(&directory));
        let mut record = read_authority_json(directory.path());
        record
            .as_object_mut()
            .unwrap()
            .remove("history_validation")
            .expect("the committed record carried a validation to remove");
        write_authority_json(directory.path(), &record);

        let reopened = reopen(&directory);
        assert!(
            !reopened.opened_by_history_validation(),
            "the control: this open has no record to trust"
        );
        let lease = reopened.read_authority();
        assert!(
            lease.snapshot().changes.is_decoded(),
            "the control: an unproven open holds its history in memory"
        );
        let workspace_id = lease.metadata().workspaces[0].workspace_id;
        let base = lease
            .workspace_graph_snapshot(&workspace_id)
            .expect("the workspace base resolves")
            .expect("the fixture workspace exists");
        assert!(
            AdmittedChangeMap::on_disk(&base.changes).is_none(),
            "a decoded map is not witnessable on disk, so this base took the \
             ordinary admission pass"
        );
    }

    #[test]
    fn an_open_without_a_verified_record_decodes_eagerly_and_validates_in_full() {
        let directory = TempDir::new().unwrap();
        drop(committed_local_repository(&directory));
        let mut record = read_authority_json(directory.path());
        record
            .as_object_mut()
            .unwrap()
            .remove("history_validation")
            .expect("the committed record carried a validation to remove");
        write_authority_json(directory.path(), &record);

        let reopened = reopen(&directory);
        assert!(!reopened.opened_by_history_validation());
        assert!(
            reopened.read_authority().snapshot().changes.is_decoded(),
            "with no record to trust, the open validates the whole history and holds it"
        );
    }

    #[test]
    fn a_lazy_change_map_outlives_the_snapshot_file_it_came_from() {
        let directory = TempDir::new().unwrap();
        drop(committed_local_repository(&directory));
        let generation_one = snapshot_file(&directory, 1);
        assert!(
            generation_one.exists(),
            "the control: generation one is on disk"
        );

        let reopened = reopen(&directory);
        let held = reopened.read_authority().snapshot().changes.clone();
        assert!(!held.is_decoded(), "the clone shares the encoded source");
        let workspace_id = reopened.read_authority().metadata().workspaces[0].workspace_id;
        // A representation rewrite persists a new generation ...
        let outcome = reopened
            .materialize_workspace_base_graph_section(&repository_id(), &workspace_id)
            .unwrap()
            .expect("the fixture workspace exists");
        let MaterializedGraphSectionOutcome::Persisted { .. } = outcome else {
            panic!("the first explicit materialization must persist a new generation")
        };
        drop(reopened);
        // ... and the next open retires the superseded file by name.
        let again = reopen(&directory);
        assert!(
            !generation_one.exists(),
            "the control: the superseded snapshot file was retired"
        );
        assert!(snapshot_file(&directory, 2).exists());

        // The map held from before the rewrite still reads, through the handle
        // the open kept, and reads the same history the new generation carries.
        let decoded = held
            .decoded()
            .expect("a retired file stays readable through its handle");
        assert_eq!(decoded.len(), 1);
        assert_eq!(*decoded, *again.read_authority().snapshot().changes);
    }

    #[test]
    fn a_snapshot_file_changed_underneath_an_open_refuses_at_the_first_history_read() {
        let directory = TempDir::new().unwrap();
        drop(committed_local_repository(&directory));
        let reopened = reopen(&directory);
        let lease = reopened.read_authority();
        assert!(!lease.snapshot().changes.is_decoded());

        let path = snapshot_file(&directory, 1);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[40] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();

        let error = lease
            .snapshot()
            .changes
            .decoded()
            .expect_err("bytes that changed since the open refuse");
        assert!(
            error
                .to_string()
                .contains("could not be decoded on first use"),
            "{error}"
        );
        assert!(!lease.snapshot().changes.is_decoded());
    }

    #[test]
    fn the_history_sweep_collects_what_the_two_walks_it_replaces_collect() {
        let blob = b"fn main() {}\n";
        let change = {
            let mut change = kin_model::SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
                origin: ChangeOrigin::GitCommit {
                    oid: GitObjectId::sha1([7; 20]),
                },
                parents: Vec::new(),
                timestamp: Timestamp(
                    chrono::DateTime::parse_from_rfc3339("2026-09-01T12:00:00Z")
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                ),
                author: AuthorId::new("sweep"),
                message: "a blob and a gitlink".to_string(),
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![
                    TreeDelta::Added {
                        artifact_id: ArtifactId(Uuid::from_u128(31)),
                        new: LocatedEntry::new(
                            RepoPath::from_bytes(b"src/main.rs".to_vec()).unwrap(),
                            TreeEntry::blob(digest(blob), false),
                        ),
                    },
                    TreeDelta::Added {
                        artifact_id: ArtifactId(Uuid::from_u128(32)),
                        new: LocatedEntry::new(
                            RepoPath::from_bytes(b"vendor/dep".to_vec()).unwrap(),
                            TreeEntry::Gitlink {
                                target: GitObjectId::sha1([9; 20]),
                            },
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
            change.id = compute_semantic_change_id(&change).unwrap();
            change
        };

        let mut sweep = HistorySweep::default();
        sweep.visit(&change).unwrap();
        assert_eq!(sweep.changes_seen, 1);

        let mut eager_bodies = BTreeMap::new();
        collect_tree_delta_body_requirements(
            &mut eager_bodies,
            &change.tree_deltas,
            &format!("change {}", change.id),
        )
        .unwrap();
        assert!(
            !eager_bodies.is_empty(),
            "the control: the blob is a body requirement"
        );
        assert_eq!(sweep.body_requirements, eager_bodies);

        let mut eager_gitlinks = BTreeSet::new();
        extend_authenticated_gitlinks(&mut eager_gitlinks, std::iter::once(&change));
        assert!(
            !eager_gitlinks.is_empty(),
            "the control: the Git-origin change carries a Gitlink"
        );
        assert_eq!(sweep.authenticated_gitlinks, eager_gitlinks);
    }
}

/// FIR-2334 attribution harness.
///
/// Runs the two dominant successor-preparation phases against a real
/// on-disk repository authority and prints the per-function breakdown. It is
/// ignored by default and needs `KIN_FIR2334_STORE` naming a `kindb`
/// directory, so the default suite never opens a multi-gigabyte store.
#[cfg(test)]
mod fir2334_attribution {
    use super::*;

    fn print_phase_log(label: &str) {
        PREPARATION_PHASE_LOG.with(|log| {
            for (name, laps) in log.borrow().iter() {
                let total: u128 = laps.iter().map(|(_, ms)| *ms).sum();
                let detail = laps
                    .iter()
                    .map(|(field, ms)| format!("{field}={ms}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                println!("[{label}] {name} total_ms={total} {detail}");
            }
            log.borrow_mut().clear();
        });
    }

    /// Before and after, on one real store, in one process.
    ///
    /// The store is NOT rewritten. A section is built in memory from the same
    /// `resolve_graph_at` a publish would capture, and the second arm resolves
    /// against that. Rewriting the snapshot file to carry a section would
    /// invalidate the durable validation record, which binds the snapshot's
    /// sha256, and the next open would replay the whole history: the after arm
    /// would then measure a store whose fast path is gone and present as a
    /// regression this change did not cause.
    ///
    /// Both arms resolve the same workspace base at the same change through the
    /// same function, so the only difference between them is whether a section
    /// is present.
    #[test]
    #[ignore = "needs KIN_FIR2334_STORE naming a real kindb directory"]
    fn measure_a_base_resolution_with_and_without_a_section() {
        let store = std::env::var("KIN_FIR2334_STORE")
            .expect("set KIN_FIR2334_STORE to a <repo>/.kin/kindb directory");
        let repo = std::env::var("KIN_FIR2334_REPO")
            .expect("set KIN_FIR2334_REPO to the repository id under that directory");
        let repository_id = RepositoryId::new(&repo).expect("repository id");
        let backend = Arc::new(crate::storage::backend::LocalFileBackend::new(&store));
        let manager = RepositoryAuthorityManager::open(repository_id, backend)
            .expect("open repository authority");
        let lease = manager.read_authority();
        let metadata = lease.metadata().clone();
        let workspace = metadata.workspaces[0].clone();
        let mut snapshot = lease.snapshot().clone();
        drop(lease);

        let change_id = target_change_id(
            &metadata,
            workspace
                .base_target
                .as_ref()
                .expect("the workspace bases at a change"),
        )
        .expect("the base target names a change");

        println!(
            "[subject] changes={} section_present={}",
            snapshot.changes.len(),
            snapshot.materialized_graph.is_some()
        );

        // BEFORE: no section, so the base is folded out of history.
        snapshot.materialized_graph = None;
        PREPARATION_PHASE_LOG.with(|log| log.borrow_mut().clear());
        let started = std::time::Instant::now();
        let folded = resolve_workspace_base_graph_snapshot(
            &snapshot,
            &metadata,
            workspace.base_target.as_ref(),
            WorkspaceBaseHistory::Omitted,
        )
        .expect("fold the base");
        println!("[TERM] before_resolve_ms={}", started.elapsed().as_millis());
        print_phase_log("before");

        // The section a publish would have written, from the same call.
        let state = AuthorityHistoryView {
            changes: &snapshot.changes,
        }
        .resolve_graph_at(&change_id)
        .expect("resolve the head");
        let section = CapturedBaseGraph::capture(change_id, state).into_section();
        // What the section costs, in the units the memory guards price in. The
        // publish path holds this beside the base it was captured from, so this
        // is the peak a capture adds.
        let enc = |label: &str, bytes: usize, count: usize| {
            println!("[cost] {label} bytes={bytes} count={count}");
        };
        enc(
            "whole_section",
            rmp_serde::to_vec(&section).expect("encodes").len(),
            1,
        );
        enc(
            "entities",
            rmp_serde::to_vec(&section.state.entities)
                .expect("encodes")
                .len(),
            section.state.entities.len(),
        );
        enc(
            "relations",
            rmp_serde::to_vec(&section.state.relations)
                .expect("encodes")
                .len(),
            section.state.relations.len(),
        );
        enc(
            "entity_revisions",
            rmp_serde::to_vec(&section.state.entity_revisions)
                .expect("encodes")
                .len(),
            section.state.entity_revisions.len(),
        );
        enc(
            "entity_tombstones",
            rmp_serde::to_vec(&section.state.entity_tombstones)
                .expect("encodes")
                .len(),
            section.state.entity_tombstones.len(),
        );
        enc(
            "relation_tombstones",
            rmp_serde::to_vec(&section.state.relation_tombstones)
                .expect("encodes")
                .len(),
            section.state.relation_tombstones.len(),
        );
        enc(
            "tree",
            rmp_serde::to_vec(&section.state.tree)
                .expect("encodes")
                .len(),
            0,
        );
        enc(
            "external_references",
            rmp_serde::to_vec(&section.state.external_references)
                .expect("encodes")
                .len(),
            section.state.external_references.len(),
        );
        snapshot.materialized_graph = Some(Arc::new(section));

        // AFTER: the same resolution, served.
        PREPARATION_PHASE_LOG.with(|log| log.borrow_mut().clear());
        let started = std::time::Instant::now();
        let served = resolve_workspace_base_graph_snapshot(
            &snapshot,
            &metadata,
            workspace.base_target.as_ref(),
            WorkspaceBaseHistory::Omitted,
        )
        .expect("serve the base");
        println!("[TERM] after_resolve_ms={}", started.elapsed().as_millis());
        print_phase_log("after");

        // The measurement is worth nothing if the two answers differ, so this
        // is asserted rather than reported.
        assert_eq!(folded.entities, served.entities, "entities");
        assert_eq!(folded.relations, served.relations, "relations");
        assert_eq!(folded.resolved_tree, served.resolved_tree, "resolved_tree");
        assert_eq!(
            folded.entity_revisions, served.entity_revisions,
            "entity_revisions"
        );
        println!(
            "[equal] entities={} relations={}",
            served.entities.len(),
            served.relations.len()
        );

        // THE THIRD ARM. `entity_revisions` is 94 percent of a section's bytes,
        // so the obvious narrowing is to leave it out. What that costs is not
        // obvious: on the read path the base carries the change map, and
        // `InMemoryGraph::from_snapshot` re-derives the revision timeline when
        // it arrives empty and changes do not, which this crate calls the
        // largest thing a conversion's workspace lap does. So the saving may be
        // handed straight back here, and this arm is the only way to know.
        //
        // The base is resolved CARRYING the history, because that is the shape
        // the read path uses and the shape in which the re-derivation can fire
        // at all.
        let carried = resolve_workspace_base_graph_snapshot(
            &snapshot,
            &metadata,
            workspace.base_target.as_ref(),
            WorkspaceBaseHistory::Carried(None),
        )
        .expect("resolve carrying the history");
        println!(
            "[carried] changes={} revisions={}",
            carried.changes.len(),
            carried.entity_revisions.len()
        );

        let mut without_revisions = carried.clone();
        without_revisions.entity_revisions.clear();

        let started = std::time::Instant::now();
        let with_graph = InMemoryGraph::from_snapshot_without_text_index(carried)
            .expect("build over a base that carries its revisions");
        println!(
            "[TERM] graph_build_with_revisions_ms={}",
            started.elapsed().as_millis()
        );

        let started = std::time::Instant::now();
        let without_graph = InMemoryGraph::from_snapshot_without_text_index(without_revisions)
            .expect("build over a base whose revisions were left out");
        println!(
            "[TERM] graph_build_without_revisions_ms={}",
            started.elapsed().as_millis()
        );
        // READ THESE TWO NUMBERS ACROSS ARMS BEFORE SUBTRACTING THEM.
        //
        // Measured 2026-08-30 on the converted psf/requests store: the deltas
        // over three arms were 36, 1,373 and 1,185 ms, while the spread of the
        // `with` measurement ALONE across the same three arms was 1,397 ms. The
        // noise is larger than the signal, so this difference is not resolvable
        // at this precision, and a single arm reported 4,102 ms, outside even
        // that range. One reading of it was published as a finding and had to be
        // retracted.
        //
        // The line below is the one that repeats: it read 4,693 against 5,979
        // and `false` in every arm, character for character, because it is not a
        // timing.

        // And the correctness half: a re-derived timeline has to be the one the
        // section would have carried, or the narrowing is not a trade, it is a
        // different answer.
        let with_snapshot = with_graph.to_snapshot();
        let without_snapshot = without_graph.to_snapshot();
        println!(
            "[revisions] carried={} rederived={} equal={}",
            with_snapshot.entity_revisions.len(),
            without_snapshot.entity_revisions.len(),
            with_snapshot.entity_revisions == without_snapshot.entity_revisions
        );
    }

    #[test]
    #[ignore = "needs KIN_FIR2334_STORE naming a real kindb directory"]
    fn attribute_one_successor_preparation() {
        let store = std::env::var("KIN_FIR2334_STORE")
            .expect("set KIN_FIR2334_STORE to a <repo>/.kin/kindb directory");
        let repo = std::env::var("KIN_FIR2334_REPO")
            .expect("set KIN_FIR2334_REPO to the repository id under that directory");
        let repository_id = RepositoryId::new(&repo).expect("repository id");
        let backend = Arc::new(crate::storage::backend::LocalFileBackend::new(&store));

        let open_started = std::time::Instant::now();
        let manager = RepositoryAuthorityManager::open(repository_id.clone(), backend)
            .expect("open repository authority");
        println!(
            "[open] authority_open_ms={}",
            open_started.elapsed().as_millis()
        );

        let lease = manager.read_authority();
        let snapshot = lease.snapshot();
        let metadata = lease.metadata();
        println!(
            "[store] changes={} entities={} relations={} shallow_files={} artifacts={} workspaces={} operations={} receipts={}",
            snapshot.changes.len(),
            snapshot.entities.len(),
            snapshot.relations.len(),
            snapshot.shallow_files.len(),
            snapshot.resolved_tree.artifacts().count(),
            metadata.workspaces.len(),
            metadata.operation_log.len(),
            metadata.receipts.len(),
        );
        PREPARATION_PHASE_LOG.with(|log| log.borrow_mut().clear());

        let started = std::time::Instant::now();
        snapshot
            .validate_storage_admission_with(GitProjectionTreeReplay::Proven)
            .expect("top-level storage admission");
        println!(
            "[TERM] storage_admission_ms={}",
            started.elapsed().as_millis()
        );
        print_phase_log("storage_admission");

        let Some(workspace) = metadata.workspaces.first().cloned() else {
            println!("[TERM] workspace_ms=0 (no workspace on this authority)");
            return;
        };

        let started = std::time::Instant::now();
        let base = resolve_workspace_base_graph_snapshot(
            snapshot,
            metadata,
            workspace.base_target.as_ref(),
            WorkspaceBaseHistory::Carried(None),
        )
        .expect("resolve workspace base");
        println!(
            "[TERM] resolve_workspace_base_ms={}",
            started.elapsed().as_millis()
        );
        println!(
            "[base] changes={} entities={} relations={} artifacts={}",
            base.changes.len(),
            base.entities.len(),
            base.relations.len(),
            base.resolved_tree.artifacts().count(),
        );
        print_phase_log("resolve_base");

        let started = std::time::Instant::now();
        let materialized =
            materialize_workspace_graph_snapshot_from_base(base.clone(), &workspace, None)
                .expect("materialize workspace graph");
        println!(
            "[TERM] materialize_workspace_ms={}",
            started.elapsed().as_millis()
        );
        println!(
            "[materialized] changes={} entities={} relations={} artifacts={}",
            materialized.changes.len(),
            materialized.entities.len(),
            materialized.relations.len(),
            materialized.resolved_tree.artifacts().count(),
        );
        print_phase_log("materialize");

        let started = std::time::Instant::now();
        let materialized_facts = WorkspaceGraphFacts::from_snapshot(materialized.clone());
        let overlay =
            derive_workspace_semantic_overlay(&base, &materialized_facts).expect("derive overlay");
        println!(
            "[TERM] derive_overlay_ms={} entity_deltas={} relation_deltas={}",
            started.elapsed().as_millis(),
            overlay.entity_deltas().len(),
            overlay.relation_deltas().len(),
        );

        let started = std::time::Instant::now();
        let graph = InMemoryGraph::from_snapshot_without_text_index(materialized.clone())
            .expect("build in-memory graph");
        println!(
            "[TERM] in_memory_graph_build_ms={}",
            started.elapsed().as_millis()
        );
        let started = std::time::Instant::now();
        let round_tripped = graph.to_snapshot();
        println!("[TERM] to_snapshot_ms={}", started.elapsed().as_millis());
        assert_eq!(round_tripped.entities.len(), materialized.entities.len());

        let started = std::time::Instant::now();
        let mut adjacency = materialized.clone();
        rebuild_snapshot_adjacency(&mut adjacency);
        println!(
            "[TERM] rebuild_adjacency_ms={}",
            started.elapsed().as_millis()
        );
    }
}

/// Step-13 replay wall measurements.
///
/// A bootstrap commit carries the whole converted history in one transaction,
/// so every per-change body in `commit_repository_transaction` runs at history
/// scale rather than at delta scale. This measures the entry point's own
/// per-change bodies against transaction size, so the scaling law is visible
/// before anything is changed. Ignored by default because the larger sizes are
/// deliberately slow.
#[cfg(test)]
mod replaywall_measurements {
    use super::*;
    use kin_model::{
        compute_semantic_change_id, ChangeOrigin, LocatedEntry,
        REPOSITORY_TRANSACTION_SCHEMA_VERSION,
    };

    /// One synthetic native change carrying `files` tree deltas.
    ///
    /// A converted change is not empty: it carries the tree deltas for the
    /// files that commit touched, and those deltas are what every per-change
    /// body actually walks. Measuring with empty changes measures the floor.
    fn synthetic_change_with_payload(index: u128, files: usize) -> kin_model::SemanticChange {
        let tree_deltas: Vec<TreeDelta> = (0..files)
            .map(|file| {
                let artifact = (index + 1) * 1_000 + file as u128;
                TreeDelta::Added {
                    artifact_id: ArtifactId(uuid::Uuid::from_u128(artifact)),
                    new: LocatedEntry::new(
                        RepoPath::from_bytes(
                            format!("src/generated/module_{artifact}.rs").into_bytes(),
                        )
                        .expect("synthetic path is valid"),
                        TreeEntry::Blob {
                            hash: Hash256::from_bytes([(artifact % 251) as u8; 32]),
                            executable: false,
                        },
                    ),
                }
            })
            .collect();
        let mut change = synthetic_change(index);
        change.tree_deltas = tree_deltas;
        change.id = compute_semantic_change_id(&change).expect("change id computes");
        change
    }

    /// One synthetic native change, content-addressed like a real one.
    fn synthetic_change(index: u128) -> kin_model::SemanticChange {
        let mut change = kin_model::SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: Vec::new(),
            timestamp: Timestamp(
                chrono::DateTime::parse_from_rfc3339("2026-07-26T12:00:00Z")
                    .expect("fixed timestamp parses")
                    .with_timezone(&chrono::Utc),
            ),
            author: AuthorId::new("replaywall-measurement"),
            message: format!("synthetic bootstrap change {index}"),
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
        change.id = compute_semantic_change_id(&change).expect("change id computes");
        change
    }

    fn bootstrap_transaction_with_payload(changes: usize, files: usize) -> RepositoryTransaction {
        let mut transaction = bootstrap_transaction(0);
        transaction.changes = (0..changes as u128)
            .map(|index| synthetic_change_with_payload(index, files))
            .collect();
        transaction
    }

    fn bootstrap_transaction(changes: usize) -> RepositoryTransaction {
        RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::from_uuid(uuid::Uuid::from_u128(1)),
            repository_id: RepositoryId::new("replaywall-measurement").expect("repository id"),
            expected_generation: 0,
            expected_roots: placeholder_roots(0),
            actor: AuthorId::new("replaywall-measurement"),
            reason: "synthetic bootstrap".to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: (0..changes as u128).map(synthetic_change).collect(),
            aliases: Vec::new(),
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        }
    }

    #[test]
    #[ignore = "measurement: scales the commit entry point's per-change bodies"]
    fn entry_point_bodies_scale_with_transaction_size() {
        println!("changes  validate_ms  hash_ms  hash_minus_validate_ms");
        for size in [100usize, 400, 1600, 6400] {
            let transaction = bootstrap_transaction(size);

            // Warm any lazy allocation so the first timed call is not the outlier.
            transaction
                .validate()
                .expect("synthetic transaction validates");

            let started = std::time::Instant::now();
            transaction.validate().expect("validates");
            let validate_ms = started.elapsed().as_millis();

            let started = std::time::Instant::now();
            let _hash = transaction.transaction_hash().expect("hashes");
            let hash_ms = started.elapsed().as_millis();

            println!(
                "{size:>7}  {validate_ms:>11}  {hash_ms:>7}  {:>22}",
                hash_ms.saturating_sub(validate_ms)
            );
        }
    }

    /// An invalid transaction must refuse at the commit entry point with the
    /// same error surface whether the external `validate()` is present or not.
    ///
    /// This is the falsification for removing kin-db's external
    /// `transaction.validate()`, which sat one line above
    /// `transaction_hash()`, whose own contract opens with `self.validate()`.
    /// The internal check is deliberately kept, so the refusal has to survive
    /// the removal unchanged. Run before the cut and after it: the same error
    /// text either way means the external call was proving nothing the
    /// internal one did not already prove.
    #[test]
    fn an_invalid_transaction_still_refuses_at_the_commit_entry_point() {
        let directory = tempfile::tempdir().expect("tempdir");
        let backend = std::sync::Arc::new(crate::storage::backend::LocalFileBackend::new(
            directory.path(),
        ));
        let repository = RepositoryId::new("replaywall-refusal").expect("repository id");
        let manager = RepositoryAuthorityManager::open(repository.clone(), backend)
            .expect("open fresh authority");

        let mut transaction = bootstrap_transaction(1);
        transaction.repository_id = repository;
        transaction.schema_version = REPOSITORY_TRANSACTION_SCHEMA_VERSION + 1;

        let error = manager
            .commit_repository_transaction(transaction)
            .expect_err("an unsupported transaction schema must be refused");
        assert!(
            error
                .to_string()
                .contains("unsupported repository transaction version"),
            "the refusal must keep naming the unsupported schema version, got: {error}"
        );
    }

    /// Does the cost of ONE commit grow with how much history the store
    /// already holds?
    ///
    /// A conversion commits its history one change at a time. If a single
    /// commit's preparation walks the whole store, then converting N changes
    /// costs O(N^2) rather than O(N), and nothing in a per-call measurement
    /// would ever show it, because every individual call looks linear and
    /// cheap. This times each successive commit into the same store and prints
    /// the per-commit wall against the history already present, so the shape
    /// is read off the trend rather than assumed.
    #[test]
    #[ignore = "measurement: commits one change at a time and times each"]
    fn one_commit_cost_against_history_already_present() {
        let commits: usize = std::env::var("KIN_REPLAYWALL_COMMITS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(120);

        let directory = tempfile::tempdir().expect("tempdir");
        let backend = std::sync::Arc::new(crate::storage::backend::LocalFileBackend::new(
            directory.path(),
        ));
        let repository = RepositoryId::new("replaywall-growth").expect("repository id");
        let manager = RepositoryAuthorityManager::open(repository.clone(), backend)
            .expect("open fresh authority");

        println!("history_before  commit_ms  cumulative_ms");
        let mut parent: Option<SemanticChangeId> = None;
        let mut cumulative: u128 = 0;
        for index in 0..commits {
            // No tree deltas: a native change that introduces artifacts needs a
            // bound workspace admission context, and what this measures is
            // whether cost grows with HISTORY DEPTH, not with payload.
            let mut change = synthetic_change(index as u128);
            change.parents = parent.into_iter().collect();
            change.id = compute_semantic_change_id(&change).expect("change id computes");
            let change_id = change.id;

            let lease = manager.read_authority();
            let transaction = RepositoryTransaction {
                schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
                operation_id: OperationId::from_uuid(uuid::Uuid::from_u128(index as u128 + 1)),
                repository_id: repository.clone(),
                expected_generation: lease.generation(),
                expected_roots: lease.roots().clone(),
                actor: AuthorId::new("replaywall-growth"),
                reason: format!("synthetic commit {index}"),
                external_objects: Vec::new(),
                git_authority_delta: None,
                changes: vec![change],
                aliases: Vec::new(),
                ref_mutations: Vec::new(),
                default_ref_mutation: None,
                workspace_mutation: None,
                local_overlay_delta: None,
                merge_transaction_delta: None,
                sealed_observation: None,
            };
            drop(lease);

            let started = std::time::Instant::now();
            manager
                .commit_repository_transaction(transaction)
                .unwrap_or_else(|error| panic!("commit {index} failed: {error}"));
            let commit_ms = started.elapsed().as_millis();
            cumulative += commit_ms;
            if index % 10 == 0 || index + 1 == commits {
                println!("{index:>14}  {commit_ms:>9}  {cumulative:>13}");
            }
            parent = Some(change_id);
        }
        println!("total_ms={cumulative} for {commits} commits");
    }

    /// The same bodies against payload per change, which is what a converted
    /// change actually carries and what the empty-change run above excludes.
    #[test]
    #[ignore = "measurement: scales the commit entry point against payload per change"]
    fn entry_point_bodies_scale_with_payload_per_change() {
        println!("changes  files/chg  deltas  validate_ms  hash_ms  hash_minus_validate_ms");
        for (size, files) in [
            (1200usize, 1usize),
            (1200, 8),
            (1200, 32),
            (1200, 128),
            (6400, 8),
        ] {
            let transaction = bootstrap_transaction_with_payload(size, files);
            transaction
                .validate()
                .expect("synthetic transaction validates");

            let started = std::time::Instant::now();
            transaction.validate().expect("validates");
            let validate_ms = started.elapsed().as_millis();

            let started = std::time::Instant::now();
            let _hash = transaction.transaction_hash().expect("hashes");
            let hash_ms = started.elapsed().as_millis();

            println!(
                "{size:>7}  {files:>9}  {:>6}  {validate_ms:>11}  {hash_ms:>7}  {:>22}",
                size * files,
                hash_ms.saturating_sub(validate_ms)
            );
        }
    }
}

/// Step-13's own shape, priced by phase.
///
/// The 1200-commit growth loop prices the INCREMENTAL path, one transaction
/// per commit. Step 13 hands kin-db ONE transaction carrying the whole
/// history, so every per-change body inside a single `prepare_successor` runs
/// at history scale rather than at delta scale. This commits exactly that
/// shape into a fresh authority and prints the preparation's own phase laps,
/// so the candidates are priced against each other instead of by elimination.
///
/// Two arms, because the workspace half is the expensive half and the growth
/// loop had it switched off: one transaction with no `workspace_mutation`, and
/// one that binds a workspace to the history's head exactly as a conversion
/// does. Only the head change introduces artifacts, which is what the v3
/// Native admission contract permits.
#[cfg(test)]
mod clockhalf_whole_history {
    use super::*;
    use kin_model::{
        compute_resolved_tree_hash, compute_semantic_change_id, AdmissionCase,
        AdmissionPolicyDelta, ChangeOrigin, EffectiveAdmissionPolicyStamp, EntityDelta, EntityId,
        EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm,
        FrozenLocalOverlayDelta, LanguageId, LocatedEntry, SemanticFingerprint, Visibility,
        WorkspaceExpectation, WorkspaceMutation, WorkspaceSemanticDelta,
        REPOSITORY_TRANSACTION_SCHEMA_VERSION,
    };
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    fn digest(body: &[u8]) -> Hash256 {
        Hash256::from_bytes(Sha256::digest(body).into())
    }

    fn fixed_timestamp() -> Timestamp {
        Timestamp(
            chrono::DateTime::parse_from_rfc3339("2026-07-26T12:00:00Z")
                .expect("fixed timestamp parses")
                .with_timezone(&chrono::Utc),
        )
    }

    /// One distinct entity per commit, so the resolved graph grows with
    /// history the way a converted repository's does.
    fn measurement_entity(index: usize) -> kin_model::Entity {
        let path = format!("src/module_{index}.rs");
        let name = format!("kin_{index}");
        let byte = (index % 251) as u8;
        kin_model::Entity {
            id: EntityId::from_content(&path, &name, "function", 1),
            kind: EntityKind::Function,
            name: name.clone(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([byte; 32]),
                signature_hash: Hash256::from_bytes([byte.wrapping_add(1); 32]),
                behavior_hash: Hash256::from_bytes([byte.wrapping_add(2); 32]),
                equivalence_hash: Hash256::from_bytes([byte.wrapping_add(3); 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(&path)),
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

    /// The head tree a conversion publishes: `files` artifacts and their bodies.
    fn head_tree(files: usize) -> (Vec<TreeDelta>, Vec<(Hash256, Vec<u8>)>) {
        let mut deltas = Vec::with_capacity(files);
        let mut blobs = Vec::with_capacity(files);
        for file in 0..files {
            let path = format!("src/module_{file}.rs");
            let body = format!("pub fn kin_{file}() {{}}\n").into_bytes();
            let hash = digest(&body);
            deltas.push(TreeDelta::Added {
                artifact_id: ArtifactId(Uuid::from_u128(1_000_000 + file as u128)),
                new: LocatedEntry::new(
                    RepoPath::from_bytes(path.into_bytes()).expect("synthetic path is valid"),
                    TreeEntry::blob(hash, false),
                ),
            });
            blobs.push((hash, body));
        }
        (deltas, blobs)
    }

    /// `commits` chained Native changes, one entity each, head carrying `tree`.
    fn history_chain(
        commits: usize,
        shared: &SharedAdmissionPolicy,
        tree: &[TreeDelta],
        depth: HistoryDepth,
    ) -> Vec<kin_model::SemanticChange> {
        let mut chain: Vec<kin_model::SemanticChange> = Vec::with_capacity(commits);
        let mut parent: Option<SemanticChangeId> = None;
        for index in 0..commits {
            let mut change = kin_model::SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
                origin: ChangeOrigin::Native,
                parents: parent.into_iter().collect(),
                timestamp: fixed_timestamp(),
                author: AuthorId::new("clockhalf-measurement"),
                message: format!("synthetic converted commit {index}"),
                entity_deltas: vec![EntityDelta::Added {
                    new: measurement_entity(index),
                }],
                relation_deltas: Vec::new(),
                tree_deltas: if index + 1 == commits {
                    tree.to_vec()
                } else {
                    Vec::new()
                },
                admission_policy_delta: (index == 0)
                    .then(|| AdmissionPolicyDelta::initialize(shared.clone())),
                external_reference_deltas: Vec::new(),
                projected_files: Vec::new(),
                spec_link: None,
                evidence: Vec::new(),
                risk_summary: None,
            };
            change.id = compute_semantic_change_id(&change).expect("change id computes");
            // A flat forest keeps the change COUNT and drops the lineage DEPTH,
            // which is the only variable a per-change lineage walk can be
            // quadratic in. The head still chains to the change before it so
            // the workspace has a base whose tree the mutation can name.
            parent = match depth {
                HistoryDepth::Chain => Some(change.id),
                HistoryDepth::Flat if index + 2 == commits => Some(change.id),
                HistoryDepth::Flat => None,
            };
            chain.push(change);
        }
        chain
    }

    /// Whether the synthetic history is one chain or a flat forest.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum HistoryDepth {
        Chain,
        Flat,
    }

    /// Commit one whole-history bootstrap and print its phase laps.
    fn price_one_bootstrap(
        commits: usize,
        files: usize,
        with_workspace: bool,
        depth: HistoryDepth,
    ) {
        let directory = tempfile::tempdir().expect("tempdir");
        let backend = std::sync::Arc::new(crate::storage::backend::LocalFileBackend::new(
            directory.path(),
        ));
        let repository = RepositoryId::new("clockhalf-measurement").expect("repository id");
        let manager = RepositoryAuthorityManager::open(repository.clone(), backend)
            .expect("open fresh authority");

        let shared = SharedAdmissionPolicy::empty(0);
        let (tree_deltas, blobs) = if with_workspace {
            head_tree(files)
        } else {
            (Vec::new(), Vec::new())
        };
        for (hash, body) in &blobs {
            manager.save_source_blob(*hash, body).expect("save blob");
        }
        let changes = history_chain(commits, &shared, &tree_deltas, depth);
        let head_change = changes.last().expect("at least one change").id;

        let lease = manager.read_authority();
        let mut transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::from_uuid(Uuid::from_u128(1)),
            repository_id: repository.clone(),
            expected_generation: lease.generation(),
            expected_roots: lease.roots().clone(),
            actor: AuthorId::new("clockhalf-measurement"),
            reason: "synthetic whole-history bootstrap".to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes,
            aliases: Vec::new(),
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        drop(lease);

        if with_workspace {
            let tree = ResolvedTree::default()
                .apply(&tree_deltas)
                .expect("head tree applies");
            let tree_hash = compute_resolved_tree_hash(&tree).expect("tree hash");
            let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(20));
            let overlay =
                FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::Sensitive, Vec::new())
                    .expect("frozen overlay");
            let policy = EffectiveAdmissionPolicyStamp {
                shared: shared.stamp(),
                local: overlay.stamp(),
            };
            let main = RefName::branch(b"main").expect("branch name");
            let target = RefTarget::change(head_change);
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
            transaction.workspace_mutation = Some(WorkspaceMutation {
                workspace_id,
                expected: WorkspaceExpectation::MustNotExist,
                new_generation: 0,
                new_head: WorkspaceHead::Symbolic { target: main },
                new_base_target: Some(target),
                new_base_tree_hash: Some(tree_hash),
                tree_deltas,
                new_tree_hash: tree_hash,
                semantic_delta: WorkspaceSemanticDelta::default(),
                new_shared_admission_policy: shared,
                new_admission_policy: policy,
            });
            transaction.local_overlay_delta = Some(FrozenLocalOverlayDelta::initialize(overlay));
        }

        PREPARATION_PHASE_LOG.with(|log| log.borrow_mut().clear());
        let started = std::time::Instant::now();
        let receipt = manager
            .commit_repository_transaction(transaction)
            .unwrap_or_else(|error| {
                panic!("whole-history bootstrap of {commits} changes failed: {error}")
            });
        let commit_ms = started.elapsed().as_millis();
        assert_eq!(receipt.generation, 1);

        let arm = match (with_workspace, depth) {
            (true, HistoryDepth::Chain) => "with_workspace",
            (false, HistoryDepth::Chain) => "no_workspace",
            (true, HistoryDepth::Flat) => "with_workspace_flat",
            (false, HistoryDepth::Flat) => "no_workspace_flat",
        };
        println!("[{arm}] commits={commits} files={files} commit_ms={commit_ms}");
        PREPARATION_PHASE_LOG.with(|log| {
            for (name, laps) in log.borrow().iter() {
                let total: u128 = laps.iter().map(|(_, ms)| *ms).sum();
                let detail = laps
                    .iter()
                    .map(|(field, ms)| format!("{field}={ms}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                println!("[{arm}]   {name} sum_ms={total} {detail}");
            }
            log.borrow_mut().clear();
        });
    }

    /// Price one whole-history bootstrap preparation by phase, both arms.
    ///
    /// `KIN_CLOCKHALF_COMMITS` is a comma-separated size ladder so the growth
    /// law across sizes is read off the same run that attributes the phases.
    #[test]
    #[ignore = "measurement: commits a whole-history bootstrap and prints its phase laps"]
    fn whole_history_bootstrap_phase_costs() {
        let sizes: Vec<usize> = std::env::var("KIN_CLOCKHALF_COMMITS")
            .unwrap_or_else(|_| "150,300,600,1200".to_string())
            .split(',')
            .filter_map(|value| value.trim().parse().ok())
            .collect();
        let files: usize = std::env::var("KIN_CLOCKHALF_FILES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(200);
        let flat = std::env::var("KIN_CLOCKHALF_FLAT").is_ok_and(|value| value == "1");
        let depth = if flat {
            HistoryDepth::Flat
        } else {
            HistoryDepth::Chain
        };
        for commits in sizes {
            price_one_bootstrap(commits, files, false, depth);
            price_one_bootstrap(commits, files, true, depth);
        }
    }
}

/// Step 13's per-change bodies at Git origin, which is the origin a conversion
/// actually uses.
///
/// The bootstrap-transaction measurement beside this one cannot give every
/// change a tree delta: the v3 Native admission contract lets only the change
/// the successor workspace bases on introduce artifacts. A conversion's changes
/// are `ChangeOrigin::GitCommit`, which that rule does not reach, so every one
/// of them carries its own tree deltas. These bodies are callable directly
/// against a synthetic snapshot, with no transaction and no admission contract
/// in the way, so they can be priced at the payload a converted commit really
/// has.
#[cfg(test)]
mod clockhalf_git_origin {
    use super::*;
    use kin_model::{compute_semantic_change_id, ChangeOrigin, LocatedEntry};
    use uuid::Uuid;

    fn oid(seed: u64) -> GitObjectId {
        let mut bytes = [0_u8; 20];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        GitObjectId::sha1(bytes)
    }

    fn artifact(index: usize) -> ArtifactId {
        ArtifactId(Uuid::from_u128(index as u128 + 1))
    }

    fn path_of(index: usize) -> RepoPath {
        RepoPath::from_utf8(format!("src/file_{index}.rs")).expect("synthetic path is valid")
    }

    /// Two blob states per artifact, so the whole tree alternates between two
    /// shapes and the raw-tree fixture stays O(tree) instead of O(commits x
    /// tree). The replay still applies every delta of every commit.
    fn entry_of(index: usize, state: u8) -> TreeEntry {
        let mut bytes = [0_u8; 32];
        bytes[0] = state;
        bytes[1] = (index % 251) as u8;
        bytes[2] = ((index / 251) % 251) as u8;
        TreeEntry::blob(Hash256::from_bytes(bytes), false)
    }

    struct GitHistory {
        snapshot: GraphSnapshot,
        targets: BTreeMap<SemanticChangeId, GitProjectionTreeTarget>,
        raw_trees: BTreeMap<GitObjectId, BTreeMap<RepoPath, TreeEntry>>,
        order: Vec<SemanticChangeId>,
    }

    /// `commits` chained Git-origin changes over a `files`-artifact tree, where
    /// the root adds every artifact and each later commit updates `churn` of
    /// them.
    fn git_history(commits: usize, files: usize, churn: usize) -> GitHistory {
        let tree_a: BTreeMap<RepoPath, TreeEntry> = (0..files)
            .map(|index| (path_of(index), entry_of(index, 0)))
            .collect();
        let mut tree_b = tree_a.clone();
        for index in 0..churn.min(files) {
            tree_b.insert(path_of(index), entry_of(index, 1));
        }
        let oid_a = oid(900_001);
        let oid_b = oid(900_002);
        let mut raw_trees = BTreeMap::new();
        raw_trees.insert(oid_a, tree_a);
        raw_trees.insert(oid_b, tree_b);

        let mut snapshot = GraphSnapshot::empty();
        let mut targets = BTreeMap::new();
        let mut order = Vec::with_capacity(commits);
        let mut parent: Option<SemanticChangeId> = None;
        for index in 0..commits {
            let tree_deltas: Vec<TreeDelta> = if index == 0 {
                (0..files)
                    .map(|file| TreeDelta::Added {
                        artifact_id: artifact(file),
                        new: LocatedEntry::new(path_of(file), entry_of(file, 0)),
                    })
                    .collect()
            } else {
                // The tree is in state 0 after the root, then alternates. So
                // commit i starts from the state commit i-1 left, which is
                // (i+1) % 2, not i % 2. Getting this backwards makes every
                // `Updated` name an `old` the tree does not hold.
                let from = ((index + 1) % 2) as u8;
                let to = 1 - from;
                (0..churn.min(files))
                    .map(|file| TreeDelta::Updated {
                        artifact_id: artifact(file),
                        old: LocatedEntry::new(path_of(file), entry_of(file, from)),
                        new: LocatedEntry::new(path_of(file), entry_of(file, to)),
                    })
                    .collect()
            };
            let commit_oid = oid(index as u64 + 1);
            let mut change = kin_model::SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
                origin: ChangeOrigin::GitCommit { oid: commit_oid },
                parents: parent.into_iter().collect(),
                timestamp: Timestamp(
                    chrono::DateTime::parse_from_rfc3339("2026-07-26T12:00:00Z")
                        .expect("fixed timestamp parses")
                        .with_timezone(&chrono::Utc),
                ),
                author: AuthorId::new("clockhalf-git-measurement"),
                message: format!("converted commit {index}"),
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
            change.id = compute_semantic_change_id(&change).expect("change id computes");
            let raw_tree_oid = if index == 0 || index % 2 == 0 {
                oid_a
            } else {
                oid_b
            };
            targets.insert(
                change.id,
                GitProjectionTreeTarget {
                    commit_oid,
                    raw_tree_oid,
                },
            );
            parent = Some(change.id);
            order.push(change.id);
            snapshot.changes.insert(change.id, change);
        }
        snapshot.change_children = derive_change_children(&snapshot.changes);
        GitHistory {
            snapshot,
            targets,
            raw_trees,
            order,
        }
    }

    fn lap<T>(label: &str, body: impl FnOnce() -> T) -> T {
        let started = std::time::Instant::now();
        let out = body();
        println!("    {label}={}", started.elapsed().as_millis());
        out
    }

    /// Price the per-change bodies of one whole-history preparation at Git
    /// origin, against history length.
    #[test]
    #[ignore = "measurement: prices step 13's per-change bodies at Git origin"]
    fn git_origin_whole_history_body_costs() {
        let sizes: Vec<usize> = std::env::var("KIN_CLOCKHALF_COMMITS")
            .unwrap_or_else(|_| "300,600,1200,2400".to_string())
            .split(',')
            .filter_map(|value| value.trim().parse().ok())
            .collect();
        let files: usize = std::env::var("KIN_CLOCKHALF_FILES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(200);
        let churn: usize = std::env::var("KIN_CLOCKHALF_CHURN")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(8);

        for commits in sizes {
            let history = git_history(commits, files, churn);
            println!("[git] commits={commits} files={files} churn={churn}");

            lap("derive_change_children_ms", || {
                let children = derive_change_children(&history.snapshot.changes);
                assert_eq!(children.len(), commits.saturating_sub(1));
            });

            lap("derive_admission_policies_ms", || {
                derive_admission_policies(&history.snapshot.changes)
                    .expect("admission policies derive");
            });

            lap("storage_admission_ms", || {
                history
                    .snapshot
                    .validate_storage_admission()
                    .expect("synthetic snapshot admits");
            });

            lap("history_replay_ms", || {
                validate_first_parent_history(&history.snapshot.changes, &history.order)
                    .expect("first-parent history replays");
            });

            lap("history_root_ms", || {
                let mut root = DomainRoot::new(b"kin-repository-history-root-v1\0");
                root.unordered(
                    "changes",
                    &history.snapshot.changes.iter().collect::<Vec<_>>(),
                )
                .expect("history root hashes");
                let _ = root.finish();
            });

            let mut materializations = 0_usize;
            lap("git_projection_replay_ms", || {
                validate_git_projection_tree_replay(
                    &history.snapshot,
                    &history.targets,
                    |raw_tree_oid| {
                        materializations += 1;
                        Ok(history
                            .raw_trees
                            .get(&raw_tree_oid)
                            .expect("every projection has one exact raw tree")
                            .clone())
                    },
                )
                .expect("git projection tree replay");
            });
            println!("    materializations={materializations}");
        }
    }
}

/// The cost SHAPE of Native admission, asserted as a count.
///
/// `verify_native_change_admission` reads the tree at every Native change the
/// transaction carries and the tree at each of that change's parents. Asking
/// for each of those separately walks the whole first-parent lineage once per
/// request, so an ordinary one-change commit re-derived the entire repository
/// history twice and a transaction of `N` chained Native changes was quadratic
/// in `N`. FIR-2569.
///
/// These assert lineage members entered, never milliseconds: the count is the
/// property, and it holds on a loaded box where seconds do not.
#[cfg(test)]
mod native_admission_lineage {
    use super::*;
    use crate::storage::history_replay::take_lineage_steps;
    use kin_model::{
        compute_resolved_tree_hash, compute_semantic_change_id, AdmissionCase,
        AdmissionPolicyDelta, ChangeOrigin, EffectiveAdmissionPolicyStamp, FrozenLocalOverlayDelta,
        LocatedEntry, WorkspaceExpectation, WorkspaceMutation, WorkspaceSemanticDelta,
        REPOSITORY_TRANSACTION_SCHEMA_VERSION,
    };
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    /// Changes in the synthetic history. Small enough to stay a fast gate,
    /// large enough that one pass and one pass per change cannot be confused:
    /// the per-change shape costs CHANGES squared steps against CHANGES here.
    const CHANGES: usize = 64;
    /// Artifacts the head change publishes.
    const FILES: usize = 4;

    fn digest(body: &[u8]) -> Hash256 {
        Hash256::from_bytes(Sha256::digest(body).into())
    }

    fn fixed_timestamp() -> Timestamp {
        Timestamp(
            chrono::DateTime::parse_from_rfc3339("2026-08-21T00:00:00Z")
                .expect("fixed timestamp parses")
                .with_timezone(&chrono::Utc),
        )
    }

    fn repository() -> RepositoryId {
        RepositoryId::new("native-admission-lineage").expect("repository id")
    }

    /// The tree the head change publishes, with the bodies behind it.
    fn head_tree() -> (Vec<TreeDelta>, Vec<(Hash256, Vec<u8>)>) {
        let mut deltas = Vec::with_capacity(FILES);
        let mut blobs = Vec::with_capacity(FILES);
        for file in 0..FILES {
            let path = format!("src/module_{file}.rs");
            let body = format!("pub fn kin_{file}() {{}}\n").into_bytes();
            let hash = digest(&body);
            deltas.push(TreeDelta::Added {
                artifact_id: ArtifactId(Uuid::from_u128(9_000_000 + file as u128)),
                new: LocatedEntry::new(
                    RepoPath::from_bytes(path.into_bytes()).expect("synthetic path is valid"),
                    TreeEntry::blob(hash, false),
                ),
            });
            blobs.push((hash, body));
        }
        (deltas, blobs)
    }

    /// A tree holding exactly one artifact, at a path the caller chooses.
    ///
    /// `head_tree` fixes its paths at `src/module_N.rs`, which cannot exercise a
    /// rule whose whole point is the spelling of the path it matches.
    fn named_tree(path: &str) -> (Vec<TreeDelta>, Vec<(Hash256, Vec<u8>)>) {
        let body = format!("contents of {path}\n").into_bytes();
        let hash = digest(&body);
        let deltas = vec![TreeDelta::Added {
            artifact_id: ArtifactId(Uuid::from_u128(9_100_000)),
            new: LocatedEntry::new(
                RepoPath::from_bytes(path.as_bytes().to_vec()).expect("synthetic path is valid"),
                TreeEntry::blob(hash, false),
            ),
        }];
        (deltas, vec![(hash, body)])
    }

    /// `transfer_fixture`, but the transferred head holds one named artifact.
    fn transfer_fixture_holding(
        path: &str,
    ) -> (
        tempfile::TempDir,
        RepositoryAuthorityManager<crate::storage::backend::LocalFileBackend>,
        Vec<TreeDelta>,
    ) {
        let directory = tempfile::tempdir().expect("tempdir");
        let backend = std::sync::Arc::new(crate::storage::backend::LocalFileBackend::new(
            directory.path(),
        ));
        let manager =
            RepositoryAuthorityManager::open(repository(), backend).expect("open fresh authority");
        let (tree_deltas, blobs) = named_tree(path);
        for (hash, body) in &blobs {
            manager.save_source_blob(*hash, body).expect("save blob");
        }
        (directory, manager, tree_deltas)
    }

    /// One Native change, content-addressed exactly as a real one is.
    fn native_change(
        index: usize,
        parent: Option<SemanticChangeId>,
        shared: &SharedAdmissionPolicy,
        tree_deltas: Vec<TreeDelta>,
    ) -> kin_model::SemanticChange {
        let mut change = kin_model::SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: parent.into_iter().collect(),
            timestamp: fixed_timestamp(),
            author: AuthorId::new("native-admission-lineage"),
            message: format!("synthetic native change {index}"),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas,
            admission_policy_delta: (parent.is_none())
                .then(|| AdmissionPolicyDelta::initialize(shared.clone())),
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        change.id = compute_semantic_change_id(&change).expect("change id computes");
        change
    }

    /// A Git-origin sibling of `native_change`, for the arm that has to NOT be
    /// admission-checked.
    ///
    /// Everything else is identical, deliberately: the only variable between the
    /// two arms below is the origin, so an outcome that differs can only be the
    /// origin deciding it.
    fn git_change(
        index: usize,
        parent: Option<SemanticChangeId>,
        shared: &SharedAdmissionPolicy,
        tree_deltas: Vec<TreeDelta>,
    ) -> kin_model::SemanticChange {
        let mut change = kin_model::SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::GitCommit {
                oid: kin_model::GitObjectId::sha1([0x70 + index as u8; 20]),
            },
            parents: parent.into_iter().collect(),
            timestamp: fixed_timestamp(),
            author: AuthorId::new("native-admission-lineage"),
            message: format!("synthetic git change {index}"),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas,
            admission_policy_delta: (parent.is_none())
                .then(|| AdmissionPolicyDelta::initialize(shared.clone())),
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        change.id = compute_semantic_change_id(&change).expect("change id computes");
        change
    }

    /// `CHANGES` chained GIT-origin changes, the head carrying `tree`.
    fn git_history(
        shared: &SharedAdmissionPolicy,
        tree: &[TreeDelta],
    ) -> Vec<kin_model::SemanticChange> {
        let mut chain = Vec::with_capacity(CHANGES);
        let mut parent = None;
        for index in 0..CHANGES {
            let deltas = if index + 1 == CHANGES {
                tree.to_vec()
            } else {
                Vec::new()
            };
            let change = git_change(index, parent, shared, deltas);
            parent = Some(change.id);
            chain.push(change);
        }
        chain
    }

    /// `CHANGES` chained Native changes, the head carrying `tree`.
    fn chained_history(
        shared: &SharedAdmissionPolicy,
        tree: &[TreeDelta],
    ) -> Vec<kin_model::SemanticChange> {
        let mut chain = Vec::with_capacity(CHANGES);
        let mut parent = None;
        for index in 0..CHANGES {
            let deltas = if index + 1 == CHANGES {
                tree.to_vec()
            } else {
                Vec::new()
            };
            let change = native_change(index, parent, shared, deltas);
            parent = Some(change.id);
            chain.push(change);
        }
        chain
    }

    fn transaction_shell(
        manager: &RepositoryAuthorityManager<crate::storage::backend::LocalFileBackend>,
        operation: u128,
        changes: Vec<kin_model::SemanticChange>,
    ) -> RepositoryTransaction {
        let lease = manager.read_authority();
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::from_uuid(Uuid::from_u128(operation)),
            repository_id: repository(),
            expected_generation: lease.generation(),
            expected_roots: lease.roots().clone(),
            actor: AuthorId::new("native-admission-lineage"),
            reason: "native admission lineage fixture".to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes,
            aliases: Vec::new(),
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        drop(lease);
        transaction
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        manager: RepositoryAuthorityManager<crate::storage::backend::LocalFileBackend>,
        head: SemanticChangeId,
    }

    /// A committed history of `CHANGES` chained Native changes whose head
    /// publishes `FILES` artifacts through a bound workspace.
    ///
    /// This is the only arrangement the v3 Native admission contract permits
    /// for a multi-change transaction: exactly one change may introduce
    /// artifacts, and the successor workspace must base on that change.
    fn committed_history(with_workspace: bool) -> Fixture {
        let directory = tempfile::tempdir().expect("tempdir");
        let backend = std::sync::Arc::new(crate::storage::backend::LocalFileBackend::new(
            directory.path(),
        ));
        let manager =
            RepositoryAuthorityManager::open(repository(), backend).expect("open fresh authority");

        let shared = SharedAdmissionPolicy::empty(0);
        let (tree_deltas, blobs) = if with_workspace {
            head_tree()
        } else {
            (Vec::new(), Vec::new())
        };
        for (hash, body) in &blobs {
            manager.save_source_blob(*hash, body).expect("save blob");
        }
        let changes = chained_history(&shared, &tree_deltas);
        let head = changes.last().expect("the chain has a head").id;
        let mut transaction = transaction_shell(&manager, 1, changes);

        if with_workspace {
            let tree = ResolvedTree::default()
                .apply(&tree_deltas)
                .expect("the head tree applies");
            let tree_hash = compute_resolved_tree_hash(&tree).expect("tree hash");
            let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(30));
            let overlay =
                FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::Sensitive, Vec::new())
                    .expect("frozen overlay");
            let policy = EffectiveAdmissionPolicyStamp {
                shared: shared.stamp(),
                local: overlay.stamp(),
            };
            let main = RefName::branch(b"main").expect("branch name");
            let target = RefTarget::change(head);
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
            transaction.workspace_mutation = Some(WorkspaceMutation {
                workspace_id,
                expected: WorkspaceExpectation::MustNotExist,
                new_generation: 0,
                new_head: WorkspaceHead::Symbolic { target: main },
                new_base_target: Some(target),
                new_base_tree_hash: Some(tree_hash),
                tree_deltas,
                new_tree_hash: tree_hash,
                semantic_delta: WorkspaceSemanticDelta::default(),
                new_shared_admission_policy: shared,
                new_admission_policy: policy,
            });
            transaction.local_overlay_delta = Some(FrozenLocalOverlayDelta::initialize(overlay));
        }

        take_lineage_steps();
        let receipt = manager
            .commit_repository_transaction(transaction)
            .expect("the synthetic history commits");
        assert_eq!(receipt.generation, 1);

        Fixture {
            _directory: directory,
            manager,
            head,
        }
    }

    /// One transaction of chained Native changes walks its lineage once.
    ///
    /// Three whole-history resolutions happen in this preparation and each is
    /// one pass over the same chain: Native admission resolves every change in
    /// the transaction and every parent of one, workspace admission resolves
    /// the successor workspace's base, and workspace validation resolves that
    /// base again for its tree hash. The last two are one walk each no matter
    /// how many changes the transaction carries; only the first scales with
    /// the transaction, and it is the one that used to scale by multiplying.
    ///
    /// Resolving each Native change and each parent separately would enter
    /// `CHANGES * (CHANGES + 1)` members for the admission term alone.
    #[test]
    fn one_transaction_walks_its_native_lineage_once() {
        let fixture = committed_history(true);
        let steps = take_lineage_steps();
        let native_admission = CHANGES;
        let workspace_admission_base = CHANGES;
        let workspace_state_base = CHANGES;
        assert_eq!(
            steps,
            native_admission + workspace_admission_base + workspace_state_base,
            "one preparation must enter this chain once per resolution, not once per change"
        );
        // The shape this replaces, stated so the assertion above cannot be
        // read as an arbitrary constant.
        let per_change_steps = CHANGES * (CHANGES + 1);
        assert!(
            per_change_steps > native_admission * 50,
            "the fixture must separate one pass ({native_admission}) from per-change \
             resolution ({per_change_steps}) by more than a constant"
        );
        drop(fixture);
    }

    /// An ordinary commit reads its history once, not once per resolved tree.
    ///
    /// This is the shape FIR-2569 is about: one Native change on top of an
    /// existing history. Its own tree and its parent's tree share the whole
    /// lineage, so one pass costs the history's depth plus the new change.
    ///
    /// The commit must also SUCCEED, and that is what proves the parent tree
    /// is really being resolved: the head already carries `FILES` artifacts,
    /// so a parent tree that came back empty would make every one of them read
    /// as newly introduced and the transaction would be refused for having no
    /// bound workspace admission context.
    #[test]
    fn an_ordinary_commit_reads_its_history_once() {
        let fixture = committed_history(true);
        let shared = SharedAdmissionPolicy::empty(0);
        let follow_on = native_change(CHANGES, Some(fixture.head), &shared, Vec::new());
        let transaction = transaction_shell(&fixture.manager, 2, vec![follow_on]);

        take_lineage_steps();
        let receipt = fixture
            .manager
            .commit_repository_transaction(transaction)
            .expect("a follow-on Native change that introduces nothing must commit");
        let steps = take_lineage_steps();

        assert_eq!(receipt.generation, 2);
        // Native admission enters the new change and its whole lineage once.
        // The persisted workspace's base tree hash is the other resolution in
        // this preparation, and it is one walk whatever the commit did.
        let native_admission = CHANGES + 1;
        let workspace_state_base = CHANGES;
        assert_eq!(
            steps,
            native_admission + workspace_state_base,
            "one commit must read the history once, not once for the change and again for its parent"
        );
    }

    /// The refusal the resolution exists to raise still fires.
    ///
    /// A Native change that introduces artifacts with no workspace bound to it
    /// is refused by name. This is the positive control for the count tests
    /// above: it can only fire when the candidate tree and the parent tree
    /// were both resolved, since the refusal is reached through the difference
    /// between them.
    #[test]
    fn an_unbound_native_introduction_is_still_refused() {
        let directory = tempfile::tempdir().expect("tempdir");
        let backend = std::sync::Arc::new(crate::storage::backend::LocalFileBackend::new(
            directory.path(),
        ));
        let manager =
            RepositoryAuthorityManager::open(repository(), backend).expect("open fresh authority");

        let shared = SharedAdmissionPolicy::empty(0);
        let (tree_deltas, blobs) = head_tree();
        for (hash, body) in &blobs {
            manager.save_source_blob(*hash, body).expect("save blob");
        }
        let changes = chained_history(&shared, &tree_deltas);
        // No workspace mutation, so the head's artifacts have nothing to
        // publish them.
        let transaction = transaction_shell(&manager, 3, changes);

        let error = manager
            .commit_repository_transaction(transaction)
            .expect_err("an unbound Native introduction must be refused")
            .to_string();
        assert!(
            error.contains("introduces artifacts without a bound workspace admission context"),
            "the refusal must name the missing admission context: {error}"
        );
    }

    /// One fresh authority with the head's blobs saved, ready to receive.
    fn transfer_fixture() -> (
        tempfile::TempDir,
        RepositoryAuthorityManager<crate::storage::backend::LocalFileBackend>,
        Vec<TreeDelta>,
    ) {
        let directory = tempfile::tempdir().expect("tempdir");
        let backend = std::sync::Arc::new(crate::storage::backend::LocalFileBackend::new(
            directory.path(),
        ));
        let manager =
            RepositoryAuthorityManager::open(repository(), backend).expect("open fresh authority");
        let (tree_deltas, blobs) = head_tree();
        for (hash, body) in &blobs {
            manager.save_source_blob(*hash, body).expect("save blob");
        }
        (directory, manager, tree_deltas)
    }

    /// A shared policy carrying one gitignore-shaped rule body.
    fn policy_excluding(
        manager: &RepositoryAuthorityManager<crate::storage::backend::LocalFileBackend>,
        pattern: &str,
    ) -> SharedAdmissionPolicy {
        policy_with_rules(manager, &[pattern])
    }

    /// A shared policy carrying several rule lines in one source, in order.
    ///
    /// Order is the point for a negation: gitignore semantics let a later `!`
    /// line re-admit what an earlier line excluded, and that pair is the only
    /// place the two admission cases disagree in the permissive direction.
    fn policy_with_rules(
        manager: &RepositoryAuthorityManager<crate::storage::backend::LocalFileBackend>,
        patterns: &[&str],
    ) -> SharedAdmissionPolicy {
        let body = patterns
            .iter()
            .map(|pattern| format!("{pattern}\n"))
            .collect::<String>()
            .into_bytes();
        let hash = digest(&body);
        manager
            .save_source_blob(hash, &body)
            .expect("save the rule body");
        SharedAdmissionPolicy::new(
            0,
            vec![kin_model::AdmissionRuleSource {
                kind: kin_model::AdmissionRuleSourceKind::KinIgnore,
                path: RepoPath::from_bytes(b".kinignore".to_vec()).expect("rule path"),
                base_directory: None,
                body_hash: hash,
                body_len: body.len() as u64,
                precedence: 0,
            }],
            Vec::new(),
        )
        .expect("a one-source shared policy is valid")
    }

    /// The journal WALK reaches the envelope a full open reaches.
    ///
    /// Every live store takes this path, because a store's acknowledged head
    /// moves past its snapshot base the first time its daemon writes anything,
    /// and a walk that builds a wrong envelope gives wrong workspace answers
    /// with no error on the daemon's primary read.
    ///
    /// It lives here because this module has the two-commit shape the outer one
    /// does not. `committed_history(true)` lands the bootstrap through a bound
    /// workspace, and `transaction_shell` then reads `expected_generation` and
    /// `expected_roots` off the current lease while mutating no refs, so a
    /// second call is a valid successor and therefore a frame past the base.
    ///
    /// **The follow-on change carries no tree deltas, and that is required
    /// rather than incidental.** `transaction_shell` sets
    /// `workspace_mutation: None`, so a change introducing artifacts is refused
    /// with "introduces artifacts without a bound workspace admission context".
    /// An earlier version of this test built its own first commit out of
    /// `transfer_fixture` plus `chained_history` and hit exactly that.
    ///
    /// The assertion is the JOIN, against what the full open produces, because
    /// a hardcoded expectation passes with both sides wrong. The control above
    /// it is what makes the join mean anything: without a frame past the base
    /// the read takes its early return and this test passes with the walk
    /// deleted.
    #[test]
    fn the_envelope_walk_reaches_the_envelope_a_full_open_reaches() {
        let fixture = committed_history(true);
        let shared = SharedAdmissionPolicy::empty(0);
        let follow_on = native_change(CHANGES, Some(fixture.head), &shared, Vec::new());
        let receipt = fixture
            .manager
            .commit_repository_transaction(transaction_shell(&fixture.manager, 2, vec![follow_on]))
            .expect("a follow-on Native change that introduces nothing must commit");
        assert_eq!(receipt.generation, 2);

        let backend = std::sync::Arc::new(crate::storage::backend::LocalFileBackend::new(
            fixture._directory.path(),
        ));

        // THE CONTROL. A fixture whose base already is its head exercises the
        // early return, and this test would then pass with the walk deleted.
        let persisted = backend
            .load_snapshot_authority(repository().as_str())
            .expect("the authority loads")
            .expect("the fixture wrote an authority");
        assert!(
            persisted.snapshot_generation < persisted.head_generation,
            "this fixture must carry an acknowledged frame past its base, or the walk is not \
             under test: base {} head {}",
            persisted.snapshot_generation,
            persisted.head_generation
        );

        let envelope =
            RepositoryAuthorityMetadata::open(repository(), std::sync::Arc::clone(&backend))
                .expect("the envelope read must not error")
                .expect("the envelope read must answer over a journal, not decline");
        assert_eq!(
            envelope.generation(),
            fixture.manager.read_authority().generation(),
            "the walked envelope must reach the acknowledged head"
        );
        assert_eq!(
            envelope.metadata(),
            fixture.manager.read_authority().metadata(),
            "the walked envelope must equal the one a full open produces, field for field"
        );
    }

    /// Call the transferred-commit entry through a GENERIC bound.
    ///
    /// This exists because of how 0.7.72 shipped broken. The method landed in
    /// `impl RepositoryAuthorityManager<LocalFileBackend>` instead of the
    /// generic impl, so it was reachable only from one concrete backend. Every
    /// kin-db gate passed: a concrete impl is valid Rust, and every test in this
    /// module holds a `LocalFileBackend` manager, so none of them could tell the
    /// difference. kin's receive path is generic over the backend and could not
    /// see the method at all.
    ///
    /// **The guard is that this does not compile if the method is not generic.**
    /// A monomorphic call site cannot express the requirement; a generic one
    /// makes the bound itself the assertion, and it fails at build time rather
    /// than in a consumer's repository one publish later.
    fn commit_transferred_through_a_generic_bound<B: StorageBackend + ?Sized + 'static>(
        manager: &RepositoryAuthorityManager<B>,
        transaction: RepositoryTransaction,
        case: Option<crate::admission::AdmissionCase>,
    ) -> Result<RepositoryCommitReceipt, KinDbError> {
        manager.commit_transferred_repository_transaction(transaction, case)
    }

    /// The transferred-commit entry is reachable from a generic backend.
    ///
    /// The assertion that matters is the one the compiler makes on the helper
    /// above. This test also runs it, so the path is exercised rather than only
    /// type-checked.
    #[test]
    fn the_transferred_commit_entry_is_reachable_from_any_backend() {
        let (_directory, manager, tree_deltas) = transfer_fixture();
        let shared = SharedAdmissionPolicy::empty(0);
        let changes = chained_history(&shared, &tree_deltas);
        let transaction = transaction_shell(&manager, 3, changes);

        commit_transferred_through_a_generic_bound(&manager, transaction, None)
            .expect("a transferred introduction must be admitted through a generic bound");
    }

    /// THE PROPERTY. What a local publish is refused for, a transfer is admitted
    /// for, because the receiver performed no publication and is held instead to
    /// the shared policy it can resolve from the transferred history.
    ///
    /// Its control is `an_unbound_native_introduction_is_still_refused` directly
    /// above: the same shape, the same transaction, refused on the local path.
    /// The pair is the whole point, so neither is readable alone.
    #[test]
    fn a_transferred_native_introduction_is_admitted_where_a_local_one_is_refused() {
        let (_directory, manager, tree_deltas) = transfer_fixture();
        let shared = SharedAdmissionPolicy::empty(0);
        let changes = chained_history(&shared, &tree_deltas);
        let transaction = transaction_shell(&manager, 3, changes);

        let receipt = manager
            .commit_transferred_repository_transaction(
                transaction,
                Some(crate::admission::AdmissionCase::Sensitive),
            )
            .expect("a transferred Native introduction must be admitted");
        assert_eq!(receipt.generation, 1, "the transfer must move authority");
    }

    /// The receiver refuses by name what the SHARED policy excludes, so dropping
    /// the workspace legs did not drop the policy legs with them.
    #[test]
    fn a_transferred_introduction_the_shared_policy_excludes_is_refused_by_name() {
        let (_directory, manager, tree_deltas) = transfer_fixture();
        let shared = policy_excluding(&manager, "src/module_0.rs");
        let changes = chained_history(&shared, &tree_deltas);
        let transaction = transaction_shell(&manager, 3, changes);

        let error = manager
            .commit_transferred_repository_transaction(
                transaction,
                Some(crate::admission::AdmissionCase::Sensitive),
            )
            .expect_err("an excluded artifact must be refused on the receiver")
            .to_string();
        assert!(
            error.contains("excluded by the exact graph-owned admission policy"),
            "the refusal must name the policy that excluded it: {error}"
        );
        assert!(
            error.contains("src/module_0.rs"),
            "the refusal must name the artifact: {error}"
        );
    }

    /// THE CASE IS AUTHORITY, and this is what proves it rather than asserting
    /// it. One policy, one artifact, two cases, opposite outcomes.
    ///
    /// The rule is spelled in upper case and the artifact in lower. Under
    /// `FoldAscii` the shared rule matches and the receiver refuses; under
    /// `Sensitive` it does not match and the receiver admits.
    ///
    /// Which case a receiver supplies is settled elsewhere and is its OWN: kin
    /// reads it from the overlay of the workspace its daemon pinned at startup,
    /// and a replica with no overlay admits under `Sensitive` because byte-exact
    /// object storage is what it stores into. What this test pins is the half
    /// that belongs here, that the supplied case reaches the shared matcher and
    /// decides, so `commit_transferred_repository_transaction` is right to make
    /// the caller supply one and never default.
    #[test]
    fn the_supplied_case_decides_the_shared_policy_on_the_receiver() {
        let folded = {
            let (_directory, manager, tree_deltas) = transfer_fixture();
            let shared = policy_excluding(&manager, "SRC/MODULE_0.RS");
            let changes = chained_history(&shared, &tree_deltas);
            let transaction = transaction_shell(&manager, 3, changes);
            manager
                .commit_transferred_repository_transaction(
                    transaction,
                    Some(crate::admission::AdmissionCase::FoldAscii),
                )
                .map(|_| ())
                .map_err(|error| error.to_string())
        };
        let sensitive = {
            let (_directory, manager, tree_deltas) = transfer_fixture();
            let shared = policy_excluding(&manager, "SRC/MODULE_0.RS");
            let changes = chained_history(&shared, &tree_deltas);
            let transaction = transaction_shell(&manager, 3, changes);
            manager
                .commit_transferred_repository_transaction(
                    transaction,
                    Some(crate::admission::AdmissionCase::Sensitive),
                )
                .map(|_| ())
                .map_err(|error| error.to_string())
        };

        let folded_error = folded.expect_err(
            "an upper-case rule must match a lower-case path under FoldAscii, so this must refuse",
        );
        assert!(
            folded_error.contains("excluded by the exact graph-owned admission policy"),
            "the FoldAscii arm must refuse by policy: {folded_error}"
        );
        sensitive.expect(
            "the same rule must NOT match under Sensitive, so this must be admitted; if it \
             refuses, the case is not reaching the shared matcher and carrying it buys nothing",
        );
    }

    /// FOLDING IS NOT STRICTER, and this is the pair that proves it.
    ///
    /// The tidy story is that ASCII-folded matching admits less, because an
    /// exclusion rule matches more paths under it. That is only half of it: a
    /// NEGATION folds too, so a `!` line re-admits more paths as well, and the
    /// two cases disagree in both directions depending on which line wins.
    ///
    /// `*.LOG` then `!keep.log`, against an artifact spelled `keep.LOG`:
    ///
    /// - `FoldAscii`: `*.LOG` matches, then `!keep.log` folds onto `keep.LOG`
    ///   and re-admits it. ADMITTED.
    /// - `Sensitive`: `*.LOG` matches exactly, and `!keep.log` does not match
    ///   `keep.LOG` at all, so nothing re-admits it. REFUSED.
    ///
    /// So the folded case is the PERMISSIVE one here, which is the opposite of
    /// what the tidy story predicts, and it is why no receiver can pick a case
    /// as the safe default. Rare, since rules and paths are usually lowercase,
    /// and real, which is the only reason it needs a test rather than a
    /// sentence.
    ///
    /// It matters now in a way it did not before: a receiver applies its own
    /// case, so a `FoldAscii` publisher pushing `keep.LOG` to a replica that
    /// admits under `Sensitive`, which is every hosted replica, lands exactly
    /// here.
    #[test]
    fn a_negation_makes_folding_permissive_where_the_tidy_story_says_strict() {
        let outcome = |case: crate::admission::AdmissionCase| {
            let (_directory, manager, tree_deltas) = transfer_fixture_holding("keep.LOG");
            let shared = policy_with_rules(&manager, &["*.LOG", "!keep.log"]);
            let changes = chained_history(&shared, &tree_deltas);
            let transaction = transaction_shell(&manager, 3, changes);
            manager
                .commit_transferred_repository_transaction(transaction, Some(case))
                .map(|_| ())
                .map_err(|error| error.to_string())
        };

        let folded = outcome(crate::admission::AdmissionCase::FoldAscii);
        let sensitive = outcome(crate::admission::AdmissionCase::Sensitive);

        assert_ne!(
            folded.is_ok(),
            sensitive.is_ok(),
            "the two cases must decide this pair differently, or the fixture is not exercising \
             the negation at all: folded={folded:?} sensitive={sensitive:?}"
        );
        folded.expect(
            "under FoldAscii the negation !keep.log folds onto keep.LOG and re-admits it, so this \
             must be ADMITTED; a refusal here means folding is stricter in both directions, which \
             is the claim this test exists to refute",
        );
        let refusal = sensitive.expect_err(
            "under Sensitive the negation does not match keep.LOG, so nothing re-admits what \
             *.LOG excluded and this must be REFUSED",
        );
        assert!(
            refusal.contains("excluded by the exact graph-owned admission policy"),
            "the Sensitive arm must refuse by policy: {refusal}"
        );
        assert!(
            refusal.contains("case-sensitive"),
            "the refusal must name the case it matched under, so a reader can tell this apart \
             from the same policy deciding the other way: {refusal}"
        );
        assert!(
            refusal.contains("*.LOG"),
            "the refusal must name the rule that decided, not only that one did: {refusal}"
        );
    }

    /// A FORGED Git-origin label cannot skip admission, and this is the pair
    /// that proves it rather than trusting the filter's shape.
    ///
    /// `verify_native_change_admission` filters to `ChangeOrigin::Native` and
    /// returns `Ok` when none remain, which the comment there says is exactly
    /// what a Git import is. Read alone that looks like a hole: label a Native
    /// change as Git-origin and the shared policy never runs.
    ///
    /// It is not a hole, and the reason is one layer up. A transaction carrying
    /// a Git-origin change must also carry that commit's RAW OBJECT and its
    /// final alias binding the oid to the change, so the label costs a git
    /// object the forger does not have. This arm pays the label and is refused
    /// for the object, by name.
    ///
    /// The control is the same artifact on a Native change, refused by the
    /// shared policy. Without it, a refusal in the forged arm could be the
    /// policy biting rather than the object check, and the two are different
    /// claims.
    ///
    /// What this pair deliberately does NOT cover is a REAL Git import being
    /// admitted without an admission check, which is the brownfield behaviour a
    /// conversion depends on. That was measured end to end on 2026-08-30 through
    /// a real hosted transfer, where a file git tracked only because it was
    /// force-added past its own `*.log` rule survived `kin init`, the wire and
    /// the projection. Constructing it here needs external object records and
    /// aliases rather than a synthesised oid, and the end state it argues for is
    /// filed as FIR-2981.
    #[test]
    fn a_forged_git_origin_change_cannot_skip_admission() {
        let arm = |forge_git_origin: bool| {
            let (_directory, manager, tree_deltas) = transfer_fixture_holding("keep.log");
            let shared = policy_with_rules(&manager, &["*.log"]);
            let changes = if forge_git_origin {
                git_history(&shared, &tree_deltas)
            } else {
                chained_history(&shared, &tree_deltas)
            };
            let transaction = transaction_shell(&manager, 3, changes);
            manager
                .commit_transferred_repository_transaction(
                    transaction,
                    Some(crate::admission::AdmissionCase::Sensitive),
                )
                .map(|_| ())
                .map_err(|error| error.to_string())
        };

        let native_refusal = arm(false).expect_err(
            "the control must refuse: a Native change introducing keep.log against a policy that \
             excludes *.log is exactly what the shared-policy check is for, and if this admits \
             then the forged arm proves nothing",
        );
        assert!(
            native_refusal.contains("excluded by the exact graph-owned admission policy"),
            "the control must refuse by POLICY, not for some unrelated reason: {native_refusal}"
        );
        assert!(
            native_refusal.contains("keep.log"),
            "the control's refusal must name the artifact: {native_refusal}"
        );

        let forged_refusal = arm(true).expect_err(
            "a forged Git-origin label must NOT be admitted; if it is, relabelling a Native change \
             is a way past the shared admission policy",
        );
        assert!(
            forged_refusal.contains("lacks raw commit object"),
            "the forged arm must be refused for the git object it cannot produce, which is what \
             makes the label cost something: {forged_refusal}"
        );
        assert!(
            !forged_refusal.contains("excluded by the exact graph-owned admission policy"),
            "the forged arm must NOT be refused by the policy, or this test is measuring the \
             control twice and says nothing about the label: {forged_refusal}"
        );
    }

    /// A repository with NO shared admission rules needs no case, and this is
    /// what makes `None` an exact answer rather than a convenient one.
    ///
    /// With no shared sources and no local sources, `resolve_admission_matcher`
    /// compiles a matcher over an empty rule set, which matches nothing and so
    /// decides identically under either case. Admitting with `None` there
    /// invents nothing.
    #[test]
    fn a_transfer_needs_no_case_when_the_shared_policy_has_no_rules() {
        let (_directory, manager, tree_deltas) = transfer_fixture();
        let shared = SharedAdmissionPolicy::empty(0);
        assert!(
            shared.sources.is_empty(),
            "this test is about the no-rules case, so the fixture must have none"
        );
        let changes = chained_history(&shared, &tree_deltas);
        let transaction = transaction_shell(&manager, 3, changes);

        manager
            .commit_transferred_repository_transaction(transaction, None)
            .expect("a transfer against a rule-free policy must not require a case");
    }

    /// And a repository that HAS shared rules is refused by name until the
    /// publisher's case travels, rather than being decided by a guess.
    ///
    /// This is the pair to the test above. Together they say the case is
    /// required exactly when it can change an answer and not one moment before,
    /// which is the difference between an exact rule and a cautious one.
    #[test]
    fn a_transfer_against_a_rule_carrying_policy_is_refused_without_a_case() {
        let (_directory, manager, tree_deltas) = transfer_fixture();
        let shared = policy_excluding(&manager, "does/not/match/anything.rs");
        assert!(
            !shared.sources.is_empty(),
            "this test is about the rules-present case"
        );
        let changes = chained_history(&shared, &tree_deltas);
        let transaction = transaction_shell(&manager, 3, changes);

        let error = manager
            .commit_transferred_repository_transaction(transaction, None)
            .expect_err("a rule-carrying policy must refuse a transfer with no case")
            .to_string();
        assert!(
            error.contains("its receiver named no admission case to decide under"),
            "the refusal must name the missing case: {error}"
        );
        assert!(
            error.contains("neither is uniformly stricter"),
            "the refusal must say WHY it declines to guess, since a reader who thinks one case \
             is the safe default will read this as pedantry: {error}"
        );
        // The rule deliberately matches nothing, so this cannot be the artifact
        // being excluded. It is the missing case alone.
        assert!(
            !error.contains("excluded by the exact graph-owned admission policy"),
            "the refusal must be about the case, not about an exclusion: {error}"
        );
    }

    /// What the receiver-side sensitive check costs on a realistic first push.
    ///
    /// A receiver has no previous workspace, so nothing is skipped as
    /// already-tracked and `verify_artifact_admission` loads every introduced
    /// artifact's body. That is stricter than a local publish and it is not
    /// free, so the cost is measured here rather than argued about.
    ///
    /// Ignored because it builds and commits a pack in the thousands of files.
    /// Run it deliberately:
    ///   cargo test -p kin-db --lib transferred_first_push_cost -- --ignored --nocapture
    #[test]
    #[ignore = "measurement: builds a multi-thousand-file pack"]
    fn transferred_first_push_cost() {
        const REALISTIC_FILES: usize = 2_000;
        let directory = tempfile::tempdir().expect("tempdir");
        let backend = std::sync::Arc::new(crate::storage::backend::LocalFileBackend::new(
            directory.path(),
        ));
        let manager =
            RepositoryAuthorityManager::open(repository(), backend).expect("open fresh authority");

        // Bodies sized like real source rather than like a fixture: a few KB of
        // plausible text each, so the per-artifact read is not measuring an
        // empty file.
        let mut deltas = Vec::with_capacity(REALISTIC_FILES);
        let mut total_bytes = 0usize;
        for file in 0..REALISTIC_FILES {
            let path = format!("src/pkg_{}/module_{file}.rs", file % 40);
            let body = format!(
                "// module {file}\npub struct Item{file} {{ id: u64, name: String }}\n\n\
                 impl Item{file} {{\n    pub fn new(id: u64) -> Self {{\n        \
                 Self {{ id, name: format!(\"item-{{id}}\") }}\n    }}\n}}\n{}",
                "// filler to reach a realistic body size\n".repeat(60)
            )
            .into_bytes();
            total_bytes += body.len();
            let hash = digest(&body);
            manager.save_source_blob(hash, &body).expect("save blob");
            deltas.push(TreeDelta::Added {
                artifact_id: ArtifactId(Uuid::from_u128(2_000_000 + file as u128)),
                new: LocatedEntry::new(
                    RepoPath::from_bytes(path.into_bytes()).expect("path is valid"),
                    TreeEntry::blob(hash, false),
                ),
            });
        }

        let shared = SharedAdmissionPolicy::empty(0);
        let change = native_change(0, None, &shared, deltas);
        let transaction = transaction_shell(&manager, 9, vec![change]);

        let started = std::time::Instant::now();
        let receipt = manager
            .commit_transferred_repository_transaction(
                transaction,
                Some(crate::admission::AdmissionCase::Sensitive),
            )
            .expect("a realistic first push must be admitted");
        let elapsed = started.elapsed();

        assert_eq!(receipt.generation, 1);
        println!(
            "MEASURED transferred first push: files={REALISTIC_FILES} bytes={total_bytes} \
             elapsed_ms={} per_artifact_us={}",
            elapsed.as_millis(),
            elapsed.as_micros() / REALISTIC_FILES as u128
        );
    }
}

/// FIR-3064 open-cost harness.
///
/// Opens a real on-disk repository authority and reports the resident set
/// after each step a daemon startup takes, so the cost of an open can be read
/// as memory rather than inferred from a stopwatch. Ignored by default and
/// needs `KIN_FIR3064_STORE` naming a `kindb` directory, so the default suite
/// never opens a multi-gigabyte store.
#[cfg(test)]
mod fir3064_open_cost {
    use super::*;

    /// Resident set of this process in KiB, read from `ps` so the number is
    /// the one an operator reads, not an allocator's own accounting.
    fn resident_kb() -> i64 {
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .expect("ps runs");
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .expect("ps prints the resident set as a number")
    }

    fn report(label: &str, started: std::time::Instant, previous_kb: i64) -> i64 {
        let now_kb = resident_kb();
        println!(
            "[TERM] {label}_ms={} rss_kb={now_kb} delta_kb={}",
            started.elapsed().as_millis(),
            now_kb - previous_kb
        );
        now_kb
    }

    #[test]
    #[ignore = "needs KIN_FIR3064_STORE naming a real kindb directory"]
    fn measure_what_an_open_retains() {
        let store = std::env::var("KIN_FIR3064_STORE")
            .expect("set KIN_FIR3064_STORE to a <repo>/.kin/kindb directory");
        let repo = std::env::var("KIN_FIR3064_REPO")
            .expect("set KIN_FIR3064_REPO to the repository id under that directory");
        let repository_id = RepositoryId::new(&repo).expect("repository id");
        let backend = Arc::new(crate::storage::backend::LocalFileBackend::new(&store));
        let baseline_kb = resident_kb();
        println!("[TERM] baseline rss_kb={baseline_kb}");

        let started = std::time::Instant::now();
        let manager = RepositoryAuthorityManager::open(repository_id, backend)
            .expect("open repository authority");
        let after_open_kb = report("authority_open", started, baseline_kb);
        println!(
            "[open] by_history_validation={}",
            manager.opened_by_history_validation()
        );

        let lease = manager.read_authority();
        let snapshot = lease.snapshot();
        let started = std::time::Instant::now();
        println!(
            "[store] changes={} entities={} relations={} entity_revisions={} section_present={} change_map_decoded={}",
            snapshot.changes.len(),
            snapshot.entities.len(),
            snapshot.relations.len(),
            snapshot.entity_revisions.len(),
            snapshot.materialized_graph.is_some(),
            snapshot.changes.is_decoded()
        );
        let after_len_kb = report("changes_len", started, after_open_kb);

        let Some(workspace) = lease.metadata().workspaces.first().cloned() else {
            println!("[TERM] no workspace on this authority");
            return;
        };
        let started = std::time::Instant::now();
        let workspace_snapshot = lease
            .workspace_graph_snapshot(&workspace.workspace_id)
            .expect("materialize the workspace graph")
            .expect("the workspace exists");
        let after_workspace_kb = report("workspace_graph_snapshot", started, after_len_kb);
        println!(
            "[workspace] changes={} entities={} relations={} entity_revisions={} change_map_decoded={} authority_change_map_decoded={}",
            workspace_snapshot.changes.len(),
            workspace_snapshot.entities.len(),
            workspace_snapshot.relations.len(),
            workspace_snapshot.entity_revisions.len(),
            workspace_snapshot.changes.is_decoded(),
            snapshot.changes.is_decoded(),
        );

        let started = std::time::Instant::now();
        let graph = InMemoryGraph::from_snapshot_without_text_index(workspace_snapshot)
            .expect("build the served graph");
        let after_graph_kb = report("in_memory_graph_build", started, after_workspace_kb);
        println!(
            "[graph] authority_change_map_decoded={}",
            snapshot.changes.is_decoded()
        );

        let started = std::time::Instant::now();
        drop(graph);
        drop(lease);
        drop(manager);
        report("after_drop", started, after_graph_kb);
    }
}
