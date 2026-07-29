// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Canonical types for Kin semantic VCS.
//!
//! This crate defines all shared types used across the Kin codebase:
//! entities, relations, exact repository trees, semantic changes, refs,
//! contracts, and more.
//!
//! # Positional-wire rule for persisted types
//!
//! Types reachable from a snapshot, delta, or operation record are persisted
//! by `kin-db` through a compact MessagePack encoding. That encoding writes a
//! struct as an **array**, so a field is identified by its position and never
//! by its name. Two rules follow, and both are enforced rather than trusted:
//!
//! 1. **A new field goes last.** Appending is additive: a record written by an
//!    older version simply runs out of array elements, and the trailing field
//!    takes its `#[serde(default)]`. Inserting a field anywhere else shifts
//!    every following value into the wrong slot, which decodes as the wrong
//!    type or, worse, as a plausible wrong value.
//! 2. **`skip_serializing_if` belongs only on trailing fields.** A skipped
//!    field shortens the array, so a skip on a non-trailing field moves every
//!    field after it whenever the predicate fires. The result is a type that
//!    round-trips in the common case and fails only for the values that skip.
//!
//! A field carrying `skip_serializing_if` must also carry `#[serde(default)]`,
//! otherwise the shortened array fails to decode instead of filling the gap.
//!
//! Both rules are checked by `tests/persisted_schema.rs`: a source scan denies
//! a non-trailing `skip_serializing_if`, and per-type round-trips exercise the
//! skipping values themselves. Changing a persisted type additionally runs the
//! downstream `kin-db` suite against the change (`.github/workflows/kin-db-compat.yml`),
//! because kin-model's own suite cannot observe an existing store decoding
//! wrongly.

pub mod admission;
pub mod branch;
pub mod change;
pub mod conflict;
pub mod context;
pub mod contract;
pub mod entity;
pub mod error;
pub mod evidence;
pub mod external;
pub mod external_reference;
pub mod federation;
pub mod git_authority;
pub mod graph;
pub mod identity;
pub mod ids;
pub mod layout;
pub mod merge;
pub mod preset;
pub mod projection;
pub mod provenance;
pub mod refs;
pub mod relation;
pub mod repository;
pub mod retrieval;
pub mod review;
pub mod sealed_observation;
pub mod session;
pub mod spec;
pub mod stats;
pub mod temporal;
pub mod timestamp;
pub mod verification;
pub mod work;
pub mod workspace_tree;

// Re-export all public types at crate root for convenience.
pub use admission::{
    AdmissionCase, AdmissionPolicyDelta, AdmissionPolicyHash, AdmissionPolicyStamp,
    AdmissionRuleSource, AdmissionRuleSourceKind, EffectiveAdmissionPolicyStamp,
    FrozenLocalOverlay, FrozenLocalOverlayDelta, LocalAdmissionRuleSource,
    LocalAdmissionRuleSourceKind, LocalOverlayHash, LocalOverlayStamp, SensitiveArtifactAllowance,
    SensitiveArtifactKind, SharedAdmissionPolicy, ADMISSION_POLICY_SEMANTICS_VERSION,
};
pub use branch::MergeState;
pub use change::{
    ChangeOrigin, EntityDelta, LocatedEntry, RelationDelta, ResolvedArtifact, ResolvedTree,
    SemanticChange, TransactionDelta, TreeDelta, TreeEntry, TreeStateError,
};
pub use conflict::{ConflictKind, ConflictObject};
pub use context::{
    AnnotationEntry, ArtifactContextEntry, ArtifactContextKind, ContextEntry, ContextPack,
    ContextPlan, ContextPlanSeed, ProjectionLevel, TokenBudget, TrafficEntry, TrafficProximity,
    WorkItemEntry,
};
pub use contract::{Contract, ContractKind};
pub use entity::{
    Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, ParseState,
    SemanticFingerprint, SourceSpan, Visibility,
};
pub use error::{ModelError, Result};
pub use evidence::{Evidence, TestResult};
pub use external::{
    ExternalChangeAlias, ExternalObjectId, ExternalObjectKind, ExternalObjectRecord,
};
pub use external_reference::{
    ExternalReference, ExternalReferenceDelta, ExternalReferenceId,
    EXTERNAL_REFERENCE_ID_NAMESPACE_V1, EXTERNAL_REFERENCE_SCHEMA_VERSION,
};
pub use federation::{
    ActorRef, GraphCapabilitySet, GraphLocator, GraphManifest, RemoteRelation, RemoteRelationKind,
    RemoteRelationOrigin, ScopeRef, SessionLease,
};
pub use git_authority::{
    decode_git_external_object, DecodedGitObject, GitCommitCanonicalIdentity, GitCommitProjection,
    GitExternalAuthority, GitExternalAuthorityDelta, GitExternalAuthorityError, GitMaterialHead,
    GitObjectBodyLoader, GitObjectClosureEntry, GitObjectClosureManifest, GitObjectDependency,
    GitObjectDependencyKind, GitObjectFormat, GitObjectRoot, GitObjectRootSource, GitRawRef,
    GitRawTarget, GitTreeEntryMode, GitTreeEntryName, GitTreeEntryNameError,
    GIT_EXTERNAL_AUTHORITY_SCHEMA_VERSION,
};
pub use graph::{
    ChangeStore, EntityFilter, EntityStore, GraphStore, ProvenanceStore, ReviewStore, SessionStore,
    SubGraph, VerificationStore, WorkStore,
};
pub use identity::{
    compute_semantic_change_id, content_identity_from_deltas, validate_semantic_change_id,
    validate_transaction_delta,
};
pub use ids::{
    ArtifactRevisionId, AuthorId, ConflictId, ContractId, EntityId, EntityRevisionId, EvidenceId,
    FilePathId, GitObjectId, Hash256, IntentId, LanguageId, OperationId, RelationId,
    RelationRevisionId, RepoPath, RepoPathError, RepositoryId, RepositoryIdError, SemanticChangeId,
    SessionId, SpecId, WorkspaceId,
};
pub use layout::{
    ArtifactKind, FileLayout, ImportItem, ImportSection, OpaqueArtifact, ParseCompleteness,
    ShallowTrackedFile, SourceRegion, StructuredArtifact, TrackedFile,
};
pub use merge::{
    MergeConflictEntry, MergeConflictSubject, MergeDivergence, MergeEntryResolution, MergeOpening,
    MergeParentBinding, MergeResolutionPayload, MergeResolutionProvenance, MergeSide,
    MergeSideValue, MergeTransactionDelta, MergeTransactionRecord, MergeTransactionState,
    MergeWorkspaceRestorePoint, MERGE_TRANSACTION_SCHEMA_VERSION,
};
pub use preset::{
    BrokenAstBehavior, DirectoryPreset, FormattingPolicy, PolicyOverrides, PresetConfig,
    ProjectionMode, ReconcilePolicy, ReconcilePolicyProvider, ValidationLevel, WorldPreset,
};
pub use projection::{Projection, ProjectionKind};
pub use review::{
    Review, ReviewAssignment, ReviewComment, ReviewCompletionState, ReviewDecision,
    ReviewDecisionState, ReviewDiscussion, ReviewDiscussionId, ReviewDiscussionState, ReviewFilter,
    ReviewId, ReviewNote, ReviewNoteId, RiskLevel, RiskSummary,
};
pub use spec::Spec;
pub use stats::GraphStats;
pub use temporal::{is_active_at, ArtifactRevision, EntityRevision, RelationRevision};
pub use timestamp::Timestamp;

pub use provenance::{
    Actor, ActorId, ActorKind, Approval, ApprovalDecision, ApprovalId, AuditEvent, AuditEventId,
    Delegation, DelegationId,
};
pub use refs::{
    DefaultRefExpectation, DefaultRefMutation, RefExpectation, RefMutation, RefName, RefNameError,
    RefTarget, RefUpdatePolicy, RepositoryRef, RepositoryRefState, WorkspaceHead,
};
pub use relation::{
    CallArgShape, GraphNodeId, Relation, RelationEvidence, RelationKind, RelationOrigin,
};
pub use repository::{
    compute_resolved_tree_hash, AuthorityRoot, RepositoryAuthorityStore, RepositoryCommitOutcome,
    RepositoryCommitReceipt, RepositoryOperationRecord, RepositoryTransaction, RootBundle,
    WorkspaceExpectation, WorkspaceMutation, WorkspaceSemanticDelta, WorkspaceSemanticOverlay,
    WorkspaceSnapshotBinding, WorkspaceState, REPOSITORY_ROOT_SCHEMA_VERSION,
    REPOSITORY_TRANSACTION_SCHEMA_VERSION, WORKSPACE_SEMANTIC_DELTA_SCHEMA_VERSION,
    WORKSPACE_SEMANTIC_OVERLAY_SCHEMA_VERSION,
};
pub use retrieval::{ArtifactId, RetrievalKey, RetrievalKeyFileResolver};
pub use sealed_observation::{SealedObservationBinding, SEALED_OBSERVATION_BINDING_SCHEMA_VERSION};
pub use session::{
    AgentSession, CoordinationEvent, Intent, IntentConflict, IntentScope, IntentSummary, LockType,
    SessionCapabilities, SessionTransport, TrafficReport,
};
pub use verification::{
    Assertion, AssertionId, CompletionState, ContractCoverageSummary, CoverageSummary, MockHint,
    MockHintId, MockStrategy, TestCase, TestId, TestKind, TestRunner, VerificationRun,
    VerificationRunId, VerificationStatus,
};
pub use work::{
    Annotation, AnnotationFilter, AnnotationId, AnnotationKind, AnnotationTarget, ExternalRef,
    IdentityKind, IdentityRef, Priority, SemanticAnchor, StalenessState, WorkFilter, WorkId,
    WorkItem, WorkKind, WorkLink, WorkScope, WorkStatus,
};
pub use workspace_tree::{
    WorkspaceTreeArtifact, WorkspaceTreeSnapshot, WORKSPACE_TREE_SNAPSHOT_SCHEMA_VERSION,
};
