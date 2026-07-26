// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Canonical types for Kin semantic VCS.
//!
//! This crate defines all shared types used across the Kin codebase:
//! entities, relations, exact repository trees, semantic changes, refs,
//! contracts, and more.

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
pub mod federation;
pub mod git_authority;
pub mod graph;
pub mod identity;
pub mod ids;
pub mod layout;
pub mod preset;
pub mod projection;
pub mod provenance;
pub mod refs;
pub mod relation;
pub mod repository;
pub mod retrieval;
pub mod review;
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
    AdmissionPolicyDelta, AdmissionPolicyHash, AdmissionPolicyStamp, AdmissionRuleSource,
    AdmissionRuleSourceKind, AdmissionScanToken, EffectiveAdmissionPolicyStamp, FrozenLocalOverlay,
    FrozenLocalOverlayDelta, LocalAdmissionRuleSource, LocalAdmissionRuleSourceKind,
    LocalOverlayHash, LocalOverlayStamp, SensitiveArtifactAllowance, SensitiveArtifactKind,
    SharedAdmissionPolicy, ADMISSION_POLICY_SEMANTICS_VERSION,
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
    WorkspaceExpectation, WorkspaceMutation, WorkspaceSnapshotBinding, WorkspaceState,
    REPOSITORY_ROOT_SCHEMA_VERSION, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
pub use retrieval::{ArtifactId, RetrievalKey, RetrievalKeyFileResolver};
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
