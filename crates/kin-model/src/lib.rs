// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Canonical types for Kin semantic VCS.
//!
//! This crate defines all shared types used across the Kin codebase:
//! entities, relations, contracts, semantic changes, branches, and more.

pub mod branch;
pub mod change;
pub mod conflict;
pub mod context;
pub mod contract;
pub mod entity;
pub mod error;
pub mod evidence;
pub mod federation;
pub mod graph;
pub mod ids;
pub mod layout;
pub mod preset;
pub mod projection;
pub mod provenance;
pub mod relation;
pub mod retrieval;
pub mod review;
pub mod session;
pub mod spec;
pub mod stats;
pub mod temporal;
pub mod timestamp;
pub mod verification;
pub mod work;

// Re-export all public types at crate root for convenience.
pub use branch::{Branch, GraphOverlay, MergeState, WorkingCopy};
pub use change::{
    ArtifactDelta, ArtifactDeltaKind, EntityDelta, RelationDelta, SemanticChange, SourceEntryKind,
    TransactionDelta,
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
pub use federation::{
    ActorRef, GraphCapabilitySet, GraphLocator, GraphManifest, RemoteRelation, RemoteRelationKind,
    RemoteRelationOrigin, ScopeRef, SessionLease,
};
pub use graph::{
    ChangeStore, EntityFilter, EntityStore, GraphStore, ProvenanceStore, ResolvedSourceEntry,
    ReviewStore, SessionStore, SourceTreeGap, SourceTreeGapReason, SourceTreeResolution, SubGraph,
    VerificationStore, WorkStore,
};
pub use ids::{
    ArtifactRevisionId, AuthorId, BranchId, BranchName, ConflictId, ContractId, EntityId,
    EntityRevisionId, EvidenceId, FilePathId, Hash256, IntentId, LanguageId, RelationId,
    RelationRevisionId, SemanticChangeId, SessionId, SpecId,
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
pub use relation::{
    CallArgShape, GraphNodeId, Relation, RelationEvidence, RelationKind, RelationOrigin,
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
