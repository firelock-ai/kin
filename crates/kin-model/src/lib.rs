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
pub mod graph;
pub mod ids;
pub mod layout;
pub mod projection;
pub mod provenance;
pub mod relation;
pub mod review;
pub mod session;
pub mod spec;
pub mod timestamp;
pub mod verification;
pub mod work;

// Re-export all public types at crate root for convenience.
pub use branch::{Branch, GraphOverlay, MergeState, WorkingCopy};
pub use change::{ArtifactDelta, ArtifactDeltaKind, EntityDelta, RelationDelta, SemanticChange};
pub use conflict::{ConflictKind, ConflictObject};
pub use context::{
    AnnotationEntry, ContextEntry, ContextPack, ProjectionLevel, TokenBudget, TrafficEntry,
    TrafficProximity, WorkItemEntry,
};
pub use contract::{Contract, ContractKind};
pub use entity::{
    Entity, EntityKind, EntityMetadata, FingerprintAlgorithm, ParseState, SemanticFingerprint,
    SourceSpan, Visibility,
};
pub use error::{ModelError, Result};
pub use evidence::{Evidence, TestResult};
pub use graph::{EntityFilter, GraphStore, SubGraph};
pub use ids::{
    AuthorId, BranchId, BranchName, ConflictId, ContractId, EntityId, EvidenceId, FilePathId,
    Hash256, IntentId, LanguageId, RelationId, SemanticChangeId, SessionId, SpecId,
};
pub use layout::{
    ArtifactKind, FileLayout, ImportItem, ImportSection, OpaqueArtifact, ShallowTrackedFile,
    SourceRegion, StructuredArtifact, TrackedFile,
};
pub use projection::{Projection, ProjectionKind};
pub use review::{RiskLevel, RiskSummary};
pub use spec::Spec;
pub use timestamp::Timestamp;

pub use relation::{Relation, RelationKind, RelationOrigin};
pub use session::{
    AgentSession, CoordinationEvent, Intent, IntentConflict, IntentScope, IntentSummary, LockType,
    SessionCapabilities, SessionTransport, TrafficReport,
};
pub use verification::{
    AssertionId, Assertion, CompletionState, CoverageSummary, TestCase, TestId, TestKind,
    TestRunner, VerificationStatus,
};
pub use work::{
    Annotation, AnnotationFilter, AnnotationId, AnnotationKind, AnnotationTarget, ExternalRef,
    IdentityKind, IdentityRef, Priority, SemanticAnchor, StalenessState, WorkFilter, WorkId,
    WorkItem, WorkKind, WorkLink, WorkScope, WorkStatus,
};
pub use provenance::{
    Actor, ActorId, ActorKind, Approval, ApprovalDecision, ApprovalId, AuditEvent, AuditEventId,
    Delegation, DelegationId,
};
