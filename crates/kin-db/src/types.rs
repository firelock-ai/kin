// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Re-exports of canonical types from kin-model.
//!
//! All kin-db code uses kin-model's types directly. This module provides
//! a single import point for backwards compatibility within kin-db.

// IDs
pub use kin_model::{
    AuthorId, BranchId, BranchName, ConflictId, ContractId, EntityId, EvidenceId, FilePathId,
    Hash256, IntentId, LanguageId, RelationId, SemanticChangeId, SessionId, SpecId,
};

// Entity types
pub use kin_model::{
    Entity, EntityKind, EntityMetadata, FingerprintAlgorithm, ParseState, SemanticFingerprint,
    SourceSpan, Visibility,
};

// Relation types
pub use kin_model::{Relation, RelationKind, RelationOrigin};

// Change types
pub use kin_model::{ArtifactDelta, ArtifactDeltaKind, EntityDelta, RelationDelta, SemanticChange};

// Branch types
pub use kin_model::{Branch, GraphOverlay, MergeState, WorkingCopy};

// Graph query types
pub use kin_model::{EntityFilter, SubGraph};

// Timestamp / review
pub use kin_model::Timestamp;
pub use kin_model::{RiskLevel, RiskSummary};

// Work graph (Phase 8)
pub use kin_model::{
    Annotation, AnnotationFilter, AnnotationId, AnnotationKind, AnnotationTarget, ExternalRef,
    IdentityKind, IdentityRef, Priority, SemanticAnchor, StalenessState, WorkFilter, WorkId,
    WorkItem, WorkKind, WorkLink, WorkScope, WorkStatus,
};

// Verification (Phase 9)
pub use kin_model::{
    Assertion, AssertionId, CompletionState, ContractCoverageSummary, CoverageSummary, MockHint,
    MockHintId, MockStrategy, TestCase, TestId, TestKind, TestRunner, VerificationRun,
    VerificationRunId, VerificationStatus,
};

// Contract
pub use kin_model::{Contract, ContractKind};

// Provenance (Phase 10)
pub use kin_model::{
    Actor, ActorId, ActorKind, Approval, ApprovalDecision, ApprovalId, AuditEvent, AuditEventId,
    Delegation, DelegationId,
};

// Session / intent (daemon)
pub use kin_model::{AgentSession, Intent, IntentScope, LockType};

// Layout / file tracking
pub use kin_model::{
    ArtifactKind, FileLayout, ImportItem, ImportSection, OpaqueArtifact, ShallowTrackedFile,
    SourceRegion, StructuredArtifact, TrackedFile,
};
