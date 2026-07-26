// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Re-exports of canonical types from kin-model.
//!
//! All kin-db code uses kin-model's types directly. This module provides
//! a single import point for kin-db.

// IDs
pub use kin_model::{
    ArtifactId, ArtifactRevisionId, AuthorId, ConflictId, ContractId, EntityId, EntityRevisionId,
    EvidenceId, FilePathId, GitObjectId, Hash256, IntentId, LanguageId, OperationId, RefName,
    RefTarget, RelationId, RelationRevisionId, RepoPath, RepositoryId, ResolvedArtifact,
    ResolvedTree, RetrievalKey, RetrievalKeyFileResolver, SemanticChangeId, SessionId, SpecId,
    TreeEntry, TreeStateError, WorkspaceId,
};

// Entity types
pub use kin_model::{
    Entity, EntityKind, EntityMetadata, EntityRevision, EntityRole, FingerprintAlgorithm,
    ParseState, SemanticFingerprint, SourceSpan, Visibility,
};

// Relation types
pub use kin_model::{GraphNodeId, Relation, RelationKind, RelationOrigin, RelationRevision};

pub use kin_model::ArtifactRevision;
pub use kin_model::{
    EntityDelta, LocatedEntry, RelationDelta, SemanticChange, TransactionDelta, TreeDelta,
};

// Graph query types
pub use kin_model::{EntityFilter, SubGraph};

// Timestamp / review
pub use kin_model::Timestamp;
pub use kin_model::{
    Review, ReviewAssignment, ReviewComment, ReviewCompletionState, ReviewDecision,
    ReviewDecisionState, ReviewDiscussion, ReviewDiscussionId, ReviewDiscussionState, ReviewFilter,
    ReviewId, ReviewNote, ReviewNoteId,
};
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
    ArtifactKind, FileLayout, ImportItem, ImportSection, OpaqueArtifact, ParseCompleteness,
    ShallowTrackedFile, SourceRegion, StructuredArtifact, TrackedFile,
};

// Graph observability
pub use kin_model::GraphStats;

#[cfg(test)]
pub(crate) fn regular_tree_entry(byte: u8) -> TreeEntry {
    TreeEntry::blob(Hash256::from_bytes([byte; 32]), false)
}
