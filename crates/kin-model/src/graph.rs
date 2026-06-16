// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use crate::branch::Branch;
use crate::change::{SemanticChange, TransactionDelta};
use crate::entity::{Entity, EntityKind, EntityRole};
use crate::ids::*;
use crate::relation::{GraphNodeId, Relation, RelationKind};
use crate::review::{
    Review, ReviewAssignment, ReviewComment, ReviewDecision, ReviewDecisionState, ReviewDiscussion,
    ReviewDiscussionId, ReviewDiscussionState, ReviewFilter, ReviewId, ReviewNote, ReviewNoteId,
};
use crate::temporal::{ArtifactRevision, EntityRevision, RelationRevision};
use crate::verification::{ContractCoverageSummary, MockHint, VerificationRun, VerificationRunId};
use crate::work::{
    Annotation, AnnotationFilter, AnnotationId, WorkFilter, WorkId, WorkItem, WorkLink, WorkScope,
    WorkStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ===========================================================================
// Domain sub-traits — narrower interfaces for consumers that only need a
// subset of GraphStore.
// ===========================================================================

/// Core entity and relation CRUD plus graph traversal operations.
pub trait EntityStore: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn get_entity(&self, id: &EntityId) -> std::result::Result<Option<Entity>, Self::Error>;
    fn get_relations(
        &self,
        id: &EntityId,
        kinds: &[RelationKind],
    ) -> std::result::Result<Vec<Relation>, Self::Error>;
    fn get_all_relations_for_entity(
        &self,
        id: &EntityId,
    ) -> std::result::Result<Vec<Relation>, Self::Error>;
    fn get_downstream_impact(
        &self,
        id: &EntityId,
        max_depth: u32,
    ) -> std::result::Result<Vec<Entity>, Self::Error>;
    fn get_dependency_neighborhood(
        &self,
        id: &EntityId,
        depth: u32,
    ) -> std::result::Result<SubGraph, Self::Error>;
    fn expand_neighborhood(
        &self,
        entity_ids: &[EntityId],
        edge_kinds: &[RelationKind],
        depth: u32,
    ) -> std::result::Result<SubGraph, Self::Error>;
    fn traverse(
        &self,
        start: &GraphNodeId,
        edge_kinds: &[RelationKind],
        depth: u32,
    ) -> std::result::Result<SubGraph, Self::Error>;
    fn find_dead_code(&self) -> std::result::Result<Vec<Entity>, Self::Error>;
    fn has_incoming_relation_kinds(
        &self,
        id: &EntityId,
        kinds: &[RelationKind],
        exclude_same_file: bool,
    ) -> std::result::Result<bool, Self::Error>;
    fn query_entities(
        &self,
        filter: &EntityFilter,
    ) -> std::result::Result<Vec<Entity>, Self::Error>;
    fn list_all_entities(&self) -> std::result::Result<Vec<Entity>, Self::Error>;
    fn upsert_entity(&self, entity: &Entity) -> std::result::Result<(), Self::Error>;
    fn upsert_relation(&self, relation: &Relation) -> std::result::Result<(), Self::Error>;
    fn remove_entity(&self, id: &EntityId) -> std::result::Result<(), Self::Error>;
    fn remove_entities_batch(&self, ids: &[EntityId]) -> std::result::Result<(), Self::Error> {
        for id in ids {
            self.remove_entity(id)?;
        }
        Ok(())
    }
    fn remove_relation(&self, id: &RelationId) -> std::result::Result<(), Self::Error>;

    // Shallow file tracking (C2 tier)
    fn upsert_shallow_file(
        &self,
        shallow: &crate::layout::ShallowTrackedFile,
    ) -> std::result::Result<(), Self::Error>;
    fn get_shallow_file(
        &self,
        file_id: &FilePathId,
    ) -> std::result::Result<Option<crate::layout::ShallowTrackedFile>, Self::Error>;
    fn list_shallow_files(
        &self,
    ) -> std::result::Result<Vec<crate::layout::ShallowTrackedFile>, Self::Error>;
    fn upsert_structured_artifact(
        &self,
        artifact: &crate::layout::StructuredArtifact,
    ) -> std::result::Result<(), Self::Error>;
    fn get_structured_artifact(
        &self,
        file_id: &FilePathId,
    ) -> std::result::Result<Option<crate::layout::StructuredArtifact>, Self::Error>;
    fn list_structured_artifacts(
        &self,
    ) -> std::result::Result<Vec<crate::layout::StructuredArtifact>, Self::Error>;
    fn delete_structured_artifact(
        &self,
        file_id: &FilePathId,
    ) -> std::result::Result<(), Self::Error>;
    fn upsert_opaque_artifact(
        &self,
        artifact: &crate::layout::OpaqueArtifact,
    ) -> std::result::Result<(), Self::Error>;
    fn get_opaque_artifact(
        &self,
        file_id: &FilePathId,
    ) -> std::result::Result<Option<crate::layout::OpaqueArtifact>, Self::Error>;
    fn list_opaque_artifacts(
        &self,
    ) -> std::result::Result<Vec<crate::layout::OpaqueArtifact>, Self::Error>;
    fn delete_opaque_artifact(&self, file_id: &FilePathId) -> std::result::Result<(), Self::Error>;
    /// Resolve a tracked file path to its graph-assigned `ArtifactId` via the
    /// graph's artifact index, if the path is tracked. The default returns
    /// `None` for stores that do not maintain an artifact index; the in-memory
    /// graph overrides this with the real lookup so generic `GraphStore`
    /// consumers obtain graph-assigned identity instead of re-deriving it from
    /// the path (path derivation is deprecated — the graph owns artifact
    /// identity).
    fn artifact_id_for_path(&self, _path: &FilePathId) -> Option<crate::ArtifactId> {
        None
    }
    fn upsert_file_layout(
        &self,
        layout: &crate::layout::FileLayout,
    ) -> std::result::Result<(), Self::Error>;
    fn get_file_layout(
        &self,
        file_id: &FilePathId,
    ) -> std::result::Result<Option<crate::layout::FileLayout>, Self::Error>;
    fn list_file_layouts(&self)
        -> std::result::Result<Vec<crate::layout::FileLayout>, Self::Error>;
    fn get_file_hash(
        &self,
        file_id: &FilePathId,
    ) -> std::result::Result<Option<Hash256>, Self::Error>;
    fn delete_file_layout(&self, file_id: &FilePathId) -> std::result::Result<(), Self::Error>;

    /// Apply multiple transactional mutations atomically to the graph store.
    fn apply_transaction_delta(
        &self,
        delta: &TransactionDelta,
    ) -> std::result::Result<(), Self::Error> {
        for ent_delta in &delta.entity_deltas {
            match ent_delta {
                crate::change::EntityDelta::Added(entity) => {
                    self.upsert_entity(entity)?;
                }
                crate::change::EntityDelta::Modified { old: _, new } => {
                    self.upsert_entity(new)?;
                }
                crate::change::EntityDelta::Removed(id) => {
                    self.remove_entity(id)?;
                }
            }
        }
        for rel_delta in &delta.relation_deltas {
            match rel_delta {
                crate::change::RelationDelta::Added(relation) => {
                    self.upsert_relation(relation)?;
                }
                crate::change::RelationDelta::Removed(id) => {
                    self.remove_relation(id)?;
                }
            }
        }
        Ok(())
    }

    /// Batch-insert entities with a single lock acquisition and one deferred
    /// text-index refresh.  The default falls back to per-entity `upsert_entity`.
    fn upsert_entities_batch(&self, entities: &[Entity]) -> std::result::Result<(), Self::Error> {
        for entity in entities {
            self.upsert_entity(entity)?;
        }
        Ok(())
    }

    /// Batch-insert relations with a single lock acquisition and one deferred
    /// text-index refresh.  The default falls back to per-relation `upsert_relation`.
    fn upsert_relations_batch(
        &self,
        relations: &[Relation],
    ) -> std::result::Result<(), Self::Error> {
        for relation in relations {
            self.upsert_relation(relation)?;
        }
        Ok(())
    }

    /// Batch-remove relations with a single lock acquisition and one deferred
    /// text-index rebuild. The default falls back to per-relation `remove_relation`.
    fn remove_relations_batch(&self, ids: &[&RelationId]) -> std::result::Result<(), Self::Error> {
        for id in ids {
            self.remove_relation(id)?;
        }
        Ok(())
    }

    /// Atomically replace all relations of a given kind with a new set.
    /// Default impl falls back to remove_relations_batch + upsert_relations_batch.
    fn replace_relations_of_kind(
        &self,
        kind: RelationKind,
        new_relations: Vec<Relation>,
    ) -> std::result::Result<(), Self::Error> {
        // Default: scan all entities for relations of this kind, remove, then insert
        let existing: Vec<RelationId> = self
            .query_entities(&EntityFilter::default())?
            .iter()
            .flat_map(|e| self.get_all_relations_for_entity(&e.id).unwrap_or_default())
            .filter(|r| r.kind == kind)
            .map(|r| r.id)
            .collect();
        let refs: Vec<_> = existing.iter().collect();
        if !refs.is_empty() {
            self.remove_relations_batch(&refs)?;
        }
        if !new_relations.is_empty() {
            self.upsert_relations_batch(&new_relations)?;
        }
        Ok(())
    }
}

/// Semantic change DAG and branch operations.
pub trait ChangeStore: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn get_entity_history(
        &self,
        id: &EntityId,
    ) -> std::result::Result<Vec<SemanticChange>, Self::Error>;
    fn get_entity_revisions(
        &self,
        id: &EntityId,
    ) -> std::result::Result<Vec<EntityRevision>, Self::Error> {
        let changes = self.get_entity_history(id)?;
        Ok(derive_entity_revisions_from_changes(changes)
            .remove(id)
            .unwrap_or_default())
    }
    fn find_merge_bases(
        &self,
        a: &SemanticChangeId,
        b: &SemanticChangeId,
    ) -> std::result::Result<Vec<SemanticChangeId>, Self::Error>;
    fn create_change(&self, change: &SemanticChange) -> std::result::Result<(), Self::Error>;
    fn get_change(
        &self,
        id: &SemanticChangeId,
    ) -> std::result::Result<Option<SemanticChange>, Self::Error>;
    fn get_changes_since(
        &self,
        base: &SemanticChangeId,
        head: &SemanticChangeId,
    ) -> std::result::Result<Vec<SemanticChange>, Self::Error>;
    fn get_entity_history_at(
        &self,
        id: &EntityId,
        head: &SemanticChangeId,
    ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
        let (changes, _order) = collect_changes_topologically(self, head)?;
        Ok(changes
            .into_iter()
            .filter(|change| entity_is_touched_by_change(change, id))
            .collect())
    }
    fn get_entity_revisions_at(
        &self,
        id: &EntityId,
        head: &SemanticChangeId,
    ) -> std::result::Result<Vec<EntityRevision>, Self::Error> {
        let changes = self.get_entity_history_at(id, head)?;
        Ok(derive_entity_revisions_from_changes(changes)
            .remove(id)
            .unwrap_or_default())
    }
    fn resolve_entity_revision_at(
        &self,
        id: &EntityId,
        head: &SemanticChangeId,
    ) -> std::result::Result<Option<EntityRevision>, Self::Error> {
        Ok(self
            .get_entity_revisions_at(id, head)?
            .into_iter()
            .rev()
            .find(|revision| revision.ended_by.is_none()))
    }
    fn get_relation_revisions_at(
        &self,
        id: &RelationId,
        head: &SemanticChangeId,
    ) -> std::result::Result<Vec<RelationRevision>, Self::Error> {
        let (changes, _order) = collect_changes_topologically(self, head)?;
        Ok(replay_relation_revisions(changes, id))
    }
    fn resolve_relation_revision_at(
        &self,
        id: &RelationId,
        head: &SemanticChangeId,
    ) -> std::result::Result<Option<RelationRevision>, Self::Error> {
        Ok(self
            .get_relation_revisions_at(id, head)?
            .into_iter()
            .rev()
            .find(|revision| revision.ended_by.is_none()))
    }
    fn get_artifact_revisions_at(
        &self,
        file_id: &FilePathId,
        head: &SemanticChangeId,
    ) -> std::result::Result<Vec<ArtifactRevision>, Self::Error> {
        let (changes, _order) = collect_changes_topologically(self, head)?;
        Ok(replay_artifact_revisions(changes, file_id))
    }
    fn resolve_artifact_revision_at(
        &self,
        file_id: &FilePathId,
        head: &SemanticChangeId,
    ) -> std::result::Result<Option<ArtifactRevision>, Self::Error> {
        Ok(self
            .get_artifact_revisions_at(file_id, head)?
            .into_iter()
            .rev()
            .find(|revision| revision.ended_by.is_none()))
    }
    fn resolve_entity_at(
        &self,
        id: &EntityId,
        head: &SemanticChangeId,
    ) -> std::result::Result<Option<Entity>, Self::Error> {
        Ok(self
            .resolve_entity_revision_at(id, head)?
            .map(|revision| revision.entity))
    }
    fn resolve_graph_at(
        &self,
        head: &SemanticChangeId,
    ) -> std::result::Result<ResolvedGraphState, Self::Error> {
        let (changes, _order) = collect_changes_topologically(self, head)?;
        Ok(replay_graph_state(changes))
    }
    fn resolve_file_tree_at(
        &self,
        head: &SemanticChangeId,
    ) -> std::result::Result<HashMap<FilePathId, Hash256>, Self::Error> {
        let (changes, _order) = collect_changes_topologically(self, head)?;
        Ok(replay_file_tree(changes))
    }
    /// Build a topological ordinal map for all changes reachable from `head`.
    ///
    /// Maps each `SemanticChangeId` to its ordinal position in the DAG
    /// (0 = oldest/genesis, N = newest/head). Used by temporal scope queries
    /// to determine whether an entity was active at a given ref.
    fn build_change_order_at(
        &self,
        head: &SemanticChangeId,
    ) -> std::result::Result<HashMap<SemanticChangeId, u64>, Self::Error> {
        let (_changes, order) = collect_changes_topologically(self, head)?;
        Ok(order)
    }
    fn get_branch(&self, name: &BranchName) -> std::result::Result<Option<Branch>, Self::Error>;
    fn create_branch(&self, branch: &Branch) -> std::result::Result<(), Self::Error>;
    fn update_branch_head(
        &self,
        name: &BranchName,
        new_head: &SemanticChangeId,
    ) -> std::result::Result<(), Self::Error>;
    fn delete_branch(&self, name: &BranchName) -> std::result::Result<(), Self::Error>;
    fn list_branches(&self) -> std::result::Result<Vec<Branch>, Self::Error>;
}

/// Work items, annotations, and work graph relationships.
pub trait WorkStore: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn create_work_item(&self, item: &WorkItem) -> std::result::Result<(), Self::Error>;
    fn get_work_item(&self, id: &WorkId) -> std::result::Result<Option<WorkItem>, Self::Error>;
    fn list_work_items(
        &self,
        filter: &WorkFilter,
    ) -> std::result::Result<Vec<WorkItem>, Self::Error>;
    fn update_work_status(
        &self,
        id: &WorkId,
        status: WorkStatus,
    ) -> std::result::Result<(), Self::Error>;
    fn delete_work_item(&self, id: &WorkId) -> std::result::Result<(), Self::Error>;
    fn create_annotation(&self, ann: &Annotation) -> std::result::Result<(), Self::Error>;
    fn get_annotation(
        &self,
        id: &AnnotationId,
    ) -> std::result::Result<Option<Annotation>, Self::Error>;
    fn list_annotations(
        &self,
        filter: &AnnotationFilter,
    ) -> std::result::Result<Vec<Annotation>, Self::Error>;
    fn update_annotation_staleness(
        &self,
        id: &AnnotationId,
        staleness: crate::work::StalenessState,
    ) -> std::result::Result<(), Self::Error>;
    fn delete_annotation(&self, id: &AnnotationId) -> std::result::Result<(), Self::Error>;
    fn create_work_link(&self, link: &WorkLink) -> std::result::Result<(), Self::Error>;
    fn delete_work_link(&self, link: &WorkLink) -> std::result::Result<(), Self::Error>;
    fn get_work_for_scope(
        &self,
        scope: &WorkScope,
    ) -> std::result::Result<Vec<WorkItem>, Self::Error>;
    fn get_annotations_for_scope(
        &self,
        scope: &WorkScope,
    ) -> std::result::Result<Vec<Annotation>, Self::Error>;
    fn get_child_work_items(
        &self,
        parent: &WorkId,
    ) -> std::result::Result<Vec<WorkItem>, Self::Error>;
    fn get_parent_work_items(
        &self,
        child: &WorkId,
    ) -> std::result::Result<Vec<WorkItem>, Self::Error>;
    fn get_blockers(&self, work_id: &WorkId) -> std::result::Result<Vec<WorkItem>, Self::Error>;
    fn get_blocked_work_items(
        &self,
        work_id: &WorkId,
    ) -> std::result::Result<Vec<WorkItem>, Self::Error>;
    fn get_implementors(
        &self,
        work_id: &WorkId,
    ) -> std::result::Result<Vec<WorkScope>, Self::Error>;
    fn get_annotations_for_work_item(
        &self,
        work_id: &WorkId,
    ) -> std::result::Result<Vec<Annotation>, Self::Error>;
}

/// Test verification, coverage, contracts, and mock hints.
pub trait VerificationStore: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn create_test_case(
        &self,
        test: &crate::verification::TestCase,
    ) -> std::result::Result<(), Self::Error>;
    fn get_test_case(
        &self,
        id: &crate::verification::TestId,
    ) -> std::result::Result<Option<crate::verification::TestCase>, Self::Error>;
    fn get_tests_for_entity(
        &self,
        id: &EntityId,
    ) -> std::result::Result<Vec<crate::verification::TestCase>, Self::Error>;
    fn delete_test_case(
        &self,
        id: &crate::verification::TestId,
    ) -> std::result::Result<(), Self::Error>;
    fn create_assertion(
        &self,
        assertion: &crate::verification::Assertion,
    ) -> std::result::Result<(), Self::Error>;
    fn get_assertion(
        &self,
        id: &crate::verification::AssertionId,
    ) -> std::result::Result<Option<crate::verification::Assertion>, Self::Error>;
    fn get_coverage_summary(
        &self,
    ) -> std::result::Result<crate::verification::CoverageSummary, Self::Error>;
    fn create_verification_run(
        &self,
        run: &VerificationRun,
    ) -> std::result::Result<(), Self::Error>;
    fn get_verification_run(
        &self,
        id: &VerificationRunId,
    ) -> std::result::Result<Option<VerificationRun>, Self::Error>;
    fn list_runs_for_test(
        &self,
        test_id: &crate::verification::TestId,
    ) -> std::result::Result<Vec<VerificationRun>, Self::Error>;
    fn create_test_covers_entity(
        &self,
        test_id: &crate::verification::TestId,
        entity_id: &EntityId,
    ) -> std::result::Result<(), Self::Error>;
    fn create_test_covers_contract(
        &self,
        test_id: &crate::verification::TestId,
        contract_id: &ContractId,
    ) -> std::result::Result<(), Self::Error>;
    fn create_test_verifies_work(
        &self,
        test_id: &crate::verification::TestId,
        work_id: &WorkId,
    ) -> std::result::Result<(), Self::Error>;
    fn get_tests_covering_contract(
        &self,
        contract_id: &ContractId,
    ) -> std::result::Result<Vec<crate::verification::TestCase>, Self::Error>;
    fn get_tests_verifying_work(
        &self,
        work_id: &WorkId,
    ) -> std::result::Result<Vec<crate::verification::TestCase>, Self::Error>;
    fn create_mock_hint(&self, hint: &MockHint) -> std::result::Result<(), Self::Error>;
    fn get_mock_hints_for_test(
        &self,
        test_id: &crate::verification::TestId,
    ) -> std::result::Result<Vec<MockHint>, Self::Error>;
    fn link_run_proves_entity(
        &self,
        run_id: &VerificationRunId,
        entity_id: &EntityId,
    ) -> std::result::Result<(), Self::Error>;
    fn link_run_proves_work(
        &self,
        run_id: &VerificationRunId,
        work_id: &WorkId,
    ) -> std::result::Result<(), Self::Error>;
    fn list_runs_proving_entity(
        &self,
        entity_id: &EntityId,
    ) -> std::result::Result<Vec<VerificationRun>, Self::Error>;
    fn list_runs_proving_work(
        &self,
        work_id: &WorkId,
    ) -> std::result::Result<Vec<VerificationRun>, Self::Error>;
    fn create_contract(
        &self,
        contract: &crate::contract::Contract,
    ) -> std::result::Result<(), Self::Error>;
    fn get_contract(
        &self,
        id: &ContractId,
    ) -> std::result::Result<Option<crate::contract::Contract>, Self::Error>;
    fn list_contracts(&self) -> std::result::Result<Vec<crate::contract::Contract>, Self::Error>;
    fn get_contract_coverage_summary(
        &self,
    ) -> std::result::Result<ContractCoverageSummary, Self::Error>;
}

/// Actor provenance, delegations, approvals, and audit trail.
pub trait ProvenanceStore: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn create_actor(
        &self,
        actor: &crate::provenance::Actor,
    ) -> std::result::Result<(), Self::Error>;
    fn get_actor(
        &self,
        id: &crate::provenance::ActorId,
    ) -> std::result::Result<Option<crate::provenance::Actor>, Self::Error>;
    fn list_actors(&self) -> std::result::Result<Vec<crate::provenance::Actor>, Self::Error>;
    fn create_delegation(
        &self,
        delegation: &crate::provenance::Delegation,
    ) -> std::result::Result<(), Self::Error>;
    fn get_delegations_for_actor(
        &self,
        id: &crate::provenance::ActorId,
    ) -> std::result::Result<Vec<crate::provenance::Delegation>, Self::Error>;
    fn create_approval(
        &self,
        approval: &crate::provenance::Approval,
    ) -> std::result::Result<(), Self::Error>;
    fn get_approvals_for_change(
        &self,
        id: &SemanticChangeId,
    ) -> std::result::Result<Vec<crate::provenance::Approval>, Self::Error>;
    fn record_audit_event(
        &self,
        event: &crate::provenance::AuditEvent,
    ) -> std::result::Result<(), Self::Error>;
    fn query_audit_events(
        &self,
        actor_id: Option<&crate::provenance::ActorId>,
        limit: usize,
    ) -> std::result::Result<Vec<crate::provenance::AuditEvent>, Self::Error>;
}

/// Review decisions, notes, discussions, and assignments.
pub trait ReviewStore: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn create_review(&self, review: &Review) -> std::result::Result<(), Self::Error>;
    fn get_review(&self, id: &ReviewId) -> std::result::Result<Option<Review>, Self::Error>;
    fn list_reviews(&self, filter: &ReviewFilter) -> std::result::Result<Vec<Review>, Self::Error>;
    fn update_review_state(
        &self,
        id: &ReviewId,
        state: ReviewDecisionState,
    ) -> std::result::Result<(), Self::Error>;
    fn delete_review(&self, id: &ReviewId) -> std::result::Result<(), Self::Error>;

    fn add_review_decision(
        &self,
        id: &ReviewId,
        decision: &ReviewDecision,
    ) -> std::result::Result<(), Self::Error>;
    fn get_review_decisions(
        &self,
        id: &ReviewId,
    ) -> std::result::Result<Vec<ReviewDecision>, Self::Error>;

    fn add_review_note(&self, note: &ReviewNote) -> std::result::Result<(), Self::Error>;
    fn get_review_notes(&self, id: &ReviewId) -> std::result::Result<Vec<ReviewNote>, Self::Error>;
    fn delete_review_note(&self, note_id: &ReviewNoteId) -> std::result::Result<(), Self::Error>;

    fn create_review_discussion(
        &self,
        discussion: &ReviewDiscussion,
    ) -> std::result::Result<(), Self::Error>;
    fn get_review_discussions(
        &self,
        id: &ReviewId,
    ) -> std::result::Result<Vec<ReviewDiscussion>, Self::Error>;
    fn add_discussion_comment(
        &self,
        id: &ReviewDiscussionId,
        comment: &ReviewComment,
    ) -> std::result::Result<(), Self::Error>;
    fn set_discussion_state(
        &self,
        id: &ReviewDiscussionId,
        state: ReviewDiscussionState,
    ) -> std::result::Result<(), Self::Error>;

    fn assign_reviewer(
        &self,
        assignment: &ReviewAssignment,
    ) -> std::result::Result<(), Self::Error>;
    fn get_review_assignments(
        &self,
        id: &ReviewId,
    ) -> std::result::Result<Vec<ReviewAssignment>, Self::Error>;
    fn remove_reviewer(
        &self,
        review_id: &ReviewId,
        reviewer: &str,
    ) -> std::result::Result<(), Self::Error>;
}

/// Session and intent management (daemon coordination).
pub trait SessionStore: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn upsert_session(
        &self,
        session: &crate::session::AgentSession,
    ) -> std::result::Result<(), Self::Error>;
    fn get_session(
        &self,
        session_id: &SessionId,
    ) -> std::result::Result<Option<crate::session::AgentSession>, Self::Error>;
    fn delete_session(&self, session_id: &SessionId) -> std::result::Result<(), Self::Error>;
    fn list_sessions(&self) -> std::result::Result<Vec<crate::session::AgentSession>, Self::Error>;
    fn update_heartbeat(
        &self,
        session_id: &SessionId,
        heartbeat: &crate::timestamp::Timestamp,
    ) -> std::result::Result<(), Self::Error>;
    fn register_intent(
        &self,
        intent: &crate::session::Intent,
    ) -> std::result::Result<(), Self::Error>;
    fn get_intent(
        &self,
        intent_id: &IntentId,
    ) -> std::result::Result<Option<crate::session::Intent>, Self::Error>;
    fn delete_intent(&self, intent_id: &IntentId) -> std::result::Result<(), Self::Error>;
    fn list_intents_for_session(
        &self,
        session_id: &SessionId,
    ) -> std::result::Result<Vec<crate::session::Intent>, Self::Error>;
    fn list_all_intents(&self) -> std::result::Result<Vec<crate::session::Intent>, Self::Error>;
}

// ===========================================================================
// GraphStore — convenience supertrait
// ===========================================================================

/// Trait abstracting the graph database.
///
/// This is a convenience supertrait that combines all domain-specific store
/// traits. Consumers that only need a subset should bound on the narrower
/// sub-trait (e.g. `G: EntityStore`) instead.
///
/// Existing code using `G: GraphStore` continues to work unchanged — all
/// sub-trait methods are accessible through the supertrait bound.
pub trait GraphStore:
    EntityStore<Error = <Self as GraphStore>::Error>
    + ChangeStore<Error = <Self as GraphStore>::Error>
    + WorkStore<Error = <Self as GraphStore>::Error>
    + ReviewStore<Error = <Self as GraphStore>::Error>
    + VerificationStore<Error = <Self as GraphStore>::Error>
    + ProvenanceStore<Error = <Self as GraphStore>::Error>
    + SessionStore<Error = <Self as GraphStore>::Error>
    + Send
    + Sync
{
    type Error: std::error::Error + Send + Sync + 'static;
}

// ===========================================================================
// Supporting types
// ===========================================================================

/// A subgraph returned from neighborhood queries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubGraph {
    #[serde(default)]
    pub nodes: Vec<GraphNodeId>,
    pub entities: HashMap<EntityId, Entity>,
    pub relations: Vec<Relation>,
}

/// Immutable committed graph state resolved at a specific semantic ref.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResolvedGraphState {
    #[serde(default)]
    pub entities: HashMap<EntityId, Entity>,
    #[serde(default)]
    pub relations: HashMap<RelationId, Relation>,
    #[serde(default)]
    pub entity_revisions: HashMap<EntityId, Vec<EntityRevision>>,
    #[serde(default)]
    pub file_tree: HashMap<FilePathId, Hash256>,
    /// Entities that were explicitly removed by a semantic change.
    /// Maps entity ID to the removed entity and the change that removed it.
    #[serde(default)]
    pub entity_tombstones: HashMap<EntityId, (Entity, SemanticChangeId)>,
    /// Relations that were explicitly removed by a semantic change or pruned
    /// because a referenced entity was removed.
    /// Maps relation ID to the removed relation and the change that caused removal.
    #[serde(default)]
    pub relation_tombstones: HashMap<RelationId, (Relation, SemanticChangeId)>,
}

/// Filter for querying entities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntityFilter {
    pub kinds: Option<Vec<EntityKind>>,
    pub languages: Option<Vec<LanguageId>>,
    pub name_pattern: Option<String>,
    pub file_path: Option<FilePathId>,
    pub roles: Option<Vec<EntityRole>>,
}

/// Success payload of [`collect_changes_topologically`]: the topologically
/// ordered changes plus their ordinal-position map.
type TopoOrderedChanges = (Vec<SemanticChange>, HashMap<SemanticChangeId, u64>);

/// Topologically ordered changes with an ordinal position map.
///
/// The ordinal map assigns 0 to the oldest (genesis) change and N to the
/// newest (head). This total order allows temporal queries over the DAG
/// even though `SemanticChangeId` is a content hash with no natural ordering.
fn collect_changes_topologically<G: ChangeStore + ?Sized>(
    store: &G,
    head: &SemanticChangeId,
) -> std::result::Result<TopoOrderedChanges, G::Error> {
    let mut visited = HashSet::new();
    let mut ordered = Vec::new();
    enum Frame {
        Visit(SemanticChangeId),
        Emit(Box<SemanticChange>),
    }

    let mut stack = vec![Frame::Visit(*head)];
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Visit(id) => {
                if !visited.insert(id) {
                    continue;
                }
                let Some(change) = store.get_change(&id)? else {
                    continue;
                };

                stack.push(Frame::Emit(Box::new(change.clone())));
                for parent in change.parents.iter().rev() {
                    stack.push(Frame::Visit(*parent));
                }
            }
            Frame::Emit(change) => ordered.push(*change),
        }
    }

    let change_order: HashMap<SemanticChangeId, u64> = ordered
        .iter()
        .enumerate()
        .map(|(i, change)| (change.id, i as u64))
        .collect();

    Ok((ordered, change_order))
}

fn replay_graph_state<I>(changes: I) -> ResolvedGraphState
where
    I: IntoIterator<Item = SemanticChange>,
{
    let mut state = ResolvedGraphState::default();

    for change in changes {
        let change_id = change.id;
        for delta in change.entity_deltas {
            match delta {
                crate::change::EntityDelta::Added(entity) => {
                    let previous_revision = mark_matching_entity_revision_ended(
                        &mut state.entity_revisions,
                        &entity,
                        change_id,
                    );
                    state
                        .entity_revisions
                        .entry(entity.id)
                        .or_default()
                        .push(EntityRevision::new(
                            entity.clone(),
                            change_id,
                            previous_revision,
                        ));
                    state.entities.insert(entity.id, entity);
                }
                crate::change::EntityDelta::Modified { old, new } => {
                    let previous_revision = mark_matching_entity_revision_ended(
                        &mut state.entity_revisions,
                        &old,
                        change_id,
                    );
                    state
                        .entity_revisions
                        .entry(new.id)
                        .or_default()
                        .push(EntityRevision::new(
                            new.clone(),
                            change_id,
                            previous_revision,
                        ));
                    state.entities.insert(new.id, new);
                }
                crate::change::EntityDelta::Removed(entity_id) => {
                    if let Some(entries) = state.entity_revisions.get_mut(&entity_id) {
                        if let Some(previous) = entries.last_mut() {
                            previous.mark_ended(change_id);
                        }
                    }
                    if let Some(entity) = state.entities.remove(&entity_id) {
                        state
                            .entity_tombstones
                            .insert(entity_id, (entity, change_id));
                    }
                    // Prune dangling relations and tombstone them.
                    let dangling: Vec<RelationId> = state
                        .relations
                        .iter()
                        .filter(|(_, rel)| relation_mentions_entity(rel, entity_id))
                        .map(|(id, _)| *id)
                        .collect();
                    for rel_id in dangling {
                        if let Some(relation) = state.relations.remove(&rel_id) {
                            state
                                .relation_tombstones
                                .insert(rel_id, (relation, change_id));
                        }
                    }
                }
            }
        }

        for delta in change.relation_deltas {
            match delta {
                crate::change::RelationDelta::Added(relation) => {
                    state.relations.insert(relation.id, relation);
                }
                crate::change::RelationDelta::Removed(relation_id) => {
                    if let Some(relation) = state.relations.remove(&relation_id) {
                        state
                            .relation_tombstones
                            .insert(relation_id, (relation, change_id));
                    }
                }
            }
        }

        for delta in change.artifact_deltas {
            match delta.kind {
                crate::change::ArtifactDeltaKind::Added
                | crate::change::ArtifactDeltaKind::Modified => {
                    if let Some(hash) = delta.new_hash {
                        state.file_tree.insert(delta.file_id, hash);
                    }
                }
                crate::change::ArtifactDeltaKind::Removed => {
                    state.file_tree.remove(&delta.file_id);
                }
            }
        }
    }

    state
}

pub fn derive_entity_revisions_from_changes<I>(changes: I) -> HashMap<EntityId, Vec<EntityRevision>>
where
    I: IntoIterator<Item = SemanticChange>,
{
    replay_graph_state(changes).entity_revisions
}

fn replay_relation_revisions<I>(changes: I, relation_id: &RelationId) -> Vec<RelationRevision>
where
    I: IntoIterator<Item = SemanticChange>,
{
    let mut revisions: Vec<RelationRevision> = Vec::new();
    let mut active_revision: Option<usize> = None;

    for change in changes {
        let change_id = change.id;
        for delta in change.relation_deltas {
            match delta {
                crate::change::RelationDelta::Added(relation) if relation.id == *relation_id => {
                    let previous_revision = active_revision
                        .and_then(|index| revisions.get_mut(index))
                        .map(|revision| {
                            revision.mark_ended(change_id);
                            revision.revision_id
                        });
                    revisions.push(RelationRevision::new(
                        relation,
                        change_id,
                        previous_revision,
                    ));
                    active_revision = Some(revisions.len() - 1);
                }
                crate::change::RelationDelta::Removed(removed_id) if removed_id == *relation_id => {
                    if let Some(index) = active_revision.take() {
                        if let Some(revision) = revisions.get_mut(index) {
                            revision.mark_ended(change_id);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    revisions
}

fn replay_artifact_revisions<I>(changes: I, file_id: &FilePathId) -> Vec<ArtifactRevision>
where
    I: IntoIterator<Item = SemanticChange>,
{
    let mut revisions: Vec<ArtifactRevision> = Vec::new();
    let mut active_revision: Option<usize> = None;

    for change in changes {
        let change_id = change.id;
        for delta in change.artifact_deltas {
            if delta.file_id != *file_id {
                continue;
            }

            match delta.kind {
                crate::change::ArtifactDeltaKind::Added
                | crate::change::ArtifactDeltaKind::Modified => {
                    let Some(hash) = delta.new_hash else {
                        continue;
                    };
                    let previous_revision = active_revision
                        .and_then(|index| revisions.get_mut(index))
                        .map(|revision| {
                            revision.mark_ended(change_id);
                            revision.revision_id
                        });
                    revisions.push(ArtifactRevision::new(
                        delta.file_id,
                        hash,
                        delta.kind,
                        change_id,
                        previous_revision,
                    ));
                    active_revision = Some(revisions.len() - 1);
                }
                crate::change::ArtifactDeltaKind::Removed => {
                    if let Some(index) = active_revision.take() {
                        if let Some(revision) = revisions.get_mut(index) {
                            revision.mark_ended(change_id);
                        }
                    }
                }
            }
        }
    }

    revisions
}

fn replay_file_tree<I>(changes: I) -> HashMap<FilePathId, Hash256>
where
    I: IntoIterator<Item = SemanticChange>,
{
    let mut file_tree = HashMap::new();

    for change in changes {
        for delta in change.artifact_deltas {
            match delta.kind {
                crate::change::ArtifactDeltaKind::Added
                | crate::change::ArtifactDeltaKind::Modified => {
                    if let Some(hash) = delta.new_hash {
                        file_tree.insert(delta.file_id, hash);
                    }
                }
                crate::change::ArtifactDeltaKind::Removed => {
                    file_tree.remove(&delta.file_id);
                }
            }
        }
    }

    file_tree
}

fn entity_is_touched_by_change(change: &SemanticChange, entity_id: &EntityId) -> bool {
    change.entity_deltas.iter().any(|delta| match delta {
        crate::change::EntityDelta::Added(entity) => entity.id == *entity_id,
        crate::change::EntityDelta::Modified { old, new } => {
            old.id == *entity_id || new.id == *entity_id
        }
        crate::change::EntityDelta::Removed(removed_id) => removed_id == entity_id,
    })
}

fn mark_matching_entity_revision_ended(
    revisions: &mut HashMap<EntityId, Vec<EntityRevision>>,
    entity: &Entity,
    ended_by: SemanticChangeId,
) -> Option<EntityRevisionId> {
    revisions
        .get_mut(&entity.id)
        .and_then(|entries| {
            let match_index = entries
                .iter()
                .enumerate()
                .rev()
                .find(|(_, revision)| entities_match_for_revision(&revision.entity, entity))
                .map(|(index, _)| index)
                .or_else(|| entries.len().checked_sub(1));
            match_index.and_then(|index| entries.get_mut(index))
        })
        .map(|revision| {
            revision.mark_ended(ended_by);
            revision.revision_id
        })
}

fn entities_match_for_revision(left: &Entity, right: &Entity) -> bool {
    left.id == right.id
        && left.kind == right.kind
        && left.name == right.name
        && left.language == right.language
        && left.fingerprint.ast_hash == right.fingerprint.ast_hash
        && left.fingerprint.signature_hash == right.fingerprint.signature_hash
        && left.fingerprint.behavior_hash == right.fingerprint.behavior_hash
        && left.file_origin == right.file_origin
        && left.span == right.span
        && left.signature == right.signature
        && left.visibility == right.visibility
        && left.role == right.role
        && left.doc_summary == right.doc_summary
        && left.metadata.extra == right.metadata.extra
        && left.lineage_parent == right.lineage_parent
}

fn relation_mentions_entity(relation: &Relation, entity_id: EntityId) -> bool {
    matches!(relation.src, GraphNodeId::Entity(id) if id == entity_id)
        || matches!(relation.dst, GraphNodeId::Entity(id) if id == entity_id)
}

// ===========================================================================
// Blanket impls — &G delegates to G for every trait
// ===========================================================================

impl<G: EntityStore> EntityStore for &G {
    type Error = G::Error;

    fn get_entity(&self, id: &EntityId) -> std::result::Result<Option<Entity>, Self::Error> {
        (**self).get_entity(id)
    }
    fn get_relations(
        &self,
        id: &EntityId,
        kinds: &[RelationKind],
    ) -> std::result::Result<Vec<Relation>, Self::Error> {
        (**self).get_relations(id, kinds)
    }
    fn get_all_relations_for_entity(
        &self,
        id: &EntityId,
    ) -> std::result::Result<Vec<Relation>, Self::Error> {
        (**self).get_all_relations_for_entity(id)
    }
    fn get_downstream_impact(
        &self,
        id: &EntityId,
        max_depth: u32,
    ) -> std::result::Result<Vec<Entity>, Self::Error> {
        (**self).get_downstream_impact(id, max_depth)
    }
    fn get_dependency_neighborhood(
        &self,
        id: &EntityId,
        depth: u32,
    ) -> std::result::Result<SubGraph, Self::Error> {
        (**self).get_dependency_neighborhood(id, depth)
    }
    fn expand_neighborhood(
        &self,
        entity_ids: &[EntityId],
        edge_kinds: &[RelationKind],
        depth: u32,
    ) -> std::result::Result<SubGraph, Self::Error> {
        (**self).expand_neighborhood(entity_ids, edge_kinds, depth)
    }
    fn traverse(
        &self,
        start: &GraphNodeId,
        edge_kinds: &[RelationKind],
        depth: u32,
    ) -> std::result::Result<SubGraph, Self::Error> {
        (**self).traverse(start, edge_kinds, depth)
    }
    fn find_dead_code(&self) -> std::result::Result<Vec<Entity>, Self::Error> {
        (**self).find_dead_code()
    }
    fn has_incoming_relation_kinds(
        &self,
        id: &EntityId,
        kinds: &[RelationKind],
        exclude_same_file: bool,
    ) -> std::result::Result<bool, Self::Error> {
        (**self).has_incoming_relation_kinds(id, kinds, exclude_same_file)
    }
    fn query_entities(
        &self,
        filter: &EntityFilter,
    ) -> std::result::Result<Vec<Entity>, Self::Error> {
        (**self).query_entities(filter)
    }
    fn list_all_entities(&self) -> std::result::Result<Vec<Entity>, Self::Error> {
        (**self).list_all_entities()
    }
    fn upsert_entity(&self, entity: &Entity) -> std::result::Result<(), Self::Error> {
        (**self).upsert_entity(entity)
    }
    fn upsert_relation(&self, relation: &Relation) -> std::result::Result<(), Self::Error> {
        (**self).upsert_relation(relation)
    }
    fn remove_entity(&self, id: &EntityId) -> std::result::Result<(), Self::Error> {
        (**self).remove_entity(id)
    }
    fn remove_entities_batch(&self, ids: &[EntityId]) -> std::result::Result<(), Self::Error> {
        (**self).remove_entities_batch(ids)
    }
    fn remove_relation(&self, id: &RelationId) -> std::result::Result<(), Self::Error> {
        (**self).remove_relation(id)
    }
    fn upsert_shallow_file(
        &self,
        shallow: &crate::layout::ShallowTrackedFile,
    ) -> std::result::Result<(), Self::Error> {
        (**self).upsert_shallow_file(shallow)
    }
    fn get_shallow_file(
        &self,
        file_id: &FilePathId,
    ) -> std::result::Result<Option<crate::layout::ShallowTrackedFile>, Self::Error> {
        (**self).get_shallow_file(file_id)
    }
    fn list_shallow_files(
        &self,
    ) -> std::result::Result<Vec<crate::layout::ShallowTrackedFile>, Self::Error> {
        (**self).list_shallow_files()
    }
    fn upsert_structured_artifact(
        &self,
        artifact: &crate::layout::StructuredArtifact,
    ) -> std::result::Result<(), Self::Error> {
        (**self).upsert_structured_artifact(artifact)
    }
    fn get_structured_artifact(
        &self,
        file_id: &FilePathId,
    ) -> std::result::Result<Option<crate::layout::StructuredArtifact>, Self::Error> {
        (**self).get_structured_artifact(file_id)
    }
    fn list_structured_artifacts(
        &self,
    ) -> std::result::Result<Vec<crate::layout::StructuredArtifact>, Self::Error> {
        (**self).list_structured_artifacts()
    }
    fn delete_structured_artifact(
        &self,
        file_id: &FilePathId,
    ) -> std::result::Result<(), Self::Error> {
        (**self).delete_structured_artifact(file_id)
    }
    fn upsert_opaque_artifact(
        &self,
        artifact: &crate::layout::OpaqueArtifact,
    ) -> std::result::Result<(), Self::Error> {
        (**self).upsert_opaque_artifact(artifact)
    }
    fn get_opaque_artifact(
        &self,
        file_id: &FilePathId,
    ) -> std::result::Result<Option<crate::layout::OpaqueArtifact>, Self::Error> {
        (**self).get_opaque_artifact(file_id)
    }
    fn list_opaque_artifacts(
        &self,
    ) -> std::result::Result<Vec<crate::layout::OpaqueArtifact>, Self::Error> {
        (**self).list_opaque_artifacts()
    }
    fn delete_opaque_artifact(&self, file_id: &FilePathId) -> std::result::Result<(), Self::Error> {
        (**self).delete_opaque_artifact(file_id)
    }
    fn upsert_file_layout(
        &self,
        layout: &crate::layout::FileLayout,
    ) -> std::result::Result<(), Self::Error> {
        (**self).upsert_file_layout(layout)
    }
    fn get_file_layout(
        &self,
        file_id: &FilePathId,
    ) -> std::result::Result<Option<crate::layout::FileLayout>, Self::Error> {
        (**self).get_file_layout(file_id)
    }
    fn list_file_layouts(
        &self,
    ) -> std::result::Result<Vec<crate::layout::FileLayout>, Self::Error> {
        (**self).list_file_layouts()
    }
    fn get_file_hash(
        &self,
        file_id: &FilePathId,
    ) -> std::result::Result<Option<Hash256>, Self::Error> {
        (**self).get_file_hash(file_id)
    }
    fn delete_file_layout(&self, file_id: &FilePathId) -> std::result::Result<(), Self::Error> {
        (**self).delete_file_layout(file_id)
    }
}

impl<G: ChangeStore> ChangeStore for &G {
    type Error = G::Error;

    fn get_entity_history(
        &self,
        id: &EntityId,
    ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
        (**self).get_entity_history(id)
    }
    fn find_merge_bases(
        &self,
        a: &SemanticChangeId,
        b: &SemanticChangeId,
    ) -> std::result::Result<Vec<SemanticChangeId>, Self::Error> {
        (**self).find_merge_bases(a, b)
    }
    fn create_change(&self, change: &SemanticChange) -> std::result::Result<(), Self::Error> {
        (**self).create_change(change)
    }
    fn get_change(
        &self,
        id: &SemanticChangeId,
    ) -> std::result::Result<Option<SemanticChange>, Self::Error> {
        (**self).get_change(id)
    }
    fn get_changes_since(
        &self,
        base: &SemanticChangeId,
        head: &SemanticChangeId,
    ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
        (**self).get_changes_since(base, head)
    }
    fn get_branch(&self, name: &BranchName) -> std::result::Result<Option<Branch>, Self::Error> {
        (**self).get_branch(name)
    }
    fn create_branch(&self, branch: &Branch) -> std::result::Result<(), Self::Error> {
        (**self).create_branch(branch)
    }
    fn update_branch_head(
        &self,
        name: &BranchName,
        new_head: &SemanticChangeId,
    ) -> std::result::Result<(), Self::Error> {
        (**self).update_branch_head(name, new_head)
    }
    fn delete_branch(&self, name: &BranchName) -> std::result::Result<(), Self::Error> {
        (**self).delete_branch(name)
    }
    fn list_branches(&self) -> std::result::Result<Vec<Branch>, Self::Error> {
        (**self).list_branches()
    }
}

impl<G: WorkStore> WorkStore for &G {
    type Error = G::Error;

    fn create_work_item(&self, item: &WorkItem) -> std::result::Result<(), Self::Error> {
        (**self).create_work_item(item)
    }
    fn get_work_item(&self, id: &WorkId) -> std::result::Result<Option<WorkItem>, Self::Error> {
        (**self).get_work_item(id)
    }
    fn list_work_items(
        &self,
        filter: &WorkFilter,
    ) -> std::result::Result<Vec<WorkItem>, Self::Error> {
        (**self).list_work_items(filter)
    }
    fn update_work_status(
        &self,
        id: &WorkId,
        status: WorkStatus,
    ) -> std::result::Result<(), Self::Error> {
        (**self).update_work_status(id, status)
    }
    fn delete_work_item(&self, id: &WorkId) -> std::result::Result<(), Self::Error> {
        (**self).delete_work_item(id)
    }
    fn create_annotation(&self, ann: &Annotation) -> std::result::Result<(), Self::Error> {
        (**self).create_annotation(ann)
    }
    fn get_annotation(
        &self,
        id: &AnnotationId,
    ) -> std::result::Result<Option<Annotation>, Self::Error> {
        (**self).get_annotation(id)
    }
    fn list_annotations(
        &self,
        filter: &AnnotationFilter,
    ) -> std::result::Result<Vec<Annotation>, Self::Error> {
        (**self).list_annotations(filter)
    }
    fn update_annotation_staleness(
        &self,
        id: &AnnotationId,
        staleness: crate::work::StalenessState,
    ) -> std::result::Result<(), Self::Error> {
        (**self).update_annotation_staleness(id, staleness)
    }
    fn delete_annotation(&self, id: &AnnotationId) -> std::result::Result<(), Self::Error> {
        (**self).delete_annotation(id)
    }
    fn create_work_link(&self, link: &WorkLink) -> std::result::Result<(), Self::Error> {
        (**self).create_work_link(link)
    }
    fn delete_work_link(&self, link: &WorkLink) -> std::result::Result<(), Self::Error> {
        (**self).delete_work_link(link)
    }
    fn get_work_for_scope(
        &self,
        scope: &WorkScope,
    ) -> std::result::Result<Vec<WorkItem>, Self::Error> {
        (**self).get_work_for_scope(scope)
    }
    fn get_annotations_for_scope(
        &self,
        scope: &WorkScope,
    ) -> std::result::Result<Vec<Annotation>, Self::Error> {
        (**self).get_annotations_for_scope(scope)
    }
    fn get_child_work_items(
        &self,
        parent: &WorkId,
    ) -> std::result::Result<Vec<WorkItem>, Self::Error> {
        (**self).get_child_work_items(parent)
    }
    fn get_parent_work_items(
        &self,
        child: &WorkId,
    ) -> std::result::Result<Vec<WorkItem>, Self::Error> {
        (**self).get_parent_work_items(child)
    }
    fn get_blockers(&self, work_id: &WorkId) -> std::result::Result<Vec<WorkItem>, Self::Error> {
        (**self).get_blockers(work_id)
    }
    fn get_blocked_work_items(
        &self,
        work_id: &WorkId,
    ) -> std::result::Result<Vec<WorkItem>, Self::Error> {
        (**self).get_blocked_work_items(work_id)
    }
    fn get_implementors(
        &self,
        work_id: &WorkId,
    ) -> std::result::Result<Vec<WorkScope>, Self::Error> {
        (**self).get_implementors(work_id)
    }
    fn get_annotations_for_work_item(
        &self,
        work_id: &WorkId,
    ) -> std::result::Result<Vec<Annotation>, Self::Error> {
        (**self).get_annotations_for_work_item(work_id)
    }
}

impl<G: ReviewStore> ReviewStore for &G {
    type Error = G::Error;

    fn create_review(&self, review: &Review) -> std::result::Result<(), Self::Error> {
        (**self).create_review(review)
    }
    fn get_review(&self, id: &ReviewId) -> std::result::Result<Option<Review>, Self::Error> {
        (**self).get_review(id)
    }
    fn list_reviews(&self, filter: &ReviewFilter) -> std::result::Result<Vec<Review>, Self::Error> {
        (**self).list_reviews(filter)
    }
    fn update_review_state(
        &self,
        id: &ReviewId,
        state: ReviewDecisionState,
    ) -> std::result::Result<(), Self::Error> {
        (**self).update_review_state(id, state)
    }
    fn delete_review(&self, id: &ReviewId) -> std::result::Result<(), Self::Error> {
        (**self).delete_review(id)
    }
    fn add_review_decision(
        &self,
        id: &ReviewId,
        decision: &ReviewDecision,
    ) -> std::result::Result<(), Self::Error> {
        (**self).add_review_decision(id, decision)
    }
    fn get_review_decisions(
        &self,
        id: &ReviewId,
    ) -> std::result::Result<Vec<ReviewDecision>, Self::Error> {
        (**self).get_review_decisions(id)
    }
    fn add_review_note(&self, note: &ReviewNote) -> std::result::Result<(), Self::Error> {
        (**self).add_review_note(note)
    }
    fn get_review_notes(&self, id: &ReviewId) -> std::result::Result<Vec<ReviewNote>, Self::Error> {
        (**self).get_review_notes(id)
    }
    fn delete_review_note(&self, note_id: &ReviewNoteId) -> std::result::Result<(), Self::Error> {
        (**self).delete_review_note(note_id)
    }
    fn create_review_discussion(
        &self,
        discussion: &ReviewDiscussion,
    ) -> std::result::Result<(), Self::Error> {
        (**self).create_review_discussion(discussion)
    }
    fn get_review_discussions(
        &self,
        id: &ReviewId,
    ) -> std::result::Result<Vec<ReviewDiscussion>, Self::Error> {
        (**self).get_review_discussions(id)
    }
    fn add_discussion_comment(
        &self,
        id: &ReviewDiscussionId,
        comment: &ReviewComment,
    ) -> std::result::Result<(), Self::Error> {
        (**self).add_discussion_comment(id, comment)
    }
    fn set_discussion_state(
        &self,
        id: &ReviewDiscussionId,
        state: ReviewDiscussionState,
    ) -> std::result::Result<(), Self::Error> {
        (**self).set_discussion_state(id, state)
    }
    fn assign_reviewer(
        &self,
        assignment: &ReviewAssignment,
    ) -> std::result::Result<(), Self::Error> {
        (**self).assign_reviewer(assignment)
    }
    fn get_review_assignments(
        &self,
        id: &ReviewId,
    ) -> std::result::Result<Vec<ReviewAssignment>, Self::Error> {
        (**self).get_review_assignments(id)
    }
    fn remove_reviewer(
        &self,
        review_id: &ReviewId,
        reviewer: &str,
    ) -> std::result::Result<(), Self::Error> {
        (**self).remove_reviewer(review_id, reviewer)
    }
}

impl<G: VerificationStore> VerificationStore for &G {
    type Error = G::Error;

    fn create_test_case(
        &self,
        test: &crate::verification::TestCase,
    ) -> std::result::Result<(), Self::Error> {
        (**self).create_test_case(test)
    }
    fn get_test_case(
        &self,
        id: &crate::verification::TestId,
    ) -> std::result::Result<Option<crate::verification::TestCase>, Self::Error> {
        (**self).get_test_case(id)
    }
    fn get_tests_for_entity(
        &self,
        id: &EntityId,
    ) -> std::result::Result<Vec<crate::verification::TestCase>, Self::Error> {
        (**self).get_tests_for_entity(id)
    }
    fn delete_test_case(
        &self,
        id: &crate::verification::TestId,
    ) -> std::result::Result<(), Self::Error> {
        (**self).delete_test_case(id)
    }
    fn create_assertion(
        &self,
        assertion: &crate::verification::Assertion,
    ) -> std::result::Result<(), Self::Error> {
        (**self).create_assertion(assertion)
    }
    fn get_assertion(
        &self,
        id: &crate::verification::AssertionId,
    ) -> std::result::Result<Option<crate::verification::Assertion>, Self::Error> {
        (**self).get_assertion(id)
    }
    fn get_coverage_summary(
        &self,
    ) -> std::result::Result<crate::verification::CoverageSummary, Self::Error> {
        (**self).get_coverage_summary()
    }
    fn create_verification_run(
        &self,
        run: &VerificationRun,
    ) -> std::result::Result<(), Self::Error> {
        (**self).create_verification_run(run)
    }
    fn get_verification_run(
        &self,
        id: &VerificationRunId,
    ) -> std::result::Result<Option<VerificationRun>, Self::Error> {
        (**self).get_verification_run(id)
    }
    fn list_runs_for_test(
        &self,
        test_id: &crate::verification::TestId,
    ) -> std::result::Result<Vec<VerificationRun>, Self::Error> {
        (**self).list_runs_for_test(test_id)
    }
    fn create_test_covers_entity(
        &self,
        test_id: &crate::verification::TestId,
        entity_id: &EntityId,
    ) -> std::result::Result<(), Self::Error> {
        (**self).create_test_covers_entity(test_id, entity_id)
    }
    fn create_test_covers_contract(
        &self,
        test_id: &crate::verification::TestId,
        contract_id: &ContractId,
    ) -> std::result::Result<(), Self::Error> {
        (**self).create_test_covers_contract(test_id, contract_id)
    }
    fn create_test_verifies_work(
        &self,
        test_id: &crate::verification::TestId,
        work_id: &WorkId,
    ) -> std::result::Result<(), Self::Error> {
        (**self).create_test_verifies_work(test_id, work_id)
    }
    fn get_tests_covering_contract(
        &self,
        contract_id: &ContractId,
    ) -> std::result::Result<Vec<crate::verification::TestCase>, Self::Error> {
        (**self).get_tests_covering_contract(contract_id)
    }
    fn get_tests_verifying_work(
        &self,
        work_id: &WorkId,
    ) -> std::result::Result<Vec<crate::verification::TestCase>, Self::Error> {
        (**self).get_tests_verifying_work(work_id)
    }
    fn create_mock_hint(&self, hint: &MockHint) -> std::result::Result<(), Self::Error> {
        (**self).create_mock_hint(hint)
    }
    fn get_mock_hints_for_test(
        &self,
        test_id: &crate::verification::TestId,
    ) -> std::result::Result<Vec<MockHint>, Self::Error> {
        (**self).get_mock_hints_for_test(test_id)
    }
    fn link_run_proves_entity(
        &self,
        run_id: &VerificationRunId,
        entity_id: &EntityId,
    ) -> std::result::Result<(), Self::Error> {
        (**self).link_run_proves_entity(run_id, entity_id)
    }
    fn link_run_proves_work(
        &self,
        run_id: &VerificationRunId,
        work_id: &WorkId,
    ) -> std::result::Result<(), Self::Error> {
        (**self).link_run_proves_work(run_id, work_id)
    }
    fn list_runs_proving_entity(
        &self,
        entity_id: &EntityId,
    ) -> std::result::Result<Vec<VerificationRun>, Self::Error> {
        (**self).list_runs_proving_entity(entity_id)
    }
    fn list_runs_proving_work(
        &self,
        work_id: &WorkId,
    ) -> std::result::Result<Vec<VerificationRun>, Self::Error> {
        (**self).list_runs_proving_work(work_id)
    }
    fn create_contract(
        &self,
        contract: &crate::contract::Contract,
    ) -> std::result::Result<(), Self::Error> {
        (**self).create_contract(contract)
    }
    fn get_contract(
        &self,
        id: &ContractId,
    ) -> std::result::Result<Option<crate::contract::Contract>, Self::Error> {
        (**self).get_contract(id)
    }
    fn list_contracts(&self) -> std::result::Result<Vec<crate::contract::Contract>, Self::Error> {
        (**self).list_contracts()
    }
    fn get_contract_coverage_summary(
        &self,
    ) -> std::result::Result<ContractCoverageSummary, Self::Error> {
        (**self).get_contract_coverage_summary()
    }
}

impl<G: ProvenanceStore> ProvenanceStore for &G {
    type Error = G::Error;

    fn create_actor(
        &self,
        actor: &crate::provenance::Actor,
    ) -> std::result::Result<(), Self::Error> {
        (**self).create_actor(actor)
    }
    fn get_actor(
        &self,
        id: &crate::provenance::ActorId,
    ) -> std::result::Result<Option<crate::provenance::Actor>, Self::Error> {
        (**self).get_actor(id)
    }
    fn list_actors(&self) -> std::result::Result<Vec<crate::provenance::Actor>, Self::Error> {
        (**self).list_actors()
    }
    fn create_delegation(
        &self,
        delegation: &crate::provenance::Delegation,
    ) -> std::result::Result<(), Self::Error> {
        (**self).create_delegation(delegation)
    }
    fn get_delegations_for_actor(
        &self,
        id: &crate::provenance::ActorId,
    ) -> std::result::Result<Vec<crate::provenance::Delegation>, Self::Error> {
        (**self).get_delegations_for_actor(id)
    }
    fn create_approval(
        &self,
        approval: &crate::provenance::Approval,
    ) -> std::result::Result<(), Self::Error> {
        (**self).create_approval(approval)
    }
    fn get_approvals_for_change(
        &self,
        id: &SemanticChangeId,
    ) -> std::result::Result<Vec<crate::provenance::Approval>, Self::Error> {
        (**self).get_approvals_for_change(id)
    }
    fn record_audit_event(
        &self,
        event: &crate::provenance::AuditEvent,
    ) -> std::result::Result<(), Self::Error> {
        (**self).record_audit_event(event)
    }
    fn query_audit_events(
        &self,
        actor_id: Option<&crate::provenance::ActorId>,
        limit: usize,
    ) -> std::result::Result<Vec<crate::provenance::AuditEvent>, Self::Error> {
        (**self).query_audit_events(actor_id, limit)
    }
}

impl<G: SessionStore> SessionStore for &G {
    type Error = G::Error;

    fn upsert_session(
        &self,
        session: &crate::session::AgentSession,
    ) -> std::result::Result<(), Self::Error> {
        (**self).upsert_session(session)
    }
    fn get_session(
        &self,
        session_id: &SessionId,
    ) -> std::result::Result<Option<crate::session::AgentSession>, Self::Error> {
        (**self).get_session(session_id)
    }
    fn delete_session(&self, session_id: &SessionId) -> std::result::Result<(), Self::Error> {
        (**self).delete_session(session_id)
    }
    fn list_sessions(&self) -> std::result::Result<Vec<crate::session::AgentSession>, Self::Error> {
        (**self).list_sessions()
    }
    fn update_heartbeat(
        &self,
        session_id: &SessionId,
        heartbeat: &crate::timestamp::Timestamp,
    ) -> std::result::Result<(), Self::Error> {
        (**self).update_heartbeat(session_id, heartbeat)
    }
    fn register_intent(
        &self,
        intent: &crate::session::Intent,
    ) -> std::result::Result<(), Self::Error> {
        (**self).register_intent(intent)
    }
    fn get_intent(
        &self,
        intent_id: &IntentId,
    ) -> std::result::Result<Option<crate::session::Intent>, Self::Error> {
        (**self).get_intent(intent_id)
    }
    fn delete_intent(&self, intent_id: &IntentId) -> std::result::Result<(), Self::Error> {
        (**self).delete_intent(intent_id)
    }
    fn list_intents_for_session(
        &self,
        session_id: &SessionId,
    ) -> std::result::Result<Vec<crate::session::Intent>, Self::Error> {
        (**self).list_intents_for_session(session_id)
    }
    fn list_all_intents(&self) -> std::result::Result<Vec<crate::session::Intent>, Self::Error> {
        (**self).list_all_intents()
    }
}

/// Blanket impl: any shared reference to a GraphStore is also a GraphStore.
/// This allows `&InMemoryGraph` (from Arc::deref) to satisfy `G: GraphStore` bounds.
impl<G: GraphStore> GraphStore for &G {
    type Error = <G as GraphStore>::Error;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::{EntityDelta, RelationDelta, SemanticChange};
    use crate::entity::{
        Entity, EntityKind, EntityMetadata, FingerprintAlgorithm, SemanticFingerprint, Visibility,
    };
    use crate::relation::{GraphNodeId, Relation, RelationKind, RelationOrigin};
    use crate::timestamp::Timestamp;

    fn make_change_id(byte: u8) -> SemanticChangeId {
        SemanticChangeId::from_hash(Hash256::from_bytes([byte; 32]))
    }

    fn make_entity(id: EntityId, name: &str) -> Entity {
        Entity {
            id,
            kind: EntityKind::Function,
            name: name.into(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: Default::default(),
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn make_relation(id: RelationId, src: EntityId, dst: EntityId) -> Relation {
        Relation {
            id,
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    fn make_semantic_change(
        id: SemanticChangeId,
        parents: Vec<SemanticChangeId>,
        entity_deltas: Vec<EntityDelta>,
        relation_deltas: Vec<RelationDelta>,
    ) -> SemanticChange {
        SemanticChange {
            id,
            parents,
            timestamp: Timestamp::now(),
            author: AuthorId("test".into()),
            message: "test change".into(),
            entity_deltas,
            relation_deltas,
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        }
    }

    #[test]
    fn entity_tombstone_on_removal() {
        let c1 = make_change_id(1);
        let c2 = make_change_id(2);
        let c3 = make_change_id(3);

        let entity_a_id = EntityId::new();
        let entity_b_id = EntityId::new();
        let entity_a = make_entity(entity_a_id, "a");
        let entity_b = make_entity(entity_b_id, "b");

        let changes = vec![
            make_semantic_change(
                c1,
                vec![],
                vec![EntityDelta::Added(entity_a.clone())],
                vec![],
            ),
            make_semantic_change(
                c2,
                vec![c1],
                vec![EntityDelta::Added(entity_b.clone())],
                vec![],
            ),
            make_semantic_change(
                c3,
                vec![c2],
                vec![EntityDelta::Removed(entity_a_id)],
                vec![],
            ),
        ];

        let state = replay_graph_state(changes);

        assert!(
            !state.entities.contains_key(&entity_a_id),
            "entity A should be removed from entities"
        );
        assert!(
            state.entities.contains_key(&entity_b_id),
            "entity B should still be in entities"
        );
        assert!(
            state.entity_tombstones.contains_key(&entity_a_id),
            "entity A should be in tombstones"
        );
        let (tombstoned_entity, removal_change) =
            state.entity_tombstones.get(&entity_a_id).unwrap();
        assert_eq!(tombstoned_entity.name, "a");
        assert_eq!(*removal_change, c3);
        assert!(
            state.entity_tombstones.is_empty()
                || !state.entity_tombstones.contains_key(&entity_b_id),
            "entity B should NOT be in tombstones"
        );
    }

    #[test]
    fn no_tombstones_before_removal() {
        let c1 = make_change_id(1);
        let c2 = make_change_id(2);

        let entity_a_id = EntityId::new();
        let entity_b_id = EntityId::new();
        let entity_a = make_entity(entity_a_id, "a");
        let entity_b = make_entity(entity_b_id, "b");

        let changes = vec![
            make_semantic_change(c1, vec![], vec![EntityDelta::Added(entity_a)], vec![]),
            make_semantic_change(c2, vec![c1], vec![EntityDelta::Added(entity_b)], vec![]),
        ];

        let state = replay_graph_state(changes);

        assert!(state.entities.contains_key(&entity_a_id));
        assert!(state.entities.contains_key(&entity_b_id));
        assert!(state.entity_tombstones.is_empty());
        assert!(state.relation_tombstones.is_empty());
    }

    #[test]
    fn relation_tombstone_on_explicit_removal() {
        let c1 = make_change_id(1);
        let c2 = make_change_id(2);
        let c3 = make_change_id(3);

        let entity_a_id = EntityId::new();
        let entity_b_id = EntityId::new();
        let rel_id = RelationId::new();

        let entity_a = make_entity(entity_a_id, "a");
        let entity_b = make_entity(entity_b_id, "b");
        let relation = make_relation(rel_id, entity_a_id, entity_b_id);

        let changes = vec![
            make_semantic_change(c1, vec![], vec![EntityDelta::Added(entity_a)], vec![]),
            make_semantic_change(
                c2,
                vec![c1],
                vec![EntityDelta::Added(entity_b)],
                vec![RelationDelta::Added(relation)],
            ),
            make_semantic_change(c3, vec![c2], vec![], vec![RelationDelta::Removed(rel_id)]),
        ];

        let state = replay_graph_state(changes);

        assert!(
            !state.relations.contains_key(&rel_id),
            "relation should be removed from active relations"
        );
        assert!(
            state.relation_tombstones.contains_key(&rel_id),
            "relation should be in tombstones"
        );
        let (tombstoned_rel, removal_change) = state.relation_tombstones.get(&rel_id).unwrap();
        assert_eq!(tombstoned_rel.id, rel_id);
        assert_eq!(*removal_change, c3);
    }

    #[test]
    fn dangling_relation_tombstoned_on_entity_removal() {
        let c1 = make_change_id(1);
        let c2 = make_change_id(2);
        let c3 = make_change_id(3);

        let entity_a_id = EntityId::new();
        let entity_b_id = EntityId::new();
        let rel_id = RelationId::new();

        let entity_a = make_entity(entity_a_id, "a");
        let entity_b = make_entity(entity_b_id, "b");
        let relation = make_relation(rel_id, entity_a_id, entity_b_id);

        let changes = vec![
            make_semantic_change(c1, vec![], vec![EntityDelta::Added(entity_a)], vec![]),
            make_semantic_change(
                c2,
                vec![c1],
                vec![EntityDelta::Added(entity_b)],
                vec![RelationDelta::Added(relation)],
            ),
            make_semantic_change(
                c3,
                vec![c2],
                vec![EntityDelta::Removed(entity_a_id)],
                vec![],
            ),
        ];

        let state = replay_graph_state(changes);

        assert!(
            state.entity_tombstones.contains_key(&entity_a_id),
            "entity A should be tombstoned"
        );
        assert!(
            state.relation_tombstones.contains_key(&rel_id),
            "relation should be tombstoned because entity A was removed"
        );
        let (_, removal_change) = state.relation_tombstones.get(&rel_id).unwrap();
        assert_eq!(
            *removal_change, c3,
            "dangling relation tombstone should reference the change that removed the entity"
        );
    }
}
