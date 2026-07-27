// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use crate::change::{ResolvedTree, SemanticChange, TransactionDelta, TreeEntry};
use crate::entity::{Entity, EntityKind, EntityRole};
use crate::error::ModelError;
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

/// Core entity, relation, and repository-tree operations.
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
    /// Resolve an exact tracked path through graph-owned repository state.
    ///
    /// This is lookup-only. Artifact identities are assigned by explicit
    /// admission/tree transactions, never by a path query.
    fn artifact_id_at_path(&self, path: &crate::RepoPath) -> Option<crate::ArtifactId>;
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
    fn get_tree_entry(
        &self,
        file_id: &FilePathId,
    ) -> std::result::Result<Option<TreeEntry>, Self::Error>;
    fn delete_file_layout(&self, file_id: &FilePathId) -> std::result::Result<(), Self::Error>;

    /// Apply entity, relation, and repository-tree mutations atomically.
    ///
    /// There is intentionally no partial default implementation: every store
    /// must account for all three delta classes in one transaction.
    fn apply_transaction_delta(
        &self,
        delta: &TransactionDelta,
    ) -> std::result::Result<(), Self::Error>;

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

    /// Replace all relations of a given kind with a new set.
    ///
    /// The default implementation is **not atomic**: it removes existing
    /// relations then upserts the new set as two separate operations. If the
    /// upsert fails after the remove has committed, a best-effort rollback is
    /// attempted; if the rollback also fails, the relations of that kind are
    /// left absent. Implementors that need true atomicity must override this
    /// method and wrap both operations in a single database transaction.
    fn replace_relations_of_kind(
        &self,
        kind: RelationKind,
        new_relations: Vec<Relation>,
    ) -> std::result::Result<(), Self::Error> {
        let existing: Vec<Relation> = self
            .query_entities(&EntityFilter::default())?
            .iter()
            .flat_map(|e| self.get_all_relations_for_entity(&e.id).unwrap_or_default())
            .filter(|r| r.kind == kind)
            .collect();
        let existing_ids: Vec<_> = existing.iter().map(|r| &r.id).collect();
        if !existing_ids.is_empty() {
            self.remove_relations_batch(&existing_ids)?;
        }
        if let Err(upsert_err) = self.upsert_relations_batch(&new_relations) {
            // Best-effort rollback: attempt to restore the removed relations.
            // Ignore the rollback error and return the original upsert error.
            if !existing.is_empty() {
                let _ = self.upsert_relations_batch(&existing);
            }
            return Err(upsert_err);
        }
        Ok(())
    }
}

/// Immutable semantic change DAG operations.
pub trait ChangeStore: Send + Sync {
    /// Store errors must be able to represent model-level history integrity
    /// failures surfaced by the default replay helpers.
    type Error: std::error::Error + Send + Sync + From<ModelError> + 'static;

    fn get_entity_history(
        &self,
        id: &EntityId,
    ) -> std::result::Result<Vec<SemanticChange>, Self::Error>;
    fn get_entity_revisions(
        &self,
        id: &EntityId,
    ) -> std::result::Result<Vec<EntityRevision>, Self::Error> {
        let changes = self.get_entity_history(id)?;
        Ok(replay_entity_revisions(changes, id)?)
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
    /// The changes reachable from `head` that mention `id`, oldest first.
    ///
    /// The result is filtered to one entity, so it is not a history any
    /// whole-graph replay can validate: the changes it keeps also carry deltas
    /// for entities whose own introducing changes were filtered out. Derive
    /// revisions from it with [`replay_entity_revisions`], never with
    /// [`derive_entity_revisions_from_changes`].
    fn get_entity_history_at(
        &self,
        id: &EntityId,
        head: &SemanticChangeId,
    ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
        Ok(collect_changes_first_parent(self, head)?
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
        Ok(replay_entity_revisions(changes, id)?)
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
        Ok(replay_relation_revisions(
            collect_changes_first_parent(self, head)?,
            id,
        ))
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
        artifact_id: &crate::ArtifactId,
        head: &SemanticChangeId,
    ) -> std::result::Result<Vec<ArtifactRevision>, Self::Error> {
        let (changes, _order) = collect_changes_topologically(self, head)?;
        resolve_tree_states(&changes).map_err(Self::Error::from)?;
        Ok(replay_artifact_revisions(&changes, artifact_id)
            .map_err(Self::Error::from)?
            .revisions)
    }
    fn resolve_artifact_revision_at(
        &self,
        artifact_id: &crate::ArtifactId,
        head: &SemanticChangeId,
    ) -> std::result::Result<Option<ArtifactRevision>, Self::Error> {
        let (changes, _order) = collect_changes_topologically(self, head)?;
        resolve_tree_states(&changes).map_err(Self::Error::from)?;
        let replay = replay_artifact_revisions(&changes, artifact_id).map_err(Self::Error::from)?;
        let Some(active_revision) = replay.active_at.get(head).copied().flatten() else {
            return Ok(None);
        };
        Ok(replay
            .revisions
            .into_iter()
            .find(|revision| revision.revision_id == active_revision))
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
        let first_parent_history = collect_changes_first_parent(self, head)?;
        let mut state = replay_graph_state(first_parent_history.clone())?;
        state.tree = replay_tree(first_parent_history).map_err(Self::Error::from)?;
        Ok(state)
    }
    /// Resolve the exact repository tree at `head`.
    fn resolve_tree_at(
        &self,
        head: &SemanticChangeId,
    ) -> std::result::Result<ResolvedTree, Self::Error> {
        replay_tree(collect_changes_first_parent(self, head)?).map_err(Self::Error::from)
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
    pub nodes: Vec<GraphNodeId>,
    pub entities: HashMap<EntityId, Entity>,
    pub relations: Vec<Relation>,
}

/// Immutable committed graph state resolved at a specific semantic ref.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResolvedGraphState {
    pub entities: HashMap<EntityId, Entity>,
    pub relations: HashMap<RelationId, Relation>,
    pub entity_revisions: HashMap<EntityId, Vec<EntityRevision>>,
    pub tree: ResolvedTree,
    /// Entities that were explicitly removed by a semantic change.
    /// Maps entity ID to the removed entity and the change that removed it.
    pub entity_tombstones: HashMap<EntityId, (Entity, SemanticChangeId)>,
    /// Relations that were explicitly removed by a semantic change or pruned
    /// because a referenced entity was removed.
    /// Maps relation ID to the removed relation and the change that caused removal.
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
                let change = store
                    .get_change(&id)?
                    .ok_or_else(|| ModelError::ChangeNotFound(id.to_string()))?;

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

/// Fetch the material state lineage for `head`.
///
/// Every change is interpreted relative to its first declared parent. Other
/// parents remain ancestry and revision-contribution links; resolving state
/// neither fetches nor implicitly unions them.
fn collect_changes_first_parent<G: ChangeStore + ?Sized>(
    store: &G,
    head: &SemanticChangeId,
) -> std::result::Result<Vec<SemanticChange>, G::Error> {
    let mut seen = HashSet::new();
    let mut reverse_history = Vec::new();
    let mut current = Some(*head);

    while let Some(change_id) = current {
        if !seen.insert(change_id) {
            return Err(ModelError::Conflict(format!(
                "cycle in first-parent history at change {change_id}"
            ))
            .into());
        }
        let change = store
            .get_change(&change_id)?
            .ok_or_else(|| ModelError::ChangeNotFound(change_id.to_string()))?;
        reverse_history.push(change.clone());
        current = change.parents.first().copied();
    }

    reverse_history.reverse();
    Ok(reverse_history)
}

/// Resolve every reachable change against its own first parent.
///
/// Keeping states keyed by change prevents deltas from divergent siblings
/// from being folded together merely because both are ancestors of a merge.
fn resolve_tree_states(
    changes: &[SemanticChange],
) -> std::result::Result<HashMap<SemanticChangeId, ResolvedTree>, ModelError> {
    let mut states: HashMap<SemanticChangeId, ResolvedTree> = HashMap::new();

    for change in changes {
        for parent in &change.parents {
            if !states.contains_key(parent) {
                return Err(ModelError::ChangeNotFound(parent.to_string()));
            }
        }
        let parent = change
            .parents
            .first()
            .map(|parent| {
                states
                    .get(parent)
                    .cloned()
                    .ok_or_else(|| ModelError::ChangeNotFound(parent.to_string()))
            })
            .transpose()?
            .unwrap_or_default();
        let state = parent.apply(&change.tree_deltas).map_err(|error| {
            ModelError::Conflict(format!(
                "invalid repository tree transition in change {}: {error}",
                change.id
            ))
        })?;
        states.insert(change.id, state);
    }

    Ok(states)
}

fn replay_tree<I>(changes: I) -> std::result::Result<ResolvedTree, ModelError>
where
    I: IntoIterator<Item = SemanticChange>,
{
    let mut tree = ResolvedTree::default();

    for change in changes {
        tree = tree.apply(&change.tree_deltas).map_err(|error| {
            ModelError::Conflict(format!(
                "invalid repository tree transition in change {}: {error}",
                change.id
            ))
        })?;
    }

    Ok(tree)
}

fn replay_graph_state<I>(changes: I) -> std::result::Result<ResolvedGraphState, ModelError>
where
    I: IntoIterator<Item = SemanticChange>,
{
    let mut state = ResolvedGraphState::default();

    for change in changes {
        let change_id = change.id;
        for delta in change.entity_deltas {
            match delta {
                crate::change::EntityDelta::Added { new: entity } => {
                    if state.entities.contains_key(&entity.id) {
                        return Err(ModelError::Conflict(format!(
                            "change {change_id} adds existing entity {}",
                            entity.id
                        )));
                    }
                    let entries = state.entity_revisions.entry(entity.id).or_default();
                    let previous_revision =
                        mark_matching_entity_revision_ended(entries, &entity, change_id);
                    entries.push(EntityRevision::new(
                        entity.clone(),
                        change_id,
                        previous_revision,
                    ));
                    state.entity_tombstones.remove(&entity.id);
                    state.entities.insert(entity.id, entity);
                }
                crate::change::EntityDelta::Modified { old, new } => {
                    if old.id != new.id {
                        return Err(ModelError::Conflict(format!(
                            "change {change_id} modifies entity {} into different identity {}",
                            old.id, new.id
                        )));
                    }
                    if state.entities.get(&old.id) != Some(&old) {
                        return Err(ModelError::Conflict(format!(
                            "change {change_id} has stale old payload for entity {}",
                            old.id
                        )));
                    }
                    let entries = state.entity_revisions.entry(new.id).or_default();
                    let previous_revision =
                        mark_matching_entity_revision_ended(entries, &old, change_id);
                    entries.push(EntityRevision::new(
                        new.clone(),
                        change_id,
                        previous_revision,
                    ));
                    state.entities.insert(new.id, new);
                }
                crate::change::EntityDelta::Removed { old } => {
                    let entity_id = old.id;
                    if state.entities.get(&entity_id) != Some(&old) {
                        return Err(ModelError::Conflict(format!(
                            "change {change_id} has stale old payload for removed entity {entity_id}"
                        )));
                    }
                    if let Some(entries) = state.entity_revisions.get_mut(&entity_id) {
                        if let Some(previous) = entries.last_mut() {
                            previous.mark_ended(change_id);
                        }
                    }
                    state.entities.remove(&entity_id);
                    state.entity_tombstones.insert(entity_id, (old, change_id));
                }
            }
        }

        for delta in change.relation_deltas {
            match delta {
                crate::change::RelationDelta::Added { new: relation } => {
                    if state.relations.contains_key(&relation.id) {
                        return Err(ModelError::Conflict(format!(
                            "change {change_id} adds existing relation {}",
                            relation.id
                        )));
                    }
                    state.relation_tombstones.remove(&relation.id);
                    state.relations.insert(relation.id, relation);
                }
                crate::change::RelationDelta::Modified { old, new } => {
                    if old.id != new.id {
                        return Err(ModelError::Conflict(format!(
                            "change {change_id} modifies relation {} into different identity {}",
                            old.id, new.id
                        )));
                    }
                    if state.relations.get(&old.id) != Some(&old) {
                        return Err(ModelError::Conflict(format!(
                            "change {change_id} has stale old payload for relation {}",
                            old.id
                        )));
                    }
                    state.relations.insert(new.id, new);
                }
                crate::change::RelationDelta::Removed { old } => {
                    let relation_id = old.id;
                    if state.relations.get(&relation_id) != Some(&old) {
                        return Err(ModelError::Conflict(format!(
                            "change {change_id} has stale old payload for removed relation {relation_id}"
                        )));
                    }
                    state.relations.remove(&relation_id);
                    state
                        .relation_tombstones
                        .insert(relation_id, (old, change_id));
                }
            }
        }

        for relation in state.relations.values() {
            for node in [relation.src, relation.dst] {
                if let GraphNodeId::Entity(entity_id) = node {
                    if !state.entities.contains_key(&entity_id) {
                        return Err(ModelError::Conflict(format!(
                            "change {change_id} leaves relation {} dangling from entity {entity_id}; \
                             relation removal must be explicit",
                            relation.id
                        )));
                    }
                }
            }
        }
    }

    Ok(state)
}

/// Replay the revision timelines of every entity in `changes`.
///
/// `changes` must be a complete history: replaying validates every delta each
/// change carries, so a list already filtered to one entity fails on the other
/// entities that change touches. Use [`replay_entity_revisions`] for a single
/// entity's timeline.
pub fn derive_entity_revisions_from_changes<I>(
    changes: I,
) -> std::result::Result<HashMap<EntityId, Vec<EntityRevision>>, ModelError>
where
    I: IntoIterator<Item = SemanticChange>,
{
    Ok(replay_graph_state(changes)?.entity_revisions)
}

/// Replay one entity's revision timeline, oldest first.
///
/// Only `entity_id`'s own deltas are replayed and validated. Every other
/// entity's deltas are skipped rather than checked, which is what makes this
/// sound over a change list that has been filtered to one entity: the changes
/// that introduced the other entities are not in such a list, so validating
/// their `Modified`/`Removed` preconditions checks them against a state they
/// were never added to and reports a stale payload for an entity nobody asked
/// about. A single commit that revised the queried entity while removing a
/// second one was enough to make `kin history` and `kin blame` fail outright.
///
/// The queried entity's own preconditions are still enforced, so a genuinely
/// inconsistent timeline fails closed.
pub fn replay_entity_revisions<I>(
    changes: I,
    entity_id: &EntityId,
) -> std::result::Result<Vec<EntityRevision>, ModelError>
where
    I: IntoIterator<Item = SemanticChange>,
{
    let mut revisions: Vec<EntityRevision> = Vec::new();
    let mut live: Option<Entity> = None;

    for change in changes {
        let change_id = change.id;
        for delta in change.entity_deltas {
            match delta {
                crate::change::EntityDelta::Added { new: entity } if entity.id == *entity_id => {
                    if live.is_some() {
                        return Err(ModelError::Conflict(format!(
                            "change {change_id} adds existing entity {entity_id}"
                        )));
                    }
                    let previous_revision =
                        mark_matching_entity_revision_ended(&mut revisions, &entity, change_id);
                    revisions.push(EntityRevision::new(
                        entity.clone(),
                        change_id,
                        previous_revision,
                    ));
                    live = Some(entity);
                }
                crate::change::EntityDelta::Modified { old, new }
                    if old.id == *entity_id || new.id == *entity_id =>
                {
                    if old.id != new.id {
                        return Err(ModelError::Conflict(format!(
                            "change {change_id} modifies entity {} into different identity {}",
                            old.id, new.id
                        )));
                    }
                    if live.as_ref() != Some(&old) {
                        return Err(ModelError::Conflict(format!(
                            "change {change_id} has stale old payload for entity {}",
                            old.id
                        )));
                    }
                    let previous_revision =
                        mark_matching_entity_revision_ended(&mut revisions, &old, change_id);
                    revisions.push(EntityRevision::new(
                        new.clone(),
                        change_id,
                        previous_revision,
                    ));
                    live = Some(new);
                }
                crate::change::EntityDelta::Removed { old } if old.id == *entity_id => {
                    if live.as_ref() != Some(&old) {
                        return Err(ModelError::Conflict(format!(
                            "change {change_id} has stale old payload for removed entity {entity_id}"
                        )));
                    }
                    if let Some(previous) = revisions.last_mut() {
                        previous.mark_ended(change_id);
                    }
                    live = None;
                }
                _ => {}
            }
        }
    }

    Ok(revisions)
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
                crate::change::RelationDelta::Added { new: relation }
                    if relation.id == *relation_id =>
                {
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
                crate::change::RelationDelta::Modified { old, new }
                    if old.id == *relation_id && new.id == *relation_id =>
                {
                    let previous_revision = active_revision
                        .take()
                        .and_then(|index| revisions.get_mut(index))
                        .map(|revision| {
                            revision.mark_ended(change_id);
                            revision.revision_id
                        });
                    revisions.push(RelationRevision::new(new, change_id, previous_revision));
                    active_revision = Some(revisions.len() - 1);
                }
                crate::change::RelationDelta::Removed { old } if old.id == *relation_id => {
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

struct ArtifactRevisionReplay {
    revisions: Vec<ArtifactRevision>,
    active_at: HashMap<SemanticChangeId, Option<ArtifactRevisionId>>,
}

/// Replay one artifact's revision graph while keeping material state
/// first-parent-relative.
///
/// A new revision points to the revisions active at each declared parent.
/// Parent order is preserved and duplicate revision IDs are removed.
fn replay_artifact_revisions(
    changes: &[SemanticChange],
    artifact_id: &crate::ArtifactId,
) -> std::result::Result<ArtifactRevisionReplay, ModelError> {
    let mut revisions = Vec::new();
    let mut active_at = HashMap::new();

    for change in changes {
        for parent in &change.parents {
            if !active_at.contains_key(parent) {
                return Err(ModelError::ChangeNotFound(parent.to_string()));
            }
        }

        let first_parent_active = change
            .parents
            .first()
            .and_then(|parent| active_at.get(parent).copied().flatten());
        let mut matching = change
            .tree_deltas
            .iter()
            .filter(|delta| delta.artifact_id() == *artifact_id);
        let delta = matching.next();
        if matching.next().is_some() {
            return Err(ModelError::Conflict(format!(
                "tree transaction contains more than one delta for artifact {artifact_id:?} in change {}",
                change.id
            )));
        }

        let active = match delta {
            None => first_parent_active,
            Some(delta) => {
                let Some(new) = delta.new_state() else {
                    active_at.insert(change.id, None);
                    continue;
                };
                let mut predecessor_revisions = Vec::new();
                for parent in &change.parents {
                    let Some(predecessor) = active_at.get(parent).copied().flatten() else {
                        continue;
                    };
                    if !predecessor_revisions.contains(&predecessor) {
                        predecessor_revisions.push(predecessor);
                    }
                }
                let revision = ArtifactRevision::new(
                    *artifact_id,
                    new.path.clone(),
                    new.entry,
                    change.id,
                    predecessor_revisions,
                );
                let revision_id = revision.revision_id;
                revisions.push(revision);
                Some(revision_id)
            }
        };
        active_at.insert(change.id, active);
    }

    Ok(ArtifactRevisionReplay {
        revisions,
        active_at,
    })
}

fn entity_is_touched_by_change(change: &SemanticChange, entity_id: &EntityId) -> bool {
    change.entity_deltas.iter().any(|delta| match delta {
        crate::change::EntityDelta::Added { new } => new.id == *entity_id,
        crate::change::EntityDelta::Modified { old, new } => {
            old.id == *entity_id || new.id == *entity_id
        }
        crate::change::EntityDelta::Removed { old } => old.id == *entity_id,
    })
}

/// Close out the revision of `entity` that a change supersedes, and name it as
/// the predecessor of the revision that change introduces.
///
/// `entries` holds one entity's revisions, oldest first. An empty slice means
/// nothing to supersede, which is the same answer as an entity with no recorded
/// history at all.
fn mark_matching_entity_revision_ended(
    entries: &mut [EntityRevision],
    entity: &Entity,
    ended_by: SemanticChangeId,
) -> Option<EntityRevisionId> {
    let match_index = entries
        .iter()
        .enumerate()
        .rev()
        .find(|(_, revision)| entities_match_for_revision(&revision.entity, entity))
        .map(|(index, _)| index)
        .or_else(|| entries.len().checked_sub(1));
    match_index
        .and_then(|index| entries.get_mut(index))
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
    fn artifact_id_at_path(&self, path: &crate::RepoPath) -> Option<crate::ArtifactId> {
        (**self).artifact_id_at_path(path)
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
    fn get_tree_entry(
        &self,
        file_id: &FilePathId,
    ) -> std::result::Result<Option<TreeEntry>, Self::Error> {
        (**self).get_tree_entry(file_id)
    }
    fn delete_file_layout(&self, file_id: &FilePathId) -> std::result::Result<(), Self::Error> {
        (**self).delete_file_layout(file_id)
    }
    fn apply_transaction_delta(
        &self,
        delta: &TransactionDelta,
    ) -> std::result::Result<(), Self::Error> {
        (**self).apply_transaction_delta(delta)
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
    use crate::change::{
        EntityDelta, LocatedEntry, RelationDelta, SemanticChange, TreeDelta, TreeEntry,
    };
    use crate::entity::{
        Entity, EntityKind, EntityMetadata, FingerprintAlgorithm, SemanticFingerprint, Visibility,
    };
    use crate::relation::{GraphNodeId, Relation, RelationKind, RelationOrigin};
    use crate::timestamp::Timestamp;
    use crate::{ArtifactId, RepoPath};

    fn make_change_id(byte: u8) -> SemanticChangeId {
        SemanticChangeId::from_hash(Hash256::from_bytes([byte; 32]))
    }

    fn repo_path(path: &str) -> RepoPath {
        RepoPath::from_utf8(path).unwrap()
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
                equivalence_hash: Hash256::from_bytes([0; 32]),
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
            origin: crate::ChangeOrigin::Native,
            parents,
            timestamp: Timestamp::now(),
            author: AuthorId("test".into()),
            message: "test change".into(),
            entity_deltas,
            relation_deltas,
            tree_deltas: vec![],
            admission_policy_delta: None,
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
        }
    }

    fn resolved_tree_at(changes: Vec<SemanticChange>, head: SemanticChangeId) -> ResolvedTree {
        resolve_tree_states(&changes)
            .unwrap()
            .remove(&head)
            .unwrap()
    }

    #[derive(Default)]
    struct HistoryStore {
        changes: HashMap<SemanticChangeId, SemanticChange>,
    }

    impl HistoryStore {
        fn from_changes(changes: impl IntoIterator<Item = SemanticChange>) -> Self {
            Self {
                changes: changes
                    .into_iter()
                    .map(|change| (change.id, change))
                    .collect(),
            }
        }
    }

    impl ChangeStore for HistoryStore {
        type Error = ModelError;

        fn get_entity_history(
            &self,
            _id: &EntityId,
        ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
            Ok(Vec::new())
        }

        fn find_merge_bases(
            &self,
            _a: &SemanticChangeId,
            _b: &SemanticChangeId,
        ) -> std::result::Result<Vec<SemanticChangeId>, Self::Error> {
            Ok(Vec::new())
        }

        fn create_change(&self, _change: &SemanticChange) -> std::result::Result<(), Self::Error> {
            Ok(())
        }

        fn get_change(
            &self,
            id: &SemanticChangeId,
        ) -> std::result::Result<Option<SemanticChange>, Self::Error> {
            Ok(self.changes.get(id).cloned())
        }

        fn get_changes_since(
            &self,
            _base: &SemanticChangeId,
            _head: &SemanticChangeId,
        ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
            Ok(Vec::new())
        }
    }

    fn assert_missing_change(error: ModelError, expected: SemanticChangeId) {
        match error {
            ModelError::ChangeNotFound(id) => assert_eq!(id, expected.to_string()),
            other => panic!("expected missing-change error, got {other}"),
        }
    }

    #[test]
    fn resolve_graph_at_fails_closed_when_head_is_missing() {
        let head = make_change_id(240);
        let error = HistoryStore::default().resolve_graph_at(&head).unwrap_err();

        assert_missing_change(error, head);
    }

    #[test]
    fn resolve_tree_at_fails_closed_when_first_parent_is_missing() {
        let second_parent = make_change_id(239);
        let missing_parent = make_change_id(241);
        let head = make_change_id(242);
        let store = HistoryStore::from_changes([
            make_semantic_change(second_parent, vec![], Vec::new(), Vec::new()),
            make_semantic_change(
                head,
                vec![missing_parent, second_parent],
                Vec::new(),
                Vec::new(),
            ),
        ]);

        let error = store.resolve_tree_at(&head).unwrap_err();

        assert_missing_change(error, missing_parent);
    }

    #[test]
    fn state_resolution_needs_only_first_parent_but_lineage_needs_all_parents() {
        let first_parent = make_change_id(243);
        let missing_contributor = make_change_id(244);
        let head = make_change_id(245);
        let artifact_id = ArtifactId::new();
        let entry = TreeEntry::blob(Hash256::from_bytes([0xf5; 32]), false);
        let mut root = make_semantic_change(first_parent, vec![], vec![], vec![]);
        root.tree_deltas = vec![TreeDelta::Added {
            artifact_id,
            new: LocatedEntry::new(repo_path("artifact"), entry),
        }];
        let merge = make_semantic_change(
            head,
            vec![first_parent, missing_contributor],
            vec![],
            vec![],
        );
        let store = HistoryStore::from_changes([root, merge]);

        assert_eq!(
            store
                .resolve_tree_at(&head)
                .unwrap()
                .get(&artifact_id)
                .map(|artifact| artifact.entry),
            Some(entry)
        );
        let error = store
            .resolve_artifact_revision_at(&artifact_id, &head)
            .unwrap_err();
        assert_missing_change(error, missing_contributor);
    }

    #[test]
    fn divergent_sibling_state_is_not_folded_into_merge_result() {
        let root_id = make_change_id(20);
        let left_id = make_change_id(21);
        let right_id = make_change_id(22);
        let merge_id = make_change_id(23);
        let shared = ArtifactId::new();
        let right_only = ArtifactId::new();
        let right_only_entity = make_entity(EntityId::new(), "right_only");
        let base = TreeEntry::blob(Hash256::from_bytes([0x20; 32]), false);
        let left = TreeEntry::blob(Hash256::from_bytes([0x21; 32]), false);
        let right = TreeEntry::blob(Hash256::from_bytes([0x22; 32]), false);
        let right_only_entry = TreeEntry::blob(Hash256::from_bytes([0x23; 32]), false);

        let mut root = make_semantic_change(root_id, vec![], vec![], vec![]);
        root.tree_deltas = vec![TreeDelta::Added {
            artifact_id: shared,
            new: LocatedEntry::new(repo_path("shared"), base),
        }];
        let mut left_change = make_semantic_change(left_id, vec![root_id], vec![], vec![]);
        left_change.tree_deltas = vec![TreeDelta::Updated {
            artifact_id: shared,
            old: LocatedEntry::new(repo_path("shared"), base),
            new: LocatedEntry::new(repo_path("shared"), left),
        }];
        let mut right_change = make_semantic_change(
            right_id,
            vec![root_id],
            vec![EntityDelta::Added {
                new: right_only_entity.clone(),
            }],
            vec![],
        );
        right_change.tree_deltas = vec![
            TreeDelta::Updated {
                artifact_id: shared,
                old: LocatedEntry::new(repo_path("shared"), base),
                new: LocatedEntry::new(repo_path("shared"), right),
            },
            TreeDelta::Added {
                artifact_id: right_only,
                new: LocatedEntry::new(repo_path("right-only"), right_only_entry),
            },
        ];
        let merge = make_semantic_change(merge_id, vec![left_id, right_id], vec![], vec![]);
        let store = HistoryStore::from_changes([root, left_change, right_change, merge]);

        let tree = store.resolve_tree_at(&merge_id).unwrap();

        assert_eq!(tree.get(&shared).map(|artifact| artifact.entry), Some(left));
        assert!(tree.get(&right_only).is_none());
        assert!(!store
            .resolve_graph_at(&merge_id)
            .unwrap()
            .entities
            .contains_key(&right_only_entity.id));
    }

    #[test]
    fn explicit_merge_result_is_applied_relative_to_first_parent() {
        let root_id = make_change_id(30);
        let left_id = make_change_id(31);
        let right_id = make_change_id(32);
        let merge_id = make_change_id(33);
        let artifact_id = ArtifactId::new();
        let base = TreeEntry::blob(Hash256::from_bytes([0x30; 32]), false);
        let left = TreeEntry::blob(Hash256::from_bytes([0x31; 32]), false);
        let right = TreeEntry::blob(Hash256::from_bytes([0x32; 32]), false);
        let merged = TreeEntry::blob(Hash256::from_bytes([0x33; 32]), false);

        let mut root = make_semantic_change(root_id, vec![], vec![], vec![]);
        root.tree_deltas = vec![TreeDelta::Added {
            artifact_id,
            new: LocatedEntry::new(repo_path("artifact"), base),
        }];
        let mut left_change = make_semantic_change(left_id, vec![root_id], vec![], vec![]);
        left_change.tree_deltas = vec![TreeDelta::Updated {
            artifact_id,
            old: LocatedEntry::new(repo_path("artifact"), base),
            new: LocatedEntry::new(repo_path("artifact"), left),
        }];
        let mut right_change = make_semantic_change(right_id, vec![root_id], vec![], vec![]);
        right_change.tree_deltas = vec![TreeDelta::Updated {
            artifact_id,
            old: LocatedEntry::new(repo_path("artifact"), base),
            new: LocatedEntry::new(repo_path("artifact"), right),
        }];
        let mut merge = make_semantic_change(merge_id, vec![left_id, right_id], vec![], vec![]);
        merge.tree_deltas = vec![TreeDelta::Updated {
            artifact_id,
            old: LocatedEntry::new(repo_path("artifact"), left),
            new: LocatedEntry::new(repo_path("artifact"), merged),
        }];
        let store = HistoryStore::from_changes([root, left_change, right_change, merge]);

        let tree = store.resolve_tree_at(&merge_id).unwrap();

        assert_eq!(
            tree.get(&artifact_id).map(|artifact| artifact.entry),
            Some(merged)
        );
    }

    #[test]
    fn exact_tree_preserves_regular_executable_and_symlink_across_changes() {
        let c1 = make_change_id(1);
        let c2 = make_change_id(2);
        let regular = ArtifactId::new();
        let executable = ArtifactId::new();
        let symlink = ArtifactId::new();
        let regular_v1 = TreeEntry::blob(Hash256::from_bytes([1; 32]), false);
        let executable_v1 = TreeEntry::blob(Hash256::from_bytes([2; 32]), true);
        let symlink_v1 = TreeEntry::symlink(Hash256::from_bytes([3; 32]));
        let regular_v2 = TreeEntry::blob(Hash256::from_bytes([4; 32]), false);
        let executable_v2 = TreeEntry::blob(Hash256::from_bytes([5; 32]), true);
        let symlink_v2 = TreeEntry::symlink(Hash256::from_bytes([6; 32]));
        let mut first = make_semantic_change(c1, vec![], vec![], vec![]);
        first.tree_deltas = vec![
            TreeDelta::Added {
                artifact_id: regular,
                new: LocatedEntry::new(repo_path("README.md"), regular_v1),
            },
            TreeDelta::Added {
                artifact_id: executable,
                new: LocatedEntry::new(repo_path("bin/run"), executable_v1),
            },
            TreeDelta::Added {
                artifact_id: symlink,
                new: LocatedEntry::new(repo_path("current"), symlink_v1),
            },
        ];
        let mut second = make_semantic_change(c2, vec![c1], vec![], vec![]);
        second.tree_deltas = vec![
            TreeDelta::Updated {
                artifact_id: regular,
                old: LocatedEntry::new(repo_path("README.md"), regular_v1),
                new: LocatedEntry::new(repo_path("README.md"), regular_v2),
            },
            TreeDelta::Updated {
                artifact_id: executable,
                old: LocatedEntry::new(repo_path("bin/run"), executable_v1),
                new: LocatedEntry::new(repo_path("bin/run"), executable_v2),
            },
            TreeDelta::Updated {
                artifact_id: symlink,
                old: LocatedEntry::new(repo_path("current"), symlink_v1),
                new: LocatedEntry::new(repo_path("current"), symlink_v2),
            },
        ];

        let entries = resolved_tree_at(vec![first, second], c2);
        assert_eq!(
            entries.get(&regular).map(|value| value.entry),
            Some(regular_v2)
        );
        assert_eq!(
            entries.get(&executable).map(|value| value.entry),
            Some(executable_v2)
        );
        assert_eq!(
            entries.get(&symlink).map(|value| value.entry),
            Some(symlink_v2)
        );
    }

    #[test]
    fn exact_tree_tracks_and_removes_non_language_files() {
        let c1 = make_change_id(7);
        let c2 = make_change_id(8);
        let compose = ArtifactId::new();
        let dockerfile = ArtifactId::new();
        let compose_entry = TreeEntry::blob(Hash256::from_bytes([7; 32]), false);
        let dockerfile_entry = TreeEntry::blob(Hash256::from_bytes([8; 32]), false);
        let mut added = make_semantic_change(c1, vec![], vec![], vec![]);
        added.tree_deltas = vec![
            TreeDelta::Added {
                artifact_id: compose,
                new: LocatedEntry::new(repo_path("compose.yaml"), compose_entry),
            },
            TreeDelta::Added {
                artifact_id: dockerfile,
                new: LocatedEntry::new(repo_path("Dockerfile"), dockerfile_entry),
            },
        ];
        let mut removed = make_semantic_change(c2, vec![c1], vec![], vec![]);
        removed.tree_deltas = vec![TreeDelta::Removed {
            artifact_id: compose,
            old: LocatedEntry::new(repo_path("compose.yaml"), compose_entry),
        }];

        let entries = resolved_tree_at(vec![added, removed], c2);
        assert!(entries.get(&compose).is_none());
        assert_eq!(
            entries.get(&dockerfile).map(|value| value.entry),
            Some(dockerfile_entry)
        );
    }

    #[test]
    fn exact_tree_preserves_mode_only_changes() {
        let c1 = make_change_id(9);
        let c2 = make_change_id(10);
        let artifact_id = ArtifactId::new();
        let regular = TreeEntry::blob(Hash256::from_bytes([9; 32]), false);
        let executable = TreeEntry::blob(Hash256::from_bytes([9; 32]), true);
        let mut added = make_semantic_change(c1, vec![], vec![], vec![]);
        added.tree_deltas = vec![TreeDelta::Added {
            artifact_id,
            new: LocatedEntry::new(repo_path("bin/run"), regular),
        }];
        let mut mode_changed = make_semantic_change(c2, vec![c1], vec![], vec![]);
        mode_changed.tree_deltas = vec![TreeDelta::Updated {
            artifact_id,
            old: LocatedEntry::new(repo_path("bin/run"), regular),
            new: LocatedEntry::new(repo_path("bin/run"), executable),
        }];

        assert_eq!(
            resolved_tree_at(vec![added, mode_changed], c2)
                .get(&artifact_id)
                .map(|value| value.entry),
            Some(executable)
        );
        assert!(matches!(
            executable,
            TreeEntry::Blob {
                executable: true,
                ..
            }
        ));
    }

    #[test]
    fn rename_preserves_artifact_identity_and_revision_lineage() {
        let add_id = make_change_id(40);
        let rename_id = make_change_id(41);
        let artifact_id = ArtifactId::new();
        let old_path = RepoPath::from_bytes(vec![b'o', b'l', b'd', b'/', 0xff]).unwrap();
        let new_path = RepoPath::from_bytes(vec![b'n', b'e', b'w', b'/', 0xfe]).unwrap();
        let entry = TreeEntry::blob(Hash256::from_bytes([0x40; 32]), false);
        let mut add = make_semantic_change(add_id, vec![], vec![], vec![]);
        add.tree_deltas = vec![TreeDelta::Added {
            artifact_id,
            new: LocatedEntry::new(old_path.clone(), entry),
        }];
        let mut rename = make_semantic_change(rename_id, vec![add_id], vec![], vec![]);
        rename.tree_deltas = vec![TreeDelta::Updated {
            artifact_id,
            old: LocatedEntry::new(old_path, entry),
            new: LocatedEntry::new(new_path.clone(), entry),
        }];
        let store = HistoryStore::from_changes([add, rename]);

        let revisions = store
            .get_artifact_revisions_at(&artifact_id, &rename_id)
            .unwrap();
        let first = revisions
            .iter()
            .find(|revision| revision.introduced_by == add_id)
            .unwrap();
        let renamed = revisions
            .iter()
            .find(|revision| revision.introduced_by == rename_id)
            .unwrap();
        let active = store
            .resolve_artifact_revision_at(&artifact_id, &rename_id)
            .unwrap()
            .unwrap();

        assert_eq!(revisions.len(), 2);
        assert_eq!(renamed.artifact_id, artifact_id);
        assert_eq!(renamed.path, new_path);
        assert_eq!(renamed.predecessor_revisions, vec![first.revision_id]);
        assert_eq!(active.revision_id, renamed.revision_id);
        assert_eq!(
            store
                .resolve_tree_at(&rename_id)
                .unwrap()
                .artifact_id_at_path(&renamed.path),
            Some(artifact_id)
        );
    }

    #[test]
    fn path_reuse_does_not_join_distinct_artifact_lineages() {
        let add_id = make_change_id(42);
        let replace_id = make_change_id(43);
        let old_artifact = ArtifactId::new();
        let new_artifact = ArtifactId::new();
        let old_entry = TreeEntry::blob(Hash256::from_bytes([0x42; 32]), false);
        let new_entry = TreeEntry::blob(Hash256::from_bytes([0x43; 32]), false);
        let reused_path = repo_path("README");
        let mut add = make_semantic_change(add_id, vec![], vec![], vec![]);
        add.tree_deltas = vec![TreeDelta::Added {
            artifact_id: old_artifact,
            new: LocatedEntry::new(reused_path.clone(), old_entry),
        }];
        let mut replace = make_semantic_change(replace_id, vec![add_id], vec![], vec![]);
        replace.tree_deltas = vec![
            TreeDelta::Removed {
                artifact_id: old_artifact,
                old: LocatedEntry::new(reused_path.clone(), old_entry),
            },
            TreeDelta::Added {
                artifact_id: new_artifact,
                new: LocatedEntry::new(reused_path.clone(), new_entry),
            },
        ];
        let store = HistoryStore::from_changes([add, replace]);

        let new_revisions = store
            .get_artifact_revisions_at(&new_artifact, &replace_id)
            .unwrap();

        assert_eq!(new_revisions.len(), 1);
        assert!(new_revisions[0].predecessor_revisions.is_empty());
        assert!(store
            .resolve_artifact_revision_at(&old_artifact, &replace_id)
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .resolve_tree_at(&replace_id)
                .unwrap()
                .artifact_id_at_path(&reused_path),
            Some(new_artifact)
        );
    }

    /// One version of an entity. `marker` varies the fingerprint so two
    /// versions of the same entity are distinguishable revisions.
    fn make_entity_version(id: EntityId, name: &str, marker: u8) -> Entity {
        let mut entity = make_entity(id, name);
        entity.fingerprint.ast_hash = Hash256::from_bytes([marker; 32]);
        entity.signature = format!("fn {name}(v{marker})");
        entity
    }

    /// A history whose last change carries a mixed add/remove shape.
    ///
    /// `beta` is introduced by a change that never mentions `alpha`, so
    /// filtering the change list to `alpha` drops the only change that adds
    /// `beta`, while the change that revises `alpha` still carries `beta`'s
    /// removal.
    fn mixed_shape_history(
        alpha: EntityId,
        beta: EntityId,
        gamma: EntityId,
    ) -> (HistoryStore, [SemanticChangeId; 3]) {
        let add_alpha_id = make_change_id(60);
        let add_beta_id = make_change_id(61);
        let revise_alpha_id = make_change_id(62);

        let add_alpha = make_semantic_change(
            add_alpha_id,
            vec![],
            vec![EntityDelta::Added {
                new: make_entity_version(alpha, "alpha", 1),
            }],
            vec![],
        );
        let add_beta = make_semantic_change(
            add_beta_id,
            vec![add_alpha_id],
            vec![EntityDelta::Added {
                new: make_entity_version(beta, "beta", 1),
            }],
            vec![],
        );
        let revise_alpha = make_semantic_change(
            revise_alpha_id,
            vec![add_beta_id],
            vec![
                EntityDelta::Modified {
                    old: make_entity_version(alpha, "alpha", 1),
                    new: make_entity_version(alpha, "alpha", 2),
                },
                EntityDelta::Removed {
                    old: make_entity_version(beta, "beta", 1),
                },
                EntityDelta::Added {
                    new: make_entity_version(gamma, "gamma", 1),
                },
            ],
            vec![],
        );

        (
            HistoryStore::from_changes([add_alpha, add_beta, revise_alpha]),
            [add_alpha_id, add_beta_id, revise_alpha_id],
        )
    }

    /// Deriving an entity's revisions replays only the changes that mention it,
    /// so validating the other entities those changes touch checks their
    /// preconditions against a state their own introducing changes were
    /// filtered out of. A sound repository then answers a query about `alpha`
    /// with a stale-payload conflict naming `beta`, which is what made
    /// `kin history` and `kin blame` fail before printing anything.
    #[test]
    fn entity_revisions_at_survive_a_change_that_also_removes_another_entity() {
        let alpha = EntityId::new();
        let beta = EntityId::new();
        let gamma = EntityId::new();
        let (store, [add_alpha_id, add_beta_id, revise_alpha_id]) =
            mixed_shape_history(alpha, beta, gamma);

        // The trap this fix closes: the filtered change list is not a history
        // the whole-graph replay can validate, and routing revisions through it
        // is what turned a sound repository into a conflict.
        let filtered = store
            .get_entity_history_at(&alpha, &revise_alpha_id)
            .unwrap();
        let error = derive_entity_revisions_from_changes(filtered)
            .expect_err("a change list filtered to one entity is not a complete history");
        assert!(
            matches!(&error, ModelError::Conflict(message) if message.contains("stale old payload")),
            "expected the whole-graph replay to reject the filtered list, got {error}"
        );

        let revisions = store
            .get_entity_revisions_at(&alpha, &revise_alpha_id)
            .expect("a sound history must not report a conflict for an unqueried entity");

        assert_eq!(revisions.len(), 2);
        assert_eq!(revisions[0].introduced_by, add_alpha_id);
        assert_eq!(revisions[0].ended_by, Some(revise_alpha_id));
        assert_eq!(revisions[1].introduced_by, revise_alpha_id);
        assert_eq!(revisions[1].ended_by, None);
        assert_eq!(
            revisions[1].previous_revision,
            Some(revisions[0].revision_id)
        );
        assert!(
            !revisions
                .iter()
                .any(|revision| revision.introduced_by == add_beta_id),
            "a change that never touches alpha is not a revision of alpha"
        );

        let active = store
            .resolve_entity_revision_at(&alpha, &revise_alpha_id)
            .unwrap()
            .expect("alpha is live at the head");
        assert_eq!(active.revision_id, revisions[1].revision_id);
    }

    /// The removed entity's own timeline stays answerable, and ends where the
    /// change that removed it says it does.
    #[test]
    fn entity_revisions_at_close_the_timeline_of_a_removed_entity() {
        let alpha = EntityId::new();
        let beta = EntityId::new();
        let gamma = EntityId::new();
        let (store, [_, add_beta_id, revise_alpha_id]) = mixed_shape_history(alpha, beta, gamma);

        let revisions = store
            .get_entity_revisions_at(&beta, &revise_alpha_id)
            .unwrap();

        assert_eq!(revisions.len(), 1);
        assert_eq!(revisions[0].introduced_by, add_beta_id);
        assert_eq!(revisions[0].ended_by, Some(revise_alpha_id));
        assert!(store
            .resolve_entity_revision_at(&beta, &revise_alpha_id)
            .unwrap()
            .is_none());
    }

    /// Skipping the other entities' deltas must not weaken the queried
    /// entity's own preconditions.
    #[test]
    fn entity_revisions_at_fail_closed_on_a_stale_payload_for_the_queried_entity() {
        let alpha = EntityId::new();
        let add_id = make_change_id(63);
        let revise_id = make_change_id(64);
        let add = make_semantic_change(
            add_id,
            vec![],
            vec![EntityDelta::Added {
                new: make_entity_version(alpha, "alpha", 1),
            }],
            vec![],
        );
        // `old` is a payload alpha never had at this point in history.
        let revise = make_semantic_change(
            revise_id,
            vec![add_id],
            vec![EntityDelta::Modified {
                old: make_entity_version(alpha, "alpha", 9),
                new: make_entity_version(alpha, "alpha", 2),
            }],
            vec![],
        );
        let store = HistoryStore::from_changes([add, revise]);

        let error = store
            .get_entity_revisions_at(&alpha, &revise_id)
            .expect_err("an inconsistent timeline for the queried entity must fail closed");

        assert!(
            matches!(&error, ModelError::Conflict(message) if message.contains("stale old payload")),
            "expected a stale-payload conflict, got {error}"
        );
    }

    /// Over a complete history the per-entity replay must agree with the
    /// whole-graph replay, so routing revisions through it is a soundness fix
    /// rather than a behavior change.
    #[test]
    fn per_entity_replay_matches_the_whole_graph_replay_over_complete_history() {
        let alpha = EntityId::new();
        let beta = EntityId::new();
        let gamma = EntityId::new();
        let add_both_id = make_change_id(65);
        let revise_alpha_id = make_change_id(66);
        let add_both = make_semantic_change(
            add_both_id,
            vec![],
            vec![
                EntityDelta::Added {
                    new: make_entity_version(alpha, "alpha", 1),
                },
                EntityDelta::Added {
                    new: make_entity_version(beta, "beta", 1),
                },
            ],
            vec![],
        );
        let revise_alpha = make_semantic_change(
            revise_alpha_id,
            vec![add_both_id],
            vec![
                EntityDelta::Modified {
                    old: make_entity_version(alpha, "alpha", 1),
                    new: make_entity_version(alpha, "alpha", 2),
                },
                EntityDelta::Removed {
                    old: make_entity_version(beta, "beta", 1),
                },
                EntityDelta::Added {
                    new: make_entity_version(gamma, "gamma", 1),
                },
            ],
            vec![],
        );
        let history = vec![add_both, revise_alpha];
        let whole_graph = derive_entity_revisions_from_changes(history.clone()).unwrap();

        for entity_id in [alpha, beta, gamma] {
            assert_eq!(
                replay_entity_revisions(history.clone(), &entity_id).unwrap(),
                whole_graph.get(&entity_id).cloned().unwrap_or_default(),
                "per-entity replay diverged for {entity_id}"
            );
        }
    }

    #[test]
    fn merge_revision_records_all_parent_predecessors_in_parent_order() {
        let root_id = make_change_id(50);
        let left_id = make_change_id(51);
        let right_id = make_change_id(52);
        let merge_id = make_change_id(53);
        let artifact_id = ArtifactId::new();
        let base = TreeEntry::blob(Hash256::from_bytes([0x50; 32]), false);
        let left = TreeEntry::blob(Hash256::from_bytes([0x51; 32]), false);
        let right = TreeEntry::blob(Hash256::from_bytes([0x52; 32]), false);
        let merged = TreeEntry::blob(Hash256::from_bytes([0x53; 32]), false);

        let mut root = make_semantic_change(root_id, vec![], vec![], vec![]);
        root.tree_deltas = vec![TreeDelta::Added {
            artifact_id,
            new: LocatedEntry::new(repo_path("artifact"), base),
        }];
        let mut left_change = make_semantic_change(left_id, vec![root_id], vec![], vec![]);
        left_change.tree_deltas = vec![TreeDelta::Updated {
            artifact_id,
            old: LocatedEntry::new(repo_path("artifact"), base),
            new: LocatedEntry::new(repo_path("artifact"), left),
        }];
        let mut right_change = make_semantic_change(right_id, vec![root_id], vec![], vec![]);
        right_change.tree_deltas = vec![TreeDelta::Updated {
            artifact_id,
            old: LocatedEntry::new(repo_path("artifact"), base),
            new: LocatedEntry::new(repo_path("artifact"), right),
        }];
        let mut merge = make_semantic_change(merge_id, vec![left_id, right_id], vec![], vec![]);
        merge.tree_deltas = vec![TreeDelta::Updated {
            artifact_id,
            old: LocatedEntry::new(repo_path("artifact"), left),
            new: LocatedEntry::new(repo_path("artifact"), merged),
        }];
        let store = HistoryStore::from_changes([root, left_change, right_change, merge]);

        let revisions = store
            .get_artifact_revisions_at(&artifact_id, &merge_id)
            .unwrap();
        let root_revision = revisions
            .iter()
            .find(|revision| revision.introduced_by == root_id)
            .unwrap();
        let left_revision = revisions
            .iter()
            .find(|revision| revision.introduced_by == left_id)
            .unwrap();
        let right_revision = revisions
            .iter()
            .find(|revision| revision.introduced_by == right_id)
            .unwrap();
        let merge_revision = revisions
            .iter()
            .find(|revision| revision.introduced_by == merge_id)
            .unwrap();
        let active = store
            .resolve_artifact_revision_at(&artifact_id, &merge_id)
            .unwrap()
            .unwrap();

        assert_eq!(
            left_revision.predecessor_revisions,
            vec![root_revision.revision_id]
        );
        assert_eq!(
            right_revision.predecessor_revisions,
            vec![root_revision.revision_id]
        );
        assert_eq!(
            merge_revision.predecessor_revisions,
            vec![left_revision.revision_id, right_revision.revision_id]
        );
        assert_eq!(active.revision_id, merge_revision.revision_id);
    }

    #[test]
    fn resolved_graph_state_requires_exact_tree_state() {
        let payload_without_tree = serde_json::json!({
            "entities": {},
            "relations": {},
            "entity_revisions": {},
            "entity_tombstones": {},
            "relation_tombstones": {}
        });

        assert!(serde_json::from_value::<ResolvedGraphState>(payload_without_tree).is_err());
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
                vec![EntityDelta::Added {
                    new: entity_a.clone(),
                }],
                vec![],
            ),
            make_semantic_change(
                c2,
                vec![c1],
                vec![EntityDelta::Added {
                    new: entity_b.clone(),
                }],
                vec![],
            ),
            make_semantic_change(
                c3,
                vec![c2],
                vec![EntityDelta::Removed {
                    old: entity_a.clone(),
                }],
                vec![],
            ),
        ];

        let state = replay_graph_state(changes).unwrap();

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
            make_semantic_change(
                c1,
                vec![],
                vec![EntityDelta::Added { new: entity_a }],
                vec![],
            ),
            make_semantic_change(
                c2,
                vec![c1],
                vec![EntityDelta::Added { new: entity_b }],
                vec![],
            ),
        ];

        let state = replay_graph_state(changes).unwrap();

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
            make_semantic_change(
                c1,
                vec![],
                vec![EntityDelta::Added { new: entity_a }],
                vec![],
            ),
            make_semantic_change(
                c2,
                vec![c1],
                vec![EntityDelta::Added { new: entity_b }],
                vec![RelationDelta::Added {
                    new: relation.clone(),
                }],
            ),
            make_semantic_change(
                c3,
                vec![c2],
                vec![],
                vec![RelationDelta::Removed { old: relation }],
            ),
        ];

        let state = replay_graph_state(changes).unwrap();

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
    fn entity_removal_requires_explicit_relation_removal() {
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
            make_semantic_change(
                c1,
                vec![],
                vec![EntityDelta::Added {
                    new: entity_a.clone(),
                }],
                vec![],
            ),
            make_semantic_change(
                c2,
                vec![c1],
                vec![EntityDelta::Added { new: entity_b }],
                vec![RelationDelta::Added { new: relation }],
            ),
            make_semantic_change(
                c3,
                vec![c2],
                vec![EntityDelta::Removed { old: entity_a }],
                vec![],
            ),
        ];

        let error = replay_graph_state(changes).unwrap_err();
        assert!(error
            .to_string()
            .contains("relation removal must be explicit"));
    }

    #[test]
    fn exact_graph_and_tree_deltas_are_self_inverting() {
        let entity_id = EntityId::new();
        let mut old_entity = make_entity(entity_id, "old_name");
        let mut new_entity = old_entity.clone();
        new_entity.name = "new_name".to_string();

        let other_id = EntityId::new();
        let relation_id = RelationId::new();
        let old_relation = make_relation(relation_id, entity_id, other_id);
        let mut new_relation = old_relation.clone();
        new_relation.confidence = 0.75;

        let artifact_id = ArtifactId::new();
        let old_entry = LocatedEntry::new(
            repo_path("compose.yaml"),
            TreeEntry::blob(Hash256::from_bytes([0x91; 32]), false),
        );
        let new_entry = LocatedEntry::new(
            RepoPath::from_bytes(b"infra/compose-\xff.yaml".to_vec()).unwrap(),
            TreeEntry::symlink(Hash256::from_bytes([0x92; 32])),
        );
        let delta = TransactionDelta {
            entity_deltas: vec![EntityDelta::Modified {
                old: old_entity.clone(),
                new: new_entity,
            }],
            relation_deltas: vec![RelationDelta::Modified {
                old: old_relation,
                new: new_relation,
            }],
            tree_deltas: vec![TreeDelta::Updated {
                artifact_id,
                old: old_entry.clone(),
                new: new_entry,
            }],
            admission_policy_delta: None,
        };

        crate::validate_transaction_delta(&delta).unwrap();
        assert_eq!(delta.inverse().inverse(), delta);

        let base = ResolvedTree::from_artifacts([crate::ResolvedArtifact::new(
            artifact_id,
            old_entry.path.clone(),
            old_entry.entry,
        )])
        .unwrap();
        let changed = base.apply(&delta.tree_deltas).unwrap();
        assert_eq!(changed.apply(&delta.inverse().tree_deltas).unwrap(), base);

        old_entity.name = "stale_old_payload".to_string();
        let mut wrong_identity = old_entity.clone();
        wrong_identity.id = EntityId::new();
        let invalid = TransactionDelta {
            entity_deltas: vec![EntityDelta::Modified {
                old: old_entity,
                new: wrong_identity,
            }],
            ..TransactionDelta::default()
        };
        assert!(crate::validate_transaction_delta(&invalid).is_err());
    }

    #[test]
    fn exact_inverse_readdition_clears_entity_and_relation_tombstones() {
        let c1 = make_change_id(41);
        let c2 = make_change_id(42);
        let c3 = make_change_id(43);
        let entity_a = make_entity(EntityId::new(), "a");
        let entity_b = make_entity(EntityId::new(), "b");
        let relation = make_relation(RelationId::new(), entity_a.id, entity_b.id);
        let removal = TransactionDelta {
            entity_deltas: vec![EntityDelta::Removed {
                old: entity_a.clone(),
            }],
            relation_deltas: vec![RelationDelta::Removed {
                old: relation.clone(),
            }],
            ..TransactionDelta::default()
        };
        let restoration = removal.inverse();

        let changes = vec![
            make_semantic_change(
                c1,
                Vec::new(),
                vec![
                    EntityDelta::Added {
                        new: entity_a.clone(),
                    },
                    EntityDelta::Added { new: entity_b },
                ],
                vec![RelationDelta::Added {
                    new: relation.clone(),
                }],
            ),
            make_semantic_change(c2, vec![c1], removal.entity_deltas, removal.relation_deltas),
            make_semantic_change(
                c3,
                vec![c2],
                restoration.entity_deltas,
                restoration.relation_deltas,
            ),
        ];

        let state = replay_graph_state(changes).unwrap();
        assert_eq!(state.entities.get(&entity_a.id), Some(&entity_a));
        assert_eq!(state.relations.get(&relation.id), Some(&relation));
        assert!(!state.entity_tombstones.contains_key(&entity_a.id));
        assert!(!state.relation_tombstones.contains_key(&relation.id));
    }
}
