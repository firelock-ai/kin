// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod common;

// Handler submodules are public so each tool's rich `*_DESC` description const
// can live next to the handler that implements it, and be referenced by the
// MCP tool registry in `tools.rs`. Keeping the prose beside the code keeps the
// two from drifting apart.
pub mod bench;
pub mod entities;
pub mod provenance;
pub mod review;
pub mod sessions;
pub mod verification;
pub mod work;

use std::collections::HashMap;

use kin_model::graph::GraphStore;

use crate::error::{McpError, Result};
use crate::server::SessionAuthorityMode;
use crate::session::SessionRegistry;
use crate::types::ToolCallResult;

/// Dispatch a tool call to the appropriate handler.
pub async fn handle_tool_call<G: GraphStore>(
    tool_name: &str,
    arguments: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
) -> Result<ToolCallResult> {
    match tool_name {
        // Entities
        "semantic_search" => entities::handle_semantic_search(arguments, store),
        "semantic_locate" => entities::handle_semantic_locate(arguments, store),
        "get_entity" => entities::handle_get_entity(arguments, store),
        "get_entity_source" | "get_entity_body" => {
            entities::handle_get_entity_source(arguments, store)
        }
        "get_context_pack" => entities::handle_get_context_pack(arguments, store, sessions),
        "trace_computation" => entities::handle_trace_computation(arguments, store, sessions),
        "trace_data_flow" => entities::handle_trace_data_flow(arguments, store),
        "find_references" => entities::handle_find_references(arguments, store).await,
        "bulk_check_references" => entities::handle_bulk_check_references(arguments, store),
        "explore_codebase" => entities::handle_explore_codebase(arguments, store),
        "dead_code" => entities::handle_dead_code(arguments, store),
        "find_dead_code_seeded" => entities::handle_find_dead_code_seeded(arguments, store),
        "graph_neighborhood" => entities::handle_graph_neighborhood(arguments, store),
        // Review
        "semantic_diff" => review::handle_semantic_diff(arguments, store),
        "impact_analysis" => review::handle_impact_analysis(arguments, store, sessions).await,
        "semantic_review" => review::handle_semantic_review(arguments, store, sessions),
        "entity_history" => review::handle_entity_history(arguments, store),
        // Sessions
        "register_session" => sessions::handle_register_session(arguments, sessions),
        "kin_session_start" => {
            sessions::handle_session_start(arguments, sessions, session_authority_mode).await
        }
        "kin_session_heartbeat" => {
            sessions::handle_session_heartbeat(arguments, sessions, session_authority_mode).await
        }
        "kin_session_end" => {
            sessions::handle_session_end(arguments, sessions, session_authority_mode).await
        }
        "kin_register_intent" => {
            sessions::handle_register_intent(arguments, sessions, session_authority_mode).await
        }
        "kin_release_intent" => {
            sessions::handle_release_intent(arguments, sessions, session_authority_mode).await
        }
        "kin_check_traffic" => {
            sessions::handle_check_traffic(arguments, sessions, session_authority_mode).await
        }
        "kin_transaction_begin" => {
            sessions::handle_transaction_begin(arguments, sessions, session_authority_mode).await
        }
        "kin_transaction_stage" => {
            sessions::handle_transaction_stage(arguments, sessions, session_authority_mode).await
        }
        "kin_transaction_validate" => {
            sessions::handle_transaction_validate(arguments, sessions, session_authority_mode).await
        }
        "kin_transaction_commit" => {
            sessions::handle_transaction_commit(arguments, store, sessions, session_authority_mode)
                .await
        }
        "kin_transaction_abort" => {
            sessions::handle_transaction_abort(arguments, sessions, session_authority_mode).await
        }
        // Work graph and annotations
        "kin_work_create" => work::handle_work_create(arguments, store),
        "kin_work_list" => work::handle_work_list(arguments, store),
        "kin_work_show" => work::handle_work_show(arguments, store),
        "kin_work_link" => work::handle_work_link(arguments, store),
        "kin_work_decompose" => work::handle_work_decompose(arguments, store),
        "kin_work_block" => work::handle_work_block(arguments, store),
        "kin_work_implement" => work::handle_work_implement(arguments, store),
        "kin_work_status" => work::handle_work_status(arguments, store),
        "kin_annotation_add" => work::handle_annotation_add(arguments, store),
        "kin_annotation_list" => work::handle_annotation_list(arguments, store),
        "kin_annotation_mark_resolved" => work::handle_annotation_mark_resolved(arguments, store),
        "kin_todo_import" => work::handle_todo_import(arguments, store),
        // Verification, security, release, contract
        "kin_verify_entity" => verification::handle_verify_entity(arguments, store),
        "kin_coverage_summary" => verification::handle_coverage_summary(store),
        "kin_security_scan" => verification::handle_security_scan(arguments, store),
        "kin_release_check" => verification::handle_release_check(arguments, store),
        "kin_contract_check" => verification::handle_contract_check(arguments, store),
        // Review mutations (Phase 11)
        "kin_review_create" => review::handle_review_create(arguments, store),
        "kin_review_decide" => review::handle_review_decide(arguments, store),
        "kin_review_note_add" => review::handle_review_note_add(arguments, store),
        "kin_review_discuss" => review::handle_review_discuss(arguments, store),
        "kin_review_discuss_reply" => review::handle_review_discuss_reply(arguments, store),
        "kin_review_discuss_resolve" => review::handle_review_discuss_resolve(arguments, store),
        "kin_review_assign" => review::handle_review_assign(arguments, store),
        "kin_review_unassign" => review::handle_review_unassign(arguments, store),
        "kin_review_list" => review::handle_review_list(arguments, store),
        "kin_review_get" => review::handle_review_get(arguments, store),
        // Provenance
        "kin_provenance_query" => provenance::handle_provenance_query(arguments, store),
        // Graph status
        "kin_graph_status" => entities::handle_graph_status(arguments, store),
        // Benchmark
        "benchmark" => bench::handle_benchmark(arguments, store),
        _ => Err(McpError::ToolNotFound(tool_name.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::common::*;
    use super::*;
    use kin_db::{InMemoryGraph, KinDbError};
    use kin_model::branch::Branch;
    use kin_model::change::SemanticChange;
    use kin_model::entity::Entity;
    use kin_model::entity::{EntityKind, Visibility};
    use kin_model::graph::{EntityFilter, SubGraph};
    use kin_model::ids::*;
    use kin_model::relation::{Relation, RelationKind};
    use kin_model::session::{IntentScope, LockType, SessionCapabilities, SessionTransport};
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[derive(Default)]
    struct EmptyStore {
        entities_by_file: HashMap<String, Vec<Entity>>,
        entities_by_id: HashMap<EntityId, Entity>,
        relations_by_entity: HashMap<EntityId, Vec<Relation>>,
        dead_entities: Vec<Entity>,
        live_entity_ids: HashSet<EntityId>,
        file_hashes: HashMap<FilePathId, Hash256>,
        branches: Vec<Branch>,
        changes_by_id: HashMap<SemanticChangeId, SemanticChange>,
        approvals_by_change: HashMap<SemanticChangeId, Vec<kin_model::provenance::Approval>>,
    }

    impl kin_model::graph::EntityStore for EmptyStore {
        type Error = KinDbError;

        fn get_entity(&self, id: &EntityId) -> std::result::Result<Option<Entity>, Self::Error> {
            Ok(self.entities_by_id.get(id).cloned())
        }
        fn get_relations(
            &self,
            id: &EntityId,
            kinds: &[RelationKind],
        ) -> std::result::Result<Vec<Relation>, Self::Error> {
            Ok(self
                .relations_by_entity
                .get(id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|relation| kinds.contains(&relation.kind))
                .collect())
        }
        fn get_all_relations_for_entity(
            &self,
            id: &EntityId,
        ) -> std::result::Result<Vec<Relation>, Self::Error> {
            Ok(self
                .relations_by_entity
                .get(id)
                .cloned()
                .unwrap_or_default())
        }
        fn get_downstream_impact(
            &self,
            _: &EntityId,
            _: u32,
        ) -> std::result::Result<Vec<Entity>, Self::Error> {
            Ok(vec![])
        }
        fn get_dependency_neighborhood(
            &self,
            _: &EntityId,
            _: u32,
        ) -> std::result::Result<SubGraph, Self::Error> {
            Ok(SubGraph::default())
        }
        fn expand_neighborhood(
            &self,
            _: &[EntityId],
            _: &[RelationKind],
            _: u32,
        ) -> std::result::Result<SubGraph, Self::Error> {
            Ok(SubGraph::default())
        }
        fn find_dead_code(&self) -> std::result::Result<Vec<Entity>, Self::Error> {
            Ok(self.dead_entities.clone())
        }
        fn has_incoming_relation_kinds(
            &self,
            id: &EntityId,
            _: &[RelationKind],
            _: bool,
        ) -> std::result::Result<bool, Self::Error> {
            Ok(self.live_entity_ids.contains(id))
        }
        fn query_entities(
            &self,
            filter: &EntityFilter,
        ) -> std::result::Result<Vec<Entity>, Self::Error> {
            if let Some(file_path) = filter.file_path.as_ref() {
                return Ok(self
                    .entities_by_file
                    .get(&file_path.0)
                    .cloned()
                    .unwrap_or_default());
            }

            let mut entities = self.entities_by_id.values().cloned().collect::<Vec<_>>();
            if let Some(name_pattern) = filter.name_pattern.as_ref() {
                let needle = name_pattern.to_ascii_lowercase();
                entities.retain(|entity| entity.name.to_ascii_lowercase().contains(&needle));
            }
            Ok(entities)
        }
        fn list_all_entities(&self) -> std::result::Result<Vec<Entity>, Self::Error> {
            Ok(self.entities_by_id.values().cloned().collect())
        }
        fn upsert_entity(&self, _: &Entity) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn upsert_relation(&self, _: &Relation) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn remove_entity(&self, _: &EntityId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn remove_relation(&self, _: &RelationId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn upsert_shallow_file(
            &self,
            _: &kin_model::ShallowTrackedFile,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_shallow_files(
            &self,
        ) -> std::result::Result<Vec<kin_model::ShallowTrackedFile>, Self::Error> {
            Ok(vec![])
        }
        fn upsert_structured_artifact(
            &self,
            _: &kin_model::StructuredArtifact,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_structured_artifacts(
            &self,
        ) -> std::result::Result<Vec<kin_model::StructuredArtifact>, Self::Error> {
            Ok(vec![])
        }
        fn delete_structured_artifact(
            &self,
            _: &FilePathId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn upsert_opaque_artifact(
            &self,
            _: &kin_model::OpaqueArtifact,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_opaque_artifacts(
            &self,
        ) -> std::result::Result<Vec<kin_model::OpaqueArtifact>, Self::Error> {
            Ok(vec![])
        }
        fn delete_opaque_artifact(&self, _: &FilePathId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn upsert_file_layout(
            &self,
            _: &kin_model::FileLayout,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_file_layout(
            &self,
            _: &FilePathId,
        ) -> std::result::Result<Option<kin_model::FileLayout>, Self::Error> {
            Ok(None)
        }
        fn list_file_layouts(
            &self,
        ) -> std::result::Result<Vec<kin_model::FileLayout>, Self::Error> {
            Ok(vec![])
        }
        fn delete_file_layout(&self, _: &FilePathId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn traverse(
            &self,
            _: &kin_model::GraphNodeId,
            _: &[RelationKind],
            _: u32,
        ) -> std::result::Result<SubGraph, Self::Error> {
            Ok(SubGraph::default())
        }
        fn get_shallow_file(
            &self,
            _: &FilePathId,
        ) -> std::result::Result<Option<kin_model::ShallowTrackedFile>, Self::Error> {
            Ok(None)
        }
        fn get_structured_artifact(
            &self,
            _: &FilePathId,
        ) -> std::result::Result<Option<kin_model::StructuredArtifact>, Self::Error> {
            Ok(None)
        }
        fn get_opaque_artifact(
            &self,
            _: &FilePathId,
        ) -> std::result::Result<Option<kin_model::OpaqueArtifact>, Self::Error> {
            Ok(None)
        }
        fn get_file_hash(
            &self,
            file_id: &FilePathId,
        ) -> std::result::Result<Option<kin_model::Hash256>, Self::Error> {
            Ok(self.file_hashes.get(file_id).copied())
        }
    }

    impl kin_model::graph::ChangeStore for EmptyStore {
        type Error = KinDbError;

        fn get_entity_history(
            &self,
            _: &EntityId,
        ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
            Ok(vec![])
        }
        fn find_merge_bases(
            &self,
            _: &SemanticChangeId,
            _: &SemanticChangeId,
        ) -> std::result::Result<Vec<SemanticChangeId>, Self::Error> {
            Ok(vec![])
        }
        fn create_change(&self, _: &SemanticChange) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_change(
            &self,
            id: &SemanticChangeId,
        ) -> std::result::Result<Option<SemanticChange>, Self::Error> {
            Ok(self.changes_by_id.get(id).cloned())
        }
        fn get_changes_since(
            &self,
            _: &SemanticChangeId,
            _: &SemanticChangeId,
        ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
            Ok(vec![])
        }
        fn get_branch(
            &self,
            name: &BranchName,
        ) -> std::result::Result<Option<Branch>, Self::Error> {
            Ok(self.branches.iter().find(|b| &b.name == name).cloned())
        }
        fn create_branch(&self, _: &Branch) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn update_branch_head(
            &self,
            _: &BranchName,
            _: &SemanticChangeId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn delete_branch(&self, _: &BranchName) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_branches(&self) -> std::result::Result<Vec<Branch>, Self::Error> {
            Ok(self.branches.clone())
        }
    }

    impl kin_model::graph::WorkStore for EmptyStore {
        type Error = KinDbError;

        fn create_work_item(
            &self,
            _: &kin_model::WorkItem,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_work_item(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Option<kin_model::WorkItem>, Self::Error> {
            Ok(None)
        }
        fn list_work_items(
            &self,
            _: &kin_model::WorkFilter,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn update_work_status(
            &self,
            _: &kin_model::WorkId,
            _: kin_model::WorkStatus,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn delete_work_item(&self, _: &kin_model::WorkId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_annotation(
            &self,
            _: &kin_model::Annotation,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_annotation(
            &self,
            _: &kin_model::AnnotationId,
        ) -> std::result::Result<Option<kin_model::Annotation>, Self::Error> {
            Ok(None)
        }
        fn list_annotations(
            &self,
            _: &kin_model::AnnotationFilter,
        ) -> std::result::Result<Vec<kin_model::Annotation>, Self::Error> {
            Ok(vec![])
        }
        fn update_annotation_staleness(
            &self,
            _: &kin_model::AnnotationId,
            _: kin_model::StalenessState,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn delete_annotation(
            &self,
            _: &kin_model::AnnotationId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_work_link(
            &self,
            _: &kin_model::WorkLink,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn delete_work_link(
            &self,
            _: &kin_model::WorkLink,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_work_for_scope(
            &self,
            _: &kin_model::WorkScope,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_annotations_for_scope(
            &self,
            _: &kin_model::WorkScope,
        ) -> std::result::Result<Vec<kin_model::Annotation>, Self::Error> {
            Ok(vec![])
        }
        fn get_child_work_items(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_parent_work_items(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_blockers(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_blocked_work_items(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_implementors(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkScope>, Self::Error> {
            Ok(vec![])
        }
        fn get_annotations_for_work_item(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::Annotation>, Self::Error> {
            Ok(vec![])
        }
    }

    impl kin_model::graph::ReviewStore for EmptyStore {
        type Error = KinDbError;

        fn create_review(
            &self,
            _: &kin_model::review::Review,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_review(
            &self,
            _: &kin_model::review::ReviewId,
        ) -> std::result::Result<Option<kin_model::review::Review>, Self::Error> {
            Ok(None)
        }
        fn list_reviews(
            &self,
            _: &kin_model::review::ReviewFilter,
        ) -> std::result::Result<Vec<kin_model::review::Review>, Self::Error> {
            Ok(vec![])
        }
        fn update_review_state(
            &self,
            _: &kin_model::review::ReviewId,
            _: kin_model::review::ReviewDecisionState,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn delete_review(
            &self,
            _: &kin_model::review::ReviewId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn add_review_decision(
            &self,
            _: &kin_model::review::ReviewId,
            _: &kin_model::review::ReviewDecision,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_review_decisions(
            &self,
            _: &kin_model::review::ReviewId,
        ) -> std::result::Result<Vec<kin_model::review::ReviewDecision>, Self::Error> {
            Ok(vec![])
        }
        fn add_review_note(
            &self,
            _: &kin_model::review::ReviewNote,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_review_notes(
            &self,
            _: &kin_model::review::ReviewId,
        ) -> std::result::Result<Vec<kin_model::review::ReviewNote>, Self::Error> {
            Ok(vec![])
        }
        fn delete_review_note(
            &self,
            _: &kin_model::review::ReviewNoteId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_review_discussion(
            &self,
            _: &kin_model::review::ReviewDiscussion,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_review_discussions(
            &self,
            _: &kin_model::review::ReviewId,
        ) -> std::result::Result<Vec<kin_model::review::ReviewDiscussion>, Self::Error> {
            Ok(vec![])
        }
        fn add_discussion_comment(
            &self,
            _: &kin_model::review::ReviewDiscussionId,
            _: &kin_model::review::ReviewComment,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn set_discussion_state(
            &self,
            _: &kin_model::review::ReviewDiscussionId,
            _: kin_model::review::ReviewDiscussionState,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn assign_reviewer(
            &self,
            _: &kin_model::review::ReviewAssignment,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_review_assignments(
            &self,
            _: &kin_model::review::ReviewId,
        ) -> std::result::Result<Vec<kin_model::review::ReviewAssignment>, Self::Error> {
            Ok(vec![])
        }
        fn remove_reviewer(
            &self,
            _: &kin_model::review::ReviewId,
            _: &str,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
    }

    impl kin_model::graph::VerificationStore for EmptyStore {
        type Error = KinDbError;

        fn create_test_case(
            &self,
            _: &kin_model::verification::TestCase,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_test_case(
            &self,
            _: &kin_model::verification::TestId,
        ) -> std::result::Result<Option<kin_model::verification::TestCase>, Self::Error> {
            Ok(None)
        }
        fn get_tests_for_entity(
            &self,
            _: &EntityId,
        ) -> std::result::Result<Vec<kin_model::verification::TestCase>, Self::Error> {
            Ok(vec![])
        }
        fn delete_test_case(
            &self,
            _: &kin_model::verification::TestId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_assertion(
            &self,
            _: &kin_model::verification::Assertion,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_assertion(
            &self,
            _: &kin_model::verification::AssertionId,
        ) -> std::result::Result<Option<kin_model::verification::Assertion>, Self::Error> {
            Ok(None)
        }
        fn get_coverage_summary(
            &self,
        ) -> std::result::Result<kin_model::verification::CoverageSummary, Self::Error> {
            Ok(kin_model::verification::CoverageSummary {
                total_entities: 0,
                covered_entities: 0,
                coverage_ratio: 0.0,
                missing_proof: vec![],
            })
        }
        fn create_verification_run(
            &self,
            _: &kin_model::verification::VerificationRun,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_verification_run(
            &self,
            _: &kin_model::verification::VerificationRunId,
        ) -> std::result::Result<Option<kin_model::verification::VerificationRun>, Self::Error>
        {
            Ok(None)
        }
        fn list_runs_for_test(
            &self,
            _: &kin_model::verification::TestId,
        ) -> std::result::Result<Vec<kin_model::verification::VerificationRun>, Self::Error>
        {
            Ok(vec![])
        }
        fn create_test_covers_entity(
            &self,
            _: &kin_model::verification::TestId,
            _: &EntityId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_test_covers_contract(
            &self,
            _: &kin_model::verification::TestId,
            _: &ContractId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_test_verifies_work(
            &self,
            _: &kin_model::verification::TestId,
            _: &kin_model::WorkId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_tests_covering_contract(
            &self,
            _: &ContractId,
        ) -> std::result::Result<Vec<kin_model::verification::TestCase>, Self::Error> {
            Ok(vec![])
        }
        fn get_tests_verifying_work(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::verification::TestCase>, Self::Error> {
            Ok(vec![])
        }
        fn create_mock_hint(
            &self,
            _: &kin_model::verification::MockHint,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_mock_hints_for_test(
            &self,
            _: &kin_model::verification::TestId,
        ) -> std::result::Result<Vec<kin_model::verification::MockHint>, Self::Error> {
            Ok(vec![])
        }
        fn link_run_proves_entity(
            &self,
            _: &kin_model::verification::VerificationRunId,
            _: &EntityId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn link_run_proves_work(
            &self,
            _: &kin_model::verification::VerificationRunId,
            _: &kin_model::WorkId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_runs_proving_entity(
            &self,
            _: &kin_model::EntityId,
        ) -> std::result::Result<Vec<kin_model::verification::VerificationRun>, Self::Error>
        {
            Ok(vec![])
        }
        fn list_runs_proving_work(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::verification::VerificationRun>, Self::Error>
        {
            Ok(vec![])
        }
        fn get_contract_coverage_summary(
            &self,
        ) -> std::result::Result<kin_model::verification::ContractCoverageSummary, Self::Error>
        {
            Ok(kin_model::verification::ContractCoverageSummary {
                total_contracts: 0,
                covered_contracts: 0,
                coverage_ratio: 0.0,
                uncovered_contract_ids: vec![],
            })
        }
        fn create_contract(
            &self,
            _: &kin_model::contract::Contract,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_contract(
            &self,
            _: &kin_model::ids::ContractId,
        ) -> std::result::Result<Option<kin_model::contract::Contract>, Self::Error> {
            Ok(None)
        }
        fn list_contracts(
            &self,
        ) -> std::result::Result<Vec<kin_model::contract::Contract>, Self::Error> {
            Ok(vec![])
        }
    }

    impl kin_model::graph::ProvenanceStore for EmptyStore {
        type Error = KinDbError;

        fn create_actor(
            &self,
            _: &kin_model::provenance::Actor,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_actor(
            &self,
            _: &kin_model::provenance::ActorId,
        ) -> std::result::Result<Option<kin_model::provenance::Actor>, Self::Error> {
            Ok(None)
        }
        fn list_actors(
            &self,
        ) -> std::result::Result<Vec<kin_model::provenance::Actor>, Self::Error> {
            Ok(vec![])
        }
        fn create_delegation(
            &self,
            _: &kin_model::provenance::Delegation,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_delegations_for_actor(
            &self,
            _: &kin_model::provenance::ActorId,
        ) -> std::result::Result<Vec<kin_model::provenance::Delegation>, Self::Error> {
            Ok(vec![])
        }
        fn create_approval(
            &self,
            _: &kin_model::provenance::Approval,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_approvals_for_change(
            &self,
            id: &SemanticChangeId,
        ) -> std::result::Result<Vec<kin_model::provenance::Approval>, Self::Error> {
            Ok(self
                .approvals_by_change
                .get(id)
                .cloned()
                .unwrap_or_default())
        }
        fn record_audit_event(
            &self,
            _: &kin_model::provenance::AuditEvent,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn query_audit_events(
            &self,
            _: Option<&kin_model::provenance::ActorId>,
            _: usize,
        ) -> std::result::Result<Vec<kin_model::provenance::AuditEvent>, Self::Error> {
            Ok(vec![])
        }
    }

    impl kin_model::graph::SessionStore for EmptyStore {
        type Error = KinDbError;

        fn upsert_session(
            &self,
            _: &kin_model::session::AgentSession,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_session(
            &self,
            _: &kin_model::SessionId,
        ) -> std::result::Result<Option<kin_model::session::AgentSession>, Self::Error> {
            Ok(None)
        }
        fn delete_session(&self, _: &kin_model::SessionId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_sessions(
            &self,
        ) -> std::result::Result<Vec<kin_model::session::AgentSession>, Self::Error> {
            Ok(vec![])
        }
        fn update_heartbeat(
            &self,
            _: &kin_model::SessionId,
            _: &kin_model::timestamp::Timestamp,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn register_intent(
            &self,
            _: &kin_model::session::Intent,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_intent(
            &self,
            _: &kin_model::IntentId,
        ) -> std::result::Result<Option<kin_model::session::Intent>, Self::Error> {
            Ok(None)
        }
        fn delete_intent(&self, _: &kin_model::IntentId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_intents_for_session(
            &self,
            _: &kin_model::SessionId,
        ) -> std::result::Result<Vec<kin_model::session::Intent>, Self::Error> {
            Ok(vec![])
        }
        fn list_all_intents(
            &self,
        ) -> std::result::Result<Vec<kin_model::session::Intent>, Self::Error> {
            Ok(vec![])
        }
    }

    impl kin_model::graph::GraphStore for EmptyStore {
        type Error = KinDbError;
    }

    #[test]
    fn parse_entity_id_valid() {
        let id = EntityId::new().to_string();
        let result = parse_entity_id(&id);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_entity_id_invalid() {
        let result = parse_entity_id("not-a-uuid");
        assert!(result.is_err());
    }

    #[test]
    fn parse_change_id_valid() {
        let hex = "aa".repeat(32);
        let result = parse_change_id(&hex);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_change_id_invalid() {
        let result = parse_change_id("zzz");
        assert!(result.is_err());
    }

    #[test]
    fn parse_transport_values() {
        assert_eq!(parse_transport("mcp"), SessionTransport::Mcp);
        assert_eq!(parse_transport("cli"), SessionTransport::Cli);
        assert_eq!(parse_transport("wrapper"), SessionTransport::Wrapper);
        assert_eq!(parse_transport("ui"), SessionTransport::Ui);
        assert_eq!(parse_transport("unknown"), SessionTransport::Mcp);
    }

    #[test]
    fn parse_lock_type_values() {
        assert_eq!(parse_lock_type("soft"), LockType::Soft);
        assert_eq!(parse_lock_type("hard"), LockType::Hard);
        assert_eq!(parse_lock_type("anything"), LockType::Soft);
    }

    #[test]
    fn parse_session_id_valid() {
        let id = SessionId::new().to_string();
        let result = parse_session_id(&id);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_scopes_valid() {
        let entity_id = EntityId::new();
        let val = serde_json::json!([
            { "Entity": entity_id },
            { "Artifact": "src/main.rs" }
        ]);
        let result = parse_scopes(&val);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn parse_scopes_invalid() {
        let val = serde_json::json!("not an array");
        let result = parse_scopes(&val);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn unknown_tool_returns_error() {
        let store = EmptyStore::default();
        let sessions = SessionRegistry::new();
        let args = HashMap::new();
        let result = handle_tool_call(
            "nonexistent_tool",
            &args,
            &store,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
        )
        .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), McpError::ToolNotFound(_)));
    }

    #[tokio::test]
    async fn session_start_and_heartbeat_and_end() {
        let store = EmptyStore::default();
        let sessions = SessionRegistry::new();

        // Start a session
        let mut start_args = HashMap::new();
        start_args.insert("vendor".into(), serde_json::json!("claude-code"));
        start_args.insert("client_name".into(), serde_json::json!("test-client"));
        start_args.insert("cwd".into(), serde_json::json!("/project"));
        start_args.insert("transport".into(), serde_json::json!("mcp"));

        let result = handle_tool_call(
            "kin_session_start",
            &start_args,
            &store,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
        )
        .await
        .unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response["status"], "active");
        assert_eq!(response["vendor"], "claude-code");

        let session_id = response["session_id"].as_str().unwrap().to_string();

        // Heartbeat
        let mut hb_args = HashMap::new();
        hb_args.insert("session_id".into(), serde_json::json!(session_id));
        let result = handle_tool_call(
            "kin_session_heartbeat",
            &hb_args,
            &store,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
        )
        .await
        .unwrap();
        assert!(result.is_error.is_none());

        // End session
        let mut end_args = HashMap::new();
        end_args.insert("session_id".into(), serde_json::json!(session_id));
        let result = handle_tool_call(
            "kin_session_end",
            &end_args,
            &store,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
        )
        .await
        .unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response["status"], "ended");
    }

    #[tokio::test]
    async fn register_and_release_intent() {
        let sessions = SessionRegistry::new();

        // Start session first
        let session = sessions.start_agent_session(
            "codex",
            "test",
            SessionTransport::Cli,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities::default(),
        );
        let session_id_str = session.session_id.to_string();

        let entity_id = EntityId::new();

        // Register intent
        let mut args = HashMap::new();
        args.insert("session_id".into(), serde_json::json!(session_id_str));
        args.insert(
            "scopes".into(),
            serde_json::json!([{ "Entity": entity_id }]),
        );
        args.insert("lock_type".into(), serde_json::json!("hard"));
        args.insert(
            "task_description".into(),
            serde_json::json!("editing auth module"),
        );

        let result = sessions::handle_register_intent(
            &args,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
        )
        .await
        .unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response["status"], "registered");
        let intent_id = response["intent_id"].as_str().unwrap().to_string();

        // Release intent
        let mut release_args = HashMap::new();
        release_args.insert("session_id".into(), serde_json::json!(session_id_str));
        release_args.insert("intent_id".into(), serde_json::json!(intent_id));
        let result = sessions::handle_release_intent(
            &release_args,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
        )
        .await
        .unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response["status"], "released");
    }

    #[tokio::test]
    async fn check_traffic_with_active_intents() {
        let sessions = SessionRegistry::new();

        let session = sessions.start_agent_session(
            "claude-code",
            "test",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/project"),
            SessionCapabilities::default(),
        );

        let entity_id = EntityId::new();
        sessions.register_intent(
            session.session_id,
            vec![IntentScope::Entity(entity_id)],
            LockType::Soft,
            "refactoring".into(),
            None,
        );

        let mut args = HashMap::new();
        args.insert(
            "scopes".into(),
            serde_json::json!([{ "Entity": entity_id }]),
        );
        let result =
            sessions::handle_check_traffic(&args, &sessions, SessionAuthorityMode::OfflineFallback)
                .await
                .unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response["scope_count"], 1);
        let reports = response["reports"].as_array().unwrap();
        assert_eq!(reports.len(), 1);
        assert!(!reports[0]["active_intents"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn register_intent_without_session_fails() {
        let sessions = SessionRegistry::new();

        let mut args = HashMap::new();
        args.insert(
            "session_id".into(),
            serde_json::json!(SessionId::new().to_string()),
        );
        args.insert(
            "scopes".into(),
            serde_json::json!([{ "Entity": EntityId::new() }]),
        );
        args.insert("task_description".into(), serde_json::json!("test"));

        let result = sessions::handle_register_intent(
            &args,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
        )
        .await
        .unwrap();
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn get_optional_bool_test() {
        let mut args = HashMap::new();
        args.insert("flag".into(), serde_json::json!(false));
        assert!(!get_optional_bool(&args, "flag", true));
        assert!(get_optional_bool(&args, "missing", true));
    }

    #[test]
    fn function_filter_includes_methods() {
        let kinds = parse_kind_filter("function").unwrap();
        assert!(kinds.contains(&EntityKind::Function));
        assert!(kinds.contains(&EntityKind::Method));
    }

    #[test]
    fn language_filter_supports_aliases() {
        assert_eq!(
            parse_language_filter("js"),
            Some(vec![LanguageId::JavaScript])
        );
        assert_eq!(
            parse_language_filter("ts"),
            Some(vec![LanguageId::TypeScript])
        );
        assert_eq!(parse_language_filter("py"), Some(vec![LanguageId::Python]));
        assert_eq!(parse_language_filter("c"), Some(vec![LanguageId::C]));
        assert_eq!(parse_language_filter("c++"), Some(vec![LanguageId::Cpp]));
        assert_eq!(parse_language_filter("cs"), Some(vec![LanguageId::CSharp]));
        assert_eq!(parse_language_filter("rb"), Some(vec![LanguageId::Ruby]));
    }

    #[test]
    fn build_semantic_search_request_applies_language_and_kind_filters() {
        let mut args = HashMap::new();
        args.insert("query".into(), serde_json::json!("save"));
        args.insert("kind".into(), serde_json::json!("function"));
        args.insert("language".into(), serde_json::json!("javascript"));
        args.insert("limit".into(), serde_json::json!(7));

        let (query, limit, filter) = build_semantic_search_request(&args).unwrap();
        assert_eq!(query, "save");
        assert_eq!(limit, 7);
        assert_eq!(filter.languages, Some(vec![LanguageId::JavaScript]));

        let kinds = filter.kinds.unwrap();
        assert!(kinds.contains(&EntityKind::Function));
        assert!(kinds.contains(&EntityKind::Method));
    }

    fn make_source_backed_entity(content: &str) -> (tempfile::TempDir, Entity) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("validate.ts");
        fs::write(&path, content).unwrap();
        let file_id = kin_model::ids::FilePathId::new(path.to_string_lossy());

        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "validate_probe_range_1d8f8275".into(),
            language: LanguageId::TypeScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                stability_score: 0.9,
            },
            file_origin: Some(file_id.clone()),
            span: Some(kin_model::entity::SourceSpan {
                file: file_id,
                start_byte: 0,
                end_byte: content.len(),
                start_line: 1,
                start_col: 0,
                end_line: content.lines().count() as u32,
                end_col: 1,
            }),
            signature: "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean".into(),
            visibility: kin_model::entity::Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: Some("Validate an inclusive numeric range.".into()),
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        (dir, entity)
    }

    fn make_signature_only_python_entity(content: &str) -> (tempfile::TempDir, Entity) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("validate.py");
        fs::write(&path, content).unwrap();
        let file_id = kin_model::ids::FilePathId::new(path.to_string_lossy());
        let signature = content
            .lines()
            .next()
            .unwrap_or_default()
            .trim_end_matches(':')
            .to_string();
        let end_byte = content.lines().next().unwrap_or_default().len();

        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "validate_probe_range_f0cc1f1d".into(),
            language: LanguageId::Python,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([9; 32]),
                signature_hash: Hash256::from_bytes([10; 32]),
                behavior_hash: Hash256::from_bytes([11; 32]),
                stability_score: 0.9,
            },
            file_origin: Some(file_id.clone()),
            span: Some(kin_model::entity::SourceSpan {
                file: file_id,
                start_byte: 0,
                end_byte,
                start_line: 1,
                start_col: 0,
                end_line: 1,
                end_col: end_byte as u32,
            }),
            signature,
            visibility: kin_model::entity::Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        (dir, entity)
    }

    fn make_dead_code_entity(file_path: &str, name: &str, start_line: u32) -> Entity {
        let file_id = kin_model::ids::FilePathId::new(file_path);
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.into(),
            language: LanguageId::TypeScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([4; 32]),
                signature_hash: Hash256::from_bytes([5; 32]),
                behavior_hash: Hash256::from_bytes([6; 32]),
                stability_score: 0.9,
            },
            file_origin: Some(file_id.clone()),
            span: Some(kin_model::entity::SourceSpan {
                file: file_id,
                start_byte: 0,
                end_byte: 32,
                start_line,
                start_col: 0,
                end_line: start_line + 1,
                end_col: 1,
            }),
            signature: format!("export function {name}(): number"),
            visibility: Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn make_trace_entity(
        dir: &tempfile::TempDir,
        rel_path: &str,
        name: &str,
        kind: EntityKind,
        signature: &str,
        content: &str,
    ) -> Entity {
        let path = dir.path().join(rel_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, content).unwrap();
        let file_id = kin_model::ids::FilePathId::new(path.to_string_lossy());

        Entity {
            id: EntityId::new(),
            kind,
            name: name.into(),
            language: LanguageId::TypeScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([7; 32]),
                signature_hash: Hash256::from_bytes([8; 32]),
                behavior_hash: Hash256::from_bytes([9; 32]),
                stability_score: 0.9,
            },
            file_origin: Some(file_id.clone()),
            span: Some(kin_model::entity::SourceSpan {
                file: file_id,
                start_byte: 0,
                end_byte: content.len(),
                start_line: 1,
                start_col: 0,
                end_line: content.lines().count() as u32,
                end_col: 1,
            }),
            signature: signature.into(),
            visibility: Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn insert_trace_relation(
        store: &mut EmptyStore,
        src: &Entity,
        dst: &Entity,
        kind: RelationKind,
    ) {
        let relation = Relation {
            id: RelationId::new(),
            kind,
            src: kin_model::GraphNodeId::Entity(src.id),
            dst: kin_model::GraphNodeId::Entity(dst.id),
            confidence: 1.0,
            origin: kin_model::relation::RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        store
            .relations_by_entity
            .entry(src.id)
            .or_default()
            .push(relation.clone());
        store
            .relations_by_entity
            .entry(dst.id)
            .or_default()
            .push(relation);
    }

    #[test]
    fn entity_response_json_includes_real_source_excerpt() {
        // read_path is only the raw file_origin while KIN_SOURCE_ROOT is unset;
        // hold ENV_MUTEX so the EnvVarGuard tests can't set it mid-assertion.
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let content = "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean {\n  if (value < minVal) {\n    return false;\n  }\n  return value <= maxVal;\n}\n";
        let (_dir, entity) = make_source_backed_entity(content);

        let value = entity_response_json(&EmptyStore::default(), &entity).unwrap();
        let object = value.as_object().unwrap();
        let excerpt = object
            .get("source_excerpt")
            .and_then(|value| value.as_str())
            .unwrap();

        assert!(excerpt.contains("return value <= maxVal;"));
        assert_eq!(object.get("start_line").unwrap(), 1);
        assert_eq!(
            object
                .get("read_path")
                .and_then(|value| value.as_str())
                .unwrap(),
            entity.file_origin.as_ref().unwrap().0
        );
    }

    #[test]
    fn focal_context_json_prefers_real_source_excerpt() {
        let content = "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean {\n  if (value < minVal) {\n    return false;\n  }\n  return value <= maxVal;\n}\n";
        let (_dir, entity) = make_source_backed_entity(content);
        let entry = kin_model::ContextEntry {
            entity_id: entity.id,
            projection_level: kin_model::ProjectionLevel::FullBody,
            content: entity.signature.clone(),
        };

        let value = focal_context_json(&EmptyStore::default(), &entry, &entity, false);
        let object = value.as_object().unwrap();
        let body = object.get("body").and_then(|value| value.as_str()).unwrap();

        assert!(body.contains("return value <= maxVal;"));
        assert_ne!(body, entity.signature);
        assert_eq!(object.get("start_line").unwrap(), 1);
    }

    #[test]
    fn focal_context_json_surfaces_source_and_stale_markers() {
        // W1-B contract: get_context_pack's focal entity must carry the
        // graph/disk source marker and staleness flag in the response payload,
        // matching get_entity_source.
        let content = "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean {\n  return value <= maxVal;\n}\n";
        let (_dir, entity) = make_source_backed_entity(content);
        let entry = kin_model::ContextEntry {
            entity_id: entity.id,
            projection_level: kin_model::ProjectionLevel::FullBody,
            content: entity.signature.clone(),
        };

        let value = focal_context_json(&EmptyStore::default(), &entry, &entity, false);
        let object = value.as_object().unwrap();

        let source = object.get("source").and_then(|v| v.as_str()).unwrap();
        assert!(
            source == "graph" || source == "disk",
            "focal source marker must reflect the read path, got: {source}"
        );
        assert!(
            object.get("stale").map(|v| v.is_boolean()).unwrap_or(false),
            "focal payload must include a boolean stale flag"
        );
    }

    #[test]
    fn focal_context_json_expands_signature_only_python_span() {
        let content = "def validate_probe_range_f0cc1f1d(value: float, min_val: float, max_val: float) -> bool:\n    return min_val <= value and value <= max_val\n";
        let (_dir, entity) = make_signature_only_python_entity(content);
        let entry = kin_model::ContextEntry {
            entity_id: entity.id,
            projection_level: kin_model::ProjectionLevel::FullBody,
            content: entity.signature.clone(),
        };

        let value = focal_context_json(&EmptyStore::default(), &entry, &entity, false);
        let object = value.as_object().unwrap();
        let body = object.get("body").and_then(|value| value.as_str()).unwrap();

        assert!(body.contains("value <= max_val"));
        assert_ne!(body.trim(), entity.signature);
    }

    #[test]
    fn handle_explore_codebase_trace_returns_ordered_bodies_and_constants() {
        let dir = tempdir().unwrap();
        let tag = "trace9f31";

        let entry = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step4_{tag}.ts"),
            &format!("probeFinalTransform_{tag}"),
            EntityKind::Function,
            &format!("function probeFinalTransform_{tag}(n: number): number"),
            &format!(
                "export function probeFinalTransform_{tag}(n: number): number {{\n  return probeReduce_{tag}(n) + 17;\n}}\n"
            ),
        );
        let reduce_step = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step3_{tag}.ts"),
            &format!("probeReduce_{tag}"),
            EntityKind::Function,
            &format!("function probeReduce_{tag}(n: number): number"),
            &format!(
                "export function probeReduce_{tag}(n: number): number {{\n  return probeConditionalAdjust_{tag}(n) - 5;\n}}\n"
            ),
        );
        let import_only_step = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step2_{tag}.ts"),
            &format!("probeConditionalAdjust_{tag}"),
            EntityKind::Function,
            &format!("function probeConditionalAdjust_{tag}(n: number): number"),
            &format!(
                "export function probeConditionalAdjust_{tag}(n: number): number {{\n  return probeDoubleShifted_{tag}(n) + 3;\n}}\n"
            ),
        );
        let step = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step1_{tag}.ts"),
            &format!("probeDoubleShifted_{tag}"),
            EntityKind::Function,
            &format!("function probeDoubleShifted_{tag}(n: number): number"),
            &format!(
                "export function probeDoubleShifted_{tag}(n: number): number {{\n  return probeAddOffset_{tag}(n) * 2;\n}}\n"
            ),
        );
        let base_step = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step0_{tag}.ts"),
            &format!("probeAddOffset_{tag}"),
            EntityKind::Function,
            &format!("function probeAddOffset_{tag}(n: number): number"),
            &format!(
                "import {{ PROBE_BASE_{tag} }} from './base_{tag}';\n\nexport function probeAddOffset_{tag}(n: number): number {{\n  return n + PROBE_BASE_{tag};\n}}\n"
            ),
        );
        let constant = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/base_{tag}.ts"),
            &format!("PROBE_BASE_{tag}"),
            EntityKind::Constant,
            &format!("const PROBE_BASE_{tag}: number"),
            &format!("export const PROBE_BASE_{tag} = 13;\n"),
        );
        let decoy = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/decoy_transform_{tag}.ts"),
            &format!("probeFinalTransformAlt_{tag}"),
            EntityKind::Function,
            &format!("function probeFinalTransformAlt_{tag}(n: number): number"),
            &format!(
                "export function probeFinalTransformAlt_{tag}(n: number): number {{\n  return n * 100;\n}}\n"
            ),
        );

        let mut store = EmptyStore::default();
        for entity in [
            entry.clone(),
            reduce_step.clone(),
            import_only_step.clone(),
            step.clone(),
            base_step.clone(),
            constant.clone(),
            decoy.clone(),
        ] {
            store.entities_by_id.insert(entity.id, entity);
        }
        insert_trace_relation(&mut store, &entry, &reduce_step, RelationKind::Calls);
        insert_trace_relation(
            &mut store,
            &reduce_step,
            &import_only_step,
            RelationKind::Imports,
        );
        insert_trace_relation(&mut store, &import_only_step, &step, RelationKind::Calls);
        insert_trace_relation(&mut store, &reduce_step, &step, RelationKind::References);
        insert_trace_relation(&mut store, &step, &base_step, RelationKind::Calls);
        insert_trace_relation(&mut store, &base_step, &constant, RelationKind::Imports);

        let mut args = HashMap::new();
        args.insert("query".into(), serde_json::json!(entry.name));
        args.insert("strategy".into(), serde_json::json!("trace"));
        args.insert("token_budget".into(), serde_json::json!(8000));

        let result = entities::handle_explore_codebase(&args, &store).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        let content = parsed["content"].as_str().unwrap();

        let entry_pos = content.find(&entry.name).unwrap();
        let reduce_pos = content.find(&reduce_step.name).unwrap();
        let import_only_pos = content.find(&import_only_step.name).unwrap();
        let step_pos = content.find(&step.name).unwrap();
        let base_step_pos = content.find(&base_step.name).unwrap();

        assert!(content.contains("## Ordered Call Chain"));
        assert!(entry_pos < reduce_pos);
        assert!(reduce_pos < import_only_pos);
        assert!(import_only_pos < step_pos);
        assert!(step_pos < base_step_pos);
        assert!(content.contains("Imported constants"));
        assert!(content.contains(&constant.name));
        assert!(content.contains("export const"));
        assert!(content.contains("Similar/Decoy Matches"));
        assert!(content.contains(&decoy.name));
        assert!(content.contains("return n + PROBE_BASE"));
    }

    #[test]
    fn handle_explore_codebase_trace_infers_constants_without_graph_edges() {
        let dir = tempdir().unwrap();
        let tag = "traceconst";

        let step = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step1_{tag}.ts"),
            &format!("probeAddOffset_{tag}"),
            EntityKind::Function,
            &format!("function probeAddOffset_{tag}(n: number): number"),
            &format!(
                "import {{ PROBE_BASE_{tag} }} from './base_{tag}';\n\nexport function probeAddOffset_{tag}(n: number): number {{\n  return n + PROBE_BASE_{tag};\n}}\n"
            ),
        );
        let constant = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/base_{tag}.ts"),
            &format!("PROBE_BASE_{tag}"),
            EntityKind::Constant,
            &format!("const PROBE_BASE_{tag}: number"),
            &format!("export const PROBE_BASE_{tag} = 13;\n"),
        );

        let mut store = EmptyStore::default();
        store.entities_by_id.insert(step.id, step.clone());
        store.entities_by_id.insert(constant.id, constant.clone());

        let mut args = HashMap::new();
        args.insert("query".into(), serde_json::json!(step.name));
        args.insert("strategy".into(), serde_json::json!("trace"));
        args.insert("token_budget".into(), serde_json::json!(8000));

        let result = entities::handle_explore_codebase(&args, &store).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        let content = parsed["content"].as_str().unwrap();

        assert!(content.contains("Imported constants"));
        assert!(content.contains(&constant.name));
        assert!(content.contains("export const"));
    }

    #[test]
    fn handle_explore_codebase_trace_evaluates_rust_call_query() {
        let dir = tempdir().unwrap();
        let tag = "traceeval";

        let entry = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step7_{tag}.rs"),
            &format!("probe_final_transform_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_final_transform_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_final_transform_{tag}(n: i64) -> i64 {{\n  probe_conditional_shift_{tag}(n) + 17\n}}\n"
            ),
        );
        let step6 = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step6_{tag}.rs"),
            &format!("probe_conditional_shift_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_conditional_shift_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_conditional_shift_{tag}(n: i64) -> i64 {{\n  let amplified = probe_amplify_{tag}(n);\n  if amplified % 2 == 0 {{\n    amplified + 7\n  }} else {{\n    amplified - 11\n  }}\n}}\n"
            ),
        );
        let step5 = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step5_{tag}.rs"),
            &format!("probe_amplify_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_amplify_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_amplify_{tag}(n: i64) -> i64 {{\n  probe_reduce_{tag}(n) * 3\n}}\n"
            ),
        );
        let step4 = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step4_{tag}.rs"),
            &format!("probe_reduce_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_reduce_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_reduce_{tag}(n: i64) -> i64 {{\n  probe_conditional_adjust_{tag}(n) - 5\n}}\n"
            ),
        );
        let step3 = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step3_{tag}.rs"),
            &format!("probe_conditional_adjust_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_conditional_adjust_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_conditional_adjust_{tag}(n: i64) -> i64 {{\n  let intermediate = probe_double_shifted_{tag}(n);\n  if intermediate % 2 == 0 {{\n    intermediate + 3\n  }} else {{\n    intermediate * 2\n  }}\n}}\n"
            ),
        );
        let step2 = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step2_{tag}.rs"),
            &format!("probe_double_shifted_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_double_shifted_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_double_shifted_{tag}(n: i64) -> i64 {{\n  probe_add_offset_{tag}(n) * 2\n}}\n"
            ),
        );
        let step1 = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step1_{tag}.rs"),
            &format!("probe_add_offset_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_add_offset_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_add_offset_{tag}(n: i64) -> i64 {{\n  n + PROBE_BASE_{tag}\n}}\n"
            ),
        );
        let constant = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/base_{tag}.rs"),
            &format!("PROBE_BASE_{tag}"),
            EntityKind::Constant,
            &format!("pub const PROBE_BASE_{tag}: i64"),
            &format!("pub const PROBE_BASE_{tag}: i64 = 13;\n"),
        );

        let mut store = EmptyStore::default();
        for entity in [
            entry.clone(),
            step6.clone(),
            step5.clone(),
            step4.clone(),
            step3.clone(),
            step2.clone(),
            step1.clone(),
            constant.clone(),
        ] {
            store.entities_by_id.insert(entity.id, entity);
        }

        insert_trace_relation(&mut store, &entry, &step6, RelationKind::Calls);
        insert_trace_relation(&mut store, &step6, &step5, RelationKind::Calls);
        insert_trace_relation(&mut store, &step5, &step4, RelationKind::Calls);
        insert_trace_relation(&mut store, &step4, &step3, RelationKind::Calls);
        insert_trace_relation(&mut store, &step3, &step2, RelationKind::Calls);
        insert_trace_relation(&mut store, &step2, &step1, RelationKind::Calls);
        insert_trace_relation(&mut store, &step1, &constant, RelationKind::Imports);

        let mut args = HashMap::new();
        args.insert(
            "query".into(),
            serde_json::json!(format!("{}(5)", entry.name)),
        );
        args.insert("strategy".into(), serde_json::json!("trace"));
        args.insert("token_budget".into(), serde_json::json!(8000));

        let result = entities::handle_explore_codebase(&args, &store).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        let content = parsed["content"].as_str().unwrap();

        assert!(content.contains("## Evaluation Walkthrough"));
        assert!(content.contains("Input: 5"));
        assert!(content.contains("probe_add_offset"));
        assert!(content.contains("36 is even, so 36 + 3"));
        assert!(content.contains("102 is even, so 102 + 7"));
        assert!(content.contains("Final result: 126"));
    }

    #[test]
    fn handle_dead_code_scopes_to_requested_files() {
        let dead = make_dead_code_entity("src/probe_group0.ts", "probeDelta_1d8f8275", 10);
        let live = make_dead_code_entity("src/probe_group1.ts", "probeAlpha_1d8f8275", 20);
        let ignored = make_dead_code_entity("src/other.ts", "probeOutside_1d8f8275", 30);

        let mut store = EmptyStore::default();
        store
            .entities_by_file
            .insert("src/probe_group0.ts".into(), vec![dead.clone()]);
        store
            .entities_by_file
            .insert("src/probe_group1.ts".into(), vec![live.clone()]);
        store
            .entities_by_file
            .insert("src/other.ts".into(), vec![ignored.clone()]);
        store.live_entity_ids.insert(live.id);

        let mut args = HashMap::new();
        args.insert("limit".into(), serde_json::json!(50));
        args.insert(
            "files".into(),
            serde_json::json!(["src/probe_group0.ts", "src/probe_group1.ts"]),
        );

        let result = entities::handle_dead_code(&args, &store).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["name"], dead.name);
        assert_eq!(
            parsed[0]["file_origin"],
            dead.file_origin.as_ref().unwrap().0
        );
    }

    #[test]
    fn handle_dead_code_falls_back_to_global_query_without_files() {
        let dead = make_dead_code_entity("src/global.ts", "probeGlobal_1d8f8275", 5);
        let mut store = EmptyStore::default();
        store.dead_entities.push(dead.clone());

        let mut args = HashMap::new();
        args.insert("limit".into(), serde_json::json!(10));

        let result = entities::handle_dead_code(&args, &store).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["name"], dead.name);
    }

    #[test]
    fn semantic_search_result_is_compact_summary() {
        let entity = kin_model::entity::Entity {
            id: EntityId::new(),
            kind: EntityKind::Method,
            name: "SnapDocsApp.saveDocument".into(),
            language: LanguageId::JavaScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                stability_score: 0.9,
            },
            file_origin: Some(kin_model::ids::FilePathId::new("src/app.js")),
            span: Some(kin_model::entity::SourceSpan {
                file: kin_model::ids::FilePathId::new("src/app.js"),
                start_byte: 10,
                end_byte: 40,
                start_line: 12,
                start_col: 4,
                end_line: 16,
                end_col: 2,
            }),
            signature: "saveDocument(doc)".into(),
            visibility: kin_model::entity::Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: Some("Persist one document.".into()),
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        let summary = SemanticSearchResult::from(entity);
        let value = serde_json::to_value(summary).unwrap();
        let object = value.as_object().unwrap();

        assert_eq!(object.get("name").unwrap(), "SnapDocsApp.saveDocument");
        assert_eq!(object.get("file_path").unwrap(), "src/app.js");
        assert_eq!(object.get("start_line").unwrap(), 12);
        assert!(object.get("signature").is_some());
        assert!(object.get("fingerprint").is_none());
        assert!(object.get("metadata").is_none());
    }

    #[test]
    fn work_handlers_manage_relationships_and_status() {
        let store = InMemoryGraph::default();

        let mut feature_args = HashMap::new();
        feature_args.insert("kind".into(), serde_json::json!("feature"));
        feature_args.insert("title".into(), serde_json::json!("Ship hosted review"));
        let feature = work::handle_work_create(&feature_args, &store).unwrap();
        let feature_text = match &feature.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let feature_json: serde_json::Value = serde_json::from_str(&feature_text).unwrap();
        let feature_id = feature_json["work_id"].as_str().unwrap().to_string();

        let mut task_args = HashMap::new();
        task_args.insert("kind".into(), serde_json::json!("task"));
        task_args.insert(
            "title".into(),
            serde_json::json!("Wire semantic work graph"),
        );
        task_args.insert("scopes".into(), serde_json::json!(["artifact:src/lib.rs"]));
        let task = work::handle_work_create(&task_args, &store).unwrap();
        let task_text = match &task.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let task_json: serde_json::Value = serde_json::from_str(&task_text).unwrap();
        let task_id = task_json["work_id"].as_str().unwrap().to_string();

        let mut blocker_args = HashMap::new();
        blocker_args.insert("kind".into(), serde_json::json!("issue"));
        blocker_args.insert("title".into(), serde_json::json!("Resolve sync edge cases"));
        let blocker = work::handle_work_create(&blocker_args, &store).unwrap();
        let blocker_text = match &blocker.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let blocker_json: serde_json::Value = serde_json::from_str(&blocker_text).unwrap();
        let blocker_id = blocker_json["work_id"].as_str().unwrap().to_string();

        let mut decompose_args = HashMap::new();
        decompose_args.insert("parent_work_id".into(), serde_json::json!(feature_id));
        decompose_args.insert("child_work_id".into(), serde_json::json!(task_id.clone()));
        work::handle_work_decompose(&decompose_args, &store).unwrap();

        let mut block_args = HashMap::new();
        block_args.insert("blocked_work_id".into(), serde_json::json!(task_id.clone()));
        block_args.insert("blocker_work_id".into(), serde_json::json!(blocker_id));
        work::handle_work_block(&block_args, &store).unwrap();

        let mut implement_args = HashMap::new();
        implement_args.insert("work_id".into(), serde_json::json!(task_id.clone()));
        implement_args.insert("scopes".into(), serde_json::json!(["artifact:src/lib.rs"]));
        work::handle_work_implement(&implement_args, &store).unwrap();

        let mut status_args = HashMap::new();
        status_args.insert("work_id".into(), serde_json::json!(task_id.clone()));
        status_args.insert("status".into(), serde_json::json!("in_progress"));
        work::handle_work_status(&status_args, &store).unwrap();

        let mut show_args = HashMap::new();
        show_args.insert("work_id".into(), serde_json::json!(task_id));
        let shown = work::handle_work_show(&show_args, &store).unwrap();
        let shown_text = match &shown.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let shown_json: serde_json::Value = serde_json::from_str(&shown_text).unwrap();

        assert_eq!(shown_json["status"], "in_progress");
        assert_eq!(shown_json["parents"].as_array().unwrap().len(), 1);
        assert_eq!(shown_json["blockers"].as_array().unwrap().len(), 1);
        assert_eq!(shown_json["implementors"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn annotation_handlers_support_work_targets() {
        let store = InMemoryGraph::default();

        let mut create_args = HashMap::new();
        create_args.insert("kind".into(), serde_json::json!("task"));
        create_args.insert("title".into(), serde_json::json!("Track proof gaps"));
        create_args.insert(
            "scopes".into(),
            serde_json::json!(["artifact:src/proof.rs"]),
        );
        let work = work::handle_work_create(&create_args, &store).unwrap();
        let work_text = match &work.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let work_json: serde_json::Value = serde_json::from_str(&work_text).unwrap();
        let work_id = work_json["work_id"].as_str().unwrap().to_string();

        let mut add_args = HashMap::new();
        add_args.insert("kind".into(), serde_json::json!("reasoning"));
        add_args.insert(
            "body".into(),
            serde_json::json!("Keep this attached to the work object."),
        );
        add_args.insert(
            "targets".into(),
            serde_json::json!([format!("work:{}", work_id)]),
        );
        let added = work::handle_annotation_add(&add_args, &store).unwrap();
        let added_text = match &added.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let added_json: serde_json::Value = serde_json::from_str(&added_text).unwrap();
        assert_eq!(added_json["kind"], "reasoning");

        let mut list_args = HashMap::new();
        list_args.insert(
            "targets".into(),
            serde_json::json!([format!("work:{}", work_id)]),
        );
        let listed = work::handle_annotation_list(&list_args, &store).unwrap();
        let listed_text = match &listed.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let listed_json: serde_json::Value = serde_json::from_str(&listed_text).unwrap();
        assert_eq!(listed_json.as_array().unwrap().len(), 1);
        assert_eq!(listed_json[0]["scopes"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn get_context_pack_recalls_annotation_deposited_on_focal_entity() {
        // D.7 Track B (annotation deposit + recall): an annotation deposited on
        // an entity via kin_annotation_add must be recalled inside that entity's
        // get_context_pack response, through the real graph surfaces — no fake
        // or demo data, the same create/query path the product uses.
        use kin_model::graph::EntityStore;
        let content = "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean {\n  return value <= maxVal;\n}\n";
        let (_dir, entity) = make_source_backed_entity(content);
        let store = InMemoryGraph::default();
        store.upsert_entity(&entity).unwrap();

        // Deposit via the real add handler against the entity scope.
        let mut add_args = HashMap::new();
        add_args.insert("kind".into(), serde_json::json!("warning"));
        add_args.insert(
            "body".into(),
            serde_json::json!("Bounds validated upstream; do not re-check here."),
        );
        add_args.insert(
            "targets".into(),
            serde_json::json!([format!("entity:{}", entity.id)]),
        );
        work::handle_annotation_add(&add_args, &store).unwrap();

        // Recall through get_context_pack (traffic off to keep the pack focused).
        let sessions = SessionRegistry::new();
        let mut args = HashMap::new();
        args.insert("entity_id".into(), serde_json::json!(entity.id.to_string()));
        args.insert("include_traffic".into(), serde_json::json!(false));
        let result = entities::handle_get_context_pack(&args, &store, &sessions).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();

        let annotations = response
            .get("annotations")
            .and_then(|v| v.as_array())
            .expect("context pack must recall annotations on the focal entity");
        assert!(
            !annotations.is_empty(),
            "expected the deposited annotation to be recalled, got none"
        );
        let rendered = serde_json::to_string(annotations).unwrap();
        assert!(
            rendered.contains("do not re-check here"),
            "recalled annotation body should be present; got: {rendered}"
        );
    }

    #[test]
    fn handle_trace_computation_returns_focal_body_for_entity_id() {
        use kin_model::graph::EntityStore;
        let content = "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean {\n  if (value < minVal) {\n    return false;\n  }\n  return value <= maxVal;\n}\n";
        let (_dir, entity) = make_source_backed_entity(content);
        let store = InMemoryGraph::default();
        store.upsert_entity(&entity).unwrap();

        let sessions = SessionRegistry::new();
        let mut args = HashMap::new();
        args.insert("entity_id".into(), serde_json::json!(entity.id.to_string()));

        let result = entities::handle_trace_computation(&args, &store, &sessions).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();

        let focal = response
            .get("focal_entity")
            .expect("focal_entity present in trace_computation response");
        let body = focal
            .get("body")
            .and_then(|v| v.as_str())
            .expect("focal entity body");
        assert!(
            body.contains("return value <= maxVal;"),
            "trace_computation focal body should include the real source excerpt; got: {body}"
        );
        assert!(response.get("token_budget").is_some());
    }

    #[test]
    fn handle_trace_computation_resolves_query_to_entity() {
        use kin_model::graph::EntityStore;
        let content = "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean {\n  if (value < minVal) {\n    return false;\n  }\n  return value <= maxVal;\n}\n";
        let (_dir, entity) = make_source_backed_entity(content);
        let store = InMemoryGraph::default();
        store.upsert_entity(&entity).unwrap();

        let sessions = SessionRegistry::new();
        let mut args = HashMap::new();
        args.insert("query".into(), serde_json::json!(entity.name.clone()));

        let result = entities::handle_trace_computation(&args, &store, &sessions).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        let focal_id = response
            .get("focal_entity")
            .and_then(|f| f.get("id"))
            .and_then(|v| v.as_str())
            .expect("focal_entity.id present");
        assert_eq!(focal_id, entity.id.to_string());
    }

    #[test]
    fn handle_trace_computation_requires_entity_id_or_query() {
        let store = InMemoryGraph::default();
        let sessions = SessionRegistry::new();
        let args = HashMap::new();

        let err = entities::handle_trace_computation(&args, &store, &sessions)
            .expect_err("missing entity_id and query should error");
        assert!(matches!(err, McpError::InvalidParams(_)));
    }

    #[tokio::test]
    async fn handle_transaction_handlers_lifecycle() {
        use crate::session::{McpMutationOperation, McpMutationPayload};
        use kin_db::InMemoryGraph;
        use kin_model::entity::{FingerprintAlgorithm, SemanticFingerprint};
        use kin_model::graph::EntityStore;
        use kin_model::ids::{Hash256, LanguageId};

        let store = InMemoryGraph::default();
        let sessions = SessionRegistry::new();
        let session_authority = SessionAuthorityMode::OfflineFallback;

        // 1. Begin transaction
        let mut begin_args = HashMap::new();
        begin_args.insert("session_id".into(), serde_json::json!("sess-test"));
        begin_args.insert("scope".into(), serde_json::json!("src/lib.rs"));
        let begin_res =
            sessions::handle_transaction_begin(&begin_args, &sessions, session_authority)
                .await
                .unwrap();
        let begin_text = match &begin_res.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let begin_val: serde_json::Value = serde_json::from_str(&begin_text).unwrap();
        let tx_id = begin_val["transaction_id"].as_str().unwrap().to_string();

        // 2. Stage mutation (add entity)
        let entity = kin_model::Entity {
            id: EntityId::new(),
            kind: kin_model::entity::EntityKind::Function,
            name: "test_fn".into(),
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
            signature: "fn test_fn()".into(),
            visibility: kin_model::entity::Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };
        let op = McpMutationOperation {
            verb: "create".into(),
            target: "".into(),
            payload: Some(McpMutationPayload::Entity(entity.clone())),
            description: "add test function".into(),
        };

        let mut stage_args = HashMap::new();
        stage_args.insert("transaction_id".into(), serde_json::json!(tx_id));
        stage_args.insert("operations".into(), serde_json::json!(vec![op]));
        let stage_res =
            sessions::handle_transaction_stage(&stage_args, &sessions, session_authority)
                .await
                .unwrap();
        let stage_text = match &stage_res.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let stage_val: serde_json::Value = serde_json::from_str(&stage_text).unwrap();
        assert_eq!(stage_val["staged_count"].as_u64().unwrap(), 1);

        // 3. Validate transaction
        let mut val_args = HashMap::new();
        val_args.insert("transaction_id".into(), serde_json::json!(tx_id));
        let val_res =
            sessions::handle_transaction_validate(&val_args, &sessions, session_authority)
                .await
                .unwrap();
        let val_text = match &val_res.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let val_val: serde_json::Value = serde_json::from_str(&val_text).unwrap();
        assert_eq!(val_val["state"].as_str().unwrap(), "validated");

        // 4. Commit transaction
        let mut commit_args = HashMap::new();
        commit_args.insert("transaction_id".into(), serde_json::json!(tx_id));
        let commit_res =
            sessions::handle_transaction_commit(&commit_args, &store, &sessions, session_authority)
                .await
                .unwrap();
        let commit_text = match &commit_res.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let commit_val: serde_json::Value = serde_json::from_str(&commit_text).unwrap();
        assert_eq!(commit_val["state"].as_str().unwrap(), "committed");

        // Verify entity was added to the store
        let retrieved = store.get_entity(&entity.id).unwrap().unwrap();
        assert_eq!(retrieved.name, "test_fn");
    }

    #[tokio::test]
    async fn handle_transaction_stage_rejects_malformed_op_at_stage_time() {
        // D.7 Track A: a payload-less operation must fail loud at stage time —
        // before the transaction is even consulted — instead of being silently
        // dropped at commit. The transaction id here does not exist; validation
        // is expected to reject the operation first.
        use crate::session::{McpMutationOperation, McpMutationPayload};
        let sessions = SessionRegistry::new();
        let session_authority = SessionAuthorityMode::OfflineFallback;

        let op: McpMutationOperation = McpMutationOperation {
            verb: "create".into(),
            target: "function".into(),
            payload: None::<McpMutationPayload>,
            description: "add dummy".into(),
        };
        let mut stage_args = HashMap::new();
        stage_args.insert("transaction_id".into(), serde_json::json!("no-such-tx"));
        stage_args.insert("operations".into(), serde_json::json!(vec![op]));

        let err = sessions::handle_transaction_stage(&stage_args, &sessions, session_authority)
            .await
            .expect_err("payload-less op must be rejected at stage time");
        assert!(matches!(err, McpError::InvalidParams(_)));
        assert!(
            err.to_string().contains("missing payload"),
            "actionable stage-time message expected, got: {err}"
        );
    }

    struct EnvVarGuard {
        key: &'static str,
        old_val: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, val: &std::path::Path) -> Self {
            let old_val = std::env::var_os(key);
            std::env::set_var(key, val);
            Self { key, old_val }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(ref val) = self.old_val {
                std::env::set_var(self.key, val);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    use std::sync::{Mutex, OnceLock};
    static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

    #[test]
    fn test_entity_served_from_blob_store_file_deleted() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());

        let objects_dir = kin_dir.join("objects");
        let blob_store = kin_blobs::BlobStore::new(objects_dir).unwrap();

        let content = "export function test_blob() { return 42; }";
        let hash = blob_store.write(content.as_bytes()).unwrap();

        let file_path = "src/lib.rs";
        let file_id = FilePathId::new(file_path);

        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "test_blob".into(),
            language: LanguageId::TypeScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: hash,
                signature_hash: hash,
                behavior_hash: hash,
                stability_score: 1.0,
            },
            file_origin: Some(file_id.clone()),
            span: Some(kin_model::entity::SourceSpan {
                file: file_id.clone(),
                start_byte: 0,
                end_byte: content.len(),
                start_line: 1,
                start_col: 0,
                end_line: 1,
                end_col: content.len() as u32,
            }),
            signature: "export function test_blob()".into(),
            visibility: Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        let mut store = EmptyStore::default();
        store.file_hashes.insert(file_id, hash);

        let value = entity_response_json(&store, &entity).unwrap();
        let object = value.as_object().unwrap();
        let excerpt = object
            .get("source_excerpt")
            .and_then(|v| v.as_str())
            .unwrap();

        assert_eq!(excerpt, content);
        assert_eq!(object.get("stale").unwrap().as_bool().unwrap(), false);
        assert_eq!(object.get("source").unwrap().as_str().unwrap(), "graph");
    }

    #[test]
    fn test_disk_fallback_stale_flag() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());

        let file_path = "src/lib.rs";
        let full_path = dir.path().join(file_path);
        fs::create_dir_all(full_path.parent().unwrap()).unwrap();

        let disk_content = "export function test_disk() { return 99; }";
        fs::write(&full_path, disk_content).unwrap();

        let file_id = FilePathId::new(file_path);
        let graph_content = "export function test_disk() { return 42; }";
        let graph_hash = kin_blobs::digest(graph_content.as_bytes());

        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "test_disk".into(),
            language: LanguageId::TypeScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: graph_hash,
                signature_hash: graph_hash,
                behavior_hash: graph_hash,
                stability_score: 1.0,
            },
            file_origin: Some(file_id.clone()),
            span: Some(kin_model::entity::SourceSpan {
                file: file_id.clone(),
                start_byte: 0,
                end_byte: disk_content.len(),
                start_line: 1,
                start_col: 0,
                end_line: 1,
                end_col: disk_content.len() as u32,
            }),
            signature: "export function test_disk()".into(),
            visibility: Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        let mut store = EmptyStore::default();
        store.file_hashes.insert(file_id, graph_hash);

        let before_misses = GRAPH_MISS_COUNT.load(std::sync::atomic::Ordering::SeqCst);

        let value = entity_response_json(&store, &entity).unwrap();
        let object = value.as_object().unwrap();
        let excerpt = object
            .get("source_excerpt")
            .and_then(|v| v.as_str())
            .unwrap();

        assert_eq!(excerpt, disk_content);
        assert_eq!(object.get("stale").unwrap().as_bool().unwrap(), true);
        assert_eq!(object.get("source").unwrap().as_str().unwrap(), "disk");

        let after_misses = GRAPH_MISS_COUNT.load(std::sync::atomic::Ordering::SeqCst);
        assert!(after_misses >= before_misses + 1);
    }

    #[test]
    fn test_hash_mismatch_falls_back_to_disk() {
        let _lock = ENV_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        fs::create_dir_all(&kin_dir).unwrap();
        let _guard = EnvVarGuard::set("KIN_SOURCE_ROOT", dir.path());

        let objects_dir = kin_dir.join("objects");
        let blob_store = kin_blobs::BlobStore::new(objects_dir).unwrap();

        // correct content
        let content = "export function test_mismatch() { return 42; }";
        let correct_hash = kin_blobs::digest(content.as_bytes());

        // Write incorrect bytes to the correct hash path to simulate corrupt/mismatched blob
        let bad_content = "corrupt content";
        let hex = correct_hash.to_string();
        let shard_dir = blob_store.root().join(&hex[..2]);
        fs::create_dir_all(&shard_dir).unwrap();
        let blob_file = shard_dir.join(&hex[2..]);
        fs::write(&blob_file, bad_content.as_bytes()).unwrap();

        // Write the correct file on disk
        let file_path = "src/lib.rs";
        let full_path = dir.path().join(file_path);
        fs::create_dir_all(full_path.parent().unwrap()).unwrap();
        fs::write(&full_path, content).unwrap();

        let file_id = FilePathId::new(file_path);
        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "test_mismatch".into(),
            language: LanguageId::TypeScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: correct_hash,
                signature_hash: correct_hash,
                behavior_hash: correct_hash,
                stability_score: 1.0,
            },
            file_origin: Some(file_id.clone()),
            span: Some(kin_model::entity::SourceSpan {
                file: file_id.clone(),
                start_byte: 0,
                end_byte: content.len(),
                start_line: 1,
                start_col: 0,
                end_line: 1,
                end_col: content.len() as u32,
            }),
            signature: "export function test_mismatch()".into(),
            visibility: Visibility::Public,
            role: kin_model::entity::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        let mut store = EmptyStore::default();
        store.file_hashes.insert(file_id, correct_hash);

        let before_misses = GRAPH_MISS_COUNT.load(std::sync::atomic::Ordering::SeqCst);

        let value = entity_response_json(&store, &entity).unwrap();
        let object = value.as_object().unwrap();
        let excerpt = object
            .get("source_excerpt")
            .and_then(|v| v.as_str())
            .unwrap();

        // It should verify incorrect blob, discard it, fall back to disk, which has the correct content
        assert_eq!(excerpt, content);
        // Since disk matches correct_hash, it should NOT be stale
        assert_eq!(object.get("stale").unwrap().as_bool().unwrap(), false);
        assert_eq!(object.get("source").unwrap().as_str().unwrap(), "disk");

        let after_misses = GRAPH_MISS_COUNT.load(std::sync::atomic::Ordering::SeqCst);
        assert!(after_misses >= before_misses + 1);
    }

    // ── Governance handlers: release_check + security_scan ──────────────────

    fn gov_change_id(byte: u8) -> SemanticChangeId {
        SemanticChangeId::from_hash(Hash256::from_bytes([byte; 32]))
    }

    fn gov_change(id: u8, parent: Option<u8>, author: &str) -> SemanticChange {
        SemanticChange {
            id: gov_change_id(id),
            parents: parent.map(|p| vec![gov_change_id(p)]).unwrap_or_default(),
            timestamp: kin_model::timestamp::Timestamp::now(),
            author: AuthorId::new(author),
            message: format!("change {}", id),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        }
    }

    fn gov_approval(
        change: &SemanticChange,
        decision: kin_model::provenance::ApprovalDecision,
    ) -> kin_model::provenance::Approval {
        kin_model::provenance::Approval {
            approval_id: kin_model::provenance::ApprovalId::new(),
            change_id: change.id,
            approver: kin_model::provenance::ActorId::new(),
            decision,
            reason: "test".into(),
            timestamp: kin_model::timestamp::Timestamp::now(),
        }
    }

    fn gov_entity(name: &str, kind: EntityKind, visibility: Visibility) -> Entity {
        use kin_model::entity::{
            EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        };
        Entity {
            id: EntityId::new(),
            kind,
            name: name.to_string(),
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
            signature: format!("fn {}()", name),
            visibility,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    async fn call_release_check(store: &EmptyStore, require_approval: bool) -> serde_json::Value {
        let sessions = SessionRegistry::new();
        let mut args = HashMap::new();
        args.insert(
            "require_approval".into(),
            serde_json::json!(require_approval),
        );
        let result = handle_tool_call(
            "kin_release_check",
            &args,
            store,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
        )
        .await
        .unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        serde_json::from_str(&text).unwrap()
    }

    #[tokio::test]
    async fn release_check_require_approval_passes_with_no_branches() {
        // No branches => nothing to walk => approval gate cannot find blockers.
        let store = EmptyStore::default();
        let response = call_release_check(&store, true).await;
        assert_eq!(response["pass"], true);
    }

    #[tokio::test]
    async fn release_check_blocks_on_unapproved_agent_change() {
        // The false-green this fix targets: an agent change with NO approval must
        // fail the gate. (Previously it passed because any audit event sufficed.)
        let mut store = EmptyStore::default();
        let head = gov_change(1, None, "claude-agent");
        store.changes_by_id.insert(head.id, head.clone());
        store.branches.push(Branch {
            name: BranchName::new("main"),
            head: head.id,
        });

        let response = call_release_check(&store, true).await;
        assert_eq!(response["pass"], false);
        let blockers = response["blockers"].as_array().unwrap();
        assert!(
            blockers
                .iter()
                .any(|b| b.as_str().unwrap().contains("unapproved agent change")),
            "blocker list must name the unapproved agent change: {blockers:?}"
        );
    }

    #[tokio::test]
    async fn release_check_passes_when_agent_change_approved() {
        let mut store = EmptyStore::default();
        let head = gov_change(1, None, "claude-agent");
        store.changes_by_id.insert(head.id, head.clone());
        store.approvals_by_change.insert(
            head.id,
            vec![gov_approval(
                &head,
                kin_model::provenance::ApprovalDecision::Approved,
            )],
        );
        store.branches.push(Branch {
            name: BranchName::new("main"),
            head: head.id,
        });

        let response = call_release_check(&store, true).await;
        assert_eq!(response["pass"], true, "approved agent change must pass");
    }

    #[tokio::test]
    async fn release_check_blocks_on_approved_then_mutated() {
        // c1 (agent, approved) <- c2 (agent, unapproved, HEAD): the later
        // unapproved mutation must block even though an earlier change is approved.
        let mut store = EmptyStore::default();
        let c1 = gov_change(1, None, "agent-a");
        let c2 = gov_change(2, Some(1), "agent-a");
        store.changes_by_id.insert(c1.id, c1.clone());
        store.changes_by_id.insert(c2.id, c2.clone());
        store.approvals_by_change.insert(
            c1.id,
            vec![gov_approval(
                &c1,
                kin_model::provenance::ApprovalDecision::Approved,
            )],
        );
        store.branches.push(Branch {
            name: BranchName::new("main"),
            head: c2.id,
        });

        let response = call_release_check(&store, true).await;
        assert_eq!(response["pass"], false);

        // Approving the head clears the gate.
        store.approvals_by_change.insert(
            c2.id,
            vec![gov_approval(
                &c2,
                kin_model::provenance::ApprovalDecision::Approved,
            )],
        );
        let response = call_release_check(&store, true).await;
        assert_eq!(response["pass"], true);
    }

    #[tokio::test]
    async fn release_check_human_change_does_not_block() {
        let mut store = EmptyStore::default();
        let head = gov_change(1, None, "alice");
        store.changes_by_id.insert(head.id, head.clone());
        store.branches.push(Branch {
            name: BranchName::new("main"),
            head: head.id,
        });

        let response = call_release_check(&store, true).await;
        assert_eq!(response["pass"], true, "human-authored change is not gated");
    }

    #[tokio::test]
    async fn release_check_approval_disabled_skips_gate() {
        // With require_approval=false, an unapproved agent change must NOT block.
        let mut store = EmptyStore::default();
        let head = gov_change(1, None, "claude-agent");
        store.changes_by_id.insert(head.id, head.clone());
        store.branches.push(Branch {
            name: BranchName::new("main"),
            head: head.id,
        });

        let response = call_release_check(&store, false).await;
        assert_eq!(response["pass"], true);
    }

    #[tokio::test]
    async fn security_scan_surfaces_untested_api_endpoint() {
        let mut store = EmptyStore::default();
        let api = gov_entity("login", EntityKind::ApiEndpoint, Visibility::Public);
        store.entities_by_id.insert(api.id, api);

        let sessions = SessionRegistry::new();
        let args = HashMap::new();
        let result = handle_tool_call(
            "kin_security_scan",
            &args,
            &store,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
        )
        .await
        .unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();

        assert!(response["finding_count"].as_u64().unwrap() >= 1);
        assert_eq!(response["severity_counts"]["high"], 1);
        let findings = response["findings"].as_array().unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f["finding_type"] == "untested-api" && f["severity"] == "high"),
            "untested API endpoint must appear as a high finding: {findings:?}"
        );
    }

    #[tokio::test]
    async fn security_scan_empty_graph_has_no_findings() {
        let store = EmptyStore::default();
        let sessions = SessionRegistry::new();
        let args = HashMap::new();
        let result = handle_tool_call(
            "kin_security_scan",
            &args,
            &store,
            &sessions,
            SessionAuthorityMode::OfflineFallback,
        )
        .await
        .unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response["finding_count"], 0);
    }

    #[tokio::test]
    async fn release_check_blockers_are_byte_stable() {
        // Two branches, each headed by a distinct unapproved agent change. The
        // blockers string concatenates change ids in the order branches are walked,
        // so the sort is what makes the output stable. Two identical-state calls
        // must produce byte-identical blockers.
        let mut store = EmptyStore::default();
        let c_a = gov_change(0xAA, None, "agent-a");
        let c_b = gov_change(0xBB, None, "agent-b");
        store.changes_by_id.insert(c_a.id, c_a.clone());
        store.changes_by_id.insert(c_b.id, c_b.clone());
        store.branches.push(Branch {
            name: BranchName::new("feature"),
            head: c_a.id,
        });
        store.branches.push(Branch {
            name: BranchName::new("main"),
            head: c_b.id,
        });

        let first = call_release_check(&store, true).await;
        let second = call_release_check(&store, true).await;
        assert_eq!(first["pass"], false);
        assert_eq!(
            first["blockers"], second["blockers"],
            "blockers must be deterministic across identical-state runs"
        );
    }
}
