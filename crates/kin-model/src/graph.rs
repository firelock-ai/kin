use crate::branch::Branch;
use crate::change::SemanticChange;
use crate::entity::{Entity, EntityKind};
use crate::ids::*;
use crate::relation::{Relation, RelationKind};
use crate::work::{
    Annotation, AnnotationFilter, AnnotationId, WorkFilter, WorkId, WorkItem, WorkLink, WorkScope,
    WorkStatus,
};
use crate::verification::{
    ContractCoverageSummary, MockHint, VerificationRun, VerificationRunId,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Trait abstracting the graph database.
///
/// All crates outside `kin-graph` use this trait. No raw Cypher
/// strings are allowed outside the `kin-graph` crate.
pub trait GraphStore: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    // Read operations
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
    fn find_dead_code(&self) -> std::result::Result<Vec<Entity>, Self::Error>;
    fn get_entity_history(
        &self,
        id: &EntityId,
    ) -> std::result::Result<Vec<SemanticChange>, Self::Error>;
    fn find_merge_bases(
        &self,
        a: &SemanticChangeId,
        b: &SemanticChangeId,
    ) -> std::result::Result<Vec<SemanticChangeId>, Self::Error>;
    fn query_entities(
        &self,
        filter: &EntityFilter,
    ) -> std::result::Result<Vec<Entity>, Self::Error>;
    fn list_all_entities(&self) -> std::result::Result<Vec<Entity>, Self::Error>;

    // Write operations
    fn upsert_entity(&self, entity: &Entity) -> std::result::Result<(), Self::Error>;
    fn upsert_relation(&self, relation: &Relation) -> std::result::Result<(), Self::Error>;
    fn remove_entity(&self, id: &EntityId) -> std::result::Result<(), Self::Error>;
    fn remove_relation(&self, id: &RelationId) -> std::result::Result<(), Self::Error>;

    // SemanticChange DAG
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

    // Branch operations
    fn get_branch(&self, name: &BranchName) -> std::result::Result<Option<Branch>, Self::Error>;
    fn create_branch(&self, branch: &Branch) -> std::result::Result<(), Self::Error>;
    fn update_branch_head(
        &self,
        name: &BranchName,
        new_head: &SemanticChangeId,
    ) -> std::result::Result<(), Self::Error>;
    fn delete_branch(&self, name: &BranchName) -> std::result::Result<(), Self::Error>;
    fn list_branches(&self) -> std::result::Result<Vec<Branch>, Self::Error>;

    // Work graph operations (Phase 8)
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

    // Annotation operations (Phase 8)
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

    // Work graph relationships (Phase 8)
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
    fn get_implementors(
        &self,
        work_id: &WorkId,
    ) -> std::result::Result<Vec<WorkScope>, Self::Error>;

    // Verification graph operations (Phase 9)
    fn create_test_case(&self, test: &crate::verification::TestCase) -> std::result::Result<(), Self::Error>;
    fn get_test_case(&self, id: &crate::verification::TestId) -> std::result::Result<Option<crate::verification::TestCase>, Self::Error>;
    fn get_tests_for_entity(&self, id: &EntityId) -> std::result::Result<Vec<crate::verification::TestCase>, Self::Error>;
    fn delete_test_case(&self, id: &crate::verification::TestId) -> std::result::Result<(), Self::Error>;
    fn create_assertion(&self, assertion: &crate::verification::Assertion) -> std::result::Result<(), Self::Error>;
    fn get_assertion(&self, id: &crate::verification::AssertionId) -> std::result::Result<Option<crate::verification::Assertion>, Self::Error>;
    fn get_coverage_summary(&self) -> std::result::Result<crate::verification::CoverageSummary, Self::Error>;

    // Verification runs (Phase 9 completion)
    fn create_verification_run(&self, run: &VerificationRun) -> std::result::Result<(), Self::Error>;
    fn get_verification_run(&self, id: &VerificationRunId) -> std::result::Result<Option<VerificationRun>, Self::Error>;
    fn list_runs_for_test(&self, test_id: &crate::verification::TestId) -> std::result::Result<Vec<VerificationRun>, Self::Error>;

    // Test ↔ scope linking: COVERS and VERIFIES edges (Phase 9 completion)
    fn create_test_covers_entity(&self, test_id: &crate::verification::TestId, entity_id: &EntityId) -> std::result::Result<(), Self::Error>;
    fn create_test_covers_contract(&self, test_id: &crate::verification::TestId, contract_id: &ContractId) -> std::result::Result<(), Self::Error>;
    fn create_test_verifies_work(&self, test_id: &crate::verification::TestId, work_id: &WorkId) -> std::result::Result<(), Self::Error>;
    fn get_tests_covering_contract(&self, contract_id: &ContractId) -> std::result::Result<Vec<crate::verification::TestCase>, Self::Error>;
    fn get_tests_verifying_work(&self, work_id: &WorkId) -> std::result::Result<Vec<crate::verification::TestCase>, Self::Error>;

    // Mock hints (Phase 9 completion)
    fn create_mock_hint(&self, hint: &MockHint) -> std::result::Result<(), Self::Error>;
    fn get_mock_hints_for_test(&self, test_id: &crate::verification::TestId) -> std::result::Result<Vec<MockHint>, Self::Error>;

    // Verification run → proof links (Phase 9 completion)
    fn link_run_proves_entity(&self, run_id: &VerificationRunId, entity_id: &EntityId) -> std::result::Result<(), Self::Error>;
    fn link_run_proves_work(&self, run_id: &VerificationRunId, work_id: &WorkId) -> std::result::Result<(), Self::Error>;

    // Contract CRUD
    fn create_contract(&self, contract: &crate::contract::Contract) -> std::result::Result<(), Self::Error>;
    fn get_contract(&self, id: &ContractId) -> std::result::Result<Option<crate::contract::Contract>, Self::Error>;
    fn list_contracts(&self) -> std::result::Result<Vec<crate::contract::Contract>, Self::Error>;

    // Contract coverage (Phase 9 completion)
    fn get_contract_coverage_summary(&self) -> std::result::Result<ContractCoverageSummary, Self::Error>;

    // Provenance operations (Phase 10)
    fn create_actor(&self, actor: &crate::provenance::Actor) -> std::result::Result<(), Self::Error>;
    fn get_actor(&self, id: &crate::provenance::ActorId) -> std::result::Result<Option<crate::provenance::Actor>, Self::Error>;
    fn list_actors(&self) -> std::result::Result<Vec<crate::provenance::Actor>, Self::Error>;
    fn create_delegation(&self, delegation: &crate::provenance::Delegation) -> std::result::Result<(), Self::Error>;
    fn get_delegations_for_actor(&self, id: &crate::provenance::ActorId) -> std::result::Result<Vec<crate::provenance::Delegation>, Self::Error>;
    fn create_approval(&self, approval: &crate::provenance::Approval) -> std::result::Result<(), Self::Error>;
    fn get_approvals_for_change(&self, id: &SemanticChangeId) -> std::result::Result<Vec<crate::provenance::Approval>, Self::Error>;
    fn record_audit_event(&self, event: &crate::provenance::AuditEvent) -> std::result::Result<(), Self::Error>;
    fn query_audit_events(&self, actor_id: Option<&crate::provenance::ActorId>, limit: usize) -> std::result::Result<Vec<crate::provenance::AuditEvent>, Self::Error>;

    // Shallow file tracking (C2 tier)
    fn upsert_shallow_file(&self, shallow: &crate::layout::ShallowTrackedFile) -> std::result::Result<(), Self::Error>;
    fn list_shallow_files(&self) -> std::result::Result<Vec<crate::layout::ShallowTrackedFile>, Self::Error>;
}

/// A subgraph returned from neighborhood queries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubGraph {
    pub entities: HashMap<EntityId, Entity>,
    pub relations: Vec<Relation>,
}

/// Filter for querying entities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntityFilter {
    pub kinds: Option<Vec<EntityKind>>,
    pub languages: Option<Vec<LanguageId>>,
    pub name_pattern: Option<String>,
    pub file_path: Option<FilePathId>,
}
