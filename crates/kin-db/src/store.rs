use crate::types::*;

/// Trait abstracting the graph database.
///
/// All crates outside the storage engine use this trait.
pub trait GraphStore: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    // -----------------------------------------------------------------------
    // Read operations
    // -----------------------------------------------------------------------

    fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>, Self::Error>;

    fn get_relations(
        &self,
        id: &EntityId,
        kinds: &[RelationKind],
    ) -> Result<Vec<Relation>, Self::Error>;

    fn get_all_relations_for_entity(
        &self,
        id: &EntityId,
    ) -> Result<Vec<Relation>, Self::Error>;

    fn get_downstream_impact(
        &self,
        id: &EntityId,
        max_depth: u32,
    ) -> Result<Vec<Entity>, Self::Error>;

    fn get_dependency_neighborhood(
        &self,
        id: &EntityId,
        depth: u32,
    ) -> Result<SubGraph, Self::Error>;

    fn find_dead_code(&self) -> Result<Vec<Entity>, Self::Error>;

    fn has_incoming_relation_kinds(
        &self,
        id: &EntityId,
        kinds: &[RelationKind],
        exclude_same_file: bool,
    ) -> Result<bool, Self::Error>;

    fn get_entity_history(
        &self,
        id: &EntityId,
    ) -> Result<Vec<SemanticChange>, Self::Error>;

    fn find_merge_bases(
        &self,
        a: &SemanticChangeId,
        b: &SemanticChangeId,
    ) -> Result<Vec<SemanticChangeId>, Self::Error>;

    fn query_entities(
        &self,
        filter: &EntityFilter,
    ) -> Result<Vec<Entity>, Self::Error>;

    fn list_all_entities(&self) -> Result<Vec<Entity>, Self::Error>;

    // -----------------------------------------------------------------------
    // Write operations
    // -----------------------------------------------------------------------

    fn upsert_entity(&self, entity: &Entity) -> Result<(), Self::Error>;

    fn upsert_relation(&self, relation: &Relation) -> Result<(), Self::Error>;

    fn remove_entity(&self, id: &EntityId) -> Result<(), Self::Error>;

    fn remove_relation(&self, id: &RelationId) -> Result<(), Self::Error>;

    // -----------------------------------------------------------------------
    // SemanticChange DAG
    // -----------------------------------------------------------------------

    fn create_change(&self, change: &SemanticChange) -> Result<(), Self::Error>;

    fn get_change(
        &self,
        id: &SemanticChangeId,
    ) -> Result<Option<SemanticChange>, Self::Error>;

    fn get_changes_since(
        &self,
        base: &SemanticChangeId,
        head: &SemanticChangeId,
    ) -> Result<Vec<SemanticChange>, Self::Error>;

    // -----------------------------------------------------------------------
    // Branch operations
    // -----------------------------------------------------------------------

    fn get_branch(&self, name: &BranchName) -> Result<Option<Branch>, Self::Error>;

    fn create_branch(&self, branch: &Branch) -> Result<(), Self::Error>;

    fn update_branch_head(
        &self,
        name: &BranchName,
        new_head: &SemanticChangeId,
    ) -> Result<(), Self::Error>;

    fn delete_branch(&self, name: &BranchName) -> Result<(), Self::Error>;

    fn list_branches(&self) -> Result<Vec<Branch>, Self::Error>;
}
