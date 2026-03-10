use crate::branch::Branch;
use crate::change::SemanticChange;
use crate::entity::{Entity, EntityKind};
use crate::ids::*;
use crate::relation::{Relation, RelationKind};
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
    fn get_branch(
        &self,
        name: &BranchName,
    ) -> std::result::Result<Option<Branch>, Self::Error>;
    fn create_branch(&self, branch: &Branch) -> std::result::Result<(), Self::Error>;
    fn update_branch_head(
        &self,
        name: &BranchName,
        new_head: &SemanticChangeId,
    ) -> std::result::Result<(), Self::Error>;
    fn delete_branch(&self, name: &BranchName) -> std::result::Result<(), Self::Error>;
    fn list_branches(&self) -> std::result::Result<Vec<Branch>, Self::Error>;
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
