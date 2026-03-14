use hashbrown::HashMap;
use parking_lot::RwLock;

use crate::error::KinDbError;
use crate::store::GraphStore;
use crate::types::*;

use super::index::IndexSet;
use super::traverse;

/// In-memory graph engine with O(1) entity/relation lookup and secondary indexes.
///
/// All read operations take `&self` and acquire a shared read lock.
/// All write operations take `&self` and acquire an exclusive write lock.
pub struct InMemoryGraph {
    inner: RwLock<GraphInner>,
}

/// The inner mutable state behind the RwLock.
struct GraphInner {
    entities: HashMap<EntityId, Entity>,
    relations: HashMap<RelationId, Relation>,
    /// Entity → outgoing relation IDs (entity's dependencies).
    outgoing: HashMap<EntityId, Vec<RelationId>>,
    /// Entity → incoming relation IDs (entity's callers/dependents).
    incoming: HashMap<EntityId, Vec<RelationId>>,
    /// Secondary indexes for fast lookup.
    indexes: IndexSet,

    // SemanticChange DAG
    changes: HashMap<SemanticChangeId, SemanticChange>,
    /// Parent → children in the change DAG.
    change_children: HashMap<SemanticChangeId, Vec<SemanticChangeId>>,

    // Branches
    branches: HashMap<BranchName, Branch>,
}

impl InMemoryGraph {
    /// Create a new empty in-memory graph.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(GraphInner {
                entities: HashMap::new(),
                relations: HashMap::new(),
                outgoing: HashMap::new(),
                incoming: HashMap::new(),
                indexes: IndexSet::new(),
                changes: HashMap::new(),
                change_children: HashMap::new(),
                branches: HashMap::new(),
            }),
        }
    }

    /// Number of entities in the graph.
    pub fn entity_count(&self) -> usize {
        self.inner.read().entities.len()
    }

    /// Number of relations in the graph.
    pub fn relation_count(&self) -> usize {
        self.inner.read().relations.len()
    }
}

impl Default for InMemoryGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for InMemoryGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.read();
        f.debug_struct("InMemoryGraph")
            .field("entities", &inner.entities.len())
            .field("relations", &inner.relations.len())
            .field("changes", &inner.changes.len())
            .field("branches", &inner.branches.len())
            .finish()
    }
}

impl GraphStore for InMemoryGraph {
    type Error = KinDbError;

    // -----------------------------------------------------------------------
    // Read operations
    // -----------------------------------------------------------------------

    fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>, KinDbError> {
        Ok(self.inner.read().entities.get(id).cloned())
    }

    fn get_relations(
        &self,
        id: &EntityId,
        kinds: &[RelationKind],
    ) -> Result<Vec<Relation>, KinDbError> {
        let inner = self.inner.read();
        let mut result = Vec::new();

        if let Some(edge_ids) = inner.outgoing.get(id) {
            for rid in edge_ids {
                if let Some(rel) = inner.relations.get(rid) {
                    if kinds.is_empty() || kinds.contains(&rel.kind) {
                        result.push(rel.clone());
                    }
                }
            }
        }

        Ok(result)
    }

    fn get_all_relations_for_entity(
        &self,
        id: &EntityId,
    ) -> Result<Vec<Relation>, KinDbError> {
        let inner = self.inner.read();
        let mut result = Vec::new();

        // Outgoing
        if let Some(edge_ids) = inner.outgoing.get(id) {
            for rid in edge_ids {
                if let Some(rel) = inner.relations.get(rid) {
                    result.push(rel.clone());
                }
            }
        }

        // Incoming
        if let Some(edge_ids) = inner.incoming.get(id) {
            for rid in edge_ids {
                if let Some(rel) = inner.relations.get(rid) {
                    // Avoid duplicates for self-referencing relations
                    if !result.iter().any(|r| r.id == rel.id) {
                        result.push(rel.clone());
                    }
                }
            }
        }

        Ok(result)
    }

    fn get_downstream_impact(
        &self,
        id: &EntityId,
        max_depth: u32,
    ) -> Result<Vec<Entity>, KinDbError> {
        let inner = self.inner.read();
        Ok(traverse::downstream_impact(
            id,
            max_depth,
            &inner.entities,
            &inner.incoming,
            &inner.relations,
        ))
    }

    fn get_dependency_neighborhood(
        &self,
        id: &EntityId,
        depth: u32,
    ) -> Result<SubGraph, KinDbError> {
        let inner = self.inner.read();
        Ok(traverse::bfs_neighborhood(
            id,
            depth,
            &inner.entities,
            &inner.relations,
            &inner.outgoing,
        ))
    }

    fn find_dead_code(&self) -> Result<Vec<Entity>, KinDbError> {
        let inner = self.inner.read();
        Ok(traverse::find_dead_code(
            &inner.entities,
            &inner.incoming,
            &inner.relations,
        ))
    }

    fn has_incoming_relation_kinds(
        &self,
        id: &EntityId,
        kinds: &[RelationKind],
        exclude_same_file: bool,
    ) -> Result<bool, KinDbError> {
        let inner = self.inner.read();
        let entity = match inner.entities.get(id) {
            Some(e) => e,
            None => return Ok(false),
        };
        Ok(traverse::has_incoming_of_kinds(
            id,
            entity,
            kinds,
            exclude_same_file,
            &inner.incoming,
            &inner.relations,
            &inner.entities,
        ))
    }

    fn get_entity_history(
        &self,
        id: &EntityId,
    ) -> Result<Vec<SemanticChange>, KinDbError> {
        let inner = self.inner.read();
        // Find all changes that mention this entity in their deltas
        let mut history: Vec<SemanticChange> = inner
            .changes
            .values()
            .filter(|change| {
                change.entity_deltas.iter().any(|delta| match delta {
                    EntityDelta::Added(e) => e.id == *id,
                    EntityDelta::Modified { old, new } => old.id == *id || new.id == *id,
                    EntityDelta::Removed(eid) => eid == id,
                })
            })
            .cloned()
            .collect();
        // Sort by timestamp ascending
        history.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        Ok(history)
    }

    fn find_merge_bases(
        &self,
        a: &SemanticChangeId,
        b: &SemanticChangeId,
    ) -> Result<Vec<SemanticChangeId>, KinDbError> {
        let inner = self.inner.read();

        // Collect all ancestors of `a`
        let mut ancestors_a: hashbrown::HashSet<SemanticChangeId> = hashbrown::HashSet::new();
        let mut stack = vec![*a];
        while let Some(cid) = stack.pop() {
            if ancestors_a.insert(cid) {
                if let Some(change) = inner.changes.get(&cid) {
                    stack.extend_from_slice(&change.parents);
                }
            }
        }

        // Walk ancestors of `b`, find the first ones that are also ancestors of `a`
        let mut bases = Vec::new();
        let mut visited: hashbrown::HashSet<SemanticChangeId> = hashbrown::HashSet::new();
        let mut stack = vec![*b];
        while let Some(cid) = stack.pop() {
            if !visited.insert(cid) {
                continue;
            }
            if ancestors_a.contains(&cid) {
                bases.push(cid);
                // Don't traverse further past a merge base
                continue;
            }
            if let Some(change) = inner.changes.get(&cid) {
                stack.extend_from_slice(&change.parents);
            }
        }

        Ok(bases)
    }

    fn query_entities(
        &self,
        filter: &EntityFilter,
    ) -> Result<Vec<Entity>, KinDbError> {
        let inner = self.inner.read();

        let candidate_ids: Vec<EntityId> = if let Some(ref fp) = filter.file_path {
            inner.indexes.by_file(&fp.0).to_vec()
        } else if let Some(ref pattern) = filter.name_pattern {
            inner.indexes.by_name_pattern(pattern)
        } else if let Some(ref kinds) = filter.kinds {
            if kinds.len() == 1 {
                inner.indexes.by_kind(kinds[0]).to_vec()
            } else {
                inner.entities.keys().copied().collect()
            }
        } else {
            inner.entities.keys().copied().collect()
        };

        let mut results = Vec::new();
        for eid in candidate_ids {
            if let Some(entity) = inner.entities.get(&eid) {
                if matches_filter(entity, filter) {
                    results.push(entity.clone());
                }
            }
        }

        Ok(results)
    }

    fn list_all_entities(&self) -> Result<Vec<Entity>, KinDbError> {
        Ok(self.inner.read().entities.values().cloned().collect())
    }

    // -----------------------------------------------------------------------
    // Write operations
    // -----------------------------------------------------------------------

    fn upsert_entity(&self, entity: &Entity) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();

        // Remove old index entries if updating
        if let Some(old) = inner.entities.remove(&entity.id) {
            inner
                .indexes
                .remove(&old.id, &old.name, old.file_origin.as_ref(), old.kind);
        }

        // Insert new index entries
        inner.indexes.insert(
            entity.id,
            &entity.name,
            entity.file_origin.as_ref(),
            entity.kind,
        );

        inner.entities.insert(entity.id, entity.clone());
        Ok(())
    }

    fn upsert_relation(&self, relation: &Relation) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();

        // Remove old edge entries if updating
        if let Some(old) = inner.relations.remove(&relation.id) {
            if let Some(out) = inner.outgoing.get_mut(&old.src) {
                out.retain(|r| *r != relation.id);
            }
            if let Some(inc) = inner.incoming.get_mut(&old.dst) {
                inc.retain(|r| *r != relation.id);
            }
        }

        // Insert new edge entries
        inner
            .outgoing
            .entry(relation.src)
            .or_default()
            .push(relation.id);
        inner
            .incoming
            .entry(relation.dst)
            .or_default()
            .push(relation.id);

        inner.relations.insert(relation.id, relation.clone());
        Ok(())
    }

    fn remove_entity(&self, id: &EntityId) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();

        if let Some(entity) = inner.entities.remove(id) {
            inner
                .indexes
                .remove(&entity.id, &entity.name, entity.file_origin.as_ref(), entity.kind);
        }

        // Clean up edge maps (but leave the relations themselves — caller should
        // remove relations explicitly if desired)
        inner.outgoing.remove(id);
        inner.incoming.remove(id);

        Ok(())
    }

    fn remove_relation(&self, id: &RelationId) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();

        if let Some(rel) = inner.relations.remove(id) {
            if let Some(out) = inner.outgoing.get_mut(&rel.src) {
                out.retain(|r| *r != *id);
            }
            if let Some(inc) = inner.incoming.get_mut(&rel.dst) {
                inc.retain(|r| *r != *id);
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // SemanticChange DAG
    // -----------------------------------------------------------------------

    fn create_change(&self, change: &SemanticChange) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();

        // Register in parent → children index
        for parent in &change.parents {
            inner
                .change_children
                .entry(*parent)
                .or_default()
                .push(change.id);
        }

        inner.changes.insert(change.id, change.clone());
        Ok(())
    }

    fn get_change(
        &self,
        id: &SemanticChangeId,
    ) -> Result<Option<SemanticChange>, KinDbError> {
        Ok(self.inner.read().changes.get(id).cloned())
    }

    fn get_changes_since(
        &self,
        base: &SemanticChangeId,
        head: &SemanticChangeId,
    ) -> Result<Vec<SemanticChange>, KinDbError> {
        let inner = self.inner.read();

        // Walk backwards from head collecting changes until we hit base
        let mut result = Vec::new();
        let mut visited: hashbrown::HashSet<SemanticChangeId> = hashbrown::HashSet::new();
        let mut stack = vec![*head];

        while let Some(cid) = stack.pop() {
            if cid == *base || !visited.insert(cid) {
                continue;
            }
            if let Some(change) = inner.changes.get(&cid) {
                result.push(change.clone());
                stack.extend_from_slice(&change.parents);
            }
        }

        // Reverse so oldest-first
        result.reverse();
        Ok(result)
    }

    // -----------------------------------------------------------------------
    // Branch operations
    // -----------------------------------------------------------------------

    fn get_branch(&self, name: &BranchName) -> Result<Option<Branch>, KinDbError> {
        Ok(self.inner.read().branches.get(name).cloned())
    }

    fn create_branch(&self, branch: &Branch) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        if inner.branches.contains_key(&branch.name) {
            return Err(KinDbError::DuplicateEntity(format!(
                "branch '{}' already exists",
                branch.name
            )));
        }
        inner.branches.insert(branch.name.clone(), branch.clone());
        Ok(())
    }

    fn update_branch_head(
        &self,
        name: &BranchName,
        new_head: &SemanticChangeId,
    ) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        match inner.branches.get_mut(name) {
            Some(branch) => {
                branch.head = *new_head;
                Ok(())
            }
            None => Err(KinDbError::NotFound(format!("branch '{}'", name))),
        }
    }

    fn delete_branch(&self, name: &BranchName) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        inner.branches.remove(name);
        Ok(())
    }

    fn list_branches(&self) -> Result<Vec<Branch>, KinDbError> {
        Ok(self.inner.read().branches.values().cloned().collect())
    }
}

/// Check whether an entity matches all filter criteria.
fn matches_filter(entity: &Entity, filter: &EntityFilter) -> bool {
    if let Some(ref kinds) = filter.kinds {
        if !kinds.contains(&entity.kind) {
            return false;
        }
    }

    if let Some(ref langs) = filter.languages {
        if !langs.contains(&entity.language) {
            return false;
        }
    }

    if let Some(ref pattern) = filter.name_pattern {
        let pat = pattern.to_lowercase();
        let name = entity.name.to_lowercase();
        if let Some(suffix) = pat.strip_prefix('*') {
            if !name.ends_with(suffix) {
                return false;
            }
        } else if let Some(prefix) = pat.strip_suffix('*') {
            if !name.starts_with(prefix) {
                return false;
            }
        } else if name != pat {
            return false;
        }
    }

    if let Some(ref fp) = filter.file_path {
        match &entity.file_origin {
            Some(origin) if origin == fp => {}
            _ => return false,
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entity(name: &str, file: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn test_relation(src: EntityId, dst: EntityId, kind: RelationKind) -> Relation {
        Relation {
            id: RelationId::new(),
            kind,
            src,
            dst,
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
        }
    }

    #[test]
    fn upsert_and_get_entity() {
        let graph = InMemoryGraph::new();
        let entity = test_entity("foo", "src/main.rs");
        let id = entity.id;

        graph.upsert_entity(&entity).unwrap();
        let fetched = graph.get_entity(&id).unwrap().unwrap();
        assert_eq!(fetched.name, "foo");
        assert_eq!(graph.entity_count(), 1);
    }

    #[test]
    fn upsert_entity_overwrites() {
        let graph = InMemoryGraph::new();
        let mut entity = test_entity("foo", "src/main.rs");
        let id = entity.id;

        graph.upsert_entity(&entity).unwrap();
        entity.name = "bar".to_string();
        graph.upsert_entity(&entity).unwrap();

        let fetched = graph.get_entity(&id).unwrap().unwrap();
        assert_eq!(fetched.name, "bar");
        assert_eq!(graph.entity_count(), 1);
    }

    #[test]
    fn remove_entity_cleans_up() {
        let graph = InMemoryGraph::new();
        let entity = test_entity("foo", "src/main.rs");
        let id = entity.id;

        graph.upsert_entity(&entity).unwrap();
        graph.remove_entity(&id).unwrap();

        assert!(graph.get_entity(&id).unwrap().is_none());
        assert_eq!(graph.entity_count(), 0);
    }

    #[test]
    fn upsert_and_get_relations() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("caller", "a.rs");
        let e2 = test_entity("callee", "b.rs");
        let rel = test_relation(e1.id, e2.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();

        // Outgoing from e1
        let rels = graph.get_relations(&e1.id, &[RelationKind::Calls]).unwrap();
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].dst, e2.id);

        // All relations for e2 (incoming)
        let rels = graph.get_all_relations_for_entity(&e2.id).unwrap();
        assert_eq!(rels.len(), 1);
    }

    #[test]
    fn remove_relation() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("a", "a.rs");
        let e2 = test_entity("b", "b.rs");
        let rel = test_relation(e1.id, e2.id, RelationKind::Calls);
        let rid = rel.id;

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();
        graph.remove_relation(&rid).unwrap();

        assert!(graph.get_relations(&e1.id, &[]).unwrap().is_empty());
        assert_eq!(graph.relation_count(), 0);
    }

    #[test]
    fn query_by_kind() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("func1", "a.rs");
        let mut e2 = test_entity("MyClass", "b.rs");
        e2.kind = EntityKind::Class;

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let filter = EntityFilter {
            kinds: Some(vec![EntityKind::Function]),
            ..Default::default()
        };
        let results = graph.query_entities(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "func1");
    }

    #[test]
    fn query_by_name_pattern() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("getUser", "a.rs");
        let e2 = test_entity("getPost", "a.rs");
        let e3 = test_entity("deleteUser", "a.rs");

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();

        let filter = EntityFilter {
            name_pattern: Some("get*".to_string()),
            ..Default::default()
        };
        let results = graph.query_entities(&filter).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn query_by_file() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("a", "src/main.rs");
        let e2 = test_entity("b", "src/lib.rs");

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let filter = EntityFilter {
            file_path: Some(FilePathId::new("src/main.rs")),
            ..Default::default()
        };
        let results = graph.query_entities(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "a");
    }

    #[test]
    fn downstream_impact() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("core_fn", "a.rs");
        let e2 = test_entity("caller", "b.rs");
        let rel = test_relation(e2.id, e1.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();

        let impact = graph.get_downstream_impact(&e1.id, 10).unwrap();
        assert_eq!(impact.len(), 1);
        assert_eq!(impact[0].id, e2.id);
    }

    #[test]
    fn dependency_neighborhood() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("a", "a.rs");
        let e2 = test_entity("b", "b.rs");
        let e3 = test_entity("c", "c.rs");
        let r1 = test_relation(e1.id, e2.id, RelationKind::Calls);
        let r2 = test_relation(e2.id, e3.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();
        graph.upsert_relation(&r1).unwrap();
        graph.upsert_relation(&r2).unwrap();

        let sg = graph.get_dependency_neighborhood(&e1.id, 2).unwrap();
        assert_eq!(sg.entities.len(), 3);
        assert_eq!(sg.relations.len(), 2);
    }

    #[test]
    fn dead_code_detection() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("used", "a.rs");
        let e2 = test_entity("unused", "b.rs");
        let e3 = test_entity("caller", "c.rs");
        let rel = test_relation(e3.id, e1.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();
        graph.upsert_relation(&rel).unwrap();

        let dead = graph.find_dead_code().unwrap();
        let dead_names: Vec<&str> = dead.iter().map(|e| e.name.as_str()).collect();
        assert!(dead_names.contains(&"unused"));
        assert!(dead_names.contains(&"caller"));
        assert!(!dead_names.contains(&"used"));
    }

    #[test]
    fn has_incoming_relation_kinds() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("target", "a.rs");
        let e2 = test_entity("caller", "b.rs");
        let rel = test_relation(e2.id, e1.id, RelationKind::Calls);

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();

        assert!(graph
            .has_incoming_relation_kinds(&e1.id, &[RelationKind::Calls], false)
            .unwrap());
        assert!(!graph
            .has_incoming_relation_kinds(&e1.id, &[RelationKind::Imports], false)
            .unwrap());
    }

    #[test]
    fn branch_operations() {
        let graph = InMemoryGraph::new();
        let change_id = SemanticChangeId::from_hash(Hash256::from_bytes([1; 32]));
        let branch = Branch {
            id: BranchId::new(),
            name: BranchName::new("main"),
            head: change_id,
            created_at: Timestamp::now(),
        };

        graph.create_branch(&branch).unwrap();
        let fetched = graph
            .get_branch(&BranchName::new("main"))
            .unwrap()
            .unwrap();
        assert_eq!(fetched.name.0, "main");

        let new_head = SemanticChangeId::from_hash(Hash256::from_bytes([2; 32]));
        graph
            .update_branch_head(&BranchName::new("main"), &new_head)
            .unwrap();
        let updated = graph
            .get_branch(&BranchName::new("main"))
            .unwrap()
            .unwrap();
        assert_eq!(updated.head, new_head);

        let branches = graph.list_branches().unwrap();
        assert_eq!(branches.len(), 1);

        graph.delete_branch(&BranchName::new("main")).unwrap();
        assert!(graph
            .get_branch(&BranchName::new("main"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn change_dag_operations() {
        let graph = InMemoryGraph::new();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([1; 32]));
        let genesis = SemanticChange {
            id: genesis_id,
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "genesis".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        graph.create_change(&genesis).unwrap();

        let child_id = SemanticChangeId::from_hash(Hash256::from_bytes([2; 32]));
        let child = SemanticChange {
            id: child_id,
            parents: vec![genesis_id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "child".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        graph.create_change(&child).unwrap();

        let fetched = graph.get_change(&child_id).unwrap().unwrap();
        assert_eq!(fetched.message, "child");

        let since = graph.get_changes_since(&genesis_id, &child_id).unwrap();
        assert_eq!(since.len(), 1);
        assert_eq!(since[0].message, "child");
    }

    #[test]
    fn list_all_entities() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("a", "a.rs");
        let e2 = test_entity("b", "b.rs");

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let all = graph.list_all_entities().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn concurrent_read_access() {
        use std::sync::Arc;
        use std::thread;

        let graph = Arc::new(InMemoryGraph::new());
        let e = test_entity("concurrent", "a.rs");
        let id = e.id;
        graph.upsert_entity(&e).unwrap();

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let g = Arc::clone(&graph);
                thread::spawn(move || g.get_entity(&id).unwrap().unwrap().name)
            })
            .collect();

        for h in handles {
            assert_eq!(h.join().unwrap(), "concurrent");
        }
    }
}
