use hashbrown::HashMap;
use parking_lot::RwLock;
use rayon::prelude::*;

use crate::error::KinDbError;
use crate::storage::GraphSnapshot;
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

    // Work graph (Phase 8)
    work_items: HashMap<WorkId, WorkItem>,
    annotations: HashMap<AnnotationId, Annotation>,
    work_links: Vec<WorkLink>,

    // Verification (Phase 9)
    test_cases: HashMap<TestId, TestCase>,
    assertions: HashMap<AssertionId, Assertion>,
    verification_runs: HashMap<VerificationRunId, VerificationRun>,
    test_covers_entity: Vec<(TestId, EntityId)>,
    test_covers_contract: Vec<(TestId, ContractId)>,
    test_verifies_work: Vec<(TestId, WorkId)>,
    run_proves_entity: Vec<(VerificationRunId, EntityId)>,
    run_proves_work: Vec<(VerificationRunId, WorkId)>,
    mock_hints: Vec<MockHint>,

    // Contracts
    contracts: HashMap<ContractId, Contract>,

    // Provenance (Phase 10)
    actors: HashMap<ActorId, Actor>,
    delegations: Vec<Delegation>,
    approvals: Vec<Approval>,
    audit_events: Vec<AuditEvent>,

    // Shallow file tracking (C2 tier)
    shallow_files: Vec<ShallowTrackedFile>,

    // Incremental indexing: file path → SHA-256 content hash
    file_hashes: HashMap<String, [u8; 32]>,

    // Session/intent management (daemon)
    sessions: HashMap<SessionId, AgentSession>,
    intents: HashMap<IntentId, Intent>,
    downstream_warnings: Vec<(IntentId, EntityId, String)>,
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
                work_items: HashMap::new(),
                annotations: HashMap::new(),
                work_links: Vec::new(),
                test_cases: HashMap::new(),
                assertions: HashMap::new(),
                verification_runs: HashMap::new(),
                test_covers_entity: Vec::new(),
                test_covers_contract: Vec::new(),
                test_verifies_work: Vec::new(),
                run_proves_entity: Vec::new(),
                run_proves_work: Vec::new(),
                mock_hints: Vec::new(),
                contracts: HashMap::new(),
                actors: HashMap::new(),
                delegations: Vec::new(),
                approvals: Vec::new(),
                audit_events: Vec::new(),
                shallow_files: Vec::new(),
                file_hashes: HashMap::new(),
                sessions: HashMap::new(),
                intents: HashMap::new(),
                downstream_warnings: Vec::new(),
            }),
        }
    }

    pub(crate) fn from_snapshot(snapshot: GraphSnapshot) -> Self {
        let mut indexes = IndexSet::new();
        for entity in snapshot.entities.values() {
            indexes.insert(
                entity.id,
                &entity.name,
                entity.file_origin.as_ref(),
                entity.kind,
            );
        }

        Self {
            inner: RwLock::new(GraphInner {
                entities: snapshot.entities.into_iter().collect(),
                relations: snapshot.relations.into_iter().collect(),
                outgoing: snapshot.outgoing.into_iter().collect(),
                incoming: snapshot.incoming.into_iter().collect(),
                indexes,
                changes: snapshot.changes.into_iter().collect(),
                change_children: snapshot.change_children.into_iter().collect(),
                branches: snapshot.branches.into_iter().collect(),
                work_items: snapshot.work_items.into_iter().collect(),
                annotations: snapshot.annotations.into_iter().collect(),
                work_links: snapshot.work_links,
                test_cases: snapshot.test_cases.into_iter().collect(),
                assertions: snapshot.assertions.into_iter().collect(),
                verification_runs: snapshot.verification_runs.into_iter().collect(),
                test_covers_entity: snapshot.test_covers_entity,
                test_covers_contract: snapshot.test_covers_contract,
                test_verifies_work: snapshot.test_verifies_work,
                run_proves_entity: snapshot.run_proves_entity,
                run_proves_work: snapshot.run_proves_work,
                mock_hints: snapshot.mock_hints,
                contracts: snapshot.contracts.into_iter().collect(),
                actors: snapshot.actors.into_iter().collect(),
                delegations: snapshot.delegations,
                approvals: snapshot.approvals,
                audit_events: snapshot.audit_events,
                shallow_files: snapshot.shallow_files,
                file_hashes: snapshot.file_hashes.into_iter().collect(),
                sessions: snapshot.sessions.into_iter().collect(),
                intents: snapshot.intents.into_iter().collect(),
                downstream_warnings: snapshot.downstream_warnings,
            }),
        }
    }

    pub(crate) fn to_snapshot(&self) -> GraphSnapshot {
        let inner = self.inner.read();
        GraphSnapshot {
            version: GraphSnapshot::CURRENT_VERSION,
            entities: inner
                .entities
                .iter()
                .map(|(id, entity)| (*id, entity.clone()))
                .collect(),
            relations: inner
                .relations
                .iter()
                .map(|(id, relation)| (*id, relation.clone()))
                .collect(),
            outgoing: inner
                .outgoing
                .iter()
                .map(|(id, rels)| (*id, rels.clone()))
                .collect(),
            incoming: inner
                .incoming
                .iter()
                .map(|(id, rels)| (*id, rels.clone()))
                .collect(),
            changes: inner
                .changes
                .iter()
                .map(|(id, change)| (*id, change.clone()))
                .collect(),
            change_children: inner
                .change_children
                .iter()
                .map(|(id, children)| (*id, children.clone()))
                .collect(),
            branches: inner
                .branches
                .iter()
                .map(|(name, branch)| (name.clone(), branch.clone()))
                .collect(),
            work_items: inner
                .work_items
                .iter()
                .map(|(id, item)| (*id, item.clone()))
                .collect(),
            annotations: inner
                .annotations
                .iter()
                .map(|(id, ann)| (*id, ann.clone()))
                .collect(),
            work_links: inner.work_links.clone(),
            test_cases: inner
                .test_cases
                .iter()
                .map(|(id, test)| (*id, test.clone()))
                .collect(),
            assertions: inner
                .assertions
                .iter()
                .map(|(id, assertion)| (*id, assertion.clone()))
                .collect(),
            verification_runs: inner
                .verification_runs
                .iter()
                .map(|(id, run)| (*id, run.clone()))
                .collect(),
            test_covers_entity: inner.test_covers_entity.clone(),
            test_covers_contract: inner.test_covers_contract.clone(),
            test_verifies_work: inner.test_verifies_work.clone(),
            run_proves_entity: inner.run_proves_entity.clone(),
            run_proves_work: inner.run_proves_work.clone(),
            mock_hints: inner.mock_hints.clone(),
            contracts: inner
                .contracts
                .iter()
                .map(|(id, contract)| (*id, contract.clone()))
                .collect(),
            actors: inner
                .actors
                .iter()
                .map(|(id, actor)| (*id, actor.clone()))
                .collect(),
            delegations: inner.delegations.clone(),
            approvals: inner.approvals.clone(),
            audit_events: inner.audit_events.clone(),
            shallow_files: inner.shallow_files.clone(),
            file_hashes: inner.file_hashes.iter().map(|(path, hash)| (path.clone(), *hash)).collect(),
            sessions: inner
                .sessions
                .iter()
                .map(|(id, session)| (*id, session.clone()))
                .collect(),
            intents: inner
                .intents
                .iter()
                .map(|(id, intent)| (*id, intent.clone()))
                .collect(),
            downstream_warnings: inner.downstream_warnings.clone(),
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

    // ---------------------------------------------------------------
    // Non-trait methods (needed by commit.rs, matching KuzuGraphStore)
    // ---------------------------------------------------------------

    /// Remove all outgoing relations for an entity.
    /// Called during re-linking after file re-parse.
    pub fn remove_outgoing_relations(&self, id: &EntityId) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        if let Some(rel_ids) = inner.outgoing.remove(id) {
            for rel_id in &rel_ids {
                if let Some(rel) = inner.relations.remove(rel_id) {
                    // Also remove from incoming side
                    if let Some(inc) = inner.incoming.get_mut(&rel.dst) {
                        inc.retain(|r| r != rel_id);
                    }
                }
            }
        }
        Ok(())
    }

    /// Delete a shallow tracked file by file path.
    pub fn delete_shallow_file(&self, file_id: &FilePathId) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        inner.shallow_files.retain(|sf| sf.file_id != *file_id);
        Ok(())
    }

    /// Get a single shallow tracked file.
    pub fn get_shallow_file(&self, file_id: &FilePathId) -> Result<Option<ShallowTrackedFile>, KinDbError> {
        let inner = self.inner.read();
        Ok(inner.shallow_files.iter().find(|sf| sf.file_id == *file_id).cloned())
    }

    // -------------------------------------------------------------------
    // Session/intent management (daemon)
    // -------------------------------------------------------------------

    pub fn upsert_session(&self, session: &AgentSession) -> Result<(), KinDbError> {
        self.inner.write().sessions.insert(session.session_id, session.clone());
        Ok(())
    }
    pub fn get_session(&self, session_id: &SessionId) -> Result<Option<AgentSession>, KinDbError> {
        Ok(self.inner.read().sessions.get(session_id).cloned())
    }
    pub fn delete_session(&self, session_id: &SessionId) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        inner.sessions.remove(session_id);
        inner.intents.retain(|_, i| i.session_id != *session_id);
        Ok(())
    }
    pub fn list_sessions(&self) -> Result<Vec<AgentSession>, KinDbError> {
        Ok(self.inner.read().sessions.values().cloned().collect())
    }
    pub fn update_heartbeat(&self, session_id: &SessionId, heartbeat: &Timestamp) -> Result<(), KinDbError> {
        if let Some(s) = self.inner.write().sessions.get_mut(session_id) {
            s.last_heartbeat = heartbeat.clone();
        }
        Ok(())
    }
    pub fn register_intent(&self, intent: &Intent) -> Result<(), KinDbError> {
        self.inner.write().intents.insert(intent.intent_id, intent.clone());
        Ok(())
    }
    pub fn get_intent(&self, intent_id: &IntentId) -> Result<Option<Intent>, KinDbError> {
        Ok(self.inner.read().intents.get(intent_id).cloned())
    }
    pub fn delete_intent(&self, intent_id: &IntentId) -> Result<(), KinDbError> {
        self.inner.write().intents.remove(intent_id);
        Ok(())
    }
    pub fn list_intents_for_session(&self, session_id: &SessionId) -> Result<Vec<Intent>, KinDbError> {
        Ok(self.inner.read().intents.values().filter(|i| i.session_id == *session_id).cloned().collect())
    }
    pub fn list_all_intents(&self) -> Result<Vec<Intent>, KinDbError> {
        Ok(self.inner.read().intents.values().cloned().collect())
    }
    pub fn hard_collisions_for_entity(&self, entity_id: &EntityId, _exclude_intent: &IntentId) -> Result<Vec<Intent>, KinDbError> {
        Ok(self.inner.read().intents.values()
            .filter(|i| i.scopes.iter().any(|s| matches!(s, IntentScope::Entity(eid) if eid == entity_id)) && i.lock_type == LockType::Hard)
            .cloned().collect())
    }
    pub fn locks_for_entity(&self, entity_id: &EntityId) -> Result<Vec<Intent>, KinDbError> {
        Ok(self.inner.read().intents.values()
            .filter(|i| i.scopes.iter().any(|s| matches!(s, IntentScope::Entity(eid) if eid == entity_id)) && i.lock_type == LockType::Hard)
            .cloned().collect())
    }
    pub fn downstream_warnings_for_entity(&self, entity_id: &EntityId) -> Result<Vec<Intent>, KinDbError> {
        let inner = self.inner.read();
        let intent_ids: Vec<IntentId> = inner.downstream_warnings.iter()
            .filter(|(_, eid, _)| eid == entity_id)
            .map(|(iid, _, _)| *iid)
            .collect();
        Ok(intent_ids.iter().filter_map(|iid| inner.intents.get(iid).cloned()).collect())
    }
    pub fn create_downstream_warning(&self, intent_id: &IntentId, entity_id: &EntityId, reason: &str) -> Result<(), KinDbError> {
        self.inner.write().downstream_warnings.push((*intent_id, *entity_id, reason.to_string()));
        Ok(())
    }

    // -------------------------------------------------------------------
    // Incremental indexing helpers
    // -------------------------------------------------------------------

    /// Record the content hash for a file.
    pub fn set_file_hash(&self, path: &str, hash: [u8; 32]) {
        self.inner.write().file_hashes.insert(path.to_string(), hash);
    }

    /// Get the recorded hash for a file.
    pub fn get_file_hash(&self, path: &str) -> Option<[u8; 32]> {
        self.inner.read().file_hashes.get(path).copied()
    }

    /// Remove all entities and their outgoing relations for entities in a given file.
    ///
    /// Incoming relations from OTHER files pointing to removed entities are kept
    /// (they become dangling but will be fixed during the cross-file linking phase).
    ///
    /// Returns the removed entity IDs.
    pub fn remove_entities_for_file(&self, path: &str) -> Vec<EntityId> {
        let mut inner = self.inner.write();

        // Find all entity IDs in this file via the file index.
        let entity_ids: Vec<EntityId> = inner
            .indexes
            .by_file(path)
            .to_vec();

        if entity_ids.is_empty() {
            return Vec::new();
        }

        let entity_set: hashbrown::HashSet<EntityId> = entity_ids.iter().copied().collect();

        for &eid in &entity_ids {
            // Remove the entity itself.
            if let Some(entity) = inner.entities.remove(&eid) {
                inner.indexes.remove(
                    &entity.id,
                    &entity.name,
                    entity.file_origin.as_ref(),
                    entity.kind,
                );
            }

            // Remove all outgoing relations from this entity.
            if let Some(out_rids) = inner.outgoing.remove(&eid) {
                for rid in &out_rids {
                    if let Some(rel) = inner.relations.remove(rid) {
                        // Clean up the incoming side of the destination entity.
                        if let Some(inc) = inner.incoming.get_mut(&rel.dst) {
                            inc.retain(|r| r != rid);
                            if inc.is_empty() {
                                inner.incoming.remove(&rel.dst);
                            }
                        }
                    }
                }
            }

            // Remove incoming relations that originate from entities in the SAME file
            // (they were already removed above as outgoing from another entity in
            // entity_ids). For incoming relations from OTHER files, keep them as
            // dangling. We only need to clean up the incoming vec for this entity.
            if let Some(inc_rids) = inner.incoming.remove(&eid) {
                for rid in &inc_rids {
                    // If the relation still exists, it's from an external file — keep it
                    // in the relations map but just remove from this entity's incoming vec
                    // (which we already did by removing the key). However we also need to
                    // check if the source is in the same file set — if so the relation
                    // was already removed above.
                    if let Some(rel) = inner.relations.get(rid) {
                        if entity_set.contains(&rel.src) {
                            // Already removed as outgoing above — this is a leftover ref.
                            // The relation is already gone from inner.relations via the
                            // outgoing removal pass.
                        }
                        // If src is NOT in entity_set, this is a cross-file incoming
                        // relation. Keep the relation in inner.relations (dangling dst).
                    }
                }
            }
        }

        // Also remove the file hash entry.
        inner.file_hashes.remove(path);

        entity_ids
    }

    /// Get all file paths that have recorded content hashes.
    pub fn indexed_file_paths(&self) -> Vec<String> {
        self.inner.read().file_hashes.keys().cloned().collect()
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
                    if !result.iter().any(|r: &Relation| r.id == rel.id) {
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

        let results: Vec<Entity> = candidate_ids
            .par_iter()
            .filter_map(|eid| {
                inner.entities.get(eid).and_then(|entity| {
                    if matches_filter(entity, filter) {
                        Some(entity.clone())
                    } else {
                        None
                    }
                })
            })
            .collect();

        Ok(results)
    }

    fn list_all_entities(&self) -> Result<Vec<Entity>, KinDbError> {
        Ok(self
            .inner
            .read()
            .entities
            .par_values()
            .cloned()
            .collect())
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

        // Clean up edge maps
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

    // -----------------------------------------------------------------------
    // Work graph operations (Phase 8)
    // -----------------------------------------------------------------------

    fn create_work_item(&self, item: &WorkItem) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        inner.work_items.insert(item.work_id, item.clone());
        Ok(())
    }

    fn get_work_item(&self, id: &WorkId) -> Result<Option<WorkItem>, KinDbError> {
        Ok(self.inner.read().work_items.get(id).cloned())
    }

    fn list_work_items(
        &self,
        filter: &WorkFilter,
    ) -> Result<Vec<WorkItem>, KinDbError> {
        let inner = self.inner.read();
        let results = inner
            .work_items
            .values()
            .filter(|item| {
                if let Some(ref kinds) = filter.kinds {
                    if !kinds.contains(&item.kind) {
                        return false;
                    }
                }
                if let Some(ref statuses) = filter.statuses {
                    if !statuses.contains(&item.status) {
                        return false;
                    }
                }
                if let Some(ref scope) = filter.scope {
                    if !item.scopes.contains(scope) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        Ok(results)
    }

    fn update_work_status(
        &self,
        id: &WorkId,
        status: WorkStatus,
    ) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        match inner.work_items.get_mut(id) {
            Some(item) => {
                item.status = status;
                Ok(())
            }
            None => Err(KinDbError::NotFound(format!("work item '{}'", id))),
        }
    }

    fn delete_work_item(&self, id: &WorkId) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        inner.work_items.remove(id);
        // Also remove associated links
        inner.work_links.retain(|link| match link {
            WorkLink::Affects { work_id, .. } => work_id != id,
            WorkLink::DecomposesTo { parent, child } => parent != id && child != id,
            WorkLink::BlockedBy { blocked, blocker } => blocked != id && blocker != id,
            WorkLink::Implements { work_id, .. } => work_id != id,
            _ => true,
        });
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Annotation operations (Phase 8)
    // -----------------------------------------------------------------------

    fn create_annotation(&self, ann: &Annotation) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        inner.annotations.insert(ann.annotation_id, ann.clone());
        Ok(())
    }

    fn get_annotation(
        &self,
        id: &AnnotationId,
    ) -> Result<Option<Annotation>, KinDbError> {
        Ok(self.inner.read().annotations.get(id).cloned())
    }

    fn list_annotations(
        &self,
        filter: &AnnotationFilter,
    ) -> Result<Vec<Annotation>, KinDbError> {
        let inner = self.inner.read();
        let results = inner
            .annotations
            .values()
            .filter(|ann| {
                if let Some(ref kinds) = filter.kinds {
                    if !kinds.contains(&ann.kind) {
                        return false;
                    }
                }
                if let Some(ref scopes) = filter.scopes {
                    if !ann.scopes.iter().any(|s| scopes.contains(s)) {
                        return false;
                    }
                }
                if !filter.include_stale && ann.staleness == StalenessState::Stale {
                    return false;
                }
                true
            })
            .cloned()
            .collect();
        Ok(results)
    }

    fn update_annotation_staleness(
        &self,
        id: &AnnotationId,
        staleness: StalenessState,
    ) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        match inner.annotations.get_mut(id) {
            Some(ann) => {
                ann.staleness = staleness;
                Ok(())
            }
            None => Err(KinDbError::NotFound(format!("annotation '{}'", id))),
        }
    }

    fn delete_annotation(&self, id: &AnnotationId) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        inner.annotations.remove(id);
        // Remove associated links
        inner.work_links.retain(|link| match link {
            WorkLink::AttachedTo { annotation_id, .. } => annotation_id != id,
            WorkLink::Supersedes { new_id, old_id } => new_id != id && old_id != id,
            _ => true,
        });
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Work graph relationships (Phase 8)
    // -----------------------------------------------------------------------

    fn create_work_link(&self, link: &WorkLink) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        // Avoid duplicates
        if !inner.work_links.contains(link) {
            inner.work_links.push(link.clone());
        }
        Ok(())
    }

    fn delete_work_link(&self, link: &WorkLink) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        inner.work_links.retain(|l| l != link);
        Ok(())
    }

    fn get_work_for_scope(
        &self,
        scope: &WorkScope,
    ) -> Result<Vec<WorkItem>, KinDbError> {
        let inner = self.inner.read();
        // Find work IDs that affect this scope
        let work_ids: Vec<WorkId> = inner
            .work_links
            .iter()
            .filter_map(|link| match link {
                WorkLink::Affects { work_id, scope: s } if s == scope => Some(*work_id),
                _ => None,
            })
            .collect();
        // Also include items whose scopes contain this scope directly
        let mut results: Vec<WorkItem> = inner
            .work_items
            .values()
            .filter(|item| {
                item.scopes.contains(scope) || work_ids.contains(&item.work_id)
            })
            .cloned()
            .collect();
        results.dedup_by_key(|item| item.work_id);
        Ok(results)
    }

    fn get_annotations_for_scope(
        &self,
        scope: &WorkScope,
    ) -> Result<Vec<Annotation>, KinDbError> {
        let inner = self.inner.read();
        let results = inner
            .annotations
            .values()
            .filter(|ann| ann.scopes.contains(scope))
            .cloned()
            .collect();
        Ok(results)
    }

    fn get_child_work_items(
        &self,
        parent: &WorkId,
    ) -> Result<Vec<WorkItem>, KinDbError> {
        let inner = self.inner.read();
        let child_ids: Vec<WorkId> = inner
            .work_links
            .iter()
            .filter_map(|link| match link {
                WorkLink::DecomposesTo { parent: p, child } if p == parent => Some(*child),
                _ => None,
            })
            .collect();
        let results = child_ids
            .iter()
            .filter_map(|id| inner.work_items.get(id).cloned())
            .collect();
        Ok(results)
    }

    fn get_implementors(
        &self,
        work_id: &WorkId,
    ) -> Result<Vec<WorkScope>, KinDbError> {
        let inner = self.inner.read();
        let scopes = inner
            .work_links
            .iter()
            .filter_map(|link| match link {
                WorkLink::Implements { scope, work_id: wid } if wid == work_id => {
                    Some(scope.clone())
                }
                _ => None,
            })
            .collect();
        Ok(scopes)
    }

    // -----------------------------------------------------------------------
    // Verification graph operations (Phase 9)
    // -----------------------------------------------------------------------

    fn create_test_case(&self, test: &TestCase) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        // Auto-create coverage edges from entity scopes (matches KuzuGraphStore behavior).
        for scope in &test.scopes {
            if let WorkScope::Entity(eid) = scope {
                if inner.entities.contains_key(eid) {
                    let pair = (test.test_id, *eid);
                    if !inner.test_covers_entity.contains(&pair) {
                        inner.test_covers_entity.push(pair);
                    }
                }
            }
        }
        inner.test_cases.insert(test.test_id, test.clone());
        Ok(())
    }

    fn get_test_case(&self, id: &TestId) -> Result<Option<TestCase>, KinDbError> {
        Ok(self.inner.read().test_cases.get(id).cloned())
    }

    fn get_tests_for_entity(
        &self,
        id: &EntityId,
    ) -> Result<Vec<TestCase>, KinDbError> {
        let inner = self.inner.read();
        let test_ids: Vec<TestId> = inner
            .test_covers_entity
            .iter()
            .filter_map(|(tid, eid)| if eid == id { Some(*tid) } else { None })
            .collect();
        let results = test_ids
            .iter()
            .filter_map(|tid| inner.test_cases.get(tid).cloned())
            .collect();
        Ok(results)
    }

    fn delete_test_case(&self, id: &TestId) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        inner.test_cases.remove(id);
        inner.test_covers_entity.retain(|(tid, _)| tid != id);
        inner.test_covers_contract.retain(|(tid, _)| tid != id);
        inner.test_verifies_work.retain(|(tid, _)| tid != id);
        inner.mock_hints.retain(|h| h.test_id != *id);
        Ok(())
    }

    fn create_assertion(&self, assertion: &Assertion) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        inner
            .assertions
            .insert(assertion.assertion_id, assertion.clone());
        Ok(())
    }

    fn get_assertion(
        &self,
        id: &AssertionId,
    ) -> Result<Option<Assertion>, KinDbError> {
        Ok(self.inner.read().assertions.get(id).cloned())
    }

    fn get_coverage_summary(&self) -> Result<CoverageSummary, KinDbError> {
        let inner = self.inner.read();
        let total = inner.entities.len();
        let covered_ids: std::collections::HashSet<EntityId> = inner
            .test_covers_entity
            .iter()
            .map(|(_, eid)| *eid)
            .collect();
        let covered = covered_ids.len();
        let ratio = if total > 0 {
            covered as f64 / total as f64
        } else {
            0.0
        };
        let missing: Vec<EntityId> = inner
            .entities
            .keys()
            .filter(|id| !covered_ids.contains(id))
            .copied()
            .collect();
        Ok(CoverageSummary {
            total_entities: total,
            covered_entities: covered,
            coverage_ratio: ratio,
            missing_proof: missing,
        })
    }

    // -----------------------------------------------------------------------
    // Verification runs (Phase 9 completion)
    // -----------------------------------------------------------------------

    fn create_verification_run(&self, run: &VerificationRun) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        inner.verification_runs.insert(run.run_id, run.clone());
        Ok(())
    }

    fn get_verification_run(
        &self,
        id: &VerificationRunId,
    ) -> Result<Option<VerificationRun>, KinDbError> {
        Ok(self.inner.read().verification_runs.get(id).cloned())
    }

    fn list_runs_for_test(
        &self,
        test_id: &TestId,
    ) -> Result<Vec<VerificationRun>, KinDbError> {
        let inner = self.inner.read();
        let results = inner
            .verification_runs
            .values()
            .filter(|run| run.test_ids.contains(test_id))
            .cloned()
            .collect();
        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Test ↔ scope linking (Phase 9 completion)
    // -----------------------------------------------------------------------

    fn create_test_covers_entity(
        &self,
        test_id: &TestId,
        entity_id: &EntityId,
    ) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        let pair = (*test_id, *entity_id);
        if !inner.test_covers_entity.contains(&pair) {
            inner.test_covers_entity.push(pair);
        }
        Ok(())
    }

    fn create_test_covers_contract(
        &self,
        test_id: &TestId,
        contract_id: &ContractId,
    ) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        let pair = (*test_id, *contract_id);
        if !inner.test_covers_contract.contains(&pair) {
            inner.test_covers_contract.push(pair);
        }
        Ok(())
    }

    fn create_test_verifies_work(
        &self,
        test_id: &TestId,
        work_id: &WorkId,
    ) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        let pair = (*test_id, *work_id);
        if !inner.test_verifies_work.contains(&pair) {
            inner.test_verifies_work.push(pair);
        }
        Ok(())
    }

    fn get_tests_covering_contract(
        &self,
        contract_id: &ContractId,
    ) -> Result<Vec<TestCase>, KinDbError> {
        let inner = self.inner.read();
        let test_ids: Vec<TestId> = inner
            .test_covers_contract
            .iter()
            .filter_map(|(tid, cid)| {
                if cid == contract_id {
                    Some(*tid)
                } else {
                    None
                }
            })
            .collect();
        let results = test_ids
            .iter()
            .filter_map(|tid| inner.test_cases.get(tid).cloned())
            .collect();
        Ok(results)
    }

    fn get_tests_verifying_work(
        &self,
        work_id: &WorkId,
    ) -> Result<Vec<TestCase>, KinDbError> {
        let inner = self.inner.read();
        let test_ids: Vec<TestId> = inner
            .test_verifies_work
            .iter()
            .filter_map(|(tid, wid)| {
                if wid == work_id {
                    Some(*tid)
                } else {
                    None
                }
            })
            .collect();
        let results = test_ids
            .iter()
            .filter_map(|tid| inner.test_cases.get(tid).cloned())
            .collect();
        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Mock hints (Phase 9 completion)
    // -----------------------------------------------------------------------

    fn create_mock_hint(&self, hint: &MockHint) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        inner.mock_hints.push(hint.clone());
        Ok(())
    }

    fn get_mock_hints_for_test(
        &self,
        test_id: &TestId,
    ) -> Result<Vec<MockHint>, KinDbError> {
        let inner = self.inner.read();
        let results = inner
            .mock_hints
            .iter()
            .filter(|h| h.test_id == *test_id)
            .cloned()
            .collect();
        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Verification run → proof links (Phase 9 completion)
    // -----------------------------------------------------------------------

    fn link_run_proves_entity(
        &self,
        run_id: &VerificationRunId,
        entity_id: &EntityId,
    ) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        let pair = (*run_id, *entity_id);
        if !inner.run_proves_entity.contains(&pair) {
            inner.run_proves_entity.push(pair);
        }
        Ok(())
    }

    fn link_run_proves_work(
        &self,
        run_id: &VerificationRunId,
        work_id: &WorkId,
    ) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        let pair = (*run_id, *work_id);
        if !inner.run_proves_work.contains(&pair) {
            inner.run_proves_work.push(pair);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Contract CRUD
    // -----------------------------------------------------------------------

    fn create_contract(&self, contract: &Contract) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        // Contract uses EntityId for its `id` field but the trait keys by ContractId.
        // We derive a ContractId from the contract's EntityId for storage.
        let key = ContractId(contract.id.0);
        inner.contracts.insert(key, contract.clone());
        Ok(())
    }

    fn get_contract(
        &self,
        id: &ContractId,
    ) -> Result<Option<Contract>, KinDbError> {
        Ok(self.inner.read().contracts.get(id).cloned())
    }

    fn list_contracts(&self) -> Result<Vec<Contract>, KinDbError> {
        Ok(self.inner.read().contracts.values().cloned().collect())
    }

    // -----------------------------------------------------------------------
    // Contract coverage (Phase 9 completion)
    // -----------------------------------------------------------------------

    fn get_contract_coverage_summary(&self) -> Result<ContractCoverageSummary, KinDbError> {
        let inner = self.inner.read();
        let total = inner.contracts.len();
        let covered_ids: std::collections::HashSet<ContractId> = inner
            .test_covers_contract
            .iter()
            .map(|(_, cid)| *cid)
            .collect();
        let covered = inner
            .contracts
            .keys()
            .filter(|cid| covered_ids.contains(cid))
            .count();
        let ratio = if total > 0 {
            covered as f64 / total as f64
        } else {
            0.0
        };
        let uncovered: Vec<ContractId> = inner
            .contracts
            .keys()
            .filter(|cid| !covered_ids.contains(cid))
            .copied()
            .collect();
        Ok(ContractCoverageSummary {
            total_contracts: total,
            covered_contracts: covered,
            coverage_ratio: ratio,
            uncovered_contract_ids: uncovered,
        })
    }

    // -----------------------------------------------------------------------
    // Provenance operations (Phase 10)
    // -----------------------------------------------------------------------

    fn create_actor(&self, actor: &Actor) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        inner.actors.insert(actor.actor_id, actor.clone());
        Ok(())
    }

    fn get_actor(&self, id: &ActorId) -> Result<Option<Actor>, KinDbError> {
        Ok(self.inner.read().actors.get(id).cloned())
    }

    fn list_actors(&self) -> Result<Vec<Actor>, KinDbError> {
        Ok(self.inner.read().actors.values().cloned().collect())
    }

    fn create_delegation(&self, delegation: &Delegation) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        inner.delegations.push(delegation.clone());
        Ok(())
    }

    fn get_delegations_for_actor(
        &self,
        id: &ActorId,
    ) -> Result<Vec<Delegation>, KinDbError> {
        let inner = self.inner.read();
        let results = inner
            .delegations
            .iter()
            .filter(|d| d.principal == *id || d.delegate == *id)
            .cloned()
            .collect();
        Ok(results)
    }

    fn create_approval(&self, approval: &Approval) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        inner.approvals.push(approval.clone());
        Ok(())
    }

    fn get_approvals_for_change(
        &self,
        id: &SemanticChangeId,
    ) -> Result<Vec<Approval>, KinDbError> {
        let inner = self.inner.read();
        let results = inner
            .approvals
            .iter()
            .filter(|a| a.change_id == *id)
            .cloned()
            .collect();
        Ok(results)
    }

    fn record_audit_event(&self, event: &AuditEvent) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        inner.audit_events.push(event.clone());
        Ok(())
    }

    fn query_audit_events(
        &self,
        actor_id: Option<&ActorId>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, KinDbError> {
        let inner = self.inner.read();
        let results: Vec<AuditEvent> = inner
            .audit_events
            .iter()
            .rev()
            .filter(|e| {
                if let Some(aid) = actor_id {
                    e.actor_id == *aid
                } else {
                    true
                }
            })
            .take(limit)
            .cloned()
            .collect();
        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Shallow file tracking (C2 tier)
    // -----------------------------------------------------------------------

    fn upsert_shallow_file(&self, shallow: &ShallowTrackedFile) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        // Replace existing entry for same file_id
        inner
            .shallow_files
            .retain(|sf| sf.file_id != shallow.file_id);
        inner.shallow_files.push(shallow.clone());
        Ok(())
    }

    fn list_shallow_files(&self) -> Result<Vec<ShallowTrackedFile>, KinDbError> {
        Ok(self.inner.read().shallow_files.clone())
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
        } else if !name.contains(&pat) {
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
            name: BranchName::new("main"),
            head: change_id,
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

    #[test]
    fn work_item_crud() {
        let graph = InMemoryGraph::new();
        let item = WorkItem {
            work_id: WorkId::new(),
            kind: WorkKind::Feature,
            title: "Add login".into(),
            description: "OAuth login".into(),
            status: WorkStatus::Proposed,
            priority: Priority::High,
            scopes: vec![],
            acceptance_criteria: vec![],
            external_refs: vec![],
            created_by: IdentityRef::human("alice"),
            created_at: Timestamp::now(),
        };
        let id = item.work_id;

        graph.create_work_item(&item).unwrap();
        let fetched = graph.get_work_item(&id).unwrap().unwrap();
        assert_eq!(fetched.title, "Add login");

        graph
            .update_work_status(&id, WorkStatus::InProgress)
            .unwrap();
        let updated = graph.get_work_item(&id).unwrap().unwrap();
        assert_eq!(updated.status, WorkStatus::InProgress);

        graph.delete_work_item(&id).unwrap();
        assert!(graph.get_work_item(&id).unwrap().is_none());
    }

    #[test]
    fn annotation_crud() {
        let graph = InMemoryGraph::new();
        let ann = Annotation {
            annotation_id: AnnotationId::new(),
            kind: AnnotationKind::Warning,
            body: "Deprecated API".into(),
            scopes: vec![],
            anchored_fingerprint: None,
            authored_by: IdentityRef::human("bob"),
            created_at: Timestamp::now(),
            staleness: StalenessState::Fresh,
        };
        let id = ann.annotation_id;

        graph.create_annotation(&ann).unwrap();
        let fetched = graph.get_annotation(&id).unwrap().unwrap();
        assert_eq!(fetched.body, "Deprecated API");

        graph
            .update_annotation_staleness(&id, StalenessState::Stale)
            .unwrap();
        let updated = graph.get_annotation(&id).unwrap().unwrap();
        assert_eq!(updated.staleness, StalenessState::Stale);

        graph.delete_annotation(&id).unwrap();
        assert!(graph.get_annotation(&id).unwrap().is_none());
    }

    #[test]
    fn test_case_and_coverage() {
        let graph = InMemoryGraph::new();
        let entity = test_entity("target_fn", "src/lib.rs");
        let eid = entity.id;
        graph.upsert_entity(&entity).unwrap();

        let tc = TestCase {
            test_id: TestId::new(),
            name: "test_target".into(),
            language: "rust".into(),
            kind: TestKind::Unit,
            scopes: vec![],
            runner: TestRunner::Cargo,
            file_origin: None,
        };
        let tid = tc.test_id;

        graph.create_test_case(&tc).unwrap();
        graph.create_test_covers_entity(&tid, &eid).unwrap();

        let tests = graph.get_tests_for_entity(&eid).unwrap();
        assert_eq!(tests.len(), 1);

        let summary = graph.get_coverage_summary().unwrap();
        assert_eq!(summary.total_entities, 1);
        assert_eq!(summary.covered_entities, 1);
    }

    #[test]
    fn actor_and_audit() {
        let graph = InMemoryGraph::new();
        let actor = Actor {
            actor_id: ActorId::new(),
            kind: ActorKind::Human,
            display_name: "Alice".into(),
            external_refs: vec![],
        };
        let aid = actor.actor_id;

        graph.create_actor(&actor).unwrap();
        let fetched = graph.get_actor(&aid).unwrap().unwrap();
        assert_eq!(fetched.display_name, "Alice");

        let event = AuditEvent {
            event_id: AuditEventId::new(),
            actor_id: aid,
            action: "commit".into(),
            target_scope: None,
            timestamp: Timestamp::now(),
            details: None,
        };
        graph.record_audit_event(&event).unwrap();

        let events = graph.query_audit_events(Some(&aid), 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "commit");
    }

    #[test]
    fn shallow_file_tracking() {
        let graph = InMemoryGraph::new();
        let sf = ShallowTrackedFile {
            file_id: FilePathId::new("lib.c"),
            language_hint: "c".into(),
            declaration_count: 5,
            import_count: 3,
            syntax_hash: Hash256::from_bytes([0xaa; 32]),
            signature_hash: None,
        };

        graph.upsert_shallow_file(&sf).unwrap();
        let files = graph.list_shallow_files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].declaration_count, 5);

        // Upsert replaces
        let sf2 = ShallowTrackedFile {
            declaration_count: 10,
            ..sf.clone()
        };
        graph.upsert_shallow_file(&sf2).unwrap();
        let files = graph.list_shallow_files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].declaration_count, 10);
    }
}
