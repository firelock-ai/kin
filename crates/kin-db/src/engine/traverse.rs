use hashbrown::{HashMap, HashSet};
use rayon::prelude::*;
use std::collections::VecDeque;

use crate::types::*;

/// BFS from `start` following outgoing edges up to `max_depth`.
/// Returns (entities, relations) in the neighborhood.
pub fn bfs_neighborhood(
    start: &EntityId,
    max_depth: u32,
    entities: &HashMap<EntityId, Entity>,
    relations: &HashMap<RelationId, Relation>,
    outgoing: &HashMap<EntityId, Vec<RelationId>>,
) -> SubGraph {
    let mut visited: HashSet<EntityId> = HashSet::new();
    let mut result_entities: HashMap<EntityId, Entity> = HashMap::new();
    let mut result_relations: Vec<Relation> = Vec::new();
    let mut queue: VecDeque<(EntityId, u32)> = VecDeque::new();

    if let Some(entity) = entities.get(start) {
        visited.insert(*start);
        result_entities.insert(*start, entity.clone());
        queue.push_back((*start, 0));
    }

    while let Some((current, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }

        if let Some(edge_ids) = outgoing.get(&current) {
            for rid in edge_ids {
                if let Some(rel) = relations.get(rid) {
                    result_relations.push(rel.clone());

                    let neighbor = rel.dst;
                    if !visited.contains(&neighbor) {
                        visited.insert(neighbor);
                        if let Some(entity) = entities.get(&neighbor) {
                            result_entities.insert(neighbor, entity.clone());
                        }
                        queue.push_back((neighbor, depth + 1));
                    }
                }
            }
        }
    }

    // Convert to std HashMap for SubGraph
    SubGraph {
        entities: result_entities.into_iter().collect(),
        relations: result_relations,
    }
}

/// BFS from `start` following INCOMING edges up to `max_depth`.
/// Returns all entities that transitively depend on `start`.
pub fn downstream_impact(
    start: &EntityId,
    max_depth: u32,
    entities: &HashMap<EntityId, Entity>,
    incoming: &HashMap<EntityId, Vec<RelationId>>,
    relations: &HashMap<RelationId, Relation>,
) -> Vec<Entity> {
    let mut visited: HashSet<EntityId> = HashSet::new();
    let mut impacted_ids: Vec<EntityId> = Vec::new();
    let mut queue: VecDeque<(EntityId, u32)> = VecDeque::new();

    visited.insert(*start);
    queue.push_back((*start, 0));

    while let Some((current, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }

        if let Some(edge_ids) = incoming.get(&current) {
            for rid in edge_ids {
                if let Some(rel) = relations.get(rid) {
                    let caller = rel.src;
                    if !visited.contains(&caller) {
                        visited.insert(caller);
                        impacted_ids.push(caller);
                        queue.push_back((caller, depth + 1));
                    }
                }
            }
        }
    }

    // Parallel entity collection from the discovered IDs
    impacted_ids
        .par_iter()
        .filter_map(|id| entities.get(id).cloned())
        .collect()
}

/// Find entities with zero incoming relations from other files.
/// These are potential dead code (unreferenced from outside their file).
pub fn find_dead_code(
    entities: &HashMap<EntityId, Entity>,
    incoming: &HashMap<EntityId, Vec<RelationId>>,
    relations: &HashMap<RelationId, Relation>,
) -> Vec<Entity> {
    entities
        .par_iter()
        .filter(|(id, entity)| {
            // Skip non-addressable kinds
            matches!(
                entity.kind,
                EntityKind::Function
                    | EntityKind::Method
                    | EntityKind::Class
                    | EntityKind::Interface
                    | EntityKind::TraitDef
                    | EntityKind::TypeAlias
                    | EntityKind::EnumDef
                    | EntityKind::Constant
                    | EntityKind::StaticVar
            ) && !has_cross_file_incoming(id, entity, incoming, relations, entities)
        })
        .map(|(_, entity)| entity.clone())
        .collect()
}

/// Check if an entity has any incoming relation from a different file.
fn has_cross_file_incoming(
    id: &EntityId,
    entity: &Entity,
    incoming: &HashMap<EntityId, Vec<RelationId>>,
    relations: &HashMap<RelationId, Relation>,
    entities: &HashMap<EntityId, Entity>,
) -> bool {
    let Some(edge_ids) = incoming.get(id) else {
        return false;
    };

    for rid in edge_ids {
        if let Some(rel) = relations.get(rid) {
            if let Some(src_entity) = entities.get(&rel.src) {
                // Different file = cross-file reference
                if src_entity.file_origin != entity.file_origin {
                    return true;
                }
            }
        }
    }

    false
}

/// Check if entity has incoming relations of specific kinds, optionally
/// excluding same-file relations.
pub fn has_incoming_of_kinds(
    id: &EntityId,
    entity: &Entity,
    kinds: &[RelationKind],
    exclude_same_file: bool,
    incoming: &HashMap<EntityId, Vec<RelationId>>,
    relations: &HashMap<RelationId, Relation>,
    entities: &HashMap<EntityId, Entity>,
) -> bool {
    let Some(edge_ids) = incoming.get(id) else {
        return false;
    };

    for rid in edge_ids {
        if let Some(rel) = relations.get(rid) {
            if !kinds.contains(&rel.kind) {
                continue;
            }
            if exclude_same_file {
                if let Some(src_entity) = entities.get(&rel.src) {
                    if src_entity.file_origin == entity.file_origin {
                        continue;
                    }
                }
            }
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entity(id: EntityId, name: &str, file: &str) -> Entity {
        Entity {
            id,
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

    fn make_relation(id: RelationId, src: EntityId, dst: EntityId, kind: RelationKind) -> Relation {
        Relation {
            id,
            kind,
            src,
            dst,
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
        }
    }

    #[test]
    fn bfs_neighborhood_basic() {
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let e3 = EntityId::new();
        let r1 = RelationId::new();
        let r2 = RelationId::new();

        let mut entities = HashMap::new();
        entities.insert(e1, make_entity(e1, "a", "a.rs"));
        entities.insert(e2, make_entity(e2, "b", "b.rs"));
        entities.insert(e3, make_entity(e3, "c", "c.rs"));

        let mut rels = HashMap::new();
        rels.insert(r1, make_relation(r1, e1, e2, RelationKind::Calls));
        rels.insert(r2, make_relation(r2, e2, e3, RelationKind::Calls));

        let mut outgoing: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        outgoing.entry(e1).or_default().push(r1);
        outgoing.entry(e2).or_default().push(r2);

        // Depth 1: should get e1, e2 but not e3
        let sg = bfs_neighborhood(&e1, 1, &entities, &rels, &outgoing);
        assert!(sg.entities.contains_key(&e1));
        assert!(sg.entities.contains_key(&e2));
        assert!(!sg.entities.contains_key(&e3));

        // Depth 2: should get all three
        let sg = bfs_neighborhood(&e1, 2, &entities, &rels, &outgoing);
        assert_eq!(sg.entities.len(), 3);
    }

    #[test]
    fn downstream_impact_basic() {
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let r1 = RelationId::new();

        let mut entities = HashMap::new();
        entities.insert(e1, make_entity(e1, "a", "a.rs"));
        entities.insert(e2, make_entity(e2, "b", "b.rs"));

        let mut rels = HashMap::new();
        // e2 calls e1 => e2 is an incoming edge on e1
        rels.insert(r1, make_relation(r1, e2, e1, RelationKind::Calls));

        let mut incoming: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        incoming.entry(e1).or_default().push(r1);

        let impact = downstream_impact(&e1, 10, &entities, &incoming, &rels);
        assert_eq!(impact.len(), 1);
        assert_eq!(impact[0].id, e2);
    }

    #[test]
    fn dead_code_detection() {
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let r1 = RelationId::new();

        let mut entities = HashMap::new();
        entities.insert(e1, make_entity(e1, "used_fn", "a.rs"));
        entities.insert(e2, make_entity(e2, "unused_fn", "b.rs"));

        let mut rels = HashMap::new();
        // e_other calls e1 from a different file
        let e_other = EntityId::new();
        entities.insert(e_other, make_entity(e_other, "caller", "c.rs"));
        rels.insert(r1, make_relation(r1, e_other, e1, RelationKind::Calls));

        let mut incoming: HashMap<EntityId, Vec<RelationId>> = HashMap::new();
        incoming.entry(e1).or_default().push(r1);

        let dead = find_dead_code(&entities, &incoming, &rels);
        // e2 and e_other have no cross-file incoming refs, but e1 does
        let dead_ids: Vec<EntityId> = dead.iter().map(|e| e.id).collect();
        assert!(dead_ids.contains(&e2));
        assert!(dead_ids.contains(&e_other));
        assert!(!dead_ids.contains(&e1));
    }
}
