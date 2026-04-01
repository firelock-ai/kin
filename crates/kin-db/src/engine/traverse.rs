// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

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

                    let Some(neighbor) = rel.dst.as_entity() else {
                        continue;
                    };
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
        nodes: result_entities
            .keys()
            .copied()
            .map(GraphNodeId::Entity)
            .collect(),
        entities: result_entities.into_iter().collect(),
        relations: result_relations,
    }
}

/// BFS from multiple seeds following both incoming and outgoing edges of
/// specific kinds up to `max_depth`.
pub fn expand_neighborhood(
    starts: &[EntityId],
    edge_kinds: &[RelationKind],
    max_depth: u32,
    entities: &HashMap<EntityId, Entity>,
    relations: &HashMap<RelationId, Relation>,
    outgoing: &HashMap<EntityId, Vec<RelationId>>,
    incoming: &HashMap<EntityId, Vec<RelationId>>,
) -> SubGraph {
    let mut visited: HashSet<EntityId> = HashSet::new();
    let mut seen_relations: HashSet<RelationId> = HashSet::new();
    let mut result_entities: HashMap<EntityId, Entity> = HashMap::new();
    let mut result_relations: Vec<Relation> = Vec::new();
    let mut queue: VecDeque<(EntityId, u32)> = VecDeque::new();
    let filter_all = edge_kinds.is_empty();

    for start in starts {
        if let Some(entity) = entities.get(start) {
            if visited.insert(*start) {
                result_entities.insert(*start, entity.clone());
                queue.push_back((*start, 0));
            }
        }
    }

    while let Some((current, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }

        for edge_ids in [outgoing.get(&current), incoming.get(&current)] {
            let Some(edge_ids) = edge_ids else {
                continue;
            };
            for rid in edge_ids {
                let Some(rel) = relations.get(rid) else {
                    continue;
                };
                if !filter_all && !edge_kinds.contains(&rel.kind) {
                    continue;
                }
                if seen_relations.insert(rel.id) {
                    result_relations.push(rel.clone());
                }

                let current_node = GraphNodeId::Entity(current);
                let neighbor = if rel.src == current_node {
                    rel.dst.as_entity()
                } else if rel.dst == current_node {
                    rel.src.as_entity()
                } else {
                    None
                };
                let Some(neighbor) = neighbor else {
                    continue;
                };

                if visited.insert(neighbor) {
                    if let Some(entity) = entities.get(&neighbor) {
                        result_entities.insert(neighbor, entity.clone());
                    }
                    queue.push_back((neighbor, depth + 1));
                }
            }
        }
    }

    SubGraph {
        nodes: result_entities
            .keys()
            .copied()
            .map(GraphNodeId::Entity)
            .collect(),
        entities: result_entities.into_iter().collect(),
        relations: result_relations,
    }
}

/// BFS from a typed start node following both incoming and outgoing edges.
pub fn traverse(
    start: &GraphNodeId,
    edge_kinds: &[RelationKind],
    max_depth: u32,
    entities: &HashMap<EntityId, Entity>,
    relations: &HashMap<RelationId, Relation>,
    outgoing: &HashMap<GraphNodeId, Vec<RelationId>>,
    incoming: &HashMap<GraphNodeId, Vec<RelationId>>,
) -> SubGraph {
    let mut visited: HashSet<GraphNodeId> = HashSet::new();
    let mut seen_relations: HashSet<RelationId> = HashSet::new();
    let mut result_nodes = Vec::new();
    let mut result_entities: HashMap<EntityId, Entity> = HashMap::new();
    let mut result_relations = Vec::new();
    let mut queue: VecDeque<(GraphNodeId, u32)> = VecDeque::new();
    let filter_all = edge_kinds.is_empty();

    visited.insert(*start);
    result_nodes.push(*start);
    if let Some(entity_id) = start.as_entity() {
        if let Some(entity) = entities.get(&entity_id) {
            result_entities.insert(entity_id, entity.clone());
        }
    }
    queue.push_back((*start, 0));

    while let Some((current, depth)) = queue.pop_front() {
        if depth >= max_depth {
            continue;
        }

        for edge_ids in [outgoing.get(&current), incoming.get(&current)] {
            let Some(edge_ids) = edge_ids else {
                continue;
            };

            for rid in edge_ids {
                let Some(rel) = relations.get(rid) else {
                    continue;
                };
                if !filter_all && !edge_kinds.contains(&rel.kind) {
                    continue;
                }
                if seen_relations.insert(rel.id) {
                    result_relations.push(rel.clone());
                }

                let neighbor = if rel.src == current {
                    rel.dst
                } else if rel.dst == current {
                    rel.src
                } else {
                    continue;
                };

                if visited.insert(neighbor) {
                    result_nodes.push(neighbor);
                    if let Some(entity_id) = neighbor.as_entity() {
                        if let Some(entity) = entities.get(&entity_id) {
                            result_entities.insert(entity_id, entity.clone());
                        }
                    }
                    queue.push_back((neighbor, depth + 1));
                }
            }
        }
    }

    SubGraph {
        nodes: result_nodes,
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
                    let Some(caller) = rel.src.as_entity() else {
                        continue;
                    };
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

/// Find production entities with zero incoming relations from other files.
/// These are potential unreferenced entities, not a guarantee of semantic dead code.
pub fn find_dead_code(
    entities: &HashMap<EntityId, Entity>,
    incoming: &HashMap<EntityId, Vec<RelationId>>,
    relations: &HashMap<RelationId, Relation>,
) -> Vec<Entity> {
    entities
        .par_iter()
        .filter(|(id, entity)| {
            is_dead_code_candidate(entity)
                && !has_cross_file_incoming(id, entity, incoming, relations, entities)
        })
        .map(|(_, entity)| entity.clone())
        .collect()
}

fn is_dead_code_candidate(entity: &Entity) -> bool {
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
    ) && !matches!(entity.kind, EntityKind::Test)
        && !is_nonproduction_path(entity.file_origin.as_ref())
        && !is_runtime_magic_method(entity)
}

fn is_nonproduction_path(file_origin: Option<&FilePathId>) -> bool {
    let Some(file_origin) = file_origin else {
        return false;
    };

    let normalized = file_origin.0.to_ascii_lowercase().replace('\\', "/");
    let file_name = normalized.rsplit('/').next().unwrap_or(&normalized);

    file_name == "conftest.py"
        || file_name.starts_with("test_")
        || file_name.ends_with("_test.py")
        || file_name.ends_with("_test.rs")
        || file_name.ends_with("_test.go")
        || file_name.ends_with(".spec.ts")
        || file_name.ends_with(".spec.tsx")
        || file_name.ends_with(".spec.js")
        || file_name.ends_with(".spec.jsx")
        || normalized.contains("/test/")
        || normalized.contains("/tests/")
        || normalized.contains("/testing/")
        || normalized.starts_with("test/")
        || normalized.starts_with("tests/")
        || normalized.starts_with("testing/")
        || normalized.contains("/example/")
        || normalized.contains("/examples/")
        || normalized.starts_with("example/")
        || normalized.starts_with("examples/")
        || normalized.contains("/bench/")
        || normalized.contains("/benches/")
        || normalized.contains("/benchmark/")
        || normalized.contains("/benchmarks/")
        || normalized.starts_with("bench/")
        || normalized.starts_with("benches/")
        || normalized.starts_with("benchmark/")
        || normalized.starts_with("benchmarks/")
}

fn is_runtime_magic_method(entity: &Entity) -> bool {
    if entity.kind != EntityKind::Method {
        return false;
    }

    let leaf = entity.name.rsplit('.').next().unwrap_or(&entity.name);
    leaf.starts_with("__") && leaf.ends_with("__")
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
            let Some(src_id) = rel.src.as_entity() else {
                continue;
            };
            if let Some(src_entity) = entities.get(&src_id) {
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
                let Some(src_id) = rel.src.as_entity() else {
                    continue;
                };
                if let Some(src_entity) = entities.get(&src_id) {
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
            role: EntityRole::Source,
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
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
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

    #[test]
    fn dead_code_skips_test_and_example_paths() {
        let prod = EntityId::new();
        let test_file = EntityId::new();
        let example_file = EntityId::new();

        let mut entities = HashMap::new();
        entities.insert(prod, make_entity(prod, "prod_fn", "src/lib.rs"));
        entities.insert(
            test_file,
            make_entity(test_file, "test_helper", "tests/test_lib.py"),
        );
        entities.insert(
            example_file,
            make_entity(example_file, "demo_helper", "examples/demo.py"),
        );

        let dead = find_dead_code(&entities, &HashMap::new(), &HashMap::new());
        let dead_ids: Vec<EntityId> = dead.iter().map(|entity| entity.id).collect();
        assert!(dead_ids.contains(&prod));
        assert!(!dead_ids.contains(&test_file));
        assert!(!dead_ids.contains(&example_file));
    }

    #[test]
    fn dead_code_skips_runtime_magic_methods() {
        let magic = EntityId::new();
        let normal = EntityId::new();

        let mut entities = HashMap::new();
        let mut magic_entity = make_entity(magic, "ConfigAttribute.__get__", "src/config.py");
        magic_entity.kind = EntityKind::Method;
        let mut normal_entity = make_entity(normal, "ConfigAttribute.resolve", "src/config.py");
        normal_entity.kind = EntityKind::Method;
        entities.insert(magic, magic_entity);
        entities.insert(normal, normal_entity);

        let dead = find_dead_code(&entities, &HashMap::new(), &HashMap::new());
        let dead_ids: Vec<EntityId> = dead.iter().map(|entity| entity.id).collect();
        assert!(!dead_ids.contains(&magic));
        assert!(dead_ids.contains(&normal));
    }
}
