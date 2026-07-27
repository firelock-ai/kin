// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Canonical semantic transitions between graph-owned workspace states.
//!
//! Exact repository membership is carried independently by tree deltas. This
//! module compares only live entity and relation authority so callers cannot
//! accidentally infer semantic state from files or parser availability.

use std::collections::{BTreeSet, HashMap};

use kin_model::{
    Entity, EntityDelta, EntityId, Relation, RelationDelta, RelationId, WorkspaceSemanticDelta,
};

/// Derive the exact incremental semantic transition from one workspace graph
/// to another.
///
/// The result is canonicalized and validated by [`WorkspaceSemanticDelta`].
/// Unsupported-language, configuration, binary, and other opaque artifacts
/// remain represented by the separate exact tree even when this delta is
/// empty.
pub fn diff_workspace_semantics(
    current_entities: &HashMap<EntityId, Entity>,
    current_relations: &HashMap<RelationId, Relation>,
    desired_entities: &HashMap<EntityId, Entity>,
    desired_relations: &HashMap<RelationId, Relation>,
) -> kin_model::Result<WorkspaceSemanticDelta> {
    let entity_deltas = current_entities
        .keys()
        .copied()
        .chain(desired_entities.keys().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|entity_id| {
            match (
                current_entities.get(&entity_id),
                desired_entities.get(&entity_id),
            ) {
                (None, Some(new)) => Some(EntityDelta::Added { new: new.clone() }),
                (Some(old), Some(new)) if old != new => Some(EntityDelta::Modified {
                    old: old.clone(),
                    new: new.clone(),
                }),
                (Some(old), None) => Some(EntityDelta::Removed { old: old.clone() }),
                (Some(_), Some(_)) | (None, None) => None,
            }
        })
        .collect();
    let relation_deltas = current_relations
        .keys()
        .copied()
        .chain(desired_relations.keys().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|relation_id| {
            match (
                current_relations.get(&relation_id),
                desired_relations.get(&relation_id),
            ) {
                (None, Some(new)) => Some(RelationDelta::Added { new: new.clone() }),
                (Some(old), Some(new)) if old != new => Some(RelationDelta::Modified {
                    old: old.clone(),
                    new: new.clone(),
                }),
                (Some(old), None) => Some(RelationDelta::Removed { old: old.clone() }),
                (Some(_), Some(_)) | (None, None) => None,
            }
        })
        .collect();

    WorkspaceSemanticDelta::new(entity_deltas, relation_deltas)
}
