// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Project semantic relation authority from the same graph snapshot as its endpoints.
//!
//! Older stores can contain inferred members with parser-certain edges. Reading
//! those edges must not upgrade a candidate while waiting for re-admission. This
//! view leaves the persisted evidence and history intact; it changes only the
//! returned copies used for semantic answers, counts and rankings.

use std::collections::HashMap;

use kin_model::{Entity, EntityId, EntityStore, Relation, RelationKind, RepoPath};

/// Apply the derived-member trust floor before filtering, composing or scoring edges.
/// Endpoint reads are cached within this batch and errors propagate to the caller.
pub fn project_relations_for_read<S: EntityStore + ?Sized>(
    store: &S,
    relations: &mut Vec<Relation>,
) -> Result<(), S::Error> {
    let mut entities: HashMap<EntityId, Option<Entity>> = HashMap::new();
    for relation in relations.iter() {
        for id in [relation.src.as_entity(), relation.dst.as_entity()]
            .into_iter()
            .flatten()
        {
            if let std::collections::hash_map::Entry::Vacant(entry) = entities.entry(id) {
                entry.insert(store.get_entity(&id)?);
            }
        }
    }
    let mut projected = Vec::with_capacity(relations.len());
    for mut relation in relations.drain(..) {
        let endpoint = |id: Option<EntityId>| id.and_then(|id| entities.get(&id)?.as_ref());
        let source = endpoint(relation.src.as_entity());
        let destination = endpoint(relation.dst.as_entity());
        let derived = source.is_some_and(kin_model::is_derived_member)
            || destination.is_some_and(kin_model::is_derived_member)
            || crate::resolution::is_derived_member_candidate(&relation);
        if !derived {
            projected.push(relation);
            continue;
        }
        if relation.src.as_entity().is_some() && relation.dst.as_entity().is_some() {
            if project_entity_relation_for_read(&mut relation, true) {
                projected.push(relation);
            }
            continue;
        }
        // A generator edge proves its source site, not runtime member membership.
        // Preserve that distinct authority only when the recorded graph artifact,
        // current source digest and exact generator site agree.
        let mut valid_generator = false;
        if relation.kind == RelationKind::DerivedFrom {
            if let Some(entity) = source {
                if let Ok(Some(derivation)) = kin_model::entity_derivation(entity) {
                    if let Ok(path) = RepoPath::from_utf8(derivation.generator.file.0.clone()) {
                        if let (Some(artifact), Some(kin_model::TreeEntry::Blob { hash, .. })) = (
                            store.artifact_id_at_path(&path),
                            store.get_tree_entry(&derivation.generator.file)?,
                        ) {
                            valid_generator = kin_model::derivation::generator_relation_matches(
                                entity,
                                &relation,
                                artifact,
                                &hash.to_string(),
                            );
                        }
                    }
                }
            }
        }
        if !valid_generator {
            crate::resolution::limit_derived_relation(&mut relation);
        }
        projected.push(relation);
    }
    *relations = projected;
    Ok(())
}

/// Apply the same trust floor to entity-only adjacency from a historical view.
/// The caller supplies endpoint classification from that ref, including removed
/// endpoint tombstones. Artifact provenance requires the separate validation above.
pub fn project_entity_relation_for_read(relation: &mut Relation, derived_endpoint: bool) -> bool {
    if (!derived_endpoint && !crate::resolution::is_derived_member_candidate(relation))
        || relation.src.as_entity().is_none()
        || relation.dst.as_entity().is_none()
    {
        return true;
    }
    if relation.kind == RelationKind::Overrides {
        return false;
    }
    crate::resolution::limit_derived_relation(relation);
    true
}

/// Read entity relations with endpoint authority applied before any consumer logic.
pub fn relations_for_read<S: EntityStore + ?Sized>(
    store: &S,
    id: &EntityId,
) -> Result<Vec<Relation>, S::Error> {
    let mut relations = store.get_all_relations_for_entity(id)?;
    project_relations_for_read(store, &mut relations)?;
    Ok(relations)
}
