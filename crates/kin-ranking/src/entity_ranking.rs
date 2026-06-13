// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared entity ranking primitives used by CLI, MCP, and other surfaces.
//!
//! These functions provide a single source of truth for how entities are
//! ranked when disambiguating search results, selecting reference targets,
//! and ordering relation kinds.

use std::path::Path;

use kin_model::entity::{Entity, EntityKind, Visibility};
use kin_model::graph::GraphStore;
use kin_model::relation::RelationKind;

/// Rank declaration kinds for entity selection.
///
/// Higher values indicate more interesting entity kinds when multiple
/// entities match a query.
pub fn declaration_kind_rank(kind: &EntityKind) -> usize {
    match kind {
        EntityKind::Function
        | EntityKind::Method
        | EntityKind::Interface
        | EntityKind::TypeAlias => 3,
        EntityKind::Class | EntityKind::TraitDef | EntityKind::EnumDef => 2,
        EntityKind::Constant | EntityKind::StaticVar => 1,
        _ => 0,
    }
}

/// Rank relation kinds for display ordering.
///
/// Lower values appear first: imports before calls before references.
pub fn relation_kind_rank(kind: &RelationKind) -> usize {
    match kind {
        RelationKind::Imports => 0,
        RelationKind::Calls => 1,
        RelationKind::References => 2,
        _ => 3,
    }
}

/// The composite ranking key used to select the best entity match.
///
/// Compared via tuple ordering (higher = better):
/// 1. Exact name match
/// 2. Exported (public/internal)
/// 3. Declaration kind rank
/// 4. Direct call/import count (incoming)
/// 5. Total incoming reference count
/// 6. Has file origin
/// 7. Shorter name preferred (Reverse)
pub type EntityRankingKey = (
    bool,
    bool,
    usize,
    usize,
    usize,
    bool,
    std::cmp::Reverse<usize>,
);

/// Compute the ranking key for an entity given a query and its relations.
pub fn entity_ranking_key(
    entity: &Entity,
    query: &str,
    incoming_refs: usize,
    direct_signal: usize,
) -> EntityRankingKey {
    let exported = matches!(entity.visibility, Visibility::Public | Visibility::Internal);
    (
        entity.name == query,
        exported,
        declaration_kind_rank(&entity.kind),
        direct_signal,
        incoming_refs,
        entity.file_origin.is_some(),
        std::cmp::Reverse(entity.name.len()),
    )
}

/// Select the best entity match for a query from a graph store.
///
/// Queries the store by name pattern, then ranks all matches using
/// [`entity_ranking_key`] to pick the single best result.
pub fn select_best_entity<G: GraphStore>(
    store: &G,
    query: &str,
) -> std::result::Result<Option<Entity>, <G as GraphStore>::Error> {
    use kin_model::graph::EntityFilter;

    let matches = store.query_entities(&EntityFilter {
        name_pattern: Some(query.to_string()),
        ..Default::default()
    })?;
    if matches.is_empty() {
        return Ok(None);
    }

    let mut best: Option<(Entity, EntityRankingKey)> = None;

    for entity in matches {
        let relations = store.get_all_relations_for_entity(&entity.id)?;
        let incoming_refs = relations
            .iter()
            .filter(|rel| {
                rel.dst == kin_model::GraphNodeId::Entity(entity.id)
                    && matches!(
                        rel.kind,
                        RelationKind::Calls | RelationKind::Imports | RelationKind::References
                    )
            })
            .count();
        let direct_signal = relations
            .iter()
            .filter(|rel| {
                rel.dst == kin_model::GraphNodeId::Entity(entity.id)
                    && matches!(rel.kind, RelationKind::Calls | RelationKind::Imports)
            })
            .count();

        let score = entity_ranking_key(&entity, query, incoming_refs, direct_signal);
        if best
            .as_ref()
            .map(|(_, best_score)| score > *best_score)
            .unwrap_or(true)
        {
            best = Some((entity, score));
        }
    }

    Ok(best.map(|(entity, _)| entity))
}

/// Rank relation kinds for trace operations.
///
/// Higher values indicate more significant relations: Calls > Imports > References.
pub fn trace_relation_rank(kind: RelationKind) -> usize {
    match kind {
        RelationKind::Calls => 2,
        RelationKind::Imports => 1,
        RelationKind::References => 0,
        _ => 0,
    }
}

/// Extract the directory component of an entity's file origin.
pub fn entity_directory(entity: &Entity) -> Option<String> {
    entity
        .file_origin
        .as_ref()
        .and_then(|path| Path::new(path.0.as_str()).parent())
        .map(|dir| dir.to_string_lossy().into_owned())
}

/// Compute a composite score for trace callee selection.
///
/// Returns a tuple ordered by: relation rank, same directory,
/// declaration kind, has file origin, shorter name.
pub fn trace_callee_score(
    entity: &Entity,
    relation_kind: RelationKind,
    focal_dir: Option<&str>,
) -> (usize, bool, usize, bool, usize) {
    let same_dir = focal_dir
        .zip(entity_directory(entity).as_deref())
        .map(|(root, dir)| root == dir)
        .unwrap_or(false);
    (
        trace_relation_rank(relation_kind),
        same_dir,
        declaration_kind_rank(&entity.kind),
        entity.file_origin.is_some(),
        usize::MAX.saturating_sub(entity.name.len()),
    )
}

/// Compute a composite score for trace constant selection.
pub fn trace_constant_score(entity: &Entity, focal_dir: Option<&str>) -> (bool, bool, usize) {
    let same_dir = focal_dir
        .zip(entity_directory(entity).as_deref())
        .map(|(root, dir)| root == dir)
        .unwrap_or(false);
    (
        same_dir,
        entity.file_origin.is_some(),
        usize::MAX.saturating_sub(entity.name.len()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declaration_kind_rank_function_highest() {
        assert_eq!(declaration_kind_rank(&EntityKind::Function), 3);
        assert_eq!(declaration_kind_rank(&EntityKind::Method), 3);
    }

    #[test]
    fn declaration_kind_rank_class_middle() {
        assert_eq!(declaration_kind_rank(&EntityKind::Class), 2);
        assert_eq!(declaration_kind_rank(&EntityKind::TraitDef), 2);
    }

    #[test]
    fn declaration_kind_rank_constant_low() {
        assert_eq!(declaration_kind_rank(&EntityKind::Constant), 1);
        assert_eq!(declaration_kind_rank(&EntityKind::StaticVar), 1);
    }

    #[test]
    fn declaration_kind_rank_module_zero() {
        assert_eq!(declaration_kind_rank(&EntityKind::Module), 0);
    }

    #[test]
    fn relation_kind_rank_ordering() {
        assert!(
            relation_kind_rank(&RelationKind::Imports) < relation_kind_rank(&RelationKind::Calls)
        );
        assert!(
            relation_kind_rank(&RelationKind::Calls)
                < relation_kind_rank(&RelationKind::References)
        );
    }

    #[test]
    fn trace_relation_rank_ordering() {
        assert!(
            trace_relation_rank(RelationKind::Calls) > trace_relation_rank(RelationKind::Imports)
        );
        assert!(
            trace_relation_rank(RelationKind::Imports)
                > trace_relation_rank(RelationKind::References)
        );
    }
}
