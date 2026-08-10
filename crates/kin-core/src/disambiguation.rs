// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Entity disambiguation — resolving entity queries against the graph.
//!
//! These functions handle the multi-step lookup process: exact match,
//! qualified name match (with generic normalization), and leaf fallback.

use kin_model::{Entity, EntityFilter, GraphStore};

use crate::error::KinError;
use crate::ranking::normalize_symbol_hint;

/// Query the graph for entities matching a trace query.
///
/// Tries exact name match first, then falls back to qualified name matching
/// (e.g., `Router::route` matching `Router<S>::route`).
pub fn query_trace_matches(graph: &impl GraphStore, query: &str) -> Result<Vec<Entity>, KinError> {
    let filter = EntityFilter {
        name_pattern: Some(query.to_string()),
        ..Default::default()
    };
    let matches = graph
        .query_entities(&filter)
        .map_err(|e| KinError::Graph(e.to_string()))?;
    if !matches.is_empty() {
        return Ok(matches);
    }

    // Try qualified name matching: strip generics and match qualifier + leaf
    if let Some((qualifier, leaf)) = query.rsplit_once("::") {
        if leaf != query {
            let leaf_filter = EntityFilter {
                name_pattern: Some(leaf.to_string()),
                ..Default::default()
            };
            let leaf_matches = graph
                .query_entities(&leaf_filter)
                .map_err(|e| KinError::Graph(e.to_string()))?;
            if leaf_matches.is_empty() {
                return Ok(leaf_matches);
            }

            let qualifier_hint = normalize_symbol_hint(qualifier);
            let qualified_matches: Vec<_> = leaf_matches
                .iter()
                .filter(|entity| {
                    normalize_symbol_hint(&crate::ranking::normalize_trace_name(&entity.name))
                        .contains(&qualifier_hint)
                })
                .cloned()
                .collect();

            if !qualified_matches.is_empty() {
                return Ok(qualified_matches);
            }
        }
    }

    Ok(matches)
}

/// Whether the name index rules out every resolver match for `query`.
///
/// `find_references` and `trace_data_flow` both resolve a caller's name through
/// [`query_trace_matches`] and `kin_ranking::select_best_entity`, and both reach
/// that resolution only after their route has built the state the answer would
/// be read from: a detached graph snapshot with its merkle root recomputed, or a
/// whole-store repository-authority open. Both are linear in store size, and a
/// name that matches nothing pays all of it to conclude what one index lookup
/// already knew.
///
/// Answering `true` promises that both resolvers would miss, so every branch
/// that cannot promise it answers `false` and leaves the caller on the unchanged
/// path. An id, a name the index knows, or a qualified name whose leaf the index
/// knows are all "not certainly a miss" even where resolution would go on to
/// reject them for some other reason.
pub fn name_resolution_certainly_misses(
    graph: &impl GraphStore,
    query: &str,
) -> Result<bool, KinError> {
    let trimmed = query.trim();
    if trimmed.is_empty() || uuid::Uuid::parse_str(trimmed).is_ok() {
        return Ok(false);
    }
    if !name_index_rules_out(graph, trimmed)? {
        return Ok(false);
    }
    // `query_trace_matches` retries a qualified name against its leaf, so a leaf
    // the index knows keeps the caller on the resolving path.
    if let Some((_, leaf)) = trimmed.rsplit_once("::") {
        if leaf != trimmed && !name_index_rules_out(graph, leaf)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn name_index_rules_out(graph: &impl GraphStore, name: &str) -> Result<bool, KinError> {
    let filter = EntityFilter {
        name_pattern: Some(name.to_string()),
        ..Default::default()
    };
    graph
        .query_entities(&filter)
        .map(|matches| matches.is_empty())
        .map_err(|e| KinError::Graph(e.to_string()))
}

/// Fallback: split on `::` or `.` and search for just the leaf name.
///
/// Used when `query_trace_matches` returns empty. For example,
/// `cfg.run` falls back to searching for `run`.
pub fn fallback_leaf_trace_matches(
    graph: &impl GraphStore,
    query: &str,
) -> Result<Vec<Entity>, KinError> {
    let split = query
        .rfind("::")
        .map(|idx| (idx, 2usize))
        .or_else(|| query.rfind('.').map(|idx| (idx, 1usize)));
    let Some((idx, sep_len)) = split else {
        return Ok(Vec::new());
    };
    let leaf = &query[idx + sep_len..];
    if leaf == query {
        return Ok(Vec::new());
    }
    let leaf_filter = EntityFilter {
        name_pattern: Some(leaf.to_string()),
        ..Default::default()
    };
    graph
        .query_entities(&leaf_filter)
        .map_err(|e| KinError::Graph(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_model::{
        Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore,
        FingerprintAlgorithm, Hash256, LanguageId, SemanticFingerprint, Visibility,
    };

    fn make_entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::TypeScript,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_hex(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
                signature_hash: Hash256::from_hex(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                )
                .unwrap(),
                behavior_hash: Hash256::from_hex(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                )
                .unwrap(),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("function {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn query_trace_matches_falls_back_to_leaf_for_rust_style_names() {
        let store = InMemoryGraph::new();
        let entity = make_entity("Router<S>::route");
        store.upsert_entity(&entity).unwrap();

        let matches = query_trace_matches(&store, "Router::route").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "Router<S>::route");
    }

    #[test]
    fn query_trace_matches_rejects_unrelated_leaf_match_for_qualified_name() {
        let store = InMemoryGraph::new();
        store.upsert_entity(&make_entity("run")).unwrap();

        let matches = query_trace_matches(&store, "$Config::run").unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn name_resolution_certainly_misses_only_for_a_name_the_index_cannot_place() {
        let store = InMemoryGraph::new();
        store.upsert_entity(&make_entity("route")).unwrap();

        assert!(
            name_resolution_certainly_misses(&store, "no_such_symbol").unwrap(),
            "a name no index entry carries is a certain miss"
        );
        assert!(
            !name_resolution_certainly_misses(&store, "route").unwrap(),
            "a name the index carries must stay on the resolving path"
        );
    }

    /// The three shapes that must never be short-circuited, each of which the
    /// bare name index cannot place on its own: a uuid the caller means as an
    /// id, a qualified name whose leaf resolves, and an empty query whose own
    /// error the resolver owns.
    #[test]
    fn name_resolution_certainly_misses_defers_what_the_name_index_cannot_decide() {
        let store = InMemoryGraph::new();
        let entity = make_entity("run");
        let id = entity.id;
        store.upsert_entity(&entity).unwrap();

        assert!(!name_resolution_certainly_misses(&store, &id.to_string()).unwrap());
        assert!(!name_resolution_certainly_misses(&store, "Config::run").unwrap());
        assert!(!name_resolution_certainly_misses(&store, "   ").unwrap());
    }

    #[test]
    fn fallback_leaf_trace_matches_supports_dotted_queries() {
        let graph = InMemoryGraph::new();
        let run = make_entity("run");
        graph.upsert_entity(&run).unwrap();

        let matches = fallback_leaf_trace_matches(&graph, "cfg.run").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "run");
    }
}
