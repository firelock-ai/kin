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

/// Fallback: split on `::` or `.` and search for just the leaf name.
///
/// Used when `query_trace_matches` returns empty. For example,
/// `_zod.run` falls back to searching for `run`.
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
        Entity, EntityId, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, Hash256, LanguageId,
        SemanticFingerprint, Visibility,
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

        let matches = query_trace_matches(&store, "$ZodType::run").unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn fallback_leaf_trace_matches_supports_dotted_queries() {
        let graph = InMemoryGraph::new();
        let run = make_entity("run");
        graph.upsert_entity(&run).unwrap();

        let matches = fallback_leaf_trace_matches(&graph, "_zod.run").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "run");
    }
}
