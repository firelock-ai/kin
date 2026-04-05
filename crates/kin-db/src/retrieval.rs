// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Unified retrieval interface combining lexical, semantic, and structural signals.
//!
//! This module is the bridge between kin-db's index primitives and kin-search's
//! ranking logic. It produces [`RetrievalCandidate`] structs with raw scores
//! from each dimension; kin-search combines these into a final ranking.

use std::collections::HashMap;

use crate::engine::InMemoryGraph;
use crate::error::KinDbError;
use crate::search::TextIndex;
use crate::store::EntityStore;
use crate::types::*;
#[cfg(feature = "vector")]
use crate::vector::VectorIndex;
use kin_model::EntityRole;

/// A retrieval candidate with raw scores from each search dimension.
///
/// All scores are optional — a candidate may appear in lexical results
/// but not vector results (no embedding), or in graph proximity results
/// but not text results (no name match).
#[derive(Debug, Clone)]
pub struct RetrievalCandidate {
    /// The matched retrieval key.
    pub retrieval_key: RetrievalKey,
    /// Lexical match score from tantivy full-text search (higher = better match).
    /// `None` if the entity did not appear in text search results.
    pub lexical_score: Option<f32>,
    /// Semantic similarity score from vector search (lower distance = more similar).
    /// `None` if no embedding was available or the entity was not in vector results.
    pub vector_distance: Option<f32>,
    /// Graph proximity: shortest hop count from a query entity (lower = closer).
    /// `None` if no structural query was performed or the entity was not reachable.
    pub graph_hops: Option<u32>,
    /// Entity role (Source, Test, External, etc.). Used for role-based grouping
    /// in downstream ranking. `None` for non-entity retrieval keys.
    pub role: Option<EntityRole>,
}

/// Configuration for a unified retrieval query.
#[derive(Debug, Clone)]
pub struct RetrievalQuery {
    /// Text query string for lexical search (tantivy). `None` to skip lexical.
    pub text_query: Option<String>,
    /// Embedding vector for semantic search (usearch). `None` to skip vector.
    #[cfg(feature = "vector")]
    pub embedding: Option<Vec<f32>>,
    /// Entity ID for structural proximity search. `None` to skip graph traversal.
    pub proximity_anchor: Option<EntityId>,
    /// Maximum depth for graph proximity BFS (default: 3).
    pub max_hops: u32,
    /// Maximum number of results per dimension before merging.
    pub limit_per_dimension: usize,
}

impl Default for RetrievalQuery {
    fn default() -> Self {
        Self {
            text_query: None,
            #[cfg(feature = "vector")]
            embedding: None,
            proximity_anchor: None,
            max_hops: 3,
            limit_per_dimension: 50,
        }
    }
}

/// Execute a unified retrieval query across all available dimensions.
///
/// Returns candidates merged from lexical, semantic, and structural results.
/// Each candidate carries raw scores from whichever dimensions matched.
/// The caller (kin-search) is responsible for combining scores into a final rank.
pub fn unified_retrieve(
    graph: &InMemoryGraph,
    text_index: Option<&TextIndex>,
    #[cfg(feature = "vector")] vector_index: Option<&VectorIndex>,
    query: &RetrievalQuery,
) -> Result<Vec<RetrievalCandidate>, KinDbError> {
    let mut candidates: HashMap<RetrievalKey, RetrievalCandidate> = HashMap::new();

    // Dimension 1: Lexical (tantivy full-text search)
    if let (Some(text_query), Some(ti)) = (&query.text_query, text_index) {
        let text_results = ti.fuzzy_search(text_query, query.limit_per_dimension)?;
        for (retrieval_key, score) in text_results {
            candidates
                .entry(retrieval_key)
                .or_insert_with(|| RetrievalCandidate {
                    retrieval_key,
                    lexical_score: None,
                    vector_distance: None,
                    graph_hops: None,
                    role: None,
                })
                .lexical_score = Some(score);
        }
    }

    // Dimension 2: Semantic (HNSW vector similarity)
    #[cfg(feature = "vector")]
    if let (Some(embedding), Some(vi)) = (&query.embedding, vector_index) {
        let vector_results = vi.search_similar(embedding, query.limit_per_dimension)?;
        for (retrieval_key, distance) in vector_results {
            candidates
                .entry(retrieval_key)
                .or_insert_with(|| RetrievalCandidate {
                    retrieval_key,
                    lexical_score: None,
                    vector_distance: None,
                    graph_hops: None,
                    role: None,
                })
                .vector_distance = Some(distance);
        }
    }

    // Dimension 3: Structural (graph BFS proximity)
    if let Some(anchor_id) = &query.proximity_anchor {
        let neighborhood = graph.expand_neighborhood(&[*anchor_id], &[], query.max_hops)?;
        let hop_distances = bfs_hop_distances(anchor_id, &neighborhood);
        for (entity_id, hops) in hop_distances {
            if entity_id == *anchor_id {
                continue; // skip the anchor itself
            }
            candidates
                .entry(RetrievalKey::Entity(entity_id))
                .or_insert_with(|| RetrievalCandidate {
                    retrieval_key: RetrievalKey::Entity(entity_id),
                    lexical_score: None,
                    vector_distance: None,
                    graph_hops: None,
                    role: None,
                })
                .graph_hops = Some(hops);
        }
        let _ = neighborhood; // consumed above via BFS
    }

    // Resolve entity roles from the graph
    for candidate in candidates.values_mut() {
        if let RetrievalKey::Entity(eid) = candidate.retrieval_key {
            if let Ok(Some(entity)) = graph.get_entity(&eid) {
                candidate.role = Some(entity.role);
            }
        }
    }

    Ok(candidates.into_values().collect())
}

/// BFS from an anchor entity over an expanded subgraph, returning
/// `(entity_id, hop_count)` pairs.
fn bfs_hop_distances(anchor: &EntityId, neighborhood: &SubGraph) -> Vec<(EntityId, u32)> {
    use std::collections::{HashSet, VecDeque};

    let mut adjacency: std::collections::HashMap<EntityId, Vec<EntityId>> =
        std::collections::HashMap::new();
    for relation in &neighborhood.relations {
        let (Some(src), Some(dst)) = (relation.src.as_entity(), relation.dst.as_entity()) else {
            continue;
        };
        adjacency.entry(src).or_default().push(dst);
        adjacency.entry(dst).or_default().push(src);
    }

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let mut results = Vec::new();

    visited.insert(*anchor);
    queue.push_back((*anchor, 0u32));

    while let Some((current, depth)) = queue.pop_front() {
        if depth > 0 {
            results.push((current, depth));
        }
        if let Some(neighbors) = adjacency.get(&current) {
            for neighbor in neighbors {
                if visited.insert(*neighbor) {
                    queue.push_back((*neighbor, depth + 1));
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entity(name: &str) -> Entity {
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
            file_origin: Some(FilePathId::new("src/lib.rs")),
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

    #[test]
    fn retrieval_with_text_only() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("process_payment");
        let e2 = test_entity("validate_input");
        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let text_index = TextIndex::new().unwrap();
        text_index.upsert(&e1).unwrap();
        text_index.upsert(&e2).unwrap();
        text_index.commit().unwrap();

        let query = RetrievalQuery {
            text_query: Some("payment".to_string()),
            #[cfg(feature = "vector")]
            embedding: None,
            proximity_anchor: None,
            max_hops: 3,
            limit_per_dimension: 10,
        };

        let results = unified_retrieve(
            &graph,
            Some(&text_index),
            #[cfg(feature = "vector")]
            None,
            &query,
        )
        .unwrap();

        assert!(!results.is_empty());
        let payment_result = results
            .iter()
            .find(|r| r.retrieval_key == RetrievalKey::from(e1.id));
        assert!(payment_result.is_some());
        assert!(payment_result.unwrap().lexical_score.is_some());
        assert!(payment_result.unwrap().vector_distance.is_none());
        assert!(payment_result.unwrap().graph_hops.is_none());
    }

    #[test]
    fn retrieval_with_graph_proximity() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("caller");
        let e2 = test_entity("callee");
        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let rel = Relation {
            id: RelationId::new(),
            src: GraphNodeId::Entity(e1.id),
            dst: GraphNodeId::Entity(e2.id),
            kind: RelationKind::Calls,
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
        };
        graph.upsert_relation(&rel).unwrap();

        let query = RetrievalQuery {
            text_query: None,
            #[cfg(feature = "vector")]
            embedding: None,
            proximity_anchor: Some(e1.id),
            max_hops: 2,
            limit_per_dimension: 10,
        };

        let results = unified_retrieve(
            &graph,
            None,
            #[cfg(feature = "vector")]
            None,
            &query,
        )
        .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].retrieval_key, RetrievalKey::from(e2.id));
        assert_eq!(results[0].graph_hops, Some(1));
    }

    #[test]
    fn retrieval_merges_dimensions() {
        let graph = InMemoryGraph::new();
        let e1 = test_entity("handle_request");
        let e2 = test_entity("parse_request");
        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();

        let rel = Relation {
            id: RelationId::new(),
            src: GraphNodeId::Entity(e1.id),
            dst: GraphNodeId::Entity(e2.id),
            kind: RelationKind::Calls,
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
        };
        graph.upsert_relation(&rel).unwrap();

        let text_index = TextIndex::new().unwrap();
        text_index.upsert(&e1).unwrap();
        text_index.upsert(&e2).unwrap();
        text_index.commit().unwrap();

        let query = RetrievalQuery {
            text_query: Some("request".to_string()),
            #[cfg(feature = "vector")]
            embedding: None,
            proximity_anchor: Some(e1.id),
            max_hops: 2,
            limit_per_dimension: 10,
        };

        let results = unified_retrieve(
            &graph,
            Some(&text_index),
            #[cfg(feature = "vector")]
            None,
            &query,
        )
        .unwrap();

        // e2 should appear with both lexical and graph scores.
        let e2_result = results
            .iter()
            .find(|r| r.retrieval_key == RetrievalKey::from(e2.id));
        assert!(e2_result.is_some(), "e2 should be in merged results");
        let e2_r = e2_result.unwrap();
        assert!(e2_r.lexical_score.is_some(), "should have lexical score");
        assert_eq!(e2_r.graph_hops, Some(1), "should have graph proximity");
    }
}
