// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Converts raw TextIndex BM25 scores and VectorIndex cosine distances
//! into normalised [`CandidateSignals`] ready for [`rank_candidates`].

use crate::CandidateSignals;

/// A raw hit from TextIndex (BM25) or VectorIndex (cosine distance).
#[derive(Debug, Clone)]
pub struct RawHit {
    pub entity_id: String,
    pub entity_name: String,
    /// Raw BM25 score from TextIndex::fuzzy_search (None if text search unavailable).
    pub bm25_score: Option<f32>,
    /// Cosine distance from VectorIndex::search_similar (None if no embeddings).
    pub cosine_distance: Option<f32>,
    /// Raw graph-centrality signal, typically relation fan-out count.
    pub graph_score: Option<f32>,
    /// Raw proof-coverage signal already normalized by the caller into 0..1.
    pub proof_score: Option<f32>,
    /// Raw provenance-quality signal already normalized by the caller into 0..1.
    pub provenance_score: Option<f32>,
}

/// Normalise a batch of [`RawHit`]s into [`CandidateSignals`].
///
/// - BM25 scores are divided by the max score in the batch to get 0..1.
/// - Cosine distance is converted to similarity via `1.0 - distance`.
/// - Graph scores are divided by the max score in the batch to get 0..1.
/// - Proof and provenance scores are clamped into 0..1.
pub fn build_signals(hits: &[RawHit]) -> Vec<(String, String, CandidateSignals)> {
    let max_bm25 = hits
        .iter()
        .filter_map(|h| h.bm25_score)
        .fold(0.0_f32, f32::max);
    let max_graph = hits
        .iter()
        .filter_map(|h| h.graph_score)
        .fold(0.0_f32, f32::max);

    hits.iter()
        .map(|hit| {
            let lexical = match hit.bm25_score {
                Some(score) if max_bm25 > 0.0 => score / max_bm25,
                _ => 0.0,
            };
            let semantic = match hit.cosine_distance {
                Some(dist) => (1.0 - dist).max(0.0),
                None => 0.0,
            };
            let graph = match hit.graph_score {
                Some(score) if max_graph > 0.0 => score / max_graph,
                _ => 0.0,
            };
            let proof = hit.proof_score.unwrap_or(0.0).clamp(0.0, 1.0);
            let provenance = hit.provenance_score.unwrap_or(0.0).clamp(0.0, 1.0);
            (
                hit.entity_id.clone(),
                hit.entity_name.clone(),
                CandidateSignals::new(lexical, semantic, graph, proof, provenance),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bm25_normalises_to_unit_range() {
        let hits = vec![
            RawHit {
                entity_id: "a".into(),
                entity_name: "Alpha".into(),
                bm25_score: Some(10.0),
                cosine_distance: None,
                graph_score: None,
                proof_score: None,
                provenance_score: None,
            },
            RawHit {
                entity_id: "b".into(),
                entity_name: "Beta".into(),
                bm25_score: Some(5.0),
                cosine_distance: None,
                graph_score: None,
                proof_score: None,
                provenance_score: None,
            },
        ];
        let signals = build_signals(&hits);
        assert_eq!(signals[0].2.lexical, 1.0);
        assert_eq!(signals[1].2.lexical, 0.5);
    }

    #[test]
    fn cosine_distance_converted_to_similarity() {
        let hits = vec![RawHit {
            entity_id: "a".into(),
            entity_name: "Alpha".into(),
            bm25_score: None,
            cosine_distance: Some(0.3),
            graph_score: None,
            proof_score: None,
            provenance_score: None,
        }];
        let signals = build_signals(&hits);
        assert!((signals[0].2.semantic - 0.7).abs() < 1e-5);
    }

    #[test]
    fn empty_input_returns_empty() {
        assert!(build_signals(&[]).is_empty());
    }

    #[test]
    fn missing_scores_default_to_zero() {
        let hits = vec![RawHit {
            entity_id: "a".into(),
            entity_name: "Alpha".into(),
            bm25_score: None,
            cosine_distance: None,
            graph_score: None,
            proof_score: None,
            provenance_score: None,
        }];
        let signals = build_signals(&hits);
        assert_eq!(signals[0].2.lexical, 0.0);
        assert_eq!(signals[0].2.semantic, 0.0);
        assert_eq!(signals[0].2.graph, 0.0);
        assert_eq!(signals[0].2.proof, 0.0);
        assert_eq!(signals[0].2.provenance, 0.0);
    }

    #[test]
    fn graph_proof_and_provenance_signals_are_carried() {
        let hits = vec![RawHit {
            entity_id: "a".into(),
            entity_name: "Alpha".into(),
            bm25_score: Some(5.0),
            cosine_distance: Some(0.2),
            graph_score: Some(4.0),
            proof_score: Some(0.75),
            provenance_score: Some(0.6),
        }];
        let signals = build_signals(&hits);
        assert_eq!(signals[0].2.graph, 1.0);
        assert_eq!(signals[0].2.proof, 0.75);
        assert_eq!(signals[0].2.provenance, 0.6);
    }

    #[test]
    fn preserves_entity_id_and_name() {
        let hits = vec![RawHit {
            entity_id: "entity:abc".into(),
            entity_name: "MyFunction".into(),
            bm25_score: Some(1.0),
            cosine_distance: None,
            graph_score: None,
            proof_score: None,
            provenance_score: None,
        }];
        let signals = build_signals(&hits);
        assert_eq!(signals[0].0, "entity:abc");
        assert_eq!(signals[0].1, "MyFunction");
    }

    #[test]
    fn multiple_hits_all_normalised() {
        let hits = vec![
            RawHit {
                entity_id: "a".into(),
                entity_name: "A".into(),
                bm25_score: Some(20.0),
                cosine_distance: Some(0.1),
                graph_score: Some(10.0),
                proof_score: Some(1.0),
                provenance_score: Some(0.8),
            },
            RawHit {
                entity_id: "b".into(),
                entity_name: "B".into(),
                bm25_score: Some(10.0),
                cosine_distance: Some(0.5),
                graph_score: Some(5.0),
                proof_score: Some(0.5),
                provenance_score: Some(0.4),
            },
            RawHit {
                entity_id: "c".into(),
                entity_name: "C".into(),
                bm25_score: Some(5.0),
                cosine_distance: Some(0.9),
                graph_score: Some(2.5),
                proof_score: Some(0.0),
                provenance_score: Some(0.2),
            },
        ];
        let signals = build_signals(&hits);

        // BM25: 20/20=1.0, 10/20=0.5, 5/20=0.25
        assert!((signals[0].2.lexical - 1.0).abs() < 1e-5);
        assert!((signals[1].2.lexical - 0.5).abs() < 1e-5);
        assert!((signals[2].2.lexical - 0.25).abs() < 1e-5);

        // Cosine: 1-0.1=0.9, 1-0.5=0.5, 1-0.9=0.1
        assert!((signals[0].2.semantic - 0.9).abs() < 1e-5);
        assert!((signals[1].2.semantic - 0.5).abs() < 1e-5);
        assert!((signals[2].2.semantic - 0.1).abs() < 1e-5);

        // Graph: 10/10=1.0, 5/10=0.5, 2.5/10=0.25
        assert!((signals[0].2.graph - 1.0).abs() < 1e-5);
        assert!((signals[1].2.graph - 0.5).abs() < 1e-5);
        assert!((signals[2].2.graph - 0.25).abs() < 1e-5);

        assert!((signals[0].2.proof - 1.0).abs() < 1e-5);
        assert!((signals[1].2.proof - 0.5).abs() < 1e-5);
        assert!((signals[2].2.proof - 0.0).abs() < 1e-5);

        assert!((signals[0].2.provenance - 0.8).abs() < 1e-5);
        assert!((signals[1].2.provenance - 0.4).abs() < 1e-5);
        assert!((signals[2].2.provenance - 0.2).abs() < 1e-5);
    }
}
