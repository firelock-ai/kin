// SPDX-License-Identifier: BUSL-1.1
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
}

/// Normalise a batch of [`RawHit`]s into [`CandidateSignals`].
///
/// - BM25 scores are divided by the max score in the batch to get 0..1.
/// - Cosine distance is converted to similarity via `1.0 - distance`.
/// - Graph, proof, and provenance signals are stubbed at 0.0 for now.
pub fn build_signals(hits: &[RawHit]) -> Vec<(String, String, CandidateSignals)> {
    let max_bm25 = hits
        .iter()
        .filter_map(|h| h.bm25_score)
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
            (
                hit.entity_id.clone(),
                hit.entity_name.clone(),
                CandidateSignals::new(lexical, semantic, 0.0, 0.0, 0.0),
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
            },
            RawHit {
                entity_id: "b".into(),
                entity_name: "Beta".into(),
                bm25_score: Some(5.0),
                cosine_distance: None,
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
        }];
        let signals = build_signals(&hits);
        assert_eq!(signals[0].2.lexical, 0.0);
        assert_eq!(signals[0].2.semantic, 0.0);
    }
}
