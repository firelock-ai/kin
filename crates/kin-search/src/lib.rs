// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod corpus;
pub mod relevance;
pub mod signal_builder;
pub mod tuner;

use serde::{Deserialize, Serialize};

/// Configurable weight parameters for search ranking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeightConfig {
    pub lexical: f32,
    pub semantic: f32,
    pub graph: f32,
    pub proof: f32,
    pub provenance: f32,
    pub proof_bias: f32,
}

impl Default for WeightConfig {
    fn default() -> Self {
        Self {
            lexical: 0.30,
            semantic: 0.28,
            graph: 0.18,
            proof: 0.16,
            provenance: 0.08,
            proof_bias: 1.35,
        }
    }
}

impl WeightConfig {
    /// Returns true if weights sum to approximately 1.0 (within epsilon).
    pub fn is_normalized(&self) -> bool {
        let sum = self.lexical + self.semantic + self.graph + self.proof + self.provenance;
        (sum - 1.0).abs() < 0.01
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchQuery {
    pub text: String,
    pub require_proof: bool,
    pub limit: usize,
}

impl SearchQuery {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            require_proof: false,
            limit: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CandidateSignals {
    pub lexical: f32,
    pub semantic: f32,
    pub graph: f32,
    pub proof: f32,
    pub provenance: f32,
}

impl CandidateSignals {
    pub const fn new(lexical: f32, semantic: f32, graph: f32, proof: f32, provenance: f32) -> Self {
        Self {
            lexical,
            semantic,
            graph,
            proof,
            provenance,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SearchCandidate {
    pub id: String,
    pub title: String,
    pub signals: CandidateSignals,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RankedResult {
    pub id: String,
    pub title: String,
    pub score: f32,
    pub explanation: String,
}

pub use signal_builder::RawHit;

pub fn rank_candidates(query: &SearchQuery, candidates: &[SearchCandidate]) -> Vec<RankedResult> {
    rank_candidates_with_config(query, candidates, &WeightConfig::default())
}

pub fn rank_candidates_with_config(
    query: &SearchQuery,
    candidates: &[SearchCandidate],
    config: &WeightConfig,
) -> Vec<RankedResult> {
    let mut ranked: Vec<_> = candidates
        .iter()
        .filter(|c| !query.require_proof || c.signals.proof > 0.0)
        .map(|c| RankedResult {
            id: c.id.clone(),
            title: c.title.clone(),
            score: score_with_config(query, &c.signals, config),
            explanation: explanation_for(&c.signals),
        })
        .collect();

    ranked.sort_by(|a, b| b.score.total_cmp(&a.score));
    ranked.truncate(query.limit);
    ranked
}

/// Convert raw hits into ranked results in one shared step.
pub fn rank_raw_hits(query: &SearchQuery, hits: &[RawHit]) -> Vec<RankedResult> {
    let signals = signal_builder::build_signals(hits);
    let candidates: Vec<SearchCandidate> = signals
        .into_iter()
        .map(|(id, title, signals)| SearchCandidate { id, title, signals })
        .collect();
    rank_candidates(query, &candidates)
}

fn score_with_config(
    query: &SearchQuery,
    signals: &CandidateSignals,
    config: &WeightConfig,
) -> f32 {
    let proof_bias = if query.require_proof {
        config.proof_bias
    } else {
        1.0
    };
    signals.lexical * config.lexical
        + signals.semantic * config.semantic
        + signals.graph * config.graph
        + signals.proof * config.proof * proof_bias
        + signals.provenance * config.provenance
}

fn explanation_for(signals: &CandidateSignals) -> String {
    let mut parts = Vec::new();
    if signals.lexical > 0.0 {
        parts.push("lexical");
    }
    if signals.semantic > 0.0 {
        parts.push("semantic");
    }
    if signals.graph > 0.0 {
        parts.push("graph");
    }
    if signals.proof > 0.0 {
        parts.push("proof");
    }
    if signals.provenance > 0.0 {
        parts.push("provenance");
    }
    if parts.is_empty() {
        "unranked".to_string()
    } else {
        format!("ranked via {}", parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        rank_candidates, rank_candidates_with_config, CandidateSignals, SearchCandidate,
        SearchQuery, WeightConfig,
    };

    // -----------------------------------------------------------------------
    // WeightConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn weight_config_default_is_normalized() {
        let config = WeightConfig::default();
        assert!(config.is_normalized());
    }

    #[test]
    fn weight_config_unnormalized() {
        let config = WeightConfig {
            lexical: 0.5,
            semantic: 0.5,
            graph: 0.5,
            proof: 0.5,
            provenance: 0.5,
            proof_bias: 1.0,
        };
        assert!(!config.is_normalized());
    }

    #[test]
    fn weight_config_serde_roundtrip() {
        let config = WeightConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let restored: WeightConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, restored);
    }

    // -----------------------------------------------------------------------
    // rank_candidates_with_config tests
    // -----------------------------------------------------------------------

    #[test]
    fn rank_with_custom_config_changes_order() {
        let query = SearchQuery::new("x");
        // With default weights, lexical (0.30) > semantic (0.28), so lex-dominant wins.
        // With flipped config, semantic-dominant should win.
        let candidates = vec![
            SearchCandidate {
                id: "lex".into(),
                title: "Lex".into(),
                signals: CandidateSignals::new(1.0, 0.0, 0.0, 0.0, 0.0),
            },
            SearchCandidate {
                id: "sem".into(),
                title: "Sem".into(),
                signals: CandidateSignals::new(0.0, 1.0, 0.0, 0.0, 0.0),
            },
        ];

        // Default: lexical wins
        let default_ranked = rank_candidates(&query, &candidates);
        assert_eq!(default_ranked[0].id, "lex");

        // Custom: semantic heavy
        let config = WeightConfig {
            lexical: 0.10,
            semantic: 0.60,
            graph: 0.10,
            proof: 0.10,
            provenance: 0.10,
            proof_bias: 1.0,
        };
        let custom_ranked = rank_candidates_with_config(&query, &candidates, &config);
        assert_eq!(custom_ranked[0].id, "sem");
    }

    #[test]
    fn rank_with_config_delegates_correctly() {
        // rank_candidates should produce the same result as rank_candidates_with_config
        // using the default config.
        let query = SearchQuery::new("test");
        let candidates = vec![
            SearchCandidate {
                id: "a".into(),
                title: "A".into(),
                signals: CandidateSignals::new(0.8, 0.6, 0.4, 0.2, 0.1),
            },
            SearchCandidate {
                id: "b".into(),
                title: "B".into(),
                signals: CandidateSignals::new(0.3, 0.9, 0.5, 0.7, 0.6),
            },
        ];
        let default_ranked = rank_candidates(&query, &candidates);
        let config_ranked =
            rank_candidates_with_config(&query, &candidates, &WeightConfig::default());
        assert_eq!(default_ranked.len(), config_ranked.len());
        for (d, c) in default_ranked.iter().zip(config_ranked.iter()) {
            assert_eq!(d.id, c.id);
            assert!((d.score - c.score).abs() < 1e-6);
        }
    }

    #[test]
    fn proof_requirement_filters_unproven_results() {
        let mut query = SearchQuery::new("queue");
        query.require_proof = true;

        let ranked = rank_candidates(
            &query,
            &[
                SearchCandidate {
                    id: "entity:1".into(),
                    title: "QueueRuntime".into(),
                    signals: CandidateSignals::new(0.7, 0.8, 0.6, 0.0, 0.4),
                },
                SearchCandidate {
                    id: "entity:2".into(),
                    title: "QueueProof".into(),
                    signals: CandidateSignals::new(0.6, 0.7, 0.5, 0.8, 0.4),
                },
            ],
        );

        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].id, "entity:2");
    }

    #[test]
    fn ranking_prefers_balanced_high_signal_candidates() {
        let query = SearchQuery::new("runtime");

        let ranked = rank_candidates(
            &query,
            &[
                SearchCandidate {
                    id: "entity:weak-proof".into(),
                    title: "RuntimeNotes".into(),
                    signals: CandidateSignals::new(0.9, 0.7, 0.2, 0.0, 0.2),
                },
                SearchCandidate {
                    id: "entity:balanced".into(),
                    title: "RuntimeController".into(),
                    signals: CandidateSignals::new(0.7, 0.8, 0.8, 0.8, 0.6),
                },
            ],
        );

        assert_eq!(ranked[0].id, "entity:balanced");
        assert!(ranked[0].explanation.contains("proof"));
    }

    // -----------------------------------------------------------------------
    // SearchQuery tests
    // -----------------------------------------------------------------------

    #[test]
    fn search_query_defaults() {
        let q = SearchQuery::new("hello");
        assert_eq!(q.text, "hello");
        assert!(!q.require_proof);
        assert_eq!(q.limit, 20);
    }

    #[test]
    fn search_query_from_string_type() {
        let q = SearchQuery::new(String::from("world"));
        assert_eq!(q.text, "world");
    }

    #[test]
    fn search_query_eq_and_clone() {
        let q1 = SearchQuery::new("test");
        let q2 = q1.clone();
        assert_eq!(q1, q2);
    }

    // -----------------------------------------------------------------------
    // CandidateSignals tests
    // -----------------------------------------------------------------------

    #[test]
    fn candidate_signals_const_new() {
        let s = CandidateSignals::new(0.1, 0.2, 0.3, 0.4, 0.5);
        assert_eq!(s.lexical, 0.1);
        assert_eq!(s.semantic, 0.2);
        assert_eq!(s.graph, 0.3);
        assert_eq!(s.proof, 0.4);
        assert_eq!(s.provenance, 0.5);
    }

    #[test]
    fn candidate_signals_zero() {
        let s = CandidateSignals::new(0.0, 0.0, 0.0, 0.0, 0.0);
        assert_eq!(s.lexical, 0.0);
        assert_eq!(s.provenance, 0.0);
    }

    #[test]
    fn candidate_signals_clone_eq() {
        let s1 = CandidateSignals::new(0.5, 0.5, 0.5, 0.5, 0.5);
        let s2 = s1.clone();
        assert_eq!(s1, s2);
    }

    // -----------------------------------------------------------------------
    // Scoring weight tests
    // -----------------------------------------------------------------------

    #[test]
    fn lexical_only_score_uses_030_weight() {
        let query = SearchQuery::new("x");
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "a".into(),
                title: "A".into(),
                signals: CandidateSignals::new(1.0, 0.0, 0.0, 0.0, 0.0),
            }],
        );
        assert!((ranked[0].score - 0.30).abs() < 1e-5);
    }

    #[test]
    fn semantic_only_score_uses_028_weight() {
        let query = SearchQuery::new("x");
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "a".into(),
                title: "A".into(),
                signals: CandidateSignals::new(0.0, 1.0, 0.0, 0.0, 0.0),
            }],
        );
        assert!((ranked[0].score - 0.28).abs() < 1e-5);
    }

    #[test]
    fn graph_only_score_uses_018_weight() {
        let query = SearchQuery::new("x");
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "a".into(),
                title: "A".into(),
                signals: CandidateSignals::new(0.0, 0.0, 1.0, 0.0, 0.0),
            }],
        );
        assert!((ranked[0].score - 0.18).abs() < 1e-5);
    }

    #[test]
    fn proof_only_score_uses_016_weight_without_proof_requirement() {
        let query = SearchQuery::new("x");
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "a".into(),
                title: "A".into(),
                signals: CandidateSignals::new(0.0, 0.0, 0.0, 1.0, 0.0),
            }],
        );
        assert!((ranked[0].score - 0.16).abs() < 1e-5);
    }

    #[test]
    fn provenance_only_score_uses_008_weight() {
        let query = SearchQuery::new("x");
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "a".into(),
                title: "A".into(),
                signals: CandidateSignals::new(0.0, 0.0, 0.0, 0.0, 1.0),
            }],
        );
        assert!((ranked[0].score - 0.08).abs() < 1e-5);
    }

    #[test]
    fn all_signals_max_score_is_one() {
        let query = SearchQuery::new("x");
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "a".into(),
                title: "A".into(),
                signals: CandidateSignals::new(1.0, 1.0, 1.0, 1.0, 1.0),
            }],
        );
        assert!((ranked[0].score - 1.0).abs() < 1e-5);
    }

    #[test]
    fn proof_bias_applied_when_require_proof() {
        let mut query = SearchQuery::new("x");
        query.require_proof = true;
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "a".into(),
                title: "A".into(),
                signals: CandidateSignals::new(0.0, 0.0, 0.0, 1.0, 0.0),
            }],
        );
        // proof weight = 0.16 * 1.35 = 0.216
        assert!((ranked[0].score - 0.216).abs() < 1e-5);
    }

    // -----------------------------------------------------------------------
    // Empty and edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn empty_candidates_returns_empty() {
        let query = SearchQuery::new("anything");
        let ranked = rank_candidates(&query, &[]);
        assert!(ranked.is_empty());
    }

    #[test]
    fn empty_query_text_still_ranks() {
        let query = SearchQuery::new("");
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "a".into(),
                title: "A".into(),
                signals: CandidateSignals::new(0.5, 0.5, 0.5, 0.5, 0.5),
            }],
        );
        assert_eq!(ranked.len(), 1);
    }

    #[test]
    fn special_characters_in_query() {
        let query = SearchQuery::new("fn<T: Debug + 'static>(x: &[u8]) -> Result<()>");
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "a".into(),
                title: "A".into(),
                signals: CandidateSignals::new(0.9, 0.0, 0.0, 0.0, 0.0),
            }],
        );
        assert_eq!(ranked.len(), 1);
    }

    #[test]
    fn unicode_in_query() {
        let query = SearchQuery::new("日本語テスト");
        let ranked = rank_candidates(&query, &[]);
        assert!(ranked.is_empty());
    }

    // -----------------------------------------------------------------------
    // Ordering tests
    // -----------------------------------------------------------------------

    #[test]
    fn results_sorted_descending_by_score() {
        let query = SearchQuery::new("x");
        let ranked = rank_candidates(
            &query,
            &[
                SearchCandidate {
                    id: "low".into(),
                    title: "Low".into(),
                    signals: CandidateSignals::new(0.1, 0.0, 0.0, 0.0, 0.0),
                },
                SearchCandidate {
                    id: "high".into(),
                    title: "High".into(),
                    signals: CandidateSignals::new(1.0, 1.0, 1.0, 1.0, 1.0),
                },
                SearchCandidate {
                    id: "mid".into(),
                    title: "Mid".into(),
                    signals: CandidateSignals::new(0.5, 0.5, 0.0, 0.0, 0.0),
                },
            ],
        );
        assert_eq!(ranked[0].id, "high");
        assert_eq!(ranked[1].id, "mid");
        assert_eq!(ranked[2].id, "low");
    }

    #[test]
    fn limit_truncates_results() {
        let mut query = SearchQuery::new("x");
        query.limit = 2;
        let candidates: Vec<_> = (0..10)
            .map(|i| SearchCandidate {
                id: format!("e:{i}"),
                title: format!("E{i}"),
                signals: CandidateSignals::new(i as f32 / 10.0, 0.0, 0.0, 0.0, 0.0),
            })
            .collect();
        let ranked = rank_candidates(&query, &candidates);
        assert_eq!(ranked.len(), 2);
    }

    #[test]
    fn limit_zero_returns_empty() {
        let mut query = SearchQuery::new("x");
        query.limit = 0;
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "a".into(),
                title: "A".into(),
                signals: CandidateSignals::new(1.0, 1.0, 1.0, 1.0, 1.0),
            }],
        );
        assert!(ranked.is_empty());
    }

    #[test]
    fn limit_larger_than_candidates_returns_all() {
        let mut query = SearchQuery::new("x");
        query.limit = 100;
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "a".into(),
                title: "A".into(),
                signals: CandidateSignals::new(0.5, 0.5, 0.5, 0.5, 0.5),
            }],
        );
        assert_eq!(ranked.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Proof filtering tests
    // -----------------------------------------------------------------------

    #[test]
    fn proof_requirement_keeps_proven_candidates() {
        let mut query = SearchQuery::new("x");
        query.require_proof = true;
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "proven".into(),
                title: "Proven".into(),
                signals: CandidateSignals::new(0.5, 0.5, 0.5, 0.9, 0.5),
            }],
        );
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].id, "proven");
    }

    #[test]
    fn proof_requirement_filters_all_when_none_proven() {
        let mut query = SearchQuery::new("x");
        query.require_proof = true;
        let ranked = rank_candidates(
            &query,
            &[
                SearchCandidate {
                    id: "a".into(),
                    title: "A".into(),
                    signals: CandidateSignals::new(1.0, 1.0, 1.0, 0.0, 1.0),
                },
                SearchCandidate {
                    id: "b".into(),
                    title: "B".into(),
                    signals: CandidateSignals::new(0.5, 0.5, 0.5, 0.0, 0.5),
                },
            ],
        );
        assert!(ranked.is_empty());
    }

    #[test]
    fn no_proof_requirement_keeps_unproven() {
        let query = SearchQuery::new("x");
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "a".into(),
                title: "A".into(),
                signals: CandidateSignals::new(0.5, 0.5, 0.5, 0.0, 0.5),
            }],
        );
        assert_eq!(ranked.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Explanation tests
    // -----------------------------------------------------------------------

    #[test]
    fn explanation_all_signals() {
        let query = SearchQuery::new("x");
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "a".into(),
                title: "A".into(),
                signals: CandidateSignals::new(0.5, 0.5, 0.5, 0.5, 0.5),
            }],
        );
        assert!(ranked[0].explanation.contains("lexical"));
        assert!(ranked[0].explanation.contains("semantic"));
        assert!(ranked[0].explanation.contains("graph"));
        assert!(ranked[0].explanation.contains("proof"));
        assert!(ranked[0].explanation.contains("provenance"));
    }

    #[test]
    fn explanation_lexical_only() {
        let query = SearchQuery::new("x");
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "a".into(),
                title: "A".into(),
                signals: CandidateSignals::new(1.0, 0.0, 0.0, 0.0, 0.0),
            }],
        );
        assert_eq!(ranked[0].explanation, "ranked via lexical");
    }

    #[test]
    fn explanation_no_signals_shows_unranked() {
        let query = SearchQuery::new("x");
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "a".into(),
                title: "A".into(),
                signals: CandidateSignals::new(0.0, 0.0, 0.0, 0.0, 0.0),
            }],
        );
        assert_eq!(ranked[0].explanation, "unranked");
    }

    #[test]
    fn explanation_semantic_and_graph_only() {
        let query = SearchQuery::new("x");
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "a".into(),
                title: "A".into(),
                signals: CandidateSignals::new(0.0, 0.8, 0.6, 0.0, 0.0),
            }],
        );
        assert_eq!(ranked[0].explanation, "ranked via semantic, graph");
    }

    // -----------------------------------------------------------------------
    // Duplicate and identity tests
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_candidates_both_appear() {
        let query = SearchQuery::new("x");
        let ranked = rank_candidates(
            &query,
            &[
                SearchCandidate {
                    id: "same".into(),
                    title: "Same".into(),
                    signals: CandidateSignals::new(0.5, 0.5, 0.5, 0.5, 0.5),
                },
                SearchCandidate {
                    id: "same".into(),
                    title: "Same".into(),
                    signals: CandidateSignals::new(0.5, 0.5, 0.5, 0.5, 0.5),
                },
            ],
        );
        assert_eq!(ranked.len(), 2);
    }

    #[test]
    fn ranked_result_preserves_id_and_title() {
        let query = SearchQuery::new("x");
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "entity:42".into(),
                title: "MySpecialFunction".into(),
                signals: CandidateSignals::new(0.5, 0.5, 0.5, 0.5, 0.5),
            }],
        );
        assert_eq!(ranked[0].id, "entity:42");
        assert_eq!(ranked[0].title, "MySpecialFunction");
    }

    // -----------------------------------------------------------------------
    // Multi-signal combination tests
    // -----------------------------------------------------------------------

    #[test]
    fn lexical_dominant_beats_semantic_dominant() {
        let query = SearchQuery::new("x");
        // Lexical weight (0.30) > semantic weight (0.28), so higher lexical should win
        let ranked = rank_candidates(
            &query,
            &[
                SearchCandidate {
                    id: "lexical".into(),
                    title: "Lex".into(),
                    signals: CandidateSignals::new(1.0, 0.0, 0.0, 0.0, 0.0),
                },
                SearchCandidate {
                    id: "semantic".into(),
                    title: "Sem".into(),
                    signals: CandidateSignals::new(0.0, 1.0, 0.0, 0.0, 0.0),
                },
            ],
        );
        assert_eq!(ranked[0].id, "lexical");
    }

    #[test]
    fn combined_weak_signals_can_beat_single_strong() {
        let query = SearchQuery::new("x");
        // Single strong lexical = 0.30
        // Combined moderate = 0.5*0.30 + 0.5*0.28 + 0.5*0.18 = 0.38
        let ranked = rank_candidates(
            &query,
            &[
                SearchCandidate {
                    id: "single".into(),
                    title: "Single".into(),
                    signals: CandidateSignals::new(1.0, 0.0, 0.0, 0.0, 0.0),
                },
                SearchCandidate {
                    id: "combined".into(),
                    title: "Combined".into(),
                    signals: CandidateSignals::new(0.5, 0.5, 0.5, 0.0, 0.0),
                },
            ],
        );
        assert_eq!(ranked[0].id, "combined");
    }

    #[test]
    fn zero_score_candidate_still_returned() {
        let query = SearchQuery::new("x");
        let ranked = rank_candidates(
            &query,
            &[SearchCandidate {
                id: "zero".into(),
                title: "Zero".into(),
                signals: CandidateSignals::new(0.0, 0.0, 0.0, 0.0, 0.0),
            }],
        );
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].score, 0.0);
    }
}
