// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Grid-search weight tuner for optimising search ranking weights
//! against a benchmark corpus.

use crate::corpus::SearchBenchmarkCorpus;
use crate::relevance::evaluate_relevance;
use crate::{rank_candidates_with_config, WeightConfig};

/// Result of a tuning run.
#[derive(Debug, Clone)]
pub struct TuningResult {
    pub best_config: WeightConfig,
    pub best_ndcg_10: f64,
    pub baseline_ndcg_10: f64,
    pub configs_evaluated: usize,
    pub top_configs: Vec<(WeightConfig, f64)>,
}

/// Evaluate a single weight configuration against the corpus.
/// Returns mean NDCG@10 across all queries.
pub fn evaluate_config(corpus: &SearchBenchmarkCorpus, config: &WeightConfig) -> f64 {
    if corpus.is_empty() {
        return 0.0;
    }

    let total: f64 = corpus
        .queries
        .iter()
        .map(|bq| {
            let ranked = rank_candidates_with_config(&bq.query, &bq.candidates, config);
            let report = evaluate_relevance(&ranked, &bq.judgments);
            report.ndcg_10
        })
        .sum();

    total / corpus.queries.len() as f64
}

/// Grid search over weight space.
///
/// Generates weight configs by stepping each weight from 0.0 to max in
/// increments of `step`, keeping total weight normalized to 1.0.
/// The proof_bias is searched separately in the \[1.0, 1.5\] range.
///
/// Returns the config with highest mean NDCG@10.
pub fn tune_weights(corpus: &SearchBenchmarkCorpus, step: f32) -> TuningResult {
    let baseline_config = WeightConfig::default();
    let baseline_ndcg_10 = evaluate_config(corpus, &baseline_config);

    let mut best_config = baseline_config.clone();
    let mut best_ndcg = baseline_ndcg_10;
    let mut configs_evaluated = 0_usize;
    let mut top_configs: Vec<(WeightConfig, f64)> = Vec::new();

    let proof_biases = [1.0_f32, 1.1, 1.2, 1.3, 1.4, 1.5];

    // Iterate lexical, semantic, graph; derive proof and provenance from remainder.
    let mut lexical = 0.0_f32;
    while lexical <= 0.6 + 1e-6 {
        let mut semantic = 0.0_f32;
        while semantic <= 0.6 + 1e-6 {
            let mut graph = 0.0_f32;
            while graph <= 0.4 + 1e-6 {
                let used = lexical + semantic + graph;
                if used > 1.0 + 1e-6 {
                    graph += step;
                    continue;
                }
                let remaining = (1.0 - used).max(0.0);
                let proof = remaining * 0.67;
                let provenance = remaining - proof; // ensures exact sum to 1.0

                for &pb in &proof_biases {
                    let config = WeightConfig {
                        lexical,
                        semantic,
                        graph,
                        proof,
                        provenance,
                        proof_bias: pb,
                    };

                    let score = evaluate_config(corpus, &config);
                    configs_evaluated += 1;

                    if score > best_ndcg {
                        best_ndcg = score;
                        best_config = config.clone();
                    }

                    // Maintain top 5.
                    top_configs.push((config, score));
                    if top_configs.len() > 50 {
                        top_configs.sort_by(|a, b| b.1.total_cmp(&a.1));
                        top_configs.truncate(5);
                    }
                }

                graph += step;
            }
            semantic += step;
        }
        lexical += step;
    }

    top_configs.sort_by(|a, b| b.1.total_cmp(&a.1));
    top_configs.truncate(5);

    TuningResult {
        best_config,
        best_ndcg_10: best_ndcg,
        baseline_ndcg_10,
        configs_evaluated,
        top_configs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::SearchBenchmarkCorpus;

    #[test]
    fn evaluate_config_with_default_corpus_produces_reasonable_ndcg() {
        let corpus = SearchBenchmarkCorpus::default_corpus();
        let config = WeightConfig::default();
        let ndcg = evaluate_config(&corpus, &config);
        assert!(ndcg > 0.0, "Expected positive NDCG, got {ndcg}");
        assert!(ndcg <= 1.0, "NDCG should be <= 1.0, got {ndcg}");
    }

    #[test]
    fn tune_weights_best_is_at_least_baseline() {
        let corpus = SearchBenchmarkCorpus::default_corpus();
        let result = tune_weights(&corpus, 0.1);
        assert!(
            result.best_ndcg_10 >= result.baseline_ndcg_10 - 1e-10,
            "Best ({}) should be >= baseline ({})",
            result.best_ndcg_10,
            result.baseline_ndcg_10,
        );
    }

    #[test]
    fn tune_weights_evaluates_reasonable_config_count() {
        let corpus = SearchBenchmarkCorpus::default_corpus();
        let result = tune_weights(&corpus, 0.1);
        // With step 0.1 the grid should generate a manageable number of configs.
        assert!(
            result.configs_evaluated > 10,
            "Expected more than 10 configs, got {}",
            result.configs_evaluated,
        );
        assert!(
            result.configs_evaluated < 50_000,
            "Expected fewer than 50k configs, got {}",
            result.configs_evaluated,
        );
    }

    #[test]
    fn tune_weights_best_config_is_normalized() {
        let corpus = SearchBenchmarkCorpus::default_corpus();
        let result = tune_weights(&corpus, 0.1);
        assert!(
            result.best_config.is_normalized(),
            "Best config weights should sum to ~1.0: {:?}",
            result.best_config,
        );
    }

    #[test]
    fn tune_weights_top_configs_are_sorted() {
        let corpus = SearchBenchmarkCorpus::default_corpus();
        let result = tune_weights(&corpus, 0.1);
        assert!(!result.top_configs.is_empty());
        for window in result.top_configs.windows(2) {
            assert!(
                window[0].1 >= window[1].1,
                "Top configs should be sorted descending by score",
            );
        }
    }

    #[test]
    fn evaluate_config_empty_corpus_returns_zero() {
        let corpus = SearchBenchmarkCorpus { queries: vec![] };
        let config = WeightConfig::default();
        assert_eq!(evaluate_config(&corpus, &config), 0.0);
    }
}
