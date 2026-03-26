// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Search relevance benchmark integration.
//!
//! Evaluates search ranking quality using `kin-search`'s benchmark corpus,
//! producing per-query and aggregate relevance metrics compatible with the
//! `kin-bench` reporting pipeline.

use serde::{Deserialize, Serialize};

use kin_search::corpus::SearchBenchmarkCorpus;
use kin_search::relevance::evaluate_relevance;
use kin_search::tuner;
use kin_search::{rank_candidates_with_config, WeightConfig};

use crate::metrics::SearchRelevanceMetric;

/// Aggregated search relevance report across the entire benchmark corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchRelevanceReport {
    /// Per-query metrics.
    pub per_query: Vec<SearchRelevanceMetric>,
    /// Mean NDCG@5 across all queries.
    pub mean_ndcg_5: f64,
    /// Mean NDCG@10 across all queries.
    pub mean_ndcg_10: f64,
    /// Mean MRR across all queries.
    pub mean_mrr: f64,
    /// Mean Precision@5 across all queries.
    pub mean_precision_5: f64,
    /// Mean Recall@10 across all queries.
    pub mean_recall_10: f64,
    /// The weight configuration used.
    pub weight_config: WeightConfig,
}

/// Run search relevance benchmarks using default weights and corpus.
pub fn bench_search_relevance() -> SearchRelevanceReport {
    bench_search_relevance_with_config(&WeightConfig::default())
}

/// Run search relevance benchmarks with a specific weight configuration.
pub fn bench_search_relevance_with_config(config: &WeightConfig) -> SearchRelevanceReport {
    let corpus = SearchBenchmarkCorpus::default_corpus();
    let mut per_query = Vec::with_capacity(corpus.len());

    for bq in &corpus.queries {
        let results = rank_candidates_with_config(&bq.query, &bq.candidates, config);
        let report = evaluate_relevance(&results, &bq.judgments);
        per_query.push(SearchRelevanceMetric {
            query_name: bq.name.clone(),
            ndcg_5: report.ndcg_5,
            ndcg_10: report.ndcg_10,
            mrr: report.mrr,
            precision_5: report.precision_5,
            recall_10: report.recall_10,
        });
    }

    let n = per_query.len() as f64;
    let mean = |f: fn(&SearchRelevanceMetric) -> f64| -> f64 {
        if n == 0.0 {
            0.0
        } else {
            per_query.iter().map(f).sum::<f64>() / n
        }
    };

    SearchRelevanceReport {
        mean_ndcg_5: mean(|m| m.ndcg_5),
        mean_ndcg_10: mean(|m| m.ndcg_10),
        mean_mrr: mean(|m| m.mrr),
        mean_precision_5: mean(|m| m.precision_5),
        mean_recall_10: mean(|m| m.recall_10),
        weight_config: config.clone(),
        per_query,
    }
}

/// Run weight tuning against the benchmark corpus and return the optimal report.
///
/// Step size controls the granularity of the grid search (smaller = more precise but slower).
/// Recommended: 0.05 for thorough search, 0.10 for quick evaluation.
pub fn bench_search_tuning(step: f32) -> (SearchRelevanceReport, tuner::TuningResult) {
    let corpus = SearchBenchmarkCorpus::default_corpus();
    let tuning = tuner::tune_weights(&corpus, step);
    let report = bench_search_relevance_with_config(&tuning.best_config);
    (report, tuning)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_search_relevance_returns_per_query_entries() {
        let report = bench_search_relevance();
        let corpus = SearchBenchmarkCorpus::default_corpus();
        assert_eq!(
            report.per_query.len(),
            corpus.len(),
            "should have one metric per corpus query"
        );
    }

    #[test]
    fn mean_metrics_in_valid_range() {
        let report = bench_search_relevance();
        assert!(report.mean_ndcg_5 >= 0.0 && report.mean_ndcg_5 <= 1.0);
        assert!(report.mean_ndcg_10 >= 0.0 && report.mean_ndcg_10 <= 1.0);
        assert!(report.mean_mrr >= 0.0 && report.mean_mrr <= 1.0);
        assert!(report.mean_precision_5 >= 0.0 && report.mean_precision_5 <= 1.0);
        assert!(report.mean_recall_10 >= 0.0 && report.mean_recall_10 <= 1.0);
    }

    #[test]
    fn default_weights_produce_reasonable_ndcg() {
        let report = bench_search_relevance();
        assert!(
            report.mean_ndcg_10 > 0.5,
            "default weights should produce NDCG@10 > 0.5, got {}",
            report.mean_ndcg_10
        );
    }

    #[test]
    fn with_config_matches_default() {
        let default_report = bench_search_relevance();
        let explicit_report = bench_search_relevance_with_config(&WeightConfig::default());
        assert!(
            (default_report.mean_ndcg_10 - explicit_report.mean_ndcg_10).abs() < f64::EPSILON,
            "bench_search_relevance and bench_search_relevance_with_config(default) should match"
        );
    }

    #[test]
    fn search_relevance_report_serialization_roundtrip() {
        let report = bench_search_relevance();
        let json = serde_json::to_string(&report).unwrap();
        let parsed: SearchRelevanceReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.per_query.len(), report.per_query.len());
        assert!((parsed.mean_ndcg_10 - report.mean_ndcg_10).abs() < f64::EPSILON);
        assert_eq!(parsed.weight_config, report.weight_config);
    }
}
