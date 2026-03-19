// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use chrono::{DateTime, Utc};
use kin_model::GraphStore;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::collector::MetricCollector;
use crate::error::Result;
use crate::metrics::*;

/// A complete benchmark run with all collected metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkRun {
    /// Unique ID for this run.
    pub run_id: String,
    /// When the benchmark was executed.
    pub timestamp: DateTime<Utc>,
    /// Label for the target (e.g., branch name).
    pub target: String,
    /// All collected metrics.
    pub metrics: Vec<Metric>,
    /// Structured metric results.
    pub dependency_coverage: Option<DependencyCoverage>,
    pub dead_code: Option<DeadCodeAccuracy>,
    pub token_savings: Option<TokenSavings>,
    pub token_to_logic: Option<TokenToLogicRatio>,
    pub test_coverage: Option<DependencyCoverage>,
    /// Latency percentiles across all timed operations in this run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_percentiles: Option<LatencyPercentiles>,
    /// Memory usage during this run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryMetric>,
    /// Throughput measurements collected during this run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub throughput: Vec<ThroughputMetric>,
}

/// Options for a benchmark run.
#[derive(Debug, Clone)]
pub struct BenchOptions {
    /// Label for this benchmark target.
    pub target: String,
    /// Run reliability metrics (dependency coverage, dead code).
    pub reliability: bool,
    /// Run economic metrics (token savings).
    pub economic: bool,
    /// Average tokens per file for naive estimate.
    pub avg_tokens_per_file: u64,
    /// Average tokens per entity for semantic estimate.
    pub avg_tokens_per_entity: u64,
    /// Total tokens consumed (for ratio calculation).
    pub total_tokens_consumed: u64,
}

impl Default for BenchOptions {
    fn default() -> Self {
        Self {
            target: "HEAD".to_string(),
            reliability: true,
            economic: true,
            avg_tokens_per_file: 500,
            avg_tokens_per_entity: 50,
            total_tokens_consumed: 0,
        }
    }
}

/// Run a complete benchmark suite against the graph store.
pub fn run_benchmarks<G>(graph: &G, opts: &BenchOptions) -> Result<BenchmarkRun>
where
    G: GraphStore,
{
    let run_id = uuid::Uuid::new_v4().to_string();
    let mut metrics = Vec::new();
    let mut dependency_coverage = None;
    let mut dead_code = None;
    let mut token_savings = None;
    let mut token_to_logic = None;
    let mut test_coverage = None;

    if opts.reliability {
        // Dependency coverage (timed).
        let (dep_cov, dep_metric) = MetricCollector::time_operation(
            "dependency_coverage_collection",
            MetricCategory::Reliability,
            || MetricCollector::collect_dependency_coverage(graph),
        );
        metrics.push(dep_metric);
        if let Ok(cov) = dep_cov {
            dependency_coverage = Some(cov);
        }

        // Dead code stats (timed).
        let (dead_stats, dead_metric) = MetricCollector::time_operation(
            "dead_code_detection",
            MetricCategory::Reliability,
            || MetricCollector::collect_dead_code_stats(graph),
        );
        metrics.push(dead_metric);
        if let Ok(stats) = dead_stats {
            dead_code = Some(stats);
        }

        // Test coverage (timed).
        let (test_cov, test_metric) = MetricCollector::time_operation(
            "test_coverage_collection",
            MetricCategory::Reliability,
            || MetricCollector::collect_test_coverage(graph),
        );
        metrics.push(test_metric);
        if let Ok(cov) = test_cov {
            test_coverage = Some(cov);
        }
    }

    if opts.economic {
        // Token savings.
        let (savings, savings_metric) = MetricCollector::time_operation(
            "token_savings_collection",
            MetricCategory::Economic,
            || {
                MetricCollector::collect_token_savings(
                    graph,
                    opts.avg_tokens_per_file,
                    opts.avg_tokens_per_entity,
                )
            },
        );
        metrics.push(savings_metric);
        if let Ok(s) = savings {
            token_savings = Some(s);
        }

        // Token-to-logic ratio.
        if opts.total_tokens_consumed > 0 {
            let (ratio, ratio_metric) = MetricCollector::time_operation(
                "token_to_logic_ratio",
                MetricCategory::Economic,
                || {
                    MetricCollector::collect_token_to_logic_ratio(
                        graph,
                        opts.total_tokens_consumed,
                    )
                },
            );
            metrics.push(ratio_metric);
            if let Ok(r) = ratio {
                token_to_logic = Some(r);
            }
        }
    }

    // Compute latency percentiles from all Duration metrics.
    let durations: Vec<f64> = metrics
        .iter()
        .filter_map(|m| {
            if let MetricValue::Duration(d) = &m.value {
                Some(d.0)
            } else {
                None
            }
        })
        .collect();
    let latency_percentiles = LatencyPercentiles::from_samples(&durations);

    info!(
        run_id = %run_id,
        target = %opts.target,
        metric_count = metrics.len(),
        "benchmark run complete"
    );

    Ok(BenchmarkRun {
        run_id,
        timestamp: Utc::now(),
        target: opts.target.clone(),
        metrics,
        dependency_coverage,
        dead_code,
        token_savings,
        token_to_logic,
        test_coverage,
        latency_percentiles,
        memory: None,
        throughput: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_options_default() {
        let opts = BenchOptions::default();
        assert_eq!(opts.target, "HEAD");
        assert!(opts.reliability);
        assert!(opts.economic);
        assert_eq!(opts.avg_tokens_per_file, 500);
    }

    #[test]
    fn benchmark_run_serializes() {
        let run = BenchmarkRun {
            run_id: "test-001".to_string(),
            timestamp: Utc::now(),
            target: "main".to_string(),
            metrics: vec![],
            dependency_coverage: None,
            dead_code: None,
            token_savings: Some(TokenSavings {
                naive_file_tokens: 10000,
                semantic_tokens: 4000,
                tokens_saved: 6000,
                savings_pct: 60.0,
            }),
            token_to_logic: None,
            test_coverage: None,
            latency_percentiles: None,
            memory: None,
            throughput: Vec::new(),
        };

        let json = serde_json::to_string(&run).unwrap();
        let parsed: BenchmarkRun = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.run_id, "test-001");
        assert!(parsed.token_savings.is_some());
    }
}
