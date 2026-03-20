// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Performance regression detection.
//!
//! Compares two benchmark reports and flags regressions (latency up >20%,
//! throughput down >15%) and improvements (latency down >10%, throughput up >10%).

use std::fmt::Write;

use serde::{Deserialize, Serialize};

use crate::runner::BenchmarkRun;

/// Threshold constants for regression/improvement detection.
const LATENCY_REGRESSION_PCT: f64 = 20.0;
const LATENCY_IMPROVEMENT_PCT: f64 = 10.0;
const THROUGHPUT_REGRESSION_PCT: f64 = 15.0;
const THROUGHPUT_IMPROVEMENT_PCT: f64 = 10.0;

/// A single regression or improvement item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionItem {
    /// Name of the metric (e.g. "entity_lookup throughput", "p95 latency").
    pub metric_name: String,
    /// Baseline value.
    pub baseline_value: f64,
    /// Current value.
    pub current_value: f64,
    /// Percentage change (positive = got worse for regressions, got better for improvements).
    pub change_pct: f64,
    /// Unit of the metric (e.g. "ms", "ops/sec").
    pub unit: String,
}

/// Full regression report comparing two benchmark runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionReport {
    pub baseline_run_id: String,
    pub current_run_id: String,
    pub regressions: Vec<RegressionItem>,
    pub improvements: Vec<RegressionItem>,
    pub stable: Vec<String>,
}

impl RegressionReport {
    /// Whether any regressions were detected.
    pub fn has_regressions(&self) -> bool {
        !self.regressions.is_empty()
    }

    /// Format the report as a markdown table.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();

        writeln!(
            out,
            "## Regression Report: {} vs {}",
            self.baseline_run_id, self.current_run_id
        )
        .unwrap();
        writeln!(out).unwrap();

        if !self.regressions.is_empty() {
            writeln!(out, "### Regressions").unwrap();
            writeln!(out).unwrap();
            writeln!(
                out,
                "| Metric | Baseline | Current | Change |"
            )
            .unwrap();
            writeln!(
                out,
                "|--------|----------|---------|--------|"
            )
            .unwrap();
            for item in &self.regressions {
                writeln!(
                    out,
                    "| {} | {:.2} {} | {:.2} {} | {:+.1}% |",
                    item.metric_name,
                    item.baseline_value,
                    item.unit,
                    item.current_value,
                    item.unit,
                    item.change_pct,
                )
                .unwrap();
            }
            writeln!(out).unwrap();
        }

        if !self.improvements.is_empty() {
            writeln!(out, "### Improvements").unwrap();
            writeln!(out).unwrap();
            writeln!(
                out,
                "| Metric | Baseline | Current | Change |"
            )
            .unwrap();
            writeln!(
                out,
                "|--------|----------|---------|--------|"
            )
            .unwrap();
            for item in &self.improvements {
                writeln!(
                    out,
                    "| {} | {:.2} {} | {:.2} {} | {:+.1}% |",
                    item.metric_name,
                    item.baseline_value,
                    item.unit,
                    item.current_value,
                    item.unit,
                    item.change_pct,
                )
                .unwrap();
            }
            writeln!(out).unwrap();
        }

        if !self.stable.is_empty() {
            writeln!(out, "### Stable").unwrap();
            writeln!(out).unwrap();
            for name in &self.stable {
                writeln!(out, "- {}", name).unwrap();
            }
            writeln!(out).unwrap();
        }

        if self.regressions.is_empty() && self.improvements.is_empty() {
            writeln!(out, "No significant changes detected.").unwrap();
        }

        out
    }
}

/// Compare two benchmark runs and produce a regression report.
pub fn compare_runs(baseline: &BenchmarkRun, current: &BenchmarkRun) -> RegressionReport {
    let mut regressions = Vec::new();
    let mut improvements = Vec::new();
    let mut stable = Vec::new();

    // Compare latency percentiles
    if let (Some(base_lat), Some(curr_lat)) =
        (&baseline.latency_percentiles, &current.latency_percentiles)
    {
        compare_latency("p50", base_lat.p50, curr_lat.p50, &mut regressions, &mut improvements, &mut stable);
        compare_latency("p75", base_lat.p75, curr_lat.p75, &mut regressions, &mut improvements, &mut stable);
        compare_latency("p90", base_lat.p90, curr_lat.p90, &mut regressions, &mut improvements, &mut stable);
        compare_latency("p95", base_lat.p95, curr_lat.p95, &mut regressions, &mut improvements, &mut stable);
        compare_latency("p99", base_lat.p99, curr_lat.p99, &mut regressions, &mut improvements, &mut stable);
        compare_latency("max", base_lat.max, curr_lat.max, &mut regressions, &mut improvements, &mut stable);
    }

    // Compare throughput metrics (matched by operation name)
    for base_tp in &baseline.throughput {
        if let Some(curr_tp) = current.throughput.iter().find(|t| t.operation == base_tp.operation) {
            compare_throughput(
                &base_tp.operation,
                base_tp.ops_per_sec,
                curr_tp.ops_per_sec,
                &mut regressions,
                &mut improvements,
                &mut stable,
            );
        }
    }

    RegressionReport {
        baseline_run_id: baseline.run_id.clone(),
        current_run_id: current.run_id.clone(),
        regressions,
        improvements,
        stable,
    }
}

fn compare_latency(
    name: &str,
    baseline: f64,
    current: f64,
    regressions: &mut Vec<RegressionItem>,
    improvements: &mut Vec<RegressionItem>,
    stable: &mut Vec<String>,
) {
    if baseline <= 0.0 {
        return;
    }
    let change_pct = ((current - baseline) / baseline) * 100.0;
    let label = format!("{} latency", name);

    if change_pct > LATENCY_REGRESSION_PCT {
        regressions.push(RegressionItem {
            metric_name: label,
            baseline_value: baseline,
            current_value: current,
            change_pct,
            unit: "ms".into(),
        });
    } else if change_pct < -LATENCY_IMPROVEMENT_PCT {
        improvements.push(RegressionItem {
            metric_name: label,
            baseline_value: baseline,
            current_value: current,
            change_pct,
            unit: "ms".into(),
        });
    } else {
        stable.push(label);
    }
}

fn compare_throughput(
    operation: &str,
    baseline: f64,
    current: f64,
    regressions: &mut Vec<RegressionItem>,
    improvements: &mut Vec<RegressionItem>,
    stable: &mut Vec<String>,
) {
    if baseline <= 0.0 {
        return;
    }
    // For throughput, a decrease is a regression
    let change_pct = ((current - baseline) / baseline) * 100.0;
    let label = format!("{} throughput", operation);

    if change_pct < -THROUGHPUT_REGRESSION_PCT {
        regressions.push(RegressionItem {
            metric_name: label,
            baseline_value: baseline,
            current_value: current,
            change_pct,
            unit: "ops/sec".into(),
        });
    } else if change_pct > THROUGHPUT_IMPROVEMENT_PCT {
        improvements.push(RegressionItem {
            metric_name: label,
            baseline_value: baseline,
            current_value: current,
            change_pct,
            unit: "ops/sec".into(),
        });
    } else {
        stable.push(label);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{LatencyPercentiles, ThroughputMetric};
    use chrono::Utc;

    fn make_run(
        id: &str,
        latency: Option<LatencyPercentiles>,
        throughput: Vec<ThroughputMetric>,
    ) -> BenchmarkRun {
        BenchmarkRun {
            run_id: id.into(),
            timestamp: Utc::now(),
            target: "test".into(),
            metrics: vec![],
            dependency_coverage: None,
            dead_code: None,
            token_savings: None,
            token_to_logic: None,
            test_coverage: None,
            latency_percentiles: latency,
            memory: None,
            throughput,
        }
    }

    #[test]
    fn no_change_reports_stable() {
        let latency = LatencyPercentiles {
            p50: 10.0,
            p75: 15.0,
            p90: 20.0,
            p95: 25.0,
            p99: 30.0,
            max: 35.0,
            count: 100,
        };
        let baseline = make_run("base", Some(latency.clone()), vec![]);
        let current = make_run("curr", Some(latency), vec![]);
        let report = compare_runs(&baseline, &current);

        assert!(!report.has_regressions());
        assert!(report.improvements.is_empty());
        assert!(!report.stable.is_empty());
    }

    #[test]
    fn detects_latency_regression() {
        let base_lat = LatencyPercentiles {
            p50: 10.0,
            p75: 15.0,
            p90: 20.0,
            p95: 25.0,
            p99: 30.0,
            max: 35.0,
            count: 100,
        };
        // p95 increased by 40%: 25 -> 35
        let curr_lat = LatencyPercentiles {
            p50: 10.0,
            p75: 15.0,
            p90: 20.0,
            p95: 35.0, // +40%
            p99: 30.0,
            max: 35.0,
            count: 100,
        };
        let baseline = make_run("base", Some(base_lat), vec![]);
        let current = make_run("curr", Some(curr_lat), vec![]);
        let report = compare_runs(&baseline, &current);

        assert!(report.has_regressions());
        assert!(report
            .regressions
            .iter()
            .any(|r| r.metric_name == "p95 latency"));
    }

    #[test]
    fn detects_latency_improvement() {
        let base_lat = LatencyPercentiles {
            p50: 10.0,
            p75: 15.0,
            p90: 20.0,
            p95: 25.0,
            p99: 30.0,
            max: 35.0,
            count: 100,
        };
        // p50 decreased by 50%: 10 -> 5
        let curr_lat = LatencyPercentiles {
            p50: 5.0, // -50%
            p75: 15.0,
            p90: 20.0,
            p95: 25.0,
            p99: 30.0,
            max: 35.0,
            count: 100,
        };
        let baseline = make_run("base", Some(base_lat), vec![]);
        let current = make_run("curr", Some(curr_lat), vec![]);
        let report = compare_runs(&baseline, &current);

        assert!(!report.improvements.is_empty());
        assert!(report
            .improvements
            .iter()
            .any(|r| r.metric_name == "p50 latency"));
    }

    #[test]
    fn detects_throughput_regression() {
        let base_tp = vec![ThroughputMetric {
            ops_per_sec: 1000.0,
            total_duration_ms: 1000.0,
            iterations: 1000,
            operation: "entity_lookup".into(),
        }];
        let curr_tp = vec![ThroughputMetric {
            ops_per_sec: 800.0, // -20%
            total_duration_ms: 1250.0,
            iterations: 1000,
            operation: "entity_lookup".into(),
        }];
        let baseline = make_run("base", None, base_tp);
        let current = make_run("curr", None, curr_tp);
        let report = compare_runs(&baseline, &current);

        assert!(report.has_regressions());
        assert!(report
            .regressions
            .iter()
            .any(|r| r.metric_name == "entity_lookup throughput"));
    }

    #[test]
    fn detects_throughput_improvement() {
        let base_tp = vec![ThroughputMetric {
            ops_per_sec: 1000.0,
            total_duration_ms: 1000.0,
            iterations: 1000,
            operation: "query_by_name".into(),
        }];
        let curr_tp = vec![ThroughputMetric {
            ops_per_sec: 1200.0, // +20%
            total_duration_ms: 833.0,
            iterations: 1000,
            operation: "query_by_name".into(),
        }];
        let baseline = make_run("base", None, base_tp);
        let current = make_run("curr", None, curr_tp);
        let report = compare_runs(&baseline, &current);

        assert!(!report.improvements.is_empty());
        assert!(report
            .improvements
            .iter()
            .any(|r| r.metric_name == "query_by_name throughput"));
    }

    #[test]
    fn markdown_output_contains_tables() {
        let base_lat = LatencyPercentiles {
            p50: 10.0,
            p75: 15.0,
            p90: 20.0,
            p95: 25.0,
            p99: 30.0,
            max: 35.0,
            count: 100,
        };
        let curr_lat = LatencyPercentiles {
            p50: 15.0, // +50% regression
            p75: 15.0,
            p90: 20.0,
            p95: 25.0,
            p99: 30.0,
            max: 35.0,
            count: 100,
        };
        let baseline = make_run("base-123", Some(base_lat), vec![]);
        let current = make_run("curr-456", Some(curr_lat), vec![]);
        let report = compare_runs(&baseline, &current);
        let md = report.to_markdown();

        assert!(md.contains("## Regression Report"));
        assert!(md.contains("base-123"));
        assert!(md.contains("curr-456"));
        assert!(md.contains("### Regressions"));
        assert!(md.contains("| Metric |"));
    }

    #[test]
    fn empty_runs_no_changes() {
        let baseline = make_run("base", None, vec![]);
        let current = make_run("curr", None, vec![]);
        let report = compare_runs(&baseline, &current);

        assert!(!report.has_regressions());
        assert!(report.improvements.is_empty());
        assert!(report.stable.is_empty());
        let md = report.to_markdown();
        assert!(md.contains("No significant changes detected"));
    }

    #[test]
    fn regression_report_serialization_roundtrip() {
        let report = RegressionReport {
            baseline_run_id: "base".into(),
            current_run_id: "curr".into(),
            regressions: vec![RegressionItem {
                metric_name: "p95 latency".into(),
                baseline_value: 25.0,
                current_value: 35.0,
                change_pct: 40.0,
                unit: "ms".into(),
            }],
            improvements: vec![],
            stable: vec!["p50 latency".into()],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: RegressionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.regressions.len(), 1);
        assert_eq!(parsed.stable.len(), 1);
    }
}
