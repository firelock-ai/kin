// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};

use crate::metrics::BenchmarkSubstrate;
use crate::report::BenchmarkReport;

/// Dashboard-ready data output for kin-local-ui and external dashboards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardData {
    pub repo_name: Option<String>,
    pub summary: DashboardSummary,
    pub velocity_chart: Vec<ChartDataPoint>,
    pub token_savings_chart: Vec<ChartDataPoint>,
    pub coverage_gauges: CoverageGauges,
    pub assistant_comparison: Vec<AssistantStats>,
    pub assistant_task_comparisons: Vec<TaskComparisonCard>,
}

/// High-level summary numbers for the dashboard.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DashboardSummary {
    pub total_entities: u64,
    pub dependency_coverage_pct: f64,
    pub test_coverage_pct: f64,
    pub token_savings_pct: f64,
    pub avg_context_warmup_ms: f64,
    pub avg_review_turnaround_ms: f64,
    pub dead_code_count: u64,
    pub risk_level: String,
}

/// A single data point for time-series charts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartDataPoint {
    pub label: String,
    pub value: f64,
    pub unit: String,
}

/// Gauge data for coverage metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageGauges {
    pub dependency_coverage: f64,
    pub test_coverage: f64,
    pub contract_coverage: f64,
}

/// Stats for side-by-side assistant comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssistantStats {
    pub assistant_name: String,
    pub substrate: BenchmarkSubstrate,
    pub tasks_completed: u64,
    pub tokens_used: u64,
    pub avg_duration_ms: f64,
    pub avg_cost_per_task_usd: f64,
    pub first_pass_rate: f64,
    pub validation_pass_rate: f64,
}

/// Per-task Git vs Kin comparison cards for dashboards and demos.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskComparisonCard {
    pub task_name: String,
    pub assistant_name: String,
    pub git_avg_duration_ms: f64,
    pub kin_avg_duration_ms: f64,
    pub git_avg_total_tokens: f64,
    pub kin_avg_total_tokens: f64,
    pub duration_saved_pct_by_kin: f64,
    pub tokens_saved_pct_by_kin: f64,
    pub cost_saved_pct_by_kin: f64,
}

impl DashboardData {
    /// Generate dashboard data from a benchmark report.
    pub fn from_report(report: &BenchmarkReport) -> Self {
        let mut summary = DashboardSummary::default();

        // Populate from reliability
        if let Some(ref dc) = report.reliability.dependency_coverage {
            summary.total_entities = dc.total_entities;
            summary.dependency_coverage_pct = dc.coverage_pct;
        }
        if let Some(ref tc) = report.reliability.test_coverage {
            summary.test_coverage_pct = tc.coverage_pct;
        }
        if let Some(ref dead) = report.reliability.dead_code {
            summary.dead_code_count = dead.detected_dead;
        }

        // Populate from economic
        if let Some(ref ts) = report.economic.token_savings {
            summary.token_savings_pct = ts.savings_pct;
        }

        // Populate from velocity
        if !report.velocity.context_warmup_latencies.is_empty() {
            summary.avg_context_warmup_ms = report
                .velocity
                .context_warmup_latencies
                .iter()
                .map(|l| l.latency_ms.0)
                .sum::<f64>()
                / report.velocity.context_warmup_latencies.len() as f64;
        }
        if !report.velocity.review_turnarounds.is_empty() {
            summary.avg_review_turnaround_ms = report
                .velocity
                .review_turnarounds
                .iter()
                .map(|r| r.turnaround_ms.0)
                .sum::<f64>()
                / report.velocity.review_turnarounds.len() as f64;
        }

        // Build velocity chart from warmup latencies
        let velocity_chart: Vec<ChartDataPoint> = report
            .velocity
            .context_warmup_latencies
            .iter()
            .map(|l| ChartDataPoint {
                label: l.entity_name.clone(),
                value: l.latency_ms.0,
                unit: "ms".into(),
            })
            .collect();

        // Build token savings chart
        let mut token_savings_chart = Vec::new();
        if let Some(ref ts) = report.economic.token_savings {
            token_savings_chart.push(ChartDataPoint {
                label: "Naive (file dump)".into(),
                value: ts.naive_file_tokens as f64,
                unit: "tokens".into(),
            });
            token_savings_chart.push(ChartDataPoint {
                label: "Semantic".into(),
                value: ts.semantic_tokens as f64,
                unit: "tokens".into(),
            });
            token_savings_chart.push(ChartDataPoint {
                label: "Saved".into(),
                value: ts.tokens_saved as f64,
                unit: "tokens".into(),
            });
        }

        let coverage_gauges = CoverageGauges {
            dependency_coverage: summary.dependency_coverage_pct,
            test_coverage: summary.test_coverage_pct,
            contract_coverage: 0.0, // populated when contract data available
        };

        let assistant_comparison = build_assistant_stats(report);
        let assistant_task_comparisons = report
            .assistant
            .comparisons
            .iter()
            .map(|comparison| TaskComparisonCard {
                task_name: comparison.task_name.clone(),
                assistant_name: comparison.assistant_name.clone(),
                git_avg_duration_ms: comparison.git_avg_duration_ms,
                kin_avg_duration_ms: comparison.kin_avg_duration_ms,
                git_avg_total_tokens: comparison.git_avg_total_tokens,
                kin_avg_total_tokens: comparison.kin_avg_total_tokens,
                duration_saved_pct_by_kin: comparison.duration_saved_pct_by_kin,
                tokens_saved_pct_by_kin: comparison.tokens_saved_pct_by_kin,
                cost_saved_pct_by_kin: comparison.cost_saved_pct_by_kin,
            })
            .collect();

        DashboardData {
            repo_name: report.repo_name.clone(),
            summary,
            velocity_chart,
            token_savings_chart,
            coverage_gauges,
            assistant_comparison,
            assistant_task_comparisons,
        }
    }

    /// Serialize to JSON for consumption by the UI.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

fn build_assistant_stats(report: &BenchmarkReport) -> Vec<AssistantStats> {
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Aggregate {
        tasks_completed: u64,
        tokens_used: u64,
        duration_ms_total: f64,
        cost_total_usd: f64,
        first_pass_successes: u64,
        validation_successes: u64,
    }

    let mut grouped: BTreeMap<(String, BenchmarkSubstrate), Aggregate> = BTreeMap::new();
    for run in &report.assistant.runs {
        let key = (run.assistant_name.clone(), run.substrate);
        let aggregate = grouped.entry(key).or_default();
        aggregate.tasks_completed += 1;
        aggregate.tokens_used = aggregate.tokens_used.saturating_add(run.total_tokens);
        aggregate.duration_ms_total += run.duration_ms.0;
        aggregate.cost_total_usd += run.estimated_cost_usd;
        if run.first_pass_success {
            aggregate.first_pass_successes += 1;
        }
        if run.validation_passed {
            aggregate.validation_successes += 1;
        }
    }

    grouped
        .into_iter()
        .map(|((assistant_name, substrate), aggregate)| {
            let tasks_completed = aggregate.tasks_completed.max(1);
            AssistantStats {
                assistant_name,
                substrate,
                tasks_completed: aggregate.tasks_completed,
                tokens_used: aggregate.tokens_used,
                avg_duration_ms: aggregate.duration_ms_total / tasks_completed as f64,
                avg_cost_per_task_usd: aggregate.cost_total_usd / tasks_completed as f64,
                first_pass_rate: (aggregate.first_pass_successes as f64 / tasks_completed as f64)
                    * 100.0,
                validation_pass_rate: (aggregate.validation_successes as f64
                    / tasks_completed as f64)
                    * 100.0,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::*;
    use crate::report::BenchmarkReport;

    #[test]
    fn dashboard_from_empty_report() {
        let report = BenchmarkReport::new("empty");
        let dashboard = DashboardData::from_report(&report);
        assert_eq!(dashboard.summary.total_entities, 0);
        assert!(dashboard.velocity_chart.is_empty());
        assert!(dashboard.assistant_comparison.is_empty());
        assert!(dashboard.assistant_task_comparisons.is_empty());
    }

    #[test]
    fn dashboard_from_report_with_data() {
        let mut report = BenchmarkReport::new("with data");
        report.repo_name = Some("my-repo".into());
        report.reliability.dependency_coverage = Some(DependencyCoverage {
            total_entities: 200,
            entities_with_deps: 160,
            coverage_pct: 80.0,
        });
        report.economic.token_savings = Some(TokenSavings {
            naive_file_tokens: 50000,
            semantic_tokens: 20000,
            tokens_saved: 30000,
            savings_pct: 60.0,
        });
        report.velocity.context_warmup_latencies = vec![
            ContextWarmupLatency {
                entity_name: "foo".into(),
                token_budget: 8000,
                latency_ms: DurationMs(15.0),
            },
            ContextWarmupLatency {
                entity_name: "bar".into(),
                token_budget: 16000,
                latency_ms: DurationMs(25.0),
            },
        ];

        let dashboard = DashboardData::from_report(&report);
        assert_eq!(dashboard.repo_name, Some("my-repo".into()));
        assert_eq!(dashboard.summary.total_entities, 200);
        assert_eq!(dashboard.summary.dependency_coverage_pct, 80.0);
        assert_eq!(dashboard.summary.token_savings_pct, 60.0);
        assert!((dashboard.summary.avg_context_warmup_ms - 20.0).abs() < 0.01);
        assert_eq!(dashboard.velocity_chart.len(), 2);
        assert_eq!(dashboard.token_savings_chart.len(), 3);
        assert_eq!(dashboard.coverage_gauges.dependency_coverage, 80.0);
    }

    #[test]
    fn dashboard_json_roundtrip() {
        let report = BenchmarkReport::new("json test");
        let dashboard = DashboardData::from_report(&report);
        let json = dashboard.to_json().unwrap();
        let parsed: DashboardData = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.summary.total_entities, 0);
    }

    #[test]
    fn dashboard_populates_assistant_views() {
        let mut report = BenchmarkReport::new("assistant test");
        report.add_assistant_runs([
            AssistantTaskRun {
                task_name: "ship feature".into(),
                assistant_name: "Claude Code".into(),
                model_name: Some("opus".into()),
                substrate: BenchmarkSubstrate::Git,
                duration_ms: DurationMs(5000.0),
                input_tokens: 4000,
                output_tokens: 1000,
                total_tokens: 5000,
                estimated_cost_usd: 0.5,
                first_pass_success: false,
                validation_passed: true,
                run_source: super::super::metrics::AssistantRunSource::ArtifactImport,
                notes: None,
                recorded_at: chrono::Utc::now(),
            },
            AssistantTaskRun {
                task_name: "ship feature".into(),
                assistant_name: "Claude Code".into(),
                model_name: Some("opus".into()),
                substrate: BenchmarkSubstrate::Kin,
                duration_ms: DurationMs(2800.0),
                input_tokens: 1500,
                output_tokens: 600,
                total_tokens: 2100,
                estimated_cost_usd: 0.18,
                first_pass_success: true,
                validation_passed: true,
                run_source: super::super::metrics::AssistantRunSource::ArtifactImport,
                notes: None,
                recorded_at: chrono::Utc::now(),
            },
        ]);

        let dashboard = DashboardData::from_report(&report);
        assert_eq!(dashboard.assistant_comparison.len(), 2);
        assert_eq!(dashboard.assistant_task_comparisons.len(), 1);
        assert!(dashboard.assistant_task_comparisons[0].duration_saved_pct_by_kin > 0.0);
    }
}
