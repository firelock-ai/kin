// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::metrics::*;

/// A complete benchmark report containing all metric categories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub title: String,
    pub generated_at: DateTime<Utc>,
    pub repo_name: Option<String>,
    pub velocity: VelocityReport,
    pub reliability: ReliabilityReport,
    pub economic: EconomicReport,
    pub assistant: AssistantBenchmarkReport,
    pub raw_metrics: Vec<Metric>,
}

/// Developer velocity metrics section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VelocityReport {
    pub context_warmup_latencies: Vec<ContextWarmupLatency>,
    pub review_turnarounds: Vec<ReviewTurnaround>,
    pub impact_analysis_times: Vec<ImpactAnalysisTime>,
    pub context_quality_scores: Vec<ContextQuality>,
}

/// Reliability metrics section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReliabilityReport {
    pub dependency_coverage: Option<DependencyCoverage>,
    pub test_coverage: Option<DependencyCoverage>,
    pub risk_detection: Option<RiskDetectionAccuracy>,
    pub dead_code: Option<DeadCodeAccuracy>,
}

/// Economic metrics section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EconomicReport {
    pub token_to_logic: Option<TokenToLogicRatio>,
    pub token_savings: Option<TokenSavings>,
    pub cicd_savings: Option<CiCdSavings>,
    pub cost_per_task: Vec<CostPerTask>,
}

/// Assistant benchmark section for Git vs Kin task comparisons.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssistantBenchmarkReport {
    pub runs: Vec<AssistantTaskRun>,
    pub comparisons: Vec<AssistantTaskComparison>,
}

impl BenchmarkReport {
    /// Create a new empty report.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            generated_at: Utc::now(),
            repo_name: None,
            velocity: VelocityReport::default(),
            reliability: ReliabilityReport::default(),
            economic: EconomicReport::default(),
            assistant: AssistantBenchmarkReport::default(),
            raw_metrics: Vec::new(),
        }
    }

    /// Serialize the report to JSON.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Add a raw metric to the report.
    pub fn add_metric(&mut self, metric: Metric) {
        self.raw_metrics.push(metric);
    }

    /// Add an assistant task run and refresh Git-vs-Kin comparisons.
    pub fn add_assistant_run(&mut self, run: AssistantTaskRun) {
        self.assistant.runs.push(run.normalized());
        self.assistant.comparisons = build_assistant_comparisons(&self.assistant.runs);
    }

    /// Add multiple assistant task runs and refresh Git-vs-Kin comparisons.
    pub fn add_assistant_runs<I>(&mut self, runs: I)
    where
        I: IntoIterator<Item = AssistantTaskRun>,
    {
        self.assistant
            .runs
            .extend(runs.into_iter().map(AssistantTaskRun::normalized));
        self.assistant.comparisons = build_assistant_comparisons(&self.assistant.runs);
    }

    /// Generate a text summary of the report.
    pub fn summary(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();

        writeln!(out, "=== Benchmark Report: {} ===", self.title).unwrap();
        writeln!(out, "Generated: {}", self.generated_at.to_rfc3339()).unwrap();
        if let Some(ref repo) = self.repo_name {
            writeln!(out, "Repository: {}", repo).unwrap();
        }
        writeln!(out).unwrap();

        // Velocity
        writeln!(out, "--- Developer Velocity ---").unwrap();
        if !self.velocity.context_warmup_latencies.is_empty() {
            let avg: f64 = self
                .velocity
                .context_warmup_latencies
                .iter()
                .map(|l| l.latency_ms.0)
                .sum::<f64>()
                / self.velocity.context_warmup_latencies.len() as f64;
            writeln!(out, "  Avg context warmup: {:.1}ms", avg).unwrap();
        }
        if !self.velocity.review_turnarounds.is_empty() {
            let avg: f64 = self
                .velocity
                .review_turnarounds
                .iter()
                .map(|r| r.turnaround_ms.0)
                .sum::<f64>()
                / self.velocity.review_turnarounds.len() as f64;
            writeln!(out, "  Avg review turnaround: {:.1}ms", avg).unwrap();
        }
        if !self.velocity.context_quality_scores.is_empty() {
            let avg_f1: f64 = self
                .velocity
                .context_quality_scores
                .iter()
                .map(|q| q.f1_score)
                .sum::<f64>()
                / self.velocity.context_quality_scores.len() as f64;
            writeln!(out, "  Avg context F1 score: {:.2}", avg_f1).unwrap();
        }
        writeln!(out).unwrap();

        // Reliability
        writeln!(out, "--- Reliability ---").unwrap();
        if let Some(ref dc) = self.reliability.dependency_coverage {
            writeln!(
                out,
                "  Dependency coverage: {:.1}% ({}/{})",
                dc.coverage_pct, dc.entities_with_deps, dc.total_entities,
            )
            .unwrap();
        }
        if let Some(ref tc) = self.reliability.test_coverage {
            writeln!(
                out,
                "  Test coverage: {:.1}% ({}/{})",
                tc.coverage_pct, tc.entities_with_deps, tc.total_entities,
            )
            .unwrap();
        }
        if let Some(ref dead) = self.reliability.dead_code {
            writeln!(out, "  Dead code detected: {}", dead.detected_dead).unwrap();
        }
        writeln!(out).unwrap();

        // Economic
        writeln!(out, "--- Economic ---").unwrap();
        if let Some(ref tl) = self.economic.token_to_logic {
            writeln!(
                out,
                "  Token-to-logic ratio: {:.1} tokens/entity ({} tokens, {} entities)",
                tl.ratio, tl.total_tokens, tl.total_entities,
            )
            .unwrap();
        }
        if let Some(ref ts) = self.economic.token_savings {
            writeln!(
                out,
                "  Token savings: {:.1}% ({} saved of {})",
                ts.savings_pct, ts.tokens_saved, ts.naive_file_tokens,
            )
            .unwrap();
        }
        if let Some(ref ci) = self.economic.cicd_savings {
            writeln!(
                out,
                "  CI/CD savings: {:.1}% ({}/{} builds skipped)",
                ci.savings_pct, ci.skipped_builds, ci.total_builds,
            )
            .unwrap();
        }

        if !self.assistant.comparisons.is_empty() {
            writeln!(out).unwrap();
            writeln!(out, "--- Assistant Benchmarks ---").unwrap();
            for comparison in &self.assistant.comparisons {
                writeln!(
                    out,
                    "  {} [{}]: git {:.1}ms / {:.0} tokens vs kin {:.1}ms / {:.0} tokens ({:.1}% faster, {:.1}% fewer tokens)",
                    comparison.task_name,
                    comparison.assistant_name,
                    comparison.git_avg_duration_ms,
                    comparison.git_avg_total_tokens,
                    comparison.kin_avg_duration_ms,
                    comparison.kin_avg_total_tokens,
                    comparison.duration_saved_pct_by_kin,
                    comparison.tokens_saved_pct_by_kin,
                )
                .unwrap();
            }
        }

        if !self.assistant.runs.is_empty() {
            let manual_runs = self
                .assistant
                .runs
                .iter()
                .filter(|run| matches!(run.run_source, AssistantRunSource::ManualFlags))
                .count();
            let artifact_runs = self
                .assistant
                .runs
                .iter()
                .filter(|run| matches!(run.run_source, AssistantRunSource::ArtifactImport))
                .count();
            let live_runs = self
                .assistant
                .runs
                .iter()
                .filter(|run| matches!(run.run_source, AssistantRunSource::LiveHarness))
                .count();

            writeln!(out).unwrap();
            writeln!(
                out,
                "  Benchmark run sources: {} manual, {} artifact-derived, {} live-harness",
                manual_runs, artifact_runs, live_runs
            )
            .unwrap();
        }

        out
    }
}

#[derive(Default)]
struct SubstrateAggregate {
    samples: u64,
    duration_ms_total: f64,
    total_tokens_total: u64,
    cost_total_usd: f64,
    first_pass_successes: u64,
    validation_successes: u64,
}

impl SubstrateAggregate {
    fn push(&mut self, run: &AssistantTaskRun) {
        self.samples += 1;
        self.duration_ms_total += run.duration_ms.0;
        self.total_tokens_total = self.total_tokens_total.saturating_add(run.total_tokens);
        self.cost_total_usd += run.estimated_cost_usd;
        if run.first_pass_success {
            self.first_pass_successes += 1;
        }
        if run.validation_passed {
            self.validation_successes += 1;
        }
    }

    fn avg_duration_ms(&self) -> f64 {
        average(self.duration_ms_total, self.samples)
    }

    fn avg_total_tokens(&self) -> f64 {
        average(self.total_tokens_total as f64, self.samples)
    }

    fn avg_cost_usd(&self) -> f64 {
        average(self.cost_total_usd, self.samples)
    }

    fn first_pass_rate(&self) -> f64 {
        average(self.first_pass_successes as f64 * 100.0, self.samples)
    }

    fn validation_rate(&self) -> f64 {
        average(self.validation_successes as f64 * 100.0, self.samples)
    }
}

fn average(total: f64, samples: u64) -> f64 {
    if samples == 0 {
        0.0
    } else {
        total / samples as f64
    }
}

fn pct_savings(baseline: f64, improved: f64) -> f64 {
    if baseline <= 0.0 {
        0.0
    } else {
        ((baseline - improved) / baseline) * 100.0
    }
}

fn build_assistant_comparisons(runs: &[AssistantTaskRun]) -> Vec<AssistantTaskComparison> {
    let mut grouped: BTreeMap<
        (String, String, Option<String>),
        (SubstrateAggregate, SubstrateAggregate),
    > = BTreeMap::new();

    for run in runs {
        let entry = grouped
            .entry((
                run.task_name.clone(),
                run.assistant_name.clone(),
                run.model_name.clone(),
            ))
            .or_default();

        match run.substrate {
            BenchmarkSubstrate::Git => entry.0.push(run),
            BenchmarkSubstrate::Kin => entry.1.push(run),
        }
    }

    let mut comparisons = Vec::new();
    for ((task_name, assistant_name, model_name), (git, kin)) in grouped {
        if git.samples == 0 || kin.samples == 0 {
            continue;
        }

        let git_avg_duration_ms = git.avg_duration_ms();
        let kin_avg_duration_ms = kin.avg_duration_ms();
        let git_avg_total_tokens = git.avg_total_tokens();
        let kin_avg_total_tokens = kin.avg_total_tokens();
        let git_avg_cost_usd = git.avg_cost_usd();
        let kin_avg_cost_usd = kin.avg_cost_usd();

        comparisons.push(AssistantTaskComparison {
            task_name,
            assistant_name,
            model_name,
            git_samples: git.samples,
            kin_samples: kin.samples,
            git_avg_duration_ms,
            kin_avg_duration_ms,
            git_avg_total_tokens,
            kin_avg_total_tokens,
            git_avg_cost_usd,
            kin_avg_cost_usd,
            git_first_pass_rate: git.first_pass_rate(),
            kin_first_pass_rate: kin.first_pass_rate(),
            git_validation_rate: git.validation_rate(),
            kin_validation_rate: kin.validation_rate(),
            duration_saved_ms_by_kin: git_avg_duration_ms - kin_avg_duration_ms,
            duration_saved_pct_by_kin: pct_savings(git_avg_duration_ms, kin_avg_duration_ms),
            tokens_saved_by_kin: git_avg_total_tokens - kin_avg_total_tokens,
            tokens_saved_pct_by_kin: pct_savings(git_avg_total_tokens, kin_avg_total_tokens),
            cost_saved_usd_by_kin: git_avg_cost_usd - kin_avg_cost_usd,
            cost_saved_pct_by_kin: pct_savings(git_avg_cost_usd, kin_avg_cost_usd),
        });
    }

    comparisons
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_report_has_timestamp() {
        let report = BenchmarkReport::new("test");
        assert_eq!(report.title, "test");
        assert!(report.raw_metrics.is_empty());
        assert!(report.assistant.runs.is_empty());
    }

    #[test]
    fn report_json_roundtrip() {
        let mut report = BenchmarkReport::new("roundtrip test");
        report.repo_name = Some("test-repo".into());
        report.reliability.dependency_coverage = Some(DependencyCoverage {
            total_entities: 100,
            entities_with_deps: 80,
            coverage_pct: 80.0,
        });

        let json = report.to_json().unwrap();
        let parsed: BenchmarkReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.title, "roundtrip test");
        assert_eq!(parsed.repo_name, Some("test-repo".into()));
        let dc = parsed.reliability.dependency_coverage.unwrap();
        assert_eq!(dc.total_entities, 100);
    }

    #[test]
    fn report_summary_output() {
        let mut report = BenchmarkReport::new("summary test");
        report.reliability.dependency_coverage = Some(DependencyCoverage {
            total_entities: 50,
            entities_with_deps: 40,
            coverage_pct: 80.0,
        });
        report.economic.token_savings = Some(TokenSavings {
            naive_file_tokens: 10000,
            semantic_tokens: 4000,
            tokens_saved: 6000,
            savings_pct: 60.0,
        });

        let summary = report.summary();
        assert!(summary.contains("Benchmark Report"));
        assert!(summary.contains("80.0%"));
        assert!(summary.contains("60.0%"));
    }

    #[test]
    fn assistant_runs_build_git_vs_kin_comparison() {
        let mut report = BenchmarkReport::new("assistant comparison");
        report.add_assistant_runs([
            AssistantTaskRun {
                task_name: "refactor auth".into(),
                assistant_name: "Claude Code".into(),
                model_name: Some("opus".into()),
                substrate: BenchmarkSubstrate::Git,
                duration_ms: DurationMs(4200.0),
                input_tokens: 5000,
                output_tokens: 1200,
                total_tokens: 6200,
                estimated_cost_usd: 0.42,
                first_pass_success: false,
                validation_passed: true,
                run_source: AssistantRunSource::ArtifactImport,
                notes: None,
                recorded_at: Utc::now(),
            },
            AssistantTaskRun {
                task_name: "refactor auth".into(),
                assistant_name: "Claude Code".into(),
                model_name: Some("opus".into()),
                substrate: BenchmarkSubstrate::Kin,
                duration_ms: DurationMs(2500.0),
                input_tokens: 1800,
                output_tokens: 700,
                total_tokens: 2500,
                estimated_cost_usd: 0.17,
                first_pass_success: true,
                validation_passed: true,
                run_source: AssistantRunSource::ArtifactImport,
                notes: None,
                recorded_at: Utc::now(),
            },
        ]);

        assert_eq!(report.assistant.comparisons.len(), 1);
        let comparison = &report.assistant.comparisons[0];
        assert_eq!(comparison.task_name, "refactor auth");
        assert_eq!(comparison.assistant_name, "Claude Code");
        assert!(comparison.duration_saved_ms_by_kin > 0.0);
        assert!(comparison.tokens_saved_by_kin > 0.0);
        assert!(report.summary().contains("Assistant Benchmarks"));
    }
}
