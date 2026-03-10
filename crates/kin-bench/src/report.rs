use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
            let avg: f64 = self.velocity.context_warmup_latencies.iter()
                .map(|l| l.latency_ms.0)
                .sum::<f64>()
                / self.velocity.context_warmup_latencies.len() as f64;
            writeln!(out, "  Avg context warmup: {:.1}ms", avg).unwrap();
        }
        if !self.velocity.review_turnarounds.is_empty() {
            let avg: f64 = self.velocity.review_turnarounds.iter()
                .map(|r| r.turnaround_ms.0)
                .sum::<f64>()
                / self.velocity.review_turnarounds.len() as f64;
            writeln!(out, "  Avg review turnaround: {:.1}ms", avg).unwrap();
        }
        if !self.velocity.context_quality_scores.is_empty() {
            let avg_f1: f64 = self.velocity.context_quality_scores.iter()
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

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_report_has_timestamp() {
        let report = BenchmarkReport::new("test");
        assert_eq!(report.title, "test");
        assert!(report.raw_metrics.is_empty());
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
}
