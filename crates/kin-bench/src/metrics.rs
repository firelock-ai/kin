use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single metric measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    pub name: String,
    pub category: MetricCategory,
    pub value: MetricValue,
    pub unit: String,
    pub timestamp: DateTime<Utc>,
    pub labels: Vec<(String, String)>,
}

/// Categories of metrics as defined in PLAN.md Section 6.9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MetricCategory {
    DeveloperVelocity,
    Reliability,
    Economic,
}

/// Metric value — supports numeric and percentage types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricValue {
    Count(u64),
    Duration(DurationMs),
    Percentage(f64),
    Ratio(f64, f64),
    Bytes(u64),
    Tokens(u64),
}

impl MetricValue {
    pub fn as_f64(&self) -> f64 {
        match self {
            MetricValue::Count(n) => *n as f64,
            MetricValue::Duration(d) => d.0,
            MetricValue::Percentage(p) => *p,
            MetricValue::Ratio(a, b) => {
                if *b == 0.0 {
                    0.0
                } else {
                    a / b
                }
            }
            MetricValue::Bytes(b) => *b as f64,
            MetricValue::Tokens(t) => *t as f64,
        }
    }
}

/// Duration in milliseconds.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DurationMs(pub f64);

impl DurationMs {
    pub fn from_millis(ms: f64) -> Self {
        Self(ms)
    }

    pub fn from_std(d: std::time::Duration) -> Self {
        Self(d.as_secs_f64() * 1000.0)
    }
}

// -- Developer Velocity Metrics --

/// Context warm-up latency (time to build a context pack).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextWarmupLatency {
    pub entity_name: String,
    pub token_budget: u32,
    pub latency_ms: DurationMs,
}

/// Semantic review turnaround time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewTurnaround {
    pub change_id: String,
    pub entity_count: usize,
    pub turnaround_ms: DurationMs,
}

/// Time to complete impact analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAnalysisTime {
    pub changed_entity_count: usize,
    pub affected_entity_count: usize,
    pub analysis_ms: DurationMs,
}

/// Context precision/recall for a context pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextQuality {
    pub entity_name: String,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
}

// -- Reliability Metrics --

/// Dependency coverage: fraction of entities with complete dependency info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyCoverage {
    pub total_entities: u64,
    pub entities_with_deps: u64,
    pub coverage_pct: f64,
}

/// Risk detection accuracy (if ground truth is available).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskDetectionAccuracy {
    pub true_positives: u64,
    pub false_positives: u64,
    pub false_negatives: u64,
    pub precision: f64,
    pub recall: f64,
}

/// Orphan/dead-code detection accuracy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadCodeAccuracy {
    pub detected_dead: u64,
    pub confirmed_dead: u64,
    pub false_positives: u64,
}

// -- Economic Metrics --

/// Token-to-logic ratio: tokens used vs semantic entities captured.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenToLogicRatio {
    pub total_tokens: u64,
    pub total_entities: u64,
    pub ratio: f64,
}

/// Token waste avoided by semantic context vs file dumping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSavings {
    pub naive_file_tokens: u64,
    pub semantic_tokens: u64,
    pub tokens_saved: u64,
    pub savings_pct: f64,
}

/// CI/CD savings from semantic build skipping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiCdSavings {
    pub total_builds: u64,
    pub skipped_builds: u64,
    pub savings_pct: f64,
    pub estimated_time_saved_ms: DurationMs,
}

/// Cost per task estimate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostPerTask {
    pub task_name: String,
    pub tokens_used: u64,
    pub estimated_cost_usd: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_value_as_f64() {
        assert_eq!(MetricValue::Count(42).as_f64(), 42.0);
        assert_eq!(MetricValue::Percentage(0.95).as_f64(), 0.95);
        assert_eq!(MetricValue::Ratio(3.0, 4.0).as_f64(), 0.75);
        assert_eq!(MetricValue::Ratio(1.0, 0.0).as_f64(), 0.0);
        assert_eq!(MetricValue::Tokens(1000).as_f64(), 1000.0);
    }

    #[test]
    fn duration_ms_from_std() {
        let d = std::time::Duration::from_millis(500);
        let ms = DurationMs::from_std(d);
        assert!((ms.0 - 500.0).abs() < 0.01);
    }

    #[test]
    fn metric_serialization_roundtrip() {
        let metric = Metric {
            name: "context_warmup".into(),
            category: MetricCategory::DeveloperVelocity,
            value: MetricValue::Duration(DurationMs(42.5)),
            unit: "ms".into(),
            timestamp: Utc::now(),
            labels: vec![("entity".into(), "foo".into())],
        };

        let json = serde_json::to_string(&metric).unwrap();
        let parsed: Metric = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "context_warmup");
        assert_eq!(parsed.category, MetricCategory::DeveloperVelocity);
    }

    #[test]
    fn token_savings_calculation() {
        let savings = TokenSavings {
            naive_file_tokens: 10000,
            semantic_tokens: 4000,
            tokens_saved: 6000,
            savings_pct: 60.0,
        };
        assert_eq!(savings.tokens_saved, savings.naive_file_tokens - savings.semantic_tokens);
    }
}
