// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

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
    /// Primary language of the source file (e.g. "TypeScript", "Go").
    #[serde(default)]
    pub language: String,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
}

/// Aggregated context quality scores for a single language.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageContextQuality {
    pub language: String,
    pub sample_count: usize,
    pub avg_precision: f64,
    pub avg_recall: f64,
    pub avg_f1_score: f64,
    pub min_f1_score: f64,
    pub max_f1_score: f64,
}

impl LanguageContextQuality {
    /// Compute per-language aggregates from a slice of individual measurements.
    pub fn aggregate(scores: &[ContextQuality]) -> Vec<Self> {
        use std::collections::BTreeMap;

        let mut by_lang: BTreeMap<&str, Vec<&ContextQuality>> = BTreeMap::new();
        for s in scores {
            let lang = if s.language.is_empty() {
                "Unknown"
            } else {
                s.language.as_str()
            };
            by_lang.entry(lang).or_default().push(s);
        }

        by_lang
            .into_iter()
            .map(|(lang, samples)| {
                let n = samples.len();
                let sum_p: f64 = samples.iter().map(|s| s.precision).sum();
                let sum_r: f64 = samples.iter().map(|s| s.recall).sum();
                let sum_f: f64 = samples.iter().map(|s| s.f1_score).sum();
                let min_f = samples
                    .iter()
                    .map(|s| s.f1_score)
                    .fold(f64::INFINITY, f64::min);
                let max_f = samples
                    .iter()
                    .map(|s| s.f1_score)
                    .fold(f64::NEG_INFINITY, f64::max);
                LanguageContextQuality {
                    language: lang.to_string(),
                    sample_count: n,
                    avg_precision: sum_p / n as f64,
                    avg_recall: sum_r / n as f64,
                    avg_f1_score: sum_f / n as f64,
                    min_f1_score: min_f,
                    max_f1_score: max_f,
                }
            })
            .collect()
    }
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

// -- Latency Percentiles --

/// Latency percentile distribution computed from a set of duration samples.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyPercentiles {
    pub p50: f64,
    pub p75: f64,
    pub p90: f64,
    pub p95: f64,
    pub p99: f64,
    pub max: f64,
    pub count: usize,
}

impl LatencyPercentiles {
    /// Compute percentiles from a slice of duration samples (in milliseconds).
    ///
    /// Returns `None` if the slice is empty.
    pub fn from_samples(samples: &[f64]) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = sorted.len();
        Some(Self {
            p50: percentile_at(&sorted, 50.0),
            p75: percentile_at(&sorted, 75.0),
            p90: percentile_at(&sorted, 90.0),
            p95: percentile_at(&sorted, 95.0),
            p99: percentile_at(&sorted, 99.0),
            max: sorted[n - 1],
            count: n,
        })
    }
}

/// Compute the value at a given percentile (0–100) using nearest-rank.
fn percentile_at(sorted: &[f64], pct: f64) -> f64 {
    let n = sorted.len();
    if n == 0 {
        return 0.0;
    }
    if n == 1 {
        return sorted[0];
    }
    let rank = (pct / 100.0 * (n - 1) as f64).round() as usize;
    sorted[rank.min(n - 1)]
}

// -- Throughput Metrics --

/// Result of a throughput benchmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputMetric {
    /// Operations per second.
    pub ops_per_sec: f64,
    /// Total wall-clock duration in milliseconds.
    pub total_duration_ms: f64,
    /// Number of iterations performed.
    pub iterations: usize,
    /// Name of the operation measured.
    pub operation: String,
}

// -- Memory Metrics --

/// Memory measurement around an operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMetric {
    /// RSS before the operation (kilobytes).
    pub rss_before_kb: u64,
    /// RSS after the operation (kilobytes).
    pub rss_after_kb: u64,
    /// Change in RSS (kilobytes, can be negative if memory was freed).
    pub rss_delta_kb: i64,
    /// Peak RSS observed during the operation (kilobytes).
    /// May equal rss_after_kb if no peak tracking is available.
    pub peak_kb: u64,
}

impl MemoryMetric {
    /// Capture the current process RSS in kilobytes.
    /// Returns 0 if measurement is not available on this platform.
    pub fn current_rss_kb() -> u64 {
        current_rss_kb_impl()
    }
}

#[cfg(target_os = "macos")]
fn current_rss_kb_impl() -> u64 {
    // Use mach_task_info on macOS
    use std::mem;
    #[repr(C)]
    struct MachTaskBasicInfo {
        virtual_size: u64,
        resident_size: u64,
        resident_size_max: u64,
        user_time: [u32; 2],
        system_time: [u32; 2],
        policy: i32,
        suspend_count: i32,
    }
    extern "C" {
        fn mach_task_self() -> u32;
        fn task_info(
            target_task: u32,
            flavor: u32,
            task_info_out: *mut MachTaskBasicInfo,
            task_info_count: *mut u32,
        ) -> i32;
    }
    const MACH_TASK_BASIC_INFO: u32 = 20;
    unsafe {
        let mut info: MachTaskBasicInfo = mem::zeroed();
        let mut count = (mem::size_of::<MachTaskBasicInfo>() / mem::size_of::<u32>()) as u32;
        let kr = task_info(
            mach_task_self(),
            MACH_TASK_BASIC_INFO,
            &mut info,
            &mut count,
        );
        if kr == 0 {
            info.resident_size / 1024
        } else {
            0
        }
    }
}

#[cfg(target_os = "linux")]
fn current_rss_kb_impl() -> u64 {
    // Read VmRSS from /proc/self/status
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        })
        .unwrap_or(0)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn current_rss_kb_impl() -> u64 {
    0
}

// -- Search Relevance Metrics --

/// Search relevance quality metrics for a single benchmark query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchRelevanceMetric {
    /// Name of the benchmark query evaluated.
    pub query_name: String,
    /// NDCG@5 — ranking quality in top 5 results.
    pub ndcg_5: f64,
    /// NDCG@10 — ranking quality in top 10 results.
    pub ndcg_10: f64,
    /// Mean Reciprocal Rank — how quickly the first relevant result appears.
    pub mrr: f64,
    /// Precision@5 — fraction of top 5 that are relevant.
    pub precision_5: f64,
    /// Recall@10 — fraction of all relevant items found in top 10.
    pub recall_10: f64,
}

/// Execution substrate used for an assistant task benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkSubstrate {
    Git,
    Kin,
}

impl BenchmarkSubstrate {
    pub fn as_str(&self) -> &'static str {
        match self {
            BenchmarkSubstrate::Git => "git",
            BenchmarkSubstrate::Kin => "kin",
        }
    }
}

/// Provenance of a benchmark run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AssistantRunSource {
    /// Values were entered explicitly by a user or script.
    #[default]
    ManualFlags,
    /// Derived from a raw assistant artifact or session log.
    ArtifactImport,
    /// Produced by a dedicated live harness executing the task end to end.
    LiveHarness,
}

impl AssistantRunSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            AssistantRunSource::ManualFlags => "manual_flags",
            AssistantRunSource::ArtifactImport => "artifact_import",
            AssistantRunSource::LiveHarness => "live_harness",
        }
    }
}

/// A single assistant task run recorded against a specific substrate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssistantTaskRun {
    pub task_name: String,
    pub assistant_name: String,
    pub model_name: Option<String>,
    pub substrate: BenchmarkSubstrate,
    pub duration_ms: DurationMs,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub estimated_cost_usd: f64,
    pub first_pass_success: bool,
    pub validation_passed: bool,
    #[serde(default)]
    pub run_source: AssistantRunSource,
    pub notes: Option<String>,
    pub recorded_at: DateTime<Utc>,
}

impl AssistantTaskRun {
    pub fn normalized(mut self) -> Self {
        if self.total_tokens == 0 {
            self.total_tokens = self.input_tokens.saturating_add(self.output_tokens);
        }
        self
    }
}

/// Side-by-side Git vs Kin comparison for one task/assistant pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssistantTaskComparison {
    pub task_name: String,
    pub assistant_name: String,
    pub model_name: Option<String>,
    pub git_samples: u64,
    pub kin_samples: u64,
    pub git_avg_duration_ms: f64,
    pub kin_avg_duration_ms: f64,
    pub git_avg_total_tokens: f64,
    pub kin_avg_total_tokens: f64,
    pub git_avg_cost_usd: f64,
    pub kin_avg_cost_usd: f64,
    pub git_first_pass_rate: f64,
    pub kin_first_pass_rate: f64,
    pub git_validation_rate: f64,
    pub kin_validation_rate: f64,
    pub duration_saved_ms_by_kin: f64,
    pub duration_saved_pct_by_kin: f64,
    pub tokens_saved_by_kin: f64,
    pub tokens_saved_pct_by_kin: f64,
    pub cost_saved_usd_by_kin: f64,
    pub cost_saved_pct_by_kin: f64,
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
        assert_eq!(
            savings.tokens_saved,
            savings.naive_file_tokens - savings.semantic_tokens
        );
    }

    // -- LatencyPercentiles tests --

    #[test]
    fn latency_percentiles_from_samples() {
        let samples: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let p = LatencyPercentiles::from_samples(&samples).unwrap();
        assert_eq!(p.count, 100);
        assert!((p.p50 - 50.0).abs() < 1.5);
        assert!((p.p90 - 90.0).abs() < 1.5);
        assert!((p.p99 - 99.0).abs() < 1.5);
        assert!((p.max - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn latency_percentiles_single_sample() {
        let p = LatencyPercentiles::from_samples(&[42.0]).unwrap();
        assert_eq!(p.count, 1);
        assert!((p.p50 - 42.0).abs() < f64::EPSILON);
        assert!((p.p99 - 42.0).abs() < f64::EPSILON);
        assert!((p.max - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn latency_percentiles_empty() {
        assert!(LatencyPercentiles::from_samples(&[]).is_none());
    }

    #[test]
    fn latency_percentiles_unsorted_input() {
        let samples = vec![100.0, 1.0, 50.0, 25.0, 75.0];
        let p = LatencyPercentiles::from_samples(&samples).unwrap();
        assert!((p.max - 100.0).abs() < f64::EPSILON);
        assert!(p.p50 >= 1.0 && p.p50 <= 100.0);
    }

    #[test]
    fn latency_percentiles_serialization_roundtrip() {
        let p = LatencyPercentiles::from_samples(&[1.0, 2.0, 3.0, 4.0, 5.0]).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        let parsed: LatencyPercentiles = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.count, 5);
        assert!((parsed.max - 5.0).abs() < f64::EPSILON);
    }

    // -- ThroughputMetric tests --

    #[test]
    fn throughput_metric_serialization_roundtrip() {
        let m = ThroughputMetric {
            ops_per_sec: 1500.0,
            total_duration_ms: 666.0,
            iterations: 1000,
            operation: "entity_lookup".into(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let parsed: ThroughputMetric = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.iterations, 1000);
        assert!((parsed.ops_per_sec - 1500.0).abs() < f64::EPSILON);
    }

    // -- MemoryMetric tests --

    #[test]
    fn memory_metric_serialization_roundtrip() {
        let m = MemoryMetric {
            rss_before_kb: 50_000,
            rss_after_kb: 55_000,
            rss_delta_kb: 5_000,
            peak_kb: 56_000,
        };
        let json = serde_json::to_string(&m).unwrap();
        let parsed: MemoryMetric = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.rss_delta_kb, 5_000);
        assert_eq!(parsed.peak_kb, 56_000);
    }

    #[test]
    fn memory_metric_current_rss_returns_nonzero() {
        let rss = MemoryMetric::current_rss_kb();
        // On macOS/Linux this should be nonzero; on other platforms it's 0
        if cfg!(any(target_os = "macos", target_os = "linux")) {
            assert!(rss > 0, "expected non-zero RSS on this platform");
        }
    }

    #[test]
    fn context_quality_language_field_default() {
        let cq: ContextQuality = serde_json::from_str(
            r#"{"entity_name":"foo","precision":0.9,"recall":0.8,"f1_score":0.85}"#,
        )
        .unwrap();
        assert_eq!(cq.language, "");
    }

    #[test]
    fn context_quality_with_language_roundtrip() {
        let cq = ContextQuality {
            entity_name: "bar".into(),
            language: "Go".into(),
            precision: 0.95,
            recall: 0.88,
            f1_score: 0.91,
        };
        let json = serde_json::to_string(&cq).unwrap();
        let parsed: ContextQuality = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.language, "Go");
        assert!((parsed.f1_score - 0.91).abs() < f64::EPSILON);
    }

    #[test]
    fn language_context_quality_aggregate_single_language() {
        let scores = vec![
            ContextQuality {
                entity_name: "a".into(),
                language: "TypeScript".into(),
                precision: 0.9,
                recall: 0.8,
                f1_score: 0.85,
            },
            ContextQuality {
                entity_name: "b".into(),
                language: "TypeScript".into(),
                precision: 0.95,
                recall: 0.90,
                f1_score: 0.92,
            },
        ];
        let agg = LanguageContextQuality::aggregate(&scores);
        assert_eq!(agg.len(), 1);
        assert_eq!(agg[0].language, "TypeScript");
        assert_eq!(agg[0].sample_count, 2);
        assert!((agg[0].avg_f1_score - 0.885).abs() < 0.001);
        assert!((agg[0].min_f1_score - 0.85).abs() < f64::EPSILON);
        assert!((agg[0].max_f1_score - 0.92).abs() < f64::EPSILON);
    }

    #[test]
    fn language_context_quality_aggregate_multi_language() {
        let scores = vec![
            ContextQuality {
                entity_name: "a".into(),
                language: "Go".into(),
                precision: 0.80,
                recall: 0.70,
                f1_score: 0.75,
            },
            ContextQuality {
                entity_name: "b".into(),
                language: "Java".into(),
                precision: 0.90,
                recall: 0.85,
                f1_score: 0.87,
            },
            ContextQuality {
                entity_name: "c".into(),
                language: "Go".into(),
                precision: 0.85,
                recall: 0.80,
                f1_score: 0.82,
            },
        ];
        let agg = LanguageContextQuality::aggregate(&scores);
        assert_eq!(agg.len(), 2);
        // BTreeMap sorts alphabetically: Go first, then Java
        assert_eq!(agg[0].language, "Go");
        assert_eq!(agg[0].sample_count, 2);
        assert!((agg[0].avg_f1_score - 0.785).abs() < 0.001);
        assert_eq!(agg[1].language, "Java");
        assert_eq!(agg[1].sample_count, 1);
    }

    #[test]
    fn language_context_quality_aggregate_empty() {
        let agg = LanguageContextQuality::aggregate(&[]);
        assert!(agg.is_empty());
    }

    #[test]
    fn language_context_quality_aggregate_missing_language() {
        let scores = vec![ContextQuality {
            entity_name: "x".into(),
            language: "".into(),
            precision: 0.9,
            recall: 0.9,
            f1_score: 0.9,
        }];
        let agg = LanguageContextQuality::aggregate(&scores);
        assert_eq!(agg.len(), 1);
        assert_eq!(agg[0].language, "Unknown");
    }

    // -- SearchRelevanceMetric tests --

    #[test]
    fn search_relevance_metric_serialization_roundtrip() {
        let m = SearchRelevanceMetric {
            query_name: "find_auth_handler".into(),
            ndcg_5: 0.85,
            ndcg_10: 0.90,
            mrr: 0.75,
            precision_5: 0.80,
            recall_10: 0.70,
        };
        let json = serde_json::to_string(&m).unwrap();
        let parsed: SearchRelevanceMetric = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.query_name, "find_auth_handler");
        assert!((parsed.ndcg_5 - 0.85).abs() < f64::EPSILON);
        assert!((parsed.ndcg_10 - 0.90).abs() < f64::EPSILON);
        assert!((parsed.mrr - 0.75).abs() < f64::EPSILON);
        assert!((parsed.precision_5 - 0.80).abs() < f64::EPSILON);
        assert!((parsed.recall_10 - 0.70).abs() < f64::EPSILON);
    }

    #[test]
    fn assistant_task_run_normalizes_total_tokens() {
        let run = AssistantTaskRun {
            task_name: "semantic review".into(),
            assistant_name: "Claude Code".into(),
            model_name: Some("opus".into()),
            substrate: BenchmarkSubstrate::Kin,
            duration_ms: DurationMs(1500.0),
            input_tokens: 1200,
            output_tokens: 800,
            total_tokens: 0,
            estimated_cost_usd: 0.12,
            first_pass_success: true,
            validation_passed: true,
            run_source: AssistantRunSource::ArtifactImport,
            notes: None,
            recorded_at: Utc::now(),
        }
        .normalized();

        assert_eq!(run.total_tokens, 2000);
    }
}
