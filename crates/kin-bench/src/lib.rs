// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

pub mod assistant_import;
pub mod capture;
pub mod collector;
pub mod corpus;
pub mod dashboard;
pub mod error;
pub mod live;
pub mod metrics;
pub mod profiles;
pub mod regression;
pub mod report;
pub mod runner;
mod stress;
pub mod throughput;

pub use assistant_import::{
    load_assistant_runs_from_path, load_from_import_spec, parse_claude_artifact,
    parse_codex_artifact, parse_gemini_artifact, AssistantArtifact, AssistantRunImportSpec,
    AssistantRunSourceFormat,
};
pub use capture::{build_run_from_flags, CaptureConfig, CaptureSession};
pub use collector::MetricCollector;
pub use corpus::{
    CorpusConfig, CorpusEntry, CorpusManifest, CorpusResult, CorpusRunner, CorpusSummary,
    CorpusTier,
};
pub use dashboard::DashboardData;
pub use error::{BenchError, Result};
pub use live::{
    ArmComparison, ArmResult, BenchWorkspace, BenchmarkArm, CliInfo, ConversionMetrics,
    LiveBenchmarkReport, LiveRunResult, LiveTask, PlantedArtifacts, ResourceMonitor,
    ResourceReport, SpawnedTask, StepHotspot, StepKind, StepTrace, StepTraceEntry,
    StepTraceSummary, SystemBaseline, TaskSet, TimedLineEvent,
};
pub use metrics::{
    AssistantTaskComparison, AssistantTaskRun, BenchmarkSubstrate, CiCdSavings, ContextQuality,
    ContextWarmupLatency, CostPerTask, DeadCodeAccuracy, DependencyCoverage, DurationMs,
    ImpactAnalysisTime, LatencyPercentiles, Metric, MetricCategory, MemoryMetric, MetricValue,
    ReviewTurnaround, RiskDetectionAccuracy, ThroughputMetric, TokenSavings, TokenToLogicRatio,
};
pub use profiles::{BenchmarkProfile, ProfileConfig};
pub use regression::{compare_runs, RegressionItem, RegressionReport};
pub use report::BenchmarkReport;
pub use runner::{run_benchmarks, BenchOptions, BenchmarkRun};
pub use throughput::{
    bench_all_throughput, bench_dependency_neighborhood, bench_downstream_impact,
    bench_entity_lookup, bench_query_by_name,
};
