pub mod collector;
pub mod dashboard;
pub mod error;
pub mod metrics;
pub mod report;

pub use collector::MetricCollector;
pub use dashboard::DashboardData;
pub use error::{BenchError, Result};
pub use metrics::{
    CiCdSavings, ContextQuality, ContextWarmupLatency, CostPerTask, DeadCodeAccuracy,
    DependencyCoverage, DurationMs, ImpactAnalysisTime, Metric, MetricCategory, MetricValue,
    ReviewTurnaround, RiskDetectionAccuracy, TokenSavings, TokenToLogicRatio,
};
pub use report::BenchmarkReport;
