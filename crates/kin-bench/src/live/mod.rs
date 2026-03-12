pub mod detect;
pub mod report;
pub mod resources;
pub mod runner;
pub mod shim_log;
pub mod steps;
pub mod telemetry;
pub mod workspace;

// Re-exports
pub use detect::{detect_available_clis, filter_clis, CliInfo};
pub use report::{
    build_comparisons, format_summary, ArmComparison, ArmResult, LiveBenchmarkReport,
};
pub use resources::{
    capture_process_metrics, capture_system_baseline, sample_system_resources, ProcessMetrics,
    ResourceMonitor, ResourceReport, ResourceSample, SystemBaseline,
};
pub use runner::{
    build_prompt_with_guidance, default_live_tasks, run_task, run_task_with_pid, spawn_task,
    spawn_task_via_kin_with, LiveRunResult, LiveTask, SpawnedTask, TimedLineEvent, Validator,
};
pub use shim_log::{
    format_shim_summary, parse_shim_log, summarize_shim_log, CommandStats, ShimLogEntry,
    ShimLogSummary,
};
pub use steps::{extract_step_trace, StepHotspot, StepKind, StepTrace, StepTraceEntry, StepTraceSummary, SubagentTraceSummary};
pub use telemetry::{extract_tool_usage, format_tool_usage, ToolUsageLog};
pub use workspace::{
    cleanup_stale_workspaces, collect_shim_log, create_isolated_env, shim_log_path,
    BenchWorkspace, ConversionMetrics,
};

use serde::{Deserialize, Serialize};

/// Which arm of the benchmark we're running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkArm {
    /// Pure git — no kin, no special guidance
    Git,
    /// Kin in compatibility mode — projected files at the repo root
    KinCompat,
    /// Kin in native mode — control root plus source-root/session workspaces
    KinNative,
}

impl BenchmarkArm {
    pub fn as_str(&self) -> &'static str {
        match self {
            BenchmarkArm::Git => "git",
            BenchmarkArm::KinCompat => "kin-compat",
            BenchmarkArm::KinNative => "kin-native",
        }
    }
}

impl std::fmt::Display for BenchmarkArm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm_display() {
        assert_eq!(BenchmarkArm::Git.to_string(), "git");
        assert_eq!(BenchmarkArm::KinCompat.to_string(), "kin-compat");
        assert_eq!(BenchmarkArm::KinNative.to_string(), "kin-native");
    }

    #[test]
    fn arm_serialization_roundtrip() {
        let arms = [
            BenchmarkArm::Git,
            BenchmarkArm::KinCompat,
            BenchmarkArm::KinNative,
        ];
        for arm in &arms {
            let json = serde_json::to_string(arm).unwrap();
            let parsed: BenchmarkArm = serde_json::from_str(&json).unwrap();
            assert_eq!(*arm, parsed);
        }
    }

    #[test]
    fn arm_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&BenchmarkArm::KinCompat).unwrap(),
            "\"kin_compat\""
        );
        assert_eq!(
            serde_json::to_string(&BenchmarkArm::KinNative).unwrap(),
            "\"kin_native\""
        );
    }
}
