use std::collections::BTreeMap;
use std::fmt::Write;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::BenchmarkArm;
use crate::metrics::AssistantTaskRun;

// ---------------------------------------------------------------------------
// Sibling module types — created by other teammates
// ---------------------------------------------------------------------------
use super::resources::ResourceReport;
use super::shim_log::ShimLogSummary;
use super::steps::{StepKind, StepTraceEntry, StepTraceSummary};
use super::telemetry::ToolUsageLog;
pub use super::resources::SystemBaseline;
pub use super::workspace::ConversionMetrics;

// =========================================================================
// Core structs
// =========================================================================

/// Result of running a single benchmark arm (one task x one CLI x one arm).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmResult {
    pub arm: BenchmarkArm,
    pub task_name: String,
    pub cli_name: String,
    pub run: AssistantTaskRun,
    pub resource_report: Option<ResourceReport>,
    pub transcript_path: Option<String>,
    pub step_trace_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shim_log_path: Option<String>,
    pub step_summary: Option<StepTraceSummary>,
    pub tool_usage: Option<ToolUsageLog>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shim_log_summary: Option<ShimLogSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_trace_entries: Option<Vec<StepTraceEntry>>,
}

/// Comparison across arms for a single (task_name, cli_name) pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmComparison {
    pub task_name: String,
    pub cli_name: String,
    pub git_duration_ms: f64,
    pub kin_compat_duration_ms: Option<f64>,
    pub kin_native_duration_ms: Option<f64>,
    pub git_tokens: u64,
    pub kin_compat_tokens: Option<u64>,
    pub kin_native_tokens: Option<u64>,
    pub git_cost: f64,
    pub kin_compat_cost: Option<f64>,
    pub kin_native_cost: Option<f64>,
    /// (git - kin_native) / git * 100
    pub native_savings_pct: Option<f64>,
    /// (git - kin_compat) / git * 100
    pub compat_savings_pct: Option<f64>,
    /// Human-readable summary of the combined improvement.
    pub combined_improvement: Option<String>,
}

/// Top-level report for a live benchmark session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveBenchmarkReport {
    pub repo_name: String,
    pub commit_sha: Option<String>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    /// Conversion metrics for each Kin arm (compat and native).
    #[serde(default)]
    pub conversions: Vec<ConversionMetrics>,
    pub arms: Vec<ArmResult>,
    pub comparisons: Vec<ArmComparison>,
    pub system_baseline: Option<SystemBaseline>,
}

// =========================================================================
// Implementation
// =========================================================================

impl LiveBenchmarkReport {
    /// Create a new report with `started_at = now` and empty collections.
    pub fn new(repo_name: String) -> Self {
        let now = Utc::now();
        Self {
            repo_name,
            commit_sha: None,
            started_at: now,
            finished_at: now,
            conversions: Vec::new(),
            arms: Vec::new(),
            comparisons: Vec::new(),
            system_baseline: None,
        }
    }

    /// Finalise the report: set `finished_at` to now and compute comparisons.
    pub fn finish(&mut self) {
        self.finished_at = Utc::now();
        self.comparisons = build_comparisons(&self.arms);
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Wall-clock duration of the entire benchmark run in milliseconds.
    pub fn total_duration_ms(&self) -> f64 {
        let diff = self.finished_at - self.started_at;
        diff.num_milliseconds() as f64
    }
}

// =========================================================================
// Comparison builder
// =========================================================================

/// Build per-(task, cli) comparisons from a set of arm results.
pub fn build_comparisons(arms: &[ArmResult]) -> Vec<ArmComparison> {
    // Group by (task_name, cli_name).
    let mut groups: BTreeMap<(String, String), Vec<&ArmResult>> = BTreeMap::new();
    for arm in arms {
        groups
            .entry((arm.task_name.clone(), arm.cli_name.clone()))
            .or_default()
            .push(arm);
    }

    let mut comparisons = Vec::new();
    for ((task_name, cli_name), results) in &groups {
        let git = results.iter().find(|r| r.arm == BenchmarkArm::Git);
        let kin_compat = results.iter().find(|r| r.arm == BenchmarkArm::KinCompat);
        let kin_native = results.iter().find(|r| r.arm == BenchmarkArm::KinNative);

        // We need at least a Git baseline to compute meaningful comparisons.
        let git = match git {
            Some(g) => g,
            None => continue,
        };

        let git_dur = git.run.duration_ms.0;
        let git_tok = git.run.total_tokens;
        let git_cost = git.run.estimated_cost_usd;

        let kin_compat_dur = kin_compat.map(|r| r.run.duration_ms.0);
        let kin_compat_tok = kin_compat.map(|r| r.run.total_tokens);
        let kin_compat_cost = kin_compat.map(|r| r.run.estimated_cost_usd);

        let kin_native_dur = kin_native.map(|r| r.run.duration_ms.0);
        let kin_native_tok = kin_native.map(|r| r.run.total_tokens);
        let kin_native_cost = kin_native.map(|r| r.run.estimated_cost_usd);

        let native_savings_pct = kin_native_dur.and_then(|k| pct_savings(git_dur, k));
        let compat_savings_pct = kin_compat_dur.and_then(|d| pct_savings(git_dur, d));

        let combined_improvement = build_combined_summary(
            native_savings_pct,
            compat_savings_pct,
            kin_native_tok,
            git_tok,
        );

        comparisons.push(ArmComparison {
            task_name: task_name.clone(),
            cli_name: cli_name.clone(),
            git_duration_ms: git_dur,
            kin_compat_duration_ms: kin_compat_dur,
            kin_native_duration_ms: kin_native_dur,
            git_tokens: git_tok,
            kin_compat_tokens: kin_compat_tok,
            kin_native_tokens: kin_native_tok,
            git_cost,
            kin_compat_cost,
            kin_native_cost,
            native_savings_pct,
            compat_savings_pct,
            combined_improvement,
        });
    }

    comparisons
}

// =========================================================================
// Summary formatter
// =========================================================================

/// Produce a CLI-friendly text summary of the benchmark report.
pub fn format_summary(report: &LiveBenchmarkReport) -> String {
    let mut out = String::new();

    // --- header ---
    writeln!(out, "=== Live Benchmark Report ===").unwrap();
    writeln!(out, "Repository: {}", report.repo_name).unwrap();
    if let Some(ref sha) = report.commit_sha {
        writeln!(out, "Commit:     {}", sha).unwrap();
    }
    writeln!(
        out,
        "Started:    {}",
        report.started_at.to_rfc3339()
    )
    .unwrap();
    writeln!(
        out,
        "Finished:   {}",
        report.finished_at.to_rfc3339()
    )
    .unwrap();
    writeln!(
        out,
        "Total time: {:.1}s",
        report.total_duration_ms() / 1000.0
    )
    .unwrap();
    writeln!(out).unwrap();

    // --- conversion metrics ---
    for c in &report.conversions {
        let label = if c.arm.is_empty() { "Kin Conversion" } else { &c.arm };
        let cache_tag = if c.cached { "cached" } else { "fresh" };
        writeln!(out, "--- Kin Conversion ({}, {}) ---", label, cache_tag).unwrap();
        writeln!(out, "  Init time:   {:.1}s", c.init_duration_ms / 1000.0).unwrap();
        writeln!(out, "  Commit time: {:.1}s", c.commit_duration_ms / 1000.0).unwrap();
        writeln!(out, "  Total setup: {:.1}s", c.total_setup_ms / 1000.0).unwrap();
        writeln!(out, "  Entities:    {}", c.entity_count).unwrap();
        writeln!(out, "  Files:       {}", c.file_count).unwrap();
        if c.git_dir_size_bytes > 0 && c.kin_dir_size_bytes > 0 {
            writeln!(
                out,
                "  .git size:   {}",
                format_bytes(c.git_dir_size_bytes)
            )
            .unwrap();
            writeln!(
                out,
                "  .kin size:   {}",
                format_bytes(c.kin_dir_size_bytes)
            )
            .unwrap();
        }
        writeln!(out).unwrap();
    }

    // --- system baseline ---
    if let Some(ref sys) = report.system_baseline {
        writeln!(out, "--- System ---").unwrap();
        writeln!(out, "  Cores: {}", sys.cpu_cores).unwrap();
        writeln!(out, "  RAM:   {}", format_bytes(sys.ram_total_bytes)).unwrap();
        writeln!(out, "  OS:    {} ({})", sys.os_name, sys.arch).unwrap();
        writeln!(out).unwrap();
    }

    // --- results table ---
    if !report.comparisons.is_empty() {
        writeln!(out, "--- Results ---").unwrap();
        writeln!(
            out,
            "{:<24} {:<16} {:>12} {:>12} {:>12} {:>10}",
            "Task", "CLI", "Git", "KinCompat", "KinNative", "Savings"
        )
        .unwrap();
        writeln!(
            out,
            "{}",
            "\u{2500}".repeat(90)
        )
        .unwrap();

        for cmp in &report.comparisons {
            // Duration row
            writeln!(
                out,
                "{:<24} {:<16} {:>12} {:>12} {:>12} {:>10}",
                cmp.task_name,
                cmp.cli_name,
                format_duration(cmp.git_duration_ms),
                cmp.kin_compat_duration_ms
                    .map(format_duration)
                    .unwrap_or_else(|| "-".to_string()),
                cmp.kin_native_duration_ms
                    .map(format_duration)
                    .unwrap_or_else(|| "-".to_string()),
                cmp.native_savings_pct
                    .map(|p| format!("{:.1}%", p))
                    .unwrap_or_else(|| "-".to_string()),
            )
            .unwrap();

            // Token row
            writeln!(
                out,
                "{:<24} {:<16} {:>12} {:>12} {:>12} {:>10}",
                "",
                "",
                format_tokens(cmp.git_tokens),
                cmp.kin_compat_tokens
                    .map(format_tokens)
                    .unwrap_or_else(|| "-".to_string()),
                cmp.kin_native_tokens
                    .map(format_tokens)
                    .unwrap_or_else(|| "-".to_string()),
                cmp.kin_native_tokens
                    .and_then(|k| pct_savings(cmp.git_tokens as f64, k as f64))
                    .map(|p| format!("{:.1}%", p))
                    .unwrap_or_else(|| "-".to_string()),
            )
            .unwrap();

            // Cost row
            writeln!(
                out,
                "{:<24} {:<16} {:>12} {:>12} {:>12} {:>10}",
                "",
                "",
                format_cost(cmp.git_cost),
                cmp.kin_compat_cost
                    .map(format_cost)
                    .unwrap_or_else(|| "-".to_string()),
                cmp.kin_native_cost
                    .map(format_cost)
                    .unwrap_or_else(|| "-".to_string()),
                cmp.kin_native_cost
                    .and_then(|k| pct_savings(cmp.git_cost, k))
                    .map(|p| format!("{:.1}%", p))
                    .unwrap_or_else(|| "-".to_string()),
            )
            .unwrap();
        }
        writeln!(out).unwrap();

        // --- aggregate summary ---
        let savings: Vec<f64> = report
            .comparisons
            .iter()
            .filter_map(|c| c.native_savings_pct)
            .collect();
        if !savings.is_empty() {
            let avg = savings.iter().sum::<f64>() / savings.len() as f64;
            writeln!(
                out,
                "Average Kin-native duration savings: {:.1}% across {} comparison(s)",
                avg,
                savings.len()
            )
            .unwrap();
        }

        let token_savings: Vec<f64> = report
            .comparisons
            .iter()
            .filter_map(|c| {
                let kin = c.kin_native_tokens?;
                pct_savings(c.git_tokens as f64, kin as f64)
            })
            .collect();
        if !token_savings.is_empty() {
            let avg = token_savings.iter().sum::<f64>() / token_savings.len() as f64;
            writeln!(
                out,
                "Average Kin-native token savings: {:.1}% across {} comparison(s)",
                avg,
                token_savings.len()
            )
            .unwrap();
        }
    }

    // --- tool usage section ---
    let tool_logs: Vec<&ToolUsageLog> = report
        .arms
        .iter()
        .filter_map(|a| a.tool_usage.as_ref())
        .collect();
    if !tool_logs.is_empty() {
        writeln!(out).unwrap();
        let owned: Vec<ToolUsageLog> = tool_logs.into_iter().cloned().collect();
        out.push_str(&super::telemetry::format_tool_usage(&owned));
    }

    let step_logs: Vec<&ArmResult> = report
        .arms
        .iter()
        .filter(|a| a.step_summary.is_some())
        .collect();
    if !step_logs.is_empty() {
        writeln!(out).unwrap();
        writeln!(out, "--- Step Hotspots ---").unwrap();
        for arm in step_logs {
            let summary = arm.step_summary.as_ref().unwrap();
            writeln!(
                out,
                "  {} / {} / {}: {} steps, {} commands, {} MCP, {} subagents, {} failed",
                arm.arm,
                arm.cli_name,
                arm.task_name,
                summary.total_steps,
                summary.command_steps,
                summary.mcp_steps,
                summary.subagent_steps,
                summary.failed_steps,
            )
            .unwrap();
            let slowest_action = summary
                .top_by_duration
                .iter()
                .find(|hotspot| is_actionable_hotspot(&hotspot.kind))
                .or_else(|| summary.top_by_duration.first());
            if let Some(top) = slowest_action {
                writeln!(
                    out,
                    "    slowest: {} ({})",
                    top.label,
                    top.duration_ms
                        .map(format_duration)
                        .unwrap_or_else(|| "n/a".to_string())
                )
                .unwrap();
            }
            let noisiest_action = summary
                .top_by_output
                .iter()
                .find(|hotspot| is_actionable_hotspot(&hotspot.kind))
                .or_else(|| summary.top_by_output.first());
            if let Some(top) = noisiest_action {
                writeln!(
                    out,
                    "    noisiest: {} ({} chars)",
                    top.label, top.output_chars
                )
                .unwrap();
            }
            if !summary.subagents.is_empty() {
                for subagent in summary.subagents.iter().take(3) {
                    writeln!(
                        out,
                        "    subagent: {} | {} child steps, {} commands, {} MCP{}",
                        subagent.label,
                        subagent.child_steps,
                        subagent.child_command_steps,
                        subagent.child_mcp_steps,
                        subagent
                            .duration_ms
                            .map(|d| format!(" | {}", format_duration(d)))
                            .unwrap_or_default()
                    )
                    .unwrap();
                }
            }
        }
    }

    // --- Task Hierarchy ---
    let hierarchy_arms: Vec<&ArmResult> = report
        .arms
        .iter()
        .filter(|a| a.step_summary.is_some())
        .collect();
    if !hierarchy_arms.is_empty() {
        writeln!(out).unwrap();
        writeln!(out, "--- Task Hierarchy ---").unwrap();
        for arm in &hierarchy_arms {
            let summary = arm.step_summary.as_ref().unwrap();
            writeln!(
                out,
                "{} / {} / {}: {} steps",
                arm.arm, arm.cli_name, arm.task_name, summary.total_steps,
            )
            .unwrap();
            if let Some(ref trace) = arm.step_trace_entries {
                format_hierarchy_tree(&mut out, trace, summary);
            }
        }
    }

    // --- Cost Attribution ---
    let cost_arms: Vec<&ArmResult> = report
        .arms
        .iter()
        .filter(|a| {
            a.step_summary
                .as_ref()
                .map(|s| {
                    s.main_agent_total_tokens > 0
                        || s.subagent_total_tokens > 0
                        || s.unattributed_total_tokens > 0
                })
                .unwrap_or(false)
        })
        .collect();
    if !cost_arms.is_empty() {
        writeln!(out).unwrap();
        writeln!(out, "--- Cost Attribution ---").unwrap();
        for arm in &cost_arms {
            let summary = arm.step_summary.as_ref().unwrap();
            writeln!(out, "{} / {} / {}:", arm.arm, arm.cli_name, arm.task_name).unwrap();
            writeln!(
                out,
                "  Main agent:  {} input + {} output = {} ({})",
                format_tokens(summary.main_agent_input_tokens),
                format_tokens(summary.main_agent_output_tokens),
                format_tokens(summary.main_agent_total_tokens),
                format_cost(summary.main_agent_cost_usd),
            )
            .unwrap();
            for subagent in &summary.subagents {
                if subagent.total_tokens > 0 {
                    writeln!(
                        out,
                        "  {}: {} input + {} output = {} ({})",
                        subagent.label,
                        format_tokens(subagent.input_tokens),
                        format_tokens(subagent.output_tokens),
                        format_tokens(subagent.total_tokens),
                        format_cost(subagent.estimated_cost_usd),
                    )
                    .unwrap();
                }
            }
            if summary.unattributed_total_tokens > 0 {
                writeln!(
                    out,
                    "  Unattributed: {} ({})",
                    format_tokens(summary.unattributed_total_tokens),
                    format_cost(summary.unattributed_cost_usd),
                )
                .unwrap();
            }
            let grand_total = summary.main_agent_total_tokens
                + summary.subagent_total_tokens
                + summary.unattributed_total_tokens;
            let grand_cost = summary.main_agent_cost_usd
                + summary.subagent_total_cost_usd
                + summary.unattributed_cost_usd;
            writeln!(
                out,
                "  Total:       {} ({})",
                format_tokens(grand_total),
                format_cost(grand_cost),
            )
            .unwrap();
        }
    }

    // --- Shim Commands ---
    let shim_arms: Vec<&ArmResult> = report
        .arms
        .iter()
        .filter(|a| a.shim_log_summary.is_some())
        .collect();
    if !shim_arms.is_empty() {
        writeln!(out).unwrap();
        writeln!(out, "--- Shim Commands ---").unwrap();
        for arm in &shim_arms {
            let shim = arm.shim_log_summary.as_ref().unwrap();
            writeln!(out, "{} / {} / {}:", arm.arm, arm.cli_name, arm.task_name).unwrap();
            for (cmd, stats) in &shim.commands_by_name {
                writeln!(
                    out,
                    "  {}: {} call{} ({}ms total)",
                    cmd,
                    stats.count,
                    if stats.count == 1 { "" } else { "s" },
                    stats.total_wall_ms,
                )
                .unwrap();
            }
            writeln!(
                out,
                "  Total: {} shimmed command{}, {} failure{}",
                shim.total_commands,
                if shim.total_commands == 1 { "" } else { "s" },
                shim.failed_commands,
                if shim.failed_commands == 1 { "" } else { "s" },
            )
            .unwrap();
        }
    }

    out
}

// =========================================================================
// Hierarchy tree rendering
// =========================================================================

/// Build an indented tree view of step trace entries, grouping children under
/// their parent subagent. Top-level entries (no parent) are listed first, with
/// subagent children indented beneath them.
fn format_hierarchy_tree(
    out: &mut String,
    entries: &[StepTraceEntry],
    summary: &StepTraceSummary,
) {
    // Collect top-level actionable entries (no parent_item_id, skip non-actionable)
    let top_level: Vec<&StepTraceEntry> = entries
        .iter()
        .filter(|e| {
            e.parent_item_id.is_none()
                && matches!(
                    e.kind,
                    StepKind::CommandExecution
                        | StepKind::McpToolCall
                        | StepKind::SubagentTask
                        | StepKind::Result
                )
        })
        .collect();

    let total = top_level.len();
    for (i, entry) in top_level.iter().enumerate() {
        let is_last = i + 1 == total;
        let connector = if is_last { "\u{2514}\u{2500}" } else { "\u{251c}\u{2500}" };

        let timing = entry
            .duration_ms
            .map(|d| format!(" ({})", format_duration(d)))
            .unwrap_or_default();

        // For subagents, also show token count if available
        let token_info = if entry.kind == StepKind::SubagentTask {
            summary
                .subagents
                .iter()
                .find(|s| s.item_id == entry.item_id)
                .filter(|s| s.total_tokens > 0)
                .map(|s| {
                    format!(
                        ", {}, {}",
                        format_tokens(s.total_tokens),
                        format_cost(s.estimated_cost_usd)
                    )
                })
                .unwrap_or_default()
        } else {
            String::new()
        };

        writeln!(out, "  {} {}{}{}", connector, entry.label, timing, token_info).unwrap();

        // If this is a subagent, show its children indented
        if entry.kind == StepKind::SubagentTask {
            let children: Vec<&StepTraceEntry> = entries
                .iter()
                .filter(|e| {
                    e.parent_item_id.is_some()
                        && e.parent_item_id.as_deref() == entry.item_id.as_deref()
                        && matches!(
                            e.kind,
                            StepKind::CommandExecution
                                | StepKind::McpToolCall
                                | StepKind::SubagentTask
                                | StepKind::AgentMessage
                        )
                })
                .collect();

            let prefix = if is_last { "   " } else { "  \u{2502}" };
            let child_total = children.len();
            for (j, child) in children.iter().enumerate() {
                let child_last = j + 1 == child_total;
                let child_connector = if child_last { "\u{2514}\u{2500}" } else { "\u{251c}\u{2500}" };
                let child_timing = child
                    .duration_ms
                    .map(|d| format!(" ({})", format_duration(d)))
                    .unwrap_or_default();
                writeln!(
                    out,
                    "  {} {} {}{}",
                    prefix, child_connector, child.label, child_timing,
                )
                .unwrap();
            }
        }
    }
}

// =========================================================================
// Helpers
// =========================================================================

/// Compute percentage savings: (baseline - improved) / baseline * 100.
/// Returns `None` when the baseline is zero or negative (avoids division by zero).
fn pct_savings(baseline: f64, improved: f64) -> Option<f64> {
    if baseline <= 0.0 {
        None
    } else {
        Some(((baseline - improved) / baseline) * 100.0)
    }
}

fn is_actionable_hotspot(kind: &crate::live::StepKind) -> bool {
    matches!(
        kind,
        crate::live::StepKind::CommandExecution
            | crate::live::StepKind::McpToolCall
            | crate::live::StepKind::SubagentTask
    )
}

/// Build a human-readable combined summary string.
fn build_combined_summary(
    duration_pct: Option<f64>,
    docs_pct: Option<f64>,
    kin_tokens: Option<u64>,
    git_tokens: u64,
) -> Option<String> {
    let mut parts = Vec::new();

    if let Some(pct) = duration_pct {
        parts.push(format!("{:.1}% faster", pct));
    }

    if let Some(tok) = kin_tokens {
        if let Some(pct) = pct_savings(git_tokens as f64, tok as f64) {
            parts.push(format!("{:.1}% fewer tokens", pct));
        }
    }

    if let Some(pct) = docs_pct {
        parts.push(format!("{:.1}% docs boost", pct));
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

fn format_duration(ms: f64) -> String {
    if ms < 1000.0 {
        format!("{:.0}ms", ms)
    } else if ms < 60_000.0 {
        format!("{:.1}s", ms / 1000.0)
    } else {
        let mins = (ms / 60_000.0).floor();
        let secs = (ms - mins * 60_000.0) / 1000.0;
        format!("{:.0}m{:.0}s", mins, secs)
    }
}

fn format_tokens(tok: u64) -> String {
    if tok < 1_000 {
        format!("{} tok", tok)
    } else if tok < 1_000_000 {
        format!("{:.1}K tok", tok as f64 / 1_000.0)
    } else {
        format!("{:.2}M tok", tok as f64 / 1_000_000.0)
    }
}

fn format_cost(cost: f64) -> String {
    if cost < 0.01 {
        format!("${:.4}", cost)
    } else {
        format!("${:.2}", cost)
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1_024 {
        format!("{} B", bytes)
    } else if bytes < 1_048_576 {
        format!("{:.1} KB", bytes as f64 / 1_024.0)
    } else if bytes < 1_073_741_824 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{AssistantRunSource, BenchmarkSubstrate, DurationMs};

    fn make_run(
        task: &str,
        assistant: &str,
        substrate: BenchmarkSubstrate,
        duration_ms: f64,
        total_tokens: u64,
        cost: f64,
    ) -> AssistantTaskRun {
        AssistantTaskRun {
            task_name: task.to_string(),
            assistant_name: assistant.to_string(),
            model_name: Some("test-model".to_string()),
            substrate,
            duration_ms: DurationMs(duration_ms),
            input_tokens: total_tokens / 2,
            output_tokens: total_tokens / 2,
            total_tokens,
            estimated_cost_usd: cost,
            first_pass_success: true,
            validation_passed: true,
            run_source: AssistantRunSource::LiveHarness,
            notes: None,
            recorded_at: Utc::now(),
        }
    }

    fn make_arm(
        arm: BenchmarkArm,
        task: &str,
        cli: &str,
        duration_ms: f64,
        tokens: u64,
        cost: f64,
    ) -> ArmResult {
        let substrate = match arm {
            BenchmarkArm::KinCompat | BenchmarkArm::KinNative => BenchmarkSubstrate::Kin,
            _ => BenchmarkSubstrate::Git,
        };
        ArmResult {
            arm,
            task_name: task.to_string(),
            cli_name: cli.to_string(),
            run: make_run(task, cli, substrate, duration_ms, tokens, cost),
            resource_report: None,
            transcript_path: None,
            step_trace_path: None,
            shim_log_path: None,
            step_summary: None,
            tool_usage: None,
            shim_log_summary: None,
            step_trace_entries: None,
        }
    }

    #[test]
    fn build_comparisons_basic_percentage_calculations() {
        let arms = vec![
            make_arm(BenchmarkArm::Git, "search-fn", "Claude Code", 45200.0, 12000, 0.12),
            make_arm(BenchmarkArm::KinCompat, "search-fn", "Claude Code", 38100.0, 10000, 0.10),
            make_arm(BenchmarkArm::KinNative, "search-fn", "Claude Code", 12400.0, 4000, 0.04),
        ];

        let comparisons = build_comparisons(&arms);
        assert_eq!(comparisons.len(), 1);

        let cmp = &comparisons[0];
        assert_eq!(cmp.task_name, "search-fn");
        assert_eq!(cmp.cli_name, "Claude Code");

        // Duration: (45200 - 12400) / 45200 * 100 = ~72.57%
        let savings = cmp.native_savings_pct.unwrap();
        assert!((savings - 72.57).abs() < 0.1, "expected ~72.57%, got {:.2}%", savings);

        // Docs: (45200 - 38100) / 45200 * 100 = ~15.71%
        let docs = cmp.compat_savings_pct.unwrap();
        assert!((docs - 15.71).abs() < 0.1, "expected ~15.71%, got {:.2}%", docs);

        // Tokens
        assert_eq!(cmp.git_tokens, 12000);
        assert_eq!(cmp.kin_native_tokens, Some(4000));
        assert_eq!(cmp.kin_compat_tokens, Some(10000));

        // Cost
        assert!((cmp.git_cost - 0.12).abs() < f64::EPSILON);
        assert!((cmp.kin_native_cost.unwrap() - 0.04).abs() < f64::EPSILON);

        // Combined improvement should be present
        assert!(cmp.combined_improvement.is_some());
        let summary = cmp.combined_improvement.as_ref().unwrap();
        assert!(summary.contains("faster"));
        assert!(summary.contains("fewer tokens"));
    }

    #[test]
    fn build_comparisons_missing_arms() {
        // Only Git and native Kin, no compat arm
        let arms = vec![
            make_arm(BenchmarkArm::Git, "refactor", "Codex", 30000.0, 8000, 0.08),
            make_arm(BenchmarkArm::KinNative, "refactor", "Codex", 10000.0, 3000, 0.03),
        ];

        let comparisons = build_comparisons(&arms);
        assert_eq!(comparisons.len(), 1);

        let cmp = &comparisons[0];
        assert!(cmp.kin_compat_duration_ms.is_none());
        assert!(cmp.kin_compat_tokens.is_none());
        assert!(cmp.kin_compat_cost.is_none());
        assert!(cmp.compat_savings_pct.is_none());
        assert!(cmp.native_savings_pct.is_some());
    }

    #[test]
    fn build_comparisons_no_git_baseline_skipped() {
        // Only a Kin arm, no Git — should produce zero comparisons
        let arms = vec![
            make_arm(BenchmarkArm::KinNative, "explore", "Gemini", 5000.0, 2000, 0.02),
        ];

        let comparisons = build_comparisons(&arms);
        assert!(comparisons.is_empty());
    }

    #[test]
    fn format_summary_produces_non_empty_output() {
        let mut report = LiveBenchmarkReport::new("test-repo".to_string());
        report.arms.push(
            make_arm(BenchmarkArm::Git, "task-a", "Claude Code", 20000.0, 6000, 0.06),
        );
        report.arms.push(
            make_arm(BenchmarkArm::KinNative, "task-a", "Claude Code", 8000.0, 2000, 0.02),
        );
        report.finish();

        let summary = format_summary(&report);
        assert!(!summary.is_empty());
        assert!(summary.contains("test-repo"));
        assert!(summary.contains("Results"));
        assert!(summary.contains("Savings"));
    }

    #[test]
    fn serialization_roundtrip() {
        let mut report = LiveBenchmarkReport::new("roundtrip-repo".to_string());
        report.commit_sha = Some("abc123".to_string());
        report.arms.push(
            make_arm(BenchmarkArm::Git, "build", "Codex", 10000.0, 5000, 0.05),
        );
        report.finish();

        let json = report.to_json().unwrap();
        let parsed: LiveBenchmarkReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.repo_name, "roundtrip-repo");
        assert_eq!(parsed.commit_sha, Some("abc123".to_string()));
        assert_eq!(parsed.arms.len(), 1);
    }

    #[test]
    fn zero_duration_git_run_no_panic() {
        let arms = vec![
            make_arm(BenchmarkArm::Git, "zero-task", "Claude Code", 0.0, 0, 0.0),
            make_arm(BenchmarkArm::KinNative, "zero-task", "Claude Code", 5000.0, 1000, 0.01),
        ];

        let comparisons = build_comparisons(&arms);
        assert_eq!(comparisons.len(), 1);

        let cmp = &comparisons[0];
        // With zero baseline, savings should be None (avoids divide-by-zero).
        assert!(cmp.native_savings_pct.is_none());
    }

    #[test]
    fn multiple_task_cli_pairs() {
        let arms = vec![
            make_arm(BenchmarkArm::Git, "task-a", "Claude Code", 10000.0, 5000, 0.05),
            make_arm(BenchmarkArm::KinNative, "task-a", "Claude Code", 4000.0, 2000, 0.02),
            make_arm(BenchmarkArm::Git, "task-b", "Codex", 20000.0, 8000, 0.08),
            make_arm(BenchmarkArm::KinNative, "task-b", "Codex", 6000.0, 2500, 0.025),
        ];

        let comparisons = build_comparisons(&arms);
        assert_eq!(comparisons.len(), 2);
        assert_eq!(comparisons[0].task_name, "task-a");
        assert_eq!(comparisons[1].task_name, "task-b");
    }

    #[test]
    fn report_total_duration_ms() {
        let mut report = LiveBenchmarkReport::new("dur-test".to_string());
        // Manually set timestamps to verify calculation.
        report.started_at = Utc::now() - chrono::Duration::seconds(10);
        report.finished_at = Utc::now();
        let dur = report.total_duration_ms();
        // Should be approximately 10_000ms.
        assert!(dur >= 9_900.0 && dur <= 10_100.0, "total_duration_ms was {}", dur);
    }

    #[test]
    fn format_helpers() {
        assert_eq!(format_duration(500.0), "500ms");
        assert_eq!(format_duration(1500.0), "1.5s");
        assert_eq!(format_duration(90_000.0), "1m30s");

        assert_eq!(format_tokens(500), "500 tok");
        assert_eq!(format_tokens(12400), "12.4K tok");
        assert_eq!(format_tokens(2_500_000), "2.50M tok");

        assert_eq!(format_cost(0.001), "$0.0010");
        assert_eq!(format_cost(0.12), "$0.12");
        assert_eq!(format_cost(1.5), "$1.50");

        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1_536), "1.5 KB");
        assert_eq!(format_bytes(10_485_760), "10.0 MB");
        assert_eq!(format_bytes(1_610_612_736), "1.50 GB");
    }

    use super::super::steps::{
        SubagentTraceSummary, StepKind, StepTraceEntry, StepTraceSummary,
    };
    use super::super::shim_log::{CommandStats, ShimLogSummary};
    use std::collections::BTreeMap;

    fn make_step_entry(
        sequence: usize,
        item_id: Option<&str>,
        parent_item_id: Option<&str>,
        kind: StepKind,
        label: &str,
        duration_ms: Option<f64>,
    ) -> StepTraceEntry {
        StepTraceEntry {
            sequence,
            item_id: item_id.map(|s| s.to_string()),
            parent_item_id: parent_item_id.map(|s| s.to_string()),
            kind,
            raw_type: "test".to_string(),
            label: label.to_string(),
            status: None,
            exit_code: None,
            started_offset_ms: None,
            ended_offset_ms: None,
            duration_ms,
            output_chars: 0,
            output_tokens_est: 0,
            turn_input_tokens: 0,
            turn_output_tokens: 0,
        }
    }

    fn make_summary_with_subagents(
        subagents: Vec<SubagentTraceSummary>,
    ) -> StepTraceSummary {
        StepTraceSummary {
            total_steps: 5,
            command_steps: 2,
            mcp_steps: 0,
            subagent_steps: subagents.len(),
            agent_message_steps: 0,
            failed_steps: 0,
            total_output_chars: 0,
            total_output_tokens_est: 0,
            has_precise_timing: true,
            top_by_duration: Vec::new(),
            top_by_output: Vec::new(),
            subagents,
            main_agent_input_tokens: 5000,
            main_agent_output_tokens: 2000,
            main_agent_total_tokens: 7000,
            main_agent_cost_usd: 0.021,
            subagent_total_input_tokens: 3000,
            subagent_total_output_tokens: 1000,
            subagent_total_tokens: 4000,
            subagent_total_cost_usd: 0.012,
            unattributed_total_tokens: 0,
            unattributed_cost_usd: 0.0,
        }
    }

    #[test]
    fn format_hierarchy_tree_renders_top_level_and_children() {
        let entries = vec![
            make_step_entry(0, None, None, StepKind::CommandExecution, "kin overview --compact", Some(2100.0)),
            make_step_entry(1, Some("agent_1"), None, StepKind::SubagentTask, "Subagent Explore: trace flow", Some(18500.0)),
            make_step_entry(2, Some("tool_1"), Some("agent_1"), StepKind::CommandExecution, "kin search \"save\" --show-body", Some(3200.0)),
            make_step_entry(3, Some("tool_2"), Some("agent_1"), StepKind::CommandExecution, "Read src/main.rs", Some(500.0)),
            make_step_entry(4, None, None, StepKind::Result, "result", Some(32400.0)),
        ];
        let subagent = SubagentTraceSummary {
            item_id: Some("agent_1".to_string()),
            label: "Subagent Explore: trace flow".to_string(),
            duration_ms: Some(18500.0),
            child_steps: 2,
            child_command_steps: 2,
            child_mcp_steps: 0,
            child_output_chars: 0,
            child_output_tokens_est: 0,
            input_tokens: 3000,
            output_tokens: 1000,
            total_tokens: 4000,
            estimated_cost_usd: 0.012,
        };
        let summary = make_summary_with_subagents(vec![subagent]);

        let mut out = String::new();
        format_hierarchy_tree(&mut out, &entries, &summary);

        // Should have the top-level command
        assert!(out.contains("kin overview --compact (2.1s)"), "got: {}", out);
        // Should have the subagent with cost info
        assert!(out.contains("Subagent Explore: trace flow (18.5s"), "got: {}", out);
        assert!(out.contains("4.0K tok"), "got: {}", out);
        assert!(out.contains("$0.01"), "got: {}", out);
        // Should have children indented
        assert!(out.contains("kin search \"save\" --show-body (3.2s)"), "got: {}", out);
        assert!(out.contains("Read src/main.rs (500ms)"), "got: {}", out);
        // Should have the result
        assert!(out.contains("result (32.4s)"), "got: {}", out);
    }

    #[test]
    fn format_summary_includes_cost_attribution() {
        let mut report = LiveBenchmarkReport::new("cost-repo".to_string());
        let subagent = SubagentTraceSummary {
            item_id: Some("agent_1".to_string()),
            label: "Subagent Explore".to_string(),
            duration_ms: Some(10000.0),
            child_steps: 1,
            child_command_steps: 1,
            child_mcp_steps: 0,
            child_output_chars: 0,
            child_output_tokens_est: 0,
            input_tokens: 3000,
            output_tokens: 1000,
            total_tokens: 4000,
            estimated_cost_usd: 0.012,
        };
        let mut arm = make_arm(BenchmarkArm::Git, "task-a", "Claude Code", 20000.0, 6000, 0.06);
        arm.step_summary = Some(make_summary_with_subagents(vec![subagent]));
        report.arms.push(arm);
        report.finish();

        let text = format_summary(&report);
        assert!(text.contains("Cost Attribution"), "got: {}", text);
        assert!(text.contains("Main agent:"), "got: {}", text);
        assert!(text.contains("7.0K tok"), "got: {}", text);
        assert!(text.contains("Total:"), "got: {}", text);
    }

    #[test]
    fn format_summary_includes_shim_commands() {
        let mut report = LiveBenchmarkReport::new("shim-repo".to_string());
        let mut commands_by_name = BTreeMap::new();
        commands_by_name.insert(
            "cat".to_string(),
            CommandStats {
                count: 3,
                total_wall_ms: 45,
                failures: 0,
            },
        );
        commands_by_name.insert(
            "rg".to_string(),
            CommandStats {
                count: 2,
                total_wall_ms: 120,
                failures: 0,
            },
        );
        let mut arm = make_arm(BenchmarkArm::KinNative, "task-a", "Claude Code", 10000.0, 3000, 0.03);
        arm.shim_log_summary = Some(ShimLogSummary {
            total_commands: 5,
            commands_by_name,
            total_wall_ms: 165,
            failed_commands: 0,
            entries: Vec::new(),
        });
        // Need a Git arm for comparisons
        report.arms.push(make_arm(BenchmarkArm::Git, "task-a", "Claude Code", 20000.0, 6000, 0.06));
        report.arms.push(arm);
        report.finish();

        let text = format_summary(&report);
        assert!(text.contains("Shim Commands"), "got: {}", text);
        assert!(text.contains("cat: 3 calls (45ms total)"), "got: {}", text);
        assert!(text.contains("rg: 2 calls (120ms total)"), "got: {}", text);
        assert!(text.contains("Total: 5 shimmed commands, 0 failures"), "got: {}", text);
    }

    #[test]
    fn format_hierarchy_tree_empty_entries() {
        let summary = StepTraceSummary {
            total_steps: 0,
            command_steps: 0,
            mcp_steps: 0,
            subagent_steps: 0,
            agent_message_steps: 0,
            failed_steps: 0,
            total_output_chars: 0,
            total_output_tokens_est: 0,
            has_precise_timing: false,
            top_by_duration: Vec::new(),
            top_by_output: Vec::new(),
            subagents: Vec::new(),
            main_agent_input_tokens: 0,
            main_agent_output_tokens: 0,
            main_agent_total_tokens: 0,
            main_agent_cost_usd: 0.0,
            subagent_total_input_tokens: 0,
            subagent_total_output_tokens: 0,
            subagent_total_tokens: 0,
            subagent_total_cost_usd: 0.0,
            unattributed_total_tokens: 0,
            unattributed_cost_usd: 0.0,
        };
        let mut out = String::new();
        format_hierarchy_tree(&mut out, &[], &summary);
        assert!(out.is_empty());
    }
}
