// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::BTreeMap;
use std::io::BufRead;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// A single shimmed-command invocation logged by the bash shim scripts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShimLogEntry {
    pub cmd: String,
    #[serde(default)]
    pub args: String,
    pub start_epoch_ms: u64,
    pub end_epoch_ms: u64,
    pub exit_code: i32,
}

/// Per-command aggregate stats.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CommandStats {
    pub count: usize,
    pub total_wall_ms: u64,
    pub failures: usize,
}

/// Aggregate summary of all shimmed commands in a benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShimLogSummary {
    pub total_commands: usize,
    pub commands_by_name: BTreeMap<String, CommandStats>,
    pub total_wall_ms: u64,
    pub failed_commands: usize,
    pub entries: Vec<ShimLogEntry>,
}

/// Parse a JSONL shim log file into entries.
/// Skips malformed lines silently (the shim writes best-effort JSON).
pub fn parse_shim_log(path: &Path) -> std::io::Result<Vec<ShimLogEntry>> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<ShimLogEntry>(trimmed) {
            entries.push(entry);
        }
    }
    Ok(entries)
}

/// Build an aggregate summary from parsed shim log entries.
pub fn summarize_shim_log(entries: &[ShimLogEntry]) -> ShimLogSummary {
    let mut summary = ShimLogSummary {
        total_commands: entries.len(),
        entries: entries.to_vec(),
        ..Default::default()
    };

    for entry in entries {
        let wall_ms = entry.end_epoch_ms.saturating_sub(entry.start_epoch_ms);
        summary.total_wall_ms += wall_ms;

        if entry.exit_code != 0 {
            summary.failed_commands += 1;
        }

        let stats = summary
            .commands_by_name
            .entry(entry.cmd.clone())
            .or_default();
        stats.count += 1;
        stats.total_wall_ms += wall_ms;
        if entry.exit_code != 0 {
            stats.failures += 1;
        }
    }

    summary
}

/// Format a shim log summary for CLI display.
pub fn format_shim_summary(summary: &ShimLogSummary) -> String {
    let mut lines = Vec::new();

    for (cmd, stats) in &summary.commands_by_name {
        lines.push(format!(
            "{}: {} call{} ({}ms total)",
            cmd,
            stats.count,
            if stats.count == 1 { "" } else { "s" },
            stats.total_wall_ms,
        ));
    }

    lines.push(format!(
        "Total: {} shimmed command{}, {} failure{}",
        summary.total_commands,
        if summary.total_commands == 1 { "" } else { "s" },
        summary.failed_commands,
        if summary.failed_commands == 1 {
            ""
        } else {
            "s"
        },
    ));

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn sample_jsonl() -> &'static str {
        concat!(
            r#"{"cmd":"cat","args":"src/main.rs","start_epoch_ms":1000,"end_epoch_ms":1012,"exit_code":0}"#,
            "\n",
            r#"{"cmd":"rg","args":"--json pattern src/","start_epoch_ms":1020,"end_epoch_ms":1085,"exit_code":0}"#,
            "\n",
            r#"{"cmd":"cat","args":"Cargo.toml","start_epoch_ms":1100,"end_epoch_ms":1110,"exit_code":0}"#,
            "\n",
            r#"{"cmd":"find","args":". -name *.rs","start_epoch_ms":1200,"end_epoch_ms":1250,"exit_code":1}"#,
            "\n",
        )
    }

    fn write_temp_file(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn parse_entries_from_jsonl() {
        let tmp = write_temp_file(sample_jsonl());
        let entries = parse_shim_log(tmp.path()).unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].cmd, "cat");
        assert_eq!(entries[0].args, "src/main.rs");
        assert_eq!(entries[0].start_epoch_ms, 1000);
        assert_eq!(entries[0].end_epoch_ms, 1012);
        assert_eq!(entries[0].exit_code, 0);
        assert_eq!(entries[3].cmd, "find");
        assert_eq!(entries[3].exit_code, 1);
    }

    #[test]
    fn summarize_groups_by_command() {
        let tmp = write_temp_file(sample_jsonl());
        let entries = parse_shim_log(tmp.path()).unwrap();
        let summary = summarize_shim_log(&entries);

        assert_eq!(summary.total_commands, 4);
        assert_eq!(summary.failed_commands, 1);

        // cat: 2 calls, 12 + 10 = 22ms
        let cat = summary.commands_by_name.get("cat").unwrap();
        assert_eq!(cat.count, 2);
        assert_eq!(cat.total_wall_ms, 22);
        assert_eq!(cat.failures, 0);

        // rg: 1 call, 65ms
        let rg = summary.commands_by_name.get("rg").unwrap();
        assert_eq!(rg.count, 1);
        assert_eq!(rg.total_wall_ms, 65);
        assert_eq!(rg.failures, 0);

        // find: 1 call, 50ms, 1 failure
        let find = summary.commands_by_name.get("find").unwrap();
        assert_eq!(find.count, 1);
        assert_eq!(find.total_wall_ms, 50);
        assert_eq!(find.failures, 1);

        // Total wall: 12 + 65 + 10 + 50 = 137ms
        assert_eq!(summary.total_wall_ms, 137);
    }

    #[test]
    fn format_summary_output() {
        let tmp = write_temp_file(sample_jsonl());
        let entries = parse_shim_log(tmp.path()).unwrap();
        let summary = summarize_shim_log(&entries);
        let output = format_shim_summary(&summary);

        // BTreeMap iterates alphabetically: cat, find, rg
        assert!(output.contains("cat: 2 calls (22ms total)"));
        assert!(output.contains("find: 1 call (50ms total)"));
        assert!(output.contains("rg: 1 call (65ms total)"));
        assert!(output.contains("Total: 4 shimmed commands, 1 failure"));
    }

    #[test]
    fn skips_malformed_lines() {
        let content = concat!(
            r#"{"cmd":"cat","args":"f.rs","start_epoch_ms":100,"end_epoch_ms":110,"exit_code":0}"#,
            "\n",
            "this is not json\n",
            "{broken json\n",
            "\n",
            r#"{"cmd":"rg","args":"pat","start_epoch_ms":200,"end_epoch_ms":220,"exit_code":0}"#,
            "\n",
        );
        let tmp = write_temp_file(content);
        let entries = parse_shim_log(tmp.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].cmd, "cat");
        assert_eq!(entries[1].cmd, "rg");
    }

    #[test]
    fn serialization_roundtrip() {
        let entry = ShimLogEntry {
            cmd: "cat".to_string(),
            args: "src/main.rs".to_string(),
            start_epoch_ms: 1000,
            end_epoch_ms: 1050,
            exit_code: 0,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: ShimLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cmd, entry.cmd);
        assert_eq!(parsed.args, entry.args);
        assert_eq!(parsed.start_epoch_ms, entry.start_epoch_ms);
        assert_eq!(parsed.end_epoch_ms, entry.end_epoch_ms);
        assert_eq!(parsed.exit_code, entry.exit_code);

        let tmp = write_temp_file(sample_jsonl());
        let entries = parse_shim_log(tmp.path()).unwrap();
        let summary = summarize_shim_log(&entries);
        let summary_json = serde_json::to_string(&summary).unwrap();
        let parsed_summary: ShimLogSummary = serde_json::from_str(&summary_json).unwrap();
        assert_eq!(parsed_summary.total_commands, summary.total_commands);
        assert_eq!(parsed_summary.failed_commands, summary.failed_commands);
        assert_eq!(parsed_summary.total_wall_ms, summary.total_wall_ms);
        assert_eq!(
            parsed_summary.commands_by_name.len(),
            summary.commands_by_name.len()
        );
    }

    #[test]
    fn empty_file_returns_empty_vec() {
        let tmp = write_temp_file("");
        let entries = parse_shim_log(tmp.path()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn empty_summary_defaults() {
        let summary = summarize_shim_log(&[]);
        assert_eq!(summary.total_commands, 0);
        assert_eq!(summary.total_wall_ms, 0);
        assert_eq!(summary.failed_commands, 0);
        assert!(summary.commands_by_name.is_empty());

        let output = format_shim_summary(&summary);
        assert!(output.contains("Total: 0 shimmed commands, 0 failures"));
    }
}
