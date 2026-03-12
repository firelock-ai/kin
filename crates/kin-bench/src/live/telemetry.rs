use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Tracks which tools an assistant used during a benchmark task.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolUsageLog {
    /// Benchmark arm name (git, kin-compat, kin-native)
    pub arm: String,
    /// Assistant name (claude, codex, gemini)
    pub assistant: String,
    /// Task name
    pub task: String,
    /// Kin CLI commands used (e.g. "kin search save --show-body")
    pub kin_commands: Vec<String>,
    /// Traditional filesystem commands used (e.g. "grep -r save", "cat src/index.ts")
    pub filesystem_commands: Vec<String>,
    /// MCP tool calls (e.g. "semantic_search", "get_context_pack")
    pub mcp_calls: Vec<String>,
    /// Ratio of kin tools to total tools used (0.0 to 1.0)
    pub kin_tool_ratio: f64,
}

/// Known MCP tool names from Kin's MCP server.
const KIN_MCP_TOOLS: &[&str] = &[
    "semantic_search",
    "get_context_pack",
    "impact_analysis",
    "semantic_diff",
    "semantic_review",
    "graph_neighborhood",
    "dead_code",
    "entity_history",
];

/// Filesystem commands commonly used for code discovery.
const FS_COMMANDS: &[&str] = &[
    "grep", "rg", "find", "cat", "head", "tail", "ls", "tree", "wc", "sed", "awk",
];

/// Extract tool usage from assistant output text.
///
/// Uses pragmatic text scanning: looks for `kin <subcommand>` patterns,
/// filesystem tool invocations, and MCP tool names in the raw output.
pub fn extract_tool_usage(output: &str, assistant: &str, arm: &str, task: &str) -> ToolUsageLog {
    let mut kin_commands = Vec::new();
    let mut filesystem_commands = Vec::new();
    let mut mcp_calls = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();

        if extract_structured_tool_usage(
            trimmed,
            &mut kin_commands,
            &mut filesystem_commands,
            &mut mcp_calls,
        ) {
            continue;
        }

        // Look for kin CLI commands: "kin <word>" patterns
        extract_kin_commands(trimmed, &mut kin_commands);

        // Look for filesystem commands in command-like contexts
        extract_fs_commands(trimmed, &mut filesystem_commands);

        // Look for MCP tool names
        extract_mcp_calls(trimmed, &mut mcp_calls);
    }

    // Deduplicate
    kin_commands.sort();
    kin_commands.dedup();
    filesystem_commands.sort();
    filesystem_commands.dedup();
    mcp_calls.sort();
    mcp_calls.dedup();

    let kin_count = kin_commands.len() + mcp_calls.len();
    let total = kin_count + filesystem_commands.len();
    let kin_tool_ratio = if total > 0 {
        kin_count as f64 / total as f64
    } else {
        0.0
    };

    ToolUsageLog {
        arm: arm.to_string(),
        assistant: assistant.to_string(),
        task: task.to_string(),
        kin_commands,
        filesystem_commands,
        mcp_calls,
        kin_tool_ratio,
    }
}

fn extract_structured_tool_usage(
    line: &str,
    kin_commands: &mut Vec<String>,
    filesystem_commands: &mut Vec<String>,
    mcp_calls: &mut Vec<String>,
) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return false;
    };

    if v.get("type").and_then(|t| t.as_str()) != Some("assistant") {
        return false;
    }

    let Some(content) = v
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_array())
    else {
        return false;
    };

    for item in content {
        if item.get("type").and_then(|t| t.as_str()) != Some("tool_use") {
            continue;
        }
        let name = item.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let input = item.get("input").unwrap_or(&Value::Null);
        match name {
            "Bash" => {
                if let Some(cmd) = input.get("command").and_then(|c| c.as_str()) {
                    extract_kin_commands(cmd, kin_commands);
                    extract_fs_commands(cmd, filesystem_commands);
                }
            }
            "Grep" => filesystem_commands.push("grep".to_string()),
            "Glob" => filesystem_commands.push("find".to_string()),
            "Read" => filesystem_commands.push("cat".to_string()),
            tool if KIN_MCP_TOOLS.contains(&tool) => {
                mcp_calls.push(tool.to_string());
            }
            _ => {}
        }
    }

    true
}

/// Scan a line for `kin <subcommand>` invocations and collect the full command.
fn extract_kin_commands(line: &str, out: &mut Vec<String>) {
    // Search for "kin " preceded by a word boundary (start of line, space, quote, backtick, $()
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if let Some(pos) = find_substr(&line[i..], "kin ") {
            let abs_pos = i + pos;
            // Check word boundary: must be start of string or preceded by non-alphanumeric
            if abs_pos == 0 || !bytes[abs_pos - 1].is_ascii_alphanumeric() {
                // Extract the command from "kin " to end-of-token-sequence
                let cmd_start = abs_pos;
                let cmd = extract_command_from(line, cmd_start);
                if cmd.len() > 4 {
                    // Must have more than just "kin "
                    out.push(cmd);
                }
                i = abs_pos + 4;
            } else {
                i = abs_pos + 4;
            }
        } else {
            break;
        }
    }
}

/// Scan a line for filesystem tool invocations.
fn extract_fs_commands(line: &str, out: &mut Vec<String>) {
    for &cmd in FS_COMMANDS {
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if let Some(pos) = find_substr(&line[i..], cmd) {
                let abs_pos = i + pos;
                let after = abs_pos + cmd.len();
                // Word boundary before: start of string or non-alphanumeric
                let before_ok =
                    abs_pos == 0 || !bytes[abs_pos - 1].is_ascii_alphanumeric();
                // Word boundary after: end of string or non-alphanumeric (space, quote, etc.)
                let after_ok =
                    after >= bytes.len() || !bytes[after].is_ascii_alphanumeric();

                if before_ok && after_ok {
                    let full_cmd = extract_command_from(line, abs_pos);
                    out.push(full_cmd);
                    i = after;
                } else {
                    i = after;
                }
            } else {
                break;
            }
        }
    }
}

/// Scan a line for MCP tool names.
fn extract_mcp_calls(line: &str, out: &mut Vec<String>) {
    for &tool in KIN_MCP_TOOLS {
        if line.contains(tool) {
            out.push(tool.to_string());
        }
    }
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_substr(haystack: &str, needle: &str) -> Option<usize> {
    haystack.find(needle)
}

/// Extract a shell-like command starting at `start` in `line`.
/// Captures from `start` to the next line-end, closing quote, backtick, or `)`.
fn extract_command_from(line: &str, start: usize) -> String {
    let rest = &line[start..];
    // Find the end: newline, backtick, closing paren, closing quote, or pipe
    let end = rest
        .find(|c: char| c == '`' || c == ')' || c == '"' || c == '\'' || c == '\n')
        .unwrap_or(rest.len());
    rest[..end].trim().to_string()
}

/// Format a tool-usage section for the benchmark report.
pub fn format_tool_usage(logs: &[ToolUsageLog]) -> String {
    use std::collections::BTreeMap;
    use std::fmt::Write;

    if logs.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    writeln!(out, "=== Tool Usage ===").unwrap();
    writeln!(out).unwrap();

    // Group by task
    let mut by_task: BTreeMap<&str, Vec<&ToolUsageLog>> = BTreeMap::new();
    for log in logs {
        by_task.entry(&log.task).or_default().push(log);
    }

    for (task, task_logs) in &by_task {
        writeln!(out, "Task: {task}").unwrap();
        for log in task_logs {
            let kin_pct = (log.kin_tool_ratio * 100.0).round() as u32;
            writeln!(
                out,
                "  {} ({}): {} kin / {} filesystem / {} mcp  ({}% Kin-first)",
                log.arm,
                log.assistant,
                log.kin_commands.len(),
                log.filesystem_commands.len(),
                log.mcp_calls.len(),
                kin_pct,
            )
            .unwrap();
        }
        writeln!(out).unwrap();
    }

    out
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_kin_commands_basic() {
        let output = r#"I ran kin search "save|load" --show-body to find functions."#;
        let log = extract_tool_usage(output, "claude", "kin", "search-functions");
        assert_eq!(log.kin_commands.len(), 1);
        assert!(log.kin_commands[0].starts_with("kin search"));
    }

    #[test]
    fn extract_kin_overview() {
        let output = "First I used kin overview to understand the codebase.";
        let log = extract_tool_usage(output, "codex", "kin", "explain-architecture");
        assert_eq!(log.kin_commands.len(), 1);
        assert!(log.kin_commands[0].contains("kin overview"));
    }

    #[test]
    fn extract_fs_commands_grep_and_cat() {
        let output = "I ran grep -r 'save' src/ and then cat src/main.ts to read the file.";
        let log = extract_tool_usage(output, "claude", "git", "search-functions");
        assert!(log.filesystem_commands.len() >= 2);
        assert!(log.filesystem_commands.iter().any(|c| c.starts_with("grep")));
        assert!(log.filesystem_commands.iter().any(|c| c.starts_with("cat")));
    }

    #[test]
    fn extract_mcp_calls_semantic_search() {
        let output = r#"{"type":"tool_use","name":"semantic_search","input":{"query":"save"}}"#;
        let log = extract_tool_usage(output, "claude", "kin", "search-functions");
        assert!(log.mcp_calls.contains(&"semantic_search".to_string()));
    }

    #[test]
    fn extract_mcp_multiple_tools() {
        let output = "Used semantic_search for finding, then get_context_pack for context, and dead_code for cleanup.";
        let log = extract_tool_usage(output, "claude", "kin", "find-dead-code");
        assert_eq!(log.mcp_calls.len(), 3);
        assert!(log.mcp_calls.contains(&"semantic_search".to_string()));
        assert!(log.mcp_calls.contains(&"get_context_pack".to_string()));
        assert!(log.mcp_calls.contains(&"dead_code".to_string()));
    }

    #[test]
    fn kin_tool_ratio_all_kin() {
        let output = "kin search save\nkin overview";
        let log = extract_tool_usage(output, "claude", "kin", "test");
        assert!((log.kin_tool_ratio - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn kin_tool_ratio_no_tools() {
        let output = "I looked at the code and it seems fine.";
        let log = extract_tool_usage(output, "claude", "git", "test");
        assert!((log.kin_tool_ratio - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn kin_tool_ratio_mixed() {
        // 1 kin command + 1 fs command = 0.5 ratio
        let output = "kin search save\ngrep -r save src/";
        let log = extract_tool_usage(output, "claude", "kin", "test");
        assert!((log.kin_tool_ratio - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn does_not_match_kin_inside_word() {
        // "making" contains "kin" but should not be matched
        let output = "I was making a decision about the code.";
        let log = extract_tool_usage(output, "claude", "git", "test");
        assert!(log.kin_commands.is_empty());
    }

    #[test]
    fn does_not_match_fs_inside_word() {
        // "category" contains "cat" but should not be matched
        let output = "The category of this function is utility.";
        let log = extract_tool_usage(output, "claude", "git", "test");
        assert!(
            !log.filesystem_commands.iter().any(|c| c.starts_with("cat")),
            "should not match 'cat' inside 'category'"
        );
    }

    #[test]
    fn deduplicates_commands() {
        let output = "kin search save\nkin search save";
        let log = extract_tool_usage(output, "claude", "kin", "test");
        assert_eq!(log.kin_commands.len(), 1);
    }

    #[test]
    fn serialization_roundtrip() {
        let log = ToolUsageLog {
            arm: "kin".to_string(),
            assistant: "claude".to_string(),
            task: "test".to_string(),
            kin_commands: vec!["kin search save".to_string()],
            filesystem_commands: vec![],
            mcp_calls: vec!["semantic_search".to_string()],
            kin_tool_ratio: 1.0,
        };
        let json = serde_json::to_string(&log).unwrap();
        let parsed: ToolUsageLog = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.arm, "kin");
        assert_eq!(parsed.kin_commands.len(), 1);
        assert_eq!(parsed.mcp_calls.len(), 1);
        assert!((parsed.kin_tool_ratio - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn format_tool_usage_output() {
        let logs = vec![
            ToolUsageLog {
                arm: "git".to_string(),
                assistant: "claude".to_string(),
                task: "search-functions".to_string(),
                kin_commands: vec![],
                filesystem_commands: vec!["grep -r save".to_string(); 5],
                mcp_calls: vec![],
                kin_tool_ratio: 0.0,
            },
            ToolUsageLog {
                arm: "kin".to_string(),
                assistant: "claude".to_string(),
                task: "search-functions".to_string(),
                kin_commands: vec!["kin search save".to_string(), "kin overview".to_string()],
                filesystem_commands: vec![],
                mcp_calls: vec!["semantic_search".to_string()],
                kin_tool_ratio: 1.0,
            },
        ];

        let formatted = format_tool_usage(&logs);
        assert!(formatted.contains("=== Tool Usage ==="));
        assert!(formatted.contains("search-functions"));
        assert!(formatted.contains("0 kin / 5 filesystem / 0 mcp"));
        assert!(formatted.contains("2 kin / 0 filesystem / 1 mcp"));
        assert!(formatted.contains("0% Kin-first"));
        assert!(formatted.contains("100% Kin-first"));
    }

    #[test]
    fn format_tool_usage_empty() {
        let formatted = format_tool_usage(&[]);
        assert!(formatted.is_empty());
    }

    #[test]
    fn extract_claude_stream_json_tool_use_events() {
        let output = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Grep","input":{"pattern":"save"}},{"type":"tool_use","name":"Read","input":{"file_path":"src/store.ts"}},{"type":"tool_use","name":"Bash","input":{"command":"kin search saveUser --show-body --limit 5"}}]}}"#;
        let log = extract_tool_usage(output, "claude", "kin-native", "trace");
        assert!(log.filesystem_commands.iter().any(|c| c.starts_with("grep")));
        assert!(log.filesystem_commands.iter().any(|c| c.starts_with("cat")));
        assert!(log.kin_commands.iter().any(|c| c.starts_with("kin search")));
    }
}
