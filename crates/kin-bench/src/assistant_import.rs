// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{BenchError, Result};
use crate::metrics::{AssistantRunSource, AssistantTaskRun, BenchmarkSubstrate, DurationMs};

/// Supported external assistant run source formats.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssistantRunSourceFormat {
    CodexJsonl,
    ClaudeCodeJsonl,
    GeminiCliJson,
}

/// Import spec for converting external CLI/session artifacts into AssistantTaskRun records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssistantRunImportSpec {
    pub task_name: String,
    pub substrate: BenchmarkSubstrate,
    pub source_format: AssistantRunSourceFormat,
    pub source_path: String,
    pub assistant_name: Option<String>,
    pub model_name: Option<String>,
    pub estimated_cost_usd: Option<f64>,
    pub first_pass_success: Option<bool>,
    pub validation_passed: Option<bool>,
    pub notes: Option<String>,
}

impl AssistantRunImportSpec {
    pub fn resolve_source_path(&self, base_dir: Option<&Path>) -> PathBuf {
        let path = PathBuf::from(&self.source_path);
        if path.is_absolute() {
            path
        } else if let Some(base_dir) = base_dir {
            base_dir.join(path)
        } else {
            path
        }
    }
}

/// Load assistant runs from a JSON file.
///
/// Supported file shapes:
/// - a single `AssistantTaskRun`
/// - an array of `AssistantTaskRun`
/// - a single `AssistantRunImportSpec`
/// - an array of `AssistantRunImportSpec`
pub fn load_assistant_runs_from_path(path: &Path) -> Result<Vec<AssistantTaskRun>> {
    let content = fs::read_to_string(path).map_err(|e| BenchError::io(path, e))?;

    if let Ok(run) = serde_json::from_str::<AssistantTaskRun>(&content) {
        return Ok(vec![run]);
    }

    if let Ok(runs) = serde_json::from_str::<Vec<AssistantTaskRun>>(&content) {
        return Ok(runs);
    }

    if let Ok(spec) = serde_json::from_str::<AssistantRunImportSpec>(&content) {
        return load_from_import_spec(&spec, path.parent());
    }

    if let Ok(specs) = serde_json::from_str::<Vec<AssistantRunImportSpec>>(&content) {
        let mut runs = Vec::new();
        for spec in specs {
            runs.extend(load_from_import_spec(&spec, path.parent())?);
        }
        return Ok(runs);
    }

    Err(BenchError::Other(format!(
        "assistant run file {} must be an AssistantTaskRun, an array of AssistantTaskRun, an import spec, or an array of import specs",
        path.display()
    )))
}

/// Convert an external assistant artifact into one or more AssistantTaskRun values.
pub fn load_from_import_spec(
    spec: &AssistantRunImportSpec,
    base_dir: Option<&Path>,
) -> Result<Vec<AssistantTaskRun>> {
    let source_path = spec.resolve_source_path(base_dir);
    let runs = match spec.source_format {
        AssistantRunSourceFormat::CodexJsonl => load_codex_jsonl(spec, &source_path)?,
        AssistantRunSourceFormat::ClaudeCodeJsonl => load_claude_code_jsonl(spec, &source_path)?,
        AssistantRunSourceFormat::GeminiCliJson => load_gemini_cli_json(spec, &source_path)?,
    };
    Ok(runs)
}

fn load_codex_jsonl(spec: &AssistantRunImportSpec, path: &Path) -> Result<Vec<AssistantTaskRun>> {
    let content = fs::read_to_string(path).map_err(|e| BenchError::io(path, e))?;

    let mut first_timestamp = None;
    let mut last_timestamp = None;
    let mut latest_tokens = None;
    let mut latest_model_name = spec.model_name.clone();

    for line in content.lines() {
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => continue,
        };

        let timestamp = value
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(parse_timestamp);
        if let Some(timestamp) = timestamp {
            first_timestamp = Some(first_timestamp.unwrap_or(timestamp));
            last_timestamp = Some(timestamp);
        }

        if value.get("type").and_then(Value::as_str) != Some("event_msg") {
            continue;
        }
        let payload = match value.get("payload") {
            Some(Value::Object(payload)) => payload,
            _ => continue,
        };
        if payload.get("type").and_then(Value::as_str) != Some("token_count") {
            continue;
        }

        if let Some(total_usage) = payload
            .get("info")
            .and_then(|info| info.get("total_token_usage"))
            .and_then(Value::as_object)
        {
            latest_tokens = Some((
                read_u64(total_usage.get("input_tokens")),
                read_u64(total_usage.get("output_tokens")),
                read_u64(total_usage.get("total_tokens")),
            ));
        }

        if latest_model_name.is_none() {
            latest_model_name = payload
                .get("rate_limits")
                .and_then(|rate_limits| rate_limits.get("limit_name"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
        }
    }

    let (input_tokens, output_tokens, total_tokens) = latest_tokens.ok_or_else(|| {
        BenchError::Other(format!(
            "no codex token_count events found in {}",
            path.display()
        ))
    })?;
    let recorded_at = last_timestamp.unwrap_or_else(Utc::now);
    let duration_ms = duration_ms_between(first_timestamp, last_timestamp);

    Ok(vec![AssistantTaskRun {
        task_name: spec.task_name.clone(),
        assistant_name: spec
            .assistant_name
            .clone()
            .unwrap_or_else(|| "Codex".to_string()),
        model_name: latest_model_name,
        substrate: spec.substrate,
        duration_ms,
        input_tokens,
        output_tokens,
        total_tokens,
        estimated_cost_usd: spec.estimated_cost_usd.unwrap_or(0.0),
        first_pass_success: spec.first_pass_success.unwrap_or(false),
        validation_passed: spec.validation_passed.unwrap_or(false),
        run_source: AssistantRunSource::ArtifactImport,
        notes: spec.notes.clone(),
        recorded_at,
    }])
}

fn load_claude_code_jsonl(
    spec: &AssistantRunImportSpec,
    path: &Path,
) -> Result<Vec<AssistantTaskRun>> {
    let content = fs::read_to_string(path).map_err(|e| BenchError::io(path, e))?;

    let mut first_timestamp = None;
    let mut last_timestamp = None;
    let mut model_name = spec.model_name.clone();
    let mut input_tokens = 0u64;
    let mut output_tokens = 0u64;

    for line in content.lines() {
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => continue,
        };

        let timestamp = value
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(parse_timestamp);
        if let Some(timestamp) = timestamp {
            first_timestamp = Some(first_timestamp.unwrap_or(timestamp));
            last_timestamp = Some(timestamp);
        }

        if value.get("type").and_then(Value::as_str) != Some("assistant") {
            continue;
        }
        let message = match value.get("message") {
            Some(Value::Object(message)) => message,
            _ => continue,
        };
        let usage = match message.get("usage").and_then(Value::as_object) {
            Some(usage) => usage,
            None => continue,
        };

        input_tokens = input_tokens
            .saturating_add(read_u64(usage.get("input_tokens")))
            .saturating_add(read_u64(usage.get("cache_creation_input_tokens")))
            .saturating_add(read_u64(usage.get("cache_read_input_tokens")));
        output_tokens = output_tokens.saturating_add(read_u64(usage.get("output_tokens")));

        if model_name.is_none() {
            model_name = message
                .get("model")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
        }
    }

    if input_tokens == 0 && output_tokens == 0 {
        return Err(BenchError::Other(format!(
            "no Claude Code assistant usage found in {}",
            path.display()
        )));
    }

    let total_tokens = input_tokens.saturating_add(output_tokens);
    let recorded_at = last_timestamp.unwrap_or_else(Utc::now);
    let duration_ms = duration_ms_between(first_timestamp, last_timestamp);

    Ok(vec![AssistantTaskRun {
        task_name: spec.task_name.clone(),
        assistant_name: spec
            .assistant_name
            .clone()
            .unwrap_or_else(|| "Claude Code".to_string()),
        model_name,
        substrate: spec.substrate,
        duration_ms,
        input_tokens,
        output_tokens,
        total_tokens,
        estimated_cost_usd: spec.estimated_cost_usd.unwrap_or(0.0),
        first_pass_success: spec.first_pass_success.unwrap_or(false),
        validation_passed: spec.validation_passed.unwrap_or(false),
        run_source: AssistantRunSource::ArtifactImport,
        notes: spec.notes.clone(),
        recorded_at,
    }])
}

fn load_gemini_cli_json(
    spec: &AssistantRunImportSpec,
    path: &Path,
) -> Result<Vec<AssistantTaskRun>> {
    let content = fs::read_to_string(path).map_err(|e| BenchError::io(path, e))?;
    let value: Value = serde_json::from_str(&content)?;
    let models = value
        .get("stats")
        .and_then(|stats| stats.get("models"))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            BenchError::Other(format!(
                "Gemini CLI JSON in {} is missing stats.models",
                path.display()
            ))
        })?;

    let mut total_input_tokens = 0u64;
    let mut total_output_tokens = 0u64;
    let mut total_tokens = 0u64;
    let mut total_latency_ms = 0.0;
    let mut model_names = Vec::new();

    for (model_name, stats) in models {
        model_names.push(model_name.clone());
        if let Some(tokens) = stats.get("tokens").and_then(Value::as_object) {
            total_input_tokens = total_input_tokens
                .saturating_add(read_u64(tokens.get("input")))
                .saturating_add(read_u64(tokens.get("cached")));

            let candidates = read_u64(tokens.get("candidates"));
            let thoughts = read_u64(tokens.get("thoughts"));
            let tool = read_u64(tokens.get("tool"));
            total_output_tokens = total_output_tokens
                .saturating_add(candidates)
                .saturating_add(thoughts)
                .saturating_add(tool);

            let reported_total = read_u64(tokens.get("total"));
            if reported_total > 0 {
                total_tokens = total_tokens.saturating_add(reported_total);
            }
        }

        if let Some(api) = stats.get("api").and_then(Value::as_object) {
            total_latency_ms += read_f64(api.get("totalLatencyMs"));
        }
    }

    if total_tokens == 0 {
        total_tokens = total_input_tokens.saturating_add(total_output_tokens);
    }

    model_names.sort();

    let recorded_at = file_timestamp(path)?;
    let model_name = match model_names.len() {
        0 => spec.model_name.clone(),
        1 => Some(model_names.remove(0)),
        _ => Some(model_names.join("+")),
    };

    Ok(vec![AssistantTaskRun {
        task_name: spec.task_name.clone(),
        assistant_name: spec
            .assistant_name
            .clone()
            .unwrap_or_else(|| "Gemini CLI".to_string()),
        model_name,
        substrate: spec.substrate,
        duration_ms: DurationMs(total_latency_ms),
        input_tokens: total_input_tokens,
        output_tokens: total_output_tokens,
        total_tokens,
        estimated_cost_usd: spec.estimated_cost_usd.unwrap_or(0.0),
        first_pass_success: spec.first_pass_success.unwrap_or(false),
        validation_passed: spec.validation_passed.unwrap_or(false),
        run_source: AssistantRunSource::ArtifactImport,
        notes: spec.notes.clone(),
        recorded_at,
    }])
}

fn read_u64(value: Option<&Value>) -> u64 {
    value.and_then(Value::as_u64).unwrap_or(0)
}

fn read_f64(value: Option<&Value>) -> f64 {
    value.and_then(Value::as_f64).unwrap_or(0.0)
}

fn parse_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|ts| ts.with_timezone(&Utc))
        .ok()
}

fn duration_ms_between(first: Option<DateTime<Utc>>, last: Option<DateTime<Utc>>) -> DurationMs {
    match (first, last) {
        (Some(first), Some(last)) if last >= first => {
            DurationMs((last - first).num_milliseconds() as f64)
        }
        _ => DurationMs(0.0),
    }
}

fn file_timestamp(path: &Path) -> Result<DateTime<Utc>> {
    let metadata = fs::metadata(path).map_err(|e| BenchError::io(path, e))?;
    let modified = metadata
        .modified()
        .map_err(|e| BenchError::Other(e.to_string()))?;
    Ok(DateTime::<Utc>::from(modified))
}

// ---------------------------------------------------------------------------
// AssistantArtifact: normalized file-level metrics extracted from raw logs
// ---------------------------------------------------------------------------

/// Normalized summary of what an assistant session actually touched.
///
/// Extracted from raw Claude conversation JSON, Codex patch/diff files,
/// or Gemini session logs. Complements the token-level `AssistantTaskRun`
/// with concrete file-change statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssistantArtifact {
    pub vendor: String,
    pub files_touched: Vec<String>,
    pub lines_added: usize,
    pub lines_removed: usize,
    pub tool_calls: usize,
    pub iterations: usize,
    pub raw_duration_secs: Option<f64>,
}

/// Parse a Claude conversation JSON export into an `AssistantArtifact`.
///
/// Expects JSONL where each line is an event. Extracts:
/// - files modified from `tool_use` blocks (Write/Edit tool calls with `file_path`)
/// - tool call count from `tool_use` content blocks
/// - iterations from assistant message count
/// - duration from first/last timestamps
pub fn parse_claude_artifact(path: &Path) -> Result<AssistantArtifact> {
    let content = fs::read_to_string(path).map_err(|e| BenchError::io(path, e))?;
    let mut files = HashSet::new();
    let mut tool_calls = 0usize;
    let mut iterations = 0usize;
    let mut lines_added = 0usize;
    let mut lines_removed = 0usize;
    let mut first_ts: Option<DateTime<Utc>> = None;
    let mut last_ts: Option<DateTime<Utc>> = None;

    for line in content.lines() {
        let value: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some(ts) = value
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(parse_timestamp)
        {
            if first_ts.is_none() {
                first_ts = Some(ts);
            }
            last_ts = Some(ts);
        }

        let msg_type = value.get("type").and_then(Value::as_str).unwrap_or("");
        if msg_type == "assistant" {
            iterations += 1;

            // Scan content blocks for tool_use
            if let Some(content_blocks) = value
                .get("message")
                .and_then(|m| m.get("content"))
                .and_then(Value::as_array)
            {
                for block in content_blocks {
                    if block.get("type").and_then(Value::as_str) == Some("tool_use") {
                        tool_calls += 1;
                        // Extract file path from input
                        if let Some(input) = block.get("input").and_then(Value::as_object) {
                            if let Some(fp) = input.get("file_path").and_then(Value::as_str) {
                                files.insert(fp.to_string());
                            }
                            // Count lines from new_string / old_string diffs
                            if let Some(new_s) = input.get("new_string").and_then(Value::as_str) {
                                lines_added += new_s.lines().count();
                            }
                            if let Some(old_s) = input.get("old_string").and_then(Value::as_str) {
                                lines_removed += old_s.lines().count();
                            }
                            // Write tool: content is all new lines
                            if let Some(c) = input.get("content").and_then(Value::as_str) {
                                if input.contains_key("file_path") {
                                    lines_added += c.lines().count();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let raw_duration_secs = match (first_ts, last_ts) {
        (Some(f), Some(l)) if l >= f => Some((l - f).num_milliseconds() as f64 / 1000.0),
        _ => None,
    };

    let mut files_touched: Vec<String> = files.into_iter().collect();
    files_touched.sort();

    Ok(AssistantArtifact {
        vendor: "claude".to_string(),
        files_touched,
        lines_added,
        lines_removed,
        tool_calls,
        iterations,
        raw_duration_secs,
    })
}

/// Parse a Codex patch/diff file into an `AssistantArtifact`.
///
/// Accepts unified diff format. Extracts:
/// - files modified from `--- a/` / `+++ b/` headers
/// - lines added (`+` lines) and removed (`-` lines)
/// - hunk count as iterations
pub fn parse_codex_artifact(path: &Path) -> Result<AssistantArtifact> {
    let content = fs::read_to_string(path).map_err(|e| BenchError::io(path, e))?;
    let mut files = HashSet::new();
    let mut lines_added = 0usize;
    let mut lines_removed = 0usize;
    let mut hunks = 0usize;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("+++ b/") {
            let file = rest.split('\t').next().unwrap_or(rest);
            files.insert(file.to_string());
        } else if let Some(rest) = line.strip_prefix("--- a/") {
            let file = rest.split('\t').next().unwrap_or(rest);
            files.insert(file.to_string());
        } else if line.starts_with("@@ ") {
            hunks += 1;
        } else if let Some(stripped) = line.strip_prefix('+') {
            if !stripped.is_empty() || line == "+" {
                lines_added += 1;
            }
        } else if let Some(stripped) = line.strip_prefix('-') {
            if !stripped.is_empty() || line == "-" {
                lines_removed += 1;
            }
        }
    }

    // Remove /dev/null entries
    files.remove("/dev/null");
    // Also handle "--- /dev/null" which has no a/ prefix
    // (already won't match strip_prefix("--- a/"))

    let mut files_touched: Vec<String> = files.into_iter().collect();
    files_touched.sort();

    Ok(AssistantArtifact {
        vendor: "codex".to_string(),
        files_touched,
        lines_added,
        lines_removed,
        tool_calls: 0,
        iterations: hunks,
        raw_duration_secs: None,
    })
}

/// Parse a Gemini session log (JSON) into an `AssistantArtifact`.
///
/// Expects a JSON object with a `parts` array containing turn entries.
/// Extracts:
/// - files from code blocks with file-path markers
/// - iterations from model turn count
/// - tool calls from `functionCall` parts
/// - duration from `stats.models.*.api.totalLatencyMs`
pub fn parse_gemini_artifact(path: &Path) -> Result<AssistantArtifact> {
    let content = fs::read_to_string(path).map_err(|e| BenchError::io(path, e))?;
    let value: Value = serde_json::from_str(&content)?;

    let mut files = HashSet::new();
    let mut tool_calls = 0usize;
    let mut iterations = 0usize;
    let mut lines_added = 0usize;
    let mut total_latency_ms = 0.0f64;

    // Extract file/code info from turns array
    if let Some(turns) = value.get("turns").and_then(Value::as_array) {
        for turn in turns {
            let role = turn.get("role").and_then(Value::as_str).unwrap_or("");
            if role == "model" {
                iterations += 1;
            }

            if let Some(parts) = turn.get("parts").and_then(Value::as_array) {
                for part in parts {
                    // Function calls
                    if part.get("functionCall").is_some() {
                        tool_calls += 1;
                        // Extract file path from function args
                        if let Some(args) = part
                            .get("functionCall")
                            .and_then(|fc| fc.get("args"))
                            .and_then(Value::as_object)
                        {
                            for key in ["file_path", "path", "filePath"] {
                                if let Some(fp) = args.get(key).and_then(Value::as_str) {
                                    files.insert(fp.to_string());
                                }
                            }
                        }
                    }
                    // Code blocks in text — look for file path markers like "```filepath"
                    if let Some(text) = part.get("text").and_then(Value::as_str) {
                        for line in text.lines() {
                            if line.starts_with("```") && line.len() > 3 {
                                let rest = line.trim_start_matches('`').trim();
                                // Heuristic: if it contains a dot and slash, it's likely a file path
                                if rest.contains('/') && rest.contains('.') {
                                    files.insert(rest.to_string());
                                }
                            }
                        }
                        // Count non-empty lines in code blocks as added lines
                        let mut in_block = false;
                        for line in text.lines() {
                            if line.starts_with("```") {
                                in_block = !in_block;
                                continue;
                            }
                            if in_block && !line.is_empty() {
                                lines_added += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    // Extract latency from stats
    if let Some(models) = value
        .get("stats")
        .and_then(|s| s.get("models"))
        .and_then(Value::as_object)
    {
        for (_name, stats) in models {
            if let Some(api) = stats.get("api").and_then(Value::as_object) {
                total_latency_ms += read_f64(api.get("totalLatencyMs"));
            }
        }
    }

    let raw_duration_secs = if total_latency_ms > 0.0 {
        Some(total_latency_ms / 1000.0)
    } else {
        None
    };

    let mut files_touched: Vec<String> = files.into_iter().collect();
    files_touched.sort();

    Ok(AssistantArtifact {
        vendor: "gemini".to_string(),
        files_touched,
        lines_added,
        lines_removed: 0,
        tool_calls,
        iterations,
        raw_duration_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_jsonl_import_builds_task_run() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("codex.jsonl");
        fs::write(
            &source,
            concat!(
                "{\"timestamp\":\"2026-03-10T20:00:00Z\",\"type\":\"session_meta\"}\n",
                "{\"timestamp\":\"2026-03-10T20:00:02Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":1000,\"output_tokens\":200,\"total_tokens\":1200}},\"rate_limits\":{\"limit_name\":\"GPT-5 Codex\"}}}\n"
            ),
        )
        .unwrap();

        let runs = load_from_import_spec(
            &AssistantRunImportSpec {
                task_name: "compare".into(),
                substrate: BenchmarkSubstrate::Kin,
                source_format: AssistantRunSourceFormat::CodexJsonl,
                source_path: source.display().to_string(),
                assistant_name: None,
                model_name: None,
                estimated_cost_usd: Some(0.11),
                first_pass_success: Some(true),
                validation_passed: Some(true),
                notes: None,
            },
            None,
        )
        .unwrap();

        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].assistant_name, "Codex");
        assert_eq!(runs[0].model_name.as_deref(), Some("GPT-5 Codex"));
        assert_eq!(runs[0].total_tokens, 1200);
        assert!(runs[0].duration_ms.0 > 0.0);
    }

    #[test]
    fn claude_jsonl_import_sums_usage() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("claude.jsonl");
        fs::write(
            &source,
            concat!(
                "{\"timestamp\":\"2026-03-10T20:00:00Z\",\"type\":\"assistant\",\"message\":{\"model\":\"claude-opus-4-6\",\"usage\":{\"input_tokens\":100,\"cache_creation_input_tokens\":20,\"cache_read_input_tokens\":30,\"output_tokens\":10}}}\n",
                "{\"timestamp\":\"2026-03-10T20:00:04Z\",\"type\":\"assistant\",\"message\":{\"model\":\"claude-opus-4-6\",\"usage\":{\"input_tokens\":200,\"cache_creation_input_tokens\":0,\"cache_read_input_tokens\":50,\"output_tokens\":15}}}\n"
            ),
        )
        .unwrap();

        let runs = load_from_import_spec(
            &AssistantRunImportSpec {
                task_name: "compare".into(),
                substrate: BenchmarkSubstrate::Git,
                source_format: AssistantRunSourceFormat::ClaudeCodeJsonl,
                source_path: source.display().to_string(),
                assistant_name: None,
                model_name: None,
                estimated_cost_usd: None,
                first_pass_success: Some(false),
                validation_passed: Some(true),
                notes: None,
            },
            None,
        )
        .unwrap();

        assert_eq!(runs[0].assistant_name, "Claude Code");
        assert_eq!(runs[0].model_name.as_deref(), Some("claude-opus-4-6"));
        assert_eq!(runs[0].input_tokens, 400);
        assert_eq!(runs[0].output_tokens, 25);
        assert_eq!(runs[0].total_tokens, 425);
    }

    #[test]
    fn gemini_json_import_aggregates_models() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("gemini.json");
        fs::write(
            &source,
            serde_json::json!({
                "session_id": "abc",
                "response": "OK",
                "stats": {
                    "models": {
                        "gemini-2.5-flash-lite": {
                            "api": { "totalLatencyMs": 1000.0 },
                            "tokens": {
                                "input": 1000,
                                "candidates": 50,
                                "total": 1060,
                                "cached": 0,
                                "thoughts": 10,
                                "tool": 0
                            }
                        },
                        "gemini-2.5-flash": {
                            "api": { "totalLatencyMs": 500.0 },
                            "tokens": {
                                "input": 2000,
                                "candidates": 5,
                                "total": 2010,
                                "cached": 0,
                                "thoughts": 5,
                                "tool": 0
                            }
                        }
                    }
                }
            })
            .to_string(),
        )
        .unwrap();

        let runs = load_from_import_spec(
            &AssistantRunImportSpec {
                task_name: "compare".into(),
                substrate: BenchmarkSubstrate::Kin,
                source_format: AssistantRunSourceFormat::GeminiCliJson,
                source_path: source.display().to_string(),
                assistant_name: None,
                model_name: None,
                estimated_cost_usd: None,
                first_pass_success: Some(true),
                validation_passed: Some(true),
                notes: None,
            },
            None,
        )
        .unwrap();

        assert_eq!(runs[0].assistant_name, "Gemini CLI");
        assert_eq!(
            runs[0].model_name.as_deref(),
            Some("gemini-2.5-flash+gemini-2.5-flash-lite")
        );
        assert_eq!(runs[0].total_tokens, 3070);
        assert_eq!(runs[0].duration_ms.0, 1500.0);
    }

    #[test]
    fn loader_accepts_import_spec_array() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("claude.jsonl");
        let spec_file = dir.path().join("import.json");
        fs::write(
            &source,
            "{\"timestamp\":\"2026-03-10T20:00:00Z\",\"type\":\"assistant\",\"message\":{\"model\":\"claude-opus-4-6\",\"usage\":{\"input_tokens\":100,\"output_tokens\":10}}}\n",
        )
        .unwrap();
        fs::write(
            &spec_file,
            serde_json::to_string(&vec![AssistantRunImportSpec {
                task_name: "compare".into(),
                substrate: BenchmarkSubstrate::Kin,
                source_format: AssistantRunSourceFormat::ClaudeCodeJsonl,
                source_path: "claude.jsonl".into(),
                assistant_name: None,
                model_name: None,
                estimated_cost_usd: None,
                first_pass_success: Some(true),
                validation_passed: Some(true),
                notes: None,
            }])
            .unwrap(),
        )
        .unwrap();

        let runs = load_assistant_runs_from_path(&spec_file).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].task_name, "compare");
    }

    // -- AssistantArtifact tests --

    #[test]
    fn claude_artifact_extracts_tool_calls_and_files() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("claude_session.jsonl");
        fs::write(
            &source,
            concat!(
                "{\"timestamp\":\"2026-03-10T20:00:00Z\",\"type\":\"assistant\",\"message\":{\"model\":\"claude-opus-4-6\",\"usage\":{\"input_tokens\":100,\"output_tokens\":10},\"content\":[{\"type\":\"tool_use\",\"name\":\"Edit\",\"input\":{\"file_path\":\"src/main.rs\",\"old_string\":\"fn old()\",\"new_string\":\"fn new()\\nfn extra()\"}}]}}\n",
                "{\"timestamp\":\"2026-03-10T20:00:05Z\",\"type\":\"assistant\",\"message\":{\"model\":\"claude-opus-4-6\",\"usage\":{\"input_tokens\":200,\"output_tokens\":20},\"content\":[{\"type\":\"tool_use\",\"name\":\"Write\",\"input\":{\"file_path\":\"src/lib.rs\",\"content\":\"pub fn hello() {}\\npub fn world() {}\"}}]}}\n"
            ),
        )
        .unwrap();

        let artifact = parse_claude_artifact(&source).unwrap();
        assert_eq!(artifact.vendor, "claude");
        assert_eq!(artifact.files_touched, vec!["src/lib.rs", "src/main.rs"]);
        assert_eq!(artifact.tool_calls, 2);
        assert_eq!(artifact.iterations, 2);
        // old_string has 1 line, new_string has 2 lines, Write content has 2 lines
        assert_eq!(artifact.lines_removed, 1);
        assert_eq!(artifact.lines_added, 4);
        assert!(artifact.raw_duration_secs.unwrap() > 0.0);
    }

    #[test]
    fn claude_artifact_handles_empty_session() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("empty.jsonl");
        // No timestamps at all — raw_duration_secs should be None
        fs::write(&source, "{\"type\":\"human\",\"message\":{}}\n").unwrap();

        let artifact = parse_claude_artifact(&source).unwrap();
        assert_eq!(artifact.vendor, "claude");
        assert!(artifact.files_touched.is_empty());
        assert_eq!(artifact.tool_calls, 0);
        assert_eq!(artifact.iterations, 0);
        assert!(artifact.raw_duration_secs.is_none());
    }

    #[test]
    fn codex_artifact_parses_unified_diff() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("codex.patch");
        fs::write(
            &source,
            concat!(
                "diff --git a/src/main.rs b/src/main.rs\n",
                "--- a/src/main.rs\n",
                "+++ b/src/main.rs\n",
                "@@ -1,3 +1,4 @@\n",
                " fn main() {\n",
                "-    println!(\"old\");\n",
                "+    println!(\"new\");\n",
                "+    println!(\"extra\");\n",
                " }\n",
                "diff --git a/src/lib.rs b/src/lib.rs\n",
                "--- a/src/lib.rs\n",
                "+++ b/src/lib.rs\n",
                "@@ -5,2 +5,3 @@\n",
                "+pub fn added() {}\n",
                " // end\n",
            ),
        )
        .unwrap();

        let artifact = parse_codex_artifact(&source).unwrap();
        assert_eq!(artifact.vendor, "codex");
        assert_eq!(artifact.files_touched, vec!["src/lib.rs", "src/main.rs"]);
        assert_eq!(artifact.lines_added, 3);
        assert_eq!(artifact.lines_removed, 1);
        assert_eq!(artifact.iterations, 2); // 2 hunks
    }

    #[test]
    fn codex_artifact_handles_empty_diff() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("empty.patch");
        fs::write(&source, "").unwrap();

        let artifact = parse_codex_artifact(&source).unwrap();
        assert_eq!(artifact.vendor, "codex");
        assert!(artifact.files_touched.is_empty());
        assert_eq!(artifact.lines_added, 0);
        assert_eq!(artifact.lines_removed, 0);
    }

    #[test]
    fn gemini_artifact_extracts_turns_and_tool_calls() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("gemini_session.json");
        fs::write(
            &source,
            serde_json::json!({
                "turns": [
                    {
                        "role": "user",
                        "parts": [{"text": "Fix the bug in src/main.rs"}]
                    },
                    {
                        "role": "model",
                        "parts": [
                            {"text": "I'll fix it.\n```src/utils.rs\nfn helper() {}\n```"},
                            {"functionCall": {"name": "edit_file", "args": {"file_path": "src/main.rs", "content": "fixed"}}}
                        ]
                    },
                    {
                        "role": "model",
                        "parts": [
                            {"functionCall": {"name": "write_file", "args": {"path": "src/new.rs", "content": "new file"}}}
                        ]
                    }
                ],
                "stats": {
                    "models": {
                        "gemini-2.5-pro": {
                            "api": {"totalLatencyMs": 3500.0},
                            "tokens": {"input": 500, "total": 800}
                        }
                    }
                }
            })
            .to_string(),
        )
        .unwrap();

        let artifact = parse_gemini_artifact(&source).unwrap();
        assert_eq!(artifact.vendor, "gemini");
        assert!(artifact.files_touched.contains(&"src/main.rs".to_string()));
        assert!(artifact.files_touched.contains(&"src/new.rs".to_string()));
        assert_eq!(artifact.tool_calls, 2);
        assert_eq!(artifact.iterations, 2); // 2 model turns
        assert!((artifact.raw_duration_secs.unwrap() - 3.5).abs() < 0.01);
    }

    #[test]
    fn gemini_artifact_handles_no_turns() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("gemini_empty.json");
        fs::write(
            &source,
            serde_json::json!({
                "stats": {
                    "models": {}
                }
            })
            .to_string(),
        )
        .unwrap();

        let artifact = parse_gemini_artifact(&source).unwrap();
        assert_eq!(artifact.vendor, "gemini");
        assert!(artifact.files_touched.is_empty());
        assert_eq!(artifact.tool_calls, 0);
        assert_eq!(artifact.iterations, 0);
        assert!(artifact.raw_duration_secs.is_none());
    }
}
