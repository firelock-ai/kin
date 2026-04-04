// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{anyhow, bail, Context, Result};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

const CONTEXTBENCH_LOCATE_SCHEMA: &str = "kin.contextbench-locate.v1";
const CONTEXTBENCH_QUERY_CHAR_LIMIT: usize = 4000;
const CONTEXTBENCH_DEFAULT_MAX_FILES: usize = 25;

#[derive(Debug, Serialize)]
struct ContextbenchLocateResult {
    schema: &'static str,
    selected_query_field: String,
    query_char_limit: usize,
    query_truncated: bool,
    max_files: usize,
    files: Vec<Value>,
}

pub async fn run(task_file: PathBuf, json: bool) -> Result<()> {
    let task: Value = serde_json::from_str(
        &std::fs::read_to_string(&task_file)
            .with_context(|| format!("read task payload {}", task_file.display()))?,
    )
    .with_context(|| format!("parse task payload {}", task_file.display()))?;

    let (selected_query_field, query) = select_query(&task)?;
    let query_truncated = query.chars().count() > CONTEXTBENCH_QUERY_CHAR_LIMIT;
    let bounded_query: String = query.chars().take(CONTEXTBENCH_QUERY_CHAR_LIMIT).collect();
    let max_files = contextbench_max_files();

    let current_exe = std::env::current_exe().context("resolve current kin binary")?;
    let mut child = Command::new(current_exe);
    child
        .arg("locate")
        .arg("--json")
        .arg("--explain")
        .arg("--max-files")
        .arg(max_files.to_string())
        .arg(&bounded_query)
        .current_dir(std::env::current_dir()?);
    child.env_remove("KIN_PROFILE_OUT");
    child.env_remove("KIN_PROFILE_SUMMARY");
    // Prevent VFS shim deadlock: locate is a graph operation, not a file read.
    child.env("KIN_NO_VFS", "1");
    let output = child.output().context("run kin locate")?;
    if !output.status.success() {
        bail!(
            "contextbench locate wrapper failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let locate_payload: Value =
        serde_json::from_slice(&output.stdout).context("parse locate --json output")?;
    let files = locate_payload
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("locate payload missing files array"))?;

    let normalized_files = files
        .iter()
        .filter_map(normalize_locate_entry)
        .collect::<Result<Vec<_>>>()?;

    let result = ContextbenchLocateResult {
        schema: CONTEXTBENCH_LOCATE_SCHEMA,
        selected_query_field: selected_query_field.to_string(),
        query_char_limit: CONTEXTBENCH_QUERY_CHAR_LIMIT,
        query_truncated,
        max_files,
        files: normalized_files,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(())
}

fn select_query(task: &Value) -> Result<(&'static str, String)> {
    let fields = [
        ("description", task.get("description")),
        ("problem_statement", task.get("problem_statement")),
        ("prompt", task.get("prompt")),
    ];
    for (field, value) in fields {
        if let Some(text) = value.and_then(Value::as_str) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return Ok((field, trimmed.to_string()));
            }
        }
    }
    bail!("task payload missing description/problem_statement/prompt text")
}

fn contextbench_max_files() -> usize {
    parse_contextbench_max_files(std::env::var("KIN_CONTEXTBENCH_MAX_FILES").ok().as_deref())
}

fn parse_contextbench_max_files(raw: Option<&str>) -> usize {
    raw.and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(CONTEXTBENCH_DEFAULT_MAX_FILES)
}

fn normalize_locate_entry(entry: &Value) -> Option<Result<Value>> {
    let object = entry.as_object()?;
    let raw_path = object
        .get("path")
        .or_else(|| object.get("file"))
        .or_else(|| object.get("file_path"))?
        .as_str()?;
    let normalized = normalize_path(raw_path);
    if normalized.is_empty() {
        return None;
    }
    let mut normalized_entry = object.clone();
    normalized_entry.insert("file".into(), Value::String(normalized.clone()));
    normalized_entry.insert("path".into(), Value::String(normalized.clone()));
    normalized_entry.insert("file_path".into(), Value::String(normalized.clone()));
    normalized_entry.insert("normalized_file".into(), Value::String(normalized));
    Some(Ok(Value::Object(normalized_entry)))
}

fn normalize_path(path: &str) -> String {
    let re = Regex::new(r"^/?workspace/[^/]+/").expect("workspace prefix regex");
    re.replace(path.trim(), "")
        .trim_start_matches("./")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        contextbench_max_files, normalize_path, parse_contextbench_max_files, select_query,
        CONTEXTBENCH_DEFAULT_MAX_FILES, CONTEXTBENCH_QUERY_CHAR_LIMIT,
    };
    use serde_json::json;

    #[test]
    fn select_query_prefers_description_then_problem_statement_then_prompt() {
        let payload = json!({
            "description": "",
            "problem_statement": "needle",
            "prompt": "fallback"
        });
        let (field, query) = select_query(&payload).unwrap();
        assert_eq!(field, "problem_statement");
        assert_eq!(query, "needle");
    }

    #[test]
    fn normalize_path_strips_workspace_prefix() {
        assert_eq!(
            normalize_path("/workspace/demo__repo/src/lib.rs"),
            "src/lib.rs"
        );
        assert_eq!(normalize_path("./src/lib.rs"), "src/lib.rs");
        assert_eq!(CONTEXTBENCH_QUERY_CHAR_LIMIT, 4000);
        assert_eq!(contextbench_max_files(), CONTEXTBENCH_DEFAULT_MAX_FILES);
    }

    #[test]
    fn parse_contextbench_max_files_accepts_positive_values() {
        assert_eq!(parse_contextbench_max_files(Some("40")), 40);
        assert_eq!(
            parse_contextbench_max_files(Some("0")),
            CONTEXTBENCH_DEFAULT_MAX_FILES
        );
        assert_eq!(
            parse_contextbench_max_files(Some("nope")),
            CONTEXTBENCH_DEFAULT_MAX_FILES
        );
    }
}
