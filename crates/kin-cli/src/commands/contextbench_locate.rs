// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

const CONTEXTBENCH_LOCATE_SCHEMA: &str = "kin.contextbench-locate.v1";
const CONTEXTBENCH_QUERY_CHAR_LIMIT: usize = 4000;
const CONTEXTBENCH_MAX_FILES: usize = 5;

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

    let current_exe = std::env::current_exe().context("resolve current kin binary")?;
    let mut child = Command::new(current_exe);
    child
        .arg("locate")
        .arg("--json")
        .arg("--explain")
        .arg("--max-files")
        .arg(CONTEXTBENCH_MAX_FILES.to_string())
        .arg(&bounded_query)
        .current_dir(std::env::current_dir()?);
    child.env_remove("KIN_PROFILE_OUT");
    child.env_remove("KIN_PROFILE_SUMMARY");
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
        max_files: CONTEXTBENCH_MAX_FILES,
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
        CONTEXTBENCH_MAX_FILES, CONTEXTBENCH_QUERY_CHAR_LIMIT, normalize_path, select_query,
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
        assert_eq!(CONTEXTBENCH_MAX_FILES, 5);
    }
}
