// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{anyhow, bail, Context, Result};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

const CONTEXTBENCH_LOCATE_SCHEMA: &str = "kin.contextbench-locate.v1";
const CONTEXTBENCH_QUERY_CHAR_LIMIT: usize = 4000;
const CONTEXTBENCH_DEFAULT_MAX_FILES: usize = 10;
const CONTEXTBENCH_MULTI_FILE_MAX_FILES: usize = 10;

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
    let max_files = contextbench_max_files(&bounded_query);

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
                return Ok((field, augment_query_with_test_patch(trimmed, task)));
            }
        }
    }
    bail!("task payload missing description/problem_statement/prompt text")
}

fn augment_query_with_test_patch(base: &str, task: &Value) -> String {
    let Some(test_patch) = task.get("test_patch").and_then(Value::as_str) else {
        return base.to_string();
    };

    let hints = extract_test_patch_hints(test_patch);
    if hints.is_empty() {
        return base.to_string();
    }

    let mut augmented = String::with_capacity(base.len() + 256);
    augmented.push_str(base);
    augmented.push_str("\n\nRelated test hints:");
    for hint in hints {
        if !base.contains(&hint) {
            augmented.push_str("\n- ");
            augmented.push_str(&hint);
        }
    }
    augmented
}

fn extract_test_patch_hints(test_patch: &str) -> Vec<String> {
    let mut hints = BTreeSet::new();
    let diff_path_re = Regex::new(r"(?m)^diff --git a/(.+?) b/(.+?)$").expect("diff path regex");
    let gtest_re = Regex::new(r"(?m)^[ +].*TEST(?:_F|_P)?\s*\([^,]+,\s*([A-Za-z0-9_]+)\s*\)")
        .expect("gtest name regex");
    let xunit_re =
        Regex::new(r"(?m)^[ +].*\b(?:fn|def)\s+(test_[A-Za-z0-9_]+)\b").expect("xunit regex");

    for captures in diff_path_re.captures_iter(test_patch) {
        let Some(path) = captures.get(2).map(|m| normalize_patch_path(m.as_str())) else {
            continue;
        };
        if !path.is_empty() {
            hints.insert(path);
        }
    }

    for regex in [&gtest_re, &xunit_re] {
        for captures in regex.captures_iter(test_patch) {
            if let Some(name) = captures.get(1).map(|m| m.as_str().trim()) {
                if !name.is_empty() {
                    hints.insert(name.to_string());
                }
            }
        }
    }

    hints.into_iter().take(12).collect()
}

fn normalize_patch_path(path: &str) -> String {
    path.trim()
        .trim_start_matches("a/")
        .trim_start_matches("b/")
        .trim_start_matches("./")
        .to_string()
}

fn contextbench_max_files(query: &str) -> usize {
    parse_contextbench_max_files(std::env::var("KIN_CONTEXTBENCH_MAX_FILES").ok().as_deref())
        .unwrap_or_else(|| suggested_contextbench_max_files(query))
}

fn parse_contextbench_max_files(raw: Option<&str>) -> Option<usize> {
    raw.and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
}

fn suggested_contextbench_max_files(query: &str) -> usize {
    let lower = query.to_ascii_lowercase();
    let command_list =
        Regex::new(r"(?m)^\s*[-*]\s+[a-z][a-z0-9_-]*(?:\s+[a-z][a-z0-9_-]*){1,2}\s*$")
            .expect("command list regex")
            .find_iter(query)
            .count();
    let explicit_paths = Regex::new(r"\b[A-Za-z0-9_./-]+\.[A-Za-z0-9]+\b")
        .expect("explicit path regex")
        .find_iter(query)
        .count();
    let multi_file_cues = [
        "added tests",
        "add a unit test",
        "unit test",
        "test case",
        "test suite",
        "with and without",
        "updated:",
        "update:",
        "track down all the commands",
    ];

    if command_list >= 3
        || explicit_paths >= 3
        || multi_file_cues.iter().any(|cue| lower.contains(cue))
    {
        CONTEXTBENCH_MULTI_FILE_MAX_FILES
    } else {
        CONTEXTBENCH_DEFAULT_MAX_FILES
    }
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
        contextbench_max_files, extract_test_patch_hints, normalize_path,
        parse_contextbench_max_files, select_query, suggested_contextbench_max_files,
        CONTEXTBENCH_DEFAULT_MAX_FILES, CONTEXTBENCH_MULTI_FILE_MAX_FILES,
        CONTEXTBENCH_QUERY_CHAR_LIMIT,
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
    fn select_query_appends_test_patch_hints_when_present() {
        let payload = json!({
            "description": "Fix parser edge case",
            "test_patch": "diff --git a/tests/src/unit-reference_access.cpp b/tests/src/unit-reference_access.cpp\n@@\n+TEST_F(JsonEdgeCase, KeepsReferenceAccess)\n"
        });
        let (field, query) = select_query(&payload).unwrap();
        assert_eq!(field, "description");
        assert!(query.contains("Fix parser edge case"));
        assert!(query.contains("tests/src/unit-reference_access.cpp"));
        assert!(query.contains("KeepsReferenceAccess"));
    }

    #[test]
    fn normalize_path_strips_workspace_prefix() {
        assert_eq!(
            normalize_path("/workspace/demo__repo/src/lib.rs"),
            "src/lib.rs"
        );
        assert_eq!(normalize_path("./src/lib.rs"), "src/lib.rs");
        assert_eq!(CONTEXTBENCH_QUERY_CHAR_LIMIT, 4000);
        assert_eq!(
            contextbench_max_files("simple issue"),
            CONTEXTBENCH_DEFAULT_MAX_FILES
        );
    }

    #[test]
    fn parse_contextbench_max_files_accepts_positive_values() {
        assert_eq!(parse_contextbench_max_files(Some("40")), Some(40));
        assert_eq!(parse_contextbench_max_files(Some("0")), None);
        assert_eq!(parse_contextbench_max_files(Some("nope")), None);
    }

    #[test]
    fn suggested_contextbench_max_files_expands_for_command_lists() {
        let query = "I tried to track down all the commands that prompt and updated:\n- pr create\n- auth login\n- repo fork";
        assert_eq!(
            suggested_contextbench_max_files(query),
            CONTEXTBENCH_MULTI_FILE_MAX_FILES
        );
    }

    #[test]
    fn suggested_contextbench_max_files_stays_tight_for_simple_queries() {
        assert_eq!(
            suggested_contextbench_max_files("[Autocomplete] Warn when value is invalid"),
            CONTEXTBENCH_DEFAULT_MAX_FILES
        );
    }

    #[test]
    fn extract_test_patch_hints_collects_paths_and_test_names() {
        let hints = extract_test_patch_hints(
            "diff --git a/test/libponyc/lexer.cc b/test/libponyc/lexer.cc\n@@\n+TEST_F(LexerTest, TripleStringOnlyWhitespace)\n+def test_triple_string_without_newline():\n",
        );
        assert!(hints.contains(&"test/libponyc/lexer.cc".to_string()));
        assert!(hints.contains(&"TripleStringOnlyWhitespace".to_string()));
        assert!(hints.contains(&"test_triple_string_without_newline".to_string()));
    }
}
