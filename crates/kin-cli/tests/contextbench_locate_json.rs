// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

mod common;

fn git(path: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(path)
        .output()
        .expect("run git command");
    assert!(
        output.status.success(),
        "git {:?} failed: stdout={} stderr={}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn parse_json_output(output: &std::process::Output, context: &str) -> Value {
    assert!(
        output.status.success(),
        "{} failed: stdout={} stderr={}",
        context,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout should be valid json")
}

#[test]
fn contextbench_locate_keeps_query_selection_and_normalization_inside_kin() {
    let repo = tempdir().expect("temp repo");
    fs::create_dir_all(repo.path().join("src")).expect("create src dir");
    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn benchmark_symbol() -> &'static str { \"symbol\" }\n",
    )
    .expect("write source");

    git(repo.path(), &["init"]);
    git(repo.path(), &["config", "user.email", "kin@example.com"]);
    git(repo.path(), &["config", "user.name", "Kin"]);
    git(repo.path(), &["add", "src/lib.rs"]);
    git(repo.path(), &["commit", "-m", "seed"]);

    let init = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["init", "."])
        .current_dir(repo.path())
        .output()
        .expect("run kin init");
    assert!(
        init.status.success(),
        "kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let task_payload = serde_json::json!({
        "description": "",
        "problem_statement": "benchmark_symbol lookup",
        "prompt": "this field should not win"
    });
    let task_file = repo.path().join("task.json");
    fs::write(
        &task_file,
        serde_json::to_string_pretty(&task_payload).expect("serialize task payload"),
    )
    .expect("write task file");

    let locate = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args([
            "contextbench-locate",
            "--json",
            "--task-file",
            task_file.to_str().expect("task path"),
        ])
        .env("KIN_DAEMON_BIN", common::fresh_daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_IDLE_TIMEOUT_SECS", "1")
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "30")
        .env("KIN_BYPASS_EMBEDDING_COVERAGE_CHECK", "1")
        .current_dir(repo.path())
        .output()
        .expect("run kin contextbench-locate");
    let payload = parse_json_output(&locate, "kin contextbench-locate --json");

    assert_eq!(payload["schema"], "kin.contextbench-locate.v1");
    assert_eq!(payload["selected_query_field"], "problem_statement");
    assert_eq!(payload["query_char_limit"], 4000);
    assert_eq!(payload["max_files"], 100);
    assert_eq!(payload["query_truncated"], false);

    let files = payload["files"].as_array().expect("files array");
    assert!(!files.is_empty(), "wrapper should return at least one file");
    let first = &files[0];
    assert_eq!(first["file"], "src/lib.rs");
    assert_eq!(first["path"], "src/lib.rs");
    assert_eq!(first["file_path"], "src/lib.rs");
    assert_eq!(first["normalized_file"], "src/lib.rs");
    assert!(
        first.get("provenance").is_some(),
        "provenance should be preserved"
    );

    let artifact_dir = Path::new("/tmp/workstreamB-contextbench-locate-proof");
    fs::create_dir_all(artifact_dir).expect("create proof artifact dir");
    fs::write(
        artifact_dir.join("task.json"),
        serde_json::to_string_pretty(&task_payload).expect("serialize task artifact"),
    )
    .expect("write task artifact");
    fs::write(
        artifact_dir.join("wrapper.json"),
        serde_json::to_string_pretty(&payload).expect("serialize wrapper output"),
    )
    .expect("write wrapper artifact");
    let summary = serde_json::json!({
        "selected_query_field": payload["selected_query_field"].clone(),
        "query_truncated": payload["query_truncated"].clone(),
        "max_files": payload["max_files"].clone(),
        "normalized_files": payload["files"].clone(),
    });
    fs::write(
        artifact_dir.join("summary.json"),
        serde_json::to_string_pretty(&summary).expect("serialize summary"),
    )
    .expect("write summary artifact");
}
