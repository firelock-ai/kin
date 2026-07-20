// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn bench_meta_json_reports_cache_key_dimensions() {
    let repo = tempdir().expect("temp repo");
    let output = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("bench-meta")
        .arg("--json")
        .current_dir(repo.path())
        .output()
        .expect("run kin bench-meta");
    assert!(
        output.status.success(),
        "kin bench-meta failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("bench-meta stdout should be valid json");
    assert_eq!(payload["schema"], "kin.bench-meta.v1");
    assert!(payload["init_pipeline_epoch"].is_string());
    assert!(payload["parser_schema_epoch"].is_string());
    assert!(payload["layout_schema_version"].is_u64());
    assert!(payload["graph_snapshot_version"].is_u64());
    assert!(payload["text_index_format_version"].is_u64());
    assert!(payload["kin_commit"].is_string());
    assert!(payload["kin_dirty"].is_boolean());

    let coordination = payload["coordination"]
        .as_object()
        .expect("coordination attestation object");
    assert_eq!(coordination["schema"], "kin.coordination-enforcement.v1");
    assert!(matches!(
        coordination["effective_mode"].as_str(),
        Some("off" | "warn" | "enforce")
    ));
    assert_eq!(coordination["default_mode"], "warn");
    assert_eq!(
        coordination["hard_rejection_active"],
        coordination["effective_mode"] == "enforce"
    );
    assert_eq!(coordination["intent_registration_linearized"], true);
    assert_eq!(coordination["max_concurrent_intents_enforced"], true);
    assert_eq!(coordination["contract_scope_claim_eligible"], false);
    assert_eq!(coordination["all_write_surfaces_claim_eligible"], false);
    assert_eq!(coordination["surfaces"]["mcp_transaction_entity"], true);
    assert_eq!(coordination["surfaces"]["contract"], false);
    assert_eq!(
        coordination["durable_event_schema"],
        "kin.coordination-event.v1"
    );
    assert_eq!(coordination["durable_event_fsync_before_broadcast"], true);

    let embeddings = payload["embeddings"]
        .as_object()
        .expect("embeddings object");
    assert!(embeddings.contains_key("vector_enabled"));
    assert!(embeddings.contains_key("embeddings_enabled"));
    assert!(embeddings.contains_key("metal_enabled"));
    assert!(payload["feature_flags"].is_array());
}

#[test]
fn bench_meta_prepared_state_json_reports_repo_specific_cache_keys() {
    let repo = tempdir().expect("temp repo");
    std::fs::write(repo.path().join("README.md"), "hello\n").expect("write README");

    let init = Command::new("git")
        .args(["init"])
        .current_dir(repo.path())
        .output()
        .expect("git init");
    assert!(init.status.success(), "git init failed");
    let email = Command::new("git")
        .args(["config", "user.email", "kin@example.com"])
        .current_dir(repo.path())
        .output()
        .expect("git config email");
    assert!(email.status.success(), "git config email failed");
    let name = Command::new("git")
        .args(["config", "user.name", "Kin"])
        .current_dir(repo.path())
        .output()
        .expect("git config name");
    assert!(name.status.success(), "git config name failed");
    let add = Command::new("git")
        .args(["add", "README.md"])
        .current_dir(repo.path())
        .output()
        .expect("git add");
    assert!(add.status.success(), "git add failed");
    let commit = Command::new("git")
        .args(["commit", "-m", "init"])
        .current_dir(repo.path())
        .output()
        .expect("git commit");
    assert!(
        commit.status.success(),
        "git commit failed: stdout={} stderr={}",
        String::from_utf8_lossy(&commit.stdout),
        String::from_utf8_lossy(&commit.stderr)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("bench-meta")
        .arg("--json")
        .arg("--prepared-state")
        .current_dir(repo.path())
        .output()
        .expect("run kin bench-meta --prepared-state");
    assert!(
        output.status.success(),
        "kin bench-meta --prepared-state failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: Value = serde_json::from_slice(&output.stdout)
        .expect("bench-meta prepared-state stdout should be valid json");
    let prepared = payload["prepared_manifest"]
        .as_object()
        .expect("prepared_manifest object");
    assert_eq!(prepared["schema"], "kin.prepared-state.v1");
    assert!(prepared["cache_key"].is_string());
    assert!(prepared["repo_base_key"].is_string());
    assert!(prepared["repo_identity"]
        .as_str()
        .unwrap()
        .starts_with("path:"));
    assert!(prepared["git_head"].is_string());
    assert!(prepared["git_tree"].is_string());
}
