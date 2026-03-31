// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn init_git_repo(path: &Path, remote: &str) {
    fs::create_dir_all(path).expect("create repo dir");
    fs::write(path.join("README.md"), "hello\n").expect("write repo file");

    let init = Command::new("git")
        .args(["init"])
        .current_dir(path)
        .output()
        .expect("git init");
    assert!(init.status.success(), "git init failed");

    let commands: &[&[&str]] = &[
        &["config", "user.email", "kin@example.com"],
        &["config", "user.name", "Kin"],
        &["remote", "add", "origin", remote],
        &["add", "README.md"],
        &["commit", "-m", "init"],
    ];
    for args in commands {
        let output = Command::new("git")
            .args(*args)
            .current_dir(path)
            .output()
            .expect("git command");
        assert!(
            output.status.success(),
            "git {:?} failed: stdout={} stderr={}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn init_json_reports_warm_cache_hits_for_same_repo_identity() {
    let root = tempdir().expect("temp root");
    let home_dir = root.path().join("home");
    let cache_dir = root.path().join("warm-cache");
    fs::create_dir_all(&home_dir).expect("create home");
    fs::create_dir_all(&cache_dir).expect("create cache");

    let remote = "https://example.com/acme/demo.git";
    let repo1 = root.path().join("repo1");
    let repo2 = root.path().join("repo2");
    init_git_repo(&repo1, remote);
    init_git_repo(&repo2, remote);

    let first = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["init", "--json", "."])
        .current_dir(&repo1)
        .env("HOME", &home_dir)
        .env("KIN_INIT_CACHE_DIR", &cache_dir)
        .output()
        .expect("run first kin init --json");
    assert!(
        first.status.success(),
        "first kin init --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    let first_payload: Value =
        serde_json::from_slice(&first.stdout).expect("first init stdout should be json");
    assert_eq!(first_payload["schema"], "kin.init-result.v1");
    assert_eq!(first_payload["warm_cache_hit"], false);
    assert!(first_payload["total_files"].as_u64().unwrap_or(0) >= 1);

    let second = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["init", "--json", "."])
        .current_dir(&repo2)
        .env("HOME", &home_dir)
        .env("KIN_INIT_CACHE_DIR", &cache_dir)
        .output()
        .expect("run second kin init --json");
    assert!(
        second.status.success(),
        "second kin init --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    let second_payload: Value =
        serde_json::from_slice(&second.stdout).expect("second init stdout should be json");
    assert_eq!(second_payload["schema"], "kin.init-result.v1");
    assert_eq!(second_payload["warm_cache_hit"], true);
    assert_eq!(second_payload["warm_changed_files"], 0);
    assert_eq!(second_payload["warm_reparsed_files"], 0);
    assert!(second_payload["indexed_embeddings"].is_u64());
    assert!(second_payload["pending_embeddings"].is_u64());
}
