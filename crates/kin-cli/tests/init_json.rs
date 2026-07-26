// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::Command;

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
        let mut cmd = Command::new("git");
        cmd.args(*args);
        // Explicit increasing commit timestamps: order-sensitive fixtures must
        // not depend on wall-clock second granularity.
        if args.first() == Some(&"commit") {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COMMIT_EPOCH: AtomicU64 = AtomicU64::new(1_000_000_000);
            let date = format!("{} +0000", COMMIT_EPOCH.fetch_add(100, Ordering::Relaxed));
            cmd.env("GIT_AUTHOR_DATE", &date)
                .env("GIT_COMMITTER_DATE", &date);
        }
        let output = cmd.current_dir(path).output().expect("git command");
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
fn fresh_native_init_bootstraps_agent_docs_and_next_steps() {
    let root = tempdir().expect("temp root");
    let home_dir = root.path().join("home");
    let repo = root.path().join("native");
    fs::create_dir_all(&home_dir).expect("create home");

    let output = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(&repo)
        .args(["--git-history", "off"])
        .env("HOME", &home_dir)
        .output()
        .expect("run fresh native kin init");
    assert!(
        output.status.success(),
        "fresh native kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Fresh Kin-native repository ready."));
    assert!(stdout.contains("kin with --session codex"));
    assert!(stdout.contains("kin exec -- <command>"));
    assert!(stdout.contains("kin git export --output <path>"));

    let agents = fs::read_to_string(repo.join("AGENTS.md")).expect("read generated AGENTS.md");
    assert!(agents.contains("This repository is Kin-native."));
    assert!(agents.contains("Agent Coding Workflow"));
    assert!(agents.contains("semantic_locate"));
    assert!(agents.contains("get_context_pack"));
    assert!(agents.contains("trace_data_flow"));
    assert!(agents.contains("kin commit -m \"message\""));
    assert!(agents.contains("kin git export --output <path>"));
    assert!(repo.join(".kin/assistant-sync.toml").exists());

    let config = fs::read_to_string(repo.join(".kin/config.toml")).expect("read kin config");
    assert!(config.contains("mode = \"native\""));
    assert!(!repo.join(".git").exists());
}

#[test]
fn fresh_native_init_json_stays_machine_readable_and_bootstraps_docs() {
    let root = tempdir().expect("temp root");
    let home_dir = root.path().join("home");
    let repo = root.path().join("native-json");
    fs::create_dir_all(&home_dir).expect("create home");

    let output = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(&repo)
        .args(["--json", "--git-history", "off"])
        .env("HOME", &home_dir)
        .output()
        .expect("run fresh native kin init --json");
    assert!(
        output.status.success(),
        "fresh native kin init --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("fresh native init stdout should be json");
    assert_eq!(payload["schema"], "kin.init-result.v2");
    assert_eq!(
        payload.as_object().expect("init payload object").len(),
        10,
        "clean-slate init payload should expose only canonical graph-build fields"
    );
    assert!(payload["total_files"].as_u64().unwrap_or(0) >= 1);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("Fresh Kin-native repository ready."));
    assert!(!stdout.contains("kin with --session codex"));
    assert!(repo.join("AGENTS.md").exists());
    assert!(repo.join(".kin/assistant-sync.toml").exists());
}

#[test]
fn git_backed_init_does_not_emit_fresh_native_bootstrap() {
    let root = tempdir().expect("temp root");
    let home_dir = root.path().join("home");
    let repo = root.path().join("git-backed");
    fs::create_dir_all(&home_dir).expect("create home");
    fs::create_dir_all(&repo).expect("create repo");

    let init = Command::new("git")
        .arg("init")
        .current_dir(&repo)
        .output()
        .expect("git init");
    assert!(
        init.status.success(),
        "git init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(&repo)
        .args(["--git-history", "off"])
        .env("HOME", &home_dir)
        .output()
        .expect("run git-backed kin init");
    assert!(
        output.status.success(),
        "git-backed kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("Fresh Kin-native repository ready."));
    assert!(!stdout.contains("kin with --session codex"));
    assert!(!repo.join("AGENTS.md").exists());
}
