// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The public install proof's capability flow, run against the real daemon: a
//! Git repository holding one parsed source file is admitted with `kin init`,
//! then `kin locate --json` must report every graph-owned source path as
//! carrying a graph body. Nothing between the two commands may be required.

use serial_test::serial;
use std::fs;
use tempfile::tempdir;

mod common;

use common::Command;

fn git(repo: &std::path::Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn kin_command(runtime: &common::IsolatedDaemonRuntime) -> Command<'_> {
    let mut cmd = runtime.kin_command();
    cmd.env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "30")
        .env("KIN_DAEMON_AUTO_EMBED", "0");
    cmd
}

#[test]
#[serial]
fn a_fresh_init_leaves_no_graph_body_gap_for_locate() {
    let repo = tempdir().expect("temp repo");
    let runtime = common::IsolatedDaemonRuntime::new(repo.path());
    fs::write(
        repo.path().join("probe.py"),
        "def hello():\n    return 42\n",
    )
    .expect("write probe");
    git(repo.path(), &["init", "-q"]);
    git(repo.path(), &["add", "-A"]);
    git(
        repo.path(),
        &[
            "-c",
            "user.name=kin-ci",
            "-c",
            "user.email=ci@kin.dev",
            "commit",
            "-q",
            "-m",
            "probe",
        ],
    );

    let init = kin_command(&runtime)
        .arg("init")
        .current_dir(repo.path())
        .output()
        .expect("run kin init");
    assert!(
        init.status.success(),
        "kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let locate = kin_command(&runtime)
        .args(["locate", "hello", "--json", "--explain", "--max-files", "5"])
        .current_dir(repo.path())
        .output()
        .expect("run kin locate");
    assert!(
        locate.status.success(),
        "kin locate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&locate.stdout),
        String::from_utf8_lossy(&locate.stderr)
    );
    let payload: serde_json::Value =
        serde_json::from_slice(&locate.stdout).expect("locate --json is one JSON document");

    assert!(
        payload["files"]
            .as_array()
            .is_some_and(|files| files.iter().any(|file| file["path"] == "probe.py")),
        "locate must return the admitted probe: {payload}"
    );

    let coverage = &payload["semantic_coverage"];
    let bodies = &coverage["graph_bodies"];
    assert_eq!(
        bodies,
        &serde_json::json!({"source_paths": 1, "with_body": 1, "gap_paths": 0}),
        "every graph-owned source path must carry a graph body straight after init: {coverage}"
    );
    let note = coverage["note"].as_str().unwrap_or_default();
    assert!(
        !note.contains("graph body gap"),
        "no body gap may be reported after a fresh init: {note}"
    );
    assert!(
        payload["degradations"]
            .as_array()
            .into_iter()
            .flatten()
            .all(|degradation| degradation["component"] != "graph_source_bodies"),
        "no graph_source_bodies degradation may ride a fresh init: {}",
        payload["degradations"]
    );

    let embedded = coverage["indexed"] == coverage["total"] && coverage["pending"] == 0;
    assert_eq!(
        coverage["complete"].as_bool(),
        Some(embedded),
        "complete must be decided by the embedding counters alone once bodies are whole: {coverage}"
    );
}
