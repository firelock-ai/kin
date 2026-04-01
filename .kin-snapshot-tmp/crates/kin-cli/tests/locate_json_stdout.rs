// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serial_test::serial;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
#[serial]
fn locate_json_keeps_tracing_warnings_off_stdout() {
    let repo = tempdir().expect("temp repo");
    fs::create_dir_all(repo.path().join("src")).expect("create src dir");
    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn lexer() -> &'static str { \"lexer\" }\n",
    )
    .expect("write source");

    let git_init = Command::new("git")
        .arg("init")
        .arg("-q")
        .current_dir(repo.path())
        .output()
        .expect("git init");
    assert!(
        git_init.status.success(),
        "git init failed: {}",
        String::from_utf8_lossy(&git_init.stderr)
    );

    let init = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("--offline")
        .arg("init")
        .arg(".")
        .current_dir(repo.path())
        .output()
        .expect("run kin init");
    assert!(
        init.status.success(),
        "kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let kindb_dir = repo.path().join(".kin/kindb");
    fs::write(kindb_dir.join("graph.kvec"), []).expect("write stale vector index");
    fs::write(
        kindb_dir.join("graph.kvec.meta.json"),
        serde_json::json!({
            "version": 1,
            "graph_root_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "dimensions": 1,
            "indexed": 1
        })
        .to_string(),
    )
    .expect("write stale vector metadata");

    let locate = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("--offline")
        .arg("locate")
        .arg("--json")
        .arg("lexer issue")
        .current_dir(repo.path())
        .output()
        .expect("run kin locate");
    assert!(
        locate.status.success(),
        "kin locate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&locate.stdout),
        String::from_utf8_lossy(&locate.stderr)
    );

    let stdout = String::from_utf8_lossy(&locate.stdout);
    let stderr = String::from_utf8_lossy(&locate.stderr);

    assert!(
        !stdout.contains("skipping stale vector index"),
        "warning leaked to stdout: {stdout}"
    );
    assert!(
        stderr.contains("skipping stale vector index"),
        "warning missing from stderr: {stderr}"
    );
    serde_json::from_slice::<serde_json::Value>(&locate.stdout)
        .expect("locate --json stdout should remain parseable");
}
