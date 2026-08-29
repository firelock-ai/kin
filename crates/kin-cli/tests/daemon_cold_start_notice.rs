// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A cold start says it is starting; a warm call says nothing.
//!
//! The first `kin locate` after `kin daemon stop` took 7,949 ms against 137 ms
//! warm on a freshly converted axum store, and printed nothing for any of it.
//! Silence and a hang read the same from outside, so the wait now reports the
//! phase it is in.
//!
//! Both halves are asserted here because either alone is satisfiable by a
//! broken implementation: a notice that never fires passes a warm-silence test,
//! and one that fires on every call passes a cold-notice test.

use serial_test::serial;
use std::fs;
use tempfile::tempdir;

mod common;

use common::Command;

fn kin_command(runtime: &common::IsolatedDaemonRuntime) -> Command<'_> {
    let mut cmd = runtime.kin_command();
    cmd.env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "60")
        .env("KIN_BYPASS_EMBEDDING_COVERAGE_CHECK", "1");
    cmd
}

fn git(repo: &std::path::Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .unwrap_or_else(|error| panic!("git {args:?}: {error}"));
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[serial]
fn a_cold_locate_reports_the_daemon_start_and_a_warm_one_stays_silent() {
    let repo = tempdir().expect("temp repo");
    let runtime = common::IsolatedDaemonRuntime::new(repo.path());
    fs::create_dir_all(repo.path().join("src")).expect("create src dir");
    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn lexer() -> &'static str { \"lexer\" }\n",
    )
    .expect("write source");
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
            "seed",
        ],
    );

    let init = kin_command(&runtime)
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

    let stop = kin_command(&runtime)
        .args(["daemon", "stop"])
        .current_dir(repo.path())
        .output()
        .expect("run kin daemon stop");
    assert!(
        stop.status.success(),
        "kin daemon stop failed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );

    // Cold: the next command pays for a start, and says so.
    let cold = kin_command(&runtime)
        .args(["locate", "lexer", "--json"])
        .current_dir(repo.path())
        .output()
        .expect("run cold kin locate");
    assert!(
        cold.status.success(),
        "cold locate failed: {}",
        String::from_utf8_lossy(&cold.stderr)
    );
    let cold_err = String::from_utf8_lossy(&cold.stderr).to_string();
    assert!(
        cold_err.contains("starting the kin daemon for this repository"),
        "a cold start announces itself: {cold_err}"
    );
    assert!(
        cold_err.contains("kin daemon ready in"),
        "and closes by saying how long it took, so the reader can tell the wait \
         from their own query: {cold_err}"
    );

    // The line is on stderr, so a --json caller's stdout is still one document.
    serde_json::from_slice::<serde_json::Value>(&cold.stdout)
        .expect("cold --json stdout parses as one JSON document");

    // Warm: nothing was started, so nothing is announced.
    let warm = kin_command(&runtime)
        .args(["locate", "lexer", "--json"])
        .current_dir(repo.path())
        .output()
        .expect("run warm kin locate");
    assert!(
        warm.status.success(),
        "warm locate failed: {}",
        String::from_utf8_lossy(&warm.stderr)
    );
    let warm_err = String::from_utf8_lossy(&warm.stderr).to_string();
    assert!(
        !warm_err.contains("starting the kin daemon for this repository"),
        "a warm call started nothing and must say nothing: {warm_err}"
    );
    assert!(
        !warm_err.contains("kin daemon ready in"),
        "including the closing line: {warm_err}"
    );
    serde_json::from_slice::<serde_json::Value>(&warm.stdout)
        .expect("warm --json stdout parses as one JSON document");
}
