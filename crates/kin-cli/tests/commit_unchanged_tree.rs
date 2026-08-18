// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What `kin commit` does when the tree it would publish is already committed,
//! through the real binaries.
//!
//! A stranger running Kin in a container committed a docstring edit on a
//! converted psf/requests store, read `operation timed out` from a client
//! deadline the daemon outlived, concluded the edit was uncommitted, and ran the
//! commit again. The first attempt had landed. The second was accepted and
//! recorded as a change with no entities, no relations and no files, stacked on
//! top of the real one, and `kin log` in the container carried that pair on both
//! repositories it was run against.
//!
//! A unit test on the planner cannot cover the retry, because the retry is a
//! whole second invocation. These drive `kin` itself and read `kin log`, which
//! is the surface the empty changes were found in.

use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::Command;

fn run_git(repo: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .current_dir(repo)
        .output()
        .expect("run git")
}

fn require_git(repo: &Path, args: &[&str]) {
    let output = run_git(repo, args);
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_kin(
    runtime: &common::IsolatedDaemonRuntime,
    repo: &Path,
    args: &[&str],
) -> std::process::Output {
    runtime
        .kin_command()
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .current_dir(repo)
        .output()
        .expect("run kin")
}

fn require_kin(
    runtime: &common::IsolatedDaemonRuntime,
    repo: &Path,
    args: &[&str],
) -> std::process::Output {
    let output = run_kin(runtime, repo, args);
    assert!(
        output.status.success(),
        "kin {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn initialize(runtime: &common::IsolatedDaemonRuntime, repo: &Path) {
    fs::create_dir_all(repo).expect("create repo");
    require_git(repo, &["init", "--initial-branch=main"]);
    require_git(repo, &["config", "commit.gpgsign", "false"]);
    require_git(repo, &["config", "user.name", "Ada Lovelace"]);
    require_git(repo, &["config", "user.email", "ada@example.com"]);
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    fs::write(repo.join("src/lib.rs"), b"pub fn shipped() -> u8 { 1 }\n").expect("write source");
    require_git(repo, &["add", "--all"]);
    require_git(repo, &["commit", "-m", "first commit"]);

    let init = run_kin(runtime, repo, &["init", ".", "--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
}

fn log_entries(runtime: &common::IsolatedDaemonRuntime, repo: &Path) -> Vec<Value> {
    let output = require_kin(runtime, repo, &["log", "--json", "--count", "20"]);
    let report: Value = serde_json::from_slice(&output.stdout).expect("kin log should emit JSON");
    assert_eq!(report["schema"], "kin.log.v1");
    report["entries"]
        .as_array()
        .expect("log reports its entries")
        .clone()
}

/// The change id a log entry names.
///
/// A change id serializes as its 32 raw bytes rather than as the hex a person
/// reads, so entries are compared as values here and the human form is taken
/// from what `kin commit` printed.
fn change_id(entry: &Value) -> Value {
    let id = entry["change_id"].clone();
    assert!(!id.is_null(), "every log entry names its change: {entry}");
    id
}

/// The change id `kin commit` printed, in the form a person reads.
fn printed_change_id(stdout: &[u8]) -> String {
    let printed = String::from_utf8_lossy(stdout);
    let line = printed
        .lines()
        .find(|line| line.starts_with("Created semantic change "))
        .unwrap_or_else(|| panic!("a successful commit names its change: {printed}"));
    line.split_whitespace()
        .nth(3)
        .expect("the summary names the change id")
        .to_string()
}

/// The retry that minted the empty change, run for real.
///
/// The refusal has to name the change that already holds the tree, because the
/// person reading it has just been told their commit failed and needs to be able
/// to check that claim in `kin log` without guessing which change to look at.
///
/// Falsify by removing the `refuse_a_successor_that_records_nothing` call from
/// `command_commit_after_admission` in kin-daemon: the second commit then
/// succeeds and the log grows by a change carrying nothing.
#[test]
fn a_second_commit_on_an_unchanged_tree_is_refused_and_adds_no_change() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);

    fs::write(repo.join("src/added.rs"), b"pub fn added() -> u8 { 3 }\n").expect("add source");
    let published = require_kin(&runtime, &repo, &["commit", "-m", "publish added source"]);
    let landed = printed_change_id(&published.stdout);

    let committed = log_entries(&runtime, &repo);
    let newest = change_id(committed.first().expect("the native commit"));

    let refused = run_kin(
        &runtime,
        &repo,
        &["commit", "-m", "publish added source again"],
    );
    assert!(
        !refused.status.success(),
        "a commit on a tree Kin already holds must be refused: stdout={} stderr={}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    let message = String::from_utf8_lossy(&refused.stderr);
    assert!(
        message.contains("nothing to commit"),
        "the refusal must say what it refused: {message}"
    );
    assert!(
        message.contains(&format!("already committed as {landed}")),
        "the refusal must name the change that already holds this tree: {message}"
    );

    let after = log_entries(&runtime, &repo);
    assert_eq!(
        after.len(),
        committed.len(),
        "a refused commit must record nothing: {after:?}"
    );
    assert_eq!(
        change_id(after.first().expect("the native commit")),
        newest,
        "the branch must still point at the change that did the work"
    );
    assert!(
        !after.iter().any(|entry| {
            entry["entity_delta_count"] == 0
                && entry["relation_delta_count"] == 0
                && entry["tree_delta_count"] == 0
                && entry["admission_policy_changed"] == false
        }),
        "no change may record nothing at all: {after:?}"
    );
}
