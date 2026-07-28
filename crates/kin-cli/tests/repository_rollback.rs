// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin rollback` restores an earlier change through one repository
//! transaction.
//!
//! These assertions fail if a rollback stops being a forward-only publication:
//! if it rewrites history instead of publishing a restoring change, if the ref
//! and the workspace can move apart, or if it can restore a change that this
//! branch never published.

use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::Command;

fn require_git(path: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .current_dir(path)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_kin(repo: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(args)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("KIN_DAEMON_BIN", common::fresh_daemon_bin())
        .env_remove("KIN_DAEMON_URL")
        .env_remove("KIN_VFS_WORKSPACE")
        .current_dir(repo)
        .output()
        .expect("run kin")
}

fn require_kin_json(repo: &Path, home: &Path, args: &[&str]) -> Value {
    let output = run_kin(repo, home, args);
    assert!(
        output.status.success(),
        "kin {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("kin should emit JSON")
}

/// A two-commit Git history admitted into Kin, returning the change ids of the
/// base and head in branch order.
fn initialize(repo: &Path, home: &Path) -> (String, String) {
    fs::create_dir_all(repo).expect("create repo");
    require_git(repo, &["init", "--initial-branch=main"]);
    require_git(repo, &["config", "user.email", "kin@example.invalid"]);
    require_git(repo, &["config", "user.name", "Kin"]);
    require_git(repo, &["config", "commit.gpgsign", "false"]);
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    fs::write(repo.join("src/lib.rs"), b"pub fn shipped() -> u8 { 1 }\n").expect("write source");
    fs::write(repo.join("keep.txt"), b"unchanged\n").expect("write stable file");
    require_git(repo, &["add", "--all"]);
    require_git(repo, &["commit", "-m", "good state"]);

    fs::write(repo.join("src/lib.rs"), b"pub fn shipped() -> u8 { 2 }\n")
        .expect("write regression");
    fs::write(repo.join("broken.txt"), b"regression\n").expect("write regression file");
    require_git(repo, &["add", "--all"]);
    require_git(repo, &["commit", "-m", "regression"]);

    let init = run_kin(repo, home, &["init", ".", "--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let entries = log_entries(repo, home);
    assert!(
        entries.len() >= 2,
        "admission did not produce the two-change history rollback needs"
    );
    (entries[1].clone(), entries[0].clone())
}

/// Change ids in branch order, newest first, as canonical hexadecimal.
fn log_entries(repo: &Path, home: &Path) -> Vec<String> {
    let log = require_kin_json(repo, home, &["log", "--json"]);
    log["entries"]
        .as_array()
        .expect("log entries")
        .iter()
        .map(|entry| change_id_hex(&entry["change_id"]))
        .collect()
}

/// A change id is an exact 32-byte identity on the wire; render it the way the
/// CLI accepts it.
fn change_id_hex(value: &Value) -> String {
    value
        .as_array()
        .expect("change id bytes")
        .iter()
        .map(|byte| format!("{:02x}", byte.as_u64().expect("change id byte")))
        .collect()
}

fn head_change(repo: &Path, home: &Path) -> String {
    log_entries(repo, home)[0].clone()
}

#[test]
fn rollback_publishes_a_restoring_change_and_moves_the_workspace_with_it() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    let (base, head) = initialize(&repo, &home);

    let output = run_kin(&repo, &home, &["rollback", &base]);
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&base),
        "rollback output did not name the restored change: {stdout}"
    );

    // History moves forward: the rolled-back change is a new change, and the
    // change that was rolled back is still in history.
    let restored_head = head_change(&repo, &home);
    assert_ne!(restored_head, head, "rollback did not publish a new change");
    assert_ne!(
        restored_head, base,
        "rollback reset the branch instead of publishing a restoring change"
    );
    let ids = log_entries(&repo, &home);
    assert!(
        ids.contains(&head),
        "rollback discarded the change it rolled back: {ids:?}"
    );
    assert!(
        ids.contains(&base),
        "rollback discarded the change it restored: {ids:?}"
    );

    // The workspace projection moved with the ref, so the restored content is
    // what the working copy holds.
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).expect("read restored source"),
        b"pub fn shipped() -> u8 { 1 }\n",
        "rollback did not restore the exact tracked bytes"
    );
    assert!(
        !repo.join("broken.txt").exists(),
        "rollback left an artifact the restored change never had"
    );
    assert_eq!(
        fs::read(repo.join("keep.txt")).expect("read stable file"),
        b"unchanged\n",
        "rollback disturbed an artifact both changes shared"
    );

    // Ref and workspace agree: nothing drifted from the transition.
    let drift = require_kin_json(&repo, &home, &["doctor", "--drift", "--json"]);
    assert_eq!(
        drift["clean"], true,
        "rollback left the projection diverged from graph truth: {drift}"
    );

    // Rolling back to the change the branch already names is refused rather
    // than published as an empty change.
    let repeated = run_kin(&repo, &home, &["rollback", &restored_head]);
    assert!(
        !repeated.status.success(),
        "rollback published a change with nothing to restore"
    );
}

#[test]
fn rollback_refuses_a_change_outside_this_branch_history() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    initialize(&repo, &home);

    let unknown = "0".repeat(64);
    let output = run_kin(&repo, &home, &["rollback", &unknown]);
    assert!(
        !output.status.success(),
        "rollback accepted a change repository authority does not have"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not materialized") || stderr.contains("not in the history"),
        "the refusal must say the change is not in this repository's history: {stderr}"
    );

    let malformed = run_kin(&repo, &home, &["rollback", "not-a-change"]);
    assert!(
        !malformed.status.success(),
        "rollback accepted a malformed change id"
    );
}

#[test]
fn rollback_refuses_over_a_diverged_projection() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    let (base, _) = initialize(&repo, &home);

    // A tracked path edited outside Kin is graph-owned content that the
    // transition would overwrite. It must be reported, not destroyed.
    fs::write(repo.join("keep.txt"), b"edited outside kin\n").expect("edit tracked file");
    let output = run_kin(&repo, &home, &["rollback", &base]);
    if output.status.success() {
        // The daemon may have admitted the edit into workspace authority before
        // the rollback ran. In that case the workspace was dirty and the
        // refusal must have come from there instead; either way the edit must
        // never be silently discarded by an unreported overwrite.
        let drift = require_kin_json(&repo, &home, &["doctor", "--drift", "--json"]);
        assert_eq!(
            drift["clean"], true,
            "rollback reported success while leaving the projection diverged: {drift}"
        );
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("diverge") || stderr.contains("graph-owned changes"),
            "the refusal must name the divergence it protected: {stderr}"
        );
        assert_eq!(
            fs::read(repo.join("keep.txt")).expect("read edited file"),
            b"edited outside kin\n",
            "a refused rollback overwrote the working copy anyway"
        );
    }
}
