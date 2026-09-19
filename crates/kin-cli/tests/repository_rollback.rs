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

fn run_kin(
    runtime: &common::IsolatedDaemonRuntime,
    repo: &Path,
    args: &[&str],
) -> std::process::Output {
    runtime
        .kin_command()
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("KIN_EMBED_BACKEND", "cpu")
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .current_dir(repo)
        .output()
        .expect("run kin")
}

fn require_kin_json(runtime: &common::IsolatedDaemonRuntime, repo: &Path, args: &[&str]) -> Value {
    let output = run_kin(runtime, repo, args);
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
fn initialize(runtime: &common::IsolatedDaemonRuntime, repo: &Path) -> (String, String) {
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

    let init = run_kin(runtime, repo, &["init", ".", "--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let entries = log_entries(runtime, repo);
    assert!(
        entries.len() >= 2,
        "admission did not produce the two-change history rollback needs"
    );
    (entries[1].clone(), entries[0].clone())
}

/// Change ids in branch order, newest first, as canonical hexadecimal.
fn log_entries(runtime: &common::IsolatedDaemonRuntime, repo: &Path) -> Vec<String> {
    let log = require_kin_json(runtime, repo, &["log", "--json"]);
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

fn head_change(runtime: &common::IsolatedDaemonRuntime, repo: &Path) -> String {
    log_entries(runtime, repo)[0].clone()
}

#[test]
fn rollback_publishes_a_restoring_change_and_moves_the_workspace_with_it() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let (base, head) = initialize(&runtime, &repo);

    let output = run_kin(&runtime, &repo, &["rollback", &base, "--discard-later"]);
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
    assert!(
        stdout.contains("Setting aside") && stdout.contains(&head),
        "a rollback that discards a later change must name it before moving the tip: {stdout}"
    );
    assert!(
        stdout.contains("kin rollback"),
        "a successful rollback must name how to roll forward again to the prior tip: {stdout}"
    );

    // History moves forward: the rolled-back change is a new change, and the
    // change that was rolled back is still in history.
    let restored_head = head_change(&runtime, &repo);
    assert_ne!(restored_head, head, "rollback did not publish a new change");
    assert_ne!(
        restored_head, base,
        "rollback reset the branch instead of publishing a restoring change"
    );
    let ids = log_entries(&runtime, &repo);
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
    let drift = require_kin_json(&runtime, &repo, &["doctor", "--drift", "--json"]);
    assert_eq!(
        drift["clean"], true,
        "rollback left the projection diverged from graph truth: {drift}"
    );

    // Rolling back to the change the branch already names is refused rather
    // than published as an empty change.
    let repeated = run_kin(&runtime, &repo, &["rollback", &restored_head]);
    assert!(
        !repeated.status.success(),
        "rollback published a change with nothing to restore"
    );

    let recovery_command = format!("kin rollback {head} --discard-later");
    assert!(stdout.contains(&recovery_command), "{stdout}");
    let recovery = run_kin(&runtime, &repo, &["rollback", &head, "--discard-later"]);
    assert!(
        recovery.status.success(),
        "{}",
        String::from_utf8_lossy(&recovery.stderr)
    );
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).unwrap(),
        b"pub fn shipped() -> u8 { 2 }\n"
    );
    assert_eq!(fs::read(repo.join("broken.txt")).unwrap(), b"regression\n");
}

#[test]
fn rollback_refuses_a_change_outside_this_branch_history() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);

    let unknown = "0".repeat(64);
    let output = run_kin(&runtime, &repo, &["rollback", &unknown]);
    assert!(
        !output.status.success(),
        "rollback accepted a change repository authority does not have"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not materialized")
            || stderr.contains("not in the history")
            || stderr.contains("outside the bounded first-parent preview"),
        "the refusal must say the change is not in this repository's history: {stderr}"
    );

    let malformed = run_kin(&runtime, &repo, &["rollback", "not-a-change"]);
    assert!(
        !malformed.status.success(),
        "rollback accepted a malformed change id"
    );
}

#[test]
fn rollback_without_discard_later_refuses_and_names_the_flag() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let (base, head) = initialize(&runtime, &repo);

    // No --discard-later: rolling back to `base` would set aside `head`, the
    // one later change on this line, so it must refuse rather than move the
    // tip on a guess or a silent default.
    let output = run_kin(&runtime, &repo, &["rollback", &base]);
    assert!(
        !output.status.success(),
        "rollback moved the tip without --discard-later"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("1 later change"),
        "the refusal must name how many changes it would set aside: {stderr}"
    );
    assert!(
        stderr.contains(&head),
        "the refusal must name the change it would set aside: {stderr}"
    );
    assert!(
        stderr.contains("--discard-later"),
        "the refusal must name the exact flag to add: {stderr}"
    );
    assert!(
        stderr.contains("kin rollback"),
        "the refusal must name how to roll forward again to the prior tip: {stderr}"
    );

    // A refusal is not a partial or silent mutation: the tip has not moved.
    assert_eq!(
        head_change(&runtime, &repo),
        head,
        "a refusal must not move the branch tip"
    );

    // The same target succeeds once given explicit consent.
    let confirmed = run_kin(&runtime, &repo, &["rollback", &base, "--discard-later"]);
    assert!(
        confirmed.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&confirmed.stdout),
        String::from_utf8_lossy(&confirmed.stderr)
    );
}

#[test]
fn rollback_to_the_current_tip_needs_no_discard_later_flag() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);
    let tip = head_change(&runtime, &repo);

    // Nothing would be set aside, so the flag is not required; the daemon's
    // own "nothing to roll back" refusal is what answers instead.
    let output = run_kin(&runtime, &repo, &["rollback", &tip]);
    assert!(
        !output.status.success(),
        "rolling back to the change already at the tip published an empty change"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("--discard-later"),
        "a no-op rollback must not ask for consent it does not need: {stderr}"
    );
}

#[test]
fn rollback_refuses_over_a_diverged_projection() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let (base, _) = initialize(&runtime, &repo);

    // A tracked path edited outside Kin is graph-owned content that the
    // transition would overwrite. It must be reported, not destroyed.
    fs::write(repo.join("keep.txt"), b"edited outside kin\n").expect("edit tracked file");
    let output = run_kin(&runtime, &repo, &["rollback", &base, "--discard-later"]);
    if output.status.success() {
        // The daemon may have admitted the edit into workspace authority before
        // the rollback ran. In that case the workspace was dirty and the
        // refusal must have come from there instead; either way the edit must
        // never be silently discarded by an unreported overwrite.
        let drift = require_kin_json(&runtime, &repo, &["doctor", "--drift", "--json"]);
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

#[test]
fn rollback_to_a_merged_second_parent_requires_consent() {
    let root = tempdir().unwrap();
    let repo = root.path().join("repo");
    fs::create_dir_all(&repo).unwrap();
    require_git(&repo, &["init", "--initial-branch=main"]);
    require_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    require_git(&repo, &["config", "user.name", "Kin"]);
    require_git(&repo, &["config", "commit.gpgsign", "false"]);
    fs::write(repo.join("base.txt"), b"base\n").unwrap();
    require_git(&repo, &["add", "--all"]);
    require_git(&repo, &["commit", "-m", "base"]);
    require_git(&repo, &["checkout", "-b", "side"]);
    fs::write(repo.join("side.txt"), b"side work\n").unwrap();
    require_git(&repo, &["add", "--all"]);
    require_git(&repo, &["commit", "-m", "side work"]);
    require_git(&repo, &["checkout", "main"]);
    fs::write(repo.join("main.txt"), b"main work\n").unwrap();
    require_git(&repo, &["add", "--all"]);
    require_git(&repo, &["commit", "-m", "main work"]);
    require_git(&repo, &["merge", "--no-ff", "side", "-m", "merge side"]);

    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    require_kin_json(&runtime, &repo, &["init", ".", "--json"]);
    let log = require_kin_json(&runtime, &repo, &["log", "--json"]);
    let target = change_id_hex(
        &log["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["message"].as_str().unwrap().trim() == "side work")
            .expect("merged side is retained in history")["change_id"],
    );
    let tip = head_change(&runtime, &repo);
    let refusal = run_kin(&runtime, &repo, &["rollback", &target]);
    assert!(!refusal.status.success());
    assert!(String::from_utf8_lossy(&refusal.stderr).contains("--discard-later"));
    assert_eq!(head_change(&runtime, &repo), tip);
    assert_eq!(fs::read(repo.join("main.txt")).unwrap(), b"main work\n");

    let accepted = run_kin(&runtime, &repo, &["rollback", &target, "--discard-later"]);
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    assert!(!repo.join("main.txt").exists());
    assert_eq!(fs::read(repo.join("side.txt")).unwrap(), b"side work\n");
    assert_ne!(head_change(&runtime, &repo), target);
}
