// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin doctor --drift` reports the derived projection against graph truth.
//!
//! Every assertion here fails if drift stops being answered from repository-v6
//! authority: if untracked host files start reaching the answer, if Git files
//! influence it, or if the report stops naming the exact authority generation
//! it was bound to.

use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::Command;

fn run_git(path: &Path, args: &[&str]) {
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

fn initialize_git_repo(repo: &Path) {
    fs::create_dir_all(repo).expect("create repo");
    run_git(repo, &["init", "--initial-branch=main"]);
    run_git(repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(repo, &["config", "user.name", "Kin"]);
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    fs::write(repo.join("src/lib.rs"), b"pub fn tracked() -> i32 { 1 }\n")
        .expect("write tracked source");
    fs::write(repo.join("README.md"), b"tracked bytes\n").expect("write tracked doc");
    run_git(repo, &["add", "--all"]);
    run_git(repo, &["commit", "-m", "base"]);
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
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .current_dir(repo)
        .output()
        .expect("run kin")
}

fn initialize_kin_repo(runtime: &common::IsolatedDaemonRuntime, repo: &Path) {
    let init = run_kin(runtime, repo, &["init", ".", "--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
}

fn drift_report(runtime: &common::IsolatedDaemonRuntime, repo: &Path) -> Value {
    let output = run_kin(runtime, repo, &["doctor", "--drift", "--json"]);
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("drift report should be JSON")
}

/// Stop this repository's daemon so a working-copy edit made next is not
/// observed by a live watcher.
fn stop_daemon(runtime: &common::IsolatedDaemonRuntime, repo: &Path) {
    let output = run_kin(runtime, repo, &["daemon", "stop"]);
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn drift_paths(report: &Value) -> Vec<String> {
    report["drift"]
        .as_array()
        .expect("drift array")
        .iter()
        .map(|detail| {
            detail
                .as_str()
                .expect("drift detail is a string")
                .to_string()
        })
        .collect()
}

#[test]
fn drift_reads_graph_truth_and_never_answers_from_untracked_host_files() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize_kin_repo(&runtime, &repo);

    let clean = drift_report(&runtime, &repo);
    assert_eq!(clean["schema"], "kin.projection-drift.v1");
    assert_eq!(clean["authority"], "repository-v6");
    assert_eq!(clean["clean"], true);
    assert_eq!(clean["drift_count"], 0);
    let generation = clean["authority_generation"]
        .as_u64()
        .expect("authority generation");
    let compared = clean["compared_entries"]
        .as_u64()
        .expect("compared entry count");
    assert!(
        compared >= 2,
        "drift must compare the tracked members it claims coverage over, got {compared}"
    );
    assert!(
        clean["tracked_artifacts"].as_u64().expect("tracked count") >= compared,
        "compared entries cannot exceed tracked artifacts"
    );

    // Untracked host content is not graph-owned, so it cannot drift. A drift
    // report that grows here is answering from a raw filesystem walk.
    fs::write(repo.join("untracked.rs"), b"pub fn ghost() {}\n").expect("write untracked source");
    fs::create_dir_all(repo.join("scratch")).expect("create untracked directory");
    fs::write(repo.join("scratch/notes.txt"), b"scratch\n").expect("write untracked note");
    let with_untracked = drift_report(&runtime, &repo);
    assert_eq!(
        with_untracked["clean"], true,
        "untracked host files must never be reported as drift"
    );
    assert_eq!(with_untracked["drift_count"], 0);
    assert_eq!(
        with_untracked["compared_entries"], clean["compared_entries"],
        "drift compared a member the exact workspace tree does not track"
    );
    assert_eq!(
        with_untracked["authority_generation"], generation,
        "reporting drift must not move repository authority"
    );

    // Git object and ref state has zero authority over a Kin drift answer.
    fs::rename(repo.join(".git"), repo.join("git-authority-disabled"))
        .expect("hide admitted Git metadata");
    fs::create_dir_all(repo.join(".git/refs/heads")).expect("create misleading Git refs");
    fs::write(repo.join(".git/refs/heads/fake"), b"not an oid\n").expect("write fake Git ref");
    let without_git = drift_report(&runtime, &repo);
    assert_eq!(
        without_git["clean"], true,
        "Git files influenced the repository-v6 drift answer"
    );
    assert_eq!(without_git["authority_generation"], generation);
}

#[test]
fn drift_reports_diverged_tracked_bytes_without_admitting_them() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize_kin_repo(&runtime, &repo);

    let clean = drift_report(&runtime, &repo);
    assert_eq!(clean["clean"], true);
    let generation = clean["authority_generation"]
        .as_u64()
        .expect("authority generation");
    let workspace_generation = clean["workspace_generation"]
        .as_u64()
        .expect("workspace generation");

    // Edit the tracked path with no daemon live to observe it. A running
    // watcher is entitled to admit a working-copy edit into workspace
    // authority, which would make the divergence real but transient; this test
    // is about what drift reports while the divergence still exists, so the
    // window is made deterministic rather than raced.
    stop_daemon(&runtime, &repo);
    fs::write(repo.join("README.md"), b"host edited these bytes\n").expect("edit tracked doc");
    let dirty = drift_report(&runtime, &repo);
    assert_eq!(dirty["clean"], false);
    assert_eq!(dirty["drift_count"], 1);
    let details = drift_paths(&dirty);
    assert!(
        details.iter().any(|detail| detail.contains("README.md")),
        "drift did not name the diverged tracked path: {details:?}"
    );
    assert!(
        !details.iter().any(|detail| detail.contains("src/lib.rs")),
        "drift reported a tracked path that still matches graph truth: {details:?}"
    );

    // Reporting is read-only: observing drift may not publish repository
    // authority, and it may not rematerialize graph content over the working
    // copy. Healing is a separate, explicitly gated transaction.
    assert_eq!(
        dirty["authority_generation"], generation,
        "drift reporting advanced repository authority"
    );
    assert_eq!(
        dirty["workspace_generation"], workspace_generation,
        "drift reporting advanced the workspace generation"
    );
    assert_eq!(
        fs::read(repo.join("README.md")).expect("read tracked doc"),
        b"host edited these bytes\n",
        "reporting drift rewrote the working copy from graph truth"
    );

    // A removed tracked member is drift the report also must not repair.
    stop_daemon(&runtime, &repo);
    fs::remove_file(repo.join("src/lib.rs")).expect("remove tracked source");
    let deleted = drift_report(&runtime, &repo);
    assert!(
        deleted["drift_count"].as_u64().expect("drift count") >= 1,
        "drift did not report a removed tracked member"
    );
    assert!(
        !repo.join("src/lib.rs").exists(),
        "reporting drift restored a removed tracked member"
    );
}

#[test]
fn drift_refuses_outside_a_kin_repository_instead_of_scanning_files() {
    let root = tempdir().expect("temp root");
    let plain = root.path().join("plain");
    let runtime_anchor = root.path().join("runtime-anchor");
    fs::create_dir_all(&runtime_anchor).expect("create runtime anchor");
    fs::create_dir_all(&plain).expect("create plain directory");
    fs::write(plain.join("main.rs"), b"fn main() {}\n").expect("write host source");
    let runtime = common::IsolatedDaemonRuntime::new(&runtime_anchor);

    let output = run_kin(&runtime, &plain, &["doctor", "--drift", "--json"]);
    assert!(
        !output.status.success(),
        "drift answered without repository-v6 authority: stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not a Kin repository"),
        "drift must refuse when graph authority is absent, got: {stderr}"
    );
}

#[test]
fn heal_stays_fail_closed_and_names_its_open_gate() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize_kin_repo(&runtime, &repo);

    let output = run_kin(&runtime, &repo, &["doctor", "--heal"]);
    assert!(
        !output.status.success(),
        "healing a projection is not implemented and must not report success"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("fail-closed") && stderr.contains("kin checkout"),
        "the heal refusal must name its open gate and the explicit transaction that does heal, \
         got: {stderr}"
    );
}
