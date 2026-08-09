// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! How a `.kin/` store this build cannot serve refuses a command.
//!
//! The gap itself has to be the headline. When it was reported as a line quoted
//! out of a daemon log tail underneath "kin daemon is required", every reader
//! was told a daemon was missing and left to find the sentence saying why one
//! could never start.

use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::IsolatedDaemonRuntime;

/// A `.kin/` exactly as a released 0.3.6 wrote one.
///
/// The manifest carries the field set of that release and there is no `version`
/// marker, which `KinLayout::read_version` reports as v1.
fn seed_pre_v2_store(repo: &Path) {
    let kin_dir = repo.join(".kin");
    fs::create_dir_all(&kin_dir).expect("create pre-v2 .kin");
    fs::write(
        kin_dir.join("manifest.json"),
        r#"{"kin_version":"0.3.6","languages":[],"adapters":[],"repo_id":"54c48711-e6f0-4950-b00d-5585b59188fe","created_at":"2026-07-28T03:10:45Z"}"#,
    )
    .expect("write pre-v2 manifest");
}

fn run_git(path: &Path, args: &[&str]) {
    let output = common::Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
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

fn seed_git_repo(path: &Path) {
    fs::create_dir_all(path).expect("create repo dir");
    run_git(path, &["init", "--initial-branch=main"]);
    run_git(path, &["config", "user.email", "kin@example.invalid"]);
    run_git(path, &["config", "user.name", "Kin"]);
    fs::write(path.join("README.md"), "first\n").expect("write a tracked file");
    run_git(path, &["add", "--all"]);
    run_git(path, &["commit", "-m", "first"]);
}

#[test]
fn a_pre_v2_store_refuses_a_command_by_leading_with_the_version_gap() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("pre-v2");
    fs::create_dir_all(&repo).expect("create repository directory");
    seed_pre_v2_store(&repo);

    let runtime = IsolatedDaemonRuntime::new(&repo);
    let output = runtime
        .kin_command()
        .args(["locate", "anything"])
        .current_dir(&repo)
        .output()
        .expect("run a daemon-backed command against a pre-v2 store");

    assert!(
        !output.status.success(),
        "a store this build cannot serve must refuse: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("incompatible .kin/ version: found v1, this binary requires v2"),
        "the refusal must name the version gap: {stderr}"
    );
    assert!(
        !stderr.contains("kin daemon is required"),
        "the missing daemon is a consequence of the gap and must not be the headline: {stderr}"
    );
    assert!(
        !stderr.contains("recent log:"),
        "the cause must be stated, not quoted out of a log tail: {stderr}"
    );
    assert!(
        !stderr.contains("failed cleanup during Drop"),
        "a refusal that spawns nothing has no cleanup to report: {stderr}"
    );
    assert!(
        stderr.contains("remove .kin/ and run `kin init`"),
        "the refusal must name the remedy that works in place: {stderr}"
    );
    assert!(
        !stderr.contains("fresh checkout"),
        "the remedy must not send the reader to a checkout they do not have: {stderr}"
    );
    assert!(
        !repo.join(".kin/daemon.log").exists(),
        "the gap is settled from the on-disk marker, so no daemon is started to discover it"
    );
}

#[test]
fn init_over_an_existing_store_names_the_same_remedy_the_wall_does() {
    // A reader the wall sent to `kin init` runs it in place first. The refusal
    // they get has to continue that instruction rather than contradict it.
    let root = tempdir().expect("temp root");
    let repo = root.path().join("pre-v2-init");
    fs::create_dir_all(&repo).expect("create repository directory");
    seed_pre_v2_store(&repo);

    let runtime = IsolatedDaemonRuntime::new(&repo);
    let output = runtime
        .kin_command()
        .arg("init")
        .arg(&repo)
        .output()
        .expect("run kin init over an existing store");

    assert!(
        !output.status.success(),
        "kin init never rebuilds over an existing store: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Kin repository already exists"),
        "the refusal must state its condition: {stderr}"
    );
    assert!(
        stderr.contains("remove .kin/ and run `kin init`"),
        "the refusal must name the same remedy the store wall does: {stderr}"
    );
}

#[test]
fn the_remedy_the_wall_names_rebuilds_the_store_in_place() {
    // A remedy nothing checks is a guess. This runs the exact instruction the
    // wall gives, in the directory the reader is standing in, and requires it
    // to produce a store the current build wrote.
    let root = tempdir().expect("temp root");
    let repo = root.path().join("worked-in");
    seed_git_repo(&repo);
    seed_pre_v2_store(&repo);

    let runtime = IsolatedDaemonRuntime::new(&repo);
    fs::remove_dir_all(repo.join(".kin")).expect("remove the store the wall said to remove");
    let output = runtime
        .kin_command()
        .arg("init")
        .arg(&repo)
        .output()
        .expect("run the rebuild the wall names");

    assert!(
        output.status.success(),
        "the named remedy must rebuild the store: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(repo.join(".kin/version"))
            .expect("the rebuilt store carries a layout marker")
            .trim(),
        kin_core::layout::KIN_LAYOUT_VERSION.to_string(),
        "the rebuilt store must be one this build serves"
    );
}

#[test]
fn a_refused_init_leaves_no_partial_store_behind() {
    // Whatever the refusal says, it must not leave a half-written `.kin` that
    // the next command then has to interpret.
    let root = tempdir().expect("temp root");
    let repo = root.path().join("non-empty");
    fs::create_dir_all(&repo).expect("create repository directory");
    fs::write(repo.join("notes.txt"), "untracked\n").expect("write an untracked file");

    let runtime = IsolatedDaemonRuntime::new(&repo);
    let output = runtime
        .kin_command()
        .arg("init")
        .arg(&repo)
        .output()
        .expect("run kin init over a non-empty non-Git directory");

    assert!(
        !output.status.success(),
        "a non-empty directory with no Git history is refused: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !repo.join(".kin").exists(),
        "a refused init must leave no store at all"
    );
}
