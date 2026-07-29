// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin tag` publishes an exact `refs/tags/` compare-and-swap.
//!
//! These assertions fail if a tag stops being a repository-v6 ref transaction:
//! if it starts writing Git tag files, if it can overwrite an existing tag, or
//! if a declared release policy is downgraded from a refusal to a warning.

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
    fs::write(repo.join("src/lib.rs"), b"pub fn released() -> i32 { 1 }\n").expect("write source");
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

fn branch_list(runtime: &common::IsolatedDaemonRuntime, repo: &Path) -> Value {
    let output = run_kin(runtime, repo, &["branch", "list", "--json"]);
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("branch list should be JSON")
}

#[test]
fn tag_publishes_an_exact_ref_transaction_and_never_replaces_one() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize_kin_repo(&runtime, &repo);

    let before = branch_list(&runtime, &repo);
    let refs_before = before["repository_ref_count"]
        .as_u64()
        .expect("repository ref count");
    let generation_before = before["authority_generation"]
        .as_u64()
        .expect("authority generation");

    // The source has no source-bound proof, so the baseline coverage refusal
    // fires and nothing is published.
    let unforced = run_kin(&runtime, &repo, &["tag", "v1.0.0"]);
    assert!(
        !unforced.status.success(),
        "a source below the coverage baseline was tagged without an acknowledgment"
    );
    let stderr = String::from_utf8_lossy(&unforced.stderr);
    assert!(
        stderr.contains("below the") && stderr.contains("--force"),
        "the baseline refusal must name the threshold and the acknowledgment: {stderr}"
    );
    let after_refusal = branch_list(&runtime, &repo);
    assert_eq!(
        after_refusal["repository_ref_count"], refs_before,
        "a refused tag published a ref anyway"
    );
    assert_eq!(
        after_refusal["authority_generation"], generation_before,
        "a refused tag advanced repository authority"
    );

    let tagged = run_kin(&runtime, &repo, &["tag", "v1.0.0", "--force"]);
    assert!(
        tagged.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&tagged.stdout),
        String::from_utf8_lossy(&tagged.stderr)
    );
    let stdout = String::from_utf8_lossy(&tagged.stdout);
    assert!(
        stdout.contains("refs/tags/v1.0.0"),
        "tag output did not name the exact ref it published: {stdout}"
    );

    let after = branch_list(&runtime, &repo);
    assert_eq!(
        after["repository_ref_count"].as_u64().expect("ref count"),
        refs_before + 1,
        "the tag was not published as a repository-v6 ref"
    );
    assert!(
        after["authority_generation"].as_u64().expect("generation") > generation_before,
        "publishing a tag did not advance repository authority"
    );
    assert_eq!(
        after["branch_count"], before["branch_count"],
        "a tag was published into the branch namespace"
    );

    // Tags are immutable refs. A second publication of the same name is a
    // conflict, not a silent move.
    let duplicate = run_kin(&runtime, &repo, &["tag", "v1.0.0", "--force"]);
    assert!(
        !duplicate.status.success(),
        "an existing tag was replaced in place"
    );
    let stderr = String::from_utf8_lossy(&duplicate.stderr);
    assert!(
        stderr.contains("already exists"),
        "the duplicate-tag refusal must say the tag exists: {stderr}"
    );
    let unchanged = branch_list(&runtime, &repo);
    assert_eq!(
        unchanged["repository_ref_count"], after["repository_ref_count"],
        "a refused duplicate tag mutated the ref set"
    );
}

#[test]
fn declared_release_policy_is_a_refusal_and_never_a_warning() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize_kin_repo(&runtime, &repo);

    let before = branch_list(&runtime, &repo);

    // Verification runs carry no immutable source binding yet, so proof cannot
    // be satisfied by any non-empty source and must fail closed even when the
    // baseline is explicitly acknowledged.
    let proof = run_kin(
        &runtime,
        &repo,
        &["tag", "v2.0.0", "--require-proof", "--force"],
    );
    assert!(
        !proof.status.success(),
        "--require-proof was satisfied by a source with no source-bound proof"
    );
    let stderr = String::from_utf8_lossy(&proof.stderr);
    assert!(
        stderr.contains("source-bound"),
        "the proof refusal must name the missing source binding: {stderr}"
    );

    let after = branch_list(&runtime, &repo);
    assert_eq!(
        after["repository_ref_count"], before["repository_ref_count"],
        "a policy refusal still published a tag"
    );
    assert_eq!(
        after["authority_generation"], before["authority_generation"],
        "a policy refusal advanced repository authority"
    );
}

#[test]
fn tag_refuses_a_ref_outside_the_tag_namespace() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize_kin_repo(&runtime, &repo);

    let output = run_kin(&runtime, &repo, &["tag", "refs/heads/main", "--force"]);
    assert!(
        !output.status.success(),
        "the tag command published outside refs/tags/"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refs/tags/"),
        "the namespace refusal must name refs/tags/: {stderr}"
    );
}
