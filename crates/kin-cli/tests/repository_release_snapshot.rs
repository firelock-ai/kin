// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin release snapshot` binds a release to exact repository state.
//!
//! These assertions fail if a snapshot stops naming the roots, source, and
//! immutable artifact tree it was published against, if it stops being sealed,
//! or if it can be produced without the tag transaction that publishes it.

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
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .current_dir(repo)
        .output()
        .expect("run kin")
}

fn initialize(runtime: &common::IsolatedDaemonRuntime, repo: &Path) {
    fs::create_dir_all(repo).expect("create repo");
    require_git(repo, &["init", "--initial-branch=main"]);
    require_git(repo, &["config", "user.email", "kin@example.invalid"]);
    require_git(repo, &["config", "user.name", "Kin"]);
    require_git(repo, &["config", "commit.gpgsign", "false"]);
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    fs::write(repo.join("src/lib.rs"), b"pub fn shipped() -> u8 { 1 }\n").expect("write source");
    fs::write(repo.join("asset.bin"), [0_u8, 0xff, 0x10]).expect("write binary asset");
    require_git(repo, &["add", "--all"]);
    require_git(repo, &["commit", "-m", "release surface"]);

    let init = run_kin(runtime, repo, &["init", ".", "--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
}

#[test]
fn a_release_snapshot_is_bound_to_exact_roots_source_and_artifacts() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);

    let output = run_kin(
        &runtime,
        &repo,
        &["release", "snapshot", "v1.0.0", "--force"],
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let snapshot: Value =
        serde_json::from_slice(&output.stdout).expect("release snapshot should be JSON");

    assert_eq!(snapshot["schema"], "kin.release-snapshot.v1");
    assert_eq!(
        snapshot["tag"]["bytes_hex"], "726566732f746167732f76312e302e30",
        "the snapshot must name the exact byte-level tag ref it published"
    );

    // The roots pair records exactly which authority transition published this
    // release, and the transition must have advanced authority.
    let before = snapshot["roots_before"]["generation"]
        .as_u64()
        .expect("roots before generation");
    let after = snapshot["roots_after"]["generation"]
        .as_u64()
        .expect("roots after generation");
    assert_eq!(
        after,
        before + 1,
        "the snapshot is not bound to the authority transition that published it"
    );
    assert_ne!(
        snapshot["roots_before"], snapshot["roots_after"],
        "a released snapshot must name two distinct repository root bundles"
    );

    // The tree hash and artifact composition bind the immutable artifacts.
    assert!(
        snapshot["tree_hash"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64),
        "the snapshot must carry the content identity of the released tree"
    );
    let artifacts = snapshot["artifact_count"].as_u64().expect("artifact count");
    let blobs = snapshot["blob_artifacts"].as_u64().expect("blob count");
    assert!(
        artifacts >= 2,
        "the released tree must carry its exact artifacts, got {artifacts}"
    );
    assert_eq!(
        blobs
            + snapshot["symlink_artifacts"].as_u64().expect("symlinks")
            + snapshot["gitlink_artifacts"].as_u64().expect("gitlinks"),
        artifacts,
        "artifact composition does not account for every released artifact"
    );

    // The policy decision that admitted the release is part of the binding.
    assert_eq!(
        snapshot["proof"]["baseline_acknowledged"], true,
        "the snapshot must record that the baseline was explicitly acknowledged"
    );
    assert_eq!(snapshot["proof"]["require_proof"], false);
    assert_eq!(snapshot["proof"]["require_approval"], false);

    let digest = snapshot["snapshot_digest"]
        .as_str()
        .expect("snapshot digest");
    assert_eq!(digest.len(), 64, "the snapshot binding must be sealed");
    assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));

    // A second release of a different tag over the same source is a different
    // snapshot: the digest covers the tag and the roots transition too.
    let second = run_kin(
        &runtime,
        &repo,
        &["release", "snapshot", "v1.0.1", "--force"],
    );
    assert!(
        second.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    let second: Value = serde_json::from_slice(&second.stdout).expect("second snapshot is JSON");
    assert_eq!(
        second["tree_hash"], snapshot["tree_hash"],
        "the same source must produce the same released tree identity"
    );
    assert_ne!(
        second["snapshot_digest"], snapshot["snapshot_digest"],
        "two distinct releases produced the same sealed binding"
    );
}

#[test]
fn a_refused_release_publishes_no_snapshot_and_no_tag() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);

    let refused = run_kin(
        &runtime,
        &repo,
        &[
            "release",
            "snapshot",
            "v2.0.0",
            "--require-proof",
            "--force",
        ],
    );
    assert!(
        !refused.status.success(),
        "a release that failed its declared policy still produced a snapshot"
    );
    assert!(
        refused.stdout.is_empty(),
        "a refused release emitted a snapshot document: {}",
        String::from_utf8_lossy(&refused.stdout)
    );

    // The refused tag must not exist, so the same name can still be released.
    let allowed = run_kin(
        &runtime,
        &repo,
        &["release", "snapshot", "v2.0.0", "--force"],
    );
    assert!(
        allowed.status.success(),
        "the refused release left its tag ref behind: stdout={} stderr={}",
        String::from_utf8_lossy(&allowed.stdout),
        String::from_utf8_lossy(&allowed.stderr)
    );
}
