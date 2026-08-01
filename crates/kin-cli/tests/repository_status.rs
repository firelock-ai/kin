// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Every case here drives the retained no-follow projection, which only Unix
// implements, so the whole binary is scoped to that platform.
#![cfg(unix)]

use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::Command;

#[cfg(windows)]
const NULL_GIT_CONFIG: &str = "NUL";
#[cfg(not(windows))]
const NULL_GIT_CONFIG: &str = "/dev/null";

fn run_git(path: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", NULL_GIT_CONFIG)
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
        .env_remove("KIN_DAEMON_URL")
        .env_remove("KIN_VFS_WORKSPACE")
        .current_dir(repo)
        .output()
        .expect("run kin")
}

#[cfg(unix)]
#[test]
fn status_is_one_exact_authority_lease_and_ignores_checkout_and_git_drift() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&repo).expect("create repo");

    run_git(&repo, &["init", "--initial-branch=main"]);
    run_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(&repo, &["config", "user.name", "Kin"]);
    fs::write(
        repo.join("compose.yaml"),
        b"services:\n  api:\n    build: .\n",
    )
    .expect("write Compose file");
    fs::write(repo.join("Dockerfile"), b"FROM scratch\n").expect("write Dockerfile");
    fs::write(repo.join("payload.bin"), [0_u8, 255, 17, 0, 128, 42]).expect("write opaque payload");
    fs::write(repo.join("tool"), b"#!/bin/sh\nexit 0\n").expect("write tool");
    let mut permissions = fs::metadata(repo.join("tool")).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(repo.join("tool"), permissions).expect("mark executable");
    symlink("compose.yaml", repo.join("compose-link")).expect("create symlink");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "exact mixed tree"]);

    let init = run_kin(&repo, &home, &["init", ".", "--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let before = run_kin(&repo, &home, &["status", "--json"]);
    assert!(
        before.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&before.stdout),
        String::from_utf8_lossy(&before.stderr)
    );
    let before_report: Value =
        serde_json::from_slice(&before.stdout).expect("status stdout should be JSON");
    assert_eq!(before_report["schema"], "kin.status.v3");
    assert_eq!(before_report["authority"], "repository-v6");
    assert_eq!(before_report["repository"]["generation"], 1);
    assert_eq!(before_report["repository"]["source_cas_verified"], true);
    assert_eq!(before_report["repository"]["ref_count"], 1);
    assert_eq!(
        before_report["repository"]["default_ref"]["bytes_hex"],
        "726566732f68656164732f6d61696e"
    );
    assert_eq!(before_report["workspace"]["head"]["type"], "symbolic");
    assert_eq!(before_report["workspace"]["dirty"], false);
    assert_eq!(before_report["workspace"]["artifact_count"], 5);
    assert_eq!(
        before_report["semantic_enrichment"]["view"],
        "durable_repository_authority"
    );
    assert_eq!(
        before_report["semantic_enrichment"]["authority_generation"],
        before_report["repository"]["generation"]
    );
    assert_eq!(
        before_report["semantic_enrichment"]["workspace_generation"],
        before_report["workspace"]["generation"]
    );
    assert_eq!(before_report["semantic_enrichment"]["presence"], "absent");
    assert_eq!(
        before_report["semantic_enrichment"]["completion_attested"],
        false
    );
    assert_eq!(
        before_report["semantic_enrichment"]["semantic_change_count"],
        1
    );
    // No daemon holds this repository, so there is no live graph to sample and
    // no vector index behind it. Status has to say that rather than publish the
    // zero an unindexed graph would produce, which is the reading a fully
    // embedded repository would be indistinguishable from.
    assert_eq!(
        before_report["embedding_coverage"]["state"], "unobserved",
        "coverage cannot be observed with no daemon running: {}",
        before_report["embedding_coverage"]
    );
    assert_eq!(
        before_report["embedding_coverage"]["reason"],
        "no_running_daemon"
    );
    assert!(
        before_report["embedding_coverage"].get("indexed").is_none(),
        "an unobserved coverage must carry no count: {}",
        before_report["embedding_coverage"]
    );

    // Make the checkout and Git metadata maximally misleading. Status must
    // remain byte-for-byte authority-derived: no raw file walk, Git query, or
    // repair from these surfaces is permitted.
    fs::rename(repo.join(".git"), repo.join("git-authority-disabled")).expect("hide Git metadata");
    fs::write(repo.join("compose.yaml"), b"services: {}\n").expect("drift Compose file");
    fs::remove_file(repo.join("Dockerfile")).expect("delete Dockerfile");
    fs::remove_file(repo.join("payload.bin")).expect("delete opaque payload");
    fs::remove_file(repo.join("compose-link")).expect("delete symlink");
    let mut permissions = fs::metadata(repo.join("tool")).unwrap().permissions();
    permissions.set_mode(0o644);
    fs::set_permissions(repo.join("tool"), permissions).expect("remove executable bit");
    fs::write(
        repo.join("unrelated.unsupported"),
        b"not repository truth\n",
    )
    .expect("add unrelated file");

    let after = run_kin(&repo, &home, &["status", "--json"]);
    assert!(
        after.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&after.stdout),
        String::from_utf8_lossy(&after.stderr)
    );
    let after_report: Value =
        serde_json::from_slice(&after.stdout).expect("status stdout should remain JSON");
    assert_eq!(
        after_report, before_report,
        "checkout or Git drift influenced repository-v6 status"
    );
}
