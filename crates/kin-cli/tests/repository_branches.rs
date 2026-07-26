// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::{
    AuthorId, OperationId, RefExpectation, RefMutation, RefName, RefUpdatePolicy, RepositoryId,
    RepositoryTransaction, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::sync::Arc;
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

fn add_exact_refs(layout: &kin_core::KinLayout) {
    let manifest = kin_core::KinManifest::load(&layout.manifest_path()).expect("load Kin manifest");
    let repository_id = RepositoryId::new(manifest.repo_id).expect("valid repository id");
    let manager = RepositoryAuthorityManager::open(
        repository_id.clone(),
        Arc::new(LocalFileBackend::new(layout.kindb_dir())),
    )
    .expect("open repository authority");
    let lease = manager.read_authority();
    let roots = lease.roots().clone();
    let main = RefName::branch(b"main").unwrap();
    let target = lease
        .metadata()
        .ref_state
        .refs
        .iter()
        .find(|repository_ref| repository_ref.name == main)
        .expect("main ref")
        .target
        .clone();
    drop(lease);

    let mut names = vec![
        RefName::branch(b"feature").unwrap(),
        RefName::from_bytes([
            b'r', b'e', b'f', b's', b'/', b'h', b'e', b'a', b'd', b's', b'/', b'r', b'a', b'w',
            b'-', 0xff,
        ])
        .unwrap(),
        RefName::tag(b"v1").unwrap(),
    ];
    names.sort();
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: OperationId::new(),
        repository_id,
        expected_generation: roots.generation,
        expected_roots: roots,
        actor: AuthorId::new("branch-list-adversary"),
        reason: "install exact branch-list fixture refs".to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: names
            .into_iter()
            .map(|name| RefMutation {
                name,
                expected: RefExpectation::MustNotExist,
                new_target: Some(target.clone()),
                policy: RefUpdatePolicy::FastForwardOnly,
            })
            .collect(),
        default_ref_mutation: None,
        workspace_mutation: None,
        local_overlay_delta: None,
        admission_scan_token: None,
    };
    let receipt = manager
        .commit_repository_transaction(transaction)
        .expect("commit exact refs");
    assert_eq!(receipt.generation, 2);
}

#[test]
fn branch_list_preserves_byte_refs_and_ignores_checkout_git_state() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&repo).expect("create repo");
    run_git(&repo, &["init", "--initial-branch=main"]);
    run_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(&repo, &["config", "user.name", "Kin"]);
    fs::write(repo.join("compose.yaml"), b"services: {}\n").expect("write Compose file");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "base"]);

    let init = run_kin(&repo, &home, &["init", ".", "--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
    let layout = kin_core::KinLayout::discover(&repo).expect("discover exact layout");
    add_exact_refs(&layout);

    let before = run_kin(&repo, &home, &["branch", "list", "--json"]);
    assert!(
        before.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&before.stdout),
        String::from_utf8_lossy(&before.stderr)
    );
    let before_report: Value =
        serde_json::from_slice(&before.stdout).expect("branch list should be JSON");
    assert_eq!(before_report["schema"], "kin.branch-list.v1");
    assert_eq!(before_report["authority"], "repository-v6");
    assert_eq!(before_report["authority_generation"], 2);
    assert_eq!(before_report["repository_ref_count"], 4);
    assert_eq!(before_report["branch_count"], 3);

    let branches = before_report["branches"].as_array().expect("branch array");
    let raw = branches
        .iter()
        .find(|branch| branch["name"]["bytes_hex"] == "726566732f68656164732f7261772dff")
        .expect("non-UTF8 branch survives");
    assert_eq!(raw["active"], false);
    assert_eq!(raw["default"], false);
    let main = branches
        .iter()
        .find(|branch| branch["name"]["bytes_hex"] == "726566732f68656164732f6d61696e")
        .expect("main branch");
    assert_eq!(main["active"], true);
    assert_eq!(main["default"], true);
    assert!(
        branches
            .iter()
            .all(|branch| branch["name"]["bytes_hex"] != "726566732f746167732f7631"),
        "tag refs are not branches"
    );

    let human = run_kin(&repo, &home, &["branch", "list"]);
    assert!(human.status.success());
    assert!(String::from_utf8_lossy(&human.stdout).contains("refs/heads/raw-\\xff"));

    fs::rename(repo.join(".git"), repo.join("git-authority-disabled"))
        .expect("hide admitted Git metadata");
    fs::create_dir_all(repo.join(".git/refs/heads")).expect("create misleading Git refs");
    fs::write(repo.join(".git/refs/heads/fake"), b"not an oid\n").expect("write fake Git ref");

    let after = run_kin(&repo, &home, &["branch", "list", "--json"]);
    assert!(
        after.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&after.stdout),
        String::from_utf8_lossy(&after.stderr)
    );
    let after_report: Value =
        serde_json::from_slice(&after.stdout).expect("branch list should remain JSON");
    assert_eq!(
        after_report, before_report,
        "Git ref files influenced repository-v6 branch list"
    );
}
