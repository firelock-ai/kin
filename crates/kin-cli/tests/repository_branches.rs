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

fn initialize_git_repo(repo: &Path) {
    fs::create_dir_all(repo).expect("create repo");
    run_git(repo, &["init", "--initial-branch=main"]);
    run_git(repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(repo, &["config", "user.name", "Kin"]);
    fs::write(repo.join("compose.yaml"), b"services: {}\n").expect("write Compose file");
    run_git(repo, &["add", "--all"]);
    run_git(repo, &["commit", "-m", "base"]);
}

fn initialize_kin_repo(repo: &Path, home: &Path) -> kin_core::KinLayout {
    let init = run_kin(repo, home, &["init", ".", "--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
    kin_core::KinLayout::discover(repo).expect("discover exact layout")
}

fn open_authority(
    layout: &kin_core::KinLayout,
) -> (RepositoryId, RepositoryAuthorityManager<LocalFileBackend>) {
    let manifest = kin_core::KinManifest::load(&layout.manifest_path()).expect("load Kin manifest");
    let repository_id = RepositoryId::new(manifest.repo_id).expect("valid repository id");
    let manager = RepositoryAuthorityManager::open(
        repository_id.clone(),
        Arc::new(LocalFileBackend::new(layout.kindb_dir())),
    )
    .expect("open repository authority");
    (repository_id, manager)
}

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
    let (repository_id, manager) = open_authority(layout);
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

fn exact_ref_create_transaction(
    repository_id: &RepositoryId,
    roots: &kin_model::RootBundle,
    name: RefName,
    target: kin_model::RefTarget,
    reason: &str,
) -> RepositoryTransaction {
    RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: OperationId::new(),
        repository_id: repository_id.clone(),
        expected_generation: roots.generation,
        expected_roots: roots.clone(),
        actor: AuthorId::new("branch-cas-adversary"),
        reason: reason.to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: vec![RefMutation {
            name,
            expected: RefExpectation::MustNotExist,
            new_target: Some(target),
            policy: RefUpdatePolicy::FastForwardOnly,
        }],
        default_ref_mutation: None,
        workspace_mutation: None,
        local_overlay_delta: None,
        admission_scan_token: None,
    }
}

#[test]
fn branch_list_preserves_byte_refs_and_ignores_checkout_git_state() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    initialize_git_repo(&repo);
    let layout = initialize_kin_repo(&repo, &home);
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

#[test]
fn branch_create_and_delete_commit_exact_ref_cas() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    initialize_git_repo(&repo);
    let layout = initialize_kin_repo(&repo, &home);

    let create = run_kin(&repo, &home, &["branch", "create", "feature"]);
    assert!(
        create.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );

    let (repository_id, manager) = open_authority(&layout);
    let feature = RefName::branch(b"feature").unwrap();
    let lease = manager.read_authority();
    let workspace = lease
        .metadata()
        .workspaces
        .first()
        .expect("initialized workspace");
    let feature_ref = lease
        .metadata()
        .ref_state
        .refs
        .iter()
        .find(|repository_ref| repository_ref.name == feature)
        .expect("created feature ref");
    assert_eq!(feature_ref.target, workspace.base_target.clone().unwrap());
    let create_record = lease
        .metadata()
        .operation_log
        .last()
        .expect("create operation");
    assert_eq!(create_record.ref_mutations.len(), 1);
    assert_eq!(
        create_record.ref_mutations[0].expected,
        RefExpectation::MustNotExist
    );
    assert_eq!(
        create_record.ref_mutations[0].policy,
        RefUpdatePolicy::FastForwardOnly
    );
    let generation_after_create = lease.roots().generation;
    drop(lease);

    let duplicate = run_kin(&repo, &home, &["branch", "create", "feature"]);
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already exists"));
    assert_eq!(
        manager.read_authority().roots().generation,
        generation_after_create,
        "failed create advanced authority"
    );

    let delete = run_kin(&repo, &home, &["branch", "delete", "feature"]);
    assert!(
        delete.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&delete.stdout),
        String::from_utf8_lossy(&delete.stderr)
    );
    let reopened = RepositoryAuthorityManager::open(
        repository_id,
        Arc::new(LocalFileBackend::new(layout.kindb_dir())),
    )
    .expect("reopen authority");
    let lease = reopened.read_authority();
    assert!(lease
        .metadata()
        .ref_state
        .refs
        .iter()
        .all(|repository_ref| repository_ref.name != feature));
    let delete_record = lease
        .metadata()
        .operation_log
        .last()
        .expect("delete operation");
    assert_eq!(
        delete_record.ref_mutations[0].policy,
        RefUpdatePolicy::ForceWithLease
    );
    assert_eq!(
        delete_record.ref_mutations[0].new_target, None,
        "delete receipt must retain exact deletion"
    );
}

#[test]
fn stale_branch_transaction_cannot_overwrite_new_repository_roots() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    initialize_git_repo(&repo);
    let layout = initialize_kin_repo(&repo, &home);
    let (repository_id, manager) = open_authority(&layout);
    let lease = manager.read_authority();
    let roots = lease.roots().clone();
    let target = lease
        .metadata()
        .workspaces
        .first()
        .and_then(|workspace| workspace.base_target.clone())
        .expect("initialized workspace target");
    drop(lease);

    let stale_name = RefName::branch(b"stale-writer").unwrap();
    let stale = exact_ref_create_transaction(
        &repository_id,
        &roots,
        stale_name.clone(),
        target.clone(),
        "attempt stale branch create",
    );
    let winner_name = RefName::branch(b"concurrent-winner").unwrap();
    let winner = exact_ref_create_transaction(
        &repository_id,
        &roots,
        winner_name.clone(),
        target,
        "advance roots before stale writer",
    );
    manager
        .commit_repository_transaction(winner)
        .expect("commit concurrent winner");

    manager
        .commit_repository_transaction(stale)
        .expect_err("stale roots must reject branch mutation");
    let lease = manager.read_authority();
    assert_eq!(lease.roots().generation, roots.generation + 1);
    assert!(lease
        .metadata()
        .ref_state
        .refs
        .iter()
        .any(|repository_ref| repository_ref.name == winner_name));
    assert!(lease
        .metadata()
        .ref_state
        .refs
        .iter()
        .all(|repository_ref| repository_ref.name != stale_name));
}

#[test]
fn branch_delete_rejects_default_and_checked_out_ref_without_mutation() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    initialize_git_repo(&repo);
    let layout = initialize_kin_repo(&repo, &home);
    let (_, manager) = open_authority(&layout);
    let before = manager.read_authority().roots().clone();

    let delete = run_kin(&repo, &home, &["branch", "delete", "main"]);
    assert!(!delete.status.success());
    assert!(String::from_utf8_lossy(&delete.stderr).contains("default branch"));
    assert_eq!(
        manager.read_authority().roots(),
        &before,
        "rejected delete changed repository authority"
    );
}

#[test]
fn branch_mutations_accept_canonical_hex_for_non_utf8_refs() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    initialize_git_repo(&repo);
    let layout = initialize_kin_repo(&repo, &home);
    let raw = RefName::from_bytes([
        b'r', b'e', b'f', b's', b'/', b'h', b'e', b'a', b'd', b's', b'/', b'r', b'a', b'w', b'-',
        0xff,
    ])
    .unwrap();
    let encoded = hex::encode(raw.as_bytes());

    let create = run_kin(&repo, &home, &["branch", "create", "--ref-hex", &encoded]);
    assert!(
        create.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );
    let (_, manager) = open_authority(&layout);
    assert!(manager
        .read_authority()
        .metadata()
        .ref_state
        .refs
        .iter()
        .any(|repository_ref| repository_ref.name == raw));

    let uppercase = encoded.to_uppercase();
    let rejected = run_kin(&repo, &home, &["branch", "delete", "--ref-hex", &uppercase]);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("canonical lowercase"));

    let delete = run_kin(&repo, &home, &["branch", "delete", "--ref-hex", &encoded]);
    assert!(delete.status.success());
}

#[test]
fn branch_create_uses_detached_workspace_target_without_git_fallback() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    initialize_git_repo(&repo);
    run_git(&repo, &["checkout", "--detach"]);
    let layout = initialize_kin_repo(&repo, &home);
    fs::rename(repo.join(".git"), repo.join("git-authority-disabled"))
        .expect("hide admitted Git metadata");

    let create = run_kin(&repo, &home, &["branch", "create", "detached-copy"]);
    assert!(
        create.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );
    let (_, manager) = open_authority(&layout);
    let lease = manager.read_authority();
    let workspace = lease
        .metadata()
        .workspaces
        .first()
        .expect("detached workspace");
    assert!(matches!(
        workspace.head,
        kin_model::WorkspaceHead::Detached { .. }
    ));
    let copied = lease
        .metadata()
        .ref_state
        .refs
        .iter()
        .find(|repository_ref| repository_ref.name == RefName::branch(b"detached-copy").unwrap())
        .expect("branch copied from detached target");
    assert_eq!(Some(copied.target.clone()), workspace.base_target.clone());
}
