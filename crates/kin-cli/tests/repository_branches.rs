// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::{
    AuthorId, OperationId, RefExpectation, RefMutation, RefName, RefUpdatePolicy, RepositoryId,
    RepositoryTransaction, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
use serde_json::Value;
#[cfg(target_os = "macos")]
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::tempdir;

mod common;

use common::Command;

fn initialize_git_repo(repo: &Path) {
    fs::create_dir_all(repo).expect("create repo");
    run_git(repo, &["init", "--initial-branch=main"]);
    run_git(repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(repo, &["config", "user.name", "Kin"]);
    fs::write(repo.join("compose.yaml"), b"services: {}\n").expect("write Compose file");
    fs::write(repo.join("unchanged.txt"), b"shared branch bytes\n")
        .expect("write unchanged tracked file");
    run_git(repo, &["add", "--all"]);
    run_git(repo, &["commit", "-m", "base"]);
}

#[cfg(unix)]
fn add_feature_branch(repo: &Path) {
    use std::os::unix::fs::{symlink, PermissionsExt};

    run_git(repo, &["switch", "-c", "feature"]);
    fs::write(
        repo.join("compose.yaml"),
        b"services:\n  api:\n    build: .\n",
    )
    .expect("write target Compose file");
    fs::write(repo.join("Dockerfile"), b"FROM scratch\n").expect("write Dockerfile");
    fs::create_dir_all(repo.join("src")).expect("create Rust source directory");
    fs::write(repo.join("src/lib.rs"), b"pub fn feature() {}\n").expect("write Rust source");
    fs::write(repo.join("worker.py"), b"def feature():\n    return True\n")
        .expect("write Python source");
    fs::write(repo.join("notes.mystery"), b"unsupported-language bytes\n")
        .expect("write unsupported-language file");
    fs::create_dir_all(repo.join("assets")).expect("create asset directory");
    fs::write(repo.join("assets/data.bin"), [0_u8, 0xff, 0x10, 0x00]).expect("write binary asset");
    fs::write(repo.join("run-tool"), b"#!/bin/sh\nexit 0\n").expect("write executable");
    let mut permissions = fs::metadata(repo.join("run-tool"))
        .expect("stat executable")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(repo.join("run-tool"), permissions).expect("mark executable");
    symlink("compose.yaml", repo.join("compose-link")).expect("create source symlink");
    run_git(repo, &["add", "--all"]);
    run_git(repo, &["commit", "-m", "feature tree"]);
    run_git(repo, &["switch", "main"]);
}

fn initialize_kin_repo(
    runtime: &common::IsolatedDaemonRuntime,
    repo: &Path,
) -> kin_core::KinLayout {
    let init = run_kin(runtime, repo, &["init", ".", "--json"]);
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

/// Wait until the workspace tree is level with its base, or give up.
///
/// A watcher that admits observed host content leaves the workspace ahead of
/// its base for as long as it takes the loop to drain a tick, and several
/// repository transitions refuse over exactly that state. Polling authority is
/// how a test asks "has the loop finished" without asserting on a clock.
fn wait_for_level_workspace(layout: &kin_core::KinLayout, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        let (_, manager) = open_authority(layout);
        let level = {
            let lease = manager.read_authority();
            lease
                .metadata()
                .workspaces
                .first()
                .map(|workspace| workspace.base_tree_hash == Some(workspace.tree_hash))
                .unwrap_or(false)
        };
        if level {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
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

#[cfg(target_os = "macos")]
fn run_git_os(path: &Path, args: &[OsString]) {
    let output = Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .current_dir(path)
        .output()
        .expect("run Git with byte-exact arguments");
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
fn git_stdout(path: &Path, args: &[&str]) -> String {
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
    String::from_utf8(output.stdout)
        .expect("Git text output")
        .trim()
        .to_string()
}

#[cfg(unix)]
fn add_gitlink_branch_history(repo: &Path) -> (String, String) {
    let first_target = git_stdout(repo, &["rev-parse", "HEAD"]);
    run_git(repo, &["switch", "-c", "gitlink-a"]);
    run_git(
        repo,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{first_target},vendor/dependency"),
        ],
    );
    run_git(repo, &["commit", "-m", "add exact gitlink"]);
    let second_target = git_stdout(repo, &["rev-parse", "HEAD"]);

    run_git(repo, &["switch", "-c", "gitlink-b"]);
    run_git(
        repo,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{second_target},vendor/dependency"),
        ],
    );
    run_git(repo, &["commit", "-m", "retarget exact gitlink"]);

    run_git(repo, &["switch", "-c", "gitlink-removed"]);
    run_git(
        repo,
        &["update-index", "--force-remove", "vendor/dependency"],
    );
    run_git(repo, &["commit", "-m", "remove exact gitlink"]);
    run_git(repo, &["switch", "main"]);
    (first_target, second_target)
}

#[cfg(target_os = "macos")]
fn add_host_unrepresentable_branch(repo: &Path) -> (Vec<u8>, Vec<u8>) {
    use std::os::unix::ffi::OsStringExt as _;

    let raw_path = b"assets/icon-\xff.bin".to_vec();
    let body = b"opaque exact graph bytes\n".to_vec();
    let body_file = repo
        .parent()
        .expect("repository parent")
        .join("raw-path-body.bin");
    fs::write(&body_file, &body).expect("write raw-path blob input");
    let object_id = git_stdout(
        repo,
        &[
            "hash-object",
            "-w",
            body_file.to_str().expect("temporary body path is UTF-8"),
        ],
    );

    run_git(repo, &["switch", "-c", "raw-path"]);
    let mut cache_info = format!("100644,{object_id},").into_bytes();
    cache_info.extend_from_slice(&raw_path);
    run_git_os(
        repo,
        &[
            OsString::from("update-index"),
            OsString::from("--add"),
            OsString::from("--cacheinfo"),
            OsString::from_vec(cache_info),
        ],
    );
    run_git(
        repo,
        &["commit", "-m", "track host-unrepresentable byte path"],
    );
    run_git(repo, &["switch", "main"]);
    (raw_path, body)
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
        merge_transaction_delta: None,
        sealed_observation: None,
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
        merge_transaction_delta: None,
        sealed_observation: None,
    }
}

#[test]
fn branch_list_preserves_byte_refs_and_ignores_checkout_git_state() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    add_exact_refs(&layout);

    let before = run_kin(&runtime, &repo, &["branch", "list", "--json"]);
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

    let human = run_kin(&runtime, &repo, &["branch", "list"]);
    assert!(human.status.success());
    assert!(String::from_utf8_lossy(&human.stdout).contains("refs/heads/raw-\\xff"));

    fs::rename(repo.join(".git"), repo.join("git-authority-disabled"))
        .expect("hide admitted Git metadata");
    fs::create_dir_all(repo.join(".git/refs/heads")).expect("create misleading Git refs");
    fs::write(repo.join(".git/refs/heads/fake"), b"not an oid\n").expect("write fake Git ref");

    let after = run_kin(&runtime, &repo, &["branch", "list", "--json"]);
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
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);

    let create = run_kin(&runtime, &repo, &["branch", "create", "feature"]);
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

    let duplicate = run_kin(&runtime, &repo, &["branch", "create", "feature"]);
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already exists"));
    assert_eq!(
        manager.read_authority().roots().generation,
        generation_after_create,
        "failed create advanced authority"
    );

    let delete = run_kin(&runtime, &repo, &["branch", "delete", "feature"]);
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

/// How long a served daemon is watched for self-retirement.
///
/// Long enough to cover a short idle window plus the daemon's own idle check
/// interval, so a runtime that reintroduces one is caught rather than merely
/// made less likely to bite.
const SERVED_DAEMON_OBSERVATION: Duration = Duration::from_secs(3);
const SERVED_DAEMON_POLL: Duration = Duration::from_millis(50);

#[test]
fn a_daemon_that_served_a_branch_command_keeps_answering_its_recorded_endpoint() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);

    let command = runtime.kin_command();
    for key in [
        common::IDLE_SHUTDOWN_DISABLED_ENV,
        common::SUPERVISOR_IDLE_SHUTDOWN_DISABLED_ENV,
    ] {
        let configured = command
            .configured_env_for_test(std::ffi::OsStr::new(key))
            .unwrap_or_else(|| panic!("{key} is not configured by the isolated runtime"));
        assert!(
            common::disables_idle_shutdown(configured.as_deref()),
            "{key}={configured:?} leaves an idle clock running. Daemon lifetime in this runtime \
             is bounded by its teardown proof, and an idle window instead retires daemons that a \
             command has already proven healthy."
        );
    }
    drop(command);

    let create = run_kin(&runtime, &repo, &["branch", "create", "retained"]);
    assert!(
        create.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );

    let started = Instant::now();
    let mut proofs = 0_u32;
    while started.elapsed() < SERVED_DAEMON_OBSERVATION {
        match common::probe_recorded_daemon_endpoint(layout.root()) {
            common::RecordedDaemonEndpoint::Listening { .. } => proofs += 1,
            observed => panic!(
                "the daemon that served this repository stopped answering its recorded \
                 endpoint {:.2}s after a command used it, leaving {observed:?}. A command \
                 that reads this record, proves the endpoint healthy, and then dispatches \
                 against it fails with a refused connection, and the test harness bounds \
                 daemon lifetime by its teardown proof rather than by an idle clock.",
                started.elapsed().as_secs_f64()
            ),
        }
        std::thread::sleep(SERVED_DAEMON_POLL);
    }
    assert!(
        proofs > 0,
        "observation window never probed the recorded daemon endpoint"
    );
}

#[test]
fn stale_branch_transaction_cannot_overwrite_new_repository_roots() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
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
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let (_, manager) = open_authority(&layout);
    let before = manager.read_authority().roots().clone();

    let delete = run_kin(&runtime, &repo, &["branch", "delete", "main"]);
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
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let raw = RefName::from_bytes([
        b'r', b'e', b'f', b's', b'/', b'h', b'e', b'a', b'd', b's', b'/', b'r', b'a', b'w', b'-',
        0xff,
    ])
    .unwrap();
    let encoded = hex::encode(raw.as_bytes());

    let create = run_kin(
        &runtime,
        &repo,
        &["branch", "create", "--ref-hex", &encoded],
    );
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
    let rejected = run_kin(
        &runtime,
        &repo,
        &["branch", "delete", "--ref-hex", &uppercase],
    );
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("canonical lowercase"));

    let delete = run_kin(
        &runtime,
        &repo,
        &["branch", "delete", "--ref-hex", &encoded],
    );
    assert!(delete.status.success());
}

#[test]
fn branch_create_uses_detached_workspace_target_without_git_fallback() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    run_git(&repo, &["checkout", "--detach"]);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    fs::rename(repo.join(".git"), repo.join("git-authority-disabled"))
        .expect("hide admitted Git metadata");

    let create = run_kin(&runtime, &repo, &["branch", "create", "detached-copy"]);
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
    drop(lease);

    let switched = run_kin(&runtime, &repo, &["branch", "switch", "main"]);
    assert!(
        switched.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&switched.stdout),
        String::from_utf8_lossy(&switched.stderr)
    );
    let reopened = RepositoryAuthorityManager::open(
        manager.read_authority().metadata().repository_id.clone(),
        Arc::new(LocalFileBackend::new(layout.kindb_dir())),
    )
    .expect("reopen switched authority");
    let workspace = reopened
        .read_authority()
        .metadata()
        .workspaces
        .first()
        .expect("switched workspace")
        .clone();
    assert_eq!(
        workspace.head,
        kin_model::WorkspaceHead::Symbolic {
            target: RefName::branch(b"main").unwrap()
        }
    );
}

#[cfg(unix)]
#[test]
fn branch_switch_projects_complete_polyglot_and_non_code_tree_from_repository_cas() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    add_feature_branch(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let (repository_id, manager) = open_authority(&layout);
    let lease = manager.read_authority();
    let roots = lease.roots().clone();
    let feature_target = lease
        .metadata()
        .ref_state
        .refs
        .iter()
        .find(|repository_ref| repository_ref.name == RefName::branch(b"feature").unwrap())
        .expect("imported feature branch")
        .target
        .clone();
    drop(lease);
    let raw_branch = RefName::from_bytes([
        b'r', b'e', b'f', b's', b'/', b'h', b'e', b'a', b'd', b's', b'/', b'f', b'e', b'a', b't',
        b'u', b'r', b'e', b'-', 0xff,
    ])
    .unwrap();
    manager
        .commit_repository_transaction(exact_ref_create_transaction(
            &repository_id,
            &roots,
            raw_branch.clone(),
            feature_target.clone(),
            "install byte-exact switch target",
        ))
        .expect("commit byte-exact branch");
    fs::rename(repo.join(".git"), repo.join("git-authority-disabled"))
        .expect("hide admitted Git metadata");

    let switched = run_kin(
        &runtime,
        &repo,
        &[
            "branch",
            "switch",
            "--ref-hex",
            &hex::encode(raw_branch.as_bytes()),
        ],
    );
    assert!(
        switched.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&switched.stdout),
        String::from_utf8_lossy(&switched.stderr)
    );

    assert_eq!(
        fs::read(repo.join("compose.yaml")).unwrap(),
        b"services:\n  api:\n    build: .\n"
    );
    assert_eq!(
        fs::read(repo.join("Dockerfile")).unwrap(),
        b"FROM scratch\n"
    );
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).unwrap(),
        b"pub fn feature() {}\n"
    );
    assert_eq!(
        fs::read(repo.join("worker.py")).unwrap(),
        b"def feature():\n    return True\n"
    );
    assert_eq!(
        fs::read(repo.join("notes.mystery")).unwrap(),
        b"unsupported-language bytes\n"
    );
    assert_eq!(
        fs::read(repo.join("assets/data.bin")).unwrap(),
        [0_u8, 0xff, 0x10, 0x00]
    );
    assert_ne!(
        fs::metadata(repo.join("run-tool"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111,
        0
    );
    assert_eq!(
        fs::read_link(repo.join("compose-link")).unwrap(),
        Path::new("compose.yaml")
    );
    assert!(!layout.root().join("HEAD").exists());

    let reopened = RepositoryAuthorityManager::open(
        repository_id,
        Arc::new(LocalFileBackend::new(layout.kindb_dir())),
    )
    .expect("reopen switched authority");
    let lease = reopened.read_authority();
    let workspace = lease.metadata().workspaces.first().unwrap();
    assert_eq!(
        workspace.head,
        kin_model::WorkspaceHead::Symbolic { target: raw_branch }
    );
    assert_eq!(workspace.base_target, Some(feature_target));
    assert_eq!(workspace.base_tree_hash, Some(workspace.tree_hash));
    let operation = lease.metadata().operation_log.last().unwrap();
    assert!(operation.workspace_mutation.is_some());
    assert!(operation.ref_mutations.is_empty());
    assert_eq!(lease.roots().generation, 3);
    assert!(fs::symlink_metadata(repo.join("compose-link"))
        .unwrap()
        .file_type()
        .is_symlink());
}

#[cfg(unix)]
#[test]
fn branch_switch_rejects_local_tracked_edits_and_preserves_authority() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    add_feature_branch(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let (_, manager) = open_authority(&layout);
    let before = manager.read_authority().roots().clone();
    fs::write(repo.join("unchanged.txt"), b"local uncommitted edit\n").expect("write local edit");

    let switched = run_kin(&runtime, &repo, &["branch", "switch", "feature"]);
    assert!(!switched.status.success());
    assert!(
        String::from_utf8_lossy(&switched.stderr).contains("differs from prior workspace source")
    );
    assert_eq!(
        fs::read(repo.join("unchanged.txt")).unwrap(),
        b"local uncommitted edit\n"
    );
    assert_eq!(
        manager.read_authority().roots(),
        &before,
        "rejected projection advanced repository authority"
    );
}

/// A pending edit to a member both branches hold identically moves across.
///
/// `unchanged.txt` is byte-identical on `main` and `feature`, so replaying the
/// edit onto the destination cannot overwrite anything the branch being entered
/// holds differently. This is the Git rule: a local change carries when the
/// branches agree about what it was changing.
#[cfg(unix)]
#[test]
fn branch_switch_carries_an_admitted_edit_to_a_member_both_branches_hold_identically() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    add_feature_branch(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let (repository_id, manager) = open_authority(&layout);
    admit_uncommitted_workspace_edit(
        &repository_id,
        &manager,
        &repo,
        b"unchanged.txt",
        b"admitted\n",
    );

    let switched = run_kin(&runtime, &repo, &["branch", "switch", "feature"]);
    assert!(
        switched.status.success(),
        "a pending edit to a member both branches share must carry: stdout={} stderr={}",
        String::from_utf8_lossy(&switched.stdout),
        String::from_utf8_lossy(&switched.stderr)
    );
    assert_eq!(
        fs::read(repo.join("unchanged.txt")).unwrap(),
        b"admitted\n",
        "the carried edit must survive on disk"
    );
    assert_eq!(
        fs::read(repo.join("compose.yaml")).unwrap(),
        b"services:\n  api:\n    build: .\n",
        "members the workspace never touched must take the destination's content"
    );

    let workspace = reopened_workspace(&layout);
    assert!(
        workspace.is_dirty(),
        "carried work stays uncommitted on the destination branch"
    );
    assert_eq!(
        workspace
            .tree
            .artifact_at_path(&repo_path(b"unchanged.txt"))
            .expect("carried member")
            .entry,
        kin_model::TreeEntry::blob(
            kin_model::Hash256::from_bytes(kin_blobs::digest_bytes(b"admitted\n")),
            false
        )
    );
}

/// A pending edit to a member the branches disagree about refuses.
///
/// `compose.yaml` differs between `main` and `feature`, so replaying the edit
/// would silently drop whichever side lost. Git refuses this as "your local
/// changes would be overwritten by checkout"; so does Kin, by exact path.
#[cfg(unix)]
#[test]
fn branch_switch_refuses_an_admitted_edit_to_a_member_the_branches_disagree_about() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    add_feature_branch(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let (repository_id, manager) = open_authority(&layout);
    admit_uncommitted_workspace_edit(
        &repository_id,
        &manager,
        &repo,
        b"compose.yaml",
        b"services:\n  mine: {}\n",
    );
    let before = manager.read_authority().roots().clone();

    let switched = run_kin(&runtime, &repo, &["branch", "switch", "feature"]);
    assert!(!switched.status.success());
    let stderr = String::from_utf8_lossy(&switched.stderr);
    assert!(
        stderr.contains("compose.yaml"),
        "the refusal must name the exact blocked path, got {stderr}"
    );
    assert!(
        stderr.contains("holds this member differently"),
        "the refusal must say which side the path would have cost, got {stderr}"
    );
    assert!(
        stderr.contains("Commit these") && stderr.contains("kin stash push"),
        "the refusal must name both remedies, got {stderr}"
    );
    assert_eq!(
        fs::read(repo.join("compose.yaml")).unwrap(),
        b"services:\n  mine: {}\n",
        "a refused switch leaves the workspace exactly as it was"
    );
    assert_eq!(
        manager.read_authority().roots(),
        &before,
        "refused switch advanced repository authority"
    );
}

/// A pending addition at a path the destination does not track carries.
///
/// This is the case the whole change exists for: ambient observation admits
/// every new non-ignored file, so a scratch note is uncommitted graph truth
/// within seconds of being written, and Git would have carried it in silence.
#[cfg(unix)]
#[test]
fn branch_switch_carries_an_admitted_addition_the_destination_does_not_track() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    add_feature_branch(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let (repository_id, manager) = open_authority(&layout);
    let admitted = admit_uncommitted_workspace_addition(
        &repository_id,
        &manager,
        &repo,
        b"scratch-note.md",
        b"thinking out loud\n",
    );

    let switched = run_kin(&runtime, &repo, &["branch", "switch", "feature"]);
    assert!(
        switched.status.success(),
        "a pending addition the destination does not track must carry: stdout={} stderr={}",
        String::from_utf8_lossy(&switched.stdout),
        String::from_utf8_lossy(&switched.stderr)
    );
    assert_eq!(
        fs::read(repo.join("scratch-note.md")).unwrap(),
        b"thinking out loud\n",
        "the carried addition must survive on disk"
    );
    assert!(
        String::from_utf8_lossy(&switched.stdout).contains("scratch-note.md"),
        "the switch must say where the pending work went, got {}",
        String::from_utf8_lossy(&switched.stdout)
    );

    let workspace = reopened_workspace(&layout);
    assert!(
        workspace.is_dirty(),
        "a carried addition is still uncommitted on the destination branch"
    );
    let carried = workspace
        .tree
        .artifact_at_path(&repo_path(b"scratch-note.md"))
        .expect("carried addition stays in the workspace tree");
    assert_eq!(
        carried.artifact_id, admitted,
        "carrying preserves the identity the entry was admitted under"
    );
    assert!(
        workspace
            .tree
            .artifact_at_path(&repo_path(b"Dockerfile"))
            .is_some(),
        "the destination branch's own members arrive alongside the carried work"
    );
}

/// A pending addition the destination tracks with different content refuses.
///
/// `Dockerfile` exists only on `feature`, so admitting one on `main` and then
/// switching is exactly Git's "untracked working tree file would be overwritten
/// by checkout".
#[cfg(unix)]
#[test]
fn branch_switch_refuses_an_admitted_addition_the_destination_tracks_differently() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    add_feature_branch(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let (repository_id, manager) = open_authority(&layout);
    admit_uncommitted_workspace_addition(
        &repository_id,
        &manager,
        &repo,
        b"Dockerfile",
        b"FROM mine\n",
    );
    let before = manager.read_authority().roots().clone();

    let switched = run_kin(&runtime, &repo, &["branch", "switch", "feature"]);
    assert!(!switched.status.success());
    let stderr = String::from_utf8_lossy(&switched.stderr);
    assert!(
        stderr.contains("Dockerfile"),
        "the refusal must name the exact blocked path, got {stderr}"
    );
    assert!(
        stderr.contains("would overwrite"),
        "the refusal must say what carrying would have cost, got {stderr}"
    );
    assert!(
        stderr.contains("Commit these") && stderr.contains("kin stash push"),
        "the refusal must name both remedies, got {stderr}"
    );
    assert_eq!(
        fs::read(repo.join("Dockerfile")).unwrap(),
        b"FROM mine\n",
        "a refused switch leaves the workspace exactly as it was"
    );
    assert_eq!(
        manager.read_authority().roots(),
        &before,
        "refused switch advanced repository authority"
    );
}

/// Switching away and back leaves the pending tree byte-identical.
///
/// A carry that quietly re-identified or re-encoded the pending entry would
/// still pass the single-hop tests. Only the round trip proves the entry that
/// comes home is the one that left.
#[cfg(unix)]
#[test]
fn branch_switch_round_trip_leaves_the_carried_workspace_byte_identical() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    add_feature_branch(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let (repository_id, manager) = open_authority(&layout);
    admit_uncommitted_workspace_addition(
        &repository_id,
        &manager,
        &repo,
        b"scratch-note.md",
        b"thinking out loud\n",
    );
    let departed = reopened_workspace(&layout);

    for branch in ["feature", "main"] {
        let switched = run_kin(&runtime, &repo, &["branch", "switch", branch]);
        assert!(
            switched.status.success(),
            "switch to {branch} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&switched.stdout),
            String::from_utf8_lossy(&switched.stderr)
        );
    }

    let returned = reopened_workspace(&layout);
    assert_eq!(
        returned.tree, departed.tree,
        "a round trip must reproduce the pending tree exactly"
    );
    assert_eq!(returned.tree_hash, departed.tree_hash);
    assert_eq!(returned.base_tree_hash, departed.base_tree_hash);
    assert_eq!(
        fs::read(repo.join("scratch-note.md")).unwrap(),
        b"thinking out loud\n"
    );
}

#[cfg(unix)]
fn repo_path(path: &[u8]) -> kin_model::RepoPath {
    kin_model::RepoPath::from_bytes(path.to_vec()).expect("repository path")
}

#[cfg(unix)]
fn current_workspace(
    manager: &RepositoryAuthorityManager<LocalFileBackend>,
) -> kin_model::WorkspaceState {
    let lease = manager.read_authority();
    let workspace = lease
        .metadata()
        .workspaces
        .first()
        .expect("local workspace")
        .clone();
    workspace
}

/// Read the workspace through a manager opened after the command under test.
///
/// A handle opened before a switch keeps answering from the lease it already
/// holds, so asserting post-switch state through it reads the state the test
/// set up and passes whether or not the switch did anything. Reopening is what
/// makes these assertions able to disagree.
#[cfg(unix)]
fn reopened_workspace(layout: &kin_core::KinLayout) -> kin_model::WorkspaceState {
    let (_, manager) = open_authority(layout);
    current_workspace(&manager)
}

/// Publish one uncommitted addition at an untracked path, exactly as ambient
/// observation does, and leave the bytes on disk where it found them.
///
/// Returns the artifact identity the entry was admitted under, so a caller can
/// prove a carry preserved it rather than minting a fresh one.
#[cfg(unix)]
fn admit_uncommitted_workspace_addition(
    repository_id: &RepositoryId,
    manager: &RepositoryAuthorityManager<LocalFileBackend>,
    repo: &Path,
    path: &[u8],
    body: &[u8],
) -> kin_model::ArtifactId {
    let workspace = current_workspace(manager);
    let target = repo_path(path);
    assert!(
        workspace.tree.artifact_at_path(&target).is_none(),
        "an addition fixture must name a path the workspace does not already track"
    );
    let artifact_id = kin_model::ArtifactId::new();
    let entry = save_admitted_bytes(manager, body);
    let deltas = vec![kin_model::TreeDelta::Added {
        artifact_id,
        new: kin_model::LocatedEntry::new(target, entry),
    }];
    publish_uncommitted_workspace_deltas(
        repository_id,
        manager,
        repo,
        workspace,
        deltas,
        path,
        body,
    );
    artifact_id
}

/// Publish one uncommitted edit to a tracked workspace member straight through
/// repository authority, exactly as an admission seam does. This produces the
/// graph-owned pending state a transition must decide about without depending
/// on whichever host events a watcher happens to deliver.
#[cfg(unix)]
fn admit_uncommitted_workspace_edit(
    repository_id: &RepositoryId,
    manager: &RepositoryAuthorityManager<LocalFileBackend>,
    repo: &Path,
    path: &[u8],
    body: &[u8],
) {
    let workspace = current_workspace(manager);
    let target = repo_path(path);
    let artifact = workspace
        .tree
        .artifact_at_path(&target)
        .expect("tracked workspace member")
        .clone();
    let entry = save_admitted_bytes(manager, body);
    let deltas = vec![kin_model::TreeDelta::Updated {
        artifact_id: artifact.artifact_id,
        old: artifact.located_entry(),
        new: kin_model::LocatedEntry::new(target, entry),
    }];
    publish_uncommitted_workspace_deltas(
        repository_id,
        manager,
        repo,
        workspace,
        deltas,
        path,
        body,
    );
}

#[cfg(unix)]
fn save_admitted_bytes(
    manager: &RepositoryAuthorityManager<LocalFileBackend>,
    body: &[u8],
) -> kin_model::TreeEntry {
    let digest = kin_model::Hash256::from_bytes(kin_blobs::digest_bytes(body));
    manager
        .save_source_blob(digest, body)
        .expect("save admitted source bytes");
    kin_model::TreeEntry::blob(digest, false)
}

/// Commit the admission, then leave the working copy agreeing with it.
///
/// Authority moves first on purpose. The projection drift check reads every
/// tracked path before a transition, so a fixture that wrote the file first
/// would be racing the daemon's own observation of it; admitting first and
/// writing second means both orders end at the same agreeing state.
#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn publish_uncommitted_workspace_deltas(
    repository_id: &RepositoryId,
    manager: &RepositoryAuthorityManager<LocalFileBackend>,
    repo: &Path,
    workspace: kin_model::WorkspaceState,
    deltas: Vec<kin_model::TreeDelta>,
    path: &[u8],
    body: &[u8],
) {
    let roots = manager.read_authority().roots().clone();
    let tree = workspace
        .tree
        .apply(&deltas)
        .expect("apply admitted workspace change");
    let tree_hash = kin_model::compute_resolved_tree_hash(&tree).expect("hash admitted tree");
    manager
        .commit_repository_transaction(RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id: repository_id.clone(),
            expected_generation: roots.generation,
            expected_roots: roots,
            actor: AuthorId::new("workspace-admission"),
            reason: "admit exact graph-owned workspace tree".to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: Vec::new(),
            aliases: Vec::new(),
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: Some(kin_model::WorkspaceMutation {
                workspace_id: workspace.workspace_id,
                expected: kin_model::WorkspaceExpectation::MustEqual {
                    generation: workspace.generation,
                    head: workspace.head.clone(),
                    base_target: workspace.base_target.clone(),
                    base_tree_hash: workspace.base_tree_hash,
                    tree_hash: workspace.tree_hash,
                    semantic_overlay_hash: workspace.semantic_overlay_hash,
                    admission_policy: workspace.admission_policy,
                },
                new_generation: workspace.generation + 1,
                new_head: workspace.head,
                new_base_target: workspace.base_target,
                new_base_tree_hash: workspace.base_tree_hash,
                tree_deltas: deltas,
                new_tree_hash: tree_hash,
                semantic_delta: kin_model::WorkspaceSemanticDelta::default(),
                new_shared_admission_policy: workspace.shared_admission_policy.clone(),
                new_admission_policy: workspace.admission_policy,
            }),
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        })
        .expect("commit admitted workspace change");

    let host_path = repo.join(String::from_utf8(path.to_vec()).expect("utf-8 fixture path"));
    if let Some(parent) = host_path.parent() {
        fs::create_dir_all(parent).expect("create admitted parent directory");
    }
    fs::write(&host_path, body).expect("leave the working copy agreeing with the admission");
}

#[cfg(unix)]
#[test]
fn branch_switch_preserves_graph_only_gitlinks_without_traversing_nested_checkout() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let dependency = repo.join("vendor/dependency");
    initialize_git_repo(&repo);
    let (first_target, second_target) = add_gitlink_branch_history(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let (repository_id, _) = open_authority(&layout);
    fs::rename(repo.join(".git"), repo.join("git-authority-disabled"))
        .expect("hide admitted Git metadata");

    let add_absent = run_kin(&runtime, &repo, &["branch", "switch", "gitlink-a"]);
    assert!(
        add_absent.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&add_absent.stdout),
        String::from_utf8_lossy(&add_absent.stderr)
    );
    assert!(
        !dependency.exists(),
        "an absent Gitlink must not acquire an invented blob or directory"
    );
    assert_workspace_gitlink(&open_authority(&layout).1, &first_target);

    fs::create_dir_all(dependency.join("nested")).expect("create independent nested checkout");
    fs::write(dependency.join("nested/owned.txt"), b"independent before\n")
        .expect("write independent checkout content");

    let retarget = run_kin(&runtime, &repo, &["branch", "switch", "gitlink-b"]);
    assert!(
        retarget.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&retarget.stdout),
        String::from_utf8_lossy(&retarget.stderr)
    );
    assert_eq!(
        fs::read(dependency.join("nested/owned.txt")).unwrap(),
        b"independent before\n"
    );
    assert_workspace_gitlink(&open_authority(&layout).1, &second_target);

    fs::write(dependency.join("nested/owned.txt"), b"independent after\n")
        .expect("mutate independently owned descendants");
    fs::write(dependency.join("untracked.bin"), [0_u8, 0xff, 0x44])
        .expect("add independent opaque content");
    let remove = run_kin(&runtime, &repo, &["branch", "switch", "gitlink-removed"]);
    assert!(
        remove.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&remove.stdout),
        String::from_utf8_lossy(&remove.stderr)
    );
    assert_eq!(
        fs::read(dependency.join("nested/owned.txt")).unwrap(),
        b"independent after\n"
    );
    assert_eq!(
        fs::read(dependency.join("untracked.bin")).unwrap(),
        [0_u8, 0xff, 0x44]
    );
    assert_workspace_has_no_path(&open_authority(&layout).1, b"vendor/dependency");

    // Let the watcher finish with the events these switches produced before
    // asking for another one. A switch refuses over a workspace holding content
    // ahead of its base, and admitting observed host content is what the
    // watcher now does, so a second switch issued while the loop is still
    // draining is racing the product rather than testing it.
    //
    // The wait is bounded and its failure is specific. If the loop settles and
    // the workspace is still ahead of its base, that is the one corner this
    // pairing has: events beneath a graph-only member are dropped against the
    // tree as it stands when they are drained, so events that outlive the
    // member's removal are no longer recognised as belonging to an independent
    // checkout, and the content underneath it is admitted like any other new
    // file. The message says so rather than leaving a later reader to rediscover
    // it from a timeout.
    let settled = wait_for_level_workspace(&layout, Duration::from_secs(30));
    assert!(
        settled,
        "the workspace never came level with its base. Host content beneath the removed Gitlink \
         was admitted as ordinary new content, which happens when its watcher events are drained \
         after the member is gone rather than while it is still there"
    );

    let add_retained = run_kin(&runtime, &repo, &["branch", "switch", "gitlink-a"]);
    assert!(
        add_retained.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&add_retained.stdout),
        String::from_utf8_lossy(&add_retained.stderr)
    );
    assert_eq!(
        fs::read(dependency.join("nested/owned.txt")).unwrap(),
        b"independent after\n"
    );
    assert_eq!(
        fs::read(dependency.join("untracked.bin")).unwrap(),
        [0_u8, 0xff, 0x44]
    );
    assert_workspace_gitlink(&open_authority(&layout).1, &first_target);

    let reopened = RepositoryAuthorityManager::open(
        repository_id,
        Arc::new(LocalFileBackend::new(layout.kindb_dir())),
    )
    .expect("reopen exact authority after graph-only switches");
    assert_workspace_gitlink(&reopened, &first_target);
}

#[cfg(target_os = "macos")]
#[test]
fn branch_switch_retains_host_unrepresentable_byte_path_in_graph_authority() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    let (raw_path, body) = add_host_unrepresentable_branch(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let (repository_id, _) = open_authority(&layout);
    fs::rename(repo.join(".git"), repo.join("git-authority-disabled"))
        .expect("hide admitted Git metadata");

    let switched = run_kin(&runtime, &repo, &["branch", "switch", "raw-path"]);
    assert!(
        switched.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&switched.stdout),
        String::from_utf8_lossy(&switched.stderr)
    );
    assert!(
        !repo.join("assets").exists(),
        "macOS-unrepresentable repository bytes must not acquire a lossy host alias"
    );
    assert_workspace_blob(&open_authority(&layout).1, &raw_path, &body);

    let removed = run_kin(&runtime, &repo, &["branch", "switch", "main"]);
    assert!(
        removed.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&removed.stdout),
        String::from_utf8_lossy(&removed.stderr)
    );
    assert_workspace_has_no_path(&open_authority(&layout).1, &raw_path);

    let restored = run_kin(&runtime, &repo, &["branch", "switch", "raw-path"]);
    assert!(
        restored.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&restored.stdout),
        String::from_utf8_lossy(&restored.stderr)
    );
    assert_workspace_blob(&open_authority(&layout).1, &raw_path, &body);

    let reopened = RepositoryAuthorityManager::open(
        repository_id,
        Arc::new(LocalFileBackend::new(layout.kindb_dir())),
    )
    .expect("reopen authority with host-unrepresentable workspace member");
    assert_workspace_blob(&reopened, &raw_path, &body);
}

#[cfg(unix)]
fn assert_workspace_gitlink(
    manager: &RepositoryAuthorityManager<LocalFileBackend>,
    expected_hex: &str,
) {
    let expected = kin_model::GitObjectId::sha1(
        hex::decode(expected_hex)
            .expect("hex Git object ID")
            .try_into()
            .expect("SHA-1 Git object ID"),
    );
    let lease = manager.read_authority();
    let workspace = lease.metadata().workspaces.first().expect("workspace");
    let artifact = workspace
        .tree
        .artifacts_by_path()
        .find(|artifact| artifact.path.as_bytes() == b"vendor/dependency")
        .expect("Gitlink authority member");
    assert_eq!(artifact.entry, kin_model::TreeEntry::gitlink(expected));
}

#[cfg(unix)]
fn assert_workspace_has_no_path(
    manager: &RepositoryAuthorityManager<LocalFileBackend>,
    expected_path: &[u8],
) {
    let lease = manager.read_authority();
    let workspace = lease.metadata().workspaces.first().expect("workspace");
    assert!(workspace
        .tree
        .artifacts_by_path()
        .all(|artifact| artifact.path.as_bytes() != expected_path));
}

#[cfg(target_os = "macos")]
fn assert_workspace_blob(
    manager: &RepositoryAuthorityManager<LocalFileBackend>,
    expected_path: &[u8],
    expected_body: &[u8],
) {
    let lease = manager.read_authority();
    let workspace = lease.metadata().workspaces.first().expect("workspace");
    let artifact = workspace
        .tree
        .artifacts_by_path()
        .find(|artifact| artifact.path.as_bytes() == expected_path)
        .expect("exact workspace blob member");
    let expected_identity = artifact.entry.blob_identity().expect("blob identity");
    drop(lease);
    assert_eq!(
        manager
            .load_source_blob(expected_identity)
            .expect("load exact source-CAS body")
            .expect("source-CAS body present"),
        expected_body
    );
}
