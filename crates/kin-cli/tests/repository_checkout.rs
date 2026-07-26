// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::fs;
use std::path::Path;
use std::sync::Arc;

use kin_cli::commands::checkout::{
    execute_checkout_request, execute_checkout_request_with_hooks, parse_checkout_path,
    CheckoutRequest,
};
use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::{
    AuthorId, OperationId, RefExpectation, RefMutation, RefName, RefUpdatePolicy, RepositoryId,
    RepositoryTransaction, SemanticChangeId, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
#[cfg(target_os = "macos")]
use std::ffi::OsString;
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

fn initialize_kin(repo: &Path, home: &Path) -> kin_core::KinLayout {
    let output = run_kin(repo, home, &["init", ".", "--json"]);
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    kin_core::KinLayout::discover(repo).expect("discover repository-v6 layout")
}

fn open_authority(
    layout: &kin_core::KinLayout,
) -> (RepositoryId, RepositoryAuthorityManager<LocalFileBackend>) {
    let manifest = kin_core::KinManifest::load(&layout.manifest_path()).expect("load manifest");
    let repository_id = RepositoryId::new(manifest.repo_id).expect("valid repository id");
    let manager = RepositoryAuthorityManager::open(
        repository_id.clone(),
        Arc::new(LocalFileBackend::new(layout.kindb_dir())),
    )
    .expect("open repository authority");
    (repository_id, manager)
}

fn ref_change(
    manager: &RepositoryAuthorityManager<LocalFileBackend>,
    branch: &str,
) -> SemanticChangeId {
    let lease = manager.read_authority();
    let name = RefName::branch(branch.as_bytes()).expect("branch ref");
    let target = lease
        .resolve_ref_target(&name)
        .expect("resolve ref")
        .expect("branch exists");
    lease
        .resolve_target_change_id(&target)
        .expect("resolve semantic branch target")
}

fn request(path: &str, change: Option<SemanticChangeId>) -> CheckoutRequest {
    CheckoutRequest {
        path: Some(path.to_string()),
        path_hex: None,
        change_id: change.map(|change| change.to_string()),
        operation_id: OperationId::new(),
    }
}

#[test]
fn checkout_path_parser_is_byte_safe_component_aware_and_control_safe() {
    assert_eq!(
        parse_checkout_path(Some("src"), None).unwrap().as_bytes(),
        b"src"
    );
    assert_eq!(
        parse_checkout_path(None, Some("7372632fff"))
            .unwrap()
            .as_bytes(),
        b"src/\xff"
    );
    for (path, encoded, message) in [
        (None, None, "provide"),
        (Some("src"), Some("737263"), "either"),
        (Some(""), None, "must not be empty"),
        (Some("../src"), None, "must not contain"),
        (Some("/src"), None, "must be relative"),
        (Some(".kin/config"), None, "reserved"),
        (Some(".git/config"), None, "reserved"),
    ] {
        let error = parse_checkout_path(path, encoded).expect_err("path must fail");
        assert!(error.to_string().contains(message), "{error}");
    }
    assert!(parse_checkout_path(None, Some("7372632FFF"))
        .unwrap_err()
        .to_string()
        .contains("canonical lowercase"));
    assert!(parse_checkout_path(None, Some("zz"))
        .unwrap_err()
        .to_string()
        .contains("invalid repository path hex"));
}

#[cfg(unix)]
#[test]
fn selected_checkout_preserves_unrelated_dirty_state_and_projects_universal_subtree() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let root = tempdir().unwrap();
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(repo.join("selected/swap-dir")).unwrap();
    run_git(&repo, &["init", "--initial-branch=main"]);
    run_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(&repo, &["config", "user.name", "Kin"]);
    fs::write(repo.join("selected/config.yaml"), b"main: true\n").unwrap();
    fs::write(repo.join("selected/remove.txt"), b"main only\n").unwrap();
    fs::write(repo.join("selected/swap-file"), b"main file\n").unwrap();
    fs::write(repo.join("selected/swap-dir/item.txt"), b"main child\n").unwrap();
    fs::write(repo.join("outside.txt"), b"outside base\n").unwrap();
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "main tree"]);

    run_git(&repo, &["switch", "-c", "feature"]);
    fs::write(
        repo.join("selected/config.yaml"),
        b"services:\n  api:\n    build: .\n",
    )
    .unwrap();
    fs::remove_file(repo.join("selected/remove.txt")).unwrap();
    fs::remove_file(repo.join("selected/swap-file")).unwrap();
    fs::create_dir_all(repo.join("selected/swap-file")).unwrap();
    fs::write(
        repo.join("selected/swap-file/nested.txt"),
        b"feature child\n",
    )
    .unwrap();
    fs::remove_file(repo.join("selected/swap-dir/item.txt")).unwrap();
    fs::remove_dir(repo.join("selected/swap-dir")).unwrap();
    fs::write(repo.join("selected/swap-dir"), b"feature file\n").unwrap();
    fs::write(
        repo.join("selected/compose.yaml"),
        b"services:\n  worker:\n    image: scratch\n",
    )
    .unwrap();
    fs::write(repo.join("selected/Dockerfile"), b"FROM scratch\n").unwrap();
    fs::write(repo.join("selected/data.bin"), [0_u8, 0xff, 0x10, 0x00]).unwrap();
    fs::write(repo.join("selected/run-tool"), b"#!/bin/sh\nexit 0\n").unwrap();
    let mut permissions = fs::metadata(repo.join("selected/run-tool"))
        .unwrap()
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(repo.join("selected/run-tool"), permissions).unwrap();
    fs::write(repo.join("selected/notes.mystery"), b"opaque bytes\n").unwrap();
    symlink("config.yaml", repo.join("selected/config-link")).unwrap();
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "feature tree"]);
    run_git(&repo, &["switch", "main"]);

    let layout = initialize_kin(&repo, &home);
    let (_, manager) = open_authority(&layout);
    let feature = ref_change(&manager, "feature");
    let before = manager.read_authority();
    let before_roots = before.roots().clone();
    let before_workspace = before.metadata().workspaces[0].clone();
    let before_refs = before.metadata().ref_state.clone();
    let before_change_count = before.snapshot().changes.len();
    drop(before);

    fs::write(repo.join("selected/config.yaml"), b"selected dirty\n").unwrap();
    fs::write(repo.join("outside.txt"), b"outside dirty preserved\n").unwrap();
    let response = execute_checkout_request(
        &layout,
        &kin_db::InMemoryGraph::new(),
        &request("selected", Some(feature)),
    )
    .expect("checkout feature subtree");
    assert!(response.mutated);
    assert!(!response.report.as_ref().unwrap().projection_only);
    assert_eq!(
        fs::read(repo.join("selected/config.yaml")).unwrap(),
        b"services:\n  api:\n    build: .\n"
    );
    assert_eq!(
        fs::read(repo.join("outside.txt")).unwrap(),
        b"outside dirty preserved\n"
    );
    assert!(!repo.join("selected/remove.txt").exists());
    assert_eq!(
        fs::read(repo.join("selected/swap-file/nested.txt")).unwrap(),
        b"feature child\n"
    );
    assert_eq!(
        fs::read(repo.join("selected/swap-dir")).unwrap(),
        b"feature file\n"
    );
    assert_eq!(
        fs::read(repo.join("selected/data.bin")).unwrap(),
        [0_u8, 0xff, 0x10, 0x00]
    );
    assert_ne!(
        fs::metadata(repo.join("selected/run-tool"))
            .unwrap()
            .permissions()
            .mode()
            & 0o111,
        0
    );
    assert_eq!(
        fs::read_link(repo.join("selected/config-link")).unwrap(),
        Path::new("config.yaml")
    );

    let (_, refreshed_manager) = open_authority(&layout);
    let after = refreshed_manager.read_authority();
    let workspace = &after.metadata().workspaces[0];
    assert_eq!(workspace.head, before_workspace.head);
    assert_eq!(workspace.base_target, before_workspace.base_target);
    assert_eq!(workspace.base_tree_hash, before_workspace.base_tree_hash);
    assert_eq!(after.metadata().ref_state, before_refs);
    assert_eq!(after.snapshot().changes.len(), before_change_count);
    assert_eq!(after.roots().generation, before_roots.generation + 1);
    drop(after);

    let restored = execute_checkout_request(
        &layout,
        &kin_db::InMemoryGraph::new(),
        &request("selected", None),
    )
    .expect("restore selected subtree from unchanged base");
    assert!(restored.mutated);
    assert_eq!(
        fs::read(repo.join("selected/config.yaml")).unwrap(),
        b"main: true\n"
    );
    assert_eq!(
        fs::read(repo.join("selected/remove.txt")).unwrap(),
        b"main only\n"
    );
    assert_eq!(
        fs::read(repo.join("selected/swap-file")).unwrap(),
        b"main file\n"
    );
    assert_eq!(
        fs::read(repo.join("selected/swap-dir/item.txt")).unwrap(),
        b"main child\n"
    );
    assert!(!repo.join("selected/data.bin").exists());
    assert_eq!(
        fs::read(repo.join("outside.txt")).unwrap(),
        b"outside dirty preserved\n"
    );
}

#[test]
fn same_tree_checkout_repairs_projection_without_graph_churn_and_replays_idempotently() {
    let root = tempdir().unwrap();
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&repo).unwrap();
    run_git(&repo, &["init", "--initial-branch=main"]);
    run_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(&repo, &["config", "user.name", "Kin"]);
    fs::write(repo.join("config.yaml"), b"authority: true\n").unwrap();
    fs::write(repo.join("outside.txt"), b"outside\n").unwrap();
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "base"]);
    let layout = initialize_kin(&repo, &home);
    let (_, manager) = open_authority(&layout);
    let before = manager.read_authority();
    let roots = before.roots().clone();
    let workspace = before.metadata().workspaces[0].clone();
    let operation_count = before.metadata().operation_log.len();
    drop(before);

    fs::write(repo.join("config.yaml"), b"dirty selected\n").unwrap();
    fs::write(repo.join("outside.txt"), b"dirty outside\n").unwrap();
    let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = execute_checkout_request_with_hooks(
            &layout,
            &kin_db::InMemoryGraph::new(),
            &request("config.yaml", None),
            || {},
            || {},
            || panic!("simulated crash before local projection receipt"),
        );
    }));
    assert!(crashed.is_err());
    assert_eq!(
        fs::read(repo.join("config.yaml")).unwrap(),
        b"authority: true\n"
    );
    kin_core::tree::recover_repository_workspace_projection(layout.working_dir())
        .expect("recover projection-only checkout WAL");
    assert_eq!(
        fs::read(repo.join("config.yaml")).unwrap(),
        b"dirty selected\n"
    );
    assert_eq!(
        fs::read(repo.join("outside.txt")).unwrap(),
        b"dirty outside\n"
    );

    let mut checkout = request("config.yaml", None);
    let operation_id = checkout.operation_id;
    let response = execute_checkout_request(&layout, &kin_db::InMemoryGraph::new(), &checkout)
        .expect("projection-only checkout");
    let report = response.report.unwrap();
    assert!(report.projection_only);
    assert!(!report.idempotent);
    assert_eq!(
        fs::read(repo.join("config.yaml")).unwrap(),
        b"authority: true\n"
    );
    assert_eq!(
        fs::read(repo.join("outside.txt")).unwrap(),
        b"dirty outside\n"
    );
    let (_, refreshed_manager) = open_authority(&layout);
    let after = refreshed_manager.read_authority();
    assert_eq!(after.roots(), &roots);
    assert_eq!(after.metadata().workspaces[0], workspace);
    assert_eq!(after.metadata().operation_log.len(), operation_count);
    drop(after);

    fs::write(
        repo.join("config.yaml"),
        b"new edit after completed operation\n",
    )
    .unwrap();
    checkout.operation_id = operation_id;
    let replay = execute_checkout_request(&layout, &kin_db::InMemoryGraph::new(), &checkout)
        .expect("idempotent projection receipt replay");
    assert!(!replay.mutated);
    assert!(replay.report.unwrap().idempotent);
    assert_eq!(
        fs::read(repo.join("config.yaml")).unwrap(),
        b"new edit after completed operation\n"
    );

    let different = CheckoutRequest {
        path: Some("outside.txt".to_string()),
        path_hex: None,
        change_id: None,
        operation_id,
    };
    assert!(
        execute_checkout_request(&layout, &kin_db::InMemoryGraph::new(), &different,)
            .unwrap_err()
            .to_string()
            .contains("different projection request")
    );
}

#[test]
fn committed_deletion_replays_by_operation_id_after_the_path_is_absent() {
    let root = tempdir().unwrap();
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&repo).unwrap();
    run_git(&repo, &["init", "--initial-branch=main"]);
    run_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(&repo, &["config", "user.name", "Kin"]);
    fs::write(repo.join("remove.txt"), b"remove me\n").unwrap();
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "base"]);
    run_git(&repo, &["switch", "-c", "without-file"]);
    fs::remove_file(repo.join("remove.txt")).unwrap();
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "remove file"]);
    run_git(&repo, &["switch", "main"]);

    let layout = initialize_kin(&repo, &home);
    let (_, manager) = open_authority(&layout);
    let target = ref_change(&manager, "without-file");
    let checkout = request("remove.txt", Some(target));
    let first = execute_checkout_request(&layout, &kin_db::InMemoryGraph::new(), &checkout)
        .expect("checkout deletion");
    assert!(first.mutated);
    assert!(!repo.join("remove.txt").exists());

    let replay = execute_checkout_request(&layout, &kin_db::InMemoryGraph::new(), &checkout)
        .expect("replay checkout deletion");
    assert!(!replay.mutated);
    assert!(replay.report.unwrap().idempotent);
    assert!(!repo.join("remove.txt").exists());
}

#[cfg(unix)]
#[test]
fn checkout_gitlink_targets_fail_closed_until_external_authority_admits_them() {
    let root = tempdir().unwrap();
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&repo).unwrap();
    run_git(&repo, &["init", "--initial-branch=main"]);
    run_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(&repo, &["config", "user.name", "Kin"]);
    fs::write(repo.join("base.txt"), b"base\n").unwrap();
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "base"]);
    let first = git_stdout(&repo, &["rev-parse", "HEAD"]);
    run_git(&repo, &["switch", "-c", "gitlink-a"]);
    run_git(
        &repo,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{first},vendor/dependency"),
        ],
    );
    run_git(&repo, &["commit", "-m", "add gitlink"]);
    let second = git_stdout(&repo, &["rev-parse", "HEAD"]);
    run_git(&repo, &["switch", "-c", "gitlink-b"]);
    run_git(
        &repo,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{second},vendor/dependency"),
        ],
    );
    run_git(&repo, &["commit", "-m", "retarget gitlink"]);
    run_git(&repo, &["switch", "main"]);
    let layout = initialize_kin(&repo, &home);
    let (_, manager) = open_authority(&layout);
    let a = ref_change(&manager, "gitlink-a");
    let b = ref_change(&manager, "gitlink-b");
    let dependency = repo.join("vendor/dependency");
    fs::create_dir_all(dependency.join("nested")).unwrap();
    fs::write(dependency.join("nested/owned.bin"), [0_u8, 0xff, 0x44]).unwrap();

    let before = manager.read_authority().roots().clone();
    for change in [a, b] {
        let error = execute_checkout_request(
            &layout,
            &kin_db::InMemoryGraph::new(),
            &request("vendor/dependency", Some(change)),
        )
        .expect_err("unadmitted Gitlink checkout must fail closed");
        assert!(
            format!("{error:#}").contains("without verified Git external authority"),
            "unexpected Gitlink admission error: {error:#}"
        );
        assert_eq!(
            fs::read(dependency.join("nested/owned.bin")).unwrap(),
            [0_u8, 0xff, 0x44]
        );
    }
    let (_, refreshed_manager) = open_authority(&layout);
    let lease = refreshed_manager.read_authority();
    assert_eq!(lease.roots(), &before);
    assert!(lease.metadata().workspaces[0]
        .tree
        .artifacts_by_path()
        .all(|artifact| artifact.path.as_bytes() != b"vendor/dependency"));
}

#[test]
fn selected_checkout_detects_namespace_race_before_mutation() {
    let (root, layout, manager, feature) = simple_feature_fixture();
    let repo = layout.working_dir().to_path_buf();
    let before = manager.read_authority().roots().clone();
    fs::write(repo.join("selected.txt"), b"dirty before race\n").unwrap();
    let result = execute_checkout_request_with_hooks(
        &layout,
        &kin_db::InMemoryGraph::new(),
        &request("selected.txt", Some(feature)),
        || {
            fs::write(repo.join("selected.txt"), b"raced after preflight\n").unwrap();
        },
        || {},
        || {},
    );
    let error = result.unwrap_err();
    assert!(
        format!("{error:#}").contains("changed after"),
        "unexpected namespace-race error: {error:#}"
    );
    assert_eq!(
        fs::read(repo.join("selected.txt")).unwrap(),
        b"raced after preflight\n"
    );
    let (_, refreshed_manager) = open_authority(&layout);
    assert_eq!(refreshed_manager.read_authority().roots(), &before);
    drop(root);
}

#[test]
fn stale_authority_after_projection_rolls_back_selected_dirty_bytes() {
    let (root, layout, manager, feature) = simple_feature_fixture();
    let repo = layout.working_dir().to_path_buf();
    fs::write(repo.join("selected.txt"), b"dirty bytes to restore\n").unwrap();
    let (repository_id, roots, target) = {
        let lease = manager.read_authority();
        let main = RefName::branch(b"main").unwrap();
        let target = lease
            .resolve_ref_target(&main)
            .unwrap()
            .expect("main target");
        (
            lease.metadata().repository_id.clone(),
            lease.roots().clone(),
            target,
        )
    };
    let winner = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: OperationId::new(),
        repository_id,
        expected_generation: roots.generation,
        expected_roots: roots,
        actor: AuthorId::new("checkout-race-winner"),
        reason: "advance authority during checkout projection".to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: vec![RefMutation {
            name: RefName::branch(b"concurrent").unwrap(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(target),
            policy: RefUpdatePolicy::FastForwardOnly,
        }],
        default_ref_mutation: None,
        workspace_mutation: None,
        local_overlay_delta: None,
    };
    let result = execute_checkout_request_with_hooks(
        &layout,
        &kin_db::InMemoryGraph::new(),
        &request("selected.txt", Some(feature)),
        || {},
        || {},
        || {
            manager
                .commit_repository_transaction(winner)
                .expect("commit authority race winner");
        },
    );
    let error = result.expect_err("stale checkout authority must fail");
    assert!(
        format!("{error:#}").contains("generation mismatch"),
        "unexpected authority-race error: {error:#}"
    );
    assert_eq!(
        fs::read(repo.join("selected.txt")).unwrap(),
        b"dirty bytes to restore\n",
        "determinate authority failure did not restore selected dirty bytes"
    );
    let (_, refreshed_manager) = open_authority(&layout);
    let lease = refreshed_manager.read_authority();
    assert!(lease
        .metadata()
        .ref_state
        .refs
        .iter()
        .any(|repository_ref| repository_ref.name == RefName::branch(b"concurrent").unwrap()));
    assert_eq!(
        lease.metadata().workspaces[0]
            .tree
            .artifact_at_path(&kin_model::RepoPath::from_utf8("selected.txt").unwrap())
            .unwrap()
            .entry
            .blob_identity()
            .unwrap(),
        kin_blobs::digest(b"main bytes\n")
    );
    drop(root);
}

fn simple_feature_fixture() -> (
    tempfile::TempDir,
    kin_core::KinLayout,
    RepositoryAuthorityManager<LocalFileBackend>,
    SemanticChangeId,
) {
    let root = tempdir().unwrap();
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&repo).unwrap();
    run_git(&repo, &["init", "--initial-branch=main"]);
    run_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(&repo, &["config", "user.name", "Kin"]);
    fs::write(repo.join("selected.txt"), b"main bytes\n").unwrap();
    fs::write(repo.join("outside.txt"), b"outside\n").unwrap();
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "main"]);
    run_git(&repo, &["switch", "-c", "feature"]);
    fs::write(repo.join("selected.txt"), b"feature bytes\n").unwrap();
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "feature"]);
    run_git(&repo, &["switch", "main"]);
    let layout = initialize_kin(&repo, &home);
    let (_, manager) = open_authority(&layout);
    let feature = ref_change(&manager, "feature");
    (root, layout, manager, feature)
}

#[cfg(target_os = "macos")]
#[test]
fn checkout_path_hex_retains_host_unrepresentable_member_in_graph_only() {
    use std::os::unix::ffi::OsStringExt as _;

    let root = tempdir().unwrap();
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&repo).unwrap();
    run_git(&repo, &["init", "--initial-branch=main"]);
    run_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(&repo, &["config", "user.name", "Kin"]);
    fs::write(repo.join("base.txt"), b"base\n").unwrap();
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "base"]);
    let raw_path = b"assets/icon-\xff.bin".to_vec();
    let body_file = root.path().join("raw-body.bin");
    fs::write(&body_file, b"raw body\n").unwrap();
    let object = git_stdout(
        &repo,
        &[
            "hash-object",
            "-w",
            body_file.to_str().expect("UTF-8 temp path"),
        ],
    );
    run_git(&repo, &["switch", "-c", "raw"]);
    let mut cache = format!("100644,{object},").into_bytes();
    cache.extend_from_slice(&raw_path);
    let output = Command::new("git")
        .args([
            OsString::from("update-index"),
            OsString::from("--add"),
            OsString::from("--cacheinfo"),
            OsString::from_vec(cache),
        ])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .current_dir(&repo)
        .output()
        .unwrap();
    assert!(output.status.success());
    run_git(&repo, &["commit", "-m", "raw path"]);
    run_git(&repo, &["switch", "main"]);
    let layout = initialize_kin(&repo, &home);
    let (_, manager) = open_authority(&layout);
    let target = ref_change(&manager, "raw");
    let request = CheckoutRequest {
        path: None,
        path_hex: Some(hex::encode(&raw_path)),
        change_id: Some(target.to_string()),
        operation_id: OperationId::new(),
    };
    execute_checkout_request(&layout, &kin_db::InMemoryGraph::new(), &request)
        .expect("checkout raw repository path");
    let (_, refreshed_manager) = open_authority(&layout);
    let lease = refreshed_manager.read_authority();
    assert!(lease.metadata().workspaces[0]
        .tree
        .artifacts_by_path()
        .any(|artifact| artifact.path.as_bytes() == raw_path));
    assert!(
        !repo.join("assets").exists(),
        "macOS raw path acquired a lossy projection alias"
    );
}
