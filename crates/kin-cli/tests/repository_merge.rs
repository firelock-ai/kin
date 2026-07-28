// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end proof for daemon-owned repository-v6 semantic merges.

use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::{RefName, RefTarget, RepositoryId, SemanticChangeId};
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

fn initialize_git_repo(repo: &Path) {
    fs::create_dir_all(repo).expect("create repo");
    run_git(repo, &["init", "--initial-branch=main"]);
    run_git(repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(repo, &["config", "user.name", "Kin"]);
    fs::write(repo.join("shared.txt"), b"shared bytes\n").expect("write shared file");
    fs::write(repo.join("ours.txt"), b"base ours\n").expect("write ours file");
    fs::write(repo.join("theirs.txt"), b"base theirs\n").expect("write theirs file");
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    fs::write(repo.join("src/lib.rs"), b"pub fn base() {}\n").expect("write base source");
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

fn repository_id(layout: &kin_core::KinLayout) -> RepositoryId {
    let manifest = kin_core::KinManifest::load(&layout.manifest_path()).expect("load Kin manifest");
    RepositoryId::new(manifest.repo_id).expect("valid repository id")
}

/// Every authority read reopens from disk.
///
/// A manager caches the authority it opened, so holding one across a `kin`
/// subprocess would answer from the pre-command snapshot and make an
/// "authority did not move" assertion pass without proving anything.
fn open_authority(layout: &kin_core::KinLayout) -> RepositoryAuthorityManager<LocalFileBackend> {
    RepositoryAuthorityManager::open(
        repository_id(layout),
        Arc::new(LocalFileBackend::new(layout.kindb_dir())),
    )
    .expect("open repository authority")
}

fn branch_change(layout: &kin_core::KinLayout, branch: &str) -> SemanticChangeId {
    let manager = open_authority(layout);
    let lease = manager.read_authority();
    let name = RefName::branch(branch.as_bytes()).expect("valid branch name");
    let target = lease
        .metadata()
        .ref_state
        .refs
        .iter()
        .find(|repository_ref| repository_ref.name == name)
        .unwrap_or_else(|| panic!("branch {branch} exists in repository authority"))
        .target
        .clone();
    let change = lease
        .resolve_target_change_id(&target)
        .expect("resolve branch target to an exact change");
    drop(lease);
    change
}

fn authority_generation(layout: &kin_core::KinLayout) -> u64 {
    let manager = open_authority(layout);
    let lease = manager.read_authority();
    let generation = lease.roots().generation;
    drop(lease);
    generation
}

fn workspace_is_dirty(layout: &kin_core::KinLayout) -> bool {
    let manager = open_authority(layout);
    let lease = manager.read_authority();
    let dirty = lease
        .metadata()
        .workspaces
        .first()
        .expect("the repository has a local workspace")
        .is_dirty();
    drop(lease);
    dirty
}

fn json_id<T: serde::Serialize>(id: &T) -> Value {
    serde_json::to_value(id).expect("serialize a repository identity")
}

fn merge_report(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "merge report is not JSON ({error}): stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// Both branches move, on disjoint artifacts and entities. The merge composes
/// them and publishes one merge change joining both heads.
#[test]
fn merge_composes_disjoint_semantic_and_tree_work_into_one_merge_change() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    initialize_git_repo(&repo);

    run_git(&repo, &["switch", "-c", "feature"]);
    fs::write(repo.join("theirs.txt"), b"feature theirs\n").expect("edit theirs on feature");
    fs::write(repo.join("only-feature.bin"), [0_u8, 0xff, 0x10]).expect("add feature binary");
    fs::write(repo.join("src/feature.rs"), b"pub fn feature() {}\n").expect("add feature source");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "feature work"]);

    run_git(&repo, &["switch", "main"]);
    fs::write(repo.join("ours.txt"), b"main ours\n").expect("edit ours on main");
    fs::write(repo.join("src/mainline.rs"), b"pub fn mainline() {}\n").expect("add main source");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "main work"]);

    let layout = initialize_kin_repo(&repo, &home);
    let ours_before = branch_change(&layout, "main");
    let theirs = branch_change(&layout, "feature");
    let generation_before = authority_generation(&layout);

    let merged = run_kin(&repo, &home, &["merge", "feature", "--json"]);
    assert!(
        merged.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&merged.stdout),
        String::from_utf8_lossy(&merged.stderr)
    );
    let report = merge_report(&merged);
    assert_eq!(report["schema"], "kin.merge.v1");
    assert_eq!(report["outcome"], "merged");
    assert_eq!(report["ours_change"], json_id(&ours_before));
    assert_eq!(report["theirs_change"], json_id(&theirs));
    assert_ne!(report["base_change"], report["ours_change"]);
    assert_ne!(report["base_change"], report["theirs_change"]);
    let reported_merge_change = report["merge_change"].clone();
    assert!(
        !reported_merge_change.is_null(),
        "a published merge names its change"
    );

    // Both sides of the working copy, composed.
    assert_eq!(
        fs::read(repo.join("shared.txt")).unwrap(),
        b"shared bytes\n"
    );
    assert_eq!(fs::read(repo.join("ours.txt")).unwrap(), b"main ours\n");
    assert_eq!(
        fs::read(repo.join("theirs.txt")).unwrap(),
        b"feature theirs\n"
    );
    assert_eq!(
        fs::read(repo.join("only-feature.bin")).unwrap(),
        [0_u8, 0xff, 0x10]
    );
    assert_eq!(
        fs::read(repo.join("src/feature.rs")).unwrap(),
        b"pub fn feature() {}\n"
    );
    assert_eq!(
        fs::read(repo.join("src/mainline.rs")).unwrap(),
        b"pub fn mainline() {}\n"
    );

    // Reopening replays the merge from persisted authority alone.
    let merge_change = branch_change(&layout, "main");
    assert_eq!(json_id(&merge_change), reported_merge_change);
    assert_eq!(
        branch_change(&layout, "feature"),
        theirs,
        "merging must not move the source branch"
    );
    assert!(authority_generation(&layout) > generation_before);

    let reopened = open_authority(&layout);
    let lease = reopened.read_authority();
    let workspace = lease.metadata().workspaces.first().unwrap();
    assert_eq!(
        workspace.base_target,
        Some(RefTarget::change(merge_change)),
        "the workspace tracks the published merge"
    );
    assert_eq!(workspace.base_tree_hash, Some(workspace.tree_hash));
    assert!(
        !workspace.is_dirty(),
        "a published merge leaves no uncommitted workspace state"
    );
    let snapshot = lease.snapshot().clone();
    drop(lease);

    let change = snapshot
        .changes
        .get(&merge_change)
        .expect("the merge change is persisted in history");
    assert_eq!(
        change.parents,
        vec![ours_before, theirs],
        "the active branch is the first parent and the source branch the second"
    );
    assert!(
        !change.tree_deltas.is_empty(),
        "the merge restates the source branch's tree transition against its first parent"
    );

    // The graph replays the merge without a stale-payload refusal, and the
    // replayed state is the composed one.
    let graph = kin_db::InMemoryGraph::from_snapshot(snapshot).expect("replay merged history");
    let resolved = {
        use kin_model::ChangeStore;
        graph
            .resolve_graph_at(&merge_change)
            .expect("resolve the merged graph state")
    };
    for path in [
        "shared.txt",
        "ours.txt",
        "theirs.txt",
        "only-feature.bin",
        "src/lib.rs",
        "src/feature.rs",
        "src/mainline.rs",
    ] {
        let repo_path = kin_model::RepoPath::from_utf8(path).expect("valid repository path");
        assert!(
            resolved.tree.artifact_at_path(&repo_path).is_some(),
            "merged tree keeps {path}"
        );
    }
}

/// The source branch is already an ancestor: nothing to publish.
#[test]
fn merge_of_an_ancestor_branch_is_already_up_to_date_and_publishes_nothing() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    initialize_git_repo(&repo);
    run_git(&repo, &["branch", "stable"]);
    fs::write(repo.join("ours.txt"), b"main ours\n").expect("edit ours on main");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "main work"]);

    let layout = initialize_kin_repo(&repo, &home);
    let main_before = branch_change(&layout, "main");
    let generation_before = authority_generation(&layout);

    let merged = run_kin(&repo, &home, &["merge", "stable", "--json"]);
    assert!(
        merged.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&merged.stdout),
        String::from_utf8_lossy(&merged.stderr)
    );
    assert_eq!(merge_report(&merged)["outcome"], "already_up_to_date");
    assert_eq!(branch_change(&layout, "main"), main_before);
    assert_eq!(authority_generation(&layout), generation_before);
}

/// The active branch is an ancestor: advance it, publish no merge change.
#[test]
fn merge_of_a_descendant_branch_fast_forwards_the_active_branch() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    initialize_git_repo(&repo);
    run_git(&repo, &["switch", "-c", "feature"]);
    fs::write(repo.join("theirs.txt"), b"feature theirs\n").expect("edit theirs on feature");
    fs::write(repo.join("src/feature.rs"), b"pub fn feature() {}\n").expect("add feature source");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "feature work"]);
    run_git(&repo, &["switch", "main"]);

    let layout = initialize_kin_repo(&repo, &home);
    let feature = branch_change(&layout, "feature");

    let merged = run_kin(&repo, &home, &["merge", "feature", "--json"]);
    assert!(
        merged.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&merged.stdout),
        String::from_utf8_lossy(&merged.stderr)
    );
    let report = merge_report(&merged);
    assert_eq!(report["outcome"], "fast_forward");
    assert!(
        report["merge_change"].is_null(),
        "a fast-forward publishes no merge change"
    );
    assert_eq!(branch_change(&layout, "main"), feature);
    assert_eq!(
        fs::read(repo.join("theirs.txt")).unwrap(),
        b"feature theirs\n"
    );
    assert_eq!(
        fs::read(repo.join("src/feature.rs")).unwrap(),
        b"pub fn feature() {}\n"
    );
}

/// Both branches changed the same artifact and the same entity. There is no
/// durable merge transaction to park the conflict in, so the whole merge is
/// refused and nothing is published.
#[test]
fn conflicting_merge_is_refused_atomically_and_names_every_conflict() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    initialize_git_repo(&repo);

    run_git(&repo, &["switch", "-c", "feature"]);
    fs::write(repo.join("shared.txt"), b"feature shared\n").expect("edit shared on feature");
    fs::write(repo.join("src/lib.rs"), b"pub fn base(value: i32) {}\n")
        .expect("edit source on feature");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "feature work"]);

    run_git(&repo, &["switch", "main"]);
    fs::write(repo.join("shared.txt"), b"main shared\n").expect("edit shared on main");
    fs::write(repo.join("src/lib.rs"), b"pub fn base(value: u64) {}\n")
        .expect("edit source on main");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "main work"]);

    let layout = initialize_kin_repo(&repo, &home);
    let main_before = branch_change(&layout, "main");
    let feature_before = branch_change(&layout, "feature");
    let generation_before = authority_generation(&layout);

    let merged = run_kin(&repo, &home, &["merge", "feature"]);
    assert!(
        !merged.status.success(),
        "a conflicting merge must fail closed: stdout={}",
        String::from_utf8_lossy(&merged.stdout)
    );
    let stderr = String::from_utf8_lossy(&merged.stderr);
    assert!(
        stderr.contains("unresolved conflict"),
        "the refusal names the conflict set: {stderr}"
    );
    assert!(
        stderr.contains("artifact") || stderr.contains("entity"),
        "the refusal names what conflicted: {stderr}"
    );

    // Nothing moved: refs, authority generation, and the working copy.
    assert_eq!(branch_change(&layout, "main"), main_before);
    assert_eq!(branch_change(&layout, "feature"), feature_before);
    assert_eq!(authority_generation(&layout), generation_before);
    assert_eq!(fs::read(repo.join("shared.txt")).unwrap(), b"main shared\n");
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).unwrap(),
        b"pub fn base(value: u64) {}\n"
    );

    assert!(
        !workspace_is_dirty(&layout),
        "a refused merge leaves no partial workspace state"
    );
}

/// Merging a branch into itself is a request error, not a no-op.
#[test]
fn merging_the_active_branch_into_itself_is_refused() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    initialize_git_repo(&repo);
    let layout = initialize_kin_repo(&repo, &home);
    let generation_before = authority_generation(&layout);

    let merged = run_kin(&repo, &home, &["merge", "main"]);
    assert!(
        !merged.status.success(),
        "stdout={}",
        String::from_utf8_lossy(&merged.stdout)
    );
    assert!(
        String::from_utf8_lossy(&merged.stderr).contains("into itself"),
        "stderr={}",
        String::from_utf8_lossy(&merged.stderr)
    );
    assert_eq!(authority_generation(&layout), generation_before);
}

/// A branch that does not exist must not be answered from Git or the host.
#[test]
fn merging_an_unknown_branch_is_refused_without_mutation() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    initialize_git_repo(&repo);
    let layout = initialize_kin_repo(&repo, &home);
    let generation_before = authority_generation(&layout);

    let merged = run_kin(&repo, &home, &["merge", "no-such-branch"]);
    assert!(
        !merged.status.success(),
        "stdout={}",
        String::from_utf8_lossy(&merged.stdout)
    );
    assert!(
        String::from_utf8_lossy(&merged.stderr).contains("does not exist"),
        "stderr={}",
        String::from_utf8_lossy(&merged.stderr)
    );
    assert_eq!(authority_generation(&layout), generation_before);
}

/// `kin conflicts` and `kin resolve` stay fail-closed: there is no durable
/// merge transaction for them to read or settle.
#[test]
fn merge_conflict_commands_remain_fail_closed() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    initialize_git_repo(&repo);
    initialize_kin_repo(&repo, &home);

    for args in [vec!["conflicts"], vec!["resolve", "--all-ours"]] {
        let output = run_kin(&repo, &home, &args);
        assert!(
            !output.status.success(),
            "{args:?} must stay fail-closed: stdout={}",
            String::from_utf8_lossy(&output.stdout)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("fail-closed"),
            "{args:?} names its gate: {stderr}"
        );
    }
}
