// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end proof for daemon-owned repository-v6 semantic merges.

use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::{EntityId, RefName, RefTarget, RepositoryId, SemanticChangeId};
use serde_json::Value;
use std::collections::BTreeMap;
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

/// Identify the entities a resolved state carries, without the derived
/// per-entity provenance that replay owns and is free to restate.
fn entity_identities(
    state: &kin_model::graph::ResolvedGraphState,
) -> BTreeMap<EntityId, (String, Option<String>)> {
    state
        .entities
        .iter()
        .map(|(id, entity)| {
            (
                *id,
                (
                    entity.name.clone(),
                    entity.span.as_ref().map(|span| span.file.to_string()),
                ),
            )
        })
        .collect()
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
    let repo = root.path().join("repo");
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

    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let ours_before = branch_change(&layout, "main");
    let theirs = branch_change(&layout, "feature");
    let generation_before = authority_generation(&layout);

    let merged = run_kin(&runtime, &repo, &["merge", "feature", "--json"]);
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
    let (resolved, ours_state, theirs_state) = {
        use kin_model::ChangeStore;
        (
            graph
                .resolve_graph_at(&merge_change)
                .expect("resolve the merged graph state"),
            graph
                .resolve_graph_at(&ours_before)
                .expect("resolve the active branch parent"),
            graph
                .resolve_graph_at(&theirs)
                .expect("resolve the source branch parent"),
        )
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

    // Entities, not only tree paths. Every guard inside the merge compares the
    // replayed state against itself, so a file-presence check alone stays green
    // on a replay that dropped or invented the semantics a parent published.
    let ours_entities = entity_identities(&ours_state);
    let theirs_entities = entity_identities(&theirs_state);
    let merged_entities = entity_identities(&resolved);
    let mut composed = ours_entities.clone();
    composed.extend(theirs_entities.clone());
    assert_eq!(
        merged_entities, composed,
        "the merged head carries exactly the entities of both parents"
    );
    assert!(
        merged_entities.len() > ours_entities.len()
            && merged_entities.len() > theirs_entities.len(),
        "each parent contributed entities the other lacked: merged={} ours={} theirs={}",
        merged_entities.len(),
        ours_entities.len(),
        theirs_entities.len()
    );
}

/// An ordinary one-sided merge publishes the SIBLING entities of an edited
/// function at the offsets the merged file actually holds them at.
///
/// This is the clean-merge call site of the alignment step, end to end through
/// a real daemon, and it is the most ordinary merge there is: one branch edits
/// one function, the other branch never touches that file.
///
/// The entity composer and the artifact composer decide separately. Enlarging
/// one function moves the byte span of every entity below it, so on the source
/// branch each sibling carries a new span and a new file blob stamp while its
/// own source is untouched. Content agrees, so the sibling never conflicts and
/// never gets a settlement, and composition takes ours, which is base. The
/// artifact composer takes theirs, because ours left the file alone. Without
/// the alignment the merge publishes the PRE-EDIT offsets for every sibling
/// while the tree holds the post-edit bytes, and nothing downstream catches it:
/// the entity delta is empty because content did not move, replay checks only
/// tree equality, and publish installs the stored delta without re-deriving
/// anything.
///
/// Breaking it: drop the `align_unchanged_entities_with_their_artifacts` call
/// in `three_way`, and the published spans are base's.
#[test]
fn merge_of_a_one_sided_edit_publishes_its_siblings_at_the_merged_offsets() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);

    // A file with a function above the ones this test watches, so enlarging the
    // first moves the rest.
    fs::write(
        repo.join("src/lib.rs"),
        b"pub fn alpha() {}\n\npub fn beta() {}\n\npub fn gamma() {}\n",
    )
    .expect("write the shared library");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "add the library"]);

    // The source branch edits ONLY alpha's body.
    run_git(&repo, &["switch", "-c", "feature"]);
    fs::write(
        repo.join("src/lib.rs"),
        b"pub fn alpha() {\n    let a = 1;\n    let b = 2;\n    let _ = a + b;\n}\n\npub fn beta() {}\n\npub fn gamma() {}\n",
    )
    .expect("enlarge alpha on the source branch");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "give alpha a body"]);

    // The active branch never touches that file.
    run_git(&repo, &["switch", "main"]);
    fs::write(repo.join("ours.txt"), b"main ours\n").expect("edit an unrelated file on main");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "main work"]);

    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let ours_before = branch_change(&layout, "main");
    let theirs = branch_change(&layout, "feature");

    let merged = run_kin(&runtime, &repo, &["merge", "feature", "--json"]);
    assert!(
        merged.status.success(),
        "a one-sided edit composes: stdout={} stderr={}",
        String::from_utf8_lossy(&merged.stdout),
        String::from_utf8_lossy(&merged.stderr)
    );
    assert_eq!(merge_report(&merged)["outcome"], "merged");

    let merge_change = branch_change(&layout, "main");
    let reopened = open_authority(&layout);
    let lease = reopened.read_authority();
    let snapshot = lease.snapshot().clone();
    drop(lease);
    let graph = kin_db::InMemoryGraph::from_snapshot(snapshot).expect("replay merged history");
    let (resolved, ours_state, theirs_state) = {
        use kin_model::ChangeStore;
        (
            graph
                .resolve_graph_at(&merge_change)
                .expect("resolve the merged graph state"),
            graph
                .resolve_graph_at(&ours_before)
                .expect("resolve the active branch parent"),
            graph
                .resolve_graph_at(&theirs)
                .expect("resolve the source branch parent"),
        )
    };

    let span_of = |state: &kin_model::graph::ResolvedGraphState, name: &str| {
        state
            .entities
            .values()
            .find(|entity| entity.name == name)
            .and_then(|entity| entity.span.clone())
    };

    // The fixture is the case it claims to be: the edit moved the siblings on
    // the source branch and left them where they were on ours. Without this the
    // assertions below would hold on a merge that published nothing at all.
    let ours_beta = span_of(&ours_state, "beta").expect("ours holds beta");
    let theirs_beta = span_of(&theirs_state, "beta").expect("theirs holds beta");
    assert_ne!(
        ours_beta.start_byte, theirs_beta.start_byte,
        "the edit has to have moved beta, or there is nothing to get wrong"
    );

    for name in ["beta", "gamma"] {
        let published = span_of(&resolved, name).unwrap_or_else(|| panic!("{name} survives"));
        let theirs_span =
            span_of(&theirs_state, name).unwrap_or_else(|| panic!("{name} on theirs"));
        let ours_span = span_of(&ours_state, name).unwrap_or_else(|| panic!("{name} on ours"));
        assert_eq!(
            published.start_byte, theirs_span.start_byte,
            "{name} publishes the offsets of the bytes the merge published, not ours' \
             {} against theirs' {}",
            ours_span.start_byte, theirs_span.start_byte
        );
        assert_eq!(
            published.end_byte, theirs_span.end_byte,
            "{name} end offset"
        );
    }

    // And the bytes really are theirs, so the spans above are describing them.
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).unwrap(),
        b"pub fn alpha() {\n    let a = 1;\n    let b = 2;\n    let _ = a + b;\n}\n\npub fn beta() {}\n\npub fn gamma() {}\n",
    );
}

/// The source branch is already an ancestor: nothing to publish.
#[test]
fn merge_of_an_ancestor_branch_is_already_up_to_date_and_publishes_nothing() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    run_git(&repo, &["branch", "stable"]);
    fs::write(repo.join("ours.txt"), b"main ours\n").expect("edit ours on main");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "main work"]);

    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let main_before = branch_change(&layout, "main");
    let generation_before = authority_generation(&layout);

    let merged = run_kin(&runtime, &repo, &["merge", "stable", "--json"]);
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
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    run_git(&repo, &["switch", "-c", "feature"]);
    fs::write(repo.join("theirs.txt"), b"feature theirs\n").expect("edit theirs on feature");
    fs::write(repo.join("src/feature.rs"), b"pub fn feature() {}\n").expect("add feature source");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "feature work"]);
    run_git(&repo, &["switch", "main"]);

    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let feature = branch_change(&layout, "feature");

    let merged = run_kin(&runtime, &repo, &["merge", "feature", "--json"]);
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

/// Both branches changed the same artifact and the same entity. The merge is
/// parked as a durable transaction while refs and working-copy state remain
/// unchanged.
#[test]
fn conflicting_merge_is_parked_as_a_durable_transaction_and_names_what_conflicted() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
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

    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let main_before = branch_change(&layout, "main");
    let feature_before = branch_change(&layout, "feature");
    let generation_before = authority_generation(&layout);

    let merged = run_kin(&runtime, &repo, &["merge", "feature"]);
    // The code, not merely success: a parked merge and a published one shared
    // an exit status until this was fixed, so `success()` could not tell them
    // apart and this assertion could not see the case it names.
    assert_eq!(
        merged.status.code(),
        Some(kin_cli::commands::merge::EXIT_MERGE_CONFLICTED),
        "a conflicting merge is parked, not refused and not published: stderr={}",
        String::from_utf8_lossy(&merged.stderr)
    );
    let stdout = String::from_utf8_lossy(&merged.stdout);
    assert!(
        stdout.contains("unresolved conflict"),
        "the listing names the conflict set: {stdout}"
    );
    // Each dimension is asserted on its own. An `artifact || entity` check
    // would stay green with the entity detector deleted, because divergent
    // bytes report an artifact conflict for the same file either way.
    assert!(
        stdout.contains("artifact shared.txt"),
        "the listing names the conflicting artifact: {stdout}"
    );
    assert!(
        stdout.contains("entity "),
        "the listing names the conflicting entity: {stdout}"
    );

    // No ref moved and the working copy is untouched. The authority generation
    // does advance, because the parked merge is itself a publication.
    assert_eq!(branch_change(&layout, "main"), main_before);
    assert_eq!(branch_change(&layout, "feature"), feature_before);
    assert!(
        authority_generation(&layout) > generation_before,
        "parking the merge publishes its record"
    );
    assert_eq!(fs::read(repo.join("shared.txt")).unwrap(), b"main shared\n");
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).unwrap(),
        b"pub fn base(value: u64) {}\n"
    );

    assert!(
        !workspace_is_dirty(&layout),
        "a parked merge leaves no partial workspace state"
    );
}

/// Both branches edit one file, in regions that do not overlap. Git merges
/// this cleanly by line. Composition granularity here is the whole artifact,
/// so it conflicts, and the note says so rather than letting a reader infer
/// sub-file composition from "stable identity".
#[test]
fn merge_of_disjoint_edits_to_one_file_is_parked_atomically() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    fs::write(
        repo.join("src/lib.rs"),
        b"pub fn alpha() {}\n\npub fn beta() {}\n",
    )
    .expect("write two functions");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "two functions"]);

    run_git(&repo, &["switch", "-c", "feature"]);
    fs::write(
        repo.join("src/lib.rs"),
        b"pub fn alpha() {}\n\npub fn beta(value: i32) {}\n",
    )
    .expect("edit the second function on feature");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "feature work"]);

    run_git(&repo, &["switch", "main"]);
    fs::write(
        repo.join("src/lib.rs"),
        b"pub fn alpha(value: u64) {}\n\npub fn beta() {}\n",
    )
    .expect("edit the first function on main");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "main work"]);

    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let main_before = branch_change(&layout, "main");
    let feature_before = branch_change(&layout, "feature");
    let generation_before = authority_generation(&layout);

    let merged = run_kin(&runtime, &repo, &["merge", "feature"]);
    // The code, not merely success: a parked merge and a published one shared
    // an exit status until this was fixed, so `success()` could not tell them
    // apart and this assertion could not see the case it names.
    assert_eq!(
        merged.status.code(),
        Some(kin_cli::commands::merge::EXIT_MERGE_CONFLICTED),
        "disjoint edits to one file are parked, not refused and not published: stderr={}",
        String::from_utf8_lossy(&merged.stderr)
    );
    let stdout = String::from_utf8_lossy(&merged.stdout);
    assert!(
        stdout.contains("unresolved conflict"),
        "the listing names the conflict set: {stdout}"
    );
    assert!(
        stdout.contains("artifact src/lib.rs"),
        "the whole artifact is what conflicted, not a line range: {stdout}"
    );

    // No ref moved and the working copy is untouched.
    assert_eq!(branch_change(&layout, "main"), main_before);
    assert_eq!(branch_change(&layout, "feature"), feature_before);
    assert!(
        authority_generation(&layout) > generation_before,
        "parking the merge publishes its record"
    );
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).unwrap(),
        b"pub fn alpha(value: u64) {}\n\npub fn beta() {}\n"
    );
    assert!(
        !workspace_is_dirty(&layout),
        "a parked merge leaves no partial workspace state"
    );
}

/// One branch moves an artifact while the other edits it. Composition decides
/// each identity by whole value and an artifact's path is part of that value,
/// so this is a conflict rather than a move carrying an edit along with it.
#[test]
fn merge_of_a_move_against_an_edit_is_parked_atomically() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);

    run_git(&repo, &["switch", "-c", "feature"]);
    run_git(&repo, &["mv", "src/lib.rs", "src/renamed.rs"]);
    run_git(&repo, &["commit", "-m", "move source on feature"]);

    run_git(&repo, &["switch", "main"]);
    fs::write(repo.join("src/lib.rs"), b"pub fn base(value: u64) {}\n")
        .expect("edit source on main");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "main work"]);

    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let main_before = branch_change(&layout, "main");
    let feature_before = branch_change(&layout, "feature");
    let generation_before = authority_generation(&layout);

    let merged = run_kin(&runtime, &repo, &["merge", "feature"]);
    // The code, not merely success: a parked merge and a published one were the
    // same exit status until this was fixed, so `success()` could not tell them
    // apart and this assertion could not see the case it names.
    assert_eq!(
        merged.status.code(),
        Some(kin_cli::commands::merge::EXIT_MERGE_CONFLICTED),
        "a move against an edit is parked, not refused and not published: stderr={}",
        String::from_utf8_lossy(&merged.stderr)
    );
    let stdout = String::from_utf8_lossy(&merged.stdout);
    assert!(
        stdout.contains("unresolved conflict"),
        "the listing names the conflict set: {stdout}"
    );
    assert!(
        stdout.contains("src/lib.rs"),
        "the listing names the artifact both branches moved apart: {stdout}"
    );

    // No ref moved and the working copy is untouched.
    assert_eq!(branch_change(&layout, "main"), main_before);
    assert_eq!(branch_change(&layout, "feature"), feature_before);
    assert!(
        authority_generation(&layout) > generation_before,
        "parking the merge publishes its record"
    );
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).unwrap(),
        b"pub fn base(value: u64) {}\n"
    );
    assert!(
        !repo.join("src/renamed.rs").exists(),
        "a parked merge does not materialize the source branch's move"
    );
    assert!(
        !workspace_is_dirty(&layout),
        "a parked merge leaves no partial workspace state"
    );
}

/// Merging a branch into itself is a request error, not a no-op.
#[test]
fn merging_the_active_branch_into_itself_is_refused() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let generation_before = authority_generation(&layout);

    let merged = run_kin(&runtime, &repo, &["merge", "main"]);
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
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    let generation_before = authority_generation(&layout);

    let merged = run_kin(&runtime, &repo, &["merge", "no-such-branch"]);
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

/// A workspace no merge has opened on has no merge record. `kin conflicts`
/// says so rather than inventing an empty conflict set, and `kin resolve`
/// refuses rather than settling nothing successfully.
#[test]
fn merge_conflict_commands_report_no_merge_on_a_clean_workspace() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize_kin_repo(&runtime, &repo);

    let listed = run_kin(&runtime, &repo, &["conflicts"]);
    assert!(
        listed.status.success(),
        "listing an unmerged workspace is not an error: stderr={}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(
        stdout.contains("No merge has opened"),
        "the listing says there is no merge: {stdout}"
    );

    let resolved = run_kin(&runtime, &repo, &["resolve", "--all-ours"]);
    assert!(
        !resolved.status.success(),
        "resolving without a merge must fail closed: stdout={}",
        String::from_utf8_lossy(&resolved.stdout)
    );
    assert!(
        String::from_utf8_lossy(&resolved.stderr).contains("no merge transaction"),
        "the refusal names what is missing: {}",
        String::from_utf8_lossy(&resolved.stderr)
    );
}
