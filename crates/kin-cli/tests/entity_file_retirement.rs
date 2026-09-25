// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Retiring a committed entity-owning file, through the real binaries.
//!
//! A stranger in an isolated container deleted a probe file and kept being
//! steered by it: 35 minutes later the graph still reported it as the single
//! file it held and `kin locate` still returned it as the top hit (FIR-2419).
//! A second container found the other half of the same seam: `rm` of a plain
//! file reconciled, `rm` of an entity-owning file did not, and `kin commit`
//! named the constraint outright with "absent from the staged tree"
//! (FIR-2429).
//!
//! The rename half of FIR-2429 is here too, measured before it was written: a
//! byte-identical `mv` of an entity-owning file left the repository unable to
//! accept ANY further commit. The watcher refused the transition fourteen times
//! over 59 seconds and went quiet, `kin locate` kept attributing the entity to
//! a path no longer on disk, and every later `kin commit` answered HTTP 500
//! with "transaction leaves entity ... absent from the staged tree". A control
//! run on the same fixture without the rename committed cleanly and indexed a
//! new symbol, which is what made that difference mean anything.
//!
//! A unit test on the planner cannot cover this, because the defect is in what
//! survives one whole commit and reaches the next query. These drive `kin`
//! itself and read `kin locate`, which is the surface the stale hit was found
//! on.

use serde_json::Value;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tempfile::tempdir;

mod common;

use common::Command;

fn run_git(repo: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .current_dir(repo)
        .output()
        .expect("run git")
}

fn require_git(repo: &Path, args: &[&str]) {
    let output = run_git(repo, args);
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
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_AUTO_EMBED", "0")
        .current_dir(repo)
        .output()
        .expect("run kin")
}

fn require_kin(
    runtime: &common::IsolatedDaemonRuntime,
    repo: &Path,
    args: &[&str],
) -> std::process::Output {
    let output = run_kin(runtime, repo, args);
    assert!(
        output.status.success(),
        "kin {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn initialize(runtime: &common::IsolatedDaemonRuntime, repo: &Path) {
    fs::create_dir_all(repo).expect("create repo");
    require_git(repo, &["init", "--initial-branch=main"]);
    require_git(repo, &["config", "commit.gpgsign", "false"]);
    require_git(repo, &["config", "user.name", "Ada Lovelace"]);
    require_git(repo, &["config", "user.email", "ada@example.com"]);
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    fs::write(repo.join("src/lib.rs"), b"pub fn shipped() -> u8 { 1 }\n").expect("write source");
    fs::write(
        repo.join("notes.txt"),
        b"a plain file that owns no entity\n",
    )
    .expect("write notes");
    require_git(repo, &["add", "--all"]);
    require_git(repo, &["commit", "-m", "first commit"]);

    require_kin(runtime, repo, &["init", ".", "--json"]);
}

/// Every file path `kin locate` attributes a ranked hit to.
fn located_paths(runtime: &common::IsolatedDaemonRuntime, repo: &Path, query: &str) -> Vec<String> {
    let output = require_kin(runtime, repo, &["locate", "--json", query]);
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("kin locate --json should emit JSON");
    let mut paths = report["files"]
        .as_array()
        .map(|files| {
            files
                .iter()
                .filter_map(|file| file["path"].as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    paths.extend(
        report["entities"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|entity| entity["path"].as_str().map(str::to_string)),
    );
    paths
}

/// Deleting a committed entity-owning file and committing that deletion.
///
/// Falsify by removing `record_retired_source_path`'s call site from
/// `plan_exact_transaction`, or by dropping the removal branch out of
/// `evict_enrichment_for_removed_paths`: the commit then fails with "absent
/// from the staged tree" and `kin locate` keeps returning `src/retired.rs`.
#[test]
fn deleting_a_committed_entity_owning_file_retires_it_from_every_query_surface() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);

    fs::write(
        repo.join("src/retired.rs"),
        b"pub fn soon_to_be_retired() -> u8 { 7 }\n",
    )
    .expect("add source");
    require_kin(&runtime, &repo, &["commit", "-m", "publish retired source"]);

    let before = located_paths(&runtime, &repo, "soon_to_be_retired");
    assert!(
        before.iter().any(|path| path == "src/retired.rs"),
        "the fixture never made the file findable, so nothing below proves a retirement: {before:?}"
    );

    fs::remove_file(repo.join("src/retired.rs")).expect("delete the committed source");
    let retired = run_kin(&runtime, &repo, &["commit", "-m", "retire the source"]);
    assert!(
        retired.status.success(),
        "committing a tree with a committed entity-owning file removed must succeed: \
         stdout={} stderr={}",
        String::from_utf8_lossy(&retired.stdout),
        String::from_utf8_lossy(&retired.stderr)
    );

    let after = located_paths(&runtime, &repo, "soon_to_be_retired");
    assert!(
        !after.iter().any(|path| path == "src/retired.rs"),
        "a retired file is still ranked by kin locate: {after:?}"
    );
}

/// The plain-file arm, which already worked and must keep working.
#[test]
fn deleting_a_file_that_owns_no_entity_still_commits() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);

    fs::remove_file(repo.join("notes.txt")).expect("delete the plain file");
    let retired = run_kin(&runtime, &repo, &["commit", "-m", "retire the plain file"]);
    assert!(
        retired.status.success(),
        "deleting a non-entity file must still commit: stdout={} stderr={}",
        String::from_utf8_lossy(&retired.stdout),
        String::from_utf8_lossy(&retired.stderr)
    );
}

/// What `kin refs` prints for an entity, as one string.
///
/// Read as text on purpose: `--bulk-json` needs entity UUIDs the fixture does
/// not hold, and the assertion below is about whether one known caller is still
/// attributed, which the human rendering carries.
fn references_text(runtime: &common::IsolatedDaemonRuntime, repo: &Path, entity: &str) -> String {
    let output = require_kin(runtime, repo, &["refs", entity]);
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Resolve the committed main ref from newly opened repository authority.
/// The manager is never held across a CLI subprocess or a daemon restart.
fn committed_graph(repo: &Path) -> kin_model::graph::ResolvedGraphState {
    let layout = kin_core::KinLayout::discover(repo).unwrap();
    let manifest = kin_core::KinManifest::load(&layout.manifest_path()).unwrap();
    let manager = kin_db::RepositoryAuthorityManager::open(
        kin_model::RepositoryId::new(manifest.repo_id).unwrap(),
        Arc::new(kin_db::LocalFileBackend::new(layout.kindb_dir())),
    )
    .unwrap();
    let lease = manager.read_authority();
    let name = kin_model::RefName::branch(b"main").unwrap();
    let target = &lease
        .metadata()
        .ref_state
        .refs
        .iter()
        .find(|reference| reference.name == name)
        .unwrap()
        .target;
    let change = lease.resolve_target_change_id(target).unwrap();
    let mut snapshot = lease.snapshot().clone();
    snapshot.repository_authority = None;
    drop(lease);
    let graph = kin_db::InMemoryGraph::from_snapshot(snapshot).unwrap();
    kin_db::ChangeStore::resolve_graph_at(&graph, &change).unwrap()
}

fn entity_at(
    graph: &kin_model::graph::ResolvedGraphState,
    path: &str,
    name: &str,
) -> kin_model::Entity {
    let found: Vec<_> = graph
        .entities
        .values()
        .filter(|entity| {
            entity.name == name
                && entity.file_origin.as_ref().map(|file| file.0.as_str()) == Some(path)
        })
        .collect();
    assert_eq!(found.len(), 1, "exactly one {name} at {path}: {found:?}");
    found[0].clone()
}

fn caller_binding_debt(
    graph: &kin_model::graph::ResolvedGraphState,
) -> Option<kin_index::binding_debt::LocalBindingDebt> {
    let file = kin_model::FilePathId::new("src/caller.py");
    let artifact = graph
        .tree
        .artifact_id_at_path(&kin_model::RepoPath::from_utf8(&file.0).unwrap())
        .unwrap();
    let reserved = kin_index::binding_debt::local_binding_debt_id(artifact);
    let mut found = None;
    for relation in graph.relations.values().filter(|relation| {
        relation.id == reserved || relation.src == kin_model::GraphNodeId::Artifact(artifact)
    }) {
        if let Some(debt) =
            kin_index::binding_debt::decode_local_binding_debt(&file, artifact, relation).unwrap()
        {
            assert!(found.replace(debt).is_none(), "one canonical debt record");
        }
    }
    found
}

/// Renaming a committed entity-owning file with a bare `mv`, then committing.
///
/// The move preserves artifact and entity identity, but an unchanged import of
/// the old module is no longer a valid binding. Its exact prior Calls payload
/// must become durable caller-owned debt. Updating the caller's actual import
/// restores a call to the same target identity and settles that obligation.
///
/// The trailing commit is the wedge assertion. Before the fix the repository
/// stopped accepting commits entirely once a rename had been refused, so a test
/// that only checked the rename's own commit would pass on a store that was
/// already dead.
///
/// Falsify by reverting `path_relocations_in`'s use in `exact_tree_admission`
/// so the reconcile seam publishes its tree deltas with an empty
/// `entity_deltas` again, which is the `TreeDelta::Removed`-only shape it had:
/// the rename commit then fails with "absent from the staged tree".
#[test]
fn renaming_a_committed_entity_owning_file_relocates_it_rather_than_stranding_it() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);

    fs::write(
        repo.join("src/moved.py"),
        b"def moved_target():\n    return 1\n",
    )
    .expect("add source");
    fs::write(
        repo.join("src/caller.py"),
        b"from moved import moved_target\n\ndef moved_caller():\n    return moved_target()\n",
    )
    .expect("add caller");
    require_kin(&runtime, &repo, &["commit", "-m", "publish movable source"]);

    let before = located_paths(&runtime, &repo, "moved_target");
    assert!(
        before.iter().any(|path| path == "src/moved.py"),
        "the fixture never made the file findable, so nothing below proves a relocation: \
         {before:?}"
    );
    let references_before = references_text(&runtime, &repo, "moved_target");
    assert!(
        references_before.contains("src/caller.py"),
        "the fixture never produced an incoming edge, so the half a remove-then-add pair \
         destroys is not under test here: {references_before}"
    );
    require_kin(&runtime, &repo, &["daemon", "stop"]);
    let graph_before = committed_graph(&repo);
    let target_before = entity_at(&graph_before, "src/moved.py", "moved_target");
    let caller_before = entity_at(&graph_before, "src/caller.py", "moved_caller");
    let artifact_before = graph_before
        .tree
        .artifact_id_at_path(&kin_model::RepoPath::from_utf8("src/moved.py").unwrap())
        .unwrap();
    let call_before = graph_before
        .relations
        .values()
        .find(|relation| {
            relation.kind == kin_model::RelationKind::Calls
                && relation.src == kin_model::GraphNodeId::Entity(caller_before.id)
                && relation.dst == kin_model::GraphNodeId::Entity(target_before.id)
        })
        .expect("the committed caller has a real local Calls edge")
        .clone();
    assert!(kin_index::RelationResolution::of(&call_before).is_proven());
    let caller_bytes = fs::read(repo.join("src/caller.py")).unwrap();
    assert!(caller_binding_debt(&graph_before).is_none());

    // A bare filesystem move, which is what a person reorganizing a repository
    // does. Nothing tells kin a rename happened.
    fs::rename(repo.join("src/moved.py"), repo.join("src/renamed.py"))
        .expect("rename the committed source");
    let renamed = run_kin(&runtime, &repo, &["commit", "-m", "relocate the source"]);
    assert!(
        renamed.status.success(),
        "committing a tree with an entity-owning file moved must succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&renamed.stdout),
        String::from_utf8_lossy(&renamed.stderr)
    );

    let after = located_paths(&runtime, &repo, "moved_target");
    assert!(
        !after.iter().any(|path| path == "src/moved.py"),
        "a moved file is still ranked at the path it left: {after:?}"
    );
    assert!(
        after.iter().any(|path| path == "src/renamed.py"),
        "the moved entity is not ranked at the path it arrived on: {after:?}"
    );

    let references_after = references_text(&runtime, &repo, "moved_target");
    assert!(
        !references_after.contains("src/caller.py"),
        "an unchanged old-module import must not follow a moved target: {references_after}"
    );
    let graph_after = committed_graph(&repo);
    assert_eq!(
        entity_at(&graph_after, "src/renamed.py", "moved_target").id,
        target_before.id
    );
    assert_eq!(
        entity_at(&graph_after, "src/caller.py", "moved_caller"),
        caller_before
    );
    assert_eq!(
        graph_after
            .tree
            .artifact_id_at_path(&kin_model::RepoPath::from_utf8("src/renamed.py").unwrap()),
        Some(artifact_before),
        "a real relocation preserves artifact identity"
    );
    assert!(!graph_after
        .relations
        .values()
        .any(|relation| { relation.src == call_before.src && relation.dst == call_before.dst }));
    let debt = caller_binding_debt(&graph_after).expect("the old imported binding remains owed");
    assert!(
        debt.obligations.iter().any(|obligation| {
            obligation.retired_relation == call_before
                && obligation.target_artifact == artifact_before
                && obligation.target_file.0 == "src/moved.py"
                && obligation.source_digest
                    == kin_model::Hash256::from_bytes(kin_blobs::digest(&caller_bytes).0)
        }),
        "the exact retired occurrence, target identity and source bytes must survive: {debt:?}"
    );
    assert_eq!(fs::read(repo.join("src/caller.py")).unwrap(), caller_bytes);

    require_kin(&runtime, &repo, &["daemon", "stop"]);
    assert!(!references_text(&runtime, &repo, "moved_target").contains("src/caller.py"));
    let reopened = committed_graph(&repo);
    assert_eq!(caller_binding_debt(&reopened), Some(debt.clone()));
    assert_eq!(
        entity_at(&reopened, "src/renamed.py", "moved_target").id,
        target_before.id
    );

    // The repository still accepts work. This is the half that made the defect
    // a blocker rather than a stale-path annoyance.
    fs::write(
        repo.join("src/later.py"),
        b"def later_symbol():\n    return 2\n",
    )
    .expect("add a later file");
    let later = run_kin(&runtime, &repo, &["commit", "-m", "work after the rename"]);
    assert!(
        later.status.success(),
        "a rename must not leave the repository unable to accept further commits: \
         stdout={} stderr={}",
        String::from_utf8_lossy(&later.stdout),
        String::from_utf8_lossy(&later.stderr)
    );
    let later_paths = located_paths(&runtime, &repo, "later_symbol");
    assert!(
        later_paths.iter().any(|path| path == "src/later.py"),
        "work committed after a rename never reached the graph: {later_paths:?}"
    );
    assert_eq!(caller_binding_debt(&committed_graph(&repo)), Some(debt));

    fs::write(
        repo.join("src/caller.py"),
        b"from renamed import moved_target\n\ndef moved_caller():\n    return moved_target()\n",
    )
    .unwrap();
    require_kin(
        &runtime,
        &repo,
        &["commit", "-m", "repair the caller's module import"],
    );
    let repaired = committed_graph(&repo);
    assert_eq!(
        entity_at(&repaired, "src/renamed.py", "moved_target").id,
        target_before.id
    );
    assert_eq!(
        entity_at(&repaired, "src/caller.py", "moved_caller").id,
        caller_before.id
    );
    assert!(
        repaired.relations.values().any(|relation| {
            relation.kind == kin_model::RelationKind::Calls
                && relation.src == call_before.src
                && relation.dst == call_before.dst
                && kin_index::linker::has_named_import_factory_identity(relation)
                && relation.import_source.is_none()
                && kin_index::occurrence::uniform_original_evidence(relation).is_some_and(
                    |records| {
                        records.len() == 1
                            && records.iter().all(|occurrence| {
                                occurrence.token.as_deref() == Some("moved_target")
                                    && occurrence.source_path.as_deref() == Some("renamed")
                                    && occurrence.resolved_path.as_deref() == Some("src/renamed.py")
                                    && occurrence.occurrence_count == 1
                                    && occurrence.source_span.as_ref().is_some_and(|span| {
                                        span.file.0 == "src/caller.py"
                                            && span.start_byte == 65
                                            && span.end_byte == 79
                                    })
                            })
                    },
                )
                && kin_index::RelationResolution::of(relation).is_proven()
        }),
        "the real source correction must restore the same local target"
    );
    assert!(caller_binding_debt(&repaired).is_none());
    require_kin(&runtime, &repo, &["daemon", "stop"]);
    assert!(references_text(&runtime, &repo, "moved_target").contains("src/caller.py"));
    let repaired_cold = committed_graph(&repo);
    assert_eq!(repaired_cold.entities, repaired.entities);
    assert_eq!(repaired_cold.relations, repaired.relations);
    assert!(caller_binding_debt(&repaired_cold).is_none());
}

/// The in-place edit arm, which must not be read as a relocation.
///
/// A `TreeDelta::Updated` whose path did not change is an edit, and treating it
/// as a move would rewrite `file_origin` to the path it already has. Cheap to
/// hold, and it is the obvious way for the relocation filter to be written
/// wrong.
#[test]
fn editing_a_committed_file_in_place_is_not_treated_as_a_relocation() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);

    fs::write(
        repo.join("src/edited.py"),
        b"def edited_target():\n    return 1\n",
    )
    .expect("add source");
    require_kin(
        &runtime,
        &repo,
        &["commit", "-m", "publish editable source"],
    );
    let before = located_paths(&runtime, &repo, "edited_target");
    assert!(
        before.iter().any(|path| path == "src/edited.py"),
        "the fixture never made the file findable: {before:?}"
    );

    fs::write(
        repo.join("src/edited.py"),
        b"def edited_target():\n    return 2\n",
    )
    .expect("edit source in place");
    let edited = run_kin(&runtime, &repo, &["commit", "-m", "edit in place"]);
    assert!(
        edited.status.success(),
        "an in-place edit must still commit: stdout={} stderr={}",
        String::from_utf8_lossy(&edited.stdout),
        String::from_utf8_lossy(&edited.stderr)
    );

    let after = located_paths(&runtime, &repo, "edited_target");
    assert!(
        after.iter().any(|path| path == "src/edited.py"),
        "an edited file must keep ranking at its own path: {after:?}"
    );
}

/// Moving only the importing caller must preserve the exact named target and
/// rebind site authority to the admitted new path, not merely keep a scalar edge.
#[test]
fn moving_a_caller_preserves_certified_named_import_sites() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);
    fs::write(
        repo.join("src/target.py"),
        b"def stable_target():\n    return 1\n",
    )
    .unwrap();
    fs::write(
        repo.join("src/caller.py"),
        b"from target import stable_target\n\ndef moving_caller():\n    return stable_target()\n",
    )
    .unwrap();
    require_kin(
        &runtime,
        &repo,
        &["commit", "-m", "record importing caller"],
    );
    require_kin(&runtime, &repo, &["daemon", "stop"]);
    let before = committed_graph(&repo);
    let target = entity_at(&before, "src/target.py", "stable_target");
    let caller = entity_at(&before, "src/caller.py", "moving_caller");
    let call = before
        .relations
        .values()
        .find(|row| {
            row.kind == kin_model::RelationKind::Calls
                && row.src == kin_model::GraphNodeId::Entity(caller.id)
                && row.dst == kin_model::GraphNodeId::Entity(target.id)
        })
        .expect("actual named-import call")
        .clone();
    assert!(
        call.evidence
            .iter()
            .any(|record| record.parser_rule.as_deref()
                == Some(kin_index::occurrence::OCCURRENCE_RULE)),
        "this control requires newly generated occurrence metadata"
    );
    let (sites, withheld) = kin_index::occurrence::proven_sites(&call);
    assert!(!withheld);
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].file.0, "src/caller.py");
    fs::rename(repo.join("src/caller.py"), repo.join("src/relocated.py")).unwrap();
    require_kin(&runtime, &repo, &["commit", "-m", "move importing caller"]);
    require_kin(&runtime, &repo, &["daemon", "stop"]);
    let after = committed_graph(&repo);
    assert_eq!(
        entity_at(&after, "src/relocated.py", "moving_caller").id,
        caller.id
    );
    assert_eq!(
        entity_at(&after, "src/target.py", "stable_target").id,
        target.id
    );
    let updated = after
        .relations
        .get(&call.id)
        .expect("same logical call survives move");
    assert_eq!(updated.src, call.src);
    assert_eq!(updated.dst, call.dst);
    assert!(
        kin_index::occurrence::uniform_original_evidence(updated).is_some(),
        "new path metadata remains fully bound to its original evidence"
    );
    let (sites, withheld) = kin_index::occurrence::proven_sites(updated);
    assert!(!withheld, "valid relocated occurrence must remain proven");
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].file.0, "src/relocated.py");
    assert_eq!(sites[0].start_line, 3);
    let refs = references_text(&runtime, &repo, "stable_target");
    assert!(refs.contains("src/relocated.py"), "{refs}");
    assert!(!refs.contains("src/caller.py"), "{refs}");
}
