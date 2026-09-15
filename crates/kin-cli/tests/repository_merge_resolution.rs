// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end proof that a parked repository-v6 merge is durable, readable,
//! and resolvable through the sealed repository transaction path.
//!
//! Every assertion here is made against repository authority reopened from
//! disk, or against the CLI's own report. Nothing asserts against a manager
//! held across a subprocess, which would answer from the pre-command snapshot
//! and pass without proving the record was persisted at all.

use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::{RefName, RepositoryId, SemanticChangeId};
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

/// `kin`, with the LSP enrichment sweep off for the daemon this call spawns.
///
/// The Python fixture's `kin init` fails on a loaded host, and the product's own
/// record names both the cause and the remedy: "The daemon for this store was
/// killed ... start a daemon yourself with the enrichment sweep off
/// (`KIN_DAEMON_DISABLE_LSP=1 kin graph status`)". `kin init` then exits
/// `EXIT_ENRICHMENT_UNATTESTED`, which is 7, so every assertion after it reads
/// as a merge failure. Measured on this suite: six of six runs of the Python
/// fixture hit it while the Rust fixtures hit it zero times, because Rust has no
/// language server installed here to sweep with.
///
/// Turning the sweep off is not papering over that. This test asserts entity
/// values, artifact bytes and tree deltas, and enrichment contributes none of
/// them: it adds cross-file reference and import EDGES, which nothing here
/// reads. A daemon captures the lever at process start from the command that
/// spawns it, so it goes on the call that starts the daemon.
fn run_kin_without_enrichment(
    runtime: &common::IsolatedDaemonRuntime,
    repo: &Path,
    args: &[&str],
) -> std::process::Output {
    runtime
        .kin_command()
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_EMBED_BACKEND", "cpu")
        .current_dir(repo)
        .output()
        .expect("run kin")
}

/// A merge that parked its conflicts rather than publishing.
///
/// Stronger than the `status.success()` this replaced, which could not tell a
/// parked merge from a published one: that is the defect the exit code fixes,
/// and asserting the code here is what keeps these tests able to see it.
fn parked_merge(output: &std::process::Output, what: &str) -> String {
    assert_eq!(
        output.status.code(),
        Some(kin_cli::commands::merge::EXIT_MERGE_CONFLICTED),
        "{what} did not park: status={:?} stdout={} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn ok(output: &std::process::Output, what: &str) -> String {
    assert!(
        output.status.success(),
        "{what} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn initialize_git_repo(repo: &Path) {
    fs::create_dir_all(repo).expect("create repo");
    run_git(repo, &["init", "--initial-branch=main"]);
    run_git(repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(repo, &["config", "user.name", "Kin"]);
    fs::write(repo.join("shared.txt"), b"shared bytes\n").expect("write shared file");
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
    ok(&init, "kin init");
    kin_core::KinLayout::discover(repo).expect("discover exact layout")
}

fn repository_id(layout: &kin_core::KinLayout) -> RepositoryId {
    let manifest = kin_core::KinManifest::load(&layout.manifest_path()).expect("load Kin manifest");
    RepositoryId::new(manifest.repo_id).expect("valid repository id")
}

/// Every authority read reopens from disk, so an assertion about what was
/// persisted is answered by what is on disk.
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

/// The merge record as repository authority holds it, read straight from disk
/// rather than through the daemon, so a listing that agreed with the daemon but
/// not with authority would still be caught.
fn persisted_record(layout: &kin_core::KinLayout) -> Option<kin_model::MergeTransactionRecord> {
    let manager = open_authority(layout);
    let lease = manager.read_authority();
    let record = lease.metadata().merge_transactions.first().cloned();
    drop(lease);
    record
}

/// Advance the workspace through the same transaction shape the language-server
/// enrichment worker uses: semantic authority moves while the workspace tree
/// does not. This is the counter-move arm the one-file CLI fixture cannot make
/// its real enrichment sweep produce on demand.
fn publish_non_user_semantic_move(
    layout: &kin_core::KinLayout,
) -> (
    kin_model::WorkspaceState,
    kin_model::WorkspaceState,
    kin_model::RelationId,
) {
    let manager = open_authority(layout);
    let lease = manager.read_authority();
    let roots = lease.roots().clone();
    let before = lease
        .metadata()
        .workspaces
        .first()
        .expect("the converted repository has one workspace")
        .clone();
    let graph = lease
        .workspace_graph_snapshot(&before.workspace_id)
        .expect("resolve the workspace graph")
        .expect("the workspace graph exists");
    let mut entity_ids = graph
        .entities
        .values()
        .map(|entity| entity.id)
        .collect::<Vec<_>>();
    entity_ids.sort();
    assert!(
        entity_ids.len() >= 2,
        "the non-user semantic producer needs two real entity endpoints, got {}",
        entity_ids.len()
    );
    let relation = kin_model::Relation {
        id: kin_model::RelationId::new(),
        kind: kin_model::RelationKind::Calls,
        src: kin_model::GraphNodeId::Entity(entity_ids[0]),
        dst: kin_model::GraphNodeId::Entity(entity_ids[1]),
        confidence: 1.0,
        origin: kin_model::RelationOrigin::Lsp,
        created_in: None,
        import_source: None,
        evidence: Vec::new(),
    };
    let semantic_delta = kin_model::WorkspaceSemanticDelta::new(
        Vec::new(),
        vec![kin_model::RelationDelta::Added {
            new: relation.clone(),
        }],
    )
    .expect("one LSP relation is a valid semantic transition");
    let transaction = kin_model::RepositoryTransaction {
        schema_version: kin_model::REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: kin_model::OperationId::new(),
        repository_id: repository_id(layout),
        expected_generation: roots.generation,
        expected_roots: roots,
        actor: kin_model::AuthorId::new("kin-lsp-test-producer"),
        reason: "publish a non-user semantic move while a merge is parked".to_string(),
        external_objects: Vec::new(),
        changes: Vec::new(),
        aliases: Vec::new(),
        git_authority_delta: None,
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: Some(kin_model::WorkspaceMutation {
            workspace_id: before.workspace_id,
            expected: kin_model::WorkspaceExpectation::MustEqual {
                generation: before.generation,
                head: before.head.clone(),
                base_target: before.base_target.clone(),
                base_tree_hash: before.base_tree_hash,
                tree_hash: before.tree_hash,
                semantic_overlay_hash: before.semantic_overlay_hash,
                admission_policy: before.admission_policy,
            },
            new_generation: before.generation + 1,
            new_head: before.head.clone(),
            new_base_target: before.base_target.clone(),
            new_base_tree_hash: before.base_tree_hash,
            tree_deltas: Vec::new(),
            new_tree_hash: before.tree_hash,
            semantic_delta,
            new_shared_admission_policy: before.shared_admission_policy.clone(),
            new_admission_policy: before.admission_policy,
        }),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: None,
    };
    drop(lease);
    manager
        .commit_repository_transaction(transaction)
        .expect("the non-user semantic producer advances authority");

    let lease = manager.read_authority();
    let after = lease
        .metadata()
        .workspaces
        .first()
        .expect("the workspace survives the semantic move")
        .clone();
    let after_graph = lease
        .workspace_graph_snapshot(&after.workspace_id)
        .expect("resolve the advanced workspace graph")
        .expect("the advanced workspace graph exists");
    assert!(
        after_graph.relations.contains_key(&relation.id),
        "the counter moved because a real non-user relation was published"
    );
    assert_eq!(
        after.generation,
        before.generation + 1,
        "the non-user producer advances the workspace generation exactly once"
    );
    assert_eq!(
        after.tree_hash, before.tree_hash,
        "semantic enrichment must not move the workspace tree"
    );
    assert_ne!(
        after.semantic_overlay_hash, before.semantic_overlay_hash,
        "the generation move must carry real semantic work rather than be a no-op fixture"
    );
    drop(lease);
    (before, after, relation.id)
}

fn change_parents(
    layout: &kin_core::KinLayout,
    change: &SemanticChangeId,
) -> Vec<SemanticChangeId> {
    let manager = open_authority(layout);
    let lease = manager.read_authority();
    let graph = kin_db::InMemoryGraph::from_snapshot(lease.snapshot().clone())
        .expect("prepare graph-owned history");
    drop(lease);
    let found = kin_db::ChangeStore::get_change(&graph, change)
        .expect("read the change store")
        .expect("the published merge change exists in history");
    found.parents
}

/// How many tree deltas a published change carries against its first parent.
///
/// Zero is the exact signature the rc062a stranger recorded: `tree=0` means the
/// merged tree is byte-identical to the target branch, so the source branch
/// contributed nothing while every conflict read as settled.
fn change_tree_delta_count(layout: &kin_core::KinLayout, change: &SemanticChangeId) -> usize {
    let manager = open_authority(layout);
    let lease = manager.read_authority();
    let graph = kin_db::InMemoryGraph::from_snapshot(lease.snapshot().clone())
        .expect("prepare graph-owned history");
    drop(lease);
    kin_db::ChangeStore::get_change(&graph, change)
        .expect("read the change store")
        .expect("the published merge change exists in history")
        .tree_deltas
        .len()
}

fn conflicts_report(runtime: &common::IsolatedDaemonRuntime, repo: &Path) -> Value {
    let output = run_kin(runtime, repo, &["conflicts", "--json"]);
    let stdout = ok(&output, "kin conflicts --json");
    serde_json::from_str(&stdout).expect("conflicts report is JSON")
}

fn record_hash(report: &Value) -> String {
    report["record_hash"]
        .as_str()
        .expect("a listed merge carries its record identity")
        .to_string()
}

fn stop_daemon(runtime: &common::IsolatedDaemonRuntime, repo: &Path) {
    ok(
        &run_kin(runtime, repo, &["daemon", "stop"]),
        "kin daemon stop",
    );
}

/// Both branches edit one shared artifact and one shared entity, so the merge
/// has exactly the conflicts every test here settles.
fn conflicting_repository(root: &Path) -> std::path::PathBuf {
    let repo = root.join("repo");
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
    repo
}

/// Both branches add a different file at one path. Artifact identity is seeded
/// on the commit that introduced the artifact, so each branch allocates its
/// own, both survive composition, and the merge parks on a contested path whose
/// only settlement is naming one claimant.
fn path_colliding_repository(root: &Path) -> std::path::PathBuf {
    let repo = root.join("repo");
    initialize_git_repo(&repo);

    run_git(&repo, &["switch", "-c", "feature"]);
    fs::create_dir_all(repo.join("docs")).expect("create docs directory on feature");
    fs::write(repo.join("docs/notes.md"), b"feature notes\n").expect("add notes on feature");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "feature notes"]);

    run_git(&repo, &["switch", "main"]);
    fs::create_dir_all(repo.join("docs")).expect("create docs directory on main");
    fs::write(repo.join("docs/notes.md"), b"main notes\n").expect("add notes on main");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "main notes"]);
    repo
}

/// Two branches touching disjoint files, so the merge composes cleanly and
/// publishes rather than parking.
fn disjoint_repository(root: &Path) -> std::path::PathBuf {
    let repo = root.join("repo");
    initialize_git_repo(&repo);

    run_git(&repo, &["switch", "-c", "feature"]);
    fs::write(repo.join("src/feature.rs"), b"pub fn feature() {}\n")
        .expect("add a feature source file");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "feature work"]);

    run_git(&repo, &["switch", "main"]);
    fs::write(repo.join("src/trunk.rs"), b"pub fn trunk() {}\n").expect("add a trunk source file");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "main work"]);
    repo
}

/// Every artifact identity claiming one path in the graph a change resolves to.
fn artifacts_at_path(
    layout: &kin_core::KinLayout,
    change: &SemanticChangeId,
    path: &str,
) -> Vec<String> {
    let manager = open_authority(layout);
    let lease = manager.read_authority();
    let mut snapshot = lease.snapshot().clone();
    snapshot.repository_authority = None;
    drop(lease);
    let graph =
        kin_db::InMemoryGraph::from_snapshot(snapshot).expect("prepare graph-owned history");
    let state = kin_db::ChangeStore::resolve_graph_at(&graph, change)
        .expect("resolve the exact graph a change publishes");
    state
        .tree
        .artifacts()
        .filter(|artifact| artifact.path.to_string() == path)
        .map(|artifact| artifact.artifact_id.0.to_string())
        .collect()
}

/// A parked merge is graph truth, not process state. Stopping the daemon and
/// reading again must return the identical record: same identity, same
/// conflicts, still in progress.
#[test]
fn a_parked_merge_survives_a_daemon_restart() {
    let root = tempdir().expect("temp root");
    let repo = conflicting_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);

    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );
    let before = conflicts_report(&runtime, &repo);
    let before_hash = record_hash(&before);
    assert!(
        before["unresolved_count"].as_u64().expect("a count") >= 2,
        "both the artifact and the entity conflicted: {before}"
    );
    assert_eq!(before["record"]["state"]["state"], "in_progress");

    // The record is authority, so it is on disk before any restart.
    let persisted = persisted_record(&layout).expect("the parked merge is persisted");
    assert_eq!(hex::encode(persisted.hash.as_bytes()), before_hash);

    stop_daemon(&runtime, &repo);

    let after = conflicts_report(&runtime, &repo);
    assert_eq!(
        record_hash(&after),
        before_hash,
        "a restart must not change the merge record"
    );
    assert_eq!(after["record"], before["record"]);
    assert_eq!(after["record"]["state"]["state"], "in_progress");
}

/// A session that decided against one view of the record cannot settle against
/// a newer one. The second resolution names the identity it expected and the
/// identity the record actually has.
#[test]
fn resolving_against_a_stale_record_identity_is_refused() {
    let root = tempdir().expect("temp root");
    let repo = conflicting_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );

    let stale = record_hash(&conflicts_report(&runtime, &repo));
    ok(
        &run_kin(
            &runtime,
            &repo,
            &["resolve", "--all-ours", "--expect", &stale],
        ),
        "first resolution",
    );
    let current = record_hash(&conflicts_report(&runtime, &repo));
    assert_ne!(current, stale, "settling entries advances the record");

    let refused = run_kin(
        &runtime,
        &repo,
        &["resolve", "--all-theirs", "--expect", &stale],
    );
    assert!(
        !refused.status.success(),
        "a stale view must not settle: stdout={}",
        String::from_utf8_lossy(&refused.stdout)
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains(&stale) && stderr.contains(&current),
        "the refusal names the view held and the view current: {stderr}"
    );

    // The refused resolution changed nothing.
    assert_eq!(record_hash(&conflicts_report(&runtime, &repo)), current);
    let persisted = persisted_record(&layout).expect("the merge is still parked");
    assert_eq!(hex::encode(persisted.hash.as_bytes()), current);
}

/// Two sessions settling from one view of the record: exactly one wins. The
/// loser is refused rather than silently rebased onto the winner's record.
#[test]
fn concurrent_resolutions_from_one_view_leave_one_winner() {
    let root = tempdir().expect("temp root");
    let repo = conflicting_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );

    let view = record_hash(&conflicts_report(&runtime, &repo));
    let first = std::thread::scope(|scope| {
        let ours = scope.spawn(|| {
            run_kin(
                &runtime,
                &repo,
                &["resolve", "--all-ours", "--expect", &view],
            )
        });
        let theirs = scope.spawn(|| {
            run_kin(
                &runtime,
                &repo,
                &["resolve", "--all-theirs", "--expect", &view],
            )
        });
        (ours.join().expect("ours"), theirs.join().expect("theirs"))
    });
    let winners = [&first.0, &first.1]
        .iter()
        .filter(|output| output.status.success())
        .count();
    assert_eq!(
        winners,
        1,
        "exactly one resolution settles from one view: ours={} / {}, theirs={} / {}",
        String::from_utf8_lossy(&first.0.stdout),
        String::from_utf8_lossy(&first.0.stderr),
        String::from_utf8_lossy(&first.1.stdout),
        String::from_utf8_lossy(&first.1.stderr)
    );

    // The record advanced exactly once, and both entries carry one side.
    let record = persisted_record(&layout).expect("the merge is still parked");
    let current = hex::encode(record.hash.as_bytes());
    assert_ne!(current, view);
    let loser = [&first.0, &first.1]
        .into_iter()
        .find(|output| !output.status.success())
        .expect("one concurrent resolution loses");
    let loser_stderr = String::from_utf8_lossy(&loser.stderr);
    assert!(
        loser_stderr.contains(&view) && loser_stderr.contains(&current),
        "the losing resolution must be a stale-record refusal, not a transport failure: \
         {loser_stderr}"
    );
    assert!(
        record.is_fully_resolved(),
        "the winning resolution settled every entry"
    );
    // One side won outright: a record carrying a mix would mean both
    // resolutions landed against one view.
    let sides: std::collections::BTreeSet<String> = record
        .entries
        .iter()
        .map(|entry| match &entry.resolution {
            kin_model::MergeEntryResolution::Side { side, .. } => format!("{side:?}"),
            other => format!("{other:?}"),
        })
        .collect();
    assert_eq!(
        sides.len(),
        1,
        "one resolution settled every entry, not a mix of both: {sides:?}"
    );
}

/// Completing a resolved merge publishes one merge change whose ordered parents
/// are the recorded first parent then the source head, advances only the target
/// ref, and terminates the record as committed.
#[test]
fn a_resolved_merge_publishes_ordered_parents_and_advances_only_the_target_ref() {
    let root = tempdir().expect("temp root");
    let repo = conflicting_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);

    let main_before = branch_change(&layout, "main");
    let feature_before = branch_change(&layout, "feature");
    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );

    let parked = persisted_record(&layout).expect("the merge is parked");
    assert_eq!(parked.binding.ours_change, main_before);
    assert_eq!(parked.binding.theirs_change, feature_before);

    ok(
        &run_kin(&runtime, &repo, &["resolve", "--all-theirs"]),
        "settle every conflict",
    );
    let completed = run_kin(&runtime, &repo, &["resolve", "--continue", "--json"]);
    let stdout = ok(&completed, "kin resolve --continue");
    let report: Value = serde_json::from_str(&stdout).expect("resolve report is JSON");
    assert_eq!(report["record"]["state"]["state"], "committed");
    assert_eq!(report["unresolved_count"], 0);
    let merge_change: SemanticChangeId =
        serde_json::from_value(report["merge_change"].clone()).expect("a published merge change");

    // Ordered parents, active branch first, which is what history replay
    // validates.
    assert_eq!(
        change_parents(&layout, &merge_change),
        vec![main_before, feature_before]
    );

    // Only the target ref moved.
    assert_eq!(branch_change(&layout, "main"), merge_change);
    assert_eq!(branch_change(&layout, "feature"), feature_before);

    // The record terminated, and terminated once.
    let record = persisted_record(&layout).expect("the record is retained as the merge's account");
    assert!(record.state.is_terminal());
    let again = run_kin(&runtime, &repo, &["resolve", "--continue"]);
    assert!(
        !again.status.success(),
        "a terminated merge does not publish twice: stdout={}",
        String::from_utf8_lossy(&again.stdout)
    );

    // The workspace projection is derived from the merged graph authority: the
    // side that was taken is what is on disk.
    assert_eq!(
        fs::read(repo.join("shared.txt")).unwrap(),
        b"feature shared\n"
    );
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).unwrap(),
        b"pub fn base(value: i32) {}\n"
    );
}

/// Aborting proves the workspace equals the restore point the merge recorded,
/// Abandoning a merge works from a workspace that has moved, because it
/// restores nothing.
///
/// The rc063a stranger hand-edited a conflicted file and every exit refused:
/// `resolve --continue`, `resolve --abort` and `merge` all answered 409 while
/// `status` and `conflicts` kept advertising the merge, and `stash push --yes`
/// followed by `stash pop` both succeeded and left it exactly as parked. The
/// only recovery was `kin checkout --change`.
///
/// The gate that refused the abort compared the whole restore point, and it was
/// protecting a sentence rather than an operation: abort's transaction carries
/// no workspace mutation, no ref mutation and no changes, and its execution
/// hands the finalizer the same tree twice with an empty delta.
///
/// So this asserts the property that makes unblocking it safe, rather than
/// asserting that it now succeeds and stopping there: the bytes on disk are
/// untouched, and the line says the workspace moved instead of claiming it is
/// unchanged. A version that abandoned the merge AND reverted the caller's edit
/// would pass a success-only test and lose their work.
#[test]
fn aborting_a_merge_from_a_moved_workspace_abandons_it_and_restores_nothing() {
    let root = tempdir().expect("temp root");
    let repo = conflicting_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );
    let parked = persisted_record(&layout).expect("the merge is parked");

    // Move the workspace the way a caller does: edit the conflicted file by
    // hand, then let the daemon see it. `kin status` is what the stranger ran.
    let edited = b"pub fn base(count: u64) {}\npub fn mate() {}\n// hand merged\n";
    fs::write(repo.join("src/lib.rs"), edited).expect("hand edit the conflicted file");
    ok(&run_kin(&runtime, &repo, &["status"]), "kin status");
    let moved = persisted_record(&layout).expect("the merge is still parked after the edit");
    assert_eq!(
        moved.restore, parked.restore,
        "the record's saved restore point never moves; the WORKSPACE is what moved"
    );

    let aborted_output = ok(
        &run_kin(&runtime, &repo, &["resolve", "--abort"]),
        "kin resolve --abort from a moved workspace",
    );

    let aborted = persisted_record(&layout).expect("the record is retained as the merge's account");
    assert!(
        matches!(
            aborted.state,
            kin_model::MergeTransactionState::Aborted { .. }
        ),
        "the record terminates as abandoned: {:?}",
        aborted.state
    );
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).unwrap(),
        edited,
        "abandoning a merge must not touch the caller's own edit"
    );
    assert!(
        aborted_output.contains("has moved since the merge opened"),
        "the line must say the workspace moved rather than claim it is unchanged: \
         {aborted_output}"
    );
    assert!(
        !aborted_output.contains("is unchanged at the recorded restore point"),
        "and must not claim the restore point still holds: {aborted_output}"
    );
}

/// A non-user semantic producer can advance a parked workspace even when its
/// tree is unchanged, and that background publication cannot take the abort
/// door away.
///
/// The rc063a stranger saw the enrichment sweep move the workspace generation
/// while its tree stayed at the merge's base. The compact Python fixture has no
/// cross-file work for the real sweep to publish, so this arm commits the exact
/// transaction shape directly: one LSP relation, no tree delta, one workspace
/// generation. It then reopens the daemon before resolving, so success is read
/// from durable authority rather than from a manager held across the move.
#[test]
fn aborting_after_a_non_user_semantic_move_does_not_wedge() {
    let root = tempdir().expect("temp root");
    let repo = shifting_span_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );
    let parked = persisted_record(&layout).expect("the merge is parked");

    stop_daemon(&runtime, &repo);
    let (before, after, relation_id) = publish_non_user_semantic_move(&layout);
    assert_eq!(
        before.tree_hash, after.tree_hash,
        "the arm is the stranger's unchanged-tree state"
    );
    assert_eq!(
        persisted_record(&layout).expect("the merge remains parked through enrichment"),
        parked,
        "the non-user producer moves the workspace, not the merge record"
    );

    let aborted_output = ok(
        &run_kin_without_enrichment(&runtime, &repo, &["resolve", "--abort"]),
        "kin resolve --abort after a non-user semantic move",
    );
    assert!(
        aborted_output.contains("has moved since the merge opened"),
        "the abort names the durable non-user move: {aborted_output}"
    );
    let aborted = persisted_record(&layout).expect("the record remains as the merge's account");
    assert!(
        matches!(
            aborted.state,
            kin_model::MergeTransactionState::Aborted { .. }
        ),
        "the counter move cannot keep the merge parked: {:?}",
        aborted.state
    );

    let manager = open_authority(&layout);
    let lease = manager.read_authority();
    let after_abort = lease
        .metadata()
        .workspaces
        .first()
        .expect("the workspace survives the abort")
        .clone();
    assert_eq!(
        after_abort, after,
        "aborting the merge leaves the non-user workspace move exactly as it found it"
    );
    let graph = lease
        .workspace_graph_snapshot(&after_abort.workspace_id)
        .expect("resolve the post-abort workspace graph")
        .expect("the post-abort workspace graph exists");
    assert!(
        graph.relations.contains_key(&relation_id),
        "aborting the merge must not discard the durable LSP relation"
    );
}

/// moves no ref, and frees the workspace for the next merge.
#[test]
fn aborting_a_merge_restores_the_workspace_and_frees_the_next_merge() {
    let root = tempdir().expect("temp root");
    let repo = conflicting_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);

    let main_before = branch_change(&layout, "main");
    let feature_before = branch_change(&layout, "feature");
    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );

    let parked = persisted_record(&layout).expect("the merge is parked");
    ok(
        &run_kin(&runtime, &repo, &["resolve", "--abort"]),
        "kin resolve --abort",
    );

    let aborted = persisted_record(&layout).expect("the record is retained as the merge's account");
    assert!(
        matches!(
            aborted.state,
            kin_model::MergeTransactionState::Aborted { .. }
        ),
        "the record terminates as abandoned: {:?}",
        aborted.state
    );
    assert_eq!(
        aborted.restore, parked.restore,
        "abort does not restate the restore point it proved"
    );

    // No ref moved and the working copy is exactly the pre-merge workspace.
    assert_eq!(branch_change(&layout, "main"), main_before);
    assert_eq!(branch_change(&layout, "feature"), feature_before);
    assert_eq!(fs::read(repo.join("shared.txt")).unwrap(), b"main shared\n");
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).unwrap(),
        b"pub fn base(value: u64) {}\n"
    );

    // The workspace is free, so the same merge opens again over the terminated
    // record rather than being refused as in progress.
    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "merge again after aborting",
    );
    let reopened = conflicts_report(&runtime, &repo);
    assert_eq!(reopened["record"]["state"]["state"], "in_progress");
    assert_ne!(
        record_hash(&reopened),
        hex::encode(parked.hash.as_bytes()),
        "the second merge opens its own record"
    );
}

/// One merge per workspace. A second merge while one is in progress is refused
/// and names what is outstanding, rather than replacing the record and losing
/// every resolution already settled against it.
#[test]
fn a_second_merge_while_one_is_in_progress_is_refused() {
    let root = tempdir().expect("temp root");
    let repo = conflicting_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );
    let parked = record_hash(&conflicts_report(&runtime, &repo));

    let refused = run_kin(&runtime, &repo, &["merge", "feature"]);
    assert!(
        !refused.status.success(),
        "a second merge must fail closed: stdout={}",
        String::from_utf8_lossy(&refused.stdout)
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("already has a merge") && stderr.contains("in progress"),
        "the refusal names the merge in progress: {stderr}"
    );

    assert_eq!(
        record_hash(&conflicts_report(&runtime, &repo)),
        parked,
        "the refused merge left the parked record untouched"
    );
    let record = persisted_record(&layout).expect("the merge is still parked");
    assert!(record.state.is_in_progress());
}

/// A merge composes the union of two committed graphs, which is the edges the
/// two branches already carried and not the graph the merged tree implies. A
/// daemon that can enrich now converges that itself and says nothing, because
/// having to know `kin daemon sweep` was the defect. A daemon that cannot
/// enrich has nothing that will repair the gap later, so it has to say so, and
/// this is the arm that runs with no language server on the host.
#[test]
fn a_merge_that_cannot_enrich_says_the_merged_graph_was_not_converged() {
    let root = tempdir().expect("temp root");
    let repo = disjoint_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    // The daemon serving every call below is the one this init starts, and it
    // captures the enrichment lever at process start, so the lever goes here.
    ok(
        &run_kin_without_enrichment(&runtime, &repo, &["init", ".", "--json"]),
        "kin init",
    );

    let merged = ok(
        &run_kin_without_enrichment(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );
    assert!(
        merged.contains("Merged refs/heads/feature into refs/heads/main"),
        "the fixture has to publish rather than park, or the line below proves nothing: {merged}"
    );
    assert!(
        merged.contains("Cross-file enrichment did not run for this merge"),
        "a merge that could not converge its own graph has to say so: {merged}"
    );
    assert!(
        merged.contains("kin daemon sweep"),
        "and it names the recovery, which nothing in the product used to: {merged}"
    );
}

/// A commit cannot publish around a parked merge. Forced admission advances
/// the workspace generation, so allowing the commit would make the recorded
/// restore point stale and strand every resolution already carried by it.
#[test]
fn a_commit_while_a_merge_is_in_progress_is_refused_before_admission() {
    let root = tempdir().expect("temp root");
    let repo = conflicting_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);

    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );
    let main_before = branch_change(&layout, "main");
    let parked = persisted_record(&layout).expect("the merge is parked");
    let parked_hash = hex::encode(parked.hash.as_bytes());
    let hand_authored = b"pub fn hand_authored_resolution(value: u64) {}\n";
    fs::write(repo.join("src/lib.rs"), hand_authored).expect("write a hand-authored resolution");

    let refused = run_kin(
        &runtime,
        &repo,
        &["commit", "-m", "hand-authored merge resolution"],
    );
    assert!(
        !refused.status.success(),
        "commit must not publish around an open merge: stdout={} stderr={}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("HTTP 409 Conflict"),
        "the open transaction is a conflict rather than a daemon fault: {stderr}"
    );
    assert!(
        stderr.contains(&parked_hash),
        "the refusal names the exact merge transaction: {stderr}"
    );
    assert!(
        stderr.contains("kin resolve --do-continue") && stderr.contains("kin resolve --abort"),
        "the refusal names both ways out of the open transaction: {stderr}"
    );

    assert_eq!(
        branch_change(&layout, "main"),
        main_before,
        "the refused commit does not move the target branch"
    );
    assert_eq!(
        persisted_record(&layout),
        Some(parked),
        "the refusal happens before admission and leaves the exact merge record intact"
    );
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).expect("read the authored resolution"),
        hand_authored,
        "the refusal preserves the operator's working-copy resolution"
    );
}

/// Settling names one identity at a time, and a name that matches nothing is
/// refused rather than quietly settling the wrong conflict.
#[test]
fn settling_one_named_conflict_leaves_the_others_outstanding() {
    let root = tempdir().expect("temp root");
    let repo = conflicting_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);
    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );

    let before = conflicts_report(&runtime, &repo);
    let outstanding = before["unresolved_count"].as_u64().expect("a count");
    assert!(outstanding >= 2, "the fixture has more than one conflict");

    ok(
        &run_kin(&runtime, &repo, &["resolve", "--ours", "shared.txt"]),
        "settle the shared artifact",
    );
    let after = conflicts_report(&runtime, &repo);
    assert_eq!(
        after["unresolved_count"].as_u64().expect("a count"),
        outstanding - 1,
        "settling one conflict settles exactly one"
    );
    assert_eq!(after["resolved_count"], 1);

    let unknown = run_kin(&runtime, &repo, &["resolve", "--theirs", "not-a-conflict"]);
    assert!(
        !unknown.status.success(),
        "an unmatched selector must fail closed: stdout={}",
        String::from_utf8_lossy(&unknown.stdout)
    );
    assert!(
        String::from_utf8_lossy(&unknown.stderr).contains("no recorded merge conflict matches"),
        "the refusal says nothing matched: {}",
        String::from_utf8_lossy(&unknown.stderr)
    );

    // Publishing before every conflict is settled is refused and names what is
    // still outstanding.
    let early = run_kin(&runtime, &repo, &["resolve", "--continue"]);
    assert!(
        !early.status.success(),
        "an unresolved merge does not publish: stdout={}",
        String::from_utf8_lossy(&early.stdout)
    );
    assert!(
        String::from_utf8_lossy(&early.stderr).contains("unresolved conflict"),
        "the refusal names the outstanding set: {}",
        String::from_utf8_lossy(&early.stderr)
    );
    assert!(persisted_record(&layout)
        .expect("the merge is still parked")
        .state
        .is_in_progress());
}

/// Settling and publishing are separate transactions. One request cannot do
/// both, because a record commits the resolutions it already carries.
#[test]
fn settling_and_publishing_cannot_be_one_request() {
    let root = tempdir().expect("temp root");
    let repo = conflicting_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize_kin_repo(&runtime, &repo);
    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );

    let both = run_kin(&runtime, &repo, &["resolve", "--all-ours", "--continue"]);
    assert!(
        !both.status.success(),
        "settling and publishing in one request must fail closed: stdout={}",
        String::from_utf8_lossy(&both.stdout)
    );
    assert!(
        String::from_utf8_lossy(&both.stderr).contains("settle conflicts first"),
        "the refusal says why: {}",
        String::from_utf8_lossy(&both.stderr)
    );
}

/// A contested path is settled only by naming one claimant, so the identity the
/// record reports has to be the identity the resolver accepts. When the two
/// disagreed, every claimant the report emitted was refused and a merge that
/// collided on a path could only be abandoned.
#[test]
fn a_contested_path_settles_from_the_identity_the_record_reports() {
    let root = tempdir().expect("temp root");
    let repo = path_colliding_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);

    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );

    let report = conflicts_report(&runtime, &repo);
    let entries = report["record"]["entries"]
        .as_array()
        .expect("the record lists its conflicts");
    let collision = entries
        .iter()
        .find(|entry| entry["divergence"]["divergence"] == "path_collision")
        .unwrap_or_else(|| panic!("both branches adding one path collide on it: {report}"));
    let claimants: Vec<String> = collision["divergence"]["artifacts"]
        .as_array()
        .expect("a contested path names its claimants")
        .iter()
        .map(|claimant| {
            claimant
                .as_str()
                .expect("a claimant identity serializes as a string")
                .to_string()
        })
        .collect();
    assert_eq!(claimants.len(), 2, "one claimant per branch: {report}");

    // The identity the report emitted is the identity the resolver takes back.
    let owner = claimants[0].clone();
    ok(
        &run_kin(
            &runtime,
            &repo,
            &["resolve", "--keep-path", &format!("docs/notes.md={owner}")],
        ),
        "kin resolve --keep-path",
    );
    let settled = persisted_record(&layout).expect("the merge record is persisted");
    assert_eq!(
        settled.unresolved().count(),
        0,
        "naming an owner settles the contested path"
    );

    ok(
        &run_kin(&runtime, &repo, &["resolve", "--continue"]),
        "kin resolve --continue",
    );

    let published = persisted_record(&layout).expect("the terminated record is retained");
    let merge_change = match published.state {
        kin_model::MergeTransactionState::Committed { merge_change, .. } => merge_change,
        other => panic!("a fully settled merge publishes, found {other:?}"),
    };

    // The artifact that kept the path is exactly the one that was named, and it
    // is the only one left claiming it.
    assert_eq!(
        artifacts_at_path(&layout, &merge_change, "docs/notes.md"),
        vec![owner],
        "the named claimant is the artifact the merge published at that path"
    );
}

/// The listing has to name the claimants it will accept back. Stating only how
/// many artifacts collide leaves a caller reading the human surface with no
/// selector to pass to `--keep-path`.
#[test]
fn a_contested_path_listing_names_its_claimants() {
    let root = tempdir().expect("temp root");
    let repo = path_colliding_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);

    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );

    let listing = ok(&run_kin(&runtime, &repo, &["conflicts"]), "kin conflicts");
    let record = persisted_record(&layout).expect("the merge is parked");
    let claimants: Vec<String> = record
        .entries
        .iter()
        .flat_map(|entry| match &entry.divergence {
            kin_model::MergeDivergence::PathCollision { artifacts } => artifacts.clone(),
            _ => Vec::new(),
        })
        .map(|artifact| artifact.0.to_string())
        .collect();
    assert_eq!(claimants.len(), 2, "one claimant per branch: {listing}");
    for claimant in claimants {
        assert!(
            listing.contains(&claimant),
            "the listing names claimant {claimant}: {listing}"
        );
    }
    // A wrapper rendering contains the bare identity as a substring, so the
    // assertions above alone would pass on a listing nothing can select from.
    // The listing has to carry the identity in the form the resolver accepts
    // and no other.
    assert!(
        !listing.contains("ArtifactId("),
        "the listing carries identities in the form the resolver accepts: {listing}"
    );
}

/// One file whose two entities both conflict, because editing the first to a
/// different length on each branch moves the second's span on each branch too.
///
/// That shape is the whole difficulty. `mate` is semantically identical on both
/// sides and still conflicts, so a bulk settle records a decision about it that
/// only its byte offsets distinguish. The two bodies must stay different
/// lengths or `mate` never conflicts and the fixture stops being the case.
fn shifting_span_repository(root: &Path) -> std::path::PathBuf {
    let repo = root.join("repo");
    fs::create_dir_all(&repo).expect("create repo");
    run_git(&repo, &["init", "--initial-branch=main"]);
    run_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(&repo, &["config", "user.name", "Kin"]);
    fs::write(repo.join("shared.txt"), b"shared bytes\n").expect("write shared file");
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    fs::write(
        repo.join("src/lib.rs"),
        b"pub fn base() {}\npub fn mate() {}\n",
    )
    .expect("write base source");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "base"]);

    run_git(&repo, &["switch", "-c", "feature"]);
    fs::write(repo.join("shared.txt"), b"feature shared\n").expect("edit shared on feature");
    fs::write(
        repo.join("src/lib.rs"),
        b"pub fn base(v: i32) {}\npub fn mate() {}\n",
    )
    .expect("edit source on feature");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "feature work"]);

    run_git(&repo, &["switch", "main"]);
    fs::write(repo.join("shared.txt"), b"main shared\n").expect("edit shared on main");
    fs::write(
        repo.join("src/lib.rs"),
        b"pub fn base(count: u64) {}\npub fn mate() {}\n",
    )
    .expect("edit source on main");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "main work"]);
    repo
}

/// One file whose two entities BOTH change semantically on both branches, so
/// settling them to opposite sides leaves no side carrying both decisions and
/// no committed body to publish.
fn opposed_entities_repository(root: &Path) -> std::path::PathBuf {
    let repo = root.join("repo");
    fs::create_dir_all(&repo).expect("create repo");
    run_git(&repo, &["init", "--initial-branch=main"]);
    run_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(&repo, &["config", "user.name", "Kin"]);
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    fs::write(
        repo.join("src/lib.rs"),
        b"pub fn alpha() {}\npub fn beta() {}\n",
    )
    .expect("write base source");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "base"]);

    run_git(&repo, &["switch", "-c", "feature"]);
    fs::write(
        repo.join("src/lib.rs"),
        b"pub fn alpha(v: i32) {}\npub fn beta(v: i32) {}\n",
    )
    .expect("edit source on feature");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "feature work"]);

    run_git(&repo, &["switch", "main"]);
    fs::write(
        repo.join("src/lib.rs"),
        b"pub fn alpha(count: u64) {}\npub fn beta(count: u64) {}\n",
    )
    .expect("edit source on main");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "main work"]);
    repo
}

/// The identity of the one parked entity conflict named `name`, in the form
/// `kin resolve` accepts back. Asserting there is exactly one keeps a fixture
/// that grew a second entity of that name from settling the wrong conflict.
fn entity_conflict(report: &Value, name: &str) -> String {
    let prefix = format!("{name} in ");
    let mut found: Vec<String> = report["record"]["entries"]
        .as_array()
        .expect("a parked merge lists its entries")
        .iter()
        .filter(|entry| entry["subject"]["subject"] == "entity")
        .filter(|entry| {
            entry["label"]
                .as_str()
                .is_some_and(|label| label.starts_with(&prefix))
        })
        .map(|entry| {
            entry["subject"]["entity"]
                .as_str()
                .expect("an entity conflict names its identity")
                .to_string()
        })
        .collect();
    assert_eq!(
        found.len(),
        1,
        "exactly one parked conflict names entity {name}: {report}"
    );
    found.pop().expect("checked immediately above")
}

/// The graph a published change resolves to, read from authority on disk.
fn graph_at(
    layout: &kin_core::KinLayout,
    change: &SemanticChangeId,
) -> kin_model::graph::ResolvedGraphState {
    let manager = open_authority(layout);
    let lease = manager.read_authority();
    let mut snapshot = lease.snapshot().clone();
    snapshot.repository_authority = None;
    drop(lease);
    let graph =
        kin_db::InMemoryGraph::from_snapshot(snapshot).expect("prepare graph-owned history");
    kin_db::ChangeStore::resolve_graph_at(&graph, change)
        .expect("resolve the exact graph a change publishes")
}

/// The one span graph truth records for the entity named `name`, as the byte
/// range it claims inside its file.
fn entity_span(state: &kin_model::graph::ResolvedGraphState, name: &str) -> (String, usize, usize) {
    let mut found: Vec<(String, usize, usize)> = state
        .entities
        .values()
        .filter(|entity| entity.name == name)
        .filter_map(|entity| {
            entity
                .span
                .as_ref()
                .map(|span| (span.file.to_string(), span.start_byte, span.end_byte))
        })
        .collect();
    assert_eq!(
        found.len(),
        1,
        "exactly one entity named {name} carries a span in the merged graph"
    );
    found.pop().expect("checked immediately above")
}

/// FIR-2958. A bulk artifact settle must not override the entity decision
/// already recorded inside that artifact.
///
/// Before the precedence rule, `--theirs` on one entity followed by `--all-ours`
/// reported both settled and every conflict resolved, published the `ours`
/// bytes, and recorded a merge whose tree delta against the first parent was
/// empty. The source branch contributed nothing while every conflict read as
/// settled, and nothing warned.
#[test]
fn a_bulk_artifact_settle_does_not_override_a_named_entity_settle() {
    let root = tempdir().expect("temp root");
    let repo = shifting_span_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);

    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );

    // The specific decision: this one entity takes the source branch's value.
    let parked = conflicts_report(&runtime, &repo);
    let base = entity_conflict(&parked, "base");
    ok(
        &run_kin(&runtime, &repo, &["resolve", "--theirs", &base]),
        "settle the entity to the source branch",
    );
    // The bulk decision, which covers the artifact holding that entity and the
    // sibling entity whose span the first edit moved.
    ok(
        &run_kin(&runtime, &repo, &["resolve", "--all-ours"]),
        "settle the rest to the active branch",
    );
    let stdout = ok(
        &run_kin(&runtime, &repo, &["resolve", "--continue", "--json"]),
        "kin resolve --continue",
    );
    let report: Value = serde_json::from_str(&stdout).expect("resolve report is JSON");
    let merge_change: SemanticChangeId =
        serde_json::from_value(report["merge_change"].clone()).expect("a published merge change");

    // The entity decision reached the file: specific beats bulk.
    let published = fs::read(repo.join("src/lib.rs")).expect("the merged source is on disk");
    assert_eq!(
        published, b"pub fn base(v: i32) {}\npub fn mate() {}\n",
        "the entity settled --theirs decides the bytes of the artifact holding it"
    );
    // The bulk decision still owns every artifact no entity decision covers.
    assert_eq!(
        fs::read(repo.join("shared.txt")).unwrap(),
        b"main shared\n",
        "--all-ours still settles the artifacts no entity decision contradicts"
    );

    let state = graph_at(&layout, &merge_change);
    // Graph truth and the published bytes describe the same file. `mate` was
    // settled --ours and its span on that side points four bytes past where it
    // sits in the bytes this merge published, so a projection that moved the
    // artifact and left the entity spans behind fails right here.
    let (file, start, end) = entity_span(&state, "mate");
    assert!(
        file.ends_with("lib.rs"),
        "the merged `mate` still names its own file: {file}"
    );
    assert_eq!(
        published.get(start..end).map(String::from_utf8_lossy),
        Some(std::borrow::Cow::Borrowed("pub fn mate() {}")),
        "the span graph truth records for `mate`, {start}..{end}, must select `mate` inside the \
         {} bytes kin published",
        published.len()
    );
}

/// A Python module, so the file's own module entity is in the conflict set.
///
/// This is the shape the rc062a stranger actually hit and the one a Rust fixture
/// does NOT produce. A `.py` file yields a Module entity spanning the whole
/// file, whose behaviour hash is the whole file's text, so a bulk settle records
/// a decision about the WHOLE FILE beside the decision about one function inside
/// it. `alpha` is edited to a different length on each branch so `beta`'s span
/// moves on each branch too, and the module entity conflicts on all three sides.
fn container_settle_repository(root: &Path) -> std::path::PathBuf {
    let repo = root.join("repo");
    fs::create_dir_all(&repo).expect("create repo");
    run_git(&repo, &["init", "--initial-branch=main"]);
    run_git(&repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(&repo, &["config", "user.name", "Kin"]);
    fs::create_dir_all(repo.join("ledger")).expect("create package directory");
    fs::write(
        repo.join("ledger/report.py"),
        b"ENTRIES = [1, 2]\n\n\ndef alpha(rows):\n    return len(rows)\n\n\ndef beta(x):\n    return x + 1\n",
    )
    .expect("write base source");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "base"]);

    run_git(&repo, &["switch", "-c", "feature"]);
    fs::write(
        repo.join("ledger/report.py"),
        b"ENTRIES = [1, 2]\n\n\ndef alpha(rows):\n    return len(rows) - 7\n\n\ndef beta(x):\n    return x + 1\n",
    )
    .expect("edit source on feature");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "feature work"]);

    run_git(&repo, &["switch", "main"]);
    fs::write(
        repo.join("ledger/report.py"),
        b"ENTRIES = [1, 2]\n\n\ndef alpha(rows):\n    return len(rows) + 1000000\n\n\ndef beta(x):\n    return x + 1\n",
    )
    .expect("edit source on main");
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "main work"]);
    repo
}

/// A settlement naming a CONTAINER must not override one naming something
/// inside it, which is the same precedence rule one level down from the artifact.
///
/// The file's module entity spans the whole file, so `--all-ours` records a
/// decision about the whole file beside the `--theirs` on one function inside
/// it. Judged as a peer of that function, no side carries both and the merge
/// refuses, which is the wrong answer: this is exactly the case the founder's
/// ruling says must project. The first version of the rule refused it, and its
/// own refusal named the module entity as the reason.
///
/// A Rust fixture cannot see this. `src/lib.rs` produces no conflicting module
/// entity, so the container half of the rule survived every mutation of it until
/// this test existed. That is what the falsification grid found: M5, which
/// disables the container split, was green all the way across.
#[test]
fn a_container_settle_does_not_override_a_settle_inside_it() {
    let root = tempdir().expect("temp root");
    let repo = container_settle_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    // This one call starts the daemon, so it is where the lever belongs.
    let init = run_kin_without_enrichment(&runtime, &repo, &["init", ".", "--json"]);
    ok(&init, "kin init");
    let layout = kin_core::KinLayout::discover(&repo).expect("discover exact layout");

    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );
    let parked = conflicts_report(&runtime, &repo);
    let alpha = entity_conflict(&parked, "alpha");
    ok(
        &run_kin(&runtime, &repo, &["resolve", "--theirs", &alpha]),
        "settle the function to the source branch",
    );
    // Settles beta, ENTRIES, the module entity for the whole file, and the
    // artifact, all to the active branch.
    ok(
        &run_kin(&runtime, &repo, &["resolve", "--all-ours"]),
        "settle the rest to the active branch, including the module entity",
    );
    // The refusal this test exists for happens here: a build that treats the
    // module entity as a peer of the function inside it cannot publish at all.
    let published = ok(
        &run_kin(&runtime, &repo, &["resolve", "--continue"]),
        "kin resolve --continue",
    );

    assert_eq!(
        fs::read(repo.join("ledger/report.py")).expect("the merged source is on disk"),
        b"ENTRIES = [1, 2]\n\n\ndef alpha(rows):\n    return len(rows) - 7\n\n\ndef beta(x):\n    return x + 1\n",
        "the function settled --theirs decides the bytes, and the module settled --ours follows it"
    );
    // And the merge says so, which is the half that makes it not silent. A build
    // that projected correctly and said nothing would pass the assertion above.
    assert!(
        published.contains("Projected") && published.contains("container"),
        "the merge names the projection and why the bulk settlement followed it: {published}"
    );
    // The source branch contributed bytes, which an empty tree delta would deny.
    let merge_change = branch_change(&layout, "main");
    assert_ne!(
        change_tree_delta_count(&layout, &merge_change),
        0,
        "the published merge carries the bytes the entity decision chose"
    );
}

/// Two entities in one file whose values both moved on both branches, settled
/// to opposite sides, have no publishable projection: neither branch's
/// committed bytes carry both decisions, and kin has no textual line merge to
/// build a third body from. The merge refuses and names both decisions rather
/// than honouring one of them in silence.
#[test]
fn contradictory_settlements_inside_one_artifact_refuse_and_name_both() {
    let root = tempdir().expect("temp root");
    let repo = opposed_entities_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let layout = initialize_kin_repo(&runtime, &repo);

    let main_before = branch_change(&layout, "main");
    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );

    let parked = conflicts_report(&runtime, &repo);
    let alpha = entity_conflict(&parked, "alpha");
    let beta = entity_conflict(&parked, "beta");
    ok(
        &run_kin(&runtime, &repo, &["resolve", "--theirs", &alpha]),
        "settle alpha to the source branch",
    );
    ok(
        &run_kin(&runtime, &repo, &["resolve", "--ours", &beta]),
        "settle beta to the active branch",
    );
    ok(
        &run_kin(&runtime, &repo, &["resolve", "--all-ours"]),
        "settle the artifact in bulk",
    );

    let refused = run_kin(&runtime, &repo, &["resolve", "--continue"]);
    assert!(
        !refused.status.success(),
        "an unprojectable mix does not publish: stdout={}",
        String::from_utf8_lossy(&refused.stdout)
    );
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stderr),
        String::from_utf8_lossy(&refused.stdout)
    );
    // Both decisions, by name, and the file they disagree about.
    assert!(
        said.contains("src/lib.rs"),
        "the refusal names the file: {said}"
    );
    assert!(
        said.contains("alpha") && said.contains("beta"),
        "the refusal names both entity decisions: {said}"
    );
    assert!(
        said.contains("--theirs") && said.contains("--ours"),
        "the refusal names the side each decision took: {said}"
    );

    // Nothing published, and the resolutions are still there to re-settle.
    assert_eq!(branch_change(&layout, "main"), main_before);
    assert!(persisted_record(&layout)
        .expect("the merge is still parked")
        .state
        .is_in_progress());
}

/// Name every field on which two versions of one entity disagree.
///
/// Written as a list of every field the model declares rather than a derived
/// comparison, so a field added to `Entity` later fails to compile here and has
/// to be classified deliberately as semantic or as provenance.
fn entity_field_differences(
    ours: &kin_model::Entity,
    theirs: &kin_model::Entity,
) -> Vec<&'static str> {
    let kin_model::Entity {
        id,
        kind,
        name,
        language,
        fingerprint,
        file_origin,
        span,
        signature,
        visibility,
        role,
        doc_summary,
        metadata,
        lineage_parent,
        created_in,
        superseded_by,
    } = ours;
    let mut differing = Vec::new();
    for (label, differs) in [
        ("id", *id != theirs.id),
        ("kind", *kind != theirs.kind),
        ("name", *name != theirs.name),
        ("language", *language != theirs.language),
        ("fingerprint", *fingerprint != theirs.fingerprint),
        ("file_origin", *file_origin != theirs.file_origin),
        ("span", *span != theirs.span),
        ("signature", *signature != theirs.signature),
        ("visibility", *visibility != theirs.visibility),
        ("role", *role != theirs.role),
        ("doc_summary", *doc_summary != theirs.doc_summary),
        ("metadata", *metadata != theirs.metadata),
        ("lineage_parent", *lineage_parent != theirs.lineage_parent),
        ("created_in", *created_in != theirs.created_in),
        ("superseded_by", *superseded_by != theirs.superseded_by),
    ] {
        if differs {
            differing.push(label);
        }
    }
    differing
}

/// The one entity named `name` in a resolved graph state.
fn entity_named(state: &kin_model::graph::ResolvedGraphState, name: &str) -> kin_model::Entity {
    let mut found: Vec<kin_model::Entity> = state
        .entities
        .values()
        .filter(|entity| entity.name == name)
        .cloned()
        .collect();
    assert_eq!(found.len(), 1, "exactly one entity named {name}");
    found.pop().expect("checked immediately above")
}

/// Different-length edits to `alpha` shift the untouched `beta` span and change
/// the complete source blob on each branch. Both digests must bind their exact
/// admitted trees. Every other metadata and entity field must remain equal.
#[test]
fn an_untouched_entity_differs_between_branches_only_in_its_span_and_source_digest() {
    let root = tempdir().expect("temp root");
    let repo = container_settle_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let init = run_kin_without_enrichment(&runtime, &repo, &["init", ".", "--json"]);
    ok(&init, "kin init");
    let layout = kin_core::KinLayout::discover(&repo).expect("discover exact layout");

    let ours = graph_at(&layout, &branch_change(&layout, "main"));
    let theirs = graph_at(&layout, &branch_change(&layout, "feature"));

    let mut ours_beta = entity_named(&ours, "beta");
    let mut theirs_beta = entity_named(&theirs, "beta");
    for (state, entity) in [(&ours, &ours_beta), (&theirs, &theirs_beta)] {
        let span = entity.span.as_ref().expect("untouched function has a span");
        let artifact = state
            .tree
            .artifact_at_path(&kin_model::RepoPath::from_utf8(&span.file.0).unwrap())
            .expect("span source belongs to the exact branch tree");
        let digest = artifact.entry.blob_identity().expect("source is a blob");
        assert_eq!(
            entity.metadata.extra.get("blob_hash"),
            Some(&Value::String(digest.to_string())),
            "untouched entity must bind the exact source blob in its branch tree"
        );
    }
    assert_eq!(
        entity_field_differences(&ours_beta, &theirs_beta),
        vec!["span", "metadata"],
        "different branch source bytes must change both the span and its provenance"
    );
    // Remove only the independently verified source digest before comparing.
    // Every other metadata field remains part of the strict entity comparison.
    ours_beta.metadata.extra.remove("blob_hash");
    theirs_beta.metadata.extra.remove("blob_hash");
    let untouched = entity_field_differences(&ours_beta, &theirs_beta);
    assert_eq!(
        untouched,
        vec!["span"],
        "apart from its exact source digest, an untouched entity differs only in its byte offsets; it actually differed on {untouched:?}"
    );

    // The control that keeps the reading honest: the entity both sides DID edit
    // must differ on a semantic field too, or the comparison above is measuring
    // nothing and would report the same set for every entity in the file.
    let edited = entity_field_differences(
        &entity_named(&ours, "alpha"),
        &entity_named(&theirs, "alpha"),
    );
    assert!(
        edited.contains(&"fingerprint"),
        "the entity both sides edited must differ semantically; it differed on {edited:?}"
    );
}

#[test]
fn authored_merge_body_survives_restart_and_rebuilds_added_and_removed_declarations() {
    let root = tempdir().expect("temp root");
    let repo = opposed_entities_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    ok(
        &run_kin_without_enrichment(&runtime, &repo, &["init", ".", "--json"]),
        "init",
    );
    let layout = kin_core::KinLayout::discover(&repo).unwrap();
    let ours = branch_change(&layout, "main");
    let theirs = branch_change(&layout, "feature");
    let before = fs::read(repo.join("src/lib.rs")).unwrap();
    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "park merge",
    );
    let report = conflicts_report(&runtime, &repo);
    let expected = record_hash(&report);
    let body = b"pub fn alpha(value: i32, count: u64) -> u64 { gamma(value) + count }\npub fn gamma(value: i32) -> u64 { value as u64 }\n";
    let input = root.path().join("resolved=source.rs");
    fs::write(&input, body).unwrap();
    let settled = run_kin(
        &runtime,
        &repo,
        &[
            "resolve",
            "--file",
            "src/lib.rs",
            input.to_str().unwrap(),
            "--expect",
            &expected,
            "--json",
        ],
    );
    let settled: Value = serde_json::from_str(&ok(&settled, "settle authored body")).unwrap();
    assert_eq!(settled["unresolved_count"], 0);
    assert_eq!(
        branch_change(&layout, "main"),
        ours,
        "settlement must not create an intermediate merge"
    );
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).unwrap(),
        before,
        "settlement leaves the workspace untouched"
    );
    let saved = persisted_record(&layout).unwrap();
    let authored: Vec<_> = saved
        .entries
        .iter()
        .filter_map(|entry| match &entry.resolution {
            kin_model::MergeEntryResolution::Payload {
                payload: kin_model::MergeResolutionPayload::Artifact(located),
                ..
            } => located.entry.blob_identity(),
            _ => None,
        })
        .collect();
    assert_eq!(authored.len(), 1);
    assert_eq!(
        open_authority(&layout)
            .load_source_blob(authored[0])
            .unwrap()
            .unwrap(),
        body
    );
    fs::remove_file(&input).unwrap();
    stop_daemon(&runtime, &repo);
    assert_eq!(persisted_record(&layout).unwrap().hash, saved.hash);
    let continued =
        run_kin_without_enrichment(&runtime, &repo, &["resolve", "--continue", "--json"]);
    let continued: Value =
        serde_json::from_str(&ok(&continued, "publish after restart without input file")).unwrap();
    let change: SemanticChangeId =
        serde_json::from_value(continued["merge_change"].clone()).unwrap();
    assert_eq!(change_parents(&layout, &change), vec![ours, theirs]);
    assert_eq!(fs::read(repo.join("src/lib.rs")).unwrap(), body);
    assert_eq!(branch_change(&layout, "feature"), theirs);
    let merged = graph_at(&layout, &change);
    let alpha = entity_named(&merged, "alpha");
    let gamma = entity_named(&merged, "gamma");
    assert!(
        !merged.entities.values().any(|entity| entity.name == "beta"),
        "removed declaration must not remain in graph truth"
    );
    for entity in [&alpha, &gamma] {
        let span = entity.span.as_ref().unwrap();
        let exact = &body[span.start_byte..span.end_byte];
        assert!(std::str::from_utf8(exact)
            .unwrap()
            .starts_with(&format!("pub fn {}", entity.name)));
        assert_eq!(
            entity.metadata.extra.get("blob_hash"),
            Some(&Value::String(authored[0].to_string()))
        );
    }
    assert!(
        merged.relations.values().any(|relation| {
            relation.kind == kin_model::RelationKind::Calls
                && relation.src == kin_model::GraphNodeId::Entity(alpha.id)
                && relation.dst == kin_model::GraphNodeId::Entity(gamma.id)
        }),
        "the new declaration's call edge must be derived from the authored body"
    );
    stop_daemon(&runtime, &repo);
    assert_eq!(graph_at(&layout, &change).entities, merged.entities);
}

#[test]
fn authored_merge_body_refuses_stale_and_competing_choices_without_partial_settlement() {
    let root = tempdir().expect("temp root");
    let repo = opposed_entities_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    ok(
        &run_kin_without_enrichment(&runtime, &repo, &["init", ".", "--json"]),
        "init",
    );
    let layout = kin_core::KinLayout::discover(&repo).unwrap();
    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "park merge",
    );
    let initial = persisted_record(&layout).unwrap();
    let input = root.path().join("resolution.rs");
    fs::write(&input, b"pub fn alpha() {}\npub fn gamma() {}\n").unwrap();
    let competing = run_kin(
        &runtime,
        &repo,
        &[
            "resolve",
            "--file",
            "src/lib.rs",
            input.to_str().unwrap(),
            "--theirs",
            "alpha",
        ],
    );
    assert!(
        !competing.status.success(),
        "competing whole-file and entity decisions must refuse"
    );
    assert!(
        String::from_utf8_lossy(&competing.stderr).contains("also covered"),
        "{}",
        String::from_utf8_lossy(&competing.stderr)
    );
    assert_eq!(persisted_record(&layout).unwrap().hash, initial.hash);
    ok(
        &run_kin(
            &runtime,
            &repo,
            &["resolve", "--file", "src/lib.rs", input.to_str().unwrap()],
        ),
        "settle file",
    );
    let settled = persisted_record(&layout).unwrap();
    assert_ne!(settled.hash, initial.hash);
    fs::write(&input, b"pub fn alpha(value: bool) {}\n").unwrap();
    let stale = run_kin(
        &runtime,
        &repo,
        &[
            "resolve",
            "--file",
            "src/lib.rs",
            input.to_str().unwrap(),
            "--expect",
            &initial.hash.to_string(),
        ],
    );
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("has advanced"));
    assert_eq!(persisted_record(&layout).unwrap().hash, settled.hash);
    let overlapping = run_kin(&runtime, &repo, &["resolve", "--theirs", "alpha"]);
    assert!(!overlapping.status.success());
    assert!(String::from_utf8_lossy(&overlapping.stderr).contains("authored body"));
    assert_eq!(persisted_record(&layout).unwrap().hash, settled.hash);
    ok(
        &run_kin(
            &runtime,
            &repo,
            &[
                "resolve",
                "--file",
                "src/lib.rs",
                input.to_str().unwrap(),
                "--expect",
                &settled.hash.to_string(),
            ],
        ),
        "intentionally replace whole-file decision",
    );
    assert_ne!(persisted_record(&layout).unwrap().hash, settled.hash);
}

#[test]
fn authored_merge_accepts_exact_non_source_bytes_and_refuses_invalid_source_atomically() {
    let root = tempdir().expect("temp root");
    let repo = conflicting_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    ok(
        &run_kin_without_enrichment(&runtime, &repo, &["init", ".", "--json"]),
        "init",
    );
    let layout = kin_core::KinLayout::discover(&repo).unwrap();
    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "park merge",
    );
    let initial = persisted_record(&layout).unwrap();
    let source = root.path().join("source.rs");
    let opaque = root.path().join("opaque.dat");
    let mut raw = vec![0xff; 700 * 1024];
    raw[0] = 0;
    fs::write(&opaque, &raw).unwrap();
    fs::write(&source, b"pub fn base( {\n").unwrap();
    let invalid = run_kin(
        &runtime,
        &repo,
        &[
            "resolve",
            "--file",
            "shared.txt",
            opaque.to_str().unwrap(),
            "--file",
            "src/lib.rs",
            source.to_str().unwrap(),
        ],
    );
    assert!(
        !invalid.status.success(),
        "invalid source must not publish partial graph meaning"
    );
    assert!(
        String::from_utf8_lossy(&invalid.stderr).contains("syntax errors"),
        "{}",
        String::from_utf8_lossy(&invalid.stderr)
    );
    assert_eq!(persisted_record(&layout).unwrap().hash, initial.hash);
    fs::write(&source, b"pub fn base(value: i32, count: u64) {}\n").unwrap();
    ok(
        &run_kin(
            &runtime,
            &repo,
            &[
                "resolve",
                "--file",
                "shared.txt",
                opaque.to_str().unwrap(),
                "--file",
                "src/lib.rs",
                source.to_str().unwrap(),
            ],
        ),
        "settle both file bodies",
    );
    ok(
        &run_kin(&runtime, &repo, &["resolve", "--continue"]),
        "publish both file bodies",
    );
    assert_eq!(fs::read(repo.join("shared.txt")).unwrap(), raw);
    assert_eq!(
        fs::read(repo.join("src/lib.rs")).unwrap(),
        fs::read(source).unwrap()
    );
}

#[test]
fn authored_merge_rebuilds_cross_file_relations_to_a_new_declaration() {
    exercise_authored_cross_file_resolution(false);
}

#[test]
fn authored_merge_rebuilds_cross_file_relations_across_separate_requests() {
    exercise_authored_cross_file_resolution(true);
}

fn exercise_authored_cross_file_resolution(separate_requests: bool) {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    fs::write(
        repo.join("a.py"),
        b"from b import beta\n\ndef run(value):\n    return beta(value)\n",
    )
    .unwrap();
    fs::write(repo.join("b.py"), b"def beta(value):\n    return value\n").unwrap();
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "linked Python source"]);
    run_git(&repo, &["switch", "-c", "feature"]);
    fs::write(
        repo.join("a.py"),
        b"from b import beta\n\ndef run(value):\n    return beta(value) + 1\n",
    )
    .unwrap();
    fs::write(
        repo.join("b.py"),
        b"def beta(value):\n    return value + 1\n",
    )
    .unwrap();
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "feature edits"]);
    run_git(&repo, &["switch", "main"]);
    fs::write(
        repo.join("a.py"),
        b"from b import beta\n\ndef run(value):\n    return beta(value) + 2\n",
    )
    .unwrap();
    fs::write(
        repo.join("b.py"),
        b"def beta(value):\n    return value + 2\n",
    )
    .unwrap();
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "main edits"]);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    ok(
        &run_kin_without_enrichment(&runtime, &repo, &["init", ".", "--json"]),
        "init",
    );
    let layout = kin_core::KinLayout::discover(&repo).unwrap();
    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "park merge",
    );
    let a = root.path().join("a-resolution.py");
    let b = root.path().join("b-resolution.py");
    fs::write(
        &a,
        b"from b import gamma\n\ndef run(value):\n    return gamma(value) + 3\n",
    )
    .unwrap();
    fs::write(&b, b"def gamma(value):\n    return value * 2\n").unwrap();
    if separate_requests {
        ok(
            &run_kin(
                &runtime,
                &repo,
                &["resolve", "--file", "a.py", a.to_str().unwrap()],
            ),
            "settle the calling file first",
        );
        let first = persisted_record(&layout).unwrap();
        let retained = first
            .entries
            .iter()
            .find(|entry| {
                matches!(
                    &entry.resolution,
                    kin_model::MergeEntryResolution::Payload {
                        payload: kin_model::MergeResolutionPayload::Artifact(located), ..
                    } if located.path.to_string() == "a.py"
                )
            })
            .expect("the first file must have a persisted authored body");
        ok(
            &run_kin(
                &runtime,
                &repo,
                &[
                    "resolve",
                    "--file",
                    "b.py",
                    b.to_str().unwrap(),
                    "--all-ours",
                    "--expect",
                    &first.hash.to_string(),
                ],
            ),
            "settle the referenced file in another request",
        );
        let second = persisted_record(&layout).unwrap();
        assert_eq!(
            second
                .entries
                .iter()
                .find(|entry| entry.subject == retained.subject),
            Some(retained),
            "a later file request must preserve the earlier authored body"
        );
    } else {
        ok(
            &run_kin(
                &runtime,
                &repo,
                &[
                    "resolve",
                    "--file",
                    "a.py",
                    a.to_str().unwrap(),
                    "--file",
                    "b.py",
                    b.to_str().unwrap(),
                    "--all-ours",
                ],
            ),
            "settle both linked files",
        );
    }
    stop_daemon(&runtime, &repo);
    ok(
        &run_kin_without_enrichment(&runtime, &repo, &["resolve", "--continue"]),
        "publish linked files",
    );
    let merged = graph_at(&layout, &branch_change(&layout, "main"));
    let caller = entity_named(&merged, "run");
    let target = entity_named(&merged, "gamma");
    assert!(!merged.entities.values().any(|entity| entity.name == "beta"));
    assert!(
        merged.relations.values().any(|relation| {
            relation.kind == kin_model::RelationKind::Calls
                && relation.src == kin_model::GraphNodeId::Entity(caller.id)
                && relation.dst == kin_model::GraphNodeId::Entity(target.id)
        }),
        "an authored call must resolve to the new declaration in the other authored file"
    );
    assert_eq!(fs::read(repo.join("a.py")).unwrap(), fs::read(a).unwrap());
    assert_eq!(fs::read(repo.join("b.py")).unwrap(), fs::read(b).unwrap());
}

#[test]
fn authored_merge_backend_refuses_raw_input_over_the_limit_before_record_or_blob_changes() {
    use kin_cli::commands::resolve::{
        ResolveAction, ResolveChoice, ResolveDirective, ResolveRequest, MAX_RESOLVE_FILE_BYTES,
    };
    let root = tempdir().expect("temp root");
    let repo = conflicting_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    ok(
        &run_kin_without_enrichment(&runtime, &repo, &["init", ".", "--json"]),
        "init",
    );
    let layout = kin_core::KinLayout::discover(&repo).unwrap();
    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "park merge",
    );
    let initial = persisted_record(&layout).unwrap();
    let body = vec![0; MAX_RESOLVE_FILE_BYTES + 1];
    let digest = kin_blobs::digest(&body);
    assert!(open_authority(&layout)
        .load_source_blob(digest)
        .unwrap()
        .is_none());
    let common::RecordedDaemonEndpoint::Listening { port } =
        common::probe_recorded_daemon_endpoint(layout.root())
    else {
        panic!("the fixture daemon must be listening before sending a bounded request");
    };
    let request = ResolveRequest {
        operation_id: kin_model::OperationId::new(),
        actor: kin_model::AuthorId::new("merge-resolution-test"),
        expected_record: Some(initial.hash),
        action: ResolveAction::Settle {
            directives: vec![ResolveDirective {
                selector: "shared.txt".to_string(),
                choice: ResolveChoice::File { body },
            }],
            all: None,
        },
    };
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let token = fs::read_to_string(layout.root().join("daemon.token")).unwrap();
    let response = executor
        .block_on(
            reqwest::Client::new()
                .post(format!("http://127.0.0.1:{port}/commands/resolve"))
                .bearer_auth(token.trim())
                .json(&request)
                .send(),
        )
        .expect("send directly to the fixture daemon");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    let error = executor.block_on(response.text()).unwrap();
    assert!(error.contains("custom resolution input exceeds"), "{error}");
    assert_eq!(persisted_record(&layout).unwrap().hash, initial.hash);
    assert!(open_authority(&layout)
        .load_source_blob(digest)
        .unwrap()
        .is_none());
}

#[test]
fn authored_destination_file_preserves_an_incoming_relation_conflict() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    initialize_git_repo(&repo);
    fs::write(
        repo.join("a.py"),
        b"from b import beta\n\ndef run(value):\n    return beta(value)\n",
    )
    .unwrap();
    fs::write(repo.join("b.py"), b"def beta(value):\n    return value\n").unwrap();
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "linked Python source"]);
    run_git(&repo, &["switch", "-c", "feature"]);
    fs::write(
        repo.join("a.py"),
        b"from b import beta\n\ndef run(value):\n    return 1 + beta(value)\n",
    )
    .unwrap();
    fs::write(
        repo.join("b.py"),
        b"def beta(value):\n    return value + 1\n",
    )
    .unwrap();
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "feature edits"]);
    run_git(&repo, &["switch", "main"]);
    fs::write(
        repo.join("a.py"),
        b"from b import beta\n\ndef run(value):\n    return 20 + beta(value)\n",
    )
    .unwrap();
    fs::write(
        repo.join("b.py"),
        b"def beta(value):\n    return value + 2\n",
    )
    .unwrap();
    run_git(&repo, &["add", "--all"]);
    run_git(&repo, &["commit", "-m", "main edits"]);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    ok(
        &run_kin_without_enrichment(&runtime, &repo, &["init", ".", "--json"]),
        "init",
    );
    let layout = kin_core::KinLayout::discover(&repo).unwrap();
    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "park merge",
    );
    let initial = persisted_record(&layout).unwrap();
    let ours = graph_at(&layout, &initial.binding.ours_change);
    let caller = entity_named(&ours, "run");
    let destination = entity_named(&ours, "beta");
    let incoming: Vec<_> = initial
        .entries
        .iter()
        .filter(|entry| {
            let kin_model::MergeConflictSubject::Relation { relation } = entry.subject else {
                return false;
            };
            ours.relations.get(&relation).is_some_and(|relation| {
                relation.src == kin_model::GraphNodeId::Entity(caller.id)
                    && relation.dst == kin_model::GraphNodeId::Entity(destination.id)
            })
        })
        .cloned()
        .collect();
    assert!(
        !incoming.is_empty(),
        "the fixture must hold a real incoming relation conflict"
    );
    let input = root.path().join("b-resolution.py");
    fs::write(&input, b"def beta(value):\n    return value * 3\n").unwrap();
    ok(
        &run_kin(
            &runtime,
            &repo,
            &["resolve", "--file", "b.py", input.to_str().unwrap()],
        ),
        "settle destination file",
    );
    let settled = persisted_record(&layout).unwrap();
    for original in &incoming {
        assert_eq!(
            settled
                .entries
                .iter()
                .find(|entry| entry.subject == original.subject),
            Some(original),
            "the destination file must not choose another file's incoming relationship"
        );
        let kin_model::MergeConflictSubject::Relation { relation } = original.subject else {
            unreachable!()
        };
        ok(
            &run_kin(
                &runtime,
                &repo,
                &["resolve", "--theirs", &relation.to_string()],
            ),
            "settle incoming relation independently",
        );
    }
    ok(
        &run_kin(&runtime, &repo, &["resolve", "--all-theirs"]),
        "settle remaining source file choices",
    );
    ok(
        &run_kin(&runtime, &repo, &["resolve", "--continue"]),
        "publish coherent source and destination decisions",
    );
    assert_eq!(
        fs::read(repo.join("b.py")).unwrap(),
        fs::read(input).unwrap()
    );
}

#[test]
fn authored_merge_accepts_in_place_input_and_preserves_unrelated_or_later_edits() {
    let root = tempdir().expect("temp root");
    let repo = conflicting_repository(root.path());
    fs::write(repo.join("untouched.txt"), b"keep this\n").unwrap();
    run_git(&repo, &["add", "untouched.txt"]);
    run_git(&repo, &["commit", "-m", "independent tracked file"]);
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    ok(
        &run_kin_without_enrichment(&runtime, &repo, &["init", ".", "--json"]),
        "init",
    );
    let layout = kin_core::KinLayout::discover(&repo).unwrap();
    let head = branch_change(&layout, "main");
    parked_merge(
        &run_kin(&runtime, &repo, &["merge", "feature"]),
        "park merge",
    );
    let initial = persisted_record(&layout).unwrap();
    let source = repo.join("src/lib.rs");
    let body = b"pub fn base(value: i32, count: u64) -> u64 { value as u64 + count }\n";
    fs::write(&source, body).unwrap();
    let external = root.path().join("shared-resolution.txt");
    fs::write(&external, b"combined shared bytes\n").unwrap();
    ok(
        &run_kin(
            &runtime,
            &repo,
            &[
                "resolve",
                "--file",
                "src/lib.rs",
                source.to_str().unwrap(),
                "--file",
                "shared.txt",
                external.to_str().unwrap(),
                "--expect",
                &initial.hash.to_string(),
            ],
        ),
        "settle mixed in-place and external input",
    );
    let settled = persisted_record(&layout).unwrap();
    fs::write(repo.join("untouched.txt"), b"unrelated local edit\n").unwrap();
    let unrelated = run_kin(&runtime, &repo, &["resolve", "--continue"]);
    assert!(!unrelated.status.success());
    assert!(
        String::from_utf8_lossy(&unrelated.stderr).contains("untouched.txt"),
        "{}",
        String::from_utf8_lossy(&unrelated.stderr)
    );
    assert_eq!(branch_change(&layout, "main"), head);
    assert_eq!(persisted_record(&layout).unwrap().hash, settled.hash);
    assert_eq!(fs::read(&source).unwrap(), body);
    fs::write(repo.join("untouched.txt"), b"keep this\n").unwrap();
    fs::write(&source, b"pub fn later_edit() {}\n").unwrap();
    let later = run_kin(&runtime, &repo, &["resolve", "--continue"]);
    assert!(!later.status.success());
    assert!(
        String::from_utf8_lossy(&later.stderr).contains("src/lib.rs"),
        "{}",
        String::from_utf8_lossy(&later.stderr)
    );
    assert_eq!(fs::read(&source).unwrap(), b"pub fn later_edit() {}\n");
    assert_eq!(persisted_record(&layout).unwrap().hash, settled.hash);
    fs::write(&source, body).unwrap();
    ok(
        &run_kin(&runtime, &repo, &["resolve", "--continue"]),
        "publish the exact authored input already projected in place",
    );
    assert_ne!(branch_change(&layout, "main"), head);
    assert_eq!(fs::read(source).unwrap(), body);
    assert_eq!(
        fs::read(repo.join("shared.txt")).unwrap(),
        b"combined shared bytes\n"
    );
    assert_eq!(
        fs::read(repo.join("untouched.txt")).unwrap(),
        b"keep this\n"
    );
}

/// FIR-3242. The census a merge records has to be a reading of the graph the
/// merge left live.
///
/// `settle_merged_graph` ran from inside the publication path, and the
/// publication path returns to `execute`, which is where
/// `finalize_local_repository_commit` derives and applies the merged live
/// entity and relation correction. The `create_change` calls above the settle
/// install immutable history and revision lineage, not the merged entity and
/// relation table, so the record carried this merge's timestamp and source over
/// a reading of the PREVIOUS live relation set. Every later comparison is
/// judged against that baseline, so a kind this merge introduced can disappear
/// without the store ever having recorded that it existed.
///
/// Read off disk, with enrichment off, and needing no barrier: the merged tree
/// holds a source file the target branch never had, so the merged graph holds
/// strictly more entities than the graph before it, and a record written after
/// finalization has to show that. A record written before finalization holds
/// the pre-merge count instead, and nothing between the merge and this reading
/// can move either side.
#[test]
fn a_published_merge_records_the_census_of_the_graph_it_finalized() {
    let root = tempdir().expect("temp root");
    let repo = disjoint_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    ok(
        &run_kin_without_enrichment(&runtime, &repo, &["init", ".", "--json"]),
        "kin init",
    );
    let layout = kin_core::KinLayout::discover(&repo).expect("discover exact layout");
    assert!(
        kin_core::relation_census::read(&layout)
            .recorded()
            .is_none(),
        "the recorder runs at the end of a sweep and at the end of a commit, and this init is \
         neither, so the record read below is the one this merge wrote and nothing else"
    );

    let merged = ok(
        &run_kin_without_enrichment(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );
    assert!(
        merged.contains("Merged refs/heads/feature into refs/heads/main"),
        "the fixture has to publish rather than park, or nothing below is about a merge: {merged}"
    );

    let recorded = kin_core::relation_census::read(&layout)
        .recorded()
        .cloned()
        .expect("a published merge records the baseline the next comparison is judged against");
    let published = graph_at(&layout, &branch_change(&layout, "main"));
    let published_entities = published
        .entities
        .values()
        .filter(|entity| !kin_index::is_external_reference_target(entity))
        .count() as u64;

    assert_eq!(
        recorded.entities,
        Some(published_entities),
        "the record has to describe the graph this merge published, and this one describes the \
         graph before the merged live delta was applied: the merged tree holds {published_entities} \
         entities and the record claims {:?}",
        recorded.entities
    );
}

/// FIR-3242. A parked merge settles nothing, because it published no merged
/// graph.
///
/// A merge that parks its conflicts still writes a merge transaction record and
/// finalizes like any other repository transition, so it reaches the same
/// executor the settle now runs in. It composed no merged entity and relation
/// table: a census recorded there would describe the unmerged graph under this
/// merge's timestamp and source, and retiring every file's enrichment evidence
/// would buy a full re-derivation for a merge that published nothing.
///
/// Green before the settle moved, because `open_conflicted_merge` reaches a
/// `bail!` rather than the publication path the settle used to live in. This is
/// the lock that keeps it green.
#[test]
fn a_parked_merge_records_no_census_because_it_published_no_merged_graph() {
    let root = tempdir().expect("temp root");
    let repo = conflicting_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    ok(
        &run_kin_without_enrichment(&runtime, &repo, &["init", ".", "--json"]),
        "kin init",
    );
    let layout = kin_core::KinLayout::discover(&repo).expect("discover exact layout");
    assert!(
        kin_core::relation_census::read(&layout)
            .recorded()
            .is_none(),
        "the recorder runs at the end of a sweep and at the end of a commit, and this init is \
         neither, so anything read below was written by the merge"
    );

    parked_merge(
        &run_kin_without_enrichment(&runtime, &repo, &["merge", "feature"]),
        "kin merge",
    );

    assert!(
        kin_core::relation_census::read(&layout)
            .recorded()
            .is_none(),
        "a parked merge composed no merged relation set, so it has none to record; a record \
         written here would describe the graph before the merge and carry this merge's timestamp"
    );
}
