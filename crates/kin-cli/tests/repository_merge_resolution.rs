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

/// An entity NEITHER branch edited still differs between the branches, and the
/// measurement says on which field.
///
/// Measured rather than assumed, and the measurement corrected the guess that
/// produced it. `beta` is untouched by both sides, so provenance looked like the
/// likely difference; `created_in` is in fact EQUAL, because nothing re-minted
/// the record. The one field that differs is `span`, and the reason is that the
/// two edits to `alpha` above it are different LENGTHS, so every byte offset
/// below shifts by a different amount on each side.
///
/// That is why one changed function reports three entity conflicts here and
/// nine in the rc062j stranger run. A byte offset is a projection of whichever
/// bytes the merge publishes, not an independent decision, so the operator is
/// being asked a question whose answer is already determined by another answer.
/// Removing that question is the derived-conflict design, which is FIR-2960 and
/// not this change: this test records the premise, and the count it explains.
///
/// The assertion is an equality against the exact measured set rather than a
/// subset check, so an entity that starts differing on a SEMANTIC field fails
/// here rather than being quietly folded into the same explanation.
#[test]
fn an_untouched_entity_differs_between_branches_only_in_its_span() {
    let root = tempdir().expect("temp root");
    let repo = container_settle_repository(root.path());
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let init = run_kin_without_enrichment(&runtime, &repo, &["init", ".", "--json"]);
    ok(&init, "kin init");
    let layout = kin_core::KinLayout::discover(&repo).expect("discover exact layout");

    let ours = graph_at(&layout, &branch_change(&layout, "main"));
    let theirs = graph_at(&layout, &branch_change(&layout, "feature"));

    let untouched =
        entity_field_differences(&entity_named(&ours, "beta"), &entity_named(&theirs, "beta"));
    assert_eq!(
        untouched,
        vec!["span"],
        "an entity neither side edited differs only in its byte offsets; it actually differed on {untouched:?}"
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
