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

fn initialize_kin_repo(repo: &Path, home: &Path) -> kin_core::KinLayout {
    let init = run_kin(repo, home, &["init", ".", "--json"]);
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

fn conflicts_report(repo: &Path, home: &Path) -> Value {
    let output = run_kin(repo, home, &["conflicts", "--json"]);
    let stdout = ok(&output, "kin conflicts --json");
    serde_json::from_str(&stdout).expect("conflicts report is JSON")
}

fn record_hash(report: &Value) -> String {
    report["record_hash"]
        .as_str()
        .expect("a listed merge carries its record identity")
        .to_string()
}

fn stop_daemon(repo: &Path, home: &Path) {
    ok(&run_kin(repo, home, &["daemon", "stop"]), "kin daemon stop");
}

/// Both branches edit one shared artifact and one shared entity, so the merge
/// has exactly the conflicts every test here settles.
fn conflicting_repository(root: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let home = root.join("home");
    let repo = root.join("repo");
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
    (repo, home)
}

/// A parked merge is graph truth, not process state. Stopping the daemon and
/// reading again must return the identical record: same identity, same
/// conflicts, still in progress.
#[test]
fn a_parked_merge_survives_a_daemon_restart() {
    let root = tempdir().expect("temp root");
    let (repo, home) = conflicting_repository(root.path());
    let layout = initialize_kin_repo(&repo, &home);

    ok(&run_kin(&repo, &home, &["merge", "feature"]), "kin merge");
    let before = conflicts_report(&repo, &home);
    let before_hash = record_hash(&before);
    assert!(
        before["unresolved_count"].as_u64().expect("a count") >= 2,
        "both the artifact and the entity conflicted: {before}"
    );
    assert_eq!(before["record"]["state"]["state"], "in_progress");

    // The record is authority, so it is on disk before any restart.
    let persisted = persisted_record(&layout).expect("the parked merge is persisted");
    assert_eq!(hex::encode(persisted.hash.as_bytes()), before_hash);

    stop_daemon(&repo, &home);

    let after = conflicts_report(&repo, &home);
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
    let (repo, home) = conflicting_repository(root.path());
    let layout = initialize_kin_repo(&repo, &home);
    ok(&run_kin(&repo, &home, &["merge", "feature"]), "kin merge");

    let stale = record_hash(&conflicts_report(&repo, &home));
    ok(
        &run_kin(&repo, &home, &["resolve", "--all-ours", "--expect", &stale]),
        "first resolution",
    );
    let current = record_hash(&conflicts_report(&repo, &home));
    assert_ne!(current, stale, "settling entries advances the record");

    let refused = run_kin(
        &repo,
        &home,
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
    assert_eq!(record_hash(&conflicts_report(&repo, &home)), current);
    let persisted = persisted_record(&layout).expect("the merge is still parked");
    assert_eq!(hex::encode(persisted.hash.as_bytes()), current);
}

/// Two sessions settling from one view of the record: exactly one wins. The
/// loser is refused rather than silently rebased onto the winner's record.
#[test]
fn concurrent_resolutions_from_one_view_leave_one_winner() {
    let root = tempdir().expect("temp root");
    let (repo, home) = conflicting_repository(root.path());
    let layout = initialize_kin_repo(&repo, &home);
    ok(&run_kin(&repo, &home, &["merge", "feature"]), "kin merge");

    let view = record_hash(&conflicts_report(&repo, &home));
    let first = std::thread::scope(|scope| {
        let ours =
            scope.spawn(|| run_kin(&repo, &home, &["resolve", "--all-ours", "--expect", &view]));
        let theirs = scope.spawn(|| {
            run_kin(
                &repo,
                &home,
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
    assert_ne!(hex::encode(record.hash.as_bytes()), view);
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
    let (repo, home) = conflicting_repository(root.path());
    let layout = initialize_kin_repo(&repo, &home);

    let main_before = branch_change(&layout, "main");
    let feature_before = branch_change(&layout, "feature");
    ok(&run_kin(&repo, &home, &["merge", "feature"]), "kin merge");

    let parked = persisted_record(&layout).expect("the merge is parked");
    assert_eq!(parked.binding.ours_change, main_before);
    assert_eq!(parked.binding.theirs_change, feature_before);

    ok(
        &run_kin(&repo, &home, &["resolve", "--all-theirs"]),
        "settle every conflict",
    );
    let completed = run_kin(&repo, &home, &["resolve", "--continue", "--json"]);
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
    let again = run_kin(&repo, &home, &["resolve", "--continue"]);
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
/// moves no ref, and frees the workspace for the next merge.
#[test]
fn aborting_a_merge_restores_the_workspace_and_frees_the_next_merge() {
    let root = tempdir().expect("temp root");
    let (repo, home) = conflicting_repository(root.path());
    let layout = initialize_kin_repo(&repo, &home);

    let main_before = branch_change(&layout, "main");
    let feature_before = branch_change(&layout, "feature");
    ok(&run_kin(&repo, &home, &["merge", "feature"]), "kin merge");

    let parked = persisted_record(&layout).expect("the merge is parked");
    ok(
        &run_kin(&repo, &home, &["resolve", "--abort"]),
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
    ok(
        &run_kin(&repo, &home, &["merge", "feature"]),
        "merge again after aborting",
    );
    let reopened = conflicts_report(&repo, &home);
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
    let (repo, home) = conflicting_repository(root.path());
    let layout = initialize_kin_repo(&repo, &home);
    ok(&run_kin(&repo, &home, &["merge", "feature"]), "kin merge");
    let parked = record_hash(&conflicts_report(&repo, &home));

    let refused = run_kin(&repo, &home, &["merge", "feature"]);
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
        record_hash(&conflicts_report(&repo, &home)),
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
    let (repo, home) = conflicting_repository(root.path());
    let layout = initialize_kin_repo(&repo, &home);
    ok(&run_kin(&repo, &home, &["merge", "feature"]), "kin merge");

    let before = conflicts_report(&repo, &home);
    let outstanding = before["unresolved_count"].as_u64().expect("a count");
    assert!(outstanding >= 2, "the fixture has more than one conflict");

    ok(
        &run_kin(&repo, &home, &["resolve", "--ours", "shared.txt"]),
        "settle the shared artifact",
    );
    let after = conflicts_report(&repo, &home);
    assert_eq!(
        after["unresolved_count"].as_u64().expect("a count"),
        outstanding - 1,
        "settling one conflict settles exactly one"
    );
    assert_eq!(after["resolved_count"], 1);

    let unknown = run_kin(&repo, &home, &["resolve", "--theirs", "not-a-conflict"]);
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
    let early = run_kin(&repo, &home, &["resolve", "--continue"]);
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
    let (repo, home) = conflicting_repository(root.path());
    initialize_kin_repo(&repo, &home);
    ok(&run_kin(&repo, &home, &["merge", "feature"]), "kin merge");

    let both = run_kin(&repo, &home, &["resolve", "--all-ours", "--continue"]);
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
