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
use std::time::{Duration, Instant};
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

/// Bound on how long the relocation commit's caller edge may take to reach
/// `kin refs`, and how often to ask again while waiting.
///
/// The daemon's live query graph catches up to a commit asynchronously, and a
/// read taken right after `kin commit` returns can measure that catch-up
/// instead of the relocation. CI run 34000661616 (kin main 75ffe8933, `Check &
/// Test ubuntu shard (1)`, panicked at entity_file_retirement.rs:277 on
/// 2026-09-06T00:26:01Z after a 7.306s test) read `kin refs moved_target`
/// immediately after this same relocation commit and got "No incoming Calls,
/// Imports, References relations", qualified with "Kin cannot rule out
/// references it did not see: this build produced no entity-level call edge
/// for Python although the source carries call sites". That is not a
/// permanent absence: the identical query is asserted to hold both before this
/// commit (`references_before`, above) and on ordinary runs after it, so the
/// qualifier was disclosing a graph still mid-catch-up rather than a real gap.
///
/// How long that catch-up takes is itself load-sensitive: this test passed in
/// 4.95s run alone, and with a 30s bound it still timed out when run alongside
/// three sibling tests in this file (each spinning up its own daemon) plus an
/// unrelated build sharing the machine. Ninety seconds covers that kind of
/// shared-box contention and stays well short of `COMMAND_TIMEOUT`.
const RELOCATED_CALLER_EDGE_TIMEOUT: Duration = Duration::from_secs(90);
const RELOCATED_CALLER_EDGE_POLL: Duration = Duration::from_millis(100);

/// Poll `kin refs entity` until its text contains `needle`, bounded by
/// [`RELOCATED_CALLER_EDGE_TIMEOUT`].
///
/// This retries the exact command and the exact fact the test asserts on,
/// never a side channel, so a caller edge that is genuinely gone still fails
/// below, just after the catch-up window instead of on whichever read the
/// daemon's scheduler happened to win.
fn wait_for_reference(
    runtime: &common::IsolatedDaemonRuntime,
    repo: &Path,
    entity: &str,
    needle: &str,
) -> String {
    let deadline = Instant::now() + RELOCATED_CALLER_EDGE_TIMEOUT;
    loop {
        let text = references_text(runtime, repo, entity);
        if text.contains(needle) || Instant::now() >= deadline {
            return text;
        }
        std::thread::sleep(RELOCATED_CALLER_EDGE_POLL);
    }
}

/// Renaming a committed entity-owning file with a bare `mv`, then committing.
///
/// The incoming-edge assertion is the point of this test, not decoration. A
/// relocation implemented as a removal plus an addition would satisfy every
/// path assertion here and still mint new entity ids, orphaning every reference
/// into the moved function, which `mcp_commit.rs` argues against in the same
/// words. Only the caller attribution can see that, so it is checked before and
/// after and required to be unchanged.
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

    let references_after = wait_for_reference(&runtime, &repo, "moved_target", "src/caller.py");
    assert!(
        references_after.contains("src/caller.py"),
        "the caller lost its edge into the moved function, which is what a removal plus an \
         addition does and what relocating in one delta exists to prevent, even after waiting up \
         to {RELOCATED_CALLER_EDGE_TIMEOUT:?} for the daemon's derived reference graph to catch up \
         with the relocation commit: {references_after}"
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
