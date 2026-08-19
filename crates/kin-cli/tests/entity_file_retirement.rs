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
//! A unit test on the planner cannot cover this, because the defect is in what
//! survives one whole commit and reaches the next query. These drive `kin`
//! itself and read `kin locate`, which is the surface the stale hit was found
//! on.

use serde_json::Value;
use std::fs;
use std::path::Path;
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
