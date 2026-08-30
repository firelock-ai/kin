// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin init --history-limit N` takes in part of a Git history, and says so.
//!
//! The tests here are paired on purpose. Every assertion about a bounded
//! conversion has a whole-history twin over the same fixture, because the
//! defect that would matter most is not a bound that fails to cut, it is a
//! default that silently cuts. A store missing history nobody asked to drop
//! looks exactly like a store that has it, and nothing downstream would
//! notice: the counts are self-consistent, every proof passes, and the only
//! evidence is history that is not there.
//!
//! The fixture carries a merge on purpose. A first-parent window is a chain, so
//! a side branch merged into it is reachable Git history the window does not
//! admit, and it has to be recorded as an unadmitted parent rather than
//! silently dropped.

use std::path::Path;
use std::process::Command;

/// Commits on the fixture's mainline before the side branch is merged.
const TRUNK_COMMITS: usize = 8;

/// Commits admitted by the bounded arm.
///
/// Small enough to leave real history outside the window and large enough to
/// contain the merge, so the bounded arm exercises both edges: the mainline
/// cut at the oldest admitted commit, and a merge parent outside the window.
const LIMIT: usize = 4;

fn git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(repo)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Kin Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@firelock.ai")
        .env("GIT_COMMITTER_NAME", "Kin Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@firelock.ai")
        .output()
        .unwrap_or_else(|error| panic!("git {args:?} failed to start: {error}"));
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn commit(repo: &Path, name: &str, body: &str) {
    std::fs::write(repo.join(format!("src/{name}.rs")), body.as_bytes()).unwrap();
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-m", &format!("add {name}")]);
}

/// A history with a mainline, a side branch, and a merge back into it.
///
/// Returns the total number of commits, counted from Git rather than from the
/// arithmetic above, so a fixture that does not build what this file claims
/// fails here rather than inside an assertion about Kin.
fn build_history(repo: &Path) -> usize {
    std::fs::create_dir_all(repo.join("src")).unwrap();
    git(repo, &["init", "--initial-branch=main"]);
    git(repo, &["config", "user.name", "Kin Fixture"]);
    git(repo, &["config", "user.email", "fixture@firelock.ai"]);

    for index in 0..TRUNK_COMMITS {
        commit(
            repo,
            &format!("trunk_{index}"),
            &format!("pub struct Trunk{index} {{ pub field: u32 }}\n"),
        );
    }

    git(repo, &["checkout", "-b", "side"]);
    commit(repo, "side_one", "pub struct SideOne { pub field: u32 }\n");
    commit(repo, "side_two", "pub struct SideTwo { pub field: u32 }\n");
    git(repo, &["checkout", "main"]);
    git(repo, &["merge", "--no-ff", "-m", "merge side", "side"]);
    commit(repo, "after_merge", "pub struct After { pub field: u32 }\n");

    let listed = Command::new("git")
        .current_dir(repo)
        .args(["rev-list", "--all", "--count"])
        .output()
        .expect("count fixture commits");
    String::from_utf8_lossy(&listed.stdout)
        .trim()
        .parse()
        .expect("git prints a commit count")
}

fn source(workspace: &Path) -> std::path::PathBuf {
    let repo = workspace.join("source");
    std::fs::create_dir(&repo).unwrap();
    repo
}

/// Whole history is what a conversion that says nothing takes in.
///
/// The control for every bounded assertion below, and the one that would catch
/// a default that started bounding.
#[test]
fn the_default_conversion_admits_every_commit_and_records_no_boundary() {
    let workspace = tempfile::tempdir().unwrap();
    let repo = source(workspace.path());
    let total = build_history(&repo);
    let repo = repo.canonicalize().unwrap();

    let result = kin_core::init_from_git(&repo).expect("admit the fixture repository");

    assert_eq!(
        result.authority.semantic_enrichment.semantic_change_count, total,
        "the default takes in every one of the fixture's {total} commits"
    );
    assert_eq!(
        result.manifest.history_boundary, None,
        "a whole-history conversion records no boundary, so a reader is never told its history \
         is incomplete when it is not"
    );
    assert_eq!(
        kin_core::history_boundary_for(&result.layout),
        None,
        "and the durable manifest agrees with the value the conversion returned"
    );
}

/// The same fixture through the options-taking entry point, with no bound.
///
/// Separate from the test above because they can fail apart: the default could
/// be right while the path a bounded conversion takes is wrong even when it is
/// handed no bound, which is the shape where `--history-limit` with no value
/// would quietly cut.
#[test]
fn the_options_entry_point_with_no_limit_is_the_default() {
    let workspace = tempfile::tempdir().unwrap();
    let repo = source(workspace.path());
    let total = build_history(&repo);
    let repo = repo.canonicalize().unwrap();

    let result = kin_core::init_from_git_with_options(
        &repo,
        None,
        kin_core::GitAdmissionOptions::default(),
    )
    .expect("admit the fixture repository");

    assert_eq!(
        result.authority.semantic_enrichment.semantic_change_count, total,
        "the default options take in every commit"
    );
    assert_eq!(result.manifest.history_boundary, None);
}

/// A bound admits exactly what it asked for, and records where it stopped.
#[test]
fn a_bounded_conversion_admits_the_window_and_records_its_edge() {
    let workspace = tempfile::tempdir().unwrap();
    let repo = source(workspace.path());
    let total = build_history(&repo);
    let repo = repo.canonicalize().unwrap();
    assert!(
        total > LIMIT,
        "the fixture must have more history than the bound, or this test proves nothing"
    );

    let result = kin_core::init_from_git_with_options(
        &repo,
        None,
        kin_core::GitAdmissionOptions {
            history_limit: kin_core::HistoryLimit::from_count(LIMIT),
        },
    )
    .expect("admit the fixture repository under a history limit");

    assert_eq!(
        result.authority.semantic_enrichment.semantic_change_count, LIMIT,
        "a first-parent window of {LIMIT} admits exactly {LIMIT} commits, which is the whole \
         reason the window is first-parent"
    );

    let boundary = result
        .manifest
        .history_boundary
        .as_ref()
        .expect("a conversion that cut history records where it cut");
    assert_eq!(boundary.requested_limit, LIMIT);
    assert_eq!(boundary.admitted_commits, LIMIT);
    assert!(
        !boundary.oldest_admitted_commit.is_empty(),
        "the boundary names the commit admitted history starts at"
    );
    assert!(
        !boundary.unadmitted_parents.is_empty(),
        "cutting {LIMIT} commits out of {total} leaves at least the mainline parent unadmitted"
    );

    // The durable record, read back off disk rather than from the value the
    // call returned, because the manifest is what every later command reads.
    let durable = kin_core::history_boundary_for(&result.layout)
        .expect("the boundary is durable, not just returned");
    assert_eq!(&durable, boundary);
    assert!(
        durable.summary().contains("are not in the semantic graph"),
        "the durable summary says what was left out rather than implying nothing was: {}",
        durable.summary()
    );
}

/// The merge in the fixture puts a side-branch commit outside a small window,
/// and it is recorded rather than dropped.
#[test]
fn a_side_branch_outside_the_window_is_recorded_as_unadmitted() {
    let workspace = tempfile::tempdir().unwrap();
    let repo = source(workspace.path());
    build_history(&repo);
    let repo = repo.canonicalize().unwrap();

    // Two commits back from HEAD is the merge itself, whose second parent is
    // the side branch and is therefore outside any first-parent window.
    let result = kin_core::init_from_git_with_options(
        &repo,
        None,
        kin_core::GitAdmissionOptions {
            history_limit: kin_core::HistoryLimit::from_count(2),
        },
    )
    .expect("admit the fixture repository under a history limit");

    let boundary = result
        .manifest
        .history_boundary
        .expect("a conversion that cut history records where it cut");
    assert_eq!(boundary.admitted_commits, 2);
    assert!(
        boundary.unadmitted_parents.len() >= 2,
        "a window ending on a merge leaves both the mainline parent and the side branch \
         unadmitted, and both are recorded: {:?}",
        boundary.unadmitted_parents
    );
}

/// Asking for more history than a repository has is not a boundary.
#[test]
fn a_limit_larger_than_the_history_admits_all_of_it_and_records_nothing() {
    let workspace = tempfile::tempdir().unwrap();
    let repo = source(workspace.path());
    let total = build_history(&repo);
    let repo = repo.canonicalize().unwrap();

    let result = kin_core::init_from_git_with_options(
        &repo,
        None,
        kin_core::GitAdmissionOptions {
            history_limit: kin_core::HistoryLimit::from_count(total * 10),
        },
    )
    .expect("admit the fixture repository");

    assert_eq!(
        result.authority.semantic_enrichment.semantic_change_count, total,
        "a limit nothing binds admits every commit"
    );
    assert_eq!(
        result.manifest.history_boundary, None,
        "reporting a boundary here would tell an operator their history is incomplete at the \
         exact moment all of it was admitted"
    );
}
