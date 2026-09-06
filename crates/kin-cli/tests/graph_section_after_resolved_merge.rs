// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What the graph section reads after a merge that PARKED and was then
//! published through `kin resolve --continue`.
//!
//! kin#1561 refreshes this workspace's base graph section after every
//! transition that moves the base, and installed the call at four sites. One of
//! them is `repository_merge::execute`, the plain-merge publication. That
//! module holds two publications: `execute` publishes a clean merge, and
//! `publish_resolved_merge` publishes one whose conflicts were settled, which
//! `kin resolve --continue` reaches through
//! `repository_merge_state::execute_resolve`. The second carried no refresh.
//!
//! Measured on b1837fa59 by a journey walking this repository the way a
//! stranger would: after the first commit, after each branch switch, after a
//! fast-forward merge and after a merge that parked with conflicts, the section
//! read present and current; after `kin resolve --all-ours` and
//! `kin resolve --continue` it read present but refused (`resolved_at`) until
//! `kin graph materialize` was run by hand. So the one way a merge can end that
//! needs a person's attention is also the one way that left the store folding
//! its merged base out of history at every open.
//!
//! This drives the product CLI end to end rather than the daemon's own routes,
//! for the reason [`graph_section_after_transfer`] gives: the state under test
//! is a property of the store on disk rather than of any one process, and
//! kin's `Product Acceptance` job carries
//! `if: ${{ github.event_name != 'pull_request' }}`, so a rule under
//! `scripts/acceptance/` would not grade the pull request that breaks it. The
//! matching daemon-level arm lives beside kin#1287's in `kin-daemon`'s
//! `api.rs`.
//!
//! [`graph_section_after_transfer`]: ../graph_section_after_transfer.rs

use std::fs;
use std::path::Path;
use std::process::Output;

use serde_json::Value;
use tempfile::tempdir;

mod common;

/// The prefix of the one `kin graph status` line this file is about.
const SECTION_PREFIX: &str = "Graph section:";

/// What the line says when an open serves the base from a persisted section.
const SERVING: &str = "present and current at";

fn require_success(output: Output) -> Output {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn run(runtime: &common::IsolatedDaemonRuntime, repo: &Path, args: &[&str]) -> Output {
    runtime
        .kin_command()
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_EMBED_BACKEND", "cpu")
        .current_dir(repo)
        .args(args)
        .output()
        .expect("run isolated Kin command")
}

/// The product's own `Graph section:` line, read from `kin graph status`.
///
/// Read off stdout rather than asserted on a successful exit, because
/// `kin graph status` exits non-zero when it finds a critical graph health
/// issue, and the line is printed either way. A missing line is the one thing
/// that panics, because a surface that fell silent about the state is the
/// defect this whole class is about.
fn graph_section_line(runtime: &common::IsolatedDaemonRuntime, repo: &Path) -> String {
    let output = run(runtime, repo, &["graph", "status"]);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    stdout
        .lines()
        .find(|line| line.starts_with(SECTION_PREFIX))
        .map(str::to_string)
        .unwrap_or_else(|| {
            panic!(
                "kin graph status printed no `{SECTION_PREFIX}` line in {}\nstdout={stdout}\nstderr={}",
                repo.display(),
                String::from_utf8_lossy(&output.stderr)
            )
        })
}

fn assert_serving(line: &str, what: &str) {
    assert!(
        line.contains(SERVING),
        "{what} must serve its workspace base from a persisted section, so no open of it folds \
         history: {line}"
    );
}

/// The change this workspace's base resolves to, as the hex the section line
/// prints.
///
/// `SemanticChangeId` wraps `Hash256`, which wraps `[u8; 32]`, and serde's
/// newtype passthrough serializes all three as an array of 32 numbers rather
/// than as a string, so the hex is built here to compare against the line the
/// product prints.
fn base_change(runtime: &common::IsolatedDaemonRuntime, repo: &Path) -> String {
    let report: Value = serde_json::from_slice(
        &require_success(run(runtime, repo, &["log", "--json", "--count", "1"])).stdout,
    )
    .expect("history JSON");
    let bytes = report["start_change"].as_array().unwrap_or_else(|| {
        panic!(
            "{} reports no workspace base change: {}",
            repo.display(),
            report["start_change"]
        )
    });
    bytes
        .iter()
        .map(|byte| {
            format!(
                "{:02x}",
                byte.as_u64().expect("a change id byte is a number")
            )
        })
        .collect()
}

fn configure_author(repo: &Path) {
    let path = repo.join(".kin/config.toml");
    let mut config = kin_core::KinConfig::load_or_default(&path).unwrap();
    config.default_author =
        Some("Graph Section Resolved Merge Test <graph-section@example.invalid>".to_string());
    config.save(&path).unwrap();
}

fn commit(runtime: &common::IsolatedDaemonRuntime, repo: &Path, message: &str) {
    require_success(run(runtime, repo, &["commit", "-m", message]));
}

/// The journey's own repro, one step at a time, each step naming itself.
///
/// A conflicted merge is the reason this file exists, so the fixture has to
/// produce one rather than hope for one: both branches rewrite the SAME
/// function body after the split, which is what makes `kin merge` park instead
/// of fast-forwarding. `feature` also adds a file `trunk` does not have, so
/// settling every conflict with `--all-ours` still leaves the merge with
/// something to publish rather than composing back to the first parent.
///
/// The steps before the resolution are CONTROLS, not decoration. The commit
/// path and the plain-merge path already refresh the section, and a run where
/// those read as folding is an assertion that broke rather than a defect in the
/// resolve path. The base-moved check is the other control: a section nobody
/// touched, at a base nothing moved, still reads `present and current`, so
/// without it this passes on a tree carrying no fix.
///
/// The refresh is synchronous inside the command that publishes the merge, so
/// the section is read straight after `kin resolve --continue` returns rather
/// than polled. Nothing here waits on a daemon catching up in the background;
/// if the line is wrong at this point it stays wrong until `kin graph
/// materialize` is run by hand, which is exactly the journey's reading.
#[test]
fn a_merge_published_through_resolve_continue_leaves_a_section_serving_its_merged_base() {
    let scratch = tempdir().unwrap();
    let source = scratch.path().join("source");
    let runtime = common::IsolatedDaemonRuntime::new(&source);

    fs::create_dir(&source).unwrap();
    let initialized = kin_core::init_replica(&source, "trunk").unwrap();
    drop(initialized);
    configure_author(&source);
    fs::create_dir(source.join("src")).unwrap();
    fs::write(source.join("src/lib.rs"), b"pub fn answer() -> u8 { 42 }\n").unwrap();
    commit(&runtime, &source, "Add a native source body");
    assert_serving(
        &graph_section_line(&runtime, &source),
        "a store whose own commit refreshed its section",
    );

    require_success(run(&runtime, &source, &["branch", "create", "feature"]));
    require_success(run(&runtime, &source, &["branch", "switch", "feature"]));
    fs::write(source.join("src/lib.rs"), b"pub fn answer() -> u8 { 41 }\n").unwrap();
    fs::write(
        source.join("src/only_on_feature.rs"),
        b"pub fn introduced() -> bool { true }\n",
    )
    .unwrap();
    commit(
        &runtime,
        &source,
        "Edit the answer and add a file on the branch",
    );
    assert_serving(
        &graph_section_line(&runtime, &source),
        "after committing on the branch",
    );

    require_success(run(&runtime, &source, &["branch", "switch", "trunk"]));
    fs::write(source.join("src/lib.rs"), b"pub fn answer() -> u8 { 40 }\n").unwrap();
    commit(
        &runtime,
        &source,
        "Edit the same answer on the default branch",
    );
    let before_merge = base_change(&runtime, &source);
    assert_serving(
        &graph_section_line(&runtime, &source),
        "after diverging the default branch",
    );

    // PRECONDITION, proved rather than assumed: this merge must PARK. A clean
    // merge publishes through `repository_merge::execute`, which the plain
    // merge case in `graph_section_after_transfer` already covers, and would
    // grade nothing here.
    let merge = run(&runtime, &source, &["merge", "feature"]);
    assert_eq!(
        merge.status.code(),
        Some(kin_cli::commands::merge::EXIT_MERGE_CONFLICTED),
        "NOT RUN, precondition unmet rather than property refuted: `kin merge feature` must park \
         with conflicts for this test to reach `publish_resolved_merge`\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&merge.stdout),
        String::from_utf8_lossy(&merge.stderr)
    );

    // A parked merge composed nothing and moved no base, so the section its
    // last commit wrote must still answer. This separates the parking from the
    // publication, so a red reading below names the publication.
    assert_serving(
        &graph_section_line(&runtime, &source),
        "after a merge parked with conflicts",
    );

    require_success(run(&runtime, &source, &["resolve", "--all-ours"]));
    require_success(run(&runtime, &source, &["resolve", "--continue"]));

    let after_merge = base_change(&runtime, &source);
    // CONTROL: the resolution actually moved this workspace's base. Without
    // this the assertion below passes on an untouched section.
    assert_ne!(
        after_merge, before_merge,
        "NOT RUN, precondition unmet: `kin resolve --continue` did not move this workspace's \
         base off {before_merge}, so a section nobody refreshed would still read as serving"
    );

    // THE PROPERTY.
    let line = graph_section_line(&runtime, &source);
    assert_serving(
        &line,
        "a store whose merge was published through `kin resolve --continue`",
    );
    assert!(
        line.contains(&after_merge),
        "the section must describe the merged base the resolution published ({after_merge}): \
         {line}"
    );
    assert!(
        !line.contains(&before_merge),
        "and not the base the workspace held before the merge ({before_merge}): {line}"
    );
}

/// The section a resolved merge leaves has to be on disk, not in the process
/// that wrote it.
///
/// A daemon restart is the ordinary case, and a store whose acceleration does
/// not survive one pays the fold at every open exactly as if nothing had been
/// written. Same reasoning as
/// `a_cold_reopen_of_a_fresh_clone_still_serves_from_its_section`.
#[test]
fn a_cold_reopen_after_a_resolved_merge_still_serves_from_its_section() {
    let scratch = tempdir().unwrap();
    let source = scratch.path().join("source");
    let runtime = common::IsolatedDaemonRuntime::new(&source);

    fs::create_dir(&source).unwrap();
    let initialized = kin_core::init_replica(&source, "trunk").unwrap();
    drop(initialized);
    configure_author(&source);
    fs::create_dir(source.join("src")).unwrap();
    fs::write(source.join("src/lib.rs"), b"pub fn answer() -> u8 { 42 }\n").unwrap();
    commit(&runtime, &source, "Add a native source body");

    require_success(run(&runtime, &source, &["branch", "create", "feature"]));
    require_success(run(&runtime, &source, &["branch", "switch", "feature"]));
    fs::write(source.join("src/lib.rs"), b"pub fn answer() -> u8 { 41 }\n").unwrap();
    fs::write(
        source.join("src/only_on_feature.rs"),
        b"pub fn introduced() -> bool { true }\n",
    )
    .unwrap();
    commit(
        &runtime,
        &source,
        "Edit the answer and add a file on the branch",
    );

    require_success(run(&runtime, &source, &["branch", "switch", "trunk"]));
    fs::write(source.join("src/lib.rs"), b"pub fn answer() -> u8 { 40 }\n").unwrap();
    commit(
        &runtime,
        &source,
        "Edit the same answer on the default branch",
    );

    let merge = run(&runtime, &source, &["merge", "feature"]);
    assert_eq!(
        merge.status.code(),
        Some(kin_cli::commands::merge::EXIT_MERGE_CONFLICTED),
        "NOT RUN, precondition unmet: this merge must park with conflicts\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&merge.stdout),
        String::from_utf8_lossy(&merge.stderr)
    );
    require_success(run(&runtime, &source, &["resolve", "--all-ours"]));
    require_success(run(&runtime, &source, &["resolve", "--continue"]));

    require_success(run(&runtime, &source, &["daemon", "stop"]));
    assert_serving(
        &graph_section_line(&runtime, &source),
        "a resolved merge reopened by a new daemon",
    );
}
