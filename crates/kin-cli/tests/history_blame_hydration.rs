// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end proof that `history` and `blame` report ref hydration honestly.
//! Resolving either command at an unimported Git ref lazily walks
//! and imports that ref's ancestry into the graph. That import must surface as
//! a truthful `hydrated_changes` count — a cold multi-change import and a warm
//! no-op are not the same event — instead of the old swallowed boolean. This
//! mirrors the shadow-review hydration contract proven in
//! `review_shadow_json.rs` (PR #256), applied to the two commands that share
//! the same resolving path.

use kin_cli::commands::blame::{execute_blame_request, BlameRequest};
use kin_cli::commands::history::{execute_history_request, HistoryRequest};
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::Command;

fn kin_command() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kin"));
    cmd.env("KIN_DAEMON_BIN", common::fresh_daemon_bin());
    cmd
}

fn run_git(repo: &Path, args: &[&str]) {
    let mut cmd = Command::new("git");
    cmd.args(args).current_dir(repo);
    // Fixture commits carry explicit, strictly increasing timestamps so ancestry
    // ordering never depends on git's one-second timestamp granularity.
    if args.first() == Some(&"commit") {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COMMIT_EPOCH: AtomicU64 = AtomicU64::new(1_000_000_000);
        let date = format!("{} +0000", COMMIT_EPOCH.fetch_add(100, Ordering::Relaxed));
        cmd.env("GIT_AUTHOR_DATE", &date)
            .env("GIT_COMMITTER_DATE", &date);
    }
    let output = cmd.output().expect("run git");
    assert!(
        output.status.success(),
        "git {:?} failed: stdout={} stderr={}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_head(repo: &Path) -> String {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo)
        .output()
        .expect("git rev-parse HEAD");
    assert!(output.status.success(), "git rev-parse HEAD failed");
    String::from_utf8(output.stdout)
        .expect("utf8 git head")
        .trim()
        .to_string()
}

fn kin_init(repo: &Path) {
    let init = kin_command()
        .arg("init")
        .current_dir(repo)
        .output()
        .expect("run kin init");
    assert!(
        init.status.success(),
        "kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
}

/// A two-commit Rust repo whose head defines a resolvable `pub fn` entity
/// (`compute_total`) with recorded revision history — enough for both `history`
/// and `blame` to render at the head ref. Returns the head commit oid.
fn setup_history_fixture(repo: &Path) -> String {
    std::fs::create_dir_all(repo.join("src")).expect("create src");
    std::fs::write(
        repo.join("src/billing.rs"),
        "pub fn compute_total(amount: u64) -> u64 {\n    amount + fee()\n}\n\nfn fee() -> u64 {\n    3\n}\n",
    )
    .expect("write billing.rs");
    std::fs::write(repo.join("src/lib.rs"), "pub mod billing;\n").expect("write lib.rs");

    run_git(repo, &["init"]);
    run_git(
        repo,
        &["config", "user.email", "hydration-test@example.com"],
    );
    run_git(repo, &["config", "user.name", "Hydration Test"]);
    run_git(repo, &["add", "-A"]);
    run_git(repo, &["commit", "-m", "base: compute_total"]);

    std::fs::write(
        repo.join("src/billing.rs"),
        "pub fn compute_total(amount: u64, currency: &str) -> u64 {\n    let _ = currency;\n    amount + fee()\n}\n\nfn fee() -> u64 {\n    3\n}\n",
    )
    .expect("rewrite billing.rs");
    run_git(repo, &["add", "-A"]);
    run_git(
        repo,
        &["commit", "-m", "head: add currency to compute_total"],
    );

    git_head(repo)
}

/// Cold import then warm re-resolve, both `history` and `blame`, on one graph:
/// the first resolve at an unimported head walks git ancestry and must report a
/// truthful non-zero `hydrated_changes`; every later resolve against the now
/// already-present head must report exactly zero. Proves the count is never
/// collapsed to a "did anything hydrate" boolean in either command.
#[test]
fn history_and_blame_report_hydration_count_honestly() {
    let dir = tempdir().expect("tempdir");
    let repo = dir.path();
    let head = setup_history_fixture(repo);
    kin_init(repo);

    // Fresh in-memory graph: the git commits exist on disk but no ref is
    // imported as a semantic change yet, so the first resolve must hydrate.
    let layout = kin_core::KinLayout::new(repo.join(".kin"));
    let graph = kin_db::InMemoryGraph::new();

    // Cold import via `history`: walks genesis..head, inserting real changes.
    let cold_history = execute_history_request(
        &layout,
        &graph,
        &HistoryRequest {
            entity: "compute_total".to_string(),
            reference: Some(head.clone()),
        },
    )
    .expect("history resolves and cold-imports the head ref");
    assert!(
        cold_history.hydrated_changes > 0,
        "cold history import must report a nonzero hydrated_changes count, got {}",
        cold_history.hydrated_changes
    );
    assert!(
        cold_history
            .response
            .lines
            .iter()
            .any(|line| line.contains("History for")),
        "history output must render the entity header: {:?}",
        cold_history.response.lines
    );

    // Warm re-resolve via `history`: the head is already present, so this
    // imports nothing and must report exactly zero — not a falsy flag.
    let warm_history = execute_history_request(
        &layout,
        &graph,
        &HistoryRequest {
            entity: "compute_total".to_string(),
            reference: Some(head.clone()),
        },
    )
    .expect("warm history resolve takes the fast path");
    assert_eq!(
        warm_history.hydrated_changes, 0,
        "warm history resolve (already imported) must report exactly zero hydrated changes"
    );

    // `blame` shares the same resolving path; against the now-warm graph it too
    // must report exactly zero hydrated changes while still rendering output.
    let warm_blame = execute_blame_request(
        &layout,
        &graph,
        &BlameRequest {
            entity: "compute_total".to_string(),
            reference: Some(head.clone()),
        },
    )
    .expect("blame resolves against the warm graph");
    assert_eq!(
        warm_blame.hydrated_changes, 0,
        "warm blame resolve (already imported) must report exactly zero hydrated changes"
    );
    assert!(
        warm_blame
            .response
            .lines
            .iter()
            .any(|line| line.contains("Blame for")),
        "blame output must render the entity header: {:?}",
        warm_blame.response.lines
    );
}
