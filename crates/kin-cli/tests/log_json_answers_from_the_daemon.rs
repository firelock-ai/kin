// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin log --json` answers from a running daemon, and answers identically.
//!
//! The cost it was paying, measured on a converted psf/requests store on
//! 2026-09-05: `kin log --json --count 2` took 11.04 seconds and 3,491,976 KiB
//! of peak resident set for two entries, because the `--json` arm was gated out
//! of the daemon route and opened the whole store in the CLI process. An open
//! re-verifies every persisted body against its content address, so it costs
//! whatever the store is worth, while the daemon that could have answered holds
//! one open per publication.
//!
//! What `--json` may not do is print a peer's bytes as its own, so the two arms
//! here are one test rather than two: the daemon-served answer must be byte for
//! byte what this build prints from its own open. The no-daemon arm is also the
//! control for the log reading. Both arms search the same stderr for the same
//! phrase, and it MUST be found in the arm that opens, or the arm that must not
//! open is searching stderr that carries no authority lines at all and proves
//! nothing.

use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::Command;

/// The phrase every whole-store authority open logs about itself.
///
/// `kin_core::open_persisted_local_repository_authority` is the funnel every
/// path into kin-db's recovery reaches, and it logs this at info with the caller
/// that asked. Matched on the sentence rather than on a file and line, which
/// move, and which a Windows `Location::file()` spells with backslashes.
const AUTHORITY_OPEN: &str = "re-verifies every persisted body";

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

/// One `kin` run with authority attribution turned on.
///
/// `RUST_LOG` wins over the per-command defaults this binary installs, so the
/// open lines are here whether or not a plain `kin log` would print them. That
/// is what makes the absence in the served arm a reading rather than a silence.
fn run_kin(
    runtime: &common::IsolatedDaemonRuntime,
    repo: &Path,
    args: &[&str],
    daemon: Daemon,
) -> std::process::Output {
    let mut command = runtime.kin_command();
    command
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("RUST_LOG", "kin_cli=info,kin_core=info")
        .current_dir(repo);
    match daemon {
        Daemon::Resolved => command.env_remove("KIN_DAEMON_URL"),
        // An empty endpoint is this CLI's own way of saying "no daemon", and it
        // is why this arm needs no `daemon stop`: stopping one leaves a race
        // with whatever restarts it, and this cannot be raced.
        //
        // Through `fixture_daemon_url` rather than `env`, because the harness
        // scrubs inherited Kin authority from every fixture command and
        // `KIN_DAEMON_URL` set the ordinary way does not survive it. Set that
        // way, this arm quietly resolved the runtime's own daemon and answered
        // from it, which is a control that cannot fail.
        Daemon::None => command.fixture_daemon_url(""),
    };
    command.output().expect("run kin")
}

#[derive(Clone, Copy)]
enum Daemon {
    Resolved,
    None,
}

fn require_kin(
    runtime: &common::IsolatedDaemonRuntime,
    repo: &Path,
    args: &[&str],
    daemon: Daemon,
) -> std::process::Output {
    let output = run_kin(runtime, repo, args, daemon);
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
    require_git(repo, &["add", "--all"]);
    require_git(repo, &["commit", "-m", "first commit"]);
    require_kin(runtime, repo, &["init", ".", "--json"], Daemon::Resolved);
}

/// Falsify by gating the daemon route on `!json` in `kin_cli::commands::log`,
/// which is what the shipped command did: the served arm then opens the whole
/// store too, and its stderr carries the same line the control arm's does.
#[test]
fn a_json_log_answers_from_the_daemon_without_opening_the_store_itself() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);

    // A change of its own, so the log has an entry to report and the two arms
    // are comparing a real answer rather than an empty one.
    fs::write(repo.join("src/added.rs"), b"pub fn added() -> u8 { 3 }\n").expect("add source");
    require_kin(
        &runtime,
        &repo,
        &["commit", "-m", "publish added source"],
        Daemon::Resolved,
    );

    let served = require_kin(
        &runtime,
        &repo,
        &["log", "--json", "--count", "2"],
        Daemon::Resolved,
    );
    let opened = require_kin(
        &runtime,
        &repo,
        &["log", "--json", "--count", "2"],
        Daemon::None,
    );

    let served_log = String::from_utf8_lossy(&served.stderr).into_owned();
    let opened_log = String::from_utf8_lossy(&opened.stderr).into_owned();

    // Non-vacuity first. Without this the absence below would pass on a run that
    // logged nothing at all.
    assert!(
        opened_log.contains(AUTHORITY_OPEN),
        "a `--json` log with no daemon must open the store and say so, or this test cannot see \
         an open at all: {opened_log}"
    );
    assert!(
        !served_log.contains(AUTHORITY_OPEN),
        "a `--json` log a running daemon answered must not open the whole store in the CLI: \
         {served_log}"
    );

    // The report is a contract with a machine reader, so routing it through the
    // daemon may change what it costs and nothing else.
    assert_eq!(
        String::from_utf8_lossy(&served.stdout),
        String::from_utf8_lossy(&opened.stdout),
        "a daemon-answered `--json` log must print exactly what this build prints from its own \
         open"
    );
    let report: serde_json::Value =
        serde_json::from_slice(&served.stdout).expect("a `--json` log emits JSON");
    assert_eq!(
        report["schema"], "kin.log.v1",
        "the answer compared above must be a real report: {report}"
    );
    assert!(
        report["entries"]
            .as_array()
            .is_some_and(|entries| !entries.is_empty()),
        "the answer compared above must carry the change this test committed: {report}"
    );
}
