// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The operator's background-embedding opt-out, proven against a daemon the CLI
//! actually started.
//!
//! `KIN_DAEMON_AUTO_EMBED` is read by the daemon at its own process start, which
//! makes two different claims worth pinning here. A command that starts a daemon
//! must deliver the opt-out to it, and a command that reaches a daemon it did not
//! start must say that its own setting is not the one in force. The second is the
//! failure an operator actually met: the opt-out was set, the accelerator ran
//! anyway, and nothing distinguished a rejected opt-out from an honoured one.
//!
//! Neither test embeds anything. That is the point of the variable, so a run here
//! that started real inference would be evidence against the feature rather than
//! for it.

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use serial_test::serial;
use tempfile::tempdir;

mod common;

use common::Command;

/// The exact line the daemon emits when an operator deferred the pass.
const DEFERRED: &str = "background embedding deferred by operator opt-out";

/// The line the same decision emits when the pass runs instead. One of the two
/// is always emitted, so asserting on both directions is what makes either
/// assertion mean something.
const STARTED: &str = "background embedding started";

/// Emitted immediately before that decision. It is an `info!`, so finding it
/// proves this log captures info-level records and that the worker reached the
/// decision at all — without it, "no start line" could just mean "no log".
const WORKER_REACHED_THE_DECISION: &str = "embedding worker started";

/// A line no build ever writes. If a search for it succeeds, the search is
/// matching something other than log content and every other verdict here is
/// void.
const FABRICATED_CONTROL: &str = "background embedding deferred by lunar phase";

fn git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .unwrap_or_else(|error| panic!("run git {args:?}: {error}"));
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Seed a one-file repository with a clean Git history, which is what `kin init`
/// admits from.
fn seed_repository(repo: &Path) {
    fs::create_dir_all(repo.join("src")).expect("create src dir");
    fs::write(
        repo.join("src/lib.rs"),
        "pub fn lexer() -> &'static str { \"lexer\" }\n",
    )
    .expect("write source");
    git(repo, &["init", "-q"]);
    git(repo, &["add", "-A"]);
    git(
        repo,
        &[
            "-c",
            "user.name=kin-ci",
            "-c",
            "user.email=ci@kin.dev",
            "commit",
            "-q",
            "-m",
            "seed",
        ],
    );
}

fn kin_command(runtime: &common::IsolatedDaemonRuntime) -> Command<'_> {
    let mut command = runtime.kin_command();
    command
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "60")
        .env("KIN_BYPASS_EMBEDDING_COVERAGE_CHECK", "1");
    command
}

/// Daemon logs carry ANSI colour, and an escape sequence can sit between a field
/// name and its value, so a raw byte search for a phrase can miss text that is
/// plainly there.
fn strip_ansi(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        if character != '\u{1b}' {
            plain.push(character);
            continue;
        }
        for escape in characters.by_ref() {
            if escape.is_ascii_alphabetic() {
                break;
            }
        }
    }
    plain
}

fn daemon_log(kin_root: &Path) -> String {
    fs::read_to_string(kin_root.join("daemon.log"))
        .map(|log| strip_ansi(&log))
        .unwrap_or_default()
}

/// Wait for the daemon to reach its embedding decision, which happens after the
/// first reconciliation cycle rather than at start.
fn wait_for_embedding_decision(kin_root: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let log = daemon_log(kin_root);
        if log.contains(DEFERRED) || log.contains(STARTED) {
            return log;
        }
        assert!(
            Instant::now() < deadline,
            "the daemon never reached its background-embedding decision; log was:\n{log}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
#[serial]
fn a_cli_spawned_daemon_honours_the_background_embed_opt_out() {
    let repo = tempdir().expect("temp repo");
    let runtime = common::IsolatedDaemonRuntime::new(repo.path());
    seed_repository(repo.path());

    // Every command in this flow carries the opt-out, so whichever one ends up
    // starting the daemon delivers it.
    let init = kin_command(&runtime)
        .args(["init", "."])
        .env("KIN_DAEMON_AUTO_EMBED", "0")
        .current_dir(repo.path())
        .output()
        .expect("run kin init");
    assert!(
        init.status.success(),
        "kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let status = kin_command(&runtime)
        .args(["graph", "status"])
        .env("KIN_DAEMON_AUTO_EMBED", "0")
        .current_dir(repo.path())
        .output()
        .expect("run kin graph status");
    assert!(
        status.status.success(),
        "kin graph status failed: stdout={} stderr={}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );

    let log = wait_for_embedding_decision(&repo.path().join(".kin"));
    assert!(
        log.contains(WORKER_REACHED_THE_DECISION),
        "the embedding worker never reached its decision, so nothing below is about the \
         opt-out; log was:\n{log}"
    );
    assert!(
        log.contains(DEFERRED),
        "a CLI-spawned daemon ignored the operator's background-embedding opt-out; log was:\n{log}"
    );
    assert!(
        !log.contains(STARTED),
        "the daemon deferred and started the same pass; log was:\n{log}"
    );
    assert!(
        !log.contains(FABRICATED_CONTROL),
        "a line no build writes was found in the daemon log, so this search proves nothing"
    );
}

/// A command that reaches a daemon it did not start is told its setting is not
/// the one in force.
///
/// The daemon here is started deferred and the later command asks for the
/// default instead, which is the same boundary as the operator's case read in
/// the other direction. Taking it this way round keeps the running daemon
/// deferred for the whole test: staging the operator's exact sequence would mean
/// starting a daemon that embeds, and a test that embeds to prove an opt-out has
/// already lost the plot.
#[test]
#[serial]
fn attaching_to_a_daemon_that_fixed_this_lever_first_says_so() {
    let repo = tempdir().expect("temp repo");
    let runtime = common::IsolatedDaemonRuntime::new(repo.path());
    seed_repository(repo.path());

    for arguments in [["init", "."], ["graph", "status"]] {
        let output = kin_command(&runtime)
            .args(arguments)
            .env("KIN_DAEMON_AUTO_EMBED", "0")
            .current_dir(repo.path())
            .output()
            .unwrap_or_else(|error| panic!("run kin {arguments:?}: {error}"));
        assert!(
            output.status.success(),
            "kin {arguments:?} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let kin_root = repo.path().join(".kin");
    let log = wait_for_embedding_decision(&kin_root);
    assert!(
        log.contains(DEFERRED),
        "the daemon under test did not defer, so this test would be measuring an embedding \
         run; log was:\n{log}"
    );

    // The daemon fixed this lever when it started. This command cannot change
    // it, and the whole defect was that nothing said so.
    let late = kin_command(&runtime)
        .args(["graph", "status"])
        .env("KIN_DAEMON_AUTO_EMBED", "1")
        .current_dir(repo.path())
        .output()
        .expect("run kin graph status");
    assert!(
        late.status.success(),
        "kin graph status failed: stdout={} stderr={}",
        String::from_utf8_lossy(&late.stdout),
        String::from_utf8_lossy(&late.stderr)
    );
    let told = String::from_utf8_lossy(&late.stderr);
    assert!(
        told.contains("KIN_DAEMON_AUTO_EMBED: cli=\"1\" daemon=\"0\""),
        "attaching to a daemon that fixed this command's embedding lever said nothing about \
         it; stderr was:\n{told}"
    );
    assert!(
        told.contains("restart the daemon"),
        "the divergence was reported without the remedy that would apply the setting; stderr \
         was:\n{told}"
    );
    assert!(
        !told.contains(FABRICATED_CONTROL),
        "a phrase no build writes was found on stderr, so this search proves nothing"
    );

    // Nothing above may have started the pass this variable governs.
    let log = daemon_log(&kin_root);
    assert!(
        !log.contains(STARTED),
        "an ignored lever became a real embedding run; log was:\n{log}"
    );
}
