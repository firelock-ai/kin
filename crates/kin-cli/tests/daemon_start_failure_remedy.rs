// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The recovery ladder's bottom rung carries a remedy.
//!
//! Walked end to end on 2026-08-30 against the v0.6.2 candidate, on a host with
//! five language servers checked by name and none installed. Rung one named the
//! cap, the kill count and a recovery. Doing what it said landed on rung two: a
//! cause, a log tail, and nothing to try next. Rung three did what rung two
//! said and failed identically. Four OOM kills for a lever already at the end
//! it was being moved to.
//!
//! A ladder whose bottom rung is silent is a ladder a user cannot get off, and
//! on this failure each attempt costs another kill.
//!
//! ## Which failure this drives, and which it deliberately cannot
//!
//! `resolve_daemon_url_inner` attaches the new context to every `AutoStartError`
//! except `IncompatibleStore` and `BehaviorEnvIgnored`, which keep their own
//! headline because for them the daemon is a consequence rather than the story.
//! So **`incompatible_store_wall.rs` cannot be extended to cover this**: its
//! pre-v2 store takes one of the two excluded arms and never reaches the code
//! under test here. The next person to look for a cheap fixture will find that
//! one first, which is why it is named.
//!
//! What this drives instead is `SpawnFailed`, forced with a `KIN_DAEMON_BIN`
//! that does not exist. It is one env var, it is deterministic, and it reaches
//! the same arm.
//!
//! ## What is NOT measured here
//!
//! That the remedy is right on a REAL out-of-memory kill. Forcing one needs a
//! converted store of real size inside a memory cgroup, which is a container
//! and a Linux archive rather than a cargo test. The three rungs were walked by
//! hand on the v0.6.2 candidate and recorded in
//! `.kin-coord/reports/initmem-20260829.md`; the confirmation on patched bytes
//! comes from the next Linux archive. This test grades the wiring: that a
//! daemon which cannot start says what to do about it.

use serial_test::serial;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::Command;

fn git(repo: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .unwrap_or_else(|error| panic!("git {args:?}: {error}"));
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A pid this test has watched exit, so "not running" is observed rather than
/// assumed. Picking a high number and hoping is how a flake gets written.
fn a_pid_that_is_certainly_gone() -> u32 {
    let mut child = std::process::Command::new("true")
        .spawn()
        .expect("spawn a process that exits immediately");
    let pid = child.id();
    child.wait().expect("reap it");
    pid
}

#[test]
#[serial]
fn a_daemon_that_cannot_start_still_names_a_remedy() {
    let repo = tempdir().expect("temp repo");
    let runtime = common::IsolatedDaemonRuntime::new(repo.path());
    fs::create_dir_all(repo.path().join("src")).expect("create src dir");
    fs::write(
        repo.path().join("src/lib.rs"),
        "pub fn lexer() -> &'static str { \"lexer\" }\n",
    )
    .expect("write source");
    git(repo.path(), &["init", "-q"]);
    git(repo.path(), &["add", "-A"]);
    git(
        repo.path(),
        &[
            "-c",
            "user.email=kin@example.invalid",
            "-c",
            "user.name=Kin",
            "commit",
            "-q",
            "-m",
            "first",
        ],
    );

    let init = runtime
        .kin_command()
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "120")
        .arg("init")
        .arg(repo.path())
        .output()
        .expect("run kin init");
    assert!(
        init.status.success(),
        "the fixture needs a real store: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let kin_root = repo.path().join(".kin");

    // Stop whatever init started, so the next command pays for a start rather
    // than attaching to a live daemon and never reaching the code under test.
    runtime
        .kin_command()
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .args(["daemon", "stop"])
        .current_dir(repo.path())
        .output()
        .expect("stop the daemon init started");

    // A serving record naming a dead pid is what `peek_unwatched_daemon_death`
    // grades, and it is the same shape the init-budget acceptance suite seeds
    // for the same reason: an unwatched death leaves no other trace.
    let gone = a_pid_that_is_certainly_gone();
    fs::write(
        kin_daemon_spawn::serving_path(&kin_root),
        format!(r#"{{"pid":{gone},"oom_kills_at_start":null,"at_unix":4320}}"#),
    )
    .expect("seed a serving record for a dead daemon");

    let output = runtime
        .kin_command()
        .env("KIN_DAEMON_BIN", repo.path().join("no-such-kin-daemon"))
        .args(["locate", "lexer"])
        .current_dir(repo.path())
        .output()
        .expect("run a daemon-backed command with no daemon binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a command that cannot start a daemon must refuse: stdout={} stderr={stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("kin daemon is required"),
        "the headline still names what is missing: {stderr}"
    );

    // The whole point. Before this fix the message ended at the cause.
    assert!(
        stderr.contains("To recover:"),
        "the bottom rung of the ladder carries no remedy, which is the defect: {stderr}"
    );
    assert!(
        stderr.contains("kin doctor"),
        "and it names where to read this store's headroom: {stderr}"
    );
}
