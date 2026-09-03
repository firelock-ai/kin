// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A lock nobody holds is taken; a lock somebody holds is waited on, out loud.
//!
//! `daemon.start.lock` is a create-new sentinel, not an advisory lock, so a kin
//! command killed while it starts a daemon leaves the file behind. Every later
//! command in that repository then waits the whole startup-lock timeout, which
//! defaults to 300 seconds, before it has spoken to any daemon at all. A caller
//! that caps a question below that sees the cap and nothing else: no output, no
//! CPU anywhere, and a store doing no work.
//!
//! Both halves are asserted here because either alone is satisfiable by a broken
//! implementation. Clearing every lock passes the first test and races two
//! spawns for one repository; clearing none passes the second and strands the
//! next question behind a process that has already exited.

use serial_test::serial;
use std::fs;
use std::path::Path;
use std::time::Instant;
use tempfile::tempdir;

mod common;

use common::Command;

fn kin_command(runtime: &common::IsolatedDaemonRuntime) -> Command<'_> {
    let mut cmd = runtime.kin_command();
    cmd.env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "60")
        // The wait this test is about, kept short so a red run fails fast.
        .env("KIN_DAEMON_STARTUP_LOCK_TIMEOUT_SECS", "5")
        .env("KIN_BYPASS_EMBEDDING_COVERAGE_CHECK", "1");
    cmd
}

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

/// A one-file repository with a store, and no daemon serving it.
fn seeded_store(repo: &Path, runtime: &common::IsolatedDaemonRuntime) {
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

    let init = kin_command(runtime)
        .arg("init")
        .arg(".")
        .current_dir(repo)
        .output()
        .expect("run kin init");
    assert!(
        init.status.success(),
        "kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let stop = kin_command(runtime)
        .args(["daemon", "stop"])
        .current_dir(repo)
        .output()
        .expect("run kin daemon stop");
    assert!(
        stop.status.success(),
        "kin daemon stop failed: {}",
        String::from_utf8_lossy(&stop.stderr)
    );
}

/// Write the lock exactly as the CLI writes it, naming `pid` as its holder.
fn plant_startup_lock(repo: &Path, pid: u32) -> std::path::PathBuf {
    let path = repo.join(".kin").join("daemon.start.lock");
    fs::write(
        &path,
        format!("pid={pid} acquired_at={:?}\n", std::time::SystemTime::now()),
    )
    .expect("plant a startup lock");
    path
}

/// A process identifier whose process has exited and been reaped.
#[cfg(unix)]
fn reaped_pid() -> u32 {
    let mut child = std::process::Command::new("sleep")
        .arg("0")
        .spawn()
        .expect("spawn a stand-in for a kin command that died mid-start");
    let pid = child.id();
    child.wait().expect("reap the stand-in");
    pid
}

#[cfg(unix)]
#[test]
#[serial]
fn a_question_behind_a_dead_starters_lock_answers_instead_of_waiting_out_the_budget() {
    let repo = tempdir().expect("temp repo");
    let runtime = common::IsolatedDaemonRuntime::new(repo.path());
    seeded_store(repo.path(), &runtime);

    let lock = plant_startup_lock(repo.path(), reaped_pid());
    let started = Instant::now();
    let locate = kin_command(&runtime)
        .args(["locate", "lexer", "--json"])
        .current_dir(repo.path())
        .output()
        .expect("run kin locate behind an abandoned startup lock");
    let stderr = String::from_utf8_lossy(&locate.stderr).to_string();

    assert!(
        locate.status.success(),
        "a lock whose holder is gone must not stop the question: {stderr}"
    );
    assert!(
        !stderr.contains("timed out waiting for daemon startup lock"),
        "and it must not be waited out either: {stderr}"
    );
    serde_json::from_slice::<serde_json::Value>(&locate.stdout)
        .expect("stdout is still one JSON document");
    assert!(
        !lock.exists(),
        "the abandoned lock is gone once the command that took it over finished"
    );
    // The wait it would have paid is the whole startup-lock timeout, which this
    // test sets to 5 s. The answer arrives without it; the ready wait for the
    // daemon this command starts is a separate, longer bound and is not what is
    // asserted here.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(120),
        "the run must not have sat out a startup-lock wait"
    );
}

#[cfg(unix)]
#[test]
#[serial]
fn a_startup_lock_a_live_command_holds_is_respected_and_named() {
    let repo = tempdir().expect("temp repo");
    let runtime = common::IsolatedDaemonRuntime::new(repo.path());
    seeded_store(repo.path(), &runtime);

    // Outlives the whole wait on purpose. A stand-in that exits mid-test becomes
    // an unreaped corpse, which `process_liveness` calls dead, and the lock this
    // test is about would be freed for the right reason at the wrong moment.
    let mut holder = std::process::Command::new("sleep")
        .arg("300")
        .spawn()
        .expect("spawn a live stand-in for a kin command still starting a daemon");
    let holder_pid = holder.id();
    let lock = plant_startup_lock(repo.path(), holder_pid);

    let locate = kin_command(&runtime)
        .args(["locate", "lexer", "--json"])
        .current_dir(repo.path())
        .output()
        .expect("run kin locate behind a held startup lock");
    let stderr = String::from_utf8_lossy(&locate.stderr).to_string();

    let _ = holder.kill();
    let _ = holder.wait();

    assert!(
        !locate.status.success(),
        "a lock a live command holds must not be taken: {stderr}"
    );
    assert!(
        stderr.contains("timed out waiting for daemon startup lock"),
        "the wait ends at its own bound, with its own cause: {stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "waiting for another kin command (pid {holder_pid}) to finish starting this \
             repository's daemon"
        )),
        "and while it waits it says what it is waiting for, and on whom: {stderr}"
    );
    assert!(
        fs::read_to_string(&lock)
            .expect("the held lock is still there")
            .contains(&format!("pid={holder_pid}")),
        "the live holder's lock is left exactly as it was"
    );
}
