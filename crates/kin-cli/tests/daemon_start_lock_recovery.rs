// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A lock nobody holds is taken; a lock somebody holds is waited on, out loud.
//!
//! `daemon.start.lock` is a create-new sentinel, not an advisory lock, so a kin
//! command killed while it starts a daemon leaves the file behind. Every later
//! command in that repository then waits the whole startup-lock timeout before
//! it has spoken to any daemon. A caller that caps a question below that sees
//! the cap and nothing else: no output, no CPU anywhere, and a store doing no
//! work.
//!
//! Three shapes are asserted, because each is satisfiable by an implementation
//! that gets the others right. A holder that exited must not stop the question.
//! A holder whose PID the kernel handed to another program must not stop it
//! either, which liveness alone cannot see. And a holder that is genuinely a
//! live kin start must be waited on, named on stderr, and left alone however old
//! its lock file is, because two spawns racing for one repository is worse than
//! a wait.
//!
//! Unix only, and the whole file is gated rather than each test: the live-holder
//! arms need a process whose executable this session can place and name, and the
//! Windows authority legs build `-p kin-cli --lib`, so nothing here runs there.
#![cfg(unix)]

use serial_test::serial;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
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
fn plant_startup_lock(repo: &Path, pid: u32) -> PathBuf {
    let path = repo.join(".kin").join("daemon.start.lock");
    fs::write(
        &path,
        format!("pid={pid} acquired_at={:?}\n", SystemTime::now()),
    )
    .expect("plant a startup lock");
    path
}

/// A process identifier whose process has exited and been reaped.
fn reaped_pid() -> u32 {
    let mut child = std::process::Command::new("sleep")
        .arg("0")
        .spawn()
        .expect("spawn a stand-in for a kin command that died mid-start");
    let pid = child.id();
    child.wait().expect("reap the stand-in");
    pid
}

/// Environment variable that turns the fixture test below into a process that
/// holds still, so a test can point a lock at it.
const HOLD_AS_LOCK_HOLDER: &str = "KIN_TEST_HOLD_AS_STARTUP_LOCK_HOLDER";

/// A long-lived process whose executable is named the way Kin's binaries are.
///
/// Outlives the whole test on purpose, three times over. A stand-in that exits
/// becomes an unreaped corpse, which reads as dead; a stand-in still called
/// `sleep` reads as a foreign image; and macOS kills a copy of a signed system
/// binary outright, so `sleep` cannot simply be copied under a kin name. What
/// does work is this test binary, which is ours and runs from anywhere: copy it
/// under a kin-shaped name and re-run it against the fixture test below, which
/// waits and touches nothing.
fn spawn_kin_named_holder(dir: &Path) -> std::process::Child {
    let holder = dir.join("kin-startup-lock-fixture");
    fs::copy(
        std::env::current_exe().expect("this test binary is on disk"),
        &holder,
    )
    .expect("copy this test binary under a kin-shaped name");
    fs::set_permissions(&holder, fs::Permissions::from_mode(0o755))
        .expect("make the fixture executable");
    std::process::Command::new(&holder)
        .args([
            "--exact",
            "a_held_startup_lock_fixture_that_waits",
            "--nocapture",
        ])
        .env(HOLD_AS_LOCK_HOLDER, "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn a live stand-in for a kin command still starting a daemon")
}

/// Instant in an ordinary run; a process that waits when a test asked for one.
/// It never touches a store, a lock or a daemon.
#[test]
fn a_held_startup_lock_fixture_that_waits() {
    if std::env::var(HOLD_AS_LOCK_HOLDER).is_err() {
        return;
    }
    std::thread::sleep(Duration::from_secs(120));
}

/// Age the lock file so the staleness rule would fire on it.
fn age_lock(path: &Path, by: Duration) {
    let when = SystemTime::now() - by;
    let file = fs::File::options()
        .write(true)
        .open(path)
        .expect("open the lock to age it");
    file.set_times(fs::FileTimes::new().set_accessed(when).set_modified(when))
        .expect("age the lock file");
}

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
    assert!(
        started.elapsed() < Duration::from_secs(120),
        "the run must not have sat out a startup-lock wait"
    );
}

/// The reused-PID case. The recorded holder exited, the kernel handed its number
/// to something else, and liveness reports that something else as alive. Only
/// the image behind the number separates the two.
#[test]
#[serial]
fn a_question_behind_a_recycled_pids_lock_answers_instead_of_waiting_out_the_budget() {
    let repo = tempdir().expect("temp repo");
    let runtime = common::IsolatedDaemonRuntime::new(repo.path());
    seeded_store(repo.path(), &runtime);

    let mut squatter = std::process::Command::new("sleep")
        .arg("300")
        .spawn()
        .expect("spawn a live process running an image that is not ours");
    let lock = plant_startup_lock(repo.path(), squatter.id());

    let locate = kin_command(&runtime)
        .args(["locate", "lexer", "--json"])
        .current_dir(repo.path())
        .output()
        .expect("run kin locate behind a lock whose pid was reused");
    let stderr = String::from_utf8_lossy(&locate.stderr).to_string();

    let _ = squatter.kill();
    let _ = squatter.wait();

    assert!(
        locate.status.success(),
        "a live pid running a foreign image is not a holder: {stderr}"
    );
    assert!(
        !stderr.contains("timed out waiting for daemon startup lock"),
        "and must not be waited out: {stderr}"
    );
    serde_json::from_slice::<serde_json::Value>(&locate.stdout)
        .expect("stdout is still one JSON document");
    assert!(!lock.exists(), "the squatter's lock was taken over");
}

#[test]
#[serial]
fn a_startup_lock_a_live_kin_command_holds_is_respected_and_named() {
    let repo = tempdir().expect("temp repo");
    let runtime = common::IsolatedDaemonRuntime::new(repo.path());
    seeded_store(repo.path(), &runtime);

    // Outside the repository: this fixture is a copy of a test binary, and the
    // store under test must not be asked to admit one.
    let holder_home = tempdir().expect("temp dir for the holder fixture");
    let mut holder = spawn_kin_named_holder(holder_home.path());
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
        "a lock a live kin command holds must not be taken: {stderr}"
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
        stderr.contains("of 5s"),
        "the line says when the wait gives up: {stderr}"
    );
    assert!(
        stderr.contains("daemon.start.lock"),
        "and which lock it is on: {stderr}"
    );
    assert!(
        fs::read_to_string(&lock)
            .expect("the held lock is still there")
            .contains(&format!("pid={holder_pid}")),
        "the live holder's lock is left exactly as it was"
    );
}

/// Age is the last reader, not a second opinion. A lock old enough for the
/// staleness rule is still not taken while its holder is demonstrably running,
/// because taking it puts two starts on one store.
#[test]
#[serial]
fn an_old_lock_a_live_kin_command_holds_is_not_taken_on_age() {
    let repo = tempdir().expect("temp repo");
    let runtime = common::IsolatedDaemonRuntime::new(repo.path());
    seeded_store(repo.path(), &runtime);

    let holder_home = tempdir().expect("temp dir for the holder fixture");
    let mut holder = spawn_kin_named_holder(holder_home.path());
    let holder_pid = holder.id();
    let lock = plant_startup_lock(repo.path(), holder_pid);
    // The bound is 5 s here, so the staleness rule fires at 10 s. Sixty is well
    // past it and cheap.
    age_lock(&lock, Duration::from_secs(60));

    let locate = kin_command(&runtime)
        .args(["locate", "lexer", "--json"])
        .current_dir(repo.path())
        .output()
        .expect("run kin locate behind an old, held startup lock");
    let stderr = String::from_utf8_lossy(&locate.stderr).to_string();

    let _ = holder.kill();
    let _ = holder.wait();

    assert!(
        !locate.status.success(),
        "an old lock with a live holder must still not be taken: {stderr}"
    );
    assert!(
        stderr.contains("timed out waiting for daemon startup lock"),
        "the waiter gives up at its bound rather than stealing the lock: {stderr}"
    );
    assert!(
        stderr.contains(&format!("(pid {holder_pid})")),
        "and names the holder it waited on: {stderr}"
    );
    assert!(
        stderr.contains("lock held "),
        "and how old that lock is, which is what age would have acted on: {stderr}"
    );
    assert!(
        fs::read_to_string(&lock)
            .expect("the held lock is still there")
            .contains(&format!("pid={holder_pid}")),
        "the live holder keeps its lock however old the file is"
    );
}
