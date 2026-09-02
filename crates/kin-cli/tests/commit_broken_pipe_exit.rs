// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The exit status of `kin commit` when the process reading it has gone,
//! through the real binaries.
//!
//! A stranger recovering from a wedged daemon ran `kin daemon stop` and then
//! the commit again as `kin commit -m ... 2>&1 | head -3`, and read `EXIT=101`
//! from a commit that had recorded its change: `head` closed the pipe after
//! three warnings, the summary `println!` met a closed pipe, and a failed
//! print is a panic. The retry was refused with `nothing to commit`, which is
//! how they learned the first one had worked; a caller keying on the exit
//! code would have retried or rolled back instead.
//!
//! Three arms, each driving `kin` and `kin-daemon`, and one doctrine under all
//! of them: the exit status reports the commit, never the pipe, so a recorded
//! change is never reported as a failure and a change that was not recorded
//! is never reported as a success. The change lands and the reader is gone by
//! the summary: exit 0 and the change in `kin log`. The commit is refused and
//! nobody reads either stream: exit 1, not 0 and not 101, because a refusal
//! is the caller's news whether or not it was delivered. The reader leaves
//! after one line while the daemon is still starting, `2>&1 | head -1` on a
//! cold daemon: the commit keeps going, the change is in `kin log`, and the
//! exit is 0.

use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{ExitStatus, Output, Stdio};
use tempfile::tempdir;

mod common;

use common::{Command, IsolatedDaemonRuntime};

fn run_git(repo: &Path, args: &[&str]) -> Output {
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

fn kin<'runtime>(
    runtime: &'runtime IsolatedDaemonRuntime,
    repo: &Path,
    args: &[&str],
) -> Command<'runtime> {
    let mut command = runtime.kin_command();
    command
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        // The pipe is the subject; the daemon these start must not touch the
        // one GPU on a shared host to embed a two-function fixture.
        .env("KIN_EMBED_BACKEND", "cpu")
        .current_dir(repo);
    command
}

fn run_kin(runtime: &IsolatedDaemonRuntime, repo: &Path, args: &[&str]) -> Output {
    kin(runtime, repo, args).output().expect("run kin")
}

fn require_kin(runtime: &IsolatedDaemonRuntime, repo: &Path, args: &[&str]) -> Output {
    let output = run_kin(runtime, repo, args);
    assert!(
        output.status.success(),
        "kin {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn initialize(runtime: &IsolatedDaemonRuntime, repo: &Path) {
    fs::create_dir_all(repo).expect("create repo");
    require_git(repo, &["init", "--initial-branch=main"]);
    require_git(repo, &["config", "commit.gpgsign", "false"]);
    require_git(repo, &["config", "user.name", "Ada Lovelace"]);
    require_git(repo, &["config", "user.email", "ada@example.com"]);
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    fs::write(repo.join("src/lib.rs"), b"pub fn shipped() -> u8 { 1 }\n").expect("write source");
    require_git(repo, &["add", "--all"]);
    require_git(repo, &["commit", "-m", "first commit"]);

    let init = run_kin(runtime, repo, &["init", ".", "--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
}

fn log_entries(runtime: &IsolatedDaemonRuntime, repo: &Path) -> Vec<Value> {
    let output = require_kin(runtime, repo, &["log", "--json", "--count", "20"]);
    let report: Value = serde_json::from_slice(&output.stdout).expect("kin log should emit JSON");
    assert_eq!(report["schema"], "kin.log.v1");
    report["entries"]
        .as_array()
        .expect("log reports its entries")
        .clone()
}

fn newest_change(entries: &[Value]) -> Value {
    let id = entries.first().expect("the log has a change")["change_id"].clone();
    assert!(
        !id.is_null(),
        "every log entry names its change: {entries:?}"
    );
    id
}

/// A pipe whose reader is gone before the child exists, so its first write
/// into it fails and no timing can make the arm pass.
fn gone_pipe() -> std::io::PipeWriter {
    let (reader, writer) = std::io::pipe().expect("create a pipe");
    drop(reader);
    writer
}

/// The stranger's arm, with a warm daemon: the change is recorded, the summary
/// is the first and only stdout write, and the reader is gone by then.
///
/// stderr goes to a file so the arm can also say there was no panic, which the
/// stranger could not see because their stderr was the same closed pipe.
///
/// Falsify by making the sink raise std's own panic on a closed pipe instead
/// of marking the stream gone: the status reads 101 with `failed printing to
/// stdout` on stderr, and the change is in the log all the same.
#[test]
fn a_commit_recorded_before_its_reader_left_exits_zero() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);
    // Warm the daemon and pin the log, so the commit below is measured on its
    // own and the only stderr writes it can make are warnings.
    let before = log_entries(&runtime, &repo);

    fs::write(repo.join("src/added.rs"), b"pub fn added() -> u8 { 3 }\n").expect("add source");
    let stderr_path = root.path().join("commit.stderr");
    let stderr = fs::File::create(&stderr_path).expect("create the stderr capture");
    let mut child = kin(&runtime, &repo, &["commit", "-m", "publish added source"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(gone_pipe()))
        .stderr(Stdio::from(stderr))
        .spawn_owned()
        .expect("spawn kin commit");
    let status = child.wait().expect("wait for kin commit");
    let stderr = fs::read_to_string(&stderr_path).unwrap_or_default();

    let after = log_entries(&runtime, &repo);
    assert_eq!(
        after.len(),
        before.len() + 1,
        "the commit must have recorded its change: stderr={stderr}"
    );
    assert_ne!(newest_change(&after), newest_change(&before));
    assert_eq!(
        status.code(),
        Some(0),
        "a commit that recorded its change must exit 0 whether or not its summary was read, \
         not {status:?}: stderr={stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "a closed pipe is not a panic: stderr={stderr}"
    );
}

/// A refused commit with nobody reading either stream.
///
/// The refusal is printed by the top of `main`, so this is the arm that pins
/// how `main` ends on an error when stderr is gone: exit 1, the refusal's own
/// status, and neither the 101 of a second print panic nor a 0.
///
/// Falsify by rendering the refusal through std's `eprintln!` instead of the
/// sink: the closed pipe turns that print into a panic, and the status reads
/// 101.
#[test]
fn a_refused_commit_exits_one_even_when_nobody_reads_it() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);
    fs::write(repo.join("src/added.rs"), b"pub fn added() -> u8 { 3 }\n").expect("add source");
    require_kin(&runtime, &repo, &["commit", "-m", "publish added source"]);
    let committed = log_entries(&runtime, &repo);

    // The control: with its output kept, the refusal exits 1 and says why.
    let refused = run_kin(&runtime, &repo, &["commit", "--quiet", "-m", "again"]);
    assert_eq!(
        refused.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("nothing to commit"),
        "the refusal must say what it refused: {}",
        String::from_utf8_lossy(&refused.stderr)
    );

    let both = gone_pipe();
    let stderr = both
        .try_clone()
        .expect("share the pipe between both streams");
    let mut child = kin(&runtime, &repo, &["commit", "--quiet", "-m", "again"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(both))
        .stderr(Stdio::from(stderr))
        .spawn_owned()
        .expect("spawn kin commit");
    let status: ExitStatus = child.wait().expect("wait for kin commit");
    assert_eq!(
        status.code(),
        Some(1),
        "a refused commit exits 1 whether or not anyone reads the refusal, not {status:?}"
    );

    let after = log_entries(&runtime, &repo);
    assert_eq!(
        after.len(),
        committed.len(),
        "a refused commit records nothing"
    );
}

/// The stranger's arm on a cold daemon, as `2>&1 | head -1`: both streams one
/// pipe, and the reader leaves after the first line, while the daemon this
/// commit has to start is still starting.
///
/// Every write after that first line meets a closed pipe: the startup ticks,
/// the ready line, any warning, and the summary. None of them may decide
/// anything. The doctrine, asserted first, is that the exit status and the log
/// agree: a 0 over a log that gained nothing would claim a change that does
/// not exist, and a non-zero over a log that gained one would report a landed
/// commit as a failure, which is FIR-2846 itself. What this design then
/// delivers is the first of the two agreeing shapes: the commit runs to its
/// end, the change is in `kin log`, and the status is 0.
///
/// Falsify by ending the process on the first closed-pipe write with the
/// status the old hook gave a closed stderr, 141: the log gains nothing and
/// the design assertion reads 141 over an unchanged log. Falsify the doctrine
/// assertion by ending it with 0 instead: a 0 over a log that gained nothing.
#[test]
fn a_commit_whose_reader_leaves_after_one_line_still_records_its_change_and_exits_zero() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);
    fs::write(repo.join("src/added.rs"), b"pub fn added() -> u8 { 3 }\n").expect("add source");
    require_kin(&runtime, &repo, &["commit", "-m", "publish added source"]);
    let before = log_entries(&runtime, &repo);
    require_kin(&runtime, &repo, &["daemon", "stop"]);

    fs::write(repo.join("src/more.rs"), b"pub fn more() -> u8 { 4 }\n").expect("add more source");
    let (reader, writer) = std::io::pipe().expect("create a pipe");
    let stderr = writer
        .try_clone()
        .expect("share the pipe between both streams");
    let mut child = kin(&runtime, &repo, &["commit", "-m", "publish more source"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(writer))
        .stderr(Stdio::from(stderr))
        .spawn_owned()
        .expect("spawn kin commit");
    // `head -1`: one line, then gone.
    let mut lines = BufReader::new(reader);
    let mut first = String::new();
    let read = lines
        .read_line(&mut first)
        .expect("read the first line of the shared pipe");
    assert_ne!(
        read, 0,
        "the commit must say something before it ends, and on a cold daemon it says it is \
         starting one"
    );
    drop(lines);
    let status: ExitStatus = child.wait().expect("wait for kin commit");

    let after = log_entries(&runtime, &repo);
    let recorded = match after.len().checked_sub(before.len()) {
        Some(0) => false,
        Some(1) => true,
        _ => panic!(
            "one commit moves the log by at most one entry: {} before, {} after",
            before.len(),
            after.len()
        ),
    };
    assert!(
        (status.code() == Some(0)) == recorded,
        "the exit status and the log must agree, and they do not: status {status:?}, change \
         recorded {recorded}. A 0 over a log that gained nothing claims a change that does not \
         exist, and a failure over a log that gained one reports a landed commit as failed. The \
         first line it wrote was: {first}"
    );
    assert!(
        recorded,
        "a reader leaving after one line is no reason to stop the commit, and this one recorded \
         nothing; status {status:?}; the first line it wrote was: {first}"
    );
    assert_ne!(newest_change(&after), newest_change(&before));
    assert_eq!(
        status.code(),
        Some(0),
        "a commit that recorded its change exits 0 whether or not anyone read its summary, not \
         {status:?}"
    );
}
