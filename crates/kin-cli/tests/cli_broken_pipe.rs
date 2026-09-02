// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What `kin` does when the process reading its output has gone, through the
//! real binary.
//!
//! `kin diff HEAD WORKSPACE | head -5` on a release candidate ended in
//! `thread 'main' panicked at ... failed printing to stdout: Broken pipe (os
//! error 32)` and exit 101, while the same command into a file exited 0 with
//! all 135 lines, so the output was right and only the exit was wrong. The
//! panic is std's, the CLI has over a thousand print sites, and the fix lives
//! at the process boundary, so these drive the binary itself through a pipe
//! whose reader is gone: once with no store at all, for the two exit paths the
//! boundary handles, and once against a daemon for the commands the report
//! named. Every pipe arm has the file arm beside it as the control that the
//! output still flows when the reader stays.

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

/// The file arm: the same command with its output kept, which is the control
/// that a fix did not simply stop the command from printing.
fn run_into_files(runtime: &IsolatedDaemonRuntime, repo: &Path, args: &[&str]) -> Output {
    kin(runtime, repo, args).output().expect("run kin")
}

/// Run `kin` with stdout on a pipe whose reader is already gone, so the first
/// write into it fails, and report the exit status with what stderr said.
///
/// The reader is dropped BEFORE the spawn, so there is no window in which the
/// child could write successfully and the arm could pass on timing alone.
fn run_with_reader_gone(
    runtime: &IsolatedDaemonRuntime,
    repo: &Path,
    args: &[&str],
    stderr_path: &Path,
) -> (ExitStatus, String) {
    let (reader, writer) = std::io::pipe().expect("create a pipe");
    drop(reader);
    let stderr = fs::File::create(stderr_path).expect("create the stderr capture");
    let mut child = kin(runtime, repo, args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(writer))
        .stderr(Stdio::from(stderr))
        .spawn_owned()
        .expect("spawn kin");
    let status = child.wait().expect("wait for kin");
    (status, fs::read_to_string(stderr_path).unwrap_or_default())
}

fn assert_clean_exit(args: &[&str], status: ExitStatus, stderr: &str) {
    assert_eq!(
        status.code(),
        Some(0),
        "kin {args:?} into a closed pipe must exit 0, not {status:?}: stderr={stderr}"
    );
    assert!(
        !stderr.contains("panicked at"),
        "kin {args:?} into a closed pipe must not panic: stderr={stderr}"
    );
}

fn assert_full_output(args: &[&str], output: &Output) {
    assert!(
        output.status.success(),
        "kin {args:?} into a file must still succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.stdout.is_empty(),
        "kin {args:?} into a file must still print its result: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The `print!` path: a reader gone before the first line.
///
/// `kin capabilities` needs no store and prints its matrix line by line
/// through `println!`, so its first write is the one that meets the closed
/// pipe and std's print panic is the thing under test.
///
/// Falsify by removing `install_exit_hook()` from `main`: the pipe arm then
/// exits 101 with `panicked at` on stderr, and the file arm stays green.
#[test]
fn a_print_into_a_pipe_nobody_reads_exits_zero_without_a_panic() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("anywhere");
    fs::create_dir_all(&repo).expect("create a working directory");
    let runtime = IsolatedDaemonRuntime::new(&repo);
    let args = ["capabilities"];

    let (status, stderr) =
        run_with_reader_gone(&runtime, &repo, &args, &root.path().join("pipe.stderr"));
    assert_clean_exit(&args, status, &stderr);

    assert_full_output(&args, &run_into_files(&runtime, &repo, &args));
}

/// The `?` path: a reader that takes one line of a script larger than the pipe
/// can hold, which is `| head -1` exactly.
///
/// `kin completions zsh` is thousands of lines, so once the reader has its
/// line and leaves, the child is blocked in a write the kernel then fails.
/// The completion script is written through `io::Write`, whose error comes
/// back through `?` to the top of `main`, so this is the other exit path.
///
/// Falsify by handing `clap_complete::generate` stdout directly again: its own
/// `failed to write completion file` panic names no stream, the hook lets it
/// through, and the arm reads 101. Or by returning the error from `main`
/// instead of ending on it: the arm then reads exit 1 and an `Error:` line.
#[test]
fn a_reader_that_leaves_after_one_line_of_completions_gets_a_clean_exit() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("anywhere");
    fs::create_dir_all(&repo).expect("create a working directory");
    let runtime = IsolatedDaemonRuntime::new(&repo);
    let args = ["completions", "zsh"];

    let (reader, writer) = std::io::pipe().expect("create a pipe");
    let stderr_path = root.path().join("completions.stderr");
    let stderr = fs::File::create(&stderr_path).expect("create the stderr capture");
    let mut child = kin(&runtime, &repo, &args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(writer))
        .stderr(Stdio::from(stderr))
        .spawn_owned()
        .expect("spawn kin");
    let mut lines = BufReader::new(reader);
    let mut first = String::new();
    lines
        .read_line(&mut first)
        .expect("read the first line of the script");
    assert!(
        first.starts_with("#compdef"),
        "the first line is the script's own header: {first:?}"
    );
    drop(lines);
    let status = child.wait().expect("wait for kin");
    let stderr = fs::read_to_string(&stderr_path).unwrap_or_default();
    assert_clean_exit(&args, status, &stderr);

    let output = run_into_files(&runtime, &repo, &args);
    assert_full_output(&args, &output);
    assert!(
        output.stdout.len() > 64 * 1024,
        "the script must be larger than a pipe buffer for the pipe arm to mean anything: {} bytes",
        output.stdout.len()
    );
}

fn initialize(runtime: &IsolatedDaemonRuntime, repo: &Path) {
    fs::create_dir_all(repo).expect("create repo");
    require_git(repo, &["init", "--initial-branch=main"]);
    require_git(repo, &["config", "commit.gpgsign", "false"]);
    require_git(repo, &["config", "user.name", "Ada Lovelace"]);
    require_git(repo, &["config", "user.email", "ada@example.com"]);
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    fs::write(
        repo.join("src/lib.rs"),
        b"pub fn shipped() -> u8 { 1 }\n\npub fn shipped_twice() -> u8 { shipped() + shipped() }\n",
    )
    .expect("write source");
    require_git(repo, &["add", "--all"]);
    require_git(repo, &["commit", "-m", "first commit"]);

    let init = run_into_files(runtime, repo, &["init", ".", "--json"]);
    assert!(
        init.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );
    let report: Value = serde_json::from_slice(&init.stdout).expect("kin init reports JSON");
    assert!(
        report.get("schema").is_some(),
        "init must report its schema: {report}"
    );
}

/// The commands the report named, each through a pipe whose reader is gone
/// and each into a file beside it.
///
/// One store and one daemon for all of them, because the pipe is the subject
/// and the store is only there so every command has something to print.
///
/// Falsify by removing `install_exit_hook()` from `main`: every pipe arm then
/// reads 101, and every file arm stays green.
#[test]
fn every_repository_command_survives_a_reader_that_is_gone() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    let runtime = IsolatedDaemonRuntime::new(&repo);
    initialize(&runtime, &repo);
    // A workspace edit that is not yet committed, so `diff HEAD WORKSPACE` has
    // artifact and semantic changes to print.
    fs::write(repo.join("src/added.rs"), b"pub fn added() -> u8 { 3 }\n").expect("add source");

    let commands: [&[&str]; 6] = [
        &["diff", "HEAD", "WORKSPACE"],
        &["log", "--count", "50"],
        &["history", "shipped"],
        &["status"],
        &["conflicts"],
        &["search", "shipped"],
    ];
    for (index, args) in commands.iter().enumerate() {
        let stderr_path = root.path().join(format!("pipe-{index}.stderr"));
        let (status, stderr) = run_with_reader_gone(&runtime, &repo, args, &stderr_path);
        assert_clean_exit(args, status, &stderr);
        assert_full_output(args, &run_into_files(&runtime, &repo, args));
    }
}
