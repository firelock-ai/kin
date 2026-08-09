// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What `kin init` writes when nobody is watching a terminal.
//!
//! An in-place bar redraws with a carriage return, which a terminal reads as an
//! overwrite and a pipe records as a frame. Captured runs therefore kept every
//! frame, and a consumer that stopped reading took the admission down with it.

use std::fs;
use std::path::Path;
use tempfile::tempdir;

mod common;

use common::IsolatedDaemonRuntime;

/// Entity-source files above the linker's bar threshold, in one commit.
///
/// The bar only draws past a file count, so a fixture under it would make every
/// assertion here pass for the wrong reason.
const LINKED_FILES: usize = 64;

fn run_git(path: &Path, args: &[&str]) {
    let output = common::Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .current_dir(path)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn seed_linkable_git_repo(path: &Path) {
    fs::create_dir_all(path).expect("create repo dir");
    run_git(path, &["init", "--initial-branch=main"]);
    run_git(path, &["config", "user.email", "kin@example.invalid"]);
    run_git(path, &["config", "user.name", "Kin"]);
    for index in 0..LINKED_FILES {
        let next = (index + 1) % LINKED_FILES;
        fs::write(
            path.join(format!("m{index}.rs")),
            format!("pub fn f{index}() -> usize {{ g{next}() }}\npub fn g{index}() -> usize {{ {index} }}\n"),
        )
        .expect("write a linkable source file");
    }
    run_git(path, &["add", "--all"]);
    run_git(path, &["commit", "-m", "first"]);
}

#[test]
fn a_captured_init_writes_phase_summaries_and_no_progress_frames() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("captured");
    seed_linkable_git_repo(&repo);

    let runtime = IsolatedDaemonRuntime::new(&repo);
    let output = runtime
        .kin_command()
        .arg("init")
        .arg(&repo)
        .output()
        .expect("run kin init with both streams captured");

    assert!(
        output.status.success(),
        "init must succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let frames = output.stderr.iter().filter(|byte| **byte == b'\r').count();
    assert_eq!(
        frames,
        0,
        "a captured run must carry no carriage-return frames: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Linking:"),
        "the in-place bar belongs to a terminal: {stderr}"
    );
    assert!(
        stderr.contains("derive semantic history"),
        "the per-phase summaries are what a captured run keeps: {stderr}"
    );
    assert!(
        stderr.contains("build bootstrap transaction"),
        "every phase still reports: {stderr}"
    );
    assert!(
        output.stderr.len() < 16 * 1024,
        "a captured run stays small; got {} bytes",
        output.stderr.len()
    );
}

#[test]
fn init_finishes_its_store_when_the_reader_closes_the_pipe() {
    // `kin init | head` closed the reading end partway through and the write
    // that followed panicked, so a repository that was mid-admission was left
    // with no store at all. Progress is advisory; the admission is not.
    let root = tempdir().expect("temp root");
    let repo = root.path().join("head-capped");
    seed_linkable_git_repo(&repo);
    let status_file = root.path().join("init-status");

    let runtime = IsolatedDaemonRuntime::new(&repo);
    let script = format!(
        "{{ {kin} init {repo} 2>&1; echo $? > {status}; }} | head -1 > /dev/null",
        kin = shell_quote(env!("CARGO_BIN_EXE_kin")),
        repo = shell_quote(&repo.display().to_string()),
        status = shell_quote(&status_file.display().to_string()),
    );
    let output = runtime
        .process_command_for_test("sh")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("run kin init into a reader that closes early");
    assert!(
        output.status.success(),
        "the shell driving the pipeline must itself succeed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let recorded = fs::read_to_string(&status_file).expect("init recorded its own exit status");
    assert_eq!(
        recorded.trim(),
        "0",
        "the exit status must report the admission, not the pipe"
    );
    assert_eq!(
        fs::read_to_string(repo.join(".kin/version"))
            .expect("a completed admission leaves a store")
            .trim(),
        kin_core::layout::KIN_LAYOUT_VERSION.to_string(),
        "the store must be the one this build writes"
    );
}

/// Single-quote a path for `sh`, so a temporary directory with a space in it
/// cannot silently turn one argument into two.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}
