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

/// The conversion phase must leave no daemon behind, including when it exits
/// early.
///
/// `kin init` starts a daemon to run the language-server sweep. The cleanup that
/// stops it sat after the happy-path wait, so every early return skipped it. On
/// a CI runner the sweep POST was refused 401 and the phase returned before the
/// stop, and two minutes later an independent daemon could not start against the
/// same repository: "another kin daemon (pid 10195) already owns ... and is
/// still running".
///
/// This drives the early-exit path by construction rather than by hoping: with
/// no language server on PATH the daemon reports `enrichment_available: false`
/// and the phase returns immediately, which is the same shape as the 401 and
/// reaches the same cleanup. A leaked daemon fails the assertion below by
/// leaving a live pid recorded for the repository.
#[test]
fn the_conversion_phase_leaves_no_daemon_behind_when_it_exits_early() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("no-leak");
    seed_linkable_git_repo(&repo);

    let runtime = IsolatedDaemonRuntime::new(&repo);
    let output = runtime
        .process_command_for_test(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(&repo)
        // No language server can be found on this PATH, so the phase takes its
        // early exit. `sh` and the core utilities the CLI shells out to live in
        // the standard directories, which carry no language server.
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("run kin init");
    assert!(
        output.status.success(),
        "init must succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // The daemon record is the evidence. A phase that stopped what it started
    // leaves either no pid file or a pid that is gone; a leaked daemon leaves a
    // live one, which is exactly what blocked the next daemon on the runner.
    let pid_file = repo.join(".kin").join("daemon.pid");
    if let Ok(recorded) = fs::read_to_string(&pid_file) {
        if let Ok(pid) = recorded.trim().parse::<i32>() {
            let alive = unsafe { libc::kill(pid, 0) } == 0;
            assert!(
                !alive,
                "kin init left daemon pid {pid} running; the conversion phase must stop the \
                 daemon it started on every exit, including its early ones"
            );
        }
    }
}

/// The daemon reports a cause and the CLI prints that cause, across a real
/// process boundary.
///
/// Both sides carry unit tests and they share no code, so a daemon that stopped
/// sending `enrichment_unavailable`, or renamed a row, would leave every one of
/// them green while a user read the CLI's fallback sentence instead of a cause.
/// This is the check that fails on that, which is why the fallback text is an
/// assertion below rather than a comment.
///
/// `KIN_DAEMON_DISABLE_LSP` is the row driven here because it is the one this
/// suite can reach on any host: it switches enrichment off in the daemon, so
/// the channel is closed no matter what the machine running the test has
/// installed. Restricting `PATH` instead was the first attempt and it does not
/// hold, since the daemon reached a server anyway and swept.
///
/// `--storage gcs` reaches the same row through
/// `storage_backend_graph_authority`, and it is the more common way to land
/// here in production. The two share this code path entirely, so the operator
/// who never touched an env variable gets what is asserted below.
#[test]
fn the_enrichment_note_carries_a_cause_the_daemon_reported() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("enrichment-off");
    seed_linkable_git_repo(&repo);

    let runtime = IsolatedDaemonRuntime::new(&repo);
    let output = runtime
        .process_command_for_test(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(&repo)
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .output()
        .expect("run kin init");
    assert!(
        output.status.success(),
        "init must succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // The positive control. Without it every assertion below would pass on a
    // run that printed no note at all, which is the same result a broken seam
    // produces.
    assert!(
        stderr.contains("switched off for this daemon"),
        "a daemon told not to enrich must say so in the note it causes: {stderr}"
    );
    assert!(
        !stderr.contains("did not report why"),
        "the daemon must send a cause this CLI recognises, so the fallback row must not \
         appear: {stderr}"
    );
    assert!(
        !stderr.contains("no language server is installed"),
        "no row may assert what is installed on the reader's host, and this row least of all: \
         nothing here looked at a language server: {stderr}"
    );
    assert!(
        !stderr.contains("--install-language-servers"),
        "installing a server changes nothing while enrichment is switched off, so the note \
         must not prescribe it: {stderr}"
    );
}
