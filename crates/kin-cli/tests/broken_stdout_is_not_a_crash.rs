// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A reader that goes away must not turn a successful command into a crash.
//!
//! FIR-2838. The invocation that finally landed the rc061a green arm's commit
//! reported `EXIT=101`, and the commit had landed. The shell was
//! `kin commit ... 2>&1 | head -3`: `head` took its three lines and left, the
//! next write took `EPIPE`, and because the Rust runtime sets SIGPIPE to
//! `SIG_IGN` before `main`, `println!` panicked. 101 is the panic exit status,
//! so a run that worked reported a crash inside the product, and the panic text
//! it would have printed went into the same closed pipe.
//!
//! `kin languages` is the subject because it needs no repository and no daemon
//! and still writes several hundred bytes, so the arm below is about the pipe
//! and nothing else.

#![cfg(unix)]

use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

/// Run `kin <args>` with a stdout that has no reader at all.
///
/// The read end is closed in this process before the child is spawned, so the
/// child never has a reader and its first write takes `EPIPE` deterministically.
/// Handing the child a live pipe and racing to close it would pass on a fast
/// machine for the wrong reason.
fn run_with_no_stdout_reader(home: &std::path::Path, args: &[&str]) -> (std::process::Output, i32) {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a two-element array of the exact type `pipe` writes.
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "could not create the pipe this test needs");
    // SAFETY: both descriptors were just created by `pipe` and are owned here.
    let read_end = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fds[0]) };
    // SAFETY: same.
    let write_end = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fds[1]) };
    drop(read_end);

    let child = Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(args)
        .env("HOME", home)
        .env("KIN_HOME", home.join(".kin"))
        .env_remove("KIN_MCP_REPO")
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::from(write_end))
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kin");
    let output = child.wait_with_output().expect("wait for kin");
    let signal = output.status.signal().unwrap_or(0);
    (output, signal)
}

#[test]
fn a_closed_stdout_is_not_reported_as_a_panic() {
    let home = tempfile::tempdir().expect("temp home");

    // The control first, so a failure of the arm below cannot be a command that
    // prints nothing. If `kin languages` were silent, no write would ever fail
    // and the arm would pass while proving nothing.
    let normal = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("languages")
        .env("HOME", home.path())
        .env("KIN_HOME", home.path().join(".kin"))
        .env_remove("KIN_MCP_REPO")
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .output()
        .expect("run kin languages");
    assert_eq!(
        normal.status.code(),
        Some(0),
        "the control run must succeed: stderr was {}",
        String::from_utf8_lossy(&normal.stderr)
    );
    assert!(
        normal.stdout.len() > 100,
        "the control run must actually write to stdout, or the arm below is vacuous; it wrote \
         {} bytes",
        normal.stdout.len()
    );

    let (output, signal) = run_with_no_stdout_reader(home.path(), &["languages"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "a reader leaving is not this program crashing, yet stderr carries a panic: {stderr}"
    );
    assert_ne!(
        output.status.code(),
        Some(101),
        "101 is the panic exit status; a closed stdout must not produce it. stderr: {stderr}"
    );
    assert_eq!(
        signal,
        libc::SIGPIPE,
        "with the default disposition restored the process ends on SIGPIPE, which is what every \
         other unix tool does under `| head`. status was {:?}, stderr: {stderr}",
        output.status
    );
}
