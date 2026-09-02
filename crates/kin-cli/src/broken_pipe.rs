// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! How the CLI ends when the process reading its output has gone away.
//!
//! Rust starts every binary with `SIGPIPE` ignored, so a write into a pipe
//! whose reader has closed comes back as `EPIPE` instead of ending the process,
//! and the `print!` family turns that error into a panic. `kin diff HEAD
//! WORKSPACE | head -5` therefore ended in `thread 'main' panicked at ...
//! failed printing to stdout: Broken pipe` and exit 101 on every command that
//! writes more than its reader takes, and a `kin commit ... 2>&1 | head -3`
//! whose change was already in authority died the same way while printing the
//! summary, so the caller read a landed commit as a failure (FIR-2846,
//! FIR-3039). Measured on 489138ec with the reader gone before the first
//! write: eleven of twelve commands exited 101, and only `--help` survived,
//! because clap discards its write errors.
//!
//! The CLI has over a thousand print sites, so this is handled once, at the
//! two places a failed write can leave the process: the panic hook, for the
//! `print!` family, and the top of `main`, for an `io::Error` that came back
//! through `?`. This module decides; `main.rs`, the process boundary, holds
//! the hook and performs the exits.
//!
//! Which stream broke decides the status. stdout carries a command's result
//! and is written once the work is done, so a reader that stopped taking it
//! has everything it wanted and the command exits 0. stderr carries progress
//! and warnings while the work is still running, so a reader gone there cut
//! the command off before its result, and the exit says so with the status a
//! shell reports for a process `SIGPIPE` ended. `kin commit 2>&1 | head -3`
//! shows why the two must differ. On a cold daemon, head closes after the
//! startup lines and the next progress write fails before the commit request
//! is sent, so nothing was recorded; on a warm daemon the same pipeline fails
//! on the summary line, after the change is in authority. Both exited 101
//! before. Now the first exits 141 and the second exits 0, and a caller keying
//! on the code reads each one right.
//!
//! Resetting `SIGPIPE` to its default disposition would have been one line and
//! was rejected. The daemon transport is a socket, std sets `SO_NOSIGPIPE`
//! only on Apple platforms and never sends with `MSG_NOSIGNAL`, so on Linux a
//! write to a daemon that has since gone away would kill this process silently
//! instead of returning the error `kin commit` reads to find out whether its
//! change landed anyway.

use std::io::{self, Write as _};

/// The status a shell reports for a process that `SIGPIPE` ended, 128 + 13,
/// and the status this process would have had under the default disposition.
/// Scripts already read it as "the reader closed early" rather than "the
/// command failed", which is exactly the news.
pub const CUT_OFF_STATUS: i32 = 141;

#[cfg(unix)]
const BROKEN_PIPE_OS_ERRORS: &[i32] = &[libc::EPIPE];
/// `ERROR_BROKEN_PIPE` and `ERROR_NO_DATA`: the two codes a write into a pipe
/// the other side has closed comes back with, and the two std decodes to
/// `ErrorKind::BrokenPipe`.
#[cfg(windows)]
const BROKEN_PIPE_OS_ERRORS: &[i32] = &[109, 232];

/// The status a panic earns when it is a std print into a closed pipe, for
/// the hook `main` installs; `None` for every other panic, which the hook
/// hands on to the one that was installed before it, so a real panic still
/// prints its message and still exits 101.
pub fn exit_status_for_panic(info: &std::panic::PanicHookInfo<'_>) -> Option<i32> {
    let payload = info.payload();
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())?;
    exit_status_for_print_failure(message)
}

/// The status a failed std print earns, when the failure is a closed pipe.
///
/// std's `print_to` panics with `failed printing to {stream}: {error}` and
/// nothing else carries the stream, so the message is the evidence. The error
/// half is compared against what the OS itself says for a broken pipe, built
/// here rather than written down, so the check holds on every platform and in
/// every locale the process runs in. A print that failed for any other reason
/// is still a panic.
pub fn exit_status_for_print_failure(message: &str) -> Option<i32> {
    let descriptions = broken_pipe_descriptions();
    for (stream, status) in [("stdout", 0), ("stderr", CUT_OFF_STATUS)] {
        let Some(error) = message.strip_prefix(&format!("failed printing to {stream}: ")) else {
            continue;
        };
        if descriptions.iter().any(|description| description == error) {
            return Some(status);
        }
    }
    None
}

fn broken_pipe_descriptions() -> Vec<String> {
    BROKEN_PIPE_OS_ERRORS
        .iter()
        .map(|code| io::Error::from_raw_os_error(*code).to_string())
        .collect()
}

/// The status an error that reached `main` earns when it is a closed pipe.
///
/// `Some(0)` for an `io::Error` of kind `BrokenPipe` that is the error itself,
/// under however many layers of context were added on the way up: that is
/// what a write to stdout returns through `?`, and the CLI's stderr writes go
/// through `eprint!`, which panics rather than returns. The error's source
/// chain is deliberately not walked. A daemon request that failed carries an
/// io error underneath its transport error, and a commit whose reply was lost
/// must stay an error the caller can read, never a quiet success.
pub fn broken_pipe_exit_status(error: &anyhow::Error) -> Option<i32> {
    error
        .downcast_ref::<io::Error>()
        .filter(|error| error.kind() == io::ErrorKind::BrokenPipe)
        .map(|_| 0)
}

/// Report the error a `main` is about to exit 1 on, the way std would have.
///
/// A `main` that returns `Err` prints `Error: {err:?}` through `eprintln!`, so
/// a refusal whose stderr nobody reads any more was a second broken-pipe
/// panic and exit 101 in place of exit 1. The rendering here is the same and
/// the write's failure is dropped, so the exit status stays the refusal's own.
pub fn report_error(error: &anyhow::Error) {
    let _ = writeln!(io::stderr().lock(), "Error: {error:?}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exactly what std's `print_to` formats for a broken pipe on this host.
    fn print_failure(stream: &str) -> String {
        format!(
            "failed printing to {stream}: {}",
            io::Error::from_raw_os_error(BROKEN_PIPE_OS_ERRORS[0])
        )
    }

    #[test]
    fn every_listed_os_error_decodes_to_a_broken_pipe() {
        for code in BROKEN_PIPE_OS_ERRORS {
            assert_eq!(
                io::Error::from_raw_os_error(*code).kind(),
                io::ErrorKind::BrokenPipe,
                "os error {code}"
            );
        }
    }

    #[test]
    fn a_print_into_a_closed_stdout_is_a_clean_exit() {
        assert_eq!(
            exit_status_for_print_failure(&print_failure("stdout")),
            Some(0)
        );
    }

    #[test]
    fn a_print_into_a_closed_stderr_is_the_cut_off_status() {
        assert_eq!(
            exit_status_for_print_failure(&print_failure("stderr")),
            Some(CUT_OFF_STATUS)
        );
    }

    #[test]
    fn a_print_that_failed_for_any_other_reason_stays_a_panic() {
        // Code 2 is ENOENT on Unix and ERROR_FILE_NOT_FOUND on Windows, so this
        // is a real OS message on both and a broken pipe on neither.
        let other = format!(
            "failed printing to stdout: {}",
            io::Error::from_raw_os_error(2)
        );
        assert_eq!(exit_status_for_print_failure(&other), None);
        // The kind's own description, which std never prints for a stdout
        // write, is not accepted in place of the OS message.
        assert_eq!(
            exit_status_for_print_failure("failed printing to stdout: broken pipe"),
            None
        );
        assert_eq!(
            exit_status_for_print_failure("index out of bounds: the len is 1 but the index is 1"),
            None
        );
        // A library's own write panic carries the stream nowhere and is not
        // read as one either; the completions arm renders into memory for
        // exactly this reason.
        let foreign = format!(
            "failed to write completion file: {:?}",
            io::Error::from_raw_os_error(BROKEN_PIPE_OS_ERRORS[0])
        );
        assert_eq!(exit_status_for_print_failure(&foreign), None);
    }

    #[test]
    fn a_broken_pipe_that_reached_main_as_itself_is_a_clean_exit() {
        let bare: anyhow::Error = io::Error::from(io::ErrorKind::BrokenPipe).into();
        assert_eq!(broken_pipe_exit_status(&bare), Some(0));
        let wrapped = anyhow::Error::from(io::Error::from(io::ErrorKind::BrokenPipe))
            .context("write the change log")
            .context("kin log");
        assert_eq!(broken_pipe_exit_status(&wrapped), Some(0));
        let other: anyhow::Error = io::Error::from(io::ErrorKind::NotFound).into();
        assert_eq!(broken_pipe_exit_status(&other), None);
    }

    /// A transport error shaped like reqwest's: its own message, with the io
    /// error underneath as the source.
    #[derive(Debug)]
    struct Transport {
        source: io::Error,
    }

    impl std::fmt::Display for Transport {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("error sending request")
        }
    }

    impl std::error::Error for Transport {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.source)
        }
    }

    #[test]
    fn a_transport_error_carrying_a_broken_pipe_underneath_stays_an_error() {
        let error = anyhow::Error::new(Transport {
            source: io::Error::from(io::ErrorKind::BrokenPipe),
        })
        .context("send daemon-owned native commit request");
        assert_eq!(broken_pipe_exit_status(&error), None);
        // The control: the chain does carry the broken pipe, so a walk down
        // it would have answered 0, and this test would then be passing on
        // an error that never had one.
        assert!(error.chain().any(|cause| cause
            .downcast_ref::<io::Error>()
            .is_some_and(|cause| cause.kind() == io::ErrorKind::BrokenPipe)));
    }
}
