// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What the CLI does when the process reading its output has gone away.
//!
//! Rust starts every binary with `SIGPIPE` ignored, so a write into a pipe
//! whose reader has closed comes back as `EPIPE` instead of ending the process,
//! and std's `print!` family turns that error into a panic. `kin diff HEAD
//! WORKSPACE | head -5` therefore ended in `thread 'main' panicked at ...
//! failed printing to stdout: Broken pipe` and exit 101 on every command that
//! writes more than its reader takes, and a `kin commit ... 2>&1 | head -3`
//! whose change was already in authority died the same way while printing the
//! summary, so the caller read a landed commit as a failure (FIR-2846,
//! FIR-3039). Measured on 489138ec with the reader gone before the first
//! write: eleven of twelve commands exited 101, and only `--help` survived,
//! because clap discards its write errors.
//!
//! The rule is that a reader going away changes what a command prints and
//! never what it does. The CLI has over a thousand print sites, so the four
//! macros are redefined once for the whole crate, here, and `main.rs` imports
//! the same definitions. Each one writes through [`print_stdout`] or
//! [`print_stderr`]: the first write that meets a closed pipe marks that
//! stream gone, every later write to it is skipped before it reaches the OS,
//! and the command runs to its end and exits with the status its work earned.
//! On Unix the first `EPIPE` also points the descriptor at `/dev/null`, so a
//! print in a crate this one calls into, a library writing its own
//! diagnostics, or a child process that inherits the stream finds a sink where
//! the pipe was instead of the same `EPIPE`. A write that fails for any other
//! reason is still the panic std would have raised, with std's own message, so
//! a full disk under `kin log > file` is reported exactly as before.
//!
//! `kin init 2>&1 | head -1` is the case that fixed the design. Both streams
//! are one pipe that closes after one line, and init's contract, pinned in
//! `tests/init_non_tty_output.rs`, is that its status reports the admission
//! and not the pipe: progress is advisory, the admission is not. An earlier
//! shape of this module ended the process from a panic hook on the first
//! failed print, 0 for stdout and 141 for stderr. That stopped init at a
//! progress line with its store half written and reported 141 for an
//! admission that had every right to finish, and because the hook ran before
//! the unwind it also defeated the task boundary init keeps around its own
//! advisory writes. A cut reader is never a reason to report a failed
//! admission, and never a reason to report a successful one that did not
//! happen; the only way to satisfy both is to keep working.
//!
//! One write can still end a command early: an `io::Error` of kind
//! `BrokenPipe` that reached `main` through `?` from a write this module did
//! not make. [`exit_status`] answers that with [`CUT_OFF_STATUS`], 141, the
//! status a shell reports for a process `SIGPIPE` ended and the status this
//! process would have had under the default disposition, and prints nothing,
//! because the command stopped at that write and everything after it did not
//! run. 141 cannot be read as success of work that never happened, which is
//! what makes ending early acceptable there; 0 could be, which is why this
//! module's own writes never end anything.
//!
//! Resetting `SIGPIPE` to its default disposition would have been one line and
//! was rejected. The daemon transport is a socket, std sets `SO_NOSIGPIPE`
//! only on Apple platforms and never sends with `MSG_NOSIGNAL`, so on Linux a
//! write to a daemon that has since gone away would kill this process silently
//! instead of returning the error `kin commit` reads to find out whether its
//! change landed anyway.

use std::fmt;
use std::io::{self, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};

/// The status a shell reports for a process that `SIGPIPE` ended, 128 + 13,
/// and the status this process would have had under the default disposition.
/// Scripts already read it as "the reader closed early" rather than "the
/// command failed", which is exactly the news.
pub const CUT_OFF_STATUS: i32 = 141;

/// Set by the first write to meet a closed pipe on each stream, and read
/// before every write after it.
static STDOUT_GONE: AtomicBool = AtomicBool::new(false);
static STDERR_GONE: AtomicBool = AtomicBool::new(false);

/// `print!` for this crate: std's arguments, written through [`print_stdout`].
///
/// `#[macro_export]` places the four macros at the crate root so `main.rs`
/// imports them by name, and `#[macro_use]` on this module in `lib.rs` puts
/// them in textual scope for every module declared after it, which is why the
/// module is declared first there. A print site in this crate that reached
/// std's macro instead would panic on a closed pipe exactly as before.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::broken_pipe::print_stdout(::std::format_args!($($arg)*))
    };
}

/// `println!` for this crate; see [`print!`].
#[macro_export]
macro_rules! println {
    () => {
        $crate::broken_pipe::print_stdout(::std::format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::broken_pipe::print_stdout(::std::format_args!(
            "{}\n",
            ::std::format_args!($($arg)*)
        ))
    };
}

/// `eprint!` for this crate; see [`print!`].
#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => {
        $crate::broken_pipe::print_stderr(::std::format_args!($($arg)*))
    };
}

/// `eprintln!` for this crate; see [`print!`].
#[macro_export]
macro_rules! eprintln {
    () => {
        $crate::broken_pipe::print_stderr(::std::format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::broken_pipe::print_stderr(::std::format_args!(
            "{}\n",
            ::std::format_args!($($arg)*)
        ))
    };
}

/// Write one formatted print to stdout, tolerating a reader that has gone.
///
/// Under this crate's own unit tests the write goes to std's macro instead, so
/// libtest's per-test capture keeps working; the sink is exercised through the
/// fake streams in this module's tests and through the real binary in
/// `tests/cli_broken_pipe.rs` and `tests/commit_broken_pipe_exit.rs`. The
/// switch is a runtime `cfg!` rather than a `#[cfg]` so both arms compile in
/// every build and the test build carries no unreferenced sink.
#[doc(hidden)]
pub fn print_stdout(args: fmt::Arguments<'_>) {
    if cfg!(test) {
        std::print!("{args}");
        return;
    }
    write_through(
        &STDOUT_GONE,
        "stdout",
        || io::stdout().lock(),
        |out| out.write_fmt(args),
        stdout_reader_gone,
    );
}

/// Write one formatted print to stderr, tolerating a reader that has gone.
#[doc(hidden)]
pub fn print_stderr(args: fmt::Arguments<'_>) {
    if cfg!(test) {
        std::eprint!("{args}");
        return;
    }
    write_through(
        &STDERR_GONE,
        "stderr",
        || io::stderr().lock(),
        |err| err.write_fmt(args),
        stderr_reader_gone,
    );
}

/// Write a result that was rendered whole to stdout, tolerating a reader that
/// has gone.
///
/// For a command whose output is its work, such as `kin completions`: a reader
/// that took one line of it and left has what it wanted, and the command ends
/// as it would have had the reader stayed.
pub fn write_stdout(bytes: &[u8]) {
    write_through(
        &STDOUT_GONE,
        "stdout",
        || io::stdout().lock(),
        |out| out.write_all(bytes).and_then(|()| out.flush()),
        stdout_reader_gone,
    );
}

/// Perform one write to a stream this module guards.
///
/// The stream is skipped outright once its reader is known to be gone. The
/// first write to meet a closed pipe marks it so and runs `on_gone` exactly
/// once, and the caller carries on as if the write had landed. Any other
/// failure is the panic std raises for a failed print, with std's own message,
/// so nothing about a full disk or a bad descriptor changes here.
///
/// Generic over the writer, and handed the flag and the redirect as arguments,
/// so the unit tests below drive every arm against a fake stream without
/// touching the process's own.
fn write_through<W: io::Write>(
    gone: &AtomicBool,
    label: &str,
    open: impl FnOnce() -> W,
    write: impl FnOnce(&mut W) -> io::Result<()>,
    on_gone: impl FnOnce(),
) {
    if gone.load(Ordering::Acquire) {
        return;
    }
    let mut writer = open();
    match write(&mut writer) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
            if !gone.swap(true, Ordering::AcqRel) {
                on_gone();
            }
        }
        Err(error) => panic!("failed printing to {label}: {error}"),
    }
}

/// What happens to stdout once its reader is known to be gone.
fn stdout_reader_gone() {
    #[cfg(unix)]
    redirect_to_dev_null(libc::STDOUT_FILENO);
}

/// What happens to stderr once its reader is known to be gone.
fn stderr_reader_gone() {
    #[cfg(unix)]
    redirect_to_dev_null(libc::STDERR_FILENO);
}

/// Point a standard stream whose reader has gone at `/dev/null`.
///
/// This module's own writes already stop at the flag. The redirect is for
/// everything else that writes the same descriptor: a `println!` in a crate
/// this one calls into, a library that writes its own diagnostics, and a child
/// process that inherits the stream and would otherwise die of `SIGPIPE` or
/// meet the same `EPIPE`. A failure leaves the descriptor as it was, which is
/// no worse than before this ran.
#[cfg(unix)]
fn redirect_to_dev_null(fd: libc::c_int) {
    // SAFETY: plain libc calls on descriptors this process owns. `open`
    // returns a fresh descriptor or -1, `dup2` replaces one of the two
    // standard descriptors with it, and the fresh one is closed again. The
    // path is a NUL-terminated literal and no pointer outlives the call.
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
        if null < 0 {
            return;
        }
        libc::dup2(null, fd);
        libc::close(null);
    }
}

/// The status `main` ends with when the command returned an error, and the
/// report that goes with it.
///
/// An `io::Error` of kind `BrokenPipe` that is the error itself, under however
/// many layers of context were added on the way up, is a write this module did
/// not make meeting a reader that had gone. The command stopped at that write,
/// so the status is [`CUT_OFF_STATUS`] and nothing is printed: the one stream
/// that might still be open would only be told that the other one closed. The
/// error's source chain is deliberately not walked. A daemon request that
/// failed carries an io error underneath its transport error, and a commit
/// whose reply was lost must stay an error the caller can read, never a cut
/// reader.
///
/// Every other error is rendered the way std renders a `main` that returns
/// `Err`, `Error: {err:?}`, through [`print_stderr`], so a refusal nobody
/// reads any more still exits 1 rather than becoming a second broken-pipe
/// panic.
///
/// One class earns a second paragraph after that render. A command that ran out
/// of open file descriptors reports a kernel refusal naming a descriptor and a
/// store path, and neither is the problem or the fix, so
/// [`crate::open_files::remedy`] follows it with the limit, its value and the
/// command that raises it. This is the whole CLI's error boundary, so every
/// command gets it, not just the admission that found the class.
pub fn exit_status(error: &anyhow::Error) -> i32 {
    if is_cut_off(error) {
        return CUT_OFF_STATUS;
    }
    print_stderr(format_args!("Error: {error:?}\n"));
    if let Some(remedy) = crate::open_files::remedy(error) {
        print_stderr(format_args!("{remedy}"));
    }
    1
}

fn is_cut_off(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::BrokenPipe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A stream whose reader has gone: every write is `EPIPE`.
    struct ClosedPipe;

    impl io::Write for ClosedPipe {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A stream that fails for a reason that is not the reader leaving.
    struct FullDisk;

    impl io::Write for FullDisk {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("the disk is full"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_first_write_into_a_closed_pipe_marks_the_stream_gone_and_redirects_once() {
        let gone = AtomicBool::new(false);
        let redirects = Cell::new(0);
        let opened = Cell::new(0);
        let open = || {
            opened.set(opened.get() + 1);
            ClosedPipe
        };

        write_through(
            &gone,
            "stdout",
            open,
            |out| out.write_all(b"first"),
            || redirects.set(redirects.get() + 1),
        );
        assert!(
            gone.load(Ordering::Acquire),
            "the write that met the closed pipe must mark the stream gone"
        );
        assert_eq!(redirects.get(), 1, "the redirect runs on that first write");
        assert_eq!(opened.get(), 1);

        // The reader is known to be gone, so the stream is not even opened.
        write_through(
            &gone,
            "stdout",
            open,
            |out| out.write_all(b"second"),
            || redirects.set(redirects.get() + 1),
        );
        assert_eq!(opened.get(), 1, "a later write skips the stream entirely");
        assert_eq!(redirects.get(), 1, "and the redirect runs once per stream");
    }

    #[test]
    fn a_write_that_landed_leaves_the_stream_in_use() {
        let gone = AtomicBool::new(false);
        let mut sink = Vec::new();
        let redirected = Cell::new(false);
        write_through(
            &gone,
            "stdout",
            || &mut sink,
            |out| out.write_all(b"the result\n"),
            || redirected.set(true),
        );
        assert_eq!(sink, b"the result\n");
        assert!(!gone.load(Ordering::Acquire));
        assert!(!redirected.get());
    }

    #[test]
    fn a_write_that_failed_for_any_other_reason_is_still_a_panic() {
        let gone = AtomicBool::new(false);
        let redirected = Cell::new(false);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            write_through(
                &gone,
                "stdout",
                || FullDisk,
                |out| out.write_all(b"the result\n"),
                || redirected.set(true),
            );
        }));
        let payload = outcome.expect_err("a full disk is still a failed print");
        let message = payload
            .downcast_ref::<String>()
            .expect("the panic carries std's own message");
        assert_eq!(message, "failed printing to stdout: the disk is full");
        assert!(
            !gone.load(Ordering::Acquire),
            "only a closed pipe marks a stream gone"
        );
        assert!(!redirected.get());
    }

    #[test]
    fn a_broken_pipe_that_reached_main_as_itself_is_cut_off_not_a_success() {
        let bare: anyhow::Error = io::Error::from(io::ErrorKind::BrokenPipe).into();
        assert_eq!(exit_status(&bare), CUT_OFF_STATUS);
        let wrapped = anyhow::Error::from(io::Error::from(io::ErrorKind::BrokenPipe))
            .context("write the change log")
            .context("kin log");
        assert_eq!(exit_status(&wrapped), CUT_OFF_STATUS);
        let other: anyhow::Error = io::Error::from(io::ErrorKind::NotFound).into();
        assert_eq!(exit_status(&other), 1);
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
        assert_eq!(exit_status(&error), 1);
        // The control: the chain does carry the broken pipe, so a walk down
        // it would have answered 141, and this test would then be passing on
        // an error that never had one.
        assert!(error.chain().any(|cause| cause
            .downcast_ref::<io::Error>()
            .is_some_and(|cause| cause.kind() == io::ErrorKind::BrokenPipe)));
    }
}
