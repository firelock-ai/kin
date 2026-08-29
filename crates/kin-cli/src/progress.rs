// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! TTY-aware progress output for CLI commands.
//!
//! On a terminal: uses `\r` carriage returns for inline updating (smooth UX).
//! On a pipe/redirect: uses `\n` newlines so each update is a visible line
//! (e.g., in CI logs, MCP tool output, Claude Code background commands).
//!
//! Usage:
//! ```ignore
//! let mut progress = Progress::stderr();
//! progress.update(format_args!("[{}/{}] {}%", done, total, pct));
//! progress.finish(); // prints final newline
//! ```

use std::io::IsTerminal;

/// TTY-aware progress writer.
pub struct Progress {
    is_tty: bool,
    /// How many updates have been emitted (for throttling non-TTY output).
    updates: usize,
}

impl Progress {
    /// Create a progress writer that targets stderr.
    pub fn stderr() -> Self {
        Self {
            is_tty: std::io::stderr().is_terminal(),
            updates: 0,
        }
    }

    /// Emit a progress line. On TTY: overwrites the current line with `\r`.
    /// On non-TTY: prints a new line, but throttled to avoid flooding logs.
    pub fn update(&mut self, msg: std::fmt::Arguments<'_>) {
        self.updates += 1;

        if self.is_tty {
            eprint!("{}", rendered_update(true, &msg.to_string()));
        } else {
            // Non-TTY: print every 10th update as a full line
            // (avoids flooding CI/pipe output with hundreds of lines)
            if self.updates <= 1 || self.updates.is_multiple_of(10) {
                eprint!("{}", rendered_update(false, &msg.to_string()));
            }
        }
    }

    /// Finish the progress output. Ensures the cursor is on a new line.
    pub fn finish(&self) {
        if self.is_tty {
            eprintln!();
        }
    }

    /// Finish with a final message (always printed, regardless of throttle).
    ///
    /// This is the write that garbles without an erase, because it is the one
    /// reliably SHORTER than what it replaces: the daemon notice closes with
    /// `kin daemon ready in 6.7s` over a phase line more than twice its length.
    pub fn finish_with(&self, msg: std::fmt::Arguments<'_>) {
        if self.is_tty {
            eprint!("{}", rendered_update(true, &msg.to_string()));
            eprintln!();
        } else {
            eprint!("{}", rendered_update(false, &msg.to_string()));
        }
    }
}

/// The exact bytes one progress update writes, as a function of the stream.
///
/// A carriage return moves the cursor to column zero and clears nothing, so a
/// message shorter than the one already on the line leaves that one's tail
/// rendered after it, mid-word, and the reader sees two messages spliced
/// together. The erase to end of line is what prevents that, and it is the
/// reason this function exists.
///
/// Both branches render here rather than at their call sites, so the terminal
/// branch is testable without a terminal. `Progress` writes to the real stderr
/// and every test that drives a CLI reads a pipe, which takes the newline
/// branch, so the carriage-return branch had no coverage at all: the defect
/// this prevents was invisible to exactly the tests written to catch it.
fn rendered_update(is_tty: bool, msg: &str) -> String {
    if is_tty {
        format!("\r  {msg}\x1b[K")
    } else {
        format!("  {msg}\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The erase and the carriage return, each pinned by an assertion that
    /// only its own mutation can fail.
    #[test]
    fn a_shorter_terminal_update_erases_the_line_it_replaces() {
        let long = rendered_update(
            true,
            "phase: the daemon is listening and finishing readiness checks (15.9s)",
        );
        let short = rendered_update(true, "kin daemon ready in 6.7s");

        assert!(
            short.len() < long.len(),
            "the closing message is the shorter one, which is what makes the erase load-bearing"
        );
        assert!(
            short.ends_with("\x1b[K"),
            "a shorter message erases to end of line, or the longer line's tail stays on screen: {short:?}"
        );
        assert!(
            short.starts_with("\r  "),
            "and it returns to column zero before writing: {short:?}"
        );
    }

    /// The control that must stay silent. A pipe gets no escape sequence at
    /// all, so the erase cannot reach a CI log, an MCP payload or a captured
    /// stderr, and the two branches cannot be satisfied by one rendering.
    #[test]
    fn the_piped_branch_carries_no_escape_sequence() {
        let piped = rendered_update(false, "kin daemon ready in 6.7s");
        assert!(
            !piped.contains('\x1b'),
            "a redirected stream is read as text and must carry no escape: {piped:?}"
        );
        assert!(
            piped.ends_with('\n') && !piped.contains('\r'),
            "and it ends its own line rather than returning to the start of one: {piped:?}"
        );
    }
}
