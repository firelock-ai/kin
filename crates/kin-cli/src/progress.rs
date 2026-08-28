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

/// Write one progress fragment, tolerating a reader that already left.
///
/// The `eprint` macros panic on a write error, and the panic exit status is
/// 101. `kin commit ... 2>&1 | head -3` therefore reported a crash on a commit
/// that had already landed, because `head` took its lines and left and the next
/// progress write hit a closed pipe (FIR-2838). Progress is advisory and the
/// work is not: a consumer that stopped reading must not change what the
/// command reports. Nothing is reported when this fails, because stderr is the
/// surface a reporting failure would have to be reported on.
fn write_progress(args: std::fmt::Arguments<'_>) {
    use std::io::Write as _;
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_fmt(args);
    let _ = stderr.flush();
}

/// Say one advisory line on stderr, tolerating a reader that already left.
///
/// For notices that accompany work already done, where a departed reader must
/// not change what the command reports. Same rule and same reason as
/// [`write_progress`].
pub fn note(args: std::fmt::Arguments<'_>) {
    write_progress(args);
}

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
            // TTY: overwrite current line
            write_progress(format_args!("\r  {msg}"));
        } else {
            // Non-TTY: print every 10th update as a full line
            // (avoids flooding CI/pipe output with hundreds of lines)
            if self.updates <= 1 || self.updates.is_multiple_of(10) {
                write_progress(format_args!("  {msg}\n"));
            }
        }
    }

    /// Finish the progress output. Ensures the cursor is on a new line.
    pub fn finish(&self) {
        if self.is_tty {
            write_progress(format_args!("\n"));
        }
    }

    /// Finish with a final message (always printed, regardless of throttle).
    pub fn finish_with(&self, msg: std::fmt::Arguments<'_>) {
        if self.is_tty {
            write_progress(format_args!("\r  {msg}\n"));
        } else {
            write_progress(format_args!("  {msg}\n"));
        }
    }
}
