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
            // TTY: overwrite current line
            eprint!("\r  {msg}");
        } else {
            // Non-TTY: print every 10th update as a full line
            // (avoids flooding CI/pipe output with hundreds of lines)
            if self.updates <= 1 || self.updates.is_multiple_of(10) {
                eprintln!("  {msg}");
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
    pub fn finish_with(&self, msg: std::fmt::Arguments<'_>) {
        if self.is_tty {
            eprint!("\r  {msg}");
            eprintln!();
        } else {
            eprintln!("  {msg}");
        }
    }
}
