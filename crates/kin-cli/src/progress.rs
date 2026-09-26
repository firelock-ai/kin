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
    /// Terminal width in columns, when stderr is a terminal that reports one.
    width: Option<usize>,
    /// How many updates have been emitted (for throttling non-TTY output).
    updates: usize,
}

impl Progress {
    /// Create a progress writer that targets stderr.
    pub fn stderr() -> Self {
        let is_tty = std::io::stderr().is_terminal();
        let width = is_tty
            .then(|| console::Term::stderr().size_checked())
            .flatten()
            .map(|(_, columns)| usize::from(columns));
        Self {
            is_tty,
            width,
            updates: 0,
        }
    }

    /// Emit a progress line. On TTY: overwrites the current line with `\r`.
    /// On non-TTY: prints a new line, but throttled to avoid flooding logs.
    pub fn update(&mut self, msg: std::fmt::Arguments<'_>) {
        self.updates += 1;

        if self.is_tty {
            eprint!("{}", rendered_update(true, self.width, &msg.to_string()));
        } else {
            // Non-TTY: print every 10th update as a full line
            // (avoids flooding CI/pipe output with hundreds of lines)
            if self.updates <= 1 || self.updates.is_multiple_of(10) {
                eprint!("{}", rendered_update(false, None, &msg.to_string()));
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
            eprint!("{}", rendered_update(true, self.width, &msg.to_string()));
            eprintln!();
        } else {
            eprint!("{}", rendered_update(false, None, &msg.to_string()));
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
///
/// On a terminal the line is also clipped to its width. A carriage return
/// reaches only the last row of a wrapped line, so an update wider than the
/// terminal left its first rows behind for good, mid-word, above the next
/// update. The clip keeps one column spare so the cursor never wraps.
fn rendered_update(is_tty: bool, width: Option<usize>, msg: &str) -> String {
    if is_tty {
        let msg = match width {
            Some(width) if width > 3 => console::truncate_str(msg, width - 3, "…"),
            _ => std::borrow::Cow::Borrowed(msg),
        };
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
            None,
            "phase: the daemon is listening and finishing readiness checks (15.9s)",
        );
        let short = rendered_update(true, None, "kin daemon ready in 6.7s");

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
        let piped = rendered_update(false, None, "kin daemon ready in 6.7s");
        assert!(
            !piped.contains('\x1b'),
            "a redirected stream is read as text and must carry no escape: {piped:?}"
        );
        assert!(
            piped.ends_with('\n') && !piped.contains('\r'),
            "and it ends its own line rather than returning to the start of one: {piped:?}"
        );
    }

    /// A terminal update never wraps. The daemon-start notice is 107 columns,
    /// and on an 80-column terminal its first row used to stay on screen.
    #[test]
    fn a_terminal_update_is_clipped_to_the_terminal_width() {
        let notice = "starting the kin daemon for this repository; the first query after a start \
                      waits for it to load the graph";
        let rendered = rendered_update(true, Some(80), notice);
        let visible = console::strip_ansi_codes(&rendered);
        let visible = visible.trim_start_matches('\r');
        assert!(
            console::measure_text_width(visible) < 80,
            "a clipped update fits the terminal: {visible:?}"
        );
        assert!(
            visible.ends_with('…'),
            "and says it was clipped: {visible:?}"
        );
        let piped = rendered_update(false, None, notice);
        assert!(
            piped.contains("load the graph"),
            "a pipe keeps the whole line: {piped:?}"
        );
    }
}
