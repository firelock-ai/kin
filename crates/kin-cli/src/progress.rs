// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! TTY-aware progress output for CLI commands.
//!
//! On a supported interactive terminal: uses `\r` for inline updating.
//! With either stream redirected, an unsupported terminal or CI: uses `\n`
//! newlines so each update is a visible line in the plain output.
//!
//! Usage:
//! ```ignore
//! let mut progress = Progress::stderr();
//! progress.update(format_args!("[{}/{}] {}%", done, total, pct));
//! progress.finish(); // prints final newline
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Set while a transient line is on stderr, waiting for [`clear_transient`].
static TRANSIENT_SHOWING: AtomicBool = AtomicBool::new(false);

/// The bytes that erase a transient line: back to column zero, then clear to
/// the end of the line, which leaves the cursor where the line began.
const ERASE_TRANSIENT: &str = "\r\x1b[K";

const PLAIN_UPDATE_INTERVAL: Duration = Duration::from_secs(10);

/// TTY-aware progress writer.
pub struct Progress {
    is_tty: bool,
    /// Terminal width in columns, when stderr is a terminal that reports one.
    width: Option<usize>,
    /// When a plain progress line last reached the output.
    last_plain_update: Option<Instant>,
}

impl Progress {
    /// Create a progress writer that targets stderr.
    pub fn stderr() -> Self {
        let is_tty = crate::screen::animation_allowed();
        let width = is_tty
            .then(|| console::Term::stderr().size_checked())
            .flatten()
            .map(|(_, columns)| usize::from(columns));
        Self {
            is_tty,
            width,
            last_plain_update: None,
        }
    }

    /// Emit a progress line. On TTY: overwrites the current line with `\r`.
    /// In plain output: prints immediately, then at most every ten seconds.
    pub fn update(&mut self, msg: std::fmt::Arguments<'_>) {
        if self.is_tty {
            eprint!("{}", rendered_update(true, self.width, &msg.to_string()));
        } else if admit_plain_update(&mut self.last_plain_update, Instant::now()) {
            eprint!("{}", rendered_update(false, None, &msg.to_string()));
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

/// Plain progress is a heartbeat, independent of how often a caller polls.
/// Final messages bypass this cadence and always reach the output.
fn admit_plain_update(last: &mut Option<Instant>, now: Instant) -> bool {
    if last.is_some_and(|last| now.saturating_duration_since(last) < PLAIN_UPDATE_INTERVAL) {
        return false;
    }
    *last = Some(now);
    true
}

impl Progress {
    /// Finish with a message that stays on screen only until the next
    /// [`clear_transient`].
    ///
    /// On a terminal the message replaces the progress line and the cursor
    /// stays at its end, with no newline, so the clear can take the whole line
    /// back and what prints next starts where it began. Off a terminal it is an
    /// ordinary finished line, the same bytes [`Progress::finish_with`]
    /// writes, because a log or a captured stream cannot be erased and its
    /// reader needs the line.
    ///
    /// The caller owes a [`clear_transient`] before anything else prints, or
    /// the next output continues the transient line.
    pub fn finish_transient(&self, msg: std::fmt::Arguments<'_>) {
        if self.is_tty {
            eprint!("{}", rendered_update(true, self.width, &msg.to_string()));
            TRANSIENT_SHOWING.store(true, Ordering::SeqCst);
        } else {
            eprint!("{}", rendered_update(false, None, &msg.to_string()));
        }
    }
}

/// Erase the transient line [`Progress::finish_transient`] left on screen,
/// if one is showing, and do nothing otherwise.
///
/// Safe to call from anywhere and any number of times: only the first call
/// after a transient line writes anything.
pub fn clear_transient() {
    if take_transient(&TRANSIENT_SHOWING) {
        eprint!("{ERASE_TRANSIENT}");
    }
}

/// Take the showing flag, `true` only for the first caller after it was set.
fn take_transient(flag: &AtomicBool) -> bool {
    flag.swap(false, Ordering::SeqCst)
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

    #[test]
    fn plain_progress_uses_elapsed_time_instead_of_poll_count() {
        let start = Instant::now();
        for tick_ms in [1, 200, 2000] {
            let mut last = None;
            let emitted: Vec<_> = (0..=27_000 / tick_ms)
                .map(|tick| tick * tick_ms)
                .filter(|elapsed| {
                    admit_plain_update(&mut last, start + Duration::from_millis(*elapsed))
                })
                .collect();
            assert_eq!(emitted, [0, 10_000, 20_000], "tick interval {tick_ms} ms");
        }
    }

    #[test]
    fn a_late_plain_heartbeat_does_not_create_catch_up_lines() {
        let start = Instant::now();
        let mut last = None;
        assert!(admit_plain_update(&mut last, start));
        assert!(!admit_plain_update(
            &mut last,
            start + Duration::from_millis(9999)
        ));
        assert!(admit_plain_update(
            &mut last,
            start + Duration::from_secs(35)
        ));
        assert!(!admit_plain_update(
            &mut last,
            start + Duration::from_secs(35)
        ));
        assert!(!admit_plain_update(
            &mut last,
            start + Duration::from_secs(44)
        ));
        assert!(admit_plain_update(
            &mut last,
            start + Duration::from_secs(45)
        ));
    }

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

    /// A transient line is erased whole, once. The erase returns to column
    /// zero and clears to the end, so the answer that follows starts on a
    /// clean line, and a second clear writes nothing that could erase it.
    #[test]
    fn a_transient_line_is_erased_once() {
        assert_eq!(ERASE_TRANSIENT, "\r\x1b[K");
        let flag = AtomicBool::new(false);
        assert!(!take_transient(&flag), "nothing showing, nothing to erase");
        flag.store(true, Ordering::SeqCst);
        assert!(take_transient(&flag), "a showing line is erased");
        assert!(
            !take_transient(&flag),
            "and only once, so a later clear cannot erase the line printed over it"
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
