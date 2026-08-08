// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Per-phase progress reporting for exact Git repository admission.
//!
//! Admission runs a fixed ladder of phases, several of which walk the whole of
//! a repository's history and take minutes on a large repository. The only
//! output anywhere in the pipeline used to be the cross-file linker's bar,
//! which belongs to one phase and finishes long before the command does, so a
//! terminal could sit dead for minutes with no way to tell work from a hang.
//!
//! Every line goes to stderr, so machine-readable stdout stays clean. On a
//! terminal a phase redraws in place and leaves one completed line behind with
//! its elapsed time; off a terminal each phase prints a start line and an end
//! line, and in-phase detail is throttled so a pipe is not flooded.

use std::fmt::Arguments;
use std::io::{IsTerminal, Write};
use std::time::Instant;

/// Number of phases in the exact Git admission ladder. A ladder that completes
/// on a different count than this is a drift bug that would print `[16/15]` to
/// a user, so [`PhaseProgress::finish`] asserts the two agree.
pub(crate) const GIT_ADMISSION_PHASES: usize = 17;

/// Erase the current line and return to column zero. Only ever written to a
/// terminal, so a redirected log never receives escape bytes.
const ERASE_LINE: &str = "\x1b[2K\r";

/// Stderr phase reporter for a fixed-length phase ladder.
pub(crate) struct PhaseProgress {
    total: usize,
    is_tty: bool,
    index: usize,
    label: &'static str,
    detail_updates: usize,
    phase_started: Instant,
    started: Instant,
    in_phase: bool,
}

impl PhaseProgress {
    /// Start a reporter for a ladder of `total` phases.
    pub(crate) fn new(total: usize) -> Self {
        Self {
            total,
            is_tty: std::io::stderr().is_terminal(),
            index: 0,
            label: "",
            detail_updates: 0,
            phase_started: Instant::now(),
            started: Instant::now(),
            in_phase: false,
        }
    }

    /// Enter the next phase. Closes any open phase first, so a caller cannot
    /// leave a half-drawn line behind by forgetting to end one.
    pub(crate) fn begin(&mut self, label: &'static str) {
        if self.in_phase {
            self.end();
        }
        self.index += 1;
        self.label = label;
        self.detail_updates = 0;
        self.phase_started = Instant::now();
        self.in_phase = true;
        if self.is_tty {
            self.write(format_args!(
                "{ERASE_LINE}  [{:>2}/{}] {}...",
                self.index, self.total, self.label
            ));
        } else {
            self.writeln(format_args!(
                "  [{:>2}/{}] {}...",
                self.index, self.total, self.label
            ));
        }
    }

    /// Report progress within the current phase. Callers throttle their own
    /// call rate; this throttles again off a terminal so a pipe stays readable.
    pub(crate) fn detail(&mut self, detail: Arguments<'_>) {
        if !self.in_phase {
            return;
        }
        self.detail_updates += 1;
        if self.is_tty {
            self.write(format_args!(
                "{ERASE_LINE}  [{:>2}/{}] {} {} | {:.1}s",
                self.index,
                self.total,
                self.label,
                detail,
                self.phase_started.elapsed().as_secs_f64()
            ));
        } else if self.detail_updates <= 1 || self.detail_updates.is_multiple_of(10) {
            self.writeln(format_args!(
                "  [{:>2}/{}] {} {} | {:.1}s",
                self.index,
                self.total,
                self.label,
                detail,
                self.phase_started.elapsed().as_secs_f64()
            ));
        }
    }

    /// Close the current phase, leaving one line carrying its elapsed time.
    pub(crate) fn end(&mut self) {
        if !self.in_phase {
            return;
        }
        self.in_phase = false;
        let elapsed = self.phase_started.elapsed().as_secs_f64();
        let prefix = if self.is_tty { ERASE_LINE } else { "" };
        self.writeln(format_args!(
            "{prefix}  [{:>2}/{}] {} {:.1}s",
            self.index, self.total, self.label, elapsed
        ));
    }

    /// Close the ladder with one total-elapsed line.
    ///
    /// Only the success path finishes a ladder, so every declared phase must
    /// have run. Asserting that here is what keeps the declared total and the
    /// call sites from drifting apart unnoticed.
    pub(crate) fn finish(&mut self, label: &str) {
        debug_assert_eq!(
            self.index, self.total,
            "phase ladder completed {} of {} declared phases",
            self.index, self.total
        );
        self.end();
        self.writeln(format_args!(
            "  {label} in {:.1}s",
            self.started.elapsed().as_secs_f64()
        ));
    }

    fn write(&self, args: Arguments<'_>) {
        let mut stderr = std::io::stderr().lock();
        // Progress is advisory: a closed or full stderr must never fail an
        // admission that is otherwise proceeding correctly.
        let _ = stderr.write_fmt(args);
        let _ = stderr.flush();
    }

    fn writeln(&self, args: Arguments<'_>) {
        let mut stderr = std::io::stderr().lock();
        let _ = stderr.write_fmt(args);
        let _ = stderr.write_all(b"\n");
        let _ = stderr.flush();
    }
}

impl Drop for PhaseProgress {
    /// A phase abandoned by an early return still terminates its line, so an
    /// error message is never appended to a half-drawn progress line.
    fn drop(&mut self) {
        if self.in_phase {
            self.in_phase = false;
            self.writeln(format_args!(""));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_phase_ladder_numbers_every_phase_it_enters() {
        let mut progress = PhaseProgress::new(3);
        assert_eq!(progress.index, 0);
        progress.begin("first");
        assert_eq!(progress.index, 1);
        assert!(progress.in_phase);
        progress.end();
        assert!(!progress.in_phase);
        progress.begin("second");
        assert_eq!(progress.index, 2);
    }

    #[test]
    fn beginning_a_phase_closes_the_previous_one() {
        let mut progress = PhaseProgress::new(3);
        progress.begin("first");
        progress.begin("second");
        assert_eq!(progress.index, 2);
        assert!(progress.in_phase);
    }

    #[test]
    fn detail_outside_a_phase_is_ignored() {
        let mut progress = PhaseProgress::new(3);
        progress.detail(format_args!("1/2"));
        assert_eq!(progress.detail_updates, 0);
        progress.begin("first");
        progress.detail(format_args!("1/2"));
        assert_eq!(progress.detail_updates, 1);
    }

    #[test]
    #[should_panic(expected = "phase ladder completed 1 of 3 declared phases")]
    fn finishing_short_of_the_declared_total_is_a_drift_bug() {
        let mut progress = PhaseProgress::new(3);
        progress.begin("first");
        progress.finish("done");
    }

    #[test]
    fn finishing_on_the_declared_total_is_accepted() {
        let mut progress = PhaseProgress::new(2);
        progress.begin("first");
        progress.begin("second");
        progress.finish("done");
        assert_eq!(progress.index, 2);
    }

    #[test]
    fn each_phase_restarts_its_detail_throttle() {
        let mut progress = PhaseProgress::new(3);
        progress.begin("first");
        progress.detail(format_args!("1/2"));
        progress.detail(format_args!("2/2"));
        assert_eq!(progress.detail_updates, 2);
        progress.begin("second");
        assert_eq!(progress.detail_updates, 0);
    }
}
