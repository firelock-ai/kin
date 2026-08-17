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
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Number of phases in the exact Git admission ladder. A ladder that completes
/// on a different count than this is a drift bug that would print `[16/15]` to
/// a user, so [`PhaseProgress::finish`] asserts the two agree.
pub(crate) const GIT_ADMISSION_PHASES: usize = 17;

/// Erase the current line and return to column zero. Only ever written to a
/// terminal, so a redirected log never receives escape bytes.
const ERASE_LINE: &str = "\x1b[2K\r";

/// The ladder a long phase's own instrumentation should report into.
///
/// A phase that spends minutes inside one call into another crate cannot tick
/// this ladder itself, because the call takes no progress handle and the crate
/// below has no way to reach one. What it does have is `tracing`, and the
/// admission commands already raise the emitting targets to `info` so the work
/// says something while it runs. Before this, that something was a raw log
/// record written straight over the redrawn phase line, complete with ANSI and
/// the internal span path it was emitted under.
///
/// So the ladder registers itself here for its lifetime and a subscriber layer
/// hands those events to [`report_admission_progress`] instead of formatting
/// them. The phase line advances, and nothing internal reaches the user.
static ACTIVE_LADDER: Mutex<Option<Arc<Mutex<Ladder>>>> = Mutex::new(None);

/// Report progress within whatever admission phase is currently open.
///
/// Returns whether a ladder was live to take it, so a caller with no ladder to
/// report into can print the line itself rather than dropping it.
///
/// Never blocks on the ladder's own writes: the lock is held only for the
/// redraw, and the emitting thread is by construction not the one inside a
/// [`PhaseProgress`] method, because none of them log.
pub fn report_admission_progress(detail: &str) -> bool {
    let Ok(active) = ACTIVE_LADDER.lock() else {
        return false;
    };
    let Some(ladder) = active.as_ref() else {
        return false;
    };
    let Ok(mut ladder) = ladder.lock() else {
        return false;
    };
    ladder.detail(format_args!("{detail}"))
}

/// Stderr phase reporter for a fixed-length phase ladder.
pub(crate) struct PhaseProgress {
    ladder: Arc<Mutex<Ladder>>,
}

/// The ladder's own state, behind the lock the reporter and the subscriber
/// layer share.
struct Ladder {
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
    ///
    /// Installs it as the process's live admission ladder. Nested admissions do
    /// not happen, and if one ever did the inner ladder would take the slot and
    /// hand it back on drop, which is the same discipline a single ladder
    /// already keeps.
    pub(crate) fn new(total: usize) -> Self {
        let ladder = Arc::new(Mutex::new(Ladder {
            total,
            is_tty: std::io::stderr().is_terminal(),
            index: 0,
            label: "",
            detail_updates: 0,
            phase_started: Instant::now(),
            started: Instant::now(),
            in_phase: false,
        }));
        if let Ok(mut active) = ACTIVE_LADDER.lock() {
            *active = Some(Arc::clone(&ladder));
        }
        Self { ladder }
    }

    fn with<R>(&mut self, act: impl FnOnce(&mut Ladder) -> R) -> Option<R> {
        self.ladder.lock().ok().map(|mut ladder| act(&mut ladder))
    }

    /// Enter the next phase. Closes any open phase first, so a caller cannot
    /// leave a half-drawn line behind by forgetting to end one.
    pub(crate) fn begin(&mut self, label: &'static str) {
        self.with(|ladder| ladder.begin(label));
    }

    /// Report progress within the current phase. Callers throttle their own
    /// call rate; this throttles again off a terminal so a pipe stays readable.
    pub(crate) fn detail(&mut self, detail: Arguments<'_>) {
        self.with(|ladder| ladder.detail(detail));
    }

    /// Close the current phase, leaving one line carrying its elapsed time.
    ///
    /// Admission never ends a phase without entering the next one or finishing,
    /// and both of those close the open phase themselves, so nothing outside
    /// the tests that pin that behaviour needs to reach this directly.
    #[cfg(test)]
    fn end(&mut self) {
        self.with(|ladder| ladder.end());
    }

    /// Close the ladder with one total-elapsed line.
    pub(crate) fn finish(&mut self, label: &str) {
        self.with(|ladder| ladder.finish(label));
    }

    #[cfg(test)]
    fn index(&self) -> usize {
        self.ladder.lock().expect("ladder lock").index
    }

    #[cfg(test)]
    fn in_phase(&self) -> bool {
        self.ladder.lock().expect("ladder lock").in_phase
    }

    #[cfg(test)]
    fn detail_updates(&self) -> usize {
        self.ladder.lock().expect("ladder lock").detail_updates
    }
}

impl Drop for PhaseProgress {
    /// Release the process ladder slot, and terminate a line a phase abandoned
    /// by an early return left half-drawn, so an error message is never
    /// appended to it.
    fn drop(&mut self) {
        if let Ok(mut active) = ACTIVE_LADDER.lock() {
            let ours = active
                .as_ref()
                .is_some_and(|installed| Arc::ptr_eq(installed, &self.ladder));
            if ours {
                *active = None;
            }
        }
        self.with(|ladder| {
            if ladder.in_phase {
                ladder.in_phase = false;
                ladder.writeln(format_args!(""));
            }
        });
    }
}

impl Ladder {
    fn begin(&mut self, label: &'static str) {
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

    /// Reports whether an open phase took it. A ladder between phases has no
    /// line to advance, and telling the caller so is what lets an event that
    /// arrives then be printed rather than silently dropped.
    fn detail(&mut self, detail: Arguments<'_>) -> bool {
        if !self.in_phase {
            return false;
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
        true
    }

    fn end(&mut self) {
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

    /// Only the success path finishes a ladder, so every declared phase must
    /// have run. Asserting that here is what keeps the declared total and the
    /// call sites from drifting apart unnoticed.
    fn finish(&mut self, label: &str) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_phase_ladder_numbers_every_phase_it_enters() {
        let _serial = ladder_slot().lock().unwrap_or_else(|e| e.into_inner());
        let mut progress = PhaseProgress::new(3);
        assert_eq!(progress.index(), 0);
        progress.begin("first");
        assert_eq!(progress.index(), 1);
        assert!(progress.in_phase());
        progress.end();
        assert!(!progress.in_phase());
        progress.begin("second");
        assert_eq!(progress.index(), 2);
    }

    #[test]
    fn beginning_a_phase_closes_the_previous_one() {
        let _serial = ladder_slot().lock().unwrap_or_else(|e| e.into_inner());
        let mut progress = PhaseProgress::new(3);
        progress.begin("first");
        progress.begin("second");
        assert_eq!(progress.index(), 2);
        assert!(progress.in_phase());
    }

    #[test]
    fn detail_outside_a_phase_is_ignored() {
        let _serial = ladder_slot().lock().unwrap_or_else(|e| e.into_inner());
        let mut progress = PhaseProgress::new(3);
        progress.detail(format_args!("1/2"));
        assert_eq!(progress.detail_updates(), 0);
        progress.begin("first");
        progress.detail(format_args!("1/2"));
        assert_eq!(progress.detail_updates(), 1);
    }

    #[test]
    #[should_panic(expected = "phase ladder completed 1 of 3 declared phases")]
    fn finishing_short_of_the_declared_total_is_a_drift_bug() {
        let _serial = ladder_slot().lock().unwrap_or_else(|e| e.into_inner());
        let mut progress = PhaseProgress::new(3);
        progress.begin("first");
        progress.finish("done");
    }

    #[test]
    fn finishing_on_the_declared_total_is_accepted() {
        let _serial = ladder_slot().lock().unwrap_or_else(|e| e.into_inner());
        let mut progress = PhaseProgress::new(2);
        progress.begin("first");
        progress.begin("second");
        progress.finish("done");
        assert_eq!(progress.index(), 2);
    }

    /// The sink advances the open phase, declines when none is open, and stops
    /// reaching a ladder that has been dropped.
    ///
    /// Serialized with the other ladder-installing tests through one mutex,
    /// because the sink is process-global by construction: the events it
    /// carries are emitted from inside a call that has no handle to pass.
    #[test]
    fn the_progress_sink_reaches_the_open_phase_and_nothing_else() {
        let _serial = ladder_slot().lock().unwrap_or_else(|e| e.into_inner());

        assert!(
            !crate::report_admission_progress("before any ladder"),
            "with no ladder installed there is no phase to advance"
        );

        {
            let mut progress = PhaseProgress::new(2);
            assert!(
                !crate::report_admission_progress("between phases"),
                "an installed ladder that has entered no phase has no line yet"
            );
            progress.begin("commit bootstrap transaction");
            assert!(
                crate::report_admission_progress("4096/6413 changes validated"),
                "an open phase takes the line"
            );
            assert_eq!(
                progress.detail_updates(),
                1,
                "the sink must advance the same counter the phase's own detail does"
            );
        }

        assert!(
            !crate::report_admission_progress("after the ladder dropped"),
            "a dropped ladder must release the slot rather than be written into"
        );
    }

    /// One mutex for every test that installs a ladder, since they share the
    /// process slot.
    fn ladder_slot() -> &'static Mutex<()> {
        static SLOT: Mutex<()> = Mutex::new(());
        &SLOT
    }

    #[test]
    fn each_phase_restarts_its_detail_throttle() {
        let _serial = ladder_slot().lock().unwrap_or_else(|e| e.into_inner());
        let mut progress = PhaseProgress::new(3);
        progress.begin("first");
        progress.detail(format_args!("1/2"));
        progress.detail(format_args!("2/2"));
        assert_eq!(progress.detail_updates(), 2);
        progress.begin("second");
        assert_eq!(progress.detail_updates(), 0);
    }
}
