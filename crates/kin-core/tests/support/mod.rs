// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Live-heap instrumentation shared by the admission memory tests.
//!
//! Two pieces that only mean something together. [`Counting`] is a global
//! allocator that tracks live and peak heap, and [`PhaseHeapLayer`] reads those
//! counters at every admission-phase boundary, so a run reports what each phase
//! RETAINS as well as what it merely allocates.
//!
//! That distinction is the whole point, and no process-level metric can make it.
//! Resident set and physical footprint both keep counting memory the program has
//! already freed, because the allocator does not return pages to the OS
//! promptly, so they credit a phase with allocation it released before the phase
//! ended. A phase that allocates a gigabyte and frees it looks identical to one
//! that allocates a gigabyte and holds it. The fixes those two need are opposite.
//!
//! A binary that installs [`Counting`] holds exactly one test on purpose: the
//! counters are process-wide, and a second test running beside it would charge
//! its allocations to the first.

#![allow(dead_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use tracing_subscriber::layer::{Context, SubscriberExt as _};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::Layer;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// Bytes currently allocated and not yet freed.
pub fn live() -> usize {
    LIVE.load(Ordering::SeqCst)
}

/// High-water mark of [`live`] since the last [`reset_peak`].
pub fn peak() -> usize {
    PEAK.load(Ordering::SeqCst)
}

/// Drop the high-water mark back to what is live right now.
///
/// Called once a fixture is built and before the code under measurement runs,
/// so the fixture's own allocation is not charged to it.
pub fn reset_peak() {
    PEAK.store(LIVE.load(Ordering::SeqCst), Ordering::SeqCst);
}

/// Global allocator that counts live and peak bytes.
pub struct Counting;

fn charge(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: every branch forwards to the system allocator with the same pointer
// and layout it was given, and only adjusts counters around that call.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            charge(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            charge(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let fresh = unsafe { System.realloc(ptr, layout, new_size) };
        if !fresh.is_null() {
            if new_size >= layout.size() {
                charge(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        fresh
    }
}

/// Prefix of the span names the layer records. Init opens one span per
/// admission phase under this prefix.
pub const PHASE_PREFIX: &str = "kin.init.";

/// The other span namespace worth sampling: kin-db's own commit preparation.
///
/// `kin.init.commit_bootstrap_transaction` hands the whole history to kin-db and
/// is where the peak now sits, so a probe that stops at kin's own spans reports
/// one opaque number for the largest phase in the ladder. kin-db reports its
/// preparation laps as spans as of kin-db#220, which is in the pinned 0.7.49, so
/// the laps are already there to be sampled and only this filter kept them out.
pub const DB_PHASE_PREFIX: &str = "kindb.";

/// Whether a span name belongs to a phase this probe accounts for.
fn is_sampled_phase(phase: &str) -> bool {
    phase.starts_with(PHASE_PREFIX) || phase.starts_with(DB_PHASE_PREFIX)
}

/// One reading of the counters at a phase boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhaseSample {
    /// Span name, always `'static` because tracing metadata is.
    pub phase: &'static str,
    pub entering: bool,
    pub live: usize,
    pub peak: usize,
}

static SAMPLES: Mutex<Vec<PhaseSample>> = Mutex::new(Vec::new());

/// Every sample recorded so far, in order.
pub fn samples() -> Vec<PhaseSample> {
    SAMPLES.lock().expect("phase samples poisoned").clone()
}

fn record(sample: PhaseSample) {
    if std::env::var_os("KIN_HEAP_PHASES").is_some() {
        eprintln!(
            "KINHEAP {} {} live={:.1}MiB peak={:.1}MiB",
            if sample.entering { "enter" } else { "exit " },
            sample.phase,
            sample.live as f64 / 1_048_576.0,
            sample.peak as f64 / 1_048_576.0,
        );
    }
    if let Ok(mut samples) = SAMPLES.lock() {
        samples.push(sample);
    }
}

/// Records live and peak heap on entry to and exit from each admission phase.
pub struct PhaseHeapLayer;

impl<S> Layer<S> for PhaseHeapLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_enter(&self, id: &tracing::span::Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let phase = span.name();
            if is_sampled_phase(phase) {
                record(PhaseSample {
                    phase,
                    entering: true,
                    live: live(),
                    peak: peak(),
                });
            }
        }
    }

    fn on_exit(&self, id: &tracing::span::Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let phase = span.name();
            if is_sampled_phase(phase) {
                record(PhaseSample {
                    phase,
                    entering: false,
                    live: live(),
                    peak: peak(),
                });
            }
        }
    }
}

/// Install the layer for the rest of the process. Safe to call more than once.
pub fn install_phase_layer() {
    let _ = tracing_subscriber::registry()
        .with(PhaseHeapLayer)
        .try_init();
}

/// Peak growth charged to each phase, largest first.
///
/// A phase's contribution is how far the high-water mark moved between entering
/// it and leaving it. Nested phases are reported on their own names, so an inner
/// phase's growth also appears in its parent's; read the deepest name that
/// accounts for a jump.
///
/// Growth is measured against the RUNNING high-water mark, not against zero, so
/// a phase that allocates less than some earlier phase already did reports no
/// growth even though it allocated. That is the right question for "what does
/// this phase add to the peak the machine has to survive", and the wrong one for
/// "how much does this phase allocate"; the retained column answers neither, and
/// is there to separate a structure held too long from churn inside one phase.
pub fn peak_growth_by_phase() -> Vec<(&'static str, usize, usize)> {
    let samples = samples();
    let mut out: Vec<(&'static str, usize, usize)> = Vec::new();
    for (index, sample) in samples.iter().enumerate() {
        if !sample.entering {
            continue;
        }
        let exit = samples
            .iter()
            .skip(index + 1)
            .find(|later| !later.entering && later.phase == sample.phase);
        if let Some(exit) = exit {
            let grew = exit.peak.saturating_sub(sample.peak);
            let retained = exit.live.saturating_sub(sample.live);
            out.push((sample.phase, grew, retained));
        }
    }
    out.sort_by(|a, b| b.1.cmp(&a.1));
    out
}

/// One line per phase, largest peak growth first, for a failure message.
pub fn phase_attribution_table() -> String {
    let mut text = String::from("peak growth by phase (MiB grew / MiB retained):\n");
    for (phase, grew, retained) in peak_growth_by_phase() {
        text.push_str(&format!(
            "  {:>8.1} / {:>8.1}  {phase}\n",
            grew as f64 / 1_048_576.0,
            retained as f64 / 1_048_576.0,
        ));
    }
    text
}
