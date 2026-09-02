// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Thread-local allocation probe for this crate's memory tests.
//!
//! Test-only. Three modules price what a code path allocates against what a
//! copy of its input costs, and a probe in each would be three
//! `#[global_allocator]` declarations in one test binary, which Rust refuses.
//! This is the one, and the unit-test binary has no other allocator.
//!
//! Thread-local rather than process-wide on purpose: `cargo test` runs this
//! binary's tests in parallel threads, and a global counter would be moved by
//! whatever else happens to be running, which is the difference between a
//! measurement and a coincidence.
//!
//! Counts live heap rather than RSS. RSS keeps counting pages the allocator
//! freed but has not returned to the OS, so it is not reproducible across
//! allocators or platforms; live bytes are.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
    static REQUESTED: Cell<usize> = const { Cell::new(0) };
}

pub(crate) struct CountingAllocator;

#[global_allocator]
static COUNTING_ALLOCATOR: CountingAllocator = CountingAllocator;

/// What a measured body allocated on this thread.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Allocation {
    /// The most bytes live at once beyond what was live when the measurement
    /// began.
    pub(crate) peak_live: usize,
    /// Every byte requested, whether or not it was freed again before the
    /// peak. A copy made and dropped before the peak never shows in
    /// `peak_live`; this still sees it.
    pub(crate) requested: usize,
}

fn record(delta: isize) {
    // `try_with` because a thread tearing down has no thread-local left to
    // reach, and an allocator must not panic there.
    let _ = ARMED.try_with(|armed| {
        if !armed.get() {
            return;
        }
        if let Ok(grown) = usize::try_from(delta) {
            let _ = REQUESTED.try_with(|requested| {
                requested.set(requested.get().saturating_add(grown));
            });
        }
        let _ = LIVE.try_with(|live| {
            let now = live.get() + delta;
            live.set(now);
            let _ = PEAK.try_with(|peak| {
                if now > peak.get() {
                    peak.set(now);
                }
            });
        });
    });
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record(layout.size() as isize);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        record(-(layout.size() as isize));
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            record(new_size as isize - layout.size() as isize);
        }
        moved
    }
}

/// What `body` allocates on this thread.
pub(crate) fn measure(body: impl FnOnce()) -> Allocation {
    LIVE.with(|live| live.set(0));
    PEAK.with(|peak| peak.set(0));
    REQUESTED.with(|requested| requested.set(0));
    ARMED.with(|armed| armed.set(true));
    body();
    ARMED.with(|armed| armed.set(false));
    Allocation {
        peak_live: usize::try_from(PEAK.with(Cell::get)).unwrap_or(0),
        requested: REQUESTED.with(Cell::get),
    }
}

/// Peak live bytes allocated by `body` on this thread.
pub(crate) fn peak_live_bytes(body: impl FnOnce()) -> usize {
    measure(body).peak_live
}
