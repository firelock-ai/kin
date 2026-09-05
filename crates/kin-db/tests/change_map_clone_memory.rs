// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cloning a decoded snapshot must share its immutable change history.
//!
//! Price the retained heap and peak in units of an explicit deep copy of the
//! same map. Six live clones make history-sized allocations visible, while a
//! real copy is the positive control for the allocator and the ceiling.
//! This file has one test because its allocator counters are process-global.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use kin_db::storage::ChangeMapInner;
use kin_db::GraphSnapshot;
use kin_model::{
    compute_semantic_change_id, AuthorId, ChangeOrigin, Hash256, SemanticChange, SemanticChangeId,
    Timestamp,
};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

fn record_allocation(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            if new_size >= layout.size() {
                record_allocation(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn live_bytes() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// Arm the peak at the current live heap and return that floor.
fn arm_peak() -> usize {
    let floor = LIVE.load(Ordering::Relaxed);
    PEAK.store(floor, Ordering::Relaxed);
    floor
}

fn peak_growth_since(floor: usize) -> usize {
    PEAK.load(Ordering::Relaxed).saturating_sub(floor)
}

/// Live bytes that `build` allocates and still holds when it returns.
fn retained_by<T>(build: impl FnOnce() -> T) -> (T, usize) {
    let before = live_bytes();
    let value = build();
    (value, live_bytes().saturating_sub(before))
}

const COMMITS: usize = 300;
const CHANGE_PAYLOAD_BYTES: usize = 8_192;
const CLONES: usize = 6;
const MAX_CLONE_HISTORY_COPIES: f64 = 0.25;

fn snapshot_with_history() -> GraphSnapshot {
    let mut snapshot = GraphSnapshot::empty();
    let timestamp = Timestamp(
        chrono::DateTime::parse_from_rfc3339("2026-08-23T00:00:00Z")
            .expect("fixed timestamp parses")
            .with_timezone(&chrono::Utc),
    );
    let mut parent = None;
    for index in 0..COMMITS {
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            parents: parent.into_iter().collect(),
            timestamp: timestamp.clone(),
            author: AuthorId::new("history-memory"),
            message: format!("history change {index}: ")
                + &"payload ".repeat(CHANGE_PAYLOAD_BYTES / 8),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            origin: ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };
        change.id = compute_semantic_change_id(&change).expect("change id computes");
        parent = Some(change.id);
        snapshot.changes.insert(change.id, change);
    }
    snapshot
}

#[test]
fn decoded_snapshot_clones_share_history_allocations() {
    let snapshot = snapshot_with_history();
    assert!(snapshot.changes.is_decoded());

    let control_floor = arm_peak();
    let (control, history_bytes) = retained_by(|| {
        snapshot
            .changes
            .iter()
            .map(|(id, change)| (*id, change.clone()))
            .collect::<ChangeMapInner>()
    });
    let control_peak = peak_growth_since(control_floor);
    assert_eq!(control.len(), COMMITS);
    assert!(
        history_bytes >= COMMITS * CHANGE_PAYLOAD_BYTES,
        "the real history copy must retain its payload, got {history_bytes} bytes"
    );
    let ceiling = (history_bytes as f64 * MAX_CLONE_HISTORY_COPIES) as usize;
    assert!(
        control_peak > ceiling,
        "a real history copy must fail the sharing ceiling"
    );
    drop(control);

    let floor = arm_peak();
    let (clones, retained) =
        retained_by(|| std::array::from_fn::<_, CLONES, _>(|_| snapshot.clone()));
    let peak = peak_growth_since(floor);
    println!(
        "one history copy: {history_bytes} bytes; positive-control peak: {control_peak} bytes\n\
         {CLONES} decoded snapshot clones retained {retained} bytes; peak: {peak} bytes; \
         ceiling: {ceiling} bytes"
    );

    for clone in &clones {
        assert_eq!(clone.changes.len(), COMMITS);
        assert_eq!(clone.changes, snapshot.changes);
    }
    assert!(
        retained <= ceiling && peak <= ceiling,
        "{CLONES} decoded snapshot clones allocated {retained} retained bytes and {peak} peak \
         bytes, exceeding {MAX_CLONE_HISTORY_COPIES} of the {history_bytes}-byte history; \
         unchanged snapshots must share history until a mutation needs its own entries"
    );

    let (owned_copy, shared_retained) = retained_by(|| clones[0].changes.clone().into_inner());
    assert_eq!(owned_copy, snapshot.changes);
    assert!(
        shared_retained >= history_bytes,
        "taking a still-shared map must allocate independent owned entries"
    );
    drop(owned_copy);
    drop(clones);

    let floor = arm_peak();
    let (owned, unique_retained) = retained_by(|| snapshot.changes.into_inner());
    let unique_peak = peak_growth_since(floor);
    assert_eq!(owned.len(), COMMITS);
    assert!(
        unique_retained <= ceiling && unique_peak <= ceiling,
        "taking a unique map must move its allocation, got {unique_retained} retained bytes \
         and {unique_peak} peak bytes"
    );
    println!(
        "taking shared history retained {shared_retained} bytes; taking unique history \
         retained {unique_retained} bytes and peaked at {unique_peak} bytes"
    );
}
