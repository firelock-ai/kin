// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//! What proving a snapshot round-trips holds while it does it.
//!
//! Before writing bytes to the authority store, the write path proved they
//! decode. It proved it by decoding them into an owned `GraphSnapshot` and
//! dropping the result on the next line. On a converted repository that
//! discarded value is the repository: about 855 MiB on psf/requests at full
//! history, allocated while the encoded frame, the retained import ladder, the
//! successor authority state and the successor change map are all still live.
//!
//! It is the last thing a conversion does, so every retained byte underneath it
//! is already committed when it happens, which is what made it the ceiling of
//! the whole run's peak rather than one more term in it (FIR-2654).
//!
//! The obligation is real and stays: refusing to write bytes that cannot be read
//! back is durability insurance, and it is the check that catches a serializer
//! defect before it becomes an unreadable store. What changed is that the proof
//! no longer keeps what it proves. Every element is still parsed as its declared
//! type, so a custom `Deserialize` impl that disagrees with its serializer is
//! still caught; each parsed element is dropped as soon as it has been proved.
//!
//! Live heap rather than resident set, for the reason the sibling guards give:
//! resident set keeps counting memory the allocator has freed and not returned,
//! so it moves with the platform, while live heap moves when and only when the
//! code holds differently.
//!
//! The ceiling below is expressed against the SNAPSHOT the bytes decode to, not
//! against the two calls' ratio, because the control call additionally runs the
//! semantic admission pass and comparing the two directly would credit this
//! change with that pass's allocation as well.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use kin_db::GraphSnapshot;
use kin_model::{
    Entity, EntityId, EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm,
    Hash256, LanguageId, SemanticFingerprint, Visibility,
};

// --- the instrument -------------------------------------------------------

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

/// Arm the peak at the current live heap and return that floor.
fn arm_peak() -> usize {
    let floor = LIVE.load(Ordering::Relaxed);
    PEAK.store(floor, Ordering::Relaxed);
    floor
}

fn peak_growth_since(floor: usize) -> usize {
    PEAK.load(Ordering::Relaxed).saturating_sub(floor)
}

// --- the fixture ----------------------------------------------------------

/// Enough entities that the frame is worth measuring against the harness's own
/// allocation rather than lost in it.
const ENTITIES: usize = 4_000;

/// Bytes of documentation body per entity, so the snapshot has real mass.
const ENTITY_PAYLOAD_BYTES: usize = 2_048;

fn measurement_entity(index: usize) -> Entity {
    let path = format!("src/module_{index}.rs");
    let name = format!("kin_{index}");
    let byte = (index % 251) as u8;
    Entity {
        id: EntityId::from_content(&path, &name, "function", 1),
        kind: EntityKind::Function,
        name: name.clone(),
        language: LanguageId::Rust,
        fingerprint: SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([byte; 32]),
            signature_hash: Hash256::from_bytes([byte.wrapping_add(1); 32]),
            behavior_hash: Hash256::from_bytes([byte.wrapping_add(2); 32]),
            equivalence_hash: Hash256::from_bytes([byte.wrapping_add(3); 32]),
            stability_score: 1.0,
        },
        file_origin: Some(FilePathId::new(&path)),
        span: None,
        signature: format!("fn {name}()"),
        visibility: Visibility::Public,
        role: EntityRole::Source,
        doc_summary: Some(format!("{name} ").repeat(ENTITY_PAYLOAD_BYTES / 8)),
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

fn measurement_snapshot() -> GraphSnapshot {
    let mut snapshot = GraphSnapshot::empty();
    for index in 0..ENTITIES {
        let entity = measurement_entity(index);
        snapshot.entities.insert(entity.id, entity);
    }
    snapshot
}

// --- the guard ------------------------------------------------------------

/// Fraction of one decoded snapshot the round-trip proof may hold at its peak.
///
/// Set from measurement on this fixture, not from taste. The proof that decoded
/// into an owned `GraphSnapshot` holds one whole snapshot by construction, so it
/// measures at or above 1.0. The draining proof holds one entry at a time and
/// measures near zero. A ceiling of 0.25 fails the first and passes the second
/// with room on both sides, and it is a ratio of two live-heap readings taken in
/// one process, so it is profile- and host-independent.
const PROOF_PEAK_FRACTION: f64 = 0.25;

/// Proving a snapshot round-trips must not hold the snapshot.
#[test]
fn proving_a_snapshot_round_trips_does_not_hold_it() {
    let snapshot = measurement_snapshot();
    let bytes = snapshot
        .to_bytes()
        .expect("the fixture snapshot serializes");
    let frame_bytes = bytes.len();
    assert!(
        frame_bytes > 1_000_000,
        "the fixture must be large enough to price a copy of the snapshot, got {frame_bytes} bytes"
    );

    // The control, and the reason this guard exists: a decode that KEEPS the
    // snapshot. `from_bytes` is the public decoder; it also runs the semantic
    // admission pass, so its reading is an upper bound on what the old proof
    // cost and is used only to show the order of magnitude that was removed.
    let warm = GraphSnapshot::from_bytes(&bytes).expect("the fixture decodes");
    drop(warm);
    let control_floor = arm_peak();
    let decoded = GraphSnapshot::from_bytes(&bytes).expect("the fixture decodes");
    let control_growth = peak_growth_since(control_floor);
    drop(decoded);

    // Warm the proof path the same way, so what is measured is the call's own
    // growth rather than one-time setup.
    GraphSnapshot::prove_pre_validated_round_trip(&bytes).expect("the fixture round-trips");
    let floor = arm_peak();
    GraphSnapshot::prove_pre_validated_round_trip(&bytes).expect("the fixture round-trips");
    let growth = peak_growth_since(floor);

    let control_fraction = control_growth as f64 / frame_bytes as f64;
    let fraction = growth as f64 / frame_bytes as f64;
    println!(
        "one snapshot: {frame_bytes} bytes\n\
         decoding it grew the peak by {control_growth} bytes, {control_fraction:.2} of the snapshot\n\
         proving it round-trips grew the peak by {growth} bytes, {fraction:.2} of the snapshot"
    );

    assert!(
        control_fraction > PROOF_PEAK_FRACTION,
        "the control must show the cost this guard is about; a decode that keeps the snapshot \
         grew the peak by only {control_fraction:.2} of it, so this fixture cannot demonstrate \
         the difference and the ceiling below would pass for the wrong reason"
    );
    assert!(
        fraction <= PROOF_PEAK_FRACTION,
        "proving a {frame_bytes}-byte snapshot round-trips grew the peak by {growth} bytes, \
         {fraction:.2} of the snapshot, at or over the {PROOF_PEAK_FRACTION} ceiling"
    );
}
