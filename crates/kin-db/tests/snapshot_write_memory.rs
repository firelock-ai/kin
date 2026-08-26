// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What installing a snapshot holds while it does it.
//!
//! The sibling guard `snapshot_frame_memory.rs` prices ASSEMBLING the frame.
//! This one prices WRITING it, which is the next thing that happens and, until
//! this guard existed, cost more than the assembly did.
//!
//! The write path is crash-safe by staging: the bytes go to a unique temp
//! entry, a recovery marker records their length and sha256, the temp entry is
//! renamed to the deterministic candidate path, the candidate is atomically
//! claimed under an unpredictable name, and only then is it renamed into place.
//! Three points in that sequence asked "does this file carry the bytes I
//! expect", and all three answered by reading the whole file into a `Vec` and
//! comparing it:
//!
//! 1. the candidate, checked against the marker's length and sha256;
//! 2. the claimed entry, compared byte for byte against the copy from step 1,
//!    which is live at the same time, so those two are two whole copies at once;
//! 3. the promoted destination, checked against the marker again.
//!
//! On a converted repository each of those is the repository. psf/requests at
//! full history reaches `kindb.commit.persist_successor` growing 1,268.0 MiB
//! with 0.0 retained, measured on kin-db 0.7.65, and that phase is the last
//! thing a conversion does, so every retained byte underneath it is already
//! committed when it happens. That is what makes a transient here cost the
//! whole run its high-water mark (FIR-2683).
//!
//! The question all three ask is content identity, and the marker already
//! carries the only two facts an answer needs: a length and a sha256 over the
//! exact bytes. A streaming pass answers it in a fixed buffer. The assertions
//! are unchanged; what changed is that answering them no longer requires
//! holding what is being answered about.
//!
//! Live heap rather than resident set, for the reason the sibling guards give:
//! resident set keeps counting memory the allocator has freed and not returned,
//! so it moves with the platform, while live heap moves when and only when the
//! code holds differently.
//!
//! The ceiling is expressed against the frame the backend is HANDED, and the
//! peak is armed after that frame exists. So the caller's own copy is outside
//! the measurement on purpose: it is the one copy the write genuinely needs,
//! and pricing it here would put a copy the fix does not remove into the
//! number the fix is judged by.
//!
//! This file is its own test binary and holds one test on purpose. The counters
//! below are process-global, so a second test running beside this one would be
//! measured into it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use kin_db::{
    GraphSnapshot, LocalFileBackend, SnapshotCursor, SnapshotSaveOutcome, StorageBackend,
};
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

/// Any history validator version. The write path branches on `Some` versus
/// `None`, never on the number: `Some` means the caller already proved storage
/// admission, which is the conversion's path and the one this guard prices.
const ANY_HISTORY_VALIDATOR: u32 = 1;

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

/// Copies of the frame that installing it may hold, on top of the frame the
/// backend was handed.
///
/// Set from measurement on this fixture, not from taste. The staging sequence
/// that read each staged and promoted entry back into a `Vec` measures about
/// 2.0 copies, because the candidate copy and the claim's comparison copy are
/// live at the same moment; restoring any ONE of the three reads on its own
/// measures about 1.0. The streaming version measures about 0.0, because
/// nothing it allocates scales with the frame.
///
/// 0.5 sits between 0.0 and the smallest failure, which is one whole copy, so
/// it fails every single-read regression rather than only the full one. That
/// margin is the point: a bar tightened until the intact reading passes can
/// look calibrated while being blind to half of what it was tightened for, and
/// the way to know it is not is to run every mutation, which the falsification
/// driver beside this file does.
const WRITE_PEAK_COPIES: f64 = 0.5;

/// Installing a snapshot must not hold another copy of it.
///
/// This is the last term in a conversion's ladder, which is what makes it the
/// ceiling: everything underneath it is already committed by the time it runs,
/// so a copy here costs the whole run its high-water mark.
#[test]
fn installing_a_snapshot_does_not_hold_another_copy_of_it() {
    let snapshot = measurement_snapshot();
    let directory = tempfile::tempdir().expect("scratch store");
    let backend = LocalFileBackend::new(directory.path());

    // Serialize before arming. The frame is what the backend is HANDED, so the
    // caller's copy of it is deliberately outside the window: it is the one
    // copy the write genuinely needs and no streaming change removes it.
    let frame = snapshot
        .to_bytes()
        .expect("the fixture snapshot serializes");
    let frame_bytes = frame.len();
    assert!(
        frame_bytes > 1_000_000,
        "the fixture's frame must be large enough to price a copy of it, got {frame_bytes} bytes"
    );

    // Warm the backend on a different repository id first, so the measured call
    // pays for the write and not for whatever a first touch of this store sets
    // up. A distinct id keeps the measured call a first write at
    // `SnapshotCursor::INITIAL`, which is the bootstrap shape a conversion has.
    match backend.save_snapshot_validated(
        "warmup",
        &frame,
        SnapshotCursor::INITIAL,
        Some(ANY_HISTORY_VALIDATOR),
    ) {
        SnapshotSaveOutcome::Committed { .. } => {}
        other => panic!("the warm-up write must commit, got {other:?}"),
    }

    let floor = arm_peak();
    let outcome = backend.save_snapshot_validated(
        "measured",
        &frame,
        SnapshotCursor::INITIAL,
        Some(ANY_HISTORY_VALIDATOR),
    );
    let growth = peak_growth_since(floor);

    match outcome {
        SnapshotSaveOutcome::Committed { .. } => {}
        other => panic!("the measured write must commit, got {other:?}"),
    }

    let copies = growth as f64 / frame_bytes as f64;
    println!(
        "one frame: {frame_bytes} bytes\n\
         installing it grew the peak by {growth} bytes, {copies:.2} copies of the frame"
    );

    assert!(
        copies <= WRITE_PEAK_COPIES,
        "installing a {frame_bytes}-byte snapshot grew the peak by {growth} bytes, {copies:.2} \
         copies of the frame, at or over the {WRITE_PEAK_COPIES} copy ceiling"
    );
}
