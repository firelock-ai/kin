// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What persisting a snapshot holds while it does it.
//!
//! Two sibling guards already price the pieces. `snapshot_frame_memory.rs`
//! proves the frame is assembled in ONE buffer rather than two, and
//! `snapshot_write_memory.rs` proves installing that buffer holds no further
//! copy of it. Both take the buffer as given. This guard prices the buffer
//! itself.
//!
//! It is the last term left in the persist and the largest one, because its
//! size IS the repository. A full VS Code tree admitted as one commit writes a
//! 2.24 GiB store at the commit and a 3.59 GiB store once the post-init graph
//! section is materialized, and each of those numbers is one contiguous
//! allocation standing on the heap at the moment a conversion is already at its
//! high-water mark: `kindb.commit.persist_successor` and
//! `kindb.commit.persist_equivalent` are the two spans a `kin init` peaks in
//! (FIR-3064).
//!
//! The header carries the body's length and sits ahead of the body, so a single
//! pass cannot write the frame. That is why the buffer existed. It is not why
//! it has to: the length comes from a counting pass that allocates nothing, and
//! the second pass can write to the destination file as easily as to a `Vec`.
//! So the frame is streamed into the backend's staging file, hashing and
//! counting as it goes, and the durability sequence is handed the file rather
//! than the bytes.
//!
//! What the ceiling is charged against is the STORE the producer wrote, read
//! back from the shape the streaming writer reported. Buffering it measures
//! about 1.0 copies; streaming it measures about 0.0, because nothing the
//! streaming path allocates scales with the store.
//!
//! Live heap rather than resident set, for the reason the sibling guards give:
//! resident set keeps counting memory the allocator has freed and not returned,
//! so it moves with the platform, while live heap moves when and only when the
//! code holds differently.
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

/// Enough entities that the store dwarfs the streaming path's own fixed write
/// buffer as well as the harness's allocation.
///
/// The buffer is one megabyte and does not grow with the store, so on a small
/// fixture it is most of what a streaming persist allocates and the ratio the
/// ceiling is expressed in would be reporting the buffer rather than the frame.
/// At this size the store is about forty megabytes, so the buffer is a few
/// percent of one copy and the ceiling is measuring what it names.
const ENTITIES: usize = 16_000;

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

/// Copies of the store that persisting it may hold.
///
/// Set from measurement on this fixture, not from taste. Serializing the frame
/// into a `Vec` before handing it to the backend measures about 1.0 copies,
/// because that buffer is exactly the size of the store and lives for the whole
/// write. Streaming it measures about 0.0, because the only allocation the
/// streaming path scales is a fixed one-megabyte write buffer.
///
/// 0.5 sits halfway between the two, so it fails the whole regression and has
/// no room to pass a partial one: a frame is either assembled or it is not.
const PERSIST_PEAK_COPIES: f64 = 0.5;

/// Persisting a snapshot must not assemble a copy of the store to do it.
///
/// This is the phase a conversion peaks in, so a store-sized transient here
/// costs the whole run its high-water mark rather than a phase its own.
#[test]
fn persisting_a_snapshot_does_not_assemble_a_copy_of_the_store() {
    let snapshot = measurement_snapshot();
    let directory = tempfile::tempdir().expect("scratch store");
    let backend = LocalFileBackend::new(directory.path());

    // Warm the backend on a different repository id first, so the measured call
    // pays for the persist and not for whatever a first touch of this store
    // sets up. A distinct id keeps the measured call a first write at
    // `SnapshotCursor::INITIAL`, which is the bootstrap shape a conversion has.
    let mut warm = |out: &mut dyn std::io::Write| {
        snapshot
            .stream_to(out)
            .map(|shape| (shape.byte_len, shape.sha256))
    };
    match backend.save_snapshot_streamed(
        "warmup",
        &mut warm,
        SnapshotCursor::INITIAL,
        Some(ANY_HISTORY_VALIDATOR),
    ) {
        SnapshotSaveOutcome::Committed { .. } => {}
        other => panic!("the warm-up persist must commit, got {other:?}"),
    }

    // The producer reports what it wrote, which is how a caller that never held
    // the bytes learns how big they were. `Cell` rather than a captured `&mut`,
    // so the closure borrows it immutably and the length is readable the moment
    // the call returns.
    let store_bytes = std::cell::Cell::new(0u64);
    let floor = arm_peak();
    let outcome = {
        let mut produce = |out: &mut dyn std::io::Write| {
            let shape = snapshot.stream_to(out)?;
            store_bytes.set(shape.byte_len);
            Ok((shape.byte_len, shape.sha256))
        };
        backend.save_snapshot_streamed(
            "measured",
            &mut produce,
            SnapshotCursor::INITIAL,
            Some(ANY_HISTORY_VALIDATOR),
        )
    };
    let growth = peak_growth_since(floor);

    match outcome {
        SnapshotSaveOutcome::Committed { .. } => {}
        other => panic!("the measured persist must commit, got {other:?}"),
    }

    let store_bytes = store_bytes.get() as usize;
    assert!(
        store_bytes > 1_000_000,
        "the fixture's store must be large enough to price a copy of it, got {store_bytes} bytes"
    );

    // The store is on disk and readable, or this measured a write that did not
    // happen. Read back through the backend's own load, which is the reader
    // every open uses.
    let installed = backend
        .load_snapshot("measured")
        .expect("the measured store reloads")
        .expect("the measured store is present");
    assert_eq!(
        installed.0.len(),
        store_bytes,
        "the installed store must be exactly what the streaming writer reported writing"
    );

    let copies = growth as f64 / store_bytes as f64;
    println!(
        "store: {store_bytes} bytes\n\
         persisting it grew the peak by {growth} bytes, {copies:.2} copies of the store"
    );

    assert!(
        copies <= PERSIST_PEAK_COPIES,
        "persisting a {store_bytes}-byte store grew the peak by {growth} bytes, {copies:.2} \
         copies of it, at or over the {PERSIST_PEAK_COPIES} copy ceiling"
    );
}
