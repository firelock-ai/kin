// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What framing a snapshot for disk holds while it does it.
//!
//! A full-history brownfield conversion's whole-run peak is reached inside
//! `kindb.commit.persist_successor`, and the attribution says so in one
//! invariant: across every build in this wave, `kin.init.commit_bootstrap_transaction`
//! grew the peak by exactly 3777.0 MiB while its two children,
//! `kindb.commit.prepare_successor` and `kindb.commit.persist_successor`, split
//! that figure differently every time. A sum that will not move while its parts
//! rearrange is a ceiling reached in the last part.
//!
//! The frame assembly is why. It serialized the snapshot body into its own
//! `Vec`, then copied that body into a second, exactly-sized frame buffer, so
//! both existed at once. The body of a converted repository IS the repository:
//! on psf/requests at full history it is about a gigabyte, and the copy of it
//! sat at the top of the ladder where every retained byte underneath was
//! already committed.
//!
//! The guard below prices that in copies of the frame it produces. Live heap
//! rather than resident set, because resident set keeps counting memory the
//! allocator has freed and not returned, so it moves with the platform while
//! live heap moves when and only when the code holds differently.
//!
//! There is no payload-placement subtlety here, which is worth saying because
//! the two other memory guards in this crate both have one. The term removed is
//! a whole copy of the ENCODING and the term kept is the encoding itself, so
//! they are the same size by construction and the ratio is two against one
//! whatever the fixture puts where. What the fixture does have to do is be
//! large enough that the frame dominates the harness's own allocation, which is
//! what `ENTITIES` is for.
//!
//! This file is its own test binary and holds one test on purpose. The counters
//! below are process-global, so a second test running beside this one would be
//! measured into it.

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

/// Copies of the frame that framing a snapshot may hold at its high point.
///
/// Set from measurement on this fixture, not from taste. Debug, this fixture,
/// one frame at 10,277,527 bytes: the assembly that serialized the body into
/// its own buffer and then copied it into a second one measures 2.03 copies,
/// and the assembly that counts first and writes once measures 1.00. A ceiling
/// of 1.5 fails the first and passes the second, with room on both sides, since
/// the number is a ratio of two live-heap readings taken in one process and is
/// therefore profile- and host-independent.
///
/// 1.00 rather than something under it is the floor and not slack: the frame
/// has to exist to be handed to the backend, so one copy is the whole job. The
/// 1.03 the counting pass buys is the body copy, and the fraction above 2 in
/// the old reading is the body buffer's own doubling as it grew without knowing
/// its final size.
const FRAME_PEAK_COPIES: f64 = 1.5;

/// Framing a snapshot for disk must not hold two copies of it.
///
/// This is the last term in a conversion's ladder, which is what makes it the
/// ceiling: everything underneath it is already committed by the time it runs,
/// so a copy here costs the whole run its high-water mark.
#[test]
fn framing_a_snapshot_does_not_hold_two_copies_of_it() {
    let snapshot = measurement_snapshot();
    // Serialize once before arming, so the measurement below is the assembly's
    // own growth and not the encoder's one-time setup.
    let warm = snapshot
        .to_bytes()
        .expect("the fixture snapshot serializes");
    let frame_bytes = warm.len();
    drop(warm);
    assert!(
        frame_bytes > 1_000_000,
        "the fixture's frame must be large enough to price a copy of it, got {frame_bytes} bytes"
    );

    let floor = arm_peak();
    let frame = snapshot
        .to_bytes()
        .expect("the fixture snapshot serializes");
    let growth = peak_growth_since(floor);
    assert_eq!(
        frame.len(),
        frame_bytes,
        "the measured call must produce the same frame the warm-up did"
    );
    drop(frame);

    let copies = growth as f64 / frame_bytes as f64;
    println!(
        "one frame: {frame_bytes} bytes\n\
         framing it grew the peak by {growth} bytes, {copies:.2} copies of the frame"
    );

    assert!(
        copies <= FRAME_PEAK_COPIES,
        "framing a {frame_bytes}-byte snapshot grew the peak by {growth} bytes, {copies:.2} \
         copies of the frame, at or over the {FRAME_PEAK_COPIES} copy ceiling"
    );
}
