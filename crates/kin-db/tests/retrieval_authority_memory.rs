// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! One process-wide allocator test for the served retrieval digest. The
//! snapshot export remains a positive control over the same graph.

#![cfg(feature = "vector")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use kin_db::storage::merkle::compute_retrieval_authority_hash;
use kin_db::{ChangeStore, InMemoryGraph, WorkStore};
use kin_model::{AuthorId, ChangeOrigin, Hash256, SemanticChange, SemanticChangeId, Timestamp};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

fn charge(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: allocations and deallocations are forwarded with their original
// layout and pointer. The counters do not access allocated memory.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            charge(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            charge(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, size) };
        if !moved.is_null() {
            if size >= layout.size() {
                charge(size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - size, Ordering::Relaxed);
            }
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn measure<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    let floor = LIVE.load(Ordering::Relaxed);
    PEAK.store(floor, Ordering::Relaxed);
    let result = operation();
    (result, PEAK.load(Ordering::Relaxed).saturating_sub(floor))
}

#[test]
fn served_digest_does_not_copy_history() {
    const CHANGES: usize = 128;
    const PAYLOAD: usize = 32_768;
    let graph = InMemoryGraph::new();
    let empty_digest = graph.retrieval_authority_hash();
    // Snapshot exports already share immutable history. Unrelated annotation
    // bodies make the remaining full-store export cost observable.
    graph
        .create_annotation(&kin_model::Annotation {
            annotation_id: kin_model::AnnotationId::new(),
            kind: kin_model::AnnotationKind::Comment,
            body: "a".repeat(CHANGES * PAYLOAD),
            scopes: Vec::new(),
            anchored_fingerprint: None,
            authored_by: kin_model::IdentityRef::human("fixture"),
            created_at: Timestamp(chrono::Utc::now()),
            staleness: kin_model::StalenessState::default(),
        })
        .unwrap();
    let mut parent = None;
    for index in 0..CHANGES {
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            parents: parent.into_iter().collect(),
            timestamp: Timestamp(
                chrono::DateTime::parse_from_rfc3339("2026-09-08T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            author: AuthorId::new("retrieval-memory"),
            message: format!("change {index}: ") + &"x".repeat(PAYLOAD),
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
        change.id = kin_model::compute_semantic_change_id(&change).unwrap();
        graph.create_change(&change).unwrap();
        parent = Some(change.id);
    }

    let (direct, direct_peak) = measure(|| graph.retrieval_authority_hash());
    let ((control, count), control_peak) = measure(|| {
        let snapshot = graph.to_snapshot();
        (
            compute_retrieval_authority_hash(&snapshot),
            snapshot.changes.len(),
        )
    });
    assert_eq!(count, CHANGES);
    assert_eq!(direct, control);
    assert_eq!(
        direct, empty_digest,
        "history is outside retrieval authority"
    );
    assert!(
        control_peak >= CHANGES * PAYLOAD,
        "control must copy unrelated annotation payload"
    );
    assert!(
        direct_peak < CHANGES * PAYLOAD / 8,
        "served digest copied unrelated stores: {direct_peak}"
    );
    eprintln!("direct_peak_bytes={direct_peak} snapshot_control_peak_bytes={control_peak}");
}
