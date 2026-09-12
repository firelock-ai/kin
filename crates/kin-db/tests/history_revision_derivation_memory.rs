// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What deriving a history's entity revisions holds alive while it runs.
//!
//! Building an `InMemoryGraph` from a snapshot that carries changes and no
//! entity revisions derives every revision the change DAG publishes. A
//! conversion reaches that path more than once: the desired graph a workspace
//! mutation builds over its base, and the shared replay decode
//! `prepare_successor` forces, both start from a snapshot with a full change
//! map and empty revisions.
//!
//! The derivation needs the changes in parent-first order. It does not need to
//! OWN them, and taking them by value cost two whole copies of the history at
//! the one moment a conversion's working set is already largest: one to hand
//! them to the ordering, and one more inside it to fill the ordered vector.
//!
//! The guard below prices that in units of one copy of the history itself,
//! which is the invariant rather than a byte count: the figure scales with
//! commits multiplied by per-commit payload, so a byte ceiling written for
//! this fixture would say nothing about a repository. Live heap, not resident
//! set, for the reason the neighbouring workspace guard gives: RSS keeps
//! counting memory the allocator has freed and not returned.
//!
//! `workspace_prepare_memory.rs` cannot see this class. It charges the
//! DIFFERENCE between a bootstrap with a workspace mutation and one without,
//! and the replay decode derives revisions in both arms, so the cost cancels
//! and that guard reads 4.56 copies either way. This file measures the
//! derivation head-on instead.
//!
//! This file is its own test binary and holds one test on purpose. The
//! counters below are process-global, so a second test running beside this one
//! would be measured into it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use kin_db::{GraphSnapshot, InMemoryGraph};
use kin_model::{
    compute_semantic_change_id, AdmissionPolicyDelta, AuthorId, ChangeOrigin, Entity, EntityDelta,
    EntityId, EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm, Hash256,
    LanguageId, SemanticChange, SemanticChangeId, SemanticFingerprint, SharedAdmissionPolicy,
    Timestamp, Visibility,
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

// --- the synthetic history ------------------------------------------------

/// Bytes of payload per change, so the change map is the dominant term the way
/// a converted repository's is rather than a rounding error on the fixture.
///
/// The payload lives in the change's MESSAGE and not in its entity, and that
/// placement is what makes this guard able to fail. A real commit carries tree
/// deltas, relation deltas and a message that the entity revisions it publishes
/// never reproduce, so one copy of a repository's history is far larger than
/// the revisions derived from it. A fixture that puts its bytes in the entity
/// instead makes the two the same size, the ordering's copies sit under the
/// revisions' own peak, and the guard reads 2.11 copies before the fix and 2.04
/// after: a difference of 0.07 that no honest ceiling could separate. Measured,
/// not reasoned about.
const CHANGE_PAYLOAD_BYTES: usize = 8_192;
const COMMITS: usize = 300;

fn fixed_timestamp() -> Timestamp {
    Timestamp(
        chrono::DateTime::parse_from_rfc3339("2026-08-23T00:00:00Z")
            .expect("fixed timestamp parses")
            .with_timezone(&chrono::Utc),
    )
}

/// One distinct entity per commit, deliberately small.
///
/// The revisions this fixture derives are the entities, so the entity is what
/// the derivation legitimately keeps. Keeping it small is what leaves the
/// change map as the dominant term and makes a copy of it visible.
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
        doc_summary: Some(format!("{name} publishes one revision")),
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

/// `commits` chained Native changes, one added entity each.
fn history_chain(commits: usize, shared: &SharedAdmissionPolicy) -> Vec<SemanticChange> {
    let mut chain: Vec<SemanticChange> = Vec::with_capacity(commits);
    let mut parent: Option<SemanticChangeId> = None;
    for index in 0..commits {
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: parent.into_iter().collect(),
            timestamp: fixed_timestamp(),
            author: AuthorId::new("fir2651-measurement"),
            message: format!("synthetic converted commit {index}: ")
                + &"payload ".repeat(CHANGE_PAYLOAD_BYTES / 8),
            entity_deltas: vec![EntityDelta::Added {
                new: measurement_entity(index),
            }],
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: (index == 0)
                .then(|| AdmissionPolicyDelta::initialize(shared.clone())),
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        change.id = compute_semantic_change_id(&change).expect("change id computes");
        parent = Some(change.id);
        chain.push(change);
    }
    chain
}

// --- the guard ------------------------------------------------------------

/// Peak growth the revision derivation may add, in copies of the history it
/// reads.
///
/// Set from measurement on this fixture, not from taste. Debug, this fixture,
/// one copy of the history at 2,945,718 bytes: the shape that handed the
/// ordering an owned history measured 2.11 copies, and the shape that lends it
/// measures 0.41. The difference is 4,999,308 bytes, which is two whole copies
/// of a 2,945,718-byte history, exactly the two the code held: one to build the
/// iterator of clones and one more inside the ordering to fill its vector.
///
/// The ceiling sits at 1.0, above what the derivation legitimately keeps and
/// far below one owned history, and there is nothing legitimate in between:
/// either the ordering owns a copy of the history or it borrows it.
///
/// A ratio of two live-heap readings taken in one process is
/// profile-independent, which is what makes this safe on a CI runner.
const DERIVATION_PEAK_HISTORY_COPIES: f64 = 1.0;

/// Deriving every entity revision a history publishes must not copy the
/// history to do it.
///
/// The snapshot carries the whole change map and no revisions, which is what a
/// freshly resolved workspace base and a freshly cloned authority snapshot both
/// carry on a conversion. The changes move into the graph, so anything the
/// derivation adds to the peak beyond the revisions it produces is a copy of
/// history built to walk history.
#[test]
fn deriving_entity_revisions_does_not_copy_the_history() {
    let shared = SharedAdmissionPolicy::empty(0);
    let history = history_chain(COMMITS, &shared);
    let (copy, history_bytes) = retained_by(|| history.clone());
    drop(copy);
    assert!(
        history_bytes > 1_000_000,
        "the fixture's history must be large enough to price a copy of it, got {history_bytes} bytes"
    );

    let mut snapshot = GraphSnapshot::empty();
    snapshot.changes = history
        .iter()
        .map(|change| (change.id, change.clone()))
        .collect();
    drop(history);

    // Moved in, so the graph's own change store costs nothing new and the
    // reading below is the derivation's own working set.
    let floor = arm_peak();
    let graph =
        InMemoryGraph::from_snapshot_without_text_index(snapshot).expect("the history decodes");
    let growth = peak_growth_since(floor);
    let copies = growth as f64 / history_bytes as f64;

    println!(
        "one history copy: {history_bytes} bytes\n\
         deriving {COMMITS} commits' entity revisions grew the peak by {growth} bytes, \
         {copies:.2} copies of the history"
    );

    // Read after the measurement so the graph cannot be optimized away before
    // the derivation runs, and so an empty decode cannot pass as a cheap one.
    let derived = graph.to_snapshot().entity_revisions.len();
    assert_eq!(
        derived, COMMITS,
        "the decode must publish one revision timeline per added entity, or this measured nothing"
    );

    assert!(
        copies <= DERIVATION_PEAK_HISTORY_COPIES,
        "deriving entity revisions grew the peak by {growth} bytes, {copies:.2} copies of the \
         {history_bytes}-byte history, over the {DERIVATION_PEAK_HISTORY_COPIES} copy ceiling. \
         The derivation reads the changes in parent-first order and owns none of them, so copies \
         beyond the revisions it produces are a history built to walk a history. On a conversion \
         this path runs more than once and each copy is over a gigabyte."
    );
}
