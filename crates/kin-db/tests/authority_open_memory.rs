// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What opening a persisted authority holds while it decodes one.
//!
//! An authority open reads the persisted snapshot, hashes it, and decodes it
//! into owned structures. The decode is the whole point; the bytes it decodes
//! from are not, and they used to be read onto the heap first, so a whole
//! second copy of the store stood beside the graph for exactly as long as the
//! decode ran. That is the moment an open is at its highest, which makes the
//! transient the ceiling rather than a detail.
//!
//! Measured on the full VS Code tree, 18,508 files admitted as one commit into
//! a 3.59 GiB store: the open peaked at 9.81 GiB, of which 3.61 GiB was the
//! byte buffer and 6.20 GiB the graph it decoded. The bytes came back the
//! instant recovery returned. `kin init` performs this open on the store it has
//! just written, so on a conversion the term lands on top of everything the
//! admission ladder still holds (FIR-3064).
//!
//! The answer is that a backend holding the snapshot in a file hands back a
//! mapping rather than a copy. Nothing above it changes: the digest and the
//! decoder both read a slice, and the mapping is read-only and opened through
//! the same `nofollow` capability the copying read used.
//!
//! Live heap rather than resident set, for the reason the sibling guards give:
//! resident set keeps counting memory the allocator has freed and not returned,
//! so it moves with the platform, while live heap moves when and only when the
//! code holds differently. A mapping is not heap at all, which is exactly the
//! property being asserted.
//!
//! The ceiling is charged against what the open RETAINS, so the decoded graph
//! is subtracted rather than priced: this guard is about the copy beside the
//! decode, and putting the decode itself into the number would let a change
//! that shrank the graph hide a byte buffer that came back.
//!
//! This file is its own test binary and holds one test on purpose. The counters
//! below are process-global, so a second test running beside this one would be
//! measured into it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use kin_db::{LocalFileBackend, RepositoryAuthorityManager, VersionedAuthorityState};
use kin_model::{
    compute_semantic_change_id, AdmissionPolicyDelta, AuthorId, ChangeOrigin, Entity, EntityDelta,
    EntityId, EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm, Hash256,
    LanguageId, OperationId, RepositoryId, RepositoryTransaction, SemanticChange, SemanticChangeId,
    SemanticFingerprint, SharedAdmissionPolicy, Timestamp, Visibility,
    REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
use uuid::Uuid;

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

// --- the fixture ----------------------------------------------------------

/// Enough history that the persisted snapshot is worth measuring a copy of
/// rather than lost in the harness's own allocation.
const COMMITS: usize = 800;

/// Documentation bytes per change, so the change map is the dominant term the
/// way a converted repository's is.
const CHANGE_PAYLOAD_BYTES: usize = 32_768;

fn fixed_timestamp() -> Timestamp {
    Timestamp(
        chrono::DateTime::parse_from_rfc3339("2026-09-02T00:00:00Z")
            .expect("fixed timestamp parses")
            .with_timezone(&chrono::Utc),
    )
}

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
        doc_summary: Some(format!("{name} ").repeat(CHANGE_PAYLOAD_BYTES / 8)),
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

fn history_chain(commits: usize, shared: &SharedAdmissionPolicy) -> Vec<SemanticChange> {
    let mut chain: Vec<SemanticChange> = Vec::with_capacity(commits);
    let mut parent: Option<SemanticChangeId> = None;
    for index in 0..commits {
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: parent.into_iter().collect(),
            timestamp: fixed_timestamp(),
            author: AuthorId::new("fir3064-measurement"),
            message: format!("synthetic converted commit {index}"),
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

/// Publish one whole-history bootstrap into a fresh local store.
fn publish_bootstrap(directory: &std::path::Path, repository: &RepositoryId) {
    let backend = Arc::new(LocalFileBackend::new(directory));
    let manager = RepositoryAuthorityManager::open(repository.clone(), backend)
        .expect("open fresh authority");
    let shared = SharedAdmissionPolicy::empty(0);
    let changes = history_chain(COMMITS, &shared);
    let lease = manager.read_authority();
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: OperationId::from_uuid(Uuid::from_u128(1)),
        repository_id: repository.clone(),
        expected_generation: lease.generation(),
        expected_roots: lease.roots().clone(),
        actor: AuthorId::new("fir3064-measurement"),
        reason: "synthetic whole-history bootstrap".to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes,
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: None,
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
    };
    drop(lease);
    let receipt = manager
        .commit_repository_transaction(transaction)
        .expect("whole-history bootstrap commits");
    assert_eq!(
        receipt.generation, 1,
        "the bootstrap publishes generation 1"
    );
}

// --- the guard ------------------------------------------------------------

/// Copies of the persisted snapshot an open may hold on top of the graph it
/// decodes and keeps.
///
/// Set from measurement on this fixture, not from taste. Reading the snapshot
/// into a `Vec` before decoding it measures about 1.0 copies, because the
/// buffer lives for the whole decode and is dropped the moment recovery
/// returns. Mapping it measures about 0.0, because nothing it allocates scales
/// with the store.
///
/// 0.5 sits halfway between the two, so it fails the whole regression and has
/// no room to pass a partial one: there is no half-measure between a copy and a
/// mapping.
const OPEN_TRANSIENT_COPIES: f64 = 0.5;

/// Opening an authority must not hold a copy of the store beside the graph.
#[test]
fn opening_an_authority_does_not_hold_the_snapshot_beside_the_graph() {
    let directory = tempfile::tempdir().expect("scratch store");
    let repository = RepositoryId::new("fir3064-measurement").expect("repository id");
    publish_bootstrap(directory.path(), &repository);

    // A fresh backend, so the measured open recovers from the file rather than
    // from anything the publishing manager still held.
    let backend = Arc::new(LocalFileBackend::new(directory.path()));

    let floor = arm_peak();
    let (manager, payload) =
        RepositoryAuthorityManager::open_with_payload_stats(repository.clone(), backend)
            .expect("the published authority reopens");
    let growth = peak_growth_since(floor);
    let retained = live_bytes().saturating_sub(floor);

    let snapshot_bytes = payload
        .expect("a persisted authority reports its payload")
        .snapshot_bytes() as usize;
    assert!(
        snapshot_bytes > 8_000_000,
        "the fixture's store must be large enough to price a copy of it, got {snapshot_bytes} bytes"
    );
    assert_eq!(
        manager.read_authority().generation(),
        1,
        "the reopened authority must carry the published generation, or this measured an open \
         that did not happen"
    );

    let transient = growth.saturating_sub(retained);
    let copies = transient as f64 / snapshot_bytes as f64;
    println!(
        "store: {snapshot_bytes} bytes\n\
         opening it peaked {growth} bytes above the floor and retained {retained}, \
         so the transient is {transient} bytes, {copies:.2} copies of the store"
    );

    assert!(
        copies <= OPEN_TRANSIENT_COPIES,
        "opening a {snapshot_bytes}-byte authority held {transient} transient bytes beside the \
         graph it decoded, {copies:.2} copies of the store, at or over the \
         {OPEN_TRANSIENT_COPIES} copy ceiling"
    );
}
