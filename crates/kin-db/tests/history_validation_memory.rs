// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Full history validation selects identities without retaining duplicate change payloads.
//! One test owns the process-wide allocator counters.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use kin_db::{
    LocalFileBackend, RepositoryAuthorityManager, StorageBackend, VersionedAuthorityState,
};
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
const COMMITS: usize = 96;

/// Message bytes per change, so the change map is the dominant term the
/// way a converted repository's is.
const CHANGE_PAYLOAD_BYTES: usize = 131_072;

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
        doc_summary: None,
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
            author: AuthorId::new("history-validation-measurement"),
            message: format!("synthetic converted commit {index}: ")
                + &"history ".repeat(CHANGE_PAYLOAD_BYTES / 8),
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
        actor: AuthorId::new("history-validation-measurement"),
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
        collaboration_delta: None,
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

fn transient_copies<T>(name: &str, bytes: usize, run: impl FnOnce() -> T) -> (T, f64) {
    let floor = arm_peak();
    let value = run();
    let peak = peak_growth_since(floor);
    let retained = live_bytes().saturating_sub(floor);
    let transient = peak.saturating_sub(retained);
    let copies = transient as f64 / bytes as f64;
    println!("{name}: history={bytes} peak={peak} retained={retained} transient={transient} copies={copies:.3}");
    (value, copies)
}

#[test]
fn complete_history_validation_does_not_copy_change_payloads_to_select_targets() {
    let directory = tempfile::tempdir().expect("validated store");
    let repository = RepositoryId::new("history-validation-measurement").unwrap();
    publish_bootstrap(directory.path(), &repository);
    let backend = Arc::new(LocalFileBackend::new(directory.path()));
    let (manager, payload) = RepositoryAuthorityManager::open_with_payload_stats(
        repository.clone(),
        Arc::clone(&backend),
    )
    .unwrap();
    let bytes = payload.unwrap().snapshot_bytes() as usize;
    assert!(
        bytes > COMMITS * CHANGE_PAYLOAD_BYTES,
        "the payload must be persisted"
    );
    assert!(manager.opened_by_history_validation());
    let lease = manager.read_authority();
    let roots = lease.roots().clone();
    let changes = lease.snapshot().changes.decoded().unwrap();
    assert_eq!(changes.len(), COMMITS);

    // The control makes a real payload copy and must be visible to the allocator.
    let copy_floor = arm_peak();
    let copy = changes.values().cloned().collect::<Vec<_>>();
    let copied_bytes = live_bytes().saturating_sub(copy_floor);
    println!("copy control: history={bytes} copied={copied_bytes}");
    assert!(
        copied_bytes >= COMMITS * CHANGE_PAYLOAD_BYTES,
        "the instrument must see a real history copy"
    );
    let copy_payload: usize = copy.iter().map(|change| change.message.len()).sum();
    assert!(copy_payload >= COMMITS * CHANGE_PAYLOAD_BYTES);
    drop(copy);
    drop(lease);

    let (frozen, freeze_copies) = transient_copies("full freeze", bytes, || {
        manager
            .freeze_current_authority(&roots)
            .expect("full frozen validation")
    });
    drop(frozen);

    // Save through the unvalidated backend boundary so this open cannot reuse a proof.
    let unproven_directory = tempfile::tempdir().expect("unproven store");
    let unproven_backend = Arc::new(LocalFileBackend::new(unproven_directory.path()));
    {
        let authority = backend
            .load_snapshot_authority(repository.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(
            unproven_backend
                .save_snapshot(repository.as_str(), &authority.snapshot_bytes, 0)
                .unwrap(),
            1
        );
        assert!(unproven_backend
            .load_snapshot_authority(repository.as_str())
            .unwrap()
            .unwrap()
            .history_validation
            .is_none());
    }
    let (reopened, reopen_copies) = transient_copies("unproven reopen", bytes, || {
        RepositoryAuthorityManager::open(repository.clone(), unproven_backend)
            .expect("full reopen validation")
    });
    assert!(!reopened.opened_by_history_validation());
    assert_eq!(reopened.read_authority().snapshot().changes.len(), COMMITS);
    assert!(freeze_copies < 0.5 && reopen_copies < 0.5,
        "complete validation held change-payload copies only to select replay targets: freeze={freeze_copies:.3}, reopen={reopen_copies:.3}");
}
