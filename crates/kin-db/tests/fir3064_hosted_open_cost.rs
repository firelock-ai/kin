// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What a hosted authority open pays, and what it is paying for twice.
//!
//! A hosted daemon does not open through `RepositoryAuthorityManager`. It calls
//! `load_recovered_snapshot`, which decodes the whole body, and then folds the
//! graph it serves out of the change map with `ChangeStore::resolve_graph_at`,
//! because a hosted envelope's top-level query domains are deliberately empty.
//! On a converted repository that map is most of the body.
//!
//! kin-db already persists that fold. `MaterializedGraphSection` is exactly
//! what `resolve_graph_at` returns, written by an explicit materialization and
//! validated against the change it resolves at, and
//! `AuthorityEnvelopeSnapshot::from_bytes` reads it while walking past the
//! change map, proving the frame and its checksum as a full decode does. The
//! two together answer the hosted open without decoding the history at all.
//!
//! This file prices the substitution rather than performing it: the change
//! belongs in the hosted daemon, not here (FIR-3064). It is a measurement and
//! not a guard, so it is `#[ignore]`d and no CI job runs it. Run it with
//!
//! ```text
//! cargo test --release --test fir3064_hosted_open_cost -- --ignored --nocapture
//! ```
//!
//! and size it with `FIR3064_CHANGES`.
//!
//! Both arms are timed three times, interleaved, after a discarded warm-up.
//! Timing them once in source order puts first touch of the buffer and
//! allocator warm-up entirely on whichever ran first, which is the arm under
//! measurement. Both arms also assert they resolved the same entity count, so
//! this is one comparison rather than two different answers.
//!
//! What the ratio depends on, so nobody reads one run as the answer: the fold
//! scales with history length times resolved graph size, and reading the
//! section scales with the resolved graph alone. This fixture adds one entity
//! per change, so its graph grows with its history and the ratio it shows is
//! near the low end. Measured here at 800 and 2400 changes it is about 3.9x in
//! both, stable across repeated runs; a fixture with several entities per
//! change measured nearer 8x. A converted repository with long history and a
//! modest graph sits above this, not below it.

use std::collections::HashMap;
use std::sync::Arc;

use kin_db::{
    AuthorityEnvelopeSnapshot, GraphSnapshot, KinDbError, LocalFileBackend,
    MaterializedGraphSectionOutcome, RepositoryAuthorityManager, StorageBackend,
    VersionedAuthorityState,
};
use kin_model::{
    compute_resolved_tree_hash, compute_semantic_change_id, AdmissionCase, AdmissionPolicyDelta,
    AuthorId, ChangeOrigin, ChangeStore, DefaultRefExpectation, DefaultRefMutation,
    EffectiveAdmissionPolicyStamp, Entity, EntityDelta, EntityId, EntityKind, EntityMetadata,
    EntityRole, FingerprintAlgorithm, FrozenLocalOverlay, FrozenLocalOverlayDelta, Hash256,
    LanguageId, OperationId, RefExpectation, RefMutation, RefName, RefTarget, RefUpdatePolicy,
    RepositoryId, RepositoryTransaction, ResolvedTree, SemanticChange, SemanticChangeId,
    SemanticFingerprint, SharedAdmissionPolicy, Timestamp, Visibility, WorkspaceExpectation,
    WorkspaceHead, WorkspaceId, WorkspaceMutation, WorkspaceSemanticDelta,
    REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
use uuid::Uuid;

/// Documentation bytes per entity, so the change map has mass worth not
/// decoding. The same figure `authority_open_memory.rs` uses.
const PAYLOAD_BYTES: usize = 32_768;

// --- the history a converted repository is mostly made of ------------------

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
        // No file origin, and not by accident. An entity that claims a
        // repository path must appear in the staged tree of the same
        // transaction, so giving these one would mean building a tree and the
        // source bodies under it to measure a decode that involves neither.
        // `build_synthetic_history_store` makes the same choice for the same
        // reason.
        file_origin: None,
        span: None,
        signature: format!("fn {name}()"),
        visibility: Visibility::Public,
        role: EntityRole::Source,
        doc_summary: Some(format!("{name} ").repeat(PAYLOAD_BYTES / 8)),
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

fn history_chain(changes: usize, shared: &SharedAdmissionPolicy) -> Vec<SemanticChange> {
    let mut chain: Vec<SemanticChange> = Vec::with_capacity(changes);
    let mut parent: Option<SemanticChangeId> = None;
    for index in 0..changes {
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

/// Publish one whole-history bootstrap with a default ref and a workspace whose
/// base is the chain head, which is what an explicit materialization needs.
fn publish(
    directory: &std::path::Path,
    repository: &RepositoryId,
    change_count: usize,
) -> (RepositoryAuthorityManager<LocalFileBackend>, WorkspaceId) {
    let backend = Arc::new(LocalFileBackend::new(directory));
    let manager = RepositoryAuthorityManager::open(repository.clone(), backend)
        .expect("open fresh authority");

    let shared = SharedAdmissionPolicy::empty(0);
    let changes = history_chain(change_count, &shared);
    let head = changes.last().expect("a non-empty history").id;

    let base_target = RefTarget::change(head);
    let tree_hash = compute_resolved_tree_hash(&ResolvedTree::default()).expect("tree hash");
    let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xf1_3064));
    let frozen_overlay =
        FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::Sensitive, Vec::new())
            .expect("frozen overlay");
    let effective_policy = EffectiveAdmissionPolicyStamp {
        shared: shared.stamp(),
        local: frozen_overlay.stamp(),
    };
    let main = RefName::branch(b"main").expect("branch name");

    let lease = manager.read_authority();
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: OperationId::from_uuid(Uuid::from_u128(0xf1_3064)),
        repository_id: repository.clone(),
        expected_generation: lease.generation(),
        expected_roots: lease.roots().clone(),
        actor: AuthorId::new("fir3064-measurement"),
        reason: "synthetic whole-history bootstrap".to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes,
        aliases: Vec::new(),
        ref_mutations: vec![RefMutation {
            name: main.clone(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(base_target.clone()),
            policy: RefUpdatePolicy::FastForwardOnly,
        }],
        default_ref_mutation: Some(DefaultRefMutation {
            expected: DefaultRefExpectation::MustBeUnset,
            new_default: Some(main.clone()),
        }),
        workspace_mutation: Some(WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustNotExist,
            new_generation: 0,
            new_head: WorkspaceHead::Symbolic { target: main },
            new_base_target: Some(base_target),
            new_base_tree_hash: Some(tree_hash),
            tree_deltas: Vec::new(),
            new_tree_hash: tree_hash,
            // Empty because the workspace sits AT its base target, so it has
            // no base-relative overlay to carry. Populating it with every
            // entity, which is what a workspace that had moved would carry, was
            // tried and changed the store size by about 1.5 KB, so it is not
            // where this fixture's bytes are.
            semantic_delta: WorkspaceSemanticDelta::new_with_external_references(
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
            .expect("workspace semantic delta"),
            new_shared_admission_policy: shared,
            new_admission_policy: effective_policy,
        }),
        local_overlay_delta: Some(FrozenLocalOverlayDelta::initialize(frozen_overlay)),
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: None,
    };
    drop(lease);
    manager
        .commit_repository_transaction(transaction)
        .expect("whole-history bootstrap commits");
    (manager, workspace_id)
}

// --- the fold a hosted open performs at every open -------------------------

/// The same borrowed view the hosted daemon builds over `snapshot.changes`.
///
/// `resolve_graph_at` needs only `get_change`, and it needs it by id, which is
/// why a hosted open cannot leave the change map on disk the way a local one
/// now can: it has random access to satisfy, not a stream.
struct HistoryView<'a> {
    changes: &'a HashMap<SemanticChangeId, SemanticChange>,
}

impl HistoryView<'_> {
    fn unsupported(operation: &str) -> KinDbError {
        KinDbError::StorageError(format!("{operation} is unavailable through this view"))
    }
}

impl ChangeStore for HistoryView<'_> {
    type Error = KinDbError;

    fn get_change(&self, id: &SemanticChangeId) -> Result<Option<SemanticChange>, Self::Error> {
        Ok(self.changes.get(id).cloned())
    }

    fn get_entity_history(&self, _id: &EntityId) -> Result<Vec<SemanticChange>, Self::Error> {
        Err(Self::unsupported("entity history"))
    }

    fn find_merge_bases(
        &self,
        _a: &SemanticChangeId,
        _b: &SemanticChangeId,
    ) -> Result<Vec<SemanticChangeId>, Self::Error> {
        Err(Self::unsupported("merge-base search"))
    }

    fn create_change(&self, _change: &SemanticChange) -> Result<(), Self::Error> {
        Err(Self::unsupported("change creation"))
    }

    fn get_changes_since(
        &self,
        _base: &SemanticChangeId,
        _head: &SemanticChangeId,
    ) -> Result<Vec<SemanticChange>, Self::Error> {
        Err(Self::unsupported("change-range listing"))
    }
}

// --- the measurement -------------------------------------------------------

#[test]
#[ignore = "FIR-3064 measurement; run with --ignored --nocapture"]
fn a_hosted_open_pays_for_a_fold_the_store_already_carries() {
    let change_count: usize = std::env::var("FIR3064_CHANGES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(800);

    let directory = tempfile::tempdir().expect("scratch store");
    let repository = RepositoryId::new("fir3064-hosted-open").expect("repository id");
    let (manager, workspace_id) = publish(directory.path(), &repository, change_count);

    let outcome = manager
        .materialize_workspace_base_graph_section(&repository, &workspace_id)
        .expect("materialization runs")
        .expect("the workspace has a committed base");
    let MaterializedGraphSectionOutcome::Persisted { resolved_at, .. } = outcome else {
        panic!("the first explicit materialization must persist, got {outcome:?}")
    };
    drop(manager);

    // The exact durable bytes a hosted open reads, taken through the backend's
    // own authority read rather than by re-serializing anything.
    let backend = LocalFileBackend::new(directory.path());
    let authority = backend
        .load_snapshot_authority(repository.as_str())
        .expect("authority reads")
        .expect("the bootstrap wrote authority");
    let bytes: Vec<u8> = authority.snapshot_bytes.as_ref().to_vec();
    let store_bytes = bytes.len();

    let warm = GraphSnapshot::from_bytes(&bytes).expect("warm-up decode");
    drop(warm);

    let mut folding: Vec<u128> = Vec::new();
    let mut section: Vec<u128> = Vec::new();
    let mut folded_entities = 0usize;
    let mut section_entities = 0usize;
    let mut changes_decoded = 0usize;

    let run_folding = || {
        let started = std::time::Instant::now();
        let snapshot = GraphSnapshot::from_bytes(&bytes).expect("whole-body decode");
        let resolved = HistoryView {
            changes: &snapshot.changes,
        }
        .resolve_graph_at(&resolved_at)
        .expect("the served graph folds out of history");
        (
            started.elapsed().as_millis(),
            resolved.entities.len(),
            snapshot.changes.len(),
        )
    };
    let run_section = || {
        let started = std::time::Instant::now();
        let envelope = AuthorityEnvelopeSnapshot::from_bytes(&bytes).expect("envelope decode");
        let carried = envelope
            .materialized_graph_for(&resolved_at)
            .expect("the persisted section answers for this head");
        (started.elapsed().as_millis(), carried.state.entities.len())
    };

    for round in 0..3 {
        // Alternate, so a residual ordering effect shows as spread across
        // rounds rather than as a difference between the arms.
        if round % 2 == 0 {
            let (ms, entities, decoded) = run_folding();
            folding.push(ms);
            folded_entities = entities;
            changes_decoded = decoded;
            let (ms, entities) = run_section();
            section.push(ms);
            section_entities = entities;
        } else {
            let (ms, entities) = run_section();
            section.push(ms);
            section_entities = entities;
            let (ms, entities, decoded) = run_folding();
            folding.push(ms);
            folded_entities = entities;
            changes_decoded = decoded;
        }
    }

    assert_eq!(
        folded_entities, section_entities,
        "the section must carry the graph the fold produces, or this compares two different \
         answers rather than two ways of reaching one"
    );
    assert_eq!(
        changes_decoded, change_count,
        "the folding arm must decode the whole history, or it is not the arm being priced"
    );

    println!(
        "FIR-3064: what a hosted open pays for the fold it repeats\n\
         changes={change_count} entities={folded_entities} store={store_bytes} bytes\n\
         three interleaved rounds after a discarded warm-up, ms each\n\
         decode whole body, then resolve_graph_at(head)  {folding:?}\n\
         decode envelope, then read the persisted section {section:?}"
    );
}
