// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What the shared replay proof still HOLDS when the workspace lap ends.
//!
//! A full-history brownfield conversion's peak is not set by what any phase
//! allocates and frees. It is set by what the ladder is still holding when the
//! last phase runs, and the largest single holder was `kindb.prepare.workspace`
//! at 1,706 MiB retained on psf/requests at 6,731 commits. All of it was one
//! structure: the shared replay decode cloned the whole authority snapshot in
//! order to null one field, rebuilt every index, adjacency map and Merkle root
//! from the clone, and kept the result alive until the preparation ended, to
//! answer tree questions that read the change map alone.
//!
//! The guard below prices that directly, in the same units the attribution
//! table uses. It commits one synthetic whole-history bootstrap carrying a
//! workspace mutation, samples the live heap at every `kindb.` span boundary,
//! and charges what `kindb.prepare.workspace` still holds at its exit against
//! one copy of the history it committed. Live heap rather than resident set,
//! because resident set keeps counting memory the allocator has freed and not
//! returned, so it moves with the platform while live heap moves when and only
//! when the code holds differently.
//!
//! ## Why the payload lives in the message
//!
//! This is the trap that made an earlier guard in this wave unable to fail, and
//! it is live here too. The term removed is a whole copy of the SNAPSHOT, which
//! on a conversion is dominated by the change map. The terms kept are the
//! workspace state the mutation publishes and the entity revisions derived from
//! the history, both of which scale with the ENTITIES a change carries and not
//! with the change body. A fixture that puts its payload in the entity makes
//! those two the same size, hides the removed term underneath the kept one, and
//! reports a ratio no honest ceiling could separate. Putting the payload in the
//! change's message is what a real repository looks like anyway: a commit
//! carries tree deltas, relation deltas and a message that the entity revisions
//! it publishes never reproduce.
//!
//! This file is its own test binary and holds one test on purpose. The
//! allocator counters and the span sampler below are process-global, so a
//! second test running beside this one would be measured into it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use kin_db::{LocalFileBackend, RepositoryAuthorityManager, VersionedAuthorityState};
use kin_model::{
    compute_resolved_tree_hash, compute_semantic_change_id, AdmissionCase, AdmissionPolicyDelta,
    ArtifactId, AuthorId, ChangeOrigin, DefaultRefExpectation, DefaultRefMutation,
    EffectiveAdmissionPolicyStamp, Entity, EntityDelta, EntityId, EntityKind, EntityMetadata,
    EntityRole, FilePathId, FingerprintAlgorithm, FrozenLocalOverlay, FrozenLocalOverlayDelta,
    Hash256, LanguageId, LocatedEntry, OperationId, RefExpectation, RefMutation, RefName,
    RefTarget, RefUpdatePolicy, RepoPath, RepositoryId, RepositoryTransaction, ResolvedTree,
    SemanticChange, SemanticChangeId, SemanticFingerprint, SharedAdmissionPolicy, Timestamp,
    TreeDelta, TreeEntry, Visibility, WorkspaceExpectation, WorkspaceHead, WorkspaceId,
    WorkspaceMutation, WorkspaceSemanticDelta, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};
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

/// Live bytes that `build` allocates and still holds when it returns.
fn retained_by<T>(build: impl FnOnce() -> T) -> (T, usize) {
    let before = live_bytes();
    let value = build();
    (value, live_bytes().saturating_sub(before))
}

// --- the span sampler -----------------------------------------------------

/// The span namespace kin-db reports its preparation laps under.
const PHASE_PREFIX: &str = "kindb.";

/// One reading of the live heap at a phase boundary.
#[derive(Debug, Clone, Copy)]
struct PhaseSample {
    phase: &'static str,
    entering: bool,
    live: usize,
}

static SAMPLES: Mutex<Vec<PhaseSample>> = Mutex::new(Vec::new());
static SPAN_NAMES: Mutex<Option<HashMap<u64, &'static str>>> = Mutex::new(None);
static NEXT_SPAN_ID: AtomicU64 = AtomicU64::new(1);

/// A `tracing` subscriber that records the live heap on entering and leaving
/// every `kindb.` span, and does nothing else.
///
/// Hand-rolled rather than a `tracing-subscriber` layer on purpose: this crate
/// carries no subscriber dependency, and a memory guard should not add one to
/// the dependency tree of a registry-published crate in order to read two
/// counters.
struct PhaseSampler;

fn phase_name(id: &tracing::span::Id) -> Option<&'static str> {
    SPAN_NAMES
        .lock()
        .expect("span names poisoned")
        .as_ref()
        .and_then(|names| names.get(&id.into_u64()).copied())
}

fn record(sample: PhaseSample) {
    SAMPLES.lock().expect("samples poisoned").push(sample);
}

impl tracing::Subscriber for PhaseSampler {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.is_span() && metadata.name().starts_with(PHASE_PREFIX)
    }

    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let id = NEXT_SPAN_ID.fetch_add(1, Ordering::Relaxed);
        SPAN_NAMES
            .lock()
            .expect("span names poisoned")
            .get_or_insert_with(HashMap::new)
            .insert(id, span.metadata().name());
        tracing::span::Id::from_u64(id)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, _event: &tracing::Event<'_>) {}

    fn enter(&self, id: &tracing::span::Id) {
        if let Some(phase) = phase_name(id) {
            record(PhaseSample {
                phase,
                entering: true,
                live: live_bytes(),
            });
        }
    }

    fn exit(&self, id: &tracing::span::Id) {
        if let Some(phase) = phase_name(id) {
            record(PhaseSample {
                phase,
                entering: false,
                live: live_bytes(),
            });
        }
    }
}

/// Live bytes a phase still holds when it exits, for the first time it ran.
///
/// `None` when the phase never opened, which is a different answer from zero
/// and is treated as one: a guard whose span name went stale must fail rather
/// than report that the holder it was written for holds nothing.
fn retained_by_phase(phase: &str) -> Option<usize> {
    let samples = SAMPLES.lock().expect("samples poisoned").clone();
    let entered = samples
        .iter()
        .position(|sample| sample.entering && sample.phase == phase)?;
    let exit = samples
        .iter()
        .skip(entered + 1)
        .find(|sample| !sample.entering && sample.phase == phase)?;
    Some(exit.live.saturating_sub(samples[entered].live))
}

/// Every distinct phase the run opened, for a failure message that can be acted on.
fn observed_phases() -> Vec<&'static str> {
    let mut phases: Vec<&'static str> = SAMPLES
        .lock()
        .expect("samples poisoned")
        .iter()
        .map(|sample| sample.phase)
        .collect();
    phases.sort_unstable();
    phases.dedup();
    phases
}

// --- the synthetic conversion ---------------------------------------------

/// Bytes of payload per change, carried in the change's own message.
///
/// See the module comment: this belongs in the change body and not in the
/// entity, or the term this guard prices hides underneath the terms it does not.
const CHANGE_PAYLOAD_BYTES: usize = 8_192;
const COMMITS: usize = 300;
const FILES: usize = 60;

fn digest(body: &[u8]) -> Hash256 {
    Hash256::from_bytes(Sha256::digest(body).into())
}

fn fixed_timestamp() -> Timestamp {
    Timestamp(
        chrono::DateTime::parse_from_rfc3339("2026-08-23T00:00:00Z")
            .expect("fixed timestamp parses")
            .with_timezone(&chrono::Utc),
    )
}

/// One small distinct entity per commit. Deliberately small: the payload is in
/// the change, and an entity heavy enough to rival it would put the derived
/// revisions and the published workspace overlay on the same scale as the
/// snapshot copy this guard exists to price.
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

/// The head tree a conversion publishes: `files` artifacts and their bodies.
fn head_tree(files: usize) -> (Vec<TreeDelta>, Vec<(Hash256, Vec<u8>)>) {
    let mut deltas = Vec::with_capacity(files);
    let mut blobs = Vec::with_capacity(files);
    for file in 0..files {
        let path = format!("src/module_{file}.rs");
        let body = format!("pub fn kin_{file}() {{}}\n").into_bytes();
        let hash = digest(&body);
        deltas.push(TreeDelta::Added {
            artifact_id: ArtifactId(Uuid::from_u128(1_000_000 + file as u128)),
            new: LocatedEntry::new(
                RepoPath::from_bytes(path.into_bytes()).expect("synthetic path is valid"),
                TreeEntry::blob(hash, false),
            ),
        });
        blobs.push((hash, body));
    }
    (deltas, blobs)
}

/// `commits` chained Native changes, one entity each, head carrying `tree`.
fn history_chain(
    commits: usize,
    shared: &SharedAdmissionPolicy,
    tree: &[TreeDelta],
) -> Vec<SemanticChange> {
    let mut chain: Vec<SemanticChange> = Vec::with_capacity(commits);
    let mut parent: Option<SemanticChangeId> = None;
    for index in 0..commits {
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: parent.into_iter().collect(),
            timestamp: fixed_timestamp(),
            author: AuthorId::new("fir2651-replay-measurement"),
            message: format!("synthetic converted commit {index} ")
                + &"body ".repeat(CHANGE_PAYLOAD_BYTES / 5),
            entity_deltas: vec![EntityDelta::Added {
                new: measurement_entity(index),
            }],
            relation_deltas: Vec::new(),
            tree_deltas: if index + 1 == commits {
                tree.to_vec()
            } else {
                Vec::new()
            },
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

/// Commit one whole-history bootstrap carrying a workspace mutation.
///
/// The store, the blobs and the transaction are all built before the commit, so
/// the span samples taken inside it describe the commit and not the fixture.
fn commit_one_bootstrap_with_a_workspace() {
    let directory = tempfile::tempdir().expect("tempdir");
    let backend = Arc::new(LocalFileBackend::new(directory.path()));
    let repository = RepositoryId::new("fir2651-replay-measurement").expect("repository id");
    let manager = RepositoryAuthorityManager::open(repository.clone(), backend)
        .expect("open fresh authority");

    let shared = SharedAdmissionPolicy::empty(0);
    let (tree_deltas, blobs) = head_tree(FILES);
    for (hash, body) in &blobs {
        manager.save_source_blob(*hash, body).expect("save blob");
    }
    let changes = history_chain(COMMITS, &shared, &tree_deltas);
    let head_change = changes.last().expect("at least one change").id;

    let lease = manager.read_authority();
    let mut transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: OperationId::from_uuid(Uuid::from_u128(1)),
        repository_id: repository.clone(),
        expected_generation: lease.generation(),
        expected_roots: lease.roots().clone(),
        actor: AuthorId::new("fir2651-replay-measurement"),
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

    let tree = ResolvedTree::default()
        .apply(&tree_deltas)
        .expect("head tree applies");
    let tree_hash = compute_resolved_tree_hash(&tree).expect("tree hash");
    let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(20));
    let overlay = FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::Sensitive, Vec::new())
        .expect("frozen overlay");
    let policy = EffectiveAdmissionPolicyStamp {
        shared: shared.stamp(),
        local: overlay.stamp(),
    };
    let main = RefName::branch(b"main").expect("branch name");
    let target = RefTarget::change(head_change);
    transaction.ref_mutations.push(RefMutation {
        name: main.clone(),
        expected: RefExpectation::MustNotExist,
        new_target: Some(target.clone()),
        policy: RefUpdatePolicy::FastForwardOnly,
    });
    transaction.default_ref_mutation = Some(DefaultRefMutation {
        expected: DefaultRefExpectation::MustBeUnset,
        new_default: Some(main.clone()),
    });
    transaction.workspace_mutation = Some(WorkspaceMutation {
        workspace_id,
        expected: WorkspaceExpectation::MustNotExist,
        new_generation: 0,
        new_head: WorkspaceHead::Symbolic { target: main },
        new_base_target: Some(target),
        new_base_tree_hash: Some(tree_hash),
        tree_deltas,
        new_tree_hash: tree_hash,
        semantic_delta: WorkspaceSemanticDelta::default(),
        new_shared_admission_policy: shared,
        new_admission_policy: policy,
    });
    transaction.local_overlay_delta = Some(FrozenLocalOverlayDelta::initialize(overlay));

    let receipt = manager
        .commit_repository_transaction(transaction)
        .expect("whole-history bootstrap commits");
    assert_eq!(
        receipt.generation, 1,
        "the bootstrap publishes generation 1"
    );

    drop(manager);
    drop(directory);
}

// --- the guard ------------------------------------------------------------

/// Copies of the committed history that `kindb.prepare.workspace` may still be
/// holding when it exits.
///
/// Set from measurement on this fixture, not from taste. Debug, this fixture,
/// one copy of the history at 2,947,618 bytes: the shape that decoded a whole
/// second snapshot into an `InMemoryGraph` and kept it measures 1.47 copies,
/// and the shape that proves the same two things over the borrowed snapshot
/// measures 0.20. A ceiling of 0.5 fails the first and passes the second, with
/// room on both sides, since the number is a ratio of two live-heap readings
/// taken in one process and is therefore profile- and host-independent.
///
/// It is not zero because the lap genuinely publishes something: the workspace
/// state it validates goes into the authority metadata and outlives the lap.
/// That is the workspace, not a copy of the repository.
const WORKSPACE_RETAINED_HISTORY_COPIES: f64 = 0.5;

/// A workspace lap must not still be holding a copy of the repository's history
/// when it ends.
///
/// This is the figure FIR-2651's acceptance names and the figure that sets a
/// conversion's ceiling, because peak growth is measured against the running
/// high-water mark: a phase that allocates and frees costs nothing at the top
/// of the ladder, and a phase that HOLDS costs the whole ladder above it.
#[test]
fn the_workspace_lap_does_not_hold_a_second_copy_of_the_history() {
    tracing::subscriber::set_global_default(PhaseSampler)
        .expect("this binary holds one test, so nothing else installed a subscriber");

    let shared = SharedAdmissionPolicy::empty(0);
    let (tree_deltas, _) = head_tree(FILES);
    let history = history_chain(COMMITS, &shared, &tree_deltas);
    let (copy, history_bytes) = retained_by(|| history.clone());
    drop(copy);
    drop(history);
    assert!(
        history_bytes > 1_000_000,
        "the fixture's history must be large enough to price a copy of it, got {history_bytes} bytes"
    );

    commit_one_bootstrap_with_a_workspace();

    // A positive control on the sampler itself. If the preparation span is
    // missing, every reading below is about a run that was never observed, and
    // reporting zero retained bytes would be the most flattering possible way
    // to be wrong.
    let prepare = retained_by_phase("kindb.commit.prepare_successor").unwrap_or_else(|| {
        panic!(
            "the sampler never saw the preparation span, so it observed nothing; \
             phases seen: {:?}",
            observed_phases()
        )
    });
    let workspace = retained_by_phase("kindb.prepare.workspace").unwrap_or_else(|| {
        panic!(
            "the sampler never saw the workspace lap, so this guard is measuring nothing; \
             phases seen: {:?}",
            observed_phases()
        )
    });

    let copies = workspace as f64 / history_bytes as f64;
    println!(
        "one history copy: {history_bytes} bytes\n\
         kindb.commit.prepare_successor retained: {prepare} bytes\n\
         kindb.prepare.workspace retained:        {workspace} bytes, {copies:.2} copies of the history"
    );

    assert!(
        copies <= WORKSPACE_RETAINED_HISTORY_COPIES,
        "the workspace lap ended still holding {workspace} bytes, {copies:.2} copies of the \
         {history_bytes}-byte history, at or over the {WORKSPACE_RETAINED_HISTORY_COPIES} copy ceiling"
    );
}
