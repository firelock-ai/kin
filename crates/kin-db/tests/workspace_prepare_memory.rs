// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What a workspace mutation holds alive while it prepares a successor.
//!
//! A full-history brownfield conversion commits its whole history in one
//! transaction, and the workspace half of that commit was the largest single
//! allocation in it. `apply_workspace` resolved a base graph, resolved or
//! cloned a second one, turned the second into an `InMemoryGraph`, exported
//! that graph back into a third whole snapshot, and then materialized a fourth
//! over the first, with every one of them carrying a copy of the repository's
//! entire change map although the comparisons between them read four domains.
//!
//! The guard below prices that. It commits the same synthetic whole history
//! twice, once with a workspace mutation and once without, and charges the
//! difference between their peak live heaps to the workspace mutation, in
//! units of one copy of the history itself. Resident set is deliberately not
//! the instrument: it keeps counting memory the allocator has freed and not
//! returned, so it moves with the allocator and the platform, while live heap
//! moves when and only when the code allocates differently.
//!
//! This file is its own test binary and holds one test on purpose. The
//! counters below are process-global, so a second test running beside this one
//! would be measured into it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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

/// Arm the peak at the current live heap and return that floor.
///
/// Peak is a running high-water mark, so it has to be pulled back down to the
/// live floor before a phase or it reports the previous phase's high point.
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

// --- the synthetic conversion ---------------------------------------------

/// Bytes of payload per change, so the change map is the dominant term the way
/// a converted repository's is rather than a rounding error on the fixture.
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

/// One distinct entity per commit, carrying enough documentation body that the
/// change holding it is worth measuring.
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
            author: AuthorId::new("fir2648-measurement"),
            message: format!("synthetic converted commit {index}"),
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

/// What one bootstrap arm cost and what it actually published.
///
/// The cost alone is not enough to judge. The guard below charges a difference
/// between two arms, so an arm whose workspace mutation quietly did nothing
/// makes that difference small and the guard pass. The published counts are
/// here so the ratio can refuse to be read until each arm is shown to have
/// done the thing it is named for.
struct BootstrapArm {
    /// Peak live heap the commit itself added, in bytes.
    peak_growth: usize,
    /// Workspaces the committed authority carries.
    workspaces: usize,
    /// Artifacts in the first workspace's tree, zero when there is none.
    workspace_artifacts: usize,
}

/// Commit one whole-history bootstrap and report the peak live heap it reached.
///
/// The store, the blobs and the transaction are all built before the peak is
/// armed, so the number is the commit's own growth and not the fixture's. The
/// authority is read back after the growth is captured, so reading it cannot
/// move the number it is reported beside.
fn peak_growth_of_one_bootstrap(with_workspace: bool) -> BootstrapArm {
    let directory = tempfile::tempdir().expect("tempdir");
    let backend = Arc::new(LocalFileBackend::new(directory.path()));
    let repository = RepositoryId::new("fir2648-measurement").expect("repository id");
    let manager = RepositoryAuthorityManager::open(repository.clone(), backend)
        .expect("open fresh authority");

    let shared = SharedAdmissionPolicy::empty(0);
    let (tree_deltas, blobs) = if with_workspace {
        head_tree(FILES)
    } else {
        (Vec::new(), Vec::new())
    };
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
        actor: AuthorId::new("fir2648-measurement"),
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

    if with_workspace {
        let tree = ResolvedTree::default()
            .apply(&tree_deltas)
            .expect("head tree applies");
        let tree_hash = compute_resolved_tree_hash(&tree).expect("tree hash");
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(20));
        let overlay =
            FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::Sensitive, Vec::new())
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
    }

    let floor = arm_peak();
    let receipt = manager
        .commit_repository_transaction(transaction)
        .expect("whole-history bootstrap commits");
    assert_eq!(
        receipt.generation, 1,
        "the bootstrap publishes generation 1"
    );
    let growth = peak_growth_since(floor);

    let lease = manager.read_authority();
    let published = &lease.metadata().workspaces;
    let arm = BootstrapArm {
        peak_growth: growth,
        workspaces: published.len(),
        workspace_artifacts: published
            .first()
            .map(|workspace| workspace.tree.artifacts().count())
            .unwrap_or(0),
    };
    drop(lease);

    drop(manager);
    drop(directory);
    arm
}

// --- the guard ------------------------------------------------------------

/// Peak growth a workspace mutation may add, in copies of the history it
/// commits.
///
/// Set from measurement on this fixture, not from taste. One copy of the
/// history at 2,833,178 bytes: the shape that carried whole snapshots for
/// four-domain comparisons measured 8.81 copies, the shape that replaced it
/// measured 4.56 and had drifted to 4.07, and the shape that stops a comparison
/// base carrying the change map measured 3.67 against a ceiling of 3.9. The
/// readings jitter by about half a percent across runs, because the number is a
/// ratio of two live-heap readings taken in the same process.
///
/// **The ceiling moved to 4.4 when the write path stopped holding copies, and
/// the reason is worth reading before touching it again.** This number is a
/// DIFFERENCE between two bootstrap peaks, one with a workspace mutation and one
/// without, so anything that lowers either arm moves it. Installing a snapshot
/// used to read the whole staged and promoted file back into memory three times
/// to check it, and removing that lowered BOTH arms while lowering the arm
/// WITHOUT a mutation proportionally more, because that arm has no high-water
/// mark above the write for the copies to hide under. Measured, one variable,
/// same fixture and host:
///
/// ```text
///   before  without 10,794,798  with 21,185,516  ratio 3.67
///   after   without  8,683,082  with 20,239,073  ratio 4.08
/// ```
///
/// Both peaks fell and the ratio rose. A ratio between two peaks is not a
/// memory measurement; it is a measurement of how two peaks relate, and an
/// unrelated improvement can move it in either direction. So the ceiling was
/// re-derived on the new baseline with the same mutations it was calibrated
/// against, rather than nudged until the intact reading passed: intact 4.08,
/// `next_base` carrying again 4.82, both bases carrying again 4.82. 4.4 sits
/// 0.32 above the intact reading and 0.42 below the smallest failure, which is
/// a wider margin on both sides than the 3.9 it replaces had.
///
/// What this ceiling does NOT price is the second of the two copies, and that
/// is worth writing down rather than leaving for someone to rediscover.
/// Restoring the `next_base` copy alone takes the ratio to 4.82 and this fails.
/// Restoring the `current_base` copy alone leaves it at 4.08 and this passes,
/// because on a 300-commit fixture that copy fits entirely under a high-water
/// mark another term has already set. Peak growth is measured against a running
/// mark and overlapping terms are not additive, so a ratio cannot see a term
/// that never reaches the top. The per-holder job belongs to
/// `a_workspace_mutation_resolves_no_base_carrying_the_history`, which counts
/// the changes each resolved base actually carried and goes red for either
/// copy on its own.
const WORKSPACE_PEAK_HISTORY_COPIES: f64 = 4.4;

/// A workspace mutation must not hold the repository's whole change map more
/// than about twice while it prepares a successor.
///
/// The two arms differ in one thing, whether the transaction carries a
/// workspace mutation, so the difference between their peaks is what the
/// mutation costs. Charging that difference against one copy of the history
/// makes the number readable as what it is: how many whole histories the
/// preparation is holding at its high point.
#[test]
fn a_workspace_mutation_does_not_hold_the_whole_history_four_times() {
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

    let without_workspace = peak_growth_of_one_bootstrap(false);
    let with_workspace = peak_growth_of_one_bootstrap(true);

    // The ratio below is a difference between two arms taken through
    // `saturating_sub`, so an arm that skipped its workspace mutation reads
    // 0.00 copies and passes. That is a check that cannot fail. Each arm has
    // to show what it published before the difference is allowed to mean
    // anything, and the evidence is the committed authority rather than the
    // transaction that was handed in.
    assert_eq!(
        without_workspace.workspaces, 0,
        "the arm without a workspace mutation published {} workspaces",
        without_workspace.workspaces
    );
    assert_eq!(
        with_workspace.workspaces, 1,
        "the arm with a workspace mutation published {} workspaces, so the difference below \
         would charge the mutation for work it never did",
        with_workspace.workspaces
    );
    assert_eq!(
        with_workspace.workspace_artifacts, FILES,
        "the published workspace carries {} artifacts rather than the {FILES} the fixture \
         commits, so its mutation did not do what this guard prices",
        with_workspace.workspace_artifacts
    );

    let workspace_cost = with_workspace
        .peak_growth
        .saturating_sub(without_workspace.peak_growth);
    let copies = workspace_cost as f64 / history_bytes as f64;

    println!(
        "one history copy: {history_bytes} bytes\n\
         bootstrap peak growth without a workspace mutation: {} bytes\n\
         bootstrap peak growth with a workspace mutation:    {} bytes\n\
         charged to the workspace mutation: {workspace_cost} bytes, {copies:.2} copies of the history",
        without_workspace.peak_growth, with_workspace.peak_growth
    );

    assert!(
        copies <= WORKSPACE_PEAK_HISTORY_COPIES,
        "a workspace mutation grew the peak by {workspace_cost} bytes, {copies:.2} copies of the \
         {history_bytes}-byte history, at or over the {WORKSPACE_PEAK_HISTORY_COPIES} copy ceiling"
    );
}
