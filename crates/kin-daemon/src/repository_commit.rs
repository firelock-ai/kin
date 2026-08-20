// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Repository-v6 native commit publication.
//!
//! Filesystem observation belongs to the serialized reconcile/admission
//! boundary. This module consumes only the admitted live graph, immutable blob
//! CAS, and one persisted repository-authority lease. History, exact tree,
//! workspace base, and the named ref advance in one storage compare-and-swap.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::{
    compute_resolved_tree_hash, compute_semantic_change_id, AuthorId, ChangeOrigin,
    EffectiveAdmissionPolicyStamp, Hash256, ModelError, OperationId, RefExpectation, RefMutation,
    RefName, RefTarget, RefUpdatePolicy, RepoPath, RepositoryCommitOutcome,
    RepositoryCommitReceipt, RepositoryTransaction, RootBundle, SemanticChange, SemanticChangeId,
    SharedAdmissionPolicy, Timestamp, WorkspaceExpectation, WorkspaceHead, WorkspaceId,
    WorkspaceMutation, WorkspaceSemanticDelta, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};

use crate::commit_deltas::compute_deltas_vs_repository_authority;
use crate::error::{DaemonError, Result};
use crate::local_repository_authority::LocalRepositoryAuthorityContext;
use crate::source_cas::read_publishable_source;

type ProjectionEntry = (kin_model::RepoPath, kin_model::TreeEntry, Arc<[u8]>);

/// Complete immutable plan for one native repository transaction.
///
/// `source_hashes` name bodies already present in the daemon's admitted blob
/// CAS. They are copied into repository-owned CAS immediately before the
/// authority compare-and-swap; raw checkout bytes are never consulted.
///
/// The plan also carries the repository authority it was read from, still open.
/// Opening one is O(store): it decodes the whole persisted authority and then
/// re-verifies every body in repository CAS against its content address, which
/// kin-db does unconditionally on every open. A commit that planned against one
/// open authority and then published through a second paid that twice for one
/// change. Carrying it is what makes the plan and the publication the same
/// authority rather than two reads of the same generation, so the roots the
/// transaction expects and the roots the publication compare-and-swaps against
/// are the same in-memory state.
pub struct NativeCommitPlan {
    pub change: SemanticChange,
    pub transaction: RepositoryTransaction,
    pub branch: RefName,
    pub entity_count: usize,
    pub relation_count: usize,
    pub file_count: usize,
    /// Files this change publishes that the caller's own operations did not
    /// author, carried in from working-tree content the workspace had already
    /// admitted ahead of its base change.
    ///
    /// Always empty for a caller that does not declare which files it authored,
    /// because a planner cannot tell an unclaimed file from an authored one,
    /// and an unclaimed file must never be reported as carried on a guess.
    pub carried_pending_files: Vec<RepoPath>,
    previous_tree: kin_model::ResolvedTree,
    target_tree: kin_model::ResolvedTree,
    source_hashes: Vec<Hash256>,
    authority: RepositoryAuthorityManager<LocalFileBackend>,
}

#[derive(Debug)]
pub struct NativeCommitResult {
    pub change: SemanticChange,
    pub receipt: RepositoryCommitReceipt,
    pub branch: RefName,
    pub entity_count: usize,
    pub relation_count: usize,
    pub file_count: usize,
}

/// One coherent, clean workspace authority base for a prospective native
/// commit.
///
/// The graph is materialized from the workspace lease, not from the daemon's
/// mutable query overlay. `roots` must still match when the final plan is
/// constructed; repository publication independently repeats the same CAS.
pub struct NativeCommitBase {
    pub graph: kin_db::InMemoryGraph,
    pub roots: RootBundle,
    pub tree: kin_model::ResolvedTree,
}

/// Result of durably admitting one exact working-tree transition.
///
/// This advances workspace authority only. It does not manufacture a semantic
/// history node or move a named ref: dirty Compose/config/binary/unsupported
/// artifacts remain dirty workspace state until an explicit Kin commit.
#[derive(Debug)]
pub struct WorkspaceAdmissionResult {
    pub receipt: RepositoryCommitReceipt,
    pub workspace_id: WorkspaceId,
    pub tree_hash: Hash256,
    pub file_count: usize,
}

/// One exact workspace transition that a complete host scan actually proved.
///
/// The constructor requires [`kin_index::CompleteScanToken`], which only a
/// fully successful repository walk mints, so publication cannot be handed a
/// tree assembled from a partial walk or from nothing at all. It also binds the
/// authority roots and the workspace tree the transition was planned against,
/// which is what lets publication refuse a stale desired tree instead of
/// silently replanning it against newer authority.
#[derive(Debug)]
pub(crate) struct AdmittedWorkspaceTree {
    previous_tree: kin_model::ResolvedTree,
    desired_tree: kin_model::ResolvedTree,
    expected_roots: RootBundle,
    /// Held, not read: the proof does its work by being impossible to supply
    /// without a completed walk, and by staying attached to the tree it
    /// proved.
    #[allow(dead_code)]
    completion: kin_index::CompleteScanToken,
}

impl AdmittedWorkspaceTree {
    pub(crate) fn from_complete_observation(
        completion: kin_index::CompleteScanToken,
        expected_roots: RootBundle,
        previous_tree: kin_model::ResolvedTree,
        desired_tree: kin_model::ResolvedTree,
    ) -> Self {
        Self {
            previous_tree,
            desired_tree,
            expected_roots,
            completion,
        }
    }
}

/// Admit `desired_tree` for a test by taking a real host walk first.
///
/// `CompleteScanToken` cannot be minted outside `kin-index`, so a test cannot
/// fabricate an admission any more than production can. It has to walk the
/// working directory and carry back the proof that the walk finished.
#[cfg(test)]
pub(crate) fn admitted_workspace_tree_for_test(
    working_dir: &std::path::Path,
    expected_roots: RootBundle,
    previous_tree: kin_model::ResolvedTree,
    desired_tree: kin_model::ResolvedTree,
) -> AdmittedWorkspaceTree {
    let ignore = kin_index::RepositoryIgnore::load(working_dir).expect("load repository ignore");
    let scan = kin_index::scan_repository(
        working_dir,
        &ignore,
        previous_tree
            .artifacts_by_path()
            .map(|artifact| &artifact.path),
    )
    .expect("complete host walk");
    AdmittedWorkspaceTree::from_complete_observation(
        scan.completion(),
        expected_roots,
        previous_tree,
        desired_tree,
    )
}

/// Immutable session-reconcile plan bound to the authority lease captured when
/// the disposable session was materialized.
pub struct SessionWorkspaceAdmissionPlan {
    pub transaction: RepositoryTransaction,
    pub previous_tree: kin_model::ResolvedTree,
    pub target_tree: kin_model::ResolvedTree,
    pub deltas: Vec<kin_model::TreeDelta>,
    pub workspace_id: WorkspaceId,
    source_hashes: Vec<Hash256>,
    recovered_receipt: Option<RepositoryCommitReceipt>,
}

#[derive(Debug)]
pub struct SessionWorkspaceAdmissionResult {
    pub receipt: RepositoryCommitReceipt,
    pub workspace_id: WorkspaceId,
    pub tree_hash: Hash256,
    pub file_count: usize,
    pub idempotent_replay: bool,
}

/// Build one exact session admission against the session's retained roots and
/// complete source workspace.
///
/// Planning takes the sealed observation rather than a loose base and tree, so
/// the retained no-follow directory capability is still held here and can be
/// re-proved before anything is planned against it. A caller cannot reach this
/// boundary with a desired tree that no retained walk produced.
///
/// Unlike the ambient filesystem synchronizer, this never silently rebases
/// onto a newer workspace. The only accepted moved-authority state is the
/// exact durable receipt for this session's caller-stable operation and
/// transaction hash.
pub(crate) fn plan_session_workspace_admission(
    layout: &kin_core::KinLayout,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    observation: &kin_cli::commands::reconcile::SessionReconcileObservation,
) -> Result<SessionWorkspaceAdmissionPlan> {
    observation
        .revalidate_retained_capability(layout)
        .map_err(|error| invalid(error.to_string()))?;
    let base = observation.base();
    let desired_tree = observation.desired_tree();
    let repository_id = authority_context.repository_id().clone();
    let workspace_id = authority_context.workspace_id();
    if base.repository_id != repository_id
        || base.source_workspace.repository_id != repository_id
        || base.source_workspace.workspace_id != workspace_id
    {
        return Err(invalid(
            "session base repository/workspace identity does not match this repository",
        ));
    }
    base.authority_roots.validate()?;
    base.source_workspace.validate()?;
    let deltas = kin_core::exact_tree_correction(&base.source_workspace.tree, desired_tree)?;
    if deltas.is_empty() {
        return Err(invalid(
            "session workspace admission planner rejects empty transitions",
        ));
    }

    let authority = authority_context.open().map_err(DaemonError::Graph)?;
    let mut source_lengths = std::collections::BTreeMap::new();
    let (shared_policy, _) = SharedAdmissionPolicy::derive_from_tree_with_allowances(
        Some(&base.source_workspace.shared_admission_policy),
        desired_tree,
        |hash| {
            if let Some(length) = source_lengths.get(&hash) {
                return Ok(*length);
            }
            let source = read_publishable_source(blobs, &authority, hash).map_err(|error| {
                ModelError::InvalidOperation(format!(
                    "{error}, while deriving the exact session admission policy"
                ))
            })?;
            let length = u64::try_from(source.body().len()).map_err(|_| {
                ModelError::InvalidOperation(format!(
                    "exact session admission-policy source {hash} exceeds u64"
                ))
            })?;
            source_lengths.insert(hash, length);
            Ok(length)
        },
    |hash| {
    read_publishable_source(blobs, &authority, hash)
        .map(|source| source.body().to_vec())
        .map_err(|error| {
            ModelError::InvalidOperation(format!(
                "{error}, while reading the approvals the exact session policy derives"
            ))
        })
},
    )?;
    let tree_hash = compute_resolved_tree_hash(desired_tree)?;
    let new_generation = base
        .source_workspace
        .generation
        .checked_add(1)
        .ok_or_else(|| invalid("session workspace generation exhausted"))?;
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: base.reconcile_operation_id,
        repository_id: repository_id.clone(),
        expected_generation: base.authority_roots.generation,
        expected_roots: base.authority_roots.clone(),
        actor: AuthorId::new("kin-session-reconcile"),
        reason: "admit exact disposable-session observation".to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: Some(WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: base.source_workspace.generation,
                head: base.source_workspace.head.clone(),
                base_target: base.source_workspace.base_target.clone(),
                base_tree_hash: base.source_workspace.base_tree_hash,
                tree_hash: base.source_workspace.tree_hash,
                semantic_overlay_hash: base.source_workspace.semantic_overlay_hash,
                admission_policy: base.source_workspace.admission_policy,
            },
            new_generation,
            new_head: base.source_workspace.head.clone(),
            new_base_target: base.source_workspace.base_target.clone(),
            new_base_tree_hash: base.source_workspace.base_tree_hash,
            tree_deltas: deltas.clone(),
            new_tree_hash: tree_hash,
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: shared_policy.clone(),
            new_admission_policy: EffectiveAdmissionPolicyStamp {
                shared: shared_policy.stamp(),
                local: base.source_workspace.admission_policy.local,
            },
        }),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
    };
    transaction.validate()?;
    let transaction_hash = transaction.transaction_hash()?;

    let mut source_hashes = BTreeSet::new();
    for delta in &deltas {
        if let Some(hash) = delta
            .new_state()
            .and_then(|located| located.entry.blob_identity())
        {
            source_hashes.insert(hash);
        }
    }
    source_hashes.extend(shared_policy.sources.iter().map(|source| source.body_hash));

    let lease = authority.read_authority();
    let current_workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == workspace_id)
        .ok_or_else(|| {
            invalid(format!(
                "repository authority has no workspace {workspace_id}"
            ))
        })?;
    let exact_base_is_current =
        lease.roots() == &base.authority_roots && current_workspace == &base.source_workspace;
    let recovered_receipt = if exact_base_is_current {
        None
    } else {
        let receipt = lease
            .metadata()
            .receipts
            .iter()
            .find(|receipt| receipt.operation_id == base.reconcile_operation_id)
            .cloned()
            .ok_or_else(|| {
                invalid(
                    "repository authority moved after session materialization; exact reconcile \
                     does not silently rebase",
                )
            })?;
        receipt.validate()?;
        if receipt.transaction_hash != transaction_hash || current_workspace.tree != *desired_tree {
            return Err(invalid(
                "session operation already names a different authority transition",
            ));
        }
        Some(receipt)
    };
    drop(lease);

    Ok(SessionWorkspaceAdmissionPlan {
        transaction,
        previous_tree: base.source_workspace.tree.clone(),
        target_tree: desired_tree.clone(),
        deltas,
        workspace_id,
        source_hashes: source_hashes.into_iter().collect(),
        recovered_receipt,
    })
}

/// Persist session-observed immutable bodies and linearize the exact primary
/// projection with one workspace-only repository transaction.
pub(crate) fn commit_session_workspace_admission(
    layout: &kin_core::KinLayout,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    plan: SessionWorkspaceAdmissionPlan,
) -> Result<SessionWorkspaceAdmissionResult> {
    let repository_id = authority_context.repository_id().clone();
    if plan.transaction.repository_id != repository_id {
        return Err(invalid(format!(
            "session admission plan belongs to {}, not {}",
            plan.transaction.repository_id, repository_id
        )));
    }
    let authority = authority_context.open().map_err(DaemonError::Graph)?;
    for hash in &plan.source_hashes {
        if let Some(body) = read_publishable_source(blobs, &authority, *hash)?.body_to_publish() {
            authority.save_source_blob(*hash, body)?;
        }
    }

    let tree_hash = compute_resolved_tree_hash(&plan.target_tree)?;
    let (receipt, replayed) = if let Some(receipt) = plan.recovered_receipt {
        // A prior attempt crossed authority. Recovery must prove that the
        // primary projection is the same exact complete tree before reporting
        // success; graph-only members use their typed host proof.
        let freeze = kin_core::ExactProjectionFreeze::acquire_existing(layout.working_dir())?;
        let verification = freeze.verify_resolved_tree_from_blobs(&plan.target_tree, blobs)?;
        freeze.revalidate_resolved_tree_from_blobs(&verification, &plan.target_tree, blobs)?;
        (receipt, true)
    } else {
        let mut body_cache = BTreeMap::new();
        let target_entries =
            load_projection_entries(&authority, &plan.target_tree, &mut body_cache)?;
        let previous_entries =
            load_projection_entries(&authority, &plan.previous_tree, &mut body_cache)?;
        let (_, receipt) = kin_core::reconcile_source_tree_and_commit_repository_transaction(
            layout.working_dir(),
            &plan.previous_tree,
            &plan.target_tree,
            previous_entries
                .iter()
                .map(|(path, entry, body)| (path, *entry, body.as_ref())),
            target_entries
                .iter()
                .map(|(path, entry, body)| (path, *entry, body.as_ref())),
            &authority,
            plan.transaction,
        )?;
        let replayed = receipt.outcome == RepositoryCommitOutcome::IdempotentReplay;
        (receipt, replayed)
    };
    receipt.validate()?;
    Ok(SessionWorkspaceAdmissionResult {
        receipt,
        workspace_id: plan.workspace_id,
        tree_hash,
        file_count: plan.deltas.len(),
        idempotent_replay: replayed,
    })
}

/// Atomically publish one exact graph-owned workspace tree.
///
/// The caller has already performed the explicit filesystem-ingestion scan and
/// carries its completion proof in `admitted`. This boundary consumes only that
/// admitted exact tree plus bodies the repository already owns or the
/// non-authoritative ingestion CAS still stages, copies newly referenced bodies
/// into repository CAS, and compare-and-swaps the workspace. It never creates a
/// history node or advances a ref.
///
/// Bodies are read from ingestion staging first and from repository CAS when
/// staging no longer has them. Staging is not authority and promises no
/// retention, so a source the repository already published stays publishable
/// whether or not its staged copy survives.
///
/// Authority that moved after the observation was planned fails the whole
/// publication. The desired tree describes one transition out of one observed
/// prior tree; re-deriving it against a newer workspace would publish a
/// transition nobody observed, and would silently revert whatever moved
/// authority in the meantime.
pub(crate) fn publish_workspace_tree(
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    admitted: &AdmittedWorkspaceTree,
    operation_id: OperationId,
    actor: AuthorId,
) -> Result<Option<WorkspaceAdmissionResult>> {
    let desired_tree = &admitted.desired_tree;
    let repository_id = authority_context.repository_id().clone();
    let workspace_id = authority_context.workspace_id();
    let authority = authority_context.open().map_err(DaemonError::Graph)?;
    let lease = authority.read_authority();
    if lease.roots() != &admitted.expected_roots {
        return Err(invalid(
            "repository authority moved after the complete workspace observation was planned; \
             exact admission does not replan a stale desired tree against newer authority",
        ));
    }
    let workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == workspace_id)
        .ok_or_else(|| {
            invalid(format!(
                "repository authority has no local workspace {workspace_id}"
            ))
        })?
        .clone();
    if workspace.repository_id != repository_id {
        return Err(invalid(format!(
            "workspace {} belongs to {}, not {}",
            workspace.workspace_id, workspace.repository_id, repository_id
        )));
    }
    if workspace.tree != admitted.previous_tree {
        return Err(invalid(
            "the complete workspace observation was planned against a tree that is not this \
             workspace's authority tree; exact admission does not replan a stale desired tree \
             against newer authority",
        ));
    }
    if workspace.tree == *desired_tree {
        return Ok(None);
    }

    let tree_deltas = kin_core::exact_tree_correction(&workspace.tree, desired_tree)?;
    let mut source_lengths = std::collections::BTreeMap::new();
    let (shared_policy, _) = SharedAdmissionPolicy::derive_from_tree_with_allowances(
        Some(&workspace.shared_admission_policy),
        desired_tree,
        |hash| {
            if let Some(length) = source_lengths.get(&hash) {
                return Ok(*length);
            }
            // Every rule file in the desired tree is measured here, changed or
            // not, because the policy is derived from the whole tree rather
            // than from what moved.
            let source = read_publishable_source(blobs, &authority, hash).map_err(|error| {
                ModelError::InvalidOperation(format!(
                    "{error}, while deriving the admitted workspace policy"
                ))
            })?;
            let length = u64::try_from(source.body().len()).map_err(|_| {
                ModelError::InvalidOperation(format!(
                    "admitted workspace policy source {hash} exceeds u64"
                ))
            })?;
            source_lengths.insert(hash, length);
            Ok(length)
        },
    |hash| {
    read_publishable_source(blobs, &authority, hash)
        .map(|source| source.body().to_vec())
        .map_err(|error| {
            ModelError::InvalidOperation(format!(
                "{error}, while reading the approvals the admitted workspace policy derives"
            ))
        })
},
    )?;
    let tree_hash = compute_resolved_tree_hash(desired_tree)?;
    let new_generation = workspace.generation.checked_add(1).ok_or_else(|| {
        invalid(format!(
            "workspace {} generation exhausted",
            workspace.workspace_id
        ))
    })?;
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id,
        repository_id,
        expected_generation: lease.roots().generation,
        expected_roots: lease.roots().clone(),
        actor,
        reason: "admit exact graph-owned workspace tree".to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: Some(WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: workspace.generation,
                head: workspace.head.clone(),
                base_target: workspace.base_target.clone(),
                base_tree_hash: workspace.base_tree_hash,
                tree_hash: workspace.tree_hash,
                semantic_overlay_hash: workspace.semantic_overlay_hash,
                admission_policy: workspace.admission_policy,
            },
            new_generation,
            new_head: workspace.head,
            new_base_target: workspace.base_target,
            new_base_tree_hash: workspace.base_tree_hash,
            tree_deltas: tree_deltas.clone(),
            new_tree_hash: tree_hash,
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: shared_policy.clone(),
            new_admission_policy: EffectiveAdmissionPolicyStamp {
                shared: shared_policy.stamp(),
                local: workspace.admission_policy.local,
            },
        }),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
    };
    transaction.validate()?;

    let mut source_hashes = BTreeSet::new();
    for delta in &tree_deltas {
        if let Some(hash) = delta
            .new_state()
            .and_then(|located| located.entry.blob_identity())
        {
            source_hashes.insert(hash);
        }
    }
    source_hashes.extend(shared_policy.sources.iter().map(|source| source.body_hash));
    drop(lease);

    // Copying a staged body into repository CAS is how a newly referenced
    // source becomes durable. An unchanged rule source is already there and
    // needs no copy.
    for hash in source_hashes {
        if let Some(body) = read_publishable_source(blobs, &authority, hash)?.body_to_publish() {
            authority.save_source_blob(hash, body)?;
        }
    }
    let receipt = authority.commit_repository_transaction(transaction)?;
    receipt.validate()?;
    Ok(Some(WorkspaceAdmissionResult {
        receipt,
        workspace_id,
        tree_hash,
        file_count: tree_deltas.len(),
    }))
}

/// Construct one exact native transaction without mutating repository
/// authority.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_native_commit(
    graph: &kin_db::InMemoryGraph,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    operation_id: OperationId,
    timestamp: Timestamp,
    author: AuthorId,
    message: String,
) -> Result<NativeCommitPlan> {
    plan_native_commit_inner(
        graph,
        blobs,
        authority_context,
        operation_id,
        timestamp,
        author,
        None,
        &|_| message.clone(),
        None,
    )
}

/// Construct one exact native transaction against the authority generation
/// from which `base` was materialized.
///
/// This closes the read-plan race where a caller could build a prospective
/// graph from generation N while the generic planner silently based its delta
/// on generation N+1. Publication still performs the storage CAS, so a move
/// after planning also fails closed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_native_commit_from_base(
    graph: &kin_db::InMemoryGraph,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    operation_id: OperationId,
    timestamp: Timestamp,
    author: AuthorId,
    message: String,
    base: &NativeCommitBase,
) -> Result<NativeCommitPlan> {
    plan_native_commit_inner(
        graph,
        blobs,
        authority_context,
        operation_id,
        timestamp,
        author,
        None,
        &|_| message.clone(),
        Some(&base.roots),
    )
}

/// Plan one exact native transaction whose message states which of the files it
/// publishes the caller did not author.
///
/// A workspace can hold working-tree content its base change does not carry:
/// the admission path advances the workspace tree without advancing its base,
/// and it publishes no change, so that content sits ahead of history with no
/// authorship attached to it. It is already inside the prospective graph a
/// caller plans against, because the workspace graph takes its resolved tree
/// from the workspace, so a commit either publishes it or reverts the working
/// files that hold it. It gets published, and this is what makes that
/// publication say so.
///
/// `authored_files` names the files the caller's own operations produced. Every
/// other file this change publishes came from the pending tree, and the rendered
/// message is handed exactly that list, so the record cannot name a different
/// set than the one it published: the message is settled after the tree deltas
/// are computed and before the change is identified by its hash.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_native_commit_from_base_declaring_carry(
    graph: &kin_db::InMemoryGraph,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    operation_id: OperationId,
    timestamp: Timestamp,
    author: AuthorId,
    authored_files: &BTreeSet<RepoPath>,
    message: &dyn Fn(&[RepoPath]) -> String,
    base: &NativeCommitBase,
) -> Result<NativeCommitPlan> {
    plan_native_commit_inner(
        graph,
        blobs,
        authority_context,
        operation_id,
        timestamp,
        author,
        Some(authored_files),
        message,
        Some(&base.roots),
    )
}

/// The paths one change publishes that its author's own operations did not
/// write.
///
/// One definition, because two callers need the same answer from different
/// starting points: the planner has the authored set in hand, and a commit
/// resumed after an interruption recovers it from the staged operations. If
/// these ever computed the fold differently, a resumed commit would describe
/// itself differently from the one it is resuming.
pub(crate) fn carried_pending_paths(
    tree_deltas: &[kin_model::TreeDelta],
    authored: &BTreeSet<RepoPath>,
) -> Vec<RepoPath> {
    let mut carried = tree_deltas
        .iter()
        // A pending deletion moves the tree exactly as a pending edit does, and
        // is the transition a reader is least likely to expect, so it is named
        // through its old state rather than dropped for having no new one.
        .filter_map(|delta| delta.new_state().or_else(|| delta.old_state()))
        .map(|located| located.path.clone())
        .filter(|path| !authored.contains(path))
        .collect::<Vec<_>>();
    carried.sort();
    carried.dedup();
    carried
}

#[allow(clippy::too_many_arguments)]
fn plan_native_commit_inner(
    graph: &kin_db::InMemoryGraph,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    operation_id: OperationId,
    timestamp: Timestamp,
    author: AuthorId,
    authored_files: Option<&BTreeSet<RepoPath>>,
    message: &dyn Fn(&[RepoPath]) -> String,
    expected_roots: Option<&RootBundle>,
) -> Result<NativeCommitPlan> {
    let repository_id = authority_context.repository_id().clone();
    let workspace_id = authority_context.workspace_id();
    let authority = authority_context.open().map_err(DaemonError::Graph)?;
    let lease = authority.read_authority();
    if expected_roots.is_some_and(|expected| expected != lease.roots()) {
        return Err(invalid(
            "repository authority moved after the prospective commit base was read",
        ));
    }
    let metadata = lease.metadata();
    let workspace = metadata
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == workspace_id)
        .ok_or_else(|| {
            invalid(format!(
                "repository authority has no local workspace {workspace_id}"
            ))
        })?
        .clone();
    if workspace.repository_id != repository_id {
        return Err(invalid(format!(
            "workspace {} belongs to {}, not {}",
            workspace.workspace_id, workspace.repository_id, repository_id
        )));
    }

    let (branch, current_ref_target, parent) =
        resolve_symbolic_commit_base(metadata, &workspace.head, workspace.base_target.as_ref())?;
    let parent_policy = match parent {
        Some(parent) => Some(
            metadata
                .admission_policies
                .iter()
                .find(|candidate| candidate.change_id == parent)
                .and_then(|candidate| candidate.policy.clone())
                .ok_or_else(|| {
                    invalid(format!(
                        "native commit parent {parent} has no resolved shared admission policy"
                    ))
                })?,
        ),
        None => None,
    };

    // Both sides of the semantic diff are whole copies of the graph and neither
    // is read again once the delta exists, so both are scoped to the diff and
    // freed before the phase that follows.
    //
    // `InMemoryGraph::to_snapshot` deep-clones every sub-store, the change DAG
    // included, so on a converted repository it is a copy of the store rather
    // than a copy of the workspace. Left at function scope it stayed resident
    // through `plan_compute_deltas`, which is where a one-file commit on a
    // 1.0 GB psf/requests store reaches its resident-set peak, and through the
    // whole authority publication after it. It has nothing to contribute to
    // either.
    let workspace_semantic_delta = {
        let authority_workspace_graph =
            lease
                .workspace_graph_snapshot(&workspace_id)?
                .ok_or_else(|| {
                    invalid(format!(
                        "repository authority has no graph snapshot for workspace {workspace_id}"
                    ))
                })?;
        let desired_workspace_graph =
            crate::mcp_commit::timed_commit_phase("plan_snapshot_clone", || graph.to_snapshot());
        crate::mcp_commit::timed_commit_phase("plan_diff_semantics", || {
            kin_core::diff_workspace_semantics(
                &authority_workspace_graph.entities,
                &authority_workspace_graph.relations,
                &desired_workspace_graph.entities,
                &desired_workspace_graph.relations,
            )
        })?
    };
    let deltas = crate::mcp_commit::timed_commit_phase("plan_compute_deltas", || {
        compute_deltas_vs_repository_authority(graph, lease.snapshot(), parent.as_ref())
    })?;
    let mut source_lengths = std::collections::BTreeMap::new();
    let (shared_policy, admission_policy_delta) =
        crate::mcp_commit::timed_commit_phase("plan_derive_admission_policy", || {
            SharedAdmissionPolicy::derive_from_tree_with_allowances(
                parent_policy.as_ref(),
                &deltas.expected_tree,
                |hash| {
                    if let Some(length) = source_lengths.get(&hash) {
                        return Ok(*length);
                    }
                    let source =
                        read_publishable_source(blobs, &authority, hash).map_err(|error| {
                            ModelError::InvalidOperation(format!(
                                "{error}, while deriving the graph-owned admission policy"
                            ))
                        })?;
                    let length = u64::try_from(source.body().len()).map_err(|_| {
                        ModelError::InvalidOperation(format!(
                            "graph-owned admission source {hash} exceeds u64"
                        ))
                    })?;
                    source_lengths.insert(hash, length);
                    Ok(length)
                },
            |hash| {
    read_publishable_source(blobs, &authority, hash)
        .map(|source| source.body().to_vec())
        .map_err(|error| {
            ModelError::InvalidOperation(format!(
                "{error}, while reading the approvals the graph-owned policy derives"
            ))
        })
},
            )
        })?;

    // Settled here, not before planning: the message may have to name what this
    // change carried in, and that set is not known until the published tree
    // deltas are.
    let carried_pending_files = authored_files
        .map(|authored| carried_pending_paths(&deltas.tree_deltas, authored))
        .unwrap_or_default();
    let message = message(&carried_pending_files);
    if message.trim().is_empty() {
        return Err(invalid("native commit message must not be empty"));
    }

    let entity_count = deltas.entity_deltas.len();
    let relation_count = deltas.relation_deltas.len();
    let file_count = deltas.tree_deltas.len();
    let mut change = SemanticChange {
        id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
        origin: ChangeOrigin::Native,
        parents: parent.into_iter().collect(),
        timestamp,
        author: author.clone(),
        message,
        entity_deltas: deltas.entity_deltas,
        relation_deltas: deltas.relation_deltas,
        tree_deltas: deltas.tree_deltas,
        admission_policy_delta,
        projected_files: Vec::new(),
        spec_link: None,
        evidence: Vec::new(),
        risk_summary: None,
        external_reference_deltas: Vec::new(),
    };
    change.id = compute_semantic_change_id(&change)?;

    let tree_hash = compute_resolved_tree_hash(&deltas.expected_tree)?;
    let workspace_tree_deltas =
        kin_core::exact_tree_correction(&workspace.tree, &deltas.expected_tree)?;
    let workspace_generation = workspace.generation.checked_add(1).ok_or_else(|| {
        invalid(format!(
            "workspace {} generation exhausted",
            workspace.workspace_id
        ))
    })?;
    let new_target = RefTarget::change(change.id);
    let workspace_mutation = WorkspaceMutation {
        workspace_id,
        expected: WorkspaceExpectation::MustEqual {
            generation: workspace.generation,
            head: workspace.head.clone(),
            base_target: workspace.base_target.clone(),
            base_tree_hash: workspace.base_tree_hash,
            tree_hash: workspace.tree_hash,
            semantic_overlay_hash: workspace.semantic_overlay_hash,
            admission_policy: workspace.admission_policy,
        },
        new_generation: workspace_generation,
        new_head: workspace.head.clone(),
        new_base_target: Some(new_target.clone()),
        new_base_tree_hash: Some(tree_hash),
        tree_deltas: workspace_tree_deltas,
        new_tree_hash: tree_hash,
        semantic_delta: workspace_semantic_delta,
        new_shared_admission_policy: shared_policy.clone(),
        new_admission_policy: EffectiveAdmissionPolicyStamp {
            shared: shared_policy.stamp(),
            local: workspace.admission_policy.local,
        },
    };
    let ref_mutation = RefMutation {
        name: branch.clone(),
        expected: current_ref_target
            .map(|target| RefExpectation::MustEqual { target })
            .unwrap_or(RefExpectation::MustNotExist),
        new_target: Some(new_target),
        policy: RefUpdatePolicy::FastForwardOnly,
    };
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id,
        repository_id,
        expected_generation: lease.roots().generation,
        expected_roots: lease.roots().clone(),
        actor: author,
        reason: "publish admitted native semantic change".to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: vec![change.clone()],
        aliases: Vec::new(),
        ref_mutations: vec![ref_mutation],
        default_ref_mutation: None,
        workspace_mutation: Some(workspace_mutation),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
    };
    transaction.validate()?;

    let mut source_hashes = BTreeSet::new();
    for delta in &change.tree_deltas {
        if let Some(hash) = delta
            .new_state()
            .and_then(|located| located.entry.blob_identity())
        {
            source_hashes.insert(hash);
        }
    }
    source_hashes.extend(shared_policy.sources.iter().map(|source| source.body_hash));

    // The lease is a read of this authority and the plan carries the authority
    // itself, so the read ends here and the open does not.
    drop(lease);
    Ok(NativeCommitPlan {
        change,
        transaction,
        branch,
        entity_count,
        relation_count,
        file_count,
        carried_pending_files,
        previous_tree: workspace.tree,
        target_tree: deltas.expected_tree,
        source_hashes: source_hashes.into_iter().collect(),
        authority,
    })
}

/// Load one local workspace from repository-v6 authority as a commit base.
///
/// A workspace holding a pending tree is not refused here, and the difference
/// between that and the rule this replaces is the difference between an agent
/// that can write to a repository somebody works in and one that cannot.
/// Admission advances the workspace tree without advancing its base and
/// publishes no change, so ordinary editing leaves every used workspace ahead of
/// its base change permanently: the state never clears itself, and the refusal's
/// own remedy could not reach it, because there was no graph-owned change to
/// seal.
///
/// Refusing it never kept that content out of a commit either. The workspace
/// graph takes its resolved tree from the workspace, so the pending content is
/// inside the prospective graph every caller plans against, and a commit that
/// excluded it would have to revert the working files that hold it. What the
/// refusal actually bought was silence about a fold that was going to happen
/// anyway once the guard was lifted, which is why the caller that lifts it
/// declares the fold instead: see
/// [`plan_native_commit_from_base_declaring_carry`].
pub(crate) fn load_native_commit_base(
    authority_context: &LocalRepositoryAuthorityContext,
) -> Result<NativeCommitBase> {
    let workspace_id = authority_context.workspace_id();
    let authority = authority_context.open().map_err(DaemonError::Graph)?;
    let lease = authority.read_authority();
    let workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == workspace_id)
        .ok_or_else(|| {
            invalid(format!(
                "repository authority has no local workspace {workspace_id}"
            ))
        })?;
    let tree = workspace.tree.clone();
    let snapshot = lease
        .workspace_graph_snapshot(&workspace_id)?
        .ok_or_else(|| {
            invalid(format!(
                "repository authority has no graph snapshot for workspace {workspace_id}"
            ))
        })?;
    let roots = lease.roots().clone();
    drop(lease);
    let graph = kin_db::InMemoryGraph::from_snapshot(snapshot)?;
    Ok(NativeCommitBase { graph, roots, tree })
}

/// Load one immutable source body directly from repository-owned CAS.
pub(crate) fn load_native_source_blob(
    authority_context: &LocalRepositoryAuthorityContext,
    hash: Hash256,
) -> Result<Vec<u8>> {
    let authority = authority_context.open().map_err(DaemonError::Graph)?;
    authority.load_source_blob(hash)?.ok_or_else(|| {
        invalid(format!(
            "repository source CAS is missing exact body {hash}"
        ))
    })
}

/// Recover the exact native change and receipt for a caller-stable operation.
///
/// A daemon can use this after restart or an indeterminate local persistence
/// acknowledgement. No transaction is rebuilt and no branch is advanced.
pub(crate) fn recover_native_commit(
    authority_context: &LocalRepositoryAuthorityContext,
    operation_id: OperationId,
) -> Result<Option<NativeCommitResult>> {
    let authority = authority_context.open().map_err(DaemonError::Graph)?;
    let lease = authority.read_authority();
    let Some(receipt) = lease
        .metadata()
        .receipts
        .iter()
        .find(|receipt| receipt.operation_id == operation_id)
        .cloned()
    else {
        return Ok(None);
    };
    let mut native_targets = receipt
        .operation
        .ref_mutations
        .iter()
        .filter_map(|mutation| match mutation.new_target.as_ref() {
            Some(RefTarget::Change { change_id }) => Some((mutation.name.clone(), *change_id)),
            _ => None,
        });
    let (branch, change_id) = native_targets.next().ok_or_else(|| {
        invalid(format!(
            "repository receipt for MCP operation {operation_id} has no native change target"
        ))
    })?;
    if native_targets.next().is_some() {
        return Err(invalid(format!(
            "repository receipt for MCP operation {operation_id} has multiple native change targets"
        )));
    }
    let change = lease
        .snapshot()
        .changes
        .get(&change_id)
        .cloned()
        .ok_or_else(|| {
            invalid(format!(
                "repository receipt for MCP operation {operation_id} references missing change {change_id}"
            ))
        })?;
    Ok(Some(NativeCommitResult {
        entity_count: change.entity_deltas.len(),
        relation_count: change.relation_deltas.len(),
        file_count: change.tree_deltas.len(),
        change,
        receipt,
        branch,
    }))
}

/// Persist immutable bodies, then atomically publish the complete repository
/// transaction.
///
/// Product commit paths use [`commit_native_plan_with_projection`], which also
/// linearizes the working-tree transition. This bare variant exists so tests
/// can exercise repository authority publication on its own.
#[cfg(test)]
pub(crate) fn commit_native_plan(
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    plan: NativeCommitPlan,
) -> Result<NativeCommitResult> {
    let repository_id = authority_context.repository_id().clone();
    if plan.transaction.repository_id != repository_id {
        return Err(invalid(format!(
            "native plan belongs to {}, not {}",
            plan.transaction.repository_id, repository_id
        )));
    }
    let authority = plan.authority;
    for hash in &plan.source_hashes {
        if let Some(body) = read_publishable_source(blobs, &authority, *hash)?.body_to_publish() {
            authority.save_source_blob(*hash, body)?;
        }
    }
    let receipt = authority.commit_repository_transaction(plan.transaction)?;
    receipt.validate()?;
    Ok(NativeCommitResult {
        change: plan.change,
        receipt,
        branch: plan.branch,
        entity_count: plan.entity_count,
        relation_count: plan.relation_count,
        file_count: plan.file_count,
    })
}

/// Atomically project and publish one native repository transaction.
///
/// Source bodies are copied into repository CAS first, then the exact prior
/// and target trees are loaded back through that immutable authority. The
/// projection recovery journal linearizes the working-tree transition with
/// the repository transaction: a pre-commit failure restores the prior tree,
/// while recovery after a durable authority commit finalizes the target tree.
/// No graph-commit-then-best-effort-projection state is observable.
pub(crate) fn commit_native_plan_with_projection(
    layout: &kin_core::KinLayout,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    plan: NativeCommitPlan,
) -> Result<NativeCommitResult> {
    commit_native_plan_with_working_copy_proof(
        layout,
        blobs,
        authority_context,
        plan,
        WorkingCopyProof::MatchesPreviousTree,
    )
}

/// Publish one native repository transaction that also carries the exact tree
/// transition a completed host walk observed.
///
/// The commit seam derives its target tree from a complete filesystem scan
/// taken moments earlier under the same coordination gate, so the tree
/// transition it carries is a statement about bytes that are already on disk.
/// Saying so here lets one repository-authority successor carry both that tree
/// transition and the semantic change, instead of publishing the tree in its
/// own successor first and paying a second O(store) preparation and snapshot
/// for the change.
///
/// `observed` is that walk's proof, and it is a parameter rather than a flag
/// for the reason [`AdmittedWorkspaceTree`] exists at all: it cannot be
/// constructed without a [`kin_index::CompleteScanToken`], so a collapsed
/// commit cannot be assembled from a partial walk. Standalone publication has
/// required that proof since it was introduced, and folding the tree into this
/// transaction moves where the tree crosses authority without moving what has
/// to be true before it does.
///
/// The proof is checked against the plan rather than merely accompanying it.
/// A token proves some walk completed; it does not say which tree that walk
/// proved, and a plan built against a different pair of trees would publish a
/// transition nobody observed while carrying a genuine token for a different
/// one.
pub(crate) fn commit_native_plan_with_observed_target_tree(
    layout: &kin_core::KinLayout,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    plan: NativeCommitPlan,
    observed: &AdmittedWorkspaceTree,
) -> Result<NativeCommitResult> {
    if observed.previous_tree != plan.previous_tree {
        return Err(invalid(
            "the completed host walk was planned out of a different workspace tree than this \
             commit publishes from; a collapsed commit may not carry a tree transition no walk \
             observed",
        ));
    }
    if observed.desired_tree != plan.target_tree {
        return Err(invalid(
            "the completed host walk observed a different working tree than this commit \
             publishes; a collapsed commit may not carry a tree transition no walk observed",
        ));
    }
    commit_native_plan_with_working_copy_proof(
        layout,
        blobs,
        authority_context,
        plan,
        WorkingCopyProof::ObservedTargetTree,
    )
}

/// What the caller knows about the working copy the transaction publishes over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkingCopyProof {
    /// The working copy still holds the plan's previous tree. A tree
    /// transition is a namespace mutation and is journalled as one.
    MatchesPreviousTree,
    /// A complete scan observed the working copy already holding the plan's
    /// target tree. A tree transition is verified rather than written.
    ObservedTargetTree,
}

fn commit_native_plan_with_working_copy_proof(
    layout: &kin_core::KinLayout,
    blobs: &kin_blobs::BlobStore,
    authority_context: &LocalRepositoryAuthorityContext,
    plan: NativeCommitPlan,
    working_copy: WorkingCopyProof,
) -> Result<NativeCommitResult> {
    let repository_id = authority_context.repository_id().clone();
    if plan.transaction.repository_id != repository_id {
        return Err(invalid(format!(
            "native plan belongs to {}, not {}",
            plan.transaction.repository_id, repository_id
        )));
    }
    // The plan carries the authority it planned against, still open. The phase
    // keeps its name and its place in the table so a reader can compare a trace
    // against an older one; what it now measures is the handoff, and a commit
    // whose plan and publication share one authority reports it as the near-zero
    // span it is. A second open here would decode the whole persisted authority
    // and re-verify every body in repository CAS a second time for one change.
    let authority =
        crate::mcp_commit::timed_commit_phase("open_repository_authority", || plan.authority);
    crate::mcp_commit::timed_commit_phase("stage_changed_source_blobs", || {
        for hash in &plan.source_hashes {
            if let Some(body) = read_publishable_source(blobs, &authority, *hash)?.body_to_publish()
            {
                authority.save_source_blob(*hash, body)?;
            }
        }
        Ok::<(), DaemonError>(())
    })?;

    let mut body_cache = BTreeMap::new();
    let target_entries = crate::mcp_commit::timed_commit_phase("load_projection_entries", || {
        load_projection_entries(&authority, &plan.target_tree, &mut body_cache)
    })?;
    let (projected, receipt) = if plan.previous_tree == plan.target_tree {
        crate::mcp_commit::timed_commit_phase("reconcile_workspace_and_commit_authority", || {
            kin_core::verify_unchanged_source_tree_and_commit_repository_transaction(
                layout.working_dir(),
                &plan.target_tree,
                target_entries
                    .iter()
                    .map(|(path, entry, body)| (path, *entry, body.as_ref())),
                &authority,
                plan.transaction,
            )
        })?
    } else {
        let previous_entries =
            crate::mcp_commit::timed_commit_phase("load_previous_projection_entries", || {
                load_projection_entries(&authority, &plan.previous_tree, &mut body_cache)
            })?;
        match working_copy {
            WorkingCopyProof::ObservedTargetTree => crate::mcp_commit::timed_commit_phase(
                "reconcile_workspace_and_commit_authority",
                || {
                    kin_core::verify_observed_target_tree_and_commit_repository_transaction(
                        layout.working_dir(),
                        &plan.previous_tree,
                        &plan.target_tree,
                        previous_entries
                            .iter()
                            .map(|(path, entry, body)| (path, *entry, body.as_ref())),
                        target_entries
                            .iter()
                            .map(|(path, entry, body)| (path, *entry, body.as_ref())),
                        &authority,
                        plan.transaction,
                    )
                },
            )?,
            WorkingCopyProof::MatchesPreviousTree => crate::mcp_commit::timed_commit_phase(
                "reconcile_workspace_and_commit_authority",
                || {
                    kin_core::reconcile_source_tree_and_commit_repository_transaction(
                        layout.working_dir(),
                        &plan.previous_tree,
                        &plan.target_tree,
                        previous_entries
                            .iter()
                            .map(|(path, entry, body)| (path, *entry, body.as_ref())),
                        target_entries
                            .iter()
                            .map(|(path, entry, body)| (path, *entry, body.as_ref())),
                        &authority,
                        plan.transaction,
                    )
                },
            )?,
        }
    };
    let materializable = materializable_artifact_count(&plan.target_tree)?;
    if projected != materializable {
        return Err(invalid(format!(
            "exact projection verified {projected} source artifacts but target authority contains \
             {materializable} materializable artifacts"
        )));
    }
    receipt.validate()?;
    Ok(NativeCommitResult {
        change: plan.change,
        receipt,
        branch: plan.branch,
        entity_count: plan.entity_count,
        relation_count: plan.relation_count,
        file_count: plan.file_count,
    })
}

fn load_projection_entries(
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    tree: &kin_model::ResolvedTree,
    body_cache: &mut BTreeMap<Hash256, Arc<[u8]>>,
) -> Result<Vec<ProjectionEntry>> {
    let mut entries = Vec::with_capacity(materializable_artifact_count(tree)?);
    for artifact in tree.artifacts_by_path() {
        if kin_core::source_projection_disposition(&artifact.path, artifact.entry)?
            != kin_core::SourceProjectionDisposition::Materialized
        {
            continue;
        }
        let hash = artifact.entry.blob_identity().ok_or_else(|| {
            invalid(format!(
                "materializable repository entry {} has no source identity",
                artifact.path
            ))
        })?;
        let body = if let Some(body) = body_cache.get(&hash) {
            Arc::clone(body)
        } else {
            let body: Arc<[u8]> = authority
                .load_source_blob(hash)?
                .ok_or_else(|| {
                    invalid(format!(
                        "repository source CAS is missing {} for {}",
                        hash, artifact.path
                    ))
                })?
                .into();
            body_cache.insert(hash, Arc::clone(&body));
            body
        };
        entries.push((artifact.path.clone(), artifact.entry, body));
    }
    Ok(entries)
}

fn materializable_artifact_count(tree: &kin_model::ResolvedTree) -> Result<usize> {
    let mut count = 0;
    for artifact in tree.artifacts_by_path() {
        if kin_core::source_projection_disposition(&artifact.path, artifact.entry)?
            == kin_core::SourceProjectionDisposition::Materialized
        {
            count += 1;
        }
    }
    Ok(count)
}

fn resolve_symbolic_commit_base(
    metadata: &kin_db::PersistedRepositoryAuthority,
    head: &WorkspaceHead,
    workspace_base: Option<&RefTarget>,
) -> Result<(RefName, Option<RefTarget>, Option<SemanticChangeId>)> {
    let WorkspaceHead::Symbolic { target: branch } = head else {
        return Err(invalid(
            "native repository commit requires a symbolic workspace HEAD",
        ));
    };
    let current = metadata
        .ref_state
        .refs
        .iter()
        .find(|repository_ref| repository_ref.name == *branch)
        .map(|repository_ref| repository_ref.target.clone());
    if current.as_ref() != workspace_base {
        return Err(invalid(format!(
            "workspace base does not match current symbolic ref {branch}; refresh or rebase before commit"
        )));
    }
    let parent = match current.as_ref() {
        None => None,
        Some(RefTarget::Change { change_id }) => Some(*change_id),
        Some(RefTarget::ExternalObject { object }) => Some(
            metadata
                .aliases
                .iter()
                .find(|alias| alias.oid == object.oid)
                .map(|alias| alias.change_id)
                .ok_or_else(|| {
                    invalid(format!(
                        "workspace base external commit {} has no semantic alias",
                        object.oid
                    ))
                })?,
        ),
        Some(RefTarget::Symbolic { target }) => {
            return Err(invalid(format!(
                "native commit does not yet mutate symbolic ref chain {branch} -> {target}"
            )));
        }
    };
    Ok((branch.clone(), current, parent))
}

fn invalid(message: impl Into<String>) -> DaemonError {
    ModelError::InvalidOperation(message.into()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        ArtifactId, EntityStore, LocatedEntry, RepoPath, RepositoryAuthorityStore,
        ResolvedArtifact, ResolvedTree, TransactionDelta, TreeDelta, TreeEntry,
    };

    fn add_artifact(
        graph: &kin_db::InMemoryGraph,
        blobs: &kin_blobs::BlobStore,
        path: &[u8],
        bytes: &[u8],
        entry: impl FnOnce(Hash256) -> TreeEntry,
    ) -> ResolvedArtifact {
        let digest = blobs.write(bytes).unwrap();
        let artifact = ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_bytes(path.to_vec()).unwrap(),
            entry(Hash256::from_bytes(digest.0)),
        );
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: artifact.artifact_id,
                    new: LocatedEntry::new(artifact.path.clone(), artifact.entry),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();
        artifact
    }

    fn fixed_timestamp() -> Timestamp {
        Timestamp::from(
            chrono::DateTime::parse_from_rfc3339("2026-07-26T12:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
    }

    fn reopen(init: &kin_core::InitResult) -> RepositoryAuthorityManager<LocalFileBackend> {
        RepositoryAuthorityManager::open(
            init.repository_id.clone(),
            Arc::new(LocalFileBackend::new(init.layout.kindb_dir())),
        )
        .unwrap()
    }

    fn test_authority_context(layout: &kin_core::KinLayout) -> LocalRepositoryAuthorityContext {
        LocalRepositoryAuthorityContext::from_layout_for_test(layout).unwrap()
    }

    fn publish_workspace_tree(
        layout: &kin_core::KinLayout,
        blobs: &kin_blobs::BlobStore,
        desired_tree: &ResolvedTree,
        operation_id: OperationId,
        actor: AuthorId,
    ) -> Result<Option<WorkspaceAdmissionResult>> {
        let context = test_authority_context(layout);
        let authority = context.open()?;
        let lease = authority.read_authority();
        let expected_roots = lease.roots().clone();
        let previous_tree = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == context.workspace_id())
            .map(|workspace| workspace.tree.clone())
            .unwrap_or_default();
        drop(lease);
        let admitted = super::admitted_workspace_tree_for_test(
            layout.working_dir(),
            expected_roots,
            previous_tree,
            desired_tree.clone(),
        );
        super::publish_workspace_tree(blobs, &context, &admitted, operation_id, actor)
    }

    #[allow(clippy::too_many_arguments)]
    fn plan_native_commit(
        layout: &kin_core::KinLayout,
        graph: &kin_db::InMemoryGraph,
        blobs: &kin_blobs::BlobStore,
        operation_id: OperationId,
        timestamp: Timestamp,
        author: AuthorId,
        message: String,
    ) -> Result<NativeCommitPlan> {
        super::plan_native_commit(
            graph,
            blobs,
            &test_authority_context(layout),
            operation_id,
            timestamp,
            author,
            message,
        )
    }

    fn commit_native_plan(
        layout: &kin_core::KinLayout,
        blobs: &kin_blobs::BlobStore,
        plan: NativeCommitPlan,
    ) -> Result<NativeCommitResult> {
        super::commit_native_plan(blobs, &test_authority_context(layout), plan)
    }

    fn commit_native_plan_with_projection(
        layout: &kin_core::KinLayout,
        blobs: &kin_blobs::BlobStore,
        plan: NativeCommitPlan,
    ) -> Result<NativeCommitResult> {
        super::commit_native_plan_with_projection(
            layout,
            blobs,
            &test_authority_context(layout),
            plan,
        )
    }

    /// One commit opens the repository authority exactly once.
    ///
    /// An open is O(store) rather than a cheap handle: kin-db decodes the whole
    /// persisted authority and then re-verifies every body in repository CAS
    /// against its content address, unconditionally, on every one. A commit that
    /// planned against one open authority and then published through a second
    /// paid that whole cost twice to record one change, so the plan carries the
    /// authority it planned against and the publication consumes it.
    ///
    /// The count is the invariant, not the timing. A publication that opens its
    /// own authority again fails the second assertion here whatever the store
    /// costs to open, including on a fixture small enough for the duplicate to
    /// be invisible in wall time.
    #[test]
    fn one_commit_opens_the_repository_authority_once() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        add_artifact(
            &graph,
            &blobs,
            b"api.py",
            b"def get():\n    pass\n",
            |hash| TreeEntry::blob(hash, false),
        );

        crate::local_repository_authority::reset_authority_open_count();
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("commitwall"),
            "publish one artifact".to_string(),
        )
        .unwrap();
        assert_eq!(
            crate::local_repository_authority::authority_open_count(),
            1,
            "planning must open the repository authority exactly once"
        );

        commit_native_plan_with_projection(&init.layout, &blobs, plan).unwrap();
        assert_eq!(
            crate::local_repository_authority::authority_open_count(),
            1,
            "the publication opened a second repository authority instead of consuming the \
             one the plan carries; every open decodes the whole persisted authority and \
             re-verifies every body in repository CAS, so this commit paid that twice"
        );
    }

    /// A desired tree describes one transition out of one observed prior tree.
    /// Once authority has moved past that prior tree, re-deriving the same
    /// desired tree against the newer workspace would publish a transition
    /// nobody observed and silently revert whatever moved authority. The stale
    /// admission must be refused instead.
    #[test]
    fn stale_desired_tree_is_refused_against_newer_authority() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();

        let observed = add_artifact(&graph, &blobs, b"observed.txt", b"observed\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        let concurrent = add_artifact(
            &graph,
            &blobs,
            b"concurrent.txt",
            b"published by someone else\n",
            |hash| TreeEntry::blob(hash, false),
        );

        let context = test_authority_context(&init.layout);
        let roots_at_observation = context.open().unwrap().read_authority().roots().clone();
        let previous_tree = ResolvedTree::default();

        // The observation is planned against the empty workspace tree.
        let stale = super::admitted_workspace_tree_for_test(
            init.layout.working_dir(),
            roots_at_observation.clone(),
            previous_tree.clone(),
            ResolvedTree::from_artifacts([observed]).unwrap(),
        );

        // Authority moves before the stale admission reaches publication.
        publish_workspace_tree(
            &init.layout,
            &blobs,
            &ResolvedTree::from_artifacts([concurrent.clone()]).unwrap(),
            OperationId::new(),
            AuthorId::new("concurrent-writer"),
        )
        .unwrap()
        .expect("the concurrent transition must advance authority");

        let roots_after_concurrent = context.open().unwrap().read_authority().roots().clone();
        assert_ne!(roots_at_observation, roots_after_concurrent);

        let error = super::publish_workspace_tree(
            &blobs,
            &context,
            &stale,
            OperationId::new(),
            AuthorId::new("stale-observer"),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not replan a stale desired tree against newer authority"),
            "{error}"
        );

        let lease = context.open().unwrap().read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap()
            .clone();
        drop(lease);
        assert_eq!(
            workspace.tree,
            ResolvedTree::from_artifacts([concurrent]).unwrap(),
            "the refused stale admission must not revert the concurrent transition"
        );
        assert!(workspace
            .tree
            .artifact_at_path(&kin_model::RepoPath::from_utf8("observed.txt").unwrap())
            .is_none());
    }

    /// The same refusal applies when authority did not move but the plan was
    /// taken against a tree that was never this workspace's authority tree.
    #[test]
    fn desired_tree_planned_against_a_foreign_prior_tree_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let invented = add_artifact(
            &graph,
            &blobs,
            b"invented.txt",
            b"never admitted\n",
            |hash| TreeEntry::blob(hash, false),
        );
        let desired = add_artifact(&graph, &blobs, b"desired.txt", b"desired\n", |hash| {
            TreeEntry::blob(hash, false)
        });

        let context = test_authority_context(&init.layout);
        let roots = context.open().unwrap().read_authority().roots().clone();
        let admitted = super::admitted_workspace_tree_for_test(
            init.layout.working_dir(),
            roots,
            ResolvedTree::from_artifacts([invented]).unwrap(),
            ResolvedTree::from_artifacts([desired]).unwrap(),
        );

        let error = super::publish_workspace_tree(
            &blobs,
            &context,
            &admitted,
            OperationId::new(),
            AuthorId::new("foreign-base-observer"),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not replan a stale desired tree against newer authority"),
            "{error}"
        );
    }

    #[test]
    fn workspace_admission_persists_dirty_exact_tree_without_history_or_ref_move() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let compose = add_artifact(
            &graph,
            &blobs,
            b"compose.yaml",
            b"services:\n  app:\n    image: kin:test\n",
            |hash| TreeEntry::blob(hash, false),
        );
        let opaque = add_artifact(
            &graph,
            &blobs,
            b"assets/model.bin",
            &[0, 0xff, 0x41, 0x00],
            |hash| TreeEntry::blob(hash, false),
        );
        let symlink = add_artifact(
            &graph,
            &blobs,
            b"current-compose",
            b"compose.yaml",
            TreeEntry::symlink,
        );
        let desired = ResolvedTree::from_artifacts([compose, opaque, symlink]).unwrap();

        let initial_authority = reopen(&init);
        let initial_lease = initial_authority.read_authority();
        let initial_workspace = initial_lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap()
            .clone();
        let initial_refs = initial_lease.metadata().ref_state.clone();
        drop(initial_lease);

        let result = publish_workspace_tree(
            &init.layout,
            &blobs,
            &desired,
            OperationId::new(),
            AuthorId::new("dogfood"),
        )
        .unwrap()
        .expect("dirty exact tree must advance workspace authority");
        assert_eq!(result.receipt.generation, 2);
        assert_eq!(result.workspace_id, init.workspace_id);
        assert_eq!(result.file_count, 3);
        assert_eq!(
            result.tree_hash,
            compute_resolved_tree_hash(&desired).unwrap()
        );

        let authority = reopen(&init);
        let lease = authority.read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap();
        assert_eq!(workspace.tree, desired);
        assert_eq!(workspace.head, initial_workspace.head);
        assert_eq!(workspace.base_target, initial_workspace.base_target);
        assert_eq!(workspace.base_tree_hash, initial_workspace.base_tree_hash);
        assert!(workspace.is_dirty());
        assert_eq!(lease.metadata().ref_state, initial_refs);
        assert!(lease.snapshot().changes.is_empty());
        for artifact in desired.artifacts() {
            if let Some(hash) = artifact.entry.blob_identity() {
                assert_eq!(
                    authority.load_source_blob(hash).unwrap().as_deref(),
                    Some(blobs.read(&hash).unwrap().as_slice())
                );
            }
        }
        drop(lease);

        assert!(publish_workspace_tree(
            &init.layout,
            &blobs,
            &desired,
            OperationId::new(),
            AuthorId::new("dogfood"),
        )
        .unwrap()
        .is_none());
        assert_eq!(reopen(&init).read_authority().roots().generation, 2);
    }

    /// Publication must not depend on ingestion staging still holding a body the
    /// repository already owns.
    ///
    /// Every `.gitignore` and `.kinignore` blob in the desired tree is measured
    /// on every publication, because the shared admission policy is derived from
    /// the whole tree and not from what changed. Bounding one tick to what moved
    /// removed the per-scan rewrite that used to restage every leaf ahead of
    /// every publication, so that read now has to reach the store that actually
    /// promises the body. Staging is not authority and keeps no retention
    /// promise; a store that loses it while its authority survives must still
    /// publish, instead of failing every admission until someone happens to edit
    /// a rule file.
    #[test]
    fn an_unchanged_rule_source_publishes_after_ingestion_staging_is_lost() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();

        let rules = add_artifact(&graph, &blobs, b".gitignore", b"target/\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        let first = add_artifact(
            &graph,
            &blobs,
            b"first.rs",
            b"pub fn first() {}\n",
            |hash| TreeEntry::blob(hash, false),
        );
        publish_workspace_tree(
            &init.layout,
            &blobs,
            &ResolvedTree::from_artifacts([rules.clone(), first.clone()]).unwrap(),
            OperationId::new(),
            AuthorId::new("fir2152"),
        )
        .unwrap()
        .expect("the first transition must advance workspace authority");

        // Lose the staging directory the way a restore that carries the
        // authority database but not a directory named like a cache does.
        let rules_hash = rules.entry.blob_identity().unwrap();
        std::fs::remove_dir_all(init.layout.ingest_cas_dir()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        assert!(
            blobs.read(&rules_hash).is_err(),
            "the fixture only proves anything while the staged rule body is genuinely gone"
        );

        let second = add_artifact(
            &graph,
            &blobs,
            b"second.rs",
            b"pub fn second() {}\n",
            |hash| TreeEntry::blob(hash, false),
        );
        let desired = ResolvedTree::from_artifacts([rules.clone(), first, second]).unwrap();
        let result = publish_workspace_tree(
            &init.layout,
            &blobs,
            &desired,
            OperationId::new(),
            AuthorId::new("fir2152"),
        )
        .unwrap()
        .expect("a transition that leaves the rule file untouched must still advance authority");
        assert_eq!(result.receipt.generation, 3);

        let authority = reopen(&init);
        let lease = authority.read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap();
        assert_eq!(workspace.tree, desired);
        assert_eq!(
            workspace
                .shared_admission_policy
                .sources
                .iter()
                .map(|source| source.path.clone())
                .collect::<Vec<_>>(),
            vec![rules.path.clone()],
            "the derived policy still names the rule file whose body only authority holds"
        );
    }

    /// Publish a rule file and one source, lose the whole staging directory,
    /// then publish a second source through `publish`.
    ///
    /// The second transition has to read one body from each store: the new
    /// file's is staged, and the untouched `.gitignore` the policy still
    /// measures is only in repository CAS.
    fn publish_across_a_lost_staging_directory(
        publish: fn(
            &kin_core::KinLayout,
            &kin_blobs::BlobStore,
            NativeCommitPlan,
        ) -> Result<NativeCommitResult>,
    ) -> (tempfile::TempDir, kin_core::InitResult) {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();

        let rules = add_artifact(&graph, &blobs, b".gitignore", b"target/\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        add_artifact(
            &graph,
            &blobs,
            b"first.rs",
            b"pub fn first() {}\n",
            |hash| TreeEntry::blob(hash, false),
        );
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("fir2171"),
            "publish the rule file and one source".to_string(),
        )
        .unwrap();
        publish(&init.layout, &blobs, plan).unwrap();

        // Lose the staging directory the way a restore that carries the
        // authority database but not a directory named like a cache does.
        let rules_hash = rules.entry.blob_identity().unwrap();
        std::fs::remove_dir_all(init.layout.ingest_cas_dir()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        assert!(
            blobs
                .read(&kin_blobs::Hash256::from_bytes(*rules_hash.as_bytes()))
                .is_err(),
            "the fixture only proves anything while the staged rule body is genuinely gone"
        );

        add_artifact(
            &graph,
            &blobs,
            b"second.rs",
            b"pub fn second() {}\n",
            |hash| TreeEntry::blob(hash, false),
        );
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("fir2171"),
            "publish a change that leaves the rule file untouched".to_string(),
        )
        .unwrap();
        let result = publish(&init.layout, &blobs, plan).unwrap();
        assert_eq!(result.receipt.generation, 3);

        let authority = reopen(&init);
        assert_eq!(
            authority.load_source_blob(rules_hash).unwrap().as_deref(),
            Some(b"target/\n".as_slice()),
            "the rule body the commit measured is the one authority already held"
        );
        (root, init)
    }

    /// The same loss on the native commit path, which reads unchanged bodies
    /// twice: once to measure every rule file while deriving the policy, and
    /// once to copy every source the change references into repository CAS.
    /// Neither read is bounded to what moved, so an untouched `.gitignore` is
    /// consulted by every commit forever, and before this both reads went to
    /// ingestion staging alone.
    #[test]
    fn a_native_commit_publishes_after_ingestion_staging_is_lost() {
        let (root, _init) =
            publish_across_a_lost_staging_directory(commit_native_plan_with_projection);
        assert_eq!(
            std::fs::read(root.path().join("second.rs")).unwrap(),
            b"pub fn second() {}\n",
            "the projecting path still materializes what it published"
        );
    }

    /// The bare publication path carries its own copy loop, and tests reach
    /// authority through it. A test helper that reads one store where product
    /// code reads two would pass while the thing it stands in for fails.
    #[test]
    fn a_bare_native_publication_publishes_after_ingestion_staging_is_lost() {
        let (root, _init) = publish_across_a_lost_staging_directory(commit_native_plan);
        assert!(
            !root.path().join("second.rs").exists(),
            "publication without projection is what distinguishes this path from the other"
        );
    }

    /// The control that keeps the fallback from swallowing a real loss. A body
    /// no store holds is not an unchanged body that authority already owns, and
    /// a publication that cannot find one must still refuse, as the typed blob
    /// absence rather than as a sentence.
    #[test]
    fn a_native_commit_still_refuses_a_body_neither_store_holds() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();

        add_artifact(&graph, &blobs, b".gitignore", b"target/\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("fir2171"),
            "publish the rule file".to_string(),
        )
        .unwrap();
        commit_native_plan(&init.layout, &blobs, plan).unwrap();

        // Staged and never published, then lost: the one body that is genuinely
        // gone rather than merely unstaged.
        add_artifact(
            &graph,
            &blobs,
            b"orphan.rs",
            b"pub fn orphan() {}\n",
            |hash| TreeEntry::blob(hash, false),
        );
        std::fs::remove_dir_all(init.layout.ingest_cas_dir()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();

        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("fir2171"),
            "publish a body no store holds".to_string(),
        )
        .expect("the rule file authority still owns lets planning get as far as publication");
        let error = commit_native_plan(&init.layout, &blobs, plan)
            .expect_err("a body neither store holds cannot be published");
        assert!(
            matches!(error, DaemonError::Blob(_)),
            "absence stays the typed blob failure a caller can match on: {error}"
        );
    }

    #[test]
    fn workspace_admission_cannot_invent_unverified_gitlink_authority() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let desired = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8("vendor/semantic-engine").unwrap(),
            TreeEntry::gitlink(kin_model::GitObjectId::sha1([0x73; 20])),
        )])
        .unwrap();

        let error = publish_workspace_tree(
            &init.layout,
            &blobs,
            &desired,
            OperationId::new(),
            AuthorId::new("dogfood"),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("without verified Git external authority"),
            "unexpected external-authority rejection: {error}"
        );
        let authority = reopen(&init);
        let lease = authority.read_authority();
        assert_eq!(lease.roots().generation, 1);
        assert!(lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap()
            .tree
            .is_empty());
    }

    #[test]
    fn workspace_admission_missing_body_cannot_advance_authority() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let desired = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8("compose.yaml").unwrap(),
            TreeEntry::blob(Hash256::from_bytes([0xee; 32]), false),
        )])
        .unwrap();

        let error = publish_workspace_tree(
            &init.layout,
            &blobs,
            &desired,
            OperationId::new(),
            AuthorId::new("dogfood"),
        )
        .unwrap_err();
        assert!(
            matches!(
                &error,
                DaemonError::Blob(kin_blobs::BlobError::NotFound { .. })
            ),
            "missing admitted body must surface the typed blob absence, got {error:?}"
        );
        let authority = reopen(&init);
        let lease = authority.read_authority();
        assert_eq!(lease.roots().generation, 1);
        assert!(lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap()
            .tree
            .is_empty());
    }

    #[test]
    fn native_commit_atomically_projects_exact_non_code_tree_and_ref() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let compose = add_artifact(
            &graph,
            &blobs,
            b"compose.yaml",
            b"services:\n  app:\n    image: kin:test\n",
            |hash| TreeEntry::blob(hash, false),
        );
        let dockerfile = add_artifact(&graph, &blobs, b"Dockerfile", b"FROM scratch\n", |hash| {
            TreeEntry::blob(hash, true)
        });
        let opaque = add_artifact(
            &graph,
            &blobs,
            b"assets/model.bin",
            &[0, 0xff, 0x41, 0x00],
            |hash| TreeEntry::blob(hash, false),
        );
        let symlink = add_artifact(
            &graph,
            &blobs,
            b"current-compose",
            b"compose.yaml",
            TreeEntry::symlink,
        );

        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("dogfood"),
            "commit exact repository artifacts".to_string(),
        )
        .unwrap();
        assert_eq!(plan.file_count, 4);
        let result = commit_native_plan_with_projection(&init.layout, &blobs, plan).unwrap();
        assert_eq!(result.receipt.generation, 2);
        assert_eq!(
            std::fs::read(root.path().join("compose.yaml")).unwrap(),
            b"services:\n  app:\n    image: kin:test\n"
        );
        assert_eq!(
            std::fs::read(root.path().join("Dockerfile")).unwrap(),
            b"FROM scratch\n"
        );
        assert_eq!(
            std::fs::read(root.path().join("assets/model.bin")).unwrap(),
            [0, 0xff, 0x41, 0x00]
        );
        assert_eq!(
            std::fs::read_link(root.path().join("current-compose")).unwrap(),
            std::path::PathBuf::from("compose.yaml")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_ne!(
                std::fs::metadata(root.path().join("Dockerfile"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
        }

        let authority = reopen(&init);
        let lease = authority.read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap();
        let expected =
            ResolvedTree::from_artifacts([compose, dockerfile, opaque, symlink]).unwrap();
        assert_eq!(workspace.tree, expected);
        assert_eq!(
            workspace.base_target,
            Some(RefTarget::change(result.change.id))
        );
        assert_eq!(
            authority
                .get_repository_ref(&init.repository_id, &result.branch)
                .unwrap()
                .unwrap()
                .target,
            RefTarget::change(result.change.id)
        );
        for artifact in expected.artifacts() {
            if let Some(hash) = artifact.entry.blob_identity() {
                assert!(authority.load_source_blob(hash).unwrap().is_some());
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_commit_preserves_host_unrepresentable_byte_exact_path() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let raw_path = b"assets/icon-\xff.bin";
        let body = b"\0opaque non-code bytes\xff";
        let artifact = add_artifact(&graph, &blobs, raw_path, body, |hash| {
            TreeEntry::blob(hash, false)
        });
        let desired = ResolvedTree::from_artifacts([artifact]).unwrap();

        publish_workspace_tree(
            &init.layout,
            &blobs,
            &desired,
            OperationId::new(),
            AuthorId::new("admission"),
        )
        .unwrap()
        .expect("raw path must enter workspace authority before commit");
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("dogfood"),
            "commit byte-exact unsupported artifact".to_string(),
        )
        .unwrap();
        let result = commit_native_plan_with_projection(&init.layout, &blobs, plan).unwrap();

        assert_eq!(result.receipt.generation, 3);
        assert!(
            !root.path().join("assets").exists(),
            "host-unrepresentable repository path must remain graph-only"
        );
        let authority = reopen(&init);
        let lease = authority.read_authority();
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap();
        assert_eq!(workspace.tree, desired);
        let raw = workspace
            .tree
            .artifact_at_path(&RepoPath::from_bytes(raw_path.to_vec()).unwrap())
            .unwrap();
        let digest = raw.entry.blob_identity().unwrap();
        assert_eq!(
            authority.load_source_blob(digest).unwrap().as_deref(),
            Some(body.as_slice())
        );
        assert_eq!(
            authority
                .get_repository_ref(&init.repository_id, &result.branch)
                .unwrap()
                .unwrap()
                .target,
            RefTarget::change(result.change.id)
        );
    }

    #[test]
    fn stale_plan_cannot_split_change_workspace_and_ref_authority() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        add_artifact(&graph, &blobs, b"compose.yaml", b"services: {}\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        let winner = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("winner"),
            "winner".to_string(),
        )
        .unwrap();
        let winner_id = winner.change.id;
        let stale = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("stale"),
            "stale".to_string(),
        )
        .unwrap();
        commit_native_plan(&init.layout, &blobs, winner).unwrap();
        // The refusal comes from the durable compare-and-swap. A plan carries
        // the authority it planned against, so publishing a stale plan no
        // longer re-reads authority first and cannot notice the move before
        // preparing its successor; kin-db refuses the write itself because the
        // persisted base generation is not the one the successor was built on.
        // The refusal is what matters and it is unconditional: the successor
        // exists only in memory, and nothing durable moved, which the state
        // assertions below check rather than assume.
        let error = commit_native_plan(&init.layout, &blobs, stale).unwrap_err();
        let refusal = error.to_string();
        assert!(
            refusal.contains("generation mismatch") && refusal.contains("another writer committed"),
            "a stale plan must be refused naming the generation conflict, got: {refusal}"
        );

        let authority = reopen(&init);
        let lease = authority.read_authority();
        assert_eq!(lease.roots().generation, 2);
        let default_ref = lease.metadata().ref_state.default_ref.as_ref().unwrap();
        assert_eq!(
            authority
                .get_repository_ref(&init.repository_id, default_ref)
                .unwrap()
                .unwrap()
                .target,
            RefTarget::change(winner_id)
        );
        assert_eq!(lease.snapshot().changes.len(), 1);
    }

    /// An exclusion rule takes effect from the generation AFTER the one that
    /// publishes it, so the transaction introducing a rule is judged by the
    /// policy already in force rather than by the one it is about to install.
    /// The contract is stated on kin-db's `judging_shared_policy`; this is its
    /// kin-side half, and it is deliberately the inverse of what this test
    /// asserted before kin-db 0.7.30. Judging a transaction by its own new rule
    /// livelocked: the rule file could never land, because landing it required
    /// admitting content the unlanded rule already excluded, and every retry
    /// failed identically.
    #[test]
    fn a_rule_and_the_content_it_will_exclude_land_together_then_the_rule_bites() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        add_artifact(&graph, &blobs, b".gitignore", b"*.secret\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        add_artifact(&graph, &blobs, b"one.secret", b"not admitted\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("dogfood"),
            "publish the rule beside the content it will exclude".to_string(),
        )
        .unwrap();
        commit_native_plan(&init.layout, &blobs, plan).unwrap();

        let authority = reopen(&init);
        let lease = authority.read_authority();
        assert_eq!(lease.roots().generation, 2);
        assert_eq!(lease.snapshot().changes.len(), 1);
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == init.workspace_id)
            .unwrap();
        assert_eq!(workspace.tree.len(), 2);
        drop(lease);
        drop(authority);

        // The rule is in force from here, so the next new path under it is
        // refused, and refused without moving authority.
        add_artifact(&graph, &blobs, b"two.secret", b"also secret\n", |hash| {
            TreeEntry::blob(hash, false)
        });
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("dogfood"),
            "must fail admission under the rule now in force".to_string(),
        )
        .unwrap();
        let error = commit_native_plan(&init.layout, &blobs, plan).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("excluded by the exact graph-owned admission policy"),
            "unexpected error: {error}"
        );

        let authority = reopen(&init);
        let lease = authority.read_authority();
        assert_eq!(lease.roots().generation, 2);
        assert_eq!(lease.snapshot().changes.len(), 1);
    }

    #[test]
    fn missing_graph_blob_fails_before_repository_authority_moves() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let artifact = ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8("compose.yaml").unwrap(),
            TreeEntry::blob(Hash256::from_bytes([0xee; 32]), false),
        );
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: artifact.artifact_id,
                    new: LocatedEntry::new(artifact.path, artifact.entry),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();
        let plan = plan_native_commit(
            &init.layout,
            &graph,
            &blobs,
            OperationId::new(),
            fixed_timestamp(),
            AuthorId::new("dogfood"),
            "missing body".to_string(),
        )
        .unwrap();
        let error = commit_native_plan(&init.layout, &blobs, plan).unwrap_err();
        assert!(
            matches!(
                &error,
                DaemonError::Blob(kin_blobs::BlobError::NotFound { .. })
            ),
            "missing graph body must surface the typed blob absence, got {error:?}"
        );
        assert_eq!(reopen(&init).read_authority().roots().generation, 1);
    }
}
