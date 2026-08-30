// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon-owned repository-v6 semantic merge authority.
//!
//! A merge is a three-way composition over graph truth, never a file-level
//! text merge. Both heads and their merge base are materialized by replaying
//! the change DAG; entities, relations, and exact tree artifacts are composed
//! by stable identity; and the result is published as one merge change whose
//! deltas are authored against its first parent, which is the branch being
//! merged into. Nothing is read from the working copy to decide the merge.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use axum::http::StatusCode;
use kin_cli::commands::merge::{
    MergeOutcome, MergeReport, MergeRequest, MergeResponse, MERGE_REPORT_SCHEMA,
};
use kin_db::{LocalFileBackend, LocalRepositoryAuthorityFreeze, RepositoryAuthorityManager};
use kin_model::{
    compute_resolved_tree_hash, compute_semantic_change_id, ChangeOrigin, ChangeStore,
    EffectiveAdmissionPolicyStamp, EntityStore, Hash256, MergeConflictEntry, MergeConflictSubject,
    MergeDivergence, MergeEntryResolution, MergeOpening, MergeParentBinding,
    MergeResolutionPayload, MergeSide, MergeSideValue, MergeTransactionDelta,
    MergeTransactionRecord, MergeTransactionState, MergeWorkspaceRestorePoint, ModelError,
    RefExpectation, RefMutation, RefName, RefTarget, RefUpdatePolicy, RepositoryCommitOutcome,
    RepositoryCommitReceipt, RepositoryTransaction, ResolvedArtifact, ResolvedTree, RootBundle,
    SemanticChange, SemanticChangeId, SharedAdmissionPolicy, Timestamp, TransactionDelta,
    WorkspaceExpectation, WorkspaceHead, WorkspaceMutation, WorkspaceSemanticDelta, WorkspaceState,
    REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};

use crate::local_repository_authority::{
    require_fresh_daemon_workspace, ActiveLocalRepositoryAuthority, RepositoryAuthorityBindRefusal,
};
use crate::source_cas::read_publishable_source;
use crate::state::{DaemonEvent, DaemonState};

const MERGE_REASON: &str = "publish exact repository-v6 semantic merge";
const FAST_FORWARD_REASON: &str = "advance exact repository-v6 branch to a descendant";
const OPEN_MERGE_REASON: &str = "open a durable repository-v6 merge transaction";

/// How many conflicts a refusal names individually before summarizing. The
/// total is always stated, so the message never reads as a complete list when
/// it is truncated.
const RENDERED_CONFLICT_LIMIT: usize = 25;

pub(crate) struct MergeExecution {
    response: MergeResponse,
    /// Present only when the merge was published by `kin resolve --continue`,
    /// whose caller answers on the resolve wire rather than the merge one.
    pub(crate) resolve_response: Option<kin_cli::commands::resolve::ResolveResponse>,
    pub(crate) receipt: RepositoryCommitReceipt,
    pub(crate) authority_freeze: LocalRepositoryAuthorityFreeze,
    pub(crate) daemon_delta: TransactionDelta,
    pub(crate) previous_tree: ResolvedTree,
    pub(crate) desired_tree: ResolvedTree,
}

enum MergeCommandOutcome {
    Commit(Box<MergeExecution>),
    ReadOnly(MergeResponse),
}

#[derive(Debug)]
struct MergeConflictRefusal(String);

impl std::fmt::Display for MergeConflictRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for MergeConflictRefusal {}

#[derive(Debug)]
struct MergeBadRequest(String);

impl std::fmt::Display for MergeBadRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for MergeBadRequest {}

pub(crate) fn merge_conflict(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(MergeConflictRefusal(message.into()))
}

pub(crate) fn merge_bad_request(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(MergeBadRequest(message.into()))
}

pub(crate) fn execute(
    state: &DaemonState,
    request: &MergeRequest,
) -> std::result::Result<MergeResponse, (StatusCode, String)> {
    let graph_mutation = state.begin_graph_authority_mutation();
    let persistence = state.persist_lock.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "daemon persistence lock poisoned".to_string(),
        )
    })?;
    let previous_graph_root = hex::encode(state.graph.compute_root_hash());
    let authority =
        ActiveLocalRepositoryAuthority::open_bound(state).map_err(merge_bind_refusal)?;
    let outcome = plan_and_publish(state, &authority, request).map_err(classify_merge_error)?;
    let execution = match outcome {
        MergeCommandOutcome::Commit(execution) => execution,
        MergeCommandOutcome::ReadOnly(response) => {
            drop(persistence);
            drop(graph_mutation);
            return Ok(response);
        }
    };

    let finalization = state
        .finalize_local_repository_commit(
            &execution.receipt,
            &execution.authority_freeze,
            &execution.daemon_delta,
            &execution.previous_tree,
            &execution.desired_tree,
        )
        .map_err(repository_finalization_error)?;
    if finalization.graph_changed {
        let current_graph_root = hex::encode(state.graph.compute_root_hash());
        state.bump_version();
        state.emit_event(DaemonEvent::GraphRootChanged {
            old_root_hash: Some(previous_graph_root),
            new_root_hash: current_graph_root,
        });
    } else if finalization.generation_advanced {
        state.mark_dirty();
    }
    if finalization.generation_advanced {
        state.emit_event(DaemonEvent::RepositoryAuthorityChanged {
            repository_id: execution.receipt.repository_id.to_string(),
            operation_id: execution.receipt.operation_id,
            previous_generation: execution.receipt.roots_before.generation,
            new_generation: execution.receipt.generation,
        });
    }
    if !finalization.graph_changed {
        state.invalidate_projection();
    }

    drop(persistence);
    drop(graph_mutation);
    Ok(execution.response)
}

/// Everything the merge decided from one authority lease, carried past the
/// point the lease is released so nothing is re-read against newer authority.
struct MergePlan {
    roots: RootBundle,
    workspace: WorkspaceState,
    target_ref: RefName,
    ours_target: RefTarget,
    ours_change: SemanticChangeId,
    theirs_target: RefTarget,
    theirs_change: SemanticChangeId,
    ours_policy: SharedAdmissionPolicy,
    workspace_graph: kin_db::GraphSnapshot,
    graph: kin_db::InMemoryGraph,
    /// The workspace's durable merge record as this lease saw it. An
    /// in-progress record refuses the merge; a terminated one is what the next
    /// merge compare-and-swaps over.
    existing_merge: Option<MergeTransactionRecord>,
}

fn plan_and_publish(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    request: &MergeRequest,
) -> Result<MergeCommandOutcome> {
    let plan = read_merge_plan(state, authority, request)?;
    let bases = plan
        .graph
        .find_merge_bases(&plan.ours_change, &plan.theirs_change)
        .context("resolve exact merge base from graph history")?;
    let base = match bases.as_slice() {
        [] => {
            return Err(merge_conflict(format!(
                "branch {} and the active branch {} share no common ancestor, and kin does not \
                 merge unrelated histories; rebase the source onto the target first, or import \
                 them separately",
                request.source, plan.target_ref
            )))
        }
        [base] => *base,
        multiple => {
            return Err(merge_conflict(format!(
                "branch {} and the active branch {} have {} merge bases, and kin does not \
                 resolve a criss-cross merge; merge one of the intermediate branches first so a \
                 single base remains",
                request.source,
                plan.target_ref,
                multiple.len()
            )))
        }
    };

    if base == plan.theirs_change {
        return Ok(MergeCommandOutcome::ReadOnly(already_up_to_date(
            request, &plan, base,
        )?));
    }
    if base == plan.ours_change {
        return fast_forward(state, authority, request, plan, base)
            .map(Box::new)
            .map(MergeCommandOutcome::Commit);
    }
    three_way(state, authority, request, plan, base)
        .map(Box::new)
        .map(MergeCommandOutcome::Commit)
}

fn read_merge_plan(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    request: &MergeRequest,
) -> Result<MergePlan> {
    if !request.source.is_branch() {
        return Err(merge_bad_request(format!(
            "merge requires a source ref below refs/heads/, found {}",
            request.source
        )));
    }
    let lease = authority.manager.read_authority();
    let roots = lease.roots().clone();
    let metadata = lease.metadata();
    let workspace = local_workspace(authority, metadata)?.clone();
    let existing_merge =
        crate::repository_merge_state::workspace_merge_record(metadata, workspace.workspace_id)
            .cloned();
    if let Some(open) = existing_merge
        .as_ref()
        .filter(|record| record.state.is_in_progress())
    {
        return Err(merge_conflict(format!(
            "workspace {} already has a merge of {} into {} in progress with {} unresolved \
             conflict(s); settle it with `kin resolve` or discard it with `kin resolve --abort` \
             before merging again",
            workspace.workspace_id,
            open.binding.source_ref,
            open.binding.target_ref,
            open.unresolved().count()
        )));
    }
    if workspace.is_dirty() {
        return Err(merge_conflict(format!(
            "workspace {} has graph-owned changes; commit or discard them before merging",
            workspace.workspace_id
        )));
    }
    let target_ref = match &workspace.head {
        WorkspaceHead::Symbolic { target } => target.clone(),
        WorkspaceHead::Detached { .. } => {
            return Err(merge_conflict(format!(
                "workspace {} has a detached head; merge publishes into the active branch and \
                 requires a symbolic workspace head",
                workspace.workspace_id
            )))
        }
    };
    if target_ref == request.source {
        return Err(merge_bad_request(format!(
            "cannot merge branch {} into itself",
            request.source
        )));
    }
    let ours_target = workspace.base_target.clone().ok_or_else(|| {
        merge_conflict(format!(
            "cannot merge into unborn branch {target_ref}; publish a change on it first"
        ))
    })?;
    if matches!(ours_target, RefTarget::Symbolic { .. }) {
        bail!(
            "workspace {} base target is symbolic instead of resolved",
            workspace.workspace_id
        );
    }
    let ours_change = lease
        .resolve_target_change_id(&ours_target)
        .with_context(|| format!("resolve exact semantic head of {target_ref}"))?;
    let theirs_target = lease
        .resolve_ref_target(&request.source)
        .with_context(|| {
            format!(
                "resolve repository branch {} from one authority lease",
                request.source
            )
        })?
        .ok_or_else(|| {
            merge_conflict(format!(
                "repository branch {} does not exist",
                request.source
            ))
        })?;
    let theirs_change = lease
        .resolve_target_change_id(&theirs_target)
        .with_context(|| format!("resolve exact semantic head of {}", request.source))?;
    let ours_policy = resolved_policy(metadata, &ours_change)?;
    let workspace_graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .context("materialize graph-owned workspace semantics for merge")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no graph snapshot for workspace {}",
                authority.repository_id,
                workspace.workspace_id
            )
        })?;
    require_fresh_daemon_workspace(state, &roots, &workspace_graph, "merging a branch")
        .map_err(|error| merge_conflict(error.to_string()))?;
    let mut snapshot = lease.snapshot().clone();
    snapshot.repository_authority = None;
    drop(lease);

    let graph = kin_db::InMemoryGraph::from_snapshot(snapshot)
        .context("prepare graph-owned merge history")?;
    Ok(MergePlan {
        roots,
        workspace,
        target_ref,
        ours_target,
        ours_change,
        theirs_target,
        theirs_change,
        ours_policy,
        workspace_graph,
        graph,
        existing_merge,
    })
}

fn already_up_to_date(
    request: &MergeRequest,
    plan: &MergePlan,
    base: SemanticChangeId,
) -> Result<MergeResponse> {
    let report = MergeReport {
        schema: MERGE_REPORT_SCHEMA.to_string(),
        authority: "repository-v6".to_string(),
        repository_id: plan.workspace.repository_id.clone(),
        authority_generation: plan.roots.generation,
        roots: plan.roots.clone(),
        workspace_id: plan.workspace.workspace_id,
        target_ref: plan.target_ref.clone(),
        source_ref: request.source.clone(),
        base_change: base,
        ours_change: plan.ours_change,
        theirs_change: plan.theirs_change,
        outcome: MergeOutcome::AlreadyUpToDate,
        merge_change: None,
        entity_delta_count: 0,
        relation_delta_count: 0,
        tree_delta_count: 0,
    };
    Ok(MergeResponse {
        lines: vec![format!(
            "Already up to date; {} at change {} is an ancestor of {}",
            request.source, plan.theirs_change, plan.target_ref
        )],
        mutated: false,
        report: Some(report),
        operation_id: Some(request.operation_id),
        authority_generation: Some(plan.roots.generation),
        idempotent: true,
    })
}

/// Advance the active branch to a descendant head. No merge change is
/// published: the target already has the source's complete history as an
/// ancestor, so the DAG needs no join.
fn fast_forward(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    request: &MergeRequest,
    plan: MergePlan,
    base: SemanticChangeId,
) -> Result<MergeExecution> {
    let theirs_state = plan
        .graph
        .resolve_graph_at(&plan.theirs_change)
        .with_context(|| format!("resolve exact graph for branch {}", request.source))?;
    let theirs_policy_source = plan.theirs_change;
    let target_tree = theirs_state.tree.clone();
    let target_tree_hash =
        compute_resolved_tree_hash(&target_tree).context("hash exact fast-forward target tree")?;
    let tree_deltas = kin_core::exact_tree_correction(&plan.workspace.tree, &target_tree)
        .context("plan exact fast-forward workspace transition")?;
    let semantic_delta = kin_core::diff_workspace_semantics(
        &plan.workspace_graph.entities,
        &plan.workspace_graph.relations,
        &theirs_state.entities,
        &theirs_state.relations,
    )
    .context("plan exact fast-forward semantic transition")?;
    let theirs_policy = {
        let lease = authority.manager.read_authority();
        let policy = resolved_policy(lease.metadata(), &theirs_policy_source)?;
        drop(lease);
        policy
    };
    let daemon_semantic_delta = crate::local_repository_authority::plan_daemon_semantic_delta(
        state,
        &theirs_state.entities,
        &theirs_state.relations,
    )
    .context("plan the exact fast-forward semantic transition for the daemon view")?;
    let daemon_delta = TransactionDelta {
        entity_deltas: daemon_semantic_delta.entity_deltas().to_vec(),
        relation_deltas: daemon_semantic_delta.relation_deltas().to_vec(),
        tree_deltas: tree_deltas.clone(),
        admission_policy_delta: None,
        external_reference_deltas: Vec::new(),
    };
    preflight_merge_delta(
        state,
        &plan.workspace.tree,
        &target_tree,
        &theirs_state.entities,
        &theirs_state.relations,
        &daemon_delta,
    )?;
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: request.operation_id,
        repository_id: plan.workspace.repository_id.clone(),
        expected_generation: plan.roots.generation,
        expected_roots: plan.roots.clone(),
        actor: request.actor.clone(),
        reason: FAST_FORWARD_REASON.to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: vec![RefMutation {
            name: plan.target_ref.clone(),
            expected: RefExpectation::MustEqual {
                target: plan.ours_target.clone(),
            },
            new_target: Some(plan.theirs_target.clone()),
            policy: RefUpdatePolicy::FastForwardOnly,
        }],
        default_ref_mutation: None,
        workspace_mutation: Some(workspace_mutation(
            &plan.workspace,
            plan.theirs_target.clone(),
            target_tree_hash,
            tree_deltas,
            semantic_delta,
            theirs_policy,
        )?),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
    };
    publish(
        state,
        authority,
        request,
        plan,
        transaction,
        target_tree,
        daemon_delta,
        MergeOutcome::FastForward,
        base,
        None,
    )
}

fn three_way(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    request: &MergeRequest,
    plan: MergePlan,
    base: SemanticChangeId,
) -> Result<MergeExecution> {
    let base_state = plan
        .graph
        .resolve_graph_at(&base)
        .context("resolve exact graph at the merge base")?;
    let ours_state = plan
        .graph
        .resolve_graph_at(&plan.ours_change)
        .with_context(|| format!("resolve exact graph for branch {}", plan.target_ref))?;
    let theirs_state = plan
        .graph
        .resolve_graph_at(&plan.theirs_change)
        .with_context(|| format!("resolve exact graph for branch {}", request.source))?;

    let mut conflicts = Vec::new();
    let merged_entities = compose(
        &base_state.entities,
        &ours_state.entities,
        &theirs_state.entities,
        |entity| MergeConflictSubject::Entity { entity: *entity },
        MergeSideValue::entity,
        |entity| describe_entity(&ours_state.entities, &theirs_state.entities, entity),
        &mut conflicts,
    )?;
    let merged_relations = compose(
        &base_state.relations,
        &ours_state.relations,
        &theirs_state.relations,
        |relation| MergeConflictSubject::Relation {
            relation: *relation,
        },
        MergeSideValue::relation,
        |_| None,
        &mut conflicts,
    )?;
    let merged_artifacts = compose(
        &artifacts_by_id(&base_state.tree),
        &artifacts_by_id(&ours_state.tree),
        &artifacts_by_id(&theirs_state.tree),
        |artifact| MergeConflictSubject::Artifact {
            artifact: *artifact,
        },
        MergeSideValue::artifact,
        |artifact| {
            ours_state
                .tree
                .get(artifact)
                .or_else(|| theirs_state.tree.get(artifact))
                .map(|resolved| resolved.path.to_string())
        },
        &mut conflicts,
    )?;
    let mut claimed: BTreeMap<&kin_model::RepoPath, Vec<kin_model::ArtifactId>> = BTreeMap::new();
    for artifact in merged_artifacts.values() {
        claimed
            .entry(&artifact.path)
            .or_default()
            .push(artifact.artifact_id);
    }
    for (path, mut artifacts) in claimed {
        if artifacts.len() > 1 {
            artifacts.sort();
            conflicts.push(MergeConflictEntry {
                subject: MergeConflictSubject::Path { path: path.clone() },
                divergence: MergeDivergence::PathCollision { artifacts },
                // A contested path holds no value on any side: each claimant
                // composed cleanly on its own, so the claimants above are the
                // whole conflict.
                base: MergeSideValue::Absent,
                ours: MergeSideValue::Absent,
                theirs: MergeSideValue::Absent,
                label: Some(path.to_string()),
                resolution: MergeEntryResolution::Unresolved,
            });
        }
    }
    collect_dangling_endpoints(
        &merged_relations,
        &merged_entities,
        &merged_artifacts,
        &base_state,
        &ours_state,
        &theirs_state,
        &mut conflicts,
    )?;
    if !conflicts.is_empty() {
        return open_conflicted_merge(state, authority, request, plan, base, conflicts);
    }

    let desired_tree = ResolvedTree::from_artifacts(merged_artifacts.into_values())
        .context("compose exact merged repository tree")?;
    let (shared_policy, admission_policy_delta) = derive_policy(
        &state.blobs,
        &authority.manager,
        &plan.ours_policy,
        &desired_tree,
    )?;
    if admission_policy_delta.is_some() || shared_policy != plan.ours_policy {
        return Err(merge_conflict(format!(
            "merging {} into {} changes the shared admission policy; a merge that transitions \
             admission policy is not a shape kin merges",
            request.source, plan.target_ref
        )));
    }

    let change_delta = kin_core::diff_workspace_semantics(
        &ours_state.entities,
        &ours_state.relations,
        &merged_entities,
        &merged_relations,
    )
    .context("author exact merge semantics against the first parent")?;
    let change_tree_deltas = kin_core::exact_tree_correction(&ours_state.tree, &desired_tree)
        .context("author exact merge tree deltas against the first parent")?;
    let mut change = SemanticChange {
        id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
        origin: ChangeOrigin::Native,
        parents: vec![plan.ours_change, plan.theirs_change],
        timestamp: Timestamp::now(),
        author: request.actor.clone(),
        message: format!("Merge {} into {}", request.source, plan.target_ref),
        entity_deltas: change_delta.entity_deltas().to_vec(),
        relation_deltas: change_delta.relation_deltas().to_vec(),
        tree_deltas: change_tree_deltas,
        admission_policy_delta: None,
        projected_files: Vec::new(),
        spec_link: None,
        evidence: Vec::new(),
        risk_summary: None,
        external_reference_deltas: Vec::new(),
    };
    change.id = compute_semantic_change_id(&change).context("hash exact merge change")?;
    let merge_target = RefTarget::change(change.id);

    // Plan the workspace against what replaying this merge actually yields,
    // not against the composition that produced it. Replay owns derived
    // per-entity provenance, so a workspace planned from the composed values
    // would sit one delta away from its own base the moment it is published.
    let replay = kin_db::InMemoryGraph::from_snapshot(plan.graph.to_snapshot())
        .context("prepare merge replay validation")?;
    replay
        .create_change(&change)
        .context("admit the merge change for replay validation")?;
    let authoritative = replay
        .resolve_graph_at(&change.id)
        .context("replay the exact merge change")?;
    if authoritative.tree != desired_tree {
        bail!(
            "merging {} into {} produced a change that does not replay to the same tree, so kin \
             refused to publish it; nothing was written, so re-run `kin merge {}` and report the \
             mismatch if it repeats",
            request.source,
            plan.target_ref,
            request.source
        );
    }
    let desired_tree_hash =
        compute_resolved_tree_hash(&desired_tree).context("hash exact merged tree")?;

    let workspace_tree_deltas =
        kin_core::exact_tree_correction(&plan.workspace.tree, &desired_tree)
            .context("plan exact merged workspace transition")?;
    let workspace_semantic_delta = kin_core::diff_workspace_semantics(
        &plan.workspace_graph.entities,
        &plan.workspace_graph.relations,
        &authoritative.entities,
        &authoritative.relations,
    )
    .context("plan exact merged workspace semantics")?;
    let daemon_semantic_delta = crate::local_repository_authority::plan_daemon_semantic_delta(
        state,
        &authoritative.entities,
        &authoritative.relations,
    )
    .context("plan the exact merged workspace semantics for the daemon view")?;
    let daemon_delta = TransactionDelta {
        entity_deltas: daemon_semantic_delta.entity_deltas().to_vec(),
        relation_deltas: daemon_semantic_delta.relation_deltas().to_vec(),
        tree_deltas: workspace_tree_deltas.clone(),
        admission_policy_delta: None,
        external_reference_deltas: Vec::new(),
    };
    preflight_merge_delta(
        state,
        &plan.workspace.tree,
        &desired_tree,
        &authoritative.entities,
        &authoritative.relations,
        &daemon_delta,
    )?;
    let entity_delta_count = change.entity_deltas.len();
    let relation_delta_count = change.relation_deltas.len();
    let tree_delta_count = change.tree_deltas.len();
    let change_id = change.id;
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: request.operation_id,
        repository_id: plan.workspace.repository_id.clone(),
        expected_generation: plan.roots.generation,
        expected_roots: plan.roots.clone(),
        actor: request.actor.clone(),
        reason: MERGE_REASON.to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: vec![change],
        aliases: Vec::new(),
        ref_mutations: vec![RefMutation {
            name: plan.target_ref.clone(),
            expected: RefExpectation::MustEqual {
                target: plan.ours_target.clone(),
            },
            new_target: Some(merge_target.clone()),
            policy: RefUpdatePolicy::FastForwardOnly,
        }],
        default_ref_mutation: None,
        workspace_mutation: Some(workspace_mutation(
            &plan.workspace,
            merge_target,
            desired_tree_hash,
            workspace_tree_deltas,
            workspace_semantic_delta,
            shared_policy,
        )?),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
    };
    let mut execution = publish(
        state,
        authority,
        request,
        plan,
        transaction,
        desired_tree,
        daemon_delta,
        MergeOutcome::Merged,
        base,
        Some(change_id),
    )?;
    if let Some(report) = execution.response.report.as_mut() {
        report.entity_delta_count = entity_delta_count;
        report.relation_delta_count = relation_delta_count;
        report.tree_delta_count = tree_delta_count;
    }
    Ok(execution)
}

/// Publish a parked merge from the resolutions its record already carries.
///
/// Composition is redone from graph truth rather than replayed from anything
/// the record cached: the record holds which identities conflicted and how each
/// was settled, and history holds the values. Recomposition is then held to the
/// record, so a merge whose inputs moved underneath it fails loud instead of
/// publishing a different merge than the one that was resolved.
pub(crate) fn publish_resolved_merge(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    request: &kin_cli::commands::resolve::ResolveRequest,
    roots: RootBundle,
    workspace: WorkspaceState,
    record: MergeTransactionRecord,
) -> Result<MergeExecution> {
    if !record.is_fully_resolved() {
        return Err(merge_conflict(format!(
            "merging {} into {} still has {} unresolved conflict(s): {}",
            record.binding.source_ref,
            record.binding.target_ref,
            record.unresolved().count(),
            crate::repository_merge_state::describe_unresolved(&record)
        )));
    }
    if restore_point(&workspace) != record.restore {
        return Err(merge_conflict(format!(
            "workspace {} has moved since this merge opened, so publishing it would not be the \
             merge that was resolved; abandon it with `kin resolve --abort` and merge again",
            workspace.workspace_id
        )));
    }

    let lease = authority.manager.read_authority();
    let metadata = lease.metadata();
    let ours_policy = resolved_policy(metadata, &record.binding.ours_change)?;
    let current_target = lease
        .resolve_ref_target(&record.binding.target_ref)
        .with_context(|| {
            format!(
                "resolve repository branch {} from one authority lease",
                record.binding.target_ref
            )
        })?;
    if current_target.as_ref() != Some(&record.binding.ours_target) {
        return Err(merge_conflict(format!(
            "branch {} has advanced since this merge opened; abandon it with `kin resolve --abort` \
             and merge again",
            record.binding.target_ref
        )));
    }
    let workspace_graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .context("materialize graph-owned workspace semantics for merge publication")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no graph snapshot for workspace {}",
                authority.repository_id,
                workspace.workspace_id
            )
        })?;
    require_fresh_daemon_workspace(state, &roots, &workspace_graph, "publishing a merge")
        .map_err(|error| merge_conflict(error.to_string()))?;
    let mut snapshot = lease.snapshot().clone();
    snapshot.repository_authority = None;
    drop(lease);

    let graph = kin_db::InMemoryGraph::from_snapshot(snapshot)
        .context("prepare graph-owned merge history")?;
    let base_state = graph
        .resolve_graph_at(&record.binding.base_change)
        .context("resolve exact graph at the merge base")?;
    let ours_state = graph
        .resolve_graph_at(&record.binding.ours_change)
        .context("resolve exact graph for the branch being merged into")?;
    let theirs_state = graph
        .resolve_graph_at(&record.binding.theirs_change)
        .context("resolve exact graph for the branch being merged in")?;

    let mut recomposed = Vec::new();
    let mut merged_entities = compose(
        &base_state.entities,
        &ours_state.entities,
        &theirs_state.entities,
        |entity| MergeConflictSubject::Entity { entity: *entity },
        MergeSideValue::entity,
        |entity| describe_entity(&ours_state.entities, &theirs_state.entities, entity),
        &mut recomposed,
    )?;
    let mut merged_relations = compose(
        &base_state.relations,
        &ours_state.relations,
        &theirs_state.relations,
        |relation| MergeConflictSubject::Relation {
            relation: *relation,
        },
        MergeSideValue::relation,
        |_| None,
        &mut recomposed,
    )?;
    let ours_artifacts = artifacts_by_id(&ours_state.tree);
    let theirs_artifacts = artifacts_by_id(&theirs_state.tree);
    let base_artifacts = artifacts_by_id(&base_state.tree);
    let mut merged_artifacts = compose(
        &base_artifacts,
        &ours_artifacts,
        &theirs_artifacts,
        |artifact| MergeConflictSubject::Artifact {
            artifact: *artifact,
        },
        MergeSideValue::artifact,
        |artifact| {
            ours_state
                .tree
                .get(artifact)
                .or_else(|| theirs_state.tree.get(artifact))
                .map(|resolved| resolved.path.to_string())
        },
        &mut recomposed,
    )?;
    let mut claimed: BTreeMap<&kin_model::RepoPath, Vec<kin_model::ArtifactId>> = BTreeMap::new();
    for artifact in merged_artifacts.values() {
        claimed
            .entry(&artifact.path)
            .or_default()
            .push(artifact.artifact_id);
    }
    for (path, mut artifacts) in claimed {
        if artifacts.len() > 1 {
            artifacts.sort();
            recomposed.push(MergeConflictEntry {
                subject: MergeConflictSubject::Path { path: path.clone() },
                divergence: MergeDivergence::PathCollision { artifacts },
                base: MergeSideValue::Absent,
                ours: MergeSideValue::Absent,
                theirs: MergeSideValue::Absent,
                label: Some(path.to_string()),
                resolution: MergeEntryResolution::Unresolved,
            });
        }
    }
    collect_dangling_endpoints(
        &merged_relations,
        &merged_entities,
        &merged_artifacts,
        &base_state,
        &ours_state,
        &theirs_state,
        &mut recomposed,
    )?;
    require_same_conflicts(&record, &mut recomposed)?;

    for entry in &record.entries {
        apply_resolution(
            entry,
            &base_state,
            &ours_state,
            &theirs_state,
            &base_artifacts,
            &ours_artifacts,
            &theirs_artifacts,
            &mut merged_entities,
            &mut merged_relations,
            &mut merged_artifacts,
        )?;
    }

    // Two settlements can cover one file, and only one of them becomes bytes.
    // This is the rule that decides which, and refuses when neither composes.
    let projections = project_artifacts_from_settled_entities(
        &record,
        &base_state,
        &ours_state,
        &theirs_state,
        &base_artifacts,
        &ours_artifacts,
        &theirs_artifacts,
        &mut merged_entities,
        &mut merged_artifacts,
    )?;

    // The resolutions are the caller's, so a composition they leave broken is
    // named rather than parked again: the record already holds one settlement
    // per conflict, and re-opening would discard it.
    let mut residual = Vec::new();
    let mut settled_paths: BTreeMap<&kin_model::RepoPath, usize> = BTreeMap::new();
    for artifact in merged_artifacts.values() {
        *settled_paths.entry(&artifact.path).or_default() += 1;
    }
    for (path, count) in settled_paths {
        if count > 1 {
            residual.push(format!("{count} artifacts still occupy path {path}"));
        }
    }
    let mut dangling = Vec::new();
    collect_dangling_endpoints(
        &merged_relations,
        &merged_entities,
        &merged_artifacts,
        &base_state,
        &ours_state,
        &theirs_state,
        &mut dangling,
    )?;
    residual.extend(dangling.iter().map(render_entry));
    if !residual.is_empty() {
        return Err(merge_conflict(format!(
            "the recorded resolutions do not compose into a publishable merge: {}",
            residual.join("; ")
        )));
    }

    let desired_tree = ResolvedTree::from_artifacts(merged_artifacts.into_values())
        .context("compose exact resolved repository tree")?;
    let (shared_policy, admission_policy_delta) = derive_policy(
        &state.blobs,
        &authority.manager,
        &ours_policy,
        &desired_tree,
    )?;
    if admission_policy_delta.is_some() || shared_policy != ours_policy {
        return Err(merge_conflict(format!(
            "merging {} into {} changes the shared admission policy; a merge that transitions \
             admission policy is not a shape kin merges",
            record.binding.source_ref, record.binding.target_ref
        )));
    }

    let change_delta = kin_core::diff_workspace_semantics(
        &ours_state.entities,
        &ours_state.relations,
        &merged_entities,
        &merged_relations,
    )
    .context("author exact merge semantics against the first parent")?;
    let change_tree_deltas = kin_core::exact_tree_correction(&ours_state.tree, &desired_tree)
        .context("author exact merge tree deltas against the first parent")?;
    let mut change = SemanticChange {
        id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
        origin: ChangeOrigin::Native,
        parents: vec![record.binding.ours_change, record.binding.theirs_change],
        timestamp: Timestamp::now(),
        author: request.actor.clone(),
        message: format!(
            "Merge {} into {}",
            record.binding.source_ref, record.binding.target_ref
        ),
        entity_deltas: change_delta.entity_deltas().to_vec(),
        relation_deltas: change_delta.relation_deltas().to_vec(),
        tree_deltas: change_tree_deltas,
        admission_policy_delta: None,
        projected_files: Vec::new(),
        spec_link: None,
        evidence: Vec::new(),
        risk_summary: None,
        external_reference_deltas: Vec::new(),
    };
    change.id = compute_semantic_change_id(&change).context("hash exact merge change")?;
    let merge_target = RefTarget::change(change.id);

    let replay = kin_db::InMemoryGraph::from_snapshot(graph.to_snapshot())
        .context("prepare merge replay validation")?;
    replay
        .create_change(&change)
        .context("admit the merge change for replay validation")?;
    let authoritative = replay
        .resolve_graph_at(&change.id)
        .context("replay the exact merge change")?;
    if authoritative.tree != desired_tree {
        bail!(
            "the resolution of {} into {} produced a change that does not replay to the same \
             tree, so kin refused to publish it; nothing was written, and your recorded conflict \
             resolutions are still there for another `kin resolve`",
            record.binding.source_ref,
            record.binding.target_ref
        );
    }
    let desired_tree_hash =
        compute_resolved_tree_hash(&desired_tree).context("hash exact merged tree")?;
    let workspace_tree_deltas = kin_core::exact_tree_correction(&workspace.tree, &desired_tree)
        .context("plan exact merged workspace transition")?;
    let workspace_semantic_delta = kin_core::diff_workspace_semantics(
        &workspace_graph.entities,
        &workspace_graph.relations,
        &authoritative.entities,
        &authoritative.relations,
    )
    .context("plan exact merged workspace semantics")?;
    let daemon_semantic_delta = crate::local_repository_authority::plan_daemon_semantic_delta(
        state,
        &authoritative.entities,
        &authoritative.relations,
    )
    .context("plan the exact merged workspace semantics for the daemon view")?;
    let daemon_delta = TransactionDelta {
        entity_deltas: daemon_semantic_delta.entity_deltas().to_vec(),
        relation_deltas: daemon_semantic_delta.relation_deltas().to_vec(),
        tree_deltas: workspace_tree_deltas.clone(),
        admission_policy_delta: None,
        external_reference_deltas: Vec::new(),
    };
    preflight_merge_delta(
        state,
        &workspace.tree,
        &desired_tree,
        &authoritative.entities,
        &authoritative.relations,
        &daemon_delta,
    )?;

    let terminated = record
        .terminate(MergeTransactionState::Committed {
            merge_change: change.id,
            operation_id: request.operation_id,
            committed_at: Timestamp::now(),
        })
        .context("terminate the merge transaction as published")?;
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: request.operation_id,
        repository_id: workspace.repository_id.clone(),
        expected_generation: roots.generation,
        expected_roots: roots.clone(),
        actor: request.actor.clone(),
        reason: MERGE_REASON.to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: vec![change.clone()],
        aliases: Vec::new(),
        ref_mutations: vec![RefMutation {
            name: record.binding.target_ref.clone(),
            expected: RefExpectation::MustEqual {
                target: record.binding.ours_target.clone(),
            },
            new_target: Some(merge_target.clone()),
            policy: RefUpdatePolicy::FastForwardOnly,
        }],
        default_ref_mutation: None,
        workspace_mutation: Some(workspace_mutation(
            &workspace,
            merge_target,
            desired_tree_hash,
            workspace_tree_deltas,
            workspace_semantic_delta,
            shared_policy,
        )?),
        local_overlay_delta: None,
        merge_transaction_delta: Some(MergeTransactionDelta::update(
            record.clone(),
            terminated.clone(),
        )),
        sealed_observation: None,
    };
    transaction
        .validate()
        .context("validate exact repository-v6 resolved merge transaction")?;
    let drift = kin_core::report_repository_workspace_projection_drift(
        state.layout.working_dir(),
        &workspace.tree,
        &authority.manager,
    )
    .context("validate exact workspace projection before publishing the merge")?;
    if let Some(first) = drift.first() {
        return Err(kin_core::KinError::ProjectionConflict(format!(
            "{first}; {} tracked path(s) diverge from the graph-owned workspace projection; \
             reconcile them into graph authority or discard them before publishing this merge",
            drift.len()
        ))
        .into());
    }
    let (materialized, receipt, authority_freeze) =
        kin_core::tree::transition_repository_workspace_tree_and_commit_repository_transaction(
            state.layout.working_dir(),
            &workspace.tree,
            &desired_tree,
            &authority.manager,
            transaction,
        )
        .with_context(|| {
            format!(
                "publish resolved repository-v6 merge of {} into {}",
                record.binding.source_ref, record.binding.target_ref
            )
        })?;

    let resolved_count = terminated.entries.len();
    let report = kin_cli::commands::resolve::ResolveReport {
        schema: kin_cli::commands::resolve::RESOLVE_REPORT_SCHEMA.to_string(),
        authority: "repository-v6".to_string(),
        repository_id: workspace.repository_id.clone(),
        workspace_id: workspace.workspace_id,
        authority_generation: receipt.generation,
        roots: receipt.roots_after.clone(),
        record: Some(terminated),
        merge_change: Some(change.id),
        resolved_count,
        unresolved_count: 0,
    };
    let previous_tree = workspace.tree.clone();
    Ok(MergeExecution {
        response: MergeResponse::default(),
        resolve_response: Some(kin_cli::commands::resolve::ResolveResponse {
            lines: {
                let mut lines = vec![format!(
                    "Merged {} into {} as change {} after settling {} conflict(s) ({} projected \
                     entries, authority generation {})",
                    record.binding.source_ref,
                    record.binding.target_ref,
                    change.id,
                    resolved_count,
                    materialized,
                    receipt.generation
                )];
                lines.extend(projections);
                lines
            },
            mutated: matches!(receipt.outcome, RepositoryCommitOutcome::Committed),
            report: Some(report),
            operation_id: Some(receipt.operation_id),
            authority_generation: Some(receipt.generation),
            idempotent: matches!(receipt.outcome, RepositoryCommitOutcome::IdempotentReplay),
        }),
        receipt,
        authority_freeze,
        daemon_delta,
        previous_tree,
        desired_tree,
    })
}

/// Hold recomposition to the record: same identities, same divergences, same
/// side values. Anything else means the merge being published is not the merge
/// that was resolved.
fn require_same_conflicts(
    record: &MergeTransactionRecord,
    recomposed: &mut Vec<MergeConflictEntry>,
) -> Result<()> {
    recomposed.sort_by(|left, right| left.subject.cmp(&right.subject));
    if recomposed.len() != record.entries.len() {
        return Err(merge_conflict(format!(
            "recomposing this merge now finds {} conflict(s) where the record holds {}; history \
             moved underneath the merge, so abandon it with `kin resolve --abort` and merge again",
            recomposed.len(),
            record.entries.len()
        )));
    }
    for (recorded, found) in record.entries.iter().zip(recomposed.iter()) {
        if recorded.subject != found.subject
            || recorded.divergence != found.divergence
            || recorded.base != found.base
            || recorded.ours != found.ours
            || recorded.theirs != found.theirs
        {
            return Err(merge_conflict(format!(
                "recomposing this merge no longer reproduces the recorded conflict {}; history \
                 moved underneath the merge, so abandon it with `kin resolve --abort` and merge \
                 again",
                render_subject(recorded)
            )));
        }
    }
    Ok(())
}

/// Apply one settled entry to the composed maps.
#[allow(clippy::too_many_arguments)]
fn apply_resolution(
    entry: &MergeConflictEntry,
    base_state: &kin_model::graph::ResolvedGraphState,
    ours_state: &kin_model::graph::ResolvedGraphState,
    theirs_state: &kin_model::graph::ResolvedGraphState,
    base_artifacts: &std::collections::HashMap<kin_model::ArtifactId, ResolvedArtifact>,
    ours_artifacts: &std::collections::HashMap<kin_model::ArtifactId, ResolvedArtifact>,
    theirs_artifacts: &std::collections::HashMap<kin_model::ArtifactId, ResolvedArtifact>,
    entities: &mut std::collections::HashMap<kin_model::EntityId, kin_model::Entity>,
    relations: &mut std::collections::HashMap<kin_model::RelationId, kin_model::Relation>,
    artifacts: &mut std::collections::HashMap<kin_model::ArtifactId, ResolvedArtifact>,
) -> Result<()> {
    match (&entry.subject, &entry.resolution) {
        (_, MergeEntryResolution::Unresolved) => {
            bail!("an unresolved entry reached merge publication")
        }
        (MergeConflictSubject::Entity { entity }, MergeEntryResolution::Side { side, .. }) => {
            let state = graph_side(side, base_state, ours_state, theirs_state);
            let value = state.entities.get(entity);
            require_recorded_side(entry, side, MergeSideValue::entity(value)?)?;
            match value {
                Some(value) => entities.insert(*entity, value.clone()),
                None => entities.remove(entity),
            };
        }
        (MergeConflictSubject::Relation { relation }, MergeEntryResolution::Side { side, .. }) => {
            let state = graph_side(side, base_state, ours_state, theirs_state);
            let value = state.relations.get(relation);
            require_recorded_side(entry, side, MergeSideValue::relation(value)?)?;
            match value {
                Some(value) => relations.insert(*relation, value.clone()),
                None => relations.remove(relation),
            };
        }
        (MergeConflictSubject::Artifact { artifact }, MergeEntryResolution::Side { side, .. }) => {
            let side_artifacts =
                artifact_side(*side, base_artifacts, ours_artifacts, theirs_artifacts);
            let value = side_artifacts.get(artifact);
            require_recorded_side(entry, side, MergeSideValue::artifact(value)?)?;
            match value {
                Some(value) => artifacts.insert(*artifact, value.clone()),
                None => artifacts.remove(artifact),
            };
        }
        (MergeConflictSubject::Path { .. }, MergeEntryResolution::Side { .. }) => {
            bail!("a contested path has no side to take")
        }
        (subject, MergeEntryResolution::Payload { payload, .. }) => match (subject, payload) {
            (MergeConflictSubject::Entity { entity }, MergeResolutionPayload::Removed) => {
                entities.remove(entity);
            }
            (MergeConflictSubject::Relation { relation }, MergeResolutionPayload::Removed) => {
                relations.remove(relation);
            }
            (MergeConflictSubject::Artifact { artifact }, MergeResolutionPayload::Removed) => {
                artifacts.remove(artifact);
            }
            (
                MergeConflictSubject::Path { path },
                MergeResolutionPayload::PathOwner { artifact: owner },
            ) => {
                let MergeDivergence::PathCollision {
                    artifacts: claimants,
                } = &entry.divergence
                else {
                    bail!("a path owner settles a path collision")
                };
                for claimant in claimants {
                    if claimant != owner {
                        artifacts.remove(claimant);
                    }
                }
                if !artifacts.contains_key(owner) {
                    bail!("the artifact chosen to keep path {path} did not survive composition")
                }
            }
            (MergeConflictSubject::Path { .. }, MergeResolutionPayload::Removed) => {
                let MergeDivergence::PathCollision {
                    artifacts: claimants,
                } = &entry.divergence
                else {
                    bail!("a removal of a contested path settles a path collision")
                };
                for claimant in claimants {
                    artifacts.remove(claimant);
                }
            }
            _ => {
                return Err(merge_bad_request(format!(
                    "authoring a merge resolution value for {} is not a proven repository-v6 \
                     shape; settle it by taking a side, removing it, or naming a path owner",
                    render_subject(entry)
                )))
            }
        },
    }
    Ok(())
}

fn graph_side<'a>(
    side: &MergeSide,
    base: &'a kin_model::graph::ResolvedGraphState,
    ours: &'a kin_model::graph::ResolvedGraphState,
    theirs: &'a kin_model::graph::ResolvedGraphState,
) -> &'a kin_model::graph::ResolvedGraphState {
    match side {
        MergeSide::Base => base,
        MergeSide::Ours => ours,
        MergeSide::Theirs => theirs,
    }
}

/// A resolution that claims a side is checked against history rather than
/// trusted: the value that side holds now must be the value the record bound.
fn require_recorded_side(
    entry: &MergeConflictEntry,
    side: &MergeSide,
    found: MergeSideValue,
) -> Result<()> {
    let recorded = match side {
        MergeSide::Base => &entry.base,
        MergeSide::Ours => &entry.ours,
        MergeSide::Theirs => &entry.theirs,
    };
    if &found != recorded {
        return Err(merge_conflict(format!(
            "the {side:?} side of {} no longer holds the value this merge recorded; abandon the \
             merge with `kin resolve --abort` and merge again",
            render_subject(entry)
        )));
    }
    Ok(())
}

/// An entity settlement, paired with the file paths that entity occupies on the
/// sides this merge composed. The path is what joins an entity decision to the
/// artifact decision that would otherwise overwrite it.
struct SettledEntity<'a> {
    entry: &'a MergeConflictEntry,
    entity: kin_model::EntityId,
    side: MergeSide,
    paths: BTreeSet<String>,
}

/// The one precedence rule for two settlements that cover one file:
/// **entity beats artifact, specific beats bulk.**
///
/// A file's bytes are a projection of graph truth, so settling one entity is a
/// decision about that entity, and settling the artifact holding it is a
/// decision about the whole file. Those land in two independent maps, and only
/// the artifact map becomes file bytes. Before this rule both were honoured
/// separately: a named `--theirs` on an entity followed by a bulk `--all-ours`
/// reported every conflict settled, published the `ours` bytes, and recorded a
/// merge whose tree delta against the first parent was empty. The source branch
/// contributed nothing, and nothing said so.
///
/// The rule takes the file, and the entities settled inside it, from whichever
/// side carries every one of those entity decisions. Nothing is synthesized:
/// the candidates are the sides this merge already bound, so what publishes is
/// a side's own committed blob, held to history by the same
/// `require_recorded_side` check the settled side got. That matters because a
/// kin merge composes at the granularity of a whole entity or artifact and
/// never the line, so a choice among recorded sides is one kin can make
/// honestly and a spliced third body is not.
///
/// Where no single side carries every decision, the settlements do not compose
/// into any publishable file and the merge REFUSES, naming both decisions.
/// Refusing is the fallback. Publishing one of two contradictory decisions in
/// silence is the defect this rule exists to remove.
///
/// Founder ruling, 2026-08-30: entity beats artifact, a bulk artifact settle
/// never overrides a recorded entity decision inside it, unprojectable mixes
/// refuse naming both decisions, never silent.
fn project_artifacts_from_settled_entities(
    record: &MergeTransactionRecord,
    base_state: &kin_model::graph::ResolvedGraphState,
    ours_state: &kin_model::graph::ResolvedGraphState,
    theirs_state: &kin_model::graph::ResolvedGraphState,
    base_artifacts: &std::collections::HashMap<kin_model::ArtifactId, ResolvedArtifact>,
    ours_artifacts: &std::collections::HashMap<kin_model::ArtifactId, ResolvedArtifact>,
    theirs_artifacts: &std::collections::HashMap<kin_model::ArtifactId, ResolvedArtifact>,
    merged_entities: &mut std::collections::HashMap<kin_model::EntityId, kin_model::Entity>,
    merged_artifacts: &mut std::collections::HashMap<kin_model::ArtifactId, ResolvedArtifact>,
) -> Result<Vec<String>> {
    let settled_entities = settled_entities_by_path(record, base_state, ours_state, theirs_state);
    if settled_entities.is_empty() {
        return Ok(Vec::new());
    }

    let mut projections = Vec::new();
    for entry in &record.entries {
        let (MergeConflictSubject::Artifact { artifact }, MergeEntryResolution::Side { side, .. }) =
            (&entry.subject, &entry.resolution)
        else {
            continue;
        };
        let Some(path) = artifact_path(artifact, base_artifacts, ours_artifacts, theirs_artifacts)
        else {
            continue;
        };
        let inside: Vec<&SettledEntity<'_>> = settled_entities
            .iter()
            .filter(|settled| settled.paths.contains(&path))
            .collect();
        if inside.is_empty() {
            continue;
        }
        if decisions_a_side_drops(*side, &inside, base_state, ours_state, theirs_state).is_empty() {
            continue;
        }

        let mut carried: Vec<(MergeSide, Option<&ResolvedArtifact>)> = Vec::new();
        for candidate in [MergeSide::Ours, MergeSide::Theirs, MergeSide::Base] {
            if !decisions_a_side_drops(candidate, &inside, base_state, ours_state, theirs_state)
                .is_empty()
            {
                continue;
            }
            let value = artifact_side(candidate, base_artifacts, ours_artifacts, theirs_artifacts)
                .get(artifact);
            // Sides holding byte-identical artifacts are one choice, not
            // several, so a base that never moved cannot make a projection
            // ambiguous merely by existing.
            let mut seen = false;
            for (_, kept) in &carried {
                if MergeSideValue::artifact(*kept)? == MergeSideValue::artifact(value)? {
                    seen = true;
                    break;
                }
            }
            if !seen {
                carried.push((candidate, value));
            }
        }

        if carried.len() != 1 {
            let decisions = name_decisions(&inside);
            let why = if carried.is_empty() {
                format!(
                    "no side of {path} carries every one of those entity decisions, and a kin \
                     merge composes at the granularity of a whole entity or artifact and never \
                     the line, so there is no third body to publish"
                )
            } else {
                format!(
                    "{} sides of {path} carry every one of those entity decisions and their \
                     bytes differ, so which body to publish is not determined by what was \
                     settled",
                    carried.len()
                )
            };
            return Err(merge_conflict(format!(
                "the recorded resolutions disagree about {path}: {} was settled `{}`, while \
                 inside it {decisions}. {why}. Settle {path} to the side that carries those \
                 entity decisions, or re-settle the entities, then continue.",
                render_subject(entry),
                side_flag(*side),
            )));
        }

        let (projected, value) = carried[0];
        // The projected side is held to history exactly as the settled one was:
        // the value that side carries now must be the value the record bound.
        require_recorded_side(entry, &projected, MergeSideValue::artifact(value)?)?;
        match value {
            Some(value) => merged_artifacts.insert(*artifact, value.clone()),
            None => merged_artifacts.remove(artifact),
        };
        // The file and the entities settled inside it come from one side, so
        // the spans graph truth records are the spans the published bytes have.
        // Every one of these entities agrees semantically with its settlement
        // on this side, which is what made the side a candidate at all, so no
        // decision is lost by taking that side's copy of it.
        for settled in &inside {
            let taken = graph_side(&projected, base_state, ours_state, theirs_state)
                .entities
                .get(&settled.entity);
            match taken {
                Some(taken) => merged_entities.insert(settled.entity, taken.clone()),
                None => merged_entities.remove(&settled.entity),
            };
        }
        projections.push(format!(
            "Projected {} from the `{}` side rather than the `{}` it was settled to, because {}; \
             a file's bytes follow the entities settled inside it.",
            render_subject(entry),
            side_flag(projected),
            side_flag(*side),
            name_decisions(&inside),
        ));
    }
    Ok(projections)
}

/// Every entity this merge settled by taking a side, with the file paths that
/// entity occupies on the sides that were composed.
fn settled_entities_by_path<'a>(
    record: &'a MergeTransactionRecord,
    base_state: &kin_model::graph::ResolvedGraphState,
    ours_state: &kin_model::graph::ResolvedGraphState,
    theirs_state: &kin_model::graph::ResolvedGraphState,
) -> Vec<SettledEntity<'a>> {
    let mut settled = Vec::new();
    for entry in &record.entries {
        let (MergeConflictSubject::Entity { entity }, MergeEntryResolution::Side { side, .. }) =
            (&entry.subject, &entry.resolution)
        else {
            continue;
        };
        // An entity names its file in its span, which is the field the conflict
        // listing labels it by. Reading every side covers an entity that moved:
        // the decision binds wherever the identity is claimed.
        let mut paths = BTreeSet::new();
        for state in [base_state, ours_state, theirs_state] {
            if let Some(found) = state.entities.get(entity) {
                if let Some(span) = found.span.as_ref() {
                    paths.insert(span.file.to_string());
                }
            }
        }
        if paths.is_empty() {
            continue;
        }
        settled.push(SettledEntity {
            entry,
            entity: *entity,
            side: *side,
            paths,
        });
    }
    settled
}

/// Which of these entity decisions one side's published state does not carry.
fn decisions_a_side_drops<'a>(
    side: MergeSide,
    settled: &[&'a SettledEntity<'a>],
    base_state: &kin_model::graph::ResolvedGraphState,
    ours_state: &kin_model::graph::ResolvedGraphState,
    theirs_state: &kin_model::graph::ResolvedGraphState,
) -> Vec<&'a SettledEntity<'a>> {
    settled
        .iter()
        .filter(|entity| {
            let decided = graph_side(&entity.side, base_state, ours_state, theirs_state)
                .entities
                .get(&entity.entity);
            let carried = graph_side(&side, base_state, ours_state, theirs_state)
                .entities
                .get(&entity.entity);
            !entities_agree(decided, carried)
        })
        .copied()
        .collect()
}

/// Whether two sides hold the same SEMANTIC value for one entity.
///
/// Byte offsets and the change a revision was recorded in are projection facts,
/// not semantic ones. Editing one function moves the span of every entity below
/// it, so a whole-value comparison would report every entity in that file as
/// disagreeing when only one of them moved. That is the same fan-out the
/// conflict listing already shows, twenty-two entity conflicts for one edited
/// function, and judging agreement on it would refuse every mixed settle kin
/// can honestly project. Agreement is judged on what the graph calls content:
/// the fingerprint over normalized structure, signature, exact source text and
/// behaviour class, beside the declaration facts around it.
fn entities_agree(left: Option<&kin_model::Entity>, right: Option<&kin_model::Entity>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.kind == right.kind
                && left.name == right.name
                && left.language == right.language
                && left.fingerprint == right.fingerprint
                && left.signature == right.signature
                && left.visibility == right.visibility
                && left.role == right.role
        }
        _ => false,
    }
}

/// Name entity decisions the way the caller made them, so a refusal quotes the
/// identity the listing showed and the flag that settled it.
fn name_decisions(settled: &[&SettledEntity<'_>]) -> String {
    settled
        .iter()
        .map(|entity| {
            format!(
                "{} was settled `{}`",
                render_subject(entity.entry),
                side_flag(entity.side)
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The path an artifact identity occupies, preferring the branch being merged
/// into, then the branch being merged in, then the base.
fn artifact_path(
    artifact: &kin_model::ArtifactId,
    base_artifacts: &std::collections::HashMap<kin_model::ArtifactId, ResolvedArtifact>,
    ours_artifacts: &std::collections::HashMap<kin_model::ArtifactId, ResolvedArtifact>,
    theirs_artifacts: &std::collections::HashMap<kin_model::ArtifactId, ResolvedArtifact>,
) -> Option<String> {
    ours_artifacts
        .get(artifact)
        .or_else(|| theirs_artifacts.get(artifact))
        .or_else(|| base_artifacts.get(artifact))
        .map(|resolved| resolved.path.to_string())
}

fn artifact_side<'a>(
    side: MergeSide,
    base: &'a std::collections::HashMap<kin_model::ArtifactId, ResolvedArtifact>,
    ours: &'a std::collections::HashMap<kin_model::ArtifactId, ResolvedArtifact>,
    theirs: &'a std::collections::HashMap<kin_model::ArtifactId, ResolvedArtifact>,
) -> &'a std::collections::HashMap<kin_model::ArtifactId, ResolvedArtifact> {
    match side {
        MergeSide::Base => base,
        MergeSide::Ours => ours,
        MergeSide::Theirs => theirs,
    }
}

/// The spelling of a side a caller actually types, so a refusal names the
/// decision in the form that produced it rather than in a Rust variant name.
fn side_flag(side: MergeSide) -> &'static str {
    match side {
        MergeSide::Base => "--base",
        MergeSide::Ours => "--ours",
        MergeSide::Theirs => "--theirs",
    }
}

/// Compose one identity-keyed dimension of the three-way merge.
///
/// Every decision is by exact value equality against the merge base, so a side
/// that did not move never overrides a side that did, and both sides moving to
/// the same value is agreement rather than conflict.
fn compose<K, V, S, D, L>(
    base: &std::collections::HashMap<K, V>,
    ours: &std::collections::HashMap<K, V>,
    theirs: &std::collections::HashMap<K, V>,
    subject: S,
    side_value: D,
    label: L,
    conflicts: &mut Vec<MergeConflictEntry>,
) -> Result<std::collections::HashMap<K, V>>
where
    K: Copy + Ord + std::hash::Hash,
    V: Clone + PartialEq,
    S: Fn(&K) -> MergeConflictSubject,
    D: Fn(Option<&V>) -> std::result::Result<MergeSideValue, ModelError>,
    L: Fn(&K) -> Option<String>,
{
    // Identity iteration is ordered so the reported conflict set is stable
    // across runs; the composed maps themselves are order-independent.
    let mut ids = BTreeSet::new();
    ids.extend(base.keys().copied());
    ids.extend(ours.keys().copied());
    ids.extend(theirs.keys().copied());
    let mut merged = std::collections::HashMap::new();
    for id in ids {
        let base_side = base.get(&id);
        let our_side = ours.get(&id);
        let their_side = theirs.get(&id);
        let resolved = if our_side == their_side {
            our_side
        } else if our_side == base_side {
            their_side
        } else if their_side == base_side {
            our_side
        } else {
            conflicts.push(MergeConflictEntry {
                subject: subject(&id),
                divergence: value_divergence(
                    base_side.is_some(),
                    our_side.is_some(),
                    their_side.is_some(),
                )?,
                base: side_value(base_side)?,
                ours: side_value(our_side)?,
                theirs: side_value(their_side)?,
                label: label(&id),
                resolution: MergeEntryResolution::Unresolved,
            });
            continue;
        };
        if let Some(value) = resolved {
            merged.insert(id, value.clone());
        }
    }
    Ok(merged)
}

/// Classify a value divergence from which of the three inputs held the identity.
///
/// Composition only reaches this for an identity where both sides moved and
/// moved differently, so exactly four shapes are reachable. Anything else means
/// composition and classification disagree, which is a defect rather than a
/// conflict, and is refused instead of recorded.
fn value_divergence(in_base: bool, in_ours: bool, in_theirs: bool) -> Result<MergeDivergence> {
    Ok(match (in_base, in_ours, in_theirs) {
        (true, true, true) => MergeDivergence::ChangedBothSides,
        (false, true, true) => MergeDivergence::AddedBothSides,
        (_, true, false) => MergeDivergence::ChangedOursRemovedTheirs,
        (_, false, true) => MergeDivergence::RemovedOursChangedTheirs,
        (_, false, false) => {
            bail!("composition reported a conflict for an identity neither side holds")
        }
    })
}

/// Refuse a composition where one side removed a node the other side still
/// points at.
///
/// Each dimension composes independently, so "remove an entity" and "add an
/// edge to that entity" are both non-conflicting on their own and compose into
/// an edge with no endpoint. Replay would silently prune it, which is a quiet
/// way to drop work the source branch published. An endpoint that was already
/// absent from both sides is pre-existing and not this merge's doing.
fn collect_dangling_endpoints(
    relations: &std::collections::HashMap<kin_model::RelationId, kin_model::Relation>,
    entities: &std::collections::HashMap<kin_model::EntityId, kin_model::Entity>,
    artifacts: &std::collections::HashMap<kin_model::ArtifactId, ResolvedArtifact>,
    base: &kin_model::graph::ResolvedGraphState,
    ours: &kin_model::graph::ResolvedGraphState,
    theirs: &kin_model::graph::ResolvedGraphState,
    conflicts: &mut Vec<MergeConflictEntry>,
) -> Result<()> {
    let mut dangling: BTreeMap<kin_model::RelationId, (kin_model::GraphNodeId, String)> =
        BTreeMap::new();
    for (id, relation) in relations {
        for endpoint in [&relation.src, &relation.dst] {
            if let Some(entity) = endpoint.as_entity() {
                let survives = entities.contains_key(&entity);
                let existed =
                    ours.entities.contains_key(&entity) || theirs.entities.contains_key(&entity);
                if !survives && existed {
                    dangling.entry(*id).or_insert_with(|| {
                        let name = describe_entity(&ours.entities, &theirs.entities, &entity);
                        (
                            *endpoint,
                            format!(
                                "one branch removed {}, which the other branch still relates to",
                                name.unwrap_or_else(|| entity.to_string())
                            ),
                        )
                    });
                }
            }
            if let kin_model::GraphNodeId::Artifact(artifact) = endpoint {
                let artifact = *artifact;
                let survives = artifacts.contains_key(&artifact);
                let existed =
                    ours.tree.get(&artifact).is_some() || theirs.tree.get(&artifact).is_some();
                if !survives && existed {
                    dangling.entry(*id).or_insert_with(|| {
                        let path = ours
                            .tree
                            .get(&artifact)
                            .or_else(|| theirs.tree.get(&artifact))
                            .map(|resolved| resolved.path.to_string())
                            .unwrap_or_else(|| render_artifact(&artifact));
                        (
                            *endpoint,
                            format!(
                                "one branch removed {path}, which the other branch still relates to"
                            ),
                        )
                    });
                }
            }
        }
    }
    for (relation, (endpoint, detail)) in dangling {
        conflicts.push(MergeConflictEntry {
            subject: MergeConflictSubject::Relation { relation },
            divergence: MergeDivergence::DanglingEndpoint { endpoint },
            // The relation itself composed; what broke is the node it points
            // at, so its sides are recorded as history holds them.
            base: MergeSideValue::relation(base.relations.get(&relation))?,
            ours: MergeSideValue::relation(ours.relations.get(&relation))?,
            theirs: MergeSideValue::relation(theirs.relations.get(&relation))?,
            label: Some(detail),
            resolution: MergeEntryResolution::Unresolved,
        });
    }
    Ok(())
}

fn artifacts_by_id(
    tree: &ResolvedTree,
) -> std::collections::HashMap<kin_model::ArtifactId, ResolvedArtifact> {
    tree.artifacts()
        .map(|artifact| (artifact.artifact_id, artifact.clone()))
        .collect()
}

/// Measure the merged tree's rule sources to derive its admission policy.
///
/// Takes the two stores rather than the daemon state because a merge composes
/// published trees: every rule file it measures was published by an earlier
/// change and is therefore durable in repository CAS, whether or not its staged
/// copy survived. Naming both stores here is what keeps a merge from depending
/// on ingestion staging that nothing promises to retain.
fn derive_policy(
    blobs: &kin_blobs::BlobStore,
    authority: &RepositoryAuthorityManager<LocalFileBackend>,
    parent: &SharedAdmissionPolicy,
    tree: &ResolvedTree,
) -> Result<(
    SharedAdmissionPolicy,
    Option<kin_model::AdmissionPolicyDelta>,
)> {
    let mut lengths: BTreeMap<Hash256, u64> = BTreeMap::new();
    SharedAdmissionPolicy::derive_from_tree_with_allowances(
        Some(parent),
        tree,
        |hash| {
            if let Some(length) = lengths.get(&hash) {
                return Ok(*length);
            }
            let source = read_publishable_source(blobs, authority, hash).map_err(|error| {
                ModelError::InvalidOperation(format!(
                    "{error}, while deriving the merged tree's admission policy"
                ))
            })?;
            let length = u64::try_from(source.body().len()).map_err(|_| {
                ModelError::InvalidOperation(format!(
                    "graph-owned admission source {hash} exceeds u64"
                ))
            })?;
            lengths.insert(hash, length);
            Ok(length)
        },
        |hash| {
            read_publishable_source(blobs, authority, hash)
                .map(|source| source.body().to_vec())
                .map_err(|error| {
                    ModelError::InvalidOperation(format!(
                        "{error}, while reading the approvals the merged tree's policy derives"
                    ))
                })
        },
    )
    .context("derive exact admission policy for the merged tree")
}

fn workspace_mutation(
    workspace: &WorkspaceState,
    new_base_target: RefTarget,
    new_tree_hash: Hash256,
    tree_deltas: Vec<kin_model::TreeDelta>,
    semantic_delta: WorkspaceSemanticDelta,
    shared_policy: SharedAdmissionPolicy,
) -> Result<WorkspaceMutation> {
    Ok(WorkspaceMutation {
        workspace_id: workspace.workspace_id,
        expected: WorkspaceExpectation::MustEqual {
            generation: workspace.generation,
            head: workspace.head.clone(),
            base_target: workspace.base_target.clone(),
            base_tree_hash: workspace.base_tree_hash,
            tree_hash: workspace.tree_hash,
            semantic_overlay_hash: workspace.semantic_overlay_hash,
            admission_policy: workspace.admission_policy,
        },
        new_generation: workspace.generation.checked_add(1).ok_or_else(|| {
            crate::error::workspace_generation_exhausted(
                workspace.workspace_id,
                workspace.generation,
            )
        })?,
        new_head: workspace.head.clone(),
        new_base_target: Some(new_base_target),
        new_base_tree_hash: Some(new_tree_hash),
        tree_deltas,
        new_tree_hash,
        semantic_delta,
        new_shared_admission_policy: shared_policy.clone(),
        new_admission_policy: EffectiveAdmissionPolicyStamp {
            shared: shared_policy.stamp(),
            local: workspace.admission_policy.local,
        },
    })
}

/// Prove the daemon's own graph reaches the exact merged state through the
/// same delta the transaction carries, before anything is materialized.
///
/// Without this the daemon can publish authority it cannot itself reproduce,
/// and the divergence only surfaces later as an inexplicably dirty workspace.
fn preflight_merge_delta(
    state: &DaemonState,
    previous_tree: &ResolvedTree,
    desired_tree: &ResolvedTree,
    desired_entities: &std::collections::HashMap<kin_model::EntityId, kin_model::Entity>,
    desired_relations: &std::collections::HashMap<kin_model::RelationId, kin_model::Relation>,
    delta: &TransactionDelta,
) -> Result<()> {
    let live_tree = state.graph.resolved_tree();
    if live_tree != *previous_tree && live_tree != *desired_tree {
        return Err(merge_conflict(
            "daemon query tree matches neither the merge base workspace nor the merged authority",
        ));
    }
    let preflight = kin_db::InMemoryGraph::from_snapshot(state.graph.to_snapshot())
        .context("prepare merge daemon graph preflight")?;
    preflight
        .apply_transaction_delta(delta)
        .context("apply merge daemon graph preflight")?;
    let snapshot = preflight.to_snapshot();
    if snapshot.resolved_tree != *desired_tree {
        bail!(
            "the merge preflighted to a tree that does not match the one it composed, so kin \
             refused to publish it; your workspace is unchanged, so run `kin status` and try again"
        );
    }
    if snapshot.entities != *desired_entities || snapshot.relations != *desired_relations {
        bail!(
            "the merge preflighted to graph semantics that do not match the ones it composed, so \
             kin refused to publish it; your workspace is unchanged, so run `kin status` and try \
             again"
        );
    }
    Ok(())
}

/// Validate the derived view, then materialize and publish in one transaction.
#[allow(clippy::too_many_arguments)]
fn publish(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    request: &MergeRequest,
    plan: MergePlan,
    transaction: RepositoryTransaction,
    desired_tree: ResolvedTree,
    daemon_delta: TransactionDelta,
    outcome: MergeOutcome,
    base: SemanticChangeId,
    merge_change: Option<SemanticChangeId>,
) -> Result<MergeExecution> {
    transaction
        .validate()
        .context("validate exact repository-v6 merge transaction")?;
    let drift = kin_core::report_repository_workspace_projection_drift(
        state.layout.working_dir(),
        &plan.workspace.tree,
        &authority.manager,
    )
    .context("validate exact workspace projection before merging")?;
    if let Some(first) = drift.first() {
        return Err(kin_core::KinError::ProjectionConflict(format!(
            "{first}; {} tracked path(s) diverge from the graph-owned workspace projection; \
             reconcile them into graph authority or discard them before merging",
            drift.len()
        ))
        .into());
    }
    let (materialized, receipt, authority_freeze) =
        kin_core::tree::transition_repository_workspace_tree_and_commit_repository_transaction(
            state.layout.working_dir(),
            &plan.workspace.tree,
            &desired_tree,
            &authority.manager,
            transaction,
        )
        .with_context(|| {
            format!(
                "publish repository-v6 merge of {} into {}",
                request.source, plan.target_ref
            )
        })?;
    let line = match outcome {
        MergeOutcome::FastForward => format!(
            "Fast-forwarded {} to change {} ({} projected entries, authority generation {})",
            plan.target_ref, plan.theirs_change, materialized, receipt.generation
        ),
        MergeOutcome::Merged => format!(
            "Merged {} into {} as change {} ({} projected entries, authority generation {})",
            request.source,
            plan.target_ref,
            merge_change.expect("a published merge carries its change id"),
            materialized,
            receipt.generation
        ),
        MergeOutcome::AlreadyUpToDate => {
            bail!("an up-to-date merge must not reach the publication path")
        }
        MergeOutcome::Conflicted => {
            bail!("a parked merge must not reach the workspace publication path")
        }
    };
    let report = MergeReport {
        schema: MERGE_REPORT_SCHEMA.to_string(),
        authority: "repository-v6".to_string(),
        repository_id: plan.workspace.repository_id.clone(),
        authority_generation: receipt.generation,
        roots: receipt.roots_after.clone(),
        workspace_id: plan.workspace.workspace_id,
        target_ref: plan.target_ref.clone(),
        source_ref: request.source.clone(),
        base_change: base,
        ours_change: plan.ours_change,
        theirs_change: plan.theirs_change,
        outcome,
        merge_change,
        entity_delta_count: 0,
        relation_delta_count: 0,
        tree_delta_count: 0,
    };
    Ok(MergeExecution {
        resolve_response: None,
        response: MergeResponse {
            lines: vec![line],
            mutated: matches!(receipt.outcome, RepositoryCommitOutcome::Committed),
            report: Some(report),
            operation_id: Some(receipt.operation_id),
            authority_generation: Some(receipt.generation),
            idempotent: matches!(receipt.outcome, RepositoryCommitOutcome::IdempotentReplay),
        },
        receipt,
        authority_freeze,
        daemon_delta,
        previous_tree: plan.workspace.tree,
        desired_tree,
    })
}

/// Park a merge that did not compose as one durable merge-transaction record.
///
/// Nothing else moves: no merge change is authored, no ref advances, and the
/// workspace stays exactly where the restore point says it was. The record is
/// the whole of the publication, so the merge is recoverable across a daemon
/// restart and abortable back to a workspace that never moved.
fn open_conflicted_merge(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    request: &MergeRequest,
    plan: MergePlan,
    base: SemanticChangeId,
    conflicts: Vec<MergeConflictEntry>,
) -> Result<MergeExecution> {
    let conflict_count = conflicts.len();
    let record = MergeTransactionRecord::open(
        plan.workspace.repository_id.clone(),
        plan.workspace.workspace_id,
        MergeOpening {
            operation_id: request.operation_id,
            actor: request.actor.clone(),
            opened_at: Timestamp::now(),
        },
        MergeParentBinding {
            target_ref: plan.target_ref.clone(),
            source_ref: request.source.clone(),
            base_change: base,
            ours_change: plan.ours_change,
            theirs_change: plan.theirs_change,
            ours_target: plan.ours_target.clone(),
            theirs_target: plan.theirs_target.clone(),
        },
        restore_point(&plan.workspace),
        conflicts,
    )
    .context("open the durable merge transaction for a merge that did not compose")?;
    let delta = match plan.existing_merge.clone() {
        Some(previous) => MergeTransactionDelta::update(previous, record.clone()),
        None => MergeTransactionDelta::open(record.clone()),
    };
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: request.operation_id,
        repository_id: plan.workspace.repository_id.clone(),
        expected_generation: plan.roots.generation,
        expected_roots: plan.roots.clone(),
        actor: request.actor.clone(),
        reason: OPEN_MERGE_REASON.to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: None,
        local_overlay_delta: None,
        merge_transaction_delta: Some(delta),
        sealed_observation: None,
    };
    transaction
        .validate()
        .context("validate the durable merge transaction that parks this merge")?;
    let (receipt, authority_freeze) =
        crate::repository_merge_state::commit_and_freeze_exact(&authority.manager, transaction)
            .with_context(|| {
                format!(
                    "open the durable merge transaction for {} into {}",
                    request.source, plan.target_ref
                )
            })?;
    let _ = state;
    let mut lines = vec![format!(
        "Merging {} into {} left {} unresolved conflict(s); the merge is held as merge \
         transaction {} (authority generation {})",
        request.source, plan.target_ref, conflict_count, record.hash, receipt.generation
    )];
    lines.extend(render_conflict_lines(&record));
    lines.push(
        "Settle each conflict with `kin resolve`, then `kin resolve --continue`, or discard the \
         merge with `kin resolve --abort`"
            .to_string(),
    );
    let report = MergeReport {
        schema: MERGE_REPORT_SCHEMA.to_string(),
        authority: "repository-v6".to_string(),
        repository_id: plan.workspace.repository_id.clone(),
        authority_generation: receipt.generation,
        roots: receipt.roots_after.clone(),
        workspace_id: plan.workspace.workspace_id,
        target_ref: plan.target_ref.clone(),
        source_ref: request.source.clone(),
        base_change: base,
        ours_change: plan.ours_change,
        theirs_change: plan.theirs_change,
        outcome: MergeOutcome::Conflicted,
        merge_change: None,
        entity_delta_count: 0,
        relation_delta_count: 0,
        tree_delta_count: 0,
    };
    let tree = plan.workspace.tree.clone();
    Ok(MergeExecution {
        resolve_response: None,
        response: MergeResponse {
            lines,
            mutated: matches!(receipt.outcome, RepositoryCommitOutcome::Committed),
            report: Some(report),
            operation_id: Some(receipt.operation_id),
            authority_generation: Some(receipt.generation),
            idempotent: matches!(receipt.outcome, RepositoryCommitOutcome::IdempotentReplay),
        },
        receipt,
        authority_freeze,
        daemon_delta: TransactionDelta::default(),
        previous_tree: tree.clone(),
        desired_tree: tree,
    })
}

/// The exact workspace an abort must prove the workspace equals again.
pub(crate) fn restore_point(workspace: &WorkspaceState) -> MergeWorkspaceRestorePoint {
    MergeWorkspaceRestorePoint {
        generation: workspace.generation,
        head: workspace.head.clone(),
        base_target: workspace.base_target.clone(),
        base_tree_hash: workspace.base_tree_hash,
        tree_hash: workspace.tree_hash,
        semantic_overlay_hash: workspace.semantic_overlay_hash,
        admission_policy: workspace.admission_policy,
    }
}

/// Name the first conflicts individually and state the total, so a listing
/// never reads as complete when it is truncated.
pub(crate) fn render_conflict_lines(record: &MergeTransactionRecord) -> Vec<String> {
    let unresolved: Vec<&MergeConflictEntry> = record.unresolved().collect();
    let mut lines: Vec<String> = unresolved
        .iter()
        .take(RENDERED_CONFLICT_LIMIT)
        .map(|entry| format!("  - {}", render_entry(entry)))
        .collect();
    if unresolved.len() > RENDERED_CONFLICT_LIMIT {
        lines.push(format!(
            "  - ... and {} further conflict(s) not listed",
            unresolved.len() - RENDERED_CONFLICT_LIMIT
        ));
    }
    lines
}

pub(crate) fn render_entry(entry: &MergeConflictEntry) -> String {
    let detail = match &entry.divergence {
        MergeDivergence::ChangedBothSides => {
            "changed on both branches with different content".to_string()
        }
        MergeDivergence::AddedBothSides => {
            "added independently on both branches with different content".to_string()
        }
        MergeDivergence::ChangedOursRemovedTheirs => {
            "changed on the active branch and removed on the source branch".to_string()
        }
        MergeDivergence::RemovedOursChangedTheirs => {
            "removed on the active branch and changed on the source branch".to_string()
        }
        // The claimants are the whole conflict, and naming an owner is the only
        // way to settle it, so the listing names them. A caller who cannot read
        // the claimants from the listing has no selector to pass back.
        MergeDivergence::PathCollision { artifacts } => format!(
            "{} distinct artifacts occupy this path after composing both sides ({}); keep one \
             with `kin resolve --keep-path {}=<ARTIFACT>`",
            artifacts.len(),
            artifacts
                .iter()
                .map(render_artifact)
                .collect::<Vec<_>>()
                .join(", "),
            match &entry.subject {
                MergeConflictSubject::Path { path } => path.to_string(),
                _ => "<PATH>".to_string(),
            }
        ),
        MergeDivergence::DanglingEndpoint { .. } => entry
            .label
            .clone()
            .unwrap_or_else(|| "relates to a node neither composed side kept".to_string()),
    };
    format!("{}: {detail}", render_subject(entry))
}

/// The one textual form of an artifact identity these commands emit and accept.
///
/// It is exactly the form the record serializes, so an identity read out of
/// `kin conflicts --json` is the string `kin resolve` takes back. `ArtifactId`
/// has no `Display`, so a `{:?}` rendering here would print a wrapper form that
/// no surface emits and that therefore cannot round-trip.
pub(crate) fn render_artifact(artifact: &kin_model::ArtifactId) -> String {
    artifact.0.to_string()
}

/// Name a subject held without the entry that labels it.
///
/// `MergeConflictSubject` has no `Display`, so the alternative at these sites is
/// a `{:?}` rendering that reaches the caller as `ArtifactId(<uuid>)`. That is
/// the wrapper form the resolver refuses, quoted by a message the caller is
/// meant to act on. Routing these sites here keeps one identity form across
/// every surface, including the refusals.
pub(crate) fn render_subject_identity(subject: &MergeConflictSubject) -> String {
    match subject {
        MergeConflictSubject::Entity { entity } => format!("entity {entity}"),
        MergeConflictSubject::Relation { relation } => format!("relation {relation}"),
        MergeConflictSubject::Artifact { artifact } => {
            format!("artifact {}", render_artifact(artifact))
        }
        MergeConflictSubject::Path { path } => format!("path {path}"),
    }
}

pub(crate) fn render_subject(entry: &MergeConflictEntry) -> String {
    match (&entry.subject, &entry.label) {
        (MergeConflictSubject::Entity { entity }, Some(name)) => {
            format!("entity {name} ({entity})")
        }
        (MergeConflictSubject::Artifact { artifact }, Some(path)) => {
            format!("artifact {path} ({})", render_artifact(artifact))
        }
        (subject, _) => render_subject_identity(subject),
    }
}

/// Name a conflicting entity by whichever side still carries it, preferring
/// the active branch. A removal on one side leaves only the other side able to
/// describe what was removed.
fn describe_entity(
    ours: &std::collections::HashMap<kin_model::EntityId, kin_model::Entity>,
    theirs: &std::collections::HashMap<kin_model::EntityId, kin_model::Entity>,
    entity: &kin_model::EntityId,
) -> Option<String> {
    let found = ours.get(entity).or_else(|| theirs.get(entity))?;
    Some(
        match found.span.as_ref().map(|span| span.file.to_string()) {
            Some(file) => format!("{} in {file}", found.name),
            None => found.name.clone(),
        },
    )
}

fn resolved_policy(
    metadata: &kin_db::PersistedRepositoryAuthority,
    change_id: &SemanticChangeId,
) -> Result<SharedAdmissionPolicy> {
    metadata
        .admission_policies
        .iter()
        .find(|resolved| &resolved.change_id == change_id)
        .ok_or_else(|| {
            anyhow::anyhow!("change {change_id} has no repository-v6 admission-policy record")
        })?
        .policy
        .clone()
        .ok_or_else(|| {
            anyhow::anyhow!("change {change_id} has an unresolved shared admission policy")
        })
}

pub(crate) fn local_workspace<'a>(
    authority: &ActiveLocalRepositoryAuthority,
    metadata: &'a kin_db::PersistedRepositoryAuthority,
) -> Result<&'a WorkspaceState> {
    metadata
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == authority.workspace_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no workspace {} in repository-v6 authority",
                authority.repository_id,
                authority.workspace_id
            )
        })
}

pub(crate) fn classify_merge_error(error: anyhow::Error) -> (StatusCode, String) {
    if error.downcast_ref::<MergeBadRequest>().is_some() {
        return (StatusCode::BAD_REQUEST, crate::error::cause_first(&error));
    }
    if error.downcast_ref::<MergeConflictRefusal>().is_some() {
        return (StatusCode::CONFLICT, crate::error::cause_first(&error));
    }
    if let Some(core) = error.downcast_ref::<kin_core::KinError>() {
        let status = match core {
            kin_core::KinError::Model(model) => merge_model_status(model),
            kin_core::KinError::RepositoryConflict(_)
            | kin_core::KinError::ProjectionConflict(_) => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return (status, crate::error::cause_first(&error));
    }
    if let Some(database) = error.downcast_ref::<kin_db::KinDbError>() {
        let status = match database {
            kin_db::KinDbError::Model(model) => merge_model_status(model),
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return (status, crate::error::cause_first(&error));
    }
    if let Some(model) = error.downcast_ref::<kin_model::ModelError>() {
        return (merge_model_status(model), crate::error::cause_first(&error));
    }
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        crate::error::cause_first(&error),
    )
}

fn merge_model_status(error: &kin_model::ModelError) -> StatusCode {
    match error {
        kin_model::ModelError::InvalidHash(_) | kin_model::ModelError::InvalidOperation(_) => {
            StatusCode::BAD_REQUEST
        }
        kin_model::ModelError::Conflict(_)
        | kin_model::ModelError::RefNotFound(_)
        | kin_model::ModelError::WorkspaceNotFound(_)
        | kin_model::ModelError::ChangeNotFound(_) => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

pub(crate) fn repository_finalization_error(
    error: crate::error::DaemonError,
) -> (StatusCode, String) {
    use crate::error::DaemonError;
    let status = match &error {
        DaemonError::Graph(kin_db::KinDbError::Model(kin_model::ModelError::InvalidOperation(
            _,
        )))
        | DaemonError::Core(kin_core::KinError::Model(kin_model::ModelError::InvalidOperation(
            _,
        ))) => StatusCode::BAD_REQUEST,
        DaemonError::Graph(kin_db::KinDbError::Model(kin_model::ModelError::Conflict(_)))
        | DaemonError::IncompatibleRepo(_) => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, error.to_string())
}

pub(crate) fn merge_bind_refusal(refusal: RepositoryAuthorityBindRefusal) -> (StatusCode, String) {
    let identity = refusal.is_identity_refusal();
    let error = refusal.into_error();
    if identity {
        (StatusCode::CONFLICT, crate::error::cause_first(&error))
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            crate::error::cause_first(&error),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use kin_model::{
        graph::ResolvedGraphState, ArtifactId, AuthorId, GraphNodeId, MergeEntryResolution,
        MergeResolutionProvenance, OperationId, Relation, RelationId, RelationKind, RelationOrigin,
        RepoPath, ResolvedArtifact, ResolvedTree, TreeEntry,
    };

    use super::*;

    fn artifact(id: ArtifactId, path: &str, content: u8) -> ResolvedArtifact {
        ResolvedArtifact::new(
            id,
            RepoPath::from_utf8(path).unwrap(),
            TreeEntry::blob(Hash256::from_bytes([content; 32]), false),
        )
    }

    fn graph_state(
        target: ResolvedArtifact,
        anchor: ResolvedArtifact,
        relation: Relation,
    ) -> ResolvedGraphState {
        ResolvedGraphState {
            relations: [(relation.id, relation)].into(),
            tree: ResolvedTree::from_artifacts([target, anchor]).unwrap(),
            ..ResolvedGraphState::default()
        }
    }

    /// The form these commands print is the form the record serializes, so a
    /// selector can be copied straight out of `kin conflicts --json`. This
    /// fails the moment a rendering drifts back to the `ArtifactId(..)` wrapper
    /// form, which no Kin surface emits and which therefore cannot be passed
    /// back to settle anything.
    #[test]
    fn an_artifact_renders_exactly_as_the_record_serializes_it() {
        let artifact = ArtifactId::new();
        let serialized = serde_json::to_value(artifact).expect("an artifact identity serializes");
        assert_eq!(
            render_artifact(&artifact),
            serialized
                .as_str()
                .expect("an artifact identity serializes as a string"),
        );
        assert_ne!(
            render_artifact(&artifact),
            format!("{artifact:?}"),
            "the wrapper debug form is not what the record serializes"
        );
    }

    /// A contested path is settled only by naming one claimant, so a listing
    /// that states the count without naming them leaves the caller no selector
    /// to pass back.
    #[test]
    fn a_contested_path_names_the_claimants_it_accepts_back() {
        let left = ArtifactId::new();
        let right = ArtifactId::new();
        let entry = MergeConflictEntry {
            subject: MergeConflictSubject::Path {
                path: RepoPath::from_utf8("docs/notes.md").unwrap(),
            },
            divergence: MergeDivergence::PathCollision {
                artifacts: vec![left, right],
            },
            base: MergeSideValue::Absent,
            ours: MergeSideValue::Absent,
            theirs: MergeSideValue::Absent,
            label: Some("docs/notes.md".to_string()),
            resolution: MergeEntryResolution::Unresolved,
        };
        let rendered = render_entry(&entry);
        assert!(
            rendered.contains(&render_artifact(&left)),
            "listing names its first claimant: {rendered}"
        );
        assert!(
            rendered.contains(&render_artifact(&right)),
            "listing names its second claimant: {rendered}"
        );
        assert!(
            rendered.contains("docs/notes.md"),
            "listing names the contested path: {rendered}"
        );
        // A wrapper rendering contains the bare identity as a substring, so the
        // assertions above alone would pass on a listing nothing can select
        // from. The claimants have to appear in the form the resolver accepts.
        assert!(
            !rendered.contains("ArtifactId("),
            "listing carries identities in the form the resolver accepts: {rendered}"
        );
    }

    /// Taking a side for everything names a subject without the entry that
    /// labels it, and it names it inside a refusal the caller is meant to act
    /// on. A claimant quoted there has to carry the same form as the listing,
    /// or the message hands back an identity the resolver rejects.
    #[test]
    fn a_subject_named_without_its_entry_carries_the_form_the_resolver_accepts() {
        let artifact = ArtifactId::new();
        let rendered = render_subject_identity(&MergeConflictSubject::Artifact { artifact });
        assert!(
            rendered.contains(&render_artifact(&artifact)),
            "a subject names its artifact: {rendered}"
        );
        // The wrapper form carries the bare identity as a substring, so the
        // assertion above alone is satisfied by a rendering nothing can select
        // from. The form itself is what has to hold.
        assert!(
            !rendered.contains("ArtifactId("),
            "a subject names its artifact in the form the resolver accepts: {rendered}"
        );
        // One rendering serves both halves. A second one is precisely how the
        // wrapper form survived on this surface while every other emitter moved.
        let entry = MergeConflictEntry {
            subject: MergeConflictSubject::Artifact { artifact },
            divergence: MergeDivergence::ChangedBothSides,
            base: MergeSideValue::Absent,
            ours: MergeSideValue::Absent,
            theirs: MergeSideValue::Absent,
            label: None,
            resolution: MergeEntryResolution::Unresolved,
        };
        assert_eq!(
            render_subject(&entry),
            rendered,
            "the entry path and the bare-subject path render one identity form"
        );
    }

    #[test]
    fn dangling_relation_records_and_accepts_its_present_base_side() {
        let target_id = ArtifactId::new();
        let anchor_id = ArtifactId::new();
        let relation = Relation {
            id: RelationId::new(),
            kind: RelationKind::References,
            src: GraphNodeId::Artifact(anchor_id),
            dst: GraphNodeId::Artifact(target_id),
            confidence: 1.0,
            origin: RelationOrigin::Manual,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        let base_state = graph_state(
            artifact(target_id, "src/target.rs", 0x10),
            artifact(anchor_id, "src/anchor.rs", 0x20),
            relation.clone(),
        );
        let ours_state = graph_state(
            artifact(target_id, "src/target.rs", 0x11),
            artifact(anchor_id, "src/anchor.rs", 0x20),
            relation.clone(),
        );
        let theirs_state = graph_state(
            artifact(target_id, "src/target.rs", 0x12),
            artifact(anchor_id, "src/anchor.rs", 0x20),
            relation.clone(),
        );

        let base_artifacts = artifacts_by_id(&base_state.tree);
        let ours_artifacts = artifacts_by_id(&ours_state.tree);
        let theirs_artifacts = artifacts_by_id(&theirs_state.tree);
        let mut conflicts = Vec::new();
        let mut merged_artifacts = compose(
            &base_artifacts,
            &ours_artifacts,
            &theirs_artifacts,
            |artifact| MergeConflictSubject::Artifact {
                artifact: *artifact,
            },
            MergeSideValue::artifact,
            |_| None,
            &mut conflicts,
        )
        .unwrap();
        let mut merged_relations = compose(
            &base_state.relations,
            &ours_state.relations,
            &theirs_state.relations,
            |relation| MergeConflictSubject::Relation {
                relation: *relation,
            },
            MergeSideValue::relation,
            |_| None,
            &mut conflicts,
        )
        .unwrap();
        let mut merged_entities = HashMap::new();

        collect_dangling_endpoints(
            &merged_relations,
            &merged_entities,
            &merged_artifacts,
            &base_state,
            &ours_state,
            &theirs_state,
            &mut conflicts,
        )
        .unwrap();

        let mut dangling = conflicts
            .iter()
            .find(|entry| matches!(entry.divergence, MergeDivergence::DanglingEndpoint { .. }))
            .expect("the unchanged relation must dangle from the conflicted artifact")
            .clone();
        let expected = MergeSideValue::relation(Some(&relation)).unwrap();
        assert_eq!(dangling.base, expected);
        assert_eq!(dangling.ours, expected);
        assert_eq!(dangling.theirs, expected);

        dangling.resolution = MergeEntryResolution::Side {
            side: MergeSide::Base,
            provenance: MergeResolutionProvenance {
                actor: AuthorId::new("test"),
                operation_id: OperationId::new(),
                resolved_at: Timestamp::now(),
            },
        };
        dangling.validate().unwrap();
        apply_resolution(
            &dangling,
            &base_state,
            &ours_state,
            &theirs_state,
            &base_artifacts,
            &ours_artifacts,
            &theirs_artifacts,
            &mut merged_entities,
            &mut merged_relations,
            &mut merged_artifacts,
        )
        .unwrap();
        assert_eq!(merged_relations.get(&relation.id), Some(&relation));
    }

    fn rule_source_fixture() -> (
        tempfile::TempDir,
        kin_core::InitResult,
        Hash256,
        ResolvedTree,
    ) {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let hash = Hash256::from_bytes(blobs.write(b"target/\n").unwrap().0);
        let tree = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8(".gitignore").unwrap(),
            TreeEntry::blob(hash, false),
        )])
        .unwrap();
        (root, init, hash, tree)
    }

    fn empty_policy() -> SharedAdmissionPolicy {
        SharedAdmissionPolicy::derive_from_tree(None, &ResolvedTree::default(), |_| Ok(0))
            .unwrap()
            .0
    }

    fn authority(init: &kin_core::InitResult) -> RepositoryAuthorityManager<LocalFileBackend> {
        RepositoryAuthorityManager::open(
            init.repository_id.clone(),
            std::sync::Arc::new(LocalFileBackend::new(init.layout.kindb_dir())),
        )
        .unwrap()
    }

    /// A merge measures every rule file in the merged tree, and by construction
    /// every one of them was published by an earlier change rather than
    /// observed by this one. Reading only ingestion staging made a merge depend
    /// on a store that promises no retention, for bodies the repository already
    /// owns and for a policy the merge then refuses to let change.
    #[test]
    fn a_merge_derives_its_policy_after_ingestion_staging_is_lost() {
        let (_root, init, hash, tree) = rule_source_fixture();
        let authority = authority(&init);
        authority.save_source_blob(hash, b"target/\n").unwrap();

        std::fs::remove_dir_all(init.layout.ingest_cas_dir()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        assert!(
            blobs
                .read(&kin_blobs::Hash256::from_bytes(*hash.as_bytes()))
                .is_err(),
            "the fixture only proves anything while the staged rule body is genuinely gone"
        );

        let (policy, _) = derive_policy(&blobs, &authority, &empty_policy(), &tree)
            .expect("a merged tree whose rule bodies authority owns still derives its policy");
        assert_eq!(
            policy
                .sources
                .iter()
                .map(|source| source.body_len)
                .collect::<Vec<_>>(),
            vec![8],
            "the measured length is the published body's, not a guess"
        );
    }

    /// The control. A rule body no store holds still fails the merge, so the
    /// fallback cannot be mistaken for one that invents a length.
    #[test]
    fn a_merge_still_refuses_a_rule_body_neither_store_holds() {
        let (_root, init, _hash, tree) = rule_source_fixture();
        let authority = authority(&init);

        std::fs::remove_dir_all(init.layout.ingest_cas_dir()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();

        let error = derive_policy(&blobs, &authority, &empty_policy(), &tree)
            .expect_err("a rule body neither store holds cannot be measured");
        assert!(
            format!("{error:#}").contains("absent from both ingestion staging and repository CAS"),
            "the refusal names both stores it consulted: {error:#}"
        );
    }

    /// The merged tree's policy has to be derived through the entry point that
    /// reads a tracked `.kin-allowances`, or an approval a reviewer accepted on
    /// one side of a merge is dropped by the merge itself.
    ///
    /// Reverting this file's derivation to `derive_from_tree` fails here,
    /// because the compatibility entry point refuses by name the moment the
    /// tree carries approvals it cannot read. The two structural assertions
    /// below are what stop this passing for the wrong reason: the approval must
    /// land in `sensitive_allowances` and must NOT land in `sources`, because
    /// the allowance file is an approval set rather than an exclusion rule, and
    /// a derivation that treated it as an ordinary rule source would satisfy a
    /// bare "the policy changed" check while approving nothing.
    #[test]
    fn a_merged_tree_derives_the_approvals_it_carries() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let blobs = kin_blobs::BlobStore::new(init.layout.ingest_cas_dir()).unwrap();
        let authority = authority(&init);

        let secret = b"API_TOKEN = \"sk-proj-abcd1234efgh5678ijkl\"\n";
        let secret_hash = Hash256::from_bytes(blobs.write(secret).unwrap().0);
        let approvals = format!(
            "# approvals for this fixture\n\
             kin-allowances 1\n\
             notekeeper/client.py\t{secret_hash}\tblob\tcredscan@firelock.ai\tpinned by the \
             test covering this derivation site\n"
        );
        let approvals_hash = Hash256::from_bytes(blobs.write(approvals.as_bytes()).unwrap().0);

        let tree = ResolvedTree::from_artifacts([
            ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8("notekeeper/client.py").unwrap(),
                TreeEntry::blob(secret_hash, false),
            ),
            ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8(".kin-allowances").unwrap(),
                TreeEntry::blob(approvals_hash, false),
            ),
        ])
        .unwrap();

        let (policy, delta) = derive_policy(&blobs, &authority, &empty_policy(), &tree)
            .unwrap_or_else(|error| {
                panic!(
                    "a merged tree carrying .kin-allowances must derive its approvals rather \
                     than refusing: {error:#}"
                )
            });

        assert_eq!(
            policy.sensitive_allowances.len(),
            1,
            "the merged policy must carry the tree's one approval: {:?}",
            policy.sensitive_allowances
        );
        assert_eq!(policy.sensitive_allowances[0].content_hash, secret_hash);
        assert!(
            policy.sources.is_empty(),
            "an approval set is not an exclusion rule source: {:?}",
            policy.sources
        );
        assert!(
            delta.is_some(),
            "a tree that introduces approvals moves the policy, so the merge records a delta"
        );
    }
}
