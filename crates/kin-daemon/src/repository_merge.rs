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
    MergeConflict, MergeConflictScope, MergeOutcome, MergeReport, MergeRequest, MergeResponse,
    MERGE_REPORT_SCHEMA,
};
use kin_db::LocalRepositoryAuthorityFreeze;
use kin_model::{
    compute_resolved_tree_hash, compute_semantic_change_id, ChangeOrigin, ChangeStore,
    EffectiveAdmissionPolicyStamp, EntityStore, Hash256, ModelError, RefExpectation, RefMutation,
    RefName, RefTarget, RefUpdatePolicy, RepositoryCommitOutcome, RepositoryCommitReceipt,
    RepositoryTransaction, ResolvedArtifact, ResolvedTree, RootBundle, SemanticChange,
    SemanticChangeId, SharedAdmissionPolicy, Timestamp, TransactionDelta, WorkspaceExpectation,
    WorkspaceHead, WorkspaceMutation, WorkspaceSemanticDelta, WorkspaceState,
    REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};

use crate::local_repository_authority::{
    require_fresh_daemon_workspace, ActiveLocalRepositoryAuthority, RepositoryAuthorityBindRefusal,
};
use crate::state::{DaemonEvent, DaemonState};

const MERGE_REASON: &str = "publish exact repository-v6 semantic merge";
const FAST_FORWARD_REASON: &str = "advance exact repository-v6 branch to a descendant";

/// How many conflicts a refusal names individually before summarizing. The
/// total is always stated, so the message never reads as a complete list when
/// it is truncated.
const RENDERED_CONFLICT_LIMIT: usize = 25;

struct MergeExecution {
    response: MergeResponse,
    receipt: RepositoryCommitReceipt,
    authority_freeze: LocalRepositoryAuthorityFreeze,
    daemon_delta: TransactionDelta,
    previous_tree: ResolvedTree,
    desired_tree: ResolvedTree,
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

fn merge_conflict(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(MergeConflictRefusal(message.into()))
}

fn merge_bad_request(message: impl Into<String>) -> anyhow::Error {
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
                "branch {} and the active branch {} share no common change; merging unrelated \
                 histories is not a proven repository-v6 shape",
                request.source, plan.target_ref
            )))
        }
        [base] => *base,
        multiple => {
            return Err(merge_conflict(format!(
                "branch {} and the active branch {} have {} merge bases; a criss-cross merge is \
                 not a proven repository-v6 shape",
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
    let daemon_delta = TransactionDelta {
        entity_deltas: semantic_delta.entity_deltas().to_vec(),
        relation_deltas: semantic_delta.relation_deltas().to_vec(),
        tree_deltas: tree_deltas.clone(),
        admission_policy_delta: None,
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
        |entity| MergeConflictScope::Entity {
            entity: *entity,
            name: describe_entity(&ours_state.entities, &theirs_state.entities, entity),
        },
        &mut conflicts,
    );
    let merged_relations = compose(
        &base_state.relations,
        &ours_state.relations,
        &theirs_state.relations,
        |relation| MergeConflictScope::Relation {
            relation: *relation,
        },
        &mut conflicts,
    );
    let merged_artifacts = compose(
        &artifacts_by_id(&base_state.tree),
        &artifacts_by_id(&ours_state.tree),
        &artifacts_by_id(&theirs_state.tree),
        |artifact| MergeConflictScope::Artifact {
            artifact: *artifact,
            path: ours_state
                .tree
                .get(artifact)
                .or_else(|| theirs_state.tree.get(artifact))
                .map(|resolved| resolved.path.to_string()),
        },
        &mut conflicts,
    );
    let mut claimed: BTreeMap<&kin_model::RepoPath, usize> = BTreeMap::new();
    for artifact in merged_artifacts.values() {
        *claimed.entry(&artifact.path).or_default() += 1;
    }
    for (path, count) in claimed {
        if count > 1 {
            conflicts.push(MergeConflict {
                scope: MergeConflictScope::Path {
                    path: path.to_string(),
                },
                detail: format!(
                    "{count} distinct artifacts occupy this path after composing both sides"
                ),
            });
        }
    }
    if !conflicts.is_empty() {
        return Err(conflict_refusal(request, &plan, &conflicts));
    }

    let desired_tree = ResolvedTree::from_artifacts(merged_artifacts.into_values())
        .context("compose exact merged repository tree")?;
    let (shared_policy, admission_policy_delta) =
        derive_policy(state, &plan.ours_policy, &desired_tree)?;
    if admission_policy_delta.is_some() || shared_policy != plan.ours_policy {
        return Err(merge_conflict(format!(
            "merging {} into {} changes the shared admission policy; a merge that transitions \
             admission policy is not a proven repository-v6 shape",
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
        bail!("replaying the merge change did not reproduce the composed merged tree");
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
    let daemon_delta = TransactionDelta {
        entity_deltas: workspace_semantic_delta.entity_deltas().to_vec(),
        relation_deltas: workspace_semantic_delta.relation_deltas().to_vec(),
        tree_deltas: workspace_tree_deltas.clone(),
        admission_policy_delta: None,
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

/// Compose one identity-keyed dimension of the three-way merge.
///
/// Every decision is by exact value equality against the merge base, so a side
/// that did not move never overrides a side that did, and both sides moving to
/// the same value is agreement rather than conflict.
fn compose<K, V, S>(
    base: &std::collections::HashMap<K, V>,
    ours: &std::collections::HashMap<K, V>,
    theirs: &std::collections::HashMap<K, V>,
    scope: S,
    conflicts: &mut Vec<MergeConflict>,
) -> std::collections::HashMap<K, V>
where
    K: Copy + Ord + std::hash::Hash,
    V: Clone + PartialEq,
    S: Fn(&K) -> MergeConflictScope,
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
            conflicts.push(MergeConflict {
                scope: scope(&id),
                detail: describe_divergence(
                    base_side.is_some(),
                    our_side.is_some(),
                    their_side.is_some(),
                ),
            });
            continue;
        };
        if let Some(value) = resolved {
            merged.insert(id, value.clone());
        }
    }
    merged
}

fn describe_divergence(in_base: bool, in_ours: bool, in_theirs: bool) -> String {
    match (in_base, in_ours, in_theirs) {
        (_, false, true) => {
            "removed on the active branch and changed on the source branch".to_string()
        }
        (_, true, false) => {
            "changed on the active branch and removed on the source branch".to_string()
        }
        (false, true, true) => {
            "added independently on both branches with different content".to_string()
        }
        _ => "changed on both branches with different content".to_string(),
    }
}

fn artifacts_by_id(
    tree: &ResolvedTree,
) -> std::collections::HashMap<kin_model::ArtifactId, ResolvedArtifact> {
    tree.artifacts()
        .map(|artifact| (artifact.artifact_id, artifact.clone()))
        .collect()
}

fn derive_policy(
    state: &DaemonState,
    parent: &SharedAdmissionPolicy,
    tree: &ResolvedTree,
) -> Result<(
    SharedAdmissionPolicy,
    Option<kin_model::AdmissionPolicyDelta>,
)> {
    let mut lengths: BTreeMap<Hash256, u64> = BTreeMap::new();
    SharedAdmissionPolicy::derive_from_tree(Some(parent), tree, |hash| {
        if let Some(length) = lengths.get(&hash) {
            return Ok(*length);
        }
        let body = state
            .blobs
            .read(&kin_blobs::Hash256::from_bytes(*hash.as_bytes()))
            .map_err(|error| {
                ModelError::InvalidOperation(format!(
                    "read graph-owned admission source {hash}: {error}"
                ))
            })?;
        let length = u64::try_from(body.len()).map_err(|_| {
            ModelError::InvalidOperation(format!("graph-owned admission source {hash} exceeds u64"))
        })?;
        lengths.insert(hash, length);
        Ok(length)
    })
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
        new_generation: workspace
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("workspace generation overflow"))?,
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
        bail!("merge daemon graph preflight did not produce the exact merged tree");
    }
    if snapshot.entities != *desired_entities || snapshot.relations != *desired_relations {
        bail!("merge daemon graph preflight did not produce the exact merged semantics");
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

fn conflict_refusal(
    request: &MergeRequest,
    plan: &MergePlan,
    conflicts: &[MergeConflict],
) -> anyhow::Error {
    let mut message = format!(
        "merging {} into {} has {} unresolved conflict(s); repository-v6 has no durable merge \
         transaction to hold them, so nothing was published",
        request.source,
        plan.target_ref,
        conflicts.len()
    );
    for conflict in conflicts.iter().take(RENDERED_CONFLICT_LIMIT) {
        message.push_str(&format!(
            "\n  - {}: {}",
            render_scope(&conflict.scope),
            conflict.detail
        ));
    }
    if conflicts.len() > RENDERED_CONFLICT_LIMIT {
        message.push_str(&format!(
            "\n  - ... and {} further conflict(s) not listed",
            conflicts.len() - RENDERED_CONFLICT_LIMIT
        ));
    }
    merge_conflict(message)
}

fn render_scope(scope: &MergeConflictScope) -> String {
    match scope {
        MergeConflictScope::Entity {
            entity,
            name: Some(name),
        } => format!("entity {name} ({entity})"),
        MergeConflictScope::Entity { entity, name: None } => format!("entity {entity}"),
        MergeConflictScope::Relation { relation } => format!("relation {relation}"),
        MergeConflictScope::Artifact {
            path: Some(path), ..
        } => format!("artifact {path}"),
        MergeConflictScope::Artifact { artifact, .. } => format!("artifact {artifact:?}"),
        MergeConflictScope::Path { path } => format!("path {path}"),
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

fn local_workspace<'a>(
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

fn classify_merge_error(error: anyhow::Error) -> (StatusCode, String) {
    if error.downcast_ref::<MergeBadRequest>().is_some() {
        return (StatusCode::BAD_REQUEST, format!("{error:#}"));
    }
    if error.downcast_ref::<MergeConflictRefusal>().is_some() {
        return (StatusCode::CONFLICT, format!("{error:#}"));
    }
    if let Some(core) = error.downcast_ref::<kin_core::KinError>() {
        let status = match core {
            kin_core::KinError::Model(model) => merge_model_status(model),
            kin_core::KinError::RepositoryConflict(_)
            | kin_core::KinError::ProjectionConflict(_) => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return (status, format!("{error:#}"));
    }
    if let Some(database) = error.downcast_ref::<kin_db::KinDbError>() {
        let status = match database {
            kin_db::KinDbError::Model(model) => merge_model_status(model),
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return (status, format!("{error:#}"));
    }
    if let Some(model) = error.downcast_ref::<kin_model::ModelError>() {
        return (merge_model_status(model), format!("{error:#}"));
    }
    (StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}"))
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

fn repository_finalization_error(error: crate::error::DaemonError) -> (StatusCode, String) {
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

fn merge_bind_refusal(refusal: RepositoryAuthorityBindRefusal) -> (StatusCode, String) {
    let identity = refusal.is_identity_refusal();
    let error = refusal.into_error();
    if identity {
        (StatusCode::CONFLICT, format!("{error:#}"))
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}"))
    }
}
