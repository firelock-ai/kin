// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon-owned repository-v6 rollback authority.
//!
//! A rollback publishes one new change whose content is exactly a change that
//! already exists in this branch's history. Its deltas are derived by comparing
//! two immutable graph states, so every restored artifact keeps the identity
//! and the source CAS entry the target already had, and nothing is rewritten.
//! The change, the branch ref, and the workspace transition are one repository
//! transaction committed alongside the projection, so the repository is never
//! observable at a tree that no ref names.

use anyhow::{bail, Context, Result};
use axum::http::StatusCode;
use kin_cli::commands::rollback::{
    RollbackReport, RollbackRequest, RollbackResponse, ROLLBACK_SCHEMA,
};
use kin_db::ChangeStore;
use kin_model::{
    compute_resolved_tree_hash, compute_semantic_change_id, ChangeOrigin,
    EffectiveAdmissionPolicyStamp, EntityDelta, EntityStore, Hash256, OperationId, RefExpectation,
    RefMutation, RefTarget, RefUpdatePolicy, RelationDelta, RepositoryCommitOutcome,
    RepositoryTransaction, ResolvedTree, SemanticChange, SemanticChangeId, SharedAdmissionPolicy,
    Timestamp, TransactionDelta, WorkspaceExpectation, WorkspaceHead, WorkspaceMutation,
    REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};

use crate::local_repository_authority::{
    require_fresh_daemon_workspace, ActiveLocalRepositoryAuthority, RepositoryAuthorityBindRefusal,
};
use crate::state::{DaemonEvent, DaemonState};

const ROLLBACK_REASON: &str = "publish exact repository-v6 rollback change";

#[derive(Debug)]
struct RollbackConflict(String);

impl std::fmt::Display for RollbackConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RollbackConflict {}

#[derive(Debug)]
struct RollbackBadRequest(String);

impl std::fmt::Display for RollbackBadRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RollbackBadRequest {}

fn conflict(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(RollbackConflict(message.into()))
}

fn bad_request(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(RollbackBadRequest(message.into()))
}

pub(crate) fn execute(
    state: &DaemonState,
    request: &RollbackRequest,
) -> std::result::Result<RollbackResponse, (StatusCode, String)> {
    let graph_mutation = state.begin_graph_authority_mutation();
    let persistence = state.persist_lock.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "daemon persistence lock poisoned".to_string(),
        )
    })?;
    let previous_graph_root = hex::encode(state.graph.compute_root_hash());
    let authority =
        ActiveLocalRepositoryAuthority::open_bound(state).map_err(rollback_bind_refusal)?;
    let execution =
        match plan_and_commit(state, &authority, request).map_err(classify_rollback_error)? {
            RollbackOutcome::Committed(execution) => execution,
            RollbackOutcome::AlreadyCommitted(response) => {
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
            &execution.target_tree,
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
    state.invalidate_projection();

    drop(persistence);
    drop(graph_mutation);
    Ok(execution.response)
}

struct RollbackExecution {
    response: RollbackResponse,
    receipt: kin_model::RepositoryCommitReceipt,
    authority_freeze: kin_db::LocalRepositoryAuthorityFreeze,
    daemon_delta: TransactionDelta,
    previous_tree: ResolvedTree,
    target_tree: ResolvedTree,
}

enum RollbackOutcome {
    Committed(Box<RollbackExecution>),
    /// This operation id already published its rollback. Nothing is committed
    /// and nothing is materialized; the already-published result is reported.
    AlreadyCommitted(RollbackResponse),
}

fn plan_and_commit(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    request: &RollbackRequest,
) -> Result<RollbackOutcome> {
    let target_change_id = parse_change_id(&request.change_id)?;
    let lease = authority.manager.read_authority();
    let roots = lease.roots().clone();
    let metadata = lease.metadata();
    // The client retries a lost response with the same operation id, so an
    // operation that already published must be reported as what it is rather
    // than replanned. Replanning would compare the restored head against the
    // same target, find nothing left to restore, and report a false failure for
    // an operation that succeeded.
    //
    // Whole rather than as persisted: a receipt names its operation record
    // rather than repeating it (kin-db 0.7.89, FIR-3064).
    if let Some(receipt) = kin_core::rejoined_receipt(metadata, request.operation_id) {
        let roots = roots.clone();
        drop(lease);
        return report_already_committed(
            state,
            authority,
            request,
            &roots,
            receipt,
            target_change_id,
        )
        .map(RollbackOutcome::AlreadyCommitted);
    }
    let workspace = metadata
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == authority.workspace_id)
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no workspace {} in repository-v6 authority",
                authority.repository_id,
                authority.workspace_id
            )
        })?;
    workspace
        .validate()
        .context("active repository-v6 workspace is invalid")?;
    // A rollback replaces the complete workspace tree. Graph-owned uncommitted
    // state would be silently destroyed by that, so it is refused rather than
    // absorbed.
    if workspace.is_dirty() {
        return Err(conflict(format!(
            "workspace {} has graph-owned changes; commit or discard them before rolling back",
            workspace.workspace_id
        )));
    }
    let WorkspaceHead::Symbolic { target: branch } = workspace.head.clone() else {
        return Err(conflict(
            "a detached workspace has no branch to publish a rollback onto; switch to a branch \
             first",
        ));
    };
    let current_target = workspace.base_target.clone().ok_or_else(|| {
        conflict(format!(
            "workspace {} is unborn and has nothing to roll back",
            workspace.workspace_id
        ))
    })?;
    if matches!(current_target, RefTarget::Symbolic { .. }) {
        bail!(
            "workspace {} base target is symbolic instead of resolved",
            workspace.workspace_id
        );
    }
    let branch_target = lease
        .resolve_ref_target(&branch)
        .with_context(|| format!("resolve branch {branch} for rollback"))?
        .ok_or_else(|| conflict(format!("branch {branch} does not exist")))?;
    if branch_target != current_target {
        return Err(conflict(format!(
            "branch {branch} does not name the workspace base; reopen the workspace against its \
             branch before rolling back"
        )));
    }
    let previous_change_id = lease
        .resolve_target_change_id(&current_target)
        .context("resolve the change this branch currently names")?;
    let previous_policy = metadata
        .admission_policies
        .iter()
        .find(|resolved| resolved.change_id == previous_change_id)
        .and_then(|resolved| resolved.policy.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "current change {previous_change_id} has no resolved shared admission policy"
            )
        })?;
    let workspace_graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .context("materialize rollback workspace authority")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no graph snapshot for workspace {}",
                authority.repository_id,
                workspace.workspace_id
            )
        })?;
    require_fresh_daemon_workspace(state, &roots, &workspace_graph, "rolling back")
        .map_err(|error| conflict(error.to_string()))?;
    let mut snapshot = lease.snapshot().clone();
    snapshot.repository_authority = None;
    drop(lease);

    let history = kin_db::InMemoryGraph::from_snapshot(snapshot)
        .context("open immutable repository history for rollback")?;
    if history
        .get_change(&target_change_id)
        .context("look up the rollback target")?
        .is_none()
    {
        return Err(conflict(format!(
            "change {target_change_id} is not materialized in this repository"
        )));
    }
    if target_change_id == previous_change_id {
        return Err(conflict(format!(
            "branch {branch} already names change {target_change_id}"
        )));
    }
    if !reaches(&history, previous_change_id, target_change_id)? {
        return Err(conflict(format!(
            "change {target_change_id} is not in the history of {branch}; rollback restores a \
             change this branch already published"
        )));
    }

    let previous_state = history
        .resolve_graph_at(&previous_change_id)
        .with_context(|| format!("resolve the current graph at {previous_change_id}"))?;
    let target_state = history
        .resolve_graph_at(&target_change_id)
        .with_context(|| format!("resolve the restored graph at {target_change_id}"))?;
    let target_tree = target_state.tree.clone();

    let entity_deltas = entity_transition(&previous_state, &target_state);
    let relation_deltas = relation_transition(&previous_state, &target_state);
    let tree_deltas = kin_core::exact_tree_correction(&previous_state.tree, &target_tree)
        .context("plan the exact artifact restoration")?;
    if entity_deltas.is_empty() && relation_deltas.is_empty() && tree_deltas.is_empty() {
        return Err(conflict(format!(
            "change {target_change_id} has the same content as {previous_change_id}; there is \
             nothing to roll back"
        )));
    }

    // Every restored source already exists in repository CAS because the target
    // change was published from it. Reading lengths back through authority
    // proves that, and fails closed if any source is missing.
    let (shared_policy, admission_policy_delta) =
        SharedAdmissionPolicy::derive_from_tree_with_allowances(
            Some(&previous_policy),
            &target_tree,
            |hash| source_body_len(authority, hash),
            |hash| source_body(authority, hash),
        )
        .context("derive the restored shared admission policy")?;

    let mut change = SemanticChange {
        id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
        origin: ChangeOrigin::Native,
        parents: vec![previous_change_id],
        timestamp: Timestamp::now(),
        author: request.actor.clone(),
        message: format!("Roll back to {target_change_id}"),
        entity_deltas: entity_deltas.clone(),
        relation_deltas: relation_deltas.clone(),
        tree_deltas: tree_deltas.clone(),
        admission_policy_delta,
        projected_files: Vec::new(),
        spec_link: None,
        evidence: Vec::new(),
        risk_summary: None,
        external_reference_deltas: Vec::new(),
    };
    change.id =
        compute_semantic_change_id(&change).context("compute the rollback change identity")?;
    let inverse_change_id = change.id;
    // Named rather than inlined into the transaction, so the install after the
    // CAS below is over exactly the set this transaction publishes. A rollback
    // publishes one change today; reading the set rather than a single
    // variable is what keeps the install correct if that ever stops being true.
    let published_changes = vec![change];

    let target_tree_hash =
        compute_resolved_tree_hash(&target_tree).context("hash the restored tree")?;
    let workspace_tree_deltas = kin_core::exact_tree_correction(&workspace.tree, &target_tree)
        .context("plan the exact workspace restoration")?;
    let workspace_semantic_delta = kin_core::diff_workspace_semantics(
        &workspace_graph.entities,
        &workspace_graph.relations,
        &target_state.entities,
        &target_state.relations,
    )
    .context("plan the exact workspace semantic restoration")?;
    let daemon_semantic_delta = crate::local_repository_authority::plan_daemon_semantic_delta(
        state,
        &target_state.entities,
        &target_state.relations,
    )
    .context("plan the exact workspace semantic restoration for the daemon view")?;
    let daemon_delta = TransactionDelta {
        entity_deltas: daemon_semantic_delta.entity_deltas().to_vec(),
        relation_deltas: daemon_semantic_delta.relation_deltas().to_vec(),
        tree_deltas: workspace_tree_deltas.clone(),
        admission_policy_delta: None,
        external_reference_deltas: Vec::new(),
    };
    preflight_rollback_delta(state, &workspace.tree, &target_state, &daemon_delta)?;

    let new_target = RefTarget::change(inverse_change_id);
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: request.operation_id,
        repository_id: authority.repository_id.clone(),
        expected_generation: roots.generation,
        expected_roots: roots,
        actor: request.actor.clone(),
        reason: ROLLBACK_REASON.to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: published_changes.clone(),
        aliases: Vec::new(),
        ref_mutations: vec![RefMutation {
            name: branch.clone(),
            expected: RefExpectation::MustEqual {
                target: current_target,
            },
            new_target: Some(new_target.clone()),
            policy: RefUpdatePolicy::FastForwardOnly,
        }],
        default_ref_mutation: None,
        workspace_mutation: Some(WorkspaceMutation {
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
            new_base_target: Some(new_target),
            new_base_tree_hash: Some(target_tree_hash),
            tree_deltas: workspace_tree_deltas.clone(),
            new_tree_hash: target_tree_hash,
            semantic_delta: workspace_semantic_delta,
            new_shared_admission_policy: shared_policy.clone(),
            new_admission_policy: EffectiveAdmissionPolicyStamp {
                shared: shared_policy.stamp(),
                local: workspace.admission_policy.local,
            },
        }),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: None,
    };
    transaction
        .validate()
        .context("validate the exact rollback transaction")?;

    // The working copy is a derived view of the tree being replaced. Divergence
    // there is reported, never silently overwritten.
    let drift = kin_core::report_repository_workspace_projection_drift(
        state.layout.working_dir(),
        &workspace.tree,
        &authority.manager,
    )
    .context("validate the exact workspace projection before rolling back")?;
    if let Some(first) = drift.first() {
        return Err(kin_core::KinError::projection_conflict(format!(
            "{first}; {} tracked path(s) diverge from the graph-owned workspace projection; \
             reconcile them into graph authority or discard them before rolling back",
            drift.len()
        ))
        .into());
    }

    let (projected_entries, receipt, authority_freeze) =
        kin_core::tree::transition_repository_workspace_tree_and_commit_repository_transaction(
            state.layout.working_dir(),
            &workspace.tree,
            &target_tree,
            &authority.manager,
            transaction,
        )
        .context("publish the rollback change, ref, and workspace atomically")?;

    // The repository transaction is durable authority. The in-process graph is
    // a derived query view; install the exact immutable change only after the
    // authority CAS succeeds. This is the same contract
    // `command_commit_after_admission` states and follows for a commit, and
    // this path did not follow it: the change reached authority and the live
    // graph never learned of it, so every read that replays the graph to that
    // change failed until the daemon restarted and rebuilt from authority.
    // `kin blame` and `kin history` were the reads that failed; `kin log`,
    // `kin diff`, `kin status` and `kin graph status` answered from authority
    // and did not.
    //
    // Every change this transaction published, in the order it published them.
    // A rollback publishes exactly one, the inverse change whose id is
    // `inverse_change_id` and which the report carries as a single field, but
    // the loop reads the published set rather than that one variable so the
    // install cannot silently cover less than the transaction did.
    //
    // Installed on an idempotent replay too, not only on a fresh commit. A
    // replay means an earlier attempt published the change, and if that attempt
    // was the one that missed this install then the graph is still missing it;
    // installing an identical payload under an identical id is a no-op in
    // kin-db rather than a conflict.
    for published in &published_changes {
        state
            .graph
            .create_change(published)
            .context("install the published rollback change in the live graph")?;
    }

    let report = RollbackReport {
        schema: ROLLBACK_SCHEMA.to_string(),
        authority: "repository-v6".to_string(),
        repository_id: authority.repository_id.clone(),
        branch,
        target_change_id: target_change_id.to_string(),
        previous_change_id: previous_change_id.to_string(),
        inverse_change_id: inverse_change_id.to_string(),
        authority_generation: receipt.generation,
        workspace_generation: workspace.generation.saturating_add(1),
        entity_deltas: entity_deltas.len(),
        relation_deltas: relation_deltas.len(),
        tree_deltas: tree_deltas.len(),
        projected_entries,
        idempotent: matches!(receipt.outcome, RepositoryCommitOutcome::IdempotentReplay),
    };
    Ok(RollbackOutcome::Committed(Box::new(RollbackExecution {
        response: RollbackResponse {
            lines: kin_cli::commands::rollback::render_lines(&report),
            mutated: matches!(receipt.outcome, RepositoryCommitOutcome::Committed),
            report: Some(report),
        },
        receipt,
        authority_freeze,
        daemon_delta,
        previous_tree: workspace.tree,
        target_tree,
    })))
}

/// Report an operation this repository already published.
///
/// This path commits nothing and materializes nothing. It proves the retained
/// receipt restored exactly the change this request names, that authority has
/// not moved past it, and that the derived projection still matches the
/// workspace the receipt published. Anything else is a refusal: a stale or
/// foreign receipt must never be reported as this caller's success.
fn report_already_committed(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    request: &RollbackRequest,
    current_roots: &kin_model::RootBundle,
    receipt: kin_model::RepositoryCommitReceipt,
    target_change_id: SemanticChangeId,
) -> Result<RollbackResponse> {
    receipt
        .validate()
        .context("validate the persisted rollback receipt")?;
    if current_roots != &receipt.roots_after {
        return Err(conflict(format!(
            "rollback operation {} committed at generation {}, but authority is now at generation \
             {}; reopen against current authority before retrying",
            request.operation_id, receipt.generation, current_roots.generation
        )));
    }
    let [mutation] = receipt.operation.ref_mutations.as_slice() else {
        return Err(conflict(format!(
            "operation {} was already committed for a different request",
            request.operation_id
        )));
    };
    let Some(RefTarget::Change {
        change_id: inverse_change_id,
    }) = mutation.new_target.clone()
    else {
        return Err(conflict(format!(
            "operation {} was already committed for a different request",
            request.operation_id
        )));
    };
    let workspace_mutation = receipt
        .operation
        .workspace_mutation
        .as_ref()
        .ok_or_else(|| {
            conflict(format!(
                "operation {} was already committed for a different request",
                request.operation_id
            ))
        })?;
    let previous_change_id = match &mutation.expected {
        RefExpectation::MustEqual {
            target: RefTarget::Change { change_id },
        } => *change_id,
        _ => {
            return Err(conflict(format!(
                "operation {} was already committed for a different request",
                request.operation_id
            )))
        }
    };

    let lease = authority.manager.read_authority();
    let workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == authority.workspace_id)
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no workspace {} in repository-v6 authority",
                authority.repository_id,
                authority.workspace_id
            )
        })?;
    let mut snapshot = lease.snapshot().clone();
    snapshot.repository_authority = None;
    drop(lease);
    if workspace.generation != workspace_mutation.new_generation
        || workspace.tree_hash != workspace_mutation.new_tree_hash
    {
        return Err(conflict(format!(
            "rollback operation {} no longer matches current workspace authority",
            request.operation_id
        )));
    }

    let history = kin_db::InMemoryGraph::from_snapshot(snapshot)
        .context("open immutable repository history for an already-published rollback")?;
    require_receipt_restored_request(
        &history,
        request.operation_id,
        target_change_id,
        previous_change_id,
        inverse_change_id,
    )?;

    // The transition published its projection in the same operation, so there
    // is nothing to recover; verifying it proves that, and refuses instead of
    // reporting success over a projection that no longer matches.
    let (projected_entries, authority_freeze) = kin_core::verify_repository_workspace_projection(
        state.layout.working_dir(),
        &workspace.tree,
        &authority.manager,
    )
    .context("verify the projection an already-published rollback materialized")?;
    drop(authority_freeze);

    let report = RollbackReport {
        schema: ROLLBACK_SCHEMA.to_string(),
        authority: "repository-v6".to_string(),
        repository_id: authority.repository_id.clone(),
        branch: mutation.name.clone(),
        target_change_id: target_change_id.to_string(),
        previous_change_id: previous_change_id.to_string(),
        inverse_change_id: inverse_change_id.to_string(),
        authority_generation: receipt.generation,
        workspace_generation: workspace.generation,
        entity_deltas: workspace_mutation.semantic_delta.entity_deltas().len(),
        relation_deltas: workspace_mutation.semantic_delta.relation_deltas().len(),
        tree_deltas: workspace_mutation.tree_deltas.len(),
        projected_entries,
        idempotent: true,
    };
    Ok(RollbackResponse {
        lines: kin_cli::commands::rollback::render_lines(&report),
        mutated: false,
        report: Some(report),
    })
}

/// Prove a retained receipt published exactly the rollback this request names.
///
/// Receipts are matched on operation id alone, and an ordinary commit carries
/// the same receipt shape a rollback does: one ref mutation onto a change under
/// a `MustEqual` expectation, alongside a workspace mutation. Only the restored
/// content separates them. The change the receipt published must therefore
/// resolve to exactly the tree the requested change resolves to, and that
/// change must already be in the history the receipt published over. Otherwise
/// the receipt belongs to some other operation that reused this id, and
/// reporting it would claim a rollback that never happened.
fn require_receipt_restored_request(
    history: &kin_db::InMemoryGraph,
    operation_id: OperationId,
    target_change_id: SemanticChangeId,
    previous_change_id: SemanticChangeId,
    inverse_change_id: SemanticChangeId,
) -> Result<()> {
    if history
        .get_change(&target_change_id)
        .context("look up the rollback target")?
        .is_none()
    {
        return Err(conflict(format!(
            "change {target_change_id} is not materialized in this repository"
        )));
    }
    if history
        .get_change(&inverse_change_id)
        .context("look up the change an already-published operation committed")?
        .is_none()
    {
        return Err(conflict(format!(
            "operation {operation_id} published change {inverse_change_id}, which is not \
             materialized in this repository"
        )));
    }
    if !reaches(history, previous_change_id, target_change_id)? {
        return Err(conflict(format!(
            "change {target_change_id} is not in the history of {previous_change_id}; rollback \
             restores a change this branch already published"
        )));
    }
    if resolved_tree_hash_at(history, inverse_change_id)?
        != resolved_tree_hash_at(history, target_change_id)?
    {
        return Err(conflict(format!(
            "operation {operation_id} published change {inverse_change_id}, which does not \
             restore change {target_change_id}; it was already committed for a different request"
        )));
    }
    Ok(())
}

fn resolved_tree_hash_at(
    history: &kin_db::InMemoryGraph,
    change_id: SemanticChangeId,
) -> Result<Hash256> {
    let state = history
        .resolve_graph_at(&change_id)
        .with_context(|| format!("resolve the repository graph at {change_id}"))?;
    compute_resolved_tree_hash(&state.tree)
        .with_context(|| format!("hash the repository tree at {change_id}"))
}

/// Whether `head` reaches `ancestor` through the immutable change DAG.
fn reaches(
    history: &kin_db::InMemoryGraph,
    head: SemanticChangeId,
    ancestor: SemanticChangeId,
) -> Result<bool> {
    let mut pending = vec![head];
    let mut visited = std::collections::HashSet::new();
    while let Some(current) = pending.pop() {
        if current == ancestor {
            return Ok(true);
        }
        if !visited.insert(current) {
            continue;
        }
        let Some(change) = history
            .get_change(&current)
            .with_context(|| format!("walk repository history at {current}"))?
        else {
            continue;
        };
        pending.extend(change.parents.iter().copied());
    }
    Ok(false)
}

fn entity_transition(
    previous: &kin_model::graph::ResolvedGraphState,
    target: &kin_model::graph::ResolvedGraphState,
) -> Vec<EntityDelta> {
    let mut deltas = Vec::new();
    for (entity_id, entity) in &target.entities {
        match previous.entities.get(entity_id) {
            None => deltas.push(EntityDelta::Added {
                new: entity.clone(),
            }),
            Some(old) if old != entity => deltas.push(EntityDelta::Modified {
                old: old.clone(),
                new: entity.clone(),
            }),
            _ => {}
        }
    }
    for (entity_id, entity) in &previous.entities {
        if !target.entities.contains_key(entity_id) {
            deltas.push(EntityDelta::Removed {
                old: entity.clone(),
            });
        }
    }
    deltas.sort_by_key(EntityDelta::target_id);
    deltas
}

fn relation_transition(
    previous: &kin_model::graph::ResolvedGraphState,
    target: &kin_model::graph::ResolvedGraphState,
) -> Vec<RelationDelta> {
    let mut deltas = Vec::new();
    for (relation_id, relation) in &target.relations {
        match previous.relations.get(relation_id) {
            None => deltas.push(RelationDelta::Added {
                new: relation.clone(),
            }),
            Some(old) if old != relation => deltas.push(RelationDelta::Modified {
                old: old.clone(),
                new: relation.clone(),
            }),
            _ => {}
        }
    }
    for (relation_id, relation) in &previous.relations {
        if !target.relations.contains_key(relation_id) {
            deltas.push(RelationDelta::Removed {
                old: relation.clone(),
            });
        }
    }
    deltas.sort_by_key(RelationDelta::target_id);
    deltas
}

fn source_body(
    authority: &ActiveLocalRepositoryAuthority,
    hash: Hash256,
) -> std::result::Result<Vec<u8>, kin_model::ModelError> {
    authority
        .manager
        .load_source_blob(hash)
        .map_err(|error| {
            kin_model::ModelError::InvalidOperation(format!(
                "read restored admission source {hash}: {error}"
            ))
        })?
        .ok_or_else(|| {
            kin_model::ModelError::InvalidOperation(format!(
                "repository source CAS is missing restored admission source {hash}"
            ))
        })
}

fn source_body_len(
    authority: &ActiveLocalRepositoryAuthority,
    hash: Hash256,
) -> std::result::Result<u64, kin_model::ModelError> {
    let body = authority
        .manager
        .load_source_blob(hash)
        .map_err(|error| {
            kin_model::ModelError::InvalidOperation(format!(
                "read restored admission source {hash}: {error}"
            ))
        })?
        .ok_or_else(|| {
            kin_model::ModelError::InvalidOperation(format!(
                "repository source CAS is missing restored admission source {hash}"
            ))
        })?;
    u64::try_from(body.len()).map_err(|_| {
        kin_model::ModelError::InvalidOperation(format!(
            "restored admission source {hash} exceeds u64"
        ))
    })
}

/// Prove the daemon's live graph reaches exactly the restored state before the
/// projection or authority is touched.
fn preflight_rollback_delta(
    state: &DaemonState,
    previous_tree: &ResolvedTree,
    desired: &kin_model::graph::ResolvedGraphState,
    delta: &TransactionDelta,
) -> Result<()> {
    let live_tree = state.graph.resolved_tree();
    if live_tree != *previous_tree && live_tree != desired.tree {
        return Err(conflict(
            "daemon query tree matches neither the rollback base nor the restored authority",
        ));
    }
    let preflight = kin_db::InMemoryGraph::from_snapshot(state.graph.to_snapshot())
        .context("prepare the rollback daemon graph preflight")?;
    preflight
        .apply_transaction_delta(delta)
        .context("apply the rollback daemon graph preflight")?;
    let snapshot = preflight.to_snapshot();
    if snapshot.resolved_tree != desired.tree
        || snapshot.entities != desired.entities
        || snapshot.relations != desired.relations
    {
        bail!(
            "the rollback preflighted to a graph and tree that do not match the state it is \
             restoring, so kin refused to publish it; your workspace is unchanged, so run \
             `kin status` and try again"
        );
    }
    Ok(())
}

fn parse_change_id(value: &str) -> Result<SemanticChangeId> {
    let hash = Hash256::from_hex(value).map_err(|_| {
        bad_request(format!(
            "invalid change id '{value}': expected a canonical 64-character hash"
        ))
    })?;
    if hash.to_string() != value {
        return Err(bad_request(
            "change id must use canonical lowercase hexadecimal encoding",
        ));
    }
    Ok(SemanticChangeId::from_hash(hash))
}

fn classify_rollback_error(error: anyhow::Error) -> (StatusCode, String) {
    if error.downcast_ref::<RollbackBadRequest>().is_some() {
        return (StatusCode::BAD_REQUEST, crate::error::cause_first(&error));
    }
    if error.downcast_ref::<RollbackConflict>().is_some() {
        return (StatusCode::CONFLICT, crate::error::cause_first(&error));
    }
    if let Some(core) = error.downcast_ref::<kin_core::KinError>() {
        let status = match core {
            kin_core::KinError::RepositoryConflict(_)
            | kin_core::KinError::ProjectionConflict(_) => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return (status, crate::error::cause_first(&error));
    }
    if let Some(model) = error.downcast_ref::<kin_model::ModelError>() {
        let status = match model {
            kin_model::ModelError::InvalidHash(_) | kin_model::ModelError::InvalidOperation(_) => {
                StatusCode::BAD_REQUEST
            }
            kin_model::ModelError::Conflict(_)
            | kin_model::ModelError::RefNotFound(_)
            | kin_model::ModelError::WorkspaceNotFound(_)
            | kin_model::ModelError::ChangeNotFound(_) => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return (status, crate::error::cause_first(&error));
    }
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        crate::error::cause_first(&error),
    )
}

fn repository_finalization_error(error: crate::error::DaemonError) -> (StatusCode, String) {
    use crate::error::DaemonError;
    let status = match &error {
        DaemonError::Graph(kin_db::KinDbError::Model(kin_model::ModelError::Conflict(_)))
        | DaemonError::IncompatibleRepo(_) => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, error.to_string())
}

fn rollback_bind_refusal(refusal: RepositoryAuthorityBindRefusal) -> (StatusCode, String) {
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
