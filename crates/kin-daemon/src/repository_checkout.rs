// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon-owned exact selected-path checkout over repository-v6 authority.

use std::collections::HashSet;
use std::sync::atomic::Ordering;

use anyhow::{bail, Context, Result};
use axum::http::StatusCode;
use kin_cli::commands::checkout::{
    parse_checkout_path, CheckoutReport, CheckoutRequest, CheckoutResponse,
};
use kin_db::LocalRepositoryAuthorityFreeze;
use kin_model::graph::ResolvedGraphState;
use kin_model::{
    compute_resolved_tree_hash, ArtifactId, ChangeStore, Hash256, RepoPath,
    RepositoryCommitReceipt, RepositoryTransaction, ResolvedArtifact, ResolvedTree, RootBundle,
    SemanticChangeId, TransactionDelta, TreeDelta, WorkspaceExpectation, WorkspaceId,
    WorkspaceMutation, WorkspaceSemanticDelta, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};

use crate::error::DaemonError;
use crate::local_repository_authority::{
    require_fresh_daemon_workspace, ActiveLocalRepositoryAuthority, RepositoryAuthorityBindRefusal,
};
use crate::state::{DaemonEvent, DaemonState};

#[derive(Debug, Clone)]
struct CheckoutGraphPlan {
    selected: RepoPath,
    target_state: ResolvedGraphState,
    previous_tree: ResolvedTree,
    desired_tree: ResolvedTree,
}

/// Exact durable effect of a checkout request.
///
/// Repository transitions carry their authenticated receipt and the complete
/// graph-history inputs needed for daemon preflight/finalization. Projection
/// repair carries only the frozen workspace authority because it must never be
/// represented as a graph-root mutation.
#[derive(Debug)]
enum CheckoutAuthorityEffect {
    RepositoryCommit {
        receipt: RepositoryCommitReceipt,
        graph_plan: CheckoutGraphPlan,
        daemon_delta: TransactionDelta,
        authority_freeze: LocalRepositoryAuthorityFreeze,
    },
    ProjectionOnly {
        roots: RootBundle,
        workspace_tree: ResolvedTree,
        workspace_tree_hash: Hash256,
        projection_changed: bool,
        authority_freeze: LocalRepositoryAuthorityFreeze,
    },
}

/// Command response plus the exact authority state the daemon must install.
#[derive(Debug)]
struct CheckoutExecution {
    response: CheckoutResponse,
    effect: CheckoutAuthorityEffect,
}

#[derive(Debug)]
enum CheckoutCommandError {
    BadRequest(anyhow::Error),
    Conflict(anyhow::Error),
    Internal(anyhow::Error),
}

impl CheckoutCommandError {
    fn bad_request(error: anyhow::Error) -> Self {
        Self::BadRequest(error)
    }

    fn conflict(error: anyhow::Error) -> Self {
        Self::Conflict(error)
    }

    fn internal(error: anyhow::Error) -> Self {
        Self::Internal(error)
    }

    fn into_http(self) -> (StatusCode, String) {
        match self {
            Self::BadRequest(error) => (StatusCode::BAD_REQUEST, crate::error::cause_first(&error)),
            Self::Conflict(error) => (StatusCode::CONFLICT, crate::error::cause_first(&error)),
            Self::Internal(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                crate::error::cause_first(&error),
            ),
        }
    }
}

impl From<anyhow::Error> for CheckoutCommandError {
    fn from(error: anyhow::Error) -> Self {
        Self::Internal(error)
    }
}

impl From<kin_model::ModelError> for CheckoutCommandError {
    fn from(error: kin_model::ModelError) -> Self {
        classify_model_checkout_error(error, "validate checkout repository operation")
    }
}

type CheckoutCommandResult<T> = std::result::Result<T, CheckoutCommandError>;

/// Execute and finalize one checkout while the API handler holds the daemon's
/// coordination gate. The repository authority freeze never leaves this
/// daemon-private module.
pub(crate) fn execute(
    state: &DaemonState,
    request: &CheckoutRequest,
) -> std::result::Result<CheckoutResponse, (StatusCode, String)> {
    let graph_mutation = state.begin_graph_authority_mutation();
    let persistence = state.persist_lock.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "daemon persistence lock poisoned".to_string(),
        )
    })?;
    let previous_graph_root = hex::encode(state.graph.compute_root_hash());
    let execution = plan_and_commit(state, request).map_err(CheckoutCommandError::into_http)?;
    let response = execution.response;
    match execution.effect {
        CheckoutAuthorityEffect::RepositoryCommit {
            receipt,
            graph_plan,
            daemon_delta,
            authority_freeze,
        } => {
            let finalization = state
                .finalize_local_repository_commit(
                    &receipt,
                    &authority_freeze,
                    &daemon_delta,
                    &graph_plan.previous_tree,
                    &graph_plan.desired_tree,
                )
                .map_err(repository_commit_error)?;
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
                    repository_id: receipt.repository_id.to_string(),
                    operation_id: receipt.operation_id,
                    previous_generation: receipt.roots_before.generation,
                    new_generation: receipt.generation,
                });
            }
        }
        CheckoutAuthorityEffect::ProjectionOnly {
            roots,
            workspace_tree,
            workspace_tree_hash,
            projection_changed,
            authority_freeze,
        } => {
            if authority_freeze.roots() != &roots {
                return Err((
                    StatusCode::CONFLICT,
                    "projection-only checkout lost its exact repository authority freeze"
                        .to_string(),
                ));
            }
            let live_generation = state.snapshot_generation.load(Ordering::SeqCst);
            let live_tree_hash =
                compute_resolved_tree_hash(&state.graph.resolved_tree()).map_err(internal_error)?;
            if live_generation != roots.generation
                || state.graph.resolved_tree() != workspace_tree
                || live_tree_hash != workspace_tree_hash
            {
                return Err((
                    StatusCode::CONFLICT,
                    "projection-only checkout observed authority that is not installed in the \
                     daemon; reopen from repository authority"
                        .to_string(),
                ));
            }
            if projection_changed {
                state.invalidate_projection();
            }
        }
    }
    drop(persistence);
    drop(graph_mutation);
    Ok(response)
}

fn plan_and_commit(
    state: &DaemonState,
    request: &CheckoutRequest,
) -> CheckoutCommandResult<CheckoutExecution> {
    let layout = &state.layout;
    let selected = parse_checkout_path(request.path.as_deref(), request.path_hex.as_deref())
        .map_err(CheckoutCommandError::bad_request)?;
    let authority = ActiveLocalRepositoryAuthority::open_bound(state)
        .map_err(classify_authority_bind_refusal)?;
    let lease = authority.manager.read_authority();
    let roots = lease.roots().clone();
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
    let target_change_id = match request.change_id.as_deref() {
        Some(value) => {
            let hash = Hash256::from_hex(value).map_err(|_| {
                CheckoutCommandError::bad_request(anyhow::anyhow!(
                    "invalid change id '{value}': expected a canonical 64-character hash"
                ))
            })?;
            if hash.to_string() != value {
                return Err(CheckoutCommandError::bad_request(anyhow::anyhow!(
                    "change id must use canonical lowercase hexadecimal encoding"
                )));
            }
            SemanticChangeId::from_hash(hash)
        }
        None => {
            let base = workspace.base_target.as_ref().ok_or_else(|| {
                CheckoutCommandError::conflict(anyhow::anyhow!(
                    "workspace {} is unborn and has no base tree to restore",
                    workspace.workspace_id
                ))
            })?;
            lease.resolve_target_change_id(base).map_err(|error| {
                classify_graph_checkout_error(
                    error,
                    "resolve current symbolic or detached workspace base",
                )
            })?
        }
    };
    let actor = request.actor.clone();
    let reason = checkout_reason(&selected, &target_change_id);
    let existing_receipt = lease
        .metadata()
        .receipts
        .iter()
        .find(|receipt| receipt.operation_id == request.operation_id)
        .cloned();
    // Materialized only on the planning path. A replay returns before the
    // authority transition is planned, so demanding a workspace authority
    // graph there would fail a recovery that can otherwise complete.
    let workspace_graph = if existing_receipt.is_none() {
        let workspace_graph = lease
            .workspace_graph_snapshot(&workspace.workspace_id)
            .map_err(|error| {
                classify_graph_checkout_error(error, "materialize checkout workspace authority")
            })?
            .ok_or_else(|| {
                CheckoutCommandError::internal(anyhow::anyhow!(
                    "repository {} has no graph snapshot for workspace {}",
                    authority.repository_id,
                    workspace.workspace_id
                ))
            })?;
        require_fresh_daemon_workspace(state, &roots, &workspace_graph, "checking out a path")
            .map_err(CheckoutCommandError::conflict)?;
        Some(workspace_graph)
    } else {
        None
    };
    let mut snapshot = lease.snapshot().clone();
    snapshot.repository_authority = None;
    drop(lease);

    let graph = kin_db::InMemoryGraph::from_snapshot(snapshot)
        .context("prepare immutable checkout target graph")?;
    let target_state = graph.resolve_graph_at(&target_change_id).map_err(|error| {
        classify_graph_checkout_error(
            error,
            format!("resolve exact checkout graph at {target_change_id}"),
        )
    })?;
    let target_tree = target_state.tree.clone();

    if let Some(receipt) = existing_receipt {
        receipt
            .validate()
            .context("validate persisted checkout receipt")?;
        let replay_transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: request.operation_id,
            repository_id: authority.repository_id.clone(),
            expected_generation: receipt.roots_before.generation,
            expected_roots: receipt.roots_before.clone(),
            actor: actor.clone(),
            reason: reason.clone(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: Vec::new(),
            aliases: Vec::new(),
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: receipt.operation.workspace_mutation.clone(),
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        let replay_hash = replay_transaction
            .transaction_hash()
            .context("reconstruct exact checkout transaction identity")?;
        if replay_hash != receipt.transaction_hash {
            return Err(CheckoutCommandError::conflict(anyhow::anyhow!(
                "checkout operation {} was already committed for a different path or target",
                request.operation_id
            )));
        }
        if roots != receipt.roots_after {
            return Err(CheckoutCommandError::conflict(anyhow::anyhow!(
                "checkout operation {} committed at repository generation {}, but authority is now \
                 at generation {}; reopen against current authority before retrying",
                request.operation_id,
                receipt.generation,
                roots.generation
            )));
        }
        let mutation = receipt
            .operation
            .workspace_mutation
            .as_ref()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("checkout receipt has no workspace mutation"))?;
        if mutation.workspace_id != workspace.workspace_id
            || mutation.new_generation != workspace.generation
            || mutation.new_tree_hash != workspace.tree_hash
        {
            return Err(CheckoutCommandError::conflict(anyhow::anyhow!(
                "checkout receipt workspace effect does not match current repository authority"
            )));
        }
        let inverse = mutation
            .tree_deltas
            .iter()
            .map(TreeDelta::inverse)
            .collect::<Vec<_>>();
        let previous_tree = workspace
            .tree
            .apply(&inverse)
            .context("reconstruct pre-checkout workspace tree from persisted receipt")?;
        let previous_tree_hash = compute_resolved_tree_hash(&previous_tree)
            .context("hash reconstructed pre-checkout workspace tree")?;
        let WorkspaceExpectation::MustEqual {
            tree_hash: expected_tree_hash,
            ..
        } = &mutation.expected
        else {
            return Err(CheckoutCommandError::internal(anyhow::anyhow!(
                "checkout receipt unexpectedly creates a new workspace"
            )));
        };
        if previous_tree_hash != *expected_tree_hash {
            return Err(CheckoutCommandError::internal(anyhow::anyhow!(
                "checkout receipt reconstructed previous tree {}, expected {}",
                previous_tree_hash,
                expected_tree_hash
            )));
        }
        let graph_plan = CheckoutGraphPlan {
            selected: selected.clone(),
            target_state,
            previous_tree,
            desired_tree: workspace.tree.clone(),
        };
        let daemon_delta = crate::commit_deltas::compute_selected_checkout_delta(
            state.graph.as_ref(),
            &graph_plan.selected,
            &graph_plan.target_state,
            &graph_plan.previous_tree,
            &graph_plan.desired_tree,
        )
        .map_err(|error| {
            classify_daemon_checkout_error(error, "preflight persisted checkout graph finalization")
        })?;
        let (replay_receipt, authority_freeze) =
            kin_core::tree::replay_repository_workspace_transaction_and_recover_projection(
                layout.working_dir(),
                &authority.manager,
                replay_transaction,
            )
            .map_err(|error| {
                classify_core_checkout_error(
                    error,
                    "replay committed checkout and recover its exact projection",
                )
            })?;
        replay_receipt
            .validate()
            .context("validate replayed checkout receipt")?;
        if replay_receipt.transaction_hash != receipt.transaction_hash
            || replay_receipt.roots_before != receipt.roots_before
            || replay_receipt.roots_after != receipt.roots_after
            || replay_receipt.generation != receipt.generation
            || !matches!(
                replay_receipt.outcome,
                kin_model::RepositoryCommitOutcome::IdempotentReplay
            )
        {
            return Err(CheckoutCommandError::conflict(anyhow::anyhow!(
                "repository authority returned a non-identical replay for checkout operation {}",
                request.operation_id
            )));
        }
        if authority_freeze.roots() != &receipt.roots_after {
            return Err(CheckoutCommandError::conflict(anyhow::anyhow!(
                "repository authority advanced while recovering checkout operation {}",
                request.operation_id
            )));
        }
        let current = authority_freeze
            .authority()
            .metadata()
            .workspaces
            .iter()
            .find(|candidate| candidate.workspace_id == workspace.workspace_id)
            .ok_or_else(|| anyhow::anyhow!("checkout workspace disappeared after recovery"))?;
        if current.generation != mutation.new_generation
            || current.tree_hash != mutation.new_tree_hash
            || current.tree != graph_plan.desired_tree
        {
            return Err(CheckoutCommandError::conflict(anyhow::anyhow!(
                "checkout workspace changed while recovering its exact projection"
            )));
        }
        let projected_entries = selected_materialized_count(&target_tree, &selected)?;
        let report = CheckoutReport {
            authority: "repository-v6".to_string(),
            operation_id: request.operation_id,
            selected,
            target_change_id,
            authority_generation: replay_receipt.generation,
            workspace_generation: mutation.new_generation,
            projected_entries,
            projection_only: false,
            idempotent: true,
        };
        return Ok(repository_execution(
            report,
            false,
            replay_receipt,
            graph_plan,
            daemon_delta,
            authority_freeze,
        ));
    }

    let existing_projection_receipt = kin_core::tree::recover_checkout_projection_receipt(
        layout.working_dir(),
        &authority.manager,
        request.operation_id,
    )
    .map_err(|error| {
        classify_core_checkout_error(error, "recover prior selected checkout projection")
    })?;
    validate_checkout_selection(&workspace.tree, &target_tree, &selected)
        .map_err(CheckoutCommandError::conflict)?;
    let next_tree = splice_checkout_tree(&workspace.tree, &target_tree, &selected)
        .map_err(CheckoutCommandError::conflict)?;
    let next_tree_hash =
        compute_resolved_tree_hash(&next_tree).context("hash selected checkout workspace tree")?;

    let tree_deltas =
        kin_core::exact_tree_correction(&workspace.tree, &next_tree).map_err(|error| {
            classify_core_checkout_error(error, "plan selected exact checkout tree splice")
        })?;
    let graph_plan = CheckoutGraphPlan {
        selected: selected.clone(),
        target_state,
        previous_tree: workspace.tree.clone(),
        desired_tree: next_tree.clone(),
    };
    let daemon_delta = crate::commit_deltas::compute_selected_checkout_delta(
        state.graph.as_ref(),
        &graph_plan.selected,
        &graph_plan.target_state,
        &graph_plan.previous_tree,
        &graph_plan.desired_tree,
    )
    .map_err(|error| {
        classify_daemon_checkout_error(error, "preflight exact checkout graph transition")
    })?;
    if daemon_delta.admission_policy_delta.is_some() {
        return Err(CheckoutCommandError::internal(anyhow::anyhow!(
            "checkout graph preflight unexpectedly changed repository admission policy"
        )));
    }
    if daemon_delta.tree_deltas != tree_deltas {
        return Err(CheckoutCommandError::internal(anyhow::anyhow!(
            "checkout graph preflight was not bound to the exact repository tree transition"
        )));
    }
    // The authority-side transition is planned from the workspace lease, not
    // from the daemon delta above. The daemon graph carries derived enrichment
    // that has not crossed the compare-and-swap, so reusing its delta here
    // would ask authority to publish or retract semantics it never owned.
    let workspace_graph = workspace_graph.ok_or_else(|| {
        CheckoutCommandError::internal(anyhow::anyhow!(
            "checkout planning reached the authority transition without a workspace authority graph"
        ))
    })?;
    let authority_graph = kin_db::InMemoryGraph::from_snapshot(workspace_graph)
        .context("prepare exact checkout workspace authority graph")?;
    let authority_delta = crate::commit_deltas::compute_selected_checkout_delta(
        &authority_graph,
        &graph_plan.selected,
        &graph_plan.target_state,
        &graph_plan.previous_tree,
        &graph_plan.desired_tree,
    )
    .map_err(|error| {
        classify_daemon_checkout_error(error, "plan exact checkout authority graph transition")
    })?;
    if authority_delta.tree_deltas != tree_deltas {
        return Err(CheckoutCommandError::internal(anyhow::anyhow!(
            "checkout authority plan was not bound to the exact repository tree transition"
        )));
    }
    let semantic_delta = WorkspaceSemanticDelta::new(
        authority_delta.entity_deltas.clone(),
        authority_delta.relation_deltas.clone(),
    )
    .context("canonicalize exact checkout semantic transition")?;
    let repository_changed = !tree_deltas.is_empty() || !semantic_delta.is_empty();

    if !repository_changed {
        let projection_receipt = kin_core::tree::CheckoutProjectionReceipt::new(
            authority.repository_id.clone(),
            workspace.workspace_id,
            request.operation_id,
            roots.clone(),
            workspace.generation,
            workspace.tree_hash,
            selected.clone(),
        )
        .map_err(|error| {
            classify_core_checkout_error(error, "build exact checkout projection receipt")
        })?;
        if let Some(existing) = existing_projection_receipt {
            if existing != projection_receipt {
                return Err(CheckoutCommandError::conflict(anyhow::anyhow!(
                    "checkout operation {} was already completed for a different projection request",
                    request.operation_id
                )));
            }
            let authority_freeze =
                authority
                    .manager
                    .freeze_current_authority(&roots)
                    .map_err(|error| {
                        classify_graph_checkout_error(
                            error,
                            "freeze idempotent projection-only checkout authority",
                        )
                    })?;
            validate_projection_workspace(
                authority_freeze.authority(),
                authority.workspace_id,
                workspace.generation,
                workspace.tree_hash,
                &workspace.tree,
            )
            .map_err(CheckoutCommandError::conflict)?;
            let report = CheckoutReport {
                authority: "repository-v6".to_string(),
                operation_id: request.operation_id,
                selected,
                target_change_id,
                authority_generation: roots.generation,
                workspace_generation: workspace.generation,
                projected_entries: 0,
                projection_only: true,
                idempotent: true,
            };
            return Ok(projection_execution(
                report,
                false,
                roots,
                workspace.tree,
                workspace.tree_hash,
                authority_freeze,
            ));
        }
        let (projected_entries, _, authority_freeze) =
            kin_core::tree::repair_repository_workspace_subtree_projection(
                layout.working_dir(),
                &workspace.tree,
                &authority.manager,
                projection_receipt,
            )
            .map_err(|error| {
                classify_core_checkout_error(error, "repair exact selected checkout projection")
            })?;
        let report = CheckoutReport {
            authority: "repository-v6".to_string(),
            operation_id: request.operation_id,
            selected,
            target_change_id,
            authority_generation: roots.generation,
            workspace_generation: workspace.generation,
            projected_entries,
            projection_only: true,
            idempotent: false,
        };
        return Ok(projection_execution(
            report,
            true,
            roots,
            workspace.tree,
            workspace.tree_hash,
            authority_freeze,
        ));
    }
    if existing_projection_receipt.is_some() {
        return Err(CheckoutCommandError::conflict(anyhow::anyhow!(
            "checkout operation {} was already completed as a projection-only request",
            request.operation_id
        )));
    }

    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: request.operation_id,
        repository_id: authority.repository_id.clone(),
        expected_generation: roots.generation,
        expected_roots: roots,
        actor,
        reason,
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
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
            new_generation: workspace
                .generation
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("workspace generation overflow"))?,
            new_head: workspace.head.clone(),
            new_base_target: workspace.base_target.clone(),
            new_base_tree_hash: workspace.base_tree_hash,
            tree_deltas: tree_deltas.clone(),
            new_tree_hash: next_tree_hash,
            semantic_delta,
            new_shared_admission_policy: workspace.shared_admission_policy.clone(),
            new_admission_policy: workspace.admission_policy,
        }),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
    };
    let (projected_entries, receipt, authority_freeze) =
        kin_core::tree::checkout_repository_workspace_subtree_and_commit_repository_transaction(
            layout.working_dir(),
            &selected,
            &workspace.tree,
            &next_tree,
            &authority.manager,
            transaction,
        )
        .map_err(|error| {
            classify_core_checkout_error(
                error,
                "commit selected exact checkout workspace transition",
            )
        })?;
    let report = CheckoutReport {
        authority: "repository-v6".to_string(),
        operation_id: request.operation_id,
        selected,
        target_change_id,
        authority_generation: receipt.generation,
        workspace_generation: workspace.generation + 1,
        projected_entries,
        projection_only: false,
        idempotent: matches!(
            receipt.outcome,
            kin_model::RepositoryCommitOutcome::IdempotentReplay
        ),
    };
    Ok(repository_execution(
        report,
        true,
        receipt,
        graph_plan,
        daemon_delta,
        authority_freeze,
    ))
}

/// A pinned-namespace refusal is a conflict, not an internal fault: the request
/// is well formed and the daemon is healthy, but the repository authority it
/// pinned is no longer the one at that path, so there is no coherent truth left
/// to check out from.
fn classify_authority_bind_refusal(
    refusal: RepositoryAuthorityBindRefusal,
) -> CheckoutCommandError {
    let identity = refusal.is_identity_refusal();
    let error = refusal.into_error();
    if identity {
        CheckoutCommandError::Conflict(error)
    } else {
        CheckoutCommandError::Internal(error)
    }
}

fn classify_model_checkout_error(
    error: kin_model::ModelError,
    context: impl Into<String>,
) -> CheckoutCommandError {
    let status = match &error {
        kin_model::ModelError::InvalidHash(_)
        | kin_model::ModelError::InvalidOperation(_)
        | kin_model::ModelError::ChangeNotFound(_) => StatusCode::BAD_REQUEST,
        kin_model::ModelError::Conflict(_)
        | kin_model::ModelError::RefNotFound(_)
        | kin_model::ModelError::WorkspaceNotFound(_) => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    checkout_error_for_status(status, anyhow::Error::new(error).context(context.into()))
}

fn classify_graph_checkout_error(
    error: kin_db::KinDbError,
    context: impl Into<String>,
) -> CheckoutCommandError {
    let status = match &error {
        kin_db::KinDbError::Model(model) => match model {
            kin_model::ModelError::InvalidHash(_)
            | kin_model::ModelError::InvalidOperation(_)
            | kin_model::ModelError::ChangeNotFound(_) => StatusCode::BAD_REQUEST,
            kin_model::ModelError::Conflict(_)
            | kin_model::ModelError::RefNotFound(_)
            | kin_model::ModelError::WorkspaceNotFound(_) => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        },
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    checkout_error_for_status(status, anyhow::Error::new(error).context(context.into()))
}

fn classify_core_checkout_error(
    error: kin_core::KinError,
    context: impl Into<String>,
) -> CheckoutCommandError {
    let status = match &error {
        kin_core::KinError::Model(model) => match model {
            kin_model::ModelError::InvalidHash(_)
            | kin_model::ModelError::InvalidOperation(_)
            | kin_model::ModelError::ChangeNotFound(_) => StatusCode::BAD_REQUEST,
            kin_model::ModelError::Conflict(_)
            | kin_model::ModelError::RefNotFound(_)
            | kin_model::ModelError::WorkspaceNotFound(_) => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        },
        kin_core::KinError::RepositoryConflict(_) | kin_core::KinError::ProjectionConflict(_) => {
            StatusCode::CONFLICT
        }
        kin_core::KinError::RepositoryCommitIndeterminate(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    checkout_error_for_status(status, anyhow::Error::new(error).context(context.into()))
}

fn classify_daemon_checkout_error(
    error: DaemonError,
    context: impl Into<String>,
) -> CheckoutCommandError {
    let status = match &error {
        DaemonError::IncompatibleRepo(_) => StatusCode::CONFLICT,
        DaemonError::Graph(kin_db::KinDbError::Model(model)) => match model {
            kin_model::ModelError::InvalidHash(_)
            | kin_model::ModelError::InvalidOperation(_)
            | kin_model::ModelError::ChangeNotFound(_) => StatusCode::BAD_REQUEST,
            kin_model::ModelError::Conflict(_)
            | kin_model::ModelError::RefNotFound(_)
            | kin_model::ModelError::WorkspaceNotFound(_) => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        },
        DaemonError::Core(
            kin_core::KinError::RepositoryConflict(_) | kin_core::KinError::ProjectionConflict(_),
        ) => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    checkout_error_for_status(status, anyhow::Error::new(error).context(context.into()))
}

fn checkout_error_for_status(status: StatusCode, error: anyhow::Error) -> CheckoutCommandError {
    match status {
        StatusCode::BAD_REQUEST => CheckoutCommandError::BadRequest(error),
        StatusCode::CONFLICT => CheckoutCommandError::Conflict(error),
        _ => CheckoutCommandError::Internal(error),
    }
}

fn repository_commit_error(error: DaemonError) -> (StatusCode, String) {
    let status = match &error {
        DaemonError::Graph(kin_db::KinDbError::Model(kin_model::ModelError::Conflict(_))) => {
            StatusCode::CONFLICT
        }
        DaemonError::Graph(kin_db::KinDbError::Model(kin_model::ModelError::InvalidOperation(
            _,
        )))
        | DaemonError::Core(kin_core::KinError::Model(kin_model::ModelError::InvalidOperation(
            _,
        ))) => StatusCode::BAD_REQUEST,
        DaemonError::Core(
            kin_core::KinError::RepositoryConflict(_) | kin_core::KinError::ProjectionConflict(_),
        )
        | DaemonError::IncompatibleRepo(_) => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, error.to_string())
}

fn internal_error(error: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

fn response(report: CheckoutReport, mutated: bool) -> CheckoutResponse {
    CheckoutResponse {
        lines: vec![format!(
            "Checked out {} from change {} ({} projected entries, authority generation {})",
            report.selected,
            report.target_change_id,
            report.projected_entries,
            report.authority_generation
        )],
        mutated,
        report: Some(report),
    }
}

fn repository_execution(
    report: CheckoutReport,
    mutated: bool,
    receipt: RepositoryCommitReceipt,
    graph_plan: CheckoutGraphPlan,
    daemon_delta: TransactionDelta,
    authority_freeze: LocalRepositoryAuthorityFreeze,
) -> CheckoutExecution {
    CheckoutExecution {
        response: response(report, mutated),
        effect: CheckoutAuthorityEffect::RepositoryCommit {
            receipt,
            graph_plan,
            daemon_delta,
            authority_freeze,
        },
    }
}

fn projection_execution(
    report: CheckoutReport,
    mutated: bool,
    roots: RootBundle,
    workspace_tree: ResolvedTree,
    workspace_tree_hash: Hash256,
    authority_freeze: LocalRepositoryAuthorityFreeze,
) -> CheckoutExecution {
    CheckoutExecution {
        response: response(report, mutated),
        effect: CheckoutAuthorityEffect::ProjectionOnly {
            roots,
            workspace_tree,
            workspace_tree_hash,
            projection_changed: mutated,
            authority_freeze,
        },
    }
}

fn validate_projection_workspace(
    authority: &kin_db::RepositoryAuthorityState,
    workspace_id: WorkspaceId,
    workspace_generation: u64,
    workspace_tree_hash: Hash256,
    workspace_tree: &ResolvedTree,
) -> Result<()> {
    let workspace = authority
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == workspace_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository authority no longer contains checkout workspace {workspace_id}"
            )
        })?;
    if workspace.generation != workspace_generation
        || workspace.tree_hash != workspace_tree_hash
        || &workspace.tree != workspace_tree
    {
        bail!("repository authority changed while retaining projection-only checkout workspace");
    }
    Ok(())
}

fn checkout_reason(selected: &RepoPath, target: &SemanticChangeId) -> String {
    format!(
        "checkout exact repository workspace path {} at {}",
        hex::encode(selected.as_bytes()),
        target
    )
}

fn validate_checkout_selection(
    current: &ResolvedTree,
    target: &ResolvedTree,
    selected: &RepoPath,
) -> Result<()> {
    let current_matches = current
        .artifacts_by_path()
        .filter(|artifact| checkout_path_contains(selected, &artifact.path))
        .count();
    let target_matches = target
        .artifacts_by_path()
        .filter(|artifact| checkout_path_contains(selected, &artifact.path))
        .count();
    if current_matches == 0 && target_matches == 0 {
        bail!(
            "checkout path {} does not name an artifact or component subtree in the current or target tree",
            selected
        );
    }
    for (label, tree) in [("current", current), ("target", target)] {
        let exact = tree.artifact_at_path(selected).is_some();
        let descendant = tree.artifacts_by_path().any(|artifact| {
            artifact.path != *selected && checkout_path_contains(selected, &artifact.path)
        });
        if exact && descendant {
            bail!(
                "{label} tree contains both exact path {} and descendants; checkout prefix is ambiguous",
                selected
            );
        }
    }
    Ok(())
}

fn splice_checkout_tree(
    current: &ResolvedTree,
    target: &ResolvedTree,
    selected: &RepoPath,
) -> Result<ResolvedTree> {
    let mut artifacts = current
        .artifacts()
        .filter(|artifact| !checkout_path_contains(selected, &artifact.path))
        .cloned()
        .collect::<Vec<_>>();
    let mut occupied_ids = artifacts
        .iter()
        .map(|artifact| artifact.artifact_id)
        .collect::<HashSet<_>>();
    for target_artifact in target
        .artifacts_by_path()
        .filter(|artifact| checkout_path_contains(selected, &artifact.path))
    {
        if artifacts
            .iter()
            .any(|retained| paths_are_related(&retained.path, &target_artifact.path))
        {
            bail!(
                "checkout target {} conflicts with an unselected repository ancestor; select the common ancestor explicitly",
                target_artifact.path
            );
        }
        let mut artifact = target_artifact.clone();
        if occupied_ids.contains(&artifact.artifact_id) {
            artifact.artifact_id = collision_copy_artifact_id(target_artifact, &occupied_ids);
        }
        occupied_ids.insert(artifact.artifact_id);
        artifacts.push(artifact);
    }
    ResolvedTree::from_artifacts(artifacts)
        .map_err(|error| anyhow::anyhow!("splice selected checkout subtree: {error}"))
}

/// Allocate the stable identity of an exceptional checkout copy.
///
/// The target artifact ID cannot be reused when that identity remains outside
/// the selected subtree. Binding the copy to its source identity and selected
/// target location avoids operation-by-operation graph churn without turning
/// ordinary imported paths into identity seeds.
fn collision_copy_artifact_id(
    artifact: &ResolvedArtifact,
    occupied: &HashSet<ArtifactId>,
) -> ArtifactId {
    for counter in 0_u64.. {
        let mut hasher = Sha256::new();
        hasher.update(b"kin.checkout-collision-copy-artifact.v1\0");
        hasher.update(artifact.artifact_id.0.as_bytes());
        hasher.update(artifact.path.as_bytes());
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let candidate = ArtifactId(uuid::Uuid::from_bytes(bytes));
        if !occupied.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!("u64 artifact remap namespace exhausted")
}

fn selected_materialized_count(tree: &ResolvedTree, selected: &RepoPath) -> Result<usize> {
    tree.artifacts_by_path()
        .filter(|artifact| checkout_path_contains(selected, &artifact.path))
        .try_fold(0_usize, |count, artifact| {
            Ok(count
                + usize::from(
                    kin_core::tree::source_projection_disposition(&artifact.path, artifact.entry)?
                        == kin_core::tree::SourceProjectionDisposition::Materialized,
                ))
        })
}

fn checkout_path_contains(selected: &RepoPath, path: &RepoPath) -> bool {
    path == selected
        || path
            .as_bytes()
            .strip_prefix(selected.as_bytes())
            .is_some_and(|suffix| suffix.starts_with(b"/"))
}

fn paths_are_related(left: &RepoPath, right: &RepoPath) -> bool {
    checkout_path_contains(right, left) || checkout_path_contains(left, right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::TreeEntry;

    #[test]
    fn cross_boundary_copy_keeps_its_graph_assigned_id_across_later_checkouts() {
        let original_id = ArtifactId::new();
        let outside = RepoPath::from_utf8("outside.txt").unwrap();
        let selected = RepoPath::from_utf8("selected.txt").unwrap();
        let entry = TreeEntry::blob(Hash256::from_bytes([0x44; 32]), false);
        let current =
            ResolvedTree::from_artifacts([ResolvedArtifact::new(original_id, outside, entry)])
                .unwrap();
        let target = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            original_id,
            selected.clone(),
            entry,
        )])
        .unwrap();

        let copied = splice_checkout_tree(&current, &target, &selected).unwrap();
        let copied_id = copied.artifact_at_path(&selected).unwrap().artifact_id;
        assert_ne!(copied_id, original_id);

        let repeated = splice_checkout_tree(&copied, &target, &selected).unwrap();
        assert_eq!(repeated, copied);
        assert_eq!(
            repeated.artifact_at_path(&selected).unwrap().artifact_id,
            copied_id
        );
    }
}
