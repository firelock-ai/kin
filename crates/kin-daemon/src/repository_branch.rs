// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon-owned repository-v6 branch authority.

use anyhow::{bail, Context, Result};
use axum::http::StatusCode;
use kin_cli::commands::branch::{
    BranchListEntry, BranchListReport, BranchRequest, BranchResponse, BRANCH_LIST_SCHEMA,
};
use kin_db::{LocalFileBackend, LocalRepositoryAuthorityFreeze, RepositoryAuthorityManager};
use kin_model::{
    compute_resolved_tree_hash, AuthorId, ChangeStore, EffectiveAdmissionPolicyStamp, EntityStore,
    OperationId, RefExpectation, RefMutation, RefName, RefTarget, RefUpdatePolicy,
    RepositoryCommitOutcome, RepositoryCommitReceipt, RepositoryTransaction, ResolvedTree,
    RootBundle, TransactionDelta, WorkspaceExpectation, WorkspaceHead, WorkspaceMutation,
    REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};

use crate::local_repository_authority::{
    require_fresh_daemon_workspace, ActiveLocalRepositoryAuthority, RepositoryAuthorityBindRefusal,
};
use crate::state::{DaemonEvent, DaemonState};

const CREATE_REASON: &str = "create exact repository branch";
const DELETE_REASON: &str = "delete exact repository branch";
const SWITCH_REASON: &str = "switch exact repository workspace branch";

struct BranchExecution {
    response: BranchResponse,
    receipt: RepositoryCommitReceipt,
    authority_freeze: LocalRepositoryAuthorityFreeze,
    daemon_delta: TransactionDelta,
    previous_tree: ResolvedTree,
    desired_tree: ResolvedTree,
    projection_changed: bool,
}

enum BranchCommandOutcome {
    Commit(BranchExecution),
    ReadOnly(BranchResponse),
}

#[derive(Debug)]
struct BranchConflict(String);

impl std::fmt::Display for BranchConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for BranchConflict {}

#[derive(Debug)]
struct BranchBadRequest(String);

impl std::fmt::Display for BranchBadRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for BranchBadRequest {}

fn branch_conflict(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(BranchConflict(message.into()))
}

fn branch_bad_request(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(BranchBadRequest(message.into()))
}

/// Refuse a transition over uncommitted state that graph authority already
/// owns. Only admitted state reaches this: unadmitted working-copy bytes are
/// reported as projection drift instead, so the wording never describes host
/// content that has not crossed the repository-v6 compare-and-swap.
fn graph_owned_changes(workspace: &kin_model::WorkspaceState) -> anyhow::Error {
    branch_conflict(format!(
        "workspace {} has graph-owned changes; commit or explicitly preserve them before \
         switching branches",
        workspace.workspace_id
    ))
}

pub(crate) fn execute(
    state: &DaemonState,
    request: &BranchRequest,
) -> std::result::Result<BranchResponse, (StatusCode, String)> {
    if matches!(request, BranchRequest::List) {
        let authority =
            ActiveLocalRepositoryAuthority::open_bound(state).map_err(branch_bind_refusal)?;
        return list(&authority).map_err(internal_branch_error);
    }

    let graph_mutation = state.begin_graph_authority_mutation();
    let persistence = state.persist_lock.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "daemon persistence lock poisoned".to_string(),
        )
    })?;
    let previous_graph_root = hex::encode(state.graph.compute_root_hash());
    let authority =
        ActiveLocalRepositoryAuthority::open_bound(state).map_err(branch_bind_refusal)?;
    let outcome =
        match request {
            BranchRequest::List => unreachable!("list returned before mutation gates"),
            BranchRequest::Create {
                name,
                operation_id,
                actor,
            } => create(state, &authority, name, *operation_id, actor)
                .map(BranchCommandOutcome::Commit),
            BranchRequest::Delete {
                name,
                operation_id,
                actor,
            } => delete(state, &authority, name, *operation_id, actor)
                .map(BranchCommandOutcome::Commit),
            BranchRequest::Switch {
                name,
                operation_id,
                actor,
            } => switch(state, &authority, name, *operation_id, actor),
        }
        .map_err(classify_branch_error)?;
    let execution = match outcome {
        BranchCommandOutcome::Commit(execution) => execution,
        BranchCommandOutcome::ReadOnly(response) => {
            drop(persistence);
            drop(graph_mutation);
            return Ok(response);
        }
    };

    #[cfg(test)]
    if state
        .repository_command_fail_after_authority_once
        .swap(false, std::sync::atomic::Ordering::SeqCst)
    {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "injected failure after branch authority commit".to_string(),
        ));
    }

    #[cfg(test)]
    if state
        .repository_command_enrich_after_authority_once
        .swap(false, std::sync::atomic::Ordering::SeqCst)
    {
        state.install_derived_enrichment();
    }

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
    if execution.projection_changed && !finalization.graph_changed {
        state.invalidate_projection();
    }

    drop(persistence);
    drop(graph_mutation);
    Ok(execution.response)
}

fn list(authority: &ActiveLocalRepositoryAuthority) -> Result<BranchResponse> {
    let lease = authority.manager.read_authority();
    let metadata = lease.metadata();
    let workspace = metadata
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == authority.workspace_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no workspace {} in repository-v6 authority",
                authority.repository_id,
                authority.workspace_id
            )
        })?;
    let active_ref = match &workspace.head {
        WorkspaceHead::Symbolic { target } => Some(target),
        WorkspaceHead::Detached { .. } => None,
    };
    let default_ref = metadata.ref_state.default_ref.clone();
    let branches = metadata
        .ref_state
        .refs
        .iter()
        .filter(|repository_ref| repository_ref.name.is_branch())
        .map(|repository_ref| BranchListEntry {
            name: repository_ref.name.clone(),
            target: repository_ref.target.clone(),
            active: active_ref == Some(&repository_ref.name),
            default: default_ref.as_ref() == Some(&repository_ref.name),
        })
        .collect::<Vec<_>>();
    let report = BranchListReport {
        schema: BRANCH_LIST_SCHEMA.to_string(),
        authority: "repository-v6".to_string(),
        repository_id: authority.repository_id.clone(),
        authority_generation: lease.roots().generation,
        roots: lease.roots().clone(),
        workspace_id: workspace.workspace_id,
        workspace_generation: workspace.generation,
        workspace_head: workspace.head.clone(),
        repository_ref_count: metadata.ref_state.refs.len(),
        branch_count: branches.len(),
        default_ref,
        branches,
    };
    Ok(BranchResponse {
        lines: render_lines(&report),
        mutated: false,
        report: Some(report),
        operation_id: None,
        authority_generation: None,
        idempotent: false,
    })
}

fn create(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    name: &RefName,
    operation_id: OperationId,
    actor: &AuthorId,
) -> Result<BranchExecution> {
    require_branch_ref(name)?;
    let lease = authority.manager.read_authority();
    if let Some(receipt) = operation_receipt(lease.metadata().receipts.as_slice(), operation_id) {
        let roots = lease.roots().clone();
        drop(lease);
        return replay_ref_operation(
            authority,
            &roots,
            receipt,
            name,
            operation_id,
            actor,
            CREATE_REASON,
            true,
        );
    }
    let metadata = lease.metadata();
    if metadata
        .ref_state
        .refs
        .iter()
        .any(|repository_ref| &repository_ref.name == name)
    {
        return Err(branch_conflict(format!("branch {name} already exists")));
    }
    let workspace = local_workspace(authority, metadata)?.clone();
    let workspace_graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .context("materialize branch-creation workspace authority")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no graph snapshot for workspace {}",
                authority.repository_id,
                workspace.workspace_id
            )
        })?;
    require_fresh_daemon_workspace(state, lease.roots(), &workspace_graph, "creating a branch")
        .map_err(|error| branch_conflict(error.to_string()))?;
    let target = workspace.base_target.clone().ok_or_else(|| {
        branch_conflict(format!(
            "cannot create branch {name} from unborn workspace {}",
            workspace.workspace_id
        ))
    })?;
    if matches!(target, RefTarget::Symbolic { .. }) {
        bail!(
            "workspace {} base target is symbolic instead of resolved",
            workspace.workspace_id
        );
    }
    let transaction = ref_transaction(
        authority,
        lease.roots().clone(),
        operation_id,
        actor.clone(),
        CREATE_REASON,
        RefMutation {
            name: name.clone(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(target),
            policy: RefUpdatePolicy::FastForwardOnly,
        },
    );
    let tree = workspace.tree;
    drop(lease);
    let (receipt, authority_freeze) = commit_and_freeze_exact(&authority.manager, transaction)
        .with_context(|| format!("create repository-v6 branch {name}"))?;
    let target = receipt
        .operation
        .ref_mutations
        .first()
        .and_then(|mutation| mutation.new_target.as_ref())
        .expect("validated branch creation receipt contains its target");
    Ok(BranchExecution {
        response: BranchResponse {
            lines: vec![format!(
                "Created {} at {} (authority generation {})",
                name,
                render_target(target),
                receipt.generation
            )],
            mutated: matches!(receipt.outcome, RepositoryCommitOutcome::Committed),
            report: None,
            operation_id: Some(receipt.operation_id),
            authority_generation: Some(receipt.generation),
            idempotent: matches!(receipt.outcome, RepositoryCommitOutcome::IdempotentReplay),
        },
        receipt,
        authority_freeze,
        daemon_delta: TransactionDelta::default(),
        previous_tree: tree.clone(),
        desired_tree: tree,
        projection_changed: false,
    })
}

fn delete(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    name: &RefName,
    operation_id: OperationId,
    actor: &AuthorId,
) -> Result<BranchExecution> {
    require_branch_ref(name)?;
    let lease = authority.manager.read_authority();
    if let Some(receipt) = operation_receipt(lease.metadata().receipts.as_slice(), operation_id) {
        let roots = lease.roots().clone();
        drop(lease);
        return replay_ref_operation(
            authority,
            &roots,
            receipt,
            name,
            operation_id,
            actor,
            DELETE_REASON,
            false,
        );
    }
    let metadata = lease.metadata();
    let target = metadata
        .ref_state
        .refs
        .iter()
        .find(|repository_ref| &repository_ref.name == name)
        .map(|repository_ref| repository_ref.target.clone())
        .ok_or_else(|| branch_conflict(format!("branch {name} does not exist")))?;
    if metadata.ref_state.default_ref.as_ref() == Some(name) {
        return Err(branch_conflict(format!(
            "cannot delete default branch {name}; move the repository default ref atomically first"
        )));
    }
    if let Some(workspace) = metadata.workspaces.iter().find(
        |workspace| matches!(&workspace.head, WorkspaceHead::Symbolic { target } if target == name),
    ) {
        return Err(branch_conflict(format!(
            "cannot delete branch {name}; workspace {} has it checked out",
            workspace.workspace_id
        )));
    }
    let workspace = local_workspace(authority, metadata)?;
    let workspace_graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .context("materialize branch-deletion workspace authority")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no graph snapshot for workspace {}",
                authority.repository_id,
                workspace.workspace_id
            )
        })?;
    require_fresh_daemon_workspace(state, lease.roots(), &workspace_graph, "deleting a branch")
        .map_err(|error| branch_conflict(error.to_string()))?;
    let tree = workspace.tree.clone();
    let transaction = ref_transaction(
        authority,
        lease.roots().clone(),
        operation_id,
        actor.clone(),
        DELETE_REASON,
        RefMutation {
            name: name.clone(),
            expected: RefExpectation::MustEqual { target },
            new_target: None,
            policy: RefUpdatePolicy::ForceWithLease,
        },
    );
    drop(lease);
    let (receipt, authority_freeze) = commit_and_freeze_exact(&authority.manager, transaction)
        .with_context(|| format!("delete repository-v6 branch {name}"))?;
    Ok(BranchExecution {
        response: BranchResponse {
            lines: vec![format!(
                "Deleted {} (authority generation {})",
                name, receipt.generation
            )],
            mutated: matches!(receipt.outcome, RepositoryCommitOutcome::Committed),
            report: None,
            operation_id: Some(receipt.operation_id),
            authority_generation: Some(receipt.generation),
            idempotent: matches!(receipt.outcome, RepositoryCommitOutcome::IdempotentReplay),
        },
        receipt,
        authority_freeze,
        daemon_delta: TransactionDelta::default(),
        previous_tree: tree.clone(),
        desired_tree: tree,
        projection_changed: false,
    })
}

fn replay_ref_operation(
    authority: &ActiveLocalRepositoryAuthority,
    current_roots: &RootBundle,
    receipt: RepositoryCommitReceipt,
    name: &RefName,
    operation_id: OperationId,
    actor: &AuthorId,
    reason: &str,
    creating: bool,
) -> Result<BranchExecution> {
    receipt
        .validate()
        .context("validate persisted branch receipt")?;
    let [mutation] = receipt.operation.ref_mutations.as_slice() else {
        bail!("branch operation {operation_id} did not commit exactly one ref mutation");
    };
    if &mutation.name != name || mutation.new_target.is_some() != creating {
        return Err(branch_conflict(format!(
            "branch operation {operation_id} was already committed for a different request"
        )));
    }
    if current_roots != &receipt.roots_after {
        return Err(branch_conflict(format!(
            "branch operation {operation_id} committed at generation {}, but authority is now at \
             generation {}; reopen against current authority before retrying",
            receipt.generation, current_roots.generation
        )));
    }
    let transaction = ref_transaction(
        authority,
        receipt.roots_before.clone(),
        operation_id,
        actor.clone(),
        reason,
        mutation.clone(),
    );
    if transaction.transaction_hash()? != receipt.transaction_hash {
        return Err(branch_conflict(format!(
            "branch operation {operation_id} was already committed for a different request"
        )));
    }
    let lease = authority.manager.read_authority();
    let tree = local_workspace(authority, lease.metadata())?.tree.clone();
    drop(lease);
    let (replayed, authority_freeze) = commit_and_freeze_exact(&authority.manager, transaction)?;
    validate_identical_replay(&receipt, &replayed)?;
    let line = if creating {
        let target = mutation
            .new_target
            .as_ref()
            .expect("creating branch replay has a target");
        format!(
            "Created {} at {} (authority generation {}, idempotent replay)",
            name,
            render_target(target),
            replayed.generation
        )
    } else {
        format!(
            "Deleted {} (authority generation {}, idempotent replay)",
            name, replayed.generation
        )
    };
    Ok(BranchExecution {
        response: BranchResponse {
            lines: vec![line],
            mutated: false,
            report: None,
            operation_id: Some(replayed.operation_id),
            authority_generation: Some(replayed.generation),
            idempotent: true,
        },
        receipt: replayed,
        authority_freeze,
        daemon_delta: TransactionDelta::default(),
        previous_tree: tree.clone(),
        desired_tree: tree,
        projection_changed: false,
    })
}

fn switch(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    name: &RefName,
    operation_id: OperationId,
    actor: &AuthorId,
) -> Result<BranchCommandOutcome> {
    require_branch_ref(name)?;
    let lease = authority.manager.read_authority();
    if let Some(receipt) = operation_receipt(lease.metadata().receipts.as_slice(), operation_id) {
        let roots = lease.roots().clone();
        drop(lease);
        return replay_switch(state, authority, &roots, receipt, name, actor)
            .map(BranchCommandOutcome::Commit);
    }
    let roots = lease.roots().clone();
    let metadata = lease.metadata();
    let workspace = local_workspace(authority, metadata)?.clone();
    // A transition admits nothing, so this reads persisted authority alone. It
    // fires only where graph authority already owns uncommitted state: a
    // non-empty semantic overlay, or a workspace tree that admission moved off
    // its base. Admission only ever moves members the workspace already
    // tracks, so untracked host content can never reach this refusal, and the
    // wording never describes bytes that have not crossed the compare-and-swap.
    if workspace.is_dirty() {
        return Err(graph_owned_changes(&workspace));
    }
    let target = lease
        .resolve_ref_target(name)
        .with_context(|| format!("resolve repository branch {name} from one authority lease"))?
        .ok_or_else(|| branch_conflict(format!("repository branch {name} does not exist")))?;
    let target_change_id = lease
        .resolve_target_change_id(&target)
        .with_context(|| format!("resolve exact semantic target for branch {name}"))?;
    let target_shared_policy = metadata
        .admission_policies
        .iter()
        .find(|resolved| resolved.change_id == target_change_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "target change {target_change_id} has no repository-v6 admission-policy record"
            )
        })?
        .policy
        .clone()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "target change {target_change_id} has unresolved admission policy and cannot \
                 become a clean workspace"
            )
        })?;
    let current_workspace_graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .context("materialize current graph-owned workspace semantics")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no graph snapshot for workspace {}",
                authority.repository_id,
                workspace.workspace_id
            )
        })?;
    require_fresh_daemon_workspace(
        state,
        &roots,
        &current_workspace_graph,
        "switching branches",
    )
    .map_err(|error| branch_conflict(error.to_string()))?;
    let mut snapshot = lease.snapshot().clone();
    snapshot.repository_authority = None;
    drop(lease);

    let graph = kin_db::InMemoryGraph::from_snapshot(snapshot)
        .context("prepare graph-owned branch target")?;
    let target_state = graph
        .resolve_graph_at(&target_change_id)
        .with_context(|| format!("resolve exact graph for branch {name}"))?;
    let target_tree = target_state.tree.clone();
    let target_tree_hash =
        compute_resolved_tree_hash(&target_tree).context("hash exact branch target tree")?;
    let tree_deltas = kin_core::exact_tree_correction(&workspace.tree, &target_tree)
        .context("plan exact branch workspace transition")?;
    let semantic_delta = kin_core::diff_workspace_semantics(
        &current_workspace_graph.entities,
        &current_workspace_graph.relations,
        &target_state.entities,
        &target_state.relations,
    )
    .context("plan exact branch semantic transition")?;
    let daemon_semantic_delta = crate::local_repository_authority::plan_daemon_semantic_delta(
        state,
        &target_state.entities,
        &target_state.relations,
    )
    .context("plan the branch semantic transition for the daemon view")?;
    let daemon_delta = TransactionDelta {
        entity_deltas: daemon_semantic_delta.entity_deltas().to_vec(),
        relation_deltas: daemon_semantic_delta.relation_deltas().to_vec(),
        tree_deltas: tree_deltas.clone(),
        admission_policy_delta: None,
        external_reference_deltas: Vec::new(),
    };
    preflight_switch_delta(state, &workspace.tree, &target_state, &daemon_delta)?;
    let already_active = matches!(
        &workspace.head,
        WorkspaceHead::Symbolic { target } if target == name
    ) && workspace.base_target.as_ref() == Some(&target)
        && workspace.tree_hash == target_tree_hash
        && tree_deltas.is_empty()
        && semantic_delta.is_empty()
        && workspace.shared_admission_policy == target_shared_policy
        && workspace.admission_policy.shared == target_shared_policy.stamp();
    if already_active {
        let (verified_entries, authority_freeze) =
            kin_core::verify_repository_workspace_projection(
                state.layout.working_dir(),
                &workspace.tree,
                &authority.manager,
            )
            .with_context(|| format!("verify exact projection for already-active branch {name}"))?;
        let generation = authority_freeze.roots().generation;
        drop(authority_freeze);
        return Ok(BranchCommandOutcome::ReadOnly(BranchResponse {
            lines: vec![format!(
                "Already on {} at change {} ({} projected entries verified, authority generation {})",
                name, target_change_id, verified_entries, generation
            )],
            mutated: false,
            report: None,
            operation_id: Some(operation_id),
            authority_generation: Some(generation),
            idempotent: true,
        }));
    }
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id,
        repository_id: authority.repository_id.clone(),
        expected_generation: roots.generation,
        expected_roots: roots,
        actor: actor.clone(),
        reason: SWITCH_REASON.to_string(),
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
            new_head: WorkspaceHead::Symbolic {
                target: name.clone(),
            },
            new_base_target: Some(target),
            new_base_tree_hash: Some(target_tree_hash),
            tree_deltas,
            new_tree_hash: target_tree_hash,
            semantic_delta,
            new_shared_admission_policy: target_shared_policy.clone(),
            new_admission_policy: EffectiveAdmissionPolicyStamp {
                shared: target_shared_policy.stamp(),
                local: workspace.admission_policy.local,
            },
        }),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
    };
    // Validate the derived view before materializing anything over it. This
    // reads the working copy only at paths the workspace tree already tracks
    // and compares them against the content repository authority owns, so it
    // reports edits made outside Kin's seams without treating any of them as
    // graph-owned state. Untracked host paths are never read and never gate
    // the transition.
    let drift = kin_core::report_repository_workspace_projection_drift(
        state.layout.working_dir(),
        &workspace.tree,
        &authority.manager,
    )
    .with_context(|| format!("validate exact workspace projection before switching to {name}"))?;
    if let Some(first) = drift.first() {
        return Err(kin_core::KinError::ProjectionConflict(format!(
            "{first}; {} tracked path(s) diverge from the graph-owned workspace projection; \
             reconcile them into graph authority or discard them before switching branches",
            drift.len()
        ))
        .into());
    }
    let (materialized, receipt, authority_freeze) =
        kin_core::tree::transition_repository_workspace_tree_and_commit_repository_transaction(
            state.layout.working_dir(),
            &workspace.tree,
            &target_tree,
            &authority.manager,
            transaction,
        )
        .with_context(|| format!("switch repository-v6 workspace to branch {name}"))?;
    Ok(BranchCommandOutcome::Commit(BranchExecution {
        response: BranchResponse {
            lines: vec![format!(
                "Switched to {} at change {} ({} projected entries, authority generation {})",
                name, target_change_id, materialized, receipt.generation
            )],
            mutated: matches!(receipt.outcome, RepositoryCommitOutcome::Committed),
            report: None,
            operation_id: Some(receipt.operation_id),
            authority_generation: Some(receipt.generation),
            idempotent: matches!(receipt.outcome, RepositoryCommitOutcome::IdempotentReplay),
        },
        receipt,
        authority_freeze,
        daemon_delta,
        previous_tree: workspace.tree,
        desired_tree: target_tree,
        projection_changed: true,
    }))
}

fn replay_switch(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    current_roots: &RootBundle,
    receipt: RepositoryCommitReceipt,
    name: &RefName,
    actor: &AuthorId,
) -> Result<BranchExecution> {
    receipt
        .validate()
        .context("validate persisted branch-switch receipt")?;
    if !receipt.operation.ref_mutations.is_empty() {
        bail!(
            "branch switch operation {} unexpectedly mutated repository refs",
            receipt.operation_id
        );
    }
    let mutation = receipt
        .operation
        .workspace_mutation
        .as_ref()
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "branch switch operation {} has no workspace mutation",
                receipt.operation_id
            )
        })?;
    if !matches!(&mutation.new_head, WorkspaceHead::Symbolic { target } if target == name) {
        return Err(branch_conflict(format!(
            "branch operation {} was already committed for a different request",
            receipt.operation_id
        )));
    }
    if current_roots != &receipt.roots_after {
        return Err(branch_conflict(format!(
            "branch operation {} committed at generation {}, but authority is now at generation {}; \
             reopen against current authority before retrying",
            receipt.operation_id,
            receipt.generation,
            current_roots.generation
        )));
    }
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: receipt.operation_id,
        repository_id: authority.repository_id.clone(),
        expected_generation: receipt.roots_before.generation,
        expected_roots: receipt.roots_before.clone(),
        actor: actor.clone(),
        reason: SWITCH_REASON.to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: Some(mutation.clone()),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
    };
    if transaction.transaction_hash()? != receipt.transaction_hash {
        return Err(branch_conflict(format!(
            "branch operation {} was already committed for a different request",
            receipt.operation_id
        )));
    }
    let lease = authority.manager.read_authority();
    let workspace = local_workspace(authority, lease.metadata())?;
    if workspace.generation != mutation.new_generation
        || workspace.tree_hash != mutation.new_tree_hash
        || workspace.head != mutation.new_head
    {
        return Err(branch_conflict(format!(
            "branch switch operation {} no longer matches current workspace authority",
            receipt.operation_id
        )));
    }
    let desired_tree = workspace.tree.clone();
    let inverse = mutation
        .tree_deltas
        .iter()
        .map(kin_model::TreeDelta::inverse)
        .collect::<Vec<_>>();
    let previous_tree = desired_tree
        .apply(&inverse)
        .context("reconstruct pre-switch workspace tree from persisted receipt")?;
    // A replay recovers the daemon after authority already moved, so the
    // workspace graph the lease holds now is the switch target. Planning the
    // daemon side from the live graph to that target keeps the recovery honest
    // when derived enrichment landed before the crash.
    let target_graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .context("materialize the replayed branch-switch workspace authority")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no graph snapshot for workspace {}",
                authority.repository_id,
                workspace.workspace_id
            )
        })?;
    let daemon_semantic_delta = crate::local_repository_authority::plan_daemon_semantic_delta(
        state,
        &target_graph.entities,
        &target_graph.relations,
    )
    .context("plan the replayed branch semantic transition for the daemon view")?;
    let daemon_delta = TransactionDelta {
        entity_deltas: daemon_semantic_delta.entity_deltas().to_vec(),
        relation_deltas: daemon_semantic_delta.relation_deltas().to_vec(),
        tree_deltas: mutation.tree_deltas.clone(),
        admission_policy_delta: None,
        external_reference_deltas: Vec::new(),
    };
    drop(lease);
    let (replayed, authority_freeze) =
        kin_core::tree::replay_repository_workspace_transaction_and_recover_projection(
            state.layout.working_dir(),
            &authority.manager,
            transaction,
        )
        .context("replay branch switch and recover its exact projection")?;
    validate_identical_replay(&receipt, &replayed)?;
    Ok(BranchExecution {
        response: BranchResponse {
            lines: vec![format!(
                "Switched to {} (authority generation {}, idempotent replay)",
                name, replayed.generation
            )],
            mutated: false,
            report: None,
            operation_id: Some(replayed.operation_id),
            authority_generation: Some(replayed.generation),
            idempotent: true,
        },
        receipt: replayed,
        authority_freeze,
        daemon_delta,
        previous_tree,
        desired_tree,
        projection_changed: true,
    })
}

fn preflight_switch_delta(
    state: &DaemonState,
    previous_tree: &ResolvedTree,
    desired: &kin_model::graph::ResolvedGraphState,
    delta: &TransactionDelta,
) -> Result<()> {
    let desired_tree = &desired.tree;
    let live_tree = state.graph.resolved_tree();
    if live_tree != *previous_tree && live_tree != *desired_tree {
        return Err(branch_conflict(
            "daemon query tree matches neither branch-switch base nor desired authority",
        ));
    }
    let preflight = kin_db::InMemoryGraph::from_snapshot(state.graph.to_snapshot())
        .context("prepare branch-switch daemon graph preflight")?;
    preflight
        .apply_transaction_delta(delta)
        .context("apply branch-switch daemon graph preflight")?;
    let snapshot = preflight.to_snapshot();
    if snapshot.resolved_tree != *desired_tree
        || snapshot.entities != desired.entities
        || snapshot.relations != desired.relations
    {
        bail!(
            "branch-switch daemon graph preflight did not produce the exact target graph and tree"
        );
    }
    Ok(())
}

fn ref_transaction(
    authority: &ActiveLocalRepositoryAuthority,
    roots: RootBundle,
    operation_id: OperationId,
    actor: AuthorId,
    reason: &str,
    mutation: RefMutation,
) -> RepositoryTransaction {
    RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id,
        repository_id: authority.repository_id.clone(),
        expected_generation: roots.generation,
        expected_roots: roots,
        actor,
        reason: reason.to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: vec![mutation],
        default_ref_mutation: None,
        workspace_mutation: None,
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
    }
}

fn commit_and_freeze_exact(
    manager: &RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
) -> Result<(RepositoryCommitReceipt, LocalRepositoryAuthorityFreeze)> {
    match manager.commit_repository_transaction_and_freeze(transaction.clone()) {
        Ok(committed) => Ok(committed),
        Err(first_error) => manager
            .commit_repository_transaction_and_freeze(transaction)
            .map_err(|second_error| {
                anyhow::Error::new(second_error).context(format!(
                    "commit and freeze repository branch authority after first attempt failed: \
                     {first_error}"
                ))
            }),
    }
}

fn validate_identical_replay(
    installed: &RepositoryCommitReceipt,
    replayed: &RepositoryCommitReceipt,
) -> Result<()> {
    if replayed.transaction_hash != installed.transaction_hash
        || replayed.roots_before != installed.roots_before
        || replayed.roots_after != installed.roots_after
        || replayed.generation != installed.generation
        || !matches!(replayed.outcome, RepositoryCommitOutcome::IdempotentReplay)
    {
        bail!(
            "repository authority returned a non-identical replay for branch operation {}",
            installed.operation_id
        );
    }
    Ok(())
}

fn operation_receipt(
    receipts: &[RepositoryCommitReceipt],
    operation_id: OperationId,
) -> Option<RepositoryCommitReceipt> {
    receipts
        .iter()
        .find(|receipt| receipt.operation_id == operation_id)
        .cloned()
}

fn local_workspace<'a>(
    authority: &ActiveLocalRepositoryAuthority,
    metadata: &'a kin_db::PersistedRepositoryAuthority,
) -> Result<&'a kin_model::WorkspaceState> {
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

fn require_branch_ref(name: &RefName) -> Result<()> {
    if !name.is_branch() {
        return Err(branch_bad_request(format!(
            "branch command requires a ref below refs/heads/, found {name}"
        )));
    }
    Ok(())
}

fn render_lines(report: &BranchListReport) -> Vec<String> {
    if report.branches.is_empty() {
        return vec![format!(
            "(no branches; workspace head is {})",
            render_head(&report.workspace_head)
        )];
    }
    report
        .branches
        .iter()
        .map(|branch| {
            let active = if branch.active { "*" } else { " " };
            let default = if branch.default { " [default]" } else { "" };
            format!(
                "{active} {} -> {}{default}",
                branch.name,
                render_target(&branch.target)
            )
        })
        .collect()
}

fn render_head(head: &WorkspaceHead) -> String {
    match head {
        WorkspaceHead::Symbolic { target } => format!("symbolic {target}"),
        WorkspaceHead::Detached { target } => format!("detached {}", render_target(target)),
    }
}

fn render_target(target: &RefTarget) -> String {
    match target {
        RefTarget::Change { change_id } => format!("change {change_id}"),
        RefTarget::ExternalObject { object } => format!("{:?} {}", object.kind, object.oid),
        RefTarget::Symbolic { target } => format!("symbolic {target}"),
    }
}

fn classify_branch_error(error: anyhow::Error) -> (StatusCode, String) {
    if error.downcast_ref::<BranchBadRequest>().is_some() {
        return (StatusCode::BAD_REQUEST, format!("{error:#}"));
    }
    if error.downcast_ref::<BranchConflict>().is_some() {
        return (StatusCode::CONFLICT, format!("{error:#}"));
    }
    if let Some(core) = error.downcast_ref::<kin_core::KinError>() {
        let status = match core {
            kin_core::KinError::Model(model) => branch_model_status(model),
            kin_core::KinError::RepositoryConflict(_)
            | kin_core::KinError::ProjectionConflict(_) => StatusCode::CONFLICT,
            kin_core::KinError::RepositoryCommitIndeterminate(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return (status, format!("{error:#}"));
    }
    if let Some(database) = error.downcast_ref::<kin_db::KinDbError>() {
        let status = match database {
            kin_db::KinDbError::Model(model) => branch_model_status(model),
            kin_db::KinDbError::SnapshotPersistenceIndeterminate(_)
            | kin_db::KinDbError::StorageError(_)
            | kin_db::KinDbError::LockError(_)
            | kin_db::KinDbError::ConcurrentAccessError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return (status, format!("{error:#}"));
    }
    if let Some(model) = error.downcast_ref::<kin_model::ModelError>() {
        return (branch_model_status(model), format!("{error:#}"));
    }
    if error.downcast_ref::<std::io::Error>().is_some() {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}"));
    }
    (StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}"))
}

fn branch_model_status(error: &kin_model::ModelError) -> StatusCode {
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

fn internal_branch_error(error: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

/// Answer a pinned-namespace refusal as a conflict for the same reason checkout
/// does: the branch request is well formed, but the repository authority this
/// daemon pinned is no longer the one at that path.
fn branch_bind_refusal(refusal: RepositoryAuthorityBindRefusal) -> (StatusCode, String) {
    let identity = refusal.is_identity_refusal();
    let error = refusal.into_error();
    if identity {
        (StatusCode::CONFLICT, format!("{error:#}"))
    } else {
        internal_branch_error(format!("{error:#}"))
    }
}
