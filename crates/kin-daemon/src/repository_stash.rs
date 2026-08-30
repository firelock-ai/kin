// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon-owned repository-v6 stashes.
//!
//! A stash seals the exact graph-owned workspace state, tree and base-relative
//! semantics together, as one immutable semantic change reachable only from
//! `refs/kin/stash/<ordinal>`. Sealing and any workspace reset cross authority
//! in a single repository transaction, so a stash is never a marker file, a
//! branch sidecar, or a re-read of the working tree.
//!
//! Restore is deliberately not a rebase. A sealed state describes one exact
//! transition out of the authority target it was taken against; replaying it
//! onto a target that has since moved would publish a workspace nobody
//! observed and silently revert whatever moved authority in the meantime.

use anyhow::{bail, Context, Result};
use axum::http::StatusCode;
use kin_cli::commands::stash::{
    stash_ref_name, stash_ref_ordinal, StashEntryReport, StashListReport, StashRequest,
    StashResponse, STASH_LIST_SCHEMA,
};
use kin_model::{
    compute_resolved_tree_hash, compute_semantic_change_id, AuthorId, ChangeOrigin, ChangeStore,
    EffectiveAdmissionPolicyStamp, Hash256, OperationId, RefExpectation, RefMutation, RefName,
    RefTarget, RepositoryCommitOutcome, RepositoryCommitReceipt, RepositoryTransaction,
    ResolvedTree, SemanticChange, SemanticChangeId, SharedAdmissionPolicy, Timestamp,
    TransactionDelta, WorkspaceExpectation, WorkspaceMutation, WorkspaceState,
    REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};

use crate::local_repository_authority::{
    ActiveLocalRepositoryAuthority, RepositoryAuthorityBindRefusal,
};
use crate::state::{DaemonEvent, DaemonState};

const SEAL_REASON: &str = "seal exact graph-owned workspace state as a repository stash";
const RESTORE_REASON: &str = "restore exact graph-owned workspace state from a repository stash";
const RETURN_REASON: &str =
    "return the exact graph-owned workspace to its authority base after sealing a stash";

enum StashOutcome {
    Commit(StashExecution, Option<Box<ReturnToBase>>),
    ReadOnly(StashResponse),
}

/// Everything the workspace return needs, carried across the seal.
///
/// Repository authority hands each commit a freeze that the daemon must
/// finalize before another transaction can be published, so the two exact
/// transitions a seal performs cannot both be built up front. The seal returns
/// this, the command loop finalizes the seal, and only then is the return
/// planned against the authority the seal actually installed.
struct ReturnToBase {
    sealed_workspace: WorkspaceState,
    base_head: kin_model::WorkspaceHead,
    base_target: RefTarget,
    base_tree: ResolvedTree,
    base_entities: std::collections::HashMap<kin_model::EntityId, kin_model::Entity>,
    base_relations: std::collections::HashMap<kin_model::RelationId, kin_model::Relation>,
    sealed_entities: std::collections::HashMap<kin_model::EntityId, kin_model::Entity>,
    sealed_relations: std::collections::HashMap<kin_model::RelationId, kin_model::Relation>,
    base_policy: SharedAdmissionPolicy,
    actor: AuthorId,
    stash_ref: RefName,
    entry: StashEntryReport,
}

struct StashExecution {
    response: StashResponse,
    receipt: RepositoryCommitReceipt,
    authority_freeze: kin_db::LocalRepositoryAuthorityFreeze,
    daemon_delta: TransactionDelta,
    previous_tree: ResolvedTree,
    desired_tree: ResolvedTree,
    projection_changed: bool,
}

#[derive(Debug)]
struct StashConflict(String);

impl std::fmt::Display for StashConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for StashConflict {}

fn stash_conflict(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(StashConflict(message.into()))
}

pub(crate) fn execute(
    state: &DaemonState,
    request: &StashRequest,
) -> std::result::Result<StashResponse, (StatusCode, String)> {
    if matches!(request, StashRequest::List) {
        let authority =
            ActiveLocalRepositoryAuthority::open_bound(state).map_err(stash_bind_refusal)?;
        return list(&authority, &state.layout).map_err(internal_stash_error);
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
        ActiveLocalRepositoryAuthority::open_bound(state).map_err(stash_bind_refusal)?;
    let outcome = match request {
        StashRequest::List => unreachable!("list returned before the mutation gates"),
        StashRequest::Push {
            message,
            operation_id,
            timestamp,
            actor,
        } => push(
            state,
            &authority,
            message.as_deref(),
            *operation_id,
            timestamp.clone(),
            actor,
        ),
        StashRequest::Pop {
            operation_id,
            actor,
        } => pop(state, &authority, *operation_id, actor),
    }
    .map_err(classify_stash_error)?;
    let (execution, follow_up) = match outcome {
        StashOutcome::Commit(execution, follow_up) => (execution, follow_up),
        StashOutcome::ReadOnly(response) => {
            drop(persistence);
            drop(graph_mutation);
            return Ok(response);
        }
    };

    let mut previous_graph_root = previous_graph_root;
    let mut response = finalize(state, execution, &mut previous_graph_root)?;
    if let Some(follow_up) = follow_up {
        let execution =
            return_to_base(state, &authority, *follow_up).map_err(classify_stash_error)?;
        response = finalize(state, execution, &mut previous_graph_root)?;
    }

    drop(persistence);
    drop(graph_mutation);
    Ok(response)
}

/// Install one committed transition into the daemon and release its freeze.
fn finalize(
    state: &DaemonState,
    execution: StashExecution,
    previous_graph_root: &mut String,
) -> std::result::Result<StashResponse, (StatusCode, String)> {
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
            old_root_hash: Some(previous_graph_root.clone()),
            new_root_hash: current_graph_root.clone(),
        });
        *previous_graph_root = current_graph_root;
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
    Ok(execution.response)
}

fn list(
    authority: &ActiveLocalRepositoryAuthority,
    layout: &kin_core::KinLayout,
) -> Result<StashResponse> {
    let lease = authority.manager.read_authority();
    let metadata = lease.metadata();
    let workspace = local_workspace(authority, metadata)?.clone();
    let sealed = metadata
        .ref_state
        .refs
        .iter()
        .filter_map(|repository_ref| {
            stash_ref_ordinal(&repository_ref.name)
                .map(|ordinal| (ordinal, repository_ref.name.clone(), &repository_ref.target))
        })
        .collect::<Vec<_>>();
    let mut entries = Vec::with_capacity(sealed.len());
    if !sealed.is_empty() {
        let graph = sealed_graph(&lease)?;
        for (ordinal, name, target) in sealed {
            let change_id = lease
                .resolve_target_change_id(target)
                .with_context(|| format!("resolve exact sealed change for stash {name}"))?;
            let change = sealed_change(&lease, &name, change_id)?;
            let sealed_state = graph
                .resolve_graph_at(&change_id)
                .with_context(|| format!("resolve exact graph at sealed change {change_id}"))?;
            entries.push(StashEntryReport {
                name,
                ordinal,
                change_id,
                message: change.message.clone(),
                timestamp: change.timestamp,
                base_target: change
                    .parents
                    .first()
                    .map(|parent| RefTarget::change(*parent)),
                tree_hash: compute_resolved_tree_hash(&sealed_state.tree)
                    .context("hash the exact sealed workspace tree")?,
                file_count: change.tree_deltas.len(),
                entity_count: change.entity_deltas.len(),
            });
        }
    }
    entries.sort_by(|left, right| right.ordinal.cmp(&left.ordinal));
    let report = StashListReport {
        schema: STASH_LIST_SCHEMA.to_string(),
        authority: "repository-v6".to_string(),
        repository_id: authority.repository_id.clone(),
        authority_generation: lease.roots().generation,
        workspace_id: workspace.workspace_id,
        workspace_generation: workspace.generation,
        workspace_dirty: workspace.is_dirty(),
        entries,
    };
    Ok(StashResponse {
        lines: render_list(&report, &kin_core::last_admission::read(layout)),
        mutated: false,
        report: Some(report),
        entry: None,
        operation_id: None,
        authority_generation: None,
        idempotent: false,
    })
}

/// Seal the exact graph-owned workspace state as one immutable stash change.
///
/// The sealed content is read from persisted workspace authority, never from
/// the daemon's mutable query overlay and never from a fresh host walk: what a
/// stash promises to restore is precisely the state that already crossed
/// admission. The live daemon graph must still agree with that authority, so
/// unadmitted daemon state is refused rather than silently dropped from the
/// seal.
fn push(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    message: Option<&str>,
    operation_id: OperationId,
    timestamp: Timestamp,
    actor: &AuthorId,
) -> Result<StashOutcome> {
    let lease = authority.manager.read_authority();
    if let Some(receipt) = operation_receipt(lease.metadata().receipts.as_slice(), operation_id) {
        drop(lease);
        return recover(authority, receipt);
    }
    let roots = lease.roots().clone();
    let metadata = lease.metadata();
    let workspace = local_workspace(authority, metadata)?.clone();
    if !workspace.is_dirty() {
        return Err(stash_conflict(
            "workspace holds no graph-owned changes to seal; its exact tree and semantics already \
             match its authority base",
        ));
    }
    let parent = workspace
        .base_target
        .as_ref()
        .map(|target| lease.resolve_target_change_id(target))
        .transpose()
        .context("resolve the exact authority target this workspace is based on")?;
    let workspace_graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .context("materialize exact graph-owned workspace semantics")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no graph snapshot for workspace {}",
                authority.repository_id,
                workspace.workspace_id
            )
        })?;
    let daemon_snapshot = state.graph.to_snapshot();
    let daemon_entities = daemon_snapshot.entities;
    let daemon_relations = daemon_snapshot.relations;
    let ordinal = next_stash_ordinal(metadata)?;
    let stash_ref = stash_ref_name(ordinal)?;
    if lease
        .resolve_ref_target(&stash_ref)
        .with_context(|| format!("read repository stash ref {stash_ref}"))?
        .is_some()
    {
        return Err(stash_conflict(format!(
            "repository stash ref {stash_ref} already exists"
        )));
    }

    let parent_policy = match parent {
        Some(parent) => Some(resolved_admission_policy(metadata, parent)?),
        None => None,
    };
    let (parent_tree, parent_entities, parent_relations) = match parent {
        Some(parent) => {
            let mut snapshot = lease.snapshot().clone();
            snapshot.repository_authority = None;
            let graph = kin_db::InMemoryGraph::from_snapshot(snapshot)
                .context("prepare the exact stash parent graph")?;
            let state = graph
                .resolve_graph_at(&parent)
                .with_context(|| format!("resolve exact graph at stash parent {parent}"))?;
            (state.tree.clone(), state.entities, state.relations)
        }
        None => (
            ResolvedTree::default(),
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        ),
    };
    // The sealed content is built exactly the way a native commit builds its
    // own: from the daemon graph the admission just installed, diffed against
    // the authority target. A stash that sealed only persisted workspace
    // authority would quietly drop whatever the same admission enriched.
    let sealed = crate::commit_deltas::compute_deltas_vs_repository_authority(
        state.graph.as_ref(),
        lease.snapshot(),
        parent.as_ref(),
    )
    .context("plan the exact sealed change against the authority target")?;
    let workspace_semantic_delta = kin_core::diff_workspace_semantics(
        &workspace_graph.entities,
        &workspace_graph.relations,
        &daemon_entities,
        &daemon_relations,
    )
    .context("plan the exact sealed workspace semantic transition")?;
    let (sealed_policy, admission_policy_delta) =
        SharedAdmissionPolicy::derive_from_tree_with_allowances(
            parent_policy.as_ref(),
            &sealed.expected_tree,
            |hash| repository_source_length(&authority.manager, hash),
            |hash| repository_source_body(&authority.manager, hash),
        )
        .context("derive the exact admission policy for the sealed workspace tree")?;
    let sealed_tree = sealed.expected_tree;
    let sealed_tree_hash =
        compute_resolved_tree_hash(&sealed_tree).context("hash the exact sealed workspace tree")?;
    let workspace_tree_deltas = kin_core::exact_tree_correction(&workspace.tree, &sealed_tree)
        .context("plan the exact sealed workspace tree transition")?;

    let mut change = SemanticChange {
        id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
        origin: ChangeOrigin::Native,
        parents: parent.into_iter().collect(),
        timestamp: timestamp.clone(),
        author: actor.clone(),
        message: seal_message(message, &workspace),
        entity_deltas: sealed.entity_deltas,
        relation_deltas: sealed.relation_deltas,
        tree_deltas: sealed.tree_deltas,
        admission_policy_delta,
        projected_files: Vec::new(),
        spec_link: None,
        evidence: Vec::new(),
        risk_summary: None,
        external_reference_deltas: Vec::new(),
    };
    change.id = compute_semantic_change_id(&change).context("identify the exact sealed change")?;
    let sealed_change_id = change.id;
    let sealed_file_count = change.tree_deltas.len();
    let sealed_entity_count = change.entity_deltas.len();
    let sealed_message = change.message.clone();
    let entry = StashEntryReport {
        name: stash_ref.clone(),
        ordinal,
        change_id: sealed_change_id,
        message: sealed_message,
        timestamp,
        base_target: parent.map(RefTarget::change),
        tree_hash: sealed_tree_hash,
        file_count: sealed_file_count,
        entity_count: sealed_entity_count,
    };

    // Repository authority binds one native admission to the workspace that
    // publishes it: a change introducing artifacts must leave its publisher
    // based on that exact change, so the introduced members have a workspace
    // whose admission policy validated them. A symbolic head must equal its
    // ref, so the publishing workspace detaches onto the sealed change without
    // moving a single projected byte, and a second exact transition returns it
    // to its branch base. Ordering is the safety property: the state is durable
    // before anything is discarded, and a failure between the two leaves a
    // clean workspace detached on the sealed change with every file still on
    // disk, recoverable with a branch switch or kin stash pop.
    let seal = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id,
        repository_id: authority.repository_id.clone(),
        expected_generation: roots.generation,
        expected_roots: roots.clone(),
        actor: actor.clone(),
        reason: SEAL_REASON.to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: vec![change],
        aliases: Vec::new(),
        ref_mutations: vec![RefMutation {
            name: stash_ref.clone(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(RefTarget::change(sealed_change_id)),
            policy: kin_model::RefUpdatePolicy::FastForwardOnly,
        }],
        default_ref_mutation: None,
        workspace_mutation: Some(WorkspaceMutation {
            workspace_id: workspace.workspace_id,
            expected: expect_exact(&workspace),
            new_generation: workspace.generation.checked_add(1).ok_or_else(|| {
                crate::error::workspace_generation_exhausted(
                    workspace.workspace_id,
                    workspace.generation,
                )
            })?,
            new_head: kin_model::WorkspaceHead::Detached {
                target: RefTarget::change(sealed_change_id),
            },
            new_base_target: Some(RefTarget::change(sealed_change_id)),
            new_base_tree_hash: Some(sealed_tree_hash),
            tree_deltas: workspace_tree_deltas,
            new_tree_hash: sealed_tree_hash,
            semantic_delta: workspace_semantic_delta,
            new_shared_admission_policy: sealed_policy.clone(),
            new_admission_policy: EffectiveAdmissionPolicyStamp {
                shared: sealed_policy.stamp(),
                local: workspace.admission_policy.local,
            },
        }),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
    };
    seal.validate()
        .context("validate the exact stash seal transaction")?;
    let sealed_workspace = WorkspaceState::new(
        workspace.repository_id.clone(),
        workspace.workspace_id,
        workspace.generation + 1,
        kin_model::WorkspaceHead::Detached {
            target: RefTarget::change(sealed_change_id),
        },
        Some(RefTarget::change(sealed_change_id)),
        Some(sealed_tree_hash),
        sealed_tree.clone(),
        kin_model::WorkspaceSemanticOverlay::default(),
        sealed_policy.clone(),
        EffectiveAdmissionPolicyStamp {
            shared: sealed_policy.stamp(),
            local: workspace.admission_policy.local,
        },
    )
    .context("derive the exact workspace state the seal installs")?;
    drop(lease);

    require_sealed_sources_in_repository_cas(&authority.manager, &sealed_policy, &seal)?;
    let (sealed_receipt, sealed_freeze) = authority
        .manager
        .commit_repository_transaction_and_freeze(seal)
        .context("seal a repository stash")?;
    sealed_receipt
        .validate()
        .context("validate the sealed stash receipt")?;
    let seal_execution = StashExecution {
        response: StashResponse {
            lines: vec![format!(
                "Sealed {} at change {} ({} file(s), {} entity delta(s), authority generation {})",
                stash_ref,
                sealed_change_id,
                sealed_file_count,
                sealed_entity_count,
                sealed_receipt.generation
            )],
            mutated: matches!(sealed_receipt.outcome, RepositoryCommitOutcome::Committed),
            report: None,
            entry: Some(entry.clone()),
            operation_id: Some(sealed_receipt.operation_id),
            authority_generation: Some(sealed_receipt.generation),
            idempotent: false,
        },
        receipt: sealed_receipt,
        authority_freeze: sealed_freeze,
        // The seal publishes the graph the daemon already holds, so it moves
        // persisted authority without moving the daemon's own view.
        daemon_delta: TransactionDelta::default(),
        previous_tree: workspace.tree.clone(),
        desired_tree: sealed_tree.clone(),
        projection_changed: false,
    };
    let base_target = workspace.base_target.clone().ok_or_else(|| {
        stash_conflict("an unborn workspace has no authority base to return to after sealing")
    })?;
    let base_policy = parent_policy.ok_or_else(|| {
        stash_conflict("an unborn workspace has no admission policy to return to after sealing")
    })?;
    Ok(StashOutcome::Commit(
        seal_execution,
        Some(Box::new(ReturnToBase {
            sealed_workspace,
            base_head: workspace.head,
            base_target,
            base_tree: parent_tree,
            base_entities: parent_entities,
            base_relations: parent_relations,
            sealed_entities: daemon_entities,
            sealed_relations: daemon_relations,
            base_policy,
            actor: actor.clone(),
            stash_ref,
            entry,
        })),
    ))
}

/// Return the sealed workspace to the branch base it was taken from.
///
/// This runs only after the seal is durable and finalized, so a failure here
/// discards nothing: the workspace is left clean and detached on the sealed
/// change with every file still projected, recoverable with a branch switch.
fn return_to_base(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    plan: ReturnToBase,
) -> Result<StashExecution> {
    let lease = authority.manager.read_authority();
    let roots = lease.roots().clone();
    drop(lease);
    let base_tree_hash = compute_resolved_tree_hash(&plan.base_tree)
        .context("hash the exact authority base tree")?;
    let tree_deltas = kin_core::exact_tree_correction(&plan.sealed_workspace.tree, &plan.base_tree)
        .context("plan the exact workspace return tree transition")?;
    let semantic_delta = kin_core::diff_workspace_semantics(
        &plan.sealed_entities,
        &plan.sealed_relations,
        &plan.base_entities,
        &plan.base_relations,
    )
    .context("plan the exact workspace return semantic transition")?;
    let daemon_snapshot = state.graph.to_snapshot();
    let daemon_semantic_delta = kin_core::diff_workspace_semantics(
        &daemon_snapshot.entities,
        &daemon_snapshot.relations,
        &plan.base_entities,
        &plan.base_relations,
    )
    .context("plan the exact workspace return transition for the daemon view")?;
    let daemon_delta = TransactionDelta {
        entity_deltas: daemon_semantic_delta.entity_deltas().to_vec(),
        relation_deltas: daemon_semantic_delta.relation_deltas().to_vec(),
        tree_deltas: kin_core::exact_tree_correction(
            &daemon_snapshot.resolved_tree,
            &plan.base_tree,
        )
        .context("plan the exact workspace return tree transition for the daemon view")?,
        admission_policy_delta: None,
        external_reference_deltas: Vec::new(),
    };
    let transaction =
        RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id: authority.repository_id.clone(),
            expected_generation: roots.generation,
            expected_roots: roots,
            actor: plan.actor.clone(),
            reason: RETURN_REASON.to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: Vec::new(),
            aliases: Vec::new(),
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: Some(WorkspaceMutation {
                workspace_id: plan.sealed_workspace.workspace_id,
                expected: expect_exact(&plan.sealed_workspace),
                new_generation: plan.sealed_workspace.generation.checked_add(1).ok_or_else(
                    || {
                        crate::error::workspace_generation_exhausted(
                            plan.sealed_workspace.workspace_id,
                            plan.sealed_workspace.generation,
                        )
                    },
                )?,
                new_head: plan.base_head,
                new_base_target: Some(plan.base_target),
                new_base_tree_hash: Some(base_tree_hash),
                tree_deltas,
                new_tree_hash: base_tree_hash,
                semantic_delta,
                new_shared_admission_policy: plan.base_policy.clone(),
                new_admission_policy: EffectiveAdmissionPolicyStamp {
                    shared: plan.base_policy.stamp(),
                    local: plan.sealed_workspace.admission_policy.local,
                },
            }),
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
    transaction
        .validate()
        .context("validate the exact workspace return transaction")?;
    let drift = kin_core::report_repository_workspace_projection_drift(
        state.layout.working_dir(),
        &plan.sealed_workspace.tree,
        &authority.manager,
    )
    .context("validate the exact workspace projection before returning it to its base")?;
    if let Some(first) = drift.first() {
        return Err(kin_core::KinError::projection_conflict(format!(
            "{first}; {} tracked path(s) diverge from the graph-owned workspace projection; the \
             workspace state is already sealed as {}",
            drift.len(),
            plan.stash_ref
        ))
        .into());
    }
    let (materialized, receipt, authority_freeze) =
        kin_core::tree::transition_repository_workspace_tree_and_commit_repository_transaction(
            state.layout.working_dir(),
            &plan.sealed_workspace.tree,
            &plan.base_tree,
            &authority.manager,
            transaction,
        )
        .with_context(|| {
            format!(
                "return the workspace to its authority base after sealing {}; the state is \
                 already sealed and can be restored with kin stash pop",
                plan.stash_ref
            )
        })?;
    receipt
        .validate()
        .context("validate the workspace-return receipt")?;
    Ok(StashExecution {
        response: StashResponse {
            lines: vec![
                format!(
                    "Sealed {} at change {} ({} file(s), {} entity delta(s))",
                    plan.stash_ref,
                    plan.entry.change_id,
                    plan.entry.file_count,
                    plan.entry.entity_count
                ),
                format!(
                    "Workspace returned to its authority base ({} projected entries, authority \
                     generation {})",
                    materialized, receipt.generation
                ),
            ],
            mutated: matches!(receipt.outcome, RepositoryCommitOutcome::Committed),
            report: None,
            entry: Some(plan.entry),
            operation_id: Some(receipt.operation_id),
            authority_generation: Some(receipt.generation),
            idempotent: false,
        },
        receipt,
        authority_freeze,
        daemon_delta,
        previous_tree: plan.sealed_workspace.tree,
        desired_tree: plan.base_tree,
        projection_changed: true,
    })
}

/// Restore the most recently sealed workspace state and drop its stash ref.
///
/// The restore refuses unless the workspace is clean and still based on the
/// exact authority target the stash was sealed against. Both refusals exist for
/// the same reason: a sealed state is a transition out of one observed base,
/// and no other base makes its tree or its semantics mean what they meant.
fn pop(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    operation_id: OperationId,
    actor: &AuthorId,
) -> Result<StashOutcome> {
    let lease = authority.manager.read_authority();
    if let Some(receipt) = operation_receipt(lease.metadata().receipts.as_slice(), operation_id) {
        drop(lease);
        return recover(authority, receipt);
    }
    let roots = lease.roots().clone();
    let metadata = lease.metadata();
    let workspace = local_workspace(authority, metadata)?.clone();
    let (ordinal, stash_ref, stash_target) = latest_stash(metadata)
        .ok_or_else(|| stash_conflict("repository holds no sealed stash to restore"))?;
    let sealed_change_id = lease
        .resolve_target_change_id(&stash_target)
        .with_context(|| format!("resolve exact sealed change for stash {stash_ref}"))?;
    let sealed_change = sealed_change(&lease, &stash_ref, sealed_change_id)?;

    if workspace.is_dirty() {
        return Err(stash_conflict(format!(
            "workspace {} holds graph-owned changes of its own; restoring {stash_ref} over them \
             would discard state no stash sealed. Seal or discard the current workspace first",
            workspace.workspace_id
        )));
    }
    let current_base = workspace
        .base_target
        .as_ref()
        .map(|target| lease.resolve_target_change_id(target))
        .transpose()
        .context("resolve the exact authority target this workspace is based on")?;
    let sealed_base = sealed_change.parents.first().copied();
    if current_base != sealed_base {
        return Err(stash_conflict(format!(
            "{stash_ref} was sealed against {}, but this workspace is now based on {}; exact \
             restore does not replan a sealed workspace state onto a base it was never observed \
             against",
            render_base(sealed_base),
            render_base(current_base)
        )));
    }
    let workspace_graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .context("materialize exact graph-owned workspace semantics")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no graph snapshot for workspace {}",
                authority.repository_id,
                workspace.workspace_id
            )
        })?;
    let mut snapshot = lease.snapshot().clone();
    snapshot.repository_authority = None;
    drop(lease);
    let graph = kin_db::InMemoryGraph::from_snapshot(snapshot)
        .context("prepare the exact sealed workspace graph")?;
    let sealed_state = graph
        .resolve_graph_at(&sealed_change_id)
        .with_context(|| format!("resolve exact graph at sealed change {sealed_change_id}"))?;
    let sealed_tree = sealed_state.tree.clone();
    let sealed_tree_hash =
        compute_resolved_tree_hash(&sealed_tree).context("hash the exact sealed workspace tree")?;
    let sealed_policy = {
        let lease = authority.manager.read_authority();
        resolved_admission_policy(lease.metadata(), sealed_change_id)?
    };
    let tree_deltas = kin_core::exact_tree_correction(&workspace.tree, &sealed_tree)
        .context("plan the exact stash restore tree transition")?;
    let semantic_delta = kin_core::diff_workspace_semantics(
        &workspace_graph.entities,
        &workspace_graph.relations,
        &sealed_state.entities,
        &sealed_state.relations,
    )
    .context("plan the exact stash restore semantic transition")?;
    let daemon_snapshot = state.graph.to_snapshot();
    let daemon_semantic_delta = kin_core::diff_workspace_semantics(
        &daemon_snapshot.entities,
        &daemon_snapshot.relations,
        &sealed_state.entities,
        &sealed_state.relations,
    )
    .context("plan the exact stash restore transition for the daemon view")?;
    let daemon_delta = TransactionDelta {
        entity_deltas: daemon_semantic_delta.entity_deltas().to_vec(),
        relation_deltas: daemon_semantic_delta.relation_deltas().to_vec(),
        tree_deltas: kin_core::exact_tree_correction(&daemon_snapshot.resolved_tree, &sealed_tree)
            .context("plan the exact stash restore tree transition for the daemon view")?,
        admission_policy_delta: None,
        external_reference_deltas: Vec::new(),
    };
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id,
        repository_id: authority.repository_id.clone(),
        expected_generation: roots.generation,
        expected_roots: roots,
        actor: actor.clone(),
        reason: RESTORE_REASON.to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: vec![RefMutation {
            name: stash_ref.clone(),
            expected: RefExpectation::MustEqual {
                target: stash_target,
            },
            new_target: None,
            policy: kin_model::RefUpdatePolicy::ForceWithLease,
        }],
        default_ref_mutation: None,
        workspace_mutation: Some(WorkspaceMutation {
            workspace_id: workspace.workspace_id,
            expected: expect_exact(&workspace),
            new_generation: workspace.generation.checked_add(1).ok_or_else(|| {
                crate::error::workspace_generation_exhausted(
                    workspace.workspace_id,
                    workspace.generation,
                )
            })?,
            new_head: workspace.head.clone(),
            new_base_target: workspace.base_target.clone(),
            new_base_tree_hash: workspace.base_tree_hash,
            tree_deltas,
            new_tree_hash: sealed_tree_hash,
            semantic_delta,
            new_shared_admission_policy: sealed_policy.clone(),
            new_admission_policy: EffectiveAdmissionPolicyStamp {
                shared: sealed_policy.stamp(),
                local: workspace.admission_policy.local,
            },
        }),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
    };
    transaction
        .validate()
        .context("validate the exact stash restore transaction")?;

    let drift = kin_core::report_repository_workspace_projection_drift(
        state.layout.working_dir(),
        &workspace.tree,
        &authority.manager,
    )
    .context("validate the exact workspace projection before restoring a stash")?;
    if let Some(first) = drift.first() {
        return Err(kin_core::KinError::projection_conflict(format!(
            "{first}; {} tracked path(s) diverge from the graph-owned workspace projection; \
             reconcile them into graph authority before restoring a stash",
            drift.len()
        ))
        .into());
    }
    let previous_tree = workspace.tree.clone();
    let (materialized, receipt, authority_freeze) =
        kin_core::tree::transition_repository_workspace_tree_and_commit_repository_transaction(
            state.layout.working_dir(),
            &previous_tree,
            &sealed_tree,
            &authority.manager,
            transaction,
        )
        .with_context(|| format!("restore repository stash {stash_ref}"))?;
    receipt
        .validate()
        .context("validate the restored stash receipt")?;

    Ok(StashOutcome::Commit(
        StashExecution {
            response: StashResponse {
                lines: vec![format!(
                    "Restored {} from change {} ({} projected entries, authority generation {})",
                    stash_ref, sealed_change_id, materialized, receipt.generation
                )],
                mutated: matches!(receipt.outcome, RepositoryCommitOutcome::Committed),
                report: None,
                entry: Some(StashEntryReport {
                    name: stash_ref,
                    ordinal,
                    change_id: sealed_change_id,
                    message: sealed_change.message,
                    timestamp: sealed_change.timestamp,
                    base_target: sealed_base.map(RefTarget::change),
                    tree_hash: sealed_tree_hash,
                    file_count: sealed_change.tree_deltas.len(),
                    entity_count: sealed_change.entity_deltas.len(),
                }),
                operation_id: Some(receipt.operation_id),
                authority_generation: Some(receipt.generation),
                idempotent: matches!(receipt.outcome, RepositoryCommitOutcome::IdempotentReplay),
            },
            receipt,
            authority_freeze,
            daemon_delta,
            previous_tree,
            desired_tree: sealed_tree,
            projection_changed: true,
        },
        None,
    ))
}

/// Answer a caller-stable operation whose exact effect already crossed
/// authority.
///
/// A sealed stash is carried by an immutable change, and the persisted
/// operation record deliberately does not retain history payloads, so the
/// original transaction cannot be rebuilt byte-identically from it. Rather than
/// approximate one, this reports the durable effect that is already installed.
/// Nothing is replanned, so a retry can never seal a second stash or restore
/// onto authority that has since moved.
fn recover(
    authority: &ActiveLocalRepositoryAuthority,
    receipt: RepositoryCommitReceipt,
) -> Result<StashOutcome> {
    receipt
        .validate()
        .context("validate the persisted stash receipt")?;
    let lease = authority.manager.read_authority();
    if lease.roots() != &receipt.roots_after {
        return Err(stash_conflict(format!(
            "stash operation {} committed at repository generation {}, but authority is now at \
             generation {}; reopen against current authority before retrying",
            receipt.operation_id,
            receipt.generation,
            lease.roots().generation
        )));
    }
    let mutation = receipt
        .operation
        .ref_mutations
        .first()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "stash operation {} has no repository ref effect",
                receipt.operation_id
            )
        })?
        .clone();
    let ordinal = stash_ref_ordinal(&mutation.name).ok_or_else(|| {
        anyhow::anyhow!(
            "operation {} is not a stash operation: it mutated {}",
            receipt.operation_id,
            mutation.name
        )
    })?;
    let entry = match mutation.new_target {
        Some(target) => {
            let change_id = lease.resolve_target_change_id(&target).with_context(|| {
                format!("resolve exact sealed change for stash {}", mutation.name)
            })?;
            let change = sealed_change(&lease, &mutation.name, change_id)?;
            let graph = sealed_graph(&lease)?;
            let sealed_state = graph
                .resolve_graph_at(&change_id)
                .with_context(|| format!("resolve exact graph at sealed change {change_id}"))?;
            Some(StashEntryReport {
                name: mutation.name.clone(),
                ordinal,
                change_id,
                message: change.message.clone(),
                timestamp: change.timestamp,
                base_target: change
                    .parents
                    .first()
                    .map(|parent| RefTarget::change(*parent)),
                tree_hash: compute_resolved_tree_hash(&sealed_state.tree)
                    .context("hash the exact sealed workspace tree")?,
                file_count: change.tree_deltas.len(),
                entity_count: change.entity_deltas.len(),
            })
        }
        None => None,
    };
    Ok(StashOutcome::ReadOnly(StashResponse {
        lines: vec![format!(
            "Stash operation {} already crossed authority at generation {} ({})",
            receipt.operation_id,
            receipt.generation,
            if entry.is_some() {
                format!("sealed {}", mutation.name)
            } else {
                format!("restored and dropped {}", mutation.name)
            }
        )],
        mutated: false,
        report: None,
        entry,
        operation_id: Some(receipt.operation_id),
        authority_generation: Some(receipt.generation),
        idempotent: true,
    }))
}

fn expect_exact(workspace: &WorkspaceState) -> WorkspaceExpectation {
    WorkspaceExpectation::MustEqual {
        generation: workspace.generation,
        head: workspace.head.clone(),
        base_target: workspace.base_target.clone(),
        base_tree_hash: workspace.base_tree_hash,
        tree_hash: workspace.tree_hash,
        semantic_overlay_hash: workspace.semantic_overlay_hash,
        admission_policy: workspace.admission_policy,
    }
}

/// Copy every body the sealed change names into repository-owned CAS.
///
/// Workspace authority already holds these bodies, so this is a repository-CAS
/// read followed by a repository-CAS write. No ingestion cache and no working
/// file is consulted: a stash that could only be restored while some
/// non-authoritative cache survived would not be a durable seal.
fn require_sealed_sources_in_repository_cas(
    manager: &kin_db::RepositoryAuthorityManager<kin_db::LocalFileBackend>,
    shared_policy: &SharedAdmissionPolicy,
    transaction: &RepositoryTransaction,
) -> Result<()> {
    let mut hashes = std::collections::BTreeSet::new();
    for change in &transaction.changes {
        for delta in &change.tree_deltas {
            if let Some(hash) = delta
                .new_state()
                .and_then(|located| located.entry.blob_identity())
            {
                hashes.insert(hash);
            }
        }
    }
    hashes.extend(shared_policy.sources.iter().map(|source| source.body_hash));
    for hash in hashes {
        if manager
            .load_source_blob(hash)
            .with_context(|| format!("read sealed source {hash} from repository CAS"))?
            .is_none()
        {
            bail!(
                "repository source CAS is missing exact body {hash}; the workspace state cannot \
                 be sealed as a restorable stash"
            );
        }
    }
    Ok(())
}

fn repository_source_body(
    manager: &kin_db::RepositoryAuthorityManager<kin_db::LocalFileBackend>,
    hash: Hash256,
) -> std::result::Result<Vec<u8>, kin_model::ModelError> {
    manager
        .load_source_blob(hash)
        .map_err(|error| {
            kin_model::ModelError::InvalidOperation(format!(
                "read graph-owned admission source {hash}: {error}"
            ))
        })?
        .ok_or_else(|| {
            kin_model::ModelError::InvalidOperation(format!(
                "repository source CAS is missing exact admission source {hash}"
            ))
        })
}

fn repository_source_length(
    manager: &kin_db::RepositoryAuthorityManager<kin_db::LocalFileBackend>,
    hash: Hash256,
) -> std::result::Result<u64, kin_model::ModelError> {
    let body = manager
        .load_source_blob(hash)
        .map_err(|error| {
            kin_model::ModelError::InvalidOperation(format!(
                "read graph-owned admission source {hash}: {error}"
            ))
        })?
        .ok_or_else(|| {
            kin_model::ModelError::InvalidOperation(format!(
                "repository source CAS is missing exact admission source {hash}"
            ))
        })?;
    u64::try_from(body.len()).map_err(|_| {
        kin_model::ModelError::InvalidOperation(format!(
            "graph-owned admission source {hash} exceeds u64"
        ))
    })
}

/// Materialize the immutable history graph behind one authority lease.
fn sealed_graph(
    lease: &kin_db::AuthorityReadLease<kin_db::RepositoryAuthorityState>,
) -> Result<kin_db::InMemoryGraph> {
    let mut snapshot = lease.snapshot().clone();
    snapshot.repository_authority = None;
    kin_db::InMemoryGraph::from_snapshot(snapshot).context("prepare the exact sealed change graph")
}

fn sealed_change(
    lease: &kin_db::AuthorityReadLease<kin_db::RepositoryAuthorityState>,
    name: &RefName,
    change_id: SemanticChangeId,
) -> Result<SemanticChange> {
    lease
        .snapshot()
        .changes
        .get(&change_id)
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "stash {name} names change {change_id}, which repository history does not hold"
            )
        })
}

fn next_stash_ordinal(metadata: &kin_db::PersistedRepositoryAuthority) -> Result<u64> {
    let highest = metadata
        .ref_state
        .refs
        .iter()
        .filter_map(|repository_ref| stash_ref_ordinal(&repository_ref.name))
        .max();
    match highest {
        Some(highest) => highest.checked_add(1).ok_or_else(|| {
            anyhow::anyhow!(
                "this repository has used every stash ordinal kin can record, so it cannot \
                     take another stash; nothing was written, so drop stashes you no longer need \
                     with `kin stash pop`"
            )
        }),
        None => Ok(0),
    }
}

fn latest_stash(
    metadata: &kin_db::PersistedRepositoryAuthority,
) -> Option<(u64, RefName, RefTarget)> {
    metadata
        .ref_state
        .refs
        .iter()
        .filter_map(|repository_ref| {
            stash_ref_ordinal(&repository_ref.name).map(|ordinal| {
                (
                    ordinal,
                    repository_ref.name.clone(),
                    repository_ref.target.clone(),
                )
            })
        })
        .max_by_key(|(ordinal, _, _)| *ordinal)
}

fn resolved_admission_policy(
    metadata: &kin_db::PersistedRepositoryAuthority,
    change_id: SemanticChangeId,
) -> Result<SharedAdmissionPolicy> {
    metadata
        .admission_policies
        .iter()
        .find(|resolved| resolved.change_id == change_id)
        .ok_or_else(|| {
            anyhow::anyhow!("change {change_id} has no repository-v6 admission-policy record")
        })?
        .policy
        .clone()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "change {change_id} has an unresolved admission policy and cannot bound a \
                 workspace"
            )
        })
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

fn seal_message(message: Option<&str>, workspace: &WorkspaceState) -> String {
    match message.map(str::trim).filter(|value| !value.is_empty()) {
        Some(message) => message.to_string(),
        None => match &workspace.head {
            kin_model::WorkspaceHead::Symbolic { target } => {
                format!("stash on {target}")
            }
            kin_model::WorkspaceHead::Detached { .. } => {
                "stash on a detached workspace".to_string()
            }
        },
    }
}

/// The base-change verdict with the basis it rests on.
///
/// Every arm states one. An absent or unparseable marker renders as its own arm
/// rather than as a bare verdict, because a surface that goes quiet when its
/// basis is unknown is indistinguishable from one reporting a healthy store,
/// which is the failure the marker was built to end.
fn workspace_state_clause(
    dirty: bool,
    admission: &kin_core::last_admission::LastAdmissionRead,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    use kin_core::last_admission::LastAdmissionRead;
    let verdict = if dirty {
        "ahead of its base change"
    } else {
        "matching its base change"
    };
    match admission {
        LastAdmissionRead::Recorded(recorded) => format!(
            "{verdict} as admitted {} ago",
            kin_core::last_admission::humanize_age(recorded.age_seconds(now))
        ),
        LastAdmissionRead::Absent => format!(
            "{verdict} as last admitted; this store records no complete admission, so how far \
             behind the working copy that is is unknown"
        ),
        LastAdmissionRead::Unreadable(reason) => format!(
            "{verdict} as last admitted; the last-admission record will not parse ({reason}), so \
             how far behind the working copy that is is unknown"
        ),
    }
}

fn render_base(change_id: Option<SemanticChangeId>) -> String {
    change_id.map_or_else(|| "an unborn base".to_string(), |id| id.to_string())
}

fn render_list(
    report: &StashListReport,
    admission: &kin_core::last_admission::LastAdmissionRead,
) -> Vec<String> {
    if report.entries.is_empty() {
        // Phrased as a comparison against the base change for the same reason
        // `kin status` is: "clean" reads as "everything on disk is in the
        // graph", which this flag does not mean and cannot answer.
        //
        // And carrying the admission's age for the same reason `kin status` now
        // does. That verdict compares two graph-owned values and is always right
        // about the graph; whether it is also a statement about the files on
        // disk depends on when the graph last looked, and with no clock beside it
        // there is nothing else for a reader to take it as. `kin status` shipped
        // the same bare sentence and a stranger read it over a tracked file
        // edited twenty-two seconds earlier (FIR-2961). This surface is lower
        // stakes, because nobody decides whether to commit off a stash listing,
        // and it is the same sentence.
        return vec![format!(
            "(no sealed stashes; workspace {} is {})",
            report.workspace_id,
            workspace_state_clause(report.workspace_dirty, admission, chrono::Utc::now())
        )];
    }
    report
        .entries
        .iter()
        .map(|entry| {
            format!(
                "{}  {}  {} file(s)  {}",
                entry.name, entry.change_id, entry.file_count, entry.message
            )
        })
        .collect()
}

fn classify_stash_error(error: anyhow::Error) -> (StatusCode, String) {
    if error.downcast_ref::<StashConflict>().is_some() {
        return (StatusCode::CONFLICT, crate::error::cause_first(&error));
    }
    if let Some(kin_core::KinError::ProjectionConflict(message)) =
        error.downcast_ref::<kin_core::KinError>()
    {
        return (StatusCode::CONFLICT, message.message.clone());
    }
    for cause in error.chain() {
        if let Some(model) = cause.downcast_ref::<kin_model::ModelError>() {
            if matches!(model, kin_model::ModelError::Conflict(_)) {
                return (StatusCode::CONFLICT, crate::error::cause_first(&error));
            }
        }
    }
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        crate::error::cause_first(&error),
    )
}

fn repository_finalization_error(error: crate::error::DaemonError) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

fn internal_stash_error(error: anyhow::Error) -> (StatusCode, String) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        crate::error::cause_first(&error),
    )
}

fn stash_bind_refusal(refusal: RepositoryAuthorityBindRefusal) -> (StatusCode, String) {
    let status = if refusal.is_identity_refusal() {
        StatusCode::CONFLICT
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (status, format!("{:#}", refusal.into_error()))
}

#[cfg(test)]
mod tests {
    use super::workspace_state_clause;
    use chrono::Utc;
    use kin_core::last_admission::{LastAdmission, LastAdmissionRead};

    /// FIR-2961. The verdict is right about the graph and says nothing about when
    /// the graph last looked, which is what a reader takes it for. `kin status`
    /// shipped the same bare sentence and a stranger read it over a tracked file
    /// edited twenty-two seconds earlier.
    #[test]
    fn the_empty_stash_verdict_carries_the_age_of_its_admission() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-08-29T20:49:16Z")
            .unwrap()
            .with_timezone(&Utc);
        let admitted_at = chrono::DateTime::parse_from_rfc3339("2026-08-29T20:47:16Z")
            .unwrap()
            .with_timezone(&Utc);
        let recorded = LastAdmissionRead::Recorded(LastAdmission::new(admitted_at, 8));

        let clean = workspace_state_clause(false, &recorded, now);
        assert!(clean.contains("matching its base change"), "{clean}");
        assert!(clean.contains("admitted 2m ago"), "{clean}");

        let dirty = workspace_state_clause(true, &recorded, now);
        assert!(dirty.contains("ahead of its base change"), "{dirty}");
        assert!(dirty.contains("admitted 2m ago"), "{dirty}");
    }

    /// An unknown basis is the case the marker exists for and must not render as
    /// a bare verdict, because a surface that goes quiet when its basis is
    /// unknown cannot be told from one reporting a healthy store.
    #[test]
    fn an_unknown_basis_is_never_rendered_as_a_bare_verdict() {
        let now = Utc::now();

        let absent = workspace_state_clause(false, &LastAdmissionRead::Absent, now);
        assert!(absent.contains("no complete admission"), "{absent}");

        let unreadable = workspace_state_clause(
            false,
            &LastAdmissionRead::Unreadable("trailing bytes".to_string()),
            now,
        );
        assert!(unreadable.contains("will not parse"), "{unreadable}");
        assert!(unreadable.contains("trailing bytes"), "{unreadable}");

        // The control. Every arm carries the verdict, so the qualification is an
        // addition to the answer and never a replacement for it.
        for clause in [&absent, &unreadable] {
            assert!(clause.contains("matching its base change"), "{clause}");
        }
    }
}
