// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon-owned reads and resolutions of the durable merge-transaction record.
//!
//! Everything here answers from the merge record repository authority holds for
//! the bound workspace. Nothing is read from the working copy, and no conflict
//! set is reconstructed from a sidecar: a merge that is not in the record is not
//! in progress, and a conflict the record does not carry cannot be settled.
//!
//! Settling and publishing are separate transactions by construction. A record
//! commits the resolutions it already carries, so the transaction that publishes
//! the merge is never the one that decided any part of it.

use anyhow::{Context, Result};
use axum::http::StatusCode;
use kin_cli::commands::conflicts::{
    ConflictsReport, ConflictsRequest, ConflictsResponse, CONFLICTS_REPORT_SCHEMA,
};
use kin_cli::commands::resolve::{
    ResolveAction, ResolveChoice, ResolveDirective, ResolveReport, ResolveRequest, ResolveResponse,
    RESOLVE_REPORT_SCHEMA,
};
use kin_db::{LocalFileBackend, LocalRepositoryAuthorityFreeze, RepositoryAuthorityManager};
use kin_model::{
    MergeConflictSubject, MergeEntryResolution, MergeResolutionPayload, MergeResolutionProvenance,
    MergeSide, MergeTransactionDelta, MergeTransactionRecord, MergeTransactionState,
    RepositoryCommitOutcome, RepositoryCommitReceipt, RepositoryTransaction, Timestamp,
    TransactionDelta, WorkspaceId, WorkspaceState, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};

use crate::local_repository_authority::ActiveLocalRepositoryAuthority;
use crate::repository_merge::{
    classify_merge_error, local_workspace, merge_bad_request, merge_bind_refusal, merge_conflict,
    publish_resolved_merge, render_artifact, render_conflict_lines, render_entry, render_subject,
    render_subject_identity, repository_finalization_error, restore_point, MergeExecution,
};
use crate::state::DaemonState;

const RESOLVE_REASON: &str = "settle repository-v6 merge conflicts";
const ABORT_REASON: &str = "abandon a repository-v6 merge transaction";

/// The merge record bound to one workspace, which is the only place a
/// repository-v6 merge in progress exists.
pub(crate) fn workspace_merge_record(
    metadata: &kin_db::PersistedRepositoryAuthority,
    workspace_id: WorkspaceId,
) -> Option<&MergeTransactionRecord> {
    metadata
        .merge_transactions
        .iter()
        .find(|record| record.workspace_id == workspace_id)
}

pub(crate) fn commit_and_freeze_exact(
    manager: &RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
) -> Result<(RepositoryCommitReceipt, LocalRepositoryAuthorityFreeze)> {
    match manager.commit_repository_transaction_and_freeze(transaction.clone()) {
        Ok(committed) => Ok(committed),
        Err(first_error) => manager
            .commit_repository_transaction_and_freeze(transaction)
            .map_err(|second_error| {
                anyhow::Error::new(second_error).context(format!(
                    "commit and freeze repository merge authority after first attempt failed: \
                     {first_error}"
                ))
            }),
    }
}

pub(crate) fn execute_conflicts(
    state: &DaemonState,
    _request: &ConflictsRequest,
) -> std::result::Result<ConflictsResponse, (StatusCode, String)> {
    let authority =
        ActiveLocalRepositoryAuthority::open_bound(state).map_err(merge_bind_refusal)?;
    read_conflicts(&authority).map_err(classify_merge_error)
}

fn read_conflicts(authority: &ActiveLocalRepositoryAuthority) -> Result<ConflictsResponse> {
    let lease = authority.manager.read_authority();
    let generation = lease.roots().generation;
    let metadata = lease.metadata();
    let workspace = local_workspace(authority, metadata)?;
    let record = workspace_merge_record(metadata, workspace.workspace_id).cloned();
    let repository_id = workspace.repository_id.clone();
    let workspace_id = workspace.workspace_id;
    drop(lease);

    let (lines, unresolved_count, resolved_count) = match &record {
        None => (
            vec![format!(
                "No merge has opened on workspace {workspace_id}; there is nothing to resolve"
            )],
            0,
            0,
        ),
        Some(record) => {
            let unresolved = record.unresolved().count();
            let resolved = record.entries.len() - unresolved;
            let mut lines = Vec::new();
            match &record.state {
                MergeTransactionState::InProgress => {
                    lines.push(format!(
                        "Merging {} into {} is in progress as merge transaction {} ({} of {} \
                         conflict(s) settled)",
                        record.binding.source_ref,
                        record.binding.target_ref,
                        record.hash,
                        resolved,
                        record.entries.len()
                    ));
                    if unresolved == 0 {
                        lines.push(
                            "Every conflict is settled; publish the merge with `kin resolve \
                             --continue`"
                                .to_string(),
                        );
                    } else {
                        lines.extend(render_conflict_lines(
                            &record.unresolved().collect::<Vec<_>>(),
                        ));
                    }
                }
                MergeTransactionState::Committed { merge_change, .. } => lines.push(format!(
                    "The last merge of {} into {} published as change {merge_change}; no merge is \
                     in progress",
                    record.binding.source_ref, record.binding.target_ref
                )),
                MergeTransactionState::Aborted { .. } => lines.push(format!(
                    "The last merge of {} into {} was abandoned; no merge is in progress",
                    record.binding.source_ref, record.binding.target_ref
                )),
            }
            (lines, unresolved, resolved)
        }
    };
    let record_hash = record.as_ref().map(|record| record.hash.to_string());
    Ok(ConflictsResponse {
        lines,
        report: Some(ConflictsReport {
            schema: CONFLICTS_REPORT_SCHEMA.to_string(),
            authority: "repository-v6".to_string(),
            repository_id,
            workspace_id,
            authority_generation: generation,
            record,
            record_hash,
            unresolved_count,
            resolved_count,
        }),
    })
}

pub(crate) fn execute_resolve(
    state: &DaemonState,
    request: &ResolveRequest,
) -> std::result::Result<ResolveResponse, (StatusCode, String)> {
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
    let execution = plan_resolution(state, &authority, request).map_err(classify_merge_error)?;
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
        state.emit_event(crate::state::DaemonEvent::GraphRootChanged {
            old_root_hash: Some(previous_graph_root),
            new_root_hash: current_graph_root,
        });
    } else if finalization.generation_advanced {
        state.mark_dirty();
    }
    if finalization.generation_advanced {
        state.emit_event(crate::state::DaemonEvent::RepositoryAuthorityChanged {
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
    Ok(execution.resolve_response)
}

/// One resolution's outcome, carrying the merge execution the daemon finalizes.
pub(crate) struct ResolveExecution {
    resolve_response: ResolveResponse,
    receipt: RepositoryCommitReceipt,
    authority_freeze: LocalRepositoryAuthorityFreeze,
    daemon_delta: TransactionDelta,
    previous_tree: kin_model::ResolvedTree,
    desired_tree: kin_model::ResolvedTree,
}

fn plan_resolution(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    request: &ResolveRequest,
) -> Result<ResolveExecution> {
    let lease = authority.manager.read_authority();
    let roots = lease.roots().clone();
    let metadata = lease.metadata();
    let workspace = local_workspace(authority, metadata)?.clone();
    let record = workspace_merge_record(metadata, workspace.workspace_id)
        .cloned()
        .ok_or_else(|| {
            merge_conflict(format!(
                "workspace {} has no merge transaction; there is nothing to resolve",
                workspace.workspace_id
            ))
        })?;
    drop(lease);

    if !record.state.is_in_progress() {
        return Err(merge_conflict(format!(
            "the last merge of {} into {} has already terminated; start a new merge with `kin \
             merge`",
            record.binding.source_ref, record.binding.target_ref
        )));
    }
    if let Some(expected) = request.expected_record {
        if expected != record.hash {
            return Err(merge_conflict(format!(
                "merge transaction {} has advanced to {} since this session read it; re-read it \
                 with `kin conflicts` before resolving",
                expected, record.hash
            )));
        }
    }

    match &request.action {
        ResolveAction::Settle { directives, all } => settle(
            authority, request, roots, workspace, record, directives, *all,
        ),
        ResolveAction::Continue => {
            let execution =
                publish_resolved_merge(state, authority, request, roots, workspace, record)?;
            Ok(into_resolve_execution(execution))
        }
        ResolveAction::Abort => abort(authority, request, roots, workspace, record),
    }
}

fn into_resolve_execution(execution: MergeExecution) -> ResolveExecution {
    ResolveExecution {
        resolve_response: execution
            .resolve_response
            .expect("a merge execution reached through resolve carries its resolve response"),
        receipt: execution.receipt,
        authority_freeze: execution.authority_freeze,
        daemon_delta: execution.daemon_delta,
        previous_tree: execution.previous_tree,
        desired_tree: execution.desired_tree,
    }
}

/// Settle named entries, and optionally every entry one side can settle, in one
/// transaction.
#[allow(clippy::too_many_arguments)]
fn settle(
    authority: &ActiveLocalRepositoryAuthority,
    request: &ResolveRequest,
    roots: kin_model::RootBundle,
    workspace: WorkspaceState,
    record: MergeTransactionRecord,
    directives: &[ResolveDirective],
    all: Option<MergeSide>,
) -> Result<ResolveExecution> {
    let provenance = MergeResolutionProvenance {
        actor: request.actor.clone(),
        operation_id: request.operation_id,
        resolved_at: Timestamp::now(),
    };
    let mut next = record.clone();
    let mut settled = Vec::new();
    for directive in directives {
        let subject = select_subject(&next, &directive.selector)?;
        let resolution = resolution_for(&next, &subject, &directive.choice, &provenance)?;
        next = next
            .resolve_entry(&subject, resolution)
            .with_context(|| format!("settle merge conflict {}", directive.selector))?;
        settled.push(subject);
    }
    if let Some(side) = all {
        // A contested path has no side to take, so taking a side for
        // everything settles every value divergence and leaves paths named
        // rather than silently deciding an owner for them.
        let remaining: Vec<MergeConflictSubject> = next
            .unresolved()
            .filter(|entry| !matches!(entry.subject, MergeConflictSubject::Path { .. }))
            .map(|entry| entry.subject.clone())
            .collect();
        for subject in remaining {
            let resolution =
                resolution_for(&next, &subject, &ResolveChoice::Side { side }, &provenance)?;
            next = next.resolve_entry(&subject, resolution).with_context(|| {
                format!(
                    "settle merge conflict {} by taking the {side:?} side",
                    render_subject_identity(&subject)
                )
            })?;
            settled.push(subject);
        }
    }
    if settled.is_empty() {
        return Err(merge_bad_request(
            "no conflict matched this resolution; list what is outstanding with `kin conflicts`"
                .to_string(),
        ));
    }

    let transaction = record_transaction(
        &workspace,
        &roots,
        request,
        RESOLVE_REASON,
        MergeTransactionDelta::update(record, next.clone()),
    );
    transaction
        .validate()
        .context("validate the merge resolution transaction")?;
    let (receipt, authority_freeze) = commit_and_freeze_exact(&authority.manager, transaction)
        .context("settle merge conflicts")?;

    let unresolved = next.unresolved().count();
    let mut lines = vec![format!(
        "Settled {} conflict(s); merge transaction {} has {} of {} conflict(s) settled",
        settled.len(),
        next.hash,
        next.entries.len() - unresolved,
        next.entries.len()
    )];
    if unresolved == 0 {
        lines.push("Publish the merge with `kin resolve --continue`".to_string());
    } else {
        lines.extend(render_conflict_lines(
            &next.unresolved().collect::<Vec<_>>(),
        ));
    }
    Ok(record_execution(
        lines,
        workspace,
        receipt,
        authority_freeze,
        next,
        None,
    ))
}

/// Abandon the merge, proving the workspace still equals its restore point.
fn abort(
    authority: &ActiveLocalRepositoryAuthority,
    request: &ResolveRequest,
    roots: kin_model::RootBundle,
    workspace: WorkspaceState,
    record: MergeTransactionRecord,
) -> Result<ResolveExecution> {
    let current = restore_point(&workspace);
    if current != record.restore {
        return Err(merge_conflict(format!(
            "workspace {} no longer equals the restore point this merge recorded, so abandoning \
             it cannot prove the workspace it restores; reconcile the workspace into graph \
             authority first",
            workspace.workspace_id
        )));
    }
    let next = record
        .terminate(MergeTransactionState::Aborted {
            operation_id: request.operation_id,
            actor: request.actor.clone(),
            aborted_at: Timestamp::now(),
        })
        .context("terminate the merge transaction as abandoned")?;
    let transaction = record_transaction(
        &workspace,
        &roots,
        request,
        ABORT_REASON,
        MergeTransactionDelta::update(record.clone(), next.clone()),
    );
    transaction
        .validate()
        .context("validate the merge abort transaction")?;
    let (receipt, authority_freeze) = commit_and_freeze_exact(&authority.manager, transaction)
        .context("abandon the merge transaction")?;
    let lines = vec![format!(
        "Abandoned the merge of {} into {}; workspace {} is unchanged at the recorded restore \
         point (authority generation {})",
        record.binding.source_ref,
        record.binding.target_ref,
        workspace.workspace_id,
        receipt.generation
    )];
    Ok(record_execution(
        lines,
        workspace,
        receipt,
        authority_freeze,
        next,
        None,
    ))
}

/// A transaction that moves only the merge record: no change, no ref, no
/// workspace mutation.
fn record_transaction(
    workspace: &WorkspaceState,
    roots: &kin_model::RootBundle,
    request: &ResolveRequest,
    reason: &str,
    delta: MergeTransactionDelta,
) -> RepositoryTransaction {
    RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: request.operation_id,
        repository_id: workspace.repository_id.clone(),
        expected_generation: roots.generation,
        expected_roots: roots.clone(),
        actor: request.actor.clone(),
        reason: reason.to_string(),
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
    }
}

fn record_execution(
    lines: Vec<String>,
    workspace: WorkspaceState,
    receipt: RepositoryCommitReceipt,
    authority_freeze: LocalRepositoryAuthorityFreeze,
    record: MergeTransactionRecord,
    merge_change: Option<kin_model::SemanticChangeId>,
) -> ResolveExecution {
    let unresolved = record.unresolved().count();
    let report = ResolveReport {
        schema: RESOLVE_REPORT_SCHEMA.to_string(),
        authority: "repository-v6".to_string(),
        repository_id: workspace.repository_id.clone(),
        workspace_id: workspace.workspace_id,
        authority_generation: receipt.generation,
        roots: receipt.roots_after.clone(),
        resolved_count: record.entries.len() - unresolved,
        unresolved_count: unresolved,
        record: Some(record),
        merge_change,
    };
    let tree = workspace.tree;
    ResolveExecution {
        resolve_response: ResolveResponse {
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
    }
}

/// Resolve a caller's selector to exactly one recorded conflict.
///
/// Ambiguity is refused rather than broken by preference: settling the wrong
/// identity is indistinguishable from settling the right one once the merge
/// publishes.
fn select_subject(record: &MergeTransactionRecord, selector: &str) -> Result<MergeConflictSubject> {
    let needle = selector.trim();
    if needle.is_empty() {
        return Err(merge_bad_request("a conflict selector must not be blank"));
    }
    let matched: Vec<&kin_model::MergeConflictEntry> = record
        .entries
        .iter()
        .filter(|entry| entry_matches(entry, needle))
        .collect();
    match matched.as_slice() {
        [] => Err(merge_bad_request(format!(
            "no recorded merge conflict matches {needle}; list what is outstanding with `kin \
             conflicts`"
        ))),
        [entry] => Ok(entry.subject.clone()),
        several => Err(merge_bad_request(format!(
            "{needle} matches {} recorded merge conflicts; name one exactly: {}",
            several.len(),
            several
                .iter()
                .map(|entry| render_subject(entry))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// Identity first, then the label a listing showed. A caller may name what they
/// read, but an id always names exactly one conflict.
fn entry_matches(entry: &kin_model::MergeConflictEntry, needle: &str) -> bool {
    let by_identity = match &entry.subject {
        MergeConflictSubject::Entity { entity } => entity.to_string() == needle,
        MergeConflictSubject::Relation { relation } => relation.to_string() == needle,
        MergeConflictSubject::Artifact { artifact } => render_artifact(artifact) == needle,
        MergeConflictSubject::Path { path } => path.to_string() == needle,
    };
    if by_identity {
        return true;
    }
    match &entry.label {
        Some(label) => label == needle,
        None => false,
    }
}

fn resolution_for(
    record: &MergeTransactionRecord,
    subject: &MergeConflictSubject,
    choice: &ResolveChoice,
    provenance: &MergeResolutionProvenance,
) -> Result<MergeEntryResolution> {
    Ok(match choice {
        ResolveChoice::Side { side } => {
            if matches!(subject, MergeConflictSubject::Path { .. }) {
                return Err(merge_bad_request(
                    "a contested path has no side to take; name the claimant that keeps it with \
                     --keep-path <PATH>=<ARTIFACT>",
                ));
            }
            MergeEntryResolution::Side {
                side: *side,
                provenance: provenance.clone(),
            }
        }
        ResolveChoice::Remove => MergeEntryResolution::Payload {
            payload: MergeResolutionPayload::Removed,
            provenance: provenance.clone(),
        },
        ResolveChoice::PathOwner { artifact } => {
            let entry = record
                .entries
                .iter()
                .find(|entry| &entry.subject == subject)
                .ok_or_else(|| merge_bad_request("merge record has no conflict for that path"))?;
            let kin_model::MergeDivergence::PathCollision { artifacts } = &entry.divergence else {
                return Err(merge_bad_request(
                    "--keep-path settles a contested path; this conflict is not one",
                ));
            };
            let owner = artifacts
                .iter()
                .find(|claimant| render_artifact(claimant) == artifact.trim())
                .copied()
                .ok_or_else(|| {
                    merge_bad_request(format!(
                        "{artifact} does not claim this path; its claimants are {}",
                        artifacts
                            .iter()
                            .map(render_artifact)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                })?;
            MergeEntryResolution::Payload {
                payload: MergeResolutionPayload::PathOwner { artifact: owner },
                provenance: provenance.clone(),
            }
        }
    })
}

/// Render one entry for a refusal that names what is still outstanding.
pub(crate) fn describe_unresolved(record: &MergeTransactionRecord) -> String {
    record
        .unresolved()
        .map(render_entry)
        .collect::<Vec<_>>()
        .join("; ")
}
