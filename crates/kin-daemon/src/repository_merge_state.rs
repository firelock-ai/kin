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
use kin_db::{
    ChangeStore, LocalFileBackend, LocalRepositoryAuthorityFreeze, RepositoryAuthorityManager,
};
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
    request: &ConflictsRequest,
) -> std::result::Result<ConflictsResponse, (StatusCode, String)> {
    let authority =
        ActiveLocalRepositoryAuthority::open_bound(state).map_err(merge_bind_refusal)?;
    read_conflicts(state, &authority, request).map_err(classify_merge_error)
}

fn read_conflicts(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    request: &ConflictsRequest,
) -> Result<ConflictsResponse> {
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
    let bodies = match (&record, request.bodies) {
        (Some(record), true) => materialize_bodies(state, record),
        _ => Vec::new(),
    };
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
            bodies,
        }),
    })
}

/// Re-materialize each conflict subject's three sides as source.
///
/// The record holds one `Hash256` per side, and it is a digest of the model
/// value rather than a content address, so nothing can be looked up from it. The
/// bytes come from the graph at the three changes this merge bound, which is the
/// only place they exist, and each side is hashed back to the recorded digest
/// before it is offered. That check is what makes the rendering an account of
/// the merge rather than an account of the graph as it stands now: a side whose
/// value has moved is named, not shown.
///
/// A side that cannot be read is named too. A body quietly missing reads exactly
/// like an identity that is absent on that side, and those are opposite facts.
fn materialize_bodies(
    state: &DaemonState,
    record: &MergeTransactionRecord,
) -> Vec<kin_cli::commands::conflicts::ConflictBody> {
    materialize_bodies_at(
        state,
        &record.binding.base_change,
        &record.binding.ours_change,
        &record.binding.theirs_change,
        &record.entries,
    )
}

/// The half of [`materialize_bodies`] that needs only the three bound changes
/// and the entries.
///
/// Split out so a test can hand it a record whose recorded digest disagrees
/// with the graph. Without that seam the verification below is a check nothing
/// can fail: on a healthy merge every side hashes back, so deleting the check
/// changes nothing any fixture built through the product can observe.
pub(crate) fn materialize_bodies_at(
    state: &DaemonState,
    base_change: &kin_db::SemanticChangeId,
    ours_change: &kin_db::SemanticChangeId,
    theirs_change: &kin_db::SemanticChangeId,
    entries: &[kin_model::MergeConflictEntry],
) -> Vec<kin_cli::commands::conflicts::ConflictBody> {
    let sides = [
        ("base", base_change),
        ("ours", ours_change),
        ("theirs", theirs_change),
    ];
    let resolved: Vec<(&str, Option<kin_model::graph::ResolvedGraphState>)> = sides
        .iter()
        .map(|(name, change)| (*name, state.graph.resolve_graph_at(change).ok()))
        .collect();

    let mut out = Vec::new();
    for entry in entries.iter() {
        if !matches!(
            entry.subject,
            MergeConflictSubject::Entity { .. } | MergeConflictSubject::Artifact { .. }
        ) {
            // A relation has no source of its own. Rendering its endpoints here
            // would print the same bodies twice under a different name.
            continue;
        }
        let mut body = kin_cli::commands::conflicts::ConflictBody {
            subject: render_subject_identity(&entry.subject),
            label: entry.label.clone(),
            base: None,
            ours: None,
            theirs: None,
            unverified: Vec::new(),
        };
        for (name, state_at) in resolved.iter() {
            let recorded = match *name {
                "base" => &entry.base,
                "ours" => &entry.ours,
                _ => &entry.theirs,
            };
            match side_source(state, state_at.as_ref(), &entry.subject, recorded) {
                SideSource::Absent => {}
                SideSource::Source(text) => match *name {
                    "base" => body.base = Some(text),
                    "ours" => body.ours = Some(text),
                    _ => body.theirs = Some(text),
                },
                SideSource::Unverified => body.unverified.push((*name).to_string()),
            }
        }
        out.push(body);
    }
    out
}

/// Whether the value re-read from the graph is the one the record bound.
///
/// One site, deliberately. An entity and an artifact reach this by different
/// routes and hash different model values, but the decision they make is the
/// same one, and a decision written twice can be deleted once: a mutation
/// removing only the entity copy would survive a test that grades only the
/// artifact, which is the shape where two branches reporting the same field
/// hide each other's absence.
fn side_agrees(
    recomputed: std::result::Result<kin_model::MergeSideValue, kin_model::ModelError>,
    recorded: &kin_model::MergeSideValue,
) -> bool {
    matches!(recomputed, Ok(value) if &value == recorded)
}

/// What one side of one conflict subject could be read as.
enum SideSource {
    /// The identity does not exist on this side, which the record agrees with.
    Absent,
    Source(String),
    /// The value did not hash back to the recorded digest, or its bytes could
    /// not be read. Never rendered, always named.
    Unverified,
}

fn side_source(
    state: &DaemonState,
    state_at: Option<&kin_model::graph::ResolvedGraphState>,
    subject: &MergeConflictSubject,
    recorded: &kin_model::MergeSideValue,
) -> SideSource {
    let Some(state_at) = state_at else {
        return SideSource::Unverified;
    };
    match subject {
        MergeConflictSubject::Entity { entity } => {
            let held = state_at.entities.get(entity);
            match (held, recorded) {
                (None, kin_model::MergeSideValue::Absent) => SideSource::Absent,
                (Some(held), _) => {
                    if !side_agrees(kin_model::MergeSideValue::entity(Some(held)), recorded) {
                        return SideSource::Unverified;
                    }
                    let Some(span) = held.span.as_ref() else {
                        return SideSource::Unverified;
                    };
                    // `FilePathId` already holds a UTF-8 path, so this crossing
                    // adds no new failure mode; a path it cannot express is
                    // reported rather than approximated.
                    let Ok(path) = kin_model::RepoPath::from_utf8(span.file.0.clone()) else {
                        return SideSource::Unverified;
                    };
                    let Some(artifact) = state_at.tree.artifact_at_path(&path) else {
                        return SideSource::Unverified;
                    };
                    match blob_text(state, artifact) {
                        Some(text) => slice_span(&text, span.start_byte, span.end_byte)
                            .map(SideSource::Source)
                            .unwrap_or(SideSource::Unverified),
                        None => SideSource::Unverified,
                    }
                }
                _ => SideSource::Unverified,
            }
        }
        MergeConflictSubject::Artifact { artifact } => {
            let held = state_at.tree.get(artifact);
            match (held, recorded) {
                (None, kin_model::MergeSideValue::Absent) => SideSource::Absent,
                (Some(held), _) => {
                    if !side_agrees(kin_model::MergeSideValue::artifact(Some(held)), recorded) {
                        return SideSource::Unverified;
                    }
                    match blob_text(state, held) {
                        Some(text) => SideSource::Source(text),
                        None => SideSource::Unverified,
                    }
                }
                _ => SideSource::Unverified,
            }
        }
        _ => SideSource::Unverified,
    }
}

/// The artifact's bytes as text, or `None` when it is not a readable blob.
///
/// A symlink and a gitlink are deliberately not text: their tree entries carry
/// a target rather than a body, and printing one as source would be a fiction.
fn blob_text(state: &DaemonState, artifact: &kin_model::ResolvedArtifact) -> Option<String> {
    let kin_model::TreeEntry::Blob { hash, .. } = &artifact.entry else {
        return None;
    };
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)
            .ok()?;
    let bytes = crate::repository_commit::load_native_source_blob(&context, *hash).ok()?;
    String::from_utf8(bytes).ok()
}

/// The entity's own bytes inside its file.
///
/// Refuses rather than clamps. A span that does not lie on character boundaries
/// or runs past the end of the blob means the span and the bytes disagree, and a
/// clamped slice would render a body that is not the entity's while looking
/// exactly like one that is.
fn slice_span(text: &str, start: usize, end: usize) -> Option<String> {
    if end < start || end > text.len() {
        return None;
    }
    text.get(start..end).map(|slice| slice.to_string())
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
