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

use std::collections::{BTreeMap, BTreeSet};

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
    EntityStore, MergeConflictSubject, MergeEntryResolution, MergeResolutionPayload,
    MergeResolutionProvenance, MergeSide, MergeTransactionDelta, MergeTransactionRecord,
    MergeTransactionState, RepositoryCommitOutcome, RepositoryCommitReceipt, RepositoryTransaction,
    Timestamp, TransactionDelta, WorkspaceId, WorkspaceState,
    REPOSITORY_TRANSACTION_SCHEMA_VERSION,
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

/// What a caller needs to refuse around an open merge without carrying the
/// record: the transaction to name, the two refs it binds, and how much of it
/// is already settled.
#[derive(Clone)]
pub(crate) struct OpenMergeSummary {
    pub(crate) transaction: String,
    pub(crate) source_ref: String,
    pub(crate) target_ref: String,
    pub(crate) unresolved_count: usize,
    pub(crate) conflict_count: usize,
}

/// The merge a workspace still holds open, summarized from an authority lease.
///
/// Takes the lease rather than the metadata a caller has already read, so the
/// accessor stays in this module. Every `.metadata()` here reads a repository-v6
/// authority lease and returns graph-owned truth, which is the justification
/// this module carries; the daemon RPC surface is scanned in full because it is
/// the answer authority, and moving one accessor into the module that owns
/// merge state is the cheaper of the two ways to keep both statements true.
pub(crate) fn open_merge_summary(
    lease: &kin_db::AuthorityReadLease<kin_db::RepositoryAuthorityState>,
    workspace_id: WorkspaceId,
) -> Option<OpenMergeSummary> {
    workspace_merge_record(lease.metadata(), workspace_id)
        .filter(|record| record.state.is_in_progress())
        .map(|record| OpenMergeSummary {
            transaction: record.hash.to_string(),
            source_ref: record.binding.source_ref.to_string(),
            target_ref: record.binding.target_ref.to_string(),
            unresolved_count: record.unresolved().count(),
            conflict_count: record.entries.len(),
        })
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
) -> std::result::Result<ResolveResponse, crate::repository_merge::CommandRefusal> {
    use crate::repository_merge::CommandRefusal;
    let graph_mutation = state.begin_graph_authority_mutation();
    let persistence = state.persist_lock.lock().map_err(|_| {
        CommandRefusal::from((
            StatusCode::INTERNAL_SERVER_ERROR,
            "daemon persistence lock poisoned".to_string(),
        ))
    })?;
    let previous_graph_root = hex::encode(state.graph.compute_root_hash());
    // Same boundary as the merge: everything to `finalize_local_repository_commit`
    // below runs before this command's first authority write. `plan_resolution`
    // is where a settlement is refused and where `resolve --continue` refuses
    // with conflicts outstanding, which is the refusal that was being reported
    // as a possible write.
    let authority = ActiveLocalRepositoryAuthority::open_bound(state)
        .map_err(|refusal| CommandRefusal::before_write(merge_bind_refusal(refusal)))?;
    let mut execution = plan_resolution(state, &authority, request)
        .map_err(|error| CommandRefusal::before_write(classify_merge_error(error)))?;
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

    // Settled after the finalization for the reason `repository_merge::execute`
    // settles after its own: a merge published through `resolve --continue`
    // reaches the live entity and relation table at exactly this call and not
    // before it.
    //
    // A settlement and an abort reach here too, and neither composed a merged
    // graph, so neither settles one.
    if execution.published_merged_graph {
        execution
            .resolve_response
            .lines
            .extend(crate::repository_merge::settle_merged_graph(state));
    }

    // The freeze this resolution committed under is an EXCLUSIVE cross-process
    // lease over the repository's storage lock, and the graph-section writer
    // takes that same lock, so it is released before the refresh rather than at
    // the end of the function. Holding it across the refresh is a command
    // waiting on itself.
    //
    // This is also why `publish_resolved_merge` cannot make the call itself the
    // way `repository_merge::execute` does: it hands the freeze back inside its
    // `MergeExecution` for the finalization above, so at every point inside it
    // the lease is still alive.
    drop(execution.authority_freeze);

    // A merge published through `resolve --continue` moves this workspace's
    // base exactly as a plain merge does, and it publishes through
    // `publish_resolved_merge` rather than through the `execute` path that
    // refreshes the section, so before this a resolved merge left every later
    // open folding the merged base out of history. Same rule as the commit, the
    // workspace transition and the plain merge: idempotent, run under the gates
    // this resolution already holds, and never fatal, because the merge is
    // durable and a memoization that did not persist is a slower next open.
    //
    // A settlement and an abort reach here too. Neither moves this workspace's
    // base, so the writer finds the section valid and returns `AlreadyCurrent`
    // with no durable write.
    crate::repository_commit::refresh_workspace_base_graph_section(
        &authority.manager,
        &authority.repository_id,
        authority.workspace_id,
        "resolved merge",
    );

    drop(persistence);
    drop(graph_mutation);
    Ok(execution.resolve_response)
}

/// One resolution's outcome, carrying the merge execution the daemon finalizes.
pub(crate) struct ResolveExecution {
    resolve_response: ResolveResponse,
    /// Whether this execution published a merged graph. False for a settlement
    /// and for an abort, which record decisions and restore a workspace without
    /// composing one; see [`MergeExecution::published_merged_graph`].
    published_merged_graph: bool,
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
            state, authority, request, roots, workspace, record, directives, *all,
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
        published_merged_graph: execution.published_merged_graph,
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
    state: &DaemonState,
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
    let (authored, covered) =
        settle_authored_files(state, authority, &record, directives, &provenance)?;
    for (subject, resolution) in authored {
        next = next.resolve_entry(&subject, resolution)?;
        settled.push(subject);
    }
    for directive in directives {
        if matches!(directive.choice, ResolveChoice::File { .. }) {
            continue;
        }
        let subject = select_subject(&next, &directive.selector)?;
        if covered.contains(&subject) {
            return Err(merge_bad_request(format!(
                "{} is also covered by --file in this request; choose one resolution for that file",
                directive.selector
            )));
        }
        refuse_authored_overlap(authority, &next, &subject)?;
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

type MergeInputs = [kin_model::graph::ResolvedGraphState; 3];
type SettledEntries = Vec<(MergeConflictSubject, MergeEntryResolution)>;

fn merge_inputs(
    authority: &ActiveLocalRepositoryAuthority,
    record: &MergeTransactionRecord,
) -> Result<(kin_db::GraphSnapshot, MergeInputs)> {
    let lease = authority.manager.read_authority();
    let mut snapshot = lease.snapshot().clone();
    snapshot.repository_authority = None;
    drop(lease);
    let graph = kin_db::InMemoryGraph::from_snapshot(snapshot.clone())?;
    let inputs = [
        graph.resolve_graph_at(&record.binding.ours_change)?,
        graph.resolve_graph_at(&record.binding.theirs_change)?,
        graph.resolve_graph_at(&record.binding.base_change)?,
    ];
    snapshot.entities = inputs[0].entities.clone();
    snapshot.relations = inputs[0].relations.clone();
    snapshot.entity_revisions = inputs[0].entity_revisions.clone();
    snapshot.resolved_tree = inputs[0].tree.clone();
    snapshot.external_references = inputs[0].external_references.clone();
    snapshot.outgoing.clear();
    snapshot.incoming.clear();
    Ok((snapshot, inputs))
}

fn file_coverage(
    record: &MergeTransactionRecord,
    inputs: &MergeInputs,
    artifact: kin_model::ArtifactId,
) -> BTreeSet<MergeConflictSubject> {
    let paths: BTreeSet<String> = inputs
        .iter()
        .filter_map(|input| input.tree.get(&artifact))
        .map(|entry| entry.path.to_string())
        .collect();
    let entities: BTreeSet<kin_model::EntityId> = inputs
        .iter()
        .flat_map(|input| input.entities.values())
        .filter(|entity| entity_path(entity).is_some_and(|path| paths.contains(path)))
        .map(|entity| entity.id)
        .collect();
    record
        .entries
        .iter()
        .filter(|entry| match entry.subject {
            MergeConflictSubject::Artifact { artifact: id } => id == artifact,
            MergeConflictSubject::Entity { entity } => entities.contains(&entity),
            MergeConflictSubject::Relation { relation } => inputs.iter().any(|input| {
                input
                    .relations
                    .get(&relation)
                    .is_some_and(|value| match value.src {
                        kin_model::GraphNodeId::Entity(id) => entities.contains(&id),
                        kin_model::GraphNodeId::Artifact(id) => id == artifact,
                        _ => false,
                    })
            }),
            MergeConflictSubject::Path { .. } => false,
        })
        .map(|entry| entry.subject.clone())
        .collect()
}

fn entity_path(entity: &kin_model::Entity) -> Option<&str> {
    entity
        .span
        .as_ref()
        .map(|span| span.file.0.as_str())
        .or_else(|| entity.file_origin.as_ref().map(|file| file.0.as_str()))
}

fn authored_artifacts(
    record: &MergeTransactionRecord,
) -> Vec<(kin_model::ArtifactId, kin_model::LocatedEntry)> {
    record
        .entries
        .iter()
        .filter_map(|entry| match (&entry.subject, &entry.resolution) {
            (
                MergeConflictSubject::Artifact { artifact },
                MergeEntryResolution::Payload {
                    payload: MergeResolutionPayload::Artifact(located),
                    ..
                },
            ) => Some((*artifact, located.clone())),
            _ => None,
        })
        .collect()
}

fn refuse_authored_overlap(
    authority: &ActiveLocalRepositoryAuthority,
    record: &MergeTransactionRecord,
    subject: &MergeConflictSubject,
) -> Result<()> {
    let authored = authored_artifacts(record);
    if authored.is_empty() {
        return Ok(());
    }
    let (_, inputs) = merge_inputs(authority, record)?;
    for (artifact, located) in authored {
        let authored_operation =
            record
                .entries
                .iter()
                .find_map(|entry| match (&entry.subject, &entry.resolution) {
                    (
                        MergeConflictSubject::Artifact { artifact: id },
                        MergeEntryResolution::Payload { provenance, .. },
                    ) if *id == artifact => Some(provenance.operation_id),
                    _ => None,
                });
        let removed_by_body = record.entries.iter().any(|entry| {
            &entry.subject == subject && matches!(&entry.resolution,
                MergeEntryResolution::Payload { payload: MergeResolutionPayload::Removed, provenance }
                    if Some(provenance.operation_id) == authored_operation)
        });
        if file_coverage(record, &inputs, artifact).contains(subject) || removed_by_body {
            return Err(merge_conflict(format!(
                "{} is covered by the authored body for {}; use --file again to replace that whole-file decision",
                render_subject_identity(subject), located.path
            )));
        }
    }
    Ok(())
}

fn settle_authored_files(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    record: &MergeTransactionRecord,
    directives: &[ResolveDirective],
    provenance: &MergeResolutionProvenance,
) -> Result<(SettledEntries, BTreeSet<MergeConflictSubject>)> {
    let total = directives
        .iter()
        .try_fold(0usize, |total, directive| match &directive.choice {
            ResolveChoice::File { body } => total.checked_add(body.len()),
            _ => Some(total),
        })
        .ok_or_else(|| merge_bad_request("custom resolution input size overflow"))?;
    if total > kin_cli::commands::resolve::MAX_RESOLVE_FILE_BYTES {
        return Err(merge_bad_request(format!(
            "custom resolution input exceeds {} bytes; settle files in separate requests",
            kin_cli::commands::resolve::MAX_RESOLVE_FILE_BYTES
        )));
    }
    if !directives
        .iter()
        .any(|directive| matches!(directive.choice, ResolveChoice::File { .. }))
    {
        return Ok((Vec::new(), BTreeSet::new()));
    }
    let (mut snapshot, inputs) = merge_inputs(authority, record)?;
    let mut files = BTreeMap::new();
    let mut covered = BTreeSet::new();
    for directive in directives {
        let ResolveChoice::File { body } = &directive.choice else {
            continue;
        };
        let matches: Vec<_> = record
            .entries
            .iter()
            .filter(|entry| {
                matches!(entry.subject, MergeConflictSubject::Artifact { .. })
                    && entry_matches(entry, &directive.selector)
            })
            .collect();
        let [entry] = matches.as_slice() else {
            return Err(merge_bad_request(format!(
                "--file {} must name exactly one recorded artifact conflict",
                directive.selector
            )));
        };
        let MergeConflictSubject::Artifact { artifact } = entry.subject else {
            unreachable!()
        };
        if files.contains_key(&artifact) {
            return Err(merge_bad_request(format!(
                "{} has more than one --file body",
                directive.selector
            )));
        }
        let original = inputs
            .iter()
            .find_map(|input| input.tree.get(&artifact))
            .ok_or_else(|| {
                merge_conflict("the conflicted artifact is absent from merge history")
            })?;
        let kin_model::TreeEntry::Blob { executable, .. } = original.entry else {
            return Err(merge_bad_request(format!(
                "--file {} requires a regular file artifact",
                directive.selector
            )));
        };
        let hash = kin_blobs::digest(body);
        let located = kin_model::LocatedEntry::new(
            original.path.clone(),
            kin_model::TreeEntry::blob(hash, executable),
        );
        covered.extend(file_coverage(record, &inputs, artifact));
        files.insert(artifact, (located, body.clone()));
    }
    for directive in directives {
        if !matches!(directive.choice, ResolveChoice::File { .. }) {
            let subject = select_subject(record, &directive.selector)?;
            if covered.contains(&subject) {
                return Err(merge_bad_request(format!(
                    "{} is also covered by --file in this request; choose one resolution for that file",
                    directive.selector
                )));
            }
        }
    }
    // A file deleted on the target side still has historical identities to
    // match. Bring those identities into the detached planning view only.
    for artifact in files.keys() {
        if snapshot.resolved_tree.get(artifact).is_none() {
            let input = inputs
                .iter()
                .find(|input| input.tree.get(artifact).is_some())
                .unwrap();
            let original = input.tree.get(artifact).unwrap();
            let mut artifacts: Vec<_> = snapshot.resolved_tree.artifacts().cloned().collect();
            artifacts.push(original.clone());
            snapshot.resolved_tree = kin_model::ResolvedTree::from_artifacts(artifacts)?;
            for entity in input
                .entities
                .values()
                .filter(|entity| entity_path(entity) == Some(original.path.to_string().as_str()))
            {
                snapshot.entities.insert(entity.id, entity.clone());
            }
        }
    }
    seed_authored_identities(&mut snapshot, &inputs, record, &files);
    let parsed = reparse_authored_files(state, snapshot, &files)?;
    let paths: BTreeSet<_> = files
        .values()
        .map(|(located, _)| located.path.to_string())
        .collect();
    let removed_entities: BTreeSet<_> = inputs
        .iter()
        .flat_map(|input| input.entities.values())
        .filter(|entity| {
            entity_path(entity).is_some_and(|path| paths.contains(path))
                && !parsed.entities.contains_key(&entity.id)
        })
        .map(|entity| entity.id)
        .collect();
    for entry in &record.entries {
        if let MergeConflictSubject::Relation { relation } = entry.subject {
            if inputs.iter().any(|input| {
                input.relations.get(&relation).is_some_and(|value| {
                    [value.src, value.dst].iter().any(|node| {
                        node.as_entity()
                            .is_some_and(|id| removed_entities.contains(&id))
                    })
                })
            }) {
                covered.insert(entry.subject.clone());
            }
        }
    }
    for directive in directives {
        if !matches!(directive.choice, ResolveChoice::File { .. }) {
            let subject = select_subject(record, &directive.selector)?;
            if covered.contains(&subject) {
                return Err(merge_bad_request(format!(
                    "{} is also covered by --file in this request; its endpoint is removed by that body",
                    directive.selector
                )));
            }
        }
    }
    let mut resolutions = Vec::new();
    for subject in &covered {
        let payload = match subject {
            MergeConflictSubject::Artifact { artifact } => {
                MergeResolutionPayload::Artifact(files[artifact].0.clone())
            }
            MergeConflictSubject::Entity { entity } => parsed
                .entities
                .get(entity)
                .map(|entity| MergeResolutionPayload::Entity(Box::new(entity.clone())))
                .unwrap_or(MergeResolutionPayload::Removed),
            MergeConflictSubject::Relation { relation } => parsed
                .relations
                .get(relation)
                .map(|relation| MergeResolutionPayload::Relation(Box::new(relation.clone())))
                .unwrap_or(MergeResolutionPayload::Removed),
            MergeConflictSubject::Path { .. } => unreachable!(),
        };
        resolutions.push((
            subject.clone(),
            MergeEntryResolution::Payload {
                payload,
                provenance: provenance.clone(),
            },
        ));
    }
    // Blobs become immutable input before the single merge-record CAS can
    // reference them. A rejected record update can leave only unreferenced CAS.
    for (located, body) in files.values() {
        let kin_model::TreeEntry::Blob { hash: content, .. } = located.entry else {
            unreachable!()
        };
        authority.manager.save_source_blob(content, body)?;
    }
    Ok((resolutions, covered))
}

/// Reconstruct the complete graph-derived meaning of explicit file input.
/// This is an ingestion boundary over immutable bytes, with no workspace read.
fn reparse_authored_files(
    state: &DaemonState,
    mut snapshot: kin_db::GraphSnapshot,
    files: &BTreeMap<kin_model::ArtifactId, (kin_model::LocatedEntry, Vec<u8>)>,
) -> Result<kin_db::GraphSnapshot> {
    snapshot.repository_authority = None;
    snapshot.outgoing.clear();
    snapshot.incoming.clear();
    let external_references = snapshot.external_references.clone();
    let prospective = kin_db::InMemoryGraph::from_snapshot(snapshot)?;
    let pipeline = kin_index::IndexPipeline::new();
    let mut reconciler = kin_reconcile::Reconciler::new(std::path::PathBuf::new());
    reconciler.seed_cross_file_linker_from_graph(&prospective);
    let mut ordered: Vec<_> = files.iter().collect();
    ordered.sort_by(|left, right| left.1 .0.path.cmp(&right.1 .0.path));
    for (artifact, (located, body)) in ordered {
        let file = kin_model::FilePathId::new(located.path.to_string());
        let digest = state.blobs.write(body)?;
        let kin_model::TreeEntry::Blob { hash: content, .. } = located.entry else {
            return Err(merge_bad_request(
                "an authored merge body must be a regular file",
            ));
        };
        if digest.0 != *content.as_bytes() {
            return Err(merge_conflict(format!(
                "authored body digest differs for {}",
                located.path
            )));
        }
        let old = prospective.resolved_tree().get(artifact).cloned();
        let delta = match old {
            Some(old) if old.located_entry() == *located => None,
            Some(old) => Some(kin_model::TreeDelta::Updated {
                artifact_id: *artifact,
                old: old.located_entry(),
                new: located.clone(),
            }),
            None => Some(kin_model::TreeDelta::Added {
                artifact_id: *artifact,
                new: located.clone(),
            }),
        };
        if let Some(delta) = delta {
            prospective.apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![delta],
                ..TransactionDelta::default()
            })?;
        }
        match pipeline
            .index_any_content(&file, body, digest)
            .with_context(|| format!("parse authored merge body for {file}"))?
        {
            kin_index::IndexedAny::EntitySource(indexed) => {
                if !matches!(indexed.parse_state, kin_model::ParseState::Valid) {
                    return Err(merge_bad_request(format!("the authored body for {file} has syntax errors; correct it before settling")));
                }
                let result = reconciler
                    .reconcile_indexed_content(&indexed, state.blobs.as_ref(), &prospective)
                    .with_context(|| format!("derive complete merge semantics for {file}"))?;
                prospective.apply_transaction_delta(&result.delta)?;
            }
            _ => {
                let before = prospective.to_snapshot();
                let retired: BTreeSet<_> = before
                    .entities
                    .values()
                    .filter(|entity| entity_path(entity) == Some(file.0.as_str()))
                    .map(|entity| entity.id)
                    .collect();
                let delta = TransactionDelta {
                    entity_deltas: retired
                        .iter()
                        .map(|id| kin_model::EntityDelta::Removed {
                            old: before.entities[id].clone(),
                        })
                        .collect(),
                    relation_deltas: before
                        .relations
                        .values()
                        .filter(|relation| {
                            [relation.src, relation.dst].iter().any(|node| {
                                node.as_entity().is_some_and(|id| retired.contains(&id))
                            }) || (relation.src == kin_model::GraphNodeId::Artifact(*artifact)
                                && matches!(
                                    relation.origin,
                                    kin_model::RelationOrigin::Parsed
                                        | kin_model::RelationOrigin::Inferred
                                ))
                        })
                        .map(|relation| kin_model::RelationDelta::Removed {
                            old: relation.clone(),
                        })
                        .collect(),
                    ..TransactionDelta::default()
                };
                prospective.apply_transaction_delta(&delta)?;
            }
        }
    }
    let parsed = prospective.to_snapshot();
    if parsed.external_references != external_references {
        return Err(merge_conflict(
            "authored merge input changes external-reference records; this merge cannot publish those records safely",
        ));
    }
    Ok(parsed)
}

fn seed_authored_identities(
    snapshot: &mut kin_db::GraphSnapshot,
    inputs: &MergeInputs,
    record: &MergeTransactionRecord,
    files: &BTreeMap<kin_model::ArtifactId, (kin_model::LocatedEntry, Vec<u8>)>,
) {
    // Original first-parent identities are stable anchors even when a
    // conflict payload removes an old declaration before this full reparse.
    let paths: BTreeSet<_> = files
        .values()
        .map(|(located, _)| located.path.to_string())
        .collect();
    snapshot
        .entities
        .retain(|_, entity| !entity_path(entity).is_some_and(|path| paths.contains(path)));
    for input in inputs {
        for entity in input
            .entities
            .values()
            .filter(|entity| entity_path(entity).is_some_and(|path| paths.contains(path)))
        {
            snapshot
                .entities
                .entry(entity.id)
                .or_insert_with(|| entity.clone());
        }
    }
    // Derived relation payloads can name declarations absent from the original
    // conflict set. Recreate those relations only after their declarations have
    // been parsed, using recorded input identities as matching anchors.
    let covered: BTreeSet<_> = files
        .keys()
        .flat_map(|artifact| file_coverage(record, inputs, *artifact))
        .collect();
    for subject in &covered {
        let MergeConflictSubject::Relation { relation } = subject else {
            continue;
        };
        snapshot.relations.remove(relation);
        if let Some(original) = inputs
            .iter()
            .find_map(|input| input.relations.get(relation))
        {
            let valid = [original.src, original.dst].iter().all(|node| match node {
                kin_model::GraphNodeId::Entity(entity) => snapshot.entities.contains_key(entity),
                kin_model::GraphNodeId::Artifact(artifact) => {
                    snapshot.resolved_tree.get(artifact).is_some()
                }
                _ => true,
            });
            if valid {
                snapshot.relations.insert(*relation, original.clone());
            }
        }
    }
}

/// Load only durable authored bodies, then rederive their complete semantics
/// over the composed graph. The external input pathname is never consulted.
pub(crate) fn replay_authored_files(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    record: &MergeTransactionRecord,
    mut snapshot: kin_db::GraphSnapshot,
) -> Result<kin_db::GraphSnapshot> {
    let mut files = BTreeMap::new();
    for (artifact, located) in authored_artifacts(record) {
        let kin_model::TreeEntry::Blob { hash: content, .. } = located.entry else {
            return Err(merge_conflict(
                "an authored file record names a non-file artifact",
            ));
        };
        let body = authority
            .manager
            .load_source_blob(content)?
            .ok_or_else(|| {
                merge_conflict(format!(
                    "authored body {content} is missing from repository CAS"
                ))
            })?;
        files.insert(artifact, (located, body));
    }
    if files.is_empty() {
        return Ok(snapshot);
    }
    let (_, inputs) = merge_inputs(authority, record)?;
    seed_authored_identities(&mut snapshot, &inputs, record, &files);
    reparse_authored_files(state, snapshot, &files)
}

/// Abandon the merge, whatever the workspace has done since it opened.
///
/// This used to refuse unless the workspace still equalled the restore point,
/// on the reasoning that abandoning could not prove the workspace it restores.
/// It restores no workspace. The transaction below is documented as moving only
/// the merge record, and it is: `workspace_mutation: None`, no ref mutations and
/// no changes, and `record_execution` hands the finalizer the same tree for
/// `previous_tree` and `desired_tree` with an empty delta, so nothing is
/// projected either. The gate was keeping one sentence true, not guarding an
/// operation, and it refused the one command whose whole job is getting out.
///
/// Measured on the rc063a stranger's shape: hand-edit a conflicted file and
/// `resolve --continue`, `resolve --abort` and `merge` all answer 409 while
/// `status` and `conflicts` keep advertising the merge. `stash push --yes` and
/// `stash pop` both succeed and leave the merge exactly as parked, so they are
/// not a way out either. The only recovery was `kin checkout --change`.
///
/// So it abandons, and the line it prints says what is true rather than what
/// used to be. What it must never do is claim to have put anything back.
fn abort(
    authority: &ActiveLocalRepositoryAuthority,
    request: &ResolveRequest,
    roots: kin_model::RootBundle,
    workspace: WorkspaceState,
    record: MergeTransactionRecord,
) -> Result<ResolveExecution> {
    let workspace_moved = restore_point(&workspace) != record.restore;
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
    let lines = vec![if workspace_moved {
        format!(
            "Abandoned the merge of {} into {}; workspace {} has moved since the merge opened \
             and is left exactly as it is, because abandoning a merge restores nothing \
             (authority generation {})",
            record.binding.source_ref,
            record.binding.target_ref,
            workspace.workspace_id,
            receipt.generation
        )
    } else {
        format!(
            "Abandoned the merge of {} into {}; workspace {} is unchanged at the recorded \
             restore point (authority generation {})",
            record.binding.source_ref,
            record.binding.target_ref,
            workspace.workspace_id,
            receipt.generation
        )
    }];
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
        collaboration_delta: None,
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
        published_merged_graph: false,
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
    let Some(label) = entry.label.as_deref() else {
        return false;
    };
    if label == needle {
        return true;
    }
    // The name on its own, which is what `kin conflicts` prints beside the
    // identity and therefore what a caller reaches for. An entity's label is
    // composed as `<name> in <file>` wherever it carries a span, so the name is
    // the segment before the first ` in `, and a label with no span is already
    // the bare name and matched above.
    //
    // Widening the match cannot settle the wrong identity: `select_subject`
    // refuses anything matching more than one entry and names every candidate,
    // so a name shared by two files asks the caller to pick rather than
    // guessing for them.
    label
        .split_once(" in ")
        .is_some_and(|(name, _file)| name == needle)
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
        ResolveChoice::File { .. } => {
            return Err(merge_bad_request(
                "a file body must settle its artifact and derived conflicts together",
            ));
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
