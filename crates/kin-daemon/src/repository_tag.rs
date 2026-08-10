// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon-owned repository-v6 tag authority.
//!
//! Publishing a tag is one repository transaction: a `refs/tags/`
//! compare-and-swap that must not exist yet, targeting the exact change the
//! release policy was evaluated over. Policy and publication read the same
//! authority lease, and the transaction carries that lease's roots as its
//! expected roots, so a tag can never name a source that was never checked.

use anyhow::{bail, Context, Result};
use axum::http::StatusCode;
use kin_cli::commands::tag::{
    encode_coverage, ReleaseSnapshot, TagProofDecision, TagReport, TagRequest, TagResponse,
    BASELINE_COVERAGE_RATIO, RELEASE_SNAPSHOT_SCHEMA, TAG_SCHEMA,
};
use kin_db::{
    ChangeStore, LocalFileBackend, LocalRepositoryAuthorityFreeze, RepositoryAuthorityManager,
};
use kin_model::{
    RefExpectation, RefMutation, RefName, RefTarget, RefUpdatePolicy, RepositoryCommitOutcome,
    RepositoryCommitReceipt, RepositoryTransaction, ResolvedTree, RootBundle, SemanticChangeId,
    TransactionDelta, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};

use crate::local_repository_authority::{
    ActiveLocalRepositoryAuthority, RepositoryAuthorityBindRefusal,
};
use crate::state::{DaemonEvent, DaemonState};

const TAG_REASON: &str = "publish exact repository-v6 tag";

struct TagExecution {
    response: TagResponse,
    receipt: RepositoryCommitReceipt,
    authority_freeze: LocalRepositoryAuthorityFreeze,
    tree: ResolvedTree,
}

#[derive(Debug)]
struct TagConflict(String);

impl std::fmt::Display for TagConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for TagConflict {}

#[derive(Debug)]
struct TagBadRequest(String);

impl std::fmt::Display for TagBadRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for TagBadRequest {}

/// A declared release policy that the exact source does not satisfy. This is a
/// refusal, never a warning: nothing is published.
#[derive(Debug)]
struct TagPolicyRefusal(String);

impl std::fmt::Display for TagPolicyRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for TagPolicyRefusal {}

fn tag_conflict(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(TagConflict(message.into()))
}

fn tag_bad_request(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(TagBadRequest(message.into()))
}

pub(crate) fn execute(
    state: &DaemonState,
    request: &TagRequest,
) -> std::result::Result<TagResponse, (StatusCode, String)> {
    let graph_mutation = state.begin_graph_authority_mutation();
    let persistence = state.persist_lock.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "daemon persistence lock poisoned".to_string(),
        )
    })?;
    let authority = ActiveLocalRepositoryAuthority::open_bound(state).map_err(tag_bind_refusal)?;
    let execution = publish(&authority, request).map_err(classify_tag_error)?;

    let finalization = state
        .finalize_local_repository_commit(
            &execution.receipt,
            &execution.authority_freeze,
            &TransactionDelta::default(),
            &execution.tree,
            &execution.tree,
        )
        .map_err(repository_finalization_error)?;
    if finalization.generation_advanced {
        state.mark_dirty();
        state.emit_event(DaemonEvent::RepositoryAuthorityChanged {
            repository_id: execution.receipt.repository_id.to_string(),
            operation_id: execution.receipt.operation_id,
            previous_generation: execution.receipt.roots_before.generation,
            new_generation: execution.receipt.generation,
        });
    }

    drop(persistence);
    drop(graph_mutation);
    Ok(execution.response)
}

fn publish(
    authority: &ActiveLocalRepositoryAuthority,
    request: &TagRequest,
) -> Result<TagExecution> {
    require_tag_ref(&request.name)?;
    let lease = authority.manager.read_authority();
    if let Some(receipt) = lease
        .metadata()
        .receipts
        .iter()
        .find(|receipt| receipt.operation_id == request.operation_id)
        .cloned()
    {
        let roots = lease.roots().clone();
        drop(lease);
        return replay(authority, &roots, receipt, request);
    }
    let roots = lease.roots().clone();
    let metadata = lease.metadata();
    if metadata
        .ref_state
        .refs
        .iter()
        .any(|repository_ref| repository_ref.name == request.name)
    {
        return Err(tag_conflict(format!(
            "tag {} already exists; repository-v6 tags are immutable refs and are never moved in \
             place",
            request.name
        )));
    }
    let workspace = local_workspace(authority, metadata)?.clone();
    let target = workspace.base_target.clone().ok_or_else(|| {
        tag_conflict(format!(
            "cannot tag unborn workspace {}; commit a change first",
            workspace.workspace_id
        ))
    })?;
    if matches!(target, RefTarget::Symbolic { .. }) {
        bail!(
            "workspace {} base target is symbolic instead of resolved",
            workspace.workspace_id
        );
    }
    let change_id = lease
        .resolve_target_change_id(&target)
        .context("resolve the exact semantic change this tag names")?;

    // Policy is decided over the same lease the compare-and-swap will carry, so
    // the entities counted here and the source published below are the same
    // immutable state.
    let mut snapshot = lease.snapshot().clone();
    snapshot.repository_authority = None;
    let tree = workspace.tree.clone();
    drop(lease);

    let history =
        kin_db::InMemoryGraph::from_snapshot(snapshot).context("open immutable release source")?;
    let decision = decide(&history, change_id, request)?;

    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: request.operation_id,
        repository_id: authority.repository_id.clone(),
        expected_generation: roots.generation,
        expected_roots: roots,
        actor: request.actor.clone(),
        reason: TAG_REASON.to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: vec![RefMutation {
            name: request.name.clone(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(target.clone()),
            policy: RefUpdatePolicy::FastForwardOnly,
        }],
        default_ref_mutation: None,
        workspace_mutation: None,
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
    };
    let (receipt, authority_freeze) = commit_and_freeze_exact(&authority.manager, transaction)
        .with_context(|| format!("publish repository-v6 tag {}", request.name))?;

    let snapshot = request
        .snapshot
        .then(|| {
            bind_snapshot(
                &history,
                &authority.repository_id,
                change_id,
                &receipt,
                &decision,
            )
        })
        .transpose()?;
    let report = TagReport {
        schema: TAG_SCHEMA.to_string(),
        authority: "repository-v6".to_string(),
        repository_id: authority.repository_id.clone(),
        name: request.name.clone(),
        target,
        change_id,
        authority_generation: receipt.generation,
        proof: decision,
        idempotent: matches!(receipt.outcome, RepositoryCommitOutcome::IdempotentReplay),
        snapshot,
    };
    Ok(TagExecution {
        response: TagResponse {
            lines: kin_cli::commands::tag::render_lines(&report),
            mutated: matches!(receipt.outcome, RepositoryCommitOutcome::Committed),
            report: Some(report),
        },
        receipt,
        authority_freeze,
        tree,
    })
}

/// Bind the release snapshot to the exact roots, source, artifacts, and policy
/// decision this publication committed.
///
/// The tree hash is the identity of the complete artifact set, so a snapshot
/// naming a different artifact anywhere is a different snapshot; the roots pair
/// records exactly which authority transition published it.
fn bind_snapshot(
    history: &kin_db::InMemoryGraph,
    repository_id: &kin_model::RepositoryId,
    change_id: SemanticChangeId,
    receipt: &RepositoryCommitReceipt,
    decision: &TagProofDecision,
) -> Result<ReleaseSnapshot> {
    let source = history
        .resolve_graph_at(&change_id)
        .with_context(|| format!("resolve the released source at {change_id}"))?;
    let tree_hash = kin_model::compute_resolved_tree_hash(&source.tree)
        .context("hash the exact released artifact tree")?;
    let mut blob_artifacts = 0;
    let mut symlink_artifacts = 0;
    let mut gitlink_artifacts = 0;
    for artifact in source.tree.artifacts_by_path() {
        match artifact.entry {
            kin_model::TreeEntry::Blob { .. } => blob_artifacts += 1,
            kin_model::TreeEntry::Symlink { .. } => symlink_artifacts += 1,
            kin_model::TreeEntry::Gitlink { .. } => gitlink_artifacts += 1,
        }
    }
    let artifact_count = source.tree.artifacts().len();
    let [mutation] = receipt.operation.ref_mutations.as_slice() else {
        bail!(
            "the release for {change_id} recorded something other than exactly one ref change, so \
             kin refused to publish the tag; nothing was written, so re-run `kin tag` and report \
             it if it repeats"
        );
    };
    ReleaseSnapshot {
        schema: RELEASE_SNAPSHOT_SCHEMA.to_string(),
        repository_id: repository_id.clone(),
        tag: mutation.name.clone(),
        change_id: change_id.to_string(),
        roots_before: receipt.roots_before.clone(),
        roots_after: receipt.roots_after.clone(),
        tree_hash: hex::encode(tree_hash.as_bytes()),
        artifact_count,
        blob_artifacts,
        symlink_artifacts,
        gitlink_artifacts,
        entity_count: source.entities.len(),
        relation_count: source.relations.len(),
        proof: decision.clone(),
        snapshot_digest: String::new(),
    }
    .seal()
}

/// Evaluate the declared release policy against one immutable source.
///
/// Only policy the caller declared can block, and every declared check that
/// fails blocks: a tag is either published against a source that satisfied the
/// policy, or it is not published at all.
fn decide(
    history: &kin_db::InMemoryGraph,
    change_id: SemanticChangeId,
    request: &TagRequest,
) -> Result<TagProofDecision> {
    let source = history
        .resolve_graph_at(&change_id)
        .with_context(|| format!("resolve the immutable release source at {change_id}"))?;
    let coverage =
        kin_review::source_bound_release_proof_coverage_for_entities(source.entities.values());
    let mut unapproved_changes = Vec::new();
    let mut blockers = Vec::new();

    if request.require_proof && !coverage.missing_proof.is_empty() {
        blockers.push(format!(
            "{} of {} source entities have no source-bound passing test proof; verification runs \
             do not yet carry immutable source authority, so --require-proof cannot be satisfied \
             by any non-empty source",
            coverage.missing_proof.len(),
            coverage.total_entities
        ));
    }
    if request.require_approval {
        let mut unapproved = kin_review::unapproved_changes(history, &change_id, usize::MAX)
            .context("collect unapproved reachable changes")?;
        unapproved.sort_by_key(|change| change.change_id.to_string());
        if !unapproved.is_empty() {
            blockers.push(format!(
                "{} reachable non-root change(s) lack known-human approval: {}",
                unapproved.len(),
                unapproved
                    .iter()
                    .map(|change| format!("{} ({})", change.change_id, change.author))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        unapproved_changes = unapproved
            .into_iter()
            .map(|change| change.change_id)
            .collect();
    }
    if !request.force
        && coverage.total_entities > 0
        && coverage.coverage_ratio < BASELINE_COVERAGE_RATIO
    {
        blockers.push(format!(
            "source-bound proof coverage {:.2}% is below the {:.0}% release baseline; pass --force \
             to record an explicit acknowledgment that this source is tagged without it",
            coverage.coverage_ratio * 100.0,
            BASELINE_COVERAGE_RATIO * 100.0
        ));
    }

    if !blockers.is_empty() {
        return Err(anyhow::Error::new(TagPolicyRefusal(
            kin_cli::commands::tag::render_blocked(&request.name, &change_id, &blockers),
        )));
    }

    Ok(TagProofDecision {
        source_entities: coverage.total_entities,
        entities_with_source_bound_proof: coverage.covered_entities,
        coverage_percent_hundredths: encode_coverage(coverage.coverage_ratio),
        baseline_acknowledged: request.force,
        require_proof: request.require_proof,
        require_approval: request.require_approval,
        unapproved_changes,
        entities_missing_proof: Vec::new(),
    })
}

fn replay(
    authority: &ActiveLocalRepositoryAuthority,
    current_roots: &RootBundle,
    receipt: RepositoryCommitReceipt,
    request: &TagRequest,
) -> Result<TagExecution> {
    receipt
        .validate()
        .context("validate persisted tag receipt")?;
    let [mutation] = receipt.operation.ref_mutations.as_slice() else {
        bail!(
            "tag operation {} did not commit exactly one ref mutation",
            request.operation_id
        );
    };
    if mutation.name != request.name || mutation.new_target.is_none() {
        return Err(tag_conflict(format!(
            "tag operation {} was already committed for a different request",
            request.operation_id
        )));
    }
    if current_roots != &receipt.roots_after {
        return Err(tag_conflict(format!(
            "tag operation {} committed at generation {}, but authority is now at generation {}; \
             reopen against current authority before retrying",
            request.operation_id, receipt.generation, current_roots.generation
        )));
    }
    let lease = authority.manager.read_authority();
    let workspace = local_workspace(authority, lease.metadata())?.clone();
    let change_id = lease
        .resolve_target_change_id(
            mutation
                .new_target
                .as_ref()
                .expect("validated tag replay has a target"),
        )
        .context("resolve the exact semantic change a replayed tag names")?;
    let mut snapshot = lease.snapshot().clone();
    snapshot.repository_authority = None;
    drop(lease);

    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: request.operation_id,
        repository_id: authority.repository_id.clone(),
        expected_generation: receipt.roots_before.generation,
        expected_roots: receipt.roots_before.clone(),
        actor: request.actor.clone(),
        reason: TAG_REASON.to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: vec![mutation.clone()],
        default_ref_mutation: None,
        workspace_mutation: None,
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
    };
    if transaction.transaction_hash()? != receipt.transaction_hash {
        return Err(tag_conflict(format!(
            "tag operation {} was already committed for a different request",
            request.operation_id
        )));
    }
    let history =
        kin_db::InMemoryGraph::from_snapshot(snapshot).context("open immutable release source")?;
    let decision = decide(&history, change_id, request)?;
    let (replayed, authority_freeze) = commit_and_freeze_exact(&authority.manager, transaction)?;
    if replayed.transaction_hash != receipt.transaction_hash
        || replayed.roots_after != receipt.roots_after
        || !matches!(replayed.outcome, RepositoryCommitOutcome::IdempotentReplay)
    {
        bail!(
            "repository authority returned a non-identical replay for tag operation {}",
            request.operation_id
        );
    }
    let snapshot = request
        .snapshot
        .then(|| {
            bind_snapshot(
                &history,
                &authority.repository_id,
                change_id,
                &replayed,
                &decision,
            )
        })
        .transpose()?;
    let report = TagReport {
        schema: TAG_SCHEMA.to_string(),
        authority: "repository-v6".to_string(),
        repository_id: authority.repository_id.clone(),
        name: request.name.clone(),
        target: mutation
            .new_target
            .clone()
            .expect("validated tag replay has a target"),
        change_id,
        authority_generation: replayed.generation,
        proof: decision,
        idempotent: true,
        snapshot,
    };
    Ok(TagExecution {
        response: TagResponse {
            lines: kin_cli::commands::tag::render_lines(&report),
            mutated: false,
            report: Some(report),
        },
        receipt: replayed,
        authority_freeze,
        tree: workspace.tree,
    })
}

fn commit_and_freeze_exact(
    manager: &RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
) -> Result<(RepositoryCommitReceipt, LocalRepositoryAuthorityFreeze)> {
    manager
        .commit_repository_transaction_and_freeze(transaction)
        .map_err(anyhow::Error::new)
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

fn require_tag_ref(name: &RefName) -> Result<()> {
    if !name.is_tag() {
        return Err(tag_bad_request(format!(
            "tag command requires a ref below refs/tags/, found {name}"
        )));
    }
    Ok(())
}

fn classify_tag_error(error: anyhow::Error) -> (StatusCode, String) {
    if error.downcast_ref::<TagBadRequest>().is_some() {
        return (StatusCode::BAD_REQUEST, crate::error::cause_first(&error));
    }
    if error.downcast_ref::<TagPolicyRefusal>().is_some() {
        return (
            StatusCode::PRECONDITION_FAILED,
            crate::error::cause_first(&error),
        );
    }
    if error.downcast_ref::<TagConflict>().is_some() {
        return (StatusCode::CONFLICT, crate::error::cause_first(&error));
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
    if let Some(database) = error.downcast_ref::<kin_db::KinDbError>() {
        if matches!(database, kin_db::KinDbError::Model(_)) {
            return (StatusCode::CONFLICT, crate::error::cause_first(&error));
        }
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

fn tag_bind_refusal(refusal: RepositoryAuthorityBindRefusal) -> (StatusCode, String) {
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
