// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The one writer for review state.
//!
//! Every review mutation, whether it arrives through `POST /review` or one of the
//! MCP review tools, is planned against the live graph and committed here as one
//! collaboration-only repository transaction before the caller is answered. Only
//! once authority holds the records are they applied to the live graph, so the
//! graph never shows a review authority does not hold, and a daemon that reopens
//! the store serves exactly the reviews it answered with: the workspace graph a
//! daemon opens carries the collaboration maps authority holds.
//!
//! The writer takes `persist_lock` itself. Its caller holds the coordination gate
//! and a graph-authority mutation guard, the pair every authority writer in this
//! daemon holds, because the MCP dispatch already takes both for each tool that
//! mutates the graph and neither lock is reentrant.

use std::collections::HashMap;

use kin_model::{
    AuthorId, CollaborationDelta, OperationId, RepositoryCommitReceipt, RepositoryTransaction,
    SessionId, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
use kin_review::write::PlannedReviewEvent;

use crate::local_repository_authority::ActiveLocalRepositoryAuthority;
use crate::state::{DaemonEvent, DaemonState};

/// Why a review write did not complete.
#[derive(Debug)]
pub(crate) enum ReviewWriteRefusal<E> {
    /// The planner refused the request. Nothing was written.
    Plan(E),
    /// A hosted daemon's review state arrives through the transfer seam.
    Hosted,
    /// The daemon could not bind or open its repository authority. Nothing was
    /// written.
    Authority(String),
    /// The transaction was not committed. Nothing was written. `conflict` is set
    /// when authority kept moving under the write.
    Commit { conflict: bool, detail: String },
    /// The transaction committed and the live graph could not follow it.
    Diverged { generation: u64, detail: String },
}

impl<E: std::fmt::Display> std::fmt::Display for ReviewWriteRefusal<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plan(error) => write!(f, "{error}"),
            Self::Hosted => f.write_str(
                "a hosted daemon takes review state through the repository transfer seam, not \
                 through review writes",
            ),
            Self::Authority(detail) => write!(f, "review state is repository authority: {detail}"),
            Self::Commit { detail, .. } => {
                write!(
                    f,
                    "review write was not committed to repository authority: {detail}"
                )
            }
            Self::Diverged { generation, detail } => write!(
                f,
                "review write committed to repository authority at generation {generation}, but \
                 the daemon's live graph could not follow it: {detail}; restart the daemon to \
                 serve review state from authority again"
            ),
        }
    }
}

/// Plan, commit and apply one review event, and return the planner's answer once
/// the records are durable. An event that changes nothing commits nothing.
///
/// The caller holds `coordination_gate` and a graph-authority mutation guard for
/// the whole call. `plan` runs against the live graph under those locks, so the
/// records it reads are the ones authority holds.
pub(crate) fn commit_review_event<A, E>(
    state: &DaemonState,
    session: Option<&SessionId>,
    plan: impl FnOnce(&kin_db::InMemoryGraph) -> Result<PlannedReviewEvent<A>, E>,
) -> Result<A, ReviewWriteRefusal<E>> {
    if state.storage_backend.is_some() {
        return Err(ReviewWriteRefusal::Hosted);
    }
    let _persistence = state
        .persist_lock
        .lock()
        .map_err(|_| ReviewWriteRefusal::Authority("daemon persistence lock poisoned".into()))?;
    let authority = ActiveLocalRepositoryAuthority::open_bound(state)
        .map_err(|refusal| ReviewWriteRefusal::Authority(format!("{:#}", refusal.into_error())))?;
    let mut planned = plan(state.graph.as_ref()).map_err(ReviewWriteRefusal::Plan)?;
    if planned.write.is_empty() {
        return Ok(planned.answer);
    }

    if planned.records_audit_event() {
        record_provenance(state, &authority, session, &mut planned)?;
    }
    let delta = planned
        .write
        .to_delta()
        .map_err(|error| ReviewWriteRefusal::Commit {
            conflict: false,
            detail: error.to_string(),
        })?;
    let reason = match session {
        Some(session) => format!(
            "{} {} (session {session})",
            planned.action, planned.review_id
        ),
        None => format!("{} {}", planned.action, planned.review_id),
    };
    let receipt = commit_collaboration(
        &authority,
        delta,
        &reason,
        &AuthorId::new(planned.actor_label.clone()),
    )?;

    // Durable from here. The two steps below make this process agree with what
    // authority now holds, and a failure in either is reported as exactly that.
    state
        .record_repository_authority_commit(receipt.generation)
        .map_err(|error| ReviewWriteRefusal::Diverged {
            generation: receipt.generation,
            detail: error.to_string(),
        })?;
    planned
        .write
        .apply_to(state.graph.as_ref())
        .map_err(|error| ReviewWriteRefusal::Diverged {
            generation: receipt.generation,
            detail: error.to_string(),
        })?;

    state.bump_version();
    state.mark_dirty();
    state.emit_event(DaemonEvent::GraphRootChanged {
        old_root_hash: None,
        new_root_hash: "review-state".to_string(),
    });
    state.emit_event(DaemonEvent::RepositoryAuthorityChanged {
        repository_id: receipt.repository_id.to_string(),
        operation_id: receipt.operation_id,
        previous_generation: receipt.roots_before.generation,
        new_generation: receipt.generation,
    });
    Ok(planned.answer)
}

/// Commit one MCP review write tool through [`commit_review_event`].
///
/// The dispatch that calls this already holds the coordination gate and a
/// graph-authority mutation guard, as it does for every tool that mutates the
/// graph.
pub(crate) fn commit_mcp_review_tool(
    state: &DaemonState,
    session: Option<&SessionId>,
    tool: &str,
    arguments: &HashMap<String, serde_json::Value>,
) -> Result<kin_mcp::ToolCallResult, kin_mcp::McpError> {
    let outcome = commit_review_event(state, session, |graph| {
        kin_mcp::handlers::review::plan_review_mutation(tool, arguments, graph)
            .unwrap_or_else(|| Err(kin_mcp::McpError::ToolNotFound(tool.to_string())))
    });
    match outcome {
        Ok(answer) => Ok(answer),
        Err(ReviewWriteRefusal::Plan(error)) => Err(error),
        Err(refusal) => Err(kin_mcp::McpError::Other(refusal.to_string())),
    }
}

/// Add the audit event for a create or a decision, carrying what only the
/// writer knows: the changes the review's refs resolve to under the lease it
/// commits against, the session that asked, and the authority generation.
fn record_provenance<A, E>(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    session: Option<&SessionId>,
    planned: &mut PlannedReviewEvent<A>,
) -> Result<(), ReviewWriteRefusal<E>> {
    let mut details = planned.details.clone();
    {
        let lease = authority.manager.read_authority();
        if let Some((base, head)) = &planned.refs {
            details.push_str("; ");
            details.push_str(&kin_cli::commands::review::review_ref_provenance(
                &lease,
                &authority.workspace_id,
                state.graph.as_ref(),
                base,
                head,
            ));
        }
        details.push_str(&format!(
            "; authority_generation={}",
            lease.roots().generation
        ));
    }
    if let Some(session) = session {
        details.push_str(&format!("; session={session}"));
    }
    let (actor, event) = kin_cli::provenance::plan_audit_event(
        state.graph.as_ref(),
        &planned.actor_label,
        planned.action,
        None,
        Some(details),
    )
    .map_err(|error| ReviewWriteRefusal::Commit {
        conflict: false,
        detail: format!("{error:#}"),
    })?;
    planned.write.actors.extend(actor);
    planned.write.audit_events.push(event);
    Ok(())
}

/// Commit `delta` as a transaction whose only mutation it is.
///
/// A roots conflict means another process moved authority between the read and
/// the compare-and-swap. The records do not depend on the roots they commit
/// against, so one fresh attempt is safe; a second conflict is reported.
fn commit_collaboration<E>(
    authority: &ActiveLocalRepositoryAuthority,
    delta: CollaborationDelta,
    reason: &str,
    actor: &AuthorId,
) -> Result<RepositoryCommitReceipt, ReviewWriteRefusal<E>> {
    let mut attempts = 0;
    loop {
        attempts += 1;
        let roots = authority.manager.read_authority().roots().clone();
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id: authority.repository_id.clone(),
            expected_generation: roots.generation,
            expected_roots: roots,
            actor: actor.clone(),
            reason: reason.to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: Vec::new(),
            aliases: Vec::new(),
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
            collaboration_delta: Some(delta.clone()),
        };
        match authority.manager.commit_repository_transaction(transaction) {
            Ok(receipt) => return Ok(receipt),
            Err(kin_db::KinDbError::Model(kin_model::ModelError::Conflict(_))) if attempts == 1 => {
                continue
            }
            Err(error) => {
                let conflict = matches!(
                    error,
                    kin_db::KinDbError::Model(kin_model::ModelError::Conflict(_))
                );
                return Err(ReviewWriteRefusal::Commit {
                    conflict,
                    detail: error.to_string(),
                });
            }
        }
    }
}
