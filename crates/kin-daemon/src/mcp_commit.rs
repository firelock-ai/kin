// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact repository-authority commit path for MCP transactions.
//!
//! This planner never reads source from the working filesystem and never
//! mutates the daemon's live query graph before repository-v6 authority
//! commits. Existing source bodies come from repository CAS, entity bodies are
//! spliced in memory, and final semantics are re-derived from those exact
//! bytes. The repository transaction and exact working-tree projection share
//! the projection WAL in `repository_commit`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use kin_model::graph::ProvenanceStore;
use kin_model::provenance::{Actor, ActorId, ActorKind, AuditEvent, AuditEventId};
use kin_model::work::WorkScope;
use kin_model::{
    Entity, EntityDelta, EntityId, EntityStore, FileLayout, FilePathId, GraphNodeId, Hash256,
    LocatedEntry, OperationId, Relation, RelationDelta, RelationOrigin, RepoPath, SemanticChangeId,
    SourceRegion, TransactionDelta, TreeDelta, TreeEntry,
};
use sha2::{Digest, Sha256};

use crate::local_repository_authority::{
    require_fresh_daemon_workspace, LocalRepositoryAuthorityContext,
};
use crate::repository_commit::{
    commit_native_plan_with_projection, load_native_commit_base, load_native_source_blob,
    plan_native_commit_from_base, recover_native_commit, NativeCommitBase, NativeCommitResult,
};
use crate::state::DaemonState;

struct ExactMcpPlan {
    native: crate::repository_commit::NativeCommitPlan,
    layouts: Vec<FileLayout>,
}

fn authority_context(state: &DaemonState) -> Result<LocalRepositoryAuthorityContext, String> {
    LocalRepositoryAuthorityContext::from_state(state)
        .map_err(|error| format!("open startup-pinned repository authority: {error}"))
}

/// Commit one daemon-owned MCP transaction through exact repository authority.
///
/// The caller holds `DaemonState::coordination_gate` and the graph-authority
/// mutation guard for the complete call.
pub(crate) fn commit_exact_transaction(
    state: &Arc<DaemonState>,
    sessions: &kin_mcp::SessionRegistry,
    arguments: &HashMap<String, serde_json::Value>,
    coordination: Option<&kin_mcp::CoordinationWritePreflight>,
) -> kin_mcp::ToolCallResult {
    match commit_exact_transaction_inner(state, sessions, arguments, coordination) {
        Ok(result) => result,
        Err(error) => kin_mcp::ToolCallResult::error(error),
    }
}

fn commit_exact_transaction_inner(
    state: &Arc<DaemonState>,
    sessions: &kin_mcp::SessionRegistry,
    arguments: &HashMap<String, serde_json::Value>,
    coordination: Option<&kin_mcp::CoordinationWritePreflight>,
) -> Result<kin_mcp::ToolCallResult, String> {
    if state.storage_backend.is_some() {
        return Err(
            "exact MCP repository commits are not yet available for hosted snapshot backends"
                .to_string(),
        );
    }
    let transaction_id = arguments
        .get("transaction_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing required parameter: transaction_id".to_string())?
        .to_string();

    let Some(mut transaction) = sessions.get_transaction(&transaction_id) else {
        // A missing record is not proof the work never happened. A successful
        // commit evicts its own transaction, and a client whose per-attempt
        // HTTP budget expired during a long apply retries straight into that
        // gap: the retry blocks on the coordination gate, the first attempt
        // finishes and evicts, and the retry then reads a registry that no
        // longer holds what it just applied. Answering "not found" there
        // reports failure over a commit whose file, entity, and provenance
        // all landed, which is a double-apply generator, because any correct
        // agent retries a failure. Repository authority still holds the
        // receipt for this caller-stable operation id, so ask it.
        return replay_applied_commit(state, &transaction_id, coordination);
    };

    // Operations handed to the commit call itself stage and publish in one
    // step. Once the transaction is fenced they are read as a restatement of
    // what is already fenced instead: `kin_transaction_commit` documents
    // re-entry as an idempotent resume, and staging onto a fenced transaction
    // would fail on the state check and strand a caller whose only published
    // recovery is to re-send the identical call.
    if let Some(inline) = arguments.get("operations") {
        let operations = kin_mcp::session::parse_staged_operations(inline)?;
        kin_mcp::session::validate_staged_operations(&operations)?;
        if matches!(transaction.state.as_str(), "committing" | "committed") {
            if !kin_mcp::session::staged_operations_match(
                &transaction.staged_operations,
                &operations,
            ) {
                return Err(format!(
                    "Cannot commit transaction {transaction_id}: the inline operations differ from \
                     the operations already fenced for publication, and a fenced payload cannot be \
                     edited. Re-send this commit with no `operations` array at all to resume the \
                     fenced payload as it stands, which is the exit that always works and the one \
                     to use when the fenced set includes operations staged separately. Re-sending \
                     the exact fenced operations also resumes it. Begin a new transaction with \
                     kin_transaction_begin only for a genuinely different change."
                ));
            }
        } else {
            transaction = sessions
                .stage_transaction(&transaction_id, operations)
                .map_err(|error| format!("cannot stage inline transaction operations: {error}"))?;
        }
    }
    if !matches!(
        transaction.state.as_str(),
        "active" | "validated" | "committing" | "committed"
    ) {
        return Err(format!(
            "Cannot commit transaction {} in state: {}",
            transaction_id, transaction.state
        ));
    }
    let rejected = kin_mcp::session::uncommittable_operations(&transaction.staged_operations);
    if !rejected.is_empty() {
        let detail = format!(
            "Cannot commit transaction {}: {} staged operation(s) are not committable:\n  - {}",
            transaction_id,
            rejected.len(),
            rejected.join("\n  - ")
        );
        return Err(unstage_failed_attempt(
            state,
            sessions,
            &transaction_id,
            detail,
        ));
    }
    if transaction.staged_operations.is_empty() {
        return Err(format!(
            "Cannot commit transaction {transaction_id}: exact repository commits reject empty transactions"
        ));
    }

    let operation_uuid = uuid::Uuid::parse_str(&transaction_id).map_err(|error| {
        format!(
            "transaction id {transaction_id} is not a stable repository operation UUID: {error}"
        )
    })?;
    let operation_id = OperationId::from_uuid(operation_uuid);
    let payload_hash = transaction_payload_hash(&transaction)?;
    let authority_context = authority_context(state)?;
    // Resolved once, from the live registry, and used for both the change
    // author and the durable attribution record. Resolving it twice could
    // straddle the session ending and attribute one commit two ways.
    let actor = resolve_commit_actor(sessions, &transaction.session_id);

    // A non-terminal committing marker means authority may already have moved.
    // Recover by the caller-stable operation ID before attempting any new plan.
    if matches!(transaction.state.as_str(), "committing" | "committed") {
        if transaction.commit_payload_hash.as_deref() != Some(payload_hash.as_str()) {
            return Err(format!(
                "Cannot recover transaction {transaction_id}: staged payload does not match its durable committing fence"
            ));
        }
        if let Some(recovered) = recover_native_commit(&authority_context, operation_id)
            .map_err(|error| format!("recover exact MCP repository receipt: {error}"))?
        {
            return finalize_committed_transaction(
                state,
                sessions,
                transaction,
                &actor,
                recovered,
                Vec::new(),
                coordination,
            );
        }
        if transaction.state == "committed" {
            return Err(format!(
                "transaction {transaction_id} is terminal but repository authority has no matching receipt"
            ));
        }

        // Repository-v6 publishes the receipt in the same atomic successor as
        // authority. Its absence proves the fenced attempt did not move
        // authority (it may only have copied immutable CAS bodies), so this
        // attempt can be safely reset and replanned against current roots.
        transaction = sessions
            .reset_transaction_commit(&transaction_id)
            .map_err(|error| format!("reset receipt-less committing fence: {error}"))?;
        persist_registry_checked(state, sessions)
            .map_err(|error| format!("persist receipt-less committing reset: {error}"))?;
    }

    let base = load_native_commit_base(&authority_context)
        .map_err(|error| format!("load exact MCP commit base: {error}"))?;
    require_bound_authority_revision(state, &base, &transaction_id)?;
    let plan = match plan_exact_transaction(
        state,
        &authority_context,
        &transaction,
        &actor,
        operation_id,
        &base,
    ) {
        Ok(plan) => plan,
        Err(error) => {
            return Err(unstage_failed_attempt(
                state,
                sessions,
                &transaction_id,
                error,
            ))
        }
    };

    // Publication fence: from this point until receipt recovery or an explicit
    // reset, the staged operation set is immutable and durable.
    sessions
        .prepare_transaction_commit(&transaction_id, &payload_hash)
        .map_err(|error| format!("prepare exact MCP transaction: {error}"))?;
    if let Err(error) = persist_registry_checked(state, sessions) {
        let _ = sessions.reset_transaction_commit(&transaction_id);
        return Err(format!(
            "persist exact MCP committing fence before repository mutation: {error}"
        ));
    }

    let committed = match commit_native_plan_with_projection(
        &state.layout,
        state.blobs.as_ref(),
        &authority_context,
        plan.native,
    ) {
        Ok(committed) => committed,
        Err(commit_error) => match recover_native_commit(&authority_context, operation_id) {
            Ok(Some(recovered)) => recovered,
            Ok(None) => {
                sessions
                        .reset_transaction_commit(&transaction_id)
                        .map_err(|reset_error| {
                            format!(
                                "repository commit failed ({commit_error}); reset committing fence: {reset_error}"
                            )
                        })?;
                persist_registry_checked(state, sessions).map_err(|persist_error| {
                        format!(
                            "repository commit failed ({commit_error}); persist reset transaction: {persist_error}"
                        )
                    })?;
                return Err(format!(
                    "exact MCP repository commit failed before authority moved: {commit_error}"
                ));
            }
            Err(recovery_error) => {
                return Err(format!(
                        "exact MCP repository commit returned {commit_error}; receipt recovery also failed: {recovery_error}"
                    ));
            }
        },
    };

    #[cfg(test)]
    if state
        .mcp_fail_after_authority_once
        .swap(false, Ordering::SeqCst)
    {
        return Err(format!(
            "injected crash boundary after repository receipt for transaction {transaction_id}"
        ));
    }

    finalize_committed_transaction(
        state,
        sessions,
        transaction,
        &actor,
        committed,
        plan.layouts,
        coordination,
    )
}

/// Discard the operations of a commit attempt that failed before the
/// publication fence, and say so in the refusal.
///
/// Every caller sits strictly before `prepare_transaction_commit`, so no
/// repository authority has moved and no CAS body has been published: the
/// staged set is the only state to undo. Leaving it staged is what wedges the
/// transaction, because a later `kin_transaction_stage` appends to it and the
/// next commit re-plans the same failing operation and returns the identical
/// error. Clearing it returns the transaction to a clean, editable state, so
/// the corrective action the error describes is actually reachable on the
/// transaction the caller already has.
fn unstage_failed_attempt(
    state: &Arc<DaemonState>,
    sessions: &kin_mcp::SessionRegistry,
    transaction_id: &str,
    detail: String,
) -> String {
    let cleared = match sessions.clear_staged_operations(transaction_id) {
        Ok(cleared) => cleared,
        Err(clear_error) => {
            return format!(
                "{detail}\nthe staged operations could not be cleared ({clear_error}); \
                 begin a new transaction with kin_transaction_begin"
            )
        }
    };
    let count = cleared.len();
    let dropped = describe_cleared_operations(&cleared);
    if let Err(persist_error) = persist_registry_checked(state, sessions) {
        return format!(
            "{detail}\nthe {count} failed operation(s) were cleared but could not be persisted \
             ({persist_error}); begin a new transaction with kin_transaction_begin\ndropped: \
             {dropped}"
        );
    }
    format!(
        "{detail}\nrepository authority did not move, and the {count} failed operation(s) have \
         been cleared from transaction {transaction_id}: stage corrected operations on it and \
         commit again, or begin a new transaction with kin_transaction_begin\ndropped: {dropped}"
    )
}

/// Name every operation the clear discarded.
///
/// The clear takes the whole staged set, so an attempt that failed on one bad
/// target also drops the correct operations staged alongside it, bodies and
/// all. A count alone leaves the caller guessing at what to re-stage; naming
/// the targets makes the retry mechanical.
fn describe_cleared_operations(cleared: &[kin_mcp::McpMutationOperation]) -> String {
    /// Enough to reconstruct a realistic staged set without letting one
    /// refusal carry an unbounded operation dump.
    const MAX_NAMED: usize = 32;

    if cleared.is_empty() {
        return "(none)".to_string();
    }
    let mut named = cleared
        .iter()
        .take(MAX_NAMED)
        .map(describe_cleared_operation)
        .collect::<Vec<_>>()
        .join(", ");
    if let Some(remaining) = cleared.len().checked_sub(MAX_NAMED).filter(|n| *n > 0) {
        named.push_str(&format!(", and {remaining} more"));
    }
    named
}

fn describe_cleared_operation(operation: &kin_mcp::McpMutationOperation) -> String {
    let verb = operation.verb.trim();
    let verb = if verb.is_empty() { "operation" } else { verb };
    match (operation.target.trim(), &operation.payload) {
        ("", Some(kin_mcp::McpMutationPayload::Relation { from, to, kind })) => {
            format!("{verb} relation {kind:?} {from} -> {to}")
        }
        ("", _) => format!("{verb} (unnamed target)"),
        (target, _) => format!("{verb} {target}"),
    }
}

/// Who a committed MCP transaction is attributed to.
///
/// The actor is the agent session that opened the transaction. A raw session id
/// identifies nobody once that session ends, and the session registry is
/// in-memory, so the vendor and client name the session registered with are
/// copied into the commit author and into a durable actor record at commit
/// time. The session id stays inside the author so a live coordination lookup
/// remains possible while the session is running, and so the two records can be
/// tied together afterwards.
struct CommitActor {
    author: kin_model::AuthorId,
    actor: Actor,
    session_id: String,
}

fn resolve_commit_actor(sessions: &kin_mcp::SessionRegistry, session_id: &str) -> CommitActor {
    let agent = uuid::Uuid::parse_str(session_id)
        .ok()
        .map(kin_model::SessionId)
        .and_then(|id| sessions.get_agent_session(&id));
    let display_name = match agent {
        Some(agent) => format!(
            "{}/{}",
            provenance_label(&agent.vendor),
            provenance_label(&agent.client_name)
        ),
        // A session registered through the legacy compatibility surface, or one
        // that has already ended, has no vendor to name. The id it committed
        // under is still an identity, and is better than an empty author.
        None => provenance_label(session_id),
    };
    CommitActor {
        author: kin_model::AuthorId::new(format!("{display_name} <mcp-agent:{session_id}>")),
        actor: Actor {
            actor_id: mcp_actor_id(session_id),
            kind: ActorKind::Assistant,
            display_name,
            external_refs: Vec::new(),
        },
        session_id: session_id.to_string(),
    }
}

/// One field of a provenance display name, made safe to render.
///
/// `kin history` reads everything before the first `<` as the author's name and
/// prints one row per revision, so an angle bracket or a newline arriving from a
/// client-supplied session name would truncate or break the row it appears in.
/// `/` goes too, because it is the separator the vendor and client names are
/// joined with: a vendor of `a/b` with client `c` would otherwise render
/// identically to a vendor of `a` with client `b/c`.
fn provenance_label(raw: &str) -> String {
    /// Long enough for a real vendor and session name, short enough that a
    /// pathological one cannot dominate a change record.
    const MAX_LABEL: usize = 64;

    let collapsed = raw
        .chars()
        .map(|character| {
            if character.is_control() || matches!(character, '<' | '>' | '/') {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if collapsed.is_empty() {
        return "unknown".to_string();
    }
    collapsed.chars().take(MAX_LABEL).collect()
}

/// A stable actor identity for one MCP session.
///
/// Derived rather than random so every commit a session makes resolves to the
/// same actor, which is what lets `query_audit_events` filter by actor and what
/// keeps a session's writes from reading as a crowd of one-commit strangers.
fn mcp_actor_id(session_id: &str) -> ActorId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-mcp-session-actor-v1\0");
    hasher.update(session_id.as_bytes());
    ActorId::from_hash(Hash256::from_bytes(hasher.finalize().into()))
}

/// A stable audit-event identity for one scope within one committed change.
///
/// Derived so a commit that is resumed after a crash re-derives the identifiers
/// it already wrote instead of appending a second attribution record for a
/// single write. `None` names the change itself, which is what a commit that
/// touched no entity is attributed to.
fn mcp_audit_event_id(change: &SemanticChangeId, entity: Option<&EntityId>) -> AuditEventId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-mcp-commit-audit-v1\0");
    hasher.update(change.to_string().as_bytes());
    hasher.update([0]);
    match entity {
        Some(entity) => hasher.update(entity.to_string().as_bytes()),
        None => hasher.update(b"change"),
    }
    AuditEventId::from_hash(Hash256::from_bytes(hasher.finalize().into()))
}

/// Record who committed, and what they touched, into the provenance surfaces.
///
/// Without this an MCP write is anonymous to every read surface that answers
/// "who changed this": `kin_provenance_query` returns no audit context, and
/// `kin-review`'s impact analysis, which resolves attribution and its
/// unreviewed-agent-change signal entirely from audit events and the actor they
/// name, treats an agent's commit as if nobody made it. The change author alone
/// does not reach either, because both read the audit trail.
///
/// One event per changed entity, because that is the scope the review layer
/// matches on, and one event scoped to the change itself when a transaction
/// changed no entity at all: a relation-only commit is still an agent write,
/// and leaving it out of the audit trail is the same silence this closes.
/// Called only after the repository receipt exists, so nothing is attributed to
/// a commit that did not land.
fn record_commit_provenance(
    graph: &kin_db::InMemoryGraph,
    actor: &CommitActor,
    transaction: &kin_mcp::McpTransaction,
    committed: &NativeCommitResult,
) -> Result<(), String> {
    /// How far back a resume looks for the attribution it may already have
    /// written.
    ///
    /// Queried without an actor filter deliberately. The store applies its
    /// limit with `take`, after any filter, so a filtered query short-circuits
    /// only once it has found that many matching events; a session with fewer
    /// commits than the limit never reaches it and the traversal runs the whole
    /// log. Unfiltered, the limit bounds the traversal itself, which is the
    /// property this needs. The derived event ids do the matching.
    ///
    /// MCP commits are serialized behind the coordination gate, so a resume
    /// sits within a handful of events of the attempt it is resuming, and the
    /// window is wide enough to absorb an interleaved restart.
    const DEDUP_WINDOW: usize = 1024;

    graph
        .create_actor(&actor.actor)
        .map_err(|error| format!("record committing agent actor: {error}"))?;

    let mut entities = committed
        .change
        .entity_deltas
        .iter()
        .map(|delta| match delta {
            EntityDelta::Added { new } | EntityDelta::Modified { new, .. } => new.id,
            EntityDelta::Removed { old } => old.id,
        })
        .collect::<Vec<_>>();
    // A relation-only commit changed no entity, so it has no entity delta to
    // scope to, but it is still an agent write against the entities the relation
    // joins. Scoping it to the change alone made it unfindable: every reader
    // that answers "who touched this entity" selects changes by scanning entity
    // deltas, which a relation-only change has none of, so the commit was
    // recorded and invisible. Its endpoints are the entities an operator would
    // ask about, so they are what it is attributed to.
    if entities.is_empty() {
        entities.extend(
            committed
                .change
                .relation_deltas
                .iter()
                .flat_map(|delta| match delta {
                    RelationDelta::Added { new } | RelationDelta::Modified { new, .. } => {
                        [new.src, new.dst]
                    }
                    RelationDelta::Removed { old } => [old.src, old.dst],
                })
                .filter_map(|endpoint| match endpoint {
                    GraphNodeId::Entity(id) => Some(id),
                    _ => None,
                }),
        );
    }
    entities.sort_unstable();
    entities.dedup();
    let scopes = if entities.is_empty() {
        // Nothing entity-shaped to name, so the change itself carries the
        // attribution rather than the write going unrecorded.
        vec![(
            mcp_audit_event_id(&committed.change.id, None),
            WorkScope::Change(committed.change.id),
        )]
    } else {
        entities
            .into_iter()
            .map(|entity| {
                (
                    mcp_audit_event_id(&committed.change.id, Some(&entity)),
                    WorkScope::Entity(entity),
                )
            })
            .collect()
    };

    let already_recorded = graph
        .query_audit_events(None, DEDUP_WINDOW)
        .map_err(|error| format!("read existing commit attribution: {error}"))?
        .into_iter()
        .map(|event| event.event_id)
        .collect::<HashSet<_>>();

    let details = serde_json::json!({
        "schema": "kin.mcp.commit_audit.v1",
        "transaction_id": transaction.transaction_id,
        "session_id": actor.session_id,
        "actor": actor.actor.display_name,
        "change_id": committed.change.id.to_string(),
        "repository_generation": committed.receipt.generation,
        "repository_operation_id": committed.receipt.operation_id.to_string(),
    })
    .to_string();

    for (event_id, scope) in scopes {
        if already_recorded.contains(&event_id) {
            continue;
        }
        graph
            .record_audit_event(&AuditEvent {
                event_id,
                actor_id: actor.actor.actor_id,
                action: "kin_transaction_commit".to_string(),
                target_scope: Some(scope.clone()),
                timestamp: committed.change.timestamp.clone(),
                details: Some(details.clone()),
            })
            .map_err(|error| format!("record commit attribution for {scope}: {error}"))?;
    }
    Ok(())
}

fn transaction_payload_hash(transaction: &kin_mcp::McpTransaction) -> Result<String, String> {
    let value = serde_json::to_value(serde_json::json!({
        "transaction_id": transaction.transaction_id,
        "session_id": transaction.session_id,
        "scope": transaction.scope,
        "operations": transaction.staged_operations,
    }))
    .map_err(|error| format!("serialize exact transaction payload: {error}"))?;
    let mut hasher = Sha256::new();
    hasher.update(b"kin-exact-mcp-transaction-v1\0");
    hash_canonical_json(&mut hasher, &value);
    Ok(hex::encode(hasher.finalize()))
}

fn hash_canonical_json(hasher: &mut Sha256, value: &serde_json::Value) {
    match value {
        serde_json::Value::Null => hasher.update([0]),
        serde_json::Value::Bool(value) => hasher.update([1, u8::from(*value)]),
        serde_json::Value::Number(value) => {
            hasher.update([2]);
            hash_bytes(hasher, value.to_string().as_bytes());
        }
        serde_json::Value::String(value) => {
            hasher.update([3]);
            hash_bytes(hasher, value.as_bytes());
        }
        serde_json::Value::Array(values) => {
            hasher.update([4]);
            hasher.update((values.len() as u64).to_le_bytes());
            for value in values {
                hash_canonical_json(hasher, value);
            }
        }
        serde_json::Value::Object(values) => {
            hasher.update([5]);
            hasher.update((values.len() as u64).to_le_bytes());
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for key in keys {
                hash_bytes(hasher, key.as_bytes());
                hash_canonical_json(hasher, &values[key]);
            }
        }
    }
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn persist_registry_checked(
    state: &DaemonState,
    sessions: &kin_mcp::SessionRegistry,
) -> Result<(), String> {
    let mut store = state
        .mcp_transactions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for transaction in sessions.list_transactions() {
        store.insert(transaction.transaction_id.clone(), transaction);
    }
    crate::state::write_persisted_mcp_transactions_checked(&state.layout, &store)
        .map_err(|error| error.to_string())
}

/// Refuse an exact MCP commit unless the daemon is still bound to the authority
/// revision this attempt is being planned against.
///
/// This is deliberately not a live-graph-equals-authority check. That invariant
/// is unachievable by design: the reconcile loop publishes only the tree through
/// the repository compare-and-swap and leaves parser semantics in the live
/// graph, and the asynchronous LSP enrichment worker writes relations into the
/// live graph outside the coordination gate. Both reach authority only when a
/// change is committed, so equality held for a moment after each commit and then
/// failed at the next enrichment tick, refusing every legitimate agent commit
/// that followed one.
///
/// Equality was never what kept derived enrichment out of the published change
/// either. [`plan_exact_transaction`] builds its prospective graph from
/// `base.graph`, which is repository authority, and applies only the staged
/// operations, so a derived lead in the live graph cannot reach publication no
/// matter what this precondition says. The live graph matters after the commit
/// instead, because [`install_authority_graph`] corrects it onto authority from
/// the live side.
///
/// So what must hold is the binding, not the equality: the daemon is at the same
/// authority generation this plan is loading, it holds no exact tree state
/// authority has not admitted, and it has neither dropped nor rewritten anything
/// that generation owns. That is exactly the boundary every other repository
/// command is held to, and reusing it keeps one definition of freshness across
/// them rather than a second, stricter one that only the MCP path can fail.
fn require_bound_authority_revision(
    state: &DaemonState,
    base: &NativeCommitBase,
    transaction_id: &str,
) -> Result<(), String> {
    require_fresh_daemon_workspace(
        state,
        &base.roots,
        &base.graph.to_snapshot(),
        "committing an MCP transaction",
    )
    .map_err(|error| {
        format!(
            "Cannot commit transaction {transaction_id}: {error}. No repository authority moved \
             and the staged operations are untouched, so re-send this commit unchanged once the \
             daemon is reading current repository authority."
        )
    })
}

fn semantic_workspace_matches(left: &kin_db::InMemoryGraph, right: &kin_db::InMemoryGraph) -> bool {
    let left = left.to_snapshot();
    let right = right.to_snapshot();
    left.entities == right.entities
        && left.relations == right.relations
        && left.resolved_tree == right.resolved_tree
}

fn plan_exact_transaction(
    state: &DaemonState,
    authority_context: &LocalRepositoryAuthorityContext,
    transaction: &kin_mcp::McpTransaction,
    actor: &CommitActor,
    operation_id: OperationId,
    base: &NativeCommitBase,
) -> Result<ExactMcpPlan, String> {
    let prospective = kin_db::InMemoryGraph::from_snapshot(base.graph.to_snapshot())
        .map_err(|error| format!("create prospective exact graph: {error}"))?;
    let mut edits: BTreeMap<String, (FilePathId, Vec<(Entity, Vec<u8>)>)> = BTreeMap::new();
    let mut relation_operations = Vec::new();
    let mut edited_entities = HashSet::new();

    for operation in &transaction.staged_operations {
        let verb = operation.verb.trim().to_ascii_lowercase();
        // A payload-less `update` carrying a target and a body is the minimal
        // agent write surface: an agent knows a name and the new source text but
        // not Kin's entity structs. Staging accepts it, so the planner must too,
        // or the operation is admitted and then refused at commit. The target is
        // resolved against repository authority (a uuid must exist, a name must
        // match exactly one entity by exact name) and lands on the same exact
        // span edit an entity payload produces.
        if operation.payload.is_none() {
            if !kin_mcp::session::is_target_body_update(operation) {
                return Err(format!("operation '{}' has no payload", operation.verb));
            }
            let existing =
                kin_mcp::handlers::sessions::resolve_target_entity(&base.graph, &operation.target)?;
            let body = operation
                .body
                .as_ref()
                .expect("a target body update always carries a body");
            record_source_edit(
                &mut edits,
                &mut edited_entities,
                base,
                existing,
                body.as_bytes(),
            )?;
            continue;
        }
        let payload = operation
            .payload
            .as_ref()
            .ok_or_else(|| format!("operation '{}' has no payload", operation.verb))?;
        match payload {
            kin_mcp::McpMutationPayload::Entity(payload_entity) => {
                if operation.target.trim() != payload_entity.id.to_string() {
                    return Err(format!(
                        "exact entity mutation target must be the repository entity ID {}; got {:?}",
                        payload_entity.id, operation.target
                    ));
                }
                if !matches!(verb.as_str(), "update" | "modify") {
                    return Err(format!(
                        "entity verb '{}' is not yet supported by exact MCP commits; create/insertion/delete operations fail before mutation",
                        operation.verb
                    ));
                }
                let body = operation.body.as_ref().ok_or_else(|| {
                    format!(
                        "source-bound entity {} requires an exact UTF-8 body; metadata-only source mutations are rejected",
                        payload_entity.id
                    )
                })?;
                let existing = base
                    .graph
                    .get_entity(&payload_entity.id)
                    .map_err(|error| format!("load exact entity {}: {error}", payload_entity.id))?
                    .ok_or_else(|| {
                        format!(
                            "entity {} is absent from repository authority; insertion is not supported",
                            payload_entity.id
                        )
                    })?;
                if payload_entity.name != existing.name || payload_entity.kind != existing.kind {
                    return Err(format!(
                        "exact body edits cannot rename or re-kind entity {}; staged {} {:?}, authority has {} {:?}",
                        existing.id,
                        payload_entity.name,
                        payload_entity.kind,
                        existing.name,
                        existing.kind
                    ));
                }
                if payload_entity
                    .file_origin
                    .as_ref()
                    .is_some_and(|origin| Some(origin) != existing.file_origin.as_ref())
                {
                    return Err(format!(
                        "staged file origin for entity {} does not match repository authority",
                        existing.id
                    ));
                }
                if payload_entity
                    .span
                    .as_ref()
                    .is_some_and(|span| Some(span) != existing.span.as_ref())
                {
                    return Err(format!(
                        "staged source span for entity {} does not match repository authority",
                        existing.id
                    ));
                }
                // The commit publishes whatever reparsing the new bytes derives,
                // so a doc summary the caller edited by hand cannot survive.
                // Refusing an edited one is the same rule already applied to
                // name, kind, origin, and span: keeping it would report a
                // documentation edit as committed while publishing only the
                // body.
                //
                // Scoped to `doc_summary` and deliberately not extended to the
                // whole `metadata` bag. That bag carries values derived from the
                // entity's own source: `kin-parser` writes
                // `embedding_body_preview` out of the source bytes at extraction
                // time, so any commit that changes a body necessarily changes it
                // too. An agent that reads an entity once and then makes two
                // edits therefore holds, on the second, a bag that its own first
                // commit already moved authority past, and comparing the bag
                // would refuse it for a difference it caused by succeeding.
                // `doc_summary` is a single named field whose value a caller
                // either changed on purpose or did not, so a difference there is
                // real evidence of intent.
                if payload_entity.doc_summary != existing.doc_summary {
                    return Err(format!(
                        "staged doc summary for entity {} differs from repository authority; \
                         entity documentation is derived from the committed source, so send it \
                         unchanged and put the new documentation in `body`",
                        existing.id
                    ));
                }
                record_source_edit(
                    &mut edits,
                    &mut edited_entities,
                    base,
                    existing,
                    body.as_bytes(),
                )?;
            }
            kin_mcp::McpMutationPayload::Relation { .. } => {
                relation_operations.push((verb, payload.clone()));
            }
            kin_mcp::McpMutationPayload::Blob(_) => {
                return Err("blob payloads are not supported by exact MCP transactions".to_string());
            }
        }
    }

    let mut layouts = Vec::new();
    let pipeline = kin_index::IndexPipeline::new();
    for (_, (file_id, file_edits)) in edits {
        let path = RepoPath::from_utf8(file_id.0.clone())
            .map_err(|error| format!("invalid exact source path {file_id}: {error}"))?;
        let artifact = prospective
            .resolved_tree()
            .artifact_at_path(&path)
            .cloned()
            .ok_or_else(|| {
                format!("exact source artifact disappeared during planning: {file_id}")
            })?;
        let (old_hash, executable) = match artifact.entry {
            TreeEntry::Blob { hash, executable } => (hash, executable),
            TreeEntry::Symlink { .. } => {
                return Err(format!(
                    "exact source entity {} resolves through a symlink",
                    file_id
                ))
            }
            TreeEntry::Gitlink { .. } => {
                return Err(format!(
                    "exact source entity {} resolves through a gitlink",
                    file_id
                ))
            }
        };
        let original = load_native_source_blob(authority_context, old_hash)
            .map_err(|error| format!("load exact source body for {file_id}: {error}"))?;
        std::str::from_utf8(&original).map_err(|error| {
            format!(
                "entity source {} is not valid UTF-8 at byte {}; exact body splicing is unavailable",
                file_id,
                error.valid_up_to()
            )
        })?;
        // `entity_body_splice`, not a raw span splice: an entity span opens at
        // the entity's first token, so a nested entity's indentation sits in the
        // file ahead of the span while the rest of its body carries indentation
        // inside it. A caller that submits the entity as the file renders it
        // would otherwise have line 1 indented twice.
        let splices = file_edits
            .iter()
            .map(|(entity, body)| {
                let span = entity
                    .span
                    .as_ref()
                    .expect("validated source edit always has a span");
                kin_projection::entity_body_splice(&original, span.start_byte..span.end_byte, body)
            })
            .collect();
        let projected = kin_projection::apply_splices(&original, splices)
            .map_err(|error| format!("splice exact source {file_id}: {error}"))?;
        if projected == original {
            return Err(format!(
                "exact body edit for {file_id} is a no-op; no repository commit was created"
            ));
        }
        let digest = state
            .blobs
            .write(&projected)
            .map_err(|error| format!("store projected source {file_id}: {error}"))?;
        let new_hash = Hash256::from_bytes(digest.0);
        prospective
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id: artifact.artifact_id,
                    old: artifact.located_entry(),
                    new: LocatedEntry::new(path, TreeEntry::blob(new_hash, executable)),
                }],
                ..TransactionDelta::default()
            })
            .map_err(|error| format!("install prospective exact tree for {file_id}: {error}"))?;

        let indexed = pipeline
            .index_any_content(&file_id, &projected, digest)
            .map_err(|error| format!("reparse projected exact source {file_id}: {error}"))?;
        let kin_index::IndexedAny::EntitySource(indexed) = indexed else {
            return Err(format!(
                "projected entity source {file_id} no longer classifies as supported source; commit rejected"
            ));
        };
        let mut reconciler = kin_reconcile::Reconciler::new(PathBuf::new());
        let reconcile = reconciler
            .reconcile_indexed_content(&indexed, state.blobs.as_ref(), &prospective)
            .map_err(|error| format!("derive exact semantics for {file_id}: {error}"))?;
        if let Some(delta) = reconcile.delta.entity_deltas.iter().find(|delta| {
            matches!(
                delta,
                EntityDelta::Added { .. } | EntityDelta::Removed { .. }
            )
        }) {
            return Err(format!(
                "body edit for {file_id} would create or remove source entities ({delta:?}); insertion/deletion is not yet supported"
            ));
        }
        prospective
            .apply_transaction_delta(&reconcile.delta)
            .map_err(|error| format!("apply reparsed exact semantics for {file_id}: {error}"))?;
        for (entity, _) in &file_edits {
            let parsed = prospective
                .get_entity(&entity.id)
                .map_err(|error| format!("load reparsed entity {}: {error}", entity.id))?
                .ok_or_else(|| {
                    format!(
                        "reparsed exact bytes did not preserve existing entity {}",
                        entity.id
                    )
                })?;
            if parsed.name != entity.name || parsed.kind != entity.kind {
                return Err(format!(
                    "reparsed exact bytes changed entity {} identity; rename/re-kind is unsupported",
                    entity.id
                ));
            }
        }
        let layout = reconciler
            .projection()
            .get_layout(&file_id)
            .cloned()
            .ok_or_else(|| format!("reparse produced no exact file layout for {file_id}"))?;
        prospective
            .upsert_file_layout(&layout)
            .map_err(|error| format!("install prospective layout for {file_id}: {error}"))?;
        layouts.push(layout);
    }

    apply_relation_operations(&prospective, relation_operations)?;
    if semantic_workspace_matches(&prospective, &base.graph) {
        return Err(
            "exact MCP transaction produced no semantic, relation, or tree change".to_string(),
        );
    }

    let message = format!("MCP transaction {}", transaction.transaction_id);
    let native = plan_native_commit_from_base(
        &prospective,
        state.blobs.as_ref(),
        authority_context,
        operation_id,
        kin_model::Timestamp::now(),
        actor.author.clone(),
        message,
        base,
    )
    .map_err(|error| format!("plan exact MCP repository commit: {error}"))?;
    Ok(ExactMcpPlan { native, layouts })
}

/// Record one entity source edit against repository authority.
///
/// Shared by the entity-payload form and the payload-less target/body form:
/// both end in the same place, an authoritative span in an exact blob replaced
/// by exact new bytes. `existing` is always the authority-side entity, never the
/// staged payload, so the span is the one repository truth records.
fn record_source_edit(
    edits: &mut BTreeMap<String, (FilePathId, Vec<(Entity, Vec<u8>)>)>,
    edited_entities: &mut HashSet<kin_model::EntityId>,
    base: &NativeCommitBase,
    existing: Entity,
    body: &[u8],
) -> Result<(), String> {
    if !edited_entities.insert(existing.id) {
        return Err(format!(
            "entity {} is edited more than once in one transaction; overlapping source authority is ambiguous",
            existing.id
        ));
    }
    let file_id = existing.file_origin.clone().ok_or_else(|| {
        format!(
            "entity {} has no exact source origin; graph-only entity mutation is not supported",
            existing.id
        )
    })?;
    let span = existing.span.as_ref().ok_or_else(|| {
        format!(
            "entity {} has no exact source span; mutation requires a full body and authoritative span",
            existing.id
        )
    })?;
    if span.file != file_id {
        return Err(format!(
            "entity {} source span file {} disagrees with origin {}",
            existing.id, span.file, file_id
        ));
    }
    if span.start_byte >= span.end_byte {
        return Err(format!(
            "entity {} has an empty or inverted exact source span {}..{}",
            existing.id, span.start_byte, span.end_byte
        ));
    }
    let path = RepoPath::from_utf8(file_id.0.clone())
        .map_err(|error| format!("invalid entity repository path {file_id}: {error}"))?;
    let artifact = base.tree.artifact_at_path(&path).ok_or_else(|| {
        format!(
            "entity {} source {} is absent from exact workspace tree",
            existing.id, file_id
        )
    })?;
    if !matches!(artifact.entry, TreeEntry::Blob { .. }) {
        return Err(format!(
            "entity {} source {} is not a regular blob entry",
            existing.id, file_id
        ));
    }
    edits
        .entry(file_id.0.clone())
        .or_insert_with(|| (file_id, Vec::new()))
        .1
        .push((existing, body.to_vec()));
    Ok(())
}

fn apply_relation_operations(
    prospective: &kin_db::InMemoryGraph,
    operations: Vec<(String, kin_mcp::McpMutationPayload)>,
) -> Result<(), String> {
    for (verb, payload) in operations {
        let kin_mcp::McpMutationPayload::Relation { from, to, kind } = payload else {
            return Err("internal exact relation planner received a non-relation payload".into());
        };
        for endpoint in [from, to] {
            if prospective
                .get_entity(&endpoint)
                .map_err(|error| format!("load relation endpoint {endpoint}: {error}"))?
                .is_none()
            {
                return Err(format!(
                    "relation endpoint {endpoint} is absent from prospective repository authority"
                ));
            }
        }
        let mut matching = prospective
            .get_all_relations_for_entity(&from)
            .map_err(|error| format!("load existing relations for {from}: {error}"))?
            .into_iter()
            .filter(|relation| {
                relation.kind == kind
                    && relation.src == GraphNodeId::Entity(from)
                    && relation.dst == GraphNodeId::Entity(to)
            })
            .collect::<Vec<_>>();
        matching.sort_by_key(|relation| relation.id);

        let delta = match verb.as_str() {
            "create" | "add" | "insert" => {
                if !matching.is_empty() {
                    return Err(format!(
                        "relation {:?} from {} to {} already exists; use upsert or remove the duplicate operation",
                        kind, from, to
                    ));
                }
                TransactionDelta {
                    relation_deltas: vec![RelationDelta::Added {
                        new: Relation {
                            id: kin_model::RelationId::new(),
                            kind,
                            src: GraphNodeId::Entity(from),
                            dst: GraphNodeId::Entity(to),
                            confidence: 1.0,
                            origin: RelationOrigin::Manual,
                            created_in: None,
                            import_source: None,
                            evidence: Vec::new(),
                        },
                    }],
                    ..TransactionDelta::default()
                }
            }
            "upsert" if matching.is_empty() => TransactionDelta {
                relation_deltas: vec![RelationDelta::Added {
                    new: Relation {
                        id: kin_model::RelationId::new(),
                        kind,
                        src: GraphNodeId::Entity(from),
                        dst: GraphNodeId::Entity(to),
                        confidence: 1.0,
                        origin: RelationOrigin::Manual,
                        created_in: None,
                        import_source: None,
                        evidence: Vec::new(),
                    },
                }],
                ..TransactionDelta::default()
            },
            "upsert" => continue,
            "delete" | "remove" => {
                let [old] = matching.as_slice() else {
                    return Err(if matching.is_empty() {
                        format!(
                            "relation {:?} from {} to {} does not exist in repository authority",
                            kind, from, to
                        )
                    } else {
                        format!(
                            "relation {:?} from {} to {} is ambiguous across {} matching edges",
                            kind,
                            from,
                            to,
                            matching.len()
                        )
                    });
                };
                TransactionDelta {
                    relation_deltas: vec![RelationDelta::Removed { old: old.clone() }],
                    ..TransactionDelta::default()
                }
            }
            _ => {
                return Err(format!(
                    "relation verb '{verb}' is not supported by exact MCP commits"
                ))
            }
        };
        prospective
            .apply_transaction_delta(&delta)
            .map_err(|error| format!("apply prospective relation operation: {error}"))?;
    }
    Ok(())
}

/// Answer a commit whose transaction record is gone by asking repository
/// authority whether that transaction already landed.
///
/// The record is deliberately evicted once a commit succeeds, so its absence
/// carries no information on its own: it is the state left behind by success
/// and the state left behind by an id that never existed. Repository authority
/// separates them, because the receipt is keyed by the same caller-stable
/// operation id the transaction id derives from and it is published in the same
/// atomic successor as the authority it moved. A receipt therefore proves the
/// work applied, and its absence proves it did not.
///
/// Nothing here re-applies or re-installs anything. The reply is derived
/// entirely from the persisted receipt, so a caller that retries an
/// already-applied commit any number of times gets the same answer and moves
/// authority exactly once.
fn replay_applied_commit(
    state: &Arc<DaemonState>,
    transaction_id: &str,
    coordination: Option<&kin_mcp::CoordinationWritePreflight>,
) -> Result<kin_mcp::ToolCallResult, String> {
    let Ok(operation_uuid) = uuid::Uuid::parse_str(transaction_id) else {
        // Not a transaction id this daemon could ever have minted, so there is
        // no receipt to look for and nothing to be idempotent about.
        return Err(format!("Transaction not found: {transaction_id}"));
    };
    let authority_context = authority_context(state)?;
    let Some(recovered) =
        recover_native_commit(&authority_context, OperationId::from_uuid(operation_uuid))
            .map_err(|error| format!("recover exact MCP repository receipt: {error}"))?
    else {
        return Err(format!(
            "Transaction not found: {transaction_id}. Repository authority holds no receipt for \
             it either, so nothing was published under this id and re-sending this commit cannot \
             succeed. Begin a new transaction with kin_transaction_begin and stage the operations \
             again."
        ));
    };

    let modified_files = changed_file_ids(&recovered.change)?;
    let result = serde_json::json!({
        "transaction_id": transaction_id,
        "state": "committed",
        "status": "committed",
        "already_applied": true,
        "empty": false,
        "entity_deltas": recovered.entity_count,
        "relation_deltas": recovered.relation_count,
        "change_id": recovered.change.id.to_string(),
        "repository_generation": recovered.receipt.generation,
        "repository_operation_id": recovered.receipt.operation_id.to_string(),
        "new_root_hash": hex::encode(state.graph.compute_root_hash()),
        "modified_files": modified_files.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "collision_warnings": [],
        "conflicts": [],
        "semantic_authority": "reparsed_exact_repository_bytes",
        "coordination": coordination,
    });
    let json = serde_json::to_string_pretty(&result)
        .map_err(|error| format!("serialize replayed exact MCP commit response: {error}"))?;
    Ok(kin_mcp::ToolCallResult::text(json))
}

fn finalize_committed_transaction(
    state: &Arc<DaemonState>,
    sessions: &kin_mcp::SessionRegistry,
    transaction: kin_mcp::McpTransaction,
    actor: &CommitActor,
    committed: NativeCommitResult,
    planned_layouts: Vec<FileLayout>,
    coordination: Option<&kin_mcp::CoordinationWritePreflight>,
) -> Result<kin_mcp::ToolCallResult, String> {
    let authority_context = authority_context(state)?;
    let authority = load_native_commit_base(&authority_context)
        .map_err(|error| format!("reload committed MCP repository authority: {error}"))?;
    if authority.roots != committed.receipt.roots_after {
        return Err(format!(
            "repository authority advanced beyond MCP receipt generation {}; reopen the daemon before finalizing transaction {}",
            committed.receipt.generation, transaction.transaction_id
        ));
    }

    install_authority_graph(state.graph.as_ref(), &authority.graph, &committed)?;
    let layouts = if planned_layouts.is_empty() && committed.file_count > 0 {
        rebuild_changed_layouts(state, &authority, &committed.change)?
    } else {
        planned_layouts
    };
    for layout in layouts {
        state.graph.upsert_file_layout(&layout).map_err(|error| {
            format!("install committed exact layout {}: {error}", layout.file_id)
        })?;
    }
    if !semantic_workspace_matches(state.graph.as_ref(), &authority.graph) {
        return Err(format!(
            "derived daemon graph does not match repository authority after transaction {}",
            transaction.transaction_id
        ));
    }
    record_commit_provenance(state.graph.as_ref(), actor, &transaction, &committed)?;

    let observed_generation = state.snapshot_generation.load(Ordering::SeqCst);
    if observed_generation < committed.receipt.generation {
        state
            .record_repository_authority_commit(committed.receipt.generation)
            .map_err(|error| format!("record committed repository generation: {error}"))?;
    } else if observed_generation > committed.receipt.generation {
        return Err(format!(
            "daemon generation {observed_generation} is ahead of recovered MCP receipt {}; reopen before terminalizing",
            committed.receipt.generation
        ));
    }

    let terminal = if transaction.state == "committed" {
        transaction
    } else {
        sessions
            .commit_transaction(&transaction.transaction_id)
            .map_err(|error| format!("terminalize exact MCP transaction: {error}"))?
    };
    let modified_files = changed_file_ids(&committed.change)?;
    let root_hash = hex::encode(state.graph.compute_root_hash());
    let result = serde_json::json!({
        "transaction_id": terminal.transaction_id,
        "state": "committed",
        "status": "committed",
        "ops_applied": terminal.staged_operations.len(),
        "entity_deltas": committed.entity_count,
        "relation_deltas": committed.relation_count,
        "empty": false,
        "change_id": committed.change.id.to_string(),
        "repository_generation": committed.receipt.generation,
        "repository_operation_id": committed.receipt.operation_id.to_string(),
        "new_root_hash": root_hash,
        "modified_files": modified_files.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "collision_warnings": [],
        "conflicts": [],
        "semantic_authority": "reparsed_exact_repository_bytes",
        "coordination": coordination,
    });
    let json = serde_json::to_string_pretty(&result)
        .map_err(|error| format!("serialize exact MCP commit response: {error}"))?;
    Ok(kin_mcp::ToolCallResult::text(json))
}

fn install_authority_graph(
    live: &kin_db::InMemoryGraph,
    authority: &kin_db::InMemoryGraph,
    committed: &NativeCommitResult,
) -> Result<(), String> {
    live.create_changes(vec![committed.change.clone()])
        .map_err(|error| format!("install committed semantic change: {error}"))?;
    if semantic_workspace_matches(live, authority) {
        return Ok(());
    }
    let correction = transaction_delta_between(live, authority)?;
    live.apply_transaction_delta(&correction)
        .map_err(|error| format!("install committed authority delta into derived graph: {error}"))
}

fn transaction_delta_between(
    current: &kin_db::InMemoryGraph,
    desired: &kin_db::InMemoryGraph,
) -> Result<TransactionDelta, String> {
    let current = current.to_snapshot();
    let desired = desired.to_snapshot();
    let mut entity_deltas = Vec::new();
    for (id, entity) in &desired.entities {
        match current.entities.get(id) {
            None => entity_deltas.push(EntityDelta::Added {
                new: entity.clone(),
            }),
            Some(old) if old != entity => entity_deltas.push(EntityDelta::Modified {
                old: old.clone(),
                new: entity.clone(),
            }),
            Some(_) => {}
        }
    }
    for (id, entity) in &current.entities {
        if !desired.entities.contains_key(id) {
            entity_deltas.push(EntityDelta::Removed {
                old: entity.clone(),
            });
        }
    }
    entity_deltas.sort_by_key(EntityDelta::target_id);

    let mut relation_deltas = Vec::new();
    for (id, relation) in &desired.relations {
        match current.relations.get(id) {
            None => relation_deltas.push(RelationDelta::Added {
                new: relation.clone(),
            }),
            Some(old) if old != relation => relation_deltas.push(RelationDelta::Modified {
                old: old.clone(),
                new: relation.clone(),
            }),
            Some(_) => {}
        }
    }
    for (id, relation) in &current.relations {
        if !desired.relations.contains_key(id) {
            relation_deltas.push(RelationDelta::Removed {
                old: relation.clone(),
            });
        }
    }
    relation_deltas.sort_by_key(RelationDelta::target_id);
    let tree_deltas =
        kin_core::exact_tree_correction(&current.resolved_tree, &desired.resolved_tree).map_err(
            |error| format!("derive exact tree correction from committed authority: {error}"),
        )?;
    Ok(TransactionDelta {
        entity_deltas,
        relation_deltas,
        tree_deltas,
        admission_policy_delta: None,
        external_reference_deltas: Vec::new(),
    })
}

fn changed_file_ids(change: &kin_model::SemanticChange) -> Result<Vec<FilePathId>, String> {
    let mut files = change
        .tree_deltas
        .iter()
        .filter_map(|delta| delta.new_state().map(|located| located.path.clone()))
        .map(|path| {
            path.as_utf8()
                .map(|path| FilePathId::new(path.to_string()))
                .ok_or_else(|| {
                    format!(
                        "MCP source change contains non-UTF-8 path {}; source entity paths must be UTF-8",
                        path
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files.dedup();
    Ok(files)
}

fn rebuild_changed_layouts(
    state: &DaemonState,
    authority: &NativeCommitBase,
    change: &kin_model::SemanticChange,
) -> Result<Vec<FileLayout>, String> {
    let authority_context = authority_context(state)?;
    let pipeline = kin_index::IndexPipeline::new();
    let mut layouts = Vec::new();
    for file_id in changed_file_ids(change)? {
        let path = RepoPath::from_utf8(file_id.0.clone())
            .map_err(|error| format!("invalid recovered source path {file_id}: {error}"))?;
        let artifact = authority
            .tree
            .artifact_at_path(&path)
            .ok_or_else(|| format!("recovered authority has no changed artifact {file_id}"))?;
        let hash = artifact.entry.blob_identity().ok_or_else(|| {
            format!("recovered changed artifact {file_id} is an unmaterializable gitlink")
        })?;
        let body = load_native_source_blob(&authority_context, hash)
            .map_err(|error| format!("load recovered exact body for {file_id}: {error}"))?;
        let indexed = pipeline
            .index_any_content(
                &file_id,
                &body,
                kin_blobs::Hash256::from_bytes(*hash.as_bytes()),
            )
            .map_err(|error| format!("reindex recovered exact body for {file_id}: {error}"))?;
        let kin_index::IndexedAny::EntitySource(indexed) = indexed else {
            continue;
        };
        let mut layout = indexed.file_layout;
        stabilize_layout_ids(&mut layout, &indexed.entities, &authority.graph)?;
        layouts.push(layout);
    }
    Ok(layouts)
}

fn stabilize_layout_ids(
    layout: &mut FileLayout,
    parsed_entities: &[Entity],
    authority: &kin_db::InMemoryGraph,
) -> Result<(), String> {
    let layout_file_id = layout.file_id.clone();
    let authority_entities = authority
        .query_entities(&kin_model::EntityFilter {
            file_path: Some(layout_file_id.clone()),
            ..kin_model::EntityFilter::default()
        })
        .map_err(|error| format!("load authority entities for {}: {error}", layout_file_id))?;
    for region in &mut layout.regions {
        let SourceRegion::EntityRef { entity_id, .. } = region else {
            continue;
        };
        let parsed = parsed_entities
            .iter()
            .find(|entity| entity.id == *entity_id)
            .ok_or_else(|| {
                format!(
                    "layout {} references parser entity {} that was not returned",
                    layout_file_id, entity_id
                )
            })?;
        let mut matches = authority_entities
            .iter()
            .filter(|entity| entity.name == parsed.name && entity.kind == parsed.kind);
        let stable = matches.next().ok_or_else(|| {
            format!(
                "recovered layout entity {} {:?} has no authority identity in {}",
                parsed.name, parsed.kind, layout_file_id
            )
        })?;
        if matches.next().is_some() {
            return Err(format!(
                "recovered layout entity {} {:?} is ambiguous in {}",
                parsed.name, parsed.kind, layout_file_id
            ));
        }
        *entity_id = stable.id;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::OnceLock;

    use kin_model::{AuthorId, EntityFilter, LocatedEntry, SemanticChangeId, Timestamp, TreeDelta};

    fn install_test_registry_override() {
        static REGISTRY_PATH: OnceLock<PathBuf> = OnceLock::new();
        let _guard = crate::test_env_lock();
        let path = REGISTRY_PATH.get_or_init(|| {
            let root = std::env::temp_dir().join(format!(
                "kin-daemon-exact-mcp-registry-{}",
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&root).unwrap();
            let path = root.join("registry.toml");
            kin_core::registry::KinRegistry { repos: Vec::new() }
                .save_to(&path)
                .unwrap();
            path
        });
        kin_core::test_env::install_process_wide("KIN_REGISTRY_PATH", path);
    }

    fn test_state() -> (tempfile::TempDir, Arc<DaemonState>) {
        install_test_registry_override();
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::init(dir.path()).unwrap().layout;
        let state = Arc::new(DaemonState::open(layout).unwrap());
        (dir, state)
    }

    fn test_authority_context(layout: &kin_core::KinLayout) -> LocalRepositoryAuthorityContext {
        LocalRepositoryAuthorityContext::from_layout_for_test(layout).unwrap()
    }

    fn load_native_commit_base(
        layout: &kin_core::KinLayout,
    ) -> crate::error::Result<NativeCommitBase> {
        crate::repository_commit::load_native_commit_base(&test_authority_context(layout))
    }

    fn load_native_source_blob(
        layout: &kin_core::KinLayout,
        hash: Hash256,
    ) -> crate::error::Result<Vec<u8>> {
        crate::repository_commit::load_native_source_blob(&test_authority_context(layout), hash)
    }

    fn commit_native_plan_with_projection(
        layout: &kin_core::KinLayout,
        blobs: &kin_blobs::BlobStore,
        plan: crate::repository_commit::NativeCommitPlan,
    ) -> crate::error::Result<NativeCommitResult> {
        crate::repository_commit::commit_native_plan_with_projection(
            layout,
            blobs,
            &test_authority_context(layout),
            plan,
        )
    }

    fn git(repo: &Path, args: &[&str]) -> String {
        let output = kin_git::test_support::fixture_git_in(repo)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
            .output()
            .unwrap_or_else(|error| panic!("run git {args:?}: {error}"));
        assert!(
            output.status.success(),
            "git {args:?} failed\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn install_exact_source(
        state: &Arc<DaemonState>,
        file: &str,
        content: &[u8],
        entity_name: &str,
    ) -> (Entity, SemanticChangeId) {
        let file_id = FilePathId::new(file);
        let blob_hash = state.blobs.write(content).unwrap();
        let source_hash = Hash256::from_bytes(blob_hash.0);
        let path = RepoPath::from_utf8(file).unwrap();
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: kin_model::ArtifactId::new(),
                    new: LocatedEntry::new(path, TreeEntry::blob(source_hash, false)),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();

        let indexed = kin_index::IndexPipeline::new()
            .index_any_content(&file_id, content, blob_hash)
            .unwrap();
        let kin_index::IndexedAny::EntitySource(indexed) = indexed else {
            panic!("{file} must classify as supported source");
        };
        let mut reconciler = kin_reconcile::Reconciler::new(PathBuf::new());
        let reconciled = reconciler
            .reconcile_indexed_content(&indexed, state.blobs.as_ref(), state.graph.as_ref())
            .unwrap();
        state
            .graph
            .apply_transaction_delta(&reconciled.delta)
            .unwrap();
        let layout = reconciler
            .projection()
            .get_layout(&file_id)
            .cloned()
            .expect("source reconcile must produce an exact layout");
        state.graph.upsert_file_layout(&layout).unwrap();
        let entity = state
            .graph
            .query_entities(&EntityFilter {
                name_pattern: Some(entity_name.to_string()),
                file_path: Some(file_id),
                ..EntityFilter::default()
            })
            .unwrap()
            .into_iter()
            .find(|entity| entity.name == entity_name)
            .expect("source fixture must contain requested entity");

        let plan = crate::repository_commit::plan_native_commit(
            state.graph.as_ref(),
            state.blobs.as_ref(),
            &authority_context(state).unwrap(),
            OperationId::new(),
            Timestamp::now(),
            AuthorId::new("exact-mcp-test"),
            format!("install exact source {file}"),
        )
        .unwrap();
        let committed =
            commit_native_plan_with_projection(&state.layout, state.blobs.as_ref(), plan).unwrap();
        state
            .graph
            .create_changes(vec![committed.change.clone()])
            .unwrap();
        state
            .record_repository_authority_commit(committed.receipt.generation)
            .unwrap();
        (entity, committed.change.id)
    }

    fn commit_live_graph(
        state: &Arc<DaemonState>,
        message: &str,
        project_tree: bool,
    ) -> NativeCommitResult {
        let plan = crate::repository_commit::plan_native_commit(
            state.graph.as_ref(),
            state.blobs.as_ref(),
            &authority_context(state).unwrap(),
            OperationId::new(),
            Timestamp::now(),
            AuthorId::new("exact-mcp-test"),
            message.to_string(),
        )
        .unwrap();
        let committed = if project_tree {
            commit_native_plan_with_projection(&state.layout, state.blobs.as_ref(), plan).unwrap()
        } else {
            crate::repository_commit::commit_native_plan(
                state.blobs.as_ref(),
                &authority_context(state).unwrap(),
                plan,
            )
            .unwrap()
        };
        state
            .graph
            .create_changes(vec![committed.change.clone()])
            .unwrap();
        state
            .record_repository_authority_commit(committed.receipt.generation)
            .unwrap();
        committed
    }

    const TEST_SESSION: &str = "exact-mcp-test";

    /// A registry whose `TEST_SESSION` is already live.
    ///
    /// Beginning a transaction requires an existing session so a commit
    /// attributes to a real actor. These fixtures drive the daemon commit path
    /// directly instead of through `kin_session_start`, so they register the
    /// session themselves.
    fn test_sessions() -> kin_mcp::SessionRegistry {
        let sessions = kin_mcp::SessionRegistry::new();
        sessions.register(TEST_SESSION, "kin-daemon-test");
        sessions
    }

    fn stage_entity_edit(
        sessions: &kin_mcp::SessionRegistry,
        entity: &Entity,
        body: &str,
    ) -> (String, HashMap<String, serde_json::Value>) {
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![kin_mcp::McpMutationOperation {
                    verb: "update".to_string(),
                    target: entity.id.to_string(),
                    payload: Some(kin_mcp::McpMutationPayload::Entity(entity.clone())),
                    body: Some(body.to_string()),
                    description: "replace exact entity body".to_string(),
                }],
            )
            .unwrap();
        let arguments = HashMap::from([(
            "transaction_id".to_string(),
            serde_json::json!(transaction.transaction_id),
        )]);
        (transaction.transaction_id, arguments)
    }

    fn result_text(result: &kin_mcp::ToolCallResult) -> &str {
        match result
            .content
            .first()
            .expect("tool result must have content")
        {
            kin_mcp::ContentBlock::Text { text } => text,
        }
    }

    #[test]
    fn payload_less_target_body_update_commits_like_an_entity_payload() {
        // Staging accepts verb `update` with a `target` (entity name or id) and a
        // `body`, and no entity payload. The planner has to accept the same
        // shape, or the operation is admitted at stage time and refused at
        // commit. The target resolves against repository authority, so the span
        // spliced is the one authority records, not one the caller supplied.
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();
        let operation = kin_mcp::McpMutationOperation {
            verb: "update".to_string(),
            // The entity's name, not its id: an agent knows the name and the new
            // source text but not Kin's entity structs.
            target: "value".to_string(),
            payload: None,
            body: Some("pub fn value() -> u8 { 2 }".to_string()),
            description: "payload-less body update".to_string(),
        };
        kin_mcp::session::validate_staged_operations(std::slice::from_ref(&operation))
            .expect("staging must accept the payload-less target body form");
        sessions
            .stage_transaction(&transaction.transaction_id, vec![operation])
            .unwrap();

        let result = commit_exact_transaction(
            &state,
            &sessions,
            &HashMap::from([(
                "transaction_id".to_string(),
                serde_json::json!(transaction.transaction_id),
            )]),
            None,
        );
        assert_ne!(
            result.is_error,
            Some(true),
            "payload-less target body commit failed: {}",
            result_text(&result)
        );

        let expected = b"pub fn value() -> u8 { 2 }\n";
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            expected
        );
        let after = load_native_commit_base(&state.layout).unwrap();
        let artifact = after
            .tree
            .artifact_at_path(&RepoPath::from_utf8("src/lib.rs").unwrap())
            .unwrap();
        assert_eq!(
            load_native_source_blob(&state.layout, artifact.entry.blob_identity().unwrap())
                .unwrap(),
            expected
        );
        let reparsed = after.graph.get_entity(&entity.id).unwrap().unwrap();
        assert_ne!(
            reparsed.fingerprint, entity.fingerprint,
            "semantic fingerprint must come from reparsing the exact new bytes"
        );
    }

    /// Operations handed to the commit call itself must land exactly like
    /// staged ones.
    ///
    /// The tool advertises the inline array as the single-call convenience
    /// form, so a caller that uses it is entitled to the same durability as
    /// stage-then-commit. The failure this closes reported `status: committed`
    /// with `ops_applied: 1` while `modified_files` stayed empty and the body
    /// never reached the file: a success response for a change that never
    /// happened, which is the one outcome an agent cannot detect or recover
    /// from. Read-back is byte-exact against the working file, the repository
    /// CAS blob, and the reparsed entity.
    #[test]
    fn inline_operations_commit_persists_the_body_byte_exact() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();

        // The exact shape reported as lost: an entity payload plus a body,
        // passed on the commit call with no prior kin_transaction_stage.
        let arguments = HashMap::from([
            (
                "transaction_id".to_string(),
                serde_json::json!(transaction.transaction_id),
            ),
            (
                "operations".to_string(),
                serde_json::json!([{
                    "verb": "update",
                    "target": entity.id.to_string(),
                    "payload": {"Entity": entity},
                    "body": "pub fn value() -> u8 { 2 }",
                    "description": "inline entity body update",
                }]),
            ),
        ]);
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "inline operations commit failed: {}",
            result_text(&result)
        );

        let response: serde_json::Value = serde_json::from_str(result_text(&result)).unwrap();
        assert_eq!(response["status"], "committed");
        assert_eq!(response["ops_applied"], 1);
        assert_eq!(
            response["modified_files"],
            serde_json::json!(["src/lib.rs"]),
            "a committed inline body must name the file it changed: {}",
            result_text(&result)
        );

        let expected = b"pub fn value() -> u8 { 2 }\n";
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            expected,
            "inline body must reach the working file byte-exact"
        );
        let after = load_native_commit_base(&state.layout).unwrap();
        let artifact = after
            .tree
            .artifact_at_path(&RepoPath::from_utf8("src/lib.rs").unwrap())
            .unwrap();
        assert_eq!(
            load_native_source_blob(&state.layout, artifact.entry.blob_identity().unwrap())
                .unwrap(),
            expected,
            "inline body must reach repository CAS byte-exact"
        );
        let reparsed = after.graph.get_entity(&entity.id).unwrap().unwrap();
        assert_ne!(
            reparsed.fingerprint, entity.fingerprint,
            "inline body must be reparsed into graph truth"
        );
    }

    /// The payload-less inline form has to persist too.
    #[test]
    fn inline_payload_less_operations_commit_persists_the_body_byte_exact() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();

        let arguments = HashMap::from([
            (
                "transaction_id".to_string(),
                serde_json::json!(transaction.transaction_id),
            ),
            (
                "operations".to_string(),
                serde_json::json!([{
                    "verb": "update",
                    "target": "value",
                    "body": "pub fn value() -> u8 { 3 }",
                    "description": "inline payload-less body update",
                }]),
            ),
        ]);
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "inline payload-less commit failed: {}",
            result_text(&result)
        );

        let expected = b"pub fn value() -> u8 { 3 }\n";
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            expected
        );
        let after = load_native_commit_base(&state.layout).unwrap();
        let reparsed = after.graph.get_entity(&entity.id).unwrap().unwrap();
        assert_ne!(reparsed.fingerprint, entity.fingerprint);
    }

    /// An `operations` element carrying a key Kin does not model is refused
    /// before anything commits.
    ///
    /// A caller improvising the shape reaches for `content`, `source`, or
    /// `new_body` before it reaches for `body`. Serde ignores keys it does not
    /// know, so the misspelled body vanished and the operation was planned as
    /// if no body had been sent at all. Naming the unknown key is the whole
    /// difference between a caller fixing one word and a caller concluding
    /// that inline commits do not work.
    #[test]
    fn inline_operations_with_an_unmodelled_key_are_refused() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let before = load_native_commit_base(&state.layout).unwrap();
        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();

        let arguments = HashMap::from([
            (
                "transaction_id".to_string(),
                serde_json::json!(transaction.transaction_id),
            ),
            (
                "operations".to_string(),
                serde_json::json!([{
                    "verb": "update",
                    "target": entity.id.to_string(),
                    "content": "pub fn value() -> u8 { 2 }",
                    "description": "misspelled body key",
                }]),
            ),
        ]);
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_eq!(result.is_error, Some(true));
        assert!(
            result_text(&result).contains("content"),
            "the refusal must name the unknown key: {}",
            result_text(&result)
        );

        let after = load_native_commit_base(&state.layout).unwrap();
        assert_eq!(after.roots.generation, before.roots.generation);
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            b"pub fn value() -> u8 { 1 }\n"
        );
    }

    /// Re-sending an inline commit after its fence is a resume, not a restage.
    ///
    /// `kin_transaction_commit` documents itself as idempotent on re-entry: the
    /// fenced payload resumes and the call reports whether it landed. Inline
    /// callers were excluded from that contract, because the resume tried to
    /// stage the same array onto a transaction no longer in `active` and died
    /// on the staging error instead of resolving the commit. The identical
    /// array now resumes; a different one is refused rather than appended to a
    /// payload already fenced under a different digest.
    #[test]
    fn re_sent_inline_operations_resume_a_fenced_commit() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();
        let operations = serde_json::json!([{
            "verb": "update",
            "target": entity.id.to_string(),
            "body": "pub fn value() -> u8 { 2 }",
            "description": "inline body update",
        }]);
        let arguments = HashMap::from([
            (
                "transaction_id".to_string(),
                serde_json::json!(transaction.transaction_id),
            ),
            ("operations".to_string(), operations.clone()),
        ]);

        // Fail after the repository receipt exists, so the transaction is left
        // fenced exactly as a crashed publication would leave it.
        state
            .mcp_fail_after_authority_once
            .store(true, Ordering::SeqCst);
        let crashed = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_eq!(crashed.is_error, Some(true));
        assert_eq!(
            sessions
                .get_transaction(&transaction.transaction_id)
                .unwrap()
                .state,
            "committing"
        );

        let resumed = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            resumed.is_error,
            Some(true),
            "re-sending the same inline array must resume the fenced commit: {}",
            result_text(&resumed)
        );
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            b"pub fn value() -> u8 { 2 }\n"
        );
    }

    /// A fenced transaction must not absorb a different inline payload.
    #[test]
    fn divergent_inline_operations_cannot_edit_a_fenced_commit() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();
        let arguments = |body: &str| {
            HashMap::from([
                (
                    "transaction_id".to_string(),
                    serde_json::json!(transaction.transaction_id),
                ),
                (
                    "operations".to_string(),
                    serde_json::json!([{
                        "verb": "update",
                        "target": entity.id.to_string(),
                        "body": body,
                        "description": "inline body update",
                    }]),
                ),
            ])
        };

        state
            .mcp_fail_after_authority_once
            .store(true, Ordering::SeqCst);
        let crashed = commit_exact_transaction(
            &state,
            &sessions,
            &arguments("pub fn value() -> u8 { 2 }"),
            None,
        );
        assert_eq!(crashed.is_error, Some(true));

        let diverged = commit_exact_transaction(
            &state,
            &sessions,
            &arguments("pub fn value() -> u8 { 9 }"),
            None,
        );
        assert_eq!(diverged.is_error, Some(true));
        assert!(
            result_text(&diverged).contains("differ from the operations already fenced"),
            "a divergent resume must say so: {}",
            result_text(&diverged)
        );
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            b"pub fn value() -> u8 { 2 }\n",
            "the fenced body, not the divergent one, is what authority holds"
        );
    }

    /// A live agent session, the way `kin_session_start` registers one.
    fn start_agent_session(
        sessions: &kin_mcp::SessionRegistry,
        vendor: &str,
        client_name: &str,
    ) -> kin_model::session::AgentSession {
        sessions.start_agent_session(
            vendor,
            client_name,
            kin_model::session::SessionTransport::Mcp,
            None,
            PathBuf::from("/tmp"),
            kin_model::session::SessionCapabilities {
                can_write: true,
                can_commit: true,
                ..kin_model::session::SessionCapabilities::default()
            },
        )
    }

    fn commit_one_entity_edit(
        state: &Arc<DaemonState>,
        sessions: &kin_mcp::SessionRegistry,
        session_id: &str,
        entity: &Entity,
        body: &str,
    ) -> kin_mcp::ToolCallResult {
        let transaction = sessions
            .begin_transaction(session_id, "file:src/lib.rs")
            .unwrap();
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![kin_mcp::McpMutationOperation {
                    verb: "update".to_string(),
                    target: entity.id.to_string(),
                    payload: None,
                    body: Some(body.to_string()),
                    description: "attributed body update".to_string(),
                }],
            )
            .unwrap();
        commit_exact_transaction(
            state,
            sessions,
            &HashMap::from([(
                "transaction_id".to_string(),
                serde_json::json!(transaction.transaction_id),
            )]),
            None,
        )
    }

    /// An agent's commit has to be attributable afterwards, by name.
    ///
    /// The pitch is that the graph knows who changed what, and an MCP write
    /// used to leave nothing any read surface could answer that with: the audit
    /// trail was empty, no actor existed, and the only identity anywhere was a
    /// session id that lived in the live response and nowhere else. Sealing the
    /// change later with `kin commit` then attributed the operator who ran the
    /// CLI, not the agent that wrote the code. This asserts every surface an
    /// operator would actually reach for.
    #[test]
    fn a_committed_transaction_is_attributable_to_the_agent_that_made_it() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let sessions = kin_mcp::SessionRegistry::new();
        let session = start_agent_session(&sessions, "claude-code", "one-change-demo");
        let session_id = session.session_id.to_string();

        let result = commit_one_entity_edit(
            &state,
            &sessions,
            &session_id,
            &entity,
            "pub fn value() -> u8 { 2 }",
        );
        assert_ne!(
            result.is_error,
            Some(true),
            "attributed commit failed: {}",
            result_text(&result)
        );

        // kin history: the agent's name, not an opaque id and not the operator.
        let binding = state.local_repository_authority_binding().unwrap();
        let history = kin_cli::commands::history::execute_history_request(
            &binding,
            state.graph.as_ref(),
            &kin_cli::commands::history::HistoryRequest {
                entity: "value".to_string(),
                reference: None,
            },
        )
        .unwrap();
        // `kin history` sizes its author column to the widest author it is
        // rendering, so a 27-character agent identity arrives whole. Asserted on
        // the rendered line rather than on a prefix, so a column that started
        // cutting the client name again would fail here: the client name is the
        // half that tells two sessions of one vendor apart, and it is the half a
        // fixed column removed.
        assert!(
            history
                .lines
                .iter()
                .any(|line| line.contains("claude-code/one-change-demo")),
            "history must name the committing agent in full: {:#?}",
            history.lines
        );
        assert!(
            !history.lines.iter().any(|line| line.contains('\u{2026}')),
            "no identity may be ellipsized: {:#?}",
            history.lines
        );

        // kin blame: the full author, so the session id is recoverable from a
        // read surface after the session itself is gone.
        let blame = kin_cli::commands::blame::execute_blame_request(
            &binding,
            state.graph.as_ref(),
            &kin_cli::commands::blame::BlameRequest {
                entity: "value".to_string(),
                reference: None,
            },
        )
        .unwrap();
        assert!(
            blame
                .lines
                .iter()
                .any(|line| line.contains(&format!("mcp-agent:{session_id}"))),
            "blame must carry the committing session id: {:#?}",
            blame.lines
        );

        // kin_provenance_query: change count, latest change, and audit context.
        let provenance = kin_mcp::handlers::provenance::handle_provenance_query(
            &HashMap::from([(
                "entity_id".to_string(),
                serde_json::json!(entity.id.to_string()),
            )]),
            state.graph.as_ref(),
        )
        .unwrap();
        let provenance: serde_json::Value = serde_json::from_str(result_text(&provenance)).unwrap();
        assert!(
            provenance["change_count"].as_u64().unwrap() >= 1,
            "provenance must count the MCP change: {provenance}"
        );
        assert!(!provenance["latest_change"].is_null());
        let events = provenance["recent_audit_events"].as_array().unwrap();
        assert_eq!(
            events.len(),
            1,
            "one commit of one entity is one attribution record: {provenance}"
        );
        assert_eq!(events[0]["action"], "kin_transaction_commit");
        let details: serde_json::Value =
            serde_json::from_str(events[0]["details"].as_str().unwrap()).unwrap();
        assert_eq!(details["session_id"], session_id);
        assert_eq!(details["actor"], "claude-code/one-change-demo");

        // The actor the audit event names resolves, and resolves as an agent:
        // this is what kin-review's impact analysis reads to decide an agent
        // change went in unreviewed.
        let actor_id = mcp_actor_id(&session_id);
        let actor = state.graph.get_actor(&actor_id).unwrap().unwrap();
        assert_eq!(actor.kind, ActorKind::Assistant);
        assert_eq!(actor.display_name, "claude-code/one-change-demo");
        assert_eq!(
            state
                .graph
                .query_audit_events(Some(&actor_id), 16)
                .unwrap()
                .len(),
            1,
            "the audit trail must be queryable by the agent that wrote it"
        );
    }

    /// Asking who touched one entity must not answer with another entity's writer.
    ///
    /// Every field of the provenance response is keyed to the entity asked
    /// about, so an audit list filled from the repository's most recent activity
    /// reads as that entity's history. Before anything wrote audit events the
    /// list was always empty and the omission was invisible; once commits record
    /// attribution it becomes a confident wrong answer. Two entities, two
    /// sessions, and the later commit is the unrelated one, so an unfiltered
    /// list would put the wrong agent at the top.
    #[test]
    fn provenance_answers_for_the_entity_asked_about_not_the_latest_commit() {
        let (_dir, state) = test_state();
        let (subject, _) = install_exact_source(
            &state,
            "src/subject.rs",
            b"pub fn subject() -> u8 { 1 }\n",
            "subject",
        );
        let (unrelated, _) = install_exact_source(
            &state,
            "src/unrelated.rs",
            b"pub fn unrelated() -> u8 { 1 }\n",
            "unrelated",
        );
        let sessions = kin_mcp::SessionRegistry::new();

        let author = start_agent_session(&sessions, "claude-code", "feature-work");
        let result = commit_one_entity_edit(
            &state,
            &sessions,
            &author.session_id.to_string(),
            &subject,
            "pub fn subject() -> u8 { 2 }",
        );
        assert_ne!(
            result.is_error,
            Some(true),
            "subject commit failed: {}",
            result_text(&result)
        );

        // A different session commits something else, afterwards, so it owns
        // the most recent audit rows.
        let other = start_agent_session(&sessions, "codex", "cleanup");
        let result = commit_one_entity_edit(
            &state,
            &sessions,
            &other.session_id.to_string(),
            &unrelated,
            "pub fn unrelated() -> u8 { 2 }",
        );
        assert_ne!(
            result.is_error,
            Some(true),
            "unrelated commit failed: {}",
            result_text(&result)
        );

        let provenance = kin_mcp::handlers::provenance::handle_provenance_query(
            &HashMap::from([(
                "entity_id".to_string(),
                serde_json::json!(subject.id.to_string()),
            )]),
            state.graph.as_ref(),
        )
        .unwrap();
        let provenance: serde_json::Value = serde_json::from_str(result_text(&provenance)).unwrap();
        let events = provenance["recent_audit_events"].as_array().unwrap();
        assert_eq!(
            events.len(),
            1,
            "only the subject's own write belongs in its provenance: {provenance}"
        );
        assert_eq!(
            events[0]["target_scope"]["Entity"],
            serde_json::json!(subject.id.to_string()),
            "the surviving event must name the entity that was asked about"
        );
        let details: serde_json::Value =
            serde_json::from_str(events[0]["details"].as_str().unwrap()).unwrap();
        assert_eq!(
            details["actor"], "claude-code/feature-work",
            "the answer must be the agent that wrote this entity, not the last agent to write anything"
        );

        // And the same query for the other entity answers with the other agent,
        // so the filter narrows rather than simply returning the first event.
        let other_provenance = kin_mcp::handlers::provenance::handle_provenance_query(
            &HashMap::from([(
                "entity_id".to_string(),
                serde_json::json!(unrelated.id.to_string()),
            )]),
            state.graph.as_ref(),
        )
        .unwrap();
        let other_provenance: serde_json::Value =
            serde_json::from_str(result_text(&other_provenance)).unwrap();
        let other_events = other_provenance["recent_audit_events"].as_array().unwrap();
        assert_eq!(other_events.len(), 1);
        let other_details: serde_json::Value =
            serde_json::from_str(other_events[0]["details"].as_str().unwrap()).unwrap();
        assert_eq!(other_details["actor"], "codex/cleanup");
    }

    /// A payload field the commit cannot honor is refused, not dropped.
    ///
    /// The commit publishes what reparsing the new bytes derives, so a
    /// doc summary the caller edited by hand never lands. Committing the body
    /// and discarding that edit reports `ops_applied: 1` for an operation only
    /// half of which happened, which is the same defect this PR closes on the
    /// other path, in the other half of the operation.
    #[test]
    fn an_edited_payload_field_the_commit_cannot_honor_is_refused() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let before = load_native_commit_base(&state.layout).unwrap();
        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();

        let mut edited = entity.clone();
        edited.doc_summary = Some("returns the configured value".to_string());
        let arguments = HashMap::from([
            (
                "transaction_id".to_string(),
                serde_json::json!(transaction.transaction_id),
            ),
            (
                "operations".to_string(),
                serde_json::json!([{
                    "verb": "update",
                    "target": entity.id.to_string(),
                    "payload": {"Entity": edited},
                    "body": "pub fn value() -> u8 { 2 }",
                    "description": "body edit plus a hand-edited doc summary",
                }]),
            ),
        ]);
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_eq!(
            result.is_error,
            Some(true),
            "a metadata edit that cannot land must be refused: {}",
            result_text(&result)
        );
        assert!(
            result_text(&result).contains("doc summary"),
            "the refusal must name the field it could not honor: {}",
            result_text(&result)
        );

        let after = load_native_commit_base(&state.layout).unwrap();
        assert_eq!(
            after.roots.generation, before.roots.generation,
            "the body must not land on its own while the metadata half is refused"
        );
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            b"pub fn value() -> u8 { 1 }\n"
        );
    }

    /// The payload an agent actually builds is what `get_entity` handed it,
    /// decoded from the wire, and it has to commit.
    ///
    /// This is the shape the product uses: call `get_entity`, take the returned
    /// object whole, add a `body`, commit. It is not the same as echoing the
    /// in-memory struct, because `entity_response_json` injects response-only keys
    /// at top level (read_path, start_line, end_line, source_excerpt, source_state,
    /// span_coherence, artifact_id, artifact_path, artifact_entry, source, plus
    /// either source_change_id for committed bytes or workspace_tree_hash /
    /// workspace_generation / base_change_id for uncommitted ones) and `Entity`
    /// does not deny unknown fields.
    ///
    /// What this pins is that the round trip is faithful: those keys are
    /// discarded on the way back in and land nowhere, so an echoed payload
    /// equals what authority holds. That is worth a test because it is not
    /// obvious. `EntityMetadata` is `#[serde(flatten)] extra: HashMap`, so it
    /// absorbs unknown keys found inside the `metadata` object; `Entity.metadata`
    /// is a plain named field, so top-level decorations never reach it. Flip
    /// either of those and every field-by-field check the commit planner makes
    /// against authority starts refusing a caller that did nothing but echo.
    #[test]
    fn a_payload_decoded_from_a_real_get_entity_response_still_commits() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );

        // The exact bytes `get_entity` returns, then straight back in as the
        // payload, which is the round trip nothing else in the workspace walks.
        let binding = kin_mcp::handlers::RequestRepositoryAuthority::pinned(
            state.local_repository_authority_binding().unwrap(),
        );
        let response = kin_mcp::handlers::common::entity_response_json(
            state.graph.as_ref(),
            &entity,
            Some(&binding),
        )
        .expect("the read surface must render the entity");
        // `span_coherence` stands where `stale` used to: same role in this test, a
        // response-only key that must round-trip harmlessly. `stale` was removed
        // because nothing ever set it true, so it asserted a freshness the read had
        // not established; `span_coherence` reports what was actually checked.
        for injected in [
            "read_path",
            "start_line",
            "source_excerpt",
            "span_coherence",
        ] {
            assert!(
                response.get(injected).is_some(),
                "fixture must exercise a response carrying the injected key {injected}: {response}"
            );
        }
        let echoed: Entity = serde_json::from_value(response)
            .expect("a get_entity response must decode back into an Entity");
        assert_eq!(
            echoed.metadata, entity.metadata,
            "response-only keys must be discarded on decode, not folded into metadata"
        );
        assert_eq!(
            echoed.doc_summary, entity.doc_summary,
            "an echoed payload must carry the doc summary authority holds"
        );

        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();
        let arguments = HashMap::from([
            (
                "transaction_id".to_string(),
                serde_json::json!(transaction.transaction_id),
            ),
            (
                "operations".to_string(),
                serde_json::json!([{
                    "verb": "update",
                    "target": entity.id.to_string(),
                    "payload": {"Entity": echoed},
                    "body": "pub fn value() -> u8 { 2 }",
                    "description": "echo the read response back as the payload",
                }]),
            ),
        ]);
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "a payload echoed from a real get_entity response must commit: {}",
            result_text(&result)
        );
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            b"pub fn value() -> u8 { 2 }\n",
            "the body must land for the payload shape the product actually builds"
        );
    }

    /// An unchanged payload beside a body still commits.
    ///
    /// The refusal above is scoped to a field the caller edited. Echoing back
    /// the entity exactly as it was read is the documented shape and must keep
    /// working.
    #[test]
    fn an_unedited_payload_beside_a_body_still_commits() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let sessions = test_sessions();
        let (_tx, arguments) = stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "an unedited payload must still commit: {}",
            result_text(&result)
        );
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            b"pub fn value() -> u8 { 2 }\n"
        );
    }

    /// Two commits by one session are two records by one actor.
    #[test]
    fn one_agent_session_keeps_one_actor_identity_across_commits() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let sessions = kin_mcp::SessionRegistry::new();
        let session = start_agent_session(&sessions, "codex", "repeat-writer");
        let session_id = session.session_id.to_string();

        for body in ["pub fn value() -> u8 { 2 }", "pub fn value() -> u8 { 3 }"] {
            let result = commit_one_entity_edit(&state, &sessions, &session_id, &entity, body);
            assert_ne!(
                result.is_error,
                Some(true),
                "commit failed: {}",
                result_text(&result)
            );
        }

        let actor_id = mcp_actor_id(&session_id);
        assert_eq!(
            state.graph.list_actors().unwrap().len(),
            1,
            "a session is one actor, not one per commit"
        );
        assert_eq!(
            state
                .graph
                .query_audit_events(Some(&actor_id), 16)
                .unwrap()
                .len(),
            2,
            "each commit contributes its own attribution record"
        );
    }

    /// A resumed commit must not double-count itself in the audit trail.
    ///
    /// Attribution is written after the repository receipt exists, and the
    /// receipt path is re-entered on resume. A second record for one write
    /// would read as an agent that committed twice.
    #[test]
    fn a_resumed_commit_records_its_attribution_once() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let sessions = kin_mcp::SessionRegistry::new();
        let session = start_agent_session(&sessions, "claude-code", "resumed-writer");
        let session_id = session.session_id.to_string();
        let transaction = sessions
            .begin_transaction(&session_id, "file:src/lib.rs")
            .unwrap();
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![kin_mcp::McpMutationOperation {
                    verb: "update".to_string(),
                    target: entity.id.to_string(),
                    payload: None,
                    body: Some("pub fn value() -> u8 { 2 }".to_string()),
                    description: "attributed body update".to_string(),
                }],
            )
            .unwrap();
        let arguments = HashMap::from([(
            "transaction_id".to_string(),
            serde_json::json!(transaction.transaction_id),
        )]);

        state
            .mcp_fail_after_authority_once
            .store(true, Ordering::SeqCst);
        let crashed = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_eq!(crashed.is_error, Some(true));

        let resumed = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            resumed.is_error,
            Some(true),
            "resume failed: {}",
            result_text(&resumed)
        );

        assert_eq!(
            state
                .graph
                .query_audit_events(Some(&mcp_actor_id(&session_id)), 16)
                .unwrap()
                .len(),
            1,
            "one write is one attribution record, however many attempts it took"
        );
    }

    /// A relation-only commit must be answerable through the surface an
    /// operator actually asks.
    ///
    /// Attribution keyed only to changed entities would leave a relation-only
    /// transaction out of the audit trail entirely. Scoping it to the change
    /// instead was no better in practice: every reader that answers "who touched
    /// this entity" selects changes by scanning entity deltas, and a
    /// relation-only change has none, so the record existed and no query could
    /// reach it. Asserted through `kin_provenance_query` rather than through
    /// `query_audit_events`, because querying the store directly is exactly what
    /// hid the gap.
    #[test]
    fn a_relation_only_commit_is_attributed_to_the_entities_it_joined() {
        let (_dir, state) = test_state();
        let (caller, _) = install_exact_source(
            &state,
            "src/caller.rs",
            b"pub fn caller() -> u8 { 1 }\n",
            "caller",
        );
        let (callee, _) = install_exact_source(
            &state,
            "src/callee.rs",
            b"pub fn callee() -> u8 { 2 }\n",
            "callee",
        );
        let sessions = kin_mcp::SessionRegistry::new();
        let session = start_agent_session(&sessions, "gemini-cli", "relation-writer");
        let session_id = session.session_id.to_string();
        let transaction = sessions
            .begin_transaction(&session_id, "relations")
            .unwrap();
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![kin_mcp::McpMutationOperation {
                    verb: "create".to_string(),
                    target: String::new(),
                    payload: Some(kin_mcp::McpMutationPayload::Relation {
                        from: caller.id,
                        to: callee.id,
                        kind: kin_model::relation::RelationKind::Calls,
                    }),
                    body: None,
                    description: "link the call".to_string(),
                }],
            )
            .unwrap();

        let result = commit_exact_transaction(
            &state,
            &sessions,
            &HashMap::from([(
                "transaction_id".to_string(),
                serde_json::json!(transaction.transaction_id),
            )]),
            None,
        );
        assert_ne!(
            result.is_error,
            Some(true),
            "relation-only commit failed: {}",
            result_text(&result)
        );

        let events = state
            .graph
            .query_audit_events(Some(&mcp_actor_id(&session_id)), 16)
            .unwrap();
        assert_eq!(
            events.len(),
            2,
            "a relation-only commit is attributed to both endpoints it joined"
        );
        let mut scoped = events
            .iter()
            .filter_map(|event| match event.target_scope {
                Some(WorkScope::Entity(id)) => Some(id),
                _ => None,
            })
            .collect::<Vec<_>>();
        scoped.sort_unstable();
        let mut expected = vec![caller.id, callee.id];
        expected.sort_unstable();
        assert_eq!(scoped, expected, "both endpoints must be named");

        // The surface that matters: asking about either endpoint returns the
        // agent that created the relation.
        for endpoint in [&caller, &callee] {
            let provenance = kin_mcp::handlers::provenance::handle_provenance_query(
                &HashMap::from([(
                    "entity_id".to_string(),
                    serde_json::json!(endpoint.id.to_string()),
                )]),
                state.graph.as_ref(),
            )
            .unwrap();
            let provenance: serde_json::Value =
                serde_json::from_str(result_text(&provenance)).unwrap();
            let events = provenance["recent_audit_events"].as_array().unwrap();
            assert_eq!(
                events.len(),
                1,
                "provenance for {} must reach the relation write: {provenance}",
                endpoint.name
            );
            let details: serde_json::Value =
                serde_json::from_str(events[0]["details"].as_str().unwrap()).unwrap();
            assert_eq!(details["actor"], "gemini-cli/relation-writer");
        }
    }

    fn entity_span_by_name(state: &Arc<DaemonState>, name: &str) -> kin_model::SourceSpan {
        state
            .graph
            .query_entities(&EntityFilter {
                name_pattern: Some(name.to_string()),
                ..EntityFilter::default()
            })
            .unwrap()
            .into_iter()
            .find(|entity| entity.name == name)
            .unwrap_or_else(|| panic!("graph must contain {name}"))
            .span
            .unwrap_or_else(|| panic!("{name} must carry a source span"))
    }

    /// A commit moves the positions of entities it did not edit.
    ///
    /// An edit that makes one entity taller pushes everything below it down. If
    /// the graph keeps the pre-commit position for those neighbours, then a
    /// graph-native read after a graph-native write hands back line anchors that
    /// no longer describe the file, and an agent deriving anything from them
    /// derives it wrong. Positions have to move with the bytes or not be served
    /// at all.
    ///
    /// Asserted against the file rather than against a constant, and accepting
    /// either line-numbering base, so this measures freshness only. Which base
    /// `start_line` counts from is a separate question about the read boundary
    /// and is not what this test pins.
    #[test]
    fn a_commit_repositions_the_entities_it_pushed_down() {
        let (_dir, state) = test_state();
        let (first, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn first() -> u8 { 1 }\n\npub fn second() -> u8 { 2 }\n",
            "first",
        );
        let before = entity_span_by_name(&state, "second");

        // Two lines taller than what it replaces.
        let sessions = test_sessions();
        let (_tx, arguments) =
            stage_entity_edit(&sessions, &first, "pub fn first() -> u8 {\n    1\n}");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "commit failed: {}",
            result_text(&result)
        );

        let after = entity_span_by_name(&state, "second");
        assert_eq!(
            after.start_line - before.start_line,
            2,
            "an untouched neighbour must move by exactly the lines inserted above it"
        );

        let file = std::fs::read_to_string(state.layout.working_dir().join("src/lib.rs")).unwrap();
        let lines = file.lines().collect::<Vec<_>>();
        let named = |index: u32| {
            usize::try_from(index)
                .ok()
                .and_then(|index| lines.get(index))
                .is_some_and(|line| line.contains("fn second"))
        };
        assert!(
            named(after.start_line) || named(after.start_line.saturating_sub(1)),
            "start_line {} does not land on 'fn second' under either base:\n{file}",
            after.start_line
        );
        assert!(
            file[after.start_byte..].starts_with("pub fn second"),
            "start_byte {} must index the post-commit bytes of the entity it names",
            after.start_byte
        );
    }

    /// A session with no registration still commits under an identity.
    #[test]
    fn a_session_without_an_agent_registration_still_names_an_author() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let sessions = test_sessions();
        let (_tx, arguments) = stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(result.is_error, Some(true), "{}", result_text(&result));

        let binding = state.local_repository_authority_binding().unwrap();
        let history = kin_cli::commands::history::execute_history_request(
            &binding,
            state.graph.as_ref(),
            &kin_cli::commands::history::HistoryRequest {
                entity: "value".to_string(),
                reference: None,
            },
        )
        .unwrap();
        assert!(
            history.lines.iter().any(|line| line.contains(TEST_SESSION)),
            "an unregistered session still commits under the id it used: {:#?}",
            history.lines
        );
        assert_eq!(
            state
                .graph
                .query_audit_events(Some(&mcp_actor_id(TEST_SESSION)), 16)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn unresolvable_target_body_update_fails_before_repository_mutation() {
        let (_dir, state) = test_state();
        install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let before = load_native_commit_base(&state.layout).unwrap();
        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![kin_mcp::McpMutationOperation {
                    verb: "update".to_string(),
                    target: "no_such_entity".to_string(),
                    payload: None,
                    body: Some("pub fn no_such_entity() {}".to_string()),
                    description: String::new(),
                }],
            )
            .unwrap();

        let result = commit_exact_transaction(
            &state,
            &sessions,
            &HashMap::from([(
                "transaction_id".to_string(),
                serde_json::json!(transaction.transaction_id),
            )]),
            None,
        );
        assert_eq!(result.is_error, Some(true));
        assert!(
            result_text(&result).contains("not found in the graph"),
            "unresolvable target must say so: {}",
            result_text(&result)
        );
        let after = load_native_commit_base(&state.layout).unwrap();
        assert_eq!(after.roots.generation, before.roots.generation);
        assert_eq!(
            sessions
                .get_transaction(&transaction.transaction_id)
                .unwrap()
                .state,
            "active"
        );
    }

    /// A commit that fails while planning must leave the transaction usable.
    ///
    /// The failure mode this closes: the failed operations stayed staged, so
    /// staging a corrected operation appended to them and the next commit
    /// re-planned the original failure and returned the identical error
    /// forever. The transaction was wedged with no way out that any error
    /// message described.
    #[test]
    fn a_failed_commit_unstages_its_operations_so_a_corrected_retry_works() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let before = load_native_commit_base(&state.layout).unwrap();
        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();
        let arguments = HashMap::from([(
            "transaction_id".to_string(),
            serde_json::json!(transaction.transaction_id),
        )]);

        // One bad target alongside correct work: the clear takes both, so the
        // refusal has to name both or the caller cannot reconstruct what it
        // lost.
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: entity.id.to_string(),
                        payload: None,
                        body: Some("pub fn value() -> u8 { 3 }".to_string()),
                        description: "correct work staged alongside the failure".to_string(),
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: "no_such_entity".to_string(),
                        payload: None,
                        body: Some("pub fn no_such_entity() {}".to_string()),
                        description: String::new(),
                    },
                ],
            )
            .unwrap();

        let failed = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_eq!(failed.is_error, Some(true));
        let message = result_text(&failed);
        assert!(
            message.contains("not found in the graph"),
            "the refusal keeps naming the real problem: {message}"
        );
        assert!(
            message.contains("have been cleared from transaction"),
            "the refusal must say the failed operations were dropped: {message}"
        );
        let dropped = message
            .split_once("dropped: ")
            .expect("the refusal must list what it dropped")
            .1;
        assert!(
            dropped.contains("update no_such_entity"),
            "the refusal must name the operation that failed: {message}"
        );
        assert!(
            dropped.contains(&format!("update {}", entity.id)),
            "the refusal must name the correct work it dropped too: {message}"
        );
        assert!(
            sessions
                .get_transaction(&transaction.transaction_id)
                .unwrap()
                .staged_operations
                .is_empty(),
            "a pre-authority failure must not leave its operations staged"
        );

        // The corrected operation, staged on the SAME transaction, commits.
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![kin_mcp::McpMutationOperation {
                    verb: "update".to_string(),
                    target: entity.id.to_string(),
                    payload: None,
                    body: Some("pub fn value() -> u8 { 2 }".to_string()),
                    description: "corrected retry".to_string(),
                }],
            )
            .unwrap();
        let committed = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            committed.is_error,
            Some(true),
            "the corrected retry must commit: {}",
            result_text(&committed)
        );

        let after = load_native_commit_base(&state.layout).unwrap();
        assert!(after.roots.generation > before.roots.generation);
        let artifact = after
            .tree
            .artifact_at_path(&RepoPath::from_utf8("src/lib.rs").unwrap())
            .unwrap();
        assert_eq!(
            load_native_source_blob(&state.layout, artifact.entry.blob_identity().unwrap())
                .unwrap(),
            b"pub fn value() -> u8 { 2 }\n"
        );
    }

    /// An ambiguous bare name must hand back the candidates it could not choose
    /// between, and the corrected id must commit on the transaction the caller
    /// already holds.
    ///
    /// Without the candidate list the advice ("use the entity id") names an id
    /// the caller has no way to learn, and without the clear the corrected retry
    /// re-plans the same ambiguity forever. Both halves are needed for an
    /// unscripted agent to recover in-session.
    #[test]
    fn ambiguous_name_target_lists_candidates_and_the_id_retry_commits() {
        let (_dir, state) = test_state();
        let (left, _) = install_exact_source(
            &state,
            "src/left.rs",
            b"pub fn shared() -> u8 { 1 }\n",
            "shared",
        );
        let (right, _) = install_exact_source(
            &state,
            "src/right.rs",
            b"pub fn shared() -> u8 { 10 }\n",
            "shared",
        );
        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "entity:shared")
            .unwrap();
        let arguments = HashMap::from([(
            "transaction_id".to_string(),
            serde_json::json!(transaction.transaction_id),
        )]);
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![kin_mcp::McpMutationOperation {
                    verb: "update".to_string(),
                    target: "shared".to_string(),
                    payload: None,
                    body: Some("pub fn shared() -> u8 { 2 }".to_string()),
                    description: "bare name an agent would reach for first".to_string(),
                }],
            )
            .unwrap();

        let ambiguous = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_eq!(ambiguous.is_error, Some(true));
        let message = result_text(&ambiguous);
        assert!(
            message.contains("is ambiguous (2 exact-name matches)"),
            "the refusal must say what was ambiguous: {message}"
        );
        for candidate in [&left, &right] {
            assert!(
                message.contains(&candidate.id.to_string()),
                "candidate id {} must be listed: {message}",
                candidate.id
            );
        }
        for path in ["src/left.rs", "src/right.rs"] {
            assert!(
                message.contains(path),
                "candidate file path {path} must be listed: {message}"
            );
        }
        assert!(
            message.contains("pub fn shared() -> u8"),
            "each candidate must carry its declaration so the caller can tell them apart: {message}"
        );

        // The id the refusal named, staged on the SAME transaction, commits.
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![kin_mcp::McpMutationOperation {
                    verb: "update".to_string(),
                    target: left.id.to_string(),
                    payload: None,
                    body: Some("pub fn shared() -> u8 { 2 }".to_string()),
                    description: "corrected id retry".to_string(),
                }],
            )
            .unwrap();
        let committed = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            committed.is_error,
            Some(true),
            "the id retry must commit on the same transaction: {}",
            result_text(&committed)
        );
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/left.rs")).unwrap(),
            b"pub fn shared() -> u8 { 2 }\n"
        );
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/right.rs")).unwrap(),
            b"pub fn shared() -> u8 { 10 }\n"
        );
    }

    /// A nested entity submitted exactly as the file renders it lands at its own
    /// indentation, not at twice it.
    ///
    /// An entity span opens at the entity's first token, so an impl method's
    /// four spaces sit in the file ahead of the span while the rest of its body
    /// carries indentation inside it. Splicing the caller's body verbatim put
    /// its copy of line 1's indentation after the file's: the method compiled at
    /// eight spaces and failed `cargo fmt`. Byte-exactness is the promise, so
    /// this asserts the whole file byte-for-byte, for an impl method and a
    /// module-nested function committed together, against a top-level function
    /// that has no indentation to double.
    #[test]
    fn nested_entity_bodies_commit_at_their_own_indentation() {
        let (_dir, state) = test_state();
        let impl_source =
            b"pub struct Builder;\n\nimpl Builder {\n    pub fn set(&mut self) -> u8 {\n        1\n    }\n}\n";
        let (method, _) =
            install_exact_source(&state, "src/builder.rs", impl_source, "Builder::set");
        let module_source = b"pub mod inner {\n    pub fn nested() -> u8 {\n        1\n    }\n}\n";
        let (nested, _) = install_exact_source(&state, "src/nested.rs", module_source, "nested");
        let (top_level, _) = install_exact_source(
            &state,
            "src/plain.rs",
            b"pub fn plain() -> u8 {\n    1\n}\n",
            "plain",
        );

        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "entity:set")
            .unwrap();
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![
                    // Each body is the entity exactly as the file renders it,
                    // leading indentation included: what an agent writes back
                    // after reading the source.
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: method.id.to_string(),
                        payload: None,
                        body: Some(
                            "    pub fn set(&mut self) -> u8 {\n        2\n    }".to_string(),
                        ),
                        description: "impl-nested method".to_string(),
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: nested.id.to_string(),
                        payload: None,
                        body: Some("    pub fn nested() -> u8 {\n        2\n    }".to_string()),
                        description: "module-nested function".to_string(),
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: top_level.id.to_string(),
                        payload: None,
                        body: Some("pub fn plain() -> u8 {\n    2\n}".to_string()),
                        description: "top-level function".to_string(),
                    },
                ],
            )
            .unwrap();

        let result = commit_exact_transaction(
            &state,
            &sessions,
            &HashMap::from([(
                "transaction_id".to_string(),
                serde_json::json!(transaction.transaction_id),
            )]),
            None,
        );
        assert_ne!(
            result.is_error,
            Some(true),
            "nested body commit failed: {}",
            result_text(&result)
        );

        for (file, expected) in [
            (
                "src/builder.rs",
                b"pub struct Builder;\n\nimpl Builder {\n    pub fn set(&mut self) -> u8 {\n        2\n    }\n}\n".to_vec(),
            ),
            (
                "src/nested.rs",
                b"pub mod inner {\n    pub fn nested() -> u8 {\n        2\n    }\n}\n".to_vec(),
            ),
            ("src/plain.rs", b"pub fn plain() -> u8 {\n    2\n}\n".to_vec()),
        ] {
            assert_eq!(
                std::fs::read(state.layout.working_dir().join(file)).unwrap(),
                expected,
                "{file} is not byte-identical to the intended source"
            );
            let after = load_native_commit_base(&state.layout).unwrap();
            let artifact = after
                .tree
                .artifact_at_path(&RepoPath::from_utf8(file).unwrap())
                .unwrap();
            assert_eq!(
                load_native_source_blob(&state.layout, artifact.entry.blob_identity().unwrap())
                    .unwrap(),
                expected,
                "{file} repository authority is not byte-identical either"
            );
        }
    }

    /// The exact bytes the read surface serves are the span slice, with no
    /// leading indentation on line 1. Submitting those back unchanged has to
    /// keep committing, or the indentation fix traded one break for another.
    #[test]
    fn span_slice_body_for_a_nested_entity_still_commits_exactly() {
        let (_dir, state) = test_state();
        let source =
            b"pub struct Builder;\n\nimpl Builder {\n    pub fn set(&mut self) -> u8 {\n        1\n    }\n}\n";
        let (method, _) = install_exact_source(&state, "src/builder.rs", source, "Builder::set");
        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "entity:set")
            .unwrap();
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![kin_mcp::McpMutationOperation {
                    verb: "update".to_string(),
                    target: method.id.to_string(),
                    payload: None,
                    // No leading indentation: the span slice, verbatim.
                    body: Some("pub fn set(&mut self) -> u8 {\n        2\n    }".to_string()),
                    description: "span-slice body".to_string(),
                }],
            )
            .unwrap();

        let result = commit_exact_transaction(
            &state,
            &sessions,
            &HashMap::from([(
                "transaction_id".to_string(),
                serde_json::json!(transaction.transaction_id),
            )]),
            None,
        );
        assert_ne!(
            result.is_error,
            Some(true),
            "span-slice body commit failed: {}",
            result_text(&result)
        );
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/builder.rs")).unwrap(),
            b"pub struct Builder;\n\nimpl Builder {\n    pub fn set(&mut self) -> u8 {\n        2\n    }\n}\n"
        );
    }

    /// The whole rehearsal, end to end: a three-file signature change staged on
    /// one transaction, surviving a deliberate mid-flight staging error, landing
    /// byte-identical.
    ///
    /// This is the shape an unscripted agent could not survive. It reaches for a
    /// bare name, the name is ambiguous, and before the fixes the refusal named
    /// an id it could not see while the failed operation stayed staged, so every
    /// later commit on that transaction re-failed identically. Then the bodies it
    /// wrote back carried the indentation the file showed it, and the nested ones
    /// landed at twice it.
    ///
    /// The assertion is the whole file, byte for byte, for all three files, plus
    /// `ops_applied` and the modified-file set from the commit receipt.
    #[test]
    fn three_file_signature_change_survives_a_mid_flight_staging_error() {
        let (_dir, state) = test_state();

        // The entity whose signature changes, plus a same-named `commands` that
        // makes the bare name ambiguous the way `hostname` was in the rehearsal.
        let cli_source = b"pub fn resolve_binary(prog: &str) -> String {\n    prog.to_string()\n}\n\npub mod compat {\n    pub fn commands() -> String {\n        String::new()\n    }\n}\n";
        let (resolve_binary, _) =
            install_exact_source(&state, "src/cli.rs", cli_source, "resolve_binary");
        // Caller one: an impl-nested method.
        let worker_source = b"pub struct Worker;\n\nimpl Worker {\n    pub fn preprocessor(&mut self) -> String {\n        crate::cli::resolve_binary(\"pre\")\n    }\n}\n";
        let (preprocessor, _) = install_exact_source(
            &state,
            "src/worker.rs",
            worker_source,
            "Worker::preprocessor",
        );
        // Caller two: a module-nested function.
        let defaults_source = b"pub mod defaults {\n    pub fn commands() -> String {\n        crate::cli::resolve_binary(\"cmd\")\n    }\n}\n";
        let (commands, _) =
            install_exact_source(&state, "src/defaults.rs", defaults_source, "commands");
        let before = load_native_commit_base(&state.layout).unwrap();

        const NEW_RESOLVE_BINARY: &str = "pub fn resolve_binary(prog: &str, search_dirs: Option<&[String]>) -> String {\n    let _ = search_dirs;\n    prog.to_string()\n}";
        // Both caller bodies carry the indentation their files render, because
        // that is what a caller reading the source writes back.
        const NEW_PREPROCESSOR: &str = "    pub fn preprocessor(&mut self) -> String {\n        crate::cli::resolve_binary(\"pre\", None)\n    }";
        const NEW_COMMANDS: &str = "    pub fn commands() -> String {\n        crate::cli::resolve_binary(\"cmd\", None)\n    }";

        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "entity:resolve_binary")
            .unwrap();
        let arguments = HashMap::from([(
            "transaction_id".to_string(),
            serde_json::json!(transaction.transaction_id),
        )]);

        // Attempt one: correct work alongside one bare name that cannot resolve.
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: resolve_binary.id.to_string(),
                        payload: None,
                        body: Some(NEW_RESOLVE_BINARY.to_string()),
                        description: "add the search_dirs parameter".to_string(),
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: preprocessor.id.to_string(),
                        payload: None,
                        body: Some(NEW_PREPROCESSOR.to_string()),
                        description: "pass None".to_string(),
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: "commands".to_string(),
                        payload: None,
                        body: Some(NEW_COMMANDS.to_string()),
                        description: "pass None, targeted by bare name".to_string(),
                    },
                ],
            )
            .unwrap();

        let refused = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_eq!(refused.is_error, Some(true));
        let message = result_text(&refused);
        assert!(
            message.contains(&commands.id.to_string()),
            "the refusal must name the id that resolves the ambiguity: {message}"
        );
        assert!(
            message.contains("src/defaults.rs") && message.contains("src/cli.rs"),
            "the refusal must locate every candidate: {message}"
        );
        assert!(
            sessions
                .get_transaction(&transaction.transaction_id)
                .unwrap()
                .staged_operations
                .is_empty(),
            "a refused attempt must leave the transaction editable"
        );
        assert_eq!(
            load_native_commit_base(&state.layout)
                .unwrap()
                .roots
                .generation,
            before.roots.generation,
            "a refused attempt must not move repository authority"
        );

        // Attempt two: the same transaction, every target an id.
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: resolve_binary.id.to_string(),
                        payload: None,
                        body: Some(NEW_RESOLVE_BINARY.to_string()),
                        description: "add the search_dirs parameter".to_string(),
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: preprocessor.id.to_string(),
                        payload: None,
                        body: Some(NEW_PREPROCESSOR.to_string()),
                        description: "pass None".to_string(),
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: commands.id.to_string(),
                        payload: None,
                        body: Some(NEW_COMMANDS.to_string()),
                        description: "pass None".to_string(),
                    },
                ],
            )
            .unwrap();
        let committed = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            committed.is_error,
            Some(true),
            "the corrected three-file change must commit on the same transaction: {}",
            result_text(&committed)
        );
        let receipt: serde_json::Value = serde_json::from_str(result_text(&committed)).unwrap();
        assert_eq!(receipt["ops_applied"], 3);
        assert_eq!(
            receipt["modified_files"],
            serde_json::json!(["src/cli.rs", "src/defaults.rs", "src/worker.rs"])
        );

        for (file, expected) in [
            (
                "src/cli.rs",
                "pub fn resolve_binary(prog: &str, search_dirs: Option<&[String]>) -> String {\n    let _ = search_dirs;\n    prog.to_string()\n}\n\npub mod compat {\n    pub fn commands() -> String {\n        String::new()\n    }\n}\n",
            ),
            (
                "src/worker.rs",
                "pub struct Worker;\n\nimpl Worker {\n    pub fn preprocessor(&mut self) -> String {\n        crate::cli::resolve_binary(\"pre\", None)\n    }\n}\n",
            ),
            (
                "src/defaults.rs",
                "pub mod defaults {\n    pub fn commands() -> String {\n        crate::cli::resolve_binary(\"cmd\", None)\n    }\n}\n",
            ),
        ] {
            assert_eq!(
                String::from_utf8(
                    std::fs::read(state.layout.working_dir().join(file)).unwrap()
                )
                .unwrap(),
                expected,
                "{file} is not byte-identical to the intended source"
            );
        }
    }

    /// Abandoning a transaction must leave the repository exactly as if it had
    /// never been begun.
    ///
    /// `kin_transaction_abort` sits in the default agent write profile and its
    /// description promises to discard the staged mutations, so what has to be
    /// asserted is not the state label but that repository authority and the
    /// working tree are untouched and the staged set is gone.
    #[test]
    fn aborting_a_staged_transaction_moves_neither_authority_nor_the_working_tree() {
        let (_dir, state) = test_state();
        let (value, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let before = load_native_commit_base(&state.layout).unwrap();
        let before_file = std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap();

        let sessions = test_sessions();
        let (transaction_id, _arguments) =
            stage_entity_edit(&sessions, &value, "pub fn value() -> u8 { 2 }");
        assert_eq!(
            sessions
                .get_transaction(&transaction_id)
                .unwrap()
                .staged_operations
                .len(),
            1
        );

        let aborted = sessions.abort_transaction(&transaction_id).unwrap();
        assert_eq!(aborted.state, "aborted");
        assert!(
            aborted.staged_operations.is_empty(),
            "abort must discard the staged mutations it says it discards"
        );
        assert_eq!(
            load_native_commit_base(&state.layout)
                .unwrap()
                .roots
                .generation,
            before.roots.generation,
            "an aborted transaction must not move repository authority"
        );
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            before_file,
            "an aborted transaction must not touch the working tree"
        );
        assert!(
            sessions
                .begin_transaction(TEST_SESSION, "file:src/lib.rs")
                .is_ok(),
            "the session must outlive the transaction it abandoned"
        );
    }

    /// The recovery an agent actually reaches for: a transaction whose commit
    /// was refused must still be abandonable.
    ///
    /// A refused pre-publication commit returns the transaction to `active`
    /// with its operations cleared. An agent that decides against the work
    /// rather than correcting it calls abort, so abort has to accept the state
    /// the failure path leaves behind and not only a pristine one.
    #[test]
    fn a_transaction_whose_commit_was_refused_can_still_be_aborted() {
        let (_dir, state) = test_state();
        let (value, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let before = load_native_commit_base(&state.layout).unwrap();
        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();
        let arguments = HashMap::from([(
            "transaction_id".to_string(),
            serde_json::json!(transaction.transaction_id),
        )]);

        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: value.id.to_string(),
                        payload: None,
                        body: Some("pub fn value() -> u8 { 2 }".to_string()),
                        description: "correct work staged alongside the failure".to_string(),
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: "no_such_entity".to_string(),
                        payload: None,
                        body: Some("pub fn no_such_entity() {}".to_string()),
                        description: String::new(),
                    },
                ],
            )
            .unwrap();

        let refused = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_eq!(refused.is_error, Some(true));
        let poisoned = sessions
            .get_transaction(&transaction.transaction_id)
            .unwrap();
        assert_eq!(poisoned.state, "active");
        assert!(poisoned.staged_operations.is_empty());

        let aborted = sessions
            .abort_transaction(&transaction.transaction_id)
            .expect("a transaction a refused commit returned to active must be abortable");
        assert_eq!(aborted.state, "aborted");
        assert_eq!(
            load_native_commit_base(&state.layout)
                .unwrap()
                .roots
                .generation,
            before.roots.generation,
            "neither the refused commit nor the abort may move repository authority"
        );
        assert!(
            sessions
                .stage_transaction(
                    &transaction.transaction_id,
                    vec![kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: value.id.to_string(),
                        payload: None,
                        body: Some("pub fn value() -> u8 { 3 }".to_string()),
                        description: "after the abort".to_string(),
                    }],
                )
                .is_err(),
            "an abandoned transaction must not accept new work"
        );
    }

    /// A caller that guesses the operations shape gets the accepted shapes
    /// back, not a serde field name from inside a payload variant.
    #[test]
    fn improvised_operation_shapes_are_refused_with_the_accepted_shapes() {
        let (_dir, state) = test_state();
        install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();

        let result = commit_exact_transaction(
            &state,
            &sessions,
            &HashMap::from([
                (
                    "transaction_id".to_string(),
                    serde_json::json!(transaction.transaction_id),
                ),
                (
                    "operations".to_string(),
                    serde_json::json!([{
                        "verb": "update",
                        "target": "value",
                        "payload": {"name": "value", "body": "pub fn value() -> u8 { 2 }"},
                        "description": "improvised payload shape",
                    }]),
                ),
            ]),
            None,
        );
        assert_eq!(result.is_error, Some(true));
        let message = result_text(&result);
        assert!(
            message.contains("each element of `operations` is one of"),
            "the refusal must spell out the accepted shapes: {message}"
        );
        assert!(
            message.contains("\"body\""),
            "the minimal target-body shape must be named: {message}"
        );
    }

    #[test]
    fn transaction_fence_hash_is_independent_of_metadata_map_order() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let mut left = entity.clone();
        left.metadata
            .extra
            .insert("z".to_string(), serde_json::json!(1));
        left.metadata
            .extra
            .insert("a".to_string(), serde_json::json!({"y": 2, "b": 3}));
        let mut right = entity.clone();
        right
            .metadata
            .extra
            .insert("a".to_string(), serde_json::json!({"b": 3, "y": 2}));
        right
            .metadata
            .extra
            .insert("z".to_string(), serde_json::json!(1));
        let transaction = |payload: Entity| kin_mcp::McpTransaction {
            transaction_id: uuid::Uuid::nil().to_string(),
            session_id: "session".to_string(),
            scope: "file:src/lib.rs".to_string(),
            state: "active".to_string(),
            staged_operations: vec![kin_mcp::McpMutationOperation {
                verb: "update".to_string(),
                target: entity.id.to_string(),
                payload: Some(kin_mcp::McpMutationPayload::Entity(payload)),
                body: Some("pub fn value() -> u8 { 2 }".to_string()),
                description: String::new(),
            }],
            commit_payload_hash: None,
        };
        assert_eq!(
            transaction_payload_hash(&transaction(left)).unwrap(),
            transaction_payload_hash(&transaction(right)).unwrap()
        );
    }

    #[test]
    fn source_body_commit_publishes_exact_bytes_and_reparsed_semantics() {
        let (_dir, state) = test_state();
        let initial = b"pub fn value() -> u8 { 1 }\n";
        let (entity, _) = install_exact_source(&state, "src/lib.rs", initial, "value");
        let before = load_native_commit_base(&state.layout).unwrap();
        let sessions = test_sessions();
        let (transaction_id, arguments) =
            stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");

        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "exact source commit failed: {}",
            result_text(&result)
        );
        let response: serde_json::Value = serde_json::from_str(result_text(&result)).unwrap();
        assert_eq!(
            response["semantic_authority"],
            "reparsed_exact_repository_bytes"
        );
        assert_eq!(
            response["modified_files"],
            serde_json::json!(["src/lib.rs"])
        );
        assert_eq!(
            sessions.get_transaction(&transaction_id).unwrap().state,
            "committed"
        );

        let expected = b"pub fn value() -> u8 { 2 }\n";
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            expected
        );
        let after = load_native_commit_base(&state.layout).unwrap();
        assert!(after.roots.generation > before.roots.generation);
        let artifact = after
            .tree
            .artifact_at_path(&RepoPath::from_utf8("src/lib.rs").unwrap())
            .unwrap();
        let hash = artifact.entry.blob_identity().unwrap();
        assert_eq!(
            load_native_source_blob(&state.layout, hash).unwrap(),
            expected
        );
        assert!(semantic_workspace_matches(
            state.graph.as_ref(),
            &after.graph
        ));

        let reparsed = state.graph.get_entity(&entity.id).unwrap().unwrap();
        let authority_entity = after.graph.get_entity(&entity.id).unwrap().unwrap();
        assert_eq!(reparsed, authority_entity);
        assert_ne!(
            reparsed.fingerprint, entity.fingerprint,
            "semantic fingerprint must come from reparsing the exact new bytes"
        );
    }

    #[test]
    fn dirty_checkout_rejects_before_authority_and_preserves_local_bytes() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let before = load_native_commit_base(&state.layout).unwrap();
        let live_before = state.graph.compute_root_hash();
        let dirty = b"pub fn value() -> u8 { 99 }\n";
        std::fs::write(state.layout.working_dir().join("src/lib.rs"), dirty).unwrap();

        let sessions = test_sessions();
        let (transaction_id, arguments) =
            stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_eq!(result.is_error, Some(true));
        assert!(
            result_text(&result).contains("before authority moved"),
            "{}",
            result_text(&result)
        );
        assert_eq!(
            sessions.get_transaction(&transaction_id).unwrap().state,
            "active"
        );
        let after = load_native_commit_base(&state.layout).unwrap();
        assert_eq!(after.roots, before.roots);
        assert_eq!(state.graph.compute_root_hash(), live_before);
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            dirty,
            "failed exact commit must preserve the caller's unrelated local edit"
        );
    }

    #[test]
    fn unsupported_source_mutations_fail_before_repository_mutation() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let before = load_native_commit_base(&state.layout).unwrap();

        let create_sessions = test_sessions();
        let create = create_sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();
        let mut inserted = entity.clone();
        inserted.id = kin_model::EntityId::new();
        inserted.name = "inserted".to_string();
        create_sessions
            .stage_transaction(
                &create.transaction_id,
                vec![kin_mcp::McpMutationOperation {
                    verb: "create".to_string(),
                    target: inserted.id.to_string(),
                    payload: Some(kin_mcp::McpMutationPayload::Entity(inserted)),
                    body: Some("pub fn inserted() {}".to_string()),
                    description: String::new(),
                }],
            )
            .unwrap();
        let create_result = commit_exact_transaction(
            &state,
            &create_sessions,
            &HashMap::from([(
                "transaction_id".to_string(),
                serde_json::json!(create.transaction_id),
            )]),
            None,
        );
        assert_eq!(create_result.is_error, Some(true));
        assert!(result_text(&create_result).contains("insertion"));
        assert_eq!(
            create_sessions
                .get_transaction(&create.transaction_id)
                .unwrap()
                .state,
            "active"
        );

        let metadata_sessions = test_sessions();
        let metadata = metadata_sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();
        metadata_sessions
            .stage_transaction(
                &metadata.transaction_id,
                vec![kin_mcp::McpMutationOperation {
                    verb: "update".to_string(),
                    target: entity.id.to_string(),
                    payload: Some(kin_mcp::McpMutationPayload::Entity(entity)),
                    body: None,
                    description: String::new(),
                }],
            )
            .unwrap();
        let metadata_result = commit_exact_transaction(
            &state,
            &metadata_sessions,
            &HashMap::from([(
                "transaction_id".to_string(),
                serde_json::json!(metadata.transaction_id),
            )]),
            None,
        );
        assert_eq!(metadata_result.is_error, Some(true));
        assert!(result_text(&metadata_result).contains("requires an exact UTF-8 body"));

        let after = load_native_commit_base(&state.layout).unwrap();
        assert_eq!(after.roots, before.roots);
    }

    #[test]
    fn non_utf8_source_and_overlapping_regions_fail_before_mutation() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );

        let mut shadow = entity.clone();
        shadow.id = kin_model::EntityId::new();
        shadow.name = "shadow".to_string();
        shadow.signature = "pub fn shadow() -> u8".to_string();
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![EntityDelta::Added {
                    new: shadow.clone(),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();
        commit_live_graph(&state, "install overlapping authority fixture", false);
        let overlap_before = load_native_commit_base(&state.layout).unwrap();

        let overlap_sessions = test_sessions();
        let overlap_tx = overlap_sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();
        overlap_sessions
            .stage_transaction(
                &overlap_tx.transaction_id,
                vec![
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: entity.id.to_string(),
                        payload: Some(kin_mcp::McpMutationPayload::Entity(entity.clone())),
                        body: Some("pub fn value() -> u8 { 2 }".to_string()),
                        description: String::new(),
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: shadow.id.to_string(),
                        payload: Some(kin_mcp::McpMutationPayload::Entity(shadow.clone())),
                        body: Some("pub fn shadow() -> u8 { 3 }".to_string()),
                        description: String::new(),
                    },
                ],
            )
            .unwrap();
        let overlap_result = commit_exact_transaction(
            &state,
            &overlap_sessions,
            &HashMap::from([(
                "transaction_id".to_string(),
                serde_json::json!(overlap_tx.transaction_id),
            )]),
            None,
        );
        assert_eq!(overlap_result.is_error, Some(true));
        assert!(
            result_text(&overlap_result).contains("overlap"),
            "{}",
            result_text(&overlap_result)
        );
        assert_eq!(
            load_native_commit_base(&state.layout).unwrap().roots,
            overlap_before.roots
        );

        // Remove the intentionally ambiguous entity, then move the exact tree
        // to bytes that cannot be represented by an MCP UTF-8 entity body.
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![EntityDelta::Removed { old: shadow }],
                ..TransactionDelta::default()
            })
            .unwrap();
        let artifact = state
            .graph
            .resolved_tree()
            .artifact_at_path(&RepoPath::from_utf8("src/lib.rs").unwrap())
            .cloned()
            .unwrap();
        let non_utf8 = [0xff, 0xfe, 0xfd];
        let digest = state.blobs.write(&non_utf8).unwrap();
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id: artifact.artifact_id,
                    old: artifact.located_entry(),
                    new: LocatedEntry::new(
                        RepoPath::from_utf8("src/lib.rs").unwrap(),
                        TreeEntry::blob(Hash256::from_bytes(digest.0), false),
                    ),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();
        commit_live_graph(&state, "install non-UTF-8 exact source fixture", true);
        let non_utf8_before = load_native_commit_base(&state.layout).unwrap();

        let utf8_sessions = test_sessions();
        let (_, utf8_arguments) =
            stage_entity_edit(&utf8_sessions, &entity, "pub fn value() -> u8 { 2 }");
        let utf8_result = commit_exact_transaction(&state, &utf8_sessions, &utf8_arguments, None);
        assert_eq!(utf8_result.is_error, Some(true));
        assert!(
            result_text(&utf8_result).contains("not valid UTF-8"),
            "{}",
            result_text(&utf8_result)
        );
        assert_eq!(
            load_native_commit_base(&state.layout).unwrap().roots,
            non_utf8_before.roots
        );
    }

    #[test]
    fn untouched_gitlink_does_not_block_an_unrelated_exact_source_commit() {
        install_test_registry_override();
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        git(repo, &["init", "--initial-branch=subtarget"]);
        git(repo, &["config", "user.email", "kin@example.invalid"]);
        git(repo, &["config", "user.name", "Kin"]);
        git(repo, &["config", "commit.gpgsign", "false"]);
        std::fs::write(repo.join(".subtarget"), b"subrepository target\n").unwrap();
        git(repo, &["add", ".subtarget"]);
        git(repo, &["commit", "-s", "-m", "subrepository target"]);
        let gitlink_target = git(repo, &["rev-parse", "HEAD"]);
        git(repo, &["switch", "--orphan", "main"]);
        if repo.join(".subtarget").exists() {
            std::fs::remove_file(repo.join(".subtarget")).unwrap();
        }
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::create_dir_all(repo.join("modules/dependency")).unwrap();
        let initial = b"pub fn value() -> u8 { 1 }\n";
        std::fs::write(repo.join("src/lib.rs"), initial).unwrap();
        git(repo, &["add", "src/lib.rs"]);
        git(
            repo,
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("160000,{gitlink_target},modules/dependency"),
            ],
        );
        git(repo, &["commit", "-s", "-m", "source with exact gitlink"]);

        let layout = kin_core::init_from_git(repo).unwrap().layout;
        let state = Arc::new(DaemonState::open(layout).unwrap());
        let file_id = FilePathId::new("src/lib.rs");
        let mut entities = state
            .graph
            .query_entities(&EntityFilter {
                name_pattern: Some("value".to_string()),
                file_path: Some(file_id.clone()),
                ..EntityFilter::default()
            })
            .unwrap();
        if entities.iter().all(|entity| entity.name != "value") {
            let blob_hash = state.blobs.write(initial).unwrap();
            let indexed = kin_index::IndexPipeline::new()
                .index_any_content(&file_id, initial, blob_hash)
                .unwrap();
            let kin_index::IndexedAny::EntitySource(indexed) = indexed else {
                panic!("Rust source fixture must produce semantic entities");
            };
            assert!(
                state
                    .graph
                    .resolved_tree()
                    .artifact_at_path(&RepoPath::from_utf8("src/lib.rs").unwrap())
                    .is_some(),
                "daemon query graph must begin from the imported exact workspace tree"
            );
            let layout = indexed.file_layout.clone();
            state
                .graph
                .apply_transaction_delta(&TransactionDelta {
                    entity_deltas: indexed
                        .entities
                        .into_iter()
                        .map(|new| EntityDelta::Added { new })
                        .collect(),
                    relation_deltas: indexed
                        .relations
                        .into_iter()
                        .map(|new| RelationDelta::Added { new })
                        .collect(),
                    ..TransactionDelta::default()
                })
                .unwrap();
            state.graph.upsert_file_layout(&layout).unwrap();
            commit_live_graph(&state, "install source semantics", false);
            entities = state
                .graph
                .query_entities(&EntityFilter {
                    name_pattern: Some("value".to_string()),
                    file_path: Some(file_id),
                    ..EntityFilter::default()
                })
                .unwrap();
        }
        let entity = entities
            .into_iter()
            .find(|entity| entity.name == "value")
            .expect("source fixture must contain value");

        let before = load_native_commit_base(&state.layout).unwrap();
        let gitlink_path = RepoPath::from_utf8("modules/dependency").unwrap();
        let gitlink = before
            .tree
            .artifact_at_path(&gitlink_path)
            .cloned()
            .expect("Git import must retain the exact Gitlink");
        assert!(matches!(gitlink.entry, TreeEntry::Gitlink { .. }));
        let retained = state
            .layout
            .working_dir()
            .join("modules/dependency/local-only.txt");
        std::fs::write(&retained, b"independently managed bytes\n").unwrap();

        let sessions = test_sessions();
        let (_, arguments) = stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "unrelated exact source commit failed: {}",
            result_text(&result)
        );

        let after = load_native_commit_base(&state.layout).unwrap();
        assert!(after.roots.generation > before.roots.generation);
        assert_eq!(
            after.tree.get(&gitlink.artifact_id).unwrap().entry,
            gitlink.entry,
            "MCP commit must preserve the exact Gitlink target"
        );
        assert_eq!(
            std::fs::read(&retained).unwrap(),
            b"independently managed bytes\n",
            "unrelated MCP edits must not traverse or rewrite retained Gitlink content"
        );
    }

    #[test]
    fn receiptless_restart_fence_resets_and_replans_safely() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let before = load_native_commit_base(&state.layout).unwrap();
        let sessions = test_sessions();
        let (transaction_id, arguments) =
            stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let transaction = sessions.get_transaction(&transaction_id).unwrap();
        let payload_hash = transaction_payload_hash(&transaction).unwrap();
        sessions
            .prepare_transaction_commit(&transaction_id, &payload_hash)
            .unwrap();
        persist_registry_checked(&state, &sessions).unwrap();

        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "receipt-less fence recovery failed: {}",
            result_text(&result)
        );
        let after = load_native_commit_base(&state.layout).unwrap();
        assert_eq!(after.roots.generation, before.roots.generation + 1);
        assert_eq!(
            sessions.get_transaction(&transaction_id).unwrap().state,
            "committed"
        );
    }

    #[test]
    fn repository_receipt_recovers_after_restart_without_double_commit() {
        let (dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let sessions = test_sessions();
        let (transaction_id, arguments) =
            stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        state
            .mcp_fail_after_authority_once
            .store(true, Ordering::SeqCst);

        let interrupted = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_eq!(interrupted.is_error, Some(true));
        assert!(result_text(&interrupted).contains("after repository receipt"));
        assert_eq!(
            sessions.get_transaction(&transaction_id).unwrap().state,
            "committing"
        );
        let committed_generation = load_native_commit_base(&state.layout)
            .unwrap()
            .roots
            .generation;
        let layout = state.layout.clone();
        drop(state);
        drop(sessions);

        install_test_registry_override();
        let reopened = Arc::new(DaemonState::open(layout).unwrap());
        let restored = reopened
            .mcp_transactions
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].state, "committing");
        let recovered_sessions = test_sessions();
        recovered_sessions.replace_transactions(restored);
        let recovered = commit_exact_transaction(&reopened, &recovered_sessions, &arguments, None);
        assert_ne!(
            recovered.is_error,
            Some(true),
            "receipt recovery failed: {}",
            result_text(&recovered)
        );
        assert_eq!(
            load_native_commit_base(&reopened.layout)
                .unwrap()
                .roots
                .generation,
            committed_generation,
            "receipt recovery must not publish a second repository generation"
        );
        assert_eq!(
            recovered_sessions
                .get_transaction(&transaction_id)
                .unwrap()
                .state,
            "committed"
        );
        assert_eq!(
            std::fs::read(reopened.layout.working_dir().join("src/lib.rs")).unwrap(),
            b"pub fn value() -> u8 { 2 }\n"
        );
        let authority = load_native_commit_base(&reopened.layout).unwrap();
        assert!(semantic_workspace_matches(
            reopened.graph.as_ref(),
            &authority.graph
        ));
        drop(dir);
    }

    /// Find the derived entity an enrichment tick installed into the live graph.
    fn live_enrichment_entity(state: &Arc<DaemonState>) -> Entity {
        state
            .graph
            .to_snapshot()
            .entities
            .values()
            .find(|entity| entity.name == "enriched_inside_the_command_window")
            .cloned()
            .expect("the enrichment tick installs its anchor entity into the live graph")
    }

    /// The precondition must accept the state an ordinary agent session is
    /// actually in.
    ///
    /// The enrichment worker publishes into the live query graph continuously
    /// and those facets cross the repository compare-and-swap only when a change
    /// is committed, so a live graph that leads authority is the normal case
    /// between commits, not a corrupt one. A precondition demanding equality
    /// refuses here, which is the wedge: it holds for a moment after each commit
    /// and then fails at the next tick.
    ///
    /// Accepting it costs nothing, because the exact planner reads its
    /// prospective graph from repository authority and applies only the staged
    /// operations. This proves both halves: the commit succeeds, and the derived
    /// lead it committed over is absent from the published authority graph.
    #[test]
    fn a_commit_after_an_enrichment_tick_publishes_only_its_staged_operations() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let before = load_native_commit_base(&state.layout).unwrap();
        assert!(
            semantic_workspace_matches(state.graph.as_ref(), &before.graph),
            "the fixture must start from a daemon that matches authority, or this test cannot \
             prove the enrichment tick is what the old precondition refused"
        );

        state.install_derived_enrichment();
        let derived = live_enrichment_entity(&state);
        let derived_relations: Vec<_> = state
            .graph
            .to_snapshot()
            .relations
            .iter()
            .filter(|(_, relation)| relation.origin == RelationOrigin::Lsp)
            .map(|(id, _)| *id)
            .collect();
        assert!(
            !derived_relations.is_empty(),
            "the enrichment tick must install at least one derived relation"
        );
        assert!(
            !semantic_workspace_matches(state.graph.as_ref(), &before.graph),
            "the enrichment tick must actually put the live graph ahead of authority, or this \
             test passes without reproducing the refusal it exists to falsify"
        );

        let sessions = test_sessions();
        let (transaction_id, arguments) =
            stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "a commit issued after an enrichment tick must not be refused: {}",
            result_text(&result)
        );
        assert_eq!(
            sessions.get_transaction(&transaction_id).unwrap().state,
            "committed"
        );

        let after = load_native_commit_base(&state.layout).unwrap();
        assert_eq!(after.roots.generation, before.roots.generation + 1);
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            b"pub fn value() -> u8 { 2 }\n"
        );
        let published = after.graph.to_snapshot();
        assert!(
            !published.entities.contains_key(&derived.id),
            "the published change must carry only the staged operations; the derived enrichment \
             entity reached repository authority"
        );
        for relation_id in &derived_relations {
            assert!(
                !published.relations.contains_key(relation_id),
                "derived relation {relation_id} reached repository authority"
            );
        }
        let reparsed = after.graph.get_entity(&entity.id).unwrap().unwrap();
        assert_ne!(
            reparsed.fingerprint, entity.fingerprint,
            "the staged body edit must still be what this commit published"
        );
    }

    /// Enrich the live graph the way the LSP worker actually does: one relation
    /// on an entity repository authority already owns, upserted under nothing
    /// but the graph-authority epoch.
    ///
    /// `DaemonState::install_derived_enrichment` also adds an anchor entity, so
    /// it diverges both domains at once. The real worker only ever adds
    /// relations, which is the divergence an ordinary session actually carries
    /// between commits, and it is the narrower case to prove.
    fn install_lsp_relation_on(state: &Arc<DaemonState>, entity: &Entity) -> Relation {
        let relation = Relation {
            id: kin_model::RelationId::new(),
            kind: kin_model::RelationKind::Calls,
            src: GraphNodeId::Entity(entity.id),
            dst: GraphNodeId::Entity(entity.id),
            confidence: 0.95,
            origin: RelationOrigin::Lsp,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        let guard = state.begin_graph_authority_mutation();
        state.graph.upsert_relation(&relation).unwrap();
        state.bump_version();
        drop(guard);
        relation
    }

    /// The same acceptance as the enrichment-tick case, in the exact shape the
    /// LSP worker writes: relations only, on entities authority already owns.
    #[test]
    fn a_commit_after_an_lsp_relation_tick_publishes_only_its_staged_operations() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let before = load_native_commit_base(&state.layout).unwrap();
        assert!(semantic_workspace_matches(
            state.graph.as_ref(),
            &before.graph
        ));

        let derived = install_lsp_relation_on(&state, &entity);
        assert!(
            !semantic_workspace_matches(state.graph.as_ref(), &before.graph),
            "an LSP relation tick must put the live graph ahead of authority, or this test \
             proves nothing about the refusal it exists to falsify"
        );

        let sessions = test_sessions();
        let (_, arguments) = stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "a commit issued after an LSP relation tick must not be refused: {}",
            result_text(&result)
        );

        let after = load_native_commit_base(&state.layout).unwrap();
        assert_eq!(after.roots.generation, before.roots.generation + 1);
        assert!(
            !after
                .graph
                .to_snapshot()
                .relations
                .contains_key(&derived.id),
            "the derived LSP relation must not be absorbed into the published change"
        );
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            b"pub fn value() -> u8 { 2 }\n"
        );
    }

    /// The binding this precondition protects is the authority revision, so a
    /// daemon reading an older revision than the one being planned against must
    /// still be refused, and the refusal must name that revision gap.
    #[test]
    fn a_commit_planned_against_a_trailing_daemon_cursor_is_refused() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let before = load_native_commit_base(&state.layout).unwrap();
        let live_before = state.graph.compute_root_hash();
        assert!(
            before.roots.generation > 0,
            "the fixture must have published at least one generation to trail"
        );
        let stale_generation = before.roots.generation - 1;
        state
            .snapshot_generation
            .store(stale_generation, Ordering::SeqCst);

        let sessions = test_sessions();
        let (transaction_id, arguments) =
            stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);

        assert_eq!(result.is_error, Some(true));
        let message = result_text(&result);
        assert!(
            message.contains(&format!("cursor is at generation {stale_generation}"))
                && message.contains(&format!("is at generation {}", before.roots.generation)),
            "the refusal must name both sides of the stale revision binding: {message}"
        );
        assert!(
            message.contains("reopen from repository authority"),
            "the refusal must say what to do: {message}"
        );
        assert_eq!(
            sessions.get_transaction(&transaction_id).unwrap().state,
            "active",
            "a refused precondition must leave the staged operations re-sendable"
        );
        assert_eq!(
            load_native_commit_base(&state.layout).unwrap().roots,
            before.roots,
            "no repository authority may move behind a refused precondition"
        );
        assert_eq!(state.graph.compute_root_hash(), live_before);
    }

    /// A derived lead is permitted, a derived loss is not. A daemon that has
    /// dropped semantics repository authority owns is answering from something
    /// other than graph truth, and the post-commit correction would be computed
    /// from that gap, so the commit must be refused and the refusal must name
    /// what went missing.
    #[test]
    fn a_commit_from_a_daemon_missing_authority_owned_semantics_is_refused() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let before = load_native_commit_base(&state.layout).unwrap();
        let authority_owned = before
            .graph
            .to_snapshot()
            .entities
            .values()
            .find(|candidate| candidate.id == entity.id)
            .cloned()
            .expect("the fixture entity is owned by repository authority");
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![EntityDelta::Removed {
                    old: authority_owned.clone(),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();

        let sessions = test_sessions();
        let (transaction_id, arguments) =
            stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);

        assert_eq!(result.is_error, Some(true));
        let message = result_text(&result);
        assert!(
            message.contains("no longer holds the repository workspace authority")
                && message.contains(&format!("entity {} is missing", entity.id)),
            "the refusal must name the authority-owned semantics that went missing: {message}"
        );
        assert!(
            message.contains("reopen before committing an MCP transaction"),
            "the refusal must say what to do: {message}"
        );
        assert_eq!(
            sessions.get_transaction(&transaction_id).unwrap().state,
            "active"
        );
        assert_eq!(
            load_native_commit_base(&state.layout).unwrap().roots,
            before.roots,
            "no repository authority may move behind a refused precondition"
        );
    }
}
