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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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
    plan_native_commit_from_base_declaring_carry, recover_native_commit, NativeCommitBase,
    NativeCommitResult,
};
use crate::state::DaemonState;

struct ExactMcpPlan {
    native: crate::repository_commit::NativeCommitPlan,
    layouts: Vec<FileLayout>,
    carried_pending_files: Vec<RepoPath>,
}

/// What this process knows about a commit beyond the change it published.
///
/// Present when the commit was planned here and absent when it was recovered by
/// operation id after an interrupted attempt, because only the planner knows
/// which files this transaction's own operations authored and a recovered change
/// does not record that split. The change message declares any fold on both
/// paths, so an absent split is never the only record that one happened.
struct PlannedCommitFacts {
    layouts: Vec<FileLayout>,
    carried_pending_files: Vec<RepoPath>,
}

/// How far back a commit looks in the audit log for attribution it may already
/// have written, or for the fold declaration an earlier attempt recorded.
///
/// Queried without an actor filter deliberately. The store applies its limit
/// with `take`, after any filter, so a filtered query short-circuits only once
/// it has found that many matching events; a session with fewer commits than
/// the limit never reaches it and the traversal runs the whole log. Unfiltered,
/// the limit bounds the traversal itself, which is the property this needs. The
/// derived event ids and the recorded change id do the matching.
///
/// MCP commits are serialized behind the coordination gate, so a resume or a
/// retry sits within a handful of events of the attempt it is answering for,
/// and the window is wide enough to absorb an interleaved restart.
const ATTRIBUTION_WINDOW: usize = 1024;

fn authority_context(state: &DaemonState) -> Result<LocalRepositoryAuthorityContext, String> {
    LocalRepositoryAuthorityContext::from_state(state)
        .map_err(|error| format!("open startup-pinned repository authority: {error}"))
}

/// The files this transaction's own operations wrote, resolved from the staged
/// operations instead of from the plan.
///
/// The planner knows this set exactly, but a commit interrupted after its
/// receipt and then resumed by id has no plan and still has to answer for the
/// same change. The staged operations survive that interruption, and a body
/// edit never moves an entity between files, so resolving the same targets
/// against authority after the commit names the files the planner named.
///
/// Best effort on purpose: a target that no longer resolves gives `None`, and
/// the caller then reports no split at all rather than a wrong one.
fn authored_files_from_staged(
    graph: &kin_db::InMemoryGraph,
    operations: &[kin_mcp::McpMutationOperation],
) -> Option<BTreeSet<RepoPath>> {
    let mut authored = BTreeSet::new();
    for operation in operations {
        let entity = match operation.payload.as_ref() {
            Some(kin_mcp::McpMutationPayload::Entity(payload)) => {
                graph.get_entity(&payload.id).ok().flatten()?
            }
            // A relation operation writes no file, so it claims none.
            Some(_) => continue,
            None => {
                // A creation names its file directly and has no entity to
                // resolve, which is also why it must be answered here: falling
                // through to entity resolution fails, the whole authored set
                // collapses to `None`, and a resumed commit would then declare
                // every file it published as carried when the original declared
                // none of them.
                if kin_mcp::session::is_new_source_file(operation)
                    || kin_mcp::session::is_replaced_source_file(operation)
                    || kin_mcp::session::is_retired_source_file(operation)
                {
                    authored.insert(RepoPath::from_utf8(operation.target.trim().to_string()).ok()?);
                    continue;
                }
                // A rename writes at both ends. Claiming only the destination
                // would leave the origin looking like a file the workspace
                // happened to be carrying, which is the distinction this set
                // exists to keep.
                if kin_mcp::session::is_renamed_source_file(operation) {
                    authored.insert(RepoPath::from_utf8(operation.target.trim().to_string()).ok()?);
                    authored.insert(
                        RepoPath::from_utf8(operation.destination.as_deref()?.trim().to_string())
                            .ok()?,
                    );
                    continue;
                }
                kin_mcp::handlers::sessions::resolve_target_entity(graph, &operation.target).ok()?
            }
        };
        authored.insert(RepoPath::from_utf8(entity.file_origin?.0).ok()?);
    }
    Some(authored)
}

/// The fold declaration a commit already recorded, read back from its own
/// attribution.
///
/// This is how a retry answers the same way the original did. A commit that
/// outran the caller's per-attempt budget is retried into a registry the first
/// attempt has already emptied, so the retry has the change and nothing else,
/// and the change alone cannot say which of its files an operation wrote.
fn recorded_carried_files(
    graph: &kin_db::InMemoryGraph,
    change_id: &kin_model::SemanticChangeId,
) -> Vec<String> {
    let change_id = change_id.to_string();
    graph
        .query_audit_events(None, ATTRIBUTION_WINDOW)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|event| event.details)
        .filter_map(|details| serde_json::from_str::<serde_json::Value>(&details).ok())
        .find(|details| {
            details.get("change_id").and_then(serde_json::Value::as_str) == Some(change_id.as_str())
        })
        .and_then(|details| {
            Some(
                details
                    .get("carried_pending_files")?
                    .as_array()?
                    .iter()
                    .filter_map(|file| file.as_str().map(str::to_string))
                    .collect(),
            )
        })
        .unwrap_or_default()
}

/// Attach the carried-file split to a commit reply, when there is one to
/// attach.
///
/// `modified_files` stays exactly what it was, because it is what every
/// existing caller reads. The split is added beside it and only when this
/// commit folded pending working-tree content in, so a caller that sees these
/// keys is being told its commit published files it did not write.
fn declare_carried_split(
    result: &mut serde_json::Value,
    modified_files: &[FilePathId],
    carried: &[String],
) {
    if carried.is_empty() {
        return;
    }
    let staged = modified_files
        .iter()
        .map(ToString::to_string)
        .filter(|file| !carried.contains(file))
        .collect::<Vec<_>>();
    result["staged_operation_files"] = serde_json::json!(staged);
    result["carried_pending_files"] = serde_json::json!(carried);
}

/// Whether the receipt a commit reply describes was published by this call or
/// by an earlier one under the same caller-stable transaction id.
///
/// A caller that retried needs exactly this bit to know whether its re-send
/// double-applied, and no other field in the reply carries it: a replay
/// restates the original change id, repository generation, and root hash
/// exactly, which is what makes the idempotency correct and also what makes it
/// invisible. So the bit is threaded from the path that knows rather than
/// inferred at the reply.
#[derive(Clone, Copy)]
enum CommitApplication {
    /// This call moved repository authority.
    Applied,
    /// Authority had already moved under this transaction id before this call
    /// ran, so the reply restates a landing this call did not make.
    AlreadyApplied,
}

impl CommitApplication {
    fn already_applied(self) -> bool {
        matches!(self, Self::AlreadyApplied)
    }
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
            // The fence this recovered against was set by an earlier attempt,
            // so authority moved before this call ran.
            return finalize_committed_transaction(
                state,
                sessions,
                transaction,
                &actor,
                recovered,
                None,
                coordination,
                CommitApplication::AlreadyApplied,
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

    let base = timed_commit_phase("load_commit_base", || {
        load_native_commit_base(&authority_context)
    })
    .map_err(|error| format!("load exact MCP commit base: {error}"))?;
    require_bound_authority_revision(state, &base, &transaction_id)?;
    let plan = match timed_commit_phase("plan_transaction", || {
        plan_exact_transaction(
            state,
            &authority_context,
            &transaction,
            &actor,
            operation_id,
            &base,
        )
    }) {
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

    let committed = match timed_commit_phase("publish_authority_and_projection", || {
        commit_native_plan_with_projection(
            &state.layout,
            state.blobs.as_ref(),
            &authority_context,
            plan.native,
        )
    }) {
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

    // This call planned and published under its own fence, including the branch
    // where the mutation reported an error and the receipt recovery below it
    // found the receipt that same attempt had already written.
    finalize_committed_transaction(
        state,
        sessions,
        transaction,
        &actor,
        committed,
        Some(PlannedCommitFacts {
            layouts: plan.layouts,
            carried_pending_files: plan.carried_pending_files,
        }),
        coordination,
        CommitApplication::Applied,
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
    carried_pending_files: &[RepoPath],
) -> Result<(), String> {
    graph
        .create_actor(&actor.actor)
        .map_err(|error| format!("record committing agent actor: {error}"))?;

    // Scoped to the entities this change moved that the agent's own operations
    // wrote, which is what keeps a folded-in pending file from being attributed
    // to the agent.
    //
    // A carried file's entities DO move in this change. They have to: a change
    // that publishes new bytes for a file must publish the semantics those bytes
    // derive to, or it seals a tree and an entity set that describe different
    // source (see `derive_carried_pending_semantics`). That is a content
    // revision, and it belongs in the change. It is not an authorship claim, and
    // that is why it is filtered out here rather than left to reach the audit
    // trail: every entity inside a carried file keeps answering
    // `kin_provenance_query` with the authorship it already had, and the fold is
    // declared at the level it happened at, in the change message, which the
    // `change_id` recorded below leads to.
    let carried_origins = carried_pending_files
        .iter()
        .filter_map(|path| path.as_utf8().map(FilePathId::new))
        .collect::<HashSet<_>>();
    // Where each entity this change names lives, read from the change's own
    // payloads before the graph. A removed entity is gone from the graph by
    // here, so a lookup alone would report it as owned by no file and wave it
    // through; the delta still carries the payload that says which file it came
    // from. The graph answers for the rest, which is every relation endpoint
    // this change did not otherwise touch.
    let mut origin_of = HashMap::new();
    for delta in &committed.change.entity_deltas {
        let entity = match delta {
            EntityDelta::Added { new } | EntityDelta::Modified { new, .. } => new,
            EntityDelta::Removed { old } => old,
        };
        if let Some(origin) = entity.file_origin.clone() {
            origin_of.insert(entity.id, origin);
        }
    }
    let is_carried = |entity_id: &kin_model::EntityId| -> bool {
        if let Some(origin) = origin_of.get(entity_id) {
            return carried_origins.contains(origin);
        }
        graph
            .get_entity(entity_id)
            .ok()
            .flatten()
            .and_then(|entity| entity.file_origin)
            .is_some_and(|origin| carried_origins.contains(&origin))
    };
    let mut entities = committed
        .change
        .entity_deltas
        .iter()
        .map(|delta| match delta {
            EntityDelta::Added { new } | EntityDelta::Modified { new, .. } => new.id,
            EntityDelta::Removed { old } => old.id,
        })
        .filter(|entity_id| !is_carried(entity_id))
        .collect::<Vec<_>>();
    // A relation-only commit changed no entity of its own, so it has no entity
    // delta to scope to, but it is still an agent write against the entities the
    // relation joins. Scoping it to the change alone made it unfindable: every
    // reader that answers "who touched this entity" selects changes by scanning
    // entity deltas, which a relation-only change has none of, so the commit was
    // recorded and invisible. Its endpoints are the entities an operator would
    // ask about, so they are what it is attributed to.
    //
    // The carried filter applies to this source as well as to the one above, and
    // that is the whole reason it is written twice rather than once. A carried
    // file now contributes entity deltas, so a relation-only transaction beside
    // a carried edit to one of its endpoints leaves the list above empty, opens
    // this fallback, and would hand the carried endpoint straight back to the
    // committing session. The trigger is "no scopes the agent authored" rather
    // than "no entity deltas" for the same reason.
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
                })
                .filter(|entity_id| !is_carried(entity_id)),
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
        .query_audit_events(None, ATTRIBUTION_WINDOW)
        .map_err(|error| format!("read existing commit attribution: {error}"))?
        .into_iter()
        .map(|event| event.event_id)
        .collect::<HashSet<_>>();

    let mut details = serde_json::json!({
        "schema": "kin.mcp.commit_audit.v1",
        "transaction_id": transaction.transaction_id,
        "session_id": actor.session_id,
        "actor": actor.actor.display_name,
        "change_id": committed.change.id.to_string(),
        "repository_generation": committed.receipt.generation,
        "repository_operation_id": committed.receipt.operation_id.to_string(),
    });
    // The durable home of the fold declaration, and the reason it survives.
    // Only the process that planned or resumed this commit can tell a file its
    // operations wrote from one the workspace carried in, and a retry that
    // arrives after the transaction record is gone has neither. It reads the
    // split back from here instead, so a caller whose commit outran its own
    // request budget is told the same thing as one whose commit fit inside it.
    // Absent entirely when nothing was carried, so a reader that finds no key
    // on a commit is reading one that folded nothing.
    if !carried_pending_files.is_empty() {
        details["carried_pending_files"] = serde_json::json!(carried_pending_files
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>());
    }
    let details = details.to_string();

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

/// Whether the derived graph and repository authority agree on the workspace.
///
/// This snapshots both sides to compare three fields of the result, and a
/// snapshot deep-clones every sub-store, including the entity revision history
/// and the audit log, both of which grow with every commit a repository has
/// ever taken. So a comparison of three maps costs two whole-graph clones, the
/// reply path runs it twice, and both runs sit after the change is already
/// durable. That is most of what a caller waits through on a large store, and
/// `timed_finalize_step` is what makes the cost visible instead of silent.
///
/// kin-db 0.7.21 answers the same question under its own read lock with no
/// clone at all, and the comparison is identical, so this wrapper is a cost
/// change only: three-map equality without deep-cloning revision history and
/// the audit log on both sides, twice per reply.
fn semantic_workspace_matches(left: &kin_db::InMemoryGraph, right: &kin_db::InMemoryGraph) -> bool {
    left.semantic_workspace_matches(right)
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
    let mut creations: BTreeMap<String, (FilePathId, Vec<u8>)> = BTreeMap::new();
    let mut replacements: BTreeMap<String, (FilePathId, Vec<u8>)> = BTreeMap::new();
    let mut retirements: BTreeMap<String, FilePathId> = BTreeMap::new();
    let mut relocations: BTreeMap<String, (FilePathId, FilePathId)> = BTreeMap::new();
    let mut relation_operations = Vec::new();
    let mut edited_entities = HashSet::new();

    for operation in &transaction.staged_operations {
        let verb = operation.verb.trim().to_ascii_lowercase();
        // A payload-less `create` carrying a repository path and a body admits
        // source the graph has never seen. It is the only shape that can: an
        // edit resolves its target against an existing entity and splices into
        // an existing span, so a file with neither is unreachable through it,
        // and the structured branch would require the caller to invent entity
        // identity the extractor is about to derive. Recorded here and planned
        // below, beside the edits, so one transaction can create a file and
        // edit another and publish both or neither.
        if operation.payload.is_none() && kin_mcp::session::is_new_source_file(operation) {
            record_new_source_file(&mut creations, base, operation)?;
            continue;
        }
        // A payload-less `replace` carrying a repository path and a body
        // rewrites source the graph already holds. It is the create's sibling
        // for a file that exists, and it is the only shape a caller holding a
        // path and a whole file can use: an entity edit resolves its target
        // against one entity and splices into that entity's span, so a rewrite
        // that adds or drops declarations has no span to land in. Recorded here
        // and planned below, beside the creations and the edits, so one
        // transaction can rewrite one file and create another and publish both
        // or neither.
        if operation.payload.is_none() && kin_mcp::session::is_replaced_source_file(operation) {
            record_replaced_source_file(&mut replacements, base, operation)?;
            continue;
        }
        // A payload-less `delete` carrying a repository path retires source the
        // graph already holds, and a payload-less `rename` carrying two paths
        // relocates it. They are the mirror image of `create`: an entity
        // payload names one entity, which can neither retire the artifact it
        // sits on nor move it, so a file-level transition has to name the file.
        // Recorded here and planned below, beside the creations and the edits,
        // so one transaction can retire one file and write another and publish
        // both or neither.
        if operation.payload.is_none() && kin_mcp::session::is_retired_source_file(operation) {
            record_retired_source_path(&mut retirements, base, operation)?;
            continue;
        }
        if operation.payload.is_none() && kin_mcp::session::is_renamed_source_file(operation) {
            record_renamed_source_path(&mut relocations, base, operation)?;
            continue;
        }
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

    // The files this transaction's own operations write, named before the edits
    // are consumed. Every other file the published change carries came from the
    // workspace's pending tree, and this is the only place that distinction is
    // known: after publication a carried file and an authored one are both just
    // tree deltas.
    let authored_files = edits
        .values()
        .map(|(file_id, _)| file_id)
        .chain(creations.values().map(|(file_id, _)| file_id))
        .chain(replacements.values().map(|(file_id, _)| file_id))
        .chain(retirements.values())
        .chain(relocations.values().flat_map(|(from, to)| [from, to]))
        .map(|file_id| {
            RepoPath::from_utf8(file_id.0.clone())
                .map_err(|error| format!("invalid exact source path {file_id}: {error}"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;

    let mut layouts = Vec::new();
    let pipeline = kin_index::IndexPipeline::new();

    refuse_overlapping_file_operations(
        &creations,
        &replacements,
        &retirements,
        &relocations,
        &edits,
    )?;
    // Retirements and relocations run before the creations and the edits. A
    // transaction that retires one path and creates another has to see the
    // retirement first, or the create plans against a tree that still carries
    // what this transaction is about to take out of it. Ordering them here also
    // means a relocation's destination is occupied by the time a later create
    // is planned against the same tree, so the collision is caught rather than
    // published.
    plan_retired_source_files(&prospective, retirements)?;
    plan_renamed_source_files(&prospective, relocations, &mut layouts)?;
    plan_new_source_files(state, &prospective, &pipeline, creations, &mut layouts)?;
    plan_replaced_source_files(state, &prospective, &pipeline, replacements, &mut layouts)?;
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
                "body edit for {file_id} would create or remove source entities ({delta:?}); an \
                 edit may only change the body of the entity it names. To add a whole new file, \
                 stage verb 'create' with `target` set to its repository path and `body` set to \
                 its complete text; adding or removing an entity inside an existing file is not \
                 yet supported"
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

    let plan_against = |graph: &kin_db::InMemoryGraph| {
        plan_native_commit_from_base_declaring_carry(
            graph,
            state.blobs.as_ref(),
            authority_context,
            operation_id,
            kin_model::Timestamp::now(),
            actor.author.clone(),
            &authored_files,
            &|carried| commit_message(&transaction.transaction_id, carried),
            base,
        )
        .map_err(|error| format!("plan exact MCP repository commit: {error}"))
    };
    let native = plan_against(&prospective)?;
    // Planned first, then read for what it carries, because the carried set is
    // not knowable until the published tree deltas are: it is the fold
    // `carried_pending_paths` computes from them. Taking it from the plan rather
    // than computing it a second way is what keeps the files re-derived below
    // and the files declared in the reply the same set by construction.
    let native = match derive_carried_pending_semantics(
        state,
        &prospective,
        &pipeline,
        authority_context,
        &native,
        &mut layouts,
    )? {
        // The carry moved no semantics, so this plan already describes the graph
        // it was planned from and nothing is spent on the common case.
        CarriedDerivation::AlreadyCoherent => native,
        // Semantics moved under the carried paths, so the plan is stale by
        // exactly that much. Planned once more and never in a loop: the second
        // pass publishes the same tree bytes as the first, so it carries the
        // same set, and re-deriving that set again would find nothing.
        CarriedDerivation::Derived => {
            drop(native);
            plan_against(&prospective)?
        }
    };
    let carried_pending_files = native.carried_pending_files.clone();
    Ok(ExactMcpPlan {
        native,
        layouts,
        carried_pending_files,
    })
}

/// How many carried paths one commit message names before it stops listing.
///
/// A sample rather than the whole set, because a workspace can hold hundreds of
/// pending files and a message nobody reads declares nothing. The count is
/// always exact, so a truncated sample never understates the fold.
const CARRIED_SAMPLE: usize = 10;

/// The message one MCP commit publishes, stating what it folded in.
///
/// A commit that carried nothing gets the bare transaction line it has always
/// had, byte for byte: the declaration exists to describe a fold, and a
/// declaration on a commit that folded nothing would teach every reader to skim
/// past the ones that did.
///
/// When something was carried, the first line says so on its own, because a
/// subject-only view of history is where a reader is most likely to meet this
/// change and least able to ask a follow-up question. The body then says what
/// the fold does and does not do: the bytes move and the semantics move with
/// them, because a change that published one without the other would describe
/// two different sources, and the entities inside those files keep the
/// authorship they already had rather than silently becoming this agent's work,
/// because no operation here wrote them.
fn commit_message(transaction_id: &str, carried: &[RepoPath]) -> String {
    if carried.is_empty() {
        return format!("MCP transaction {transaction_id}");
    }
    let count = carried.len();
    let files = if count == 1 { "file" } else { "files" };
    let mut sample = carried
        .iter()
        .take(CARRIED_SAMPLE)
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    if count > CARRIED_SAMPLE {
        sample.push_str(&format!(", and {} more", count - CARRIED_SAMPLE));
    }
    format!(
        "MCP transaction {transaction_id} (also admitted {count} pending working-tree {files})\n\n\
         The workspace already held admitted working-tree content its base change did not carry, \
         so this change publishes that content beside the staged operations rather than reverting \
         it, and re-derives its semantics from the exact bytes published here, because a change \
         that moved one without the other would describe two different sources. No operation in \
         this transaction authored that content, so the entities inside it keep the authorship \
         they already had.\n\
         Carried: {sample}"
    )
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

/// Record one "admit this new source file" operation against repository
/// authority, refusing every shape the planner could not honor later.
///
/// The path is validated with the same rule the projection applies, so a
/// creation the planner accepts is a creation the commit can materialize, and
/// a path already tracked is refused by name rather than silently turned into
/// an edit of somebody else's file.
fn record_new_source_file(
    creations: &mut BTreeMap<String, (FilePathId, Vec<u8>)>,
    base: &NativeCommitBase,
    operation: &kin_mcp::McpMutationOperation,
) -> Result<(), String> {
    let target = operation.target.trim();
    let path = RepoPath::from_utf8(target.to_string())
        .map_err(|error| format!("new source path {target:?} is unusable: {error}"))?;
    kin_core::validate_source_paths([&path]).map_err(|error| {
        format!("new source path {target:?} is not an admissible repository path: {error}")
    })?;
    if base.tree.artifact_at_path(&path).is_some() {
        return Err(format!(
            "{target} is already tracked by repository authority, so it cannot be created; \
             'create' admits only source the graph has never seen. Rewrite it with verb \
             'replace' carrying its complete new text, edit one entity inside it with verb \
             'update', or create a path that does not exist yet"
        ));
    }
    let body = operation
        .body
        .as_ref()
        .expect("a new source file operation always carries a body");
    let file_id = FilePathId::new(target.to_string());
    if creations
        .insert(file_id.0.clone(), (file_id, body.as_bytes().to_vec()))
        .is_some()
    {
        return Err(format!(
            "{target} is created more than once in one transaction; overlapping source authority \
             is ambiguous"
        ));
    }
    Ok(())
}

/// Record one "rewrite this tracked source file" operation against repository
/// authority, refusing every shape the planner could not honor later.
///
/// The mirror of [`record_new_source_file`]: that one refuses a path authority
/// already tracks, this one refuses a path it does not, so between them a
/// caller is always pointed at the verb that does what it asked for. A rewrite
/// of a path nothing tracks is not a harmless creation, because the caller
/// believes it is changing a file that exists.
///
/// An identical body is refused here as well as at stage time. Publishing it
/// would mint a change whose tree delta moves no bytes, and the transaction's
/// own no-semantic-change guard would then refuse the whole commit with a
/// message about the transaction rather than about the operation that emptied
/// it. The comparison is on content hashes, which is what the tracked entry
/// carries, so nothing is read off disk and no source is loaded to answer it.
fn record_replaced_source_file(
    replacements: &mut BTreeMap<String, (FilePathId, Vec<u8>)>,
    base: &NativeCommitBase,
    operation: &kin_mcp::McpMutationOperation,
) -> Result<(), String> {
    let target = operation.target.trim();
    let path = RepoPath::from_utf8(target.to_string())
        .map_err(|error| format!("replaced source path {target:?} is unusable: {error}"))?;
    kin_core::validate_source_paths([&path]).map_err(|error| {
        format!("replaced source path {target:?} is not an admissible repository path: {error}")
    })?;
    let artifact = base.tree.artifact_at_path(&path).ok_or_else(|| {
        format!(
            "{target} is not tracked by repository authority, so there is nothing to replace; \
             'replace' rewrites only source the graph already holds. Admit a path the graph has \
             never seen with verb 'create' instead, carrying the same body"
        )
    })?;
    let body = operation
        .body
        .as_ref()
        .expect("a replaced source file operation always carries a body");
    if let TreeEntry::Blob { hash, .. } = artifact.entry {
        if hash == kin_blobs::digest(body.as_bytes()) {
            return Err(format!(
                "the body sent for {target} is byte-identical to the contents repository \
                 authority already tracks, so this operation changes nothing; no repository \
                 commit was created"
            ));
        }
    }
    let file_id = FilePathId::new(target.to_string());
    if replacements
        .insert(file_id.0.clone(), (file_id, body.as_bytes().to_vec()))
        .is_some()
    {
        return Err(format!(
            "{target} is replaced more than once in one transaction; overlapping source \
             authority is ambiguous"
        ));
    }
    Ok(())
}

/// Refuse a transaction whose file-level operations act on the same path twice.
///
/// The three file-level shapes are planned in a fixed order (retire, relocate,
/// create), and each one is checked against the base tree when it is recorded,
/// so an overlap is invisible at record time and only surfaces as whichever
/// error the second operation happens to hit against a tree the first one
/// already moved. That error names an internal planning step rather than the
/// pair of operations the caller wrote. Two operations on one path also have no
/// unambiguous meaning: retiring and renaming the same file is a question about
/// intent, not an ordering problem, and answering it by ordering would publish
/// a guess.
///
/// An edit inside a file this transaction retires is the same class. The edit
/// would be planned against a path the retirement has already taken out, and
/// there is no reading of "change this function and delete the file it lives
/// in" that both halves survive.
fn refuse_overlapping_file_operations(
    creations: &BTreeMap<String, (FilePathId, Vec<u8>)>,
    replacements: &BTreeMap<String, (FilePathId, Vec<u8>)>,
    retirements: &BTreeMap<String, FilePathId>,
    relocations: &BTreeMap<String, (FilePathId, FilePathId)>,
    edits: &BTreeMap<String, (FilePathId, Vec<(Entity, Vec<u8>)>)>,
) -> Result<(), String> {
    for path in retirements.keys() {
        if relocations.contains_key(path) {
            return Err(format!(
                "{path} is both retired and renamed in one transaction; a file either leaves the \
                 repository or moves within it, and which one was meant cannot be inferred"
            ));
        }
        if creations.contains_key(path) {
            return Err(format!(
                "{path} is both retired and created in one transaction; retire it in one change \
                 and admit the new file in the next, so each is reviewable on its own"
            ));
        }
        if replacements.contains_key(path) {
            return Err(format!(
                "{path} is both retired and rewritten in one transaction; the rewrite would be \
                 planned against a path this transaction has already taken out"
            ));
        }
        if edits.contains_key(path) {
            return Err(format!(
                "{path} is retired and also carries an entity edit in one transaction; the edit \
                 would be planned against a path this transaction has already taken out"
            ));
        }
    }
    // A rewrite states the file's whole new text, so anything else that also
    // writes the same path in the same transaction is a second authority over
    // the same bytes. Whichever one ran last would win silently, and the
    // caller would have no way to tell which it was.
    for path in replacements.keys() {
        if relocations.contains_key(path) {
            return Err(format!(
                "{path} is both rewritten and renamed away in one transaction; rewrite the file \
                 where it lands, or move it in a separate transaction"
            ));
        }
        if edits.contains_key(path) {
            return Err(format!(
                "{path} carries both a whole-file rewrite and an entity edit in one transaction; \
                 the rewrite already states the file's complete new text, so the edit would be \
                 spliced into bytes it replaces"
            ));
        }
    }
    let mut destinations = BTreeSet::new();
    for (from, (_, to)) in relocations {
        if !destinations.insert(to.0.clone()) {
            return Err(format!(
                "two files are renamed onto {} in one transaction; a destination holds one file",
                to.0
            ));
        }
        if creations.contains_key(&to.0) {
            return Err(format!(
                "{} is both a rename destination (from {from}) and a created path in one \
                 transaction; a rename may not overwrite a file",
                to.0
            ));
        }
        if relocations.contains_key(&to.0) {
            return Err(format!(
                "{} is renamed away and is also the destination of {from} in one transaction; \
                 chained renames are ambiguous, so stage them as separate transactions",
                to.0
            ));
        }
    }
    Ok(())
}

/// Record one retirement: the file at `target` leaves the repository.
///
/// The path must be one repository authority already tracks. A retirement of a
/// path nothing holds is refused rather than treated as satisfied, because the
/// caller believes a file left the graph and would have no way to learn it
/// never did; a silent success there is the same failure class as an admission
/// that quietly overwrote somebody else's file.
fn record_retired_source_path(
    retirements: &mut BTreeMap<String, FilePathId>,
    base: &NativeCommitBase,
    operation: &kin_mcp::McpMutationOperation,
) -> Result<(), String> {
    let target = operation.target.trim();
    let path = RepoPath::from_utf8(target.to_string())
        .map_err(|error| format!("retired source path {target:?} is unusable: {error}"))?;
    if base.tree.artifact_at_path(&path).is_none() {
        return Err(format!(
            "{target} is not tracked by repository authority, so there is nothing to retire; \
             'delete' retires only a path the graph already holds. Name a path kin_graph_status \
             or semantic_locate reports, or drop this operation"
        ));
    }
    let file_id = FilePathId::new(target.to_string());
    if retirements.insert(file_id.0.clone(), file_id).is_some() {
        return Err(format!(
            "{target} is retired more than once in one transaction; retiring a path that is \
             already gone is ambiguous"
        ));
    }
    Ok(())
}

/// Record one relocation: the file at `target` moves to `destination`.
///
/// Both ends are checked against the base tree here rather than only at the
/// transition, so a caller learns which end was wrong. A destination that is
/// already tracked is refused instead of overwritten, for the same reason
/// `create` refuses a tracked path: a move that silently replaces another file
/// destroys truth the caller never named.
fn record_renamed_source_path(
    relocations: &mut BTreeMap<String, (FilePathId, FilePathId)>,
    base: &NativeCommitBase,
    operation: &kin_mcp::McpMutationOperation,
) -> Result<(), String> {
    let target = operation.target.trim();
    let destination = operation
        .destination
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    let from = RepoPath::from_utf8(target.to_string())
        .map_err(|error| format!("renamed source path {target:?} is unusable: {error}"))?;
    let to = RepoPath::from_utf8(destination.to_string())
        .map_err(|error| format!("rename destination {destination:?} is unusable: {error}"))?;
    kin_core::validate_source_paths([&to]).map_err(|error| {
        format!("rename destination {destination:?} is not an admissible repository path: {error}")
    })?;
    if base.tree.artifact_at_path(&from).is_none() {
        return Err(format!(
            "{target} is not tracked by repository authority, so there is nothing to rename; \
             'rename' moves only a path the graph already holds"
        ));
    }
    if base.tree.artifact_at_path(&to).is_some() {
        return Err(format!(
            "{destination} is already tracked by repository authority, so {target} cannot move \
             onto it; a rename may not overwrite a file. Retire {destination} first, or pick a \
             path that does not exist yet"
        ));
    }
    let from_id = FilePathId::new(target.to_string());
    let to_id = FilePathId::new(destination.to_string());
    if relocations
        .insert(from_id.0.clone(), (from_id, to_id))
        .is_some()
    {
        return Err(format!(
            "{target} is renamed more than once in one transaction; a file has one destination"
        ));
    }
    Ok(())
}

/// Take every recorded retirement out of prospective graph truth: entities,
/// their incident edges, the file layout, every non-entity enrichment facet,
/// and the tree entry itself.
///
/// The enrichment goes before the tree entry and through the same function the
/// watcher seam uses ([`crate::loop_runner::clear_incompatible_facets_in`]),
/// which is what keeps the two definitions of "retire this file" from drifting
/// apart. The order is not a preference: repository authority refuses a
/// transition that leaves an entity on a path the staged tree no longer
/// carries, and it is right to, because an artifact that stops existing while
/// its entities keep ranking is exactly the stale top hit this exists to
/// prevent. Removing the entities first is what makes the tree transition
/// admissible.
fn plan_retired_source_files(
    prospective: &kin_db::InMemoryGraph,
    retirements: BTreeMap<String, FilePathId>,
) -> Result<(), String> {
    if retirements.is_empty() {
        return Ok(());
    }
    let mut artifacts = Vec::new();
    for (_, file_id) in retirements {
        let path = RepoPath::from_utf8(file_id.0.clone())
            .map_err(|error| format!("invalid retired source path {file_id}: {error}"))?;
        let artifact = prospective
            .resolved_tree()
            .artifact_at_path(&path)
            .cloned()
            .ok_or_else(|| {
                format!("retired source artifact disappeared during planning: {file_id}")
            })?;
        crate::loop_runner::clear_incompatible_facets_in(
            prospective,
            &file_id,
            crate::loop_runner::EnrichmentFacet::None,
        )
        .map_err(|error| format!("retire enrichment for {file_id}: {error}"))?;
        artifacts.push(artifact);
    }

    // Edges that address the ARTIFACT rather than an entity inside it. Removing
    // the entities took every edge incident to them, and this is what is left:
    // an import that resolved to the file, a dependency drawn on the file. They
    // are collected after the enrichment pass so an edge already gone is not
    // removed twice, and carried in the same delta as the tree removal because
    // repository authority requires artifact retirement and incident-edge
    // retirement to be atomic. Without them the transition is refused outright
    // with "unadmitted destination endpoint", which is the shape a two-file
    // Python fixture reaches on its first import.
    let mut seen = HashSet::new();
    let mut relation_deltas = Vec::new();
    for artifact in &artifacts {
        let node = GraphNodeId::Artifact(artifact.artifact_id);
        for relation in prospective
            .get_all_relations_for_node(&node)
            .map_err(|error| format!("load edges incident to {}: {error}", artifact.path))?
        {
            // An edge between two retired artifacts is reachable from both, and
            // removing it twice in one delta is not the same statement as
            // removing it once.
            if seen.insert(relation.id) {
                relation_deltas.push(RelationDelta::Removed { old: relation });
            }
        }
    }

    let tree_deltas = artifacts
        .iter()
        .map(|artifact| TreeDelta::Removed {
            artifact_id: artifact.artifact_id,
            old: artifact.located_entry(),
        })
        .collect::<Vec<_>>();
    prospective
        .apply_transaction_delta(&TransactionDelta {
            relation_deltas,
            tree_deltas,
            ..TransactionDelta::default()
        })
        .map_err(|error| {
            let paths = artifacts
                .iter()
                .map(|artifact| artifact.path.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            format!("retire {paths} from the exact tree: {error}")
        })?;
    Ok(())
}

/// Move every recorded relocation in prospective graph truth, keeping the
/// identity of everything it moves.
///
/// The artifact keeps its id, every entity keeps its id, span, lineage, and
/// documentation, and every relation keeps both endpoints, because relations
/// address entities rather than paths. Only the path changes, which is the
/// whole difference between a rename and a retirement followed by an admission:
/// the second mints new identity and orphans every incoming edge.
///
/// The entity relocation and the tree transition travel in ONE delta. Split
/// across two, the first half would be exactly the state repository authority
/// refuses (entities on a path the staged tree no longer carries), so a rename
/// planned in two steps cannot reach the second. This is the "or relocation"
/// half of what that refusal asks a caller to carry.
///
/// The layout and the non-entity facets carry the path in their key rather than
/// in their body, so they are re-keyed rather than rebuilt: the bytes did not
/// move, so every byte range in them is still correct.
/// The entity relocations one path change requires, returned rather than
/// applied.
///
/// Returned, because the caller's transaction is the only place they may land.
/// kin-db refuses a tree transition that leaves an entity on a path the staged
/// tree no longer carries, in those words, so a relocation published as a
/// second transaction beside the tree move is refused exactly as a stranded
/// entity is. Applying these here would work only where the caller is staging a
/// prospective graph it publishes later, and the reconcile seam is not.
///
/// FIR-2429: a bare filesystem `mv` reached the reconcile seam with no entity
/// relocation at all, and the repository stopped accepting commits.
/// Typed rather than stringly: every failure here is the graph refusing a read
/// or a write, so the daemon's reconcile seam can map it to `DaemonError::Graph`
/// and the commit seam can add its own context. A `String` crossing this
/// boundary would force one of the two to invent an error class.
pub(crate) fn plan_entity_relocations(
    graph: &kin_db::InMemoryGraph,
    from_id: &FilePathId,
    to_id: &FilePathId,
) -> std::result::Result<Vec<EntityDelta>, kin_db::KinDbError> {
    Ok(graph
        .query_entities(&kin_model::EntityFilter {
            file_path: Some(from_id.clone()),
            ..Default::default()
        })?
        .into_iter()
        .map(|old| {
            let mut new = old.clone();
            new.file_origin = Some(to_id.clone());
            EntityDelta::Modified { old, new }
        })
        .collect())
}

/// Re-key the per-file records a path change moves: layout, shallow,
/// structured and opaque.
///
/// These are not part of a [`TransactionDelta`], so they are applied here and
/// stay outside the caller's transaction, which is where they already sat. Run
/// after the transaction publishes, in the order the MCP seam has always used.
pub(crate) fn relocate_file_records(
    graph: &kin_db::InMemoryGraph,
    from_id: &FilePathId,
    to_id: &FilePathId,
    layouts: &mut Vec<FileLayout>,
) -> std::result::Result<(), kin_db::KinDbError> {
    if let Some(layout) = graph.get_file_layout(from_id)? {
        let mut moved = layout;
        moved.file_id = to_id.clone();
        graph.delete_file_layout(from_id)?;
        graph.upsert_file_layout(&moved)?;
        layouts.push(moved);
    }
    if let Some(shallow) = graph.get_shallow_file(from_id)? {
        let mut moved = shallow;
        moved.file_id = to_id.clone();
        graph.delete_shallow_file(from_id)?;
        graph.upsert_shallow_file(&moved)?;
    }
    if let Some(structured) = graph.get_structured_artifact(from_id)? {
        let mut moved = structured;
        moved.file_id = to_id.clone();
        graph.delete_structured_artifact(from_id)?;
        graph.upsert_structured_artifact(&moved)?;
    }
    if let Some(opaque) = graph.get_opaque_artifact(from_id)? {
        let mut moved = opaque;
        moved.file_id = to_id.clone();
        graph.delete_opaque_artifact(from_id)?;
        graph.upsert_opaque_artifact(&moved)?;
    }
    Ok(())
}

fn plan_renamed_source_files(
    prospective: &kin_db::InMemoryGraph,
    relocations: BTreeMap<String, (FilePathId, FilePathId)>,
    layouts: &mut Vec<FileLayout>,
) -> Result<(), String> {
    for (_, (from_id, to_id)) in relocations {
        let from = RepoPath::from_utf8(from_id.0.clone())
            .map_err(|error| format!("invalid rename origin {from_id}: {error}"))?;
        let to = RepoPath::from_utf8(to_id.0.clone())
            .map_err(|error| format!("invalid rename destination {to_id}: {error}"))?;
        let artifact = prospective
            .resolved_tree()
            .artifact_at_path(&from)
            .cloned()
            .ok_or_else(|| {
                format!("renamed source artifact disappeared during planning: {from_id}")
            })?;

        // One transaction, entity relocation and tree move together. This is
        // the shape the reconcile seam was missing.
        prospective
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: plan_entity_relocations(prospective, &from_id, &to_id)
                    .map_err(|error| format!("load entities on {from_id}: {error}"))?,
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id: artifact.artifact_id,
                    old: artifact.located_entry(),
                    new: LocatedEntry::new(to.clone(), artifact.entry),
                }],
                ..TransactionDelta::default()
            })
            .map_err(|error| format!("relocate {from_id} to {to_id}: {error}"))?;

        relocate_file_records(prospective, &from_id, &to_id, layouts)
            .map_err(|error| format!("relocate records {from_id} to {to_id}: {error}"))?;
    }
    Ok(())
}

/// Turn recorded creations into prospective graph truth: exact blob, tree
/// identity, derived entities, derived relations, and a file layout.
///
/// Every step here is the one the ingest path runs. The bytes come from the
/// call rather than from the filesystem, and after they are written to the blob
/// store the file is admitted to the tree, classified and parsed by
/// [`kin_index::IndexPipeline`], and reconciled by [`kin_reconcile::Reconciler`]
/// exactly as an admitted file is. Nothing in this function reads the working
/// copy; the working file appears afterwards because the commit projects the
/// tree it published, which is the graph-owns-truth direction rather than the
/// filesystem-tells-the-graph one.
///
/// One reconciler spans the whole batch, and it is seeded from the prospective
/// graph, because cross-file resolution is skipped outright on an unseeded
/// linker. That is what lets two files created in one transaction reference
/// each other: the first file's unresolved references wait on the names it
/// imported, and installing the second file's entities binds them. The seeding
/// pass is one walk of the entity universe and runs only when a transaction
/// actually creates a file, so a transaction that only edits bodies keeps
/// exactly the planning it had before.
///
/// A file whose content does not classify as entity source is still admitted.
/// Parser support decides how much semantics a file gets, never whether the
/// repository holds it, which is the rule the ambient admission seam already
/// follows.
fn plan_new_source_files(
    state: &DaemonState,
    prospective: &kin_db::InMemoryGraph,
    pipeline: &kin_index::IndexPipeline,
    creations: BTreeMap<String, (FilePathId, Vec<u8>)>,
    layouts: &mut Vec<FileLayout>,
) -> Result<(), String> {
    if creations.is_empty() {
        return Ok(());
    }
    let mut reconciler = kin_reconcile::Reconciler::new(PathBuf::new());
    reconciler.seed_cross_file_linker_from_graph(prospective);

    for (_, (file_id, body)) in creations {
        let path = RepoPath::from_utf8(file_id.0.clone())
            .map_err(|error| format!("invalid new source path {file_id}: {error}"))?;
        let digest = state
            .blobs
            .write(&body)
            .map_err(|error| format!("store new source {file_id}: {error}"))?;
        let hash = Hash256::from_bytes(digest.0);
        prospective
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: kin_model::ArtifactId::new(),
                    new: LocatedEntry::new(path, TreeEntry::blob(hash, false)),
                }],
                ..TransactionDelta::default()
            })
            .map_err(|error| format!("admit new source {file_id} to the exact tree: {error}"))?;

        let indexed = pipeline
            .index_any_content(&file_id, &body, digest)
            .map_err(|error| format!("parse new source {file_id}: {error}"))?;
        let kin_index::IndexedAny::EntitySource(indexed) = indexed else {
            continue;
        };
        let reconcile = reconciler
            .reconcile_indexed_content(&indexed, state.blobs.as_ref(), prospective)
            .map_err(|error| format!("derive semantics for new source {file_id}: {error}"))?;
        prospective
            .apply_transaction_delta(&reconcile.delta)
            .map_err(|error| format!("apply derived semantics for {file_id}: {error}"))?;
        let layout = reconciler
            .projection()
            .get_layout(&file_id)
            .cloned()
            .ok_or_else(|| format!("parsing produced no file layout for new source {file_id}"))?;
        prospective
            .upsert_file_layout(&layout)
            .map_err(|error| format!("install prospective layout for {file_id}: {error}"))?;
        layouts.push(layout);
    }
    Ok(())
}

/// Turn recorded rewrites into prospective graph truth: exact blob, tree
/// transition, re-derived entities, re-derived relations, and a file layout.
///
/// Every step is the one [`plan_new_source_files`] runs, against a path that
/// already exists rather than one that does not, so the artifact keeps its
/// identity and the transition is an update rather than an admission. The
/// bytes come from the call, never from the working copy, and the working file
/// appears afterwards because the commit projects the tree it published.
///
/// The reconciler is what makes this a rewrite rather than a splice. It reads
/// the entities the graph already holds for the file, matches them against the
/// declarations the new text parses to, and derives the additions, the
/// modifications and the removals from the difference. So an entity the new
/// text drops leaves the graph, an entity it adds enters, and one it merely
/// edits keeps its id and its incoming edges. That is exactly what an entity
/// edit cannot do: it names one entity and one span, so a rewrite that changes
/// how many declarations a file has has nowhere to land.
///
/// A rewritten file must still classify as entity source. The alternative is
/// to admit the new bytes and leave the entities the old bytes derived standing
/// with nothing under them, which is a graph that answers about source the
/// repository no longer holds. Refusing says so instead.
fn plan_replaced_source_files(
    state: &DaemonState,
    prospective: &kin_db::InMemoryGraph,
    pipeline: &kin_index::IndexPipeline,
    replacements: BTreeMap<String, (FilePathId, Vec<u8>)>,
    layouts: &mut Vec<FileLayout>,
) -> Result<(), String> {
    if replacements.is_empty() {
        return Ok(());
    }
    let mut reconciler = kin_reconcile::Reconciler::new(PathBuf::new());
    reconciler.seed_cross_file_linker_from_graph(prospective);

    for (_, (file_id, body)) in replacements {
        let path = RepoPath::from_utf8(file_id.0.clone())
            .map_err(|error| format!("invalid replaced source path {file_id}: {error}"))?;
        let artifact = prospective
            .resolved_tree()
            .artifact_at_path(&path)
            .cloned()
            .ok_or_else(|| {
                format!("replaced source artifact disappeared during planning: {file_id}")
            })?;
        let executable = match artifact.entry {
            TreeEntry::Blob { executable, .. } => executable,
            TreeEntry::Symlink { .. } => {
                return Err(format!(
                    "replaced source {file_id} resolves through a symlink"
                ))
            }
            TreeEntry::Gitlink { .. } => {
                return Err(format!(
                    "replaced source {file_id} resolves through a gitlink"
                ))
            }
        };

        let digest = state
            .blobs
            .write(&body)
            .map_err(|error| format!("store replaced source {file_id}: {error}"))?;
        let hash = Hash256::from_bytes(digest.0);
        prospective
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id: artifact.artifact_id,
                    old: artifact.located_entry(),
                    new: LocatedEntry::new(path, TreeEntry::blob(hash, executable)),
                }],
                ..TransactionDelta::default()
            })
            .map_err(|error| format!("install prospective exact tree for {file_id}: {error}"))?;

        let indexed = pipeline
            .index_any_content(&file_id, &body, digest)
            .map_err(|error| format!("parse replaced source {file_id}: {error}"))?;
        let kin_index::IndexedAny::EntitySource(indexed) = indexed else {
            return Err(format!(
                "the replacement body for {file_id} does not classify as supported entity \
                 source, and the entities the tracked file derives would be left standing over \
                 bytes the repository no longer holds; retire the file with verb 'delete' if \
                 that is what you meant"
            ));
        };
        let reconcile = reconciler
            .reconcile_indexed_content(&indexed, state.blobs.as_ref(), prospective)
            .map_err(|error| format!("derive semantics for replaced source {file_id}: {error}"))?;
        prospective
            .apply_transaction_delta(&reconcile.delta)
            .map_err(|error| format!("apply derived semantics for {file_id}: {error}"))?;
        let layout = reconciler
            .projection()
            .get_layout(&file_id)
            .cloned()
            .ok_or_else(|| {
                format!("parsing produced no file layout for replaced source {file_id}")
            })?;
        prospective
            .upsert_file_layout(&layout)
            .map_err(|error| format!("install prospective layout for {file_id}: {error}"))?;
        layouts.push(layout);
    }
    Ok(())
}

/// What re-deriving the carried paths did to the prospective graph.
enum CarriedDerivation {
    /// Nothing semantic moved. Every carried path's entities already described
    /// the bytes the plan publishes for it, so the plan that produced the
    /// carried set still describes the graph it was planned from.
    AlreadyCoherent,
    /// Semantics moved under one or more carried paths, so the plan is stale by
    /// exactly that much and has to be planned again.
    Derived,
}

/// Re-derive the semantics of every file this commit carries in, so the change
/// it seals describes the bytes it publishes.
///
/// The two commit surfaces plan from different graphs. The CLI route is handed
/// the daemon's live derived graph, which the reconcile loop keeps current
/// against the working tree, so a pending file's entities there came from the
/// pending bytes. The MCP route is handed repository authority's own workspace
/// graph snapshot, whose tree is the workspace tree and whose entities are
/// whatever the last published semantic delta left, because
/// `publish_workspace_tree` advances that tree with an empty
/// `WorkspaceSemanticDelta`. [`plan_exact_transaction`] reparses only the files
/// its staged operations name, so a file the workspace admitted and no
/// operation authored arrives at publication as new bytes standing over old
/// entity spans, and the change seals both.
///
/// Declaring the carry does not settle that. The declaration says who authored
/// the file, and this is about whether one change's tree and entities agree
/// with each other. Nothing downstream repairs it either:
/// [`install_authority_graph`] corrects the live graph ONTO authority, so on
/// this path it propagates the disagreement rather than closing it, and
/// `semantic_workspace_matches` passes because both sides then hold the same
/// wrong answer.
///
/// Every byte read here is graph-owned. The paths come from the plan's own
/// carried set rather than from a second computation, so the files re-derived
/// are exactly the files the reply and the change message declare; the blob
/// identities come from the tree deltas that same change publishes; and the
/// bodies come out of repository CAS through [`load_native_source_blob`], never
/// off the working copy.
///
/// Republishing a carried file's semantics is not a claim on its authorship.
/// The reconciler matches the entities the graph already holds against the
/// declarations the new bytes parse to, so an entity that merely changed body
/// keeps its id, its lineage and every incoming edge, and
/// [`record_commit_provenance`] keeps the carried paths out of the attribution
/// it writes.
fn derive_carried_pending_semantics(
    state: &DaemonState,
    prospective: &kin_db::InMemoryGraph,
    pipeline: &kin_index::IndexPipeline,
    authority_context: &LocalRepositoryAuthorityContext,
    planned: &crate::repository_commit::NativeCommitPlan,
    layouts: &mut Vec<FileLayout>,
) -> Result<CarriedDerivation, String> {
    if planned.carried_pending_files.is_empty() {
        return Ok(CarriedDerivation::AlreadyCoherent);
    }
    let carried = planned
        .carried_pending_files
        .iter()
        .collect::<BTreeSet<_>>();
    let mut reconciler = kin_reconcile::Reconciler::new(PathBuf::new());
    reconciler.seed_cross_file_linker_from_graph(prospective);
    let mut derived = false;

    for delta in &planned.change.tree_deltas {
        // A deletion is named through its old state, which is the only state it
        // has, exactly as `carried_pending_paths` names it.
        let Some(path) = delta
            .new_state()
            .or_else(|| delta.old_state())
            .map(|located| &located.path)
        else {
            continue;
        };
        // Only the carried half. A path this transaction's operations wrote was
        // reparsed when it was planned, and parsing the same bytes again would
        // be work to conclude nothing.
        if !carried.contains(&path) {
            continue;
        }
        let file_id = path
            .as_utf8()
            .map(FilePathId::new)
            .ok_or_else(|| format!("carried repository path {path} is not valid UTF-8"))?;

        let Some(located) = delta.new_state() else {
            // A carried removal, which two independent mechanisms make
            // unreachable rather than one. Ambient admission publishes the tree
            // and no semantics, so vacating a path that way would leave that
            // path's entities standing over a tree that no longer carries it,
            // and repository authority refuses the transaction outright:
            // "transaction leaves entity <id> on repository path <path> absent
            // from the staged tree; carry its exact entity removal or relocation
            // in the same delta". The seam that does vacate a path,
            // `commit_session_workspace_admission`, derives the retirement
            // through `retire_semantics_on_vacated` and carries it in the same
            // transaction. So a carried tree delta is an addition or an update,
            // and the only removals that reach a plan are the ones a staged
            // `delete` authored, which are not carried.
            //
            // Asserted rather than repaired. A retirement written here would be
            // a branch nothing can reach and nothing can falsify, and if either
            // mechanism above ever regresses, sealing a change quietly is the
            // wrong answer and saying so is the right one.
            let standing = prospective
                .query_entities(&kin_model::EntityFilter {
                    file_path: Some(file_id.clone()),
                    ..Default::default()
                })
                .map_err(|error| format!("read carried entities for {path}: {error}"))?;
            if standing.is_empty() {
                continue;
            }
            return Err(format!(
                "this commit carries a removal of {path} that no operation in it authored, and \
                 the graph still holds {} entities derived from that path. Repository authority \
                 does not admit a vacated path without retiring its semantics, so this state \
                 should be unreachable; report it rather than working around it. Nothing was \
                 published.",
                standing.len()
            ));
        };
        // Named per variant rather than left to a wildcard, so a new entry kind
        // cannot be handed to the parser by accident.
        //
        // Neither a symlink nor a gitlink carries a source body, so neither is
        // parsed and neither is ever dereferenced: a symlink's target is not
        // this repository's answer for this path. What they CAN carry is the
        // previous occupant's entities, and that is not an assumption this code
        // gets to make about the tree. kin-db revalidates an invalidated path by
        // requiring an artifact to remain at it and does not require that
        // artifact to be a blob (0.7.104 `src/engine/graph.rs:8705`), so a
        // same-path source-to-symlink conversion satisfies every check while the
        // old entities keep describing bytes the repository no longer holds.
        // That is this function's own defect wearing a different tree entry, so
        // it gets the same refusal the unsupported-blob arm gives.
        let hash = match &located.entry {
            TreeEntry::Blob { hash, .. } => *hash,
            TreeEntry::Symlink { .. } => {
                refuse_carry_standing_over_unparsed_content(
                    prospective,
                    &file_id,
                    path,
                    "a symlink",
                )?;
                continue;
            }
            TreeEntry::Gitlink { .. } => {
                refuse_carry_standing_over_unparsed_content(
                    prospective,
                    &file_id,
                    path,
                    "a submodule pointer",
                )?;
                continue;
            }
        };
        let body = load_native_source_blob(authority_context, hash)
            .map_err(|error| format!("load carried source body for {path}: {error}"))?;
        let digest = state
            .blobs
            .write(&body)
            .map_err(|error| format!("store carried source {path}: {error}"))?;
        let indexed = pipeline
            .index_any_content(&file_id, &body, digest)
            .map_err(|error| format!("parse carried source {path}: {error}"))?;
        let kin_index::IndexedAny::EntitySource(indexed) = indexed else {
            // The third shape of the same condition: content the parser cannot
            // derive entities from, standing where entities already are.
            refuse_carry_standing_over_unparsed_content(
                prospective,
                &file_id,
                path,
                "content that no longer classifies as supported entity source",
            )?;
            continue;
        };
        let reconcile = reconciler
            .reconcile_indexed_content(&indexed, state.blobs.as_ref(), prospective)
            .map_err(|error| format!("derive semantics for carried source {path}: {error}"))?;
        // Entity and relation deltas are the only two that change what the
        // sealed change carries, so they are what decides whether the plan has
        // to be taken again. A carried file whose edit moved neither leaves the
        // first plan correct.
        derived |= !reconcile.delta.entity_deltas.is_empty()
            || !reconcile.delta.relation_deltas.is_empty();
        prospective
            .apply_transaction_delta(&reconcile.delta)
            .map_err(|error| format!("apply derived semantics for carried {path}: {error}"))?;
        let layout = reconciler
            .projection()
            .get_layout(&file_id)
            .cloned()
            .ok_or_else(|| format!("parsing produced no file layout for carried source {path}"))?;
        prospective
            .upsert_file_layout(&layout)
            .map_err(|error| format!("install prospective layout for carried {path}: {error}"))?;
        layouts.push(layout);
    }

    Ok(if derived {
        CarriedDerivation::Derived
    } else {
        CarriedDerivation::AlreadyCoherent
    })
}

/// Refuse a carried path whose new tree entry cannot have derived the entities
/// the graph still holds for it.
///
/// One helper for three arms, because "the content at this path cannot be what
/// those entities describe" is one condition whether the new entry is a symlink,
/// a submodule pointer, or a blob that stopped classifying as source. Nothing
/// standing there is the ordinary tree-only carry, and returns quietly.
///
/// A refusal rather than a retirement, and rather than a skip. Publishing the
/// entities over content they never came from is the defect this module is
/// closing. Retiring somebody else's entities is not this commit's call to
/// make: no operation in it named that file. So it says what it found, names
/// the path, and gives the three ways out.
fn refuse_carry_standing_over_unparsed_content(
    prospective: &kin_db::InMemoryGraph,
    file_id: &FilePathId,
    path: &RepoPath,
    became: &str,
) -> Result<(), String> {
    let standing = prospective
        .query_entities(&kin_model::EntityFilter {
            file_path: Some(file_id.clone()),
            ..Default::default()
        })
        .map_err(|error| format!("read carried entities for {path}: {error}"))?;
    if standing.is_empty() {
        return Ok(());
    }
    Err(format!(
        "the workspace holds pending content for {path} whose new tree entry is {became}, and \
         committing it would publish the {} entities the graph still derives from the source it \
         replaces over content they never came from. Stage that file in this transaction with \
         verb 'replace' to re-derive it or verb 'delete' to retire it, or revert the working file, \
         then re-send this transaction unchanged.",
        standing.len()
    ))
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
    let mut result = serde_json::json!({
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
    declare_carried_split(
        &mut result,
        &modified_files,
        &recorded_carried_files(state.graph.as_ref(), &recovered.change.id),
    );
    let json = serde_json::to_string_pretty(&result)
        .map_err(|error| format!("serialize replayed exact MCP commit response: {error}"))?;
    Ok(kin_mcp::ToolCallResult::text(json))
}

/// A finalize step slower than this names itself at `info`, the level an
/// operator actually sees.
const SLOW_FINALIZE_STEP: std::time::Duration = std::time::Duration::from_millis(500);

/// Run one step of the post-durability finalize and record what it cost.
///
/// The change is already durable when this stretch begins, and on a large store
/// the caller waited minutes in it with not one line in the log. That silence
/// is why the block was attributed to re-embedding across two releases, until a
/// reconstruction against `kin log` timestamps showed the re-embedding was
/// under a second of it. Every step reports its own duration now, so the next
/// slow commit says which part was slow instead of leaving it to be guessed.
fn timed_finalize_step<T>(step: &'static str, work: impl FnOnce() -> T) -> T {
    let started = std::time::Instant::now();
    let outcome = work();
    let elapsed = started.elapsed();
    let elapsed_ms = elapsed.as_millis();
    if elapsed >= SLOW_FINALIZE_STEP {
        tracing::info!(step, elapsed_ms, "slow commit finalize step");
    } else {
        tracing::debug!(step, elapsed_ms, "commit finalize step");
    }
    outcome
}

/// Run one phase of the commit that precedes durable publication and record
/// what it cost.
///
/// The finalize after authority publication already times its own steps, and
/// the first measurement under that timing showed the multi-minute wait
/// sitting in front of it instead: building and persisting the authority
/// successor runs whole-graph work with nothing in the log. Naming these
/// phases lets the next slow commit attribute the wait to the phase that
/// spent it instead of leaving the reply gap unexplained.
pub(crate) fn timed_commit_phase<T>(phase: &'static str, work: impl FnOnce() -> T) -> T {
    let started = std::time::Instant::now();
    crate::commit_liveness::enter_phase(phase);
    let outcome = work();
    let elapsed = started.elapsed();
    let elapsed_ms = elapsed.as_millis();
    if elapsed >= SLOW_FINALIZE_STEP {
        tracing::info!(phase, elapsed_ms, "slow commit phase");
    } else {
        tracing::debug!(phase, elapsed_ms, "commit phase");
    }
    outcome
}

/// Time one awaited phase of the commit and report it exactly as the blocking
/// helper does.
///
/// The CLI commit path opens with two phases that cannot be measured by a
/// closure: waiting on the coordination gate, and the forced filesystem
/// admission that runs under it. Both are `async`, and a phase that is skipped
/// because it does not fit the helper's shape is a phase the wall time hides.
/// The elapsed span covers suspension as well as work, which is the point for a
/// gate wait: the queue behind a held lock is the cost being attributed.
pub(crate) async fn timed_commit_phase_async<T>(
    phase: &'static str,
    work: impl std::future::Future<Output = T>,
) -> T {
    let started = std::time::Instant::now();
    crate::commit_liveness::enter_phase(phase);
    let outcome = work.await;
    let elapsed = started.elapsed();
    let elapsed_ms = elapsed.as_millis();
    if elapsed >= SLOW_FINALIZE_STEP {
        tracing::info!(phase, elapsed_ms, "slow commit phase");
    } else {
        tracing::debug!(phase, elapsed_ms, "commit phase");
    }
    outcome
}

fn finalize_committed_transaction(
    state: &Arc<DaemonState>,
    sessions: &kin_mcp::SessionRegistry,
    transaction: kin_mcp::McpTransaction,
    actor: &CommitActor,
    committed: NativeCommitResult,
    planned: Option<PlannedCommitFacts>,
    coordination: Option<&kin_mcp::CoordinationWritePreflight>,
    application: CommitApplication,
) -> Result<kin_mcp::ToolCallResult, String> {
    let (planned_layouts, planned_carry) = match planned {
        Some(planned) => (planned.layouts, Some(planned.carried_pending_files)),
        None => (Vec::new(), None),
    };
    let authority_context = authority_context(state)?;
    let authority = timed_finalize_step("reload_repository_authority", || {
        load_native_commit_base(&authority_context)
    })
    .map_err(|error| format!("reload committed MCP repository authority: {error}"))?;
    // A resume has no plan and still owes the same answer, so it recovers the
    // split from the staged operations the interruption left behind.
    let carried_pending_files = planned_carry.unwrap_or_else(|| {
        authored_files_from_staged(&authority.graph, &transaction.staged_operations)
            .map(|authored| {
                crate::repository_commit::carried_pending_paths(
                    &committed.change.tree_deltas,
                    &authored,
                )
            })
            .unwrap_or_default()
    });
    if authority.roots != committed.receipt.roots_after {
        return Err(format!(
            "repository authority advanced beyond MCP receipt generation {}; reopen the daemon before finalizing transaction {}",
            committed.receipt.generation, transaction.transaction_id
        ));
    }

    timed_finalize_step("install_authority_graph", || {
        install_authority_graph(state.graph.as_ref(), &authority.graph, &committed)
    })?;
    // The live graph now carries what authority carries, so this is the moment
    // the two are level and the only honest place to record the durable side's
    // count (FIR-2421). Taken from the authority graph rather than the live one:
    // an ambient admission may already have added entities to the live graph
    // that this commit did not publish, and reading the live count here would
    // record those as durable.
    state.record_durable_entity_count(authority.graph.entity_count() as u64);
    // The relation half, from the authority graph for the reason the entity
    // count is taken from it: an ambient admission or an enrichment sweep may
    // already have added relations to the live graph that this commit did not
    // publish, and reading the live count here would record those as durable
    // (FIR-3202).
    state.record_durable_relation_count(authority.graph.relation_count() as u64);
    let layouts = timed_finalize_step("rebuild_changed_layouts", || {
        if planned_layouts.is_empty() && committed.file_count > 0 {
            rebuild_changed_layouts(state, &authority, &committed.change)
        } else {
            Ok(planned_layouts)
        }
    })?;
    timed_finalize_step("install_layouts", || {
        for layout in layouts {
            state.graph.upsert_file_layout(&layout).map_err(|error| {
                format!("install committed exact layout {}: {error}", layout.file_id)
            })?;
        }
        Ok::<(), String>(())
    })?;
    if !timed_finalize_step("verify_workspace_matches_authority", || {
        semantic_workspace_matches(state.graph.as_ref(), &authority.graph)
    }) {
        return Err(format!(
            "derived daemon graph does not match repository authority after transaction {}",
            transaction.transaction_id
        ));
    }
    timed_finalize_step("record_commit_provenance", || {
        record_commit_provenance(
            state.graph.as_ref(),
            actor,
            &transaction,
            &committed,
            &carried_pending_files,
        )
    })?;
    // The second commit path, recorded for the same reason the first one is.
    // An agent that only ever writes through MCP would otherwise leave the
    // store's census frozen at whatever the last CLI commit or sweep left, and
    // every comparison after that would span a window nobody can date.
    //
    // Taken from the LIVE graph, unlike the durable entity count above, and the
    // difference is deliberate. That count describes what authority carries, so
    // reading it live would record entities an ambient admission added and this
    // commit never published. A census is the baseline `kin graph status`
    // compares against, and status answers from the live graph, so a census
    // taken from authority would make every ambient admission read as movement
    // this commit caused. `semantic_workspace_matches` ran just above, so the
    // two views are level here either way; the live read is what keeps them
    // level on every later path too.
    crate::background_work::record_relation_census(
        &state.layout,
        state.graph.as_ref(),
        kin_core::relation_census::CensusSource::Commit,
    );

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
    let root_hash = timed_finalize_step("compute_root_hash", || {
        hex::encode(state.graph.compute_root_hash())
    });
    let mut result = serde_json::json!({
        "transaction_id": terminal.transaction_id,
        "state": "committed",
        "status": "committed",
        "already_applied": application.already_applied(),
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
    declare_carried_split(
        &mut result,
        &modified_files,
        &carried_pending_files
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    );
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

    use kin_model::{
        AuthorId, ChangeStore, EntityFilter, LocatedEntry, SemanticChangeId, Timestamp, TreeDelta,
    };

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
                    destination: None,
                }],
            )
            .unwrap();
        let arguments = HashMap::from([(
            "transaction_id".to_string(),
            serde_json::json!(transaction.transaction_id),
        )]);
        (transaction.transaction_id, arguments)
    }

    /// Leave one working-file edit admitted the way the live daemon leaves it.
    ///
    /// This is the admission path, not a commit: the workspace tree advances to
    /// the edited bytes, the workspace base stays where it was, and no semantic
    /// change is published. That is the state every used store sits in, and the
    /// state the MCP commit path used to refuse outright.
    fn admit_pending_working_tree_edit(state: &Arc<DaemonState>, file: &str, content: &[u8]) {
        let path = RepoPath::from_utf8(file).unwrap();
        std::fs::write(state.layout.working_dir().join(file), content).unwrap();
        let digest = state.blobs.write(content).unwrap();
        let artifact = state
            .graph
            .resolved_tree()
            .artifact_at_path(&path)
            .cloned()
            .expect("a pending edit lands on an already admitted artifact");
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id: artifact.artifact_id,
                    old: artifact.located_entry(),
                    new: LocatedEntry::new(
                        path,
                        TreeEntry::blob(Hash256::from_bytes(digest.0), false),
                    ),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();

        publish_pending_workspace_tree(state);
    }

    /// Advance workspace authority to whatever the live graph's tree now holds,
    /// publishing no semantic change.
    ///
    /// The second half of every ambient admission, shared by the helpers above
    /// and below so a pending edit, a pending addition and a pending removal all
    /// reach authority through the same call the reconcile loop uses. This is
    /// where the split the MCP commit route inherits is created:
    /// `publish_workspace_tree` moves the tree and hands it an empty
    /// `WorkspaceSemanticDelta`.
    fn publish_pending_workspace_tree(state: &Arc<DaemonState>) {
        try_publish_pending_workspace_tree(state)
            .expect("a moved working tree must advance workspace authority");
    }

    /// The same publication, handing back what repository authority said.
    ///
    /// Ambient admission is refused for some transitions and the refusal is the
    /// interesting half, so one caller needs it rather than a panic.
    fn try_publish_pending_workspace_tree(state: &Arc<DaemonState>) -> crate::error::Result<()> {
        let base = load_native_commit_base(&state.layout)?;
        let admitted = crate::repository_commit::admitted_workspace_tree_for_test(
            state.layout.working_dir(),
            base.roots.clone(),
            base.tree.clone(),
            state.graph.resolved_tree(),
        );
        let admission = crate::repository_commit::publish_workspace_tree(
            state.blobs.as_ref(),
            &authority_context(state).unwrap(),
            &admitted,
            OperationId::new(),
            AuthorId::new("kin-session-reconcile"),
        )?
        .expect("a moved working tree must advance workspace authority");
        state
            .record_repository_authority_commit(admission.receipt.generation)
            .unwrap();
        Ok(())
    }

    /// Leave one brand new working file admitted the way the watcher leaves it.
    ///
    /// The workspace tree gains a path its base change never carried and no
    /// semantic change is published for it, so the change that follows carries
    /// this path as a `TreeDelta::Added` with no entities behind it.
    fn admit_pending_working_tree_file(state: &Arc<DaemonState>, file: &str, content: &[u8]) {
        let path = RepoPath::from_utf8(file).unwrap();
        let target = state.layout.working_dir().join(file);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&target, content).unwrap();
        let digest = state.blobs.write(content).unwrap();
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: kin_model::ArtifactId::new(),
                    new: LocatedEntry::new(
                        path,
                        TreeEntry::blob(Hash256::from_bytes(digest.0), false),
                    ),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();
        publish_pending_workspace_tree(state);
    }

    /// Leave one working file's removal admitted the way the watcher leaves it.
    ///
    /// The entities go with the artifact in the LIVE graph, because kin-db
    /// refuses a tree transition that strands an entity on a path the staged
    /// tree no longer carries. Workspace authority still learns only about the
    /// tree, because that is all `publish_workspace_tree` publishes, which is
    /// what leaves the entities standing on the authority side.
    fn admit_pending_working_tree_removal(
        state: &Arc<DaemonState>,
        file: &str,
    ) -> crate::error::Result<()> {
        let path = RepoPath::from_utf8(file).unwrap();
        let file_id = FilePathId::new(file);
        std::fs::remove_file(state.layout.working_dir().join(file)).unwrap();
        let artifact = state
            .graph
            .resolved_tree()
            .artifact_at_path(&path)
            .cloned()
            .expect("a pending removal takes an already admitted artifact");
        let standing = state
            .graph
            .query_entities(&EntityFilter {
                file_path: Some(file_id),
                ..EntityFilter::default()
            })
            .unwrap();
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: standing
                    .into_iter()
                    .map(|old| EntityDelta::Removed { old })
                    .collect(),
                tree_deltas: vec![TreeDelta::Removed {
                    artifact_id: artifact.artifact_id,
                    old: artifact.located_entry(),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();
        try_publish_pending_workspace_tree(state)
    }

    /// Whether workspace authority still holds a tree its base change does not.
    fn workspace_is_dirty(state: &Arc<DaemonState>) -> bool {
        let context = authority_context(state).unwrap();
        let workspace_id = context.workspace_id();
        let authority = context.open().unwrap();
        let lease = authority.read_authority();
        let dirty = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == workspace_id)
            .expect("authority has the local workspace")
            .is_dirty();
        dirty
    }

    fn commit_reply(result: &kin_mcp::ToolCallResult) -> serde_json::Value {
        serde_json::from_str(result_text(result)).expect("a commit reply is JSON")
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

    /// Build the create-file operation an agent stages for new source.
    fn new_source_file(path: &str, body: &str) -> kin_mcp::McpMutationOperation {
        kin_mcp::McpMutationOperation {
            verb: "create".to_string(),
            target: path.to_string(),
            payload: None,
            body: Some(body.to_string()),
            destination: None,
            description: format!("admit new source {path}"),
        }
    }

    const NEW_UTIL_PY: &str = "def helper(value):\n    return value + 1\n";
    const NEW_APP_PY: &str =
        "from pkg.util import helper\n\n\ndef run(value):\n    return helper(value)\n";

    /// An agent holding only the MCP belt creates new source and the graph holds
    /// it, including the references that cross between two files created in the
    /// same transaction.
    ///
    /// This is the defect FIR-2417 records, driven the way it was found. Before
    /// this operation existed there was no call on the belt that could introduce
    /// a file: an edit resolves its target against an existing entity, so a path
    /// with no entity was unreachable through it, and nothing ambient admits
    /// untracked content (the watch loop leaves it for an explicit admission
    /// seam, and the only seams are `kin commit` and `kin admit`, both of which
    /// need a shell). So an agent wrote files and the graph stayed empty.
    ///
    /// Cross-file resolution is asserted rather than assumed because it is what
    /// separates two files that are merely present from two files Kin
    /// understands together, and because the planner has to seed its linker for
    /// it to happen at all.
    #[test]
    fn new_source_files_created_over_mcp_enter_the_graph_and_reference_each_other() {
        let (_dir, state) = test_state();
        let sessions = test_sessions();

        let before = load_native_commit_base(&state.layout).unwrap();
        let entities_before = before
            .graph
            .query_entities(&EntityFilter::default())
            .unwrap()
            .len();
        let files_before = before.tree.artifacts().count();

        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:pkg/app.py")
            .unwrap();
        let operations = vec![
            new_source_file("pkg/util.py", NEW_UTIL_PY),
            new_source_file("pkg/app.py", NEW_APP_PY),
        ];
        kin_mcp::session::validate_staged_operations(&operations)
            .expect("staging must accept the new source file form");
        sessions
            .stage_transaction(&transaction.transaction_id, operations)
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
            "creating new source over MCP failed: {}",
            result_text(&result)
        );

        // The working files are a projection of what committed, written by the
        // commit rather than by the agent. Byte-exact, so a body that arrived
        // mangled cannot pass.
        assert_eq!(
            std::fs::read_to_string(state.layout.working_dir().join("pkg/util.py")).unwrap(),
            NEW_UTIL_PY
        );
        assert_eq!(
            std::fs::read_to_string(state.layout.working_dir().join("pkg/app.py")).unwrap(),
            NEW_APP_PY
        );

        let after = load_native_commit_base(&state.layout).unwrap();
        assert_eq!(
            after.tree.artifacts().count(),
            files_before + 2,
            "both created files must be tracked by repository authority"
        );

        let find = |name: &str, file: &str| {
            after
                .graph
                .query_entities(&EntityFilter {
                    name_pattern: Some(name.to_string()),
                    file_path: Some(FilePathId::new(file)),
                    ..EntityFilter::default()
                })
                .unwrap()
                .into_iter()
                .find(|entity| entity.name == name)
                .unwrap_or_else(|| panic!("{name} must be a graph entity derived from {file}"))
        };
        let helper = find("helper", "pkg/util.py");
        let run = find("run", "pkg/app.py");
        assert!(
            after
                .graph
                .query_entities(&EntityFilter::default())
                .unwrap()
                .len()
                > entities_before,
            "the graph must hold more entities after admitting two source files"
        );

        // The reference that crosses files. `find_references` reads exactly
        // these relation rows, so asserting them here is asserting what the
        // belt sees.
        let crossing = after
            .graph
            .get_all_relations_for_entity(&run.id)
            .unwrap()
            .into_iter()
            .any(|relation| relation.dst == GraphNodeId::Entity(helper.id));
        assert!(
            crossing,
            "pkg/app.py's run must reference pkg/util.py's helper across the two created files"
        );

        // What the agent actually reads back. `modified_files` is the field the
        // tool documents, and a created file has to appear in it exactly as an
        // edited one does or the caller cannot tell the commit landed.
        let reply: serde_json::Value = serde_json::from_str(result_text(&result)).unwrap();
        let modified = reply["modified_files"]
            .as_array()
            .expect("a successful commit reply names modified_files")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>();
        assert!(
            modified.contains(&"pkg/util.py") && modified.contains(&"pkg/app.py"),
            "the commit reply must name both created files, got {modified:?}"
        );
        assert!(
            reply["change_id"].as_str().is_some_and(|id| !id.is_empty()),
            "the commit must publish a change an agent can review: {reply}"
        );
    }

    /// A `create` naming a path the graph already tracks is refused by name.
    ///
    /// The refusal exists because the alternative is worse than a failure: an
    /// agent that meant to add a file and typed a path already in use would
    /// silently replace somebody else's file with its own, and a whole-file
    /// replacement is exactly what an edit is designed not to be. It also keeps
    /// `create` honest about what it means, so the caller is pointed at the verb
    /// that does what it wanted.
    #[test]
    fn creating_a_path_the_graph_already_tracks_is_refused_by_name() {
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
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![new_source_file("src/lib.rs", "pub fn replaced() {}\n")],
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
        let text = result_text(&result);
        assert!(
            text.contains("src/lib.rs is already tracked by repository authority"),
            "refusal must name the tracked path: {text}"
        );

        // The refusal is not merely a message: the file it named is untouched.
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            b"pub fn value() -> u8 { 1 }\n"
        );
    }

    /// Build the replace-file operation an agent stages to rewrite tracked
    /// source from its complete new text.
    fn replaced_source_file(path: &str, body: &str) -> kin_mcp::McpMutationOperation {
        kin_mcp::McpMutationOperation {
            verb: "replace".to_string(),
            target: path.to_string(),
            payload: None,
            body: Some(body.to_string()),
            destination: None,
            description: format!("rewrite {path}"),
        }
    }

    const TRACKED_RS: &str =
        "pub fn value() -> u8 {\n    1\n}\n\npub fn doomed() -> u8 {\n    9\n}\n";
    const REWRITTEN_RS: &str =
        "pub fn value() -> u8 {\n    2\n}\n\npub fn added() -> u8 {\n    3\n}\n";

    /// An agent holding a path and a file's complete new text lands the rewrite
    /// as one change, and the graph re-derives the file's entities from the
    /// bytes that were published.
    ///
    /// This is the half of the write surface FIR-2586 found missing. `create`
    /// admits a path the graph has never seen, and an entity edit resolves a
    /// target against one entity and splices into that entity's span, so a
    /// caller holding a path and a whole file could reach neither. Every local
    /// `edit_file` and `write_file` harness holds exactly that, which is why
    /// kin#1049 opens no transaction for an in-place edit at all.
    ///
    /// The re-derivation is asserted rather than assumed, because it is what
    /// separates a rewrite from an admission: the entity the new text keeps
    /// holds its id, the entity it drops leaves the graph, and the entity it
    /// adds enters. An entity edit refuses this case by name, since it may
    /// only change the body of the one entity it resolved.
    #[test]
    fn replacing_a_tracked_file_over_mcp_republishes_it_and_re_derives_its_entities() {
        let (_dir, state) = test_state();
        let (before_entity, installed_change) =
            install_exact_source(&state, "src/lib.rs", TRACKED_RS.as_bytes(), "value");
        let doomed_before = state
            .graph
            .query_entities(&EntityFilter {
                name_pattern: Some("doomed".to_string()),
                file_path: Some(FilePathId::new("src/lib.rs")),
                ..EntityFilter::default()
            })
            .unwrap();
        assert_eq!(
            doomed_before.len(),
            1,
            "the fixture must hold the entity the rewrite drops"
        );

        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();
        let operations = vec![replaced_source_file("src/lib.rs", REWRITTEN_RS)];
        kin_mcp::session::validate_staged_operations(&operations)
            .expect("staging must accept the whole-file rewrite form");
        sessions
            .stage_transaction(&transaction.transaction_id, operations)
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
            "rewriting tracked source over MCP failed: {}",
            result_text(&result)
        );

        // The working file is a projection of what committed, written by the
        // commit rather than by the agent. Byte-exact, so a body that arrived
        // mangled cannot pass.
        assert_eq!(
            std::fs::read_to_string(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            REWRITTEN_RS
        );

        // One change, which is what `kin log` reports. A rewrite that published
        // a retirement and an admission would read as two.
        let reply: serde_json::Value = commit_reply(&result);
        let committed = SemanticChangeId::from_hash(
            Hash256::from_hex(
                reply["change_id"]
                    .as_str()
                    .expect("a successful commit names its change"),
            )
            .expect("the change id is a content hash"),
        );
        let published = state
            .graph
            .get_changes_since(&installed_change, &committed)
            .unwrap();
        assert_eq!(
            published.iter().map(|change| change.id).collect::<Vec<_>>(),
            vec![committed],
            "the rewrite must publish exactly one change on top of the fixture"
        );

        let after = load_native_commit_base(&state.layout).unwrap();
        let named = |name: &str| {
            after
                .graph
                .query_entities(&EntityFilter {
                    name_pattern: Some(name.to_string()),
                    file_path: Some(FilePathId::new("src/lib.rs")),
                    ..EntityFilter::default()
                })
                .unwrap()
                .into_iter()
                .filter(|entity| entity.name == name)
                .collect::<Vec<_>>()
        };
        let kept = named("value");
        assert_eq!(kept.len(), 1, "the entity the new text keeps must survive");
        assert_eq!(
            kept[0].id, before_entity.id,
            "a rewrite keeps entity identity; minting a new id would orphan every incoming edge"
        );
        assert_eq!(
            named("added").len(),
            1,
            "an entity the new text adds must enter the graph"
        );
        assert!(
            named("doomed").is_empty(),
            "an entity the new text drops must leave the graph"
        );
    }

    /// A rewrite of a path repository authority does not track is refused by
    /// name, and told which verb admits one.
    ///
    /// The mirror of the create refusal, and it matters for the same reason:
    /// admitting the file instead would report a rewrite of something that
    /// existed while actually creating it, and the caller would have no way to
    /// learn the file it meant to change was never there.
    #[test]
    fn replacing_a_path_the_graph_does_not_track_is_refused_by_name() {
        let (_dir, state) = test_state();
        install_exact_source(&state, "src/lib.rs", TRACKED_RS.as_bytes(), "value");
        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/absent.rs")
            .unwrap();
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![replaced_source_file("src/absent.rs", REWRITTEN_RS)],
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
        let text = result_text(&result);
        assert!(
            text.contains("src/absent.rs is not tracked by repository authority"),
            "refusal must name the untracked path: {text}"
        );
        assert!(
            text.contains("verb 'create'"),
            "refusal must name the verb that admits a new path: {text}"
        );
        assert!(
            !state.layout.working_dir().join("src/absent.rs").exists(),
            "a refused rewrite must not leave the file it named on disk"
        );
    }

    /// A rewrite carrying the text authority already holds is refused as the
    /// empty change it is.
    ///
    /// Publishing it would mint a change whose tree delta moves no bytes, and
    /// the transaction's own no-semantic-change guard would then refuse the
    /// commit with a message about the transaction rather than about the
    /// operation that emptied it. The comparison is on content hashes, which is
    /// what the tracked entry carries, so nothing is read off the working copy
    /// to answer it.
    #[test]
    fn replacing_a_tracked_file_with_the_text_it_already_holds_is_refused_as_an_empty_change() {
        let (_dir, state) = test_state();
        install_exact_source(&state, "src/lib.rs", TRACKED_RS.as_bytes(), "value");
        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![replaced_source_file("src/lib.rs", TRACKED_RS)],
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
        let text = result_text(&result);
        assert!(
            text.contains("byte-identical to the contents repository authority already tracks"),
            "refusal must say the operation changes nothing: {text}"
        );

        // The control: the same path, the same shape, different text, commits.
        // Without it the refusal above would also be satisfied by a planner
        // that refused every rewrite.
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![replaced_source_file("src/lib.rs", REWRITTEN_RS)],
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
            "a rewrite carrying new text must still commit: {}",
            result_text(&result)
        );
    }

    /// A path that could not be materialized is refused where it was typed.
    ///
    /// Stage time, not commit time, so a caller learns which operation is wrong
    /// while the transaction still holds only what it typed. Checking it here as
    /// well as in the planner is what keeps stage-time rejection a superset of
    /// commit-time rejection, which is the contract the stage tool advertises.
    #[test]
    fn an_inadmissible_new_source_path_is_refused_at_stage_time() {
        for path in [
            "/etc/passwd",
            "../outside.py",
            ".kin/objects/sneak.py",
            ".git/hooks/pre-commit",
        ] {
            let operation = new_source_file(path, "print('x')\n");
            let error =
                kin_mcp::session::validate_staged_operations(std::slice::from_ref(&operation))
                    .expect_err(&format!("{path} must not stage"));
            assert!(
                error.contains(path),
                "the refusal must quote the path it rejected: {error}"
            );
        }

        // Positive control: the check refuses these paths because they are
        // inadmissible, not because it refuses every path.
        let ordinary = new_source_file("pkg/util.py", "print('x')\n");
        kin_mcp::session::validate_staged_operations(std::slice::from_ref(&ordinary))
            .expect("an ordinary repository-relative path must stage");
    }

    /// One repository path, for the assertions that read the exact tree.
    fn test_path(path: &str) -> RepoPath {
        RepoPath::from_utf8(path.to_string()).expect("test repository path must be usable")
    }

    /// Build the delete-file operation an agent stages to retire source.
    fn retired_source_file(path: &str) -> kin_mcp::McpMutationOperation {
        kin_mcp::McpMutationOperation {
            verb: "delete".to_string(),
            target: path.to_string(),
            payload: None,
            body: None,
            destination: None,
            description: format!("retire {path}"),
        }
    }

    /// Build the rename operation an agent stages to relocate source.
    fn renamed_source_file(from: &str, to: &str) -> kin_mcp::McpMutationOperation {
        kin_mcp::McpMutationOperation {
            verb: "rename".to_string(),
            target: from.to_string(),
            payload: None,
            body: None,
            destination: Some(to.to_string()),
            description: format!("move {from} to {to}"),
        }
    }

    /// An agent holding only the MCP belt retires a file, and the graph stops
    /// holding it.
    ///
    /// This is the defect FIR-2419 records, from the query side. A probe file
    /// deleted 35 minutes earlier was still the top `semantic_locate` hit and
    /// still the single file the graph counted, because retirement never
    /// reached the retrieval index. It could not: the belt had no call that
    /// retires anything. `create` admits a file and `update` edits an entity
    /// inside one, and an entity payload carrying verb `delete` names one
    /// entity, which cannot take the artifact it sits on out of the tree.
    ///
    /// Every surface a stale hit can come through is asserted, not just the
    /// tree: the entity ids stop resolving, the file stops being an
    /// entity-bearing path, the layout goes, and the working file goes with
    /// them. `semantic_locate`, `find_references` and `get_context_pack` all
    /// read those, so a retirement that left any of them standing would keep
    /// steering an agent toward a file that no longer exists.
    #[test]
    fn retiring_a_tracked_file_over_mcp_takes_its_entities_and_its_tree_entry() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/retired.rs",
            b"pub fn retired_value() -> u8 { 1 }\n",
            "retired_value",
        );
        let (kept, _) = install_exact_source(
            &state,
            "src/kept.rs",
            b"pub fn kept_value() -> u8 { 2 }\n",
            "kept_value",
        );
        let file_id = FilePathId::new("src/retired.rs");
        let before = load_native_commit_base(&state.layout).unwrap();
        assert!(
            before
                .tree
                .artifact_at_path(&test_path("src/retired.rs"))
                .is_some(),
            "the fixture never tracked the file, so nothing below proves a retirement"
        );

        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/retired.rs")
            .unwrap();
        let operations = vec![retired_source_file("src/retired.rs")];
        kin_mcp::session::validate_staged_operations(&operations)
            .expect("staging must accept the retirement form");
        sessions
            .stage_transaction(&transaction.transaction_id, operations)
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
            "retiring a tracked file over MCP failed: {}",
            result_text(&result)
        );

        let after = load_native_commit_base(&state.layout).unwrap();
        assert!(
            after
                .tree
                .artifact_at_path(&test_path("src/retired.rs"))
                .is_none(),
            "a retired file is still tracked by repository authority"
        );
        assert!(
            after.graph.get_entity(&entity.id).unwrap().is_none(),
            "a retired file's entity id still resolves: {}",
            entity.id
        );
        assert!(
            after
                .graph
                .query_entities(&EntityFilter {
                    file_path: Some(file_id.clone()),
                    ..EntityFilter::default()
                })
                .unwrap()
                .is_empty(),
            "a retired path still owns entities"
        );
        assert!(
            !after
                .graph
                .entity_bearing_file_paths()
                .contains(&"src/retired.rs".to_string()),
            "a retired path is still counted as an entity-bearing file"
        );
        // Enrichment lives on the live query graph rather than in the published
        // change, and the live graph is what `semantic_locate`,
        // `find_references` and `get_context_pack` read, so it is where a stale
        // hit would actually come from. Asserted with the sibling beside it, so
        // an assertion that could only ever pass would fail here too.
        assert!(
            state.graph.get_file_layout(&file_id).unwrap().is_none(),
            "a retired file kept its layout on the live query graph"
        );
        assert!(
            state
                .graph
                .get_file_layout(&FilePathId::new("src/kept.rs"))
                .unwrap()
                .is_some(),
            "the control layout is absent, so the retired-layout assertion proves nothing"
        );
        assert!(
            state
                .graph
                .query_entities(&EntityFilter {
                    file_path: Some(file_id.clone()),
                    ..EntityFilter::default()
                })
                .unwrap()
                .is_empty(),
            "a retired path still owns entities on the live query graph"
        );
        assert!(
            state.graph.get_entity(&kept.id).unwrap().is_some(),
            "the control entity is absent from the live graph, so the retirement proves nothing"
        );
        assert!(
            !state.layout.working_dir().join("src/retired.rs").exists(),
            "the commit projects the tree it published, so the working file must go with it"
        );

        // The two-sided arm: the sibling this transaction never named keeps its
        // artifact and the exact entity id it had, so a retirement retired one
        // path rather than emptying the graph.
        assert!(
            after
                .tree
                .artifact_at_path(&test_path("src/kept.rs"))
                .is_some(),
            "an unnamed sibling lost its artifact"
        );
        assert!(
            after.graph.get_entity(&kept.id).unwrap().is_some(),
            "an unnamed sibling lost its entity"
        );

        let reply: serde_json::Value = serde_json::from_str(result_text(&result)).unwrap();
        assert!(
            reply["change_id"].as_str().is_some_and(|id| !id.is_empty()),
            "a retirement must publish a change an agent can review: {reply}"
        );
    }

    /// A retired file leaves every row a retrieval surface reads.
    ///
    /// FIR-2419 is a query defect, not a bookkeeping one: the deleted file was
    /// still the top `semantic_locate` hit and still the single file the graph
    /// counted. Those surfaces do not read the tree. `semantic_locate` and
    /// `get_context_pack` rank entities and read their layouts,
    /// `find_references` reads relation rows, the file count reads
    /// entity-bearing paths, and the embedding queue holds a retrieval key per
    /// entity. A retirement that moved the tree and left any of those standing
    /// would keep steering an agent toward a file that no longer exists, which
    /// is exactly what 35 minutes of that container looked like.
    ///
    /// The cross-file edge is what makes this more than a restatement of the
    /// previous test. `run` lives in a file this transaction never names, so
    /// its edge to `helper` can only go if retiring a file takes the edges
    /// incident to its entities with it.
    #[test]
    fn retiring_a_file_evicts_it_from_the_rows_every_retrieval_surface_reads() {
        let (_dir, state) = test_state();
        let sessions = test_sessions();

        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:pkg/app.py")
            .unwrap();
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![
                    new_source_file("pkg/util.py", NEW_UTIL_PY),
                    new_source_file("pkg/app.py", NEW_APP_PY),
                ],
            )
            .unwrap();
        let created = commit_exact_transaction(
            &state,
            &sessions,
            &HashMap::from([(
                "transaction_id".to_string(),
                serde_json::json!(transaction.transaction_id),
            )]),
            None,
        );
        assert_ne!(created.is_error, Some(true), "{}", result_text(&created));

        let entity_in = |file: &str, name: &str| {
            state
                .graph
                .query_entities(&EntityFilter {
                    file_path: Some(FilePathId::new(file)),
                    ..EntityFilter::default()
                })
                .unwrap()
                .into_iter()
                .find(|entity| entity.name == name)
                .unwrap_or_else(|| panic!("{name} must be a graph entity derived from {file}"))
        };
        let helper = entity_in("pkg/util.py", "helper");
        let run = entity_in("pkg/app.py", "run");
        let crossing = |graph: &kin_db::InMemoryGraph| {
            graph
                .get_all_relations_for_entity(&run.id)
                .unwrap()
                .into_iter()
                .any(|relation| relation.dst == GraphNodeId::Entity(helper.id))
        };
        assert!(
            crossing(state.graph.as_ref()),
            "the fixture produced no cross-file edge, so nothing below proves one was evicted"
        );
        // The embedding queue only exists in a build that carries the vector
        // feature, and `pending_embeddings` is a constant zero without it, so
        // the fixture guard below would refuse a build that simply has no queue
        // to evict from. Gated rather than softened: a zero that means "no
        // queue" and a zero that means "the eviction did not happen" are
        // different answers, and a guard that cannot tell them apart is not a
        // guard.
        #[cfg(feature = "vector")]
        let queued_before = {
            let queued = state.graph.pending_embeddings();
            assert!(
                queued > 0,
                "the fixture queued no embeddings, so the queue assertion below proves nothing"
            );
            queued
        };

        let retire = sessions
            .begin_transaction(TEST_SESSION, "file:pkg/util.py")
            .unwrap();
        sessions
            .stage_transaction(
                &retire.transaction_id,
                vec![retired_source_file("pkg/util.py")],
            )
            .unwrap();
        let result = commit_exact_transaction(
            &state,
            &sessions,
            &HashMap::from([(
                "transaction_id".to_string(),
                serde_json::json!(retire.transaction_id),
            )]),
            None,
        );
        assert_ne!(result.is_error, Some(true), "{}", result_text(&result));

        // What `semantic_locate` and `get_context_pack` rank.
        assert!(
            state.graph.get_entity(&helper.id).unwrap().is_none(),
            "a retired file's entity still resolves, so it can still be ranked"
        );
        // What `find_references` reads, from the surviving side of the edge.
        assert!(
            !crossing(state.graph.as_ref()),
            "an entity in an untouched file still holds an edge into the retired file"
        );
        // What the file count reads.
        let bearing = state.graph.entity_bearing_file_paths();
        assert!(
            !bearing.contains(&"pkg/util.py".to_string()),
            "a retired path is still counted as an entity-bearing file: {bearing:?}"
        );
        assert!(
            bearing.contains(&"pkg/app.py".to_string()),
            "the untouched file left the count too, so this proves nothing: {bearing:?}"
        );
        // What the vector index is fed from. kin-db drops the retrieval key for
        // every removed entity in the same call that removes it, so a store
        // that never built an index still shows the eviction here.
        #[cfg(feature = "vector")]
        assert!(
            state.graph.pending_embeddings() < queued_before,
            "the retired entities are still queued for embedding: {} of {queued_before}",
            state.graph.pending_embeddings()
        );
        // The survivor keeps its own entity, so the eviction was scoped.
        assert!(
            state.graph.get_entity(&run.id).unwrap().is_some(),
            "retiring one file took an entity out of another"
        );
    }

    /// A `delete` naming a path the graph does not track is refused by name.
    ///
    /// Answering "already gone, nothing to do" would be the worse failure. A
    /// caller that mistyped a path would be told its file left the graph while
    /// the real one kept ranking, which is the FIR-2419 symptom arriving by a
    /// second route.
    #[test]
    fn retiring_a_path_the_graph_does_not_track_is_refused_by_name() {
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
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![retired_source_file("src/never_existed.rs")],
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
        let text = result_text(&result);
        assert!(
            text.contains("src/never_existed.rs is not tracked by repository authority"),
            "refusal must name the path it could not retire: {text}"
        );

        // The refusal is not merely a message: the file it did not name is
        // untouched.
        let after = load_native_commit_base(&state.layout).unwrap();
        assert!(after
            .tree
            .artifact_at_path(&test_path("src/lib.rs"))
            .is_some());
    }

    /// Two file-level operations on one path are refused by name, before
    /// anything is planned.
    ///
    /// The three shapes are planned in a fixed order and each is checked
    /// against the base tree when it is recorded, so an overlap is invisible
    /// until the second operation meets a tree the first one already moved.
    /// What comes back then names an internal planning step, not the pair the
    /// caller wrote. Two operations on one path also have no unambiguous
    /// meaning, so ordering them would publish a guess.
    #[test]
    fn overlapping_file_level_operations_on_one_path_are_refused_by_name() {
        let (_dir, state) = test_state();
        install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        install_exact_source(
            &state,
            "src/other.rs",
            b"pub fn other() -> u8 { 2 }\n",
            "other",
        );
        let sessions = test_sessions();

        let commit_with = |operations: Vec<kin_mcp::McpMutationOperation>| {
            let transaction = sessions
                .begin_transaction(TEST_SESSION, "file:src/lib.rs")
                .unwrap();
            sessions
                .stage_transaction(&transaction.transaction_id, operations)
                .unwrap();
            commit_exact_transaction(
                &state,
                &sessions,
                &HashMap::from([(
                    "transaction_id".to_string(),
                    serde_json::json!(transaction.transaction_id),
                )]),
                None,
            )
        };

        let both = commit_with(vec![
            retired_source_file("src/lib.rs"),
            renamed_source_file("src/lib.rs", "src/moved.rs"),
        ]);
        assert_eq!(both.is_error, Some(true));
        assert!(
            result_text(&both).contains("is both retired and renamed in one transaction"),
            "{}",
            result_text(&both)
        );

        let collide = commit_with(vec![
            renamed_source_file("src/lib.rs", "src/dest.rs"),
            renamed_source_file("src/other.rs", "src/dest.rs"),
        ]);
        assert_eq!(collide.is_error, Some(true));
        assert!(
            result_text(&collide).contains("two files are renamed onto src/dest.rs"),
            "{}",
            result_text(&collide)
        );

        // The control: the same two renames onto distinct destinations are not
        // an overlap, so this refusal is about collisions rather than about
        // refusing every multi-operation transaction.
        let fine = commit_with(vec![
            renamed_source_file("src/lib.rs", "src/one.rs"),
            renamed_source_file("src/other.rs", "src/two.rs"),
        ]);
        assert_ne!(fine.is_error, Some(true), "{}", result_text(&fine));

        // Neither end of the refused pairs moved.
        let after = load_native_commit_base(&state.layout).unwrap();
        assert!(after
            .tree
            .artifact_at_path(&test_path("src/one.rs"))
            .is_some());
        assert!(after
            .tree
            .artifact_at_path(&test_path("src/two.rs"))
            .is_some());
        assert!(after
            .tree
            .artifact_at_path(&test_path("src/dest.rs"))
            .is_none());
    }

    /// A rename moves the file and everything keeps its identity.
    ///
    /// This is the half of FIR-2429 that a retirement cannot cover. A rename is
    /// a removal at one path and an arrival at another, and doing it as that
    /// pair mints new entity ids and orphans every incoming reference, so the
    /// history of the code that moved is lost and every caller of it stops
    /// resolving. Repository authority says as much from its own side: it
    /// refuses a transition that leaves an entity on a path the staged tree no
    /// longer carries unless the same delta carries its removal OR RELOCATION.
    /// This is the relocation.
    ///
    /// The incoming edge is asserted because it is what `find_references` reads.
    /// A move that kept the entity but dropped its callers would still report a
    /// renamed function as referenced by nothing.
    #[test]
    fn renaming_a_tracked_file_over_mcp_keeps_entity_identity_and_incoming_edges() {
        let (_dir, state) = test_state();
        let sessions = test_sessions();

        // Two files created in one transaction so the second really references
        // the first; the planner seeds its cross-file linker for exactly this.
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:pkg/app.py")
            .unwrap();
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![
                    new_source_file("pkg/util.py", NEW_UTIL_PY),
                    new_source_file("pkg/app.py", NEW_APP_PY),
                ],
            )
            .unwrap();
        let created = commit_exact_transaction(
            &state,
            &sessions,
            &HashMap::from([(
                "transaction_id".to_string(),
                serde_json::json!(transaction.transaction_id),
            )]),
            None,
        );
        assert_ne!(created.is_error, Some(true), "{}", result_text(&created));

        let before = load_native_commit_base(&state.layout).unwrap();
        let helper = before
            .graph
            .query_entities(&EntityFilter {
                file_path: Some(FilePathId::new("pkg/util.py")),
                ..EntityFilter::default()
            })
            .unwrap()
            .into_iter()
            .find(|entity| entity.name == "helper")
            .expect("the fixture must hold helper");
        let referencing_before = before
            .graph
            .get_all_relations_for_entity(&helper.id)
            .unwrap()
            .len();
        assert!(
            referencing_before > 0,
            "the fixture produced no edges on helper, so nothing below proves they survived"
        );

        let moved = sessions
            .begin_transaction(TEST_SESSION, "file:pkg/util.py")
            .unwrap();
        let operations = vec![renamed_source_file("pkg/util.py", "pkg/core/util.py")];
        kin_mcp::session::validate_staged_operations(&operations)
            .expect("staging must accept the rename form");
        sessions
            .stage_transaction(&moved.transaction_id, operations)
            .unwrap();
        let result = commit_exact_transaction(
            &state,
            &sessions,
            &HashMap::from([(
                "transaction_id".to_string(),
                serde_json::json!(moved.transaction_id),
            )]),
            None,
        );
        assert_ne!(
            result.is_error,
            Some(true),
            "renaming a tracked file over MCP failed: {}",
            result_text(&result)
        );

        let after = load_native_commit_base(&state.layout).unwrap();
        assert!(
            after
                .tree
                .artifact_at_path(&test_path("pkg/util.py"))
                .is_none(),
            "the origin path is still tracked after a rename"
        );
        let destination = after
            .tree
            .artifact_at_path(&test_path("pkg/core/util.py"))
            .expect("the destination path must be tracked after a rename");
        assert_eq!(
            destination.artifact_id,
            before
                .tree
                .artifact_at_path(&test_path("pkg/util.py"))
                .unwrap()
                .artifact_id,
            "a rename must keep artifact identity; a new id is a delete plus a create"
        );

        let relocated = after
            .graph
            .get_entity(&helper.id)
            .unwrap()
            .expect("a rename must keep the entity id it moved");
        assert_eq!(
            relocated.file_origin,
            Some(FilePathId::new("pkg/core/util.py")),
            "the relocated entity still claims its old path"
        );
        assert_eq!(
            after
                .graph
                .get_all_relations_for_entity(&helper.id)
                .unwrap()
                .len(),
            referencing_before,
            "a rename dropped edges incident to the entity it moved"
        );
        assert!(
            state
                .graph
                .get_file_layout(&FilePathId::new("pkg/core/util.py"))
                .unwrap()
                .is_some(),
            "the layout must move with the file on the live query graph"
        );
        assert!(
            state
                .graph
                .get_file_layout(&FilePathId::new("pkg/util.py"))
                .unwrap()
                .is_none(),
            "the layout must not stay behind at the old path"
        );

        // The bytes travelled unchanged, and the working copy is the projection
        // of what committed rather than anything the agent wrote.
        assert_eq!(
            std::fs::read_to_string(state.layout.working_dir().join("pkg/core/util.py")).unwrap(),
            NEW_UTIL_PY
        );
        assert!(
            !state.layout.working_dir().join("pkg/util.py").exists(),
            "the origin file must go with the rename"
        );
    }

    /// A rename onto a path the graph already tracks is refused by name.
    #[test]
    fn renaming_onto_a_tracked_path_is_refused_by_name() {
        let (_dir, state) = test_state();
        install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        install_exact_source(
            &state,
            "src/other.rs",
            b"pub fn other() -> u8 { 2 }\n",
            "other",
        );
        let sessions = test_sessions();
        let transaction = sessions
            .begin_transaction(TEST_SESSION, "file:src/lib.rs")
            .unwrap();
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![renamed_source_file("src/lib.rs", "src/other.rs")],
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
        let text = result_text(&result);
        assert!(
            text.contains("src/other.rs is already tracked by repository authority"),
            "refusal must name the destination it would have overwritten: {text}"
        );

        // Neither end moved.
        let after = load_native_commit_base(&state.layout).unwrap();
        assert!(after
            .tree
            .artifact_at_path(&test_path("src/lib.rs"))
            .is_some());
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/other.rs")).unwrap(),
            b"pub fn other() -> u8 { 2 }\n"
        );
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
            destination: None,
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
                    destination: None,
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
                // The DEFAULT, so these keep grading the shape a caller gets
                // without asking for anything.
                all_revisions: false,
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
                // The DEFAULT, so these keep grading the shape a caller gets
                // without asking for anything.
                all_revisions: false,
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
            events[0]["target_scope"],
            serde_json::json!(format!("entity:{}", subject.id)),
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

    /// The newest write is the one provenance reports, through the real commit path.
    ///
    /// `get_entity_history` hands back an entity's changes oldest first, so
    /// reading the head of that list named the change that introduced the entity
    /// and dropped every write since. An entity with one change cannot show
    /// that, which is why this commits twice: the second agent's write is the
    /// answer, and the first agent's is what the defect returned instead. The
    /// same selector picks the change whose approvals are reported, so a stale
    /// pick answers "has this been signed off" about the wrong change too.
    #[test]
    fn provenance_reports_the_newest_write_not_the_change_that_introduced_the_entity() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let sessions = kin_mcp::SessionRegistry::new();

        let first = start_agent_session(&sessions, "claude-code", "earlier-session");
        let first_result = commit_one_entity_edit(
            &state,
            &sessions,
            &first.session_id.to_string(),
            &entity,
            "pub fn value() -> u8 { 2 }",
        );
        assert_ne!(
            first_result.is_error,
            Some(true),
            "first commit failed: {}",
            result_text(&first_result)
        );
        let first_body: serde_json::Value =
            serde_json::from_str(result_text(&first_result)).unwrap();

        let second = start_agent_session(&sessions, "codex", "later-session");
        let second_result = commit_one_entity_edit(
            &state,
            &sessions,
            &second.session_id.to_string(),
            &entity,
            "pub fn value() -> u8 { 3 }",
        );
        assert_ne!(
            second_result.is_error,
            Some(true),
            "second commit failed: {}",
            result_text(&second_result)
        );
        let second_body: serde_json::Value =
            serde_json::from_str(result_text(&second_result)).unwrap();
        assert_ne!(
            first_body["change_id"], second_body["change_id"],
            "the two commits must be distinct changes for this to discriminate"
        );

        let provenance = kin_mcp::handlers::provenance::handle_provenance_query(
            &HashMap::from([(
                "entity_id".to_string(),
                serde_json::json!(entity.id.to_string()),
            )]),
            state.graph.as_ref(),
        )
        .unwrap();
        let provenance: serde_json::Value = serde_json::from_str(result_text(&provenance)).unwrap();

        assert_eq!(
            provenance["latest_change"]["id"], second_body["change_id"],
            "latest_change must be the write that landed last: {provenance}"
        );
        assert!(
            provenance["latest_change"]["author"]
                .as_str()
                .unwrap()
                .contains(&format!("mcp-agent:{}", second.session_id)),
            "latest_change must carry the agent that made it: {provenance}"
        );
        assert_eq!(
            provenance["changes"][0]["id"], second_body["change_id"],
            "the change page is newest first: {provenance}"
        );
        assert_eq!(
            provenance["changes"][1]["id"], first_body["change_id"],
            "the earlier write is still reachable, one page down: {provenance}"
        );
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
                    destination: None,
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
                    destination: None,
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
                // The DEFAULT, so these keep grading the shape a caller gets
                // without asking for anything.
                all_revisions: false,
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
                    destination: None,
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
                        destination: None,
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: "no_such_entity".to_string(),
                        payload: None,
                        body: Some("pub fn no_such_entity() {}".to_string()),
                        description: String::new(),
                        destination: None,
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
                    destination: None,
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
                    destination: None,
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
                    destination: None,
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
                        destination: None,
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: nested.id.to_string(),
                        payload: None,
                        body: Some("    pub fn nested() -> u8 {\n        2\n    }".to_string()),
                        description: "module-nested function".to_string(),
                        destination: None,
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: top_level.id.to_string(),
                        payload: None,
                        body: Some("pub fn plain() -> u8 {\n    2\n}".to_string()),
                        description: "top-level function".to_string(),
                        destination: None,
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
                    destination: None,
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
                        destination: None,
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: preprocessor.id.to_string(),
                        payload: None,
                        body: Some(NEW_PREPROCESSOR.to_string()),
                        description: "pass None".to_string(),
                        destination: None,
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: "commands".to_string(),
                        payload: None,
                        body: Some(NEW_COMMANDS.to_string()),
                        description: "pass None, targeted by bare name".to_string(),
                        destination: None,
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
                        destination: None,
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: preprocessor.id.to_string(),
                        payload: None,
                        body: Some(NEW_PREPROCESSOR.to_string()),
                        description: "pass None".to_string(),
                        destination: None,
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: commands.id.to_string(),
                        payload: None,
                        body: Some(NEW_COMMANDS.to_string()),
                        description: "pass None".to_string(),
                        destination: None,
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
                        destination: None,
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: "no_such_entity".to_string(),
                        payload: None,
                        body: Some("pub fn no_such_entity() {}".to_string()),
                        description: String::new(),
                        destination: None,
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
                        destination: None,
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
                destination: None,
            }],
            commit_payload_hash: None,
            last_activity_at: kin_model::timestamp::Timestamp::now(),
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
                    destination: None,
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
                    destination: None,
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
                        destination: None,
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: shadow.id.to_string(),
                        payload: Some(kin_mcp::McpMutationPayload::Entity(shadow.clone())),
                        body: Some("pub fn shadow() -> u8 { 3 }".to_string()),
                        description: String::new(),
                        destination: None,
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

    /// Rewrite one authority-owned entity in the live graph the way parser
    /// reconciliation does: in place, under the graph-authority epoch alone,
    /// holding neither the coordination gate nor the persistence lock.
    fn rewrite_authority_entity_in_live_graph(state: &Arc<DaemonState>, entity: &Entity) -> Entity {
        use kin_model::EntityStore;
        let mut rewritten = entity.clone();
        rewritten.doc_summary = Some("derived summary the enrichment worker computed".to_string());
        let guard = state.begin_graph_authority_mutation();
        state.graph.upsert_entity(&rewritten).unwrap();
        state.bump_version();
        drop(guard);
        rewritten
    }

    /// A derived REWRITE of an authority-owned entity must not refuse a commit.
    ///
    /// Parser reconciliation and the LSP worker rewrite existing entities
    /// continuously and outside the coordination gate, so refusing on a rewrite
    /// refuses every commit that follows any tick, naming a different entity
    /// each attempt. The instruction such a refusal carries, to re-send once the
    /// daemon reads current authority, can then never converge: the worker wins
    /// the race every time and only a daemon recycle clears it.
    #[test]
    fn a_commit_after_a_derived_entity_rewrite_is_not_refused() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let before = load_native_commit_base(&state.layout).unwrap();
        let rewritten = rewrite_authority_entity_in_live_graph(&state, &entity);
        assert!(
            !semantic_workspace_matches(state.graph.as_ref(), &before.graph),
            "the rewrite must put the live graph out of step with authority, or this test proves \
             nothing about the refusal it exists to falsify"
        );

        let sessions = test_sessions();
        let (_, arguments) = stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "a commit issued after a derived entity rewrite must not be refused: {}",
            result_text(&result)
        );

        let after = load_native_commit_base(&state.layout).unwrap();
        assert_eq!(after.roots.generation, before.roots.generation + 1);
        assert_eq!(
            after
                .graph
                .to_snapshot()
                .entities
                .get(&entity.id)
                .expect("the entity must survive the commit")
                .doc_summary,
            None,
            "the derived summary must not be absorbed into the published change"
        );
        assert_ne!(
            rewritten.doc_summary, None,
            "the fixture must actually have written a derived value"
        );
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            b"pub fn value() -> u8 { 2 }\n"
        );
    }

    /// Losing an entity authority owns is still divergence: a derived view may
    /// hold more than authority, and may hold a richer value for what authority
    /// owns, but it may never hold less.
    #[test]
    fn a_commit_is_refused_when_the_live_graph_has_dropped_an_authority_entity() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\npub fn other() -> u8 { 3 }\n",
            "value",
        );
        let dropped = load_native_commit_base(&state.layout)
            .unwrap()
            .graph
            .to_snapshot()
            .entities
            .into_values()
            .find(|candidate| candidate.id != entity.id)
            .expect("the fixture must own a second entity to drop");
        let guard = state.begin_graph_authority_mutation();
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![EntityDelta::Removed { old: dropped }],
                ..TransactionDelta::default()
            })
            .unwrap();
        state.bump_version();
        drop(guard);

        let sessions = test_sessions();
        let (_, arguments) = stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_eq!(
            result.is_error,
            Some(true),
            "a commit must be refused while the daemon holds less than authority owns"
        );
        assert!(
            result_text(&result).contains("is missing"),
            "the refusal must name the loss: {}",
            result_text(&result)
        );
    }

    /// A retry of a commit whose record is gone must be answered from the
    /// repository receipt, not reported as a missing transaction.
    ///
    /// A successful commit evicts its own record, and a client whose per-attempt
    /// budget expired during a long apply retries straight into that gap. The
    /// old answer, `Transaction not found`, reported failure over a commit whose
    /// file, entity, and provenance had all landed, which is a double-apply
    /// generator because any correct agent retries a failure.
    #[test]
    fn a_retry_of_an_evicted_committed_transaction_answers_from_the_receipt() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let sessions = test_sessions();
        let (transaction_id, arguments) =
            stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let first = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(first.is_error, Some(true), "{}", result_text(&first));
        let first_body: serde_json::Value = serde_json::from_str(result_text(&first)).unwrap();
        let generation_after_first = load_native_commit_base(&state.layout)
            .unwrap()
            .roots
            .generation;

        // Exactly what a successful commit leaves behind for the next attempt:
        // the durable store and the live registry both forget the transaction.
        state
            .mcp_transactions
            .lock()
            .unwrap()
            .remove(&transaction_id);
        let retry_sessions = test_sessions();
        assert!(
            retry_sessions.get_transaction(&transaction_id).is_none(),
            "the fixture must reproduce the evicted-record state the retry actually meets"
        );

        let retry = commit_exact_transaction(&state, &retry_sessions, &arguments, None);
        assert_ne!(
            retry.is_error,
            Some(true),
            "a retry of an applied commit must not report failure: {}",
            result_text(&retry)
        );
        let retry_body: serde_json::Value = serde_json::from_str(result_text(&retry)).unwrap();
        assert_eq!(retry_body["status"], "committed");
        assert_eq!(retry_body["already_applied"], true);
        assert_eq!(retry_body["change_id"], first_body["change_id"]);
        assert_eq!(
            load_native_commit_base(&state.layout)
                .unwrap()
                .roots
                .generation,
            generation_after_first,
            "answering the retry must not publish a second repository generation"
        );
    }

    /// `already_applied` must separate a first application from a replay, and
    /// it is the only field that can.
    ///
    /// A replay restates the original change id, repository generation, and
    /// root hash exactly, which is what makes the idempotency correct and also
    /// what makes it invisible. The field was emitted only on the replay path,
    /// where it is hardcoded true, and was absent from the reply a fresh commit
    /// returns, so no code path could ever answer false and a caller deciding
    /// whether its retry double-applied had nothing to read.
    #[test]
    fn already_applied_separates_a_first_application_from_a_replay() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let sessions = test_sessions();
        let (transaction_id, arguments) =
            stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");

        let first = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(first.is_error, Some(true), "{}", result_text(&first));
        let first_body: serde_json::Value = serde_json::from_str(result_text(&first)).unwrap();
        assert_eq!(
            first_body["already_applied"],
            serde_json::json!(false),
            "a first-ever application must report that it moved authority: {}",
            result_text(&first)
        );

        // Exactly what a successful commit leaves behind for the next attempt.
        state
            .mcp_transactions
            .lock()
            .unwrap()
            .remove(&transaction_id);
        let retry_sessions = test_sessions();
        let retry = commit_exact_transaction(&state, &retry_sessions, &arguments, None);
        assert_ne!(retry.is_error, Some(true), "{}", result_text(&retry));
        let retry_body: serde_json::Value = serde_json::from_str(result_text(&retry)).unwrap();
        assert_eq!(
            retry_body["already_applied"],
            serde_json::json!(true),
            "an exact replay must report that it published nothing further: {}",
            result_text(&retry)
        );

        assert_eq!(retry_body["change_id"], first_body["change_id"]);
        assert_eq!(retry_body["new_root_hash"], first_body["new_root_hash"]);
        assert_eq!(
            retry_body["repository_generation"], first_body["repository_generation"],
            "the two replies agree on every fact about the change, which is why \
             already_applied is the only bit that can carry the distinction"
        );
    }

    /// Resuming a fenced commit is a replay too, and must say so.
    ///
    /// The publication crashed after the repository receipt existed, so
    /// authority moved under the earlier attempt. The resume recovers that
    /// receipt and publishes nothing, which is the same fact the evicted-record
    /// retry reports and reaches the caller through a different path.
    #[test]
    fn a_resumed_fenced_commit_reports_that_authority_had_already_moved() {
        let (_dir, state) = test_state();
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
        let crashed = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_eq!(crashed.is_error, Some(true), "{}", result_text(&crashed));
        assert_eq!(
            sessions.get_transaction(&transaction_id).unwrap().state,
            "committing"
        );

        let resumed = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(resumed.is_error, Some(true), "{}", result_text(&resumed));
        let resumed_body: serde_json::Value = serde_json::from_str(result_text(&resumed)).unwrap();
        assert_eq!(
            resumed_body["already_applied"],
            serde_json::json!(true),
            "a resume recovers a receipt an earlier attempt published: {}",
            result_text(&resumed)
        );
    }

    /// An id that never named a transaction still fails closed, and says it
    /// checked repository authority too, so the caller can tell "already landed"
    /// apart from "nothing was ever published under this id".
    #[test]
    fn a_commit_for_an_unknown_transaction_id_still_fails_closed() {
        let (_dir, state) = test_state();
        install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let sessions = test_sessions();
        let arguments = HashMap::from([(
            "transaction_id".to_string(),
            serde_json::json!(uuid::Uuid::new_v4().to_string()),
        )]);
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_eq!(result.is_error, Some(true));
        let message = result_text(&result);
        assert!(message.contains("Transaction not found"), "{message}");
        assert!(
            message.contains("holds no receipt"),
            "the refusal must say authority was consulted as well: {message}"
        );
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

    /// A store somebody has been working in commits in one pass, and says what
    /// it took with it.
    ///
    /// The workspace here holds an admitted edit to a file no staged operation
    /// names, which is the state the commit path used to refuse with "requires a
    /// clean exact workspace". The pending content is inside the prospective
    /// graph either way, so the only honest options were publishing it or
    /// reverting the working file. It is published, and both the reply and the
    /// change record name it as carried rather than presenting it as the agent's
    /// work.
    #[test]
    fn a_commit_carrying_pending_working_tree_content_declares_it_in_the_reply_and_the_record() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        install_exact_source(
            &state,
            "src/other.rs",
            b"pub fn other() -> u8 { 1 }\n",
            "other",
        );
        admit_pending_working_tree_edit(&state, "src/other.rs", b"pub fn other() -> u8 { 7 }\n");

        let sessions = test_sessions();
        let (_, arguments) = stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "a workspace holding pending content must still commit: {}",
            result_text(&result)
        );

        let reply = commit_reply(&result);
        assert_eq!(
            reply["staged_operation_files"],
            serde_json::json!(["src/lib.rs"]),
            "the reply must separate the files the operations wrote: {reply:#}"
        );
        assert_eq!(
            reply["carried_pending_files"],
            serde_json::json!(["src/other.rs"]),
            "the reply must name the files it carried in: {reply:#}"
        );
        assert_eq!(
            reply["modified_files"],
            serde_json::json!(["src/lib.rs", "src/other.rs"]),
            "the split covers modified_files rather than replacing it: {reply:#}"
        );

        let change_id = reply["change_id"].as_str().unwrap().to_string();
        let change = state
            .graph
            .get_entity_history(&entity.id)
            .unwrap()
            .into_iter()
            .find(|change| change.id.to_string() == change_id)
            .expect("the published change is reachable from the entity the operation wrote");
        assert!(
            change
                .message
                .contains("also admitted 1 pending working-tree file"),
            "the change record must state the fold and its count: {}",
            change.message
        );
        assert!(
            change.message.contains("src/other.rs"),
            "the change record must sample what it carried: {}",
            change.message
        );

        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            b"pub fn value() -> u8 { 2 }\n",
            "the staged edit reaches the working file"
        );
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/other.rs")).unwrap(),
            b"pub fn other() -> u8 { 7 }\n",
            "the carried file keeps the bytes the human left in it"
        );
        assert!(
            !workspace_is_dirty(&state),
            "the commit must leave the workspace level with its base"
        );
    }

    /// The closing arm: a file nothing did but write is carried by the next
    /// commit and named as carried.
    ///
    /// The pending content here comes from the real watcher path rather than
    /// from a delta assembled to look like one, because the composition is the
    /// claim. Writing the file is the whole of the user's action: ambient
    /// admission puts it in the workspace tree without moving the base, and the
    /// commit that follows publishes it while stating plainly that its author
    /// did not write it. Either half alone is defensible and useless; a file
    /// that becomes queryable and then gets published as somebody's work is
    /// worse than one that never appeared.
    #[test]
    fn a_commit_declares_a_watcher_admitted_file_as_carried() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );

        // Nothing here but a write and the notification it produces.
        let written = state.layout.working_dir().join("src/brand_new.rs");
        std::fs::write(&written, b"pub fn brand_new() -> u8 { 1 }\n").unwrap();
        crate::loop_runner::admit_one_ambient_host_event(&state, written).unwrap();
        assert!(
            state
                .graph
                .resolved_tree()
                .artifact_at_path(&RepoPath::from_utf8("src/brand_new.rs").unwrap())
                .is_some(),
            "the watcher pass must have admitted the new file before the commit sees it"
        );

        let sessions = test_sessions();
        let (_, arguments) = stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "a workspace carrying a watcher-admitted file must still commit: {}",
            result_text(&result)
        );

        let reply = commit_reply(&result);
        assert_eq!(
            reply["staged_operation_files"],
            serde_json::json!(["src/lib.rs"]),
            "the reply must keep the operations' own file separate: {reply:#}"
        );
        assert_eq!(
            reply["carried_pending_files"],
            serde_json::json!(["src/brand_new.rs"]),
            "a file the watcher admitted is carried, not authored: {reply:#}"
        );

        let change_id = reply["change_id"].as_str().unwrap().to_string();
        let change = state
            .graph
            .get_entity_history(&entity.id)
            .unwrap()
            .into_iter()
            .find(|change| change.id.to_string() == change_id)
            .expect("the published change is reachable from the entity the operation wrote");
        assert!(
            change.message.contains("src/brand_new.rs"),
            "the permanent record must name what it carried: {}",
            change.message
        );
        assert!(
            !workspace_is_dirty(&state),
            "the commit must leave the workspace level with its base"
        );
    }

    /// A workspace with nothing pending answers exactly as it did before the
    /// fold existed.
    ///
    /// The discriminating half of the pair: a declaration that appears on every
    /// commit is a declaration nobody reads, so the keys and the message have to
    /// be absent when there is nothing to declare.
    #[test]
    fn a_commit_from_a_clean_workspace_declares_no_fold_at_all() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );

        let sessions = test_sessions();
        let (transaction_id, arguments) =
            stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(result.is_error, Some(true), "{}", result_text(&result));

        let reply = commit_reply(&result);
        assert!(
            reply.get("staged_operation_files").is_none()
                && reply.get("carried_pending_files").is_none(),
            "a clean commit answers with the flat file list it always did: {reply:#}"
        );
        assert_eq!(reply["modified_files"], serde_json::json!(["src/lib.rs"]));

        let change_id = reply["change_id"].as_str().unwrap().to_string();
        let change = state
            .graph
            .get_entity_history(&entity.id)
            .unwrap()
            .into_iter()
            .find(|change| change.id.to_string() == change_id)
            .expect("the published change is reachable from the entity it wrote");
        assert_eq!(
            change.message,
            format!("MCP transaction {transaction_id}"),
            "a clean commit's message stays byte-identical"
        );
    }

    /// The retry that a slow commit guarantees is told about the fold too.
    ///
    /// This is the reply a real caller reads. The MCP client budgets 60 seconds
    /// per attempt, a commit on a store of any size takes longer, and the
    /// duplicate request that follows is answered from the repository receipt
    /// after the first attempt has evicted its own transaction record. A split
    /// that only the planning process could produce would therefore never reach
    /// anyone, so the fold is recorded in the commit's own attribution and read
    /// back here.
    #[test]
    fn a_retry_of_an_evicted_commit_still_declares_what_that_commit_carried() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        install_exact_source(
            &state,
            "src/other.rs",
            b"pub fn other() -> u8 { 1 }\n",
            "other",
        );
        admit_pending_working_tree_edit(&state, "src/other.rs", b"pub fn other() -> u8 { 7 }\n");

        let sessions = test_sessions();
        let (transaction_id, arguments) =
            stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let first = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(first.is_error, Some(true), "{}", result_text(&first));
        let first_reply = commit_reply(&first);

        // Exactly what a successful commit leaves behind for the retry: the
        // durable store and the live registry both forget the transaction.
        state
            .mcp_transactions
            .lock()
            .unwrap()
            .remove(&transaction_id);
        let retry_sessions = test_sessions();
        assert!(retry_sessions.get_transaction(&transaction_id).is_none());

        let retry = commit_exact_transaction(&state, &retry_sessions, &arguments, None);
        assert_ne!(retry.is_error, Some(true), "{}", result_text(&retry));
        let retry_reply = commit_reply(&retry);
        assert_eq!(retry_reply["already_applied"], true);
        assert_eq!(retry_reply["change_id"], first_reply["change_id"]);
        assert_eq!(
            retry_reply["carried_pending_files"], first_reply["carried_pending_files"],
            "the retry must declare the same fold the first answer did: {retry_reply:#}"
        );
        assert_eq!(
            retry_reply["staged_operation_files"],
            first_reply["staged_operation_files"]
        );
        assert_eq!(
            retry_reply["carried_pending_files"],
            serde_json::json!(["src/other.rs"])
        );
    }

    /// Carrying a file in never rewrites who authored what is inside it.
    ///
    /// A carried file reaches the change as a tree delta AND the semantics those
    /// bytes derive to, because a change that published one without the other
    /// would seal a tree and an entity set describing different source. So its
    /// entities do gain a revision, and that revision is a statement about
    /// content, not about authorship: the entity keeps its id and the change it
    /// was created in, and no attribution event names it, which is what keeps a
    /// provenance reader from being told the agent wrote a human's uncommitted
    /// work. The fold is also reachable from provenance one level up, because
    /// the change every attributed entity names carries the declaration in its
    /// message.
    ///
    /// The assertion that the carried entity's history did NOT contain this
    /// change was here until the incoherence it described was fixed. It could
    /// not survive the fix and be true at the same time: `get_entity_history`
    /// selects changes by scanning entity deltas, so the only change that
    /// satisfies it is one that publishes bytes for a file and no semantics for
    /// them. What that assertion was protecting is below, in the origin change
    /// and the attribution, and it is asserted there rather than through the
    /// absence of a revision.
    #[test]
    fn a_carried_file_keeps_the_authorship_its_entities_already_had() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let (carried_entity, installed_change) = install_exact_source(
            &state,
            "src/other.rs",
            b"pub fn other() -> u8 { 1 }\n",
            "other",
        );
        admit_pending_working_tree_edit(&state, "src/other.rs", b"pub fn other() -> u8 { 7 }\n");

        let sessions = test_sessions();
        let (_, arguments) = stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
        let reply = commit_reply(&result);
        let change_id = reply["change_id"].as_str().unwrap().to_string();

        let carried_history = state.graph.get_entity_history(&carried_entity.id).unwrap();
        assert!(
            carried_history
                .iter()
                .any(|change| change.id.to_string() == change_id),
            "the change that republished the carried file's bytes must carry its semantics too, \
             or it seals a tree and an entity set describing different source"
        );
        assert_eq!(
            carried_history.first().map(|change| change.id),
            Some(installed_change),
            "the carried file's entity keeps the change it was created in"
        );
        assert_eq!(
            state
                .graph
                .get_entity(&carried_entity.id)
                .unwrap()
                .map(|entity| (entity.name, entity.kind)),
            Some((carried_entity.name.clone(), carried_entity.kind)),
            "the carried file's entity keeps the identity it already had"
        );

        let attributed = state
            .graph
            .query_audit_events(None, 64)
            .unwrap()
            .into_iter()
            .filter(|event| {
                event.action == "kin_transaction_commit"
                    && event
                        .details
                        .as_deref()
                        .is_some_and(|details| details.contains(&change_id))
            })
            .filter_map(|event| match event.target_scope {
                Some(WorkScope::Entity(id)) => Some(id),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            attributed.contains(&entity.id),
            "the entity the operation wrote is attributed to the committing session"
        );
        assert!(
            !attributed.contains(&carried_entity.id),
            "no attribution event may name an entity inside a carried file"
        );

        // Reachability, from provenance rather than from the plan: the events
        // above name a change id, and that change states what it folded in.
        let declared = state
            .graph
            .get_entity_history(&entity.id)
            .unwrap()
            .into_iter()
            .find(|change| change.id.to_string() == change_id)
            .expect("the attributed change is loadable by the id its audit event names");
        assert!(
            declared.message.contains("src/other.rs"),
            "the change an audit event names must declare the fold: {}",
            declared.message
        );
    }

    /// How the store's own entities disagree with the exact bytes it publishes
    /// for one file.
    ///
    /// The oracle is Kin's own parser reading Kin's own CAS: the graph names a
    /// blob for the path, the blob is read back out of repository CAS rather
    /// than off the working copy, and the entities it parses to are compared
    /// with the entities the graph answers with for that file. `None` is a
    /// coherent file. Anything else is a file whose entities describe bytes the
    /// repository no longer holds, which is what a change that seals newer tree
    /// bytes over older semantic spans leaves behind.
    ///
    /// Read against the live graph on purpose. `install_authority_graph` levels
    /// it onto repository authority inside every commit reply and
    /// `verify_workspace_matches_authority` refuses if it did not, so after a
    /// commit the live graph, authority and the change just sealed are the same
    /// answer, and asking the cheapest of the three asks all of them.
    fn semantic_disagreement(state: &Arc<DaemonState>, file: &str) -> Option<String> {
        let file_id = FilePathId::new(file);
        let path = RepoPath::from_utf8(file).unwrap();
        let tree = state.graph.resolved_tree();
        let artifact = tree
            .artifact_at_path(&path)
            .unwrap_or_else(|| panic!("the store must publish {file}"));
        let TreeEntry::Blob { hash, .. } = artifact.entry else {
            panic!("{file} must be a blob in the published tree");
        };
        let body = load_native_source_blob(&state.layout, hash)
            .unwrap_or_else(|error| panic!("repository CAS must hold the body of {file}: {error}"));
        let digest = state.blobs.write(&body).unwrap();
        let indexed = kin_index::IndexPipeline::new()
            .index_any_content(&file_id, &body, digest)
            .unwrap();
        let kin_index::IndexedAny::EntitySource(indexed) = indexed else {
            panic!("{file} must classify as supported source");
        };
        for parsed in &indexed.entities {
            let held = state
                .graph
                .query_entities(&EntityFilter {
                    name_pattern: Some(parsed.name.clone()),
                    file_path: Some(file_id.clone()),
                    ..EntityFilter::default()
                })
                .unwrap()
                .into_iter()
                .find(|entity| entity.name == parsed.name);
            let Some(held) = held else {
                return Some(format!(
                    "{file}: the published bytes declare {} and the store holds no entity by that \
                     name",
                    parsed.name
                ));
            };
            if held.fingerprint.behavior_hash != parsed.fingerprint.behavior_hash {
                return Some(format!(
                    "{file}: entity {} answers with behaviour hash {} while the exact bytes the \
                     store publishes for it parse to {}",
                    parsed.name, held.fingerprint.behavior_hash, parsed.fingerprint.behavior_hash
                ));
            }
            let held_span = held
                .span
                .as_ref()
                .map(|span| (span.start_byte, span.end_byte));
            let parsed_span = parsed
                .span
                .as_ref()
                .map(|span| (span.start_byte, span.end_byte));
            if held_span != parsed_span {
                return Some(format!(
                    "{file}: entity {} answers with span {held_span:?} while the exact bytes the \
                     store publishes for it place it at {parsed_span:?}",
                    parsed.name
                ));
            }
        }
        None
    }

    /// A commit over MCP must publish entities that describe the bytes it
    /// published, for a carried file as much as for an authored one.
    ///
    /// The two commit surfaces plan from different graphs. The CLI route is
    /// handed the daemon's live derived graph, which the reconcile loop keeps
    /// current, so a pending file's entities there came from the pending bytes.
    /// The MCP route is handed repository authority's own workspace graph
    /// snapshot, whose tree is the workspace tree and whose entities are
    /// whatever the last published semantic delta left, because
    /// `publish_workspace_tree` advances the tree with an empty
    /// `WorkspaceSemanticDelta`. `plan_exact_transaction` reparses only the
    /// files its staged operations name, so a carried file reaches the sealed
    /// change as new tree bytes over old entity spans and nothing on that path
    /// re-derives them.
    ///
    /// Declaring the carry does not make that acceptable. The declaration is
    /// about authorship, and this is about whether canonical truth agrees with
    /// itself.
    #[test]
    fn a_carried_immediate_edit_commits_entities_that_describe_the_bytes_it_published() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        install_exact_source(
            &state,
            "src/other.rs",
            b"pub fn other() -> u8 { 1 }\n",
            "other",
        );
        admit_pending_working_tree_edit(&state, "src/other.rs", b"pub fn other() -> u8 { 100 }\n");

        let sessions = test_sessions();
        let (_, arguments) = stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
        let reply = commit_reply(&result);
        assert_eq!(
            reply["carried_pending_files"],
            serde_json::json!(["src/other.rs"]),
            "the fixture must actually exercise the carry: {reply:#}"
        );

        // The control for the check itself. The authored file is re-derived by
        // the edit path, so a checker that could not tell a coherent file from
        // an incoherent one would report this one too.
        assert_eq!(
            semantic_disagreement(&state, "src/lib.rs"),
            None,
            "the file the operation authored must be coherent, or the check below proves nothing"
        );
        assert_eq!(
            semantic_disagreement(&state, "src/other.rs"),
            None,
            "the carried file's entities must describe the bytes this commit published for it"
        );
    }

    /// The same defect where no span moves, so only a fingerprint can catch it.
    ///
    /// `return 1` to `return 7` leaves every byte offset in the file identical,
    /// so a coherence check written as a span or a length comparison passes over
    /// it while the entity's body is still wrong. `behavior_hash` is the hash of
    /// an entity's full source text, so it is the field that moves, and this arm
    /// exists to keep the check honest about which one it reads.
    #[test]
    fn a_carried_same_length_body_edit_commits_entities_that_describe_the_bytes_it_published() {
        const BEFORE: &[u8] = b"pub fn other() -> u8 { 1 }\n";
        const AFTER: &[u8] = b"pub fn other() -> u8 { 7 }\n";
        assert_eq!(
            BEFORE.len(),
            AFTER.len(),
            "this arm's whole point is that no span moves"
        );

        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let (carried_entity, _) = install_exact_source(&state, "src/other.rs", BEFORE, "other");
        let span_before = carried_entity
            .span
            .as_ref()
            .map(|span| (span.start_byte, span.end_byte))
            .expect("an installed source entity has a span");
        admit_pending_working_tree_edit(&state, "src/other.rs", AFTER);

        let sessions = test_sessions();
        let (_, arguments) = stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
        let reply = commit_reply(&result);
        assert_eq!(
            reply["carried_pending_files"],
            serde_json::json!(["src/other.rs"]),
            "the fixture must actually exercise the carry: {reply:#}"
        );

        assert_eq!(
            semantic_disagreement(&state, "src/lib.rs"),
            None,
            "the file the operation authored must be coherent, or the check below proves nothing"
        );
        assert_eq!(
            semantic_disagreement(&state, "src/other.rs"),
            None,
            "the carried file's entities must describe the bytes this commit published for it, \
             including when the edit moved no byte offset"
        );

        let carried_after = state
            .graph
            .get_entity(&carried_entity.id)
            .unwrap()
            .expect("the carried entity keeps its identity across the commit");
        assert_eq!(
            carried_after
                .span
                .as_ref()
                .map(|span| (span.start_byte, span.end_byte)),
            Some(span_before),
            "a same-length edit must leave the span exactly where it was, so the assertion above \
             can only have been answered by the fingerprint"
        );
    }

    /// The same defect on a store nothing in this process derived.
    ///
    /// Reopening drops every graph this process built and rebuilds the daemon's
    /// view from what the store persisted, so the commit that follows plans
    /// against cold repository authority and cold source. If the incoherence
    /// were an artifact of live in-memory state carried across the admission it
    /// would not survive here; it does, because the snapshot the MCP route plans
    /// from is the persisted one.
    #[test]
    fn a_carried_edit_committed_after_a_reopen_publishes_entities_that_describe_its_tree() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        install_exact_source(
            &state,
            "src/other.rs",
            b"pub fn other() -> u8 { 1 }\n",
            "other",
        );
        admit_pending_working_tree_edit(&state, "src/other.rs", b"pub fn other() -> u8 { 7 }\n");

        let layout = state.layout.clone();
        drop(state);
        let state = Arc::new(DaemonState::open(layout).unwrap());

        let sessions = test_sessions();
        let (_, arguments) = stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
        let reply = commit_reply(&result);
        assert_eq!(
            reply["carried_pending_files"],
            serde_json::json!(["src/other.rs"]),
            "the fixture must actually exercise the carry: {reply:#}"
        );

        assert_eq!(
            semantic_disagreement(&state, "src/lib.rs"),
            None,
            "the file the operation authored must be coherent, or the check below proves nothing"
        );
        assert_eq!(
            semantic_disagreement(&state, "src/other.rs"),
            None,
            "a cold graph and cold source must still publish entities that describe the bytes the \
             commit published"
        );
    }

    /// The success contract a carried commit already has, held to while the
    /// semantics are repaired.
    ///
    /// Deriving a carried file's semantics into the commit is the fix, and the
    /// thing it could plausibly break is everything this asserts: the commit
    /// still lands, the reply and the change record still declare the fold, the
    /// carried entity keeps its identity and the change it was created in, and
    /// no attribution event names it. Republishing an entity's bytes is not the
    /// same as claiming its authorship, and this is where the two stay separate.
    #[test]
    fn a_coherent_carried_pending_commit_still_succeeds_and_declares_the_carry() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let (carried_entity, installed_change) = install_exact_source(
            &state,
            "src/other.rs",
            b"pub fn other() -> u8 { 1 }\n",
            "other",
        );
        admit_pending_working_tree_edit(&state, "src/other.rs", b"pub fn other() -> u8 { 7 }\n");

        let sessions = test_sessions();
        let (_, arguments) = stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "a workspace holding pending content must still commit: {}",
            result_text(&result)
        );
        let reply = commit_reply(&result);
        let change_id = reply["change_id"].as_str().unwrap().to_string();
        assert_eq!(
            reply["staged_operation_files"],
            serde_json::json!(["src/lib.rs"])
        );
        assert_eq!(
            reply["carried_pending_files"],
            serde_json::json!(["src/other.rs"])
        );
        assert_eq!(
            reply["modified_files"],
            serde_json::json!(["src/lib.rs", "src/other.rs"])
        );

        let declared = state
            .graph
            .get_entity_history(&entity.id)
            .unwrap()
            .into_iter()
            .find(|change| change.id.to_string() == change_id)
            .expect("the published change is reachable from the entity the operation wrote");
        assert!(
            declared
                .message
                .contains("also admitted 1 pending working-tree file")
                && declared.message.contains("src/other.rs"),
            "the change record must still state the fold and sample it: {}",
            declared.message
        );

        let carried_after = state
            .graph
            .get_entity(&carried_entity.id)
            .unwrap()
            .expect("the carried entity keeps the identity it already had");
        assert_eq!(carried_after.name, carried_entity.name);
        assert_eq!(carried_after.kind, carried_entity.kind);
        assert_eq!(
            state
                .graph
                .get_entity_history(&carried_entity.id)
                .unwrap()
                .first()
                .map(|change| change.id),
            Some(installed_change),
            "the carried entity keeps the change it was created in"
        );

        let attributed = state
            .graph
            .query_audit_events(None, 64)
            .unwrap()
            .into_iter()
            .filter(|event| {
                event.action == "kin_transaction_commit"
                    && event
                        .details
                        .as_deref()
                        .is_some_and(|details| details.contains(&change_id))
            })
            .filter_map(|event| match event.target_scope {
                Some(WorkScope::Entity(id)) => Some(id),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            attributed.contains(&entity.id),
            "the entity the operation wrote is attributed to the committing session"
        );
        assert!(
            !attributed.contains(&carried_entity.id),
            "republishing a carried entity's bytes must not attribute it to the committing session"
        );

        assert!(
            !workspace_is_dirty(&state),
            "the commit must leave the workspace level with its base"
        );
    }

    /// A carried path the workspace ADDED reaches the change with the entities
    /// its bytes derive to.
    ///
    /// The other carried arms exercise a `TreeDelta::Updated`, where the entity
    /// deltas are modifications. This one is the admission of untracked content:
    /// the workspace tree gains a path its base change never carried, and
    /// because ambient admission publishes no semantic delta, the change would
    /// otherwise publish a source file with no entities inside it at all. That
    /// is not a subtler version of the same defect; it is a file the graph
    /// cannot answer a single question about.
    #[test]
    fn a_carried_added_path_commits_the_entities_its_bytes_derive_to() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        admit_pending_working_tree_file(&state, "src/added.rs", b"pub fn added() -> u8 { 5 }\n");

        let sessions = test_sessions();
        let (_, arguments) = stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(result.is_error, Some(true), "{}", result_text(&result));
        let reply = commit_reply(&result);
        assert_eq!(
            reply["carried_pending_files"],
            serde_json::json!(["src/added.rs"]),
            "the fixture must actually exercise the carry: {reply:#}"
        );

        assert_eq!(
            semantic_disagreement(&state, "src/lib.rs"),
            None,
            "the file the operation authored must be coherent, or the check below proves nothing"
        );
        assert_eq!(
            semantic_disagreement(&state, "src/added.rs"),
            None,
            "a carried file the workspace admitted must reach the change with its entities"
        );
        assert!(
            state
                .graph
                .query_entities(&EntityFilter {
                    file_path: Some(FilePathId::new("src/added.rs")),
                    ..EntityFilter::default()
                })
                .unwrap()
                .iter()
                .any(|held| held.name == "added"),
            "the graph must be able to answer about the file the commit published"
        );
    }

    /// A carried path is never a removal, and this is the mechanism rather than
    /// an assumption.
    ///
    /// Ambient admission publishes the tree and no semantics, so vacating a path
    /// that way would leave the entities that file derived standing over a tree
    /// that no longer carries it. Repository authority refuses the transaction
    /// outright, so `publish_workspace_tree` cannot create the state at all. The
    /// seam that does vacate a path, `commit_session_workspace_admission`,
    /// derives the retirement through `retire_semantics_on_vacated` and carries
    /// it in the same transaction. Two independent mechanisms, one conclusion:
    /// every carried tree delta the MCP commit planner sees is an addition or an
    /// update, and the only removals that reach a plan are the ones a staged
    /// `delete` authored, which are not carried.
    ///
    /// That is why `derive_carried_pending_semantics` asserts the invariant
    /// instead of implementing a retirement, and this is what makes the
    /// assertion evidence rather than decoration: take either mechanism away and
    /// a carried removal becomes reachable, so the arm it guards has something
    /// to guard.
    ///
    /// A move is NOT a removal beside an addition, and an earlier version of
    /// this comment said it was. `TreeDelta::Updated` carries an old and a new
    /// state and nothing requires their paths to match, so a move is one delta
    /// that keeps its artifact identity;
    /// `a_pending_move_is_one_updated_delta_and_ambient_admission_refuses_it`
    /// asserts that from the product's own tree correction. What a move shares
    /// with a removal is only this refusal, because it vacates its old path the
    /// same way.
    #[test]
    fn ambient_admission_cannot_vacate_a_path_without_retiring_its_semantics() {
        let (_dir, state) = test_state();
        install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        install_exact_source(
            &state,
            "src/other.rs",
            b"pub fn other() -> u8 { 1 }\n",
            "other",
        );
        let before = load_native_commit_base(&state.layout).unwrap();

        let refusal = admit_pending_working_tree_removal(&state, "src/other.rs")
            .expect_err("authority must refuse a vacated path whose semantics still stand");

        let message = refusal.to_string();
        assert!(
            message.contains("src/other.rs"),
            "the refusal must name the path it will not vacate: {message}"
        );
        assert!(
            message.contains("absent from the staged tree"),
            "the refusal must say what is wrong with the transition: {message}"
        );
        assert!(
            message.contains("carry its exact entity removal or relocation in the same delta"),
            "the refusal must say what a caller has to carry instead: {message}"
        );
        assert_eq!(
            load_native_commit_base(&state.layout).unwrap().roots,
            before.roots,
            "no repository authority may move behind a refused admission"
        );
    }

    /// A carried path whose new bytes stop being source is refused by name, not
    /// published with the old entities still standing over them.
    ///
    /// Deriving cannot answer this one: there is nothing to parse, so there are
    /// no entities to replace the ones the graph holds. Publishing anyway is the
    /// defect in its worst form, entities describing source the repository is
    /// about to stop holding. Retiring them silently is not this commit's call
    /// either, because no operation in it named that file and a retirement is a
    /// decision about somebody else's work. So it refuses, names the path, says
    /// what the graph still holds, and gives the three ways out.
    #[test]
    fn a_carried_path_that_stops_being_source_is_refused_by_name() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        install_exact_source(
            &state,
            "src/other.rs",
            b"pub fn other() -> u8 { 1 }\n",
            "other",
        );
        // Not valid UTF-8, so the classifier cannot call it entity source no
        // matter what the extension says.
        admit_pending_working_tree_edit(&state, "src/other.rs", &[0xff, 0xfe, 0x00, 0x01]);
        let before = load_native_commit_base(&state.layout).unwrap();

        let sessions = test_sessions();
        let (transaction_id, arguments) =
            stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);

        assert_eq!(
            result.is_error,
            Some(true),
            "publishing stale entities under bytes they never came from is not an option: {}",
            result_text(&result)
        );
        let message = result_text(&result);
        assert!(
            message.contains("src/other.rs"),
            "the refusal must name the path that cannot be derived: {message}"
        );
        assert!(
            message.contains("no longer classifies as supported entity source"),
            "the refusal must say what is wrong with it: {message}"
        );
        assert!(
            message.contains("'replace'") && message.contains("'delete'"),
            "the refusal must say what to do about it: {message}"
        );
        assert_eq!(
            sessions.get_transaction(&transaction_id).unwrap().state,
            "active",
            "a refused commit leaves the transaction where the caller can retry it"
        );
        assert_eq!(
            load_native_commit_base(&state.layout).unwrap().roots,
            before.roots,
            "no repository authority may move behind a refusal"
        );
    }

    /// Leave one source path converted to a symlink the way a working session
    /// leaves it, and hand back whatever refused if something did.
    ///
    /// A real transition, not a fabricated tree: the working copy gets an actual
    /// symlink and the admitted tree is the one the live graph resolves. Both
    /// halves can refuse, and which one refuses is the interesting answer, so
    /// neither is unwrapped here.
    #[cfg(unix)]
    fn admit_pending_working_tree_symlink(
        state: &Arc<DaemonState>,
        file: &str,
        target: &str,
    ) -> crate::error::Result<()> {
        let path = RepoPath::from_utf8(file).unwrap();
        let on_disk = state.layout.working_dir().join(file);
        std::fs::remove_file(&on_disk).unwrap();
        std::os::unix::fs::symlink(target, &on_disk).unwrap();
        let digest = state.blobs.write(target.as_bytes()).unwrap();
        let artifact = state
            .graph
            .resolved_tree()
            .artifact_at_path(&path)
            .cloned()
            .expect("a conversion lands on an already admitted artifact");
        state.graph.apply_transaction_delta(&TransactionDelta {
            tree_deltas: vec![TreeDelta::Updated {
                artifact_id: artifact.artifact_id,
                old: artifact.located_entry(),
                new: LocatedEntry::new(path, TreeEntry::symlink(Hash256::from_bytes(digest.0))),
            }],
            ..TransactionDelta::default()
        })?;
        try_publish_pending_workspace_tree(state)
    }

    /// A carried path that became a symlink is refused by name, not skipped.
    ///
    /// The first cut of the derivation skipped every non-blob tree entry on the
    /// reasoning that a symlink carries no source body and therefore no entities
    /// to disagree with it. The first half is true and the second does not
    /// follow: the tree and the semantics are independent, and kin-db
    /// revalidates an invalidated path by requiring an artifact to remain at it
    /// without requiring that artifact to be a blob (0.7.104
    /// `src/engine/graph.rs:8705`). So a same-path source-to-symlink conversion
    /// satisfies every check while the entities the old source derived keep
    /// standing, and the skip published them over a link. It is the same defect
    /// as an unsupported blob, so it gets the same refusal.
    #[cfg(unix)]
    #[test]
    fn a_carried_source_to_symlink_conversion_is_refused_by_name() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        install_exact_source(
            &state,
            "src/other.rs",
            b"pub fn other() -> u8 { 1 }\n",
            "other",
        );
        admit_pending_working_tree_symlink(&state, "src/other.rs", "lib.rs").expect(
            "if some earlier layer refuses this conversion, that mechanism is the finding and \
             this test must be rewritten around it rather than deleted",
        );
        let before = load_native_commit_base(&state.layout).unwrap();

        let sessions = test_sessions();
        let (transaction_id, arguments) =
            stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);

        assert_eq!(
            result.is_error,
            Some(true),
            "publishing source entities over a symlink is not an option: {}",
            result_text(&result)
        );
        let message = result_text(&result);
        assert!(
            message.contains("src/other.rs"),
            "the refusal must name the path it cannot derive: {message}"
        );
        assert!(
            message.contains("a symlink"),
            "the refusal must say what the path became: {message}"
        );
        assert!(
            message.contains("'replace'") && message.contains("'delete'"),
            "the refusal must say what to do about it: {message}"
        );
        assert_eq!(
            sessions.get_transaction(&transaction_id).unwrap().state,
            "active",
            "a refused commit leaves the transaction where the caller can retry it"
        );
        assert_eq!(
            load_native_commit_base(&state.layout).unwrap().roots,
            before.roots,
            "no repository authority may move behind a refusal"
        );
    }

    /// A newly admitted symlink with nothing standing under it stays a legal
    /// tree-only carry, and its target is never resolved through the parser.
    ///
    /// The control for the refusal above. A symlink is a perfectly ordinary
    /// thing for a workspace to carry, and refusing every one of them would
    /// trade one broken commit for another. The refusal is about the entities
    /// standing at the path, not about the entry kind, and this is what says so.
    #[cfg(unix)]
    #[test]
    fn a_carried_symlink_with_no_standing_entities_is_a_legal_tree_only_carry() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );

        let path = RepoPath::from_utf8("src/link.rs").unwrap();
        let on_disk = state.layout.working_dir().join("src/link.rs");
        std::os::unix::fs::symlink("lib.rs", &on_disk).unwrap();
        let digest = state.blobs.write(b"lib.rs").unwrap();
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: kin_model::ArtifactId::new(),
                    new: LocatedEntry::new(path, TreeEntry::symlink(Hash256::from_bytes(digest.0))),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();
        publish_pending_workspace_tree(&state);

        let sessions = test_sessions();
        let (_, arguments) = stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "a symlink nothing derives entities from must still commit: {}",
            result_text(&result)
        );
        let reply = commit_reply(&result);
        assert_eq!(
            reply["carried_pending_files"],
            serde_json::json!(["src/link.rs"]),
            "the symlink is carried and declared like any other pending path: {reply:#}"
        );
        assert!(
            state
                .graph
                .query_entities(&EntityFilter {
                    file_path: Some(FilePathId::new("src/link.rs")),
                    ..EntityFilter::default()
                })
                .unwrap()
                .is_empty(),
            "the link's target must never be resolved through the parser on its behalf"
        );
        assert_eq!(
            semantic_disagreement(&state, "src/lib.rs"),
            None,
            "the file the operation authored stays coherent beside a carried symlink"
        );
    }

    /// A relation-only commit beside a carried edit attributes the endpoint the
    /// agent joined and not the one it carried.
    ///
    /// The carried-path filter that keeps a folded-in file out of attribution
    /// applies while entity-delta scopes are collected. A relation-only commit
    /// has no entity deltas of its own, so it falls back to the relation's
    /// endpoints, and once a carried file contributes entity deltas the two
    /// interact: the carried entity is filtered out of the first list, the list
    /// is empty, the fallback opens, and an unfiltered fallback hands the carried
    /// endpoint straight back to the committing session. Both sources are
    /// filtered for that reason.
    #[test]
    fn a_relation_only_commit_beside_a_carry_attributes_only_the_endpoint_it_joined() {
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
        // The carried half, on the callee's own path, so the commit re-derives
        // the entity the staged relation points at.
        admit_pending_working_tree_edit(&state, "src/callee.rs", b"pub fn callee() -> u8 { 7 }\n");

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
                    destination: None,
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
            "a relation-only commit beside a carry must still land: {}",
            result_text(&result)
        );
        let reply = commit_reply(&result);
        assert_eq!(
            reply["carried_pending_files"],
            serde_json::json!(["src/callee.rs"]),
            "the fixture must actually exercise the carry: {reply:#}"
        );

        let scoped = state
            .graph
            .query_audit_events(Some(&mcp_actor_id(&session_id)), 16)
            .unwrap()
            .into_iter()
            .filter_map(|event| match event.target_scope {
                Some(WorkScope::Entity(id)) => Some(id),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            scoped.contains(&caller.id),
            "the endpoint the agent joined and did not carry is still attributed to it"
        );
        assert!(
            !scoped.contains(&callee.id),
            "an endpoint inside a carried file must not reach the committing session's \
             attribution through the relation fallback"
        );
        assert_eq!(
            semantic_disagreement(&state, "src/callee.rs"),
            None,
            "the carried endpoint's own entities still describe the bytes this commit published"
        );
    }

    /// Leave one working file moved the way a session leaves it, and hand back
    /// whatever refused if something did.
    ///
    /// Same shape as the removal helper, and for the same reason: the ambient
    /// publication path can refuse this, and which layer refuses is the answer
    /// worth having rather than a panic.
    /// The same tree with one artifact at a different path and the same
    /// identity, which is what a move leaves behind.
    ///
    /// Built by naming the artifacts rather than by assembling the delta the
    /// assertion is about, so the correction under test is derived from two
    /// states rather than read back from an answer the fixture supplied.
    fn moved_workspace_tree(
        tree: &kin_model::ResolvedTree,
        from: &RepoPath,
        to: &RepoPath,
    ) -> kin_model::ResolvedTree {
        kin_model::ResolvedTree::from_artifacts(tree.artifacts_by_path().map(|artifact| {
            let path = if &artifact.path == from {
                to.clone()
            } else {
                artifact.path.clone()
            };
            kin_model::ResolvedArtifact::new(artifact.artifact_id, path, artifact.entry.clone())
        }))
        .expect("moving one artifact keeps every identity and every path unique")
    }

    fn admit_pending_working_tree_move(
        state: &Arc<DaemonState>,
        from: &str,
        to: &str,
    ) -> crate::error::Result<()> {
        let from_path = RepoPath::from_utf8(from).unwrap();
        let to_path = RepoPath::from_utf8(to).unwrap();
        let working = state.layout.working_dir();
        if let Some(parent) = working.join(to).parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::rename(working.join(from), working.join(to)).unwrap();
        let artifact = state
            .graph
            .resolved_tree()
            .artifact_at_path(&from_path)
            .cloned()
            .expect("a move takes an already admitted artifact");
        state.graph.apply_transaction_delta(&TransactionDelta {
            tree_deltas: vec![TreeDelta::Updated {
                artifact_id: artifact.artifact_id,
                old: artifact.located_entry(),
                new: LocatedEntry::new(to_path, artifact.entry),
            }],
            ..TransactionDelta::default()
        })?;
        try_publish_pending_workspace_tree(state)
    }

    /// `TreeDelta::Updated` can carry a path change, and ambient admission
    /// cannot publish the transition either way.
    ///
    /// An earlier comment in this module asserted the opposite, that a moved
    /// path must arrive as a `Removed` beside an `Added` because `TreeDelta` has
    /// no move variant. The variant count does not settle it: `Updated` carries
    /// an old and a new state and nothing requires their paths to match, so the
    /// carry code cannot assume it will see a pair, and this holds that where it
    /// can see it.
    ///
    /// What follows from either shape is the same, and is the second half: the
    /// old path ends with no artifact while its entities still stand there,
    /// which is the transition repository authority refuses, in the same words
    /// it refuses a pending deletion.
    /// The scope of the first half is exactly the correction, and not the
    /// scanner that feeds it. `exact_tree_correction` is handed two tree states
    /// in which one artifact keeps its identity at a different path, and it
    /// answers with a single `Updated` carrying both paths, which is what says
    /// `TreeDelta::Updated` does not require its old and new paths to match.
    /// Whether any particular scanner produces that input is a separate
    /// question with a separate answer: a scanner that mints fresh identity for
    /// the new path yields a `Removed` beside an `Added` instead. Both shapes
    /// leave the old path with no artifact and its entities still standing,
    /// which is the state the refusal below is about, so the second half holds
    /// either way.
    #[test]
    fn a_relocated_artifact_corrects_to_one_updated_delta_ambient_admission_refuses() {
        let (_dir, state) = test_state();
        install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        install_exact_source(
            &state,
            "src/old.rs",
            b"pub fn moved() -> u8 { 1 }\n",
            "moved",
        );
        let before = load_native_commit_base(&state.layout).unwrap();

        // The tree transition a move actually produces, from the product's own
        // correction rather than from a delta assembled to look like one.
        let from_path = RepoPath::from_utf8("src/old.rs").unwrap();
        let to_path = RepoPath::from_utf8("src/new.rs").unwrap();
        let artifact = before
            .tree
            .artifact_at_path(&from_path)
            .cloned()
            .expect("the fixture installed this path");
        let moved_tree = moved_workspace_tree(&before.tree, &from_path, &to_path);
        let deltas = kin_core::exact_tree_correction(&before.tree, &moved_tree).unwrap();
        assert_eq!(
            deltas.len(),
            1,
            "an artifact that keeps its identity at a new path corrects to one delta: {deltas:#?}"
        );
        assert!(
            matches!(
                &deltas[0],
                TreeDelta::Updated { artifact_id, old, new }
                    if *artifact_id == artifact.artifact_id
                        && old.path == from_path
                        && new.path == to_path
            ),
            "and that delta is an Updated whose paths differ, so a path change is not necessarily \
             a Removed beside an Added: {:#?}",
            deltas[0]
        );

        let refusal = admit_pending_working_tree_move(&state, "src/old.rs", "src/new.rs")
            .expect_err("authority must refuse a move whose old path's semantics still stand");
        let message = refusal.to_string();
        assert!(
            message.contains("src/old.rs"),
            "the refusal must name the path being vacated: {message}"
        );
        assert!(
            message.contains("carry its exact entity removal or relocation in the same delta"),
            "the refusal must say what a caller has to carry instead: {message}"
        );
        assert_eq!(
            load_native_commit_base(&state.layout).unwrap().roots,
            before.roots,
            "no repository authority may move behind a refused admission"
        );
    }

    /// The seam that CAN admit a move retires the moved path's identity before
    /// any MCP commit could see it.
    ///
    /// This is the half the ambient refusal above does not settle. Session
    /// admission carries the retirement the refusal demands, and it derives that
    /// retirement from the vacated set rather than from a relocation: an entity
    /// on the old path is removed outright, and so is every relation incident to
    /// it. So a carried move reaches the MCP commit planner with the file at its
    /// new path and no entities anywhere, which is why the derivation in this
    /// module can make that file answerable again but cannot give it back the
    /// identity it had. The loss happens here, in the admission, not in the
    /// carry.
    ///
    /// Driven through the product's own `VacatedPaths::from_deltas` and
    /// `retire_semantics_on_vacated`, which is what `plan_session_workspace_
    /// admission` calls, rather than through a hand-built delta.
    ///
    /// **Every assertion here describes retirement, and retirement is not the
    /// behaviour a preserved move identity would have.** The whole set inverts
    /// under a relocating admission: the moved entity becomes an
    /// `EntityDelta::Modified` carrying its original id at the new path, its
    /// incident relations survive with both endpoints intact, and the assertion
    /// that nothing relocates it becomes the failing one. Replace them together
    /// when that is what the admission does. This test is a record of a
    /// mechanism, not an argument that the mechanism is right.
    #[test]
    fn session_admission_retires_a_moved_path_identity_and_its_incoming_edges() {
        let (_dir, state) = test_state();
        let (caller, _) = install_exact_source(
            &state,
            "src/caller.rs",
            b"pub fn caller() -> u8 { 1 }\n",
            "caller",
        );
        let (moved, _) = install_exact_source(
            &state,
            "src/old.rs",
            b"pub fn moved() -> u8 { 1 }\n",
            "moved",
        );
        // An incoming edge, so the retirement's reach is asserted rather than
        // assumed.
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                relation_deltas: vec![RelationDelta::Added {
                    new: Relation {
                        id: kin_model::RelationId::new(),
                        kind: kin_model::relation::RelationKind::Calls,
                        src: GraphNodeId::Entity(caller.id),
                        dst: GraphNodeId::Entity(moved.id),
                        confidence: 1.0,
                        origin: RelationOrigin::Manual,
                        created_in: None,
                        import_source: None,
                        evidence: Vec::new(),
                    },
                }],
                ..TransactionDelta::default()
            })
            .unwrap();
        commit_live_graph(&state, "install the incoming edge", false);

        let base = load_native_commit_base(&state.layout).unwrap();
        let from_path = RepoPath::from_utf8("src/old.rs").unwrap();
        let to_path = RepoPath::from_utf8("src/new.rs").unwrap();
        let moved_tree = moved_workspace_tree(&base.tree, &from_path, &to_path);
        let deltas = kin_core::exact_tree_correction(&base.tree, &moved_tree).unwrap();

        let vacated = crate::repository_commit::VacatedPaths::from_deltas(&deltas);
        assert!(
            !vacated.is_empty(),
            "a move's old path is vacated, because the kept set is built from new paths only"
        );

        let retirement = crate::repository_commit::retire_semantics_on_vacated(
            &base.graph.to_snapshot(),
            &vacated,
        )
        .unwrap();
        assert!(
            retirement.entity_deltas().iter().any(|delta| matches!(
                delta,
                EntityDelta::Removed { old } if old.id == moved.id
            )),
            "session admission removes the moved entity outright rather than relocating it: {:#?}",
            retirement.entity_deltas()
        );
        assert!(
            !retirement.relation_deltas().is_empty(),
            "and takes every edge incident to it with it: {:#?}",
            retirement.relation_deltas()
        );
        assert!(
            retirement.entity_deltas().iter().all(|delta| !matches!(
                delta,
                EntityDelta::Modified { new, .. } if new.id == moved.id
            )),
            "nothing here relocates the entity, which is why the identity is gone by the time a \
             carried move reaches an MCP commit"
        );
    }
}
