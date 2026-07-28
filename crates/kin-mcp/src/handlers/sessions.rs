// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;
use std::path::PathBuf;

use crate::session::{McpMutationOperation, McpMutationPayload};
use kin_model::graph::GraphStore;
use kin_model::ids::EntityId;
use kin_model::timestamp::Timestamp;

use crate::error::Result;
use crate::server::SessionAuthorityMode;
use crate::session::SessionRegistry;
use crate::types::ToolCallResult;

use super::common::*;

fn daemon_required_unavailable(operation: &str) -> ToolCallResult {
    ToolCallResult::error(format!(
        "Kin daemon is required for {operation}, but the daemon delegate is unavailable"
    ))
}

pub const REGISTER_SESSION_DESC: &str = "\
Register a lightweight assistant session with Kin so its activity can be tracked. This \
is the legacy, minimal entry point — it records an assistant name and session ID and \
nothing more. Prefer kin_session_start for new integrations, which captures \
capabilities, transport, and working directory and unlocks intent registration and \
collision detection. Use this only for simple or backward-compatible setups.";

pub fn handle_register_session(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let assistant_name = get_string_param(args, "assistant_name")?;
    let session_id = args
        .get("session_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| EntityId::new().to_string());

    sessions.register(&session_id, &assistant_name);

    let result = serde_json::json!({
        "session_id": session_id,
        "assistant": assistant_name,
        "status": "registered",
    });

    let json = serde_json::to_string_pretty(&result).map_err(crate::error::McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const SESSION_START_DESC: &str = "\
Start a rich agent session with Kin, declaring who you are and what you can do: vendor, \
client name, transport, working directory, optional PID, and a capability set \
(read/write/execute/branch/commit, max concurrent intents). Reach for it at the \
beginning of an agent's work so Kin can attribute activity, surface your presence to \
other agents, and gate collaboration features. It returns a session ID that the rest of \
the session lifecycle uses — keep it alive with kin_session_heartbeat, declare what \
you'll touch via kin_register_intent (enabling collision detection against other \
agents), and close out with kin_session_end. Prefer this over the legacy \
register_session, which captures none of this context.";

pub async fn handle_session_start(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
) -> Result<ToolCallResult> {
    let vendor = get_string_param(args, "vendor")?;
    let client_name = get_string_param(args, "client_name")?;
    let cwd_str = get_string_param(args, "cwd")?;

    let transport_str = args
        .get("transport")
        .and_then(|v| v.as_str())
        .unwrap_or("mcp");
    let transport = parse_transport(transport_str);

    let pid = args.get("pid").and_then(|v| v.as_u64()).map(|p| p as u32);
    let cwd = PathBuf::from(&cwd_str);
    let capabilities = parse_capabilities(args);

    if session_authority_mode.uses_daemon() {
        let daemon_result = crate::daemon_delegate::forward_session_start(
            &vendor,
            &client_name,
            transport_str,
            pid,
            &cwd_str,
            &capabilities,
        )
        .await;
        match daemon_result {
            Ok(Some(value)) => {
                let json =
                    serde_json::to_string_pretty(&value).map_err(crate::error::McpError::Json)?;
                return Ok(ToolCallResult::text(json));
            }
            Ok(None) if session_authority_mode.requires_daemon() => {
                return Ok(daemon_required_unavailable("session start"));
            }
            Ok(None) => {}
            Err(err) => {
                return Ok(ToolCallResult::error(err));
            }
        }
    }

    let session =
        sessions.start_agent_session(&vendor, &client_name, transport, pid, cwd, capabilities);

    let result = serde_json::json!({
        "session_id": session.session_id.to_string(),
        "vendor": session.vendor,
        "client_name": session.client_name,
        "transport": session.transport,
        "started_at": session.started_at,
        "capabilities": session.capabilities,
        "status": "active",
    });

    let json = serde_json::to_string_pretty(&result).map_err(crate::error::McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const SESSION_HEARTBEAT_DESC: &str = "\
Send a heartbeat to keep an agent session marked alive. Reach for it periodically \
during a long-running session so Kin doesn't treat it as stale and so the agent's \
presence (and any held intents) stays visible to other agents. Pair it with \
kin_session_start (which issues the session ID) and kin_session_end (which closes the \
session and releases its intents).";

pub async fn handle_session_heartbeat(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "session_id")?;
    let session_id = parse_session_id(&id_str)?;

    if session_authority_mode.uses_daemon() {
        match crate::daemon_delegate::forward_session_heartbeat(&id_str).await {
            Ok(Some(value)) => {
                let json =
                    serde_json::to_string_pretty(&value).map_err(crate::error::McpError::Json)?;
                return Ok(ToolCallResult::text(json));
            }
            Ok(None) if session_authority_mode.requires_daemon() => {
                return Ok(daemon_required_unavailable("session heartbeat"));
            }
            Ok(None) => {}
            Err(err) => {
                return Ok(ToolCallResult::error(err));
            }
        }
    }

    let alive = sessions.heartbeat(&session_id);

    if alive {
        let result = serde_json::json!({
            "session_id": id_str,
            "status": "alive",
            "heartbeat_at": Timestamp::now(),
        });
        let json = serde_json::to_string_pretty(&result).map_err(crate::error::McpError::Json)?;
        Ok(ToolCallResult::text(json))
    } else {
        Ok(ToolCallResult::error(format!(
            "Session not found: {}",
            id_str
        )))
    }
}

pub const SESSION_END_DESC: &str = "\
End an agent session and release everything it held — all of its registered intents are \
freed so other agents are no longer blocked or warned off the scopes it was working. \
Reach for it when an agent finishes its work or shuts down, so the collaboration graph \
reflects reality and doesn't leave stale locks behind. The complement to \
kin_session_start.";

pub async fn handle_session_end(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "session_id")?;
    let session_id = parse_session_id(&id_str)?;

    if session_authority_mode.uses_daemon() {
        match crate::daemon_delegate::forward_session_end(&id_str).await {
            Ok(Some(value)) => {
                let json =
                    serde_json::to_string_pretty(&value).map_err(crate::error::McpError::Json)?;
                return Ok(ToolCallResult::text(json));
            }
            Ok(None) if session_authority_mode.requires_daemon() => {
                return Ok(daemon_required_unavailable("session end"));
            }
            Ok(None) => {}
            Err(err) => {
                return Ok(ToolCallResult::error(err));
            }
        }
    }

    match sessions.end_agent_session(&session_id) {
        Some(session) => {
            let result = serde_json::json!({
                "session_id": id_str,
                "vendor": session.vendor,
                "status": "ended",
                "started_at": session.started_at,
                "ended_at": Timestamp::now(),
            });
            let json =
                serde_json::to_string_pretty(&result).map_err(crate::error::McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        None => Ok(ToolCallResult::error(format!(
            "Session not found: {}",
            id_str
        ))),
    }
}

pub const REGISTER_INTENT_DESC: &str = "\
Declare, ahead of acting, which scopes (entities, contracts, or artifacts) an agent \
intends to modify and why. This is how Kin does collision detection: by publishing your \
intent — with a soft or hard lock — other agents can see you're working a region and \
avoid clobbering it, and you can see if someone is already there. Reach for it before \
making changes in a multi-agent setting so concurrent work coordinates through graph \
truth instead of racing. Optionally set an expiry; release it early with \
kin_release_intent, and check who else is active with kin_check_traffic. Requires an \
active session from kin_session_start.";

pub async fn handle_register_intent(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "session_id")?;
    let session_id = parse_session_id(&id_str)?;
    let task_description = get_string_param(args, "task_description")?;

    let scopes_val = args.get("scopes").ok_or_else(|| {
        crate::error::McpError::InvalidParams("missing required parameter: scopes".into())
    })?;
    let scopes = parse_scopes(scopes_val)?;

    let lock_type_str = args
        .get("lock_type")
        .and_then(|v| v.as_str())
        .unwrap_or("soft");
    let lock_type = parse_lock_type(lock_type_str);

    let expires_at_raw: Option<String> = args
        .get("expires_at")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let expires_at: Option<Timestamp> = expires_at_raw
        .as_deref()
        .and_then(|s| serde_json::from_value(serde_json::json!(s)).ok());

    let scope_strings: Vec<String> = scopes.iter().map(intent_scope_to_string).collect();

    if session_authority_mode.uses_daemon() {
        match crate::daemon_delegate::forward_register_intent(
            &id_str,
            &scope_strings,
            lock_type_str,
            &task_description,
            expires_at_raw.as_deref(),
        )
        .await
        {
            Ok(Some(value)) => {
                let json =
                    serde_json::to_string_pretty(&value).map_err(crate::error::McpError::Json)?;
                return Ok(ToolCallResult::text(json));
            }
            Ok(None) if session_authority_mode.requires_daemon() => {
                return Ok(daemon_required_unavailable("intent registration"));
            }
            Ok(None) => {}
            Err(err) => {
                return Ok(ToolCallResult::error(err));
            }
        }
    }

    match sessions.register_intent_checked(
        session_id,
        scopes,
        lock_type,
        task_description,
        expires_at,
    ) {
        crate::session::IntentRegistrationAttempt::Registered {
            intent,
            policy_warnings,
        } => {
            let result = serde_json::json!({
                "intent_id": intent.intent_id.to_string(),
                "session_id": intent.session_id.to_string(),
                "scopes": intent.scopes,
                "lock_type": intent.lock_type,
                "task_description": intent.task_description,
                "registered_at": intent.registered_at,
                "status": "registered",
                "coordination_warnings": policy_warnings,
            });
            let json =
                serde_json::to_string_pretty(&result).map_err(crate::error::McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        crate::session::IntentRegistrationAttempt::Blocked {
            intent_id,
            conflicts,
        } => {
            let result = serde_json::json!({
                "intent_id": intent_id.to_string(),
                "session_id": session_id.to_string(),
                "status": "blocked",
                "conflicts": conflicts,
            });
            let json =
                serde_json::to_string_pretty(&result).map_err(crate::error::McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        crate::session::IntentRegistrationAttempt::LimitExceeded {
            intent_id,
            active,
            limit,
        } => {
            let result = serde_json::json!({
                "intent_id": intent_id.to_string(),
                "session_id": session_id.to_string(),
                "status": "limit_exceeded",
                "active_intents": active,
                "max_concurrent_intents": limit,
            });
            let json =
                serde_json::to_string_pretty(&result).map_err(crate::error::McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        crate::session::IntentRegistrationAttempt::CapabilityDenied {
            intent_id,
            capability,
        } => {
            let result = serde_json::json!({
                "intent_id": intent_id.to_string(),
                "session_id": session_id.to_string(),
                "status": "capability_denied",
                "required_capability": capability,
            });
            let json =
                serde_json::to_string_pretty(&result).map_err(crate::error::McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        crate::session::IntentRegistrationAttempt::SessionNotFound => {
            Ok(ToolCallResult::error(format!(
                "Session not found: {}. Start a session with kin_session_start first.",
                id_str
            )))
        }
    }
}

pub const RELEASE_INTENT_DESC: &str = "\
Release a single previously registered intent by ID, freeing the scopes it held so \
other agents can proceed. Reach for it as soon as you finish the specific piece of work \
an intent covered, rather than holding the lock until session end — it keeps the \
collaboration graph tight and unblocks teammates promptly. Ending the whole session \
with kin_session_end releases all remaining intents at once.";

pub async fn handle_release_intent(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
) -> Result<ToolCallResult> {
    let session_str = get_string_param(args, "session_id")?;
    let intent_str = get_string_param(args, "intent_id")?;
    let session_id = parse_session_id(&session_str)?;
    let intent_id = parse_intent_id(&intent_str)?;

    if session_authority_mode.uses_daemon() {
        match crate::daemon_delegate::forward_release_intent(&session_str, &intent_str).await {
            Ok(Some(value)) => {
                let json =
                    serde_json::to_string_pretty(&value).map_err(crate::error::McpError::Json)?;
                return Ok(ToolCallResult::text(json));
            }
            Ok(None) if session_authority_mode.requires_daemon() => {
                return Ok(daemon_required_unavailable("intent release"));
            }
            Ok(None) => {}
            Err(err) => {
                return Ok(ToolCallResult::error(err));
            }
        }
    }

    match sessions.release_intent(&session_id, &intent_id) {
        Some(intent) => {
            let result = serde_json::json!({
                "intent_id": intent_str,
                "session_id": session_str,
                "task_description": intent.task_description,
                "status": "released",
            });
            let json =
                serde_json::to_string_pretty(&result).map_err(crate::error::McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        None => Ok(ToolCallResult::error(format!(
            "Intent not found or not owned by session: intent={}, session={}",
            intent_str, session_str
        ))),
    }
}

pub const CHECK_TRAFFIC_DESC: &str = "\
Check whether other agents are actively working on or near a set of scopes (entities, \
contracts, or artifacts), and what they're doing. Reach for it before you start \
changing something in a multi-agent setting — it surfaces in-flight intents and locks \
so you can avoid collisions, coordinate, or pick different work. It's the read-side \
companion to kin_register_intent (the write side): one declares what you'll touch, the \
other tells you what others are touching.";

pub async fn handle_check_traffic(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
) -> Result<ToolCallResult> {
    let scopes_val = args.get("scopes").ok_or_else(|| {
        crate::error::McpError::InvalidParams("missing required parameter: scopes".into())
    })?;
    let scopes = parse_scopes(scopes_val)?;

    if session_authority_mode.uses_daemon() {
        let scope_strings: Vec<String> = scopes.iter().map(intent_scope_to_string).collect();
        match crate::daemon_delegate::forward_check_traffic(&scope_strings).await {
            Ok(Some(value)) => {
                let json =
                    serde_json::to_string_pretty(&value).map_err(crate::error::McpError::Json)?;
                return Ok(ToolCallResult::text(json));
            }
            Ok(None) if session_authority_mode.requires_daemon() => {
                return Ok(daemon_required_unavailable("traffic checks"));
            }
            Ok(None) => {}
            Err(err) => {
                return Ok(ToolCallResult::error(err));
            }
        }
    }

    let reports = sessions.check_traffic(&scopes);

    let result = serde_json::json!({
        "reports": reports,
        "scope_count": scopes.len(),
    });

    let json = serde_json::to_string_pretty(&result).map_err(crate::error::McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn intent_scope_to_string(scope: &kin_model::session::IntentScope) -> String {
    use kin_model::session::IntentScope;

    match scope {
        IntentScope::Entity(id) => format!("entity:{id}"),
        IntentScope::Contract(id) => format!("contract:{id}"),
        IntentScope::Artifact(id) => format!("file:{id}"),
    }
}

/// Resolve a target-body update's entity by id or exact name, fail closed.
///
/// A uuid target must exist; a name target must match exactly one entity by
/// exact name (broad substring matches are filtered out). Anything else is an
/// error, because a mutation that guesses its target is worse than one that
/// fails.
pub fn resolve_target_entity<G: GraphStore>(
    store: &G,
    target: &str,
) -> std::result::Result<kin_model::Entity, String> {
    let target = target.trim();
    if let Ok(uuid) = uuid::Uuid::parse_str(target) {
        return match store.get_entity(&kin_model::ids::EntityId(uuid)) {
            Ok(Some(entity)) => Ok(entity),
            _ => Err(format!(
                "target entity id '{target}' not found in the graph"
            )),
        };
    }
    let mut matches = store
        .query_entities(&kin_model::EntityFilter {
            name_pattern: Some(target.to_string()),
            ..Default::default()
        })
        .map_err(|error| format!("target lookup for '{target}' failed: {error}"))?;
    matches.retain(|entity| entity.name == target);
    match matches.len() {
        0 => Err(format!("target entity '{target}' not found in the graph")),
        1 => Ok(matches.remove(0)),
        n => {
            // An unqualified name that matches several entities is structurally
            // unrecoverable unless the refusal carries the candidates: the
            // caller cannot re-target what it cannot see, and it has no other
            // way to learn which entity it meant.
            matches.sort_by(|left, right| {
                candidate_location(left)
                    .cmp(&candidate_location(right))
                    .then_with(|| left.id.to_string().cmp(&right.id.to_string()))
            });
            let candidates = matches
                .iter()
                .map(|entity| {
                    format!(
                        "{} ({:?} at {})",
                        entity.id,
                        entity.kind,
                        candidate_location(entity)
                    )
                })
                .collect::<Vec<_>>()
                .join("\n  - ");
            Err(format!(
                "target entity '{target}' is ambiguous ({n} exact-name matches); re-target one of \
                 these entity ids:\n  - {candidates}"
            ))
        }
    }
}

/// `file:line` for an ambiguity candidate, or a stable placeholder when the
/// entity carries no source origin.
fn candidate_location(entity: &kin_model::Entity) -> String {
    match (entity.file_origin.as_ref(), entity.span.as_ref()) {
        (Some(file), Some(span)) => format!("{}:{}", file.0, span.start_line),
        (Some(file), None) => file.0.clone(),
        (None, _) => "<no source origin>".to_string(),
    }
}

pub const TRANSACTION_BEGIN_DESC: &str = "\
Begin a new semantic graph mutation transaction. Transactions allow you to stage \
multiple mutations (inserts, updates, deletes) and commit them atomically. Returns \
a unique transaction_id.";

pub async fn handle_transaction_begin(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
) -> Result<ToolCallResult> {
    let session_id = get_string_param(args, "session_id")?;
    let scope = get_string_param(args, "scope")?;

    if session_authority_mode.uses_daemon() {
        match crate::daemon_delegate::forward_tool_call("kin_transaction_begin", args).await {
            Ok(Some(value)) => return Ok(value),
            Ok(None) if session_authority_mode.requires_daemon() => {
                return Ok(daemon_required_unavailable("transaction begin"));
            }
            Ok(None) => {}
            Err(err) => return Ok(ToolCallResult::error(err)),
        }
    }

    let _coordination_apply = sessions.lock_coordination_apply();
    match sessions.begin_transaction(&session_id, &scope) {
        Ok(tx) => {
            let result = serde_json::json!({
                "transaction_id": tx.transaction_id,
                "session_id": tx.session_id,
                "scope": tx.scope,
                "state": tx.state,
            });
            let json =
                serde_json::to_string_pretty(&result).map_err(crate::error::McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        Err(err) => Ok(ToolCallResult::error(err)),
    }
}

pub const TRANSACTION_STAGE_DESC: &str = "\
Stage one or more mutation operations onto an active transaction. The simplest write is \
a payload-less entity source edit: {verb: \"update\", target: \"<entity name or id>\", \
body: \"<the entity's full new source text>\", description: \"...\"}. The entity is \
resolved fail-closed server-side (exact name or id; ambiguity is an error) and on \
commit the graph-to-file projection writes the body into the entity's working-directory \
file. Structured payloads (full entity, relation add/remove) are also accepted. Each \
operation is validated at stage time: anything the commit path would silently drop (a \
missing or unknown verb, a missing payload, a nameless entity, a relation \
update/modify, or a blob payload) is rejected immediately with an actionable error \
instead of vanishing at commit. This rejection is identical in daemon and in-process \
modes. Accepted operations are queued and can be validated or committed together.";

pub async fn handle_transaction_stage(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
) -> Result<ToolCallResult> {
    let transaction_id = get_string_param(args, "transaction_id")?;
    let operations_val = args.get("operations").ok_or_else(|| {
        crate::error::McpError::InvalidParams("missing required parameter: operations".into())
    })?;

    let operations: Vec<McpMutationOperation> =
        crate::session::parse_staged_operations(operations_val)
            .map_err(crate::error::McpError::InvalidParams)?;

    // Stage-time validation: reject intrinsically-malformed operations now, with
    // an actionable message, rather than letting the commit path silently drop
    // them. Runs before forwarding so the agent gets the same fast failure in
    // both daemon and in-process modes.
    crate::session::validate_staged_operations(&operations)
        .map_err(crate::error::McpError::InvalidParams)?;

    if session_authority_mode.uses_daemon() {
        match crate::daemon_delegate::forward_tool_call("kin_transaction_stage", args).await {
            Ok(Some(value)) => return Ok(value),
            Ok(None) if session_authority_mode.requires_daemon() => {
                return Ok(daemon_required_unavailable("transaction stage"));
            }
            Ok(None) => {}
            Err(err) => return Ok(ToolCallResult::error(err)),
        }
    }

    let _coordination_apply = sessions.lock_coordination_apply();
    match sessions.stage_transaction(&transaction_id, operations) {
        Ok(tx) => {
            let result = serde_json::json!({
                "transaction_id": tx.transaction_id,
                "state": tx.state,
                "staged_count": tx.staged_operations.len(),
            });
            let json =
                serde_json::to_string_pretty(&result).map_err(crate::error::McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        Err(err) => Ok(ToolCallResult::error(err)),
    }
}

pub const TRANSACTION_VALIDATE_DESC: &str = "\
Validate staged mutations on an active transaction. Runs semantic and structural \
schema validation on the staged deltas without committing them.";

pub async fn handle_transaction_validate(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
) -> Result<ToolCallResult> {
    let transaction_id = get_string_param(args, "transaction_id")?;

    if session_authority_mode.uses_daemon() {
        match crate::daemon_delegate::forward_tool_call("kin_transaction_validate", args).await {
            Ok(Some(value)) => return Ok(value),
            Ok(None) if session_authority_mode.requires_daemon() => {
                return Ok(daemon_required_unavailable("transaction validate"));
            }
            Ok(None) => {}
            Err(err) => return Ok(ToolCallResult::error(err)),
        }
    }

    let _coordination_apply = sessions.lock_coordination_apply();
    match sessions.validate_transaction(&transaction_id) {
        Ok(tx) => {
            let result = serde_json::json!({
                "transaction_id": tx.transaction_id,
                "state": tx.state,
                "status": "valid",
            });
            let json =
                serde_json::to_string_pretty(&result).map_err(crate::error::McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        Err(err) => Ok(ToolCallResult::error(err)),
    }
}

pub const TRANSACTION_COMMIT_DESC: &str = "\
Commit all staged mutations in the transaction atomically to the graph. On success \
returns status, ops_applied (entity+relation deltas applied), empty (true for a \
no-op commit), new_root_hash (graph Merkle root after the commit), modified_files \
(working-directory files the projection wrote — entity-body edits reach disk here), \
collision_warnings, and conflicts (entities skipped due to a concurrent file edit; a \
non-empty set is surfaced as an error instead). Before graph application, exact entity/artifact \
intent conflicts and session write/commit capabilities are attested; enforce mode rejects \
before graph truth changes. Contract-scope coverage remains explicitly false until touched \
contracts can be derived from the semantic delta.";

fn push_scope_once(scopes: &mut Vec<kin_model::IntentScope>, scope: kin_model::IntentScope) {
    if !scopes.contains(&scope) {
        scopes.push(scope);
    }
}

/// Derive only the scopes the transaction payload can prove it touches. Entity
/// ids and their old/new file origins are exact. Relation mutations cover both
/// endpoint entities. Contract scopes are intentionally absent: the current
/// delta carries no touched-contract derivation, so claiming them would be a
/// false enforcement guarantee.
fn transaction_touched_scopes<G: GraphStore>(
    store: &G,
    operations: &[McpMutationOperation],
) -> Vec<kin_model::IntentScope> {
    let mut scopes = Vec::new();
    for operation in operations {
        match operation.payload.as_ref() {
            Some(McpMutationPayload::Entity(entity)) => {
                push_scope_once(&mut scopes, kin_model::IntentScope::Entity(entity.id));
                if let Some(file) = entity.file_origin.clone() {
                    push_scope_once(&mut scopes, kin_model::IntentScope::Artifact(file));
                }
                let mut existing = store.get_entity(&entity.id).ok().flatten();
                if existing.is_none() {
                    let filter = kin_model::EntityFilter {
                        name_pattern: Some(entity.name.clone()),
                        kinds: Some(vec![entity.kind]),
                        ..Default::default()
                    };
                    existing = store
                        .query_entities(&filter)
                        .ok()
                        .and_then(|mut matches| matches.pop());
                }
                if let Some(existing) = existing {
                    push_scope_once(&mut scopes, kin_model::IntentScope::Entity(existing.id));
                    if let Some(file) = existing.file_origin {
                        push_scope_once(&mut scopes, kin_model::IntentScope::Artifact(file));
                    }
                }
            }
            Some(McpMutationPayload::Relation { from, to, .. }) => {
                push_scope_once(&mut scopes, kin_model::IntentScope::Entity(*from));
                push_scope_once(&mut scopes, kin_model::IntentScope::Entity(*to));
            }
            Some(McpMutationPayload::Blob(_)) => {}
            None => {
                if crate::session::is_target_body_update(operation) {
                    if let Ok(existing) = resolve_target_entity(store, &operation.target) {
                        push_scope_once(&mut scopes, kin_model::IntentScope::Entity(existing.id));
                        if let Some(file) = existing.file_origin {
                            push_scope_once(&mut scopes, kin_model::IntentScope::Artifact(file));
                        }
                    }
                }
            }
        }
    }
    scopes
}

/// Indexed reasons for every staged operation the in-process commit path must
/// refuse even though staging and the daemon planner accept it.
///
/// Today that is exactly the payload-less source update (verb update/modify
/// with a `target` and a `body`). Turning that shape into a real change means
/// planning the exact span edit and projecting the new source into the working
/// file, and both live in the daemon (`kin-daemon`'s `plan_exact_transaction`).
/// The in-process path has no projection, so committing it here can only
/// produce a same-entity no-op delta while reporting success, discarding the
/// agent's body. Refuse instead.
///
/// Deliberately private and applied only after the daemon-delegate early
/// return in [`handle_transaction_commit`]: the daemon commits through
/// `kin-daemon`'s own entry point and the staging validation it shares with
/// this crate (`validate_staged_operations`, `uncommittable_operations`) is
/// untouched, so the daemon keeps accepting the shape.
fn offline_only_uncommittable_operations(operations: &[McpMutationOperation]) -> Vec<String> {
    operations
        .iter()
        .enumerate()
        .filter(|(_, op)| crate::session::is_target_body_update(op))
        .map(|(idx, op)| {
            format!(
                "operation #{idx} ('{}'): a payload-less source update (target '{}' plus body) \
                 requires the daemon commit path, which plans the exact span edit and projects \
                 the new source into the working file; the in-process commit path has no \
                 projection and would report success while discarding the body",
                op.verb,
                op.target.trim()
            )
        })
        .collect()
}

pub async fn handle_transaction_commit<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
) -> Result<ToolCallResult> {
    let transaction_id = get_string_param(args, "transaction_id")?;

    // If operations are provided, validate and stage them in one shot
    // to bypass state-loss across HTTP calls.
    let mut inline_ops = None;
    if let Some(ops_val) = args.get("operations") {
        let parsed: Vec<crate::session::McpMutationOperation> =
            serde_json::from_value(ops_val.clone()).map_err(|e| {
                crate::error::McpError::InvalidParams(format!("invalid operations array: {e}"))
            })?;
        crate::session::validate_staged_operations(&parsed)
            .map_err(crate::error::McpError::InvalidParams)?;
        inline_ops = Some(parsed);
    }

    if session_authority_mode.uses_daemon() {
        match crate::daemon_delegate::forward_tool_call("kin_transaction_commit", args).await {
            Ok(Some(value)) => return Ok(value),
            Ok(None) if session_authority_mode.requires_daemon() => {
                return Ok(daemon_required_unavailable("transaction commit"));
            }
            Ok(None) => {}
            Err(err) => return Ok(ToolCallResult::error(err)),
        }
    }

    // Serialize the entire local/offline transaction transition, final
    // preflight, graph apply, and terminal state change with intent mutation
    // and the other transaction lifecycle handlers.
    let _coordination_apply = sessions.lock_coordination_apply();

    if let Some(ops) = inline_ops {
        match sessions.stage_transaction(&transaction_id, ops) {
            Ok(_) => {}
            Err(err) => return Ok(ToolCallResult::error(err)),
        }
    }

    let tx = match sessions.get_transaction(&transaction_id) {
        Some(t) => t,
        None => {
            return Ok(ToolCallResult::error(format!(
                "Transaction not found: {}",
                transaction_id
            )))
        }
    };

    if tx.state != "active" && tx.state != "validated" {
        return Ok(ToolCallResult::error(format!(
            "Cannot commit transaction {} in state: {}",
            transaction_id, tx.state
        )));
    }

    // Fail loud on operations the commit path cannot turn into a delta (relation
    // update/modify, blob payloads) instead of silently dropping them while
    // still reporting "committed". Reject the whole commit atomically — nothing
    // is applied and the transaction stays active so the agent can fix it.
    let uncommittable = crate::session::uncommittable_operations(&tx.staged_operations);
    if !uncommittable.is_empty() {
        return Ok(ToolCallResult::error(format!(
            "Cannot commit transaction {}: {} staged operation(s) are not committable and would \
             be silently dropped:\n  - {}\nFix or remove them and retry; the transaction is left \
             active.",
            transaction_id,
            uncommittable.len(),
            uncommittable.join("\n  - ")
        )));
    }

    // Everything from here down is the in-process path: the daemon returned
    // above. Refuse the operation shapes only the daemon can honor rather than
    // applying a delta that reports success and changes nothing. Rejected
    // atomically and before any graph apply, so the transaction stays active.
    let daemon_only = offline_only_uncommittable_operations(&tx.staged_operations);
    if !daemon_only.is_empty() {
        return Ok(ToolCallResult::error(format!(
            "Cannot commit transaction {}: {} staged operation(s) require the daemon commit \
             path:\n  - {}\nCommit through a running Kin daemon, or restage the change as an \
             entity payload. The transaction is left active.",
            transaction_id,
            daemon_only.len(),
            daemon_only.join("\n  - ")
        )));
    }

    // Load-bearing ordering: run coordination enforcement against the fully
    // staged operation set before constructing or applying any graph delta.
    // A denied transaction remains active and graph truth is unchanged.
    let touched_scopes = transaction_touched_scopes(store, &tx.staged_operations);
    let coordination = sessions.evaluate_transaction_write(&tx.session_id, touched_scopes);
    if !coordination.allowed {
        let evidence =
            serde_json::to_string(&coordination).map_err(crate::error::McpError::Json)?;
        return Ok(ToolCallResult::error(format!(
            "coordination enforcement rejected transaction {transaction_id} before graph apply: {evidence}"
        )));
    }

    let mut entity_deltas = Vec::new();
    let mut relation_deltas = Vec::new();

    for op in tx.staged_operations {
        let verb = op.verb.to_lowercase();
        // Payload-less source updates were refused above, so every operation
        // reaching here carries a payload this path can turn into a real delta.
        if let Some(payload) = op.payload {
            match payload {
                McpMutationPayload::Entity(entity) => {
                    let mut old_opt = store.get_entity(&entity.id).ok().flatten();

                    // Fall back to lookup by name+kind if ID lookup fails (common for upserts)
                    if old_opt.is_none() {
                        let filter = kin_model::EntityFilter {
                            name_pattern: Some(entity.name.clone()),
                            kinds: Some(vec![entity.kind]),
                            ..Default::default()
                        };
                        if let Ok(mut found) = store.query_entities(&filter) {
                            if let Some(first) = found.pop() {
                                old_opt = Some(first);
                            }
                        }
                    }

                    // An agent knows an entity's name/id and the field it's
                    // changing but not Kin's file placement, so a partial payload
                    // often carries file_origin/span = None. Carry placement
                    // forward from the existing entity when the payload omits it.
                    let mut new = entity.clone();
                    if let Some(old) = &old_opt {
                        if new.file_origin.is_none() {
                            new.file_origin = old.file_origin.clone();
                        }
                        if new.span.is_none() {
                            new.span = old.span.clone();
                        }
                    } else if (verb == "create"
                        || verb == "add"
                        || verb == "upsert"
                        || verb == "insert")
                        && new.file_origin.is_none()
                    {
                        // Fail loud if it's a completely new entity with no placement info
                        return Ok(ToolCallResult::error(format!(
                            "Cannot commit transaction {}: Payload for new entity '{}' missing required 'file_origin'.",
                            transaction_id, entity.name
                        )));
                    }

                    if verb == "create" || verb == "add" || verb == "upsert" || verb == "insert" {
                        if old_opt.is_some()
                            && (verb == "upsert"
                                || verb == "create"
                                || verb == "add"
                                || verb == "insert")
                        {
                            // Convert upserts of existing entities into Modified deltas to avoid duplicates
                            entity_deltas.push(kin_model::change::EntityDelta::Modified {
                                old: old_opt.unwrap(),
                                new,
                            });
                        } else {
                            entity_deltas.push(kin_model::change::EntityDelta::Added { new });
                        }
                    } else if verb == "update" || verb == "modify" {
                        let old = old_opt.unwrap_or_else(|| entity.clone());
                        entity_deltas.push(kin_model::change::EntityDelta::Modified { old, new });
                    } else if verb == "delete" || verb == "remove" {
                        let Some(old) = old_opt else {
                            return Ok(ToolCallResult::error(format!(
                                "Cannot commit transaction {}: entity '{}' does not exist in \
                                 graph authority",
                                transaction_id, entity.id
                            )));
                        };
                        entity_deltas.push(kin_model::change::EntityDelta::Removed { old });
                    }
                }
                McpMutationPayload::Relation { from, to, kind } => {
                    if verb == "create" || verb == "add" || verb == "upsert" || verb == "insert" {
                        let relation = kin_model::relation::Relation {
                            id: kin_model::ids::RelationId::new(),
                            kind,
                            src: kin_model::relation::GraphNodeId::Entity(from),
                            dst: kin_model::relation::GraphNodeId::Entity(to),
                            confidence: 1.0,
                            origin: kin_model::relation::RelationOrigin::Manual,
                            created_in: None,
                            import_source: None,
                            evidence: Vec::new(),
                        };
                        relation_deltas
                            .push(kin_model::change::RelationDelta::Added { new: relation });
                    } else if verb == "delete" || verb == "remove" {
                        let matching_relation = store
                            .get_all_relations_for_entity(&from)
                            .ok()
                            .and_then(|rels| {
                                rels.into_iter().find(|r| {
                                    r.kind == kind
                                        && r.src == kin_model::relation::GraphNodeId::Entity(from)
                                        && r.dst == kin_model::relation::GraphNodeId::Entity(to)
                                })
                            });
                        if let Some(rel) = matching_relation {
                            relation_deltas
                                .push(kin_model::change::RelationDelta::Removed { old: rel });
                        }
                    }
                }
                McpMutationPayload::Blob(_) => {}
            }
        }
    }

    // Count the deltas the commit will actually apply so the response
    // distinguishes a real commit from a no-op. A relation delete that matched
    // nothing, or a transaction with no staged ops, lands here as zero.
    let ops_applied = entity_deltas.len() + relation_deltas.len();

    let delta = kin_model::change::TransactionDelta {
        entity_deltas,
        relation_deltas,
        tree_deltas: Vec::new(),
        admission_policy_delta: None,
    };

    if let Err(err) = store.apply_transaction_delta(&delta) {
        return Ok(ToolCallResult::error(format!(
            "Failed to commit transaction delta: {err}"
        )));
    }

    let committed_tx = sessions
        .commit_transaction(&transaction_id)
        .map_err(|e| crate::error::McpError::InvalidParams(e))?;

    // Report what the commit did. `ops_applied`/`empty` make a zero-op
    // commit unambiguous; the daemon path further enriches this with the real
    // `new_root_hash`, `modified_files`, `collision_warnings`, and `conflicts`
    // once the graph→file projection has run.
    let result = serde_json::json!({
        "transaction_id": committed_tx.transaction_id,
        "state": committed_tx.state,
        "status": "committed",
        "ops_applied": ops_applied,
        "empty": ops_applied == 0,
        "coordination": coordination,
    });
    let json = serde_json::to_string_pretty(&result).map_err(crate::error::McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const TRANSACTION_ABORT_DESC: &str = "\
Abort the transaction and discard all staged mutations.";

pub async fn handle_transaction_abort(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
) -> Result<ToolCallResult> {
    let transaction_id = get_string_param(args, "transaction_id")?;

    if session_authority_mode.uses_daemon() {
        match crate::daemon_delegate::forward_tool_call("kin_transaction_abort", args).await {
            Ok(Some(value)) => return Ok(value),
            Ok(None) if session_authority_mode.requires_daemon() => {
                return Ok(daemon_required_unavailable("transaction abort"));
            }
            Ok(None) => {}
            Err(err) => return Ok(ToolCallResult::error(err)),
        }
    }

    let _coordination_apply = sessions.lock_coordination_apply();
    match sessions.abort_transaction(&transaction_id) {
        Ok(tx) => {
            let result = serde_json::json!({
                "transaction_id": tx.transaction_id,
                "state": tx.state,
            });
            let json =
                serde_json::to_string_pretty(&result).map_err(crate::error::McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        Err(err) => Ok(ToolCallResult::error(err)),
    }
}
