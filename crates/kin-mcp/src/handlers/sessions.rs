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
is the legacy, minimal entry point: it records an assistant name and session ID and \
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
the session lifecycle uses: keep it alive with kin_session_heartbeat, declare what \
you'll touch via kin_register_intent (enabling collision detection against other \
agents), and close out with kin_session_end. Prefer this over the legacy \
register_session, which captures none of this context. When the session is daemon-backed \
the response also carries idle_timeout_secs and idle_reap_eligible_at: the latter is the \
next boundary at which an idle PID-less session may be reaped, not an unconditional \
expiry (a live registered PID is stronger liveness evidence). If your next step is a read \
phase that could outlast that boundary, send kin_session_heartbeat; any session-bound call \
also refreshes the window. A call on an already-reaped session fails saying so and names \
kin_session_start as the recovery. An in-process session returns neither field; heartbeat \
it on the same cadence rather than reading a boundary off the response. The capabilities \
in the response are what this session may actually do on this store, not an echo of what \
you sent: declaring nothing gets you what the store permits, and declaring less than that \
keeps your own restriction. capability_policy names what decided each bit, so you can tell \
a store permission (`store`) from your own self-limit (`client_declared`) from a bit only a \
declaration grants (`client_opt_in`: can_execute, which kin_session_exec requires) from a bit \
Kin checks nowhere today (`ungated`). Read can_write and can_commit before deciding a write is \
forbidden; they now report false only when this store really refuses it. Supply the original \
session_id UUID to re-register an absent daemon session before resuming a retained transaction \
or unpublished keyed mutation after restart; an already registered UUID refuses and offline registration is unsupported.";

pub async fn handle_session_start(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
) -> Result<ToolCallResult> {
    if args
        .get("session_id")
        .is_some_and(|value| !value.is_string())
    {
        return Ok(ToolCallResult::error(
            "session_id must be a UUID string when supplied",
        ));
    }
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
        let daemon_result = crate::daemon_delegate::forward_session_start_with_id(
            args.get("session_id").and_then(serde_json::Value::as_str),
            &vendor,
            &client_name,
            transport_str,
            pid,
            &cwd_str,
            capabilities.as_ref(),
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

    if args.contains_key("session_id") {
        return Ok(ToolCallResult::error("caller-allocated session_id registration requires an authenticated supporting daemon; offline registration cannot resume a durable keyed request"));
    }
    // This surface accepts kin_transaction_commit, so a session that declared
    // nothing is not a read-only session and must not be reported as one. The
    // daemon resolves the same question against its store.
    let capabilities = capabilities.unwrap_or(kin_model::SessionCapabilities {
        can_read: true,
        can_write: true,
        can_execute: false,
        can_branch: false,
        can_commit: true,
        max_concurrent_intents: 1,
    });
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
session and releases its intents). A daemon-backed response carries the refreshed \
idle_timeout_secs and idle_reap_eligible_at, the next boundary at which an idle PID-less \
session may be reaped; a live registered PID can keep it active beyond that boundary. \
Heartbeating an already-reaped session fails saying so and names kin_session_start as the \
recovery. An in-process response carries neither field and reports only that the session \
is alive.";

pub(crate) fn delegated_session_heartbeat_result(
    daemon_result: std::result::Result<Option<serde_json::Value>, String>,
    session_authority_mode: SessionAuthorityMode,
) -> Result<Option<ToolCallResult>> {
    match daemon_result {
        Ok(Some(value)) => {
            let json =
                serde_json::to_string_pretty(&value).map_err(crate::error::McpError::Json)?;
            Ok(Some(ToolCallResult::text(json)))
        }
        Ok(None) if session_authority_mode.requires_daemon() => {
            Ok(Some(daemon_required_unavailable("session heartbeat")))
        }
        Ok(None) => Ok(None),
        Err(error) => Ok(Some(ToolCallResult::error(error))),
    }
}

pub async fn handle_session_heartbeat(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "session_id")?;
    let session_id = parse_session_id(&id_str)?;

    if session_authority_mode.uses_daemon() {
        if let Some(result) = delegated_session_heartbeat_result(
            crate::daemon_delegate::forward_session_heartbeat(&id_str).await,
            session_authority_mode,
        )? {
            return Ok(result);
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
End an agent session and release everything it held. All of its registered intents are \
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
intent (with a soft or hard lock), other agents can see you're working a region and \
avoid clobbering it, and you can see if someone is already there. Reach for it before \
making changes in a multi-agent setting so concurrent work coordinates through graph \
truth instead of racing. Optionally set an expiry; release it early with \
kin_release_intent, and check who else is active with kin_check_traffic. Requires an \
active session from kin_session_start. A scope naming a symbol outside the repository is \
refused with external_symbol_not_served.";

pub async fn handle_register_intent<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "session_id")?;
    let session_id = parse_session_id(&id_str)?;
    let task_description = get_string_param(args, "task_description")?;

    let scopes_val = args.get("scopes").ok_or_else(|| {
        crate::error::McpError::InvalidParams("missing required parameter: scopes".into())
    })?;
    if let Some(refusal) = super::external_symbols::external_scope_refusal(
        store,
        scopes_val,
        "kin_register_intent",
        "scopes",
    )? {
        return Ok(ToolCallResult::error(refusal));
    }
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
                return Ok(crate::daemon_delegate::relayed_scope_refusal(&err)
                    .unwrap_or_else(|| ToolCallResult::error(err)));
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
an intent covered, rather than holding the lock until session end. Doing so keeps the \
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
changing something in a multi-agent setting. It surfaces in-flight intents and locks \
so you can avoid collisions, coordinate, or pick different work. It's the read-side \
companion to kin_register_intent (the write side): one declares what you'll touch, the \
other tells you what others are touching. A scope naming a symbol outside the repository \
is refused with external_symbol_not_served, since no intent can be declared on one.";

pub async fn handle_check_traffic<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
) -> Result<ToolCallResult> {
    let scopes_val = args.get("scopes").ok_or_else(|| {
        crate::error::McpError::InvalidParams("missing required parameter: scopes".into())
    })?;
    if let Some(refusal) = super::external_symbols::external_scope_refusal(
        store,
        scopes_val,
        "kin_check_traffic",
        "scopes",
    )? {
        return Ok(ToolCallResult::error(refusal));
    }
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
                return Ok(crate::daemon_delegate::relayed_scope_refusal(&err)
                    .unwrap_or_else(|| ToolCallResult::error(err)));
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
    // A file named `mutable.rs` contributes a module surface whose name is the
    // file stem, beside the function the author actually declared. The agent
    // names that function. The surface is not a second declaration, so it does
    // not make the name ambiguous when the declared entity is in the same file.
    // Two declared entities, or two file surfaces in different files, stay
    // ambiguous and the refusal still names them.
    matches = without_colocated_file_module_surfaces(matches);
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
                        "{} ({:?} at {}): {}",
                        entity.id,
                        entity.kind,
                        candidate_location(entity),
                        candidate_declaration(entity)
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

/// The synthetic module a source file contributes for its own path.
///
/// Adapters mint it with the signature `module {path}` and the file stem as
/// its name. A `mod` item the author wrote has the module's own declaration
/// as its signature, so this predicate does not treat that item as a surface.
fn is_file_module_surface(entity: &kin_model::Entity) -> bool {
    let Some(file) = entity.file_origin.as_ref() else {
        return false;
    };
    entity.kind == kin_model::EntityKind::Module && entity.signature == format!("module {}", file.0)
}

/// Drop a file-module surface that only repeats a declared entity in the same
/// file. Surfaces with no colocated declaration stay, so a name that is only
/// a file stem is still that file, and two of them stay ambiguous.
fn without_colocated_file_module_surfaces(
    mut matches: Vec<kin_model::Entity>,
) -> Vec<kin_model::Entity> {
    let hidden: Vec<_> = matches
        .iter()
        .filter(|entity| is_file_module_surface(entity))
        .filter(|surface| {
            matches.iter().any(|other| {
                !is_file_module_surface(other) && other.file_origin == surface.file_origin
            })
        })
        .map(|entity| entity.id)
        .collect();
    if hidden.is_empty() {
        return matches;
    }
    matches.retain(|entity| !hidden.contains(&entity.id));
    matches
}

/// `file:line` for an ambiguity candidate, or a stable placeholder when the
/// entity carries no source origin.
fn candidate_location(entity: &kin_model::Entity) -> String {
    match (entity.file_origin.as_ref(), entity.span.as_ref()) {
        // `file:line` is read straight into an editor, so it carries the 1-based
        // line rather than the graph's 0-based row.
        (Some(file), Some(span)) => format!(
            "{}:{}",
            file.0,
            crate::handlers::common::presentation_line(span.start_line)
        ),
        (Some(file), None) => file.0.clone(),
        (None, _) => "<no source origin>".to_string(),
    }
}

/// The one-line declaration that tells two same-named candidates apart.
///
/// A location says where a candidate lives; the declaration says what it is,
/// which is what the caller is actually choosing between when the same name
/// appears as several overloads or trait implementations. Bounded so one
/// ambiguity refusal cannot carry an unbounded signature dump.
fn candidate_declaration(entity: &kin_model::Entity) -> String {
    /// Long enough for a real signature, short enough that a dozen candidates
    /// stay readable.
    const MAX_DECLARATION: usize = 160;

    let declaration = entity
        .signature
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or(entity.name.as_str());
    if declaration.chars().count() <= MAX_DECLARATION {
        return declaration.to_string();
    }
    let truncated = declaration
        .chars()
        .take(MAX_DECLARATION)
        .collect::<String>();
    format!("{truncated}...")
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
Stage targeted entity and relationship mutations onto an active transaction. \
Prefer a guarded entity patch: verb 'patch', the exact entity UUID as target, and \
payload.EntitySourcePatch with the unchanged source_base from get_entity_source and \
edits containing unique old_text/new_text anchors. Each anchor applies within that \
original entity body. A stale, ambiguous, missing or overlapping anchor is refused. \
An 'update' or 'modify' operation replaces one entity's whole body: target its UUID and \
carry payload.EntitySourceBase with the unchanged source_base from get_entity_source, which \
binds the edit to the exact revision read. Without it the operation is refused as \
source_base_required; one fresh get_entity_source read and a resend is the fix. Preserve its \
own source indentation and use complete entity source from get_entity_source; a retrieval \
excerpt marked [truncated] is refused. \
Create a declaration with verb 'create' and payload.EntityCreate. Addressed to a unit, \
which is the form for an empty repository and for every Go declaration kind, it carries \
the repository_base from session, status or the last mutate, the unit by language \
identity (Go: package relative to the module root, package name, role source or test), \
name, kind, body and the imports it needs, and its target is the declared name; Kin \
derives the unit's file and owns its package clause and import block. Anchored beside a \
function, it carries that anchor's source_base and placement, with the anchor's UUID as \
target. Add or remove imports with verb 'update', the package name as target and \
payload.UnitImports. Remove a function with verb 'remove', its UUID and \
payload.EntityRemove carrying its source_base. These operations require a supporting \
daemon; their schemas state language, kind and placement limits. Relation payloads \
change edges; a structured Entity payload is Kin's internal record and never creates \
source. File-level \
create, replace, delete and rename operations are refused. Source-tree conversion \
and materialization are separate from semantic agent work. Every operation requires \
verb, target and description; unknown fields are refused.";

pub async fn handle_transaction_stage<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
) -> Result<ToolCallResult> {
    let transaction_id = get_string_param(args, "transaction_id")?;
    let operations_val = args.get("operations").ok_or_else(|| {
        crate::error::McpError::InvalidParams("missing required parameter: operations".into())
    })?;

    if let Some(refusal) = super::external_symbols::external_relation_refusal(
        store,
        operations_val,
        "kin_transaction_stage",
    )? {
        return Ok(ToolCallResult::error(refusal));
    }

    let operations: Vec<McpMutationOperation> =
        crate::session::parse_staged_operations(operations_val)
            .map_err(crate::error::McpError::InvalidParams)?;

    // Stage-time validation: reject intrinsically-malformed operations now, with
    // an actionable message, rather than letting the commit path silently drop
    // them. Runs before forwarding so the agent gets the same fast failure in
    // both daemon and in-process modes.
    crate::session::validate_semantic_operations(&operations)
        .map_err(crate::error::McpError::InvalidParams)?;

    // A body Kin cut short is not the entity's source, and the paragraph above
    // in this tool's own description has always said so. Enforced here so the
    // promise is construction rather than instruction, and refused before the
    // forward so the daemon and in-process modes answer identically.
    if let Err(error) = reject_truncated_bodies(&operations) {
        return Ok(ToolCallResult::error(error));
    }

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
    if let Some(tx) = sessions.get_transaction(&transaction_id) {
        if let Err(error) = crate::session::validate_semantic_operations(&tx.staged_operations) {
            return Ok(ToolCallResult::error(error));
        }
    }
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
Publish all staged mutations atomically through exact repository authority. The daemon loads \
source from repository CAS, splices existing entity \
body edits in memory, reparses the final bytes, and journals semantic change, exact workspace \
tree, and ref publication together. Only targeted entity and relationship operations are \
admitted; whole-file creation, replacement, deletion and relocation are refused. Prefer a \
guarded entity patch for a source change. Relation-only transactions, EntityCreate addressed \
to a unit or anchored, UnitImports and EntityRemove are admitted. Unsupported \
lifecycle forms, metadata-only source edits, \
ambiguous or overlapping spans, non-UTF-8 source, \
gitlinks, and mismatched authority fail before mutation. On success the result names \
status, ops_applied, empty, change_id, repository_generation, new_root_hash, and modified_files. \
A workspace holding working-tree content its base change does not carry does not block the \
commit and is not reverted by it: that content is published beside the staged operations and the \
fold is declared rather than silent. The reply then adds staged_operation_files and \
carried_pending_files beside modified_files, and the change message names the count and a sample \
of what was carried. Neither key appears when nothing was carried. The daemon derives \
the semantic state of carried source from its exact admitted content before publication. \
The carried split describes prior pending workspace content, not authorship by this request. \
New publication requires a live session in every coordination mode. After daemon restart, \
re-register the original session_id with kin_session_start before resuming retained staged work. \
Owner expiry preserves a recent staged payload; it does not clear it. Already-published receipts \
remain recoverable without re-registration. A transaction whose owning session started without \
can_write or can_commit is refused in every coordination mode. Before graph application, exact \
entity/artifact intent conflicts are attested; enforce mode rejects them before graph truth \
changes. Contract-scope \
coverage remains explicitly false until touched contracts can be derived from the semantic \
delta. An invalid or unplannable operation may be cleared and named in a refusal; re-stage only \
the rejected operations named by that response on the SAME transaction and commit again. \
Owner, coordination and source-base refusals preserve the staged payload. \
kin_transaction_abort is the clean exit if you would rather abandon it. An optional operations array may stage and commit in one call and uses the same \
operation shapes as kin_transaction_stage; it \
commits with identical durability, so a success naming modified_files means the body reached the \
file, and re-sending the same array after an interrupted commit resumes it rather than staging it \
twice. An entity replacement carries `body` with EntitySourceBase; an anchored patch carries \
EntitySourcePatch, and creation carries EntityCreate.body. Unknown fields are refused \
by name, never accepted with the source dropped. A refusal ends with a \
one-line JSON object carrying schema, code, and the operations it names, so you can branch on the \
code instead of reading the sentence. On success the change is attributed to the calling session: \
its vendor and client name become the change author and a queryable audit record, so \
kin_provenance_query, kin history, and kin blame all name the agent that wrote it. Re-sending a \
commit that already landed is safe and is answered, not refused: the reply carries \
already_applied true beside the original change_id, repository_generation, and modified_files, and \
publishes nothing further. That answer is derived from the repository receipt rather than from any \
in-memory record, so it survives the transaction being forgotten and stays correct however many \
times it is retried, and it declares the same carried_pending_files split the original answer did. \
It omits ops_applied, which only the staged record could name. A commit that never landed under \
this id still fails closed and says authority was consulted too. already_applied is present on \
every successful commit and is the one field that separates these two answers: false means this \
call moved authority, true means an earlier call did and this one published nothing. Read it to \
decide whether a retry double-applied, because every other field is identical across both.";

fn push_scope_once(scopes: &mut Vec<kin_model::IntentScope>, scope: kin_model::IntentScope) {
    if !scopes.contains(&scope) {
        scopes.push(scope);
    }
}

/// The artifact a unit-addressed operation writes, when the store can say
/// where the unit's module root is. A store without a tree inventory claims no
/// artifact rather than guessing one.
fn push_unit_scope<G: GraphStore>(
    store: &G,
    scopes: &mut Vec<kin_model::IntentScope>,
    unit: &crate::source_unit::SourceUnit,
) {
    if let Ok(Some(tree)) = store.resolved_tree_snapshot() {
        if let Ok(path) = crate::source_unit::unit_projection_path(unit, &tree) {
            push_scope_once(
                scopes,
                kin_model::IntentScope::Artifact(kin_model::FilePathId::new(path.to_string())),
            );
        }
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
            Some(McpMutationPayload::EntityCreate(
                create @ crate::entity_lifecycle::EntityCreate {
                    source_base: None, ..
                },
            )) => {
                if let Some((_, unit)) = create.unit_target() {
                    push_unit_scope(store, &mut scopes, unit);
                }
            }
            Some(McpMutationPayload::UnitImports(imports)) => {
                push_unit_scope(store, &mut scopes, &imports.unit);
            }
            Some(McpMutationPayload::EntitySourceBase(base))
            | Some(McpMutationPayload::EntitySourcePatch(
                crate::source_base::EntitySourcePatch {
                    source_base: base, ..
                },
            ))
            | Some(McpMutationPayload::EntityCreate(crate::entity_lifecycle::EntityCreate {
                source_base: Some(base),
                ..
            }))
            | Some(McpMutationPayload::EntityRemove(crate::entity_lifecycle::EntityRemove {
                source_base: base,
            })) => {
                push_scope_once(&mut scopes, kin_model::IntentScope::Entity(base.entity_id));
                if let Ok(Some(entity)) = store.get_entity(&base.entity_id) {
                    if let Some(file) = entity.file_origin {
                        if let Some(McpMutationPayload::EntityCreate(create)) =
                            operation.payload.as_ref()
                        {
                            if create.placement
                                == Some(crate::entity_lifecycle::EntityPlacement::NewSourceUnit)
                            {
                                if let Ok(path) = crate::entity_lifecycle::generated_source_path(
                                    &file,
                                    entity.language,
                                    &create.name,
                                ) {
                                    push_scope_once(
                                        &mut scopes,
                                        kin_model::IntentScope::Artifact(
                                            kin_model::FilePathId::new(path.to_string()),
                                        ),
                                    );
                                }
                            }
                        }

                        push_scope_once(&mut scopes, kin_model::IntentScope::Artifact(file));
                    }
                }
            }
            // A payload-less entity update is refused before it can commit
            // (`crate::session::source_base_required`), so it claims no scope.
            Some(McpMutationPayload::Blob(_)) | None => {}
        }
    }
    scopes
}

/// Indexed reasons for every staged operation the in-process commit path must
/// refuse even though staging and the daemon planner accept it.
///
/// That is every operation carrying new source text, whether or not it also
/// carries an entity payload. Turning a body into a real change means planning
/// the exact span edit and projecting the new source into the working file, and
/// both live in the daemon (`kin-daemon`'s `plan_exact_transaction`). The
/// in-process path has no projection, so it can only apply whatever else the
/// operation carries and drop the body.
///
/// The payload-ful case is the one that bit hardest, because it does not look
/// like a no-op from the outside: the entity payload commits, the response says
/// `ops_applied: 1` and `empty: false`, and the source the agent actually sent
/// is gone. A partial success reported as a success is worse than a refusal,
/// because the caller has no way to detect it and no reason to retry.
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
        .filter(|(_, op)| {
            crate::session::carries_source_body(op)
                || matches!(op.payload, Some(McpMutationPayload::EntityRemove(_)))
                || crate::session::is_retired_source_file(op)
                || crate::session::is_renamed_source_file(op)
        })
        .map(|(idx, op)| {
            // A retirement and a rename carry no body, so the body-shaped
            // refusal above cannot see them, and the in-process delta builder
            // has no arm for either: both would land as `ops_applied: 0`,
            // `empty: true`, which is a refusal wearing the costume of a
            // no-op transaction. They need the daemon for the same reason a
            // body edit does. A tree transition has to reach repository
            // authority and the working copy has to be projected to match, and
            // this path can do neither.
            let shape = if matches!(
                op.payload,
                Some(
                    McpMutationPayload::EntityCreate(_)
                        | McpMutationPayload::EntityRemove(_)
                        | McpMutationPayload::UnitImports(_)
                )
            ) {
                "a source-bound entity lifecycle operation"
            } else if crate::session::is_retired_source_file(op) {
                "a payload-less retirement (target naming a tracked path)"
            } else if crate::session::is_renamed_source_file(op) {
                "a payload-less rename (target plus destination)"
            } else if crate::session::is_replaced_source_file(op) {
                "a payload-less rewrite (target naming a tracked path, plus the file's complete \
                 new body)"
            } else if op.payload.is_some() {
                "an entity payload plus a source body"
            } else {
                "a payload-less source update (target plus body)"
            };
            let target = op.target.trim();
            let target = if target.is_empty() {
                "(unnamed)"
            } else {
                target
            };
            format!(
                "operation #{idx} ('{}'): {shape} for target '{target}' requires the daemon \
                 commit path, which carries the tree transition into repository authority and \
                 projects the working copy to match; the in-process commit path has no \
                 projection and would report success while discarding it",
                op.verb,
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
    // to bypass state-loss across HTTP calls. Decoded through the same parser
    // the stage tool uses, so an inline caller gets the identical contract: a
    // field Kin does not model is named rather than dropped, and a shape the
    // commit path cannot honor is refused here instead of at commit.
    let mut inline_ops = None;
    if let Some(ops_val) = args.get("operations") {
        let parsed = crate::session::parse_staged_operations(ops_val)
            .map_err(crate::error::McpError::InvalidParams)?;
        crate::session::validate_staged_operations(&parsed)
            .map_err(crate::error::McpError::InvalidParams)?;
        if let Err(error) = reject_truncated_bodies(&parsed) {
            return Ok(ToolCallResult::error(error));
        }
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

    if let Some(ref operations) = inline_ops {
        crate::session::validate_semantic_operations(operations)
            .map_err(crate::error::McpError::InvalidParams)?;
    }

    // Serialize the entire local/offline transaction transition, final
    // preflight, graph apply, and terminal state change with intent mutation
    // and the other transaction lifecycle handlers.
    let _coordination_apply = sessions.lock_coordination_apply();

    // Refused before any inline operation is staged, so a read-only session's
    // commit leaves the transaction exactly as the caller last saw it.
    if let Some(owner) = sessions
        .get_transaction(&transaction_id)
        .map(|tx| tx.session_id)
    {
        if let Err(error) =
            sessions.require_write_capability(&owner, crate::session::WriteDoor::Commit)
        {
            return Ok(ToolCallResult::error(error));
        }
    }

    if let Some(tx) = sessions.get_transaction(&transaction_id) {
        if let Err(error) = crate::session::validate_semantic_operations(&tx.staged_operations) {
            return Ok(ToolCallResult::error(error));
        }
    }
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

    if let Err(error) = sessions.require_live_session(&tx.session_id) {
        return Ok(ToolCallResult::error(error));
    }

    if tx.state != "active" && tx.state != "validated" {
        return Ok(ToolCallResult::error(format!(
            "Cannot commit transaction {} in state: {}",
            transaction_id, tx.state
        )));
    }

    if let Err(error) = crate::session::validate_semantic_operations(&tx.staged_operations) {
        return Ok(ToolCallResult::error(error));
    }

    // Fail loud on operations the commit path cannot turn into a delta (relation
    // update/modify, blob payloads) instead of silently dropping them while
    // still reporting "committed". Reject the whole commit atomically: nothing
    // is applied and the transaction stays active so the agent can fix it.
    let uncommittable = crate::session::uncommittable_operations(&tx.staged_operations);
    if !uncommittable.is_empty() {
        return Ok(ToolCallResult::error(
            crate::session::CommitRefusal::new(
                crate::session::CommitRefusalCode::NotCommittable,
                &transaction_id,
                uncommittable,
            )
            .render(),
        ));
    }

    // Everything from here down is the in-process path: the daemon returned
    // above. Refuse the operation shapes only the daemon can honor rather than
    // applying a delta that reports success while dropping the source the
    // caller sent. Rejected atomically and before any graph apply, so the
    // transaction stays active.
    let daemon_only = offline_only_uncommittable_operations(&tx.staged_operations);
    if !daemon_only.is_empty() {
        return Ok(ToolCallResult::error(
            crate::session::CommitRefusal::new(
                crate::session::CommitRefusalCode::SourceBodyRequiresDaemonCommit,
                &transaction_id,
                daemon_only,
            )
            .render(),
        ));
    }

    if let Some(refusal) = super::external_symbols::external_relation_refusal(
        store,
        &serde_json::to_value(&tx.staged_operations)?,
        "kin_transaction_commit",
    )? {
        return Ok(ToolCallResult::error(refusal));
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
                McpMutationPayload::EntitySourceBase(_)
                | McpMutationPayload::EntitySourcePatch(_)
                | McpMutationPayload::EntityCreate(_)
                | McpMutationPayload::EntityRemove(_)
                | McpMutationPayload::UnitImports(_) => {
                    return Ok(ToolCallResult::error(
                        "Guarded entity source edits require the exact daemon commit path",
                    ));
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
        external_reference_deltas: Vec::new(),
        resolution_record_deltas: Vec::new(),
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

/// The token Kin appends where it cuts a rendered body short.
///
/// `clip_rendered_text_with_cap` writes `"... [truncated]"`, and that is the
/// spelling a source body carries. The constant holds only the bracketed part
/// because the ellipsis before it is not stable across the codebase: the
/// daemon delegate already writes the same token after a Unicode ellipsis when
/// it cuts an error body (`daemon_delegate.rs`). Keying on the ellipsis would
/// make this guard depend on which renderer produced the text, which is the one
/// thing the caller cannot tell us.
const TRUNCATION_MARKER: &str = "[truncated]";

/// Refuse any staged operation whose `body` is text Kin itself cut short.
///
/// An entity response's `source_excerpt`, a context pack's body and a trace
/// step's body are all clipped at [`MCP_SOURCE_MAX_LINES`] lines or
/// [`MCP_SOURCE_MAX_CHARS`] characters, and the clip is marked. Staging what
/// came back is the one mistake an agent makes without noticing: the text is
/// syntactically plausible, and the commit path replaces the entity's whole
/// span with whatever arrives, so the rest of the function is simply gone and
/// the receipt still says `committed`.
///
/// The stage tool description has said such a body "must not be staged as-is"
/// since the shape shipped. That is instruction. This is construction, and it
/// runs before staging or forwarding on `kin_transaction_stage`, `kin_mutate`,
/// and the inline operations of `kin_transaction_commit`. The daemon's direct
/// commit route uses the same guard before accepting inline operations.
///
/// Matched on a body whose trailing text IS the marker, never on one that
/// merely contains it. Kin's own source carries the literal token (the CLI's
/// trace renderer writes it), and refusing to edit those entities would be a
/// false positive with no way around it.
pub fn reject_truncated_bodies(
    operations: &[McpMutationOperation],
) -> std::result::Result<(), String> {
    for (idx, op) in operations.iter().enumerate() {
        let Some(body) = op.body.as_deref().or(match op.payload.as_ref() {
            Some(McpMutationPayload::EntityCreate(create)) => Some(create.body.as_str()),
            _ => None,
        }) else {
            continue;
        };
        if !body.trim_end().ends_with(TRUNCATION_MARKER) {
            continue;
        }
        let target = op.target.trim();
        let target = if target.is_empty() {
            "(unnamed)"
        } else {
            target
        };
        return Err(format!(
            "operation #{idx} ('{}'): `body` for target '{target}' ends in \
             \"{TRUNCATION_MARKER}\", so it is text Kin cut short rather than the entity's full \
             source. Bodies rendered inside search results, context packs and trace steps are \
             capped at {MCP_SOURCE_MAX_LINES} lines or {MCP_SOURCE_MAX_CHARS} characters and the \
             cut is marked; committing that text would replace the entity's whole span with the \
             part that fit. get_entity_source is the read that serves an entity's complete span \
             and applies no line or character cap of its own. Read the body there, then send \
             that.",
            op.verb,
        ));
    }
    Ok(())
}

/// The change message a `kin_mutate` call asked for, if it asked for one.
///
/// Trimmed, and an all-whitespace summary is read as no summary rather than as
/// a request for a blank subject line. Absent, the commit records exactly what
/// it recorded before this argument existed, so a caller that sends nothing
/// sees no change at all.
pub fn commit_message_argument(arguments: &HashMap<String, serde_json::Value>) -> Option<String> {
    let summary = arguments
        .get("summary")
        .and_then(serde_json::Value::as_str)?
        .trim();
    (!summary.is_empty()).then(|| summary.to_string())
}

pub const MUTATE_DESC: &str = "\
Atomically validate and commit a batch of graph mutations in a single call. Automatically \
manages transaction lifecycle (begin, validation, commit, and abort-on-refusal) so an agent \
does not need multi-step transaction ceremonies. Provide an operations array with mutation \
verbs ('patch', 'create', 'update', 'delete') and payloads, and an optional `summary` that becomes the \
recorded change message instead of the bare transaction line. On success returns a compact \
receipt with status, ops_applied, change_id, and modified_files. Every refusal comes back as a \
tool error you can read and retry from, never as a protocol fault: a malformed operations array, \
a body Kin cut short, a failed validation and a refused commit all return the structured reason. \
Without request_id, a refused commit is aborted unless it reports source_base_conflict, which \
retains the attempted operations; a repository_base_conflict is aborted too and says so, since \
you still hold the operations. If abort cannot run, the answer names the transaction left open. \
With request_id, an authenticated supporting daemon durably binds the \
complete request to one transaction before execution. Retry with the same session_id, request_id \
and arguments to recover the original receipt after a lost response or restart; changed arguments \
refuse. Keyed success uses schema kin.mutate.receipt.v1 and original authoritative roots_before \
and roots_after instead of the legacy live-graph new_root_hash. An expired session can recover \
published work but cannot resume unpublished work. Keyed offline or older-daemon calls refuse. \
Keyed requests accept only session_id, request_id, operations, scope and summary; unknown fields \
and unsupported freshness constraints refuse before execution. Every source change is guarded. \
An edit of an existing entity carries the source_base returned by a current get_entity_source \
read in the matching EntitySourceBase, EntitySourcePatch or EntityRemove payload; a \
whole-entity update without EntitySourceBase is refused as source_base_required, and one fresh \
read and a resend is the fix. An EntityCreate or UnitImports addressed to a unit carries the \
repository_base from session, status or the last mutate's reply, and a stale one is refused as \
repository_base_conflict carrying current_repository_base and a next_step: resend with that \
base, first re-reading with get_entity_source each entity its source_reads_required lists; \
anchored creation uses the anchor's \
source_base. An unkeyed success also carries the next repository_base and created_entities; \
a keyed receipt keeps its fixed shape, so a keyed caller reads the next base with status. \
A new stale request refuses without discarding its operations; an already-published \
key still recovers its original receipt. Keys are retained within configurable daemon quotas. \
A relation whose from or to names a symbol outside the repository is refused with \
external_symbol_not_served, to add or to remove it: a language server proves such an \
edge from the caller's source.";

/// Whether any relation operation in a raw `operations` array names a symbol
/// outside the repository by its `external_reference:` address at either end.
///
/// A route that holds no graph asks this before it decodes the array, because
/// an address is no entity id and decoding refuses it as a malformed
/// operation. Such an array is left for the route that holds the graph, which
/// answers the address by what it names.
pub fn names_external_relation_endpoint(operations: &serde_json::Value) -> bool {
    operations.as_array().is_some_and(|entries| {
        entries.iter().any(|entry| {
            ["from", "to"].iter().any(|end| {
                entry["payload"]["Relation"][*end]
                    .as_str()
                    .is_some_and(super::external_symbols::is_external_address)
            })
        })
    })
}

/// Decode and check the operations a `kin_mutate` call carries.
///
/// Shared by both routes so the belt gets one contract whatever is serving it,
/// and returning the refusal rather than an `Err` because every refusal here is
/// a tool error: the caller is a model that just wrote this argument, and the
/// one-shot is only worth having if a rejected attempt is retryable from what
/// came back. A JSON-RPC fault leaves the client to decide whether the model
/// ever sees the reason, while `is_error` puts it in the transcript the next
/// turn reads.
pub fn checked_mutate_operations(
    arguments: &HashMap<String, serde_json::Value>,
) -> std::result::Result<&serde_json::Value, ToolCallResult> {
    let Some(ops_val) = arguments.get("operations") else {
        return Err(ToolCallResult::error(
            "Missing required parameter: 'operations' array is required for kin_mutate.",
        ));
    };
    let parsed = crate::session::parse_staged_operations(ops_val).map_err(ToolCallResult::error)?;
    crate::session::validate_semantic_operations(&parsed).map_err(ToolCallResult::error)?;
    reject_truncated_bodies(&parsed).map_err(ToolCallResult::error)?;
    Ok(ops_val)
}

/// A supplied ID always requests the durable daemon contract. Invalid IDs must
/// never fall through to unkeyed execution. The string is opaque and exact.
pub fn checked_mutate_request_id(
    arguments: &HashMap<String, serde_json::Value>,
) -> std::result::Result<Option<&str>, String> {
    let Some(value) = arguments.get("request_id") else {
        return Ok(None);
    };
    let id = value.as_str().ok_or(
        "invalid_request_id: request_id must be a nonempty UTF-8 string of at most 256 bytes",
    )?;
    if id.trim().is_empty() || id.len() > 256 {
        return Err(
            "invalid_request_id: request_id must be a nonempty UTF-8 string of at most 256 bytes"
                .to_string(),
        );
    }
    Ok(Some(id))
}

pub const DURABLE_MUTATE_TOOL: &str = "kin_mutate_durable_v1";

/// The session a daemon-owned mutation belongs to, or the refusal that names it.
///
/// The daemon owns sessions and resolves a transaction against one it holds, so
/// there is nothing here to fall back to: a session invented locally is an id
/// the daemon has never heard of, and `kin_transaction_begin` refuses it one
/// call later with a message about a session rather than about the argument
/// that was actually missing. Say the true thing at the call that can still be
/// fixed, and name the tool that produces the id.
fn required_session(
    arguments: &HashMap<String, serde_json::Value>,
) -> std::result::Result<String, ToolCallResult> {
    arguments
        .get("session_id")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            ToolCallResult::error(
                "Missing required parameter: 'session_id'. This server's sessions are owned by \
                 the Kin daemon, so a mutation names the session it belongs to. Call \
                 kin_session_start first and pass the session_id it returns; an agent harness \
                 that already holds the session fills this in for you.",
            )
        })
}

/// Stamp the caller's own request id into a receipt it can match its retry against.
fn carry_request_id(result: &mut ToolCallResult, request_id: Option<&str>) {
    let Some(request_id) = request_id else {
        return;
    };
    let Some(crate::types::ContentBlock::Text { text }) = result.content.first_mut() else {
        return;
    };
    let Ok(mut map) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    if let Some(obj) = map.as_object_mut() {
        obj.insert("request_id".to_string(), serde_json::json!(request_id));
        *text = serde_json::to_string_pretty(&obj).unwrap_or_else(|_| text.clone());
    }
}

/// Send a one-shot mutation to the daemon's exact repository writer.
///
/// A keyed call travels intact under the durable protocol's versioned internal
/// name. An unkeyed call retains the begin/inline-commit expansion and its
/// historical abort-on-refusal behavior. The offline graph-only handler cannot
/// promise either exact source projection or durable request identity.
pub async fn mutate_through_daemon(
    arguments: &HashMap<String, serde_json::Value>,
) -> Result<ToolCallResult> {
    mutate_through(
        arguments,
        |name: &'static str, args: HashMap<String, serde_json::Value>| async move {
            crate::daemon_delegate::forward_tool_call(name, &args).await
        },
    )
    .await
}

/// Transport injection keeps compatibility and failure behavior testable:
/// keyed calls never expand or abort after an uncertain transport result.
pub(super) async fn mutate_through<F, Fut>(
    arguments: &HashMap<String, serde_json::Value>,
    forward: F,
) -> Result<ToolCallResult>
where
    F: Fn(&'static str, HashMap<String, serde_json::Value>) -> Fut,
    Fut: std::future::Future<Output = std::result::Result<Option<ToolCallResult>, String>>,
{
    match checked_mutate_request_id(arguments) {
        Err(error) => return Ok(ToolCallResult::error(error)),
        Ok(Some(_)) => {
            if let Err(refusal) = required_session(arguments) {
                return Ok(refusal);
            }
            // The versioned internal name is intentionally unknown to old
            // daemons. Never fall back to begin/commit after accepting a key.
            return Ok(match forward(DURABLE_MUTATE_TOOL, arguments.clone()).await {
                Ok(Some(result)) => result,
                Ok(None) => ToolCallResult::error("durable_request_daemon_required: keyed kin_mutate requires a daemon supporting kin_mutate_durable_v1; no mutation was started"),
                Err(error) => ToolCallResult::error(format!("durable_request_outcome_unknown: {error}; retry kin_mutate with the same session_id, request_id and complete arguments; do not begin or abort a replacement transaction")),
            });
        }
        Ok(None) => {}
    }
    // An operation naming a symbol outside the repository by its address is
    // no entity id, so it cannot be decoded here, and only the daemon holds
    // the graph that says what it names; its commit refuses it by that.
    let ops_val = match arguments.get("operations") {
        Some(ops_val) if names_external_relation_endpoint(ops_val) => ops_val,
        _ => match checked_mutate_operations(arguments) {
            Ok(ops_val) => ops_val,
            Err(refusal) => return Ok(refusal),
        },
    };
    let session_id = match required_session(arguments) {
        Ok(session_id) => session_id,
        Err(refusal) => return Ok(refusal),
    };
    let scope = arguments
        .get("scope")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("repository")
        .to_string();
    let request_id = arguments
        .get("request_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);

    let begin_args = HashMap::from([
        ("session_id".to_string(), serde_json::json!(session_id)),
        ("scope".to_string(), serde_json::json!(scope)),
    ]);
    let mut begin_res = match forward("kin_transaction_begin", begin_args).await {
        Ok(Some(res)) => res,
        Ok(None) => return Ok(daemon_required_unavailable("transaction begin")),
        Err(err) => return Ok(ToolCallResult::error(err)),
    };
    if begin_res.is_error == Some(true) {
        name_the_mutate_door(&mut begin_res);
        // A begin refused because this call's session is gone started nothing:
        // no transaction exists and no operation was sent. That is the one
        // refusal a caller may answer by opening a new session and resending, so
        // it alone gets a machine-readable first line. Nothing after the begin
        // (the commit, the abort, the open-transaction note) ever writes one.
        if let Some(crate::types::ContentBlock::Text { text }) = begin_res.content.first_mut() {
            if text.starts_with(&format!("Session not found: {session_id}.")) {
                let marker = serde_json::json!({
                    "stage": "begin",
                    "refusal": "session_not_found",
                    "session_id": session_id,
                });
                *text = format!("kin_mutate_not_started: {marker}\n{text}");
            }
        }
        return Ok(begin_res);
    }

    let tx_id = begin_res
        .content
        .first()
        .and_then(|block| match block {
            crate::types::ContentBlock::Text { text } => {
                serde_json::from_str::<serde_json::Value>(text).ok()
            }
        })
        .and_then(|value| {
            value
                .get("transaction_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        });
    let Some(tx_id) = tx_id else {
        return Ok(ToolCallResult::error(
            "kin_transaction_begin answered without a transaction_id, so this mutation has no \
             transaction to commit. Nothing was applied.",
        ));
    };

    let mut commit_args = HashMap::from([
        ("transaction_id".to_string(), serde_json::json!(tx_id)),
        ("session_id".to_string(), serde_json::json!(session_id)),
        ("operations".to_string(), ops_val.clone()),
    ]);
    // `message`, not `description`. `description` is already the name of the
    // per-operation field, and the daemon reads `message` off the commit call as
    // the change message a human will read in history. Sending the summary under
    // the other name is how it used to be dropped silently: nothing consumed it,
    // and every change still read "MCP transaction <id>".
    if let Some(summary) = commit_message_argument(arguments) {
        commit_args.insert("message".to_string(), serde_json::json!(summary));
    }

    // Preserve a source-base conflict so the caller can recover its durable
    // draft. Other failures retain the existing one-shot abort behavior.
    let mut refusal = match forward("kin_transaction_commit", commit_args).await {
        Ok(Some(mut value)) if value.is_error != Some(true) => {
            carry_request_id(&mut value, request_id.as_deref());
            return Ok(value);
        }
        Ok(Some(value)) => value,
        Ok(None) => daemon_required_unavailable("transaction commit"),
        Err(err) => ToolCallResult::error(err),
    };
    name_the_mutate_door(&mut refusal);
    let refused = tool_text(&refusal);
    if crate::source_base::is_source_base_conflict(&refused) {
        return Ok(refusal);
    }
    // A one-shot caller still holds the operations it just sent, and the
    // refusal hands it the current repository base, so the retry is a resend.
    // Retaining the transaction would only spend the session's transaction
    // budget, so it is aborted and the refusal says so.
    let repository_conflict = crate::source_unit::is_repository_base_conflict(&refused);
    let abort_args = HashMap::from([
        ("transaction_id".to_string(), serde_json::json!(tx_id)),
        ("session_id".to_string(), serde_json::json!(session_id)),
    ]);
    let left_open = match forward("kin_transaction_abort", abort_args).await {
        Ok(Some(abort)) if abort.is_error != Some(true) => None,
        Ok(Some(abort)) => Some(tool_text(&abort)),
        Ok(None) => Some("the daemon could not be reached to abort it".to_string()),
        Err(err) => Some(err),
    };
    match left_open {
        Some(why) => note_open_transaction(&mut refusal, &tx_id, &why),
        None if repository_conflict => mark_conflict_transaction_aborted(&mut refusal),
        None => {}
    }
    Ok(refusal)
}

/// Say on a repository-base conflict that the one-shot aborted its transaction.
fn mark_conflict_transaction_aborted(result: &mut ToolCallResult) {
    let Some(crate::types::ContentBlock::Text { text }) = result.content.first_mut() else {
        return;
    };
    let Ok(mut refusal) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    refusal["staged_operations_retained"] = serde_json::json!(false);
    refusal["transaction_aborted"] = serde_json::json!(true);
    refusal["remedy"] = serde_json::json!(
        "Repository authority moved after you read the repository_base you sent. Follow \
         next_step; nothing was applied and this call's transaction was aborted, so there is \
         nothing to clean up. A name taken since is refused again, and every declaration \
         already in the unit keeps its exact bytes."
    );
    if let Ok(rewritten) = serde_json::to_string(&refusal) {
        *text = rewritten;
    }
}

/// Name `kin_mutate` in a read-only refusal a forwarded begin or commit gave.
///
/// An unkeyed one-shot reaches the daemon as a begin and a commit, so the
/// daemon's refusal names whichever of the two refused it, and a caller that
/// sent `kin_mutate` would read about a tool it never called. Only the door is
/// renamed; the session, the missing bits and the remedy stay as the daemon
/// wrote them.
fn name_the_mutate_door(result: &mut ToolCallResult) {
    use crate::session::WriteDoor;
    let Some(crate::types::ContentBlock::Text { text }) = result.content.first_mut() else {
        return;
    };
    // The commit refuses a relation naming a symbol outside the repository in
    // its own name; the caller sent `kin_mutate`, which refuses it offline in
    // that name, so the forwarded refusal is renamed to match.
    if let Ok(mut refusal) = serde_json::from_str::<serde_json::Value>(text) {
        let error = &mut refusal["error"];
        if error["code"].as_str() == Some(super::external_symbols::EXTERNAL_SYMBOL_NOT_SERVED)
            && error["tool"].as_str() == Some("kin_transaction_commit")
        {
            error["tool"] = serde_json::json!("kin_mutate");
            if let Some(message) = error["message"].as_str() {
                error["message"] = serde_json::json!(message.replacen(
                    "so kin_transaction_commit ",
                    "so kin_mutate ",
                    1
                ));
            }
            *text = refusal.to_string();
            return;
        }
    }
    for door in [WriteDoor::Begin, WriteDoor::Commit] {
        let forwarded = format!("read_only_session: {} writes", door.name());
        if let Some(rest) = text.strip_prefix(&forwarded) {
            *text = format!(
                "read_only_session: {} writes{rest}",
                WriteDoor::Mutate.name()
            );
            return;
        }
    }
}

/// Every text block of a tool result, joined, for quoting inside another.
fn tool_text(result: &ToolCallResult) -> String {
    result
        .content
        .iter()
        .map(|block| match block {
            crate::types::ContentBlock::Text { text } => text.as_str(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Say, on a failed mutation's own answer, that its transaction is still open.
///
/// Joined onto the answer's FIRST text block, because that is the block every
/// reader reads: a second block is invisible to any client that takes
/// `content[0]` as the answer, which is the common reading and the one this
/// crate's own tests use. Refusals here are already prose with a JSON line
/// inside, so text after them reads the same way. The alternative this replaced
/// was `let _ =`, which dropped a failed abort on the floor and left the caller
/// believing a transaction it could no longer see had been cleaned up.
fn note_open_transaction(result: &mut ToolCallResult, tx_id: &str, why: &str) {
    result.is_error = Some(true);
    let note = format!(
        "kin_mutate could not abort transaction {tx_id} after its commit failed ({why}), so that \
         transaction is still open. Once the daemon answers, re-send kin_transaction_commit for \
         {tx_id} to resume it or kin_transaction_abort to discard it."
    );
    match result.content.first_mut() {
        Some(crate::types::ContentBlock::Text { text }) => {
            text.push_str("\n\n");
            text.push_str(&note);
        }
        None => result
            .content
            .push(crate::types::ContentBlock::Text { text: note }),
    }
}

pub async fn handle_mutate<G: GraphStore>(
    arguments: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
    session_authority_mode: SessionAuthorityMode,
) -> Result<ToolCallResult> {
    // A keyed retry belongs to the daemon receipt path, which must recover a
    // committed result before examining today's graph. Unkeyed/offline work
    // has no receipt to recover and can refuse before creating a transaction.
    if let Some(operations) = arguments
        .get("operations")
        .filter(|_| !arguments.contains_key("request_id"))
    {
        if let Some(refusal) =
            super::external_symbols::external_relation_refusal(store, operations, "kin_mutate")?
        {
            return Ok(ToolCallResult::error(refusal));
        }
    }

    if session_authority_mode.uses_daemon() {
        return mutate_through_daemon(arguments).await;
    }

    match checked_mutate_request_id(arguments) {
        Err(error) => return Ok(ToolCallResult::error(error)),
        Ok(Some(_)) => return Ok(ToolCallResult::error("durable_request_daemon_required: offline graph-only MCP cannot provide durable request_id retries; use an authenticated daemon supporting kin_mutate_durable_v1")),
        Ok(None) => {}
    }

    let ops_val = match checked_mutate_operations(arguments) {
        Ok(ops_val) => ops_val,
        Err(refusal) => return Ok(refusal),
    };

    // Offline, the local registry IS the authority, so a caller that names no
    // session gets one rather than a refusal: there is no other party whose
    // idea of a session this could disagree with.
    let session_id = match arguments
        .get("session_id")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(session_id) => session_id.to_string(),
        None => match sessions.list_agent_sessions().first() {
            Some(existing) => existing.session_id.to_string(),
            None => sessions
                .start_agent_session(
                    "kin",
                    "kin_agent",
                    kin_model::session::SessionTransport::Mcp,
                    None,
                    std::path::PathBuf::from("."),
                    kin_model::session::SessionCapabilities {
                        can_write: true,
                        can_commit: true,
                        ..Default::default()
                    },
                )
                .session_id
                .to_string(),
        },
    };
    let scope = arguments
        .get("scope")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("repository")
        .to_string();
    let request_id = arguments
        .get("request_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);

    // Named for the tool the caller used rather than the begin it expands to.
    if let Err(error) =
        sessions.require_write_capability(&session_id, crate::session::WriteDoor::Mutate)
    {
        return Ok(ToolCallResult::error(error));
    }
    let tx = match sessions.begin_transaction(&session_id, &scope) {
        Ok(tx) => tx,
        Err(err) => return Ok(ToolCallResult::error(err)),
    };
    let tx_id = tx.transaction_id.clone();
    let mut commit_args = HashMap::from([
        ("transaction_id".to_string(), serde_json::json!(tx_id)),
        ("session_id".to_string(), serde_json::json!(session_id)),
        ("operations".to_string(), ops_val.clone()),
    ]);
    if let Some(summary) = commit_message_argument(arguments) {
        commit_args.insert("message".to_string(), serde_json::json!(summary));
    }
    let mut refusal = match handle_transaction_commit(
        &commit_args,
        store,
        sessions,
        session_authority_mode,
    )
    .await
    {
        Ok(mut res) if res.is_error != Some(true) => {
            carry_request_id(&mut res, request_id.as_deref());
            return Ok(res);
        }
        Ok(res) => res,
        Err(err) => ToolCallResult::error(err.to_string()),
    };
    let abort_args = HashMap::from([
        ("transaction_id".to_string(), serde_json::json!(tx_id)),
        ("session_id".to_string(), serde_json::json!(session_id)),
    ]);
    let left_open =
        match handle_transaction_abort(&abort_args, sessions, session_authority_mode).await {
            Ok(abort) if abort.is_error != Some(true) => None,
            Ok(abort) => Some(tool_text(&abort)),
            Err(err) => Some(err.to_string()),
        };
    if let Some(why) = left_open {
        note_open_transaction(&mut refusal, &tx_id, &why);
    }
    Ok(refusal)
}

pub const TRANSACTION_ABORT_DESC: &str = "\
Abort an active or validated transaction and discard all staged mutations. Reach for it \
when you decide against work you already staged, so the transaction ends instead of \
sitting open holding operations you no longer intend. Once kin_transaction_commit has \
fenced the transaction for publication this is refused, because repository authority may \
already have moved; re-send the commit instead, which resumes the fenced payload \
idempotently and reports whether it landed. Read a refusal before retrying: planning errors \
may name cleared operations; authority, semantic-boundary and source-base refusals preserve \
staged work. Abort only when you intend to discard that retained work.";

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
