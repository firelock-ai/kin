// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;
use std::path::PathBuf;

use kin_model::ids::EntityId;
use kin_model::timestamp::Timestamp;

use crate::error::Result;
use crate::session::SessionRegistry;
use crate::types::ToolCallResult;

use super::common::*;

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

pub fn handle_session_start(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
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

    let session =
        sessions.start_agent_session(&vendor, &client_name, transport, pid, cwd, capabilities);

    // Delegate session start to daemon (fire-and-forget).
    {
        let v = vendor.to_string();
        let c = client_name.to_string();
        let t = transport_str.to_string();
        tokio::spawn(async move {
            crate::daemon_delegate::forward_session_start(&v, &c, &t, pid, &cwd_str).await;
        });
    }

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

pub fn handle_session_heartbeat(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "session_id")?;
    let session_id = parse_session_id(&id_str)?;

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

pub fn handle_session_end(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "session_id")?;
    let session_id = parse_session_id(&id_str)?;

    match sessions.end_agent_session(&session_id) {
        Some(session) => {
            // Delegate session end to daemon (fire-and-forget).
            let delegate_id = id_str.clone();
            tokio::spawn(async move {
                crate::daemon_delegate::forward_session_end(&delegate_id).await;
            });

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

pub fn handle_register_intent(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
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

    let expires_at: Option<Timestamp> = args
        .get("expires_at")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_value(serde_json::json!(s)).ok());

    match sessions.register_intent(session_id, scopes, lock_type, task_description, expires_at) {
        Some(intent) => {
            let result = serde_json::json!({
                "intent_id": intent.intent_id.to_string(),
                "session_id": intent.session_id.to_string(),
                "scopes": intent.scopes,
                "lock_type": intent.lock_type,
                "task_description": intent.task_description,
                "registered_at": intent.registered_at,
                "status": "registered",
            });
            let json =
                serde_json::to_string_pretty(&result).map_err(crate::error::McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        None => Ok(ToolCallResult::error(format!(
            "Session not found: {}. Start a session with kin_session_start first.",
            id_str
        ))),
    }
}

pub fn handle_release_intent(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let session_str = get_string_param(args, "session_id")?;
    let intent_str = get_string_param(args, "intent_id")?;
    let session_id = parse_session_id(&session_str)?;
    let intent_id = parse_intent_id(&intent_str)?;

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

pub fn handle_check_traffic(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let scopes_val = args.get("scopes").ok_or_else(|| {
        crate::error::McpError::InvalidParams("missing required parameter: scopes".into())
    })?;
    let scopes = parse_scopes(scopes_val)?;

    let reports = sessions.check_traffic(&scopes);

    let result = serde_json::json!({
        "reports": reports,
        "scope_count": scopes.len(),
    });

    let json = serde_json::to_string_pretty(&result).map_err(crate::error::McpError::Json)?;
    Ok(ToolCallResult::text(json))
}
