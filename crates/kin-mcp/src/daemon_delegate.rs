// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon delegate for MCP operations.
//!
//! Product-mode MCP is transport-only: graph and mutation tools are forwarded
//! to the repo daemon, and session/intent tools are forwarded to the daemon's
//! session endpoints. In-process handlers are reserved for explicit offline
//! unit tests.

use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use kin_model::session::SessionCapabilities;
use tracing::debug;

use crate::types::ToolCallResult;

/// Cached daemon HTTP client. We only cache positive connectivity so that a
/// daemon that comes online after MCP startup can still take authority.
static DAEMON_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

/// Base URL for the daemon HTTP API.
fn daemon_base_url() -> Option<String> {
    std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// Bearer token the daemon expects on non-public routes.
///
/// Resolution mirrors the daemon and CLI client exactly so all three agree in
/// every case: an explicit `KIN_DAEMON_AUTH_TOKEN` env override wins, otherwise
/// the auto-provisioned per-install loopback token at `.kin/daemon.token`
/// (which the daemon writes via `ensure_loopback_token`). When neither is
/// present we send no header — harmless while enforcement is flag-gated, and
/// correct once it is enabled.
fn daemon_auth_token() -> Option<String> {
    resolve_daemon_auth_token(
        std::env::var("KIN_DAEMON_AUTH_TOKEN").ok(),
        discover_kin_dir().as_deref(),
    )
}

/// Pure resolution of the daemon bearer token, factored out of
/// [`daemon_auth_token`] so the precedence is unit-testable without mutating
/// process env or cwd.
///
/// Precedence mirrors the daemon's `resolve_serve_auth_token` and the CLI's
/// `resolve_daemon_auth_token` exactly so all three agree in every case: an
/// explicit `KIN_DAEMON_AUTH_TOKEN` override wins, otherwise the
/// auto-provisioned per-install loopback token at `<kin_dir>/daemon.token`
/// (which the daemon writes via `ensure_loopback_token`). Empty/whitespace
/// values — env or file — are treated as absent so a blank file never shadows
/// the env override and never produces a `Bearer ` header with no secret.
fn resolve_daemon_auth_token(env_token: Option<String>, kin_dir: Option<&Path>) -> Option<String> {
    if let Some(env_token) = env_token {
        let env_token = env_token.trim().to_string();
        if !env_token.is_empty() {
            return Some(env_token);
        }
    }
    let token_path = kin_dir?.join("daemon.token");
    let contents = std::fs::read_to_string(token_path).ok()?;
    let token = contents.trim().to_string();
    (!token.is_empty()).then_some(token)
}

/// Walk up from the working directory to the repo's `.kin` directory.
///
/// This intentionally does not use `KinLayout::discover`, whose `KIN_DAEMON_URL`
/// short-circuit assumes the cwd is the repo root; the token file lives in the
/// repo `.kin` even when an agent runs from a subdirectory, so we walk up to
/// find it.
fn discover_kin_dir() -> Option<std::path::PathBuf> {
    let mut current = std::env::current_dir().ok()?;
    loop {
        let candidate = current.join(".kin");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Attach the daemon bearer token to a request when auth is configured.
fn with_auth(request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    match daemon_auth_token() {
        Some(token) => request.bearer_auth(token),
        None => request,
    }
}

/// Attach the session header (from explicit args or `KIN_SESSION_ID`) to a
/// forwarded request so the daemon resolves the caller's session graph.
fn with_session_header(
    request: reqwest::RequestBuilder,
    arguments: &HashMap<String, serde_json::Value>,
) -> reqwest::RequestBuilder {
    if let Some(session_id) = optional_string(arguments, "session_id") {
        return request.header("X-Kin-Session", session_id);
    }
    if let Ok(session_id) = std::env::var("KIN_SESSION_ID") {
        if !session_id.trim().is_empty() {
            return request.header("X-Kin-Session", session_id);
        }
    }
    request
}

fn daemon_required_unavailable(operation: &str) -> ToolCallResult {
    ToolCallResult::error(format!(
        "Kin daemon is required for {operation}, but the daemon delegate is unavailable"
    ))
}

fn text_result_from_value(value: serde_json::Value) -> Result<ToolCallResult, String> {
    let json = serde_json::to_string_pretty(&value)
        .map_err(|e| format!("daemon response serialization failed: {e}"))?;
    Ok(ToolCallResult::text(json))
}

fn required_string(args: &HashMap<String, serde_json::Value>, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("missing required parameter: {key}"))
}

fn optional_string<'a>(args: &'a HashMap<String, serde_json::Value>, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|value| value.as_str())
}

fn optional_u32(args: &HashMap<String, serde_json::Value>, key: &str) -> Option<u32> {
    args.get(key)
        .and_then(|value| value.as_u64())
        .map(|value| value as u32)
}

fn parse_capabilities(args: &HashMap<String, serde_json::Value>) -> SessionCapabilities {
    let Some(obj) = args.get("capabilities").and_then(|value| value.as_object()) else {
        return SessionCapabilities::default();
    };
    SessionCapabilities {
        can_read: obj
            .get("can_read")
            .and_then(|value| value.as_bool())
            .unwrap_or(true),
        can_write: obj
            .get("can_write")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        can_execute: obj
            .get("can_execute")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        can_branch: obj
            .get("can_branch")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        can_commit: obj
            .get("can_commit")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        max_concurrent_intents: obj
            .get("max_concurrent_intents")
            .and_then(|value| value.as_u64())
            .map(|value| value as usize)
            .unwrap_or(1),
    }
}

fn scope_to_string(value: &serde_json::Value) -> Result<String, String> {
    if let Some(scope) = value.as_str() {
        return Ok(scope.to_string());
    }
    let Some(obj) = value.as_object() else {
        return Err(
            "invalid scope: expected string, {\"Entity\":\"uuid\"}, {\"Contract\":\"uuid\"}, or {\"Artifact\":\"path\"}"
                .to_string(),
        );
    };
    if let Some(entity) = obj.get("Entity").and_then(|value| value.as_str()) {
        return Ok(format!("entity:{entity}"));
    }
    if let Some(contract) = obj.get("Contract").and_then(|value| value.as_str()) {
        return Ok(format!("contract:{contract}"));
    }
    if let Some(artifact) = obj.get("Artifact").and_then(|value| value.as_str()) {
        return Ok(format!("file:{artifact}"));
    }
    Err(
        "invalid scope: expected string, {\"Entity\":\"uuid\"}, {\"Contract\":\"uuid\"}, or {\"Artifact\":\"path\"}"
            .to_string(),
    )
}

fn scope_strings(args: &HashMap<String, serde_json::Value>) -> Result<Vec<String>, String> {
    let scopes = args
        .get("scopes")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "missing required parameter: scopes".to_string())?;
    scopes.iter().map(scope_to_string).collect()
}

async fn forward_mcp_tool_call(
    name: &str,
    arguments: &HashMap<String, serde_json::Value>,
) -> Result<Option<ToolCallResult>, String> {
    let Some(client) = daemon_client().await else {
        return Ok(None);
    };
    let Some(base) = daemon_base_url() else {
        return Ok(None);
    };
    let request = client
        .post(format!("{}/mcp/tools/call", base))
        .json(&serde_json::json!({
            "name": name,
            "arguments": arguments,
        }));
    let request = with_session_header(with_auth(request), arguments);
    let resp = request
        .send()
        .await
        .map_err(|e| format!("daemon MCP tool call failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "daemon MCP tool call failed: HTTP {}",
            resp.status()
        ));
    }
    let result = resp
        .json::<ToolCallResult>()
        .await
        .map_err(|e| format!("daemon MCP tool call response parse failed: {e}"))?;
    Ok(Some(result))
}

/// Forward any product-mode MCP tool call to the daemon-owned implementation.
pub async fn forward_tool_call(
    name: &str,
    arguments: &HashMap<String, serde_json::Value>,
) -> Result<Option<ToolCallResult>, String> {
    match name {
        "register_session" => {
            let assistant_name = required_string(arguments, "assistant_name")?;
            let cwd = std::env::current_dir()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|_| ".".to_string());
            let capabilities = SessionCapabilities::default();
            forward_session_start(
                &assistant_name,
                &assistant_name,
                "mcp",
                None,
                &cwd,
                &capabilities,
            )
            .await?
            .map(text_result_from_value)
            .transpose()
        }
        "kin_session_start" => {
            let vendor = required_string(arguments, "vendor")?;
            let client_name = required_string(arguments, "client_name")?;
            let cwd = required_string(arguments, "cwd")?;
            let transport = optional_string(arguments, "transport").unwrap_or("mcp");
            let pid = optional_u32(arguments, "pid");
            let capabilities = parse_capabilities(arguments);
            forward_session_start(&vendor, &client_name, transport, pid, &cwd, &capabilities)
                .await?
                .map(text_result_from_value)
                .transpose()
        }
        "kin_session_heartbeat" => {
            let session_id = required_string(arguments, "session_id")?;
            forward_session_heartbeat(&session_id)
                .await?
                .map(text_result_from_value)
                .transpose()
        }
        "kin_session_end" => {
            let session_id = required_string(arguments, "session_id")?;
            forward_session_end(&session_id)
                .await?
                .map(text_result_from_value)
                .transpose()
        }
        "kin_register_intent" => {
            let session_id = required_string(arguments, "session_id")?;
            let task_description = required_string(arguments, "task_description")?;
            let lock_type = optional_string(arguments, "lock_type").unwrap_or("soft");
            let expires_at = optional_string(arguments, "expires_at");
            let scopes = scope_strings(arguments)?;
            forward_register_intent(
                &session_id,
                &scopes,
                lock_type,
                &task_description,
                expires_at,
            )
            .await?
            .map(text_result_from_value)
            .transpose()
        }
        "kin_release_intent" => {
            let session_id = required_string(arguments, "session_id")?;
            let intent_id = required_string(arguments, "intent_id")?;
            forward_release_intent(&session_id, &intent_id)
                .await?
                .map(text_result_from_value)
                .transpose()
        }
        "kin_check_traffic" => {
            let scopes = scope_strings(arguments)?;
            forward_check_traffic(&scopes)
                .await?
                .map(text_result_from_value)
                .transpose()
        }
        // Coverage exposure: surface embedding-index coverage to MCP agents.
        // The generic graph tool dispatcher only knows entity_count; the
        // daemon's status command computes embedding coverage from the live
        // graph (`graph.embedding_status()`), so forward there and project the
        // fields MCP agents need. Self-contained — no daemon-api coordination.
        "kin_graph_status" => forward_graph_status(arguments).await,
        _ => forward_mcp_tool_call(name, arguments).await,
    }
}

/// Forward `kin_graph_status` to the daemon's status command and project the
/// graph/embedding coverage fields agents care about.
///
/// In product mode coverage is otherwise CLI-only (`kin status`); this gives
/// MCP agents the same embedding-index visibility without leaving graph-owned
/// truth — the daemon computes the counts from its live graph.
async fn forward_graph_status(
    arguments: &HashMap<String, serde_json::Value>,
) -> Result<Option<ToolCallResult>, String> {
    let Some(client) = daemon_client().await else {
        return Ok(None);
    };
    let Some(base) = daemon_base_url() else {
        return Ok(None);
    };
    let request = client
        .post(format!("{}/commands/status", base))
        .json(&serde_json::json!({ "json": false }));
    let request = with_session_header(with_auth(request), arguments);
    let resp = request
        .send()
        .await
        .map_err(|e| format!("daemon graph status failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("daemon graph status failed: HTTP {}", resp.status()));
    }
    let value: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("daemon graph status response parse failed: {e}"))?;
    let summary = value.get("summary").unwrap_or(&value);
    let field_u64 = |key: &str| summary.get(key).and_then(serde_json::Value::as_u64);
    let result = serde_json::json!({
        "entity_count": field_u64("entities").unwrap_or(0),
        "embeddings_indexed": field_u64("embeddings_indexed").unwrap_or(0),
        "embeddings_total": field_u64("embeddings_total").unwrap_or(0),
        "embeddings_pending": field_u64("embeddings_pending").unwrap_or(0),
        "authority": "repo-daemon",
        "note": "Embedding coverage is computed from the daemon-owned live graph."
    });
    text_result_from_value(result).map(Some)
}

pub fn daemon_unavailable_tool_result(name: &str) -> ToolCallResult {
    daemon_required_unavailable(name)
}

/// Get or initialize the daemon client. Returns `None` if the daemon is not
/// reachable right now; daemon-required callers turn that into a hard error.
pub async fn daemon_client() -> Option<reqwest::Client> {
    if let Some(client) = DAEMON_CLIENT.get() {
        return Some(client.clone());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_millis(500))
        .build()
        .ok()?;

    let Some(base) = daemon_base_url() else {
        debug!("daemon delegate: KIN_DAEMON_URL is not set");
        return None;
    };
    let probe_url = format!("{}/health", base);
    let ok = client
        .get(&probe_url)
        .send()
        .await
        .ok()?
        .status()
        .is_success();

    if ok {
        debug!("daemon delegate: connected to {}", base);
        let cached = client.clone();
        let _ = DAEMON_CLIENT.set(cached.clone());
        Some(cached)
    } else {
        debug!("daemon delegate: daemon not reachable");
        None
    }
}

/// Forward a session start to the daemon.
///
/// POST /session with JSON body. Returns the response JSON on success.
pub async fn forward_session_start(
    vendor: &str,
    client_name: &str,
    transport: &str,
    pid: Option<u32>,
    cwd: &str,
    capabilities: &SessionCapabilities,
) -> Result<Option<serde_json::Value>, String> {
    let Some(client) = daemon_client().await else {
        return Ok(None);
    };
    let Some(base) = daemon_base_url() else {
        return Ok(None);
    };
    let mut body = serde_json::json!({
        "vendor": vendor,
        "client_name": client_name,
        "transport": transport,
        "cwd": cwd,
        "capabilities": capabilities,
    });
    if let Some(p) = pid {
        body["pid"] = serde_json::json!(p);
    }
    let resp = with_auth(client.post(format!("{}/session", base)).json(&body))
        .send()
        .await
        .map_err(|e| format!("daemon session start failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "daemon session start failed: HTTP {}",
            resp.status()
        ));
    }
    let value = resp
        .json()
        .await
        .map_err(|e| format!("daemon session start response parse failed: {e}"))?;
    Ok(Some(value))
}

/// Forward a session heartbeat to the daemon.
pub async fn forward_session_heartbeat(
    session_id: &str,
) -> Result<Option<serde_json::Value>, String> {
    let Some(client) = daemon_client().await else {
        return Ok(None);
    };
    let Some(base) = daemon_base_url() else {
        return Ok(None);
    };
    let resp = with_auth(client.post(format!("{}/session/{}/heartbeat", base, session_id)))
        .send()
        .await
        .map_err(|e| format!("daemon heartbeat failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("daemon heartbeat failed: HTTP {}", resp.status()));
    }
    let value = resp
        .json()
        .await
        .map_err(|e| format!("daemon heartbeat response parse failed: {e}"))?;
    Ok(Some(value))
}

/// Forward a session end to the daemon.
pub async fn forward_session_end(session_id: &str) -> Result<Option<serde_json::Value>, String> {
    let Some(client) = daemon_client().await else {
        return Ok(None);
    };
    let Some(base) = daemon_base_url() else {
        return Ok(None);
    };
    let resp = with_auth(client.delete(format!("{}/session/{}", base, session_id)))
        .send()
        .await
        .map_err(|e| format!("daemon session end failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("daemon session end failed: HTTP {}", resp.status()));
    }
    let value = resp
        .json()
        .await
        .map_err(|e| format!("daemon session end response parse failed: {e}"))?;
    Ok(Some(value))
}

/// Forward an intent registration to the daemon.
pub async fn forward_register_intent(
    session_id: &str,
    scopes: &[String],
    lock_type: &str,
    task_description: &str,
    expires_at: Option<&str>,
) -> Result<Option<serde_json::Value>, String> {
    let Some(client) = daemon_client().await else {
        return Ok(None);
    };
    let Some(base) = daemon_base_url() else {
        return Ok(None);
    };
    let body = serde_json::json!({
        "session_id": session_id,
        "scopes": scopes,
        "lock_type": lock_type,
        "task_description": task_description,
    });
    let body = if let Some(expires_at) = expires_at {
        let mut body = body;
        body["expires_at"] = serde_json::json!(expires_at);
        body
    } else {
        body
    };
    let resp = with_auth(client.post(format!("{}/intent/register", base)).json(&body))
        .send()
        .await
        .map_err(|e| format!("daemon intent register failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "daemon intent register failed: HTTP {}",
            resp.status()
        ));
    }
    let value = resp
        .json()
        .await
        .map_err(|e| format!("daemon intent register response parse failed: {e}"))?;
    Ok(Some(value))
}

/// Forward an intent release to the daemon.
///
/// DELETE /intent/{intent_id}. The daemon returns 204 No Content on success,
/// so we synthesize a JSON response for the MCP handler.
pub async fn forward_release_intent(
    session_id: &str,
    intent_id: &str,
) -> Result<Option<serde_json::Value>, String> {
    let Some(client) = daemon_client().await else {
        return Ok(None);
    };
    let Some(base) = daemon_base_url() else {
        return Ok(None);
    };
    let resp = with_auth(client.delete(format!("{}/intent/{}", base, intent_id)))
        .send()
        .await
        .map_err(|e| format!("daemon release intent failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "daemon release intent failed: HTTP {}",
            resp.status()
        ));
    }
    // Daemon returns 204 No Content; synthesize a result for the MCP handler.
    Ok(Some(serde_json::json!({
        "intent_id": intent_id,
        "session_id": session_id,
        "status": "released",
    })))
}

/// Forward a traffic check to the daemon.
///
/// The daemon exposes GET /traffic/{scope} for a single scope, so we issue
/// one request per scope and collect the results.
pub async fn forward_check_traffic(
    scope_strings: &[String],
) -> Result<Option<serde_json::Value>, String> {
    let Some(client) = daemon_client().await else {
        return Ok(None);
    };
    let Some(base) = daemon_base_url() else {
        return Ok(None);
    };
    let mut reports = Vec::new();
    for scope in scope_strings {
        let encoded = scope.replace(':', "%3A");
        let resp = with_auth(client.get(format!("{}/traffic/{}", base, encoded)))
            .send()
            .await
            .map_err(|e| format!("daemon check traffic failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "daemon check traffic failed: HTTP {}",
                resp.status()
            ));
        }
        let value: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("daemon check traffic response parse failed: {e}"))?;
        reports.push(value);
    }
    Ok(Some(serde_json::json!({
        "reports": reports,
        "scope_count": scope_strings.len(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a `daemon.token` containing `contents` into a fresh temp `.kin`
    /// dir and return (tempdir, kin_dir). The tempdir must outlive the call.
    fn kin_dir_with_token(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).expect("mkdir .kin");
        std::fs::write(kin_dir.join("daemon.token"), contents).expect("write token");
        (dir, kin_dir)
    }

    // ── Auth token resolution (the R0 loopback-token contract seam) ──────────
    //
    // These lock the MCP client's precedence to the daemon's
    // `resolve_serve_auth_token` / `ensure_loopback_token` and the CLI's
    // `resolve_daemon_auth_token`: env override wins, else `<.kin>/daemon.token`,
    // with empty/whitespace treated as absent. A regression here silently breaks
    // every authenticated MCP→daemon forward once enforcement is enabled.

    #[test]
    fn auth_token_env_override_wins_over_file() {
        let (_guard, kin_dir) = kin_dir_with_token("file-token");
        let resolved =
            resolve_daemon_auth_token(Some("  env-token  ".to_string()), Some(&kin_dir));
        assert_eq!(resolved.as_deref(), Some("env-token"));
    }

    #[test]
    fn auth_token_falls_back_to_loopback_file() {
        let (_guard, kin_dir) = kin_dir_with_token("loopback-secret\n");
        let resolved = resolve_daemon_auth_token(None, Some(&kin_dir));
        // Trailing newline (as written by the daemon) is trimmed.
        assert_eq!(resolved.as_deref(), Some("loopback-secret"));
    }

    #[test]
    fn auth_token_empty_env_does_not_shadow_file() {
        let (_guard, kin_dir) = kin_dir_with_token("loopback-secret");
        let resolved = resolve_daemon_auth_token(Some("   ".to_string()), Some(&kin_dir));
        assert_eq!(resolved.as_deref(), Some("loopback-secret"));
    }

    #[test]
    fn auth_token_blank_file_is_absent() {
        // A blank token file must never produce a bare `Bearer ` header.
        let (_guard, kin_dir) = kin_dir_with_token("   \n");
        assert!(resolve_daemon_auth_token(None, Some(&kin_dir)).is_none());
    }

    #[test]
    fn auth_token_absent_when_no_env_and_no_kin_dir() {
        assert!(resolve_daemon_auth_token(None, None).is_none());
    }

    #[test]
    fn auth_token_absent_when_file_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        // .kin exists but has no daemon.token.
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).expect("mkdir .kin");
        assert!(resolve_daemon_auth_token(None, Some(&kin_dir)).is_none());
    }

    // ── Scope request-building (forwarded session/intent tools) ──────────────

    #[test]
    fn scope_to_string_accepts_bare_string() {
        let value = serde_json::json!("file:src/main.rs");
        assert_eq!(scope_to_string(&value).unwrap(), "file:src/main.rs");
    }

    #[test]
    fn scope_to_string_maps_tagged_variants() {
        assert_eq!(
            scope_to_string(&serde_json::json!({ "Entity": "abc" })).unwrap(),
            "entity:abc"
        );
        assert_eq!(
            scope_to_string(&serde_json::json!({ "Contract": "c1" })).unwrap(),
            "contract:c1"
        );
        assert_eq!(
            scope_to_string(&serde_json::json!({ "Artifact": "src/lib.rs" })).unwrap(),
            "file:src/lib.rs"
        );
    }

    #[test]
    fn scope_to_string_rejects_unknown_shape() {
        assert!(scope_to_string(&serde_json::json!(42)).is_err());
        assert!(scope_to_string(&serde_json::json!({ "Bogus": "x" })).is_err());
    }
}
