// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon delegate for MCP session operations.
//!
//! When the kin daemon is running, session operations (start, heartbeat, end,
//! register intent) are forwarded to the daemon's HTTP API so that session
//! state is centralized. Falls back to in-process `SessionRegistry` when
//! the daemon is unavailable.

use std::sync::OnceLock;
use std::time::Duration;

use kin_model::session::SessionCapabilities;
use tracing::debug;

/// Cached daemon HTTP client. We only cache positive connectivity so that a
/// daemon that comes online after MCP startup can still take authority.
static DAEMON_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

/// Base URL for the daemon HTTP API.
fn daemon_base_url() -> String {
    std::env::var("KIN_DAEMON_URL").unwrap_or_else(|_| "http://127.0.0.1:4219".to_string())
}

/// Get or initialize the daemon client. Returns `None` if the daemon
/// is not reachable right now.
pub async fn daemon_client() -> Option<reqwest::Client> {
    if let Some(client) = DAEMON_CLIENT.get() {
        return Some(client.clone());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_millis(500))
        .build()
        .ok()?;

    let base = daemon_base_url();
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
        debug!("daemon delegate: daemon not reachable, using in-process sessions");
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
    let base = daemon_base_url();
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
    let resp = client
        .post(format!("{}/session", base))
        .json(&body)
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
    let base = daemon_base_url();
    let resp = client
        .post(format!("{}/session/{}/heartbeat", base, session_id))
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
    let base = daemon_base_url();
    let resp = client
        .delete(format!("{}/session/{}", base, session_id))
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
    let base = daemon_base_url();
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
    let resp = client
        .post(format!("{}/intent/register", base))
        .json(&body)
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
    let base = daemon_base_url();
    let resp = client
        .delete(format!("{}/intent/{}", base, intent_id))
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
    let base = daemon_base_url();
    let mut reports = Vec::new();
    for scope in scope_strings {
        let encoded = scope.replace(':', "%3A");
        let resp = client
            .get(format!("{}/traffic/{}", base, encoded))
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
