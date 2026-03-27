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

use tracing::{debug, warn};

/// Cached daemon connection state. Probed once at first use and cached
/// for the lifetime of the MCP server process.
static DAEMON_CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();

/// Base URL for the daemon HTTP API.
fn daemon_base_url() -> String {
    std::env::var("KIN_DAEMON_URL").unwrap_or_else(|_| "http://127.0.0.1:4219".to_string())
}

/// Get or initialize the daemon client. Returns `None` if the daemon
/// is not reachable.
pub fn daemon_client() -> Option<&'static reqwest::Client> {
    DAEMON_CLIENT
        .get_or_init(|| {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .connect_timeout(Duration::from_millis(500))
                .build()
                .ok()?;

            // Synchronous probe: MCP runs in a tokio context, but OnceLock
            // init is sync. Use a blocking probe via a short-lived runtime.
            // This runs once at first session operation.
            let base = daemon_base_url();
            let probe_url = format!("{}/health", base);
            let ok = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .ok()?;
                rt.block_on(async {
                    client.get(&probe_url).send().await.ok()?.status().is_success().then_some(())
                })
            })
            .join()
            .ok()
            .flatten()
            .is_some();

            if ok {
                debug!("daemon delegate: connected to {}", daemon_base_url());
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(5))
                    .build()
                    .ok()?;
                Some(client)
            } else {
                debug!("daemon delegate: daemon not reachable, using in-process sessions");
                None
            }
        })
        .as_ref()
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
) -> Option<serde_json::Value> {
    let client = daemon_client()?;
    let base = daemon_base_url();
    let mut body = serde_json::json!({
        "vendor": vendor,
        "client_name": client_name,
        "transport": transport,
        "cwd": cwd,
    });
    if let Some(p) = pid {
        body["pid"] = serde_json::json!(p);
    }
    match client.post(format!("{}/session", base)).json(&body).send().await {
        Ok(resp) if resp.status().is_success() => resp.json().await.ok(),
        Ok(resp) => {
            warn!("daemon session start failed: HTTP {}", resp.status());
            None
        }
        Err(e) => {
            warn!("daemon session start failed: {}", e);
            None
        }
    }
}

/// Forward a session heartbeat to the daemon.
pub async fn forward_session_heartbeat(session_id: &str) -> Option<serde_json::Value> {
    let client = daemon_client()?;
    let base = daemon_base_url();
    match client
        .get(format!("{}/session/{}", base, session_id))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => resp.json().await.ok(),
        _ => None,
    }
}

/// Forward a session end to the daemon.
pub async fn forward_session_end(session_id: &str) -> Option<serde_json::Value> {
    let client = daemon_client()?;
    let base = daemon_base_url();
    match client
        .delete(format!("{}/session/{}", base, session_id))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => resp.json().await.ok(),
        Ok(resp) => {
            warn!("daemon session end failed: HTTP {}", resp.status());
            None
        }
        Err(e) => {
            warn!("daemon session end failed: {}", e);
            None
        }
    }
}

/// Forward an intent registration to the daemon.
pub async fn forward_register_intent(
    session_id: &str,
    scope: &str,
    lock_type: &str,
    task_description: &str,
) -> Option<serde_json::Value> {
    let client = daemon_client()?;
    let base = daemon_base_url();
    let body = serde_json::json!({
        "session_id": session_id,
        "scope": scope,
        "lock_type": lock_type,
        "task_description": task_description,
    });
    match client
        .post(format!("{}/intent/register", base))
        .json(&body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => resp.json().await.ok(),
        Ok(resp) => {
            warn!("daemon intent register failed: HTTP {}", resp.status());
            None
        }
        Err(e) => {
            warn!("daemon intent register failed: {}", e);
            None
        }
    }
}

/// Check whether the daemon is reachable for session delegation.
pub fn is_daemon_available() -> bool {
    daemon_client().is_some()
}
