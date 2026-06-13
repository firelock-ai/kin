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

/// Runtime override for the daemon base URL.
///
/// Set by the revival path when it restarts the daemon on a (potentially
/// different) port.  Takes precedence over `KIN_DAEMON_URL` so subsequent
/// tool calls are routed at the revived daemon immediately, without requiring
/// a process restart.
static DAEMON_URL_OVERRIDE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Base URL for the daemon HTTP API.
///
/// Checks the revival-path override first; falls back to the `KIN_DAEMON_URL`
/// environment variable that `kin mcp start` sets at process startup.
fn daemon_base_url() -> Option<String> {
    if let Ok(guard) = DAEMON_URL_OVERRIDE.lock() {
        if let Some(url) = guard.as_ref() {
            return Some(url.clone());
        }
    }
    std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

// ── MCP-path idle timeout ───────────────────────────────────────────────

/// Idle timeout injected into daemons started by the MCP revival path.
///
/// Interactive MCP agent loops routinely pause longer than a minute between
/// tool calls.  The CLI default of 60 s is far too short for these sessions;
/// 30 minutes gives ample headroom while still ensuring eventual cleanup when
/// an agent session is truly abandoned.  An explicit
/// `KIN_DAEMON_IDLE_TIMEOUT_SECS` env var always overrides this at runtime.
const MCP_IDLE_TIMEOUT_SECS: &str = "1800";

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

// ── Daemon revival seam ─────────────────────────────────────────────────

/// Error returned by [`DaemonCallSeam::call_tool`].
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DaemonCallError {
    /// Transport-level failure (connection refused, timeout, TCP reset) —
    /// the daemon may have exited.  The revival path will attempt exactly one
    /// restart before surfacing an error.
    ConnectionLost(String),
    /// HTTP-level or protocol failure — the daemon responded but signalled an
    /// error.  Revival is not attempted; the error is surfaced immediately.
    DaemonError(String),
}

/// Abstraction over daemon communication and revival used by
/// [`forward_mcp_with_seam`].
///
/// The production implementation ([`RealDaemonSeam`]) makes real HTTP requests
/// and can spawn a new daemon process via `std::process::Command`.  Tests
/// inject a controlled stub to exercise the revival state machine without
/// touching the network or spawning any processes.
pub(crate) trait DaemonCallSeam: Sync {
    /// Attempt a single MCP tool call against the daemon at `base`.
    ///
    /// Returns:
    /// - `Ok(Some(result))` on success.
    /// - `Ok(None)` when the daemon URL is not configured (graceful no-op).
    /// - `Err(ConnectionLost(_))` for transport failures — warrants revival.
    /// - `Err(DaemonError(_))` for HTTP/protocol failures — no revival.
    async fn call_tool(
        &self,
        base: &str,
        name: &str,
        args: &HashMap<String, serde_json::Value>,
    ) -> Result<Option<ToolCallResult>, DaemonCallError>;

    /// Attempt to revive a dead daemon and return its new base URL.
    async fn revive(&self) -> Result<String, String>;
}

/// Production implementation of [`DaemonCallSeam`].
pub(crate) struct RealDaemonSeam;

impl DaemonCallSeam for RealDaemonSeam {
    async fn call_tool(
        &self,
        base: &str,
        name: &str,
        args: &HashMap<String, serde_json::Value>,
    ) -> Result<Option<ToolCallResult>, DaemonCallError> {
        let Some(client) = daemon_client().await else {
            return Ok(None);
        };
        let request = client
            .post(format!("{}/mcp/tools/call", base))
            .json(&serde_json::json!({ "name": name, "arguments": args }));
        let request = with_session_header(with_auth(request), args);
        let resp = request.send().await.map_err(|e| {
            if e.is_connect() || e.is_timeout() {
                DaemonCallError::ConnectionLost(e.to_string())
            } else {
                DaemonCallError::DaemonError(format!("daemon MCP tool call failed: {e}"))
            }
        })?;
        if !resp.status().is_success() {
            return Err(DaemonCallError::DaemonError(format!(
                "daemon MCP tool call failed: HTTP {}",
                resp.status()
            )));
        }
        let result = resp.json::<ToolCallResult>().await.map_err(|e| {
            DaemonCallError::DaemonError(format!("daemon MCP tool call response parse failed: {e}"))
        })?;
        Ok(Some(result))
    }

    async fn revive(&self) -> Result<String, String> {
        revive_mcp_daemon().await
    }
}

// ── Revival helpers ─────────────────────────────────────────────────────

/// Locate the `kin-daemon` binary for the revival path.
///
/// Resolution order mirrors `lifecycle.rs::find_daemon_binary` so the MCP
/// revival path finds the same binary without a `kin-daemon` crate dep
/// (which would be circular: `kin-daemon` already depends on `kin-mcp`).
fn find_mcp_daemon_binary() -> Option<std::path::PathBuf> {
    if let Ok(explicit) = std::env::var("KIN_DAEMON_BIN") {
        let path = std::path::PathBuf::from(explicit);
        if path.exists() {
            return Some(path);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("kin-daemon");
        if sibling.exists() {
            return Some(sibling);
        }
        // Dev/test layout: .../target/<profile>/deps/ → .../target/<profile>/
        if exe
            .parent()
            .and_then(|p| p.file_name())
            .is_some_and(|name| name == "deps")
        {
            if let Some(target_dir) = exe.parent().and_then(|p| p.parent()) {
                let sibling = target_dir.join("kin-daemon");
                if sibling.exists() {
                    return Some(sibling);
                }
            }
        }
    }
    // Walk PATH manually (avoids `which` crate dep).
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join("kin-daemon");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn find_mcp_free_port() -> Option<u16> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
}

/// Spawn a fresh daemon and wait for it to pass `/health`.
///
/// Uses the MCP-path idle timeout (30 min) unless the user has set
/// `KIN_DAEMON_IDLE_TIMEOUT_SECS` explicitly.  On success, writes the new
/// base URL into [`DAEMON_URL_OVERRIDE`] so all subsequent delegate calls
/// are routed to the revived daemon automatically.
async fn revive_mcp_daemon() -> Result<String, String> {
    let kin_dir =
        discover_kin_dir().ok_or_else(|| "MCP revival: cannot find .kin directory".to_string())?;
    let working_dir = kin_dir
        .parent()
        .ok_or_else(|| "MCP revival: invalid .kin layout (no parent directory)".to_string())?
        .to_path_buf();
    let daemon_bin = find_mcp_daemon_binary().ok_or_else(|| {
        "MCP revival: kin-daemon binary not found (not in PATH or next to kin binary)".to_string()
    })?;
    let port = find_mcp_free_port().unwrap_or(4219);

    tracing::info!(
        binary = %daemon_bin.display(),
        repo = %working_dir.display(),
        port,
        "MCP revival: starting fresh daemon"
    );

    let mut cmd = std::process::Command::new(&daemon_bin);
    cmd.args([
        "--repo",
        &working_dir.display().to_string(),
        "--port",
        &port.to_string(),
    ]);
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    // Inject the MCP-path idle timeout unless the user has an explicit
    // override in the environment — user's value always wins.
    if std::env::var_os("KIN_DAEMON_IDLE_TIMEOUT_SECS").is_none() {
        cmd.env("KIN_DAEMON_IDLE_TIMEOUT_SECS", MCP_IDLE_TIMEOUT_SECS);
    }
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }

    cmd.spawn()
        .map_err(|e| format!("MCP revival: spawn kin-daemon failed: {e}"))?;

    // Poll /health until the daemon is ready (bounded at 15 s).
    let new_base = format!("http://127.0.0.1:{port}");
    let probe = reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(300))
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| format!("MCP revival: build probe client: {e}"))?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "MCP revival: daemon did not become healthy within 15s (port {port})"
            ));
        }
        if let Ok(resp) = probe.get(format!("{new_base}/health")).send().await {
            if resp.status().is_success() {
                // Route all subsequent delegate calls at the revived daemon.
                if let Ok(mut guard) = DAEMON_URL_OVERRIDE.lock() {
                    *guard = Some(new_base.clone());
                }
                tracing::info!(url = %new_base, "MCP revival: daemon is healthy");
                return Ok(new_base);
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ── Seam-based MCP tool dispatch ────────────────────────────────────────

/// Core MCP-tool-call dispatch with one-shot daemon revival.
///
/// On a connection-class failure ([`DaemonCallError::ConnectionLost`]) the
/// seam's `revive` method is called **exactly once**.  If revival succeeds the
/// original request is retried against the new URL.  Non-connection failures
/// bypass revival entirely.
///
/// Invariants:
/// - `revive` is called at most once per invocation.
/// - `call_tool` is called at most twice (first attempt + one retry).
/// - Non-connection errors are never silently discarded.
async fn forward_mcp_with_seam(
    name: &str,
    args: &HashMap<String, serde_json::Value>,
    seam: &impl DaemonCallSeam,
    daemon_url: &str,
) -> Result<Option<ToolCallResult>, String> {
    match seam.call_tool(daemon_url, name, args).await {
        Ok(result) => Ok(result),
        Err(DaemonCallError::DaemonError(e)) => Err(e),
        Err(DaemonCallError::ConnectionLost(first_err)) => {
            // Daemon may have exited (idle timeout or crash).  Single revival
            // attempt before giving up.
            match seam.revive().await {
                Err(revive_err) => Err(format!(
                    "tool {name}: daemon at {daemon_url} is not responding \
                     ({first_err}); revival failed: {revive_err}. \
                     Restart `kin mcp start` to recover."
                )),
                Ok(new_url) => {
                    // Retry exactly once on the post-revival URL.
                    match seam.call_tool(&new_url, name, args).await {
                        Ok(result) => Ok(result),
                        Err(e) => {
                            let detail = match e {
                                DaemonCallError::ConnectionLost(s)
                                | DaemonCallError::DaemonError(s) => s,
                            };
                            Err(format!(
                                "tool {name}: daemon was revived at {new_url} but \
                                 the retry still failed: {detail}. \
                                 Check `kin daemon status`."
                            ))
                        }
                    }
                }
            }
        }
    }
}

async fn forward_mcp_tool_call(
    name: &str,
    arguments: &HashMap<String, serde_json::Value>,
) -> Result<Option<ToolCallResult>, String> {
    let Some(base) = daemon_base_url() else {
        return Ok(None);
    };
    forward_mcp_with_seam(name, arguments, &RealDaemonSeam, &base).await
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
        // Stage-time validation in product mode: reject intrinsically-malformed
        // staged operations locally before the daemon round-trip, so the agent
        // gets the same fast, actionable failure it gets in-process. The daemon
        // still owns graph-dependent validation and the actual staging.
        "kin_transaction_stage" => match validate_stage_arguments(arguments) {
            Ok(()) => forward_mcp_tool_call(name, arguments).await,
            Err(message) => Ok(Some(ToolCallResult::error(message))),
        },
        _ => forward_mcp_tool_call(name, arguments).await,
    }
}

/// Run the intrinsic stage-time validation over a `kin_transaction_stage`
/// argument map. A missing `operations` field is left for the daemon to report
/// (so the missing-parameter message stays authoritative); a malformed array or
/// a payload that would be silently dropped at commit fails loud here.
fn validate_stage_arguments(arguments: &HashMap<String, serde_json::Value>) -> Result<(), String> {
    let Some(operations_val) = arguments.get("operations") else {
        return Ok(());
    };
    let operations: Vec<crate::session::McpMutationOperation> =
        serde_json::from_value(operations_val.clone())
            .map_err(|e| format!("invalid operations array: {e}"))?;
    crate::session::validate_staged_operations(&operations)
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
        return Err(format!(
            "daemon graph status failed: HTTP {}",
            resp.status()
        ));
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

/// Best-effort fetch of the daemon `/health` body for response-envelope
/// enrichment.
///
/// Returns the parsed JSON on success and `None` whenever the daemon is
/// unreachable, the request fails, or the body does not parse. The envelope
/// folds the honest degraded/freshness fields from this body
/// (`embed_worker_failed`, `mass_deletion_blocked`, reconciliation state); a
/// `None` here simply leaves those envelope fields unknown rather than blocking
/// or failing the tool call. `/health` is liveness-only and never lazy-loads a
/// repo graph, so this is a cheap localhost probe.
pub async fn fetch_health_snapshot() -> Option<serde_json::Value> {
    let client = daemon_client().await?;
    let base = daemon_base_url()?;
    let resp = client.get(format!("{}/health", base)).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<serde_json::Value>().await.ok()
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

    // ── Revival state machine ──────────────────────────────────────────────
    //
    // Tests exercise `forward_mcp_with_seam` via a controlled stub seam.
    // No real daemon is started; no network calls beyond loopback are made.

    struct FakeSeam {
        /// Results to return on successive `call_tool` invocations (FIFO).
        calls: std::sync::Mutex<
            std::collections::VecDeque<Result<Option<ToolCallResult>, DaemonCallError>>,
        >,
        /// Value that `revive` returns.
        revive_result: Result<String, String>,
        /// Number of `call_tool` invocations.
        call_count: std::sync::atomic::AtomicUsize,
        /// Number of `revive` invocations.
        revive_count: std::sync::atomic::AtomicUsize,
    }

    impl FakeSeam {
        fn new(
            call_sequence: Vec<Result<Option<ToolCallResult>, DaemonCallError>>,
            revive_result: Result<String, String>,
        ) -> Self {
            Self {
                calls: std::sync::Mutex::new(call_sequence.into()),
                revive_result,
                call_count: std::sync::atomic::AtomicUsize::new(0),
                revive_count: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn calls_made(&self) -> usize {
            self.call_count.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn revives_attempted(&self) -> usize {
            self.revive_count.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl DaemonCallSeam for FakeSeam {
        async fn call_tool(
            &self,
            _base: &str,
            _name: &str,
            _args: &HashMap<String, serde_json::Value>,
        ) -> Result<Option<ToolCallResult>, DaemonCallError> {
            self.call_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.calls
                .lock()
                .unwrap()
                .pop_front()
                .expect("FakeSeam: unexpected extra call_tool invocation")
        }

        async fn revive(&self) -> Result<String, String> {
            self.revive_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.revive_result.clone()
        }
    }

    fn conn_lost() -> DaemonCallError {
        DaemonCallError::ConnectionLost("connection refused".into())
    }

    fn daemon_err() -> DaemonCallError {
        DaemonCallError::DaemonError("HTTP 500 Internal Server Error".into())
    }

    fn ok_tool_result() -> Result<Option<ToolCallResult>, DaemonCallError> {
        Ok(Some(ToolCallResult::text("ok".to_string())))
    }

    #[tokio::test]
    async fn revival_triggered_exactly_once_on_connection_error() {
        let seam = FakeSeam::new(
            vec![Err(conn_lost()), ok_tool_result()],
            Ok("http://127.0.0.1:9999".to_string()),
        );
        let result =
            forward_mcp_with_seam("tool", &HashMap::new(), &seam, "http://127.0.0.1:4219").await;
        assert!(result.is_ok(), "should succeed after revival: {result:?}");
        assert_eq!(seam.calls_made(), 2, "call_tool must run exactly twice");
        assert_eq!(seam.revives_attempted(), 1, "revive must run exactly once");
    }

    #[tokio::test]
    async fn non_connection_error_bypasses_revival() {
        let seam = FakeSeam::new(
            vec![Err(daemon_err())],
            Ok("http://127.0.0.1:9999".to_string()),
        );
        let result =
            forward_mcp_with_seam("tool", &HashMap::new(), &seam, "http://127.0.0.1:4219").await;
        let err = result.unwrap_err();
        assert!(err.contains("HTTP 500"), "original error preserved: {err}");
        assert_eq!(
            seam.revives_attempted(),
            0,
            "revive must NOT run for HTTP errors"
        );
        assert_eq!(
            seam.calls_made(),
            1,
            "only one call_tool attempt for HTTP errors"
        );
    }

    #[tokio::test]
    async fn revival_failure_yields_actionable_error() {
        let seam = FakeSeam::new(vec![Err(conn_lost())], Err("binary not found".to_string()));
        let err = forward_mcp_with_seam("tool", &HashMap::new(), &seam, "http://127.0.0.1:4219")
            .await
            .unwrap_err();
        assert!(
            err.contains("revival failed"),
            "must mention revival failure: {err}"
        );
        assert!(
            err.contains("kin mcp start"),
            "must suggest recovery action: {err}"
        );
    }

    #[tokio::test]
    async fn second_failure_after_revival_surfaces_clear_error() {
        let seam = FakeSeam::new(
            vec![Err(conn_lost()), Err(conn_lost())],
            Ok("http://127.0.0.1:9999".to_string()),
        );
        let err = forward_mcp_with_seam("tool", &HashMap::new(), &seam, "http://127.0.0.1:4219")
            .await
            .unwrap_err();
        assert!(
            err.contains("retry still failed"),
            "must indicate retry failure: {err}"
        );
        assert!(
            err.contains("kin daemon status"),
            "must suggest diagnostic: {err}"
        );
        assert_eq!(
            seam.revives_attempted(),
            1,
            "revival attempted at most once even when retry fails"
        );
    }

    #[test]
    fn mcp_idle_timeout_constant_is_1800() {
        assert_eq!(
            MCP_IDLE_TIMEOUT_SECS, "1800",
            "MCP path must use 30-min timeout"
        );
    }

    /// Verify that `reqwest::Error` from a connection-refused qualifies as a
    /// transport error.  Uses a loopback port that is guaranteed to be closed.
    /// No real daemon is spawned.
    #[tokio::test]
    async fn connection_refused_is_a_transport_error() {
        // Bind then immediately drop to guarantee the port is closed.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(300))
            .build()
            .unwrap();
        let err = client
            .get(format!("http://127.0.0.1:{port}/health"))
            .send()
            .await
            .unwrap_err();
        // The real seam classifies is_connect() as ConnectionLost.
        assert!(
            err.is_connect() || err.is_timeout(),
            "connection refused must be a connect error: {err:?}"
        );
    }

    // ── Existing tests below ───────────────────────────────────────────────

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
        let resolved = resolve_daemon_auth_token(Some("  env-token  ".to_string()), Some(&kin_dir));
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

    // ── Stage-time rejection parity on the daemon-forward path ───────────────
    //
    // `kin_transaction_stage` runs the same intrinsic validation before the
    // daemon round-trip as the in-process handler does, so an operation the
    // commit path would silently drop fails loud at stage time in product
    // (daemon) mode too — not only in offline/in-process mode.

    fn stage_args(
        operations: Vec<crate::session::McpMutationOperation>,
    ) -> HashMap<String, serde_json::Value> {
        let mut args = HashMap::new();
        args.insert("transaction_id".into(), serde_json::json!("tx-1"));
        args.insert(
            "operations".into(),
            serde_json::to_value(operations).expect("serialize operations"),
        );
        args
    }

    fn stage_op(
        verb: &str,
        payload: Option<crate::session::McpMutationPayload>,
    ) -> crate::session::McpMutationOperation {
        crate::session::McpMutationOperation {
            verb: verb.into(),
            target: String::new(),
            payload,
            body: None,
            description: String::new(),
        }
    }

    fn stage_relation() -> crate::session::McpMutationPayload {
        crate::session::McpMutationPayload::Relation {
            from: kin_model::ids::EntityId::new(),
            to: kin_model::ids::EntityId::new(),
            kind: kin_model::relation::RelationKind::Calls,
        }
    }

    #[test]
    fn delegate_stage_rejects_relation_modify() {
        let args = stage_args(vec![stage_op("modify", Some(stage_relation()))]);
        let err = validate_stage_arguments(&args).unwrap_err();
        assert!(
            err.contains("not committable for relation payloads"),
            "{err}"
        );
    }

    #[test]
    fn delegate_stage_rejects_blob_payload() {
        let args = stage_args(vec![stage_op(
            "create",
            Some(crate::session::McpMutationPayload::Blob(vec![1, 2, 3])),
        )]);
        let err = validate_stage_arguments(&args).unwrap_err();
        assert!(
            err.contains("blob payloads are not yet committable"),
            "{err}"
        );
    }

    #[test]
    fn delegate_stage_accepts_committable_relation() {
        let args = stage_args(vec![stage_op("add", Some(stage_relation()))]);
        assert!(validate_stage_arguments(&args).is_ok());
    }

    #[test]
    fn delegate_stage_missing_operations_defers_to_daemon() {
        // No `operations` key => stage validation is a no-op so the daemon's
        // authoritative missing-parameter message stays the one the agent sees.
        let mut args = HashMap::new();
        args.insert("transaction_id".into(), serde_json::json!("tx-1"));
        assert!(validate_stage_arguments(&args).is_ok());
    }
}
