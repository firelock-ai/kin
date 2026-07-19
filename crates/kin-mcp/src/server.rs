// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};

use kin_model::graph::GraphStore;
use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use crate::daemon_delegate;
use crate::envelope::{self, Envelope};
use crate::error::{McpError, Result};
use crate::handlers::handle_tool_call;
use crate::session::SessionRegistry;
use crate::tools::tool_definitions;
use crate::types::*;

/// MCP server configuration.
#[derive(Debug, Clone)]
pub struct McpServerConfig {
    pub server_name: String,
    pub server_version: String,
    pub allowed_tools: Option<HashSet<String>>,
    pub session_authority_mode: SessionAuthorityMode,
    pub snapshot_path: Option<PathBuf>,
}

/// How the stdio server should present session authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAuthorityMode {
    /// The daemon must own session state. Local registry fallback is disabled.
    DaemonRequired,
    /// The local in-process registry is only a fallback for offline/test use.
    OfflineFallback,
}

impl SessionAuthorityMode {
    pub fn uses_daemon(self) -> bool {
        matches!(self, Self::DaemonRequired)
    }

    pub fn requires_daemon(self) -> bool {
        matches!(self, Self::DaemonRequired)
    }
}

impl Default for McpServerConfig {
    fn default() -> Self {
        Self {
            server_name: "kin-mcp".into(),
            server_version: env!("CARGO_PKG_VERSION").into(),
            allowed_tools: None,
            session_authority_mode: SessionAuthorityMode::DaemonRequired,
            snapshot_path: None,
        }
    }
}

pub trait PersistableMcpStore: GraphStore {
    fn persist_primary_snapshot(&self, snapshot_path: Option<&Path>) -> Result<()> {
        let _ = snapshot_path;
        Ok(())
    }
}

impl PersistableMcpStore for kin_db::InMemoryGraph {
    fn persist_primary_snapshot(&self, snapshot_path: Option<&Path>) -> Result<()> {
        let Some(snapshot_path) = snapshot_path else {
            return Ok(());
        };
        self.flush_text_index().map_err(McpError::graph)?;
        let snapshot = self.to_snapshot();
        let text_index_path = snapshot_path
            .parent()
            .map(|parent| parent.join("text-index"))
            .ok_or_else(|| McpError::Other("snapshot path has no parent directory".into()))?;
        let manager = kin_db::SnapshotManager::new(snapshot_path.to_path_buf());
        manager.swap(kin_db::InMemoryGraph::from_snapshot_with_text_index(
            snapshot,
            text_index_path,
        ));
        manager.save().map_err(McpError::graph)?;
        Ok(())
    }
}

/// Run the in-process MCP server over stdio (stdin/stdout).
///
/// This is the explicit offline/test runtime. Product `kin mcp start` uses
/// [`run_stdio_daemon`], which never receives a graph store and cannot fall
/// through to local graph handlers.
pub async fn run_stdio<G: PersistableMcpStore + 'static>(
    store: G,
    config: McpServerConfig,
) -> Result<()> {
    let sessions = SessionRegistry::new();
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let reader = BufReader::new(stdin);
    let mut reader = reader;

    tracing::info!("kin-mcp stdio server starting");
    match config.session_authority_mode {
        SessionAuthorityMode::DaemonRequired => {
            tracing::info!(
                "kin-mcp session authority: daemon-required; local registry fallback is disabled"
            );
        }
        SessionAuthorityMode::OfflineFallback => {
            tracing::info!(
                "kin-mcp session authority: explicit offline test mode; local registry is authoritative for this run"
            );
        }
    }

    while let Some((message, framed)) = read_stdio_message(&mut reader).await? {
        if let Some(response) = process_message(&message, &store, &config, &sessions).await {
            let response_json = serde_json::to_string(&response).map_err(McpError::Json)?;
            write_stdio_message(&mut stdout, &response_json, framed).await?;
        }
    }

    tracing::info!("kin-mcp stdio server shutting down");
    Ok(())
}

/// Binds the repo daemon from the MCP client's advertised workspace roots.
///
/// Receives the filesystem paths of the client's roots, binds the daemon for the
/// first one that is a Kin repository (setting `KIN_DAEMON_URL` as a side
/// effect), and returns the bound daemon URL — or `None` if none of the roots is
/// a Kin repository. Supplied by the kin-cli MCP command; when `None`, roots
/// binding is disabled (a repository was already bound at startup, or the client
/// cannot serve roots).
pub type RepoBinder =
    Box<dyn Fn(Vec<PathBuf>) -> Pin<Box<dyn Future<Output = Option<String>> + Send>> + Send + Sync>;

/// The JSON-RPC id the server uses for its own `roots/list` request so it can
/// recognize the matching response coming back from the client.
const ROOTS_REQUEST_ID: &str = "kin-mcp-roots-list";

/// Run the daemon-required MCP server over stdio.
///
/// This mode is intentionally graphless: every `tools/call` request is
/// forwarded to the repo daemon, which executes against its live graph and
/// session coordinator. The stdio process only handles JSON-RPC framing,
/// initialization, tool listing, allow-list checks, and transport errors.
///
/// When no repository was bound at startup (no `--repo`/`KIN_MCP_REPO` and the
/// launch cwd is not inside a Kin repo — the common case for editors that spawn
/// MCP servers from `$HOME`) and the client advertises the MCP `roots`
/// capability, the server requests `roots/list` after initialization and binds
/// the daemon to the open workspace via `repo_binder`. That is what lets Cursor,
/// Windsurf, and other editors reach whatever repository the user has open
/// without a hardcoded path in the MCP config.
pub async fn run_stdio_daemon(
    config: McpServerConfig,
    repo_binder: Option<RepoBinder>,
) -> Result<()> {
    if !config.session_authority_mode.requires_daemon() {
        return Err(McpError::Other(
            "daemon stdio mode requires daemon session authority".to_string(),
        ));
    }

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let reader = BufReader::new(stdin);
    let mut reader = reader;

    tracing::info!("kin-mcp daemon-proxy stdio server starting");

    // MCP `roots` binding state. We only reach out for workspace roots when we
    // could not bind a repository at startup and the client says it can serve
    // them. An editor may initialize the shared MCP process before opening a
    // workspace, so only suppress a request while one is actually in flight.
    let mut client_supports_roots = false;
    let mut roots_request_in_flight = false;

    while let Some((message, framed)) = read_stdio_message(&mut reader).await? {
        // Peek at the raw JSON so we can distinguish the client's requests and
        // notifications from the `roots/list` response we may have sent: a
        // response carries no `method`, which the strongly-typed
        // `JsonRpcRequest` requires.
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&message) {
            let method = value.get("method").and_then(|m| m.as_str());

            if method == Some("initialize") {
                client_supports_roots = value.pointer("/params/capabilities/roots").is_some();
            }

            // Our own `roots/list` response returning from the client: bind the
            // daemon and swallow it (a response is never itself answered).
            if method.is_none()
                && value.get("id").and_then(|id| id.as_str()) == Some(ROOTS_REQUEST_ID)
            {
                roots_request_in_flight = false;
                if let Some(binder) = repo_binder.as_ref() {
                    let roots = parse_workspace_roots(&value);
                    if roots.is_empty() {
                        tracing::info!(
                            "kin-mcp: client returned no workspace roots; repository stays unbound"
                        );
                    } else if binder(roots).await.is_none() {
                        tracing::info!(
                            "kin-mcp: no Kin repository among the client's workspace roots"
                        );
                    }
                }
                continue;
            }

            // Once the client finishes initializing (or asks for the tool list)
            // and we still have no bound daemon, ask it for its workspace roots.
            // Retry after an earlier empty response, and honor the MCP roots
            // change notification used when an editor opens or changes folders.
            if should_request_workspace_roots(
                method,
                client_supports_roots,
                roots_request_in_flight,
                repo_binder.is_some(),
                daemon_is_unbound(),
            ) {
                roots_request_in_flight = true;
                let request = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": ROOTS_REQUEST_ID,
                    "method": "roots/list",
                });
                let request_json = serde_json::to_string(&request).map_err(McpError::Json)?;
                write_stdio_message(&mut stdout, &request_json, framed).await?;
                // Fall through: `initialized` has no response, and `tools/list`
                // is still answered normally below.
            }
        }

        if let Some(response) = process_daemon_message(&message, &config).await {
            let response_json = serde_json::to_string(&response).map_err(McpError::Json)?;
            write_stdio_message(&mut stdout, &response_json, framed).await?;
        }
    }

    tracing::info!("kin-mcp daemon-proxy stdio server shutting down");
    Ok(())
}

/// True when no repo daemon has been bound yet (`KIN_DAEMON_URL` unset/empty).
fn daemon_is_unbound() -> bool {
    std::env::var("KIN_DAEMON_URL")
        .map(|value| value.trim().is_empty())
        .unwrap_or(true)
}

/// Decide whether an inbound client message should trigger a workspace-roots
/// request. Kept separate from the stdio loop so the retry semantics remain
/// deterministic and testable without mutating process-global daemon state.
fn should_request_workspace_roots(
    method: Option<&str>,
    client_supports_roots: bool,
    request_in_flight: bool,
    has_repo_binder: bool,
    daemon_unbound: bool,
) -> bool {
    let refresh_trigger = matches!(
        method,
        Some("initialized")
            | Some("notifications/initialized")
            | Some("notifications/roots/list_changed")
            | Some("tools/list")
    );

    refresh_trigger
        && client_supports_roots
        && !request_in_flight
        && has_repo_binder
        && daemon_unbound
}

/// Extract filesystem paths from an MCP `roots/list` response
/// (`result.roots[].uri`), accepting both `file://` URIs and bare paths.
fn parse_workspace_roots(value: &serde_json::Value) -> Vec<PathBuf> {
    value
        .pointer("/result/roots")
        .and_then(|roots| roots.as_array())
        .map(|roots| {
            roots
                .iter()
                .filter_map(|root| root.get("uri").and_then(|uri| uri.as_str()))
                .filter_map(root_uri_to_path)
                .collect()
        })
        .unwrap_or_default()
}

/// Convert an MCP root's `uri` into a filesystem path. Accepts spec-compliant
/// `file://` URIs (decoding `%XX` escapes) and the bare absolute path some
/// clients (e.g. Cursor) send instead. Returns `None` for remote/non-file URIs.
fn root_uri_to_path(uri: &str) -> Option<PathBuf> {
    if uri
        .get(.."file://".len())
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("file://"))
    {
        let rest = &uri["file://".len()..];

        // Empty authority: `file:///abs/path` or `file:///C:/Users/me/repo`.
        if rest.starts_with('/') {
            return Some(file_uri_path(percent_decode(rest)));
        }

        let slash = rest.find('/')?;
        let authority = &rest[..slash];
        let path = percent_decode(&rest[slash..]);

        // `localhost` is the local machine, so only its path component matters.
        if authority.eq_ignore_ascii_case("localhost") {
            return Some(file_uri_path(path));
        }

        // A few Windows clients emit the non-canonical but common
        // `file://C:/Users/...` spelling, treating the drive as an authority.
        if is_windows_drive_authority(authority) {
            return Some(PathBuf::from(format!("{authority}{path}")));
        }

        // A non-local file authority is a Windows UNC share. Do not reinterpret
        // it as a local POSIX path on Unix hosts.
        #[cfg(windows)]
        {
            return Some(PathBuf::from(format!(
                r"\\{authority}{}",
                path.replace('/', "\\")
            )));
        }
        #[cfg(not(windows))]
        {
            return None;
        }
    }
    // Some clients (Cursor) send a bare absolute path rather than a file URI.
    if uri.starts_with('/') || is_windows_drive_path(uri) || uri.starts_with(r"\\") {
        return Some(PathBuf::from(uri));
    }
    None
}

/// Normalize the path component of a file URI. RFC 8089 spells a Windows drive
/// URI as `file:///C:/...`; the leading slash is URI syntax, not part of the
/// native Windows path.
fn file_uri_path(path: String) -> PathBuf {
    if path.starts_with('/') && is_windows_drive_path(&path[1..]) {
        PathBuf::from(&path[1..])
    } else {
        PathBuf::from(path)
    }
}

fn is_windows_drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

fn is_windows_drive_authority(authority: &str) -> bool {
    let bytes = authority.as_bytes();
    bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// Minimal percent-decoding for `file://` URI paths (handles `%20`, etc.).
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(decoded) = u8::from_str_radix(&input[i + 1..i + 3], 16) {
                out.push(decoded);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn read_stdio_message<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Option<(String, bool)>> {
    let mut first_line = String::new();
    loop {
        first_line.clear();
        let bytes = reader
            .read_line(&mut first_line)
            .await
            .map_err(McpError::Io)?;
        if bytes == 0 {
            return Ok(None);
        }
        if !first_line.trim().is_empty() {
            break;
        }
    }

    if let Some(content_length) = parse_content_length(&first_line) {
        let mut header_line = String::new();
        loop {
            header_line.clear();
            let bytes = reader
                .read_line(&mut header_line)
                .await
                .map_err(McpError::Io)?;
            if bytes == 0 {
                return Err(McpError::Protocol(
                    "unexpected EOF while reading MCP headers".into(),
                ));
            }
            if header_line == "\n" || header_line == "\r\n" {
                break;
            }
        }

        let mut payload = vec![0u8; content_length];
        reader
            .read_exact(&mut payload)
            .await
            .map_err(McpError::Io)?;
        let message = String::from_utf8(payload)
            .map_err(|e| McpError::Protocol(format!("invalid UTF-8 payload: {e}")))?;
        return Ok(Some((message, true)));
    }

    Ok(Some((first_line.trim().to_string(), false)))
}

async fn write_stdio_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response_json: &str,
    framed: bool,
) -> Result<()> {
    if framed {
        let response_bytes = response_json.as_bytes();
        let header = format!("Content-Length: {}\r\n\r\n", response_bytes.len());
        writer
            .write_all(header.as_bytes())
            .await
            .map_err(McpError::Io)?;
        writer
            .write_all(response_bytes)
            .await
            .map_err(McpError::Io)?;
    } else {
        writer
            .write_all(response_json.as_bytes())
            .await
            .map_err(McpError::Io)?;
        writer.write_all(b"\n").await.map_err(McpError::Io)?;
    }
    writer.flush().await.map_err(McpError::Io)?;
    Ok(())
}

fn parse_content_length(line: &str) -> Option<usize> {
    let (name, value) = line.split_once(':')?;
    if !name.trim().eq_ignore_ascii_case("Content-Length") {
        return None;
    }
    value.trim().parse().ok()
}

/// Process a single JSON-RPC message and return a response.
pub async fn process_message<G: PersistableMcpStore>(
    message: &str,
    store: &G,
    config: &McpServerConfig,
    sessions: &SessionRegistry,
) -> Option<JsonRpcResponse> {
    let request: JsonRpcRequest = match serde_json::from_str(message) {
        Ok(req) => req,
        Err(e) => {
            return Some(JsonRpcResponse::error(
                None,
                -32700,
                format!("Parse error: {}", e),
            ));
        }
    };

    let id = request.id.clone();
    let is_notification = id.is_none();

    let response = match request.method.as_str() {
        "initialize" => Some(handle_initialize(id, &request.params, config)),
        "initialized" => None,
        "tools/list" => Some(handle_tools_list(id, config)),
        "tools/call" if config.session_authority_mode.requires_daemon() => {
            Some(handle_tools_call_daemon(id, &request.params, config).await)
        }
        "tools/call" => Some(handle_tools_call(id, &request.params, store, sessions, config).await),
        "ping" => Some(JsonRpcResponse::success(id, serde_json::json!({}))),
        _ => Some(JsonRpcResponse::error(
            id,
            -32601,
            format!("Method not found: {}", request.method),
        )),
    };

    if is_notification {
        None
    } else {
        response
    }
}

/// Process a single JSON-RPC message for daemon-backed product mode.
pub async fn process_daemon_message(
    message: &str,
    config: &McpServerConfig,
) -> Option<JsonRpcResponse> {
    let request: JsonRpcRequest = match serde_json::from_str(message) {
        Ok(req) => req,
        Err(e) => {
            return Some(JsonRpcResponse::error(
                None,
                -32700,
                format!("Parse error: {}", e),
            ));
        }
    };

    let id = request.id.clone();
    let is_notification = id.is_none();

    let response = match request.method.as_str() {
        "initialize" => Some(handle_initialize(id, &request.params, config)),
        "initialized" => None,
        "tools/list" => Some(handle_tools_list(id, config)),
        "tools/call" => Some(handle_tools_call_daemon(id, &request.params, config).await),
        "ping" => Some(JsonRpcResponse::success(id, serde_json::json!({}))),
        _ => Some(JsonRpcResponse::error(
            id,
            -32601,
            format!("Method not found: {}", request.method),
        )),
    };

    if is_notification {
        None
    } else {
        response
    }
}

/// The MCP protocol version this server supports.
const SUPPORTED_PROTOCOL_VERSION: &str = "2024-11-05";

fn handle_initialize(
    id: Option<serde_json::Value>,
    params: &serde_json::Value,
    config: &McpServerConfig,
) -> JsonRpcResponse {
    // Check if the client requests a newer protocol version than we support.
    // We respond with our supported version and include a warning — we never
    // error, to remain forward-compatible.
    let client_version = params
        .get("protocolVersion")
        .and_then(|v| v.as_str())
        .unwrap_or(SUPPORTED_PROTOCOL_VERSION);

    let mut result = serde_json::to_value(&InitializeResult {
        protocol_version: SUPPORTED_PROTOCOL_VERSION.into(),
        capabilities: ServerCapabilities {
            tools: ToolsCapability {
                list_changed: false,
            },
        },
        server_info: ServerInfo {
            name: config.server_name.clone(),
            version: config.server_version.clone(),
        },
    })
    .unwrap_or_default();

    // Add kinVersion to serverInfo for Kin-aware clients.
    if let Some(info) = result.get_mut("serverInfo") {
        info["kinVersion"] = serde_json::json!(config.server_version);
    }

    // Warn if client requested a newer protocol version.
    if client_version != SUPPORTED_PROTOCOL_VERSION {
        result["_warning"] = serde_json::json!(format!(
            "client requested protocol version '{}', server supports '{}'; \
             falling back to server version",
            client_version, SUPPORTED_PROTOCOL_VERSION
        ));
    }

    JsonRpcResponse::success(id, result)
}

fn handle_tools_list(id: Option<serde_json::Value>, config: &McpServerConfig) -> JsonRpcResponse {
    let mut tools = tool_definitions();
    if let Some(allowed) = &config.allowed_tools {
        tools.tools.retain(|tool| allowed.contains(&tool.name));
    }
    JsonRpcResponse::success(id, serde_json::to_value(&tools).unwrap_or_default())
}

async fn handle_tools_call<G: PersistableMcpStore>(
    id: Option<serde_json::Value>,
    params: &serde_json::Value,
    store: &G,
    sessions: &SessionRegistry,
    config: &McpServerConfig,
) -> JsonRpcResponse {
    let call_params: ToolCallParams = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(e) => {
            return JsonRpcResponse::error(id, -32602, format!("Invalid params: {}", e));
        }
    };

    if let Some(allowed) = &config.allowed_tools {
        if !allowed.contains(&call_params.name) {
            let error_result = ToolCallResult::error(format!(
                "tool '{}' is not enabled in this MCP profile",
                call_params.name
            ));
            return offline_envelope_success(id, error_result, &call_params.name);
        }
    }

    let mut handler = std::pin::pin!(handle_tool_call(
        &call_params.name,
        &call_params.arguments,
        store,
        sessions,
        config.session_authority_mode,
    ));
    let outcome = std::future::poll_fn(|cx| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            std::future::Future::poll(handler.as_mut(), cx)
        })) {
            Ok(poll) => poll.map(Ok),
            Err(panic) => std::task::Poll::Ready(Err(panic)),
        }
    })
    .await;

    let call_result = match outcome {
        Ok(call_result) => call_result,
        Err(panic) => {
            let detail = panic
                .downcast_ref::<&str>()
                .map(|message| (*message).to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "tool handler panicked".to_string());
            return JsonRpcResponse::error(
                id,
                -32603,
                format!(
                    "Internal error: tool '{}' panicked: {detail}",
                    call_params.name
                ),
            );
        }
    };

    match call_result {
        Ok(result) => {
            if tool_requires_persist(&call_params.name) {
                if let Err(error) = store.persist_primary_snapshot(config.snapshot_path.as_deref())
                {
                    let error_result = ToolCallResult::error(format!(
                        "tool succeeded but snapshot persistence failed: {error}"
                    ));
                    return offline_envelope_success(id, error_result, &call_params.name);
                }
            }
            offline_envelope_success(id, result, &call_params.name)
        }
        Err(e) => {
            offline_envelope_success(id, ToolCallResult::error(e.to_string()), &call_params.name)
        }
    }
}

/// Attach the offline/in-process response envelope and wrap the result as a
/// JSON-RPC success. The in-process path is the explicit offline runtime, so the
/// envelope honestly flags `offline_fallback` (not daemon-owned truth). The tool
/// name lets `finalize` synthesize the confidence-qualified negative for empty
/// retrieval results on this path too.
fn offline_envelope_success(
    id: Option<serde_json::Value>,
    result: ToolCallResult,
    tool_name: &str,
) -> JsonRpcResponse {
    let enveloped = envelope::finalize(result, Envelope::offline(), tool_name);
    JsonRpcResponse::success(id, serde_json::to_value(&enveloped).unwrap_or_default())
}

async fn handle_tools_call_daemon(
    id: Option<serde_json::Value>,
    params: &serde_json::Value,
    config: &McpServerConfig,
) -> JsonRpcResponse {
    let call_params: ToolCallParams = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(e) => {
            return JsonRpcResponse::error(id, -32602, format!("Invalid params: {}", e));
        }
    };

    if let Some(allowed) = &config.allowed_tools {
        if !allowed.contains(&call_params.name) {
            let error_result = ToolCallResult::error(format!(
                "tool '{}' is not enabled in this MCP profile",
                call_params.name
            ));
            let enveloped = envelope::finalize(error_result, Envelope::daemon(), &call_params.name);
            return JsonRpcResponse::success(
                id,
                serde_json::to_value(&enveloped).unwrap_or_default(),
            );
        }
    }

    let (result, mut base_env) =
        match daemon_delegate::forward_tool_call(&call_params.name, &call_params.arguments).await {
            Ok(Some(result)) => (result, Envelope::daemon()),
            Ok(None) => (
                daemon_delegate::daemon_unavailable_tool_result(&call_params.name),
                Envelope::daemon_unreachable(),
            ),
            Err(error) => (ToolCallResult::error(error), Envelope::daemon()),
        };

    // Enrich the envelope with honest degraded/freshness signals from the daemon
    // `/health` body when the daemon is actually reachable. When it was already
    // determined unreachable, skip the probe — there is nothing to ask.
    if base_env.degraded.daemon_unreachable != Some(true) {
        if let Some(health) = daemon_delegate::fetch_health_snapshot().await {
            base_env = base_env.with_health(&health);
        }
    }

    let enveloped = envelope::finalize(result, base_env, &call_params.name);
    JsonRpcResponse::success(id, serde_json::to_value(&enveloped).unwrap_or_default())
}

fn tool_requires_persist(name: &str) -> bool {
    matches!(
        name,
        "kin_review_create"
            | "kin_review_decide"
            | "kin_review_note_add"
            | "kin_review_discuss"
            | "kin_review_discuss_reply"
            | "kin_review_discuss_resolve"
            | "kin_review_assign"
            | "kin_review_remove_reviewer"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{ENVELOPE_KEY, ENVELOPE_VERSION};
    use kin_db::InMemoryGraph;

    /// Run a `tools/call` through the real in-process chokepoint and return the
    /// parsed tool payload (the JSON inside the single text content block).
    async fn call_tool_payload(tool: &str, arguments: serde_json::Value) -> serde_json::Value {
        let mut config = McpServerConfig::default();
        config.session_authority_mode = SessionAuthorityMode::OfflineFallback;
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": tool, "arguments": arguments },
        })
        .to_string();
        let resp = process_message(&msg, &store, &config, &sessions)
            .await
            .expect("response");
        assert!(resp.error.is_none(), "transport error for {tool}");
        let result: ToolCallResult =
            serde_json::from_value(resp.result.expect("result")).expect("tool call result");
        let ContentBlock::Text { text } = result.content.first().expect("one content block");
        serde_json::from_str(text)
            .unwrap_or_else(|e| panic!("envelope-annotated payload for {tool} is not JSON: {e}"))
    }

    /// Assert the offline envelope is present and well-formed on a payload.
    fn assert_offline_envelope(payload: &serde_json::Value, tool: &str) {
        let env = payload
            .get(ENVELOPE_KEY)
            .unwrap_or_else(|| panic!("tool {tool} response is missing the _kin envelope"));
        assert_eq!(
            env["envelope_version"], ENVELOPE_VERSION,
            "tool {tool} envelope version"
        );
        assert_eq!(
            env["runtime"], "offline-in-process",
            "tool {tool} runtime should report the in-process fallback"
        );
        // Honesty: the offline path flags itself as a non-daemon fallback.
        assert_eq!(env["degraded"]["offline_fallback"], true, "tool {tool}");
    }

    // ── D.8: every tool family carries the unified response envelope ──────────

    #[tokio::test]
    async fn envelope_present_on_entities_family() {
        // semantic_search returns an object payload; the envelope must ride
        // alongside the original `results` key without displacing it.
        let payload =
            call_tool_payload("semantic_search", serde_json::json!({ "query": "foo" })).await;
        assert_offline_envelope(&payload, "semantic_search");
        assert!(
            payload.get("results").is_some(),
            "semantic_search payload must keep its `results` key where agents expect it"
        );
    }

    #[tokio::test]
    async fn envelope_present_on_work_family() {
        let payload = call_tool_payload("kin_work_list", serde_json::json!({})).await;
        assert_offline_envelope(&payload, "kin_work_list");
    }

    #[tokio::test]
    async fn envelope_present_on_verification_family() {
        let payload = call_tool_payload("kin_coverage_summary", serde_json::json!({})).await;
        assert_offline_envelope(&payload, "kin_coverage_summary");
    }

    #[tokio::test]
    async fn envelope_present_on_error_results() {
        // semantic_locate errors offline (vector search needs the daemon). The
        // envelope must still be attached so degraded states are surfaced, and
        // the human message preserved alongside it.
        let payload = call_tool_payload(
            "semantic_locate",
            serde_json::json!({ "query": "where is auth handled" }),
        )
        .await;
        assert_offline_envelope(&payload, "semantic_locate");
        let message = payload["message"]
            .as_str()
            .expect("wrapped error message present");
        assert!(
            message.contains("requires the Kin daemon"),
            "original error message preserved, got: {message}"
        );
    }

    // ── Track C: confidence-qualified negatives ride the envelope through the
    //    real dispatch chokepoint, on the offline path, across tool groups. ──────

    /// Assert the additive `negative` contract is present and shaped, without
    /// disturbing the envelope or the original payload keys.
    fn assert_negative(payload: &serde_json::Value, tool: &str, kind: &str) -> serde_json::Value {
        assert_offline_envelope(payload, tool);
        let negative = payload
            .get("negative")
            .unwrap_or_else(|| panic!("tool {tool} empty result must carry a `negative` contract"));
        assert_eq!(negative["kind"], kind, "tool {tool} negative kind");
        // Offline is a fallback surface: absence is never authoritative here.
        assert_eq!(
            negative["safe_to_conclude_absent"], false,
            "tool {tool} offline absence must be inconclusive"
        );
        assert_eq!(negative["trust"], "inconclusive", "tool {tool}");
        assert!(
            negative["advice"].as_str().is_some_and(|a| !a.is_empty()),
            "tool {tool} negative must carry human advice"
        );
        negative.clone()
    }

    #[tokio::test]
    async fn negative_contract_on_empty_object_payload_search() {
        // Object payload: `negative` is added beside `_kin` and the untouched
        // `results` key.
        let payload = call_tool_payload(
            "semantic_search",
            serde_json::json!({ "query": "nonexistent" }),
        )
        .await;
        let negative = assert_negative(&payload, "semantic_search", "no_entity_match");
        assert_eq!(negative["result_count"], 0);
        assert_eq!(negative["interpretation"], "absent_as_indexed");
        // Back-compat: the original result collection still lives where agents
        // expect it, empty.
        assert_eq!(
            payload["results"].as_array().map(|a| a.len()),
            Some(0),
            "negative must not displace the original `results` key"
        );
    }

    #[tokio::test]
    async fn negative_contract_on_empty_bare_array_dead_code() {
        // Bare-array payload: the annotator wraps it under `result`; `negative`
        // rides alongside.
        let payload = call_tool_payload("dead_code", serde_json::json!({})).await;
        let negative = assert_negative(&payload, "dead_code", "no_dead_code");
        assert_eq!(negative["result_count"], 0);
        assert!(
            payload["result"].is_array(),
            "bare-array dead_code payload is wrapped under `result`"
        );
    }

    #[tokio::test]
    async fn no_negative_on_non_retrieval_tool() {
        // Work-graph listing is not a code-retrieval negative surface: an empty
        // work list must NOT be dressed up as a confidence-qualified absence.
        let payload = call_tool_payload("kin_work_list", serde_json::json!({})).await;
        assert_offline_envelope(&payload, "kin_work_list");
        assert!(
            payload.get("negative").is_none(),
            "non-retrieval tools must not carry a `negative` contract"
        );
    }

    #[test]
    fn default_config_requires_daemon_session_authority() {
        let config = McpServerConfig::default();
        assert_eq!(
            config.session_authority_mode,
            SessionAuthorityMode::DaemonRequired
        );
        assert!(config.session_authority_mode.requires_daemon());
    }

    #[tokio::test]
    async fn process_initialize() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());

        let result = resp.result.unwrap();
        assert_eq!(result["serverInfo"]["name"], "kin-mcp");
        // P2-2.3: kinVersion must be present in serverInfo
        assert!(result["serverInfo"]["kinVersion"].is_string());
    }

    #[tokio::test]
    async fn initialize_with_newer_protocol_version_includes_warning() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01"}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());

        let result = resp.result.unwrap();
        // Server falls back to its supported version
        assert_eq!(result["protocolVersion"], "2024-11-05");
        // Warning is present
        assert!(result["_warning"].is_string());
        assert!(result["_warning"].as_str().unwrap().contains("2099-01-01"));
    }

    #[tokio::test]
    async fn initialize_with_matching_protocol_version_no_warning() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        let result = resp.result.unwrap();
        assert!(result.get("_warning").is_none());
    }

    #[tokio::test]
    async fn process_tools_list() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.result.is_some());

        let tools = &resp.result.unwrap()["tools"];
        assert!(tools.is_array());
        assert!(!tools.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn process_tools_call_semantic_search() {
        let mut config = McpServerConfig::default();
        config.session_authority_mode = SessionAuthorityMode::OfflineFallback;
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"semantic_search","arguments":{"query":"foo"}}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn process_tools_call_semantic_locate_requires_daemon_offline() {
        // End-to-end dispatch check: semantic_locate must reach
        // handle_semantic_locate and report the daemon requirement rather than
        // silently degrading to a metadata filter when no daemon graph is
        // present.
        let mut config = McpServerConfig::default();
        config.session_authority_mode = SessionAuthorityMode::OfflineFallback;
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"semantic_locate","arguments":{"query":"where is auth handled"}}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.error.is_none());
        let result: ToolCallResult = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(result.is_error, Some(true));
        let text = match result.content.first().unwrap() {
            ContentBlock::Text { text } => text,
        };
        assert!(
            text.contains("requires the Kin daemon"),
            "expected daemon-required message, got: {text}"
        );
    }

    #[tokio::test]
    async fn daemon_required_tools_do_not_use_local_handlers() {
        struct RemoveCreatedKinDir(Option<std::path::PathBuf>);

        impl Drop for RemoveCreatedKinDir {
            fn drop(&mut self) {
                if let Some(path) = self.0.take() {
                    let _ = std::fs::remove_dir(path);
                }
            }
        }

        // Bind this end-to-end dispatch test to a Kin repository explicitly.
        // Without `.kin`, the production delegate correctly reports the
        // distinct "not inside a kin repository" state before it can prove the
        // daemon-required branch this test is intended to lock down.
        let kin_dir = std::env::current_dir().unwrap().join(".kin");
        let remove_kin_dir = match std::fs::create_dir(&kin_dir) {
            Ok(()) => RemoveCreatedKinDir(Some(kin_dir)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && kin_dir.is_dir() => {
                RemoveCreatedKinDir(None)
            }
            Err(error) => panic!("failed to establish Kin repo fixture: {error}"),
        };
        std::env::remove_var("KIN_DAEMON_URL");
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"semantic_search","arguments":{"query":"foo"}}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.error.is_none());
        let result: ToolCallResult = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(result.is_error, Some(true));
        let text = match result.content.first().unwrap() {
            ContentBlock::Text { text } => text,
        };
        assert!(text.contains("Kin daemon is required"));
        drop(remove_kin_dir);
    }

    #[tokio::test]
    async fn process_tools_call_register_session() {
        let mut config = McpServerConfig::default();
        config.session_authority_mode = SessionAuthorityMode::OfflineFallback;
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"register_session","arguments":{"assistant_name":"claude-code","session_id":"test-123"}}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.result.is_some());
        assert_eq!(sessions.count(), 1);
    }

    #[tokio::test]
    async fn process_daemon_message_handles_transport_methods_without_store() {
        let config = McpServerConfig::default();
        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let resp = process_daemon_message(msg, &config).await.unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn process_unknown_method() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":5,"method":"unknown/method","params":{}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[tokio::test]
    async fn process_invalid_json() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let resp = process_message("not json", &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32700);
    }

    #[tokio::test]
    async fn process_ping() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":6,"method":"ping","params":{}}"#;
        let resp = process_message(msg, &store, &config, &sessions)
            .await
            .unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn process_initialized_notification_has_no_response() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","method":"initialized","params":{}}"#;
        let resp = process_message(msg, &store, &config, &sessions).await;
        assert!(resp.is_none());
    }

    #[test]
    fn parse_content_length_header() {
        assert_eq!(parse_content_length("Content-Length: 123\r\n"), Some(123));
        assert_eq!(parse_content_length("content-length: 7\n"), Some(7));
        assert_eq!(parse_content_length("X-Test: 1"), None);
        assert_eq!(parse_content_length("Content-Length: nope"), None);
    }

    #[test]
    fn root_uri_to_path_handles_file_uris_and_bare_paths() {
        assert_eq!(
            root_uri_to_path("file:///Users/me/proj"),
            Some(PathBuf::from("/Users/me/proj"))
        );
        // `file://host/path` drops the authority, leaving the absolute path.
        assert_eq!(
            root_uri_to_path("file://localhost/Users/me/proj"),
            Some(PathBuf::from("/Users/me/proj"))
        );
        // Percent-escaped characters (e.g. spaces) decode.
        assert_eq!(
            root_uri_to_path("file:///Users/me/My%20Repo"),
            Some(PathBuf::from("/Users/me/My Repo"))
        );
        // RFC 8089 Windows drive URIs drop the URI-only leading slash.
        assert_eq!(
            root_uri_to_path("file:///C:/Users/me/My%20Repo"),
            Some(PathBuf::from("C:/Users/me/My Repo"))
        );
        assert_eq!(
            root_uri_to_path("file://localhost/C:/Users/me/kin"),
            Some(PathBuf::from("C:/Users/me/kin"))
        );
        // Accept the non-canonical spelling emitted by some Windows clients.
        assert_eq!(
            root_uri_to_path("file://C:/Users/me/kin"),
            Some(PathBuf::from("C:/Users/me/kin"))
        );
        // Some clients (Cursor) send a bare absolute path, not a file:// URI.
        assert_eq!(
            root_uri_to_path("/Users/me/kin"),
            Some(PathBuf::from("/Users/me/kin"))
        );
        assert_eq!(
            root_uri_to_path(r"C:\Users\me\kin"),
            Some(PathBuf::from(r"C:\Users\me\kin"))
        );
        assert_eq!(
            root_uri_to_path("C:/Users/me/kin"),
            Some(PathBuf::from("C:/Users/me/kin"))
        );
        assert_eq!(root_uri_to_path("C:relative\\kin"), None);
        #[cfg(windows)]
        assert_eq!(
            root_uri_to_path("file://server/share/kin"),
            Some(PathBuf::from(r"\\server\share\kin"))
        );
        #[cfg(not(windows))]
        assert_eq!(root_uri_to_path("file://server/share/kin"), None);
        // Non-file schemes (e.g. remote workspaces) are skipped.
        assert_eq!(root_uri_to_path("vscode-remote://host/x"), None);
        assert_eq!(root_uri_to_path("https://example.com/x"), None);
    }

    #[test]
    fn parse_workspace_roots_extracts_local_paths() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": ROOTS_REQUEST_ID,
            "result": {
                "roots": [
                    {"uri": "file:///Users/me/kin", "name": "kin"},
                    {"uri": "vscode-remote://host/y"},
                    {"uri": "/Users/me/bare", "name": "bare"},
                    {"uri": "file:///Users/me/other"}
                ]
            }
        });
        assert_eq!(
            parse_workspace_roots(&response),
            vec![
                PathBuf::from("/Users/me/kin"),
                PathBuf::from("/Users/me/bare"),
                PathBuf::from("/Users/me/other"),
            ]
        );
        // A response carrying no roots yields an empty list, never a panic.
        assert!(parse_workspace_roots(&serde_json::json!({ "result": {} })).is_empty());
    }

    #[test]
    fn workspace_roots_retry_after_empty_response_or_root_change() {
        for method in [
            "initialized",
            "notifications/initialized",
            "notifications/roots/list_changed",
            "tools/list",
        ] {
            assert!(should_request_workspace_roots(
                Some(method),
                true,
                false,
                true,
                true,
            ));
        }
    }

    #[test]
    fn workspace_roots_request_stays_serialized() {
        assert!(!should_request_workspace_roots(
            Some("notifications/roots/list_changed"),
            true,
            true,
            true,
            true,
        ));
        assert!(!should_request_workspace_roots(
            Some("tools/list"),
            true,
            true,
            true,
            true,
        ));
    }

    #[test]
    fn workspace_roots_request_requires_capability_binder_and_unbound_daemon() {
        let trigger = Some("tools/list");
        assert!(!should_request_workspace_roots(
            trigger, false, false, true, true,
        ));
        assert!(!should_request_workspace_roots(
            trigger, true, false, false, true,
        ));
        assert!(!should_request_workspace_roots(
            trigger, true, false, true, false,
        ));
        assert!(!should_request_workspace_roots(
            Some("tools/call"),
            true,
            false,
            true,
            true,
        ));
    }
}
