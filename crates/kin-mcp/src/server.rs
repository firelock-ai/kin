// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};

use kin_model::graph::GraphStore;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::daemon_delegate;
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

/// Run the daemon-required MCP server over stdio.
///
/// This mode is intentionally graphless: every `tools/call` request is
/// forwarded to the repo daemon, which executes against its live graph and
/// session coordinator. The stdio process only handles JSON-RPC framing,
/// initialization, tool listing, allow-list checks, and transport errors.
pub async fn run_stdio_daemon(config: McpServerConfig) -> Result<()> {
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

    while let Some((message, framed)) = read_stdio_message(&mut reader).await? {
        if let Some(response) = process_daemon_message(&message, &config).await {
            let response_json = serde_json::to_string(&response).map_err(McpError::Json)?;
            write_stdio_message(&mut stdout, &response_json, framed).await?;
        }
    }

    tracing::info!("kin-mcp daemon-proxy stdio server shutting down");
    Ok(())
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
            return JsonRpcResponse::success(
                id,
                serde_json::to_value(&error_result).unwrap_or_default(),
            );
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
                    return JsonRpcResponse::success(
                        id,
                        serde_json::to_value(&error_result).unwrap_or_default(),
                    );
                }
            }
            JsonRpcResponse::success(id, serde_json::to_value(&result).unwrap_or_default())
        }
        Err(e) => {
            let error_result = ToolCallResult::error(e.to_string());
            JsonRpcResponse::success(id, serde_json::to_value(&error_result).unwrap_or_default())
        }
    }
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
            return JsonRpcResponse::success(
                id,
                serde_json::to_value(&error_result).unwrap_or_default(),
            );
        }
    }

    let result =
        match daemon_delegate::forward_tool_call(&call_params.name, &call_params.arguments).await {
            Ok(Some(result)) => result,
            Ok(None) => daemon_delegate::daemon_unavailable_tool_result(&call_params.name),
            Err(error) => ToolCallResult::error(error),
        };

    JsonRpcResponse::success(id, serde_json::to_value(&result).unwrap_or_default())
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
    use kin_db::InMemoryGraph;

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
}
