// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};

use kin_model::graph::GraphStore;
use std::collections::HashSet;

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
}

/// How the stdio server should present session authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAuthorityMode {
    /// The daemon is expected to own session state when reachable.
    DaemonFirst,
    /// The local in-process registry is only a fallback for offline/test use.
    OfflineFallback,
}

impl Default for McpServerConfig {
    fn default() -> Self {
        Self {
            server_name: "kin-mcp".into(),
            server_version: env!("CARGO_PKG_VERSION").into(),
            allowed_tools: None,
            session_authority_mode: SessionAuthorityMode::OfflineFallback,
        }
    }
}

/// Run the MCP server over stdio (stdin/stdout).
///
/// # Graph Staleness
///
/// The graph store `G` is loaded once and shared for the server's lifetime.
/// Because `GraphStore` is a read-only trait with no `reload()` method, the
/// server cannot hot-swap the underlying snapshot. If the kin-daemon commits
/// new generations while this server is running, query results will drift.
///
/// Mitigation:
/// - **Generation tracking:** When `config.generation_file` is set, the server
///   reads `.kin/kindb/generation` every 10 tool calls and logs a warning if
///   the on-disk generation has advanced past the loaded snapshot.
/// - **`kin_graph_status` tool:** Clients can call this tool to check entity
///   count and see a staleness advisory.
/// - **Restart to reload:** The definitive fix is to restart the MCP server,
///   which reloads the snapshot from disk.
pub async fn run_stdio<G: GraphStore + 'static>(store: G, config: McpServerConfig) -> Result<()> {
    let sessions = SessionRegistry::new();
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let reader = BufReader::new(stdin);
    let mut reader = reader;

    tracing::info!("kin-mcp stdio server starting");
    match config.session_authority_mode {
        SessionAuthorityMode::DaemonFirst => {
            tracing::info!(
                "kin-mcp session authority: daemon-first, with local registry as offline fallback"
            );
        }
        SessionAuthorityMode::OfflineFallback => {
            tracing::info!(
                "kin-mcp session authority: offline fallback, local registry is authoritative for this run"
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
pub async fn process_message<G: GraphStore>(
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
        "tools/call" => Some(
            handle_tools_call(id, &request.params, store, sessions, config).await,
        ),
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

async fn handle_tools_call<G: GraphStore>(
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

        match handle_tool_call(
            &call_params.name,
            &call_params.arguments,
            store,
            sessions,
            config.session_authority_mode,
        )
        .await
        {
        Ok(result) => {
            JsonRpcResponse::success(id, serde_json::to_value(&result).unwrap_or_default())
        }
        Err(e) => {
            let error_result = ToolCallResult::error(e.to_string());
            JsonRpcResponse::success(id, serde_json::to_value(&error_result).unwrap_or_default())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::branch::Branch;
    use kin_db::InMemoryGraph;

    #[tokio::test]
    async fn process_initialize() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let resp = process_message(msg, &store, &config, &sessions).await.unwrap();
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
        let resp = process_message(msg, &store, &config, &sessions).await.unwrap();
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
        let resp = process_message(msg, &store, &config, &sessions).await.unwrap();
        let result = resp.result.unwrap();
        assert!(result.get("_warning").is_none());
    }

    #[tokio::test]
    async fn process_tools_list() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
        let resp = process_message(msg, &store, &config, &sessions).await.unwrap();
        assert!(resp.result.is_some());

        let tools = &resp.result.unwrap()["tools"];
        assert!(tools.is_array());
        assert!(!tools.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn process_tools_call_semantic_search() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"semantic_search","arguments":{"query":"foo"}}}"#;
        let resp = process_message(msg, &store, &config, &sessions).await.unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn process_tools_call_register_session() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"register_session","arguments":{"assistant_name":"claude-code","session_id":"test-123"}}}"#;
        let resp = process_message(msg, &store, &config, &sessions).await.unwrap();
        assert!(resp.result.is_some());
        assert_eq!(sessions.count(), 1);
    }

    #[tokio::test]
    async fn process_unknown_method() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":5,"method":"unknown/method","params":{}}"#;
        let resp = process_message(msg, &store, &config, &sessions).await.unwrap();
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[tokio::test]
    async fn process_invalid_json() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let resp = process_message("not json", &store, &config, &sessions).await.unwrap();
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32700);
    }

    #[tokio::test]
    async fn process_ping() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = InMemoryGraph::default();

        let msg = r#"{"jsonrpc":"2.0","id":6,"method":"ping","params":{}}"#;
        let resp = process_message(msg, &store, &config, &sessions).await.unwrap();
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
