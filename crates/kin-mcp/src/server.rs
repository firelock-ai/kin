use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use kin_model::graph::GraphStore;

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
}

impl Default for McpServerConfig {
    fn default() -> Self {
        Self {
            server_name: "kin-mcp".into(),
            server_version: env!("CARGO_PKG_VERSION").into(),
        }
    }
}

/// Run the MCP server over stdio (stdin/stdout).
pub async fn run_stdio<G: GraphStore + 'static>(
    store: G,
    config: McpServerConfig,
) -> Result<()> {
    let sessions = SessionRegistry::new();
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    tracing::info!("kin-mcp stdio server starting");

    while let Some(line) = lines.next_line().await.map_err(McpError::Io)? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response = process_message(&line, &store, &config, &sessions);
        let response_json = serde_json::to_string(&response).map_err(McpError::Json)?;

        stdout
            .write_all(response_json.as_bytes())
            .await
            .map_err(McpError::Io)?;
        stdout.write_all(b"\n").await.map_err(McpError::Io)?;
        stdout.flush().await.map_err(McpError::Io)?;
    }

    tracing::info!("kin-mcp stdio server shutting down");
    Ok(())
}

/// Process a single JSON-RPC message and return a response.
pub fn process_message<G: GraphStore>(
    message: &str,
    store: &G,
    config: &McpServerConfig,
    sessions: &SessionRegistry,
) -> JsonRpcResponse {
    let request: JsonRpcRequest = match serde_json::from_str(message) {
        Ok(req) => req,
        Err(e) => {
            return JsonRpcResponse::error(
                None,
                -32700,
                format!("Parse error: {}", e),
            );
        }
    };

    let id = request.id.clone();

    match request.method.as_str() {
        "initialize" => handle_initialize(id, config),
        "initialized" => {
            // Notification, no response needed but we'll ack
            JsonRpcResponse::success(id, serde_json::json!({}))
        }
        "tools/list" => handle_tools_list(id),
        "tools/call" => handle_tools_call(id, &request.params, store, sessions),
        "ping" => JsonRpcResponse::success(id, serde_json::json!({})),
        _ => JsonRpcResponse::error(
            id,
            -32601,
            format!("Method not found: {}", request.method),
        ),
    }
}

fn handle_initialize(
    id: Option<serde_json::Value>,
    config: &McpServerConfig,
) -> JsonRpcResponse {
    let result = InitializeResult {
        protocol_version: "2024-11-05".into(),
        capabilities: ServerCapabilities {
            tools: ToolsCapability {
                list_changed: false,
            },
        },
        server_info: ServerInfo {
            name: config.server_name.clone(),
            version: config.server_version.clone(),
        },
    };

    JsonRpcResponse::success(
        id,
        serde_json::to_value(&result).unwrap_or_default(),
    )
}

fn handle_tools_list(id: Option<serde_json::Value>) -> JsonRpcResponse {
    let tools = tool_definitions();
    JsonRpcResponse::success(
        id,
        serde_json::to_value(&tools).unwrap_or_default(),
    )
}

fn handle_tools_call<G: GraphStore>(
    id: Option<serde_json::Value>,
    params: &serde_json::Value,
    store: &G,
    sessions: &SessionRegistry,
) -> JsonRpcResponse {
    let call_params: ToolCallParams = match serde_json::from_value(params.clone()) {
        Ok(p) => p,
        Err(e) => {
            return JsonRpcResponse::error(
                id,
                -32602,
                format!("Invalid params: {}", e),
            );
        }
    };

    match handle_tool_call(&call_params.name, &call_params.arguments, store, sessions) {
        Ok(result) => {
            JsonRpcResponse::success(
                id,
                serde_json::to_value(&result).unwrap_or_default(),
            )
        }
        Err(e) => {
            let error_result = ToolCallResult::error(e.to_string());
            JsonRpcResponse::success(
                id,
                serde_json::to_value(&error_result).unwrap_or_default(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::branch::Branch;
    use kin_model::change::SemanticChange;
    use kin_model::entity::Entity;
    use kin_model::graph::{EntityFilter, SubGraph};
    use kin_model::ids::*;
    use kin_model::relation::{Relation, RelationKind};

    struct EmptyStore;
    impl GraphStore for EmptyStore {
        type Error = std::io::Error;
        fn get_entity(&self, _: &EntityId) -> std::result::Result<Option<Entity>, Self::Error> { Ok(None) }
        fn get_relations(&self, _: &EntityId, _: &[RelationKind]) -> std::result::Result<Vec<Relation>, Self::Error> { Ok(vec![]) }
        fn get_all_relations_for_entity(&self, _: &EntityId) -> std::result::Result<Vec<Relation>, Self::Error> { Ok(vec![]) }
        fn get_downstream_impact(&self, _: &EntityId, _: u32) -> std::result::Result<Vec<Entity>, Self::Error> { Ok(vec![]) }
        fn get_dependency_neighborhood(&self, _: &EntityId, _: u32) -> std::result::Result<SubGraph, Self::Error> { Ok(SubGraph::default()) }
        fn find_dead_code(&self) -> std::result::Result<Vec<Entity>, Self::Error> { Ok(vec![]) }
        fn get_entity_history(&self, _: &EntityId) -> std::result::Result<Vec<SemanticChange>, Self::Error> { Ok(vec![]) }
        fn find_merge_bases(&self, _: &SemanticChangeId, _: &SemanticChangeId) -> std::result::Result<Vec<SemanticChangeId>, Self::Error> { Ok(vec![]) }
        fn query_entities(&self, _: &EntityFilter) -> std::result::Result<Vec<Entity>, Self::Error> { Ok(vec![]) }
        fn list_all_entities(&self) -> std::result::Result<Vec<Entity>, Self::Error> { Ok(vec![]) }
        fn upsert_entity(&self, _: &Entity) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn upsert_relation(&self, _: &Relation) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn remove_entity(&self, _: &EntityId) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn remove_relation(&self, _: &RelationId) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn create_change(&self, _: &SemanticChange) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn get_change(&self, _: &SemanticChangeId) -> std::result::Result<Option<SemanticChange>, Self::Error> { Ok(None) }
        fn get_changes_since(&self, _: &SemanticChangeId, _: &SemanticChangeId) -> std::result::Result<Vec<SemanticChange>, Self::Error> { Ok(vec![]) }
        fn get_branch(&self, _: &BranchName) -> std::result::Result<Option<Branch>, Self::Error> { Ok(None) }
        fn create_branch(&self, _: &Branch) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn update_branch_head(&self, _: &BranchName, _: &SemanticChangeId) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn delete_branch(&self, _: &BranchName) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn list_branches(&self) -> std::result::Result<Vec<Branch>, Self::Error> { Ok(vec![]) }
    }

    #[test]
    fn process_initialize() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = EmptyStore;

        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let resp = process_message(msg, &store, &config, &sessions);
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());

        let result = resp.result.unwrap();
        assert_eq!(result["serverInfo"]["name"], "kin-mcp");
    }

    #[test]
    fn process_tools_list() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = EmptyStore;

        let msg = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
        let resp = process_message(msg, &store, &config, &sessions);
        assert!(resp.result.is_some());

        let tools = &resp.result.unwrap()["tools"];
        assert!(tools.is_array());
        assert!(!tools.as_array().unwrap().is_empty());
    }

    #[test]
    fn process_tools_call_semantic_search() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = EmptyStore;

        let msg = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"semantic_search","arguments":{"query":"foo"}}}"#;
        let resp = process_message(msg, &store, &config, &sessions);
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn process_tools_call_register_session() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = EmptyStore;

        let msg = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"register_session","arguments":{"assistant_name":"claude-code","session_id":"test-123"}}}"#;
        let resp = process_message(msg, &store, &config, &sessions);
        assert!(resp.result.is_some());
        assert_eq!(sessions.count(), 1);
    }

    #[test]
    fn process_unknown_method() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = EmptyStore;

        let msg = r#"{"jsonrpc":"2.0","id":5,"method":"unknown/method","params":{}}"#;
        let resp = process_message(msg, &store, &config, &sessions);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[test]
    fn process_invalid_json() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = EmptyStore;

        let resp = process_message("not json", &store, &config, &sessions);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32700);
    }

    #[test]
    fn process_ping() {
        let config = McpServerConfig::default();
        let sessions = SessionRegistry::new();
        let store = EmptyStore;

        let msg = r#"{"jsonrpc":"2.0","id":6,"method":"ping","params":{}}"#;
        let resp = process_message(msg, &store, &config, &sessions);
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }
}
