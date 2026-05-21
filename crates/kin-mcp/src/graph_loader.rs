// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use crate::{McpError, Result};

const MCP_BOOTSTRAP_PRIMARY_COUNT_HEADER: &str = "x-kin-primary-entity-count";
const MCP_BOOTSTRAP_SIBLING_COUNT_HEADER: &str = "x-kin-sibling-repo-count";

/// Loaded stdio graph state for `kin mcp start`.
pub struct StdioGraphLoad {
    pub graph: kin_db::InMemoryGraph,
    pub primary_entity_count: usize,
    pub sibling_repo_count: usize,
}

/// Load the daemon-authoritative MCP bootstrap graph.
pub async fn load_stdio_graph_from_daemon() -> Result<StdioGraphLoad> {
    let base_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            McpError::Other(
                "KIN_DAEMON_URL is required; start MCP through `kin mcp start` so the repo daemon is supervisor-routed"
                    .to_string(),
            )
        })?;
    let url = format!("{}/mcp/bootstrap", base_url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .map_err(|e| McpError::Other(format!("failed to fetch daemon MCP bootstrap: {e}")))?;

    if !response.status().is_success() {
        return Err(McpError::Other(format!(
            "daemon MCP bootstrap failed: HTTP {}",
            response.status()
        )));
    }

    let headers = response.headers().clone();
    let bytes = response
        .bytes()
        .await
        .map_err(|e| McpError::Other(format!("failed to read daemon MCP bootstrap body: {e}")))?;
    let snapshot = kin_db::GraphSnapshot::from_bytes(&bytes).map_err(|e| {
        McpError::Other(format!(
            "failed to decode daemon MCP bootstrap snapshot: {e}"
        ))
    })?;
    let graph = kin_db::InMemoryGraph::from_snapshot(snapshot);

    Ok(StdioGraphLoad {
        primary_entity_count: parse_count_header(&headers, MCP_BOOTSTRAP_PRIMARY_COUNT_HEADER)
            .unwrap_or_else(|| graph.entity_count()),
        sibling_repo_count: parse_count_header(&headers, MCP_BOOTSTRAP_SIBLING_COUNT_HEADER)
            .unwrap_or(0),
        graph,
    })
}

fn parse_count_header(headers: &reqwest::header::HeaderMap, name: &str) -> Option<usize> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
}
