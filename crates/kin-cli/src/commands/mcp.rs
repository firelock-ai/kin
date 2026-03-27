// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use std::collections::HashSet;

/// `kin mcp start` — Start the MCP stdio server.
///
/// Loads the CWD repo's graph as primary, then merges entities and relations
/// from all sibling repos in `~/.kin/registry.toml` for cross-repo context.
pub async fn start() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let loaded = kin_mcp::load_stdio_graph(&cwd)?;

    eprintln!(
        "Kin MCP: {} primary entities, {} sibling repo(s), {} total entities",
        loaded.primary_entity_count,
        loaded.sibling_repo_count,
        loaded.graph.entity_count(),
    );

    let mut config = kin_mcp::McpServerConfig::default();
    if matches!(
        std::env::var("KIN_MCP_TOOL_PROFILE").ok().as_deref(),
        Some("benchmark")
    ) {
        config.allowed_tools = Some(
            kin_mcp::benchmark_tool_names()
                .iter()
                .map(|name| (*name).to_string())
                .collect::<HashSet<_>>(),
        );
    }

    kin_mcp::run_stdio(loaded.graph, config)
        .await
        .map_err(|e| anyhow::anyhow!("MCP server error: {}", e))?;

    Ok(())
}
