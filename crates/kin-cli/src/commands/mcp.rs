// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use std::collections::HashSet;

/// `kin mcp start` — Start the MCP stdio server.
///
/// This launches the MCP (Model Context Protocol) server over stdin/stdout,
/// allowing assistants like Claude Code and Cursor to interact with the
/// Kin graph via JSON-RPC.
pub async fn start() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

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

    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let arc = snap.graph();
    drop(snap);
    let graph = std::sync::Arc::try_unwrap(arc)
        .map_err(|_| anyhow::anyhow!("KinDB graph has outstanding references"))?;
    kin_mcp::run_stdio(graph, config)
        .await
        .map_err(|e| anyhow::anyhow!("MCP server error: {}", e))?;

    Ok(())
}
