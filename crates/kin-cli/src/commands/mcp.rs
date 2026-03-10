use anyhow::Result;

/// `kin mcp start` — Start the MCP stdio server.
///
/// This launches the MCP (Model Context Protocol) server over stdin/stdout,
/// allowing assistants like Claude Code and Cursor to interact with the
/// Kin graph via JSON-RPC.
pub async fn start() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;
    let config = kin_mcp::McpServerConfig::default();

    kin_mcp::run_stdio(graph, config)
        .await
        .map_err(|e| anyhow::anyhow!("MCP server error: {}", e))?;

    Ok(())
}
