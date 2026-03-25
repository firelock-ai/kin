// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use std::collections::HashSet;

/// `kin mcp start` — Start the MCP stdio server.
///
/// This launches the MCP (Model Context Protocol) server over stdin/stdout,
/// allowing assistants like Claude Code and Cursor to interact with the
/// Kin graph via JSON-RPC.
///
/// When `global` is true, the server operates in global mode — intended to
/// serve all repos registered in `~/.kin/registry.toml`.
pub async fn start(global: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let layout = match kin_core::KinLayout::discover(&cwd) {
        Some(l) => l,
        None => {
            // Auto-initialize so `kin mcp start` works in any directory.
            let init_result = kin_core::init(&cwd).map_err(|e| {
                anyhow::anyhow!(
                    "not a Kin repository and auto-init failed: {}\nhint: run `kin init .` to initialize manually",
                    e
                )
            })?;
            eprintln!("Auto-initialized Kin repository. Run `kin commit` to extract entities from source.");
            init_result.layout
        }
    };

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

    // Always check the global registry for sibling repos.
    // CWD repo is primary; siblings provide cross-repo context.
    let sibling_count = match kin_core::registry::KinRegistry::load() {
        Ok(reg) => {
            let count = reg.repos.len();
            if count > 1 {
                eprintln!(
                    "Kin MCP: primary repo + {} sibling(s) from global registry",
                    count - 1
                );
            }
            count
        }
        Err(_) => 0,
    };
    let _ = (global, sibling_count); // --global is always-on, flag kept for backwards compat

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
