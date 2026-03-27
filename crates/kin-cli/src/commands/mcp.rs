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
    let daemon_available = kin_mcp::daemon_delegate::daemon_client().await.is_some();
    eprintln!("{}", session_authority_notice(daemon_available));
    let loaded = kin_mcp::load_stdio_graph(&cwd)?;

    eprintln!(
        "Kin MCP: {} primary entities, {} sibling repo(s), {} total entities",
        loaded.primary_entity_count,
        loaded.sibling_repo_count,
        loaded.graph.entity_count(),
    );

    let mut config = kin_mcp::McpServerConfig::default();
    config.session_authority_mode = if daemon_available {
        kin_mcp::SessionAuthorityMode::DaemonFirst
    } else {
        kin_mcp::SessionAuthorityMode::OfflineFallback
    };
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

fn session_authority_notice(daemon_available: bool) -> &'static str {
    if daemon_available {
        "Kin daemon detected: MCP session authority is daemon-centered; local session state is fallback only."
    } else {
        "Kin daemon unavailable: MCP will use local session fallback for session state."
    }
}

#[cfg(test)]
mod tests {
    use super::session_authority_notice;

    #[test]
    fn daemon_available_notice_mentions_daemon_authority() {
        let message = session_authority_notice(true);
        assert!(message.contains("daemon-centered"));
        assert!(message.contains("fallback only"));
    }

    #[test]
    fn offline_notice_mentions_local_fallback() {
        let message = session_authority_notice(false);
        assert!(message.contains("local session fallback"));
    }
}
