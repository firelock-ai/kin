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
    let layout = kin_core::KinLayout::discover(&cwd).ok_or_else(|| {
        anyhow::anyhow!("not a Kin repository (no .kin/ found); run `kin init .` first")
    })?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Kin daemon is required for MCP startup but no daemon endpoint is available"
            )
        })?;
    std::env::set_var("KIN_DAEMON_URL", &daemon_url);
    eprintln!("{}", session_authority_notice());
    let loaded = kin_mcp::load_stdio_graph_from_daemon().await?;

    eprintln!(
        "Kin MCP: {} primary entities, {} sibling repo(s), {} total entities",
        loaded.primary_entity_count,
        loaded.sibling_repo_count,
        loaded.graph.entity_count(),
    );

    let mut config = build_mcp_start_config();
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

fn session_authority_notice() -> &'static str {
    "Kin daemon detected: MCP graph and session authority are daemon-centered; local fallback is disabled for this run."
}

fn build_mcp_start_config() -> kin_mcp::McpServerConfig {
    let mut config = kin_mcp::McpServerConfig::default();
    config.session_authority_mode = kin_mcp::SessionAuthorityMode::DaemonRequired;
    config.snapshot_path = None;
    config
}

#[cfg(test)]
mod tests {
    use super::{build_mcp_start_config, session_authority_notice};

    #[test]
    fn daemon_available_notice_mentions_daemon_authority() {
        let message = session_authority_notice();
        assert!(message.contains("daemon-centered"));
        assert!(message.contains("disabled"));
    }

    #[test]
    fn daemon_required_disables_local_snapshot_bootstrap() {
        let config = build_mcp_start_config();
        assert_eq!(
            config.session_authority_mode,
            kin_mcp::SessionAuthorityMode::DaemonRequired
        );
        assert!(config.snapshot_path.is_none());
    }
}
