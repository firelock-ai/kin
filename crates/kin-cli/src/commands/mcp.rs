// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use std::collections::HashSet;

/// `kin mcp start` — Start the MCP stdio server.
///
/// Starts a transport-only MCP server. Graph-backed tools are executed by the
/// repo daemon resolved through the supervisor route; MCP never loads or serves
/// a local graph snapshot in product mode.
pub async fn start() -> Result<()> {
    let daemon_url = if let Ok(url) = std::env::var("KIN_DAEMON_URL") {
        url
    } else {
        let cwd = std::env::current_dir()?;
        let layout = kin_core::KinLayout::discover(&cwd).ok_or_else(|| {
            anyhow::anyhow!("not a Kin repository (no .kin/ found); run `kin init .` first")
        })?;
        let url = crate::daemon_client::resolve_daemon_url_for_mcp(&layout)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Kin daemon is required for MCP startup but no daemon endpoint is available"
                )
            })?;
        std::env::set_var("KIN_DAEMON_URL", &url);
        url
    };
    eprintln!("{}", session_authority_notice());
    eprintln!("Kin MCP: forwarding graph tools to repo daemon at {daemon_url}");

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

    kin_mcp::run_stdio_daemon(config)
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
