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
    let offline_fallback = std::env::var("KIN_NO_DAEMON").unwrap_or_default() == "1"
        || std::env::var("KIN_MCP_OFFLINE_FALLBACK").unwrap_or_default() == "1";
    let layout = kin_core::KinLayout::discover(&cwd);
    let daemon_url = if offline_fallback {
        None
    } else if let Some(layout) = &layout {
        match crate::daemon_client::resolve_daemon_url(layout).await? {
            Some(url) => {
                std::env::set_var("KIN_DAEMON_URL", &url);
                Some(url)
            }
            None => {
                anyhow::bail!(
                    "Kin daemon unavailable for MCP startup. Run `kin init .` if needed, or set KIN_MCP_OFFLINE_FALLBACK=1 for explicit local recovery."
                );
            }
        }
    } else {
        None
    };
    let daemon_available = daemon_url.is_some();
    eprintln!("{}", session_authority_notice(daemon_available));
    let loaded = if daemon_available {
        kin_mcp::load_stdio_graph_from_daemon().await?
    } else {
        kin_mcp::load_stdio_graph(&cwd)?
    };

    eprintln!(
        "Kin MCP: {} primary entities, {} sibling repo(s), {} total entities",
        loaded.primary_entity_count,
        loaded.sibling_repo_count,
        loaded.graph.entity_count(),
    );

    let snapshot_path = if daemon_available {
        None
    } else {
        kin_core::KinLayout::discover(&cwd).map(|layout| layout.kindb_snapshot_path())
    };
    let mut config = build_mcp_start_config(daemon_available, snapshot_path);
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
        "Kin daemon detected: MCP graph and session authority are daemon-centered; local fallback is disabled for this run."
    } else {
        "Kin daemon unavailable: MCP will use local session fallback for session state."
    }
}

fn build_mcp_start_config(
    daemon_available: bool,
    snapshot_path: Option<std::path::PathBuf>,
) -> kin_mcp::McpServerConfig {
    let mut config = kin_mcp::McpServerConfig::default();
    config.session_authority_mode = if daemon_available {
        kin_mcp::SessionAuthorityMode::DaemonRequired
    } else {
        kin_mcp::SessionAuthorityMode::OfflineFallback
    };
    config.snapshot_path = if daemon_available {
        None
    } else {
        snapshot_path
    };
    config
}

#[cfg(test)]
mod tests {
    use super::{build_mcp_start_config, session_authority_notice};

    #[test]
    fn daemon_available_notice_mentions_daemon_authority() {
        let message = session_authority_notice(true);
        assert!(message.contains("daemon-centered"));
        assert!(message.contains("disabled"));
    }

    #[test]
    fn offline_notice_mentions_local_fallback() {
        let message = session_authority_notice(false);
        assert!(message.contains("local session fallback"));
    }

    #[test]
    fn daemon_required_disables_local_snapshot_bootstrap() {
        let config = build_mcp_start_config(
            true,
            Some(std::path::PathBuf::from("/tmp/kin/.kin/kindb/graph.kndb")),
        );
        assert_eq!(
            config.session_authority_mode,
            kin_mcp::SessionAuthorityMode::DaemonRequired
        );
        assert!(config.snapshot_path.is_none());
    }

    #[test]
    fn offline_mode_keeps_snapshot_bootstrap() {
        let snapshot_path = Some(std::path::PathBuf::from("/tmp/kin/.kin/kindb/graph.kndb"));
        let config = build_mcp_start_config(false, snapshot_path.clone());
        assert_eq!(
            config.session_authority_mode,
            kin_mcp::SessionAuthorityMode::OfflineFallback
        );
        assert_eq!(config.snapshot_path, snapshot_path);
    }
}
