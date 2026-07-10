// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// `kin mcp start` — Start the MCP stdio server.
///
/// Starts a transport-only MCP server. Graph-backed tools are executed by the
/// repo daemon resolved through the supervisor route; MCP never loads or serves
/// a local graph snapshot in product mode.
///
/// Never hard-exits on a missing repository or an unreachable daemon: an agent
/// CLI that launches this as a global MCP entry from a non-Kin directory must
/// still get a working `initialize`/`tools/list` handshake, not a dead process
/// before the handshake. When no repository can be bound at startup, the
/// server starts anyway and each `tools/call` fails loud with a structured,
/// actionable error (see `kin_mcp::daemon_delegate::daemon_unavailable_tool_result`)
/// instead of the process silently never having started at all.
pub async fn start(global: bool, repo: Option<PathBuf>) -> Result<()> {
    if global {
        anyhow::bail!(
            "`kin mcp start --global` (multi-repo registry mode) is not yet implemented.\n\
             Omit --global to start in single-repo mode, or set KIN_DAEMON_URL to a running daemon."
        );
    }

    if let Some(repo_dir) = resolve_repo_override(repo) {
        if let Err(err) = std::env::set_current_dir(&repo_dir) {
            eprintln!(
                "Kin MCP: --repo/KIN_MCP_REPO path {} could not be used as the working directory \
                 ({err}); continuing from the launch directory.",
                repo_dir.display()
            );
        }
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    match bind_daemon_for_repo_dir(&cwd).await {
        Ok(daemon_url) => {
            eprintln!("{}", session_authority_notice());
            eprintln!("Kin MCP: forwarding graph tools to repo daemon at {daemon_url}");
        }
        Err(reason) => {
            eprintln!(
                "Kin MCP: starting without a bound Kin repository ({reason}). Tool calls will \
                 return a structured error until a repository is bound: run `kin init .`, \
                 relaunch this MCP server with its working directory inside a Kin repository, or \
                 pass --repo <path> (or set KIN_MCP_REPO=<path>)."
            );
        }
    }

    let mut config = build_mcp_start_config();
    let profile_tools: Option<&'static [&'static str]> =
        match std::env::var("KIN_MCP_TOOL_PROFILE").ok().as_deref() {
            Some("agent-default") => Some(kin_mcp::agent_default_tool_names()),
            Some("benchmark") => Some(kin_mcp::benchmark_tool_names()),
            // Read-only graph-native ContextBench belt: no write-side session/
            // transaction tools and no filesystem tools (none exist) — the
            // purely graph-native arm.
            Some("context-bench") => Some(kin_mcp::context_bench_tool_names()),
            _ => None,
        };
    if let Some(names) = profile_tools {
        config.allowed_tools = Some(
            names
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
    kin_mcp::McpServerConfig {
        session_authority_mode: kin_mcp::SessionAuthorityMode::DaemonRequired,
        snapshot_path: None,
        ..Default::default()
    }
}

/// Resolve an explicit repository override for MCP startup: an explicit
/// `--repo` flag wins, then `KIN_MCP_REPO`. Returns `None` when neither is
/// set, in which case MCP binds whatever repository (if any) contains the
/// launching process's working directory — the pre-existing behavior for a
/// per-repo MCP entry.
///
/// This is the fix-shape the agent-global wiring case needs: a global agent
/// CLI MCP entry always launches with cwd at the session's project directory,
/// which is frequently not a Kin repository at all (an umbrella workspace
/// root, brownfield code before `kin init`, etc). Pointing that entry at
/// --repo/KIN_MCP_REPO lets it bind a specific repository regardless of cwd.
fn resolve_repo_override(repo_arg: Option<PathBuf>) -> Option<PathBuf> {
    repo_arg.or_else(|| std::env::var_os("KIN_MCP_REPO").map(PathBuf::from))
}

/// Resolve (autostarting if needed) the repo daemon for `dir` and pin
/// `KIN_DAEMON_URL` so the stdio server's per-call tool forwarding routes to
/// it. Returns a human-readable reason on failure instead of propagating a
/// hard error: `kin mcp start` must always reach the stdio loop so
/// `initialize`/`tools/list` succeed even when no repository is bound yet,
/// with individual `tools/call` requests failing loud instead.
async fn bind_daemon_for_repo_dir(dir: &Path) -> std::result::Result<String, String> {
    if let Ok(url) = std::env::var("KIN_DAEMON_URL") {
        if !url.trim().is_empty() {
            return Ok(url);
        }
    }
    let layout = kin_core::KinLayout::discover(dir).ok_or_else(|| {
        "not inside a kin repository (no .kin/ found); run `kin init .` first".to_string()
    })?;
    let url = crate::daemon_client::resolve_daemon_url_for_mcp(&layout)
        .await
        .map_err(|e| format!("{e:#}"))?
        .ok_or_else(|| {
            "Kin daemon is required for MCP startup but no daemon endpoint is available".to_string()
        })?;
    std::env::set_var("KIN_DAEMON_URL", &url);
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::{
        bind_daemon_for_repo_dir, build_mcp_start_config, resolve_repo_override,
        session_authority_notice, start,
    };
    use serial_test::serial;
    use std::path::PathBuf;

    /// RAII guard that saves and restores a single env var around a test, so
    /// tests that mutate process-global env state (unavoidable — cwd/env are
    /// how `kin mcp start` binds its repo) don't leak into other tests in this
    /// binary.
    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

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

    #[tokio::test]
    async fn global_flag_returns_clear_error() {
        let err = start(true, None).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not yet implemented"),
            "unexpected message: {msg}"
        );
        assert!(msg.contains("--global"), "missing flag hint: {msg}");
    }

    #[test]
    #[serial]
    fn repo_override_prefers_explicit_flag_over_env() {
        let _guard = EnvVarGuard::set("KIN_MCP_REPO", "/env/path");
        let resolved = resolve_repo_override(Some(PathBuf::from("/flag/path")));
        assert_eq!(resolved, Some(PathBuf::from("/flag/path")));
    }

    #[test]
    #[serial]
    fn repo_override_falls_back_to_env_var() {
        let _guard = EnvVarGuard::set("KIN_MCP_REPO", "/env/path");
        let resolved = resolve_repo_override(None);
        assert_eq!(resolved, Some(PathBuf::from("/env/path")));
    }

    #[test]
    #[serial]
    fn repo_override_none_when_neither_flag_nor_env_set() {
        let _guard = EnvVarGuard::remove("KIN_MCP_REPO");
        assert_eq!(resolve_repo_override(None), None);
    }

    // Serialized against every other test that mutates the process-global
    // `KIN_DAEMON_URL` (its sibling below, and the init bootstrap test) so a
    // concurrent set/remove from another test can never be observed mid-body.
    #[tokio::test]
    #[serial]
    async fn bind_daemon_reports_missing_repo_without_hard_error() {
        // A directory with no .kin/ must produce an `Err` reason string for
        // the caller to log, never a panic or a process-killing error
        // propagated out of `start`.
        let _daemon_guard = EnvVarGuard::remove("KIN_DAEMON_URL");
        let tmp = tempfile::tempdir().unwrap();
        let reason = bind_daemon_for_repo_dir(tmp.path())
            .await
            .expect_err("a directory with no .kin/ must not resolve a daemon");
        assert!(
            reason.contains("not inside a kin repository"),
            "unexpected reason: {reason}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn bind_daemon_short_circuits_on_explicit_daemon_url() {
        // When KIN_DAEMON_URL is already set (e.g. by a supervising session),
        // binding must trust it directly rather than requiring a local .kin/
        // — this is the existing multi-process pinning contract and must
        // survive the lazy-binding rework unchanged.
        let _guard = EnvVarGuard::set("KIN_DAEMON_URL", "http://127.0.0.1:4242");
        let tmp = tempfile::tempdir().unwrap();
        let url = bind_daemon_for_repo_dir(tmp.path())
            .await
            .expect("an explicit KIN_DAEMON_URL must be trusted without repo discovery");
        assert_eq!(url, "http://127.0.0.1:4242");
    }
}
