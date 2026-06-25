// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Machine-readable first-run health engine.
//!
//! [`run_health_checks`] probes the real filesystem, daemon, and agent
//! configuration and returns a [`HealthReport`]. It is the single source of
//! truth behind `kin setup status [--json]` and `kin doctor [--fix]`.

use std::env;
use std::path::PathBuf;

use serde_json::Value;

use crate::commands::auth::default_base_url_for_health;
use crate::commands::setup::{
    check_binary_in_path, detect_shell, hook_filename, kin_dir, shell_rc, shim_filename,
};

/// Outcome of a single probed health check.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Missing,
    Stale,
    Misconfigured,
    Unsupported,
}

/// A single probed health check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthCheck {
    pub id: String,
    pub label: String,
    pub status: HealthStatus,
    pub detail: String,
    pub platform_note: Option<String>,
    pub fixable: bool,
    pub manual_fix: Option<String>,
}

/// Aggregated report across every health check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HealthReport {
    pub platform: String,
    pub checks: Vec<HealthCheck>,
    pub healthy: bool,
}

impl HealthCheck {
    fn new(id: &str, label: &str, status: HealthStatus, detail: impl Into<String>) -> Self {
        Self {
            id: id.to_string(),
            label: label.to_string(),
            status,
            detail: detail.into(),
            platform_note: None,
            fixable: false,
            manual_fix: None,
        }
    }

    fn with_platform_note(mut self, note: impl Into<String>) -> Self {
        self.platform_note = Some(note.into());
        self
    }

    fn fixable(mut self) -> Self {
        self.fixable = true;
        self
    }

    fn with_manual_fix(mut self, fix: impl Into<String>) -> Self {
        self.manual_fix = Some(fix.into());
        self
    }
}

fn is_failing(status: &HealthStatus) -> bool {
    matches!(status, HealthStatus::Missing | HealthStatus::Misconfigured)
}

/// A pass/attention/skip tally over a set of checks, used for the one-line
/// readiness summary printed by `kin doctor` and `kin setup status`.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct HealthSummary {
    /// Checks that are Healthy.
    pub passed: usize,
    /// Checks that need attention (Missing, Misconfigured, or Stale).
    pub attention: usize,
    /// Checks that do not apply on this platform / context (Unsupported).
    pub skipped: usize,
}

impl HealthReport {
    /// Tally checks into pass / needs-attention / not-applicable buckets.
    pub fn summary(&self) -> HealthSummary {
        let mut summary = HealthSummary {
            passed: 0,
            attention: 0,
            skipped: 0,
        };
        for check in &self.checks {
            match check.status {
                HealthStatus::Healthy => summary.passed += 1,
                HealthStatus::Unsupported => summary.skipped += 1,
                HealthStatus::Missing | HealthStatus::Misconfigured | HealthStatus::Stale => {
                    summary.attention += 1
                }
            }
        }
        summary
    }
}

/// Run every health check and assemble the report.
///
/// This is the single source of truth consumed by the CLI, editor, and
/// hosted UI. Every check reflects real probed state — nothing is assumed
/// healthy.
pub async fn run_health_checks() -> HealthReport {
    let mut checks = vec![
        check_kin_binary(),
        check_kin_daemon_binary(),
        check_daemon_running().await,
        check_vfs_projection(),
        check_repo_init(),
        check_shell_path(),
    ];
    checks.extend(check_mcp_clients());
    checks.push(check_editor());
    checks.push(check_kinlab_connect());
    checks.push(check_semantic_query_readiness().await);

    let healthy = !checks.iter().any(|c| is_failing(&c.status));

    HealthReport {
        platform: env::consts::OS.to_string(),
        checks,
        healthy,
    }
}

fn check_kin_binary() -> HealthCheck {
    let version = env!("CARGO_PKG_VERSION");
    match env::current_exe() {
        Ok(exe) => HealthCheck::new(
            "kin_binary",
            "kin binary",
            HealthStatus::Healthy,
            format!("v{version} ({})", exe.display()),
        ),
        Err(e) => HealthCheck::new(
            "kin_binary",
            "kin binary",
            HealthStatus::Missing,
            format!("could not resolve current executable: {e}"),
        ),
    }
}

/// Resolve the `kin-daemon` binary using the same search order as
/// `daemon_client::find_daemon_binary`: sibling of the current exe, the
/// cargo target dir (when running from `deps/`), then PATH.
fn resolve_daemon_binary() -> Option<PathBuf> {
    if let Ok(exe) = env::current_exe() {
        let sibling = exe.with_file_name("kin-daemon");
        if sibling.exists() {
            return Some(sibling);
        }
        if exe
            .parent()
            .and_then(|path| path.file_name())
            .is_some_and(|name| name == "deps")
        {
            if let Some(target_dir) = exe.parent().and_then(|path| path.parent()) {
                let target_sibling = target_dir.join("kin-daemon");
                if target_sibling.exists() {
                    return Some(target_sibling);
                }
            }
        }
    }
    check_binary_in_path("kin-daemon")
}

fn check_kin_daemon_binary() -> HealthCheck {
    match resolve_daemon_binary() {
        Some(path) => HealthCheck::new(
            "kin_daemon_binary",
            "kin-daemon binary",
            HealthStatus::Healthy,
            format!("found ({})", path.display()),
        ),
        None => HealthCheck::new(
            "kin_daemon_binary",
            "kin-daemon binary",
            HealthStatus::Missing,
            "not found beside the kin binary or on PATH",
        )
        .with_manual_fix("reinstall Kin so kin-daemon is installed alongside kin"),
    }
}

/// Probe whether the daemon is actually *running* (reachable) for the current
/// repository — distinct from [`check_kin_daemon_binary`], which only confirms
/// the binary is installed.
///
/// Outside a Kin repository there is no repo-scoped daemon to probe, so this is
/// reported as Unsupported rather than a failure. Inside a repo, a daemon that
/// is not reachable is reported as Stale (recoverable): any `kin` command in the
/// repo auto-starts it, so it is not a hard first-run blocker.
async fn check_daemon_running() -> HealthCheck {
    let cwd = env::current_dir().unwrap_or_default();
    let layout = match kin_core::KinLayout::discover(&cwd) {
        Some(l) => l,
        None => {
            return HealthCheck::new(
                "daemon_running",
                "kin-daemon running",
                HealthStatus::Unsupported,
                "n/a — not in a Kin repository (the daemon is repo-scoped)",
            )
            .with_manual_fix(
                "cd into a Kin repository, then run any `kin` command to start its daemon",
            );
        }
    };

    let repo = layout.working_dir().display().to_string();
    match crate::daemon_client::resolve_daemon_url_if_running_async(&layout).await {
        Some(url) => HealthCheck::new(
            "daemon_running",
            "kin-daemon running",
            HealthStatus::Healthy,
            format!("daemon reachable for {repo} ({url})"),
        ),
        None => HealthCheck::new(
            "daemon_running",
            "kin-daemon running",
            HealthStatus::Stale,
            format!("no daemon reachable for {repo} — it auto-starts on first use"),
        )
        .fixable()
        .with_manual_fix("run any `kin` command in the repo to auto-start the daemon"),
    }
}

fn check_vfs_projection() -> HealthCheck {
    if cfg!(target_os = "windows") {
        return HealthCheck::new(
            "vfs_projection",
            "VFS projection",
            HealthStatus::Unsupported,
            "Windows uses ProjFS, which is not shell-auto-injected",
        )
        .with_platform_note(
            "Windows projection uses ProjFS (planned), enabled via the optional \
             feature and started by an explicit daemon init — it is not injected \
             by the shell hook like the macOS/Linux shim.",
        )
        .with_manual_fix(
            "Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart",
        );
    }

    let lib_path = match kin_dir() {
        Ok(dir) => dir.join("lib").join(shim_filename()),
        Err(e) => {
            return HealthCheck::new(
                "vfs_projection",
                "VFS projection",
                HealthStatus::Missing,
                format!("could not resolve ~/.kin: {e}"),
            );
        }
    };

    let size = lib_path.metadata().map(|m| m.len()).unwrap_or(0);
    if lib_path.exists() && size > 0 {
        HealthCheck::new(
            "vfs_projection",
            "VFS projection",
            HealthStatus::Healthy,
            format!("shim installed ({} bytes, {})", size, lib_path.display()),
        )
    } else if lib_path.exists() {
        HealthCheck::new(
            "vfs_projection",
            "VFS projection",
            HealthStatus::Misconfigured,
            format!(
                "shim is 0 bytes ({}) — a 0-byte injected library crashes processes",
                lib_path.display()
            ),
        )
        .with_manual_fix(format!("rm {} && kin setup", lib_path.display()))
    } else {
        HealthCheck::new(
            "vfs_projection",
            "VFS projection",
            HealthStatus::Missing,
            format!("shim not installed at {}", lib_path.display()),
        )
        .with_manual_fix("run `kin setup` (builds/copies the VFS shim into ~/.kin/lib)")
    }
}

fn check_repo_init() -> HealthCheck {
    let cwd = env::current_dir().unwrap_or_default();
    match kin_core::KinLayout::discover(&cwd) {
        Some(layout) => HealthCheck::new(
            "repo_init",
            "Repository",
            HealthStatus::Healthy,
            format!("Kin repository at {}", layout.root().display()),
        ),
        None => HealthCheck::new(
            "repo_init",
            "Repository",
            HealthStatus::Missing,
            "current directory is not inside a Kin repository",
        )
        .with_manual_fix("run `kin init .` to initialize a repository here"),
    }
}

fn check_shell_path() -> HealthCheck {
    let shell = detect_shell();

    let kin_home = match kin_dir() {
        Ok(dir) => dir,
        Err(e) => {
            return HealthCheck::new(
                "shell_path",
                "Shell integration",
                HealthStatus::Missing,
                format!("could not resolve ~/.kin: {e}"),
            )
            .fixable();
        }
    };

    let bin_dir = kin_home.join("bin");
    let on_path = env::var_os("PATH")
        .map(|paths| env::split_paths(&paths).any(|p| p == bin_dir))
        .unwrap_or(false);

    let hook_path = kin_home.join("shell").join(hook_filename(shell));
    let hook_installed = hook_path.exists();

    let rc_path = shell_rc(shell).ok();
    let rc_sources = rc_path
        .as_ref()
        .map(|rc| {
            std::fs::read_to_string(rc)
                .map(|c| c.contains("kin-vfs"))
                .unwrap_or(false)
        })
        .unwrap_or(false);

    let rc_display = rc_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<unknown>".to_string());

    if hook_installed && rc_sources {
        let detail = if on_path {
            format!("{shell} hook installed and sourced from {rc_display}; ~/.kin/bin on PATH")
        } else {
            format!("{shell} hook installed and sourced from {rc_display}")
        };
        HealthCheck::new(
            "shell_path",
            "Shell integration",
            HealthStatus::Healthy,
            detail,
        )
        .fixable()
    } else {
        let mut missing = Vec::new();
        if !hook_installed {
            missing.push(format!("hook missing at {}", hook_path.display()));
        }
        if !rc_sources {
            missing.push(format!("{rc_display} does not source the kin-vfs hook"));
        }
        HealthCheck::new(
            "shell_path",
            "Shell integration",
            HealthStatus::Misconfigured,
            format!("{shell}: {}", missing.join("; ")),
        )
        .fixable()
        .with_manual_fix("run `kin setup` (or `kin doctor --fix`) to reinstall the shell hook")
    }
}

/// Path + detection metadata for one AI client's MCP config file.
struct McpClient {
    id: &'static str,
    label: &'static str,
    path: PathBuf,
}

pub(crate) fn mcp_client_config_paths() -> Vec<(&'static str, &'static str, PathBuf)> {
    let home = directories::BaseDirs::new().map(|d| d.home_dir().to_path_buf());
    let home = match home {
        Some(h) => h,
        None => return Vec::new(),
    };
    vec![
        (
            "claude",
            "Claude Code",
            // Prefer ~/.claude.json, falling back to ~/.claude/config.json.
            {
                let primary = home.join(".claude.json");
                let alt = home.join(".claude").join("config.json");
                if alt.exists() && !primary.exists() {
                    alt
                } else {
                    primary
                }
            },
        ),
        ("cursor", "Cursor", home.join(".cursor").join("mcp.json")),
        ("codex", "Codex CLI", home.join(".codex").join("mcp.json")),
        (
            "gemini",
            "Gemini CLI",
            home.join(".gemini").join("settings.json"),
        ),
        (
            "windsurf",
            "Windsurf",
            home.join(".codeium")
                .join("windsurf")
                .join("mcp_config.json"),
        ),
    ]
}

/// Inspect a single MCP config file for a `kin` server entry carrying the
/// agent-default tool profile.
pub(crate) fn evaluate_mcp_client(path: &PathBuf) -> (HealthStatus, String) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => {
            return (
                HealthStatus::Missing,
                format!("no config file at {}", path.display()),
            )
        }
    };
    let root: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return (
                HealthStatus::Misconfigured,
                format!("{} is not valid JSON: {e}", path.display()),
            )
        }
    };
    let kin_entry = root.get("mcpServers").and_then(|s| s.get("kin"));
    match kin_entry {
        None => (
            HealthStatus::Missing,
            format!("no mcpServers.kin entry in {}", path.display()),
        ),
        Some(entry) => {
            let profile = entry
                .get("env")
                .and_then(|e| e.get("KIN_MCP_TOOL_PROFILE"))
                .and_then(|p| p.as_str());
            if profile == Some("agent-default") {
                (
                    HealthStatus::Healthy,
                    format!(
                        "mcpServers.kin present with agent-default profile ({})",
                        path.display()
                    ),
                )
            } else {
                (
                    HealthStatus::Misconfigured,
                    format!(
                        "mcpServers.kin present but KIN_MCP_TOOL_PROFILE is {} (expected agent-default) in {}",
                        profile.unwrap_or("unset"),
                        path.display()
                    ),
                )
            }
        }
    }
}

fn check_mcp_clients() -> Vec<HealthCheck> {
    let clients: Vec<McpClient> = mcp_client_config_paths()
        .into_iter()
        .map(|(id, label, path)| McpClient { id, label, path })
        .filter(|c| c.path.exists())
        .collect();

    if clients.is_empty() {
        return vec![HealthCheck::new(
            "mcp_clients",
            "AI client MCP config",
            HealthStatus::Healthy,
            "no AI client config files detected — nothing to configure",
        )];
    }

    clients
        .into_iter()
        .map(|client| {
            let (status, detail) = evaluate_mcp_client(&client.path);
            let mut check = HealthCheck::new(
                &format!("mcp_client_{}", client.id),
                &format!("MCP: {}", client.label),
                status,
                detail,
            );
            if is_failing(&check.status) {
                check = check.fixable().with_manual_fix(
                    "run `kin setup` (or `kin doctor --fix`) to re-merge the kin MCP server entry",
                );
            }
            check
        })
        .collect()
}

fn check_editor() -> HealthCheck {
    let home = directories::BaseDirs::new().map(|d| d.home_dir().to_path_buf());
    let extensions_glob = home.as_ref().map(|h| h.join(".vscode").join("extensions"));

    let detected = extensions_glob
        .as_ref()
        .and_then(|dir| std::fs::read_dir(dir).ok())
        .map(|entries| {
            entries.filter_map(|e| e.ok()).any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .to_lowercase()
                    .contains("kin-editor")
            })
        })
        .unwrap_or(false);

    if detected {
        HealthCheck::new(
            "editor",
            "Editor extension",
            HealthStatus::Healthy,
            "kin-editor extension found in ~/.vscode/extensions",
        )
    } else {
        HealthCheck::new(
            "editor",
            "Editor extension",
            HealthStatus::Unsupported,
            "kin-editor extension not detected in ~/.vscode/extensions (cannot be \
             determined from the CLI for non-VS Code editors)",
        )
        .with_manual_fix("install the kin-editor VS Code extension (see the kin-editor README)")
    }
}

fn check_kinlab_connect() -> HealthCheck {
    let base_url = default_base_url_for_health();
    if crate::commands::auth::has_stored_credential(&base_url) {
        HealthCheck::new(
            "kinlab_connect",
            "KinLab connection",
            HealthStatus::Healthy,
            format!("stored credential present for {base_url}"),
        )
    } else {
        HealthCheck::new(
            "kinlab_connect",
            "KinLab connection",
            HealthStatus::Unsupported,
            format!("no stored credential for {base_url}"),
        )
        .with_platform_note("hosted connect is not yet a first-run flow")
        .with_manual_fix("run `kin auth login` once hosted connect is available")
    }
}

async fn check_semantic_query_readiness() -> HealthCheck {
    let cwd = env::current_dir().unwrap_or_default();
    let layout = match kin_core::KinLayout::discover(&cwd) {
        Some(l) => l,
        None => {
            return HealthCheck::new(
                "semantic_query_readiness",
                "Semantic query readiness",
                HealthStatus::Unsupported,
                "n/a — not in a Kin repository",
            );
        }
    };

    let daemon_url = crate::daemon_client::resolve_daemon_url_if_running_async(&layout).await;
    let Some(daemon_url) = daemon_url else {
        return HealthCheck::new(
            "semantic_query_readiness",
            "Semantic query readiness",
            HealthStatus::Missing,
            "daemon not reachable for this repository",
        )
        .with_manual_fix("run any `kin` command in the repo to auto-start the daemon");
    };

    let vector_index = layout.kindb_vector_index_path();
    let indexed = vector_index
        .metadata()
        .map(|m| m.len() > 0)
        .unwrap_or(false);

    if indexed {
        HealthCheck::new(
            "semantic_query_readiness",
            "Semantic query readiness",
            HealthStatus::Healthy,
            format!(
                "daemon reachable ({daemon_url}); vector index present at {}",
                vector_index.display()
            ),
        )
    } else {
        HealthCheck::new(
            "semantic_query_readiness",
            "Semantic query readiness",
            HealthStatus::Stale,
            format!("daemon reachable ({daemon_url}); no vector index yet — embeddings pending"),
        )
        .with_manual_fix("run `kin embed` to build the vector index")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn report_is_non_empty_and_serializes_with_ids() {
        let report = run_health_checks().await;
        assert!(!report.checks.is_empty());
        let json = serde_json::to_string(&report).expect("report serializes");
        assert!(json.contains("\"kin_binary\""));
        assert!(json.contains("\"kin_daemon_binary\""));
        assert!(json.contains("\"daemon_running\""));
        assert!(json.contains("\"vfs_projection\""));
        assert!(json.contains("\"shell_path\""));
        assert!(json.contains("\"platform\""));
        assert!(json.contains("\"healthy\""));
    }

    fn check_with(id: &str, status: HealthStatus) -> HealthCheck {
        HealthCheck::new(id, id, status, "")
    }

    #[test]
    fn summary_tallies_pass_attention_skip_buckets() {
        let report = HealthReport {
            platform: "test".to_string(),
            checks: vec![
                check_with("a", HealthStatus::Healthy),
                check_with("b", HealthStatus::Healthy),
                check_with("c", HealthStatus::Missing),
                check_with("d", HealthStatus::Misconfigured),
                check_with("e", HealthStatus::Stale),
                check_with("f", HealthStatus::Unsupported),
            ],
            healthy: false,
        };
        let summary = report.summary();
        assert_eq!(summary.passed, 2, "two Healthy checks pass");
        assert_eq!(
            summary.attention, 3,
            "Missing + Misconfigured + Stale need attention"
        );
        assert_eq!(summary.skipped, 1, "Unsupported is not applicable");
    }

    #[test]
    fn summary_buckets_sum_to_total_checks() {
        let report = HealthReport {
            platform: "test".to_string(),
            checks: vec![
                check_with("a", HealthStatus::Healthy),
                check_with("b", HealthStatus::Stale),
                check_with("c", HealthStatus::Unsupported),
            ],
            healthy: false,
        };
        let summary = report.summary();
        assert_eq!(
            summary.passed + summary.attention + summary.skipped,
            report.checks.len(),
            "every check lands in exactly one bucket"
        );
    }

    #[tokio::test]
    async fn daemon_running_check_is_present_and_never_hard_fails() {
        // The daemon-running probe is recoverable by construction: Healthy when
        // reachable, Stale when not started (auto-starts on use), Unsupported
        // outside a repo. It must never report Missing/Misconfigured, which
        // would make first-run readiness look broken when it is merely idle.
        // This holds regardless of the test's working directory, so no global
        // cwd mutation (which would race other tests) is needed.
        let daemon = check_daemon_running().await;
        assert_eq!(daemon.id, "daemon_running");
        assert!(
            !is_failing(&daemon.status),
            "daemon-running must not hard-fail; got {:?}",
            daemon.status
        );
        // When the daemon is not Healthy (Stale/Unsupported), there is always a
        // remediation hint so the user knows what to do.
        if !matches!(daemon.status, HealthStatus::Healthy) {
            assert!(
                daemon.manual_fix.is_some(),
                "non-healthy daemon-running must offer a remediation hint"
            );
        }
    }

    #[test]
    fn health_status_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&HealthStatus::Healthy).unwrap(),
            "\"healthy\""
        );
        assert_eq!(
            serde_json::to_string(&HealthStatus::Missing).unwrap(),
            "\"missing\""
        );
        assert_eq!(
            serde_json::to_string(&HealthStatus::Stale).unwrap(),
            "\"stale\""
        );
        assert_eq!(
            serde_json::to_string(&HealthStatus::Misconfigured).unwrap(),
            "\"misconfigured\""
        );
        assert_eq!(
            serde_json::to_string(&HealthStatus::Unsupported).unwrap(),
            "\"unsupported\""
        );
    }

    #[test]
    fn mcp_config_without_agent_default_profile_is_misconfigured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "kin": {
                        "command": "kin",
                        "args": ["mcp", "start", "--global"],
                        "env": {}
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let (status, _detail) = evaluate_mcp_client(&path);
        assert!(matches!(status, HealthStatus::Misconfigured));
    }

    #[test]
    fn mcp_config_with_agent_default_profile_is_healthy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": {
                    "kin": {
                        "command": "kin",
                        "args": ["mcp", "start", "--global"],
                        "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let (status, _detail) = evaluate_mcp_client(&path);
        assert!(matches!(status, HealthStatus::Healthy));
    }

    #[test]
    fn mcp_config_missing_file_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        let (status, _detail) = evaluate_mcp_client(&path);
        assert!(matches!(status, HealthStatus::Missing));
    }
}
