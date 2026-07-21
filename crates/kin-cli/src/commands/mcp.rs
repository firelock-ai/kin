// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

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

    let repo_override = resolve_repo_override(repo);
    if let Some(repo_dir) = &repo_override {
        if let Err(err) = std::env::set_current_dir(repo_dir) {
            eprintln!(
                "Kin MCP: --repo/KIN_MCP_REPO path {} could not be used as the working directory \
                 ({err}); continuing from the launch directory.",
                repo_dir.display()
            );
        }
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let bound_at_start = match bind_daemon_for_repo_dir(&cwd).await {
        Ok(daemon_url) => {
            eprintln!("{}", session_authority_notice());
            eprintln!("Kin MCP: forwarding graph tools to repo daemon at {daemon_url}");
            true
        }
        Err(reason) => {
            eprintln!(
                "Kin MCP: no repository bound at startup ({reason}). If the MCP client advertises \
                 workspace roots, Kin binds to the open repository after initialization; otherwise \
                 run `kin init .`, relaunch inside a Kin repository, or pass --repo <path> (or set \
                 KIN_MCP_REPO=<path>)."
            );
            false
        }
    };

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

    // The stdio server always binds through the MCP client's advertised
    // workspace roots: late, when nothing bound from --repo/KIN_MCP_REPO/cwd
    // (how editors that launch MCP servers from $HOME — Cursor, Windsurf, ... —
    // reach the open repo), and again whenever the client reports that its
    // workspace changed, so a window that moves to another folder does not keep
    // being answered from the folder it left.
    //
    // An explicit --repo/KIN_MCP_REPO that bound successfully is an operator
    // decision that workspace roots must not quietly overrule, so that pin never
    // follows the client to another repository. It still refuses to answer for
    // one: the binder reports the disagreement and the server fails loud, rather
    // than serving the pinned repository's graph for a workspace the client
    // moved away from.
    let pinned_by_operator = repo_override.is_some() && bound_at_start;
    let repo_binder: Option<kin_mcp::RepoBinder> = Some(Box::new(
        move |roots: Vec<PathBuf>| -> Pin<Box<dyn Future<Output = Option<kin_mcp::BoundRepo>> + Send>> {
            Box::pin(bind_first_kin_repo(roots, pinned_by_operator))
        },
    ));

    kin_mcp::run_stdio_daemon(config, repo_binder)
        .await
        .map_err(|e| anyhow::anyhow!("MCP server error: {}", e))?;

    Ok(())
}

/// Bind — or re-bind — the repo daemon for the first workspace root that is a
/// Kin repository. Returns the bound repository and its daemon URL (and sets
/// `KIN_DAEMON_URL`), or `None` when none of the client's workspace roots is a
/// Kin repository whose daemon can be resolved.
///
/// Re-binding is the point as much as binding: an editor that moves its window
/// to another folder reports new roots, and a process that keeps its original
/// binding answers every later tool call from a repository the user has left.
/// When the roots still contain the bound repository this is a no-op that keeps
/// the running daemon; when they name a different one it repoints the process at
/// it; when nothing there can be bound it returns `None`, which the stdio server
/// turns into an explicit refusal.
///
/// `pinned_by_operator` marks a binding that came from an explicit
/// `--repo`/`KIN_MCP_REPO`. That pin is never repointed by the client — it is a
/// deliberate choice about which repository this server serves — so a workspace
/// that names a different repository returns `None` and fails loud instead of
/// following the client or, worse, answering from the pinned repository anyway.
async fn bind_first_kin_repo(
    roots: Vec<PathBuf>,
    pinned_by_operator: bool,
) -> Option<kin_mcp::BoundRepo> {
    bind_first_kin_repo_against(roots, bound_repo_working_dir(), pinned_by_operator).await
}

/// Core of [`bind_first_kin_repo`] with the currently bound repository as an
/// explicit input rather than a read of the process working directory, so the
/// same-repo/different-repo branch is testable without moving the cwd out from
/// under every other test in this binary.
async fn bind_first_kin_repo_against(
    roots: Vec<PathBuf>,
    bound_repo: Option<PathBuf>,
    pinned_by_operator: bool,
) -> Option<kin_mcp::BoundRepo> {
    // Force the real upward walk. `KinLayout::discover` short-circuits to
    // `<start>/.kin` whenever `KIN_DAEMON_URL` is set, so once a repository is
    // bound it would accept any directory — including one with no `.kin/` at
    // all — as the client's new repository.
    let candidates: Vec<PathBuf> = roots
        .iter()
        .filter_map(|root| kin_core::KinLayout::discover_with_daemon_url(root, None))
        .map(|layout| canonical_path(layout.working_dir()))
        .collect();
    let bound_repo_still_open = bound_repo.as_deref().is_some_and(|bound| {
        candidates
            .iter()
            .any(|candidate| candidate.as_path() == bound)
    });

    if bound_repo_still_open {
        // The client still has the bound repository open — anywhere in its
        // workspace, not merely first. Keep the running daemon rather than
        // churning it because another folder happens to sort ahead of it.
        return bound_repo
            .zip(current_daemon_url())
            .map(|(root, daemon_url)| kin_mcp::BoundRepo { root, daemon_url });
    }

    if pinned_by_operator {
        // An explicit --repo/KIN_MCP_REPO names a repository the client is not
        // looking at. Following the client would overrule a deliberate operator
        // choice; serving the pinned repository anyway would answer about a
        // codebase the client left. Report neither, and let the server refuse.
        eprintln!(
            "Kin MCP: the repository pinned by --repo/KIN_MCP_REPO is not among the client's \
             workspace roots; refusing tool calls until the workspace and the pin agree."
        );
        return None;
    }

    if bound_repo.is_some() {
        // The workspace moved off the bound repository. Drop the pin so daemon
        // resolution binds the new one instead of returning the one being left.
        // Deliberately not restored if binding fails below: falling back to the
        // previous repository is exactly the wrong-repo answer this path
        // prevents, so failure must leave the process unbound and failing loud.
        std::env::remove_var("KIN_DAEMON_URL");
    }

    for working_dir in candidates {
        let Ok(url) = bind_daemon_for_repo_dir(&working_dir).await else {
            continue;
        };
        // Point the process at the bound repo so the daemon delegate resolves
        // the per-install loopback auth token from <root>/.kin/daemon.token,
        // exactly as the --repo startup path does (it set_current_dir's first).
        // Without this, tool-call forwarding sends no bearer token and the
        // daemon replies 401 even though the repo bound correctly.
        if let Err(err) = std::env::set_current_dir(&working_dir) {
            eprintln!(
                "Kin MCP: bound {url} but could not switch cwd to {} ({err}); \
                 tool auth will fall back to KIN_DAEMON_AUTH_TOKEN if set.",
                working_dir.display()
            );
        }
        eprintln!("{}", session_authority_notice());
        eprintln!(
            "Kin MCP: bound repo daemon at {url} from workspace root {}",
            working_dir.display()
        );
        return Some(kin_mcp::BoundRepo {
            root: working_dir,
            daemon_url: url,
        });
    }
    None
}

/// The repository this process is bound to, or `None` when it is not bound.
///
/// A binding exists only while a daemon URL is pinned, and the repository it
/// serves is the one containing the process working directory: every bind path
/// (`--repo`, `KIN_MCP_REPO`, the launch cwd, workspace roots) leaves the cwd
/// inside the bound repository. A `KIN_DAEMON_URL` pinned from outside while the
/// cwd is in no repository stays an explicit override — nothing to compare
/// roots against, so roots never repoint it.
fn bound_repo_working_dir() -> Option<PathBuf> {
    current_daemon_url()?;
    let cwd = std::env::current_dir().ok()?;
    kin_core::KinLayout::discover_with_daemon_url(&cwd, None)
        .map(|layout| canonical_path(layout.working_dir()))
}

fn current_daemon_url() -> Option<String> {
    std::env::var("KIN_DAEMON_URL")
        .ok()
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty())
}

/// Resolve symlinks so a client-supplied root and the process working directory
/// compare equal when they name the same repository (`/tmp` vs `/private/tmp`
/// on macOS, for one). Falls back to the path as given when it cannot be
/// canonicalized.
fn canonical_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
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
        bind_daemon_for_repo_dir, bind_first_kin_repo_against, build_mcp_start_config,
        resolve_repo_override, session_authority_notice, start,
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

    /// A directory that passes `KinLayout` discovery: a `.kin/` and nothing
    /// else, so nothing here can resolve a repo id or a running daemon.
    fn kin_repo_fixture() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join(".kin")).unwrap();
        tmp
    }

    #[tokio::test]
    #[serial]
    async fn roots_naming_the_bound_repo_keep_the_running_daemon() {
        // A redundant roots change (same folder still open) must not tear down
        // or re-resolve the binding.
        let _daemon_guard = EnvVarGuard::set("KIN_DAEMON_URL", "http://127.0.0.1:4242");
        let repo = kin_repo_fixture();
        let repo_dir = std::fs::canonicalize(repo.path()).unwrap();

        let bound = bind_first_kin_repo_against(
            vec![repo.path().to_path_buf()],
            Some(repo_dir.clone()),
            false,
        )
        .await
        .expect("the bound repository still being open must stay bound");

        assert_eq!(bound.root, repo_dir);
        assert_eq!(bound.daemon_url, "http://127.0.0.1:4242");
        assert_eq!(
            std::env::var("KIN_DAEMON_URL").ok().as_deref(),
            Some("http://127.0.0.1:4242"),
            "a no-op roots change must leave the pinned daemon alone"
        );
    }

    #[tokio::test]
    #[serial]
    async fn switching_to_an_unresolvable_repo_never_falls_back_to_the_old_one() {
        // The wrong-repo failure mode in miniature: the client moved to another
        // repository whose daemon cannot be resolved. Binding must end up
        // unbound and report failure, never silently keep serving the previous
        // repository's daemon.
        let _daemon_guard = EnvVarGuard::set("KIN_DAEMON_URL", "http://127.0.0.1:4242");
        // No autostart: this test must never spawn a daemon process.
        let _no_daemon_guard = EnvVarGuard::set("KIN_NO_DAEMON", "1");
        let previous = kin_repo_fixture();
        let switched_to = kin_repo_fixture();

        let bound = bind_first_kin_repo_against(
            vec![switched_to.path().to_path_buf()],
            Some(std::fs::canonicalize(previous.path()).unwrap()),
            false,
        )
        .await;

        assert!(
            bound.is_none(),
            "an unresolvable new repository must not report a successful bind"
        );
        assert_eq!(
            std::env::var("KIN_DAEMON_URL").ok().as_deref(),
            None,
            "the previous repository's daemon must not survive the switch"
        );
    }

    #[tokio::test]
    #[serial]
    async fn the_bound_repo_wins_wherever_it_sits_among_the_roots() {
        // A second folder opened alongside the bound one is not a switch. Root
        // order must not move a working binding.
        let _daemon_guard = EnvVarGuard::set("KIN_DAEMON_URL", "http://127.0.0.1:4242");
        let _no_daemon_guard = EnvVarGuard::set("KIN_NO_DAEMON", "1");
        let other = kin_repo_fixture();
        let bound = kin_repo_fixture();
        let bound_dir = std::fs::canonicalize(bound.path()).unwrap();

        let result = bind_first_kin_repo_against(
            vec![other.path().to_path_buf(), bound.path().to_path_buf()],
            Some(bound_dir.clone()),
            false,
        )
        .await
        .expect("the bound repository being open anywhere must keep the binding");

        assert_eq!(result.root, bound_dir);
        assert_eq!(result.daemon_url, "http://127.0.0.1:4242");
    }

    #[tokio::test]
    #[serial]
    async fn an_operator_pin_is_never_repointed_by_workspace_roots() {
        // --repo/KIN_MCP_REPO is a deliberate choice about which repository this
        // server serves. A roots change naming a different repository must
        // neither follow the client nor keep answering from the pin: it reports
        // failure so the stdio server refuses.
        let _daemon_guard = EnvVarGuard::set("KIN_DAEMON_URL", "http://127.0.0.1:4242");
        let _no_daemon_guard = EnvVarGuard::set("KIN_NO_DAEMON", "1");
        let pinned = kin_repo_fixture();
        let other = kin_repo_fixture();

        let bound = bind_first_kin_repo_against(
            vec![other.path().to_path_buf()],
            Some(std::fs::canonicalize(pinned.path()).unwrap()),
            true,
        )
        .await;

        assert!(
            bound.is_none(),
            "a pinned server must report failure for a workspace it does not serve"
        );
        assert_eq!(
            std::env::var("KIN_DAEMON_URL").ok().as_deref(),
            Some("http://127.0.0.1:4242"),
            "the operator's pin must survive a roots change it does not match"
        );
    }

    #[tokio::test]
    #[serial]
    async fn an_operator_pin_still_binds_when_the_roots_name_it() {
        let _daemon_guard = EnvVarGuard::set("KIN_DAEMON_URL", "http://127.0.0.1:4242");
        let pinned = kin_repo_fixture();
        let pinned_dir = std::fs::canonicalize(pinned.path()).unwrap();

        let bound = bind_first_kin_repo_against(
            vec![pinned.path().to_path_buf()],
            Some(pinned_dir.clone()),
            true,
        )
        .await
        .expect("roots naming the pinned repository must stay bound");

        assert_eq!(bound.root, pinned_dir);
        assert_eq!(bound.daemon_url, "http://127.0.0.1:4242");
    }

    #[tokio::test]
    #[serial]
    async fn roots_with_no_kin_repository_bind_nothing() {
        let _daemon_guard = EnvVarGuard::remove("KIN_DAEMON_URL");
        // No autostart: this test must never spawn a daemon process.
        let _no_daemon_guard = EnvVarGuard::set("KIN_NO_DAEMON", "1");
        let plain = tempfile::tempdir().unwrap();
        assert!(
            bind_first_kin_repo_against(vec![plain.path().to_path_buf()], None, false)
                .await
                .is_none()
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
