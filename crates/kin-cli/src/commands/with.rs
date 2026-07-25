// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::io::Write;
use std::path::Path;

use anyhow::Result;

use kin_core::{AssistantKind, PromptMode};

/// `kin with [--session] <assistant> -- <task...>` — Launch an assistant with
/// Kin guidance injected.
///
/// Without `--session` the assistant launches from the repo working directory
/// with native-mode shims redirecting file commands to the source surface.
/// With `--session` the assistant launches inside a graph-backed session
/// workspace: its cwd and file operations target the materialized session,
/// its environment pins the repo daemon and session identity (so MCP tools
/// spawned by the assistant bind to the same repo and session), and a
/// successful exit reconciles the session back into the graph.
pub async fn run(
    assistant: String,
    task: Vec<String>,
    session: bool,
    passive_guidance: bool,
    restrict_discovery: bool,
    restrict_filesystem: bool,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let kind = AssistantKind::from_str(&assistant).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown assistant '{}'. Known: claude-code, codex, gemini-cli",
            assistant
        )
    })?;

    let task_text = task.join(" ");
    if task_text.is_empty() {
        return Err(anyhow::anyhow!(
            "no task provided. Usage: kin with <assistant> -- <task prompt>"
        ));
    }

    // Build summary (best-effort, continue without it)
    let summary = build_repo_summary_opt(&layout).await;

    let guidance =
        kin_core::generate_assistant_prompt(kind, PromptMode::Normal, &layout, summary.as_ref());

    if session {
        return run_in_session(
            &layout,
            kind,
            &guidance,
            &task_text,
            passive_guidance,
            restrict_discovery,
            restrict_filesystem,
        )
        .await;
    }

    let full_prompt = build_full_prompt(&guidance, &task_text, passive_guidance);

    let headless = std::env::var("KIN_BENCHMARK").ok().as_deref() == Some("1");
    let (program, args) = build_assistant_command(kind, &full_prompt, headless)?;

    // In native mode, generate PATH shims so agents' file-system commands
    // (cat, rg, find, etc.) transparently target .kin/source-root/ instead
    // of the empty control root.
    let shim_env = native_shim_env(&layout, restrict_discovery, restrict_filesystem)?;

    eprintln!("Launching {} with Kin guidance...", kind);

    let status = std::process::Command::new(&program)
        .args(&args)
        .current_dir(launch_dir(&layout))
        .envs(shim_env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| anyhow::anyhow!("failed to launch '{}': {}", program, e))?;

    let code = status.code().unwrap_or(1);
    if code != 0 {
        eprintln!("{} exited with code {}", kind, code);
    }

    std::process::exit(code);
}

/// Launch the assistant inside a freshly materialized session workspace and
/// close the session out when it exits.
async fn run_in_session(
    layout: &kin_core::KinLayout,
    kind: AssistantKind,
    guidance: &str,
    task_text: &str,
    passive_guidance: bool,
    restrict_discovery: bool,
    restrict_filesystem: bool,
) -> Result<()> {
    let session_id = uuid::Uuid::new_v4();
    let session_dir = layout
        .root()
        .join("runs")
        .join(format!("session-{session_id}"));

    let ws = super::session_workspace::create_session_workspace(layout, &session_dir, None, None)
        .await?;

    // Pin the daemon endpoint for the assistant and everything it spawns.
    // `kin mcp start` prefers KIN_DAEMON_URL over cwd discovery, so MCP tool
    // calls from this assistant bind to the same repo daemon as this session.
    let daemon_url = match std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        Some(url) => url,
        None => crate::daemon_client::resolve_daemon_url(layout)
            .await?
            .ok_or_else(|| anyhow::anyhow!("kin daemon is required for a session launch"))?,
    };
    let repo_id = super::remote::resolve_repo_id(layout).ok();

    let session_guidance = format!("{guidance}\n\n{}", session_guidance_note(&ws.root));
    let full_prompt = build_full_prompt(&session_guidance, task_text, passive_guidance);

    let headless = std::env::var("KIN_BENCHMARK").ok().as_deref() == Some("1");
    let (program, args) = build_assistant_command(kind, &full_prompt, headless)?;

    // Shims target the live session workspace so shell-outs from the
    // assistant resolve against the same files it is editing.
    let shim_env = session_shim_env(layout, &ws.root, restrict_discovery, restrict_filesystem)?;
    let mut env = session_launch_env(session_id, &ws.root, &daemon_url, repo_id.as_deref());
    env.extend(shim_env);

    eprintln!("Session workspace: {}", ws.root.display());
    eprintln!("Launching {} in session workspace...", kind);

    let code = spawn_assistant_in_session(&program, &args, &ws.root, &env)?;
    eprintln!("\n{} exited (code {}).", kind, code);

    {
        let stderr = std::io::stderr();
        let mut stderr = stderr.lock();
        close_agent_session(layout, &session_dir, code, &mut stderr).await?;
    }

    std::process::exit(code);
}

/// Spawn the assistant process with cwd set to the session workspace root.
fn spawn_assistant_in_session(
    program: &str,
    args: &[String],
    ws_root: &Path,
    env: &[(String, String)],
) -> Result<i32> {
    let status = std::process::Command::new(program)
        .args(args)
        .current_dir(ws_root)
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| anyhow::anyhow!("failed to launch '{}': {}", program, e))?;
    Ok(status.code().unwrap_or(1))
}

/// Session identity and daemon-binding env for an agent session launch.
///
/// - `KIN_SESSION` / `KIN_SESSION_DIR`: the `kin shell`/`kin open` contract.
/// - `KIN_SESSION_ID`: read by the MCP daemon delegate, which forwards it as
///   the `X-Kin-Session` header so the daemon can resolve session-scoped
///   graph state for this agent's tool calls.
/// - `KIN_DAEMON_URL`: pins `kin` CLI/MCP invocations inside the session to
///   this repo's daemon instead of re-discovering from cwd.
/// - `KIN_REPO_ID`: repo identity for provenance attribution.
fn session_launch_env(
    session_id: uuid::Uuid,
    ws_root: &Path,
    daemon_url: &str,
    repo_id: Option<&str>,
) -> Vec<(String, String)> {
    let mut env = vec![
        ("KIN_SESSION".into(), session_id.to_string()),
        ("KIN_SESSION_ID".into(), session_id.to_string()),
        (
            "KIN_SESSION_DIR".into(),
            ws_root.to_string_lossy().into_owned(),
        ),
        ("KIN_DAEMON_URL".into(), daemon_url.to_string()),
    ];
    if let Some(repo_id) = repo_id {
        env.push(("KIN_REPO_ID".into(), repo_id.to_string()));
    }
    env
}

fn session_guidance_note(ws_root: &Path) -> String {
    format!(
        "You are working inside a Kin session workspace at {}. Ordinary shell \
         commands and file edits apply to this workspace, and Kin reconciles \
         your changes into the semantic graph when the session ends. Kin MCP \
         tools are bound to this repository's daemon and this session.",
        ws_root.display()
    )
}

/// Close out an agent session: a clean exit reconciles the workspace into
/// the graph; any failure preserves the workspace with recovery commands.
async fn close_agent_session<W: Write>(
    layout: &kin_core::KinLayout,
    session_dir: &Path,
    exit_code: i32,
    writer: &mut W,
) -> Result<()> {
    if exit_code == 0 {
        return super::session_closeout::finalize_shell_session_with_writer(
            layout,
            session_dir,
            writer,
        )
        .await;
    }

    let session_hint = session_dir
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("session-"))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| session_dir.display().to_string());
    writeln!(
        writer,
        "Assistant failed; session workspace kept at: {}",
        session_dir.display()
    )?;
    writeln!(
        writer,
        "To reconcile its changes anyway: kin reconcile {session_hint} --cleanup"
    )?;
    writeln!(writer, "To discard it: rm -rf {}", session_dir.display())?;
    Ok(())
}

fn session_shim_env(
    layout: &kin_core::KinLayout,
    workspace_root: &Path,
    restrict_discovery: bool,
    restrict_filesystem: bool,
) -> Result<Vec<(String, String)>> {
    let shim_dir = kin_core::shims::ensure_shim_dir(layout)?;
    let mut env = kin_core::shims::shim_env_for_root(&shim_dir, workspace_root);
    if restrict_filesystem {
        eprintln!("Native mode: filesystem discovery and direct file reads are restricted");
        env.push(("KIN_DISCOVERY_MODE".into(), "deny".into()));
        env.push(("KIN_CONTENT_MODE".into(), "deny".into()));
    } else if restrict_discovery {
        eprintln!("Native mode: filesystem discovery commands are restricted");
        env.push(("KIN_DISCOVERY_MODE".into(), "deny".into()));
    }
    Ok(env)
}

fn build_full_prompt(guidance: &str, task: &str, passive_guidance: bool) -> String {
    if passive_guidance {
        task.to_string()
    } else {
        format!("{guidance}\n\n---\n\n{task}")
    }
}

fn native_shim_env(
    layout: &kin_core::KinLayout,
    restrict_discovery: bool,
    restrict_filesystem: bool,
) -> Result<Vec<(String, String)>> {
    // Benchmark/native harnesses may already have a shimmed PATH active.
    // Re-wrapping that environment makes KIN_ORIGINAL_PATH point at a path
    // that already contains the shims, which causes recursive resolution.
    if std::env::var_os("KIN_ORIGINAL_PATH").is_some()
        && std::env::var_os("KIN_SOURCE_ROOT").is_some()
    {
        let mut env = Vec::new();
        if restrict_filesystem {
            eprintln!("Native mode: filesystem discovery and direct file reads are restricted");
            env.push(("KIN_DISCOVERY_MODE".into(), "deny".into()));
            env.push(("KIN_CONTENT_MODE".into(), "deny".into()));
        } else if restrict_discovery {
            eprintln!("Native mode: filesystem discovery commands are restricted");
            env.push(("KIN_DISCOVERY_MODE".into(), "deny".into()));
        }
        return Ok(env);
    }

    let shim_dir = kin_core::shims::ensure_shim_dir(layout)?;
    eprintln!("Native mode: shims at {}", shim_dir.display());

    let mut env = kin_core::shims::shim_env(layout, &shim_dir);
    if restrict_filesystem {
        eprintln!("Native mode: filesystem discovery and direct file reads are restricted");
        env.push(("KIN_DISCOVERY_MODE".into(), "deny".into()));
        env.push(("KIN_CONTENT_MODE".into(), "deny".into()));
    } else if restrict_discovery {
        eprintln!("Native mode: filesystem discovery commands are restricted");
        env.push(("KIN_DISCOVERY_MODE".into(), "deny".into()));
    }
    Ok(env)
}

/// Returns the directory from which the assistant should be launched.
/// Always the repo working directory (control root), never the user's cwd.
fn launch_dir(layout: &kin_core::KinLayout) -> std::path::PathBuf {
    layout.working_dir().to_path_buf()
}

fn build_assistant_command(
    kind: AssistantKind,
    prompt: &str,
    headless: bool,
) -> Result<(String, Vec<String>)> {
    let claude_disallowed_tools = std::env::var("KIN_CLAUDE_DISALLOWED_TOOLS").ok();
    let plugin_dir = std::env::var("KIN_PLUGIN_DIR").ok();
    match kind {
        AssistantKind::ClaudeCode => Ok((
            "claude".into(),
            if headless {
                let mut args = vec![
                    "-p".into(),
                    prompt.into(),
                    "--output-format".into(),
                    "stream-json".into(),
                    "--verbose".into(),
                    "--setting-sources".into(),
                    "project,local".into(),
                    "--strict-mcp-config".into(),
                    "--permission-mode".into(),
                    "bypassPermissions".into(),
                ];
                if let Some(ref dir) = plugin_dir {
                    args.push("--plugin-dir".into());
                    args.push(dir.clone());
                }
                if let Some(disallowed) = claude_disallowed_tools {
                    args.push("--disallowedTools".into());
                    args.push(disallowed);
                }
                args
            } else {
                let mut args = vec![
                    "-p".into(),
                    prompt.into(),
                    "--output-format".into(),
                    "json".into(),
                ];
                if let Some(ref dir) = plugin_dir {
                    args.push("--plugin-dir".into());
                    args.push(dir.clone());
                }
                if let Some(disallowed) = claude_disallowed_tools {
                    args.push("--disallowedTools".into());
                    args.push(disallowed);
                }
                args
            },
        )),
        AssistantKind::Codex => Ok((
            "codex".into(),
            if headless {
                vec![
                    "exec".into(),
                    "--json".into(),
                    "--ephemeral".into(),
                    "--dangerously-bypass-approvals-and-sandbox".into(),
                    prompt.into(),
                ]
            } else {
                vec![
                    "exec".into(),
                    "--json".into(),
                    "--ephemeral".into(),
                    prompt.into(),
                ]
            },
        )),
        AssistantKind::GeminiCli => Ok((
            "gemini".into(),
            vec![
                "-p".into(),
                prompt.into(),
                "--yolo".into(),
                "--output-format".into(),
                "json".into(),
            ],
        )),
        _ => Err(anyhow::anyhow!(
            "'kin with' supports: claude-code, codex, gemini-cli. Got: {}",
            kind
        )),
    }
}

async fn build_repo_summary_opt(layout: &kin_core::KinLayout) -> Option<kin_core::RepoSummary> {
    use std::collections::HashMap;

    let base_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(
            crate::daemon_client::resolve_daemon_url(layout)
                .await
                .ok()?,
        )?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url).ok()?;
    let status = client
        .command_status(&crate::commands::status::CommandStatusRequest::new(false))
        .await
        .ok()?;

    Some(kin_core::RepoSummary {
        entity_count: status.summary.entities,
        language_breakdown: HashMap::new(),
        relation_count: 0,
        change_count: 0,
        work_item_count: 0,
        coverage_ratio: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_core::AssistantKind;
    use serial_test::serial;

    #[test]
    fn claude_command_structure() {
        let (prog, args) =
            build_assistant_command(AssistantKind::ClaudeCode, "find save", false).unwrap();
        assert_eq!(prog, "claude");
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"find save".to_string()));
        assert!(args.contains(&"--output-format".to_string()));
        assert!(args.contains(&"json".to_string()));
    }

    #[test]
    #[serial]
    fn claude_command_can_disable_explore_subagent() {
        std::env::set_var("KIN_CLAUDE_DISALLOWED_TOOLS", "Agent(Explore)");
        let (_prog, args) =
            build_assistant_command(AssistantKind::ClaudeCode, "find save", true).unwrap();
        std::env::remove_var("KIN_CLAUDE_DISALLOWED_TOOLS");

        assert!(args.contains(&"--disallowedTools".to_string()));
        assert!(args.contains(&"Agent(Explore)".to_string()));
    }

    #[test]
    fn codex_command_structure() {
        let (prog, args) =
            build_assistant_command(AssistantKind::Codex, "refactor auth", false).unwrap();
        assert_eq!(prog, "codex");
        assert!(args.contains(&"exec".to_string()));
        assert!(args.contains(&"refactor auth".to_string()));
        assert!(args.contains(&"--json".to_string()));
        assert!(args.contains(&"--ephemeral".to_string()));
    }

    #[test]
    fn gemini_command_structure() {
        let (prog, args) =
            build_assistant_command(AssistantKind::GeminiCli, "fix the bug", false).unwrap();
        assert_eq!(prog, "gemini");
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"fix the bug".to_string()));
        assert!(args.contains(&"--yolo".to_string()));
        assert!(args.contains(&"--output-format".to_string()));
        assert!(args.contains(&"json".to_string()));
    }

    #[test]
    fn cursor_unsupported() {
        let result = build_assistant_command(AssistantKind::Cursor, "anything", false);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("cursor"), "error should mention cursor: {msg}");
    }

    #[test]
    fn generic_unsupported() {
        let result = build_assistant_command(AssistantKind::Generic, "anything", false);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("generic"),
            "error should mention generic: {msg}"
        );
    }

    #[test]
    fn codex_headless_command_structure() {
        let (prog, args) =
            build_assistant_command(AssistantKind::Codex, "trace flow", true).unwrap();
        assert_eq!(prog, "codex");
        assert!(args.contains(&"--dangerously-bypass-approvals-and-sandbox".to_string()));
    }

    #[test]
    fn launch_dir_is_control_root_not_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();

        let layout = kin_core::KinLayout::discover(dir.path()).expect("should discover kin layout");

        let ldir = launch_dir(&layout);

        // Must be the repo root (control root), not wherever the test runner is
        assert_eq!(ldir, dir.path());
        assert_ne!(ldir, std::env::current_dir().unwrap());
    }

    #[test]
    fn launch_dir_stable_across_calls() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();

        let layout = kin_core::KinLayout::discover(dir.path()).expect("should discover kin layout");

        // Deterministic — same layout always gives same launch dir
        assert_eq!(launch_dir(&layout), launch_dir(&layout));
    }

    #[test]
    fn build_full_prompt_includes_guidance_by_default() {
        let prompt = build_full_prompt("GUIDANCE", "TASK", false);
        assert!(prompt.contains("GUIDANCE"));
        assert!(prompt.contains("TASK"));
        assert!(prompt.contains("---"));
    }

    #[test]
    fn build_full_prompt_can_be_passive() {
        let prompt = build_full_prompt("GUIDANCE", "TASK", true);
        assert_eq!(prompt, "TASK");
    }

    #[test]
    fn native_shim_env_adds_deny_flag_when_requested() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(kin_dir.join("source-root")).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        // No mode to set — there's one mode: Kin.

        let env = native_shim_env(&layout, true, false).unwrap();
        assert!(env
            .iter()
            .any(|(k, v)| k == "KIN_DISCOVERY_MODE" && v == "deny"));
    }

    #[test]
    fn native_shim_env_bootstraps_native_mode_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();

        let env = native_shim_env(&layout, true, false).unwrap();
        assert!(env.iter().any(|(k, _)| k == "KIN_SOURCE_ROOT"));
        assert!(env.iter().any(|(k, _)| k == "KIN_ORIGINAL_PATH"));
        assert!(env
            .iter()
            .any(|(k, v)| k == "KIN_DISCOVERY_MODE" && v == "deny"));
    }

    #[test]
    fn native_shim_env_can_restrict_all_filesystem_access() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(kin_dir.join("source-root")).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        // No mode to set — there's one mode: Kin.

        let env = native_shim_env(&layout, false, true).unwrap();
        assert!(env
            .iter()
            .any(|(k, v)| k == "KIN_DISCOVERY_MODE" && v == "deny"));
        assert!(env
            .iter()
            .any(|(k, v)| k == "KIN_CONTENT_MODE" && v == "deny"));
    }

    #[test]
    fn session_launch_env_pins_session_and_daemon() {
        let session_id = uuid::Uuid::new_v4();
        let ws_root = std::path::Path::new("/tmp/repo/.kin/runs/session-x");

        let env = session_launch_env(
            session_id,
            ws_root,
            "http://127.0.0.1:4242",
            Some("repo-uuid"),
        );

        for (key, expected) in [
            ("KIN_SESSION", session_id.to_string()),
            ("KIN_SESSION_ID", session_id.to_string()),
            ("KIN_SESSION_DIR", ws_root.to_string_lossy().into_owned()),
            ("KIN_DAEMON_URL", "http://127.0.0.1:4242".to_string()),
            ("KIN_REPO_ID", "repo-uuid".to_string()),
        ] {
            assert_eq!(
                env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str()),
                Some(expected.as_str()),
                "missing or wrong {key}"
            );
        }
    }

    #[test]
    fn session_launch_env_omits_repo_id_when_unknown() {
        let env = session_launch_env(
            uuid::Uuid::new_v4(),
            std::path::Path::new("/tmp/ws"),
            "http://127.0.0.1:4242",
            None,
        );
        assert!(!env.iter().any(|(k, _)| k == "KIN_REPO_ID"));
    }

    #[test]
    fn session_shim_env_targets_session_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(kin_dir.join("source-root")).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let workspace_root = dir.path().join(".kin/runs/session-123");
        std::fs::create_dir_all(&workspace_root).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();

        let env = session_shim_env(&layout, &workspace_root, false, false).unwrap();
        assert!(
            env.iter()
                .any(|(k, v)| k == "KIN_SOURCE_ROOT"
                    && v == workspace_root.to_string_lossy().as_ref())
        );
    }

    #[test]
    fn session_guidance_note_names_the_workspace() {
        let note = session_guidance_note(std::path::Path::new("/tmp/ws/session-abc"));
        assert!(note.contains("/tmp/ws/session-abc"));
        assert!(note.contains("reconciles"));
    }

    /// Smoke: a fake `claude` binary launched via the session path must start
    /// with cwd in the session workspace and see the session/daemon env.
    #[cfg(unix)]
    #[test]
    #[serial]
    fn claude_stub_launch_starts_in_session_workspace_with_session_env() {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let session_id = uuid::Uuid::new_v4();
        let ws_root = layout.root().join(format!("runs/session-{session_id}"));
        std::fs::create_dir_all(&ws_root).unwrap();

        let stub_dir = repo.path().join("stub-bin");
        std::fs::create_dir_all(&stub_dir).unwrap();
        let record = repo.path().join("claude-record.txt");
        std::fs::write(
            stub_dir.join("claude"),
            format!(
                "#!/bin/sh\n\
                 printf 'cwd=%s\\n' \"$PWD\" > {record}\n\
                 printf 'session=%s\\n' \"$KIN_SESSION\" >> {record}\n\
                 printf 'session_id=%s\\n' \"$KIN_SESSION_ID\" >> {record}\n\
                 printf 'session_dir=%s\\n' \"$KIN_SESSION_DIR\" >> {record}\n\
                 printf 'daemon=%s\\n' \"$KIN_DAEMON_URL\" >> {record}\n\
                 printf 'source_root=%s\\n' \"$KIN_SOURCE_ROOT\" >> {record}\n\
                 printf 'prompt=%s\\n' \"$2\" >> {record}\n",
                record = record.display()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                stub_dir.join("claude"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }

        let (program, args) =
            build_assistant_command(AssistantKind::ClaudeCode, "session smoke task", false)
                .unwrap();
        assert_eq!(program, "claude");
        // Launch the stub by absolute path. Resolving the assistant through a
        // process-global `PATH` prepend races every other thread in this binary
        // and can fall through to a real `claude` on a developer machine. The
        // launcher inherits this process's stdin by contract, so a real
        // interactive assistant would block on the terminal and never return.
        let stub = stub_dir.join(&program);

        let mut env = session_launch_env(session_id, &ws_root, "http://127.0.0.1:9/test", None);
        env.extend(session_shim_env(&layout, &ws_root, false, false).unwrap());

        let launch_root = ws_root.clone();
        let code = crate::commands::test_subprocess::call_with_deadline(
            "session assistant launch",
            crate::commands::test_subprocess::DEFAULT_TEST_SUBPROCESS_TIMEOUT,
            move || spawn_assistant_in_session(&stub.to_string_lossy(), &args, &launch_root, &env),
        )
        .unwrap();

        assert_eq!(code, 0);
        let recorded = std::fs::read_to_string(&record).unwrap();
        let ws_display = ws_root.display().to_string();
        let cwd_line = recorded
            .lines()
            .find(|l| l.starts_with("cwd="))
            .unwrap()
            .trim_start_matches("cwd=");
        assert_eq!(
            std::fs::canonicalize(cwd_line).unwrap(),
            std::fs::canonicalize(&ws_root).unwrap(),
            "assistant must start inside the session workspace"
        );
        assert!(recorded.contains(&format!("session={session_id}")));
        assert!(recorded.contains(&format!("session_id={session_id}")));
        assert!(recorded.contains(&format!("session_dir={ws_display}")));
        assert!(recorded.contains("daemon=http://127.0.0.1:9/test"));
        assert!(recorded.contains(&format!("source_root={ws_display}")));
        assert!(recorded.contains("prompt="));
        assert!(recorded.contains("session smoke task"));
    }

    #[tokio::test]
    async fn close_agent_session_reconciles_on_clean_exit() {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let session_dir = layout.root().join("runs/session-agent-clean");
        let updated = "pub fn agent_edit() -> &'static str { \"ok\" }\n";
        std::fs::create_dir_all(session_dir.join("src")).unwrap();
        std::fs::write(session_dir.join("src/lib.rs"), updated).unwrap();

        let mut stderr = Vec::new();
        close_agent_session(&layout, &session_dir, 0, &mut stderr)
            .await
            .unwrap();

        assert!(
            !session_dir.exists(),
            "clean agent exit should reconcile and remove the session workspace"
        );
        assert_eq!(
            std::fs::read_to_string(repo.path().join("src/lib.rs")).unwrap(),
            updated
        );
    }

    #[tokio::test]
    async fn close_agent_session_preserves_workspace_on_failure() {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let session_dir = layout.root().join("runs/session-agent-fail");
        std::fs::create_dir_all(&session_dir).unwrap();
        std::fs::write(session_dir.join("partial.txt"), "half-done\n").unwrap();

        let mut stderr = Vec::new();
        close_agent_session(&layout, &session_dir, 1, &mut stderr)
            .await
            .unwrap();

        let output = String::from_utf8(stderr).unwrap();
        assert!(output.contains("session workspace kept"));
        assert!(output.contains("kin reconcile agent-fail --cleanup"));
        assert!(output.contains("rm -rf"));
        assert!(session_dir.join("partial.txt").exists());
        assert!(
            !repo.path().join("partial.txt").exists(),
            "failed agent session must not auto-reconcile"
        );
    }
}
