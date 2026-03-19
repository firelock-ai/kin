use anyhow::Result;

use kin_core::{AssistantKind, PromptMode};

/// `kin with <assistant> -- <task...>` — Launch an assistant with Kin guidance injected.
pub async fn run(
    assistant: String,
    task: Vec<String>,
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
    let summary = build_repo_summary_opt(&layout);

    let guidance =
        kin_core::generate_assistant_prompt(kind, PromptMode::Normal, &layout, summary.as_ref());

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
    if kin_core::read_repo_mode(layout) != kin_core::RepoMode::Native {
        return Ok(vec![]);
    }

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

fn build_repo_summary_opt(layout: &kin_core::KinLayout) -> Option<kin_core::RepoSummary> {
    use kin_model::{EntityFilter, GraphStore, WorkFilter};
    use std::collections::HashMap;

    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(layout)).ok()?;
    let graph = _snap.graph();
    let entities = graph.query_entities(&EntityFilter::default()).ok()?;

    let mut language_breakdown = HashMap::new();
    for entity in &entities {
        *language_breakdown
            .entry(entity.language.to_string())
            .or_insert(0usize) += 1;
    }

    let work_items = graph
        .list_work_items(&WorkFilter {
            kinds: None,
            statuses: None,
            scope: None,
        })
        .unwrap_or_default();

    Some(kin_core::RepoSummary {
        entity_count: entities.len(),
        language_breakdown,
        relation_count: 0,
        change_count: 0,
        work_item_count: work_items.len(),
        coverage_ratio: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_core::{AssistantKind, RepoMode};

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
        kin_core::write_repo_mode(&layout, RepoMode::Native).unwrap();

        let env = native_shim_env(&layout, true, false).unwrap();
        assert!(env
            .iter()
            .any(|(k, v)| k == "KIN_DISCOVERY_MODE" && v == "deny"));
    }

    #[test]
    fn native_shim_env_empty_in_compat_mode() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();

        let env = native_shim_env(&layout, true, false).unwrap();
        assert!(env.is_empty());
    }

    #[test]
    fn native_shim_env_can_restrict_all_filesystem_access() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(kin_dir.join("source-root")).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        kin_core::write_repo_mode(&layout, RepoMode::Native).unwrap();

        let env = native_shim_env(&layout, false, true).unwrap();
        assert!(env
            .iter()
            .any(|(k, v)| k == "KIN_DISCOVERY_MODE" && v == "deny"));
        assert!(env
            .iter()
            .any(|(k, v)| k == "KIN_CONTENT_MODE" && v == "deny"));
    }
}
