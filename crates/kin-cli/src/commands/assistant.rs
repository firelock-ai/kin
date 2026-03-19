use anyhow::Result;

use kin_core::{doctor, install_adapter, list_adapters, AssistantKind};
use kin_core::{ManagedDocConfig, RepoSummary, SyncMode};

/// `kin assistant install <assistant>` — Install an assistant adapter.
pub async fn install(assistant: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let kind = AssistantKind::from_str(&assistant).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown assistant '{}'. Known: claude-code, codex, gemini-cli, cursor, generic",
            assistant
        )
    })?;

    let result = install_adapter(&layout, kind)?;

    println!("Installed {} adapter.", kind);
    println!("  Config:   {}", result.config_path.display());
    println!("  Guide:    {}", result.guidance_path.display());
    if let Some(agents_md) = &result.agents_md_path {
        println!("  AGENTS.md: {}", agents_md.display());
    }
    if let Some(assistant_doc) = &result.assistant_doc_path {
        println!("  Assistant doc: {}", assistant_doc.display());
    }

    // Show assistant-specific next steps.
    let config = kin_core::AssistantAdapterConfig::default_for(kind);
    println!();
    match kind {
        AssistantKind::ClaudeCode => {
            println!("Next:");
            println!("  claude mcp add kin -- kin mcp start");
            println!("  Keep AGENTS.md and CLAUDE.md synced with `kin assistant sync`.");
            println!("  Consider Claude hooks for reminders like `kin review` before mutation.");
        }
        AssistantKind::Codex => {
            println!("Next:");
            println!("  codex mcp add kin -- kin mcp start");
            println!("  Keep AGENTS.md and CODEX.md synced with `kin assistant sync`.");
            println!("  Use direct Kin CLI instructions in prompts until Codex learns Kin-native flows by default.");
        }
        AssistantKind::GeminiCli => {
            println!("Next:");
            println!("  gemini mcp add kin -- kin mcp start");
            println!("  Keep AGENTS.md and GEMINI.md synced with `kin assistant sync`.");
            println!("  Prefer narrow Kin CLI guidance for focused context.");
        }
        _ if config.mcp_capable => {
            println!(
                "Next: configure your assistant's MCP settings to connect to `kin mcp start`."
            );
            if let Some(ref mcp) = config.mcp {
                println!("  transport: {}", mcp.transport);
                if let Some(ref cmd) = mcp.command {
                    let args = mcp.args.join(" ");
                    println!("  command:   {} {}", cmd, args);
                }
            }
        }
        _ if config.wrapper_script.is_some() => {
            println!("Next: use the wrapper script to connect your assistant to Kin CLI commands.");
        }
        _ => {
            println!("Next: run Kin CLI commands directly from your assistant.");
        }
    }

    Ok(())
}

/// `kin assistant doctor` — Run connectivity checks for all installed adapters.
pub async fn run_doctor(assistant: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    if let Some(name) = assistant {
        // Doctor a specific assistant.
        let kind = AssistantKind::from_str(&name).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown assistant '{}'. Known: claude-code, codex, gemini-cli, cursor, generic",
                name
            )
        })?;

        let report = doctor(&layout, kind)?;
        print!("{}", report.summary());
    } else {
        // Doctor all installed adapters.
        let adapters = list_adapters(&layout)?;

        if adapters.is_empty() {
            println!("No adapters installed. Run `kin assistant install <assistant>` first.");
            return Ok(());
        }

        for config in &adapters {
            let report = doctor(&layout, config.kind)?;
            print!("{}", report.summary());
            println!();
        }
    }

    Ok(())
}

/// `kin assistant list` — List installed assistant adapters.
pub async fn list() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let adapters = list_adapters(&layout)?;

    if adapters.is_empty() {
        println!("No assistant adapters installed.");
        println!("Run `kin assistant install <assistant>` to install one.");
        println!("Known assistants: claude-code, codex, gemini-cli, cursor, generic");
        return Ok(());
    }

    println!(
        "{:<15}  {:<18}  {:<5}  {:<8}",
        "KIND", "NAME", "MCP", "COOP"
    );
    println!("{}", "-".repeat(55));

    for config in &adapters {
        let mcp = if config.mcp_capable { "yes" } else { "no" };
        let coop = if config.cooperative { "yes" } else { "no" };
        println!(
            "{:<15}  {:<18}  {:<5}  {:<8}",
            config.kind.as_str(),
            config.display_name,
            mcp,
            coop,
        );
    }

    println!("\n{} adapter(s) installed.", adapters.len());
    Ok(())
}

/// `kin assistant sync` — Regenerate managed blocks in all enabled target files.
pub async fn sync() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let config = ManagedDocConfig::load(&layout)?;

    let enabled = config.enabled_targets();
    if enabled.is_empty() {
        println!("No enabled sync targets. Run `kin assistant configure --enable AGENTS.md`.");
        return Ok(());
    }

    // Build repo summary from graph state
    let summary = build_repo_summary(&layout)?;

    let results = kin_core::sync_all(&layout, &config, &summary)?;

    for result in &results {
        let status = if result.created {
            "created"
        } else if result.updated {
            "updated"
        } else {
            "unchanged"
        };
        println!("  {} — {}", result.path.display(), status);
    }

    let updated_count = results.iter().filter(|r| r.updated || r.created).count();
    println!(
        "\nSynced {} target(s) ({} updated).",
        results.len(),
        updated_count
    );

    Ok(())
}

/// `kin assistant configure` — Configure managed doc sync targets.
pub async fn configure(
    sync_mode: Option<String>,
    enable: Option<String>,
    disable: Option<String>,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let mut config = ManagedDocConfig::load(&layout)?;
    let mut changed = false;

    // Update sync mode
    if let Some(mode_str) = sync_mode {
        let mode = match mode_str.as_str() {
            "manual" => SyncMode::Manual,
            "on-commit" => SyncMode::OnCommit,
            "daemon-auto" => SyncMode::DaemonAuto,
            _ => {
                return Err(anyhow::anyhow!(
                    "unknown sync mode '{}'. Options: manual, on-commit, daemon-auto",
                    mode_str
                ))
            }
        };
        config.sync_mode = mode;
        changed = true;
        println!("Sync mode set to: {}", mode);
    }

    // Enable a target
    if let Some(ref target_path) = enable {
        if let Some(target) = config.targets.iter_mut().find(|t| t.path == *target_path) {
            target.enabled = true;
            changed = true;
            println!("Enabled target: {}", target_path);
        } else {
            // Add new target with default sections
            config.targets.push(kin_core::ManagedDocTarget {
                path: target_path.clone(),
                enabled: true,
                sections: vec!["summary".into(), "conventions".into()],
            });
            changed = true;
            println!("Added and enabled target: {}", target_path);
        }
    }

    // Disable a target
    if let Some(ref target_path) = disable {
        if let Some(target) = config.targets.iter_mut().find(|t| t.path == *target_path) {
            target.enabled = false;
            changed = true;
            println!("Disabled target: {}", target_path);
        } else {
            println!("Target '{}' not found in config.", target_path);
        }
    }

    if changed {
        config.save(&layout)?;
        println!(
            "Config saved to {}",
            ManagedDocConfig::config_path(&layout).display()
        );
    }

    // Show current config
    if !changed {
        println!("Sync mode: {}", config.sync_mode);
        println!();
        println!("{:<30}  {:<8}  SECTIONS", "TARGET", "ENABLED");
        println!("{}", "-".repeat(65));
        for target in &config.targets {
            let enabled = if target.enabled { "yes" } else { "no" };
            println!(
                "{:<30}  {:<8}  {}",
                target.path,
                enabled,
                target.sections.join(", "),
            );
        }
    }

    Ok(())
}

/// `kin assistant hooks [assistant]` — Show recommended hook templates.
pub async fn hooks(assistant: Option<String>) -> Result<()> {
    let kind = assistant.as_deref().unwrap_or("claude-code");

    match kind {
        "claude-code" => {
            let hook_templates = kin_core::generate_claude_hooks();
            let json = kin_core::render_hooks_json(&hook_templates);
            let instructions = kin_core::render_hooks_instructions(&hook_templates);

            println!("{}", instructions);
            println!("## JSON Configuration\n");
            println!("{}", json);
        }
        other => {
            println!(
                "Hook templates are currently only available for Claude Code.\n\
                 Requested assistant: {}\n\n\
                 For other assistants, use `kin assistant install {}` and follow the\n\
                 generated guidance document for integration instructions.",
                other, other
            );
        }
    }

    Ok(())
}

/// `kin assistant snippets [assistant]` — Generate config snippets.
pub async fn snippets(assistant: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let kinds: Vec<AssistantKind> = if let Some(name) = assistant {
        let kind = AssistantKind::from_str(&name).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown assistant '{}'. Known: claude-code, codex, gemini-cli",
                name
            )
        })?;
        vec![kind]
    } else {
        // All MCP-capable assistants
        vec![
            AssistantKind::ClaudeCode,
            AssistantKind::Codex,
            AssistantKind::GeminiCli,
        ]
    };

    for kind in &kinds {
        let snippets = kin_core::generate_config_snippets(*kind);
        if snippets.is_empty() {
            println!("{}: no config snippets available.", kind);
            continue;
        }

        let paths = kin_core::write_config_snippets(&layout, *kind)?;

        println!("=== {} ===\n", kind);
        for (snippet, path) in snippets.iter().zip(paths.iter()) {
            println!("--- {} ---", snippet.target_path);
            println!("  {}", snippet.description);
            println!();
            println!("{}", snippet.content);
            println!();
            println!("  (saved to {})", path.display());
            println!();
        }
    }

    println!("Tip: Kin CLI commands (kin search, kin context, kin review, kin commit)");
    println!("are always available. MCP is a convenience layer on top.");

    Ok(())
}

/// `kin assistant prompt --assistant <name> [--mode benchmark|normal]`
pub async fn prompt(assistant: String, mode: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let kind = AssistantKind::from_str(&assistant).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown assistant '{}'. Known: claude-code, codex, gemini-cli, cursor, generic",
            assistant
        )
    })?;

    let prompt_mode = match mode.as_str() {
        "normal" => kin_core::PromptMode::Normal,
        "benchmark" => kin_core::PromptMode::Benchmark,
        _ => {
            return Err(anyhow::anyhow!(
                "unknown mode '{}'. Options: normal, benchmark",
                mode
            ))
        }
    };

    let summary = build_repo_summary(&layout).ok();
    let output = kin_core::generate_assistant_prompt(kind, prompt_mode, &layout, summary.as_ref());

    // Print raw — designed for piping/injection
    print!("{}", output);
    Ok(())
}

/// Build a RepoSummary from the current graph state.
fn build_repo_summary(_layout: &kin_core::KinLayout) -> Result<RepoSummary> {
    use kin_model::{EntityFilter, GraphStore, WorkFilter};
    use std::collections::HashMap;

    let graph = kin_db::InMemoryGraph::new();

    let entities = graph.query_entities(&EntityFilter::default())?;
    let mut language_breakdown = HashMap::new();
    for entity in &entities {
        *language_breakdown
            .entry(entity.language.to_string())
            .or_insert(0usize) += 1;
    }

    let work_items = graph.list_work_items(&WorkFilter {
        kinds: None,
        statuses: None,
        scope: None,
    })?;

    Ok(RepoSummary {
        entity_count: entities.len(),
        language_breakdown,
        relation_count: 0,
        change_count: 0,
        work_item_count: work_items.len(),
        coverage_ratio: None,
    })
}
