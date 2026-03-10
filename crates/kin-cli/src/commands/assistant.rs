use anyhow::Result;

use kin_core::{AssistantKind, install_adapter, list_adapters, doctor};

/// `kin assistant install <assistant>` — Install an assistant adapter.
pub async fn install(assistant: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let kind = AssistantKind::from_str(&assistant)
        .ok_or_else(|| {
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

    // Show assistant-specific next steps.
    let config = kin_core::AssistantAdapterConfig::default_for(kind);
    println!();
    if config.mcp_capable {
        println!("Next: configure your assistant's MCP settings to connect to `kin mcp`.");
        if let Some(ref mcp) = config.mcp {
            println!("  transport: {}", mcp.transport);
            if let Some(ref cmd) = mcp.command {
                let args = mcp.args.join(" ");
                println!("  command:   {} {}", cmd, args);
            }
        }
    } else if config.wrapper_script.is_some() {
        println!("Next: use the wrapper script to connect your assistant to Kin CLI commands.");
    } else {
        println!("Next: run Kin CLI commands directly from your assistant.");
    }

    Ok(())
}

/// `kin assistant doctor` — Run connectivity checks for all installed adapters.
pub async fn run_doctor(assistant: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    if let Some(name) = assistant {
        // Doctor a specific assistant.
        let kind = AssistantKind::from_str(&name)
            .ok_or_else(|| {
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

    println!("{:<15}  {:<18}  {:<5}  {:<8}", "KIND", "NAME", "MCP", "COOP");
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
