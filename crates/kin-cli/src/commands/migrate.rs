// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::PathBuf;

use anyhow::Result;

/// `kin migrate [source] --history snapshot|full [--resume]`.
pub async fn run(source: Option<String>, history: String, resume: bool) -> Result<()> {
    let source_path = source
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("cannot determine current directory"));

    // Guard: if this is NOT a Git repository, suggest `kin init` instead.
    if !source_path.join(".git").exists() {
        anyhow::bail!(
            "not a Git repository: {}\nhint: use `kin init` for non-Git directories",
            source_path.display()
        );
    }

    let strategy = match history.to_lowercase().as_str() {
        "snapshot" => kin_migrate::strategy::MigrationStrategy::Snapshot,
        "full" => kin_migrate::strategy::MigrationStrategy::Full,
        _ => anyhow::bail!(
            "invalid history mode '{}': expected 'snapshot' or 'full'",
            history
        ),
    };

    // Check for an existing checkpoint if --resume is set.
    if resume {
        if let Some(checkpoint) = kin_migrate::read_checkpoint(&source_path)
            .map_err(|e| anyhow::anyhow!("failed to read checkpoint: {}", e))?
        {
            println!(
                "Resuming from checkpoint: {} commits processed (last: {})",
                checkpoint.total_processed, checkpoint.last_commit,
            );
            println!(
                "  Entities: {}, Relations: {}, Files: {}",
                checkpoint.entities_extracted,
                checkpoint.relations_extracted,
                checkpoint.files_indexed,
            );
        } else {
            println!("No checkpoint found, starting fresh migration.");
        }
    }

    println!("Scanning repository at {}...", source_path.display());

    let scan =
        kin_migrate::scan_repo(&source_path).map_err(|e| anyhow::anyhow!("scan failed: {}", e))?;

    println!(
        "  Default branch: {}",
        scan.default_branch.as_deref().unwrap_or("(detached)")
    );
    println!("  Source files: {}", scan.source_files.len());

    let plan = kin_migrate::plan_migration(&scan, strategy, None);
    print!("{}", plan.describe());

    println!("Executing migration...");

    let result = kin_migrate::execute_migration_persisted(&plan)
        .map_err(|e| anyhow::anyhow!("migration failed: {}", e))?;

    // Clear checkpoint on successful completion.
    let _ = kin_migrate::clear_checkpoint(&source_path);

    print!("{}", result.summary());

    // Trigger LSP cold sweep only through an already-routed daemon.
    let daemon_url = if let Some(daemon_url) = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        Some(daemon_url)
    } else if let Some(layout) = kin_core::KinLayout::discover(&source_path) {
        crate::daemon_client::resolve_daemon_url_if_running_async(&layout).await
    } else {
        None
    };
    if let Some(daemon_url) = daemon_url {
        if let Ok(resp) = reqwest::Client::new()
            .post(format!("{}/v1/lsp/sweep", daemon_url.trim_end_matches('/')))
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await
        {
            if resp.status().is_success() {
                println!("LSP cold sweep triggered — enriching all entities in background");
            }
        }
    }

    Ok(())
}
