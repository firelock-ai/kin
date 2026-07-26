// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::PathBuf;

use anyhow::Result;

/// `kin migrate [source] [--target PATH] --history snapshot|full`.
pub async fn run(source: Option<String>, target: Option<PathBuf>, history: String) -> Result<()> {
    let source_path = source
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("cannot determine current directory"));

    let strategy = match history.to_lowercase().as_str() {
        "snapshot" => kin_migrate::strategy::MigrationStrategy::Snapshot,
        "full" => kin_migrate::strategy::MigrationStrategy::Full,
        _ => anyhow::bail!(
            "invalid history mode '{}': expected 'snapshot' or 'full'",
            history
        ),
    };

    println!("Scanning repository at {}...", source_path.display());

    let scan = kin_migrate::scan_repo(&source_path).map_err(|error| match error {
        kin_migrate::MigrateError::NotAGitRepo(_) => anyhow::anyhow!(
            "not a Git repository: {}\nhint: use `kin init` for non-Git directories",
            source_path.display()
        ),
        error => anyhow::anyhow!("scan failed: {error}"),
    })?;

    println!(
        "  Default branch: {}",
        scan.default_branch.as_deref().unwrap_or("(detached)")
    );
    let plan = kin_migrate::plan_migration(&scan, strategy, target);
    print!("{}", plan.describe());

    println!("Executing migration...");

    let result = kin_migrate::execute_migration_persisted(&plan)
        .map_err(|e| anyhow::anyhow!("migration failed: {}", e))?;

    print!("{}", result.summary());
    let migrated_root = PathBuf::from(&result.kin_root);

    // Trigger LSP cold sweep only through an already-routed daemon.
    let daemon_url = if let Some(daemon_url) = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        Some(daemon_url)
    } else if let Some(layout) = kin_core::KinLayout::discover(&migrated_root) {
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
