// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::PathBuf;

use anyhow::Result;

/// `kin migrate [source] --depth shallow|deep` — Migrate a Git repo to Kin.
pub async fn run(source: Option<String>, depth: String) -> Result<()> {
    let source_path = source
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("cannot determine current directory"));

    let strategy = match depth.to_lowercase().as_str() {
        "shallow" => kin_migrate::strategy::MigrationStrategy::Shallow,
        "deep" => kin_migrate::strategy::MigrationStrategy::Deep,
        _ => anyhow::bail!("invalid depth '{}': expected 'shallow' or 'deep'", depth),
    };

    println!("Scanning repository at {}...", source_path.display());

    let scan =
        kin_migrate::scan_repo(&source_path).map_err(|e| anyhow::anyhow!("scan failed: {}", e))?;

    println!(
        "  Default branch: {}",
        scan.default_branch.as_deref().unwrap_or("(detached)")
    );
    println!("  Source files: {}", scan.source_files.len());

    let plan = kin_migrate::plan_migration(&scan, strategy, None, 0);
    print!("{}", plan.describe());

    println!("Executing migration...");

    let result = kin_migrate::execute_migration_persisted(&plan)
        .map_err(|e| anyhow::anyhow!("migration failed: {}", e))?;

    print!("{}", result.summary());

    Ok(())
}
