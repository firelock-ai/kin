// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::PathBuf;

use anyhow::Result;

/// `kin migrate [source] [--target PATH]`.
pub async fn run(source: Option<String>, target: Option<PathBuf>) -> Result<()> {
    let source_path = source
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("cannot determine current directory"));

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
    let plan = kin_migrate::plan_migration(
        &scan,
        kin_migrate::strategy::MigrationStrategy::Full,
        target,
    );
    print!("{}", plan.describe());

    println!("Executing migration...");

    let result = kin_migrate::execute_migration_persisted(&plan)
        .map_err(|e| anyhow::anyhow!("migration failed: {}", e))?;

    print!("{}", result.summary());
    Ok(())
}
