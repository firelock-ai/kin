// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_core::registry::KinRegistry;

/// List all registered Kin repositories.
pub async fn list() -> Result<()> {
    let registry = KinRegistry::load()
        .map_err(|e| anyhow::anyhow!("failed to load registry: {}", e))?;

    if registry.repos.is_empty() {
        println!("No registered repositories.");
        println!("hint: run `kin init` in a directory to register it");
        return Ok(());
    }

    println!("Registered repositories:");
    for repo in &registry.repos {
        let age = format_age(&repo.last_commit);
        println!(
            "  {:<16} {:<50} {:>6} entities  {}",
            repo.id,
            repo.path.display(),
            format_count(repo.entities),
            age,
        );
    }

    Ok(())
}

/// Remove stale entries (paths that no longer contain .kin/).
pub async fn clean() -> Result<()> {
    let mut registry = KinRegistry::load()
        .map_err(|e| anyhow::anyhow!("failed to load registry: {}", e))?;

    let removed = registry.clean();

    registry
        .save()
        .map_err(|e| anyhow::anyhow!("failed to save registry: {}", e))?;

    println!("Removed {} stale entries.", removed);
    Ok(())
}

/// Format an entity count with comma separators.
fn format_count(n: usize) -> String {
    if n < 1_000 {
        return n.to_string();
    }
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Format an ISO 8601 timestamp as a human-readable relative age.
fn format_age(iso: &str) -> String {
    let Ok(ts) = chrono::DateTime::parse_from_rfc3339(iso) else {
        return iso.to_string();
    };
    let now = chrono::Utc::now();
    let duration = now.signed_duration_since(ts);

    let secs = duration.num_seconds();
    if secs < 60 {
        return format!("{}s ago", secs);
    }
    let mins = duration.num_minutes();
    if mins < 60 {
        return format!("{}m ago", mins);
    }
    let hours = duration.num_hours();
    if hours < 24 {
        return format!("{}h ago", hours);
    }
    let days = duration.num_days();
    format!("{}d ago", days)
}
