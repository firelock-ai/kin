// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_core::registry::KinRegistry;
use std::collections::HashSet;

use super::deps;

#[derive(Debug, serde::Deserialize)]
struct RegisteredRepoDaemon {
    repo_id: String,
    repo_root: String,
    pid: u32,
    port: u16,
    endpoint: String,
    graph_entity_count: Option<usize>,
    last_heartbeat_at: String,
}

/// List all registered Kin repositories.
pub async fn list() -> Result<()> {
    let registry =
        KinRegistry::load().map_err(|e| anyhow::anyhow!("failed to load registry: {}", e))?;

    if registry.repos.is_empty() {
        println!("No registered repositories.");
        println!("hint: run `kin init` in a directory to register it");
        return Ok(());
    }

    let known_ids: HashSet<String> = registry.repos.iter().map(|r| r.id.clone()).collect();

    println!("Registered repositories:");
    for repo in &registry.repos {
        let age = format_age(&repo.last_commit);
        let repo_deps = deps::detect_dependencies_for_repo(&repo.path, &known_ids);
        let dep_str = deps::format_deps_short(&repo_deps);
        println!(
            "  {:<16} {:>6} entities  {}  {}",
            repo.id,
            format_count(repo.entities),
            dep_str,
            age,
        );
    }

    Ok(())
}

/// List repo daemons registered with the central local supervisor.
pub async fn daemons() -> Result<()> {
    let supervisor_url = crate::daemon_client::ensure_supervisor_running().await?;
    let daemons: Vec<RegisteredRepoDaemon> = reqwest::Client::new()
        .get(format!("{}/daemons", supervisor_url.trim_end_matches('/')))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    println!("Kin supervisor: {}", supervisor_url);
    if daemons.is_empty() {
        println!("No repo daemons registered.");
        return Ok(());
    }

    println!(
        "{:<22} {:>6} {:>7} {:<22} PATH",
        "REPO", "PID", "PORT", "ENTITIES"
    );
    for daemon in daemons {
        let entity_count = daemon
            .graph_entity_count
            .map(format_count)
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<22} {:>6} {:>7} {:<22} {}",
            daemon.repo_id, daemon.pid, daemon.port, entity_count, daemon.repo_root
        );
        println!("  endpoint: {}", daemon.endpoint);
        println!("  heartbeat: {}", daemon.last_heartbeat_at);
    }
    Ok(())
}

/// Remove stale entries (paths that no longer contain .kin/).
pub async fn clean() -> Result<()> {
    let mut registry =
        KinRegistry::load().map_err(|e| anyhow::anyhow!("failed to load registry: {}", e))?;

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
