// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_core::registry::KinRegistry;
use std::collections::HashSet;

use crate::daemon_client::{DaemonHomeScope, RegisteredRepoDaemon};

use super::deps;

#[derive(Debug, serde::Serialize)]
struct RegisteredRepoDaemonsOutput {
    supervisor_url: String,
    daemons: Vec<RegisteredRepoDaemon>,
}

/// Verify registry authority without reading or printing file contents.
pub async fn authority(json: bool, fix: bool, initialize: bool) -> Result<()> {
    let repaired = if fix {
        kin_core::registry::repair_registry_authority_permissions()
            .map_err(|e| anyhow::anyhow!("registry permission repair refused: {e}"))?
    } else {
        Vec::new()
    };
    let initialized = if initialize {
        kin_core::registry::initialize_registry_authority()
            .map_err(|e| anyhow::anyhow!("registry authority initialization refused: {e}"))?
    } else {
        Vec::new()
    };
    let report = kin_core::registry::inspect_registry_authority();
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for path in repaired {
            println!("Repaired mode to 0600: {}", path.display());
        }
        for path in initialized {
            println!("Initialized private authority: {}", path.display());
        }
        println!("Local registry authority:");
        for check in &report.checks {
            println!(
                "  {:<28} {:<24} {}",
                check.label,
                authority_state_label(check.state),
                check.path.display()
            );
            println!("    {}", check.detail);
        }
    }
    kin_core::registry::require_registry_authority_secure()
        .map_err(|e| anyhow::anyhow!(e.to_string()))
}

fn authority_state_label(state: kin_core::registry::RegistryAuthorityState) -> &'static str {
    use kin_core::registry::RegistryAuthorityState;
    match state {
        RegistryAuthorityState::Secure => "secure",
        RegistryAuthorityState::Absent => "absent",
        RegistryAuthorityState::RepairablePermissions => "repairable-permissions",
        RegistryAuthorityState::Unsafe => "unsafe",
        RegistryAuthorityState::Unsupported => "not-applicable",
    }
}

/// List all registered Kin repositories.
pub async fn list() -> Result<()> {
    let registry =
        KinRegistry::load().map_err(|e| anyhow::anyhow!("failed to load registry: {}", e))?;

    if registry.repos.is_empty() {
        println!("No registered repositories.");
        println!(
            "hint: `kin init` registers a repository when it runs; a repository initialized \
             before this build predates that and has no entry"
        );
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
pub async fn daemons(json: bool) -> Result<()> {
    let supervisor_url = crate::daemon_client::ensure_supervisor_running().await?;
    let daemons = crate::daemon_client::fetch_registered_daemons(&supervisor_url).await?;

    if json {
        let output = RegisteredRepoDaemonsOutput {
            supervisor_url,
            daemons,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    // One supervisor per machine, so this listing can span managed homes. Each
    // entry states which home it belongs to and whether that is the caller's.
    let caller_home = crate::daemon_client::caller_home_id();

    println!("Kin supervisor: {} (machine-wide)", supervisor_url);
    println!("This KIN_HOME:  {caller_home}");
    if daemons.is_empty() {
        println!("No repo daemons registered.");
        return Ok(());
    }

    println!(
        "{:<24} {:>6} {:>7} {:<22} PATH",
        "REPO", "PID", "PORT", "ENTITIES"
    );
    for daemon in daemons {
        let entity_count = daemon
            .graph_entity_count
            .map(format_count)
            .unwrap_or_else(|| "-".to_string());
        let label = if daemon.display_name.trim().is_empty() {
            daemon.repo_id.clone()
        } else {
            daemon.display_name.clone()
        };
        println!(
            "{:<24} {:>6} {:>7} {:<22} {}",
            label, daemon.pid, daemon.port, entity_count, daemon.repo_root
        );
        println!("  route: {}", daemon.repo_id);
        if !daemon.instance_id.trim().is_empty() {
            println!("  instance: {}", daemon.instance_id);
        }
        println!("  endpoint: {}", daemon.endpoint);
        println!(
            "  kin home: {} ({})",
            daemon.home_label(),
            match daemon.home_scope(&caller_home) {
                DaemonHomeScope::Own => "this KIN_HOME",
                DaemonHomeScope::Foreign => "other KIN_HOME",
                DaemonHomeScope::Unrecorded => "home unrecorded",
            }
        );
        println!("  heartbeat: {}", daemon.last_heartbeat_at);
    }
    Ok(())
}

/// Remove stale entries (paths that no longer contain .kin/).
pub async fn clean() -> Result<()> {
    let removed = KinRegistry::update(KinRegistry::clean)
        .map_err(|e| anyhow::anyhow!("failed to update registry: {}", e))?;

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
