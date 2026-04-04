// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::provenance::ActorId;
use kin_model::Hash256;
use kin_model::ProvenanceStore;

enum ActorFilter {
    Exact(ActorId),
    Prefix(String),
}

/// Additional audit filters beyond actor.
#[derive(Default)]
pub struct AuditFilters {
    pub action: Option<String>,
    pub since: Option<String>,
    pub scope: Option<String>,
}

/// `kin audit` — List recent audit events with optional filters.
pub async fn run_with_filters(
    actor: Option<String>,
    limit: usize,
    filters: AuditFilters,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = &*_snap.graph();

    let actor_filter = actor.as_deref().map(parse_actor_filter).transpose()?;

    let fetch_limit = match actor_filter {
        Some(ActorFilter::Prefix(_)) => limit.max(100),
        _ => limit,
    };

    let actor_id = match &actor_filter {
        Some(ActorFilter::Exact(actor_id)) => Some(actor_id),
        _ => None,
    };

    let all_events = graph.query_audit_events(actor_id, fetch_limit)?;

    // Apply client-side filters for action, since, and scope
    let events: Vec<_> = all_events
        .into_iter()
        .filter(|event| {
            if let Some(ActorFilter::Prefix(prefix)) = &actor_filter {
                let full = event.actor_id.to_string();
                let short = if full.len() >= 12 { &full[..12] } else { &full };
                if !full.starts_with(prefix) && !short.starts_with(prefix) {
                    return false;
                }
            }
            // --action filter
            if let Some(ref action_filter) = filters.action {
                if !event.action.contains(action_filter.as_str()) {
                    return false;
                }
            }
            // --since filter (ISO 8601 date string comparison)
            if let Some(ref since_str) = filters.since {
                let event_ts = event.timestamp.to_string();
                if event_ts.as_str() < since_str.as_str() {
                    return false;
                }
            }
            // --scope filter (match target scope string representation)
            if let Some(ref scope_filter) = filters.scope {
                match &event.target_scope {
                    Some(scope) => {
                        let scope_str = scope.to_string();
                        if !scope_str.contains(scope_filter.as_str()) {
                            return false;
                        }
                    }
                    None => return false,
                }
            }
            true
        })
        .take(limit)
        .collect();

    if events.is_empty() {
        println!("No audit events found.");
        return Ok(());
    }

    println!(
        "{:<20}  {:<14}  {:<16}  {:<24}  DETAILS",
        "TIMESTAMP", "ACTOR", "ACTION", "TARGET"
    );
    println!("{}", "-".repeat(100));

    for event in &events {
        let actor_str = event.actor_id.to_string();
        let actor_short = if actor_str.len() >= 12 {
            &actor_str[..12]
        } else {
            &actor_str
        };
        let target = event
            .target_scope
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".to_string());
        let details = event.details.as_deref().unwrap_or("-");

        println!(
            "{:<20}  {:<14}  {:<16}  {:<24}  {}",
            event.timestamp, actor_short, event.action, target, details
        );
    }

    println!("\n{} event(s)", events.len());
    Ok(())
}

fn parse_actor_filter(s: &str) -> Result<ActorFilter> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        anyhow::bail!("invalid actor ID: value is empty");
    }
    if !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        anyhow::bail!(
            "invalid actor ID (expected hex actor hash or displayed prefix): {}",
            s
        );
    }
    if trimmed.len() == 64 {
        let hash = Hash256::from_hex(trimmed)
            .map_err(|_| anyhow::anyhow!("invalid actor ID (expected 64 hex chars): {}", s))?;
        Ok(ActorFilter::Exact(ActorId::from_hash(hash)))
    } else {
        Ok(ActorFilter::Prefix(trimmed.to_lowercase()))
    }
}
