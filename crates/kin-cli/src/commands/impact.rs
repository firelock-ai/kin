// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::EntityFilter;
use kin_model::EntityStore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactRequest {
    pub entity: String,
    pub depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactResponse {
    pub lines: Vec<String>,
}

pub async fn run(entity: String, depth: u32) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let response = run_daemon_impact(&layout, &ImpactRequest { entity, depth }).await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

async fn run_daemon_impact(
    layout: &kin_core::KinLayout,
    request: &ImpactRequest,
) -> Result<ImpactResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for impact but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.impact(request).await.context("daemon impact failed")
}

pub async fn build_impact_response(
    _layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &ImpactRequest,
) -> Result<ImpactResponse> {
    // Find the entity by name
    let filter = EntityFilter {
        name_pattern: Some(request.entity.clone()),
        ..Default::default()
    };
    let matches = graph.query_entities(&filter)?;

    if matches.is_empty() {
        return Ok(ImpactResponse {
            lines: vec![format!("Entity '{}' not found", request.entity)],
        });
    }

    let target = &matches[0];
    let mut lines = vec![
        format!("Impact analysis for '{}' ({:?}):", target.name, target.kind),
        format!("  Depth: {}", request.depth),
    ];

    // 1. Local Impact
    let local_impacted = graph.get_downstream_impact(&target.id, request.depth)?;
    if local_impacted.is_empty() {
        lines.push("  No local downstream impact found.".to_string());
    } else {
        lines.push(format!(
            "  {} local entities impacted:",
            local_impacted.len()
        ));
        for e in &local_impacted {
            lines.push(format!("    - {} ({:?}, {})", e.name, e.kind, e.language));
        }
    }

    Ok(ImpactResponse { lines })
}
