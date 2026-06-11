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
            lines: impact_not_found_guidance(&request.entity),
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

/// Actionable guidance when `kin impact <symbol>` can't resolve the symbol in
/// this repo's graph. Keeps the not-found signal, then offers concrete next
/// steps: a name/semantic search to find the right symbol, and a note that
/// impact analysis is local-graph-scoped (cross-repo dependents live behind
/// `kin xref`). Honest by construction — no claim the symbol exists elsewhere.
fn impact_not_found_guidance(entity: &str) -> Vec<String> {
    vec![
        format!("Entity '{entity}' not found in this repo's graph."),
        format!(
            "hint: try `kin search {entity}` to find the symbol by name, or check the spelling."
        ),
        "      `kin impact` analyzes LOCAL downstream impact; for cross-repo dependents use `kin xref`."
            .to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::impact_not_found_guidance;

    #[test]
    fn impact_not_found_guidance_keeps_signal_and_offers_next_steps() {
        let lines = impact_not_found_guidance("frobnicate");
        assert!(
            lines[0].contains("not found"),
            "keeps not-found signal: {lines:?}"
        );
        let joined = lines.join("\n");
        assert!(
            joined.contains("kin search frobnicate"),
            "offers a search next step: {joined}"
        );
        assert!(
            joined.contains("kin xref"),
            "notes cross-repo path: {joined}"
        );
    }
}
