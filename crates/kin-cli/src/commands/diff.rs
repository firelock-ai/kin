// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::ChangeStore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffRequest {
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub head: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResponse {
    #[serde(default)]
    pub lines: Vec<String>,
}

pub async fn run(base: Option<String>, head: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let response = run_daemon_diff(&layout, &DiffRequest { base, head }).await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

async fn run_daemon_diff(
    layout: &kin_core::KinLayout,
    request: &DiffRequest,
) -> Result<DiffResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for diff but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.diff(request).await.context("daemon diff failed")
}

pub fn build_diff_response(
    graph: &kin_db::InMemoryGraph,
    request: &DiffRequest,
) -> Result<DiffResponse> {
    let mut lines = Vec::new();
    match (&request.base, &request.head) {
        (Some(b), Some(h)) => {
            let base_id = kin_model::SemanticChangeId::from_hash(
                kin_model::Hash256::from_hex(b)
                    .map_err(|e| anyhow::anyhow!("invalid base hash: {}", e))?,
            );
            let head_id = kin_model::SemanticChangeId::from_hash(
                kin_model::Hash256::from_hex(h)
                    .map_err(|e| anyhow::anyhow!("invalid head hash: {}", e))?,
            );
            let changes = graph.get_changes_since(&base_id, &head_id)?;
            lines.push(format!("Changes between {} and {}:", b, h));
            for change in &changes {
                lines.push(format!("  {} - {}", change.id, change.message));
                for delta in &change.entity_deltas {
                    match delta {
                        kin_model::change::EntityDelta::Added(e) => {
                            lines.push(format!("    + {} ({:?})", e.name, e.kind))
                        }
                        kin_model::change::EntityDelta::Modified { old, new } => lines.push(
                            format!("    ~ {} -> {} ({:?})", old.name, new.name, new.kind),
                        ),
                        kin_model::change::EntityDelta::Removed(id) => {
                            lines.push(format!("    - {}", id))
                        }
                    }
                }
            }
        }
        _ => {
            lines.push("Usage: kin diff <base> <head>".to_string());
            lines.push("Shows entity-level diff between two semantic changes.".to_string());
        }
    }

    Ok(DiffResponse { lines })
}
