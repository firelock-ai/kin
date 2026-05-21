// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::EntityFilter;
use kin_model::EntityStore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefRequest {
    pub entity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefResponse {
    #[serde(default)]
    pub lines: Vec<String>,
}

pub async fn run(entity: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let response = run_daemon_xref(&layout, &XrefRequest { entity }).await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

async fn run_daemon_xref(
    layout: &kin_core::KinLayout,
    request: &XrefRequest,
) -> Result<XrefResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for xref but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.xref(request).await.context("daemon xref failed")
}

pub async fn build_xref_response(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &XrefRequest,
) -> Result<XrefResponse> {
    // Find the entity by name
    let filter = EntityFilter {
        name_pattern: Some(request.entity.clone()),
        ..Default::default()
    };
    let matches = graph.query_entities(&filter)?;

    if matches.is_empty() {
        return Ok(XrefResponse {
            lines: vec![format!("Entity '{}' not found", request.entity)],
        });
    }

    let target = &matches[0];
    let mut lines = vec![format!(
        "Cross-repo references (xrefs) for '{}':",
        target.name
    )];

    let repo_id = crate::commands::remote::resolve_repo_id(layout)?;

    match crate::backend::get_spine_xref(layout, &repo_id, &target.id).await {
        Ok(Some(edges)) if !edges.is_empty() => {
            lines.push(format!("  Found {} cross-repo edges:", edges.len()));
            for edge in edges {
                lines.push(format!(
                    "    - Impact: [{}] {} depends on us ([{}] {}) (conf: {:.2})",
                    edge.src_repo, edge.src_entity, edge.dst_repo, edge.dst_entity, edge.confidence
                ));
            }
        }
        Ok(_) => {
            lines.push("  No cross-repo references found in the spine.".to_string());
        }
        Err(e) => {
            lines.push(format!("  Failed to query spine: {}", e));
        }
    }

    Ok(XrefResponse { lines })
}
