// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::ChangeStore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlameRequest {
    pub entity: String,
    #[serde(default)]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlameResponse {
    pub lines: Vec<String>,
}

/// `kin blame <entity>` — Show who/when each version of an entity was committed.
pub async fn run(entity: String, reference: Option<String>) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let response = run_daemon_blame(&layout, &BlameRequest { entity, reference }).await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

async fn run_daemon_blame(
    layout: &kin_core::KinLayout,
    request: &BlameRequest,
) -> Result<BlameResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url =
        daemon_url.ok_or_else(|| crate::daemon_client::daemon_required_error("blame", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.blame(request).await.context("daemon blame failed")
}

pub fn execute_blame_request(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &kin_db::InMemoryGraph,
    request: &BlameRequest,
) -> Result<BlameResponse> {
    let head =
        crate::commands::ref_lookup::resolve_ref(graph, binding, request.reference.as_deref())?;
    let (target, revisions) = match request.reference.as_deref() {
        Some(_) => crate::commands::ref_lookup::resolve_entity_with_revisions_at(
            graph,
            &request.entity,
            &head,
        )?,
        None => {
            let target = crate::commands::ref_lookup::resolve_entity_query(graph, &request.entity)?;
            let revisions =
                crate::commands::ref_lookup::resolve_entity_revisions_at(graph, &target.id, &head)?;
            (target, revisions)
        }
    };
    let mut lines = Vec::new();
    lines.push(format!(
        "Blame for '{}' ({:?}, {}) at {}:",
        target.name, target.kind, target.language, head
    ));
    lines.push(String::new());

    if revisions.is_empty() {
        lines.push("  No history recorded for this entity.".to_string());
        return Ok(BlameResponse { lines });
    }

    lines.push(format!(
        "{:<36}  {:<36}  {:<20}  {:<15}  MESSAGE",
        "REVISION", "CHANGE", "TIMESTAMP", "AUTHOR"
    ));
    lines.push("-".repeat(140));

    for revision in &revisions {
        let Some(change) = graph.get_change(&revision.introduced_by)? else {
            continue;
        };
        lines.push(format!(
            "{:<36}  {:<36}  {:<20}  {:<15}  {}",
            revision.revision_id, change.id, change.timestamp, change.author, change.message,
        ));
    }

    lines.push(format!("\n{} version(s) found.", revisions.len()));

    lines.push(format!("\nState at {}:", head));
    lines.push(format!("  Signature: {}", target.signature));
    lines.push(format!("  Visibility: {:?}", target.visibility));
    if let Some(ref file) = target.file_origin {
        lines.push(format!("  File: {}", file));
    }
    if let Some(ref doc) = target.doc_summary {
        lines.push(format!("  Doc: {}", doc));
    }

    Ok(BlameResponse { lines })
}
