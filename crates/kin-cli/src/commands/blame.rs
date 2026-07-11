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

pub struct BlameExecution {
    pub response: BlameResponse,
    /// Count of historical changes resolving this request's ref lazily
    /// hydrated into the graph (0 when the ref was already present, or when
    /// no ref was supplied and the current head resolved with no import).
    /// Reported as a real count rather than a swallowed "did anything
    /// hydrate" boolean, so a cold multi-thousand-change import is never
    /// described the same way as a no-op: daemon owners persist the hydrated
    /// state and broadcast the growth on this count being non-zero.
    pub hydrated_changes: usize,
}

/// Ref-resolution result prepared before blame rendering begins.
///
/// Resolving an unimported Git ref mutates the supplied graph. Daemon callers
/// must acknowledge `hydrated_changes` (persisting HEAD-owned graphs, or
/// retaining the mutation only in a scoped session graph) before calling
/// [`render_prepared_blame_request`], because entity lookup and rendering can
/// still fail after hydration has succeeded.
#[derive(Debug)]
pub struct PreparedBlameRequest {
    resolution: crate::commands::ref_lookup::PreparedRefResolution,
}

impl PreparedBlameRequest {
    pub fn hydrated_changes(&self) -> usize {
        self.resolution.hydrated_changes
    }
}

/// `kin blame <entity>` — Show who/when each version of an entity was committed.
pub async fn run(entity: String, reference: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
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
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for blame but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.blame(request).await.context("daemon blame failed")
}

pub fn execute_blame_request(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &BlameRequest,
) -> Result<BlameExecution> {
    let prepared = prepare_blame_request(layout, graph, request)?;
    let hydrated_changes = prepared.hydrated_changes();
    let response = render_prepared_blame_request(graph, request, prepared)?;
    Ok(BlameExecution {
        response,
        hydrated_changes,
    })
}

pub fn prepare_blame_request(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &BlameRequest,
) -> Result<PreparedBlameRequest> {
    let resolution = crate::commands::ref_lookup::prepare_ref_importing_git_if_needed_with_report(
        graph,
        layout,
        request.reference.as_deref(),
    );
    Ok(PreparedBlameRequest { resolution })
}

pub fn render_prepared_blame_request(
    graph: &kin_db::InMemoryGraph,
    request: &BlameRequest,
    prepared: PreparedBlameRequest,
) -> Result<BlameResponse> {
    let head = prepared.resolution.into_result()?.head;
    let target = match request.reference.as_deref() {
        Some(_) => {
            crate::commands::ref_lookup::resolve_entity_query_at_ref(graph, &request.entity, &head)?
        }
        None => crate::commands::ref_lookup::resolve_entity_query(graph, &request.entity)?,
    };
    let mut lines = Vec::new();
    lines.push(format!(
        "Blame for '{}' ({:?}, {}) at {}:",
        target.name, target.kind, target.language, head
    ));
    lines.push(String::new());

    let revisions = graph.get_entity_revisions_at(&target.id, &head)?;

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
