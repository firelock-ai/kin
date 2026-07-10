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
    pub hydrated_git_history: bool,
    pub hydrated_change_ids: Vec<kin_model::SemanticChangeId>,
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
    let cache = crate::commands::ref_lookup::GitHistoryClosureCache::default();
    execute_blame_request_cached(layout, graph, request, &cache, &mut || {})
}

pub fn execute_blame_request_cached(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &BlameRequest,
    closure_cache: &crate::commands::ref_lookup::GitHistoryClosureCache,
    before_first_insert: &mut dyn FnMut(),
) -> Result<BlameExecution> {
    execute_blame_request_cached_inner(
        layout,
        graph,
        request,
        closure_cache,
        before_first_insert,
        None,
    )
}

pub fn execute_blame_request_cached_cancellable(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &BlameRequest,
    closure_cache: &crate::commands::ref_lookup::GitHistoryClosureCache,
    before_first_insert: &mut dyn FnMut(),
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<BlameExecution> {
    execute_blame_request_cached_inner(
        layout,
        graph,
        request,
        closure_cache,
        before_first_insert,
        Some(cancelled),
    )
}

fn execute_blame_request_cached_inner(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &BlameRequest,
    closure_cache: &crate::commands::ref_lookup::GitHistoryClosureCache,
    before_first_insert: &mut dyn FnMut(),
    cancelled: Option<&std::sync::atomic::AtomicBool>,
) -> Result<BlameExecution> {
    let ensure_not_cancelled = || -> Result<()> {
        if cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
            anyhow::bail!("blame request cancelled");
        }
        Ok(())
    };
    ensure_not_cancelled()?;
    let resolved =
        crate::commands::ref_lookup::resolve_ref_importing_git_if_needed_with_report_cached(
            graph,
            layout,
            request.reference.as_deref(),
            closure_cache,
            before_first_insert,
        )?;
    ensure_not_cancelled()?;
    let head = resolved.head;
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
    ensure_not_cancelled()?;

    if revisions.is_empty() {
        lines.push("  No history recorded for this entity.".to_string());
        return Ok(BlameExecution {
            response: BlameResponse { lines },
            hydrated_git_history: resolved.hydrated_git_history,
            hydrated_change_ids: resolved.hydrated_change_ids,
        });
    }

    lines.push(format!(
        "{:<36}  {:<36}  {:<20}  {:<15}  MESSAGE",
        "REVISION", "CHANGE", "TIMESTAMP", "AUTHOR"
    ));
    lines.push("-".repeat(140));

    for revision in &revisions {
        ensure_not_cancelled()?;
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

    Ok(BlameExecution {
        response: BlameResponse { lines },
        hydrated_git_history: resolved.hydrated_git_history,
        hydrated_change_ids: resolved.hydrated_change_ids,
    })
}
