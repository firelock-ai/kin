// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::ChangeStore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryRequest {
    pub entity: String,
    #[serde(default)]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryResponse {
    pub lines: Vec<String>,
}

pub struct HistoryExecution {
    pub response: HistoryResponse,
    /// Count of historical changes resolving this request's ref lazily
    /// hydrated into the graph (0 when the ref was already present, or when
    /// no ref was supplied and the current head resolved with no import).
    /// Reported as a real count rather than a swallowed "did anything
    /// hydrate" boolean, so a cold multi-thousand-change import is never
    /// described the same way as a no-op: daemon owners persist the hydrated
    /// state and broadcast the growth on this count being non-zero.
    pub hydrated_changes: usize,
}

/// Ref-resolution result prepared before history rendering begins.
///
/// Resolving an unimported Git ref mutates the supplied graph. Daemon callers
/// must acknowledge `hydrated_changes` (persisting HEAD-owned graphs, or
/// retaining the mutation only in a scoped session graph) before calling
/// [`render_prepared_history_request`], because entity lookup and rendering can
/// still fail after hydration has succeeded.
#[derive(Debug)]
pub struct PreparedHistoryRequest {
    resolution: crate::commands::ref_lookup::PreparedRefResolution,
}

impl PreparedHistoryRequest {
    pub fn hydrated_changes(&self) -> usize {
        self.resolution.hydrated_changes
    }
}

pub async fn run(entity: String, reference: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let response = run_daemon_history(&layout, &HistoryRequest { entity, reference }).await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

async fn run_daemon_history(
    layout: &kin_core::KinLayout,
    request: &HistoryRequest,
) -> Result<HistoryResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for history but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .history(request)
        .await
        .context("daemon history failed")
}

pub fn execute_history_request(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &HistoryRequest,
) -> Result<HistoryExecution> {
    let prepared = prepare_history_request(layout, graph, request)?;
    let hydrated_changes = prepared.hydrated_changes();
    let response = render_prepared_history_request(graph, request, prepared)?;
    Ok(HistoryExecution {
        response,
        hydrated_changes,
    })
}

pub fn prepare_history_request(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &HistoryRequest,
) -> Result<PreparedHistoryRequest> {
    let resolution = crate::commands::ref_lookup::prepare_ref_importing_git_if_needed_with_report(
        graph,
        layout,
        request.reference.as_deref(),
    );
    Ok(PreparedHistoryRequest { resolution })
}

pub fn render_prepared_history_request(
    graph: &kin_db::InMemoryGraph,
    request: &HistoryRequest,
    prepared: PreparedHistoryRequest,
) -> Result<HistoryResponse> {
    let head = prepared.resolution.into_result()?.head;
    let target = match request.reference.as_deref() {
        Some(_) => {
            crate::commands::ref_lookup::resolve_entity_query_at_ref(graph, &request.entity, &head)?
        }
        None => crate::commands::ref_lookup::resolve_entity_query(graph, &request.entity)?,
    };
    let mut lines = vec![format!(
        "History for '{}' ({:?}, {}) at {}:",
        target.name, target.kind, target.language, head
    )];

    let revisions = graph.get_entity_revisions_at(&target.id, &head)?;
    if revisions.is_empty() {
        lines.push("  No history recorded".to_string());
    } else {
        for revision in &revisions {
            let change = graph.get_change(&revision.introduced_by)?;
            let message = change
                .as_ref()
                .map(|entry| entry.message.as_str())
                .unwrap_or("unknown");
            lines.push(format!(
                "  {} @ {} - {}",
                revision.revision_id, revision.introduced_by, message
            ));
        }
    }

    Ok(HistoryResponse { lines })
}
