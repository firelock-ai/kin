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
    pub hydrated_git_history: bool,
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
    let resolved = crate::commands::ref_lookup::resolve_ref_importing_git_if_needed_with_report(
        graph,
        layout,
        request.reference.as_deref(),
    )?;
    let head = resolved.head;
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

    Ok(HistoryExecution {
        response: HistoryResponse { lines },
        hydrated_git_history: resolved.hydrated_git_history,
    })
}
