// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::ChangeStore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRequest {
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogResponse {
    #[serde(default)]
    pub lines: Vec<String>,
}

pub async fn run(count: usize) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let response = run_daemon_log(&layout, &LogRequest { count }).await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

async fn run_daemon_log(layout: &kin_core::KinLayout, request: &LogRequest) -> Result<LogResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for log but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.log(request).await.context("daemon log failed")
}

pub fn build_log_response(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &LogRequest,
) -> Result<LogResponse> {
    let current = kin_core::read_current_branch(layout)?;
    let branch = graph
        .get_branch(&current)?
        .ok_or_else(|| anyhow::anyhow!("branch '{}' not found", current))?;

    let mut lines = vec![
        format!("Semantic change log (branch: {}):", branch.name),
        format!("  Head: {}", branch.head),
    ];

    // Walk the change DAG from head
    let mut current_id = Some(branch.head);
    let mut shown = 0usize;

    while let Some(id) = current_id {
        if shown >= request.count {
            break;
        }
        if let Some(change) = graph.get_change(&id)? {
            lines.push(String::new());
            lines.push(format!("  {} - {}", change.id, change.message));
            lines.push(format!("    Author: {}", change.author));
            lines.push(format!("    Time: {}", change.timestamp));
            lines.push(format!(
                "    Entities: {} added/modified/removed",
                change.entity_deltas.len()
            ));
            shown += 1;
            current_id = change.parents.first().copied();
        } else {
            break;
        }
    }

    if shown == 0 {
        lines.push(String::new());
        lines.push("  (no changes found)".to_string());
    }

    Ok(LogResponse { lines })
}
