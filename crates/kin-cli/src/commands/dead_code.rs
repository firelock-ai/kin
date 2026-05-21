// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::EntityStore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeadCodeRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadCodeResponse {
    #[serde(default)]
    pub lines: Vec<String>,
}

pub async fn run() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let response = run_daemon_dead_code(&layout).await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

async fn run_daemon_dead_code(layout: &kin_core::KinLayout) -> Result<DeadCodeResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!(
            "Kin daemon is required for dead-code scan but no daemon endpoint is available"
        )
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .dead_code(&DeadCodeRequest::default())
        .await
        .context("daemon dead-code scan failed")
}

pub fn build_dead_code_response(graph: &kin_db::InMemoryGraph) -> Result<DeadCodeResponse> {
    let mut lines = vec!["Scanning for dead code...".to_string()];

    let dead = graph.find_dead_code()?;
    if dead.is_empty() {
        lines.push("No dead code found.".to_string());
    } else {
        lines.push(format!("Found {} unreferenced entities:", dead.len()));
        for e in &dead {
            lines.push(format!(
                "  {} ({:?}, {}) - {}",
                e.name,
                e.kind,
                e.language,
                e.file_origin
                    .as_ref()
                    .map(|f| f.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            ));
        }
    }

    Ok(DeadCodeResponse { lines })
}
