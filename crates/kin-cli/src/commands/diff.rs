// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
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
    _graph: &kin_db::InMemoryGraph,
    _request: &DiffRequest,
) -> Result<DiffResponse> {
    anyhow::bail!(
        "diff is fail-closed until its daemon executor compares exact repository-v6 trees and \
         semantic changes together; inspect `kin capabilities --json`"
    )
}
