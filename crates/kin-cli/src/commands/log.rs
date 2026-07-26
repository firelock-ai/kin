// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
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
    _layout: &kin_core::KinLayout,
    _graph: &kin_db::InMemoryGraph,
    _request: &LogRequest,
) -> Result<LogResponse> {
    anyhow::bail!(
        "log is fail-closed until its daemon executor resolves the active repository-v6 \
         workspace/ref and immutable change DAG; inspect `kin capabilities --json`"
    )
}
