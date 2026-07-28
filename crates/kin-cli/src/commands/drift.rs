// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wire types and CLI transport for daemon-owned projection drift reporting.
//!
//! Drift compares the derived working-copy projection against the exact
//! workspace tree repository-v6 authority owns. Content for every compared path
//! is loaded from repository authority, never from the working copy, and paths
//! the workspace tree does not track are never read: untracked host bytes are
//! not graph-owned, so they cannot drift. The observation is bound to one exact
//! workspace generation and is refused rather than reported when authority
//! moves underneath it.

use anyhow::Result;
use kin_model::{RepositoryId, RootBundle, WorkspaceHead, WorkspaceId};
use serde::{Deserialize, Serialize};

pub const DRIFT_SCHEMA: &str = "kin.projection-drift.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftRequest {
    #[serde(default)]
    pub json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DriftReport {
    pub schema: String,
    pub authority: String,
    pub repository_id: RepositoryId,
    pub authority_generation: u64,
    pub roots: RootBundle,
    pub workspace_id: WorkspaceId,
    pub workspace_generation: u64,
    pub workspace_head: WorkspaceHead,
    /// Tracked members of the exact workspace tree, including members this host
    /// cannot materialize.
    pub tracked_artifacts: usize,
    /// Materializable tracked members actually compared against the projection.
    pub compared_entries: usize,
    pub drift_count: usize,
    pub drift: Vec<String>,
    pub clean: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<DriftReport>,
}

pub async fn run(json: bool) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?).ok_or_else(|| {
        anyhow::anyhow!(
            "not a Kin repository (no .kin/ found)\nhint: run `kin init .` to initialize a Kin repository here"
        )
    })?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Kin daemon is required for projection drift reporting but no daemon endpoint is \
                 available"
            )
        })?;
    let daemon = crate::daemon_client::DaemonClient::from_base_url_for_layout(daemon_url, &layout)?;
    let response = daemon.drift(&DriftRequest { json }).await?;
    if json {
        let report = response
            .report
            .ok_or_else(|| anyhow::anyhow!("daemon drift response omitted its report"))?;
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for line in response.lines {
            println!("{line}");
        }
    }
    Ok(())
}

pub fn render_lines(report: &DriftReport) -> Vec<String> {
    let mut lines = vec![
        "Kin repository-v6 projection drift".to_string(),
        format!("Authority generation: {}", report.authority_generation),
        format!(
            "Workspace {} generation {} ({})",
            report.workspace_id,
            report.workspace_generation,
            render_head(&report.workspace_head)
        ),
        format!(
            "Compared {} of {} tracked artifact(s) against graph-owned content",
            report.compared_entries, report.tracked_artifacts
        ),
    ];
    if report.clean {
        lines.push("No drift: the derived projection matches graph authority.".to_string());
        return lines;
    }
    lines.push(format!(
        "{} tracked path(s) diverge from graph-owned workspace truth:",
        report.drift_count
    ));
    for detail in &report.drift {
        lines.push(format!("  {detail}"));
    }
    lines.push(
        "Restore graph truth with `kin checkout <path>`, or admit the working-copy state with \
         `kin commit`."
            .to_string(),
    );
    lines
}

fn render_head(head: &WorkspaceHead) -> String {
    match head {
        WorkspaceHead::Symbolic { target } => format!("on {target}"),
        WorkspaceHead::Detached { .. } => "detached".to_string(),
    }
}
