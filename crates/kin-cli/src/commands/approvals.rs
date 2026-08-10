// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::ProvenanceStore;
use kin_model::{Hash256, SemanticChangeId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum ApprovalsRequest {
    Show { change_id: String },
    List,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalsResponse {
    #[serde(default)]
    pub lines: Vec<String>,
}

/// `kin approvals <change-id>` — Show approvals for a specific change.
pub async fn show(change_id: String) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    print_approvals_response(
        run_daemon_approvals(&layout, &ApprovalsRequest::Show { change_id }).await?,
    )
}

/// `kin approvals list` — Show all actors and their delegation counts.
pub async fn list() -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    print_approvals_response(run_daemon_approvals(&layout, &ApprovalsRequest::List).await?)
}

async fn run_daemon_approvals(
    layout: &kin_core::KinLayout,
    request: &ApprovalsRequest,
) -> Result<ApprovalsResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url
        .ok_or_else(|| crate::daemon_client::daemon_required_error("approvals", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .approvals(request)
        .await
        .context("daemon approvals failed")
}

fn print_approvals_response(response: ApprovalsResponse) -> Result<()> {
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

pub fn build_approvals_response(
    graph: &kin_db::InMemoryGraph,
    request: &ApprovalsRequest,
) -> Result<ApprovalsResponse> {
    match request {
        ApprovalsRequest::Show { change_id } => build_approvals_show_response(graph, change_id),
        ApprovalsRequest::List => build_approvals_list_response(graph),
    }
}

fn build_approvals_show_response(
    graph: &kin_db::InMemoryGraph,
    change_id: &str,
) -> Result<ApprovalsResponse> {
    let id = parse_change_id(change_id)?;
    let approvals = graph.get_approvals_for_change(&id)?;

    if approvals.is_empty() {
        return Ok(ApprovalsResponse {
            lines: vec![format!("No approvals found for change {}", change_id)],
        });
    }

    let mut lines = vec![
        format!(
            "{:<14}  {:<14}  {:<12}  {:<20}  REASON",
            "APPROVAL", "APPROVER", "DECISION", "TIMESTAMP"
        ),
        "-".repeat(90),
    ];

    for approval in &approvals {
        let approval_short = &approval.approval_id.to_string()[..12];
        let approver_short = &approval.approver.to_string()[..12];

        lines.push(format!(
            "{:<14}  {:<14}  {:<12}  {:<20}  {}",
            approval_short, approver_short, approval.decision, approval.timestamp, approval.reason,
        ));
    }

    lines.push(String::new());
    lines.push(format!("{} approval(s)", approvals.len()));
    Ok(ApprovalsResponse { lines })
}

fn build_approvals_list_response(graph: &kin_db::InMemoryGraph) -> Result<ApprovalsResponse> {
    let actors = graph.list_actors()?;

    if actors.is_empty() {
        return Ok(ApprovalsResponse {
            lines: vec!["No actors registered.".to_string()],
        });
    }

    let mut lines = vec![
        format!(
            "{:<14}  {:<12}  {:<20}  DELEGATIONS",
            "ACTOR", "KIND", "NAME"
        ),
        "-".repeat(65),
    ];

    for actor in &actors {
        let actor_short = &actor.actor_id.to_string()[..12];
        let delegations = graph.get_delegations_for_actor(&actor.actor_id)?;

        lines.push(format!(
            "{:<14}  {:<12}  {:<20}  {}",
            actor_short,
            actor.kind,
            actor.display_name,
            delegations.len(),
        ));
    }

    lines.push(String::new());
    lines.push(format!("{} actor(s)", actors.len()));
    Ok(ApprovalsResponse { lines })
}

fn parse_change_id(s: &str) -> Result<SemanticChangeId> {
    let hash = Hash256::from_hex(s)
        .map_err(|_| anyhow::anyhow!("invalid change ID (expected 64 hex chars): {}", s))?;
    Ok(SemanticChangeId::from_hash(hash))
}
