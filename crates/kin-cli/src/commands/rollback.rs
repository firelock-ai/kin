// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wire types and CLI transport for daemon-owned repository-v6 rollback.
//!
//! Rollback moves history forward, never backward: it constructs a new change
//! whose content is exactly the target change's content, so the branch keeps
//! its complete immutable history and the repository ends up at a tree that
//! already existed. Every artifact identity in the result is the identity the
//! target already had, so no source is rewritten and no CAS entry is created.

use anyhow::Result;
use kin_model::{AuthorId, OperationId, RefName, RepositoryId};
use serde::{Deserialize, Serialize};

pub const ROLLBACK_SCHEMA: &str = "kin.rollback.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackRequest {
    /// Canonical lowercase hexadecimal change to restore.
    pub change_id: String,
    pub operation_id: OperationId,
    pub actor: AuthorId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RollbackReport {
    pub schema: String,
    pub authority: String,
    pub repository_id: RepositoryId,
    pub branch: RefName,
    /// The change whose content is restored.
    pub target_change_id: String,
    /// The change the branch pointed at before this rollback.
    pub previous_change_id: String,
    /// The new change this rollback published.
    pub inverse_change_id: String,
    pub authority_generation: u64,
    pub workspace_generation: u64,
    pub entity_deltas: usize,
    pub relation_deltas: usize,
    pub tree_deltas: usize,
    pub projected_entries: usize,
    pub idempotent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default)]
    pub mutated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<RollbackReport>,
}

pub async fn run(change_id: String, feature: Option<String>) -> Result<()> {
    if feature.is_some() {
        anyhow::bail!(
            "rolling back every change linked to a work item is not implemented; roll back to an \
             explicit change instead"
        );
    }
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?).ok_or_else(|| {
        anyhow::anyhow!(
            "not a Kin repository (no .kin/ found)\nhint: run `kin init .` to initialize a Kin repository here"
        )
    })?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Kin daemon is required for rollback but no daemon endpoint is available"
            )
        })?;
    let daemon = crate::daemon_client::DaemonClient::from_base_url_for_layout(daemon_url, &layout)?;
    let response = daemon
        .rollback(&RollbackRequest {
            change_id,
            operation_id: OperationId::new(),
            actor: AuthorId::new(kin_core::whoami()),
        })
        .await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

pub fn render_lines(report: &RollbackReport) -> Vec<String> {
    vec![
        format!(
            "Rolled {} back to change {}{}",
            report.branch,
            report.target_change_id,
            if report.idempotent {
                " (idempotent replay)"
            } else {
                ""
            }
        ),
        format!(
            "Published change {} over {}",
            report.inverse_change_id, report.previous_change_id
        ),
        format!(
            "Restored {} artifact(s), {} entity change(s), {} relation change(s); {} entries \
             projected",
            report.tree_deltas,
            report.entity_deltas,
            report.relation_deltas,
            report.projected_entries
        ),
        format!(
            "Authority generation {} (workspace generation {})",
            report.authority_generation, report.workspace_generation
        ),
    ]
}
