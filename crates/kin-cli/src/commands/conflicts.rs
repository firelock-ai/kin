// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wire types and CLI transport for reading a workspace's durable merge record.
//!
//! The listing is the record itself, not a rendering of one. A conflict set
//! that lived only in the composing process could not survive a restart or be
//! resolved by a later session, so what this command returns is the exact
//! merge-transaction record repository authority holds for this workspace.

use anyhow::Result;
use kin_model::{MergeTransactionRecord, RepositoryId, WorkspaceId};
use serde::{Deserialize, Serialize};

pub const CONFLICTS_REPORT_SCHEMA: &str = "kin.conflicts.v1";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictsRequest {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictsReport {
    pub schema: String,
    pub authority: String,
    pub repository_id: RepositoryId,
    pub workspace_id: WorkspaceId,
    pub authority_generation: u64,
    /// The workspace's merge record, absent when no merge has ever opened on
    /// it. A terminated record is still returned: it is the durable account of
    /// the last merge, and "is a merge in progress" is a state check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<MergeTransactionRecord>,
    /// Hex identity of `record`, repeated so a caller can pass it back as the
    /// lease a later resolution is required to have been authored against. The
    /// record carries the same value as bytes; this is the form `kin resolve
    /// --expect` accepts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_hash: Option<String>,
    pub unresolved_count: usize,
    pub resolved_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictsResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<ConflictsReport>,
}

pub async fn run(json: bool) -> Result<()> {
    let response = execute(ConflictsRequest {}).await?;
    if json {
        let report = response
            .report
            .ok_or_else(|| anyhow::anyhow!("daemon conflicts response omitted its report"))?;
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for line in response.lines {
            println!("{line}");
        }
    }
    Ok(())
}

async fn execute(request: ConflictsRequest) -> Result<ConflictsResponse> {
    let layout = super::merge::require_repository_layout()?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| {
            crate::daemon_client::daemon_required_error("merge conflict state", &layout)
        })?;
    let daemon = crate::daemon_client::DaemonClient::from_base_url_for_layout(daemon_url, &layout)?;
    daemon.conflicts(&request).await
}
