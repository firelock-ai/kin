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
pub struct ConflictsRequest {
    /// Materialize each conflict subject's three sides as source.
    ///
    /// Defaulted, so a client that sends `{}` keeps today's behaviour and
    /// today's cost. Reading bodies resolves the graph at three changes and
    /// reads a blob per side, which a listing does not otherwise do.
    #[serde(default)]
    pub bodies: bool,
}

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
    /// One entry per conflict subject whose sides could be materialized, in the
    /// listing's own order. Empty unless the request asked for bodies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bodies: Vec<ConflictBody>,
}

/// One conflict subject's three sides, as the source each side actually holds.
///
/// The record itself carries only a `Hash256` per side, which is a digest of
/// the model value and not a content address: it cannot be resolved to bytes by
/// any lookup. These are re-materialized from the graph at the three changes the
/// merge bound, which is why each side is checked back against its recorded
/// digest before it is offered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictBody {
    /// The subject as the listing names it, so a reader can pair a body with
    /// the row it belongs to without re-deriving the identity.
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// `None` means the identity is absent on that side, which is a real
    /// answer. A side that could not be verified is named in `unverified` and
    /// is `None` here too, so the two are never confused by a reader that only
    /// looks at the body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ours: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theirs: Option<String>,
    /// Sides whose re-materialized value did not hash back to the digest the
    /// record holds, or whose bytes could not be read. Named rather than
    /// silently omitted, because a body that is quietly missing reads exactly
    /// like an identity that is absent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unverified: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictsResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<ConflictsReport>,
}

pub async fn run(json: bool, show: bool) -> Result<()> {
    let response = execute(ConflictsRequest { bodies: show }).await?;
    if json {
        let report = response
            .report
            .ok_or_else(|| anyhow::anyhow!("daemon conflicts response omitted its report"))?;
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for line in response.lines {
            println!("{line}");
        }
        if show {
            let report = response.report.as_ref().ok_or_else(|| {
                anyhow::anyhow!("daemon conflicts response omitted its report")
            })?;
            for body in &report.bodies {
                print_body(body);
            }
        }
    }
    Ok(())
}

/// Print one subject's two decisions as diffs against the base.
///
/// Rendered against base rather than against each other because the question a
/// settlement answers is which side's departure from the common ancestor to
/// keep, and a diff of ours against theirs shows neither departure.
fn print_body(body: &ConflictBody) {
    println!();
    match &body.label {
        Some(label) => println!("{} ({})", label, body.subject),
        None => println!("{}", body.subject),
    }
    for side in &body.unverified {
        println!(
            "  {side}: not shown, because the value re-read from the graph did not hash back to \
             the digest this merge recorded"
        );
    }
    for (name, side) in [("ours", &body.ours), ("theirs", &body.theirs)] {
        if side.is_none() && body.unverified.iter().any(|entry| entry == name) {
            continue;
        }
        println!("  base -> {name}:");
        if body.base.is_none() && side.is_none() {
            println!("    (absent on both sides)");
            continue;
        }
        for line in crate::commands::diff::render_hunks(body.base.as_deref(), side.as_deref()) {
            println!("    {line}");
        }
    }
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
