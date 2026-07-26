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
    /// Count of historical changes resolving this request's ref lazily
    /// hydrated into the graph (0 when the ref was already present, or when
    /// no ref was supplied and the current head resolved with no import).
    /// Reported as a real count rather than a swallowed "did anything
    /// hydrate" boolean, so a cold multi-thousand-change import is never
    /// described the same way as a no-op: daemon owners persist the hydrated
    /// state and broadcast the growth on this count being non-zero.
    pub hydrated_changes: usize,
}

/// Ref-resolution result prepared before history rendering begins.
///
/// Resolving an unimported Git ref mutates the supplied graph. Daemon callers
/// must acknowledge `hydrated_changes` (persisting HEAD-owned graphs, or
/// retaining the mutation only in a scoped session graph) before calling
/// [`render_prepared_history_request`], because entity lookup and rendering can
/// still fail after hydration has succeeded.
#[derive(Debug)]
pub struct PreparedHistoryRequest {
    resolution: crate::commands::ref_lookup::PreparedRefResolution,
}

impl PreparedHistoryRequest {
    pub fn hydrated_changes(&self) -> usize {
        self.resolution.hydrated_changes
    }
}

/// Twelve hex characters, matching the width Kin already uses when it echoes a
/// change range back to the operator.
fn abbreviate_id(id: &str) -> String {
    id.chars().take(12).collect()
}

/// The first non-empty line of a commit message. Git calls this the subject and
/// renders exactly this in `--oneline`; the body belongs in a detail view, not
/// in a one-row-per-revision list.
fn subject_line(message: &str) -> String {
    message
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("(no message)")
        .to_string()
}

/// `YYYY-MM-DD` from an ISO-8601 timestamp. The clock time costs eleven columns
/// and tells you nothing an entity history is asked for; the date is what makes
/// a gap between two revisions legible.
fn calendar_date(timestamp: &str) -> String {
    timestamp
        .split('T')
        .next()
        .filter(|date| date.len() == 10)
        .unwrap_or(timestamp)
        .to_string()
}

/// Drop the `<email>` from a git-style author. The name identifies the person;
/// the address just eats the column and then gets ellipsized anyway.
fn author_name(author: &str) -> String {
    author
        .split('<')
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(author)
        .to_string()
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    let kept: String = value.chars().take(width.saturating_sub(1)).collect();
    format!("{kept}…")
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
    let prepared = prepare_history_request(layout, graph, request)?;
    let hydrated_changes = prepared.hydrated_changes();
    let response = render_prepared_history_request(graph, request, prepared)?;
    Ok(HistoryExecution {
        response,
        hydrated_changes,
    })
}

pub fn prepare_history_request(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &HistoryRequest,
) -> Result<PreparedHistoryRequest> {
    let resolution = crate::commands::ref_lookup::prepare_ref_importing_git_if_needed_with_report(
        graph,
        layout,
        request.reference.as_deref(),
    );
    Ok(PreparedHistoryRequest { resolution })
}

pub fn render_prepared_history_request(
    graph: &kin_db::InMemoryGraph,
    request: &HistoryRequest,
    prepared: PreparedHistoryRequest,
) -> Result<HistoryResponse> {
    let head = prepared.resolution.into_result()?.head;
    let target = match request.reference.as_deref() {
        Some(_) => {
            crate::commands::ref_lookup::resolve_entity_query_at_ref(graph, &request.entity, &head)?
        }
        None => crate::commands::ref_lookup::resolve_entity_query(graph, &request.entity)?,
    };
    // Identifiers are abbreviated and messages are reduced to their subject
    // line, the way `git log --oneline` does. Printing two full 64-character
    // hashes per row plus a whole commit body pushed every readable field off
    // the right edge and turned a three-entry history into a wall of hex.
    let mut lines = vec![format!(
        "History for '{}' ({:?}, {}) at {}:",
        target.name,
        target.kind,
        target.language,
        abbreviate_id(&head.to_string())
    )];

    let revisions = graph.get_entity_revisions_at(&target.id, &head)?;
    if revisions.is_empty() {
        lines.push("  No history recorded".to_string());
    } else {
        for revision in &revisions {
            let change = graph.get_change(&revision.introduced_by)?;
            let (when, who, subject) = match change.as_ref() {
                Some(entry) => (
                    calendar_date(&entry.timestamp.to_string()),
                    author_name(&entry.author.to_string()),
                    subject_line(&entry.message),
                ),
                None => ("?".to_string(), "?".to_string(), "unknown".to_string()),
            };
            lines.push(format!(
                "  {}  {:<10}  {:<20}  {}",
                abbreviate_id(&revision.introduced_by.to_string()),
                when,
                truncate(&who, 20),
                subject
            ));
        }
    }

    Ok(HistoryResponse { lines })
}
