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

/// One rendered revision, before the author column has been sized.
struct RevisionRow {
    id: String,
    when: String,
    who: String,
    subject: String,
}

/// Render the revision rows with an author column sized to the widest author
/// present.
///
/// The column is measured rather than fixed because an author is an identity,
/// and half an identity answers nobody. An MCP commit is authored by
/// `{vendor}/{client_name}`, so a fixed column cut exactly the client name, the
/// half that tells two sessions of one vendor apart, and an unregistered
/// session left nineteen characters of a UUID. The date column stays fixed
/// because a calendar date is always ten characters wide, and the subject is
/// last so nothing after it needs padding: a wide terminal spends its extra
/// columns on the message rather than on trailing space.
fn render_revision_rows(rows: &[RevisionRow]) -> Vec<String> {
    let author_width = rows
        .iter()
        .map(|row| row.who.chars().count())
        .max()
        .unwrap_or(0);
    rows.iter()
        .map(|row| {
            format!(
                "  {}  {:<10}  {:<author_width$}  {}",
                row.id, row.when, row.who, row.subject
            )
        })
        .collect()
}

pub async fn run(entity: String, reference: Option<String>) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let response = run_daemon_history(&layout, &HistoryRequest { entity, reference }).await?;
    for line in response.lines {
        println!("{}", crate::output_style::paint_history_line(&line));
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
    let base_url =
        daemon_url.ok_or_else(|| crate::daemon_client::daemon_required_error("history", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .history(request)
        .await
        .context("daemon history failed")
}

pub fn execute_history_request(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &kin_db::InMemoryGraph,
    request: &HistoryRequest,
) -> Result<HistoryResponse> {
    let head =
        crate::commands::ref_lookup::resolve_ref(graph, binding, request.reference.as_deref())?;
    let (target, revisions) = match request.reference.as_deref() {
        Some(_) => crate::commands::ref_lookup::resolve_entity_with_revisions_at(
            graph,
            &request.entity,
            &head,
        )?,
        None => {
            let target = crate::commands::ref_lookup::resolve_entity_query(graph, &request.entity)?;
            let revisions =
                crate::commands::ref_lookup::resolve_entity_revisions_at(graph, &target.id, &head)?;
            (target, revisions)
        }
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

    if revisions.is_empty() {
        lines.push("  No history recorded".to_string());
    } else {
        let mut rows = Vec::with_capacity(revisions.len());
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
            rows.push(RevisionRow {
                id: abbreviate_id(&revision.introduced_by.to_string()),
                when,
                who,
                subject,
            });
        }
        lines.extend(render_revision_rows(&rows));
    }

    Ok(HistoryResponse { lines })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(who: &str, subject: &str) -> RevisionRow {
        RevisionRow {
            id: "0123456789ab".to_string(),
            when: "2026-07-31".to_string(),
            who: author_name(who),
            subject: subject.to_string(),
        }
    }

    /// Column each row's subject starts at, which is what "aligned" means here.
    fn subject_column(line: &str, subject: &str) -> usize {
        line.char_indices()
            .position(|(offset, _)| line[offset..].starts_with(subject))
            .expect("every rendered row carries its subject")
    }

    #[test]
    fn an_agent_identity_is_never_cut_to_fit_the_author_column() {
        // Both values are what `kin history` actually shows for an MCP commit:
        // the registered `{vendor}/{client_name}`, and the session id an
        // unregistered session falls back to. Neither fits twenty columns, and
        // the part a fixed column removed was the part that identifies the
        // session rather than the vendor.
        let client = "claude-code/one-change-demo";
        let session = "3f2a9c8e-7b41-4c2d-9e05-1a6b8c3d4e5f";
        assert!(client.chars().count() > 20 && session.chars().count() > 20);

        let rendered = render_revision_rows(&[
            row(
                &format!("{client} <mcp-agent:{session}>"),
                "Rename the parser entry point",
            ),
            row(
                &format!("{session} <mcp-agent:{session}>"),
                "Seed the graph",
            ),
        ]);

        for (line, who) in rendered.iter().zip([client, session]) {
            assert!(
                line.contains(who),
                "the author column must carry the whole identity: {line}"
            );
        }
        assert!(
            !rendered.iter().any(|line| line.contains('…')),
            "no identity may be ellipsized: {rendered:?}"
        );
    }

    #[test]
    fn the_author_column_is_sized_from_the_widest_author_so_subjects_stay_aligned() {
        // Growing the column is only worth doing if the table still reads as a
        // table: every subject has to start in the same place regardless of how
        // long its row's author is.
        let rendered = render_revision_rows(&[
            row("kin <kin@firelock.ai>", "short author"),
            row("claude-code/one-change-demo <mcp-agent:abc>", "long author"),
        ]);

        assert_eq!(
            subject_column(&rendered[0], "short author"),
            subject_column(&rendered[1], "long author"),
            "subjects must line up: {rendered:?}"
        );
        // Nothing is padded past the widest author, so a history of short
        // authors does not pay for a column no row needs.
        assert!(
            rendered[1].contains("claude-code/one-change-demo  long author"),
            "the widest author must be followed by the column gap alone: {}",
            rendered[1]
        );
    }
}
