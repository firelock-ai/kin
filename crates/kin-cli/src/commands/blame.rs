// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::ChangeStore;
use serde::{Deserialize, Serialize};

use super::ref_lookup;
use super::repository_authority::RequestRepositoryAuthority;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlameRequest {
    pub entity: String,
    #[serde(default)]
    pub reference: Option<String>,
    /// List every file-level revision, not only the ones that changed this
    /// entity. `#[serde(default)]` because this crosses the daemon wire and an
    /// older peer sends none, which means the trimmed default.
    #[serde(default)]
    pub all_revisions: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlameResponse {
    pub lines: Vec<String>,
}

/// `kin blame <entity>` — Show who/when each version of an entity was committed.
pub async fn run(entity: String, reference: Option<String>, all_revisions: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let response = run_daemon_blame(
        &layout,
        &BlameRequest {
            entity,
            reference,
            all_revisions,
        },
    )
    .await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

async fn run_daemon_blame(
    layout: &kin_core::KinLayout,
    request: &BlameRequest,
) -> Result<BlameResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url =
        daemon_url.ok_or_else(|| crate::daemon_client::daemon_required_error("blame", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.blame(request).await.context("daemon blame failed")
}

/// Blame with a binding this call opens for itself when its ref needs
/// repository authority. A caller that already holds an authority, as the
/// daemon does, uses [`execute_blame_request_with`].
pub fn execute_blame_request(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &kin_db::InMemoryGraph,
    request: &BlameRequest,
) -> Result<BlameResponse> {
    execute_blame_request_with(
        &RequestRepositoryAuthority::pinned(binding.clone()),
        graph,
        request,
    )
}

/// Blame an entity, resolving its ref through `authority`.
///
/// The daemon passes the authority it keeps for the current publication, so
/// `HEAD` costs this answer nothing that grows with the store, and the answer
/// names an open only when one happened on the thread that built it.
pub fn execute_blame_request_with(
    authority: &RequestRepositoryAuthority,
    graph: &kin_db::InMemoryGraph,
    request: &BlameRequest,
) -> Result<BlameResponse> {
    let head = ref_lookup::resolve_ref_through(graph, authority, request.reference.as_deref())?;
    let ref_lookup::EntityTimeline {
        target,
        revisions,
        pointer,
        choice,
    } = ref_lookup::resolve_entity_timeline(
        graph,
        &request.entity,
        &head.change_id,
        request.reference.as_deref(),
    )?;
    // Trimmed by default: the revisions where THIS entity's own text moved.
    //
    // Blame's job is attribution, and the untrimmed list answers a different
    // question. Measured on 2026-08-30: a function written once and never edited
    // was credited with two later changes whose commit messages say, in as many
    // words, that they edited a different function in the same file.
    //
    // The withheld ones are named rather than dropped, because they are real and
    // a reader who cannot see they exist has lost information rather than been
    // spared noise. `--all-revisions` restores them.
    let (revisions, withheld) = if request.all_revisions {
        (revisions, Vec::new())
    } else {
        ref_lookup::split_own_revisions(&revisions)
    };
    let mut lines = Vec::new();
    lines.push(format!(
        "Blame for '{}' ({:?}, {}){} at {}:",
        target.name,
        target.kind,
        target.language,
        ref_lookup::pointer_suffix(&pointer),
        head.change_id
    ));
    lines.extend(choice);
    lines.push(String::new());

    if revisions.is_empty() {
        lines.extend(ref_lookup::empty_history_lines(
            graph,
            &target,
            &pointer,
            &head.change_id,
            request.reference.as_deref(),
        )?);
        let closing = ref_lookup::closing_notes(&lines, head.authority_open);
        lines.extend(closing);
        return Ok(BlameResponse { lines });
    }

    lines.push(format!(
        "{:<36}  {:<36}  {:<20}  {:<15}  MESSAGE",
        "REVISION", "CHANGE", "TIMESTAMP", "AUTHOR"
    ));
    lines.push("-".repeat(140));

    // A revision whose change cannot be read is NAMED, not skipped.
    //
    // This loop used to `continue` past it while the tally below printed
    // `revisions.len()`, so the rows could be fewer than the stated count with
    // nothing saying so. A blame that quietly drops a row is worse than one that
    // fails: the reader has no way to know the attribution is partial.
    let mut unreadable = 0usize;
    for revision in &revisions {
        let Some(change) = graph.get_change(&revision.introduced_by)? else {
            unreadable += 1;
            lines.push(format!(
                "{:<36}  {:<36}  {}",
                revision.revision_id,
                revision.introduced_by,
                "change is not readable from this graph, so this revision cannot be attributed",
            ));
            continue;
        };
        // The subject line, the way `kin history` and `git log --oneline` print
        // a change. The whole message put a pull request's entire body under one
        // row and pushed every later revision off the screen.
        lines.push(format!(
            "{:<36}  {:<36}  {:<20}  {:<15}  {}",
            revision.revision_id,
            change.id,
            change.timestamp,
            change.author,
            ref_lookup::subject_line(&change.message),
        ));
    }

    lines.push(format!("\n{} version(s) found.", revisions.len()));
    if let Some(line) = ref_lookup::withheld_line(withheld.len()) {
        lines.push(line);
    }
    if unreadable > 0 {
        lines.push(format!(
            "{unreadable} of them name a change this graph cannot read, so their author and \
             message are unknown here; durable history still holds them and `kin log` reads it."
        ));
    }

    lines.push(format!("\nState at {}:", head.change_id));
    lines.push(format!("  Signature: {}", target.signature));
    lines.push(format!("  Visibility: {:?}", target.visibility));
    if let Some(ref file) = target.file_origin {
        lines.push(format!("  File: {}", file));
    }
    if let Some(ref doc) = target.doc_summary {
        lines.push(format!("  Doc: {}", doc));
    }
    let closing = ref_lookup::closing_notes(&lines, head.authority_open);
    lines.extend(closing);

    Ok(BlameResponse { lines })
}
