// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};

pub async fn run(message: String, quiet: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;

    let result = run_daemon_commit(&layout, &message).await?;
    if !quiet {
        println!(
            "Created semantic change {} on branch '{}' ({} entities, {} relations, {} artifacts)",
            result.change_id,
            result.branch,
            result.entity_count,
            result.relation_count,
            result.file_count
        );
    }
    Ok(())
}

/// Result from the daemon-owned native commit transaction.
///
/// Commit construction deliberately has no CLI-local fallback. Repository
/// membership, stable artifact identities, exact blobs, semantic enrichment,
/// the immutable change, and ref publication all belong to the daemon's one
/// serialized authority path.
#[derive(Debug, serde::Deserialize)]
struct DaemonCommitResult {
    change_id: String,
    branch: String,
    entity_count: usize,
    relation_count: usize,
    file_count: usize,
}

async fn run_daemon_commit(
    layout: &kin_core::KinLayout,
    message: &str,
) -> Result<DaemonCommitResult> {
    // Resolved here, in the caller's own environment and working directory,
    // rather than inside the daemon. The daemon is spawned with every `GIT_*`
    // variable scrubbed and does not share the caller's shell, so an identity it
    // resolved for itself would answer a different question than "who is running
    // this command". Resolution also comes before the daemon is contacted: a
    // commit that cannot be attributed must not reach the authority path at all.
    let author = crate::commands::require_commit_author_for(layout)?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(layout)
        .await?
        .ok_or_else(|| crate::daemon_client::daemon_required_error("commit", layout))?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_millis(500))
        .build()?;
    // Create these once per CLI invocation so transport retry logic can reuse
    // the byte-identical repository transaction.
    let operation_id = kin_model::OperationId::new();
    let timestamp = kin_model::Timestamp::now();
    let mut request = client
        .post(format!(
            "{}/commands/commit",
            daemon_url.trim_end_matches('/')
        ))
        .json(&serde_json::json!({
            "operation_id": operation_id,
            "timestamp": timestamp,
            "message": message,
            "author": author,
        }));
    if let Some(token) = crate::daemon_client::resolve_daemon_auth_token() {
        request = request.bearer_auth(token);
    }

    let response = request
        .send()
        .await
        .context("send daemon-owned native commit request")?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("daemon native commit failed (HTTP {status}): {body}");
    }
    response
        .json()
        .await
        .context("decode daemon native commit response")
}
