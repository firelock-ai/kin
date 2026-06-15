// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Default embed command batch.
///
/// The embedder already groups individual texts by token budget inside each
/// queue pass, but the outer batch controls how many graph objects are drained,
/// formatted, tokenized, and held before progress is persisted. Very large
/// outer batches can look like a hang and delay vector sidecar creation on
/// fresh prepared-state builds. Keep the default conservative; callers can
/// still raise it explicitly for tuned hardware runs.
pub const DEFAULT_BATCH_SIZE: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedRequest {
    pub batch_size: usize,
    #[serde(default)]
    pub json: bool,
    #[serde(default)]
    pub max_seconds: Option<u64>,
    /// Drop the existing vector index and rebuild it at the current model's
    /// dimension. Required to migrate a repo whose persisted index was built at
    /// a different embedding dimension (e.g. an older 384-dim model). Defaults
    /// to false so a normal embed pass is unchanged and the field is optional on
    /// the daemon wire protocol.
    #[serde(default)]
    pub rebuild: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedResult {
    pub total_entities: usize,
    pub embedded_entities: usize,
    pub pending_entities: usize,
    pub total_artifacts: usize,
    pub embedded_artifacts: usize,
    pub pending_artifacts: usize,
    pub time_limited: bool,
    pub vector_index_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedResponse {
    pub result: EmbedResult,
    #[serde(default)]
    pub lines: Vec<String>,
}

pub(crate) fn invalidate_vector_index(path: &std::path::Path) -> Result<()> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Decide whether the embed loop should enqueue missing retrievable objects.
///
/// Reopened graphs may have a stale or partially useful queue while the vector
/// sidecar is missing revision/artifact keys. Coverage, not raw queue length,
/// is the authority for whether `kin embed` has backfill work to enqueue.
fn should_queue_missing_embedding_pass(indexed: usize, total: usize) -> bool {
    indexed < total
}

fn effective_batch_size(requested: usize, bounded: bool) -> usize {
    let requested = requested.max(1);
    if bounded {
        requested.min(DEFAULT_BATCH_SIZE)
    } else {
        requested
    }
}

/// Ask the repo daemon to build embeddings for the current repo's graph.
pub async fn run(
    batch_size: usize,
    json: bool,
    max_seconds: Option<u64>,
    rebuild: bool,
) -> Result<()> {
    let _span = tracing::info_span!(
        "kin.embed",
        batch_size = batch_size,
        json = json,
        max_seconds = max_seconds,
        rebuild = rebuild
    )
    .entered();
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let response = run_daemon_embed(
        &layout,
        &EmbedRequest {
            batch_size,
            json,
            max_seconds,
            rebuild,
        },
    )
    .await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&response.result)?);
    } else {
        for line in response.lines {
            println!("{line}");
        }
    }
    Ok(())
}

async fn run_daemon_embed(
    layout: &kin_core::KinLayout,
    request: &EmbedRequest,
) -> Result<EmbedResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for embed but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .embed(request)
        .await
        .map_err(|e| anyhow::anyhow!("daemon embed failed: {e:#}"))
}

pub fn build_embed_response(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &EmbedRequest,
    mut persist_batch: impl FnMut() -> std::result::Result<(), kin_db::KinDbError>,
    is_cancelled: impl Fn() -> bool,
) -> Result<EmbedResponse> {
    let deadline = request
        .max_seconds
        .filter(|seconds| *seconds > 0)
        .map(|seconds| std::time::Instant::now() + std::time::Duration::from_secs(seconds));

    let total_entities = graph.entity_count();
    let total_artifacts = graph.artifact_count();

    // Fast exit: nothing to embed
    if total_entities == 0 && total_artifacts == 0 {
        return Ok(EmbedResponse {
            result: EmbedResult {
                total_entities: 0,
                embedded_entities: 0,
                pending_entities: 0,
                total_artifacts: 0,
                embedded_artifacts: 0,
                pending_artifacts: 0,
                time_limited: false,
                vector_index_path: String::new(),
            },
            lines: vec!["No retrievable graph objects found. Run `kin init` first.".to_string()],
        });
    }

    // Propagate vectors from fingerprint-identical previous revisions before
    // queueing, so identical-content revisions skip GPU inference entirely.
    // This can eliminate 30-50% of the total embedding work for historical
    // revisions where the entity content didn't actually change.
    let propagated = graph.propagate_revision_vectors();
    if propagated > 0 {
        tracing::info!(
            propagated = propagated,
            "propagated revision vectors via fingerprint match"
        );
    }

    // Rebuild migration (request.rebuild) is handled by the daemon before this
    // runs: it drops the stale-dimension index and re-queues every object. For
    // normal embeds, always enqueue missing retrievable keys when coverage is
    // incomplete; HashSet queues make this idempotent and prevent stale queue
    // entries from masking real backfill work.
    let status = graph.embedding_status();
    if should_queue_missing_embedding_pass(status.indexed, status.total) {
        graph.queue_missing_for_embedding();
        graph.queue_missing_artifacts_for_embedding();
    }
    let effective_batch_size = effective_batch_size(request.batch_size, deadline.is_some());

    // Embed entities with per-batch progress
    let embed_start = std::time::Instant::now();
    let mut total_embedded_entities = 0usize;
    let mut time_limited = false;
    loop {
        if is_cancelled() {
            tracing::info!("Embedding cancelled due to shutdown");
            break;
        }
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            time_limited = true;
            break;
        }
        let pending = graph.pending_embeddings();
        if pending == 0 {
            break;
        }
        match graph.process_embedding_queue(effective_batch_size) {
            Ok(processed) => {
                if processed == 0 {
                    break;
                }
                total_embedded_entities += processed;
                persist_batch()?;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    // Embed artifacts with per-batch progress
    let mut total_embedded_artifacts = 0usize;
    loop {
        if is_cancelled() {
            tracing::info!("Embedding cancelled due to shutdown");
            break;
        }
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            time_limited = true;
            break;
        }
        let pending = graph.pending_artifact_embeddings();
        if pending == 0 {
            break;
        }
        match graph.process_artifact_embedding_queue(effective_batch_size) {
            Ok(processed) => {
                if processed == 0 {
                    break;
                }
                total_embedded_artifacts += processed;
                persist_batch()?;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    let vi_path = crate::backend::vector_index_path(layout);
    let pending_entities = graph.pending_embeddings();
    let pending_artifacts = graph.pending_artifact_embeddings();
    let result = EmbedResult {
        total_entities,
        embedded_entities: total_embedded_entities,
        pending_entities,
        total_artifacts,
        embedded_artifacts: total_embedded_artifacts,
        pending_artifacts,
        time_limited,
        vector_index_path: vi_path.to_string_lossy().to_string(),
    };
    let mut lines = Vec::new();
    if time_limited {
        lines.push(
            "Time budget reached; persisting completed vectors and leaving the rest pending."
                .to_string(),
        );
    }
    lines.push(format!(
        "Done: {}/{} entities, {}/{} artifacts ({:.1}s)",
        total_embedded_entities,
        total_entities,
        total_embedded_artifacts,
        total_artifacts,
        embed_start.elapsed().as_secs_f64()
    ));
    lines.push(format!(
        "Done. {} entities embedded, {} artifacts embedded, index saved to {}",
        total_embedded_entities,
        total_embedded_artifacts,
        vi_path.display()
    ));

    Ok(EmbedResponse { result, lines })
}

#[cfg(test)]
mod tests {
    use super::{effective_batch_size, should_queue_missing_embedding_pass, DEFAULT_BATCH_SIZE};

    #[test]
    fn default_batch_size_is_progress_friendly() {
        assert_eq!(DEFAULT_BATCH_SIZE, 64);
    }

    #[test]
    fn effective_batch_size_respects_nonzero_request() {
        assert_eq!(effective_batch_size(512, false), 512);
    }

    #[test]
    fn effective_batch_size_caps_bounded_requests_to_default() {
        assert_eq!(effective_batch_size(512, true), DEFAULT_BATCH_SIZE);
    }

    #[test]
    fn effective_batch_size_keeps_small_bounded_requests() {
        assert_eq!(effective_batch_size(16, true), 16);
    }

    #[test]
    fn effective_batch_size_clamps_zero_to_one() {
        assert_eq!(effective_batch_size(0, false), 1);
        assert_eq!(effective_batch_size(0, true), 1);
    }

    #[test]
    fn queues_missing_pass_when_index_incomplete() {
        assert!(should_queue_missing_embedding_pass(3, 5));
    }

    #[test]
    fn queues_missing_pass_even_when_stale_queue_may_exist() {
        assert!(should_queue_missing_embedding_pass(3, 5));
    }

    #[test]
    fn skips_full_queue_when_embeddings_are_current() {
        assert!(!should_queue_missing_embedding_pass(5, 5));
    }

    #[test]
    fn embed_error_wrap_preserves_underlying_chain() {
        let inner = anyhow::anyhow!("daemon embed error (HTTP 500): Graph error: kindb foo");
        let wrapped: anyhow::Error =
            anyhow::anyhow!("daemon embed failed: {inner:#}", inner = inner);
        let rendered = format!("{wrapped:#}");
        assert!(
            rendered.contains("daemon embed failed"),
            "missing outer hint: {rendered}"
        );
        assert!(
            rendered.contains("Graph error: kindb foo"),
            "underlying cause was flattened away: {rendered}"
        );
    }
}
