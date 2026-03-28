// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use serde::Serialize;

pub(crate) const DEFAULT_BATCH_SIZE: usize = 64;

#[derive(Serialize)]
struct EmbedResult {
    total_entities: usize,
    embedded: usize,
    vector_index_path: String,
}

pub(crate) fn drain_pending_embeddings(
    graph: &kin_db::InMemoryGraph,
    batch_size: usize,
) -> Result<usize> {
    Ok(graph.process_all_pending_embeddings(batch_size)?)
}

/// Build embeddings for all entities in the current repo's graph.
///
/// Opens the graph snapshot, queues all entities for embedding, processes
/// the queue in batches, and persists the HNSW vector index to disk.
pub async fn run(batch_size: usize, json: bool) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let snap = crate::backend::open_snapshot_daemon_first(&layout).await?;
    let graph = snap.graph();

    let total = graph.entity_count();
    if total == 0 {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&EmbedResult {
                    total_entities: 0,
                    embedded: 0,
                    vector_index_path: String::new(),
                })?
            );
        } else {
            println!("No entities in graph. Run `kin init` first.");
        }
        return Ok(());
    }

    if !json {
        println!("Embedding {} entities (batch_size={})...", total, batch_size);
    }

    // Queue all entities for embedding.
    graph.queue_all_for_embedding();

    let total_embedded = match drain_pending_embeddings(&graph, batch_size) {
        Ok(count) => count,
        Err(e) => {
            if !json {
                eprintln!("\nError during embedding: {}", e);
            }
            return Err(e);
        }
    };

    if !json {
        let pct = if total > 0 {
            (total_embedded as f64 / total as f64 * 100.0) as u32
        } else {
            100
        };
        eprintln!("  Embedded {}/{} entities ({}%)", total_embedded, total, pct);
    }

    // Persist the HNSW vector index to disk.
    let vi_path = crate::backend::vector_index_path(&layout);
    graph.save_vector_index(&vi_path)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&EmbedResult {
                total_entities: total,
                embedded: total_embedded,
                vector_index_path: vi_path.to_string_lossy().to_string(),
            })?
        );
    } else {
        println!(
            "Done. {} entities embedded, index saved to {}",
            total_embedded,
            vi_path.display()
        );
    }

    Ok(())
}
