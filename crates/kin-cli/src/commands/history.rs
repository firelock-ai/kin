// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::ChangeStore;

pub async fn run(entity: String, reference: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = &*_snap.graph();
    let head = crate::commands::ref_lookup::resolve_ref(graph, &layout, reference.as_deref())?;
    let target = match reference.as_deref() {
        Some(_) => crate::commands::ref_lookup::resolve_entity_query_at_ref(graph, &entity, &head)?,
        None => crate::commands::ref_lookup::resolve_entity_query(graph, &entity)?,
    };
    println!(
        "History for '{}' ({:?}, {}) at {}:",
        target.name, target.kind, target.language, head
    );

    let changes = graph.get_entity_history_at(&target.id, &head)?;
    if changes.is_empty() {
        println!("  No history recorded");
    } else {
        for change in &changes {
            println!(
                "  {} - {} ({})",
                change.id, change.message, change.timestamp
            );
        }
    }

    Ok(())
}
