// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::{EntityFilter, GraphStore};

pub async fn run(entity: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();

    let filter = EntityFilter {
        name_pattern: Some(entity.clone()),
        ..Default::default()
    };
    let matches = graph.query_entities(&filter)?;

    if matches.is_empty() {
        println!("Entity '{}' not found", entity);
        return Ok(());
    }

    let target = &matches[0];
    println!(
        "History for '{}' ({:?}, {}):",
        target.name, target.kind, target.language
    );

    let changes = graph.get_entity_history(&target.id)?;
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
