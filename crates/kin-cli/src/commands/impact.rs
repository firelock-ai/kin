// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::{EntityFilter, GraphStore};

pub async fn run(entity: String, depth: u32) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();

    // Find the entity by name
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
    println!("Impact analysis for '{}' ({:?}):", target.name, target.kind);
    println!("  Depth: {}", depth);

    let impacted = graph.get_downstream_impact(&target.id, depth)?;
    if impacted.is_empty() {
        println!("  No downstream impact found.");
    } else {
        println!("  {} entities impacted:", impacted.len());
        for e in &impacted {
            println!("    - {} ({:?}, {})", e.name, e.kind, e.language);
        }
    }

    Ok(())
}
