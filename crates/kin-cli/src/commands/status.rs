// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;

pub async fn run() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();
    let current = kin_core::read_current_branch(&layout)?;

    use kin_model::GraphStore;
    if let Some(branch) = graph.get_branch(&current)? {
        println!("On branch: {}", branch.name);
        println!("Head: {}", branch.head);
    } else {
        println!("On branch: {} (not found in graph)", current);
    }

    // Show entity count
    let entities = graph.list_all_entities()?;
    println!("Entities: {}", entities.len());

    Ok(())
}
