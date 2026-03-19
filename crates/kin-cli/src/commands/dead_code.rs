// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::GraphStore;

pub async fn run() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();

    println!("Scanning for dead code...");

    let dead = graph.find_dead_code()?;
    if dead.is_empty() {
        println!("No dead code found.");
    } else {
        println!("Found {} unreferenced entities:", dead.len());
        for e in &dead {
            println!(
                "  {} ({:?}, {}) - {}",
                e.name,
                e.kind,
                e.language,
                e.file_origin
                    .as_ref()
                    .map(|f| f.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            );
        }
    }

    Ok(())
}
