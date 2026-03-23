// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;

pub async fn run() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();
    let current = kin_core::read_current_branch(&layout)?;
    let mode = kin_core::read_repo_mode(&layout);
    let source_root = kin_core::source_dir(&layout);
    let config = kin_core::KinConfig::load_or_default(&layout.config_path())?;
    let default_remote = config
        .resolve_remote(None)
        .map(|remote| format!("{} [{} / {}]", remote.name, remote.host, remote.transport))
        .unwrap_or_else(|| "(not configured)".to_string());

    use kin_model::GraphStore;
    println!("Repo root: {}", layout.working_dir().display());
    println!("Mode: {}", mode);
    println!("Source root: {}", source_root.display());
    println!("World preset: {}", config.world.preset);
    println!("Default remote: {}", default_remote);

    if let Some(branch) = graph.get_branch(&current)? {
        println!("Branch: {}", branch.name);
        println!("Head: {}", branch.head);
    } else {
        println!("Branch: {} (not found in graph)", current);
        println!("Head: (missing)");
    }

    // Show entity count
    let entities = graph.list_all_entities()?;
    println!("Entities: {}", entities.len());

    Ok(())
}
