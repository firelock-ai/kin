// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::EntityFilter;
use kin_model::EntityStore;

pub async fn run(entity: String, depth: u32) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = crate::backend::open_snapshot_daemon_first(&layout).await?;
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

    // 1. Local Impact
    let local_impacted = graph.get_downstream_impact(&target.id, depth)?;
    if local_impacted.is_empty() {
        println!("  No local downstream impact found.");
    } else {
        println!("  {} local entities impacted:", local_impacted.len());
        for e in &local_impacted {
            println!("    - {} ({:?}, {})", e.name, e.kind, e.language);
        }
    }

    // 2. Federated Impact (via Spine)
    let repo_id = std::env::var("KIN_REPO_ID").unwrap_or_else(|_| {
        layout.working_dir()
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string()
    });

    if let Ok(Some(federated)) = crate::backend::get_spine_impact(&repo_id, &target.id, depth).await {
        let external_hits: Vec<_> = federated.nodes.iter()
            .filter(|n| n.repo_id != repo_id)
            .collect();

        if !external_hits.is_empty() {
            println!("\n  {} external entities impacted (across the spine):", external_hits.len());
            for node in external_hits {
                println!("    - [{}] {} ({:?})", node.repo_id, node.name, node.kind);
            }
        }
    }

    Ok(())
}
