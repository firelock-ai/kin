// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::EntityFilter;
use kin_model::EntityStore;

pub async fn run(entity: String) -> Result<()> {
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
    println!("Cross-repo references (xrefs) for '{}':", target.name);

    let repo_id = std::env::var("KIN_REPO_ID").unwrap_or_else(|_| {
        layout
            .working_dir()
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string()
    });

    match crate::backend::get_spine_xref(&repo_id, &target.id).await {
        Ok(Some(edges)) if !edges.is_empty() => {
            println!("  Found {} cross-repo edges:", edges.len());
            for edge in edges {
                println!(
                    "    - Impact: [{}] {} depends on us ([{}] {}) (conf: {:.2})",
                    edge.src_repo, edge.src_entity, edge.dst_repo, edge.dst_entity, edge.confidence
                );
            }
        }
        Ok(_) => {
            println!("  No cross-repo references found in the spine.");
        }
        Err(e) => {
            println!("  Failed to query spine: {}", e);
        }
    }

    Ok(())
}
