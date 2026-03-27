// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::ChangeStore;

pub async fn run(base: Option<String>, head: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = crate::backend::open_kindb_snapshot(&layout)?;
    let graph = &*_snap.graph();

    match (base, head) {
        (Some(b), Some(h)) => {
            let base_id = kin_model::SemanticChangeId::from_hash(
                kin_model::Hash256::from_hex(&b)
                    .map_err(|e| anyhow::anyhow!("invalid base hash: {}", e))?,
            );
            let head_id = kin_model::SemanticChangeId::from_hash(
                kin_model::Hash256::from_hex(&h)
                    .map_err(|e| anyhow::anyhow!("invalid head hash: {}", e))?,
            );
            let changes = graph.get_changes_since(&base_id, &head_id)?;
            println!("Changes between {} and {}:", b, h);
            for change in &changes {
                println!("  {} - {}", change.id, change.message);
                for delta in &change.entity_deltas {
                    match delta {
                        kin_model::change::EntityDelta::Added(e) => {
                            println!("    + {} ({:?})", e.name, e.kind)
                        }
                        kin_model::change::EntityDelta::Modified { old, new } => {
                            println!("    ~ {} -> {} ({:?})", old.name, new.name, new.kind)
                        }
                        kin_model::change::EntityDelta::Removed(id) => {
                            println!("    - {}", id)
                        }
                    }
                }
            }
        }
        _ => {
            println!("Usage: kin diff <base> <head>");
            println!("Shows entity-level diff between two semantic changes.");
        }
    }

    Ok(())
}
