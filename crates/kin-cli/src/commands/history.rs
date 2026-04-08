// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::ChangeStore;

pub async fn run(entity: String, reference: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = &*_snap.graph();
    let head = crate::commands::ref_lookup::resolve_ref_importing_git_if_needed(
        graph,
        &layout,
        reference.as_deref(),
    )?;
    let target = match reference.as_deref() {
        Some(_) => crate::commands::ref_lookup::resolve_entity_query_at_ref(graph, &entity, &head)?,
        None => crate::commands::ref_lookup::resolve_entity_query(graph, &entity)?,
    };
    println!(
        "History for '{}' ({:?}, {}) at {}:",
        target.name, target.kind, target.language, head
    );

    let revisions = graph.get_entity_revisions_at(&target.id, &head)?;
    if revisions.is_empty() {
        println!("  No history recorded");
    } else {
        for revision in &revisions {
            let change = graph.get_change(&revision.introduced_by)?;
            let message = change
                .as_ref()
                .map(|entry| entry.message.as_str())
                .unwrap_or("unknown");
            println!(
                "  {} @ {} - {}",
                revision.revision_id, revision.introduced_by, message
            );
        }
    }

    Ok(())
}
