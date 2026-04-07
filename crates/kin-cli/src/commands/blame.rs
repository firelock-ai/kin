// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::ChangeStore;

/// `kin blame <entity>` — Show who/when each version of an entity was committed.
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
        "Blame for '{}' ({:?}, {}) at {}:",
        target.name, target.kind, target.language, head
    );
    println!();

    let changes = graph.get_entity_history_at(&target.id, &head)?;

    if changes.is_empty() {
        println!("  No history recorded for this entity.");
        return Ok(());
    }

    println!(
        "{:<36}  {:<20}  {:<15}  MESSAGE",
        "CHANGE", "TIMESTAMP", "AUTHOR"
    );
    println!("{}", "-".repeat(100));

    for change in &changes {
        println!(
            "{:<36}  {:<20}  {:<15}  {}",
            change.id, change.timestamp, change.author, change.message,
        );
    }

    println!("\n{} version(s) found.", changes.len());

    println!("\nState at {}:", head);
    println!("  Signature: {}", target.signature);
    println!("  Visibility: {:?}", target.visibility);
    if let Some(ref file) = target.file_origin {
        println!("  File: {}", file);
    }
    if let Some(ref doc) = target.doc_summary {
        println!("  Doc: {}", doc);
    }

    Ok(())
}
