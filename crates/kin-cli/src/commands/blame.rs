use anyhow::Result;
use kin_model::{EntityFilter, GraphStore};

/// `kin blame <entity>` — Show who/when each version of an entity was committed.
pub async fn run(entity: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_db::SnapshotManager::open(layout.graph_dir().join("kindb"))?.graph();

    // Resolve entity by name pattern.
    let filter = EntityFilter {
        name_pattern: Some(entity.clone()),
        ..Default::default()
    };
    let matches = graph.query_entities(&filter)?;

    if matches.is_empty() {
        println!("Entity '{}' not found.", entity);
        return Ok(());
    }

    let target = &matches[0];
    println!(
        "Blame for '{}' ({:?}, {}):",
        target.name, target.kind, target.language
    );
    println!();

    // Query the entity's change history from the graph.
    let changes = graph.get_entity_history(&target.id)?;

    if changes.is_empty() {
        println!("  No history recorded for this entity.");
        return Ok(());
    }

    println!(
        "{:<36}  {:<20}  {:<15}  {}",
        "CHANGE", "TIMESTAMP", "AUTHOR", "MESSAGE"
    );
    println!("{}", "-".repeat(100));

    for change in &changes {
        println!(
            "{:<36}  {:<20}  {:<15}  {}",
            change.id, change.timestamp, change.author, change.message,
        );
    }

    println!("\n{} version(s) found.", changes.len());

    // Show current entity details.
    println!("\nCurrent state:");
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
