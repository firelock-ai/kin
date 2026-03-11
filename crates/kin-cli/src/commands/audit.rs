use anyhow::Result;
use kin_model::{GraphStore, Hash256};
use kin_model::provenance::ActorId;

/// `kin audit` — List recent audit events, optionally filtered by actor.
pub async fn run(actor: Option<String>, limit: usize) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

    let actor_id = actor
        .map(|s| parse_actor_id(&s))
        .transpose()?;

    let events = graph.query_audit_events(actor_id.as_ref(), limit)?;

    if events.is_empty() {
        println!("No audit events found.");
        return Ok(());
    }

    println!(
        "{:<20}  {:<14}  {:<16}  {:<24}  {}",
        "TIMESTAMP", "ACTOR", "ACTION", "TARGET", "DETAILS"
    );
    println!("{}", "-".repeat(100));

    for event in &events {
        let actor_short = &event.actor_id.to_string()[..12];
        let target = event
            .target_scope
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".to_string());
        let details = event
            .details
            .as_deref()
            .unwrap_or("-");

        println!(
            "{:<20}  {:<14}  {:<16}  {:<24}  {}",
            event.timestamp, actor_short, event.action, target, details
        );
    }

    println!("\n{} event(s)", events.len());
    Ok(())
}

fn parse_actor_id(s: &str) -> Result<ActorId> {
    let hash = Hash256::from_hex(s)
        .map_err(|_| anyhow::anyhow!("invalid actor ID (expected 64 hex chars): {}", s))?;
    Ok(ActorId::from_hash(hash))
}
