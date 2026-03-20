// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::{GraphStore, Hash256, SemanticChangeId};

/// `kin approvals <change-id>` — Show approvals for a specific change.
pub async fn show(change_id: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();

    let id = parse_change_id(&change_id)?;
    let approvals = graph.get_approvals_for_change(&id)?;

    if approvals.is_empty() {
        println!("No approvals found for change {}", change_id);
        return Ok(());
    }

    println!(
        "{:<14}  {:<14}  {:<12}  {:<20}  REASON",
        "APPROVAL", "APPROVER", "DECISION", "TIMESTAMP"
    );
    println!("{}", "-".repeat(90));

    for approval in &approvals {
        let approval_short = &approval.approval_id.to_string()[..12];
        let approver_short = &approval.approver.to_string()[..12];

        println!(
            "{:<14}  {:<14}  {:<12}  {:<20}  {}",
            approval_short, approver_short, approval.decision, approval.timestamp, approval.reason,
        );
    }

    println!("\n{} approval(s)", approvals.len());
    Ok(())
}

/// `kin approvals list` — Show all actors and their delegation counts.
pub async fn list() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();

    let actors = graph.list_actors()?;

    if actors.is_empty() {
        println!("No actors registered.");
        return Ok(());
    }

    println!(
        "{:<14}  {:<12}  {:<20}  DELEGATIONS",
        "ACTOR", "KIND", "NAME"
    );
    println!("{}", "-".repeat(65));

    for actor in &actors {
        let actor_short = &actor.actor_id.to_string()[..12];
        let delegations = graph.get_delegations_for_actor(&actor.actor_id)?;

        println!(
            "{:<14}  {:<12}  {:<20}  {}",
            actor_short,
            actor.kind,
            actor.display_name,
            delegations.len(),
        );
    }

    println!("\n{} actor(s)", actors.len());
    Ok(())
}

fn parse_change_id(s: &str) -> Result<SemanticChangeId> {
    let hash = Hash256::from_hex(s)
        .map_err(|_| anyhow::anyhow!("invalid change ID (expected 64 hex chars): {}", s))?;
    Ok(SemanticChangeId::from_hash(hash))
}
