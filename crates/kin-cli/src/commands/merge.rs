// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::{
    AuthorId, BranchName, ChangeStore, Entity, EntityDelta, EntityStore, GraphStore, Hash256,
    SemanticChange, SemanticChangeId, Timestamp,
};
use kin_reconcile::{group_conflicts_by_file, MergeConflictKind, Reconciler};

use crate::commands::conflicts::{
    conflict_kind_tag, load_merge_state, save_merge_state, PersistedConflict, PersistedMergeState,
};

/// `kin merge <branch>` — Semantic two-phase merge.
///
/// Phase 1: structural (AST-level) merge via reconciler conflict detection.
/// Phase 2: semantic (fingerprint-aware) merge that preserves entity identity.
///
/// When conflicts are detected, they are persisted to `.kin/merge_state.json`.
/// Use `kin conflicts` to view them and `kin resolve` to resolve them.
pub async fn run(branch: String, strategy: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    // Check for in-progress merge.
    if let Some(existing) = load_merge_state(&layout)? {
        anyhow::bail!(
            "merge already in progress: '{}' -> '{}' ({} unresolved conflict(s)).\n\
             Run `kin conflicts` to see them, `kin resolve` to resolve, or `kin resolve --abort` to cancel.",
            existing.source_branch,
            existing.target_branch,
            existing.unresolved_count()
        );
    }

    let snapshot = crate::backend::open_snapshot_daemon_first(&layout).await?;
    let graph = snapshot.graph();
    let graph = &*graph;

    // Resolve source branch.
    let source_branch = graph.get_branch(&BranchName::new(&branch))?;
    let source = source_branch.ok_or_else(|| anyhow::anyhow!("branch '{}' not found", branch))?;

    // Resolve current (target) branch from HEAD.
    let current_name = kin_core::read_current_branch(&layout)?;
    let ensured_current =
        crate::commands::branch_bootstrap::ensure_current_branch(graph, &current_name)?;
    let current = graph
        .get_branch(&current_name)?
        .ok_or_else(|| anyhow::anyhow!("current branch '{}' not found in graph", current_name))?;
    if ensured_current.bootstrapped {
        // If bootstrapped, push the head update to daemon
        let daemon_success = crate::backend::try_daemon_update_head(
            &current_name.to_string(),
            &current.head.to_string(),
        )
        .unwrap_or(false);
        if !daemon_success {
            kin_db::SnapshotManager::save_graph(layout.kindb_snapshot_path(), graph)?;
        }
    }

    if current.name == source.name {
        println!("Already on branch '{}', nothing to merge.", branch);
        return Ok(());
    }

    println!(
        "Merging '{}' into '{}' (strategy: {})...",
        branch, current.name, strategy
    );

    // Find merge bases.
    let bases = graph.find_merge_bases(&current.head, &source.head)?;
    if bases.is_empty() {
        println!("  No common ancestor found — performing unrelated-history merge.");

        // Collect current branch entities as "ours".
        let our_entities: Vec<Entity> = graph.list_all_entities()?;

        // Collect source branch entities from the head change.
        let their_entities: Vec<Entity> =
            if let Some(head_change) = graph.get_change(&source.head)? {
                head_change
                    .entity_deltas
                    .into_iter()
                    .filter_map(|d| match d {
                        EntityDelta::Added(e) => Some(e),
                        EntityDelta::Modified { new, .. } => Some(new),
                        EntityDelta::Removed(_) => None,
                    })
                    .collect()
            } else {
                vec![]
            };

        let preview = Reconciler::analyze_unrelated_merge(&our_entities, &their_entities);

        println!("  Files affected: {}", preview.files_affected.len());
        println!("  Additions:      {}", preview.added.len());
        println!("  Kept (ours):    {}", preview.kept.len());

        if preview.is_clean() {
            println!("\n  No conflicts — clean unrelated merge.");
            let merge = build_merge_change(
                &current.head,
                &source.head,
                &[],
                &format!("Merge unrelated '{}' into '{}'", branch, current.name),
            );
            let daemon_success =
                crate::backend::try_daemon_commit(&merge, &current.name.to_string())
                    .unwrap_or(false);
            if !daemon_success {
                graph.create_change(&merge)?;
                graph.update_branch_head(&current.name, &merge.id)?;
                kin_db::SnapshotManager::save_graph(layout.kindb_snapshot_path(), graph)?;
            }
            println!("  Merge commit: {}", merge.id);
            println!("  Updated '{}' -> {}", current.name, merge.id);
        } else {
            display_and_persist_conflicts(
                &layout,
                &preview.conflicts,
                &branch,
                &current.name.to_string(),
                &current.head.to_string(),
                &source.head.to_string(),
                &strategy,
            )?;
        }
        return Ok(());
    }

    println!("  Merge base(s): {}", bases.len());
    for base in &bases {
        println!("    {}", base);
    }

    // Gather changes on each side since the merge base.
    let base_id = &bases[0];
    let ours = graph.get_changes_since(base_id, &current.head)?;
    let theirs = graph.get_changes_since(base_id, &source.head)?;

    println!("  Changes on '{}': {}", current.name, ours.len());
    println!("  Changes on '{}': {}", branch, theirs.len());

    if theirs.is_empty() {
        println!("\n  Already up to date.");
        return Ok(());
    }

    // Use proper 3-way merge analysis via the reconciler.
    // Collect entity snapshots at each state.
    let base_entities = collect_entities_at(graph, base_id)?;
    let our_entities: Vec<Entity> = graph.list_all_entities()?;
    let their_entities = collect_entities_from_changes(&theirs, &base_entities);

    let preview = Reconciler::analyze_merge_3way(&base_entities, &our_entities, &their_entities);

    if preview.is_clean() {
        println!("\n  No conflicts detected — clean merge.");
        if ours.is_empty() {
            // Fast-forward: no changes on our side
            let daemon_success = crate::backend::try_daemon_update_head(
                &current.name.to_string(),
                &source.head.to_string(),
            )
            .unwrap_or(false);
            if !daemon_success {
                graph.update_branch_head(&current.name, &source.head)?;
                kin_db::SnapshotManager::save_graph(layout.kindb_snapshot_path(), graph)?;
            }
            println!("  Fast-forward: '{}' -> {}", current.name, source.head);
        } else {
            // Diverged branches: create merge commit with two parents
            let merge = build_merge_change(
                &current.head,
                &source.head,
                &theirs,
                &format!("Merge '{}' into '{}'", branch, current.name),
            );
            let daemon_success =
                crate::backend::try_daemon_commit(&merge, &current.name.to_string())
                    .unwrap_or(false);
            if !daemon_success {
                graph.create_change(&merge)?;
                graph.update_branch_head(&current.name, &merge.id)?;
                kin_db::SnapshotManager::save_graph(layout.kindb_snapshot_path(), graph)?;
            }
            println!("  Merge commit: {}", merge.id);
            println!("  Updated '{}' -> {}", current.name, merge.id);
        }
    } else {
        // Separate auto-resolvable (convergent) from manual conflicts.
        let manual: Vec<_> = preview
            .conflicts
            .iter()
            .filter(|c| !matches!(c.kind, MergeConflictKind::Convergent))
            .collect();
        let auto_count = preview.conflicts.len() - manual.len();

        if auto_count > 0 {
            println!(
                "\n  Auto-resolved {} convergent conflict(s) (identical changes on both sides).",
                auto_count
            );
        }

        if manual.is_empty() {
            // All conflicts were convergent — auto-resolve and merge.
            println!("  All conflicts auto-resolved.");
            if ours.is_empty() {
                let daemon_success = crate::backend::try_daemon_update_head(
                    &current.name.to_string(),
                    &source.head.to_string(),
                )
                .unwrap_or(false);
                if !daemon_success {
                    graph.update_branch_head(&current.name, &source.head)?;
                    kin_db::SnapshotManager::save_graph(layout.kindb_snapshot_path(), graph)?;
                }
                println!("  Fast-forward: '{}' -> {}", current.name, source.head);
            } else {
                let merge = build_merge_change(
                    &current.head,
                    &source.head,
                    &theirs,
                    &format!("Merge '{}' into '{}' (auto-resolved)", branch, current.name),
                );
                let daemon_success =
                    crate::backend::try_daemon_commit(&merge, &current.name.to_string())
                        .unwrap_or(false);
                if !daemon_success {
                    graph.create_change(&merge)?;
                    graph.update_branch_head(&current.name, &merge.id)?;
                    kin_db::SnapshotManager::save_graph(layout.kindb_snapshot_path(), graph)?;
                }
                println!("  Merge commit: {}", merge.id);
                println!("  Updated '{}' -> {}", current.name, merge.id);
            }
        } else {
            // Non-trivial conflicts — persist state for interactive resolution.
            let conflict_refs: Vec<_> = manual.into_iter().cloned().collect();
            display_and_persist_conflicts(
                &layout,
                &conflict_refs,
                &branch,
                &current.name.to_string(),
                &current.head.to_string(),
                &source.head.to_string(),
                &strategy,
            )?;
        }
    }

    Ok(())
}

/// Display conflicts in a rich file-grouped format and persist to merge state.
fn display_and_persist_conflicts(
    layout: &kin_core::KinLayout,
    conflicts: &[kin_reconcile::MergeConflict],
    source_branch: &str,
    target_branch: &str,
    target_head: &str,
    source_head: &str,
    strategy: &str,
) -> Result<()> {
    println!(
        "\n  {} conflict(s) require manual resolution:\n",
        conflicts.len()
    );

    // Display grouped by file.
    let grouped = group_conflicts_by_file(conflicts);
    let mut file_keys: Vec<_> = grouped.keys().collect();
    file_keys.sort_by_key(|k| k.as_ref().map(|f| f.to_string()));

    for file_key in &file_keys {
        let file_label = file_key
            .as_ref()
            .map(|f| f.to_string())
            .unwrap_or_else(|| "(no file)".to_string());
        println!("    {}:", file_label);
        for c in &grouped[file_key] {
            let kind_label = match &c.kind {
                MergeConflictKind::Divergent => "divergent",
                MergeConflictKind::ModifyDelete => "modify/delete",
                MergeConflictKind::AddAdd => "add/add",
                MergeConflictKind::SignatureChange => "signature change",
                MergeConflictKind::VisibilityChange { from, to } => {
                    // Leak is fine: this runs once per merge conflict display.
                    Box::leak(format!("{:?} -> {:?}", from, to).into_boxed_str())
                }
                MergeConflictKind::Convergent => "convergent",
            };
            println!("      {} ({}) — {}", c.entity_name, c.entity_id, kind_label);
        }
    }

    // Persist conflict state.
    let persisted_conflicts: Vec<PersistedConflict> = conflicts
        .iter()
        .map(|c| PersistedConflict {
            entity_id: c.entity_id.to_string(),
            entity_name: c.entity_name.clone(),
            file_origin: c.file_origin.as_ref().map(|f| f.to_string()),
            kind: conflict_kind_tag(&c.kind),
            resolution: None,
        })
        .collect();

    let state = PersistedMergeState {
        source_branch: source_branch.to_string(),
        target_branch: target_branch.to_string(),
        target_head: target_head.to_string(),
        source_head: source_head.to_string(),
        strategy: strategy.to_string(),
        conflicts: persisted_conflicts,
    };
    save_merge_state(layout, &state)?;

    println!("\n  Conflict state saved. To resolve:");
    println!("    kin conflicts                    View conflicts");
    println!("    kin resolve --ours <entity>      Keep your version");
    println!("    kin resolve --theirs <entity>     Keep incoming version");
    println!("    kin resolve --all-ours            Resolve all: keep yours");
    println!("    kin resolve --all-theirs           Resolve all: keep incoming");
    println!("    kin resolve --continue             Complete merge after resolving");
    println!("    kin resolve --abort                Abort and discard merge state");

    Ok(())
}

/// Collect entities at a given change point by replaying deltas.
///
/// This builds an approximation of the entity set at the merge base.
fn collect_entities_at<G: GraphStore>(
    graph: &G,
    change_id: &SemanticChangeId,
) -> Result<Vec<Entity>> {
    if let Some(change) = graph.get_change(change_id)? {
        let mut entities = Vec::new();
        for delta in &change.entity_deltas {
            match delta {
                EntityDelta::Added(e) => entities.push(e.clone()),
                EntityDelta::Modified { new, .. } => entities.push(new.clone()),
                EntityDelta::Removed(_) => {}
            }
        }
        Ok(entities)
    } else {
        Ok(vec![])
    }
}

/// Collect entities from the source branch by applying changes to base entities.
fn collect_entities_from_changes(changes: &[SemanticChange], base: &[Entity]) -> Vec<Entity> {
    let mut entity_map: std::collections::HashMap<kin_model::EntityId, Entity> =
        base.iter().map(|e| (e.id, e.clone())).collect();

    for change in changes {
        for delta in &change.entity_deltas {
            match delta {
                EntityDelta::Added(e) => {
                    entity_map.insert(e.id, e.clone());
                }
                EntityDelta::Modified { new, .. } => {
                    entity_map.insert(new.id, new.clone());
                }
                EntityDelta::Removed(id) => {
                    entity_map.remove(id);
                }
            }
        }
    }

    entity_map.into_values().collect()
}

/// Build a merge SemanticChange with two parents.
fn build_merge_change(
    ours_head: &SemanticChangeId,
    theirs_head: &SemanticChangeId,
    their_changes: &[SemanticChange],
    message: &str,
) -> SemanticChange {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"kin-merge-v1:");
    hasher.update(ours_head.0.as_bytes());
    hasher.update(theirs_head.0.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    let id = SemanticChangeId::from_hash(Hash256::from_bytes(bytes));

    // Collect all deltas from their side
    let entity_deltas: Vec<_> = their_changes
        .iter()
        .flat_map(|c| c.entity_deltas.clone())
        .collect();
    let relation_deltas: Vec<_> = their_changes
        .iter()
        .flat_map(|c| c.relation_deltas.clone())
        .collect();
    let artifact_deltas: Vec<_> = their_changes
        .iter()
        .flat_map(|c| c.artifact_deltas.clone())
        .collect();

    SemanticChange {
        id,
        parents: vec![*ours_head, *theirs_head],
        timestamp: Timestamp::now(),
        author: AuthorId::new("kin-merge"),
        message: message.to_string(),
        entity_deltas,
        relation_deltas,
        artifact_deltas,
        projected_files: vec![],
        spec_link: None,
        evidence: vec![],
        risk_summary: None,
        authored_on: None,
    }
}
