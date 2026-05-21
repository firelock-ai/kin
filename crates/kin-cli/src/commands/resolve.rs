// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::ChangeStore;
use kin_model::{
    AuthorId, BranchName, EntityDelta, Hash256, SemanticChange, SemanticChangeId, Timestamp,
};

use crate::commands::conflicts::{
    clear_merge_state, load_merge_state, save_merge_state, ConflictResolution,
};

/// `kin resolve` — Resolve merge conflicts interactively.
///
/// Strategies:
///   --ours <entity>     Mark a single conflict as resolved (keep ours)
///   --theirs <entity>   Mark a single conflict as resolved (keep theirs)
///   --all-ours          Resolve all remaining conflicts keeping ours
///   --all-theirs        Resolve all remaining conflicts keeping theirs
///   --continue          Complete the merge after all conflicts are resolved
///   --abort             Abort the merge and discard conflict state
pub async fn run(
    ours: Option<String>,
    theirs: Option<String>,
    all_ours: bool,
    all_theirs: bool,
    do_continue: bool,
    abort: bool,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    // Abort is special — just clear state and return.
    if abort {
        return run_abort(&layout);
    }

    let mut state = load_merge_state(&layout)?
        .ok_or_else(|| anyhow::anyhow!("no merge in progress (no conflict state found)"))?;

    // Resolve individual conflicts.
    if let Some(ref entity_query) = ours {
        resolve_single(&mut state, entity_query, ConflictResolution::Ours)?;
        save_merge_state(&layout, &state)?;
        print_progress(&state);
        return Ok(());
    }
    if let Some(ref entity_query) = theirs {
        resolve_single(&mut state, entity_query, ConflictResolution::Theirs)?;
        save_merge_state(&layout, &state)?;
        print_progress(&state);
        return Ok(());
    }

    // Resolve all remaining.
    if all_ours {
        resolve_all(&mut state, ConflictResolution::Ours);
        save_merge_state(&layout, &state)?;
        print_progress(&state);
        return Ok(());
    }
    if all_theirs {
        resolve_all(&mut state, ConflictResolution::Theirs);
        save_merge_state(&layout, &state)?;
        print_progress(&state);
        return Ok(());
    }

    // Continue — complete the merge.
    if do_continue {
        return run_continue(&layout, &state).await;
    }

    // No flags — show usage.
    anyhow::bail!(
        "no resolution action specified.\n\n\
         Usage:\n  \
         kin resolve --ours <entity>      Keep your version of entity\n  \
         kin resolve --theirs <entity>    Keep incoming version of entity\n  \
         kin resolve --all-ours           Resolve all: keep yours\n  \
         kin resolve --all-theirs         Resolve all: keep incoming\n  \
         kin resolve --continue           Complete merge\n  \
         kin resolve --abort              Abort merge"
    );
}

/// Resolve a single conflict by entity name or ID prefix.
fn resolve_single(
    state: &mut crate::commands::conflicts::PersistedMergeState,
    query: &str,
    resolution: ConflictResolution,
) -> Result<()> {
    let query_lower = query.to_lowercase();

    // Match by entity name (exact, case-insensitive) or entity ID prefix.
    let matches: Vec<usize> = state
        .conflicts
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            c.entity_name.to_lowercase() == query_lower
                || c.entity_id.to_lowercase().starts_with(&query_lower)
        })
        .map(|(i, _)| i)
        .collect();

    match matches.len() {
        0 => anyhow::bail!(
            "no conflict matching '{}'. Run `kin conflicts` to see active conflicts.",
            query
        ),
        1 => {
            let idx = matches[0];
            let c = &mut state.conflicts[idx];
            let label = match &resolution {
                ConflictResolution::Ours => "ours",
                ConflictResolution::Theirs => "theirs",
            };
            println!("Resolved: {} ({}) -> {}", c.entity_name, c.entity_id, label);
            c.resolution = Some(resolution);
            Ok(())
        }
        n => {
            let mut msg = format!("ambiguous: '{}' matches {} conflicts:\n", query, n);
            for idx in matches {
                let c = &state.conflicts[idx];
                msg.push_str(&format!("  {} — {}\n", c.entity_id, c.entity_name));
            }
            msg.push_str("\nUse the full entity ID to disambiguate.");
            anyhow::bail!(msg);
        }
    }
}

/// Resolve all remaining unresolved conflicts with the given resolution.
fn resolve_all(
    state: &mut crate::commands::conflicts::PersistedMergeState,
    resolution: ConflictResolution,
) {
    let label = match &resolution {
        ConflictResolution::Ours => "ours",
        ConflictResolution::Theirs => "theirs",
    };
    let mut count = 0;
    for c in &mut state.conflicts {
        if c.resolution.is_none() {
            c.resolution = Some(resolution.clone());
            count += 1;
        }
    }
    println!("Resolved {} conflict(s) as '{}'.", count, label);
}

/// Print post-resolution progress summary.
fn print_progress(state: &crate::commands::conflicts::PersistedMergeState) {
    let unresolved = state.unresolved_count();
    if unresolved == 0 {
        println!("\nAll conflicts resolved. Run `kin resolve --continue` to complete the merge.");
    } else {
        println!(
            "\n{} conflict(s) remaining. Run `kin conflicts` to see them.",
            unresolved
        );
    }
}

/// Abort the merge and clear conflict state.
fn run_abort(layout: &kin_core::KinLayout) -> Result<()> {
    if !layout.merge_state_path().exists() {
        println!("No merge in progress.");
        return Ok(());
    }
    clear_merge_state(layout)?;
    println!("Merge aborted. Conflict state cleared.");
    Ok(())
}

/// Complete the merge after all conflicts have been resolved.
async fn run_continue(
    layout: &kin_core::KinLayout,
    state: &crate::commands::conflicts::PersistedMergeState,
) -> Result<()> {
    let unresolved = state.unresolved_count();
    if unresolved > 0 {
        anyhow::bail!(
            "{} conflict(s) still unresolved. Resolve them first with `kin resolve`, \
             or run `kin resolve --abort` to cancel the merge.",
            unresolved
        );
    }

    let snapshot = crate::backend::open_snapshot_daemon_first_read_only(layout).await?;
    let graph = snapshot.graph();
    let graph = &*graph;

    // Verify branches still exist and heads haven't changed.
    let target_branch = graph
        .get_branch(&BranchName::new(&state.target_branch))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "target branch '{}' no longer exists in graph",
                state.target_branch
            )
        })?;
    if target_branch.head.to_string() != state.target_head {
        anyhow::bail!(
            "target branch '{}' head has changed since merge started \
             (was {}, now {}). Abort and re-merge.",
            state.target_branch,
            state.target_head,
            target_branch.head
        );
    }

    let source_head_hash = Hash256::from_hex(&state.source_head)
        .map_err(|e| anyhow::anyhow!("invalid source head hash: {}", e))?;
    let source_head = SemanticChangeId::from_hash(source_head_hash);
    let target_head_hash = Hash256::from_hex(&state.target_head)
        .map_err(|e| anyhow::anyhow!("invalid target head hash: {}", e))?;
    let target_head = SemanticChangeId::from_hash(target_head_hash);

    // Build entity deltas based on resolution choices.
    // For "theirs": include their changes. For "ours": exclude (keep ours).
    let theirs_changes = graph.get_changes_since(&target_head, &source_head)?;
    let mut included_deltas = Vec::new();
    let mut included_relation_deltas = Vec::new();
    let mut included_artifact_deltas = Vec::new();

    // Collect entity IDs resolved as "ours" (skip their deltas for these).
    let ours_entity_ids: std::collections::HashSet<String> = state
        .conflicts
        .iter()
        .filter(|c| matches!(c.resolution, Some(ConflictResolution::Ours)))
        .map(|c| c.entity_id.clone())
        .collect();

    for change in &theirs_changes {
        for delta in &change.entity_deltas {
            let entity_id_str = match delta {
                EntityDelta::Added(e) => e.id.to_string(),
                EntityDelta::Modified { new, .. } => new.id.to_string(),
                EntityDelta::Removed(id) => id.to_string(),
            };
            // Skip deltas for entities we chose "ours" on.
            if !ours_entity_ids.contains(&entity_id_str) {
                included_deltas.push(delta.clone());
            }
        }
        // Include all non-entity deltas (relations, artifacts).
        included_relation_deltas.extend(change.relation_deltas.clone());
        included_artifact_deltas.extend(change.artifact_deltas.clone());
    }

    // Build merge commit.
    let merge = build_resolution_merge(
        &target_head,
        &source_head,
        included_deltas,
        included_relation_deltas,
        included_artifact_deltas,
        &format!(
            "Merge '{}' into '{}' (conflicts resolved)",
            state.source_branch, state.target_branch
        ),
    );

    crate::backend::require_daemon_commit(&layout, &merge, &state.target_branch).await?;

    // Clear the merge state.
    clear_merge_state(layout)?;

    println!(
        "Merge complete: '{}' into '{}'",
        state.source_branch, state.target_branch
    );
    println!("  Merge commit: {}", merge.id);
    println!(
        "  {} conflict(s) resolved ({} kept ours, {} kept theirs)",
        state.conflicts.len(),
        state
            .conflicts
            .iter()
            .filter(|c| matches!(c.resolution, Some(ConflictResolution::Ours)))
            .count(),
        state
            .conflicts
            .iter()
            .filter(|c| matches!(c.resolution, Some(ConflictResolution::Theirs)))
            .count(),
    );

    Ok(())
}

/// Build a merge SemanticChange from resolved conflict deltas.
fn build_resolution_merge(
    ours_head: &SemanticChangeId,
    theirs_head: &SemanticChangeId,
    entity_deltas: Vec<EntityDelta>,
    relation_deltas: Vec<kin_model::RelationDelta>,
    artifact_deltas: Vec<kin_model::ArtifactDelta>,
    message: &str,
) -> SemanticChange {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"kin-merge-resolved-v1:");
    hasher.update(ours_head.0.as_bytes());
    hasher.update(theirs_head.0.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    let id = SemanticChangeId::from_hash(Hash256::from_bytes(bytes));

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
