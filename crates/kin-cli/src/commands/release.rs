// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::provenance::ApprovalDecision;
use kin_model::{
    ArtifactDeltaKind, AuthorId, EntityDelta, GraphStore, Hash256, RelationDelta, SemanticChange,
    SemanticChangeId, Timestamp, Visibility, WorkId,
};

/// Semver bump level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SemverBump {
    Patch,
    Minor,
    Major,
}

impl std::fmt::Display for SemverBump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SemverBump::Patch => write!(f, "patch"),
            SemverBump::Minor => write!(f, "minor"),
            SemverBump::Major => write!(f, "major"),
        }
    }
}

/// Analyze entity changes since the last tag and suggest a semver bump.
///
/// `kin semver` walks the change history from HEAD back to the genesis
/// (or a future tag mechanism), classifying each entity delta:
///   - Removed public entity -> major (breaking)
///   - Modified public entity signature -> major (breaking)
///   - Added public entity -> minor (additive)
///   - Modified private/internal -> patch
///   - Any other modification -> patch
pub async fn semver() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();

    let branch_name = kin_core::read_current_branch(&layout)?;
    let branch = graph
        .get_branch(&branch_name)?
        .ok_or_else(|| anyhow::anyhow!("branch '{}' not found", branch_name))?;

    // Walk change history from HEAD
    let changes = collect_changes_from_head(&graph, &branch.head, 100)?;

    if changes.is_empty() {
        println!("No changes found on branch '{}'.", branch_name);
        return Ok(());
    }

    let mut max_bump = SemverBump::Patch;
    let mut breaking_reasons: Vec<String> = Vec::new();
    let mut additive_count = 0u32;
    let mut patch_count = 0u32;

    for change in &changes {
        for delta in &change.entity_deltas {
            match delta {
                EntityDelta::Removed(id) => {
                    // Removing any entity is potentially breaking.
                    // We'd need the entity to check visibility, but since it's removed
                    // we treat removal as breaking.
                    breaking_reasons.push(format!("removed entity {}", id));
                    max_bump = SemverBump::Major;
                }
                EntityDelta::Modified { old, new } => {
                    if old.visibility == Visibility::Public
                        && old.fingerprint.signature_hash != new.fingerprint.signature_hash
                    {
                        breaking_reasons.push(format!("changed public signature: {}", old.name));
                        max_bump = max_bump.max(SemverBump::Major);
                    } else if old.visibility == Visibility::Public
                        && new.visibility != Visibility::Public
                    {
                        breaking_reasons.push(format!(
                            "reduced visibility: {} (public -> {:?})",
                            old.name, new.visibility
                        ));
                        max_bump = max_bump.max(SemverBump::Major);
                    } else {
                        patch_count += 1;
                    }
                }
                EntityDelta::Added(entity) => {
                    if entity.visibility == Visibility::Public {
                        additive_count += 1;
                        max_bump = max_bump.max(SemverBump::Minor);
                    } else {
                        patch_count += 1;
                    }
                }
            }
        }
    }

    println!("Semver analysis for branch '{}':", branch_name);
    println!("  Changes analyzed: {}", changes.len());
    println!("  Suggested bump:   {}", max_bump);
    println!();

    if !breaking_reasons.is_empty() {
        println!("  Breaking changes ({}):", breaking_reasons.len());
        for reason in &breaking_reasons {
            println!("    - {}", reason);
        }
    }
    if additive_count > 0 {
        println!("  Additive (new public entities): {}", additive_count);
    }
    if patch_count > 0 {
        println!("  Patch-level modifications:      {}", patch_count);
    }

    Ok(())
}

/// Release gating options.
#[derive(Default)]
pub struct ReleaseOptions {
    pub force: bool,
    pub require_proof: bool,
    pub require_approval: bool,
}


/// Create a release change that snapshots the current entity graph state.
///
/// `kin release <tag>` creates a special SemanticChange with a release message
/// that marks the current graph state as a versioned release point.
///
/// Gating checks:
///   - Coverage ratio < 0.5 warns and requires `--force` to proceed
///   - `--require-proof`: blocks if any entity in the change lacks linked passing tests
///   - `--require-approval`: blocks if unapproved agent changes exist
pub async fn release_with_options(tag: String, opts: ReleaseOptions) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*snap.graph();

    let branch_name = kin_core::read_current_branch(&layout)?;
    let branch = graph
        .get_branch(&branch_name)?
        .ok_or_else(|| anyhow::anyhow!("branch '{}' not found", branch_name))?;

    let entities = graph.list_all_entities()?;

    // Gating: coverage ratio check
    let summary = graph.get_coverage_summary()?;
    if summary.coverage_ratio < 0.5 {
        if opts.force {
            eprintln!(
                "Warning: coverage ratio {:.1}% is below 50% threshold, proceeding with --force.",
                summary.coverage_ratio * 100.0
            );
        } else {
            anyhow::bail!(
                "Release blocked: coverage ratio {:.1}% is below 50% threshold. Use --force to override.",
                summary.coverage_ratio * 100.0
            );
        }
    }

    // Gating: --require-proof
    if opts.require_proof && !summary.missing_proof.is_empty() {
        let missing_names: Vec<String> = summary
            .missing_proof
            .iter()
            .filter_map(|eid| graph.get_entity(eid).ok().flatten().map(|e| e.name))
            .collect();
        anyhow::bail!(
            "Release blocked: {} entity(ies) lack linked passing tests: {}",
            missing_names.len(),
            missing_names.join(", ")
        );
    }

    // Gating: --require-approval (check recent changes for unapproved agent changes)
    if opts.require_approval {
        let changes = collect_changes_from_head(&graph, &branch.head, 50)?;
        let mut unapproved = Vec::new();
        for change in &changes {
            let approvals = graph.get_approvals_for_change(&change.id)?;
            let is_approved = approvals
                .iter()
                .any(|a| a.decision == ApprovalDecision::Approved);
            if !is_approved && change.author.0.contains("agent") {
                unapproved.push(format!("{} ({})", change.id, change.author));
            }
        }
        if !unapproved.is_empty() {
            anyhow::bail!(
                "Release blocked: {} unapproved agent change(s): {}",
                unapproved.len(),
                unapproved.join(", ")
            );
        }
    }

    // Build a release change — empty deltas, just a marker with entity count snapshot
    let change_id = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(format!("release:{}:{}", tag, branch.head).as_bytes());
        hasher.update(chrono::Utc::now().to_rfc3339().as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        SemanticChangeId::from_hash(Hash256::from_bytes(bytes))
    };

    let release_change = SemanticChange {
        id: change_id,
        parents: vec![branch.head],
        timestamp: Timestamp::now(),
        author: AuthorId::new("kin-release"),
        message: format!("release: {} ({} entities snapshot)", tag, entities.len()),
        entity_deltas: Vec::new(),
        relation_deltas: Vec::new(),
        artifact_deltas: Vec::new(),
        projected_files: Vec::new(),
        spec_link: None,
        evidence: Vec::new(),
        risk_summary: None,
        authored_on: Some(branch_name.clone()),
    };

    graph.create_change(&release_change)?;
    graph.update_branch_head(&branch_name, &change_id)?;
    snap.save()?;
    println!("Snapshot saved.");

    println!("Release '{}' created on branch '{}'.", tag, branch_name);
    println!("  Change: {}", change_id);
    println!("  Entities: {}", entities.len());
    println!("  Parent: {}", branch.head);

    Ok(())
}

/// Revert to a previous semantic change, restoring entity graph state.
///
/// `kin rollback <change_id>` creates a new change that reverses entity deltas
/// from HEAD back to the specified change.
///
/// `kin rollback --feature <work_id>` finds all changes linked to a work item
/// via graph traversal and reverses them in topological order.
pub async fn rollback_with_options(change_id_str: String, feature: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*snap.graph();

    let branch_name = kin_core::read_current_branch(&layout)?;
    let branch = graph
        .get_branch(&branch_name)?
        .ok_or_else(|| anyhow::anyhow!("branch '{}' not found", branch_name))?;

    // Feature-based rollback: find all changes linked to a work item
    if let Some(work_id_str) = feature {
        let work_uuid = uuid::Uuid::parse_str(&work_id_str)
            .map_err(|e| anyhow::anyhow!("invalid work ID '{}': {}", work_id_str, e))?;
        let work_id = WorkId(work_uuid);

        let work_item = graph
            .get_work_item(&work_id)?
            .ok_or_else(|| anyhow::anyhow!("work item '{}' not found", work_id_str))?;

        // Walk HEAD history and find changes that reference the work item
        let all_changes = collect_changes_from_head(&graph, &branch.head, 200)?;

        // Collect changes whose message references the work item ID
        let mut feature_changes: Vec<&SemanticChange> = Vec::new();
        for change in &all_changes {
            // Check if this change's message references the work item
            if change.message.contains(&work_id_str) {
                feature_changes.push(change);
            }
        }

        if feature_changes.is_empty() {
            println!(
                "No changes found linked to work item '{}' ({}).",
                work_item.title, work_id_str
            );
            return Ok(());
        }

        println!(
            "Rolling back {} change(s) linked to work item '{}' ({}):",
            feature_changes.len(),
            work_item.title,
            work_id_str
        );

        // Reverse in topological order (newest first — already in HEAD-first order)
        let mut reversed_entity_deltas = Vec::new();
        let mut reversed_relation_deltas = Vec::new();
        let mut reversed_artifact_deltas = Vec::new();

        for change in &feature_changes {
            println!("  reverting: {} - {}", change.id, change.message);
            for delta in &change.entity_deltas {
                let reversed = match delta {
                    EntityDelta::Added(entity) => EntityDelta::Removed(entity.id),
                    EntityDelta::Removed(id) => {
                        if let Some(entity) = graph.get_entity(id)? {
                            EntityDelta::Added(entity)
                        } else {
                            continue;
                        }
                    }
                    EntityDelta::Modified { old, new } => EntityDelta::Modified {
                        old: new.clone(),
                        new: old.clone(),
                    },
                };
                reversed_entity_deltas.push(reversed);
            }
            for delta in &change.relation_deltas {
                let reversed = match delta {
                    RelationDelta::Added(rel) => RelationDelta::Removed(rel.id),
                    RelationDelta::Removed(_id) => continue,
                };
                reversed_relation_deltas.push(reversed);
            }
            for delta in &change.artifact_deltas {
                let reversed_kind = match delta.kind {
                    ArtifactDeltaKind::Added => ArtifactDeltaKind::Removed,
                    ArtifactDeltaKind::Removed => ArtifactDeltaKind::Added,
                    ArtifactDeltaKind::Modified => ArtifactDeltaKind::Modified,
                };
                reversed_artifact_deltas.push(kin_model::ArtifactDelta {
                    file_id: delta.file_id.clone(),
                    kind: reversed_kind,
                    old_hash: delta.new_hash,
                    new_hash: delta.old_hash,
                });
            }
        }

        let rollback_change_id = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(format!("feature-rollback:{}:{}", work_id_str, branch.head).as_bytes());
            hasher.update(chrono::Utc::now().to_rfc3339().as_bytes());
            let result = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            SemanticChangeId::from_hash(Hash256::from_bytes(bytes))
        };

        let rollback_change = SemanticChange {
            id: rollback_change_id,
            parents: vec![branch.head],
            timestamp: Timestamp::now(),
            author: AuthorId::new("kin-rollback"),
            message: format!(
                "rollback: revert feature '{}' ({} change(s))",
                work_item.title,
                feature_changes.len()
            ),
            entity_deltas: reversed_entity_deltas,
            relation_deltas: reversed_relation_deltas,
            artifact_deltas: reversed_artifact_deltas,
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            authored_on: Some(branch_name.clone()),
        };

        for delta in &rollback_change.entity_deltas {
            match delta {
                EntityDelta::Added(entity) => {
                    graph.upsert_entity(entity)?;
                }
                EntityDelta::Removed(id) => {
                    graph.remove_entity(id)?;
                }
                EntityDelta::Modified { new, .. } => {
                    graph.upsert_entity(new)?;
                }
            }
        }
        for delta in &rollback_change.relation_deltas {
            match delta {
                RelationDelta::Added(rel) => {
                    graph.upsert_relation(rel)?;
                }
                RelationDelta::Removed(id) => {
                    graph.remove_relation(id)?;
                }
            }
        }

        graph.create_change(&rollback_change)?;
        graph.update_branch_head(&branch_name, &rollback_change_id)?;
        snap.save()?;
        println!("Snapshot saved.");

        println!("  Rollback change: {}", rollback_change_id);
        println!(
            "  Entity deltas reversed: {}",
            rollback_change.entity_deltas.len()
        );

        return Ok(());
    }

    let target_id = SemanticChangeId::from_hash(
        Hash256::from_hex(&change_id_str)
            .map_err(|e| anyhow::anyhow!("invalid change ID '{}': {}", change_id_str, e))?,
    );

    // Verify target change exists
    let target_change = graph
        .get_change(&target_id)?
        .ok_or_else(|| anyhow::anyhow!("change '{}' not found", change_id_str))?;

    // Get changes between target and HEAD (these are the ones we want to reverse)
    let changes_to_reverse = graph.get_changes_since(&target_id, &branch.head)?;

    if changes_to_reverse.is_empty() {
        println!(
            "Already at change '{}', nothing to rollback.",
            change_id_str
        );
        return Ok(());
    }

    // Build reversed deltas: walk changes in reverse, invert each delta
    let mut reversed_entity_deltas = Vec::new();
    let mut reversed_relation_deltas = Vec::new();
    let mut reversed_artifact_deltas = Vec::new();

    for change in changes_to_reverse.iter().rev() {
        for delta in &change.entity_deltas {
            let reversed = match delta {
                EntityDelta::Added(entity) => EntityDelta::Removed(entity.id),
                EntityDelta::Removed(id) => {
                    // We need the entity to restore it — try to get from graph
                    if let Some(entity) = graph.get_entity(id)? {
                        EntityDelta::Added(entity)
                    } else {
                        // Entity already gone, skip
                        continue;
                    }
                }
                EntityDelta::Modified { old, new } => EntityDelta::Modified {
                    old: new.clone(),
                    new: old.clone(),
                },
            };
            reversed_entity_deltas.push(reversed);
        }

        for delta in &change.relation_deltas {
            let reversed = match delta {
                RelationDelta::Added(rel) => RelationDelta::Removed(rel.id),
                RelationDelta::Removed(id) => {
                    // Cannot restore removed relations without the full relation data.
                    // Log and skip.
                    eprintln!("  warning: cannot restore removed relation {}", id);
                    continue;
                }
            };
            reversed_relation_deltas.push(reversed);
        }

        for delta in &change.artifact_deltas {
            let reversed_kind = match delta.kind {
                ArtifactDeltaKind::Added => ArtifactDeltaKind::Removed,
                ArtifactDeltaKind::Removed => ArtifactDeltaKind::Added,
                ArtifactDeltaKind::Modified => ArtifactDeltaKind::Modified,
            };
            reversed_artifact_deltas.push(kin_model::ArtifactDelta {
                file_id: delta.file_id.clone(),
                kind: reversed_kind,
                old_hash: delta.new_hash,
                new_hash: delta.old_hash,
            });
        }
    }

    // Create the rollback change
    let rollback_change_id = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(format!("rollback:{}:{}", change_id_str, branch.head).as_bytes());
        hasher.update(chrono::Utc::now().to_rfc3339().as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        SemanticChangeId::from_hash(Hash256::from_bytes(bytes))
    };

    let rollback_change = SemanticChange {
        id: rollback_change_id,
        parents: vec![branch.head],
        timestamp: Timestamp::now(),
        author: AuthorId::new("kin-rollback"),
        message: format!(
            "rollback: revert {} change(s) to {}",
            changes_to_reverse.len(),
            &change_id_str[..change_id_str.len().min(12)]
        ),
        entity_deltas: reversed_entity_deltas,
        relation_deltas: reversed_relation_deltas,
        artifact_deltas: reversed_artifact_deltas,
        projected_files: target_change.projected_files.clone(),
        spec_link: None,
        evidence: Vec::new(),
        risk_summary: None,
        authored_on: Some(branch_name.clone()),
    };

    // Apply reversed entity deltas to the graph
    for delta in &rollback_change.entity_deltas {
        match delta {
            EntityDelta::Added(entity) => {
                graph.upsert_entity(entity)?;
            }
            EntityDelta::Removed(id) => {
                graph.remove_entity(id)?;
            }
            EntityDelta::Modified { new, .. } => {
                graph.upsert_entity(new)?;
            }
        }
    }

    for delta in &rollback_change.relation_deltas {
        match delta {
            RelationDelta::Added(rel) => {
                graph.upsert_relation(rel)?;
            }
            RelationDelta::Removed(id) => {
                graph.remove_relation(id)?;
            }
        }
    }

    graph.create_change(&rollback_change)?;
    graph.update_branch_head(&branch_name, &rollback_change_id)?;
    snap.save()?;
    println!("Snapshot saved.");

    println!(
        "Rolled back {} change(s) on branch '{}'.",
        changes_to_reverse.len(),
        branch_name
    );
    println!(
        "  Target:   {} - {}",
        target_change.id, target_change.message
    );
    println!("  Rollback: {}", rollback_change_id);
    println!(
        "  Entity deltas reversed: {}",
        rollback_change.entity_deltas.len()
    );

    Ok(())
}

/// Walk change history from HEAD, collecting up to `limit` changes.
fn collect_changes_from_head<G: GraphStore>(
    graph: &G,
    head: &SemanticChangeId,
    limit: usize,
) -> Result<Vec<SemanticChange>> {
    let mut changes = Vec::new();
    let mut current = *head;

    for _ in 0..limit {
        match graph.get_change(&current)? {
            Some(change) => {
                let parents = change.parents.clone();
                changes.push(change);
                // Follow first parent (linear history)
                if let Some(parent) = parents.first() {
                    current = *parent;
                } else {
                    break; // Genesis
                }
            }
            None => break,
        }
    }

    Ok(changes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_bump_ordering() {
        assert!(SemverBump::Patch < SemverBump::Minor);
        assert!(SemverBump::Minor < SemverBump::Major);
        assert_eq!(SemverBump::Patch.max(SemverBump::Minor), SemverBump::Minor);
        assert_eq!(SemverBump::Minor.max(SemverBump::Major), SemverBump::Major);
    }

    #[test]
    fn semver_bump_display() {
        assert_eq!(format!("{}", SemverBump::Patch), "patch");
        assert_eq!(format!("{}", SemverBump::Minor), "minor");
        assert_eq!(format!("{}", SemverBump::Major), "major");
    }
}
