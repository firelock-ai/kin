use anyhow::Result;
use kin_model::{
    AuthorId, BranchName, EntityDelta, GraphStore, Hash256, SemanticChange, SemanticChangeId,
    Timestamp,
};

/// `kin merge <branch>` — Semantic two-phase merge.
///
/// Phase 1: structural (AST-level) merge via reconciler conflict detection.
/// Phase 2: semantic (fingerprint-aware) merge that preserves entity identity.
pub async fn run(branch: String, strategy: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

    // Resolve source branch.
    let source_branch = graph.get_branch(&BranchName::new(&branch))?;
    let source = source_branch
        .ok_or_else(|| anyhow::anyhow!("branch '{}' not found", branch))?;

    // Resolve current (target) branch from HEAD.
    let current_name = kin_core::read_current_branch(&layout)?;
    let current = graph
        .get_branch(&current_name)?
        .ok_or_else(|| anyhow::anyhow!("current branch '{}' not found in graph", current_name))?;

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
        println!("  No common ancestor found — branches are unrelated.");
        println!("  A full-tree merge would be required (not yet supported).");
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

    // Phase 1: structural check — compare entity sets for conflicts.
    let extract_ids = |deltas: &[EntityDelta]| -> Vec<kin_model::EntityId> {
        deltas
            .iter()
            .map(|d| match d {
                EntityDelta::Added(e) => e.id,
                EntityDelta::Modified { new, .. } => new.id,
                EntityDelta::Removed(id) => *id,
            })
            .collect()
    };

    let mut conflicts = Vec::new();
    for our_change in &ours {
        let our_ids = extract_ids(&our_change.entity_deltas);
        for their_change in &theirs {
            let their_ids = extract_ids(&their_change.entity_deltas);
            for our_id in &our_ids {
                if their_ids.contains(our_id) {
                    conflicts.push(format!(
                        "entity {} modified in both '{}' and '{}'",
                        our_id, current.name, branch
                    ));
                }
            }
        }
    }

    if conflicts.is_empty() {
        println!("\n  No conflicts detected — clean merge.");
        if ours.is_empty() {
            // Fast-forward: no changes on our side
            graph.update_branch_head(&current.name, &source.head)?;
            println!("  Fast-forward: '{}' -> {}", current.name, source.head);
        } else {
            // Diverged branches: create merge commit with two parents
            let merge = build_merge_change(
                &current.head,
                &source.head,
                &theirs,
                &format!("Merge '{}' into '{}'", branch, current.name),
            );
            graph.create_change(&merge)?;
            graph.update_branch_head(&current.name, &merge.id)?;
            println!("  Merge commit: {}", merge.id);
            println!("  Updated '{}' -> {}", current.name, merge.id);
        }
    } else {
        println!("\n  Conflicts detected ({}):", conflicts.len());
        for c in &conflicts {
            println!("    - {}", c);
        }
        match strategy.as_str() {
            "semantic" => {
                // Attempt fingerprint-based auto-resolution
                let mut auto_resolved = 0usize;
                let mut remaining = Vec::new();

                for c in &conflicts {
                    // Check if the entity was modified identically on both sides
                    // (same fingerprint = convergent change, can auto-resolve)
                    let is_convergent = ours.iter().any(|our_change| {
                        theirs.iter().any(|their_change| {
                            our_change.entity_deltas.iter().zip(their_change.entity_deltas.iter()).any(|(od, td)| {
                                match (od, td) {
                                    (EntityDelta::Modified { new: our_new, .. }, EntityDelta::Modified { new: their_new, .. }) => {
                                        our_new.fingerprint.ast_hash == their_new.fingerprint.ast_hash
                                    }
                                    _ => false,
                                }
                            })
                        })
                    });

                    if is_convergent {
                        auto_resolved += 1;
                    } else {
                        remaining.push(c.clone());
                    }
                }

                if auto_resolved > 0 {
                    println!("\n  Semantic strategy auto-resolved {} conflict(s) (convergent changes).", auto_resolved);
                }
                if !remaining.is_empty() {
                    println!("  {} conflict(s) require manual resolution:", remaining.len());
                    for r in &remaining {
                        println!("    - {}", r);
                    }
                } else if auto_resolved > 0 {
                    // All conflicts were auto-resolved
                    if ours.is_empty() {
                        graph.update_branch_head(&current.name, &source.head)?;
                        println!("  Fast-forward: '{}' -> {}", current.name, source.head);
                    } else {
                        let merge = build_merge_change(
                            &current.head,
                            &source.head,
                            &theirs,
                            &format!(
                                "Merge '{}' into '{}' (auto-resolved)",
                                branch, current.name
                            ),
                        );
                        graph.create_change(&merge)?;
                        graph.update_branch_head(&current.name, &merge.id)?;
                        println!("  Merge commit: {}", merge.id);
                        println!("  Updated '{}' -> {}", current.name, merge.id);
                    }
                }
            }
            _ => {
                println!("\n  Structural merge: manual conflict resolution required.");
            }
        }
    }

    Ok(())
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
