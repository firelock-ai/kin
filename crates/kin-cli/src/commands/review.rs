use anyhow::Result;
use kin_model::provenance::ApprovalDecision;

pub async fn run(change: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_db::SnapshotManager::open(layout.graph_dir().join("kindb"))?.graph();

    use kin_model::GraphStore;

    let change_id = match change {
        Some(h) => kin_model::SemanticChangeId::from_hash(
            kin_model::Hash256::from_hex(&h).map_err(|e| anyhow::anyhow!("invalid hash: {}", e))?,
        ),
        None => {
            let current = kin_core::read_current_branch(&layout)?;
            let branch = graph
                .get_branch(&current)?
                .ok_or_else(|| anyhow::anyhow!("branch '{}' not found", current))?;
            branch.head
        }
    };

    let semantic_change = graph
        .get_change(&change_id)?
        .ok_or_else(|| anyhow::anyhow!("change {} not found", change_id))?;

    println!("Reviewing semantic change: {}", change_id);
    println!("  Message: {}", semantic_change.message);
    println!("  Author: {}", semantic_change.author);
    println!();

    // Compute full review on demand
    let review = if let Some(parent_id) = semantic_change.parents.first() {
        match kin_review::SemanticReview::create_review(parent_id, &change_id, &graph) {
            Ok(r) => r,
            Err(_) => {
                // Fall back to single-change diff
                let diff = kin_review::diff_from_change(&semantic_change);
                kin_review::SemanticReview::review_from_diff(diff, &graph)?
            }
        }
    } else {
        // No parent — use single-change diff
        let diff = kin_review::diff_from_change(&semantic_change);
        kin_review::SemanticReview::review_from_diff(diff, &graph)?
    };

    // Print the full formatted review
    print!("{}", kin_review::format_review(&review));

    // --- Provenance: Agent Changes Pending Review ---
    // Check approvals for this change and show attribution per changed entity
    let approvals = graph.get_approvals_for_change(&change_id)?;
    let is_agent_change = semantic_change.author.0.contains("agent")
        || semantic_change.author.0.contains("assistant")
        || semantic_change.author.0.contains("codex")
        || semantic_change.author.0.contains("claude")
        || semantic_change.author.0.contains("gemini");

    let is_approved = approvals
        .iter()
        .any(|a| a.decision == ApprovalDecision::Approved);

    if is_agent_change || !approvals.is_empty() {
        println!();
        println!("--- Provenance ---");

        // Actor attribution per changed entity
        println!(
            "Author: {} {}",
            semantic_change.author,
            if is_agent_change {
                "(agent)"
            } else {
                "(human)"
            }
        );

        let changed_entity_count = semantic_change.entity_deltas.len();
        if changed_entity_count > 0 {
            println!("Changed entities: {}", changed_entity_count);
            for delta in &semantic_change.entity_deltas {
                match delta {
                    kin_model::EntityDelta::Added(e) => {
                        println!(
                            "  + {} ({:?}) by {}",
                            e.name, e.kind, semantic_change.author
                        );
                    }
                    kin_model::EntityDelta::Modified { new, .. } => {
                        println!(
                            "  ~ {} ({:?}) by {}",
                            new.name, new.kind, semantic_change.author
                        );
                    }
                    kin_model::EntityDelta::Removed(id) => {
                        println!("  - {} by {}", id, semantic_change.author);
                    }
                }
            }
        }

        // Agent changes pending review
        if is_agent_change && !is_approved {
            println!();
            println!("Agent Changes Pending Review:");
            println!(
                "  Change {} by {} has NO human approval.",
                change_id, semantic_change.author
            );
            if !approvals.is_empty() {
                for a in &approvals {
                    println!("  Approval: {} — {} ({})", a.approver, a.decision, a.reason);
                }
            }
        } else if is_agent_change && is_approved {
            println!();
            println!("Agent change approved:");
            for a in &approvals {
                if a.decision == ApprovalDecision::Approved {
                    println!("  Approved by {} — {}", a.approver, a.reason);
                }
            }
        }
    }

    Ok(())
}
