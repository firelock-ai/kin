// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::provenance::ApprovalDecision;
use serde::Serialize;

#[derive(Serialize)]
struct ReviewFindingJson {
    entity: String,
    kind: String,
    file: String,
    line: u32,
    severity: &'static str,
    message: String,
}

#[derive(Serialize)]
struct ReviewResultJson {
    file: String,
    findings: Vec<ReviewFindingJson>,
    summary: String,
}

pub async fn run(
    change: Option<String>,
    entities: Option<String>,
    files: Option<String>,
    changes: Option<String>,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();

    use kin_model::GraphStore;

    // --- Arbitrary change set modes ---
    // --entities: review specific entity IDs (UUIDs)
    if let Some(entity_csv) = entities {
        let entity_ids: Vec<kin_model::EntityId> = entity_csv
            .split(',')
            .map(|s| {
                let trimmed = s.trim();
                let uuid = uuid::Uuid::parse_str(trimmed)
                    .map_err(|e| anyhow::anyhow!("invalid entity UUID '{}': {}", trimmed, e))?;
                Ok(kin_model::EntityId(uuid))
            })
            .collect::<Result<Vec<_>>>()?;

        println!("Reviewing {} user-specified entities", entity_ids.len());
        println!();

        let review = kin_review::SemanticReview::review_entities(&entity_ids, &graph)?;
        print!("{}", kin_review::format_review(&review));
        return Ok(());
    }

    // --files: review all entities from specific files
    if let Some(file_csv) = files {
        let file_paths: Vec<String> = file_csv.split(',').map(|s| s.trim().to_string()).collect();

        println!("Reviewing entities from {} files:", file_paths.len());
        for f in &file_paths {
            println!("  {}", f);
        }
        println!();

        let review = kin_review::SemanticReview::review_files(&file_paths, &graph)?;
        print!("{}", kin_review::format_review(&review));
        return Ok(());
    }

    // --changes: combine multiple change IDs into one review
    if let Some(change_csv) = changes {
        let change_ids: Vec<kin_model::SemanticChangeId> = change_csv
            .split(',')
            .map(|s| {
                let trimmed = s.trim();
                Ok(kin_model::SemanticChangeId::from_hash(
                    kin_model::Hash256::from_hex(trimmed)
                        .map_err(|e| anyhow::anyhow!("invalid change ID '{}': {}", trimmed, e))?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        let mut semantic_changes = Vec::new();
        for cid in &change_ids {
            let sc = graph
                .get_change(cid)?
                .ok_or_else(|| anyhow::anyhow!("change {} not found", cid))?;
            semantic_changes.push(sc);
        }

        println!(
            "Reviewing {} user-specified changes as a single unit",
            semantic_changes.len()
        );
        println!();

        let review = kin_review::SemanticReview::review_changes(&semantic_changes, &graph)?;
        print!("{}", kin_review::format_review(&review));
        return Ok(());
    }

    // --- Default mode: single change ID (original behavior) ---
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

pub async fn run_json(
    change: Option<String>,
    entities: Option<String>,
    files: Option<String>,
    changes: Option<String>,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();

    use kin_model::GraphStore;

    let (review, file_hint) = if let Some(entity_csv) = entities {
        let entity_ids: Vec<kin_model::EntityId> = entity_csv
            .split(',')
            .map(|s| {
                let trimmed = s.trim();
                let uuid = uuid::Uuid::parse_str(trimmed)
                    .map_err(|e| anyhow::anyhow!("invalid entity UUID '{}': {}", trimmed, e))?;
                Ok(kin_model::EntityId(uuid))
            })
            .collect::<Result<Vec<_>>>()?;
        (kin_review::SemanticReview::review_entities(&entity_ids, &graph)?, String::new())
    } else if let Some(file_csv) = files {
        let file_paths: Vec<String> = file_csv.split(',').map(|s| s.trim().to_string()).collect();
        let hint = file_paths.first().cloned().unwrap_or_default();
        (kin_review::SemanticReview::review_files(&file_paths, &graph)?, hint)
    } else if let Some(change_csv) = changes {
        let change_ids: Vec<kin_model::SemanticChangeId> = change_csv
            .split(',')
            .map(|s| {
                let trimmed = s.trim();
                Ok(kin_model::SemanticChangeId::from_hash(
                    kin_model::Hash256::from_hex(trimmed)
                        .map_err(|e| anyhow::anyhow!("invalid change ID '{}': {}", trimmed, e))?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        let mut semantic_changes = Vec::new();
        for cid in &change_ids {
            let sc = graph
                .get_change(cid)?
                .ok_or_else(|| anyhow::anyhow!("change {} not found", cid))?;
            semantic_changes.push(sc);
        }
        (
            kin_review::SemanticReview::review_changes(&semantic_changes, &graph)?,
            String::new(),
        )
    } else {
        let change_id = match change {
            Some(h) => kin_model::SemanticChangeId::from_hash(
                kin_model::Hash256::from_hex(&h)
                    .map_err(|e| anyhow::anyhow!("invalid hash: {}", e))?,
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

        let review = if let Some(parent_id) = semantic_change.parents.first() {
            match kin_review::SemanticReview::create_review(parent_id, &change_id, &graph) {
                Ok(r) => r,
                Err(_) => {
                    let diff = kin_review::diff_from_change(&semantic_change);
                    kin_review::SemanticReview::review_from_diff(diff, &graph)?
                }
            }
        } else {
            let diff = kin_review::diff_from_change(&semantic_change);
            kin_review::SemanticReview::review_from_diff(diff, &graph)?
        };

        (review, String::new())
    };

    let findings = review
        .inline_comments
        .iter()
        .map(|comment| ReviewFindingJson {
            entity: comment.file.clone(),
            kind: format!("{:?}", comment.kind),
            file: comment.file.clone(),
            line: comment.start_line,
            severity: inline_comment_severity(comment.kind),
            message: comment.message.clone(),
        })
        .collect::<Vec<_>>();

    let summary = format!(
        "Overall risk: {:?}; {} finding(s)",
        review.risk.overall_risk,
        findings.len()
    );

    println!(
        "{}",
        serde_json::to_string(&ReviewResultJson {
            file: file_hint,
            findings,
            summary,
        })?
    );
    Ok(())
}

fn inline_comment_severity(kind: kin_review::InlineCommentKind) -> &'static str {
    use kin_review::InlineCommentKind;

    match kind {
        InlineCommentKind::Breaking | InlineCommentKind::ContractViolation => "error",
        InlineCommentKind::CoverageGap
        | InlineCommentKind::SignatureChange
        | InlineCommentKind::VisibilityChange
        | InlineCommentKind::Renamed
        | InlineCommentKind::AgentUnreviewed => "warning",
        InlineCommentKind::Added | InlineCommentKind::Removed => "info",
    }
}
