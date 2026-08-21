// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::fmt::Write;

use kin_model::provenance::ActorKind;
use kin_model::review::RiskLevel;

use crate::diff::{RelationChangeKind, SemanticDiff};
use crate::impact::ImpactReport;
use crate::inline::{group_by_file, InlineComment};
use crate::review::Review;

/// Format a full review for display.
pub fn format_review(review: &Review) -> String {
    let mut out = String::new();

    // Header
    writeln!(out, "=== Semantic Review ===").unwrap();
    if let Some(base) = &review.base {
        writeln!(out, "Base: {}", base).unwrap();
    }
    if let Some(head) = &review.head {
        writeln!(out, "Head: {}", head).unwrap();
    }
    writeln!(out).unwrap();

    // Entity changes
    out.push_str(&format_diff(&review.diff));

    // Inline comments (line-level)
    if !review.inline_comments.is_empty() {
        out.push_str(&format_inline_comments(&review.inline_comments));
    }

    // Impact summary
    out.push_str(&format_impact(&review.impact));

    // Risk highlights
    out.push_str(&format_risk_highlights(review));

    out
}

/// Convert a graph-owned 0-based line index to the 1-based line number every
/// editor, `file:line` reference, and diff hunk uses.
///
/// A review renders locations a reader clicks or greps, so emitting the raw
/// graph row sends them one line above the declaration. The agent-facing
/// surfaces convert at one seam per surface for this reason; this is that seam
/// for the review renderers.
pub(crate) fn presentation_line(graph_line: u32) -> u32 {
    graph_line.saturating_add(1)
}

/// `file:line` for an entity, or just the file when no span was captured.
fn entity_location(entity: &kin_model::entity::Entity) -> Option<String> {
    if let Some(span) = entity.span.as_ref() {
        return Some(format!(
            "{}:{}",
            span.file,
            presentation_line(span.start_line)
        ));
    }
    entity.file_origin.as_ref().map(|origin| origin.to_string())
}

/// Format entity-level diff.
pub fn format_diff(diff: &SemanticDiff) -> String {
    let mut out = String::new();

    // The provenance note comes before the empty check on purpose. A change
    // that re-emitted a whole file and edited nothing in it is exactly the case
    // where a bare "No entity changes." would look like the review had read
    // nothing, so the line that explains the discrepancy has to survive it.
    let provenance_note = if diff.provenance_only_entity_changes > 0 {
        Some(format!(
            "{} entity record(s) in the touched file(s) advanced only their span or source-blob \
             provenance and are not listed as modified.",
            diff.provenance_only_entity_changes,
        ))
    } else {
        None
    };

    if diff.is_empty() {
        writeln!(out, "No entity changes.").unwrap();
        if let Some(note) = provenance_note {
            writeln!(out, "{note}").unwrap();
        }
        return out;
    }

    writeln!(out, "--- Entity Changes ---").unwrap();

    let added = diff.added_entities();
    let modified = diff.modified_entities();
    let removed = diff.removed_entities();

    if !added.is_empty() {
        writeln!(out, "\nAdded ({}):", added.len()).unwrap();
        for entity in &added {
            writeln!(
                out,
                "  + {} ({:?}) — {}",
                entity.name, entity.kind, entity.signature,
            )
            .unwrap();
            if let Some(file) = &entity.file_origin {
                writeln!(out, "    file: {}", file).unwrap();
            }
        }
    }

    if let Some(note) = provenance_note {
        writeln!(out, "\n{note}").unwrap();
    }

    if !modified.is_empty() {
        writeln!(out, "\nModified ({}):", modified.len()).unwrap();
        for (old, new) in &modified {
            writeln!(out, "  ~ {} ({:?})", new.name, new.kind).unwrap();
            if old.signature != new.signature {
                writeln!(out, "    signature: {} -> {}", old.signature, new.signature).unwrap();
            }
            if old.name != new.name {
                writeln!(out, "    renamed: {} -> {}", old.name, new.name).unwrap();
            }
            if old.visibility != new.visibility {
                writeln!(
                    out,
                    "    visibility: {:?} -> {:?}",
                    old.visibility, new.visibility,
                )
                .unwrap();
            }
        }
    }

    if !removed.is_empty() {
        writeln!(out, "\nRemoved ({}):", removed.len()).unwrap();
        for (id, entity) in &removed {
            match entity {
                Some(entity) => {
                    writeln!(
                        out,
                        "  - {} ({:?}) — {}",
                        entity.name, entity.kind, entity.signature,
                    )
                    .unwrap();
                    if let Some(location) = entity_location(entity) {
                        writeln!(out, "    file: {}", location).unwrap();
                    }
                }
                // An unresolved removal is reported as one. Printing the id
                // alone would read as a name and hide that the base-side record
                // was unrecoverable.
                None => {
                    writeln!(out, "  - <unresolved removal> id {}", id).unwrap();
                    writeln!(
                        out,
                        "    no base-side record for this entity; its name, kind and location are unknown"
                    )
                    .unwrap();
                }
            }
        }
    }

    // Relation changes
    if !diff.relation_changes.is_empty() {
        writeln!(out, "\n--- Relation Changes ---").unwrap();
        for rel_change in &diff.relation_changes {
            match &rel_change.kind {
                RelationChangeKind::Added(rel) => {
                    writeln!(out, "  + {:?}: {} -> {}", rel.kind, rel.src, rel.dst,).unwrap();
                }
                RelationChangeKind::Modified { old, new } => {
                    writeln!(
                        out,
                        "  ~ {:?}: {} -> {} (was {:?}: {} -> {})",
                        new.kind, new.src, new.dst, old.kind, old.src, old.dst,
                    )
                    .unwrap();
                }
                RelationChangeKind::Removed { old } => {
                    writeln!(out, "  - {:?}: {} -> {}", old.kind, old.src, old.dst).unwrap();
                }
            }
        }
    }

    writeln!(out).unwrap();
    out
}

/// Format impact summary.
pub fn format_impact(impact: &ImpactReport) -> String {
    let mut out = String::new();

    if impact.is_empty() {
        writeln!(out, "No downstream impact detected.").unwrap();
        return out;
    }

    writeln!(out, "--- Impact Analysis ---").unwrap();
    writeln!(out, "Total affected entities: {}", impact.total_affected(),).unwrap();

    if !impact.affected_callers.is_empty() {
        writeln!(
            out,
            "\nAffected callers ({}):",
            impact.affected_callers.len()
        )
        .unwrap();
        for entity in &impact.affected_callers {
            writeln!(out, "  {} ({:?})", entity.name, entity.kind).unwrap();
        }
    }

    if !impact.affected_dependents.is_empty() {
        writeln!(
            out,
            "\nAffected dependents ({}):",
            impact.affected_dependents.len(),
        )
        .unwrap();
        for entity in &impact.affected_dependents {
            writeln!(out, "  {} ({:?})", entity.name, entity.kind).unwrap();
        }
    }

    if !impact.affected_contract_consumers.is_empty() {
        writeln!(
            out,
            "\nAffected contract consumers ({}):",
            impact.affected_contract_consumers.len(),
        )
        .unwrap();
        for entity in &impact.affected_contract_consumers {
            writeln!(out, "  {} ({:?})", entity.name, entity.kind).unwrap();
        }
    }

    if !impact.affected_tests.is_empty() {
        writeln!(out, "\nAffected tests ({}):", impact.affected_tests.len(),).unwrap();
        for entity in &impact.affected_tests {
            writeln!(out, "  {} ({:?})", entity.name, entity.kind).unwrap();
        }
    }

    if !impact.affected_work_items.is_empty() {
        writeln!(
            out,
            "\nAffected work items ({}):",
            impact.affected_work_items.len(),
        )
        .unwrap();
        for item in &impact.affected_work_items {
            writeln!(out, "  [{}] {} — {}", item.kind, item.title, item.status).unwrap();
        }
    }

    if !impact.affected_annotations.is_empty() {
        writeln!(
            out,
            "\nAffected annotations ({}):",
            impact.affected_annotations.len(),
        )
        .unwrap();
        for ann in &impact.affected_annotations {
            let preview = if ann.body.len() > 60 {
                format!("{}...", &ann.body[..60])
            } else {
                ann.body.clone()
            };
            writeln!(out, "  [{}] {} — \"{}\"", ann.kind, ann.staleness, preview).unwrap();
        }
    }

    if !impact.unreviewed_agent_changes.is_empty() {
        writeln!(out, "\n--- Agent Changes Pending Review ---").unwrap();
        for entity_id in &impact.unreviewed_agent_changes {
            // Look up the actor kind from attribution if available.
            let actor_kind = impact
                .actor_attribution
                .iter()
                .find(|(eid, _)| eid == entity_id)
                .map(|(_, kind)| *kind)
                .unwrap_or(ActorKind::Assistant);
            writeln!(
                out,
                "  {} changed by {} (not yet approved)",
                entity_id, actor_kind,
            )
            .unwrap();
        }
    }

    writeln!(out).unwrap();
    out
}

/// Format risk highlights from a review.
pub fn format_risk_highlights(review: &Review) -> String {
    let mut out = String::new();
    let risk = &review.risk;

    writeln!(out, "--- Risk Assessment ---").unwrap();
    let level_str = match risk.overall_risk {
        RiskLevel::Low => "LOW",
        RiskLevel::Medium => "MEDIUM",
        RiskLevel::High => "HIGH",
        RiskLevel::Critical => "CRITICAL",
    };
    writeln!(out, "Overall risk: {}", level_str).unwrap();

    if !risk.breaking_changes.is_empty() {
        writeln!(out, "\nBreaking changes:").unwrap();
        for bc in &risk.breaking_changes {
            writeln!(out, "  ! {}", bc).unwrap();
        }
    }

    if !risk.test_coverage_gaps.is_empty() {
        writeln!(out, "\nTest coverage gaps:").unwrap();
        for gap in &risk.test_coverage_gaps {
            writeln!(out, "  ? {}", gap).unwrap();
        }
    }

    if !risk.contract_violations.is_empty() {
        writeln!(out, "\nContract violations:").unwrap();
        for cv in &risk.contract_violations {
            writeln!(out, "  !! {}", cv).unwrap();
        }
    }

    if !risk.work_risks.is_empty() {
        writeln!(out, "\nWork item risks:").unwrap();
        for wr in &risk.work_risks {
            writeln!(out, "  @ {}", wr).unwrap();
        }
    }

    if !risk.notes.is_empty() {
        writeln!(out, "\nNotes:").unwrap();
        for note in &risk.notes {
            writeln!(out, "  - {}", note).unwrap();
        }
    }

    out
}

/// Format line-level inline comments grouped by file.
pub fn format_inline_comments(comments: &[InlineComment]) -> String {
    let mut out = String::new();

    writeln!(out, "--- Inline Comments ---").unwrap();

    let grouped = group_by_file(comments);
    for (file, file_comments) in &grouped {
        writeln!(out, "\n{}:", file).unwrap();
        for comment in file_comments {
            let prefix = comment.kind.prefix();
            if comment.start_line == comment.end_line {
                writeln!(
                    out,
                    "  L{}: {} {}",
                    comment.start_line, prefix, comment.message,
                )
                .unwrap();
            } else {
                writeln!(
                    out,
                    "  L{}-{}: {} {}",
                    comment.start_line, comment.end_line, prefix, comment.message,
                )
                .unwrap();
            }
        }
    }

    writeln!(out).unwrap();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::{EntityChange, EntityChangeKind};
    use crate::inline::{InlineComment, InlineCommentKind};
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        Visibility,
    };
    use kin_model::ids::*;
    use kin_model::review::RiskSummary;

    fn test_entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {}()", name),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn format_empty_review() {
        let review = Review {
            base: None,
            head: None,
            diff: SemanticDiff::default(),
            impact: ImpactReport::default(),
            risk: RiskSummary {
                overall_risk: RiskLevel::Low,
                breaking_changes: vec![],
                test_coverage_gaps: vec![],
                contract_violations: vec![],
                work_risks: vec![],
                notes: vec![],
            },
            inline_comments: vec![],
        };

        let output = format_review(&review);
        assert!(output.contains("Semantic Review"));
        assert!(output.contains("LOW"));
        assert!(output.contains("No entity changes"));
    }

    #[test]
    fn format_review_with_changes() {
        let entity = test_entity("handle_request");

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: entity.id,
                kind: EntityChangeKind::Added(entity.clone()),
            }],
            ..Default::default()
        };

        let review = Review {
            base: None,
            head: None,
            diff,
            impact: ImpactReport::default(),
            risk: RiskSummary {
                overall_risk: RiskLevel::Low,
                breaking_changes: vec![],
                test_coverage_gaps: vec![],
                contract_violations: vec![],
                work_risks: vec![],
                notes: vec![],
            },
            inline_comments: vec![],
        };

        let output = format_review(&review);
        assert!(output.contains("handle_request"));
        assert!(output.contains("Added (1)"));
    }

    #[test]
    fn format_risk_shows_critical() {
        let review = Review {
            base: None,
            head: None,
            diff: SemanticDiff::default(),
            impact: ImpactReport::default(),
            risk: RiskSummary {
                overall_risk: RiskLevel::Critical,
                breaking_changes: vec!["API changed".into()],
                test_coverage_gaps: vec![],
                contract_violations: vec!["Schema v2 incompatible".into()],
                work_risks: vec![],
                notes: vec![],
            },
            inline_comments: vec![],
        };

        let output = format_risk_highlights(&review);
        assert!(output.contains("CRITICAL"));
        assert!(output.contains("API changed"));
        assert!(output.contains("Schema v2 incompatible"));
    }

    #[test]
    fn format_inline_comments_groups_by_file() {
        let comments = vec![
            InlineComment {
                file: "src/api.rs".to_string(),
                start_line: 10,
                end_line: 25,
                kind: InlineCommentKind::Added,
                message: "New Function `handle_request`".to_string(),
            },
            InlineComment {
                file: "src/api.rs".to_string(),
                start_line: 10,
                end_line: 25,
                kind: InlineCommentKind::CoverageGap,
                message: "No test coverage".to_string(),
            },
            InlineComment {
                file: "src/core.rs".to_string(),
                start_line: 5,
                end_line: 5,
                kind: InlineCommentKind::SignatureChange,
                message: "Signature changed".to_string(),
            },
        ];

        let output = format_inline_comments(&comments);
        assert!(output.contains("--- Inline Comments ---"));
        assert!(output.contains("src/api.rs:"));
        assert!(output.contains("src/core.rs:"));
        assert!(output.contains("L10-25: +"));
        assert!(output.contains("L5: ~"));
    }

    #[test]
    fn format_review_includes_inline_comments() {
        let comments = vec![InlineComment {
            file: "src/lib.rs".to_string(),
            start_line: 1,
            end_line: 10,
            kind: InlineCommentKind::Breaking,
            message: "Breaking: signature change".to_string(),
        }];

        let review = Review {
            base: None,
            head: None,
            diff: SemanticDiff::default(),
            impact: ImpactReport::default(),
            risk: RiskSummary {
                overall_risk: RiskLevel::High,
                breaking_changes: vec!["sig change".into()],
                test_coverage_gaps: vec![],
                contract_violations: vec![],
                work_risks: vec![],
                notes: vec![],
            },
            inline_comments: comments,
        };

        let output = format_review(&review);
        assert!(output.contains("--- Inline Comments ---"));
        assert!(output.contains("L1-10: !! Breaking: signature change"));
    }

    #[test]
    fn format_review_omits_inline_section_when_empty() {
        let review = Review {
            base: None,
            head: None,
            diff: SemanticDiff::default(),
            impact: ImpactReport::default(),
            risk: RiskSummary {
                overall_risk: RiskLevel::Low,
                breaking_changes: vec![],
                test_coverage_gaps: vec![],
                contract_violations: vec![],
                work_risks: vec![],
                notes: vec![],
            },
            inline_comments: vec![],
        };

        let output = format_review(&review);
        assert!(!output.contains("Inline Comments"));
    }
}
