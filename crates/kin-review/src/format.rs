use std::fmt::Write;

use kin_model::provenance::ActorKind;
use kin_model::review::RiskLevel;

use crate::diff::{RelationChangeKind, SemanticDiff};
use crate::impact::ImpactReport;
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

    // Impact summary
    out.push_str(&format_impact(&review.impact));

    // Risk highlights
    out.push_str(&format_risk_highlights(review));

    out
}

/// Format entity-level diff.
pub fn format_diff(diff: &SemanticDiff) -> String {
    let mut out = String::new();

    if diff.is_empty() {
        writeln!(out, "No entity changes.").unwrap();
        return out;
    }

    writeln!(out, "--- Entity Changes ---").unwrap();

    let added = diff.added_entities();
    let modified = diff.modified_entities();
    let removed = diff.removed_entity_ids();

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
        for id in &removed {
            writeln!(out, "  - {}", id).unwrap();
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
                RelationChangeKind::Removed(id) => {
                    writeln!(out, "  - relation {}", id).unwrap();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::{EntityChange, EntityChangeKind};
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, FingerprintAlgorithm, SemanticFingerprint, Visibility,
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
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {}()", name),
            visibility: Visibility::Public,
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
        };

        let output = format_risk_highlights(&review);
        assert!(output.contains("CRITICAL"));
        assert!(output.contains("API changed"));
        assert!(output.contains("Schema v2 incompatible"));
    }
}
