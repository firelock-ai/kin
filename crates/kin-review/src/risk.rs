use crate::diff::{EntityChangeKind, SemanticDiff};
use crate::impact::ImpactReport;
use kin_model::entity::{EntityKind, Visibility};
use kin_model::review::{RiskLevel, RiskSummary};

/// Assess risk given a diff and its impact report.
///
/// Returns a `RiskSummary` (from kin-model) with:
/// - breaking changes (contract/signature changes with consumers)
/// - test coverage gaps (modified entities with no test coverage)
/// - contract violations
/// - overall risk level
pub fn assess_risk(diff: &SemanticDiff, impact: &ImpactReport) -> RiskSummary {
    let mut breaking_changes = Vec::new();
    let mut test_coverage_gaps = Vec::new();
    let mut contract_violations = Vec::new();
    let mut notes = Vec::new();

    // Check for signature changes on entities with consumers/callers
    for change in &diff.entity_changes {
        match &change.kind {
            EntityChangeKind::Modified { old, new } => {
                // Signature changed?
                if old.signature != new.signature {
                    let has_callers = impact.affected_callers.iter().any(|_| true);
                    let has_consumers = !impact.affected_contract_consumers.is_empty();

                    if has_callers || has_consumers {
                        breaking_changes.push(format!(
                            "Signature change on `{}`: `{}` -> `{}`",
                            new.name, old.signature, new.signature,
                        ));
                    }

                    // Public visibility change is notable
                    if old.visibility == Visibility::Public && new.visibility != Visibility::Public
                    {
                        breaking_changes
                            .push(format!("Visibility reduced on `{}` from public", new.name,));
                    }
                }

                // Contract entity modified with consumers
                if matches!(
                    new.kind,
                    EntityKind::ApiEndpoint | EntityKind::EventContract | EntityKind::Schema
                ) && !impact.affected_contract_consumers.is_empty()
                {
                    contract_violations.push(format!(
                        "Contract `{}` ({:?}) modified with {} consumer(s)",
                        new.name,
                        new.kind,
                        impact.affected_contract_consumers.len(),
                    ));
                }

                // Check test coverage gap
                if !matches!(new.kind, EntityKind::Test) {
                    let has_test_coverage = impact.affected_tests.iter().any(|_| true);
                    if !has_test_coverage {
                        test_coverage_gaps.push(format!(
                            "Modified entity `{}` has no test coverage",
                            new.name,
                        ));
                    }
                }
            }
            EntityChangeKind::Removed(id) => {
                let has_dependents =
                    !impact.affected_dependents.is_empty() || !impact.affected_callers.is_empty();
                if has_dependents {
                    breaking_changes.push(format!("Removed entity `{}` still has dependents", id,));
                }
            }
            EntityChangeKind::Added(entity) => {
                // New public API without tests
                if entity.visibility == Visibility::Public
                    && !matches!(entity.kind, EntityKind::Test)
                {
                    let has_test_coverage = impact.affected_tests.iter().any(|_| true);
                    if !has_test_coverage {
                        notes.push(format!(
                            "New public entity `{}` has no test coverage",
                            entity.name,
                        ));
                    }
                }
            }
        }
    }

    // Removed relations that break contracts
    for rel_change in &diff.relation_changes {
        if let crate::diff::RelationChangeKind::Removed(id) = &rel_change.kind {
            notes.push(format!("Relation {} removed", id));
        }
    }

    // Work item risks: flag in-progress work affected by changes.
    let mut work_risks = Vec::new();
    for item in &impact.affected_work_items {
        work_risks.push(format!(
            "Changes affect {} work item `{}` ({})",
            item.status, item.title, item.kind,
        ));
    }
    for ann in &impact.affected_annotations {
        if ann.staleness == kin_model::work::StalenessState::Fresh {
            work_risks.push(format!(
                "Fresh {} annotation may become stale: \"{}\"",
                ann.kind,
                if ann.body.len() > 60 {
                    format!("{}...", &ann.body[..60])
                } else {
                    ann.body.clone()
                },
            ));
        }
    }

    let overall_risk = compute_risk_level(
        &breaking_changes,
        &test_coverage_gaps,
        &contract_violations,
        &work_risks,
        impact,
    );

    RiskSummary {
        overall_risk,
        breaking_changes,
        test_coverage_gaps,
        contract_violations,
        work_risks,
        notes,
    }
}

fn compute_risk_level(
    breaking_changes: &[String],
    test_coverage_gaps: &[String],
    contract_violations: &[String],
    work_risks: &[String],
    impact: &ImpactReport,
) -> RiskLevel {
    if !contract_violations.is_empty() {
        return RiskLevel::Critical;
    }

    if !breaking_changes.is_empty() {
        return RiskLevel::High;
    }

    if !test_coverage_gaps.is_empty() && impact.total_affected() > 5 {
        return RiskLevel::High;
    }

    if !test_coverage_gaps.is_empty() || impact.total_affected() > 3 {
        return RiskLevel::Medium;
    }

    // In-progress work items on changed code is at least Medium risk.
    if !work_risks.is_empty() {
        return RiskLevel::Medium;
    }

    RiskLevel::Low
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::{EntityChange, EntityChangeKind, SemanticDiff};
    use crate::impact::ImpactReport;
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, FingerprintAlgorithm, SemanticFingerprint, Visibility,
    };
    use kin_model::ids::*;

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
    fn low_risk_for_empty_diff() {
        let diff = SemanticDiff::default();
        let impact = ImpactReport::default();
        let summary = assess_risk(&diff, &impact);
        assert_eq!(summary.overall_risk, RiskLevel::Low);
        assert!(summary.breaking_changes.is_empty());
    }

    #[test]
    fn medium_risk_for_uncovered_modification() {
        let old = test_entity("process");
        let mut new = old.clone();
        new.signature = "fn process(x: i32)".to_string();

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };

        // No callers, no tests
        let impact = ImpactReport {
            changed_ids: vec![new.id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        // signature changed but no callers => no breaking change
        // but no test coverage => gap
        assert!(!summary.test_coverage_gaps.is_empty());
        assert_eq!(summary.overall_risk, RiskLevel::Medium);
    }

    #[test]
    fn high_risk_for_breaking_signature_change() {
        let old = test_entity("api_handler");
        let mut new = old.clone();
        new.signature = "fn api_handler(req: Request, extra: bool)".to_string();

        let caller = test_entity("caller_fn");

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };

        let impact = ImpactReport {
            affected_callers: vec![caller],
            changed_ids: vec![new.id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(!summary.breaking_changes.is_empty());
        assert_eq!(summary.overall_risk, RiskLevel::High);
    }

    #[test]
    fn critical_risk_for_contract_violation() {
        let mut old = test_entity("user_schema");
        old.kind = EntityKind::Schema;
        let mut new = old.clone();
        new.signature = "schema User { id: UUID, name: String, email: String }".to_string();

        let consumer = test_entity("user_service");

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            ..Default::default()
        };

        let impact = ImpactReport {
            affected_contract_consumers: vec![consumer],
            changed_ids: vec![new.id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(!summary.contract_violations.is_empty());
        assert_eq!(summary.overall_risk, RiskLevel::Critical);
    }
}
