// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

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

    // Unreviewed agent changes increase risk.
    if !impact.unreviewed_agent_changes.is_empty() {
        let total = diff.entity_changes.len().max(1);
        let agent_count = impact.unreviewed_agent_changes.len();
        let ratio = agent_count as f64 / total as f64;
        if ratio > 0.5 {
            notes.push(format!(
                "{} of {} changed entities are unreviewed agent changes (>{:.0}%)",
                agent_count,
                total,
                ratio * 100.0,
            ));
        } else {
            notes.push(format!(
                "{} unreviewed agent change(s) among {} changed entities",
                agent_count, total,
            ));
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

    // Unreviewed agent changes bump risk to at least Medium.
    if !impact.unreviewed_agent_changes.is_empty() {
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

    // ── Empty diff tests ────────────────────────────────────────────────

    #[test]
    fn empty_diff_empty_impact_is_low() {
        let summary = assess_risk(&SemanticDiff::default(), &ImpactReport::default());
        assert_eq!(summary.overall_risk, RiskLevel::Low);
        assert!(summary.breaking_changes.is_empty());
        assert!(summary.test_coverage_gaps.is_empty());
        assert!(summary.contract_violations.is_empty());
        assert!(summary.notes.is_empty());
    }

    // ── Only additions tests ────────────────────────────────────────────

    #[test]
    fn addition_only_low_risk_with_test_coverage() {
        let entity = test_entity("new_helper");

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: entity.id,
                kind: EntityChangeKind::Added(entity.clone()),
            }],
            ..Default::default()
        };

        let test_entity_val = test_entity("test_new_helper");
        let impact = ImpactReport {
            affected_tests: vec![test_entity_val],
            changed_ids: vec![entity.id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        // Added public entity with test coverage should not flag
        assert!(summary.notes.is_empty() || !summary.notes.iter().any(|n| n.contains("no test")));
    }

    #[test]
    fn public_addition_without_tests_gets_note() {
        let entity = test_entity("public_api");

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: entity.id,
                kind: EntityChangeKind::Added(entity.clone()),
            }],
            ..Default::default()
        };

        let impact = ImpactReport {
            changed_ids: vec![entity.id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(summary.notes.iter().any(|n| n.contains("no test coverage")));
    }

    // ── Only deletions tests ────────────────────────────────────────────

    #[test]
    fn removal_with_dependents_is_high_risk() {
        let entity_id = EntityId::new();
        let dependent = test_entity("consumer");

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id,
                kind: EntityChangeKind::Removed(entity_id),
            }],
            ..Default::default()
        };

        let impact = ImpactReport {
            affected_dependents: vec![dependent],
            changed_ids: vec![entity_id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(!summary.breaking_changes.is_empty());
        assert_eq!(summary.overall_risk, RiskLevel::High);
    }

    #[test]
    fn removal_without_dependents_is_low_risk() {
        let entity_id = EntityId::new();

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id,
                kind: EntityChangeKind::Removed(entity_id),
            }],
            ..Default::default()
        };

        let impact = ImpactReport {
            changed_ids: vec![entity_id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(summary.breaking_changes.is_empty());
        assert_eq!(summary.overall_risk, RiskLevel::Low);
    }

    // ── Impact with no downstream tests ─────────────────────────────────

    #[test]
    fn modification_with_no_downstream_and_tests_is_low() {
        let old = test_entity("helper");
        let mut new = old.clone();
        new.signature = "fn helper(x: u32)".to_string();

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

        let test_ent = test_entity("test_helper");
        let impact = ImpactReport {
            affected_tests: vec![test_ent],
            changed_ids: vec![new.id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        // No callers => no breaking change, has test coverage
        assert!(summary.breaking_changes.is_empty());
        assert!(summary.test_coverage_gaps.is_empty());
    }

    // ── Visibility reduction tests ──────────────────────────────────────

    #[test]
    fn visibility_reduction_with_callers_is_breaking() {
        let old = test_entity("public_fn");
        let mut new = old.clone();
        new.signature = "fn public_fn(x: i32)".to_string();
        new.visibility = Visibility::Private;

        let caller = test_entity("caller");

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
        assert!(summary
            .breaking_changes
            .iter()
            .any(|b| b.contains("Visibility reduced")));
    }

    // ── High risk for many affected entities ────────────────────────────

    #[test]
    fn high_risk_when_many_affected_and_no_tests() {
        let old = test_entity("core_fn");
        let mut new = old.clone();
        new.signature = "fn core_fn(a: i32, b: i32)".to_string();

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

        // > 5 affected entities + no test coverage => High
        let dependents: Vec<Entity> = (0..6).map(|i| test_entity(&format!("dep_{i}"))).collect();

        let impact = ImpactReport {
            affected_dependents: dependents,
            changed_ids: vec![new.id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert_eq!(summary.overall_risk, RiskLevel::High);
    }

    // ── Medium risk for moderate affected entities ──────────────────────

    #[test]
    fn medium_risk_when_moderate_affected() {
        let diff = SemanticDiff::default();

        let dependents: Vec<Entity> = (0..4).map(|i| test_entity(&format!("dep_{i}"))).collect();

        let impact = ImpactReport {
            affected_dependents: dependents,
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert_eq!(summary.overall_risk, RiskLevel::Medium);
    }

    // ── Unreviewed agent changes tests ──────────────────────────────────

    #[test]
    fn unreviewed_agent_changes_bump_risk_to_medium() {
        let entity_id = EntityId::new();
        let diff = SemanticDiff::default();

        let impact = ImpactReport {
            unreviewed_agent_changes: vec![entity_id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert_eq!(summary.overall_risk, RiskLevel::Medium);
    }

    #[test]
    fn agent_changes_over_half_generate_note() {
        let id1 = EntityId::new();
        let entity = test_entity("auto_fn");

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: entity.id,
                kind: EntityChangeKind::Added(entity.clone()),
            }],
            ..Default::default()
        };

        let impact = ImpactReport {
            unreviewed_agent_changes: vec![id1],
            changed_ids: vec![entity.id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(summary.notes.iter().any(|n| n.contains("unreviewed agent")));
    }

    // ── Work item risk tests ────────────────────────────────────────────

    #[test]
    fn work_items_on_changed_entities_add_risk() {
        use kin_model::{IdentityRef, Priority, WorkId, WorkItem, WorkKind, WorkScope, WorkStatus};

        let diff = SemanticDiff::default();
        let work = WorkItem {
            work_id: WorkId::new(),
            kind: WorkKind::Feature,
            title: "New login flow".to_string(),
            description: String::new(),
            status: WorkStatus::InProgress,
            priority: Priority::None,
            scopes: vec![WorkScope::Entity(EntityId::new())],
            acceptance_criteria: vec![],
            external_refs: vec![],
            created_by: IdentityRef::human("dev"),
            created_at: kin_model::timestamp::Timestamp::now(),
        };

        let impact = ImpactReport {
            affected_work_items: vec![work],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert_eq!(summary.overall_risk, RiskLevel::Medium);
        assert!(!summary.work_risks.is_empty());
    }

    // ── Relation removal tests ──────────────────────────────────────────

    #[test]
    fn removed_relation_generates_note() {
        use crate::diff::{RelationChange, RelationChangeKind};
        use kin_model::ids::RelationId;

        let rel_id = RelationId::new();
        let diff = SemanticDiff {
            relation_changes: vec![RelationChange {
                kind: RelationChangeKind::Removed(rel_id),
            }],
            ..Default::default()
        };

        let impact = ImpactReport::default();
        let summary = assess_risk(&diff, &impact);
        assert!(summary.notes.iter().any(|n| n.contains("Relation")));
    }

    // ── API endpoint contract tests ─────────────────────────────────────

    #[test]
    fn api_endpoint_modification_with_consumers_is_critical() {
        let mut old = test_entity("get_users");
        old.kind = EntityKind::ApiEndpoint;
        let mut new = old.clone();
        new.signature = "GET /api/v2/users".to_string();

        let consumer = test_entity("frontend_client");

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
        assert_eq!(summary.overall_risk, RiskLevel::Critical);
    }

    #[test]
    fn event_contract_modification_with_consumers_is_critical() {
        let mut old = test_entity("user_created_event");
        old.kind = EntityKind::EventContract;
        let mut new = old.clone();
        new.signature = "event UserCreated { id, name, email }".to_string();

        let consumer = test_entity("notification_handler");

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

    // ── Test entity modification tests ──────────────────────────────────

    #[test]
    fn test_entity_modification_no_coverage_gap() {
        let mut old = test_entity("test_login");
        old.kind = EntityKind::Test;
        let mut new = old.clone();
        new.signature = "fn test_login_v2()".to_string();

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
            changed_ids: vec![new.id],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        // Test entities should not generate coverage gaps
        assert!(summary.test_coverage_gaps.is_empty());
    }

    // ── Annotation staleness tests ──────────────────────────────────────

    #[test]
    fn fresh_annotation_on_changed_entity_generates_risk() {
        use kin_model::{
            Annotation, AnnotationId, AnnotationKind, EntityId as EId, IdentityRef, StalenessState,
            WorkScope,
        };

        let diff = SemanticDiff::default();
        let ann = Annotation {
            annotation_id: AnnotationId::new(),
            scopes: vec![WorkScope::Entity(EId::new())],
            kind: AnnotationKind::Warning,
            body: "Watch for race conditions here".to_string(),
            anchored_fingerprint: None,
            authored_by: IdentityRef::human("dev"),
            created_at: kin_model::timestamp::Timestamp::now(),
            staleness: StalenessState::Fresh,
        };

        let impact = ImpactReport {
            affected_annotations: vec![ann],
            ..Default::default()
        };

        let summary = assess_risk(&diff, &impact);
        assert!(summary.work_risks.iter().any(|r| r.contains("annotation")));
    }
}
