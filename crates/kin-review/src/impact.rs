// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashSet;

use kin_model::entity::{Entity, EntityRole};
use kin_model::graph::GraphStore;
use kin_model::ids::EntityId;
use kin_model::provenance::{ActorKind, ApprovalDecision};
use kin_model::relation::{GraphNodeId, RelationKind};
use kin_model::work::{Annotation, StalenessState, WorkItem, WorkScope};
use serde::{Deserialize, Serialize};

use crate::diff::SemanticDiff;
use crate::error::ReviewError;

/// Structured impact report for a set of changed entities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImpactReport {
    /// Entities that call into changed entities.
    pub affected_callers: Vec<Entity>,
    /// Entities that depend on changed entities.
    pub affected_dependents: Vec<Entity>,
    /// Contract consumers affected by changed entities.
    pub affected_contract_consumers: Vec<Entity>,
    /// Tests that cover changed entities.
    pub affected_tests: Vec<Entity>,
    /// Active work items scoped to changed entities.
    pub affected_work_items: Vec<WorkItem>,
    /// Annotations on changed entities that may become stale.
    pub affected_annotations: Vec<Annotation>,
    /// Entity IDs that were directly changed (for cross-referencing).
    pub changed_ids: Vec<EntityId>,
    /// Entities changed by agents (assistant/service) without human approval.
    pub unreviewed_agent_changes: Vec<EntityId>,
    /// Attribution of who changed each entity (entity ID → actor kind).
    pub actor_attribution: Vec<(EntityId, ActorKind)>,
}

impl ImpactReport {
    pub fn is_empty(&self) -> bool {
        self.affected_callers.is_empty()
            && self.affected_dependents.is_empty()
            && self.affected_contract_consumers.is_empty()
            && self.affected_tests.is_empty()
            && self.affected_work_items.is_empty()
            && self.affected_annotations.is_empty()
            && self.unreviewed_agent_changes.is_empty()
    }

    /// Total number of affected entities (deduplicated).
    pub fn total_affected(&self) -> usize {
        let mut seen = HashSet::new();
        for e in &self.affected_callers {
            seen.insert(e.id);
        }
        for e in &self.affected_dependents {
            seen.insert(e.id);
        }
        for e in &self.affected_contract_consumers {
            seen.insert(e.id);
        }
        for e in &self.affected_tests {
            seen.insert(e.id);
        }
        seen.len()
    }
}

/// Analyze the impact of changes described in a `SemanticDiff` by walking
/// the graph for each changed entity.
pub fn analyze_impact<G: GraphStore>(
    store: &G,
    diff: &SemanticDiff,
) -> Result<ImpactReport, ReviewError> {
    let changed_ids = diff.changed_entity_ids();
    let changed_set: HashSet<EntityId> = changed_ids.iter().copied().collect();

    let mut callers = Vec::new();
    let mut dependents = Vec::new();
    let mut contract_consumers = Vec::new();
    let mut tests = Vec::new();

    let mut seen_callers = HashSet::new();
    let mut seen_dependents = HashSet::new();
    let mut seen_consumers = HashSet::new();
    let mut seen_tests = HashSet::new();

    for &entity_id in &changed_ids {
        // Find relations pointing TO this entity (callers, dependents, etc.)
        let relations = store
            .get_relations(
                &entity_id,
                &[
                    RelationKind::Calls,
                    RelationKind::DependsOn,
                    RelationKind::ConsumesContract,
                    RelationKind::Tests,
                    RelationKind::References,
                ],
            )
            .map_err(ReviewError::graph)?;

        for rel in &relations {
            // We want entities that reference the changed entity.
            // Relations where dst == entity_id mean src depends on entity_id.
            let affected_id = if rel.dst == GraphNodeId::Entity(entity_id) {
                rel.src.as_entity()
            } else if rel.src == GraphNodeId::Entity(entity_id) {
                rel.dst.as_entity()
            } else {
                continue;
            };
            let Some(affected_id) = affected_id else {
                continue;
            };

            // Skip if the affected entity is itself a changed entity
            if changed_set.contains(&affected_id) {
                continue;
            }

            if let Some(entity) = store.get_entity(&affected_id).map_err(ReviewError::graph)? {
                match rel.kind {
                    RelationKind::Calls => {
                        if seen_callers.insert(affected_id) {
                            callers.push(entity);
                        }
                    }
                    RelationKind::DependsOn | RelationKind::References => {
                        if seen_dependents.insert(affected_id) {
                            dependents.push(entity);
                        }
                    }
                    RelationKind::ConsumesContract => {
                        if seen_consumers.insert(affected_id) {
                            contract_consumers.push(entity);
                        }
                    }
                    RelationKind::Tests => {
                        if seen_tests.insert(affected_id) {
                            tests.push(entity);
                        }
                    }
                    _ => {}
                }
            }
        }

        // Also use get_downstream_impact for transitive effects
        let downstream = store
            .get_downstream_impact(&entity_id, 2)
            .map_err(ReviewError::graph)?;

        for entity in downstream {
            if changed_set.contains(&entity.id) {
                continue;
            }
            if entity.role == EntityRole::Test {
                if seen_tests.insert(entity.id) {
                    tests.push(entity);
                }
            } else if seen_dependents.insert(entity.id) {
                dependents.push(entity);
            }
        }
    }

    // Query work items and annotations scoped to changed entities.
    let mut work_items = Vec::new();
    let mut annotations = Vec::new();
    let mut seen_work_ids = HashSet::new();
    let mut seen_ann_ids = HashSet::new();

    for &entity_id in &changed_ids {
        let scope = WorkScope::Entity(entity_id);

        if let Ok(items) = store.get_work_for_scope(&scope) {
            for item in items {
                if !item.is_closed() && seen_work_ids.insert(item.work_id) {
                    work_items.push(item);
                }
            }
        }

        if let Ok(anns) = store.get_annotations_for_scope(&scope) {
            for ann in anns {
                if ann.staleness != StalenessState::Stale && seen_ann_ids.insert(ann.annotation_id)
                {
                    annotations.push(ann);
                }
            }
        }
    }

    // Provenance resolution: determine actor attribution and unapproved agent changes.
    let mut unreviewed_agent_changes = Vec::new();
    let mut actor_attribution = Vec::new();

    if let Some(head_id) = &diff.head {
        // Query approvals for the head change to find unapproved agent modifications.
        if let Ok(approvals) = store.get_approvals_for_change(head_id) {
            let has_human_approval = approvals
                .iter()
                .any(|a| a.decision == ApprovalDecision::Approved);

            // Query audit events to determine who made the changes.
            if let Ok(events) = store.query_audit_events(None, 100) {
                for &entity_id in &changed_ids {
                    // Find the most recent audit event targeting this entity.
                    let actor_event = events.iter().find(|e| {
                        matches!(&e.target_scope, Some(WorkScope::Entity(eid)) if *eid == entity_id)
                    });

                    if let Some(event) = actor_event {
                        // Resolve actor kind from the actor ID.
                        if let Ok(Some(actor)) = store.get_actor(&event.actor_id) {
                            actor_attribution.push((entity_id, actor.kind));

                            // Non-human actors without approval are unreviewed.
                            if actor.kind != ActorKind::Human && !has_human_approval {
                                unreviewed_agent_changes.push(entity_id);
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(ImpactReport {
        affected_callers: callers,
        affected_dependents: dependents,
        affected_contract_consumers: contract_consumers,
        affected_tests: tests,
        affected_work_items: work_items,
        affected_annotations: annotations,
        changed_ids,
        unreviewed_agent_changes,
        actor_attribution,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        Visibility,
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
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn empty_impact_report() {
        let report = ImpactReport::default();
        assert!(report.is_empty());
        assert_eq!(report.total_affected(), 0);
    }

    #[test]
    fn total_affected_deduplicates() {
        let e = test_entity("shared");
        let report = ImpactReport {
            affected_callers: vec![e.clone()],
            affected_dependents: vec![e.clone()],
            ..Default::default()
        };
        // Same entity in callers and dependents should count once
        assert_eq!(report.total_affected(), 1);
    }

    #[test]
    fn total_affected_counts_distinct() {
        let e1 = test_entity("caller1");
        let e2 = test_entity("dep1");
        let e3 = test_entity("test1");
        let report = ImpactReport {
            affected_callers: vec![e1],
            affected_dependents: vec![e2],
            affected_tests: vec![e3],
            ..Default::default()
        };
        assert_eq!(report.total_affected(), 3);
    }

    #[test]
    fn is_empty_with_only_changed_ids() {
        let report = ImpactReport {
            changed_ids: vec![EntityId::new()],
            ..Default::default()
        };
        // changed_ids alone does not make the report non-empty
        assert!(report.is_empty());
    }

    #[test]
    fn is_empty_false_with_callers() {
        let report = ImpactReport {
            affected_callers: vec![test_entity("caller")],
            ..Default::default()
        };
        assert!(!report.is_empty());
    }

    #[test]
    fn is_empty_false_with_unreviewed_agent_changes() {
        let report = ImpactReport {
            unreviewed_agent_changes: vec![EntityId::new()],
            ..Default::default()
        };
        assert!(!report.is_empty());
    }
}
