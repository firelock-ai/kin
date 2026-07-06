// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{BTreeSet, HashSet};

use kin_model::entity::{Entity, EntityRole};
use kin_model::graph::GraphStore;
use kin_model::ids::{EntityId, SemanticChangeId};
use kin_model::provenance::{Actor, ActorId, ActorKind, Approval, ApprovalDecision, AuditEvent};
use kin_model::relation::{GraphNodeId, Relation, RelationKind};
use kin_model::work::{Annotation, StalenessState, WorkItem, WorkScope};
use serde::{Deserialize, Serialize};

use crate::diff::SemanticDiff;
use crate::error::ReviewError;

/// The exact read surface the impact walker consumes.
///
/// Structural queries (`get_entity`, `get_relations`,
/// `get_all_relations_for_entity`, `get_downstream_impact`) determine the
/// blast radius and must be answered by the graph state the review is scoped
/// to. Overlay queries (work items, annotations, approvals, audit events,
/// actors) are operational state keyed by stable IDs, not part of the
/// replayed structural graph, and are answered by the live store.
///
/// The trait deliberately has no write surface: impact analysis is read-only
/// by construction, so a ref-scoped implementation cannot be misused to
/// mutate graph state.
pub trait ImpactGraph {
    fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>, ReviewError>;
    fn get_relations(
        &self,
        id: &EntityId,
        kinds: &[RelationKind],
    ) -> Result<Vec<Relation>, ReviewError>;
    /// Every entity-to-entity edge touching `id`, outgoing and incoming,
    /// deduplicated and sorted by relation id. The inbound-only impact
    /// harvest reads this full set and keeps the incoming side.
    fn get_all_relations_for_entity(&self, id: &EntityId) -> Result<Vec<Relation>, ReviewError>;
    fn get_downstream_impact(
        &self,
        id: &EntityId,
        max_depth: u32,
    ) -> Result<Vec<Entity>, ReviewError>;
    fn get_work_for_scope(&self, scope: &WorkScope) -> Result<Vec<WorkItem>, ReviewError>;
    fn get_annotations_for_scope(&self, scope: &WorkScope) -> Result<Vec<Annotation>, ReviewError>;
    fn get_approvals_for_change(&self, id: &SemanticChangeId)
        -> Result<Vec<Approval>, ReviewError>;
    fn query_audit_events(
        &self,
        actor_id: Option<&ActorId>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, ReviewError>;
    fn get_actor(&self, id: &ActorId) -> Result<Option<Actor>, ReviewError>;
}

/// Live-store view of [`ImpactGraph`]: every query answered by the current
/// graph state.
pub struct LiveGraph<'a, G>(pub &'a G);

impl<G: GraphStore> ImpactGraph for LiveGraph<'_, G> {
    fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>, ReviewError> {
        self.0.get_entity(id).map_err(ReviewError::graph)
    }

    fn get_relations(
        &self,
        id: &EntityId,
        kinds: &[RelationKind],
    ) -> Result<Vec<Relation>, ReviewError> {
        self.0.get_relations(id, kinds).map_err(ReviewError::graph)
    }

    fn get_all_relations_for_entity(&self, id: &EntityId) -> Result<Vec<Relation>, ReviewError> {
        self.0
            .get_all_relations_for_entity(id)
            .map_err(ReviewError::graph)
    }

    fn get_downstream_impact(
        &self,
        id: &EntityId,
        max_depth: u32,
    ) -> Result<Vec<Entity>, ReviewError> {
        self.0
            .get_downstream_impact(id, max_depth)
            .map_err(ReviewError::graph)
    }

    fn get_work_for_scope(&self, scope: &WorkScope) -> Result<Vec<WorkItem>, ReviewError> {
        self.0.get_work_for_scope(scope).map_err(ReviewError::graph)
    }

    fn get_annotations_for_scope(&self, scope: &WorkScope) -> Result<Vec<Annotation>, ReviewError> {
        self.0
            .get_annotations_for_scope(scope)
            .map_err(ReviewError::graph)
    }

    fn get_approvals_for_change(
        &self,
        id: &SemanticChangeId,
    ) -> Result<Vec<Approval>, ReviewError> {
        self.0
            .get_approvals_for_change(id)
            .map_err(ReviewError::graph)
    }

    fn query_audit_events(
        &self,
        actor_id: Option<&ActorId>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, ReviewError> {
        self.0
            .query_audit_events(actor_id, limit)
            .map_err(ReviewError::graph)
    }

    fn get_actor(&self, id: &ActorId) -> Result<Option<Actor>, ReviewError> {
        self.0.get_actor(id).map_err(ReviewError::graph)
    }
}

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
    /// Per-entity inbound attribution, sorted by entity id. Policy rules that
    /// judge one changed entity (breaking, coverage, fanout) key on the entry
    /// for that entity instead of the diff-global buckets above.
    pub entity_impacts: Vec<EntityImpact>,
}

/// Minimum inbound-edge confidence for a consumer to count toward
/// verdict-driving fanout decisions. Ambiguous-dispatch fan-out links carry
/// low confidence: they are real enough to display in the blast radius, but a
/// possibly-reaching edge must not alone escalate a verdict.
pub const STRONG_CONSUMER_CONFIDENCE: f32 = 0.6;

/// Graph-proven inbound impact attributed to one directly changed entity.
///
/// All counts are inbound-only: entities that reach the changed entity via
/// `Calls`, `DependsOn`, `References`, or `ConsumesContract` relations (plus
/// the incoming-edge downstream walk). The changed entity's own callees are
/// its dependencies, not its consumers, and never count here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityImpact {
    /// The directly changed entity these counts belong to.
    pub entity_id: EntityId,
    /// Distinct non-test entities that consume this entity.
    pub consumer_count: usize,
    /// Subset of `consumer_count` whose inbound edge confidence is at least
    /// [`STRONG_CONSUMER_CONFIDENCE`] — the count verdict gates key on.
    #[serde(default)]
    pub strong_consumer_count: usize,
    /// Distinct non-test entities consuming this entity as a contract.
    pub contract_consumer_count: usize,
    /// Sorted distinct source files of the non-test consumers above.
    pub consumer_files: Vec<String>,
    /// Distinct test entities covering this entity (test-kind edges plus
    /// test-role inbound entities).
    pub covering_tests: usize,
}

impl EntityImpact {
    /// Total distinct inbound entities (consumers plus covering tests).
    /// Zero means the graph connects nothing to this entity.
    pub fn inbound_total(&self) -> usize {
        self.consumer_count + self.covering_tests
    }
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

    /// Per-entity inbound attribution for one directly changed entity.
    pub fn entity_impact(&self, entity_id: &EntityId) -> Option<&EntityImpact> {
        self.entity_impacts
            .iter()
            .find(|impact| impact.entity_id == *entity_id)
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
/// the current (live) graph for each changed entity.
pub fn analyze_impact<G: GraphStore>(
    store: &G,
    diff: &SemanticDiff,
) -> Result<ImpactReport, ReviewError> {
    analyze_impact_at(&LiveGraph(store), diff)
}

/// Analyze the impact of changes described in a `SemanticDiff` by walking
/// the supplied [`ImpactGraph`] for each changed entity.
///
/// Callers reviewing a committed `base..head` range should pass a graph
/// scoped to the head ref (see `GraphAtRef`) so the blast radius reflects
/// the adjacency at that ref rather than whatever the mutable live adjacency
/// happens to hold.
pub fn analyze_impact_at<I: ImpactGraph>(
    graph: &I,
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

    let mut entity_impacts: Vec<EntityImpact> = Vec::new();

    for &entity_id in &changed_ids {
        // Per-entity inbound attribution accumulated alongside the global
        // buckets. Sets are used only for distinct counts, never for output
        // ordering, so iteration order cannot leak into the report.
        let mut ent_consumers: HashSet<EntityId> = HashSet::new();
        let mut ent_strong_consumers: HashSet<EntityId> = HashSet::new();
        let mut ent_contract_consumers: HashSet<EntityId> = HashSet::new();
        let mut ent_tests: HashSet<EntityId> = HashSet::new();
        // `consumer_files` is the human-readable projection of the consumer
        // ENTITY set below (which the fanout decision keys on) — the files those
        // consuming entities live in, for the report message only. It is never a
        // decision input: a consumer that happens to share the changed entity's
        // file is still a distinct consumer entity with a real inbound edge.
        let mut ent_consumer_files: BTreeSet<String> = BTreeSet::new();

        // Find relations pointing TO this entity (callers, dependents, etc.).
        // `get_relations` serves outgoing edges only, so the inbound harvest
        // reads the full edge set and keeps the incoming side.
        let relations = graph.get_all_relations_for_entity(&entity_id)?;

        for rel in &relations {
            if !matches!(
                rel.kind,
                RelationKind::Calls
                    | RelationKind::DependsOn
                    | RelationKind::ConsumesContract
                    | RelationKind::Tests
                    | RelationKind::References
            ) {
                continue;
            }
            // Only inbound edges prove impact: `dst == entity_id` means `src`
            // consumes the changed entity. Outbound edges point at the
            // change's own callees/dependencies — those are what the change
            // uses, not what the change can break — so they never count as
            // downstream impact.
            if rel.dst != GraphNodeId::Entity(entity_id) {
                continue;
            }
            let Some(affected_id) = rel.src.as_entity() else {
                continue;
            };

            // Skip if the affected entity is itself a changed entity
            if changed_set.contains(&affected_id) {
                continue;
            }

            if let Some(entity) = graph.get_entity(&affected_id)? {
                let is_test = entity.role == EntityRole::Test || rel.kind == RelationKind::Tests;
                if is_test {
                    ent_tests.insert(affected_id);
                } else {
                    ent_consumers.insert(affected_id);
                    if rel.confidence >= STRONG_CONSUMER_CONFIDENCE {
                        ent_strong_consumers.insert(affected_id);
                    }
                    if rel.kind == RelationKind::ConsumesContract {
                        ent_contract_consumers.insert(affected_id);
                    }
                    if let Some(file) = entity_file(&entity) {
                        ent_consumer_files.insert(file);
                    }
                }
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

        // Also use get_downstream_impact for transitive effects; the walk
        // follows incoming edges, so its results are inbound by construction.
        let downstream = graph.get_downstream_impact(&entity_id, 2)?;

        for entity in downstream {
            if changed_set.contains(&entity.id) {
                continue;
            }
            if entity.role == EntityRole::Test {
                ent_tests.insert(entity.id);
                if seen_tests.insert(entity.id) {
                    tests.push(entity);
                }
            } else {
                // Transitive (2-hop) reach populates the blast-radius
                // dependents bucket for the report, but must NOT feed the
                // per-entity consumer_count / consumer_files that drive the
                // breaking and consumer-fanout signals. Those attribute from
                // DIRECT inbound edges outside the changed set only, so a path
                // that routes through a co-updated intermediate cannot inflate
                // this entity's contract-surface risk.
                if seen_dependents.insert(entity.id) {
                    dependents.push(entity);
                }
            }
        }

        entity_impacts.push(EntityImpact {
            entity_id,
            consumer_count: ent_consumers.len(),
            strong_consumer_count: ent_strong_consumers.len(),
            contract_consumer_count: ent_contract_consumers.len(),
            consumer_files: ent_consumer_files.into_iter().collect(),
            covering_tests: ent_tests.len(),
        });
    }

    entity_impacts.sort_by_key(|impact| impact.entity_id);

    // Query work items and annotations scoped to changed entities.
    let mut work_items = Vec::new();
    let mut annotations = Vec::new();
    let mut seen_work_ids = HashSet::new();
    let mut seen_ann_ids = HashSet::new();

    for &entity_id in &changed_ids {
        let scope = WorkScope::Entity(entity_id);

        if let Ok(items) = graph.get_work_for_scope(&scope) {
            for item in items {
                if !item.is_closed() && seen_work_ids.insert(item.work_id) {
                    work_items.push(item);
                }
            }
        }

        if let Ok(anns) = graph.get_annotations_for_scope(&scope) {
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
        if let Ok(approvals) = graph.get_approvals_for_change(head_id) {
            let has_human_approval = approvals
                .iter()
                .any(|a| a.decision == ApprovalDecision::Approved);

            // Query audit events to determine who made the changes.
            if let Ok(events) = graph.query_audit_events(None, 100) {
                for &entity_id in &changed_ids {
                    // Find the most recent audit event targeting this entity.
                    let actor_event = events.iter().find(|e| {
                        matches!(&e.target_scope, Some(WorkScope::Entity(eid)) if *eid == entity_id)
                    });

                    if let Some(event) = actor_event {
                        // Resolve actor kind from the actor ID.
                        if let Ok(Some(actor)) = graph.get_actor(&event.actor_id) {
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
        entity_impacts,
    })
}

/// Source file a consumer entity lives in, from its span or file origin.
fn entity_file(entity: &Entity) -> Option<String> {
    match &entity.span {
        Some(span) => Some(span.file.to_string()),
        None => entity.file_origin.as_ref().map(|file| file.to_string()),
    }
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

    // ── Per-entity attribution: direct-only consumer_count / consumer_files ──

    use crate::diff::{EntityChange, EntityChangeKind};
    use kin_model::entity::SourceSpan;
    use kin_model::provenance::{Actor, ActorId, Approval, AuditEvent};
    use kin_model::relation::{GraphNodeId, Relation, RelationKind, RelationOrigin};
    use kin_model::work::{Annotation, WorkItem, WorkScope};
    use std::collections::HashMap;

    fn entity_in_file(name: &str, file: &str, line: u32) -> Entity {
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
            file_origin: Some(FilePathId::new(file)),
            span: Some(SourceSpan {
                file: FilePathId::new(file),
                start_byte: 0,
                end_byte: 10,
                start_line: line,
                start_col: 0,
                end_line: line + 1,
                end_col: 0,
            }),
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

    fn calls(src: &Entity, dst: &Entity) -> Relation {
        Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(src.id),
            dst: GraphNodeId::Entity(dst.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![],
        }
    }

    fn modified(entity: &Entity) -> EntityChange {
        EntityChange {
            entity_id: entity.id,
            kind: EntityChangeKind::Modified {
                old: entity.clone(),
                new: entity.clone(),
            },
        }
    }

    /// Hand-built [`ImpactGraph`] returning exactly the inbound edges and
    /// transitive downstream entities each test wires — no dependency on
    /// live-store or ref-replay traversal semantics.
    #[derive(Default)]
    struct MockImpactGraph {
        entities: HashMap<EntityId, Entity>,
        inbound: HashMap<EntityId, Vec<Relation>>,
        downstream: HashMap<EntityId, Vec<Entity>>,
    }

    impl ImpactGraph for MockImpactGraph {
        fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>, ReviewError> {
            Ok(self.entities.get(id).cloned())
        }
        fn get_relations(
            &self,
            _id: &EntityId,
            _kinds: &[RelationKind],
        ) -> Result<Vec<Relation>, ReviewError> {
            Ok(vec![])
        }
        fn get_all_relations_for_entity(
            &self,
            id: &EntityId,
        ) -> Result<Vec<Relation>, ReviewError> {
            Ok(self.inbound.get(id).cloned().unwrap_or_default())
        }
        fn get_downstream_impact(
            &self,
            id: &EntityId,
            _max_depth: u32,
        ) -> Result<Vec<Entity>, ReviewError> {
            Ok(self.downstream.get(id).cloned().unwrap_or_default())
        }
        fn get_work_for_scope(&self, _scope: &WorkScope) -> Result<Vec<WorkItem>, ReviewError> {
            Ok(vec![])
        }
        fn get_annotations_for_scope(
            &self,
            _scope: &WorkScope,
        ) -> Result<Vec<Annotation>, ReviewError> {
            Ok(vec![])
        }
        fn get_approvals_for_change(
            &self,
            _id: &SemanticChangeId,
        ) -> Result<Vec<Approval>, ReviewError> {
            Ok(vec![])
        }
        fn query_audit_events(
            &self,
            _actor_id: Option<&ActorId>,
            _limit: usize,
        ) -> Result<Vec<AuditEvent>, ReviewError> {
            Ok(vec![])
        }
        fn get_actor(&self, _id: &ActorId) -> Result<Option<Actor>, ReviewError> {
            Ok(None)
        }
    }

    #[test]
    fn consumer_count_counts_direct_inbound_not_two_hop_through_changed() {
        // A and B are both changed (co-updated). B consumes A directly, C
        // consumes B, and D consumes A directly. The 2-hop walk from A reaches
        // C through the co-updated intermediate B. C must NOT inflate A's
        // consumer_count — breaking risk is attributed from DIRECT external
        // consumers only, so A counts D alone. Before this fix C leaked in via
        // the 2-hop walk and A's consumer_count was 2.
        let a = entity_in_file("target_a", "src/a.rs", 1);
        let b = entity_in_file("mid_b", "src/b.rs", 1);
        let c = entity_in_file("far_c", "src/c.rs", 1);
        let d = entity_in_file("direct_d", "src/d.rs", 1);

        let mut graph = MockImpactGraph::default();
        for entity in [&a, &b, &c, &d] {
            graph.entities.insert(entity.id, entity.clone());
        }
        // Direct inbound to A: B and D call A.
        graph
            .inbound
            .insert(a.id, vec![calls(&b, &a), calls(&d, &a)]);
        // Direct inbound to B: C calls B.
        graph.inbound.insert(b.id, vec![calls(&c, &b)]);
        // Transitive downstream of A reaches B (depth 1) and C (depth 2).
        graph
            .downstream
            .insert(a.id, vec![b.clone(), c.clone(), d.clone()]);

        let diff = SemanticDiff {
            entity_changes: vec![modified(&a), modified(&b)],
            ..Default::default()
        };

        let report = analyze_impact_at(&graph, &diff).unwrap();
        let impact_a = report.entity_impact(&a.id).expect("A has an impact entry");
        assert_eq!(
            impact_a.consumer_count, 1,
            "only the direct external consumer D counts; C (2-hop via co-updated B) must not"
        );
        // C is still reachable as transitive blast radius (report surface),
        // just not as a direct-consumer attribution.
        assert!(report.affected_dependents.iter().any(|e| e.id == c.id));
    }

    #[test]
    fn consumer_count_is_entity_native_including_a_same_file_consumer() {
        // A (changed) in src/foo.rs is consumed by a same-file sibling B and by
        // an external C in src/bar.rs. Both B and C are distinct consumer
        // ENTITIES with real inbound edges, so both count — the fanout decision
        // is graph-native and never special-cases a consumer by the file it
        // lives in. `consumer_files` is the reported projection of that entity
        // set (both files), used only for the message, never for the decision.
        let a = entity_in_file("hot_path", "src/foo.rs", 1);
        let b = entity_in_file("sibling", "src/foo.rs", 40);
        let c = entity_in_file("external", "src/bar.rs", 1);

        let mut graph = MockImpactGraph::default();
        for entity in [&a, &b, &c] {
            graph.entities.insert(entity.id, entity.clone());
        }
        graph
            .inbound
            .insert(a.id, vec![calls(&b, &a), calls(&c, &a)]);

        let diff = SemanticDiff {
            entity_changes: vec![modified(&a)],
            ..Default::default()
        };

        let report = analyze_impact_at(&graph, &diff).unwrap();
        let impact_a = report.entity_impact(&a.id).expect("A has an impact entry");
        assert_eq!(
            impact_a.consumer_count, 2,
            "both consumer entities count, regardless of the file they live in"
        );
        assert_eq!(
            impact_a.consumer_files,
            vec!["src/bar.rs".to_string(), "src/foo.rs".to_string()],
            "consumer_files is the projected file set of the consumer entities (both), report-only"
        );
    }
}
