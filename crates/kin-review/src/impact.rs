// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{BTreeSet, HashSet};

use kin_index::RelationResolution;
use kin_model::entity::{Entity, EntityRole};
use kin_model::graph::GraphStore;
use kin_model::ids::{EntityId, RepoPath, SemanticChangeId};
use kin_model::provenance::{Actor, ActorId, ActorKind, Approval, ApprovalDecision, AuditEvent};
use kin_model::relation::{GraphNodeId, Relation, RelationKind};
use kin_model::work::{Annotation, StalenessState, WorkItem, WorkScope};
use serde::{Deserialize, Serialize};

use crate::diff::{EntityChangeKind, SemanticDiff};
use crate::error::ReviewError;

/// Line-independent identity of an entity: `(file, name, kind)`. `EntityId`
/// folds in `start_line`, so a declaration that only moved carries a new id
/// under the same identity. Co-change matching keys on this so a co-updated
/// consumer is recognized whether or not its line (and thus id) shifted.
fn entity_identity_key(entity: &Entity) -> (String, String, String) {
    (
        entity_file(entity).unwrap_or_default(),
        entity.name.clone(),
        format!("{:?}", entity.kind),
    )
}

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
    /// Whether graph-owned parser coverage proves every entity-bearing source
    /// file was parsed fully. The default is fail-closed so implementations of
    /// the older public trait remain source-compatible without certifying new
    /// rename-neutralization behavior accidentally.
    fn call_shape_parse_coverage_complete(&self) -> Result<bool, ReviewError> {
        Ok(false)
    }

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
    fn call_shape_parse_coverage_complete(&self) -> Result<bool, ReviewError> {
        let layouts = self.0.list_file_layouts().map_err(ReviewError::graph)?;
        let entities = self.0.list_all_entities().map_err(ReviewError::graph)?;
        let mut source_files = BTreeSet::new();

        for layout in layouts {
            if !matches!(
                layout.parse_completeness,
                kin_model::ParseCompleteness::Full
            ) {
                return Ok(false);
            }
            source_files.insert(layout.file_id.0);
        }
        for entity in entities {
            if let Some(file) = entity.file_origin {
                source_files.insert(file.0);
            } else if let Some(span) = entity.span {
                source_files.insert(span.file.0);
            }
        }

        for file in source_files {
            let Ok(path) = RepoPath::from_utf8(file.clone()) else {
                return Ok(false);
            };
            let Some(artifact_id) = self.0.artifact_id_at_path(&path) else {
                return Ok(false);
            };
            let artifact = GraphNodeId::Artifact(artifact_id);
            let neighborhood = self
                .0
                .traverse(&artifact, &[RelationKind::DependsOn], 1)
                .map_err(ReviewError::graph)?;
            let mut full = false;
            for relation in neighborhood
                .relations
                .iter()
                .filter(|relation| relation.src == artifact)
            {
                for evidence in &relation.evidence {
                    match evidence.parser_rule.as_deref() {
                        Some(
                            kin_index::CALL_SHAPE_PARSE_COVERAGE_INCOMPLETE_V1
                            | kin_index::CALL_SHAPE_EXTRACTION_COVERAGE_INCOMPLETE_V1,
                        ) => return Ok(false),
                        Some(kin_index::CALL_SHAPE_PARSE_COVERAGE_FULL_V1)
                            if evidence.source_path.as_deref() == Some(file.as_str()) =>
                        {
                            full = true;
                        }
                        _ => {}
                    }
                }
            }
            if !full {
                return Ok(false);
            }
        }

        Ok(true)
    }

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
    /// Subset of `consumer_count` whose inbound edge was resolved above
    /// `name_only` — a proven consumer rather than a same-name candidate.
    ///
    /// `consumer_count` counts every inbound edge, and a call edge matched by
    /// bare method name is a candidate: a same-named method on an unrelated
    /// type or a test double matches equally well. Any claim that an entity is
    /// used, or unused, must be read against this count rather than the total.
    #[serde(default)]
    pub proven_consumer_count: usize,
    /// Distinct non-test entities consuming this entity as a contract.
    pub contract_consumer_count: usize,
    /// Sorted distinct source files of the non-test consumers above.
    pub consumer_files: Vec<String>,
    /// Distinct test entities covering this entity (test-kind edges plus
    /// test-role inbound entities).
    pub covering_tests: usize,
    /// Distinct non-test, non-derived consumers that were themselves modified
    /// in the reviewed range — the coherent in-diff migration signal. These
    /// are excluded from `consumer_count` (a co-updated consumer is not a
    /// stranded external break); this field preserves the evidence that the
    /// surface change did have consumers and that they all moved with it.
    #[serde(default)]
    pub consumers_migrated_in_diff: usize,
    /// How the counted (non-migrated, non-test) consumers invoke this entity,
    /// distilled from the inbound `Calls` edges' argument-shape evidence. Lets
    /// an arity-preserving parameter rename be judged against actual call sites.
    #[serde(default)]
    pub call_shapes: ConsumerCallShapeSummary,
}

/// How a changed callable's counted consumers invoke it, distilled from the
/// inbound `Calls` edges' argument-shape evidence over the same real-consumer
/// set that drives `consumer_count`. Lets an arity-preserving rename be judged
/// against actual call sites instead of assumed keyword usage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConsumerCallShapeSummary {
    /// Union of keyword-argument names any counted call site passes. Sorted for
    /// deterministic output.
    pub caller_keyword_names: BTreeSet<String>,
    /// Some counted call site forwards `**mapping`, so its keyword set is not
    /// statically known — it could carry any renamed parameter.
    pub any_var_keyword_caller: bool,
    /// Every counted consumer is a `Calls` edge carrying argument-shape
    /// evidence. False when a counted consumer is a non-call edge, or a call
    /// whose shape was not captured (older snapshot, unresolved, or a language
    /// that does not emit shapes) — either way a rename cannot be proven safe.
    pub all_consumers_shaped_calls: bool,
}

impl EntityImpact {
    /// Total distinct inbound entities (consumers plus covering tests).
    /// Zero means the graph connects nothing to this entity.
    pub fn inbound_total(&self) -> usize {
        self.consumer_count + self.covering_tests
    }

    /// True when this entity has graph-known consumers and EVERY one was
    /// itself modified in the reviewed range: a self-contained migration with
    /// no stranded external consumer. `consumer_count` counts only external
    /// (non-migrated) consumers, so zero external plus at least one migrated
    /// consumer is a fully coherent in-diff migration.
    pub fn all_consumers_migrated(&self) -> bool {
        self.consumer_count == 0 && self.consumers_migrated_in_diff > 0
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
    // Line-independent identity of every entity touched in the reviewed range,
    // for both base and head sides of a modification. A co-updated consumer
    // that moved lines or changed its own signature keeps its (file, name,
    // kind) even as its content-derived id changes, so this key recognizes it
    // as migrated when exact-id matching cannot.
    let changed_keys: HashSet<(String, String, String)> = diff
        .entity_changes
        .iter()
        .flat_map(|change| match &change.kind {
            EntityChangeKind::Added(entity) => vec![entity_identity_key(entity)],
            EntityChangeKind::Modified { old, new } => {
                vec![entity_identity_key(old), entity_identity_key(new)]
            }
            EntityChangeKind::Removed(_) => Vec::new(),
        })
        .collect();

    let mut callers = Vec::new();
    let mut dependents = Vec::new();
    let mut contract_consumers = Vec::new();
    let mut tests = Vec::new();

    let mut seen_callers = HashSet::new();
    let mut seen_dependents = HashSet::new();
    let mut seen_consumers = HashSet::new();
    let mut seen_tests = HashSet::new();

    let mut entity_impacts: Vec<EntityImpact> = Vec::new();
    let call_shape_parse_coverage_complete = graph.call_shape_parse_coverage_complete()?;

    for &entity_id in &changed_ids {
        // Per-entity inbound attribution accumulated alongside the global
        // buckets. Sets are used only for distinct counts, never for output
        // ordering, so iteration order cannot leak into the report.
        let mut ent_consumers: HashSet<EntityId> = HashSet::new();
        let mut ent_strong_consumers: HashSet<EntityId> = HashSet::new();
        let mut ent_proven_consumers: HashSet<EntityId> = HashSet::new();
        let mut ent_contract_consumers: HashSet<EntityId> = HashSet::new();
        let mut ent_tests: HashSet<EntityId> = HashSet::new();
        // Non-test, non-derived consumers that were themselves modified in the
        // reviewed range: the coherent in-diff migration signal.
        let mut ent_migrated: HashSet<EntityId> = HashSet::new();
        // `consumer_files` is the human-readable projection of the consumer
        // ENTITY set below (which the fanout decision keys on) — the files those
        // consuming entities live in, for the report message only. It is never a
        // decision input: a consumer that happens to share the changed entity's
        // file is still a distinct consumer entity with a real inbound edge.
        let mut ent_consumer_files: BTreeSet<String> = BTreeSet::new();
        // Argument-shape distillation over the SAME counted-consumer set: the
        // union of keyword names any inbound call site uses, whether any caller
        // forwards `**kwargs` (keyword set then unknown), and whether every
        // counted consumer is a shaped call site. A non-call consumer or a call
        // whose shape was not captured leaves the rename unprovable-safe. Sets
        // accumulate a distinct union only; iteration order never reaches output.
        let mut ent_caller_keyword_names: BTreeSet<String> = BTreeSet::new();
        let mut ent_any_var_keyword_caller = false;
        let mut ent_all_consumers_shaped_calls = call_shape_parse_coverage_complete;

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

            let Some(entity) = graph.get_entity(&affected_id)? else {
                continue;
            };

            // A consumer that was itself modified in the reviewed range is a
            // MIGRATED consumer — it moved with the changed surface in the same
            // diff — not a stranded external break. Match on the exact id AND a
            // line-independent (file, name, kind) key: `EntityId` is
            // content-derived from (file, name, kind, start_line), so a
            // co-updated consumer whose declaration shifted lines or whose own
            // signature changed carries a different id at head than the id its
            // inbound edge resolves under. Exact-id matching alone would read
            // that coherent migration as an external break.
            if changed_set.contains(&affected_id)
                || changed_keys.contains(&entity_identity_key(&entity))
            {
                let is_test = entity.role == EntityRole::Test || rel.kind == RelationKind::Tests;
                let is_derived = consumer_is_derived(&entity);
                // Only a real consumer surface counts as a migrated consumer;
                // a co-updated test or regenerated copy was never a break.
                if !is_test && !is_derived {
                    ent_migrated.insert(affected_id);
                }
                continue;
            }

            let is_test = entity.role == EntityRole::Test || rel.kind == RelationKind::Tests;
            if is_test {
                ent_tests.insert(affected_id);
            } else if consumer_is_derived(&entity) {
                // Derived copies (amalgamated bundles, vendored snapshots)
                // regenerate from their sources; they appear in the blast
                // radius for navigation but cannot be "broken" consumers,
                // so they never feed consumer counts or breaking findings.
            } else {
                ent_consumers.insert(affected_id);
                if rel.confidence >= STRONG_CONSUMER_CONFIDENCE {
                    ent_strong_consumers.insert(affected_id);
                }
                if RelationResolution::of(&rel).is_proven() {
                    ent_proven_consumers.insert(affected_id);
                }
                if rel.kind == RelationKind::ConsumesContract {
                    ent_contract_consumers.insert(affected_id);
                }
                if let Some(file) = entity_file(&entity) {
                    ent_consumer_files.insert(file);
                }
                // Distill every call-site argument shape retained on this logical
                // consumer edge. A single caller can invoke the same target many
                // times, so relation evidence is a per-site set rather than a
                // scalar. A rename is only provably safe when every counted
                // consumer is a call and every occurrence carries shape evidence
                // stamped by the complete-occurrence aggregator. A non-call edge,
                // an older empty edge, an explicit unshaped occurrence, or legacy
                // first-occurrence evidence without the marker leaves it
                // unprovable.
                if rel.kind == RelationKind::Calls {
                    if rel.evidence.is_empty() {
                        ent_all_consumers_shaped_calls = false;
                    }
                    for evidence in &rel.evidence {
                        match evidence.call_shape.as_ref() {
                            Some(shape) => {
                                if evidence.parser_rule.as_deref()
                                    != Some(kin_index::CALL_SHAPE_EVIDENCE_AGGREGATION_V1)
                                {
                                    ent_all_consumers_shaped_calls = false;
                                }
                                for keyword in &shape.keywords {
                                    ent_caller_keyword_names.insert(keyword.clone());
                                }
                                if shape.has_var_keyword {
                                    ent_any_var_keyword_caller = true;
                                }
                            }
                            None => ent_all_consumers_shaped_calls = false,
                        }
                    }
                } else {
                    ent_all_consumers_shaped_calls = false;
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
                RelationKind::Tests if seen_tests.insert(affected_id) => {
                    tests.push(entity);
                }
                _ => {}
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
            proven_consumer_count: ent_proven_consumers.len(),
            contract_consumer_count: ent_contract_consumers.len(),
            consumer_files: ent_consumer_files.into_iter().collect(),
            covering_tests: ent_tests.len(),
            consumers_migrated_in_diff: ent_migrated.len(),
            call_shapes: ConsumerCallShapeSummary {
                caller_keyword_names: ent_caller_keyword_names,
                any_var_keyword_caller: ent_any_var_keyword_caller,
                all_consumers_shaped_calls: ent_all_consumers_shaped_calls,
            },
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

/// Whether a consumer is a derived copy (amalgamated single-header bundle,
/// vendored snapshot) that regenerates from its sources and so can never be a
/// broken consumer.
///
/// The persisted `role` is the primary signal, but the review evaluates a graph
/// materialized by `resolve_graph_at`, which replays persisted entities verbatim
/// and never reparses. An entity ingested before the amalgamated-bundle /
/// vendored path rules landed (e.g. a `single_include/*` copy persisted with
/// `role=Source`) therefore replays with a stale role and would be counted as a
/// real breaking consumer. The path-based check is the read-time backstop: it
/// re-derives the derived-copy status from the entity's canonical path with the
/// same pure `classify_file_role` function ingest applies. It only ever adds
/// exclusions (a derived path can never turn a real Source consumer into a
/// counted one it was not already), and `role` is not part of entity identity,
/// so this changes no persisted state.
fn consumer_is_derived(entity: &Entity) -> bool {
    if matches!(entity.role, EntityRole::Generated | EntityRole::Vendored) {
        return true;
    }
    entity_file(entity)
        .map(|path| {
            matches!(
                kin_index::classify_file_role(&path),
                EntityRole::Generated | EntityRole::Vendored
            )
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        Visibility,
    };
    use kin_model::ids::*;
    use kin_model::{
        ArtifactId, EntityStore, LocatedEntry, TransactionDelta, TreeDelta, TreeEntry,
    };

    fn admit_test_artifact(graph: &kin_db::InMemoryGraph, path: &str) -> ArtifactId {
        let path = RepoPath::from_utf8(path).expect("valid test repository path");
        let artifact_id = ArtifactId::new();
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: LocatedEntry::new(
                        path,
                        TreeEntry::blob(Hash256::from_bytes([0x5a; 32]), false),
                    ),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .expect("test artifact admission");
        artifact_id
    }

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
    use crate::inline::InlineCommentKind;
    use kin_model::entity::SourceSpan;
    use kin_model::provenance::{Actor, ActorId, Approval, AuditEvent};
    use kin_model::relation::{
        CallArgShape, GraphNodeId, Relation, RelationEvidence, RelationKind, RelationOrigin,
    };
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
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
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

    #[test]
    fn live_coverage_fails_closed_when_stale_full_and_extraction_incomplete_coexist() {
        let graph = kin_db::InMemoryGraph::new();
        let entity = entity_in_file("target", "src/lib.py", 1);
        let completeness = kin_index::FileParseCompletenessMap::from([(
            "src/lib.py".to_string(),
            kin_model::ParseCompleteness::Full,
        )]);
        let complete_files = [kin_index::FileParseData {
            file_path: "src/lib.py".to_string(),
            entities: vec![entity.clone()],
            relations: Vec::new(),
            imports: Vec::new(),
        }];
        let artifact_ids = kin_index::linker::ArtifactIdentityMap::from([(
            "src/lib.py".to_string(),
            admit_test_artifact(&graph, "src/lib.py"),
        )]);
        let mut coverage = kin_index::link_cross_file_with_completeness(
            &complete_files,
            &artifact_ids,
            &completeness,
        )
        .expect("graph-owned artifact identity must satisfy coverage linking");
        let mut extraction_incomplete = coverage[0].clone();
        extraction_incomplete.id = RelationId::from_bytes([0xee; 16]);
        extraction_incomplete.evidence = vec![RelationEvidence {
            source_path: Some("src/lib.py".to_string()),
            parser_rule: Some(kin_index::CALL_SHAPE_EXTRACTION_COVERAGE_INCOMPLETE_V1.to_string()),
            ..RelationEvidence::default()
        }];
        coverage.push(extraction_incomplete);

        graph
            .upsert_file_layout(&kin_model::FileLayout {
                file_id: FilePathId::new("src/lib.py"),
                parse_completeness: kin_model::ParseCompleteness::Full,
                imports: kin_model::ImportSection {
                    byte_range: 0..0,
                    items: Vec::new(),
                },
                regions: Vec::new(),
            })
            .unwrap();
        graph.upsert_entity(&entity).unwrap();
        for relation in coverage {
            graph.upsert_relation(&relation).unwrap();
        }

        assert!(
            !LiveGraph(&graph)
                .call_shape_parse_coverage_complete()
                .unwrap(),
            "explicit extraction-incomplete evidence must dominate a stale full marker"
        );
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
        fn call_shape_parse_coverage_complete(&self) -> Result<bool, ReviewError> {
            Ok(true)
        }

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
    fn stale_source_amalgamated_consumer_excluded_from_consumer_count_by_path() {
        // The review evaluates a graph
        // materialized by resolve_graph_at, which replays persisted entities
        // verbatim and never reparses. A single-header amalgamated copy ingested
        // before the single_include/ rule landed replays with a stale
        // role=Source, yet it must still be excluded from consumer_count by its
        // path so a benign signature change is not inflated with a phantom
        // breaking consumer. Only the real src/invoice.rs consumer counts.
        let target = entity_in_file("compute_total", "src/billing.rs", 1);
        let real = entity_in_file("render_invoice", "src/invoice.rs", 1);
        let amalgamated = entity_in_file("bundled_total", "single_include/catch.hpp", 1);
        assert_eq!(
            amalgamated.role,
            EntityRole::Source,
            "fixture: the amalgamated copy carries a stale persisted role"
        );

        let mut graph = MockImpactGraph::default();
        for entity in [&target, &real, &amalgamated] {
            graph.entities.insert(entity.id, entity.clone());
        }
        graph.inbound.insert(
            target.id,
            vec![calls(&real, &target), calls(&amalgamated, &target)],
        );

        let diff = SemanticDiff {
            entity_changes: vec![modified(&target)],
            ..Default::default()
        };

        let report = analyze_impact_at(&graph, &diff).unwrap();
        let impact = report
            .entity_impact(&target.id)
            .expect("target has an impact entry");
        assert_eq!(
            impact.consumer_count, 1,
            "the single_include/ amalgamated copy must be excluded by path; only the real \
             src/invoice.rs consumer counts"
        );
        assert_eq!(
            impact.consumer_files,
            vec!["src/invoice.rs".to_string()],
            "consumer_files must not include the generated single-header bundle"
        );
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

    // ── Call-site argument-shape harvest + arity-preserving rename gating ──

    fn calls_with_shape(src: &Entity, dst: &Entity, shape: CallArgShape) -> Relation {
        calls_with_shapes(src, dst, vec![Some(shape)])
    }

    fn calls_with_shapes(
        src: &Entity,
        dst: &Entity,
        shapes: Vec<Option<CallArgShape>>,
    ) -> Relation {
        Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(src.id),
            dst: GraphNodeId::Entity(dst.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: shapes
                .into_iter()
                .map(|call_shape| RelationEvidence {
                    parser_rule: call_shape
                        .as_ref()
                        .map(|_| kin_index::CALL_SHAPE_EVIDENCE_AGGREGATION_V1.to_string()),
                    call_shape,
                    ..RelationEvidence::default()
                })
                .collect(),
        }
    }

    fn target_entity(signature: &str) -> Entity {
        let mut e = entity_in_file("target", "src/mod.py", 10);
        e.signature = signature.to_string();
        e
    }

    /// Comment kinds emitted when `target`'s signature changes `old_sig` →
    /// `new_sig` and each caller invokes it with the given shape (`None` = a
    /// `Calls` edge with no captured shape).
    fn rename_review_kinds(
        old_sig: &str,
        new_sig: &str,
        caller_shapes: Vec<Option<CallArgShape>>,
    ) -> Vec<InlineCommentKind> {
        let new_target = target_entity(new_sig);
        let mut old_target = new_target.clone();
        old_target.signature = old_sig.to_string();

        let mut graph = MockImpactGraph::default();
        graph.entities.insert(new_target.id, new_target.clone());
        let mut edges = Vec::new();
        for (i, shape) in caller_shapes.into_iter().enumerate() {
            let caller = entity_in_file(&format!("caller{i}"), &format!("src/c{i}.py"), 1);
            graph.entities.insert(caller.id, caller.clone());
            edges.push(match shape {
                Some(s) => calls_with_shape(&caller, &new_target, s),
                None => calls(&caller, &new_target),
            });
        }
        graph.inbound.insert(new_target.id, edges);

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new_target.id,
                kind: EntityChangeKind::Modified {
                    old: old_target,
                    new: new_target.clone(),
                },
            }],
            ..Default::default()
        };
        let report = analyze_impact_at(&graph, &diff).unwrap();
        crate::inline::collect_inline_comments(&diff, &report)
            .into_iter()
            .map(|c| c.kind)
            .collect()
    }

    const RENAME_OLD: &str = "def target(self, ext, args)";
    const RENAME_NEW: &str = "def target(self, ext, lines)";

    #[test]
    fn harvest_distills_call_shapes_over_counted_consumers() {
        let target = target_entity(RENAME_NEW);
        let positional = entity_in_file("pos_caller", "src/a.py", 1);
        let keyword = entity_in_file("kw_caller", "src/b.py", 1);
        let mut graph = MockImpactGraph::default();
        for e in [&target, &positional, &keyword] {
            graph.entities.insert(e.id, e.clone());
        }
        graph.inbound.insert(
            target.id,
            vec![
                calls_with_shape(
                    &positional,
                    &target,
                    CallArgShape::new(2, vec![], false, false),
                ),
                calls_with_shape(
                    &keyword,
                    &target,
                    CallArgShape::new(1, vec!["args".to_string()], false, false),
                ),
            ],
        );
        let diff = SemanticDiff {
            entity_changes: vec![modified(&target)],
            ..Default::default()
        };
        let report = analyze_impact_at(&graph, &diff).unwrap();
        let summary = &report.entity_impact(&target.id).unwrap().call_shapes;
        assert!(
            summary.all_consumers_shaped_calls,
            "both consumers are shaped calls"
        );
        assert!(!summary.any_var_keyword_caller);
        assert!(summary.caller_keyword_names.contains("args"));
    }

    #[test]
    fn harvest_fails_closed_when_any_call_occurrence_lacks_shape() {
        let target = target_entity(RENAME_NEW);
        let caller = entity_in_file("caller", "src/caller.py", 1);
        let mut graph = MockImpactGraph::default();
        graph.entities.insert(target.id, target.clone());
        graph.entities.insert(caller.id, caller.clone());
        graph.inbound.insert(
            target.id,
            vec![calls_with_shapes(
                &caller,
                &target,
                vec![
                    Some(CallArgShape::new(
                        1,
                        vec!["safe_other_keyword".to_string()],
                        false,
                        false,
                    )),
                    None,
                ],
            )],
        );
        let diff = SemanticDiff {
            entity_changes: vec![modified(&target)],
            ..Default::default()
        };
        let report = analyze_impact_at(&graph, &diff).unwrap();
        let summary = &report.entity_impact(&target.id).unwrap().call_shapes;

        assert!(summary.caller_keyword_names.contains("safe_other_keyword"));
        assert!(
            !summary.all_consumers_shaped_calls,
            "one unshaped occurrence makes the entire rename proof incomplete"
        );
    }

    #[test]
    fn harvest_fails_closed_when_shape_lacks_complete_aggregation_marker() {
        let target = target_entity(RENAME_NEW);
        let caller = entity_in_file("caller", "src/caller.py", 1);
        let mut legacy =
            calls_with_shape(&caller, &target, CallArgShape::new(2, vec![], false, false));
        legacy.evidence[0].parser_rule = None;

        let mut graph = MockImpactGraph::default();
        graph.entities.insert(target.id, target.clone());
        graph.entities.insert(caller.id, caller);
        graph.inbound.insert(target.id, vec![legacy]);
        let diff = SemanticDiff {
            entity_changes: vec![modified(&target)],
            ..Default::default()
        };
        let report = analyze_impact_at(&graph, &diff).unwrap();
        let summary = &report.entity_impact(&target.id).unwrap().call_shapes;

        assert!(
            !summary.all_consumers_shaped_calls,
            "a v0.2.15 shaped record without the aggregation marker is incomplete proof"
        );
    }

    #[test]
    fn rename_with_only_positional_callers_is_not_breaking() {
        // (a) every call site positional → runtime-neutral, non-blocking.
        let kinds = rename_review_kinds(
            RENAME_OLD,
            RENAME_NEW,
            vec![Some(CallArgShape::new(2, vec![], false, false))],
        );
        assert!(kinds.contains(&InlineCommentKind::SignatureChange));
        assert!(!kinds.contains(&InlineCommentKind::Breaking));
        assert!(!kinds.contains(&InlineCommentKind::BreakingMigrated));
    }

    #[test]
    fn rename_with_keyword_caller_of_renamed_param_is_breaking() {
        // (b) a caller passes the renamed parameter by keyword → breaking.
        let kinds = rename_review_kinds(
            RENAME_OLD,
            RENAME_NEW,
            vec![Some(CallArgShape::new(
                1,
                vec!["args".to_string()],
                false,
                false,
            ))],
        );
        assert!(kinds.contains(&InlineCommentKind::Breaking));
    }

    #[test]
    fn rename_with_mixed_callers_is_breaking() {
        // (c) one positional, one keyword-of-renamed → breaking.
        let kinds = rename_review_kinds(
            RENAME_OLD,
            RENAME_NEW,
            vec![
                Some(CallArgShape::new(2, vec![], false, false)),
                Some(CallArgShape::new(1, vec!["args".to_string()], false, false)),
            ],
        );
        assert!(kinds.contains(&InlineCommentKind::Breaking));
    }

    #[test]
    fn rename_with_var_keyword_caller_is_breaking() {
        // (d) a `**kwargs` caller has an unknown keyword set → breaking.
        let kinds = rename_review_kinds(
            RENAME_OLD,
            RENAME_NEW,
            vec![Some(CallArgShape::new(1, vec![], false, true))],
        );
        assert!(kinds.contains(&InlineCommentKind::Breaking));
    }

    #[test]
    fn arity_change_not_rename_is_breaking() {
        // (e) an added required parameter is a real arity change, not a rename;
        // positional callers are stranded → still breaking.
        let kinds = rename_review_kinds(
            "def target(self, ext)",
            "def target(self, ext, extra)",
            vec![Some(CallArgShape::new(1, vec![], false, false))],
        );
        assert!(kinds.contains(&InlineCommentKind::Breaking));
    }

    #[test]
    fn rename_with_missing_shape_is_breaking() {
        // (f) a call edge with no captured shape cannot prove safety → breaking.
        let kinds = rename_review_kinds(RENAME_OLD, RENAME_NEW, vec![None]);
        assert!(kinds.contains(&InlineCommentKind::Breaking));
    }

    #[test]
    fn line_shifted_co_updated_consumer_is_migrated_not_an_external_break() {
        // `target` changed its signature. Its only consumer, `mover`, was ALSO
        // modified in the diff — but its declaration shifted lines, so the
        // head-graph inbound edge resolves to an id that differs from the id
        // the diff recorded for `mover`. Exact-id matching would miscount this
        // coherent migration as an external break; the (file, name, kind)
        // identity key recognizes it.
        let target = entity_in_file("target", "src/http.rs", 10);
        let mover_in_diff = entity_in_file("mover", "src/create.rs", 20);
        let mut mover_at_head = mover_in_diff.clone();
        mover_at_head.id = EntityId::new();

        let mut graph = MockImpactGraph::default();
        graph.entities.insert(target.id, target.clone());
        graph
            .entities
            .insert(mover_at_head.id, mover_at_head.clone());
        graph
            .inbound
            .insert(target.id, vec![calls(&mover_at_head, &target)]);

        let diff = SemanticDiff {
            entity_changes: vec![modified(&target), modified(&mover_in_diff)],
            ..Default::default()
        };

        let report = analyze_impact_at(&graph, &diff).unwrap();
        let impact = report.entity_impact(&target.id).expect("target impact");
        assert_eq!(
            impact.consumer_count, 0,
            "a co-updated consumer whose id shifted is not a stranded external break"
        );
        assert_eq!(
            impact.consumers_migrated_in_diff, 1,
            "the line-shifted co-update is recognized as migrated by identity key"
        );
        assert!(impact.all_consumers_migrated());
    }

    #[test]
    fn partial_migration_keeps_the_external_consumer_counted() {
        // `target` has two consumers: `mover` (co-updated, line-shifted id) and
        // `stranger` (untouched, in a file the diff never mentions). The
        // migration is PARTIAL — `stranger` still counts as an external break,
        // so the entity is not "all migrated".
        let target = entity_in_file("target", "src/http.rs", 10);
        let mover_in_diff = entity_in_file("mover", "src/create.rs", 20);
        let mut mover_at_head = mover_in_diff.clone();
        mover_at_head.id = EntityId::new();
        let stranger = entity_in_file("stranger", "src/other.rs", 5);

        let mut graph = MockImpactGraph::default();
        for entity in [&target, &mover_at_head, &stranger] {
            graph.entities.insert(entity.id, entity.clone());
        }
        graph.inbound.insert(
            target.id,
            vec![calls(&mover_at_head, &target), calls(&stranger, &target)],
        );

        let diff = SemanticDiff {
            entity_changes: vec![modified(&target), modified(&mover_in_diff)],
            ..Default::default()
        };

        let report = analyze_impact_at(&graph, &diff).unwrap();
        let impact = report.entity_impact(&target.id).expect("target impact");
        assert_eq!(
            impact.consumer_count, 1,
            "the untouched external consumer still counts"
        );
        assert_eq!(impact.consumers_migrated_in_diff, 1);
        assert!(
            !impact.all_consumers_migrated(),
            "a partial migration is not fully coherent"
        );
    }

    #[test]
    fn same_name_different_file_consumer_is_not_treated_as_migrated() {
        // A consumer that merely shares a NAME with a co-changed entity but
        // lives in a different file is a distinct entity and a real external
        // consumer — the identity key includes the file, so it is not
        // misread as a migration.
        let target = entity_in_file("target", "src/http.rs", 10);
        let changed_helper = entity_in_file("helper", "src/a.rs", 1);
        let unrelated_helper = entity_in_file("helper", "src/b.rs", 1);

        let mut graph = MockImpactGraph::default();
        for entity in [&target, &changed_helper, &unrelated_helper] {
            graph.entities.insert(entity.id, entity.clone());
        }
        graph
            .inbound
            .insert(target.id, vec![calls(&unrelated_helper, &target)]);

        let diff = SemanticDiff {
            entity_changes: vec![modified(&target), modified(&changed_helper)],
            ..Default::default()
        };

        let report = analyze_impact_at(&graph, &diff).unwrap();
        let impact = report.entity_impact(&target.id).expect("target impact");
        assert_eq!(
            impact.consumer_count, 1,
            "a same-name consumer in a different file is a real external consumer"
        );
        assert_eq!(impact.consumers_migrated_in_diff, 0);
    }
}
