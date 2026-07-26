// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Ref-scoped graph reads for review.
//!
//! The live adjacency indexes are mutable current state: they reflect the
//! latest ingest, not the graph as committed at a semantic ref. Blast-radius
//! queries for a `base..head` review must therefore not consult them —
//! whatever they return for entities of another era is residency-accidental.
//!
//! [`GraphAtRef`] materializes the committed graph state at a ref by
//! replaying the change DAG (`resolve_graph_at`) and serves the structural
//! read surface of impact analysis from that state alone. For an entity the
//! replayed history REMOVED, the at-ref adjacency is empty by construction
//! (the replay prunes its edges at the removing change), so its blast radius
//! is served from the replay's own tombstones: the edges that removal
//! severed. Work items, annotations, approvals, audit events, and actors are
//! operational overlay state keyed by stable IDs — not part of the replayed
//! structural graph — and stay answered by the live store.
//!
//! If the ancestry of the ref is not fully present in the graph, the state
//! cannot be trusted and materialization fails loud. It never falls back to
//! the live adjacency.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use kin_model::entity::Entity;
use kin_model::graph::{GraphStore, ResolvedGraphState};
use kin_model::ids::{EntityId, RelationId, SemanticChangeId};
use kin_model::provenance::{Actor, ActorId, Approval, AuditEvent};
use kin_model::relation::{Relation, RelationKind};
use kin_model::work::{Annotation, WorkItem, WorkScope};

use crate::error::ReviewError;
use crate::impact::ImpactGraph;

/// Committed graph state at a semantic ref, exposed through the impact read
/// surface. Read-only by construction: [`ImpactGraph`] has no write methods.
pub struct GraphAtRef<'a, G> {
    live: &'a G,
    at: SemanticChangeId,
    // Every change id reachable from `at` through parent edges, including
    // `at` itself — the set the materialization walk already visited. Range
    // queries use it to refuse bases that are not on this head's history.
    ancestry: HashSet<SemanticChangeId>,
    entities: HashMap<EntityId, Entity>,
    relations: HashMap<RelationId, Relation>,
    // BTree-keyed with relation-id-sorted edge lists: every traversal is
    // deterministic by construction, independent of replay or hash order.
    outgoing: BTreeMap<EntityId, Vec<RelationId>>,
    incoming: BTreeMap<EntityId, Vec<RelationId>>,
    // Edges severed by an entity's own removal, for entities absent at the
    // ref. The replay prunes a removed entity's relations at the removing
    // change, so the at-ref adjacency cannot say who consumed it — but the
    // replay's tombstones can: exactly the entity-only relations whose
    // ending change is the change that removed the entity. Edges a relation
    // delta removed EARLIER are excluded — those consumers had already let
    // go before the removal. Id-sorted; committed state, never live.
    severed: BTreeMap<EntityId, Vec<Relation>>,
}

// Manual impl: `G` is a store handle, not data — deriving would bound on
// `G: Debug` and dump the full replayed maps. Summarize the state instead.
impl<G> std::fmt::Debug for GraphAtRef<'_, G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GraphAtRef")
            .field("at", &self.at)
            .field("entities", &self.entities.len())
            .field("relations", &self.relations.len())
            .finish_non_exhaustive()
    }
}

impl<'a, G: GraphStore> GraphAtRef<'a, G> {
    /// Materialize the committed graph state at `at`.
    ///
    /// Fails with [`ReviewError::RefStateUnavailable`] if any change in the
    /// ancestry of `at` is missing from the store: `resolve_graph_at` skips
    /// missing rows silently, and a partial replay would understate the
    /// blast radius while looking authoritative.
    pub fn materialize(live: &'a G, at: &SemanticChangeId) -> Result<Self, ReviewError> {
        let mut visited = HashSet::new();
        let mut pending = vec![*at];
        while let Some(id) = pending.pop() {
            if !visited.insert(id) {
                continue;
            }
            match live.get_change(&id).map_err(ReviewError::graph)? {
                Some(change) => pending.extend(change.parents.iter().copied()),
                None => {
                    return Err(ReviewError::RefStateUnavailable {
                        at: *at,
                        missing: id,
                    })
                }
            }
        }

        let state = live.resolve_graph_at(at).map_err(ReviewError::graph)?;
        Ok(Self::from_state(live, *at, visited, state))
    }

    /// The ref this state was materialized at (cache key for reuse across
    /// repeated evaluations of the same head).
    pub fn at(&self) -> &SemanticChangeId {
        &self.at
    }

    /// Whether `id` is the materialized ref itself or one of its ancestors
    /// in the change DAG.
    pub fn ancestry_contains(&self, id: &SemanticChangeId) -> bool {
        self.ancestry.contains(id)
    }

    /// Every change reachable from the materialized ref, including itself.
    pub fn ancestry(&self) -> &HashSet<SemanticChangeId> {
        &self.ancestry
    }

    /// Whether the committed state at this ref anchors any entity in `file`,
    /// by source span or file origin. Distinguishes an inert edit of a real
    /// source file — entities captured at head, none altered in this range —
    /// from an unparsed artifact the graph never captured entities for.
    pub fn has_entity_in_file(&self, file: &str) -> bool {
        self.entities.values().any(|entity| {
            entity
                .span
                .as_ref()
                .is_some_and(|span| span.file.to_string() == file)
                || entity
                    .file_origin
                    .as_ref()
                    .is_some_and(|origin| origin.to_string() == file)
        })
    }

    fn from_state(
        live: &'a G,
        at: SemanticChangeId,
        ancestry: HashSet<SemanticChangeId>,
        state: ResolvedGraphState,
    ) -> Self {
        let mut outgoing: BTreeMap<EntityId, Vec<RelationId>> = BTreeMap::new();
        let mut incoming: BTreeMap<EntityId, Vec<RelationId>> = BTreeMap::new();
        for relation in state.relations.values() {
            if let Some(src) = relation.src.as_entity() {
                outgoing.entry(src).or_default().push(relation.id);
            }
            if let Some(dst) = relation.dst.as_entity() {
                incoming.entry(dst).or_default().push(relation.id);
            }
        }
        for edge_ids in outgoing.values_mut().chain(incoming.values_mut()) {
            edge_ids.sort_unstable_by_key(|relation_id| relation_id.0);
        }

        // Removal-severed edges: a tombstoned relation belongs to a removed
        // endpoint's severed set only when the relation was ended by the
        // same change that removed the entity — the prune the removal itself
        // caused. Entities re-added after an old removal are present at the
        // ref and keep their (empty-by-prune or rebuilt) live adjacency; the
        // severed surface is only for entities absent at the ref.
        let mut severed: BTreeMap<EntityId, Vec<Relation>> = BTreeMap::new();
        for (relation, ended_in) in state.relation_tombstones.values() {
            let (Some(src), Some(dst)) = (relation.src.as_entity(), relation.dst.as_entity())
            else {
                continue;
            };
            let endpoints = if src == dst {
                [Some(src), None]
            } else {
                [Some(src), Some(dst)]
            };
            for endpoint in endpoints.into_iter().flatten() {
                if state.entities.contains_key(&endpoint) {
                    continue;
                }
                if let Some((_, removed_in)) = state.entity_tombstones.get(&endpoint) {
                    if removed_in == ended_in {
                        severed.entry(endpoint).or_default().push(relation.clone());
                    }
                }
            }
        }
        for edges in severed.values_mut() {
            edges.sort_unstable_by_key(|relation| relation.id.0);
        }

        Self {
            live,
            at,
            ancestry,
            entities: state.entities,
            relations: state.relations,
            outgoing,
            incoming,
            severed,
        }
    }
}

/// Every change reachable from `at` through parent edges, including `at`
/// itself. Fails like [`GraphAtRef::materialize`] when a row in the walk is
/// missing: a partial ancestry would silently misscope range queries.
pub fn collect_ancestry<G: GraphStore>(
    store: &G,
    at: &SemanticChangeId,
) -> Result<HashSet<SemanticChangeId>, ReviewError> {
    let mut visited = HashSet::new();
    let mut pending = vec![*at];
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            continue;
        }
        match store.get_change(&id).map_err(ReviewError::graph)? {
            Some(change) => pending.extend(change.parents.iter().copied()),
            None => {
                return Err(ReviewError::RefStateUnavailable {
                    at: *at,
                    missing: id,
                })
            }
        }
    }
    Ok(visited)
}

impl<G: GraphStore> ImpactGraph for GraphAtRef<'_, G> {
    fn call_shape_parse_coverage_complete(&self) -> Result<bool, ReviewError> {
        let source_files = self
            .entities
            .values()
            .filter_map(|entity| {
                entity
                    .file_origin
                    .as_ref()
                    .map(|file| file.0.clone())
                    .or_else(|| entity.span.as_ref().map(|span| span.file.0.clone()))
            })
            .collect::<HashSet<_>>();
        let mut full_files = HashSet::new();

        for relation in self.relations.values() {
            for evidence in &relation.evidence {
                match evidence.parser_rule.as_deref() {
                    Some(
                        kin_index::CALL_SHAPE_PARSE_COVERAGE_INCOMPLETE_V1
                        | kin_index::CALL_SHAPE_EXTRACTION_COVERAGE_INCOMPLETE_V1,
                    ) => return Ok(false),
                    Some(kin_index::CALL_SHAPE_PARSE_COVERAGE_FULL_V1) => {
                        if let Some(file) = evidence.source_path.as_ref() {
                            full_files.insert(file.clone());
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(source_files.is_subset(&full_files))
    }

    fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>, ReviewError> {
        Ok(self.entities.get(id).cloned())
    }

    fn get_relations(
        &self,
        id: &EntityId,
        kinds: &[RelationKind],
    ) -> Result<Vec<Relation>, ReviewError> {
        let mut result = Vec::new();
        if let Some(edge_ids) = self.outgoing.get(id) {
            for relation_id in edge_ids {
                if let Some(relation) = self.relations.get(relation_id) {
                    let entity_only =
                        relation.src.as_entity().is_some() && relation.dst.as_entity().is_some();
                    if entity_only && (kinds.is_empty() || kinds.contains(&relation.kind)) {
                        result.push(relation.clone());
                    }
                }
            }
        }
        result.sort_unstable_by_key(|relation| relation.id.0);
        Ok(result)
    }

    fn get_all_relations_for_entity(&self, id: &EntityId) -> Result<Vec<Relation>, ReviewError> {
        // An entity absent at the ref was either never committed or was
        // removed by the ref's history. The replay pruned a removed entity's
        // edges at the removing change, so its blast radius is served from
        // the edges that removal severed — still committed state, never the
        // live adjacency.
        if !self.entities.contains_key(id) {
            return Ok(self.severed.get(id).cloned().unwrap_or_default());
        }

        // Union of both edge directions, mirroring the live store: entity-only
        // relations, deduplicated (a self-loop sits in both lists), sorted by
        // relation id so the order is insertion-independent.
        let mut result = Vec::new();
        let mut seen: HashSet<RelationId> = HashSet::new();
        let outgoing = self.outgoing.get(id).into_iter().flatten();
        let incoming = self.incoming.get(id).into_iter().flatten();
        for relation_id in outgoing.chain(incoming) {
            if let Some(relation) = self.relations.get(relation_id) {
                let entity_only =
                    relation.src.as_entity().is_some() && relation.dst.as_entity().is_some();
                if entity_only && seen.insert(relation.id) {
                    result.push(relation.clone());
                }
            }
        }
        result.sort_unstable_by_key(|relation| relation.id.0);
        Ok(result)
    }

    fn get_downstream_impact(
        &self,
        id: &EntityId,
        max_depth: u32,
    ) -> Result<Vec<Entity>, ReviewError> {
        // BFS over incoming edges, mirroring the live store's traversal; the
        // era of the adjacency is the only intended difference.
        let mut visited: HashSet<EntityId> = HashSet::new();
        let mut impacted_ids: Vec<EntityId> = Vec::new();
        let mut queue: VecDeque<(EntityId, u32)> = VecDeque::new();

        visited.insert(*id);
        queue.push_back((*id, 0));

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            let live_inbound = self
                .incoming
                .get(&current)
                .into_iter()
                .flatten()
                .filter_map(|relation_id| self.relations.get(relation_id));
            // An entity removed by the ref's history has no live inbound
            // edges; walk the edges its own removal severed instead so the
            // consumers a removal breaks stay reachable. `severed` only
            // holds entities absent at the ref, so present entities never
            // pick up historical edges here.
            let severed_inbound = self
                .severed
                .get(&current)
                .into_iter()
                .flatten()
                .filter(|relation| relation.dst.as_entity() == Some(current));
            for relation in live_inbound.chain(severed_inbound) {
                let Some(caller) = relation.src.as_entity() else {
                    continue;
                };
                if visited.insert(caller) {
                    impacted_ids.push(caller);
                    queue.push_back((caller, depth + 1));
                }
            }
        }

        Ok(impacted_ids
            .iter()
            .filter_map(|entity_id| self.entities.get(entity_id).cloned())
            .collect())
    }

    fn get_work_for_scope(&self, scope: &WorkScope) -> Result<Vec<WorkItem>, ReviewError> {
        self.live
            .get_work_for_scope(scope)
            .map_err(ReviewError::graph)
    }

    fn get_annotations_for_scope(&self, scope: &WorkScope) -> Result<Vec<Annotation>, ReviewError> {
        self.live
            .get_annotations_for_scope(scope)
            .map_err(ReviewError::graph)
    }

    fn get_approvals_for_change(
        &self,
        id: &SemanticChangeId,
    ) -> Result<Vec<Approval>, ReviewError> {
        self.live
            .get_approvals_for_change(id)
            .map_err(ReviewError::graph)
    }

    fn query_audit_events(
        &self,
        actor_id: Option<&ActorId>,
        limit: usize,
    ) -> Result<Vec<AuditEvent>, ReviewError> {
        self.live
            .query_audit_events(actor_id, limit)
            .map_err(ReviewError::graph)
    }

    fn get_actor(&self, id: &ActorId) -> Result<Option<Actor>, ReviewError> {
        self.live.get_actor(id).map_err(ReviewError::graph)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_model::change::{
        EntityDelta, LocatedEntry, RelationDelta, SemanticChange, TransactionDelta, TreeDelta,
        TreeEntry,
    };
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        Visibility,
    };
    use kin_model::graph::{ChangeStore, EntityStore};
    use kin_model::ids::*;
    use kin_model::relation::{GraphNodeId, RelationOrigin};
    use kin_model::timestamp::Timestamp;
    use kin_model::ArtifactId;

    fn admit_test_artifact(graph: &InMemoryGraph, path: &str) -> ArtifactId {
        let path = RepoPath::from_utf8(path).expect("valid test repository path");
        if let Some(artifact_id) = graph.artifact_id_at_path(&path) {
            return artifact_id;
        }
        let artifact_id = ArtifactId::new();
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: LocatedEntry::new(
                        path,
                        TreeEntry::blob(Hash256::from_bytes([0x4d; 32]), false),
                    ),
                }],
            })
            .expect("test artifact admission");
        artifact_id
    }

    fn test_entity(name: &str) -> Entity {
        Entity {
            id: EntityId::from_content("src/lib.rs", name, "function", 1),
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

    fn test_relation(byte: u8, src: EntityId, dst: EntityId, kind: RelationKind) -> Relation {
        Relation {
            id: RelationId::from_bytes([byte; 16]),
            kind,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![],
        }
    }

    fn graph_artifact_identities(
        graph: &InMemoryGraph,
        files: &[kin_index::FileParseData],
    ) -> kin_index::linker::ArtifactIdentityMap {
        files
            .iter()
            .map(|file| {
                (
                    file.file_path.clone(),
                    admit_test_artifact(graph, &file.file_path),
                )
            })
            .collect()
    }

    #[test]
    fn ref_scoped_parse_coverage_requires_positive_full_file_markers() {
        let live = InMemoryGraph::new();
        let at = SemanticChangeId::from_hash(Hash256::from_bytes([0x7a; 32]));
        let mut entity = test_entity("target");
        entity.file_origin = Some(FilePathId::new("src/lib.py"));
        let files = [kin_index::FileParseData {
            file_path: "src/lib.py".to_string(),
            entities: vec![entity.clone()],
            relations: Vec::new(),
            imports: Vec::new(),
        }];
        let artifact_ids = graph_artifact_identities(&live, &files);

        let materialize = |parse_completeness| {
            let completeness = kin_index::FileParseCompletenessMap::from([(
                "src/lib.py".to_string(),
                parse_completeness,
            )]);
            let relations =
                kin_index::link_cross_file_with_completeness(&files, &artifact_ids, &completeness)
                    .expect("graph-owned artifact identities must satisfy coverage linking")
                    .into_iter()
                    .map(|relation| (relation.id, relation))
                    .collect();
            GraphAtRef::from_state(
                &live,
                at,
                HashSet::from([at]),
                ResolvedGraphState {
                    entities: HashMap::from([(entity.id, entity.clone())]),
                    relations,
                    ..ResolvedGraphState::default()
                },
            )
        };

        let legacy = GraphAtRef::from_state(
            &live,
            at,
            HashSet::from([at]),
            ResolvedGraphState {
                entities: HashMap::from([(entity.id, entity.clone())]),
                ..ResolvedGraphState::default()
            },
        );
        assert!(!legacy.call_shape_parse_coverage_complete().unwrap());
        assert!(materialize(kin_model::ParseCompleteness::Full)
            .call_shape_parse_coverage_complete()
            .unwrap());
        assert!(!materialize(kin_model::ParseCompleteness::Partial(
            "recovered malformed call".to_string()
        ))
        .call_shape_parse_coverage_complete()
        .unwrap());

        let full_completeness = kin_index::FileParseCompletenessMap::from([(
            "src/lib.py".to_string(),
            kin_model::ParseCompleteness::Full,
        )]);
        let mut dual_relations =
            kin_index::link_cross_file_with_completeness(&files, &artifact_ids, &full_completeness)
                .expect("graph-owned artifact identities must satisfy coverage linking")
                .into_iter()
                .map(|relation| (relation.id, relation))
                .collect::<HashMap<_, _>>();
        let mut extraction_incomplete =
            test_relation(0x7c, entity.id, entity.id, RelationKind::DependsOn);
        extraction_incomplete.evidence = vec![kin_model::RelationEvidence {
            source_path: Some("src/lib.py".to_string()),
            parser_rule: Some(kin_index::CALL_SHAPE_EXTRACTION_COVERAGE_INCOMPLETE_V1.to_string()),
            ..kin_model::RelationEvidence::default()
        }];
        dual_relations.insert(extraction_incomplete.id, extraction_incomplete);
        let dual_state = GraphAtRef::from_state(
            &live,
            at,
            HashSet::from([at]),
            ResolvedGraphState {
                entities: HashMap::from([(entity.id, entity.clone())]),
                relations: dual_relations,
                ..ResolvedGraphState::default()
            },
        );
        assert!(
            !dual_state.call_shape_parse_coverage_complete().unwrap(),
            "historical extraction-incomplete evidence must dominate a stale full marker"
        );

        let mut target = test_entity("target");
        target.file_origin = Some(FilePathId::new("src/defs.py"));
        target.signature = "def target(ext, args)".to_string();
        let mut caller = test_entity("caller");
        caller.file_origin = Some(FilePathId::new("src/good.py"));
        let mut broken = test_entity("broken");
        broken.file_origin = Some(FilePathId::new("src/bad.py"));
        let coverage_files = [
            kin_index::FileParseData {
                file_path: "src/defs.py".to_string(),
                entities: vec![target.clone()],
                relations: Vec::new(),
                imports: Vec::new(),
            },
            kin_index::FileParseData {
                file_path: "src/good.py".to_string(),
                entities: vec![caller.clone()],
                relations: Vec::new(),
                imports: Vec::new(),
            },
            kin_index::FileParseData {
                file_path: "src/bad.py".to_string(),
                entities: vec![broken.clone()],
                relations: Vec::new(),
                imports: Vec::new(),
            },
        ];
        let completeness = kin_index::FileParseCompletenessMap::from([
            (
                "src/defs.py".to_string(),
                kin_model::ParseCompleteness::Full,
            ),
            (
                "src/good.py".to_string(),
                kin_model::ParseCompleteness::Full,
            ),
            (
                "src/bad.py".to_string(),
                kin_model::ParseCompleteness::Partial("omitted keyword call".to_string()),
            ),
        ]);
        let coverage_artifact_ids = graph_artifact_identities(&live, &coverage_files);
        let mut relations = kin_index::link_cross_file_with_completeness(
            &coverage_files,
            &coverage_artifact_ids,
            &completeness,
        )
        .expect("graph-owned artifact identities must satisfy coverage linking")
        .into_iter()
        .map(|relation| (relation.id, relation))
        .collect::<HashMap<_, _>>();
        let mut positional_call = test_relation(0x7b, caller.id, target.id, RelationKind::Calls);
        positional_call.evidence = vec![kin_model::RelationEvidence {
            parser_rule: Some(kin_index::CALL_SHAPE_EVIDENCE_AGGREGATION_V1.to_string()),
            call_shape: Some(kin_model::CallArgShape::new(2, Vec::new(), false, false)),
            ..kin_model::RelationEvidence::default()
        }];
        relations.insert(positional_call.id, positional_call);
        let historical = GraphAtRef::from_state(
            &live,
            at,
            HashSet::from([at]),
            ResolvedGraphState {
                entities: HashMap::from([
                    (target.id, target.clone()),
                    (caller.id, caller),
                    (broken.id, broken),
                ]),
                relations,
                ..ResolvedGraphState::default()
            },
        );
        let mut renamed = target.clone();
        renamed.signature = "def target(ext, lines)".to_string();
        let diff = crate::diff::SemanticDiff {
            entity_changes: vec![crate::diff::EntityChange {
                entity_id: target.id,
                kind: crate::diff::EntityChangeKind::Modified {
                    old: target,
                    new: renamed,
                },
            }],
            ..crate::diff::SemanticDiff::default()
        };
        let impact = crate::impact::analyze_impact_at(&historical, &diff).unwrap();
        assert!(
            !impact
                .entity_impact(&diff.entity_changes[0].entity_id)
                .unwrap()
                .call_shapes
                .all_consumers_shaped_calls
        );
    }

    fn change_id(byte: u8) -> SemanticChangeId {
        SemanticChangeId::from_hash(Hash256::from_bytes([byte; 32]))
    }

    fn change(
        id: SemanticChangeId,
        parents: Vec<SemanticChangeId>,
        entity_deltas: Vec<EntityDelta>,
        relation_deltas: Vec<RelationDelta>,
    ) -> SemanticChange {
        SemanticChange {
            id,
            parents,
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "test change".into(),
            entity_deltas,
            relation_deltas,
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        }
    }

    /// Committed DAG: change 1 adds target/caller/test wired by committed
    /// relations; change 2 removes the caller->target relation; change 3
    /// removes the target entity itself (pruning its remaining edges).
    fn committed_graph() -> (InMemoryGraph, Entity, Entity, Entity) {
        let graph = InMemoryGraph::new();
        let target = test_entity("target");
        let caller = test_entity("caller");
        let test = test_entity("covering_test");

        let calls = test_relation(1, caller.id, target.id, RelationKind::Calls);
        let tests = test_relation(2, test.id, target.id, RelationKind::Tests);

        graph
            .create_change(&change(
                change_id(1),
                vec![],
                vec![
                    EntityDelta::Added(target.clone()),
                    EntityDelta::Added(caller.clone()),
                    EntityDelta::Added(test.clone()),
                ],
                vec![
                    RelationDelta::Added(calls.clone()),
                    RelationDelta::Added(tests),
                ],
            ))
            .unwrap();
        graph
            .create_change(&change(
                change_id(2),
                vec![change_id(1)],
                vec![],
                vec![RelationDelta::Removed(calls.id)],
            ))
            .unwrap();
        graph
            .create_change(&change(
                change_id(3),
                vec![change_id(2)],
                vec![EntityDelta::Removed(target.id)],
                vec![],
            ))
            .unwrap();

        (graph, target, caller, test)
    }

    #[test]
    fn adjacency_is_replayed_from_committed_changes() {
        let (graph, target, caller, test) = committed_graph();

        // The live adjacency has none of the committed relations: the store
        // records change rows without applying relation deltas.
        assert!(graph.get_relations(&caller.id, &[]).unwrap().is_empty());
        assert!(graph
            .get_downstream_impact(&target.id, 2)
            .unwrap()
            .is_empty());

        let at_one = GraphAtRef::materialize(&graph, &change_id(1)).unwrap();

        let outgoing = at_one.get_relations(&caller.id, &[]).unwrap();
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].kind, RelationKind::Calls);
        assert_eq!(outgoing[0].dst, GraphNodeId::Entity(target.id));

        let kind_filtered = at_one
            .get_relations(&caller.id, &[RelationKind::Tests])
            .unwrap();
        assert!(kind_filtered.is_empty());

        // The full-edge read unions both directions: target's inbound Calls
        // and Tests edges surface even though target has no outgoing edges,
        // in relation-id order.
        let all_for_target = at_one.get_all_relations_for_entity(&target.id).unwrap();
        assert_eq!(all_for_target.len(), 2);
        assert_eq!(all_for_target[0].kind, RelationKind::Calls);
        assert_eq!(all_for_target[1].kind, RelationKind::Tests);
        assert!(all_for_target
            .iter()
            .all(|relation| relation.dst == GraphNodeId::Entity(target.id)));

        let downstream = at_one.get_downstream_impact(&target.id, 2).unwrap();
        let mut names: Vec<&str> = downstream.iter().map(|e| e.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, vec!["caller", "covering_test"]);

        // Entity bodies come from the replayed state.
        assert_eq!(
            at_one.get_entity(&test.id).unwrap().unwrap().name,
            "covering_test"
        );
    }

    #[test]
    fn adjacency_respects_relation_removal_at_later_ref() {
        let (graph, target, caller, _test) = committed_graph();

        let at_two = GraphAtRef::materialize(&graph, &change_id(2)).unwrap();

        let downstream = at_two.get_downstream_impact(&target.id, 2).unwrap();
        let names: Vec<&str> = downstream.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["covering_test"]);
        assert!(at_two.get_relations(&caller.id, &[]).unwrap().is_empty());

        // The removed Calls edge is gone from the full-edge read too; only
        // the Tests edge survives at this ref.
        let all_for_target = at_two.get_all_relations_for_entity(&target.id).unwrap();
        assert_eq!(all_for_target.len(), 1);
        assert_eq!(all_for_target[0].kind, RelationKind::Tests);
    }

    #[test]
    fn live_only_relations_are_invisible_at_ref() {
        let (graph, target, _caller, _test) = committed_graph();

        // A relation upserted into the live adjacency but never committed to
        // the change DAG must not leak into ref-scoped reads.
        let ghost = test_entity("ghost_consumer");
        graph.upsert_entity(&ghost).unwrap();
        graph
            .upsert_relation(&test_relation(9, ghost.id, target.id, RelationKind::Calls))
            .unwrap();
        assert!(!graph
            .get_downstream_impact(&target.id, 2)
            .unwrap()
            .is_empty());

        let at_two = GraphAtRef::materialize(&graph, &change_id(2)).unwrap();
        let downstream = at_two.get_downstream_impact(&target.id, 2).unwrap();
        assert!(downstream.iter().all(|e| e.name != "ghost_consumer"));
    }

    #[test]
    fn removed_entity_serves_edges_severed_by_its_own_removal() {
        let (graph, target, _caller, test) = committed_graph();

        // Change 3 removed `target`; the replay pruned its edges there. The
        // full-edge read serves exactly what that removal severed: the Tests
        // edge. The Calls edge was removed by change 2 — that consumer had
        // already let go before the removal, and must not resurrect.
        let at_three = GraphAtRef::materialize(&graph, &change_id(3)).unwrap();
        assert!(at_three.get_entity(&target.id).unwrap().is_none());

        let severed = at_three.get_all_relations_for_entity(&target.id).unwrap();
        assert_eq!(severed.len(), 1);
        assert_eq!(severed[0].kind, RelationKind::Tests);
        assert_eq!(severed[0].src, GraphNodeId::Entity(test.id));

        // The downstream walk from the removed entity reaches the surviving
        // consumer through the severed edge.
        let downstream = at_three.get_downstream_impact(&target.id, 2).unwrap();
        let names: Vec<&str> = downstream.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["covering_test"]);
    }

    #[test]
    fn missing_ancestry_fails_loud() {
        let graph = InMemoryGraph::new();
        let ghost_parent = change_id(7);
        graph
            .create_change(&change(change_id(8), vec![ghost_parent], vec![], vec![]))
            .unwrap();

        let err = GraphAtRef::materialize(&graph, &change_id(8)).unwrap_err();
        match err {
            ReviewError::RefStateUnavailable { at, missing } => {
                assert_eq!(at, change_id(8));
                assert_eq!(missing, ghost_parent);
            }
            other => panic!("expected RefStateUnavailable, got {other:?}"),
        }

        let err = GraphAtRef::materialize(&graph, &change_id(9)).unwrap_err();
        assert!(matches!(
            err,
            ReviewError::RefStateUnavailable { missing, .. } if missing == change_id(9)
        ));
    }

    #[test]
    fn downstream_impact_order_is_deterministic() {
        let (graph, target, _caller, _test) = committed_graph();

        let baseline: Vec<EntityId> = GraphAtRef::materialize(&graph, &change_id(1))
            .unwrap()
            .get_downstream_impact(&target.id, 2)
            .unwrap()
            .iter()
            .map(|e| e.id)
            .collect();
        for _ in 0..5 {
            let pass: Vec<EntityId> = GraphAtRef::materialize(&graph, &change_id(1))
                .unwrap()
                .get_downstream_impact(&target.id, 2)
                .unwrap()
                .iter()
                .map(|e| e.id)
                .collect();
            assert_eq!(pass, baseline);
        }
    }
}
