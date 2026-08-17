// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Deterministic, evidence-preserving ranking over Kin's graph-native impact walk.
//!
//! The score is an inspection-priority heuristic, not a calibrated probability.
//! Every point is attributable to a graph relation, its path length, confidence,
//! and captured source evidence. The existing [`crate::impact::ImpactReport`]
//! remains the compatibility surface for review policy; this module is additive.

use std::collections::{BTreeMap, HashMap, VecDeque};

use kin_index::RelationResolution;
use kin_model::entity::{Entity, EntityRole};
use kin_model::graph::GraphStore;
use kin_model::ids::{EntityId, RelationId};
use kin_model::relation::{GraphNodeId, Relation, RelationEvidence, RelationKind};
use serde::{Deserialize, Serialize};

use crate::error::ReviewError;
use crate::impact::{ImpactGraph, LiveGraph};

pub const RANKED_IMPACT_SCHEMA_VERSION: &str = "kin.ranked-impact.v1";

/// Exact integer formula used for [`RankedImpactCandidate::priority_score`].
///
/// The components are intentionally exposed in each result. A consumer must
/// never relabel this score as likelihood, risk probability, or calibration.
pub const PRIORITY_SCORE_FORMULA: &str = "bucket_points + relation_points + max(0, 240 - 60 * (hop - 1)) + round(100 * clamp(relation_confidence, 0, 1)) + (25 if the relation carries a source span else 0)";

/// Line-independent `(file, name, kind, normalized signature)` identity used
/// to compare candidates across re-indexes and distinguish overloads.
/// `EntityId` includes the declaration's start line, so it is included in the
/// report as snapshot provenance but is not the candidate's durable identity.
/// Stable identity is not necessarily unique within one snapshot: conditional
/// declarations may have identical signatures in the same file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StableEntityIdentity {
    pub file: String,
    pub name: String,
    pub kind: String,
    /// Whitespace-normalized declaration signature. This distinguishes
    /// overloads without depending on a declaration's line number.
    pub signature: String,
}

impl StableEntityIdentity {
    pub fn from_entity(entity: &Entity) -> Self {
        Self {
            file: entity_file(entity).unwrap_or_default(),
            name: entity.name.clone(),
            kind: entity_kind_name(entity),
            signature: normalized_signature(entity),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactBucket {
    ContractConsumer,
    RuntimeCaller,
    TypeDependent,
    Dependent,
    Test,
    Derived,
}

impl ImpactBucket {
    pub fn points(self) -> u32 {
        match self {
            Self::ContractConsumer => 500,
            Self::RuntimeCaller => 450,
            Self::TypeDependent => 400,
            Self::Dependent => 350,
            Self::Test => 250,
            Self::Derived => 100,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateLocation {
    pub file: String,
    pub start_line: Option<u32>,
    pub end_line: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationPathStep {
    pub relation_id: RelationId,
    pub relation_kind: RelationKind,
    pub from_entity_id: EntityId,
    pub from_identity: StableEntityIdentity,
    pub to_entity_id: EntityId,
    pub to_identity: StableEntityIdentity,
    pub confidence_basis_points: u32,
    /// How this hop's edge was resolved: `type_resolved`, `import_scoped`, or
    /// `name_only`. A path is only as trustworthy as its weakest hop, and a
    /// `name_only` hop was matched by bare name with nothing at the call site
    /// proving the destination. Defaulted on read so a report recorded before
    /// the marker existed still deserializes.
    #[serde(default)]
    pub resolution: String,
    /// Parser/linker evidence copied from the graph edge. Source spans, rules,
    /// tokens, and resolved paths remain machine-checkable in the output.
    pub evidence: Vec<RelationEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorityScoreComponents {
    pub bucket_points: u32,
    pub relation_points: u32,
    pub hop_points: u32,
    pub confidence_points: u32,
    pub source_evidence_points: u32,
}

impl PriorityScoreComponents {
    pub fn total(&self) -> u32 {
        self.bucket_points
            + self.relation_points
            + self.hop_points
            + self.confidence_points
            + self.source_evidence_points
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedImpactCandidate {
    /// Snapshot-local graph id. Use `identity` to compare across snapshots.
    pub entity_id: EntityId,
    pub identity: StableEntityIdentity,
    pub location: CandidateLocation,
    pub bucket: ImpactBucket,
    /// Relation joining this candidate to the next entity toward the root.
    pub relation: RelationKind,
    pub hop: u32,
    /// Inspection-priority points. This is not a calibrated probability.
    pub priority_score: u32,
    pub score_components: PriorityScoreComponents,
    /// Root-near to candidate-far graph path, preserving every edge's evidence.
    pub path: Vec<RelationPathStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedImpactReport {
    pub schema_version: String,
    pub root_entity_id: EntityId,
    pub root_identity: StableEntityIdentity,
    pub max_depth: u32,
    pub score_semantics: String,
    pub score_formula: String,
    pub candidates: Vec<RankedImpactCandidate>,
}

/// Rank graph-native downstream impact from a live graph store.
pub fn rank_impact<G: GraphStore>(
    store: &G,
    root: &EntityId,
    max_depth: u32,
) -> Result<RankedImpactReport, ReviewError> {
    rank_impact_at(&LiveGraph(store), root, max_depth)
}

/// Rank graph-native downstream impact from an explicitly scoped graph view.
///
/// Traversal follows inbound entity relations only: a candidate points to the
/// entity it consumes. Outbound dependencies of the changed entity are not
/// downstream impact. Relation iteration and final ranking have explicit
/// stable tie-breaks, so storage/hash-map order cannot affect the result.
pub fn rank_impact_at<I: ImpactGraph>(
    graph: &I,
    root: &EntityId,
    max_depth: u32,
) -> Result<RankedImpactReport, ReviewError> {
    let root_entity = graph
        .get_entity(root)?
        .ok_or(ReviewError::EntityNotFound(*root))?;
    let root_identity = StableEntityIdentity::from_entity(&root_entity);
    let bounded_depth = max_depth.min(8);

    #[derive(Clone)]
    struct Frontier {
        entity_id: EntityId,
        entity: Entity,
        hop: u32,
        path: Vec<RelationPathStep>,
    }

    let mut queue = VecDeque::from([Frontier {
        entity_id: *root,
        entity: root_entity,
        hop: 0,
        path: Vec::new(),
    }]);
    // The first route at a hop is canonical because each frontier's inbound
    // relations are sorted. A shorter route always dominates deeper traversal.
    let mut shallowest_hop: HashMap<EntityId, u32> = HashMap::from([(*root, 0)]);
    let mut candidates: BTreeMap<(StableEntityIdentity, EntityId), RankedImpactCandidate> =
        BTreeMap::new();

    while let Some(frontier) = queue.pop_front() {
        if frontier.hop >= bounded_depth {
            continue;
        }
        let mut relations = graph.get_all_relations_for_entity(&frontier.entity_id)?;
        relations.retain(|relation| is_impact_relation(relation.kind));
        relations.sort_by_key(relation_sort_key);

        for relation in relations {
            if relation.dst != GraphNodeId::Entity(frontier.entity_id) {
                continue;
            }
            let Some(candidate_id) = relation.src.as_entity() else {
                continue;
            };
            if frontier.path.iter().any(|step| {
                step.to_entity_id == candidate_id || step.from_entity_id == candidate_id
            }) || candidate_id == *root
            {
                continue;
            }
            let Some(candidate_entity) = graph.get_entity(&candidate_id)? else {
                continue;
            };
            let hop = frontier.hop + 1;
            let candidate_identity = StableEntityIdentity::from_entity(&candidate_entity);
            let candidate_key = (candidate_identity.clone(), candidate_id);
            let step = RelationPathStep {
                relation_id: relation.id,
                relation_kind: relation.kind,
                from_entity_id: candidate_id,
                from_identity: candidate_identity.clone(),
                to_entity_id: frontier.entity_id,
                to_identity: StableEntityIdentity::from_entity(&frontier.entity),
                confidence_basis_points: confidence_basis_points(relation.confidence),
                resolution: RelationResolution::of(&relation).as_str().to_string(),
                evidence: relation.evidence.clone(),
            };
            let mut path = frontier.path.clone();
            // Traversal discovers root-near edges first, so append preserves the
            // root-near -> candidate-far order promised by the wire contract.
            path.push(step);

            let bucket = impact_bucket(&candidate_entity, relation.kind);
            let components = score_components(bucket, &relation, hop);
            let ranked = RankedImpactCandidate {
                entity_id: candidate_id,
                identity: candidate_identity.clone(),
                location: candidate_location(&candidate_entity),
                bucket,
                relation: relation.kind,
                hop,
                priority_score: components.total(),
                score_components: components,
                path: path.clone(),
            };

            match candidates.get(&candidate_key) {
                Some(existing) if !candidate_is_better(&ranked, existing) => {}
                _ => {
                    candidates.insert(candidate_key, ranked);
                }
            }

            let should_expand = match shallowest_hop.get(&candidate_id) {
                Some(previous) => hop < *previous,
                None => true,
            };
            if should_expand && hop < bounded_depth {
                shallowest_hop.insert(candidate_id, hop);
                queue.push_back(Frontier {
                    entity_id: candidate_id,
                    entity: candidate_entity,
                    hop,
                    path,
                });
            }
        }
    }

    let mut candidates: Vec<_> = candidates.into_values().collect();
    candidates.sort_by(|left, right| {
        right
            .priority_score
            .cmp(&left.priority_score)
            .then_with(|| left.hop.cmp(&right.hop))
            .then_with(|| left.identity.cmp(&right.identity))
            .then_with(|| left.entity_id.cmp(&right.entity_id))
    });

    Ok(RankedImpactReport {
        schema_version: RANKED_IMPACT_SCHEMA_VERSION.to_string(),
        root_entity_id: *root,
        root_identity,
        max_depth: bounded_depth,
        score_semantics: "deterministic inspection-priority points; not a calibrated probability"
            .to_string(),
        score_formula: PRIORITY_SCORE_FORMULA.to_string(),
        candidates,
    })
}

fn candidate_is_better(
    candidate: &RankedImpactCandidate,
    existing: &RankedImpactCandidate,
) -> bool {
    candidate.hop < existing.hop
        || (candidate.hop == existing.hop
            && (candidate.priority_score > existing.priority_score
                || (candidate.priority_score == existing.priority_score
                    && candidate.entity_id < existing.entity_id)))
}

fn relation_sort_key(relation: &Relation) -> (String, String, String) {
    (
        relation.src.to_string(),
        relation_kind_name(relation.kind),
        relation.id.to_string(),
    )
}

fn is_impact_relation(kind: RelationKind) -> bool {
    matches!(
        kind,
        RelationKind::Extends
            | RelationKind::Implements
            | RelationKind::Overrides
            | RelationKind::Calls
            | RelationKind::Spawns
            | RelationKind::Instantiates
            | RelationKind::References
            | RelationKind::UsesMacro
            | RelationKind::UsesType
            | RelationKind::Imports
            | RelationKind::Includes
            | RelationKind::DependsOn
            | RelationKind::ConsumesContract
            | RelationKind::SubscribesTo
            | RelationKind::SendsMessage
            | RelationKind::Tests
            | RelationKind::Covers
            | RelationKind::DerivedFrom
    )
}

fn impact_bucket(entity: &Entity, relation: RelationKind) -> ImpactBucket {
    if matches!(entity.role, EntityRole::Generated | EntityRole::Vendored)
        || relation == RelationKind::DerivedFrom
    {
        ImpactBucket::Derived
    } else if entity.role == EntityRole::Test
        || matches!(relation, RelationKind::Tests | RelationKind::Covers)
    {
        ImpactBucket::Test
    } else {
        match relation {
            RelationKind::ConsumesContract => ImpactBucket::ContractConsumer,
            RelationKind::Calls
            | RelationKind::Spawns
            | RelationKind::Instantiates
            | RelationKind::SendsMessage => ImpactBucket::RuntimeCaller,
            RelationKind::Extends
            | RelationKind::Implements
            | RelationKind::Overrides
            | RelationKind::UsesType => ImpactBucket::TypeDependent,
            _ => ImpactBucket::Dependent,
        }
    }
}

fn score_components(
    bucket: ImpactBucket,
    relation: &Relation,
    hop: u32,
) -> PriorityScoreComponents {
    let hop_points = 240u32.saturating_sub(60u32.saturating_mul(hop.saturating_sub(1)));
    PriorityScoreComponents {
        bucket_points: bucket.points(),
        relation_points: relation_points(relation.kind),
        hop_points,
        confidence_points: (relation.confidence.clamp(0.0, 1.0) * 100.0).round() as u32,
        source_evidence_points: if relation
            .evidence
            .iter()
            .any(|evidence| evidence.source_span.is_some())
        {
            25
        } else {
            0
        },
    }
}

fn relation_points(kind: RelationKind) -> u32 {
    match kind {
        RelationKind::ConsumesContract => 120,
        RelationKind::Calls | RelationKind::Spawns => 110,
        RelationKind::Extends | RelationKind::Implements | RelationKind::Overrides => 105,
        RelationKind::Instantiates | RelationKind::References | RelationKind::UsesType => 90,
        RelationKind::SubscribesTo | RelationKind::SendsMessage => 80,
        RelationKind::Imports | RelationKind::Includes | RelationKind::DependsOn => 70,
        RelationKind::Tests | RelationKind::Covers => 50,
        RelationKind::UsesMacro | RelationKind::DerivedFrom => 40,
        _ => 0,
    }
}

fn confidence_basis_points(confidence: f32) -> u32 {
    (confidence.clamp(0.0, 1.0) * 10_000.0).round() as u32
}

fn candidate_location(entity: &Entity) -> CandidateLocation {
    CandidateLocation {
        file: entity_file(entity).unwrap_or_default(),
        start_line: entity.span.as_ref().map(|span| span.start_line),
        end_line: entity.span.as_ref().map(|span| span.end_line),
    }
}

fn entity_file(entity: &Entity) -> Option<String> {
    entity
        .span
        .as_ref()
        .map(|span| span.file.to_string())
        .or_else(|| entity.file_origin.as_ref().map(ToString::to_string))
}

fn entity_kind_name(entity: &Entity) -> String {
    serde_json::to_value(entity.kind)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| format!("{:?}", entity.kind).to_ascii_lowercase())
}

fn normalized_signature(entity: &Entity) -> String {
    let normalized = entity
        .signature
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.is_empty() {
        format!("signature_hash:{}", entity.fingerprint.signature_hash)
    } else {
        normalized
    }
}

fn relation_kind_name(kind: RelationKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| format!("{kind:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use kin_model::entity::{
        EntityKind, EntityMetadata, FingerprintAlgorithm, SemanticFingerprint, SourceSpan,
        Visibility,
    };
    use kin_model::ids::{FilePathId, Hash256, LanguageId, SemanticChangeId};
    use kin_model::provenance::{Actor, ActorId, Approval, AuditEvent};
    use kin_model::relation::{RelationEvidence, RelationOrigin};
    use kin_model::work::{Annotation, WorkItem, WorkScope};

    #[derive(Default)]
    struct Graph {
        entities: HashMap<EntityId, Entity>,
        relations: HashMap<EntityId, Vec<Relation>>,
    }

    impl ImpactGraph for Graph {
        fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>, ReviewError> {
            Ok(self.entities.get(id).cloned())
        }
        fn get_relations(
            &self,
            _id: &EntityId,
            _kinds: &[RelationKind],
        ) -> Result<Vec<Relation>, ReviewError> {
            Ok(Vec::new())
        }
        fn get_all_relations_for_entity(
            &self,
            id: &EntityId,
        ) -> Result<Vec<Relation>, ReviewError> {
            Ok(self.relations.get(id).cloned().unwrap_or_default())
        }
        fn get_downstream_impact(
            &self,
            _id: &EntityId,
            _max_depth: u32,
        ) -> Result<Vec<Entity>, ReviewError> {
            Ok(Vec::new())
        }
        fn get_work_for_scope(&self, _scope: &WorkScope) -> Result<Vec<WorkItem>, ReviewError> {
            Ok(Vec::new())
        }
        fn get_annotations_for_scope(
            &self,
            _scope: &WorkScope,
        ) -> Result<Vec<Annotation>, ReviewError> {
            Ok(Vec::new())
        }
        fn get_approvals_for_change(
            &self,
            _id: &SemanticChangeId,
        ) -> Result<Vec<Approval>, ReviewError> {
            Ok(Vec::new())
        }
        fn query_audit_events(
            &self,
            _actor_id: Option<&ActorId>,
            _limit: usize,
        ) -> Result<Vec<AuditEvent>, ReviewError> {
            Ok(Vec::new())
        }
        fn get_actor(&self, _id: &ActorId) -> Result<Option<Actor>, ReviewError> {
            Ok(None)
        }
    }

    fn entity(name: &str, file: &str, line: u32) -> Entity {
        Entity {
            id: EntityId::from_content(file, name, "function", line),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: Some(SourceSpan {
                file: FilePathId::new(file),
                start_byte: 0,
                end_byte: 8,
                start_line: line,
                start_col: 0,
                end_line: line + 1,
                end_col: 0,
            }),
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn edge(src: &Entity, dst: &Entity, kind: RelationKind, with_span: bool) -> Relation {
        Relation {
            id: RelationId::from_content(
                &src.id.to_string(),
                &dst.id.to_string(),
                &format!("{kind:?}"),
            ),
            kind,
            src: GraphNodeId::Entity(src.id),
            dst: GraphNodeId::Entity(dst.id),
            confidence: 0.8,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![RelationEvidence {
                source_span: with_span.then(|| src.span.clone().unwrap()),
                parser_rule: Some("test-rule".to_string()),
                ..RelationEvidence::default()
            }],
        }
    }

    fn graph_in_order(reverse: bool) -> (Graph, EntityId) {
        let root = entity("changed", "src/lib.rs", 10);
        let direct = entity("direct", "src/direct.rs", 20);
        let transitive = entity("transitive", "src/transitive.rs", 30);
        let contract = entity("contract", "src/contract.rs", 40);
        let mut graph = Graph::default();
        for item in [&root, &direct, &transitive, &contract] {
            graph.entities.insert(item.id, item.clone());
        }
        let mut inbound = vec![
            edge(&direct, &root, RelationKind::Calls, true),
            edge(&contract, &root, RelationKind::ConsumesContract, false),
        ];
        if reverse {
            inbound.reverse();
        }
        graph.relations.insert(root.id, inbound);
        graph.relations.insert(
            direct.id,
            vec![edge(&transitive, &direct, RelationKind::References, true)],
        );
        (graph, root.id)
    }

    #[test]
    fn ranking_is_deterministic_across_relation_storage_order() {
        let (a, root) = graph_in_order(false);
        let (b, _) = graph_in_order(true);
        let left = serde_json::to_vec(&rank_impact_at(&a, &root, 3).unwrap()).unwrap();
        let right = serde_json::to_vec(&rank_impact_at(&b, &root, 3).unwrap()).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn ranked_candidate_carries_complete_two_hop_path_evidence() {
        let (graph, root) = graph_in_order(false);
        let report = rank_impact_at(&graph, &root, 3).unwrap();
        let candidate = report
            .candidates
            .iter()
            .find(|candidate| candidate.identity.name == "transitive")
            .expect("transitive candidate");
        assert_eq!(candidate.hop, 2);
        assert_eq!(candidate.path.len(), 2);
        assert_eq!(candidate.path[0].to_identity.name, "changed");
        assert_eq!(candidate.path[0].from_identity.name, "direct");
        assert_eq!(candidate.path[1].to_identity.name, "direct");
        assert_eq!(candidate.path[1].from_identity.name, "transitive");
        assert!(candidate.path[1].evidence[0].source_span.is_some());
        assert!(report
            .score_semantics
            .contains("not a calibrated probability"));
    }

    #[test]
    fn stable_identity_ignores_line_and_snapshot_entity_id() {
        let first = entity("same", "src/same.rs", 10);
        let second = entity("same", "src/same.rs", 90);
        assert_ne!(first.id, second.id);
        assert_eq!(
            StableEntityIdentity::from_entity(&first),
            StableEntityIdentity::from_entity(&second)
        );
    }

    #[test]
    fn same_name_same_file_overloads_remain_distinct_candidates() {
        let root = entity("root", "src/root.rs", 1);
        let mut first = entity("handle", "src/handlers.rs", 10);
        first.signature = "fn handle(value: u32)".to_string();
        let mut second = entity("handle", "src/handlers.rs", 30);
        second.signature = "fn   handle(value: String)".to_string();
        let mut graph = Graph::default();
        for value in [&root, &first, &second] {
            graph.entities.insert(value.id, value.clone());
        }
        graph.relations.insert(
            root.id,
            vec![
                edge(&first, &root, RelationKind::Calls, true),
                edge(&second, &root, RelationKind::Calls, true),
            ],
        );
        let report = rank_impact_at(&graph, &root.id, 1).unwrap();
        assert_eq!(report.candidates.len(), 2);
        let signatures: Vec<_> = report
            .candidates
            .iter()
            .map(|candidate| candidate.identity.signature.as_str())
            .collect();
        assert!(signatures.contains(&"fn handle(value: u32)"));
        assert!(signatures.contains(&"fn handle(value: String)"));
    }

    #[test]
    fn identical_conditional_declarations_remain_distinct_candidates() {
        let root = entity("root", "src/root.rs", 1);
        let first = entity("platform", "src/platform.rs", 10);
        let second = entity("platform", "src/platform.rs", 30);
        assert_eq!(
            StableEntityIdentity::from_entity(&first),
            StableEntityIdentity::from_entity(&second)
        );

        let mut graph = Graph::default();
        for value in [&root, &first, &second] {
            graph.entities.insert(value.id, value.clone());
        }
        graph.relations.insert(
            root.id,
            vec![
                edge(&first, &root, RelationKind::Calls, true),
                edge(&second, &root, RelationKind::Calls, true),
            ],
        );

        let report = rank_impact_at(&graph, &root.id, 1).unwrap();
        assert_eq!(report.candidates.len(), 2);
        let ids: Vec<_> = report
            .candidates
            .iter()
            .map(|candidate| candidate.entity_id)
            .collect();
        assert!(ids.contains(&first.id));
        assert!(ids.contains(&second.id));
    }

    #[test]
    fn confidence_points_match_the_documented_rounding_formula() {
        let root = entity("root", "src/root.rs", 1);
        let caller = entity("caller", "src/caller.rs", 1);
        let mut relation = edge(&caller, &root, RelationKind::Calls, false);
        relation.confidence = 0.8049;
        let components = score_components(ImpactBucket::RuntimeCaller, &relation, 1);
        assert_eq!(components.confidence_points, 80);
    }

    #[test]
    fn spawned_runtime_caller_is_ranked_with_direct_path_evidence() {
        let root = entity("worker", "src/worker.rs", 10);
        let caller = entity("launch", "src/launch.rs", 20);
        let mut graph = Graph::default();
        for value in [&root, &caller] {
            graph.entities.insert(value.id, value.clone());
        }
        graph.relations.insert(
            root.id,
            vec![edge(&caller, &root, RelationKind::Spawns, true)],
        );

        let report = rank_impact_at(&graph, &root.id, 1).unwrap();
        let candidate = report.candidates.first().expect("spawn caller");
        assert_eq!(candidate.identity.name, "launch");
        assert_eq!(candidate.bucket, ImpactBucket::RuntimeCaller);
        assert_eq!(candidate.relation, RelationKind::Spawns);
        assert_eq!(candidate.score_components.relation_points, 110);
        assert_eq!(candidate.path[0].relation_kind, RelationKind::Spawns);
        assert!(candidate.path[0].evidence[0].source_span.is_some());
    }
}
