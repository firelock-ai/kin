// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Bounded, single-lock facts for comparing admitted source with its derivation.
//! Classification and certificate interpretation belong to the consumer.
//!
//! The facts depend on the inspected graph and the caps below, never on timing.
//! Inspection waits for a writer that holds or is waiting for the lock instead
//! of refusing, and no cap is a clock, so one graph yields the same facts, or
//! the same refusal, on every call. The daemon folds these facts into the
//! verdict of every source-derived answer. A refusal chosen by host load or
//! scheduling would change what that verdict discloses about a graph that did
//! not change.

use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;
use std::time::Instant;

use super::InMemoryGraph;
use crate::types::{
    ArtifactId, Entity, FilePathId, GraphNodeId, Hash256, ParseCompleteness, Relation, RelationId,
    RepoPath, ResolvedArtifact,
};

/// Limits apply to inspected records as well as copied facts. Exact-path reads
/// still inspect entity references because span paths can differ from the
/// file-origin index. Every limit counts graph content, so the graph alone
/// decides whether one refuses. There is deliberately no time budget.
#[derive(Debug, Clone, Copy)]
pub struct SourceDerivationLimits {
    /// Tree paths, layout records, opaque records and artifact adjacency lists,
    /// each capped separately. Requested paths also obey this limit.
    pub max_artifacts: usize,
    pub max_entities: usize,
    /// Outgoing adjacency slots plus requested reserved-ID lookups, including
    /// absent occupants. The bounded mixed-node adjacency scan also uses this cap.
    pub max_relations: usize,
    /// Logical copied bytes, including fixed-size records and nested strings.
    /// Allocator bookkeeping and vector spare capacity are not included.
    pub max_bytes: usize,
}

impl Default for SourceDerivationLimits {
    fn default() -> Self {
        Self {
            max_artifacts: 4_096,
            max_entities: 65_536,
            max_relations: 16_384,
            max_bytes: 8 * 1_024 * 1_024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceDerivationLimit {
    Artifacts,
    Entities,
    Relations,
    Bytes,
}

/// No partial facts are returned when the graph exceeds a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SourceDerivationUnavailable {
    #[error("source derivation inspection exceeded its {0:?} limit")]
    LimitExceeded(SourceDerivationLimit),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEntityBinding {
    pub file: FilePathId,
    /// Absent for missing, malformed or noncanonical source-digest metadata.
    pub digest: Option<Hash256>,
}

impl SourceEntityBinding {
    /// Project only source identity, without cloning an entity's body or
    /// metadata. The defining span wins over the fallback file origin.
    pub fn from_entity(entity: &Entity) -> Option<Self> {
        let file = entity_file(entity)?;
        Some(Self {
            file: file.clone(),
            digest: Self::source_digest(entity),
        })
    }

    /// Decode the recorded digest without cloning source identity. A digest
    /// alone is not proof that this entity belongs to any particular file.
    pub fn source_digest(entity: &Entity) -> Option<Hash256> {
        entity
            .metadata
            .extra
            .get("blob_hash")
            .and_then(serde_json::Value::as_str)
            .filter(|raw| raw.len() == 64)
            .and_then(|raw| {
                let digest = Hash256::from_hex(raw).ok()?;
                (digest.to_string() == raw).then_some(digest)
            })
    }
}

fn entity_file(entity: &Entity) -> Option<&FilePathId> {
    entity
        .span
        .as_ref()
        .map(|span| &span.file)
        .or(entity.file_origin.as_ref())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLayoutFact {
    pub file: FilePathId,
    pub full: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceOpaqueFact {
    pub file: FilePathId,
    pub hash: Hash256,
}

/// An exact relation-ID lookup for one admitted artifact. The occupant is
/// retained even when its endpoints or kind do not describe that artifact.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceReservedRelation {
    pub artifact: ArtifactId,
    pub id: RelationId,
    /// `None` is observed absence at this exact ID. A missing fact means the
    /// ID was not inspected, rather than that no relation occupied it.
    pub relation: Option<Relation>,
}

/// One point-in-time observation of the selected graph's source domains.
/// A caller requesting paths receives facts only for those exact paths, not a
/// repository-wide completeness claim. Entity and layout evidence outside the
/// tree is retained rather than silently excluded. Vector order is unspecified.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SourceDerivationFacts {
    pub binding_history: kin_model::BindingHistoryObservation,
    pub artifacts: Vec<ResolvedArtifact>,
    pub missing_paths: Vec<RepoPath>,
    pub entities: Vec<SourceEntityBinding>,
    pub layouts: Vec<SourceLayoutFact>,
    pub opaque: Vec<SourceOpaqueFact>,
    /// Entire outgoing artifact payloads of every kind for the consumer's
    /// exact certificate validator, including malformed certificates.
    pub relations: Vec<Relation>,
    /// Populated only when the caller supplies an exact relation-ID factory.
    pub reserved_relations: Vec<SourceReservedRelation>,
}

struct Budget {
    limits: SourceDerivationLimits,
    bytes: usize,
}

/// How long one inspection waited for the entity read lock and then held it,
/// logged when it lets go. Nothing reads these instants back, so they cannot
/// reach the facts. Declared after the guard, it drops first, while the guard
/// is still held, so the hold it reports covers the whole scan.
struct LockHoldLog {
    requested: Instant,
    acquired: Instant,
}

impl Drop for LockHoldLog {
    fn drop(&mut self) {
        tracing::debug!(
            target: "kin_db::source_derivation",
            wait_us = self.acquired.duration_since(self.requested).as_micros() as u64,
            hold_us = self.acquired.elapsed().as_micros() as u64,
            "source derivation inspection released the entity read lock"
        );
    }
}

impl Budget {
    fn count(
        &self,
        count: usize,
        max: usize,
        kind: SourceDerivationLimit,
    ) -> Result<(), SourceDerivationUnavailable> {
        if count > max {
            return Err(SourceDerivationUnavailable::LimitExceeded(kind));
        }
        Ok(())
    }

    fn charge(&mut self, bytes: usize) -> Result<(), SourceDerivationUnavailable> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.limits.max_bytes)
            .ok_or(SourceDerivationUnavailable::LimitExceeded(
                SourceDerivationLimit::Bytes,
            ))?;
        Ok(())
    }

    fn array<T>(&mut self, count: usize) -> Result<(), SourceDerivationUnavailable> {
        let bytes =
            count
                .checked_mul(size_of::<T>())
                .ok_or(SourceDerivationUnavailable::LimitExceeded(
                    SourceDerivationLimit::Bytes,
                ))?;
        self.charge(bytes)
    }

    /// Inspect every variable-size part before the caller clones the relation.
    fn relation(&mut self, relation: &Relation) -> Result<(), SourceDerivationUnavailable> {
        self.array::<Relation>(1)?;
        self.relation_payload(relation)
    }

    /// Variable-sized storage beyond the inline `Relation` value, which may
    /// already be charged as part of a `SourceReservedRelation` record.
    fn relation_payload(&mut self, relation: &Relation) -> Result<(), SourceDerivationUnavailable> {
        if let Some(source) = &relation.import_source {
            self.charge(source.len())?;
        }
        self.array::<kin_model::relation::RelationEvidence>(relation.evidence.len())?;
        for evidence in &relation.evidence {
            if let Some(span) = &evidence.source_span {
                self.charge(span.file.0.len())?;
            }
            for value in [
                &evidence.parser_rule,
                &evidence.token,
                &evidence.source_path,
                &evidence.resolved_path,
            ]
            .into_iter()
            .flatten()
            {
                self.charge(value.len())?;
            }
            if let Some(shape) = &evidence.call_shape {
                self.array::<String>(shape.keywords.len())?;
                for keyword in &shape.keywords {
                    self.charge(keyword.len())?;
                }
            }
        }
        Ok(())
    }
}

impl InMemoryGraph {
    /// Inspect compact source facts under one entity-store read guard. A writer
    /// that holds or is waiting for the lock finishes first, so the facts
    /// describe the graph as that writer left it. Waiting is what keeps the
    /// answer a property of the graph: a refusal here would be decided by
    /// whichever write happened to overlap the call. No host reads, full
    /// snapshot, derived cache, or mutation occurs. `None` selects all
    /// inventory; `Some` selects exact byte-preserving paths.
    pub fn source_derivation_facts(
        &self,
        limits: SourceDerivationLimits,
        paths: Option<&[RepoPath]>,
    ) -> Result<SourceDerivationFacts, SourceDerivationUnavailable> {
        self.source_derivation_facts_inner(limits, paths, None)
    }

    /// Also inspect the exact reserved relation ID for every selected admitted
    /// artifact. The factory defines the ID; this layer does not interpret the
    /// occupant. Exact lookups, including absence, share the relation count cap
    /// with outgoing adjacency slots. All facts use the same read guard.
    pub fn source_derivation_facts_with_reserved_relation(
        &self,
        limits: SourceDerivationLimits,
        paths: Option<&[RepoPath]>,
        factory: fn(ArtifactId) -> RelationId,
    ) -> Result<SourceDerivationFacts, SourceDerivationUnavailable> {
        self.source_derivation_facts_inner(limits, paths, Some(factory))
    }

    fn source_derivation_facts_inner(
        &self,
        limits: SourceDerivationLimits,
        paths: Option<&[RepoPath]>,
        reserved_relation: Option<fn(ArtifactId) -> RelationId>,
    ) -> Result<SourceDerivationFacts, SourceDerivationUnavailable> {
        let mut budget = Budget { limits, bytes: 0 };
        let lock_requested = Instant::now();
        let ent = self.entities.read();
        let _hold = LockHoldLog {
            requested: lock_requested,
            acquired: Instant::now(),
        };
        // Borrow request paths. Nothing proportional to a supplied path's
        // length is cloned merely to select scope.
        let requested = if let Some(paths) = paths {
            budget.count(
                paths.len(),
                limits.max_artifacts,
                SourceDerivationLimit::Artifacts,
            )?;
            budget.array::<(&[u8], &RepoPath)>(paths.len())?;
            let mut requested = BTreeMap::new();
            for path in paths {
                if path.as_bytes().len() > limits.max_bytes {
                    return Err(SourceDerivationUnavailable::LimitExceeded(
                        SourceDerivationLimit::Bytes,
                    ));
                }
                requested.insert(path.as_bytes(), path);
            }
            Some(requested)
        } else {
            None
        };
        let included = |file: &FilePathId| {
            requested
                .as_ref()
                .is_none_or(|paths| paths.contains_key(file.0.as_bytes()))
        };
        let mut facts = SourceDerivationFacts {
            binding_history: ent
                .verified_binding_history
                .as_ref()
                .map_or(kin_model::BindingHistoryObservation::Unproven, |proof| {
                    proof.observation()
                }),
            ..Default::default()
        };
        let mut selected_artifacts = BTreeSet::new();
        if let Some(paths) = &requested {
            if paths.is_empty() {
                return Ok(facts);
            }
            for &path in paths.values() {
                if let Some(artifact) = ent.resolved_tree.artifact_at_path(path) {
                    budget.array::<ResolvedArtifact>(1)?;
                    budget.charge(artifact.path.as_bytes().len())?;
                    budget.array::<crate::types::ArtifactId>(1)?;
                    facts.artifacts.push(artifact.clone());
                    selected_artifacts.insert(artifact.artifact_id);
                } else {
                    budget.array::<RepoPath>(1)?;
                    budget.charge(path.as_bytes().len())?;
                    facts.missing_paths.push(path.clone());
                }
            }
        } else {
            budget.count(
                ent.resolved_tree.len(),
                limits.max_artifacts,
                SourceDerivationLimit::Artifacts,
            )?;
            for artifact in ent.resolved_tree.artifacts_by_path() {
                budget.array::<ResolvedArtifact>(1)?;
                budget.charge(artifact.path.as_bytes().len())?;
                facts.artifacts.push(artifact.clone());
            }
        }
        budget.count(
            ent.entities.len(),
            limits.max_entities,
            SourceDerivationLimit::Entities,
        )?;
        for entity in ent.entities.values() {
            let Some(file) = entity_file(entity).filter(|file| included(file)) else {
                continue;
            };
            budget.array::<SourceEntityBinding>(1)?;
            budget.charge(file.0.len())?;
            // A digest is interpreted, not copied. Still reject an oversized
            // malformed string before passing it to the projector.
            if entity
                .metadata
                .extra
                .get("blob_hash")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|raw| raw.len() > limits.max_bytes)
            {
                return Err(SourceDerivationUnavailable::LimitExceeded(
                    SourceDerivationLimit::Bytes,
                ));
            }
            if let Some(binding) = SourceEntityBinding::from_entity(entity) {
                facts.entities.push(binding);
            }
        }
        budget.count(
            ent.file_layouts.len(),
            limits.max_artifacts,
            SourceDerivationLimit::Artifacts,
        )?;
        for layout in ent.file_layouts.values() {
            if included(&layout.file_id) {
                budget.array::<SourceLayoutFact>(1)?;
                budget.charge(layout.file_id.0.len())?;
                facts.layouts.push(SourceLayoutFact {
                    file: layout.file_id.clone(),
                    full: matches!(layout.parse_completeness, ParseCompleteness::Full),
                });
            }
        }
        budget.count(
            ent.opaque_artifacts.len(),
            limits.max_artifacts,
            SourceDerivationLimit::Artifacts,
        )?;
        for opaque in ent.opaque_artifacts.values() {
            if included(&opaque.file_id) {
                budget.array::<SourceOpaqueFact>(1)?;
                budget.charge(opaque.file_id.0.len())?;
                facts.opaque.push(SourceOpaqueFact {
                    file: opaque.file_id.clone(),
                    hash: opaque.content_hash,
                });
            }
        }
        // Exact lookups retain foreign occupants even when no adjacency list
        // for the requested artifact could lead to them.
        let mut edges = 0usize;
        if let Some(factory) = reserved_relation {
            budget.count(
                facts.artifacts.len(),
                limits.max_relations,
                SourceDerivationLimit::Relations,
            )?;
            for artifact in &facts.artifacts {
                budget.array::<SourceReservedRelation>(1)?;
                let id = factory(artifact.artifact_id);
                let relation = ent.relations.get(&id);
                if let Some(relation) = relation {
                    budget.relation_payload(relation)?;
                }
                facts.reserved_relations.push(SourceReservedRelation {
                    artifact: artifact.artifact_id,
                    id,
                    relation: relation.cloned(),
                });
            }
            edges = facts.artifacts.len();
        }
        // Use the mixed-node adjacency without cloning it. Count every examined
        // adjacency slot and retain every outgoing artifact relation kind.
        let mut artifact_nodes = 0usize;
        for (node_index, (node, outgoing)) in ent.node_outgoing.iter().enumerate() {
            budget.count(
                node_index.saturating_add(1),
                limits
                    .max_entities
                    .saturating_add(limits.max_artifacts)
                    .saturating_add(limits.max_relations),
                SourceDerivationLimit::Relations,
            )?;
            let GraphNodeId::Artifact(id) = node else {
                continue;
            };
            artifact_nodes = artifact_nodes.saturating_add(1);
            budget.count(
                artifact_nodes,
                limits.max_artifacts,
                SourceDerivationLimit::Artifacts,
            )?;
            if requested.is_some() && !selected_artifacts.contains(id) {
                continue;
            }
            edges = edges.checked_add(outgoing.len()).ok_or(
                SourceDerivationUnavailable::LimitExceeded(SourceDerivationLimit::Relations),
            )?;
            budget.count(
                edges,
                limits.max_relations,
                SourceDerivationLimit::Relations,
            )?;
            for id in outgoing {
                let Some(relation) = ent.relations.get(id) else {
                    continue;
                };
                if relation.src == *node {
                    budget.relation(relation)?;
                    facts.relations.push(relation.clone());
                }
            }
        }
        Ok(facts)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl InMemoryGraph {
    /// Hold the entity-store write lock without writing, so a dependent
    /// crate's test can put a reader behind a writer in flight. Unlike a real
    /// write through `entities_write`, it leaves graph truth, the truth epoch
    /// and the binding-history proof exactly as they were.
    #[must_use = "the lock is released as soon as the guard drops"]
    pub fn hold_entity_writer_for_test(&self) -> impl Sized + '_ {
        self.entities.write()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use kin_model::relation::{CallArgShape, RelationEvidence};

    fn limits() -> SourceDerivationLimits {
        SourceDerivationLimits::default()
    }

    fn path(value: &str) -> RepoPath {
        RepoPath::from_utf8(value).unwrap()
    }

    fn artifact(path: RepoPath, byte: u8) -> ResolvedArtifact {
        ResolvedArtifact::new(
            ArtifactId::new(),
            path,
            TreeEntry::blob(Hash256::from_bytes([byte; 32]), false),
        )
    }

    fn entity(file: &str, byte: u8) -> Entity {
        let mut metadata = EntityMetadata::default();
        metadata.extra.insert(
            "blob_hash".to_string(),
            serde_json::json!(Hash256::from_bytes([byte; 32]).to_string()),
        );
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "worker".to_string(),
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
            span: None,
            signature: "fn worker()".to_string(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata,
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn relation(artifact: &ResolvedArtifact) -> Relation {
        let node = GraphNodeId::Artifact(artifact.artifact_id);
        Relation {
            id: RelationId::new(),
            kind: RelationKind::DependsOn,
            src: node,
            dst: node,
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: Some("module".to_string()),
            evidence: vec![RelationEvidence {
                token: Some("uninterpreted-evidence".to_string()),
                source_path: Some("a.rs".to_string()),
                call_shape: Some(CallArgShape::new(
                    1,
                    vec!["value".to_string()],
                    false,
                    false,
                )),
                ..RelationEvidence::default()
            }],
        }
    }

    fn insert_relation(graph: &InMemoryGraph, relation: Relation) {
        let mut ent = graph.entities.write();
        ent.node_outgoing
            .entry(relation.src)
            .or_default()
            .push(relation.id);
        ent.relations.insert(relation.id, relation);
    }

    fn reserved_id(artifact: ArtifactId) -> RelationId {
        RelationId(artifact.0)
    }

    #[test]
    fn reserved_lookup_retains_foreign_endpoints_and_all_outgoing_kinds() {
        let graph = InMemoryGraph::new();
        let a = artifact(path("a.rs"), 1);
        let b = artifact(path("b.rs"), 2);
        graph.entities.write().resolved_tree =
            ResolvedTree::from_artifacts([a.clone(), b.clone()]).unwrap();
        let mut foreign = relation(&b);
        foreign.id = reserved_id(a.artifact_id);
        foreign.kind = RelationKind::Calls;
        foreign.dst = GraphNodeId::Entity(EntityId::new());
        insert_relation(&graph, foreign.clone());
        let mut wrong_kind = relation(&a);
        wrong_kind.kind = RelationKind::References;
        insert_relation(&graph, wrong_kind.clone());
        let claimed_at_wrong_id = relation(&a);
        insert_relation(&graph, claimed_at_wrong_id.clone());

        let facts = graph
            .source_derivation_facts_with_reserved_relation(
                limits(),
                Some(&[path("a.rs")]),
                reserved_id,
            )
            .unwrap();
        assert_eq!(facts.artifacts, vec![a.clone()]);
        assert_eq!(
            facts.reserved_relations,
            vec![SourceReservedRelation {
                artifact: a.artifact_id,
                id: reserved_id(a.artifact_id),
                relation: Some(foreign),
            }]
        );
        assert_eq!(facts.relations, vec![wrong_kind, claimed_at_wrong_id]);
    }

    #[test]
    fn missing_selector_is_unchecked_and_missing_reserved_id_is_observed_absent() {
        let graph = InMemoryGraph::new();
        let a = artifact(path("a.rs"), 1);
        let b = artifact(path("b.rs"), 2);
        graph.entities.write().resolved_tree =
            ResolvedTree::from_artifacts([a.clone(), b.clone()]).unwrap();
        assert!(graph
            .source_derivation_facts(limits(), None)
            .unwrap()
            .reserved_relations
            .is_empty());
        let facts = graph
            .source_derivation_facts_with_reserved_relation(limits(), None, reserved_id)
            .unwrap();
        assert_eq!(
            facts.reserved_relations,
            [a, b]
                .map(|artifact| SourceReservedRelation {
                    artifact: artifact.artifact_id,
                    id: reserved_id(artifact.artifact_id),
                    relation: None,
                })
                .to_vec()
        );
        let missing = graph
            .source_derivation_facts_with_reserved_relation(
                limits(),
                Some(&[path("missing.rs")]),
                reserved_id,
            )
            .unwrap();
        assert_eq!(missing.missing_paths, vec![path("missing.rs")]);
        assert!(missing.reserved_relations.is_empty());
        assert_eq!(
            graph
                .source_derivation_facts_with_reserved_relation(limits(), Some(&[]), reserved_id,)
                .unwrap(),
            SourceDerivationFacts::default()
        );
    }

    #[test]
    fn reserved_lookup_preserves_combined_relation_caps() {
        fn unexpected_factory(_: ArtifactId) -> RelationId {
            panic!("unavailable reads must not invoke the ID factory")
        }
        let graph = InMemoryGraph::new();
        let a = artifact(path("a.rs"), 1);
        graph.entities.write().resolved_tree = ResolvedTree::from_artifacts([a.clone()]).unwrap();
        assert_eq!(
            graph.source_derivation_facts_with_reserved_relation(
                SourceDerivationLimits {
                    max_relations: 0,
                    ..limits()
                },
                None,
                unexpected_factory,
            ),
            Err(SourceDerivationUnavailable::LimitExceeded(
                SourceDerivationLimit::Relations
            ))
        );
        let mut edge = relation(&a);
        edge.id = reserved_id(a.artifact_id);
        insert_relation(&graph, edge.clone());
        assert_eq!(
            graph.source_derivation_facts_with_reserved_relation(
                SourceDerivationLimits {
                    max_relations: 1,
                    ..limits()
                },
                None,
                reserved_id,
            ),
            Err(SourceDerivationUnavailable::LimitExceeded(
                SourceDerivationLimit::Relations
            ))
        );
        let facts = graph
            .source_derivation_facts_with_reserved_relation(
                SourceDerivationLimits {
                    max_relations: 2,
                    ..limits()
                },
                None,
                reserved_id,
            )
            .unwrap();
        assert_eq!(facts.relations, vec![edge.clone()]);
        assert_eq!(facts.reserved_relations[0].relation, Some(edge));
    }

    #[test]
    fn reserved_occupant_copies_obey_exact_byte_budget_and_foreign_payload_preflight() {
        let graph = InMemoryGraph::new();
        let a = artifact(path("a.rs"), 1);
        graph.entities.write().resolved_tree = ResolvedTree::from_artifacts([a.clone()]).unwrap();
        let mut edge = relation(&a);
        edge.id = reserved_id(a.artifact_id);
        insert_relation(&graph, edge.clone());
        let mut budget = Budget {
            limits: limits(),
            bytes: 0,
        };
        budget.array::<ResolvedArtifact>(1).unwrap();
        budget.charge(a.path.as_bytes().len()).unwrap();
        budget.array::<SourceReservedRelation>(1).unwrap();
        budget.relation_payload(&edge).unwrap();
        budget.relation(&edge).unwrap();
        let exact = budget.bytes;
        let facts = graph
            .source_derivation_facts_with_reserved_relation(
                SourceDerivationLimits {
                    max_bytes: exact,
                    ..limits()
                },
                None,
                reserved_id,
            )
            .unwrap();
        assert_eq!(facts.reserved_relations[0].relation, Some(edge.clone()));
        assert_eq!(facts.relations, vec![edge.clone()]);
        assert_eq!(
            graph.source_derivation_facts_with_reserved_relation(
                SourceDerivationLimits {
                    max_bytes: exact - 1,
                    ..limits()
                },
                None,
                reserved_id,
            ),
            Err(SourceDerivationUnavailable::LimitExceeded(
                SourceDerivationLimit::Bytes
            ))
        );

        let graph = InMemoryGraph::new();
        graph.entities.write().resolved_tree = ResolvedTree::from_artifacts([a]).unwrap();
        edge.src = GraphNodeId::Entity(EntityId::new());
        edge.evidence[0].token = Some("x".repeat(8_192));
        insert_relation(&graph, edge);
        let small = SourceDerivationLimits {
            max_bytes: 4_096,
            ..limits()
        };
        assert!(graph.source_derivation_facts(small, None).is_ok());
        assert_eq!(
            graph.source_derivation_facts_with_reserved_relation(small, None, reserved_id),
            Err(SourceDerivationUnavailable::LimitExceeded(
                SourceDerivationLimit::Bytes
            ))
        );
    }

    #[test]
    fn binding_uses_span_before_origin_and_accepts_only_canonical_digests() {
        let mut item = entity("origin.rs", 0xab);
        item.span = Some(SourceSpan {
            file: FilePathId::new("span.rs"),
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            start_col: 0,
            end_line: 1,
            end_col: 1,
        });
        let observed = SourceEntityBinding::from_entity(&item).unwrap();
        assert_eq!(observed.file, FilePathId::new("span.rs"));
        assert_eq!(observed.digest, Some(Hash256::from_bytes([0xab; 32])));
        for invalid in [
            serde_json::json!("AB".repeat(32)),
            serde_json::json!("not-a-digest"),
            serde_json::json!(null),
        ] {
            item.metadata.extra.insert("blob_hash".to_string(), invalid);
            assert_eq!(
                SourceEntityBinding::from_entity(&item).unwrap().digest,
                None
            );
        }
        item.metadata.extra.remove("blob_hash");
        assert_eq!(
            SourceEntityBinding::from_entity(&item).unwrap().digest,
            None
        );
        item.span = None;
        assert_eq!(
            SourceEntityBinding::from_entity(&item).unwrap().file,
            FilePathId::new("origin.rs")
        );
        item.file_origin = None;
        assert!(SourceEntityBinding::from_entity(&item).is_none());
    }

    #[test]
    fn inventory_retains_stale_and_out_of_tree_facts_without_large_payloads() {
        let graph = InMemoryGraph::new();
        let current = artifact(path("a.rs"), 2);
        let raw_path = RepoPath::from_bytes(b"asset-\xff.bin".to_vec()).unwrap();
        let binary = artifact(raw_path, 3);
        let mut stale = entity("a.rs", 1);
        stale.doc_summary = Some("large unrelated body".repeat(10_000));
        let held = entity("removed.rs", 4);
        {
            let mut ent = graph.entities.write();
            ent.resolved_tree =
                ResolvedTree::from_artifacts([current.clone(), binary.clone()]).unwrap();
            ent.entities.insert(stale.id, stale);
            ent.entities.insert(held.id, held);
            let file = FilePathId::new("removed.rs");
            ent.file_layouts.insert(
                file.clone(),
                FileLayout {
                    file_id: file,
                    parse_completeness: ParseCompleteness::Failed(
                        "large diagnostic".repeat(10_000),
                    ),
                    imports: ImportSection {
                        byte_range: 0..0,
                        items: Vec::new(),
                    },
                    regions: Vec::new(),
                },
            );
            let file = FilePathId::new("a.rs");
            ent.file_layouts.insert(
                file.clone(),
                FileLayout {
                    file_id: file.clone(),
                    parse_completeness: ParseCompleteness::Full,
                    imports: ImportSection {
                        byte_range: 0..0,
                        items: Vec::new(),
                    },
                    regions: Vec::new(),
                },
            );
            ent.opaque_artifacts.insert(
                file.clone(),
                OpaqueArtifact {
                    file_id: file,
                    content_hash: Hash256::from_bytes([9; 32]),
                    mime_type: None,
                    text_preview: Some("large opaque preview".repeat(10_000)),
                },
            );
        }
        let edge = relation(&current);
        insert_relation(&graph, edge.clone());
        let facts = graph
            .source_derivation_facts(
                SourceDerivationLimits {
                    max_bytes: 4_096,
                    ..limits()
                },
                None,
            )
            .unwrap();
        assert_eq!(facts.artifacts, vec![current, binary]);
        assert!(facts.entities.contains(&SourceEntityBinding {
            file: FilePathId::new("a.rs"),
            digest: Some(Hash256::from_bytes([1; 32]))
        }));
        assert!(facts
            .entities
            .iter()
            .any(|binding| binding.file.0 == "removed.rs"));
        assert_eq!(facts.layouts.len(), 2);
        assert!(facts.layouts.contains(&SourceLayoutFact {
            file: FilePathId::new("removed.rs"),
            full: false,
        }));
        assert!(facts.layouts.contains(&SourceLayoutFact {
            file: FilePathId::new("a.rs"),
            full: true,
        }));
        assert_eq!(
            facts.opaque,
            vec![SourceOpaqueFact {
                file: FilePathId::new("a.rs"),
                hash: Hash256::from_bytes([9; 32])
            }]
        );
        assert_eq!(facts.relations, vec![edge]);
    }

    #[test]
    fn exact_paths_include_missing_and_span_owned_evidence_but_exclude_other_files() {
        let graph = InMemoryGraph::new();
        let a = artifact(path("a.rs"), 1);
        let b = artifact(path("ab.rs"), 2);
        let mut span_owned = entity("ab.rs", 1);
        span_owned.span = Some(SourceSpan {
            file: FilePathId::new("a.rs"),
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            start_col: 0,
            end_line: 1,
            end_col: 1,
        });
        let outside = entity("gone.rs", 3);
        {
            let mut ent = graph.entities.write();
            ent.resolved_tree = ResolvedTree::from_artifacts([a.clone(), b.clone()]).unwrap();
            ent.entities.insert(span_owned.id, span_owned);
            ent.entities.insert(outside.id, outside);
            let other = entity("ab.rs", 2);
            ent.entities.insert(other.id, other);
            for name in ["a.rs", "ab.rs", "gone.rs"] {
                let file = FilePathId::new(name);
                ent.file_layouts.insert(
                    file.clone(),
                    FileLayout {
                        file_id: file.clone(),
                        parse_completeness: ParseCompleteness::Full,
                        imports: ImportSection {
                            byte_range: 0..0,
                            items: Vec::new(),
                        },
                        regions: Vec::new(),
                    },
                );
                ent.opaque_artifacts.insert(
                    file.clone(),
                    OpaqueArtifact {
                        file_id: file,
                        content_hash: Hash256::from_bytes([4; 32]),
                        mime_type: None,
                        text_preview: None,
                    },
                );
            }
        }
        let selected_edge = relation(&a);
        insert_relation(&graph, selected_edge.clone());
        insert_relation(&graph, relation(&b));
        let facts = graph
            .source_derivation_facts(
                limits(),
                Some(&[path("a.rs"), path("gone.rs"), path("a.rs")]),
            )
            .unwrap();
        assert_eq!(facts.artifacts, vec![a]);
        assert_eq!(facts.missing_paths, vec![path("gone.rs")]);
        assert_eq!(facts.entities.len(), 2);
        assert!(facts
            .entities
            .iter()
            .all(|binding| binding.file.0 != "ab.rs"));
        assert_eq!(facts.layouts.len(), 2);
        assert!(facts.layouts.iter().all(|fact| fact.file.0 != "ab.rs"));
        assert_eq!(facts.opaque.len(), 2);
        assert!(facts.opaque.iter().all(|fact| fact.file.0 != "ab.rs"));
        assert_eq!(facts.relations, vec![selected_edge]);
        assert_eq!(
            graph.source_derivation_facts(limits(), Some(&[])).unwrap(),
            SourceDerivationFacts::default()
        );
    }

    /// The daemon samples these facts after every source-derived query and
    /// turns a refusal into `derived_source_unproven` in the verdict. While a
    /// refusal could come from a writer overlapping the call or from a scan
    /// outliving a 25 ms clock on a loaded host, one of 75 repeated queries
    /// disclosed it in one run over an unchanged graph. A writer holding the
    /// lock four times longer than that old clock must only delay the call:
    /// the facts are the ones an uncontended call returns, taken after the
    /// writer left.
    #[test]
    fn an_in_flight_writer_delays_inspection_without_changing_its_facts() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        let graph = InMemoryGraph::new();
        let a = artifact(path("a.rs"), 1);
        {
            let mut ent = graph.entities.write();
            ent.resolved_tree = ResolvedTree::from_artifacts([a.clone()]).unwrap();
            let item = entity("a.rs", 1);
            ent.entities.insert(item.id, item);
        }
        let mut edge = relation(&a);
        edge.id = reserved_id(a.artifact_id);
        insert_relation(&graph, edge);
        insert_relation(&graph, relation(&a));
        let settled = graph
            .source_derivation_facts_with_reserved_relation(limits(), None, reserved_id)
            .unwrap();

        let released = AtomicBool::new(false);
        let (held, holding) = std::sync::mpsc::channel();
        let observed = std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                // The raw lock, not `entities_write`: this writer changes nothing,
                // so any difference below could only have come from timing.
                let guard = graph.entities.write();
                held.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(100));
                released.store(true, Ordering::SeqCst);
                drop(guard);
            });
            holding.recv().unwrap();
            let observed =
                graph.source_derivation_facts_with_reserved_relation(limits(), None, reserved_id);
            // Sampled before the join: only an inspection that waited for the
            // writer can return after the writer set this.
            let waited = released.load(Ordering::SeqCst);
            writer.join().unwrap();
            (observed, waited)
        });
        let (observed, waited) = observed;
        assert!(
            waited,
            "inspection must read after the writer leaves, not refuse beside it"
        );
        assert_eq!(observed, Ok(settled));
    }

    /// With no clock to give up on, the caps alone bound how long one
    /// inspection holds the entity read lock. This builds inventories up to
    /// them and records the uncontended call time, which is that hold. It is a
    /// measurement, not a timing assertion; run it with `--release --ignored`.
    #[test]
    #[ignore = "explicit diagnostic: records inspection lock hold up to the caps without asserting timing"]
    fn source_derivation_lock_hold_up_to_the_caps_diagnostic() {
        for (files, entities_per_file, artifact_relations_per_file) in [
            (1_024, 16, 3),
            (2_048, 16, 3),
            (4_096, 8, 2),
            (4_096, 16, 2),
            (4_096, 16, 3),
        ] {
            let graph = InMemoryGraph::new();
            let tree: Vec<_> = (0..files)
                .map(|i| artifact(path(&format!("src/file_{i}.rs")), (i % 251) as u8))
                .collect();
            {
                let mut ent = graph.entities.write();
                ent.resolved_tree = ResolvedTree::from_artifacts(tree.clone()).unwrap();
                for i in 0..files {
                    let name = format!("src/file_{i}.rs");
                    for _ in 0..entities_per_file {
                        let item = entity(&name, (i % 251) as u8);
                        ent.entities.insert(item.id, item);
                    }
                    let file = FilePathId::new(&name);
                    ent.file_layouts.insert(
                        file.clone(),
                        FileLayout {
                            file_id: file,
                            parse_completeness: ParseCompleteness::Full,
                            imports: ImportSection {
                                byte_range: 0..0,
                                items: Vec::new(),
                            },
                            regions: Vec::new(),
                        },
                    );
                }
            }
            for item in &tree {
                for _ in 0..artifact_relations_per_file {
                    insert_relation(&graph, relation(item));
                }
            }
            // One entity-owned edge per entity, so the adjacency walk also
            // passes the entity nodes it skips, as it does on a real graph.
            let owners: Vec<_> = graph.entities.read().entities.keys().copied().collect();
            for owner in owners {
                let mut edge = relation(&tree[0]);
                edge.src = GraphNodeId::Entity(owner);
                edge.dst = edge.src;
                insert_relation(&graph, edge);
            }
            let mut samples = Vec::new();
            let mut outcome = String::new();
            for _ in 0..21 {
                let started = Instant::now();
                let result = graph.source_derivation_facts_with_reserved_relation(
                    SourceDerivationLimits::default(),
                    None,
                    reserved_id,
                );
                samples.push(started.elapsed().as_micros());
                outcome = match result {
                    Ok(facts) => format!(
                        "facts: {} artifacts, {} entities, {} relations",
                        facts.artifacts.len(),
                        facts.entities.len(),
                        facts.relations.len()
                    ),
                    Err(error) => error.to_string(),
                };
            }
            samples.sort_unstable();
            println!(
                "source-derivation-lock-hold: {}",
                serde_json::json!({
                    "files": files,
                    "entities": graph.entity_count(),
                    "relations": graph.relation_count(),
                    "p50_us": samples[10],
                    "p95_us": samples[19],
                    "max_us": samples[20],
                    "outcome": outcome,
                })
            );
        }
    }

    #[test]
    fn record_caps_refuse_and_exact_path_scope_does_not_copy_unselected_artifacts() {
        let graph = InMemoryGraph::new();
        let a = artifact(path("a.rs"), 1);
        {
            let mut ent = graph.entities.write();
            ent.resolved_tree =
                ResolvedTree::from_artifacts([a.clone(), artifact(path("b.rs"), 2)]).unwrap();
        }
        let one = SourceDerivationLimits {
            max_artifacts: 1,
            ..limits()
        };
        assert_eq!(
            graph.source_derivation_facts(one, None),
            Err(SourceDerivationUnavailable::LimitExceeded(
                SourceDerivationLimit::Artifacts
            ))
        );
        assert_eq!(
            graph
                .source_derivation_facts(one, Some(&[path("a.rs")]))
                .unwrap()
                .artifacts,
            vec![a.clone()]
        );
        let item = entity("a.rs", 1);
        graph.entities.write().entities.insert(item.id, item);
        assert_eq!(
            graph.source_derivation_facts(
                SourceDerivationLimits {
                    max_entities: 0,
                    ..limits()
                },
                None
            ),
            Err(SourceDerivationUnavailable::LimitExceeded(
                SourceDerivationLimit::Entities
            ))
        );
        insert_relation(&graph, relation(&a));
        assert_eq!(
            graph.source_derivation_facts(
                SourceDerivationLimits {
                    max_relations: 0,
                    ..limits()
                },
                None
            ),
            Err(SourceDerivationUnavailable::LimitExceeded(
                SourceDerivationLimit::Relations
            ))
        );
    }

    #[test]
    fn byte_preflight_refuses_nested_evidence_and_oversized_paths_before_clone() {
        let a = artifact(path("a.rs"), 1);
        let edge = relation(&a);
        let mut budget = Budget {
            limits: limits(),
            bytes: 0,
        };
        budget.relation(&edge).unwrap();
        let exact = budget.bytes;
        let mut too_small = Budget {
            limits: SourceDerivationLimits {
                max_bytes: exact - 1,
                ..limits()
            },
            bytes: 0,
        };
        assert_eq!(
            too_small.relation(&edge),
            Err(SourceDerivationUnavailable::LimitExceeded(
                SourceDerivationLimit::Bytes
            ))
        );
        let graph = InMemoryGraph::new();
        graph.entities.write().resolved_tree = ResolvedTree::from_artifacts([a.clone()]).unwrap();
        let mut huge = edge;
        huge.evidence[0].token = Some("x".repeat(8_192));
        insert_relation(&graph, huge);
        assert_eq!(
            graph.source_derivation_facts(
                SourceDerivationLimits {
                    max_bytes: 4_096,
                    ..limits()
                },
                None
            ),
            Err(SourceDerivationUnavailable::LimitExceeded(
                SourceDerivationLimit::Bytes
            ))
        );
        let graph = InMemoryGraph::new();
        graph.entities.write().resolved_tree =
            ResolvedTree::from_artifacts([artifact(path(&"x".repeat(8_192)), 1)]).unwrap();
        assert_eq!(
            graph.source_derivation_facts(
                SourceDerivationLimits {
                    max_bytes: 4_096,
                    ..limits()
                },
                None
            ),
            Err(SourceDerivationUnavailable::LimitExceeded(
                SourceDerivationLimit::Bytes
            ))
        );
    }
}
