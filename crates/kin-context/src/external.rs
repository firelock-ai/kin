// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Calls an entity makes to symbols outside the repository.
//!
//! A language server that resolves a call to a declaration in a package the
//! repository depends on proves an edge from the caller to an
//! [`ExternalReference`] node, not to an entity. Such an edge is not among an
//! entity's entity-to-entity relations, so a reader that lists an entity's
//! calls from those alone never names `Array.map` or `json.dumps` at all.
//! Every reader that lists calls reads these edges here, typed, and renders
//! them beside its entity rows.
//!
//! Nothing here reads a file. The external declaration's location is not
//! recorded anywhere in the graph, and the node's identity (package, version
//! and descriptor chain) is the whole of what the repository knows about it.

use std::collections::HashMap;

use kin_model::{
    EntityId, ExternalReference, ExternalReferenceId, ExternalSymbol, GraphNodeId, GraphStore,
    ProofContext, Relation, RelationKind, RelationOrigin, ResolutionRecord, ResolutionRecordId,
    SourceSpan,
};

use crate::error::{ContextError, Result};

/// The proof a resolver recorded for one edge to an external symbol.
#[derive(Debug, Clone, PartialEq)]
pub struct ExternalEdgeProof {
    /// The proof context the edge's evidence names.
    pub context: ResolutionRecordId,
    /// That context's record, or `None` when the graph does not hold it.
    pub record: Option<ProofContext>,
    /// The rule that produced the evidence: `lsp_definition`,
    /// `lsp_definition_alias` or `lsp_call_hierarchy`.
    pub rule: Option<String>,
}

/// One edge between a repository entity and a symbol outside the repository.
#[derive(Debug, Clone, PartialEq)]
pub struct ExternalEdge {
    /// The edge as the graph holds it.
    pub relation: Relation,
    /// The entity at the repository end.
    pub entity: EntityId,
    /// The symbol at the other end.
    pub target: ExternalReferenceId,
    /// The symbol's record. A store validates both ends of an edge, so this is
    /// `None` only for a store that lost the node after admitting the edge.
    pub reference: Option<ExternalReference>,
    /// The first proof context the edge's evidence names, when one does.
    pub proof: Option<ExternalEdgeProof>,
}

impl ExternalEdge {
    /// The typed view of the target, when it is recorded in the SCIP namespace.
    pub fn symbol(&self) -> Option<ExternalSymbol> {
        self.reference
            .as_ref()
            .and_then(ExternalSymbol::from_reference)
    }

    /// The target as a reader spells it: `Array.map` for a SCIP symbol, the
    /// recorded selector for any other namespace.
    pub fn display_name(&self) -> String {
        match (self.symbol(), self.reference.as_ref()) {
            (Some(symbol), _) => symbol.display_name(),
            (None, Some(reference)) => reference.symbol.clone(),
            (None, None) => String::new(),
        }
    }

    /// Whether a language server proved this edge.
    pub fn is_proven(&self) -> bool {
        self.relation.origin == RelationOrigin::Lsp
    }

    /// Every site the edge's evidence records, in source order, each once.
    pub fn sites(&self) -> Vec<&SourceSpan> {
        let mut sites: Vec<&SourceSpan> = self
            .relation
            .evidence
            .iter()
            .filter_map(|evidence| evidence.source_span.as_ref())
            .collect();
        sites.sort_by_key(|span| (span.start_byte, span.end_byte));
        sites.dedup_by_key(|span| (span.start_byte, span.end_byte));
        sites
    }
}

/// Reads one graph's external edges with the proof contexts they name, looking
/// each node and context up once.
pub struct ExternalEdgeReader<'a, G: GraphStore> {
    graph: &'a G,
    references: HashMap<ExternalReferenceId, Option<ExternalReference>>,
    contexts: HashMap<ResolutionRecordId, Option<ProofContext>>,
}

impl<'a, G: GraphStore> ExternalEdgeReader<'a, G> {
    pub fn new(graph: &'a G) -> Self {
        Self {
            graph,
            references: HashMap::new(),
            contexts: HashMap::new(),
        }
    }

    /// The external symbol recorded under `id`.
    pub fn reference(&mut self, id: &ExternalReferenceId) -> Result<Option<ExternalReference>> {
        if let Some(held) = self.references.get(id) {
            return Ok(held.clone());
        }
        let reference = self
            .graph
            .lookup_external_reference(id)
            .map_err(|error| ContextError::Graph(error.to_string()))?;
        self.references.insert(*id, reference.clone());
        Ok(reference)
    }

    fn proof_context(&mut self, id: &ResolutionRecordId) -> Result<Option<ProofContext>> {
        if let Some(held) = self.contexts.get(id) {
            return Ok(held.clone());
        }
        let record = match self
            .graph
            .lookup_resolution_record(id)
            .map_err(|error| ContextError::Graph(error.to_string()))?
        {
            Some(ResolutionRecord::ProofContext(context)) => Some(context),
            _ => None,
        };
        self.contexts.insert(*id, record.clone());
        Ok(record)
    }

    /// Type one relation, or `None` when it does not join an entity and an
    /// external symbol.
    pub fn edge(&mut self, relation: Relation) -> Result<Option<ExternalEdge>> {
        let (entity, target) = match (relation.src, relation.dst) {
            (GraphNodeId::Entity(entity), GraphNodeId::ExternalReference(target))
            | (GraphNodeId::ExternalReference(target), GraphNodeId::Entity(entity)) => {
                (entity, target)
            }
            _ => return Ok(None),
        };
        let reference = self.reference(&target)?;
        let named = relation.evidence.iter().find_map(|evidence| {
            let context = ResolutionRecordId::from_context_token(evidence.token.as_deref()?)?;
            Some((context, evidence.parser_rule.clone()))
        });
        let proof = match named {
            Some((context, rule)) => Some(ExternalEdgeProof {
                context,
                record: self.proof_context(&context)?,
                rule,
            }),
            None => None,
        };
        Ok(Some(ExternalEdge {
            relation,
            entity,
            target,
            reference,
            proof,
        }))
    }

    /// Every edge from `entity` to an external symbol, of the given kinds, or
    /// of every kind when `kinds` is `None`. Ordered by the target's display
    /// name, then its identity.
    pub fn outgoing(
        &mut self,
        entity: &EntityId,
        kinds: Option<&[RelationKind]>,
    ) -> Result<Vec<ExternalEdge>> {
        let relations = self
            .graph
            .get_external_relations_for_entity(entity)
            .map_err(|error| ContextError::Graph(error.to_string()))?;
        let mut edges = Vec::new();
        for relation in relations {
            if relation.src != GraphNodeId::Entity(*entity)
                || kinds.is_some_and(|kinds| !kinds.contains(&relation.kind))
            {
                continue;
            }
            if let Some(edge) = self.edge(relation)? {
                edges.push(edge);
            }
        }
        sort_edges(&mut edges);
        Ok(edges)
    }

    /// Every edge from a repository entity into the external symbol `id`, of
    /// the given kinds. Ordered by the entity's identity, then the kind.
    pub fn incoming(
        &mut self,
        id: &ExternalReferenceId,
        kinds: &[RelationKind],
    ) -> Result<Vec<ExternalEdge>> {
        let relations = self
            .graph
            .relations_of_external_reference(id)
            .map_err(|error| ContextError::Graph(error.to_string()))?;
        let mut edges = Vec::new();
        for relation in relations {
            if relation.dst != GraphNodeId::ExternalReference(*id)
                || relation.src.as_entity().is_none()
                || !kinds.contains(&relation.kind)
            {
                continue;
            }
            if let Some(edge) = self.edge(relation)? {
                edges.push(edge);
            }
        }
        edges.sort_by(|left, right| {
            left.entity
                .cmp(&right.entity)
                .then_with(|| {
                    format!("{:?}", left.relation.kind).cmp(&format!("{:?}", right.relation.kind))
                })
                .then_with(|| left.relation.id.0.cmp(&right.relation.id.0))
        });
        Ok(edges)
    }
}

fn sort_edges(edges: &mut [ExternalEdge]) {
    edges.sort_by(|left, right| {
        left.display_name()
            .cmp(&right.display_name())
            .then_with(|| left.target.cmp(&right.target))
            .then_with(|| left.relation.id.0.cmp(&right.relation.id.0))
    });
}

/// Every call the focal makes to a symbol outside the repository.
///
/// The dependency section of a pack is built from entity-to-entity edges, and
/// an external call has no entity at its far end, so a pack that listed the
/// focal's calls from that section alone reported a function whose every call
/// lands in a dependency as calling nothing. This is the rest of that list.
pub fn focal_external_calls<G: GraphStore>(
    graph: &G,
    focal: &EntityId,
) -> Result<Vec<ExternalEdge>> {
    ExternalEdgeReader::new(graph).outgoing(focal, Some(&[RelationKind::Calls]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::*;

    fn entity(name: &str) -> Entity {
        let zero = Hash256::from_bytes([0; 32]);
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::TypeScript,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: zero,
                signature_hash: zero,
                behavior_hash: zero,
                equivalence_hash: zero,
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("function {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn array_map() -> ExternalSymbol {
        ExternalSymbol::new(
            ScipPackage::new("npm", "typescript", "5.6.3").unwrap(),
            vec![
                ScipDescriptor::namespace("lib.es5.d.ts"),
                ScipDescriptor::type_("Array"),
                ScipDescriptor::method("map"),
            ],
        )
        .unwrap()
    }

    fn context() -> ProofContext {
        ProofContext {
            language: LanguageId::TypeScript,
            resolver: "lsp:tsserver".to_string(),
            resolver_version: "5.6.3".to_string(),
            configuration_hash: Hash256::from_bytes([1; 32]),
            environment_hash: Hash256::from_bytes([2; 32]),
            environment_summary: "typescript 5.6.3".to_string(),
        }
    }

    #[test]
    fn a_proven_external_call_is_read_with_its_symbol_and_proof() {
        let graph = kin_db::InMemoryGraph::new();
        let caller = entity("render");
        let callee = entity("helper");
        let node = array_map().to_reference().unwrap();
        let context = ResolutionRecord::ProofContext(context());
        let token = context.id().context_token();
        let src = GraphNodeId::Entity(caller.id);
        let dst = GraphNodeId::ExternalReference(node.id);
        let external = Relation {
            id: RelationId::resolver(RelationKind::Calls, &src, &dst),
            kind: RelationKind::Calls,
            src,
            dst,
            confidence: 1.0,
            origin: RelationOrigin::Lsp,
            created_in: None,
            import_source: None,
            evidence: vec![RelationEvidence {
                parser_rule: Some("lsp_definition".to_string()),
                token: Some(token),
                occurrence_count: 1,
                ..RelationEvidence::default()
            }],
        };
        let internal = Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src,
            dst: GraphNodeId::Entity(callee.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![
                    EntityDelta::Added {
                        new: caller.clone(),
                    },
                    EntityDelta::Added { new: callee },
                ],
                relation_deltas: vec![
                    RelationDelta::Added {
                        new: external.clone(),
                    },
                    RelationDelta::Added { new: internal },
                ],
                external_reference_deltas: vec![ExternalReferenceDelta::Added {
                    new: node.clone(),
                }],
                resolution_record_deltas: vec![ResolutionRecordDelta::Added {
                    new: context.clone(),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();

        let calls = focal_external_calls(&graph, &caller.id).unwrap();
        assert_eq!(calls.len(), 1, "the entity-to-entity call is not external");
        let call = &calls[0];
        assert_eq!(call.target, node.id);
        assert_eq!(call.entity, caller.id);
        assert_eq!(call.display_name(), "Array.map");
        assert!(call.is_proven());
        let proof = call.proof.as_ref().unwrap();
        assert_eq!(proof.context, context.id());
        assert_eq!(proof.rule.as_deref(), Some("lsp_definition"));
        assert_eq!(
            proof.record.as_ref().map(|record| record.resolver.as_str()),
            Some("lsp:tsserver")
        );

        let callers = ExternalEdgeReader::new(&graph)
            .incoming(&node.id, &[RelationKind::Calls])
            .unwrap();
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0].entity, caller.id);
        assert!(ExternalEdgeReader::new(&graph)
            .incoming(&node.id, &[RelationKind::Imports])
            .unwrap()
            .is_empty());
    }
}
