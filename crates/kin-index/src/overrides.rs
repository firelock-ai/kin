// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Which methods override a resolved call destination, read from the graph's
//! own `Overrides` edges.
//!
//! Python and C++ both let a base or mixin class declare a method that a
//! concrete subclass replaces, and the linker records that as a first-class
//! `Overrides` edge the moment it can resolve the base
//! (`kin-index/src/linker.rs`, `derive_override_relations`). That is different
//! from Go interface satisfaction ([`crate::dispatch`]): there the graph holds
//! no edge for "this concrete method implements that interface method" and
//! the module has to compute a structural guess at query time. Here the edge
//! already exists, so this module's job is only to read it back out for a
//! focal method — the same discipline [`crate::resolution`] uses for its own
//! marker, and the reason a `self`/`cls` call that reaches an overridden
//! destination is stamped [`crate::resolution::DISPATCH_CANDIDATE_CONFIDENCE`]
//! rather than a new resolution tier: the graph can already answer "what else
//! might this run" on demand.
//!
//! What this returns is accordingly a fact, not a candidate the way
//! [`crate::dispatch`]'s Go answers are: an `Overrides` edge is direct parser
//! evidence that a subclass replaces this exact method, so every row here is a
//! real alternative body a `self`/`cls` call at the destination could run.

use kin_model::{Entity, EntityId, GraphStore, RelationKind};

use crate::error::{IndexError, Result};

/// Field name an override-candidate list is published under on an
/// agent-facing response. Named to match the wire label the graph storage
/// layer already gives the reverse direction of an `Overrides` edge
/// (`overridden_by`) rather than inventing a second name for the same
/// relationship.
pub const OVERRIDDEN_BY_FIELD: &str = "overridden_by";

/// A method that replaces `focal` in some subclass, read off the graph's own
/// `Overrides` edges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverrideCandidate {
    /// The overriding method's entity id.
    pub entity_id: EntityId,
    /// That method's owner-qualified name (`Session.send`), for a reader to
    /// recognize without a second lookup.
    pub qualified_name: String,
}

/// Every method an `Overrides` edge names as replacing `focal`.
///
/// Empty when nothing overrides `focal`, which is the ordinary case for most
/// methods and is not itself informative. Unlike [`crate::dispatch`]'s Go
/// answers, that emptiness needs no separate "does the question even apply"
/// gate: an `Overrides` edge is direct parser evidence, not a structural guess,
/// so a focal with none simply has none, the same as an entity with no
/// callers.
///
/// Reads `focal`'s INCOMING relations — [`GraphStore::get_relations`] answers
/// a node's outgoing edges only, and the base is always on the incoming side
/// of `Overrides` — then keeps the ones whose destination is `focal` and whose
/// source resolves to a real entity. Sorted by qualified name and deduplicated
/// by id so a repeated query and a freshly rebuilt graph answer identically.
pub fn overriding_methods<G: GraphStore>(
    store: &G,
    focal: &Entity,
) -> Result<Vec<OverrideCandidate>> {
    let relations = store
        .get_all_relations_for_entity(&focal.id)
        .map_err(|error| IndexError::Graph(error.to_string()))?;
    let mut candidates = Vec::new();
    for relation in relations {
        if relation.kind != RelationKind::Overrides {
            continue;
        }
        if relation.dst.as_entity() != Some(focal.id) {
            continue;
        }
        let Some(src_id) = relation.src.as_entity() else {
            continue;
        };
        let Some(overrider) = store
            .get_entity(&src_id)
            .map_err(|error| IndexError::Graph(error.to_string()))?
        else {
            continue;
        };
        candidates.push(OverrideCandidate {
            entity_id: overrider.id,
            qualified_name: overrider.name.clone(),
        });
    }
    candidates.sort_by(|a, b| {
        a.qualified_name
            .cmp(&b.qualified_name)
            .then_with(|| a.entity_id.cmp(&b.entity_id))
    });
    candidates.dedup_by(|a, b| a.entity_id == b.entity_id);
    Ok(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_model::{
        EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId, FingerprintAlgorithm,
        GraphNodeId, Hash256, LanguageId, Relation, RelationId, RelationOrigin,
        SemanticFingerprint, Visibility,
    };

    fn test_fingerprint() -> SemanticFingerprint {
        let zero = Hash256::from_bytes([0u8; 32]);
        SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: zero,
            signature_hash: zero,
            behavior_hash: zero,
            equivalence_hash: zero,
            stability_score: 1.0,
        }
    }

    fn method(name: &str, file: &str) -> Entity {
        Entity {
            id: EntityId::from_content(file, name, "Method", 1),
            kind: EntityKind::Method,
            name: name.to_string(),
            language: LanguageId::Python,
            fingerprint: test_fingerprint(),
            file_origin: Some(FilePathId::new(file)),
            span: None,
            signature: name.to_string(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn overrides(child: EntityId, base: EntityId) -> Relation {
        Relation {
            id: RelationId::from_content("child", "base", "Overrides"),
            kind: RelationKind::Overrides,
            src: GraphNodeId::Entity(child),
            dst: GraphNodeId::Entity(base),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    #[test]
    fn a_method_nothing_overrides_has_no_candidates() {
        let store = InMemoryGraph::new();
        let stub = method("SessionRedirectMixin.send", "sessions.py");
        store.upsert_entity(&stub).expect("seed entity");

        let candidates = overriding_methods(&store, &stub).expect("read overrides");
        assert!(candidates.is_empty(), "{candidates:?}");
    }

    #[test]
    fn an_overridden_method_names_its_overrider() {
        let store = InMemoryGraph::new();
        let stub = method("SessionRedirectMixin.send", "sessions.py");
        let concrete = method("Session.send", "sessions.py");
        store.upsert_entity(&stub).expect("seed base");
        store.upsert_entity(&concrete).expect("seed override");
        store
            .upsert_relation(&overrides(concrete.id, stub.id))
            .expect("seed Overrides edge");

        let candidates = overriding_methods(&store, &stub).expect("read overrides");
        assert_eq!(
            candidates,
            vec![OverrideCandidate {
                entity_id: concrete.id,
                qualified_name: "Session.send".to_string(),
            }]
        );
    }

    #[test]
    fn a_repeated_edge_to_the_same_overrider_is_not_double_counted() {
        let store = InMemoryGraph::new();
        let stub = method("SessionRedirectMixin.send", "sessions.py");
        let concrete = method("Session.send", "sessions.py");
        store.upsert_entity(&stub).expect("seed base");
        store.upsert_entity(&concrete).expect("seed override");
        store
            .upsert_relation(&overrides(concrete.id, stub.id))
            .expect("seed Overrides edge");
        store
            .upsert_relation(&overrides(concrete.id, stub.id))
            .expect("seed the same edge again");

        let candidates = overriding_methods(&store, &stub).expect("read overrides");
        assert_eq!(candidates.len(), 1, "{candidates:?}");
    }

    #[test]
    fn the_overrider_side_of_the_edge_is_not_mistaken_for_a_candidate() {
        let store = InMemoryGraph::new();
        let stub = method("SessionRedirectMixin.send", "sessions.py");
        let concrete = method("Session.send", "sessions.py");
        store.upsert_entity(&stub).expect("seed base");
        store.upsert_entity(&concrete).expect("seed override");
        store
            .upsert_relation(&overrides(concrete.id, stub.id))
            .expect("seed Overrides edge");

        // Asking from the OVERRIDER's own perspective must not echo itself
        // back: `Session.send` overrides something, it is not overridden by
        // anything in this fixture.
        let candidates = overriding_methods(&store, &concrete).expect("read overrides");
        assert!(candidates.is_empty(), "{candidates:?}");
    }
}
