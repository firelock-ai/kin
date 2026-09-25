// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Project semantic relation authority from the same graph snapshot as its endpoints.
//!
//! Older stores can contain inferred members with parser-certain edges. Reading
//! those edges must not upgrade a candidate while waiting for re-admission. They
//! can also hold a Go method's language-server reference sites recorded before
//! each was proven, which must not confirm a caller while waiting for the
//! enrichment to re-derive them. This view leaves the persisted evidence and
//! history intact; it changes only the returned copies used for semantic
//! answers, counts and rankings.

use std::collections::HashMap;

use kin_model::{Entity, EntityId, EntityStore, Relation, RelationKind, RepoPath};

/// Apply the derived-member trust floor before filtering, composing or scoring edges.
/// Endpoint reads are cached within this batch and errors propagate to the caller.
pub fn project_relations_for_read<S: EntityStore + ?Sized>(
    store: &S,
    relations: &mut Vec<Relation>,
) -> Result<(), S::Error> {
    let mut entities: HashMap<EntityId, Option<Entity>> = HashMap::new();
    for relation in relations.iter() {
        for id in [relation.src.as_entity(), relation.dst.as_entity()]
            .into_iter()
            .flatten()
        {
            if let std::collections::hash_map::Entry::Vacant(entry) = entities.entry(id) {
                entry.insert(store.get_entity(&id)?);
            }
        }
    }
    let mut projected = Vec::with_capacity(relations.len());
    for mut relation in relations.drain(..) {
        let endpoint = |id: Option<EntityId>| id.and_then(|id| entities.get(&id)?.as_ref());
        let source = endpoint(relation.src.as_entity());
        let destination = endpoint(relation.dst.as_entity());
        if !read_behind_widened_method_references(&mut relation, destination) {
            continue;
        }
        let derived = source.is_some_and(kin_model::is_derived_member)
            || destination.is_some_and(kin_model::is_derived_member)
            || crate::resolution::is_derived_member_candidate(&relation);
        if !derived {
            projected.push(relation);
            continue;
        }
        if relation.src.as_entity().is_some() && relation.dst.as_entity().is_some() {
            if project_entity_relation_for_read(&mut relation, true) {
                projected.push(relation);
            }
            continue;
        }
        // A generator edge proves its source site, not runtime member membership.
        // Preserve that distinct authority only when the recorded graph artifact,
        // current source digest and exact generator site agree.
        let mut valid_generator = false;
        if relation.kind == RelationKind::DerivedFrom {
            if let Some(entity) = source {
                if let Ok(Some(derivation)) = kin_model::entity_derivation(entity) {
                    if let Ok(path) = RepoPath::from_utf8(derivation.generator.file.0.clone()) {
                        if let (Some(artifact), Some(kin_model::TreeEntry::Blob { hash, .. })) = (
                            store.artifact_id_at_path(&path),
                            store.get_tree_entry(&derivation.generator.file)?,
                        ) {
                            valid_generator = kin_model::derivation::generator_relation_matches(
                                entity,
                                &relation,
                                artifact,
                                &hash.to_string(),
                            );
                        }
                    }
                }
            }
        }
        if !valid_generator {
            crate::resolution::limit_derived_relation(&mut relation);
        }
        projected.push(relation);
    }
    *relations = projected;
    Ok(())
}

/// Take a Go method's reference sites that were never proven as no evidence,
/// and say whether anything is left of the edge.
///
/// gopls answers a method's references with those of every method related to
/// it through interface satisfaction. Builds before the site-by-site proof
/// recorded that answer as it came, under [`kin_model::LSP_REFERENCES_RULE`], so
/// a store they enriched says a call on a `ghrepo.Interface` value is a
/// type-resolved reference to `Repository.RepoOwner`, and a direct call of
/// `Repository.RepoOwner` one to `Interface.RepoOwner`. Released builds wrote the
/// second shape for every Go interface method, and nothing they left behind is
/// ever removed: the enrichment write only adds, and a re-sweep's answer is
/// merged into the edge it already holds.
///
/// Those records are read as absent rather than rewritten, the same way this
/// view reads a derived member's legacy edges, so the store and its history stay
/// exactly as written and every semantic reader sees the same answer. What
/// replaces them is the enrichment's own re-derivation: a store whose Go files
/// were enriched before the proof has them swept again, and the proven sites
/// arrive under [`kin_model::LSP_PROVEN_METHOD_REFERENCES_RULE`]. Until then a
/// Go method's language-server references read as the proven records alone,
/// which can be none, while the parser's edges and the language server's call
/// hierarchy, whose outgoing calls were never widened, still answer.
///
/// Only a `References` edge from the language server into a Go method is read
/// this way, because only that answer was widened. An edge left with no
/// evidence at all by this is dropped from the view; one with a proven or
/// other record keeps those.
fn read_behind_widened_method_references(
    relation: &mut Relation,
    destination: Option<&Entity>,
) -> bool {
    if relation.kind != RelationKind::References
        || relation.origin != kin_model::RelationOrigin::Lsp
    {
        return true;
    }
    let Some(destination) = destination else {
        return true;
    };
    if destination.kind != kin_model::EntityKind::Method
        || destination.language != kin_model::LanguageId::Go
    {
        return true;
    }
    let held = relation.evidence.len();
    relation
        .evidence
        .retain(|evidence| evidence.parser_rule.as_deref() != Some(kin_model::LSP_REFERENCES_RULE));
    relation.evidence.len() == held || !relation.evidence.is_empty()
}

/// Apply the same trust floor to entity-only adjacency from a historical view.
/// The caller supplies endpoint classification from that ref, including removed
/// endpoint tombstones. Artifact provenance requires the separate validation above.
pub fn project_entity_relation_for_read(relation: &mut Relation, derived_endpoint: bool) -> bool {
    if (!derived_endpoint && !crate::resolution::is_derived_member_candidate(relation))
        || relation.src.as_entity().is_none()
        || relation.dst.as_entity().is_none()
    {
        return true;
    }
    if relation.kind == RelationKind::Overrides {
        return false;
    }
    crate::resolution::limit_derived_relation(relation);
    true
}

/// Read entity relations with endpoint authority applied before any consumer logic.
pub fn relations_for_read<S: EntityStore + ?Sized>(
    store: &S,
    id: &EntityId,
) -> Result<Vec<Relation>, S::Error> {
    let mut relations = store.get_all_relations_for_entity(id)?;
    project_relations_for_read(store, &mut relations)?;
    Ok(relations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_model::{
        EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm, GraphNodeId,
        Hash256, LanguageId, RelationEvidence, RelationId, RelationOrigin, SemanticFingerprint,
        SourceSpan, Visibility, LSP_PROVEN_METHOD_REFERENCES_RULE, LSP_REFERENCES_RULE,
    };

    fn entity(language: LanguageId, kind: EntityKind, name: &str, file: &str) -> Entity {
        let zero = Hash256::from_bytes([0u8; 32]);
        Entity {
            id: EntityId::from_content(file, name, &format!("{kind:?}"), 1),
            kind,
            name: name.to_string(),
            language,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: zero,
                signature_hash: zero,
                behavior_hash: zero,
                equivalence_hash: zero,
                stability_score: 1.0,
            },
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

    fn site(rule: &str, line: u32) -> RelationEvidence {
        RelationEvidence {
            source_span: Some(SourceSpan {
                file: FilePathId::new("pkg/cmd/pr/create/create.go"),
                start_byte: 0,
                end_byte: 1,
                start_line: line,
                start_col: 0,
                end_line: line,
                end_col: 1,
            }),
            parser_rule: Some(rule.to_string()),
            occurrence_count: 1,
            ..RelationEvidence::default()
        }
    }

    fn language_server_edge(
        src: &Entity,
        dst: &Entity,
        kind: RelationKind,
        evidence: Vec<RelationEvidence>,
    ) -> Relation {
        Relation {
            id: RelationId::new(),
            kind,
            src: GraphNodeId::Entity(src.id),
            dst: GraphNodeId::Entity(dst.id),
            confidence: 0.95,
            origin: RelationOrigin::Lsp,
            created_in: None,
            import_source: None,
            evidence,
        }
    }

    fn rules(relations: &[Relation], dst: &Entity) -> Vec<Vec<String>> {
        relations
            .iter()
            .filter(|relation| relation.dst == GraphNodeId::Entity(dst.id))
            .map(|relation| {
                relation
                    .evidence
                    .iter()
                    .filter_map(|evidence| evidence.parser_rule.clone())
                    .collect()
            })
            .collect()
    }

    /// A store enriched before a Go method's sites were proven holds the
    /// widened answer under the plain rule. It reads as no evidence there, and
    /// the proven sites a re-derivation adds to the same edge read in its
    /// place; every other destination keeps its records.
    #[test]
    fn a_go_methods_unproven_reference_sites_read_behind() {
        let store = InMemoryGraph::new();
        let caller = entity(
            LanguageId::Go,
            EntityKind::Function,
            "NewCreateContext",
            "pkg/cmd/pr/create/create.go",
        );
        let interface = entity(
            LanguageId::Go,
            EntityKind::Method,
            "Interface.RepoOwner",
            "internal/ghrepo/repo.go",
        );
        let concrete = entity(
            LanguageId::Go,
            EntityKind::Method,
            "Repository.RepoOwner",
            "api/queries_repo.go",
        );
        let function = entity(
            LanguageId::Go,
            EntityKind::Function,
            "FindByRepo",
            "context/remote.go",
        );
        let python = entity(
            LanguageId::Python,
            EntityKind::Method,
            "HTTPAdapter.send",
            "src/requests/adapters.py",
        );
        for e in [&caller, &interface, &concrete, &function, &python] {
            store.upsert_entity(e).unwrap();
        }
        // What a released build left: the interface method's widened answer.
        store
            .upsert_relation(&language_server_edge(
                &caller,
                &interface,
                RelationKind::References,
                vec![
                    site(LSP_REFERENCES_RULE, 648),
                    site(LSP_REFERENCES_RULE, 677),
                ],
            ))
            .unwrap();
        // Re-derived since: the widened records beside the proven one.
        store
            .upsert_relation(&language_server_edge(
                &caller,
                &concrete,
                RelationKind::References,
                vec![
                    site(LSP_REFERENCES_RULE, 648),
                    site(LSP_PROVEN_METHOD_REFERENCES_RULE, 677),
                ],
            ))
            .unwrap();
        // Destinations whose answers were never widened keep their records.
        for dst in [&function, &python] {
            store
                .upsert_relation(&language_server_edge(
                    &caller,
                    dst,
                    RelationKind::References,
                    vec![site(LSP_REFERENCES_RULE, 700)],
                ))
                .unwrap();
        }
        // So does the call hierarchy, whose outgoing calls were never widened.
        store
            .upsert_relation(&language_server_edge(
                &caller,
                &interface,
                RelationKind::Calls,
                vec![site("lsp_call_hierarchy", 648)],
            ))
            .unwrap();

        let read = relations_for_read(&store, &caller.id).unwrap();
        assert_eq!(
            rules(&read, &interface),
            vec![vec!["lsp_call_hierarchy".to_string()]],
            "the widened References edge reads as absent; the call edge stays: {read:?}"
        );
        assert_eq!(
            rules(&read, &concrete),
            vec![vec![LSP_PROVEN_METHOD_REFERENCES_RULE.to_string()]],
            "the proven site reads, the widened one beside it does not: {read:?}"
        );
        for dst in [&function, &python] {
            assert_eq!(
                rules(&read, dst),
                vec![vec![LSP_REFERENCES_RULE.to_string()]],
                "{}: {read:?}",
                dst.name
            );
        }

        // The store itself is untouched: this is a view.
        let raw = store.get_all_relations_for_entity(&caller.id).unwrap();
        assert_eq!(
            rules(&raw, &interface).concat().len(),
            3,
            "the persisted records are exactly as written: {raw:?}"
        );
    }
}
