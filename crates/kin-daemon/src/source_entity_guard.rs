// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Preserve source declarations while reparsing an entity body or rename.

use kin_model::{EntityDelta, EntityStore, FilePathId, Relation, TransactionDelta};

/// Entity kinds that live inside a type and are named after it (`Owner.Member`).
fn is_member_kind(kind: kin_model::EntityKind) -> bool {
    matches!(
        kind,
        kin_model::EntityKind::Field
            | kin_model::EntityKind::Method
            | kin_model::EntityKind::EnumVariant
    )
}

/// Entity kinds that own members declared inside their own source span.
fn is_member_owner_kind(kind: kin_model::EntityKind) -> bool {
    matches!(
        kind,
        kin_model::EntityKind::Class
            | kin_model::EntityKind::Interface
            | kin_model::EntityKind::TraitDef
            | kin_model::EntityKind::EnumDef
    )
}

fn span_contains(
    outer: Option<&kin_model::SourceSpan>,
    inner: Option<&kin_model::SourceSpan>,
) -> bool {
    match (outer, inner) {
        (Some(outer), Some(inner)) => {
            outer.file == inner.file
                && outer.start_byte <= inner.start_byte
                && inner.end_byte <= outer.end_byte
        }
        _ => false,
    }
}

/// Whether `member` is a member of `owner`: a member kind, named `Owner.Name`,
/// inside the owner's span, in the edited file.
fn is_member_of(member: &kin_model::Entity, owner: &kin_model::Entity, file: &FilePathId) -> bool {
    is_member_kind(member.kind)
        && is_member_owner_kind(owner.kind)
        && member.file_origin.as_ref() == Some(file)
        && member
            .name
            .strip_prefix(owner.name.as_str())
            .and_then(|rest| rest.strip_prefix('.'))
            .is_some_and(|rest| !rest.is_empty() && !rest.contains('.'))
        && span_contains(owner.span.as_ref(), member.span.as_ref())
}

/// [`first_unsupported_entity_change`] for an edit of the entities in `edited`.
///
/// Editing a struct, interface, trait or enum is how its members change, so a
/// member nested inside an edited owner may appear (inside the owner's new
/// span) or disappear (from inside its old span) with the edit. Every other
/// creation or removal is still refused, so an edit can never add or drop a
/// declaration beside the one it names.
pub(crate) fn first_unsupported_entity_change_for_edit<'a, G: EntityStore>(
    delta: &'a TransactionDelta,
    graph: &G,
    source_file: &FilePathId,
    edited: &[kin_model::EntityId],
) -> Result<Option<&'a EntityDelta>, G::Error> {
    let mut owners_before = Vec::new();
    let mut owners_after = Vec::new();
    for id in edited {
        if let Some(before) = graph.get_entity(id)? {
            owners_before.push(before);
        }
        if let Some(after) = delta
            .entity_deltas
            .iter()
            .find(|change| change.target_id() == *id)
            .and_then(EntityDelta::new_state)
        {
            owners_after.push(after.clone());
        }
    }
    for change in &delta.entity_deltas {
        let member = match change {
            EntityDelta::Added { new } => {
                graph.get_entity(&new.id)?.is_none()
                    && owners_after
                        .iter()
                        .any(|owner| is_member_of(new, owner, source_file))
            }
            EntityDelta::Removed { old } => owners_before
                .iter()
                .any(|owner| is_member_of(old, owner, source_file)),
            EntityDelta::Modified { .. } => false,
        };
        if !member && change_is_unsupported(change, delta, graph, source_file)? {
            return Ok(Some(change));
        }
    }
    Ok(None)
}

/// External import targets have no source declaration. A newly admitted target
/// is allowed only when a resulting canonical edge in this same transaction
/// constructs exactly that entity. The reconciler owns the parsed occurrence
/// proof; this boundary checks the entity it proposes before publishing it.
pub(crate) fn first_unsupported_entity_change<'a, G: EntityStore>(
    delta: &'a TransactionDelta,
    graph: &G,
    source_file: &FilePathId,
) -> Result<Option<&'a EntityDelta>, G::Error> {
    for change in &delta.entity_deltas {
        if change_is_unsupported(change, delta, graph, source_file)? {
            return Ok(Some(change));
        }
    }
    Ok(None)
}

fn change_is_unsupported<G: EntityStore>(
    change: &EntityDelta,
    delta: &TransactionDelta,
    graph: &G,
    source_file: &FilePathId,
) -> Result<bool, G::Error> {
    match change {
        EntityDelta::Modified { .. } => Ok(false),
        EntityDelta::Removed { .. } => Ok(true),
        EntityDelta::Added { new } => {
            if graph.get_entity(&new.id)?.is_some() {
                return Ok(true);
            }
            for relation in delta.relation_deltas.iter().filter_map(|d| d.new_state()) {
                if relation.dst.as_entity() == Some(new.id)
                    && admitted_external_relation(relation, delta, graph, source_file)?
                {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }
}

/// Check only relations emitted by the reconciler for this exact parsed file.
/// A held target retains its original language and commit provenance; a new
/// target must be the unmodified factory result in this same transaction.
pub(crate) fn admitted_external_relation<G: EntityStore>(
    relation: &Relation,
    delta: &TransactionDelta,
    graph: &G,
    source_file: &FilePathId,
) -> Result<bool, G::Error> {
    if !kin_index::is_external_import_placeholder(relation) {
        return Ok(false);
    }
    let (Some(source_id), Some(target_id)) = (relation.src.as_entity(), relation.dst.as_entity())
    else {
        return Ok(false);
    };
    let source = match delta
        .entity_deltas
        .iter()
        .find(|entity| entity.target_id() == source_id)
    {
        Some(pending) => pending.new_state().cloned(),
        None => graph.get_entity(&source_id)?,
    };
    let Some(source) = source
        .filter(|source| source.file_origin.as_ref() == Some(source_file) && source.span.is_some())
    else {
        return Ok(false);
    };
    let Some(mut expected) = kin_index::placeholder_target_entity(relation, source.language) else {
        return Ok(false);
    };
    match delta
        .entity_deltas
        .iter()
        .find(|entity| entity.target_id() == target_id)
    {
        Some(EntityDelta::Added { new }) => {
            Ok(graph.get_entity(&target_id)?.is_none() && expected == *new)
        }
        Some(_) => Ok(false),
        None => {
            let Some(held) = graph.get_entity(&target_id)? else {
                return Ok(false);
            };
            expected.language = held.language;
            expected.created_in = held.created_in;
            Ok(expected == held)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{Entity, FilePathId, LanguageId, Relation, RelationDelta};

    fn fixture() -> (kin_db::InMemoryGraph, Entity, Entity, Relation) {
        let bytes =
            b"const remote = require('external-one');\nfunction run() { return remote(); }\n";
        let file = FilePathId::new("src/app.js");
        let kin_index::IndexedAny::EntitySource(indexed) = kin_index::IndexPipeline::new()
            .index_any_content(&file, bytes, kin_blobs::digest(bytes))
            .unwrap()
        else {
            panic!("fixture must be supported source");
        };
        let source = indexed
            .entities
            .iter()
            .find(|e| e.name == "run")
            .unwrap()
            .clone();
        let relations = kin_index::link_cross_file(
            &[kin_index::FileParseData {
                file_path: file.0.clone(),
                entities: indexed.entities.clone(),
                relations: indexed.extracted_relations,
                imports: indexed.imports,
            }],
            &kin_index::linker::ArtifactIdentityMap::from([(file.0, kin_model::ArtifactId::new())]),
        )
        .unwrap();
        let relation = relations
            .into_iter()
            .find(kin_index::is_external_import_placeholder)
            .unwrap();
        let target = kin_index::placeholder_target_entity(&relation, source.language).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        graph.upsert_entity(&source).unwrap();
        (graph, source, target, relation)
    }

    fn transaction(target: Entity, relation: Relation) -> TransactionDelta {
        TransactionDelta {
            entity_deltas: vec![EntityDelta::Added { new: target }],
            relation_deltas: vec![RelationDelta::Added { new: relation }],
            ..Default::default()
        }
    }

    #[test]
    fn source_entity_guard_accepts_only_the_resulting_factory_target() {
        let (graph, source, target, relation) = fixture();
        let mut delta = transaction(target.clone(), relation.clone());
        assert!(
            first_unsupported_entity_change(&delta, &graph, &FilePathId::new("src/app.js"))
                .unwrap()
                .is_none()
        );
        delta.relation_deltas = vec![RelationDelta::Modified {
            old: relation.clone(),
            new: relation.clone(),
        }];
        assert!(
            first_unsupported_entity_change(&delta, &graph, &FilePathId::new("src/app.js"))
                .unwrap()
                .is_none()
        );

        // The pending source language, not its previous graph state, owns the factory input.
        let mut updated = source.clone();
        updated.language = LanguageId::TypeScript;
        delta.entity_deltas = vec![
            EntityDelta::Added {
                new: kin_index::placeholder_target_entity(&relation, updated.language).unwrap(),
            },
            EntityDelta::Modified {
                old: source,
                new: updated,
            },
        ];
        assert!(
            first_unsupported_entity_change(&delta, &graph, &FilePathId::new("src/app.js"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn source_entity_guard_refuses_unbacked_or_noncanonical_targets() {
        let (graph, source, target, relation) = fixture();
        let valid = transaction(target.clone(), relation.clone());
        let mut cases = Vec::new();
        let mut delta = valid.clone();
        delta.relation_deltas.clear();
        cases.push(("no relation", delta));
        let mut delta = valid.clone();
        delta.relation_deltas = vec![RelationDelta::Removed {
            old: relation.clone(),
        }];
        cases.push(("only old relation", delta));
        let mut malformed = relation.clone();
        malformed.evidence[0].occurrence_count = 0;
        cases.push(("malformed evidence", transaction(target.clone(), malformed)));
        for (label, entity) in [
            ("language", {
                let mut e = target.clone();
                e.language = LanguageId::TypeScript;
                e
            }),
            ("created_in", {
                let mut e = target.clone();
                e.created_in = Some(kin_model::SemanticChangeId::from_hash(
                    kin_model::Hash256::from_bytes([1; 32]),
                ));
                e
            }),
            ("metadata", {
                let mut e = target.clone();
                e.metadata
                    .extra
                    .insert("body".into(), serde_json::json!("fabricated"));
                e
            }),
            ("signature", {
                let mut e = target.clone();
                e.signature = "fabricated".into();
                e
            }),
        ] {
            cases.push((label, transaction(entity, relation.clone())));
        }
        let mut delta = valid.clone();
        delta.entity_deltas.push(EntityDelta::Removed {
            old: source.clone(),
        });
        cases.push(("removed source cannot back target", delta));
        let mut extra_source = source.clone();
        extra_source.id = kin_model::EntityId::new();
        let mut delta = valid.clone();
        delta
            .entity_deltas
            .push(EntityDelta::Added { new: extra_source });
        cases.push(("extra source declaration", delta));
        let mut delta = valid;
        delta.entity_deltas = vec![EntityDelta::Removed {
            old: target.clone(),
        }];
        cases.push(("external target removal", delta));
        for (label, delta) in cases {
            assert!(
                first_unsupported_entity_change(&delta, &graph, &FilePathId::new("src/app.js"))
                    .unwrap()
                    .is_some(),
                "{label}"
            );
        }
        graph.upsert_entity(&target).unwrap();
        assert!(
            first_unsupported_entity_change(
                &transaction(target, relation),
                &graph,
                &FilePathId::new("src/app.js")
            )
            .unwrap()
            .is_some(),
            "held ID collision"
        );
    }

    #[test]
    fn source_entity_guard_existing_target_preserves_provenance_but_refuses_forgery() {
        let (graph, source, mut target, relation) = fixture();
        let file = FilePathId::new("src/app.js");
        target.language = LanguageId::TypeScript;
        target.created_in = Some(kin_model::SemanticChangeId::from_hash(
            kin_model::Hash256::from_bytes([3; 32]),
        ));
        graph.upsert_entity(&target).unwrap();
        let delta = TransactionDelta {
            relation_deltas: vec![RelationDelta::Added {
                new: relation.clone(),
            }],
            ..Default::default()
        };
        assert!(admitted_external_relation(&relation, &delta, &graph, &file).unwrap());
        assert!(!admitted_external_relation(
            &relation,
            &delta,
            &graph,
            &FilePathId::new("unrelated.js")
        )
        .unwrap());
        let mut forged_edge = relation.clone();
        forged_edge.evidence[0].token = Some("forged".into());
        assert!(!admitted_external_relation(&forged_edge, &delta, &graph, &file).unwrap());
        let mut removed_source = delta.clone();
        removed_source
            .entity_deltas
            .push(EntityDelta::Removed { old: source });
        assert!(!admitted_external_relation(&relation, &removed_source, &graph, &file).unwrap());
        target
            .metadata
            .extra
            .insert("body".into(), serde_json::json!("forged"));
        graph.upsert_entity(&target).unwrap();
        assert!(!admitted_external_relation(&relation, &delta, &graph, &file).unwrap());
    }
}
