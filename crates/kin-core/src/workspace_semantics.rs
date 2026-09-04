// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Canonical semantic transitions between graph-owned workspace states.
//!
//! Exact repository membership is carried independently by tree deltas. This
//! module compares only live entity and relation authority so callers cannot
//! accidentally infer semantic state from files or parser availability.

use std::collections::{BTreeSet, HashMap};

use kin_model::{
    Entity, EntityDelta, EntityId, Relation, RelationDelta, RelationId, WorkspaceSemanticDelta,
};

/// Whether two versions of one entity hold the same CONTENT.
///
/// THE one answer to "did this entity itself change", so every surface that
/// reports a change gives the same number. Two implementations of this were two
/// answers to the same question: `kin blame` filtered on `behavior_hash` alone
/// in the CLI, the merge composer had its own richer field set in the daemon,
/// and `kin conflicts`, `kin diff` and `kin log` used neither and compared the
/// whole `Entity`.
///
/// Comparing the whole `Entity` is what produced the over-report. `reconciler`
/// stamps the whole FILE's blob hash into every entity's `metadata.extra`, and
/// editing one function moves the byte span of every entity below it, so every
/// entity in a touched file compares unequal even when its own text never
/// moved. A two-function change then read as fourteen merge conflicts and
/// `Entities: +1 ~11`, and `kin conflicts --show` printed empty `base -> ours`
/// and `base -> theirs` diffs for the ten spurious ones, contradicting the same
/// command's own list.
///
/// So the fields here are the ones the graph calls content: the fingerprint
/// over normalized structure, signature, exact source text and behaviour class,
/// beside the declaration facts around it. Byte offsets, the file blob stamp
/// and the change a revision was recorded in are projection facts and are
/// excluded deliberately.
///
/// This does NOT change what gets minted. The revisions and deltas a file-level
/// edit records are real, they are what the file did, and
/// `diff_workspace_semantics` below still authors them on exact equality. What
/// this changes is reporting one of them as a change to an entity that did not
/// change.
pub fn entity_content_agrees(left: &Entity, right: &Entity) -> bool {
    left.kind == right.kind
        && left.name == right.name
        && left.language == right.language
        && left.fingerprint == right.fingerprint
        && left.signature == right.signature
        && left.visibility == right.visibility
        && left.role == right.role
}

/// [`entity_content_agrees`] for a dimension where the identity can be absent
/// on a side.
///
/// Absent on both sides is agreement: neither side holds the entity, so neither
/// side has anything to say about it. Present on one side only is a real
/// disagreement about the entity's existence, which no content comparison can
/// soften.
pub fn entity_sides_agree(left: Option<&Entity>, right: Option<&Entity>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => entity_content_agrees(left, right),
        (Some(_), None) | (None, Some(_)) => false,
    }
}

/// Derive the exact incremental semantic transition from one workspace graph
/// to another.
///
/// The result is canonicalized and validated by [`WorkspaceSemanticDelta`].
/// Unsupported-language, configuration, binary, and other opaque artifacts
/// remain represented by the separate exact tree even when this delta is
/// empty.
pub fn diff_workspace_semantics(
    current_entities: &HashMap<EntityId, Entity>,
    current_relations: &HashMap<RelationId, Relation>,
    desired_entities: &HashMap<EntityId, Entity>,
    desired_relations: &HashMap<RelationId, Relation>,
) -> kin_model::Result<WorkspaceSemanticDelta> {
    let entity_deltas = current_entities
        .keys()
        .copied()
        .chain(desired_entities.keys().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|entity_id| {
            match (
                current_entities.get(&entity_id),
                desired_entities.get(&entity_id),
            ) {
                (None, Some(new)) => Some(EntityDelta::Added { new: new.clone() }),
                (Some(old), Some(new)) if old != new => Some(EntityDelta::Modified {
                    old: old.clone(),
                    new: new.clone(),
                }),
                (Some(old), None) => Some(EntityDelta::Removed { old: old.clone() }),
                (Some(_), Some(_)) | (None, None) => None,
            }
        })
        .collect();
    let relation_deltas = current_relations
        .keys()
        .copied()
        .chain(desired_relations.keys().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|relation_id| {
            match (
                current_relations.get(&relation_id),
                desired_relations.get(&relation_id),
            ) {
                (None, Some(new)) => Some(RelationDelta::Added { new: new.clone() }),
                (Some(old), Some(new)) if old != new => Some(RelationDelta::Modified {
                    old: old.clone(),
                    new: new.clone(),
                }),
                (Some(old), None) => Some(RelationDelta::Removed { old: old.clone() }),
                (Some(_), Some(_)) | (None, None) => None,
            }
        })
        .collect();

    WorkspaceSemanticDelta::new(entity_deltas, relation_deltas)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm, Hash256,
        LanguageId, SemanticFingerprint, SourceSpan, Visibility,
    };

    /// One version of one entity. `body` is its own source; `stamp` is the
    /// containing FILE's blob hash and the byte offset every entity below an
    /// edit shifts to, which is what a reconcile writes for every entity in a
    /// touched file whether or not that entity moved.
    fn entity(body: u8, stamp: u8) -> Entity {
        let mut extra = HashMap::new();
        extra.insert(
            "artifact_blob".to_string(),
            serde_json::Value::String(format!("{stamp:02x}")),
        );
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "format_totals".to_string(),
            language: LanguageId::Python,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([body; 32]),
                signature_hash: Hash256::from_bytes([1; 32]),
                behavior_hash: Hash256::from_bytes([body; 32]),
                equivalence_hash: Hash256::from_bytes([body; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("ledger/reporting.py")),
            span: Some(SourceSpan {
                file: FilePathId::new("ledger/reporting.py"),
                start_byte: usize::from(stamp) * 100,
                end_byte: usize::from(stamp) * 100 + 40,
                start_line: u32::from(stamp),
                start_col: 0,
                end_line: u32::from(stamp) + 3,
                end_col: 0,
            }),
            signature: "def format_totals()".to_string(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata { extra },
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    /// The over-report itself. Two versions of an entity whose own source never
    /// moved, carrying the file blob stamp and the shifted span a neighbour's
    /// edit gave them, are the same entity.
    ///
    /// Breaking it: compare the whole `Entity` and this goes red, which is the
    /// comparison `kin conflicts`, `kin diff` and `kin log` used to make.
    #[test]
    fn a_file_level_stamp_and_a_shifted_span_are_not_a_change() {
        let before = entity(1, 0x10);
        let mut after = entity(1, 0x30);
        after.id = before.id;
        assert_ne!(
            before, after,
            "the fixture is the noisy case it claims to be"
        );
        assert!(entity_content_agrees(&before, &after));
    }

    /// The positive control. Without it, a predicate that returned `true`
    /// unconditionally would satisfy the test above, and every surface reading
    /// it would report that nothing ever changes.
    #[test]
    fn an_edited_body_is_a_change() {
        let before = entity(1, 0x10);
        let mut after = entity(2, 0x10);
        after.id = before.id;
        assert!(!entity_content_agrees(&before, &after));
    }

    /// A rename is a change even when the body is byte-identical, and an
    /// entity present on one side only disagrees with an absent one. Both are
    /// cases a fingerprint-only comparison would answer wrong.
    #[test]
    fn a_rename_and_a_one_sided_absence_are_both_changes() {
        let before = entity(1, 0x10);
        let mut renamed = before.clone();
        renamed.name = "format_report".to_string();
        assert!(!entity_content_agrees(&before, &renamed));

        assert!(entity_sides_agree(None, None));
        assert!(!entity_sides_agree(Some(&before), None));
        assert!(!entity_sides_agree(None, Some(&before)));
    }
}
