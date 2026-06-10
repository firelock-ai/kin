// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use std::collections::HashMap;

use crate::{
    ArtifactDeltaKind, ArtifactRevisionId, Entity, EntityId, EntityRevisionId, FilePathId, Hash256,
    Relation, RelationId, RelationRevisionId, SemanticChangeId,
};

/// Immutable entity state introduced by a semantic change.
///
/// `EntityId` remains the stable anchor identity for migration compatibility.
/// Each revision identifies one committed shape for that anchor.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EntityRevision {
    pub revision_id: EntityRevisionId,
    pub entity_id: EntityId,
    pub entity: Entity,
    pub introduced_by: SemanticChangeId,
    #[serde(default)]
    pub previous_revision: Option<EntityRevisionId>,
    #[serde(default)]
    pub ended_by: Option<SemanticChangeId>,
}

impl EntityRevision {
    pub fn new(
        entity: Entity,
        introduced_by: SemanticChangeId,
        supersedes: Option<EntityRevisionId>,
    ) -> Self {
        let revision_id = EntityRevisionId::for_entity_change(&entity.id, &introduced_by);
        Self {
            revision_id,
            entity_id: entity.id,
            entity,
            introduced_by,
            previous_revision: supersedes,
            ended_by: None,
        }
    }

    pub fn mark_ended(&mut self, change_id: SemanticChangeId) {
        self.ended_by.get_or_insert(change_id);
    }
}

impl PartialEq for EntityRevision {
    fn eq(&self, other: &Self) -> bool {
        self.revision_id == other.revision_id
            && self.entity_id == other.entity_id
            && self.introduced_by == other.introduced_by
            && self.previous_revision == other.previous_revision
            && self.ended_by == other.ended_by
            && serde_json::to_vec(&self.entity).ok() == serde_json::to_vec(&other.entity).ok()
    }
}

/// Immutable relation state introduced by a semantic change.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RelationRevision {
    pub revision_id: RelationRevisionId,
    pub relation_id: RelationId,
    pub relation: Relation,
    pub introduced_by: SemanticChangeId,
    #[serde(default)]
    pub previous_revision: Option<RelationRevisionId>,
    #[serde(default)]
    pub ended_by: Option<SemanticChangeId>,
}

impl RelationRevision {
    pub fn new(
        relation: Relation,
        introduced_by: SemanticChangeId,
        previous_revision: Option<RelationRevisionId>,
    ) -> Self {
        let revision_id = RelationRevisionId::for_relation_change(&relation.id, &introduced_by);
        Self {
            revision_id,
            relation_id: relation.id,
            relation,
            introduced_by,
            previous_revision,
            ended_by: None,
        }
    }

    pub fn mark_ended(&mut self, change_id: SemanticChangeId) {
        self.ended_by.get_or_insert(change_id);
    }
}

impl PartialEq for RelationRevision {
    fn eq(&self, other: &Self) -> bool {
        self.revision_id == other.revision_id
            && self.relation_id == other.relation_id
            && self.introduced_by == other.introduced_by
            && self.previous_revision == other.previous_revision
            && self.ended_by == other.ended_by
            && serde_json::to_vec(&self.relation).ok() == serde_json::to_vec(&other.relation).ok()
    }
}

/// Immutable tracked-file content revision introduced by a semantic change.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactRevision {
    pub revision_id: ArtifactRevisionId,
    pub file_id: FilePathId,
    pub content_hash: Hash256,
    pub kind: ArtifactDeltaKind,
    pub introduced_by: SemanticChangeId,
    #[serde(default)]
    pub previous_revision: Option<ArtifactRevisionId>,
    #[serde(default)]
    pub ended_by: Option<SemanticChangeId>,
}

impl ArtifactRevision {
    pub fn new(
        file_id: FilePathId,
        content_hash: Hash256,
        kind: ArtifactDeltaKind,
        introduced_by: SemanticChangeId,
        previous_revision: Option<ArtifactRevisionId>,
    ) -> Self {
        let revision_id =
            ArtifactRevisionId::for_artifact_change(&file_id, &introduced_by, &content_hash);
        Self {
            revision_id,
            file_id,
            content_hash,
            kind,
            introduced_by,
            previous_revision,
            ended_by: None,
        }
    }

    pub fn mark_ended(&mut self, change_id: SemanticChangeId) {
        self.ended_by.get_or_insert(change_id);
    }
}

impl EntityRevisionId {
    pub fn for_entity_change(entity_id: &EntityId, change_id: &SemanticChangeId) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(entity_id.0.as_bytes());
        hasher.update(change_id.0.as_bytes());
        Self::from_hash(kin_blobs::Hash256::from_bytes(hasher.finalize().into()))
    }
}

impl RelationRevisionId {
    pub fn for_relation_change(relation_id: &RelationId, change_id: &SemanticChangeId) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(relation_id.0.as_bytes());
        hasher.update(change_id.0.as_bytes());
        Self::from_hash(kin_blobs::Hash256::from_bytes(hasher.finalize().into()))
    }
}

impl ArtifactRevisionId {
    pub fn for_artifact_change(
        file_id: &FilePathId,
        change_id: &SemanticChangeId,
        content_hash: &Hash256,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(file_id.0.as_bytes());
        hasher.update(change_id.0.as_bytes());
        hasher.update(content_hash.as_bytes());
        Self::from_hash(kin_blobs::Hash256::from_bytes(hasher.finalize().into()))
    }
}

/// Check whether an entity (or relation/artifact revision) was active at a
/// given reference change, using the topological ordinal map.
///
/// Returns `true` when:
/// - `introduced_ord <= ref_ord`, AND
/// - `ended_by` is `None` OR `ended_ord > ref_ord`
///
/// Returns `false` if any of the provided change IDs are missing from
/// `change_order` (unknown/out-of-scope change).
pub fn is_active_at(
    introduced_by: &SemanticChangeId,
    ended_by: Option<&SemanticChangeId>,
    ref_change: &SemanticChangeId,
    change_order: &HashMap<SemanticChangeId, u64>,
) -> bool {
    let Some(&introduced_ord) = change_order.get(introduced_by) else {
        return false;
    };
    let Some(&ref_ord) = change_order.get(ref_change) else {
        return false;
    };
    if introduced_ord > ref_ord {
        return false;
    }
    if let Some(ended) = ended_by {
        let Some(&ended_ord) = change_order.get(ended) else {
            return false;
        };
        if ended_ord <= ref_ord {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, Hash256, LanguageId,
        SemanticFingerprint, Visibility,
    };

    fn entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
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

    #[test]
    fn entity_revision_id_depends_on_anchor_and_change() {
        let entity = entity("handler");
        let change_a = SemanticChangeId::from_hash(Hash256::from_bytes([0x11; 32]));
        let change_b = SemanticChangeId::from_hash(Hash256::from_bytes([0x22; 32]));

        let rev_a = EntityRevisionId::for_entity_change(&entity.id, &change_a);
        let rev_b = EntityRevisionId::for_entity_change(&entity.id, &change_b);

        assert_ne!(rev_a, rev_b);
    }

    #[test]
    fn entity_revision_tracks_superseded_lineage() {
        let entity = entity("handler");
        let add = SemanticChangeId::from_hash(Hash256::from_bytes([0x31; 32]));
        let modify = SemanticChangeId::from_hash(Hash256::from_bytes([0x32; 32]));

        let first = EntityRevision::new(entity.clone(), add, None);
        let second = EntityRevision::new(entity, modify, Some(first.revision_id));

        assert_eq!(second.previous_revision, Some(first.revision_id));
        assert_eq!(second.entity_id, first.entity_id);
    }

    #[test]
    fn entity_revision_can_mark_end_change_once() {
        let entity = entity("handler");
        let add = SemanticChangeId::from_hash(Hash256::from_bytes([0x41; 32]));
        let remove = SemanticChangeId::from_hash(Hash256::from_bytes([0x42; 32]));
        let later = SemanticChangeId::from_hash(Hash256::from_bytes([0x43; 32]));

        let mut revision = EntityRevision::new(entity, add, None);
        revision.mark_ended(remove);
        revision.mark_ended(later);

        assert_eq!(revision.ended_by, Some(remove));
    }

    fn make_change_order() -> (
        SemanticChangeId,
        SemanticChangeId,
        SemanticChangeId,
        HashMap<SemanticChangeId, u64>,
    ) {
        let c0 = SemanticChangeId::from_hash(Hash256::from_bytes([0xA0; 32]));
        let c1 = SemanticChangeId::from_hash(Hash256::from_bytes([0xA1; 32]));
        let c2 = SemanticChangeId::from_hash(Hash256::from_bytes([0xA2; 32]));
        let mut order = HashMap::new();
        order.insert(c0, 0);
        order.insert(c1, 1);
        order.insert(c2, 2);
        (c0, c1, c2, order)
    }

    #[test]
    fn is_active_at_introduced_before_ref() {
        let (c0, c1, _c2, order) = make_change_order();
        assert!(super::is_active_at(&c0, None, &c1, &order));
    }

    #[test]
    fn is_active_at_introduced_at_ref() {
        let (c0, _c1, _c2, order) = make_change_order();
        assert!(super::is_active_at(&c0, None, &c0, &order));
    }

    #[test]
    fn is_active_at_introduced_after_ref() {
        let (_c0, c1, _c2, order) = make_change_order();
        assert!(!super::is_active_at(&c1, None, &_c0, &order));
    }

    #[test]
    fn is_active_at_ended_before_ref() {
        let (c0, c1, c2, order) = make_change_order();
        // introduced at c0, ended at c1, queried at c2 => not active
        assert!(!super::is_active_at(&c0, Some(&c1), &c2, &order));
    }

    #[test]
    fn is_active_at_ended_at_ref() {
        let (c0, c1, _c2, order) = make_change_order();
        // introduced at c0, ended at c1, queried at c1 => not active (ended_ord <= ref_ord)
        assert!(!super::is_active_at(&c0, Some(&c1), &c1, &order));
    }

    #[test]
    fn is_active_at_ended_after_ref() {
        let (c0, c1, c2, order) = make_change_order();
        // introduced at c0, ended at c2, queried at c1 => active
        assert!(super::is_active_at(&c0, Some(&c2), &c1, &order));
    }

    #[test]
    fn is_active_at_unknown_change_returns_false() {
        let (c0, _c1, _c2, order) = make_change_order();
        let unknown = SemanticChangeId::from_hash(Hash256::from_bytes([0xFF; 32]));
        assert!(!super::is_active_at(&unknown, None, &c0, &order));
        assert!(!super::is_active_at(&c0, None, &unknown, &order));
    }
}
