// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use std::collections::{BTreeSet, HashMap};

use crate::{
    ArtifactId, ArtifactRevisionId, Entity, EntityId, EntityRevisionId, LocatedEntry, Relation,
    RelationId, RelationRevisionId, RepoPath, SemanticChangeId, TreeEntry,
};

const ARTIFACT_REVISION_DOMAIN: &[u8] = b"kin.artifact-revision.v2\0";

/// Immutable entity state introduced by a semantic change.
///
/// `EntityId` is the stable anchor identity; each revision identifies one
/// committed shape for that anchor.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EntityRevision {
    pub revision_id: EntityRevisionId,
    pub entity_id: EntityId,
    pub entity: Entity,
    pub introduced_by: SemanticChangeId,
    pub previous_revision: Option<EntityRevisionId>,
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
    pub previous_revision: Option<RelationRevisionId>,
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

/// Immutable tracked-file tree entry introduced by a semantic change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRevision {
    pub revision_id: ArtifactRevisionId,
    pub artifact_id: ArtifactId,
    pub path: RepoPath,
    pub entry: TreeEntry,
    pub introduced_by: SemanticChangeId,
    /// Revisions active for this artifact at the declared parents, in parent
    /// order with duplicates removed. A merge can therefore preserve multiple
    /// predecessor lines without changing first-parent state semantics.
    pub predecessor_revisions: Vec<ArtifactRevisionId>,
}

impl ArtifactRevision {
    pub fn new(
        artifact_id: ArtifactId,
        path: RepoPath,
        entry: TreeEntry,
        introduced_by: SemanticChangeId,
        mut predecessor_revisions: Vec<ArtifactRevisionId>,
    ) -> Self {
        let mut seen_predecessors = BTreeSet::new();
        predecessor_revisions.retain(|revision_id| seen_predecessors.insert(*revision_id));
        let located = LocatedEntry::new(path.clone(), entry);
        let revision_id = ArtifactRevisionId::for_artifact_change(
            &artifact_id,
            &introduced_by,
            &located,
            &predecessor_revisions,
        );
        Self {
            revision_id,
            artifact_id,
            path,
            entry,
            introduced_by,
            predecessor_revisions,
        }
    }

    pub fn located_entry(&self) -> LocatedEntry {
        LocatedEntry::new(self.path.clone(), self.entry)
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
        artifact_id: &ArtifactId,
        change_id: &SemanticChangeId,
        located: &LocatedEntry,
        predecessor_revisions: &[ArtifactRevisionId],
    ) -> Self {
        let mut seen_predecessors = BTreeSet::new();
        let canonical_predecessors: Vec<_> = predecessor_revisions
            .iter()
            .copied()
            .filter(|revision_id| seen_predecessors.insert(*revision_id))
            .collect();
        let mut hasher = Sha256::new();
        hasher.update(ARTIFACT_REVISION_DOMAIN);
        hasher.update(artifact_id.0.as_bytes());
        hasher.update(change_id.0.as_bytes());
        hasher.update((located.path.as_bytes().len() as u64).to_be_bytes());
        hasher.update(located.path.as_bytes());
        match located.entry {
            TreeEntry::Blob {
                hash,
                executable: false,
            } => {
                hasher.update([0]);
                hasher.update(hash.as_bytes());
            }
            TreeEntry::Blob {
                hash,
                executable: true,
            } => {
                hasher.update([1]);
                hasher.update(hash.as_bytes());
            }
            TreeEntry::Symlink { target_blob } => {
                hasher.update([2]);
                hasher.update(target_blob.as_bytes());
            }
            TreeEntry::Gitlink { target } => {
                hasher.update([3]);
                hasher.update([match target {
                    crate::GitObjectId::Sha1(_) => 1,
                    crate::GitObjectId::Sha256(_) => 2,
                }]);
                hasher.update(target.as_bytes());
            }
        }
        hasher.update((canonical_predecessors.len() as u64).to_be_bytes());
        for predecessor in canonical_predecessors {
            hasher.update(predecessor.0.as_bytes());
        }
        Self::from_hash(kin_blobs::Hash256::from_bytes(hasher.finalize().into()))
    }
}

/// Check whether an entity or relation revision was active at a given
/// reference change, using the topological ordinal map.
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
                equivalence_hash: Hash256::from_bytes([0; 32]),
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

    #[test]
    fn artifact_revision_identity_includes_anchor_path_and_exact_tree_mode() {
        let artifact_id = ArtifactId::new();
        let change = SemanticChangeId::from_hash(Hash256::from_bytes([0x51; 32]));
        let blob_hash = Hash256::from_bytes([0x52; 32]);
        let regular = LocatedEntry::new(
            RepoPath::from_utf8("bin/run").unwrap(),
            TreeEntry::blob(blob_hash, false),
        );
        let executable = LocatedEntry::new(
            RepoPath::from_utf8("bin/run").unwrap(),
            TreeEntry::blob(blob_hash, true),
        );
        let renamed = LocatedEntry::new(
            RepoPath::from_utf8("bin/renamed").unwrap(),
            TreeEntry::blob(blob_hash, false),
        );

        let regular_id =
            ArtifactRevisionId::for_artifact_change(&artifact_id, &change, &regular, &[]);
        let executable_id =
            ArtifactRevisionId::for_artifact_change(&artifact_id, &change, &executable, &[]);
        let renamed_id =
            ArtifactRevisionId::for_artifact_change(&artifact_id, &change, &renamed, &[]);
        let other_artifact_id =
            ArtifactRevisionId::for_artifact_change(&ArtifactId::new(), &change, &regular, &[]);
        let first_parent = ArtifactRevisionId::from_hash(Hash256::from_bytes([0x53; 32]));
        let second_parent = ArtifactRevisionId::from_hash(Hash256::from_bytes([0x54; 32]));
        let lineage_id = ArtifactRevisionId::for_artifact_change(
            &artifact_id,
            &change,
            &regular,
            &[first_parent, second_parent],
        );
        let reversed_lineage_id = ArtifactRevisionId::for_artifact_change(
            &artifact_id,
            &change,
            &regular,
            &[second_parent, first_parent],
        );
        let duplicate_lineage_id = ArtifactRevisionId::for_artifact_change(
            &artifact_id,
            &change,
            &regular,
            &[first_parent, second_parent, first_parent],
        );

        assert_ne!(regular_id, executable_id);
        assert_ne!(regular_id, renamed_id);
        assert_ne!(regular_id, other_artifact_id);
        assert_ne!(regular_id, lineage_id);
        assert_ne!(lineage_id, reversed_lineage_id);
        assert_eq!(lineage_id, duplicate_lineage_id);
    }

    #[test]
    fn artifact_revision_hash_encoding_is_version_pinned() {
        let artifact_id = ArtifactId(uuid::Uuid::from_u128(1));
        let change = SemanticChangeId::from_hash(Hash256::from_bytes([0x11; 32]));
        let located = LocatedEntry::new(
            RepoPath::from_bytes(vec![b'a', 0xff]).unwrap(),
            TreeEntry::symlink(Hash256::from_bytes([0x22; 32])),
        );
        let predecessor = ArtifactRevisionId::from_hash(Hash256::from_bytes([0x33; 32]));

        let revision_id = ArtifactRevisionId::for_artifact_change(
            &artifact_id,
            &change,
            &located,
            &[predecessor],
        );

        assert_eq!(
            revision_id.to_string(),
            "e858852f60cf556541aceaf7e9351ac874fb5557ef4e0cbbdab41489172cd54d"
        );
    }

    #[test]
    fn artifact_revision_uses_explicit_predecessor_lineage() {
        let artifact_id = ArtifactId::new();
        let introduced_by = SemanticChangeId::from_hash(Hash256::from_bytes([0x61; 32]));
        let first_parent = ArtifactRevisionId::from_hash(Hash256::from_bytes([0x62; 32]));
        let second_parent = ArtifactRevisionId::from_hash(Hash256::from_bytes([0x63; 32]));
        let revision = ArtifactRevision::new(
            artifact_id,
            RepoPath::from_utf8("compose.yaml").unwrap(),
            TreeEntry::blob(Hash256::from_bytes([0x64; 32]), false),
            introduced_by,
            vec![first_parent, second_parent, first_parent],
        );

        assert_eq!(revision.artifact_id, artifact_id);
        assert_eq!(
            revision.predecessor_revisions,
            vec![first_parent, second_parent]
        );

        let encoded = serde_json::to_value(&revision).unwrap();
        assert_eq!(
            encoded["path"],
            serde_json::json!({ "bytes_hex": "636f6d706f73652e79616d6c" })
        );
        assert!(encoded.get("file_id").is_none());
        assert!(encoded.get("previous_revision").is_none());

        let legacy = serde_json::json!({
            "revision_id": revision.revision_id,
            "file_id": "compose.yaml",
            "entry": revision.entry,
            "introduced_by": revision.introduced_by,
            "previous_revision": first_parent,
            "ended_by": null
        });
        assert!(serde_json::from_value::<ArtifactRevision>(legacy).is_err());
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
