// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Diff and commit construction helpers.
//!
//! Shared utilities for building semantic changes, computing change IDs,
//! and resolving author identity.

#[cfg(test)]
use kin_model::Hash256;
use kin_model::{EntityDelta, RelationDelta, SemanticChange, SemanticChangeId, TreeDelta};

use crate::{KinError, Result};

/// Compute the immutable identity of a complete native semantic change.
///
/// The existing `id` field is excluded to avoid a self-reference; every other
/// serialized field participates, including all parents, author, timestamp,
/// message, deltas, provenance links, risk, and authored branch. Native change
/// constructors must use this after assembling the final payload so daemon
/// exact-retry equality and ID authority describe the same bytes.
pub fn compute_semantic_change_id(change: &SemanticChange) -> Result<SemanticChangeId> {
    kin_model::compute_semantic_change_id(change)
        .map_err(|error| KinError::Other(error.to_string()))
}

/// Derive a deterministic content fingerprint from the complete delta payloads.
///
/// Canonical encodings of independent deltas are sorted before hashing so their
/// insertion order does not affect the result. If deltas overlap a replay
/// target, their order is retained because graph replay is order-sensitive.
/// Every field of every delta participates, including entity
/// bodies/fingerprints, relation evidence/confidence, and exact tree entry
/// transitions. This is deliberately not an ID-only projection: two
/// immutable `SemanticChange` records must never receive the same ID merely
/// because they touch the same graph IDs or file paths.
pub fn content_identity_from_deltas(
    entity_deltas: &[EntityDelta],
    relation_deltas: &[RelationDelta],
    tree_deltas: &[TreeDelta],
) -> Result<[u8; 32]> {
    kin_model::content_identity_from_deltas(entity_deltas, relation_deltas, tree_deltas)
        .map_err(|error| KinError::Other(error.to_string()))
}

/// Get a human-readable author name from environment variables.
///
/// Checks `USER` (Unix) then `USERNAME` (Windows), falls back to `"unknown"`.
pub fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        relation::GraphNodeId, ArtifactId, AuthorId, BranchName, Entity, EntityId, EntityKind,
        EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm, LanguageId, LocatedEntry,
        Relation, RelationId, RelationKind, RelationOrigin, RepoPath, SemanticFingerprint,
        Timestamp, TreeEntry, Visibility,
    };

    fn test_entity(id: EntityId, name: &str) -> Entity {
        Entity {
            id,
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: Hash256::from_bytes([4; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/lib.rs")),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Private,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn modified_tree(
        artifact_id: ArtifactId,
        path: &str,
        old_hash: Hash256,
        new_hash: Hash256,
        executable: bool,
    ) -> TreeDelta {
        TreeDelta::Updated {
            artifact_id,
            old: LocatedEntry::new(
                RepoPath::from_utf8(path).unwrap(),
                TreeEntry::blob(old_hash, false),
            ),
            new: LocatedEntry::new(
                RepoPath::from_utf8(path).unwrap(),
                TreeEntry::blob(new_hash, executable),
            ),
        }
    }

    #[test]
    fn complete_change_identity_binds_provenance_but_excludes_existing_id() {
        let mut original = crate::build_genesis_change();
        original.author = AuthorId::new("agent-a");
        original.authored_on = Some(BranchName::new("main"));
        let original_id = compute_semantic_change_id(&original).unwrap();

        let mut different_author = original.clone();
        different_author.author = AuthorId::new("agent-b");
        assert_ne!(
            original_id,
            compute_semantic_change_id(&different_author).unwrap()
        );

        let mut different_branch = original.clone();
        different_branch.authored_on = Some(BranchName::new("feature"));
        assert_ne!(
            original_id,
            compute_semantic_change_id(&different_branch).unwrap()
        );

        original.id = SemanticChangeId::from_hash(Hash256::from_bytes([0x55; 32]));
        assert_eq!(original_id, compute_semantic_change_id(&original).unwrap());
    }

    #[test]
    fn semantic_change_v5_hash_domain_has_a_pinned_fixture() {
        let mut fixture = crate::build_genesis_change();
        fixture.id = SemanticChangeId::from_hash(Hash256::from_bytes([0x55; 32]));
        fixture.timestamp = Timestamp(
            chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        fixture.author = AuthorId::new("fixture");
        fixture.message = "phase two".to_string();
        fixture.authored_on = Some(BranchName::new("main"));

        assert_eq!(
            compute_semantic_change_id(&fixture).unwrap().to_string(),
            "4c2bb2dc66a780f9b807e0c08b0ab61d37ae0d861af9dea8347145932bf1f7c5",
            "changing the kin-semantic-change-v5 domain or canonical fixture is a wire break"
        );
    }

    #[test]
    fn content_identity_empty_deltas_is_deterministic() {
        let h1 = content_identity_from_deltas(&[], &[], &[]).unwrap();
        let h2 = content_identity_from_deltas(&[], &[], &[]).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(
            h1,
            [
                0xe2, 0xe3, 0x49, 0x04, 0x8f, 0x3e, 0xed, 0x2e, 0xb2, 0xab, 0x77, 0x63, 0xdc, 0x51,
                0xe7, 0xfd, 0xd0, 0x3f, 0xa6, 0x7c, 0xbb, 0xcc, 0x09, 0xe2, 0x07, 0xfd, 0xde, 0x68,
                0x8c, 0x34, 0xf8, 0x8e,
            ],
            "changing the kin-content-v4 domain or canonical empty payload is a wire break"
        );
    }

    #[test]
    fn content_identity_binds_complete_tree_delta_and_ignores_slice_order() {
        let regular_artifact = ArtifactId(uuid::Uuid::from_u128(1));
        let executable_artifact = ArtifactId(uuid::Uuid::from_u128(2));
        let old_artifact = ArtifactId(uuid::Uuid::from_u128(3));
        let old_hash = Hash256::from_bytes([1; 32]);
        let new_hash = Hash256::from_bytes([2; 32]);
        let different_old_hash = Hash256::from_bytes([3; 32]);
        let regular = modified_tree(regular_artifact, "bin/kin", old_hash, new_hash, false);
        let executable = modified_tree(regular_artifact, "bin/kin", old_hash, new_hash, true);
        let different_old = modified_tree(
            regular_artifact,
            "bin/kin",
            different_old_hash,
            new_hash,
            false,
        );

        let regular_id =
            content_identity_from_deltas(&[], &[], std::slice::from_ref(&regular)).unwrap();
        let executable_id =
            content_identity_from_deltas(&[], &[], std::slice::from_ref(&executable)).unwrap();
        let different_old_id =
            content_identity_from_deltas(&[], &[], std::slice::from_ref(&different_old)).unwrap();
        assert_ne!(regular_id, executable_id);
        assert_ne!(regular_id, different_old_id);

        let ordered_executable = modified_tree(
            executable_artifact,
            "bin/kin-exec",
            old_hash,
            new_hash,
            true,
        );
        let ordered_different_old = modified_tree(
            old_artifact,
            "bin/kin-old",
            different_old_hash,
            new_hash,
            false,
        );
        let first = content_identity_from_deltas(
            &[],
            &[],
            &[
                regular.clone(),
                ordered_executable.clone(),
                ordered_different_old.clone(),
            ],
        )
        .unwrap();
        let reordered = content_identity_from_deltas(
            &[],
            &[],
            &[ordered_different_old, regular, ordered_executable],
        )
        .unwrap();
        assert_eq!(first, reordered);
    }

    #[test]
    fn content_identity_binds_order_for_duplicate_tree_targets() {
        let artifact_id = ArtifactId(uuid::Uuid::from_u128(4));
        let first_hash = Hash256::from_bytes([1; 32]);
        let second_hash = Hash256::from_bytes([2; 32]);
        let third_hash = Hash256::from_bytes([3; 32]);
        let first = modified_tree(artifact_id, "src/lib.rs", first_hash, second_hash, false);
        let second = modified_tree(artifact_id, "src/lib.rs", second_hash, third_hash, false);

        let forward =
            content_identity_from_deltas(&[], &[], &[first.clone(), second.clone()]).unwrap();
        let reversed = content_identity_from_deltas(&[], &[], &[second, first]).unwrap();
        assert_ne!(forward, reversed);
    }

    #[test]
    fn content_identity_binds_artifact_identity_and_byte_exact_path() {
        let hash = Hash256::from_bytes([0x44; 32]);
        let first_id = ArtifactId(uuid::Uuid::from_u128(5));
        let second_id = ArtifactId(uuid::Uuid::from_u128(6));
        let utf8_path = RepoPath::from_utf8("assets/icon.bin").unwrap();
        let byte_path = RepoPath::from_bytes(b"assets/icon-\xff.bin".to_vec()).unwrap();
        let delta = |artifact_id, path| TreeDelta::Added {
            artifact_id,
            new: LocatedEntry::new(path, TreeEntry::blob(hash, false)),
        };

        let first =
            content_identity_from_deltas(&[], &[], &[delta(first_id, utf8_path.clone())]).unwrap();
        let other_identity =
            content_identity_from_deltas(&[], &[], &[delta(second_id, utf8_path)]).unwrap();
        let other_path =
            content_identity_from_deltas(&[], &[], &[delta(first_id, byte_path)]).unwrap();

        assert_ne!(first, other_identity);
        assert_ne!(first, other_path);
    }

    #[test]
    fn phase_one_tree_wire_is_rejected_instead_of_rehashed() {
        let legacy = serde_json::json!({
            "operation": "modified",
            "file_id": "src/lib.rs",
            "old_entry": {
                "blob_hash": Hash256::from_bytes([0x11; 32]),
                "kind": { "type": "regular", "executable": false }
            },
            "new_entry": {
                "blob_hash": Hash256::from_bytes([0x22; 32]),
                "kind": { "type": "regular", "executable": false }
            }
        });

        assert!(serde_json::from_value::<TreeDelta>(legacy).is_err());
    }

    #[test]
    fn content_identity_binds_order_for_cross_linked_entity_modifications() {
        let a = test_entity(EntityId::new(), "a");
        let b = test_entity(EntityId::new(), "b");
        let c = test_entity(EntityId::new(), "c");
        let a_to_b = EntityDelta::Modified {
            old: a,
            new: b.clone(),
        };
        let b_to_c = EntityDelta::Modified { old: b, new: c };

        let forward =
            content_identity_from_deltas(&[a_to_b.clone(), b_to_c.clone()], &[], &[]).unwrap();
        let reversed = content_identity_from_deltas(&[b_to_c, a_to_b], &[], &[]).unwrap();
        assert_ne!(forward, reversed);
    }

    #[test]
    fn content_identity_rejects_non_finite_semantic_scores() {
        let relation = Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(EntityId::new()),
            dst: GraphNodeId::Entity(EntityId::new()),
            confidence: f32::NAN,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![],
        };
        let error =
            content_identity_from_deltas(&[], &[RelationDelta::Added(relation)], &[]).unwrap_err();
        assert!(error.to_string().contains("non-finite confidence"));
    }

    #[test]
    fn whoami_returns_nonempty_string() {
        let name = whoami();
        assert!(!name.is_empty());
    }
}
