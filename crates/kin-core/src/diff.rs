// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Diff and commit construction helpers.
//!
//! Shared utilities for building semantic changes, computing change IDs,
//! and resolving author identity.

#[cfg(test)]
use kin_model::Hash256;
use kin_model::{SemanticChange, SemanticChangeId, TransactionDelta};

use crate::{KinError, Result};

/// Compute the immutable identity of a complete native semantic change.
///
/// The existing `id` field is excluded to avoid a self-reference; every other
/// serialized field participates, including all parents, author, timestamp,
/// message, deltas, provenance links, risk, origin, and admission policy. Native change
/// constructors must use this after assembling the final payload so daemon
/// exact-retry equality and ID authority describe the same bytes.
pub fn compute_semantic_change_id(change: &SemanticChange) -> Result<SemanticChangeId> {
    kin_model::compute_semantic_change_id(change)
        .map_err(|error| KinError::Other(error.to_string()))
}

/// Derive a deterministic content fingerprint from a complete transaction.
///
/// Canonical encodings of independent deltas are sorted before hashing so their
/// insertion order does not affect the result. Multiple deltas for one replay
/// target are rejected rather than assigned an order-dependent identity. Every
/// field of every delta participates, including entity
/// bodies/fingerprints, relation evidence/confidence, and exact tree entry
/// transitions. This is deliberately not an ID-only projection: two
/// immutable `SemanticChange` records must never receive the same ID merely
/// because they touch the same graph IDs or file paths.
pub fn content_identity_from_deltas(delta: &TransactionDelta) -> Result<[u8; 32]> {
    kin_model::content_identity_from_deltas(delta)
        .map_err(|error| KinError::Other(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        relation::GraphNodeId, ArtifactId, AuthorId, ChangeOrigin, Entity, EntityDelta, EntityId,
        EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm, GitObjectId,
        LanguageId, LocatedEntry, Relation, RelationDelta, RelationId, RelationKind,
        RelationOrigin, RepoPath, SemanticFingerprint, Timestamp, TreeDelta, TreeEntry, Visibility,
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

    fn test_change() -> SemanticChange {
        SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: Vec::new(),
            timestamp: Timestamp::from(chrono::DateTime::UNIX_EPOCH),
            author: AuthorId::new("kin"),
            message: "fixture".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            external_reference_deltas: Vec::new(),
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
        let mut original = test_change();
        original.author = AuthorId::new("agent-a");
        let original_id = compute_semantic_change_id(&original).unwrap();

        let mut different_author = original.clone();
        different_author.author = AuthorId::new("agent-b");
        assert_ne!(
            original_id,
            compute_semantic_change_id(&different_author).unwrap()
        );

        let mut different_origin = original.clone();
        different_origin.origin = ChangeOrigin::GitCommit {
            oid: GitObjectId::sha1([0x44; 20]),
        };
        assert_ne!(
            original_id,
            compute_semantic_change_id(&different_origin).unwrap()
        );

        original.id = SemanticChangeId::from_hash(Hash256::from_bytes([0x55; 32]));
        assert_eq!(original_id, compute_semantic_change_id(&original).unwrap());
    }

    #[test]
    fn semantic_change_v6_hash_domain_has_a_pinned_fixture() {
        let mut fixture = test_change();
        fixture.id = SemanticChangeId::from_hash(Hash256::from_bytes([0x55; 32]));
        fixture.timestamp = Timestamp(
            chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        fixture.author = AuthorId::new("fixture");
        fixture.message = "phase two".to_string();

        assert_eq!(
            compute_semantic_change_id(&fixture).unwrap().to_string(),
            "58af6c048bc950d7948d34594072e38e085f5f5de602591be06965b45b95712b",
            "changing the kin-semantic-change-v6 domain or canonical fixture is a wire break"
        );
    }

    #[test]
    fn content_identity_empty_deltas_is_deterministic() {
        let h1 = content_identity_from_deltas(&TransactionDelta::default()).unwrap();
        let h2 = content_identity_from_deltas(&TransactionDelta::default()).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(
            h1,
            [
                0x0b, 0x42, 0xbc, 0x33, 0xa4, 0x38, 0xf5, 0x48, 0xa4, 0xff, 0x32, 0x36, 0xa4, 0x00,
                0x1f, 0xab, 0xe7, 0x85, 0x55, 0x1f, 0xf1, 0xda, 0x5b, 0xa7, 0x41, 0xb8, 0x03, 0x16,
                0x5f, 0xfa, 0x7a, 0x0d,
            ],
            "changing the kin-content-v5 domain or canonical empty payload is a wire break"
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

        let regular_id = content_identity_from_deltas(&TransactionDelta {
            tree_deltas: vec![regular.clone()],
            ..TransactionDelta::default()
        })
        .unwrap();
        let executable_id = content_identity_from_deltas(&TransactionDelta {
            tree_deltas: vec![executable],
            ..TransactionDelta::default()
        })
        .unwrap();
        let different_old_id = content_identity_from_deltas(&TransactionDelta {
            tree_deltas: vec![different_old],
            ..TransactionDelta::default()
        })
        .unwrap();
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
        let first = content_identity_from_deltas(&TransactionDelta {
            tree_deltas: vec![
                regular.clone(),
                ordered_executable.clone(),
                ordered_different_old.clone(),
            ],
            ..TransactionDelta::default()
        })
        .unwrap();
        let reordered = content_identity_from_deltas(&TransactionDelta {
            tree_deltas: vec![ordered_different_old, regular, ordered_executable],
            ..TransactionDelta::default()
        })
        .unwrap();
        assert_eq!(first, reordered);
    }

    #[test]
    fn content_identity_rejects_duplicate_tree_targets() {
        let artifact_id = ArtifactId(uuid::Uuid::from_u128(4));
        let first_hash = Hash256::from_bytes([1; 32]);
        let second_hash = Hash256::from_bytes([2; 32]);
        let third_hash = Hash256::from_bytes([3; 32]);
        let first = modified_tree(artifact_id, "src/lib.rs", first_hash, second_hash, false);
        let second = modified_tree(artifact_id, "src/lib.rs", second_hash, third_hash, false);

        let error = content_identity_from_deltas(&TransactionDelta {
            tree_deltas: vec![first, second],
            ..TransactionDelta::default()
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("more than one delta for artifact"));
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

        let first = content_identity_from_deltas(&TransactionDelta {
            tree_deltas: vec![delta(first_id, utf8_path.clone())],
            ..TransactionDelta::default()
        })
        .unwrap();
        let other_identity = content_identity_from_deltas(&TransactionDelta {
            tree_deltas: vec![delta(second_id, utf8_path)],
            ..TransactionDelta::default()
        })
        .unwrap();
        let other_path = content_identity_from_deltas(&TransactionDelta {
            tree_deltas: vec![delta(first_id, byte_path)],
            ..TransactionDelta::default()
        })
        .unwrap();

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
    fn content_identity_rejects_identity_changing_entity_modifications() {
        let a = test_entity(EntityId::new(), "a");
        let b = test_entity(EntityId::new(), "b");
        let c = test_entity(EntityId::new(), "c");
        let a_to_b = EntityDelta::Modified {
            old: a,
            new: b.clone(),
        };
        let b_to_c = EntityDelta::Modified { old: b, new: c };

        let error = content_identity_from_deltas(&TransactionDelta {
            entity_deltas: vec![a_to_b, b_to_c],
            ..TransactionDelta::default()
        })
        .unwrap_err();
        assert!(error.to_string().contains("changes identity"));
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
        let error = content_identity_from_deltas(&TransactionDelta {
            relation_deltas: vec![RelationDelta::Added { new: relation }],
            ..TransactionDelta::default()
        })
        .unwrap_err();
        assert!(error.to_string().contains("invalid confidence score"));
    }
}
