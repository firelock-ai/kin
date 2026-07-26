// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Diff and commit construction helpers.
//!
//! Shared utilities for building semantic changes, computing change IDs,
//! and resolving author identity.

use std::collections::HashSet;

use kin_model::{
    Entity, EntityDelta, Hash256, Relation, RelationDelta, SemanticChange, SemanticChangeId,
    TreeDelta,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{KinError, Result};

/// Compute the immutable identity of a complete native semantic change.
///
/// The existing `id` field is excluded to avoid a self-reference; every other
/// serialized field participates, including all parents, author, timestamp,
/// message, deltas, provenance links, risk, and authored branch. Native change
/// constructors must use this after assembling the final payload so daemon
/// exact-retry equality and ID authority describe the same bytes.
pub fn compute_semantic_change_id(change: &SemanticChange) -> Result<SemanticChangeId> {
    // Reuse delta validation so non-finite semantic scores cannot enter a
    // canonical JSON identity through this higher-level path.
    let _ = content_identity_from_deltas(
        &change.entity_deltas,
        &change.relation_deltas,
        &change.tree_deltas,
    )?;

    let mut payload = serde_json::to_value(change)?;
    let fields = payload.as_object_mut().ok_or_else(|| {
        KinError::Other("semantic change identity payload is not an object".to_string())
    })?;
    if fields.remove("id").is_none() {
        return Err(KinError::Other(
            "semantic change identity payload has no id field".to_string(),
        ));
    }
    let mut canonical = Vec::new();
    append_canonical_json(&mut canonical, &payload)?;

    let mut hasher = Sha256::new();
    hasher.update(b"kin-semantic-change-v4\0");
    append_len_prefixed_hash_field(&mut hasher, &canonical)?;
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Ok(SemanticChangeId::from_hash(Hash256::from_bytes(bytes)))
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
    for delta in entity_deltas {
        match delta {
            EntityDelta::Added(entity) => validate_entity_numbers(entity)?,
            EntityDelta::Modified { old, new } => {
                validate_entity_numbers(old)?;
                validate_entity_numbers(new)?;
            }
            EntityDelta::Removed(_) => {}
        }
    }
    for delta in relation_deltas {
        if let RelationDelta::Added(relation) = delta {
            validate_relation_numbers(relation)?;
        }
    }

    let entity_payloads = replay_equivalent_payloads(
        entity_deltas,
        entity_deltas_have_overlapping_targets(entity_deltas),
    )?;
    let relation_payloads = replay_equivalent_payloads(
        relation_deltas,
        relation_deltas_have_overlapping_targets(relation_deltas),
    )?;
    let tree_payloads = replay_equivalent_payloads(
        tree_deltas,
        tree_deltas_have_overlapping_targets(tree_deltas),
    )?;

    let mut hasher = Sha256::new();
    hasher.update(b"kin-content-v3\0");
    append_payload_slice(&mut hasher, b"entities", &entity_payloads)?;
    append_payload_slice(&mut hasher, b"relations", &relation_payloads)?;
    append_payload_slice(&mut hasher, b"tree", &tree_payloads)?;
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Ok(bytes)
}

fn entity_deltas_have_overlapping_targets(entity_deltas: &[EntityDelta]) -> bool {
    let mut entity_targets = HashSet::with_capacity(entity_deltas.len());
    for delta in entity_deltas {
        match delta {
            EntityDelta::Added(entity) => {
                if !entity_targets.insert(entity.id) {
                    return true;
                }
            }
            EntityDelta::Modified { old, new } => {
                if !entity_targets.insert(old.id)
                    || (new.id != old.id && !entity_targets.insert(new.id))
                {
                    return true;
                }
            }
            EntityDelta::Removed(id) => {
                if !entity_targets.insert(*id) {
                    return true;
                }
            }
        }
    }
    false
}

fn relation_deltas_have_overlapping_targets(relation_deltas: &[RelationDelta]) -> bool {
    let mut relation_targets = HashSet::with_capacity(relation_deltas.len());
    for delta in relation_deltas {
        let target = match delta {
            RelationDelta::Added(relation) => relation.id,
            RelationDelta::Removed(id) => *id,
        };
        if !relation_targets.insert(target) {
            return true;
        }
    }
    false
}

fn tree_deltas_have_overlapping_targets(tree_deltas: &[TreeDelta]) -> bool {
    let mut tree_targets = HashSet::with_capacity(tree_deltas.len());
    for delta in tree_deltas {
        if !tree_targets.insert(delta.file_id().clone()) {
            return true;
        }
    }
    false
}

fn validate_entity_numbers(entity: &Entity) -> Result<()> {
    if !entity.fingerprint.stability_score.is_finite() {
        return Err(KinError::Other(format!(
            "entity {} has a non-finite fingerprint stability score",
            entity.id
        )));
    }
    Ok(())
}

fn validate_relation_numbers(relation: &Relation) -> Result<()> {
    if !relation.confidence.is_finite() {
        return Err(KinError::Other(format!(
            "relation {} has a non-finite confidence score",
            relation.id
        )));
    }
    Ok(())
}

fn canonical_payloads<T: Serialize>(values: &[T]) -> Result<Vec<Vec<u8>>> {
    values
        .iter()
        .map(|value| {
            let value = serde_json::to_value(value)?;
            let mut encoded = Vec::new();
            append_canonical_json(&mut encoded, &value)?;
            Ok(encoded)
        })
        .collect()
}

fn replay_equivalent_payloads<T: Serialize>(
    values: &[T],
    order_matters: bool,
) -> Result<Vec<Vec<u8>>> {
    let mut payloads = canonical_payloads(values)?;
    if !order_matters {
        payloads.sort_unstable();
    }
    Ok(payloads)
}

fn append_payload_slice(hasher: &mut Sha256, label: &[u8], payloads: &[Vec<u8>]) -> Result<()> {
    append_len_prefixed_hash_field(hasher, label)?;
    hasher.update(
        u64::try_from(payloads.len())
            .map_err(|_| KinError::Other("change delta count exceeds u64".to_string()))?
            .to_le_bytes(),
    );
    for payload in payloads {
        append_len_prefixed_hash_field(hasher, payload)?;
    }
    Ok(())
}

fn append_len_prefixed_hash_field(hasher: &mut Sha256, value: &[u8]) -> Result<()> {
    hasher.update(
        u64::try_from(value.len())
            .map_err(|_| KinError::Other("canonical change field exceeds u64".to_string()))?
            .to_le_bytes(),
    );
    hasher.update(value);
    Ok(())
}

fn append_canonical_json(output: &mut Vec<u8>, value: &serde_json::Value) -> Result<()> {
    match value {
        serde_json::Value::Null => output.push(0),
        serde_json::Value::Bool(value) => {
            output.push(1);
            output.push(u8::from(*value));
        }
        serde_json::Value::Number(value) => {
            output.push(2);
            append_len_prefixed_vec_field(output, value.to_string().as_bytes())?;
        }
        serde_json::Value::String(value) => {
            output.push(3);
            append_len_prefixed_vec_field(output, value.as_bytes())?;
        }
        serde_json::Value::Array(values) => {
            output.push(4);
            output.extend_from_slice(
                &u64::try_from(values.len())
                    .map_err(|_| KinError::Other("canonical array exceeds u64".to_string()))?
                    .to_le_bytes(),
            );
            for value in values {
                append_canonical_json(output, value)?;
            }
        }
        serde_json::Value::Object(values) => {
            output.push(5);
            output.extend_from_slice(
                &u64::try_from(values.len())
                    .map_err(|_| KinError::Other("canonical object exceeds u64".to_string()))?
                    .to_le_bytes(),
            );
            let mut values: Vec<_> = values.iter().collect();
            values.sort_by(|left, right| left.0.cmp(right.0));
            for (key, value) in values {
                append_len_prefixed_vec_field(output, key.as_bytes())?;
                append_canonical_json(output, value)?;
            }
        }
    }
    Ok(())
}

fn append_len_prefixed_vec_field(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    output.extend_from_slice(
        &u64::try_from(value.len())
            .map_err(|_| KinError::Other("canonical value exceeds u64".to_string()))?
            .to_le_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
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
        relation::GraphNodeId, ArtifactDeltaKind, AuthorId, BranchName, EntityId, EntityKind,
        EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm, LanguageId, RelationId,
        RelationKind, RelationOrigin, SemanticFingerprint, Visibility,
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
    fn content_identity_empty_deltas_is_deterministic() {
        let h1 = content_identity_from_deltas(&[], &[], &[]).unwrap();
        let h2 = content_identity_from_deltas(&[], &[], &[]).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn content_identity_binds_complete_artifact_delta_and_ignores_slice_order() {
        let regular = ArtifactDelta {
            file_id: FilePathId::new("bin/kin"),
            kind: ArtifactDeltaKind::ModifiedRegularFile,
            old_hash: Some(Hash256::from_bytes([1; 32])),
            new_hash: Some(Hash256::from_bytes([2; 32])),
        };
        let executable = ArtifactDelta {
            kind: ArtifactDeltaKind::ModifiedExecutableFile,
            ..regular.clone()
        };
        let different_old = ArtifactDelta {
            old_hash: Some(Hash256::from_bytes([3; 32])),
            ..regular.clone()
        };

        let regular_id =
            content_identity_from_deltas(&[], &[], std::slice::from_ref(&regular)).unwrap();
        let executable_id =
            content_identity_from_deltas(&[], &[], std::slice::from_ref(&executable)).unwrap();
        let different_old_id =
            content_identity_from_deltas(&[], &[], std::slice::from_ref(&different_old)).unwrap();
        assert_ne!(regular_id, executable_id);
        assert_ne!(regular_id, different_old_id);

        let ordered_executable = ArtifactDelta {
            file_id: FilePathId::new("bin/kin-exec"),
            ..executable
        };
        let ordered_different_old = ArtifactDelta {
            file_id: FilePathId::new("bin/kin-old"),
            ..different_old
        };
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
    fn content_identity_binds_order_for_duplicate_artifact_targets() {
        let first = ArtifactDelta {
            file_id: FilePathId::new("src/lib.rs"),
            kind: ArtifactDeltaKind::ModifiedRegularFile,
            old_hash: Some(Hash256::from_bytes([1; 32])),
            new_hash: Some(Hash256::from_bytes([2; 32])),
        };
        let second = ArtifactDelta {
            new_hash: Some(Hash256::from_bytes([3; 32])),
            ..first.clone()
        };

        let forward =
            content_identity_from_deltas(&[], &[], &[first.clone(), second.clone()]).unwrap();
        let reversed = content_identity_from_deltas(&[], &[], &[second, first]).unwrap();
        assert_ne!(forward, reversed);
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
