// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Canonical identities for immutable repository objects.
//!
//! Change identity belongs in the shared model boundary, not in one producer.
//! Every store and transport can therefore recompute an incoming
//! [`SemanticChange`](crate::SemanticChange) before admitting it.

use std::collections::HashSet;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    Entity, EntityDelta, Hash256, ModelError, Relation, RelationDelta, Result, SemanticChange,
    SemanticChangeId, TreeDelta,
};

/// Compute the immutable identity of a complete native semantic change.
///
/// The existing `id` field is excluded to avoid a self-reference; every other
/// serialized field participates, including parents, author, timestamp,
/// message, exact repository-tree transitions, semantic deltas, provenance,
/// risk, and authored branch.
pub fn compute_semantic_change_id(change: &SemanticChange) -> Result<SemanticChangeId> {
    // Reuse delta validation so non-finite semantic scores cannot enter a
    // canonical identity through this higher-level path.
    let _ = content_identity_from_deltas(
        &change.entity_deltas,
        &change.relation_deltas,
        &change.tree_deltas,
    )?;

    let mut payload = serde_json::to_value(change).map_err(serialization)?;
    let fields = payload.as_object_mut().ok_or_else(|| {
        ModelError::InvalidOperation(
            "semantic change identity payload is not an object".to_string(),
        )
    })?;
    if fields.remove("id").is_none() {
        return Err(ModelError::InvalidOperation(
            "semantic change identity payload has no id field".to_string(),
        ));
    }
    let mut canonical = Vec::new();
    append_canonical_json(&mut canonical, &payload)?;

    let mut hasher = Sha256::new();
    hasher.update(b"kin-semantic-change-v5\0");
    append_len_prefixed_hash_field(&mut hasher, &canonical)?;
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Ok(SemanticChangeId::from_hash(Hash256::from_bytes(bytes)))
}

/// Reject an incoming change whose declared identity does not match its
/// complete immutable payload.
pub fn validate_semantic_change_id(change: &SemanticChange) -> Result<()> {
    let computed = compute_semantic_change_id(change)?;
    if computed == change.id {
        return Ok(());
    }
    Err(ModelError::InvalidOperation(format!(
        "semantic change {} declares an identity that recomputes to {}",
        change.id, computed
    )))
}

/// Derive a deterministic content fingerprint from complete delta payloads.
///
/// Canonical encodings of independent deltas are sorted before hashing so
/// insertion order does not affect the result. When deltas overlap a replay
/// target, order remains part of the identity because replay is order-sensitive.
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
    hasher.update(b"kin-content-v4\0");
    append_payload_slice(&mut hasher, b"entities", &entity_payloads)?;
    append_payload_slice(&mut hasher, b"relations", &relation_payloads)?;
    append_payload_slice(&mut hasher, b"tree", &tree_payloads)?;
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Ok(bytes)
}

fn entity_deltas_have_overlapping_targets(entity_deltas: &[EntityDelta]) -> bool {
    let mut targets = HashSet::with_capacity(entity_deltas.len());
    for delta in entity_deltas {
        match delta {
            EntityDelta::Added(entity) => {
                if !targets.insert(entity.id) {
                    return true;
                }
            }
            EntityDelta::Modified { old, new } => {
                if !targets.insert(old.id) || (new.id != old.id && !targets.insert(new.id)) {
                    return true;
                }
            }
            EntityDelta::Removed(id) => {
                if !targets.insert(*id) {
                    return true;
                }
            }
        }
    }
    false
}

fn relation_deltas_have_overlapping_targets(relation_deltas: &[RelationDelta]) -> bool {
    let mut targets = HashSet::with_capacity(relation_deltas.len());
    for delta in relation_deltas {
        let target = match delta {
            RelationDelta::Added(relation) => relation.id,
            RelationDelta::Removed(id) => *id,
        };
        if !targets.insert(target) {
            return true;
        }
    }
    false
}

fn tree_deltas_have_overlapping_targets(tree_deltas: &[TreeDelta]) -> bool {
    let mut targets = HashSet::with_capacity(tree_deltas.len());
    tree_deltas
        .iter()
        .any(|delta| !targets.insert(delta.artifact_id()))
}

fn validate_entity_numbers(entity: &Entity) -> Result<()> {
    if entity.fingerprint.stability_score.is_finite() {
        return Ok(());
    }
    Err(ModelError::InvalidOperation(format!(
        "entity {} has a non-finite fingerprint stability score",
        entity.id
    )))
}

fn validate_relation_numbers(relation: &Relation) -> Result<()> {
    if relation.confidence.is_finite() {
        return Ok(());
    }
    Err(ModelError::InvalidOperation(format!(
        "relation {} has a non-finite confidence score",
        relation.id
    )))
}

fn canonical_payloads<T: Serialize>(values: &[T]) -> Result<Vec<Vec<u8>>> {
    values
        .iter()
        .map(|value| {
            let value = serde_json::to_value(value).map_err(serialization)?;
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
            .map_err(|_| {
                ModelError::InvalidOperation("change delta count exceeds u64".to_string())
            })?
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
            .map_err(|_| {
                ModelError::InvalidOperation("canonical change field exceeds u64".to_string())
            })?
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
                    .map_err(|_| {
                        ModelError::InvalidOperation("canonical array exceeds u64".to_string())
                    })?
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
                    .map_err(|_| {
                        ModelError::InvalidOperation("canonical object exceeds u64".to_string())
                    })?
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
            .map_err(|_| ModelError::InvalidOperation("canonical value exceeds u64".to_string()))?
            .to_le_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}

fn serialization(error: serde_json::Error) -> ModelError {
    ModelError::Serialization(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorId, BranchName, Timestamp};
    use chrono::{TimeZone, Utc};

    fn empty_change() -> SemanticChange {
        SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            parents: Vec::new(),
            timestamp: Timestamp::from(
                Utc.timestamp_millis_opt(1_700_000_000_000)
                    .single()
                    .unwrap(),
            ),
            author: AuthorId::new("identity-test"),
            message: "identity-bearing change".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            authored_on: None,
        }
    }

    #[test]
    fn declared_id_is_excluded_but_every_payload_field_participates() {
        let original = empty_change();
        let expected = compute_semantic_change_id(&original).unwrap();

        let mut different_declared_id = original.clone();
        different_declared_id.id = SemanticChangeId::from_hash(Hash256::from_bytes([9; 32]));
        assert_eq!(
            compute_semantic_change_id(&different_declared_id).unwrap(),
            expected
        );

        let mut different_message = original;
        different_message.message.push('!');
        assert_ne!(
            compute_semantic_change_id(&different_message).unwrap(),
            expected
        );
    }

    #[test]
    fn validation_rejects_spoofed_and_accepts_recomputed_identity() {
        let mut change = empty_change();
        let error = validate_semantic_change_id(&change).unwrap_err();
        assert!(error.to_string().contains("recomputes to"));

        change.id = compute_semantic_change_id(&change).unwrap();
        validate_semantic_change_id(&change).unwrap();
    }

    #[test]
    fn semantic_change_v5_hash_domain_has_a_pinned_fixture() {
        let mut fixture = empty_change();
        fixture.id = SemanticChangeId::from_hash(Hash256::from_bytes([0x55; 32]));
        fixture.timestamp = Timestamp::from(
            chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
                .unwrap()
                .with_timezone(&Utc),
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
}
