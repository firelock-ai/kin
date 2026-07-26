// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Canonical identities for immutable repository objects.
//!
//! Change identity belongs in the shared model boundary, not in one producer.
//! Every store and transport can therefore recompute an incoming
//! [`SemanticChange`](crate::SemanticChange) before admitting it.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::{
    Entity, EntityDelta, Hash256, ModelError, Relation, RelationDelta, Result, SemanticChange,
    SemanticChangeId, TransactionDelta, TreeDelta,
};

/// Compute the immutable v6 identity of a complete semantic change.
///
/// The existing `id` field is excluded to avoid self-reference. Independent
/// deltas are sorted by stable target identity, so producer iteration order is
/// irrelevant. All remaining immutable fields participate, including exact
/// change origin and admission-policy transitions.
pub fn compute_semantic_change_id(change: &SemanticChange) -> Result<SemanticChangeId> {
    let delta = change.transaction_delta();
    validate_transaction_delta(&delta)?;

    let mut canonical_change = change.clone();
    canonical_change
        .entity_deltas
        .sort_by_key(EntityDelta::target_id);
    canonical_change
        .relation_deltas
        .sort_by_key(RelationDelta::target_id);
    canonical_change
        .tree_deltas
        .sort_by_key(TreeDelta::artifact_id);

    let mut payload = serde_json::to_value(&canonical_change).map_err(serialization)?;
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
    hasher.update(b"kin-semantic-change-v6\0");
    append_len_prefixed_hash_field(&mut hasher, &canonical)?;
    let result = hasher.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&result);
    Ok(SemanticChangeId::from_hash(Hash256::from_bytes(bytes)))
}

/// Reject an incoming change whose declared identity does not match its
/// complete immutable payload.
pub fn validate_semantic_change_id(change: &SemanticChange) -> Result<()> {
    if change.parents.contains(&change.id) {
        return Err(ModelError::InvalidOperation(format!(
            "semantic change {} cannot name itself as a parent",
            change.id
        )));
    }
    let computed = compute_semantic_change_id(change)?;
    if computed == change.id {
        return Ok(());
    }
    Err(ModelError::InvalidOperation(format!(
        "semantic change {} declares an identity that recomputes to {}",
        change.id, computed
    )))
}

/// Validate exact, self-inverting deltas before replay or identity derivation.
///
/// One transaction may target each entity, relation, or artifact at most once.
/// Modified deltas preserve identity and carry two different complete states.
pub fn validate_transaction_delta(delta: &TransactionDelta) -> Result<()> {
    let mut entity_targets = BTreeSet::new();
    for entity_delta in &delta.entity_deltas {
        let target = entity_delta.target_id();
        if !entity_targets.insert(target) {
            return Err(ModelError::InvalidOperation(format!(
                "transaction contains more than one delta for entity {target}"
            )));
        }
        match entity_delta {
            EntityDelta::Added { new } => validate_entity_numbers(new)?,
            EntityDelta::Modified { old, new } => {
                validate_entity_numbers(old)?;
                validate_entity_numbers(new)?;
                if old.id != new.id {
                    return Err(ModelError::InvalidOperation(format!(
                        "entity modification changes identity from {} to {}",
                        old.id, new.id
                    )));
                }
                if old == new {
                    return Err(ModelError::InvalidOperation(format!(
                        "entity {} modification is a no-op",
                        old.id
                    )));
                }
            }
            EntityDelta::Removed { old } => validate_entity_numbers(old)?,
        }
    }

    let mut relation_targets = BTreeSet::new();
    for relation_delta in &delta.relation_deltas {
        let target = relation_delta.target_id();
        if !relation_targets.insert(target) {
            return Err(ModelError::InvalidOperation(format!(
                "transaction contains more than one delta for relation {target}"
            )));
        }
        match relation_delta {
            RelationDelta::Added { new } => validate_relation_numbers(new)?,
            RelationDelta::Modified { old, new } => {
                validate_relation_numbers(old)?;
                validate_relation_numbers(new)?;
                if old.id != new.id {
                    return Err(ModelError::InvalidOperation(format!(
                        "relation modification changes identity from {} to {}",
                        old.id, new.id
                    )));
                }
                if old == new {
                    return Err(ModelError::InvalidOperation(format!(
                        "relation {} modification is a no-op",
                        old.id
                    )));
                }
            }
            RelationDelta::Removed { old } => validate_relation_numbers(old)?,
        }
    }

    let mut tree_targets = BTreeSet::new();
    for tree_delta in &delta.tree_deltas {
        let target = tree_delta.artifact_id();
        if !tree_targets.insert(target) {
            return Err(ModelError::InvalidOperation(format!(
                "transaction contains more than one delta for artifact {target:?}"
            )));
        }
        if let TreeDelta::Updated { old, new, .. } = tree_delta {
            if old == new {
                return Err(ModelError::InvalidOperation(format!(
                    "artifact {target:?} update is a no-op"
                )));
            }
        }
    }

    if let Some(policy_delta) = &delta.admission_policy_delta {
        policy_delta.validate()?;
    }
    Ok(())
}

/// Derive a deterministic content fingerprint from a complete transaction.
pub fn content_identity_from_deltas(delta: &TransactionDelta) -> Result<[u8; 32]> {
    validate_transaction_delta(delta)?;

    let mut canonical = delta.clone();
    canonical.entity_deltas.sort_by_key(EntityDelta::target_id);
    canonical
        .relation_deltas
        .sort_by_key(RelationDelta::target_id);
    canonical.tree_deltas.sort_by_key(TreeDelta::artifact_id);

    let encoded = canonical_json_bytes(&canonical)?;

    let mut hasher = Sha256::new();
    hasher.update(b"kin-content-v5\0");
    append_len_prefixed_hash_field(&mut hasher, &encoded)?;
    let result = hasher.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&result);
    Ok(bytes)
}

fn validate_entity_numbers(entity: &Entity) -> Result<()> {
    let score = entity.fingerprint.stability_score;
    if score.is_finite() && (0.0..=1.0).contains(&score) {
        return Ok(());
    }
    Err(ModelError::InvalidOperation(format!(
        "entity {} has invalid fingerprint stability score {score}",
        entity.id
    )))
}

fn validate_relation_numbers(relation: &Relation) -> Result<()> {
    if relation.confidence.is_finite() && (0.0..=1.0).contains(&relation.confidence) {
        return Ok(());
    }
    Err(ModelError::InvalidOperation(format!(
        "relation {} has invalid confidence score {}",
        relation.id, relation.confidence
    )))
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

pub(crate) fn canonical_json_bytes(value: &impl serde::Serialize) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).map_err(serialization)?;
    let mut encoded = Vec::new();
    append_canonical_json(&mut encoded, &value)?;
    Ok(encoded)
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
    use crate::{
        AuthorId, ChangeOrigin, GitObjectId, LocatedEntry, RepoPath, Timestamp, TreeEntry,
    };
    use chrono::{TimeZone, Utc};

    fn empty_change() -> SemanticChange {
        SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
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
            admission_policy_delta: None,
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        }
    }

    fn tree_delta(id: u128, path: &str, byte: u8) -> TreeDelta {
        TreeDelta::Added {
            artifact_id: crate::ArtifactId(uuid::Uuid::from_u128(id)),
            new: LocatedEntry::new(
                RepoPath::from_utf8(path).unwrap(),
                TreeEntry::blob(Hash256::from_bytes([byte; 32]), false),
            ),
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
    fn change_origin_participates_in_v6_identity() {
        let native = empty_change();
        let mut imported = native.clone();
        imported.origin = ChangeOrigin::GitCommit {
            oid: GitObjectId::sha1([0x91; 20]),
        };

        assert_ne!(
            compute_semantic_change_id(&native).unwrap(),
            compute_semantic_change_id(&imported).unwrap()
        );
    }

    #[test]
    fn octopus_and_repeated_git_parents_preserve_exact_order() {
        let first = SemanticChangeId::from_hash(Hash256::from_bytes([0x31; 32]));
        let second = SemanticChangeId::from_hash(Hash256::from_bytes([0x32; 32]));
        let third = SemanticChangeId::from_hash(Hash256::from_bytes([0x33; 32]));
        let mut change = empty_change();
        change.parents = vec![first, second, first, third];

        let identity = compute_semantic_change_id(&change).unwrap();
        change.id = identity;
        validate_semantic_change_id(&change).unwrap();

        let encoded = serde_json::to_vec(&change).unwrap();
        let decoded: SemanticChange = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.parents, vec![first, second, first, third]);

        let mut reordered = decoded;
        reordered.parents.swap(0, 1);
        assert_ne!(
            compute_semantic_change_id(&reordered).unwrap(),
            identity,
            "parent order participates in identity"
        );
    }

    #[test]
    fn independent_delta_order_is_canonical_but_duplicate_targets_are_rejected() {
        let first = tree_delta(1, "Dockerfile", 0x11);
        let second = tree_delta(2, "compose.yaml", 0x22);
        let left = TransactionDelta {
            tree_deltas: vec![first.clone(), second.clone()],
            ..TransactionDelta::default()
        };
        let right = TransactionDelta {
            tree_deltas: vec![second, first.clone()],
            ..TransactionDelta::default()
        };
        assert_eq!(
            content_identity_from_deltas(&left).unwrap(),
            content_identity_from_deltas(&right).unwrap()
        );

        let duplicate = TransactionDelta {
            tree_deltas: vec![
                first.clone(),
                TreeDelta::Removed {
                    artifact_id: first.artifact_id(),
                    old: first.new_state().unwrap().clone(),
                },
            ],
            ..TransactionDelta::default()
        };
        assert!(validate_transaction_delta(&duplicate).is_err());
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
    fn semantic_change_v6_hash_domain_has_a_pinned_fixture() {
        let mut fixture = empty_change();
        fixture.id = SemanticChangeId::from_hash(Hash256::from_bytes([0x55; 32]));
        fixture.timestamp = Timestamp::from(
            chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        fixture.author = AuthorId::new("fixture");
        fixture.message = "phase two".to_string();
        fixture.origin = ChangeOrigin::GitCommit {
            oid: GitObjectId::sha1([0x66; 20]),
        };

        assert_eq!(
            compute_semantic_change_id(&fixture).unwrap().to_string(),
            "f455b244cffbf4eee002e607b19926cefb575e2549fdc21ecbbb956a2eed9fad",
            "changing the kin-semantic-change-v6 domain or canonical fixture is a wire break"
        );
    }
}
