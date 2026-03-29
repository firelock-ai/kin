// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Bridge between kin-model's `SemanticChange` (entity-level deltas in the
//! change DAG) and kin-remote's sync protocol types (`SemanticDelta`, `LocalMutation`).
//!
//! This module enables extracting sync protocol payloads from the semantic
//! change history, and converting received deltas back into graph mutations.

use kin_model::{EntityDelta, SemanticChange};
use uuid::Uuid;

use crate::sync_types::{FieldDiff, LocalMutation, SemanticDelta};

/// Extract `SemanticDelta` entries from a `SemanticChange`.
///
/// Each entity delta within the change becomes a separate `SemanticDelta`
/// suitable for wire transfer via the sync protocol. This bridges the
/// change DAG (kin-model) to the sync protocol (kin-remote).
pub fn semantic_deltas_from_change(change: &SemanticChange) -> Vec<SemanticDelta> {
    let timestamp = change.timestamp.0;
    let actor_id = change.author.0.clone();

    change
        .entity_deltas
        .iter()
        .map(|delta| match delta {
            EntityDelta::Added(entity) => SemanticDelta {
                entity_id: entity.id.to_string(),
                before_hash: None,
                after_hash: format!("{:?}", entity.fingerprint.ast_hash),
                change_set: vec![
                    FieldDiff {
                        field: "name".to_string(),
                        old_value: None,
                        new_value: Some(entity.name.clone()),
                    },
                    FieldDiff {
                        field: "kind".to_string(),
                        old_value: None,
                        new_value: Some(format!("{:?}", entity.kind)),
                    },
                    FieldDiff {
                        field: "signature".to_string(),
                        old_value: None,
                        new_value: Some(entity.signature.clone()),
                    },
                ],
                timestamp,
                actor_id: actor_id.clone(),
            },
            EntityDelta::Modified { old, new } => {
                let mut change_set = Vec::new();
                if old.name != new.name {
                    change_set.push(FieldDiff {
                        field: "name".to_string(),
                        old_value: Some(old.name.clone()),
                        new_value: Some(new.name.clone()),
                    });
                }
                if old.signature != new.signature {
                    change_set.push(FieldDiff {
                        field: "signature".to_string(),
                        old_value: Some(old.signature.clone()),
                        new_value: Some(new.signature.clone()),
                    });
                }
                if old.visibility != new.visibility {
                    change_set.push(FieldDiff {
                        field: "visibility".to_string(),
                        old_value: Some(format!("{:?}", old.visibility)),
                        new_value: Some(format!("{:?}", new.visibility)),
                    });
                }
                if old.doc_summary != new.doc_summary {
                    change_set.push(FieldDiff {
                        field: "doc_summary".to_string(),
                        old_value: old.doc_summary.clone(),
                        new_value: new.doc_summary.clone(),
                    });
                }
                if old.kind != new.kind {
                    change_set.push(FieldDiff {
                        field: "kind".to_string(),
                        old_value: Some(format!("{:?}", old.kind)),
                        new_value: Some(format!("{:?}", new.kind)),
                    });
                }

                SemanticDelta {
                    entity_id: new.id.to_string(),
                    before_hash: Some(format!("{:?}", old.fingerprint.ast_hash)),
                    after_hash: format!("{:?}", new.fingerprint.ast_hash),
                    change_set,
                    timestamp,
                    actor_id: actor_id.clone(),
                }
            }
            EntityDelta::Removed(entity_id) => SemanticDelta {
                entity_id: entity_id.to_string(),
                before_hash: None,
                after_hash: String::new(),
                change_set: vec![FieldDiff {
                    field: "_removed".to_string(),
                    old_value: None,
                    new_value: Some("true".to_string()),
                }],
                timestamp,
                actor_id: actor_id.clone(),
            },
        })
        .collect()
}

/// Convert a `SemanticDelta` into a `LocalMutation` suitable for pushing
/// to a remote via `MutationPusher`.
pub fn mutation_from_delta(delta: &SemanticDelta) -> LocalMutation {
    LocalMutation {
        entity_id: delta.entity_id.clone(),
        mutation_id: Uuid::new_v4(),
        change_set: delta.change_set.clone(),
        base_hash: delta.before_hash.clone(),
        new_hash: delta.after_hash.clone(),
        timestamp: delta.timestamp,
    }
}

/// Extract `LocalMutation` entries from a sequence of `SemanticChange` objects.
///
/// This is the primary entry point for push: given a list of changes
/// between the last sync point and the current head, produce the mutations
/// that should be sent to the remote.
pub fn mutations_from_changes(changes: &[SemanticChange]) -> Vec<LocalMutation> {
    changes
        .iter()
        .flat_map(|change| {
            semantic_deltas_from_change(change)
                .iter()
                .map(mutation_from_delta)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::*;

    fn test_entity(name: &str) -> Entity {
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
            file_origin: Some(FilePathId::new("src/lib.rs")),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn test_change(deltas: Vec<EntityDelta>) -> SemanticChange {
        SemanticChange {
            id: SemanticChangeId(Hash256::from_bytes([0; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId("test-author".to_string()),
            message: "test change".to_string(),
            entity_deltas: deltas,
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        }
    }

    #[test]
    fn added_entity_produces_delta() {
        let entity = test_entity("fn_new");
        let change = test_change(vec![EntityDelta::Added(entity.clone())]);

        let deltas = semantic_deltas_from_change(&change);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].entity_id, entity.id.to_string());
        assert!(deltas[0].before_hash.is_none());
        assert!(!deltas[0].after_hash.is_empty());

        let name_diff = deltas[0]
            .change_set
            .iter()
            .find(|d| d.field == "name")
            .unwrap();
        assert_eq!(name_diff.new_value.as_deref(), Some("fn_new"));
    }

    #[test]
    fn modified_entity_produces_field_diffs() {
        let old = test_entity("fn_old");
        let mut new = old.clone();
        new.name = "fn_renamed".to_string();
        new.signature = "fn fn_renamed()".to_string();

        let change = test_change(vec![EntityDelta::Modified { old, new }]);

        let deltas = semantic_deltas_from_change(&change);
        assert_eq!(deltas.len(), 1);
        assert!(deltas[0].before_hash.is_some());

        let fields: Vec<&str> = deltas[0]
            .change_set
            .iter()
            .map(|d| d.field.as_str())
            .collect();
        assert!(fields.contains(&"name"));
        assert!(fields.contains(&"signature"));
    }

    #[test]
    fn removed_entity_produces_delta() {
        let entity_id = EntityId::new();
        let change = test_change(vec![EntityDelta::Removed(entity_id)]);

        let deltas = semantic_deltas_from_change(&change);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].entity_id, entity_id.to_string());
        assert!(deltas[0].change_set.iter().any(|d| d.field == "_removed"));
    }

    #[test]
    fn mutations_from_changes_flattens() {
        let e1 = test_entity("fn_a");
        let e2 = test_entity("fn_b");

        let change1 = test_change(vec![EntityDelta::Added(e1)]);
        let change2 = test_change(vec![EntityDelta::Added(e2)]);

        let mutations = mutations_from_changes(&[change1, change2]);
        assert_eq!(mutations.len(), 2);
        // Each mutation has a unique ID
        assert_ne!(mutations[0].mutation_id, mutations[1].mutation_id);
    }

    #[test]
    fn mutation_from_delta_preserves_hashes() {
        let entity = test_entity("fn_test");
        let change = test_change(vec![EntityDelta::Added(entity)]);
        let deltas = semantic_deltas_from_change(&change);
        let mutation = mutation_from_delta(&deltas[0]);

        assert_eq!(mutation.entity_id, deltas[0].entity_id);
        assert_eq!(mutation.base_hash, deltas[0].before_hash);
        assert_eq!(mutation.new_hash, deltas[0].after_hash);
    }
}
