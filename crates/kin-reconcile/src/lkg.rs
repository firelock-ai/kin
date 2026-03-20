// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use kin_model::{Entity, EntityId, Relation, SemanticFingerprint};

/// Last Known Good state for an entity.
///
/// When a file edit produces a broken AST, the entity retains its LKG
/// fingerprint, signature, and relations. The broken parse is noted but
/// does not propagate to dependents.
#[derive(Debug, Clone)]
pub struct LkgEntry {
    pub entity: Entity,
    pub relations: Vec<Relation>,
}

/// Tracks LKG state for all entities. The reconciler consults this when
/// a parse produces errors, falling back to LKG rather than corrupting
/// the graph.
#[derive(Debug, Default, Clone)]
pub struct LkgStore {
    entries: HashMap<EntityId, LkgEntry>,
}

impl LkgStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the current good state of an entity.
    pub fn record(&mut self, entity: Entity, relations: Vec<Relation>) {
        self.entries
            .insert(entity.id, LkgEntry { entity, relations });
    }

    /// Get the LKG state for an entity.
    pub fn get(&self, id: &EntityId) -> Option<&LkgEntry> {
        self.entries.get(id)
    }

    /// Remove an entity's LKG entry (e.g. when it is deleted).
    pub fn remove(&mut self, id: &EntityId) {
        self.entries.remove(id);
    }

    /// Check if a new fingerprint differs from the LKG fingerprint.
    /// Returns true if there is a real semantic change.
    pub fn has_changed(&self, id: &EntityId, new_fingerprint: &SemanticFingerprint) -> bool {
        match self.entries.get(id) {
            Some(entry) => {
                entry.entity.fingerprint.ast_hash != new_fingerprint.ast_hash
                    || entry.entity.fingerprint.signature_hash != new_fingerprint.signature_hash
                    || entry.entity.fingerprint.behavior_hash != new_fingerprint.behavior_hash
            }
            None => true, // No LKG means it's new
        }
    }

    /// Number of tracked entities.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        EntityKind, EntityMetadata, FingerprintAlgorithm, Hash256, LanguageId, Visibility,
    };

    fn test_entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0xaa; 32]),
                signature_hash: Hash256::from_bytes([0xbb; 32]),
                behavior_hash: Hash256::from_bytes([0xcc; 32]),
                stability_score: 0.95,
            },
            file_origin: None,
            span: None,
            signature: "fn test()".to_string(),
            visibility: Visibility::Public,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn record_and_get() {
        let mut store = LkgStore::new();
        let entity = test_entity("foo");
        let id = entity.id;
        store.record(entity, vec![]);

        assert!(store.get(&id).is_some());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn has_changed_detects_difference() {
        let mut store = LkgStore::new();
        let entity = test_entity("bar");
        let id = entity.id;
        store.record(entity, vec![]);

        // Same fingerprint
        let same = SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0xaa; 32]),
            signature_hash: Hash256::from_bytes([0xbb; 32]),
            behavior_hash: Hash256::from_bytes([0xcc; 32]),
            stability_score: 0.95,
        };
        assert!(!store.has_changed(&id, &same));

        // Different fingerprint
        let different = SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0xff; 32]),
            signature_hash: Hash256::from_bytes([0xbb; 32]),
            behavior_hash: Hash256::from_bytes([0xcc; 32]),
            stability_score: 0.95,
        };
        assert!(store.has_changed(&id, &different));
    }

    #[test]
    fn unknown_entity_is_always_changed() {
        let store = LkgStore::new();
        let fp = SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0; 32]),
            signature_hash: Hash256::from_bytes([0; 32]),
            behavior_hash: Hash256::from_bytes([0; 32]),
            stability_score: 0.0,
        };
        assert!(store.has_changed(&EntityId::new(), &fp));
    }

    #[test]
    fn remove_entry() {
        let mut store = LkgStore::new();
        let entity = test_entity("baz");
        let id = entity.id;
        store.record(entity, vec![]);
        store.remove(&id);
        assert!(store.get(&id).is_none());
        assert!(store.is_empty());
    }
}
