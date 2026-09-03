// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use kin_model::{Entity, EntityId, SemanticFingerprint};

/// Last Known Good state for an entity: the fingerprint the reconciler last
/// admitted for it.
///
/// The entry holds a fingerprint and nothing else because a fingerprint is all
/// any reader has ever taken out of this store. [`LkgStore::has_changed`]
/// compares three of its hashes and there is no other read.
///
/// It used to hold a whole owned [`Entity`] and a `Vec<Relation>` beside it. A
/// serving daemon seeds one entry per entity in the repository and keeps the
/// store for its life, so that was a second complete copy of every entity: the
/// name, the signature, the doc summary and two separate allocations of the
/// same file path, none of which anything read. The relations vector had no
/// reader at all and every live call site passed an empty one. The reconcile
/// path also clones this whole store before deriving a transaction, so the copy
/// was duplicated again on every file edit; a fingerprint is plain data, so that
/// snapshot now allocates nothing.
#[derive(Debug, Clone)]
pub struct LkgEntry {
    pub fingerprint: SemanticFingerprint,
    // FALSIFICATION ARM, not for landing: today's shape under a new name, so
    // the guard has to catch an entry that reaches the entity it recorded.
    pub entity: Entity,
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
    ///
    /// Takes the entity by reference and keeps a copy of its fingerprint, so a
    /// caller that already owns an entity does not have to clone it to record
    /// one.
    pub fn record(&mut self, entity: &Entity) {
        self.entries.insert(
            entity.id,
            LkgEntry {
                fingerprint: entity.fingerprint.clone(),
                entity: entity.clone(),
            },
        );
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
                entry.fingerprint.ast_hash != new_fingerprint.ast_hash
                    || entry.fingerprint.signature_hash != new_fingerprint.signature_hash
                    || entry.fingerprint.behavior_hash != new_fingerprint.behavior_hash
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
        EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, Hash256, LanguageId,
        Visibility,
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
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 0.95,
            },
            file_origin: None,
            span: None,
            signature: "fn test()".to_string(),
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
    fn record_and_get() {
        let mut store = LkgStore::new();
        let entity = test_entity("foo");
        let id = entity.id;
        store.record(&entity);

        assert!(store.get(&id).is_some());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn has_changed_detects_difference() {
        let mut store = LkgStore::new();
        let entity = test_entity("bar");
        let id = entity.id;
        store.record(&entity);

        // Same fingerprint
        let same = SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0xaa; 32]),
            signature_hash: Hash256::from_bytes([0xbb; 32]),
            behavior_hash: Hash256::from_bytes([0xcc; 32]),
            equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
            stability_score: 0.95,
        };
        assert!(!store.has_changed(&id, &same));

        // Different fingerprint
        let different = SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0xff; 32]),
            signature_hash: Hash256::from_bytes([0xbb; 32]),
            behavior_hash: Hash256::from_bytes([0xcc; 32]),
            equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
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
            equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
            stability_score: 0.0,
        };
        assert!(store.has_changed(&EntityId::new(), &fp));
    }

    #[test]
    fn remove_entry() {
        let mut store = LkgStore::new();
        let entity = test_entity("baz");
        let id = entity.id;
        store.record(&entity);
        store.remove(&id);
        assert!(store.get(&id).is_none());
        assert!(store.is_empty());
    }

    /// The entry is exactly the fingerprint it holds and nothing beside it,
    /// which is the property the daemon's retained footprint rests on. An
    /// `Entity`, a `String` or a `Vec` back on this struct moves the size and
    /// fails here. The bytes the entry does not reach are proved separately, by
    /// the allocator guard in `tests/lkg_retained_bytes.rs`.
    #[test]
    fn an_entry_is_exactly_a_fingerprint() {
        assert_eq!(
            std::mem::size_of::<LkgEntry>(),
            std::mem::size_of::<SemanticFingerprint>(),
            "an entry must be exactly the fingerprint it holds"
        );
    }

    /// Recording an entity twice under the same id keeps one entry, so a
    /// reconcile loop that re-records unchanged entities cannot grow the store.
    #[test]
    fn re_recording_an_entity_does_not_grow_the_store() {
        let mut store = LkgStore::new();
        let entity = test_entity("qux");
        store.record(&entity);
        store.record(&entity);
        store.record(&entity);
        assert_eq!(store.len(), 1);
    }
}
