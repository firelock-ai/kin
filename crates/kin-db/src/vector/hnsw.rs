use std::path::Path;

use hashbrown::HashMap;
use parking_lot::RwLock;
use usearch::ffi::{IndexOptions, MetricKind, ScalarKind};
use usearch::Index;

use crate::error::KinDbError;
use crate::types::EntityId;

/// A mapping key for usearch. We map EntityId (UUID) → u64 key and back.
struct KeyMap {
    entity_to_key: HashMap<EntityId, u64>,
    key_to_entity: HashMap<u64, EntityId>,
    next_key: u64,
}

impl KeyMap {
    fn new() -> Self {
        Self {
            entity_to_key: HashMap::new(),
            key_to_entity: HashMap::new(),
            next_key: 1,
        }
    }

    fn get_or_insert(&mut self, entity_id: EntityId) -> u64 {
        if let Some(&key) = self.entity_to_key.get(&entity_id) {
            return key;
        }
        let key = self.next_key;
        self.next_key += 1;
        self.entity_to_key.insert(entity_id, key);
        self.key_to_entity.insert(key, entity_id);
        key
    }

    fn get_key(&self, entity_id: &EntityId) -> Option<u64> {
        self.entity_to_key.get(entity_id).copied()
    }

    fn get_entity(&self, key: u64) -> Option<EntityId> {
        self.key_to_entity.get(&key).copied()
    }

    fn remove(&mut self, entity_id: &EntityId) -> Option<u64> {
        if let Some(key) = self.entity_to_key.remove(entity_id) {
            self.key_to_entity.remove(&key);
            Some(key)
        } else {
            None
        }
    }
}

struct VectorIndexInner {
    index: Index,
    keys: KeyMap,
    dimensions: usize,
}

/// HNSW-backed vector similarity index for entity embeddings.
///
/// Wraps usearch for approximate nearest-neighbor search. Each entity
/// can have an optional embedding vector; this index stores and queries them.
pub struct VectorIndex {
    inner: RwLock<VectorIndexInner>,
    /// Optional path for persisting the index to disk.
    persistence_path: RwLock<Option<std::path::PathBuf>>,
}

impl VectorIndex {
    /// Create a new vector index for embeddings of the given dimensionality.
    pub fn new(dimensions: usize) -> Result<Self, KinDbError> {
        let options = IndexOptions {
            dimensions,
            metric: MetricKind::Cos,
            quantization: ScalarKind::F32,
            connectivity: 16,
            expansion_add: 128,
            expansion_search: 64,
            multi: false,
        };

        let index = Index::new(&options)
            .map_err(|e| KinDbError::IndexError(format!("failed to create vector index: {e}")))?;

        index.reserve(1024).map_err(|e| {
            KinDbError::IndexError(format!("failed to reserve vector index capacity: {e}"))
        })?;

        Ok(Self {
            inner: RwLock::new(VectorIndexInner {
                index,
                keys: KeyMap::new(),
                dimensions,
            }),
            persistence_path: RwLock::new(None),
        })
    }

    /// The dimensionality of vectors in this index.
    pub fn dimensions(&self) -> usize {
        self.inner.read().dimensions
    }

    /// Number of vectors currently indexed.
    pub fn len(&self) -> usize {
        self.inner.read().keys.entity_to_key.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Add or update the embedding for an entity.
    ///
    /// The embedding slice must have exactly `dimensions` elements.
    pub fn upsert(&self, entity_id: EntityId, embedding: &[f32]) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();

        if embedding.len() != inner.dimensions {
            return Err(KinDbError::IndexError(format!(
                "embedding dimension mismatch: expected {}, got {}",
                inner.dimensions,
                embedding.len()
            )));
        }

        // Remove old vector if present
        if let Some(old_key) = inner.keys.get_key(&entity_id) {
            let _ = inner.index.remove(old_key);
        }

        let key = inner.keys.get_or_insert(entity_id);

        // Auto-grow capacity if needed
        let current_cap = inner.index.capacity();
        let current_len = inner.index.size();
        if current_len >= current_cap {
            let new_cap = (current_cap * 2).max(1024);
            inner
                .index
                .reserve(new_cap)
                .map_err(|e| KinDbError::IndexError(format!("failed to reserve capacity: {e}")))?;
        }

        inner
            .index
            .add(key, embedding)
            .map_err(|e| KinDbError::IndexError(format!("failed to add vector: {e}")))?;

        Ok(())
    }

    /// Remove the embedding for an entity.
    pub fn remove(&self, entity_id: &EntityId) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        if let Some(key) = inner.keys.remove(entity_id) {
            inner
                .index
                .remove(key)
                .map_err(|e| KinDbError::IndexError(format!("failed to remove vector: {e}")))?;
        }
        Ok(())
    }

    /// Search for the `limit` most similar entities to the given embedding.
    ///
    /// Returns pairs of (EntityId, distance_score) sorted by similarity.
    pub fn search_similar(
        &self,
        embedding: &[f32],
        limit: usize,
    ) -> Result<Vec<(EntityId, f32)>, KinDbError> {
        let inner = self.inner.read();

        if embedding.len() != inner.dimensions {
            return Err(KinDbError::IndexError(format!(
                "query dimension mismatch: expected {}, got {}",
                inner.dimensions,
                embedding.len()
            )));
        }

        if inner.keys.entity_to_key.is_empty() {
            return Ok(Vec::new());
        }

        let matches = inner
            .index
            .search(embedding, limit)
            .map_err(|e| KinDbError::IndexError(format!("vector search failed: {e}")))?;

        let mut results = Vec::with_capacity(matches.keys.len());
        for (key, distance) in matches.keys.iter().zip(matches.distances.iter()) {
            if let Some(entity_id) = inner.keys.get_entity(*key) {
                results.push((entity_id, *distance));
            }
        }

        Ok(results)
    }

    /// Set the persistence path for this index.
    pub fn set_persistence_path(&self, path: impl Into<std::path::PathBuf>) {
        *self.persistence_path.write() = Some(path.into());
    }

    /// Save the HNSW index to disk.
    ///
    /// Persists the usearch index structure. The key mapping is not included
    /// in the usearch file — callers must save/restore the key map separately
    /// if needed, or reconstruct it from the graph.
    pub fn save(&self, path: &Path) -> Result<(), KinDbError> {
        let inner = self.inner.read();
        let path_str = path
            .to_str()
            .ok_or_else(|| KinDbError::IndexError(format!("non-UTF-8 path: {}", path.display())))?;
        inner
            .index
            .save(path_str)
            .map_err(|e| KinDbError::IndexError(format!("failed to save vector index: {e}")))?;
        Ok(())
    }

    /// Load a previously saved HNSW index from disk.
    ///
    /// Returns a new `VectorIndex` with the loaded index data.
    /// The key mapping must be reconstructed by the caller (e.g., by
    /// re-upserting entities from the graph).
    pub fn load(path: &Path, dimensions: usize) -> Result<Self, KinDbError> {
        let options = IndexOptions {
            dimensions,
            metric: MetricKind::Cos,
            quantization: ScalarKind::F32,
            connectivity: 16,
            expansion_add: 128,
            expansion_search: 64,
            multi: false,
        };

        let index = Index::new(&options)
            .map_err(|e| KinDbError::IndexError(format!("failed to create vector index: {e}")))?;

        let path_str = path
            .to_str()
            .ok_or_else(|| KinDbError::IndexError(format!("non-UTF-8 path: {}", path.display())))?;
        index.load(path_str).map_err(|e| {
            KinDbError::IndexError(format!(
                "failed to load vector index from {}: {e}",
                path.display()
            ))
        })?;

        Ok(Self {
            inner: RwLock::new(VectorIndexInner {
                index,
                keys: KeyMap::new(),
                dimensions,
            }),
            persistence_path: RwLock::new(Some(path.to_path_buf())),
        })
    }
}

impl std::fmt::Debug for VectorIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.read();
        f.debug_struct("VectorIndex")
            .field("dimensions", &inner.dimensions)
            .field("vectors", &inner.keys.entity_to_key.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_add_vectors() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();
        let e2 = EntityId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e2, &[0.0, 1.0, 0.0, 0.0]).unwrap();

        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn dimension_mismatch_rejected() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();

        let result = idx.upsert(e1, &[1.0, 0.0]);
        assert!(result.is_err());
    }

    #[test]
    fn search_returns_nearest() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let e3 = EntityId::new();

        // Three orthogonal-ish vectors
        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e2, &[0.0, 1.0, 0.0, 0.0]).unwrap();
        idx.upsert(e3, &[0.9, 0.1, 0.0, 0.0]).unwrap();

        // Query close to e1/e3
        let results = idx.search_similar(&[1.0, 0.0, 0.0, 0.0], 2).unwrap();
        assert_eq!(results.len(), 2);
        // e1 should be closest (exact match)
        assert_eq!(results[0].0, e1);
    }

    #[test]
    fn remove_vector() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        assert_eq!(idx.len(), 1);

        idx.remove(&e1).unwrap();
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn upsert_replaces_existing() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e1, &[0.0, 1.0, 0.0, 0.0]).unwrap();

        assert_eq!(idx.len(), 1);

        // After updating to [0, 1, 0, 0], searching for [0, 1, 0, 0] should find e1
        let results = idx.search_similar(&[0.0, 1.0, 0.0, 0.0], 1).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, e1);
    }

    #[test]
    fn search_empty_index() {
        let idx = VectorIndex::new(4).unwrap();
        let results = idx.search_similar(&[1.0, 0.0, 0.0, 0.0], 5).unwrap();
        assert!(results.is_empty());
    }
}
