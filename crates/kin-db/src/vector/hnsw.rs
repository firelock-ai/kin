// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Vector index wrapper — delegates to kin-vector with EntityId ↔ Uuid
//! conversion at the boundary.

use std::path::Path;

use crate::error::KinDbError;
use crate::types::EntityId;

// ── Public API ──────────────────────────────────────────────────────────────

/// HNSW-backed vector similarity index for entity embeddings.
///
/// Thin wrapper around `kin_vector::VectorIndex<uuid::Uuid>` that converts
/// between `EntityId` (kin-model newtype) and `Uuid` at the boundary, and
/// maps `VectorError` to `KinDbError` for seamless integration with kin-db.
pub struct VectorIndex {
    inner: kin_vector::VectorIndex<uuid::Uuid>,
}

impl VectorIndex {
    /// Create a new vector index for embeddings of the given dimensionality.
    pub fn new(dimensions: usize) -> Result<Self, KinDbError> {
        let inner = kin_vector::VectorIndex::new(dimensions)
            .map_err(|e| KinDbError::IndexError(e.to_string()))?;
        Ok(Self { inner })
    }

    /// The dimensionality of vectors in this index.
    pub fn dimensions(&self) -> usize {
        self.inner.dimensions()
    }

    /// Number of vectors currently indexed.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Add or update the embedding for an entity.
    ///
    /// The embedding slice must have exactly `dimensions` elements.
    pub fn upsert(&self, entity_id: EntityId, embedding: &[f32]) -> Result<(), KinDbError> {
        self.inner
            .upsert(entity_id.0, embedding)
            .map_err(|e| KinDbError::IndexError(e.to_string()))
    }

    /// Remove the embedding for an entity.
    pub fn remove(&self, entity_id: &EntityId) -> Result<(), KinDbError> {
        self.inner
            .remove(&entity_id.0)
            .map_err(|e| KinDbError::IndexError(e.to_string()))
    }

    /// Search for the `limit` most similar entities to the given embedding.
    ///
    /// Returns pairs of (EntityId, distance_score) sorted by similarity.
    pub fn search_similar(
        &self,
        embedding: &[f32],
        limit: usize,
    ) -> Result<Vec<(EntityId, f32)>, KinDbError> {
        let results = self
            .inner
            .search_similar(embedding, limit)
            .map_err(|e| KinDbError::IndexError(e.to_string()))?;
        Ok(results
            .into_iter()
            .map(|(uuid, dist)| (EntityId(uuid), dist))
            .collect())
    }

    /// Set the persistence path for this index.
    pub fn set_persistence_path(&self, path: impl Into<std::path::PathBuf>) {
        self.inner.set_persistence_path(path);
    }

    /// Save the HNSW index to disk.
    ///
    /// Persists the full HNSW graph as a single MessagePack file with atomic
    /// write semantics (write-to-tmp then rename).
    pub fn save(&self, path: &Path) -> Result<(), KinDbError> {
        self.inner
            .save(path)
            .map_err(|e| KinDbError::IndexError(e.to_string()))
    }

    /// Load a previously saved HNSW index from disk.
    ///
    /// Returns a new `VectorIndex` with the loaded index data.
    /// The `dimensions` parameter is used to validate the loaded data matches.
    pub fn load(path: &Path, dimensions: usize) -> Result<Self, KinDbError> {
        let inner = kin_vector::VectorIndex::<uuid::Uuid>::load(path, dimensions)
            .map_err(|e| KinDbError::IndexError(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Load a previously saved HNSW index from disk without dimension validation.
    ///
    /// The dimensions are read from the persisted data. Use this when the
    /// embedder is not available (e.g., loading an existing index for search
    /// without the `embeddings` feature enabled).
    pub fn load_from_disk(path: &Path) -> Result<Self, KinDbError> {
        let inner = kin_vector::VectorIndex::<uuid::Uuid>::load_from_disk(path)
            .map_err(|e| KinDbError::IndexError(e.to_string()))?;
        Ok(Self { inner })
    }
}

impl std::fmt::Debug for VectorIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.inner)
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

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e2, &[0.0, 1.0, 0.0, 0.0]).unwrap();
        idx.upsert(e3, &[0.9, 0.1, 0.0, 0.0]).unwrap();

        let results = idx.search_similar(&[1.0, 0.0, 0.0, 0.0], 2).unwrap();
        assert_eq!(results.len(), 2);
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

    #[test]
    fn save_reload_preserves_search_coherence() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");

        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let e3 = EntityId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e2, &[0.0, 1.0, 0.0, 0.0]).unwrap();
        idx.upsert(e3, &[0.9, 0.1, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let loaded = VectorIndex::load(&path, 4).unwrap();
        let results = loaded.search_similar(&[1.0, 0.0, 0.0, 0.0], 2).unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, e1);
        assert_eq!(results[1].0, e3);
    }

    #[test]
    fn load_rejects_corrupted_main_index_after_save() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");

        let idx = VectorIndex::new(4).unwrap();
        idx.upsert(EntityId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        std::fs::write(&path, b"corrupted hnsw index").unwrap();

        let error = VectorIndex::load(&path, 4).unwrap_err();
        assert!(
            error.to_string().contains("failed to deserialize")
                || error.to_string().contains("recovery"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn many_vectors_search_quality() {
        let idx = VectorIndex::new(8).unwrap();
        let mut entities = Vec::new();

        for i in 0..100 {
            let eid = EntityId::new();
            let mut vec = [0.0f32; 8];
            vec[i % 8] = 1.0;
            vec[(i + 1) % 8] = 0.5;
            idx.upsert(eid, &vec).unwrap();
            entities.push((eid, vec));
        }

        assert_eq!(idx.len(), 100);

        let results = idx.search_similar(&entities[0].1, 5).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, entities[0].0);
    }

    #[test]
    fn cosine_distance_sanity() {
        assert!((kin_vector::cosine_distance(&[1.0, 0.0], &[1.0, 0.0]) - 0.0).abs() < 1e-6);
        assert!((kin_vector::cosine_distance(&[1.0, 0.0], &[0.0, 1.0]) - 1.0).abs() < 1e-6);
        assert!((kin_vector::cosine_distance(&[1.0, 0.0], &[-1.0, 0.0]) - 2.0).abs() < 1e-6);
    }

    #[test]
    fn load_from_disk_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.hnsw");

        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e2, &[0.0, 1.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        // Load without specifying dimensions
        let loaded = VectorIndex::load_from_disk(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.dimensions(), 4);

        // Search works on loaded index
        let results = loaded.search_similar(&[1.0, 0.0, 0.0, 0.0], 2).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, e1);
    }
}
