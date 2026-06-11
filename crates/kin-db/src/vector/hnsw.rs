// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Vector index wrapper — delegates to kin-vector with EntityId convenience
//! APIs at the boundary while storing `RetrievalKey` natively.

use std::path::Path;

use crate::error::KinDbError;
use crate::search::{resolve_roles, ScoredHit};
use crate::types::EntityId;
use kin_model::{EntityRole, RetrievalKey};
use kin_vector::IndexDescriptor;

// ── Public API ──────────────────────────────────────────────────────────────

/// HNSW-backed vector similarity index for entity embeddings.
///
/// Thin wrapper around `kin_vector::VectorIndex<RetrievalKey>` that keeps
/// `EntityId` convenience APIs at the boundary and maps `VectorError` to
/// `KinDbError` for seamless integration with kin-db.
pub struct VectorIndex {
    inner: kin_vector::VectorIndex<RetrievalKey>,
}

impl VectorIndex {
    /// Create a new vector index for embeddings of the given dimensionality.
    pub fn new(dimensions: usize) -> Result<Self, KinDbError> {
        let inner = kin_vector::VectorIndex::new(dimensions)
            .map_err(|e| KinDbError::IndexError(e.to_string()))?;
        Ok(Self { inner })
    }

    /// The index's self-description (embedding model identity + graph provenance)
    /// stamped into the persisted file.
    pub fn descriptor(&self) -> IndexDescriptor {
        self.inner.descriptor()
    }

    /// Stamp the index's self-description before saving, so a later load can
    /// prove the persisted vectors were produced by the expected model/graph and
    /// refuse silently-wrong neighbors.
    pub fn set_descriptor(&self, descriptor: IndexDescriptor) {
        self.inner.set_descriptor(descriptor);
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

    /// Whether the index already contains a vector for this entity.
    pub fn contains(&self, entity_id: &EntityId) -> bool {
        let key = RetrievalKey::from(*entity_id);
        self.inner.contains(&key)
    }

    /// Whether the index already contains a vector for this retrieval key.
    pub fn contains_retrievable(&self, key: &RetrievalKey) -> bool {
        self.inner.contains(key)
    }

    /// All retrieval keys currently held in the index.
    pub fn retrievable_keys(&self) -> Vec<RetrievalKey> {
        self.inner.keys()
    }

    /// Get the embedding vector for this entity if present.
    pub fn get(&self, entity_id: &EntityId) -> Option<Vec<f32>> {
        let key = RetrievalKey::from(*entity_id);
        self.inner.get(&key)
    }

    /// Get the embedding vector for this retrieval key if present.
    pub fn get_retrievable(&self, key: &RetrievalKey) -> Option<Vec<f32>> {
        self.inner.get(key)
    }

    /// Add or update the embedding for an entity.
    ///
    /// The embedding slice must have exactly `dimensions` elements.
    pub fn upsert(&self, entity_id: EntityId, embedding: &[f32]) -> Result<(), KinDbError> {
        self.upsert_retrievable(entity_id.into(), embedding)
    }

    /// Add or update the embedding for any retrieval key.
    ///
    /// The embedding slice must have exactly `dimensions` elements.
    pub fn upsert_retrievable(
        &self,
        key: RetrievalKey,
        embedding: &[f32],
    ) -> Result<(), KinDbError> {
        let _span =
            tracing::info_span!("kindb.vector_index.upsert", dims = embedding.len()).entered();
        self.inner
            .upsert(key, embedding)
            .map_err(|e| KinDbError::IndexError(e.to_string()))
    }

    /// Remove the embedding for an entity.
    pub fn remove(&self, entity_id: &EntityId) -> Result<(), KinDbError> {
        let _span = tracing::info_span!("kindb.vector_index.remove").entered();
        let key = RetrievalKey::from(*entity_id);
        self.remove_retrievable(&key)
    }

    /// Remove the embedding for any retrieval key.
    pub fn remove_retrievable(&self, key: &RetrievalKey) -> Result<(), KinDbError> {
        self.inner
            .remove(key)
            .map_err(|e| KinDbError::IndexError(e.to_string()))
    }

    /// Remove a batch of entity embeddings from the index.
    pub fn remove_batch(&self, entity_ids: &[EntityId]) -> Result<(), KinDbError> {
        let _span =
            tracing::info_span!("kindb.vector_index.remove_batch", count = entity_ids.len())
                .entered();
        for id in entity_ids {
            let key = RetrievalKey::from(*id);
            self.inner
                .remove(&key)
                .map_err(|e| KinDbError::IndexError(e.to_string()))?;
        }
        Ok(())
    }

    /// Search for the `limit` most similar entities to the given embedding.
    ///
    /// Returns pairs of (RetrievalKey, distance_score) sorted by similarity.
    pub fn search_similar(
        &self,
        embedding: &[f32],
        limit: usize,
    ) -> Result<Vec<(RetrievalKey, f32)>, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.vector_index.search_similar",
            dims = embedding.len(),
            limit = limit
        )
        .entered();
        let results = self
            .inner
            .search_similar(embedding, limit)
            .map_err(|e| KinDbError::IndexError(e.to_string()))?;
        Ok(results)
    }

    /// Search for the `limit` most similar entities, filtering by a predicate.
    pub fn search_similar_filtered(
        &self,
        embedding: &[f32],
        limit: usize,
        predicate: impl Fn(&RetrievalKey) -> bool,
    ) -> Result<Vec<(RetrievalKey, f32)>, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.vector_index.search_similar_filtered",
            dims = embedding.len(),
            limit = limit
        )
        .entered();
        let results = self
            .inner
            .search_similar_filtered(embedding, limit, predicate)
            .map_err(|e| KinDbError::IndexError(e.to_string()))?;
        Ok(results)
    }

    /// Search with role enrichment: returns `ScoredHit` results with entity roles attached.
    ///
    /// The `role_lookup` closure resolves an `EntityId` to its `EntityRole`.
    /// Non-entity keys get `role: None`. This follows the grouping-over-penalizing
    /// design — roles are metadata for downstream ranking, not score modifiers.
    pub fn search_similar_with_roles<F>(
        &self,
        embedding: &[f32],
        limit: usize,
        role_lookup: F,
    ) -> Result<Vec<ScoredHit>, KinDbError>
    where
        F: Fn(&EntityId) -> Option<EntityRole>,
    {
        let raw = self.search_similar(embedding, limit)?;
        Ok(resolve_roles(raw, role_lookup))
    }

    /// Search with role enrichment, filtering by a predicate.
    pub fn search_similar_filtered_with_roles<F, P>(
        &self,
        embedding: &[f32],
        limit: usize,
        predicate: P,
        role_lookup: F,
    ) -> Result<Vec<ScoredHit>, KinDbError>
    where
        F: Fn(&EntityId) -> Option<EntityRole>,
        P: Fn(&RetrievalKey) -> bool,
    {
        let raw = self.search_similar_filtered(embedding, limit, predicate)?;
        Ok(resolve_roles(raw, role_lookup))
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
        let _span = tracing::info_span!(
            "kindb.vector_index.save",
            path = %path.display()
        )
        .entered();
        self.inner
            .save(path)
            .map_err(|e| KinDbError::IndexError(e.to_string()))
    }

    /// Load a previously saved HNSW index from disk.
    ///
    /// Returns a new `VectorIndex` with the loaded index data.
    /// The `dimensions` parameter is used to validate the loaded data matches.
    pub fn load(path: &Path, dimensions: usize) -> Result<Self, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.vector_index.load",
            path = %path.display(),
            dimensions = dimensions
        )
        .entered();
        let inner = kin_vector::VectorIndex::<RetrievalKey>::load(path, dimensions)
            .map_err(|e| KinDbError::IndexError(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Load a previously saved HNSW index from disk without dimension validation.
    ///
    /// The dimensions are read from the persisted data. Use this when the
    /// embedder is not available (e.g., loading an existing index for search
    /// without the `embeddings` feature enabled).
    pub fn load_from_disk(path: &Path) -> Result<Self, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.vector_index.load_from_disk",
            path = %path.display()
        )
        .entered();
        let inner = kin_vector::VectorIndex::<RetrievalKey>::load_from_disk(path)
            .map_err(|e| KinDbError::IndexError(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Load the index at `path` and verify its self-description against
    /// `expected`, returning [`IndexLoadOutcome`].
    ///
    /// This NEVER returns an error for an incompatible or unreadable index:
    /// a model/graph mismatch (kin-vector's typed `ModelMismatch`) or a corrupt
    /// file both resolve to [`IndexLoadOutcome::Incompatible`] so the caller can
    /// archive-and-rebuild rather than crash-loop or serve silently-wrong
    /// neighbors. `expected` pins only the fields it sets to `Some`; an index
    /// whose descriptor cannot satisfy a pinned field is treated as incompatible
    /// (this includes a legacy/unstamped index when the caller pins identity).
    pub fn load_compatible(path: &Path, expected: &IndexDescriptor) -> IndexLoadOutcome {
        let inner = match kin_vector::VectorIndex::<RetrievalKey>::load_from_disk(path) {
            Ok(inner) => inner,
            Err(e) => return IndexLoadOutcome::Incompatible(format!("unreadable vector index: {e}")),
        };
        match inner.descriptor().verify_compatible(expected) {
            Ok(()) => IndexLoadOutcome::Loaded(Self { inner }),
            Err(e) => IndexLoadOutcome::Incompatible(e.to_string()),
        }
    }

    /// Like [`VectorIndex::load_compatible`], but GRANDFATHERS a legacy index
    /// that does not self-describe: only a field the stored index actually
    /// stamped is enforced. An unstamped index (the pre-stamping format) loads
    /// regardless — it cannot prove a mismatch and must remain usable — while a
    /// stamped index that positively declares a different model/graph is
    /// rejected as [`IndexLoadOutcome::Incompatible`] (kin-vector's typed
    /// `ModelMismatch`). A corrupt/unreadable index is also `Incompatible`.
    pub fn load_compatible_grandfathered(
        path: &Path,
        expected: &IndexDescriptor,
    ) -> IndexLoadOutcome {
        let inner = match kin_vector::VectorIndex::<RetrievalKey>::load_from_disk(path) {
            Ok(inner) => inner,
            Err(e) => return IndexLoadOutcome::Incompatible(format!("unreadable vector index: {e}")),
        };
        let stored = inner.descriptor();
        // Enforce only the fields the stored index actually stamped (grandfather
        // unstamped fields to None = "don't care").
        let effective = IndexDescriptor {
            model_id: stored.model_id.as_ref().and(expected.model_id.clone()),
            graph_root: stored.graph_root.as_ref().and(expected.graph_root.clone()),
        };
        match stored.verify_compatible(&effective) {
            Ok(()) => IndexLoadOutcome::Loaded(Self { inner }),
            Err(e) => IndexLoadOutcome::Incompatible(e.to_string()),
        }
    }
}

/// Outcome of [`VectorIndex::load_compatible`].
pub enum IndexLoadOutcome {
    /// The on-disk index loaded and proved compatible with the expected
    /// model/graph self-description.
    Loaded(VectorIndex),
    /// The index exists but is incompatible (model/graph mismatch) or unreadable
    /// and must be archived + rebuilt rather than served. Carries a
    /// human-readable reason for the LOUD recovery notice.
    Incompatible(String),
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
        assert!(idx.contains(&e1));
        assert!(idx.contains(&e2));
    }

    #[test]
    fn upsert_retrievable_accepts_artifacts() {
        let idx = VectorIndex::new(4).unwrap();
        let key = RetrievalKey::Artifact(kin_model::ArtifactId::from_path("src/lib.rs"));

        idx.upsert_retrievable(key, &[1.0, 0.0, 0.0, 0.0]).unwrap();

        assert_eq!(idx.len(), 1);
        assert!(idx.contains_retrievable(&key));
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
        assert_eq!(results[0].0, RetrievalKey::from(e1));
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
        assert_eq!(results[0].0, RetrievalKey::from(e1));
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
        assert_eq!(results[0].0, RetrievalKey::from(e1));
        assert_eq!(results[1].0, RetrievalKey::from(e3));
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
        assert_eq!(results[0].0, RetrievalKey::from(entities[0].0));
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
        assert_eq!(results[0].0, RetrievalKey::from(e1));
    }

    #[test]
    fn search_returns_retrieval_keys_for_mixed_ids() {
        let idx = VectorIndex::new(4).unwrap();
        let entity = EntityId::new();
        let artifact = kin_model::ArtifactId::from_path("README.md");

        idx.upsert(entity, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert_retrievable(RetrievalKey::Artifact(artifact), &[0.95, 0.05, 0.0, 0.0])
            .unwrap();

        let results = idx.search_similar(&[1.0, 0.0, 0.0, 0.0], 2).unwrap();
        assert_eq!(results[0].0, RetrievalKey::from(entity));
        assert!(results
            .iter()
            .any(|(key, _)| *key == RetrievalKey::Artifact(artifact)));
    }

    #[test]
    fn search_similar_with_roles_enriches_results() {
        let idx = VectorIndex::new(4).unwrap();
        let src_entity = EntityId::new();
        let test_entity = EntityId::new();

        idx.upsert(src_entity, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(test_entity, &[0.95, 0.05, 0.0, 0.0]).unwrap();

        let mut roles = std::collections::HashMap::new();
        roles.insert(src_entity, EntityRole::Source);
        roles.insert(test_entity, EntityRole::Test);

        let hits = idx
            .search_similar_with_roles(&[1.0, 0.0, 0.0, 0.0], 5, |id| roles.get(id).copied())
            .unwrap();

        assert_eq!(hits.len(), 2);
        // First hit should be the closest (src_entity)
        assert_eq!(hits[0].key, RetrievalKey::from(src_entity));
        assert_eq!(hits[0].role, Some(EntityRole::Source));
        assert_eq!(hits[1].key, RetrievalKey::from(test_entity));
        assert_eq!(hits[1].role, Some(EntityRole::Test));
    }

    #[test]
    fn search_similar_with_roles_artifacts_get_none_role() {
        let idx = VectorIndex::new(4).unwrap();
        let artifact = kin_model::ArtifactId::from_path("README.md");

        idx.upsert_retrievable(RetrievalKey::Artifact(artifact), &[1.0, 0.0, 0.0, 0.0])
            .unwrap();

        let hits = idx
            .search_similar_with_roles(&[1.0, 0.0, 0.0, 0.0], 5, |_| None)
            .unwrap();

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].role, None);
    }

    fn descriptor(model: &str, root: &str) -> IndexDescriptor {
        IndexDescriptor {
            model_id: Some(model.to_string()),
            graph_root: Some(root.to_string()),
        }
    }

    #[test]
    fn load_compatible_accepts_match_and_rejects_model_or_graph_swap() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");

        let idx = VectorIndex::new(4).unwrap();
        idx.upsert(EntityId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.set_descriptor(descriptor("model-A@1", "root-1"));
        idx.save(&path).unwrap();

        // Exact match loads.
        assert!(matches!(
            VectorIndex::load_compatible(&path, &descriptor("model-A@1", "root-1")),
            IndexLoadOutcome::Loaded(_)
        ));
        // Same dimension, DIFFERENT model → incompatible (would be silently-wrong).
        assert!(matches!(
            VectorIndex::load_compatible(&path, &descriptor("model-B@1", "root-1")),
            IndexLoadOutcome::Incompatible(_)
        ));
        // Graph root changed → incompatible.
        assert!(matches!(
            VectorIndex::load_compatible(&path, &descriptor("model-A@1", "root-2")),
            IndexLoadOutcome::Incompatible(_)
        ));
        // Pinning nothing (sidecar-vouched path) loads regardless.
        assert!(matches!(
            VectorIndex::load_compatible(&path, &IndexDescriptor::default()),
            IndexLoadOutcome::Loaded(_)
        ));
    }

    #[test]
    fn load_compatible_rejects_unstamped_or_corrupt_index() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");

        let idx = VectorIndex::new(4).unwrap();
        idx.upsert(EntityId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        // No set_descriptor → legacy/unstamped index.
        idx.save(&path).unwrap();

        // A pinned identity cannot be proven by an unstamped index → incompatible.
        assert!(matches!(
            VectorIndex::load_compatible(
                &path,
                &IndexDescriptor {
                    model_id: Some("model-A@1".into()),
                    graph_root: None,
                },
            ),
            IndexLoadOutcome::Incompatible(_)
        ));

        // An unreadable/corrupt index is Incompatible (archive + rebuild), never a crash.
        std::fs::write(&path, b"corrupt").unwrap();
        assert!(matches!(
            VectorIndex::load_compatible(&path, &IndexDescriptor::default()),
            IndexLoadOutcome::Incompatible(_)
        ));
    }
}
