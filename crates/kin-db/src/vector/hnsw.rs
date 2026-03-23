// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::Path;
use std::path::PathBuf;
use std::{fs, fs::File};

use hashbrown::HashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use usearch::ffi::{IndexOptions, MetricKind, ScalarKind};
use usearch::Index;

use crate::error::KinDbError;
use crate::types::EntityId;

/// A mapping key for usearch. We map EntityId (UUID) → u64 key and back.
#[derive(Clone, Serialize, Deserialize)]
struct KeyMap {
    entity_to_key: HashMap<EntityId, u64>,
    key_to_entity: HashMap<u64, EntityId>,
    next_key: u64,
}

#[derive(Serialize, Deserialize)]
struct KeyMapSidecar {
    format_version: u8,
    index_sha256: [u8; 32],
    keys: KeyMap,
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

fn fsync_and_rename(tmp_path: &Path, path: &Path) -> Result<(), KinDbError> {
    let file = File::open(tmp_path).map_err(|e| {
        KinDbError::IndexError(format!(
            "failed to reopen for fsync {}: {e}",
            tmp_path.display()
        ))
    })?;
    file.sync_all()
        .map_err(|e| KinDbError::IndexError(format!("fsync failed: {e}")))?;

    fs::rename(tmp_path, path).map_err(|e| {
        KinDbError::IndexError(format!(
            "failed to rename {} → {}: {e}",
            tmp_path.display(),
            path.display()
        ))
    })?;

    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> Result<(), KinDbError> {
    let tmp_path = path.with_extension("tmp");

    fs::write(&tmp_path, bytes).map_err(|e| {
        KinDbError::IndexError(format!("failed to write {}: {e}", tmp_path.display()))
    })?;

    fsync_and_rename(&tmp_path, path)
}

fn atomic_save_index(index: &Index, path: &Path) -> Result<(), KinDbError> {
    let tmp_path = path.with_extension("tmp");
    if tmp_path.exists() {
        fs::remove_file(&tmp_path).map_err(|e| {
            KinDbError::IndexError(format!(
                "failed to clear stale temporary vector index {}: {e}",
                tmp_path.display()
            ))
        })?;
    }
    let tmp_str = tmp_path
        .to_str()
        .ok_or_else(|| KinDbError::IndexError(format!("non-UTF-8 path: {}", tmp_path.display())))?;
    index
        .save(tmp_str)
        .map_err(|e| KinDbError::IndexError(format!("failed to save vector index: {e}")))?;
    fsync_and_rename(&tmp_path, path)
}

fn file_sha256(path: &Path) -> Result<[u8; 32], KinDbError> {
    let bytes = fs::read(path)
        .map_err(|e| KinDbError::IndexError(format!("failed to read {}: {e}", path.display())))?;
    let digest = Sha256::digest(&bytes);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    Ok(hash)
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
    pub fn set_persistence_path(&self, path: impl Into<PathBuf>) {
        *self.persistence_path.write() = Some(path.into());
    }

    /// Save the HNSW index to disk.
    ///
    /// Persists the usearch index structure and a small sidecar key-map file
    /// so reloads can resolve EntityId lookups without graph reconstruction.
    /// The sidecar includes a digest of the saved index file so stale same-size
    /// key maps fail closed on reload instead of silently misrouting entities.
    pub fn save(&self, path: &Path) -> Result<(), KinDbError> {
        let inner = self.inner.read();
        atomic_save_index(&inner.index, path)?;

        let keymap_path = path.with_extension("keys");
        let sidecar = KeyMapSidecar {
            format_version: 1,
            index_sha256: file_sha256(path)?,
            keys: inner.keys.clone(),
        };
        let keymap_bytes = bincode::serialize(&sidecar).map_err(|e| {
            KinDbError::IndexError(format!("failed to serialize vector key map: {e}"))
        })?;
        atomic_write_bytes(&keymap_path, &keymap_bytes)?;
        Ok(())
    }

    /// Load a previously saved HNSW index from disk.
    ///
    /// Returns a new `VectorIndex` with the loaded index data.
    ///
    /// The EntityId key map is restored from the paired sidecar file written
    /// by `save()`. Non-empty indexes without a matching sidecar or digest are
    /// rejected so search cannot silently return the wrong EntityIds.
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

        let keys = {
            let keymap_path = path.with_extension("keys");
            let index_sha256 = file_sha256(path)?;
            if keymap_path.exists() {
                let bytes = fs::read(&keymap_path).map_err(|e| {
                    KinDbError::IndexError(format!(
                        "failed to read vector key map {}: {e}",
                        keymap_path.display()
                    ))
                })?;
                let sidecar: KeyMapSidecar = match bincode::deserialize(&bytes) {
                    Ok(sidecar) => sidecar,
                    Err(sidecar_err) => {
                        if bincode::deserialize::<KeyMap>(&bytes).is_ok() {
                            return Err(KinDbError::IndexError(format!(
                                "vector key map {} uses legacy format without index digest; rebuild required",
                                keymap_path.display()
                            )));
                        }
                        return Err(KinDbError::IndexError(format!(
                            "failed to deserialize vector key map {}: {sidecar_err}",
                            keymap_path.display()
                        )));
                    }
                };
                if sidecar.format_version != 1 {
                    return Err(KinDbError::IndexError(format!(
                        "vector key map {} has unsupported format version {}",
                        keymap_path.display(),
                        sidecar.format_version
                    )));
                }
                if sidecar.index_sha256 != index_sha256 {
                    return Err(KinDbError::IndexError(format!(
                        "vector key map {} does not match index {} (digest mismatch)",
                        keymap_path.display(),
                        path.display()
                    )));
                }
                let keys = sidecar.keys;
                let index_size = index.size();
                let key_count = keys.entity_to_key.len();
                if key_count != keys.key_to_entity.len() || key_count != index_size {
                    return Err(KinDbError::IndexError(format!(
                        "vector key map {} is out of sync with index {} (keys={}, index={})",
                        keymap_path.display(),
                        path.display(),
                        key_count,
                        index_size
                    )));
                }
                keys
            } else if index.size() > 0 {
                return Err(KinDbError::IndexError(format!(
                    "vector key map {} is missing for non-empty index {}",
                    keymap_path.display(),
                    path.display()
                )));
            } else {
                KeyMap::new()
            }
        };

        Ok(Self {
            inner: RwLock::new(VectorIndexInner {
                index,
                keys,
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

    #[test]
    fn save_reload_preserves_search_coherence() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");

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
    fn load_rejects_missing_keymap_for_nonempty_index() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");

        let idx = VectorIndex::new(4).unwrap();
        idx.upsert(EntityId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        fs::remove_file(path.with_extension("keys")).unwrap();

        let error = VectorIndex::load(&path, 4).unwrap_err();
        assert!(
            error.to_string().contains("missing for non-empty index"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn load_rejects_mismatched_keymap_for_nonempty_index() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let keymap_path = path.with_extension("keys");

        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e2, &[0.0, 1.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let bytes = fs::read(&keymap_path).unwrap();
        let mut sidecar: KeyMapSidecar = bincode::deserialize(&bytes).unwrap();
        let removed_key = sidecar.keys.remove(&e2).unwrap();
        assert_eq!(removed_key, 2);
        atomic_write_bytes(&keymap_path, &bincode::serialize(&sidecar).unwrap()).unwrap();

        let error = VectorIndex::load(&path, 4).unwrap_err();
        assert!(
            error.to_string().contains("out of sync with index"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn load_rejects_stale_same_size_keymap_sidecar() {
        let dir = tempfile::TempDir::new().unwrap();
        let first_path = dir.path().join("vectors-a.usearch");
        let second_path = dir.path().join("vectors-b.usearch");
        let first_keymap_path = first_path.with_extension("keys");
        let second_keymap_path = second_path.with_extension("keys");

        let first = VectorIndex::new(4).unwrap();
        let a1 = EntityId::new();
        let a2 = EntityId::new();
        first.upsert(a1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        first.upsert(a2, &[0.0, 1.0, 0.0, 0.0]).unwrap();
        first.save(&first_path).unwrap();

        let second = VectorIndex::new(4).unwrap();
        let b1 = EntityId::new();
        let b2 = EntityId::new();
        second.upsert(b1, &[0.0, 0.0, 1.0, 0.0]).unwrap();
        second.upsert(b2, &[0.0, 0.0, 0.0, 1.0]).unwrap();
        second.save(&second_path).unwrap();

        fs::copy(&second_keymap_path, &first_keymap_path).unwrap();

        let error = VectorIndex::load(&first_path, 4).unwrap_err();
        assert!(
            error.to_string().contains("digest mismatch"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn load_rejects_corrupted_keymap_sidecar_bytes() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let keymap_path = path.with_extension("keys");

        let idx = VectorIndex::new(4).unwrap();
        idx.upsert(EntityId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        atomic_write_bytes(&keymap_path, b"not a keymap").unwrap();

        let error = VectorIndex::load(&path, 4).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("failed to deserialize vector key map"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn load_rejects_unsupported_keymap_sidecar_version() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let keymap_path = path.with_extension("keys");

        let idx = VectorIndex::new(4).unwrap();
        idx.upsert(EntityId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let bytes = fs::read(&keymap_path).unwrap();
        let mut sidecar: KeyMapSidecar = bincode::deserialize(&bytes).unwrap();
        sidecar.format_version = 2;
        atomic_write_bytes(&keymap_path, &bincode::serialize(&sidecar).unwrap()).unwrap();

        let error = VectorIndex::load(&path, 4).unwrap_err();
        assert!(
            error.to_string().contains("unsupported format version"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn save_overwrites_partial_keymap_tmp_without_corrupting_saved_index() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let keymap_path = path.with_extension("keys");
        let keymap_tmp_path = keymap_path.with_extension("tmp");

        let idx = VectorIndex::new(4).unwrap();
        let entity_id = EntityId::new();
        idx.upsert(entity_id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        fs::write(&keymap_tmp_path, b"partial sidecar write").unwrap();

        idx.save(&path).unwrap();

        let loaded = VectorIndex::load(&path, 4).unwrap();
        let results = loaded.search_similar(&[1.0, 0.0, 0.0, 0.0], 1).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, entity_id);
        assert!(!keymap_tmp_path.exists());
    }

    #[test]
    fn load_rejects_corrupted_main_index_after_save() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");

        let idx = VectorIndex::new(4).unwrap();
        idx.upsert(EntityId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        fs::write(&path, b"corrupted usearch index").unwrap();

        let error = VectorIndex::load(&path, 4).unwrap_err();
        assert!(
            error.to_string().contains("failed to load vector index"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn save_atomically_replaces_main_index_and_preserves_reload_coherence() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.usearch");
        let tmp_path = path.with_extension("tmp");

        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();
        let e2 = EntityId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        fs::write(&tmp_path, b"partial main index write").unwrap();

        idx.upsert(e2, &[0.9, 0.1, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let loaded = VectorIndex::load(&path, 4).unwrap();
        let results = loaded.search_similar(&[1.0, 0.0, 0.0, 0.0], 2).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, e1);
        assert_eq!(results[1].0, e2);
        assert!(!tmp_path.exists());
    }
}
