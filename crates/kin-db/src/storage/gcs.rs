// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! GCS storage backend for cloud deployment.
//!
//! Uses the `object_store` crate with built-in GCS support. Provides:
//! - Generation-match for CAS writes (replaces flock)
//! - Auth via Application Default Credentials
//! - Feature-gated: `cargo build --features gcs`
//!
//! Object layout in the bucket:
//! ```text
//! {prefix}/{repo_id}/graph.kndb              — snapshot
//! {prefix}/{repo_id}/overlays/{session_id}.bin — overlay state
//! ```

use std::collections::HashMap;
use std::sync::OnceLock;

use object_store::gcp::GoogleCloudStorageBuilder;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, PutMode, PutOptions, PutPayload, UpdateVersion};
use parking_lot::Mutex;

use crate::error::KinDbError;
use crate::storage::backend::{Generation, StorageBackend, GENERATION_INIT};

/// GCS-backed storage for graph snapshots and overlays.
///
/// Uses GCS object generation numbers for compare-and-swap semantics.
/// When `save_snapshot` is called with `expected_gen`, the backend sets
/// `if-generation-match` so GCS atomically rejects the write if another
/// writer committed in between.
pub struct GcsBackend {
    store: Box<dyn ObjectStore>,
    prefix: String,
    /// Lazily-initialized tokio runtime for when no ambient runtime exists.
    fallback_rt: OnceLock<tokio::runtime::Runtime>,
    /// Maps object paths to their last-seen raw ETag string.
    /// Used for UpdateVersion on subsequent writes so we don't lose
    /// fidelity by round-tripping through u64.
    etags: Mutex<HashMap<String, String>>,
}

impl GcsBackend {
    /// Create a new GCS backend.
    ///
    /// - `bucket`: GCS bucket name (e.g., `kin-graphs-prod`)
    /// - `prefix`: Optional path prefix within the bucket (e.g., `snapshots/`)
    ///
    /// Auth uses Application Default Credentials (ADC) — works automatically
    /// on GKE with Workload Identity, and locally with `gcloud auth application-default login`.
    pub fn new(bucket: &str, prefix: impl Into<String>) -> Result<Self, KinDbError> {
        let store = GoogleCloudStorageBuilder::new()
            .with_bucket_name(bucket)
            .build()
            .map_err(|e| KinDbError::StorageError(format!("failed to create GCS client: {e}")))?;

        Ok(Self {
            store: Box::new(store),
            prefix: prefix.into(),
            fallback_rt: OnceLock::new(),
            etags: Mutex::new(HashMap::new()),
        })
    }

    /// Create from an existing `ObjectStore` implementation (useful for testing
    /// with `object_store::memory::InMemory`).
    pub fn from_store(store: Box<dyn ObjectStore>, prefix: impl Into<String>) -> Self {
        Self {
            store,
            prefix: prefix.into(),
            fallback_rt: OnceLock::new(),
            etags: Mutex::new(HashMap::new()),
        }
    }

    fn snapshot_path(&self, repo_id: &str) -> ObjectPath {
        if self.prefix.is_empty() {
            ObjectPath::from(format!("{repo_id}/graph.kndb"))
        } else {
            ObjectPath::from(format!("{}/{repo_id}/graph.kndb", self.prefix))
        }
    }

    fn overlay_path(&self, repo_id: &str, session_id: &str) -> ObjectPath {
        if self.prefix.is_empty() {
            ObjectPath::from(format!("{repo_id}/overlays/{session_id}.bin"))
        } else {
            ObjectPath::from(format!(
                "{}/{repo_id}/overlays/{session_id}.bin",
                self.prefix
            ))
        }
    }
}

impl StorageBackend for GcsBackend {
    fn load_snapshot(&self, repo_id: &str) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
        let path = self.snapshot_path(repo_id);

        match self.block_on(self.store.get(&path)) {
            Ok(get_result) => {
                // Parse generation from ETag for the trait interface, but also
                // stash the raw ETag so save_snapshot can use it verbatim.
                let raw_etag = get_result.meta.e_tag.clone();
                let generation = raw_etag
                    .as_ref()
                    .and_then(|etag| etag.trim_matches('"').parse::<Generation>().ok())
                    .unwrap_or(1);

                if let Some(ref etag) = raw_etag {
                    self.etags
                        .lock()
                        .insert(path.to_string(), etag.clone());
                }

                let bytes = self.block_on(get_result.bytes()).map_err(|e| {
                    KinDbError::StorageError(format!("GCS read bytes failed for {path}: {e}"))
                })?;
                Ok(Some((bytes.to_vec(), generation)))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(KinDbError::StorageError(format!(
                "GCS load failed for {path}: {e}"
            ))),
        }
    }

    fn save_snapshot(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let path = self.snapshot_path(repo_id);
        let payload = PutPayload::from(data.to_vec());

        let opts = if expected_gen == GENERATION_INIT {
            PutOptions {
                mode: PutMode::Create,
                ..PutOptions::default()
            }
        } else {
            // Use the raw ETag stored from load_snapshot when available.
            // Falls back to stringified generation for backwards compat.
            let etag = self
                .etags
                .lock()
                .get(&path.to_string())
                .cloned()
                .unwrap_or_else(|| format!("{expected_gen}"));
            PutOptions {
                mode: PutMode::Update(UpdateVersion {
                    e_tag: Some(etag),
                    version: None,
                }),
                ..PutOptions::default()
            }
        };

        let result = self
            .block_on(self.store.put_opts(&path, payload, opts))
            .map_err(|e| {
                KinDbError::StorageError(format!("GCS save failed for {path}: {e}"))
            })?;

        // Stash the new ETag for the next CAS write.
        if let Some(ref etag) = result.e_tag {
            self.etags
                .lock()
                .insert(path.to_string(), etag.clone());
        }

        // Parse generation for the trait return value. Clamp to at least
        // expected_gen + 1 to guarantee forward progress (InMemory backend
        // returns "0" on first write).
        let raw_gen = result
            .e_tag
            .as_ref()
            .and_then(|etag| etag.trim_matches('"').parse::<Generation>().ok())
            .unwrap_or(expected_gen + 1);
        let new_gen = raw_gen.max(expected_gen + 1);

        Ok(new_gen)
    }

    fn save_delta(
        &self,
        repo_id: &str,
        delta_data: &[u8],
        _base_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        // Use a monotonic timestamp suffix to order deltas.
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = ObjectPath::from(format!(
            "{}/{repo_id}/deltas/{ts:020}.kndd",
            self.prefix
        ));
        let payload = PutPayload::from(delta_data.to_vec());

        self.block_on(self.store.put(&path, payload)).map_err(|e| {
            KinDbError::StorageError(format!("GCS delta save failed for {path}: {e}"))
        })?;

        // Return a synthetic generation (timestamp-based).
        Ok(ts as Generation)
    }

    fn load_deltas_since(
        &self,
        repo_id: &str,
        since_gen: Generation,
    ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
        let prefix = ObjectPath::from(format!("{}/{repo_id}/deltas/", self.prefix));

        let list_result = self
            .block_on(self.store.list_with_delimiter(Some(&prefix)))
            .map_err(|e| {
                KinDbError::StorageError(format!("GCS list deltas failed: {e}"))
            })?;

        let mut deltas: Vec<(Generation, ObjectPath)> = Vec::new();
        for meta in list_result.objects {
            let filename = meta.location.filename().unwrap_or_default();
            if let Some(stem) = filename.strip_suffix(".kndd") {
                if let Ok(gen) = stem.parse::<Generation>() {
                    if gen > since_gen {
                        deltas.push((gen, meta.location));
                    }
                }
            }
        }
        deltas.sort_by_key(|(gen, _)| *gen);

        let mut result = Vec::with_capacity(deltas.len());
        for (gen, path) in deltas {
            let get_result = self.block_on(self.store.get(&path)).map_err(|e| {
                KinDbError::StorageError(format!("GCS delta read failed for {path}: {e}"))
            })?;
            let bytes = self.block_on(get_result.bytes()).map_err(|e| {
                KinDbError::StorageError(format!("GCS delta bytes failed for {path}: {e}"))
            })?;
            result.push((bytes.to_vec(), gen));
        }

        Ok(result)
    }

    fn clear_deltas(&self, repo_id: &str) -> Result<(), KinDbError> {
        let prefix = ObjectPath::from(format!("{}/{repo_id}/deltas/", self.prefix));

        let list_result = self
            .block_on(self.store.list_with_delimiter(Some(&prefix)))
            .map_err(|e| {
                KinDbError::StorageError(format!("GCS list deltas for clear failed: {e}"))
            })?;

        for meta in list_result.objects {
            match self.block_on(self.store.delete(&meta.location)) {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                Err(e) => {
                    return Err(KinDbError::StorageError(format!(
                        "GCS delta delete failed for {}: {e}",
                        meta.location
                    )));
                }
            }
        }

        Ok(())
    }

    fn save_overlay(
        &self,
        repo_id: &str,
        session_id: &str,
        data: &[u8],
    ) -> Result<(), KinDbError> {
        let path = self.overlay_path(repo_id, session_id);
        let payload = PutPayload::from(data.to_vec());

        self.block_on(self.store.put(&path, payload)).map_err(|e| {
            KinDbError::StorageError(format!("GCS overlay save failed for {path}: {e}"))
        })?;
        Ok(())
    }

    fn load_overlay(
        &self,
        repo_id: &str,
        session_id: &str,
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        let path = self.overlay_path(repo_id, session_id);

        match self.block_on(self.store.get(&path)) {
            Ok(get_result) => {
                let bytes = self.block_on(get_result.bytes()).map_err(|e| {
                    KinDbError::StorageError(format!(
                        "GCS overlay read bytes failed for {path}: {e}"
                    ))
                })?;
                Ok(Some(bytes.to_vec()))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(KinDbError::StorageError(format!(
                "GCS overlay load failed for {path}: {e}"
            ))),
        }
    }

    fn delete_overlay(
        &self,
        repo_id: &str,
        session_id: &str,
    ) -> Result<(), KinDbError> {
        let path = self.overlay_path(repo_id, session_id);

        match self.block_on(self.store.delete(&path)) {
            Ok(()) => Ok(()),
            Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(KinDbError::StorageError(format!(
                "GCS overlay delete failed for {path}: {e}"
            ))),
        }
    }

    fn list_repos(&self) -> Result<Vec<String>, KinDbError> {
        let prefix = if self.prefix.is_empty() {
            ObjectPath::from("/")
        } else {
            ObjectPath::from(format!("{}/", self.prefix))
        };

        let result = self
            .block_on(self.store.list_with_delimiter(Some(&prefix)))
            .map_err(|e| {
                KinDbError::StorageError(format!("GCS list repos failed: {e}"))
            })?;

        let repos: Vec<String> = result
            .common_prefixes
            .into_iter()
            .filter_map(|p| p.filename().map(|f| f.to_string()))
            .collect();

        Ok(repos)
    }
}

impl GcsBackend {
    /// Block on an async future, reusing the cached runtime when no ambient
    /// tokio runtime exists. Avoids the overhead of constructing a new
    /// `Runtime` on every call.
    fn block_on<F, T, E>(&self, future: F) -> Result<T, E>
    where
        F: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| handle.block_on(future)),
            Err(_) => {
                let rt = self.fallback_rt.get_or_init(|| {
                    tokio::runtime::Runtime::new()
                        .expect("failed to create tokio runtime for blocking GCS call")
                });
                rt.block_on(future)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::format::GraphSnapshot;
    use object_store::memory::InMemory;

    fn test_backend() -> GcsBackend {
        GcsBackend::from_store(Box::new(InMemory::new()), "test")
    }

    #[test]
    fn gcs_backend_roundtrip_snapshot() {
        let backend = test_backend();

        // No snapshot yet
        assert!(backend.load_snapshot("test-repo").unwrap().is_none());

        // Create and save
        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();
        let new_gen = backend
            .save_snapshot("test-repo", &bytes, GENERATION_INIT)
            .unwrap();
        assert!(new_gen > 0);

        // Load back
        let (loaded_bytes, _gen) = backend.load_snapshot("test-repo").unwrap().unwrap();
        let loaded = GraphSnapshot::from_bytes(&loaded_bytes).unwrap();
        assert_eq!(loaded.version, GraphSnapshot::CURRENT_VERSION);
    }

    #[test]
    fn gcs_backend_overlay_roundtrip() {
        let backend = test_backend();

        // No overlay yet
        assert!(backend
            .load_overlay("test-repo", "session-1")
            .unwrap()
            .is_none());

        // Save
        let data = b"overlay bytes";
        backend
            .save_overlay("test-repo", "session-1", data)
            .unwrap();

        // Load back
        let loaded = backend
            .load_overlay("test-repo", "session-1")
            .unwrap()
            .unwrap();
        assert_eq!(loaded, data);
    }

    #[test]
    fn gcs_backend_delete_overlay() {
        let backend = test_backend();

        // Save an overlay
        backend
            .save_overlay("test-repo", "session-1", b"overlay data")
            .unwrap();
        assert!(backend
            .load_overlay("test-repo", "session-1")
            .unwrap()
            .is_some());

        // Delete it
        backend.delete_overlay("test-repo", "session-1").unwrap();
        assert!(backend
            .load_overlay("test-repo", "session-1")
            .unwrap()
            .is_none());

        // Deleting a non-existent overlay is a no-op
        backend.delete_overlay("test-repo", "session-1").unwrap();
    }

    #[test]
    fn gcs_backend_etag_cached_across_load_save() {
        let backend = test_backend();

        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();

        // First write (Create mode)
        let gen1 = backend
            .save_snapshot("test-repo", &bytes, GENERATION_INIT)
            .unwrap();
        assert!(gen1 > 0);

        // Load populates the ETag cache
        let (_loaded, gen_loaded) = backend.load_snapshot("test-repo").unwrap().unwrap();

        // Second write should use the cached ETag from load
        let gen2 = backend
            .save_snapshot("test-repo", &bytes, gen_loaded)
            .unwrap();
        assert!(gen2 > gen_loaded);

        // The etag map should have an entry for this path
        let etags = backend.etags.lock();
        assert!(!etags.is_empty());
    }
}
