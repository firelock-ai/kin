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

use object_store::gcp::GoogleCloudStorageBuilder;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, PutMode, PutOptions, PutPayload, UpdateVersion};

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
        })
    }

    /// Create from an existing `ObjectStore` implementation (useful for testing
    /// with `object_store::memory::InMemory`).
    pub fn from_store(store: Box<dyn ObjectStore>, prefix: impl Into<String>) -> Self {
        Self {
            store,
            prefix: prefix.into(),
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

        match block_on(self.store.get(&path)) {
            Ok(get_result) => {
                let generation = get_result
                    .meta
                    .e_tag
                    .as_ref()
                    .and_then(|etag| etag.trim_matches('"').parse::<Generation>().ok())
                    .unwrap_or(1);

                let bytes = block_on(get_result.bytes()).map_err(|e| {
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
            PutOptions {
                mode: PutMode::Update(UpdateVersion {
                    e_tag: Some(format!("{expected_gen}")),
                    version: None,
                }),
                ..PutOptions::default()
            }
        };

        let result = block_on(self.store.put_opts(&path, payload, opts)).map_err(|e| {
            KinDbError::StorageError(format!("GCS save failed for {path}: {e}"))
        })?;

        // GCS returns the new object generation in the e_tag. The InMemory
        // test backend returns "0" on first write, so we clamp to at least
        // expected_gen + 1 to guarantee forward progress.
        let raw_gen = result
            .e_tag
            .as_ref()
            .and_then(|etag| etag.trim_matches('"').parse::<Generation>().ok())
            .unwrap_or(expected_gen + 1);
        let new_gen = raw_gen.max(expected_gen + 1);

        Ok(new_gen)
    }

    fn save_overlay(
        &self,
        repo_id: &str,
        session_id: &str,
        data: &[u8],
    ) -> Result<(), KinDbError> {
        let path = self.overlay_path(repo_id, session_id);
        let payload = PutPayload::from(data.to_vec());

        block_on(self.store.put(&path, payload)).map_err(|e| {
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

        match block_on(self.store.get(&path)) {
            Ok(get_result) => {
                let bytes = block_on(get_result.bytes()).map_err(|e| {
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
}

/// Block on an async future, handling both inside-runtime and no-runtime cases.
///
/// Preserves the original error type so callers can pattern-match on
/// specific variants (e.g., `object_store::Error::NotFound`).
fn block_on<F, T, E>(future: F) -> Result<T, E>
where
    F: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(future)),
        Err(_) => {
            let rt = tokio::runtime::Runtime::new()
                .expect("failed to create tokio runtime for blocking GCS call");
            rt.block_on(future)
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
}
