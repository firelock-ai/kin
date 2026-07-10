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
//! {prefix}/{repo_id}/graph.kndb              — checksummed full-authority snapshot envelope
//! {prefix}/{repo_id}/overlays/{session_id}.bin — overlay state
//! ```

use std::sync::OnceLock;

use object_store::gcp::GoogleCloudStorageBuilder;
use object_store::path::Path as ObjectPath;
use object_store::{
    ObjectMeta, ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload, UpdateVersion,
};
use sha2::{Digest, Sha256};

use crate::error::KinDbError;
use crate::storage::backend::{
    Generation, SnapshotAuthority, SnapshotRecoveryState, StorageBackend, GENERATION_INIT,
};

const GCS_FULL_AUTHORITY_MAGIC: [u8; 8] = *b"KNGCSF02";
const GCS_FULL_AUTHORITY_HEADER_LEN: usize = 8 + 8 + 32;

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
        })
    }

    /// Create from an existing `ObjectStore` implementation (useful for testing
    /// with `object_store::memory::InMemory`).
    pub fn from_store(store: Box<dyn ObjectStore>, prefix: impl Into<String>) -> Self {
        Self {
            store,
            prefix: prefix.into(),
            fallback_rt: OnceLock::new(),
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

    fn numeric_version(version: Option<&str>, authority: &str) -> Result<Generation, KinDbError> {
        let version = version.ok_or_else(|| {
            KinDbError::StorageError(format!(
                "GCS {authority} is missing object meta.version; refusing ETag or synthetic generation fallback"
            ))
        })?;
        version.parse::<Generation>().map_err(|error| {
            KinDbError::StorageError(format!(
                "GCS {authority} has nonnumeric object version {version:?}: {error}"
            ))
        })
    }

    fn snapshot_meta(&self, path: &ObjectPath) -> Result<ObjectMeta, KinDbError> {
        self.block_on(self.store.head(path)).map_err(|error| {
            KinDbError::StorageError(format!("GCS head failed for {path}: {error}"))
        })
    }

    fn encode_full_snapshot_authority(snapshot_bytes: &[u8]) -> Result<Vec<u8>, KinDbError> {
        let payload_len = u64::try_from(snapshot_bytes.len()).map_err(|_| {
            KinDbError::StorageError("GCS snapshot payload length exceeds u64".to_string())
        })?;
        let mut encoded = Vec::with_capacity(GCS_FULL_AUTHORITY_HEADER_LEN + snapshot_bytes.len());
        encoded.extend_from_slice(&GCS_FULL_AUTHORITY_MAGIC);
        encoded.extend_from_slice(&payload_len.to_le_bytes());
        encoded.extend_from_slice(&Sha256::digest(snapshot_bytes));
        encoded.extend_from_slice(snapshot_bytes);
        Ok(encoded)
    }

    fn decode_full_snapshot_authority(bytes: &[u8]) -> Result<(Vec<u8>, bool), KinDbError> {
        if !bytes.starts_with(&GCS_FULL_AUTHORITY_MAGIC) {
            return Ok((bytes.to_vec(), false));
        }
        if bytes.len() < GCS_FULL_AUTHORITY_HEADER_LEN {
            return Err(KinDbError::StorageError(
                "GCS full-snapshot authority envelope is truncated".to_string(),
            ));
        }
        let payload_len = u64::from_le_bytes(bytes[8..16].try_into().expect("fixed range"));
        let payload_len = usize::try_from(payload_len).map_err(|_| {
            KinDbError::StorageError(
                "GCS full-snapshot authority payload length exceeds usize".to_string(),
            )
        })?;
        let expected_len = GCS_FULL_AUTHORITY_HEADER_LEN
            .checked_add(payload_len)
            .ok_or_else(|| {
                KinDbError::StorageError(
                    "GCS full-snapshot authority payload length overflows".to_string(),
                )
            })?;
        if bytes.len() != expected_len {
            return Err(KinDbError::StorageError(format!(
                "GCS full-snapshot authority length mismatch: expected {expected_len}, found {}",
                bytes.len()
            )));
        }
        let payload = &bytes[GCS_FULL_AUTHORITY_HEADER_LEN..];
        let expected_digest: [u8; 32] = bytes[16..48].try_into().expect("fixed range");
        let actual_digest: [u8; 32] = Sha256::digest(payload).into();
        if actual_digest != expected_digest {
            return Err(KinDbError::StorageError(
                "GCS full-snapshot authority digest mismatch".to_string(),
            ));
        }
        Ok((payload.to_vec(), true))
    }

    fn load_snapshot_object(
        &self,
        repo_id: &str,
    ) -> Result<Option<(SnapshotAuthority, bool)>, KinDbError> {
        let path = self.snapshot_path(repo_id);
        let get_result = match self.block_on(self.store.get(&path)) {
            Ok(result) => result,
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "GCS load failed for {path}: {error}"
                )))
            }
        };
        let generation = Self::numeric_version(
            get_result.meta.version.as_deref(),
            &format!("snapshot {path}"),
        )?;
        let bytes = self.block_on(get_result.bytes()).map_err(|error| {
            KinDbError::StorageError(format!("GCS read bytes failed for {path}: {error}"))
        })?;
        let (snapshot_bytes, has_full_authority) = Self::decode_full_snapshot_authority(&bytes)?;
        Ok(Some((
            SnapshotAuthority {
                snapshot_bytes,
                snapshot_generation: generation,
                head_generation: generation,
            },
            has_full_authority,
        )))
    }
}

impl StorageBackend for GcsBackend {
    fn load_snapshot(&self, repo_id: &str) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
        Ok(self
            .load_snapshot_authority(repo_id)?
            .map(|authority| (authority.snapshot_bytes, authority.head_generation)))
    }

    fn load_snapshot_authority(
        &self,
        repo_id: &str,
    ) -> Result<Option<SnapshotAuthority>, KinDbError> {
        Ok(self
            .load_snapshot_object(repo_id)?
            .map(|(authority, _)| authority))
    }

    fn load_recovery_state(&self, repo_id: &str) -> Result<SnapshotRecoveryState, KinDbError> {
        // GCS incremental writes are disabled until snapshot+journal authority
        // has one conditional commit point. A snapshot written by this backend
        // carries a full-authority envelope, so leftover legacy journals after
        // its commit are stale and ignored. Raw legacy snapshots with journals
        // fail closed because no base/head binding exists.
        let Some((authority, has_full_authority)) = self.load_snapshot_object(repo_id)? else {
            return Ok((None, Vec::new()));
        };
        if !has_full_authority && !self.load_deltas_since(repo_id, GENERATION_INIT)?.is_empty() {
            return Err(KinDbError::StorageError(format!(
                "legacy GCS repo {repo_id} has journals but no full-snapshot authority envelope; refusing unbound replay"
            )));
        }
        Ok((Some(authority), Vec::new()))
    }

    fn save_snapshot(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let _snapshot = crate::storage::format::GraphSnapshot::from_bytes(data)?;
        let path = self.snapshot_path(repo_id);
        let payload = PutPayload::from(Self::encode_full_snapshot_authority(data)?);

        let opts = if expected_gen == GENERATION_INIT {
            PutOptions {
                mode: PutMode::Create,
                ..PutOptions::default()
            }
        } else {
            let meta = self.snapshot_meta(&path)?;
            let current_generation =
                Self::numeric_version(meta.version.as_deref(), &format!("snapshot {path}"))?;
            if current_generation != expected_gen {
                return Err(KinDbError::StorageError(format!(
                    "GCS snapshot generation mismatch for {path}: expected {expected_gen}, found {current_generation}"
                )));
            }
            PutOptions {
                mode: PutMode::Update(UpdateVersion {
                    e_tag: meta.e_tag,
                    version: meta.version,
                }),
                ..PutOptions::default()
            }
        };

        let result = self
            .block_on(self.store.put_opts(&path, payload, opts))
            .map_err(|e| KinDbError::StorageError(format!("GCS save failed for {path}: {e}")))?;

        let generation = Self::numeric_version(
            result.version.as_deref(),
            &format!("save result for {path}"),
        )?;
        if generation <= expected_gen {
            return Err(KinDbError::StorageError(format!(
                "GCS save result for {path} did not advance generation: expected above {expected_gen}, found {generation}"
            )));
        }
        Ok(generation)
    }

    fn save_delta(
        &self,
        repo_id: &str,
        _delta_data: &[u8],
        base_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        Err(KinDbError::StorageError(format!(
            "GCS incremental delta persistence is disabled for repo {repo_id} at base {base_gen}: no single conditional snapshot+journal authority"
        )))
    }

    fn load_deltas_since(
        &self,
        repo_id: &str,
        since_gen: Generation,
    ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
        let prefix = ObjectPath::from(format!("{}/{repo_id}/deltas/", self.prefix));

        let list_result = self
            .block_on(self.store.list_with_delimiter(Some(&prefix)))
            .map_err(|e| KinDbError::StorageError(format!("GCS list deltas failed: {e}")))?;

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

    fn save_overlay(&self, repo_id: &str, session_id: &str, data: &[u8]) -> Result<(), KinDbError> {
        let path = self.overlay_path(repo_id, session_id);
        let payload = PutPayload::from(data.to_vec());

        self.block_on(self.store.put(&path, payload)).map_err(|e| {
            KinDbError::StorageError(format!("GCS overlay save failed for {path}: {e}"))
        })?;
        Ok(())
    }

    fn load_overlay(&self, repo_id: &str, session_id: &str) -> Result<Option<Vec<u8>>, KinDbError> {
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

    fn delete_overlay(&self, repo_id: &str, session_id: &str) -> Result<(), KinDbError> {
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
            .map_err(|e| KinDbError::StorageError(format!("GCS list repos failed: {e}")))?;

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
    fn gcs_backend_rejects_nonversioned_store_without_etag_fallback() {
        let backend = test_backend();

        // No snapshot yet
        assert!(backend.load_snapshot("test-repo").unwrap().is_none());

        // Create and save
        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();
        let error = backend
            .save_snapshot("test-repo", &bytes, GENERATION_INIT)
            .expect_err("InMemory has ETags but no numeric object versions");
        assert!(error.to_string().contains("missing object meta.version"));

        let load_error = backend
            .load_snapshot("test-repo")
            .expect_err("load must also reject ETag-only authority");
        assert!(load_error
            .to_string()
            .contains("missing object meta.version"));
    }

    #[test]
    fn gcs_backend_requires_numeric_object_versions() {
        assert_eq!(
            GcsBackend::numeric_version(Some("123456789"), "test").unwrap(),
            123456789
        );
        for version in [None, Some("etag-hash"), Some("-1")] {
            let error = GcsBackend::numeric_version(version, "test")
                .expect_err("missing or nonnumeric GCS version must fail closed");
            assert!(error.to_string().contains("GCS test"));
        }
    }

    #[test]
    fn gcs_full_snapshot_authority_envelope_roundtrips_and_detects_corruption() {
        let bytes = GraphSnapshot::empty().to_bytes().unwrap();
        let encoded = GcsBackend::encode_full_snapshot_authority(&bytes).unwrap();
        let (decoded, authoritative) =
            GcsBackend::decode_full_snapshot_authority(&encoded).unwrap();
        assert!(authoritative);
        assert_eq!(decoded, bytes);

        let (legacy, authoritative) = GcsBackend::decode_full_snapshot_authority(&bytes).unwrap();
        assert!(!authoritative);
        assert_eq!(legacy, bytes);

        let mut corrupt = encoded;
        *corrupt.last_mut().unwrap() ^= 0xff;
        let error = GcsBackend::decode_full_snapshot_authority(&corrupt)
            .expect_err("corrupt authoritative envelope must fail closed");
        assert!(error.to_string().contains("digest mismatch"));
    }

    #[test]
    fn gcs_backend_disables_uncommitted_legacy_delta_authority() {
        let backend = test_backend();
        let repo_id = "restart-repo";
        assert!(!backend.supports_incremental_deltas());
        let delta = crate::storage::delta::GraphSnapshotDelta::empty(42)
            .to_bytes()
            .unwrap();
        let error = backend
            .save_delta(repo_id, &delta, 42)
            .expect_err("GCS delta writes must remain disabled");
        assert!(error
            .to_string()
            .contains("no single conditional snapshot+journal authority"));

        let legacy_path = ObjectPath::from(format!("test/{repo_id}/deltas/{:020}.kndd", 43_u64));
        backend
            .block_on(backend.store.put(&legacy_path, PutPayload::from(delta)))
            .unwrap();
        assert_eq!(backend.load_deltas_since(repo_id, 0).unwrap().len(), 1);
        let (authority, recovery_deltas) = backend.load_recovery_state(repo_id).unwrap();
        assert!(authority.is_none());
        assert!(
            recovery_deltas.is_empty(),
            "unbound legacy GCS journals must never be inferred as authority"
        );
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

    /// Real-GCS proof of numeric version authority and conditional updates.
    /// InMemory has no object versions and intentionally fails the unit path;
    /// this hits the live bucket via ADC and exercises GCS's generation-based
    /// precondition. Run explicitly:
    /// `KINDB_GCS_CAS_BUCKET=kin-ecosystem-kin-graphs-dev \
    ///  cargo test -p kin-db --features gcs gcs_real_conditional_update -- --ignored --nocapture`
    #[test]
    #[ignore = "requires real GCS + ADC credentials"]
    fn gcs_real_conditional_update_roundtrip() {
        let Ok(bucket) = std::env::var("KINDB_GCS_CAS_BUCKET") else {
            eprintln!("KINDB_GCS_CAS_BUCKET not set; skipping");
            return;
        };
        let prefix = format!("v2-cas-check/{}", std::process::id());
        let backend = GcsBackend::new(&bucket, prefix).unwrap();
        let repo = "cas-test-repo";

        let bytes = GraphSnapshot::empty().to_bytes().unwrap();
        let gen1 = backend
            .save_snapshot(repo, &bytes, GENERATION_INIT)
            .expect("first save (Create) should succeed");
        let (_loaded, gen_loaded) = backend.load_snapshot(repo).unwrap().unwrap();
        // The previously-failing conditional Update against real GCS:
        let gen2 = backend
            .save_snapshot(repo, &bytes, gen_loaded)
            .expect("second save (conditional Update) must succeed against real GCS");
        let gen3 = backend
            .save_snapshot(repo, &bytes, gen2)
            .expect("third save (conditional Update) must also succeed");
        eprintln!("gens: create={gen1} loaded={gen_loaded} update1={gen2} update2={gen3}");
        assert!(gen2 > GENERATION_INIT && gen3 > GENERATION_INIT);
    }
}
