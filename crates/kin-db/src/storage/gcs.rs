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
//! {prefix}/{repo_id}/source-blobs/sha256/HH/HASH — immutable exact source bytes
//! {prefix}/{repo_id}/overlays/{session_id}.bin — overlay state
//! ```

use std::sync::OnceLock;

use object_store::gcp::GoogleCloudStorageBuilder;
use object_store::path::Path as ObjectPath;
use object_store::{
    GetOptions, GetRange, ObjectMeta, ObjectStore, ObjectStoreExt, PutMode, PutOptions, PutPayload,
    UpdateVersion,
};
use sha2::{Digest, Sha256};

use crate::error::KinDbError;
use crate::storage::backend::{
    validate_source_blob_read_size, validate_source_blob_repo_id, validate_source_blob_size,
    verify_source_blob_digest, Generation, SnapshotAuthority, SnapshotRecoveryState,
    StorageBackend, GENERATION_INIT, MAX_SOURCE_BLOB_BYTES,
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

    fn source_blob_path(&self, repo_id: &str, digest: [u8; 32]) -> Result<ObjectPath, KinDbError> {
        validate_source_blob_repo_id(repo_id)?;
        let digest = hex::encode(digest);
        let suffix = format!("{repo_id}/source-blobs/sha256/{}/{}", &digest[..2], digest);
        Ok(if self.prefix.is_empty() {
            ObjectPath::from(suffix)
        } else {
            ObjectPath::from(format!("{}/{suffix}", self.prefix))
        })
    }

    fn deltas_prefix(&self, repo_id: &str) -> ObjectPath {
        if self.prefix.is_empty() {
            ObjectPath::from(format!("{repo_id}/deltas/"))
        } else {
            ObjectPath::from(format!("{}/{repo_id}/deltas/", self.prefix))
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

    fn list_delta_objects(
        &self,
        repo_id: &str,
    ) -> Result<Vec<(Generation, ObjectMeta)>, KinDbError> {
        let prefix = self.deltas_prefix(repo_id);
        let list_result = self
            .block_on(self.store.list_with_delimiter(Some(&prefix)))
            .map_err(|error| {
                KinDbError::StorageError(format!("GCS list deltas failed: {error}"))
            })?;

        let mut deltas = Vec::new();
        for meta in list_result.objects {
            let filename = meta.location.filename().ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "GCS delta authority {} has no filename",
                    meta.location
                ))
            })?;
            let stem = filename.strip_suffix(".kndd").ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "GCS delta authority {} has an unexpected object name",
                    meta.location
                ))
            })?;
            let generation = stem.parse::<Generation>().map_err(|error| {
                KinDbError::StorageError(format!(
                    "GCS delta authority {} has an invalid generation: {error}",
                    meta.location
                ))
            })?;
            if generation == GENERATION_INIT || filename != format!("{generation:020}.kndd") {
                return Err(KinDbError::StorageError(format!(
                    "GCS delta authority {} has a reserved or noncanonical generation",
                    meta.location
                )));
            }
            deltas.push((generation, meta));
        }
        deltas.sort_by_key(|(generation, _)| *generation);
        if deltas.windows(2).any(|window| window[0].0 == window[1].0) {
            return Err(KinDbError::StorageError(format!(
                "GCS repo {repo_id} has duplicate delta generations"
            )));
        }
        Ok(deltas)
    }

    fn delta_object_identity(
        deltas: &[(Generation, ObjectMeta)],
    ) -> Vec<(Generation, String, Option<String>, Option<String>)> {
        deltas
            .iter()
            .map(|(generation, meta)| {
                (
                    *generation,
                    meta.location.to_string(),
                    meta.version.clone(),
                    meta.e_tag.clone(),
                )
            })
            .collect()
    }

    fn put_full_snapshot_cas(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
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
            .map_err(|error| {
                KinDbError::StorageError(format!("GCS save failed for {path}: {error}"))
            })?;
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
}

impl StorageBackend for GcsBackend {
    fn load_snapshot(&self, repo_id: &str) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
        Ok(self
            .load_snapshot_authority(repo_id)?
            .map(|authority| (authority.snapshot_bytes, authority.snapshot_generation)))
    }

    fn save_source_blob(
        &self,
        repo_id: &str,
        digest: [u8; 32],
        data: &[u8],
    ) -> Result<(), KinDbError> {
        validate_source_blob_repo_id(repo_id)?;
        let byte_len = u64::try_from(data.len()).map_err(|_| {
            KinDbError::StorageError(format!(
                "immutable source blob for repo {repo_id} does not fit the size boundary"
            ))
        })?;
        validate_source_blob_size(byte_len, &format!("repo {repo_id}"))?;
        verify_source_blob_digest(digest, data, &format!("repo {repo_id}"))?;
        let path = self.source_blob_path(repo_id, digest)?;
        let result = self.block_on(self.store.put_opts(
            &path,
            PutPayload::from(data.to_vec()),
            PutOptions {
                mode: PutMode::Create,
                ..PutOptions::default()
            },
        ));

        if let Err(write_error) = result {
            return match self.load_source_blob(repo_id, digest) {
                Ok(Some(existing)) if existing == data => Ok(()),
                Ok(Some(_)) => Err(KinDbError::StorageError(format!(
                    "immutable GCS source blob collision at {path}; create failed: {write_error}"
                ))),
                Ok(None) => Err(KinDbError::StorageError(format!(
                    "GCS source blob create failed for {path}: {write_error}"
                ))),
                Err(read_error) => Err(KinDbError::StorageError(format!(
                    "GCS source blob create failed for {path}: {write_error}; retry verification failed: {read_error}"
                ))),
            };
        }

        let installed = self.load_source_blob(repo_id, digest)?.ok_or_else(|| {
            KinDbError::StorageError(format!(
                "GCS acknowledged immutable source blob create but {path} is missing"
            ))
        })?;
        if installed != data {
            return Err(KinDbError::StorageError(format!(
                "immutable GCS source blob changed while installing {path}"
            )));
        }
        Ok(())
    }

    fn load_source_blob(
        &self,
        repo_id: &str,
        digest: [u8; 32],
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        self.load_source_blob_bounded(repo_id, digest, MAX_SOURCE_BLOB_BYTES)
    }

    fn load_source_blob_bounded(
        &self,
        repo_id: &str,
        digest: [u8; 32],
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        validate_source_blob_repo_id(repo_id)?;
        let path = self.source_blob_path(repo_id, digest)?;
        let metadata = match self.block_on(self.store.head(&path)) {
            Ok(metadata) => metadata,
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "GCS source blob metadata load failed for {path}: {error}"
                )))
            }
        };
        validate_source_blob_read_size(metadata.size, max_bytes, path.as_ref())?;
        // Object stores commonly reject a bounded 0..N range request for an
        // existing zero-byte object. Its HEAD metadata is authoritative enough
        // to avoid that invalid range; the digest still verifies the identity.
        if metadata.size == 0 {
            let data = Vec::new();
            verify_source_blob_digest(digest, &data, path.as_ref())?;
            return Ok(Some(data));
        }
        let get_result = match self.block_on(self.store.get_opts(
            &path,
            GetOptions {
                // HEAD already proved this exact range fits both limits. Never
                // ask the store for max+1 bytes merely to detect oversize: the
                // returned metadata is checked again before the body is read.
                range: Some(GetRange::Bounded(0..metadata.size)),
                ..GetOptions::default()
            },
        )) {
            Ok(result) => result,
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "GCS source blob load failed for {path}: {error}"
                )))
            }
        };
        validate_source_blob_read_size(get_result.meta.size, max_bytes, path.as_ref())?;
        let bytes = self.block_on(get_result.bytes()).map_err(|error| {
            KinDbError::StorageError(format!(
                "GCS source blob read bytes failed for {path}: {error}"
            ))
        })?;
        let data = bytes.to_vec();
        let data_len = u64::try_from(data.len()).map_err(|_| {
            KinDbError::StorageError(format!(
                "GCS source blob byte length does not fit the read boundary for {path}"
            ))
        })?;
        validate_source_blob_read_size(data_len, max_bytes, path.as_ref())?;
        if data_len != metadata.size {
            return Err(KinDbError::StorageError(format!(
                "GCS source blob changed size while reading {path}: HEAD reported {}, body returned {data_len}",
                metadata.size
            )));
        }
        verify_source_blob_digest(digest, &data, path.as_ref())?;
        Ok(Some(data))
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
        // has one conditional commit point. Any visible journal is therefore
        // unbound legacy state or a post-migration write from an old binary.
        // Silently deleting or ignoring it would acknowledge graph state that
        // is absent from the full-snapshot authority.
        let deltas = self.list_delta_objects(repo_id)?;
        if !deltas.is_empty() {
            return Err(KinDbError::StorageError(format!(
                "GCS repo {repo_id} has {} unbound or mixed-version delta objects; drain legacy writers and reconcile them before retrying",
                deltas.len()
            )));
        }
        let Some((authority, _has_full_authority)) = self.load_snapshot_object(repo_id)? else {
            return Ok((None, Vec::new()));
        };
        Ok((Some(authority), Vec::new()))
    }

    fn save_snapshot(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let _snapshot = crate::storage::format::GraphSnapshot::from_bytes(data)?;
        let deltas = self.list_delta_objects(repo_id)?;
        if !deltas.is_empty() {
            return Err(KinDbError::StorageError(format!(
                "refusing GCS full-snapshot commit for repo {repo_id}: {} legacy or mixed-version delta objects remain",
                deltas.len()
            )));
        }
        let generation = self.put_full_snapshot_cas(repo_id, data, expected_gen)?;
        // Do not perform another fallible read after the conditional put. At
        // this point authority has committed and callers must receive its new
        // generation so their CAS cursor cannot remain on the pre-commit value.
        // `load_recovery_state` and `clear_deltas` both list journals and fail
        // closed if a legacy writer raced this commit; Kin's retryable
        // post-commit finalizer exercises that fence immediately.
        Ok(generation)
    }

    fn rebuild_legacy_journal(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let _snapshot = crate::storage::format::GraphSnapshot::from_bytes(data)?;
        let captured = self.list_delta_objects(repo_id)?;
        if captured.is_empty() {
            return Err(KinDbError::StorageError(format!(
                "GCS repo {repo_id} has no legacy journal to rebuild"
            )));
        }
        let captured_identity = Self::delta_object_identity(&captured);

        // GCS legacy filenames were wall-clock values, not a provable chain.
        // Never infer graph truth from them. The caller supplies reconciled
        // full bytes; versions are used only to prove the artifact set stayed
        // unchanged before the conditional snapshot promotion.
        let rechecked = self.list_delta_objects(repo_id)?;
        if Self::delta_object_identity(&rechecked) != captured_identity {
            return Err(KinDbError::StorageError(format!(
                "GCS legacy journal changed while rebuilding repo {repo_id}; authority was not committed"
            )));
        }
        let generation = self.put_full_snapshot_cas(repo_id, data, expected_gen)?;

        // Authority is durable. Cleanup is deliberately best effort so an
        // object-store outage cannot strand the caller on the old CAS cursor.
        // Each object is re-headed and removed only if its version/ETag still
        // matches the pre-commit capture. Any residual object keeps normal
        // recovery fail-closed and can be reconciled by retrying this method.
        for (_, captured_meta) in &captured {
            let current = match self.block_on(self.store.head(&captured_meta.location)) {
                Ok(meta) => meta,
                Err(object_store::Error::NotFound { .. }) => continue,
                Err(error) => {
                    tracing::warn!(repo_id, path = %captured_meta.location, error = %error, generation, "GCS rebuild committed; deferred legacy delta verification");
                    continue;
                }
            };
            if current.version != captured_meta.version || current.e_tag != captured_meta.e_tag {
                tracing::warn!(repo_id, path = %captured_meta.location, generation, "GCS rebuild preserved a legacy delta that changed after capture");
                continue;
            }
            if let Err(error) = self.block_on(self.store.delete(&captured_meta.location)) {
                tracing::warn!(repo_id, path = %captured_meta.location, error = %error, generation, "GCS rebuild committed; deferred captured-delta cleanup");
            }
        }
        match self.list_delta_objects(repo_id) {
            Ok(remaining) if !remaining.is_empty() => tracing::warn!(
                repo_id,
                generation,
                remaining = remaining.len(),
                "GCS rebuild committed with residual journal artifacts; recovery remains fail-closed"
            ),
            Err(error) => tracing::warn!(
                repo_id,
                generation,
                error = %error,
                "GCS rebuild committed; could not verify journal drain"
            ),
            Ok(_) => {}
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
        let deltas = self.list_delta_objects(repo_id)?;
        let mut result = Vec::with_capacity(deltas.len());
        for (generation, meta) in deltas {
            if generation <= since_gen {
                continue;
            }
            let path = meta.location;
            let get_result = self.block_on(self.store.get(&path)).map_err(|e| {
                KinDbError::StorageError(format!("GCS delta read failed for {path}: {e}"))
            })?;
            let bytes = self.block_on(get_result.bytes()).map_err(|e| {
                KinDbError::StorageError(format!("GCS delta bytes failed for {path}: {e}"))
            })?;
            result.push((bytes.to_vec(), generation));
        }

        Ok(result)
    }

    fn clear_deltas(&self, repo_id: &str) -> Result<(), KinDbError> {
        let deltas = self.list_delta_objects(repo_id)?;
        if !deltas.is_empty() {
            return Err(KinDbError::StorageError(format!(
                "refusing to delete {} unbound GCS delta objects for repo {repo_id}; reconcile mixed-version writes explicitly",
                deltas.len()
            )));
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
    use async_trait::async_trait;
    use futures_util::stream::BoxStream;
    use futures_util::StreamExt;
    use object_store::memory::InMemory;
    use object_store::{
        CopyOptions, GetResult, ListResult, MultipartUpload, PutMultipartOptions, PutResult,
        Result as ObjectStoreResult,
    };
    use std::collections::HashMap;
    use std::fmt;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Debug)]
    struct VersionState {
        next_generation: Generation,
        versions: HashMap<String, Generation>,
    }

    /// Deterministic GCS-compatible fixture: InMemory payload behavior plus
    /// numeric object versions and atomic UpdateVersion preconditions.
    struct VersionedMemoryStore {
        inner: InMemory,
        state: Arc<tokio::sync::Mutex<VersionState>>,
        fail_next_delete: Arc<AtomicBool>,
        report_next_get_as_oversized: Arc<AtomicBool>,
        body_get_count: Arc<AtomicUsize>,
    }

    impl VersionedMemoryStore {
        fn new() -> Self {
            Self {
                inner: InMemory::new(),
                state: Arc::new(tokio::sync::Mutex::new(VersionState {
                    next_generation: 100,
                    versions: HashMap::new(),
                })),
                fail_next_delete: Arc::new(AtomicBool::new(false)),
                report_next_get_as_oversized: Arc::new(AtomicBool::new(false)),
                body_get_count: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn fail_next_delete(&self) {
            self.fail_next_delete.store(true, Ordering::SeqCst);
        }

        fn report_next_get_as_oversized(&self) {
            self.report_next_get_as_oversized
                .store(true, Ordering::SeqCst);
        }

        fn body_get_count(&self) -> usize {
            self.body_get_count.load(Ordering::SeqCst)
        }

        fn precondition_error(path: &ObjectPath, message: String) -> object_store::Error {
            object_store::Error::Precondition {
                path: path.to_string(),
                source: Box::new(std::io::Error::other(message)),
            }
        }

        fn apply_version(meta: &mut ObjectMeta, state: &VersionState) {
            meta.version = state
                .versions
                .get(meta.location.as_ref())
                .map(ToString::to_string);
        }
    }

    impl fmt::Debug for VersionedMemoryStore {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("VersionedMemoryStore")
        }
    }

    impl fmt::Display for VersionedMemoryStore {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("VersionedMemoryStore")
        }
    }

    #[async_trait]
    impl ObjectStore for VersionedMemoryStore {
        async fn put_opts(
            &self,
            location: &ObjectPath,
            payload: PutPayload,
            opts: PutOptions,
        ) -> ObjectStoreResult<PutResult> {
            let mut state = self.state.lock().await;
            if let PutMode::Update(update) = &opts.mode {
                let expected = update.version.as_deref().ok_or_else(|| {
                    Self::precondition_error(location, "numeric version is required".to_string())
                })?;
                let current = state.versions.get(location.as_ref()).ok_or_else(|| {
                    Self::precondition_error(location, "object has no numeric version".to_string())
                })?;
                if expected != current.to_string() {
                    return Err(Self::precondition_error(
                        location,
                        format!("version {current} does not match {expected}"),
                    ));
                }
            }

            let mut result = self.inner.put_opts(location, payload, opts).await?;
            let generation = state.next_generation;
            state.next_generation += 1;
            state.versions.insert(location.to_string(), generation);
            result.version = Some(generation.to_string());
            Ok(result)
        }

        async fn put_multipart_opts(
            &self,
            location: &ObjectPath,
            opts: PutMultipartOptions,
        ) -> ObjectStoreResult<Box<dyn MultipartUpload>> {
            self.inner.put_multipart_opts(location, opts).await
        }

        async fn get_opts(
            &self,
            location: &ObjectPath,
            options: GetOptions,
        ) -> ObjectStoreResult<GetResult> {
            let reads_body = !options.head;
            let mut result = self.inner.get_opts(location, options).await?;
            if reads_body {
                self.body_get_count.fetch_add(1, Ordering::SeqCst);
            }
            let state = self.state.lock().await;
            Self::apply_version(&mut result.meta, &state);
            if self
                .report_next_get_as_oversized
                .swap(false, Ordering::SeqCst)
            {
                result.meta.size = MAX_SOURCE_BLOB_BYTES + 1;
            }
            Ok(result)
        }

        fn delete_stream(
            &self,
            locations: BoxStream<'static, ObjectStoreResult<ObjectPath>>,
        ) -> BoxStream<'static, ObjectStoreResult<ObjectPath>> {
            if self.fail_next_delete.swap(false, Ordering::SeqCst) {
                return locations
                    .then(|location| async move {
                        let location = location?;
                        Err(object_store::Error::Generic {
                            store: "VersionedMemoryStore",
                            source: Box::new(std::io::Error::other(format!(
                                "injected delete failure for {location}"
                            ))),
                        })
                    })
                    .boxed();
            }
            let state = Arc::clone(&self.state);
            self.inner
                .delete_stream(locations)
                .then(move |result| {
                    let state = Arc::clone(&state);
                    async move {
                        if let Ok(location) = &result {
                            state.lock().await.versions.remove(location.as_ref());
                        }
                        result
                    }
                })
                .boxed()
        }

        fn list(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> BoxStream<'static, ObjectStoreResult<ObjectMeta>> {
            let state = Arc::clone(&self.state);
            self.inner
                .list(prefix)
                .then(move |result| {
                    let state = Arc::clone(&state);
                    async move {
                        let mut meta = result?;
                        let state = state.lock().await;
                        Self::apply_version(&mut meta, &state);
                        Ok(meta)
                    }
                })
                .boxed()
        }

        async fn list_with_delimiter(
            &self,
            prefix: Option<&ObjectPath>,
        ) -> ObjectStoreResult<ListResult> {
            let mut result = self.inner.list_with_delimiter(prefix).await?;
            let state = self.state.lock().await;
            for meta in &mut result.objects {
                Self::apply_version(meta, &state);
            }
            Ok(result)
        }

        async fn copy_opts(
            &self,
            from: &ObjectPath,
            to: &ObjectPath,
            options: CopyOptions,
        ) -> ObjectStoreResult<()> {
            let mut state = self.state.lock().await;
            self.inner.copy_opts(from, to, options).await?;
            let generation = state.next_generation;
            state.next_generation += 1;
            state.versions.insert(to.to_string(), generation);
            Ok(())
        }
    }

    fn test_backend() -> GcsBackend {
        GcsBackend::from_store(Box::new(InMemory::new()), "test")
    }

    fn source_digest(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    #[test]
    fn gcs_source_blob_roundtrips_retries_and_reports_missing() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let data = b"immutable cloud source bytes";
        let digest = source_digest(data);

        assert!(backend
            .load_source_blob("repo-a", digest)
            .unwrap()
            .is_none());
        backend.save_source_blob("repo-a", digest, data).unwrap();
        backend.save_source_blob("repo-a", digest, data).unwrap();
        drop(backend);
        let reopened = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        assert_eq!(
            reopened.load_source_blob("repo-a", digest).unwrap(),
            Some(data.to_vec())
        );
        assert!(reopened
            .load_source_blob("repo-b", digest)
            .unwrap()
            .is_none());
    }

    #[test]
    fn gcs_source_blob_roundtrips_zero_length_object() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let data = b"";
        let digest = source_digest(data);

        backend.save_source_blob("repo-a", digest, data).unwrap();
        assert_eq!(
            backend.load_source_blob("repo-a", digest).unwrap(),
            Some(Vec::new())
        );
        backend
            .save_source_blob("repo-a", digest, data)
            .expect("zero-byte immutable retry remains idempotent");
    }

    #[test]
    fn gcs_source_blob_honors_caller_limit_before_body_get() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let data = b"bounded cloud source bytes";
        let digest = source_digest(data);
        let path = backend.source_blob_path("repo-a", digest).unwrap();
        backend
            .block_on(backend.store.put(&path, PutPayload::from(data.to_vec())))
            .unwrap();

        let error = backend
            .load_source_blob_bounded("repo-a", digest, data.len() as u64 - 1)
            .expect_err("HEAD above the caller limit must reject before GET");
        assert!(matches!(
            error,
            KinDbError::SourceBlobReadLimitExceeded {
                actual_bytes,
                max_bytes
            } if actual_bytes == data.len() as u64 && max_bytes == data.len() as u64 - 1
        ));
        assert_eq!(store.body_get_count(), 0);

        assert_eq!(
            backend
                .load_source_blob_bounded("repo-a", digest, data.len() as u64)
                .unwrap(),
            Some(data.to_vec())
        );
        assert_eq!(store.body_get_count(), 1);
    }

    #[test]
    fn gcs_source_blob_rejects_wrong_digest_corruption_and_unsafe_repo_id() {
        let backend = test_backend();
        let data = b"expected";
        let digest = source_digest(data);

        let wrong_digest_error = backend
            .save_source_blob("repo-a", source_digest(b"different"), data)
            .expect_err("write identity must bind exact bytes");
        assert!(wrong_digest_error.to_string().contains("digest mismatch"));
        for repo_id in ["", ".", "..", "../escape", "owner/repo"] {
            let error = backend
                .load_source_blob(repo_id, digest)
                .expect_err("repo id must not control a GCS object path");
            assert!(error.to_string().contains("invalid repo id"));
        }

        let path = backend.source_blob_path("repo-a", digest).unwrap();
        backend
            .block_on(
                backend
                    .store
                    .put(&path, PutPayload::from(b"corrupt".to_vec())),
            )
            .unwrap();
        let read_error = backend
            .load_source_blob("repo-a", digest)
            .expect_err("corrupt immutable object must fail closed");
        assert!(read_error.to_string().contains("digest mismatch"));
        let retry_error = backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("create retry must not replace corrupt authority");
        assert!(retry_error
            .to_string()
            .contains("retry verification failed"));
    }

    #[test]
    fn gcs_source_blob_rejects_oversized_metadata_before_body_read() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let data = b"small payload with hostile reported size";
        let digest = source_digest(data);
        let path = backend.source_blob_path("repo-a", digest).unwrap();
        backend
            .block_on(backend.store.put(&path, PutPayload::from(data.to_vec())))
            .unwrap();
        store.report_next_get_as_oversized();

        let error = backend
            .load_source_blob("repo-a", digest)
            .expect_err("oversized object metadata must fail before body allocation");
        assert!(error.to_string().contains("safety limit"));
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
        let recovery_error = backend
            .load_recovery_state(repo_id)
            .expect_err("unbound legacy GCS journals must fail closed");
        assert!(recovery_error.to_string().contains("mixed-version delta"));
        let cleanup_error = backend
            .clear_deltas(repo_id)
            .expect_err("automatic cleanup must not erase unbound journal state");
        assert!(cleanup_error.to_string().contains("refusing to delete"));
        assert_eq!(backend.load_deltas_since(repo_id, 0).unwrap().len(), 1);
    }

    #[test]
    fn gcs_versioned_fixture_reopens_exact_full_authority_and_rejects_stale_writer() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "fixture");
        let stale = GcsBackend::from_store(Box::new(Arc::clone(&store)), "fixture");
        let repo_id = "restart-repo";

        let mut base = GraphSnapshot::empty();
        base.file_hashes.insert("base.rs".to_string(), [1; 32]);
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let stale_gen = stale.load_snapshot(repo_id).unwrap().unwrap().1;
        assert_eq!(stale_gen, gen1);

        let mut current = base.clone();
        current
            .file_hashes
            .insert("current.rs".to_string(), [2; 32]);
        let gen2 = backend
            .save_snapshot(repo_id, &current.to_bytes().unwrap(), gen1)
            .unwrap();
        let stale_error = stale
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), stale_gen)
            .expect_err("stale GCS writer must lose conditional update");
        assert!(stale_error.to_string().contains("generation mismatch"));

        let reopened = GcsBackend::from_store(Box::new(Arc::clone(&store)), "fixture");
        let recovered = crate::storage::backend::load_recovered_snapshot(&reopened, repo_id)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.generation, gen2);
        assert_eq!(recovered.snapshot.file_hashes, current.file_hashes);

        let mut after_reopen = recovered.snapshot;
        after_reopen
            .file_hashes
            .insert("after-reopen.rs".to_string(), [3; 32]);
        let gen3 = reopened
            .save_snapshot(repo_id, &after_reopen.to_bytes().unwrap(), gen2)
            .unwrap();
        let final_backend = GcsBackend::from_store(Box::new(store), "fixture");
        let final_recovery =
            crate::storage::backend::load_recovered_snapshot(&final_backend, repo_id)
                .unwrap()
                .unwrap();
        assert_eq!(final_recovery.generation, gen3);
        assert_eq!(
            final_recovery.snapshot.file_hashes,
            after_reopen.file_hashes
        );
    }

    #[test]
    fn gcs_versioned_fixture_fails_closed_on_post_authority_legacy_journal() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "fixture");
        let repo_id = "mixed-version";
        let bytes = GraphSnapshot::empty().to_bytes().unwrap();
        let generation = backend
            .save_snapshot(repo_id, &bytes, GENERATION_INIT)
            .unwrap();
        let delta_path = ObjectPath::from(format!(
            "fixture/{repo_id}/deltas/{:020}.kndd",
            generation + 1
        ));
        let delta = crate::storage::delta::GraphSnapshotDelta::empty(generation)
            .to_bytes()
            .unwrap();
        backend
            .block_on(store.put(&delta_path, PutPayload::from(delta)))
            .unwrap();

        let recovery_error = crate::storage::backend::load_recovered_snapshot(&backend, repo_id)
            .expect_err("post-authority legacy journal must fail closed");
        assert!(recovery_error.to_string().contains("mixed-version delta"));
        backend
            .clear_deltas(repo_id)
            .expect_err("mixed-version journal must be preserved for reconciliation");
        assert_eq!(
            backend
                .load_deltas_since(repo_id, generation)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn gcs_explicit_rebuild_uses_caller_truth_and_preserves_committed_cursor() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "fixture");
        let repo_id = "legacy-rebuild";
        let mut legacy_base = GraphSnapshot::empty();
        legacy_base
            .file_hashes
            .insert("legacy-base.rs".to_string(), [1; 32]);
        let snapshot_path = backend.snapshot_path(repo_id);
        let legacy_put = backend
            .block_on(store.put(
                &snapshot_path,
                PutPayload::from(legacy_base.to_bytes().unwrap()),
            ))
            .unwrap();
        let legacy_generation =
            GcsBackend::numeric_version(legacy_put.version.as_deref(), "legacy test snapshot")
                .unwrap();
        let timestamp_generation = 1_700_000_000_000_000_000_u64;
        let delta_path = ObjectPath::from(format!(
            "fixture/{repo_id}/deltas/{timestamp_generation:020}.kndd"
        ));
        backend
            .block_on(
                store.put(
                    &delta_path,
                    PutPayload::from(
                        crate::storage::delta::GraphSnapshotDelta::empty(legacy_generation)
                            .to_bytes()
                            .unwrap(),
                    ),
                ),
            )
            .unwrap();

        let stale = backend
            .rebuild_legacy_journal(
                repo_id,
                &legacy_base.to_bytes().unwrap(),
                legacy_generation - 1,
            )
            .expect_err("snapshot CAS must reject a stale quiesce cursor");
        assert!(stale.to_string().contains("generation mismatch"));

        // GCS timestamp filenames are not replay authority. The reconciled
        // graph below is deliberately caller-supplied and becomes the exact
        // full snapshot committed by the migration.
        let mut reconciled = legacy_base.clone();
        reconciled
            .file_hashes
            .insert("reconciled.rs".to_string(), [2; 32]);
        store.fail_next_delete();
        let committed = backend
            .rebuild_legacy_journal(repo_id, &reconciled.to_bytes().unwrap(), legacy_generation)
            .expect("conditional authority commit must return despite cleanup failure");
        assert!(committed > legacy_generation);
        let (committed_bytes, tuple_generation) = backend.load_snapshot(repo_id).unwrap().unwrap();
        assert_eq!(tuple_generation, committed);
        assert_eq!(committed_bytes, reconciled.to_bytes().unwrap());
        let recovery_error = crate::storage::backend::load_recovered_snapshot(&backend, repo_id)
            .expect_err("residual journal must keep normal recovery fail-closed");
        assert!(recovery_error.to_string().contains("mixed-version delta"));

        let retried = backend
            .rebuild_legacy_journal(repo_id, &reconciled.to_bytes().unwrap(), committed)
            .unwrap();
        assert!(retried > committed);
        assert!(backend.load_deltas_since(repo_id, 0).unwrap().is_empty());
        let recovered = crate::storage::backend::load_recovered_snapshot(&backend, repo_id)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.generation, retried);
        assert_eq!(recovered.snapshot.file_hashes, reconciled.file_hashes);
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
        let bucket = std::env::var("KINDB_GCS_CAS_BUCKET").expect(
            "KINDB_GCS_CAS_BUCKET must name the credentialed proof bucket; an explicit ignored-test run must never pass by skipping",
        );
        let prefix = format!("v3-recovery-check/{}", uuid::Uuid::new_v4());
        let backend = GcsBackend::new(&bucket, prefix.clone()).unwrap();
        let stale = GcsBackend::new(&bucket, prefix.clone()).unwrap();
        let repo = "cas-test-repo";

        let mut base = GraphSnapshot::empty();
        base.file_hashes.insert("base.rs".to_string(), [1; 32]);
        let bytes = base.to_bytes().unwrap();
        let gen1 = backend
            .save_snapshot(repo, &bytes, GENERATION_INIT)
            .expect("first save (Create) should succeed");
        let stale_gen = stale.load_snapshot(repo).unwrap().unwrap().1;
        assert_eq!(stale_gen, gen1);

        let mut current = base.clone();
        current
            .file_hashes
            .insert("current.rs".to_string(), [2; 32]);
        let gen2 = backend
            .save_snapshot(repo, &current.to_bytes().unwrap(), gen1)
            .expect("second save (conditional Update) must succeed against real GCS");
        stale
            .save_snapshot(repo, &bytes, stale_gen)
            .expect_err("stale real-GCS writer must fail its generation precondition");

        let reopened = GcsBackend::new(&bucket, prefix).unwrap();
        let recovered = crate::storage::backend::load_recovered_snapshot(&reopened, repo)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.generation, gen2);
        assert_eq!(recovered.snapshot.file_hashes, current.file_hashes);

        eprintln!(
            "gens: create={gen1} update={gen2} recovered={}",
            recovered.generation
        );
        reopened
            .block_on(reopened.store.delete(&reopened.snapshot_path(repo)))
            .expect("proof object cleanup should succeed");
    }
}
