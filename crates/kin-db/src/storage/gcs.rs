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
//! {prefix}/{repo_id}/vector-artifacts/v{hash_version}/{snapshot_cursor}/{retrieval_hash}.kvec
//!                                              — checksummed, graph-bound derived vector artifact
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
    verify_source_blob_digest, Generation, PersistedVectorArtifact, SnapshotAuthority,
    SnapshotCursor, SnapshotRecoveryState, SnapshotSaveOutcome, StorageBackend, VectorArtifact,
    VectorArtifactBinding, VectorArtifactCursor, VectorArtifactLoadOutcome,
    VectorArtifactSaveOutcome, VectorRepositoryIdentity, GENERATION_INIT, MAX_SOURCE_BLOB_BYTES,
    MAX_VECTOR_ARTIFACT_BYTES, MAX_VECTOR_ARTIFACT_METADATA_BYTES,
};

const GCS_FULL_AUTHORITY_MAGIC: [u8; 8] = *b"KNGCSF02";
const GCS_FULL_AUTHORITY_HEADER_LEN: usize = 8 + 8 + 32;
const GCS_VECTOR_ARTIFACT_MAGIC: [u8; 8] = *b"KNGCSV02";
const GCS_VECTOR_ARTIFACT_HEADER_LEN: usize = 8 + 32 + 8 + 4 + 32 + 8 + 8 + 32;
const MAX_GCS_VECTOR_ARTIFACT_ENVELOPE_BYTES: u64 = GCS_VECTOR_ARTIFACT_HEADER_LEN as u64
    + MAX_VECTOR_ARTIFACT_METADATA_BYTES
    + MAX_VECTOR_ARTIFACT_BYTES;

#[derive(Debug)]
enum ExactVectorArtifactRetry {
    Missing,
    Exact {
        cursor: VectorArtifactCursor,
        artifact_sha256: [u8; 32],
    },
    Different(VectorArtifactCursor),
    Corrupt {
        cursor: VectorArtifactCursor,
        error: KinDbError,
    },
}

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

    fn vector_artifact_path(
        &self,
        repo_id: &str,
        binding: VectorArtifactBinding,
    ) -> Result<ObjectPath, KinDbError> {
        binding.validate_for_repository(repo_id)?;
        let suffix = format!(
            "{repo_id}/vector-artifacts/v{}/{:020}/{}.kvec",
            binding.retrieval_hash_version,
            binding.snapshot_cursor.backend_generation(),
            hex::encode(binding.retrieval_authority_hash)
        );
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

    fn decode_full_snapshot_authority(bytes: &[u8]) -> Result<Vec<u8>, KinDbError> {
        if !bytes.starts_with(&GCS_FULL_AUTHORITY_MAGIC) {
            return Err(KinDbError::StorageError(
                "GCS snapshot object is not a current full-authority envelope".to_string(),
            ));
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
        Ok(payload.to_vec())
    }

    fn validate_vector_artifact(artifact: &VectorArtifact) -> Result<(), KinDbError> {
        if artifact.binding.snapshot_cursor == SnapshotCursor::INITIAL {
            return Err(KinDbError::StorageError(
                "vector artifact cannot bind the initial snapshot cursor".to_string(),
            ));
        }
        if artifact.binding.retrieval_hash_version
            != crate::storage::merkle::RETRIEVAL_AUTHORITY_HASH_VERSION
        {
            return Err(KinDbError::StorageError(format!(
                "vector artifact retrieval hash version {} does not match current {}",
                artifact.binding.retrieval_hash_version,
                crate::storage::merkle::RETRIEVAL_AUTHORITY_HASH_VERSION
            )));
        }
        let metadata_len = u64::try_from(artifact.metadata.len()).map_err(|_| {
            KinDbError::StorageError("vector artifact metadata length exceeds u64".to_string())
        })?;
        if metadata_len > MAX_VECTOR_ARTIFACT_METADATA_BYTES {
            return Err(KinDbError::StorageError(format!(
                "vector artifact metadata is {metadata_len} bytes, above the {MAX_VECTOR_ARTIFACT_METADATA_BYTES}-byte safety limit"
            )));
        }
        let index_len = u64::try_from(artifact.index.len()).map_err(|_| {
            KinDbError::StorageError("vector artifact index length exceeds u64".to_string())
        })?;
        if index_len > MAX_VECTOR_ARTIFACT_BYTES {
            return Err(KinDbError::StorageError(format!(
                "vector artifact index is {index_len} bytes, above the {MAX_VECTOR_ARTIFACT_BYTES}-byte safety limit"
            )));
        }
        Ok(())
    }

    fn encode_vector_artifact(artifact: &VectorArtifact) -> Result<Vec<u8>, KinDbError> {
        Self::validate_vector_artifact(artifact)?;
        let artifact_sha256 = artifact.artifact_sha256()?;
        let expected_len = GCS_VECTOR_ARTIFACT_HEADER_LEN
            .checked_add(artifact.metadata.len())
            .and_then(|len| len.checked_add(artifact.index.len()))
            .ok_or_else(|| {
                KinDbError::StorageError("vector artifact envelope length overflows".to_string())
            })?;
        let mut encoded = Vec::with_capacity(expected_len);
        encoded.extend_from_slice(&GCS_VECTOR_ARTIFACT_MAGIC);
        encoded.extend_from_slice(&artifact.binding.repository_identity.digest());
        encoded.extend_from_slice(
            &artifact
                .binding
                .snapshot_cursor
                .backend_generation()
                .to_le_bytes(),
        );
        encoded.extend_from_slice(&artifact.binding.retrieval_hash_version.to_le_bytes());
        encoded.extend_from_slice(&artifact.binding.retrieval_authority_hash);
        encoded.extend_from_slice(&(artifact.metadata.len() as u64).to_le_bytes());
        encoded.extend_from_slice(&(artifact.index.len() as u64).to_le_bytes());
        encoded.extend_from_slice(&artifact_sha256);
        encoded.extend_from_slice(&artifact.metadata);
        encoded.extend_from_slice(&artifact.index);
        Ok(encoded)
    }

    fn decode_vector_artifact(
        bytes: &[u8],
        expected_binding: VectorArtifactBinding,
    ) -> Result<(VectorArtifact, [u8; 32]), KinDbError> {
        if bytes.len() < GCS_VECTOR_ARTIFACT_HEADER_LEN {
            return Err(KinDbError::StorageError(
                "GCS vector artifact envelope is truncated".to_string(),
            ));
        }
        if !bytes.starts_with(&GCS_VECTOR_ARTIFACT_MAGIC) {
            return Err(KinDbError::StorageError(
                "GCS vector artifact is not a current integrity envelope".to_string(),
            ));
        }
        let repository_identity =
            VectorRepositoryIdentity::from_digest(bytes[8..40].try_into().expect("fixed range"));
        let snapshot_generation =
            Generation::from_le_bytes(bytes[40..48].try_into().expect("fixed range"));
        let retrieval_hash_version =
            u32::from_le_bytes(bytes[48..52].try_into().expect("fixed range"));
        let retrieval_authority_hash = bytes[52..84].try_into().expect("fixed range");
        let binding = VectorArtifactBinding {
            repository_identity,
            snapshot_cursor: SnapshotCursor::from_backend_generation(snapshot_generation),
            retrieval_hash_version,
            retrieval_authority_hash,
        };
        if binding != expected_binding {
            return Err(KinDbError::StorageError(format!(
                "GCS vector artifact binding mismatch: expected repository {}, snapshot cursor {}, retrieval hash version {}, and retrieval hash {}; found repository {}, snapshot cursor {}, retrieval hash version {}, and retrieval hash {}",
                hex::encode(expected_binding.repository_identity.digest()),
                expected_binding.snapshot_cursor.backend_generation(),
                expected_binding.retrieval_hash_version,
                hex::encode(expected_binding.retrieval_authority_hash),
                hex::encode(binding.repository_identity.digest()),
                binding.snapshot_cursor.backend_generation(),
                binding.retrieval_hash_version,
                hex::encode(binding.retrieval_authority_hash)
            )));
        }
        let metadata_len = u64::from_le_bytes(bytes[84..92].try_into().expect("fixed range"));
        let index_len = u64::from_le_bytes(bytes[92..100].try_into().expect("fixed range"));
        if metadata_len > MAX_VECTOR_ARTIFACT_METADATA_BYTES {
            return Err(KinDbError::StorageError(format!(
                "GCS vector artifact metadata is {metadata_len} bytes, above the {MAX_VECTOR_ARTIFACT_METADATA_BYTES}-byte safety limit"
            )));
        }
        if index_len > MAX_VECTOR_ARTIFACT_BYTES {
            return Err(KinDbError::StorageError(format!(
                "GCS vector artifact index is {index_len} bytes, above the {MAX_VECTOR_ARTIFACT_BYTES}-byte safety limit"
            )));
        }
        let metadata_len = usize::try_from(metadata_len).map_err(|_| {
            KinDbError::StorageError("GCS vector artifact metadata exceeds usize".to_string())
        })?;
        let index_len = usize::try_from(index_len).map_err(|_| {
            KinDbError::StorageError("GCS vector artifact index exceeds usize".to_string())
        })?;
        let expected_len = GCS_VECTOR_ARTIFACT_HEADER_LEN
            .checked_add(metadata_len)
            .and_then(|len| len.checked_add(index_len))
            .ok_or_else(|| {
                KinDbError::StorageError(
                    "GCS vector artifact envelope length overflows".to_string(),
                )
            })?;
        if bytes.len() != expected_len {
            return Err(KinDbError::StorageError(format!(
                "GCS vector artifact length mismatch: expected {expected_len}, found {}",
                bytes.len()
            )));
        }
        let metadata_end = GCS_VECTOR_ARTIFACT_HEADER_LEN + metadata_len;
        let artifact = VectorArtifact {
            binding,
            metadata: bytes[GCS_VECTOR_ARTIFACT_HEADER_LEN..metadata_end].to_vec(),
            index: bytes[metadata_end..].to_vec(),
        };
        let expected_digest: [u8; 32] = bytes[100..132].try_into().expect("fixed range");
        let actual_digest = artifact.artifact_sha256()?;
        if actual_digest != expected_digest {
            return Err(KinDbError::StorageError(
                "GCS vector artifact digest mismatch".to_string(),
            ));
        }
        Ok((artifact, actual_digest))
    }

    fn verify_current_vector_binding(
        &self,
        repo_id: &str,
        binding: VectorArtifactBinding,
    ) -> Result<(), KinDbError> {
        binding.validate_for_repository(repo_id)?;
        let current = self.load_snapshot_cursor(repo_id)?.ok_or_else(|| {
            KinDbError::StorageError(format!(
                "repo {repo_id}: vector artifact binding names missing graph authority"
            ))
        })?;
        if current != binding.snapshot_cursor {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id}: vector artifact snapshot cursor mismatch: expected current {}, found binding {}",
                current.backend_generation(),
                binding.snapshot_cursor.backend_generation()
            )));
        }
        Ok(())
    }

    fn load_vector_artifact_object(
        &self,
        repo_id: &str,
        binding: VectorArtifactBinding,
    ) -> Result<VectorArtifactLoadOutcome, KinDbError> {
        let path = self.vector_artifact_path(repo_id, binding)?;
        let get_result = match self.block_on(self.store.get(&path)) {
            Ok(result) => result,
            Err(object_store::Error::NotFound { .. }) => {
                return Ok(VectorArtifactLoadOutcome::Missing)
            }
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "GCS vector artifact load failed for {path}: {error}"
                )))
            }
        };
        let cursor = VectorArtifactCursor::from_backend_generation(Self::numeric_version(
            get_result.meta.version.as_deref(),
            &format!("vector artifact {path}"),
        )?);
        let meta_size = get_result.meta.size;
        if meta_size > MAX_GCS_VECTOR_ARTIFACT_ENVELOPE_BYTES {
            return Ok(VectorArtifactLoadOutcome::Corrupt {
                cursor,
                error: KinDbError::StorageError(format!(
                    "GCS vector artifact {} is {} bytes, above the {}-byte safety limit",
                    path, meta_size, MAX_GCS_VECTOR_ARTIFACT_ENVELOPE_BYTES
                )),
            });
        }
        let bytes = self.block_on(get_result.bytes()).map_err(|error| {
            KinDbError::StorageError(format!(
                "GCS vector artifact read bytes failed for {path}: {error}"
            ))
        })?;
        let actual_len = match u64::try_from(bytes.len()) {
            Ok(actual_len) => actual_len,
            Err(_) => {
                return Ok(VectorArtifactLoadOutcome::Corrupt {
                    cursor,
                    error: KinDbError::StorageError(format!(
                        "GCS vector artifact byte length does not fit u64 for {path}"
                    )),
                })
            }
        };
        if actual_len != meta_size {
            return Ok(VectorArtifactLoadOutcome::Corrupt {
                cursor,
                error: KinDbError::StorageError(format!(
                    "GCS vector artifact changed size while reading {path}: metadata reported {}, body returned {actual_len}",
                    meta_size
                )),
            });
        }
        let (artifact, artifact_sha256) = match Self::decode_vector_artifact(&bytes, binding) {
            Ok(decoded) => decoded,
            Err(error) => return Ok(VectorArtifactLoadOutcome::Corrupt { cursor, error }),
        };
        Ok(VectorArtifactLoadOutcome::Loaded(PersistedVectorArtifact {
            artifact,
            cursor,
            artifact_sha256,
        }))
    }

    fn confirm_exact_vector_artifact_retry(
        &self,
        repo_id: &str,
        artifact: &VectorArtifact,
        expected: VectorArtifactCursor,
    ) -> Result<ExactVectorArtifactRetry, KinDbError> {
        match self.load_vector_artifact_object(repo_id, artifact.binding)? {
            VectorArtifactLoadOutcome::Missing => Ok(ExactVectorArtifactRetry::Missing),
            VectorArtifactLoadOutcome::Loaded(installed) if installed.cursor == expected => {
                Ok(ExactVectorArtifactRetry::Missing)
            }
            VectorArtifactLoadOutcome::Loaded(installed) if installed.artifact == *artifact => {
                Ok(ExactVectorArtifactRetry::Exact {
                    cursor: installed.cursor,
                    artifact_sha256: installed.artifact_sha256,
                })
            }
            VectorArtifactLoadOutcome::Loaded(installed) => {
                Ok(ExactVectorArtifactRetry::Different(installed.cursor))
            }
            VectorArtifactLoadOutcome::Corrupt { cursor, error } => {
                Ok(ExactVectorArtifactRetry::Corrupt { cursor, error })
            }
        }
    }

    fn load_snapshot_object(&self, repo_id: &str) -> Result<Option<SnapshotAuthority>, KinDbError> {
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
        let snapshot_bytes = Self::decode_full_snapshot_authority(&bytes)?;
        Ok(Some(SnapshotAuthority {
            snapshot_bytes,
            snapshot_generation: generation,
            head_generation: generation,
            // No durable place to bind a history validation here, so every
            // open of a GCS-backed repository validates in full.
            history_validation: None,
        }))
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

    fn put_full_snapshot_cas(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let path = self.snapshot_path(repo_id);
        let payload = PutPayload::from(Self::encode_full_snapshot_authority(data)?);
        let current_meta = match self.block_on(self.store.head(&path)) {
            Ok(meta) => Some(meta),
            Err(object_store::Error::NotFound { .. }) => None,
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "GCS head failed for {path} before save: {error}"
                )));
            }
        };
        let opts = match current_meta {
            None if expected_gen == GENERATION_INIT => PutOptions {
                mode: PutMode::Create,
                ..PutOptions::default()
            },
            None => {
                return Err(KinDbError::StorageError(format!(
                    "GCS snapshot {path} is missing at expected cursor {expected_gen}"
                )));
            }
            Some(meta) => {
                let current_generation =
                    Self::numeric_version(meta.version.as_deref(), &format!("snapshot {path}"))?;
                if current_generation != expected_gen {
                    return match self.confirm_exact_snapshot_retry(repo_id, data, expected_gen)? {
                        Some(installed_generation) => Ok(installed_generation),
                        None => Err(KinDbError::StorageError(format!(
                            "GCS snapshot generation mismatch for {path}: expected {expected_gen}, found {current_generation}"
                        ))),
                    };
                }
                PutOptions {
                    mode: PutMode::Update(UpdateVersion {
                        e_tag: meta.e_tag,
                        version: meta.version,
                    }),
                    ..PutOptions::default()
                }
            }
        };

        let result = match self.block_on(self.store.put_opts(&path, payload, opts)) {
            Ok(result) => result,
            Err(error)
                if matches!(
                    &error,
                    object_store::Error::AlreadyExists { .. }
                        | object_store::Error::Precondition { .. }
                        | object_store::Error::NotModified { .. }
                ) =>
            {
                return match self.confirm_exact_snapshot_retry(repo_id, data, expected_gen) {
                    Ok(Some(installed_generation)) => Ok(installed_generation),
                    Ok(None) => Err(KinDbError::StorageError(format!(
                        "GCS conditional save failed for {path}: {error}"
                    ))),
                    Err(verification_error) => Err(KinDbError::StorageError(format!(
                        "GCS conditional save failed for {path}: {error}; installed authority verification failed: {verification_error}"
                    ))),
                };
            }
            Err(
                error @ (object_store::Error::NotFound { .. }
                | object_store::Error::InvalidPath { .. }
                | object_store::Error::NotSupported { .. }
                | object_store::Error::NotImplemented { .. }
                | object_store::Error::PermissionDenied { .. }
                | object_store::Error::Unauthenticated { .. }
                | object_store::Error::UnknownConfigurationKey { .. }),
            ) => {
                return Err(KinDbError::StorageError(format!(
                    "GCS save was rejected before installation for {path}: {error}"
                )));
            }
            Err(error) => {
                return Err(KinDbError::SnapshotPersistenceIndeterminate(format!(
                    "GCS save outcome is unknown for {path}: {error}"
                )));
            }
        };
        let generation = Self::numeric_version(
            result.version.as_deref(),
            &format!("save result for {path}"),
        )
        .map_err(|error| {
            KinDbError::SnapshotPersistenceIndeterminate(format!(
                "GCS acknowledged save for {path}, but its installed cursor is unknown: {error}"
            ))
        })?;
        if generation <= expected_gen {
            return Err(KinDbError::SnapshotPersistenceIndeterminate(format!(
                "GCS save result for {path} did not advance generation: expected above {expected_gen}, found {generation}"
            )));
        }
        Ok(generation)
    }

    /// Confirm a retry only when the store exposes the exact serialized
    /// candidate at a cursor different from the caller's prior CAS cursor.
    fn confirm_exact_snapshot_retry(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Option<Generation>, KinDbError> {
        let Some(authority) = self.load_snapshot_object(repo_id)? else {
            if expected_gen == GENERATION_INIT {
                return Ok(None);
            }
            return Err(KinDbError::StorageError(format!(
                "GCS snapshot for repo {repo_id} is missing at expected cursor {expected_gen}"
            )));
        };
        let current_generation = authority.head_generation;
        if current_generation == expected_gen {
            return Ok(None);
        }
        if authority.snapshot_bytes == data {
            return Ok(Some(current_generation));
        }
        Err(KinDbError::StorageError(format!(
            "GCS snapshot generation mismatch for repo {repo_id}: expected {expected_gen}, found {current_generation} with different authority bytes"
        )))
    }
}

impl StorageBackend for GcsBackend {
    fn load_snapshot_cursor(&self, repo_id: &str) -> Result<Option<SnapshotCursor>, KinDbError> {
        let deltas = self.list_delta_objects(repo_id)?;
        if !deltas.is_empty() {
            return Err(KinDbError::StorageError(format!(
                "GCS repo {repo_id} has {} unbound delta objects outside current authority",
                deltas.len()
            )));
        }
        let path = self.snapshot_path(repo_id);
        let metadata = match self.block_on(self.store.head(&path)) {
            Ok(metadata) => metadata,
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "GCS snapshot metadata load failed for {path}: {error}"
                )))
            }
        };
        let generation =
            Self::numeric_version(metadata.version.as_deref(), &format!("snapshot {path}"))?;
        Ok(Some(SnapshotCursor::from_backend_generation(generation)))
    }

    fn load_snapshot(&self, repo_id: &str) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
        Ok(self
            .load_snapshot_authority(repo_id)?
            .map(|authority| (authority.snapshot_bytes, authority.snapshot_generation)))
    }

    fn supports_vector_artifacts(&self) -> bool {
        true
    }

    fn load_vector_artifact(
        &self,
        repo_id: &str,
        binding: VectorArtifactBinding,
    ) -> Result<VectorArtifactLoadOutcome, KinDbError> {
        self.verify_current_vector_binding(repo_id, binding)?;
        let outcome = self.load_vector_artifact_object(repo_id, binding)?;
        // Re-read graph authority after probing the object. Missing and corrupt
        // outcomes can both trigger a replacement write, so they require the
        // same exact-authority fence as a successfully decoded artifact.
        self.verify_current_vector_binding(repo_id, binding)?;
        Ok(outcome)
    }

    fn save_vector_artifact(
        &self,
        repo_id: &str,
        artifact: &VectorArtifact,
        expected: VectorArtifactCursor,
    ) -> VectorArtifactSaveOutcome {
        if let Err(error) = Self::validate_vector_artifact(artifact) {
            return VectorArtifactSaveOutcome::NotCommitted {
                error,
                observed_cursor: None,
            };
        }
        if let Err(error) = artifact.binding.validate_for_repository(repo_id) {
            return VectorArtifactSaveOutcome::NotCommitted {
                error,
                observed_cursor: None,
            };
        }
        let current_snapshot_cursor = match self.load_snapshot_cursor(repo_id) {
            Ok(Some(cursor)) => cursor,
            Ok(None) => {
                return VectorArtifactSaveOutcome::NotCommitted {
                    error: KinDbError::StorageError(format!(
                        "repo {repo_id}: vector artifact binding names missing graph authority"
                    )),
                    observed_cursor: None,
                }
            }
            Err(error) => {
                return VectorArtifactSaveOutcome::Indeterminate {
                    error: KinDbError::StorageError(format!(
                        "repo {repo_id}: graph authority could not be verified before vector artifact save: {error}"
                    )),
                    observed_cursor: None,
                }
            }
        };
        if current_snapshot_cursor != artifact.binding.snapshot_cursor {
            return VectorArtifactSaveOutcome::NotCommitted {
                error: KinDbError::StorageError(format!(
                    "repo {repo_id}: vector artifact snapshot cursor mismatch: expected current {}, found binding {}",
                    current_snapshot_cursor.backend_generation(),
                    artifact.binding.snapshot_cursor.backend_generation()
                )),
                observed_cursor: None,
            };
        }
        let path = match self.vector_artifact_path(repo_id, artifact.binding) {
            Ok(path) => path,
            Err(error) => {
                return VectorArtifactSaveOutcome::NotCommitted {
                    error,
                    observed_cursor: None,
                }
            }
        };
        let encoded = match Self::encode_vector_artifact(artifact) {
            Ok(encoded) => encoded,
            Err(error) => {
                return VectorArtifactSaveOutcome::NotCommitted {
                    error,
                    observed_cursor: None,
                }
            }
        };
        let artifact_sha256: [u8; 32] = encoded[100..132]
            .try_into()
            .expect("validated vector envelope has a fixed digest range");
        let current_meta = match self.block_on(self.store.head(&path)) {
            Ok(meta) => Some(meta),
            Err(object_store::Error::NotFound { .. }) => None,
            Err(error) => {
                return VectorArtifactSaveOutcome::Indeterminate {
                    error: KinDbError::StorageError(format!(
                        "GCS head failed for vector artifact {path} before save: {error}"
                    )),
                    observed_cursor: None,
                }
            }
        };
        let options = match current_meta {
            None if expected == VectorArtifactCursor::INITIAL => PutOptions {
                mode: PutMode::Create,
                ..PutOptions::default()
            },
            None => {
                return VectorArtifactSaveOutcome::NotCommitted {
                    error: KinDbError::StorageError(format!(
                        "GCS vector artifact {path} is missing at expected cursor {}",
                        expected.backend_generation()
                    )),
                    observed_cursor: None,
                }
            }
            Some(meta) => {
                let current = match Self::numeric_version(
                    meta.version.as_deref(),
                    &format!("vector artifact {path}"),
                ) {
                    Ok(generation) => VectorArtifactCursor::from_backend_generation(generation),
                    Err(error) => {
                        return VectorArtifactSaveOutcome::Indeterminate {
                            error,
                            observed_cursor: None,
                        }
                    }
                };
                if current != expected {
                    return match self.confirm_exact_vector_artifact_retry(
                        repo_id, artifact, expected,
                    ) {
                        Ok(ExactVectorArtifactRetry::Exact {
                            cursor,
                            artifact_sha256,
                        }) => match self.verify_current_vector_binding(repo_id, artifact.binding) {
                            Ok(()) => VectorArtifactSaveOutcome::Committed {
                                cursor,
                                artifact_sha256,
                            },
                            Err(error) => VectorArtifactSaveOutcome::Indeterminate {
                                error: KinDbError::StorageError(format!(
                                    "GCS vector artifact {path} was already installed at cursor {}, but graph authority moved before retry acknowledgement: {error}",
                                    cursor.backend_generation()
                                )),
                                observed_cursor: Some(cursor),
                            },
                        },
                        Ok(ExactVectorArtifactRetry::Different(observed_cursor)) => {
                            VectorArtifactSaveOutcome::NotCommitted {
                                error: KinDbError::StorageError(format!(
                                    "GCS vector artifact cursor mismatch for {path}: expected {}, found {}",
                                    expected.backend_generation(),
                                    observed_cursor.backend_generation()
                                )),
                                observed_cursor: Some(observed_cursor),
                            }
                        }
                        Ok(ExactVectorArtifactRetry::Corrupt {
                            cursor: observed_cursor,
                            error,
                        }) => VectorArtifactSaveOutcome::NotCommitted {
                            error: KinDbError::StorageError(format!(
                                "GCS vector artifact cursor mismatch for {path}: expected {}, found corrupt object at {}: {error}",
                                expected.backend_generation(),
                                observed_cursor.backend_generation()
                            )),
                            observed_cursor: Some(observed_cursor),
                        },
                        Ok(ExactVectorArtifactRetry::Missing) => {
                            VectorArtifactSaveOutcome::NotCommitted {
                                error: KinDbError::StorageError(format!(
                                    "GCS vector artifact cursor mismatch for {path}: expected {}, found {}",
                                    expected.backend_generation(),
                                    current.backend_generation()
                                )),
                                observed_cursor: Some(current),
                            }
                        }
                        Err(error) => VectorArtifactSaveOutcome::Indeterminate {
                            error: KinDbError::StorageError(format!(
                                "GCS vector artifact cursor mismatch for {path}: expected {}, found {}; confirmation failed: {error}",
                                expected.backend_generation(),
                                current.backend_generation()
                            )),
                            observed_cursor: Some(current),
                        },
                    };
                }
                PutOptions {
                    mode: PutMode::Update(UpdateVersion {
                        e_tag: meta.e_tag,
                        version: meta.version,
                    }),
                    ..PutOptions::default()
                }
            }
        };

        let put_result = self.block_on(self.store.put_opts(
            &path,
            PutPayload::from(encoded),
            options,
        ));
        let result = match put_result {
            Ok(result) => result,
            Err(error) => {
                let confirmation =
                    self.confirm_exact_vector_artifact_retry(repo_id, artifact, expected);
                let confirmation_detail = match confirmation {
                    Ok(ExactVectorArtifactRetry::Exact {
                        cursor,
                        artifact_sha256,
                    }) => {
                        return match self
                            .verify_current_vector_binding(repo_id, artifact.binding)
                        {
                            Ok(()) => VectorArtifactSaveOutcome::Committed {
                                cursor,
                                artifact_sha256,
                            },
                            Err(binding_error) => VectorArtifactSaveOutcome::Indeterminate {
                                error: KinDbError::StorageError(format!(
                                    "GCS vector artifact {path} was installed at cursor {}, but graph authority moved before acknowledgement: {binding_error}",
                                    cursor.backend_generation()
                                )),
                                observed_cursor: Some(cursor),
                            },
                        };
                    }
                    Ok(ExactVectorArtifactRetry::Different(observed_cursor)) => {
                        return VectorArtifactSaveOutcome::NotCommitted {
                            error: KinDbError::StorageError(format!(
                                "GCS vector artifact save failed for {path}: {error}; readback found a different installed object at cursor {}",
                                observed_cursor.backend_generation()
                            )),
                            observed_cursor: Some(observed_cursor),
                        };
                    }
                    Ok(ExactVectorArtifactRetry::Corrupt {
                        cursor: observed_cursor,
                        error: read_error,
                    }) => {
                        return VectorArtifactSaveOutcome::NotCommitted {
                            error: KinDbError::StorageError(format!(
                                "GCS vector artifact save failed for {path}: {error}; readback found a corrupt installed object at cursor {}: {read_error}",
                                observed_cursor.backend_generation()
                            )),
                            observed_cursor: Some(observed_cursor),
                        };
                    }
                    Ok(ExactVectorArtifactRetry::Missing) => {
                        "no exact installed candidate was found".to_string()
                    }
                    Err(read_error) => {
                        return VectorArtifactSaveOutcome::Indeterminate {
                            error: KinDbError::StorageError(format!(
                                "GCS vector artifact save failed for {path}: {error}; installed candidate verification failed: {read_error}"
                            )),
                            observed_cursor: None,
                        };
                    }
                };

                let rejected_before_install = matches!(
                    &error,
                    object_store::Error::AlreadyExists { .. }
                        | object_store::Error::Precondition { .. }
                        | object_store::Error::NotModified { .. }
                        | object_store::Error::NotFound { .. }
                        | object_store::Error::InvalidPath { .. }
                        | object_store::Error::NotSupported { .. }
                        | object_store::Error::NotImplemented { .. }
                        | object_store::Error::PermissionDenied { .. }
                        | object_store::Error::Unauthenticated { .. }
                        | object_store::Error::UnknownConfigurationKey { .. }
                );
                let classified = KinDbError::StorageError(format!(
                    "GCS vector artifact save failed for {path}: {error}; {confirmation_detail}"
                ));
                return if rejected_before_install {
                    VectorArtifactSaveOutcome::NotCommitted {
                        error: classified,
                        observed_cursor: None,
                    }
                } else {
                    VectorArtifactSaveOutcome::Indeterminate {
                        error: classified,
                        observed_cursor: None,
                    }
                };
            }
        };

        let cursor = match Self::numeric_version(
            result.version.as_deref(),
            &format!("vector artifact save result for {path}"),
        ) {
            Ok(generation) => VectorArtifactCursor::from_backend_generation(generation),
            Err(error) => {
                return VectorArtifactSaveOutcome::Indeterminate {
                    error: KinDbError::StorageError(format!(
                        "GCS acknowledged vector artifact save for {path}, but its installed cursor is unknown: {error}"
                    )),
                    observed_cursor: None,
                }
            }
        };
        if cursor.backend_generation() <= expected.backend_generation() {
            return VectorArtifactSaveOutcome::Indeterminate {
                error: KinDbError::StorageError(format!(
                    "GCS vector artifact save for {path} did not advance its cursor: expected above {}, found {}",
                    expected.backend_generation(),
                    cursor.backend_generation()
                )),
                observed_cursor: Some(cursor),
            };
        }

        match self.load_vector_artifact_object(repo_id, artifact.binding) {
            Ok(VectorArtifactLoadOutcome::Loaded(installed))
                if installed.cursor == cursor
                    && installed.artifact_sha256 == artifact_sha256
                    && installed.artifact == *artifact => {}
            Ok(VectorArtifactLoadOutcome::Loaded(installed)) => {
                return VectorArtifactSaveOutcome::Indeterminate {
                    error: KinDbError::StorageError(format!(
                        "GCS acknowledged vector artifact save for {path} at cursor {}, but readback found cursor {} or different bytes",
                        cursor.backend_generation(),
                        installed.cursor.backend_generation()
                    )),
                    observed_cursor: Some(installed.cursor),
                }
            }
            Ok(VectorArtifactLoadOutcome::Missing) => {
                return VectorArtifactSaveOutcome::Indeterminate {
                    error: KinDbError::StorageError(format!(
                        "GCS acknowledged vector artifact save for {path} at cursor {}, but readback found no object",
                        cursor.backend_generation()
                    )),
                    observed_cursor: None,
                }
            }
            Ok(VectorArtifactLoadOutcome::Corrupt {
                cursor: observed_cursor,
                error,
            }) => {
                return VectorArtifactSaveOutcome::Indeterminate {
                    error: KinDbError::StorageError(format!(
                        "GCS acknowledged vector artifact save for {path} at cursor {}, but readback found a corrupt object at cursor {}: {error}",
                        cursor.backend_generation(),
                        observed_cursor.backend_generation()
                    )),
                    observed_cursor: Some(observed_cursor),
                }
            }
            Err(error) => {
                return VectorArtifactSaveOutcome::Indeterminate {
                    error: KinDbError::StorageError(format!(
                        "GCS acknowledged vector artifact save for {path} at cursor {}, but readback failed: {error}",
                        cursor.backend_generation()
                    )),
                    observed_cursor: None,
                }
            }
        }
        if let Err(error) = self.verify_current_vector_binding(repo_id, artifact.binding) {
            return VectorArtifactSaveOutcome::Indeterminate {
                error: KinDbError::StorageError(format!(
                    "GCS vector artifact {path} committed at cursor {}, but graph authority moved before acknowledgement: {error}",
                    cursor.backend_generation()
                )),
                observed_cursor: Some(cursor),
            };
        }
        VectorArtifactSaveOutcome::Committed {
            cursor,
            artifact_sha256,
        }
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

    fn source_blob_len(&self, repo_id: &str, digest: [u8; 32]) -> Result<Option<u64>, KinDbError> {
        validate_source_blob_repo_id(repo_id)?;
        let path = self.source_blob_path(repo_id, digest)?;
        match self.block_on(self.store.head(&path)) {
            Ok(metadata) => {
                validate_source_blob_size(metadata.size, path.as_ref())?;
                Ok(Some(metadata.size))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(error) => Err(KinDbError::StorageError(format!(
                "GCS source blob metadata load failed for {path}: {error}"
            ))),
        }
    }

    fn load_snapshot_authority(
        &self,
        repo_id: &str,
    ) -> Result<Option<SnapshotAuthority>, KinDbError> {
        self.load_snapshot_object(repo_id)
    }

    fn load_recovery_state(&self, repo_id: &str) -> Result<SnapshotRecoveryState, KinDbError> {
        // GCS incremental writes are disabled until snapshot+journal authority
        // has one conditional commit point. Any visible journal is unbound
        // state and must fail closed.
        let deltas = self.list_delta_objects(repo_id)?;
        if !deltas.is_empty() {
            return Err(KinDbError::StorageError(format!(
                "GCS repo {repo_id} has {} unbound delta objects outside current authority",
                deltas.len()
            )));
        }
        let Some(authority) = self.load_snapshot_object(repo_id)? else {
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
                "refusing GCS full-snapshot commit for repo {repo_id}: {} unbound delta objects remain",
                deltas.len()
            )));
        }
        let generation = self.put_full_snapshot_cas(repo_id, data, expected_gen)?;
        // Do not perform another fallible read after the conditional put. At
        // this point authority has committed and callers must receive its new
        // generation so their CAS cursor cannot remain on the pre-commit value.
        // `load_recovery_state` and `clear_deltas` both list journals and fail
        // closed if an unbound write raced this commit.
        Ok(generation)
    }

    fn save_snapshot_classified(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_cursor: SnapshotCursor,
    ) -> SnapshotSaveOutcome {
        match self.save_snapshot(repo_id, data, expected_cursor.backend_generation()) {
            Ok(generation) => SnapshotSaveOutcome::Committed {
                cursor: SnapshotCursor::from_backend_generation(generation),
            },
            Err(error @ KinDbError::SnapshotPersistenceIndeterminate(_)) => {
                SnapshotSaveOutcome::Indeterminate(error)
            }
            Err(error) => SnapshotSaveOutcome::NotCommitted(error),
        }
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
        if deltas.is_empty() {
            return Ok(Vec::new());
        }
        Err(KinDbError::StorageError(format!(
            "GCS repo {repo_id} has {} unbound delta objects while reading after generation {since_gen}",
            deltas.len()
        )))
    }

    fn clear_deltas(&self, repo_id: &str) -> Result<(), KinDbError> {
        let deltas = self.list_delta_objects(repo_id)?;
        if !deltas.is_empty() {
            return Err(KinDbError::StorageError(format!(
                "refusing to delete {} unbound GCS delta objects for repo {repo_id}",
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
pub(crate) mod tests {
    use super::*;
    use crate::storage::format::GraphSnapshot;
    use crate::storage::RepositoryAuthorityManager;
    use async_trait::async_trait;
    use futures_util::stream::BoxStream;
    use futures_util::StreamExt;
    use kin_model::{
        compute_resolved_tree_hash, AdmissionCase, AuthorId, DefaultRefExpectation,
        DefaultRefMutation, EffectiveAdmissionPolicyStamp, FrozenLocalOverlay,
        FrozenLocalOverlayDelta, OperationId, RefName, RepositoryId, RepositoryTransaction,
        ResolvedTree, SharedAdmissionPolicy, WorkspaceExpectation, WorkspaceHead, WorkspaceId,
        WorkspaceMutation, WorkspaceSemanticDelta, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
    };
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
    pub(crate) struct VersionedMemoryStore {
        inner: InMemory,
        state: Arc<tokio::sync::Mutex<VersionState>>,
        report_next_get_as_oversized: Arc<AtomicBool>,
        body_get_count: Arc<AtomicUsize>,
        snapshot_body_get_count: Arc<AtomicUsize>,
        fail_next_put_after_commit: Arc<AtomicBool>,
        fail_next_put_before_commit: Arc<AtomicBool>,
        fail_next_snapshot_head: Arc<AtomicBool>,
        fail_next_vector_head: Arc<AtomicBool>,
        fail_next_vector_body_get: Arc<AtomicBool>,
        omit_next_vector_head_version: Arc<AtomicBool>,
        advance_snapshot_cursor_on_next_vector_get: Arc<AtomicBool>,
    }

    impl VersionedMemoryStore {
        pub(crate) fn new() -> Self {
            Self {
                inner: InMemory::new(),
                state: Arc::new(tokio::sync::Mutex::new(VersionState {
                    next_generation: 100,
                    versions: HashMap::new(),
                })),
                report_next_get_as_oversized: Arc::new(AtomicBool::new(false)),
                body_get_count: Arc::new(AtomicUsize::new(0)),
                snapshot_body_get_count: Arc::new(AtomicUsize::new(0)),
                fail_next_put_after_commit: Arc::new(AtomicBool::new(false)),
                fail_next_put_before_commit: Arc::new(AtomicBool::new(false)),
                fail_next_snapshot_head: Arc::new(AtomicBool::new(false)),
                fail_next_vector_head: Arc::new(AtomicBool::new(false)),
                fail_next_vector_body_get: Arc::new(AtomicBool::new(false)),
                omit_next_vector_head_version: Arc::new(AtomicBool::new(false)),
                advance_snapshot_cursor_on_next_vector_get: Arc::new(AtomicBool::new(false)),
            }
        }

        fn report_next_get_as_oversized(&self) {
            self.report_next_get_as_oversized
                .store(true, Ordering::SeqCst);
        }

        fn body_get_count(&self) -> usize {
            self.body_get_count.load(Ordering::SeqCst)
        }

        fn snapshot_body_get_count(&self) -> usize {
            self.snapshot_body_get_count.load(Ordering::SeqCst)
        }

        fn fail_next_put_after_commit(&self) {
            self.fail_next_put_after_commit
                .store(true, Ordering::SeqCst);
        }

        fn fail_next_put_before_commit(&self) {
            self.fail_next_put_before_commit
                .store(true, Ordering::SeqCst);
        }

        fn fail_next_snapshot_head(&self) {
            self.fail_next_snapshot_head.store(true, Ordering::SeqCst);
        }

        fn fail_next_vector_head(&self) {
            self.fail_next_vector_head.store(true, Ordering::SeqCst);
        }

        fn fail_next_vector_body_get(&self) {
            self.fail_next_vector_body_get.store(true, Ordering::SeqCst);
        }

        fn omit_next_vector_head_version(&self) {
            self.omit_next_vector_head_version
                .store(true, Ordering::SeqCst);
        }

        fn advance_snapshot_cursor_on_next_vector_get(&self) {
            self.advance_snapshot_cursor_on_next_vector_get
                .store(true, Ordering::SeqCst);
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
            if self
                .fail_next_put_before_commit
                .swap(false, Ordering::SeqCst)
            {
                return Err(object_store::Error::Generic {
                    store: "VersionedMemoryStore",
                    source: Box::new(std::io::Error::other(
                        "injected ambiguous failure before object install",
                    )),
                });
            }
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
            if self
                .fail_next_put_after_commit
                .swap(false, Ordering::SeqCst)
            {
                return Err(object_store::Error::Generic {
                    store: "VersionedMemoryStore",
                    source: Box::new(std::io::Error::other(
                        "injected acknowledgement loss after object install",
                    )),
                });
            }
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
            let is_head = options.head;
            let reads_body = !is_head;
            let is_vector = location.as_ref().contains("/vector-artifacts/");
            if is_head
                && location.as_ref().ends_with("graph.kndb")
                && self.fail_next_snapshot_head.swap(false, Ordering::SeqCst)
            {
                return Err(object_store::Error::Generic {
                    store: "VersionedMemoryStore",
                    source: Box::new(std::io::Error::other("injected snapshot HEAD uncertainty")),
                });
            }
            if is_head && is_vector && self.fail_next_vector_head.swap(false, Ordering::SeqCst) {
                return Err(object_store::Error::Generic {
                    store: "VersionedMemoryStore",
                    source: Box::new(std::io::Error::other("injected vector HEAD uncertainty")),
                });
            }
            if reads_body
                && is_vector
                && self.fail_next_vector_body_get.swap(false, Ordering::SeqCst)
            {
                return Err(object_store::Error::Generic {
                    store: "VersionedMemoryStore",
                    source: Box::new(std::io::Error::other(
                        "injected vector body read uncertainty",
                    )),
                });
            }
            if reads_body
                && is_vector
                && self
                    .advance_snapshot_cursor_on_next_vector_get
                    .swap(false, Ordering::SeqCst)
            {
                let mut state = self.state.lock().await;
                let snapshot_path = state
                    .versions
                    .keys()
                    .find(|path| path.ends_with("graph.kndb"))
                    .cloned()
                    .expect("fixture must have a graph snapshot before a vector probe");
                let generation = state.next_generation;
                state.next_generation += 1;
                state.versions.insert(snapshot_path, generation);
            }
            let mut result = self.inner.get_opts(location, options).await?;
            if reads_body {
                self.body_get_count.fetch_add(1, Ordering::SeqCst);
                if location.as_ref().ends_with("graph.kndb") {
                    self.snapshot_body_get_count.fetch_add(1, Ordering::SeqCst);
                }
            }
            let state = self.state.lock().await;
            Self::apply_version(&mut result.meta, &state);
            if is_head
                && is_vector
                && self
                    .omit_next_vector_head_version
                    .swap(false, Ordering::SeqCst)
            {
                result.meta.version = None;
            }
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

    fn vector_binding(
        backend: &GcsBackend,
        repo_id: &str,
        snapshot: &GraphSnapshot,
    ) -> VectorArtifactBinding {
        let cursor = backend
            .load_snapshot_cursor(repo_id)
            .unwrap()
            .expect("saved snapshot must have a cursor");
        VectorArtifactBinding::for_repository(
            repo_id,
            cursor,
            crate::storage::merkle::compute_retrieval_authority_hash(snapshot),
        )
        .unwrap()
    }

    #[test]
    fn gcs_vector_artifact_roundtrips_across_reopen_with_its_own_cas_cursor() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let repo_id = "vector-repo";
        let snapshot = GraphSnapshot::empty();
        backend
            .save_snapshot(repo_id, &snapshot.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let artifact = VectorArtifact {
            binding: vector_binding(&backend, repo_id, &snapshot),
            metadata: br#"{"indexed":2,"total":2}"#.to_vec(),
            index: b"opaque vector index bytes".to_vec(),
        };
        let body_reads_before_vectors = store.body_get_count();
        let snapshot_body_reads_before_vectors = store.snapshot_body_get_count();

        assert!(
            backend.supports_vector_artifacts(),
            "GCS must advertise durable vector-artifact persistence"
        );
        assert!(matches!(
            backend
                .load_vector_artifact(repo_id, artifact.binding)
                .unwrap(),
            VectorArtifactLoadOutcome::Missing
        ));
        let (cursor, artifact_sha256) =
            match backend.save_vector_artifact(repo_id, &artifact, VectorArtifactCursor::INITIAL) {
                VectorArtifactSaveOutcome::Committed {
                    cursor,
                    artifact_sha256,
                } => (cursor, artifact_sha256),
                other => panic!("initial vector artifact save did not commit: {other:?}"),
            };
        assert_ne!(cursor, VectorArtifactCursor::INITIAL);
        assert_eq!(artifact_sha256, artifact.artifact_sha256().unwrap());

        drop(backend);
        let reopened = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        match reopened
            .load_vector_artifact(repo_id, artifact.binding)
            .unwrap()
        {
            VectorArtifactLoadOutcome::Loaded(installed) => assert_eq!(
                installed,
                PersistedVectorArtifact {
                    artifact: artifact.clone(),
                    cursor,
                    artifact_sha256,
                }
            ),
            other => panic!("reopened vector artifact did not load: {other:?}"),
        }

        let (retry_cursor, retry_sha256) = match reopened.save_vector_artifact(
            repo_id,
            &artifact,
            VectorArtifactCursor::INITIAL,
        ) {
            VectorArtifactSaveOutcome::Committed {
                cursor,
                artifact_sha256,
            } => (cursor, artifact_sha256),
            other => panic!("exact vector artifact retry did not reconcile: {other:?}"),
        };
        assert_eq!(retry_cursor, cursor, "an exact retry must not rewrite");
        assert_eq!(retry_sha256, artifact_sha256);

        let updated = VectorArtifact {
            binding: artifact.binding,
            metadata: br#"{"indexed":3,"total":3}"#.to_vec(),
            index: b"updated opaque vector index bytes".to_vec(),
        };
        let (updated_cursor, updated_sha256) =
            match reopened.save_vector_artifact(repo_id, &updated, cursor) {
                VectorArtifactSaveOutcome::Committed {
                    cursor,
                    artifact_sha256,
                } => (cursor, artifact_sha256),
                other => panic!("vector artifact CAS update did not commit: {other:?}"),
            };
        assert_ne!(updated_cursor, cursor);
        assert_ne!(updated_sha256, artifact_sha256);
        match reopened.save_vector_artifact(repo_id, &artifact, cursor) {
            VectorArtifactSaveOutcome::NotCommitted {
                observed_cursor: Some(observed),
                ..
            } => assert_eq!(observed, updated_cursor),
            other => panic!("stale vector CAS did not report the observed cursor: {other:?}"),
        }
        match reopened
            .load_vector_artifact(repo_id, updated.binding)
            .unwrap()
        {
            VectorArtifactLoadOutcome::Loaded(installed) => assert_eq!(
                installed,
                PersistedVectorArtifact {
                    artifact: updated,
                    cursor: updated_cursor,
                    artifact_sha256: updated_sha256,
                }
            ),
            other => panic!("updated vector artifact did not load: {other:?}"),
        }
        assert_eq!(
            store.snapshot_body_get_count(),
            snapshot_body_reads_before_vectors,
            "vector load/save/reopen must verify graph authority from object metadata only"
        );
        assert!(
            store.body_get_count() > body_reads_before_vectors,
            "the fixture must observe vector body reads while snapshot body reads stay flat"
        );
    }

    #[test]
    fn gcs_vector_artifact_fails_closed_on_stale_or_cross_repository_binding() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let repo_id = "bound-vector-repo";
        let snapshot = GraphSnapshot::empty();
        backend
            .save_snapshot(repo_id, &snapshot.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let binding = vector_binding(&backend, repo_id, &snapshot);

        let stale = VectorArtifactBinding {
            snapshot_cursor: SnapshotCursor::from_backend_generation(
                binding.snapshot_cursor.backend_generation() + 1,
            ),
            ..binding
        };
        let stale_error = backend
            .load_vector_artifact(repo_id, stale)
            .expect_err("a stale graph cursor must not load vectors");
        assert!(stale_error.to_string().contains("snapshot cursor mismatch"));

        let unsupported_version = VectorArtifactBinding {
            retrieval_hash_version: binding.retrieval_hash_version + 1,
            ..binding
        };
        let version_error = backend
            .load_vector_artifact(repo_id, unsupported_version)
            .expect_err("an unknown retrieval hash version must fail closed");
        assert!(version_error.to_string().contains("retrieval hash version"));

        let cross_repository = VectorArtifact {
            binding: VectorArtifactBinding::for_repository(
                "different-repo",
                binding.snapshot_cursor,
                binding.retrieval_authority_hash,
            )
            .unwrap(),
            metadata: b"metadata".to_vec(),
            index: b"index".to_vec(),
        };
        let cross_repository_error = match backend.save_vector_artifact(
            repo_id,
            &cross_repository,
            VectorArtifactCursor::INITIAL,
        ) {
            VectorArtifactSaveOutcome::NotCommitted { error, .. } => error,
            other => panic!("cross-repository binding was not refused: {other:?}"),
        };
        assert!(cross_repository_error
            .to_string()
            .contains("repository identity mismatch"));
    }

    #[test]
    fn gcs_vector_artifact_envelope_detects_corruption_and_relabeling() {
        let binding = VectorArtifactBinding::for_repository(
            "envelope-repo",
            SnapshotCursor::from_backend_generation(42),
            [0x42; 32],
        )
        .unwrap();
        let artifact = VectorArtifact {
            binding,
            metadata: b"metadata".to_vec(),
            index: b"index".to_vec(),
        };
        let encoded = GcsBackend::encode_vector_artifact(&artifact).unwrap();
        let (decoded, decoded_sha256) =
            GcsBackend::decode_vector_artifact(&encoded, binding).unwrap();
        assert_eq!(decoded, artifact);
        assert_eq!(decoded_sha256, artifact.artifact_sha256().unwrap());

        let mut corrupt = encoded.clone();
        *corrupt.last_mut().unwrap() ^= 0xff;
        let corrupt_error = GcsBackend::decode_vector_artifact(&corrupt, binding)
            .expect_err("corrupt vector bytes must fail their envelope digest");
        assert!(corrupt_error.to_string().contains("digest mismatch"));

        let truncated_error = GcsBackend::decode_vector_artifact(
            &encoded[..GCS_VECTOR_ARTIFACT_HEADER_LEN - 1],
            binding,
        )
        .expect_err("a truncated envelope must fail before allocation");
        assert!(truncated_error.to_string().contains("truncated"));

        let mut oversized = encoded.clone();
        oversized[92..100].copy_from_slice(&(MAX_VECTOR_ARTIFACT_BYTES + 1).to_le_bytes());
        let oversized_error = GcsBackend::decode_vector_artifact(&oversized, binding)
            .expect_err("an oversized declared index must fail before allocation");
        assert!(oversized_error.to_string().contains("above the"));

        for offset in [8usize, 40, 48, 52] {
            let mut rebound = encoded.clone();
            rebound[offset] ^= 0x01;
            let error = GcsBackend::decode_vector_artifact(&rebound, binding)
                .expect_err("every outer binding field must be checked independently");
            assert!(error.to_string().contains("binding mismatch"));
        }

        let relabeled = VectorArtifactBinding::for_repository(
            "other-envelope-repo",
            binding.snapshot_cursor,
            binding.retrieval_authority_hash,
        )
        .unwrap();
        let relabel_error = GcsBackend::decode_vector_artifact(&encoded, relabeled)
            .expect_err("artifact bytes must not be copied into another repository namespace");
        assert!(relabel_error.to_string().contains("binding mismatch"));
    }

    #[test]
    fn gcs_vector_artifact_cross_repository_copy_is_repairable_corruption() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let source_repo = "vector-copy-source";
        let destination_repo = "vector-copy-destination";
        let snapshot = GraphSnapshot::empty();
        backend
            .save_snapshot(source_repo, &snapshot.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        backend
            .save_snapshot(
                destination_repo,
                &snapshot.to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .unwrap();
        let destination_binding = vector_binding(&backend, destination_repo, &snapshot);
        let copied_artifact = VectorArtifact {
            binding: VectorArtifactBinding::for_repository(
                source_repo,
                destination_binding.snapshot_cursor,
                destination_binding.retrieval_authority_hash,
            )
            .unwrap(),
            metadata: b"metadata".to_vec(),
            index: b"index".to_vec(),
        };
        let destination_path = backend
            .vector_artifact_path(destination_repo, destination_binding)
            .unwrap();
        let copied_put = backend
            .block_on(store.put_opts(
                &destination_path,
                PutPayload::from(GcsBackend::encode_vector_artifact(&copied_artifact).unwrap()),
                PutOptions::default(),
            ))
            .unwrap();
        let copied_cursor = VectorArtifactCursor::from_backend_generation(
            copied_put.version.unwrap().parse().unwrap(),
        );

        match backend
            .load_vector_artifact(destination_repo, destination_binding)
            .unwrap()
        {
            VectorArtifactLoadOutcome::Corrupt { cursor, error } => {
                assert_eq!(cursor, copied_cursor);
                assert!(error.to_string().contains("binding mismatch"));
            }
            other => panic!("cross-repository copy was not refused as corruption: {other:?}"),
        }
    }

    #[test]
    fn gcs_vector_artifact_recovers_an_exact_post_install_acknowledgement_loss() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let repo_id = "vector-ack-loss";
        let snapshot = GraphSnapshot::empty();
        backend
            .save_snapshot(repo_id, &snapshot.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let artifact = VectorArtifact {
            binding: vector_binding(&backend, repo_id, &snapshot),
            metadata: b"metadata".to_vec(),
            index: b"index".to_vec(),
        };

        store.fail_next_put_after_commit();
        let (cursor, artifact_sha256) =
            match backend.save_vector_artifact(repo_id, &artifact, VectorArtifactCursor::INITIAL) {
                VectorArtifactSaveOutcome::Committed {
                    cursor,
                    artifact_sha256,
                } => (cursor, artifact_sha256),
                other => panic!("exact installed artifact was not reconciled: {other:?}"),
            };
        match backend
            .load_vector_artifact(repo_id, artifact.binding)
            .unwrap()
        {
            VectorArtifactLoadOutcome::Loaded(installed) => assert_eq!(
                installed,
                PersistedVectorArtifact {
                    artifact,
                    cursor,
                    artifact_sha256,
                }
            ),
            other => panic!("acknowledged artifact did not load: {other:?}"),
        }
    }

    #[test]
    fn gcs_vector_artifact_ambiguous_preinstall_failure_is_indeterminate() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let repo_id = "vector-ambiguous-preinstall";
        let snapshot = GraphSnapshot::empty();
        backend
            .save_snapshot(repo_id, &snapshot.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let artifact = VectorArtifact {
            binding: vector_binding(&backend, repo_id, &snapshot),
            metadata: b"metadata".to_vec(),
            index: b"index".to_vec(),
        };

        store.fail_next_put_before_commit();
        match backend.save_vector_artifact(repo_id, &artifact, VectorArtifactCursor::INITIAL) {
            VectorArtifactSaveOutcome::Indeterminate {
                error,
                observed_cursor: None,
            } => assert!(error.to_string().contains("ambiguous failure")),
            other => panic!("ambiguous write failure was misclassified: {other:?}"),
        }
        assert!(matches!(
            backend
                .load_vector_artifact(repo_id, artifact.binding)
                .unwrap(),
            VectorArtifactLoadOutcome::Missing
        ));
    }

    #[test]
    fn gcs_vector_artifact_write_failure_with_unreadable_confirmation_is_indeterminate() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let repo_id = "vector-unreadable-write-confirmation";
        let snapshot = GraphSnapshot::empty();
        backend
            .save_snapshot(repo_id, &snapshot.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let artifact = VectorArtifact {
            binding: vector_binding(&backend, repo_id, &snapshot),
            metadata: b"metadata".to_vec(),
            index: b"index".to_vec(),
        };

        store.fail_next_put_before_commit();
        store.fail_next_vector_body_get();
        match backend.save_vector_artifact(repo_id, &artifact, VectorArtifactCursor::INITIAL) {
            VectorArtifactSaveOutcome::Indeterminate {
                error,
                observed_cursor: None,
            } => {
                let message = error.to_string();
                assert!(message.contains("installed candidate verification failed"));
                assert!(message.contains("vector body read uncertainty"));
            }
            other => panic!("unreadable write confirmation was misclassified: {other:?}"),
        }
    }

    #[test]
    fn gcs_vector_artifact_snapshot_head_uncertainty_is_indeterminate() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let repo_id = "vector-snapshot-head-uncertainty";
        let snapshot = GraphSnapshot::empty();
        backend
            .save_snapshot(repo_id, &snapshot.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let artifact = VectorArtifact {
            binding: vector_binding(&backend, repo_id, &snapshot),
            metadata: b"metadata".to_vec(),
            index: b"index".to_vec(),
        };

        store.fail_next_snapshot_head();
        match backend.save_vector_artifact(repo_id, &artifact, VectorArtifactCursor::INITIAL) {
            VectorArtifactSaveOutcome::Indeterminate {
                error,
                observed_cursor: None,
            } => assert!(error.to_string().contains("snapshot HEAD uncertainty")),
            other => panic!("snapshot HEAD uncertainty was misclassified: {other:?}"),
        }
    }

    #[test]
    fn gcs_vector_artifact_vector_head_uncertainty_is_indeterminate() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let repo_id = "vector-object-head-uncertainty";
        let snapshot = GraphSnapshot::empty();
        backend
            .save_snapshot(repo_id, &snapshot.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let artifact = VectorArtifact {
            binding: vector_binding(&backend, repo_id, &snapshot),
            metadata: b"metadata".to_vec(),
            index: b"index".to_vec(),
        };

        store.fail_next_vector_head();
        match backend.save_vector_artifact(repo_id, &artifact, VectorArtifactCursor::INITIAL) {
            VectorArtifactSaveOutcome::Indeterminate {
                error,
                observed_cursor: None,
            } => assert!(error.to_string().contains("vector HEAD uncertainty")),
            other => panic!("vector HEAD uncertainty was misclassified: {other:?}"),
        }
    }

    #[test]
    fn gcs_vector_artifact_unknown_prewrite_cursor_is_indeterminate() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let repo_id = "vector-unknown-prewrite-cursor";
        let snapshot = GraphSnapshot::empty();
        backend
            .save_snapshot(repo_id, &snapshot.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let artifact = VectorArtifact {
            binding: vector_binding(&backend, repo_id, &snapshot),
            metadata: b"metadata".to_vec(),
            index: b"index".to_vec(),
        };
        let cursor =
            match backend.save_vector_artifact(repo_id, &artifact, VectorArtifactCursor::INITIAL) {
                VectorArtifactSaveOutcome::Committed { cursor, .. } => cursor,
                other => panic!("initial vector artifact save did not commit: {other:?}"),
            };

        store.omit_next_vector_head_version();
        match backend.save_vector_artifact(repo_id, &artifact, cursor) {
            VectorArtifactSaveOutcome::Indeterminate {
                error,
                observed_cursor: None,
            } => assert!(error.to_string().contains("missing object meta.version")),
            other => panic!("unknown object cursor was misclassified: {other:?}"),
        }
    }

    #[test]
    fn gcs_vector_artifact_stale_confirmation_uncertainty_carries_observed_cursor() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let repo_id = "vector-stale-confirmation-uncertainty";
        let snapshot = GraphSnapshot::empty();
        backend
            .save_snapshot(repo_id, &snapshot.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let first = VectorArtifact {
            binding: vector_binding(&backend, repo_id, &snapshot),
            metadata: b"metadata".to_vec(),
            index: b"first".to_vec(),
        };
        let first_cursor =
            match backend.save_vector_artifact(repo_id, &first, VectorArtifactCursor::INITIAL) {
                VectorArtifactSaveOutcome::Committed { cursor, .. } => cursor,
                other => panic!("initial vector artifact save did not commit: {other:?}"),
            };
        let second = VectorArtifact {
            binding: first.binding,
            metadata: first.metadata.clone(),
            index: b"second".to_vec(),
        };
        let second_cursor = match backend.save_vector_artifact(repo_id, &second, first_cursor) {
            VectorArtifactSaveOutcome::Committed { cursor, .. } => cursor,
            other => panic!("replacement vector artifact save did not commit: {other:?}"),
        };

        store.fail_next_vector_body_get();
        match backend.save_vector_artifact(repo_id, &first, first_cursor) {
            VectorArtifactSaveOutcome::Indeterminate {
                error,
                observed_cursor: Some(observed_cursor),
            } => {
                assert_eq!(observed_cursor, second_cursor);
                assert!(error.to_string().contains("vector body read uncertainty"));
            }
            other => panic!("stale confirmation uncertainty was misclassified: {other:?}"),
        }
    }

    #[test]
    fn gcs_vector_artifact_valid_load_does_not_attach_after_graph_moves() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let repo_id = "vector-valid-load-race";
        let snapshot = GraphSnapshot::empty();
        backend
            .save_snapshot(repo_id, &snapshot.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let artifact = VectorArtifact {
            binding: vector_binding(&backend, repo_id, &snapshot),
            metadata: b"metadata".to_vec(),
            index: b"index".to_vec(),
        };
        match backend.save_vector_artifact(repo_id, &artifact, VectorArtifactCursor::INITIAL) {
            VectorArtifactSaveOutcome::Committed { .. } => {}
            other => panic!("initial vector artifact save did not commit: {other:?}"),
        }

        store.advance_snapshot_cursor_on_next_vector_get();
        let error = backend
            .load_vector_artifact(repo_id, artifact.binding)
            .expect_err("graph cursor movement after a valid body read must fail the load");
        assert!(error.to_string().contains("snapshot cursor mismatch"));
    }

    #[test]
    fn gcs_vector_artifact_successful_put_is_indeterminate_if_graph_moves_on_readback() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let repo_id = "vector-successful-put-race";
        let snapshot = GraphSnapshot::empty();
        backend
            .save_snapshot(repo_id, &snapshot.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let artifact = VectorArtifact {
            binding: vector_binding(&backend, repo_id, &snapshot),
            metadata: b"metadata".to_vec(),
            index: b"index".to_vec(),
        };

        store.advance_snapshot_cursor_on_next_vector_get();
        match backend.save_vector_artifact(repo_id, &artifact, VectorArtifactCursor::INITIAL) {
            VectorArtifactSaveOutcome::Indeterminate {
                error,
                observed_cursor: Some(cursor),
            } => {
                assert_ne!(cursor, VectorArtifactCursor::INITIAL);
                assert!(error.to_string().contains("graph authority moved"));
            }
            other => panic!("successful old-graph put was incorrectly acknowledged: {other:?}"),
        }
    }

    #[test]
    fn gcs_vector_artifact_exact_retry_does_not_ack_after_graph_moves() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let repo_id = "vector-exact-retry-race";
        let snapshot = GraphSnapshot::empty();
        backend
            .save_snapshot(repo_id, &snapshot.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let artifact = VectorArtifact {
            binding: vector_binding(&backend, repo_id, &snapshot),
            metadata: b"metadata".to_vec(),
            index: b"index".to_vec(),
        };
        let cursor =
            match backend.save_vector_artifact(repo_id, &artifact, VectorArtifactCursor::INITIAL) {
                VectorArtifactSaveOutcome::Committed { cursor, .. } => cursor,
                other => panic!("initial vector artifact save did not commit: {other:?}"),
            };

        store.advance_snapshot_cursor_on_next_vector_get();
        match backend.save_vector_artifact(repo_id, &artifact, VectorArtifactCursor::INITIAL) {
            VectorArtifactSaveOutcome::Indeterminate {
                error,
                observed_cursor: Some(observed),
            } => {
                assert_eq!(observed, cursor);
                assert!(error.to_string().contains("graph authority moved"));
            }
            other => panic!("exact retry acknowledged stale graph authority: {other:?}"),
        }
    }

    #[test]
    fn gcs_vector_artifact_corruption_returns_a_trusted_repair_cursor() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let repo_id = "vector-corrupt-repair";
        let snapshot = GraphSnapshot::empty();
        backend
            .save_snapshot(repo_id, &snapshot.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let artifact = VectorArtifact {
            binding: vector_binding(&backend, repo_id, &snapshot),
            metadata: b"metadata".to_vec(),
            index: b"index".to_vec(),
        };
        let original_cursor =
            match backend.save_vector_artifact(repo_id, &artifact, VectorArtifactCursor::INITIAL) {
                VectorArtifactSaveOutcome::Committed { cursor, .. } => cursor,
                other => panic!("initial vector artifact save did not commit: {other:?}"),
            };

        let path = backend
            .vector_artifact_path(repo_id, artifact.binding)
            .unwrap();
        let mut corrupted = GcsBackend::encode_vector_artifact(&artifact).unwrap();
        *corrupted.last_mut().unwrap() ^= 0xff;
        let corrupt_put = backend
            .block_on(store.put_opts(&path, PutPayload::from(corrupted), PutOptions::default()))
            .unwrap();
        let corrupt_cursor = VectorArtifactCursor::from_backend_generation(
            corrupt_put.version.unwrap().parse().unwrap(),
        );
        assert_ne!(corrupt_cursor, original_cursor);

        match backend
            .load_vector_artifact(repo_id, artifact.binding)
            .unwrap()
        {
            VectorArtifactLoadOutcome::Corrupt { cursor, error } => {
                assert_eq!(cursor, corrupt_cursor);
                assert!(error.to_string().contains("digest mismatch"));
            }
            other => panic!("corrupt vector artifact was not classified: {other:?}"),
        }

        match backend.save_vector_artifact(repo_id, &artifact, VectorArtifactCursor::INITIAL) {
            VectorArtifactSaveOutcome::NotCommitted {
                observed_cursor: Some(observed),
                ..
            } => assert_eq!(observed, corrupt_cursor),
            other => panic!(
                "an initial cursor overwrote corruption or discarded its repair cursor: {other:?}"
            ),
        }

        let (repaired_cursor, repaired_sha256) =
            match backend.save_vector_artifact(repo_id, &artifact, corrupt_cursor) {
                VectorArtifactSaveOutcome::Committed {
                    cursor,
                    artifact_sha256,
                } => (cursor, artifact_sha256),
                other => panic!("corrupt vector artifact was not repairable: {other:?}"),
            };
        assert_ne!(repaired_cursor, corrupt_cursor);
        match backend
            .load_vector_artifact(repo_id, artifact.binding)
            .unwrap()
        {
            VectorArtifactLoadOutcome::Loaded(installed) => {
                assert_eq!(installed.artifact, artifact);
                assert_eq!(installed.cursor, repaired_cursor);
                assert_eq!(installed.artifact_sha256, repaired_sha256);
            }
            other => panic!("repaired vector artifact did not load: {other:?}"),
        }
    }

    #[test]
    fn gcs_vector_artifact_rechecks_graph_cursor_after_a_missing_probe() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let repo_id = "vector-missing-race";
        let snapshot = GraphSnapshot::empty();
        backend
            .save_snapshot(repo_id, &snapshot.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let binding = vector_binding(&backend, repo_id, &snapshot);

        store.advance_snapshot_cursor_on_next_vector_get();
        let error = backend
            .load_vector_artifact(repo_id, binding)
            .expect_err("graph cursor movement after a missing probe must fail the load");
        assert!(error.to_string().contains("snapshot cursor mismatch"));
    }

    #[test]
    fn gcs_vector_artifact_rechecks_graph_cursor_after_a_corrupt_probe() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "test");
        let repo_id = "vector-corrupt-race";
        let snapshot = GraphSnapshot::empty();
        backend
            .save_snapshot(repo_id, &snapshot.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let artifact = VectorArtifact {
            binding: vector_binding(&backend, repo_id, &snapshot),
            metadata: b"metadata".to_vec(),
            index: b"index".to_vec(),
        };
        let path = backend
            .vector_artifact_path(repo_id, artifact.binding)
            .unwrap();
        let mut corrupted = GcsBackend::encode_vector_artifact(&artifact).unwrap();
        *corrupted.last_mut().unwrap() ^= 0xff;
        backend
            .block_on(store.put_opts(&path, PutPayload::from(corrupted), PutOptions::default()))
            .unwrap();

        store.advance_snapshot_cursor_on_next_vector_get();
        let error = backend
            .load_vector_artifact(repo_id, artifact.binding)
            .expect_err("graph cursor movement after a corrupt probe must fail the load");
        assert!(error.to_string().contains("snapshot cursor mismatch"));
    }

    fn unborn_authority_transaction(
        manager: &RepositoryAuthorityManager<GcsBackend>,
        repository_id: &RepositoryId,
        workspace_id: WorkspaceId,
        publish_default_ref: bool,
    ) -> RepositoryTransaction {
        let default_ref = RefName::branch(b"main").unwrap();
        let head = WorkspaceHead::Symbolic {
            target: default_ref.clone(),
        };
        let tree_hash = compute_resolved_tree_hash(&ResolvedTree::default()).unwrap();
        let shared = SharedAdmissionPolicy::empty(0);
        let overlay =
            FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::Sensitive, Vec::new()).unwrap();
        let policy = EffectiveAdmissionPolicyStamp {
            shared: shared.stamp(),
            local: overlay.stamp(),
        };
        let workspace_mutation = WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustNotExist,
            new_generation: 0,
            new_head: head.clone(),
            new_base_target: None,
            new_base_tree_hash: None,
            tree_deltas: Vec::new(),
            new_tree_hash: tree_hash,
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: shared,
            new_admission_policy: policy,
        };
        let lease = manager.read_authority();
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id: repository_id.clone(),
            expected_generation: lease.roots().generation,
            expected_roots: lease.roots().clone(),
            actor: AuthorId::new("gcs-authority-test"),
            reason: "publish an exact unborn GCS workspace".to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: Vec::new(),
            aliases: Vec::new(),
            ref_mutations: Vec::new(),
            default_ref_mutation: publish_default_ref.then_some(DefaultRefMutation {
                expected: DefaultRefExpectation::MustBeUnset,
                new_default: Some(default_ref),
            }),
            workspace_mutation: Some(workspace_mutation),
            local_overlay_delta: Some(FrozenLocalOverlayDelta::initialize(overlay)),
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        drop(lease);
        transaction
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
        assert_eq!(
            reopened.source_blob_len("repo-a", digest).unwrap(),
            Some(data.len() as u64)
        );
        assert!(reopened
            .load_source_blob("repo-b", digest)
            .unwrap()
            .is_none());
        assert!(reopened
            .source_blob_len("repo-b", digest)
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

        let cursor_error = backend
            .load_snapshot_cursor("test-repo")
            .expect_err("cursor probes must reject ETag-only authority too");
        assert!(cursor_error
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
        let decoded = GcsBackend::decode_full_snapshot_authority(&encoded).unwrap();
        assert_eq!(decoded, bytes);

        let error = GcsBackend::decode_full_snapshot_authority(&bytes)
            .expect_err("raw snapshot bytes are not current GCS authority");
        assert!(error.to_string().contains("not a current"));

        let mut corrupt = encoded;
        *corrupt.last_mut().unwrap() ^= 0xff;
        let error = GcsBackend::decode_full_snapshot_authority(&corrupt)
            .expect_err("corrupt authoritative envelope must fail closed");
        assert!(error.to_string().contains("digest mismatch"));
    }

    #[test]
    fn gcs_backend_rejects_unbound_delta_objects() {
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

        let unbound_path = ObjectPath::from(format!("test/{repo_id}/deltas/{:020}.kndd", 43_u64));
        backend
            .block_on(backend.store.put(&unbound_path, PutPayload::from(delta)))
            .unwrap();
        backend
            .load_deltas_since(repo_id, 0)
            .expect_err("unbound GCS deltas must not be exposed as replay authority");
        let recovery_error = backend
            .load_recovery_state(repo_id)
            .expect_err("unbound GCS journals must fail closed");
        assert!(recovery_error.to_string().contains("unbound delta"));
        let cleanup_error = backend
            .clear_deltas(repo_id)
            .expect_err("automatic cleanup must not erase unbound journal state");
        assert!(cleanup_error.to_string().contains("refusing to delete"));
        backend
            .load_deltas_since(repo_id, 0)
            .expect_err("unbound journal state must remain fail-closed");
    }

    #[test]
    fn gcs_versioned_fixture_reopens_exact_full_authority_and_rejects_stale_writer() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "fixture");
        let stale = GcsBackend::from_store(Box::new(Arc::clone(&store)), "fixture");
        let repo_id = "restart-repo";

        let mut base = GraphSnapshot::empty();
        base.admit_artifact_for_test("base.rs".to_string(), crate::types::regular_tree_entry(1));
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let stale_gen = stale.load_snapshot(repo_id).unwrap().unwrap().1;
        assert_eq!(stale_gen, gen1);

        let mut current = base.clone();
        current.admit_artifact_for_test(
            "current.rs".to_string(),
            crate::types::regular_tree_entry(2),
        );
        let current_bytes = current.to_bytes().unwrap();
        let gen2 = backend
            .save_snapshot(repo_id, &current_bytes, gen1)
            .unwrap();
        let stale_error = stale
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), stale_gen)
            .expect_err("stale GCS writer must lose conditional update");
        assert!(stale_error.to_string().contains("generation mismatch"));

        let reopened = GcsBackend::from_store(Box::new(Arc::clone(&store)), "fixture");
        let recovered_authority =
            crate::storage::backend::load_recovered_repository_authority(&reopened, repo_id, 0)
                .unwrap()
                .unwrap();
        let stats = recovered_authority.payload_stats;
        let recovered = recovered_authority.recovered;
        assert_eq!(recovered.generation, gen2);
        assert_eq!(recovered.snapshot.resolved_tree, current.resolved_tree);
        assert_eq!(stats.snapshot_generation(), gen2);
        assert_eq!(stats.head_generation(), gen2);
        assert_eq!(stats.snapshot_bytes(), current_bytes.len() as u64);
        assert_eq!(stats.acknowledged_delta_count(), 0);
        assert_eq!(stats.acknowledged_delta_bytes(), 0);
        assert_eq!(stats.total_payload_bytes(), current_bytes.len() as u64);

        let mut after_reopen = recovered.snapshot;
        after_reopen.admit_artifact_for_test(
            "after-reopen.rs".to_string(),
            crate::types::regular_tree_entry(3),
        );
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
            final_recovery.snapshot.resolved_tree,
            after_reopen.resolved_tree
        );
    }

    #[test]
    fn repository_authority_separates_logical_generation_from_gcs_version() {
        let store = Arc::new(VersionedMemoryStore::new());
        let repository_id = RepositoryId::new("gcs-authority-repo").unwrap();
        let backend = Arc::new(GcsBackend::from_store(
            Box::new(Arc::clone(&store)),
            "fixture",
        ));
        let stale_backend = Arc::new(GcsBackend::from_store(
            Box::new(Arc::clone(&store)),
            "fixture",
        ));
        let manager =
            RepositoryAuthorityManager::open(repository_id.clone(), Arc::clone(&backend)).unwrap();
        let stale = RepositoryAuthorityManager::open(repository_id.clone(), stale_backend).unwrap();
        let stale_transaction =
            unborn_authority_transaction(&stale, &repository_id, WorkspaceId::new(), false);

        let first =
            unborn_authority_transaction(&manager, &repository_id, WorkspaceId::new(), true);
        let receipt = manager.commit_repository_transaction(first).unwrap();
        assert_eq!(receipt.generation, 1);
        assert_eq!(
            backend
                .load_snapshot(repository_id.as_str())
                .unwrap()
                .unwrap()
                .1,
            100,
            "provider-assigned version is deliberately not Kin generation 1"
        );

        stale
            .commit_repository_transaction(stale_transaction)
            .expect_err("a manager holding the pre-create GCS cursor must lose CAS");
        assert_eq!(stale.read_authority().roots().generation, 0);

        let reopened_backend = Arc::new(GcsBackend::from_store(
            Box::new(Arc::clone(&store)),
            "fixture",
        ));
        let reopened =
            RepositoryAuthorityManager::open(repository_id.clone(), Arc::clone(&reopened_backend))
                .unwrap();
        assert_eq!(reopened.read_authority().roots().generation, 1);

        let second =
            unborn_authority_transaction(&reopened, &repository_id, WorkspaceId::new(), false);
        let receipt = reopened.commit_repository_transaction(second).unwrap();
        assert_eq!(receipt.generation, 2);
        assert_eq!(
            reopened_backend
                .load_snapshot(repository_id.as_str())
                .unwrap()
                .unwrap()
                .1,
            101
        );

        let final_backend = Arc::new(GcsBackend::from_store(Box::new(store), "fixture"));
        let final_manager = RepositoryAuthorityManager::open(repository_id, final_backend).unwrap();
        assert_eq!(final_manager.read_authority().roots().generation, 2);
    }

    #[test]
    fn repository_authority_recovers_gcs_post_install_error_live_and_after_reopen() {
        let store = Arc::new(VersionedMemoryStore::new());
        let repository_id = RepositoryId::new("gcs-indeterminate-authority").unwrap();
        let backend = Arc::new(GcsBackend::from_store(
            Box::new(Arc::clone(&store)),
            "fixture",
        ));
        let manager =
            RepositoryAuthorityManager::open(repository_id.clone(), Arc::clone(&backend)).unwrap();
        let transaction =
            unborn_authority_transaction(&manager, &repository_id, WorkspaceId::new(), true);

        store.fail_next_put_after_commit();
        let error = manager
            .commit_repository_transaction(transaction.clone())
            .expect_err("installed object with a lost acknowledgement is indeterminate");
        assert!(matches!(
            error,
            KinDbError::SnapshotPersistenceIndeterminate(_)
        ));
        assert_eq!(manager.read_authority().roots().generation, 0);

        let installed = backend
            .load_snapshot_authority(repository_id.as_str())
            .unwrap()
            .expect("the provider installed the exact candidate");
        assert_eq!(installed.head_generation, 100);
        let installed_bytes = installed.snapshot_bytes;

        let reopened_backend = Arc::new(GcsBackend::from_store(
            Box::new(Arc::clone(&store)),
            "fixture",
        ));
        let reopened =
            RepositoryAuthorityManager::open(repository_id.clone(), reopened_backend).unwrap();
        assert_eq!(reopened.read_authority().roots().generation, 1);
        let reopened_receipt = reopened
            .commit_repository_transaction(transaction.clone())
            .expect("reopen must recognize the installed operation as idempotent");

        let live_receipt = manager
            .commit_repository_transaction(transaction)
            .expect("live manager must publish its retained exact candidate before prepare");
        assert_eq!(live_receipt, reopened_receipt);
        assert_eq!(manager.read_authority().roots().generation, 1);
        let final_authority = backend
            .load_snapshot_authority(repository_id.as_str())
            .unwrap()
            .unwrap();
        assert_eq!(final_authority.head_generation, 100);
        assert_eq!(
            final_authority.snapshot_bytes, installed_bytes,
            "reconciliation must not emit a timestamp-rebuilt successor"
        );
    }

    #[test]
    fn gcs_exact_content_retry_confirms_installed_candidate_without_rewrite() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "fixture");
        let repo_id = "gcs-exact-retry";
        let bytes = GraphSnapshot::empty().to_bytes().unwrap();

        store.fail_next_put_after_commit();
        let error = backend
            .save_snapshot(repo_id, &bytes, GENERATION_INIT)
            .expect_err("provider acknowledgement loss must be surfaced");
        assert!(matches!(
            error,
            KinDbError::SnapshotPersistenceIndeterminate(_)
        ));

        let cursor = backend
            .save_snapshot(repo_id, &bytes, GENERATION_INIT)
            .expect("exact retry must confirm the installed candidate");
        assert_eq!(cursor, 100);
        assert_eq!(
            backend.load_snapshot(repo_id).unwrap().unwrap().1,
            100,
            "confirmation must not create provider version 101"
        );
    }

    #[test]
    fn gcs_normal_snapshot_cas_does_not_download_the_existing_body() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "fixture");
        let repo_id = "gcs-metadata-cas";
        let base = GraphSnapshot::empty().to_bytes().unwrap();
        let cursor = backend
            .save_snapshot(repo_id, &base, GENERATION_INIT)
            .unwrap();

        let mut successor = GraphSnapshot::empty();
        successor.admit_artifact_for_test(
            "compose.yaml".to_string(),
            crate::types::regular_tree_entry(1),
        );
        backend
            .save_snapshot(repo_id, &successor.to_bytes().unwrap(), cursor)
            .unwrap();
        assert_eq!(
            store.body_get_count(),
            0,
            "normal CAS should use HEAD; only retry reconciliation needs exact bytes"
        );
    }

    #[test]
    fn gcs_snapshot_cursor_probe_is_metadata_only_and_tracks_publication() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "fixture");
        let repo_id = "gcs-cursor-probe";

        assert_eq!(backend.load_snapshot_cursor(repo_id).unwrap(), None);
        assert_eq!(store.body_get_count(), 0);

        let base = GraphSnapshot::empty().to_bytes().unwrap();
        let first = backend
            .save_snapshot(repo_id, &base, GENERATION_INIT)
            .unwrap();
        assert_eq!(
            backend.load_snapshot_cursor(repo_id).unwrap(),
            Some(SnapshotCursor::from_backend_generation(first))
        );
        assert_eq!(
            store.body_get_count(),
            0,
            "a publication identity probe must not download snapshot bytes"
        );

        let mut successor = GraphSnapshot::empty();
        successor.admit_artifact_for_test(
            "cursor.txt".to_string(),
            crate::types::regular_tree_entry(1),
        );
        let second = backend
            .save_snapshot(repo_id, &successor.to_bytes().unwrap(), first)
            .unwrap();
        assert_ne!(second, first);
        assert_eq!(
            backend.load_snapshot_cursor(repo_id).unwrap(),
            Some(SnapshotCursor::from_backend_generation(second))
        );
        assert_eq!(
            store.body_get_count(),
            0,
            "the changed publication must still be detected by metadata alone"
        );
    }

    #[test]
    fn gcs_versioned_fixture_fails_closed_on_post_authority_unbound_journal() {
        let store = Arc::new(VersionedMemoryStore::new());
        let backend = GcsBackend::from_store(Box::new(Arc::clone(&store)), "fixture");
        let repo_id = "unbound-journal";
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
            .expect_err("post-authority unbound journal must fail closed");
        assert!(recovery_error.to_string().contains("unbound delta"));
        assert!(
            backend
                .load_snapshot_cursor(repo_id)
                .expect_err("a metadata-only cursor probe must preserve the same refusal")
                .to_string()
                .contains("unbound delta"),
            "a cache probe must never hide state that makes a full open fail closed"
        );
        backend
            .clear_deltas(repo_id)
            .expect_err("unbound journal must not be silently deleted");
        backend
            .load_deltas_since(repo_id, generation)
            .expect_err("unbound journal must not become replay authority");
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
        base.admit_artifact_for_test("base.rs".to_string(), crate::types::regular_tree_entry(1));
        let bytes = base.to_bytes().unwrap();
        let gen1 = backend
            .save_snapshot(repo, &bytes, GENERATION_INIT)
            .expect("first save (Create) should succeed");
        assert_eq!(
            backend.load_snapshot_cursor(repo).unwrap(),
            Some(SnapshotCursor::from_backend_generation(gen1))
        );
        let stale_gen = stale.load_snapshot(repo).unwrap().unwrap().1;
        assert_eq!(stale_gen, gen1);

        let mut current = base.clone();
        current.admit_artifact_for_test(
            "current.rs".to_string(),
            crate::types::regular_tree_entry(2),
        );
        let gen2 = backend
            .save_snapshot(repo, &current.to_bytes().unwrap(), gen1)
            .expect("second save (conditional Update) must succeed against real GCS");
        assert_eq!(
            backend.load_snapshot_cursor(repo).unwrap(),
            Some(SnapshotCursor::from_backend_generation(gen2))
        );
        stale
            .save_snapshot(repo, &bytes, stale_gen)
            .expect_err("stale real-GCS writer must fail its generation precondition");

        let reopened = GcsBackend::new(&bucket, prefix).unwrap();
        let recovered = crate::storage::backend::load_recovered_snapshot(&reopened, repo)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.generation, gen2);
        assert_eq!(
            reopened.load_snapshot_cursor(repo).unwrap(),
            Some(SnapshotCursor::from_backend_generation(gen2))
        );
        assert_eq!(recovered.snapshot.resolved_tree, current.resolved_tree);

        eprintln!(
            "gens: create={gen1} update={gen2} recovered={}",
            recovered.generation
        );
        reopened
            .block_on(reopened.store.delete(&reopened.snapshot_path(repo)))
            .expect("proof object cleanup should succeed");
    }
}
