// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use fs2::FileExt;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::engine::InMemoryGraph;
use crate::error::KinDbError;
use crate::storage::format::CompactionStats;
use crate::storage::merkle::compute_graph_root_hash;
use crate::storage::mmap;

/// Manages graph snapshots on disk with RCU-style concurrent access.
///
/// - Readers access the current `Arc<InMemoryGraph>` (cheap clone, no locking).
/// - Writer builds a new snapshot, serializes to disk atomically, then swaps the Arc.
/// - Old snapshot is freed when the last reader drops its Arc.
/// - An OS-level exclusive file lock prevents multiple processes from opening
///   the same snapshot simultaneously. The lock is released when the manager is dropped.
pub struct SnapshotManager {
    /// Path to the snapshot file.
    path: PathBuf,
    /// Optional persistent text index directory (sibling of snapshot file).
    text_index_path: Option<PathBuf>,
    /// Current live graph behind an Arc for cheap sharing.
    current: RwLock<Arc<InMemoryGraph>>,
    /// OS-level lock file handle. Held for the lifetime of this manager;
    /// the exclusive flock is released automatically when the File is dropped.
    _lock_file: Option<File>,
    /// Whether this manager was opened in read-only mode.
    read_only: bool,
}

/// Derive the text index directory as a sibling of the snapshot file.
/// e.g. `.kin/kindb/graph.kndb` → `.kin/kindb/text-index/`
fn text_index_dir_for(snapshot_path: &Path) -> Option<PathBuf> {
    snapshot_path.parent().map(|p| p.join("text-index"))
}

#[cfg(feature = "vector")]
fn vector_index_path_for(snapshot_path: &Path) -> PathBuf {
    snapshot_path.with_extension("kvec")
}

#[cfg(feature = "vector")]
fn vector_index_metadata_path_for(snapshot_path: &Path) -> PathBuf {
    vector_index_path_for(snapshot_path).with_extension("kvec.meta.json")
}

#[cfg(feature = "vector")]
pub const VECTOR_INDEX_METADATA_VERSION: u32 = 1;

#[cfg(feature = "vector")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VectorIndexMetadata {
    version: u32,
    graph_root_hash: String,
    dimensions: usize,
    indexed: usize,
    #[serde(default)]
    embedding_model_id: Option<String>,
    #[serde(default)]
    embedding_model_revision: Option<String>,
    #[serde(default)]
    embedding_pipeline_epoch: Option<String>,
}

#[cfg(feature = "vector")]
impl VectorIndexMetadata {
    const VERSION: u32 = VECTOR_INDEX_METADATA_VERSION;
}

fn normalize_snapshot_path(path: PathBuf) -> PathBuf {
    if path.extension().is_some() {
        return path;
    }

    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return path;
    };
    if name != "kindb" {
        return path;
    }

    let legacy_graph_dir = path
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .map(|name| name == "graph")
        .unwrap_or(false);
    if legacy_graph_dir {
        if let Some(root) = path.parent().and_then(|parent| parent.parent()) {
            return root.join("kindb").join("graph.kndb");
        }
    }

    path.join("graph.kndb")
}

#[cfg(feature = "vector")]
fn read_vector_index_metadata(path: &Path) -> Result<Option<VectorIndexMetadata>, KinDbError> {
    if !path.exists() {
        return Ok(None);
    }

    let bytes = std::fs::read(path).map_err(|err| {
        KinDbError::StorageError(format!(
            "failed to read vector index metadata {}: {err}",
            path.display()
        ))
    })?;
    let metadata: VectorIndexMetadata = serde_json::from_slice(&bytes).map_err(|err| {
        KinDbError::StorageError(format!(
            "failed to decode vector index metadata {}: {err}",
            path.display()
        ))
    })?;
    if metadata.version != VectorIndexMetadata::VERSION {
        return Err(KinDbError::StorageError(format!(
            "unsupported vector index metadata version {} in {}",
            metadata.version,
            path.display()
        )));
    }
    Ok(Some(metadata))
}

#[cfg(feature = "vector")]
fn write_vector_index_metadata(
    path: &Path,
    metadata: &VectorIndexMetadata,
) -> Result<(), KinDbError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            KinDbError::StorageError(format!(
                "failed to create vector index metadata directory {}: {err}",
                parent.display()
            ))
        })?;
    }

    let encoded = serde_json::to_vec_pretty(metadata).map_err(|err| {
        KinDbError::StorageError(format!("failed to encode vector index metadata: {err}"))
    })?;
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, encoded).map_err(|err| {
        KinDbError::StorageError(format!(
            "failed to write vector index metadata {}: {err}",
            tmp_path.display()
        ))
    })?;
    std::fs::rename(&tmp_path, path).map_err(|err| {
        KinDbError::StorageError(format!(
            "failed to promote vector index metadata {} -> {}: {err}",
            tmp_path.display(),
            path.display()
        ))
    })?;
    Ok(())
}

#[cfg(feature = "vector")]
fn current_embedding_runtime_fields() -> (Option<String>, Option<String>, Option<String>) {
    #[cfg(feature = "embeddings")]
    {
        let runtime = crate::embed::configured_embedding_runtime();
        return (
            Some(runtime.model_id),
            Some(runtime.revision),
            Some(runtime.pipeline_epoch),
        );
    }

    #[cfg(not(feature = "embeddings"))]
    {
        (None, None, None)
    }
}

#[cfg(feature = "vector")]
fn vector_metadata_matches_graph(
    metadata: &VectorIndexMetadata,
    graph_root_hash: [u8; 32],
) -> bool {
    if metadata.graph_root_hash != hex::encode(graph_root_hash) {
        return false;
    }

    #[cfg(feature = "embeddings")]
    {
        let runtime = crate::embed::configured_embedding_runtime();
        if let Some(model_id) = metadata.embedding_model_id.as_ref() {
            if model_id != &runtime.model_id {
                return false;
            }
        }
        if let Some(revision) = metadata.embedding_model_revision.as_ref() {
            if revision != &runtime.revision {
                return false;
            }
        }
        if let Some(epoch) = metadata.embedding_pipeline_epoch.as_ref() {
            if epoch != &runtime.pipeline_epoch {
                return false;
            }
        }
    }

    true
}

impl SnapshotManager {
    /// Acquire an OS-level file lock adjacent to the snapshot path.
    /// Returns the lock file handle on success.
    fn acquire_lock(path: &Path, read_only: bool) -> Result<File, KinDbError> {
        let lock_path = path.with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to create directory for lock file {}: {e}",
                    parent.display()
                ))
            })?;
        }
        let lock_file = File::create(&lock_path).map_err(|e| {
            KinDbError::LockError(format!(
                "failed to create lock file {}: {e}",
                lock_path.display()
            ))
        })?;
        if read_only {
            lock_file.try_lock_shared().map_err(|e| {
                KinDbError::LockError(format!(
                    "failed to acquire shared lock on {}: {e} (another process may be writing this database)",
                    lock_path.display()
                ))
            })?;
        } else {
            lock_file.try_lock_exclusive().map_err(|e| {
                KinDbError::LockError(format!(
                    "failed to acquire exclusive lock on {}: {e} (another process may be using this database)",
                    lock_path.display()
                ))
            })?;
        }
        Ok(lock_file)
    }

    fn graph_from_snapshot(
        snapshot: crate::storage::GraphSnapshot,
        text_index_path: Option<&PathBuf>,
        read_only: bool,
    ) -> (InMemoryGraph, [u8; 32]) {
        let graph_root_hash = compute_graph_root_hash(&snapshot);
        let graph = match text_index_path {
            Some(p) => {
                if read_only {
                    InMemoryGraph::from_snapshot_with_text_index_and_root_hash_read_only(
                        snapshot,
                        p.clone(),
                        graph_root_hash,
                    )
                } else {
                    InMemoryGraph::from_snapshot_with_text_index_and_root_hash(
                        snapshot,
                        p.clone(),
                        graph_root_hash,
                    )
                }
            }
            None => InMemoryGraph::from_snapshot_with_root_hash(snapshot, graph_root_hash),
        };
        (graph, graph_root_hash)
    }

    #[cfg(feature = "vector")]
    fn load_vector_index_if_valid(
        path: &Path,
        graph: &InMemoryGraph,
        graph_root_hash: [u8; 32],
        write_missing_metadata: bool,
    ) -> Result<(), KinDbError> {
        let vector_path = vector_index_path_for(path);
        if !vector_path.exists() {
            return Ok(());
        }

        let metadata_path = vector_index_metadata_path_for(path);
        let metadata = read_vector_index_metadata(&metadata_path)?;
        let should_load = metadata
            .as_ref()
            .map(|metadata| vector_metadata_matches_graph(metadata, graph_root_hash))
            .unwrap_or(true);

        if !should_load {
            tracing::warn!(
                path = %vector_path.display(),
                metadata = %metadata_path.display(),
                "skipping stale vector index because metadata no longer matches graph truth"
            );
            if write_missing_metadata {
                graph.queue_missing_for_embedding();
                graph.queue_missing_artifacts_for_embedding();
            }
            return Ok(());
        }

        let count = graph.load_vector_index(&vector_path)?;
        if metadata.is_none() && write_missing_metadata {
            if let Some((dimensions, indexed)) = graph.vector_index_stats() {
                let (model_id, revision, pipeline_epoch) = current_embedding_runtime_fields();
                let metadata = VectorIndexMetadata {
                    version: VectorIndexMetadata::VERSION,
                    graph_root_hash: hex::encode(graph_root_hash),
                    dimensions,
                    indexed,
                    embedding_model_id: model_id,
                    embedding_model_revision: revision,
                    embedding_pipeline_epoch: pipeline_epoch,
                };
                write_vector_index_metadata(&metadata_path, &metadata)?;
            }
        } else if count == 0 {
            tracing::debug!(path = %vector_path.display(), "vector index metadata matched but index was empty");
        }

        Ok(())
    }

    /// Create a new SnapshotManager with an empty in-memory graph.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = normalize_snapshot_path(path.into());
        let ti_path = text_index_dir_for(&path);
        let graph = match ti_path {
            Some(ref p) => InMemoryGraph::with_text_index(p.clone()),
            None => InMemoryGraph::new(),
        };
        Self {
            path,
            text_index_path: ti_path,
            current: RwLock::new(Arc::new(graph)),
            _lock_file: None,
            read_only: false,
        }
    }

    fn recover_graph_from_tmp(
        path: &Path,
        primary_error: Option<&KinDbError>,
        text_index_path: Option<&PathBuf>,
        read_only: bool,
    ) -> Result<(InMemoryGraph, [u8; 32]), KinDbError> {
        let tmp_path = mmap::recovery_tmp_path(path);
        if !tmp_path.exists() {
            return Err(match primary_error {
                Some(err) => KinDbError::StorageError(format!(
                    "failed to open {} and no recovery snapshot exists: {err}",
                    path.display()
                )),
                None => KinDbError::StorageError(format!(
                    "snapshot {} is missing and recovery snapshot {} is not present",
                    path.display(),
                    tmp_path.display()
                )),
            });
        }

        let snapshot = mmap::load_recovery_candidate(path).map_err(|tmp_err| {
            let prefix = match primary_error {
                Some(primary_err) => format!(
                    "failed to open primary snapshot {}: {primary_err}; ",
                    path.display()
                ),
                None => format!("primary snapshot {} is missing; ", path.display()),
            };
            KinDbError::StorageError(format!(
                "{prefix}recovery snapshot {} is invalid: {tmp_err}",
                tmp_path.display()
            ))
        })?;

        mmap::promote_recovery_candidate(path).map_err(|err| {
            KinDbError::StorageError(format!(
                "loaded recovery snapshot {} but failed to promote it to {}: {err}",
                tmp_path.display(),
                path.display()
            ))
        })?;

        Ok(Self::graph_from_snapshot(
            snapshot,
            text_index_path,
            read_only,
        ))
    }

    fn open_graph(
        path: &Path,
        text_index_path: Option<&PathBuf>,
        read_only: bool,
    ) -> Result<InMemoryGraph, KinDbError> {
        let (graph, graph_root_hash) = if path.exists() {
            match mmap::MmapReader::open(path) {
                Ok(snapshot) => Ok(Self::graph_from_snapshot(
                    snapshot,
                    text_index_path,
                    read_only,
                )),
                Err(err) => {
                    Self::recover_graph_from_tmp(path, Some(&err), text_index_path, read_only)
                }
            }
        } else {
            let tmp_path = mmap::recovery_tmp_path(path);
            if tmp_path.exists() {
                Self::recover_graph_from_tmp(path, None, text_index_path, read_only)
            } else {
                match text_index_path {
                    Some(p) => {
                        if !read_only {
                            #[cfg(feature = "vector")]
                            {
                                let vector_path = vector_index_path_for(path);
                                if vector_path.exists() {
                                    std::fs::remove_file(&vector_path).map_err(|err| {
                                        KinDbError::StorageError(format!(
                                            "failed to clear stale vector index {}: {err}",
                                            vector_path.display()
                                        ))
                                    })?;
                                }
                                let metadata_path = vector_index_metadata_path_for(path);
                                if metadata_path.exists() {
                                    std::fs::remove_file(&metadata_path).map_err(|err| {
                                        KinDbError::StorageError(format!(
                                            "failed to clear stale vector index metadata {}: {err}",
                                            metadata_path.display()
                                        ))
                                    })?;
                                }
                            }
                        }

                        if !read_only && p.exists() {
                            let cleanup = if p.is_dir() {
                                std::fs::remove_dir_all(p)
                            } else {
                                std::fs::remove_file(p)
                            };
                            cleanup.map_err(|err| {
                                KinDbError::StorageError(format!(
                                    "failed to clear stale text index {}: {err}",
                                    p.display()
                                ))
                            })?;
                        }
                        Ok((InMemoryGraph::with_text_index(p.clone()), [0u8; 32]))
                    }
                    None => Ok((InMemoryGraph::new(), [0u8; 32])),
                }
            }
        }?;

        #[cfg(feature = "vector")]
        {
            Self::load_vector_index_if_valid(path, &graph, graph_root_hash, !read_only)?;
        }

        Ok(graph)
    }

    /// Open an existing snapshot from disk, or create a new empty graph if
    /// the file doesn't exist.
    ///
    /// Acquires an OS-level exclusive file lock to prevent concurrent access
    /// from other processes. Returns `LockError` if another process holds the lock.
    ///
    /// The text index is automatically persisted to a `text-index/` directory
    /// next to the snapshot file, avoiding full index rebuilds on cold start.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, KinDbError> {
        let path = normalize_snapshot_path(path.into());
        let lock_file = Self::acquire_lock(&path, false)?;
        let ti_path = text_index_dir_for(&path);
        let graph = Self::open_graph(&path, ti_path.as_ref(), false)?;

        Ok(Self {
            path,
            text_index_path: ti_path,
            current: RwLock::new(Arc::new(graph)),
            _lock_file: Some(lock_file),
            read_only: false,
        })
    }

    /// Open an existing snapshot while intentionally skipping the persisted
    /// text index sidecar.
    ///
    /// This is useful for graph-only workflows like warm-cache diffing where
    /// loading the full lexical index would dominate startup time even though
    /// the caller only needs snapshot entities/file hashes.
    pub fn open_without_text_index(path: impl Into<PathBuf>) -> Result<Self, KinDbError> {
        let path = normalize_snapshot_path(path.into());
        let lock_file = Self::acquire_lock(&path, false)?;
        let graph = Self::open_graph(&path, None, false)?;

        Ok(Self {
            path,
            text_index_path: None,
            current: RwLock::new(Arc::new(graph)),
            _lock_file: Some(lock_file),
            read_only: false,
        })
    }

    /// Open an existing snapshot in read-only mode, allowing multiple shared
    /// readers while still excluding concurrent writers.
    pub fn open_read_only(path: impl Into<PathBuf>) -> Result<Self, KinDbError> {
        let path = normalize_snapshot_path(path.into());
        let lock_file = Self::acquire_lock(&path, true)?;
        let ti_path = text_index_dir_for(&path);
        let graph = Self::open_graph(&path, ti_path.as_ref(), true)?;

        Ok(Self {
            path,
            text_index_path: ti_path,
            current: RwLock::new(Arc::new(graph)),
            _lock_file: Some(lock_file),
            read_only: true,
        })
    }

    /// Construct a read-only snapshot manager from an already-bootstrapped
    /// in-memory graph without taking a local file lock.
    ///
    /// This is used by daemon-backed read-only commands that already fetched
    /// authoritative graph state from a daemon and would otherwise contend on
    /// the local `.lock` file just to validate the same repo.
    pub fn from_bootstrap_graph_read_only(path: impl Into<PathBuf>, graph: InMemoryGraph) -> Self {
        let path = normalize_snapshot_path(path.into());
        let ti_path = text_index_dir_for(&path);
        Self {
            path,
            text_index_path: ti_path,
            current: RwLock::new(Arc::new(graph)),
            _lock_file: None,
            read_only: true,
        }
    }

    /// Get a shared reference to the current graph.
    /// The returned Arc can be held across async boundaries without blocking writers.
    pub fn graph(&self) -> Arc<InMemoryGraph> {
        Arc::clone(&self.current.read())
    }

    /// Get the underlying path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Save the current graph state to disk atomically (full snapshot).
    /// Returns the Merkle root hash computed during save.
    pub fn save(&self) -> Result<crate::storage::merkle::MerkleHash, KinDbError> {
        if self.read_only {
            return Err(KinDbError::LockError(format!(
                "snapshot {} was opened read-only and cannot be saved",
                self.path.display()
            )));
        }
        let graph = self.graph();
        Self::save_graph_with_hash(&self.path, graph.as_ref(), None)
    }

    /// Persist an arbitrary live graph to disk using snapshot semantics.
    ///
    /// Uses a borrowed serialization path that avoids cloning the entire
    /// in-memory graph.  The live sub-stores are read-locked, hashed, and
    /// serialized directly, then written atomically to disk.
    pub fn save_graph(
        path: impl Into<PathBuf>,
        graph: &InMemoryGraph,
    ) -> Result<crate::storage::merkle::MerkleHash, KinDbError> {
        Self::save_graph_with_hash(path, graph, None)
    }

    /// Like [`save_graph`] but accepts a pre-computed Merkle root hash.
    /// When provided, the expensive root-hash traversal is skipped.
    pub fn save_graph_with_hash(
        path: impl Into<PathBuf>,
        graph: &InMemoryGraph,
        precomputed_hash: Option<crate::storage::merkle::MerkleHash>,
    ) -> Result<crate::storage::merkle::MerkleHash, KinDbError> {
        let path = normalize_snapshot_path(path.into());

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to create directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        let t0 = std::time::Instant::now();
        let precomputed_hash = precomputed_hash.or_else(|| graph.snapshot_root_hash_hint());
        let (bytes, graph_root_hash) =
            graph.serialize_snapshot_borrowed_with_hash(precomputed_hash)?;
        let t_ser = t0.elapsed();

        let t1 = std::time::Instant::now();
        mmap::atomic_write_bytes(&path, &bytes)?;
        let t_write = t1.elapsed();

        // Drop the serialized bytes before text-index work.
        drop(bytes);

        let t2 = std::time::Instant::now();
        graph.persist_text_index_with_root_hash(graph_root_hash)?;
        let t_text = t2.elapsed();

        eprintln!(
            "[save_graph] serialize={:.1}s  atomic_write={:.1}s  text_index={:.1}s  total={:.1}s",
            t_ser.as_secs_f64(),
            t_write.as_secs_f64(),
            t_text.as_secs_f64(),
            t0.elapsed().as_secs_f64(),
        );

        #[cfg(feature = "vector")]
        {
            let vector_path = vector_index_path_for(&path);
            graph.save_vector_index(&vector_path)?;
            let metadata_path = vector_index_metadata_path_for(&path);
            if let Some((dimensions, indexed)) = graph.vector_index_stats() {
                let (model_id, revision, pipeline_epoch) = current_embedding_runtime_fields();
                let metadata = VectorIndexMetadata {
                    version: VectorIndexMetadata::VERSION,
                    graph_root_hash: hex::encode(graph_root_hash),
                    dimensions,
                    indexed,
                    embedding_model_id: model_id,
                    embedding_model_revision: revision,
                    embedding_pipeline_epoch: pipeline_epoch,
                };
                write_vector_index_metadata(&metadata_path, &metadata)?;
            } else if metadata_path.exists() {
                std::fs::remove_file(&metadata_path).map_err(|err| {
                    KinDbError::StorageError(format!(
                        "failed to remove stale vector index metadata {}: {err}",
                        metadata_path.display()
                    ))
                })?;
            }
        }

        Ok(graph_root_hash)
    }

    /// Compute a delta between the on-disk snapshot and the current in-memory
    /// graph state. Returns the serialized delta bytes. If no on-disk snapshot
    /// exists, returns `None` (caller should use `save()` for the initial write).
    ///
    /// This enables incremental persistence: instead of writing the full graph
    /// on every change, callers can write only what changed.
    pub fn compute_delta(
        &self,
    ) -> Result<Option<crate::storage::delta::GraphSnapshotDelta>, KinDbError> {
        if !self.path.exists() {
            return Ok(None);
        }

        let old_snapshot = mmap::MmapReader::open(&self.path)?;
        let current_snapshot = self.graph().to_snapshot();

        let delta = crate::storage::delta::compute_graph_delta(
            &old_snapshot,
            &current_snapshot,
            0, // generation is set by the StorageBackend on save
        );

        if delta.is_empty() {
            return Ok(None);
        }

        Ok(Some(delta))
    }

    /// Replace the current graph with a new one (RCU swap).
    pub fn swap(&self, new_graph: InMemoryGraph) {
        let mut current = self.current.write();
        *current = Arc::new(new_graph);
    }

    /// Compact the graph snapshot: garbage-collect orphaned data and save.
    ///
    /// For large graphs (>500K entities), orphaned relations, stale test
    /// coverage entries, and other dangling references accumulate over time
    /// as entities are deleted and re-indexed. This method:
    ///
    /// 1. Exports the current graph to a snapshot
    /// 2. Runs GC to remove all orphaned cross-references
    /// 3. Rebuilds the in-memory graph from the clean snapshot (RCU swap)
    /// 4. Atomically writes the compacted snapshot to disk
    ///
    /// Returns statistics about what was removed.
    pub fn compact(&self) -> Result<CompactionStats, KinDbError> {
        if self.read_only {
            return Err(KinDbError::LockError(format!(
                "snapshot {} was opened read-only and cannot be compacted",
                self.path.display()
            )));
        }
        let graph = self.graph();
        let mut snapshot = graph.to_snapshot();
        let stats = snapshot.compact();

        if !stats.is_clean() {
            // Ensure parent directory exists
            if let Some(parent) = self.path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    KinDbError::StorageError(format!(
                        "failed to create directory {}: {e}",
                        parent.display()
                    ))
                })?;
            }

            // Write to disk first while we still have a reference to the snapshot.
            // Then consume the snapshot to build the in-memory graph (no clone).
            // This avoids doubling memory for graphs with >500K entities.
            mmap::atomic_write(&self.path, &snapshot)?;
            let compacted_graph = match self.text_index_path.as_ref() {
                Some(p) => InMemoryGraph::from_snapshot_with_text_index(snapshot, p.clone()),
                None => InMemoryGraph::from_snapshot(snapshot),
            };
            self.swap(compacted_graph);
        }

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::merkle::{
        build_entity_hash_map, compute_graph_root_hash, verify_entity, verify_subgraph,
        EntityVerification,
    };
    use crate::storage::GraphSnapshot;
    use crate::store::{
        ChangeStore, EntityStore, ProvenanceStore, SessionStore, VerificationStore, WorkStore,
    };
    use crate::types::*;
    #[cfg(feature = "vector")]
    use crate::VectorIndex;
    use tempfile::TempDir;

    fn test_entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/main.rs")),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn test_entity_with_language(name: &str, file_origin: &str, language: LanguageId) -> Entity {
        let mut entity = test_entity(name);
        entity.file_origin = Some(FilePathId::new(file_origin));
        entity.language = language;
        entity
    }

    #[test]
    fn save_and_reload() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        // Create and populate
        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        let entity = test_entity("save_test");
        let id = entity.id;
        graph.upsert_entity(&entity).unwrap();
        mgr.save().unwrap();

        // Reload from disk
        let mgr2 = SnapshotManager::open(&path).unwrap();
        let graph2 = mgr2.graph();
        let fetched = graph2.get_entity(&id).unwrap().unwrap();
        assert_eq!(fetched.name, "save_test");
    }

    #[test]
    fn rcu_swap() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let mgr = SnapshotManager::new(&path);

        // Get a reference to the old graph
        let old_graph = mgr.graph();
        let e = test_entity("old");
        old_graph.upsert_entity(&e).unwrap();

        // Swap with a new graph
        let new = InMemoryGraph::new();
        let e2 = test_entity("new");
        new.upsert_entity(&e2).unwrap();
        mgr.swap(new);

        // Old reference still works
        assert_eq!(old_graph.entity_count(), 1);

        // New reference sees new data
        let new_graph = mgr.graph();
        assert_eq!(new_graph.entity_count(), 1);
        let fetched = new_graph.list_all_entities().unwrap();
        assert_eq!(fetched[0].name, "new");
    }

    #[test]
    fn open_nonexistent_creates_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does_not_exist.kndb");
        let mgr = SnapshotManager::open(&path).unwrap();
        assert_eq!(mgr.graph().entity_count(), 0);
    }

    #[test]
    fn open_recovers_from_tmp_when_primary_is_missing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let tmp_path = mmap::recovery_tmp_path(&path);

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        let entity = test_entity("recover_missing_primary");
        let entity_id = entity.id;
        graph.upsert_entity(&entity).unwrap();
        let snapshot = graph.to_snapshot();
        mmap::write_recovery_candidate(&path, &snapshot).unwrap();
        drop(mgr);

        let recovered = SnapshotManager::open(&path).unwrap();
        let recovered_graph = recovered.graph();
        let fetched = recovered_graph.get_entity(&entity_id).unwrap().unwrap();
        assert_eq!(fetched.name, "recover_missing_primary");
        assert!(path.exists(), "primary snapshot should be promoted");
        assert!(!tmp_path.exists(), "recovery tmp should be consumed");
    }

    #[test]
    fn open_recovers_from_valid_tmp_when_primary_is_corrupted() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let tmp_path = mmap::recovery_tmp_path(&path);

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        let entity = test_entity("recover_corrupted_primary");
        let entity_id = entity.id;
        graph.upsert_entity(&entity).unwrap();
        mgr.save().unwrap();

        let snapshot = graph.to_snapshot();
        mmap::write_recovery_candidate(&path, &snapshot).unwrap();
        drop(mgr);

        let mut corrupt_bytes = std::fs::read(&path).unwrap();
        let mid = corrupt_bytes.len() / 2;
        corrupt_bytes[mid] ^= 0xFF;
        std::fs::write(&path, corrupt_bytes).unwrap();

        let recovered = SnapshotManager::open(&path).unwrap();
        let recovered_graph = recovered.graph();
        let fetched = recovered_graph.get_entity(&entity_id).unwrap().unwrap();
        assert_eq!(fetched.name, "recover_corrupted_primary");
        assert!(!tmp_path.exists(), "recovery tmp should be consumed");
    }

    #[test]
    fn open_rejects_invalid_tmp_when_primary_is_missing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let tmp_path = mmap::recovery_tmp_path(&path);
        std::fs::write(&tmp_path, b"not a snapshot").unwrap();

        let err = match SnapshotManager::open(&path) {
            Ok(_) => panic!("expected invalid recovery snapshot to fail opening"),
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("primary snapshot") && msg.contains("recovery snapshot"),
            "expected explicit recovery error, got: {msg}"
        );
    }

    #[test]
    fn open_rejects_unproven_tmp_when_primary_is_missing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let tmp_path = mmap::recovery_tmp_path(&path);

        let mut snapshot = GraphSnapshot::empty();
        let entity = test_entity("unproven_tmp");
        snapshot.entities = [(entity.id, entity)].into_iter().collect();
        std::fs::write(&tmp_path, snapshot.to_bytes().unwrap()).unwrap();

        let err = match SnapshotManager::open(&path) {
            Ok(_) => panic!("expected unproven recovery snapshot to fail opening"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("unproven without a valid marker"));
    }

    #[test]
    fn open_legacy_graph_kindb_path_redirects_to_snapshot_file() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join(".kin").join("kindb").join("graph.kndb");
        let legacy_path = dir.path().join(".kin").join("graph").join("kindb");

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        graph.upsert_entity(&test_entity("legacy_path")).unwrap();
        mgr.save().unwrap();

        let redirected = SnapshotManager::open(&legacy_path).unwrap();
        let entities = redirected.graph().list_all_entities().unwrap();
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].name, "legacy_path");
        assert_eq!(redirected.path(), snapshot_path.as_path());
    }

    #[test]
    fn save_and_reload_preserves_extended_state() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();

        let entity = test_entity("extended");
        graph.upsert_entity(&entity).unwrap();

        let base_change = SemanticChangeId::from_hash(Hash256::from_bytes([1; 32]));
        let change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([2; 32])),
            parents: vec![base_change],
            timestamp: Timestamp::now(),
            author: AuthorId::new("tester"),
            message: "snapshot roundtrip".into(),
            entity_deltas: vec![EntityDelta::Added(entity.clone())],
            relation_deltas: Vec::new(),
            artifact_deltas: Vec::new(),
            projected_files: vec![FilePathId::new("src/main.rs")],
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            authored_on: Some(BranchName::new("main")),
        };
        graph.create_change(&change).unwrap();
        graph
            .create_branch(&Branch {
                name: BranchName::new("main"),
                head: change.id,
            })
            .unwrap();

        let shallow = ShallowTrackedFile {
            file_id: FilePathId::new("src/main.rs"),
            language_hint: "rust".into(),
            declaration_count: 1,
            import_count: 0,
            syntax_hash: Hash256::from_bytes([3; 32]),
            signature_hash: Some(Hash256::from_bytes([4; 32])),
            declaration_names: vec!["main".into()],
            import_paths: vec![],
        };
        graph.upsert_shallow_file(&shallow).unwrap();
        graph
            .upsert_structured_artifact(&StructuredArtifact {
                file_id: FilePathId::new("Makefile"),
                kind: ArtifactKind::Makefile,
                content_hash: Hash256::from_bytes([5; 32]),
                text_preview: Some("build test".into()),
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("assets/logo.svg"),
                content_hash: Hash256::from_bytes([6; 32]),
                mime_type: Some("image/svg+xml".into()),
                text_preview: Some("<svg".into()),
            })
            .unwrap();
        graph.set_file_hash("src/main.rs", [9; 32]);

        let work = WorkItem {
            work_id: WorkId::new(),
            kind: WorkKind::Task,
            title: "Persist snapshot state".into(),
            description: "Ensure KinDB round-trips all CLI-visible state.".into(),
            status: WorkStatus::InProgress,
            priority: Priority::High,
            scopes: vec![WorkScope::Entity(entity.id)],
            acceptance_criteria: vec!["Roundtrip succeeds".into()],
            external_refs: Vec::new(),
            created_by: IdentityRef::assistant("codex"),
            created_at: Timestamp::now(),
        };
        graph.create_work_item(&work).unwrap();

        let annotation = Annotation {
            annotation_id: AnnotationId::new(),
            kind: AnnotationKind::Instruction,
            body: "Keep snapshot state complete.".into(),
            scopes: vec![WorkScope::Entity(entity.id)],
            anchored_fingerprint: None,
            authored_by: IdentityRef::assistant("codex"),
            created_at: Timestamp::now(),
            staleness: StalenessState::Fresh,
        };
        graph.create_annotation(&annotation).unwrap();
        graph
            .create_work_link(&WorkLink::AttachedTo {
                annotation_id: annotation.annotation_id,
                target: AnnotationTarget::Work(work.work_id),
            })
            .unwrap();

        let test = TestCase {
            test_id: TestId::new(),
            name: "snapshot_roundtrip".into(),
            language: "rust".into(),
            kind: TestKind::Unit,
            scopes: vec![WorkScope::Entity(entity.id)],
            runner: TestRunner::Cargo,
            file_origin: Some(FilePathId::new("tests/snapshot.rs")),
        };
        graph.create_test_case(&test).unwrap();
        graph
            .create_test_covers_entity(&test.test_id, &entity.id)
            .unwrap();

        let run = VerificationRun {
            run_id: VerificationRunId::new(),
            test_ids: vec![test.test_id],
            status: VerificationStatus::Passing,
            runner: TestRunner::Cargo,
            started_at: Timestamp::now(),
            finished_at: None,
            duration_ms: Some(12),
            evidence_blob: None,
            exit_code: Some(0),
        };
        graph.create_verification_run(&run).unwrap();
        graph
            .create_mock_hint(&MockHint {
                hint_id: MockHintId::new(),
                test_id: test.test_id,
                dependency_scope: WorkScope::Entity(entity.id),
                strategy: MockStrategy::Stub,
            })
            .unwrap();

        let actor = Actor {
            actor_id: ActorId::new(),
            kind: ActorKind::Assistant,
            display_name: "Codex".into(),
            external_refs: Vec::new(),
        };
        graph.create_actor(&actor).unwrap();
        graph
            .create_approval(&Approval {
                approval_id: ApprovalId::new(),
                change_id: change.id,
                approver: actor.actor_id,
                decision: ApprovalDecision::Approved,
                reason: "Looks correct".into(),
                timestamp: Timestamp::now(),
            })
            .unwrap();
        graph
            .record_audit_event(&AuditEvent {
                event_id: AuditEventId::new(),
                actor_id: actor.actor_id,
                action: "snapshot.save".into(),
                target_scope: Some(WorkScope::Entity(entity.id)),
                timestamp: Timestamp::now(),
                details: Some("roundtrip test".into()),
            })
            .unwrap();

        let session = AgentSession {
            session_id: SessionId::new(),
            vendor: "openai".into(),
            client_name: "codex".into(),
            transport: kin_model::SessionTransport::Cli,
            pid: Some(42),
            cwd: PathBuf::from("/tmp/kin"),
            started_at: Timestamp::now(),
            last_heartbeat: Timestamp::now(),
            capabilities: kin_model::SessionCapabilities::default(),
        };
        graph.upsert_session(&session).unwrap();

        let intent = Intent {
            intent_id: IntentId::new(),
            session_id: session.session_id,
            scopes: vec![IntentScope::Entity(entity.id)],
            lock_type: LockType::Hard,
            task_description: "Persist KinDB".into(),
            registered_at: Timestamp::now(),
            expires_at: None,
        };
        graph.register_intent(&intent).unwrap();
        graph
            .create_downstream_warning(&intent.intent_id, &entity.id, "watch downstream")
            .unwrap();

        mgr.save().unwrap();

        let reloaded = SnapshotManager::open(&path).unwrap();
        let graph = reloaded.graph();

        assert!(graph.get_change(&change.id).unwrap().is_some());
        assert_eq!(
            graph
                .get_branch(&BranchName::new("main"))
                .unwrap()
                .unwrap()
                .head,
            change.id
        );
        assert_eq!(graph.list_shallow_files().unwrap().len(), 1);
        assert_eq!(graph.list_structured_artifacts().unwrap().len(), 1);
        assert_eq!(graph.list_opaque_artifacts().unwrap().len(), 1);
        assert_eq!(graph.get_file_hash("src/main.rs"), Some([9; 32]));
        assert_eq!(
            graph.list_work_items(&WorkFilter::default()).unwrap().len(),
            1
        );
        assert_eq!(
            graph
                .list_annotations(&AnnotationFilter::default())
                .unwrap()
                .len(),
            1
        );
        assert_eq!(graph.get_tests_for_entity(&entity.id).unwrap().len(), 1);
        assert_eq!(
            graph.get_mock_hints_for_test(&test.test_id).unwrap().len(),
            1
        );
        assert_eq!(graph.list_actors().unwrap().len(), 1);
        assert_eq!(graph.get_approvals_for_change(&change.id).unwrap().len(), 1);
        assert_eq!(graph.query_audit_events(None, 10).unwrap().len(), 1);
        assert_eq!(graph.list_sessions().unwrap().len(), 1);
        assert_eq!(graph.list_all_intents().unwrap().len(), 1);
        assert_eq!(
            graph
                .downstream_warnings_for_entity(&entity.id)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn save_and_reload_preserves_mixed_language_entities_and_verification() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();

        let rust_entity = test_entity_with_language("compileRust", "src/lib.rs", LanguageId::Rust);
        let ts_entity = test_entity_with_language("renderTs", "web/app.ts", LanguageId::TypeScript);
        let py_entity = test_entity_with_language("trainPy", "tools/train.py", LanguageId::Python);

        graph.upsert_entity(&rust_entity).unwrap();
        graph.upsert_entity(&ts_entity).unwrap();
        graph.upsert_entity(&py_entity).unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(rust_entity.id),
                dst: GraphNodeId::Entity(ts_entity.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
            })
            .unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(ts_entity.id),
                dst: GraphNodeId::Entity(py_entity.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
            })
            .unwrap();

        let test_case = TestCase {
            test_id: TestId::new(),
            name: "test_render_ts".into(),
            language: "typescript".into(),
            kind: TestKind::Unit,
            scopes: vec![],
            runner: TestRunner::Jest,
            file_origin: Some(FilePathId::new("web/app.test.ts")),
        };

        graph.create_test_case(&test_case).unwrap();
        graph
            .create_test_covers_entity(&test_case.test_id, &ts_entity.id)
            .unwrap();
        let root_before = compute_graph_root_hash(&graph.to_snapshot());
        mgr.save().unwrap();

        let reloaded = SnapshotManager::open(&path).unwrap();
        let graph = reloaded.graph();

        let filter = EntityFilter {
            languages: Some(vec![LanguageId::Rust, LanguageId::TypeScript]),
            ..Default::default()
        };
        let results = graph.query_entities(&filter).unwrap();
        let names: std::collections::HashSet<_> =
            results.iter().map(|entity| entity.name.as_str()).collect();

        assert_eq!(results.len(), 2);
        assert!(names.contains("compileRust"));
        assert!(names.contains("renderTs"));
        assert!(!names.contains("trainPy"));

        let summary = graph.get_coverage_summary().unwrap();
        assert_eq!(summary.total_entities, 3);
        assert_eq!(summary.covered_entities, 1);

        let reloaded_snapshot = graph.to_snapshot();
        let root_after = compute_graph_root_hash(&reloaded_snapshot);
        assert_eq!(root_before, root_after);

        let hashes = build_entity_hash_map(&reloaded_snapshot);
        assert_eq!(
            verify_entity(&rust_entity.id, &reloaded_snapshot, &hashes),
            EntityVerification::Valid
        );
        assert_eq!(
            verify_entity(&ts_entity.id, &reloaded_snapshot, &hashes),
            EntityVerification::Valid
        );
        let subgraph_report =
            verify_subgraph(&rust_entity.id, &reloaded_snapshot, &hashes).unwrap();
        assert!(subgraph_report.is_valid);
        assert!(subgraph_report.tampered.is_empty());
    }

    #[test]
    #[cfg(feature = "vector")]
    fn save_and_reload_preserves_mixed_language_vector_search_contract() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = dir.path().join("vectors.usearch");

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();

        let rust_entity = test_entity_with_language("compileRust", "src/lib.rs", LanguageId::Rust);
        let ts_entity = test_entity_with_language("renderTs", "web/app.ts", LanguageId::TypeScript);
        let py_entity = test_entity_with_language("trainPy", "tools/train.py", LanguageId::Python);

        graph.upsert_entity(&rust_entity).unwrap();
        graph.upsert_entity(&ts_entity).unwrap();
        graph.upsert_entity(&py_entity).unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(rust_entity.id),
                dst: GraphNodeId::Entity(ts_entity.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
            })
            .unwrap();

        let root_before = compute_graph_root_hash(&graph.to_snapshot());

        let vectors = VectorIndex::new(4).unwrap();
        vectors
            .upsert(rust_entity.id, &[1.0, 0.0, 0.0, 0.0])
            .unwrap();
        vectors
            .upsert(ts_entity.id, &[0.92, 0.08, 0.0, 0.0])
            .unwrap();
        vectors.upsert(py_entity.id, &[0.0, 1.0, 0.0, 0.0]).unwrap();
        let results_before = vectors.search_similar(&[1.0, 0.0, 0.0, 0.0], 2).unwrap();

        mgr.save().unwrap();
        vectors.save(&vector_path).unwrap();

        let reloaded = SnapshotManager::open(&snapshot_path).unwrap();
        let graph = reloaded.graph();
        let reloaded_snapshot = graph.to_snapshot();
        let root_after = compute_graph_root_hash(&reloaded_snapshot);
        assert_eq!(root_before, root_after);

        let filter = EntityFilter {
            languages: Some(vec![LanguageId::Rust, LanguageId::TypeScript]),
            ..Default::default()
        };
        let filtered = graph.query_entities(&filter).unwrap();
        let filtered_ids: std::collections::HashSet<_> =
            filtered.iter().map(|entity| entity.id).collect();
        assert_eq!(filtered_ids.len(), 2);
        assert!(filtered_ids.contains(&rust_entity.id));
        assert!(filtered_ids.contains(&ts_entity.id));
        assert!(!filtered_ids.contains(&py_entity.id));

        let loaded_vectors = VectorIndex::load(&vector_path, 4).unwrap();
        let results_after = loaded_vectors
            .search_similar(&[1.0, 0.0, 0.0, 0.0], 2)
            .unwrap();

        assert_eq!(results_after, results_before);
        assert_eq!(results_after[0].0, RetrievalKey::from(rust_entity.id));
        assert_eq!(results_after[1].0, RetrievalKey::from(ts_entity.id));
    }

    #[test]
    #[cfg(feature = "vector")]
    fn save_writes_vector_index_metadata() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);
        let metadata_path = vector_index_metadata_path_for(&snapshot_path);

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        let entity = test_entity("vector_owner");
        graph.upsert_entity(&entity).unwrap();

        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(entity.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        vectors.save(&vector_path).unwrap();
        graph.load_vector_index(&vector_path).unwrap();

        mgr.save().unwrap();

        let metadata = read_vector_index_metadata(&metadata_path)
            .unwrap()
            .expect("vector metadata should be written");
        assert_eq!(
            metadata.graph_root_hash,
            hex::encode(compute_graph_root_hash(&graph.to_snapshot()))
        );
        assert_eq!(metadata.dimensions, 4);
        assert_eq!(metadata.indexed, 1);
    }

    #[test]
    fn save_updates_text_index_root_hash_even_without_entity_changes() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let text_index_path = text_index_dir_for(&snapshot_path).unwrap();

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        let entity = test_entity("text_root");
        graph.upsert_entity(&entity).unwrap();
        mgr.save().unwrap();

        let branch = kin_model::Branch {
            name: kin_model::BranchName::new("main"),
            head: kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes([7; 32])),
        };
        graph.create_branch(&branch).unwrap();
        mgr.save().unwrap();

        let persisted = crate::search::TextIndex::open_read_only(Some(&text_index_path)).unwrap();
        assert_eq!(
            persisted.graph_root_hash(),
            Some(compute_graph_root_hash(&graph.to_snapshot()))
        );
    }

    #[test]
    #[cfg(feature = "vector")]
    fn stale_vector_metadata_prevents_load_on_reopen() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);
        let metadata_path = vector_index_metadata_path_for(&snapshot_path);

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        let entity = test_entity("stale_vector");
        let artifact = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([0x31; 32]),
            text_preview: Some("build test".into()),
        };
        graph.upsert_entity(&entity).unwrap();
        graph.upsert_structured_artifact(&artifact).unwrap();
        mgr.save().unwrap();

        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(entity.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        vectors
            .upsert_retrievable(
                RetrievalKey::Artifact(ArtifactId::from_file_id(&artifact.file_id)),
                &[0.0, 1.0, 0.0, 0.0],
            )
            .unwrap();
        vectors.save(&vector_path).unwrap();
        write_vector_index_metadata(
            &metadata_path,
            &VectorIndexMetadata {
                version: VectorIndexMetadata::VERSION,
                graph_root_hash: hex::encode([42u8; 32]),
                dimensions: 4,
                indexed: 1,
                embedding_model_id: None,
                embedding_model_revision: None,
                embedding_pipeline_epoch: None,
            },
        )
        .unwrap();

        let reloaded = SnapshotManager::open(&snapshot_path).unwrap();
        assert_eq!(reloaded.graph().embedding_status().indexed, 0);
        assert_eq!(reloaded.graph().pending_embeddings(), 1);
        assert_eq!(reloaded.graph().pending_artifact_embeddings(), 1);
    }

    #[test]
    fn compact_removes_orphans_and_saves() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();

        // Insert two entities with a relation between them
        let e1 = test_entity("caller");
        let e2 = test_entity("callee");
        let rel = Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(e1.id),
            dst: GraphNodeId::Entity(e2.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
        };
        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();

        // Add a downstream warning for a non-existent intent
        let dead_intent = IntentId::new();
        graph
            .create_downstream_warning(&dead_intent, &e1.id, "orphan warning")
            .unwrap();

        // Save initial state
        mgr.save().unwrap();
        let size_before = std::fs::metadata(&path).unwrap().len();

        // Compact — should remove the orphaned downstream warning
        let stats = mgr.compact().unwrap();
        assert_eq!(stats.orphaned_downstream_warnings_removed, 1);
        assert_eq!(stats.entities_before, 2);
        assert_eq!(stats.relations_before, 1);
        assert_eq!(stats.orphaned_relations_removed, 0); // relation is valid

        // Verify compacted snapshot is smaller or equal
        let size_after = std::fs::metadata(&path).unwrap().len();
        assert!(size_after <= size_before);

        // Reload from disk and verify data integrity
        drop(mgr);
        let reloaded = SnapshotManager::open(&path).unwrap();
        let g = reloaded.graph();
        assert_eq!(g.entity_count(), 2);
        assert_eq!(g.relation_count(), 1);
        assert!(
            g.downstream_warnings_for_entity(&e1.id).unwrap().is_empty(),
            "orphaned warning should be gone after compact"
        );
    }

    #[test]
    fn compact_clean_graph_is_noop() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        let e = test_entity("clean");
        graph.upsert_entity(&e).unwrap();
        mgr.save().unwrap();

        let stats = mgr.compact().unwrap();
        assert!(stats.is_clean());
    }

    #[test]
    fn open_rejects_corrupted_snapshot_after_save() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        let entity = test_entity("corrupt_me");
        graph.upsert_entity(&entity).unwrap();
        mgr.save().unwrap();

        let mut bytes = std::fs::read(&path).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();

        let err = match SnapshotManager::open(&path) {
            Ok(_) => panic!("expected corrupted snapshot to fail reopening"),
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("checksum mismatch") || msg.contains("corrupted"),
            "expected corruption detection, got: {msg}"
        );
    }

    #[test]
    fn save_with_relations() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();

        let e1 = test_entity("caller");
        let e2 = test_entity("callee");
        let rel = Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(e1.id),
            dst: GraphNodeId::Entity(e2.id),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
        };

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();
        mgr.save().unwrap();

        // Reload
        let mgr2 = SnapshotManager::open(&path).unwrap();
        let g2 = mgr2.graph();
        assert_eq!(g2.entity_count(), 2);
        assert_eq!(g2.relation_count(), 1);
        let rels = g2.get_relations(&e1.id, &[RelationKind::Calls]).unwrap();
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].dst, GraphNodeId::Entity(e2.id));
    }

    #[test]
    fn save_with_cochange_relations() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();

        let e1 = test_entity("alpha");
        let e2 = test_entity("beta");
        let rel = Relation {
            id: RelationId::new(),
            kind: RelationKind::CoChanges,
            src: GraphNodeId::Entity(e1.id),
            dst: GraphNodeId::Entity(e2.id),
            confidence: 0.75,
            origin: RelationOrigin::Inferred,
            created_in: None,
            import_source: None,
        };

        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_relation(&rel).unwrap();
        mgr.save().unwrap();

        let mgr2 = SnapshotManager::open(&path).unwrap();
        let g2 = mgr2.graph();
        let rels = g2
            .get_relations(&e1.id, &[RelationKind::CoChanges])
            .unwrap();
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].dst, GraphNodeId::Entity(e2.id));
        assert!((rels[0].confidence - 0.75).abs() < f32::EPSILON);
    }

    #[test]
    fn concurrent_open_returns_lock_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        // First manager acquires the lock
        let _mgr1 = SnapshotManager::open(&path).unwrap();

        // Second open on the same path should fail with LockError
        let result = SnapshotManager::open(&path);
        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("lock"),
            "expected lock error, got: {err_msg}"
        );
    }

    #[test]
    fn concurrent_read_only_opens_succeed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let _mgr1 = SnapshotManager::open_read_only(&path).unwrap();
        let _mgr2 = SnapshotManager::open_read_only(&path).unwrap();
    }

    #[test]
    fn read_only_snapshot_cannot_save() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::open_read_only(&path).unwrap();
        let err = mgr.save().unwrap_err().to_string();
        assert!(err.contains("read-only"), "unexpected error: {err}");
    }

    #[test]
    fn read_only_open_does_not_write_missing_text_index() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let text_index_path = text_index_dir_for(&path).unwrap();

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        graph.upsert_entity(&test_entity("text_reader")).unwrap();
        mgr.save().unwrap();

        if text_index_path.exists() {
            std::fs::remove_dir_all(&text_index_path).unwrap();
        }

        let reloaded = SnapshotManager::open_read_only(&path).unwrap();
        assert_eq!(reloaded.graph().entity_count(), 1);
        assert!(
            !text_index_path.exists(),
            "read-only open should not recreate the text index sidecar"
        );
    }

    #[test]
    #[cfg(feature = "vector")]
    fn read_only_open_does_not_write_missing_vector_metadata() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);
        let metadata_path = vector_index_metadata_path_for(&snapshot_path);

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        let entity = test_entity("vector_reader");
        graph.upsert_entity(&entity).unwrap();
        mgr.save().unwrap();

        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(entity.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        vectors.save(&vector_path).unwrap();
        if metadata_path.exists() {
            std::fs::remove_file(&metadata_path).unwrap();
        }

        let reloaded = SnapshotManager::open_read_only(&snapshot_path).unwrap();
        assert_eq!(reloaded.graph().embedding_status().indexed, 1);
        assert!(
            !metadata_path.exists(),
            "read-only open should not create vector metadata"
        );
    }

    #[test]
    #[cfg(feature = "vector")]
    fn cyclic_graph_reopen_preserves_vector_sidecar_and_embeddings() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);
        let metadata_path = vector_index_metadata_path_for(&snapshot_path);

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();

        let e1 = test_entity("alpha");
        let e2 = test_entity("beta");
        let e3 = test_entity("gamma");
        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph.upsert_entity(&e3).unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(e1.id),
                dst: GraphNodeId::Entity(e2.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
            })
            .unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(e2.id),
                dst: GraphNodeId::Entity(e1.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
            })
            .unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(e2.id),
                dst: GraphNodeId::Entity(e3.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
            })
            .unwrap();

        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(e1.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        vectors.upsert(e2.id, &[0.9, 0.1, 0.0, 0.0]).unwrap();
        vectors.upsert(e3.id, &[0.1, 0.9, 0.0, 0.0]).unwrap();
        vectors.save(&vector_path).unwrap();
        graph.load_vector_index(&vector_path).unwrap();

        mgr.save().unwrap();

        let metadata = read_vector_index_metadata(&metadata_path)
            .unwrap()
            .expect("vector metadata should exist after save");
        assert_eq!(
            metadata.graph_root_hash,
            hex::encode(compute_graph_root_hash(&graph.to_snapshot()))
        );
        assert_eq!(metadata.indexed, 3);

        drop(mgr);

        let reopened = SnapshotManager::open_read_only(&snapshot_path).unwrap();
        let stats = reopened.graph().graph_stats();
        assert_eq!(stats.indexed_embedding_count, 3);
        assert_eq!(stats.pending_embedding_count, 0);
        assert_eq!(reopened.graph().embedding_status().indexed, 3);
    }

    #[test]
    fn lock_released_on_drop() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        // Open and immediately drop
        {
            let _mgr = SnapshotManager::open(&path).unwrap();
        }

        // Should succeed now that the previous manager is dropped
        let _mgr2 = SnapshotManager::open(&path).unwrap();
        assert_eq!(_mgr2.graph().entity_count(), 0);
    }

    #[test]
    fn concurrent_open_from_threads_one_wins() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        std::thread::scope(|s| {
            let handle1 = s.spawn(|| SnapshotManager::open(&path));
            let handle2 = s.spawn(|| SnapshotManager::open(&path));

            let r1 = handle1.join().unwrap();
            let r2 = handle2.join().unwrap();

            // Exactly one should succeed and one should fail
            match (&r1, &r2) {
                (Ok(_), Ok(_)) => panic!("both opens succeeded — lock not working"),
                (Ok(_), Err(_)) | (Err(_), Ok(_)) => {} // expected
                (Err(_), Err(_)) => panic!("both opens failed — expected one to succeed"),
            };
        });
    }

    #[test]
    fn reader_unblocked_during_writer_save() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::open(&path).unwrap();
        let graph = mgr.graph();
        let e = test_entity("concurrent_read");
        graph.upsert_entity(&e).unwrap();

        std::thread::scope(|s| {
            // Writer thread: saves to disk
            let mgr_ref = &mgr;
            let writer = s.spawn(move || {
                mgr_ref.save().unwrap();
            });

            // Reader thread: reads the graph concurrently
            let reader = s.spawn(move || {
                let g = mgr_ref.graph();
                // The graph should be readable regardless of save state
                let _ = g.entity_count(); // just verify we can read without panic
            });

            writer.join().unwrap();
            reader.join().unwrap();
        });
    }

    #[test]
    fn borrowed_root_hash_matches_snapshot_root_hash() {
        let graph = InMemoryGraph::new();
        let entity = test_entity("Foo");
        let entity2 = test_entity("Bar");
        graph.upsert_entity(&entity).unwrap();
        graph.upsert_entity(&entity2).unwrap();
        let relation = Relation {
            id: RelationId::new(),
            src: GraphNodeId::Entity(entity.id),
            dst: GraphNodeId::Entity(entity2.id),
            kind: RelationKind::Calls,
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
        };
        graph.upsert_relation(&relation).unwrap();

        let snapshot = graph.to_snapshot();
        let hash_from_snapshot = compute_graph_root_hash(&snapshot);
        let hash_from_live = graph.compute_root_hash();
        assert_eq!(
            hash_from_snapshot, hash_from_live,
            "root hash from live stores must match root hash from to_snapshot()"
        );
    }

    #[test]
    fn borrowed_save_round_trips() {
        let dir = TempDir::new().unwrap();
        let snap_path = dir.path().join("borrowed_rt.kndb");

        let graph = InMemoryGraph::new();
        let entity = test_entity("RoundTrip");
        graph.upsert_entity(&entity).unwrap();

        // Save via borrowed path (now the default)
        SnapshotManager::save_graph(&snap_path, &graph).unwrap();

        // Load back and verify
        let loaded = crate::storage::mmap::MmapReader::open(&snap_path).unwrap();
        assert_eq!(loaded.entities.len(), 1);
        let loaded_entity = loaded.entities.get(&entity.id).unwrap();
        assert_eq!(loaded_entity.name, "RoundTrip");
        assert_eq!(loaded_entity.kind, EntityKind::Function);
        assert_eq!(loaded_entity.language, LanguageId::Rust);
    }

    #[test]
    fn precomputed_hash_save_round_trips() {
        let dir = TempDir::new().unwrap();
        let snap_path = dir.path().join("precomputed.kndb");

        let graph = InMemoryGraph::new();
        let e1 = test_entity("HashTest");
        let e2 = test_entity("HashTest2");
        graph.upsert_entity(&e1).unwrap();
        graph.upsert_entity(&e2).unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                src: GraphNodeId::Entity(e1.id),
                dst: GraphNodeId::Entity(e2.id),
                kind: RelationKind::Calls,
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
            })
            .unwrap();

        // Compute hash once, then pass it to save_graph_with_hash
        let root_hash = graph.compute_root_hash();
        let returned_hash =
            SnapshotManager::save_graph_with_hash(&snap_path, &graph, Some(root_hash)).unwrap();
        assert_eq!(root_hash, returned_hash);

        // Load back and verify
        let loaded = crate::storage::mmap::MmapReader::open(&snap_path).unwrap();
        assert_eq!(loaded.entities.len(), 2);
        assert!(loaded.entities.contains_key(&e1.id));
        assert!(loaded.entities.contains_key(&e2.id));
        assert_eq!(loaded.relations.len(), 1);

        // Verify loaded root hash matches
        let loaded_hash = compute_graph_root_hash(&loaded);
        assert_eq!(root_hash, loaded_hash);
    }
}
