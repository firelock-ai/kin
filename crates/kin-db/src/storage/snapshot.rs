// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use fs2::FileExt;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::engine::{InMemoryGraph, PersistenceEpoch};
use crate::error::KinDbError;
use crate::storage::backend::{Generation, GENERATION_INIT};
use crate::storage::delta::{apply_graph_delta, GraphSnapshotDelta};
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
    /// Last generation acknowledged by the atomic local snapshot authority.
    generation: AtomicU64,
}

struct PersistenceAttempt<'a> {
    graph: &'a InMemoryGraph,
    epoch: Option<PersistenceEpoch>,
}

impl<'a> PersistenceAttempt<'a> {
    fn new(graph: &'a InMemoryGraph, epoch: PersistenceEpoch) -> Self {
        Self {
            graph,
            epoch: Some(epoch),
        }
    }

    fn complete(mut self) {
        if let Some(epoch) = self.epoch.take() {
            let completed = self.graph.complete_persistence(epoch);
            debug_assert!(completed, "persistence epoch must still be in flight");
        }
    }
}

impl Drop for PersistenceAttempt<'_> {
    fn drop(&mut self) {
        if let Some(epoch) = self.epoch.take() {
            self.graph.fail_persistence(epoch);
        }
    }
}

/// Derive the text index directory as a sibling of the snapshot file.
/// e.g. `.kin/kindb/graph.kndb` → `.kin/kindb/text-index/`
fn text_index_dir_for(snapshot_path: &Path) -> Option<PathBuf> {
    snapshot_path.parent().map(|p| p.join("text-index"))
}

fn locate_cache_path_for(snapshot_path: &Path) -> PathBuf {
    snapshot_path.with_extension("kloc")
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = std::ffi::OsString::from(path.as_os_str());
    name.push(suffix);
    PathBuf::from(name)
}

fn local_delta_dir_for(snapshot_path: &Path) -> PathBuf {
    append_suffix(snapshot_path, ".deltas")
}

const LOCAL_SNAPSHOT_AUTHORITY_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LocalSnapshotAuthority {
    version: u32,
    snapshot_generation: Generation,
    head_generation: Generation,
    snapshot_file: String,
    snapshot_root_hash: String,
}

const LOCAL_LEGACY_REBUILD_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LocalLegacyRebuildMarker {
    version: u32,
    expected_generation: Generation,
    committed_generation: Generation,
    captured_deltas: Vec<(String, String)>,
}

fn local_authority_path(snapshot_path: &Path) -> PathBuf {
    append_suffix(snapshot_path, ".authority.json")
}

fn local_legacy_rebuild_marker_path(snapshot_path: &Path) -> PathBuf {
    append_suffix(snapshot_path, ".legacy-journal-rebuild.json")
}

fn local_projection_generation_path(snapshot_path: &Path) -> PathBuf {
    append_suffix(snapshot_path, ".projection-generation")
}

fn local_projection_generation(snapshot_path: &Path) -> Option<Generation> {
    std::fs::read_to_string(local_projection_generation_path(snapshot_path))
        .ok()
        .and_then(|value| value.trim().parse().ok())
}

fn write_local_projection_generation(
    snapshot_path: &Path,
    generation: Generation,
) -> Result<(), KinDbError> {
    mmap::atomic_write_bytes_no_magic(
        &local_projection_generation_path(snapshot_path),
        generation.to_string().as_bytes(),
    )
}

fn local_snapshot_versions_dir(snapshot_path: &Path) -> PathBuf {
    append_suffix(snapshot_path, ".snapshots")
}

fn local_snapshot_file_name(generation: Generation) -> String {
    format!("{generation:020}.kndb")
}

fn local_versioned_snapshot_path(snapshot_path: &Path, generation: Generation) -> PathBuf {
    local_snapshot_versions_dir(snapshot_path).join(local_snapshot_file_name(generation))
}

fn legacy_generation_hint(snapshot_path: &Path) -> Result<Generation, KinDbError> {
    let Some(parent) = snapshot_path.parent() else {
        return Ok(GENERATION_INIT);
    };
    let marker = parent.join("generation");
    if !marker.exists() {
        return Ok(GENERATION_INIT);
    }
    let value = std::fs::read_to_string(&marker).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to read legacy generation hint {}: {error}",
            marker.display()
        ))
    })?;
    value.trim().parse::<Generation>().map_err(|error| {
        KinDbError::StorageError(format!(
            "invalid legacy generation hint in {}: {error}",
            marker.display()
        ))
    })
}

fn read_local_authority_manifest_raw(
    snapshot_path: &Path,
) -> Result<Option<LocalSnapshotAuthority>, KinDbError> {
    let path = local_authority_path(snapshot_path);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to read local snapshot authority {}: {error}",
            path.display()
        ))
    })?;
    let authority: LocalSnapshotAuthority = serde_json::from_slice(&bytes).map_err(|error| {
        KinDbError::StorageError(format!(
            "invalid local snapshot authority {}: {error}",
            path.display()
        ))
    })?;
    if authority.version != LOCAL_SNAPSHOT_AUTHORITY_VERSION {
        return Err(KinDbError::StorageError(format!(
            "unsupported local snapshot authority version {} in {}",
            authority.version,
            path.display()
        )));
    }
    if authority.snapshot_generation > authority.head_generation {
        return Err(KinDbError::StorageError(format!(
            "local snapshot authority base {} exceeds head {}",
            authority.snapshot_generation, authority.head_generation
        )));
    }
    let expected_file = local_snapshot_file_name(authority.snapshot_generation);
    if authority.snapshot_file != expected_file {
        return Err(KinDbError::StorageError(format!(
            "local snapshot authority references noncanonical snapshot file {}",
            authority.snapshot_file
        )));
    }
    let versioned_path = local_snapshot_versions_dir(snapshot_path).join(&authority.snapshot_file);
    if !versioned_path.is_file() {
        return Err(KinDbError::StorageError(format!(
            "local snapshot authority references missing snapshot {}",
            versioned_path.display()
        )));
    }
    if authority.snapshot_root_hash.len() != 64
        || hex::decode(&authority.snapshot_root_hash).is_err()
    {
        return Err(KinDbError::StorageError(format!(
            "local snapshot authority has an invalid graph root for {}",
            versioned_path.display()
        )));
    }
    let legacy_generation = legacy_generation_hint(snapshot_path)?;
    if legacy_generation > authority.head_generation {
        return Err(KinDbError::StorageError(format!(
            "legacy local writer advanced {} to generation {legacy_generation} beyond atomic authority head {}; drain pre-authority writers before retrying",
            snapshot_path.display(),
            authority.head_generation
        )));
    }
    Ok(Some(authority))
}

fn read_local_authority_manifest(
    snapshot_path: &Path,
) -> Result<Option<LocalSnapshotAuthority>, KinDbError> {
    let authority = read_local_authority_manifest_raw(snapshot_path)?;
    if authority.is_some() {
        let marker = local_legacy_rebuild_marker_path(snapshot_path);
        if marker.exists() {
            return Err(KinDbError::StorageError(format!(
                "local snapshot {} has a pending legacy-journal rebuild marker {}; retry the explicit rebuild after quiescing legacy writers",
                snapshot_path.display(),
                marker.display()
            )));
        }
    }
    Ok(authority)
}

fn local_authority_root_hash(authority: &LocalSnapshotAuthority) -> Result<[u8; 32], KinDbError> {
    let bytes = hex::decode(&authority.snapshot_root_hash).map_err(|error| {
        KinDbError::StorageError(format!(
            "invalid local snapshot authority graph root: {error}"
        ))
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        KinDbError::StorageError(format!(
            "invalid local snapshot authority graph root length {}; expected 32 bytes",
            bytes.len()
        ))
    })
}

fn write_local_authority(
    snapshot_path: &Path,
    authority: &LocalSnapshotAuthority,
) -> Result<(), KinDbError> {
    let bytes = serde_json::to_vec(authority).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to encode local snapshot authority: {error}"
        ))
    })?;
    let path = local_authority_path(snapshot_path);
    match mmap::atomic_write_bytes_no_magic(&path, &bytes) {
        Ok(()) => Ok(()),
        Err(error) => {
            // The atomic primitive can report a recovery-marker cleanup error
            // after its rename and parent-directory fsync have already
            // committed the new authority. Detect that irreversible state so
            // callers advance their cursor instead of retrying from a stale
            // generation and colliding with their own successful commit.
            if std::fs::read(&path).ok().as_deref() == Some(bytes.as_slice()) {
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "local snapshot authority committed with deferred temp-marker cleanup"
                );
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

fn local_delta_path(snapshot_path: &Path, generation: u64) -> PathBuf {
    local_delta_dir_for(snapshot_path).join(format!("{generation:020}.kndd"))
}

fn local_delta_generation(path: &Path) -> Option<u64> {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .and_then(|stem| stem.parse::<u64>().ok())
}

fn local_delta_files(snapshot_path: &Path) -> Result<Vec<(u64, PathBuf)>, KinDbError> {
    let dir = local_delta_dir_for(snapshot_path);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|err| {
        KinDbError::StorageError(format!(
            "failed to read local delta directory {}: {err}",
            dir.display()
        ))
    })? {
        let entry = entry.map_err(|err| {
            KinDbError::StorageError(format!(
                "failed to read local delta entry in {}: {err}",
                dir.display()
            ))
        })?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("kndd") {
            continue;
        }
        let generation = local_delta_generation(&path).ok_or_else(|| {
            KinDbError::StorageError(format!(
                "local delta authority {} has an invalid generation",
                path.display()
            ))
        })?;
        let canonical_name = format!("{generation:020}.kndd");
        if generation == GENERATION_INIT
            || path.file_name().and_then(|name| name.to_str()) != Some(canonical_name.as_str())
        {
            return Err(KinDbError::StorageError(format!(
                "local delta authority {} has a reserved or noncanonical generation",
                path.display()
            )));
        }
        files.push((generation, path));
    }
    files.sort_by_key(|(generation, _)| *generation);
    Ok(files)
}

fn local_delta_count(snapshot_path: &Path) -> Result<usize, KinDbError> {
    Ok(local_delta_files(snapshot_path)?.len())
}

fn validate_authoritative_base_snapshot(
    snapshot_path: &Path,
    authority: &LocalSnapshotAuthority,
    snapshot: &crate::storage::GraphSnapshot,
    persisted_root_hash: Option<[u8; 32]>,
) -> Result<[u8; 32], KinDbError> {
    let expected_root_hash = local_authority_root_hash(authority)?;
    if persisted_root_hash != Some(expected_root_hash) {
        return Err(KinDbError::StorageError(format!(
            "authoritative local snapshot {} root trailer does not match authority {}",
            snapshot_path.display(),
            authority.snapshot_root_hash
        )));
    }
    // With no journal, graph construction immediately below builds the Merkle
    // cache and performs the same content-vs-root verification. A journal
    // clears the base root after replay, so validate the base explicitly before
    // applying any deltas in that case.
    if authority.snapshot_generation < authority.head_generation {
        let actual_root_hash = compute_graph_root_hash(snapshot);
        if actual_root_hash != expected_root_hash {
            return Err(KinDbError::StorageError(format!(
                "authoritative local snapshot {} graph root mismatch: authority {}, actual {}",
                snapshot_path.display(),
                authority.snapshot_root_hash,
                hex::encode(actual_root_hash)
            )));
        }
    }
    Ok(expected_root_hash)
}

fn apply_local_deltas(
    snapshot_path: &Path,
    mut snapshot: crate::storage::GraphSnapshot,
    persisted_root_hash: Option<[u8; 32]>,
    authority: Option<&LocalSnapshotAuthority>,
) -> Result<
    (
        crate::storage::GraphSnapshot,
        Option<[u8; 32]>,
        usize,
        Generation,
    ),
    KinDbError,
> {
    let files = local_delta_files(snapshot_path)?;
    let Some(authority) = authority else {
        if !files.is_empty() {
            return Err(KinDbError::StorageError(format!(
                "local snapshot {} has {} deltas but no atomic snapshot-base authority",
                snapshot_path.display(),
                files.len()
            )));
        }
        return Ok((
            snapshot,
            persisted_root_hash,
            0,
            legacy_generation_hint(snapshot_path)?,
        ));
    };

    let mut expected_generation =
        authority
            .snapshot_generation
            .checked_add(1)
            .ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "local snapshot generation exhausted at {}",
                    authority.snapshot_generation
                ))
            })?;
    let mut recovered_generation = authority.snapshot_generation;
    let mut applied = 0usize;

    if authority.snapshot_generation == authority.head_generation {
        return Ok((snapshot, persisted_root_hash, 0, authority.head_generation));
    }

    for (generation, path) in &files {
        if *generation <= authority.snapshot_generation {
            continue;
        }
        if *generation > authority.head_generation {
            // A delta written before an authority-commit crash is not durable
            // authority. A retry may overwrite this exact generation.
            continue;
        }
        if *generation != expected_generation {
            return Err(KinDbError::StorageError(format!(
                "local delta chain is incomplete: expected generation {expected_generation}, found {generation}"
            )));
        }
        let bytes = std::fs::read(path).map_err(|err| {
            KinDbError::StorageError(format!(
                "failed to read local delta {}: {err}",
                path.display()
            ))
        })?;
        let delta = GraphSnapshotDelta::from_bytes(&bytes)?;
        let expected_base = generation - 1;
        if delta.base_generation != expected_base {
            return Err(KinDbError::StorageError(format!(
                "local delta generation {generation} declares base {}, expected {expected_base}",
                delta.base_generation
            )));
        }
        apply_graph_delta(&mut snapshot, &delta);
        applied += 1;
        recovered_generation = *generation;
        if *generation < authority.head_generation {
            expected_generation = generation.checked_add(1).ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "local delta generation exhausted at {generation}"
                ))
            })?;
        }
    }
    if recovered_generation != authority.head_generation {
        return Err(KinDbError::StorageError(format!(
            "local delta chain ended at generation {recovered_generation}, acknowledged head is {}",
            authority.head_generation
        )));
    }
    Ok((snapshot, None, applied, authority.head_generation))
}

fn write_local_delta(
    snapshot_path: &Path,
    delta: &GraphSnapshotDelta,
    base_generation: u64,
) -> Result<u64, KinDbError> {
    let mut authority = match read_local_authority_manifest(snapshot_path)? {
        Some(authority) => authority,
        None => {
            let files = local_delta_files(snapshot_path)?;
            if !files.is_empty() {
                return Err(KinDbError::StorageError(format!(
                    "local snapshot {} has an unbound journal; refusing delta persistence",
                    snapshot_path.display()
                )));
            }
            let snapshot_bytes = std::fs::read(snapshot_path).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to read legacy local snapshot {}: {error}",
                    snapshot_path.display()
                ))
            })?;
            let snapshot = crate::storage::GraphSnapshot::from_bytes(&snapshot_bytes)?;
            let snapshot_root_hash = compute_graph_root_hash(&snapshot);
            let authoritative_snapshot_bytes =
                snapshot.to_bytes_with_persisted_root_hash(snapshot_root_hash)?;
            let versioned_path = local_versioned_snapshot_path(snapshot_path, base_generation);
            std::fs::create_dir_all(local_snapshot_versions_dir(snapshot_path)).map_err(
                |error| {
                    KinDbError::StorageError(format!(
                        "failed to create local snapshot versions directory: {error}"
                    ))
                },
            )?;
            mmap::atomic_write_bytes(&versioned_path, &authoritative_snapshot_bytes)?;
            let authority = LocalSnapshotAuthority {
                version: LOCAL_SNAPSHOT_AUTHORITY_VERSION,
                snapshot_generation: base_generation,
                head_generation: base_generation,
                snapshot_file: local_snapshot_file_name(base_generation),
                snapshot_root_hash: hex::encode(snapshot_root_hash),
            };
            write_local_authority(snapshot_path, &authority)?;
            authority
        }
    };
    if authority.head_generation != base_generation {
        return Err(KinDbError::StorageError(format!(
            "local delta base generation mismatch: expected {base_generation}, found {}",
            authority.head_generation
        )));
    }
    if delta.base_generation != base_generation {
        return Err(KinDbError::StorageError(format!(
            "local delta payload declares base {}, expected {base_generation}",
            delta.base_generation
        )));
    }
    let dir = local_delta_dir_for(snapshot_path);
    std::fs::create_dir_all(&dir).map_err(|err| {
        KinDbError::StorageError(format!(
            "failed to create local delta directory {}: {err}",
            dir.display()
        ))
    })?;
    let next_generation = base_generation.checked_add(1).ok_or_else(|| {
        KinDbError::StorageError(format!(
            "local delta generation exhausted at {base_generation}"
        ))
    })?;
    let path = local_delta_path(snapshot_path, next_generation);
    let bytes = delta.to_bytes()?;
    mmap::atomic_write_bytes_no_magic(&path, &bytes)?;
    authority.head_generation = next_generation;
    write_local_authority(snapshot_path, &authority)?;
    Ok(next_generation)
}

fn clear_local_deltas(snapshot_path: &Path) -> Result<(), KinDbError> {
    let dir = local_delta_dir_for(snapshot_path);
    if !dir.exists() {
        return Ok(());
    }
    for (_, path) in local_delta_files(snapshot_path)? {
        std::fs::remove_file(&path).map_err(|err| {
            KinDbError::StorageError(format!(
                "failed to remove local delta {}: {err}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

fn capture_local_deltas(
    snapshot_path: &Path,
) -> Result<Vec<(Generation, PathBuf, Vec<u8>)>, KinDbError> {
    local_delta_files(snapshot_path)?
        .into_iter()
        .map(|(generation, path)| {
            let bytes = std::fs::read(&path).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to capture legacy delta {}: {error}",
                    path.display()
                ))
            })?;
            Ok((generation, path, bytes))
        })
        .collect()
}

fn local_delta_capture_identity(
    captured: &[(Generation, PathBuf, Vec<u8>)],
) -> Vec<(String, String)> {
    captured
        .iter()
        .map(|(_, path, bytes)| {
            (
                path.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("<non-utf8>")
                    .to_string(),
                hex::encode(Sha256::digest(bytes)),
            )
        })
        .collect()
}

fn clear_exact_captured_local_deltas(
    snapshot_path: &Path,
    captured: &[(Generation, PathBuf, Vec<u8>)],
) -> bool {
    let mut complete = true;
    for (_, path, captured_bytes) in captured {
        match std::fs::read(path) {
            Ok(current_bytes) if current_bytes == *captured_bytes => {
                if let Err(error) = std::fs::remove_file(path) {
                    complete = false;
                    tracing::warn!(path = %path.display(), error = %error, "legacy rebuild committed; deferred captured-delta cleanup");
                }
            }
            Ok(_) => {
                complete = false;
                tracing::warn!(path = %path.display(), "legacy rebuild preserved a delta that changed after capture");
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                complete = false;
                tracing::warn!(path = %path.display(), error = %error, "legacy rebuild committed; could not verify captured delta for cleanup");
            }
        }
    }
    match local_delta_files(snapshot_path) {
        Ok(remaining) if remaining.is_empty() => complete,
        Ok(remaining) => {
            tracing::warn!(
                path = %snapshot_path.display(),
                remaining = remaining.len(),
                "legacy rebuild committed with residual journal artifacts; recovery remains fail-closed"
            );
            false
        }
        Err(error) => {
            tracing::warn!(path = %snapshot_path.display(), error = %error, "legacy rebuild committed; could not verify journal drain");
            false
        }
    }
}

fn clear_superseded_local_snapshots(
    snapshot_path: &Path,
    keep_generation: Generation,
) -> Result<(), KinDbError> {
    let dir = local_snapshot_versions_dir(snapshot_path);
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(&dir).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to read local snapshot versions directory {}: {error}",
            dir.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to read local snapshot entry in {}: {error}",
                dir.display()
            ))
        })?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(generation) = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(|stem| stem.parse::<Generation>().ok())
        else {
            continue;
        };
        if path.extension().and_then(|ext| ext.to_str()) != Some("kndb")
            || name != local_snapshot_file_name(generation)
            || generation >= keep_generation
        {
            // A greater generation can be an in-flight static writer that has
            // installed its immutable base but not yet moved authority. Never
            // reap it from cleanup keyed to the older committed generation.
            continue;
        }
        std::fs::remove_file(&path).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to remove superseded local snapshot {}: {error}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

#[cfg(feature = "vector")]
fn vector_index_path_for(snapshot_path: &Path) -> PathBuf {
    snapshot_path.with_extension("kvec")
}

#[cfg(feature = "vector")]
fn vector_index_metadata_path_for(snapshot_path: &Path) -> PathBuf {
    vector_index_path_for(snapshot_path).with_extension("kvec.meta.json")
}

/// Bump this constant whenever a new required field is added to
/// `VectorIndexMetadata`. Version 1 (legacy) is still accepted on read —
/// only fields present in both sides are enforced. Unknown future versions
/// (> VERSION) are rejected.
#[cfg(feature = "vector")]
pub const VECTOR_INDEX_METADATA_VERSION: u32 = 2;

const LOCATE_CACHE_VERSION: u32 = 1;

#[cfg(feature = "vector")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VectorIndexMetadata {
    version: u32,
    graph_root_hash: String,
    dimensions: usize,
    indexed: usize,
    #[serde(default)]
    embedding_provider: Option<String>,
    #[serde(default)]
    embedding_model_id: Option<String>,
    #[serde(default)]
    embedding_model_revision: Option<String>,
    #[serde(default)]
    embedding_pipeline_epoch: Option<String>,
    /// Caller-supplied artifact/binary identity of the embedder that produced
    /// these vectors (e.g. a build SHA or version string). `None` for legacy
    /// stores (version ≤ 1). Enforced in `vector_metadata_matches_graph` only
    /// when both stored and expected are `Some` — `None` on either side is
    /// treated as legacy and logs a warning but does not reject the load.
    #[serde(default)]
    embedder_identity: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LocateSnapshotCache {
    version: u32,
    root_hash: [u8; 32],
    snapshot: crate::storage::format::LocateGraphSnapshot,
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

fn locate_cache_write_enabled() -> bool {
    matches!(
        std::env::var("KINDB_LOCATE_CACHE_WRITE"),
        Ok(value)
            if !value.is_empty()
                && value != "0"
                && !value.eq_ignore_ascii_case("false")
                && !value.eq_ignore_ascii_case("no")
    )
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
    // Accept version 1 (legacy, no embedder_identity) and version 2 (current).
    // A future version written by a newer binary is rejected so we never
    // silently interpret fields we don't understand.
    if metadata.version == 0 || metadata.version > VectorIndexMetadata::VERSION {
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
    // Crash-safe write: fsync the temp file before the atomic rename, then
    // fsync the parent directory so the rename itself is durable. This matches
    // the discipline used for the graph snapshot (mmap::atomic_write_bytes) and
    // the kvec sidecar (kin-vector atomic_save_bytes). The metadata gates whether
    // the kvec loads on reopen, so it must be at least as durable as the index it
    // describes: an incremental kvec flush that survives a crash must never be
    // paired with a metadata write that silently evaporated.
    let tmp_path = path.with_extension("tmp");
    {
        use std::io::Write as _;
        let mut tmp = File::create(&tmp_path).map_err(|err| {
            KinDbError::StorageError(format!(
                "failed to create vector index metadata temp {}: {err}",
                tmp_path.display()
            ))
        })?;
        tmp.write_all(&encoded).map_err(|err| {
            KinDbError::StorageError(format!(
                "failed to write vector index metadata {}: {err}",
                tmp_path.display()
            ))
        })?;
        tmp.sync_all().map_err(|err| {
            KinDbError::StorageError(format!(
                "failed to fsync vector index metadata {}: {err}",
                tmp_path.display()
            ))
        })?;
    }
    std::fs::rename(&tmp_path, path).map_err(|err| {
        KinDbError::StorageError(format!(
            "failed to promote vector index metadata {} -> {}: {err}",
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

#[cfg(feature = "vector")]
fn current_embedding_runtime_fields() -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<usize>,
) {
    #[cfg(feature = "embeddings")]
    {
        let runtime = crate::embed::configured_embedding_runtime();
        return (
            Some(runtime.provider),
            Some(runtime.model_id),
            Some(runtime.revision),
            Some(runtime.pipeline_epoch),
            runtime.dimensions,
        );
    }

    #[cfg(not(feature = "embeddings"))]
    {
        (None, None, None, None, None)
    }
}

#[cfg(feature = "vector")]
fn vector_metadata_matches_graph(
    metadata: &VectorIndexMetadata,
    graph_root_hash: [u8; 32],
    expected_embedder_identity: Option<&str>,
) -> bool {
    if metadata.graph_root_hash != hex::encode(graph_root_hash) {
        return false;
    }

    #[cfg(feature = "embeddings")]
    {
        let runtime = crate::embed::configured_embedding_runtime();
        if let Some(provider) = metadata.embedding_provider.as_ref() {
            if provider != &runtime.provider {
                return false;
            }
        } else if runtime.provider != "local" {
            return false;
        }
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
        if let Some(dimensions) = runtime.dimensions {
            if metadata.dimensions != dimensions {
                return false;
            }
        }
    }

    // Embedder identity: enforced only when both stored and expected are Some.
    // None on either side is a legacy/unknown value — warn but allow the load
    // so existing stores remain non-breaking.
    match (
        metadata.embedder_identity.as_deref(),
        expected_embedder_identity,
    ) {
        (Some(stored), Some(expected)) if stored != expected => {
            tracing::warn!(
                stored = %stored,
                expected = %expected,
                "vector sidecar embedder_identity mismatch: rejecting load"
            );
            return false;
        }
        (None, Some(_)) | (Some(_), None) => {
            tracing::warn!(
                stored = ?metadata.embedder_identity,
                expected = ?expected_embedder_identity,
                "vector sidecar has missing embedder_identity (legacy store); loading anyway"
            );
        }
        _ => {}
    }

    true
}

/// Append a deterministic `.archived` suffix to a path. A single archive slot
/// per file (re-archiving overwrites it) keeps recovery deterministic and caps
/// on-disk clutter.
#[cfg(feature = "vector")]
fn archived_sidecar_path(p: &Path) -> PathBuf {
    let mut name = p.as_os_str().to_os_string();
    name.push(".archived");
    PathBuf::from(name)
}

/// Move an incompatible vector index (and its metadata sidecar, if present)
/// aside to a deterministic `.archived` path so it is neither served nor
/// re-detected into a crash loop. Best-effort: a rename failure is logged, not
/// propagated — recovery (rebuild from the embedding queue) proceeds regardless,
/// so an un-archivable file never crashes the load.
#[cfg(feature = "vector")]
fn archive_incompatible_index(vector_path: &Path, metadata_path: &Path) {
    if vector_path.exists() {
        let archived = archived_sidecar_path(vector_path);
        match std::fs::rename(vector_path, &archived) {
            Ok(()) => tracing::warn!(
                from = %vector_path.display(),
                to = %archived.display(),
                "archived incompatible vector index"
            ),
            Err(e) => tracing::error!(
                path = %vector_path.display(),
                error = %e,
                "failed to archive incompatible vector index (rebuilding anyway)"
            ),
        }
    }
    if metadata_path.exists() {
        let archived = archived_sidecar_path(metadata_path);
        if let Err(e) = std::fs::rename(metadata_path, &archived) {
            tracing::error!(
                path = %metadata_path.display(),
                error = %e,
                "failed to archive vector index metadata (rebuilding anyway)"
            );
        }
    }
}

/// Outcome of a single incremental embed-progress flush
/// ([`SnapshotManager::flush_embed_progress`]).
///
/// Returned per batch so the embed driver can advance its durable cursor and
/// decide when coverage is complete without re-deriving any of it from disk.
#[cfg(feature = "vector")]
#[derive(Debug, Clone)]
pub struct EmbedFlushOutcome {
    /// Durable generation marker after the flush. Advance the caller's
    /// `base_generation` cursor to this before the next batch. `None` when the
    /// graph itself was unchanged (the common embed case — only new vectors
    /// were written), so the cursor stays put.
    pub generation: Option<Generation>,
    /// `true` when this flush took the full-snapshot path (the initial write or
    /// a compaction forced by `full_snapshot_required`); that path is O(graph)
    /// and already persists the vector bundle. `false` is the incremental hot
    /// path: a vector sidecar (+ optional graph delta) sized to the batch, never
    /// a full re-serialize of the graph.
    pub full_snapshot: bool,
    /// Embedding coverage after the flush. `status.pending` is the resume work
    /// still outstanding (objects with no vector yet); it reaches zero only at
    /// full coverage, and survives a crash/reopen because it is derived from
    /// persisted graph-vs-index truth, not the in-memory queue.
    pub status: crate::engine::EmbeddingStatus,
}

impl SnapshotManager {
    /// Return whether `path` has an atomic local snapshot authority sidecar.
    ///
    /// The canonical `graph.kndb` file is only a compatibility projection and
    /// may legitimately be absent after a crash that follows the authority
    /// commit. Callers deciding whether a repository has persisted graph truth
    /// must therefore consider this sidecar too; [`SnapshotManager::open`]
    /// performs the full validation before serving it.
    pub fn local_authority_exists(path: impl Into<PathBuf>) -> bool {
        let path = normalize_snapshot_path(path.into());
        local_authority_path(&path).exists()
    }

    fn cleanup_superseded_versions_under_exclusive_lock(path: &Path) {
        let result = read_local_authority_manifest(path).and_then(|authority| {
            let Some(authority) = authority else {
                return Ok(());
            };
            clear_superseded_local_snapshots(path, authority.snapshot_generation)
        });
        if let Err(error) = result {
            tracing::warn!(
                path = %path.display(),
                error = %error,
                "deferred superseded local snapshot cleanup"
            );
        }
    }

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

    /// Acquire the write lock for a one-shot static persistence operation.
    /// Unlike `open`, static writes wait for the current reader/writer to
    /// finish so two independent processes serialize the complete read-CAS-
    /// write interval instead of racing on the same immutable generation.
    fn acquire_static_write_lock(path: &Path) -> Result<File, KinDbError> {
        let lock_path = path.with_extension("lock");
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to create directory for lock file {}: {error}",
                    parent.display()
                ))
            })?;
        }
        let lock_file = File::create(&lock_path).map_err(|error| {
            KinDbError::LockError(format!(
                "failed to create lock file {}: {error}",
                lock_path.display()
            ))
        })?;
        lock_file.lock_exclusive().map_err(|error| {
            KinDbError::LockError(format!(
                "failed to acquire exclusive lock on {}: {error}",
                lock_path.display()
            ))
        })?;
        Ok(lock_file)
    }

    fn graph_from_snapshot(
        snapshot: crate::storage::GraphSnapshot,
        text_index_path: Option<&PathBuf>,
        read_only: bool,
        skip_text_index: bool,
        persisted_root_hash: Option<[u8; 32]>,
    ) -> (InMemoryGraph, [u8; 32]) {
        let _span = tracing::info_span!(
            "kindb.snapshot.graph_from_snapshot",
            persistent_text_index = text_index_path.is_some(),
            read_only = read_only,
            skip_text_index = skip_text_index
        )
        .entered();
        let graph_root_hash = match persisted_root_hash {
            Some(root_hash) => {
                let _span = tracing::info_span!("kindb.snapshot.use_persisted_root_hash").entered();
                root_hash
            }
            None => {
                let _span = tracing::info_span!("kindb.snapshot.compute_graph_root_hash").entered();
                compute_graph_root_hash(&snapshot)
            }
        };
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
            None => {
                if skip_text_index {
                    InMemoryGraph::from_snapshot_without_text_index_with_root_hash(
                        snapshot,
                        graph_root_hash,
                    )
                } else {
                    InMemoryGraph::from_snapshot_with_root_hash(snapshot, graph_root_hash)
                }
            }
        };
        (graph, graph_root_hash)
    }

    fn graph_from_locate_snapshot(
        snapshot: crate::storage::format::LocateGraphSnapshot,
        text_index_path: Option<&PathBuf>,
        persisted_root_hash: Option<[u8; 32]>,
    ) -> (InMemoryGraph, [u8; 32]) {
        let graph_root_hash = persisted_root_hash.unwrap_or_else(|| {
            let snapshot_for_hash: crate::storage::GraphSnapshot = snapshot.clone().into();
            compute_graph_root_hash(&snapshot_for_hash)
        });
        let graph = crate::engine::InMemoryGraph::from_locate_snapshot_read_only(
            snapshot,
            text_index_path.cloned(),
            graph_root_hash,
        );
        (graph, graph_root_hash)
    }

    fn load_locate_cache(
        snapshot_path: &Path,
        expected_root_hash: [u8; 32],
    ) -> Result<Option<crate::storage::format::LocateGraphSnapshot>, KinDbError> {
        let cache_path = locate_cache_path_for(snapshot_path);
        if !cache_path.exists() {
            return Ok(None);
        }

        let bytes = std::fs::read(&cache_path).map_err(|err| {
            KinDbError::StorageError(format!(
                "failed to read locate cache {}: {err}",
                cache_path.display()
            ))
        })?;
        let cache: LocateSnapshotCache = rmp_serde::from_slice(&bytes).map_err(|err| {
            KinDbError::StorageError(format!(
                "failed to decode locate cache {}: {err}",
                cache_path.display()
            ))
        })?;
        if cache.version != LOCATE_CACHE_VERSION || cache.root_hash != expected_root_hash {
            return Ok(None);
        }
        Ok(Some(cache.snapshot))
    }

    fn store_locate_cache(
        snapshot_path: &Path,
        root_hash: [u8; 32],
        snapshot: &crate::storage::format::LocateGraphSnapshot,
    ) -> Result<(), KinDbError> {
        let cache_path = locate_cache_path_for(snapshot_path);
        let cache = LocateSnapshotCache {
            version: LOCATE_CACHE_VERSION,
            root_hash,
            snapshot: snapshot.clone(),
        };
        let bytes = rmp_serde::to_vec(&cache).map_err(|err| {
            KinDbError::StorageError(format!(
                "failed to encode locate cache {}: {err}",
                cache_path.display()
            ))
        })?;
        mmap::atomic_write_bytes_no_magic(&cache_path, &bytes)
    }

    #[cfg(feature = "vector")]
    fn save_vector_index_bundle(
        path: &Path,
        graph: &InMemoryGraph,
        graph_root_hash: [u8; 32],
        embedder_identity: Option<&str>,
    ) -> Result<(), KinDbError> {
        let vector_path = vector_index_path_for(path);

        let (provider, model_id, revision, pipeline_epoch, runtime_dimensions) =
            current_embedding_runtime_fields();

        // Stamp the index's self-description (model identity + graph provenance)
        // BEFORE saving, so the persisted `.kvec` proves its own compatibility on
        // load — defense-in-depth alongside the sidecar metadata below.
        graph.stamp_vector_index_descriptor(crate::vector::IndexDescriptor {
            model_id: model_id.clone(),
            graph_root: Some(hex::encode(graph_root_hash)),
        });
        graph.save_vector_index(&vector_path)?;

        let metadata_path = vector_index_metadata_path_for(path);
        if let Some((dimensions, indexed)) = graph.vector_index_stats() {
            let metadata = VectorIndexMetadata {
                version: VectorIndexMetadata::VERSION,
                graph_root_hash: hex::encode(graph_root_hash),
                dimensions: runtime_dimensions.unwrap_or(dimensions),
                indexed,
                embedding_provider: provider,
                embedding_model_id: model_id,
                embedding_model_revision: revision,
                embedding_pipeline_epoch: pipeline_epoch,
                embedder_identity: embedder_identity.map(str::to_owned),
            };
            write_vector_index_metadata(&metadata_path, &metadata)?;
        }
        // When `vector_index_stats()` is `None` the index is not loaded for this
        // graph; the sidecar bytes are preserved by `save_vector_index`, so the
        // matching metadata is preserved alongside them rather than deleted. A
        // metadata file whose root hash no longer matches is rejected on the
        // next load, not destroyed here.

        Ok(())
    }

    #[cfg(feature = "vector")]
    fn invalidate_vector_index_metadata(path: &Path) -> Result<(), KinDbError> {
        let metadata_path = vector_index_metadata_path_for(path);
        let Some(mut metadata) = read_vector_index_metadata(&metadata_path)? else {
            return Ok(());
        };
        metadata.graph_root_hash = hex::encode([0u8; 32]);
        write_vector_index_metadata(&metadata_path, &metadata)
    }

    #[cfg(not(feature = "vector"))]
    fn invalidate_vector_index_metadata(_path: &Path) -> Result<(), KinDbError> {
        Ok(())
    }

    /// Prepare sidecars before committing a detached full-snapshot authority.
    /// A valid root stamp is written only while `epoch` still fences the exact
    /// captured graph. If a later mutation exists, the sidecar is preserved but
    /// deliberately invalidated so reopen rebuilds from authority.
    pub fn persist_snapshot_sidecars_for_epoch(
        path: &Path,
        graph: &InMemoryGraph,
        graph_root_hash: [u8; 32],
        epoch: PersistenceEpoch,
    ) -> Result<(), KinDbError> {
        let exact = graph.persist_derived_sidecars_for_epoch(epoch, graph_root_hash, || {
            #[cfg(feature = "vector")]
            {
                Self::save_vector_index_bundle(path, graph, graph_root_hash, None)
            }
            #[cfg(not(feature = "vector"))]
            {
                Ok(())
            }
        })?;
        if !exact {
            graph.invalidate_persisted_text_index()?;
            Self::invalidate_vector_index_metadata(path)?;
        }
        Ok(())
    }

    /// Invalidate local derived-sidecar root stamps before committing a graph
    /// delta whose exact index batch is not available. This is intentionally
    /// fallible before authority commit; a failure forces a full retry.
    pub fn invalidate_derived_sidecars(
        path: impl Into<PathBuf>,
        graph: &InMemoryGraph,
    ) -> Result<(), KinDbError> {
        let path = normalize_snapshot_path(path.into());
        graph.invalidate_persisted_text_index()?;
        Self::invalidate_vector_index_metadata(&path)
    }

    /// Load the persisted vector-index sidecar for `path` into `graph` only if
    /// its metadata still matches graph truth (root hash + embedding
    /// provider/model/revision/epoch/dimensions, via
    /// [`vector_metadata_matches_graph`]). A stale sidecar is skipped, never
    /// installed, and — when `write_missing_metadata` is set — the missing
    /// entities/artifacts are queued for a clean rebuild.
    ///
    /// Returns `true` if a vector index was installed into the graph, `false`
    /// if nothing was loaded (no sidecar present, or it was rejected as stale).
    #[cfg(feature = "vector")]
    fn load_vector_index_if_valid(
        path: &Path,
        graph: &InMemoryGraph,
        graph_root_hash: [u8; 32],
        write_missing_metadata: bool,
        expected_embedder_identity: Option<&str>,
    ) -> Result<bool, KinDbError> {
        let vector_path = vector_index_path_for(path);
        if !vector_path.exists() {
            return Ok(false);
        }

        let metadata_path = vector_index_metadata_path_for(path);
        let metadata = read_vector_index_metadata(&metadata_path)?;
        let canonical_root_hash = graph.recompute_root_hash();
        let matched_root = metadata.as_ref().and_then(|m| {
            if vector_metadata_matches_graph(m, graph_root_hash, expected_embedder_identity) {
                Some(graph_root_hash)
            } else if vector_metadata_matches_graph(
                m,
                canonical_root_hash,
                expected_embedder_identity,
            ) {
                Some(canonical_root_hash)
            } else {
                None
            }
        });
        let should_load = matched_root.is_some();

        if std::env::var("KINDB_DEBUG_KVEC").is_ok() {
            eprintln!(
                "[KVEC-DBG] should_load={} matched_root={:?} stamp_root={:?} canonical_root={} passed_root={} meta_embedder={:?} expected_embedder={:?} meta_dims={:?} meta_model={:?}",
                should_load,
                matched_root.map(hex::encode),
                metadata.as_ref().map(|m| m.graph_root_hash.clone()),
                hex::encode(canonical_root_hash),
                hex::encode(graph_root_hash),
                metadata.as_ref().and_then(|m| m.embedder_identity.clone()),
                expected_embedder_identity,
                metadata.as_ref().map(|m| m.dimensions),
                metadata.as_ref().and_then(|m| m.embedding_model_id.clone()),
            );
        }

        if !should_load {
            // Sidecar/graph-root staleness is transient (the graph may reconcile
            // back, or a matching reopen may reuse these vectors). PRESERVE the
            // sidecar on disk — never move/delete graph-owned truth here (the
            // prepared-state kvec-drop regression) — just skip it and rebuild.
            tracing::warn!(
                path = %vector_path.display(),
                metadata = %metadata_path.display(),
                "skipping stale vector index because metadata no longer matches graph truth"
            );
            if write_missing_metadata {
                graph.queue_missing_for_embedding();
                graph.queue_missing_artifacts_for_embedding();
            }
            return Ok(false);
        }

        // Defense-in-depth against silently-wrong neighbors: verify the index's
        // OWN model self-description. Catches a same-dimension MODEL swap the
        // sidecar can miss. Also passes graph_root so a positively-declared root
        // mismatch is caught here too. Grandfathering via
        // `load_vector_index_compatible` (which uses `load_compatible_grandfathered`
        // internally) means an UNSTAMPED legacy index (graph_root=None) is still
        // allowed — it cannot prove a mismatch and pre-stamp repos must load.
        let (_, runtime_model_id, _, _, _) = current_embedding_runtime_fields();
        let expected = crate::vector::IndexDescriptor {
            model_id: runtime_model_id,
            graph_root: matched_root.map(hex::encode),
        };

        let count = match graph.load_vector_index_compatible(&vector_path, &expected) {
            crate::vector::VectorIndexLoad::Loaded(count) => count,
            crate::vector::VectorIndexLoad::Incompatible(reason) => {
                tracing::warn!(
                    path = %vector_path.display(),
                    reason = %reason,
                    "LOUD WARNING: archiving incompatible vector index (index declares a different embedding model) and rebuilding"
                );
                archive_incompatible_index(&vector_path, &metadata_path);
                if write_missing_metadata {
                    graph.queue_missing_for_embedding();
                    graph.queue_missing_artifacts_for_embedding();
                }
                return Ok(false);
            }
        };

        // Generation eviction: the root-hash gate accepts a sidecar whose entity
        // content matches even when its revision keys were minted under a prior
        // (re-init) change id. Those keys are now orphans — drop them so the
        // installed index reflects only current graph truth and stale
        // generations stop competing in ANN retrieval.
        let evicted = graph.prune_orphaned_vectors();
        if evicted > 0 {
            tracing::info!(
                path = %vector_path.display(),
                evicted,
                "evicted orphaned-generation vectors after loading sidecar"
            );
        }

        if metadata.is_none() && write_missing_metadata {
            if let Some((dimensions, indexed)) = graph.vector_index_stats() {
                let (provider, model_id, revision, pipeline_epoch, runtime_dimensions) =
                    current_embedding_runtime_fields();
                let metadata = VectorIndexMetadata {
                    version: VectorIndexMetadata::VERSION,
                    graph_root_hash: hex::encode(graph_root_hash),
                    dimensions: runtime_dimensions.unwrap_or(dimensions),
                    indexed,
                    embedding_provider: provider,
                    embedding_model_id: model_id,
                    embedding_model_revision: revision,
                    embedding_pipeline_epoch: pipeline_epoch,
                    // No embedder_identity in this repair path — the daemon
                    // caller writes the authoritative sidecar via
                    // save_vector_index_for_graph.
                    embedder_identity: None,
                };
                write_vector_index_metadata(&metadata_path, &metadata)?;
            }
        } else if count == 0 {
            tracing::debug!(path = %vector_path.display(), "vector index metadata matched but index was empty");
        }

        Ok(true)
    }

    /// Validate and load a persisted vector-index sidecar into `graph` — the
    /// sanctioned public alternative to a raw `graph.load_vector_index(path)`.
    ///
    /// # Contract for out-of-process callers (e.g. the daemon)
    ///
    /// A raw `graph.load_vector_index(path)` installs whatever bytes are on disk
    /// **unconditionally**, including a sidecar whose embedding dimension/model
    /// no longer matches the live graph and embedder. Installing a stale index
    /// is exactly what triggers the embed-worker dimension loop (the in-memory
    /// `get_vector_index` self-heal then resets and rebuilds it from scratch on
    /// the next embed pass — wasted work at best, a CPU-pinning loop at worst).
    ///
    /// This entry point instead validates the sidecar against graph truth before
    /// installing it, using the graph's own recorded root hash
    /// ([`InMemoryGraph::snapshot_root_hash`]) plus the live embedding
    /// provider/model/revision/epoch/dimensions. It returns `Ok(true)` if a
    /// valid index was installed and `Ok(false)` if nothing was loaded (no
    /// sidecar, a stale sidecar, or a graph with no recorded root hash to
    /// validate against).
    ///
    /// `snapshot_path` is the `.kndb` snapshot path (the same value passed to
    /// [`SnapshotManager::open`]); the `.kvec` / `.kvec.meta.json` sidecar paths
    /// are derived from it. Note that [`SnapshotManager::open`] and
    /// `open_read_only_for_locate` already perform this validated load during
    /// graph construction, so a separate post-open call is only needed for code
    /// paths that build a graph without going through `SnapshotManager` — and it
    /// must replace, not supplement, any unchecked `load_vector_index` call.
    /// **Follow-up wiring:** the kin daemon's post-open vector load path must
    /// pass `Some(kin_binary_sha256)` as `expected_embedder_identity` once
    /// `save_vector_index_for_graph` is updated to supply the identity on
    /// write. Until then `None` is non-breaking (legacy warn+load).
    #[cfg(feature = "vector")]
    pub fn load_vector_index_into_graph_if_valid(
        graph: &InMemoryGraph,
        snapshot_path: &Path,
        expected_embedder_identity: Option<&str>,
    ) -> Result<bool, KinDbError> {
        let Some(graph_root_hash) = graph.snapshot_root_hash() else {
            tracing::warn!(
                path = %snapshot_path.display(),
                "skipping vector index load: graph has no recorded root hash to validate the sidecar against"
            );
            return Ok(false);
        };
        Self::load_vector_index_if_valid(
            snapshot_path,
            graph,
            graph_root_hash,
            false,
            expected_embedder_identity,
        )
    }

    /// Feature-disabled stub: with no vector backend there is nothing to load.
    #[cfg(not(feature = "vector"))]
    pub fn load_vector_index_into_graph_if_valid(
        _graph: &InMemoryGraph,
        _snapshot_path: &Path,
        _expected_embedder_identity: Option<&str>,
    ) -> Result<bool, KinDbError> {
        Ok(false)
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
            generation: AtomicU64::new(GENERATION_INIT),
        }
    }

    /// Short hex fingerprint of a Merkle root, used in quarantine file names
    /// and verify-on-read diagnostics.
    fn root_hash_tag(hash: [u8; 32]) -> String {
        hash.iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Compare a freshly loaded graph against its persisted Merkle commitment.
    ///
    /// Returns `Some((committed, actual))` when the graph's recomputed content
    /// root does not match the committed root (corruption), or `None` when it
    /// matches or there is no commitment to verify against. The recomputed root
    /// is read from the Merkle cache the load already built, so a clean read
    /// costs only the comparison.
    fn graph_truth_corruption(
        graph: &InMemoryGraph,
        persisted_root_hash: Option<[u8; 32]>,
    ) -> Option<([u8; 32], [u8; 32])> {
        let committed = persisted_root_hash?;
        let actual = graph.compute_root_hash();
        (actual != committed).then_some((committed, actual))
    }

    /// Quarantine a corrupt primary snapshot and self-heal from the recovery
    /// candidate, mirroring the corrupt-object quarantine kin-blobs performs on
    /// a failed verify-on-read. Fails loud when no trustworthy redundant copy
    /// exists rather than serving corrupt graph truth.
    fn quarantine_and_heal_graph_truth(
        path: &Path,
        committed_root: [u8; 32],
        actual_root: [u8; 32],
        text_index_path: Option<&PathBuf>,
        read_only: bool,
        skip_text_index: bool,
    ) -> Result<(InMemoryGraph, [u8; 32]), KinDbError> {
        if read_only {
            return Err(KinDbError::StorageError(format!(
                "graph snapshot {} failed verify-on-read (content root {} != committed root {}); \
                 refusing to self-heal under a shared read-only lock",
                path.display(),
                Self::root_hash_tag(actual_root),
                Self::root_hash_tag(committed_root)
            )));
        }
        let quarantined =
            mmap::quarantine_corrupt_snapshot(path, &Self::root_hash_tag(actual_root))?;
        tracing::warn!(
            path = %path.display(),
            quarantined = %quarantined.display(),
            "quarantined corrupt graph snapshot; healing from recovery candidate"
        );
        let cause = KinDbError::StorageError(format!(
            "graph snapshot {} failed verify-on-read: content root {} does not match committed root {}",
            path.display(),
            Self::root_hash_tag(actual_root),
            Self::root_hash_tag(committed_root)
        ));
        Self::recover_graph_from_tmp(
            path,
            Some(&cause),
            text_index_path,
            read_only,
            skip_text_index,
        )
    }

    fn recover_graph_from_tmp(
        path: &Path,
        primary_error: Option<&KinDbError>,
        text_index_path: Option<&PathBuf>,
        read_only: bool,
        skip_text_index: bool,
    ) -> Result<(InMemoryGraph, [u8; 32]), KinDbError> {
        let _span = tracing::info_span!(
            "kindb.snapshot.recover_graph_from_tmp",
            path = %path.display(),
            read_only = read_only,
            skip_text_index = skip_text_index
        )
        .entered();
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

        let (snapshot, persisted_root_hash) =
            mmap::load_recovery_candidate_with_persisted_root_hash(path).map_err(|tmp_err| {
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

        // Verify the recovery candidate against its own Merkle commitment before
        // promoting it. Healing must never replace a corrupt primary with an
        // equally corrupt recovery copy.
        if let Some(committed_root) = persisted_root_hash {
            let actual_root = compute_graph_root_hash(&snapshot);
            if actual_root != committed_root {
                return Err(KinDbError::StorageError(format!(
                    "recovery snapshot {} failed verify-on-read: content root {} does not match committed root {}",
                    tmp_path.display(),
                    Self::root_hash_tag(actual_root),
                    Self::root_hash_tag(committed_root)
                )));
            }
        }

        mmap::promote_recovery_candidate(path).map_err(|err| {
            KinDbError::StorageError(format!(
                "loaded recovery snapshot {} but failed to promote it to {}: {err}",
                tmp_path.display(),
                path.display()
            ))
        })?;

        let (snapshot, persisted_root_hash, _, _) =
            apply_local_deltas(path, snapshot, persisted_root_hash, None)?;

        Ok(Self::graph_from_snapshot(
            snapshot,
            text_index_path,
            read_only,
            skip_text_index,
            persisted_root_hash,
        ))
    }

    fn open_graph(
        path: &Path,
        text_index_path: Option<&PathBuf>,
        read_only: bool,
        skip_text_index: bool,
    ) -> Result<(InMemoryGraph, Generation), KinDbError> {
        let _span = tracing::info_span!(
            "kindb.snapshot.open_graph",
            path = %path.display(),
            persistent_text_index = text_index_path.is_some(),
            read_only = read_only,
            skip_text_index = skip_text_index
        )
        .entered();
        let authority = read_local_authority_manifest(path)?;
        let authoritative = authority.is_some();
        let generation = authority
            .as_ref()
            .map(|authority| authority.head_generation)
            .unwrap_or(if path.exists() {
                legacy_generation_hint(path)?
            } else {
                GENERATION_INIT
            });
        let read_path = authority
            .as_ref()
            .map(|authority| {
                local_snapshot_versions_dir(path).join(authority.snapshot_file.as_str())
            })
            .unwrap_or_else(|| path.to_path_buf());

        let (graph, graph_root_hash) = if read_path.exists() {
            match {
                let _span = tracing::info_span!("kindb.snapshot.open_mmap").entered();
                mmap::MmapReader::open_with_persisted_root_hash(&read_path)
            } {
                Ok(snapshot) => {
                    if let Some(authority) = authority.as_ref() {
                        validate_authoritative_base_snapshot(
                            &read_path,
                            authority,
                            &snapshot.0,
                            snapshot.1,
                        )?;
                    }
                    let (snapshot, persisted_root_hash, delta_count, recovered_generation) =
                        apply_local_deltas(path, snapshot.0, snapshot.1, authority.as_ref())?;
                    if recovered_generation != generation {
                        return Err(KinDbError::StorageError(format!(
                            "local recovery generation changed while opening {}: expected {generation}, found {recovered_generation}",
                            path.display()
                        )));
                    }
                    if delta_count > 0 {
                        tracing::info!(
                            path = %path.display(),
                            delta_count,
                            "replayed local snapshot deltas on open"
                        );
                    }
                    let (graph, graph_root_hash) = Self::graph_from_snapshot(
                        snapshot,
                        text_index_path,
                        read_only,
                        skip_text_index,
                        persisted_root_hash,
                    );
                    // Verify-on-read: the load already recomputed the Merkle root
                    // from entity/relation content, so confirm it matches the
                    // committed root before serving. On mismatch, quarantine and
                    // self-heal rather than handing back corrupt graph truth.
                    match Self::graph_truth_corruption(&graph, persisted_root_hash) {
                        None => Ok((graph, graph_root_hash)),
                        Some((committed_root, actual_root)) => {
                            if authoritative {
                                return Err(KinDbError::StorageError(format!(
                                    "authoritative local snapshot {} failed graph-root verification: committed {}, actual {}",
                                    read_path.display(),
                                    Self::root_hash_tag(committed_root),
                                    Self::root_hash_tag(actual_root)
                                )));
                            }
                            drop(graph);
                            Self::quarantine_and_heal_graph_truth(
                                &read_path,
                                committed_root,
                                actual_root,
                                text_index_path,
                                read_only,
                                skip_text_index,
                            )
                        }
                    }
                }
                Err(err) if authoritative => Err(KinDbError::StorageError(format!(
                    "failed to open authoritative local snapshot {}: {err}",
                    read_path.display()
                ))),
                Err(err) => Self::recover_graph_from_tmp(
                    &read_path,
                    Some(&err),
                    text_index_path,
                    read_only,
                    skip_text_index,
                ),
            }
        } else {
            if authoritative {
                return Err(KinDbError::StorageError(format!(
                    "authoritative local snapshot {} is missing",
                    read_path.display()
                )));
            }
            let tmp_path = mmap::recovery_tmp_path(&read_path);
            if tmp_path.exists() {
                Self::recover_graph_from_tmp(
                    &read_path,
                    None,
                    text_index_path,
                    read_only,
                    skip_text_index,
                )
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
            Self::load_vector_index_if_valid(path, &graph, graph_root_hash, !read_only, None)?;
        }

        if authoritative && !read_only {
            let recovery_tmp = mmap::recovery_tmp_path(path);
            let recovery_marker = mmap::recovery_marker_path(path);
            let snapshot_generation = authority
                .as_ref()
                .expect("authoritative branch has a manifest")
                .snapshot_generation;
            if local_projection_generation(path) != Some(snapshot_generation)
                || !path.exists()
                || recovery_tmp.exists()
                || recovery_marker.exists()
            {
                let projection_source = std::fs::read(&read_path).map_err(|error| {
                    KinDbError::StorageError(format!(
                        "failed to read authoritative snapshot projection source {}: {error}",
                        read_path.display()
                    ))
                })?;
                if let Err(error) = mmap::atomic_write_bytes(path, &projection_source) {
                    tracing::warn!(
                        path = %path.display(),
                        error = %error,
                        "failed to heal canonical snapshot compatibility projection"
                    );
                } else if let Err(error) =
                    write_local_projection_generation(path, snapshot_generation)
                {
                    tracing::warn!(
                        path = %path.display(),
                        error = %error,
                        "failed to stamp canonical snapshot compatibility projection"
                    );
                }
            }
        }

        Ok((graph, generation))
    }

    fn open_graph_for_locate(
        path: &Path,
        text_index_path: Option<&PathBuf>,
    ) -> Result<(InMemoryGraph, Generation), KinDbError> {
        let _span = tracing::info_span!(
            "kindb.snapshot.open_graph_for_locate",
            path = %path.display(),
            persistent_text_index = text_index_path.is_some()
        )
        .entered();
        let authority = read_local_authority_manifest(path)?;
        if (path.exists() || authority.is_some()) && local_delta_count(path)? > 0 {
            tracing::info!(
                path = %path.display(),
                "bypassing locate cache because local snapshot deltas are pending"
            );
            return Self::open_graph(path, text_index_path, true, false);
        }
        let generation = authority
            .as_ref()
            .map(|authority| authority.head_generation)
            .unwrap_or(if path.exists() {
                legacy_generation_hint(path)?
            } else {
                GENERATION_INIT
            });
        let read_path = authority
            .as_ref()
            .map(|authority| {
                local_snapshot_versions_dir(path).join(authority.snapshot_file.as_str())
            })
            .unwrap_or_else(|| path.to_path_buf());
        let authority_root_hash = authority
            .as_ref()
            .map(local_authority_root_hash)
            .transpose()?;
        let authoritative = authority.is_some();
        let (graph, graph_root_hash) = if read_path.exists() {
            let hinted_root_hash =
                mmap::MmapReader::read_persisted_root_hash_unverified(&read_path)?;
            if let Some(expected_root_hash) = authority_root_hash {
                if hinted_root_hash != Some(expected_root_hash) {
                    return Err(KinDbError::StorageError(format!(
                        "authoritative local locate snapshot {} root trailer does not match authority {}",
                        read_path.display(),
                        hex::encode(expected_root_hash)
                    )));
                }
            }
            if let Some(root_hash) = hinted_root_hash {
                if let Some(snapshot) = Self::load_locate_cache(path, root_hash)? {
                    let _span = tracing::info_span!("kindb.snapshot.use_locate_cache").entered();
                    let (graph, graph_root_hash) = Self::graph_from_locate_snapshot(
                        snapshot,
                        text_index_path,
                        Some(root_hash),
                    );
                    #[cfg(feature = "vector")]
                    {
                        Self::load_vector_index_if_valid(
                            path,
                            &graph,
                            graph_root_hash,
                            false,
                            None,
                        )?;
                    }
                    return Ok((graph, generation));
                }
            }
            match {
                let _span = tracing::info_span!("kindb.snapshot.open_locate_mmap").entered();
                mmap::MmapReader::open_for_locate_with_persisted_root_hash(&read_path)
            } {
                Ok((snapshot, persisted_root_hash)) => {
                    if let Some(expected_root_hash) = authority_root_hash {
                        if persisted_root_hash != Some(expected_root_hash) {
                            return Err(KinDbError::StorageError(format!(
                                "authoritative local locate snapshot {} root does not match authority {}",
                                read_path.display(),
                                hex::encode(expected_root_hash)
                            )));
                        }
                    }
                    let cache_root_hash = persisted_root_hash.or(hinted_root_hash).or_else(|| {
                        let snapshot_for_hash: crate::storage::GraphSnapshot =
                            snapshot.clone().into();
                        Some(compute_graph_root_hash(&snapshot_for_hash))
                    });
                    if locate_cache_write_enabled() {
                        if let Some(root_hash) = cache_root_hash {
                            let _ = Self::store_locate_cache(path, root_hash, &snapshot);
                        }
                    }
                    Ok(Self::graph_from_locate_snapshot(
                        snapshot,
                        text_index_path,
                        cache_root_hash,
                    ))
                }
                Err(err) if authoritative => Err(KinDbError::StorageError(format!(
                    "failed to open authoritative local locate snapshot {}: {err}",
                    read_path.display()
                ))),
                Err(err) => Self::recover_graph_from_tmp(
                    &read_path,
                    Some(&err),
                    text_index_path,
                    true,
                    false,
                ),
            }
        } else {
            match text_index_path {
                Some(p) => Ok((InMemoryGraph::with_text_index(p.clone()), [0u8; 32])),
                None => Ok((InMemoryGraph::new(), [0u8; 32])),
            }
        }?;

        #[cfg(feature = "vector")]
        {
            Self::load_vector_index_if_valid(path, &graph, graph_root_hash, false, None)?;
        }

        Ok((graph, generation))
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
        let (graph, generation) = Self::open_graph(&path, ti_path.as_ref(), false, false)?;
        Self::cleanup_superseded_versions_under_exclusive_lock(&path);

        Ok(Self {
            path,
            text_index_path: ti_path,
            current: RwLock::new(Arc::new(graph)),
            _lock_file: Some(lock_file),
            read_only: false,
            generation: AtomicU64::new(generation),
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
        let (graph, generation) = Self::open_graph(&path, None, false, true)?;
        Self::cleanup_superseded_versions_under_exclusive_lock(&path);

        Ok(Self {
            path,
            text_index_path: None,
            current: RwLock::new(Arc::new(graph)),
            _lock_file: Some(lock_file),
            read_only: false,
            generation: AtomicU64::new(generation),
        })
    }

    /// Open an existing snapshot in read-only mode, allowing multiple shared
    /// readers while still excluding concurrent writers.
    pub fn open_read_only(path: impl Into<PathBuf>) -> Result<Self, KinDbError> {
        let path = normalize_snapshot_path(path.into());
        let lock_file = Self::acquire_lock(&path, true)?;
        let ti_path = text_index_dir_for(&path);
        let (graph, generation) = Self::open_graph(&path, ti_path.as_ref(), true, false)?;

        Ok(Self {
            path,
            text_index_path: ti_path,
            current: RwLock::new(Arc::new(graph)),
            _lock_file: Some(lock_file),
            read_only: true,
            generation: AtomicU64::new(generation),
        })
    }

    /// Open an existing snapshot in read-only locate mode.
    ///
    /// This uses a lightweight decoder that skips persisted adjacency lists
    /// and non-locate domains before reconstructing the in-memory indexes.
    /// It is intended for cold-start-heavy retrieval flows where locate only
    /// needs entity/relation truth plus artifact metadata and changes.
    pub fn open_read_only_for_locate(path: impl Into<PathBuf>) -> Result<Self, KinDbError> {
        let path = normalize_snapshot_path(path.into());
        let lock_file = Self::acquire_lock(&path, true)?;
        let ti_path = text_index_dir_for(&path);
        let (graph, generation) = Self::open_graph_for_locate(&path, ti_path.as_ref())?;

        Ok(Self {
            path,
            text_index_path: ti_path,
            current: RwLock::new(Arc::new(graph)),
            _lock_file: Some(lock_file),
            read_only: true,
            generation: AtomicU64::new(generation),
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
            generation: AtomicU64::new(GENERATION_INIT),
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

    /// Last generation acknowledged by the local base/head authority.
    pub fn generation(&self) -> Generation {
        self.generation.load(Ordering::Acquire)
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
        let (root_hash, generation) = if self._lock_file.is_some() {
            Self::save_graph_with_hash_and_generation_under_exclusive_lock(
                &self.path,
                graph.as_ref(),
                None,
                Some(self.generation()),
                None,
            )?
        } else {
            Self::save_graph_with_hash_and_generation(&self.path, graph.as_ref(), None)?
        };
        self.generation.store(generation, Ordering::Release);
        if self._lock_file.is_some() {
            Self::cleanup_superseded_versions_under_exclusive_lock(&self.path);
        }
        Ok(root_hash)
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

    /// Persist a full snapshot and return both its root and acknowledged local
    /// generation. Callers that publish a generation marker must use this
    /// result rather than guessing from process-local state.
    pub fn save_graph_with_generation(
        path: impl Into<PathBuf>,
        graph: &InMemoryGraph,
    ) -> Result<(crate::storage::merkle::MerkleHash, Generation), KinDbError> {
        Self::save_graph_with_hash_and_generation(path, graph, None)
    }

    /// Persist a full snapshot only if `expected_generation` is still the
    /// acknowledged local head. The OS lock covers the authority read through
    /// commit, so this is the one-shot static CAS entry point for callers that
    /// retain a generation cursor without retaining a `SnapshotManager`.
    pub fn save_graph_with_expected_generation(
        path: impl Into<PathBuf>,
        graph: &InMemoryGraph,
        expected_generation: Generation,
    ) -> Result<(crate::storage::merkle::MerkleHash, Generation), KinDbError> {
        let path = normalize_snapshot_path(path.into());
        let _lock_file = Self::acquire_static_write_lock(&path)?;
        let result = Self::save_graph_with_hash_and_generation_under_exclusive_lock(
            &path,
            graph,
            None,
            Some(expected_generation),
            None,
        )?;
        Self::cleanup_superseded_versions_under_exclusive_lock(&path);
        Ok(result)
    }

    /// Like [`save_graph`] but accepts a pre-computed Merkle root hash.
    /// When provided, the expensive root-hash traversal is skipped.
    pub fn save_graph_with_hash(
        path: impl Into<PathBuf>,
        graph: &InMemoryGraph,
        precomputed_hash: Option<crate::storage::merkle::MerkleHash>,
    ) -> Result<crate::storage::merkle::MerkleHash, KinDbError> {
        Self::save_graph_with_hash_and_generation(path, graph, precomputed_hash)
            .map(|(root_hash, _)| root_hash)
    }

    fn save_graph_with_hash_and_generation(
        path: impl Into<PathBuf>,
        graph: &InMemoryGraph,
        precomputed_hash: Option<crate::storage::merkle::MerkleHash>,
    ) -> Result<(crate::storage::merkle::MerkleHash, Generation), KinDbError> {
        let path = normalize_snapshot_path(path.into());
        let _lock_file = Self::acquire_static_write_lock(&path)?;
        let result = Self::save_graph_with_hash_and_generation_under_exclusive_lock(
            &path,
            graph,
            precomputed_hash,
            None,
            None,
        )?;
        Self::cleanup_superseded_versions_under_exclusive_lock(&path);
        Ok(result)
    }

    fn save_graph_with_hash_and_generation_under_exclusive_lock(
        path: &Path,
        graph: &InMemoryGraph,
        precomputed_hash: Option<crate::storage::merkle::MerkleHash>,
        expected_generation: Option<Generation>,
        captured_legacy_journal: Option<&[(Generation, PathBuf, Vec<u8>)]>,
    ) -> Result<(crate::storage::merkle::MerkleHash, Generation), KinDbError> {
        let _span = tracing::info_span!(
            "kindb.snapshot.save_graph_with_hash",
            path = %path.display(),
            precomputed_hash = precomputed_hash.is_some()
        )
        .entered();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to create directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        let current_authority = if captured_legacy_journal.is_some() {
            read_local_authority_manifest_raw(path)?
        } else {
            read_local_authority_manifest(path)?
        };
        let current_generation = match current_authority {
            Some(authority) => authority.head_generation,
            None => {
                let deltas = local_delta_files(path)?;
                if !deltas.is_empty() && captured_legacy_journal.is_none() {
                    return Err(KinDbError::StorageError(format!(
                        "local snapshot {} has an unbound journal; refusing full promotion",
                        path.display()
                    )));
                }
                if path.exists() {
                    legacy_generation_hint(path)?
                } else {
                    GENERATION_INIT
                }
            }
        };
        if expected_generation.is_some_and(|expected| expected != current_generation) {
            return Err(KinDbError::StorageError(format!(
                "local snapshot generation mismatch for {}: expected {}, found {current_generation}",
                path.display(),
                expected_generation.expect("checked above")
            )));
        }
        let generation_floor = captured_legacy_journal
            .and_then(|captured| captured.iter().map(|(generation, _, _)| *generation).max())
            .map_or(current_generation, |journal_head| {
                current_generation.max(journal_head)
            });
        let new_generation = generation_floor.checked_add(1).ok_or_else(|| {
            KinDbError::StorageError(format!(
                "local snapshot generation exhausted at {generation_floor}"
            ))
        })?;

        let t0 = std::time::Instant::now();
        let precomputed_hash = precomputed_hash.or_else(|| graph.snapshot_root_hash_hint());
        let (bytes, graph_root_hash, persistence_epoch) =
            graph.begin_snapshot_persistence(precomputed_hash)?;
        let persistence_attempt = PersistenceAttempt::new(graph, persistence_epoch);
        let t_ser = t0.elapsed();

        let t1 = std::time::Instant::now();
        let versioned_path = local_versioned_snapshot_path(path, new_generation);
        std::fs::create_dir_all(local_snapshot_versions_dir(path)).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to create local snapshot versions directory: {error}"
            ))
        })?;
        {
            let _span = tracing::info_span!("kindb.snapshot.save_graph.atomic_write").entered();
            mmap::atomic_write_bytes(&versioned_path, &bytes)?;
        }
        let t_write = t1.elapsed();

        let t2 = std::time::Instant::now();
        {
            let _span =
                tracing::info_span!("kindb.snapshot.save_graph.persist_text_index").entered();
            Self::persist_snapshot_sidecars_for_epoch(
                path,
                graph,
                graph_root_hash,
                persistence_epoch,
            )?;
        }
        let t_text = t2.elapsed();

        eprintln!(
            "[save_graph] serialize={:.1}s  atomic_write={:.1}s  text_index={:.1}s  total={:.1}s",
            t_ser.as_secs_f64(),
            t_write.as_secs_f64(),
            t_text.as_secs_f64(),
            t0.elapsed().as_secs_f64(),
        );

        let authority = LocalSnapshotAuthority {
            version: LOCAL_SNAPSHOT_AUTHORITY_VERSION,
            snapshot_generation: new_generation,
            head_generation: new_generation,
            snapshot_file: local_snapshot_file_name(new_generation),
            snapshot_root_hash: hex::encode(graph_root_hash),
        };
        write_local_authority(path, &authority)?;
        persistence_attempt.complete();

        // Compatibility projection and stale-journal cleanup are downstream of
        // the atomic authority commit. They must never make a committed save
        // look failed or leave the caller on the old generation.
        match mmap::atomic_write_bytes(path, &bytes) {
            Ok(()) => {
                if let Err(error) = write_local_projection_generation(path, new_generation) {
                    tracing::warn!(
                        path = %path.display(),
                        error = %error,
                        "failed to stamp canonical snapshot projection after authority commit"
                    );
                }
            }
            Err(error) => tracing::warn!(
                path = %path.display(),
                error = %error,
                "failed to refresh canonical snapshot projection after authority commit"
            ),
        }
        if captured_legacy_journal.is_none() {
            if let Err(error) = clear_local_deltas(path) {
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "snapshot authority committed; deferred stale local delta cleanup"
                );
            }
        }
        Ok((graph_root_hash, new_generation))
    }

    /// Rebuild a local snapshot from preserved pre-authority journal
    /// artifacts.
    ///
    /// The caller must quiesce every legacy writer and supply a graph already
    /// reconciled against the captured journal. Kin does not infer authority
    /// by replaying an unbound journal. The exact journal is captured under an
    /// OS lock, a durable rebuild marker is written, the full snapshot is CAS
    /// promoted, and only byte-identical captured deltas are then removed.
    /// Once authority commits, its generation is returned even when cleanup is
    /// deferred; the marker keeps normal opens fail-closed until a retry drains
    /// the remaining artifacts.
    pub fn rebuild_legacy_journal(
        path: impl Into<PathBuf>,
        graph: &InMemoryGraph,
        expected_generation: Generation,
    ) -> Result<(crate::storage::merkle::MerkleHash, Generation), KinDbError> {
        let path = normalize_snapshot_path(path.into());
        let _lock_file = Self::acquire_static_write_lock(&path)?;
        let current_generation = read_local_authority_manifest_raw(&path)?
            .map(|authority| authority.head_generation)
            .unwrap_or(if path.exists() {
                legacy_generation_hint(&path)?
            } else {
                GENERATION_INIT
            });
        if current_generation != expected_generation {
            return Err(KinDbError::StorageError(format!(
                "legacy journal rebuild generation mismatch for {}: expected {expected_generation}, found {current_generation}; quiesce old writers and reconcile again",
                path.display()
            )));
        }
        if !path.exists() && read_local_authority_manifest_raw(&path)?.is_none() {
            return Err(KinDbError::StorageError(format!(
                "local snapshot {} has no base snapshot to rebuild",
                path.display()
            )));
        }
        let captured = capture_local_deltas(&path)?;
        if captured.is_empty() {
            return Err(KinDbError::StorageError(format!(
                "local snapshot {} has no legacy journal to rebuild",
                path.display()
            )));
        }
        let captured_identity = local_delta_capture_identity(&captured);
        if local_delta_capture_identity(&capture_local_deltas(&path)?) != captured_identity {
            return Err(KinDbError::StorageError(format!(
                "legacy journal changed while rebuilding {}; authority was not committed",
                path.display()
            )));
        }
        let journal_head = captured
            .iter()
            .map(|(generation, _, _)| *generation)
            .max()
            .unwrap_or(expected_generation);
        let committed_generation = expected_generation
            .max(journal_head)
            .checked_add(1)
            .ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "local snapshot generation exhausted while rebuilding {}",
                    path.display()
                ))
            })?;
        let marker = LocalLegacyRebuildMarker {
            version: LOCAL_LEGACY_REBUILD_VERSION,
            expected_generation,
            committed_generation,
            captured_deltas: captured_identity,
        };
        let marker_bytes = serde_json::to_vec(&marker).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to encode local legacy rebuild marker: {error}"
            ))
        })?;
        mmap::atomic_write_bytes_no_magic(&local_legacy_rebuild_marker_path(&path), &marker_bytes)?;

        let result = Self::save_graph_with_hash_and_generation_under_exclusive_lock(
            &path,
            graph,
            None,
            Some(expected_generation),
            Some(&captured),
        )?;
        debug_assert_eq!(result.1, committed_generation);

        if clear_exact_captured_local_deltas(&path, &captured) {
            let marker_path = local_legacy_rebuild_marker_path(&path);
            if let Err(error) = std::fs::remove_file(&marker_path).and_then(|_| {
                File::open(marker_path.parent().unwrap_or(Path::new(".")))?.sync_all()
            }) {
                tracing::warn!(path = %marker_path.display(), error = %error, generation = result.1, "legacy rebuild committed; deferred rebuild-marker cleanup");
            }
        }
        Self::cleanup_superseded_versions_under_exclusive_lock(&path);
        Ok(result)
    }

    /// Append the graph's mutation-time delta to the local journal.
    ///
    /// This is the steady-state durability path between semantic commits. It
    /// never diffs the old snapshot against a cloned current graph; callers
    /// supply the current durable generation marker and the graph supplies the
    /// already-recorded mutation delta. If a full snapshot is required, or no
    /// base snapshot exists yet, this falls back to a full save/compaction.
    pub fn save_graph_delta(
        path: impl Into<PathBuf>,
        graph: &InMemoryGraph,
        base_generation: Generation,
    ) -> Result<Option<Generation>, KinDbError> {
        let path = normalize_snapshot_path(path.into());
        let _lock_file = Self::acquire_static_write_lock(&path)?;
        Self::save_graph_delta_under_exclusive_lock(&path, graph, base_generation)
    }

    fn save_graph_delta_under_exclusive_lock(
        path: &Path,
        graph: &InMemoryGraph,
        base_generation: Generation,
    ) -> Result<Option<Generation>, KinDbError> {
        if graph.full_snapshot_required()
            || (!path.exists() && read_local_authority_manifest(path)?.is_none())
        {
            let (_, generation) = Self::save_graph_with_hash_and_generation_under_exclusive_lock(
                path,
                graph,
                None,
                Some(base_generation),
                None,
            )?;
            return Ok(Some(generation));
        }

        let Some((delta, persistence_epoch)) = graph.begin_delta_persistence(base_generation)
        else {
            graph.flush_text_index()?;
            return Ok(None);
        };
        let persistence_attempt = PersistenceAttempt::new(graph, persistence_epoch);
        if delta.is_empty() {
            // No graph authority changes, so existing sidecar provenance stays
            // valid. Flush any staged live text without invalidating a vector
            // index that still describes the same committed graph root.
            graph.flush_text_index()?;
            persistence_attempt.complete();
            return Ok(None);
        }

        // Derived-index failure must happen before the durable delta commit;
        // after write_local_delta succeeds there are no remaining fallible
        // steps before the generation is returned to the caller.
        Self::invalidate_derived_sidecars(path, graph)?;
        let generation = write_local_delta(path, &delta, base_generation)?;
        persistence_attempt.complete();
        Ok(Some(generation))
    }

    /// Persist the current manager's mutation journal while reusing the
    /// exclusive lock held by `open`. This is the instance counterpart to the
    /// lock-taking static [`save_graph_delta`](Self::save_graph_delta).
    pub fn save_delta(&self) -> Result<Option<Generation>, KinDbError> {
        if self.read_only {
            return Err(KinDbError::LockError(format!(
                "snapshot {} was opened read-only and cannot be saved",
                self.path.display()
            )));
        }
        let graph = self.graph();
        let result = if self._lock_file.is_some() {
            Self::save_graph_delta_under_exclusive_lock(
                &self.path,
                graph.as_ref(),
                self.generation(),
            )?
        } else {
            Self::save_graph_delta(&self.path, graph.as_ref(), self.generation())?
        };
        if let Some(generation) = result {
            self.generation.store(generation, Ordering::Release);
        }
        Ok(result)
    }

    /// Persist the vector sidecar and matching metadata for a live graph.
    ///
    /// This is intended for daemon background embedding work that updates the
    /// vector index without performing a full snapshot write on every batch.
    ///
    /// `embedder_identity` is an optional caller-supplied string that uniquely
    /// identifies the embedder binary/artifact (e.g. a build SHA). When
    /// `Some`, it is stored in the sidecar and enforced on the next load —
    /// a mismatch rejects the cached vectors so that an embedder change that
    /// leaves `model+epoch` unchanged cannot silently serve stale vectors.
    /// Pass `None` for legacy callers that do not yet supply an identity.
    ///
    /// **Follow-up wiring:** the kin daemon's embed-worker must be updated to
    /// pass `Some(kin_binary_sha256)` (or equivalent build id) as
    /// `embedder_identity`. Until that wiring lands, `None` is accepted and
    /// triggers a legacy-store warning on load (non-breaking).
    #[cfg(feature = "vector")]
    pub fn save_vector_index_for_graph(
        path: impl Into<PathBuf>,
        graph: &InMemoryGraph,
        embedder_identity: Option<&str>,
    ) -> Result<(), KinDbError> {
        let path = normalize_snapshot_path(path.into());
        let graph_root_hash = graph.compute_root_hash();
        Self::save_vector_index_bundle(&path, graph, graph_root_hash, embedder_identity)
    }

    /// Durably persist one batch of embed progress incrementally, so a long
    /// embed that is interrupted resumes from the last flushed batch instead of
    /// restarting from zero.
    ///
    /// This is the per-batch flush primitive the daemon's embed worker should
    /// call (replacing a periodic full `save`/`save_graph`, which re-serializes
    /// the whole graph — O(graph size) — on every tick and is what kills the
    /// daemon on a ~1 GB graph). It composes the two existing incremental
    /// primitives without ever taking a full-graph clone on the hot path:
    ///
    /// 1. [`save_graph_delta`](Self::save_graph_delta) appends only the graph
    ///    mutations recorded since `base_generation` (e.g. concurrent LSP
    ///    enrichment that keeps the graph dirty during embed). It falls back to
    ///    a single full snapshot on the very first write or when a compaction is
    ///    required.
    /// 2. [`save_vector_index_for_graph`](Self::save_vector_index_for_graph)
    ///    persists the vector sidecar — the embeddings produced by this batch.
    ///    The full-snapshot path in step 1 already writes the bundle, so the
    ///    sidecar is only written separately on the incremental path to avoid a
    ///    redundant double write.
    ///
    /// The vector index is a pure sidecar (not part of the graph merkle root),
    /// so a batch that only adds embeddings leaves the graph unchanged and
    /// `generation` comes back `None`; the sidecar is still flushed and reloads
    /// on a cold reopen. The returned [`EmbedFlushOutcome::status`] carries the
    /// resume `pending` count, derived from persisted graph-vs-index truth, so
    /// the driver can detect full coverage even after a restart drained the
    /// in-memory embedding queue.
    ///
    /// `embedder_identity` is forwarded to the sidecar write (see
    /// [`save_vector_index_for_graph`](Self::save_vector_index_for_graph) for
    /// the staleness-enforcement contract).
    #[cfg(feature = "vector")]
    pub fn flush_embed_progress(
        path: impl Into<PathBuf>,
        graph: &InMemoryGraph,
        base_generation: Generation,
        embedder_identity: Option<&str>,
    ) -> Result<EmbedFlushOutcome, KinDbError> {
        let path = normalize_snapshot_path(path.into());
        // Capture the branch `save_graph_delta` will take *before* calling it —
        // the full save clears `full_snapshot_required`, so reading it after
        // would always observe the incremental case and double-write the kvec.
        let full_snapshot = graph.full_snapshot_required()
            || (!path.exists() && read_local_authority_manifest(&path)?.is_none());
        let generation = Self::save_graph_delta(&path, graph, base_generation)?;
        if !full_snapshot {
            // The graph delta (the authority) is already on disk. The derived
            // vector sidecar is a full O(index) serialize, so it is written on a
            // throttle rather than every batch:
            //   - queue drained  -> always write (the completion checkpoint) and
            //     reset the throttle so the next run's first batch checkpoints;
            //   - still draining  -> write on the throttle (first batch, then
            //     every interval / batch backstop, whichever fires first) so
            //     persisted coverage tracks compute and a persisted-progress
            //     watchdog sees forward motion, without paying the full serialize
            //     every batch.
            // A checkpoint written mid-run is stamped with the graph root hash, so
            // a reopen loads the covered vectors and re-derives only the remainder
            // from the graph-vs-index diff (resume), instead of re-embedding all.
            let embedding_in_flight =
                graph.pending_embeddings() > 0 || graph.pending_artifact_embeddings() > 0;
            let write_sidecar = if embedding_in_flight {
                graph.should_flush_vector_sidecar_now()
            } else {
                graph.reset_vector_sidecar_flush_throttle();
                true
            };
            if write_sidecar {
                Self::save_vector_index_for_graph(&path, graph, embedder_identity)?;
            }
        }
        Ok(EmbedFlushOutcome {
            generation,
            full_snapshot,
            status: graph.embedding_status(),
        })
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

        Ok(self.graph().pending_delta_snapshot(0))
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

            let compacted_graph = match self.text_index_path.as_ref() {
                Some(p) => InMemoryGraph::from_snapshot_with_text_index(snapshot, p.clone()),
                None => InMemoryGraph::from_snapshot(snapshot),
            };
            let (_, generation) = if self._lock_file.is_some() {
                Self::save_graph_with_hash_and_generation_under_exclusive_lock(
                    &self.path,
                    &compacted_graph,
                    None,
                    Some(self.generation()),
                    None,
                )?
            } else {
                Self::save_graph_with_expected_generation(
                    &self.path,
                    &compacted_graph,
                    self.generation(),
                )?
            };
            self.generation.store(generation, Ordering::Release);
            if self._lock_file.is_some() {
                Self::cleanup_superseded_versions_under_exclusive_lock(&self.path);
            }
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
                equivalence_hash: Hash256::from_bytes([0; 32]),
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
    fn local_delta_save_replays_on_reopen_and_full_save_compacts() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        let mut entity = test_entity("delta_fn");
        graph.upsert_entity(&entity).unwrap();
        graph.set_file_hash("src/main.rs", [1; 32]);
        mgr.save().unwrap();
        assert_eq!(local_delta_count(&path).unwrap(), 0);

        entity.signature = "fn delta_fn() -> i32".to_string();
        graph.upsert_entity(&entity).unwrap();
        graph.set_file_hash("src/main.rs", [2; 32]);

        let generation = SnapshotManager::save_graph_delta(&path, graph.as_ref(), 1)
            .unwrap()
            .expect("changed graph should write a local delta");
        assert_eq!(generation, 2);
        assert!(!graph.has_pending_delta());
        assert_eq!(local_delta_count(&path).unwrap(), 1);

        let reopened = SnapshotManager::open_read_only(&path).unwrap();
        let reopened_graph = reopened.graph();
        let loaded = reopened_graph
            .get_entity(&entity.id)
            .unwrap()
            .expect("delta entity should replay on reopen");
        assert_eq!(loaded.signature, "fn delta_fn() -> i32");
        assert_eq!(
            reopened_graph.get_file_hash("src/main.rs"),
            Some([2; 32]),
            "delta file hash should replay on reopen"
        );

        drop(reopened);
        SnapshotManager::save_graph(&path, reopened_graph.as_ref()).unwrap();
        assert_eq!(
            local_delta_count(&path).unwrap(),
            0,
            "full save should compact local delta journal"
        );
    }

    fn write_three_generation_local_journal(path: &Path) {
        let mgr = SnapshotManager::new(path);
        let graph = mgr.graph();
        graph
            .upsert_entity(&test_entity("base_generation"))
            .unwrap();
        mgr.save().unwrap();

        graph
            .upsert_entity(&test_entity("second_generation"))
            .unwrap();
        assert_eq!(
            SnapshotManager::save_graph_delta(path, graph.as_ref(), 1).unwrap(),
            Some(2)
        );

        graph
            .upsert_entity(&test_entity("third_generation"))
            .unwrap();
        assert_eq!(
            SnapshotManager::save_graph_delta(path, graph.as_ref(), 2).unwrap(),
            Some(3)
        );
    }

    #[test]
    fn local_delta_open_rejects_missing_prefix_and_acknowledged_head() {
        let missing_prefix = TempDir::new().unwrap();
        let prefix_path = missing_prefix.path().join("graph.kndb");
        write_three_generation_local_journal(&prefix_path);
        std::fs::remove_file(local_delta_path(&prefix_path, 2)).unwrap();

        let error = match SnapshotManager::open_without_text_index(&prefix_path) {
            Ok(_) => panic!("an acknowledged journal with a missing prefix must fail closed"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("expected generation 2, found 3"),
            "unexpected missing-prefix error: {error}"
        );

        let missing_head = TempDir::new().unwrap();
        let head_path = missing_head.path().join("graph.kndb");
        write_three_generation_local_journal(&head_path);
        std::fs::remove_file(local_delta_path(&head_path, 3)).unwrap();

        let error = match SnapshotManager::open_without_text_index(&head_path) {
            Ok(_) => panic!("a missing acknowledged journal head must fail closed"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("chain ended at generation 2, acknowledged head is 3"),
            "unexpected missing-head error: {error}"
        );
    }

    #[test]
    fn committed_full_save_ignores_stale_journal_when_cleanup_crashes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        let actor = Actor {
            actor_id: ActorId::new(),
            kind: ActorKind::Assistant,
            display_name: "cleanup-test".into(),
            external_refs: Vec::new(),
        };
        graph.create_actor(&actor).unwrap();
        mgr.save().unwrap();

        let event = AuditEvent {
            event_id: AuditEventId::new(),
            actor_id: actor.actor_id,
            action: "single-event".into(),
            target_scope: None,
            timestamp: Timestamp::now(),
            details: None,
        };
        // Use a wire-compatible Vec delta directly. Current graph mutations
        // conservatively request a full save for this domain, but older/local
        // journals can contain it and replaying it twice is non-idempotent.
        let mut delta = GraphSnapshotDelta::empty(1);
        delta.audit_events.added.push(event);
        assert_eq!(write_local_delta(&path, &delta, 1).unwrap(), 2);

        // A directory with a canonical stale-journal name makes remove_file
        // fail deterministically after the new authority is committed. Both it
        // and the real generation-2 delta must then be harmless on restart.
        std::fs::create_dir(local_delta_path(&path, 1)).unwrap();
        let recovered = SnapshotManager::open_without_text_index(&path).unwrap();
        let recovered_graph = recovered.graph();
        drop(recovered);
        let (_, generation) =
            SnapshotManager::save_graph_with_generation(&path, recovered_graph.as_ref()).unwrap();
        assert_eq!(generation, 3);
        assert_eq!(
            local_delta_count(&path).unwrap(),
            2,
            "failed cleanup fixture and stale delta should remain on disk"
        );

        let reopened = SnapshotManager::open_without_text_index(&path).unwrap();
        assert_eq!(reopened.generation(), 3);
        assert_eq!(
            reopened.graph().query_audit_events(None, 10).unwrap().len(),
            1,
            "stale generation-2 Vec additions must not replay over the compacted base"
        );
    }

    #[test]
    fn local_generation_recovers_across_save_restart_save_cycles() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let base = test_entity("restart_base");
        let second = test_entity("restart_second");
        let third = test_entity("restart_third");

        let mgr = SnapshotManager::new(&path);
        mgr.graph().upsert_entity(&base).unwrap();
        mgr.save().unwrap();
        assert_eq!(mgr.generation(), 1);
        drop(mgr);

        let first_restart = SnapshotManager::open(&path).unwrap();
        assert_eq!(first_restart.generation(), 1);
        first_restart.graph().upsert_entity(&second).unwrap();
        assert_eq!(first_restart.save_delta().unwrap(), Some(2));
        drop(first_restart);

        let second_restart = SnapshotManager::open(&path).unwrap();
        assert_eq!(second_restart.generation(), 2);
        second_restart.graph().upsert_entity(&third).unwrap();
        assert_eq!(second_restart.save_delta().unwrap(), Some(3));
        drop(second_restart);

        let reopened = SnapshotManager::open(&path).unwrap();
        assert_eq!(reopened.generation(), 3);
        let names: std::collections::HashSet<_> = reopened
            .graph()
            .list_all_entities()
            .unwrap()
            .into_iter()
            .map(|entity| entity.name)
            .collect();
        assert_eq!(names.len(), 3);
        assert!(names.contains("restart_base"));
        assert!(names.contains("restart_second"));
        assert!(names.contains("restart_third"));
    }

    #[test]
    fn legacy_snapshot_without_root_trailer_migrates_before_delta() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let legacy_graph = InMemoryGraph::new();
        legacy_graph
            .upsert_entity(&test_entity("legacy_base"))
            .unwrap();
        // `to_bytes` deliberately omits the persisted Merkle trailer used by
        // the new authority format, matching pre-authority local snapshots.
        std::fs::write(&path, legacy_graph.to_snapshot().to_bytes().unwrap()).unwrap();

        let mgr = SnapshotManager::open_without_text_index(&path).unwrap();
        assert_eq!(mgr.generation(), GENERATION_INIT);
        mgr.graph()
            .upsert_entity(&test_entity("post_migration_delta"))
            .unwrap();
        assert_eq!(mgr.save_delta().unwrap(), Some(1));
        drop(mgr);

        let reopened = SnapshotManager::open_without_text_index(&path).unwrap();
        assert_eq!(reopened.generation(), 1);
        let names: std::collections::HashSet<_> = reopened
            .graph()
            .list_all_entities()
            .unwrap()
            .into_iter()
            .map(|entity| entity.name)
            .collect();
        assert!(names.contains("legacy_base"));
        assert!(names.contains("post_migration_delta"));
    }

    #[test]
    fn explicit_snapshot_manager_legacy_rebuild_promotes_caller_reconciled_graph() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let mut legacy = GraphSnapshot::empty();
        legacy.file_hashes.insert("legacy.rs".to_string(), [1; 32]);
        std::fs::write(&path, legacy.to_bytes().unwrap()).unwrap();
        std::fs::write(dir.path().join("generation"), b"8").unwrap();
        std::fs::create_dir_all(local_delta_dir_for(&path)).unwrap();
        std::fs::write(
            local_delta_path(&path, 8),
            GraphSnapshotDelta::empty(7).to_bytes().unwrap(),
        )
        .unwrap();

        let reconciled = InMemoryGraph::from_snapshot({
            let mut snapshot = legacy;
            snapshot
                .file_hashes
                .insert("reconciled.rs".to_string(), [2; 32]);
            snapshot
        });
        let stale = SnapshotManager::rebuild_legacy_journal(&path, &reconciled, 7)
            .expect_err("stale quiesce cursor must not promote authority");
        assert!(stale.to_string().contains("expected 7, found 8"));
        assert!(!local_authority_path(&path).exists());

        let (_, generation) =
            SnapshotManager::rebuild_legacy_journal(&path, &reconciled, 8).unwrap();
        assert_eq!(generation, 9);
        assert!(local_delta_files(&path).unwrap().is_empty());
        assert!(!local_legacy_rebuild_marker_path(&path).exists());
        let reopened = SnapshotManager::open_without_text_index(&path).unwrap();
        assert_eq!(reopened.generation(), generation);
        assert_eq!(reopened.graph().get_file_hash("legacy.rs"), Some([1; 32]));
        assert_eq!(
            reopened.graph().get_file_hash("reconciled.rs"),
            Some([2; 32])
        );
    }

    #[test]
    fn local_snapshot_authority_rejects_legacy_marker_ahead() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let graph = InMemoryGraph::new();
        let (_, generation) = SnapshotManager::save_graph_with_generation(&path, &graph).unwrap();
        std::fs::write(dir.path().join("generation"), (generation + 1).to_string()).unwrap();
        let error = match SnapshotManager::open_without_text_index(&path) {
            Ok(_) => panic!("legacy marker ahead of authority must fail closed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("legacy local writer advanced"));
    }

    #[test]
    fn authoritative_reopen_heals_stale_compatibility_projection() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let graph = InMemoryGraph::new();
        graph.upsert_entity(&test_entity("authoritative")).unwrap();
        SnapshotManager::save_graph_with_generation(&path, &graph).unwrap();
        let authority = read_local_authority_manifest(&path).unwrap().unwrap();
        let authoritative_bytes =
            std::fs::read(local_snapshot_versions_dir(&path).join(authority.snapshot_file))
                .unwrap();

        // Model a crash immediately after authority promotion, before the
        // compatibility graph.kndb refresh replaces an older valid snapshot.
        std::fs::write(&path, GraphSnapshot::empty().to_bytes().unwrap()).unwrap();
        std::fs::remove_file(local_projection_generation_path(&path)).unwrap();
        let reopened = SnapshotManager::open_without_text_index(&path).unwrap();
        assert!(reopened
            .graph()
            .list_all_entities()
            .unwrap()
            .iter()
            .any(|entity| entity.name == "authoritative"));
        assert_eq!(std::fs::read(&path).unwrap(), authoritative_bytes);
    }

    #[test]
    fn static_full_save_cas_rejects_stale_generation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let graph = InMemoryGraph::new();
        let (_, generation) = SnapshotManager::save_graph_with_generation(&path, &graph).unwrap();
        let error =
            SnapshotManager::save_graph_with_expected_generation(&path, &graph, GENERATION_INIT)
                .expect_err("static full save must CAS under the OS lock");
        assert!(error
            .to_string()
            .contains(&format!("expected 0, found {generation}")));
        assert_eq!(
            read_local_authority_manifest(&path)
                .unwrap()
                .unwrap()
                .head_generation,
            generation
        );
    }

    #[test]
    fn static_full_save_reclaims_only_older_versioned_bases() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let graph = InMemoryGraph::new();
        graph.upsert_entity(&test_entity("generation_one")).unwrap();
        assert_eq!(
            SnapshotManager::save_graph_with_generation(&path, &graph)
                .unwrap()
                .1,
            1
        );

        // Model an in-flight writer that installed a future immutable base but
        // has not moved authority yet. Cleanup for generation 2 must preserve
        // it while reclaiming the genuinely superseded generation 1 base.
        let future_path = local_versioned_snapshot_path(&path, 3);
        std::fs::copy(local_versioned_snapshot_path(&path, 1), &future_path).unwrap();
        graph.upsert_entity(&test_entity("generation_two")).unwrap();
        assert_eq!(
            SnapshotManager::save_graph_with_generation(&path, &graph)
                .unwrap()
                .1,
            2
        );
        assert!(!local_versioned_snapshot_path(&path, 1).exists());
        assert!(local_versioned_snapshot_path(&path, 2).exists());
        assert!(future_path.exists());
    }

    #[test]
    fn manager_full_save_reclaims_older_base_while_holding_exclusive_lock() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let seed = InMemoryGraph::new();
        seed.upsert_entity(&test_entity("generation_one")).unwrap();
        SnapshotManager::save_graph_with_generation(&path, &seed).unwrap();
        assert!(local_versioned_snapshot_path(&path, 1).exists());

        // `open` holds the database flock for this manager's lifetime, so the
        // instance save reuses that lock and still reclaims the older base.
        let mgr = SnapshotManager::open(&path).unwrap();
        mgr.graph()
            .upsert_entity(&test_entity("generation_two"))
            .unwrap();
        mgr.save().unwrap();

        assert_eq!(mgr.generation(), 2);
        assert!(!local_versioned_snapshot_path(&path, 1).exists());
        assert!(local_versioned_snapshot_path(&path, 2).exists());
    }

    #[test]
    fn later_mutation_cannot_stamp_sidecars_with_detached_snapshot_root() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let text_index_path = text_index_dir_for(&path).unwrap();
        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        let mut entity = test_entity("initialepochtoken");
        let entity_id = entity.id;
        graph.upsert_entity(&entity).unwrap();
        mgr.save().unwrap();

        entity.name = "capturedepochtoken".into();
        entity.signature = "fn capturedepochtoken()".into();
        graph.upsert_entity(&entity).unwrap();
        let (captured_bytes, captured_root, epoch) =
            graph.begin_snapshot_persistence(None).unwrap();

        // This mutation arrives after the graph bytes/root were detached but
        // before their derived sidecars are persisted.
        entity.name = "newerepochtoken".into();
        entity.signature = "fn newerepochtoken()".into();
        graph.upsert_entity(&entity).unwrap();

        #[cfg(feature = "vector")]
        {
            write_vector_index_metadata(
                &vector_index_metadata_path_for(&path),
                &VectorIndexMetadata {
                    version: VectorIndexMetadata::VERSION,
                    graph_root_hash: hex::encode(captured_root),
                    dimensions: 4,
                    indexed: 1,
                    embedding_provider: None,
                    embedding_model_id: None,
                    embedding_model_revision: None,
                    embedding_pipeline_epoch: None,
                    embedder_identity: None,
                },
            )
            .unwrap();
        }

        SnapshotManager::persist_snapshot_sidecars_for_epoch(
            &path,
            graph.as_ref(),
            captured_root,
            epoch,
        )
        .unwrap();

        let persisted_text =
            crate::search::TextIndex::open_read_only(Some(&text_index_path)).unwrap();
        assert_eq!(
            persisted_text.graph_root_hash(),
            Some([0u8; 32]),
            "mixed-epoch live text must be marked non-authoritative"
        );
        drop(persisted_text);

        #[cfg(feature = "vector")]
        assert_eq!(
            read_vector_index_metadata(&vector_index_metadata_path_for(&path))
                .unwrap()
                .unwrap()
                .graph_root_hash,
            hex::encode([0u8; 32]),
            "mixed-epoch vector metadata must be marked non-authoritative"
        );

        // Simulate the crash window after authority commit but before the
        // canonical compatibility projection is refreshed. The old canonical
        // file remains generation 1; only the immutable generation-2 snapshot
        // and atomic authority identify durable truth.
        let generation = 2;
        let versioned_path = local_versioned_snapshot_path(&path, generation);
        std::fs::create_dir_all(local_snapshot_versions_dir(&path)).unwrap();
        mmap::atomic_write_bytes(&versioned_path, &captured_bytes).unwrap();
        write_local_authority(
            &path,
            &LocalSnapshotAuthority {
                version: LOCAL_SNAPSHOT_AUTHORITY_VERSION,
                snapshot_generation: generation,
                head_generation: generation,
                snapshot_file: local_snapshot_file_name(generation),
                snapshot_root_hash: hex::encode(captured_root),
            },
        )
        .unwrap();
        assert!(graph.complete_persistence(epoch));
        drop(mgr);

        let reopened = SnapshotManager::open(&path).unwrap();
        assert_eq!(reopened.generation(), generation);
        assert_eq!(
            reopened
                .graph()
                .get_entity(&entity_id)
                .unwrap()
                .unwrap()
                .name,
            "capturedepochtoken"
        );
        assert!(reopened
            .graph()
            .text_search("capturedepochtoken", 10)
            .unwrap()
            .iter()
            .any(|(key, _)| *key == RetrievalKey::Entity(entity_id)));
        assert!(
            reopened
                .graph()
                .text_search("newerepochtoken", 10)
                .unwrap()
                .is_empty(),
            "reopen must rebuild from detached authority, never newer live sidecar content"
        );
    }

    #[test]
    fn open_without_text_index_skips_text_index_rebuild() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        let entity = test_entity("graph_only_open");
        let id = entity.id;
        graph.upsert_entity(&entity).unwrap();
        mgr.save().unwrap();

        let warm_open = SnapshotManager::open_without_text_index(&path).unwrap();
        let warm_graph = warm_open.graph();
        let fetched = warm_graph.get_entity(&id).unwrap().unwrap();
        assert_eq!(fetched.name, "graph_only_open");

        let stats = warm_graph.graph_stats();
        assert_eq!(stats.total_entities, 1);
        assert_eq!(stats.text_indexed_entity_count, 0);
    }

    #[test]
    fn open_read_only_for_locate_preserves_queryable_locate_state() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        let caller = test_entity("caller");
        let mut callee = test_entity("callee");
        callee.file_origin = Some(FilePathId::new("src/lib.rs"));

        let change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([8; 32])),
            parents: Vec::new(),
            timestamp: Timestamp::now(),
            author: AuthorId::new("tester"),
            message: "cochange".into(),
            entity_deltas: vec![EntityDelta::Added(caller.clone())],
            relation_deltas: Vec::new(),
            artifact_deltas: Vec::new(),
            projected_files: vec![FilePathId::new("src/main.rs")],
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            authored_on: Some(BranchName::new("main")),
        };
        let relation = Relation {
            id: RelationId::new(),
            kind: RelationKind::CoChanges,
            src: GraphNodeId::Entity(caller.id),
            dst: GraphNodeId::Entity(callee.id),
            confidence: 1.0,
            origin: RelationOrigin::Inferred,
            created_in: Some(change.id),
            import_source: None,
            evidence: Vec::new(),
        };

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph.create_change(&change).unwrap();
        graph.upsert_relation(&relation).unwrap();
        graph
            .upsert_shallow_file(&ShallowTrackedFile {
                file_id: FilePathId::new("src/main.rs"),
                language_hint: "rust".into(),
                declaration_count: 1,
                import_count: 0,
                syntax_hash: Hash256::from_bytes([3; 32]),
                signature_hash: Some(Hash256::from_bytes([4; 32])),
                declaration_names: vec!["caller".into()],
                import_paths: Vec::new(),
            })
            .unwrap();
        mgr.save().unwrap();

        let reopened = SnapshotManager::open_read_only_for_locate(&path).unwrap();
        let graph = reopened.graph();

        assert_eq!(
            graph.get_entity(&caller.id).unwrap().unwrap().name,
            "caller"
        );
        assert_eq!(
            graph
                .get_relations(&caller.id, &[RelationKind::CoChanges])
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            graph.get_change(&change.id).unwrap().unwrap().message,
            "cochange"
        );
        assert_eq!(graph.list_shallow_files().unwrap().len(), 1);
    }

    #[test]
    fn open_read_only_for_locate_decodes_snapshot_with_file_hashes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();

        let caller = test_entity("caller");
        let mut callee = test_entity("callee");
        callee.file_origin = Some(FilePathId::new("src/lib.rs"));
        let helper = test_entity("helper");

        let change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([8; 32])),
            parents: Vec::new(),
            timestamp: Timestamp::now(),
            author: AuthorId::new("tester"),
            message: "cochange".into(),
            entity_deltas: vec![EntityDelta::Added(caller.clone())],
            relation_deltas: Vec::new(),
            artifact_deltas: Vec::new(),
            projected_files: vec![FilePathId::new("src/main.rs")],
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            authored_on: Some(BranchName::new("main")),
        };

        let calls = Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(caller.id),
            dst: GraphNodeId::Entity(callee.id),
            confidence: 0.9,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        let cochange = Relation {
            id: RelationId::new(),
            kind: RelationKind::CoChanges,
            src: GraphNodeId::Entity(caller.id),
            dst: GraphNodeId::Entity(helper.id),
            confidence: 1.0,
            origin: RelationOrigin::Inferred,
            created_in: Some(change.id),
            import_source: None,
            evidence: Vec::new(),
        };

        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_entity(&helper).unwrap();
        graph.create_change(&change).unwrap();
        graph.upsert_relation(&calls).unwrap();
        graph.upsert_relation(&cochange).unwrap();

        // file_hashes is HashMap<String, [u8; 32]>; the 32-byte values serialize
        // as a sequence. A non-empty map exercises the snapshot field that the
        // locate decoder must skip rather than misread as artifact_index
        // (FastHashMap<FilePathId, ArtifactId>) — the latter expects 16-byte
        // UUID values and fails with "expected a 16 byte array" when drifted.
        graph.set_file_hash("src/main.rs", [7u8; 32]);
        graph.set_file_hash("src/lib.rs", [9u8; 32]);

        graph
            .upsert_shallow_file(&ShallowTrackedFile {
                file_id: FilePathId::new("src/main.rs"),
                language_hint: "rust".into(),
                declaration_count: 1,
                import_count: 0,
                syntax_hash: Hash256::from_bytes([3; 32]),
                signature_hash: Some(Hash256::from_bytes([4; 32])),
                declaration_names: vec!["caller".into()],
                import_paths: Vec::new(),
            })
            .unwrap();
        mgr.save().unwrap();

        let reopened = SnapshotManager::open_read_only_for_locate(&path).unwrap();
        let graph = reopened.graph();

        assert_eq!(
            graph.get_entity(&caller.id).unwrap().unwrap().name,
            "caller"
        );
        assert_eq!(
            graph.get_entity(&callee.id).unwrap().unwrap().name,
            "callee"
        );
        assert_eq!(
            graph.get_entity(&helper.id).unwrap().unwrap().name,
            "helper"
        );
        assert_eq!(
            graph
                .get_relations(&caller.id, &[RelationKind::Calls])
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            graph
                .get_relations(&caller.id, &[RelationKind::CoChanges])
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            graph.get_change(&change.id).unwrap().unwrap().message,
            "cochange"
        );
        assert_eq!(graph.list_shallow_files().unwrap().len(), 1);
    }

    #[test]
    fn open_read_only_for_locate_populates_locate_cache() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        graph.upsert_entity(&test_entity("cached_open")).unwrap();
        mgr.save().unwrap();

        let locate_snapshot =
            crate::storage::format::LocateGraphSnapshot::from(graph.to_snapshot());
        SnapshotManager::store_locate_cache(
            &path,
            compute_graph_root_hash(&graph.to_snapshot()),
            &locate_snapshot,
        )
        .unwrap();
        assert!(locate_cache_path_for(&path).exists());
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
    fn open_heals_corrupt_compatibility_projection_from_authority() {
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

        let authority = read_local_authority_manifest(&path).unwrap().unwrap();
        let authoritative_path =
            local_snapshot_versions_dir(&path).join(authority.snapshot_file.as_str());
        let authoritative_bytes = std::fs::read(&authoritative_path).unwrap();

        let recovered = SnapshotManager::open(&path).unwrap();
        let recovered_graph = recovered.graph();
        let fetched = recovered_graph.get_entity(&entity_id).unwrap().unwrap();
        assert_eq!(fetched.name, "recover_corrupted_primary");
        assert!(!tmp_path.exists(), "recovery tmp should be consumed");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            authoritative_bytes,
            "unfinished compatibility write should heal from committed authority"
        );
    }

    #[test]
    fn open_quarantines_and_heals_corrupt_graph_truth() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        // Non-trivial graph: two entities (16-byte ids) joined by a relation.
        let caller = test_entity("caller");
        let callee = test_entity("callee");
        let caller_id = caller.id;
        let relation = Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(caller.id),
            dst: GraphNodeId::Entity(callee.id),
            confidence: 0.9,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        let mut good = GraphSnapshot::empty();
        good.entities.insert(caller.id, caller.clone());
        good.entities.insert(callee.id, callee.clone());
        good.relations.insert(relation.id, relation.clone());
        good.outgoing.insert(caller.id, vec![relation.id]);
        good.incoming.insert(callee.id, vec![relation.id]);

        let committed_root = compute_graph_root_hash(&good);
        let good_bytes = good
            .to_bytes_with_persisted_root_hash(committed_root)
            .unwrap();

        // Corrupt an entity's content on disk while keeping the original
        // committed root: the bytes still decode and pass their checksum, but
        // the content no longer matches the Merkle commitment.
        let mut corrupt = good.clone();
        corrupt.entities.get_mut(&caller_id).unwrap().signature = "fn tampered()".into();
        let corrupt_root = compute_graph_root_hash(&corrupt);
        assert_ne!(corrupt_root, committed_root);
        let corrupt_bytes = corrupt
            .to_bytes_with_persisted_root_hash(committed_root)
            .unwrap();

        // Primary holds the corrupt truth; the recovery candidate holds the
        // verified good truth to heal from.
        std::fs::write(&path, &corrupt_bytes).unwrap();
        mmap::write_recovery_candidate_bytes(&path, &good_bytes).unwrap();

        let healed = SnapshotManager::open(&path).unwrap();
        let graph = healed.graph();

        // The tampered signature must have been rejected and self-healed.
        let restored = graph.get_entity(&caller_id).unwrap().unwrap();
        assert_eq!(restored.signature, "fn caller()");
        assert_eq!(graph.entity_count(), 2);
        assert_eq!(graph.relation_count(), 1);

        // The corrupt primary was quarantined, not deleted and not served.
        let quarantine =
            mmap::quarantine_path(&path, &SnapshotManager::root_hash_tag(corrupt_root));
        assert!(
            quarantine.exists(),
            "corrupt snapshot should be quarantined at {}",
            quarantine.display()
        );
        assert!(
            !mmap::recovery_tmp_path(&path).exists(),
            "recovery candidate should be consumed by the heal"
        );
    }

    #[test]
    fn open_fails_loud_on_corrupt_graph_truth_without_recovery() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let entity = test_entity("lonely");
        let mut good = GraphSnapshot::empty();
        good.entities.insert(entity.id, entity.clone());
        let committed_root = compute_graph_root_hash(&good);

        let mut corrupt = good.clone();
        corrupt.entities.get_mut(&entity.id).unwrap().signature = "fn tampered()".into();
        let corrupt_root = compute_graph_root_hash(&corrupt);
        let corrupt_bytes = corrupt
            .to_bytes_with_persisted_root_hash(committed_root)
            .unwrap();
        std::fs::write(&path, &corrupt_bytes).unwrap();
        // No recovery candidate exists — there is nothing trustworthy to heal from.

        let err = match SnapshotManager::open(&path) {
            Ok(_) => panic!("corrupt graph truth must fail loud, never be served"),
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("verify-on-read"),
            "expected a verify-on-read failure, got: {msg}"
        );

        // The corrupt primary was quarantined rather than left in place.
        let quarantine =
            mmap::quarantine_path(&path, &SnapshotManager::root_hash_tag(corrupt_root));
        assert!(
            quarantine.exists(),
            "corrupt snapshot should be quarantined"
        );
        assert!(
            !path.exists(),
            "corrupt primary must not remain in place after fail-loud quarantine"
        );
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
                evidence: Vec::new(),
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
                evidence: Vec::new(),
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
                evidence: Vec::new(),
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

        let loaded_vectors = VectorIndex::load_from_disk(&vector_path).unwrap();
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
        assert_eq!(metadata.embedding_provider.as_deref(), Some("local"));
    }

    #[test]
    #[cfg(feature = "vector")]
    fn save_vector_index_for_graph_refreshes_metadata() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);
        let metadata_path = vector_index_metadata_path_for(&snapshot_path);

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        let first = test_entity("first_vector_owner");
        let second = test_entity("second_vector_owner");
        graph.upsert_entity(&first).unwrap();
        graph.upsert_entity(&second).unwrap();

        let initial_vectors = VectorIndex::new(4).unwrap();
        initial_vectors
            .upsert(first.id, &[1.0, 0.0, 0.0, 0.0])
            .unwrap();
        initial_vectors.save(&vector_path).unwrap();
        graph.load_vector_index(&vector_path).unwrap();
        mgr.save().unwrap();

        let updated_vectors = VectorIndex::new(4).unwrap();
        updated_vectors
            .upsert(first.id, &[1.0, 0.0, 0.0, 0.0])
            .unwrap();
        updated_vectors
            .upsert(second.id, &[0.0, 1.0, 0.0, 0.0])
            .unwrap();
        updated_vectors.save(&vector_path).unwrap();
        graph.load_vector_index(&vector_path).unwrap();

        SnapshotManager::save_vector_index_for_graph(&snapshot_path, graph.as_ref(), None).unwrap();

        let metadata = read_vector_index_metadata(&metadata_path)
            .unwrap()
            .expect("vector metadata should be refreshed");
        assert_eq!(
            metadata.graph_root_hash,
            hex::encode(compute_graph_root_hash(&graph.to_snapshot()))
        );
        assert_eq!(metadata.dimensions, 4);
        assert_eq!(metadata.indexed, 2);

        let reopened = SnapshotManager::open_read_only(&snapshot_path).unwrap();
        assert_eq!(reopened.graph().embedding_status().indexed, 2);
    }

    /// Grounds the crash-safety contract the incremental-embed flush depends on:
    /// an incremental kvec persist (`save_vector_index_for_graph`, with no full
    /// graph re-save) is durable and reloads on a cold reopen, and a hard process
    /// exit between that flush and any further graph write leaves `graph.kndb`
    /// intact. The vector index is a pure sidecar (not part of the graph merkle
    /// root), so embedding never changes the root hash — a flush that persists
    /// only the kvec writes metadata whose root hash still matches the persisted
    /// graph snapshot, so reopen loads it. This is exactly what lets a long embed
    /// survive interruption without losing the vectors written so far.
    #[test]
    #[cfg(feature = "vector")]
    fn incremental_kvec_persist_survives_crash_with_graph_intact() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);

        let first = test_entity("incremental_first");
        let second = test_entity("incremental_second");
        let root_hash_before;
        {
            let mgr = SnapshotManager::new(&snapshot_path);
            let graph = mgr.graph();
            graph.upsert_entity(&first).unwrap();
            graph.upsert_entity(&second).unwrap();

            // Initial graph + kvec persisted together (root hash H, one vector).
            let vectors = VectorIndex::new(4).unwrap();
            vectors.upsert(first.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
            vectors.save(&vector_path).unwrap();
            graph.load_vector_index(&vector_path).unwrap();
            mgr.save().unwrap();
            root_hash_before = compute_graph_root_hash(&graph.to_snapshot());

            // Simulate the next embed batch: add a second vector and persist ONLY
            // the kvec sidecar (no full graph re-save), exactly as a per-batch
            // incremental flush would. Then "crash" by dropping the manager with
            // no further save.
            let updated = VectorIndex::new(4).unwrap();
            updated.upsert(first.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
            updated.upsert(second.id, &[0.0, 1.0, 0.0, 0.0]).unwrap();
            updated.save(&vector_path).unwrap();
            graph.load_vector_index(&vector_path).unwrap();
            SnapshotManager::save_vector_index_for_graph(&snapshot_path, graph.as_ref(), None)
                .unwrap();
            // `mgr` dropped here — models a process exit right after a flush.
        }

        // Cold reopen: fresh manager, no shared in-memory state.
        let reopened = SnapshotManager::open(&snapshot_path).unwrap();
        let graph = reopened.graph();
        assert_eq!(
            graph.entity_count(),
            2,
            "graph snapshot must survive intact"
        );
        assert_eq!(
            compute_graph_root_hash(&graph.to_snapshot()),
            root_hash_before,
            "embedding must not change the graph merkle root"
        );
        assert_eq!(
            graph.embedding_status().indexed,
            2,
            "incremental kvec flush must be durable and reload on reopen"
        );
        assert_eq!(graph.pending_embeddings(), 0);
    }

    /// Resume contract for a *partial* embed: a per-batch
    /// Recovery contract for a *mid-bulk* embed crash. While the embed queue is
    /// still draining, `flush_embed_progress` persists the graph delta (the
    /// authority) but DEFERS the derived vector sidecar's stamp to the end of the
    /// run, so a half-written sidecar is never trusted on reopen. After a crash
    /// mid-bulk the graph survives intact and `embedding_status` reports every
    /// entity as pending, so the worker re-derives the full set from graph truth
    /// rather than resuming a partially-stamped index. The fully-drained
    /// (`pending == 0`) durable-resume case is covered by
    /// `incremental_kvec_persist_survives_crash_with_graph_intact` above.
    #[test]
    #[cfg(feature = "vector")]
    fn flush_embed_progress_mid_bulk_checkpoint_resumes_from_partial_on_reopen() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);

        let one = test_entity("partial_one");
        let two = test_entity("partial_two");
        let three = test_entity("partial_three");
        {
            let mgr = SnapshotManager::new(&snapshot_path);
            let graph = mgr.graph();
            graph.upsert_entity(&one).unwrap();
            graph.upsert_entity(&two).unwrap();
            graph.upsert_entity(&three).unwrap();
            mgr.save().unwrap();

            // Embed only ONE of the three, leaving the rest queued (mid-bulk).
            let vectors = VectorIndex::new(4).unwrap();
            vectors.upsert(one.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
            vectors.save(&vector_path).unwrap();
            graph.load_vector_index(&vector_path).unwrap();
            graph.queue_missing_for_embedding();
            assert!(
                graph.pending_embeddings() > 0,
                "precondition: the embed run is still draining"
            );

            let outcome =
                SnapshotManager::flush_embed_progress(&snapshot_path, graph.as_ref(), 1, None)
                    .unwrap();
            // Embedding does not mutate graph truth, so no graph delta is written.
            assert!(!outcome.full_snapshot);
            assert_eq!(outcome.generation, None);
            assert_eq!(outcome.status.total, 3);
            // The first in-run flush checkpoints the covered vector durably.
            // `mgr` dropped here — models a process exit mid-bulk.
        }

        // Cold reopen: the graph (authority) is intact, and the mid-bulk
        // checkpoint is a valid stamped partial index for the current graph root,
        // so its covered vector is TRUSTED (resume) while only the uncovered
        // remainder is re-derived from the graph-vs-index diff — instead of
        // re-embedding the whole repo from scratch.
        let reopened = SnapshotManager::open(&snapshot_path).unwrap();
        let graph = reopened.graph();
        assert_eq!(graph.entity_count(), 3);
        let status = graph.embedding_status();
        assert_eq!(
            status.indexed, 1,
            "the stamped mid-bulk checkpoint must be trusted on reopen (resume, not restart)"
        );
        assert_eq!(status.total, 3);
        assert_eq!(
            status.pending, 2,
            "graph-vs-index truth must report only the uncovered remainder as pending"
        );
        // The next embed pass re-queues exactly the uncovered remainder; the
        // already-checkpointed vector is reused, never re-embedded.
        graph.queue_missing_for_embedding();
        assert_eq!(
            graph.pending_embeddings(),
            2,
            "reopen must re-derive only the uncovered remainder, reusing the checkpoint"
        );
    }

    /// Hot-path guarantee: an incremental `flush_embed_progress` batch must NOT
    /// re-serialize the whole graph snapshot (the O(graph) full save is what
    /// killed the daemon on a large ~1 GB graph). Proven by asserting the
    /// `graph.kndb` bytes are byte-identical across the flush while the vector
    /// sidecar is written.
    #[test]
    #[cfg(feature = "vector")]
    fn flush_embed_progress_skips_full_graph_reserialize_on_incremental_batch() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        let entity = test_entity("hot_path");
        graph.upsert_entity(&entity).unwrap();
        mgr.save().unwrap();

        let snapshot_bytes_before = std::fs::read(&snapshot_path).unwrap();

        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(entity.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        vectors.save(&vector_path).unwrap();
        graph.load_vector_index(&vector_path).unwrap();

        let outcome =
            SnapshotManager::flush_embed_progress(&snapshot_path, graph.as_ref(), 1, None).unwrap();
        assert!(
            !outcome.full_snapshot,
            "an incremental embed batch must not take the full-snapshot path"
        );

        let snapshot_bytes_after = std::fs::read(&snapshot_path).unwrap();
        assert_eq!(
            snapshot_bytes_before, snapshot_bytes_after,
            "incremental flush must not rewrite the full graph snapshot"
        );
        assert!(
            vector_path.exists(),
            "incremental flush must persist the vector sidecar"
        );
    }

    /// While a bulk embed is still draining, `flush_embed_progress` checkpoints
    /// the derived vector sidecar on a THROTTLE: the first in-run flush lands it
    /// immediately (so persisted coverage tracks compute and a persisted-progress
    /// watchdog sees forward motion), while an immediate follow-up flush is
    /// throttled (so a long run does not re-serialize the whole O(index) sidecar
    /// on every batch). This is the fix for the batch-boundary persist wedge,
    /// where a fully-deferred sidecar froze persisted coverage for the whole run.
    #[test]
    #[cfg(feature = "vector")]
    fn flush_embed_progress_throttles_sidecar_while_embedding_pending() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        let embedded = test_entity("already_embedded");
        let pending = test_entity("still_pending");
        graph.upsert_entity(&embedded).unwrap();
        graph.upsert_entity(&pending).unwrap();
        mgr.save().unwrap();

        // One entity is embedded; the other has no vector yet, so the embed is
        // still in flight (mid-bulk).
        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(embedded.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        vectors.save(&vector_path).unwrap();
        graph.load_vector_index(&vector_path).unwrap();
        graph.queue_missing_for_embedding();
        assert!(
            graph.pending_embeddings() > 0,
            "precondition: an embedding is still pending"
        );

        // Remove the sidecar so a write is observable. The FIRST in-run flush
        // must re-create it — persisted progress lands from the first batch.
        std::fs::remove_file(&vector_path).unwrap();
        let outcome =
            SnapshotManager::flush_embed_progress(&snapshot_path, graph.as_ref(), 1, None).unwrap();
        assert!(
            !outcome.full_snapshot,
            "precondition: incremental flush path"
        );
        assert!(
            vector_path.exists(),
            "the first in-run flush must checkpoint the sidecar so persisted tracks compute"
        );

        // Remove it again and flush immediately: within the throttle window (well
        // under both the time interval and the batch backstop) the write is
        // skipped, so a long run is not billed a full index serialize per batch.
        std::fs::remove_file(&vector_path).unwrap();
        let outcome =
            SnapshotManager::flush_embed_progress(&snapshot_path, graph.as_ref(), 1, None).unwrap();
        assert!(
            !outcome.full_snapshot,
            "precondition: incremental flush path"
        );
        assert!(
            !vector_path.exists(),
            "an immediate follow-up flush must be throttled, not re-serialize the index"
        );
    }

    /// Deferring WHEN the index is canonicalized preserves the retrieval RESULT
    /// that matters: an index canonicalized+saved once at the end covers the same
    /// vector set and returns the same nearest neighbour as one saved after every
    /// batch. The two are NOT byte-identical, and their full-rank ordering can even
    /// differ — HNSW canonicalization reorders the live graph, so a mid-stream
    /// canon changes the topology subsequent inserts build on, and two valid
    /// topologies may break deeper-rank ties differently across platforms. For a
    /// derived ANN index, equal coverage and a stable top match are the correctness
    /// property; identical bytes (or identical deep-rank ordering) are not required.
    #[test]
    #[cfg(feature = "vector")]
    fn deferred_canon_save_matches_per_batch_canon_save() {
        let dir = TempDir::new().unwrap();
        let eager_path = dir.path().join("eager.kvec");
        let deferred_path = dir.path().join("deferred.kvec");

        let items: Vec<(_, Vec<f32>)> = (0..64u32)
            .map(|i| {
                let f = i as f32;
                let id = test_entity(&format!("e{i}")).id;
                (id, vec![f.sin(), f.cos(), (i % 7) as f32, (i % 5) as f32])
            })
            .collect();

        // Eager: canonicalize+save after every batch (the old per-flush cadence).
        let eager = VectorIndex::new(4).unwrap();
        for batch in items.chunks(8) {
            for (id, v) in batch {
                eager.upsert(*id, v).unwrap();
            }
            eager.save(&eager_path).unwrap();
        }

        // Deferred: upsert everything, canonicalize+save exactly once at the end.
        let deferred = VectorIndex::new(4).unwrap();
        for (id, v) in &items {
            deferred.upsert(*id, v).unwrap();
        }
        deferred.save(&deferred_path).unwrap();

        let eager_idx = VectorIndex::load_from_disk(&eager_path).unwrap();
        let deferred_idx = VectorIndex::load_from_disk(&deferred_path).unwrap();

        // Same coverage: both indexes hold exactly the inserted vector set. Use
        // the exact count + membership rather than search, which is bounded by
        // `ef_search` and need not enumerate every vector even at limit == N.
        assert_eq!(eager_idx.len(), items.len());
        assert_eq!(deferred_idx.len(), items.len());
        for (id, _) in &items {
            assert!(eager_idx.contains(id), "eager index must hold every vector");
            assert!(
                deferred_idx.contains(id),
                "deferred index must hold every vector"
            );
        }

        // Same retrieval result: the nearest neighbour is identical regardless of
        // canon timing. Deeper-rank ordering can differ between the two valid
        // topologies (tie-breaks), so only the top match is asserted.
        for query in [
            vec![1.0, 0.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0],
            vec![0.3, 0.7, 2.0, 1.0],
        ] {
            let eager_top = eager_idx.search_similar(&query, 5).unwrap();
            let deferred_top = deferred_idx.search_similar(&query, 5).unwrap();
            assert_eq!(
                eager_top.first().map(|(k, _)| *k),
                deferred_top.first().map(|(k, _)| *k),
                "the nearest neighbour must match regardless of canon timing"
            );
        }
    }

    /// During a large embed, concurrent LSP enrichment keeps the graph dirty.
    /// `flush_embed_progress` must persist that graph mutation incrementally (as a
    /// delta, not a full rewrite) every flush — the graph is the authority and
    /// stays durable. The derived vector sidecar is checkpointed on a throttle
    /// while the embed drains, so on a mid-bulk reopen the enrichment (replayed
    /// delta) survives, the checkpointed vector resumes, and only the uncovered
    /// remainder is re-derived from graph truth.
    #[test]
    #[cfg(feature = "vector")]
    fn flush_embed_progress_persists_concurrent_graph_mutation_and_recovers_on_reopen() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);

        let base_one = test_entity("enrich_base_one");
        let base_two = test_entity("enrich_base_two");
        let enriched = test_entity("enrich_added_by_lsp");
        {
            let mgr = SnapshotManager::new(&snapshot_path);
            let graph = mgr.graph();
            graph.upsert_entity(&base_one).unwrap();
            graph.upsert_entity(&base_two).unwrap();
            mgr.save().unwrap();

            // Embed one object, leaving the rest queued (mid-bulk)...
            let vectors = VectorIndex::new(4).unwrap();
            vectors.upsert(base_one.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
            vectors.save(&vector_path).unwrap();
            graph.load_vector_index(&vector_path).unwrap();
            // ...while concurrent enrichment adds a new entity (graph now dirty).
            graph.upsert_entity(&enriched).unwrap();
            graph.queue_missing_for_embedding();
            assert!(
                graph.pending_embeddings() > 0,
                "precondition: the embed run is still draining"
            );

            let outcome =
                SnapshotManager::flush_embed_progress(&snapshot_path, graph.as_ref(), 1, None)
                    .unwrap();
            assert!(!outcome.full_snapshot);
            // The dirty graph is persisted as a delta, advancing the generation.
            assert_eq!(outcome.generation, Some(2));
            assert_eq!(outcome.status.total, 3);
        }

        let reopened = SnapshotManager::open(&snapshot_path).unwrap();
        let graph = reopened.graph();
        assert_eq!(
            graph.entity_count(),
            3,
            "the enrichment delta must replay on reopen"
        );
        assert!(
            graph.get_entity(&enriched.id).unwrap().is_some(),
            "the concurrently-enriched entity must survive the crash"
        );
        let status = graph.embedding_status();
        assert_eq!(
            status.indexed, 1,
            "the throttled mid-bulk checkpoint must be trusted on reopen (resume, not restart)"
        );
        assert_eq!(
            status.pending, 2,
            "only the uncovered remainder (incl. the enriched entity) must remain pending"
        );
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
                // Identity is graph-assigned by the upsert above: read it back.
                RetrievalKey::Artifact(graph.artifact_id_for_path(&artifact.file_id).unwrap()),
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
                embedding_provider: None,
                embedding_model_id: None,
                embedding_model_revision: None,
                embedding_pipeline_epoch: None,
                embedder_identity: None,
            },
        )
        .unwrap();

        let reloaded = SnapshotManager::open(&snapshot_path).unwrap();
        assert_eq!(reloaded.graph().embedding_status().indexed, 0);
        assert_eq!(reloaded.graph().pending_embeddings(), 1);
        assert_eq!(reloaded.graph().pending_artifact_embeddings(), 1);
    }

    /// "Model swap on a live repo": an index that positively declares a DIFFERENT
    /// embedding model (a same-dimension swap the sidecar can miss) is ARCHIVED
    /// aside on reopen — not served as silently-wrong neighbors, not deleted —
    /// and the entities are requeued for a clean rebuild. No crash-loop.
    #[test]
    fn model_swapped_vector_index_is_archived_on_reopen() {
        // A model-swapped index is archived when a SIDECAR is present
        // (the sidecar is the authoritative validation gate). Without a sidecar
        // the index is treated as stale rather than archived — see the
        // torn_sidecar test above. This test validates the sidecar-present path.
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);
        let metadata_path = vector_index_metadata_path_for(&snapshot_path);

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        let entity = test_entity("archived_vector");
        graph.upsert_entity(&entity).unwrap();
        mgr.save().unwrap();

        // Persist an index + a MATCHING sidecar, but the index's own descriptor
        // declares a different model — the in-index descriptor check catches it.
        let root_hash = compute_graph_root_hash(&graph.to_snapshot());
        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(entity.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        vectors.set_descriptor(crate::vector::IndexDescriptor {
            model_id: Some("definitely-not-the-runtime-model@9".into()),
            graph_root: Some(hex::encode(root_hash)),
        });
        vectors.save(&vector_path).unwrap();
        // Write a sidecar that passes the root-hash gate, so we reach the
        // in-index descriptor self-check which detects the model mismatch.
        write_vector_index_metadata(
            &metadata_path,
            &VectorIndexMetadata {
                version: VectorIndexMetadata::VERSION,
                graph_root_hash: hex::encode(root_hash),
                dimensions: 4,
                indexed: 1,
                embedding_provider: None,
                embedding_model_id: None,
                embedding_model_revision: None,
                embedding_pipeline_epoch: None,
                embedder_identity: None,
            },
        )
        .unwrap();

        let reloaded = SnapshotManager::open(&snapshot_path).unwrap();
        // Recovery requeues the entity for a clean re-embed (no crash, no serve).
        assert_eq!(reloaded.graph().pending_embeddings(), 1);
        // The incompatible index was archived aside, not served and not deleted.
        assert!(
            !vector_path.exists(),
            "model-swapped index must be moved aside on reopen"
        );
        assert!(
            archived_sidecar_path(&vector_path).exists(),
            "an archived copy of the incompatible index must exist"
        );
    }

    /// A .kvec without a .kvec.meta.json sidecar is now treated as
    /// stale regardless of whether the index is stamped or unstamped. The old
    /// grandfather behavior (load-without-sidecar) is closed because it bypassed
    /// the root-hash gate. An orphaned .kvec simply triggers a clean rebuild;
    /// it is preserved on disk (not archived) per the prepare-state hygiene rule.
    #[test]
    fn unstamped_legacy_index_without_sidecar_is_now_stale() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        let entity = test_entity("legacy_vector");
        graph.upsert_entity(&entity).unwrap();
        mgr.save().unwrap();

        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(entity.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        // No set_descriptor → unstamped legacy index. No sidecar written.
        vectors.save(&vector_path).unwrap();

        let reloaded = SnapshotManager::open(&snapshot_path).unwrap();
        // Absent sidecar = stale; NOT loaded, NOT archived.
        assert!(
            vector_path.exists(),
            ".kvec must be preserved (not deleted/archived) — only the sidecar is the gate"
        );
        assert!(!archived_sidecar_path(&vector_path).exists());
        assert_eq!(
            reloaded.graph().embedding_status().indexed,
            0,
            "absent sidecar must not allow load even for an unstamped legacy index"
        );
        // The entity should be queued for rebuild.
        assert_eq!(reloaded.graph().pending_embeddings(), 1);
    }

    /// A save from a graph that never loaded the vector index (e.g. it was
    /// skipped on reopen because the sidecar metadata no longer matched the
    /// graph root hash) must NOT delete the on-disk sidecar. An unloaded
    /// in-memory index means "not loaded", never "the repo has no vectors", so
    /// deleting graph-owned truth here would be silent data loss — the exact
    /// prepared-state kvec-drop regression.
    #[test]
    fn save_with_unloaded_index_preserves_on_disk_vector_sidecar() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);
        let metadata_path = vector_index_metadata_path_for(&snapshot_path);

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        let entity = test_entity("preserved_vector");
        graph.upsert_entity(&entity).unwrap();
        mgr.save().unwrap();

        // Write a sidecar whose metadata root hash does not match the graph, so
        // the next reopen skips loading it and leaves the in-memory index None.
        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(entity.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        vectors.save(&vector_path).unwrap();
        write_vector_index_metadata(
            &metadata_path,
            &VectorIndexMetadata {
                version: VectorIndexMetadata::VERSION,
                graph_root_hash: hex::encode([42u8; 32]),
                dimensions: 4,
                indexed: 1,
                embedding_provider: None,
                embedding_model_id: None,
                embedding_model_revision: None,
                embedding_pipeline_epoch: None,
                embedder_identity: None,
            },
        )
        .unwrap();
        let bytes_before = std::fs::metadata(&vector_path).unwrap().len();
        assert!(bytes_before > 0, "seeded sidecar should be non-empty");

        // Reopen (index skipped as stale -> in-memory None) and save again. The
        // sidecar and its metadata must survive the save untouched.
        let reloaded = SnapshotManager::open(&snapshot_path).unwrap();
        assert_eq!(reloaded.graph().embedding_status().indexed, 0);
        reloaded.save().unwrap();

        assert!(
            vector_path.exists(),
            "save with unloaded index must preserve graph.kvec, not delete it"
        );
        assert!(
            metadata_path.exists(),
            "save with unloaded index must preserve graph.kvec.meta.json"
        );
        assert_eq!(
            std::fs::metadata(&vector_path).unwrap().len(),
            bytes_before,
            "preserved sidecar bytes must be unchanged by a save that never loaded it"
        );
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
            evidence: Vec::new(),
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

        let authority = read_local_authority_manifest(&path).unwrap().unwrap();
        let authoritative_path =
            local_snapshot_versions_dir(&path).join(authority.snapshot_file.as_str());
        let mut bytes = std::fs::read(&authoritative_path).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        std::fs::write(&authoritative_path, &bytes).unwrap();

        let err = match SnapshotManager::open(&path) {
            Ok(_) => panic!("expected corrupted snapshot to fail reopening"),
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("digest mismatch")
                || msg.contains("checksum mismatch")
                || msg.contains("corrupted"),
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
            evidence: Vec::new(),
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
            evidence: Vec::new(),
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

    /// With the no-sidecar grandfather bypass closed, a read-only open
    /// where only .kvec exists (no .kvec.meta.json) must NOT load the vector
    /// index — no sidecar means no provenance, treat as stale. The .kvec is
    /// preserved (not modified), and the read-only flag means no metadata is
    /// written either.
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
        // Absent sidecar = stale; the vector index is NOT loaded.
        assert_eq!(
            reloaded.graph().embedding_status().indexed,
            0,
            "absent sidecar must not allow vector load even in read-only mode"
        );
        // The .kvec is preserved (read-only, no writes).
        assert!(vector_path.exists(), ".kvec must be preserved (read-only)");
        assert!(
            !metadata_path.exists(),
            "read-only open must not create vector metadata"
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
                evidence: Vec::new(),
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
                evidence: Vec::new(),
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
                evidence: Vec::new(),
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
            evidence: Vec::new(),
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
                evidence: Vec::new(),
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

    #[test]
    fn save_graph_with_hash_persists_root_hash_trailer() {
        let dir = TempDir::new().unwrap();
        let snap_path = dir.path().join("persisted-root.kndb");

        let graph = InMemoryGraph::new();
        let entity = test_entity("PersistedRoot");
        graph.upsert_entity(&entity).unwrap();

        let root_hash = graph.compute_root_hash();
        SnapshotManager::save_graph_with_hash(&snap_path, &graph, Some(root_hash)).unwrap();

        let (loaded, persisted_root_hash) =
            crate::storage::mmap::MmapReader::open_with_persisted_root_hash(&snap_path).unwrap();
        assert_eq!(persisted_root_hash, Some(root_hash));
        assert_eq!(compute_graph_root_hash(&loaded), root_hash);
    }

    #[test]
    fn open_read_only_uses_text_index_root_hash_when_snapshot_trailer_is_missing() {
        let dir = TempDir::new().unwrap();
        let snap_path = dir.path().join("legacy-rootless.kndb");
        let text_index_dir = dir.path().join("text-index");

        let graph = InMemoryGraph::with_text_index(text_index_dir.clone());
        let entity = test_entity("TextIndexRootHint");
        graph.upsert_entity(&entity).unwrap();

        let root_hash = graph.compute_root_hash();
        graph.persist_text_index_with_root_hash(root_hash).unwrap();

        let snapshot = graph.to_snapshot();
        std::fs::write(&snap_path, snapshot.to_bytes().unwrap()).unwrap();

        let (_, persisted_root_hash) =
            crate::storage::mmap::MmapReader::open_with_persisted_root_hash(&snap_path).unwrap();
        assert_eq!(
            persisted_root_hash, None,
            "legacy snapshot should not carry a trailer"
        );

        let reopened = SnapshotManager::open_read_only(&snap_path).unwrap();
        let reopened_graph = reopened.graph();
        assert_eq!(reopened_graph.snapshot_root_hash_hint(), Some(root_hash));
        assert_eq!(reopened_graph.compute_root_hash(), root_hash);
    }

    // ── sidecar provenance tests ─────────────────────────────────────────────

    /// A .kvec present without its .kvec.meta.json sidecar must NOT be loaded:
    /// the absent sidecar bypassed the root-hash gate in the old `unwrap_or(true)`.
    #[test]
    #[cfg(feature = "vector")]
    fn torn_sidecar_absent_rejects_load() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);
        let metadata_path = vector_index_metadata_path_for(&snapshot_path);

        // Set up: entity + vector index, full save (produces .kvec + .meta.json).
        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        let entity = test_entity("torn_sidecar_entity");
        graph.upsert_entity(&entity).unwrap();

        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(entity.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        vectors.save(&vector_path).unwrap();
        graph.load_vector_index(&vector_path).unwrap();
        mgr.save().unwrap();

        assert!(vector_path.exists(), ".kvec must exist after save");
        assert!(
            metadata_path.exists(),
            ".kvec.meta.json must exist after save"
        );

        // Tear the sidecar: remove .kvec.meta.json, leaving orphaned .kvec.
        std::fs::remove_file(&metadata_path).unwrap();

        // Reopen: the vector index must NOT be loaded (absent sidecar = stale).
        let reopened = SnapshotManager::open(&snapshot_path).unwrap();
        assert_eq!(
            reopened.graph().embedding_status().indexed,
            0,
            "torn sidecar (.kvec present, .meta.json absent) must not load the vector index"
        );
    }

    /// With both .kvec and .kvec.meta.json present and matching, the vector
    /// index must load successfully.
    #[test]
    #[cfg(feature = "vector")]
    fn stamped_match_loads_vector_index() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        let entity = test_entity("stamped_match_entity");
        graph.upsert_entity(&entity).unwrap();

        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(entity.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        vectors.save(&vector_path).unwrap();
        graph.load_vector_index(&vector_path).unwrap();
        mgr.save().unwrap();

        let reopened = SnapshotManager::open(&snapshot_path).unwrap();
        assert_eq!(
            reopened.graph().embedding_status().indexed,
            1,
            "matching sidecar must load the vector index"
        );
    }

    /// `vector_metadata_matches_graph`: embedder_identity mismatch must reject.
    #[test]
    #[cfg(feature = "vector")]
    fn embedder_identity_mismatch_rejects() {
        let root = [1u8; 32];
        let metadata = VectorIndexMetadata {
            version: VectorIndexMetadata::VERSION,
            graph_root_hash: hex::encode(root),
            dimensions: 768,
            indexed: 1,
            embedding_provider: None,
            embedding_model_id: None,
            embedding_model_revision: None,
            embedding_pipeline_epoch: None,
            embedder_identity: Some("sha256-aabbcc".to_string()),
        };
        assert!(
            !vector_metadata_matches_graph(&metadata, root, Some("sha256-ddeeff")),
            "different embedder_identity must reject"
        );
    }

    /// `vector_metadata_matches_graph`: None on either side is legacy —
    /// warn but load.
    #[test]
    #[cfg(feature = "vector")]
    fn embedder_identity_legacy_none_loads() {
        let root = [1u8; 32];

        // Stored=None (legacy store), expected=Some: warn+load.
        let metadata_none = VectorIndexMetadata {
            version: 1,
            graph_root_hash: hex::encode(root),
            dimensions: 768,
            indexed: 1,
            embedding_provider: None,
            embedding_model_id: None,
            embedding_model_revision: None,
            embedding_pipeline_epoch: None,
            embedder_identity: None,
        };
        assert!(
            vector_metadata_matches_graph(&metadata_none, root, Some("sha256-aabbcc")),
            "stored=None (legacy) must not block load when expected is Some"
        );

        // Stored=Some, expected=None: warn+load.
        let metadata_some = VectorIndexMetadata {
            version: VectorIndexMetadata::VERSION,
            graph_root_hash: hex::encode(root),
            dimensions: 768,
            indexed: 1,
            embedding_provider: None,
            embedding_model_id: None,
            embedding_model_revision: None,
            embedding_pipeline_epoch: None,
            embedder_identity: Some("sha256-aabbcc".to_string()),
        };
        assert!(
            vector_metadata_matches_graph(&metadata_some, root, None),
            "stored=Some, expected=None (legacy caller) must not block load"
        );
    }

    /// `vector_metadata_matches_graph`: matching identities on both sides loads.
    #[test]
    #[cfg(feature = "vector")]
    fn embedder_identity_match_loads() {
        let root = [1u8; 32];
        let metadata = VectorIndexMetadata {
            version: VectorIndexMetadata::VERSION,
            graph_root_hash: hex::encode(root),
            dimensions: 768,
            indexed: 1,
            embedding_provider: None,
            embedding_model_id: None,
            embedding_model_revision: None,
            embedding_pipeline_epoch: None,
            embedder_identity: Some("sha256-aabbcc".to_string()),
        };
        assert!(
            vector_metadata_matches_graph(&metadata, root, Some("sha256-aabbcc")),
            "matching embedder_identity must load"
        );
    }

    /// `save_vector_index_for_graph` stamps embedder_identity into the sidecar;
    /// a reload with the same identity succeeds, a different identity rejects.
    #[test]
    #[cfg(feature = "vector")]
    fn save_and_load_embedder_identity_roundtrip() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);
        let metadata_path = vector_index_metadata_path_for(&snapshot_path);

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        let entity = test_entity("identity_entity");
        graph.upsert_entity(&entity).unwrap();

        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(entity.id, &[0.5, 0.5, 0.5, 0.5]).unwrap();
        vectors.save(&vector_path).unwrap();
        graph.load_vector_index(&vector_path).unwrap();
        mgr.save().unwrap();

        // Overwrite sidecar with an explicit embedder_identity.
        SnapshotManager::save_vector_index_for_graph(
            &snapshot_path,
            graph.as_ref(),
            Some("build-v1"),
        )
        .unwrap();

        let stored_metadata = read_vector_index_metadata(&metadata_path)
            .unwrap()
            .expect("metadata must be present");
        assert_eq!(
            stored_metadata.embedder_identity.as_deref(),
            Some("build-v1"),
            "embedder_identity must be persisted in sidecar"
        );

        // Same identity → loads.
        let root = compute_graph_root_hash(&graph.to_snapshot());
        assert!(
            vector_metadata_matches_graph(&stored_metadata, root, Some("build-v1")),
            "matching identity must load"
        );
        // Different identity → rejects.
        assert!(
            !vector_metadata_matches_graph(&stored_metadata, root, Some("build-v2")),
            "different identity must reject"
        );
    }
}

#[cfg(test)]
#[path = "snapshot_kvec_root_stamp_test.rs"]
mod kvec_root_stamp_test;
