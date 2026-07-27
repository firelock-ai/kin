// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use fs2::FileExt;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::engine::{InMemoryGraph, PersistenceEpoch};
use crate::error::KinDbError;
use crate::storage::backend::{Generation, GENERATION_INIT};
use crate::storage::delta::{apply_graph_delta, GraphSnapshotDelta};
use crate::storage::format::CompactionStats;
use crate::storage::local_journal::{
    delete_quarantined_delta_exact, is_quarantine_delta_name, load_quarantined_deltas,
    quarantine_delta_path, quarantined_file_matches, sync_parent_directory,
};
use crate::storage::merkle::{
    compute_graph_root_hash, compute_locate_retrieval_authority_hash,
    compute_retrieval_authority_hash,
};
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
    /// OS-level lock guard. Held for the lifetime of this manager and explicitly
    /// unlocked before the manager's potentially large graph is dropped.
    _lock_file: Option<SnapshotFileLock>,
    /// Whether this manager was opened in read-only mode.
    read_only: bool,
    /// Last generation acknowledged by the atomic local snapshot authority.
    generation: AtomicU64,
}

/// Owns one acquired snapshot lock and releases it explicitly on every exit path.
///
/// Relying only on `File` close makes unlock timing depend on descriptor lifetime
/// and field destruction order. An explicit `LOCK_UN` keeps persistent managers
/// and one-shot static writes on the same deterministic release contract.
struct SnapshotFileLock {
    file: File,
    path: PathBuf,
}

impl SnapshotFileLock {
    fn new(file: File, path: PathBuf) -> Self {
        Self { file, path }
    }
}

impl Drop for SnapshotFileLock {
    fn drop(&mut self) {
        if let Err(error) = <File as FileExt>::unlock(&self.file) {
            tracing::warn!(
                path = %self.path.display(),
                error = %error,
                "failed to explicitly release snapshot lock"
            );
        }
    }
}

impl Drop for SnapshotManager {
    fn drop(&mut self) {
        // Release process-wide authority before destroying the graph. Under
        // saturation another thread can begin reopening as soon as the final
        // manager owner enters Drop, while graph teardown continues locally.
        drop(self._lock_file.take());
    }
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

struct CapturedGraphPersistence<'a> {
    bytes: Vec<u8>,
    root_hash: [u8; 32],
    retrieval_authority_hash: [u8; 32],
    epoch: PersistenceEpoch,
    serialize_elapsed: std::time::Duration,
    attempt: PersistenceAttempt<'a>,
}

impl<'a> CapturedGraphPersistence<'a> {
    fn capture(
        graph: &'a InMemoryGraph,
        precomputed_hash: Option<[u8; 32]>,
    ) -> Result<Self, KinDbError> {
        let started = std::time::Instant::now();
        let precomputed_hash = precomputed_hash.or_else(|| graph.snapshot_root_hash_hint());
        let (bytes, root_hash, retrieval_authority_hash, epoch) =
            graph.begin_snapshot_persistence_with_retrieval_hash(precomputed_hash)?;
        Ok(Self {
            bytes,
            root_hash,
            retrieval_authority_hash,
            epoch,
            serialize_elapsed: started.elapsed(),
            attempt: PersistenceAttempt::new(graph, epoch),
        })
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

const LOCAL_SNAPSHOT_AUTHORITY_VERSION: u32 = 4;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct LocalSnapshotDeltaIdentity {
    generation: Generation,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct LocalSnapshotAuthority {
    version: u32,
    snapshot_generation: Generation,
    head_generation: Generation,
    snapshot_file: String,
    snapshot_root_hash: String,
    /// SHA-256 of the complete serialized snapshot, including every truth
    /// domain and the persisted graph-root trailer.
    snapshot_sha256: String,
    /// Exact graph/tree/artifact authority for every derived retrieval cache.
    /// This is captured from the same fenced graph epoch as `snapshot_sha256`,
    /// so mutable sidecars can be validated against independent authority.
    snapshot_retrieval_authority_hash: String,
    /// Exact byte identities for every acknowledged journal generation.
    /// Deterministic filenames are not immutable identities.
    acknowledged_deltas: Vec<LocalSnapshotDeltaIdentity>,
    /// Journal bytes already represented by a promoted full snapshot but not
    /// necessarily removed yet. Only these byte-identical artifacts may be
    /// retried for cleanup; a replacement must remain on disk and fail closed.
    retired_deltas: Vec<LocalSnapshotDeltaIdentity>,
}

#[cfg(test)]
std::thread_local! {
    static LOCAL_DELTA_BEFORE_APPLY_READ_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    static LOCAL_FULL_SAVE_BEFORE_DELTA_CLEANUP_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    static LOCAL_CLEANUP_AFTER_QUARANTINE_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    static LOCAL_FULL_SAVE_BEFORE_AUTHORITY_COMMIT_HOOK:
        std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_local_delta_before_apply_read_hook(hook: impl FnOnce() + 'static) {
    LOCAL_DELTA_BEFORE_APPLY_READ_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_local_delta_before_apply_read_hook() {
    LOCAL_DELTA_BEFORE_APPLY_READ_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_local_delta_before_apply_read_hook() {}

#[cfg(test)]
fn set_local_full_save_before_delta_cleanup_hook(hook: impl FnOnce() + 'static) {
    LOCAL_FULL_SAVE_BEFORE_DELTA_CLEANUP_HOOK
        .with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_local_full_save_before_delta_cleanup_hook() {
    LOCAL_FULL_SAVE_BEFORE_DELTA_CLEANUP_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_local_full_save_before_delta_cleanup_hook() {}

#[cfg(test)]
fn set_local_cleanup_after_quarantine_hook(hook: impl FnOnce() + 'static) {
    LOCAL_CLEANUP_AFTER_QUARANTINE_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_local_cleanup_after_quarantine_hook() {
    LOCAL_CLEANUP_AFTER_QUARANTINE_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_local_cleanup_after_quarantine_hook() {}

#[cfg(test)]
fn set_local_full_save_before_authority_commit_hook(hook: impl FnOnce() + 'static) {
    LOCAL_FULL_SAVE_BEFORE_AUTHORITY_COMMIT_HOOK
        .with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_local_full_save_before_authority_commit_hook() {
    LOCAL_FULL_SAVE_BEFORE_AUTHORITY_COMMIT_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_local_full_save_before_authority_commit_hook() {}

fn local_authority_path(snapshot_path: &Path) -> PathBuf {
    append_suffix(snapshot_path, ".authority.json")
}

fn local_file_sha256_bytes(path: &Path) -> Result<[u8; 32], KinDbError> {
    let mut file = mmap::open_regular_nofollow(path, "snapshot digest source")?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to read {} for digest verification: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn local_file_sha256(path: &Path) -> Result<String, KinDbError> {
    Ok(hex::encode(local_file_sha256_bytes(path)?))
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

fn read_local_authority_manifest_raw(
    snapshot_path: &Path,
) -> Result<Option<LocalSnapshotAuthority>, KinDbError> {
    let path = local_authority_path(snapshot_path);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(KinDbError::StorageError(format!(
                "failed to inspect local snapshot authority {}: {error}",
                path.display()
            )))
        }
    }
    mmap::confirm_installed_write(&path)?;
    let bytes = mmap::read_regular_bounded(&path, "local snapshot authority", 1024 * 1024)?;
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
    let expected_root_hash = local_authority_root_hash(&authority)?;
    let persisted_root_hash =
        mmap::MmapReader::read_persisted_root_hash_unverified(&versioned_path)?;
    if persisted_root_hash != Some(expected_root_hash) {
        return Err(KinDbError::StorageError(format!(
            "authoritative local snapshot {} root trailer does not match authority {}",
            versioned_path.display(),
            authority.snapshot_root_hash
        )));
    }
    if authority.snapshot_sha256.len() != 64 || hex::decode(&authority.snapshot_sha256).is_err() {
        return Err(KinDbError::StorageError(format!(
            "local snapshot authority has an invalid serialized snapshot digest for {}",
            versioned_path.display()
        )));
    }
    if authority.snapshot_retrieval_authority_hash.len() != 64
        || hex::decode(&authority.snapshot_retrieval_authority_hash).is_err()
    {
        return Err(KinDbError::StorageError(format!(
            "local snapshot authority has an invalid retrieval authority for {}",
            versioned_path.display()
        )));
    }
    let actual_sha256 = local_file_sha256(&versioned_path)?;
    if actual_sha256 != authority.snapshot_sha256 {
        return Err(KinDbError::StorageError(format!(
            "authoritative local snapshot digest mismatch at {}: expected {}, found {actual_sha256}",
            versioned_path.display(), authority.snapshot_sha256
        )));
    }
    let expected_delta_count = authority
        .head_generation
        .checked_sub(authority.snapshot_generation)
        .ok_or_else(|| {
            KinDbError::StorageError("local snapshot authority range underflow".to_string())
        })?;
    let expected_delta_count = usize::try_from(expected_delta_count).map_err(|_| {
        KinDbError::StorageError(
            "local snapshot authority delta range does not fit in memory".to_string(),
        )
    })?;
    if authority.acknowledged_deltas.len() != expected_delta_count {
        return Err(KinDbError::StorageError(format!(
            "local snapshot authority generation range {}..={} declares {} acknowledged delta identities; expected {expected_delta_count}",
            authority.snapshot_generation.saturating_add(1),
            authority.head_generation,
            authority.acknowledged_deltas.len()
        )));
    }
    for (offset, identity) in authority.acknowledged_deltas.iter().enumerate() {
        let offset = Generation::try_from(offset).map_err(|_| {
            KinDbError::StorageError("local snapshot delta offset overflow".to_string())
        })?;
        let expected_generation = authority
            .snapshot_generation
            .checked_add(offset)
            .and_then(|generation| generation.checked_add(1))
            .ok_or_else(|| {
                KinDbError::StorageError(
                    "local snapshot authority delta generation overflow".to_string(),
                )
            })?;
        if identity.generation != expected_generation {
            return Err(KinDbError::StorageError(format!(
                "local snapshot authority delta identity names generation {}, expected {expected_generation}",
                identity.generation
            )));
        }
        if identity.sha256.len() != 64 || hex::decode(&identity.sha256).is_err() {
            return Err(KinDbError::StorageError(format!(
                "local snapshot authority delta generation {} has an invalid SHA-256 digest",
                identity.generation
            )));
        }
    }
    let mut bound_generations: std::collections::HashSet<Generation> = authority
        .acknowledged_deltas
        .iter()
        .map(|identity| identity.generation)
        .collect();
    for identity in &authority.retired_deltas {
        if identity.generation == GENERATION_INIT {
            return Err(KinDbError::StorageError(
                "local snapshot authority has a retired delta at reserved generation 0".to_string(),
            ));
        }
        if identity.generation >= authority.snapshot_generation {
            return Err(KinDbError::StorageError(format!(
                "local snapshot authority retired delta generation {} is not older than snapshot generation {}",
                identity.generation, authority.snapshot_generation
            )));
        }
        if !bound_generations.insert(identity.generation) {
            return Err(KinDbError::StorageError(format!(
                "local snapshot authority binds delta generation {} more than once",
                identity.generation
            )));
        }
        if identity.sha256.len() != 64 || hex::decode(&identity.sha256).is_err() {
            return Err(KinDbError::StorageError(format!(
                "local snapshot authority retired delta generation {} has an invalid SHA-256 digest",
                identity.generation
            )));
        }
    }
    Ok(Some(authority))
}

fn validate_loaded_local_delta_artifacts(
    authority: &LocalSnapshotAuthority,
    artifacts: &[(Generation, PathBuf, Vec<u8>)],
) -> Result<(), KinDbError> {
    for (index, identity) in authority.acknowledged_deltas.iter().enumerate() {
        let Some((_, path, bytes)) = artifacts
            .iter()
            .find(|(generation, _, _)| *generation == identity.generation)
        else {
            if let Some(next) = authority.acknowledged_deltas[index + 1..]
                .iter()
                .find(|next| {
                    artifacts
                        .iter()
                        .any(|(generation, _, _)| *generation == next.generation)
                })
            {
                return Err(KinDbError::StorageError(format!(
                    "local delta chain is incomplete: expected generation {}, found {}",
                    identity.generation, next.generation
                )));
            }
            return Err(KinDbError::StorageError(format!(
                "local delta chain ended at generation {}, acknowledged head is {}",
                identity.generation - 1,
                authority.head_generation
            )));
        };
        let digest = hex::encode(Sha256::digest(bytes));
        if digest != identity.sha256 {
            return Err(KinDbError::StorageError(format!(
                "acknowledged local delta digest mismatch at generation {} while loading replay bytes from {}: expected {}, found {digest}; committed journal bytes changed",
                identity.generation, path.display(), identity.sha256
            )));
        }
    }

    for (generation, _path, bytes) in artifacts {
        if authority
            .acknowledged_deltas
            .iter()
            .any(|identity| identity.generation == *generation)
        {
            continue;
        }
        if let Some(identity) = authority
            .retired_deltas
            .iter()
            .find(|identity| identity.generation == *generation)
        {
            let digest = hex::encode(Sha256::digest(bytes));
            if digest != identity.sha256 {
                return Err(KinDbError::StorageError(format!(
                    "retired local delta digest mismatch at generation {generation}: expected {}, found {digest}; retired journal bytes changed after full promotion",
                    identity.sha256
                )));
            }
            continue;
        }
        if *generation <= authority.head_generation {
            return Err(KinDbError::StorageError(format!(
                "local snapshot authority head {} has an unbound residual delta at generation {generation}; recovery is fail-closed",
                authority.head_generation
            )));
        }
        // A future generation can be an orphan staged before its authority
        // commit. It is not durable and is ignored until that writer retries
        // the authority CAS.
    }
    Ok(())
}

fn finalize_retired_local_quarantines(
    snapshot_path: &Path,
    authority: &LocalSnapshotAuthority,
) -> Result<(), KinDbError> {
    let quarantined = load_quarantined_deltas(&local_delta_dir_for(snapshot_path))?;
    for artifact in &quarantined {
        let Some(identity) = authority
            .retired_deltas
            .iter()
            .find(|identity| identity.generation == artifact.generation)
        else {
            return Err(KinDbError::StorageError(format!(
                "local snapshot {} has an unbound quarantined delta at generation {}; recovery is fail-closed",
                snapshot_path.display(), artifact.generation
            )));
        };
        if identity.sha256 != artifact.sha256 {
            return Err(KinDbError::StorageError(format!(
                "local snapshot {} quarantined delta identity mismatch at generation {}: authority binds {}, quarantine binds {}; recovery is fail-closed",
                snapshot_path.display(), artifact.generation, identity.sha256, artifact.sha256
            )));
        }
    }
    for artifact in &quarantined {
        delete_quarantined_delta_exact(artifact)?;
    }
    Ok(())
}

fn reject_unbound_staged_local_deltas(
    snapshot_path: &Path,
    authority: Option<&LocalSnapshotAuthority>,
) -> Result<(), KinDbError> {
    let head_generation = authority.map_or(GENERATION_INIT, |authority| authority.head_generation);
    let artifacts = load_local_delta_artifacts(snapshot_path)?;
    if let Some((generation, path, _)) = artifacts
        .iter()
        .find(|(generation, _, _)| *generation > head_generation)
    {
        return Err(KinDbError::StorageError(format!(
            "local snapshot {} has a staged unacknowledged delta at generation {generation} above authority head {head_generation} in {}; full promotion was not committed and may be retried after the staged writer resolves",
            snapshot_path.display(), path.display()
        )));
    }
    Ok(())
}

fn read_local_authority_manifest(
    snapshot_path: &Path,
) -> Result<Option<LocalSnapshotAuthority>, KinDbError> {
    let authority = read_local_authority_manifest_raw(snapshot_path)?;
    if let Some(authority) = authority.as_ref() {
        let artifacts = load_local_delta_artifacts(snapshot_path)?;
        validate_loaded_local_delta_artifacts(authority, &artifacts)?;
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

fn local_authority_snapshot_sha256(
    authority: &LocalSnapshotAuthority,
) -> Result<[u8; 32], KinDbError> {
    let bytes = hex::decode(&authority.snapshot_sha256).map_err(|error| {
        KinDbError::StorageError(format!(
            "invalid local snapshot authority payload digest: {error}"
        ))
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        KinDbError::StorageError(format!(
            "invalid local snapshot authority payload digest length {}; expected 32 bytes",
            bytes.len()
        ))
    })
}

fn local_authority_retrieval_authority_hash(
    authority: &LocalSnapshotAuthority,
) -> Result<[u8; 32], KinDbError> {
    let bytes = hex::decode(&authority.snapshot_retrieval_authority_hash).map_err(|error| {
        KinDbError::StorageError(format!(
            "invalid local snapshot retrieval authority: {error}"
        ))
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        KinDbError::StorageError(format!(
            "invalid local snapshot retrieval authority length {}; expected 32 bytes",
            bytes.len()
        ))
    })
}

fn verify_local_authoritative_snapshot_payload(
    snapshot_path: &Path,
    authority: &LocalSnapshotAuthority,
) -> Result<(), KinDbError> {
    let versioned_path = local_snapshot_versions_dir(snapshot_path).join(&authority.snapshot_file);
    let bytes = mmap::read_regular_file(&versioned_path, "authoritative local snapshot")?;
    let actual_sha256 = hex::encode(Sha256::digest(&bytes));
    if actual_sha256 != authority.snapshot_sha256 {
        return Err(KinDbError::StorageError(format!(
            "authoritative local snapshot payload {} digest mismatch: authority {}, actual {actual_sha256}",
            versioned_path.display(),
            authority.snapshot_sha256
        )));
    }
    let (snapshot, persisted_root_hash) =
        crate::storage::GraphSnapshot::from_bytes_with_persisted_root_hash(&bytes).map_err(
            |error| {
                KinDbError::StorageError(format!(
                    "authoritative local snapshot payload {} is invalid: {error}",
                    versioned_path.display()
                ))
            },
        )?;
    let expected_root_hash = local_authority_root_hash(authority)?;
    if persisted_root_hash != Some(expected_root_hash) {
        return Err(KinDbError::StorageError(format!(
            "authoritative local snapshot payload {} root trailer does not match authority {}",
            versioned_path.display(),
            authority.snapshot_root_hash
        )));
    }
    let actual_root_hash = compute_graph_root_hash(&snapshot);
    if actual_root_hash != expected_root_hash {
        return Err(KinDbError::StorageError(format!(
            "authoritative local snapshot payload {} graph root mismatch: authority {}, actual {}",
            versioned_path.display(),
            authority.snapshot_root_hash,
            hex::encode(actual_root_hash)
        )));
    }
    let expected_retrieval_authority_hash = local_authority_retrieval_authority_hash(authority)?;
    let actual_retrieval_authority_hash = compute_retrieval_authority_hash(&snapshot);
    if actual_retrieval_authority_hash != expected_retrieval_authority_hash {
        return Err(KinDbError::StorageError(format!(
            "authoritative local snapshot payload {} retrieval authority mismatch: authority {}, actual {}",
            versioned_path.display(),
            authority.snapshot_retrieval_authority_hash,
            hex::encode(actual_retrieval_authority_hash)
        )));
    }
    Ok(())
}

fn validate_or_finalize_local_quarantines(
    snapshot_path: &Path,
    authority: Option<&LocalSnapshotAuthority>,
) -> Result<(), KinDbError> {
    let quarantined = load_quarantined_deltas(&local_delta_dir_for(snapshot_path))?;
    if quarantined.is_empty() {
        return Ok(());
    }
    if let Some(authority) = authority {
        // Cleanup is permitted only after the complete authority payload is
        // readable and structurally valid. The authority then binds every
        // quarantine identity eligible for exact deletion.
        verify_local_authoritative_snapshot_payload(snapshot_path, authority)?;
        return finalize_retired_local_quarantines(snapshot_path, authority);
    }
    Err(KinDbError::StorageError(format!(
        "local snapshot {} has {} quarantined deltas but no current snapshot authority; recovery is fail-closed",
        snapshot_path.display(),
        quarantined.len()
    )))
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
    match mmap::atomic_write_bytes_no_magic_outcome(&path, &bytes)? {
        mmap::AtomicWriteOutcome::Durable => Ok(()),
        mmap::AtomicWriteOutcome::InstalledButUnconfirmed(error) => {
            Err(KinDbError::StorageError(format!(
                "local snapshot authority {} was installed but its durability is unconfirmed or exact post-install verification could not be completed: {error}",
                path.display()
            )))
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
        if is_quarantine_delta_name(&path) {
            continue;
        }
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

fn load_local_delta_artifacts(
    snapshot_path: &Path,
) -> Result<Vec<(Generation, PathBuf, Vec<u8>)>, KinDbError> {
    let mut artifacts = Vec::new();
    for (generation, path) in local_delta_files(snapshot_path)? {
        let bytes = mmap::read_regular_file(&path, "local delta")?;
        artifacts.push((generation, path, bytes));
    }
    Ok(artifacts)
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
    run_local_delta_before_apply_read_hook();
    validate_or_finalize_local_quarantines(snapshot_path, authority)?;
    let artifacts = load_local_delta_artifacts(snapshot_path)?;
    let Some(authority) = authority else {
        if !artifacts.is_empty() {
            return Err(KinDbError::StorageError(format!(
                "local snapshot {} has {} deltas but no atomic snapshot-base authority",
                snapshot_path.display(),
                artifacts.len()
            )));
        }
        return Ok((snapshot, persisted_root_hash, 0, GENERATION_INIT));
    };
    validate_loaded_local_delta_artifacts(authority, &artifacts)?;

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

    for (generation, _path, bytes) in &artifacts {
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
        let identity = authority
            .acknowledged_deltas
            .iter()
            .find(|identity| identity.generation == *generation)
            .ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "local snapshot authority does not bind delta generation {generation}"
                ))
            })?;
        let digest = hex::encode(Sha256::digest(bytes));
        if digest != identity.sha256 {
            return Err(KinDbError::StorageError(format!(
                "acknowledged local delta digest mismatch at generation {generation} while loading replay bytes: expected {}, found {digest}; committed journal bytes changed",
                identity.sha256
            )));
        }
        let delta = GraphSnapshotDelta::from_bytes(bytes)?;
        let expected_base = generation - 1;
        if delta.base_generation != expected_base {
            return Err(KinDbError::StorageError(format!(
                "local delta generation {generation} declares base {}, expected {expected_base}",
                delta.base_generation
            )));
        }
        apply_graph_delta(&mut snapshot, &delta)?;
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
    let current_authority = read_local_authority_manifest(snapshot_path)?;
    if let Some(authority) = current_authority.as_ref() {
        verify_local_authoritative_snapshot_payload(snapshot_path, authority)?;
    }
    validate_or_finalize_local_quarantines(snapshot_path, current_authority.as_ref())?;
    let Some(mut authority) = current_authority else {
        return Err(KinDbError::StorageError(format!(
            "local snapshot {} has no current snapshot authority; persist a full snapshot before writing deltas",
            snapshot_path.display()
        )));
    };
    let bytes = delta.to_bytes()?;
    let requested_digest = hex::encode(Sha256::digest(&bytes));
    if base_generation.checked_add(1) == Some(authority.head_generation)
        && authority
            .acknowledged_deltas
            .last()
            .is_some_and(|identity| {
                identity.generation == authority.head_generation
                    && identity.sha256 == requested_digest
            })
        && mmap::read_regular_file(
            &local_delta_path(snapshot_path, authority.head_generation),
            "idempotent local snapshot delta retry",
        )
        .is_ok_and(|installed| installed == bytes)
    {
        mmap::sync_parent_dir(&local_authority_path(snapshot_path))?;
        return Ok(authority.head_generation);
    }
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
    mmap::atomic_write_bytes_no_magic(&path, &bytes)?;
    authority
        .retired_deltas
        .retain(|identity| identity.generation != next_generation);
    authority
        .acknowledged_deltas
        .push(LocalSnapshotDeltaIdentity {
            generation: next_generation,
            sha256: requested_digest,
        });
    authority.head_generation = next_generation;
    write_local_authority(snapshot_path, &authority)?;
    Ok(next_generation)
}

fn capture_authority_bound_local_deltas(
    snapshot_path: &Path,
    authority: Option<&LocalSnapshotAuthority>,
) -> Result<Vec<(Generation, PathBuf, Vec<u8>)>, KinDbError> {
    let Some(authority) = authority else {
        return Ok(Vec::new());
    };
    let mut captured = Vec::new();
    for (identity, required) in authority
        .acknowledged_deltas
        .iter()
        .map(|identity| (identity, true))
        .chain(
            authority
                .retired_deltas
                .iter()
                .map(|identity| (identity, false)),
        )
    {
        let path = local_delta_path(snapshot_path, identity.generation);
        let bytes = match std::fs::symlink_metadata(&path) {
            Ok(_) => mmap::read_regular_file(&path, "authority-bound local delta")?,
            Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "failed to capture authority-bound local delta {}: {error}",
                    path.display()
                )));
            }
        };
        let digest = hex::encode(Sha256::digest(&bytes));
        if digest != identity.sha256 {
            return Err(KinDbError::StorageError(format!(
                "authority-bound local delta digest mismatch at generation {} before full promotion: expected {}, found {digest}",
                identity.generation, identity.sha256
            )));
        }
        captured.push((identity.generation, path, bytes));
    }
    Ok(captured)
}

fn clear_exact_captured_local_deltas(
    snapshot_path: &Path,
    captured: &[(Generation, PathBuf, Vec<u8>)],
) -> bool {
    let mut complete = true;
    for (generation, path, captured_bytes) in captured {
        // A compare followed by unlink is itself racy: an old writer can
        // replace the deterministic path between those syscalls. Rename the
        // current path entry to a unique same-directory quarantine first.
        // Whatever won the rename race is then stable for byte comparison;
        // mismatches are preserved under a deliberately noncanonical `.kndd`
        // name so every later recovery fails closed.
        let captured_sha256 = hex::encode(Sha256::digest(captured_bytes));
        let quarantine_path = quarantine_delta_path(path, *generation, &captured_sha256);
        match std::fs::rename(path, &quarantine_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                complete = false;
                tracing::warn!(path = %path.display(), error = %error, "journal promotion committed; could not quarantine captured delta for cleanup");
                continue;
            }
        }
        if let Err(error) = sync_parent_directory(&quarantine_path) {
            complete = false;
            tracing::warn!(path = %quarantine_path.display(), error = %error, "journal promotion committed; quarantined delta rename could not be made durable");
            continue;
        }
        run_local_cleanup_after_quarantine_hook();
        match quarantined_file_matches(
            &quarantine_path,
            &captured_sha256,
            captured_bytes.len() as u64,
        ) {
            Ok(true) => {
                if let Err(error) = std::fs::remove_file(&quarantine_path) {
                    complete = false;
                    tracing::warn!(path = %quarantine_path.display(), error = %error, "journal promotion committed; deferred quarantined captured-delta cleanup");
                } else if let Err(error) = sync_parent_directory(&quarantine_path) {
                    complete = false;
                    tracing::warn!(path = %quarantine_path.display(), error = %error, "journal promotion committed; could not fsync captured-delta cleanup");
                }
            }
            Ok(false) => {
                complete = false;
                tracing::warn!(path = %path.display(), quarantine = %quarantine_path.display(), "journal promotion preserved a delta that changed after capture");
            }
            Err(error) => {
                complete = false;
                tracing::warn!(path = %quarantine_path.display(), error = %error, "journal promotion committed; could not verify quarantined captured delta for cleanup");
            }
        }
    }
    match local_delta_files(snapshot_path) {
        Ok(remaining) if remaining.is_empty() => complete,
        Ok(remaining) => {
            tracing::warn!(
                path = %snapshot_path.display(),
                remaining = remaining.len(),
                "journal promotion committed with residual journal artifacts; recovery remains fail-closed"
            );
            false
        }
        Err(error) => {
            tracing::warn!(path = %snapshot_path.display(), error = %error, "journal promotion committed; could not verify journal drain");
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

/// Exact current vector-index sidecar metadata version.
#[cfg(feature = "vector")]
pub const VECTOR_INDEX_METADATA_VERSION: u32 = 3;

const LOCATE_CACHE_VERSION: u32 = 3;

#[cfg(feature = "vector")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VectorIndexMetadata {
    version: u32,
    /// Exact graph/tree/artifact authority digest, despite the historical
    /// field name retained in the JSON envelope.
    graph_root_hash: String,
    dimensions: usize,
    indexed: usize,
    embedding_provider: String,
    embedding_model_id: String,
    embedding_model_revision: String,
    embedding_pipeline_epoch: String,
    /// Caller-supplied artifact/binary identity of the embedder that produced
    /// these vectors (for example a build SHA or model-pipeline identity).
    embedder_identity: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LocateSnapshotCache {
    version: u32,
    snapshot_sha256: [u8; 32],
    snapshot: crate::storage::format::LocateGraphSnapshot,
}

#[cfg(feature = "vector")]
impl VectorIndexMetadata {
    const VERSION: u32 = VECTOR_INDEX_METADATA_VERSION;
}

fn normalize_snapshot_path(path: PathBuf) -> PathBuf {
    let path = if path
        .parent()
        .is_some_and(|parent| parent.as_os_str().is_empty())
    {
        Path::new(".").join(path)
    } else {
        path
    };
    if path.extension().is_some() {
        return path;
    }

    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return path;
    };
    if name != "kindb" {
        return path;
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
    if metadata.version != VectorIndexMetadata::VERSION {
        return Err(KinDbError::StorageError(format!(
            "unsupported vector index metadata version {} in {}",
            metadata.version,
            path.display()
        )));
    }
    if metadata.graph_root_hash.len() != 64
        || hex::decode(&metadata.graph_root_hash).is_err()
        || metadata.dimensions == 0
        || metadata.embedding_provider.is_empty()
        || metadata.embedding_model_id.is_empty()
        || metadata.embedding_model_revision.is_empty()
        || metadata.embedding_pipeline_epoch.is_empty()
        || metadata.embedder_identity.is_empty()
    {
        return Err(KinDbError::StorageError(format!(
            "vector index metadata {} is missing required current identity fields",
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
        if metadata.embedding_provider != runtime.provider {
            return false;
        }
        if metadata.embedding_model_id != runtime.model_id {
            return false;
        }
        if metadata.embedding_model_revision != runtime.revision {
            return false;
        }
        if metadata.embedding_pipeline_epoch != runtime.pipeline_epoch {
            return false;
        }
        if let Some(dimensions) = runtime.dimensions {
            if metadata.dimensions != dimensions {
                return false;
            }
        }
    }

    if let Some(expected) = expected_embedder_identity {
        if metadata.embedder_identity != expected {
            tracing::warn!(
                stored = %metadata.embedder_identity,
                expected = %expected,
                "vector sidecar embedder_identity mismatch: rejecting load"
            );
            return false;
        }
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
    /// The authority sidecar plus its referenced immutable version are the
    /// current local graph truth. [`SnapshotManager::open`] performs the full
    /// validation before serving it.
    pub fn local_authority_exists(path: impl Into<PathBuf>) -> bool {
        let path = normalize_snapshot_path(path.into());
        local_authority_path(&path).exists()
    }

    fn cleanup_superseded_versions_under_exclusive_lock(path: &Path) {
        let result = read_local_authority_manifest(path).and_then(|authority| {
            let Some(authority) = authority else {
                validate_or_finalize_local_quarantines(path, None)?;
                return Ok(());
            };
            validate_or_finalize_local_quarantines(path, Some(&authority))?;
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
    /// Returns an explicit-unlock guard on success.
    fn acquire_lock(path: &Path, read_only: bool) -> Result<SnapshotFileLock, KinDbError> {
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
        Ok(SnapshotFileLock::new(lock_file, lock_path))
    }

    /// Acquire the write lock for a one-shot static persistence operation.
    /// Unlike `open`, static writes wait for the current reader/writer to
    /// finish so two independent processes serialize the complete read-CAS-
    /// write interval instead of racing on the same immutable generation.
    fn acquire_static_write_lock(path: &Path) -> Result<SnapshotFileLock, KinDbError> {
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
        Ok(SnapshotFileLock::new(lock_file, lock_path))
    }

    fn graph_from_snapshot(
        snapshot: crate::storage::GraphSnapshot,
        text_index_path: Option<&PathBuf>,
        read_only: bool,
        skip_text_index: bool,
        persisted_root_hash: Option<[u8; 32]>,
    ) -> Result<(InMemoryGraph, [u8; 32]), KinDbError> {
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
        }?;
        Ok((graph, graph_root_hash))
    }

    fn graph_from_locate_snapshot(
        snapshot: crate::storage::format::LocateGraphSnapshot,
        text_index_path: Option<&PathBuf>,
        persisted_root_hash: Option<[u8; 32]>,
    ) -> Result<(InMemoryGraph, [u8; 32]), KinDbError> {
        let graph_root_hash = persisted_root_hash.unwrap_or_else(|| {
            let snapshot_for_hash: crate::storage::GraphSnapshot = snapshot.clone().into();
            compute_graph_root_hash(&snapshot_for_hash)
        });
        let graph = crate::engine::InMemoryGraph::from_locate_snapshot_read_only(
            snapshot,
            text_index_path.cloned(),
            graph_root_hash,
        )?;
        Ok((graph, graph_root_hash))
    }

    fn load_locate_cache(
        snapshot_path: &Path,
        expected_snapshot_sha256: [u8; 32],
        expected_graph_root_hash: [u8; 32],
        expected_retrieval_authority_hash: [u8; 32],
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
        if cache.version != LOCATE_CACHE_VERSION
            || cache.snapshot_sha256 != expected_snapshot_sha256
        {
            return Ok(None);
        }
        cache.snapshot.validate_storage_admission()?;
        if compute_locate_retrieval_authority_hash(&cache.snapshot, expected_graph_root_hash)
            != expected_retrieval_authority_hash
        {
            return Ok(None);
        }
        Ok(Some(cache.snapshot))
    }

    fn store_locate_cache(
        snapshot_path: &Path,
        snapshot_sha256: [u8; 32],
        graph_root_hash: [u8; 32],
        expected_retrieval_authority_hash: [u8; 32],
        snapshot: &crate::storage::format::LocateGraphSnapshot,
    ) -> Result<(), KinDbError> {
        snapshot.validate_storage_admission()?;
        let actual_retrieval_authority_hash =
            compute_locate_retrieval_authority_hash(snapshot, graph_root_hash);
        if actual_retrieval_authority_hash != expected_retrieval_authority_hash {
            return Err(KinDbError::StorageError(format!(
                "refusing locate cache whose retrieval authority {} does not match authoritative snapshot {}",
                hex::encode(actual_retrieval_authority_hash),
                hex::encode(expected_retrieval_authority_hash)
            )));
        }
        let cache_path = locate_cache_path_for(snapshot_path);
        let cache = LocateSnapshotCache {
            version: LOCATE_CACHE_VERSION,
            snapshot_sha256,
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

    fn invalidate_locate_cache(snapshot_path: &Path) -> Result<(), KinDbError> {
        let cache_path = locate_cache_path_for(snapshot_path);
        match std::fs::remove_file(&cache_path) {
            Ok(()) => sync_parent_directory(&cache_path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(KinDbError::StorageError(format!(
                "failed to invalidate locate cache {}: {error}",
                cache_path.display()
            ))),
        }
    }

    #[cfg(feature = "vector")]
    fn save_vector_index_bundle(
        path: &Path,
        graph: &InMemoryGraph,
        retrieval_authority_hash: [u8; 32],
        embedder_identity: Option<&str>,
    ) -> Result<(), KinDbError> {
        let vector_path = vector_index_path_for(path);
        let Some((dimensions, indexed)) = graph.vector_index_stats() else {
            // No index is loaded for this graph. A graph-only save must not
            // manufacture an unbound empty vector artifact. If an older
            // sidecar exists, leave its exact bytes and metadata untouched;
            // its old graph-root binding makes it ineligible on reopen.
            return Ok(());
        };

        let (provider, model_id, revision, pipeline_epoch, runtime_dimensions) =
            current_embedding_runtime_fields();
        let stored_descriptor = graph.vector_index_descriptor();
        let model_id = model_id
            .or_else(|| stored_descriptor.and_then(|descriptor| descriptor.model_id))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                KinDbError::StorageError(format!(
                    "vector index {} has no embedding-model descriptor",
                    vector_path.display()
                ))
            })?;
        let provider = provider.unwrap_or_else(|| "external".to_string());
        let revision = revision.unwrap_or_else(|| "external".to_string());
        let pipeline_epoch = pipeline_epoch.unwrap_or_else(|| "external-v1".to_string());
        let embedder_identity = match embedder_identity {
            Some(identity) if !identity.is_empty() => identity.to_string(),
            Some(_) => {
                return Err(KinDbError::StorageError(
                    "vector sidecar embedder identity cannot be empty".to_string(),
                ))
            }
            None => format!("{provider}:{model_id}:{revision}:{pipeline_epoch}"),
        };

        // Stamp the index's self-description (model identity + graph provenance)
        // BEFORE saving, so the persisted `.kvec` proves its own compatibility on
        // load — defense-in-depth alongside the sidecar metadata below.
        graph.stamp_vector_index_descriptor(crate::vector::IndexDescriptor {
            model_id: Some(model_id.clone()),
            graph_root: Some(hex::encode(retrieval_authority_hash)),
        });
        graph.save_vector_index(&vector_path)?;

        let metadata_path = vector_index_metadata_path_for(path);
        let metadata = VectorIndexMetadata {
            version: VectorIndexMetadata::VERSION,
            graph_root_hash: hex::encode(retrieval_authority_hash),
            dimensions: runtime_dimensions.unwrap_or(dimensions),
            indexed,
            embedding_provider: provider,
            embedding_model_id: model_id,
            embedding_model_revision: revision,
            embedding_pipeline_epoch: pipeline_epoch,
            embedder_identity,
        };
        write_vector_index_metadata(&metadata_path, &metadata)?;

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
        retrieval_authority_hash: [u8; 32],
        epoch: PersistenceEpoch,
    ) -> Result<(), KinDbError> {
        let exact = graph.persist_derived_sidecars_for_epoch(
            epoch,
            graph_root_hash,
            retrieval_authority_hash,
            |exact_retrieval_authority_hash| {
                #[cfg(feature = "vector")]
                {
                    Self::save_vector_index_bundle(
                        path,
                        graph,
                        exact_retrieval_authority_hash,
                        None,
                    )
                }
                #[cfg(not(feature = "vector"))]
                {
                    let _ = exact_retrieval_authority_hash;
                    Ok(())
                }
            },
        )?;
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
        retrieval_authority_hash: [u8; 32],
        write_missing_metadata: bool,
        expected_embedder_identity: Option<&str>,
    ) -> Result<bool, KinDbError> {
        let vector_path = vector_index_path_for(path);
        if !vector_path.exists() {
            return Ok(false);
        }

        let metadata_path = vector_index_metadata_path_for(path);
        let metadata = read_vector_index_metadata(&metadata_path)?;
        let matched_root = metadata.as_ref().and_then(|metadata| {
            vector_metadata_matches_graph(
                metadata,
                retrieval_authority_hash,
                expected_embedder_identity,
            )
            .then_some(retrieval_authority_hash)
        });
        let should_load = matched_root.is_some();

        if std::env::var("KINDB_DEBUG_KVEC").is_ok() {
            eprintln!(
                "[KVEC-DBG] should_load={} matched_root={:?} stamp_root={:?} retrieval_authority={} meta_embedder={:?} expected_embedder={:?} meta_dims={:?} meta_model={:?}",
                should_load,
                matched_root.map(hex::encode),
                metadata.as_ref().map(|m| m.graph_root_hash.clone()),
                hex::encode(retrieval_authority_hash),
                metadata.as_ref().map(|m| m.embedder_identity.clone()),
                expected_embedder_identity,
                metadata.as_ref().map(|m| m.dimensions),
                metadata.as_ref().map(|m| m.embedding_model_id.clone()),
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
        // own required model and graph self-description against the required
        // sidecar identities.
        let metadata = metadata.expect("matched vector metadata is present");
        let expected = crate::vector::IndexDescriptor {
            model_id: Some(metadata.embedding_model_id.clone()),
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

        if count == 0 {
            tracing::debug!(path = %vector_path.display(), "vector index metadata matched but index was empty");
        }

        Ok(true)
    }

    /// Validate and load a persisted vector-index sidecar into `graph`.
    ///
    /// # Contract for out-of-process callers (e.g. the daemon)
    ///
    /// This entry point validates the sidecar against graph truth before
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
    /// paths that build a graph without going through `SnapshotManager`.
    /// Supplying `expected_embedder_identity` additionally pins the required
    /// sidecar identity to the caller's known producer artifact.
    #[cfg(feature = "vector")]
    pub fn load_vector_index_into_graph_if_valid(
        graph: &InMemoryGraph,
        snapshot_path: &Path,
        expected_embedder_identity: Option<&str>,
    ) -> Result<bool, KinDbError> {
        let retrieval_authority_hash = graph.retrieval_authority_hash();
        Self::load_vector_index_if_valid(
            snapshot_path,
            graph,
            retrieval_authority_hash,
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
        validate_or_finalize_local_quarantines(path, authority.as_ref())?;

        let Some(authority) = authority else {
            let deltas = local_delta_files(path)?;
            if !deltas.is_empty() {
                return Err(KinDbError::StorageError(format!(
                    "local snapshot {} has {} persisted deltas but no current snapshot authority",
                    path.display(),
                    deltas.len()
                )));
            }
            let recovery_tmp = mmap::recovery_tmp_path(path);
            let recovery_marker = mmap::recovery_marker_path(path);
            if path.exists() || recovery_tmp.exists() || recovery_marker.exists() {
                return Err(KinDbError::StorageError(format!(
                    "local snapshot {} has unbound snapshot bytes but no current snapshot authority",
                    path.display()
                )));
            }

            if !read_only {
                #[cfg(feature = "vector")]
                {
                    for stale in [
                        vector_index_path_for(path),
                        vector_index_metadata_path_for(path),
                    ] {
                        match std::fs::remove_file(&stale) {
                            Ok(()) => sync_parent_directory(&stale)?,
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                            Err(error) => {
                                return Err(KinDbError::StorageError(format!(
                                    "failed to clear stale derived sidecar {}: {error}",
                                    stale.display()
                                )));
                            }
                        }
                    }
                }
                if let Some(text_path) = text_index_path {
                    if text_path.exists() {
                        let cleanup = if text_path.is_dir() {
                            std::fs::remove_dir_all(text_path)
                        } else {
                            std::fs::remove_file(text_path)
                        };
                        cleanup.map_err(|error| {
                            KinDbError::StorageError(format!(
                                "failed to clear stale text index {}: {error}",
                                text_path.display()
                            ))
                        })?;
                    }
                }
                Self::invalidate_locate_cache(path)?;
            }

            let graph = match text_index_path {
                Some(text_path) if !skip_text_index => {
                    InMemoryGraph::with_text_index(text_path.clone())
                }
                _ => InMemoryGraph::new(),
            };
            return Ok((graph, GENERATION_INIT));
        };

        let generation = authority.head_generation;
        let read_path = local_snapshot_versions_dir(path).join(authority.snapshot_file.as_str());
        let (snapshot, persisted_root_hash) =
            mmap::MmapReader::open_with_persisted_root_hash(&read_path).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to open authoritative local snapshot {}: {error}",
                    read_path.display()
                ))
            })?;
        validate_authoritative_base_snapshot(
            &read_path,
            &authority,
            &snapshot,
            persisted_root_hash,
        )?;
        let (snapshot, persisted_root_hash, delta_count, recovered_generation) =
            apply_local_deltas(path, snapshot, persisted_root_hash, Some(&authority))?;
        if recovered_generation != generation {
            return Err(KinDbError::StorageError(format!(
                "local authority generation changed while opening {}: expected {generation}, found {recovered_generation}",
                path.display()
            )));
        }
        if delta_count > 0 {
            tracing::info!(
                path = %path.display(),
                delta_count,
                "replayed current local snapshot deltas on open"
            );
        }

        let (graph, _graph_root_hash) = Self::graph_from_snapshot(
            snapshot,
            text_index_path,
            read_only,
            skip_text_index,
            persisted_root_hash,
        )?;
        if let Some((committed_root, actual_root)) =
            Self::graph_truth_corruption(&graph, persisted_root_hash)
        {
            return Err(KinDbError::StorageError(format!(
                "authoritative local snapshot {} failed graph-root verification: committed {}, actual {}",
                read_path.display(),
                Self::root_hash_tag(committed_root),
                Self::root_hash_tag(actual_root)
            )));
        }

        #[cfg(feature = "vector")]
        {
            let retrieval_authority_hash = graph.retrieval_authority_hash();
            Self::load_vector_index_if_valid(
                path,
                &graph,
                retrieval_authority_hash,
                !read_only,
                None,
            )?;
        }

        if !read_only {
            if let Err(error) = mmap::discard_recovery_artifacts_if_unchanged(&read_path) {
                tracing::warn!(
                    path = %read_path.display(),
                    error = %error,
                    "authoritative snapshot is available; deferred exact temporary-artifact cleanup"
                );
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
        validate_or_finalize_local_quarantines(path, authority.as_ref())?;
        let pending_deltas = local_delta_count(path)?;
        if authority.is_none() || pending_deltas > 0 {
            if pending_deltas > 0 {
                tracing::info!(
                    path = %path.display(),
                    "bypassing locate cache because current local snapshot deltas are pending"
                );
            }
            return Self::open_graph(path, text_index_path, true, false);
        }

        let authority = authority.expect("authority presence checked above");
        let generation = authority.head_generation;
        let read_path = local_snapshot_versions_dir(path).join(authority.snapshot_file.as_str());
        let expected_root_hash = local_authority_root_hash(&authority)?;
        let expected_snapshot_sha256 = local_authority_snapshot_sha256(&authority)?;
        let expected_retrieval_authority_hash =
            local_authority_retrieval_authority_hash(&authority)?;
        let hinted_root_hash = mmap::MmapReader::read_persisted_root_hash_unverified(&read_path)?;
        if hinted_root_hash != Some(expected_root_hash) {
            return Err(KinDbError::StorageError(format!(
                "authoritative local locate snapshot {} root trailer does not match authority {}",
                read_path.display(),
                hex::encode(expected_root_hash)
            )));
        }

        if let Some(snapshot) = Self::load_locate_cache(
            path,
            expected_snapshot_sha256,
            expected_root_hash,
            expected_retrieval_authority_hash,
        )? {
            let _span = tracing::info_span!("kindb.snapshot.use_locate_cache").entered();
            let (graph, _graph_root_hash) = Self::graph_from_locate_snapshot(
                snapshot,
                text_index_path,
                Some(expected_root_hash),
            )?;
            #[cfg(feature = "vector")]
            {
                let retrieval_authority_hash = graph.retrieval_authority_hash();
                Self::load_vector_index_if_valid(
                    path,
                    &graph,
                    retrieval_authority_hash,
                    false,
                    None,
                )?;
            }
            return Ok((graph, generation));
        }

        let (snapshot, persisted_root_hash) = {
            let _span = tracing::info_span!("kindb.snapshot.open_locate_mmap").entered();
            mmap::MmapReader::open_for_locate_with_persisted_root_hash(&read_path).map_err(
                |error| {
                    KinDbError::StorageError(format!(
                        "failed to open authoritative local locate snapshot {}: {error}",
                        read_path.display()
                    ))
                },
            )?
        };
        if persisted_root_hash != Some(expected_root_hash) {
            return Err(KinDbError::StorageError(format!(
                "authoritative local locate snapshot {} root does not match authority {}",
                read_path.display(),
                hex::encode(expected_root_hash)
            )));
        }
        if locate_cache_write_enabled() {
            let _ = Self::store_locate_cache(
                path,
                expected_snapshot_sha256,
                expected_root_hash,
                expected_retrieval_authority_hash,
                &snapshot,
            );
        }
        let (graph, _graph_root_hash) =
            Self::graph_from_locate_snapshot(snapshot, text_index_path, Some(expected_root_hash))?;

        #[cfg(feature = "vector")]
        {
            let retrieval_authority_hash = graph.retrieval_authority_hash();
            Self::load_vector_index_if_valid(path, &graph, retrieval_authority_hash, false, None)?;
        }

        Ok((graph, generation))
    }

    /// Open the exact current local authority, or create a new empty graph when
    /// the namespace contains no persisted artifacts.
    ///
    /// `path` is a logical namespace. Graph truth is the atomic authority
    /// manifest plus its referenced immutable generation, never raw bytes at
    /// `path`.
    ///
    /// Acquires an OS-level exclusive file lock to prevent concurrent access
    /// from other processes. Returns `LockError` if another process holds the lock.
    ///
    /// The text index is automatically persisted to a `text-index/` directory
    /// next to the namespace, avoiding full index rebuilds on cold start.
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
    /// the caller only needs snapshot entities and exact working-tree entries.
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

    /// Get the logical snapshot namespace path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Last generation acknowledged by the local base/head authority.
    pub fn generation(&self) -> Generation {
        self.generation.load(Ordering::Acquire)
    }

    /// Atomically commit the current graph as a new immutable generation and
    /// move the authority manifest to it.
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
        )?;
        Self::cleanup_superseded_versions_under_exclusive_lock(&path);
        Ok(result)
    }

    fn save_graph_with_hash_and_generation_under_exclusive_lock(
        path: &Path,
        graph: &InMemoryGraph,
        precomputed_hash: Option<crate::storage::merkle::MerkleHash>,
        expected_generation: Option<Generation>,
    ) -> Result<(crate::storage::merkle::MerkleHash, Generation), KinDbError> {
        let captured = CapturedGraphPersistence::capture(graph, precomputed_hash)?;
        Self::save_captured_graph_with_generation_under_exclusive_lock(
            path,
            graph,
            captured,
            expected_generation,
        )
    }

    fn save_captured_graph_with_generation_under_exclusive_lock(
        path: &Path,
        graph: &InMemoryGraph,
        captured_graph: CapturedGraphPersistence<'_>,
        expected_generation: Option<Generation>,
    ) -> Result<(crate::storage::merkle::MerkleHash, Generation), KinDbError> {
        let _span = tracing::info_span!(
            "kindb.snapshot.save_captured_graph",
            path = %path.display()
        )
        .entered();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to create directory {}: {error}",
                    parent.display()
                ))
            })?;
        }

        let current_authority = read_local_authority_manifest(path)?;
        if let Some(authority) = current_authority.as_ref() {
            verify_local_authoritative_snapshot_payload(path, authority)?;
        } else {
            let recovery_tmp = mmap::recovery_tmp_path(path);
            let recovery_marker = mmap::recovery_marker_path(path);
            if path.exists() || recovery_tmp.exists() || recovery_marker.exists() {
                return Err(KinDbError::StorageError(format!(
                    "local snapshot {} has unbound snapshot bytes but no current snapshot authority",
                    path.display()
                )));
            }
        }
        validate_or_finalize_local_quarantines(path, current_authority.as_ref())?;
        reject_unbound_staged_local_deltas(path, current_authority.as_ref())?;

        let current_generation = current_authority
            .as_ref()
            .map_or(GENERATION_INIT, |authority| authority.head_generation);
        let CapturedGraphPersistence {
            bytes,
            root_hash: graph_root_hash,
            retrieval_authority_hash,
            epoch: persistence_epoch,
            serialize_elapsed,
            attempt: persistence_attempt,
        } = captured_graph;
        let snapshot_sha256 = hex::encode(Sha256::digest(&bytes));

        if let Some(expected) = expected_generation {
            if expected.checked_add(1) == Some(current_generation)
                && current_authority.as_ref().is_some_and(|authority| {
                    authority.snapshot_generation == current_generation
                        && authority.head_generation == current_generation
                        && authority.snapshot_sha256 == snapshot_sha256
                        && authority.snapshot_retrieval_authority_hash
                            == hex::encode(retrieval_authority_hash)
                })
            {
                mmap::sync_parent_dir(&local_authority_path(path))?;
                persistence_attempt.complete();
                if let Some(authority) = current_authority.as_ref() {
                    match capture_authority_bound_local_deltas(path, Some(authority)) {
                        Ok(captured) => {
                            run_local_full_save_before_delta_cleanup_hook();
                            clear_exact_captured_local_deltas(path, &captured);
                        }
                        Err(error) => {
                            tracing::warn!(
                                path = %path.display(),
                                error = %error,
                                "confirmed full snapshot cursor; deferred retired-journal cleanup"
                            );
                        }
                    }
                }
                if let Err(error) = Self::invalidate_locate_cache(path) {
                    tracing::warn!(
                        path = %path.display(),
                        error = %error,
                        "confirmed full snapshot cursor; deferred locate-cache invalidation"
                    );
                }
                return Ok((graph_root_hash, current_generation));
            }
            if expected != current_generation {
                return Err(KinDbError::StorageError(format!(
                    "local snapshot generation mismatch for {}: expected {expected}, found {current_generation}",
                    path.display()
                )));
            }
        }

        let new_generation = current_generation.checked_add(1).ok_or_else(|| {
            KinDbError::StorageError(format!(
                "local snapshot generation exhausted at {current_generation}"
            ))
        })?;
        let versioned_path = local_versioned_snapshot_path(path, new_generation);
        std::fs::create_dir_all(local_snapshot_versions_dir(path)).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to create local snapshot versions directory: {error}"
            ))
        })?;

        let write_started = std::time::Instant::now();
        {
            let _span = tracing::info_span!("kindb.snapshot.save_graph.atomic_write").entered();
            mmap::atomic_write_bytes(&versioned_path, &bytes)?;
        }
        let write_elapsed = write_started.elapsed();

        let sidecars_started = std::time::Instant::now();
        {
            let _span =
                tracing::info_span!("kindb.snapshot.save_graph.persist_text_index").entered();
            Self::persist_snapshot_sidecars_for_epoch(
                path,
                graph,
                graph_root_hash,
                retrieval_authority_hash,
                persistence_epoch,
            )?;
        }
        let sidecars_elapsed = sidecars_started.elapsed();

        eprintln!(
            "[save_graph] serialize={:.1}s  atomic_write={:.1}s  sidecars={:.1}s",
            serialize_elapsed.as_secs_f64(),
            write_elapsed.as_secs_f64(),
            sidecars_elapsed.as_secs_f64(),
        );

        run_local_full_save_before_authority_commit_hook();
        let captured_for_cleanup =
            capture_authority_bound_local_deltas(path, current_authority.as_ref())?;
        reject_unbound_staged_local_deltas(path, current_authority.as_ref())?;
        if read_local_authority_manifest_raw(path)? != current_authority
            || capture_authority_bound_local_deltas(path, current_authority.as_ref())?
                != captured_for_cleanup
        {
            return Err(KinDbError::StorageError(format!(
                "local snapshot authority or bound journal changed while promoting {}; authority was not committed",
                path.display()
            )));
        }

        let authority = LocalSnapshotAuthority {
            version: LOCAL_SNAPSHOT_AUTHORITY_VERSION,
            snapshot_generation: new_generation,
            head_generation: new_generation,
            snapshot_file: local_snapshot_file_name(new_generation),
            snapshot_root_hash: hex::encode(graph_root_hash),
            snapshot_sha256,
            snapshot_retrieval_authority_hash: hex::encode(retrieval_authority_hash),
            acknowledged_deltas: Vec::new(),
            retired_deltas: captured_for_cleanup
                .iter()
                .map(|(generation, _, bytes)| LocalSnapshotDeltaIdentity {
                    generation: *generation,
                    sha256: hex::encode(Sha256::digest(bytes)),
                })
                .collect(),
        };
        write_local_authority(path, &authority)?;
        persistence_attempt.complete();

        if let Err(error) = Self::invalidate_locate_cache(path) {
            tracing::warn!(
                path = %path.display(),
                error = %error,
                "full snapshot committed; deferred locate-cache invalidation"
            );
        }
        run_local_full_save_before_delta_cleanup_hook();
        clear_exact_captured_local_deltas(path, &captured_for_cleanup);
        Ok((graph_root_hash, new_generation))
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
        if graph.full_snapshot_required() || read_local_authority_manifest(path)?.is_none() {
            let (_, generation) = Self::save_graph_with_hash_and_generation_under_exclusive_lock(
                path,
                graph,
                None,
                Some(base_generation),
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
    /// `embedder_identity` may explicitly identify the producer binary or
    /// artifact (for example a build SHA). If omitted, KinDB writes a required
    /// identity derived from the exact provider/model/revision/pipeline
    /// descriptor. Empty identities are rejected.
    #[cfg(feature = "vector")]
    pub fn save_vector_index_for_graph(
        path: impl Into<PathBuf>,
        graph: &InMemoryGraph,
        embedder_identity: Option<&str>,
    ) -> Result<(), KinDbError> {
        let path = normalize_snapshot_path(path.into());
        let retrieval_authority_hash = graph.retrieval_authority_hash();
        Self::save_vector_index_bundle(&path, graph, retrieval_authority_hash, embedder_identity)
    }

    /// Checkpoint a derived vector sidecar without writing graph authority.
    ///
    /// This is the repository-authority counterpart to
    /// [`flush_embed_progress`](Self::flush_embed_progress): the repository and
    /// workspace transaction has already made graph truth durable elsewhere, so
    /// this method only manages the O(index) vector checkpoint. While embedding
    /// is still draining, the first batch lands immediately and subsequent
    /// batches honor the graph's interval/batch throttle. A drained queue always
    /// lands the completion checkpoint and resets the next run.
    ///
    /// Returns `true` when this call wrote the sidecar and `false` when the
    /// in-flight checkpoint was throttled.
    #[cfg(feature = "vector")]
    pub fn checkpoint_vector_index_for_graph(
        path: impl Into<PathBuf>,
        graph: &InMemoryGraph,
        embedder_identity: Option<&str>,
    ) -> Result<bool, KinDbError> {
        let embedding_in_flight =
            graph.pending_embeddings() > 0 || graph.pending_artifact_embeddings() > 0;
        let write_sidecar = if embedding_in_flight {
            graph.should_flush_vector_sidecar_now()
        } else {
            graph.reset_vector_sidecar_flush_throttle();
            true
        };
        if write_sidecar {
            Self::save_vector_index_for_graph(path, graph, embedder_identity)?;
        }
        Ok(write_sidecar)
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
        let full_snapshot =
            graph.full_snapshot_required() || read_local_authority_manifest(&path)?.is_none();
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
            Self::checkpoint_vector_index_for_graph(&path, graph, embedder_identity)?;
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
        if read_local_authority_manifest(&self.path)?.is_none() {
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
            }?;
            let (_, generation) = if self._lock_file.is_some() {
                Self::save_graph_with_hash_and_generation_under_exclusive_lock(
                    &self.path,
                    &compacted_graph,
                    None,
                    Some(self.generation()),
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

    fn seal_change(mut change: SemanticChange) -> SemanticChange {
        change.id =
            kin_model::compute_semantic_change_id(&change).expect("valid semantic change fixture");
        change
    }

    fn test_entity_with_language(name: &str, file_origin: &str, language: LanguageId) -> Entity {
        let mut entity = test_entity(name);
        entity.file_origin = Some(FilePathId::new(file_origin));
        entity.language = language;
        entity
    }

    #[cfg(feature = "vector")]
    fn current_vector_metadata(
        graph_root_hash: [u8; 32],
        dimensions: usize,
        indexed: usize,
        embedder_identity: &str,
    ) -> VectorIndexMetadata {
        let (provider, model_id, revision, pipeline_epoch, runtime_dimensions) =
            current_embedding_runtime_fields();
        VectorIndexMetadata {
            version: VectorIndexMetadata::VERSION,
            graph_root_hash: hex::encode(graph_root_hash),
            dimensions: runtime_dimensions.unwrap_or(dimensions),
            indexed,
            embedding_provider: provider.unwrap_or_else(|| "external".to_string()),
            embedding_model_id: model_id.unwrap_or_else(|| "test-model".to_string()),
            embedding_model_revision: revision.unwrap_or_else(|| "test-revision".to_string()),
            embedding_pipeline_epoch: pipeline_epoch.unwrap_or_else(|| "test-pipeline".to_string()),
            embedder_identity: embedder_identity.to_string(),
        }
    }

    #[cfg(feature = "vector")]
    fn install_current_test_vector_index(
        graph: &InMemoryGraph,
        index: &VectorIndex,
        vector_path: &Path,
    ) {
        let (_, runtime_model_id, _, _, _) = current_embedding_runtime_fields();
        let descriptor = crate::vector::IndexDescriptor {
            model_id: Some(runtime_model_id.unwrap_or_else(|| "test-model".to_string())),
            graph_root: Some(hex::encode(graph.retrieval_authority_hash())),
        };
        index.set_descriptor(descriptor.clone());
        index.save(vector_path).unwrap();
        assert!(matches!(
            graph.load_vector_index_compatible(vector_path, &descriptor),
            crate::vector::VectorIndexLoad::Loaded(_)
        ));
    }

    fn current_snapshot_payload_path(path: &Path) -> PathBuf {
        let authority = read_local_authority_manifest(path).unwrap().unwrap();
        local_snapshot_versions_dir(path).join(authority.snapshot_file)
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
        graph.admit_artifact_for_test("src/main.rs", crate::types::regular_tree_entry(1));
        mgr.save().unwrap();
        assert_eq!(local_delta_count(&path).unwrap(), 0);

        let old_entity = entity.clone();
        entity.signature = "fn delta_fn() -> i32".to_string();
        let artifact_id = graph
            .artifact_id_at_path(&RepoPath::from_utf8("src/main.rs").unwrap())
            .unwrap();
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![EntityDelta::Modified {
                    old: old_entity,
                    new: entity.clone(),
                }],
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: LocatedEntry::new(
                        RepoPath::from_utf8("src/main.rs").unwrap(),
                        crate::types::regular_tree_entry(1),
                    ),
                    new: LocatedEntry::new(
                        RepoPath::from_utf8("src/main.rs").unwrap(),
                        crate::types::regular_tree_entry(2),
                    ),
                }],
                admission_policy_delta: None,
            })
            .unwrap();

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
            reopened_graph.tree_entry_for_test("src/main.rs"),
            Some(regular_tree_entry(2)),
            "exact tree entry should replay on reopen"
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
    fn current_authority_rejects_non_regular_delta_artifacts() {
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

        // Every current delta identity names an exact regular-file payload.
        // A directory with a canonical delta name is invalid authority, not a
        // tolerated cleanup artifact.
        std::fs::create_dir(local_delta_path(&path, 1)).unwrap();
        let error = match SnapshotManager::open_without_text_index(&path) {
            Ok(_) => panic!("non-regular delta authority must fail closed"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("refusing non-regular local delta"),
            "unexpected non-regular delta error: {error}"
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
    fn local_authority_write_propagates_post_rename_parent_sync_failure() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let snapshot_bytes = GraphSnapshot::empty()
            .to_bytes_with_persisted_root_hash([0; 32])
            .unwrap();
        let authority = LocalSnapshotAuthority {
            version: LOCAL_SNAPSHOT_AUTHORITY_VERSION,
            snapshot_generation: 1,
            head_generation: 1,
            snapshot_file: local_snapshot_file_name(1),
            snapshot_root_hash: hex::encode([0; 32]),
            snapshot_sha256: hex::encode(Sha256::digest(&snapshot_bytes)),
            snapshot_retrieval_authority_hash: hex::encode(compute_retrieval_authority_hash(
                &GraphSnapshot::empty(),
            )),
            acknowledged_deltas: Vec::new(),
            retired_deltas: Vec::new(),
        };
        mmap::fail_parent_sync_after(2);

        let error = write_local_authority(&path, &authority)
            .expect_err("authority write must not swallow a parent fsync failure");
        assert!(error
            .to_string()
            .contains("injected parent-directory fsync failure"));
        assert!(local_authority_path(&path).exists());
    }

    #[test]
    fn full_authority_post_rename_sync_failure_retries_exact_cursor_without_early_gc() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        graph.upsert_entity(&test_entity("base")).unwrap();
        mgr.save().unwrap();
        let base_generation = mgr.generation();
        graph.upsert_entity(&test_entity("delta")).unwrap();
        let delta_generation = mgr.save_delta().unwrap().unwrap();
        drop(mgr);
        let old_snapshot = local_versioned_snapshot_path(&path, base_generation);
        let delta_path = local_delta_path(&path, delta_generation);
        set_local_full_save_before_authority_commit_hook(|| {
            mmap::fail_parent_sync_after(2);
        });

        let error = SnapshotManager::save_graph_with_expected_generation(
            &path,
            graph.as_ref(),
            delta_generation,
        )
        .expect_err("installed but unconfirmed authority must be reported");
        assert!(error.to_string().contains("durability is unconfirmed"));
        assert!(mmap::recovery_marker_path(&local_authority_path(&path)).exists());
        assert!(
            old_snapshot.exists(),
            "old base must not be GC'd before confirmation"
        );
        assert!(
            delta_path.exists(),
            "retired journal must not be GC'd before confirmation"
        );

        let (_, generation) = SnapshotManager::save_graph_with_expected_generation(
            &path,
            graph.as_ref(),
            delta_generation,
        )
        .expect("exact retry must confirm and return the installed cursor");
        assert_eq!(generation, delta_generation + 1);
        assert!(!mmap::recovery_marker_path(&local_authority_path(&path)).exists());
        assert!(
            !delta_path.exists(),
            "confirmed retry should finish exact retired cleanup"
        );
        let reopened = SnapshotManager::open_without_text_index(&path).unwrap();
        assert_eq!(reopened.generation(), generation);
    }

    #[test]
    fn delta_authority_post_rename_sync_failure_retries_exact_cursor() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let graph = InMemoryGraph::new();
        let (_, base_generation) =
            SnapshotManager::save_graph_with_generation(&path, &graph).unwrap();
        let delta = GraphSnapshotDelta::empty(base_generation);
        // The delta write consumes five syncs. Authority candidate install
        // plus the exact candidate claim consume two more; fail its
        // destination rename sync.
        mmap::fail_parent_sync_after(7);
        let error = write_local_delta(&path, &delta, base_generation)
            .expect_err("installed but unconfirmed delta authority must be reported");
        assert!(error.to_string().contains("durability is unconfirmed"));
        assert!(local_delta_path(&path, base_generation + 1).exists());
        assert!(mmap::recovery_marker_path(&local_authority_path(&path)).exists());

        let retried = write_local_delta(&path, &delta, base_generation)
            .expect("exact retry must confirm installed delta cursor");
        assert_eq!(retried, base_generation + 1);
        assert!(!mmap::recovery_marker_path(&local_authority_path(&path)).exists());
    }

    #[test]
    fn local_snapshot_authority_rejects_replaced_delta_at_same_head() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let graph = InMemoryGraph::new();
        let (_, base_generation) =
            SnapshotManager::save_graph_with_generation(&path, &graph).unwrap();
        graph
            .upsert_entity(&test_entity("committed_delta"))
            .unwrap();
        let head_generation = SnapshotManager::save_graph_delta(&path, &graph, base_generation)
            .unwrap()
            .expect("mutation must append a delta");

        // Replacing the deterministic acknowledged filename without moving
        // atomic authority must fail exact-identity validation.
        mmap::atomic_write_bytes_no_magic(
            &local_delta_path(&path, head_generation),
            &GraphSnapshotDelta::empty(base_generation)
                .to_bytes()
                .unwrap(),
        )
        .unwrap();
        let error = match SnapshotManager::open_without_text_index(&path) {
            Ok(_) => panic!("authority must bind the exact acknowledged delta bytes"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("acknowledged local delta digest mismatch"));
    }

    #[test]
    fn local_snapshot_authority_binds_non_entity_serialized_truth() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let graph = InMemoryGraph::new();
        graph.upsert_entity(&test_entity("stable-root")).unwrap();
        SnapshotManager::save_graph_with_generation(&path, &graph).unwrap();
        let authority = read_local_authority_manifest_raw(&path).unwrap().unwrap();
        let versioned_path = local_snapshot_versions_dir(&path).join(&authority.snapshot_file);
        let bytes = std::fs::read(&versioned_path).unwrap();
        let (mut snapshot, persisted_root) =
            GraphSnapshot::from_bytes_with_persisted_root_hash(&bytes).unwrap();
        let original_graph_root = compute_graph_root_hash(&snapshot);
        snapshot.admit_artifact_for_test(
            "tampered-non-entity.rs".to_string(),
            crate::types::regular_tree_entry(8),
        );
        assert_eq!(
            compute_graph_root_hash(&snapshot),
            original_graph_root,
            "entity/relation root intentionally does not cover file-hash truth"
        );
        let tampered = snapshot
            .to_bytes_with_persisted_root_hash(persisted_root.unwrap())
            .unwrap();
        mmap::atomic_write_bytes(&versioned_path, &tampered).unwrap();

        let error = match SnapshotManager::open_without_text_index(&path) {
            Ok(_) => panic!("exact serialized authority must reject non-entity tampering"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("authoritative local snapshot digest mismatch"),
            "unexpected serialized-authority error: {error}"
        );
    }

    #[test]
    fn local_snapshot_replay_validates_the_exact_delta_bytes_it_applies() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let graph = InMemoryGraph::new();
        let (_, base_generation) =
            SnapshotManager::save_graph_with_generation(&path, &graph).unwrap();
        graph
            .upsert_entity(&test_entity("committed_delta"))
            .unwrap();
        let head_generation = SnapshotManager::save_graph_delta(&path, &graph, base_generation)
            .unwrap()
            .expect("mutation must append a delta");

        let delta_path = local_delta_path(&path, head_generation);
        let replacement = GraphSnapshotDelta::empty(base_generation)
            .to_bytes()
            .unwrap();
        set_local_delta_before_apply_read_hook(move || {
            mmap::atomic_write_bytes_no_magic(&delta_path, &replacement).unwrap();
        });

        let error = match SnapshotManager::open_without_text_index(&path) {
            Ok(_) => panic!("replay must hash the same bytes it is about to parse and apply"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("while loading replay bytes"),
            "unexpected replay race error: {error}"
        );
    }

    #[test]
    fn local_snapshot_revalidates_retired_delta_replaced_after_manifest_read() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        graph.upsert_entity(&test_entity("base")).unwrap();
        mgr.save().unwrap();
        let base_generation = mgr.generation();
        graph.upsert_entity(&test_entity("retired_delta")).unwrap();
        let delta_generation = mgr.save_delta().unwrap().unwrap();
        drop(mgr);

        set_local_full_save_before_delta_cleanup_hook(|| {
            panic!("simulated crash before canonical delta cleanup")
        });
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            SnapshotManager::save_graph_with_expected_generation(
                &path,
                graph.as_ref(),
                delta_generation,
            )
            .unwrap();
        }));
        assert!(crashed.is_err());
        assert!(local_delta_path(&path, delta_generation).exists());

        let replacement_path = local_delta_path(&path, delta_generation);
        let replacement = GraphSnapshotDelta::empty(base_generation)
            .to_bytes()
            .unwrap();
        set_local_delta_before_apply_read_hook(move || {
            mmap::atomic_write_bytes_no_magic(&replacement_path, &replacement).unwrap();
        });
        let error = match SnapshotManager::open_without_text_index(&path) {
            Ok(_) => panic!("retired bytes replaced after manifest validation must fail closed"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("retired local delta digest mismatch"),
            "unexpected retired replay race error: {error}"
        );
    }

    #[test]
    fn full_promotion_preserves_replaced_captured_delta_and_reopen_fails_closed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        graph.upsert_entity(&test_entity("base")).unwrap();
        mgr.save().unwrap();
        let base_generation = mgr.generation();
        graph.upsert_entity(&test_entity("captured_delta")).unwrap();
        let delta_generation = mgr
            .save_delta()
            .unwrap()
            .expect("mutation must append a delta");
        drop(mgr);

        let delta_path = local_delta_path(&path, delta_generation);
        let replacement = GraphSnapshotDelta::empty(base_generation)
            .to_bytes()
            .unwrap();
        let expected_replacement = replacement.clone();
        let replaced_path = delta_path.clone();
        set_local_full_save_before_delta_cleanup_hook(move || {
            mmap::atomic_write_bytes_no_magic(&replaced_path, &replacement).unwrap();
        });

        let (_, promoted_generation) =
            SnapshotManager::save_graph_with_generation(&path, graph.as_ref()).unwrap();
        assert_eq!(promoted_generation, delta_generation + 1);
        let residuals: Vec<_> = std::fs::read_dir(local_delta_dir_for(&path))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.is_file())
            .collect();
        assert_eq!(residuals.len(), 1);
        assert_eq!(
            std::fs::read(&residuals[0]).unwrap(),
            expected_replacement,
            "cleanup must preserve the replacement bytes that won the path race"
        );
        let authority = read_local_authority_manifest_raw(&path).unwrap().unwrap();
        assert!(authority
            .retired_deltas
            .iter()
            .any(|identity| identity.generation == delta_generation));

        let error = match SnapshotManager::open_without_text_index(&path) {
            Ok(_) => panic!("replaced retired journal bytes must keep recovery fail-closed"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("quarantined delta digest mismatch"),
            "unexpected residual-journal error: {error}"
        );
    }

    #[test]
    fn local_snapshot_reopen_finalizes_exact_quarantine_left_by_cleanup_crash() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        graph.upsert_entity(&test_entity("base")).unwrap();
        mgr.save().unwrap();
        graph.upsert_entity(&test_entity("retired_delta")).unwrap();
        let delta_generation = mgr.save_delta().unwrap().unwrap();
        drop(mgr);

        set_local_cleanup_after_quarantine_hook(|| panic!("simulated cleanup crash"));
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            SnapshotManager::save_graph_with_expected_generation(
                &path,
                graph.as_ref(),
                delta_generation,
            )
            .unwrap();
        }));
        assert!(crashed.is_err());
        assert!(!local_delta_path(&path, delta_generation).exists());
        let quarantined: Vec<_> = std::fs::read_dir(local_delta_dir_for(&path))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".kin-journal-cleanup-"))
            })
            .collect();
        assert_eq!(quarantined.len(), 1);

        let reopened = SnapshotManager::open_without_text_index(&path)
            .expect("exact authority-bound quarantine must be finalized on reopen");
        assert_eq!(reopened.generation(), delta_generation + 1);
        assert!(!quarantined[0].exists());
    }

    #[test]
    fn locate_and_writes_reject_quarantine_without_authority() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let graph = InMemoryGraph::new();
        let delta_bytes = GraphSnapshotDelta::empty(GENERATION_INIT)
            .to_bytes()
            .unwrap();
        let canonical = local_delta_path(&path, 1);
        std::fs::create_dir_all(local_delta_dir_for(&path)).unwrap();
        let quarantine =
            quarantine_delta_path(&canonical, 1, &hex::encode(Sha256::digest(&delta_bytes)));
        std::fs::write(&quarantine, &delta_bytes).unwrap();

        let locate_error = match SnapshotManager::open_read_only_for_locate(&path) {
            Ok(_) => panic!("locate-only open must not bypass unbound quarantine"),
            Err(error) => error,
        };
        assert!(locate_error
            .to_string()
            .contains("no current snapshot authority"));

        let delta = GraphSnapshotDelta::empty(GENERATION_INIT);
        let delta_error = write_local_delta(&path, &delta, GENERATION_INIT)
            .expect_err("delta bootstrap must reject unbound quarantine");
        assert!(delta_error
            .to_string()
            .contains("no current snapshot authority"));
        assert!(!local_authority_path(&path).exists());

        let full_error =
            SnapshotManager::save_graph_with_expected_generation(&path, &graph, GENERATION_INIT)
                .expect_err("full promotion must reject unbound quarantine");
        assert!(full_error
            .to_string()
            .contains("no current snapshot authority"));
        assert!(quarantine.exists());
    }

    #[test]
    fn quarantine_cleanup_waits_for_authoritative_root_verification() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        graph.upsert_entity(&test_entity("base")).unwrap();
        mgr.save().unwrap();
        graph.upsert_entity(&test_entity("retired_delta")).unwrap();
        let delta_generation = mgr.save_delta().unwrap().unwrap();
        drop(mgr);

        set_local_cleanup_after_quarantine_hook(|| panic!("leave exact quarantine"));
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            SnapshotManager::save_graph_with_expected_generation(
                &path,
                graph.as_ref(),
                delta_generation,
            )
            .unwrap();
        }));
        assert!(crashed.is_err());
        let quarantine = std::fs::read_dir(local_delta_dir_for(&path))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| is_quarantine_delta_name(path))
            .expect("cleanup crash must leave a quarantine");

        let mut authority = read_local_authority_manifest_raw(&path).unwrap().unwrap();
        authority.snapshot_root_hash = hex::encode([0xA5; 32]);
        write_local_authority(&path, &authority).unwrap();
        let error = match SnapshotManager::open_without_text_index(&path) {
            Ok(_) => panic!("authority root mismatch must fail before quarantine cleanup"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("root trailer does not match"));
        assert!(
            quarantine.exists(),
            "forensic quarantine must survive failed authority root verification"
        );
    }

    #[test]
    fn mutations_and_exact_retry_reject_bad_authority_root_without_quarantine() {
        let dir = TempDir::new().unwrap();

        let delta_path_root = dir.path().join("delta-root.kndb");
        let delta_graph = InMemoryGraph::new();
        let (_, delta_generation) =
            SnapshotManager::save_graph_with_generation(&delta_path_root, &delta_graph).unwrap();
        let mut delta_authority = read_local_authority_manifest_raw(&delta_path_root)
            .unwrap()
            .unwrap();
        delta_authority.snapshot_root_hash = hex::encode([0xB6; 32]);
        write_local_authority(&delta_path_root, &delta_authority).unwrap();
        let delta = GraphSnapshotDelta::empty(delta_generation);
        let delta_error = write_local_delta(&delta_path_root, &delta, delta_generation)
            .expect_err("delta mutation must reject a mismatched authority root");
        assert!(delta_error
            .to_string()
            .contains("root trailer does not match"));
        assert!(!local_delta_path(&delta_path_root, delta_generation + 1).exists());

        let retry_path = dir.path().join("retry-root.kndb");
        let retry_graph = InMemoryGraph::new();
        SnapshotManager::save_graph_with_generation(&retry_path, &retry_graph).unwrap();
        let mut retry_authority = read_local_authority_manifest_raw(&retry_path)
            .unwrap()
            .unwrap();
        retry_authority.snapshot_root_hash = hex::encode([0xC7; 32]);
        write_local_authority(&retry_path, &retry_authority).unwrap();
        let retry_error = SnapshotManager::save_graph_with_expected_generation(
            &retry_path,
            &retry_graph,
            GENERATION_INIT,
        )
        .expect_err("exact full retry must reject a mismatched authority root");
        assert!(retry_error
            .to_string()
            .contains("root trailer does not match"));
    }

    #[test]
    fn local_snapshot_full_save_rejects_a_staged_next_delta_before_commit() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let graph = InMemoryGraph::new();
        let (_, generation) = SnapshotManager::save_graph_with_generation(&path, &graph).unwrap();
        std::fs::create_dir_all(local_delta_dir_for(&path)).unwrap();
        mmap::atomic_write_bytes_no_magic(
            &local_delta_path(&path, generation + 1),
            &GraphSnapshotDelta::empty(generation).to_bytes().unwrap(),
        )
        .unwrap();

        let error = SnapshotManager::save_graph_with_expected_generation(&path, &graph, generation)
            .expect_err("full save must not commit over a staged next-generation delta");
        assert!(error.to_string().contains("staged unacknowledged delta"));
        assert_eq!(
            read_local_authority_manifest_raw(&path)
                .unwrap()
                .unwrap()
                .head_generation,
            generation
        );
    }

    #[test]
    fn local_snapshot_full_save_rechecks_staged_delta_before_authority_commit() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let graph = InMemoryGraph::new();
        let (_, generation) = SnapshotManager::save_graph_with_generation(&path, &graph).unwrap();
        let staged_path = local_delta_path(&path, generation + 1);
        set_local_full_save_before_authority_commit_hook(move || {
            std::fs::create_dir_all(staged_path.parent().unwrap()).unwrap();
            mmap::atomic_write_bytes_no_magic(
                &staged_path,
                &GraphSnapshotDelta::empty(generation).to_bytes().unwrap(),
            )
            .unwrap();
        });

        let error = SnapshotManager::save_graph_with_expected_generation(&path, &graph, generation)
            .expect_err("the pre-commit rescan must catch a staged delta from a racing writer");
        assert!(error.to_string().contains("staged unacknowledged delta"));
        assert_eq!(
            read_local_authority_manifest_raw(&path)
                .unwrap()
                .unwrap()
                .head_generation,
            generation
        );
    }

    #[test]
    fn static_full_save_cas_rejects_stale_generation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let graph = InMemoryGraph::new();
        let (_, generation) = SnapshotManager::save_graph_with_generation(&path, &graph).unwrap();
        let stale_graph = InMemoryGraph::new();
        stale_graph
            .upsert_entity(&test_entity("stale_different_content"))
            .unwrap();
        let error = SnapshotManager::save_graph_with_expected_generation(
            &path,
            &stale_graph,
            GENERATION_INIT,
        )
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
        let (captured_bytes, captured_root, captured_retrieval_authority, epoch) = graph
            .begin_snapshot_persistence_with_retrieval_hash(None)
            .unwrap();

        // This mutation arrives after the graph bytes/root were detached but
        // before their derived sidecars are persisted.
        entity.name = "newerepochtoken".into();
        entity.signature = "fn newerepochtoken()".into();
        graph.upsert_entity(&entity).unwrap();

        #[cfg(feature = "vector")]
        {
            write_vector_index_metadata(
                &vector_index_metadata_path_for(&path),
                &current_vector_metadata(captured_retrieval_authority, 4, 1, "detached-sidecar"),
            )
            .unwrap();
        }

        SnapshotManager::persist_snapshot_sidecars_for_epoch(
            &path,
            graph.as_ref(),
            captured_root,
            captured_retrieval_authority,
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

        // Simulate an exact authority commit from the detached capture.
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
                snapshot_sha256: hex::encode(Sha256::digest(&captured_bytes)),
                snapshot_retrieval_authority_hash: hex::encode(captured_retrieval_authority),
                acknowledged_deltas: Vec::new(),
                retired_deltas: Vec::new(),
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

        let change = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([8; 32])),
            parents: Vec::new(),
            timestamp: Timestamp::now(),
            author: AuthorId::new("tester"),
            message: "cochange".into(),
            entity_deltas: vec![EntityDelta::Added {
                new: caller.clone(),
            }],
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            projected_files: vec![FilePathId::new("src/main.rs")],
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
        });
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
        graph.admit_artifact_for_test("src/main.rs", crate::types::regular_tree_entry(3));
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
    fn open_read_only_for_locate_decodes_snapshot_with_resolved_tree() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();

        let caller = test_entity("caller");
        let mut callee = test_entity("callee");
        callee.file_origin = Some(FilePathId::new("src/lib.rs"));
        let helper = test_entity("helper");

        let change = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([8; 32])),
            parents: Vec::new(),
            timestamp: Timestamp::now(),
            author: AuthorId::new("tester"),
            message: "cochange".into(),
            entity_deltas: vec![EntityDelta::Added {
                new: caller.clone(),
            }],
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            projected_files: vec![FilePathId::new("src/main.rs")],
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
        });

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

        // A non-empty resolved tree exercises the positional field that the
        // locate decoder must preserve as identity-bearing repository truth.
        graph.admit_artifact_for_test("src/main.rs", crate::types::regular_tree_entry(7));
        graph.admit_artifact_for_test("src/lib.rs", crate::types::regular_tree_entry(9));

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
        let authority = read_local_authority_manifest(&path).unwrap().unwrap();
        let graph_root_hash = local_authority_root_hash(&authority).unwrap();
        let retrieval_authority_hash =
            local_authority_retrieval_authority_hash(&authority).unwrap();
        SnapshotManager::store_locate_cache(
            &path,
            local_authority_snapshot_sha256(&authority).unwrap(),
            graph_root_hash,
            retrieval_authority_hash,
            &locate_snapshot,
        )
        .unwrap();
        assert!(locate_cache_path_for(&path).exists());

        let mut stale_digest = local_authority_snapshot_sha256(&authority).unwrap();
        stale_digest[0] ^= 0xff;
        assert!(
            SnapshotManager::load_locate_cache(
                &path,
                stale_digest,
                graph_root_hash,
                retrieval_authority_hash,
            )
            .unwrap()
            .is_none(),
            "a cache from different authoritative snapshot bytes must be ignored"
        );
    }

    #[test]
    fn locate_cache_rejects_admission_valid_projection_tampering() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let mgr = SnapshotManager::new(&path);
        let graph = mgr.graph();
        graph.upsert_entity(&test_entity("authoritative")).unwrap();
        mgr.save().unwrap();

        let authority = read_local_authority_manifest(&path).unwrap().unwrap();
        let snapshot_sha256 = local_authority_snapshot_sha256(&authority).unwrap();
        let graph_root_hash = local_authority_root_hash(&authority).unwrap();
        let retrieval_authority_hash =
            local_authority_retrieval_authority_hash(&authority).unwrap();
        let locate_snapshot =
            crate::storage::format::LocateGraphSnapshot::from(graph.to_snapshot());
        SnapshotManager::store_locate_cache(
            &path,
            snapshot_sha256,
            graph_root_hash,
            retrieval_authority_hash,
            &locate_snapshot,
        )
        .unwrap();

        let cache_path = locate_cache_path_for(&path);
        let mut cache: LocateSnapshotCache =
            rmp_serde::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();
        let mut injected = test_entity("cache_only");
        injected.file_origin = None;
        cache.snapshot.entities.insert(injected.id, injected);
        std::fs::write(&cache_path, rmp_serde::to_vec(&cache).unwrap()).unwrap();

        assert!(
            SnapshotManager::load_locate_cache(
                &path,
                snapshot_sha256,
                graph_root_hash,
                retrieval_authority_hash,
            )
            .unwrap()
            .is_none(),
            "a mutable cache cannot self-assert the authoritative snapshot digest"
        );
    }

    #[test]
    fn locate_cache_load_and_store_validate_change_identity() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let digest = [0x51; 32];
        let spoofed = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x52; 32])),
            parents: Vec::new(),
            timestamp: Timestamp::now(),
            author: AuthorId::new("attacker"),
            message: "spoofed locate cache".into(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
        };
        let mut snapshot = crate::storage::format::LocateGraphSnapshot::from(
            crate::storage::GraphSnapshot::empty(),
        );
        snapshot.changes.insert(spoofed.id, spoofed);

        assert!(
            SnapshotManager::store_locate_cache(&path, digest, [0; 32], [0; 32], &snapshot)
                .is_err(),
            "the normal cache write path must reject spoofed identities"
        );

        let raw_cache = LocateSnapshotCache {
            version: LOCATE_CACHE_VERSION,
            snapshot_sha256: digest,
            snapshot,
        };
        std::fs::write(
            locate_cache_path_for(&path),
            rmp_serde::to_vec(&raw_cache).unwrap(),
        )
        .unwrap();
        assert!(
            SnapshotManager::load_locate_cache(&path, digest, [0; 32], [0; 32]).is_err(),
            "raw cache hydration must independently validate spoofed identities"
        );
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
    fn raw_canonical_snapshot_without_current_authority_is_rejected() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        std::fs::write(&path, GraphSnapshot::empty().to_bytes().unwrap()).unwrap();

        let error = match SnapshotManager::open_without_text_index(&path) {
            Ok(_) => panic!("unbound snapshot bytes must not become graph authority"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("unbound snapshot bytes but no current snapshot authority"),
            "unexpected unbound snapshot error: {error}"
        );
    }

    #[test]
    fn full_save_writes_only_current_authority_and_immutable_payload() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let graph = InMemoryGraph::new();

        let (_, generation) = SnapshotManager::save_graph_with_generation(&path, &graph).unwrap();
        let authority = read_local_authority_manifest(&path).unwrap().unwrap();

        assert_eq!(authority.head_generation, generation);
        assert!(local_authority_path(&path).exists());
        assert!(local_versioned_snapshot_path(&path, generation).exists());
        assert!(
            !path.exists(),
            "the requested path is a logical namespace, not persisted graph bytes"
        );
    }

    #[test]
    fn local_authority_accepts_only_the_exact_current_manifest_shape() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        SnapshotManager::save_graph_with_generation(&path, &InMemoryGraph::new()).unwrap();
        let authority_path = local_authority_path(&path);
        let current: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&authority_path).unwrap()).unwrap();

        for rejected_version in [1, 2] {
            let mut candidate = current.clone();
            candidate["version"] = serde_json::json!(rejected_version);
            mmap::atomic_write_bytes_no_magic(
                &authority_path,
                &serde_json::to_vec(&candidate).unwrap(),
            )
            .unwrap();
            let error = read_local_authority_manifest(&path)
                .expect_err("old manifest versions must not be migrated");
            assert!(
                error
                    .to_string()
                    .contains("unsupported local snapshot authority version"),
                "unexpected old-version error: {error}"
            );
        }

        for required_field in ["acknowledged_deltas", "retired_deltas"] {
            let mut candidate = current.clone();
            candidate.as_object_mut().unwrap().remove(required_field);
            mmap::atomic_write_bytes_no_magic(
                &authority_path,
                &serde_json::to_vec(&candidate).unwrap(),
            )
            .unwrap();
            let error = read_local_authority_manifest(&path)
                .expect_err("current manifest identity arrays are required");
            assert!(
                error.to_string().contains(required_field),
                "unexpected missing-field error for {required_field}: {error}"
            );
        }
    }

    #[test]
    fn graph_kindb_directory_stays_under_the_requested_parent() {
        let requested = PathBuf::from(".kin/graph/kindb");
        assert_eq!(
            normalize_snapshot_path(requested.clone()),
            requested.join("graph.kndb")
        );
    }

    #[test]
    fn missing_base_with_delta_journal_must_not_open_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        std::fs::create_dir_all(local_delta_dir_for(&path)).unwrap();
        mmap::atomic_write_bytes_no_magic(
            &local_delta_path(&path, 1),
            &GraphSnapshotDelta::empty(GENERATION_INIT)
                .to_bytes()
                .unwrap(),
        )
        .unwrap();

        let error = match SnapshotManager::open_without_text_index(&path) {
            Ok(_) => panic!("a journal without a base must never open as an empty graph"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("persisted deltas but no current snapshot authority"));
        let locate_error = match SnapshotManager::open_read_only_for_locate(&path) {
            Ok(_) => panic!("locate-only open must enforce the same missing-base journal fence"),
            Err(error) => error,
        };
        assert!(locate_error
            .to_string()
            .contains("persisted deltas but no current snapshot authority"));
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
        let change = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([2; 32])),
            parents: vec![base_change],
            timestamp: Timestamp::now(),
            author: AuthorId::new("tester"),
            message: "snapshot roundtrip".into(),
            entity_deltas: vec![EntityDelta::Added {
                new: entity.clone(),
            }],
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            projected_files: vec![FilePathId::new("src/main.rs")],
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
        });
        graph.create_change(&change).unwrap();

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
        graph.admit_artifact_for_test("src/main.rs", crate::types::regular_tree_entry(9));
        graph.admit_artifact_for_test("Makefile", crate::types::regular_tree_entry(5));
        graph.admit_artifact_for_test("assets/logo.svg", crate::types::regular_tree_entry(6));
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
        assert_eq!(graph.list_shallow_files().unwrap().len(), 1);
        assert_eq!(graph.list_structured_artifacts().unwrap().len(), 1);
        assert_eq!(graph.list_opaque_artifacts().unwrap().len(), 1);
        assert_eq!(
            graph.tree_entry_for_test("src/main.rs"),
            Some(regular_tree_entry(9))
        );
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
        install_current_test_vector_index(graph.as_ref(), &vectors, &vector_path);

        mgr.save().unwrap();

        let metadata = read_vector_index_metadata(&metadata_path)
            .unwrap()
            .expect("vector metadata should be written");
        assert_eq!(
            metadata.graph_root_hash,
            hex::encode(graph.retrieval_authority_hash())
        );
        assert_eq!(metadata.dimensions, 4);
        assert_eq!(metadata.indexed, 1);
        #[cfg(feature = "embeddings")]
        assert_eq!(metadata.embedding_provider, "local");
        #[cfg(not(feature = "embeddings"))]
        assert_eq!(metadata.embedding_provider, "external");
    }

    #[test]
    fn exact_tree_change_rebuilds_persisted_text_without_retired_artifact_docs() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        let file_id = FilePathId::new("compose.yaml");
        let old_entry = TreeEntry::blob(Hash256::from_bytes([0x61; 32]), false);
        let new_entry = TreeEntry::blob(Hash256::from_bytes([0x62; 32]), false);
        let artifact_id = graph.admit_artifact_for_test(&file_id.0, old_entry);
        graph
            .upsert_structured_artifact(&StructuredArtifact {
                file_id: file_id.clone(),
                kind: ArtifactKind::ComposeFile,
                content_hash: Hash256::from_bytes([0x61; 32]),
                text_preview: Some("obsolete_compose_sidecar_token".into()),
            })
            .unwrap();
        mgr.save().unwrap();
        let before_authority = graph.retrieval_authority_hash();

        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: LocatedEntry::new(RepoPath::from_utf8(&file_id.0).unwrap(), old_entry),
                    new: LocatedEntry::new(RepoPath::from_utf8(&file_id.0).unwrap(), new_entry),
                }],
                admission_policy_delta: None,
            })
            .unwrap();
        assert_ne!(before_authority, graph.retrieval_authority_hash());
        mgr.save().unwrap();
        drop(graph);
        drop(mgr);

        let reopened = SnapshotManager::open_read_only(&snapshot_path).unwrap();
        assert!(
            reopened
                .graph()
                .text_search("obsolete_compose_sidecar_token", 10)
                .unwrap()
                .is_empty(),
            "retired artifact text must not survive a cold reopen"
        );
    }

    #[test]
    #[cfg(feature = "vector")]
    fn exact_tree_change_rejects_preserved_vector_sidecar_with_same_graph_root() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);
        let metadata_path = vector_index_metadata_path_for(&snapshot_path);

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        let file_id = FilePathId::new("Dockerfile");
        let old_entry = TreeEntry::blob(Hash256::from_bytes([0x63; 32]), false);
        let new_entry = TreeEntry::blob(Hash256::from_bytes([0x64; 32]), false);
        let artifact_id = graph.admit_artifact_for_test(&file_id.0, old_entry);
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: file_id.clone(),
                content_hash: Hash256::from_bytes([0x63; 32]),
                mime_type: Some("text/plain".into()),
                text_preview: Some("FROM old".into()),
            })
            .unwrap();
        let vectors = VectorIndex::new(4).unwrap();
        vectors
            .upsert_retrievable(RetrievalKey::Artifact(artifact_id), &[1.0, 0.0, 0.0, 0.0])
            .unwrap();
        install_current_test_vector_index(graph.as_ref(), &vectors, &vector_path);
        mgr.save().unwrap();
        let original_graph_root = graph.compute_root_hash();
        let original_metadata = read_vector_index_metadata(&metadata_path).unwrap().unwrap();
        let replacement_snapshot = graph.to_snapshot();
        drop(graph);
        drop(mgr);

        // Rehydrate without loading the vector sidecar, then commit a tree-only
        // change. The old `.kvec` is deliberately preserved on disk; its exact
        // retrieval-authority stamp must make it ineligible.
        let replacement = InMemoryGraph::from_snapshot(replacement_snapshot).unwrap();
        replacement
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: LocatedEntry::new(RepoPath::from_utf8(&file_id.0).unwrap(), old_entry),
                    new: LocatedEntry::new(RepoPath::from_utf8(&file_id.0).unwrap(), new_entry),
                }],
                admission_policy_delta: None,
            })
            .unwrap();
        assert_eq!(
            replacement.compute_root_hash(),
            original_graph_root,
            "the legacy graph root cannot detect a tree-only change"
        );
        SnapshotManager::save_graph(&snapshot_path, &replacement).unwrap();
        assert_eq!(
            read_vector_index_metadata(&metadata_path)
                .unwrap()
                .unwrap()
                .graph_root_hash,
            original_metadata.graph_root_hash,
            "an unloaded sidecar remains intact rather than being destroyed"
        );

        let reopened = SnapshotManager::open_read_only(&snapshot_path).unwrap();
        assert_eq!(reopened.graph().embedding_status().indexed, 0);
        assert_eq!(
            reopened.graph().pending_artifact_embeddings(),
            0,
            "retired artifact enrichment leaves no vector document to rebuild"
        );
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
        install_current_test_vector_index(graph.as_ref(), &initial_vectors, &vector_path);
        mgr.save().unwrap();

        let updated_vectors = VectorIndex::new(4).unwrap();
        updated_vectors
            .upsert(first.id, &[1.0, 0.0, 0.0, 0.0])
            .unwrap();
        updated_vectors
            .upsert(second.id, &[0.0, 1.0, 0.0, 0.0])
            .unwrap();
        install_current_test_vector_index(graph.as_ref(), &updated_vectors, &vector_path);

        SnapshotManager::save_vector_index_for_graph(&snapshot_path, graph.as_ref(), None).unwrap();

        let metadata = read_vector_index_metadata(&metadata_path)
            .unwrap()
            .expect("vector metadata should be refreshed");
        assert_eq!(
            metadata.graph_root_hash,
            hex::encode(graph.retrieval_authority_hash())
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
            install_current_test_vector_index(graph.as_ref(), &vectors, &vector_path);
            mgr.save().unwrap();
            root_hash_before = compute_graph_root_hash(&graph.to_snapshot());

            // Simulate the next embed batch: add a second vector and persist ONLY
            // the kvec sidecar (no full graph re-save), exactly as a per-batch
            // incremental flush would. Then "crash" by dropping the manager with
            // no further save.
            let updated = VectorIndex::new(4).unwrap();
            updated.upsert(first.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
            updated.upsert(second.id, &[0.0, 1.0, 0.0, 0.0]).unwrap();
            install_current_test_vector_index(graph.as_ref(), &updated, &vector_path);
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
            install_current_test_vector_index(graph.as_ref(), &vectors, &vector_path);
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
    /// authoritative immutable snapshot bytes are byte-identical across the
    /// flush while the vector sidecar is written.
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

        let snapshot_payload_path = current_snapshot_payload_path(&snapshot_path);
        let snapshot_bytes_before = std::fs::read(&snapshot_payload_path).unwrap();

        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(entity.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        install_current_test_vector_index(graph.as_ref(), &vectors, &vector_path);

        let outcome =
            SnapshotManager::flush_embed_progress(&snapshot_path, graph.as_ref(), 1, None).unwrap();
        assert!(
            !outcome.full_snapshot,
            "an incremental embed batch must not take the full-snapshot path"
        );

        let snapshot_bytes_after = std::fs::read(&snapshot_payload_path).unwrap();
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
        install_current_test_vector_index(graph.as_ref(), &vectors, &vector_path);
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

    /// Repository-v6 owns graph/workspace durability outside the legacy local
    /// snapshot bundle. Its derived-only checkpoint must retain the same
    /// first-batch and in-flight throttle without creating graph.kndb.
    #[test]
    #[cfg(feature = "vector")]
    fn derived_vector_checkpoint_throttles_without_writing_graph_authority() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);
        let graph = InMemoryGraph::new();
        let embedded = test_entity("already_embedded");
        let pending = test_entity("still_pending");
        graph.upsert_entity(&embedded).unwrap();
        graph.upsert_entity(&pending).unwrap();

        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(embedded.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        install_current_test_vector_index(&graph, &vectors, &vector_path);
        graph.queue_missing_for_embedding();
        assert!(graph.pending_embeddings() > 0);

        std::fs::remove_file(&vector_path).unwrap();
        assert!(
            SnapshotManager::checkpoint_vector_index_for_graph(
                &snapshot_path,
                &graph,
                Some("fixture-embedder@1"),
            )
            .unwrap(),
            "the first derived-only batch must checkpoint"
        );
        assert!(vector_path.exists());
        assert!(
            !snapshot_path.exists(),
            "a derived checkpoint must never create graph authority"
        );

        std::fs::remove_file(&vector_path).unwrap();
        assert!(
            !SnapshotManager::checkpoint_vector_index_for_graph(
                &snapshot_path,
                &graph,
                Some("fixture-embedder@1"),
            )
            .unwrap(),
            "an immediate in-flight checkpoint must be throttled"
        );
        assert!(!vector_path.exists());
        assert!(!snapshot_path.exists());
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
            install_current_test_vector_index(graph.as_ref(), &vectors, &vector_path);
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

        graph.admit_artifact_for_test(
            "compose.yaml",
            TreeEntry::blob(Hash256::from_bytes([7; 32]), false),
        );
        mgr.save().unwrap();

        let persisted = crate::search::TextIndex::open_read_only(Some(&text_index_path)).unwrap();
        assert_eq!(
            persisted.graph_root_hash(),
            Some(graph.retrieval_authority_hash())
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
        let artifact_id = graph.admit_artifact_for_test(
            &artifact.file_id.0,
            TreeEntry::blob(artifact.content_hash, false),
        );
        graph.upsert_entity(&entity).unwrap();
        graph.upsert_structured_artifact(&artifact).unwrap();
        mgr.save().unwrap();

        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(entity.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        vectors
            .upsert_retrievable(RetrievalKey::Artifact(artifact_id), &[0.0, 1.0, 0.0, 0.0])
            .unwrap();
        vectors.save(&vector_path).unwrap();
        write_vector_index_metadata(
            &metadata_path,
            &current_vector_metadata([42u8; 32], 4, 1, "stale-sidecar"),
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
    #[cfg(all(feature = "vector", feature = "embeddings"))]
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
        let root_hash = graph.retrieval_authority_hash();
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
            &current_vector_metadata(root_hash, 4, 1, "model-swap-sidecar"),
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

    /// A .kvec without required metadata is stale regardless of its internal
    /// descriptor. It triggers a clean rebuild and is preserved on disk.
    #[test]
    #[cfg(feature = "vector")]
    fn unstamped_index_without_required_sidecar_is_stale() {
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("graph.kndb");
        let vector_path = vector_index_path_for(&snapshot_path);

        let mgr = SnapshotManager::new(&snapshot_path);
        let graph = mgr.graph();
        let entity = test_entity("unstamped_vector");
        graph.upsert_entity(&entity).unwrap();
        mgr.save().unwrap();

        let vectors = VectorIndex::new(4).unwrap();
        vectors.upsert(entity.id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        // No descriptor and no required sidecar metadata.
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
            "absent sidecar must not allow load for an unstamped index"
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
    #[cfg(feature = "vector")]
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
            &current_vector_metadata([42u8; 32], 4, 1, "preserved-sidecar"),
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
        let size_before = std::fs::metadata(current_snapshot_payload_path(&path))
            .unwrap()
            .len();

        // Compact — should remove the orphaned downstream warning
        let stats = mgr.compact().unwrap();
        assert_eq!(stats.orphaned_downstream_warnings_removed, 1);
        assert_eq!(stats.entities_before, 2);
        assert_eq!(stats.relations_before, 1);
        assert_eq!(stats.orphaned_relations_removed, 0); // relation is valid

        // Verify compacted snapshot is smaller or equal
        let size_after = std::fs::metadata(current_snapshot_payload_path(&path))
            .unwrap()
            .len();
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

    /// A read-only open where only .kvec exists must not load the index:
    /// required sidecar provenance is absent. The bytes are preserved and no
    /// metadata is synthesized.
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
        install_current_test_vector_index(graph.as_ref(), &vectors, &vector_path);

        mgr.save().unwrap();

        let metadata = read_vector_index_metadata(&metadata_path)
            .unwrap()
            .expect("vector metadata should exist after save");
        assert_eq!(
            metadata.graph_root_hash,
            hex::encode(graph.retrieval_authority_hash())
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
    fn persistent_lock_is_explicitly_released_on_manager_drop() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mgr = SnapshotManager::open(&path).unwrap();
        let retained_descriptor = mgr._lock_file.as_ref().unwrap().file.try_clone().unwrap();
        drop(mgr);

        // On Unix the duplicate shares the locked open-file description. A
        // close-only implementation leaves the lock held until the duplicate
        // is also closed; explicit unlock makes the reopen succeed immediately.
        let _mgr2 = SnapshotManager::open(&path).unwrap();
        assert_eq!(_mgr2.graph().entity_count(), 0);
        drop(retained_descriptor);
    }

    #[test]
    fn static_write_lock_is_explicitly_released_on_guard_drop() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let lock = SnapshotManager::acquire_static_write_lock(&path).unwrap();
        let retained_descriptor = lock.file.try_clone().unwrap();
        drop(lock);

        let _mgr = SnapshotManager::open(&path).unwrap();
        drop(retained_descriptor);
    }

    #[test]
    fn parallel_static_save_and_persistent_reopen_cycles_release_every_lock() {
        const WORKERS: usize = 4;
        const CYCLES: usize = 4;

        let dir = TempDir::new().unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(WORKERS));

        std::thread::scope(|scope| {
            for worker in 0..WORKERS {
                let path = dir.path().join(format!("worker-{worker}/graph.kndb"));
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    let graph = InMemoryGraph::new();
                    barrier.wait();

                    for _ in 0..CYCLES {
                        SnapshotManager::save_graph(&path, &graph).unwrap();
                        let manager = SnapshotManager::open(&path).unwrap();
                        drop(manager);
                    }
                });
            }
        });
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
        let old_path = FilePathId::new("config/old-name.yaml");
        let new_path = FilePathId::new("config/current.yaml");
        let entry = crate::types::regular_tree_entry(7);
        let artifact_id = graph.admit_artifact_for_test(&old_path.0, entry);
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: LocatedEntry::new(RepoPath::from_utf8(&old_path.0).unwrap(), entry),
                    new: LocatedEntry::new(RepoPath::from_utf8(&new_path.0).unwrap(), entry),
                }],
                admission_policy_delta: None,
            })
            .unwrap();

        // Save via borrowed path (now the default)
        SnapshotManager::save_graph(&snap_path, &graph).unwrap();

        // Load back and verify
        let loaded =
            crate::storage::mmap::MmapReader::open(&current_snapshot_payload_path(&snap_path))
                .unwrap();
        assert_eq!(loaded.entities.len(), 1);
        let loaded_entity = loaded.entities.get(&entity.id).unwrap();
        assert_eq!(loaded_entity.name, "RoundTrip");
        assert_eq!(loaded_entity.kind, EntityKind::Function);
        assert_eq!(loaded_entity.language, LanguageId::Rust);
        assert_eq!(
            loaded
                .resolved_tree
                .artifact_id_at_path(&RepoPath::from_utf8(&new_path.0).unwrap()),
            Some(artifact_id)
        );
        assert!(loaded
            .resolved_tree
            .artifact_id_at_path(&RepoPath::from_utf8(&old_path.0).unwrap())
            .is_none());
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
        let loaded =
            crate::storage::mmap::MmapReader::open(&current_snapshot_payload_path(&snap_path))
                .unwrap();
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

        let authority = read_local_authority_manifest(&snap_path).unwrap().unwrap();
        let versioned_path = local_snapshot_versions_dir(&snap_path).join(&authority.snapshot_file);
        let (loaded, persisted_root_hash) =
            crate::storage::mmap::MmapReader::open_with_persisted_root_hash(&versioned_path)
                .unwrap();
        assert_eq!(persisted_root_hash, Some(root_hash));
        assert_eq!(compute_graph_root_hash(&loaded), root_hash);
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
        install_current_test_vector_index(graph.as_ref(), &vectors, &vector_path);
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
        install_current_test_vector_index(graph.as_ref(), &vectors, &vector_path);
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
        let metadata = current_vector_metadata(root, 768, 1, "sha256-aabbcc");
        assert!(
            !vector_metadata_matches_graph(&metadata, root, Some("sha256-ddeeff")),
            "different embedder_identity must reject"
        );
    }

    #[test]
    #[cfg(feature = "vector")]
    fn vector_metadata_requires_a_bound_sidecar_identity() {
        let root = [1u8; 32];
        let metadata = current_vector_metadata(root, 768, 1, "sha256-aabbcc");
        let mut value = serde_json::to_value(&metadata).unwrap();
        value.as_object_mut().unwrap().remove("embedder_identity");
        assert!(serde_json::from_value::<VectorIndexMetadata>(value).is_err());
        assert!(
            vector_metadata_matches_graph(&metadata, root, None),
            "a bound sidecar remains valid when the caller adds no stricter producer pin"
        );
    }

    /// `vector_metadata_matches_graph`: matching identities on both sides loads.
    #[test]
    #[cfg(feature = "vector")]
    fn embedder_identity_match_loads() {
        let root = [1u8; 32];
        let metadata = current_vector_metadata(root, 768, 1, "sha256-aabbcc");
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
        install_current_test_vector_index(graph.as_ref(), &vectors, &vector_path);
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
            stored_metadata.embedder_identity, "build-v1",
            "embedder_identity must be persisted in sidecar"
        );

        // Same identity → loads.
        let root = graph.retrieval_authority_hash();
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
