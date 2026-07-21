// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Pluggable storage backend trait for graph snapshots.
//!
//! `StorageBackend` abstracts where snapshot bytes live — local filesystem
//! for CLI, GCS for cloud deployment. The daemon code calls
//! `backend.load_snapshot()` / `backend.save_snapshot()` without knowing
//! the underlying storage medium.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::KinDbError;
use crate::storage::format::GraphSnapshot;
use crate::storage::local_journal::{
    delete_quarantined_delta_exact, is_quarantine_delta_name, load_quarantined_deltas,
    quarantine_delta_path, quarantined_file_matches, sync_parent_directory,
};
use crate::storage::mmap::{self, AtomicWriteOutcome};

/// Generation counter for compare-and-swap writes.
///
/// On local filesystems this is a monotonically increasing counter persisted
/// alongside the snapshot. On GCS this maps directly to the object generation.
pub type Generation = u64;

/// Sentinel value indicating no prior generation exists (first write).
pub const GENERATION_INIT: Generation = 0;

pub(crate) fn validate_source_blob_repo_id(repo_id: &str) -> Result<(), KinDbError> {
    if repo_id.is_empty()
        || repo_id.len() > 255
        || matches!(repo_id, "." | "..")
        || !repo_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(KinDbError::StorageError(format!(
            "invalid repo id {repo_id:?} for immutable source blob storage"
        )));
    }
    Ok(())
}

pub(crate) fn verify_source_blob_digest(
    digest: [u8; 32],
    data: &[u8],
    authority: &str,
) -> Result<(), KinDbError> {
    let actual: [u8; 32] = Sha256::digest(data).into();
    if actual != digest {
        return Err(KinDbError::StorageError(format!(
            "immutable source blob digest mismatch for {authority}: requested {}, found {}",
            hex::encode(digest),
            hex::encode(actual)
        )));
    }
    Ok(())
}

pub(crate) fn checked_next_generation(
    generation: Generation,
    authority: &str,
) -> Result<Generation, KinDbError> {
    generation.checked_add(1).ok_or_else(|| {
        KinDbError::StorageError(format!(
            "generation exhausted at {generation} while allocating {authority}"
        ))
    })
}

/// Atomic persistence authority for a snapshot plus its acknowledged journal.
#[derive(Debug)]
pub struct SnapshotAuthority {
    pub snapshot_bytes: Vec<u8>,
    /// Generation represented by `snapshot_bytes` before journal replay.
    pub snapshot_generation: Generation,
    /// Last acknowledged generation. Every generation in
    /// `(snapshot_generation, head_generation]` must have one exact delta.
    pub head_generation: Generation,
}

pub type PersistedDelta = (Vec<u8>, Generation);
pub type SnapshotRecoveryState = (Option<SnapshotAuthority>, Vec<PersistedDelta>);

/// A snapshot reconstructed from durable base bytes plus its acknowledged
/// incremental-delta chain.
#[derive(Debug)]
pub struct RecoveredSnapshot {
    pub snapshot: GraphSnapshot,
    pub generation: Generation,
    pub deltas_applied: usize,
    pub deltas_seen: usize,
}

/// Load a backend snapshot and replay its complete authoritative delta chain.
///
/// Entries outside the authority's exact `(snapshot_generation,
/// head_generation]` range are unacknowledged or stale and are ignored. Every
/// generation inside that range is mandatory, ordered, and must declare the
/// immediately preceding generation as its base. Missing prefixes, missing
/// heads, duplicates, corrupt bytes, and gaps fail closed.
pub fn load_recovered_snapshot<B: StorageBackend + ?Sized>(
    backend: &B,
    repo_id: &str,
) -> Result<Option<RecoveredSnapshot>, KinDbError> {
    let (loaded, raw_deltas) = backend.load_recovery_state(repo_id)?;

    let Some(authority) = loaded else {
        if raw_deltas.is_empty() {
            return Ok(None);
        }
        return Err(KinDbError::StorageError(format!(
            "repo {repo_id} has {} persisted deltas but no base snapshot",
            raw_deltas.len()
        )));
    };

    if authority.snapshot_generation > authority.head_generation {
        return Err(KinDbError::StorageError(format!(
            "repo {repo_id} snapshot base generation {} exceeds acknowledged head {}",
            authority.snapshot_generation, authority.head_generation
        )));
    }

    let mut snapshot = GraphSnapshot::from_bytes(&authority.snapshot_bytes)?;
    let deltas_seen = raw_deltas.len();
    if authority.snapshot_generation == authority.head_generation {
        return Ok(Some(RecoveredSnapshot {
            snapshot,
            generation: authority.head_generation,
            deltas_applied: 0,
            deltas_seen,
        }));
    }
    let mut expected_generation = checked_next_generation(
        authority.snapshot_generation,
        &format!("repo {repo_id} recovery"),
    )?;
    let mut recovered_generation = authority.snapshot_generation;
    let mut applied = 0usize;
    let mut previous_generation = None;
    for (bytes, generation) in raw_deltas {
        if generation == GENERATION_INIT {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} delta journal contains reserved generation 0"
            )));
        }
        if previous_generation.is_some_and(|previous| generation <= previous) {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} delta journal is not strictly ordered: generation {generation} follows {}",
                previous_generation.expect("checked above")
            )));
        }
        previous_generation = Some(generation);

        if generation > authority.head_generation {
            // A delta staged before an authority-commit crash is not durable
            // authority. It may be overwritten by a retry at the same
            // generation and must never be attached speculatively.
            continue;
        }
        if generation != expected_generation {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} delta chain is incomplete: expected generation {expected_generation}, found {generation}"
            )));
        }
        let delta = crate::storage::delta::GraphSnapshotDelta::from_bytes(&bytes)?;
        let expected_base = generation - 1;
        if delta.base_generation != expected_base {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} delta generation {generation} declares base {}, expected {expected_base}",
                delta.base_generation
            )));
        }
        crate::storage::delta::apply_graph_delta(&mut snapshot, &delta);
        applied += 1;
        recovered_generation = generation;
        if generation < authority.head_generation {
            expected_generation =
                checked_next_generation(generation, &format!("repo {repo_id} recovery"))?;
        }
    }

    if recovered_generation != authority.head_generation {
        return Err(KinDbError::StorageError(format!(
            "repo {repo_id} delta chain ended at generation {recovered_generation}, acknowledged head is {}",
            authority.head_generation
        )));
    }

    Ok(Some(RecoveredSnapshot {
        snapshot,
        generation: authority.head_generation,
        deltas_applied: applied,
        deltas_seen,
    }))
}

/// Pluggable storage backend for graph snapshots and overlay state.
///
/// All methods are synchronous — the caller (daemon) can wrap in
/// `spawn_blocking` if needed. Implementations must be `Send + Sync`
/// so they can be shared across threads behind an `Arc`.
pub trait StorageBackend: Send + Sync {
    /// Whether this backend has a durable, CAS-safe incremental-delta write
    /// path. Backends must opt in; callers otherwise persist full snapshots.
    fn supports_incremental_deltas(&self) -> bool {
        false
    }

    /// Load snapshot bytes together with the persisted base and acknowledged
    /// journal-head generations. Backends with no incremental authority can
    /// use the default base=head representation.
    fn load_snapshot_authority(
        &self,
        repo_id: &str,
    ) -> Result<Option<SnapshotAuthority>, KinDbError> {
        Ok(self
            .load_snapshot(repo_id)?
            .map(|(snapshot_bytes, generation)| SnapshotAuthority {
                snapshot_bytes,
                snapshot_generation: generation,
                head_generation: generation,
            }))
    }

    /// Read snapshot authority and its journal from one coherent backend view.
    /// Transactional/lock-backed implementations override this so authority
    /// cannot move between the snapshot and journal reads.
    fn load_recovery_state(&self, repo_id: &str) -> Result<SnapshotRecoveryState, KinDbError> {
        let authority = self.load_snapshot_authority(repo_id)?;
        let since = authority
            .as_ref()
            .map_or(GENERATION_INIT, |authority| authority.snapshot_generation);
        let deltas = self.load_deltas_since(repo_id, since)?;
        Ok((authority, deltas))
    }

    /// Load a repo's graph snapshot.
    ///
    /// Returns `Ok(None)` if no snapshot exists yet (new repo).
    /// Returns `Ok(Some((bytes, generation)))` on success. `generation` is
    /// always the generation represented by those exact bytes. Backends with
    /// an acknowledged delta journal must return the base generation here,
    /// not the journal head. Callers that need the acknowledged head must use
    /// [`load_snapshot_authority`](Self::load_snapshot_authority) or
    /// [`load_recovered_snapshot`].
    fn load_snapshot(&self, repo_id: &str) -> Result<Option<(Vec<u8>, Generation)>, KinDbError>;

    /// Store immutable source bytes under their SHA-256 content identity.
    ///
    /// Implementations must validate that `data` hashes to `digest`, must
    /// never replace different bytes already stored under the same identity,
    /// and must treat an exact retry as success. Source blobs are deliberately
    /// separate from graph snapshots: snapshots retain the semantic history
    /// and its content hashes while this object namespace retains the exact
    /// bytes those hashes name.
    fn save_source_blob(
        &self,
        repo_id: &str,
        digest: [u8; 32],
        data: &[u8],
    ) -> Result<(), KinDbError> {
        let _ = (repo_id, digest, data);
        Err(KinDbError::StorageError(
            "immutable source blob storage is not supported by this backend".to_string(),
        ))
    }

    /// Load immutable source bytes by SHA-256 content identity.
    ///
    /// Implementations must verify the returned bytes against `digest` and
    /// fail closed on corruption. `Ok(None)` means the exact bytes were never
    /// persisted; callers must not repair that gap from a filesystem or Git
    /// fallback on an authority path.
    fn load_source_blob(
        &self,
        repo_id: &str,
        digest: [u8; 32],
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        let _ = (repo_id, digest);
        Err(KinDbError::StorageError(
            "immutable source blob storage is not supported by this backend".to_string(),
        ))
    }

    /// Save a snapshot with compare-and-swap semantics.
    ///
    /// `expected_gen` is the generation returned by the last `load_snapshot`
    /// for a journal-free snapshot. When an acknowledged journal exists, a
    /// caller promoting recovered bytes must use `RecoveredSnapshot::generation`.
    /// Passing the base generation returned with base bytes intentionally loses
    /// CAS against the later journal head. If stored authority has changed, the
    /// backend must return an error.
    ///
    /// On success returns the new generation.
    fn save_snapshot(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError>;

    /// Explicitly replace an ambiguous legacy journal with caller-reconciled
    /// full snapshot bytes.
    ///
    /// This is an upgrade/recovery operation, not an automatic replay path.
    /// The caller must first quiesce every pre-authority writer and construct
    /// `data` from preserved legacy artifacts. Implementations capture the
    /// exact visible journal, CAS the full snapshot against `expected_gen`,
    /// make the new authority durable before removing any captured artifact,
    /// and remove only the captured journal. If post-commit cleanup fails, the
    /// committed generation is still returned so the caller never retries
    /// from a stale cursor; remaining artifacts continue to fail closed until
    /// this operation is retried after reconciliation.
    fn rebuild_legacy_journal(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let _ = (repo_id, data, expected_gen);
        Err(KinDbError::StorageError(
            "legacy journal rebuild is not supported by this backend".to_string(),
        ))
    }

    /// Save a delta (incremental diff from a base snapshot generation).
    ///
    /// `delta_data` is the serialized `GraphSnapshotDelta` bytes. The delta
    /// is stored alongside the base snapshot and can be loaded via
    /// `load_deltas_since`. Backends that don't support deltas can return
    /// `Err` — callers should fall back to full snapshot save.
    ///
    /// `base_gen` is the generation of the snapshot this delta was computed
    /// against. On success returns the new generation.
    fn save_delta(
        &self,
        repo_id: &str,
        delta_data: &[u8],
        base_gen: Generation,
    ) -> Result<Generation, KinDbError>;

    /// Load all delta files for a repo since a given generation.
    ///
    /// Returns deltas ordered by generation (oldest first). Each entry
    /// contains the serialized delta bytes and the generation it was saved at.
    /// Callers deserialize with `GraphSnapshotDelta::from_bytes()` and apply
    /// sequentially.
    ///
    /// Returns `Ok(vec![])` if no deltas exist since the given generation.
    fn load_deltas_since(
        &self,
        repo_id: &str,
        since_gen: Generation,
    ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError>;

    /// Compact deltas: merge all deltas into the base snapshot, run GC
    /// to remove orphaned data, and remove the delta files.
    ///
    /// After compaction, the snapshot at the returned generation contains
    /// all changes with orphaned cross-references cleaned up, and no
    /// deltas remain. For large graphs (>500K entities) this also
    /// reclaims space from accumulated orphaned relations, stale test
    /// coverage entries, and other dangling references.
    ///
    /// Default implementation loads the snapshot, applies all deltas,
    /// runs `GraphSnapshot::compact()` for GC, saves the merged snapshot,
    /// and clears the delta journal.
    fn compact_deltas(&self, repo_id: &str) -> Result<Generation, KinDbError> {
        let recovered = load_recovered_snapshot(self, repo_id)?
            .ok_or_else(|| KinDbError::StorageError("no snapshot to compact".to_string()))?;
        if recovered.deltas_seen == 0 {
            return Ok(recovered.generation);
        }
        if recovered.deltas_applied == 0 {
            self.clear_deltas(repo_id)?;
            return Ok(recovered.generation);
        }

        // GC pass: remove orphaned cross-references accumulated over deltas
        let mut snapshot = recovered.snapshot;
        snapshot.compact();

        let merged_bytes = snapshot.to_bytes()?;
        let new_gen = self.save_snapshot(repo_id, &merged_bytes, recovered.generation)?;
        if let Err(error) = self.clear_deltas(repo_id) {
            // The full snapshot authority is already committed. Returning an
            // error here would strand the caller on `recovered.generation`
            // and make its retry collide with its own successful commit.
            tracing::warn!(
                repo_id,
                generation = new_gen,
                error = %error,
                "snapshot compaction committed; deferred stale delta cleanup"
            );
        }
        Ok(new_gen)
    }

    /// Remove all delta files for a repo. Called after compaction.
    fn clear_deltas(&self, repo_id: &str) -> Result<(), KinDbError>;

    /// Save ephemeral overlay state (for preemption recovery).
    fn save_overlay(&self, repo_id: &str, session_id: &str, data: &[u8]) -> Result<(), KinDbError>;

    /// Load overlay state (after preemption recovery).
    ///
    /// Returns `Ok(None)` if no overlay exists for this session.
    fn load_overlay(&self, repo_id: &str, session_id: &str) -> Result<Option<Vec<u8>>, KinDbError>;

    /// Delete an overlay after it has been committed or is no longer needed.
    ///
    /// Returns `Ok(())` if the overlay was deleted or did not exist.
    /// This prevents overlay accumulation on remote backends like GCS.
    fn delete_overlay(&self, repo_id: &str, session_id: &str) -> Result<(), KinDbError>;

    /// List all repo IDs available in storage.
    ///
    /// For local: list subdirectories in the base path that contain a `graph.kndb` file.
    /// For GCS: list top-level prefixes in the bucket under the configured prefix.
    fn list_repos(&self) -> Result<Vec<String>, KinDbError>;
}

/// Local filesystem storage backend for developer machines.
///
/// Layout under `base_path`:
/// ```text
/// {base_path}/{repo_id}/authority.json      — atomic base/head authority
/// {base_path}/{repo_id}/snapshots/GEN.kndb  — immutable snapshot versions
/// {base_path}/{repo_id}/graph.kndb          — compatibility projection
/// {base_path}/{repo_id}/graph.kndb.gen      — legacy generation counter
/// {base_path}/{repo_id}/source-blobs/sha256/HH/HASH — immutable exact source bytes
/// {base_path}/{repo_id}/overlays/{session_id}.bin — overlay state
/// ```
///
/// Snapshot and delta files are staged and fsynced before `authority.json` is
/// atomically replaced. That single authority rename is the commit point: a
/// crash before it leaves an ignored orphan, while a crash after it leaves a
/// complete base-to-head chain.
pub struct LocalFileBackend {
    base_path: PathBuf,
    #[cfg(test)]
    fail_before_authority_commit: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    fail_delta_cleanup: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    fail_legacy_rebuild_cleanup: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    recovery_after_authority_hook: parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    #[cfg(test)]
    compaction_before_delta_cleanup_hook:
        parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    #[cfg(test)]
    cleanup_after_quarantine_hook: parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    #[cfg(test)]
    snapshot_before_authority_commit_hook:
        parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    #[cfg(test)]
    snapshot_after_authority_before_projection_hook:
        parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
    #[cfg(test)]
    legacy_migration_before_cas_hook:
        parking_lot::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
}

const LOCAL_AUTHORITY_VERSION: u32 = 3;
const LOCAL_AUTHORITY_ACKNOWLEDGED_VERSION: u32 = 2;
const LOCAL_AUTHORITY_LEGACY_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct LocalDeltaIdentity {
    generation: Generation,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct LocalAuthorityRecord {
    version: u32,
    snapshot_generation: Generation,
    head_generation: Generation,
    snapshot_file: String,
    snapshot_sha256: String,
    /// Exact bytes acknowledged for every generation after the immutable
    /// snapshot base. A generation number alone is insufficient: a legacy
    /// writer can replace the deterministic delta filename without moving the
    /// authority head.
    #[serde(default)]
    acknowledged_deltas: Vec<LocalDeltaIdentity>,
    /// Exact journal bytes already represented by the promoted full snapshot
    /// but not necessarily removed yet. Cleanup may act only on these bytes.
    #[serde(default)]
    retired_deltas: Vec<LocalDeltaIdentity>,
}

const LOCAL_LEGACY_REBUILD_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalLegacyRebuildRecord {
    version: u32,
    expected_generation: Generation,
    committed_generation: Generation,
    /// Canonical delta filename plus the digest captured before authority
    /// promotion. Cleanup may remove only an exact match.
    captured_deltas: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalLegacyProjectionIdentity {
    snapshot_bytes: Option<Vec<u8>>,
    generation_bytes: Option<Vec<u8>>,
    generation: Generation,
}

impl LocalFileBackend {
    /// Create a new local backend rooted at `base_path`.
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            base_path: base_path.into(),
            #[cfg(test)]
            fail_before_authority_commit: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_delta_cleanup: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_legacy_rebuild_cleanup: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            recovery_after_authority_hook: parking_lot::Mutex::new(None),
            #[cfg(test)]
            compaction_before_delta_cleanup_hook: parking_lot::Mutex::new(None),
            #[cfg(test)]
            cleanup_after_quarantine_hook: parking_lot::Mutex::new(None),
            #[cfg(test)]
            snapshot_before_authority_commit_hook: parking_lot::Mutex::new(None),
            #[cfg(test)]
            snapshot_after_authority_before_projection_hook: parking_lot::Mutex::new(None),
            #[cfg(test)]
            legacy_migration_before_cas_hook: parking_lot::Mutex::new(None),
        }
    }

    /// Return the base path.
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    fn snapshot_path(&self, repo_id: &str) -> PathBuf {
        self.base_path.join(repo_id).join("graph.kndb")
    }

    fn generation_path(&self, repo_id: &str) -> PathBuf {
        self.base_path.join(repo_id).join("graph.kndb.gen")
    }

    fn authority_path(&self, repo_id: &str) -> PathBuf {
        self.base_path.join(repo_id).join("authority.json")
    }

    fn legacy_rebuild_path(&self, repo_id: &str) -> PathBuf {
        self.base_path
            .join(repo_id)
            .join("legacy-journal-rebuild.json")
    }

    fn snapshots_dir(&self, repo_id: &str) -> PathBuf {
        self.base_path.join(repo_id).join("snapshots")
    }

    fn versioned_snapshot_path(&self, repo_id: &str, generation: Generation) -> PathBuf {
        self.snapshots_dir(repo_id)
            .join(format!("{generation:020}.kndb"))
    }

    fn overlay_path(&self, repo_id: &str, session_id: &str) -> PathBuf {
        self.base_path
            .join(repo_id)
            .join("overlays")
            .join(format!("{session_id}.bin"))
    }

    fn source_blob_path(&self, repo_id: &str, digest: [u8; 32]) -> Result<PathBuf, KinDbError> {
        validate_source_blob_repo_id(repo_id)?;
        let digest = hex::encode(digest);
        Ok(self
            .base_path
            .join(repo_id)
            .join("source-blobs")
            .join("sha256")
            .join(&digest[..2])
            .join(digest))
    }

    fn deltas_dir(&self, repo_id: &str) -> PathBuf {
        self.base_path.join(repo_id).join("deltas")
    }

    fn delta_path(&self, repo_id: &str, gen: Generation) -> PathBuf {
        self.deltas_dir(repo_id).join(format!("{gen:020}.kndd"))
    }

    fn acquire_lock(&self, repo_id: &str) -> Result<std::fs::File, KinDbError> {
        let lock_path = self.base_path.join(repo_id).join(".lock");
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to create directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to open lock file {}: {e}",
                    lock_path.display()
                ))
            })?;
        use fs2::FileExt;
        lock_file.lock_exclusive().map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to acquire exclusive lock on {}: {e}",
                lock_path.display()
            ))
        })?;
        Ok(lock_file)
    }

    fn read_legacy_generation(&self, repo_id: &str) -> Result<Generation, KinDbError> {
        let gen_path = self.generation_path(repo_id);
        let bytes = match std::fs::symlink_metadata(&gen_path) {
            Ok(_) => mmap::read_regular_bounded(&gen_path, "legacy generation marker", 64 * 1024)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(GENERATION_INIT)
            }
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "failed to inspect generation file {}: {error}",
                    gen_path.display()
                )))
            }
        };
        let contents = std::str::from_utf8(&bytes).map_err(|error| {
            KinDbError::StorageError(format!(
                "invalid UTF-8 generation in {}: {error}",
                gen_path.display()
            ))
        })?;
        contents.trim().parse::<Generation>().map_err(|e| {
            KinDbError::StorageError(format!("invalid generation in {}: {e}", gen_path.display()))
        })
    }

    fn capture_legacy_projection_unlocked(
        &self,
        repo_id: &str,
    ) -> Result<LocalLegacyProjectionIdentity, KinDbError> {
        fn read_optional(path: &Path, role: &str) -> Result<Option<Vec<u8>>, KinDbError> {
            match std::fs::symlink_metadata(path) {
                Ok(_) => mmap::read_regular_file(path, role).map(Some),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(KinDbError::StorageError(format!(
                    "failed to capture {role} {}: {error}",
                    path.display()
                ))),
            }
        }

        let snapshot_path = self.snapshot_path(repo_id);
        let generation_path = self.generation_path(repo_id);
        let snapshot_bytes = read_optional(&snapshot_path, "legacy snapshot projection")?;
        let generation_bytes = read_optional(&generation_path, "legacy generation marker")?;
        let generation = match generation_bytes.as_deref() {
            Some(bytes) => std::str::from_utf8(bytes)
                .map_err(|error| {
                    KinDbError::StorageError(format!(
                        "invalid UTF-8 generation in {}: {error}",
                        generation_path.display()
                    ))
                })?
                .trim()
                .parse::<Generation>()
                .map_err(|error| {
                    KinDbError::StorageError(format!(
                        "invalid generation in {}: {error}",
                        generation_path.display()
                    ))
                })?,
            None => GENERATION_INIT,
        };
        Ok(LocalLegacyProjectionIdentity {
            snapshot_bytes,
            generation_bytes,
            generation,
        })
    }

    #[cfg(test)]
    fn write_generation(&self, repo_id: &str, gen: Generation) -> Result<(), KinDbError> {
        let gen_path = self.generation_path(repo_id);
        if let Some(parent) = gen_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to create directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
        mmap::atomic_write_bytes_no_magic(&gen_path, gen.to_string().as_bytes())
    }

    fn sync_parent(path: &Path) -> Result<(), KinDbError> {
        let Some(parent) = path.parent() else {
            return Ok(());
        };
        #[cfg(not(unix))]
        {
            let _ = parent;
            return Ok(());
        }
        #[cfg(unix)]
        {
            let directory = std::fs::File::open(parent).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to open directory {} for fsync: {error}",
                    parent.display()
                ))
            })?;
            directory.sync_all().map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to fsync directory {}: {error}",
                    parent.display()
                ))
            })
        }
    }

    fn atomic_write(path: &Path, data: &[u8]) -> Result<(), KinDbError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to create directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        mmap::atomic_write_bytes_no_magic(path, data)
    }

    fn snapshot_file_name(generation: Generation) -> String {
        format!("{generation:020}.kndb")
    }

    fn snapshot_digest(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn file_digest(path: &Path) -> Result<String, KinDbError> {
        let mut file = mmap::open_regular_nofollow(path, "digest source")?;
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
        Ok(hex::encode(hasher.finalize()))
    }

    fn validate_delta_identities(record: &LocalAuthorityRecord) -> Result<(), KinDbError> {
        // Version 1 committed only base/head numbers. A journal-bearing v1
        // record is intentionally accepted by the raw reader so the explicit
        // legacy rebuild path can capture and reconcile it; normal authority
        // reads reject it below before serving or writing.
        if record.version < LOCAL_AUTHORITY_VERSION && !record.retired_deltas.is_empty() {
            return Err(KinDbError::StorageError(format!(
                "local authority version {} cannot bind retired delta identities; version {LOCAL_AUTHORITY_VERSION} is required",
                record.version
            )));
        }
        if record.version == LOCAL_AUTHORITY_LEGACY_VERSION && record.acknowledged_deltas.is_empty()
        {
            return Ok(());
        }
        let expected_count = record
            .head_generation
            .checked_sub(record.snapshot_generation)
            .ok_or_else(|| {
                KinDbError::StorageError("local authority generation range underflow".to_string())
            })?;
        let expected_count = usize::try_from(expected_count).map_err(|_| {
            KinDbError::StorageError(
                "local authority delta range does not fit in memory".to_string(),
            )
        })?;
        if record.acknowledged_deltas.len() != expected_count {
            return Err(KinDbError::StorageError(format!(
                "local authority generation range {}..={} declares {} acknowledged delta identities; expected {expected_count}",
                record.snapshot_generation.saturating_add(1),
                record.head_generation,
                record.acknowledged_deltas.len()
            )));
        }
        for (offset, identity) in record.acknowledged_deltas.iter().enumerate() {
            let offset = Generation::try_from(offset).map_err(|_| {
                KinDbError::StorageError("local authority delta offset overflow".to_string())
            })?;
            let expected_generation = record
                .snapshot_generation
                .checked_add(offset)
                .and_then(|generation| generation.checked_add(1))
                .ok_or_else(|| {
                    KinDbError::StorageError(
                        "local authority delta generation overflow".to_string(),
                    )
                })?;
            if identity.generation != expected_generation {
                return Err(KinDbError::StorageError(format!(
                    "local authority delta identity {} names generation {}, expected {expected_generation}",
                    offset, identity.generation
                )));
            }
            if identity.sha256.len() != 64 || hex::decode(&identity.sha256).is_err() {
                return Err(KinDbError::StorageError(format!(
                    "local authority delta generation {} has an invalid SHA-256 digest",
                    identity.generation
                )));
            }
        }
        let mut bound_generations: std::collections::HashSet<Generation> = record
            .acknowledged_deltas
            .iter()
            .map(|identity| identity.generation)
            .collect();
        for identity in &record.retired_deltas {
            if identity.generation == GENERATION_INIT {
                return Err(KinDbError::StorageError(
                    "local authority has a retired delta at reserved generation 0".to_string(),
                ));
            }
            if identity.generation >= record.snapshot_generation {
                return Err(KinDbError::StorageError(format!(
                    "local authority retired delta generation {} is not older than snapshot generation {}",
                    identity.generation, record.snapshot_generation
                )));
            }
            if !bound_generations.insert(identity.generation) {
                return Err(KinDbError::StorageError(format!(
                    "local authority binds delta generation {} more than once",
                    identity.generation
                )));
            }
            if identity.sha256.len() != 64 || hex::decode(&identity.sha256).is_err() {
                return Err(KinDbError::StorageError(format!(
                    "local authority retired delta generation {} has an invalid SHA-256 digest",
                    identity.generation
                )));
            }
        }
        Ok(())
    }

    fn validate_acknowledged_deltas_unlocked(
        &self,
        repo_id: &str,
        record: &LocalAuthorityRecord,
    ) -> Result<(), KinDbError> {
        for (index, identity) in record.acknowledged_deltas.iter().enumerate() {
            let path = self.delta_path(repo_id, identity.generation);
            if !path.exists() {
                if let Some(next) = record.acknowledged_deltas[index + 1..]
                    .iter()
                    .find(|next| self.delta_path(repo_id, next.generation).exists())
                {
                    return Err(KinDbError::StorageError(format!(
                        "repo {repo_id} delta chain is incomplete: expected generation {}, found {}",
                        identity.generation, next.generation
                    )));
                }
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} delta chain ended at generation {}, acknowledged head is {}",
                    identity.generation - 1,
                    record.head_generation
                )));
            }
            let digest = Self::file_digest(&path).map_err(|error| {
                KinDbError::StorageError(format!(
                    "acknowledged delta generation {} for repo {repo_id} is unavailable: {error}",
                    identity.generation
                ))
            })?;
            if digest != identity.sha256 {
                return Err(KinDbError::StorageError(format!(
                    "acknowledged delta digest mismatch for repo {repo_id} generation {}: expected {}, found {digest}; a mixed-version writer replaced committed journal bytes",
                    identity.generation, identity.sha256
                )));
            }
        }
        Ok(())
    }

    fn validate_loaded_acknowledged_deltas(
        repo_id: &str,
        record: &LocalAuthorityRecord,
        deltas: &[(Vec<u8>, Generation)],
    ) -> Result<(), KinDbError> {
        for identity in &record.acknowledged_deltas {
            let Some((bytes, _)) = deltas
                .iter()
                .find(|(_, generation)| *generation == identity.generation)
            else {
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} delta chain ended before acknowledged generation {}",
                    identity.generation
                )));
            };
            let digest = Self::snapshot_digest(bytes);
            if digest != identity.sha256 {
                return Err(KinDbError::StorageError(format!(
                    "acknowledged delta digest mismatch for repo {repo_id} generation {} while loading recovery bytes: expected {}, found {digest}; a mixed-version writer replaced committed journal bytes",
                    identity.generation, identity.sha256
                )));
            }
        }
        Ok(())
    }

    fn validate_loaded_residual_deltas(
        repo_id: &str,
        record: &LocalAuthorityRecord,
        deltas: &[PersistedDelta],
    ) -> Result<(), KinDbError> {
        for (bytes, generation) in deltas {
            if let Some(identity) = record
                .acknowledged_deltas
                .iter()
                .find(|identity| identity.generation == *generation)
            {
                let digest = Self::snapshot_digest(bytes);
                if digest != identity.sha256 {
                    return Err(KinDbError::StorageError(format!(
                        "acknowledged delta digest mismatch for repo {repo_id} generation {generation} while loading recovery bytes: expected {}, found {digest}",
                        identity.sha256
                    )));
                }
                continue;
            }
            if let Some(identity) = record
                .retired_deltas
                .iter()
                .find(|identity| identity.generation == *generation)
            {
                let digest = Self::snapshot_digest(bytes);
                if digest != identity.sha256 {
                    return Err(KinDbError::StorageError(format!(
                        "retired delta digest mismatch for repo {repo_id} generation {generation}: expected {}, found {digest}; a mixed-version writer replaced bytes after full promotion",
                        identity.sha256
                    )));
                }
                continue;
            }
            if *generation <= record.head_generation {
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} authority head {} has an unbound residual delta at generation {generation}; recovery is fail-closed",
                    record.head_generation
                )));
            }
        }
        Ok(())
    }

    fn validate_residual_deltas_unlocked(
        &self,
        repo_id: &str,
        record: &LocalAuthorityRecord,
    ) -> Result<(), KinDbError> {
        let deltas = self.load_deltas_since_unlocked(repo_id, GENERATION_INIT)?;
        Self::validate_loaded_residual_deltas(repo_id, record, &deltas)
    }

    fn finalize_retired_quarantines_unlocked(
        &self,
        repo_id: &str,
        record: &LocalAuthorityRecord,
    ) -> Result<(), KinDbError> {
        let quarantined = load_quarantined_deltas(&self.deltas_dir(repo_id))?;
        for artifact in &quarantined {
            let Some(identity) = record
                .retired_deltas
                .iter()
                .find(|identity| identity.generation == artifact.generation)
            else {
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} has an unbound quarantined delta at generation {}; recovery is fail-closed",
                    artifact.generation
                )));
            };
            if identity.sha256 != artifact.sha256 {
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} quarantined delta identity mismatch at generation {}: authority binds {}, quarantine binds {}; recovery is fail-closed",
                    artifact.generation, identity.sha256, artifact.sha256
                )));
            }
        }
        for artifact in &quarantined {
            delete_quarantined_delta_exact(artifact)?;
        }
        Ok(())
    }

    fn reject_unbound_staged_deltas_unlocked(
        &self,
        repo_id: &str,
        record: Option<&LocalAuthorityRecord>,
    ) -> Result<(), KinDbError> {
        let head_generation = record.map_or(GENERATION_INIT, |record| record.head_generation);
        let deltas = self.load_deltas_since_unlocked(repo_id, GENERATION_INIT)?;
        if let Some((_, generation)) = deltas
            .iter()
            .find(|(_, generation)| *generation > head_generation)
        {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} has a staged unacknowledged delta at generation {generation} above authority head {head_generation}; full promotion was not committed and may be retried after the staged writer resolves"
            )));
        }
        Ok(())
    }

    fn capture_delta_identities_unlocked(
        &self,
        repo_id: &str,
        identities: &[LocalDeltaIdentity],
        required: bool,
    ) -> Result<Vec<PersistedDelta>, KinDbError> {
        let mut captured = Vec::new();
        for identity in identities {
            let path = self.delta_path(repo_id, identity.generation);
            let bytes = match std::fs::symlink_metadata(&path) {
                Ok(_) => mmap::read_regular_file(&path, "authority-bound delta")?,
                Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(KinDbError::StorageError(format!(
                        "failed to capture authority-bound delta {} for repo {repo_id}: {error}",
                        path.display()
                    )));
                }
            };
            let digest = Self::snapshot_digest(&bytes);
            if digest != identity.sha256 {
                return Err(KinDbError::StorageError(format!(
                    "authority-bound delta digest mismatch for repo {repo_id} generation {} before full promotion: expected {}, found {digest}",
                    identity.generation, identity.sha256
                )));
            }
            captured.push((bytes, identity.generation));
        }
        Ok(captured)
    }

    fn capture_authority_bound_deltas_unlocked(
        &self,
        repo_id: &str,
        record: Option<&LocalAuthorityRecord>,
    ) -> Result<Vec<PersistedDelta>, KinDbError> {
        let Some(record) = record else {
            return Ok(Vec::new());
        };
        let mut captured =
            self.capture_delta_identities_unlocked(repo_id, &record.acknowledged_deltas, true)?;
        captured.extend(self.capture_delta_identities_unlocked(
            repo_id,
            &record.retired_deltas,
            false,
        )?);
        Ok(captured)
    }

    fn delta_identities(captured: &[PersistedDelta]) -> Vec<LocalDeltaIdentity> {
        captured
            .iter()
            .map(|(bytes, generation)| LocalDeltaIdentity {
                generation: *generation,
                sha256: Self::snapshot_digest(bytes),
            })
            .collect()
    }

    fn clear_exact_captured_deltas_unlocked(
        &self,
        repo_id: &str,
        captured: &[PersistedDelta],
    ) -> bool {
        let mut complete = true;
        for (captured_bytes, generation) in captured {
            let path = self.delta_path(repo_id, *generation);
            let captured_sha256 = Self::snapshot_digest(captured_bytes);
            let quarantine_path = quarantine_delta_path(&path, *generation, &captured_sha256);
            match std::fs::rename(&path, &quarantine_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    complete = false;
                    tracing::warn!(repo_id, path = %path.display(), error = %error, "journal promotion committed; could not quarantine captured delta for cleanup");
                    continue;
                }
            }
            if let Err(error) = sync_parent_directory(&quarantine_path) {
                complete = false;
                tracing::warn!(repo_id, path = %quarantine_path.display(), error = %error, "journal promotion committed; quarantined delta rename could not be made durable");
                continue;
            }
            #[cfg(test)]
            if let Some(hook) = self.cleanup_after_quarantine_hook.lock().take() {
                hook();
            }
            match quarantined_file_matches(
                &quarantine_path,
                &captured_sha256,
                captured_bytes.len() as u64,
            ) {
                Ok(true) => match std::fs::remove_file(&quarantine_path) {
                    Ok(()) => {
                        if let Err(error) = Self::sync_parent(&quarantine_path) {
                            complete = false;
                            tracing::warn!(repo_id, path = %quarantine_path.display(), error = %error, "journal promotion committed; could not fsync captured-delta cleanup");
                        }
                    }
                    Err(error) => {
                        complete = false;
                        tracing::warn!(repo_id, path = %quarantine_path.display(), error = %error, "journal promotion committed; deferred quarantined captured-delta cleanup");
                    }
                },
                Ok(false) => {
                    complete = false;
                    tracing::warn!(repo_id, path = %path.display(), quarantine = %quarantine_path.display(), "journal promotion preserved a delta that changed after capture");
                }
                Err(error) => {
                    complete = false;
                    tracing::warn!(repo_id, path = %quarantine_path.display(), error = %error, "journal promotion committed; could not verify quarantined captured delta for cleanup");
                }
            }
        }
        match self.load_deltas_since_unlocked(repo_id, GENERATION_INIT) {
            Ok(remaining) if remaining.is_empty() => complete,
            Ok(remaining) => {
                tracing::warn!(repo_id, remaining = remaining.len(), "journal promotion committed with residual journal artifacts; recovery remains fail-closed");
                false
            }
            Err(error) => {
                tracing::warn!(repo_id, error = %error, "journal promotion committed; could not verify journal drain");
                false
            }
        }
    }

    fn read_authority_record_raw_unlocked(
        &self,
        repo_id: &str,
    ) -> Result<Option<LocalAuthorityRecord>, KinDbError> {
        let path = self.authority_path(repo_id);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "failed to inspect local authority {}: {error}",
                    path.display()
                )))
            }
        }
        mmap::confirm_installed_write(&path)?;
        let bytes = mmap::read_regular_bounded(&path, "local authority", 1024 * 1024)?;
        let record: LocalAuthorityRecord = serde_json::from_slice(&bytes).map_err(|error| {
            KinDbError::StorageError(format!(
                "invalid local authority {}: {error}",
                path.display()
            ))
        })?;
        if record.version != LOCAL_AUTHORITY_VERSION
            && record.version != LOCAL_AUTHORITY_ACKNOWLEDGED_VERSION
            && record.version != LOCAL_AUTHORITY_LEGACY_VERSION
        {
            return Err(KinDbError::StorageError(format!(
                "unsupported local authority version {} in {}",
                record.version,
                path.display()
            )));
        }
        if record.snapshot_generation > record.head_generation {
            return Err(KinDbError::StorageError(format!(
                "local authority for repo {repo_id} has snapshot generation {} above head {}",
                record.snapshot_generation, record.head_generation
            )));
        }
        let expected_file = Self::snapshot_file_name(record.snapshot_generation);
        if record.snapshot_file != expected_file {
            return Err(KinDbError::StorageError(format!(
                "local authority for repo {repo_id} references noncanonical snapshot file {}",
                record.snapshot_file
            )));
        }
        Self::validate_delta_identities(&record)?;
        Ok(Some(record))
    }

    fn read_legacy_rebuild_record_unlocked(
        &self,
        repo_id: &str,
    ) -> Result<Option<LocalLegacyRebuildRecord>, KinDbError> {
        let path = self.legacy_rebuild_path(repo_id);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "failed to inspect local legacy rebuild marker {}: {error}",
                    path.display()
                )))
            }
        }
        let bytes = mmap::read_regular_bounded(&path, "local legacy rebuild marker", 1024 * 1024)?;
        let marker: LocalLegacyRebuildRecord = serde_json::from_slice(&bytes).map_err(|error| {
            KinDbError::StorageError(format!(
                "invalid local legacy rebuild marker {}: {error}",
                path.display()
            ))
        })?;
        if marker.version != LOCAL_LEGACY_REBUILD_VERSION {
            return Err(KinDbError::StorageError(format!(
                "unsupported local legacy rebuild marker version {} in {}",
                marker.version,
                path.display()
            )));
        }
        Ok(Some(marker))
    }

    fn finalize_marker_only_legacy_rebuild_unlocked(
        &self,
        repo_id: &str,
        current_record: Option<&LocalAuthorityRecord>,
        expected_gen: Generation,
    ) -> Result<Option<Generation>, KinDbError> {
        let Some(marker) = self.read_legacy_rebuild_record_unlocked(repo_id)? else {
            return Ok(None);
        };
        let authority_matches = current_record.is_some_and(|record| {
            record.snapshot_generation == marker.committed_generation
                && record.head_generation == marker.committed_generation
        });
        if !authority_matches || expected_gen != marker.committed_generation {
            return Ok(None);
        }
        if !self
            .load_deltas_since_unlocked(repo_id, GENERATION_INIT)?
            .is_empty()
        {
            return Ok(None);
        }

        let path = self.legacy_rebuild_path(repo_id);
        match std::fs::remove_file(&path).and_then(|_| {
            Self::sync_parent(&path).map_err(|error| std::io::Error::other(error.to_string()))
        }) {
            Ok(()) => {}
            Err(error) => tracing::warn!(
                repo_id,
                path = %path.display(),
                generation = marker.committed_generation,
                error = %error,
                "legacy rebuild authority and journal are finalized; deferred rebuild-marker cleanup"
            ),
        }
        Ok(Some(marker.committed_generation))
    }

    fn read_authority_record_unlocked(
        &self,
        repo_id: &str,
    ) -> Result<Option<LocalAuthorityRecord>, KinDbError> {
        let record = self.read_authority_record_raw_unlocked(repo_id)?;
        let Some(record) = record else {
            return Ok(None);
        };
        let rebuild_path = self.legacy_rebuild_path(repo_id);
        match std::fs::symlink_metadata(&rebuild_path) {
            Ok(_) => {
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} has a pending legacy-journal rebuild marker {}; retry the explicit rebuild after quiescing legacy writers",
                    rebuild_path.display()
                )))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "failed to inspect legacy-journal rebuild marker {}: {error}",
                    rebuild_path.display()
                )))
            }
        }
        let legacy_generation = self.read_legacy_generation(repo_id)?;
        if legacy_generation > record.snapshot_generation {
            return Err(KinDbError::StorageError(format!(
                "legacy local writer advanced repo {repo_id} projection to generation {legacy_generation} beyond atomic authority base {}; drain pre-authority writers before retrying",
                record.snapshot_generation
            )));
        }
        if legacy_generation == record.head_generation {
            let projection_path = self.snapshot_path(repo_id);
            let projection_bytes = match std::fs::symlink_metadata(&projection_path) {
                Ok(_) => Some(mmap::read_regular_file(
                    &projection_path,
                    "legacy snapshot projection",
                )?),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => {
                    return Err(KinDbError::StorageError(format!(
                        "failed to inspect legacy snapshot projection {}: {error}",
                        projection_path.display()
                    )))
                }
            };
            if let Some(projection_bytes) = projection_bytes {
                let projection_is_valid = GraphSnapshot::from_bytes(&projection_bytes).is_ok();
                let projection_sha256 = Self::snapshot_digest(&projection_bytes);
                if projection_is_valid && projection_sha256 != record.snapshot_sha256 {
                    return Err(KinDbError::StorageError(format!(
                        "legacy local writer replaced repo {repo_id} with valid snapshot bytes at authority head {legacy_generation}; refusing to erase mixed-version full-snapshot divergence"
                    )));
                }
            }
        }
        if record.version == LOCAL_AUTHORITY_LEGACY_VERSION
            && record.snapshot_generation < record.head_generation
        {
            return Err(KinDbError::StorageError(format!(
                "legacy local authority for repo {repo_id} acknowledges generations {}..={} without exact delta identities; quiesce old writers and run the explicit legacy journal rebuild",
                record.snapshot_generation + 1,
                record.head_generation
            )));
        }
        self.validate_acknowledged_deltas_unlocked(repo_id, &record)?;
        self.validate_residual_deltas_unlocked(repo_id, &record)?;
        Ok(Some(record))
    }

    fn read_authoritative_snapshot_bytes_unlocked(
        &self,
        repo_id: &str,
        record: &LocalAuthorityRecord,
    ) -> Result<Vec<u8>, KinDbError> {
        let path = self.snapshots_dir(repo_id).join(&record.snapshot_file);
        let snapshot_bytes = mmap::read_regular_file(&path, "authoritative snapshot")?;
        let digest = Self::snapshot_digest(&snapshot_bytes);
        if digest != record.snapshot_sha256 {
            return Err(KinDbError::StorageError(format!(
                "authoritative snapshot digest mismatch for repo {repo_id}: expected {}, found {digest}",
                record.snapshot_sha256
            )));
        }
        GraphSnapshot::from_bytes(&snapshot_bytes).map_err(|error| {
            KinDbError::StorageError(format!(
                "authoritative snapshot payload for repo {repo_id} is invalid: {error}"
            ))
        })?;
        Ok(snapshot_bytes)
    }

    fn refresh_compatibility_projection_unlocked(
        &self,
        repo_id: &str,
        record: &LocalAuthorityRecord,
        snapshot_bytes: &[u8],
        expected: &LocalLegacyProjectionIdentity,
    ) {
        let snapshot_path = self.snapshot_path(repo_id);
        let generation_path = self.generation_path(repo_id);
        let generation_bytes = record.snapshot_generation.to_string();
        if expected.snapshot_bytes.as_deref() == Some(snapshot_bytes)
            && expected.generation_bytes.as_deref() == Some(generation_bytes.as_bytes())
        {
            return;
        }
        let snapshot_claim = match mmap::claim_exact_path(
            &snapshot_path,
            expected.snapshot_bytes.as_deref(),
            "legacy snapshot projection",
        ) {
            Ok(claim) => claim,
            Err(error) => {
                tracing::warn!(repo_id, error = %error, "preserved a racing legacy snapshot projection");
                return;
            }
        };
        let generation_claim = match mmap::claim_exact_path(
            &generation_path,
            expected.generation_bytes.as_deref(),
            "legacy generation marker",
        ) {
            Ok(claim) => claim,
            Err(error) => {
                let _ = snapshot_claim.restore();
                tracing::warn!(repo_id, error = %error, "preserved a racing legacy generation marker");
                return;
            }
        };

        let snapshot_published = match mmap::publish_new_file_no_clobber(
            &snapshot_path,
            snapshot_bytes,
            "legacy snapshot projection",
        ) {
            Ok(published) => published,
            Err(error) => {
                let _ = generation_claim.restore();
                let _ = snapshot_claim.restore();
                tracing::warn!(repo_id, error = %error, "failed to publish graph.kndb projection without clobbering");
                return;
            }
        };
        if snapshot_published {
            match mmap::publish_new_file_no_clobber(
                &generation_path,
                generation_bytes.as_bytes(),
                "legacy generation marker",
            ) {
                Ok(_) => {}
                Err(error) => {
                    let _ = generation_claim.restore();
                    let _ = snapshot_claim.release();
                    tracing::warn!(repo_id, error = %error, "failed to publish projection generation without clobbering");
                    return;
                }
            }
        }
        if snapshot_published {
            let _ = generation_claim.release();
        } else {
            let _ = generation_claim.restore();
        }
        let _ = snapshot_claim.release();
        if !snapshot_published {
            tracing::warn!(
                repo_id,
                "preserved a racing legacy full-snapshot commit after authority promotion"
            );
        }
    }

    fn clear_superseded_snapshots_unlocked(
        &self,
        repo_id: &str,
        keep_generation: Generation,
    ) -> Result<(), KinDbError> {
        let dir = self.snapshots_dir(repo_id);
        if !dir.exists() {
            return Ok(());
        }
        for entry in std::fs::read_dir(&dir).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to read local snapshot directory {}: {error}",
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
            let Some(generation) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| stem.parse::<Generation>().ok())
            else {
                continue;
            };
            if path.extension().and_then(|extension| extension.to_str()) != Some("kndb")
                || path.file_name().and_then(|name| name.to_str())
                    != Some(Self::snapshot_file_name(generation).as_str())
                || generation >= keep_generation
            {
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

    fn has_legacy_delta_artifacts_unlocked(&self, repo_id: &str) -> Result<bool, KinDbError> {
        let deltas_dir = self.deltas_dir(repo_id);
        if !deltas_dir.exists() {
            return Ok(false);
        }
        for entry in std::fs::read_dir(&deltas_dir).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to inspect legacy deltas for repo {repo_id}: {error}"
            ))
        })? {
            let entry = entry.map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to inspect legacy delta entry for repo {repo_id}: {error}"
                ))
            })?;
            if entry.path().extension().and_then(|value| value.to_str()) == Some("kndd") {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn load_authority_unlocked(
        &self,
        repo_id: &str,
    ) -> Result<Option<SnapshotAuthority>, KinDbError> {
        if let Some(record) = self.read_authority_record_unlocked(repo_id)? {
            let snapshot_bytes =
                self.read_authoritative_snapshot_bytes_unlocked(repo_id, &record)?;
            // Cleanup is downstream of both authority-directory durability and
            // exact authoritative payload verification.
            self.finalize_retired_quarantines_unlocked(repo_id, &record)?;
            let projection_identity = self.capture_legacy_projection_unlocked(repo_id)?;
            self.refresh_compatibility_projection_unlocked(
                repo_id,
                &record,
                &snapshot_bytes,
                &projection_identity,
            );
            if let Err(error) =
                self.clear_superseded_snapshots_unlocked(repo_id, record.snapshot_generation)
            {
                tracing::warn!(repo_id, error = %error, "deferred superseded local snapshot cleanup");
            }
            return Ok(Some(SnapshotAuthority {
                snapshot_bytes,
                snapshot_generation: record.snapshot_generation,
                head_generation: record.head_generation,
            }));
        }

        let unbound_quarantines = load_quarantined_deltas(&self.deltas_dir(repo_id))?;
        if !unbound_quarantines.is_empty() {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} has {} quarantined deltas but no atomic authority; recovery is fail-closed",
                unbound_quarantines.len()
            )));
        }
        let legacy_path = self.snapshot_path(repo_id);
        if !legacy_path.exists() {
            return Ok(None);
        }
        if self.has_legacy_delta_artifacts_unlocked(repo_id)? {
            return Err(KinDbError::StorageError(format!(
                "legacy local repo {repo_id} has deltas but no persisted snapshot-base authority; refusing unprovable replay"
            )));
        }
        let projection_identity = self.capture_legacy_projection_unlocked(repo_id)?;
        let snapshot_bytes = mmap::read_regular_file(&legacy_path, "legacy snapshot")?;
        let _snapshot = GraphSnapshot::from_bytes(&snapshot_bytes)?;
        let generation = self.read_legacy_generation(repo_id)?;
        let versioned_path = self.versioned_snapshot_path(repo_id, generation);
        Self::atomic_write(&versioned_path, &snapshot_bytes)?;
        #[cfg(test)]
        if let Some(hook) = self.legacy_migration_before_cas_hook.lock().take() {
            hook();
        }
        let confirmed_snapshot_bytes =
            mmap::read_regular_file(&legacy_path, "legacy snapshot CAS source")?;
        let confirmed_generation = self.read_legacy_generation(repo_id)?;
        if confirmed_snapshot_bytes != snapshot_bytes
            || confirmed_generation != generation
            || self.has_legacy_delta_artifacts_unlocked(repo_id)?
        {
            return Err(KinDbError::StorageError(format!(
                "legacy local repo {repo_id} changed while migrating snapshot generation {generation}; authority was not committed"
            )));
        }
        let record = LocalAuthorityRecord {
            version: LOCAL_AUTHORITY_VERSION,
            snapshot_generation: generation,
            head_generation: generation,
            snapshot_file: Self::snapshot_file_name(generation),
            snapshot_sha256: Self::snapshot_digest(&snapshot_bytes),
            acknowledged_deltas: Vec::new(),
            retired_deltas: Vec::new(),
        };
        self.write_authority_unlocked(repo_id, &record)?;
        self.refresh_compatibility_projection_unlocked(
            repo_id,
            &record,
            &snapshot_bytes,
            &projection_identity,
        );
        if let Err(error) = self.clear_superseded_snapshots_unlocked(repo_id, generation) {
            tracing::warn!(repo_id, error = %error, "deferred superseded local snapshot cleanup");
        }
        Ok(Some(SnapshotAuthority {
            snapshot_bytes,
            snapshot_generation: generation,
            head_generation: generation,
        }))
    }

    fn write_authority_unlocked(
        &self,
        repo_id: &str,
        record: &LocalAuthorityRecord,
    ) -> Result<(), KinDbError> {
        let bytes = serde_json::to_vec(record).map_err(|error| {
            KinDbError::StorageError(format!("failed to encode local authority: {error}"))
        })?;
        let path = self.authority_path(repo_id);
        match mmap::atomic_write_bytes_no_magic_outcome(&path, &bytes)? {
            AtomicWriteOutcome::Durable => Ok(()),
            AtomicWriteOutcome::InstalledButNotSynced(error) => {
                Err(KinDbError::StorageError(format!(
                    "local authority {} was installed but its parent-directory durability is unconfirmed: {error}",
                    path.display()
                )))
            }
        }
    }

    fn load_deltas_since_unlocked(
        &self,
        repo_id: &str,
        since_gen: Generation,
    ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
        let deltas_dir = self.deltas_dir(repo_id);
        if !deltas_dir.exists() {
            return Ok(Vec::new());
        }

        let mut entries: Vec<(Generation, PathBuf)> = Vec::new();
        for entry in std::fs::read_dir(&deltas_dir).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to read deltas directory {}: {error}",
                deltas_dir.display()
            ))
        })? {
            let entry = entry.map_err(|error| {
                KinDbError::StorageError(format!("failed to read delta entry: {error}"))
            })?;
            let path = entry.path();
            if is_quarantine_delta_name(&path) {
                continue;
            }
            if path.extension().and_then(|extension| extension.to_str()) != Some("kndd") {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .ok_or_else(|| {
                    KinDbError::StorageError(format!(
                        "delta authority {} has a non-UTF8 generation",
                        path.display()
                    ))
                })?;
            let generation = stem.parse::<Generation>().map_err(|error| {
                KinDbError::StorageError(format!(
                    "delta authority {} has an invalid generation: {error}",
                    path.display()
                ))
            })?;
            let canonical_name = format!("{generation:020}.kndd");
            if generation == GENERATION_INIT
                || path.file_name().and_then(|name| name.to_str()) != Some(canonical_name.as_str())
            {
                return Err(KinDbError::StorageError(format!(
                    "delta authority {} has a reserved or noncanonical generation",
                    path.display()
                )));
            }
            if generation > since_gen {
                entries.push((generation, path));
            }
        }
        entries.sort_by_key(|(generation, _)| *generation);

        entries
            .into_iter()
            .map(|(generation, path)| {
                mmap::read_regular_file(&path, "local delta").map(|bytes| (bytes, generation))
            })
            .collect()
    }

    #[cfg(test)]
    fn fail_next_snapshot_before_authority_commit(&self) {
        self.fail_before_authority_commit
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    fn fail_next_delta_cleanup(&self) {
        self.fail_delta_cleanup
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    fn fail_next_legacy_rebuild_cleanup(&self) {
        self.fail_legacy_rebuild_cleanup
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    fn set_recovery_after_authority_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.recovery_after_authority_hook.lock() = Some(Box::new(hook));
    }

    #[cfg(test)]
    fn set_compaction_before_delta_cleanup_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.compaction_before_delta_cleanup_hook.lock() = Some(Box::new(hook));
    }

    #[cfg(test)]
    fn set_cleanup_after_quarantine_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.cleanup_after_quarantine_hook.lock() = Some(Box::new(hook));
    }

    #[cfg(test)]
    fn set_snapshot_before_authority_commit_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.snapshot_before_authority_commit_hook.lock() = Some(Box::new(hook));
    }

    #[cfg(test)]
    fn set_snapshot_after_authority_before_projection_hook(
        &self,
        hook: impl FnOnce() + Send + 'static,
    ) {
        *self.snapshot_after_authority_before_projection_hook.lock() = Some(Box::new(hook));
    }

    #[cfg(test)]
    fn set_legacy_migration_before_cas_hook(&self, hook: impl FnOnce() + Send + 'static) {
        *self.legacy_migration_before_cas_hook.lock() = Some(Box::new(hook));
    }
}

impl StorageBackend for LocalFileBackend {
    fn supports_incremental_deltas(&self) -> bool {
        true
    }

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
        verify_source_blob_digest(digest, data, &format!("repo {repo_id}"))?;
        let _lock = self.acquire_lock(repo_id)?;
        let path = self.source_blob_path(repo_id, digest)?;
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                let existing = mmap::read_regular_file(&path, "immutable source blob")?;
                verify_source_blob_digest(digest, &existing, &path.display().to_string())?;
                if existing != data {
                    return Err(KinDbError::StorageError(format!(
                        "immutable source blob collision at {}",
                        path.display()
                    )));
                }
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "failed to inspect immutable source blob {}: {error}",
                    path.display()
                )))
            }
        }

        Self::atomic_write(&path, data)?;
        let installed = mmap::read_regular_file(&path, "installed immutable source blob")?;
        verify_source_blob_digest(digest, &installed, &path.display().to_string())?;
        if installed != data {
            return Err(KinDbError::StorageError(format!(
                "immutable source blob changed while installing {}",
                path.display()
            )));
        }
        Ok(())
    }

    fn load_source_blob(
        &self,
        repo_id: &str,
        digest: [u8; 32],
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        validate_source_blob_repo_id(repo_id)?;
        let _lock = self.acquire_lock(repo_id)?;
        let path = self.source_blob_path(repo_id, digest)?;
        let data = match std::fs::symlink_metadata(&path) {
            Ok(_) => mmap::read_regular_file(&path, "immutable source blob")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(KinDbError::StorageError(format!(
                    "failed to inspect immutable source blob {}: {error}",
                    path.display()
                )))
            }
        };
        verify_source_blob_digest(digest, &data, &path.display().to_string())?;
        Ok(Some(data))
    }

    fn load_snapshot_authority(
        &self,
        repo_id: &str,
    ) -> Result<Option<SnapshotAuthority>, KinDbError> {
        let _lock = self.acquire_lock(repo_id)?;
        self.load_authority_unlocked(repo_id)
    }

    fn load_recovery_state(&self, repo_id: &str) -> Result<SnapshotRecoveryState, KinDbError> {
        let _lock = self.acquire_lock(repo_id)?;
        let authority = self.load_authority_unlocked(repo_id)?;
        let authority_record = self.read_authority_record_raw_unlocked(repo_id)?;
        match (authority.as_ref(), authority_record.as_ref()) {
            (Some(authority), Some(record))
                if authority.snapshot_generation == record.snapshot_generation
                    && authority.head_generation == record.head_generation
                    && Self::snapshot_digest(&authority.snapshot_bytes)
                        == record.snapshot_sha256 => {}
            (None, None) => {}
            _ => {
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} snapshot authority changed while loading recovery state"
                )));
            }
        }
        #[cfg(test)]
        if let Some(hook) = self.recovery_after_authority_hook.lock().take() {
            hook();
        }
        if let Some(record) = authority_record.as_ref() {
            self.finalize_retired_quarantines_unlocked(repo_id, record)?;
        }
        let all_deltas = self.load_deltas_since_unlocked(repo_id, GENERATION_INIT)?;
        if let Some(record) = authority_record.as_ref() {
            Self::validate_loaded_residual_deltas(repo_id, record, &all_deltas)?;
            Self::validate_loaded_acknowledged_deltas(repo_id, record, &all_deltas)?;
        }
        let since = authority
            .as_ref()
            .map_or(GENERATION_INIT, |authority| authority.snapshot_generation);
        let deltas = all_deltas
            .into_iter()
            .filter(|(_, generation)| *generation > since)
            .collect();
        Ok((authority, deltas))
    }

    fn save_snapshot(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let _lock = self.acquire_lock(repo_id)?;
        let current = self.load_authority_unlocked(repo_id)?;
        let current_record = self.read_authority_record_raw_unlocked(repo_id)?;
        let projection_identity = self.capture_legacy_projection_unlocked(repo_id)?;
        match (current.as_ref(), current_record.as_ref()) {
            (Some(authority), Some(record))
                if authority.snapshot_generation == record.snapshot_generation
                    && authority.head_generation == record.head_generation
                    && Self::snapshot_digest(&authority.snapshot_bytes)
                        == record.snapshot_sha256 => {}
            (None, None) => {}
            _ => {
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} snapshot authority changed while preparing full promotion"
                )));
            }
        }
        let current_gen = current
            .as_ref()
            .map_or(GENERATION_INIT, |authority| authority.head_generation);
        let requested_digest = Self::snapshot_digest(data);
        if let Some(record) = current_record.as_ref() {
            let retry_generation = expected_gen.checked_add(1);
            if retry_generation == Some(record.head_generation)
                && record.snapshot_generation == record.head_generation
                && record.snapshot_sha256 == requested_digest
                && current.as_ref().is_some_and(|authority| {
                    authority.snapshot_generation == record.snapshot_generation
                        && authority.head_generation == record.head_generation
                        && Self::snapshot_digest(&authority.snapshot_bytes) == requested_digest
                })
            {
                // Exact serialized-content retries are idempotent whether the
                // retained recovery marker survived or its cleanup already
                // completed. Re-sync the authority directory before accepting.
                mmap::sync_parent_dir(&self.authority_path(repo_id))?;
                return Ok(record.head_generation);
            }
        }
        self.reject_unbound_staged_deltas_unlocked(repo_id, current_record.as_ref())?;
        if current_gen != expected_gen {
            return Err(KinDbError::StorageError(format!(
                "generation mismatch for repo {repo_id}: expected {expected_gen}, found {current_gen} \
                 (another writer committed since last load)"
            )));
        }

        // Validate the bytes without re-serializing — from_bytes proves the
        // data round-trips, then we write the *original* bytes to disk.
        let _snapshot = GraphSnapshot::from_bytes(data)?;
        let new_gen = checked_next_generation(current_gen, "local snapshot")?;
        let versioned_path = self.versioned_snapshot_path(repo_id, new_gen);
        Self::atomic_write(&versioned_path, data)?;

        #[cfg(test)]
        if self
            .fail_before_authority_commit
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(KinDbError::StorageError(
                "injected crash before local snapshot authority commit".to_string(),
            ));
        }

        #[cfg(test)]
        if let Some(hook) = self.snapshot_before_authority_commit_hook.lock().take() {
            hook();
        }

        let captured_for_cleanup =
            self.capture_authority_bound_deltas_unlocked(repo_id, current_record.as_ref())?;
        self.reject_unbound_staged_deltas_unlocked(repo_id, current_record.as_ref())?;
        if self.capture_authority_bound_deltas_unlocked(repo_id, current_record.as_ref())?
            != captured_for_cleanup
            || self.read_authority_record_raw_unlocked(repo_id)? != current_record
            || self.capture_legacy_projection_unlocked(repo_id)? != projection_identity
        {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} authority, journal, or legacy full-snapshot projection changed during full promotion; authority was not committed"
            )));
        }

        let record = LocalAuthorityRecord {
            version: LOCAL_AUTHORITY_VERSION,
            snapshot_generation: new_gen,
            head_generation: new_gen,
            snapshot_file: Self::snapshot_file_name(new_gen),
            snapshot_sha256: requested_digest,
            acknowledged_deltas: Vec::new(),
            retired_deltas: Self::delta_identities(&captured_for_cleanup),
        };
        self.write_authority_unlocked(repo_id, &record)?;

        #[cfg(test)]
        if let Some(hook) = self
            .snapshot_after_authority_before_projection_hook
            .lock()
            .take()
        {
            hook();
        }

        // These are compatibility projections, not authority. A failure after
        // the authority commit must not report the snapshot as uncommitted or
        // leave the caller using a stale CAS generation.
        self.refresh_compatibility_projection_unlocked(
            repo_id,
            &record,
            data,
            &projection_identity,
        );
        if let Err(error) = self.clear_superseded_snapshots_unlocked(repo_id, new_gen) {
            tracing::warn!(repo_id, error = %error, "deferred superseded local snapshot cleanup");
        }
        Ok(new_gen)
    }

    fn rebuild_legacy_journal(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let _lock = self.acquire_lock(repo_id)?;
        let _snapshot = GraphSnapshot::from_bytes(data)?;

        // This raw authority read intentionally bypasses the normal pending-
        // rebuild and legacy-marker fences. The explicit rebuild operation is
        // the only path allowed to reconcile those fail-closed states.
        let current_record = self.read_authority_record_raw_unlocked(repo_id)?;
        if let Some(record) = current_record.as_ref() {
            self.read_authoritative_snapshot_bytes_unlocked(repo_id, record)?;
            self.finalize_retired_quarantines_unlocked(repo_id, record)?;
        } else {
            let unbound = load_quarantined_deltas(&self.deltas_dir(repo_id))?;
            if !unbound.is_empty() {
                return Err(KinDbError::StorageError(format!(
                    "repo {repo_id} has {} quarantined deltas but no atomic authority; recovery is fail-closed",
                    unbound.len()
                )));
            }
        }
        if let (Some(record), Some(marker)) = (
            current_record.as_ref(),
            self.read_legacy_rebuild_record_unlocked(repo_id)?,
        ) {
            if (expected_gen == marker.expected_generation
                || expected_gen == marker.committed_generation)
                && record.snapshot_generation == marker.committed_generation
                && record.head_generation == marker.committed_generation
            {
                if record.snapshot_sha256 != Self::snapshot_digest(data) {
                    return Err(KinDbError::StorageError(format!(
                        "installed legacy rebuild for repo {repo_id} does not match the retry snapshot"
                    )));
                }
                let marker_identities = marker
                    .captured_deltas
                    .iter()
                    .map(|(name, sha256)| {
                        let generation = name
                            .strip_suffix(".kndd")
                            .ok_or_else(|| {
                                KinDbError::StorageError(format!(
                                    "invalid captured legacy delta name {name} for repo {repo_id}"
                                ))
                            })?
                            .parse::<Generation>()
                            .map_err(|error| {
                                KinDbError::StorageError(format!(
                                    "invalid captured legacy delta name {name} for repo {repo_id}: {error}"
                                ))
                            })?;
                        Ok(LocalDeltaIdentity {
                            generation,
                            sha256: sha256.clone(),
                        })
                    })
                    .collect::<Result<Vec<_>, KinDbError>>()?;
                if record.retired_deltas != marker_identities {
                    return Err(KinDbError::StorageError(format!(
                        "installed legacy rebuild authority for repo {repo_id} does not bind its captured journal"
                    )));
                }
                let remaining = self.load_deltas_since_unlocked(repo_id, GENERATION_INIT)?;
                for (bytes, generation) in &remaining {
                    let digest = Self::snapshot_digest(bytes);
                    if !marker_identities.iter().any(|identity| {
                        identity.generation == *generation && identity.sha256 == digest
                    }) {
                        return Err(KinDbError::StorageError(format!(
                            "legacy journal changed after the installed rebuild for repo {repo_id}; recovery is fail-closed"
                        )));
                    }
                }
                let cleanup_complete =
                    self.clear_exact_captured_deltas_unlocked(repo_id, &remaining);
                if cleanup_complete {
                    let marker_path = self.legacy_rebuild_path(repo_id);
                    match std::fs::remove_file(&marker_path) {
                        Ok(()) => {
                            if let Err(error) = Self::sync_parent(&marker_path) {
                                tracing::warn!(repo_id, path = %marker_path.display(), error = %error, "confirmed legacy rebuild; deferred marker deletion durability");
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            if let Err(error) = Self::sync_parent(&marker_path) {
                                tracing::warn!(repo_id, path = %marker_path.display(), error = %error, "confirmed legacy rebuild; deferred absent-marker durability confirmation");
                            }
                        }
                        Err(error) => {
                            tracing::warn!(repo_id, path = %marker_path.display(), error = %error, "confirmed legacy rebuild; deferred marker cleanup");
                        }
                    }
                }
                if let Err(error) =
                    self.clear_superseded_snapshots_unlocked(repo_id, marker.committed_generation)
                {
                    tracing::warn!(repo_id, error = %error, "confirmed legacy rebuild; deferred superseded snapshot cleanup");
                }
                return Ok(marker.committed_generation);
            }
        }
        if let Some(committed_generation) = self.finalize_marker_only_legacy_rebuild_unlocked(
            repo_id,
            current_record.as_ref(),
            expected_gen,
        )? {
            return Ok(committed_generation);
        }
        let projection_identity = self.capture_legacy_projection_unlocked(repo_id)?;
        if current_record.is_none() && !self.snapshot_path(repo_id).exists() {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} has no legacy or authoritative base snapshot to rebuild"
            )));
        }

        let captured = self.load_deltas_since_unlocked(repo_id, GENERATION_INIT)?;
        if captured.is_empty() {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} has no legacy journal to rebuild"
            )));
        }
        let journal_head = captured
            .iter()
            .map(|(_, generation)| *generation)
            .max()
            .unwrap_or(GENERATION_INIT);
        let observed_head = current_record
            .as_ref()
            .map_or(GENERATION_INIT, |record| record.head_generation)
            .max(projection_identity.generation)
            .max(journal_head);
        if expected_gen != observed_head {
            return Err(KinDbError::StorageError(format!(
                "legacy journal rebuild generation mismatch for repo {repo_id}: expected {expected_gen}, observed head {observed_head}; the supplied graph must be reconciled through the highest legacy cursor"
            )));
        }

        // Re-read the exact journal and CAS anchor immediately before staging.
        // Cooperative writers serialize on this lock; this second check also
        // catches a pre-authority writer that ignored it.
        if self.load_deltas_since_unlocked(repo_id, GENERATION_INIT)? != captured
            || self
                .read_authority_record_raw_unlocked(repo_id)?
                .as_ref()
                .map_or(self.read_legacy_generation(repo_id)?, |record| {
                    record.head_generation
                })
                != current_record
                    .as_ref()
                    .map_or(projection_identity.generation, |record| {
                        record.head_generation
                    })
            || self.capture_legacy_projection_unlocked(repo_id)? != projection_identity
        {
            return Err(KinDbError::StorageError(format!(
                "legacy journal changed while rebuilding repo {repo_id}; authority was not committed"
            )));
        }

        let new_gen = checked_next_generation(expected_gen, "local legacy journal rebuild")?;
        let versioned_path = self.versioned_snapshot_path(repo_id, new_gen);
        Self::atomic_write(&versioned_path, data)?;

        let rebuild = LocalLegacyRebuildRecord {
            version: LOCAL_LEGACY_REBUILD_VERSION,
            expected_generation: expected_gen,
            committed_generation: new_gen,
            captured_deltas: captured
                .iter()
                .map(|(bytes, generation)| {
                    (
                        format!("{generation:020}.kndd"),
                        Self::snapshot_digest(bytes),
                    )
                })
                .collect(),
        };
        let rebuild_bytes = serde_json::to_vec(&rebuild).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to encode local legacy rebuild marker: {error}"
            ))
        })?;
        Self::atomic_write(&self.legacy_rebuild_path(repo_id), &rebuild_bytes)?;

        #[cfg(test)]
        if let Some(hook) = self.snapshot_before_authority_commit_hook.lock().take() {
            hook();
        }
        if self.load_deltas_since_unlocked(repo_id, GENERATION_INIT)? != captured
            || self.read_authority_record_raw_unlocked(repo_id)? != current_record
            || self.capture_legacy_projection_unlocked(repo_id)? != projection_identity
        {
            return Err(KinDbError::StorageError(format!(
                "legacy authority, journal, or full-snapshot projection changed while rebuilding repo {repo_id}; authority was not committed"
            )));
        }

        let record = LocalAuthorityRecord {
            version: LOCAL_AUTHORITY_VERSION,
            snapshot_generation: new_gen,
            head_generation: new_gen,
            snapshot_file: Self::snapshot_file_name(new_gen),
            snapshot_sha256: Self::snapshot_digest(data),
            acknowledged_deltas: Vec::new(),
            retired_deltas: Self::delta_identities(&captured),
        };
        self.write_authority_unlocked(repo_id, &record)?;
        #[cfg(test)]
        if let Some(hook) = self
            .snapshot_after_authority_before_projection_hook
            .lock()
            .take()
        {
            hook();
        }
        self.refresh_compatibility_projection_unlocked(
            repo_id,
            &record,
            data,
            &projection_identity,
        );

        #[cfg(test)]
        let skip_cleanup = self
            .fail_legacy_rebuild_cleanup
            .swap(false, std::sync::atomic::Ordering::SeqCst);
        #[cfg(not(test))]
        let skip_cleanup = false;
        let cleanup_complete =
            !skip_cleanup && self.clear_exact_captured_deltas_unlocked(repo_id, &captured);
        if cleanup_complete {
            let marker = self.legacy_rebuild_path(repo_id);
            if let Err(error) = std::fs::remove_file(&marker).and_then(|_| {
                Self::sync_parent(&marker).map_err(|error| std::io::Error::other(error.to_string()))
            }) {
                tracing::warn!(repo_id, error = %error, "legacy rebuild committed; deferred rebuild-marker cleanup");
            }
        }
        if let Err(error) = self.clear_superseded_snapshots_unlocked(repo_id, new_gen) {
            tracing::warn!(repo_id, error = %error, "deferred superseded local snapshot cleanup");
        }
        Ok(new_gen)
    }

    fn save_delta(
        &self,
        repo_id: &str,
        delta_data: &[u8],
        base_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let _lock = self.acquire_lock(repo_id)?;
        let _ = self.load_authority_unlocked(repo_id)?;
        let Some(mut record) = self.read_authority_record_unlocked(repo_id)? else {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} has no atomic local snapshot authority; persist a full snapshot before deltas"
            )));
        };
        let current_gen = record.head_generation;
        let requested_digest = Self::snapshot_digest(delta_data);
        if base_gen.checked_add(1) == Some(current_gen)
            && record.acknowledged_deltas.last().is_some_and(|identity| {
                identity.generation == current_gen && identity.sha256 == requested_digest
            })
            && mmap::read_regular_file(
                &self.delta_path(repo_id, current_gen),
                "idempotent local delta retry",
            )
            .is_ok_and(|bytes| bytes == delta_data)
        {
            mmap::sync_parent_dir(&self.authority_path(repo_id))?;
            return Ok(current_gen);
        }
        if current_gen != base_gen {
            return Err(KinDbError::StorageError(format!(
                "delta base generation mismatch for repo {repo_id}: expected {base_gen}, found {current_gen}"
            )));
        }

        let delta = crate::storage::delta::GraphSnapshotDelta::from_bytes(delta_data)?;
        if delta.base_generation != base_gen {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} delta payload declares base {}, expected {base_gen}",
                delta.base_generation
            )));
        }
        let new_gen = checked_next_generation(current_gen, "local delta")?;
        let delta_path = self.delta_path(repo_id, new_gen);
        Self::atomic_write(&delta_path, delta_data)?;
        record.version = LOCAL_AUTHORITY_VERSION;
        record
            .retired_deltas
            .retain(|identity| identity.generation != new_gen);
        record.acknowledged_deltas.push(LocalDeltaIdentity {
            generation: new_gen,
            sha256: requested_digest,
        });
        record.head_generation = new_gen;
        self.write_authority_unlocked(repo_id, &record)?;
        // graph.kndb still contains the immutable base bytes, so its legacy
        // marker must stay at snapshot_generation. Advancing only the marker
        // would create a generation/bytes pair that never existed.
        Ok(new_gen)
    }

    fn load_deltas_since(
        &self,
        repo_id: &str,
        since_gen: Generation,
    ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
        let _lock = self.acquire_lock(repo_id)?;
        let _ = self.load_authority_unlocked(repo_id)?;
        self.load_deltas_since_unlocked(repo_id, since_gen)
    }

    fn clear_deltas(&self, repo_id: &str) -> Result<(), KinDbError> {
        let _lock = self.acquire_lock(repo_id)?;
        let _ = self.load_authority_unlocked(repo_id)?;
        #[cfg(test)]
        if let Some(hook) = self.compaction_before_delta_cleanup_hook.lock().take() {
            hook();
        }
        let record = self.read_authority_record_unlocked(repo_id)?;
        let Some(record) = record else {
            if self
                .load_deltas_since_unlocked(repo_id, GENERATION_INIT)?
                .is_empty()
            {
                return Ok(());
            }
            return Err(KinDbError::StorageError(format!(
                "refusing to clear unbound deltas for repo {repo_id} without atomic authority"
            )));
        };
        if record.snapshot_generation != record.head_generation {
            return Err(KinDbError::StorageError(format!(
                "refusing to clear authoritative deltas for repo {repo_id}: snapshot generation {}, head {}",
                record.snapshot_generation, record.head_generation
            )));
        }
        #[cfg(test)]
        if self
            .fail_delta_cleanup
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(KinDbError::StorageError(
                "injected local delta cleanup failure".to_string(),
            ));
        }
        let captured =
            self.capture_delta_identities_unlocked(repo_id, &record.retired_deltas, false)?;
        if !self.clear_exact_captured_deltas_unlocked(repo_id, &captured) {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} delta cleanup left residual journal artifacts; recovery remains fail-closed"
            )));
        }
        Ok(())
    }

    fn save_overlay(&self, repo_id: &str, session_id: &str, data: &[u8]) -> Result<(), KinDbError> {
        let path = self.overlay_path(repo_id, session_id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to create overlay directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
        std::fs::write(&path, data).map_err(|e| {
            KinDbError::StorageError(format!("failed to write overlay {}: {e}", path.display()))
        })
    }

    fn load_overlay(&self, repo_id: &str, session_id: &str) -> Result<Option<Vec<u8>>, KinDbError> {
        let path = self.overlay_path(repo_id, session_id);
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read(&path).map_err(|e| {
            KinDbError::StorageError(format!("failed to read overlay {}: {e}", path.display()))
        })?;
        Ok(Some(data))
    }

    fn delete_overlay(&self, repo_id: &str, session_id: &str) -> Result<(), KinDbError> {
        let path = self.overlay_path(repo_id, session_id);
        if !path.exists() {
            return Ok(());
        }
        std::fs::remove_file(&path).map_err(|e| {
            KinDbError::StorageError(format!("failed to delete overlay {}: {e}", path.display()))
        })
    }

    fn list_repos(&self) -> Result<Vec<String>, KinDbError> {
        let mut repos = Vec::new();
        if !self.base_path.exists() {
            return Ok(repos);
        }
        let entries = std::fs::read_dir(&self.base_path).map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to read base directory {}: {e}",
                self.base_path.display()
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                KinDbError::StorageError(format!("failed to read directory entry: {e}"))
            })?;
            if entry.path().is_dir() {
                let snapshot = entry.path().join("graph.kndb");
                let authority = entry.path().join("authority.json");
                if snapshot.exists() || authority.exists() {
                    if let Some(name) = entry.file_name().to_str() {
                        repos.push(name.to_string());
                    }
                }
            }
        }
        Ok(repos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn source_digest(data: &[u8]) -> [u8; 32] {
        Sha256::digest(data).into()
    }

    #[test]
    fn local_source_blob_roundtrips_retries_and_reports_missing() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let data = b"immutable source bytes";
        let digest = source_digest(data);

        assert!(backend
            .load_source_blob("repo-a", digest)
            .unwrap()
            .is_none());
        backend.save_source_blob("repo-a", digest, data).unwrap();
        backend.save_source_blob("repo-a", digest, data).unwrap();
        drop(backend);
        let reopened = LocalFileBackend::new(dir.path());
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
    fn local_source_blob_rejects_wrong_digest_corruption_and_unsafe_repo_id() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let data = b"expected";
        let digest = source_digest(data);

        let wrong_digest_error = backend
            .save_source_blob("repo-a", source_digest(b"different"), data)
            .expect_err("write identity must bind the exact bytes");
        assert!(wrong_digest_error.to_string().contains("digest mismatch"));

        for repo_id in ["", ".", "..", "../escape", "owner/repo"] {
            let error = backend
                .load_source_blob(repo_id, digest)
                .expect_err("repo id must not control an object path");
            assert!(error.to_string().contains("invalid repo id"));
        }

        let path = backend.source_blob_path("repo-a", digest).unwrap();
        LocalFileBackend::atomic_write(&path, b"corrupt").unwrap();
        let read_error = backend
            .load_source_blob("repo-a", digest)
            .expect_err("corrupt immutable bytes must fail closed");
        assert!(read_error.to_string().contains("digest mismatch"));
        let retry_error = backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("a write retry must not replace corrupt authority");
        assert!(retry_error.to_string().contains("digest mismatch"));
    }

    #[cfg(unix)]
    #[test]
    fn local_source_blob_rejects_symlink_object_without_touching_target() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let data = b"source";
        let digest = source_digest(data);
        let path = backend.source_blob_path("repo-a", digest).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"do not replace").unwrap();
        symlink(&victim, &path).unwrap();

        let error = backend
            .save_source_blob("repo-a", digest, data)
            .expect_err("symlink source object must fail closed");
        assert!(error.to_string().contains("immutable source blob"));
        assert_eq!(std::fs::read(&victim).unwrap(), b"do not replace");
    }

    #[test]
    fn local_backend_roundtrip_snapshot() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        // No snapshot yet
        assert!(backend.load_snapshot("test-repo").unwrap().is_none());

        // Create and save a snapshot
        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();
        let new_gen = backend
            .save_snapshot("test-repo", &bytes, GENERATION_INIT)
            .unwrap();
        assert_eq!(new_gen, 1);

        // Load it back
        let (loaded_bytes, gen) = backend.load_snapshot("test-repo").unwrap().unwrap();
        assert_eq!(gen, 1);
        let loaded = GraphSnapshot::from_bytes(&loaded_bytes).unwrap();
        assert_eq!(loaded.version, GraphSnapshot::CURRENT_VERSION);
    }

    #[test]
    fn local_backend_cas_rejects_stale_generation() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();

        // First write succeeds
        let gen1 = backend
            .save_snapshot("test-repo", &bytes, GENERATION_INIT)
            .unwrap();
        assert_eq!(gen1, 1);

        // Second write with correct generation succeeds with different bytes.
        let mut replacement = GraphSnapshot::empty();
        replacement
            .file_hashes
            .insert("replacement.rs".to_string(), [7; 32]);
        let replacement_bytes = replacement.to_bytes().unwrap();
        let gen2 = backend
            .save_snapshot("test-repo", &replacement_bytes, gen1)
            .unwrap();
        assert_eq!(gen2, 2);

        // Write with stale generation fails
        let err = backend
            .save_snapshot("test-repo", &bytes, gen1)
            .unwrap_err();
        assert!(err.to_string().contains("generation mismatch"));
    }

    #[test]
    fn local_backend_overlay_roundtrip() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        // No overlay yet
        assert!(backend
            .load_overlay("test-repo", "session-1")
            .unwrap()
            .is_none());

        // Save overlay
        let overlay_data = b"overlay state bytes";
        backend
            .save_overlay("test-repo", "session-1", overlay_data)
            .unwrap();

        // Load it back
        let loaded = backend
            .load_overlay("test-repo", "session-1")
            .unwrap()
            .unwrap();
        assert_eq!(loaded, overlay_data);
    }

    #[test]
    fn local_backend_delete_overlay() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

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
    fn local_backend_save_snapshot_writes_raw_bytes() {
        // Verify that save_snapshot writes the exact input bytes (no re-serialization).
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();
        backend
            .save_snapshot("test-repo", &bytes, GENERATION_INIT)
            .unwrap();

        // Read the file directly and confirm byte-for-byte match.
        let on_disk = std::fs::read(dir.path().join("test-repo").join("graph.kndb")).unwrap();
        assert_eq!(on_disk, bytes);
    }

    #[test]
    fn local_backend_save_and_load_delta() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        // Create initial snapshot
        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();
        let gen1 = backend
            .save_snapshot("test-repo", &bytes, GENERATION_INIT)
            .unwrap();

        // Save a delta
        let mut delta = crate::storage::delta::GraphSnapshotDelta::empty(gen1);
        delta
            .file_hashes
            .added
            .push(("new.rs".to_string(), [42; 32]));
        let delta_bytes = delta.to_bytes().unwrap();
        let gen2 = backend.save_delta("test-repo", &delta_bytes, gen1).unwrap();
        assert_eq!(gen2, 2);

        // Load deltas since gen1
        let loaded = backend.load_deltas_since("test-repo", gen1).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].1, gen2);

        let loaded_delta =
            crate::storage::delta::GraphSnapshotDelta::from_bytes(&loaded[0].0).unwrap();
        assert_eq!(loaded_delta.file_hashes.added.len(), 1);

        // No deltas since gen2
        let empty = backend.load_deltas_since("test-repo", gen2).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn local_snapshot_tuple_and_compatibility_marker_describe_base_bytes() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "generation-bytes";
        let mut base = GraphSnapshot::empty();
        base.file_hashes.insert("base.rs".to_string(), [1; 32]);
        let base_bytes = base.to_bytes().unwrap();
        let gen1 = backend
            .save_snapshot(repo_id, &base_bytes, GENERATION_INIT)
            .unwrap();
        let mut current = base.clone();
        current.file_hashes.insert("delta.rs".to_string(), [2; 32]);
        let delta = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let gen2 = backend
            .save_delta(repo_id, &delta.to_bytes().unwrap(), gen1)
            .unwrap();

        let (loaded, generation) = backend.load_snapshot(repo_id).unwrap().unwrap();
        assert_eq!(loaded, base_bytes);
        assert_eq!(generation, gen1);
        assert_eq!(backend.read_legacy_generation(repo_id).unwrap(), gen1);
        let authority = backend.load_snapshot_authority(repo_id).unwrap().unwrap();
        assert_eq!(authority.snapshot_generation, gen1);
        assert_eq!(authority.head_generation, gen2);

        // Model an old writer replacing the projection bytes and relabeling
        // them with the same base generation. Generation equality alone must
        // not suppress identity-based projection healing.
        std::fs::write(backend.snapshot_path(repo_id), b"stale projection").unwrap();
        std::fs::write(
            backend.generation_path(repo_id),
            gen1.to_string().as_bytes(),
        )
        .unwrap();
        let reopened = LocalFileBackend::new(dir.path());
        let (healed, healed_generation) = reopened.load_snapshot(repo_id).unwrap().unwrap();
        assert_eq!(healed, base_bytes);
        assert_eq!(healed_generation, gen1);
        assert_eq!(
            std::fs::read(reopened.snapshot_path(repo_id)).unwrap(),
            base_bytes
        );
        assert_eq!(reopened.read_legacy_generation(repo_id).unwrap(), gen1);
    }

    #[test]
    fn local_backend_recovery_replays_sequential_deltas_after_reopen() {
        let dir = TempDir::new().unwrap();
        let repo_id = "restart-repo";
        let mut base = GraphSnapshot::empty();
        base.file_hashes.insert("base.rs".to_string(), [1; 32]);

        {
            let backend = LocalFileBackend::new(dir.path());
            let gen1 = backend
                .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
                .unwrap();

            let mut after_first = base.clone();
            after_first
                .file_hashes
                .insert("first.rs".to_string(), [2; 32]);
            let first_delta = crate::storage::delta::compute_graph_delta(&base, &after_first, gen1);
            let gen2 = backend
                .save_delta(repo_id, &first_delta.to_bytes().unwrap(), gen1)
                .unwrap();

            let mut after_second = after_first.clone();
            after_second
                .file_hashes
                .insert("second.rs".to_string(), [3; 32]);
            let second_delta =
                crate::storage::delta::compute_graph_delta(&after_first, &after_second, gen2);
            let gen3 = backend
                .save_delta(repo_id, &second_delta.to_bytes().unwrap(), gen2)
                .unwrap();
            assert_eq!(gen3, 3);
        }

        let reopened = LocalFileBackend::new(dir.path());
        let recovered = load_recovered_snapshot(&reopened, repo_id)
            .unwrap()
            .expect("base snapshot exists");
        assert_eq!(recovered.generation, 3);
        assert_eq!(recovered.deltas_seen, 2);
        assert_eq!(recovered.deltas_applied, 2);
        assert_eq!(recovered.snapshot.file_hashes.len(), 3);
        assert!(recovered.snapshot.file_hashes.contains_key("base.rs"));
        assert!(recovered.snapshot.file_hashes.contains_key("first.rs"));
        assert!(recovered.snapshot.file_hashes.contains_key("second.rs"));
    }

    #[test]
    fn local_legacy_snapshot_without_journal_migrates_to_explicit_base_authority() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "legacy-clean";
        let snapshot = GraphSnapshot::empty().to_bytes().unwrap();
        std::fs::create_dir_all(dir.path().join(repo_id)).unwrap();
        std::fs::write(backend.snapshot_path(repo_id), &snapshot).unwrap();
        std::fs::write(backend.generation_path(repo_id), b"7").unwrap();

        let authority = backend
            .load_snapshot_authority(repo_id)
            .unwrap()
            .expect("legacy snapshot migrates");
        assert_eq!(authority.snapshot_generation, 7);
        assert_eq!(authority.head_generation, 7);
        assert!(backend.authority_path(repo_id).exists());
        assert!(backend.versioned_snapshot_path(repo_id, 7).exists());
    }

    #[test]
    fn local_legacy_snapshot_migration_rechecks_exact_bytes_and_generation() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "legacy-migration-cas";
        let original = GraphSnapshot::empty().to_bytes().unwrap();
        let mut replacement_snapshot = GraphSnapshot::empty();
        replacement_snapshot
            .file_hashes
            .insert("new-writer.rs".to_string(), [9; 32]);
        let replacement = replacement_snapshot.to_bytes().unwrap();
        std::fs::create_dir_all(dir.path().join(repo_id)).unwrap();
        std::fs::write(backend.snapshot_path(repo_id), &original).unwrap();
        std::fs::write(backend.generation_path(repo_id), b"7").unwrap();

        let replacement_path = backend.snapshot_path(repo_id);
        let replacement_marker = backend.generation_path(repo_id);
        let expected_replacement = replacement.clone();
        backend.set_legacy_migration_before_cas_hook(move || {
            LocalFileBackend::atomic_write(&replacement_path, &replacement).unwrap();
            LocalFileBackend::atomic_write(&replacement_marker, b"8").unwrap();
        });

        let error = backend
            .load_snapshot_authority(repo_id)
            .expect_err("legacy bytes and generation must be rechecked before authority commit");
        assert!(error.to_string().contains("changed while migrating"));
        assert!(!backend.authority_path(repo_id).exists());
        assert_eq!(
            std::fs::read(backend.snapshot_path(repo_id)).unwrap(),
            expected_replacement,
            "failed migration must not erase the racing writer's snapshot"
        );
        assert_eq!(backend.read_legacy_generation(repo_id).unwrap(), 8);
    }

    #[test]
    fn local_legacy_snapshot_with_unbound_journal_fails_closed() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "legacy-unbound";
        std::fs::create_dir_all(backend.deltas_dir(repo_id)).unwrap();
        std::fs::write(
            backend.snapshot_path(repo_id),
            GraphSnapshot::empty().to_bytes().unwrap(),
        )
        .unwrap();
        std::fs::write(backend.generation_path(repo_id), b"8").unwrap();
        std::fs::write(
            backend.delta_path(repo_id, 8),
            crate::storage::delta::GraphSnapshotDelta::empty(7)
                .to_bytes()
                .unwrap(),
        )
        .unwrap();

        let error = backend
            .load_snapshot_authority(repo_id)
            .expect_err("legacy journal has no provable snapshot base");
        assert!(error
            .to_string()
            .contains("no persisted snapshot-base authority"));
        assert!(!backend.authority_path(repo_id).exists());
    }

    #[test]
    fn initial_full_save_must_reject_journal_without_base() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "initial-save-unbound-journal";
        std::fs::create_dir_all(backend.deltas_dir(repo_id)).unwrap();
        LocalFileBackend::atomic_write(
            &backend.delta_path(repo_id, 1),
            &crate::storage::delta::GraphSnapshotDelta::empty(GENERATION_INIT)
                .to_bytes()
                .unwrap(),
        )
        .unwrap();

        let error = backend
            .save_snapshot(
                repo_id,
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .expect_err("initial full save must not create authority over an unbound journal");
        assert!(error.to_string().contains("staged unacknowledged delta"));
        assert!(!backend.authority_path(repo_id).exists());
        assert!(backend.delta_path(repo_id, 1).exists());
    }

    #[test]
    fn local_explicit_legacy_rebuild_preserves_cursor_across_cleanup_failure() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "legacy-rebuild";
        let mut base = GraphSnapshot::empty();
        base.file_hashes.insert("base.rs".to_string(), [1; 32]);
        let mut reconciled = base.clone();
        reconciled
            .file_hashes
            .insert("legacy-delta.rs".to_string(), [2; 32]);
        std::fs::create_dir_all(backend.deltas_dir(repo_id)).unwrap();
        std::fs::write(backend.snapshot_path(repo_id), base.to_bytes().unwrap()).unwrap();
        std::fs::write(backend.generation_path(repo_id), b"8").unwrap();
        std::fs::write(
            backend.delta_path(repo_id, 8),
            crate::storage::delta::GraphSnapshotDelta::empty(7)
                .to_bytes()
                .unwrap(),
        )
        .unwrap();

        backend.fail_next_legacy_rebuild_cleanup();
        let committed = backend
            .rebuild_legacy_journal(repo_id, &reconciled.to_bytes().unwrap(), 8)
            .expect("authority commit must return its cursor despite cleanup failure");
        assert_eq!(committed, 9);
        assert!(backend.delta_path(repo_id, 8).exists());
        let error = backend
            .load_snapshot(repo_id)
            .expect_err("pending rebuild marker must keep normal recovery fail-closed");
        assert!(error.to_string().contains("pending legacy-journal rebuild"));

        let retried = backend
            .rebuild_legacy_journal(repo_id, &reconciled.to_bytes().unwrap(), committed)
            .unwrap();
        assert_eq!(retried, committed);
        assert!(!backend.delta_path(repo_id, 8).exists());
        assert!(!backend.legacy_rebuild_path(repo_id).exists());
        let recovered = load_recovered_snapshot(&backend, repo_id).unwrap().unwrap();
        assert_eq!(recovered.generation, retried);
        assert_eq!(recovered.snapshot.file_hashes, reconciled.file_hashes);
    }

    #[test]
    fn local_legacy_rebuild_retry_finalizes_lingering_marker_without_new_commit() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "legacy-rebuild-marker-retry";
        let base = GraphSnapshot::empty();
        let mut reconciled = base.clone();
        reconciled
            .file_hashes
            .insert("reconciled.rs".to_string(), [9; 32]);
        let delta_bytes = crate::storage::delta::GraphSnapshotDelta::empty(7)
            .to_bytes()
            .unwrap();
        std::fs::create_dir_all(backend.deltas_dir(repo_id)).unwrap();
        std::fs::write(backend.snapshot_path(repo_id), base.to_bytes().unwrap()).unwrap();
        std::fs::write(backend.generation_path(repo_id), b"8").unwrap();
        std::fs::write(backend.delta_path(repo_id, 8), &delta_bytes).unwrap();

        let committed = backend
            .rebuild_legacy_journal(repo_id, &reconciled.to_bytes().unwrap(), 8)
            .unwrap();
        assert_eq!(committed, 9);
        assert!(backend
            .load_deltas_since_unlocked(repo_id, GENERATION_INIT)
            .unwrap()
            .is_empty());

        // Model a crash/failure after the journal drain but before unlinking
        // the durable rebuild marker.
        let lingering = LocalLegacyRebuildRecord {
            version: LOCAL_LEGACY_REBUILD_VERSION,
            expected_generation: 8,
            committed_generation: committed,
            captured_deltas: vec![(
                format!("{:020}.kndd", 8),
                LocalFileBackend::snapshot_digest(&delta_bytes),
            )],
        };
        LocalFileBackend::atomic_write(
            &backend.legacy_rebuild_path(repo_id),
            &serde_json::to_vec(&lingering).unwrap(),
        )
        .unwrap();

        let retried = backend
            .rebuild_legacy_journal(repo_id, &reconciled.to_bytes().unwrap(), committed)
            .expect("marker-only retry must finalize idempotently");
        assert_eq!(retried, committed);
        assert!(!backend.legacy_rebuild_path(repo_id).exists());
        assert!(!backend
            .versioned_snapshot_path(repo_id, committed + 1)
            .exists());
        assert_eq!(
            load_recovered_snapshot(&backend, repo_id)
                .unwrap()
                .unwrap()
                .generation,
            committed
        );
    }

    #[test]
    fn local_legacy_rebuild_never_unlinks_a_post_quarantine_replacement() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "legacy-rebuild-unlink-race";
        let base = GraphSnapshot::empty();
        let captured = crate::storage::delta::GraphSnapshotDelta::empty(7)
            .to_bytes()
            .unwrap();
        let mut replacement_delta = crate::storage::delta::GraphSnapshotDelta::empty(7);
        replacement_delta
            .file_hashes
            .added
            .push(("raced.rs".to_string(), [8; 32]));
        let replacement = replacement_delta.to_bytes().unwrap();
        std::fs::create_dir_all(backend.deltas_dir(repo_id)).unwrap();
        std::fs::write(backend.snapshot_path(repo_id), base.to_bytes().unwrap()).unwrap();
        std::fs::write(backend.generation_path(repo_id), b"8").unwrap();
        std::fs::write(backend.delta_path(repo_id, 8), &captured).unwrap();

        let delta_path = backend.delta_path(repo_id, 8);
        let raced_path = delta_path.clone();
        let expected_replacement = replacement.clone();
        backend.set_cleanup_after_quarantine_hook(move || {
            LocalFileBackend::atomic_write(&raced_path, &replacement).unwrap();
        });

        let committed = backend
            .rebuild_legacy_journal(repo_id, &base.to_bytes().unwrap(), 8)
            .expect("authority commit must survive a cleanup race");
        assert_eq!(committed, 9);
        assert_eq!(
            std::fs::read(&delta_path).unwrap(),
            expected_replacement,
            "replacement installed after atomic quarantine must remain canonical"
        );
        assert!(backend.legacy_rebuild_path(repo_id).exists());
        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("pending marker must keep raced legacy cleanup fail-closed");
        assert!(error.to_string().contains("pending legacy-journal rebuild"));
    }

    #[test]
    fn local_v1_authority_journal_requires_and_supports_explicit_rebuild() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "legacy-v1-authority";
        let base = GraphSnapshot::empty();
        let base_generation = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut reconciled = base.clone();
        reconciled.file_hashes.insert("v1.rs".to_string(), [4; 32]);
        let delta = crate::storage::delta::compute_graph_delta(&base, &reconciled, base_generation);
        let head_generation = backend
            .save_delta(repo_id, &delta.to_bytes().unwrap(), base_generation)
            .unwrap();

        let mut legacy = backend
            .read_authority_record_raw_unlocked(repo_id)
            .unwrap()
            .unwrap();
        legacy.version = LOCAL_AUTHORITY_LEGACY_VERSION;
        legacy.acknowledged_deltas.clear();
        backend.write_authority_unlocked(repo_id, &legacy).unwrap();

        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("v1 journal authority must not be served without byte identities");
        assert!(error.to_string().contains("without exact delta identities"));

        let committed = backend
            .rebuild_legacy_journal(repo_id, &reconciled.to_bytes().unwrap(), head_generation)
            .expect("raw rebuild path must migrate v1 journal authority");
        assert_eq!(committed, head_generation + 1);
        let recovered = load_recovered_snapshot(&backend, repo_id).unwrap().unwrap();
        assert_eq!(recovered.generation, committed);
        assert_eq!(recovered.snapshot.file_hashes, reconciled.file_hashes);
    }

    #[test]
    fn local_v3_retired_authority_is_rejected_by_a_v2_reader_gate() {
        #[derive(Deserialize)]
        struct V2AuthorityEnvelope {
            version: u32,
        }

        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "v3-authority-version-fence";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let delta = crate::storage::delta::GraphSnapshotDelta::empty(gen1);
        let gen2 = backend
            .save_delta(repo_id, &delta.to_bytes().unwrap(), gen1)
            .unwrap();
        backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), gen2)
            .unwrap();

        let bytes = std::fs::read(backend.authority_path(repo_id)).unwrap();
        let old_reader: V2AuthorityEnvelope = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(old_reader.version, LOCAL_AUTHORITY_VERSION);
        assert!(
            !matches!(
                old_reader.version,
                LOCAL_AUTHORITY_LEGACY_VERSION | LOCAL_AUTHORITY_ACKNOWLEDGED_VERSION
            ),
            "a v2 reader must reject the v3 record before ignoring retired-delta semantics"
        );
    }

    #[test]
    fn local_legacy_rebuild_rejects_stale_quiesce_cursor_without_mutation() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "legacy-rebuild-stale";
        std::fs::create_dir_all(backend.deltas_dir(repo_id)).unwrap();
        let bytes = GraphSnapshot::empty().to_bytes().unwrap();
        std::fs::write(backend.snapshot_path(repo_id), &bytes).unwrap();
        std::fs::write(backend.generation_path(repo_id), b"4").unwrap();
        std::fs::write(
            backend.delta_path(repo_id, 4),
            crate::storage::delta::GraphSnapshotDelta::empty(3)
                .to_bytes()
                .unwrap(),
        )
        .unwrap();
        let error = backend
            .rebuild_legacy_journal(repo_id, &bytes, 3)
            .expect_err("stale migration cursor must fail before authority commit");
        assert!(error.to_string().contains("expected 3, observed head 4"));
        assert!(!backend.authority_path(repo_id).exists());
        assert!(backend.delta_path(repo_id, 4).exists());
    }

    #[test]
    fn local_atomic_authority_rejects_post_migration_legacy_writer() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "mixed-version-writer";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();

        // Model a pre-authority binary committing through graph.kndb.gen after
        // the new authority record already exists. Its old path reports success
        // without advancing authority.json.
        let legacy_delta = crate::storage::delta::GraphSnapshotDelta::empty(gen1);
        LocalFileBackend::atomic_write(
            &backend.delta_path(repo_id, gen1 + 1),
            &legacy_delta.to_bytes().unwrap(),
        )
        .unwrap();
        backend.write_generation(repo_id, gen1 + 1).unwrap();

        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("mixed-version writer divergence must fail closed");
        assert!(error.to_string().contains("legacy local writer advanced"));
    }

    #[test]
    fn local_authority_rejects_equal_head_legacy_full_snapshot_divergence() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "equal-head-full-writer";
        let base = GraphSnapshot::empty();
        let generation = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut replacement_snapshot = GraphSnapshot::empty();
        replacement_snapshot
            .file_hashes
            .insert("legacy-full.rs".to_string(), [4; 32]);
        let replacement = replacement_snapshot.to_bytes().unwrap();
        LocalFileBackend::atomic_write(&backend.snapshot_path(repo_id), &replacement).unwrap();
        backend.write_generation(repo_id, generation).unwrap();

        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("valid equal-head legacy full snapshot divergence must fail closed");
        assert!(error.to_string().contains("valid snapshot bytes"));
        assert_eq!(
            std::fs::read(backend.snapshot_path(repo_id)).unwrap(),
            replacement,
            "authority projection healing must not erase a valid mixed-version full commit"
        );
    }

    #[test]
    fn local_authority_rejects_legacy_projection_advanced_to_delta_head() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "delta-head-full-writer";
        let base = GraphSnapshot::empty();
        let base_generation = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let delta = crate::storage::delta::GraphSnapshotDelta::empty(base_generation);
        let head_generation = backend
            .save_delta(repo_id, &delta.to_bytes().unwrap(), base_generation)
            .unwrap();
        let mut replacement_snapshot = GraphSnapshot::empty();
        replacement_snapshot
            .file_hashes
            .insert("legacy-head.rs".to_string(), [5; 32]);
        let replacement = replacement_snapshot.to_bytes().unwrap();
        LocalFileBackend::atomic_write(&backend.snapshot_path(repo_id), &replacement).unwrap();
        backend.write_generation(repo_id, head_generation).unwrap();

        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("legacy marker at delta head must not be mistaken for base projection");
        assert!(error.to_string().contains("beyond atomic authority base"));
        assert_eq!(
            std::fs::read(backend.snapshot_path(repo_id)).unwrap(),
            replacement
        );
    }

    #[test]
    fn local_atomic_authority_rejects_reserved_generation_delta_artifact() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "reserved-delta-generation";
        backend
            .save_snapshot(
                repo_id,
                &GraphSnapshot::empty().to_bytes().unwrap(),
                GENERATION_INIT,
            )
            .unwrap();
        LocalFileBackend::atomic_write(
            &backend.delta_path(repo_id, GENERATION_INIT),
            &crate::storage::delta::GraphSnapshotDelta::empty(GENERATION_INIT)
                .to_bytes()
                .unwrap(),
        )
        .unwrap();

        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("reserved generation-0 journal artifacts must fail closed");
        assert!(error.to_string().contains("reserved or noncanonical"));
    }

    #[test]
    fn local_atomic_authority_rejects_replaced_acknowledged_delta_at_same_head() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "mixed-version-replaced-delta";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut current = base.clone();
        current
            .file_hashes
            .insert("committed.rs".to_string(), [7; 32]);
        let committed = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let gen2 = backend
            .save_delta(repo_id, &committed.to_bytes().unwrap(), gen1)
            .unwrap();

        // A pre-authority writer uses the deterministic generation filename
        // and replaces the already-acknowledged bytes without moving atomic
        // authority.
        let replacement = crate::storage::delta::GraphSnapshotDelta::empty(gen1);
        LocalFileBackend::atomic_write(
            &backend.delta_path(repo_id, gen2),
            &replacement.to_bytes().unwrap(),
        )
        .unwrap();
        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("authority must bind the exact acknowledged delta bytes");
        assert!(error
            .to_string()
            .contains("acknowledged delta digest mismatch"));
    }

    #[test]
    fn local_recovery_validates_the_exact_delta_bytes_it_returns() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "mixed-version-recovery-read-race";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut current = base.clone();
        current
            .file_hashes
            .insert("committed.rs".to_string(), [7; 32]);
        let committed = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let gen2 = backend
            .save_delta(repo_id, &committed.to_bytes().unwrap(), gen1)
            .unwrap();

        let delta_path = backend.delta_path(repo_id, gen2);
        let replacement = crate::storage::delta::GraphSnapshotDelta::empty(gen1)
            .to_bytes()
            .unwrap();
        backend.set_recovery_after_authority_hook(move || {
            LocalFileBackend::atomic_write(&delta_path, &replacement).unwrap();
        });

        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("recovery must hash the same bytes it is about to return and replay");
        assert!(
            error.to_string().contains("while loading recovery bytes"),
            "unexpected recovery race error: {error}"
        );
    }

    #[test]
    fn local_recovery_revalidates_retired_delta_replaced_after_authority_read() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "retired-recovery-read-race";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut current = base.clone();
        current
            .file_hashes
            .insert("retired.rs".to_string(), [7; 32]);
        let delta = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let gen2 = backend
            .save_delta(repo_id, &delta.to_bytes().unwrap(), gen1)
            .unwrap();
        backend
            .save_snapshot(repo_id, &current.to_bytes().unwrap(), gen2)
            .unwrap();

        let delta_path = backend.delta_path(repo_id, gen2);
        let replacement = crate::storage::delta::GraphSnapshotDelta::empty(gen1)
            .to_bytes()
            .unwrap();
        backend.set_recovery_after_authority_hook(move || {
            LocalFileBackend::atomic_write(&delta_path, &replacement).unwrap();
        });

        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("retired bytes replaced after manifest validation must fail closed");
        assert!(
            error.to_string().contains("retired delta digest mismatch"),
            "unexpected retired recovery race error: {error}"
        );
    }

    #[test]
    fn local_backend_recovery_does_not_reapply_stale_deltas_after_full_promotion() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "promoted-repo";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();

        let mut current = base.clone();
        current
            .file_hashes
            .insert("current.rs".to_string(), [7; 32]);
        let delta = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let gen2 = backend
            .save_delta(repo_id, &delta.to_bytes().unwrap(), gen1)
            .unwrap();

        // Model a crash after full snapshot promotion but before clear_deltas.
        let gen3 = backend
            .save_snapshot(repo_id, &current.to_bytes().unwrap(), gen2)
            .unwrap();
        assert_eq!(gen3, 3);

        let recovered = load_recovered_snapshot(&backend, repo_id)
            .unwrap()
            .expect("promoted snapshot exists");
        assert_eq!(recovered.generation, gen3);
        assert_eq!(recovered.deltas_seen, 0);
        assert_eq!(recovered.deltas_applied, 0);
        assert_eq!(recovered.snapshot.file_hashes.len(), 1);
        assert!(recovered.snapshot.file_hashes.contains_key("current.rs"));
    }

    #[test]
    fn local_backend_clear_deltas() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();
        let gen1 = backend
            .save_snapshot("test-repo", &bytes, GENERATION_INIT)
            .unwrap();

        // Save two deltas
        let empty_delta = crate::storage::delta::compute_graph_delta(
            &GraphSnapshot::empty(),
            &GraphSnapshot::empty(),
            gen1,
        );
        let delta_bytes = empty_delta.to_bytes().unwrap();
        let gen2 = backend.save_delta("test-repo", &delta_bytes, gen1).unwrap();
        let second_delta = crate::storage::delta::GraphSnapshotDelta::empty(gen2);
        backend
            .save_delta("test-repo", &second_delta.to_bytes().unwrap(), gen2)
            .unwrap();

        // Should have 2 deltas
        let deltas = backend.load_deltas_since("test-repo", gen1).unwrap();
        assert_eq!(deltas.len(), 2);

        let error = backend
            .clear_deltas("test-repo")
            .expect_err("authoritative deltas cannot be cleared before promotion");
        assert!(error
            .to_string()
            .contains("refusing to clear authoritative"));

        // Promote the recovered head, then journal cleanup is safe.
        let recovered = load_recovered_snapshot(&backend, "test-repo")
            .unwrap()
            .unwrap();
        backend
            .save_snapshot(
                "test-repo",
                &recovered.snapshot.to_bytes().unwrap(),
                recovered.generation,
            )
            .unwrap();
        backend.clear_deltas("test-repo").unwrap();
        let empty = backend.load_deltas_since("test-repo", gen1).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn local_snapshot_promotion_crash_before_authority_keeps_old_chain_recoverable() {
        let dir = TempDir::new().unwrap();
        let repo_id = "promotion-crash";
        let backend = LocalFileBackend::new(dir.path());
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut current = base.clone();
        current.file_hashes.insert("delta.rs".to_string(), [9; 32]);
        let delta = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let gen2 = backend
            .save_delta(repo_id, &delta.to_bytes().unwrap(), gen1)
            .unwrap();

        backend.fail_next_snapshot_before_authority_commit();
        let error = backend
            .save_snapshot(repo_id, &current.to_bytes().unwrap(), gen2)
            .expect_err("injected inner-window crash must abort before authority commit");
        assert!(error
            .to_string()
            .contains("before local snapshot authority"));
        assert!(backend.versioned_snapshot_path(repo_id, 3).exists());

        let reopened = LocalFileBackend::new(dir.path());
        let recovered = load_recovered_snapshot(&reopened, repo_id)
            .unwrap()
            .expect("old base plus acknowledged delta remains authoritative");
        assert_eq!(recovered.generation, gen2);
        assert_eq!(recovered.deltas_applied, 1);
        assert!(recovered.snapshot.file_hashes.contains_key("delta.rs"));

        let gen3 = reopened
            .save_snapshot(repo_id, &current.to_bytes().unwrap(), gen2)
            .expect("retry promotes the staged generation atomically");
        assert_eq!(gen3, 3);
        let promoted = load_recovered_snapshot(&reopened, repo_id)
            .unwrap()
            .expect("promoted snapshot exists");
        assert_eq!(promoted.generation, gen3);
        assert_eq!(promoted.deltas_applied, 0);
        assert!(promoted.snapshot.file_hashes.contains_key("delta.rs"));
    }

    #[test]
    fn local_full_authority_post_rename_sync_failure_retries_exact_cursor_without_early_gc() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "authority-post-rename-sync";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut current = base.clone();
        current.file_hashes.insert("delta.rs".to_string(), [9; 32]);
        let delta = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let gen2 = backend
            .save_delta(repo_id, &delta.to_bytes().unwrap(), gen1)
            .unwrap();
        let old_snapshot = backend.versioned_snapshot_path(repo_id, gen1);
        let delta_path = backend.delta_path(repo_id, gen2);
        backend.set_snapshot_before_authority_commit_hook(|| {
            // Authority candidate publication and exact candidate claim consume
            // two syncs; fail the destination rename sync.
            mmap::fail_parent_sync_after(2);
        });

        let error = backend
            .save_snapshot(repo_id, &current.to_bytes().unwrap(), gen2)
            .expect_err("installed but unconfirmed authority must be reported");
        assert!(error.to_string().contains("durability is unconfirmed"));
        assert!(mmap::recovery_marker_path(&backend.authority_path(repo_id)).exists());
        assert!(
            old_snapshot.exists(),
            "old base must not be GC'd before confirmation"
        );
        assert!(
            delta_path.exists(),
            "retired journal must not be GC'd before confirmation"
        );

        let generation = backend
            .save_snapshot(repo_id, &current.to_bytes().unwrap(), gen2)
            .expect("exact retry must confirm and return the installed cursor");
        assert_eq!(generation, gen2 + 1);
        assert!(!mmap::recovery_marker_path(&backend.authority_path(repo_id)).exists());
        let recovered = load_recovered_snapshot(&backend, repo_id).unwrap().unwrap();
        assert_eq!(recovered.generation, generation);
        assert_eq!(recovered.snapshot.file_hashes, current.file_hashes);
    }

    #[test]
    fn local_delta_authority_post_rename_sync_failure_retries_exact_cursor() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "delta-authority-post-rename-sync";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let delta = crate::storage::delta::GraphSnapshotDelta::empty(gen1);
        let delta_bytes = delta.to_bytes().unwrap();
        // The delta write consumes five syncs. Authority candidate install
        // plus the exact candidate claim consume two more; fail its
        // destination rename sync.
        mmap::fail_parent_sync_after(7);

        let error = backend
            .save_delta(repo_id, &delta_bytes, gen1)
            .expect_err("installed but unconfirmed delta authority must be reported");
        assert!(error.to_string().contains("durability is unconfirmed"));
        assert!(backend.delta_path(repo_id, gen1 + 1).exists());
        assert!(mmap::recovery_marker_path(&backend.authority_path(repo_id)).exists());

        let retried = backend
            .save_delta(repo_id, &delta_bytes, gen1)
            .expect("exact retry must confirm installed delta cursor");
        assert_eq!(retried, gen1 + 1);
        assert!(!mmap::recovery_marker_path(&backend.authority_path(repo_id)).exists());
    }

    #[test]
    fn initial_full_promotion_cas_binds_legacy_projection_bytes_and_marker() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "initial-projection-race";
        let mut requested = GraphSnapshot::empty();
        requested
            .file_hashes
            .insert("requested.rs".to_string(), [1; 32]);
        let mut raced = GraphSnapshot::empty();
        raced.file_hashes.insert("raced.rs".to_string(), [2; 32]);
        let raced_bytes = raced.to_bytes().unwrap();
        let projection_path = backend.snapshot_path(repo_id);
        let generation_path = backend.generation_path(repo_id);
        let installed_race = raced_bytes.clone();
        backend.set_snapshot_before_authority_commit_hook(move || {
            std::fs::write(&projection_path, &installed_race).unwrap();
            std::fs::write(&generation_path, b"1").unwrap();
        });

        let error = backend
            .save_snapshot(repo_id, &requested.to_bytes().unwrap(), GENERATION_INIT)
            .expect_err("racing legacy full commit must win CAS without being overwritten");
        assert!(error
            .to_string()
            .contains("legacy full-snapshot projection changed"));
        assert!(!backend.authority_path(repo_id).exists());
        assert_eq!(
            std::fs::read(backend.snapshot_path(repo_id)).unwrap(),
            raced_bytes
        );
    }

    #[test]
    fn full_projection_publish_preserves_race_after_authority_commit() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "post-authority-projection-race";
        let mut requested = GraphSnapshot::empty();
        requested
            .file_hashes
            .insert("requested.rs".to_string(), [8; 32]);
        let mut raced = GraphSnapshot::empty();
        raced.file_hashes.insert("raced.rs".to_string(), [9; 32]);
        let raced_bytes = raced.to_bytes().unwrap();
        let projection_path = backend.snapshot_path(repo_id);
        let generation_path = backend.generation_path(repo_id);
        let installed_race = raced_bytes.clone();
        backend.set_snapshot_after_authority_before_projection_hook(move || {
            std::fs::write(&projection_path, &installed_race).unwrap();
            std::fs::write(&generation_path, b"1").unwrap();
        });

        let committed = backend
            .save_snapshot(repo_id, &requested.to_bytes().unwrap(), GENERATION_INIT)
            .expect("authority commit remains successful when a legacy projection races");
        assert_eq!(committed, 1);
        assert_eq!(
            std::fs::read(backend.snapshot_path(repo_id)).unwrap(),
            raced_bytes
        );
        assert_eq!(
            std::fs::read(backend.generation_path(repo_id)).unwrap(),
            b"1"
        );
        let error = backend
            .load_snapshot(repo_id)
            .expect_err("preserved equal-head divergence must remain fail-closed");
        assert!(error.to_string().contains("mixed-version"));
    }

    #[test]
    fn quarantine_cleanup_waits_for_authoritative_snapshot_payload_verification() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "quarantine-after-payload";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let delta_bytes = crate::storage::delta::GraphSnapshotDelta::empty(gen1)
            .to_bytes()
            .unwrap();
        let gen2 = backend.save_delta(repo_id, &delta_bytes, gen1).unwrap();
        let gen3 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), gen2)
            .unwrap();
        let canonical = backend.delta_path(repo_id, gen2);
        let quarantine = quarantine_delta_path(
            &canonical,
            gen2,
            &LocalFileBackend::snapshot_digest(&delta_bytes),
        );
        std::fs::rename(&canonical, &quarantine).unwrap();
        std::fs::write(backend.versioned_snapshot_path(repo_id, gen3), b"corrupt").unwrap();

        let error = backend
            .load_snapshot(repo_id)
            .expect_err("invalid authority payload must fail before quarantine cleanup");
        assert!(error.to_string().contains("digest mismatch"));
        assert!(
            quarantine.exists(),
            "forensic quarantine must remain after payload failure"
        );
    }

    #[test]
    fn direct_delta_load_finalizes_only_authority_bound_quarantine() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "direct-delta-quarantine";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let delta_bytes = crate::storage::delta::GraphSnapshotDelta::empty(gen1)
            .to_bytes()
            .unwrap();
        let gen2 = backend.save_delta(repo_id, &delta_bytes, gen1).unwrap();
        backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), gen2)
            .unwrap();
        let canonical = backend.delta_path(repo_id, gen2);
        let quarantine = quarantine_delta_path(
            &canonical,
            gen2,
            &LocalFileBackend::snapshot_digest(&delta_bytes),
        );
        std::fs::rename(&canonical, &quarantine).unwrap();

        let deltas = backend
            .load_deltas_since(repo_id, GENERATION_INIT)
            .expect("direct delta load must verify authority then finalize its quarantine");
        assert!(deltas.is_empty());
        assert!(!quarantine.exists());

        let unbound_repo = "unbound-direct-delta-quarantine";
        std::fs::create_dir_all(backend.deltas_dir(unbound_repo)).unwrap();
        let unbound_canonical = backend.delta_path(unbound_repo, 1);
        let unbound = quarantine_delta_path(
            &unbound_canonical,
            1,
            &LocalFileBackend::snapshot_digest(&delta_bytes),
        );
        std::fs::write(&unbound, &delta_bytes).unwrap();
        let error = backend
            .load_deltas_since(unbound_repo, GENERATION_INIT)
            .expect_err("quarantine without authority must fail closed");
        assert!(error.to_string().contains("no atomic authority"));
        assert!(unbound.exists());
    }

    #[test]
    fn explicit_rebuild_floors_generation_above_ahead_legacy_marker() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "ahead-legacy-rebuild";
        let base = GraphSnapshot::empty();
        let authority_generation = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let legacy_generation = authority_generation + 1;
        std::fs::create_dir_all(backend.deltas_dir(repo_id)).unwrap();
        std::fs::write(
            backend.delta_path(repo_id, legacy_generation),
            crate::storage::delta::GraphSnapshotDelta::empty(authority_generation)
                .to_bytes()
                .unwrap(),
        )
        .unwrap();
        std::fs::write(
            backend.generation_path(repo_id),
            legacy_generation.to_string(),
        )
        .unwrap();

        let stale = backend
            .rebuild_legacy_journal(repo_id, &base.to_bytes().unwrap(), authority_generation)
            .expect_err("authority cursor below the journal head must be rejected");
        assert!(stale
            .to_string()
            .contains(&format!("observed head {legacy_generation}")));
        let committed = backend
            .rebuild_legacy_journal(repo_id, &base.to_bytes().unwrap(), legacy_generation)
            .expect("explicit rebuild should accept the fully reconciled legacy cursor");
        assert_eq!(committed, legacy_generation + 1);
    }

    #[test]
    fn explicit_rebuild_rejects_quarantine_without_authority() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "rebuild-unbound-quarantine";
        let bytes = GraphSnapshot::empty().to_bytes().unwrap();
        std::fs::create_dir_all(backend.deltas_dir(repo_id)).unwrap();
        std::fs::write(backend.snapshot_path(repo_id), &bytes).unwrap();
        std::fs::write(backend.generation_path(repo_id), b"1").unwrap();
        let delta_bytes = crate::storage::delta::GraphSnapshotDelta::empty(GENERATION_INIT)
            .to_bytes()
            .unwrap();
        std::fs::write(backend.delta_path(repo_id, 1), &delta_bytes).unwrap();
        let quarantine = quarantine_delta_path(
            &backend.delta_path(repo_id, 1),
            1,
            &LocalFileBackend::snapshot_digest(&delta_bytes),
        );
        std::fs::write(&quarantine, &delta_bytes).unwrap();

        let error = backend
            .rebuild_legacy_journal(repo_id, &bytes, 1)
            .expect_err("explicit rebuild must reject quarantine without authority");
        assert!(error.to_string().contains("no atomic authority"));
        assert!(quarantine.exists());
        assert!(!backend.authority_path(repo_id).exists());
    }

    #[test]
    fn explicit_rebuild_cas_preserves_racing_legacy_full_commit() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "legacy-rebuild-projection-race";
        let base = GraphSnapshot::empty();
        let authority_generation = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let legacy_generation = authority_generation + 1;
        std::fs::create_dir_all(backend.deltas_dir(repo_id)).unwrap();
        std::fs::write(
            backend.delta_path(repo_id, legacy_generation),
            crate::storage::delta::GraphSnapshotDelta::empty(authority_generation)
                .to_bytes()
                .unwrap(),
        )
        .unwrap();
        std::fs::write(
            backend.generation_path(repo_id),
            legacy_generation.to_string(),
        )
        .unwrap();
        let mut raced = GraphSnapshot::empty();
        raced.file_hashes.insert("raced.rs".to_string(), [4; 32]);
        let raced_bytes = raced.to_bytes().unwrap();
        let projection_path = backend.snapshot_path(repo_id);
        let generation_path = backend.generation_path(repo_id);
        let installed_race = raced_bytes.clone();
        backend.set_snapshot_before_authority_commit_hook(move || {
            std::fs::write(&projection_path, &installed_race).unwrap();
            std::fs::write(&generation_path, (legacy_generation + 1).to_string()).unwrap();
        });

        let error = backend
            .rebuild_legacy_journal(repo_id, &base.to_bytes().unwrap(), legacy_generation)
            .expect_err("racing legacy full commit must abort rebuild authority CAS");
        assert!(error
            .to_string()
            .contains("full-snapshot projection changed"));
        let authority: LocalAuthorityRecord =
            serde_json::from_slice(&std::fs::read(backend.authority_path(repo_id)).unwrap())
                .unwrap();
        assert_eq!(authority.head_generation, authority_generation);
        assert_eq!(
            std::fs::read(backend.snapshot_path(repo_id)).unwrap(),
            raced_bytes
        );
    }

    #[test]
    fn local_full_save_rejects_a_staged_next_delta_before_commit() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "staged-next-before-save";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        LocalFileBackend::atomic_write(
            &backend.delta_path(repo_id, gen1 + 1),
            &crate::storage::delta::GraphSnapshotDelta::empty(gen1)
                .to_bytes()
                .unwrap(),
        )
        .unwrap();

        let error = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), gen1)
            .expect_err("full save must not commit over a staged next-generation delta");
        assert!(error.to_string().contains("staged unacknowledged delta"));
        let authority = backend
            .read_authority_record_raw_unlocked(repo_id)
            .unwrap()
            .unwrap();
        assert_eq!(authority.head_generation, gen1);
        assert!(backend.delta_path(repo_id, gen1 + 1).exists());
    }

    #[test]
    fn local_full_save_rechecks_for_a_staged_delta_before_authority_commit() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "staged-next-during-save";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let staged_path = backend.delta_path(repo_id, gen1 + 1);
        backend.set_snapshot_before_authority_commit_hook(move || {
            LocalFileBackend::atomic_write(
                &staged_path,
                &crate::storage::delta::GraphSnapshotDelta::empty(gen1)
                    .to_bytes()
                    .unwrap(),
            )
            .unwrap();
        });

        let error = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), gen1)
            .expect_err("the pre-commit rescan must catch a staged delta from a racing writer");
        assert!(error.to_string().contains("staged unacknowledged delta"));
        let authority = backend
            .read_authority_record_raw_unlocked(repo_id)
            .unwrap()
            .unwrap();
        assert_eq!(authority.head_generation, gen1);
    }

    fn local_backend_with_two_deltas() -> (TempDir, LocalFileBackend, &'static str) {
        let dir = TempDir::new().unwrap();
        let repo_id = "incomplete-chain";
        let backend = LocalFileBackend::new(dir.path());
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let first = crate::storage::delta::GraphSnapshotDelta::empty(gen1);
        let gen2 = backend
            .save_delta(repo_id, &first.to_bytes().unwrap(), gen1)
            .unwrap();
        let second = crate::storage::delta::GraphSnapshotDelta::empty(gen2);
        backend
            .save_delta(repo_id, &second.to_bytes().unwrap(), gen2)
            .unwrap();
        (dir, backend, repo_id)
    }

    #[test]
    fn local_recovery_rejects_missing_delta_prefix() {
        let (_dir, backend, repo_id) = local_backend_with_two_deltas();
        std::fs::remove_file(backend.delta_path(repo_id, 2)).unwrap();
        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("missing first delta must fail closed");
        assert!(error.to_string().contains("expected generation 2, found 3"));
    }

    #[test]
    fn local_recovery_rejects_missing_delta_head() {
        let (_dir, backend, repo_id) = local_backend_with_two_deltas();
        std::fs::remove_file(backend.delta_path(repo_id, 3)).unwrap();
        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("missing acknowledged head must fail closed");
        assert!(error
            .to_string()
            .contains("delta chain ended at generation 2, acknowledged head is 3"));
    }

    #[test]
    fn local_backend_compact_deltas() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        // Create initial snapshot with one file hash
        let mut snapshot = GraphSnapshot::empty();
        snapshot.file_hashes.insert("old.rs".to_string(), [1; 32]);
        let bytes = snapshot.to_bytes().unwrap();
        let gen1 = backend
            .save_snapshot("test-repo", &bytes, GENERATION_INIT)
            .unwrap();

        // Create a delta that adds a new file hash
        let mut new_snapshot = snapshot.clone();
        new_snapshot
            .file_hashes
            .insert("new.rs".to_string(), [2; 32]);
        let delta = crate::storage::delta::compute_graph_delta(&snapshot, &new_snapshot, gen1);
        let delta_bytes = delta.to_bytes().unwrap();
        let _gen2 = backend.save_delta("test-repo", &delta_bytes, gen1).unwrap();

        // Compact: merges delta into snapshot
        let compacted_gen = backend.compact_deltas("test-repo").unwrap();
        assert!(compacted_gen > gen1);

        // No more deltas
        let deltas = backend
            .load_deltas_since("test-repo", GENERATION_INIT)
            .unwrap();
        assert!(deltas.is_empty());

        // Snapshot now contains both file hashes
        let (snap_bytes, _) = backend.load_snapshot("test-repo").unwrap().unwrap();
        let compacted = GraphSnapshot::from_bytes(&snap_bytes).unwrap();
        assert_eq!(compacted.file_hashes.len(), 2);
        assert!(compacted.file_hashes.contains_key("old.rs"));
        assert!(compacted.file_hashes.contains_key("new.rs"));
    }

    #[test]
    fn local_compaction_returns_committed_cursor_when_cleanup_fails() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "cleanup-cursor";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut current = base.clone();
        current.file_hashes.insert("delta.rs".to_string(), [7; 32]);
        let delta = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let head = backend
            .save_delta(repo_id, &delta.to_bytes().unwrap(), gen1)
            .unwrap();
        backend.fail_next_delta_cleanup();

        let committed = backend
            .compact_deltas(repo_id)
            .expect("post-commit cleanup failure must not discard the new cursor");
        assert!(committed > head);
        let authority = backend.load_snapshot_authority(repo_id).unwrap().unwrap();
        assert_eq!(authority.snapshot_generation, committed);
        assert_eq!(authority.head_generation, committed);
        assert!(backend.delta_path(repo_id, head).exists());
        let recovered = load_recovered_snapshot(&backend, repo_id).unwrap().unwrap();
        assert_eq!(recovered.generation, committed);
        assert_eq!(recovered.snapshot.file_hashes, current.file_hashes);
    }

    #[test]
    fn local_compaction_preserves_post_authority_replacement_and_fails_closed() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "compaction-cleanup-race";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut current = base.clone();
        current
            .file_hashes
            .insert("committed.rs".to_string(), [7; 32]);
        let committed_delta = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let delta_generation = backend
            .save_delta(repo_id, &committed_delta.to_bytes().unwrap(), gen1)
            .unwrap();

        let delta_path = backend.delta_path(repo_id, delta_generation);
        let replacement = crate::storage::delta::GraphSnapshotDelta::empty(gen1)
            .to_bytes()
            .unwrap();
        let expected_replacement = replacement.clone();
        let raced_path = delta_path.clone();
        backend.set_compaction_before_delta_cleanup_hook(move || {
            LocalFileBackend::atomic_write(&raced_path, &replacement).unwrap();
        });

        let promoted_generation = backend
            .compact_deltas(repo_id)
            .expect("post-commit cleanup race must return the promoted cursor");
        assert_eq!(promoted_generation, delta_generation + 1);
        assert_eq!(
            std::fs::read(&delta_path).unwrap(),
            expected_replacement,
            "cleanup must preserve journal bytes installed after authority commit"
        );
        let authority = backend
            .read_authority_record_raw_unlocked(repo_id)
            .unwrap()
            .unwrap();
        assert!(authority
            .retired_deltas
            .iter()
            .any(|identity| identity.generation == delta_generation));
        let error = load_recovered_snapshot(&backend, repo_id)
            .expect_err("replacement of retired journal bytes must fail closed");
        assert!(
            error.to_string().contains("retired delta digest mismatch"),
            "unexpected residual-journal error: {error}"
        );
    }

    #[test]
    fn local_reopen_finalizes_exact_quarantine_left_by_cleanup_crash() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "cleanup-quarantine-crash";
        let base = GraphSnapshot::empty();
        let gen1 = backend
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut current = base.clone();
        current
            .file_hashes
            .insert("retired.rs".to_string(), [7; 32]);
        let delta = crate::storage::delta::compute_graph_delta(&base, &current, gen1);
        let gen2 = backend
            .save_delta(repo_id, &delta.to_bytes().unwrap(), gen1)
            .unwrap();
        let gen3 = backend
            .save_snapshot(repo_id, &current.to_bytes().unwrap(), gen2)
            .unwrap();
        backend.set_cleanup_after_quarantine_hook(|| panic!("simulated cleanup crash"));

        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            backend.clear_deltas(repo_id).unwrap();
        }));
        assert!(crashed.is_err());
        assert!(!backend.delta_path(repo_id, gen2).exists());
        let quarantined: Vec<_> = std::fs::read_dir(backend.deltas_dir(repo_id))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(".kin-journal-cleanup-"))
            })
            .collect();
        assert_eq!(quarantined.len(), 1);

        let reopened = LocalFileBackend::new(dir.path());
        let recovered = load_recovered_snapshot(&reopened, repo_id)
            .unwrap()
            .expect("exact authority-bound quarantine must be finalized on reopen");
        assert_eq!(recovered.generation, gen3);
        assert_eq!(recovered.deltas_seen, 0);
        assert!(!quarantined[0].exists());
        reopened.clear_deltas(repo_id).unwrap();
    }

    #[test]
    fn local_backend_reclaims_superseded_immutable_bases_after_save_and_reopen() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());
        let repo_id = "base-cleanup";
        let bytes = GraphSnapshot::empty().to_bytes().unwrap();
        let gen1 = backend
            .save_snapshot(repo_id, &bytes, GENERATION_INIT)
            .unwrap();
        let gen2 = backend.save_snapshot(repo_id, &bytes, gen1).unwrap();
        assert!(!backend.versioned_snapshot_path(repo_id, gen1).exists());
        assert!(backend.versioned_snapshot_path(repo_id, gen2).exists());

        // A crash can leave an older base behind after authority commit. The
        // next locked load retries cleanup, while preserving a future staged
        // generation that may belong to an in-flight writer.
        std::fs::copy(
            backend.versioned_snapshot_path(repo_id, gen2),
            backend.versioned_snapshot_path(repo_id, gen1),
        )
        .unwrap();
        let future = backend.versioned_snapshot_path(repo_id, gen2 + 1);
        std::fs::copy(backend.versioned_snapshot_path(repo_id, gen2), &future).unwrap();
        let reopened = LocalFileBackend::new(dir.path());
        reopened.load_snapshot(repo_id).unwrap().unwrap();
        assert!(!reopened.versioned_snapshot_path(repo_id, gen1).exists());
        assert!(reopened.versioned_snapshot_path(repo_id, gen2).exists());
        assert!(future.exists());
    }

    #[test]
    fn local_backend_delta_base_gen_mismatch() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();
        backend
            .save_snapshot("test-repo", &bytes, GENERATION_INIT)
            .unwrap();

        // Try saving a delta with wrong base generation
        let delta = crate::storage::delta::compute_graph_delta(
            &GraphSnapshot::empty(),
            &GraphSnapshot::empty(),
            0,
        );
        let delta_bytes = delta.to_bytes().unwrap();
        let err = backend
            .save_delta("test-repo", &delta_bytes, GENERATION_INIT)
            .unwrap_err();
        assert!(err.to_string().contains("base generation mismatch"));
    }

    #[test]
    fn local_backend_list_repos() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        // No repos yet
        let repos = backend.list_repos().unwrap();
        assert!(repos.is_empty());

        // Save snapshots for two repos
        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();
        backend
            .save_snapshot("repo-a", &bytes, GENERATION_INIT)
            .unwrap();
        backend
            .save_snapshot("repo-b", &bytes, GENERATION_INIT)
            .unwrap();

        // Create a directory without a graph.kndb — should NOT appear
        std::fs::create_dir_all(dir.path().join("not-a-repo")).unwrap();

        let mut repos = backend.list_repos().unwrap();
        repos.sort();
        assert_eq!(repos, vec!["repo-a", "repo-b"]);
    }

    #[test]
    fn local_backend_multiple_repos_isolated() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        let snap = GraphSnapshot::empty();
        let bytes = snap.to_bytes().unwrap();

        backend
            .save_snapshot("repo-a", &bytes, GENERATION_INIT)
            .unwrap();
        backend
            .save_snapshot("repo-b", &bytes, GENERATION_INIT)
            .unwrap();

        // Each repo has its own generation
        let (_, gen_a) = backend.load_snapshot("repo-a").unwrap().unwrap();
        let (_, gen_b) = backend.load_snapshot("repo-b").unwrap().unwrap();
        assert_eq!(gen_a, 1);
        assert_eq!(gen_b, 1);

        // Advancing one doesn't affect the other
        backend.save_snapshot("repo-a", &bytes, gen_a).unwrap();
        let (_, gen_a2) = backend.load_snapshot("repo-a").unwrap().unwrap();
        let (_, gen_b2) = backend.load_snapshot("repo-b").unwrap().unwrap();
        assert_eq!(gen_a2, 2);
        assert_eq!(gen_b2, 1);
    }

    #[test]
    fn write_generation_is_atomic() {
        // Verify that write_generation produces a valid file that can be read back,
        // and that no .tmp file is left behind.
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        // Create the repo directory
        std::fs::create_dir_all(dir.path().join("test-repo")).unwrap();

        backend.write_generation("test-repo", 42).unwrap();

        // The generation reads back correctly
        let gen = backend.read_legacy_generation("test-repo").unwrap();
        assert_eq!(gen, 42);

        // No .tmp file left behind
        let tmp_path = backend.generation_path("test-repo").with_extension("tmp");
        assert!(
            !tmp_path.exists(),
            "tmp file should not remain after atomic write"
        );

        // The actual file has the correct content
        let content = std::fs::read_to_string(backend.generation_path("test-repo")).unwrap();
        assert_eq!(content, "42");
    }

    #[test]
    fn acquire_lock_creates_lock_file() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        let _lock = backend.acquire_lock("test-repo").unwrap();
        let lock_path = dir.path().join("test-repo").join(".lock");
        assert!(lock_path.exists(), "lock file should be created");
        // Lock is released when _lock is dropped
    }
}
