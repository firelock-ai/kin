// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Pluggable storage backend trait for graph snapshots.
//!
//! `StorageBackend` abstracts where snapshot bytes live — local filesystem
//! for CLI, GCS for cloud deployment. The daemon code calls
//! `backend.load_snapshot()` / `backend.save_snapshot()` without knowing
//! the underlying storage medium.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::KinDbError;
use crate::storage::format::GraphSnapshot;

/// Generation counter for compare-and-swap writes.
///
/// On local filesystems this is a monotonically increasing counter persisted
/// alongside the snapshot. On GCS this maps directly to the object generation.
pub type Generation = u64;

/// Sentinel value indicating no prior generation exists (first write).
pub const GENERATION_INIT: Generation = 0;

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
}

const LOCAL_AUTHORITY_VERSION: u32 = 2;
const LOCAL_AUTHORITY_LEGACY_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct LocalDeltaIdentity {
    generation: Generation,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        if !gen_path.exists() {
            return Ok(GENERATION_INIT);
        }
        let contents = std::fs::read_to_string(&gen_path).map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to read generation file {}: {e}",
                gen_path.display()
            ))
        })?;
        contents.trim().parse::<Generation>().map_err(|e| {
            KinDbError::StorageError(format!("invalid generation in {}: {e}", gen_path.display()))
        })
    }

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
        // Atomic write: tmp → fsync → rename (crash-safe)
        let tmp_path = gen_path.with_extension("tmp");
        let mut file = std::fs::File::create(&tmp_path).map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to create tmp generation file {}: {e}",
                tmp_path.display()
            ))
        })?;
        write!(file, "{}", gen).map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to write tmp generation file {}: {e}",
                tmp_path.display()
            ))
        })?;
        file.sync_all().map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to fsync tmp generation file {}: {e}",
                tmp_path.display()
            ))
        })?;
        std::fs::rename(&tmp_path, &gen_path).map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to rename {} → {}: {e}",
                tmp_path.display(),
                gen_path.display()
            ))
        })?;
        Self::sync_parent(&gen_path)
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
        let tmp_path = path.with_extension(format!(
            "{}.tmp",
            path.extension()
                .and_then(|extension| extension.to_str())
                .unwrap_or("file")
        ));
        {
            let mut file = std::fs::File::create(&tmp_path).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to create staged file {}: {error}",
                    tmp_path.display()
                ))
            })?;
            file.write_all(data).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to write staged file {}: {error}",
                    tmp_path.display()
                ))
            })?;
            file.sync_all().map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to fsync staged file {}: {error}",
                    tmp_path.display()
                ))
            })?;
        }
        std::fs::rename(&tmp_path, path).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to promote {} to {}: {error}",
                tmp_path.display(),
                path.display()
            ))
        })?;
        Self::sync_parent(path)
    }

    fn snapshot_file_name(generation: Generation) -> String {
        format!("{generation:020}.kndb")
    }

    fn snapshot_digest(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn file_digest(path: &Path) -> Result<String, KinDbError> {
        let mut file = std::fs::File::open(path).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to open {} for digest verification: {error}",
                path.display()
            ))
        })?;
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

    fn read_authority_record_raw_unlocked(
        &self,
        repo_id: &str,
    ) -> Result<Option<LocalAuthorityRecord>, KinDbError> {
        let path = self.authority_path(repo_id);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to read local authority {}: {error}",
                path.display()
            ))
        })?;
        let record: LocalAuthorityRecord = serde_json::from_slice(&bytes).map_err(|error| {
            KinDbError::StorageError(format!(
                "invalid local authority {}: {error}",
                path.display()
            ))
        })?;
        if record.version != LOCAL_AUTHORITY_VERSION
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
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to read local legacy rebuild marker {}: {error}",
                path.display()
            ))
        })?;
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
        if rebuild_path.exists() {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} has a pending legacy-journal rebuild marker {}; retry the explicit rebuild after quiescing legacy writers",
                rebuild_path.display()
            )));
        }
        let legacy_generation = self.read_legacy_generation(repo_id)?;
        if legacy_generation > record.head_generation {
            return Err(KinDbError::StorageError(format!(
                "legacy local writer advanced repo {repo_id} to generation {legacy_generation} beyond atomic authority head {}; drain pre-authority writers before retrying",
                record.head_generation
            )));
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
        Ok(Some(record))
    }

    fn refresh_compatibility_projection_unlocked(
        &self,
        repo_id: &str,
        record: &LocalAuthorityRecord,
        snapshot_bytes: &[u8],
    ) {
        // graph.kndb and graph.kndb.gen are one compatibility pair. The
        // projection contains the immutable base bytes, so its marker is the
        // base generation even when authority has acknowledged later deltas.
        // Bytes are promoted first; a crash before the marker write is healed
        // on the next locked load.
        let snapshot_path = self.snapshot_path(repo_id);
        let projection_generation = self.read_legacy_generation(repo_id).ok();
        let projection_matches_authority = snapshot_path.is_file()
            && Self::file_digest(&snapshot_path)
                .is_ok_and(|digest| digest == record.snapshot_sha256);
        if !projection_matches_authority
            || projection_generation != Some(record.snapshot_generation)
        {
            if let Err(error) = Self::atomic_write(&snapshot_path, snapshot_bytes) {
                tracing::warn!(repo_id, error = %error, "failed to heal local graph.kndb projection");
                return;
            }
        }
        if projection_generation != Some(record.snapshot_generation) {
            if let Err(error) = self.write_generation(repo_id, record.snapshot_generation) {
                tracing::warn!(repo_id, error = %error, "failed to heal legacy generation projection");
            }
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

    fn load_authority_unlocked(
        &self,
        repo_id: &str,
    ) -> Result<Option<SnapshotAuthority>, KinDbError> {
        if let Some(record) = self.read_authority_record_unlocked(repo_id)? {
            let path = self.snapshots_dir(repo_id).join(&record.snapshot_file);
            let snapshot_bytes = std::fs::read(&path).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to read authoritative snapshot {}: {error}",
                    path.display()
                ))
            })?;
            let digest = Self::snapshot_digest(&snapshot_bytes);
            if digest != record.snapshot_sha256 {
                return Err(KinDbError::StorageError(format!(
                    "authoritative snapshot digest mismatch for repo {repo_id}: expected {}, found {digest}",
                    record.snapshot_sha256
                )));
            }
            self.refresh_compatibility_projection_unlocked(repo_id, &record, &snapshot_bytes);
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

        let legacy_path = self.snapshot_path(repo_id);
        if !legacy_path.exists() {
            return Ok(None);
        }
        let mut legacy_has_deltas = false;
        if self.deltas_dir(repo_id).exists() {
            for entry in std::fs::read_dir(self.deltas_dir(repo_id)).map_err(|error| {
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
                    legacy_has_deltas = true;
                    break;
                }
            }
        }
        if legacy_has_deltas {
            return Err(KinDbError::StorageError(format!(
                "legacy local repo {repo_id} has deltas but no persisted snapshot-base authority; refusing unprovable replay"
            )));
        }
        let snapshot_bytes = std::fs::read(&legacy_path).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to read legacy snapshot {}: {error}",
                legacy_path.display()
            ))
        })?;
        let _snapshot = GraphSnapshot::from_bytes(&snapshot_bytes)?;
        let generation = self.read_legacy_generation(repo_id)?;
        let versioned_path = self.versioned_snapshot_path(repo_id, generation);
        Self::atomic_write(&versioned_path, &snapshot_bytes)?;
        let record = LocalAuthorityRecord {
            version: LOCAL_AUTHORITY_VERSION,
            snapshot_generation: generation,
            head_generation: generation,
            snapshot_file: Self::snapshot_file_name(generation),
            snapshot_sha256: Self::snapshot_digest(&snapshot_bytes),
            acknowledged_deltas: Vec::new(),
        };
        self.write_authority_unlocked(repo_id, &record)?;
        self.refresh_compatibility_projection_unlocked(repo_id, &record, &snapshot_bytes);
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
        Self::atomic_write(&self.authority_path(repo_id), &bytes)
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
            if path.file_name().and_then(|name| name.to_str()) != Some(canonical_name.as_str()) {
                return Err(KinDbError::StorageError(format!(
                    "delta authority {} has a noncanonical generation name",
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
                std::fs::read(&path)
                    .map(|bytes| (bytes, generation))
                    .map_err(|error| {
                        KinDbError::StorageError(format!(
                            "failed to read delta {}: {error}",
                            path.display()
                        ))
                    })
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
        let since = authority
            .as_ref()
            .map_or(GENERATION_INIT, |authority| authority.snapshot_generation);
        let deltas = self.load_deltas_since_unlocked(repo_id, since)?;
        if let Some(record) = authority_record.as_ref() {
            Self::validate_loaded_acknowledged_deltas(repo_id, record, &deltas)?;
        }
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
        let current_gen = current
            .as_ref()
            .map_or(GENERATION_INIT, |authority| authority.head_generation);
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

        let record = LocalAuthorityRecord {
            version: LOCAL_AUTHORITY_VERSION,
            snapshot_generation: new_gen,
            head_generation: new_gen,
            snapshot_file: Self::snapshot_file_name(new_gen),
            snapshot_sha256: Self::snapshot_digest(data),
            acknowledged_deltas: Vec::new(),
        };
        self.write_authority_unlocked(repo_id, &record)?;

        // These are compatibility projections, not authority. A failure after
        // the authority commit must not report the snapshot as uncommitted or
        // leave the caller using a stale CAS generation.
        self.refresh_compatibility_projection_unlocked(repo_id, &record, data);
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
        if let Some(committed_generation) = self.finalize_marker_only_legacy_rebuild_unlocked(
            repo_id,
            current_record.as_ref(),
            expected_gen,
        )? {
            return Ok(committed_generation);
        }
        let current_generation = current_record
            .as_ref()
            .map_or(self.read_legacy_generation(repo_id)?, |record| {
                record.head_generation
            });
        if current_generation != expected_gen {
            return Err(KinDbError::StorageError(format!(
                "legacy journal rebuild generation mismatch for repo {repo_id}: expected {expected_gen}, found {current_generation}; quiesce old writers and reconcile again"
            )));
        }
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
                != expected_gen
        {
            return Err(KinDbError::StorageError(format!(
                "legacy journal changed while rebuilding repo {repo_id}; authority was not committed"
            )));
        }

        let journal_head = captured
            .iter()
            .map(|(_, generation)| *generation)
            .max()
            .unwrap_or(expected_gen);
        let new_gen = checked_next_generation(
            expected_gen.max(journal_head),
            "local legacy journal rebuild",
        )?;
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

        let record = LocalAuthorityRecord {
            version: LOCAL_AUTHORITY_VERSION,
            snapshot_generation: new_gen,
            head_generation: new_gen,
            snapshot_file: Self::snapshot_file_name(new_gen),
            snapshot_sha256: Self::snapshot_digest(data),
            acknowledged_deltas: Vec::new(),
        };
        self.write_authority_unlocked(repo_id, &record)?;
        self.refresh_compatibility_projection_unlocked(repo_id, &record, data);

        let mut cleanup_complete = true;
        #[cfg(test)]
        if self
            .fail_legacy_rebuild_cleanup
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            cleanup_complete = false;
        }
        for (captured_bytes, generation) in &captured {
            #[cfg(test)]
            if !cleanup_complete {
                break;
            }
            let path = self.delta_path(repo_id, *generation);
            match std::fs::read(&path) {
                Ok(current_bytes) if current_bytes == *captured_bytes => {
                    if let Err(error) = std::fs::remove_file(&path) {
                        cleanup_complete = false;
                        tracing::warn!(repo_id, path = %path.display(), error = %error, "legacy rebuild committed; deferred captured-delta cleanup");
                    }
                }
                Ok(_) => {
                    cleanup_complete = false;
                    tracing::warn!(repo_id, path = %path.display(), "legacy rebuild preserved a delta that changed after capture");
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    cleanup_complete = false;
                    tracing::warn!(repo_id, path = %path.display(), error = %error, "legacy rebuild committed; could not verify captured delta for cleanup");
                }
            }
        }
        match self.load_deltas_since_unlocked(repo_id, GENERATION_INIT) {
            Ok(remaining) if remaining.is_empty() => {}
            Ok(_) => cleanup_complete = false,
            Err(error) => {
                cleanup_complete = false;
                tracing::warn!(repo_id, generation = new_gen, error = %error, "legacy rebuild committed; could not verify journal drain");
            }
        }
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
        let Some(mut record) = self.read_authority_record_unlocked(repo_id)? else {
            return Err(KinDbError::StorageError(format!(
                "repo {repo_id} has no atomic local snapshot authority; persist a full snapshot before deltas"
            )));
        };
        let current_gen = record.head_generation;
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
        record.acknowledged_deltas.push(LocalDeltaIdentity {
            generation: new_gen,
            sha256: Self::snapshot_digest(delta_data),
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
        self.load_deltas_since_unlocked(repo_id, since_gen)
    }

    fn clear_deltas(&self, repo_id: &str) -> Result<(), KinDbError> {
        let _lock = self.acquire_lock(repo_id)?;
        if let Some(authority) = self.load_authority_unlocked(repo_id)? {
            if authority.snapshot_generation != authority.head_generation {
                return Err(KinDbError::StorageError(format!(
                    "refusing to clear authoritative deltas for repo {repo_id}: snapshot generation {}, head {}",
                    authority.snapshot_generation, authority.head_generation
                )));
            }
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
        let deltas_dir = self.deltas_dir(repo_id);
        if !deltas_dir.exists() {
            return Ok(());
        }
        for entry in std::fs::read_dir(&deltas_dir).map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to read deltas directory {}: {e}",
                deltas_dir.display()
            ))
        })? {
            let entry = entry.map_err(|e| {
                KinDbError::StorageError(format!("failed to read delta entry: {e}"))
            })?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("kndd") {
                std::fs::remove_file(&path).map_err(|e| {
                    KinDbError::StorageError(format!(
                        "failed to remove delta {}: {e}",
                        path.display()
                    ))
                })?;
            }
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

        // Second write with correct generation succeeds
        let gen2 = backend.save_snapshot("test-repo", &bytes, gen1).unwrap();
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
        assert_eq!(retried, 10);
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
        assert!(error.to_string().contains("expected 3, found 4"));
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

        // A pre-authority writer uses the deterministic generation filename,
        // replaces the already-acknowledged bytes, and advances only its
        // compatibility marker to the same numeric head.
        let replacement = crate::storage::delta::GraphSnapshotDelta::empty(gen1);
        LocalFileBackend::atomic_write(
            &backend.delta_path(repo_id, gen2),
            &replacement.to_bytes().unwrap(),
        )
        .unwrap();
        backend.write_generation(repo_id, gen2).unwrap();

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
