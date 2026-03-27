// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Pluggable storage backend trait for graph snapshots.
//!
//! `StorageBackend` abstracts where snapshot bytes live — local filesystem
//! for CLI, GCS for cloud deployment. The daemon code calls
//! `backend.load_snapshot()` / `backend.save_snapshot()` without knowing
//! the underlying storage medium.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::KinDbError;
use crate::storage::format::GraphSnapshot;

/// Generation counter for compare-and-swap writes.
///
/// On local filesystems this is a monotonically increasing counter persisted
/// alongside the snapshot. On GCS this maps directly to the object generation.
pub type Generation = u64;

/// Sentinel value indicating no prior generation exists (first write).
pub const GENERATION_INIT: Generation = 0;

/// Pluggable storage backend for graph snapshots and overlay state.
///
/// All methods are synchronous — the caller (daemon) can wrap in
/// `spawn_blocking` if needed. Implementations must be `Send + Sync`
/// so they can be shared across threads behind an `Arc`.
pub trait StorageBackend: Send + Sync {
    /// Load a repo's graph snapshot.
    ///
    /// Returns `Ok(None)` if no snapshot exists yet (new repo).
    /// Returns `Ok(Some((bytes, generation)))` on success — the caller
    /// passes `bytes` to `GraphSnapshot::from_bytes()`.
    fn load_snapshot(&self, repo_id: &str) -> Result<Option<(Vec<u8>, Generation)>, KinDbError>;

    /// Save a snapshot with compare-and-swap semantics.
    ///
    /// `expected_gen` is the generation returned by the last `load_snapshot`.
    /// If the stored generation has changed since then (another writer
    /// committed), the backend must return an error.
    ///
    /// On success returns the new generation.
    fn save_snapshot(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError>;

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
        let (snap_bytes, snap_gen) = self
            .load_snapshot(repo_id)?
            .ok_or_else(|| KinDbError::StorageError("no snapshot to compact".to_string()))?;

        // Load ALL deltas (since gen 0) because the shared generation counter
        // is advanced by both save_snapshot and save_delta, so snap_gen may
        // already include delta generations.
        let deltas = self.load_deltas_since(repo_id, GENERATION_INIT)?;
        if deltas.is_empty() {
            return Ok(snap_gen);
        }

        let mut snapshot = GraphSnapshot::from_bytes(&snap_bytes)?;
        for (delta_bytes, _gen) in &deltas {
            let delta = crate::storage::delta::GraphSnapshotDelta::from_bytes(delta_bytes)?;
            crate::storage::delta::apply_graph_delta(&mut snapshot, &delta);
        }

        // GC pass: remove orphaned cross-references accumulated over deltas
        snapshot.compact();

        let merged_bytes = snapshot.to_bytes()?;
        let new_gen = self.save_snapshot(repo_id, &merged_bytes, snap_gen)?;
        self.clear_deltas(repo_id)?;
        Ok(new_gen)
    }

    /// Remove all delta files for a repo. Called after compaction.
    fn clear_deltas(&self, repo_id: &str) -> Result<(), KinDbError>;

    /// Save ephemeral overlay state (for preemption recovery).
    fn save_overlay(
        &self,
        repo_id: &str,
        session_id: &str,
        data: &[u8],
    ) -> Result<(), KinDbError>;

    /// Load overlay state (after preemption recovery).
    ///
    /// Returns `Ok(None)` if no overlay exists for this session.
    fn load_overlay(
        &self,
        repo_id: &str,
        session_id: &str,
    ) -> Result<Option<Vec<u8>>, KinDbError>;

    /// Delete an overlay after it has been committed or is no longer needed.
    ///
    /// Returns `Ok(())` if the overlay was deleted or did not exist.
    /// This prevents overlay accumulation on remote backends like GCS.
    fn delete_overlay(
        &self,
        repo_id: &str,
        session_id: &str,
    ) -> Result<(), KinDbError>;

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
/// {base_path}/{repo_id}/graph.kndb          — snapshot
/// {base_path}/{repo_id}/graph.kndb.gen      — generation counter
/// {base_path}/{repo_id}/overlays/{session_id}.bin — overlay state
/// ```
///
/// Write safety uses the same atomic-write strategy as `SnapshotManager`:
/// write to `.tmp`, fsync, rename. The generation file provides CAS semantics
/// equivalent to GCS generation-match.
pub struct LocalFileBackend {
    base_path: PathBuf,
}

impl LocalFileBackend {
    /// Create a new local backend rooted at `base_path`.
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            base_path: base_path.into(),
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
        self.deltas_dir(repo_id)
            .join(format!("{gen:020}.kndd"))
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

    fn read_generation(&self, repo_id: &str) -> Result<Generation, KinDbError> {
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
            KinDbError::StorageError(format!(
                "invalid generation in {}: {e}",
                gen_path.display()
            ))
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
        })
    }
}

impl StorageBackend for LocalFileBackend {
    fn load_snapshot(&self, repo_id: &str) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
        let path = self.snapshot_path(repo_id);
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read(&path).map_err(|e| {
            KinDbError::StorageError(format!("failed to read {}: {e}", path.display()))
        })?;
        let gen = self.read_generation(repo_id)?;
        Ok(Some((data, gen)))
    }

    fn save_snapshot(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let _lock = self.acquire_lock(repo_id)?;
        let current_gen = self.read_generation(repo_id)?;
        if current_gen != expected_gen {
            return Err(KinDbError::StorageError(format!(
                "generation mismatch for repo {repo_id}: expected {expected_gen}, found {current_gen} \
                 (another writer committed since last load)"
            )));
        }

        let path = self.snapshot_path(repo_id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to create directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        // Validate the bytes without re-serializing — from_bytes proves the
        // data round-trips, then we write the *original* bytes to disk.
        let _snapshot = GraphSnapshot::from_bytes(data)?;

        // Atomic write: tmp file → fsync → rename (same crash-safety as
        // mmap::atomic_write but avoids the redundant to_bytes() call).
        let tmp_path = path.with_extension("kndb.tmp");
        {
            let mut file = std::fs::File::create(&tmp_path).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to create tmp file {}: {e}",
                    tmp_path.display()
                ))
            })?;
            file.write_all(data).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to write tmp file {}: {e}",
                    tmp_path.display()
                ))
            })?;
            file.sync_all().map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to fsync tmp file {}: {e}",
                    tmp_path.display()
                ))
            })?;
        }
        std::fs::rename(&tmp_path, &path).map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to rename {} → {}: {e}",
                tmp_path.display(),
                path.display()
            ))
        })?;

        let new_gen = current_gen + 1;
        self.write_generation(repo_id, new_gen)?;
        Ok(new_gen)
    }

    fn save_delta(
        &self,
        repo_id: &str,
        delta_data: &[u8],
        base_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let _lock = self.acquire_lock(repo_id)?;
        let current_gen = self.read_generation(repo_id)?;
        if current_gen != base_gen {
            return Err(KinDbError::StorageError(format!(
                "delta base generation mismatch for repo {repo_id}: expected {base_gen}, found {current_gen}"
            )));
        }

        let deltas_dir = self.deltas_dir(repo_id);
        std::fs::create_dir_all(&deltas_dir).map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to create deltas directory {}: {e}",
                deltas_dir.display()
            ))
        })?;

        let new_gen = current_gen + 1;
        let delta_path = self.delta_path(repo_id, new_gen);

        // Atomic write: tmp → fsync → rename
        let tmp_path = delta_path.with_extension("kndd.tmp");
        {
            let mut file = std::fs::File::create(&tmp_path).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to create tmp delta file {}: {e}",
                    tmp_path.display()
                ))
            })?;
            file.write_all(delta_data).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to write tmp delta file {}: {e}",
                    tmp_path.display()
                ))
            })?;
            file.sync_all().map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to fsync tmp delta file {}: {e}",
                    tmp_path.display()
                ))
            })?;
        }
        std::fs::rename(&tmp_path, &delta_path).map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to rename {} → {}: {e}",
                tmp_path.display(),
                delta_path.display()
            ))
        })?;

        self.write_generation(repo_id, new_gen)?;
        Ok(new_gen)
    }

    fn load_deltas_since(
        &self,
        repo_id: &str,
        since_gen: Generation,
    ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
        let deltas_dir = self.deltas_dir(repo_id);
        if !deltas_dir.exists() {
            return Ok(Vec::new());
        }

        let mut entries: Vec<(Generation, PathBuf)> = Vec::new();
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
            if path.extension().and_then(|e| e.to_str()) != Some("kndd") {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if let Ok(gen) = stem.parse::<Generation>() {
                if gen > since_gen {
                    entries.push((gen, path));
                }
            }
        }

        // Sort by generation (oldest first)
        entries.sort_by_key(|(gen, _)| *gen);

        let mut result = Vec::with_capacity(entries.len());
        for (gen, path) in entries {
            let data = std::fs::read(&path).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to read delta {}: {e}",
                    path.display()
                ))
            })?;
            result.push((data, gen));
        }

        Ok(result)
    }

    fn clear_deltas(&self, repo_id: &str) -> Result<(), KinDbError> {
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

    fn save_overlay(
        &self,
        repo_id: &str,
        session_id: &str,
        data: &[u8],
    ) -> Result<(), KinDbError> {
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
            KinDbError::StorageError(format!(
                "failed to write overlay {}: {e}",
                path.display()
            ))
        })
    }

    fn load_overlay(
        &self,
        repo_id: &str,
        session_id: &str,
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        let path = self.overlay_path(repo_id, session_id);
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read(&path).map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to read overlay {}: {e}",
                path.display()
            ))
        })?;
        Ok(Some(data))
    }

    fn delete_overlay(
        &self,
        repo_id: &str,
        session_id: &str,
    ) -> Result<(), KinDbError> {
        let path = self.overlay_path(repo_id, session_id);
        if !path.exists() {
            return Ok(());
        }
        std::fs::remove_file(&path).map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to delete overlay {}: {e}",
                path.display()
            ))
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
                if snapshot.exists() {
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
        let delta = crate::storage::delta::GraphSnapshotDelta {
            base_generation: gen1,
            entities: Default::default(),
            relations: Default::default(),
            outgoing: Default::default(),
            incoming: Default::default(),
            changes: Default::default(),
            change_children: Default::default(),
            branches: Default::default(),
            work_items: Default::default(),
            annotations: Default::default(),
            work_links: Default::default(),
            test_cases: Default::default(),
            assertions: Default::default(),
            verification_runs: Default::default(),
            test_covers_entity: Default::default(),
            test_covers_contract: Default::default(),
            test_verifies_work: Default::default(),
            run_proves_entity: Default::default(),
            run_proves_work: Default::default(),
            mock_hints: Default::default(),
            contracts: Default::default(),
            actors: Default::default(),
            delegations: Default::default(),
            approvals: Default::default(),
            audit_events: Default::default(),
            shallow_files: Default::default(),
            file_hashes: crate::storage::delta::CollectionDelta {
                added: vec![("new.rs".to_string(), [42; 32])],
                modified: vec![],
                removed: vec![],
            },
            sessions: Default::default(),
            intents: Default::default(),
            downstream_warnings: Default::default(),
        };
        let delta_bytes = delta.to_bytes().unwrap();
        let gen2 = backend
            .save_delta("test-repo", &delta_bytes, gen1)
            .unwrap();
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
        let gen2 = backend
            .save_delta("test-repo", &delta_bytes, gen1)
            .unwrap();
        backend
            .save_delta("test-repo", &delta_bytes, gen2)
            .unwrap();

        // Should have 2 deltas
        let deltas = backend.load_deltas_since("test-repo", gen1).unwrap();
        assert_eq!(deltas.len(), 2);

        // Clear them
        backend.clear_deltas("test-repo").unwrap();
        let empty = backend.load_deltas_since("test-repo", gen1).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn local_backend_compact_deltas() {
        let dir = TempDir::new().unwrap();
        let backend = LocalFileBackend::new(dir.path());

        // Create initial snapshot with one file hash
        let mut snapshot = GraphSnapshot::empty();
        snapshot
            .file_hashes
            .insert("old.rs".to_string(), [1; 32]);
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
        let gen2 = backend
            .save_delta("test-repo", &delta_bytes, gen1)
            .unwrap();

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
        let gen = backend.read_generation("test-repo").unwrap();
        assert_eq!(gen, 42);

        // No .tmp file left behind
        let tmp_path = backend.generation_path("test-repo").with_extension("tmp");
        assert!(!tmp_path.exists(), "tmp file should not remain after atomic write");

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
