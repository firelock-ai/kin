// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Pluggable storage backend trait for graph snapshots.
//!
//! `StorageBackend` abstracts where snapshot bytes live — local filesystem
//! for CLI, GCS for cloud deployment. The daemon code calls
//! `backend.load_snapshot()` / `backend.save_snapshot()` without knowing
//! the underlying storage medium.

use std::path::{Path, PathBuf};

use crate::error::KinDbError;
use crate::storage::format::GraphSnapshot;
use crate::storage::mmap;

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
        std::fs::write(&gen_path, gen.to_string()).map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to write generation file {}: {e}",
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

        // Deserialize to validate, then use atomic_write for crash safety.
        // We write the raw bytes through atomic tmp+rename.
        let snapshot = GraphSnapshot::from_bytes(data)?;
        mmap::atomic_write(&path, &snapshot)?;

        let new_gen = current_gen + 1;
        self.write_generation(repo_id, new_gen)?;
        Ok(new_gen)
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
}
