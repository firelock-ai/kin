// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! SQLite storage backend for durable, transactional graph snapshot storage.
//!
//! Uses `rusqlite` for embedded SQL storage. Provides:
//! - ACID transactions for snapshot writes
//! - CAS via generation counter stored in the same row
//! - No external server — single file, works anywhere
//! - Feature-gated: `cargo build --features sql`
//!
//! Schema:
//! ```text
//! snapshots(repo_id TEXT PK, data BLOB, generation INTEGER)
//! overlays(repo_id TEXT, session_id TEXT, data BLOB, PK(repo_id, session_id))
//! ```

use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};

use parking_lot::Mutex;

use crate::error::KinDbError;
use crate::storage::backend::{Generation, StorageBackend, GENERATION_INIT};

/// SQLite-backed storage for graph snapshots and overlays.
///
/// Stores snapshot blobs and generation counters in a single SQLite database
/// file. Compare-and-swap semantics are enforced within a transaction:
/// the write is rejected if the stored generation doesn't match `expected_gen`.
///
/// Thread-safe via `Mutex<Connection>` — SQLite's own locking is file-level,
/// so we serialize access at the Rust level to avoid `SQLITE_BUSY` contention.
pub struct SqliteBackend {
    conn: Mutex<Connection>,
    /// Retained for diagnostics / display; the connection owns the actual file.
    #[allow(dead_code)]
    db_path: PathBuf,
}

impl SqliteBackend {
    /// Create a new SQLite backend, storing the database at `db_path`.
    ///
    /// Creates the file and schema if they don't exist. Enables WAL mode
    /// for better concurrent-read performance.
    pub fn new(db_path: impl Into<PathBuf>) -> Result<Self, KinDbError> {
        let db_path = db_path.into();

        // Ensure parent directory exists.
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    KinDbError::StorageError(format!(
                        "failed to create directory {}: {e}",
                        parent.display()
                    ))
                })?;
            }
        }

        let conn = Connection::open(&db_path).map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to open SQLite database {}: {e}",
                db_path.display()
            ))
        })?;

        Self::init_schema(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            db_path,
        })
    }

    /// Create an in-memory SQLite backend (useful for testing).
    pub fn in_memory() -> Result<Self, KinDbError> {
        let conn = Connection::open_in_memory().map_err(|e| {
            KinDbError::StorageError(format!("failed to open in-memory SQLite: {e}"))
        })?;

        Self::init_schema(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            db_path: PathBuf::from(":memory:"),
        })
    }

    /// Return the database file path.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    fn init_schema(conn: &Connection) -> Result<(), KinDbError> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA busy_timeout = 5000;

             CREATE TABLE IF NOT EXISTS snapshots (
                 repo_id    TEXT    PRIMARY KEY,
                 data       BLOB    NOT NULL,
                 generation INTEGER NOT NULL DEFAULT 0
             );

             CREATE TABLE IF NOT EXISTS overlays (
                 repo_id    TEXT NOT NULL,
                 session_id TEXT NOT NULL,
                 data       BLOB NOT NULL,
                 PRIMARY KEY (repo_id, session_id)
             );

             CREATE TABLE IF NOT EXISTS deltas (
                 repo_id    TEXT    NOT NULL,
                 generation INTEGER NOT NULL,
                 data       BLOB    NOT NULL,
                 PRIMARY KEY (repo_id, generation)
             );",
        )
        .map_err(|e| KinDbError::StorageError(format!("failed to initialize SQL schema: {e}")))?;

        Ok(())
    }
}

impl StorageBackend for SqliteBackend {
    fn load_snapshot(&self, repo_id: &str) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
        let conn = self.conn.lock();

        conn.query_row(
            "SELECT data, generation FROM snapshots WHERE repo_id = ?1",
            params![repo_id],
            |row| {
                let data: Vec<u8> = row.get(0)?;
                let generation: i64 = row.get(1)?;
                Ok((data, generation as Generation))
            },
        )
        .optional()
        .map_err(|e| {
            KinDbError::StorageError(format!(
                "SQLite load_snapshot failed for repo {repo_id}: {e}"
            ))
        })
    }

    fn save_snapshot(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let conn = self.conn.lock();

        // Use an immediate transaction to hold the write lock for the
        // duration of the read-check-write cycle (CAS).
        let tx = conn.unchecked_transaction().map_err(|e| {
            KinDbError::StorageError(format!("SQLite begin transaction failed: {e}"))
        })?;

        let current_gen: Option<i64> = tx
            .query_row(
                "SELECT generation FROM snapshots WHERE repo_id = ?1",
                params![repo_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| {
                KinDbError::StorageError(format!(
                    "SQLite read generation failed for repo {repo_id}: {e}"
                ))
            })?;

        let stored_gen = current_gen.unwrap_or(GENERATION_INIT as i64) as Generation;

        if stored_gen != expected_gen {
            return Err(KinDbError::StorageError(format!(
                "generation mismatch for repo {repo_id}: expected {expected_gen}, \
                 found {stored_gen} (another writer committed since last load)"
            )));
        }

        let new_gen = (stored_gen + 1) as i64;

        if current_gen.is_some() {
            tx.execute(
                "UPDATE snapshots SET data = ?1, generation = ?2 WHERE repo_id = ?3",
                params![data, new_gen, repo_id],
            )
        } else {
            tx.execute(
                "INSERT INTO snapshots (repo_id, data, generation) VALUES (?1, ?2, ?3)",
                params![repo_id, data, new_gen],
            )
        }
        .map_err(|e| {
            KinDbError::StorageError(format!(
                "SQLite save_snapshot failed for repo {repo_id}: {e}"
            ))
        })?;

        tx.commit()
            .map_err(|e| KinDbError::StorageError(format!("SQLite commit failed: {e}")))?;

        Ok(new_gen as Generation)
    }

    fn save_delta(
        &self,
        repo_id: &str,
        delta_data: &[u8],
        base_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let conn = self.conn.lock();
        let tx = conn.unchecked_transaction().map_err(|e| {
            KinDbError::StorageError(format!("SQLite begin transaction failed: {e}"))
        })?;

        // Read current generation for CAS
        let current_gen: Option<i64> = tx
            .query_row(
                "SELECT generation FROM snapshots WHERE repo_id = ?1",
                params![repo_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| {
                KinDbError::StorageError(format!(
                    "SQLite read generation failed for repo {repo_id}: {e}"
                ))
            })?;

        let stored_gen = current_gen.unwrap_or(GENERATION_INIT as i64) as Generation;
        if stored_gen != base_gen {
            return Err(KinDbError::StorageError(format!(
                "delta base generation mismatch for repo {repo_id}: expected {base_gen}, \
                 found {stored_gen}"
            )));
        }

        let new_gen = (stored_gen + 1) as i64;

        tx.execute(
            "INSERT INTO deltas (repo_id, generation, data) VALUES (?1, ?2, ?3)",
            params![repo_id, new_gen, delta_data],
        )
        .map_err(|e| {
            KinDbError::StorageError(format!("SQLite save_delta failed for repo {repo_id}: {e}"))
        })?;

        // Update the generation counter in snapshots so subsequent delta saves
        // can CAS against the correct value.
        if current_gen.is_some() {
            tx.execute(
                "UPDATE snapshots SET generation = ?1 WHERE repo_id = ?2",
                params![new_gen, repo_id],
            )
            .map_err(|e| {
                KinDbError::StorageError(format!(
                    "SQLite update generation failed for repo {repo_id}: {e}"
                ))
            })?;
        }

        tx.commit()
            .map_err(|e| KinDbError::StorageError(format!("SQLite commit failed: {e}")))?;

        Ok(new_gen as Generation)
    }

    fn load_deltas_since(
        &self,
        repo_id: &str,
        since_gen: Generation,
    ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT data, generation FROM deltas \
                 WHERE repo_id = ?1 AND generation > ?2 \
                 ORDER BY generation ASC",
            )
            .map_err(|e| {
                KinDbError::StorageError(format!("SQLite prepare load_deltas_since failed: {e}"))
            })?;

        let rows = stmt
            .query_map(params![repo_id, since_gen as i64], |row| {
                let data: Vec<u8> = row.get(0)?;
                let gen: i64 = row.get(1)?;
                Ok((data, gen as Generation))
            })
            .map_err(|e| {
                KinDbError::StorageError(format!(
                    "SQLite load_deltas_since query failed for repo {repo_id}: {e}"
                ))
            })?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| {
                KinDbError::StorageError(format!("SQLite load_deltas_since row failed: {e}"))
            })?);
        }

        Ok(result)
    }

    fn clear_deltas(&self, repo_id: &str) -> Result<(), KinDbError> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM deltas WHERE repo_id = ?1", params![repo_id])
            .map_err(|e| {
                KinDbError::StorageError(format!(
                    "SQLite clear_deltas failed for repo {repo_id}: {e}"
                ))
            })?;
        Ok(())
    }

    fn save_overlay(&self, repo_id: &str, session_id: &str, data: &[u8]) -> Result<(), KinDbError> {
        let conn = self.conn.lock();

        conn.execute(
            "INSERT INTO overlays (repo_id, session_id, data) VALUES (?1, ?2, ?3)
             ON CONFLICT(repo_id, session_id) DO UPDATE SET data = excluded.data",
            params![repo_id, session_id, data],
        )
        .map_err(|e| {
            KinDbError::StorageError(format!(
                "SQLite save_overlay failed for {repo_id}/{session_id}: {e}"
            ))
        })?;

        Ok(())
    }

    fn load_overlay(&self, repo_id: &str, session_id: &str) -> Result<Option<Vec<u8>>, KinDbError> {
        let conn = self.conn.lock();

        conn.query_row(
            "SELECT data FROM overlays WHERE repo_id = ?1 AND session_id = ?2",
            params![repo_id, session_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| {
            KinDbError::StorageError(format!(
                "SQLite load_overlay failed for {repo_id}/{session_id}: {e}"
            ))
        })
    }

    fn delete_overlay(&self, repo_id: &str, session_id: &str) -> Result<(), KinDbError> {
        let conn = self.conn.lock();

        conn.execute(
            "DELETE FROM overlays WHERE repo_id = ?1 AND session_id = ?2",
            params![repo_id, session_id],
        )
        .map_err(|e| {
            KinDbError::StorageError(format!(
                "SQLite delete_overlay failed for {repo_id}/{session_id}: {e}"
            ))
        })?;

        Ok(())
    }

    fn list_repos(&self) -> Result<Vec<String>, KinDbError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT repo_id FROM snapshots ORDER BY repo_id")
            .map_err(|e| {
                KinDbError::StorageError(format!("SQLite list_repos prepare failed: {e}"))
            })?;

        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| {
                KinDbError::StorageError(format!("SQLite list_repos query failed: {e}"))
            })?;

        let mut repos = Vec::new();
        for row in rows {
            repos.push(row.map_err(|e| {
                KinDbError::StorageError(format!("SQLite list_repos row failed: {e}"))
            })?);
        }

        Ok(repos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::format::GraphSnapshot;

    fn test_backend() -> SqliteBackend {
        SqliteBackend::in_memory().unwrap()
    }

    #[test]
    fn sqlite_backend_roundtrip_snapshot() {
        let backend = test_backend();

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
    fn sqlite_backend_cas_rejects_stale_generation() {
        let backend = test_backend();

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
    fn sqlite_backend_overlay_roundtrip() {
        let backend = test_backend();

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
    fn sqlite_backend_overlay_upsert() {
        let backend = test_backend();

        // Save overlay
        backend
            .save_overlay("test-repo", "session-1", b"version 1")
            .unwrap();

        // Overwrite with new data
        backend
            .save_overlay("test-repo", "session-1", b"version 2")
            .unwrap();

        // Should load the latest version
        let loaded = backend
            .load_overlay("test-repo", "session-1")
            .unwrap()
            .unwrap();
        assert_eq!(loaded, b"version 2");
    }

    #[test]
    fn sqlite_backend_delete_overlay() {
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

    #[test]
    fn sqlite_backend_multiple_repos_isolated() {
        let backend = test_backend();

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
    fn sqlite_backend_file_persists() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");

        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes().unwrap();

        // Write with one backend instance
        {
            let backend = SqliteBackend::new(&db_path).unwrap();
            backend
                .save_snapshot("test-repo", &bytes, GENERATION_INIT)
                .unwrap();
        }

        // Read with a new instance — data should persist
        {
            let backend = SqliteBackend::new(&db_path).unwrap();
            let (loaded_bytes, gen) = backend.load_snapshot("test-repo").unwrap().unwrap();
            assert_eq!(gen, 1);
            let loaded = GraphSnapshot::from_bytes(&loaded_bytes).unwrap();
            assert_eq!(loaded.version, GraphSnapshot::CURRENT_VERSION);
        }
    }
}
