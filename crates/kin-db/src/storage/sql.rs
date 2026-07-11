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

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::{Path, PathBuf};

use parking_lot::Mutex;

use crate::error::KinDbError;
use crate::storage::backend::{
    checked_next_generation, Generation, SnapshotAuthority, SnapshotRecoveryState, StorageBackend,
    GENERATION_INIT,
};

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
    #[cfg(test)]
    clear_deltas_after_authority_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
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
            #[cfg(test)]
            clear_deltas_after_authority_hook: Mutex::new(None),
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
            #[cfg(test)]
            clear_deltas_after_authority_hook: Mutex::new(None),
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
                 generation INTEGER NOT NULL DEFAULT 0,
                 snapshot_generation INTEGER
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

        let has_snapshot_generation = {
            let mut statement = conn
                .prepare("PRAGMA table_info(snapshots)")
                .map_err(|error| {
                    KinDbError::StorageError(format!(
                        "failed to inspect SQLite snapshots schema: {error}"
                    ))
                })?;
            let columns = statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|error| {
                    KinDbError::StorageError(format!(
                        "failed to read SQLite snapshots schema: {error}"
                    ))
                })?;
            let mut found = false;
            for column in columns {
                if column.map_err(|error| {
                    KinDbError::StorageError(format!(
                        "failed to decode SQLite snapshots schema: {error}"
                    ))
                })? == "snapshot_generation"
                {
                    found = true;
                }
            }
            found
        };
        if !has_snapshot_generation {
            conn.execute(
                "ALTER TABLE snapshots ADD COLUMN snapshot_generation INTEGER",
                [],
            )
            .map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to add SQLite snapshot-generation authority: {error}"
                ))
            })?;
        }

        // A legacy row is safely self-contained only when it has no journal.
        // Rows with legacy deltas keep NULL and fail closed on recovery because
        // their snapshot base cannot be proven from the old schema.
        conn.execute(
            "UPDATE snapshots AS snapshots_row
             SET snapshot_generation = generation
             WHERE snapshot_generation IS NULL
               AND NOT EXISTS (
                   SELECT 1 FROM deltas WHERE deltas.repo_id = snapshots_row.repo_id
               )",
            [],
        )
        .map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to migrate safe SQLite snapshot authorities: {error}"
            ))
        })?;

        Ok(())
    }

    fn decode_generation(value: i64, label: &str) -> Result<Generation, KinDbError> {
        Generation::try_from(value).map_err(|_| {
            KinDbError::StorageError(format!(
                "SQLite {label} contains negative generation {value}"
            ))
        })
    }

    fn encode_generation(value: Generation, label: &str) -> Result<i64, KinDbError> {
        i64::try_from(value).map_err(|_| {
            KinDbError::StorageError(format!(
                "SQLite {label} generation {value} exceeds i64::MAX"
            ))
        })
    }

    fn load_authority_from_connection(
        conn: &Connection,
        repo_id: &str,
    ) -> Result<Option<SnapshotAuthority>, KinDbError> {
        let row = conn
            .query_row(
                "SELECT data, snapshot_generation, generation FROM snapshots WHERE repo_id = ?1",
                params![repo_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| {
                KinDbError::StorageError(format!(
                    "SQLite load snapshot authority failed for repo {repo_id}: {error}"
                ))
            })?;
        let Some((snapshot_bytes, snapshot_generation, head_generation)) = row else {
            return Ok(None);
        };
        let snapshot_generation = snapshot_generation.ok_or_else(|| {
            KinDbError::StorageError(format!(
                "SQLite repo {repo_id} has legacy deltas but no provable snapshot-base generation"
            ))
        })?;
        let snapshot_generation =
            Self::decode_generation(snapshot_generation, "snapshot authority")?;
        let head_generation = Self::decode_generation(head_generation, "head authority")?;
        if snapshot_generation > head_generation {
            return Err(KinDbError::StorageError(format!(
                "SQLite repo {repo_id} snapshot generation {snapshot_generation} exceeds head {head_generation}"
            )));
        }
        Ok(Some(SnapshotAuthority {
            snapshot_bytes,
            snapshot_generation,
            head_generation,
        }))
    }

    fn load_deltas_from_connection(
        conn: &Connection,
        repo_id: &str,
        since_gen: Generation,
    ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
        let since_sql_generation = Self::encode_generation(since_gen, "delta cutoff")?;
        let mut statement = conn
            .prepare(
                "SELECT data, generation FROM deltas
                 WHERE repo_id = ?1 AND (generation < 0 OR generation > ?2)
                 ORDER BY generation ASC",
            )
            .map_err(|error| {
                KinDbError::StorageError(format!(
                    "SQLite prepare load_deltas_since failed: {error}"
                ))
            })?;
        let rows = statement
            .query_map(params![repo_id, since_sql_generation], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|error| {
                KinDbError::StorageError(format!(
                    "SQLite load_deltas_since query failed for repo {repo_id}: {error}"
                ))
            })?;
        let mut result = Vec::new();
        for row in rows {
            let (data, generation) = row.map_err(|error| {
                KinDbError::StorageError(format!("SQLite load_deltas_since row failed: {error}"))
            })?;
            result.push((
                data,
                Self::decode_generation(generation, "delta authority")?,
            ));
        }
        Ok(result)
    }
}

impl StorageBackend for SqliteBackend {
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
        let conn = self.conn.lock();
        Self::load_authority_from_connection(&conn, repo_id)
    }

    fn load_recovery_state(&self, repo_id: &str) -> Result<SnapshotRecoveryState, KinDbError> {
        let conn = self.conn.lock();
        let transaction = conn.unchecked_transaction().map_err(|error| {
            KinDbError::StorageError(format!("SQLite begin recovery transaction failed: {error}"))
        })?;
        let authority = Self::load_authority_from_connection(&transaction, repo_id)?;
        let since = authority
            .as_ref()
            .map_or(GENERATION_INIT, |authority| authority.snapshot_generation);
        let deltas = Self::load_deltas_from_connection(&transaction, repo_id, since)?;
        transaction.commit().map_err(|error| {
            KinDbError::StorageError(format!(
                "SQLite recovery transaction commit failed: {error}"
            ))
        })?;
        Ok((authority, deltas))
    }

    fn save_snapshot(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let _snapshot = crate::storage::format::GraphSnapshot::from_bytes(data)?;
        let expected_sql_generation = Self::encode_generation(expected_gen, "expected snapshot")?;
        let mut conn = self.conn.lock();

        // Use an immediate transaction to hold the write lock for the
        // duration of the read-check-write cycle (CAS).
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| {
                KinDbError::StorageError(format!("SQLite begin transaction failed: {e}"))
            })?;

        let current_gen: Option<(i64, Option<i64>)> = tx
            .query_row(
                "SELECT generation, snapshot_generation FROM snapshots WHERE repo_id = ?1",
                params![repo_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| {
                KinDbError::StorageError(format!(
                    "SQLite read generation failed for repo {repo_id}: {e}"
                ))
            })?;

        let has_current = current_gen.is_some();
        let stored_gen = match current_gen {
            Some((generation, snapshot_generation)) => {
                let generation = Self::decode_generation(generation, "head authority")?;
                let snapshot_generation = snapshot_generation.ok_or_else(|| {
                    KinDbError::StorageError(format!(
                        "SQLite repo {repo_id} has no provable snapshot-base generation"
                    ))
                })?;
                let snapshot_generation =
                    Self::decode_generation(snapshot_generation, "snapshot authority")?;
                if snapshot_generation > generation {
                    return Err(KinDbError::StorageError(format!(
                        "SQLite repo {repo_id} snapshot generation {snapshot_generation} exceeds head {generation}"
                    )));
                }
                generation
            }
            None => GENERATION_INIT,
        };

        if stored_gen != expected_gen {
            return Err(KinDbError::StorageError(format!(
                "generation mismatch for repo {repo_id}: expected {expected_gen}, \
                 found {stored_gen} (another writer committed since last load)"
            )));
        }

        let new_gen = checked_next_generation(stored_gen, "SQLite snapshot")?;
        let new_sql_generation = Self::encode_generation(new_gen, "new snapshot")?;

        if has_current {
            tx.execute(
                "UPDATE snapshots
                 SET data = ?1, generation = ?2, snapshot_generation = ?2
                 WHERE repo_id = ?3 AND generation = ?4",
                params![data, new_sql_generation, repo_id, expected_sql_generation],
            )
        } else {
            tx.execute(
                "INSERT INTO snapshots (repo_id, data, generation, snapshot_generation)
                 VALUES (?1, ?2, ?3, ?3)",
                params![repo_id, data, new_sql_generation],
            )
        }
        .map_err(|e| {
            KinDbError::StorageError(format!(
                "SQLite save_snapshot failed for repo {repo_id}: {e}"
            ))
        })?;

        tx.commit()
            .map_err(|e| KinDbError::StorageError(format!("SQLite commit failed: {e}")))?;

        Ok(new_gen)
    }

    fn rebuild_legacy_journal(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let _snapshot = crate::storage::format::GraphSnapshot::from_bytes(data)?;
        let expected_sql_generation =
            Self::encode_generation(expected_gen, "legacy rebuild expected")?;
        let mut conn = self.conn.lock();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                KinDbError::StorageError(format!(
                    "SQLite begin legacy rebuild transaction failed: {error}"
                ))
            })?;

        let current: Option<(i64, Option<i64>)> = tx
            .query_row(
                "SELECT generation, snapshot_generation FROM snapshots WHERE repo_id = ?1",
                params![repo_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| {
                KinDbError::StorageError(format!(
                    "SQLite read legacy rebuild authority failed for repo {repo_id}: {error}"
                ))
            })?;
        let Some((current_generation, _snapshot_generation)) = current else {
            return Err(KinDbError::StorageError(format!(
                "SQLite repo {repo_id} has no base snapshot to rebuild"
            )));
        };
        let current_generation =
            Self::decode_generation(current_generation, "legacy rebuild head")?;
        if current_generation != expected_gen {
            return Err(KinDbError::StorageError(format!(
                "SQLite legacy rebuild generation mismatch for repo {repo_id}: expected {expected_gen}, found {current_generation}; quiesce old writers and reconcile again"
            )));
        }

        // Capture exact rows inside the same IMMEDIATE transaction that will
        // promote the rebuilt snapshot. SQLite's write lock makes the capture,
        // authority update, and exact-row deletion one serializable commit.
        let captured = Self::load_deltas_from_connection(&tx, repo_id, GENERATION_INIT)?;
        if captured.is_empty() {
            return Err(KinDbError::StorageError(format!(
                "SQLite repo {repo_id} has no legacy journal to rebuild"
            )));
        }
        let journal_head = captured
            .iter()
            .map(|(_, generation)| *generation)
            .max()
            .unwrap_or(expected_gen);
        let new_gen = checked_next_generation(
            expected_gen.max(journal_head),
            "SQLite legacy journal rebuild",
        )?;
        let new_sql_generation = Self::encode_generation(new_gen, "legacy rebuild result")?;
        let rows = tx
            .execute(
                "UPDATE snapshots
                 SET data = ?1, generation = ?2, snapshot_generation = ?2
                 WHERE repo_id = ?3 AND generation = ?4",
                params![data, new_sql_generation, repo_id, expected_sql_generation],
            )
            .map_err(|error| {
                KinDbError::StorageError(format!(
                    "SQLite legacy rebuild authority update failed for repo {repo_id}: {error}"
                ))
            })?;
        if rows != 1 {
            return Err(KinDbError::StorageError(format!(
                "SQLite legacy rebuild CAS lost for repo {repo_id} at generation {expected_gen}"
            )));
        }
        for (delta, generation) in captured {
            let sql_generation = Self::encode_generation(generation, "legacy rebuild delta")?;
            let deleted = tx
                .execute(
                    "DELETE FROM deltas
                     WHERE repo_id = ?1 AND generation = ?2 AND data = ?3",
                    params![repo_id, sql_generation, delta],
                )
                .map_err(|error| {
                    KinDbError::StorageError(format!(
                        "SQLite exact legacy delta cleanup failed for repo {repo_id}: {error}"
                    ))
                })?;
            if deleted != 1 {
                return Err(KinDbError::StorageError(format!(
                    "SQLite legacy journal changed while rebuilding repo {repo_id}; transaction was rolled back"
                )));
            }
        }
        tx.commit().map_err(|error| {
            KinDbError::StorageError(format!(
                "SQLite legacy rebuild commit failed for repo {repo_id}: {error}"
            ))
        })?;
        Ok(new_gen)
    }

    fn save_delta(
        &self,
        repo_id: &str,
        delta_data: &[u8],
        base_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        let delta = crate::storage::delta::GraphSnapshotDelta::from_bytes(delta_data)?;
        if delta.base_generation != base_gen {
            return Err(KinDbError::StorageError(format!(
                "SQLite delta payload declares base {}, expected {base_gen}",
                delta.base_generation
            )));
        }
        let base_sql_generation = Self::encode_generation(base_gen, "delta base")?;
        let mut conn = self.conn.lock();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| {
                KinDbError::StorageError(format!("SQLite begin transaction failed: {e}"))
            })?;

        // Read current generation for CAS
        let current_gen: Option<(i64, Option<i64>)> = tx
            .query_row(
                "SELECT generation, snapshot_generation FROM snapshots WHERE repo_id = ?1",
                params![repo_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| {
                KinDbError::StorageError(format!(
                    "SQLite read generation failed for repo {repo_id}: {e}"
                ))
            })?;

        let Some((current_gen, snapshot_generation)) = current_gen else {
            return Err(KinDbError::StorageError(format!(
                "SQLite repo {repo_id} has no base snapshot for delta persistence"
            )));
        };
        let snapshot_generation = snapshot_generation.ok_or_else(|| {
            KinDbError::StorageError(format!(
                "SQLite repo {repo_id} has no provable snapshot-base generation"
            ))
        })?;
        let snapshot_generation =
            Self::decode_generation(snapshot_generation, "snapshot authority")?;
        let stored_gen = Self::decode_generation(current_gen, "head authority")?;
        if snapshot_generation > stored_gen {
            return Err(KinDbError::StorageError(format!(
                "SQLite repo {repo_id} snapshot generation {snapshot_generation} exceeds head {stored_gen}"
            )));
        }
        if stored_gen != base_gen {
            return Err(KinDbError::StorageError(format!(
                "delta base generation mismatch for repo {repo_id}: expected {base_gen}, \
                 found {stored_gen}"
            )));
        }

        let new_gen = checked_next_generation(stored_gen, "SQLite delta")?;
        let new_sql_generation = Self::encode_generation(new_gen, "new delta")?;

        tx.execute(
            "INSERT INTO deltas (repo_id, generation, data) VALUES (?1, ?2, ?3)",
            params![repo_id, new_sql_generation, delta_data],
        )
        .map_err(|e| {
            KinDbError::StorageError(format!("SQLite save_delta failed for repo {repo_id}: {e}"))
        })?;

        // Update the generation counter in snapshots so subsequent delta saves
        // can CAS against the correct value.
        let rows_updated = tx
            .execute(
                "UPDATE snapshots SET generation = ?1
                 WHERE repo_id = ?2 AND generation = ?3",
                params![new_sql_generation, repo_id, base_sql_generation],
            )
            .map_err(|e| {
                KinDbError::StorageError(format!(
                    "SQLite update generation failed for repo {repo_id}: {e}"
                ))
            })?;
        if rows_updated != 1 {
            return Err(KinDbError::StorageError(format!(
                "SQLite delta CAS lost for repo {repo_id} at generation {base_gen}"
            )));
        }

        tx.commit()
            .map_err(|e| KinDbError::StorageError(format!("SQLite commit failed: {e}")))?;

        Ok(new_gen)
    }

    fn load_deltas_since(
        &self,
        repo_id: &str,
        since_gen: Generation,
    ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
        let conn = self.conn.lock();
        Self::load_deltas_from_connection(&conn, repo_id, since_gen)
    }

    fn clear_deltas(&self, repo_id: &str) -> Result<(), KinDbError> {
        let mut conn = self.conn.lock();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                KinDbError::StorageError(format!(
                    "SQLite begin delta-cleanup transaction failed: {error}"
                ))
            })?;
        if let Some(authority) = Self::load_authority_from_connection(&tx, repo_id)? {
            if authority.snapshot_generation != authority.head_generation {
                return Err(KinDbError::StorageError(format!(
                    "refusing to clear authoritative SQLite deltas for repo {repo_id}: snapshot generation {}, head {}",
                    authority.snapshot_generation, authority.head_generation
                )));
            }
            #[cfg(test)]
            if let Some(hook) = self.clear_deltas_after_authority_hook.lock().take() {
                hook();
            }
            let cutoff =
                Self::encode_generation(authority.snapshot_generation, "delta cleanup cutoff")?;
            tx.execute(
                "DELETE FROM deltas WHERE repo_id = ?1 AND generation <= ?2",
                params![repo_id, cutoff],
            )
            .map_err(|e| {
                KinDbError::StorageError(format!(
                    "SQLite clear_deltas failed for repo {repo_id}: {e}"
                ))
            })?;
        }
        tx.commit().map_err(|error| {
            KinDbError::StorageError(format!(
                "SQLite delta-cleanup commit failed for repo {repo_id}: {error}"
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
    fn sqlite_negative_delta_generation_fails_closed_before_filtering() {
        let backend = test_backend();
        let repo_id = "negative-delta";
        backend
            .conn
            .lock()
            .execute(
                "INSERT INTO deltas (repo_id, generation, data) VALUES (?1, ?2, ?3)",
                params![repo_id, -1_i64, b"corrupt"],
            )
            .unwrap();

        let error = StorageBackend::load_deltas_since(&backend, repo_id, GENERATION_INIT)
            .expect_err("negative persisted delta generation must not be hidden by the query");
        assert!(error
            .to_string()
            .contains("SQLite delta authority contains negative generation -1"));

        let overflow = StorageBackend::load_deltas_since(&backend, repo_id, Generation::MAX)
            .expect_err("overflowing cutoff must fail before lossy SQL conversion");
        assert!(overflow.to_string().contains("exceeds i64::MAX"));
    }

    #[test]
    fn sqlite_delta_load_preserves_cutoff_and_generation_order() {
        let backend = test_backend();
        let repo_id = "ordered-deltas";
        {
            let conn = backend.conn.lock();
            for (generation, data) in [(3_i64, b"three".as_slice()), (1_i64, b"one".as_slice())] {
                conn.execute(
                    "INSERT INTO deltas (repo_id, generation, data) VALUES (?1, ?2, ?3)",
                    params![repo_id, generation, data],
                )
                .unwrap();
            }
        }

        let all = StorageBackend::load_deltas_since(&backend, repo_id, GENERATION_INIT).unwrap();
        assert_eq!(all, vec![(b"one".to_vec(), 1), (b"three".to_vec(), 3)]);

        let after_one = StorageBackend::load_deltas_since(&backend, repo_id, 1).unwrap();
        assert_eq!(after_one, vec![(b"three".to_vec(), 3)]);

        let overflow = StorageBackend::load_deltas_since(&backend, repo_id, Generation::MAX)
            .expect_err("SQLite cutoff above i64::MAX must fail closed");
        assert!(overflow.to_string().contains("exceeds i64::MAX"));
    }

    #[test]
    fn sqlite_negative_snapshot_generations_fail_closed() {
        for (repo_id, snapshot_generation, head_generation, expected) in [
            ("negative-base", -1_i64, 1_i64, "snapshot authority"),
            ("negative-head", 1_i64, -1_i64, "head authority"),
        ] {
            let backend = test_backend();
            let bytes = GraphSnapshot::empty().to_bytes().unwrap();
            backend
                .conn
                .lock()
                .execute(
                    "INSERT INTO snapshots
                     (repo_id, data, generation, snapshot_generation)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![repo_id, bytes, head_generation, snapshot_generation],
                )
                .unwrap();
            let error = backend
                .load_snapshot_authority(repo_id)
                .expect_err("negative snapshot authority must fail closed");
            assert!(error.to_string().contains(expected));
            assert!(error.to_string().contains("negative generation -1"));

            let save_error = backend
                .save_snapshot(
                    repo_id,
                    &GraphSnapshot::empty().to_bytes().unwrap(),
                    Generation::try_from(head_generation).unwrap_or(GENERATION_INIT),
                )
                .expect_err("snapshot save must not overwrite negative authority");
            assert!(save_error.to_string().contains("negative generation -1"));
        }
    }

    #[test]
    fn sqlite_generation_overflow_preserves_snapshot_authority() {
        let backend = test_backend();
        let repo_id = "generation-overflow";
        let bytes = GraphSnapshot::empty().to_bytes().unwrap();
        backend
            .conn
            .lock()
            .execute(
                "INSERT INTO snapshots
                 (repo_id, data, generation, snapshot_generation)
                 VALUES (?1, ?2, ?3, ?3)",
                params![repo_id, bytes, i64::MAX],
            )
            .unwrap();

        let expected = Generation::try_from(i64::MAX).unwrap();
        let replacement = {
            let mut snapshot = GraphSnapshot::empty();
            snapshot
                .file_hashes
                .insert("replacement.rs".to_string(), [8; 32]);
            snapshot.to_bytes().unwrap()
        };
        let error = backend
            .save_snapshot(repo_id, &replacement, expected)
            .expect_err("generation above SQLite range must fail before update");
        assert!(error.to_string().contains("exceeds i64::MAX"));

        let authority = backend.load_snapshot_authority(repo_id).unwrap().unwrap();
        assert_eq!(authority.head_generation, expected);
        assert_eq!(
            GraphSnapshot::from_bytes(&authority.snapshot_bytes)
                .unwrap()
                .file_hashes
                .len(),
            0
        );
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

    #[test]
    fn sqlite_legacy_schema_migrates_only_rows_without_unbound_journals() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("legacy.db");
        let bytes = GraphSnapshot::empty().to_bytes().unwrap();
        {
            let connection = Connection::open(&db_path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE snapshots (
                         repo_id TEXT PRIMARY KEY,
                         data BLOB NOT NULL,
                         generation INTEGER NOT NULL DEFAULT 0
                     );
                     CREATE TABLE deltas (
                         repo_id TEXT NOT NULL,
                         generation INTEGER NOT NULL,
                         data BLOB NOT NULL,
                         PRIMARY KEY (repo_id, generation)
                     );",
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO snapshots (repo_id, data, generation) VALUES (?1, ?2, 7)",
                    params!["clean", &bytes],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO snapshots (repo_id, data, generation) VALUES (?1, ?2, 8)",
                    params!["unbound", &bytes],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO deltas (repo_id, generation, data) VALUES (?1, 8, ?2)",
                    params![
                        "unbound",
                        crate::storage::delta::GraphSnapshotDelta::empty(7)
                            .to_bytes()
                            .unwrap()
                    ],
                )
                .unwrap();
        }

        let backend = SqliteBackend::new(&db_path).unwrap();
        let clean = backend
            .load_snapshot_authority("clean")
            .unwrap()
            .expect("journal-free legacy row migrates");
        assert_eq!(clean.snapshot_generation, 7);
        assert_eq!(clean.head_generation, 7);

        let error = backend
            .load_snapshot_authority("unbound")
            .expect_err("legacy journal row must retain unknown base and fail closed");
        assert!(error.to_string().contains("no provable snapshot-base"));

        let stale_error = backend
            .rebuild_legacy_journal("unbound", &bytes, 7)
            .expect_err("stale quiesce cursor must fail before the migration transaction");
        assert!(stale_error.to_string().contains("expected 7, found 8"));
        let mut reconciled = GraphSnapshot::empty();
        reconciled
            .file_hashes
            .insert("reconciled.rs".to_string(), [9; 32]);
        let generation = backend
            .rebuild_legacy_journal("unbound", &reconciled.to_bytes().unwrap(), 8)
            .unwrap();
        assert_eq!(generation, 9);
        assert!(backend.load_deltas_since("unbound", 0).unwrap().is_empty());
        let recovered = crate::storage::backend::load_recovered_snapshot(&backend, "unbound")
            .unwrap()
            .unwrap();
        assert_eq!(recovered.generation, generation);
        assert_eq!(recovered.snapshot.file_hashes, reconciled.file_hashes);
    }

    #[test]
    fn sqlite_backend_recovery_replays_deltas_after_connection_reopen() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("restart.db");
        let repo_id = "restart-repo";
        let mut base = GraphSnapshot::empty();
        base.file_hashes.insert("base.rs".to_string(), [1; 32]);

        {
            let backend = SqliteBackend::new(&db_path).unwrap();
            let gen1 = backend
                .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
                .unwrap();

            let mut after_first = base.clone();
            after_first
                .file_hashes
                .insert("first.rs".to_string(), [2; 32]);
            let first = crate::storage::delta::compute_graph_delta(&base, &after_first, gen1);
            let gen2 = backend
                .save_delta(repo_id, &first.to_bytes().unwrap(), gen1)
                .unwrap();

            let mut after_second = after_first.clone();
            after_second
                .file_hashes
                .insert("second.rs".to_string(), [3; 32]);
            let second =
                crate::storage::delta::compute_graph_delta(&after_first, &after_second, gen2);
            backend
                .save_delta(repo_id, &second.to_bytes().unwrap(), gen2)
                .unwrap();
        }

        let reopened = SqliteBackend::new(&db_path).unwrap();
        let (base_bytes, base_generation) = reopened.load_snapshot(repo_id).unwrap().unwrap();
        assert_eq!(base_generation, 1, "tuple generation describes base bytes");
        assert_eq!(
            GraphSnapshot::from_bytes(&base_bytes).unwrap().file_hashes,
            base.file_hashes
        );
        let recovered = crate::storage::backend::load_recovered_snapshot(&reopened, repo_id)
            .unwrap()
            .expect("snapshot exists");
        assert_eq!(recovered.generation, 3);
        assert_eq!(recovered.deltas_applied, 2);
        assert_eq!(recovered.snapshot.file_hashes.len(), 3);
        assert!(recovered.snapshot.file_hashes.contains_key("base.rs"));
        assert!(recovered.snapshot.file_hashes.contains_key("first.rs"));
        assert!(recovered.snapshot.file_hashes.contains_key("second.rs"));
    }

    #[test]
    fn sqlite_cutoff_cleanup_cannot_delete_concurrent_writer_delta() {
        use std::sync::{mpsc, Arc};
        use std::time::Duration;

        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("cleanup-race.db");
        let repo_id = "cleanup-race";
        let cleaner = Arc::new(SqliteBackend::new(&db_path).unwrap());
        let writer = Arc::new(SqliteBackend::new(&db_path).unwrap());
        let base = GraphSnapshot::empty();
        let gen1 = cleaner
            .save_snapshot(repo_id, &base.to_bytes().unwrap(), GENERATION_INIT)
            .unwrap();
        let mut promoted = base.clone();
        promoted
            .file_hashes
            .insert("promoted.rs".to_string(), [4; 32]);
        let first = crate::storage::delta::compute_graph_delta(&base, &promoted, gen1);
        let gen2 = cleaner
            .save_delta(repo_id, &first.to_bytes().unwrap(), gen1)
            .unwrap();
        let gen3 = cleaner
            .save_snapshot(repo_id, &promoted.to_bytes().unwrap(), gen2)
            .unwrap();

        let (checked_tx, checked_rx) = mpsc::channel();
        let (continue_tx, continue_rx) = mpsc::channel();
        *cleaner.clear_deltas_after_authority_hook.lock() = Some(Box::new(move || {
            checked_tx.send(()).unwrap();
            continue_rx.recv().unwrap();
        }));

        let cleaner_thread = {
            let cleaner = Arc::clone(&cleaner);
            std::thread::spawn(move || cleaner.clear_deltas(repo_id))
        };
        checked_rx.recv().unwrap();

        let mut with_concurrent = promoted.clone();
        with_concurrent
            .file_hashes
            .insert("concurrent.rs".to_string(), [5; 32]);
        let concurrent =
            crate::storage::delta::compute_graph_delta(&promoted, &with_concurrent, gen3);
        let (writer_started_tx, writer_started_rx) = mpsc::channel();
        let (writer_done_tx, writer_done_rx) = mpsc::channel();
        let writer_thread = {
            let writer = Arc::clone(&writer);
            let bytes = concurrent.to_bytes().unwrap();
            std::thread::spawn(move || {
                writer_started_tx.send(()).unwrap();
                let result = writer.save_delta(repo_id, &bytes, gen3);
                writer_done_tx.send(()).unwrap();
                result
            })
        };
        writer_started_rx.recv().unwrap();
        assert!(
            writer_done_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err(),
            "concurrent writer must wait behind the cleanup transaction"
        );

        continue_tx.send(()).unwrap();
        cleaner_thread.join().unwrap().unwrap();
        let gen4 = writer_thread.join().unwrap().unwrap();
        assert_eq!(gen4, gen3 + 1);

        let recovered = crate::storage::backend::load_recovered_snapshot(writer.as_ref(), repo_id)
            .unwrap()
            .unwrap();
        assert_eq!(recovered.generation, gen4);
        assert!(recovered.snapshot.file_hashes.contains_key("concurrent.rs"));
    }
}
