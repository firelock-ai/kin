// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use memmap2::Mmap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::error::KinDbError;
use crate::storage::format::{GraphSnapshot, LocateGraphSnapshot};

const RECOVERY_MARKER_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryMarker {
    version: u32,
    byte_len: u64,
    sha256: [u8; 32],
}

/// Append a suffix to `path` without disturbing its existing extension.
///
/// `with_extension` *replaces* the extension, so `graph.kndb` and
/// `graph.kidx` would both collapse to `graph.tmp` and cross-contaminate
/// during concurrent saves. Appending keeps the discriminating extension,
/// so `graph.kndb` → `graph.kndb.tmp` and `graph.kidx` → `graph.kidx.tmp`
/// stay provably disjoint. The result is deterministic so crash recovery
/// can reconstruct the same name on reopen.
fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(suffix);
    PathBuf::from(name)
}

pub(crate) fn recovery_tmp_path(path: &Path) -> PathBuf {
    append_suffix(path, ".tmp")
}

pub(crate) fn recovery_marker_path(path: &Path) -> PathBuf {
    append_suffix(path, ".tmp.meta")
}

fn write_bytes_and_fsync(path: &Path, bytes: &[u8]) -> Result<(), KinDbError> {
    let mut file = File::create(path).map_err(|e| {
        KinDbError::StorageError(format!("failed to create {}: {e}", path.display()))
    })?;
    file.write_all(bytes).map_err(|e| {
        KinDbError::StorageError(format!("failed to write {}: {e}", path.display()))
    })?;
    file.sync_all().map_err(|e| {
        KinDbError::StorageError(format!("failed to fsync {}: {e}", path.display()))
    })?;
    Ok(())
}

fn sync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

fn load_recovery_marker(path: &Path) -> Result<RecoveryMarker, KinDbError> {
    let marker_path = recovery_marker_path(path);
    let marker_bytes = std::fs::read(&marker_path).map_err(|e| {
        KinDbError::StorageError(format!(
            "failed to read recovery marker {}: {e}",
            marker_path.display()
        ))
    })?;
    serde_json::from_slice(&marker_bytes).map_err(|e| {
        KinDbError::StorageError(format!(
            "failed to parse recovery marker {}: {e}",
            marker_path.display()
        ))
    })
}

pub(crate) fn write_recovery_candidate(
    path: &Path,
    snapshot: &GraphSnapshot,
) -> Result<(), KinDbError> {
    let bytes = snapshot.to_bytes()?;
    write_recovery_candidate_bytes(path, &bytes)
}

/// Like [`write_recovery_candidate`] but accepts pre-serialized snapshot bytes
/// (produced by [`BorrowedGraphSnapshot::to_bytes`]).
pub(crate) fn write_recovery_candidate_bytes(path: &Path, bytes: &[u8]) -> Result<(), KinDbError> {
    let tmp_path = recovery_tmp_path(path);
    let marker_path = recovery_marker_path(path);
    let marker = RecoveryMarker {
        version: RECOVERY_MARKER_VERSION,
        byte_len: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    };
    let marker_bytes = serde_json::to_vec(&marker).map_err(|e| {
        KinDbError::StorageError(format!(
            "failed to serialize recovery marker {}: {e}",
            marker_path.display()
        ))
    })?;

    write_bytes_and_fsync(&tmp_path, bytes)?;
    write_bytes_and_fsync(&marker_path, &marker_bytes)?;
    sync_parent_dir(path);
    Ok(())
}

pub(crate) fn load_recovery_candidate(path: &Path) -> Result<GraphSnapshot, KinDbError> {
    load_recovery_candidate_with_persisted_root_hash(path).map(|(snapshot, _)| snapshot)
}

pub(crate) fn load_recovery_candidate_with_persisted_root_hash(
    path: &Path,
) -> Result<(GraphSnapshot, Option<[u8; 32]>), KinDbError> {
    let tmp_path = recovery_tmp_path(path);
    let marker_path = recovery_marker_path(path);
    let marker = load_recovery_marker(path).map_err(|err| {
        KinDbError::StorageError(format!(
            "recovery snapshot {} is unproven without a valid marker {}: {err}",
            tmp_path.display(),
            marker_path.display()
        ))
    })?;

    if marker.version != RECOVERY_MARKER_VERSION {
        return Err(KinDbError::StorageError(format!(
            "recovery marker {} uses unsupported version {}",
            marker_path.display(),
            marker.version
        )));
    }

    let bytes = std::fs::read(&tmp_path).map_err(|e| {
        KinDbError::StorageError(format!(
            "failed to read recovery snapshot {}: {e}",
            tmp_path.display()
        ))
    })?;

    if bytes.len() as u64 != marker.byte_len {
        return Err(KinDbError::StorageError(format!(
            "recovery snapshot {} length {} does not match marker {} length {}",
            tmp_path.display(),
            bytes.len(),
            marker_path.display(),
            marker.byte_len
        )));
    }

    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if digest != marker.sha256 {
        return Err(KinDbError::StorageError(format!(
            "recovery snapshot {} checksum does not match marker {}",
            tmp_path.display(),
            marker_path.display()
        )));
    }

    GraphSnapshot::from_bytes_with_persisted_root_hash(&bytes)
}

/// Read the leading 4 bytes of `path` and confirm they equal `expected`.
///
/// Run immediately after promoting a recovery candidate so a tmp file that
/// somehow carried the wrong content (e.g. cross-contamination between the
/// snapshot and read-index tmp files) fails loudly at write time instead of
/// surfacing as a confusing "expected KNDB magic, got KIDX" at the next reopen.
fn verify_destination_magic(path: &Path, expected: &[u8; 4]) -> Result<(), KinDbError> {
    let mut file = File::open(path).map_err(|e| {
        KinDbError::StorageError(format!(
            "failed to reopen {} to verify magic: {e}",
            path.display()
        ))
    })?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).map_err(|e| {
        KinDbError::StorageError(format!(
            "failed to read magic from {}: {e}",
            path.display()
        ))
    })?;
    if &magic != expected {
        return Err(KinDbError::StorageError(format!(
            "promoted {} but magic {:?} does not match expected {:?}",
            path.display(),
            magic,
            expected
        )));
    }
    Ok(())
}

/// Promote the recovery candidate onto the primary path.
///
/// `expected_magic` is the leading 4 bytes the promoted file must carry. The
/// KNDB snapshot path passes `Some(GraphSnapshot::MAGIC)` so cross-contaminated
/// content fails loudly here; callers writing other on-disk formats through
/// this primitive (e.g. the msgpack locate cache) pass `None`.
pub(crate) fn promote_recovery_candidate(path: &Path) -> Result<(), KinDbError> {
    promote_recovery_candidate_with_magic(path, Some(&GraphSnapshot::MAGIC))
}

pub(crate) fn promote_recovery_candidate_with_magic(
    path: &Path,
    expected_magic: Option<&[u8; 4]>,
) -> Result<(), KinDbError> {
    let tmp_path = recovery_tmp_path(path);
    let marker_path = recovery_marker_path(path);

    std::fs::rename(&tmp_path, path).map_err(|e| {
        KinDbError::StorageError(format!(
            "failed to rename {} → {}: {e}",
            tmp_path.display(),
            path.display()
        ))
    })?;
    sync_parent_dir(path);

    if let Some(expected) = expected_magic {
        verify_destination_magic(path, expected)?;
    }

    if marker_path.exists() {
        std::fs::remove_file(&marker_path).map_err(|e| {
            KinDbError::StorageError(format!(
                "failed to remove recovery marker {}: {e}",
                marker_path.display()
            ))
        })?;
        sync_parent_dir(path);
    }

    Ok(())
}

/// Memory-mapped file reader for graph snapshots.
///
/// Maps the file into virtual memory so the OS handles paging.
/// The data is read directly from the mmap without copying.
pub struct MmapReader {
    _mmap: Mmap,
}

impl MmapReader {
    /// Open and mmap a snapshot file, returning the deserialized snapshot.
    ///
    /// The mmap is held open for the lifetime of the returned data,
    /// but since we deserialize into owned types, the caller doesn't
    /// need to keep the reader alive.
    pub fn open(path: &Path) -> Result<GraphSnapshot, KinDbError> {
        Self::open_with_persisted_root_hash(path).map(|(snapshot, _)| snapshot)
    }

    pub fn open_with_persisted_root_hash(
        path: &Path,
    ) -> Result<(GraphSnapshot, Option<[u8; 32]>), KinDbError> {
        let file = {
            let _span = tracing::info_span!("kindb.snapshot.mmap.open_file").entered();
            File::open(path).map_err(|e| {
                KinDbError::StorageError(format!("failed to open {}: {e}", path.display()))
            })?
        };

        let mmap = unsafe {
            let _span = tracing::info_span!("kindb.snapshot.mmap.map_file").entered();
            Mmap::map(&file).map_err(|e| {
                KinDbError::StorageError(format!("failed to mmap {}: {e}", path.display()))
            })?
        };

        let _span = tracing::info_span!("kindb.snapshot.mmap.decode_bytes").entered();
        if trust_primary_snapshot() {
            let _span = tracing::info_span!("kindb.snapshot.trust_primary_snapshot").entered();
            GraphSnapshot::from_bytes_with_persisted_root_hash_unverified(&mmap)
        } else {
            GraphSnapshot::from_bytes_with_persisted_root_hash(&mmap)
        }
    }

    pub fn open_for_locate_with_persisted_root_hash(
        path: &Path,
    ) -> Result<(LocateGraphSnapshot, Option<[u8; 32]>), KinDbError> {
        let file = {
            let _span = tracing::info_span!("kindb.snapshot.mmap.open_file").entered();
            File::open(path).map_err(|e| {
                KinDbError::StorageError(format!("failed to open {}: {e}", path.display()))
            })?
        };

        let mmap = unsafe {
            let _span = tracing::info_span!("kindb.snapshot.mmap.map_file").entered();
            Mmap::map(&file).map_err(|e| {
                KinDbError::StorageError(format!("failed to mmap {}: {e}", path.display()))
            })?
        };

        let _span = tracing::info_span!("kindb.snapshot.mmap.decode_locate_bytes").entered();
        if trust_primary_snapshot() {
            let _span = tracing::info_span!("kindb.snapshot.trust_primary_snapshot").entered();
            LocateGraphSnapshot::from_bytes_with_persisted_root_hash_unverified(&mmap)
        } else {
            LocateGraphSnapshot::from_bytes_with_persisted_root_hash(&mmap)
        }
    }

    pub fn read_persisted_root_hash_unverified(
        path: &Path,
    ) -> Result<Option<[u8; 32]>, KinDbError> {
        let file = File::open(path).map_err(|e| {
            KinDbError::StorageError(format!("failed to open {}: {e}", path.display()))
        })?;
        let mmap = unsafe {
            Mmap::map(&file).map_err(|e| {
                KinDbError::StorageError(format!("failed to mmap {}: {e}", path.display()))
            })?
        };
        GraphSnapshot::persisted_root_hash_from_bytes_unverified(&mmap)
    }
}

fn trust_primary_snapshot() -> bool {
    matches!(
        std::env::var("KINDB_TRUST_PRIMARY_SNAPSHOT"),
        Ok(value)
            if !value.is_empty()
                && value != "0"
                && !value.eq_ignore_ascii_case("false")
                && !value.eq_ignore_ascii_case("no")
    )
}

/// Write a snapshot to a file atomically.
///
/// Writes to a `.tmp` file first, then renames to the target path.
/// This ensures the target file is always in a consistent state.
pub fn atomic_write(path: &Path, snapshot: &GraphSnapshot) -> Result<(), KinDbError> {
    write_recovery_candidate(path, snapshot)?;
    promote_recovery_candidate(path)
}

/// Like [`atomic_write`] but accepts pre-serialized bytes (from
/// [`BorrowedGraphSnapshot::to_bytes`]). Asserts the promoted file carries the
/// KNDB magic.
pub fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> Result<(), KinDbError> {
    write_recovery_candidate_bytes(path, bytes)?;
    promote_recovery_candidate(path)
}

/// Like [`atomic_write_bytes`] but for on-disk formats that do not carry the
/// KNDB magic (e.g. the msgpack locate cache). Skips the post-promote magic
/// assert while keeping the same crash-safe tmp/marker/rename sequence.
pub(crate) fn atomic_write_bytes_no_magic(path: &Path, bytes: &[u8]) -> Result<(), KinDbError> {
    write_recovery_candidate_bytes(path, bytes)?;
    promote_recovery_candidate_with_magic(path, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn atomic_write_and_mmap_read() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();

        let snap = GraphSnapshot::empty();

        atomic_write(&path, &snap).unwrap();
        let loaded = MmapReader::open(&path).unwrap();
        assert_eq!(loaded.version, GraphSnapshot::CURRENT_VERSION);
    }

    #[test]
    fn atomic_write_overwrites_partial_tmp_without_corrupting_target() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        let snap = GraphSnapshot::empty();

        atomic_write(&path, &snap).unwrap();

        let tmp_path = recovery_tmp_path(&path);
        std::fs::write(&tmp_path, b"partial write").unwrap();

        atomic_write(&path, &snap).unwrap();

        let loaded = MmapReader::open(&path).unwrap();
        assert_eq!(loaded.version, GraphSnapshot::CURRENT_VERSION);
        assert!(!tmp_path.exists());
    }

    #[test]
    fn write_recovery_candidate_requires_marker_for_recovery() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        let snap = GraphSnapshot::empty();

        let tmp_path = recovery_tmp_path(&path);
        std::fs::write(&tmp_path, snap.to_bytes().unwrap()).unwrap();

        let err = load_recovery_candidate(&path).unwrap_err();
        assert!(err.to_string().contains("unproven without a valid marker"));
    }

    #[test]
    fn write_recovery_candidate_round_trips_with_matching_marker() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        let snap = GraphSnapshot::empty();

        write_recovery_candidate(&path, &snap).unwrap();
        let loaded = load_recovery_candidate(&path).unwrap();
        assert_eq!(loaded.version, GraphSnapshot::CURRENT_VERSION);

        promote_recovery_candidate(&path).unwrap();
        assert!(path.exists());
        assert!(!recovery_tmp_path(&path).exists());
        assert!(!recovery_marker_path(&path).exists());
    }

    #[test]
    fn load_recovery_candidate_rejects_mismatched_marker() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        let snap = GraphSnapshot::empty();

        write_recovery_candidate(&path, &snap).unwrap();

        let marker_path = recovery_marker_path(&path);
        let mut marker: RecoveryMarker =
            serde_json::from_slice(&std::fs::read(&marker_path).unwrap()).unwrap();
        marker.byte_len += 1;
        std::fs::write(&marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();

        let err = load_recovery_candidate(&path).unwrap_err();
        assert!(err.to_string().contains("does not match marker"));
    }

    #[test]
    fn recovery_tmp_paths_preserve_extension() {
        let snapshot = Path::new("/repo/kindb/graph.kndb");
        assert_eq!(
            recovery_tmp_path(snapshot),
            PathBuf::from("/repo/kindb/graph.kndb.tmp")
        );
        assert_eq!(
            recovery_marker_path(snapshot),
            PathBuf::from("/repo/kindb/graph.kndb.tmp.meta")
        );
    }

    #[test]
    fn snapshot_and_index_tmp_paths_are_disjoint() {
        // Sibling artifacts in the same dir: the snapshot (graph.kndb) and the
        // read-index (graph.kidx). Before the fix both derived `graph.tmp` via
        // `with_extension` and cross-contaminated. Appending the suffix keeps
        // the discriminating extension, so the tmp paths are provably disjoint.
        let dir = Path::new("/repo/kindb");
        let snapshot_tmp = recovery_tmp_path(&dir.join("graph.kndb"));
        let index_tmp = append_suffix(&dir.join("graph.kidx"), ".tmp");

        assert_ne!(snapshot_tmp, index_tmp);
        assert_eq!(snapshot_tmp, PathBuf::from("/repo/kindb/graph.kndb.tmp"));
        assert_eq!(index_tmp, PathBuf::from("/repo/kindb/graph.kidx.tmp"));
    }

    #[test]
    fn promote_rejects_wrong_magic() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();

        // Write a tmp + marker whose body has the wrong magic (KIDX, the
        // read-index magic) so the promoted file would not be a valid KNDB
        // snapshot. The post-rename magic check must fail loudly.
        let bytes = b"KIDX not actually a snapshot".to_vec();
        let tmp_path = recovery_tmp_path(&path);
        let marker_path = recovery_marker_path(&path);
        let marker = RecoveryMarker {
            version: RECOVERY_MARKER_VERSION,
            byte_len: bytes.len() as u64,
            sha256: Sha256::digest(&bytes).into(),
        };
        std::fs::write(&tmp_path, &bytes).unwrap();
        std::fs::write(&marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();

        let err = promote_recovery_candidate(&path).unwrap_err();
        assert!(
            err.to_string().contains("does not match expected"),
            "expected a magic-mismatch error, got: {err}"
        );
    }
}
