use memmap2::Mmap;
use std::fs::File;
use std::path::Path;

use crate::error::KinDbError;
use crate::storage::format::GraphSnapshot;

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
        let file = File::open(path).map_err(|e| {
            KinDbError::StorageError(format!("failed to open {}: {e}", path.display()))
        })?;

        let mmap = unsafe {
            Mmap::map(&file).map_err(|e| {
                KinDbError::StorageError(format!("failed to mmap {}: {e}", path.display()))
            })?
        };

        GraphSnapshot::from_bytes(&mmap)
    }
}

/// Write a snapshot to a file atomically.
///
/// Writes to a `.tmp` file first, then renames to the target path.
/// This ensures the target file is always in a consistent state.
pub fn atomic_write(path: &Path, snapshot: &GraphSnapshot) -> Result<(), KinDbError> {
    let tmp_path = path.with_extension("tmp");

    let bytes = snapshot.to_bytes()?;

    std::fs::write(&tmp_path, &bytes).map_err(|e| {
        KinDbError::StorageError(format!("failed to write {}: {e}", tmp_path.display()))
    })?;

    // fsync the file to ensure data is on disk before rename
    let file = File::open(&tmp_path).map_err(|e| {
        KinDbError::StorageError(format!(
            "failed to reopen for fsync {}: {e}",
            tmp_path.display()
        ))
    })?;
    file.sync_all()
        .map_err(|e| KinDbError::StorageError(format!("fsync failed: {e}")))?;

    std::fs::rename(&tmp_path, path).map_err(|e| {
        KinDbError::StorageError(format!(
            "failed to rename {} → {}: {e}",
            tmp_path.display(),
            path.display()
        ))
    })?;

    // fsync the parent directory so the rename is durable across power loss
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
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
}
