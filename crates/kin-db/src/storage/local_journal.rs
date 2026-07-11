// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Crash-recoverable cleanup primitives for local delta journals.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::KinDbError;
use crate::storage::backend::{Generation, GENERATION_INIT};

const QUARANTINE_PREFIX: &str = ".kin-journal-cleanup-";
const QUARANTINE_HASH_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub(super) struct QuarantinedDelta {
    pub(super) generation: Generation,
    pub(super) sha256: String,
    pub(super) path: PathBuf,
    pub(super) byte_len: u64,
}

pub(super) fn is_quarantine_delta_name(path: &Path) -> bool {
    path.file_name()
        .map(|name| name.to_string_lossy().starts_with(QUARANTINE_PREFIX))
        .unwrap_or(false)
}

pub(super) fn quarantine_delta_path(
    canonical_path: &Path,
    generation: Generation,
    sha256: &str,
) -> PathBuf {
    canonical_path.with_file_name(format!(
        "{QUARANTINE_PREFIX}{generation:020}-{sha256}-{}.kndd",
        uuid::Uuid::new_v4()
    ))
}

pub(super) fn sync_parent_directory(path: &Path) -> Result<(), KinDbError> {
    let Some(parent) = path.parent().map(|parent| {
        if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        }
    }) else {
        return Ok(());
    };
    #[cfg(not(unix))]
    {
        let _ = parent;
        Ok(())
    }
    #[cfg(unix)]
    {
        let directory = std::fs::File::open(parent).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to open journal directory {} for fsync: {error}",
                parent.display()
            ))
        })?;
        directory.sync_all().map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to fsync journal directory {}: {error}",
                parent.display()
            ))
        })
    }
}

fn open_regular_quarantine_nofollow(path: &Path) -> Result<File, KinDbError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to inspect quarantined delta {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(KinDbError::StorageError(format!(
            "quarantined delta {} is not a regular file; recovery is fail-closed",
            path.display()
        )));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to open quarantined delta {} without following links: {error}",
            path.display()
        ))
    })?;
    let opened_metadata = file.metadata().map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to inspect opened quarantined delta {}: {error}",
            path.display()
        ))
    })?;
    if !opened_metadata.is_file() {
        return Err(KinDbError::StorageError(format!(
            "quarantined delta {} changed to a non-regular file; recovery is fail-closed",
            path.display()
        )));
    }
    Ok(file)
}

fn hash_quarantined_delta(path: &Path) -> Result<(u64, String), KinDbError> {
    let mut file = open_regular_quarantine_nofollow(path)?;
    let expected_len = file
        .metadata()
        .map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to inspect quarantined delta {}: {error}",
                path.display()
            ))
        })?
        .len();
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; QUARANTINE_HASH_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to read quarantined delta {}: {error}",
                path.display()
            ))
        })?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(|| {
            KinDbError::StorageError(format!(
                "quarantined delta {} length overflowed during recovery",
                path.display()
            ))
        })?;
        if total > expected_len {
            return Err(KinDbError::StorageError(format!(
                "quarantined delta {} grew while being verified; recovery is fail-closed",
                path.display()
            )));
        }
        hasher.update(&buffer[..read]);
    }
    if total != expected_len {
        return Err(KinDbError::StorageError(format!(
            "quarantined delta {} changed length while being verified: expected {expected_len}, read {total}; recovery is fail-closed",
            path.display()
        )));
    }
    Ok((total, hex::encode(hasher.finalize())))
}

pub(super) fn quarantined_file_matches(
    path: &Path,
    expected_sha256: &str,
    expected_len: u64,
) -> Result<bool, KinDbError> {
    let (actual_len, actual_sha256) = hash_quarantined_delta(path)?;
    Ok(actual_len == expected_len && actual_sha256 == expected_sha256)
}

pub(super) fn load_quarantined_deltas(
    delta_dir: &Path,
) -> Result<Vec<QuarantinedDelta>, KinDbError> {
    match std::fs::symlink_metadata(delta_dir) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(KinDbError::StorageError(format!(
                "journal quarantine directory {} is not a real directory; recovery is fail-closed",
                delta_dir.display()
            )))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(KinDbError::StorageError(format!(
                "failed to inspect journal quarantine directory {}: {error}",
                delta_dir.display()
            )))
        }
    }

    let mut quarantined = Vec::new();
    for entry in std::fs::read_dir(delta_dir).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to read journal directory {}: {error}",
            delta_dir.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to read journal entry in {}: {error}",
                delta_dir.display()
            ))
        })?;
        let path = entry.path();
        let name_os = entry.file_name();
        if !name_os.to_string_lossy().starts_with(QUARANTINE_PREFIX) {
            continue;
        }
        let name = name_os
            .to_str()
            .ok_or_else(|| invalid_quarantine_name(&path))?;
        let file_type = entry.file_type().map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to inspect quarantined delta {}: {error}",
                path.display()
            ))
        })?;
        if !file_type.is_file() {
            return Err(KinDbError::StorageError(format!(
                "quarantined delta {} is not a regular file; recovery is fail-closed",
                path.display()
            )));
        }
        let encoded = name
            .strip_prefix(QUARANTINE_PREFIX)
            .and_then(|name| name.strip_suffix(".kndd"))
            .ok_or_else(|| invalid_quarantine_name(&path))?;
        let mut fields = encoded.splitn(3, '-');
        let generation_field = fields
            .next()
            .ok_or_else(|| invalid_quarantine_name(&path))?;
        let sha256 = fields
            .next()
            .ok_or_else(|| invalid_quarantine_name(&path))?;
        let nonce = fields
            .next()
            .ok_or_else(|| invalid_quarantine_name(&path))?;
        let generation = generation_field
            .parse::<Generation>()
            .map_err(|_| invalid_quarantine_name(&path))?;
        if generation == GENERATION_INIT
            || generation_field != format!("{generation:020}")
            || sha256.len() != 64
            || sha256.to_ascii_lowercase() != sha256
            || hex::decode(sha256).is_err()
            || uuid::Uuid::parse_str(nonce).is_err()
        {
            return Err(invalid_quarantine_name(&path));
        }
        let (byte_len, actual_sha256) = hash_quarantined_delta(&path)?;
        if actual_sha256 != sha256 {
            return Err(KinDbError::StorageError(format!(
                "quarantined delta digest mismatch at {}: filename binds {sha256}, bytes contain {actual_sha256}; recovery is fail-closed",
                path.display()
            )));
        }
        quarantined.push(QuarantinedDelta {
            generation,
            sha256: sha256.to_string(),
            path,
            byte_len,
        });
    }
    quarantined.sort_by(|left, right| {
        left.generation
            .cmp(&right.generation)
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(quarantined)
}

pub(super) fn delete_quarantined_delta_exact(
    quarantined: &QuarantinedDelta,
) -> Result<(), KinDbError> {
    // Move whichever entry currently owns the unpredictable quarantine name to
    // a second unpredictable quarantine name before comparing it. This closes
    // the read/compare/unlink window on the original path: a replacement races
    // either before the rename and is preserved on mismatch, or after it and is
    // left at the original name for fail-closed recovery.
    let stable_path = quarantine_delta_path(
        &quarantined.path,
        quarantined.generation,
        &quarantined.sha256,
    );
    match std::fs::rename(&quarantined.path, &stable_path) {
        Ok(()) => sync_parent_directory(&stable_path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return sync_parent_directory(&quarantined.path)
        }
        Err(error) => {
            return Err(KinDbError::StorageError(format!(
                "failed to stabilize quarantined delta {} before cleanup: {error}",
                quarantined.path.display()
            )));
        }
    }
    if !quarantined_file_matches(&stable_path, &quarantined.sha256, quarantined.byte_len)? {
        return Err(KinDbError::StorageError(format!(
            "quarantined delta {} changed during recovery cleanup and was preserved at {}; recovery is fail-closed",
            quarantined.path.display(), stable_path.display()
        )));
    }
    match std::fs::remove_file(&stable_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return sync_parent_directory(&stable_path)
        }
        Err(error) => {
            return Err(KinDbError::StorageError(format!(
                "failed to remove verified quarantined delta {}: {error}",
                stable_path.display()
            )));
        }
    }
    sync_parent_directory(&stable_path)
}

fn invalid_quarantine_name(path: &Path) -> KinDbError {
    KinDbError::StorageError(format!(
        "local delta quarantine {} has an invalid identity-bearing name; recovery is fail-closed",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_quarantine_path(dir: &Path, bytes: &[u8]) -> PathBuf {
        let canonical = dir.join("00000000000000000001.kndd");
        quarantine_delta_path(&canonical, 1, &hex::encode(Sha256::digest(bytes)))
    }

    #[cfg(unix)]
    fn make_fifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_loader_rejects_symlink_and_fifo_without_following_or_blocking() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let bytes = b"delta";
        let sentinel = dir.path().join("sentinel");
        std::fs::write(&sentinel, bytes).unwrap();
        let symlink_path = valid_quarantine_path(dir.path(), bytes);
        symlink(&sentinel, &symlink_path).unwrap();
        let error =
            load_quarantined_deltas(dir.path()).expect_err("quarantine symlink must fail closed");
        assert!(error.to_string().contains("not a regular file"));
        assert_eq!(std::fs::read(&sentinel).unwrap(), bytes);

        std::fs::remove_file(&symlink_path).unwrap();
        let fifo_path = valid_quarantine_path(dir.path(), b"fifo");
        make_fifo(&fifo_path);
        let error = load_quarantined_deltas(dir.path())
            .expect_err("quarantine FIFO must fail without blocking");
        assert!(error.to_string().contains("not a regular file"));
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_loader_rejects_symlinked_journal_directory() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real-deltas");
        let linked = dir.path().join("linked-deltas");
        std::fs::create_dir(&real).unwrap();
        symlink(&real, &linked).unwrap();

        let error = load_quarantined_deltas(&linked)
            .expect_err("journal quarantine scan must not follow a directory symlink");
        assert!(error.to_string().contains("not a real directory"));
    }

    #[test]
    fn quarantine_loader_streams_files_above_the_removed_legacy_cap() {
        const LEGACY_CAP: u64 = 256 * 1024 * 1024;
        let dir = tempfile::tempdir().unwrap();
        let len = LEGACY_CAP + 1;
        let zeros = [0u8; QUARANTINE_HASH_BUFFER_BYTES];
        let mut remaining = len;
        let mut hasher = Sha256::new();
        while remaining > 0 {
            let chunk = remaining.min(zeros.len() as u64) as usize;
            hasher.update(&zeros[..chunk]);
            remaining -= chunk as u64;
        }
        let canonical = dir.path().join("00000000000000000001.kndd");
        let path = quarantine_delta_path(&canonical, 1, &hex::encode(hasher.finalize()));
        let file = File::create(&path).unwrap();
        file.set_len(len).unwrap();
        let quarantined = load_quarantined_deltas(dir.path()).unwrap();
        assert_eq!(quarantined.len(), 1);
        assert_eq!(quarantined[0].byte_len, len);
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_prefixed_non_utf8_name_fails_closed() {
        use std::os::unix::ffi::OsStringExt;

        let dir = tempfile::tempdir().unwrap();
        let mut name = QUARANTINE_PREFIX.as_bytes().to_vec();
        name.extend_from_slice(&[0xff, b'.', b'k', b'n', b'd', b'd']);
        if File::create(dir.path().join(std::ffi::OsString::from_vec(name))).is_err() {
            // Some macOS filesystems reject non-UTF8 names at creation time;
            // Linux exercises the fail-closed parser branch.
            return;
        }
        let error = load_quarantined_deltas(dir.path())
            .expect_err("non-UTF8 cleanup-prefixed artifact must fail closed");
        assert!(error.to_string().contains("invalid identity-bearing name"));
    }

    #[test]
    fn journal_parent_sync_accepts_bare_relative_path() {
        sync_parent_directory(Path::new("00000000000000000001.kndd")).unwrap();
    }
}
