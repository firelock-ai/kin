// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exclusive per-repository runtime authority shared by daemon and maintenance
//! processes.
//!
//! This module owns the OS capability and deliberately treats the owner stamp
//! as opaque. Process-incarnation evidence remains with the caller that mints
//! the existing wire format.

use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long a contended process retries before reporting the holder.
pub const REPOSITORY_RUNTIME_AUTHORITY_RETRY_BUDGET: Duration = Duration::from_secs(5);

const REPOSITORY_RUNTIME_AUTHORITY_RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// Exclusive authority to open one repository as a live runtime.
///
/// The capability is an advisory lock on the never-unlinked
/// `.kin/daemon.lock` inode. It is bound to the canonical `.kin` root so a
/// caller cannot acquire for repository A and replay it while opening B.
#[derive(Debug)]
pub struct RepositoryRuntimeAuthority {
    file: File,
    canonical_kin_root: PathBuf,
}

impl RepositoryRuntimeAuthority {
    /// Canonical `.kin` root protected by this capability.
    pub fn canonical_kin_root(&self) -> &Path {
        &self.canonical_kin_root
    }
}

impl Drop for RepositoryRuntimeAuthority {
    /// Clear the owner stamp while the singleton is still held, then let the
    /// file handle close and release the advisory lock.
    fn drop(&mut self) {
        let _ = self.file.set_len(0);
        let _ = self.file.flush();
    }
}

/// Acquire repository runtime authority with the standard bounded retry.
pub fn acquire_repository_runtime_authority(
    kin_root: &Path,
    owner_stamp: &str,
) -> std::io::Result<Option<RepositoryRuntimeAuthority>> {
    acquire_repository_runtime_authority_within(
        kin_root,
        REPOSITORY_RUNTIME_AUTHORITY_RETRY_BUDGET,
        owner_stamp,
    )
}

/// Acquire repository runtime authority within one caller-owned budget.
///
/// `owner_stamp` is written byte-for-byte only after the singleton lock is
/// held. The caller owns its schema and process-identity semantics.
pub fn acquire_repository_runtime_authority_within(
    kin_root: &Path,
    budget: Duration,
    owner_stamp: &str,
) -> std::io::Result<Option<RepositoryRuntimeAuthority>> {
    if owner_stamp.is_empty() || owner_stamp.contains(['\n', '\r']) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "repository runtime owner stamp must be one non-empty line",
        ));
    }
    without_blocking_runtime_worker(|| {
        let deadline = Instant::now() + budget;
        loop {
            match try_acquire_repository_runtime_authority(kin_root, deadline, owner_stamp) {
                Ok(Some(authority)) => return Ok(Some(authority)),
                Ok(None) => {}
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() >= deadline =>
                {
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            std::thread::sleep(
                REPOSITORY_RUNTIME_AUTHORITY_RETRY_INTERVAL
                    .min(deadline.saturating_duration_since(now)),
            );
        }
    })
}

fn try_acquire_repository_runtime_authority(
    kin_root: &Path,
    deadline: Instant,
    owner_stamp: &str,
) -> std::io::Result<Option<RepositoryRuntimeAuthority>> {
    let canonical_kin_root = kin_root.canonicalize()?;
    let _coordination = acquire_lifecycle_coordination(&canonical_kin_root, deadline)?;
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(canonical_kin_root.join("daemon.lock"))?;
    match file.try_lock_exclusive() {
        Ok(()) => {
            stamp_owner(&mut file, owner_stamp);
            Ok(Some(RepositoryRuntimeAuthority {
                file,
                canonical_kin_root,
            }))
        }
        Err(error) if error.kind() == fs2::lock_contended_error().kind() => Ok(None),
        Err(error) => Err(error),
    }
}

/// Serialize runtime acquisition with endpoint publication and stale evidence
/// handling through the same never-unlinked coordination inode.
fn acquire_lifecycle_coordination(kin_root: &Path, deadline: Instant) -> std::io::Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(kin_root.join("daemon.lifecycle"))?;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "timed out waiting for daemon lifecycle coordination lock",
                    ));
                }
                std::thread::sleep(
                    REPOSITORY_RUNTIME_AUTHORITY_RETRY_INTERVAL
                        .min(deadline.saturating_duration_since(now)),
                );
            }
            Err(error) => return Err(error),
        }
    }
}

fn stamp_owner(file: &mut File, owner_stamp: &str) {
    if file.set_len(0).is_err() || file.seek(SeekFrom::Start(0)).is_err() {
        return;
    }
    if file.write_all(owner_stamp.as_bytes()).is_err() {
        return;
    }
    let _ = file.flush();
}

/// Keep synchronous lock waits off a multi-thread Tokio worker.
fn without_blocking_runtime_worker<T>(work: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(work)
        }
        _ => work(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_is_canonical_exclusive_and_never_unlinks_its_inode() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join(".kin");
        std::fs::create_dir(&root).unwrap();

        let held = acquire_repository_runtime_authority(&root, "owner-a")
            .unwrap()
            .expect("the first holder acquires");
        assert_eq!(held.canonical_kin_root(), root.canonicalize().unwrap());
        assert!(
            acquire_repository_runtime_authority_within(&root, Duration::ZERO, "owner-b")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            std::fs::read_to_string(root.join("daemon.lock")).unwrap(),
            "owner-a"
        );

        drop(held);
        assert!(root.join("daemon.lock").exists());
        assert_eq!(
            std::fs::read_to_string(root.join("daemon.lock")).unwrap(),
            ""
        );
        assert!(
            acquire_repository_runtime_authority_within(&root, Duration::ZERO, "owner-b")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn owner_stamp_is_opaque_but_must_be_one_nonempty_line() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join(".kin");
        std::fs::create_dir(&root).unwrap();
        for invalid in ["", "owner\nnext", "owner\rnext"] {
            assert_eq!(
                acquire_repository_runtime_authority_within(&root, Duration::ZERO, invalid)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
    }
}
