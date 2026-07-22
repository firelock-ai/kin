// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-process advisory locks for registry storage transactions.
//!
//! Tokio locks only coordinate handlers inside one daemon. Registry roots can
//! also be mounted by multiple daemon processes during rollout or recovery, so
//! every read/modify/write authority boundary needs a lock whose identity is
//! the shared storage path itself.

use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

pub(crate) struct StorageLock {
    file: File,
}

impl StorageLock {
    pub(crate) fn shared(path: &Path) -> io::Result<Self> {
        Self::acquire(path, false)
    }

    pub(crate) fn exclusive(path: &Path) -> io::Result<Self> {
        Self::acquire(path, true)
    }

    fn acquire(path: &Path, exclusive: bool) -> io::Result<Self> {
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "registry transaction lock has no parent directory",
            )
        })?;
        crate::atomic_file::ensure_directory_durable(parent)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        if exclusive {
            FileExt::lock_exclusive(&file)?;
        } else {
            FileExt::lock_shared(&file)?;
        }
        Ok(Self { file })
    }
}

impl Drop for StorageLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}
