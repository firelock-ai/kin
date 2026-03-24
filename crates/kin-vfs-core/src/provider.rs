// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use crate::{DirEntry, VfsResult, VirtualStat};

/// Trait for anything that can serve file content by path.
///
/// This is the standalone-valuable abstraction. Any project can implement
/// this to back a VirtualFileTree — blob stores, HTTP backends, in-memory
/// maps, or Kin's semantic graph.
pub trait ContentProvider: Send + Sync {
    /// Read the full content of a file.
    fn read_file(&self, path: &str) -> VfsResult<Vec<u8>>;

    /// Read a byte range from a file.
    fn read_range(&self, path: &str, offset: u64, len: u64) -> VfsResult<Vec<u8>>;

    /// Get metadata for a path (file or directory).
    fn stat(&self, path: &str) -> VfsResult<VirtualStat>;

    /// List entries in a directory.
    fn read_dir(&self, path: &str) -> VfsResult<Vec<DirEntry>>;

    /// Check if a path exists.
    fn exists(&self, path: &str) -> VfsResult<bool>;

    /// Read a symbolic link target.
    fn read_link(&self, path: &str) -> VfsResult<String> {
        Err(crate::VfsError::NotFound {
            path: path.to_string(),
        })
    }

    /// Return a monotonically increasing version counter.
    /// Used for cache invalidation — when this changes, cached data may be stale.
    fn version(&self) -> u64 {
        0
    }
}
