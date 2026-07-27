// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use crate::path::VfsPath;
use crate::{DirEntry, VfsResult, VirtualStat};

/// Trait for anything that can serve file content by byte-exact path.
///
/// This is the standalone-valuable abstraction. Any project can implement
/// this to back a VirtualFileTree — blob stores, HTTP backends, in-memory
/// maps, or Kin's semantic graph. Paths are validated [`VfsPath`] values:
/// byte-exact, workspace-relative, with the empty path as the root. `String`
/// is never a path identity here.
pub trait ContentProvider: Send + Sync {
    /// Read the full content of a file.
    fn read_file(&self, path: &VfsPath) -> VfsResult<Vec<u8>>;

    /// Read a byte range from a file.
    fn read_range(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>>;

    /// Get metadata for a path (file or directory).
    fn stat(&self, path: &VfsPath) -> VfsResult<VirtualStat>;

    /// List entries in a directory.
    fn read_dir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>>;

    /// Check if a path exists.
    fn exists(&self, path: &VfsPath) -> VfsResult<bool>;

    /// Read a symbolic link target as its exact stored bytes.
    fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>>;

    /// Return a monotonically increasing version counter.
    /// Used for cache invalidation — when this changes, cached data may be
    /// stale. Once a non-zero authority version has been observed, transient
    /// refresh failure must retain it rather than regressing to zero.
    fn version(&self) -> u64 {
        0
    }
}

/// Async counterpart of [`ContentProvider`] for use in async contexts.
///
/// The VFS daemon server runs on tokio but the original `ContentProvider`
/// trait is synchronous (required by the shim, which has no async runtime).
/// Implementors that talk to async backends (e.g. reqwest async HTTP) should
/// implement this trait to avoid `spawn_blocking` overhead.
pub trait AsyncContentProvider: Send + Sync {
    /// Read the full content of a file.
    fn read_file(
        &self,
        path: &VfsPath,
    ) -> impl std::future::Future<Output = VfsResult<Vec<u8>>> + Send;

    /// Read a byte range from a file.
    fn read_range(
        &self,
        path: &VfsPath,
        offset: u64,
        len: u64,
    ) -> impl std::future::Future<Output = VfsResult<Vec<u8>>> + Send;

    /// Get metadata for a path (file or directory).
    fn stat(
        &self,
        path: &VfsPath,
    ) -> impl std::future::Future<Output = VfsResult<VirtualStat>> + Send;

    /// List entries in a directory.
    fn read_dir(
        &self,
        path: &VfsPath,
    ) -> impl std::future::Future<Output = VfsResult<Vec<DirEntry>>> + Send;

    /// Check if a path exists.
    fn exists(&self, path: &VfsPath) -> impl std::future::Future<Output = VfsResult<bool>> + Send;

    /// Read a symbolic link target as its exact stored bytes.
    fn read_link(
        &self,
        path: &VfsPath,
    ) -> impl std::future::Future<Output = VfsResult<Vec<u8>>> + Send;

    /// Return a monotonically increasing version counter. Once established,
    /// transient refresh failure must retain the last validated value.
    fn version(&self) -> impl std::future::Future<Output = u64> + Send {
        async { 0 }
    }
}
