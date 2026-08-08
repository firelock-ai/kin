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

    /// Get metadata together with the version that produced it.
    ///
    /// A client that remembers an answer must know which snapshot answered, and
    /// the two facts have to come from the same one. Reading [`Self::version`]
    /// *after* [`Self::stat`] would stamp an answer from the old snapshot with
    /// the new version whenever an install lands between the calls, and a
    /// client would then hold a stale attribute under a current stamp with
    /// nothing left to expire it.
    ///
    /// This default reads the version first, which cannot make that mistake: an
    /// under-stated stamp only costs a client its cache entry. A provider whose
    /// answer and version share a snapshot should override this and return both
    /// from it, which is exact rather than merely safe.
    fn stat_at(&self, path: &VfsPath) -> (u64, VfsResult<VirtualStat>) {
        let version = self.version();
        (version, self.stat(path))
    }

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

    /// Start one dispatcher-scoped lookup provenance capture.
    ///
    /// Providers with a mutable remote endpoint can override this together
    /// with [`Self::finish_lookup_endpoint`] so diagnostics name the endpoint
    /// that answered this request rather than rereading shared current state
    /// after the response. Embedded providers need no capture.
    fn begin_lookup_endpoint(&self) {}

    /// Finish the dispatcher-scoped capture and return the exact endpoint that
    /// answered it, if the provider has one.
    ///
    /// The returned string may be moved from request-local state already
    /// allocated for transport; callers retain lazy log formatting and need
    /// not clone or lock mutable global endpoint state.
    fn finish_lookup_endpoint(&self) -> Option<String> {
        None
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
