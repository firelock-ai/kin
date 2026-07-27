// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use thiserror::Error;

pub type VfsResult<T> = Result<T, VfsError>;

/// VFS operation errors.
///
/// The `path` fields carry the *display* rendering of the byte-exact path
/// (see [`crate::path::VfsPath`]'s `Display`) — presentation for diagnostics,
/// never an identity or lookup form.
#[derive(Debug, Error)]
pub enum VfsError {
    #[error("not found: {path}")]
    NotFound { path: String },

    #[error("is a directory: {path}")]
    IsDirectory { path: String },

    #[error("not a directory: {path}")]
    NotDirectory { path: String },

    #[error("permission denied: {path}")]
    PermissionDenied { path: String },

    #[error("invalid operation for path: {path}")]
    InvalidInput { path: String },

    /// The path names a nested-repository boundary (a Git submodule pointer)
    /// with no child projection mounted. The entry is carried explicitly in
    /// tree listings, but its contents cannot be served as a blob, symlink, or
    /// ordinary directory — that would fabricate repository state.
    #[error("unsupported repository boundary (gitlink) at: {path}")]
    UnsupportedRepositoryBoundary { path: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("provider error: {0}")]
    Provider(String),
}
