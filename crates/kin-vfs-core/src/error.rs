// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use thiserror::Error;

pub type VfsResult<T> = Result<T, VfsError>;

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

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("provider error: {0}")]
    Provider(String),
}
