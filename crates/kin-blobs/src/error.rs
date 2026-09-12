// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::PathBuf;

/// Errors that can occur in the blob store.
#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("blob not found: {hash}")]
    NotFound { hash: String },

    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
}

impl BlobError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
