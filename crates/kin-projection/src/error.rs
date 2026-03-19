// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use thiserror::Error;

/// Errors from the projection engine.
#[derive(Debug, Error)]
pub enum ProjectionError {
    #[error("io error: {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("file layout not found for: {0}")]
    LayoutNotFound(String),

    #[error("entity not found in layout: {entity_id} in {file_id}")]
    EntityNotInLayout { entity_id: String, file_id: String },

    #[error("byte range out of bounds: {range_start}..{range_end} in {file_len} byte file")]
    ByteRangeOutOfBounds {
        range_start: usize,
        range_end: usize,
        file_len: usize,
    },

    #[error("placement ambiguity: entity {0} has multiple valid placements")]
    PlacementAmbiguity(String),

    #[error("blob error: {0}")]
    Blob(#[from] kin_blobs::BlobError),

    #[error("graph error: {0}")]
    Graph(String),

    #[error("{0}")]
    Other(String),
}

impl ProjectionError {
    pub fn io(path: impl AsRef<std::path::Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, ProjectionError>;
