// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use thiserror::Error;

use kin_model::{GitObjectId, Hash256, RepoPath};

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

    #[error("overlapping splices: {first_start}..{first_end} overlaps with {second_start}..{second_end}")]
    OverlappingSplices {
        first_start: usize,
        first_end: usize,
        second_start: usize,
        second_end: usize,
    },

    #[error("placement ambiguity: entity {0} has multiple valid placements")]
    PlacementAmbiguity(String),

    #[error(
        "entity {entity} names file_origin {file_id}, which is not addressable \
         as a repository path, so the graph cannot answer whether the \
         repository already holds it: {reason}"
    )]
    PlacementOriginUnaddressable {
        entity: String,
        file_id: String,
        reason: String,
    },

    #[error("blob error: {0}")]
    Blob(#[from] kin_blobs::BlobError),

    #[error("graph error: {0}")]
    Graph(String),

    #[error("base content unavailable for file {file_id}: {reason}")]
    BaseContentUnavailable { file_id: String, reason: String },

    #[error("body unavailable for entity {entity_id}: {reason}")]
    BodyUnavailable { entity_id: String, reason: String },

    #[error("file layout {file_id} resolves to non-blob entry {entry_kind}")]
    LayoutEntryUnsupported {
        file_id: String,
        entry_kind: &'static str,
    },

    #[error("repository tree contains conflicting paths {ancestor} and {descendant}")]
    PathConflict {
        ancestor: RepoPath,
        descendant: RepoPath,
    },

    #[error(
        "gitlink {path} at {target} cannot be materialized without submodule repository state"
    )]
    UnsupportedGitlink { path: RepoPath, target: GitObjectId },

    #[error("repository path {path} cannot be represented exactly on {platform}")]
    PathUnsupported {
        path: RepoPath,
        platform: &'static str,
    },

    #[error("symbolic link {path} cannot be represented exactly on {platform}")]
    SymlinkUnsupported {
        path: RepoPath,
        platform: &'static str,
    },

    #[error("invalid symbolic-link target stored for {path}: {reason}")]
    InvalidSymlinkTarget { path: RepoPath, reason: String },

    #[error("graph tree references unavailable blob {hash} for {path}: {reason}")]
    TreeBlobUnavailable {
        path: RepoPath,
        hash: Hash256,
        reason: String,
    },

    #[error("projection root is not a directory: {0}")]
    RootNotDirectory(String),

    #[error("initial projection root is not empty: {0}")]
    RootNotEmpty(String),

    #[error("working-copy object at {path} differs from graph-owned source: {reason}")]
    LocalModification { path: RepoPath, reason: String },

    #[error("untracked working-copy object blocks projection at {path}: {reason}")]
    UntrackedCollision { path: RepoPath, reason: String },

    #[error("projection transaction failed: {cause}; rollback: {rollback}")]
    TransactionFailed { cause: String, rollback: String },

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
