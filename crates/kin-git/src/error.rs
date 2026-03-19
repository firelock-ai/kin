// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use thiserror::Error;

/// Errors from the kin-git adapter.
#[derive(Debug, Error)]
pub enum GitError {
    #[error("git repository not found at: {0}")]
    RepoNotFound(String),

    #[error("not a git repository: {0}")]
    NotAGitRepo(String),

    #[error("git error: {0}")]
    Git(String),

    #[error("commit not found: {0}")]
    CommitNotFound(String),

    #[error("branch not found: {0}")]
    BranchNotFound(String),

    #[error("no commits in repository")]
    EmptyRepository,

    #[error("io error: {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("blob error: {0}")]
    Blob(#[from] kin_blobs::BlobError),

    #[error("model error: {0}")]
    Model(#[from] kin_model::ModelError),

    #[error("graph error: {0}")]
    Graph(String),

    #[error("{0}")]
    Other(String),
}

impl GitError {
    pub fn io(path: impl AsRef<std::path::Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, GitError>;
