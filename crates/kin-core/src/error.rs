// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use thiserror::Error;

/// Unified error type for `kin-core`.
#[derive(Debug, Error)]
pub enum KinError {
    #[error("IO error: {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("config error: {0}")]
    Config(String),

    #[error("toml parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("toml serialize error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("already initialized: {0}")]
    AlreadyInitialized(String),

    #[error(
        "repository was published at {path}, but durability or final verification is uncertain: \
         {detail}. Do not reinitialize or delete it; reopen and verify the existing repository"
    )]
    RepositoryPublishedButUncertain { path: String, detail: String },

    #[error("repository authority conflict: {0}")]
    RepositoryConflict(String),

    #[error("repository projection conflict: {0}")]
    ProjectionConflict(String),

    /// The working projection will not open until a person acts on the file
    /// the message names.
    ///
    /// Neither a conflict nor an internal failure: the store is intact and the
    /// sentence carries the remedy. A daemon answers it as a refusal in words
    /// rather than as HTTP 500, because sending a reader to the daemon for a
    /// file they can see is how a stale eject journal cost a stranger the whole
    /// write path on 0.5.52 (FIR-2664).
    #[error("{0}")]
    ProjectionBlocked(String),

    #[error("repository authority commit outcome is indeterminate: {0}")]
    RepositoryCommitIndeterminate(String),

    #[error("not a kin repository: {0}")]
    NotARepository(String),

    #[error("model error: {0}")]
    Model(#[from] kin_model::ModelError),

    #[error("graph error: {0}")]
    Graph(String),

    #[error("incompatible .kin/ version: found v{found}, this binary requires v{supported}")]
    IncompatibleVersion { found: u32, supported: u32 },

    /// The conversion was turned away at phase 1 because it forecasts needing
    /// more memory than this process can read as a ceiling.
    ///
    /// Carries no detail on purpose. The numbers, the ceiling and both remedies
    /// have already been written to stderr as their own lines, in the same
    /// register and through the same pipe-safe writer as the killed-conversion
    /// post-mortem, and repeating them inside an `anyhow` cause chain would
    /// print the whole paragraph a second time under a `Caused by:` heading.
    #[error(
        "not enough memory for this conversion; the lines above name the forecast, the ceiling \
         and what to do about it"
    )]
    ConversionBudgetExceeded,

    #[error("{0}")]
    Other(String),
}

impl KinError {
    pub fn io(path: impl AsRef<std::path::Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, KinError>;
