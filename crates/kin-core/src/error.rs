// SPDX-License-Identifier: BUSL-1.1
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

    #[error("not a kin repository: {0}")]
    NotARepository(String),

    #[error("model error: {0}")]
    Model(#[from] kin_model::ModelError),

    #[error("blob error: {0}")]
    Blob(#[from] kin_blobs::BlobError),

    #[error("graph error: {0}")]
    Graph(String),

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
