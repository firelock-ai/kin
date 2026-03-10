use thiserror::Error;

/// Errors from the migration pipeline.
#[derive(Debug, Error)]
pub enum MigrateError {
    #[error("io error: {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("source repository not found: {0}")]
    SourceNotFound(String),

    #[error("not a git repository: {0}")]
    NotAGitRepo(String),

    #[error("target already initialized: {0}")]
    AlreadyInitialized(String),

    #[error("git import failed: {0}")]
    GitImport(String),

    #[error("kin init failed: {0}")]
    Init(String),

    #[error("index error: {0}")]
    Index(String),

    #[error("graph error: {0}")]
    Graph(String),

    #[error("blob error: {0}")]
    Blob(String),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

impl MigrateError {
    pub fn io(path: impl AsRef<std::path::Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, MigrateError>;
