use thiserror::Error;

/// Errors from the runtime engine.
#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("io error: {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("workspace not found: {0}")]
    WorkspaceNotFound(String),

    #[error("run not found: {0}")]
    RunNotFound(String),

    #[error("run failed: {0}")]
    RunFailed(String),

    #[error("command execution failed: {0}")]
    CommandFailed(String),

    #[error("graph error: {0}")]
    Graph(String),

    #[error("blob error: {0}")]
    Blob(String),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

impl RuntimeError {
    pub fn io(path: impl AsRef<std::path::Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, RuntimeError>;
