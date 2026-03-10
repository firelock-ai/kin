use thiserror::Error;

/// Errors from the benchmark engine.
#[derive(Debug, Error)]
pub enum BenchError {
    #[error("io error: {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("graph error: {0}")]
    Graph(String),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

impl BenchError {
    pub fn io(path: impl AsRef<std::path::Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, BenchError>;
