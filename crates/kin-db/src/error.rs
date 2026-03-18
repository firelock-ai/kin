use thiserror::Error;

/// Errors returned by KinDB operations.
#[derive(Debug, Error)]
pub enum KinDbError {
    #[error("entity not found: {0}")]
    NotFound(String),

    #[error("duplicate entity: {0}")]
    DuplicateEntity(String),

    #[error("storage error: {0}")]
    StorageError(String),

    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("index error: {0}")]
    IndexError(String),

    #[error("lock error: {0}")]
    LockError(String),

    #[error("concurrent access error: {0}")]
    ConcurrentAccessError(String),

    #[error("slice conversion error: {0}")]
    SliceConversionError(String),
}

pub type Result<T> = std::result::Result<T, KinDbError>;
