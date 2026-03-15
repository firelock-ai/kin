use thiserror::Error;

#[derive(Error, Debug)]
pub enum DaemonError {
    #[error("Graph error: {0}")]
    Graph(String),

    #[error("Blob error: {0}")]
    Blob(String),

    #[error("Index error: {0}")]
    Index(String),

    #[error("Reconcile error: {0}")]
    Reconcile(String),

    #[error("Core error: {0}")]
    Core(String),

    #[error("Not initialized: no .kin/ directory found")]
    NotInitialized,

    #[error("Already running")]
    AlreadyRunning,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<kin_db::KinDbError> for DaemonError {
    fn from(e: kin_db::KinDbError) -> Self {
        Self::Graph(e.to_string())
    }
}

impl From<kin_blobs::BlobError> for DaemonError {
    fn from(e: kin_blobs::BlobError) -> Self {
        Self::Blob(e.to_string())
    }
}

impl From<kin_index::IndexError> for DaemonError {
    fn from(e: kin_index::IndexError) -> Self {
        Self::Index(e.to_string())
    }
}

impl From<kin_reconcile::ReconcileError> for DaemonError {
    fn from(e: kin_reconcile::ReconcileError) -> Self {
        Self::Reconcile(e.to_string())
    }
}

impl From<kin_core::KinError> for DaemonError {
    fn from(e: kin_core::KinError) -> Self {
        Self::Core(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, DaemonError>;
