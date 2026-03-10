use thiserror::Error;

/// Errors from the graph store layer.
#[derive(Error, Debug)]
pub enum GraphError {
    #[error("KuzuDB error: {0}")]
    Kuzu(String),

    #[error("Entity not found: {0}")]
    EntityNotFound(String),

    #[error("Branch not found: {0}")]
    BranchNotFound(String),

    #[error("Change not found: {0}")]
    ChangeNotFound(String),

    #[error("Schema initialization failed: {0}")]
    SchemaInit(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),
}

impl From<kuzu::Error> for GraphError {
    fn from(e: kuzu::Error) -> Self {
        GraphError::Kuzu(e.to_string())
    }
}

impl From<serde_json::Error> for GraphError {
    fn from(e: serde_json::Error) -> Self {
        GraphError::Serialization(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, GraphError>;
