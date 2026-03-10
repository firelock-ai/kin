use thiserror::Error;

/// Errors from the MCP server.
#[derive(Debug, Error)]
pub enum McpError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("graph store error: {0}")]
    GraphStore(String),

    #[error("context error: {0}")]
    Context(String),

    #[error("review error: {0}")]
    Review(String),

    #[error("tool not found: {0}")]
    ToolNotFound(String),

    #[error("invalid parameters: {0}")]
    InvalidParams(String),

    #[error("session error: {0}")]
    Session(String),

    #[error("{0}")]
    Other(String),
}

impl McpError {
    pub fn graph<E: std::error::Error>(err: E) -> Self {
        McpError::GraphStore(err.to_string())
    }

    /// Convert to a JSON-RPC error code.
    pub fn error_code(&self) -> i64 {
        match self {
            McpError::ToolNotFound(_) => -32601, // Method not found
            McpError::InvalidParams(_) => -32602, // Invalid params
            McpError::Json(_) => -32700,          // Parse error
            _ => -32603,                          // Internal error
        }
    }
}

pub type Result<T> = std::result::Result<T, McpError>;
