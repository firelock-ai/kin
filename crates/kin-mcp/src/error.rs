// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

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

    /// An entity's recorded source path does not exist at the workspace's
    /// current generation.
    ///
    /// This is graph truth answering completely, not authority failing: the
    /// graph ingests whole history, so it carries entities for files that were
    /// deleted or renamed at some point and are absent from the current
    /// workspace. It is a property of ONE entity, so a surface projecting many
    /// entities skips that candidate; a surface asked for exactly this entity
    /// still reports it. Kept apart from [`McpError::Context`] so callers
    /// classify it by type rather than by matching message text.
    #[error("entity absent at workspace generation: {0}")]
    WorkspaceAbsent(String),

    #[error("review error: {0}")]
    Review(String),

    #[error("tool not found: {0}")]
    ToolNotFound(String),

    #[error("invalid parameters: {0}")]
    InvalidParams(String),

    #[error("session error: {0}")]
    Session(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("{0}")]
    Other(String),
}

/// The prefix every message carries that reports the repository AUTHORITY
/// could not be read.
///
/// Authority failure and caller mistake both arrive as [`McpError::Context`],
/// because the context builder and the authority layer share that variant, and
/// a caller cannot act on the two the same way: one is retryable and the other
/// never will be. The producers all spell the prefix, so it lives here beside
/// the type rather than in each consumer, and
/// [`McpError::is_graph_authority_gap`] is the only reader of it.
pub const GRAPH_AUTHORITY_GAP_PREFIX: &str = "graph authority gap";

impl McpError {
    pub fn graph<E: std::error::Error>(err: E) -> Self {
        McpError::GraphStore(err.to_string())
    }

    /// True when this error reports that repository authority could not be
    /// read, rather than that the caller asked for something absent.
    ///
    /// A hosted route answers the first with a retryable service error and the
    /// second with a request error, so the distinction decides a status code.
    pub fn is_graph_authority_gap(&self) -> bool {
        matches!(
            self,
            McpError::Context(message) if message.starts_with(GRAPH_AUTHORITY_GAP_PREFIX)
        )
    }

    /// Convert to a JSON-RPC error code.
    pub fn error_code(&self) -> i64 {
        match self {
            McpError::ToolNotFound(_) => -32601,  // Method not found
            McpError::InvalidParams(_) => -32602, // Invalid params
            McpError::Json(_) => -32700,          // Parse error
            McpError::Protocol(_) => -32600,      // Invalid request / transport
            _ => -32603,                          // Internal error
        }
    }
}

pub type Result<T> = std::result::Result<T, McpError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The predicate and the prefix are one contract, and the prefix is spelled
    /// by producers in another module. This is the reading half: if the
    /// constant moves, the consumers that classify on it are wrong, and this
    /// goes red first.
    #[test]
    fn an_authority_gap_message_is_classified_as_one() {
        let gap = McpError::Context(format!(
            "{GRAPH_AUTHORITY_GAP_PREFIX}: cannot load immutable source blob abc"
        ));
        assert!(gap.is_graph_authority_gap(), "{gap}");
    }

    /// The control that must stay silent. A caller asking for something the
    /// repository does not carry is not an authority failure, and classifying
    /// it as one turns a permanent request error into a retryable outage.
    #[test]
    fn a_caller_mistake_is_not_an_authority_gap() {
        let absent = McpError::Context("entity 0000 not found in context pack".to_string());
        assert!(!absent.is_graph_authority_gap(), "{absent}");
        let params = McpError::InvalidParams("bad entity_id".to_string());
        assert!(!params.is_graph_authority_gap(), "{params}");
    }
}
