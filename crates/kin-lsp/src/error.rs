// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use thiserror::Error;

pub type Result<T> = std::result::Result<T, LspError>;

#[derive(Debug, Error)]
pub enum LspError {
    #[error("server not found: {0}")]
    ServerNotFound(String),

    #[error("server failed to start: {0}")]
    ServerStartFailed(String),

    #[error("server initialization failed: {0}")]
    InitializeFailed(String),

    #[error("JSON-RPC error: {0}")]
    JsonRpc(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("timeout waiting for response")]
    Timeout,

    #[error("server shutdown unexpectedly")]
    ServerDied,

    /// A start or handshake failure, carrying whatever the server wrote to its
    /// own stderr before it went.
    ///
    /// The reason is the original failure's message; the tail is bounded and
    /// may be truncated to its last bytes. This variant exists because a server
    /// that dies before it can frame a JSON-RPC reply has nowhere else to say
    /// why, and discarding stderr made those failures unattributable.
    #[error("{reason} (server stderr: {stderr})")]
    ServerFailedWithStderr { reason: String, stderr: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}
