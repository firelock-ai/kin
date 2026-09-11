// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Per-language LSP server adapters.
//!
//! Each adapter knows how to configure and start its language's LSP server,
//! and how to interpret server-specific behaviors or quirks.

use std::path::Path;

use kin_model::LanguageId;

/// Trait that each language adapter implements.
///
/// The generic framework handles JSON-RPC transport, message routing, and
/// enrichment conversion. Adapters handle the language-specific parts:
/// how to start the server, what initialization options to send, and
/// how to map language-specific features to graph operations.
pub trait LspAdapter: Send + Sync {
    /// Which language this adapter handles.
    fn language_id(&self) -> LanguageId;

    /// The command to start the LSP server (e.g., "rust-analyzer").
    fn server_command(&self) -> &str;

    /// Arguments to pass to the server command.
    fn server_args(&self) -> Vec<String> {
        Vec::new()
    }

    /// Language-specific initialization options to include in the
    /// `initializationOptions` field of the initialize request.
    fn initialization_options(&self, _workspace_root: &Path) -> Option<serde_json::Value> {
        None
    }

    /// File extensions this adapter handles (e.g., ["rs"] for Rust).
    fn file_extensions(&self) -> &[&str];

    /// Whether this adapter needs the server to index the entire workspace
    /// before queries are meaningful (e.g., rust-analyzer needs cargo metadata).
    fn requires_workspace_indexing(&self) -> bool {
        true
    }

    /// Estimated time in seconds for the server to index a typical workspace.
    /// Used for progress reporting, not as a hard timeout.
    fn estimated_index_time_secs(&self) -> u32 {
        30
    }
}

pub mod clangd;
pub mod go;
pub mod java;
pub mod python;
pub mod rust_analyzer;
pub mod typescript;
