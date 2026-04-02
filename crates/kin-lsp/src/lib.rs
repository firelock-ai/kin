// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! LSP client for Kin graph enrichment.
//!
//! Consumes external LSP servers (rust-analyzer, pyright, tsserver, etc.)
//! to produce type-resolved relations that tree-sitter alone cannot provide.
//!
//! Architecture:
//! - `client` — generic JSON-RPC stdio client
//! - `protocol` — LSP message types (subset we need)
//! - `lifecycle` — server process start/stop/initialize
//! - `discovery` — detect installed LSP servers
//! - `enrichment` — LSP responses → graph relations
//! - `cache` — per-file enrichment result cache
//! - `adapters/` — per-language server configuration

pub mod adapters;
pub mod cache;
pub mod client;
pub mod discovery;
pub mod enrichment;
pub mod error;
pub mod lifecycle;
pub mod protocol;
pub mod types;

use std::path::{Path, PathBuf};

use tracing::info;
use types::LanguageId;

pub use enrichment::EnrichmentResult;
pub use error::{LspError, Result};

/// Top-level LSP enricher. Manages server lifecycles and coordinates
/// enrichment across all languages detected in a workspace.
pub struct LspEnricher {
    workspace_root: PathBuf,
    servers: Vec<Box<dyn adapters::LspAdapter>>,
}

impl LspEnricher {
    /// Create a new enricher for the given workspace root.
    /// Does NOT start any servers — call `discover_and_start()` for that.
    pub fn new(workspace_root: &Path) -> Self {
        Self {
            workspace_root: workspace_root.to_path_buf(),
            servers: Vec::new(),
        }
    }

    /// Discover installed LSP servers and return which languages are available.
    pub fn discover(&self) -> Vec<discovery::DiscoveredServer> {
        discovery::discover_servers()
    }

    /// Start all discovered servers for languages present in this workspace.
    pub async fn start_available(&mut self) -> Result<Vec<LanguageId>> {
        let discovered = self.discover();
        let mut started = Vec::new();
        for server in discovered {
            info!(
                language = %server.language,
                command = %server.command,
                "discovered LSP server"
            );
            started.push(server.language);
        }
        Ok(started)
    }

    /// Enrich a single file: query the appropriate LSP server for type-resolved
    /// relations and return them.
    pub async fn enrich_file(&self, _file: &Path) -> Result<EnrichmentResult> {
        // TODO: Phase 2 — route to correct adapter, query call hierarchy
        Ok(EnrichmentResult::default())
    }

    /// Enrich all files in the workspace. Returns a summary.
    pub async fn enrich_workspace(&self) -> Result<EnrichmentSummary> {
        // TODO: Phase 2 — iterate files, batch queries
        Ok(EnrichmentSummary::default())
    }

    /// Shut down all running LSP servers.
    pub async fn shutdown(&mut self) -> Result<()> {
        // TODO: Phase 2 — send shutdown to all servers
        self.servers.clear();
        Ok(())
    }
}

/// Summary of a workspace enrichment pass.
#[derive(Debug, Default)]
pub struct EnrichmentSummary {
    pub files_enriched: usize,
    pub relations_added: usize,
    pub languages_used: Vec<LanguageId>,
    pub errors: Vec<String>,
}
