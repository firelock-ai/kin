// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! LSP client for Kin graph enrichment.
//!
//! Consumes external LSP servers (rust-analyzer, pyright, tsserver, etc.)
//! to produce type-resolved relations that tree-sitter cannot provide.

pub mod adapters;
pub mod cache;
pub mod client;
pub mod discovery;
pub mod enrichment;
pub mod error;
pub mod file_enrichment;
pub mod lifecycle;
pub mod protocol;

pub use enrichment::{EnrichmentResult, EntityIndex, EntityRef};
pub use error::{LspError, Result};
