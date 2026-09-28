// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! LSP client for Kin graph enrichment.
//!
//! Consumes external LSP servers (rust-analyzer, pyright, tsserver, etc.)
//! to produce type-resolved relations that tree-sitter cannot provide.

pub mod adapters;
pub mod analysis_env;
pub mod cache;
pub mod call_sites;
pub mod client;
pub mod discovery;
pub mod enrichment;
pub mod error;
pub mod external_symbols;
pub mod file_enrichment;
pub mod lifecycle;
pub mod proof;
pub mod proof_context;
pub mod protocol;
pub mod registry;
pub mod relation_identity;
mod server_process;
mod source_positions;
mod typescript_call_hierarchy;

pub use enrichment::{DocumentProvider, EnrichmentResult, EntityIndex, EntityRef};
pub use error::{LspError, Result};
pub use proof::{
    FileFailure, LanguageEnrichment, LspEnrichmentProof, ProofMode, ProofRecorder, ProofViolation,
};
pub use registry::{
    language_from_slug, stamp_lsp_provenance, BinaryFinder, LspCapability, LspProvenance,
    ProviderGap, ProviderGapReason, ProviderId, ProviderProbe, ProviderRegistry, RegistryConfig,
    RegistryConfigError, ResolvedProvider, SystemBinaryFinder,
};
pub use typescript_call_hierarchy::TypeScriptGrammars;

#[cfg(test)]
mod enrichment_integrity_tests;
