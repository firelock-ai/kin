// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! rust-analyzer LSP adapter.

use std::path::Path;

use crate::types::LanguageId;

use super::LspAdapter;

pub struct RustAnalyzerAdapter;

impl LspAdapter for RustAnalyzerAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Rust
    }

    fn server_command(&self) -> &str {
        "rust-analyzer"
    }

    fn file_extensions(&self) -> &[&str] {
        &["rs"]
    }

    fn initialization_options(&self, _workspace_root: &Path) -> Option<serde_json::Value> {
        // Disable features we don't need to speed up indexing.
        Some(serde_json::json!({
            "cargo": {
                "buildScripts": { "enable": false },
                "sysroot": "discover",
            },
            "procMacro": { "enable": false },
            "checkOnSave": false,
            "diagnostics": { "enable": false },
        }))
    }

    fn requires_workspace_indexing(&self) -> bool {
        true // rust-analyzer needs to load cargo metadata
    }

    fn estimated_index_time_secs(&self) -> u32 {
        30 // typical for medium Rust projects
    }
}
