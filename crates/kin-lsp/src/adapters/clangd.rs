// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! C/C++ LSP adapter (clangd).

use super::LspAdapter;
use kin_model::LanguageId;
use std::path::Path;

pub struct ClangdAdapter;

impl LspAdapter for ClangdAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::C // Covers both C and C++
    }

    fn server_command(&self) -> &str {
        "clangd"
    }

    fn file_extensions(&self) -> &[&str] {
        &["c", "h", "cpp", "hpp", "cc", "cxx"]
    }

    fn initialization_options(&self, _workspace_root: &Path) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "clangd": {
                "diagnostics": { "onOpen": false, "onChange": false, "onSave": false },
            }
        }))
    }

    fn requires_workspace_indexing(&self) -> bool {
        true // needs compile_commands.json
    }

    fn estimated_index_time_secs(&self) -> u32 {
        20
    }
}
