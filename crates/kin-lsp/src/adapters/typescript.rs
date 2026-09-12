// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! TypeScript/JavaScript LSP adapter (typescript-language-server or vtsls).

use super::LspAdapter;
use kin_model::LanguageId;
use std::path::Path;

pub struct TypeScriptAdapter;

impl LspAdapter for TypeScriptAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::TypeScript
    }

    fn server_command(&self) -> &str {
        "typescript-language-server"
    }

    fn server_args(&self) -> Vec<String> {
        vec!["--stdio".to_string()]
    }

    fn file_extensions(&self) -> &[&str] {
        &["ts", "tsx", "js", "jsx"]
    }

    fn initialization_options(&self, _workspace_root: &Path) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "preferences": {
                "includeInlayParameterNameHints": "none",
                "includeInlayPropertyDeclarationTypeHints": false,
            }
        }))
    }

    fn requires_workspace_indexing(&self) -> bool {
        true
    }

    fn estimated_index_time_secs(&self) -> u32 {
        10
    }
}
