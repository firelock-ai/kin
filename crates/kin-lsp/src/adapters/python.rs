// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! pyright LSP adapter for Python.

use std::path::Path;

use kin_model::LanguageId;

use super::LspAdapter;

pub struct PyrightAdapter;

impl LspAdapter for PyrightAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Python
    }

    fn server_command(&self) -> &str {
        "pyright-langserver"
    }

    fn server_args(&self) -> Vec<String> {
        vec!["--stdio".to_string()]
    }

    fn file_extensions(&self) -> &[&str] {
        &["py", "pyi"]
    }

    fn initialization_options(&self, _workspace_root: &Path) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "pythonPath": "python3",
            "diagnosticMode": "off",
        }))
    }

    fn requires_workspace_indexing(&self) -> bool {
        true
    }

    fn estimated_index_time_secs(&self) -> u32 {
        15
    }
}
