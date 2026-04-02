// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Go LSP adapter (gopls).

use std::path::Path;
use kin_model::LanguageId;
use super::LspAdapter;

pub struct GoplsAdapter;

impl LspAdapter for GoplsAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Go
    }

    fn server_command(&self) -> &str {
        "gopls"
    }

    fn server_args(&self) -> Vec<String> {
        vec!["serve".to_string()]
    }

    fn file_extensions(&self) -> &[&str] {
        &["go"]
    }

    fn initialization_options(&self, _workspace_root: &Path) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "analyses": { "unusedparams": false, "shadow": false },
            "diagnosticsDelay": "500ms",
        }))
    }

    fn requires_workspace_indexing(&self) -> bool {
        true
    }

    fn estimated_index_time_secs(&self) -> u32 {
        15
    }
}
