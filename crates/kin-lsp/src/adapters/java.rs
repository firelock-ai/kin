// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Java LSP adapter (Eclipse JDT Language Server).

use std::path::Path;
use kin_model::LanguageId;
use super::LspAdapter;

pub struct JdtlsAdapter;

impl LspAdapter for JdtlsAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Java
    }

    fn server_command(&self) -> &str {
        "jdtls"
    }

    fn file_extensions(&self) -> &[&str] {
        &["java"]
    }

    fn initialization_options(&self, _workspace_root: &Path) -> Option<serde_json::Value> {
        None // jdtls uses workspace-level config
    }

    fn requires_workspace_indexing(&self) -> bool {
        true
    }

    fn estimated_index_time_secs(&self) -> u32 {
        20
    }
}
