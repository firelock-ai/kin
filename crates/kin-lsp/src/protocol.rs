// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! LSP protocol types — the subset Kin needs for graph enrichment.
//!
//! We don't use the full lsp-types crate to keep dependencies minimal.
//! Only the types needed for: initialize, textDocument/definition,
//! textDocument/references, callHierarchy.

use serde::{Deserialize, Serialize};

// ── Initialize ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    pub process_id: Option<u32>,
    pub root_uri: Option<String>,
    pub capabilities: ClientCapabilities,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initialization_options: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientCapabilities {
    pub text_document: Option<TextDocumentClientCapabilities>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TextDocumentClientCapabilities {
    pub call_hierarchy: Option<serde_json::Value>,
    pub definition: Option<serde_json::Value>,
    pub references: Option<serde_json::Value>,
    pub type_hierarchy: Option<serde_json::Value>,
    pub type_definition: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub capabilities: ServerCapabilities,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ServerCapabilities {
    pub call_hierarchy_provider: Option<serde_json::Value>,
    pub definition_provider: Option<serde_json::Value>,
    pub references_provider: Option<serde_json::Value>,
    pub type_hierarchy_provider: Option<serde_json::Value>,
    pub type_definition_provider: Option<serde_json::Value>,
}

// ── Text Document ───────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TextDocumentIdentifier {
    pub uri: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Position {
    pub line: u32,
    pub character: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Range {
    pub start: Position,
    pub end: Position,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Location {
    pub uri: String,
    pub range: Range,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TextDocumentPositionParams {
    pub text_document: TextDocumentIdentifier,
    pub position: Position,
}

// ── Call Hierarchy ──────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallHierarchyPrepareParams {
    pub text_document: TextDocumentIdentifier,
    pub position: Position,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CallHierarchyItem {
    pub name: String,
    pub kind: u32, // SymbolKind
    pub uri: String,
    pub range: Range,
    pub selection_range: Range,
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CallHierarchyIncomingCallsParams {
    pub item: CallHierarchyItem,
}

#[derive(Debug, Serialize)]
pub struct CallHierarchyOutgoingCallsParams {
    pub item: CallHierarchyItem,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallHierarchyIncomingCall {
    pub from: CallHierarchyItem,
    pub from_ranges: Vec<Range>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallHierarchyOutgoingCall {
    pub to: CallHierarchyItem,
    pub from_ranges: Vec<Range>,
}

// ── Type Hierarchy ─────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeHierarchyPrepareParams {
    pub text_document: TextDocumentIdentifier,
    pub position: Position,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TypeHierarchyItem {
    pub name: String,
    pub kind: u32,
    pub uri: String,
    pub range: Range,
    pub selection_range: Range,
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TypeHierarchySupertypesParams {
    pub item: TypeHierarchyItem,
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Convert a file path to a file:// URI.
pub fn path_to_uri(path: &std::path::Path) -> String {
    format!("file://{}", path.display())
}

/// Extract a file path from a file:// URI.
pub fn uri_to_path(uri: &str) -> Option<std::path::PathBuf> {
    uri.strip_prefix("file://").map(std::path::PathBuf::from)
}

/// Build standard client capabilities requesting the features Kin needs.
pub fn kin_capabilities() -> ClientCapabilities {
    ClientCapabilities {
        text_document: Some(TextDocumentClientCapabilities {
            call_hierarchy: Some(serde_json::json!({"dynamicRegistration": false})),
            definition: Some(
                serde_json::json!({"dynamicRegistration": false, "linkSupport": false}),
            ),
            references: Some(serde_json::json!({"dynamicRegistration": false})),
            type_hierarchy: Some(serde_json::json!({"dynamicRegistration": false})),
            type_definition: Some(serde_json::json!({"dynamicRegistration": false})),
        }),
    }
}
