// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Tree-sitter parsing and language adapters for Kin.
//!
//! This crate provides the `LanguageAdapter` trait and built-in adapters
//! for TypeScript, JavaScript, Python, Go, Java, Rust, C, C++, C#, Ruby, PHP, Swift,
//! Kotlin, and HCL/Terraform.

pub const PARSER_SCHEMA_EPOCH: &str = "parser-schema-2026-03-29-v1";

/// Monotonic version of the parser's extraction semantics.
///
/// A parse is a pure function of `(source bytes, this version)`: the same bytes
/// parsed under the same version always yield the same `ParseOutput`. Callers
/// that memoize parse results across a run key that cache on
/// `(blob_hash, PARSER_SEMANTICS_VERSION)` so a cached parse is never served
/// after the parser's meaning has changed.
///
/// Bump contract — increment this by one on ANY change that can alter the
/// entities, relations, imports, tests, fingerprints, or metadata a given input
/// would produce. This includes:
/// - tree-sitter grammar upgrades (new grammar ABI or grammar revision),
/// - changes to entity/relation/import/test extraction logic,
/// - changes to fingerprint computation or attached-metadata shape.
///
/// It is a distinct, coarser knob from [`PARSER_SCHEMA_EPOCH`]: the epoch labels
/// the on-wire schema string, this integer gates in-memory parse reuse. When in
/// doubt, bump — a spurious bump only costs a cold re-parse, while a missed bump
/// silently serves stale semantics (the stale-binary class of bug). Mirrors
/// kin-db's `GraphSnapshot::CURRENT_VERSION` convention.
pub const PARSER_SEMANTICS_VERSION: u32 = 4;

pub mod adapter;
pub mod error;
pub mod extract;
pub mod languages;
pub mod shallow;
pub mod todos;

pub use adapter::{EditHint, LanguageAdapter};
pub use error::{ParseError, Result};
pub use extract::{
    attach_file_context_metadata, call_extraction_incomplete_marker,
    is_call_extraction_incomplete_marker, CallArgShape, ExtractedEntity, ExtractedRelation,
    ExtractedTest, ExtractedTestKind, FileImport, ImportedName, ParseOutput,
    CALL_EXTRACTION_INCOMPLETE_MARKER_V1, COMMAND_EFFECT_CONTRACT_KEY, FILE_IMPORT_CONTEXT_KEY,
    FILE_SURFACE_CONTEXT_KEY,
};
pub use languages::{
    attach_go_command_effect_contract_metadata, AdapterRegistry, CAdapter, CSharpAdapter,
    CppAdapter, GoAdapter, HclAdapter, JavaAdapter, JavaScriptAdapter, KotlinAdapter, PhpAdapter,
    PythonAdapter, RubyAdapter, RustAdapter, SwiftAdapter, TypeScriptAdapter,
};
pub use shallow::{
    extract_shallow, get_shallow_grammar, parse_shallow_file, ShallowDecl, ShallowDeclKind,
    ShallowFile, ShallowFingerprint, ShallowImport,
};
pub use todos::{extract_todos, ExtractedTodo};
