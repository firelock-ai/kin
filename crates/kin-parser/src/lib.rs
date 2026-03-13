//! Tree-sitter parsing and language adapters for Kin.
//!
//! This crate provides the `LanguageAdapter` trait and built-in adapters
//! for TypeScript, JavaScript, Python, Go, Java, and Rust.

pub mod adapter;
pub mod error;
pub mod extract;
pub mod languages;
pub mod shallow;
pub mod todos;

pub use adapter::LanguageAdapter;
pub use error::{ParseError, Result};
pub use extract::{
    ExtractedEntity, ExtractedRelation, ExtractedTest, ExtractedTestKind, FileImport, ImportedName,
    ParseOutput,
};
pub use languages::{
    AdapterRegistry, GoAdapter, JavaAdapter, JavaScriptAdapter, PythonAdapter, RustAdapter,
    TypeScriptAdapter,
};
pub use shallow::{
    extract_shallow, get_shallow_grammar, parse_shallow_file, ShallowDecl, ShallowDeclKind,
    ShallowFile, ShallowFingerprint, ShallowImport,
};
pub use todos::{extract_todos, ExtractedTodo};
