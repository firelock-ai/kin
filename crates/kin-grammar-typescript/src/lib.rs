// SPDX-License-Identifier: MIT
// Derived from tree-sitter-typescript's bindings/rust/lib.rs.

//! The tree-sitter TypeScript and TSX grammars, patched so two constructs the
//! TypeScript compiler accepts do not cost Kin the rest of the file.
//!
//! The grammar under `grammar/` is [tree-sitter-typescript] v0.23.2 with the two
//! patches in `patches/` applied and the parser regenerated. `README.md` records
//! why each patch exists and how to reproduce the generated files.
//!
//! The public surface matches upstream's, so a call site reads the same as it
//! did against the crates.io crate:
//!
//! ```
//! let mut parser = tree_sitter::Parser::new();
//! parser
//!     .set_language(&kin_grammar_typescript::LANGUAGE_TYPESCRIPT.into())
//!     .expect("load the TypeScript grammar");
//! let tree = parser.parse("interface I {\n  p: string\n  <T>(): void\n}\n", None).unwrap();
//! assert!(!tree.root_node().has_error());
//! ```
//!
//! [tree-sitter-typescript]: https://github.com/tree-sitter/tree-sitter-typescript

use tree_sitter_language::LanguageFn;

extern "C" {
    fn tree_sitter_typescript() -> *const ();
    fn tree_sitter_tsx() -> *const ();
}

/// The tree-sitter `LanguageFn` for TypeScript.
pub const LANGUAGE_TYPESCRIPT: LanguageFn = unsafe { LanguageFn::from_raw(tree_sitter_typescript) };

/// The tree-sitter `LanguageFn` for TSX.
pub const LANGUAGE_TSX: LanguageFn = unsafe { LanguageFn::from_raw(tree_sitter_tsx) };

/// The content of the `node-types.json` file for TypeScript.
pub const TYPESCRIPT_NODE_TYPES: &str = include_str!("../grammar/typescript/src/node-types.json");

/// The content of the `node-types.json` file for TSX.
pub const TSX_NODE_TYPES: &str = include_str!("../grammar/tsx/src/node-types.json");

/// The syntax highlighting query for TypeScript.
pub const HIGHLIGHTS_QUERY: &str = include_str!("../grammar/queries/highlights.scm");

/// The local-variable syntax highlighting query for TypeScript.
pub const LOCALS_QUERY: &str = include_str!("../grammar/queries/locals.scm");

/// The symbol tagging query for TypeScript.
pub const TAGS_QUERY: &str = include_str!("../grammar/queries/tags.scm");
