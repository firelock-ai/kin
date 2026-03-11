# Adding a Language Adapter to Kin

This guide explains how to add support for a new programming language in Kin's semantic parser.

## Overview

Kin uses tree-sitter for parsing and extracts semantic entities (functions, classes, interfaces, etc.) from source code. Each language is supported by an **adapter** that implements the `LanguageAdapter` trait.

## Architecture

```
crates/kin-parser/
  src/
    adapter.rs          # LanguageAdapter trait definition
    extract.rs          # ExtractedEntity, ParseOutput types
    languages/
      mod.rs            # AdapterRegistry
      typescript.rs     # Example: TypeScript adapter
      python.rs         # Example: Python adapter
      rust_lang.rs      # Example: Rust adapter
      your_language.rs  # <-- Your new adapter goes here
  tests/
    adapter_conformance.rs  # Conformance test suite
```

## Step 1: Add tree-sitter grammar dependency

In the workspace `Cargo.toml`, add the tree-sitter grammar for your language:

```toml
[workspace.dependencies]
tree-sitter-your-language = "0.23"
```

In `crates/kin-parser/Cargo.toml`:

```toml
[dependencies]
tree-sitter-your-language = { workspace = true }
```

## Step 2: Add LanguageId variant

In `crates/kin-model/src/ids.rs`, add your language to the `LanguageId` enum:

```rust
pub enum LanguageId {
    TypeScript,
    JavaScript,
    Python,
    Go,
    Java,
    Rust,
    YourLanguage,  // <-- Add here
}
```

## Step 3: Implement the adapter

Create `crates/kin-parser/src/languages/your_language.rs`:

```rust
use kin_model::{EntityKind, FilePathId, LanguageId, ParseState, Visibility};
use tree_sitter::Tree;

use crate::adapter::{
    collect_error_ranges, compute_fingerprint, make_parser, span_from_node, LanguageAdapter,
};
use crate::error::Result;
use crate::extract::{
    ExtractedEntity, ExtractedRelation, ExtractedTest, FileImport, ParseOutput,
};

pub struct YourLanguageAdapter;

impl LanguageAdapter for YourLanguageAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::YourLanguage
    }

    fn file_extensions(&self) -> &[&str] {
        &["ext1", "ext2"]
    }

    fn parse(&self, source: &[u8]) -> Result<Tree> {
        let mut parser = make_parser(&tree_sitter_your_language::LANGUAGE)?;
        parser
            .parse(source, None)
            .ok_or_else(|| crate::error::ParseError::ParseFailed("parse returned None".into()))
    }

    fn extract(
        &self,
        tree: &Tree,
        source: &[u8],
        file_id: &FilePathId,
    ) -> Result<ParseOutput> {
        let root = tree.root_node();
        let mut entities = Vec::new();
        let mut relations = Vec::new();
        let mut imports = Vec::new();

        let error_ranges = collect_error_ranges(tree);
        let parse_state = if error_ranges.is_empty() {
            ParseState::Valid
        } else {
            ParseState::Incomplete { error_ranges }
        };

        let mut cursor = root.walk();
        for child in root.children(&mut cursor) {
            // Walk tree-sitter nodes and extract entities
            // See typescript.rs or python.rs for examples
            extract_node(&child, source, file_id, &mut entities, &mut relations);
        }

        Ok(ParseOutput {
            entities,
            relations,
            imports,
            tests: Vec::new(),
            parse_state,
        })
    }
}

fn extract_node(
    node: &tree_sitter::Node,
    source: &[u8],
    file_id: &FilePathId,
    entities: &mut Vec<ExtractedEntity>,
    relations: &mut Vec<ExtractedRelation>,
) {
    // Match on node.kind() to find functions, classes, etc.
    // Use compute_fingerprint() for semantic identity
    // Use span_from_node() for source location
    match node.kind() {
        "function_definition" => {
            // Extract function entity
            if let Some(name_node) = node.child_by_field_name("name") {
                let name = name_node.utf8_text(source).unwrap_or("").to_string();
                entities.push(ExtractedEntity {
                    kind: EntityKind::Function,
                    name,
                    signature: node.utf8_text(source).unwrap_or("").to_string(),
                    visibility: Visibility::Public, // Determine from syntax
                    doc_summary: None,
                    fingerprint: compute_fingerprint(node, source),
                    span: span_from_node(node, file_id),
                });
            }
        }
        _ => {
            // Recurse into children
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                extract_node(&child, source, file_id, entities, relations);
            }
        }
    }
}
```

## Step 4: Register the adapter

In `crates/kin-parser/src/languages/mod.rs`:

1. Add `pub mod your_language;`
2. Add `pub use your_language::YourLanguageAdapter;`
3. Add `Box::new(YourLanguageAdapter)` to the `AdapterRegistry::new()` list

## Step 5: Add conformance fixtures

Create `tests/adapter-fixtures/your_language/basic.ext`:

```
// Fixture: basic YourLanguage entities
// Should contain at least:
// - 1 function/method
// - 1 class/struct/type (if applicable)
// - Both public and private entities
```

## Step 6: Add to conformance tests

In `crates/kin-parser/tests/adapter_conformance.rs`:

1. Add your adapter to `all_adapters()`:
   ```rust
   Box::new(YourLanguageAdapter),
   ```

2. Add fixture-based tests:
   ```rust
   #[test]
   fn conformance_extract_basic_fixture_your_language() {
       let source = load_fixture("your_language", "basic.ext");
       let adapter = YourLanguageAdapter;
       let output = parse_fixture(&adapter, &source);
       assert!(!output.entities.is_empty());
   }
   ```

3. Add your fixture to the entity name, fingerprint, span, and determinism tests.

## Step 7: Run conformance suite

```bash
cargo test -p kin-parser --test adapter_conformance
```

All 10 conformance requirements must pass:

1. `language_id()` returns a valid `LanguageId`
2. `file_extensions()` returns at least one extension (without leading dot)
3. `parse()` succeeds on valid source code
4. `parse()` handles invalid source without panicking
5. `extract()` produces at least one entity from the basic fixture
6. Extracted entities have non-empty names
7. Extracted entities have non-zero fingerprint hashes
8. Extracted entities have valid source spans (end > start, within bounds)
9. `parse_state` is `Valid` for well-formed fixtures
10. Same input produces identical output (deterministic)

## Key Types

| Type | Purpose |
|------|---------|
| `ExtractedEntity` | A semantic entity before ID assignment |
| `ExtractedRelation` | A relation between two named entities |
| `FileImport` | An import declaration for cross-file linking |
| `ExtractedTest` | A test function for verification coverage |
| `ParseOutput` | Combined output of parsing a single file |
| `SemanticFingerprint` | Identity moat: survives renames and formatting |
| `SourceSpan` | Byte-level location in source file |

## Helper Functions

- `compute_fingerprint(node, source)` — Compute AST/signature/behavior hashes
- `span_from_node(node, file_id)` — Build a `SourceSpan` from a tree-sitter node
- `collect_error_ranges(tree)` — Find parse error locations
- `make_parser(language_fn)` — Create a tree-sitter parser for a language

## Tips

- Study `typescript.rs` as the most complete reference adapter
- Use `node.kind()` to identify syntax constructs (check tree-sitter playground for your grammar)
- Visibility inference varies by language (Rust: `pub`, Python: `_` prefix, Go: capitalization)
- For import extraction, populate `FileImport` structs so the cross-file linker can resolve references
- Test extraction works correctly by checking entity counts, names, and kinds against your fixture
