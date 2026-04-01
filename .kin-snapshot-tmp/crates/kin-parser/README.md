# kin-parser

Tree-sitter parsing and language adapters for Kin.

## Overview

kin-parser extracts semantic entities and relations from source files using tree-sitter grammars. It supports 14 languages through a pluggable `LanguageAdapter` trait, each providing AST-to-entity extraction rules. The crate also includes a shallow parsing mode for fast fingerprinting without full entity extraction, and TODO/FIXME comment extraction.

## Supported Languages

**Full semantic adapters** (deep entity/relation extraction with call graphs, imports, and visibility):
TypeScript, JavaScript, Python, Go, Java, Rust, Kotlin, PHP, Swift

**Shallow-backed adapters** (entity extraction with lighter relation coverage):
C, C++, C#, Ruby, HCL

## Key Types

- **`LanguageAdapter`** -- Trait defining how a language's AST maps to Kin entities and relations.
- **`AdapterRegistry`** -- Registry of all built-in language adapters, selected by file extension.
- **`ParseOutput`** -- Result of parsing a file: extracted entities, relations, imports, and tests.
- **`ExtractedEntity`** / **`ExtractedRelation`** -- Semantic items pulled from the AST.
- **`ShallowFile`** / **`ShallowDecl`** -- Lightweight declaration-level parse for fast fingerprinting.
- **`EditHint`** -- Guidance for projection on how to splice entity changes back into source.

## Usage

```rust
use kin_parser::{AdapterRegistry, ParseOutput};

let registry = AdapterRegistry::new();
let adapter = registry.adapter_for_extension("ts").unwrap();
let output: ParseOutput = adapter.parse(source_bytes, file_path)?;
```

## Testing

```bash
cargo test -p kin-parser
```

## License

Apache-2.0 -- Copyright 2026 Firelock, LLC
