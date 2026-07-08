# kin-search

> Low-level lexical search primitives and staged retrieval.

`kin-search` is a small, in-memory BM25 text index with code-aware
tokenization and no external search-engine dependency. It splits identifiers
(camelCase / snake_case) so source symbols are matched the way developers
write them.

It is a low-level retrieval primitive in the open Kin local substrate. Higher
layers — notably `kin-db` — compose it with vector retrieval and graph
structure; Kin's ranking and proof-weighting policy lives above this crate, not
inside it.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Part of Kin](https://img.shields.io/badge/part%20of-Kin-6E56CF.svg)](https://github.com/firelock-ai/kin)

## What is Kin?

Kin is the semantic system of record for software work — your code as a graph of
entities, relations, and intents, not a pile of files and diffs. AI agents and humans
navigate it semantically, with provenance, review, and governance built in. It coexists
with Git and projects graph truth back to a normal filesystem, so any tool works unchanged.

Start at **[firelock-ai/kin](https://github.com/firelock-ai/kin)** · **[kinlab.ai](https://kinlab.ai)**

## Build

```bash
cargo build
cargo test
```

## Usage

```rust
use kin_search::TextIndex;

// Build an in-memory BM25 index over any key type.
let index: TextIndex<u64> = TextIndex::new();

// Index documents by weighted text fields (name, signature, path, …).
index.upsert(1, &[("render_frame", 5.0), ("graphics pipeline step", 2.0)])?;
index.upsert(2, &[("parse_tokens", 5.0), ("lexer token stream", 2.0)])?;

// camelCase and snake_case identifiers are split automatically.
let hits = index.fuzzy_search("renderFrame", 10)?;
for (id, score) in hits {
    println!("{id}: {score:.3}");
}
```

## Key types

- `TextIndex<Id>` — the index, generic over a document-key type.
- `DocId` — blanket trait for usable key types (`Copy + Eq + Hash + Send + Sync + Debug`).
- `Searchable` — implement to auto-extract searchable fields from your own types.
- `tokenize()` — the public code-aware tokenizer.

## License

[Apache-2.0](LICENSE).
