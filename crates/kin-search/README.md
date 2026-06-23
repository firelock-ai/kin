# kin-search

Lightweight lexical search primitives for the Kin semantic stack.

`kin-search` is a small, in-memory BM25 text index with code-aware
tokenization and no external search-engine dependency. It splits identifiers
(camelCase / snake_case) so source symbols are matched the way developers
write them.

It is a low-level retrieval primitive in the open Kin local substrate. Higher
layers — notably `kin-db` — compose it with vector retrieval and graph
structure; Kin's ranking and proof-weighting policy lives above this crate, not
inside it.

## Build

```bash
cargo build
cargo test
```

## Key types

- `TextIndex<Id>` — the index, generic over a document-key type.
- `DocId` — blanket trait for usable key types (`Copy + Eq + Hash + Send + Sync + Debug`).
- `Searchable` — implement to auto-extract searchable fields from your own types.
- `tokenize()` — the public code-aware tokenizer.

## License

Apache-2.0. Part of the open Kin local substrate.
