# kin-search

Lightweight in-memory BM25 text search with code-aware tokenization. Zero external search engine dependencies.

## Build
```bash
cargo build
cargo test
```

## Architecture
Single-file engine (src/lib.rs). Generic over document ID type via DocId trait.
BM25 parameters: k1=1.2, b=0.75.

## Key types
- `TextIndex<Id>` — the main index, generic over document key type
- `DocId` trait — blanket impl for `Copy + Eq + Hash + Send + Sync + Debug`
- `Searchable` trait — implement to auto-extract search fields from your types
- `tokenize()` — public code-aware tokenizer (camelCase/snake_case splitting)
