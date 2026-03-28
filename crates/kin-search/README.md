# kin-search

Lightweight in-memory BM25 text search with code-aware tokenization.

No external search engine dependencies. No tantivy, no Lucene, no ElasticSearch. Just a lightweight Rust program with two dependencies (`parking_lot`, `thiserror`) that does exactly what you need for searching code entities.

## Features

- **BM25 scoring** with configurable field weights for relevance ranking
- **Code-aware tokenization** — splits camelCase, snake_case, and file paths into meaningful tokens
- **Substring fuzzy matching** — finds partial matches with a scoring penalty
- **Staged writes with commit semantics** — batch mutations, then atomically promote to live state
- **Generic over document ID type** — use `u64`, `Uuid`, or your own ID type
- **Thread-safe** — concurrent readers via `parking_lot::RwLock`

## Quick Start

```rust
use kin_search::{TextIndex, Searchable};

// Define your document type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct EntityId(u64);

struct CodeEntity {
    id: EntityId,
    name: String,
    file_path: String,
}

impl Searchable for CodeEntity {
    fn search_fields(&self) -> Vec<(&str, f32)> {
        vec![
            (&self.name, 5.0),      // name matches weighted highest
            (&self.file_path, 2.0), // file path matches weighted lower
        ]
    }
}

// Create an index and add documents
let index = TextIndex::<EntityId>::new();
let entity = CodeEntity {
    id: EntityId(1),
    name: "parseTableFromHtml".into(),
    file_path: "src/parser/html.rs".into(),
};

index.upsert_searchable(entity.id, &entity).unwrap();
index.commit().unwrap();

// Search returns (id, relevance_score) pairs, highest first
let results = index.fuzzy_search("parse html", 10).unwrap();
assert!(!results.is_empty());
assert_eq!(results[0].0, EntityId(1));
```

## Tokenization

The `tokenize()` function is public and useful standalone:

```rust
use kin_search::tokenize;

assert_eq!(
    tokenize("parseTableFromHtml"),
    vec!["parse", "table", "from", "html", "parsetablefromhtml"]
);

assert_eq!(
    tokenize("src/io/ascii.py"),
    vec!["src", "io", "ascii", "py"]
);
```

## Status

**Alpha.** Extracted from the [kin-db](https://github.com/firelock-ai/kin-db) graph database where it powers full-text search over code entities. The API is stabilizing but may change.

## License

Apache-2.0. See [LICENSE](LICENSE).

---

Created by Troy Fortin at [Firelock, LLC](https://firelock.ai).

> "So neither the one who plants nor the one who waters is anything, but only God, who makes things grow." — 1 Corinthians 3:7
