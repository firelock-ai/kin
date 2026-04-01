# kin-index

Graph build and update pipeline for Kin.

## Overview

kin-index orchestrates the pipeline from source file to graph entity. It parses files (via kin-parser), stores content in the blob store (via kin-blobs), computes fingerprints for change detection, links cross-file relations, and applies results to the working copy overlay in the graph. It also provides a file watcher for incremental re-indexing. The indexer updates only the WorkingCopy overlay -- it does not create SemanticChange nodes (that is `kin commit`'s job).

## Key Types

- **`Indexer`** -- Top-level entry point combining parsing, blob storage, and graph updates.
- **`IndexPipeline`** -- Core pipeline: file -> parse -> fingerprint -> blob -> overlay.
- **`FileWatcher`** / **`FileEvent`** -- `notify`-based file watcher for incremental indexing.
- **`CrossFileLinker`** -- Links relations across files after individual file parsing.
- **`FileClassifier`** / **`FileClassification`** -- Determines file type and whether it should be indexed.
- **`ApplyResult`** -- Stats from applying index results to the graph (upserted, removed, skipped).

## Usage

```rust
use kin_index::Indexer;

let indexer = Indexer::new();
let result = indexer.index_and_apply(&file_path, &blob_store, &graph)?;
println!("upserted: {}, removed: {}", result.entities_upserted, result.entities_removed);
```

## Testing

```bash
cargo test -p kin-index
```

## License

Apache-2.0 -- Copyright 2026 Firelock, LLC
