# kin-blobs

**Content-addressable blob store with SHA-256 hashing and Git-style sharding.**

kin-blobs is a minimal, dependency-light blob store in Rust. It provides the content-addressed storage layer for the [Kin](https://github.com/firelock-ai/kin) semantic version control system and now ships as its own Apache-licensed repo.

> **Alpha** -- APIs will evolve. Proven now: the core store is exercised by Kin's full test suite and validated benchmark sweeps. Still hardening: API surface outside Kin.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Rust](https://img.shields.io/badge/Rust-2021_edition-orange.svg)](https://www.rust-lang.org/)
[![Status: Alpha](https://img.shields.io/badge/Status-Alpha-yellow.svg)](#status)

---

## What kin-blobs Does

- **Content-addressable storage** -- every blob is keyed by its SHA-256 hash, providing automatic deduplication
- **Atomic writes** -- data is written to a temp file then renamed into place, so readers never see partial content
- **Git-style sharding** -- blobs stored at `{root}/{hash[0..2]}/{hash[2..]}` to avoid filesystem bottlenecks with large object counts
- **Concurrent-safe** -- atomic rename + dedup check means multiple writers can target the same store without coordination

---

## Quick Start

```bash
# Prerequisites: Rust stable
git clone https://github.com/firelock-ai/kin-blobs.git
cd kin-blobs
cargo build --release

# Run tests
cargo test
```

### Usage

```rust
use kin_blobs::{BlobStore, Hash256, digest};
use std::path::PathBuf;

// Create or open a blob store
let store = BlobStore::new(PathBuf::from(".kin/objects")).unwrap();

// Write content -- returns the SHA-256 hash
let hash = store.write(b"fn main() {}").unwrap();

// Read content back by hash
let data = store.read(&hash).unwrap();
assert_eq!(data, b"fn main() {}");

// Check existence
assert!(store.exists(&hash).unwrap());

// Delete
store.delete(&hash).unwrap();
assert!(!store.exists(&hash).unwrap());

// Standalone digest (no store needed)
let hash = digest(b"hello world");
println!("{hash}"); // 64-char hex string
```

---

## Repo Layout

```
src/
  lib.rs       # BlobStore, Hash256, digest/digest_bytes (~585 lines incl. tests)
  error.rs     # BlobError enum
```

Minimal dependencies: `sha2`, `hex`, `serde`, `thiserror`, `tracing`.

---

## Design Principles

- **Content is truth** -- the hash *is* the identity. Same content always produces the same key.
- **No coordination needed** -- atomic writes and dedup checks mean multiple processes can share a store safely.
- **Filesystem-native** -- no database, no WAL, no lock files. Just directories and files.
- **Minimal surface** -- write, read, exists, delete. That is the entire API.

---

## Key Types

| Type | Description |
|------|-------------|
| `BlobStore` | Filesystem-backed content-addressable store |
| `Hash256` | 256-bit content hash (SHA-256), Copy + Eq + Hash + Serialize |
| `BlobError` | Error enum: NotFound, Io, HashMismatch |
| `digest()` | Compute SHA-256 hash of byte slice, returns `Hash256` |
| `digest_bytes()` | Compute SHA-256 hash, returns raw `[u8; 32]` |

---

## Status

**Proven now:**
- Atomic write/read/delete with content deduplication
- Git-style 2-char shard directory layout
- Concurrent write safety (temp file + rename)
- Full test coverage including concurrency, binary content, and edge cases
- Used as the blob store for Kin's full test and benchmark suite

**Still hardening:**
- API surface outside Kin
- Garbage collection / compaction utilities
- Streaming read/write for very large blobs

---

## Ecosystem

| Component | Status | Description |
|-----------|--------|-------------|
| **[kin](https://github.com/firelock-ai/kin)** | Shipping now | Semantic VCS -- primary consumer of kin-blobs |
| **[kin-db](https://github.com/firelock-ai/kin-db)** | Shipping now | Graph engine substrate |
| **[kin-vfs](https://github.com/firelock-ai/kin-vfs)** | Alpha | Virtual filesystem -- serves files from blob store |
| **[kin-blobs](https://github.com/firelock-ai/kin-blobs)** | Alpha | Content-addressable blob store (this repo) |
| **[kin-editor](https://github.com/firelock-ai/kin-editor)** | Active | VS Code extension |
| **[KinLab](https://kinlab.ai)** | Hardening | Hosted collaboration layer |

kin-blobs exists as a separate repo because content-addressable storage is a foundational concern that sits below the higher-level Kin product layers.

---

## Contributing

Contributions welcome. Please open an issue before submitting large changes.

## License

Apache-2.0.

---

Created by [Troy Fortin](https://www.linkedin.com/in/troy-fortin-jr/) at [Firelock, LLC](https://firelock.ai).

---

*"So neither the one who plants nor the one who waters is anything, but only God, who makes things grow." -- 1 Corinthians 3:7*
