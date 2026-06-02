> **Umbrella guidance:** the workspace-root `AGENTS.md` is the source of truth for cross-repo thesis, boundaries, and rules. This file is the repo-specific authority for `kin-blobs`.

# kin-blobs

Content-addressable blob store in Rust. SHA-256 hashing, Git-style sharding, atomic writes.

## Build
cargo build
cargo test

## Architecture
- src/lib.rs — BlobStore (write/read/exists/delete) + Hash256 type + digest functions
- src/error.rs — BlobError enum

## Key types
- BlobStore — the main store, backed by filesystem with {root}/{hash[0..2]}/{hash[2..]} layout
- Hash256 — 256-bit content hash (SHA-256)
- digest() / digest_bytes() — hash computation functions
