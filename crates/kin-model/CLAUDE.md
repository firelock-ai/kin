> **Umbrella guidance:** the workspace-root `AGENTS.md` is the source of truth for cross-repo thesis, boundaries, and rules. This file is the repo-specific authority for `kin-model`.

# kin-model

Canonical domain types for the Kin semantic VCS. Defines the shared type
vocabulary that flows across `kin-db`, `kin`, and consuming layers.

## Build

```bash
cargo build
cargo test
```

## Architecture

Single-workspace crate (`src/lib.rs` and submodules). Depends on `kin-blobs`
(for content-addressable identity) and `kin-vector` (for embedding vectors).
Zero Kin runtime dependencies — types only.

## Boundary rule

Put work here when the job is adding or changing a shared domain type or
serialization contract. Put work in `kin/packages/boundary-contracts` when
the job is cross-process payload validation. Put work in `kin-db` when the
job is graph storage or retrieval internals.
