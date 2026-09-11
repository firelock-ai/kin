> **Umbrella guidance:** the workspace-root `AGENTS.md` is the source of truth for cross-repo thesis, boundaries, and rules. This file is the repo-specific authority for `kin-vector`.

# kin-vector

Pure-Rust HNSW approximate nearest-neighbor search. No C++ FFI.

## Build
cargo build
cargo test

## Architecture
Single-file engine (src/lib.rs). Generic over Id type via VectorId trait.
HNSW parameters: M=16, M_MAX_0=32, EF_CONSTRUCTION=200, EF_SEARCH=50.

## Key types
- VectorIndex<Id>: the main index, generic over key type
- VectorId trait: bound for index keys (Copy + Eq + Hash + Serialize)
- DefaultId: UUID-based default key type
