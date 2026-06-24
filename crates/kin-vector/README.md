# kin-vector

Pure-Rust HNSW approximate nearest-neighbor search for the Kin stack.

`kin-vector` implements a Hierarchical Navigable Small World (HNSW) index for
embedding-based retrieval. It is compiled directly into the binary — no C++
FFI, no platform-specific build scripts, no external ANN library dependency.

It is a low-level retrieval primitive in the open Kin local substrate.
`kin-db` consumes it for vector-side retrieval; Kin's ranking and
proof-weighting policy lives above this crate, not inside it.

## Build

```bash
cargo build
cargo test
```

SIMD (aarch64 NEON) distance kernels are compiled in by default but gated off
at runtime. Set `KIN_VECTOR_SIMD=1` to enable them. The scalar path is
bit-identical to the frozen benchmark baseline on every target.

## Key types

- `HnswIndex<Id>` — the index, generic over the key type via `VectorId`.
  Supports `insert`, `search`, `delete`, persistence (`save`/`load`), and
  merge from a delta set.
- `VectorId` trait — implement for custom key types; blanket impls provided for
  `u64`, `u32`, and `uuid::Uuid`.
- `DefaultId` — UUID-based default key type.
- `VectorError` — typed errors including `ModelMismatch` (refuses to load an
  index built with a different embedding model).
- `VecDelta` — incremental index mutation for snapshot-based sync.

## License

Apache-2.0. Part of the open Kin local substrate.
