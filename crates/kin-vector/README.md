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

- `VectorIndex<Id>` — the index, generic over the key type via `VectorId`
  (defaults to `DefaultId`). Supports `upsert` / `upsert_batch`,
  `search_similar` / `search_similar_filtered`, `remove`, and on-disk
  persistence (`save` / `load` / `load_checked`).
- `VectorId` trait — implement for custom key types; blanket impls provided for
  `u64`, `u32`, and `uuid::Uuid`.
- `DefaultId` — UUID-based default key type.
- `VectorError` — typed errors including `ModelMismatch` (refuses to load an
  index built with a different embedding model).
- `IndexDescriptor` — stamps the embedding model and graph-snapshot root an
  index was built against; `verify_compatible` enforces it on load.

## License

Apache-2.0. Part of the open Kin local substrate.
