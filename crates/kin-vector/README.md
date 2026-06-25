# kin-vector

> Vector / ANN substrate for semantic retrieval.

`kin-vector` implements a Hierarchical Navigable Small World (HNSW) index for
embedding-based retrieval. It is compiled directly into the binary — no C++
FFI, no platform-specific build scripts, no external ANN library dependency.

It is a low-level retrieval primitive in the open Kin local substrate.
`kin-db` consumes it for vector-side retrieval; Kin's ranking and
proof-weighting policy lives above this crate, not inside it.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Part of Kin](https://img.shields.io/badge/part%20of-Kin-6E56CF.svg)](https://github.com/firelock-ai/kin)

## What is Kin?

Kin is the semantic system of record for AI-native software — your code as a graph of
entities, relations, and intents, not a pile of files and diffs. AI agents and humans
navigate it semantically, with provenance, review, and governance built in. It coexists
with Git and projects graph truth back to a normal filesystem, so any tool works unchanged.

Start at **[firelock-ai/kin](https://github.com/firelock-ai/kin)** · **[kinlab.ai](https://kinlab.ai)**

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

[Apache-2.0](LICENSE).
