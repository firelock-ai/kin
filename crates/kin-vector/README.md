# kin-vector

> Vector / ANN substrate for semantic retrieval.

`kin-vector` implements a Hierarchical Navigable Small World (HNSW) index for
embedding-based retrieval. It is compiled directly into the binary: no C++
FFI, no platform-specific build scripts, no external ANN library dependency.

It is the vector retrieval primitive in the open Kin local substrate, and it
depends on nothing else in that stack. `kin-db` composes it for ANN and
embedding retrieval behind its `vector` feature, and `kin-model` implements
this crate's `VectorId` trait for the canonical retrieval key. Kin's ranking
and proof-weighting policy lives above this crate, not inside it.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Part of Kin](https://img.shields.io/badge/part%20of-Kin-6E56CF.svg)](https://github.com/firelock-ai/kin)

## What is Kin?

Kin is the system of record for AI-written software: your code as a graph of
entities, relations, and intents, not a pile of files and diffs. AI agents and humans
navigate it semantically, with provenance, review, and governance built in. It coexists
with Git and projects graph truth back to a normal filesystem, so any tool works unchanged.

Start at **[firelock-ai/kin](https://github.com/firelock-ai/kin)** · **[kinlab.ai](https://kinlab.ai)**

## Build

```bash
cargo build
cargo test
```

The toolchain is pinned in `rust-toolchain.toml` so a local build matches CI.
CI checks formatting, runs clippy over all targets with warnings denied, builds
all targets, and runs the test suite on Linux, macOS, and Windows.

SIMD (aarch64 NEON) distance kernels are compiled in and enabled by default at
runtime. Set `KIN_VECTOR_SIMD=0` (or `false`, `no`, `off`) to select the scalar
path instead. The scalar path is bit-identical to the frozen benchmark baseline
on every target.

## Tests

`cargo test` runs the unit tests in `src/lib.rs` and the integration tests in
`tests/`. The integration suite holds an exact brute-force oracle that measures
the shipped index against the true nearest neighbors, a SHA-256 canary that
pins the recovery-marker digest to the FIPS 180-4 examples rather than to this
crate's own output, and three aarch64 SIMD arms that compile only under
`--features simd` on that architecture. Each SIMD arm is its own test binary,
because the `KIN_VECTOR_SIMD` gate is sampled once per process and has to be
set before the first distance call.

One CPU-efficiency measurement is `#[ignore]`d, so the default suite builds it
but never runs it. Take it with `cargo test -- --ignored` in a quiet window. A
timing measured while another build is competing for the same cores says
nothing.

## Key types

- `VectorIndex<Id>`: the index, generic over the key type via `VectorId`
  (defaults to `DefaultId`). Supports `upsert` / `upsert_batch`,
  `search_similar` / `search_similar_filtered`, `remove`, and on-disk
  persistence (`save` / `load` / `load_checked`).
- `VectorId` trait: implement for custom key types; blanket impls provided for
  `u64`, `u32`, and `uuid::Uuid`.
- `DefaultId`: UUID-based default key type.
- `VectorError`: typed errors including `ModelMismatch` (refuses to load an
  index built with a different embedding model).
- `IndexDescriptor`: stamps the embedding model and graph-snapshot root an
  index was built against; `verify_compatible` enforces it on load.

## License

[Apache-2.0](LICENSE).
