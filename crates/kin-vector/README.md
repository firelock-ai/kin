# kin-vector

**Pure-Rust HNSW approximate nearest-neighbor search.**

No C++ FFI, no platform-specific build scripts. A single-file implementation of the Hierarchical Navigable Small World algorithm utilized by [KinDB](https://github.com/firelock-ai/kin-db).

> **Alpha** -- API will evolve. The core engine is exercised by Kin's test suite and validated benchmark sweeps.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Rust](https://img.shields.io/badge/Rust-2021_edition-orange.svg)](https://www.rust-lang.org/)
[![Status: Alpha](https://img.shields.io/badge/Status-Alpha-yellow.svg)](#status)

---

## Features

- **Cosine distance** metric (1.0 - cosine similarity)
- **Multi-layer graph** with M=16, M_MAX_0=32, EF_CONSTRUCTION=200, EF_SEARCH=50
- **Serialization** via MessagePack with atomic write semantics and crash recovery
- **Node deletion** with free-list reuse (soft-delete, no connectivity repair)
- **Generic over Id type** via the `VectorId` trait -- use UUIDs, u64, u32, or your own key type

---

## Quick Start

```toml
# Cargo.toml
[dependencies]
kin-vector = { git = "https://github.com/firelock-ai/kin-vector" }
```

```rust
use kin_vector::{VectorIndex, DefaultId};

// Create a 4-dimensional index
let index = VectorIndex::<DefaultId>::new(4).unwrap();

let id = DefaultId::new();
index.upsert(id, &[1.0, 0.0, 0.0, 0.0]).unwrap();

let results = index.search_similar(&[0.9, 0.1, 0.0, 0.0], 5).unwrap();
```

Using a plain `u64` as the key:

```rust
use kin_vector::VectorIndex;

let index = VectorIndex::<u64>::new(128).unwrap();
index.upsert(42u64, &vec![0.1; 128]).unwrap();
```

---

## Status

Alpha. The HNSW engine is proven in production through KinDB but the standalone crate API is new.

---

## License

Apache-2.0. See [LICENSE](LICENSE).

Created by Troy Fortin at [Firelock, LLC](https://firelock.ai).

> *So neither the one who plants nor the one who waters is anything, but only God, who makes things grow.* -- 1 Corinthians 3:7
