# kin-blobs

> Content-addressable blob storage substrate.

`kin-blobs` is a small, dependency-light Rust crate that stores immutable
content keyed by its SHA-256 digest. Writes are atomic and content is sharded
Git-style (`{root}/{hash[0..2]}/{hash[2..]}`), so identical content is stored
once and always addressed by its hash.

It is the storage primitive in the open Kin local substrate. `kin-model` takes
its canonical content hash from this crate and `kin` keeps published source
bodies in a store built by it; Kin's graph, ranking, and provenance policy lives
above this crate, not inside it.

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

A blob's bytes are durable when `write` returns. The barrier that makes the
blob's *name* durable is deferred and amortized across a shard directory, and
`sync`, the `Drop` drain, or `write` itself issues it once enough renames
accumulate. A store built with `BlobStore::new_ephemeral` issues no device
barrier at all and makes none of those guarantees across a crash. Layout,
content addressing, dedup, and read-side verification are identical either way.

## Usage

```rust
use kin_blobs::{BlobStore, digest};
use std::path::PathBuf;

// Open or create a store backed by a local directory.
let store = BlobStore::new(PathBuf::from("/path/to/blobs"))?;

// Write is idempotent: identical content is stored once and returns its address.
let hash = store.write(b"hello, kin")?;

// Read back by content address; verifies the hash on the way out.
let bytes = store.read(&hash)?;
assert_eq!(bytes, b"hello, kin");

// Compute a content address without storing anything.
let h = digest(b"just hashing");
println!("{h}");
```

## Key types

- `BlobStore`: filesystem-backed store with `write`, `read`, `exists`, `delete`,
  `list_hashes`, `sync`, `quarantine`, and garbage collection (`gc`) against a
  live set. Build it with `new` for a durable store or `new_ephemeral` for one
  that issues no device barriers.
- `Hash256`: 256-bit content hash (SHA-256), with hex parsing and formatting.
- `GcReport`: what one `gc` pass scanned, retained, reclaimed, and freed in
  bytes.
- `digest()` / `digest_bytes()`: content-hash computation helpers.

## License

[Apache-2.0](LICENSE).
