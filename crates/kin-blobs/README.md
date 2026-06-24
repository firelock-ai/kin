# kin-blobs

Content-addressable blob storage substrate for the Kin semantic stack.

`kin-blobs` is a small, dependency-light Rust crate that stores immutable
content keyed by its SHA-256 digest. Writes are atomic and content is sharded
Git-style (`{root}/{hash[0..2]}/{hash[2..]}`), so identical content is stored
once and always addressed by its hash.

It is a foundational primitive in the open Kin local substrate: higher layers
such as `kin-model` and `kin-db` build the canonical types and the semantic
graph on top of content-addressable storage.

## Build

```bash
cargo build
cargo test
```

## Key types

- `BlobStore` — filesystem-backed store: `write`, `read`, `exists`, `delete`,
  `list_hashes`, and garbage collection (`gc`) against a live set.
- `Hash256` — 256-bit content hash (SHA-256), with hex parsing/formatting.
- `digest()` / `digest_bytes()` — content-hash computation helpers.

## License

Apache-2.0. Part of the open Kin local substrate.
