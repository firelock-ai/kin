# kin-blobs

Content-addressable blob store for Kin.

## Overview

kin-blobs provides a SHA-256 content-addressable blob store with Git-style directory sharding. Blobs are stored at `{root}/{hash[0..2]}/{hash[2..]}` to avoid filesystem bottlenecks with large object counts. Writes are atomic (temp file + rename) and deduplicated by content hash.

## Key Types

- **`BlobStore`** -- Main store interface. Provides `write`, `read`, `exists`, and `delete` operations.
- **`Hash256`** -- A 32-byte SHA-256 hash with hex encoding/decoding and `Display` support.
- **`BlobError`** -- Error type covering I/O failures and missing blobs (`NotFound`).

## Usage

```rust
use kin_blobs::{BlobStore, Hash256};

let store = BlobStore::new("/path/to/.kin/blobs".into())?;

// Write returns the content hash
let hash = store.write(b"hello world")?;

// Read by hash
let data = store.read(&hash)?;

// Check existence
assert!(store.exists(&hash)?);
```

## Dependencies

- `sha2` -- SHA-256 hashing
- `hex` -- Hash encoding/decoding

## Testing

```bash
cargo test -p kin-blobs
```

## License

Apache-2.0 -- Copyright 2026 Firelock, LLC
