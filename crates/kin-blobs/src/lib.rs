// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

mod error;

pub use error::BlobError;

use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

/// Content-addressed 256-bit hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(s: &str) -> std::result::Result<Self, hex::FromHexError> {
        let mut buf = [0u8; 32];
        hex::decode_to_slice(s, &mut buf)?;
        Ok(Self(buf))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash256({})", &hex::encode(self.0)[..12])
    }
}

/// Monotonic counter for unique temp file names within a process.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub type Result<T> = std::result::Result<T, BlobError>;

/// Compute the SHA-256 hash of the given data.
///
/// This is the primary way to produce a `Hash256` for content-addressed
/// storage. The `Hash256` type is hash-algorithm-agnostic; the SHA-256
/// dependency lives here.
pub fn digest(data: &[u8]) -> Hash256 {
    Hash256(digest_bytes(data))
}

/// Compute a SHA-256 digest of `data`, returning the raw 32 bytes.
///
/// Lower-level variant of [`digest`] for callers that need raw bytes.
pub fn digest_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
}

/// Content-addressable blob store using SHA-256 hashing and Git-style sharding.
///
/// Blobs are stored at `{root}/{hash[0..2]}/{hash[2..]}` where the hash is
/// hex-encoded. This provides directory-level sharding to avoid filesystem
/// bottlenecks with large numbers of objects.
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    /// Create or open a blob store at the given root directory.
    ///
    /// Creates the root directory if it does not exist.
    pub fn new(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root).map_err(|e| BlobError::io(&root, e))?;
        Ok(Self { root })
    }

    /// Write data to the blob store, returning its content hash.
    ///
    /// If a blob with the same hash already exists, this is a no-op (content
    /// deduplication). Writes are atomic: data is written to a temporary file
    /// in the shard directory, then renamed into place.
    pub fn write(&self, data: &[u8]) -> Result<Hash256> {
        let hash = digest(data);
        let blob_path = self.blob_path(&hash);

        // Deduplication: if the blob already exists, skip writing.
        if blob_path.exists() {
            debug!(hash = %hash, "blob already exists, skipping write");
            return Ok(hash);
        }

        // Ensure the shard directory exists.
        let shard_dir = blob_path.parent().expect("blob path always has a parent");
        fs::create_dir_all(shard_dir).map_err(|e| BlobError::io(shard_dir, e))?;

        // Atomic write: write to a temp file in the shard dir, then rename.
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_path = shard_dir.join(format!(".tmp-{}-{}-{}", hash, std::process::id(), seq));
        fs::write(&temp_path, data).map_err(|e| BlobError::io(&temp_path, e))?;
        fs::rename(&temp_path, &blob_path).map_err(|e| BlobError::io(&blob_path, e))?;

        debug!(hash = %hash, bytes = data.len(), "wrote blob");
        Ok(hash)
    }

    /// Read a blob by its hash.
    ///
    /// Returns an error if the blob does not exist.
    pub fn read(&self, hash: &Hash256) -> Result<Vec<u8>> {
        let blob_path = self.blob_path(hash);
        fs::read(&blob_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BlobError::NotFound {
                    hash: hash.to_string(),
                }
            } else {
                BlobError::io(&blob_path, e)
            }
        })
    }

    /// Check whether a blob exists in the store.
    pub fn exists(&self, hash: &Hash256) -> Result<bool> {
        let blob_path = self.blob_path(hash);
        match blob_path.try_exists() {
            Ok(exists) => Ok(exists),
            Err(e) => Err(BlobError::io(&blob_path, e)),
        }
    }

    /// Delete a blob from the store.
    ///
    /// Returns an error if the blob does not exist.
    pub fn delete(&self, hash: &Hash256) -> Result<()> {
        let blob_path = self.blob_path(hash);
        fs::remove_file(&blob_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BlobError::NotFound {
                    hash: hash.to_string(),
                }
            } else {
                BlobError::io(&blob_path, e)
            }
        })?;
        debug!(hash = %hash, "deleted blob");
        Ok(())
    }

    /// Return the root directory of the blob store.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Compute the filesystem path for a blob given its hash.
    ///
    /// Layout: `{root}/{hash[0..2]}/{hash[2..]}` (Git-style sharding).
    fn blob_path(&self, hash: &Hash256) -> PathBuf {
        let hex = hash.to_string();
        self.root.join(&hex[..2]).join(&hex[2..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> (tempfile::TempDir, BlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::new(dir.path().join("objects")).unwrap();
        (dir, store)
    }

    #[test]
    fn write_and_read_round_trip() {
        let (_dir, store) = make_store();
        let data = b"hello, blob store!";
        let hash = store.write(data).unwrap();
        let retrieved = store.read(&hash).unwrap();
        assert_eq!(retrieved, data);
    }

    #[test]
    fn deduplication() {
        let (_dir, store) = make_store();
        let data = b"duplicate content";
        let hash1 = store.write(data).unwrap();
        let hash2 = store.write(data).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn different_content_different_hash() {
        let (_dir, store) = make_store();
        let hash1 = store.write(b"content A").unwrap();
        let hash2 = store.write(b"content B").unwrap();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn read_missing_blob_returns_not_found() {
        let (_dir, store) = make_store();
        let fake_hash = Hash256([0xab; 32]);
        let err = store.read(&fake_hash).unwrap_err();
        assert!(matches!(err, BlobError::NotFound { .. }));
    }

    #[test]
    fn exists_returns_false_for_missing() {
        let (_dir, store) = make_store();
        let fake_hash = Hash256([0xcd; 32]);
        assert!(!store.exists(&fake_hash).unwrap());
    }

    #[test]
    fn exists_returns_true_after_write() {
        let (_dir, store) = make_store();
        let hash = store.write(b"some data").unwrap();
        assert!(store.exists(&hash).unwrap());
    }

    #[test]
    fn delete_removes_blob() {
        let (_dir, store) = make_store();
        let hash = store.write(b"delete me").unwrap();
        assert!(store.exists(&hash).unwrap());
        store.delete(&hash).unwrap();
        assert!(!store.exists(&hash).unwrap());
    }

    #[test]
    fn delete_missing_blob_returns_not_found() {
        let (_dir, store) = make_store();
        let fake_hash = Hash256([0xef; 32]);
        let err = store.delete(&fake_hash).unwrap_err();
        assert!(matches!(err, BlobError::NotFound { .. }));
    }

    #[test]
    fn sharding_directory_structure() {
        let (_dir, store) = make_store();
        let data = b"sharding test";
        let hash = store.write(data).unwrap();
        let hex = hash.to_string();

        // Verify the shard directory exists
        let shard_dir = store.root().join(&hex[..2]);
        assert!(shard_dir.is_dir());

        // Verify the blob file exists with the correct name
        let blob_file = shard_dir.join(&hex[2..]);
        assert!(blob_file.is_file());

        // Verify content matches
        let content = std::fs::read(&blob_file).unwrap();
        assert_eq!(content, data);
    }

    #[test]
    fn hash256_hex_round_trip() {
        let hash = digest(b"test data");
        let hex = hash.to_string();
        let parsed = Hash256::from_hex(&hex).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn hash256_display() {
        let hash = digest(b"display test");
        let display = format!("{hash}");
        assert_eq!(display.len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(display, hash.to_string());
    }

    #[test]
    fn empty_blob() {
        let (_dir, store) = make_store();
        let hash = store.write(b"").unwrap();
        let data = store.read(&hash).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn large_blob() {
        let (_dir, store) = make_store();
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let hash = store.write(&data).unwrap();
        let retrieved = store.read(&hash).unwrap();
        assert_eq!(retrieved, data);
    }

    // -----------------------------------------------------------------------
    // digest / Hash256 tests
    // -----------------------------------------------------------------------

    #[test]
    fn digest_deterministic() {
        let h1 = digest(b"hello");
        let h2 = digest(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn digest_different_data_different_hash() {
        let h1 = digest(b"hello");
        let h2 = digest(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash256_from_hex_invalid_length() {
        let result = Hash256::from_hex("abcd");
        assert!(result.is_err());
    }

    #[test]
    fn hash256_from_hex_invalid_chars() {
        let result = Hash256::from_hex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        assert!(result.is_err());
    }

    #[test]
    fn hash256_debug_format() {
        let hash = digest(b"debug");
        let debug = format!("{:?}", hash);
        assert!(debug.starts_with("Hash256("));
        assert!(debug.ends_with(")"));
    }

    #[test]
    fn digest_empty_data() {
        let hash = digest(b"");
        // SHA-256 of empty string is a known value
        assert_eq!(
            hash.to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hash256_copy_semantics() {
        let h1 = digest(b"copy");
        let h2 = h1; // Copy
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash256_hash_trait() {
        use std::collections::HashSet;
        let h1 = digest(b"a");
        let h2 = digest(b"b");
        let mut set = HashSet::new();
        set.insert(h1);
        set.insert(h2);
        set.insert(h1); // duplicate
        assert_eq!(set.len(), 2);
    }

    // -----------------------------------------------------------------------
    // BlobStore advanced tests
    // -----------------------------------------------------------------------

    #[test]
    fn store_root_returns_correct_path() {
        let dir = tempfile::tempdir().unwrap();
        let objects_path = dir.path().join("my_objects");
        let store = BlobStore::new(objects_path.clone()).unwrap();
        assert_eq!(store.root(), objects_path);
    }

    #[test]
    fn write_creates_root_if_missing() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("c").join("objects");
        let store = BlobStore::new(nested.clone()).unwrap();
        assert!(nested.exists());
        let hash = store.write(b"test").unwrap();
        assert!(store.exists(&hash).unwrap());
    }

    #[test]
    fn one_megabyte_blob() {
        let (_dir, store) = make_store();
        let data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        let hash = store.write(&data).unwrap();
        let retrieved = store.read(&hash).unwrap();
        assert_eq!(retrieved.len(), 1_000_000);
        assert_eq!(retrieved, data);
    }

    #[test]
    fn binary_content_blob() {
        let (_dir, store) = make_store();
        // All possible byte values
        let data: Vec<u8> = (0..=255).collect();
        let hash = store.write(&data).unwrap();
        let retrieved = store.read(&hash).unwrap();
        assert_eq!(retrieved, data);
    }

    #[test]
    fn write_read_delete_read_cycle() {
        let (_dir, store) = make_store();
        let hash = store.write(b"cycle test").unwrap();
        assert!(store.exists(&hash).unwrap());
        let data = store.read(&hash).unwrap();
        assert_eq!(data, b"cycle test");
        store.delete(&hash).unwrap();
        assert!(!store.exists(&hash).unwrap());
        assert!(store.read(&hash).is_err());
    }

    #[test]
    fn double_delete_fails() {
        let (_dir, store) = make_store();
        let hash = store.write(b"delete twice").unwrap();
        store.delete(&hash).unwrap();
        let err = store.delete(&hash).unwrap_err();
        assert!(matches!(err, BlobError::NotFound { .. }));
    }

    #[test]
    fn different_shards_for_different_content() {
        let (_dir, store) = make_store();
        let h1 = store.write(b"content alpha").unwrap();
        let h2 = store.write(b"content beta").unwrap();
        let hex1 = h1.to_string();
        let hex2 = h2.to_string();
        // Different content should (almost certainly) have different shard prefixes
        // or at minimum different hashes
        assert_ne!(hex1, hex2);
    }

    #[test]
    fn shard_directory_is_two_char_prefix() {
        let (_dir, store) = make_store();
        let hash = store.write(b"shard check").unwrap();
        let hex = hash.to_string();
        let shard = &hex[..2];
        let shard_dir = store.root().join(shard);
        assert!(shard_dir.is_dir());
        let blob_name = &hex[2..];
        let blob_path = shard_dir.join(blob_name);
        assert!(blob_path.is_file());
    }

    #[test]
    fn hash_verification_on_read() {
        let (_dir, store) = make_store();
        let data = b"verify me";
        let hash = store.write(data).unwrap();
        let retrieved = store.read(&hash).unwrap();
        let recomputed = digest(&retrieved);
        assert_eq!(hash, recomputed);
    }

    #[test]
    fn concurrent_writes_same_content() {
        let (_dir, store) = make_store();
        let store = std::sync::Arc::new(store);
        let mut handles = Vec::new();
        let data = b"concurrent content";

        for _ in 0..10 {
            let s = std::sync::Arc::clone(&store);
            handles.push(std::thread::spawn(move || s.write(data)));
        }

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        // At least one write must succeed
        let successes: Vec<Hash256> = results.into_iter().filter_map(|r| r.ok()).collect();
        assert!(!successes.is_empty(), "at least one concurrent write must succeed");

        // All successful writes should produce the same hash
        let first = successes[0];
        for h in &successes {
            assert_eq!(*h, first);
        }

        // Content should be readable
        let retrieved = store.read(&first).unwrap();
        assert_eq!(retrieved.as_slice(), data);
    }

    #[test]
    fn concurrent_writes_different_content() {
        let (_dir, store) = make_store();
        let store = std::sync::Arc::new(store);
        let mut handles = Vec::new();

        for i in 0..10u8 {
            let s = std::sync::Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                let data = vec![i; 100];
                let hash = s.write(&data).unwrap();
                (hash, data)
            }));
        }

        let results: Vec<(Hash256, Vec<u8>)> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();

        for (hash, data) in &results {
            let retrieved = store.read(hash).unwrap();
            assert_eq!(&retrieved, data);
        }
    }

    #[test]
    fn multiple_distinct_blobs_coexist() {
        let (_dir, store) = make_store();
        let mut hashes = Vec::new();
        for i in 0..50 {
            let data = format!("blob number {i}");
            let hash = store.write(data.as_bytes()).unwrap();
            hashes.push((hash, data));
        }
        for (hash, expected) in &hashes {
            let retrieved = store.read(hash).unwrap();
            assert_eq!(retrieved, expected.as_bytes());
        }
    }

    #[test]
    fn idempotent_write_returns_same_hash() {
        let (_dir, store) = make_store();
        let data = b"idempotent";
        let h1 = store.write(data).unwrap();
        let h2 = store.write(data).unwrap();
        let h3 = store.write(data).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);
    }

    #[test]
    fn exists_after_delete_returns_false() {
        let (_dir, store) = make_store();
        let hash = store.write(b"temp").unwrap();
        assert!(store.exists(&hash).unwrap());
        store.delete(&hash).unwrap();
        assert!(!store.exists(&hash).unwrap());
    }

    #[test]
    fn read_after_rewrite_succeeds() {
        let (_dir, store) = make_store();
        let data = b"rewrite";
        let hash = store.write(data).unwrap();
        store.delete(&hash).unwrap();
        let hash2 = store.write(data).unwrap();
        assert_eq!(hash, hash2);
        let retrieved = store.read(&hash2).unwrap();
        assert_eq!(retrieved.as_slice(), data);
    }

    #[test]
    fn whitespace_only_content() {
        let (_dir, store) = make_store();
        let data = b"   \n\t\r\n   ";
        let hash = store.write(data).unwrap();
        let retrieved = store.read(&hash).unwrap();
        assert_eq!(retrieved, data);
    }

    #[test]
    fn null_bytes_content() {
        let (_dir, store) = make_store();
        let data = vec![0u8; 1024];
        let hash = store.write(&data).unwrap();
        let retrieved = store.read(&hash).unwrap();
        assert_eq!(retrieved, data);
    }
}
