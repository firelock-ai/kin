// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

mod error;

pub use error::BlobError;

use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::debug;

pub type Result<T> = std::result::Result<T, BlobError>;

/// A SHA-256 hash represented as 32 bytes.
///
/// This is a local type; once `kin-model` is wired up, we can re-export from there.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    /// Compute the SHA-256 hash of the given data.
    pub fn digest(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Return the hex-encoded string of this hash.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse a hex string into a Hash256.
    pub fn from_hex(s: &str) -> std::result::Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        let mut arr = [0u8; 32];
        if bytes.len() != 32 {
            // hex::decode won't error on wrong length, so we handle it
            return Err(hex::FromHexError::InvalidStringLength);
        }
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", self.to_hex())
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
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
        let hash = Hash256::digest(data);
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
        let temp_path = shard_dir.join(format!(".tmp-{}", hash));
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
                    hash: hash.to_hex(),
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
                    hash: hash.to_hex(),
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
        let hex = hash.to_hex();
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
        let hex = hash.to_hex();

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
        let hash = Hash256::digest(b"test data");
        let hex = hash.to_hex();
        let parsed = Hash256::from_hex(&hex).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn hash256_display() {
        let hash = Hash256::digest(b"display test");
        let display = format!("{hash}");
        assert_eq!(display.len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(display, hash.to_hex());
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
}
