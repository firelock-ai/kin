// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cache for LSP enrichment results, keyed by file content hash.
//!
//! When a file hasn't changed (same content hash), we reuse the cached
//! enrichment results instead of re-querying the LSP server.

use std::collections::HashMap;
use std::path::PathBuf;

use kin_model::Hash256;

use crate::enrichment::EnrichmentResult;

/// In-memory cache for LSP enrichment results.
#[derive(Debug, Default)]
pub struct EnrichmentCache {
    /// Map from file content hash to cached enrichment.
    entries: HashMap<Hash256, CachedEnrichment>,
}

#[derive(Debug)]
struct CachedEnrichment {
    _file_path: PathBuf,
    result: EnrichmentResult,
}

impl EnrichmentCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if we have a cached result for a file with the given content hash.
    pub fn get(&self, content_hash: &Hash256) -> Option<&EnrichmentResult> {
        self.entries.get(content_hash).map(|e| &e.result)
    }

    /// Store an enrichment result for a file.
    pub fn insert(&mut self, content_hash: Hash256, file_path: PathBuf, result: EnrichmentResult) {
        self.entries.insert(
            content_hash,
            CachedEnrichment { _file_path: file_path, result },
        );
    }

    /// Invalidate the cache entry for a specific file hash.
    pub fn invalidate(&mut self, content_hash: &Hash256) {
        self.entries.remove(content_hash);
    }

    /// Clear the entire cache.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_insert_and_retrieve() {
        let mut cache = EnrichmentCache::new();
        let hash = Hash256::from_bytes([1; 32]);
        let result = EnrichmentResult::default();
        cache.insert(hash, PathBuf::from("test.rs"), result);

        assert_eq!(cache.len(), 1);
        assert!(cache.get(&hash).is_some());
        assert!(cache.get(&Hash256::from_bytes([2; 32])).is_none());
    }

    #[test]
    fn cache_invalidate() {
        let mut cache = EnrichmentCache::new();
        let hash = Hash256::from_bytes([1; 32]);
        cache.insert(hash, PathBuf::from("test.rs"), EnrichmentResult::default());
        cache.invalidate(&hash);
        assert!(cache.is_empty());
    }
}
