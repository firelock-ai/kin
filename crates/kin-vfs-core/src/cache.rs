// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;

use crate::path::VfsPath;
use crate::stat::VirtualStat;

#[derive(Debug, Clone)]
pub(crate) enum CachedEntry {
    Stat(VirtualStat),
    Content { stat: VirtualStat, data: Vec<u8> },
}

#[derive(Debug, Clone)]
struct VersionedEntry {
    provider_version: u64,
    value: CachedEntry,
}

/// LRU cache keyed by byte-exact [`VfsPath`] identity.
pub(crate) struct VfsCache {
    entries: Mutex<LruCache<VfsPath, VersionedEntry>>,
}

impl VfsCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            entries: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Return an entry only when it belongs to the provider's current
    /// monotonic snapshot version. A late writer from an older snapshot may
    /// remain in the LRU, but can never be observed under a newer version.
    pub fn get(&self, path: &VfsPath, provider_version: u64) -> Option<CachedEntry> {
        let mut entries = self.entries.lock();
        match entries.get(path).cloned() {
            Some(entry) if entry.provider_version == provider_version => Some(entry.value),
            Some(_) => {
                entries.pop(path);
                None
            }
            None => None,
        }
    }

    pub fn put(&self, path: VfsPath, provider_version: u64, value: CachedEntry) {
        self.entries.lock().put(
            path,
            VersionedEntry {
                provider_version,
                value,
            },
        );
    }

    pub fn invalidate(&self, paths: &[VfsPath]) {
        let mut cache = self.entries.lock();
        for path in paths {
            cache.pop(path);
        }
    }

    pub fn invalidate_all(&self) {
        self.entries.lock().clear();
    }
}
