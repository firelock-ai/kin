// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;

use crate::stat::VirtualStat;

#[derive(Debug, Clone)]
pub(crate) enum CachedEntry {
    Stat(VirtualStat),
    Content { stat: VirtualStat, data: Vec<u8> },
}

pub(crate) struct VfsCache {
    entries: Mutex<LruCache<String, CachedEntry>>,
    version: std::sync::atomic::AtomicU64,
}

impl VfsCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            entries: Mutex::new(LruCache::new(cap)),
            version: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn get(&self, path: &str) -> Option<CachedEntry> {
        self.entries.lock().get(path).cloned()
    }

    pub fn put(&self, path: String, entry: CachedEntry) {
        self.entries.lock().put(path, entry);
    }

    pub fn invalidate(&self, paths: &[String]) {
        let mut cache = self.entries.lock();
        for path in paths {
            cache.pop(path);
        }
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn invalidate_all(&self) {
        self.entries.lock().clear();
        self.version
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn version(&self) -> u64 {
        self.version.load(std::sync::atomic::Ordering::Relaxed)
    }
}
