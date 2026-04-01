// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Persisted sync state per remote, stored in `.kin/sync_state.json`.
//!
//! Tracks the last successful sync point for each remote so that subsequent
//! pulls can request only the delta (changes since last sync) rather than
//! a full snapshot transfer.

use crate::layout::KinLayout;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Sync state for a single remote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteSyncState {
    /// Timestamp of the last successful sync.
    pub last_synced_at: DateTime<Utc>,
    /// The remote semantic head hash at the time of last sync.
    pub remote_head: String,
    /// The local semantic head hash at the time of last sync.
    pub local_head: String,
}

/// All sync states keyed by remote name.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncStateStore {
    /// Sync state per remote name (e.g. "origin").
    pub remotes: HashMap<String, RemoteSyncState>,
}

impl SyncStateStore {
    /// Load from `.kin/sync_state.json`. Returns default (empty) if the file
    /// doesn't exist or is unreadable.
    pub fn load(layout: &KinLayout) -> Self {
        let path = layout.sync_state_path();
        match std::fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Persist to `.kin/sync_state.json`.
    pub fn save(&self, layout: &KinLayout) -> crate::Result<()> {
        let path = layout.sync_state_path();
        let json = serde_json::to_string_pretty(self).map_err(|e| {
            crate::KinError::io(&path, std::io::Error::new(std::io::ErrorKind::Other, e))
        })?;
        std::fs::write(&path, json).map_err(|e| crate::KinError::io(&path, e))
    }

    /// Get the sync state for a remote, if any.
    pub fn get(&self, remote_name: &str) -> Option<&RemoteSyncState> {
        self.remotes.get(remote_name)
    }

    /// Record a successful sync for a remote.
    pub fn record_sync(&mut self, remote_name: &str, remote_head: &str, local_head: &str) {
        self.remotes.insert(
            remote_name.to_string(),
            RemoteSyncState {
                last_synced_at: Utc::now(),
                remote_head: remote_head.to_string(),
                local_head: local_head.to_string(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_state_store_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let mut store = SyncStateStore::default();
        store.record_sync("origin", "remote-head-abc", "local-head-def");

        store.save(&layout).unwrap();

        let loaded = SyncStateStore::load(&layout);
        assert_eq!(loaded.remotes.len(), 1);
        let state = loaded.get("origin").unwrap();
        assert_eq!(state.remote_head, "remote-head-abc");
        assert_eq!(state.local_head, "local-head-def");
    }

    #[test]
    fn sync_state_store_missing_file_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);

        let loaded = SyncStateStore::load(&layout);
        assert!(loaded.remotes.is_empty());
    }

    #[test]
    fn record_sync_overwrites_previous() {
        let mut store = SyncStateStore::default();
        store.record_sync("origin", "head-1", "local-1");
        store.record_sync("origin", "head-2", "local-2");

        let state = store.get("origin").unwrap();
        assert_eq!(state.remote_head, "head-2");
        assert_eq!(state.local_head, "local-2");
    }
}
