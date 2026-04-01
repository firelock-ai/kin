// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Diff and commit construction helpers.
//!
//! Shared utilities for building semantic changes, computing change IDs,
//! and resolving author identity.

use kin_model::{Hash256, SemanticChangeId};
use sha2::{Digest, Sha256};

/// Compute a unique change ID from message + parent + timestamp.
///
/// Not deterministic — the timestamp ensures each commit gets a unique ID
/// even with the same message and parent.
pub fn compute_change_id(message: &str, parent: &SemanticChangeId) -> SemanticChangeId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-change-v1:");
    hasher.update(message.as_bytes());
    hasher.update(b":");
    hasher.update(parent.0.as_bytes());
    hasher.update(b":");
    hasher.update(chrono::Utc::now().to_rfc3339().as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    SemanticChangeId::from_hash(Hash256::from_bytes(bytes))
}

/// Get a human-readable author name from environment variables.
///
/// Checks `USER` (Unix) then `USERNAME` (Windows), falls back to `"unknown"`.
pub fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_change_id_produces_unique_ids() {
        let parent = SemanticChangeId::from_hash(Hash256::from_bytes([0xaa; 32]));
        let id1 = compute_change_id("test", &parent);
        // Tiny sleep to ensure different timestamps
        std::thread::sleep(std::time::Duration::from_millis(2));
        let id2 = compute_change_id("test", &parent);
        assert_ne!(id1, id2);
    }

    #[test]
    fn whoami_returns_nonempty_string() {
        let name = whoami();
        assert!(!name.is_empty());
    }
}
