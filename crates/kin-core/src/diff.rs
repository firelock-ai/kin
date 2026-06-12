// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Diff and commit construction helpers.
//!
//! Shared utilities for building semantic changes, computing change IDs,
//! and resolving author identity.

use kin_model::{ArtifactDelta, EntityDelta, Hash256, RelationDelta, SemanticChangeId};
use sha2::{Digest, Sha256};

/// Compute a content-addressed change ID from message + parent + content identity.
///
/// Deterministic: identical inputs always produce the same ID.  Wall-clock time
/// must NOT be mixed into the hash — use `content_identity_from_deltas` to derive
/// a stable content fingerprint and pass it as `content_identity`.
pub fn compute_change_id(
    message: &str,
    parent: &SemanticChangeId,
    content_identity: &[u8],
) -> SemanticChangeId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-change-v2:");
    hasher.update(message.as_bytes());
    hasher.update(b":");
    hasher.update(parent.0.as_bytes());
    hasher.update(b":");
    hasher.update(content_identity);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    SemanticChangeId::from_hash(Hash256::from_bytes(bytes))
}

/// Derive a deterministic content fingerprint from the three delta slices.
///
/// IDs within each slice are sorted before hashing so insertion order does not
/// affect the result.  Two preps of the same logical tree will produce the same
/// fingerprint; a different tree (different entity/relation/artifact set) will
/// produce a different one.
pub fn content_identity_from_deltas(
    entity_deltas: &[EntityDelta],
    relation_deltas: &[RelationDelta],
    artifact_deltas: &[ArtifactDelta],
) -> [u8; 32] {
    // EntityIds are content-addressed UUIDs — sort their 16-byte representations.
    let mut entity_ids: Vec<[u8; 16]> = entity_deltas
        .iter()
        .map(|d| match d {
            EntityDelta::Added(e) => *e.id.0.as_bytes(),
            EntityDelta::Modified { new, .. } => *new.id.0.as_bytes(),
            EntityDelta::Removed(id) => *id.0.as_bytes(),
        })
        .collect();
    entity_ids.sort_unstable();

    // RelationIds are also content-addressed UUIDs.
    let mut relation_ids: Vec<[u8; 16]> = relation_deltas
        .iter()
        .map(|d| match d {
            RelationDelta::Added(r) => *r.id.0.as_bytes(),
            RelationDelta::Removed(id) => *id.0.as_bytes(),
        })
        .collect();
    relation_ids.sort_unstable();

    // Artifact key = file-path bytes + NUL separator + new-hash bytes (if present).
    // Fixed-length hash after the separator prevents ambiguity.
    let mut artifact_keys: Vec<Vec<u8>> = artifact_deltas
        .iter()
        .map(|d| {
            let mut k = Vec::new();
            k.extend_from_slice(d.file_id.0.as_bytes());
            k.push(0u8);
            if let Some(h) = d.new_hash {
                k.extend_from_slice(h.as_bytes());
            }
            k
        })
        .collect();
    artifact_keys.sort_unstable();

    let mut hasher = Sha256::new();
    hasher.update(b"kin-content-v1:");
    for id in &entity_ids {
        hasher.update(id);
    }
    hasher.update(b"|");
    for id in &relation_ids {
        hasher.update(id);
    }
    hasher.update(b"|");
    for key in &artifact_keys {
        hasher.update(key);
        hasher.update(b"\x00");
    }
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
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
    fn compute_change_id_is_deterministic() {
        let parent = SemanticChangeId::from_hash(Hash256::from_bytes([0xaa; 32]));
        let content = [0u8; 32];
        let id1 = compute_change_id("test", &parent, &content);
        let id2 = compute_change_id("test", &parent, &content);
        assert_eq!(id1, id2);
    }

    #[test]
    fn compute_change_id_differs_on_content() {
        let parent = SemanticChangeId::from_hash(Hash256::from_bytes([0xaa; 32]));
        let id1 = compute_change_id("test", &parent, &[0u8; 32]);
        let id2 = compute_change_id("test", &parent, &[1u8; 32]);
        assert_ne!(id1, id2);
    }

    #[test]
    fn compute_change_id_differs_on_message() {
        let parent = SemanticChangeId::from_hash(Hash256::from_bytes([0xaa; 32]));
        let content = [0u8; 32];
        let id1 = compute_change_id("foo", &parent, &content);
        let id2 = compute_change_id("bar", &parent, &content);
        assert_ne!(id1, id2);
    }

    #[test]
    fn compute_change_id_differs_on_parent() {
        let parent1 = SemanticChangeId::from_hash(Hash256::from_bytes([0xaa; 32]));
        let parent2 = SemanticChangeId::from_hash(Hash256::from_bytes([0xbb; 32]));
        let content = [0u8; 32];
        let id1 = compute_change_id("test", &parent1, &content);
        let id2 = compute_change_id("test", &parent2, &content);
        assert_ne!(id1, id2);
    }

    #[test]
    fn content_identity_empty_deltas_is_deterministic() {
        let h1 = content_identity_from_deltas(&[], &[], &[]);
        let h2 = content_identity_from_deltas(&[], &[], &[]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn whoami_returns_nonempty_string() {
        let name = whoami();
        assert!(!name.is_empty());
    }
}
