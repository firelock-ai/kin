// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Mutation push mechanism: sends local changes to the remote on commit.
//!
//! The `MutationPusher` trait defines the interface. Implementations perform
//! conflict detection via optimistic locking: if the remote has diverged since
//! the local base hash, a `PushConflict` is returned instead of blindly
//! overwriting.

use crate::sync_types::{IntentLock, LocalMutation, LockType, PushConflict, PushResult};
use std::collections::HashMap;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum MutationPushError {
    #[error("remote unavailable: {0}")]
    RemoteUnavailable(String),
    #[error("intent lock held by {holder} on entity {entity_id}")]
    IntentLockHeld { entity_id: String, holder: String },
    #[error("protocol error: {0}")]
    Protocol(String),
}

// ---------------------------------------------------------------------------
// MutationPusher trait
// ---------------------------------------------------------------------------

/// Trait for pushing local mutations to a remote.
pub trait MutationPusher: Send + Sync {
    /// Push a batch of local mutations to the remote.
    /// Returns `PushResult::Conflict` if the remote has diverged.
    fn push_mutations(&self, mutations: &[LocalMutation]) -> Result<PushResult, MutationPushError>;
}

// ---------------------------------------------------------------------------
// In-memory implementation (for testing)
// ---------------------------------------------------------------------------

/// Simulates a remote that tracks entity hashes and intent locks.
#[derive(Debug)]
pub struct InMemoryMutationPusher {
    /// Current hash for each entity on the "remote".
    remote_hashes: HashMap<String, String>,
    /// Active intent locks on the "remote".
    intent_locks: HashMap<String, IntentLock>,
}

impl InMemoryMutationPusher {
    pub fn new() -> Self {
        Self {
            remote_hashes: HashMap::new(),
            intent_locks: HashMap::new(),
        }
    }

    /// Seed a remote entity hash for testing.
    pub fn set_remote_hash(&mut self, entity_id: &str, hash: &str) {
        self.remote_hashes
            .insert(entity_id.to_owned(), hash.to_owned());
    }

    /// Acquire an intent lock on an entity.
    pub fn acquire_lock(&mut self, lock: IntentLock) {
        self.intent_locks.insert(lock.entity_id.clone(), lock);
    }

    /// Release an intent lock.
    pub fn release_lock(&mut self, entity_id: &str) {
        self.intent_locks.remove(entity_id);
    }

    pub fn get_remote_hash(&self, entity_id: &str) -> Option<&str> {
        self.remote_hashes.get(entity_id).map(|s| s.as_str())
    }
}

impl Default for InMemoryMutationPusher {
    fn default() -> Self {
        Self::new()
    }
}

impl MutationPusher for InMemoryMutationPusher {
    fn push_mutations(&self, mutations: &[LocalMutation]) -> Result<PushResult, MutationPushError> {
        let mut conflicts = Vec::new();
        let mut accepted = 0usize;

        for mutation in mutations {
            // Check intent locks: if an exclusive lock is held by someone else,
            // reject this mutation.
            if let Some(lock) = self.intent_locks.get(&mutation.entity_id) {
                if lock.lock_type == LockType::Exclusive && lock.holder_actor_id != "local" {
                    return Err(MutationPushError::IntentLockHeld {
                        entity_id: mutation.entity_id.clone(),
                        holder: lock.holder_actor_id.clone(),
                    });
                }
            }

            // Optimistic locking: check that the remote hash matches the mutation's base hash.
            if let Some(remote_hash) = self.remote_hashes.get(&mutation.entity_id) {
                let base = mutation.base_hash.as_deref().unwrap_or("");
                if remote_hash != base {
                    conflicts.push(PushConflict {
                        entity_id: mutation.entity_id.clone(),
                        local_hash: mutation.new_hash.clone(),
                        remote_hash: remote_hash.clone(),
                        remote_actor_id: "remote".to_owned(),
                    });
                    continue;
                }
            }

            accepted += 1;
        }

        if conflicts.is_empty() {
            Ok(PushResult::Accepted {
                new_remote_head: mutations
                    .last()
                    .map(|m| m.new_hash.clone())
                    .unwrap_or_default(),
                accepted_count: accepted,
            })
        } else {
            Ok(PushResult::Conflict {
                conflicts,
                accepted_count: accepted,
            })
        }
    }
}
