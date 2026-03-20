// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Protocol types for the hybrid event-driven pull sync architecture.
//!
//! KinLab pushes lightweight invalidation events and intent locks over a channel.
//! The local daemon pulls actual semantic deltas via REST/gRPC when materializing.
//! Local mutations are pushed to remote on commit.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Invalidation events (pushed from KinLab → local daemon)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeType {
    Created,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidationEvent {
    pub entity_id: String,
    pub change_type: ChangeType,
    pub timestamp: DateTime<Utc>,
    pub actor_id: String,
}

// ---------------------------------------------------------------------------
// Intent locks (pushed from KinLab → local daemon)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockType {
    Exclusive,
    Shared,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentLock {
    pub entity_id: String,
    pub holder_actor_id: String,
    pub lock_type: LockType,
    pub acquired_at: DateTime<Utc>,
    pub ttl_seconds: u64,
}

impl IntentLock {
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        let elapsed = now.signed_duration_since(self.acquired_at);
        elapsed.num_seconds() as u64 >= self.ttl_seconds
    }
}

// ---------------------------------------------------------------------------
// Semantic deltas (pulled by local daemon from KinLab)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDiff {
    pub field: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticDelta {
    pub entity_id: String,
    pub before_hash: Option<String>,
    pub after_hash: String,
    pub change_set: Vec<FieldDiff>,
    pub timestamp: DateTime<Utc>,
    pub actor_id: String,
}

// ---------------------------------------------------------------------------
// Sync state tracking
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncState {
    pub last_synced_at: Option<DateTime<Utc>>,
    pub local_head_hash: Option<String>,
    pub remote_head_hash: Option<String>,
    pub pending_pushes: u64,
    pub pending_pulls: u64,
}

// ---------------------------------------------------------------------------
// Local mutations (pushed from local daemon → KinLab)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalMutation {
    pub entity_id: String,
    pub mutation_id: Uuid,
    pub change_set: Vec<FieldDiff>,
    pub base_hash: Option<String>,
    pub new_hash: String,
    pub timestamp: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Push results
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushConflict {
    pub entity_id: String,
    pub local_hash: String,
    pub remote_hash: String,
    pub remote_actor_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PushResult {
    Accepted {
        new_remote_head: String,
        accepted_count: usize,
    },
    Conflict {
        conflicts: Vec<PushConflict>,
        accepted_count: usize,
    },
    Rejected {
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Invalidation channel event envelope
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelEvent {
    EntityInvalidated(InvalidationEvent),
    RelationInvalidated(InvalidationEvent),
    IntentLockAcquired(IntentLock),
    IntentLockReleased {
        entity_id: String,
        holder_actor_id: String,
    },
}

// ---------------------------------------------------------------------------
// Connection state machine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Syncing,
    Idle,
}

// ---------------------------------------------------------------------------
// Stale entity tracker
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct StaleTracker {
    stale: HashMap<String, InvalidationEvent>,
}

impl StaleTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_stale(&mut self, event: InvalidationEvent) {
        self.stale.insert(event.entity_id.clone(), event);
    }

    pub fn mark_fresh(&mut self, entity_id: &str) {
        self.stale.remove(entity_id);
    }

    pub fn is_stale(&self, entity_id: &str) -> bool {
        self.stale.contains_key(entity_id)
    }

    pub fn stale_entity_ids(&self) -> Vec<String> {
        self.stale.keys().cloned().collect()
    }

    pub fn stale_count(&self) -> usize {
        self.stale.len()
    }
}
