// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Federated graph payloads for connected KinLab collaboration.
//!
//! These types layer global addressing and org-level coordination over the
//! existing local-only sync payloads in `sync_types`.

use crate::sync_types::{
    ChangeType, ChannelEvent, FieldDiff, IntentLock, InvalidationEvent, LocalMutation, LockType,
    PushConflict, SemanticDelta,
};
use chrono::{DateTime, Utc};
use kin_model::{ActorRef, GraphLocator, Hash256, ScopeRef, SemanticChangeId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Cursor for subscribed graph deltas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaCursor {
    pub graph: GraphLocator,
    pub sequence: u64,
    pub head_change: Option<SemanticChangeId>,
}

impl DeltaCursor {
    pub fn new(graph: GraphLocator, sequence: u64, head_change: Option<SemanticChangeId>) -> Self {
        Self {
            graph,
            sequence,
            head_change,
        }
    }

    pub fn advance(&self, sequence: u64, head_change: Option<SemanticChangeId>) -> Self {
        Self {
            graph: self.graph.clone(),
            sequence,
            head_change,
        }
    }
}

fn parse_hash(hash: &str) -> Hash256 {
    Hash256::from_hex(hash).expect("federated payload requires 64-character hex hashes")
}

/// Federated invalidation event carrying a global scope reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedInvalidationEvent {
    pub scope: ScopeRef,
    pub change_type: ChangeType,
    pub timestamp: DateTime<Utc>,
    pub actor: ActorRef,
    pub cursor: Option<DeltaCursor>,
}

impl FederatedInvalidationEvent {
    pub fn from_local(
        scope: ScopeRef,
        event: &InvalidationEvent,
        cursor: Option<DeltaCursor>,
    ) -> Self {
        Self {
            actor: ActorRef::new(scope.graph().authority.clone(), event.actor_id.clone()),
            scope,
            change_type: event.change_type.clone(),
            timestamp: event.timestamp,
            cursor,
        }
    }
}

/// Federated intent lock carrying a global scope reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedIntentLock {
    pub scope: ScopeRef,
    pub holder: ActorRef,
    pub lock_type: LockType,
    pub acquired_at: DateTime<Utc>,
    pub ttl_seconds: u64,
    pub lease_id: Option<String>,
}

impl FederatedIntentLock {
    pub fn from_local(scope: ScopeRef, lock: &IntentLock) -> Self {
        Self {
            holder: ActorRef::new(
                scope.graph().authority.clone(),
                lock.holder_actor_id.clone(),
            ),
            scope,
            lock_type: lock.lock_type,
            acquired_at: lock.acquired_at,
            ttl_seconds: lock.ttl_seconds,
            lease_id: None,
        }
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        let elapsed = now.signed_duration_since(self.acquired_at);
        elapsed.num_seconds() as u64 >= self.ttl_seconds
    }
}

/// Federated semantic delta carrying a global scope reference and cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedSemanticDelta {
    pub scope: ScopeRef,
    pub before_hash: Option<Hash256>,
    pub after_hash: Hash256,
    pub change_set: Vec<FieldDiff>,
    pub timestamp: DateTime<Utc>,
    pub actor: ActorRef,
    pub cursor: DeltaCursor,
}

impl FederatedSemanticDelta {
    pub fn from_local(scope: ScopeRef, delta: &SemanticDelta, cursor: DeltaCursor) -> Self {
        Self {
            actor: ActorRef::new(scope.graph().authority.clone(), delta.actor_id.clone()),
            scope,
            before_hash: delta.before_hash.as_deref().map(parse_hash),
            after_hash: parse_hash(&delta.after_hash),
            change_set: delta.change_set.clone(),
            timestamp: delta.timestamp,
            cursor,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedSyncState {
    pub cursor: Option<DeltaCursor>,
    pub pending_pushes: u64,
    pub pending_pulls: u64,
}

/// Federated local mutation sent back to KinLab.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedLocalMutation {
    pub scope: ScopeRef,
    pub mutation_id: Uuid,
    pub change_set: Vec<FieldDiff>,
    pub base_hash: Option<Hash256>,
    pub new_hash: Hash256,
    pub timestamp: DateTime<Utc>,
    pub actor: ActorRef,
}

impl FederatedLocalMutation {
    pub fn from_local(scope: ScopeRef, mutation: &LocalMutation) -> Self {
        Self {
            actor: ActorRef::new(scope.graph().authority.clone(), "local"),
            scope,
            mutation_id: mutation.mutation_id,
            change_set: mutation.change_set.clone(),
            base_hash: mutation.base_hash.as_deref().map(parse_hash),
            new_hash: parse_hash(&mutation.new_hash),
            timestamp: mutation.timestamp,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederatedPushConflict {
    pub scope: ScopeRef,
    pub local_hash: Hash256,
    pub remote_hash: Hash256,
    pub remote_actor: ActorRef,
}

impl FederatedPushConflict {
    pub fn from_local(scope: ScopeRef, conflict: &PushConflict) -> Self {
        Self {
            remote_actor: ActorRef::new(scope.graph().authority.clone(), &conflict.remote_actor_id),
            scope,
            local_hash: parse_hash(&conflict.local_hash),
            remote_hash: parse_hash(&conflict.remote_hash),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FederatedPushResult {
    Accepted {
        cursor: DeltaCursor,
        accepted_count: usize,
    },
    Conflict {
        conflicts: Vec<FederatedPushConflict>,
        accepted_count: usize,
        cursor: Option<DeltaCursor>,
    },
    Rejected {
        reason: String,
        cursor: Option<DeltaCursor>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FederatedChannelEvent {
    ScopeInvalidated(FederatedInvalidationEvent),
    IntentLockAcquired(FederatedIntentLock),
    IntentLockReleased { scope: ScopeRef, holder: ActorRef },
    CursorAdvanced(DeltaCursor),
}

impl FederatedChannelEvent {
    pub fn from_local(
        scope: ScopeRef,
        event: &ChannelEvent,
        cursor: Option<DeltaCursor>,
    ) -> Option<Self> {
        match event {
            ChannelEvent::EntityInvalidated(invalidation)
            | ChannelEvent::RelationInvalidated(invalidation) => Some(Self::ScopeInvalidated(
                FederatedInvalidationEvent::from_local(scope, invalidation, cursor),
            )),
            ChannelEvent::IntentLockAcquired(lock) => Some(Self::IntentLockAcquired(
                FederatedIntentLock::from_local(scope, lock),
            )),
            ChannelEvent::IntentLockReleased {
                holder_actor_id, ..
            } => Some(Self::IntentLockReleased {
                holder: ActorRef::new(scope.graph().authority.clone(), holder_actor_id),
                scope,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync_types::{ChangeType, InvalidationEvent, LockType, PushConflict, SemanticDelta};
    use chrono::Utc;
    use kin_model::{ContractId, EntityId, FilePathId, WorkId};

    fn graph() -> GraphLocator {
        GraphLocator::new("https://kinlab.example.com", "kin-open-core", "kin")
    }

    #[test]
    fn federated_invalidations_attach_graph_identity() {
        let scope = ScopeRef::Entity {
            graph: graph(),
            entity_id: EntityId::new(),
        };
        let local = InvalidationEvent {
            entity_id: "entity:123".into(),
            change_type: ChangeType::Modified,
            timestamp: Utc::now(),
            actor_id: "agent-1".into(),
        };

        let federated = FederatedInvalidationEvent::from_local(scope.clone(), &local, None);
        assert_eq!(federated.scope, scope);
        assert_eq!(federated.change_type, ChangeType::Modified);
        assert_eq!(federated.actor.actor_id, "agent-1");
        assert_eq!(federated.actor.authority, graph().authority);
    }

    #[test]
    fn federated_deltas_roundtrip() {
        let scope = ScopeRef::Work {
            graph: graph(),
            work_id: WorkId::new(),
        };
        let delta = SemanticDelta {
            entity_id: "entity:123".into(),
            before_hash: Some(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".into(),
            ),
            after_hash: "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100".into(),
            change_set: vec![FieldDiff {
                field: "name".into(),
                old_value: Some("old".into()),
                new_value: Some("new".into()),
            }],
            timestamp: Utc::now(),
            actor_id: "agent-1".into(),
        };
        let cursor = DeltaCursor::new(graph(), 7, None);

        let federated = FederatedSemanticDelta::from_local(scope, &delta, cursor.clone());
        let json = serde_json::to_string(&federated).unwrap();
        let parsed: FederatedSemanticDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cursor, cursor);
        assert_eq!(parsed.change_set.len(), 1);
        assert_eq!(parsed.actor.actor_id, "agent-1");
        assert_eq!(
            parsed.after_hash,
            Hash256::from_hex("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
                .unwrap()
        );
    }

    #[test]
    fn federated_mutation_roundtrip() {
        let scope = ScopeRef::Artifact {
            graph: graph(),
            path: FilePathId::new("src/lib.rs"),
        };
        let mutation = LocalMutation {
            entity_id: "artifact:1".into(),
            mutation_id: Uuid::new_v4(),
            change_set: vec![FieldDiff {
                field: "body".into(),
                old_value: Some("old".into()),
                new_value: Some("new".into()),
            }],
            base_hash: Some(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".into(),
            ),
            new_hash: "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100".into(),
            timestamp: Utc::now(),
        };

        let federated = FederatedLocalMutation::from_local(scope, &mutation);
        let json = serde_json::to_string(&federated).unwrap();
        let parsed: FederatedLocalMutation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.change_set.len(), 1);
        assert_eq!(parsed.mutation_id, mutation.mutation_id);
        assert_eq!(
            parsed.new_hash,
            Hash256::from_hex("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
                .unwrap()
        );
    }

    #[test]
    fn federated_intent_lock_roundtrip() {
        let scope = ScopeRef::Contract {
            graph: graph(),
            contract_id: ContractId::new(),
        };
        let local = IntentLock {
            entity_id: "contract:1".into(),
            holder_actor_id: "agent-2".into(),
            lock_type: LockType::Exclusive,
            acquired_at: Utc::now(),
            ttl_seconds: 30,
        };

        let federated = FederatedIntentLock::from_local(scope.clone(), &local);
        let json = serde_json::to_string(&federated).unwrap();
        let parsed: FederatedIntentLock = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.scope, scope);
        assert_eq!(parsed.lock_type, LockType::Exclusive);
        assert_eq!(parsed.holder.actor_id, "agent-2");
        assert!(!parsed.is_expired(parsed.acquired_at));
    }

    #[test]
    fn federated_push_conflict_roundtrip() {
        let scope = ScopeRef::Entity {
            graph: graph(),
            entity_id: EntityId::new(),
        };
        let conflict = PushConflict {
            entity_id: "entity:123".into(),
            local_hash: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".into(),
            remote_hash: "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100".into(),
            remote_actor_id: "agent-3".into(),
        };

        let federated = FederatedPushConflict::from_local(scope.clone(), &conflict);
        let json = serde_json::to_string(&federated).unwrap();
        let parsed: FederatedPushConflict = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.scope, scope);
        assert_eq!(parsed.remote_actor.actor_id, "agent-3");
    }

    #[test]
    fn federated_channel_event_roundtrip() {
        let event = FederatedChannelEvent::CursorAdvanced(DeltaCursor::new(graph(), 3, None));
        let json = serde_json::to_string(&event).unwrap();
        let parsed: FederatedChannelEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, event);
    }
}
