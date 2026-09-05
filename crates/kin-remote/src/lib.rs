// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod connection;
pub mod delta_bridge;
pub mod delta_pull;
pub mod federated;
#[cfg(feature = "http")]
pub mod http_transport;
pub mod invalidation;
pub mod mutation_push;
pub mod repository_transfer;
#[cfg(feature = "http")]
pub mod repository_transfer_http;
pub mod repository_transfer_negotiation;
pub mod sync_types;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    GitHub,
    GitLab,
    Bitbucket,
    KinLab,
    Peer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    GitExport,
    NativeKin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCapabilitySet {
    pub publish_semantic_changes: bool,
    pub publish_review_state: bool,
    pub publish_proofs: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRef {
    pub name: String,
    pub host: HostKind,
    pub transport: TransportKind,
    pub capabilities: RemoteCapabilitySet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoState {
    pub local_head: Option<String>,
    pub remote_head: Option<String>,
    pub approved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushDecision {
    Publish,
    FastForwardRequired,
    ApprovalRequired,
    SemanticStateRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushPlan {
    pub decision: PushDecision,
    pub publish_review_state: bool,
    pub publish_proofs: bool,
}

pub fn plan_push(remote: &RemoteRef, state: &RepoState) -> PushPlan {
    let Some(local_head) = state.local_head.as_deref() else {
        return PushPlan {
            decision: PushDecision::SemanticStateRequired,
            publish_review_state: false,
            publish_proofs: false,
        };
    };

    if !state.approved && remote.capabilities.publish_review_state {
        return PushPlan {
            decision: PushDecision::ApprovalRequired,
            publish_review_state: true,
            publish_proofs: false,
        };
    }

    if matches!(state.remote_head.as_deref(), Some(remote_head) if remote_head != local_head) {
        return PushPlan {
            decision: PushDecision::FastForwardRequired,
            publish_review_state: remote.capabilities.publish_review_state,
            publish_proofs: false,
        };
    }

    PushPlan {
        decision: PushDecision::Publish,
        publish_review_state: remote.capabilities.publish_review_state,
        publish_proofs: remote.capabilities.publish_proofs,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        plan_push, HostKind, PushDecision, RemoteCapabilitySet, RemoteRef, RepoState, TransportKind,
    };

    #[test]
    fn native_kithub_remote_requires_approval_before_publish() {
        let remote = RemoteRef {
            name: "origin".into(),
            host: HostKind::KinLab,
            transport: TransportKind::NativeKin,
            capabilities: RemoteCapabilitySet {
                publish_semantic_changes: true,
                publish_review_state: true,
                publish_proofs: true,
            },
        };

        let plan = plan_push(
            &remote,
            &RepoState {
                local_head: Some("change:abc".into()),
                remote_head: Some("change:abc".into()),
                approved: false,
            },
        );

        assert_eq!(plan.decision, PushDecision::ApprovalRequired);
        assert!(plan.publish_review_state);
        assert!(!plan.publish_proofs);
    }

    #[test]
    fn divergent_remote_requires_fast_forward() {
        let remote = RemoteRef {
            name: "origin".into(),
            host: HostKind::GitHub,
            transport: TransportKind::GitExport,
            capabilities: RemoteCapabilitySet {
                publish_semantic_changes: true,
                publish_review_state: false,
                publish_proofs: false,
            },
        };

        let plan = plan_push(
            &remote,
            &RepoState {
                local_head: Some("change:abc".into()),
                remote_head: Some("change:def".into()),
                approved: true,
            },
        );

        assert_eq!(plan.decision, PushDecision::FastForwardRequired);
    }

    #[test]
    fn publish_allowed_when_remote_is_aligned_and_approved() {
        let remote = RemoteRef {
            name: "origin".into(),
            host: HostKind::KinLab,
            transport: TransportKind::NativeKin,
            capabilities: RemoteCapabilitySet {
                publish_semantic_changes: true,
                publish_review_state: true,
                publish_proofs: true,
            },
        };

        let plan = plan_push(
            &remote,
            &RepoState {
                local_head: Some("change:abc".into()),
                remote_head: Some("change:abc".into()),
                approved: true,
            },
        );

        assert_eq!(plan.decision, PushDecision::Publish);
        assert!(plan.publish_proofs);
    }

    #[test]
    fn semantic_state_is_required_before_publish() {
        let remote = RemoteRef {
            name: "origin".into(),
            host: HostKind::GitHub,
            transport: TransportKind::GitExport,
            capabilities: RemoteCapabilitySet {
                publish_semantic_changes: true,
                publish_review_state: false,
                publish_proofs: false,
            },
        };

        let plan = plan_push(
            &remote,
            &RepoState {
                local_head: None,
                remote_head: None,
                approved: false,
            },
        );

        assert_eq!(plan.decision, PushDecision::SemanticStateRequired);
        assert!(!plan.publish_review_state);
        assert!(!plan.publish_proofs);
    }
}

#[cfg(test)]
mod sync_tests {
    use crate::connection::{ConnectionManager, ReconnectPolicy};
    use crate::delta_pull::{DeltaPuller, InMemoryDeltaPuller};
    use crate::invalidation::InvalidationChannel;
    use crate::mutation_push::{InMemoryMutationPusher, MutationPusher};
    use crate::sync_types::*;
    use chrono::Utc;
    use std::time::Duration;
    use uuid::Uuid;

    // -- Helpers -------------------------------------------------------------

    fn make_invalidation(entity_id: &str, change_type: ChangeType) -> InvalidationEvent {
        InvalidationEvent {
            entity_id: entity_id.to_owned(),
            change_type,
            timestamp: Utc::now(),
            actor_id: "actor-1".to_owned(),
        }
    }

    fn make_delta(entity_id: &str, before: Option<&str>, after: &str) -> SemanticDelta {
        SemanticDelta {
            entity_id: entity_id.to_owned(),
            before_hash: before.map(|s| s.to_owned()),
            after_hash: Some(after.to_owned()),
            change_set: vec![FieldDiff {
                field: "name".into(),
                old_value: Some("old".into()),
                new_value: Some("new".into()),
            }],
            timestamp: Utc::now(),
            actor_id: "actor-1".to_owned(),
        }
    }

    fn make_mutation(entity_id: &str, base: Option<&str>, new_hash: &str) -> LocalMutation {
        LocalMutation {
            entity_id: entity_id.to_owned(),
            mutation_id: Uuid::new_v4(),
            change_set: vec![FieldDiff {
                field: "name".into(),
                old_value: Some("old".into()),
                new_value: Some("new".into()),
            }],
            base_hash: base.map(|s| s.to_owned()),
            new_hash: Some(new_hash.to_owned()),
            timestamp: Utc::now(),
        }
    }

    // -- Test: receive invalidation → mark entity as stale -------------------

    #[tokio::test]
    async fn invalidation_marks_entity_stale() {
        let (mut channel, handle) = InvalidationChannel::new(64);

        let inv = make_invalidation("entity:1", ChangeType::Modified);
        let event = ChannelEvent::EntityInvalidated(inv);

        handle.sender.send(event.clone()).await.unwrap();

        let received = channel.recv_and_process().await.unwrap();
        assert_eq!(received, event);
        assert!(channel.stale_tracker().is_stale("entity:1"));
        assert!(!channel.stale_tracker().is_stale("entity:2"));
    }

    // -- Test: pull delta for stale entity → entity updated ------------------

    #[tokio::test]
    async fn pull_delta_updates_stale_entity() {
        let (mut channel, handle) = InvalidationChannel::new(64);

        // 1. Receive invalidation → entity is stale
        let inv = make_invalidation("entity:1", ChangeType::Modified);
        handle
            .sender
            .send(ChannelEvent::EntityInvalidated(inv))
            .await
            .unwrap();
        channel.recv_and_process().await.unwrap();
        assert!(channel.stale_tracker().is_stale("entity:1"));

        // 2. Pull delta for the stale entity
        let mut puller = InMemoryDeltaPuller::new();
        puller.insert(make_delta("entity:1", Some("hash-a"), "hash-b"));

        let delta = puller.pull_delta("entity:1").unwrap();
        assert_eq!(delta.entity_id, "entity:1");
        assert_eq!(delta.after_hash.as_deref(), Some("hash-b"));

        // 3. Mark entity as fresh after applying
        channel.stale_tracker_mut().mark_fresh("entity:1");
        assert!(!channel.stale_tracker().is_stale("entity:1"));
    }

    // -- Test: push local mutation → remote acknowledges ---------------------

    #[test]
    fn push_local_mutation_accepted() {
        let pusher = InMemoryMutationPusher::new();
        let mutation = make_mutation("entity:1", None, "hash-new");

        let result = pusher.push_mutations(&[mutation]).unwrap();
        match result {
            PushResult::Accepted {
                new_remote_head,
                accepted_count,
            } => {
                assert_eq!(new_remote_head, "hash-new");
                assert_eq!(accepted_count, 1);
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }

    // -- Test: push with remote divergence → conflict returned ---------------

    #[test]
    fn push_with_divergence_returns_conflict() {
        let mut pusher = InMemoryMutationPusher::new();
        // Remote has diverged: entity:1 is at hash-remote, but local mutation
        // was based on hash-old.
        pusher.set_remote_hash("entity:1", "hash-remote");

        let mutation = make_mutation("entity:1", Some("hash-old"), "hash-new");

        let result = pusher.push_mutations(&[mutation]).unwrap();
        match result {
            PushResult::Conflict {
                conflicts,
                accepted_count,
            } => {
                assert_eq!(conflicts.len(), 1);
                assert_eq!(conflicts[0].entity_id, "entity:1");
                assert_eq!(conflicts[0].remote_hash, "hash-remote");
                assert_eq!(accepted_count, 0);
            }
            other => panic!("expected Conflict, got {:?}", other),
        }
    }

    // -- Test: intent lock prevents concurrent modification ------------------

    #[test]
    fn intent_lock_prevents_push() {
        let mut pusher = InMemoryMutationPusher::new();
        pusher.acquire_lock(IntentLock {
            entity_id: "entity:1".to_owned(),
            holder_actor_id: "other-actor".to_owned(),
            lock_type: LockType::Exclusive,
            acquired_at: Utc::now(),
            ttl_seconds: 300,
        });

        let mutation = make_mutation("entity:1", None, "hash-new");
        let result = pusher.push_mutations(&[mutation]);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("intent lock held by other-actor"));
    }

    // -- Test: intent lock from self does not block --------------------------

    #[test]
    fn own_intent_lock_does_not_block_push() {
        let mut pusher = InMemoryMutationPusher::new();
        pusher.acquire_lock(IntentLock {
            entity_id: "entity:1".to_owned(),
            holder_actor_id: "local".to_owned(),
            lock_type: LockType::Exclusive,
            acquired_at: Utc::now(),
            ttl_seconds: 300,
        });

        let mutation = make_mutation("entity:1", None, "hash-new");
        let result = pusher.push_mutations(&[mutation]).unwrap();

        match result {
            PushResult::Accepted { accepted_count, .. } => {
                assert_eq!(accepted_count, 1);
            }
            other => panic!("expected Accepted, got {:?}", other),
        }
    }

    // -- Test: reconnection after disconnect replays queued mutations ---------

    #[test]
    fn reconnection_replays_queued_mutations() {
        let mut mgr = ConnectionManager::default();

        // Start connected
        mgr.begin_connect().unwrap();
        mgr.mark_connected().unwrap();
        mgr.begin_sync().unwrap();
        mgr.sync_complete().unwrap();

        // Disconnect
        mgr.mark_disconnected();
        assert_eq!(mgr.state(), ConnectionState::Disconnected);

        // Queue mutations while disconnected
        let m1 = make_mutation("entity:1", None, "hash-1");
        let m2 = make_mutation("entity:2", None, "hash-2");
        mgr.queue_mutation(m1.clone());
        mgr.queue_mutation(m2.clone());
        assert_eq!(mgr.queued_mutation_count(), 2);

        // Reconnect
        let delay = mgr.attempt_reconnect();
        assert!(delay.is_some());
        assert_eq!(mgr.state(), ConnectionState::Connecting);

        mgr.mark_connected().unwrap();
        assert_eq!(mgr.state(), ConnectionState::Connected);

        // Drain queued mutations for replay
        let queued = mgr.drain_queued_mutations();
        assert_eq!(queued.len(), 2);
        assert_eq!(queued[0].entity_id, "entity:1");
        assert_eq!(queued[1].entity_id, "entity:2");
        assert_eq!(mgr.queued_mutation_count(), 0);

        // Push them to the remote
        let pusher = InMemoryMutationPusher::new();
        let result = pusher.push_mutations(&queued).unwrap();
        match result {
            PushResult::Accepted { accepted_count, .. } => assert_eq!(accepted_count, 2),
            other => panic!("expected Accepted, got {:?}", other),
        }
    }

    // -- Test: connection state machine transitions correctly -----------------

    #[test]
    fn connection_state_machine_happy_path() {
        let mut mgr = ConnectionManager::default();

        // Starts disconnected
        assert_eq!(mgr.state(), ConnectionState::Disconnected);

        // Disconnected → Connecting
        mgr.begin_connect().unwrap();
        assert_eq!(mgr.state(), ConnectionState::Connecting);

        // Connecting → Connected
        mgr.mark_connected().unwrap();
        assert_eq!(mgr.state(), ConnectionState::Connected);

        // Connected → Syncing
        mgr.begin_sync().unwrap();
        assert_eq!(mgr.state(), ConnectionState::Syncing);

        // Syncing → Idle
        mgr.sync_complete().unwrap();
        assert_eq!(mgr.state(), ConnectionState::Idle);

        // Idle → Syncing (another sync cycle)
        mgr.begin_sync().unwrap();
        assert_eq!(mgr.state(), ConnectionState::Syncing);

        // Syncing → Idle
        mgr.sync_complete().unwrap();
        assert_eq!(mgr.state(), ConnectionState::Idle);
    }

    #[test]
    fn invalid_state_transitions_are_rejected() {
        let mut mgr = ConnectionManager::default();

        // Can't mark_connected from Disconnected
        assert!(mgr.mark_connected().is_err());

        // Can't begin_sync from Disconnected
        assert!(mgr.begin_sync().is_err());

        // Can't sync_complete from Disconnected
        assert!(mgr.sync_complete().is_err());

        // Connect properly
        mgr.begin_connect().unwrap();

        // Can't begin_connect again while Connecting
        assert!(mgr.begin_connect().is_err());

        // Can't begin_sync from Connecting
        assert!(mgr.begin_sync().is_err());
    }

    // -- Test: exponential backoff ------------------------------------------

    #[test]
    fn reconnect_uses_exponential_backoff() {
        let policy = ReconnectPolicy {
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(16),
            max_attempts: Some(5),
        };
        let mut mgr = ConnectionManager::new(policy);

        // First attempt: 1s
        let delay = mgr.attempt_reconnect().unwrap();
        assert_eq!(delay, Duration::from_secs(1));
        mgr.mark_disconnected(); // simulate failed connection

        // Second attempt: 2s
        let delay = mgr.attempt_reconnect().unwrap();
        assert_eq!(delay, Duration::from_secs(2));
        mgr.mark_disconnected();

        // Third attempt: 4s
        let delay = mgr.attempt_reconnect().unwrap();
        assert_eq!(delay, Duration::from_secs(4));
        mgr.mark_disconnected();

        // Fourth attempt: 8s
        let delay = mgr.attempt_reconnect().unwrap();
        assert_eq!(delay, Duration::from_secs(8));
        mgr.mark_disconnected();

        // Fifth attempt: capped at 16s
        let delay = mgr.attempt_reconnect().unwrap();
        assert_eq!(delay, Duration::from_secs(16));
        mgr.mark_disconnected();

        // Sixth attempt: exhausted
        assert!(mgr.attempt_reconnect().is_none());
    }

    // -- Test: successful connect resets attempt counter ---------------------

    #[test]
    fn successful_connect_resets_attempts() {
        let policy = ReconnectPolicy {
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            max_attempts: Some(10),
        };
        let mut mgr = ConnectionManager::new(policy);

        // Two failed attempts
        mgr.attempt_reconnect();
        mgr.mark_disconnected();
        mgr.attempt_reconnect();
        assert_eq!(mgr.reconnect_attempts(), 2);

        // Successful connect resets
        mgr.mark_connected().unwrap();
        assert_eq!(mgr.reconnect_attempts(), 0);
    }

    // -- Test: relation invalidation also marks stale -----------------------

    #[tokio::test]
    async fn relation_invalidation_marks_stale() {
        let (mut channel, handle) = InvalidationChannel::new(64);

        let inv = make_invalidation("relation:1", ChangeType::Created);
        handle
            .sender
            .send(ChannelEvent::RelationInvalidated(inv))
            .await
            .unwrap();

        channel.recv_and_process().await.unwrap();
        assert!(channel.stale_tracker().is_stale("relation:1"));
    }

    // -- Test: buffer events when busy --------------------------------------

    #[tokio::test]
    async fn buffer_events_when_busy() {
        let (mut channel, handle) = InvalidationChannel::new(64);

        let inv1 = make_invalidation("entity:1", ChangeType::Modified);
        let inv2 = make_invalidation("entity:2", ChangeType::Deleted);

        // Buffer events manually
        channel
            .buffer_event(ChannelEvent::EntityInvalidated(inv1))
            .unwrap();
        channel
            .buffer_event(ChannelEvent::EntityInvalidated(inv2))
            .unwrap();

        assert_eq!(channel.buffered_count(), 2);

        // Recv should drain from buffer first
        let event = channel.recv().await.unwrap();
        match &event {
            ChannelEvent::EntityInvalidated(inv) => assert_eq!(inv.entity_id, "entity:1"),
            _ => panic!("unexpected event"),
        }

        let event = channel.recv().await.unwrap();
        match &event {
            ChannelEvent::EntityInvalidated(inv) => assert_eq!(inv.entity_id, "entity:2"),
            _ => panic!("unexpected event"),
        }

        // Drop handle to close the channel
        drop(handle);
    }

    // -- Test: pull_deltas_since batch pull ---------------------------------

    #[test]
    fn pull_deltas_since_returns_only_newer() {
        let mut puller = InMemoryDeltaPuller::new();

        let old_time = Utc::now() - chrono::Duration::hours(2);
        let recent_time = Utc::now() - chrono::Duration::minutes(5);
        let cutoff = Utc::now() - chrono::Duration::hours(1);

        let mut old_delta = make_delta("entity:old", None, "hash-old");
        old_delta.timestamp = old_time;

        let mut new_delta = make_delta("entity:new", Some("hash-a"), "hash-b");
        new_delta.timestamp = recent_time;

        puller.insert(old_delta);
        puller.insert(new_delta);

        let results = puller.pull_deltas_since(cutoff).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entity_id, "entity:new");
    }

    // -- Test: idempotent pull (same result both times) ---------------------

    #[test]
    fn pull_delta_is_idempotent() {
        let mut puller = InMemoryDeltaPuller::new();
        puller.insert(make_delta("entity:1", Some("a"), "b"));

        let first = puller.pull_delta("entity:1").unwrap();
        let second = puller.pull_delta("entity:1").unwrap();
        assert_eq!(first, second);
    }

    // -- Test: intent lock expiry -------------------------------------------

    #[test]
    fn intent_lock_expiry() {
        let lock = IntentLock {
            entity_id: "entity:1".to_owned(),
            holder_actor_id: "actor-1".to_owned(),
            lock_type: LockType::Exclusive,
            acquired_at: Utc::now() - chrono::Duration::seconds(100),
            ttl_seconds: 60,
        };

        assert!(lock.is_expired(Utc::now()));

        let fresh_lock = IntentLock {
            acquired_at: Utc::now(),
            ttl_seconds: 300,
            ..lock
        };

        assert!(!fresh_lock.is_expired(Utc::now()));
    }

    // -- Test: stale tracker operations -------------------------------------

    #[test]
    fn stale_tracker_tracks_multiple_entities() {
        let mut tracker = StaleTracker::new();
        assert_eq!(tracker.stale_count(), 0);

        tracker.mark_stale(make_invalidation("a", ChangeType::Modified));
        tracker.mark_stale(make_invalidation("b", ChangeType::Created));
        tracker.mark_stale(make_invalidation("c", ChangeType::Deleted));

        assert_eq!(tracker.stale_count(), 3);
        assert!(tracker.is_stale("a"));
        assert!(tracker.is_stale("b"));
        assert!(tracker.is_stale("c"));
        assert!(!tracker.is_stale("d"));

        tracker.mark_fresh("b");
        assert_eq!(tracker.stale_count(), 2);
        assert!(!tracker.is_stale("b"));

        let ids = tracker.stale_entity_ids();
        assert!(ids.contains(&"a".to_owned()));
        assert!(ids.contains(&"c".to_owned()));
    }

    // -- Test: SyncState default -------------------------------------------

    #[test]
    fn sync_state_defaults() {
        let state = SyncState::default();
        assert!(state.last_synced_at.is_none());
        assert!(state.local_head_hash.is_none());
        assert!(state.remote_head_hash.is_none());
        assert_eq!(state.pending_pushes, 0);
        assert_eq!(state.pending_pulls, 0);
    }

    // -- Test: mixed push (some accepted, some conflicted) ------------------

    #[test]
    fn mixed_push_partial_conflict() {
        let mut pusher = InMemoryMutationPusher::new();
        // entity:1 has diverged, entity:2 has not
        pusher.set_remote_hash("entity:1", "hash-remote");

        let m1 = make_mutation("entity:1", Some("hash-old"), "hash-new-1");
        let m2 = make_mutation("entity:2", None, "hash-new-2");

        let result = pusher.push_mutations(&[m1, m2]).unwrap();
        match result {
            PushResult::Conflict {
                conflicts,
                accepted_count,
            } => {
                assert_eq!(conflicts.len(), 1);
                assert_eq!(conflicts[0].entity_id, "entity:1");
                assert_eq!(accepted_count, 1); // entity:2 was accepted
            }
            other => panic!("expected Conflict, got {:?}", other),
        }
    }
}
