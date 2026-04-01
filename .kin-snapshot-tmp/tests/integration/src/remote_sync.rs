// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Integration tests for the kin-remote sync protocol.
//!
//! Exercises push, pull, conflict detection, delta sync, reconnection,
//! and the full invalidation-pull-push cycle using in-memory transports.

use chrono::Utc;
use kin_remote::connection::{ConnectionManager, ReconnectPolicy};
use kin_remote::delta_pull::{DeltaPuller, InMemoryDeltaPuller};
use kin_remote::invalidation::InvalidationChannel;
use kin_remote::mutation_push::{InMemoryMutationPusher, MutationPusher};
use kin_remote::sync_types::*;
use std::time::Duration;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
        new_hash: new_hash.to_owned(),
        timestamp: Utc::now(),
    }
}

fn make_delta(entity_id: &str, before: Option<&str>, after: &str) -> SemanticDelta {
    SemanticDelta {
        entity_id: entity_id.to_owned(),
        before_hash: before.map(|s| s.to_owned()),
        after_hash: after.to_owned(),
        change_set: vec![FieldDiff {
            field: "name".into(),
            old_value: Some("old".into()),
            new_value: Some("new".into()),
        }],
        timestamp: Utc::now(),
        actor_id: "test-actor".to_owned(),
    }
}

fn make_invalidation(entity_id: &str, change_type: ChangeType) -> InvalidationEvent {
    InvalidationEvent {
        entity_id: entity_id.to_owned(),
        change_type,
        timestamp: Utc::now(),
        actor_id: "remote-actor".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Test 1: Push mutations to remote and verify acceptance
// ---------------------------------------------------------------------------

#[test]
fn push_snapshot_to_remote_and_verify_accepted() {
    let pusher = InMemoryMutationPusher::new();

    // Push three entity mutations (simulating a snapshot push)
    let mutations = vec![
        make_mutation("entity:fn_main", None, "hash-a1"),
        make_mutation("entity:fn_helper", None, "hash-b1"),
        make_mutation("entity:struct_config", None, "hash-c1"),
    ];

    let result = pusher.push_mutations(&mutations).unwrap();
    match result {
        PushResult::Accepted {
            new_remote_head,
            accepted_count,
        } => {
            assert_eq!(accepted_count, 3);
            // Remote head should be the last mutation's new hash
            assert_eq!(new_remote_head, "hash-c1");
        }
        other => panic!("expected Accepted, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Test 2: Pull delta from remote and verify graph state matches
// ---------------------------------------------------------------------------

#[test]
fn pull_delta_and_verify_graph_state() {
    let mut puller = InMemoryDeltaPuller::new();

    // Seed remote with deltas for three entities
    puller.insert(make_delta("entity:fn_main", None, "hash-a1"));
    puller.insert(make_delta(
        "entity:fn_helper",
        Some("hash-b0"),
        "hash-b1",
    ));
    puller.insert(make_delta("entity:struct_config", None, "hash-c1"));

    // Pull each entity's delta and verify it matches expected state
    let delta_main = puller.pull_delta("entity:fn_main").unwrap();
    assert_eq!(delta_main.after_hash, "hash-a1");
    assert!(delta_main.before_hash.is_none());

    let delta_helper = puller.pull_delta("entity:fn_helper").unwrap();
    assert_eq!(delta_helper.after_hash, "hash-b1");
    assert_eq!(delta_helper.before_hash.as_deref(), Some("hash-b0"));

    let delta_config = puller.pull_delta("entity:struct_config").unwrap();
    assert_eq!(delta_config.after_hash, "hash-c1");

    // Pulling a non-existent entity returns an error
    assert!(puller.pull_delta("entity:does_not_exist").is_err());
}

// ---------------------------------------------------------------------------
// Test 3: Concurrent push from two clients - conflict detection
// ---------------------------------------------------------------------------

#[test]
fn concurrent_push_detects_conflicts() {
    // Simulate two clients that have diverged from the same base state.
    // Both started from entity:fn_main at hash "hash-base".
    let mut pusher = InMemoryMutationPusher::new();
    pusher.set_remote_hash("entity:fn_main", "hash-base");

    // Client A pushes first — bases on "hash-base", succeeds
    let client_a_mutation = make_mutation("entity:fn_main", Some("hash-base"), "hash-a-new");
    let result_a = pusher.push_mutations(&[client_a_mutation]).unwrap();
    match result_a {
        PushResult::Accepted { accepted_count, .. } => {
            assert_eq!(accepted_count, 1);
        }
        other => panic!("Client A should succeed, got {:?}", other),
    }

    // Now simulate that the remote has been updated to client A's hash
    pusher.set_remote_hash("entity:fn_main", "hash-a-new");

    // Client B pushes — still bases on "hash-base" (stale), should conflict
    let client_b_mutation = make_mutation("entity:fn_main", Some("hash-base"), "hash-b-new");
    let result_b = pusher.push_mutations(&[client_b_mutation]).unwrap();
    match result_b {
        PushResult::Conflict {
            conflicts,
            accepted_count,
        } => {
            assert_eq!(conflicts.len(), 1);
            assert_eq!(conflicts[0].entity_id, "entity:fn_main");
            assert_eq!(conflicts[0].remote_hash, "hash-a-new");
            assert_eq!(conflicts[0].local_hash, "hash-b-new");
            assert_eq!(accepted_count, 0);
        }
        other => panic!("Client B should conflict, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Test 4: Delta sync - push incremental changes, pull only the delta
// ---------------------------------------------------------------------------

#[test]
fn delta_sync_incremental_changes() {
    let mut puller = InMemoryDeltaPuller::new();

    let base_time = Utc::now() - chrono::Duration::hours(2);
    let sync_point = Utc::now() - chrono::Duration::hours(1);

    // Old delta (before sync point) - should NOT appear in incremental pull
    let mut old_delta = make_delta("entity:fn_old", None, "hash-old");
    old_delta.timestamp = base_time;
    puller.insert(old_delta);

    // New deltas (after sync point) - should appear in incremental pull
    let mut new_delta_1 = make_delta("entity:fn_new_1", Some("hash-n1-before"), "hash-n1-after");
    new_delta_1.timestamp = Utc::now() - chrono::Duration::minutes(30);
    puller.insert(new_delta_1);

    let mut new_delta_2 = make_delta("entity:fn_new_2", None, "hash-n2");
    new_delta_2.timestamp = Utc::now() - chrono::Duration::minutes(10);
    puller.insert(new_delta_2);

    // Pull only deltas since the sync point
    let incremental = puller.pull_deltas_since(sync_point).unwrap();
    assert_eq!(incremental.len(), 2);
    assert_eq!(incremental[0].entity_id, "entity:fn_new_1");
    assert_eq!(incremental[1].entity_id, "entity:fn_new_2");

    // Verify the old delta is excluded
    assert!(incremental.iter().all(|d| d.entity_id != "entity:fn_old"));

    // Now push the pulled deltas as mutations to the "local" remote
    let pusher = InMemoryMutationPusher::new();
    let mutations: Vec<LocalMutation> = incremental
        .iter()
        .map(|d| LocalMutation {
            entity_id: d.entity_id.clone(),
            mutation_id: Uuid::new_v4(),
            change_set: d.change_set.clone(),
            base_hash: d.before_hash.clone(),
            new_hash: d.after_hash.clone(),
            timestamp: d.timestamp,
        })
        .collect();

    let result = pusher.push_mutations(&mutations).unwrap();
    match result {
        PushResult::Accepted { accepted_count, .. } => {
            assert_eq!(accepted_count, 2);
        }
        other => panic!("expected Accepted, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Test 5: Connection failure, reconnection, and queued mutation replay
// ---------------------------------------------------------------------------

#[test]
fn connection_failure_reconnect_and_replay() {
    let policy = ReconnectPolicy {
        base_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(10),
        max_attempts: Some(3),
    };
    let mut mgr = ConnectionManager::new(policy);

    // Establish initial connection
    mgr.begin_connect().unwrap();
    mgr.mark_connected().unwrap();
    mgr.begin_sync().unwrap();
    mgr.sync_complete().unwrap();
    assert_eq!(mgr.state(), ConnectionState::Idle);

    // Simulate connection loss
    mgr.mark_disconnected();
    assert_eq!(mgr.state(), ConnectionState::Disconnected);

    // Queue mutations while offline
    let m1 = make_mutation("entity:fn_a", None, "hash-a");
    let m2 = make_mutation("entity:fn_b", None, "hash-b");
    let m3 = make_mutation("entity:fn_c", None, "hash-c");
    mgr.queue_mutation(m1);
    mgr.queue_mutation(m2);
    mgr.queue_mutation(m3);
    assert_eq!(mgr.queued_mutation_count(), 3);

    // Reconnect with backoff
    let delay = mgr.attempt_reconnect();
    assert!(delay.is_some());
    assert_eq!(mgr.state(), ConnectionState::Connecting);

    // Connection succeeds
    mgr.mark_connected().unwrap();
    assert_eq!(mgr.state(), ConnectionState::Connected);
    assert_eq!(mgr.reconnect_attempts(), 0); // reset on success

    // Drain and replay queued mutations
    let queued = mgr.drain_queued_mutations();
    assert_eq!(queued.len(), 3);
    assert_eq!(queued[0].entity_id, "entity:fn_a");
    assert_eq!(queued[1].entity_id, "entity:fn_b");
    assert_eq!(queued[2].entity_id, "entity:fn_c");
    assert_eq!(mgr.queued_mutation_count(), 0);

    // Push queued mutations to remote
    let pusher = InMemoryMutationPusher::new();
    let result = pusher.push_mutations(&queued).unwrap();
    match result {
        PushResult::Accepted { accepted_count, .. } => {
            assert_eq!(accepted_count, 3);
        }
        other => panic!("expected Accepted, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Test 6: Reconnection exhaustion - max attempts exceeded
// ---------------------------------------------------------------------------

#[test]
fn reconnection_exhaustion_after_max_attempts() {
    let policy = ReconnectPolicy {
        base_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(80),
        max_attempts: Some(3),
    };
    let mut mgr = ConnectionManager::new(policy);

    // Attempt 1: 10ms delay
    let delay1 = mgr.attempt_reconnect().unwrap();
    assert_eq!(delay1, Duration::from_millis(10));
    mgr.mark_disconnected();

    // Attempt 2: 20ms delay
    let delay2 = mgr.attempt_reconnect().unwrap();
    assert_eq!(delay2, Duration::from_millis(20));
    mgr.mark_disconnected();

    // Attempt 3: 40ms delay
    let delay3 = mgr.attempt_reconnect().unwrap();
    assert_eq!(delay3, Duration::from_millis(40));
    mgr.mark_disconnected();

    // Attempt 4: exhausted
    assert!(mgr.attempt_reconnect().is_none());
    assert_eq!(mgr.state(), ConnectionState::Disconnected);

    // Mutations queued while permanently disconnected should still be retained
    mgr.queue_mutation(make_mutation("entity:orphan", None, "hash-orphan"));
    assert_eq!(mgr.queued_mutation_count(), 1);
}

// ---------------------------------------------------------------------------
// Test 7: Full cycle - invalidation -> pull delta -> push mutation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_invalidation_pull_push_cycle() {
    // Set up the invalidation channel
    let (mut channel, handle) = InvalidationChannel::new(64);

    // Set up remote with a delta for the entity that will be invalidated
    let mut puller = InMemoryDeltaPuller::new();
    puller.insert(make_delta(
        "entity:fn_main",
        Some("hash-v1"),
        "hash-v2",
    ));

    // Step 1: Remote sends invalidation event (entity was modified on another client)
    let inv = make_invalidation("entity:fn_main", ChangeType::Modified);
    handle
        .sender
        .send(ChannelEvent::EntityInvalidated(inv))
        .await
        .unwrap();

    // Step 2: Daemon receives and processes the invalidation
    let event = channel.recv_and_process().await.unwrap();
    match &event {
        ChannelEvent::EntityInvalidated(inv) => {
            assert_eq!(inv.entity_id, "entity:fn_main");
        }
        _ => panic!("expected EntityInvalidated"),
    }
    assert!(channel.stale_tracker().is_stale("entity:fn_main"));

    // Step 3: Pull the delta for the stale entity
    let delta = puller.pull_delta("entity:fn_main").unwrap();
    assert_eq!(delta.after_hash, "hash-v2");
    assert_eq!(delta.before_hash.as_deref(), Some("hash-v1"));

    // Step 4: Apply the delta locally (simulated) and mark fresh
    channel.stale_tracker_mut().mark_fresh("entity:fn_main");
    assert!(!channel.stale_tracker().is_stale("entity:fn_main"));

    // Step 5: Make a local modification and push back
    let pusher = InMemoryMutationPusher::new();
    let local_mutation = make_mutation("entity:fn_main", Some("hash-v2"), "hash-v3");
    let result = pusher.push_mutations(&[local_mutation]).unwrap();
    match result {
        PushResult::Accepted {
            new_remote_head,
            accepted_count,
        } => {
            assert_eq!(accepted_count, 1);
            assert_eq!(new_remote_head, "hash-v3");
        }
        other => panic!("expected Accepted, got {:?}", other),
    }

    // Clean up: drop handle to close channel
    drop(handle);
}
