// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

//! Provenance chain acceptance test.
//!
//! Verifies the full delegation chain workflow:
//! 1. Create actor entities (principal + delegate)
//! 2. Create a delegation from principal to delegate
//! 3. Have the delegate perform an action (recorded as an audit event)
//! 4. Verify the audit event is recorded and attributable
//! 5. Verify the delegation chain can be traversed via graph queries

use kin_db::InMemoryGraph;
use kin_model::graph::GraphStore;
use kin_model::provenance::*;
use kin_model::work::WorkScope;
use kin_model::*;

/// Full delegation chain: principal delegates to assistant, assistant acts,
/// audit trail links back through the delegation chain.
#[test]
fn delegation_chain_provenance() {
    let store = InMemoryGraph::new();

    // Step 1: Create two actors — a human principal and an assistant delegate
    let principal = Actor {
        actor_id: ActorId::new(),
        kind: ActorKind::Human,
        display_name: "Alice (principal)".into(),
        external_refs: vec![],
    };
    let delegate = Actor {
        actor_id: ActorId::new(),
        kind: ActorKind::Assistant,
        display_name: "Claude (delegate)".into(),
        external_refs: vec![],
    };
    store.create_actor(&principal).unwrap();
    store.create_actor(&delegate).unwrap();

    // Step 2: Create a delegation from principal to delegate, scoped to an entity
    let target_entity_id = EntityId::new();
    let delegation = Delegation {
        delegation_id: DelegationId::new(),
        principal: principal.actor_id,
        delegate: delegate.actor_id,
        scope: vec![WorkScope::Entity(target_entity_id)],
        started_at: Timestamp::now(),
        ended_at: None,
    };
    store.create_delegation(&delegation).unwrap();

    // Step 3: The delegate performs an action — record as an audit event
    let action_event = AuditEvent {
        event_id: AuditEventId::new(),
        actor_id: delegate.actor_id,
        action: "entity.modify".into(),
        target_scope: Some(WorkScope::Entity(target_entity_id)),
        timestamp: Timestamp::now(),
        details: Some("Modified entity under delegated authority".into()),
    };
    store.record_audit_event(&action_event).unwrap();

    // Step 4: Verify the audit event is recorded
    let events = store
        .query_audit_events(Some(&delegate.actor_id), 100)
        .unwrap();
    assert_eq!(events.len(), 1, "expected exactly one audit event from delegate");
    assert_eq!(events[0].event_id, action_event.event_id);
    assert_eq!(events[0].action, "entity.modify");
    assert_eq!(
        events[0].actor_id, delegate.actor_id,
        "audit event should be attributed to the delegate"
    );

    // Step 5: Traverse the delegation chain from the delegate back to the principal
    // Query delegations for the principal — should include our delegation
    let principal_delegations = store
        .get_delegations_for_actor(&principal.actor_id)
        .unwrap();
    assert_eq!(
        principal_delegations.len(),
        1,
        "principal should have exactly one delegation"
    );
    assert_eq!(principal_delegations[0].delegate, delegate.actor_id);

    // Verify the delegation is active (ended_at is None)
    assert!(
        principal_delegations[0].ended_at.is_none(),
        "delegation should be active (no end time)"
    );

    // Verify we can trace: audit event actor -> delegation -> principal
    let acting_actor_id = events[0].actor_id;
    let all_delegations = store
        .get_delegations_for_actor(&principal.actor_id)
        .unwrap();
    let chain_link = all_delegations
        .iter()
        .find(|d| d.delegate == acting_actor_id);
    assert!(
        chain_link.is_some(),
        "should find delegation linking delegate back to principal"
    );
    let chain_link = chain_link.unwrap();
    assert_eq!(chain_link.principal, principal.actor_id);
    assert_eq!(chain_link.delegate, delegate.actor_id);

    // Verify the principal actor exists and is human
    let principal_actor = store
        .get_actor(&chain_link.principal)
        .unwrap()
        .expect("principal actor should exist");
    assert_eq!(principal_actor.kind, ActorKind::Human);
    assert_eq!(principal_actor.display_name, "Alice (principal)");
}

/// Multi-hop delegation chain: A delegates to B, B delegates to C,
/// C acts — verify the full chain is traversable.
#[test]
fn multi_hop_delegation_chain() {
    let store = InMemoryGraph::new();

    let alice = Actor {
        actor_id: ActorId::new(),
        kind: ActorKind::Human,
        display_name: "Alice".into(),
        external_refs: vec![],
    };
    let bob = Actor {
        actor_id: ActorId::new(),
        kind: ActorKind::Human,
        display_name: "Bob".into(),
        external_refs: vec![],
    };
    let claude = Actor {
        actor_id: ActorId::new(),
        kind: ActorKind::Assistant,
        display_name: "Claude".into(),
        external_refs: vec![],
    };
    store.create_actor(&alice).unwrap();
    store.create_actor(&bob).unwrap();
    store.create_actor(&claude).unwrap();

    let scope = vec![WorkScope::Entity(EntityId::new())];

    // Alice delegates to Bob
    let d1 = Delegation {
        delegation_id: DelegationId::new(),
        principal: alice.actor_id,
        delegate: bob.actor_id,
        scope: scope.clone(),
        started_at: Timestamp::now(),
        ended_at: None,
    };
    store.create_delegation(&d1).unwrap();

    // Bob delegates to Claude
    let d2 = Delegation {
        delegation_id: DelegationId::new(),
        principal: bob.actor_id,
        delegate: claude.actor_id,
        scope: scope.clone(),
        started_at: Timestamp::now(),
        ended_at: None,
    };
    store.create_delegation(&d2).unwrap();

    // Claude performs an action
    let event = AuditEvent {
        event_id: AuditEventId::new(),
        actor_id: claude.actor_id,
        action: "entity.create".into(),
        target_scope: None,
        timestamp: Timestamp::now(),
        details: Some("Created entity under double-delegated authority".into()),
    };
    store.record_audit_event(&event).unwrap();

    // Traverse the chain: Claude -> Bob -> Alice
    // Step 1: Find who delegated to Claude
    let bob_delegations = store.get_delegations_for_actor(&bob.actor_id).unwrap();
    let to_claude = bob_delegations
        .iter()
        .find(|d| d.delegate == claude.actor_id);
    assert!(to_claude.is_some(), "Bob should have delegated to Claude");
    assert_eq!(to_claude.unwrap().principal, bob.actor_id);

    // Step 2: Find who delegated to Bob
    let alice_delegations = store.get_delegations_for_actor(&alice.actor_id).unwrap();
    let to_bob = alice_delegations
        .iter()
        .find(|d| d.delegate == bob.actor_id);
    assert!(to_bob.is_some(), "Alice should have delegated to Bob");
    assert_eq!(to_bob.unwrap().principal, alice.actor_id);

    // The root of the chain is Alice (human)
    let root = store.get_actor(&alice.actor_id).unwrap().unwrap();
    assert_eq!(root.kind, ActorKind::Human);

    // All three actors are in the store
    let all_actors = store.list_actors().unwrap();
    assert_eq!(all_actors.len(), 3);
}

/// Expired delegation: delegation with ended_at set should still be
/// queryable for audit purposes but is logically no longer active.
#[test]
fn expired_delegation_still_queryable() {
    let store = InMemoryGraph::new();

    let principal = Actor {
        actor_id: ActorId::new(),
        kind: ActorKind::Human,
        display_name: "Owner".into(),
        external_refs: vec![],
    };
    let delegate = Actor {
        actor_id: ActorId::new(),
        kind: ActorKind::Service,
        display_name: "CI Bot".into(),
        external_refs: vec![],
    };
    store.create_actor(&principal).unwrap();
    store.create_actor(&delegate).unwrap();

    let delegation = Delegation {
        delegation_id: DelegationId::new(),
        principal: principal.actor_id,
        delegate: delegate.actor_id,
        scope: vec![],
        started_at: Timestamp::now(),
        ended_at: Some(Timestamp::now()), // Already expired
    };
    store.create_delegation(&delegation).unwrap();

    // Expired delegations are still returned for audit trail traversal
    let delegations = store
        .get_delegations_for_actor(&principal.actor_id)
        .unwrap();
    assert_eq!(delegations.len(), 1);
    assert!(
        delegations[0].ended_at.is_some(),
        "delegation should have an end time"
    );
}
