// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Phase 10 acceptance tests: provenance tracking (actors, delegations, approvals, audit).
//!
//! These tests exercise the Phase 10 graph methods via the InMemoryGraph.

use kin_db::InMemoryGraph;
use kin_model::provenance::*;
use kin_model::work::ExternalRef;
use kin_model::*;

// ---------------------------------------------------------------------------
// 36. Actor CRUD: create human + assistant actors, get by ID, list all
// ---------------------------------------------------------------------------

#[test]
fn actor_crud() {
    let store = InMemoryGraph::new();

    let human = Actor {
        actor_id: ActorId::new(),
        kind: ActorKind::Human,
        display_name: "Alice".into(),
        external_refs: vec![ExternalRef {
            system: "github".into(),
            identifier: "alice".into(),
            url: None,
        }],
    };

    let assistant = Actor {
        actor_id: ActorId::new(),
        kind: ActorKind::Assistant,
        display_name: "Claude".into(),
        external_refs: vec![],
    };

    store.create_actor(&human).unwrap();
    store.create_actor(&assistant).unwrap();

    // Get by ID.
    let fetched = store
        .get_actor(&human.actor_id)
        .unwrap()
        .expect("human actor should exist");
    assert_eq!(fetched.actor_id, human.actor_id);
    assert_eq!(fetched.kind, ActorKind::Human);
    assert_eq!(fetched.display_name, "Alice");

    let fetched_asst = store
        .get_actor(&assistant.actor_id)
        .unwrap()
        .expect("assistant actor should exist");
    assert_eq!(fetched_asst.kind, ActorKind::Assistant);
    assert_eq!(fetched_asst.display_name, "Claude");

    // Non-existent returns None.
    let missing = store.get_actor(&ActorId::new()).unwrap();
    assert!(missing.is_none());

    // List all.
    let all = store.list_actors().unwrap();
    assert_eq!(all.len(), 2);
}

// ---------------------------------------------------------------------------
// 37. Delegation lifecycle: create a delegation, query by actor ID
// ---------------------------------------------------------------------------

#[test]
fn delegation_lifecycle() {
    let store = InMemoryGraph::new();

    let principal = Actor {
        actor_id: ActorId::new(),
        kind: ActorKind::Human,
        display_name: "Alice".into(),
        external_refs: vec![],
    };
    let delegate = Actor {
        actor_id: ActorId::new(),
        kind: ActorKind::Assistant,
        display_name: "Claude".into(),
        external_refs: vec![],
    };

    store.create_actor(&principal).unwrap();
    store.create_actor(&delegate).unwrap();

    let entity_id = EntityId::new();
    let delegation = Delegation {
        delegation_id: DelegationId::new(),
        principal: principal.actor_id,
        delegate: delegate.actor_id,
        scope: vec![WorkScope::Entity(entity_id)],
        started_at: Timestamp::now(),
        ended_at: None,
    };

    store.create_delegation(&delegation).unwrap();

    // Query delegations for the principal.
    let delegations = store
        .get_delegations_for_actor(&principal.actor_id)
        .unwrap();
    assert_eq!(delegations.len(), 1);
    assert_eq!(delegations[0].delegation_id, delegation.delegation_id);
    assert_eq!(delegations[0].principal, principal.actor_id);
    assert_eq!(delegations[0].delegate, delegate.actor_id);

    // Actor with no delegations returns empty.
    let empty = store.get_delegations_for_actor(&ActorId::new()).unwrap();
    assert!(empty.is_empty());
}

// ---------------------------------------------------------------------------
// 38. Approval workflow: create approval for a change, query by change ID
// ---------------------------------------------------------------------------

#[test]
fn approval_workflow() {
    let store = InMemoryGraph::new();

    let approver = Actor {
        actor_id: ActorId::new(),
        kind: ActorKind::Human,
        display_name: "Bob".into(),
        external_refs: vec![],
    };
    store.create_actor(&approver).unwrap();

    let change_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xdd; 32]));

    let approval = Approval {
        approval_id: ApprovalId::new(),
        change_id,
        approver: approver.actor_id,
        decision: ApprovalDecision::Approved,
        reason: "LGTM".into(),
        timestamp: Timestamp::now(),
    };

    store.create_approval(&approval).unwrap();

    let approvals = store.get_approvals_for_change(&change_id).unwrap();
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].approval_id, approval.approval_id);
    assert_eq!(approvals[0].decision, ApprovalDecision::Approved);
    assert_eq!(approvals[0].reason, "LGTM");

    // No approvals for a different change.
    let other_change = SemanticChangeId::from_hash(Hash256::from_bytes([0xee; 32]));
    let empty = store.get_approvals_for_change(&other_change).unwrap();
    assert!(empty.is_empty());
}

// ---------------------------------------------------------------------------
// 39. Audit event filtering: record multiple events, query with filter + limit
// ---------------------------------------------------------------------------

#[test]
fn audit_event_filtering() {
    let store = InMemoryGraph::new();

    let actor_a = Actor {
        actor_id: ActorId::new(),
        kind: ActorKind::Human,
        display_name: "Alice".into(),
        external_refs: vec![],
    };
    let actor_b = Actor {
        actor_id: ActorId::new(),
        kind: ActorKind::Assistant,
        display_name: "Claude".into(),
        external_refs: vec![],
    };
    store.create_actor(&actor_a).unwrap();
    store.create_actor(&actor_b).unwrap();

    // Record events from both actors.
    for i in 0..3 {
        let event = AuditEvent {
            event_id: AuditEventId::new(),
            actor_id: actor_a.actor_id,
            action: format!("action_a_{i}"),
            target_scope: None,
            timestamp: Timestamp::now(),
            details: None,
        };
        store.record_audit_event(&event).unwrap();
    }

    let event_b = AuditEvent {
        event_id: AuditEventId::new(),
        actor_id: actor_b.actor_id,
        action: "action_b".into(),
        target_scope: Some(WorkScope::Entity(EntityId::new())),
        timestamp: Timestamp::now(),
        details: Some("assistant action".into()),
    };
    store.record_audit_event(&event_b).unwrap();

    // Query all events (no actor filter).
    let all = store.query_audit_events(None, 100).unwrap();
    assert_eq!(all.len(), 4);

    // Query by actor_a only.
    let a_events = store
        .query_audit_events(Some(&actor_a.actor_id), 100)
        .unwrap();
    assert_eq!(a_events.len(), 3);
    assert!(a_events.iter().all(|e| e.actor_id == actor_a.actor_id));

    // Query by actor_b only.
    let b_events = store
        .query_audit_events(Some(&actor_b.actor_id), 100)
        .unwrap();
    assert_eq!(b_events.len(), 1);
    assert_eq!(b_events[0].action, "action_b");

    // Limit restricts results.
    let limited = store.query_audit_events(None, 2).unwrap();
    assert_eq!(limited.len(), 2);
}

// ---------------------------------------------------------------------------
// 40. Unreviewed agent changes: entities created by assistant without approval
// ---------------------------------------------------------------------------

#[test]
fn review_surfaces_unreviewed_agent_changes() {
    let store = InMemoryGraph::new();

    // Create an assistant actor.
    let assistant = Actor {
        actor_id: ActorId::new(),
        kind: ActorKind::Assistant,
        display_name: "Copilot".into(),
        external_refs: vec![],
    };
    store.create_actor(&assistant).unwrap();

    // Record an audit event for a change made by the assistant.
    let change_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xab; 32]));
    let event = AuditEvent {
        event_id: AuditEventId::new(),
        actor_id: assistant.actor_id,
        action: "commit".into(),
        target_scope: None,
        timestamp: Timestamp::now(),
        details: Some(format!("change:{change_id}")),
    };
    store.record_audit_event(&event).unwrap();

    // Verify the assistant's actor kind is Assistant.
    let fetched = store
        .get_actor(&assistant.actor_id)
        .unwrap()
        .expect("assistant should exist");
    assert_eq!(fetched.kind, ActorKind::Assistant);

    // No approvals exist for this change.
    let approvals = store.get_approvals_for_change(&change_id).unwrap();
    assert!(
        approvals.is_empty(),
        "expected no approvals for unreviewed agent change"
    );

    // Audit trail shows the assistant made the change.
    let events = store
        .query_audit_events(Some(&assistant.actor_id), 100)
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "commit");
}

// ---------------------------------------------------------------------------
// 41. Release gating: entities without test coverage block release
// ---------------------------------------------------------------------------

#[test]
fn release_gating_blocks_without_proof() {
    use crate::helpers::make_entity;

    let store = InMemoryGraph::new();

    // Create 3 entities, only 1 with test coverage.
    let e1 = make_entity("create_order", "src/order.ts", EntityKind::Function);
    let e2 = make_entity("process_payment", "src/pay.ts", EntityKind::Function);
    let e3 = make_entity("send_email", "src/email.ts", EntityKind::Function);

    store.upsert_entity(&e1).unwrap();
    store.upsert_entity(&e2).unwrap();
    store.upsert_entity(&e3).unwrap();

    // Only e1 has a test.
    let tc = kin_model::TestCase {
        test_id: kin_model::TestId::new(),
        name: "test_create_order".into(),
        language: "typescript".into(),
        kind: kin_model::TestKind::Unit,
        scopes: vec![WorkScope::Entity(e1.id)],
        runner: kin_model::TestRunner::Jest,
        file_origin: None,
    };
    store.create_test_case(&tc).unwrap();

    let summary = store.get_coverage_summary().unwrap();
    assert_eq!(summary.total_entities, 3);
    assert_eq!(summary.covered_entities, 1);

    // coverage_ratio should be ~0.33
    assert!(
        summary.coverage_ratio < 0.5,
        "expected coverage_ratio < 0.5, got {}",
        summary.coverage_ratio
    );

    // Missing proof should include e2 and e3.
    assert_eq!(summary.missing_proof.len(), 2);
    assert!(summary.missing_proof.contains(&e2.id));
    assert!(summary.missing_proof.contains(&e3.id));
}
