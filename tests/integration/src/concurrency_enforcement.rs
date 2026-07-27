// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Integration tests for graph-owned lease and intent enforcement.
//!
//! These tests verify the concurrency invariants from the
//! high-parallelism-concurrency ADR:
//! - hard leases block overlapping mutations
//! - disjoint scopes proceed safely
//! - own-session intents don't self-block
//! - soft leases produce warnings but allow mutation

use std::path::PathBuf;

use kin_daemon::session_registry::IntentRegistrationResult;
use kin_daemon::traffic_adapter::CoordinatorTrafficChecker;
use kin_daemon::SessionCoordinator;
use kin_model::session::{IntentScope, LockType, SessionCapabilities, SessionTransport};
use kin_model::{EntityId, SessionId};
use kin_reconcile::collision::{CollisionCheck, TrafficChecker};

use crate::helpers::init_kin_repo;

fn writable_capabilities() -> SessionCapabilities {
    SessionCapabilities {
        can_write: true,
        ..SessionCapabilities::default()
    }
}

// -----------------------------------------------------------------------
// 1. CoordinatorTrafficChecker blocks hard-locked scope
// -----------------------------------------------------------------------

#[test]
fn coordinator_checker_blocks_hard_locked_scope() {
    let (_dir, graph, _genesis_id) = init_kin_repo();
    let coord = SessionCoordinator::new(graph.clone());

    let s1 = coord
        .register_session(
            "claude",
            "agent-alpha",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/project"),
            writable_capabilities(),
        )
        .unwrap();

    let s2 = coord
        .register_session(
            "cursor",
            "agent-beta",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/project"),
            SessionCapabilities::default(),
        )
        .unwrap();

    let entity_id = EntityId::new();

    // Session 1 takes a hard lock on the entity.
    let registration = coord
        .register_intent(
            &s1,
            vec![IntentScope::Entity(entity_id)],
            LockType::Hard,
            "refactoring target function",
            None,
        )
        .unwrap();
    assert!(matches!(
        registration,
        IntentRegistrationResult::Registered { .. }
    ));

    // Session 2 tries to check traffic on the same scope.
    let checker = CoordinatorTrafficChecker::new(graph.clone());
    let result = checker
        .check_collisions(&IntentScope::Entity(entity_id), Some(&s2))
        .unwrap();

    match result {
        CollisionCheck::Blocked {
            blocking_intents, ..
        } => {
            assert_eq!(blocking_intents.len(), 1);
            assert_eq!(blocking_intents[0].session_id, s1);
            assert_eq!(blocking_intents[0].lock_type, LockType::Hard);
        }
        other => panic!("expected Blocked, got: {:?}", other),
    }
}

// -----------------------------------------------------------------------
// 2. Disjoint scopes proceed without blocking
// -----------------------------------------------------------------------

#[test]
fn coordinator_checker_allows_disjoint_scopes() {
    let (_dir, graph, _genesis_id) = init_kin_repo();
    let coord = SessionCoordinator::new(graph.clone());

    let s1 = coord
        .register_session(
            "claude",
            "agent-alpha",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/project"),
            writable_capabilities(),
        )
        .unwrap();

    let entity_a = EntityId::new();
    let entity_b = EntityId::new();

    // Session 1 hard-locks entity A.
    let registration = coord
        .register_intent(
            &s1,
            vec![IntentScope::Entity(entity_a)],
            LockType::Hard,
            "working on entity A",
            None,
        )
        .unwrap();
    assert!(matches!(
        registration,
        IntentRegistrationResult::Registered { .. }
    ));

    // Check traffic on entity B — should be clear.
    let checker = CoordinatorTrafficChecker::new(graph.clone());
    let s2 = SessionId::new();
    let result = checker
        .check_collisions(&IntentScope::Entity(entity_b), Some(&s2))
        .unwrap();

    assert!(
        matches!(result, CollisionCheck::Clear),
        "expected Clear for disjoint scope, got: {:?}",
        result,
    );
}

// -----------------------------------------------------------------------
// 3. Own-session intents don't self-block
// -----------------------------------------------------------------------

#[test]
fn coordinator_checker_allows_own_session() {
    let (_dir, graph, _genesis_id) = init_kin_repo();
    let coord = SessionCoordinator::new(graph.clone());

    let s1 = coord
        .register_session(
            "claude",
            "agent-alpha",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/project"),
            writable_capabilities(),
        )
        .unwrap();

    let entity_id = EntityId::new();

    // Session 1 hard-locks the entity.
    let registration = coord
        .register_intent(
            &s1,
            vec![IntentScope::Entity(entity_id)],
            LockType::Hard,
            "working on this entity",
            None,
        )
        .unwrap();
    assert!(matches!(
        registration,
        IntentRegistrationResult::Registered { .. }
    ));

    // Session 1 checks traffic on the same entity — should NOT be blocked.
    let checker = CoordinatorTrafficChecker::new(graph.clone());
    let result = checker
        .check_collisions(&IntentScope::Entity(entity_id), Some(&s1))
        .unwrap();

    assert!(
        matches!(result, CollisionCheck::Clear),
        "own session should not self-block, got: {:?}",
        result,
    );
}

// -----------------------------------------------------------------------
// 4. Soft leases produce warnings but allow mutation
// -----------------------------------------------------------------------

#[test]
fn coordinator_checker_warns_on_soft_lease() {
    let (_dir, graph, _genesis_id) = init_kin_repo();
    let coord = SessionCoordinator::new(graph.clone());

    let s1 = coord
        .register_session(
            "claude",
            "agent-alpha",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/project"),
            SessionCapabilities::default(),
        )
        .unwrap();

    let entity_id = EntityId::new();

    // Session 1 takes a soft lock on the entity.
    let registration = coord
        .register_intent(
            &s1,
            vec![IntentScope::Entity(entity_id)],
            LockType::Soft,
            "reviewing this entity",
            None,
        )
        .unwrap();
    assert!(matches!(
        registration,
        IntentRegistrationResult::Registered { .. }
    ));

    // Another session checks traffic — should get warnings, not blocked.
    let checker = CoordinatorTrafficChecker::new(graph.clone());
    let s2 = SessionId::new();
    let result = checker
        .check_collisions(&IntentScope::Entity(entity_id), Some(&s2))
        .unwrap();

    match result {
        CollisionCheck::Warnings(warnings) => {
            assert_eq!(warnings.len(), 1);
            assert_eq!(warnings[0].lock_type, LockType::Soft);
        }
        other => panic!("expected Warnings, got: {:?}", other),
    }
}
