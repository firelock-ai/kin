use kin_model::{
    EntityId, FilePathId, Intent, IntentConflict, IntentScope, IntentSummary, LockType, SessionId,
};

/// Result of a pre-write collision check.
#[derive(Debug)]
pub enum CollisionCheck {
    /// No traffic on the target scope. Proceed normally.
    Clear,
    /// Soft locks or downstream warnings exist. Mutation is allowed
    /// but the caller should surface these warnings.
    Warnings(Vec<IntentSummary>),
    /// A hard lock blocks the mutation. The caller must reject.
    Blocked {
        conflict: IntentConflict,
        blocking_intents: Vec<IntentSummary>,
    },
}

/// Trait for checking traffic/collision on a scope before mutations.
///
/// Implementations query the session/intent registry to determine
/// whether a mutation to the given scope is allowed.
pub trait TrafficChecker: Send + Sync {
    /// Check whether a mutation to the given scope is blocked by active intents.
    ///
    /// `requesting_session` is the session performing the mutation (if known).
    /// Intents from the same session do not block themselves.
    fn check_collisions(
        &self,
        scope: &IntentScope,
        requesting_session: Option<&SessionId>,
    ) -> std::result::Result<CollisionCheck, String>;
}

/// Check whether a mutation to the given entity is blocked by active intents.
///
/// This is the core pre-write collision check called before any overlay
/// mutation or file-save mutation in the reconciler.
///
/// Rules (from PLAN_P2 Section 4.7):
/// - Hard-locked by another session -> reject with HardCollision
/// - Soft-locked or downstream warnings -> allow but attach warnings
/// - No traffic -> proceed normally
pub fn check_entity_collision(
    entity_id: &EntityId,
    caller_session: &SessionId,
    active_intents: &[Intent],
) -> CollisionCheck {
    let scope = IntentScope::Entity(*entity_id);
    check_scope_collision(&scope, caller_session, active_intents)
}

/// Check whether a mutation to the given file is blocked by active intents.
pub fn check_file_collision(
    file_id: &FilePathId,
    caller_session: &SessionId,
    active_intents: &[Intent],
) -> CollisionCheck {
    let scope = IntentScope::Artifact(file_id.clone());
    check_scope_collision(&scope, caller_session, active_intents)
}

/// Core collision check against a specific scope.
fn check_scope_collision(
    target: &IntentScope,
    caller_session: &SessionId,
    active_intents: &[Intent],
) -> CollisionCheck {
    let mut hard_blockers = Vec::new();
    let mut soft_warnings = Vec::new();

    for intent in active_intents {
        // Skip intents from the same session (you can't block yourself).
        if &intent.session_id == caller_session {
            continue;
        }

        // Check if any of the intent's scopes overlap with our target.
        let overlaps = intent.scopes.iter().any(|s| s == target);
        if !overlaps {
            continue;
        }

        let summary = IntentSummary {
            intent_id: intent.intent_id,
            session_id: intent.session_id,
            vendor: String::new(), // Populated by caller with session info.
            task_description: intent.task_description.clone(),
            lock_type: intent.lock_type,
            registered_at: intent.registered_at.clone(),
        };

        match intent.lock_type {
            LockType::Hard => hard_blockers.push(summary),
            LockType::Soft => soft_warnings.push(summary),
        }
    }

    if !hard_blockers.is_empty() {
        CollisionCheck::Blocked {
            conflict: IntentConflict::HardCollision,
            blocking_intents: hard_blockers,
        }
    } else if !soft_warnings.is_empty() {
        CollisionCheck::Warnings(soft_warnings)
    } else {
        CollisionCheck::Clear
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{IntentId, Timestamp};

    fn make_intent(
        session: SessionId,
        scope: IntentScope,
        lock: LockType,
    ) -> Intent {
        Intent {
            intent_id: IntentId::new(),
            session_id: session,
            scopes: vec![scope],
            lock_type: lock,
            task_description: "test task".into(),
            registered_at: Timestamp::now(),
            expires_at: None,
        }
    }

    #[test]
    fn clear_when_no_intents() {
        let entity_id = EntityId::new();
        let session = SessionId::new();
        let result = check_entity_collision(&entity_id, &session, &[]);
        assert!(matches!(result, CollisionCheck::Clear));
    }

    #[test]
    fn clear_when_only_own_intents() {
        let entity_id = EntityId::new();
        let session = SessionId::new();
        let intent = make_intent(
            session,
            IntentScope::Entity(entity_id),
            LockType::Hard,
        );
        let result = check_entity_collision(&entity_id, &session, &[intent]);
        assert!(matches!(result, CollisionCheck::Clear));
    }

    #[test]
    fn blocked_by_hard_lock() {
        let entity_id = EntityId::new();
        let my_session = SessionId::new();
        let other_session = SessionId::new();
        let intent = make_intent(
            other_session,
            IntentScope::Entity(entity_id),
            LockType::Hard,
        );
        let result = check_entity_collision(&entity_id, &my_session, &[intent]);
        match result {
            CollisionCheck::Blocked { conflict, blocking_intents } => {
                assert_eq!(conflict, IntentConflict::HardCollision);
                assert_eq!(blocking_intents.len(), 1);
                assert_eq!(blocking_intents[0].session_id, other_session);
            }
            _ => panic!("expected Blocked"),
        }
    }

    #[test]
    fn warning_from_soft_lock() {
        let entity_id = EntityId::new();
        let my_session = SessionId::new();
        let other_session = SessionId::new();
        let intent = make_intent(
            other_session,
            IntentScope::Entity(entity_id),
            LockType::Soft,
        );
        let result = check_entity_collision(&entity_id, &my_session, &[intent]);
        match result {
            CollisionCheck::Warnings(warnings) => {
                assert_eq!(warnings.len(), 1);
                assert_eq!(warnings[0].lock_type, LockType::Soft);
            }
            _ => panic!("expected Warnings"),
        }
    }

    #[test]
    fn hard_lock_takes_priority_over_soft() {
        let entity_id = EntityId::new();
        let my_session = SessionId::new();
        let other1 = SessionId::new();
        let other2 = SessionId::new();

        let hard = make_intent(other1, IntentScope::Entity(entity_id), LockType::Hard);
        let soft = make_intent(other2, IntentScope::Entity(entity_id), LockType::Soft);

        let result = check_entity_collision(&entity_id, &my_session, &[hard, soft]);
        assert!(matches!(result, CollisionCheck::Blocked { .. }));
    }

    #[test]
    fn clear_when_different_scope() {
        let entity_a = EntityId::new();
        let entity_b = EntityId::new();
        let my_session = SessionId::new();
        let other_session = SessionId::new();

        // Other session locks entity B, we're modifying entity A.
        let intent = make_intent(
            other_session,
            IntentScope::Entity(entity_b),
            LockType::Hard,
        );
        let result = check_entity_collision(&entity_a, &my_session, &[intent]);
        assert!(matches!(result, CollisionCheck::Clear));
    }

    #[test]
    fn file_collision_check() {
        let file_id = FilePathId::new("src/main.rs");
        let my_session = SessionId::new();
        let other_session = SessionId::new();

        let intent = make_intent(
            other_session,
            IntentScope::Artifact(file_id.clone()),
            LockType::Hard,
        );
        let result = check_file_collision(&file_id, &my_session, &[intent]);
        assert!(matches!(result, CollisionCheck::Blocked { .. }));
    }

    #[test]
    fn multiple_soft_warnings() {
        let entity_id = EntityId::new();
        let my_session = SessionId::new();
        let other1 = SessionId::new();
        let other2 = SessionId::new();

        let soft1 = make_intent(other1, IntentScope::Entity(entity_id), LockType::Soft);
        let soft2 = make_intent(other2, IntentScope::Entity(entity_id), LockType::Soft);

        let result = check_entity_collision(&entity_id, &my_session, &[soft1, soft2]);
        match result {
            CollisionCheck::Warnings(warnings) => {
                assert_eq!(warnings.len(), 2);
            }
            _ => panic!("expected Warnings"),
        }
    }
}
