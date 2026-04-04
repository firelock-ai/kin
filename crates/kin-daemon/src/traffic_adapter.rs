// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::sync::Arc;

use kin_model::session::{IntentScope, LockType};
use kin_model::{SessionId, SessionStore};
use kin_reconcile::collision::{CollisionCheck, TrafficChecker};

/// Adapter that bridges the reconciler's [`TrafficChecker`] trait to the
/// daemon's authoritative intent store (the graph).
///
/// This is the production implementation used when the daemon starts.
/// It queries active intents directly from `InMemoryGraph` and returns
/// collision results that the reconciler uses to block or warn before
/// mutations.
pub struct CoordinatorTrafficChecker {
    graph: Arc<kin_db::InMemoryGraph>,
}

impl CoordinatorTrafficChecker {
    pub fn new(graph: Arc<kin_db::InMemoryGraph>) -> Self {
        Self { graph }
    }
}

impl TrafficChecker for CoordinatorTrafficChecker {
    fn check_collisions(
        &self,
        scope: &IntentScope,
        requesting_session: Option<&SessionId>,
    ) -> Result<CollisionCheck, String> {
        let intents = self
            .graph
            .list_all_intents()
            .map_err(|e| format!("failed to list intents: {e}"))?;

        let mut hard_blockers = Vec::new();
        let mut soft_warnings = Vec::new();

        for intent in &intents {
            if let Some(caller) = requesting_session {
                if &intent.session_id == caller {
                    continue;
                }
            }

            let overlaps = intent.scopes.iter().any(|s| s == scope);
            if !overlaps {
                continue;
            }

            let summary = kin_model::session::IntentSummary {
                intent_id: intent.intent_id,
                session_id: intent.session_id,
                vendor: String::new(),
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
            Ok(CollisionCheck::Blocked {
                conflict: kin_model::session::IntentConflict::HardCollision,
                blocking_intents: hard_blockers,
            })
        } else if !soft_warnings.is_empty() {
            Ok(CollisionCheck::Warnings(soft_warnings))
        } else {
            Ok(CollisionCheck::Clear)
        }
    }
}
