// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing::{debug, info, warn};

use kin_model::ids::{ContractId, EntityId, FilePathId, IntentId, SessionId};
use kin_model::session::{
    AgentSession, Intent, IntentScope, IntentSummary, LockType, SessionCapabilities,
    SessionTransport, TrafficReport,
};
use kin_model::timestamp::Timestamp;
use kin_model::{EntityFilter, EntityStore, SessionStore};

use crate::error::{DaemonError, Result};

/// Outcome of an intent registration attempt.
#[derive(Debug)]
pub enum IntentRegistrationResult {
    /// Intent registered successfully. May include downstream warnings.
    Registered {
        intent_id: IntentId,
        downstream_warnings: Vec<IntentSummary>,
        policy_warnings: Vec<String>,
    },
    /// Registration blocked by a hard collision.
    Blocked {
        intent_id: IntentId,
        conflicts: Vec<IntentSummary>,
    },
    /// Registration rejected because the session has reached the concurrency
    /// limit it declared at session start.
    LimitExceeded {
        intent_id: IntentId,
        active: usize,
        limit: usize,
    },
    /// A hard intent can block other writers, so only a session that declared
    /// write capability may register one.
    CapabilityDenied {
        intent_id: IntentId,
        capability: &'static str,
    },
}

/// Traffic check result for a set of scopes.
#[derive(Debug)]
pub struct TrafficCheck {
    /// Reports per queried scope.
    pub reports: Vec<TrafficReport>,
    /// Whether any hard blocks exist.
    pub has_hard_blocks: bool,
}

/// Session and intent coordinator backed by the graph store.
///
/// All operations go through `kin_db::InMemoryGraph`, which is the authoritative
/// source for transient session/intent state. This struct provides the
/// higher-level lifecycle operations described in PLAN_P2.md Section 4.7.
pub struct SessionCoordinator {
    graph: Arc<kin_db::InMemoryGraph>,
    /// Linearization point for session/intent lifecycle mutations. `kin-db`'s
    /// public `SessionStore` API exposes individual CRUD calls, so the
    /// conflict-check + limit-check + insert sequence must be serialized here
    /// at the owning coordinator boundary rather than performed as racy reads
    /// followed by a later write.
    arbitration: Mutex<()>,
    /// Heartbeat interval used for stale-session detection.
    heartbeat_interval: Duration,
}

impl SessionCoordinator {
    /// Create a new coordinator backed by the given graph store.
    pub fn new(graph: Arc<kin_db::InMemoryGraph>) -> Self {
        Self {
            graph,
            arbitration: Mutex::new(()),
            heartbeat_interval: Duration::from_secs(30),
        }
    }

    /// Create a coordinator with a custom heartbeat interval (useful for testing).
    pub fn with_heartbeat_interval(graph: Arc<kin_db::InMemoryGraph>, interval: Duration) -> Self {
        Self {
            graph,
            arbitration: Mutex::new(()),
            heartbeat_interval: interval,
        }
    }

    // -----------------------------------------------------------------------
    // Session lifecycle
    // -----------------------------------------------------------------------

    /// Register a new agent session. Returns the session ID.
    pub fn register_session(
        &self,
        vendor: &str,
        client_name: &str,
        transport: SessionTransport,
        pid: Option<u32>,
        cwd: PathBuf,
        capabilities: SessionCapabilities,
    ) -> Result<SessionId> {
        let session_id = SessionId::new();
        let now = Timestamp::now();
        let session = AgentSession {
            session_id,
            vendor: vendor.to_string(),
            client_name: client_name.to_string(),
            transport,
            pid,
            cwd,
            started_at: now.clone(),
            last_heartbeat: now,
            capabilities,
        };

        self.graph
            .upsert_session(&session)
            .map_err(DaemonError::from)?;
        info!(
            session_id = %session_id,
            vendor = vendor,
            transport = ?transport,
            "registered agent session"
        );

        Ok(session_id)
    }

    /// Record a heartbeat for a session. Returns an error if the session
    /// doesn't exist.
    pub fn heartbeat(&self, session_id: &SessionId) -> Result<()> {
        // Verify the session exists.
        let session = self
            .graph
            .get_session(session_id)
            .map_err(DaemonError::from)?;
        if session.is_none() {
            return Err(DaemonError::Graph(kin_db::KinDbError::NotFound(format!(
                "session not found: {}",
                session_id
            ))));
        }

        let now = Timestamp::now();
        self.graph
            .update_heartbeat(session_id, &now)
            .map_err(DaemonError::from)?;
        debug!(session_id = %session_id, "heartbeat recorded");
        Ok(())
    }

    /// Deregister a session and clean up all its intents.
    pub fn deregister_session(&self, session_id: &SessionId) -> Result<()> {
        let _arbitration = self
            .arbitration
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for intent in self.list_intents(session_id)? {
            self.graph
                .delete_intent(&intent.intent_id)
                .map_err(DaemonError::from)?;
        }
        self.graph
            .delete_session(session_id)
            .map_err(DaemonError::from)?;
        info!(session_id = %session_id, "deregistered agent session");
        Ok(())
    }

    /// Get a session by ID.
    pub fn get_session(&self, session_id: &SessionId) -> Result<Option<AgentSession>> {
        self.graph
            .get_session(session_id)
            .map_err(DaemonError::from)
    }

    /// List all active sessions.
    pub fn list_sessions(&self) -> Result<Vec<AgentSession>> {
        self.graph.list_sessions().map_err(DaemonError::from)
    }

    // -----------------------------------------------------------------------
    // Intent registration and arbitration
    // -----------------------------------------------------------------------

    /// Register an intent for a session.
    ///
    /// Follows the lifecycle from PLAN_P2.md Section 4.7:
    /// 1. Validate that the session exists
    /// 2. Check for hard collisions on each scope
    /// 3. Create the intent (even if collisions found for soft locks)
    /// 4. Compute downstream warnings via graph traversal
    /// 5. Return the result
    pub fn register_intent(
        &self,
        session_id: &SessionId,
        scopes: Vec<IntentScope>,
        lock_type: LockType,
        task_description: &str,
        expires_at: Option<Timestamp>,
    ) -> Result<IntentRegistrationResult> {
        self.register_intent_with_mode(
            session_id,
            scopes,
            lock_type,
            task_description,
            expires_at,
            kin_mcp::CoordinationEnforcementMode::from_env(),
        )
    }

    /// Register an intent under an explicit coordination mode. The daemon uses
    /// its startup-captured mode so an in-flight request cannot observe a
    /// process-environment change; the compatibility wrapper above remains for
    /// in-process callers.
    pub fn register_intent_with_mode(
        &self,
        session_id: &SessionId,
        scopes: Vec<IntentScope>,
        lock_type: LockType,
        task_description: &str,
        expires_at: Option<Timestamp>,
        mode: kin_mcp::CoordinationEnforcementMode,
    ) -> Result<IntentRegistrationResult> {
        // This guard is the linearization point for the whole arbitration
        // decision. Concurrent hard registrations cannot both observe an
        // empty conflict set, and a release/deregister cannot race the session
        // limit check.
        let _arbitration = self
            .arbitration
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // 1. Validate session exists.
        let session = self
            .graph
            .get_session(session_id)
            .map_err(DaemonError::from)?;
        let session = session.ok_or_else(|| {
            DaemonError::Graph(kin_db::KinDbError::NotFound(format!(
                "session not found: {}",
                session_id
            )))
        })?;

        let intent_id = IntentId::new();
        let now = Timestamp::now();

        let mut policy_warnings = Vec::new();
        if lock_type == LockType::Hard && !session.capabilities.can_write {
            if mode.is_enforcing() {
                return Ok(IntentRegistrationResult::CapabilityDenied {
                    intent_id,
                    capability: "can_write",
                });
            }
            if mode.evaluates() {
                policy_warnings.push(
                    "hard intent requires can_write=true; registration would be denied in enforce mode"
                        .to_string(),
                );
            }
        }

        let now_for_expiry = Timestamp::now();
        let active = self
            .graph
            .list_intents_for_session(session_id)
            .map_err(DaemonError::from)?
            .into_iter()
            .filter(|intent| {
                intent
                    .expires_at
                    .as_ref()
                    .is_none_or(|expires_at| expires_at >= &now_for_expiry)
            })
            .count();
        let limit = session.capabilities.max_concurrent_intents;
        if active >= limit {
            if mode.is_enforcing() {
                return Ok(IntentRegistrationResult::LimitExceeded {
                    intent_id,
                    active,
                    limit,
                });
            }
            if mode.evaluates() {
                policy_warnings.push(format!(
                    "active intent count {active} reached max_concurrent_intents={limit}; registration would be denied in enforce mode"
                ));
            }
        }

        // 2. Check for hard collisions on all scope types.
        let mut all_conflicts = Vec::new();
        for scope in &scopes {
            match scope {
                IntentScope::Entity(entity_id) => {
                    let collisions = self
                        .graph
                        .hard_collisions_for_entity(entity_id, &intent_id)
                        .map_err(DaemonError::from)?;
                    for collision in &collisions {
                        if collision
                            .expires_at
                            .as_ref()
                            .is_some_and(|expires_at| expires_at < &now)
                        {
                            continue;
                        }
                        // A session's own intent is not a collision: own-write
                        // exclusion is the invariant used by every apply path.
                        if collision.session_id == *session_id {
                            continue;
                        }
                        let col_session = self
                            .graph
                            .get_session(&collision.session_id)
                            .map_err(DaemonError::from)?;
                        let vendor = col_session.map(|s| s.vendor).unwrap_or_default();
                        all_conflicts.push(IntentSummary {
                            intent_id: collision.intent_id,
                            session_id: collision.session_id,
                            vendor,
                            task_description: collision.task_description.clone(),
                            lock_type: collision.lock_type,
                            registered_at: collision.registered_at.clone(),
                        });
                    }
                }
                IntentScope::Contract(_) | IntentScope::Artifact(_) => {
                    // For Contract and Artifact scopes, check all intents
                    // for matching scopes since there are no graph edges.
                    let conflicts = self.find_scope_conflicts(scope, session_id, &intent_id)?;
                    all_conflicts.extend(conflicts);
                }
            }
        }

        // If registering a hard lock and there are hard collisions, block.
        all_conflicts.sort_by_key(|conflict| conflict.intent_id.to_string());
        all_conflicts.dedup_by_key(|conflict| conflict.intent_id);
        if lock_type == LockType::Hard && !all_conflicts.is_empty() {
            return Ok(IntentRegistrationResult::Blocked {
                intent_id,
                conflicts: all_conflicts,
            });
        }

        // 3. Create the intent.
        let intent = Intent {
            intent_id,
            session_id: *session_id,
            scopes: scopes.clone(),
            lock_type,
            task_description: task_description.to_string(),
            registered_at: now,
            expires_at,
        };
        self.graph
            .register_intent(&intent)
            .map_err(DaemonError::from)?;

        // 4. Compute downstream warnings via graph traversal.
        let mut downstream_warnings = Vec::new();
        if lock_type == LockType::Hard {
            for scope in &scopes {
                match scope {
                    IntentScope::Entity(entity_id) => {
                        // Get downstream impact from the graph.
                        let downstream = self
                            .graph
                            .get_downstream_impact(entity_id, 3)
                            .map_err(DaemonError::from)?;

                        for affected in &downstream {
                            self.graph
                                .create_downstream_warning(&intent_id, &affected.id, "Entity")
                                .map_err(DaemonError::from)?;
                        }

                        self.collect_downstream_intent_warnings(
                            &intent_id,
                            &downstream,
                            &mut downstream_warnings,
                        )?;
                    }
                    IntentScope::Contract(contract_id) => {
                        // For contracts, find entities that reference this contract
                        // (producers and consumers) and treat them as downstream.
                        let downstream = self.entities_for_contract(contract_id)?;

                        for affected in &downstream {
                            self.graph
                                .create_downstream_warning(&intent_id, &affected.id, "Contract")
                                .map_err(DaemonError::from)?;
                        }

                        self.collect_downstream_intent_warnings(
                            &intent_id,
                            &downstream,
                            &mut downstream_warnings,
                        )?;
                    }
                    IntentScope::Artifact(file_id) => {
                        // For artifacts, find entities contained in that file
                        // and treat them as downstream.
                        let downstream = self.entities_for_file(file_id)?;

                        for affected in &downstream {
                            self.graph
                                .create_downstream_warning(&intent_id, &affected.id, "Artifact")
                                .map_err(DaemonError::from)?;
                        }

                        self.collect_downstream_intent_warnings(
                            &intent_id,
                            &downstream,
                            &mut downstream_warnings,
                        )?;
                    }
                }
            }
        }

        info!(
            intent_id = %intent_id,
            session_id = %session_id,
            lock_type = ?lock_type,
            scopes = scopes.len(),
            "registered intent"
        );

        Ok(IntentRegistrationResult::Registered {
            intent_id,
            downstream_warnings,
            policy_warnings,
        })
    }

    /// Release (delete) an intent.
    pub fn release_intent(&self, session_id: &SessionId, intent_id: &IntentId) -> Result<()> {
        let _arbitration = self
            .arbitration
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Verify the intent belongs to this session.
        let intent = self
            .graph
            .get_intent(intent_id)
            .map_err(DaemonError::from)?;
        match intent {
            Some(i) if i.session_id == *session_id => {}
            Some(_) => {
                return Err(DaemonError::Graph(kin_db::KinDbError::NotFound(format!(
                    "intent {} does not belong to session {}",
                    intent_id, session_id
                ))));
            }
            None => {
                return Err(DaemonError::Graph(kin_db::KinDbError::NotFound(format!(
                    "intent not found: {}",
                    intent_id
                ))));
            }
        }

        self.graph
            .delete_intent(intent_id)
            .map_err(DaemonError::from)?;
        info!(intent_id = %intent_id, session_id = %session_id, "released intent");
        Ok(())
    }

    /// Check traffic on a set of scopes.
    ///
    /// Returns a `TrafficCheck` with per-scope reports and an overall
    /// hard-block indicator.
    pub fn check_traffic(&self, scopes: &[IntentScope]) -> Result<TrafficCheck> {
        let mut reports = Vec::new();
        let mut has_hard_blocks = false;

        for scope in scopes {
            match scope {
                IntentScope::Entity(entity_id) => {
                    let active = self
                        .graph
                        .locks_for_entity(entity_id)
                        .map_err(DaemonError::from)?;
                    let downstream = self
                        .graph
                        .downstream_warnings_for_entity(entity_id)
                        .map_err(DaemonError::from)?;

                    let active_summaries = self.intents_to_summaries(&active);
                    let downstream_summaries = self.intents_to_summaries(&downstream);

                    if active_summaries
                        .iter()
                        .any(|s| s.lock_type == LockType::Hard)
                    {
                        has_hard_blocks = true;
                    }

                    reports.push(TrafficReport {
                        target: scope.clone(),
                        active_intents: active_summaries,
                        downstream_warnings: downstream_summaries,
                    });
                }
                IntentScope::Contract(contract_id) => {
                    // Find intents that lock the same ContractId.
                    let active = self.intents_matching_scope(scope)?;

                    // For downstream: find entities that reference this contract.
                    let downstream_entities = self.entities_for_contract(contract_id)?;
                    let mut downstream_intents = Vec::new();
                    for entity in &downstream_entities {
                        let locks = self
                            .graph
                            .locks_for_entity(&entity.id)
                            .map_err(DaemonError::from)?;
                        downstream_intents.extend(locks);
                    }

                    let active_summaries = self.intents_to_summaries(&active);
                    let downstream_summaries = self.intents_to_summaries(&downstream_intents);

                    if active_summaries
                        .iter()
                        .any(|s| s.lock_type == LockType::Hard)
                    {
                        has_hard_blocks = true;
                    }

                    reports.push(TrafficReport {
                        target: scope.clone(),
                        active_intents: active_summaries,
                        downstream_warnings: downstream_summaries,
                    });
                }
                IntentScope::Artifact(file_id) => {
                    // Find intents that lock the same file path.
                    let active = self.intents_matching_scope(scope)?;

                    // For downstream: find entities contained in that file.
                    let downstream_entities = self.entities_for_file(file_id)?;
                    let mut downstream_intents = Vec::new();
                    for entity in &downstream_entities {
                        let locks = self
                            .graph
                            .locks_for_entity(&entity.id)
                            .map_err(DaemonError::from)?;
                        downstream_intents.extend(locks);
                    }

                    let active_summaries = self.intents_to_summaries(&active);
                    let downstream_summaries = self.intents_to_summaries(&downstream_intents);

                    if active_summaries
                        .iter()
                        .any(|s| s.lock_type == LockType::Hard)
                    {
                        has_hard_blocks = true;
                    }

                    reports.push(TrafficReport {
                        target: scope.clone(),
                        active_intents: active_summaries,
                        downstream_warnings: downstream_summaries,
                    });
                }
            }
        }

        Ok(TrafficCheck {
            reports,
            has_hard_blocks,
        })
    }

    /// List all intents for a given session.
    pub fn list_intents(&self, session_id: &SessionId) -> Result<Vec<Intent>> {
        let mut intents = self
            .graph
            .list_intents_for_session(session_id)
            .map_err(DaemonError::from)?;
        intents.sort_by_key(|intent| intent.intent_id.to_string());
        Ok(intents)
    }

    /// Sweep expired intents from the graph.
    ///
    /// Removes any intent whose `expires_at` is in the past. Returns the
    /// number of intents reaped. Call this periodically (e.g. from the
    /// reconcile loop tick) to prevent stale leases from blocking work.
    pub fn sweep_expired_intents(&self) -> Result<usize> {
        Ok(self.sweep_expired_intents_detailed()?.len())
    }

    /// Sweep expired intents and return the removed records so the daemon can
    /// emit a complete durable lifecycle event for each release.
    pub fn sweep_expired_intents_detailed(&self) -> Result<Vec<Intent>> {
        self.sweep_expired_intents_with_reservation(|_| Ok(()))
    }

    pub fn sweep_expired_intents_with_reservation<F>(&self, mut reserve: F) -> Result<Vec<Intent>>
    where
        F: FnMut(&Intent) -> std::io::Result<()>,
    {
        let _arbitration = self
            .arbitration
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Timestamp::now();
        let mut all_intents = self.graph.list_all_intents().map_err(DaemonError::from)?;
        all_intents.sort_by_key(|intent| intent.intent_id.to_string());
        let mut reaped = Vec::new();

        for intent in &all_intents {
            if let Some(ref expires_at) = intent.expires_at {
                if expires_at < &now {
                    reserve(intent)?;
                    if let Err(e) = self.graph.delete_intent(&intent.intent_id) {
                        warn!(
                            intent_id = %intent.intent_id,
                            error = %e,
                            "failed to reap expired intent"
                        );
                        return Err(DaemonError::from(e));
                    } else {
                        info!(
                            intent_id = %intent.intent_id,
                            session_id = %intent.session_id,
                            "reaped expired intent"
                        );
                        reaped.push(intent.clone());
                    }
                }
            }
        }

        reaped.sort_by_key(|intent| intent.intent_id.to_string());
        Ok(reaped)
    }

    // -----------------------------------------------------------------------
    // Scope helpers
    // -----------------------------------------------------------------------

    /// Find hard-lock collisions for a Contract or Artifact scope by scanning
    /// all intents. Returns IntentSummary entries for conflicting hard locks.
    fn find_scope_conflicts(
        &self,
        target_scope: &IntentScope,
        caller_session: &SessionId,
        exclude_intent: &IntentId,
    ) -> Result<Vec<IntentSummary>> {
        let all_intents = self.graph.list_all_intents().map_err(DaemonError::from)?;
        let mut conflicts = Vec::new();
        let now = Timestamp::now();

        for intent in &all_intents {
            if intent
                .expires_at
                .as_ref()
                .is_some_and(|expires_at| expires_at < &now)
            {
                continue;
            }
            if &intent.session_id == caller_session {
                continue;
            }
            if &intent.intent_id == exclude_intent {
                continue;
            }
            if intent.lock_type != LockType::Hard {
                continue;
            }
            if intent.scopes.contains(target_scope) {
                let vendor = self
                    .graph
                    .get_session(&intent.session_id)
                    .ok()
                    .flatten()
                    .map(|s| s.vendor)
                    .unwrap_or_default();
                conflicts.push(IntentSummary {
                    intent_id: intent.intent_id,
                    session_id: intent.session_id,
                    vendor,
                    task_description: intent.task_description.clone(),
                    lock_type: intent.lock_type,
                    registered_at: intent.registered_at.clone(),
                });
            }
        }

        Ok(conflicts)
    }

    /// Find all intents whose scopes contain the given scope target.
    fn intents_matching_scope(&self, target: &IntentScope) -> Result<Vec<Intent>> {
        let all_intents = self.graph.list_all_intents().map_err(DaemonError::from)?;
        Ok(all_intents
            .into_iter()
            .filter(|i| i.scopes.contains(target))
            .collect())
    }

    /// Find entities that reference a given contract (producers + consumers).
    ///
    /// Queries all entities and checks if any have relations to the contract.
    /// Since contracts store producers/consumers as EntityId lists, we scan
    /// all entities and check file_origin/relations.
    fn entities_for_contract(&self, _contract_id: &ContractId) -> Result<Vec<kin_model::Entity>> {
        // The Contract type uses EntityId as its primary id (see contract.rs).
        // Entities related to a contract appear as producers/consumers.
        // Since we don't have a direct graph query for contract->entity,
        // we use the contract's EntityId to find downstream entities.
        let contract_entity_id = EntityId(_contract_id.0);
        self.graph
            .get_downstream_impact(&contract_entity_id, 2)
            .map_err(DaemonError::from)
    }

    /// Find entities contained in a given file.
    fn entities_for_file(&self, file_id: &FilePathId) -> Result<Vec<kin_model::Entity>> {
        let filter = EntityFilter {
            file_path: Some(file_id.clone()),
            ..Default::default()
        };
        self.graph
            .query_entities(&filter)
            .map_err(DaemonError::from)
    }

    /// Convert a slice of Intents to IntentSummary, looking up vendor names.
    fn intents_to_summaries(&self, intents: &[Intent]) -> Vec<IntentSummary> {
        intents
            .iter()
            .map(|i| {
                let vendor = self
                    .graph
                    .get_session(&i.session_id)
                    .ok()
                    .flatten()
                    .map(|s| s.vendor)
                    .unwrap_or_default();
                IntentSummary {
                    intent_id: i.intent_id,
                    session_id: i.session_id,
                    vendor,
                    task_description: i.task_description.clone(),
                    lock_type: i.lock_type,
                    registered_at: i.registered_at.clone(),
                }
            })
            .collect()
    }

    /// Collect downstream intent warnings: for each downstream entity,
    /// find intents that lock it and add them to the warnings list.
    fn collect_downstream_intent_warnings(
        &self,
        current_intent_id: &IntentId,
        downstream_entities: &[kin_model::Entity],
        warnings: &mut Vec<IntentSummary>,
    ) -> Result<()> {
        for affected in downstream_entities {
            let locks = self
                .graph
                .locks_for_entity(&affected.id)
                .map_err(DaemonError::from)?;
            for other_intent in locks {
                if other_intent.intent_id != *current_intent_id {
                    let other_session = self
                        .graph
                        .get_session(&other_intent.session_id)
                        .map_err(DaemonError::from)?;
                    let vendor = other_session.map(|s| s.vendor).unwrap_or_default();
                    warnings.push(IntentSummary {
                        intent_id: other_intent.intent_id,
                        session_id: other_intent.session_id,
                        vendor,
                        task_description: other_intent.task_description.clone(),
                        lock_type: other_intent.lock_type,
                        registered_at: other_intent.registered_at.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Orphan sweeper
    // -----------------------------------------------------------------------

    /// Sweep stale sessions.
    ///
    /// A session is stale if:
    /// - Its PID is set and the process is no longer alive, OR
    /// - It has missed two heartbeat intervals and no live PID can prove the
    ///   owning process is still active.
    ///
    /// Returns the number of sessions reaped.
    pub fn sweep_stale_sessions(&self) -> Result<usize> {
        Ok(self.sweep_stale_sessions_detailed()?.len())
    }

    /// Sweep stale sessions, deleting their intents before the session and
    /// returning the removed records for durable lifecycle logging.
    pub fn sweep_stale_sessions_detailed(&self) -> Result<Vec<(AgentSession, Vec<Intent>)>> {
        self.sweep_stale_sessions_with_reservation(|_, _| Ok(()))
    }

    pub fn sweep_stale_sessions_with_reservation<F>(
        &self,
        mut reserve: F,
    ) -> Result<Vec<(AgentSession, Vec<Intent>)>>
    where
        F: FnMut(&AgentSession, &[Intent]) -> std::io::Result<()>,
    {
        let _arbitration = self
            .arbitration
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut sessions = self.graph.list_sessions().map_err(DaemonError::from)?;
        sessions.sort_by_key(|session| session.session_id.to_string());
        let now = Timestamp::now();
        let stale_threshold = self.heartbeat_interval * 2;
        let mut reaped = Vec::new();

        for session in &sessions {
            let mut is_stale = false;
            let pid_alive = session.pid.map(|pid| (pid, is_process_alive(pid)));

            // Check if PID is alive first. A live PID is stronger evidence
            // than a missed heartbeat because long-running scoped operations
            // can legitimately block heartbeats for more than two intervals.
            if let Some((pid, false)) = pid_alive {
                debug!(
                    session_id = %session.session_id,
                    pid = pid,
                    "session PID is no longer alive"
                );
                is_stale = true;
            }

            // Check heartbeat staleness.
            if let Some(age) = timestamp_age(&session.last_heartbeat, &now) {
                if age > stale_threshold {
                    match pid_alive {
                        Some((pid, true)) => {
                            debug!(
                                session_id = %session.session_id,
                                vendor = %session.vendor,
                                age_secs = age.as_secs(),
                                pid = pid,
                                "session heartbeat is stale but PID is alive"
                            );
                        }
                        Some((_, false)) => {}
                        None => {
                            debug!(
                                session_id = %session.session_id,
                                vendor = %session.vendor,
                                age_secs = age.as_secs(),
                                "session heartbeat is stale and no PID is available"
                            );
                            is_stale = true;
                        }
                    }
                }
            }

            if is_stale {
                let mut intents = self
                    .graph
                    .list_intents_for_session(&session.session_id)
                    .map_err(DaemonError::from)?;
                intents.sort_by_key(|intent| intent.intent_id.to_string());
                reserve(session, &intents)?;
                for intent in &intents {
                    self.graph
                        .delete_intent(&intent.intent_id)
                        .map_err(DaemonError::from)?;
                }
                self.graph
                    .delete_session(&session.session_id)
                    .map_err(DaemonError::from)?;
                warn!(
                    session_id = %session.session_id,
                    vendor = %session.vendor,
                    "reaped stale agent session"
                );
                reaped.push((session.clone(), intents));
            }
        }

        if !reaped.is_empty() {
            info!(reaped = reaped.len(), "orphan sweep complete");
        }

        Ok(reaped)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the age of a timestamp relative to now.
/// Returns None if parsing fails.
fn timestamp_age(ts: &Timestamp, now: &Timestamp) -> Option<Duration> {
    // Timestamps are ISO-8601 strings. Parse them to compute duration.
    let ts_str = ts.to_string();
    let now_str = now.to_string();

    let ts_dt = chrono::DateTime::parse_from_rfc3339(&ts_str).ok()?;
    let now_dt = chrono::DateTime::parse_from_rfc3339(&now_str).ok()?;

    let diff = now_dt.signed_duration_since(ts_dt);
    if diff.num_milliseconds() >= 0 {
        Some(Duration::from_millis(diff.num_milliseconds() as u64))
    } else {
        Some(Duration::ZERO)
    }
}

/// Check if a process is alive by checking /proc or using kill -0.
fn is_process_alive(pid: u32) -> bool {
    // Use std::fs to check /proc on Linux, or signal 0 via Command on macOS/Unix.
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }
    #[cfg(target_os = "macos")]
    {
        // On macOS, use `kill -0 <pid>` via Command to avoid libc dependency.
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(true) // If we can't check, assume alive (conservative).
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // On unsupported platforms, assume alive (conservative).
        let _ = pid;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::ids::EntityId;

    fn make_coordinator() -> SessionCoordinator {
        let graph = Arc::new(kin_db::InMemoryGraph::new());
        SessionCoordinator::new(graph)
    }

    fn write_capabilities() -> SessionCapabilities {
        SessionCapabilities {
            can_write: true,
            ..SessionCapabilities::default()
        }
    }

    fn write_capabilities_with_limit(limit: usize) -> SessionCapabilities {
        SessionCapabilities {
            can_write: true,
            max_concurrent_intents: limit,
            ..SessionCapabilities::default()
        }
    }

    #[test]
    fn register_and_get_session() {
        let coord = make_coordinator();
        let sid = coord
            .register_session(
                "claude-code",
                "test-session",
                SessionTransport::Mcp,
                Some(std::process::id()),
                PathBuf::from("/project"),
                SessionCapabilities::default(),
            )
            .unwrap();

        let session = coord.get_session(&sid).unwrap().unwrap();
        assert_eq!(session.vendor, "claude-code");
        assert_eq!(session.transport, SessionTransport::Mcp);
    }

    #[test]
    fn heartbeat_updates() {
        let coord = make_coordinator();
        let sid = coord
            .register_session(
                "codex",
                "test",
                SessionTransport::Cli,
                None,
                PathBuf::from("/project"),
                SessionCapabilities::default(),
            )
            .unwrap();

        // Heartbeat should succeed.
        coord.heartbeat(&sid).unwrap();

        // Heartbeat on nonexistent session should fail.
        let fake = SessionId::new();
        assert!(coord.heartbeat(&fake).is_err());
    }

    #[test]
    fn deregister_session_cleans_up() {
        let coord = make_coordinator();
        let sid = coord
            .register_session(
                "gemini-cli",
                "test",
                SessionTransport::Wrapper,
                None,
                PathBuf::from("/project"),
                SessionCapabilities::default(),
            )
            .unwrap();

        coord.deregister_session(&sid).unwrap();
        assert!(coord.get_session(&sid).unwrap().is_none());
    }

    #[test]
    fn list_sessions_works() {
        let coord = make_coordinator();
        coord
            .register_session(
                "a",
                "s1",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                SessionCapabilities::default(),
            )
            .unwrap();
        coord
            .register_session(
                "b",
                "s2",
                SessionTransport::Cli,
                None,
                PathBuf::from("/"),
                SessionCapabilities::default(),
            )
            .unwrap();

        let sessions = coord.list_sessions().unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn register_intent_soft_lock() {
        let coord = make_coordinator();
        let sid = coord
            .register_session(
                "claude-code",
                "test",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                SessionCapabilities::default(),
            )
            .unwrap();

        // Register a soft-lock intent (no entity in graph, so no LOCKS edge).
        let entity_id = EntityId::new();
        let result = coord
            .register_intent(
                &sid,
                vec![IntentScope::Entity(entity_id)],
                LockType::Soft,
                "refactoring auth",
                None,
            )
            .unwrap();

        match result {
            IntentRegistrationResult::Registered { intent_id, .. } => {
                let intents = coord.list_intents(&sid).unwrap();
                assert_eq!(intents.len(), 1);
                assert_eq!(intents[0].intent_id, intent_id);
            }
            _ => panic!("expected Registered"),
        }
    }

    #[test]
    fn hard_collision_blocks_registration() {
        let coord = make_coordinator();

        // Set up: create an entity in the graph, two sessions.
        let entity = make_test_entity(&coord);

        let s1 = coord
            .register_session(
                "claude-code",
                "s1",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                write_capabilities(),
            )
            .unwrap();
        let s2 = coord
            .register_session(
                "codex",
                "s2",
                SessionTransport::Cli,
                None,
                PathBuf::from("/"),
                write_capabilities(),
            )
            .unwrap();

        // s1 registers a hard lock.
        let r1 = coord
            .register_intent(
                &s1,
                vec![IntentScope::Entity(entity)],
                LockType::Hard,
                "editing payment schema",
                None,
            )
            .unwrap();
        assert!(matches!(r1, IntentRegistrationResult::Registered { .. }));

        // s2 tries to register a hard lock on the same entity: should be blocked.
        let r2 = coord
            .register_intent(
                &s2,
                vec![IntentScope::Entity(entity)],
                LockType::Hard,
                "also editing payment schema",
                None,
            )
            .unwrap();
        assert!(matches!(r2, IntentRegistrationResult::Blocked { .. }));
    }

    #[test]
    fn release_intent_works() {
        let coord = make_coordinator();
        let sid = coord
            .register_session(
                "claude-code",
                "test",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                SessionCapabilities::default(),
            )
            .unwrap();

        let result = coord
            .register_intent(
                &sid,
                vec![IntentScope::Entity(EntityId::new())],
                LockType::Soft,
                "task",
                None,
            )
            .unwrap();

        if let IntentRegistrationResult::Registered { intent_id, .. } = result {
            coord.release_intent(&sid, &intent_id).unwrap();
            let intents = coord.list_intents(&sid).unwrap();
            assert_eq!(intents.len(), 0);
        } else {
            panic!("expected Registered");
        }
    }

    #[test]
    fn release_intent_wrong_session_fails() {
        let coord = make_coordinator();
        let s1 = coord
            .register_session(
                "a",
                "s1",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                SessionCapabilities::default(),
            )
            .unwrap();
        let s2 = coord
            .register_session(
                "b",
                "s2",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                SessionCapabilities::default(),
            )
            .unwrap();

        let result = coord
            .register_intent(&s1, vec![], LockType::Soft, "task", None)
            .unwrap();
        if let IntentRegistrationResult::Registered { intent_id, .. } = result {
            // s2 should not be able to release s1's intent.
            assert!(coord.release_intent(&s2, &intent_id).is_err());
        }
    }

    #[test]
    fn check_traffic_empty() {
        let coord = make_coordinator();
        let check = coord
            .check_traffic(&[IntentScope::Entity(EntityId::new())])
            .unwrap();
        assert!(!check.has_hard_blocks);
        assert_eq!(check.reports.len(), 1);
        assert!(check.reports[0].active_intents.is_empty());
    }

    #[test]
    fn check_traffic_with_locks() {
        let coord = make_coordinator();
        let entity = make_test_entity(&coord);

        let sid = coord
            .register_session(
                "claude-code",
                "test",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                write_capabilities(),
            )
            .unwrap();

        coord
            .register_intent(
                &sid,
                vec![IntentScope::Entity(entity)],
                LockType::Hard,
                "working on it",
                None,
            )
            .unwrap();

        let check = coord.check_traffic(&[IntentScope::Entity(entity)]).unwrap();
        assert!(check.has_hard_blocks);
        assert_eq!(check.reports[0].active_intents.len(), 1);
    }

    #[test]
    fn sweep_stale_sessions_noop_when_fresh() {
        let coord = make_coordinator();
        coord
            .register_session(
                "claude-code",
                "test",
                SessionTransport::Mcp,
                Some(std::process::id()), // Current process is alive.
                PathBuf::from("/"),
                SessionCapabilities::default(),
            )
            .unwrap();

        let reaped = coord.sweep_stale_sessions().unwrap();
        assert_eq!(reaped, 0);
    }

    // -----------------------------------------------------------------------
    // Contract and Artifact scope tests
    // -----------------------------------------------------------------------

    #[test]
    fn contract_collision_blocks_registration() {
        let coord = make_coordinator();
        let contract_id = ContractId::new();

        let s1 = coord
            .register_session(
                "claude-code",
                "s1",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                write_capabilities(),
            )
            .unwrap();
        let s2 = coord
            .register_session(
                "codex",
                "s2",
                SessionTransport::Cli,
                None,
                PathBuf::from("/"),
                write_capabilities(),
            )
            .unwrap();

        // s1 registers a hard lock on a contract scope.
        let r1 = coord
            .register_intent(
                &s1,
                vec![IntentScope::Contract(contract_id)],
                LockType::Hard,
                "editing API schema",
                None,
            )
            .unwrap();
        assert!(matches!(r1, IntentRegistrationResult::Registered { .. }));

        // s2 tries to register a hard lock on the same contract: should be blocked.
        let r2 = coord
            .register_intent(
                &s2,
                vec![IntentScope::Contract(contract_id)],
                LockType::Hard,
                "also editing API schema",
                None,
            )
            .unwrap();
        assert!(matches!(r2, IntentRegistrationResult::Blocked { .. }));
    }

    #[test]
    fn artifact_collision_blocks_registration() {
        let coord = make_coordinator();
        let file_id = FilePathId::new("src/api/routes.rs");

        let s1 = coord
            .register_session(
                "claude-code",
                "s1",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                write_capabilities(),
            )
            .unwrap();
        let s2 = coord
            .register_session(
                "gemini-cli",
                "s2",
                SessionTransport::Cli,
                None,
                PathBuf::from("/"),
                write_capabilities(),
            )
            .unwrap();

        // s1 registers a hard lock on an artifact scope.
        let r1 = coord
            .register_intent(
                &s1,
                vec![IntentScope::Artifact(file_id.clone())],
                LockType::Hard,
                "rewriting routes file",
                None,
            )
            .unwrap();
        assert!(matches!(r1, IntentRegistrationResult::Registered { .. }));

        // s2 tries to register a hard lock on the same file: should be blocked.
        let r2 = coord
            .register_intent(
                &s2,
                vec![IntentScope::Artifact(file_id.clone())],
                LockType::Hard,
                "also rewriting routes file",
                None,
            )
            .unwrap();
        assert!(matches!(r2, IntentRegistrationResult::Blocked { .. }));
    }

    #[test]
    fn mixed_scope_traffic_report() {
        let coord = make_coordinator();
        let entity = make_test_entity(&coord);
        let contract_id = ContractId::new();
        let file_id = FilePathId::new("src/models.rs");

        let sid = coord
            .register_session(
                "claude-code",
                "test",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                write_capabilities_with_limit(3),
            )
            .unwrap();

        // Register intents on all three scope types.
        coord
            .register_intent(
                &sid,
                vec![IntentScope::Entity(entity)],
                LockType::Hard,
                "editing entity",
                None,
            )
            .unwrap();
        coord
            .register_intent(
                &sid,
                vec![IntentScope::Contract(contract_id)],
                LockType::Soft,
                "updating contract",
                None,
            )
            .unwrap();
        coord
            .register_intent(
                &sid,
                vec![IntentScope::Artifact(file_id.clone())],
                LockType::Hard,
                "rewriting file",
                None,
            )
            .unwrap();

        // Check traffic for all three scopes.
        let check = coord
            .check_traffic(&[
                IntentScope::Entity(entity),
                IntentScope::Contract(contract_id),
                IntentScope::Artifact(file_id),
            ])
            .unwrap();

        // Should have 3 reports, one per scope.
        assert_eq!(check.reports.len(), 3);

        // Entity scope has hard block (via graph LOCKS edge).
        assert!(check.has_hard_blocks);
        assert_eq!(check.reports[0].active_intents.len(), 1);
        assert_eq!(check.reports[0].active_intents[0].lock_type, LockType::Hard);

        // Contract scope has soft lock (via intent scan).
        assert_eq!(check.reports[1].active_intents.len(), 1);
        assert_eq!(check.reports[1].active_intents[0].lock_type, LockType::Soft);

        // Artifact scope has hard lock (via intent scan).
        assert_eq!(check.reports[2].active_intents.len(), 1);
        assert_eq!(check.reports[2].active_intents[0].lock_type, LockType::Hard);
    }

    #[test]
    fn contract_downstream_expansion() {
        // When a contract is locked, entities downstream of the contract's
        // entity ID should appear as downstream warnings.
        let coord = make_coordinator();

        // Create a "contract entity" and a "downstream entity" linked via relation.
        use kin_model::entity::*;
        use kin_model::ids::*;
        use kin_model::relation::*;

        let contract_eid = EntityId::new();
        let contract_entity = kin_model::Entity {
            id: contract_eid,
            kind: EntityKind::Function,
            name: "PaymentApi".to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0xaa; 32]),
                signature_hash: Hash256::from_bytes([0xbb; 32]),
                behavior_hash: Hash256::from_bytes([0xcc; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 0.95,
            },
            file_origin: Some(FilePathId::new("src/api.rs")),
            span: None,
            signature: "trait PaymentApi".to_string(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };
        coord.graph.upsert_entity(&contract_entity).unwrap();

        let downstream_eid = EntityId::new();
        let downstream_entity = kin_model::Entity {
            id: downstream_eid,
            kind: EntityKind::Function,
            name: "process_payment".to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0xdd; 32]),
                signature_hash: Hash256::from_bytes([0xee; 32]),
                behavior_hash: Hash256::from_bytes([0xff; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 0.90,
            },
            file_origin: Some(FilePathId::new("src/payment.rs")),
            span: None,
            signature: "fn process_payment()".to_string(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };
        coord.graph.upsert_entity(&downstream_entity).unwrap();

        // Create a relation: downstream_entity -> contract_entity (Calls)
        // The downstream_impact query finds entities that call INTO the target,
        // so the edge must point FROM downstream TO contract.
        let relation = Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: kin_model::GraphNodeId::Entity(downstream_eid),
            dst: kin_model::GraphNodeId::Entity(contract_eid),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        coord.graph.upsert_relation(&relation).unwrap();

        // Create the ContractId that maps to contract_eid.
        let contract_id = ContractId(contract_eid.0);

        // Session 1 locks the downstream entity via an entity scope.
        let s1 = coord
            .register_session(
                "claude-code",
                "s1",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                write_capabilities(),
            )
            .unwrap();
        coord
            .register_intent(
                &s1,
                vec![IntentScope::Entity(downstream_eid)],
                LockType::Hard,
                "working on process_payment",
                None,
            )
            .unwrap();

        // Check traffic on the contract scope: should see downstream warnings
        // because entities downstream of the contract are locked.
        let check = coord
            .check_traffic(&[IntentScope::Contract(contract_id)])
            .unwrap();

        assert_eq!(check.reports.len(), 1);
        // The downstream warnings should include the intent from s1 on downstream_eid.
        assert!(
            !check.reports[0].downstream_warnings.is_empty(),
            "expected downstream warnings from contract expansion, got none"
        );
        assert_eq!(
            check.reports[0].downstream_warnings[0].vendor,
            "claude-code"
        );
    }

    #[test]
    fn artifact_no_collision_different_files() {
        // Two agents locking different files should not collide.
        let coord = make_coordinator();
        let file_a = FilePathId::new("src/a.rs");
        let file_b = FilePathId::new("src/b.rs");

        let s1 = coord
            .register_session(
                "claude-code",
                "s1",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                write_capabilities(),
            )
            .unwrap();
        let s2 = coord
            .register_session(
                "codex",
                "s2",
                SessionTransport::Cli,
                None,
                PathBuf::from("/"),
                write_capabilities(),
            )
            .unwrap();

        let r1 = coord
            .register_intent(
                &s1,
                vec![IntentScope::Artifact(file_a)],
                LockType::Hard,
                "editing file a",
                None,
            )
            .unwrap();
        assert!(matches!(r1, IntentRegistrationResult::Registered { .. }));

        // Different file should succeed.
        let r2 = coord
            .register_intent(
                &s2,
                vec![IntentScope::Artifact(file_b)],
                LockType::Hard,
                "editing file b",
                None,
            )
            .unwrap();
        assert!(matches!(r2, IntentRegistrationResult::Registered { .. }));
    }

    // -----------------------------------------------------------------------
    // Multiple sessions and intents
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_intents_same_session() {
        let coord = make_coordinator();
        let sid = coord
            .register_session(
                "claude-code",
                "test",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                SessionCapabilities {
                    max_concurrent_intents: 5,
                    ..SessionCapabilities::default()
                },
            )
            .unwrap();

        for i in 0..5 {
            let result = coord
                .register_intent(
                    &sid,
                    vec![IntentScope::Entity(EntityId::new())],
                    LockType::Soft,
                    &format!("task {i}"),
                    None,
                )
                .unwrap();
            assert!(matches!(
                result,
                IntentRegistrationResult::Registered { .. }
            ));
        }

        let intents = coord.list_intents(&sid).unwrap();
        assert_eq!(intents.len(), 5);
    }

    #[test]
    fn max_concurrent_intents_is_enforced_at_registration_boundary() {
        let coord = make_coordinator();
        let sid = coord
            .register_session(
                "codex",
                "bounded",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                write_capabilities_with_limit(1),
            )
            .unwrap();

        let first = coord
            .register_intent_with_mode(
                &sid,
                vec![IntentScope::Entity(EntityId::new())],
                LockType::Hard,
                "first",
                None,
                kin_mcp::CoordinationEnforcementMode::Enforce,
            )
            .unwrap();
        assert!(matches!(first, IntentRegistrationResult::Registered { .. }));

        let second = coord
            .register_intent_with_mode(
                &sid,
                vec![IntentScope::Entity(EntityId::new())],
                LockType::Hard,
                "second",
                None,
                kin_mcp::CoordinationEnforcementMode::Enforce,
            )
            .unwrap();
        assert!(matches!(
            second,
            IntentRegistrationResult::LimitExceeded {
                active: 1,
                limit: 1,
                ..
            }
        ));
        assert_eq!(coord.list_intents(&sid).unwrap().len(), 1);
    }

    #[test]
    fn hard_intent_requires_session_write_capability() {
        let coord = make_coordinator();
        let sid = coord
            .register_session(
                "read-only-agent",
                "reader",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                SessionCapabilities::default(),
            )
            .unwrap();

        let result = coord
            .register_intent_with_mode(
                &sid,
                vec![IntentScope::Entity(EntityId::new())],
                LockType::Hard,
                "must not block writers",
                None,
                kin_mcp::CoordinationEnforcementMode::Enforce,
            )
            .unwrap();
        assert!(matches!(
            result,
            IntentRegistrationResult::CapabilityDenied {
                capability: "can_write",
                ..
            }
        ));
        assert!(coord.list_intents(&sid).unwrap().is_empty());
    }

    #[test]
    fn concurrent_hard_registration_has_one_linearizable_winner() {
        use std::sync::{Arc, Barrier};

        let coord = Arc::new(make_coordinator());
        let entity = make_test_entity(&coord);
        let sessions = ["one", "two"].map(|name| {
            coord
                .register_session(
                    "codex",
                    name,
                    SessionTransport::Mcp,
                    None,
                    PathBuf::from("/"),
                    write_capabilities(),
                )
                .unwrap()
        });
        let barrier = Arc::new(Barrier::new(2));

        let handles = sessions.map(|session_id| {
            let coord = Arc::clone(&coord);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                coord
                    .register_intent(
                        &session_id,
                        vec![IntentScope::Entity(entity)],
                        LockType::Hard,
                        "racing registration",
                        None,
                    )
                    .unwrap()
            })
        });
        let outcomes = handles.map(|handle| handle.join().unwrap());
        let registered = outcomes
            .iter()
            .filter(|result| matches!(result, IntentRegistrationResult::Registered { .. }))
            .count();
        let blocked = outcomes
            .iter()
            .filter(|result| matches!(result, IntentRegistrationResult::Blocked { .. }))
            .count();

        assert_eq!(registered, 1);
        assert_eq!(blocked, 1);
        assert_eq!(coord.graph.list_all_intents().unwrap().len(), 1);
    }

    #[test]
    fn soft_lock_does_not_block_hard_lock_from_other_session() {
        let coord = make_coordinator();
        let entity = make_test_entity(&coord);

        let s1 = coord
            .register_session(
                "claude-code",
                "s1",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                write_capabilities(),
            )
            .unwrap();
        let s2 = coord
            .register_session(
                "codex",
                "s2",
                SessionTransport::Cli,
                None,
                PathBuf::from("/"),
                write_capabilities(),
            )
            .unwrap();

        // s1 registers a soft lock
        let r1 = coord
            .register_intent(
                &s1,
                vec![IntentScope::Entity(entity)],
                LockType::Soft,
                "soft task",
                None,
            )
            .unwrap();
        assert!(matches!(r1, IntentRegistrationResult::Registered { .. }));

        // s2 should be able to register a hard lock (soft locks don't block)
        // Note: hard_collisions_for_entity only returns Hard locks as collisions
        let r2 = coord
            .register_intent(
                &s2,
                vec![IntentScope::Entity(entity)],
                LockType::Hard,
                "hard task",
                None,
            )
            .unwrap();
        assert!(matches!(r2, IntentRegistrationResult::Registered { .. }));
    }

    #[test]
    fn deregister_session_removes_intents() {
        let coord = make_coordinator();
        let sid = coord
            .register_session(
                "claude-code",
                "test",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                SessionCapabilities::default(),
            )
            .unwrap();

        coord
            .register_intent(
                &sid,
                vec![IntentScope::Entity(EntityId::new())],
                LockType::Soft,
                "task",
                None,
            )
            .unwrap();

        // After deregister, session and its intents should be gone
        coord.deregister_session(&sid).unwrap();
        assert!(coord.get_session(&sid).unwrap().is_none());
        let intents = coord.list_intents(&sid).unwrap();
        assert!(intents.is_empty());
    }

    #[test]
    fn register_intent_on_nonexistent_session_fails() {
        let coord = make_coordinator();
        let fake_session = SessionId::new();
        let result = coord.register_intent(
            &fake_session,
            vec![IntentScope::Entity(EntityId::new())],
            LockType::Soft,
            "should fail",
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn session_vendor_and_transport_stored() {
        let coord = make_coordinator();
        let sid = coord
            .register_session(
                "gemini-cli",
                "my-client",
                SessionTransport::Wrapper,
                Some(12345),
                PathBuf::from("/workspace"),
                SessionCapabilities::default(),
            )
            .unwrap();

        let session = coord.get_session(&sid).unwrap().unwrap();
        assert_eq!(session.vendor, "gemini-cli");
        assert_eq!(session.client_name, "my-client");
        assert_eq!(session.transport, SessionTransport::Wrapper);
        assert_eq!(session.pid, Some(12345));
        assert_eq!(session.cwd, PathBuf::from("/workspace"));
    }

    #[test]
    fn list_sessions_empty_initially() {
        let coord = make_coordinator();
        let sessions = coord.list_sessions().unwrap();
        assert!(sessions.is_empty());
    }

    #[test]
    fn heartbeat_on_deregistered_session_fails() {
        let coord = make_coordinator();
        let sid = coord
            .register_session(
                "claude-code",
                "test",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                SessionCapabilities::default(),
            )
            .unwrap();
        coord.deregister_session(&sid).unwrap();
        assert!(coord.heartbeat(&sid).is_err());
    }

    #[test]
    fn release_nonexistent_intent_fails() {
        let coord = make_coordinator();
        let sid = coord
            .register_session(
                "claude-code",
                "test",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                SessionCapabilities::default(),
            )
            .unwrap();
        let fake_intent = IntentId::new();
        assert!(coord.release_intent(&sid, &fake_intent).is_err());
    }

    #[test]
    fn check_traffic_multiple_scopes() {
        let coord = make_coordinator();
        let e1 = make_test_entity(&coord);
        let e2 = make_test_entity(&coord);

        let sid = coord
            .register_session(
                "claude-code",
                "test",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                write_capabilities(),
            )
            .unwrap();

        coord
            .register_intent(
                &sid,
                vec![IntentScope::Entity(e1)],
                LockType::Hard,
                "task 1",
                None,
            )
            .unwrap();

        let check = coord
            .check_traffic(&[IntentScope::Entity(e1), IntentScope::Entity(e2)])
            .unwrap();
        assert_eq!(check.reports.len(), 2);
        assert_eq!(check.reports[0].active_intents.len(), 1);
        assert!(check.reports[1].active_intents.is_empty());
    }

    #[test]
    fn sweep_with_dead_pid_reaps() {
        let coord = SessionCoordinator::with_heartbeat_interval(
            Arc::new(kin_db::InMemoryGraph::new()),
            Duration::from_secs(30),
        );
        // Use a PID that almost certainly does not exist
        let sid = coord
            .register_session(
                "claude-code",
                "dead-agent",
                SessionTransport::Mcp,
                Some(999_999_999),
                PathBuf::from("/"),
                write_capabilities(),
            )
            .unwrap();

        let lock = coord
            .register_intent(
                &sid,
                vec![IntentScope::Entity(EntityId::new())],
                LockType::Hard,
                "non-expiring orphan candidate",
                None,
            )
            .unwrap();
        assert!(matches!(lock, IntentRegistrationResult::Registered { .. }));

        let reaped = coord.sweep_stale_sessions_detailed().unwrap();
        // On macOS, kill -0 on invalid PID fails, marking it stale
        assert_eq!(reaped.len(), 1);
        assert_eq!(reaped[0].1.len(), 1);
        assert!(coord.get_session(&sid).unwrap().is_none());
        assert!(coord.list_intents(&sid).unwrap().is_empty());
    }

    #[test]
    fn sweep_with_stale_heartbeat_keeps_live_pid() {
        let coord = SessionCoordinator::with_heartbeat_interval(
            Arc::new(kin_db::InMemoryGraph::new()),
            Duration::from_millis(1),
        );
        let sid = coord
            .register_session(
                "claude-code",
                "slow-scope",
                SessionTransport::Mcp,
                Some(std::process::id()),
                PathBuf::from("/"),
                SessionCapabilities::default(),
            )
            .unwrap();

        std::thread::sleep(Duration::from_millis(10));

        let reaped = coord.sweep_stale_sessions().unwrap();
        assert_eq!(reaped, 0);
        assert!(coord.get_session(&sid).unwrap().is_some());
    }

    #[test]
    fn custom_heartbeat_interval() {
        let coord = SessionCoordinator::with_heartbeat_interval(
            Arc::new(kin_db::InMemoryGraph::new()),
            Duration::from_secs(5),
        );
        let sid = coord
            .register_session(
                "test",
                "ci",
                SessionTransport::Mcp,
                Some(std::process::id()),
                PathBuf::from("/"),
                SessionCapabilities::default(),
            )
            .unwrap();

        // Fresh session shouldn't be reaped
        let reaped = coord.sweep_stale_sessions().unwrap();
        assert_eq!(reaped, 0);
        assert!(coord.get_session(&sid).unwrap().is_some());
    }

    #[test]
    fn contract_soft_lock_no_collision() {
        let coord = make_coordinator();
        let contract_id = ContractId::new();

        let s1 = coord
            .register_session(
                "a",
                "s1",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                SessionCapabilities::default(),
            )
            .unwrap();
        let s2 = coord
            .register_session(
                "b",
                "s2",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                SessionCapabilities::default(),
            )
            .unwrap();

        // Two soft locks on same contract should not block
        let r1 = coord
            .register_intent(
                &s1,
                vec![IntentScope::Contract(contract_id)],
                LockType::Soft,
                "reading contract",
                None,
            )
            .unwrap();
        assert!(matches!(r1, IntentRegistrationResult::Registered { .. }));

        let r2 = coord
            .register_intent(
                &s2,
                vec![IntentScope::Contract(contract_id)],
                LockType::Soft,
                "also reading contract",
                None,
            )
            .unwrap();
        assert!(matches!(r2, IntentRegistrationResult::Registered { .. }));
    }

    #[test]
    fn empty_scopes_intent() {
        let coord = make_coordinator();
        let sid = coord
            .register_session(
                "a",
                "s",
                SessionTransport::Mcp,
                None,
                PathBuf::from("/"),
                SessionCapabilities::default(),
            )
            .unwrap();

        let result = coord
            .register_intent(&sid, vec![], LockType::Soft, "no scopes", None)
            .unwrap();
        assert!(matches!(
            result,
            IntentRegistrationResult::Registered { .. }
        ));
    }

    /// Helper: create a test entity in the graph and return its ID.
    fn make_test_entity(coord: &SessionCoordinator) -> EntityId {
        use kin_model::entity::*;
        use kin_model::ids::*;

        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "test_fn".to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0xaa; 32]),
                signature_hash: Hash256::from_bytes([0xbb; 32]),
                behavior_hash: Hash256::from_bytes([0xcc; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 0.95,
            },
            file_origin: Some(FilePathId::new("src/main.rs")),
            span: None,
            signature: "fn test_fn() -> bool".to_string(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        coord.graph.upsert_entity(&entity).unwrap();
        entity.id
    }
}
