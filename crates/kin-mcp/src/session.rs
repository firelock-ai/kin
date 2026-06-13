// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use kin_model::ids::{EntityId, IntentId, SessionId};
use kin_model::session::{
    AgentSession, Intent, IntentScope, IntentSummary, LockType, SessionCapabilities,
    SessionTransport, TrafficReport,
};
use kin_model::timestamp::Timestamp;
use serde::{Deserialize, Serialize};

/// Registered assistant session (legacy compat for simple register_session tool).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssistantSession {
    pub session_id: String,
    pub assistant_name: String,
    pub registered_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum McpMutationPayload {
    Entity(kin_model::Entity),
    Relation {
        from: kin_model::ids::EntityId,
        to: kin_model::ids::EntityId,
        kind: kin_model::relation::RelationKind,
    },
    Blob(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpMutationOperation {
    pub verb: String,
    /// Legacy compat target; the tool schema declares it optional with default "".
    #[serde(default)]
    pub target: String,
    pub payload: Option<McpMutationPayload>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTransaction {
    pub transaction_id: String,
    pub session_id: String,
    pub scope: String,
    pub state: String,
    pub staged_operations: Vec<McpMutationOperation>,
}

/// The mutation verbs the transaction commit path understands, listed for
/// actionable error messages.
const KNOWN_MUTATION_VERBS: &str = "create/add/upsert/insert, update/modify, or delete/remove";

fn is_known_mutation_verb(verb: &str) -> bool {
    matches!(
        verb,
        "create" | "add" | "upsert" | "insert" | "update" | "modify" | "delete" | "remove"
    )
}

/// Validate staged mutation operations at stage time so malformed payloads fail
/// loud with an actionable message instead of being silently dropped at commit.
///
/// These checks are intrinsic to the payload (no graph access required) and are
/// safe in every runtime, so they run identically for the in-process handler and
/// the product daemon-forward path. Stage-time rejection is a superset of what
/// the commit path (`uncommittable_operations`) rejects: every operation the
/// commit `match` would fall through and silently drop — an absent or unknown
/// verb, a missing payload, a relation `update`/`modify`, or a `Blob` payload —
/// fails loud here, plus the intrinsic empty-entity-name case. This guarantees
/// anything that stages clean will not surprise-drop at commit. Deeper,
/// graph-dependent validation (does the target entity exist, contract/schema
/// conformance) stays with the daemon, which owns graph truth.
pub fn validate_staged_operations(
    operations: &[McpMutationOperation],
) -> std::result::Result<(), String> {
    for (idx, op) in operations.iter().enumerate() {
        let verb = op.verb.trim().to_lowercase();
        if verb.is_empty() {
            return Err(format!(
                "operation #{idx}: missing verb; expected one of {KNOWN_MUTATION_VERBS}"
            ));
        }
        if !is_known_mutation_verb(&verb) {
            return Err(format!(
                "operation #{idx}: unknown verb '{}'; expected one of {KNOWN_MUTATION_VERBS}",
                op.verb
            ));
        }
        let Some(payload) = op.payload.as_ref() else {
            return Err(format!(
                "operation #{idx} ('{}'): missing payload; an entity, relation, or blob payload \
                 is required — a payload-less operation is silently dropped at commit",
                op.verb
            ));
        };
        if let McpMutationPayload::Entity(entity) = payload {
            if entity.name.trim().is_empty() {
                return Err(format!(
                    "operation #{idx}: entity payload has an empty name; an entity must be named"
                ));
            }
        }
        // Reject the remaining commit-silent-drop cases (relation update/modify,
        // blob payloads) so stage-time rejection is a strict superset of what the
        // commit path drops. Verb and payload are already validated above, so
        // this only fires for these payload/verb combinations.
        if let Some(reason) = uncommittable_reason(op) {
            return Err(format!("operation #{idx} ('{}'): {reason}", op.verb));
        }
    }
    Ok(())
}

/// Why a single staged operation cannot be turned into a committed delta, or
/// `None` when it is committable.
///
/// This mirrors exactly what the commit path (`handle_transaction_commit`) can
/// turn into an `EntityDelta`/`RelationDelta`. The cases it flags are the ones
/// the commit `match` would otherwise fall through and silently drop:
/// relation `update`/`modify` (relations are identity-less edges — only
/// add/remove are committable) and `Blob` payloads (no transactional blob path
/// yet), plus the intrinsic problems stage-time validation already guards.
/// No graph access is required, so it is safe to run in any runtime; existence
/// checks (does the relation/entity actually exist) stay graph-side.
pub fn uncommittable_reason(op: &McpMutationOperation) -> Option<String> {
    let verb = op.verb.trim().to_lowercase();
    if verb.is_empty() {
        return Some(format!(
            "missing verb; expected one of {KNOWN_MUTATION_VERBS}"
        ));
    }
    if !is_known_mutation_verb(&verb) {
        return Some(format!(
            "unknown verb '{}'; expected one of {KNOWN_MUTATION_VERBS}",
            op.verb
        ));
    }
    let Some(payload) = op.payload.as_ref() else {
        return Some("missing payload".to_string());
    };
    match payload {
        // Every known verb maps to an entity delta (add/modify/remove).
        McpMutationPayload::Entity(_) => None,
        McpMutationPayload::Relation { .. } => {
            if matches!(verb.as_str(), "update" | "modify") {
                Some(format!(
                    "verb '{}' is not committable for relation payloads; relations support only \
                     create/add/upsert/insert or delete/remove",
                    op.verb
                ))
            } else {
                None
            }
        }
        McpMutationPayload::Blob(_) => {
            Some("blob payloads are not yet committable through transactions".to_string())
        }
    }
}

/// Indexed, human-readable reasons for every staged operation that cannot be
/// committed. Empty when the whole batch is committable. The commit and
/// validate handlers use this to fail loud instead of silently dropping
/// un-committable operations at commit.
pub fn uncommittable_operations(operations: &[McpMutationOperation]) -> Vec<String> {
    operations
        .iter()
        .enumerate()
        .filter_map(|(idx, op)| {
            uncommittable_reason(op)
                .map(|reason| format!("operation #{idx} ('{}'): {reason}", op.verb))
        })
        .collect()
}

/// Thread-safe registry for agent sessions and intents.
///
/// This is the in-process coordination hub. The daemon would host this
/// and expose it over HTTP; the MCP server holds a local instance for
/// direct MCP-connected agents.
pub struct SessionRegistry {
    /// Legacy simple sessions (from `register_session` tool).
    sessions: Mutex<HashMap<String, AssistantSession>>,
    /// Rich agent sessions (from `kin_session_start` tool).
    agent_sessions: Mutex<HashMap<SessionId, AgentSession>>,
    /// Active intents keyed by IntentId.
    intents: Mutex<HashMap<IntentId, Intent>>,
    /// Active transactions keyed by TransactionId.
    transactions: Mutex<HashMap<String, McpTransaction>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            agent_sessions: Mutex::new(HashMap::new()),
            intents: Mutex::new(HashMap::new()),
            transactions: Mutex::new(HashMap::new()),
        }
    }

    // ── Legacy session API (backward compat) ──

    /// Register a simple session. Returns the session ID.
    pub fn register(&self, session_id: &str, assistant_name: &str) -> String {
        let session = AssistantSession {
            session_id: session_id.to_string(),
            assistant_name: assistant_name.to_string(),
            registered_at: Timestamp::now(),
        };
        let id = session.session_id.clone();
        self.sessions
            .lock()
            .expect("session lock poisoned")
            .insert(id.clone(), session);
        id
    }

    /// Get a simple session by ID.
    pub fn get(&self, session_id: &str) -> Option<AssistantSession> {
        self.sessions
            .lock()
            .expect("session lock poisoned")
            .get(session_id)
            .cloned()
    }

    /// Remove a simple session.
    pub fn remove(&self, session_id: &str) -> Option<AssistantSession> {
        self.sessions
            .lock()
            .expect("session lock poisoned")
            .remove(session_id)
    }

    /// List all simple sessions.
    pub fn list(&self) -> Vec<AssistantSession> {
        self.sessions
            .lock()
            .expect("session lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// Number of simple sessions.
    pub fn count(&self) -> usize {
        self.sessions.lock().expect("session lock poisoned").len()
    }

    // ── Rich agent session API (Phase 7) ──

    /// Start a new agent session.
    pub fn start_agent_session(
        &self,
        vendor: &str,
        client_name: &str,
        transport: SessionTransport,
        pid: Option<u32>,
        cwd: PathBuf,
        capabilities: SessionCapabilities,
    ) -> AgentSession {
        let now = Timestamp::now();
        let session = AgentSession {
            session_id: SessionId::new(),
            vendor: vendor.to_string(),
            client_name: client_name.to_string(),
            transport,
            pid,
            cwd,
            started_at: now.clone(),
            last_heartbeat: now,
            capabilities,
        };
        let id = session.session_id;
        self.agent_sessions
            .lock()
            .expect("agent_sessions lock poisoned")
            .insert(id, session.clone());
        session
    }

    /// Record a heartbeat for an agent session. Returns true if session exists.
    pub fn heartbeat(&self, session_id: &SessionId) -> bool {
        let mut map = self
            .agent_sessions
            .lock()
            .expect("agent_sessions lock poisoned");
        if let Some(session) = map.get_mut(session_id) {
            session.last_heartbeat = Timestamp::now();
            true
        } else {
            false
        }
    }

    /// End an agent session and release all its intents.
    pub fn end_agent_session(&self, session_id: &SessionId) -> Option<AgentSession> {
        let session = self
            .agent_sessions
            .lock()
            .expect("agent_sessions lock poisoned")
            .remove(session_id);

        if session.is_some() {
            // Release all intents owned by this session.
            let mut intents = self.intents.lock().expect("intents lock poisoned");
            intents.retain(|_, intent| intent.session_id != *session_id);
        }

        session
    }

    /// Get an agent session by ID.
    pub fn get_agent_session(&self, session_id: &SessionId) -> Option<AgentSession> {
        self.agent_sessions
            .lock()
            .expect("agent_sessions lock poisoned")
            .get(session_id)
            .cloned()
    }

    /// List all agent sessions.
    pub fn list_agent_sessions(&self) -> Vec<AgentSession> {
        self.agent_sessions
            .lock()
            .expect("agent_sessions lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// Replace the rich session and intent maps from daemon-owned state.
    ///
    /// Product MCP stdio does not own sessions. The repo daemon uses this to
    /// build a per-request read snapshot for tool handlers that enrich graph
    /// answers with active traffic.
    pub fn replace_agent_sessions_and_intents(
        &self,
        agent_sessions: Vec<AgentSession>,
        intents: Vec<Intent>,
    ) {
        let mut sessions_map = self
            .agent_sessions
            .lock()
            .expect("agent_sessions lock poisoned");
        sessions_map.clear();
        for session in agent_sessions {
            sessions_map.insert(session.session_id, session);
        }
        drop(sessions_map);

        let mut intents_map = self.intents.lock().expect("intents lock poisoned");
        intents_map.clear();
        for intent in intents {
            intents_map.insert(intent.intent_id, intent);
        }
    }

    // ── Intent API ──

    /// Register a new intent. Returns the created Intent.
    pub fn register_intent(
        &self,
        session_id: SessionId,
        scopes: Vec<IntentScope>,
        lock_type: LockType,
        task_description: String,
        expires_at: Option<Timestamp>,
    ) -> Option<Intent> {
        // Verify session exists.
        let sessions = self
            .agent_sessions
            .lock()
            .expect("agent_sessions lock poisoned");
        if !sessions.contains_key(&session_id) {
            return None;
        }
        drop(sessions);

        let now = Timestamp::now();
        let intent = Intent {
            intent_id: IntentId::new(),
            session_id,
            scopes,
            lock_type,
            task_description,
            registered_at: now,
            expires_at,
        };
        let id = intent.intent_id;
        self.intents
            .lock()
            .expect("intents lock poisoned")
            .insert(id, intent.clone());
        Some(intent)
    }

    /// Release a specific intent. Returns it if it existed.
    pub fn release_intent(&self, session_id: &SessionId, intent_id: &IntentId) -> Option<Intent> {
        let mut intents = self.intents.lock().expect("intents lock poisoned");
        if let Some(intent) = intents.get(intent_id) {
            if intent.session_id == *session_id {
                return intents.remove(intent_id);
            }
        }
        None
    }

    /// List all intents for a given session.
    pub fn list_intents_for_session(&self, session_id: &SessionId) -> Vec<Intent> {
        self.intents
            .lock()
            .expect("intents lock poisoned")
            .values()
            .filter(|i| i.session_id == *session_id)
            .cloned()
            .collect()
    }

    /// Check traffic for the given scopes. Returns a TrafficReport per scope.
    pub fn check_traffic(&self, scopes: &[IntentScope]) -> Vec<TrafficReport> {
        let intents = self.intents.lock().expect("intents lock poisoned");
        let sessions = self
            .agent_sessions
            .lock()
            .expect("agent_sessions lock poisoned");

        scopes
            .iter()
            .map(|target| {
                let active: Vec<IntentSummary> = intents
                    .values()
                    .filter(|i| i.scopes.contains(target))
                    .map(|i| {
                        let vendor = sessions
                            .get(&i.session_id)
                            .map(|s| s.vendor.clone())
                            .unwrap_or_else(|| "unknown".into());
                        IntentSummary {
                            intent_id: i.intent_id,
                            session_id: i.session_id,
                            vendor,
                            task_description: i.task_description.clone(),
                            lock_type: i.lock_type,
                            registered_at: i.registered_at.clone(),
                        }
                    })
                    .collect();

                TrafficReport {
                    target: target.clone(),
                    active_intents: active,
                    // Downstream warnings require graph traversal; the MCP
                    // handler can populate this when a store is available.
                    downstream_warnings: vec![],
                }
            })
            .collect()
    }

    /// Get active traffic summaries near a given entity (for include_traffic flag).
    pub fn get_traffic_near_entity(&self, entity_id: &EntityId) -> Vec<IntentSummary> {
        let target = IntentScope::Entity(*entity_id);
        let intents = self.intents.lock().expect("intents lock poisoned");
        let sessions = self
            .agent_sessions
            .lock()
            .expect("agent_sessions lock poisoned");

        intents
            .values()
            .filter(|i| i.scopes.contains(&target))
            .map(|i| {
                let vendor = sessions
                    .get(&i.session_id)
                    .map(|s| s.vendor.clone())
                    .unwrap_or_else(|| "unknown".into());
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

    // ── Transaction API ──

    pub fn begin_transaction(
        &self,
        session_id: &str,
        scope: &str,
    ) -> std::result::Result<McpTransaction, String> {
        let transaction_id = EntityId::new().to_string();
        let transaction = McpTransaction {
            transaction_id: transaction_id.clone(),
            session_id: session_id.to_string(),
            scope: scope.to_string(),
            state: "active".to_string(),
            staged_operations: Vec::new(),
        };

        self.transactions
            .lock()
            .expect("transactions lock poisoned")
            .insert(transaction_id, transaction.clone());

        Ok(transaction)
    }

    pub fn stage_transaction(
        &self,
        transaction_id: &str,
        operations: Vec<McpMutationOperation>,
    ) -> std::result::Result<McpTransaction, String> {
        let mut map = self
            .transactions
            .lock()
            .expect("transactions lock poisoned");
        if let Some(tx) = map.get_mut(transaction_id) {
            if tx.state != "active" {
                return Err(format!(
                    "Cannot stage operations on transaction {} in state: {}",
                    transaction_id, tx.state
                ));
            }
            tx.staged_operations.extend(operations);
            Ok(tx.clone())
        } else {
            Err(format!("Transaction not found: {}", transaction_id))
        }
    }

    pub fn validate_transaction(
        &self,
        transaction_id: &str,
    ) -> std::result::Result<McpTransaction, String> {
        let mut map = self
            .transactions
            .lock()
            .expect("transactions lock poisoned");
        if let Some(tx) = map.get_mut(transaction_id) {
            if tx.state != "active" {
                return Err(format!(
                    "Cannot validate transaction {} in state: {}",
                    transaction_id, tx.state
                ));
            }
            tx.state = "validated".to_string();
            Ok(tx.clone())
        } else {
            Err(format!("Transaction not found: {}", transaction_id))
        }
    }

    pub fn commit_transaction(
        &self,
        transaction_id: &str,
    ) -> std::result::Result<McpTransaction, String> {
        let mut map = self
            .transactions
            .lock()
            .expect("transactions lock poisoned");
        if let Some(tx) = map.get_mut(transaction_id) {
            if tx.state != "active" && tx.state != "validated" {
                return Err(format!(
                    "Cannot commit transaction {} in state: {}",
                    transaction_id, tx.state
                ));
            }
            tx.state = "committed".to_string();
            Ok(tx.clone())
        } else {
            Err(format!("Transaction not found: {}", transaction_id))
        }
    }

    pub fn abort_transaction(
        &self,
        transaction_id: &str,
    ) -> std::result::Result<McpTransaction, String> {
        let mut map = self
            .transactions
            .lock()
            .expect("transactions lock poisoned");
        if let Some(tx) = map.get_mut(transaction_id) {
            tx.state = "aborted".to_string();
            Ok(tx.clone())
        } else {
            Err(format!("Transaction not found: {}", transaction_id))
        }
    }

    pub fn get_transaction(&self, transaction_id: &str) -> Option<McpTransaction> {
        self.transactions
            .lock()
            .expect("transactions lock poisoned")
            .get(transaction_id)
            .cloned()
    }

    /// Snapshot every transaction currently held by this registry.
    ///
    /// Used by the daemon to persist transaction state into its long-lived store
    /// after a tool call, since the daemon rebuilds a fresh registry per request.
    pub fn list_transactions(&self) -> Vec<McpTransaction> {
        self.transactions
            .lock()
            .expect("transactions lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// Replace all transactions in this registry with `transactions`.
    ///
    /// The daemon calls this before dispatching a tool so a registry built fresh
    /// for the request sees transactions staged by earlier requests; without it,
    /// `begin`/`stage`/`commit` issued across separate HTTP calls never share
    /// state and the transaction is reported "not found".
    pub fn replace_transactions(&self, transactions: Vec<McpTransaction>) {
        let mut map = self
            .transactions
            .lock()
            .expect("transactions lock poisoned");
        map.clear();
        for transaction in transactions {
            map.insert(transaction.transaction_id.clone(), transaction);
        }
    }
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_operation_deserializes_without_target() {
        // The tool schema declares `target` optional with default "" (FIR-936);
        // the deserializer must accept schema-conformant payloads that omit it.
        let json = serde_json::json!({
            "verb": "update",
            "description": "schema-conformant op without target"
        });
        let op: McpMutationOperation =
            serde_json::from_value(json).expect("operation without target must deserialize");
        assert_eq!(op.target, "");
        assert_eq!(op.verb, "update");
    }

    #[test]
    fn register_and_get_session() {
        let registry = SessionRegistry::new();
        let id = registry.register("sess-1", "claude-code");
        assert_eq!(id, "sess-1");

        let session = registry.get("sess-1").unwrap();
        assert_eq!(session.assistant_name, "claude-code");
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn remove_session() {
        let registry = SessionRegistry::new();
        registry.register("sess-2", "codex");
        assert_eq!(registry.count(), 1);

        let removed = registry.remove("sess-2");
        assert!(removed.is_some());
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn list_sessions() {
        let registry = SessionRegistry::new();
        registry.register("a", "claude-code");
        registry.register("b", "codex");
        registry.register("c", "gemini");

        let sessions = registry.list();
        assert_eq!(sessions.len(), 3);
    }

    #[test]
    fn get_nonexistent_session() {
        let registry = SessionRegistry::new();
        assert!(registry.get("does-not-exist").is_none());
    }

    #[test]
    fn start_agent_session_and_heartbeat() {
        let registry = SessionRegistry::new();
        let session = registry.start_agent_session(
            "claude-code",
            "test-client",
            SessionTransport::Mcp,
            Some(1234),
            PathBuf::from("/project"),
            SessionCapabilities::default(),
        );

        assert_eq!(session.vendor, "claude-code");
        assert!(registry.get_agent_session(&session.session_id).is_some());

        let ok = registry.heartbeat(&session.session_id);
        assert!(ok);

        let fake_id = SessionId::new();
        let ok = registry.heartbeat(&fake_id);
        assert!(!ok);
    }

    #[test]
    fn end_agent_session_releases_intents() {
        let registry = SessionRegistry::new();
        let session = registry.start_agent_session(
            "codex",
            "test",
            SessionTransport::Cli,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities::default(),
        );

        let intent = registry
            .register_intent(
                session.session_id,
                vec![IntentScope::Entity(EntityId::new())],
                LockType::Soft,
                "testing".into(),
                None,
            )
            .unwrap();

        assert_eq!(
            registry.list_intents_for_session(&session.session_id).len(),
            1
        );

        let ended = registry.end_agent_session(&session.session_id);
        assert!(ended.is_some());
        assert!(registry.get_agent_session(&session.session_id).is_none());
        // Intents should be cleaned up.
        assert!(registry
            .list_intents_for_session(&session.session_id)
            .is_empty());
        // Suppress unused variable warning.
        let _ = intent;
    }

    #[test]
    fn replace_agent_sessions_and_intents_hydrates_daemon_state() {
        let registry = SessionRegistry::new();
        let session = AgentSession {
            session_id: SessionId::new(),
            vendor: "codex".into(),
            client_name: "daemon-proxy".into(),
            transport: SessionTransport::Mcp,
            pid: None,
            cwd: PathBuf::from("/repo"),
            started_at: Timestamp::now(),
            last_heartbeat: Timestamp::now(),
            capabilities: SessionCapabilities::default(),
        };
        let entity_id = EntityId::new();
        let intent = Intent {
            intent_id: IntentId::new(),
            session_id: session.session_id,
            scopes: vec![IntentScope::Entity(entity_id)],
            lock_type: LockType::Soft,
            task_description: "editing".into(),
            registered_at: Timestamp::now(),
            expires_at: None,
        };

        registry.replace_agent_sessions_and_intents(vec![session], vec![intent]);

        let traffic = registry.get_traffic_near_entity(&entity_id);
        assert_eq!(traffic.len(), 1);
        assert_eq!(traffic[0].vendor, "codex");
    }

    #[test]
    fn register_intent_requires_valid_session() {
        let registry = SessionRegistry::new();
        let fake_session = SessionId::new();

        let result = registry.register_intent(
            fake_session,
            vec![IntentScope::Entity(EntityId::new())],
            LockType::Soft,
            "test".into(),
            None,
        );
        assert!(result.is_none());
    }

    #[test]
    fn release_intent_checks_ownership() {
        let registry = SessionRegistry::new();
        let session = registry.start_agent_session(
            "claude-code",
            "test",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities::default(),
        );

        let intent = registry
            .register_intent(
                session.session_id,
                vec![IntentScope::Entity(EntityId::new())],
                LockType::Hard,
                "editing".into(),
                None,
            )
            .unwrap();

        // Wrong session cannot release.
        let other_session = SessionId::new();
        let result = registry.release_intent(&other_session, &intent.intent_id);
        assert!(result.is_none());

        // Correct session can release.
        let result = registry.release_intent(&session.session_id, &intent.intent_id);
        assert!(result.is_some());
    }

    #[test]
    fn check_traffic_returns_reports() {
        let registry = SessionRegistry::new();
        let session = registry.start_agent_session(
            "claude-code",
            "test",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities::default(),
        );

        let entity_id = EntityId::new();
        let scope = IntentScope::Entity(entity_id);
        registry.register_intent(
            session.session_id,
            vec![scope.clone()],
            LockType::Soft,
            "working on entity".into(),
            None,
        );

        let reports = registry.check_traffic(std::slice::from_ref(&scope));
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].active_intents.len(), 1);
        assert_eq!(reports[0].active_intents[0].vendor, "claude-code");

        // Unrelated scope returns empty traffic.
        let other_scope = IntentScope::Entity(EntityId::new());
        let reports = registry.check_traffic(&[other_scope]);
        assert_eq!(reports.len(), 1);
        assert!(reports[0].active_intents.is_empty());
    }

    #[test]
    fn get_traffic_near_entity() {
        let registry = SessionRegistry::new();
        let session = registry.start_agent_session(
            "gemini-cli",
            "test",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities::default(),
        );

        let entity_id = EntityId::new();
        registry.register_intent(
            session.session_id,
            vec![IntentScope::Entity(entity_id)],
            LockType::Hard,
            "editing entity".into(),
            None,
        );

        let traffic = registry.get_traffic_near_entity(&entity_id);
        assert_eq!(traffic.len(), 1);
        assert_eq!(traffic[0].vendor, "gemini-cli");
        assert_eq!(traffic[0].lock_type, LockType::Hard);

        let other_id = EntityId::new();
        let traffic = registry.get_traffic_near_entity(&other_id);
        assert!(traffic.is_empty());
    }

    #[test]
    fn list_agent_sessions() {
        let registry = SessionRegistry::new();
        registry.start_agent_session(
            "claude-code",
            "a",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities::default(),
        );
        registry.start_agent_session(
            "codex",
            "b",
            SessionTransport::Cli,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities::default(),
        );

        let sessions = registry.list_agent_sessions();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn transaction_lifecycle() {
        let registry = SessionRegistry::new();
        let tx = registry.begin_transaction("sess-1", "src/lib.rs").unwrap();
        assert_eq!(tx.session_id, "sess-1");
        assert_eq!(tx.scope, "src/lib.rs");
        assert_eq!(tx.state, "active");
        assert!(tx.staged_operations.is_empty());

        let op = McpMutationOperation {
            verb: "create".to_string(),
            target: "function".to_string(),
            payload: None,
            description: "add dummy function".to_string(),
        };
        let tx_staged = registry
            .stage_transaction(&tx.transaction_id, vec![op])
            .unwrap();
        assert_eq!(tx_staged.staged_operations.len(), 1);

        let tx_validated = registry.validate_transaction(&tx.transaction_id).unwrap();
        assert_eq!(tx_validated.state, "validated");

        let tx_committed = registry.commit_transaction(&tx.transaction_id).unwrap();
        assert_eq!(tx_committed.state, "committed");

        // Cannot stage on committed
        assert!(registry
            .stage_transaction(&tx.transaction_id, vec![])
            .is_err());
    }

    // ── Stage-time validation (D.7 Track A) ──────────────────────────────────

    fn entity_named(name: &str) -> kin_model::Entity {
        use kin_model::entity::{
            EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
            Visibility,
        };
        use kin_model::ids::{Hash256, LanguageId};
        kin_model::Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn op(verb: &str, payload: Option<McpMutationPayload>) -> McpMutationOperation {
        McpMutationOperation {
            verb: verb.to_string(),
            target: "function".to_string(),
            payload,
            description: "d".to_string(),
        }
    }

    #[test]
    fn validate_staged_operations_accepts_well_formed_and_empty() {
        assert!(validate_staged_operations(&[]).is_ok());
        let ops = vec![op(
            "create",
            Some(McpMutationPayload::Entity(entity_named("foo"))),
        )];
        assert!(validate_staged_operations(&ops).is_ok());
    }

    #[test]
    fn validate_staged_operations_rejects_missing_payload() {
        // The commit path silently skips payload-less ops; stage time must not.
        let err = validate_staged_operations(&[op("create", None)]).unwrap_err();
        assert!(err.contains("missing payload"), "{err}");
        assert!(err.contains("silently dropped at commit"), "{err}");
    }

    #[test]
    fn validate_staged_operations_rejects_unknown_and_empty_verb() {
        let unknown = validate_staged_operations(&[op(
            "frobnicate",
            Some(McpMutationPayload::Entity(entity_named("foo"))),
        )])
        .unwrap_err();
        assert!(unknown.contains("unknown verb 'frobnicate'"), "{unknown}");

        let empty = validate_staged_operations(&[op(
            "  ",
            Some(McpMutationPayload::Entity(entity_named("foo"))),
        )])
        .unwrap_err();
        assert!(empty.contains("missing verb"), "{empty}");
    }

    #[test]
    fn validate_staged_operations_rejects_empty_entity_name() {
        let err = validate_staged_operations(&[op(
            "create",
            Some(McpMutationPayload::Entity(entity_named("   "))),
        )])
        .unwrap_err();
        assert!(err.contains("empty name"), "{err}");
    }

    #[test]
    fn validate_staged_operations_reports_offending_index() {
        let ops = vec![
            op(
                "create",
                Some(McpMutationPayload::Entity(entity_named("ok"))),
            ),
            op("create", None),
        ];
        let err = validate_staged_operations(&ops).unwrap_err();
        assert!(err.contains("operation #1"), "{err}");
    }

    #[test]
    fn validate_staged_operations_rejects_relation_modify() {
        // Relation update/modify is committable-looking but the commit path drops
        // it; stage time must reject it now, not just at commit.
        for verb in ["modify", "update"] {
            let err =
                validate_staged_operations(&[op(verb, Some(relation_payload()))]).unwrap_err();
            assert!(
                err.contains("not committable for relation payloads"),
                "verb {verb}: {err}"
            );
        }
    }

    #[test]
    fn validate_staged_operations_rejects_blob_payload() {
        let err =
            validate_staged_operations(&[op("create", Some(McpMutationPayload::Blob(vec![1, 2])))])
                .unwrap_err();
        assert!(
            err.contains("blob payloads are not yet committable"),
            "{err}"
        );
    }

    #[test]
    fn validate_staged_operations_accepts_relation_add_remove() {
        // create/add and delete/remove ARE committable for relations and must
        // still pass stage time.
        for verb in ["add", "create", "remove", "delete"] {
            assert!(
                validate_staged_operations(&[op(verb, Some(relation_payload()))]).is_ok(),
                "relation verb {verb} should stage cleanly"
            );
        }
    }

    #[test]
    fn stage_time_rejection_is_superset_of_commit_drop() {
        // Parity invariant: any batch the commit path would reject as
        // uncommittable must also be rejected at stage time. Guards against the
        // stage/commit asymmetry where an op stages green then drops at commit.
        let drop_batches = vec![
            vec![op("modify", Some(relation_payload()))],
            vec![op("update", Some(relation_payload()))],
            vec![op("create", Some(McpMutationPayload::Blob(vec![9])))],
            vec![op("create", None)],
            vec![op(
                "frobnicate",
                Some(McpMutationPayload::Entity(entity_named("x"))),
            )],
        ];
        for ops in &drop_batches {
            assert!(
                !uncommittable_operations(ops).is_empty(),
                "fixture should be uncommittable: {ops:?}"
            );
            assert!(
                validate_staged_operations(ops).is_err(),
                "commit would drop this but stage accepted it: {ops:?}"
            );
        }
    }

    fn relation_payload() -> McpMutationPayload {
        McpMutationPayload::Relation {
            from: EntityId::new(),
            to: EntityId::new(),
            kind: kin_model::relation::RelationKind::Calls,
        }
    }

    #[test]
    fn uncommittable_operations_accepts_commit_supported_payloads() {
        let ops = vec![
            op(
                "create",
                Some(McpMutationPayload::Entity(entity_named("foo"))),
            ),
            op("add", Some(relation_payload())),
            op("remove", Some(relation_payload())),
        ];
        assert!(uncommittable_operations(&ops).is_empty());
    }

    #[test]
    fn uncommittable_operations_reports_commit_silent_drop_cases() {
        let ops = vec![
            op("modify", Some(relation_payload())),
            op("create", Some(McpMutationPayload::Blob(vec![1, 2, 3]))),
        ];
        let reasons = uncommittable_operations(&ops);
        assert_eq!(reasons.len(), 2);
        assert!(reasons[0].contains("operation #0"), "{reasons:?}");
        assert!(
            reasons[0].contains("not committable for relation payloads"),
            "{reasons:?}"
        );
        assert!(reasons[1].contains("operation #1"), "{reasons:?}");
        assert!(reasons[1].contains("blob payloads"), "{reasons:?}");
    }
}
