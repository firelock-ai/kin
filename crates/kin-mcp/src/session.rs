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
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            agent_sessions: Mutex::new(HashMap::new()),
            intents: Mutex::new(HashMap::new()),
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
}
