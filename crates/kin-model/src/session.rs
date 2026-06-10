// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::ids::{ContractId, EntityId, FilePathId, IntentId, SessionId};
use crate::timestamp::Timestamp;

/// How the agent session connects to Kin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SessionTransport {
    /// MCP (Model Context Protocol) connection.
    Mcp,
    /// Direct CLI invocation.
    Cli,
    /// External wrapper (e.g., aider, continue.dev).
    Wrapper,
    /// Local UI (web-based dashboard).
    Ui,
}

/// Capabilities declared by the agent session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCapabilities {
    /// Agent can read files.
    pub can_read: bool,
    /// Agent can write files.
    pub can_write: bool,
    /// Agent can execute commands.
    pub can_execute: bool,
    /// Agent can create branches.
    pub can_branch: bool,
    /// Agent can commit semantic changes.
    pub can_commit: bool,
    /// Maximum number of concurrent intents this session supports.
    pub max_concurrent_intents: usize,
}

impl Default for SessionCapabilities {
    fn default() -> Self {
        Self {
            can_read: true,
            can_write: false,
            can_execute: false,
            can_branch: false,
            can_commit: false,
            max_concurrent_intents: 1,
        }
    }
}

/// A registered agent session (transient, not part of semantic history).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSession {
    pub session_id: SessionId,
    /// Vendor identifier: "claude-code", "codex", "gemini-cli", etc.
    pub vendor: String,
    /// User-facing session name.
    pub client_name: String,
    /// How the session connects to Kin.
    pub transport: SessionTransport,
    /// OS process ID (if known).
    pub pid: Option<u32>,
    /// Working directory of the agent.
    pub cwd: PathBuf,
    /// When the session was registered.
    pub started_at: Timestamp,
    /// Last heartbeat received from the agent.
    pub last_heartbeat: Timestamp,
    /// Declared capabilities.
    pub capabilities: SessionCapabilities,
}

/// Lock strength for an intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LockType {
    /// Advisory lock: other agents see a warning but can proceed.
    Soft,
    /// Exclusive lock: other agents are blocked from modifying the scope.
    Hard,
}

/// What an intent targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntentScope {
    /// An entity in the semantic graph.
    Entity(EntityId),
    /// A contract (API, schema, protocol).
    Contract(ContractId),
    /// A file artifact.
    Artifact(FilePathId),
}

/// A declared intent from an agent session (transient, not part of semantic history).
///
/// Intents represent what an agent plans to modify, enabling collision
/// detection before conflicting writes occur.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    pub intent_id: IntentId,
    /// Session that owns this intent.
    pub session_id: SessionId,
    /// What the intent targets (entities, contracts, files).
    pub scopes: Vec<IntentScope>,
    /// Lock strength.
    pub lock_type: LockType,
    /// Human-readable description of what the agent plans to do.
    pub task_description: String,
    /// When the intent was registered.
    pub registered_at: Timestamp,
    /// Optional expiry (after which the intent is auto-reaped).
    pub expires_at: Option<Timestamp>,
}

/// Classification of an intent conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntentConflict {
    /// Two hard locks on the same scope.
    HardCollision,
    /// A soft lock overlaps with downstream impact of another intent.
    DownstreamWarning,
    /// The conflicting session has expired.
    SessionExpired,
}

/// Summary of an intent for display in traffic reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentSummary {
    pub intent_id: IntentId,
    pub session_id: SessionId,
    pub vendor: String,
    pub task_description: String,
    pub lock_type: LockType,
    pub registered_at: Timestamp,
}

impl IntentSummary {
    /// Human-readable label for the lock type.
    pub fn lock_type_label(&self) -> &'static str {
        match self.lock_type {
            LockType::Soft => "soft-lock",
            LockType::Hard => "hard-lock",
        }
    }
}

/// Traffic report for a given scope target.
///
/// Shows what agents are actively working on or near a given
/// entity/contract/file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficReport {
    /// The scope being queried.
    pub target: IntentScope,
    /// Intents that directly lock this target.
    pub active_intents: Vec<IntentSummary>,
    /// Intents that lock downstream dependencies (warning zone).
    pub downstream_warnings: Vec<IntentSummary>,
}

/// Events emitted by the coordination system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoordinationEvent {
    /// A new session was registered.
    SessionRegistered {
        session_id: SessionId,
        vendor: String,
    },
    /// A session was deregistered (clean exit or reap).
    SessionDeregistered {
        session_id: SessionId,
        reason: String,
    },
    /// An intent was registered.
    IntentRegistered {
        intent_id: IntentId,
        session_id: SessionId,
    },
    /// An intent was released.
    IntentReleased { intent_id: IntentId },
    /// A conflict was detected between intents.
    ConflictDetected {
        intent_a: IntentId,
        intent_b: IntentId,
        conflict: IntentConflict,
    },
    /// A session heartbeat was received.
    Heartbeat { session_id: SessionId },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_transport_roundtrip() {
        let t = SessionTransport::Mcp;
        let json = serde_json::to_string(&t).unwrap();
        let parsed: SessionTransport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, t);
    }

    #[test]
    fn lock_type_roundtrip() {
        let lt = LockType::Hard;
        let json = serde_json::to_string(&lt).unwrap();
        let parsed: LockType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, lt);
    }

    #[test]
    fn intent_scope_entity() {
        let scope = IntentScope::Entity(EntityId::new());
        let json = serde_json::to_string(&scope).unwrap();
        let parsed: IntentScope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, scope);
    }

    #[test]
    fn intent_scope_artifact() {
        let scope = IntentScope::Artifact(FilePathId::new("src/main.rs"));
        let json = serde_json::to_string(&scope).unwrap();
        let parsed: IntentScope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, scope);
    }

    #[test]
    fn intent_conflict_roundtrip() {
        let c = IntentConflict::HardCollision;
        let json = serde_json::to_string(&c).unwrap();
        let parsed: IntentConflict = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn session_capabilities_default() {
        let caps = SessionCapabilities::default();
        assert!(caps.can_read);
        assert!(!caps.can_write);
        assert!(!caps.can_execute);
        assert_eq!(caps.max_concurrent_intents, 1);
    }

    #[test]
    fn coordination_event_roundtrip() {
        let event = CoordinationEvent::ConflictDetected {
            intent_a: IntentId::new(),
            intent_b: IntentId::new(),
            conflict: IntentConflict::DownstreamWarning,
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: CoordinationEvent = serde_json::from_str(&json).unwrap();
        // Verify it round-trips (can't compare directly since IntentId is random,
        // but if it parses, the schema is correct).
        let json2 = serde_json::to_string(&parsed).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn agent_session_serializes() {
        let now = Timestamp::now();
        let session = AgentSession {
            session_id: SessionId::new(),
            vendor: "claude-code".to_string(),
            client_name: "test-session".to_string(),
            transport: SessionTransport::Mcp,
            pid: Some(12345),
            cwd: PathBuf::from("/project"),
            started_at: now.clone(),
            last_heartbeat: now,
            capabilities: SessionCapabilities::default(),
        };
        let json = serde_json::to_string(&session).unwrap();
        let parsed: AgentSession = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.vendor, "claude-code");
        assert_eq!(parsed.transport, SessionTransport::Mcp);
    }

    #[test]
    fn intent_serializes() {
        let now = Timestamp::now();
        let intent = Intent {
            intent_id: IntentId::new(),
            session_id: SessionId::new(),
            scopes: vec![
                IntentScope::Entity(EntityId::new()),
                IntentScope::Artifact(FilePathId::new("src/lib.rs")),
            ],
            lock_type: LockType::Soft,
            task_description: "Refactoring auth module".to_string(),
            registered_at: now,
            expires_at: None,
        };
        let json = serde_json::to_string(&intent).unwrap();
        let parsed: Intent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.scopes.len(), 2);
        assert_eq!(parsed.lock_type, LockType::Soft);
    }

    #[test]
    fn traffic_report_serializes() {
        let report = TrafficReport {
            target: IntentScope::Entity(EntityId::new()),
            active_intents: vec![],
            downstream_warnings: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: TrafficReport = serde_json::from_str(&json).unwrap();
        assert!(parsed.active_intents.is_empty());
    }
}
