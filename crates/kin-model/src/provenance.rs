// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Provenance graph types: actors, delegations, approvals, and audit events.
//!
//! Phase 10 introduces first-class graph objects for provenance tracking —
//! actors (human, assistant, service), delegation chains, approval decisions,
//! and audit events that record who did what and when.

use crate::ids::{Hash256, SemanticChangeId};
use crate::timestamp::Timestamp;
use crate::work::WorkScope;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// IDs
// ---------------------------------------------------------------------------

/// Unique identifier for an actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActorId(pub Hash256);

impl ActorId {
    pub fn new() -> Self {
        let bytes = *uuid::Uuid::new_v4().as_bytes();
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(&bytes);
        Self(Hash256::from_bytes(buf))
    }

    pub fn from_hash(h: Hash256) -> Self {
        Self(h)
    }
}

impl Default for ActorId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ActorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a delegation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DelegationId(pub Hash256);

impl DelegationId {
    pub fn new() -> Self {
        let bytes = *uuid::Uuid::new_v4().as_bytes();
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(&bytes);
        Self(Hash256::from_bytes(buf))
    }

    pub fn from_hash(h: Hash256) -> Self {
        Self(h)
    }
}

impl Default for DelegationId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DelegationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApprovalId(pub Hash256);

impl ApprovalId {
    pub fn new() -> Self {
        let bytes = *uuid::Uuid::new_v4().as_bytes();
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(&bytes);
        Self(Hash256::from_bytes(buf))
    }

    pub fn from_hash(h: Hash256) -> Self {
        Self(h)
    }
}

impl Default for ApprovalId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ApprovalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for an audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuditEventId(pub Hash256);

impl AuditEventId {
    pub fn new() -> Self {
        let bytes = *uuid::Uuid::new_v4().as_bytes();
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(&bytes);
        Self(Hash256::from_bytes(buf))
    }

    pub fn from_hash(h: Hash256) -> Self {
        Self(h)
    }
}

impl Default for AuditEventId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for AuditEventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActorKind {
    Human,
    Assistant,
    Service,
}

impl std::fmt::Display for ActorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Human => write!(f, "human"),
            Self::Assistant => write!(f, "assistant"),
            Self::Service => write!(f, "service"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApprovalDecision {
    Approved,
    Rejected,
    Conditional,
}

impl std::fmt::Display for ApprovalDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Approved => write!(f, "approved"),
            Self::Rejected => write!(f, "rejected"),
            Self::Conditional => write!(f, "conditional"),
        }
    }
}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub actor_id: ActorId,
    pub kind: ActorKind,
    pub display_name: String,
    pub external_refs: Vec<crate::work::ExternalRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    pub delegation_id: DelegationId,
    pub principal: ActorId,
    pub delegate: ActorId,
    pub scope: Vec<WorkScope>,
    pub started_at: Timestamp,
    pub ended_at: Option<Timestamp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub approval_id: ApprovalId,
    pub change_id: SemanticChangeId,
    pub approver: ActorId,
    pub decision: ApprovalDecision,
    pub reason: String,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: AuditEventId,
    pub actor_id: ActorId,
    pub action: String,
    pub target_scope: Option<WorkScope>,
    pub timestamp: Timestamp,
    pub details: Option<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{EntityId, Hash256};
    use crate::work::ExternalRef;

    #[test]
    fn actor_id_display_not_empty() {
        let id = ActorId::new();
        assert!(!id.to_string().is_empty());
    }

    #[test]
    fn actor_id_from_hash_roundtrip() {
        let h = Hash256::from_bytes([0xaa; 32]);
        let id = ActorId::from_hash(h);
        assert_eq!(id.0, h);
    }

    #[test]
    fn delegation_id_display_not_empty() {
        let id = DelegationId::new();
        assert!(!id.to_string().is_empty());
    }

    #[test]
    fn approval_id_display_not_empty() {
        let id = ApprovalId::new();
        assert!(!id.to_string().is_empty());
    }

    #[test]
    fn audit_event_id_display_not_empty() {
        let id = AuditEventId::new();
        assert!(!id.to_string().is_empty());
    }

    #[test]
    fn actor_kind_display() {
        assert_eq!(ActorKind::Human.to_string(), "human");
        assert_eq!(ActorKind::Assistant.to_string(), "assistant");
        assert_eq!(ActorKind::Service.to_string(), "service");
    }

    #[test]
    fn approval_decision_display() {
        assert_eq!(ApprovalDecision::Approved.to_string(), "approved");
        assert_eq!(ApprovalDecision::Rejected.to_string(), "rejected");
        assert_eq!(ApprovalDecision::Conditional.to_string(), "conditional");
    }

    #[test]
    fn actor_id_serialization_roundtrip() {
        let id = ActorId::new();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: ActorId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn delegation_id_serialization_roundtrip() {
        let id = DelegationId::new();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: DelegationId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn approval_id_serialization_roundtrip() {
        let id = ApprovalId::new();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: ApprovalId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn audit_event_id_serialization_roundtrip() {
        let id = AuditEventId::new();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: AuditEventId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn actor_kind_serialization_roundtrip() {
        for kind in [ActorKind::Human, ActorKind::Assistant, ActorKind::Service] {
            let json = serde_json::to_string(&kind).unwrap();
            let parsed: ActorKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, parsed);
        }
    }

    #[test]
    fn approval_decision_serialization_roundtrip() {
        for decision in [
            ApprovalDecision::Approved,
            ApprovalDecision::Rejected,
            ApprovalDecision::Conditional,
        ] {
            let json = serde_json::to_string(&decision).unwrap();
            let parsed: ApprovalDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(decision, parsed);
        }
    }

    #[test]
    fn actor_serialization_roundtrip() {
        let actor = Actor {
            actor_id: ActorId::new(),
            kind: ActorKind::Human,
            display_name: "Alice".into(),
            external_refs: vec![ExternalRef {
                system: "github".into(),
                identifier: "alice".into(),
                url: None,
            }],
        };

        let json = serde_json::to_string(&actor).unwrap();
        let parsed: Actor = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.actor_id, actor.actor_id);
        assert_eq!(parsed.kind, actor.kind);
        assert_eq!(parsed.display_name, actor.display_name);
        assert_eq!(parsed.external_refs.len(), 1);
    }

    #[test]
    fn delegation_serialization_roundtrip() {
        let d = Delegation {
            delegation_id: DelegationId::new(),
            principal: ActorId::new(),
            delegate: ActorId::new(),
            scope: vec![WorkScope::Entity(EntityId::new())],
            started_at: Timestamp::now(),
            ended_at: None,
        };

        let json = serde_json::to_string(&d).unwrap();
        let parsed: Delegation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.delegation_id, d.delegation_id);
        assert_eq!(parsed.principal, d.principal);
        assert_eq!(parsed.delegate, d.delegate);
        assert_eq!(parsed.scope.len(), 1);
    }

    #[test]
    fn approval_serialization_roundtrip() {
        let change_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xcc; 32]));
        let a = Approval {
            approval_id: ApprovalId::new(),
            change_id,
            approver: ActorId::new(),
            decision: ApprovalDecision::Approved,
            reason: "LGTM".into(),
            timestamp: Timestamp::now(),
        };

        let json = serde_json::to_string(&a).unwrap();
        let parsed: Approval = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.approval_id, a.approval_id);
        assert_eq!(parsed.change_id, a.change_id);
        assert_eq!(parsed.decision, ApprovalDecision::Approved);
        assert_eq!(parsed.reason, "LGTM");
    }

    #[test]
    fn audit_event_serialization_roundtrip() {
        let event = AuditEvent {
            event_id: AuditEventId::new(),
            actor_id: ActorId::new(),
            action: "merge".into(),
            target_scope: Some(WorkScope::Entity(EntityId::new())),
            timestamp: Timestamp::now(),
            details: Some("merged feature branch".into()),
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_id, event.event_id);
        assert_eq!(parsed.action, "merge");
        assert!(parsed.target_scope.is_some());
        assert!(parsed.details.is_some());
    }

    #[test]
    fn audit_event_optional_fields() {
        let event = AuditEvent {
            event_id: AuditEventId::new(),
            actor_id: ActorId::new(),
            action: "login".into(),
            target_scope: None,
            timestamp: Timestamp::now(),
            details: None,
        };

        let json = serde_json::to_string(&event).unwrap();
        let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
        assert!(parsed.target_scope.is_none());
        assert!(parsed.details.is_none());
    }
}
