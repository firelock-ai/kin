// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::provenance::{Actor, ActorId, ActorKind, AuditEvent, AuditEventId};
use kin_model::{ExternalRef, GraphStore, Hash256, Timestamp, WorkScope};
use sha2::{Digest, Sha256};

pub fn ensure_cli_actor<G>(graph: &G) -> Result<ActorId>
where
    G: GraphStore,
    G::Error: std::fmt::Display + Send + Sync + 'static,
{
    let label = current_actor_label();
    let actor_id = actor_id_from_label(&label);
    if graph
        .get_actor(&actor_id)
        .map_err(|err| anyhow::anyhow!(err.to_string()))?
        .is_none()
    {
        let actor = Actor {
            actor_id,
            kind: actor_kind_from_label(&label),
            display_name: label.clone(),
            external_refs: vec![ExternalRef {
                system: "local".into(),
                identifier: label,
                url: None,
            }],
        };
        graph
            .create_actor(&actor)
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    }
    Ok(actor_id)
}

pub fn record_cli_audit_event<G>(
    graph: &G,
    action: &str,
    target_scope: Option<WorkScope>,
    details: Option<String>,
) -> Result<AuditEventId>
where
    G: GraphStore,
    G::Error: std::fmt::Display + Send + Sync + 'static,
{
    let actor_id = ensure_cli_actor(graph)?;
    let event = AuditEvent {
        event_id: AuditEventId::new(),
        actor_id,
        action: action.to_string(),
        target_scope,
        timestamp: Timestamp::now(),
        details,
    };
    graph
        .record_audit_event(&event)
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    Ok(event.event_id)
}

fn current_actor_label() -> String {
    std::env::var("KIN_ACTOR")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| std::env::var("USER").ok())
        .or_else(|| std::env::var("LOGNAME").ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "kin-cli".to_string())
}

fn actor_kind_from_label(label: &str) -> ActorKind {
    let lowered = label.to_ascii_lowercase();
    if lowered.contains("codex")
        || lowered.contains("assistant")
        || lowered.contains("claude")
        || lowered.contains("gemini")
        || lowered.contains("agent")
    {
        ActorKind::Assistant
    } else if lowered.contains("service") || lowered.contains("daemon") {
        ActorKind::Service
    } else {
        ActorKind::Human
    }
}

fn actor_id_from_label(label: &str) -> ActorId {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    ActorId::from_hash(Hash256::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_kind_detects_assistant_labels() {
        assert_eq!(actor_kind_from_label("codex-agent"), ActorKind::Assistant);
        assert_eq!(actor_kind_from_label("build-service"), ActorKind::Service);
        assert_eq!(actor_kind_from_label("troy"), ActorKind::Human);
    }

    #[test]
    fn actor_id_is_stable_for_same_label() {
        let a = actor_id_from_label("troy");
        let b = actor_id_from_label("troy");
        assert_eq!(a, b);
    }
}
