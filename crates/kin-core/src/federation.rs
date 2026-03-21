// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::Path;

use crate::{KinError, KinLayout, KinManifest, Result};
use kin_model::{
    ActorRef, AgentSession, GraphLocator, IntentScope, ScopeRef, SessionLease, Timestamp,
};

const DEFAULT_GRAPH_AUTHORITY: &str = "local";
const DEFAULT_GRAPH_ORGANIZATION: &str = "local";

fn graph_authority() -> String {
    for key in ["KIN_REMOTE_BASE_URL", "KINLAB_URL"] {
        if let Ok(value) = std::env::var(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.trim_end_matches('/').to_string();
            }
        }
    }
    DEFAULT_GRAPH_AUTHORITY.to_string()
}

fn graph_organization_id() -> String {
    if let Ok(value) = std::env::var("KIN_ORG_ID") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    DEFAULT_GRAPH_ORGANIZATION.to_string()
}

/// Resolve the local graph locator for a discovered Kin layout.
pub fn local_graph_locator(layout: &KinLayout) -> Result<GraphLocator> {
    let manifest = KinManifest::load(&layout.manifest_path())?;
    Ok(GraphLocator::new(
        graph_authority(),
        graph_organization_id(),
        manifest.repo_id,
    ))
}

/// Resolve the local graph locator by discovering a `.kin/` layout from cwd.
pub fn graph_locator_for_cwd(cwd: &Path) -> Result<GraphLocator> {
    let layout = KinLayout::discover(cwd).ok_or_else(|| {
        KinError::NotARepository(format!(
            "no .kin directory found when resolving graph locator from {}",
            cwd.display()
        ))
    })?;
    local_graph_locator(&layout)
}

/// Convert a local intent scope into a graph-aware scope reference.
pub fn scope_ref_from_intent_scope(graph: &GraphLocator, scope: &IntentScope) -> ScopeRef {
    match scope {
        IntentScope::Entity(entity_id) => ScopeRef::Entity {
            graph: graph.clone(),
            entity_id: *entity_id,
        },
        IntentScope::Contract(contract_id) => ScopeRef::Contract {
            graph: graph.clone(),
            contract_id: *contract_id,
        },
        IntentScope::Artifact(path) => ScopeRef::Artifact {
            graph: graph.clone(),
            path: path.clone(),
        },
    }
}

/// Convert a graph-aware scope ref into a local intent scope when it targets the local graph.
pub fn intent_scope_from_scope_ref(
    local_graph: &GraphLocator,
    scope_ref: &ScopeRef,
) -> Result<IntentScope> {
    if scope_ref.graph() != local_graph {
        return Err(KinError::Other(format!(
            "scope belongs to foreign graph {} (expected {})",
            scope_ref.graph(),
            local_graph
        )));
    }

    match scope_ref {
        ScopeRef::Entity { entity_id, .. } => Ok(IntentScope::Entity(*entity_id)),
        ScopeRef::Contract { contract_id, .. } => Ok(IntentScope::Contract(*contract_id)),
        ScopeRef::Artifact { path, .. } => Ok(IntentScope::Artifact(path.clone())),
        ScopeRef::Change { .. } | ScopeRef::Work { .. } => Err(KinError::Other(format!(
            "scope {} cannot be translated into a local intent scope",
            scope_ref
        ))),
    }
}

/// Build a stable local actor ref for a session.
pub fn actor_ref_for_session(graph: &GraphLocator, session: &AgentSession) -> ActorRef {
    ActorRef::new(graph.authority.clone(), session.session_id.to_string())
}

/// Build a local compatibility lease for a session.
pub fn session_lease_for_session(
    graph: &GraphLocator,
    session: &AgentSession,
    expires_at: Timestamp,
) -> SessionLease {
    SessionLease {
        session_id: session.session_id,
        actor: actor_ref_for_session(graph, session),
        graph: graph.clone(),
        transport: session.transport,
        capabilities: session.capabilities.clone(),
        expires_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{EntityId, FilePathId, SessionCapabilities, SessionId, SessionTransport};
    use std::path::PathBuf;

    fn test_layout() -> KinLayout {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let manifest = KinManifest::new();
        manifest.save(&kin_dir.join("manifest.json")).unwrap();
        // Keep directory alive by leaking it for the test duration.
        std::mem::forget(dir);
        KinLayout::new(kin_dir)
    }

    #[test]
    fn local_graph_locator_uses_manifest_repo_id() {
        let layout = test_layout();
        let manifest = KinManifest::load(&layout.manifest_path()).unwrap();
        let locator = local_graph_locator(&layout).unwrap();
        assert_eq!(locator.repo_id, manifest.repo_id);
        assert_eq!(locator.authority, DEFAULT_GRAPH_AUTHORITY);
        assert_eq!(locator.organization_id, DEFAULT_GRAPH_ORGANIZATION);
    }

    #[test]
    fn intent_scope_roundtrip_for_local_graph() {
        let layout = test_layout();
        let graph = local_graph_locator(&layout).unwrap();
        let scope = IntentScope::Entity(EntityId::new());
        let scope_ref = scope_ref_from_intent_scope(&graph, &scope);
        let roundtrip = intent_scope_from_scope_ref(&graph, &scope_ref).unwrap();
        assert_eq!(roundtrip, scope);
    }

    #[test]
    fn change_scope_is_rejected_for_local_intent_conversion() {
        let layout = test_layout();
        let graph = local_graph_locator(&layout).unwrap();
        let scope_ref = ScopeRef::Change {
            graph: graph.clone(),
            change_id: kin_model::SemanticChangeId::from_hash(kin_model::Hash256::from_bytes(
                [7; 32],
            )),
        };
        let error = intent_scope_from_scope_ref(&graph, &scope_ref).unwrap_err();
        assert!(error.to_string().contains("cannot be translated"));
    }

    #[test]
    fn session_lease_uses_session_identity() {
        let layout = test_layout();
        let graph = local_graph_locator(&layout).unwrap();
        let session = AgentSession {
            session_id: SessionId::new(),
            vendor: "codex".into(),
            client_name: "test".into(),
            transport: SessionTransport::Mcp,
            pid: None,
            cwd: PathBuf::from("/tmp"),
            started_at: Timestamp::now(),
            last_heartbeat: Timestamp::now(),
            capabilities: SessionCapabilities::default(),
        };

        let lease = session_lease_for_session(&graph, &session, Timestamp::now());
        assert_eq!(lease.session_id, session.session_id);
        assert_eq!(lease.graph, graph);
        assert_eq!(lease.actor.actor_id, session.session_id.to_string());
    }

    #[test]
    fn artifact_scope_ref_preserves_path() {
        let layout = test_layout();
        let graph = local_graph_locator(&layout).unwrap();
        let scope = IntentScope::Artifact(FilePathId::new("src/lib.rs"));
        let scope_ref = scope_ref_from_intent_scope(&graph, &scope);
        match scope_ref {
            ScopeRef::Artifact { path, .. } => assert_eq!(path, FilePathId::new("src/lib.rs")),
            _ => panic!("expected artifact scope"),
        }
    }
}
