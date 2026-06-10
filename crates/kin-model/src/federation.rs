// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Federation primitives for graph addressing and hosted coordination.
//!
//! These types sit above local Kin IDs rather than replacing them. They give
//! KinLab and `kin-remote` a stable way to refer to graphs, scopes, leases,
//! and remote relations across repo boundaries.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::ids::{ContractId, EntityId, FilePathId, Hash256, SemanticChangeId, SessionId};
use crate::relation::{RelationKind, RelationOrigin};
use crate::session::{SessionCapabilities, SessionTransport};
use crate::timestamp::Timestamp;
use crate::work::WorkId;

/// Routable identity for a Kin graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GraphLocator {
    pub authority: String,
    pub organization_id: String,
    pub repo_id: String,
}

impl GraphLocator {
    pub fn new(
        authority: impl Into<String>,
        organization_id: impl Into<String>,
        repo_id: impl Into<String>,
    ) -> Self {
        Self {
            authority: authority.into().trim_end_matches('/').to_string(),
            organization_id: organization_id.into(),
            repo_id: repo_id.into(),
        }
    }

    pub fn kin_uri(&self) -> String {
        format!(
            "kin://{}/{}/{}",
            self.authority.trim_end_matches('/'),
            self.organization_id,
            self.repo_id
        )
    }
}

impl fmt::Display for GraphLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kin_uri())
    }
}

/// A stable reference to a scope in a specific graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScopeRef {
    Entity {
        graph: GraphLocator,
        entity_id: EntityId,
    },
    Contract {
        graph: GraphLocator,
        contract_id: ContractId,
    },
    Artifact {
        graph: GraphLocator,
        path: FilePathId,
    },
    Change {
        graph: GraphLocator,
        change_id: SemanticChangeId,
    },
    Work {
        graph: GraphLocator,
        work_id: WorkId,
    },
}

impl ScopeRef {
    pub fn graph(&self) -> &GraphLocator {
        match self {
            ScopeRef::Entity { graph, .. }
            | ScopeRef::Contract { graph, .. }
            | ScopeRef::Artifact { graph, .. }
            | ScopeRef::Change { graph, .. }
            | ScopeRef::Work { graph, .. } => graph,
        }
    }
}

impl fmt::Display for ScopeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScopeRef::Entity { graph, entity_id } => {
                write!(f, "{}/entities/{}", graph.kin_uri(), entity_id)
            }
            ScopeRef::Contract { graph, contract_id } => {
                write!(f, "{}/contracts/{}", graph.kin_uri(), contract_id)
            }
            ScopeRef::Artifact { graph, path } => {
                write!(f, "{}/artifacts/{}", graph.kin_uri(), path)
            }
            ScopeRef::Change { graph, change_id } => {
                write!(f, "{}/changes/{}", graph.kin_uri(), change_id)
            }
            ScopeRef::Work { graph, work_id } => {
                write!(f, "{}/work/{}", graph.kin_uri(), work_id)
            }
        }
    }
}

/// Global identity for an actor that can participate in federated work.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActorRef {
    pub authority: String,
    pub actor_id: String,
}

impl ActorRef {
    pub fn new(authority: impl Into<String>, actor_id: impl Into<String>) -> Self {
        Self {
            authority: authority.into().trim_end_matches('/').to_string(),
            actor_id: actor_id.into(),
        }
    }
}

impl fmt::Display for ActorRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "actor://{}/{}", self.authority, self.actor_id)
    }
}

/// Capability summary published by a graph or hosted authority.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GraphCapabilitySet {
    pub can_publish_semantic_changes: bool,
    pub can_publish_review_state: bool,
    pub can_publish_proofs: bool,
    pub can_subscribe: bool,
    pub can_grant_intent_leases: bool,
    pub can_serve_subgraphs: bool,
}

/// Published identity and trust metadata for a graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphManifest {
    pub graph: GraphLocator,
    pub default_branch: String,
    pub head_change: Option<SemanticChangeId>,
    pub graph_root_hash: Option<Hash256>,
    pub published_at: Timestamp,
    pub protocol_version: String,
    pub capabilities: GraphCapabilitySet,
}

/// Session lease issued by a hosted authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionLease {
    pub session_id: SessionId,
    pub actor: ActorRef,
    pub graph: GraphLocator,
    pub transport: SessionTransport,
    pub capabilities: SessionCapabilities,
    #[serde(default = "default_fence_epoch")]
    pub fence_epoch: u64,
    pub expires_at: Timestamp,
}

fn default_fence_epoch() -> u64 {
    1
}

/// Cross-graph relation categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RemoteRelationKind {
    Calls,
    Imports,
    Includes,
    Contains,
    References,
    UsesMacro,
    Implements,
    Extends,
    Overrides,
    Instantiates,
    UsesType,
    SubscribesTo,
    SendsMessage,
    Spawns,
    Tests,
    DependsOn,
    CoChanges,
    DefinesContract,
    ConsumesContract,
    EmitsEvent,
    OwnedBy,
    DocumentedBy,
    Covers,
    DerivedFrom,
    OwnedByFile,
}

impl From<RelationKind> for RemoteRelationKind {
    fn from(value: RelationKind) -> Self {
        match value {
            RelationKind::Calls => Self::Calls,
            RelationKind::Imports => Self::Imports,
            RelationKind::Includes => Self::Includes,
            RelationKind::Contains => Self::Contains,
            RelationKind::References => Self::References,
            RelationKind::UsesMacro => Self::UsesMacro,
            RelationKind::Implements => Self::Implements,
            RelationKind::Extends => Self::Extends,
            RelationKind::Tests => Self::Tests,
            RelationKind::DependsOn => Self::DependsOn,
            RelationKind::CoChanges => Self::CoChanges,
            RelationKind::DefinesContract => Self::DefinesContract,
            RelationKind::ConsumesContract => Self::ConsumesContract,
            RelationKind::EmitsEvent => Self::EmitsEvent,
            RelationKind::OwnedBy => Self::OwnedBy,
            RelationKind::DocumentedBy => Self::DocumentedBy,
            RelationKind::Covers => Self::Covers,
            RelationKind::DerivedFrom => Self::DerivedFrom,
            RelationKind::OwnedByFile => Self::OwnedByFile,
            RelationKind::Overrides => Self::Overrides,
            RelationKind::Instantiates => Self::Instantiates,
            RelationKind::UsesType => Self::UsesType,
            RelationKind::SubscribesTo => Self::SubscribesTo,
            RelationKind::SendsMessage => Self::SendsMessage,
            RelationKind::Spawns => Self::Spawns,
        }
    }
}

impl From<RemoteRelationKind> for RelationKind {
    fn from(value: RemoteRelationKind) -> Self {
        match value {
            RemoteRelationKind::Calls => Self::Calls,
            RemoteRelationKind::Imports => Self::Imports,
            RemoteRelationKind::Includes => Self::Includes,
            RemoteRelationKind::Contains => Self::Contains,
            RemoteRelationKind::References => Self::References,
            RemoteRelationKind::UsesMacro => Self::UsesMacro,
            RemoteRelationKind::Implements => Self::Implements,
            RemoteRelationKind::Extends => Self::Extends,
            RemoteRelationKind::Tests => Self::Tests,
            RemoteRelationKind::DependsOn => Self::DependsOn,
            RemoteRelationKind::CoChanges => Self::CoChanges,
            RemoteRelationKind::DefinesContract => Self::DefinesContract,
            RemoteRelationKind::ConsumesContract => Self::ConsumesContract,
            RemoteRelationKind::EmitsEvent => Self::EmitsEvent,
            RemoteRelationKind::OwnedBy => Self::OwnedBy,
            RemoteRelationKind::DocumentedBy => Self::DocumentedBy,
            RemoteRelationKind::Covers => Self::Covers,
            RemoteRelationKind::DerivedFrom => Self::DerivedFrom,
            RemoteRelationKind::OwnedByFile => Self::OwnedByFile,
            RemoteRelationKind::Overrides => Self::Overrides,
            RemoteRelationKind::Instantiates => Self::Instantiates,
            RemoteRelationKind::UsesType => Self::UsesType,
            RemoteRelationKind::SubscribesTo => Self::SubscribesTo,
            RemoteRelationKind::SendsMessage => Self::SendsMessage,
            RemoteRelationKind::Spawns => Self::Spawns,
        }
    }
}

/// How a remote relation was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RemoteRelationOrigin {
    Parsed,
    Inferred,
    Manual,
    Imported,
    Overlay,
}

impl From<RelationOrigin> for RemoteRelationOrigin {
    fn from(value: RelationOrigin) -> Self {
        match value {
            RelationOrigin::Parsed => Self::Parsed,
            RelationOrigin::Inferred => Self::Inferred,
            RelationOrigin::Manual => Self::Manual,
            RelationOrigin::Lsp => Self::Inferred, // LSP maps to Inferred for remote federation
        }
    }
}

/// A typed edge between scopes in possibly different graphs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoteRelation {
    pub relation_id: String,
    pub kind: RemoteRelationKind,
    pub src: ScopeRef,
    pub dst: ScopeRef,
    pub asserted_by: GraphLocator,
    pub confidence: f32,
    pub origin: RemoteRelationOrigin,
    pub created_at: Option<Timestamp>,
}

impl RemoteRelation {
    pub fn new(
        relation_id: impl Into<String>,
        kind: RemoteRelationKind,
        src: ScopeRef,
        dst: ScopeRef,
        asserted_by: GraphLocator,
        origin: RemoteRelationOrigin,
    ) -> Self {
        Self {
            relation_id: relation_id.into(),
            kind,
            src,
            dst,
            asserted_by,
            confidence: 1.0,
            origin,
            created_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relation::{RelationKind, RelationOrigin};
    use pretty_assertions::assert_eq;

    #[test]
    fn graph_locator_roundtrip() {
        let locator = GraphLocator::new("https://kinlab.example.com", "acme", "repo-1");
        let json = serde_json::to_string(&locator).unwrap();
        let parsed: GraphLocator = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, locator);
        assert_eq!(
            locator.kin_uri(),
            "kin://https://kinlab.example.com/acme/repo-1"
        );
    }

    #[test]
    fn scope_ref_roundtrip() {
        let graph = GraphLocator::new("https://kinlab.example.com", "acme", "repo-1");
        let scope = ScopeRef::Work {
            graph,
            work_id: WorkId::new(),
        };
        let json = serde_json::to_string(&scope).unwrap();
        let parsed: ScopeRef = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, scope);
        assert!(parsed.to_string().contains("/work/"));
    }

    #[test]
    fn remote_relation_kind_conversions_roundtrip() {
        for local in [RelationKind::DependsOn, RelationKind::CoChanges] {
            let remote: RemoteRelationKind = local.into();
            let back: RelationKind = remote.into();
            assert_eq!(back, local);
        }
    }

    #[test]
    fn remote_relation_origin_from_local_origin() {
        let origin = RemoteRelationOrigin::from(RelationOrigin::Parsed);
        assert_eq!(origin, RemoteRelationOrigin::Parsed);
    }

    #[test]
    fn graph_manifest_roundtrip() {
        let graph = GraphLocator::new("https://kinlab.example.com", "acme", "repo-1");
        let manifest = GraphManifest {
            graph,
            default_branch: "main".into(),
            head_change: Some(SemanticChangeId::from_hash(Hash256::from_bytes([1; 32]))),
            graph_root_hash: Some(Hash256::from_bytes([2; 32])),
            published_at: Timestamp::now(),
            protocol_version: "1".into(),
            capabilities: GraphCapabilitySet {
                can_publish_semantic_changes: true,
                can_publish_review_state: true,
                can_publish_proofs: true,
                can_subscribe: true,
                can_grant_intent_leases: true,
                can_serve_subgraphs: true,
            },
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: GraphManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.graph, manifest.graph);
        assert_eq!(parsed.default_branch, "main");
        assert_eq!(parsed.protocol_version, "1");
    }

    #[test]
    fn session_lease_roundtrip() {
        let graph = GraphLocator::new("https://kinlab.example.com", "acme", "repo-1");
        let lease = SessionLease {
            session_id: SessionId::new(),
            actor: ActorRef::new("https://kinlab.example.com", "actor-1"),
            graph,
            transport: SessionTransport::Mcp,
            capabilities: SessionCapabilities::default(),
            fence_epoch: 1,
            expires_at: Timestamp::now(),
        };
        let json = serde_json::to_string(&lease).unwrap();
        let parsed: SessionLease = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.graph, lease.graph);
        assert_eq!(parsed.actor, lease.actor);
        assert_eq!(parsed.transport, SessionTransport::Mcp);
    }

    #[test]
    fn session_lease_defaults_fence_epoch_for_legacy_payloads() {
        let lease_json = serde_json::json!({
            "session_id": SessionId::new(),
            "actor": {
                "authority": "https://kinlab.example.com",
                "actor_id": "actor-1",
            },
            "graph": {
                "authority": "https://kinlab.example.com",
                "organization_id": "acme",
                "repo_id": "repo-1",
            },
            "transport": "Mcp",
            "capabilities": SessionCapabilities::default(),
            "expires_at": Timestamp::now(),
        });

        let parsed: SessionLease = serde_json::from_value(lease_json).unwrap();
        assert_eq!(parsed.fence_epoch, 1);
    }

    #[test]
    fn remote_relation_roundtrip() {
        let graph = GraphLocator::new("https://kinlab.example.com", "acme", "repo-1");
        let relation = RemoteRelation::new(
            "rel-1",
            RemoteRelationKind::DependsOn,
            ScopeRef::Entity {
                graph: graph.clone(),
                entity_id: EntityId::new(),
            },
            ScopeRef::Contract {
                graph: graph.clone(),
                contract_id: ContractId::new(),
            },
            graph.clone(),
            RemoteRelationOrigin::Imported,
        );
        let json = serde_json::to_string(&relation).unwrap();
        let parsed: RemoteRelation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.relation_id, "rel-1");
        assert_eq!(parsed.kind, RemoteRelationKind::DependsOn);
        assert_eq!(parsed.origin, RemoteRelationOrigin::Imported);
        assert_eq!(parsed.asserted_by, graph);

        let cochange = RemoteRelation::new(
            "rel-2",
            RemoteRelationKind::CoChanges,
            ScopeRef::Entity {
                graph: graph.clone(),
                entity_id: EntityId::new(),
            },
            ScopeRef::Entity {
                graph: graph.clone(),
                entity_id: EntityId::new(),
            },
            graph.clone(),
            RemoteRelationOrigin::Imported,
        );
        let json = serde_json::to_string(&cochange).unwrap();
        let parsed: RemoteRelation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.kind, RemoteRelationKind::CoChanges);
    }
}
