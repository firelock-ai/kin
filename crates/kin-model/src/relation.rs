// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::entity::SourceSpan;
use crate::ids::{ContractId, EntityId, RelationId, SemanticChangeId};
use crate::retrieval::ArtifactId;
use crate::verification::{TestId, VerificationRunId};
use crate::work::WorkId;

/// Typed graph node reference for first-class mixed-domain relations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum GraphNodeId {
    Entity(EntityId),
    Artifact(ArtifactId),
    Test(TestId),
    Contract(ContractId),
    Work(WorkId),
    VerificationRun(VerificationRunId),
}

impl GraphNodeId {
    pub fn as_entity(&self) -> Option<EntityId> {
        match self {
            Self::Entity(id) => Some(*id),
            _ => None,
        }
    }
}

impl fmt::Display for GraphNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entity(id) => write!(f, "entity:{id}"),
            Self::Artifact(id) => write!(f, "artifact:{}", id.0),
            Self::Test(id) => write!(f, "test:{id}"),
            Self::Contract(id) => write!(f, "contract:{id}"),
            Self::Work(id) => write!(f, "work:{id}"),
            Self::VerificationRun(id) => write!(f, "verification_run:{id}"),
        }
    }
}

impl From<EntityId> for GraphNodeId {
    fn from(value: EntityId) -> Self {
        Self::Entity(value)
    }
}

impl From<ArtifactId> for GraphNodeId {
    fn from(value: ArtifactId) -> Self {
        Self::Artifact(value)
    }
}

impl From<TestId> for GraphNodeId {
    fn from(value: TestId) -> Self {
        Self::Test(value)
    }
}

impl From<ContractId> for GraphNodeId {
    fn from(value: ContractId) -> Self {
        Self::Contract(value)
    }
}

impl From<WorkId> for GraphNodeId {
    fn from(value: WorkId) -> Self {
        Self::Work(value)
    }
}

impl From<VerificationRunId> for GraphNodeId {
    fn from(value: VerificationRunId) -> Self {
        Self::VerificationRun(value)
    }
}

/// A typed edge in the semantic graph.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Relation {
    pub id: RelationId,
    pub kind: RelationKind,
    pub src: GraphNodeId,
    pub dst: GraphNodeId,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f32,
    pub origin: RelationOrigin,
    /// None while in overlay; set on kin commit.
    pub created_in: Option<SemanticChangeId>,
    /// For Calls/References edges, the module/package the target was imported from.
    /// Enables qualified cross-repo resolution in the spine.
    /// e.g., "requests" for `from requests import get`,
    ///        "kin_db" for `use kin_db::InMemoryGraph`
    #[serde(default)]
    pub import_source: Option<String>,
    /// Parser/linker evidence for this edge. Older snapshots do not carry this
    /// field, so it must remain defaultable.
    #[serde(default)]
    pub evidence: Vec<RelationEvidence>,
}

/// Concrete evidence supporting a graph relation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RelationEvidence {
    /// Source span of the syntax that produced the edge, when available.
    #[serde(default)]
    pub source_span: Option<SourceSpan>,
    /// Parser or linker rule that produced this evidence.
    #[serde(default)]
    pub parser_rule: Option<String>,
    /// Lexical token at the evidence site, e.g. a macro name or imported symbol.
    #[serde(default)]
    pub token: Option<String>,
    /// Module/include path as written in source.
    #[serde(default)]
    pub source_path: Option<String>,
    /// Resolved graph-owned target path, when the linker could resolve it.
    #[serde(default)]
    pub resolved_path: Option<String>,
    /// Number of equivalent occurrences collapsed into this evidence record.
    #[serde(default = "default_relation_evidence_count")]
    pub occurrence_count: u32,
}

impl Default for RelationEvidence {
    fn default() -> Self {
        Self {
            source_span: None,
            parser_rule: None,
            token: None,
            source_path: None,
            resolved_path: None,
            occurrence_count: default_relation_evidence_count(),
        }
    }
}

fn default_relation_evidence_count() -> u32 {
    1
}

/// Classification of a relation edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum RelationKind {
    // ── Structural ──────────────────────────────
    Contains,   // parent encloses child (class→method, enum→variant)
    Extends,    // inherits implementation (class inheritance)
    Implements, // satisfies type contract (interface/trait/protocol)
    Overrides,  // method replaces parent method

    // ── Usage ───────────────────────────────────
    Calls,        // invokes at runtime
    Instantiates, // constructs an instance (new Foo(), Foo::new())
    References,   // non-call reference (field access, constant use)
    UsesMacro,    // C/C++ preprocessor macro expansion/use
    UsesType,     // type dependency in signature/body

    // ── Dependencies ────────────────────────────
    Imports,   // language-level import/use/require
    Includes,  // textual/file inclusion (#include, header include)
    DependsOn, // package/crate-level dependency

    // ── Behavioral ──────────────────────────────
    EmitsEvent,       // publishes named event
    SubscribesTo,     // listens/subscribes to named event
    DefinesContract,  // defines API/schema contract
    ConsumesContract, // consumes API/schema contract

    // ── Concurrency ─────────────────────────────
    SendsMessage, // sends on typed channel/queue/mailbox
    Spawns,       // creates concurrent execution context

    // ── Lifecycle ───────────────────────────────
    Tests,       // test entity verifies target
    Covers,      // test provides runtime coverage
    CoChanges,   // entities change together in commits
    DerivedFrom, // generated/derived from another entity

    // ── Metadata ────────────────────────────────
    DocumentedBy, // entity has documentation
    OwnedBy,      // entity has responsible owner/team
    OwnedByFile,  // entity associated with file
}

/// How a relation was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum RelationOrigin {
    Parsed,
    Inferred,
    Manual,
    /// Discovered via Language Server Protocol (type-resolved).
    Lsp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relation_kind_roundtrip() {
        let kinds = vec![
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::Contains,
            RelationKind::References,
            RelationKind::UsesMacro,
            RelationKind::Implements,
            RelationKind::Extends,
            RelationKind::Includes,
            RelationKind::Tests,
            RelationKind::DependsOn,
            RelationKind::CoChanges,
            RelationKind::DefinesContract,
            RelationKind::ConsumesContract,
            RelationKind::EmitsEvent,
            RelationKind::OwnedBy,
            RelationKind::DocumentedBy,
            RelationKind::Covers,
            RelationKind::DerivedFrom,
            RelationKind::OwnedByFile,
        ];
        for k in kinds {
            let json = serde_json::to_string(&k).unwrap();
            let parsed: RelationKind = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, k);
        }
    }

    #[test]
    fn graph_node_id_roundtrips_through_json() {
        let node = GraphNodeId::Work(WorkId::new());
        let json = serde_json::to_string(&node).unwrap();
        let parsed: GraphNodeId = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed, node);
    }

    #[test]
    fn relation_evidence_roundtrips_through_json() {
        let relation = Relation {
            id: RelationId::new(),
            kind: RelationKind::Includes,
            src: GraphNodeId::Artifact(ArtifactId::from_path("src/app.cpp")),
            dst: GraphNodeId::Artifact(ArtifactId::from_path("include/app.hpp")),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: Some("app.hpp".to_string()),
            evidence: vec![RelationEvidence {
                source_span: Some(SourceSpan {
                    file: crate::ids::FilePathId::new("src/app.cpp"),
                    start_byte: 0,
                    end_byte: 18,
                    start_line: 1,
                    start_col: 0,
                    end_line: 1,
                    end_col: 18,
                }),
                parser_rule: Some("include_directive".to_string()),
                token: Some("#include \"app.hpp\"".to_string()),
                source_path: Some("app.hpp".to_string()),
                resolved_path: Some("include/app.hpp".to_string()),
                occurrence_count: 1,
            }],
        };

        let json = serde_json::to_string(&relation).unwrap();
        let parsed: Relation = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, relation.id);
        assert_eq!(parsed.kind, relation.kind);
        assert_eq!(parsed.src, relation.src);
        assert_eq!(parsed.dst, relation.dst);
        assert_eq!(parsed.import_source, relation.import_source);
        assert_eq!(parsed.evidence.len(), 1);
        assert_eq!(
            parsed.evidence[0].resolved_path.as_deref(),
            Some("include/app.hpp")
        );
    }
}
