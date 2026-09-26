// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::entity::SourceSpan;
use crate::external_reference::ExternalReferenceId;
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
    /// Symbol owned outside the local repository. Deliberately last so the
    /// public variant order remains append-only even though the current
    /// MessagePack encoder tags variants by name.
    ExternalReference(ExternalReferenceId),
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
            Self::ExternalReference(id) => write!(f, "external_reference:{id}"),
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

impl From<ExternalReferenceId> for GraphNodeId {
    fn from(value: ExternalReferenceId) -> Self {
        Self::ExternalReference(value)
    }
}

/// Domain of [`RelationId::resolver`].
const RESOLVER_RELATION_ID_DOMAIN_V1: &[u8] = b"kin.relation.resolver.v1\0";

impl RelationId {
    /// The identity of an edge a resolver proved, from its kind and both of
    /// its ends, whatever kind of node each end is.
    ///
    /// SHA-256 over a domain-separated, length-prefixed preimage of the kind's
    /// name and each end's typed spelling (`entity:<uuid>`,
    /// `external_reference:<uuid>`), truncated to a UUID-v8. Stable across
    /// toolchains and processes, unlike an edge keyed through the standard
    /// library's default hasher, and able to name an end outside the
    /// repository, which an entity-keyed identity cannot.
    pub fn resolver(kind: RelationKind, src: &GraphNodeId, dst: &GraphNodeId) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(RESOLVER_RELATION_ID_DOMAIN_V1);
        for part in [format!("{kind:?}"), src.to_string(), dst.to_string()] {
            hasher.update((part.len() as u64).to_le_bytes());
            hasher.update(part.as_bytes());
        }
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Self::from_bytes(bytes)
    }
}

/// A typed edge in the semantic graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
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
    pub import_source: Option<String>,
    /// Parser/linker evidence for this edge.
    pub evidence: Vec<RelationEvidence>,
}

/// The argument shape observed at a single call site: how many positional
/// arguments were passed, which keyword-argument names were used, and whether
/// the call forwards a `*args` positional splat or a `**kwargs` keyword splat.
///
/// Captured per `Calls` edge so a consumer that invokes a callable positionally
/// (unaffected by a parameter rename) can be told apart from one that names a
/// parameter (which a rename would strand). A `**kwargs` splat means the keyword
/// set is not statically known; the arity is known exactly only when neither
/// splat flag is set.
///
/// `keywords` is kept sorted and deduplicated so the shape is order- and
/// duplicate-independent, keeping graph writes deterministic.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct CallArgShape {
    /// Number of positional argument expressions passed. A `*sequence` splat is
    /// not counted here; it is recorded by `has_var_positional`.
    pub positional: u32,
    /// Sorted, deduplicated names of explicit keyword arguments (`name=value`).
    pub keywords: Vec<String>,
    /// The call forwards a `*sequence` positional splat (or an equivalent
    /// pack-expansion).
    pub has_var_positional: bool,
    /// The call forwards a `**mapping` keyword splat, so its keyword set is not
    /// statically known.
    pub has_var_keyword: bool,
}

impl CallArgShape {
    /// Build a shape, normalizing `keywords` to sorted, deduplicated order so
    /// two call sites that differ only in argument order compare equal.
    pub fn new(
        positional: u32,
        mut keywords: Vec<String>,
        has_var_positional: bool,
        has_var_keyword: bool,
    ) -> Self {
        keywords.sort();
        keywords.dedup();
        Self {
            positional,
            keywords,
            has_var_positional,
            has_var_keyword,
        }
    }
}

/// The evidence rule the language-server references arm records a site under.
///
/// On a `References` edge into a Go method, a record under this rule was
/// written before each site was proven to resolve to that method. gopls answers
/// a method's references with those of every method related to it through
/// interface satisfaction, and those builds recorded the widened answer as it
/// came, so such a record can name a call of a related method: a call on an
/// interface value confirmed as a call of the concrete method behind it, or a
/// direct call of a concrete method confirmed as a call of the interface method
/// it implements. Semantic readers take it as no evidence there; the site-proven
/// arm records [`LSP_PROVEN_METHOD_REFERENCES_RULE`] instead. Every other
/// destination keeps this rule, and its meaning.
pub const LSP_REFERENCES_RULE: &str = "lsp_references";

/// The evidence rule a Go method's language-server reference sites are recorded
/// under once each one is proven to resolve to the method itself.
///
/// A site is proven when gopls's definition there lands in the method, or when
/// `textDocument/implementation` shows the method corresponds to no interface
/// method, so its answer cannot have been widened. The rule is distinct from
/// [`LSP_REFERENCES_RULE`] so that a store can tell the two apart: records a
/// build wrote before the proof existed are still in stores it enriched.
pub const LSP_PROVEN_METHOD_REFERENCES_RULE: &str = "lsp_method_references_proven";

/// Concrete evidence supporting a graph relation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RelationEvidence {
    /// Source span of the syntax that produced the edge, when available.
    pub source_span: Option<SourceSpan>,
    /// Parser or linker rule that produced this evidence.
    pub parser_rule: Option<String>,
    /// Lexical token at the evidence site, e.g. a macro name or imported symbol.
    pub token: Option<String>,
    /// Module/include path as written in source.
    pub source_path: Option<String>,
    /// Resolved graph-owned target path, when the linker could resolve it.
    pub resolved_path: Option<String>,
    /// Number of equivalent occurrences collapsed into this evidence record.
    pub occurrence_count: u32,
    /// Argument shape of the call site that produced this edge, when captured.
    /// Present only for `Calls` edges from languages that emit shapes;
    /// non-call edges and unresolved calls leave it `None`.
    pub call_shape: Option<CallArgShape>,
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
            call_shape: None,
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

    #[derive(Serialize)]
    enum LegacyGraphNodeId {
        Entity(EntityId),
        Artifact(ArtifactId),
        Test(TestId),
        Contract(ContractId),
        Work(WorkId),
        VerificationRun(VerificationRunId),
    }

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
    fn resolver_relation_ids_are_pinned_and_name_every_end() {
        let caller = GraphNodeId::Entity(EntityId(uuid::Uuid::from_u128(1)));
        let external =
            GraphNodeId::ExternalReference(ExternalReferenceId(uuid::Uuid::from_u128(2)));
        let id = RelationId::resolver(RelationKind::Calls, &caller, &external);
        assert_eq!(id.to_string(), "07ce52ca-0d43-8649-8a7e-f05a445544ad");
        assert_eq!(id.0.get_version_num(), 8);
        assert_eq!(
            RelationId::resolver(RelationKind::Calls, &caller, &external),
            id,
            "the same edge has one identity"
        );
        assert_ne!(
            RelationId::resolver(RelationKind::References, &caller, &external),
            id
        );
        assert_ne!(
            RelationId::resolver(
                RelationKind::Calls,
                &caller,
                &GraphNodeId::Entity(EntityId(uuid::Uuid::from_u128(2)))
            ),
            id,
            "an end's kind of node is part of the identity"
        );
    }

    #[test]
    fn graph_node_id_roundtrips_through_json() {
        let node = GraphNodeId::Work(WorkId::new());
        let json = serde_json::to_string(&node).unwrap();
        let parsed: GraphNodeId = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed, node);
    }

    #[test]
    fn external_reference_variant_is_appended_and_messagepack_pinned() {
        let entity_id = EntityId::new();
        let artifact_id = ArtifactId::new();
        let test_id = TestId::new();
        let contract_id = ContractId::new();
        let work_id = WorkId::new();
        let verification_id = VerificationRunId::new();

        let fixtures = [
            (
                rmp_serde::to_vec(&GraphNodeId::Entity(entity_id)).unwrap(),
                rmp_serde::to_vec(&LegacyGraphNodeId::Entity(entity_id)).unwrap(),
            ),
            (
                rmp_serde::to_vec(&GraphNodeId::Artifact(artifact_id)).unwrap(),
                rmp_serde::to_vec(&LegacyGraphNodeId::Artifact(artifact_id)).unwrap(),
            ),
            (
                rmp_serde::to_vec(&GraphNodeId::Test(test_id)).unwrap(),
                rmp_serde::to_vec(&LegacyGraphNodeId::Test(test_id)).unwrap(),
            ),
            (
                rmp_serde::to_vec(&GraphNodeId::Contract(contract_id)).unwrap(),
                rmp_serde::to_vec(&LegacyGraphNodeId::Contract(contract_id)).unwrap(),
            ),
            (
                rmp_serde::to_vec(&GraphNodeId::Work(work_id)).unwrap(),
                rmp_serde::to_vec(&LegacyGraphNodeId::Work(work_id)).unwrap(),
            ),
            (
                rmp_serde::to_vec(&GraphNodeId::VerificationRun(verification_id)).unwrap(),
                rmp_serde::to_vec(&LegacyGraphNodeId::VerificationRun(verification_id)).unwrap(),
            ),
        ];
        for (current, legacy) in fixtures {
            assert_eq!(
                current, legacy,
                "adding an external-reference node must not change a legacy variant's bytes"
            );
        }

        let external = GraphNodeId::ExternalReference(ExternalReferenceId(uuid::Uuid::from_u128(
            0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10,
        )));
        let bytes = rmp_serde::to_vec(&external).unwrap();
        assert_eq!(
            hex::encode(&bytes),
            "81b145787465726e616c5265666572656e6365c4100102030405060708090a0b0c0d0e0f10",
            "the appended external-reference variant tag is a persisted wire contract"
        );
        assert_eq!(
            rmp_serde::from_slice::<GraphNodeId>(&bytes).unwrap(),
            external
        );
    }

    #[test]
    fn relation_evidence_roundtrips_through_json() {
        let relation = Relation {
            id: RelationId::new(),
            kind: RelationKind::Includes,
            src: GraphNodeId::Artifact(ArtifactId::new()),
            dst: GraphNodeId::Artifact(ArtifactId::new()),
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
                call_shape: None,
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

        let mut missing_evidence = serde_json::to_value(&relation).unwrap();
        missing_evidence.as_object_mut().unwrap().remove("evidence");
        assert!(serde_json::from_value::<Relation>(missing_evidence).is_err());
    }
}
