use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// ID types
// ---------------------------------------------------------------------------

/// Content-addressed 256-bit hash.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let mut buf = [0u8; 32];
        hex::decode_to_slice(s, &mut buf)?;
        Ok(Self(buf))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", &hex::encode(self.0)[..12])
    }
}

/// Unique identifier for an Entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntityId(pub Uuid);

impl EntityId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for EntityId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a Relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RelationId(pub Uuid);

impl RelationId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }
}

impl Default for RelationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Content-addressed identifier for a SemanticChange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SemanticChangeId(pub Hash256);

impl SemanticChangeId {
    pub fn from_hash(hash: Hash256) -> Self {
        Self(hash)
    }
}

impl fmt::Display for SemanticChangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// File path identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FilePathId(pub String);

impl FilePathId {
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }
}

impl fmt::Display for FilePathId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Author identifier (human or assistant).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuthorId(pub String);

impl AuthorId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Display for AuthorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a Branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BranchId(pub Uuid);

impl BranchId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for BranchId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for BranchId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Branch name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BranchName(pub String);

impl BranchName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

impl fmt::Display for BranchName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Supported programming languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LanguageId {
    TypeScript,
    JavaScript,
    Python,
    Go,
    Java,
    Rust,
}

impl fmt::Display for LanguageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LanguageId::TypeScript => write!(f, "typescript"),
            LanguageId::JavaScript => write!(f, "javascript"),
            LanguageId::Python => write!(f, "python"),
            LanguageId::Go => write!(f, "go"),
            LanguageId::Java => write!(f, "java"),
            LanguageId::Rust => write!(f, "rust"),
        }
    }
}

/// Unique identifier for a Spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpecId(pub Uuid);

impl SpecId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SpecId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SpecId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for an Evidence record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EvidenceId(pub Uuid);

impl EvidenceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for EvidenceId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EvidenceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Entity types
// ---------------------------------------------------------------------------

/// The atomic semantic unit in Kin's graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    pub id: EntityId,
    pub kind: EntityKind,
    pub name: String,
    pub language: LanguageId,
    pub fingerprint: SemanticFingerprint,
    /// None for graph-created entities before placement.
    pub file_origin: Option<FilePathId>,
    /// None until projection assigns a file location.
    pub span: Option<SourceSpan>,
    pub signature: String,
    pub visibility: Visibility,
    pub doc_summary: Option<String>,
    pub metadata: EntityMetadata,
    pub lineage_parent: Option<EntityId>,
    /// None while in overlay; set on kin commit.
    pub created_in: Option<SemanticChangeId>,
    pub superseded_by: Option<EntityId>,
}

/// Classification of a semantic entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Function,
    Class,
    Interface,
    TraitDef,
    TypeAlias,
    Module,
    Package,
    Test,
    Schema,
    ApiEndpoint,
    EventContract,
    File,
    DocumentNode,
    Method,
    EnumDef,
    EnumVariant,
    Constant,
    StaticVar,
}

/// Kin's identity moat. Survives renames, moves, formatting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticFingerprint {
    pub algorithm: FingerprintAlgorithm,
    /// Normalized AST shape hash.
    pub ast_hash: Hash256,
    /// Parameter/return contract hash.
    pub signature_hash: Hash256,
    /// Control flow + side effects hash.
    pub behavior_hash: Hash256,
    /// Confidence in fingerprint stability (0.0 - 1.0).
    pub stability_score: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FingerprintAlgorithm {
    V1TreeSitter,
}

/// Visibility of a semantic entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Visibility {
    Public,
    Private,
    Internal,
    Crate,
}

/// Extensible metadata bag for entities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntityMetadata {
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Source location of an entity within a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpan {
    pub file: FilePathId,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
}

// ---------------------------------------------------------------------------
// Relation types
// ---------------------------------------------------------------------------

/// A typed edge in the semantic graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relation {
    pub id: RelationId,
    pub kind: RelationKind,
    pub src: EntityId,
    pub dst: EntityId,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f32,
    pub origin: RelationOrigin,
    /// None while in overlay; set on kin commit.
    pub created_in: Option<SemanticChangeId>,
}

/// Classification of a relation edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelationKind {
    Calls,
    Imports,
    Contains,
    References,
    Implements,
    Extends,
    Tests,
    DependsOn,
    DefinesContract,
    ConsumesContract,
    EmitsEvent,
    OwnedBy,
    DocumentedBy,
}

/// How a relation was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelationOrigin {
    Parsed,
    Inferred,
    Manual,
}

// ---------------------------------------------------------------------------
// SemanticChange (commit) types
// ---------------------------------------------------------------------------

/// UTC timestamp wrapper.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp(pub DateTime<Utc>);

impl Timestamp {
    pub fn now() -> Self {
        Self(Utc::now())
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_rfc3339())
    }
}

impl From<DateTime<Utc>> for Timestamp {
    fn from(dt: DateTime<Utc>) -> Self {
        Self(dt)
    }
}

/// Risk classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Summary of risk associated with a semantic change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSummary {
    pub overall_risk: RiskLevel,
    pub breaking_changes: Vec<String>,
    pub test_coverage_gaps: Vec<String>,
    pub contract_violations: Vec<String>,
    pub work_risks: Vec<String>,
    pub notes: Vec<String>,
}

/// Kin's native commit -- the unit of semantic history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticChange {
    /// Content-addressed hash.
    pub id: SemanticChangeId,
    /// 0 = genesis, 1 = normal, 2 = merge.
    pub parents: Vec<SemanticChangeId>,
    pub timestamp: Timestamp,
    /// Human or assistant.
    pub author: AuthorId,
    pub message: String,
    pub entity_deltas: Vec<EntityDelta>,
    pub relation_deltas: Vec<RelationDelta>,
    /// Non-entity file changes.
    pub artifact_deltas: Vec<ArtifactDelta>,
    pub projected_files: Vec<FilePathId>,
    pub spec_link: Option<SpecId>,
    pub evidence: Vec<EvidenceId>,
    pub risk_summary: Option<RiskSummary>,
    /// Informational: branch name at creation time.
    pub authored_on: Option<BranchName>,
}

/// Delta for a single entity within a SemanticChange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EntityDelta {
    Added(Entity),
    Modified { old: Entity, new: Entity },
    Removed(EntityId),
}

/// Delta for a single relation within a SemanticChange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelationDelta {
    Added(Relation),
    Removed(RelationId),
}

/// Delta for a non-entity file within a SemanticChange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactDelta {
    pub file_id: FilePathId,
    pub kind: ArtifactDeltaKind,
    pub old_hash: Option<Hash256>,
    pub new_hash: Option<Hash256>,
}

/// Classification of an artifact delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactDeltaKind {
    Added,
    Modified,
    Removed,
}

// ---------------------------------------------------------------------------
// Branch
// ---------------------------------------------------------------------------

/// A named branch pointing to a head SemanticChange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branch {
    pub id: BranchId,
    pub name: BranchName,
    pub head: SemanticChangeId,
    pub created_at: Timestamp,
}

// ---------------------------------------------------------------------------
// Query / filter types
// ---------------------------------------------------------------------------

/// Filter for querying entities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntityFilter {
    pub kinds: Option<Vec<EntityKind>>,
    pub languages: Option<Vec<LanguageId>>,
    pub name_pattern: Option<String>,
    pub file_path: Option<FilePathId>,
}

/// A subgraph returned from neighborhood queries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubGraph {
    pub entities: HashMap<EntityId, Entity>,
    pub relations: Vec<Relation>,
}
