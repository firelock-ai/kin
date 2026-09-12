// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use schemars::{gen::SchemaGenerator, schema::Schema, JsonSchema};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use uuid::Uuid;

/// Content-addressed 256-bit hash (re-exported from kin-blobs).
pub use kin_blobs::Hash256;

/// Unique identifier for an Entity.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub struct EntityId(pub Uuid);

impl EntityId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Deterministically derive an entity ID from its semantic identity so the
    /// same code entity gets the same ID across re-index and re-init. This is
    /// the graph-first contract: entities are addressed by content, not by a
    /// random per-process UUID. The key combines the locating fields that
    /// uniquely identify an entity within a repo snapshot.
    pub fn from_content(file_path: &str, name: &str, kind: &str, start_line: u32) -> Self {
        const NAMESPACE: Uuid = Uuid::from_bytes([
            0x6b, 0x69, 0x6e, 0x2d, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2d, 0x69, 0x64, 0x76,
            0x35, 0x00,
        ]);
        let key = format!("{file_path}\u{1f}{kind}\u{1f}{name}\u{1f}{start_line}");
        Self(Uuid::new_v5(&NAMESPACE, key.as_bytes()))
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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub struct RelationId(pub Uuid);

impl RelationId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a RelationId from raw bytes (for deterministic ID generation).
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }

    /// Deterministically derive a relation ID from its semantic identity
    /// (source id, destination id, kind) so the same edge gets the same ID
    /// across re-index and re-init — the graph-first content-addressed
    /// contract, mirroring `EntityId::from_content`.
    pub fn from_content(src: &str, dst: &str, kind: &str) -> Self {
        const NAMESPACE: Uuid = Uuid::from_bytes([
            0x6b, 0x69, 0x6e, 0x2d, 0x72, 0x65, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x69, 0x64,
            0x76, 0x35,
        ]);
        let key = format!("{src}\u{1f}{dst}\u{1f}{kind}");
        Self(Uuid::new_v5(&NAMESPACE, key.as_bytes()))
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

/// Content-addressed identifier for an immutable relation revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct RelationRevisionId(pub Hash256);

impl RelationRevisionId {
    pub fn from_hash(hash: Hash256) -> Self {
        Self(hash)
    }
}

impl fmt::Display for RelationRevisionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Content-addressed identifier for a SemanticChange.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
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

/// Stable repository identity used to scope refs, aliases, and transactions.
///
/// Repository IDs are presentation-safe opaque strings. Hosted slugs and UUID
/// text are both valid; empty, control-bearing, or oversized values are not.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepositoryId(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RepositoryIdError {
    #[error("repository id must not be empty")]
    Empty,
    #[error("repository id must not exceed 255 bytes")]
    TooLong,
    #[error("repository id must not contain control characters")]
    Control,
}

impl RepositoryId {
    pub fn new(value: impl Into<String>) -> Result<Self, RepositoryIdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(RepositoryIdError::Empty);
        }
        if value.len() > 255 {
            return Err(RepositoryIdError::TooLong);
        }
        if value.chars().any(char::is_control) {
            return Err(RepositoryIdError::Control);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for RepositoryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for RepositoryId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RepositoryId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl JsonSchema for RepositoryId {
    fn schema_name() -> String {
        "RepositoryId".to_string()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        String::json_schema(generator)
    }
}

/// Caller-stable identity for one repository authority transaction.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub struct OperationId(pub Uuid);

impl OperationId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for OperationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Local identity for one materialized repository workspace.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub struct WorkspaceId(pub Uuid);

impl WorkspaceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }
}

impl Default for WorkspaceId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for WorkspaceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Content-addressed identifier for an immutable entity revision.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub struct EntityRevisionId(pub Hash256);

impl EntityRevisionId {
    pub fn from_hash(hash: Hash256) -> Self {
        Self(hash)
    }
}

impl fmt::Display for EntityRevisionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// File path identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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

/// A byte-exact path to one leaf in a repository tree.
///
/// Repository paths use `/` as their separator and preserve their original
/// bytes. UTF-8 is a presentation property, never an authority requirement.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepoPath(Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RepoPathError {
    #[error("repository path must not be empty")]
    Empty,
    #[error("repository path must be relative")]
    Absolute,
    #[error("repository path must not contain NUL")]
    Nul,
    #[error("repository path must not contain empty components")]
    EmptyComponent,
    #[error("repository path must not contain '.' or '..' components")]
    DotComponent,
    #[error("repository path hex encoding is not canonical lowercase hex")]
    NonCanonicalHex,
    #[error("repository path hex encoding is invalid: {0}")]
    InvalidHex(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RepoPathWire {
    bytes_hex: String,
}

impl RepoPath {
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, RepoPathError> {
        let bytes = bytes.into();
        Self::validate(&bytes)?;
        Ok(Self(bytes))
    }

    pub fn from_utf8(path: impl Into<String>) -> Result<Self, RepoPathError> {
        Self::from_bytes(path.into().into_bytes())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn as_utf8(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    fn validate(bytes: &[u8]) -> Result<(), RepoPathError> {
        if bytes.is_empty() {
            return Err(RepoPathError::Empty);
        }
        if bytes[0] == b'/' {
            return Err(RepoPathError::Absolute);
        }
        if bytes.contains(&0) {
            return Err(RepoPathError::Nul);
        }
        for component in bytes.split(|byte| *byte == b'/') {
            if component.is_empty() {
                return Err(RepoPathError::EmptyComponent);
            }
            if component == b"." || component == b".." {
                return Err(RepoPathError::DotComponent);
            }
        }
        Ok(())
    }

    fn wire(&self) -> RepoPathWire {
        RepoPathWire {
            bytes_hex: hex::encode(&self.0),
        }
    }
}

impl TryFrom<&str> for RepoPath {
    type Error = RepoPathError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_utf8(value)
    }
}

impl TryFrom<&[u8]> for RepoPath {
    type Error = RepoPathError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value.to_vec())
    }
}

impl fmt::Display for RepoPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(path) = self.as_utf8() {
            return formatter.write_str(path);
        }
        for byte in &self.0 {
            match byte {
                b'\\' => formatter.write_str("\\\\")?,
                0x20..=0x7e => write!(formatter, "{}", char::from(*byte))?,
                _ => write!(formatter, "\\x{byte:02x}")?,
            }
        }
        Ok(())
    }
}

impl Serialize for RepoPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.wire().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RepoPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RepoPathWire::deserialize(deserializer)?;
        let bytes = hex::decode(&wire.bytes_hex)
            .map_err(|error| D::Error::custom(RepoPathError::InvalidHex(error.to_string())))?;
        if hex::encode(&bytes) != wire.bytes_hex {
            return Err(D::Error::custom(RepoPathError::NonCanonicalHex));
        }
        Self::from_bytes(bytes).map_err(D::Error::custom)
    }
}

impl JsonSchema for RepoPath {
    fn schema_name() -> String {
        "RepoPath".to_string()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        RepoPathWire::json_schema(generator)
    }
}

/// Exact Git object identity stored by a gitlink tree entry.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(
    tag = "algorithm",
    content = "bytes",
    rename_all = "lowercase",
    deny_unknown_fields
)]
pub enum GitObjectId {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

impl GitObjectId {
    pub const fn sha1(bytes: [u8; 20]) -> Self {
        Self::Sha1(bytes)
    }

    pub const fn sha256(bytes: [u8; 32]) -> Self {
        Self::Sha256(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Sha1(bytes) => bytes,
            Self::Sha256(bytes) => bytes,
        }
    }
}

impl fmt::Display for GitObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex::encode(self.as_bytes()))
    }
}

/// Content-addressed identifier for an immutable tracked-file revision.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub struct ArtifactRevisionId(pub Hash256);

impl ArtifactRevisionId {
    pub fn from_hash(hash: Hash256) -> Self {
        Self(hash)
    }
}

impl fmt::Display for ArtifactRevisionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a Spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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

/// Author identifier (human or assistant).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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

/// Supported programming languages (Tier 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum LanguageId {
    TypeScript,
    JavaScript,
    Python,
    Go,
    Java,
    Rust,
    C,
    Cpp,
    CSharp,
    Ruby,
    Php,
    Swift,
    Kotlin,
    Hcl,
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
            LanguageId::C => write!(f, "c"),
            LanguageId::Cpp => write!(f, "cpp"),
            LanguageId::CSharp => write!(f, "csharp"),
            LanguageId::Ruby => write!(f, "ruby"),
            LanguageId::Php => write!(f, "php"),
            LanguageId::Swift => write!(f, "swift"),
            LanguageId::Kotlin => write!(f, "kotlin"),
            LanguageId::Hcl => write!(f, "hcl"),
        }
    }
}

/// Unique identifier for a Contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ContractId(pub Uuid);

impl ContractId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ContractId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ContractId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for an AgentSession.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for an Intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct IntentId(pub Uuid);

impl IntentId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for IntentId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for IntentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a Conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ConflictId(pub Uuid);

impl ConflictId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ConflictId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ConflictId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash256_hex_roundtrip() {
        let bytes = [0xab; 32];
        let hash = Hash256::from_bytes(bytes);
        let hex_str = hash.to_string();
        let parsed = Hash256::from_hex(&hex_str).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn hash256_debug_shows_prefix() {
        let hash = Hash256::from_bytes([0xde; 32]);
        let debug = format!("{:?}", hash);
        assert!(debug.starts_with("Hash256("));
        assert!(debug.len() < 30); // truncated
    }

    #[test]
    fn entity_id_display() {
        let id = EntityId::new();
        let s = id.to_string();
        assert!(!s.is_empty());
    }

    #[test]
    fn language_id_display() {
        assert_eq!(LanguageId::Rust.to_string(), "rust");
        assert_eq!(LanguageId::TypeScript.to_string(), "typescript");
        assert_eq!(LanguageId::C.to_string(), "c");
        assert_eq!(LanguageId::Cpp.to_string(), "cpp");
        assert_eq!(LanguageId::CSharp.to_string(), "csharp");
        assert_eq!(LanguageId::Ruby.to_string(), "ruby");
        assert_eq!(LanguageId::Php.to_string(), "php");
        assert_eq!(LanguageId::Swift.to_string(), "swift");
    }

    #[test]
    fn ids_serialize_roundtrip() {
        let entity_id = EntityId::new();
        let json = serde_json::to_string(&entity_id).unwrap();
        let parsed: EntityId = serde_json::from_str(&json).unwrap();
        assert_eq!(entity_id, parsed);

        let hash = Hash256::from_bytes([0x42; 32]);
        let json = serde_json::to_string(&hash).unwrap();
        let parsed: Hash256 = serde_json::from_str(&json).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn entity_revision_id_display_roundtrip() {
        let revision_id = EntityRevisionId::from_hash(Hash256::from_bytes([0x7a; 32]));
        let printed = revision_id.to_string();
        let parsed = Hash256::from_hex(&printed).unwrap();
        assert_eq!(revision_id, EntityRevisionId::from_hash(parsed));
    }

    #[test]
    fn relation_revision_id_display_roundtrip() {
        let revision_id = RelationRevisionId::from_hash(Hash256::from_bytes([0x6b; 32]));
        let printed = revision_id.to_string();
        let parsed = Hash256::from_hex(&printed).unwrap();
        assert_eq!(revision_id, RelationRevisionId::from_hash(parsed));
    }

    #[test]
    fn artifact_revision_id_display_roundtrip() {
        let revision_id = ArtifactRevisionId::from_hash(Hash256::from_bytes([0x4c; 32]));
        let printed = revision_id.to_string();
        let parsed = Hash256::from_hex(&printed).unwrap();
        assert_eq!(revision_id, ArtifactRevisionId::from_hash(parsed));
    }

    #[test]
    fn repo_path_preserves_non_utf8_bytes_in_one_canonical_encoding() {
        let path = RepoPath::from_bytes(b"assets/icon-\xff.png".to_vec()).unwrap();
        let value = serde_json::to_value(&path).unwrap();

        assert_eq!(
            value,
            serde_json::json!({
                "bytes_hex": "6173736574732f69636f6e2dff2e706e67"
            })
        );
        assert_eq!(serde_json::from_value::<RepoPath>(value).unwrap(), path);
        assert_eq!(path.to_string(), "assets/icon-\\xff.png");
        assert!(path.as_utf8().is_none());
    }

    #[test]
    fn repo_path_rejects_noncanonical_and_structurally_unsafe_forms() {
        for path in [
            b"".as_slice(),
            b"/root",
            b"a//b",
            b"a/./b",
            b"a/../b",
            b"a\0b",
        ] {
            assert!(RepoPath::from_bytes(path.to_vec()).is_err());
        }

        assert!(serde_json::from_value::<RepoPath>(serde_json::json!({
            "bytes_hex": "524541444D452E6D64"
        }))
        .is_err());
        assert!(serde_json::from_value::<RepoPath>(serde_json::json!({
            "encoding": "utf8",
            "value": "README.md"
        }))
        .is_err());

        let allowed =
            RepoPath::from_bytes(b"control\\name/.git~1/\x01".to_vec()).expect("structural path");
        assert_eq!(allowed.as_bytes(), b"control\\name/.git~1/\x01");
    }

    #[test]
    fn git_object_id_roundtrips_with_exact_algorithm_and_width() {
        let sha1 = GitObjectId::sha1([0x11; 20]);
        let sha256 = GitObjectId::sha256([0x22; 32]);

        for object_id in [sha1, sha256] {
            let encoded = serde_json::to_vec(&object_id).unwrap();
            let decoded: GitObjectId = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(decoded, object_id);
            assert_eq!(object_id.to_string().len(), object_id.as_bytes().len() * 2);
        }
    }
}
