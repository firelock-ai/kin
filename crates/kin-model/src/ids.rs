// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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

/// Unique identifier for a Branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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
}
