use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

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

/// Supported programming languages (Tier 1).
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

/// Unique identifier for a Contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
}
