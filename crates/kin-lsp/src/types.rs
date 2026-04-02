// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Minimal type aliases for kin-model types.
//!
//! These mirror kin-model's types but are self-contained so kin-lsp
//! can compile without the kin registry. When kin-lsp is integrated
//! into a workspace with kin-model, replace these with re-exports.

use serde::{Deserialize, Serialize};

/// Language identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LanguageId {
    Rust,
    Python,
    TypeScript,
    JavaScript,
    Go,
    Java,
    C,
    Cpp,
    CSharp,
    Ruby,
    Kotlin,
    PHP,
    Swift,
    Hcl,
}

impl std::fmt::Display for LanguageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// 32-byte content hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Unique entity identifier (UUID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntityId(pub uuid::Uuid);

impl EntityId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl std::fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique relation identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RelationId(pub uuid::Uuid);

impl RelationId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

/// Node in the graph (entity or file).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GraphNodeId {
    Entity(EntityId),
}

/// File path identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FilePathId(pub String);

/// Kind of relation between entities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelationKind {
    Calls,
    References,
    Contains,
    Extends,
    Implements,
    Imports,
}

/// Origin of a relation — how it was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelationOrigin {
    Parsed,
    Inferred,
    Manual,
}

/// Semantic change identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SemanticChangeId(pub [u8; 32]);

/// A relation between two graph nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relation {
    pub id: RelationId,
    pub kind: RelationKind,
    pub src: GraphNodeId,
    pub dst: GraphNodeId,
    pub confidence: f32,
    pub origin: RelationOrigin,
    pub created_in: Option<SemanticChangeId>,
    pub import_source: Option<String>,
}
