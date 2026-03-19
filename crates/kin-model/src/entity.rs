// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ids::*;

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

/// Parse state of an entity's source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParseState {
    Valid,
    Incomplete {
        error_ranges: Vec<(usize, usize)>,
    },
    LastKnownGood {
        last_valid_fingerprint: SemanticFingerprint,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_kind_serialization() {
        let kind = EntityKind::Function;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"function\"");
        let parsed: EntityKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, EntityKind::Function);
    }

    #[test]
    fn entity_kind_all_variants_roundtrip() {
        let variants = vec![
            EntityKind::Function,
            EntityKind::Class,
            EntityKind::Interface,
            EntityKind::TraitDef,
            EntityKind::TypeAlias,
            EntityKind::Module,
            EntityKind::Package,
            EntityKind::Test,
            EntityKind::Schema,
            EntityKind::ApiEndpoint,
            EntityKind::EventContract,
            EntityKind::File,
            EntityKind::DocumentNode,
            EntityKind::Method,
            EntityKind::EnumDef,
            EntityKind::EnumVariant,
            EntityKind::Constant,
            EntityKind::StaticVar,
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let parsed: EntityKind = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, v);
        }
    }

    #[test]
    fn visibility_serialization() {
        let v = Visibility::Public;
        let json = serde_json::to_string(&v).unwrap();
        let parsed: Visibility = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, v);
    }
}
