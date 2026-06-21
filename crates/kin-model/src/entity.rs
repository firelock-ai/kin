// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ids::*;

/// The atomic semantic unit in Kin's graph.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
    #[serde(default)]
    pub role: EntityRole,
    pub doc_summary: Option<String>,
    pub metadata: EntityMetadata,
    pub lineage_parent: Option<EntityId>,
    /// None while in overlay; set on kin commit.
    pub created_in: Option<SemanticChangeId>,
    pub superseded_by: Option<EntityId>,
}

/// Classification of a semantic entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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
    Macro,
}

/// Content-based fingerprint of an entity, used to detect what changed
/// between revisions (structure, signature, and exact contents).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SemanticFingerprint {
    pub algorithm: FingerprintAlgorithm,
    /// Hash of the normalized AST/source structure (insensitive to comments and whitespace).
    pub ast_hash: Hash256,
    /// Hash of the entity's signature line / declaration shape.
    pub signature_hash: Hash256,
    /// Hash of the entity's full source text (changes on any body edit).
    pub behavior_hash: Hash256,
    /// Confidence in fingerprint stability (0.0 - 1.0).
    pub stability_score: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum FingerprintAlgorithm {
    V1TreeSitter,
}

/// Visibility of a semantic entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum Visibility {
    Public,
    Private,
    Internal,
    Crate,
}

/// Role of a semantic entity within the project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum EntityRole {
    #[default]
    Source,
    Test,
    External,
    Docs,
    Generated,
    Vendored,
}

/// Extensible metadata bag for entities.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct EntityMetadata {
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Source location of an entity within a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
            EntityKind::Macro,
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

    #[test]
    fn entity_role_default_is_source() {
        assert_eq!(EntityRole::default(), EntityRole::Source);
    }

    #[test]
    fn entity_role_all_variants_roundtrip() {
        let variants = vec![
            EntityRole::Source,
            EntityRole::Test,
            EntityRole::External,
            EntityRole::Docs,
            EntityRole::Generated,
            EntityRole::Vendored,
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let parsed: EntityRole = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, v);
        }
    }

    #[test]
    fn entity_role_serde_default_on_missing() {
        // Build a valid Entity, serialize it, strip the role field, then deserialize.
        // This proves that old snapshots (without role) default to Source.
        let entity = Entity {
            id: EntityId(uuid::Uuid::nil()),
            kind: EntityKind::Function,
            name: "f".into(),
            language: crate::ids::LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: kin_blobs::Hash256::from_bytes([0; 32]),
                signature_hash: kin_blobs::Hash256::from_bytes([0; 32]),
                behavior_hash: kin_blobs::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: "fn f()".into(),
            visibility: Visibility::Public,
            role: EntityRole::Test, // set non-default to prove the strip works
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };
        let mut json_val: serde_json::Value = serde_json::to_value(&entity).unwrap();
        json_val.as_object_mut().unwrap().remove("role");
        let deserialized: Entity = serde_json::from_value(json_val).unwrap();
        assert_eq!(deserialized.role, EntityRole::Source);
    }
}
