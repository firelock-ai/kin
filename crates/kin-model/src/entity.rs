// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use schemars::JsonSchema;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

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
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SemanticFingerprint {
    pub algorithm: FingerprintAlgorithm,
    /// Hash of the normalized AST/source structure (insensitive to comments and whitespace).
    pub ast_hash: Hash256,
    /// Hash of the entity's signature line / declaration shape.
    pub signature_hash: Hash256,
    /// Hash of the entity's full source text (changes on any body edit).
    pub behavior_hash: Hash256,
    /// Hash of the entity's behavior-equivalence class: the token stream with
    /// pure-no-op statements (e.g. docstrings) normalized away, so a
    /// behavior-preserving body edit leaves it unchanged while any real change
    /// alters it. The zero hash (the serde default) means "not computed" and is
    /// never treated as a match. Always serialized. The custom deserializer
    /// accepts both the legacy five-field sequence and the current six-field
    /// sequence because graph snapshots use a positional binary format.
    pub equivalence_hash: Hash256,
    /// Confidence in fingerprint stability (0.0 - 1.0).
    pub stability_score: f32,
}

/// Serde default for [`SemanticFingerprint::equivalence_hash`]: the zero hash,
/// the sentinel for "equivalence class not computed".
fn zero_equivalence_hash() -> Hash256 {
    Hash256::from_bytes([0; 32])
}

#[derive(Deserialize)]
struct CurrentSemanticFingerprint {
    algorithm: FingerprintAlgorithm,
    ast_hash: Hash256,
    signature_hash: Hash256,
    behavior_hash: Hash256,
    #[serde(default = "zero_equivalence_hash")]
    equivalence_hash: Hash256,
    stability_score: f32,
}

impl<'de> Deserialize<'de> for SemanticFingerprint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SemanticFingerprintVisitor;

        impl<'de> Visitor<'de> for SemanticFingerprintVisitor {
            type Value = SemanticFingerprint;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a SemanticFingerprint map or five/six-field sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let encoded_len = seq.size_hint().ok_or_else(|| {
                    serde::de::Error::custom(
                        "sequence length is required to distinguish legacy and current fingerprints",
                    )
                })?;
                if !matches!(encoded_len, 5 | 6) {
                    return Err(serde::de::Error::invalid_length(encoded_len, &self));
                }

                let algorithm = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let ast_hash = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let signature_hash = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                let behavior_hash = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;

                let (equivalence_hash, stability_score) = if encoded_len == 5 {
                    let stability_score = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(4, &self))?;
                    (zero_equivalence_hash(), stability_score)
                } else {
                    let equivalence_hash = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(4, &self))?;
                    let stability_score = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(5, &self))?;
                    (equivalence_hash, stability_score)
                };

                Ok(SemanticFingerprint {
                    algorithm,
                    ast_hash,
                    signature_hash,
                    behavior_hash,
                    equivalence_hash,
                    stability_score,
                })
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let current = CurrentSemanticFingerprint::deserialize(
                    serde::de::value::MapAccessDeserializer::new(map),
                )?;
                Ok(SemanticFingerprint {
                    algorithm: current.algorithm,
                    ast_hash: current.ast_hash,
                    signature_hash: current.signature_hash,
                    behavior_hash: current.behavior_hash,
                    equivalence_hash: current.equivalence_hash,
                    stability_score: current.stability_score,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "algorithm",
            "ast_hash",
            "signature_hash",
            "behavior_hash",
            "equivalence_hash",
            "stability_score",
        ];
        deserializer.deserialize_struct("SemanticFingerprint", FIELDS, SemanticFingerprintVisitor)
    }
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

    #[derive(Serialize)]
    struct LegacySemanticFingerprintFixture {
        algorithm: FingerprintAlgorithm,
        ast_hash: Hash256,
        signature_hash: Hash256,
        behavior_hash: Hash256,
        stability_score: f32,
    }

    fn fingerprint() -> SemanticFingerprint {
        SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0x11; 32]),
            signature_hash: Hash256::from_bytes([0x22; 32]),
            behavior_hash: Hash256::from_bytes([0x33; 32]),
            equivalence_hash: Hash256::from_bytes([0x44; 32]),
            stability_score: 0.8,
        }
    }

    #[test]
    fn semantic_fingerprint_current_msgpack_roundtrip() {
        let expected = fingerprint();
        let bytes = rmp_serde::to_vec(&expected).unwrap();
        let decoded: SemanticFingerprint = rmp_serde::from_slice(&bytes).unwrap();

        assert_eq!(decoded.algorithm, expected.algorithm);
        assert_eq!(decoded.ast_hash, expected.ast_hash);
        assert_eq!(decoded.signature_hash, expected.signature_hash);
        assert_eq!(decoded.behavior_hash, expected.behavior_hash);
        assert_eq!(decoded.equivalence_hash, expected.equivalence_hash);
        assert_eq!(decoded.stability_score, expected.stability_score);
    }

    #[test]
    fn semantic_fingerprint_reads_legacy_msgpack_sequence() {
        let fixture = LegacySemanticFingerprintFixture {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0x11; 32]),
            signature_hash: Hash256::from_bytes([0x22; 32]),
            behavior_hash: Hash256::from_bytes([0x33; 32]),
            stability_score: 0.8,
        };
        let bytes = rmp_serde::to_vec(&fixture).unwrap();
        let decoded: SemanticFingerprint = rmp_serde::from_slice(&bytes).unwrap();

        assert_eq!(decoded.algorithm, fixture.algorithm);
        assert_eq!(decoded.ast_hash, fixture.ast_hash);
        assert_eq!(decoded.signature_hash, fixture.signature_hash);
        assert_eq!(decoded.behavior_hash, fixture.behavior_hash);
        assert_eq!(decoded.equivalence_hash, Hash256::from_bytes([0; 32]));
        assert_eq!(decoded.stability_score, fixture.stability_score);
    }

    #[test]
    fn semantic_fingerprint_reads_legacy_json_map() {
        let expected = fingerprint();
        let mut value = serde_json::to_value(&expected).unwrap();
        value.as_object_mut().unwrap().remove("equivalence_hash");
        let decoded: SemanticFingerprint = serde_json::from_value(value).unwrap();

        assert_eq!(decoded.equivalence_hash, Hash256::from_bytes([0; 32]));
        assert_eq!(decoded.stability_score, expected.stability_score);
    }

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
                equivalence_hash: kin_blobs::Hash256::from_bytes([0; 32]),
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
