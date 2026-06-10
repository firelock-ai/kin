// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};
use std::ops::Range;

use crate::entity::ParseState;
use crate::ids::*;

/// How complete the persisted layout is relative to the latest parse attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParseCompleteness {
    Full,
    Partial(String),
    Failed(String),
}

impl ParseCompleteness {
    pub fn from_parse_state(parse_state: &ParseState) -> Self {
        match parse_state {
            ParseState::Valid => Self::Full,
            ParseState::Incomplete { error_ranges } => Self::Partial(format!(
                "{} parse error range(s) during indexing",
                error_ranges.len()
            )),
            ParseState::LastKnownGood { .. } => {
                Self::Failed("projection preserved last known good layout".to_string())
            }
        }
    }

    pub fn bucket(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial(_) => "partial",
            Self::Failed(_) => "failed",
        }
    }
}

impl Default for ParseCompleteness {
    fn default() -> Self {
        Self::Full
    }
}

/// CST mapping for a source file, enabling surgical byte-range splicing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLayout {
    pub file_id: FilePathId,
    #[serde(default)]
    pub parse_completeness: ParseCompleteness,
    pub imports: ImportSection,
    /// Interleaved entities and trivia.
    pub regions: Vec<SourceRegion>,
}

/// A region within a file's layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SourceRegion {
    EntityRef {
        entity_id: EntityId,
        byte_range: Range<usize>,
    },
    /// Whitespace, standalone comments, macros, decorators outside entity spans.
    Trivia { byte_range: Range<usize> },
}

/// Import section of a source file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportSection {
    pub byte_range: Range<usize>,
    pub items: Vec<ImportItem>,
}

/// A single import statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportItem {
    pub source: String,
    pub symbols: Vec<String>,
    pub byte_range: Range<usize>,
}

/// Classification of all tracked files in Kin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrackedFile {
    /// Files containing parseable semantic entities (source code).
    EntitySource(FileLayout),
    /// Files with grammar-backed shallow syntax extraction (C2 tier).
    ShallowSyntax(ShallowTrackedFile),
    /// Files with known structure but no extractable entities.
    StructuredArtifact(StructuredArtifact),
    /// Opaque files tracked by content hash only.
    OpaqueArtifact(OpaqueArtifact),
}

/// A file with known structure but no extractable semantic entities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuredArtifact {
    pub file_id: FilePathId,
    pub kind: ArtifactKind,
    pub content_hash: Hash256,
    #[serde(default)]
    pub text_preview: Option<String>,
}

/// Classification of structured artifact types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactKind {
    PackageManifest,
    SqlMigration,
    CiConfig,
    Dockerfile,
    ComposeFile,
    Makefile,
}

/// An opaque file tracked by content hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaqueArtifact {
    pub file_id: FilePathId,
    pub content_hash: Hash256,
    pub mime_type: Option<String>,
    #[serde(default)]
    pub text_preview: Option<String>,
}

/// A file tracked at C2 shallow syntax tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShallowTrackedFile {
    pub file_id: FilePathId,
    pub language_hint: String,
    pub declaration_count: usize,
    pub import_count: usize,
    pub syntax_hash: Hash256,
    pub signature_hash: Option<Hash256>,
    #[serde(default)]
    pub declaration_names: Vec<String>,
    #[serde(default)]
    pub import_paths: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_kind_roundtrip() {
        let kind = ArtifactKind::PackageManifest;
        let json = serde_json::to_string(&kind).unwrap();
        let parsed: ArtifactKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, kind);
    }

    #[test]
    fn tracked_file_variants() {
        let opaque = TrackedFile::OpaqueArtifact(OpaqueArtifact {
            file_id: FilePathId::new("image.png"),
            content_hash: Hash256::from_bytes([0; 32]),
            mime_type: Some("image/png".to_string()),
            text_preview: None,
        });
        let json = serde_json::to_string(&opaque).unwrap();
        let parsed: TrackedFile = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, TrackedFile::OpaqueArtifact(_)));
    }

    #[test]
    fn parse_completeness_buckets_match_variants() {
        assert_eq!(ParseCompleteness::Full.bucket(), "full");
        assert_eq!(
            ParseCompleteness::Partial("incomplete".to_string()).bucket(),
            "partial"
        );
        assert_eq!(
            ParseCompleteness::Failed("broken".to_string()).bucket(),
            "failed"
        );
    }
}
