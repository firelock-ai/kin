use serde::{Deserialize, Serialize};
use std::ops::Range;

use crate::ids::*;

/// CST mapping for a source file, enabling surgical byte-range splicing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLayout {
    pub file_id: FilePathId,
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
    Trivia {
        byte_range: Range<usize>,
    },
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
}

/// Classification of structured artifact types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactKind {
    PackageManifest,
    SqlMigration,
    CiConfig,
    Dockerfile,
    Makefile,
}

/// An opaque file tracked by content hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaqueArtifact {
    pub file_id: FilePathId,
    pub content_hash: Hash256,
    pub mime_type: Option<String>,
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
        });
        let json = serde_json::to_string(&opaque).unwrap();
        let parsed: TrackedFile = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, TrackedFile::OpaqueArtifact(_)));
    }
}
