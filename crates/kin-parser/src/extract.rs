// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{
    Entity, EntityId, EntityKind, EntityMetadata, FilePathId, LanguageId, ParseState, RelationKind,
    SemanticFingerprint, SourceSpan, Visibility,
};

pub const EMBEDDING_BODY_PREVIEW_KEY: &str = "embedding_body_preview";

/// Raw extracted entity before ID assignment.
#[derive(Debug, Clone)]
pub struct ExtractedEntity {
    pub kind: EntityKind,
    pub name: String,
    pub signature: String,
    pub visibility: Visibility,
    pub doc_summary: Option<String>,
    pub fingerprint: SemanticFingerprint,
    pub span: SourceSpan,
}

impl ExtractedEntity {
    /// Convert to a full Entity with a new ID.
    pub fn into_entity(self, language: LanguageId, file_id: &FilePathId) -> Entity {
        self.into_entity_with_source(language, file_id, None)
    }

    /// Convert to a full Entity with optional source bytes for richer metadata.
    pub fn into_entity_with_source(
        self,
        language: LanguageId,
        file_id: &FilePathId,
        source: Option<&[u8]>,
    ) -> Entity {
        let mut metadata = EntityMetadata::default();
        if let Some(preview) = source.and_then(|src| embedding_body_preview(src, &self.span)) {
            metadata.extra.insert(
                EMBEDDING_BODY_PREVIEW_KEY.into(),
                serde_json::Value::String(preview),
            );
        }
        Entity {
            id: EntityId::new(),
            kind: self.kind,
            name: self.name,
            language,
            fingerprint: self.fingerprint,
            file_origin: Some(file_id.clone()),
            span: Some(self.span),
            signature: self.signature,
            visibility: self.visibility,
            doc_summary: self.doc_summary,
            metadata,
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }
}

fn embedding_body_preview(source: &[u8], span: &SourceSpan) -> Option<String> {
    let start = span.start_byte.min(source.len());
    let end = span.end_byte.min(source.len());
    if start >= end {
        return None;
    }

    let raw = String::from_utf8_lossy(&source[start..end]);
    let collapsed = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }

    const MAX_CHARS: usize = 800;
    let preview = if collapsed.chars().count() > MAX_CHARS {
        let mut truncated = collapsed.chars().take(MAX_CHARS).collect::<String>();
        truncated.push_str(" ...");
        truncated
    } else {
        collapsed
    };

    Some(preview)
}

/// Raw extracted relation between two named entities.
#[derive(Debug, Clone)]
pub struct ExtractedRelation {
    pub kind: RelationKind,
    pub src_name: String,
    pub dst_name: String,
    /// For Calls/References edges, the module/package the target was imported from.
    /// e.g., `Some("requests")` for `from requests import get`,
    ///        `Some("kin_db")` for `use kin_db::InMemoryGraph`
    pub import_source: Option<String>,
}

/// A single import declaration from source code.
///
/// Represents `import { foo, bar as baz } from './utils'` or
/// `from utils import foo` etc.
#[derive(Debug, Clone)]
pub struct FileImport {
    /// The module path as written in source (e.g., `"./utils"`, `"lodash"`, `"../lib"`).
    pub module_path: String,
    /// Individual names imported from this module.
    pub specifiers: Vec<ImportedName>,
}

/// A single imported name within an import declaration.
#[derive(Debug, Clone)]
pub struct ImportedName {
    /// The name as used locally in this file.
    pub local_name: String,
    /// The original exported name if renamed (e.g., `foo` in `import { foo as bar }`).
    /// `None` if not renamed.
    pub original_name: Option<String>,
    /// Whether this is the default import.
    pub is_default: bool,
}

/// A test function discovered during parsing.
#[derive(Debug, Clone)]
pub struct ExtractedTest {
    /// Name of the test function.
    pub name: String,
    /// The kind of test (unit, integration, etc.).
    pub kind: ExtractedTestKind,
    /// The runner framework (cargo, jest, pytest, go, junit).
    pub runner: String,
}

/// Classification of a discovered test function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractedTestKind {
    Unit,
    Integration,
}

/// Output of parsing a single file.
#[derive(Debug, Clone)]
pub struct ParseOutput {
    pub entities: Vec<ExtractedEntity>,
    pub relations: Vec<ExtractedRelation>,
    /// Detailed import declarations for cross-file resolution.
    pub imports: Vec<FileImport>,
    /// Test functions discovered in this file.
    pub tests: Vec<ExtractedTest>,
    pub parse_state: ParseState,
}
