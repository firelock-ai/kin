use kin_model::{
    Entity, EntityId, EntityKind, EntityMetadata, FilePathId, LanguageId, ParseState, RelationKind,
    SemanticFingerprint, SourceSpan, Visibility,
};

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
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }
}

/// Raw extracted relation between two named entities.
#[derive(Debug, Clone)]
pub struct ExtractedRelation {
    pub kind: RelationKind,
    pub src_name: String,
    pub dst_name: String,
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
