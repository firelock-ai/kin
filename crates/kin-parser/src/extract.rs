use kin_model::{
    Entity, EntityId, EntityKind, EntityMetadata, FilePathId, LanguageId, ParseState,
    RelationKind, SemanticFingerprint, SourceSpan, Visibility,
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

/// Output of parsing a single file.
#[derive(Debug, Clone)]
pub struct ParseOutput {
    pub entities: Vec<ExtractedEntity>,
    pub relations: Vec<ExtractedRelation>,
    pub parse_state: ParseState,
}
