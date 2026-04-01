// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Text search wrapper — delegates to kin-search with RetrievalKey specialization.

use std::path::PathBuf;

use crate::error::KinDbError;
use crate::types::{Entity, EntityId};
use kin_model::{
    ArtifactKind, EntityRole, OpaqueArtifact, RetrievalKey, ShallowTrackedFile, StructuredArtifact,
};

// ── Field weights (same as the original inline implementation) ──────────────

const WEIGHT_NAME: f32 = 5.0;
const WEIGHT_SIGNATURE: f32 = 3.0;
const WEIGHT_DOC_SUMMARY: f32 = 2.5;
const WEIGHT_BODY_PREVIEW: f32 = 1.5;
const WEIGHT_FILE_IMPORT_CONTEXT: f32 = 1.4;
const WEIGHT_FILE_SURFACE_CONTEXT: f32 = 2.2;
const WEIGHT_FILE_PATH: f32 = 2.0;
const WEIGHT_KIND: f32 = 1.0;
const WEIGHT_ARTIFACT_KIND: f32 = 3.0;
const WEIGHT_ARTIFACT_PREVIEW: f32 = 2.0;
const WEIGHT_ARTIFACT_MIME: f32 = 1.4;
const WEIGHT_SHALLOW_LANGUAGE: f32 = 1.2;
const WEIGHT_SHALLOW_COUNTS: f32 = 0.8;
const WEIGHT_SHALLOW_DECLARATIONS: f32 = 2.4;
const WEIGHT_SHALLOW_IMPORTS: f32 = 1.6;
const EMBEDDING_BODY_PREVIEW_KEY: &str = "embedding_body_preview";
const FILE_IMPORT_CONTEXT_KEY: &str = "file_import_context";
const FILE_SURFACE_CONTEXT_KEY: &str = "file_surface_context";

/// Text search index specialized for retrieval search.
///
/// Thin wrapper around `kin_search::TextIndex<RetrievalKey>` that adapts the
/// generic API to the Entity-specific interface that the rest of kin-db
/// expects.
pub struct TextIndex {
    inner: kin_search::TextIndex<RetrievalKey>,
}

impl TextIndex {
    /// Create a new in-memory text search index.
    pub fn new() -> Result<Self, KinDbError> {
        Ok(Self {
            inner: kin_search::TextIndex::new(),
        })
    }

    /// Open or create a text search index.
    ///
    /// When `path` is provided, the underlying kin-search index is persisted
    /// to disk and stamped against the graph snapshot root hash.
    pub fn open(path: Option<&PathBuf>) -> Result<Self, KinDbError> {
        Ok(Self {
            inner: kin_search::TextIndex::open(path)
                .map_err(|e| KinDbError::IndexError(e.to_string()))?,
        })
    }

    /// Open a persisted text search index without allowing write-through.
    pub fn open_read_only(path: Option<&PathBuf>) -> Result<Self, KinDbError> {
        Ok(Self {
            inner: kin_search::TextIndex::open_read_only(path)
                .map_err(|e| KinDbError::IndexError(e.to_string()))?,
        })
    }

    /// Index or re-index an entity for text search.
    ///
    /// Stages the change — call `commit()` to make it visible to searches.
    pub fn upsert(&self, entity: &Entity) -> Result<(), KinDbError> {
        let fields = entity_fields(entity);
        let field_refs: Vec<(&str, f32)> = fields.iter().map(|(s, w)| (s.as_str(), *w)).collect();
        self.upsert_retrievable(RetrievalKey::Entity(entity.id), &field_refs)
    }

    /// Index or re-index a retrievable object for text search.
    ///
    /// Stages the change — call `commit()` to make it visible to searches.
    pub fn upsert_retrievable(
        &self,
        key: RetrievalKey,
        fields: &[(&str, f32)],
    ) -> Result<(), KinDbError> {
        let _span = tracing::info_span!(
            "kindb.text_index.upsert",
            key = ?key,
            fields = fields.len()
        )
        .entered();
        self.inner
            .upsert(key, fields)
            .map_err(|e| KinDbError::IndexError(e.to_string()))
    }

    /// Index or re-index an entity with additional graph-derived lexical fields.
    ///
    /// This lets kin-db fold a small amount of relation context into the
    /// entity's search document without changing the persisted entity schema.
    pub fn upsert_with_extra_fields(
        &self,
        entity: &Entity,
        extra_fields: &[(String, f32)],
    ) -> Result<(), KinDbError> {
        let _span = tracing::info_span!(
            "kindb.text_index.upsert",
            entity = %entity.name,
            extra_fields = extra_fields.len()
        )
        .entered();
        let fields = if extra_fields.is_empty() {
            entity_fields(entity)
        } else {
            entity_fields_with_extra(entity, extra_fields)
        };
        let field_refs: Vec<(&str, f32)> = fields.iter().map(|(s, w)| (s.as_str(), *w)).collect();
        self.upsert_retrievable(RetrievalKey::Entity(entity.id), &field_refs)
    }

    /// Remove an entity from the text index.
    ///
    /// Stages the removal — call `commit()` to make it visible to searches.
    pub fn remove(&self, entity_id: &EntityId) -> Result<(), KinDbError> {
        let key = RetrievalKey::Entity(*entity_id);
        self.remove_retrievable(&key)
    }

    /// Remove any retrieval key from the text index.
    pub fn remove_retrievable(&self, key: &RetrievalKey) -> Result<(), KinDbError> {
        self.inner
            .remove(key)
            .map_err(|e| KinDbError::IndexError(e.to_string()))
    }

    /// Commit all pending writes, making staged changes visible to searches.
    pub fn commit(&self) -> Result<(), KinDbError> {
        let _span = tracing::info_span!("kindb.text_index.commit").entered();
        self.inner
            .commit()
            .map_err(|e| KinDbError::IndexError(e.to_string()))
    }

    /// Search across entity names, signatures, and file paths.
    ///
    /// Returns up to `limit` matching retrieval keys with their relevance
    /// scores, ranked highest-first. Uses BM25 scoring with field weights.
    pub fn fuzzy_search(
        &self,
        query_str: &str,
        limit: usize,
    ) -> Result<Vec<(RetrievalKey, f32)>, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.text_index.fuzzy_search",
            query = %query_str,
            limit = limit
        )
        .entered();
        self.inner
            .fuzzy_search(query_str, limit)
            .map_err(|e| KinDbError::IndexError(e.to_string()))
    }

    pub fn graph_root_hash(&self) -> Option<[u8; 32]> {
        self.inner.graph_root_hash()
    }

    pub fn set_graph_root_hash(&self, graph_root_hash: [u8; 32]) {
        self.inner.set_graph_root_hash(graph_root_hash);
    }

    /// Number of committed documents currently visible to search.
    pub fn live_document_count(&self) -> usize {
        self.inner.live_document_count()
    }

    /// Whether a committed retrieval document is currently visible to search.
    pub fn contains_retrievable(&self, key: &RetrievalKey) -> bool {
        self.inner.contains(key)
    }
}

impl std::fmt::Debug for TextIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TextIndex(kin-search)")
    }
}

/// A search hit with its retrieval key, score, and optional entity role.
///
/// Used by downstream ranking to group results by role (Source, Test, External, etc.)
/// without requiring a second entity lookup pass.
#[derive(Debug, Clone)]
pub struct ScoredHit {
    pub key: RetrievalKey,
    pub score: f32,
    /// `Some` for entity keys when the lookup function returns a role,
    /// `None` for non-entity keys (artifacts, shallow files) or when the
    /// entity is not found in the store.
    pub role: Option<EntityRole>,
}

/// Enrich raw search results with entity roles from the graph.
///
/// Takes a list of `(RetrievalKey, f32)` pairs (as returned by `fuzzy_search`
/// or vector `search_similar`) and a lookup function that resolves an
/// `EntityId` to its `EntityRole`. Non-entity keys get `role: None`.
///
/// Scores are propagated unchanged — this function groups, it does not penalize.
pub fn resolve_roles<F>(results: Vec<(RetrievalKey, f32)>, role_lookup: F) -> Vec<ScoredHit>
where
    F: Fn(&EntityId) -> Option<EntityRole>,
{
    results
        .into_iter()
        .map(|(key, score)| {
            let role = match &key {
                RetrievalKey::Entity(id) => role_lookup(id),
                _ => None,
            };
            ScoredHit { key, score, role }
        })
        .collect()
}

/// Extract weighted field texts from an Entity for indexing.
fn entity_fields(entity: &Entity) -> Vec<(String, f32)> {
    entity_fields_with_extra(entity, &[])
}

fn entity_fields_with_extra(entity: &Entity, extra_fields: &[(String, f32)]) -> Vec<(String, f32)> {
    let file_path = entity
        .file_origin
        .as_ref()
        .map(|f| f.0.as_str())
        .unwrap_or("");
    let kind_str = format!("{:?}", entity.kind);

    let mut fields = Vec::with_capacity(8);

    if !entity.name.is_empty() {
        fields.push((entity.name.clone(), WEIGHT_NAME));
    }
    if !entity.signature.is_empty() {
        fields.push((entity.signature.clone(), WEIGHT_SIGNATURE));
    }
    if let Some(doc_summary) = entity.doc_summary.as_deref() {
        let doc_summary = doc_summary.trim();
        if !doc_summary.is_empty() {
            fields.push((doc_summary.to_string(), WEIGHT_DOC_SUMMARY));
        }
    }
    if let Some(body_preview) = entity
        .metadata
        .extra
        .get(EMBEDDING_BODY_PREVIEW_KEY)
        .and_then(|value| value.as_str())
    {
        let body_preview = body_preview.trim();
        if !body_preview.is_empty() {
            fields.push((body_preview.to_string(), WEIGHT_BODY_PREVIEW));
        }
    }
    if let Some(file_import_context) = entity
        .metadata
        .extra
        .get(FILE_IMPORT_CONTEXT_KEY)
        .and_then(|value| value.as_str())
    {
        let file_import_context = file_import_context.trim();
        if !file_import_context.is_empty() {
            fields.push((file_import_context.to_string(), WEIGHT_FILE_IMPORT_CONTEXT));
        }
    }
    if let Some(file_surface_context) = entity
        .metadata
        .extra
        .get(FILE_SURFACE_CONTEXT_KEY)
        .and_then(|value| value.as_str())
    {
        let file_surface_context = file_surface_context.trim();
        if !file_surface_context.is_empty() {
            fields.push((
                file_surface_context.to_string(),
                WEIGHT_FILE_SURFACE_CONTEXT,
            ));
        }
    }
    if !file_path.is_empty() {
        fields.push((file_path.to_string(), WEIGHT_FILE_PATH));
    }
    fields.push((kind_str, WEIGHT_KIND));
    for (text, weight) in extra_fields {
        let text = text.trim();
        if !text.is_empty() {
            fields.push((text.to_string(), *weight));
        }
    }

    fields
}

pub fn structured_artifact_fields(artifact: &StructuredArtifact) -> Vec<(String, f32)> {
    let mut fields = Vec::with_capacity(4);
    fields.push((
        artifact_kind_label(artifact.kind).to_string(),
        WEIGHT_ARTIFACT_KIND,
    ));
    fields.push((artifact.file_id.0.clone(), WEIGHT_FILE_PATH));
    if let Some(text_preview) = artifact.text_preview.as_deref() {
        let text_preview = text_preview.trim();
        if !text_preview.is_empty() {
            fields.push((text_preview.to_string(), WEIGHT_ARTIFACT_PREVIEW));
        }
    }
    fields
}

pub fn opaque_artifact_fields(artifact: &OpaqueArtifact) -> Vec<(String, f32)> {
    let mut fields = Vec::with_capacity(4);
    fields.push(("opaque_artifact".to_string(), WEIGHT_KIND));
    fields.push((artifact.file_id.0.clone(), WEIGHT_FILE_PATH));
    if let Some(mime_type) = artifact.mime_type.as_deref() {
        let mime_type = mime_type.trim();
        if !mime_type.is_empty() {
            fields.push((mime_type.to_string(), WEIGHT_ARTIFACT_MIME));
        }
    }
    if let Some(text_preview) = artifact.text_preview.as_deref() {
        let text_preview = text_preview.trim();
        if !text_preview.is_empty() {
            fields.push((text_preview.to_string(), WEIGHT_ARTIFACT_PREVIEW));
        }
    }
    fields
}

pub fn shallow_file_fields(file: &ShallowTrackedFile) -> Vec<(String, f32)> {
    let mut fields = Vec::with_capacity(6);
    fields.push(("shallow_file".to_string(), WEIGHT_KIND));
    fields.push((file.file_id.0.clone(), WEIGHT_FILE_PATH));
    let language_hint = file.language_hint.trim();
    if !language_hint.is_empty() {
        fields.push((language_hint.to_string(), WEIGHT_SHALLOW_LANGUAGE));
    }
    fields.push((
        format!(
            "declarations {} imports {}",
            file.declaration_count, file.import_count
        ),
        WEIGHT_SHALLOW_COUNTS,
    ));
    if !file.declaration_names.is_empty() {
        fields.push((
            file.declaration_names.join(" "),
            WEIGHT_SHALLOW_DECLARATIONS,
        ));
    }
    if !file.import_paths.is_empty() {
        fields.push((file.import_paths.join(" "), WEIGHT_SHALLOW_IMPORTS));
    }
    fields
}

fn artifact_kind_label(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::PackageManifest => "package_manifest",
        ArtifactKind::SqlMigration => "sql_migration",
        ArtifactKind::CiConfig => "ci_config",
        ArtifactKind::Dockerfile => "dockerfile",
        ArtifactKind::ComposeFile => "compose_file",
        ArtifactKind::Makefile => "makefile",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn make_entity(name: &str, file: &str, kind: EntityKind) -> Entity {
        Entity {
            id: EntityId::new(),
            kind,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn make_entity_with_context(
        name: &str,
        file: &str,
        kind: EntityKind,
        doc_summary: Option<&str>,
        body_preview: Option<&str>,
    ) -> Entity {
        let mut entity = make_entity(name, file, kind);
        entity.doc_summary = doc_summary.map(str::to_string);
        if let Some(body_preview) = body_preview {
            entity.metadata.extra.insert(
                EMBEDDING_BODY_PREVIEW_KEY.into(),
                serde_json::Value::String(body_preview.to_string()),
            );
        }
        entity
    }

    #[test]
    fn tokenize_camel_case() {
        let tokens = kin_search::tokenize("parseTableFromHtml");
        assert!(tokens.contains(&"parse".to_string()));
        assert!(tokens.contains(&"table".to_string()));
        assert!(tokens.contains(&"from".to_string()));
        assert!(tokens.contains(&"html".to_string()));
    }

    #[test]
    fn tokenize_snake_case() {
        let tokens = kin_search::tokenize("parse_table_html");
        assert!(tokens.contains(&"parse".to_string()));
        assert!(tokens.contains(&"table".to_string()));
        assert!(tokens.contains(&"html".to_string()));
    }

    #[test]
    fn tokenize_file_path() {
        let tokens = kin_search::tokenize("src/io/ascii/html.py");
        assert!(tokens.contains(&"src".to_string()));
        assert!(tokens.contains(&"io".to_string()));
        assert!(tokens.contains(&"ascii".to_string()));
        assert!(tokens.contains(&"html".to_string()));
        assert!(tokens.contains(&"py".to_string()));
    }

    #[test]
    fn index_and_search_by_name() {
        let idx = TextIndex::new().unwrap();
        let e1 = make_entity("getUserById", "src/users.rs", EntityKind::Function);
        let e2 = make_entity("deletePost", "src/posts.rs", EntityKind::Function);
        let id1 = e1.id;

        idx.upsert(&e1).unwrap();
        idx.upsert(&e2).unwrap();
        idx.commit().unwrap();

        let results = idx.fuzzy_search("getUserById", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, RetrievalKey::Entity(id1));
    }

    #[test]
    fn search_by_file_path() {
        let idx = TextIndex::new().unwrap();
        let e1 = make_entity("foo", "src/auth/login.rs", EntityKind::Function);
        let id1 = e1.id;

        idx.upsert(&e1).unwrap();
        idx.commit().unwrap();

        let results = idx.fuzzy_search("auth", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, RetrievalKey::Entity(id1));
    }

    #[test]
    fn remove_from_index() {
        let idx = TextIndex::new().unwrap();
        let e1 = make_entity("myFunction", "src/lib.rs", EntityKind::Function);
        let id1 = e1.id;

        idx.upsert(&e1).unwrap();
        idx.commit().unwrap();

        // Should find it
        let results = idx.fuzzy_search("myFunction", 10).unwrap();
        assert!(!results.is_empty());

        // Remove and verify gone
        idx.remove(&id1).unwrap();
        idx.commit().unwrap();
        let results = idx.fuzzy_search("myFunction", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn upsert_updates_existing() {
        let idx = TextIndex::new().unwrap();
        let mut e1 = make_entity("alphaHandler", "src/lib.rs", EntityKind::Function);
        let id1 = e1.id;

        idx.upsert(&e1).unwrap();
        idx.commit().unwrap();

        // Update name to something with completely different tokens
        e1.name = "betaProcessor".to_string();
        e1.signature = "fn betaProcessor()".to_string();
        idx.upsert(&e1).unwrap();
        idx.commit().unwrap();

        // Old unique token should not find it
        let results = idx.fuzzy_search("alpha", 10).unwrap();
        assert!(results.is_empty());

        // New name should
        let results = idx.fuzzy_search("betaProcessor", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, RetrievalKey::Entity(id1));
    }

    #[test]
    fn empty_search() {
        let idx = TextIndex::new().unwrap();
        let results = idx.fuzzy_search("anything", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn persistent_index_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("text_index");

        let idx = TextIndex::open(Some(&path)).unwrap();
        let e1 = make_entity("persistMe", "src/persist.rs", EntityKind::Function);

        idx.upsert(&e1).unwrap();
        idx.set_graph_root_hash([9; 32]);
        idx.commit().unwrap();

        let reopened = TextIndex::open(Some(&path)).unwrap();
        let results = reopened.fuzzy_search("persistMe", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, RetrievalKey::Entity(e1.id));
        assert_eq!(reopened.graph_root_hash(), Some([9; 32]));
    }

    #[test]
    fn substring_fuzzy_match() {
        let idx = TextIndex::new().unwrap();
        let e1 = make_entity("QdpReader", "src/io/qdp.py", EntityKind::Function);
        let id1 = e1.id;

        idx.upsert(&e1).unwrap();
        idx.commit().unwrap();

        // "qdp" should match "QdpReader" via substring
        let results = idx.fuzzy_search("qdp", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, RetrievalKey::Entity(id1));
    }

    #[test]
    fn search_by_doc_summary() {
        let idx = TextIndex::new().unwrap();
        let e1 = make_entity_with_context(
            "parseConfig",
            "src/config.rs",
            EntityKind::Function,
            Some("Parses TOML configuration values and validates required keys"),
            None,
        );
        let id1 = e1.id;

        idx.upsert(&e1).unwrap();
        idx.commit().unwrap();

        let results = idx.fuzzy_search("configuration values", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, RetrievalKey::Entity(id1));
    }

    #[test]
    fn search_by_body_preview() {
        let idx = TextIndex::new().unwrap();
        let e1 = make_entity_with_context(
            "reportFailure",
            "src/errors.rs",
            EntityKind::Function,
            None,
            Some("return Err(\"missing extension registry\".into());"),
        );
        let id1 = e1.id;

        idx.upsert(&e1).unwrap();
        idx.commit().unwrap();

        let results = idx.fuzzy_search("extension registry", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, RetrievalKey::Entity(id1));
    }

    #[test]
    fn search_by_file_import_context() {
        let idx = TextIndex::new().unwrap();
        let mut entity = make_entity(
            "hydrate",
            "packages/runtime-dom/src/index.ts",
            EntityKind::Function,
        );
        entity.metadata.extra.insert(
            FILE_IMPORT_CONTEXT_KEY.into(),
            serde_json::Value::String(
                "module @vue/runtime-core names createRenderer hydrate".into(),
            ),
        );
        let id = entity.id;

        idx.upsert(&entity).unwrap();
        idx.commit().unwrap();

        let results = idx.fuzzy_search("@vue/runtime-core hydrate", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, RetrievalKey::Entity(id));
    }

    #[test]
    fn search_by_file_surface_context() {
        let idx = TextIndex::new().unwrap();
        let mut entity = make_entity(
            "useAutocomplete",
            "packages/mui-base/src/useAutocomplete/useAutocomplete.js",
            EntityKind::Function,
        );
        entity.metadata.extra.insert(
            FILE_SURFACE_CONTEXT_KEY.into(),
            serde_json::Value::String("surface useAutocomplete surface use autocomplete".into()),
        );
        let id = entity.id;

        idx.upsert(&entity).unwrap();
        idx.commit().unwrap();

        let results = idx.fuzzy_search("Autocomplete", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, RetrievalKey::Entity(id));
    }

    #[test]
    fn resolve_roles_attaches_entity_roles() {
        use kin_model::ArtifactId;
        use std::collections::HashMap;

        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let artifact_key = RetrievalKey::Artifact(ArtifactId::from_path("README.md"));

        let mut roles: HashMap<EntityId, EntityRole> = HashMap::new();
        roles.insert(e1, EntityRole::Source);
        roles.insert(e2, EntityRole::Test);

        let results = vec![
            (RetrievalKey::Entity(e1), 5.0),
            (RetrievalKey::Entity(e2), 3.0),
            (artifact_key, 2.0),
        ];

        let hits = resolve_roles(results, |id| roles.get(id).copied());

        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].role, Some(EntityRole::Source));
        assert_eq!(hits[0].score, 5.0);
        assert_eq!(hits[1].role, Some(EntityRole::Test));
        assert_eq!(hits[1].score, 3.0);
        // Artifact keys have no role
        assert_eq!(hits[2].role, None);
        assert_eq!(hits[2].score, 2.0);
    }

    #[test]
    fn resolve_roles_missing_entity_returns_none() {
        let e1 = EntityId::new();
        let results = vec![(RetrievalKey::Entity(e1), 4.0)];

        let hits = resolve_roles(results, |_id| None);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].role, None);
    }

    #[test]
    fn upsert_retrievable_indexes_artifact_keys() {
        let idx = TextIndex::new().unwrap();
        let key = RetrievalKey::Artifact(kin_model::ArtifactId::from_path("docs/guide.md"));

        idx.upsert_retrievable(key, &[("semantic substrate", 4.0)])
            .unwrap();
        idx.commit().unwrap();

        let results = idx.fuzzy_search("semantic substrate", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, key);
    }

    #[test]
    fn structured_artifact_fields_include_kind_path_and_preview() {
        let fields = structured_artifact_fields(&StructuredArtifact {
            file_id: kin_model::FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: kin_model::Hash256::from_bytes([1; 32]),
            text_preview: Some("build install".into()),
        });

        let texts: Vec<&str> = fields.iter().map(|(text, _)| text.as_str()).collect();
        assert!(texts.contains(&"makefile"));
        assert!(texts.contains(&"Makefile"));
        assert!(texts.contains(&"build install"));
    }

    #[test]
    fn opaque_artifact_fields_include_mime_and_preview() {
        let fields = opaque_artifact_fields(&OpaqueArtifact {
            file_id: kin_model::FilePathId::new("assets/logo.svg"),
            content_hash: kin_model::Hash256::from_bytes([2; 32]),
            mime_type: Some("image/svg+xml".into()),
            text_preview: Some("<svg".into()),
        });

        let texts: Vec<&str> = fields.iter().map(|(text, _)| text.as_str()).collect();
        assert!(texts.contains(&"opaque_artifact"));
        assert!(texts.contains(&"assets/logo.svg"));
        assert!(texts.contains(&"image/svg+xml"));
        assert!(texts.contains(&"<svg"));
    }

    #[test]
    fn shallow_file_fields_include_surface_context() {
        let fields = shallow_file_fields(&ShallowTrackedFile {
            file_id: kin_model::FilePathId::new("src/lib.rs"),
            language_hint: "rust".into(),
            declaration_count: 2,
            import_count: 1,
            syntax_hash: kin_model::Hash256::from_bytes([3; 32]),
            signature_hash: None,
            declaration_names: vec!["main".into(), "helper".into()],
            import_paths: vec!["std::fmt".into()],
        });

        let texts: Vec<&str> = fields.iter().map(|(text, _)| text.as_str()).collect();
        assert!(texts.contains(&"shallow_file"));
        assert!(texts.contains(&"src/lib.rs"));
        assert!(texts.contains(&"rust"));
        assert!(texts.contains(&"main helper"));
        assert!(texts.contains(&"std::fmt"));
    }
}
