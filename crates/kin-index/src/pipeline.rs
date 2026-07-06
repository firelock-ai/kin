// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::Path;

use tracing::debug;

use kin_blobs::BlobStore;
use kin_model::{
    Entity, EntityRole, FileLayout, FilePathId, GraphStore, Hash256, LanguageId, OpaqueArtifact,
    ParseCompleteness, ParseState, Relation, RelationId, RelationOrigin, StructuredArtifact,
};
use kin_parser::{attach_file_context_metadata, parse_shallow_file, AdapterRegistry, ShallowFile};
use kin_projection::build_layout;

use crate::artifacts;
use crate::classifier::{FileClassification, FileClassifier};
use crate::error::{IndexError, Result};
use crate::linker::UnresolvedRelation;

/// Result of indexing a single file.
#[derive(Debug)]
pub struct IndexedFile {
    pub file_id: FilePathId,
    pub language: LanguageId,
    pub entities: Vec<Entity>,
    pub relations: Vec<Relation>,
    /// Cross-file relations that couldn't be fully resolved.
    /// These are collected for later linking by CrossFileLinker.
    pub unresolved_relations: Vec<UnresolvedRelation>,
    pub file_layout: FileLayout,
    pub parse_state: ParseState,
    pub blob_hash: kin_blobs::Hash256,
    /// Raw extracted relations preserved for cross-file linking.
    pub extracted_relations: Vec<kin_parser::ExtractedRelation>,
    /// Import declarations preserved for cross-file linking.
    pub imports: Vec<kin_parser::FileImport>,
}

/// Indexed file plus parser-emitted tests.
///
/// This keeps test metadata available to ingestion callers without widening the
/// existing `IndexedFile` struct yet.
#[derive(Debug)]
pub struct IndexedFileWithTests {
    pub indexed_file: IndexedFile,
    pub tests: Vec<kin_parser::ExtractedTest>,
}

/// Result of indexing any file through the classifier.
#[derive(Debug)]
pub enum IndexedAny {
    /// File was parsed for entities (source code).
    EntitySource(IndexedFile),
    /// File was recognized as a structured artifact.
    StructuredArtifact(StructuredArtifact),
    /// File was parsed at C2 shallow syntax tier.
    ShallowSyntax(ShallowFile),
    /// File was tracked as an opaque blob.
    OpaqueArtifact(OpaqueArtifact),
}

/// The indexing pipeline: parses files, stores blobs, and updates the graph.
pub struct IndexPipeline {
    registry: AdapterRegistry,
}

impl IndexPipeline {
    pub fn new() -> Self {
        Self {
            registry: AdapterRegistry::new(),
        }
    }

    /// Index a single file: parse it, store the blob, and return extracted entities/relations.
    pub fn index_file(&self, path: &Path, blob_store: &BlobStore) -> Result<IndexedFile> {
        let _span = tracing::info_span!(
            "kin.index.index_file",
            path = %path.display()
        )
        .entered();
        let source =
            std::fs::read(path).map_err(|e| IndexError::io(path.display().to_string(), e))?;
        let blob_hash = blob_store.write(&source)?;
        debug!(path = %path.display(), hash = %blob_hash, "stored source blob");
        let file_id = FilePathId::new(path.display().to_string());
        Ok(self
            .index_file_content_with_tests(&file_id, &source, blob_hash)?
            .indexed_file)
    }

    /// Index a single file and retain parser-emitted tests alongside the file result.
    pub fn index_file_with_tests(
        &self,
        path: &Path,
        blob_store: &BlobStore,
    ) -> Result<IndexedFileWithTests> {
        let _span = tracing::info_span!(
            "kin.index.index_file_with_tests",
            path = %path.display()
        )
        .entered();
        let source =
            std::fs::read(path).map_err(|e| IndexError::io(path.display().to_string(), e))?;
        let blob_hash = blob_store.write(&source)?;
        debug!(path = %path.display(), hash = %blob_hash, "stored source blob");
        let file_id = FilePathId::new(path.display().to_string());
        self.index_file_content_with_tests(&file_id, &source, blob_hash)
    }

    /// Index source content already loaded from blob storage.
    ///
    /// This is used by historical/ref-scoped views that need to rebuild an
    /// entity graph from stored blobs without materializing files to disk.
    pub fn index_file_content_with_tests(
        &self,
        file_id: &FilePathId,
        source: &[u8],
        blob_hash: kin_blobs::Hash256,
    ) -> Result<IndexedFileWithTests> {
        let path = Path::new(&file_id.0);
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .ok_or_else(|| IndexError::UnsupportedFile(file_id.0.clone()))?;

        let adapter = self
            .registry
            .get_by_extension_and_content(ext, source)
            .ok_or_else(|| IndexError::UnsupportedFile(ext.to_string()))?;
        let language = adapter.language_id();

        let tree = adapter.parse(source)?;
        let output = adapter.extract(&tree, source, file_id)?;
        let kin_parser::ParseOutput {
            entities: extracted_entities,
            relations: extracted_relations,
            imports,
            tests,
            parse_state,
        } = output;

        let role = classify_file_role(&file_id.0);
        let mut entities: Vec<Entity> = extracted_entities
            .into_iter()
            .map(|entity| {
                let mut ent = entity.into_entity_with_source(language, file_id, Some(source));
                ent.role = role;
                ent
            })
            .collect();
        attach_file_context_metadata(&mut entities, file_id, &imports);
        if language == LanguageId::Go {
            kin_parser::attach_go_command_effect_contract_metadata(&tree, source, &mut entities);
        }

        let (relations, unresolved_relations) = resolve_relations(&extracted_relations, &entities);
        let file_layout = build_layout(
            file_id,
            &entities,
            source.len(),
            &[],
            ParseCompleteness::from_parse_state(&parse_state),
        );

        debug!(
            path = %file_id,
            entities = entities.len(),
            resolved_relations = relations.len(),
            unresolved_relations = unresolved_relations.len(),
            "indexed source content"
        );

        Ok(IndexedFileWithTests {
            indexed_file: IndexedFile {
                file_id: file_id.clone(),
                language,
                entities,
                relations,
                unresolved_relations,
                file_layout,
                extracted_relations,
                imports,
                parse_state,
                blob_hash,
            },
            tests,
        })
    }

    /// Index a single file with an optional incremental parse hint.
    ///
    /// When `old_tree` and `edit_hint` are both provided, uses tree-sitter's
    /// incremental parse for speed (<5ms vs 50-100ms on large files).
    /// Falls back to a full parse when hints are missing.
    ///
    /// Returns the indexed file together with the resulting tree-sitter Tree,
    /// which the caller should cache for future incremental parses.
    pub fn index_file_with_hint(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        old_tree: Option<&tree_sitter::Tree>,
        edit_hint: Option<&kin_parser::EditHint>,
    ) -> Result<(IndexedFile, tree_sitter::Tree)> {
        let _span = tracing::info_span!(
            "kin.index.index_file_with_hint",
            path = %path.display(),
            incremental = old_tree.is_some() && edit_hint.is_some()
        )
        .entered();
        let file_id = FilePathId::new(path.display().to_string());
        let (indexed, tree) =
            self.index_file_hint_with_id(path, blob_store, &file_id, old_tree, edit_hint)?;
        Ok((indexed.indexed_file, tree))
    }

    /// Index a file for incremental reconcile using an explicit logical
    /// `file_id` for all content-addressed identity, while reading source from
    /// `path` on disk.
    ///
    /// This is the single source of truth for the incremental parse/extract
    /// path. Because `EntityId` and `RelationId` are derived from the supplied
    /// `file_id`, absolute-path and normalized (relative) callers produce
    /// identical entity and relation IDs for identical content — the graph-first
    /// content-addressed contract that keeps init and reconcile in agreement.
    fn index_file_hint_with_id(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        file_id: &FilePathId,
        old_tree: Option<&tree_sitter::Tree>,
        edit_hint: Option<&kin_parser::EditHint>,
    ) -> Result<(IndexedFileWithTests, tree_sitter::Tree)> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .ok_or_else(|| IndexError::UnsupportedFile(path.display().to_string()))?;

        let source =
            std::fs::read(path).map_err(|e| IndexError::io(path.display().to_string(), e))?;

        let adapter = self
            .registry
            .get_by_extension_and_content(ext, &source)
            .ok_or_else(|| IndexError::UnsupportedFile(ext.to_string()))?;

        // Store the raw source as a blob
        let blob_hash = blob_store.write(&source)?;
        debug!(path = %path.display(), hash = %blob_hash, "stored source blob");

        let language = adapter.language_id();

        // Parse: incremental when hints are available, full otherwise. An
        // edit can flip a content-disambiguated extension to another
        // adapter, and an old tree from the other grammar must never seed an
        // incremental parse — those files always take the full parse.
        let content_disambiguated = ext == "h";
        let tree = match (old_tree, edit_hint) {
            (Some(old), Some(hint)) if !content_disambiguated => {
                debug!(
                    path = %path.display(),
                    start = hint.start_byte,
                    old_end = hint.old_end_byte,
                    new_end = hint.new_end_byte,
                    "incremental parse"
                );
                adapter.parse_incremental(&source, old, hint)?
            }
            _ => adapter.parse(&source)?,
        };
        let output = adapter.extract(&tree, &source, file_id)?;
        let kin_parser::ParseOutput {
            entities: extracted_entities,
            relations: extracted_relations,
            imports,
            tests,
            parse_state,
        } = output;

        // Convert extracted entities to model entities
        let role = classify_file_role(&file_id.0);
        let mut entities: Vec<Entity> = extracted_entities
            .into_iter()
            .map(|e| {
                let mut ent = e.into_entity_with_source(language, file_id, Some(&source));
                ent.role = role;
                ent
            })
            .collect();
        attach_file_context_metadata(&mut entities, file_id, &imports);
        if language == LanguageId::Go {
            kin_parser::attach_go_command_effect_contract_metadata(&tree, &source, &mut entities);
        }

        // Resolve extracted relations to model relations using entity name mapping
        let (relations, unresolved_relations) = resolve_relations(&extracted_relations, &entities);
        let file_layout = build_layout(
            file_id,
            &entities,
            source.len(),
            &[],
            ParseCompleteness::from_parse_state(&parse_state),
        );

        debug!(
            path = %path.display(),
            entities = entities.len(),
            resolved_relations = relations.len(),
            unresolved_relations = unresolved_relations.len(),
            incremental = old_tree.is_some(),
            "indexed file"
        );

        Ok((
            IndexedFileWithTests {
                indexed_file: IndexedFile {
                    file_id: file_id.clone(),
                    language,
                    entities,
                    relations,
                    unresolved_relations,
                    file_layout,
                    extracted_relations,
                    imports,
                    parse_state,
                    blob_hash,
                },
                tests,
            },
            tree,
        ))
    }

    /// Index a single file with an optional incremental parse hint and retain parser tests.
    pub fn index_file_with_hint_with_tests(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        old_tree: Option<&tree_sitter::Tree>,
        edit_hint: Option<&kin_parser::EditHint>,
    ) -> Result<(IndexedFileWithTests, tree_sitter::Tree)> {
        let _span = tracing::info_span!(
            "kin.index.index_file_with_hint_with_tests",
            path = %path.display(),
            incremental = old_tree.is_some() && edit_hint.is_some()
        )
        .entered();
        let file_id = FilePathId::new(path.display().to_string());
        self.index_file_hint_with_id(path, blob_store, &file_id, old_tree, edit_hint)
    }

    /// Index a file with hint, normalizing its `FilePathId` relative to the given root.
    ///
    /// Same as `index_file_with_hint` but derives all identity from the
    /// root-relative path. `EntityId` and `RelationId` are computed from the
    /// normalized path, so a repo indexed at different absolute locations yields
    /// identical IDs and reconcile agrees with init.
    pub fn index_file_relative_with_hint(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        root: &Path,
        old_tree: Option<&tree_sitter::Tree>,
        edit_hint: Option<&kin_parser::EditHint>,
    ) -> Result<(IndexedFile, tree_sitter::Tree)> {
        let file_id = normalize_file_path_id(path, root);
        let (indexed, tree) =
            self.index_file_hint_with_id(path, blob_store, &file_id, old_tree, edit_hint)?;
        Ok((indexed.indexed_file, tree))
    }

    /// Index a file with hint, deriving identity from the root-relative path
    /// while retaining parser-emitted tests.
    pub fn index_file_relative_with_hint_with_tests(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        root: &Path,
        old_tree: Option<&tree_sitter::Tree>,
        edit_hint: Option<&kin_parser::EditHint>,
    ) -> Result<(IndexedFileWithTests, tree_sitter::Tree)> {
        let file_id = normalize_file_path_id(path, root);
        self.index_file_hint_with_id(path, blob_store, &file_id, old_tree, edit_hint)
    }

    /// Index a file, deriving all identity from the root-relative path.
    ///
    /// The `root` prefix is stripped and path separators normalized to forward
    /// slashes, producing a stable cross-platform `FilePathId` regardless of
    /// whether the caller passes an absolute or relative path. Entity and
    /// relation IDs are content-addressed from this normalized path, so the same
    /// repo content produces identical IDs across machines and across the
    /// init/reconcile paths.
    pub fn index_file_relative(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        root: &Path,
    ) -> Result<IndexedFile> {
        let _span = tracing::info_span!(
            "kin.index.index_file_relative",
            path = %path.display(),
            root = %root.display()
        )
        .entered();
        Ok(self
            .index_file_relative_with_tests(path, blob_store, root)?
            .indexed_file)
    }

    /// Index a file, deriving identity from the root-relative path and retaining
    /// parser-emitted tests.
    pub fn index_file_relative_with_tests(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        root: &Path,
    ) -> Result<IndexedFileWithTests> {
        let _span = tracing::info_span!(
            "kin.index.index_file_relative_with_tests",
            path = %path.display(),
            root = %root.display()
        )
        .entered();
        let source =
            std::fs::read(path).map_err(|e| IndexError::io(path.display().to_string(), e))?;
        let blob_hash = blob_store.write(&source)?;
        debug!(path = %path.display(), hash = %blob_hash, "stored source blob");
        let file_id = normalize_file_path_id(path, root);
        self.index_file_content_with_tests(&file_id, &source, blob_hash)
    }

    /// Index any file by classifying it first, then routing to the right handler.
    ///
    /// - EntitySource files go through the tree-sitter parser pipeline.
    /// - StructuredArtifact files go through the artifact extractor.
    /// - OpaqueArtifact files are stored as blobs with an optional MIME hint.
    pub fn index_any_file(&self, path: &Path, blob_store: &BlobStore) -> Result<IndexedAny> {
        let _span = tracing::info_span!(
            "kin.index.index_any_file",
            path = %path.display()
        )
        .entered();
        let classification = FileClassifier::classify(path);

        match classification {
            FileClassification::EntitySource => {
                let indexed = self.index_file(path, blob_store)?;
                Ok(IndexedAny::EntitySource(indexed))
            }
            FileClassification::StructuredArtifact(kind) => {
                let content = std::fs::read(path)
                    .map_err(|e| IndexError::io(path.display().to_string(), e))?;
                let blob_hash = blob_store.write(&content)?;

                let file_id = FilePathId::new(path.display().to_string());
                let artifact = artifacts::extract_artifact(kind, &content, &file_id)
                    .map_err(|e| IndexError::Graph(e.to_string()))?;

                debug!(
                    path = %path.display(),
                    kind = ?kind,
                    hash = %blob_hash,
                    "indexed structured artifact"
                );

                Ok(IndexedAny::StructuredArtifact(artifact))
            }
            FileClassification::ShallowSyntax { language_hint } => {
                let content = std::fs::read(path)
                    .map_err(|e| IndexError::io(path.display().to_string(), e))?;
                let blob_hash = blob_store.write(&content)?;
                let file_id = FilePathId::new(path.display().to_string());

                // Try to parse at C2 shallow tier
                if let Some(shallow) = parse_shallow_file(&content, &file_id, &language_hint) {
                    debug!(
                        path = %path.display(),
                        lang = %language_hint,
                        decls = shallow.declarations.len(),
                        imports = shallow.imports.len(),
                        "indexed shallow syntax file (C2)"
                    );
                    return Ok(IndexedAny::ShallowSyntax(shallow));
                }

                // Fallback: no grammar available or parse failed -> opaque
                debug!(
                    path = %path.display(),
                    lang = %language_hint,
                    "C2 grammar not available, falling back to opaque"
                );
                let content_hash = Hash256::from_bytes(blob_hash.0);
                Ok(IndexedAny::OpaqueArtifact(OpaqueArtifact {
                    file_id,
                    content_hash,
                    mime_type: None,
                    text_preview: None,
                }))
            }
            FileClassification::OpaqueArtifact { mime_hint } => {
                let content = std::fs::read(path)
                    .map_err(|e| IndexError::io(path.display().to_string(), e))?;
                let blob_hash = blob_store.write(&content)?;

                let file_id = FilePathId::new(path.display().to_string());
                let content_hash = Hash256::from_bytes(blob_hash.0);

                debug!(
                    path = %path.display(),
                    mime = ?mime_hint,
                    hash = %blob_hash,
                    "indexed opaque artifact"
                );

                Ok(IndexedAny::OpaqueArtifact(OpaqueArtifact {
                    file_id,
                    content_hash,
                    mime_type: mime_hint,
                    text_preview: None,
                }))
            }
        }
    }

    /// Index a file and upsert results into the graph store.
    pub fn index_and_store<G: GraphStore>(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        graph: &G,
    ) -> Result<IndexedFile> {
        let _span = tracing::info_span!(
            "kin.index.index_and_store",
            path = %path.display()
        )
        .entered();
        let indexed = self.index_file(path, blob_store)?;

        for entity in &indexed.entities {
            graph
                .upsert_entity(entity)
                .map_err(|e| IndexError::Graph(e.to_string()))?;
        }
        for relation in &indexed.relations {
            graph
                .upsert_relation(relation)
                .map_err(|e| IndexError::Graph(e.to_string()))?;
        }

        debug!(
            path = %path.display(),
            "upserted {} entities and {} relations",
            indexed.entities.len(),
            indexed.relations.len()
        );

        Ok(indexed)
    }

    /// Resolve cross-file relations given parse data from all files.
    pub fn resolve_cross_file(&self, files: &[crate::linker::FileParseData]) -> Vec<Relation> {
        let _span =
            tracing::info_span!("kin.index.resolve_cross_file", files = files.len()).entered();
        crate::linker::link_cross_file(files)
    }

    /// Get the adapter registry for direct access.
    pub fn registry(&self) -> &AdapterRegistry {
        &self.registry
    }
}

impl Default for IndexPipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Normalize a file path into a stable `FilePathId` by stripping the working
/// directory prefix and converting backslashes to forward slashes.
///
/// If `path` does not start with `root`, it is used as-is (already relative).
pub fn normalize_file_path_id(path: &Path, root: &Path) -> FilePathId {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let normalized = relative.to_string_lossy().replace('\\', "/");
    FilePathId::new(normalized)
}

/// Classify a file path into an [`EntityRole`] based on directory and filename patterns.
///
/// Entities from the same file share the same role. The classifier checks path
/// components against well-known patterns (test dirs, vendor dirs, docs, generated
/// markers) and falls back to `Source` for everything else.
pub fn classify_file_role(path: &str) -> EntityRole {
    let lower = path.to_ascii_lowercase();

    // Test paths
    let test_markers = [
        "test/",
        "tests/",
        "/test/",
        "/tests/",
        "/test_",
        "/_test",
        "/spec/",
        "/specs/",
        "__tests__",
    ];
    if test_markers.iter().any(|m| lower.contains(m))
        || lower.ends_with("_test.py")
        || lower.ends_with("_test.rs")
        || lower.ends_with("_test.go")
        || lower.ends_with(".test.ts")
        || lower.ends_with(".test.js")
        || lower.ends_with(".spec.ts")
        || lower.ends_with(".spec.js")
        || lower.contains("/test_")
    {
        return EntityRole::Test;
    }

    // Vendored paths (copied dependencies)
    if lower.starts_with("vendor/")
        || lower.contains("/vendor/")
        || lower.starts_with("_vendor/")
        || lower.contains("/_vendor/")
        || lower.starts_with("node_modules/")
        || lower.contains("/node_modules/")
    {
        return EntityRole::Vendored;
    }

    // External paths (foreign code not vendored)
    if lower.starts_with("cextern/")
        || lower.contains("/cextern/")
        || lower.starts_with("extern/")
        || lower.contains("/extern/")
        || lower.starts_with("external/")
        || lower.contains("/external/")
        || lower.starts_with("third_party/")
        || lower.contains("/third_party/")
        || lower.starts_with("thirdparty/")
        || lower.contains("/thirdparty/")
    {
        return EntityRole::External;
    }

    // Generated paths
    if lower.starts_with("generated/")
        || lower.contains("/generated/")
        || lower.starts_with("__generated__/")
        || lower.contains("/__generated__/")
        || lower.ends_with(".pb.go")
        || lower.ends_with("_pb2.py")
        || lower.ends_with(".generated.ts")
        || lower.ends_with(".generated.rs")
    {
        return EntityRole::Generated;
    }

    // Docs paths
    if lower.starts_with("docs/")
        || lower.contains("/docs/")
        || lower.starts_with("doc/")
        || lower.contains("/doc/")
        || lower.ends_with(".md")
        || lower.ends_with(".rst")
        || lower.ends_with(".txt")
    {
        return EntityRole::Docs;
    }

    EntityRole::Source
}

/// Resolve extracted name-based relations to entity-ID-based relations.
///
/// Returns both same-file resolved relations and cross-file unresolved ones.
/// Unresolved relations have the source entity ID but target name for deferred linking.
fn resolve_relations(
    extracted: &[kin_parser::ExtractedRelation],
    entities: &[Entity],
) -> (Vec<Relation>, Vec<UnresolvedRelation>) {
    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();

    for rel in extracted {
        let src = entities.iter().find(|e| e.name == rel.src_name);
        let dst = entities.iter().find(|e| e.name == rel.dst_name);

        match (src, dst) {
            (Some(s), Some(d)) => {
                // Same-file relation: fully resolved
                resolved.push(Relation {
                    id: RelationId::from_content(
                        &s.id.0.to_string(),
                        &d.id.0.to_string(),
                        &format!("{:?}", rel.kind),
                    ),
                    kind: rel.kind,
                    src: kin_model::GraphNodeId::Entity(s.id),
                    dst: kin_model::GraphNodeId::Entity(d.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: rel.import_source.clone(),
                    evidence: Vec::new(),
                });
            }
            (Some(s), None) => {
                // Partial resolution: src found, dst is cross-file
                debug!(
                    src = %rel.src_name,
                    dst = %rel.dst_name,
                    kind = ?rel.kind,
                    "unresolved cross-file relation, deferring to linker"
                );
                unresolved.push(UnresolvedRelation {
                    kind: rel.kind,
                    src_entity_id: s.id,
                    dst_name: rel.dst_name.clone(),
                });
            }
            _ => {
                // Both unresolved: skip entirely for now
                debug!(
                    src = %rel.src_name,
                    dst = %rel.dst_name,
                    kind = ?rel.kind,
                    "both src and dst unresolved, skipping"
                );
            }
        }
    }
    (resolved, unresolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_pipeline_creates() {
        let pipeline = IndexPipeline::new();
        let langs = pipeline.registry().supported_languages();
        assert_eq!(langs.len(), 14);
    }

    #[test]
    fn index_typescript_file() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let ts_file = dir.path().join("test.ts");
        std::fs::write(
            &ts_file,
            b"export function hello(name: string): string { return `Hello ${name}`; }",
        )
        .unwrap();

        let result = pipeline.index_file(&ts_file, &blob_store).unwrap();
        assert_eq!(result.language, LanguageId::TypeScript);
        assert!(!result.entities.is_empty());
        assert_eq!(result.entities[0].name, "hello");
        assert!(matches!(result.parse_state, ParseState::Valid));
    }

    #[test]
    fn index_python_file() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let py_file = dir.path().join("test.py");
        std::fs::write(&py_file, b"def greet(name):\n    return f'Hello {name}'").unwrap();

        let result = pipeline.index_file(&py_file, &blob_store).unwrap();
        assert_eq!(result.language, LanguageId::Python);
        assert!(
            result
                .entities
                .iter()
                .any(|entity| entity.kind == kin_model::EntityKind::Function
                    && entity.name == "greet")
        );
    }

    #[test]
    fn index_unsupported_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let txt_file = dir.path().join("readme.txt");
        std::fs::write(&txt_file, b"just some text").unwrap();

        let result = pipeline.index_file(&txt_file, &blob_store);
        assert!(result.is_err());
    }

    #[test]
    fn index_c_file_entity_source() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let c_file = dir.path().join("hello.c");
        std::fs::write(
            &c_file,
            b"#include <stdio.h>\n\nvoid hello(void) {\n    printf(\"hi\\n\");\n}\n\nint add(int a, int b) {\n    return a + b;\n}\n",
        )
        .unwrap();

        let result = pipeline.index_file(&c_file, &blob_store).unwrap();
        let names: Vec<&str> = result.entities.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(result.language, LanguageId::C);
        assert!(names.contains(&"hello"), "Expected 'hello' in {:?}", names);
        assert!(names.contains(&"add"), "Expected 'add' in {:?}", names);
    }

    #[test]
    fn index_rust_file() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let rs_file = dir.path().join("lib.rs");
        std::fs::write(
            &rs_file,
            b"pub fn add(a: i32, b: i32) -> i32 { a + b }\npub struct Point { x: f64, y: f64 }",
        )
        .unwrap();

        let result = pipeline.index_file(&rs_file, &blob_store).unwrap();
        assert_eq!(result.language, LanguageId::Rust);
        assert!(result.entities.len() >= 2);
    }

    #[test]
    fn classify_source_files() {
        assert_eq!(classify_file_role("src/lib.rs"), EntityRole::Source);
        assert_eq!(classify_file_role("pkg/api/handler.go"), EntityRole::Source);
        assert_eq!(classify_file_role("internal/core.go"), EntityRole::Source);
    }

    #[test]
    fn classify_test_files() {
        assert_eq!(classify_file_role("tests/unit_test.py"), EntityRole::Test);
        assert_eq!(classify_file_role("src/foo_test.rs"), EntityRole::Test);
        assert_eq!(classify_file_role("src/foo_test.go"), EntityRole::Test);
        assert_eq!(classify_file_role("src/foo.test.ts"), EntityRole::Test);
        assert_eq!(classify_file_role("src/foo.spec.js"), EntityRole::Test);
        assert_eq!(classify_file_role("test/helpers.py"), EntityRole::Test);
        assert_eq!(
            classify_file_role("__tests__/App.test.ts"),
            EntityRole::Test
        );
    }

    #[test]
    fn classify_external_files() {
        assert_eq!(
            classify_file_role("cextern/wcslib/wcs.c"),
            EntityRole::External
        );
        assert_eq!(
            classify_file_role("third_party/zlib/zlib.h"),
            EntityRole::External
        );
    }

    #[test]
    fn classify_vendored_files() {
        assert_eq!(
            classify_file_role("vendor/github.com/pkg/errors/errors.go"),
            EntityRole::Vendored
        );
        assert_eq!(
            classify_file_role("node_modules/react/index.js"),
            EntityRole::Vendored
        );
    }

    #[test]
    fn classify_generated_files() {
        assert_eq!(classify_file_role("proto/api.pb.go"), EntityRole::Generated);
        assert_eq!(
            classify_file_role("gen/schema_pb2.py"),
            EntityRole::Generated
        );
        assert_eq!(
            classify_file_role("src/generated/types.ts"),
            EntityRole::Generated
        );
    }

    #[test]
    fn classify_docs_files() {
        assert_eq!(classify_file_role("docs/guide.md"), EntityRole::Docs);
        assert_eq!(classify_file_role("README.md"), EntityRole::Docs);
        assert_eq!(classify_file_role("doc/api.rst"), EntityRole::Docs);
    }

    // Relative indexing must derive entity/relation identity from the
    // root-relative path, never the machine-absolute path, so that the init and
    // reconcile paths agree and identical content produces identical IDs across
    // machines and checkout locations.

    const REL_RUST_SRC: &[u8] = b"pub struct Point { x: f64, y: f64 }\n\
impl Point { pub fn origin() -> Point { Point { x: 0.0, y: 0.0 } } }\n\
pub fn add(a: i32, b: i32) -> i32 { a + b }\n";

    fn write_repo_file(root: &Path, rel: &str, content: &[u8]) -> std::path::PathBuf {
        let abs = root.join(rel);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&abs, content).unwrap();
        abs
    }

    fn entity_id_set(indexed: &IndexedFile) -> std::collections::HashSet<kin_model::EntityId> {
        indexed.entities.iter().map(|e| e.id).collect()
    }

    fn relation_id_set(indexed: &IndexedFile) -> std::collections::HashSet<kin_model::RelationId> {
        indexed.relations.iter().map(|r| r.id).collect()
    }

    #[test]
    fn relative_index_derives_entity_ids_from_relative_path_not_absolute() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let blob_store = BlobStore::new(root.join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let abs = write_repo_file(root, "src/geo/point.rs", REL_RUST_SRC);
        let indexed = pipeline
            .index_file_relative(&abs, &blob_store, root)
            .unwrap();

        assert_eq!(indexed.file_id.0, "src/geo/point.rs");

        let mut checked = 0;
        for entity in &indexed.entities {
            let Some(span) = entity.span.as_ref() else {
                continue;
            };
            let relative = kin_model::EntityId::from_content(
                "src/geo/point.rs",
                &entity.name,
                &format!("{:?}", entity.kind),
                span.start_line,
            );
            let absolute = kin_model::EntityId::from_content(
                &abs.display().to_string(),
                &entity.name,
                &format!("{:?}", entity.kind),
                span.start_line,
            );
            assert_eq!(
                entity.id, relative,
                "entity {} is not addressed by its relative path",
                entity.name
            );
            assert_ne!(
                entity.id, absolute,
                "entity {} still bakes the machine-absolute path",
                entity.name
            );
            assert_eq!(entity.file_origin.as_ref().unwrap().0, "src/geo/point.rs");
            checked += 1;
        }
        assert!(checked >= 2, "expected at least two spanned entities");
    }

    #[test]
    fn relative_index_is_invariant_across_absolute_roots() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let blob_a = BlobStore::new(dir_a.path().join("blobs")).unwrap();
        let blob_b = BlobStore::new(dir_b.path().join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let abs_a = write_repo_file(dir_a.path(), "src/foo.rs", REL_RUST_SRC);
        let abs_b = write_repo_file(dir_b.path(), "src/foo.rs", REL_RUST_SRC);

        let a = pipeline
            .index_file_relative(&abs_a, &blob_a, dir_a.path())
            .unwrap();
        let b = pipeline
            .index_file_relative(&abs_b, &blob_b, dir_b.path())
            .unwrap();

        assert!(!a.entities.is_empty());
        assert_eq!(
            entity_id_set(&a),
            entity_id_set(&b),
            "entity IDs must not depend on the absolute checkout location"
        );
        assert_eq!(
            relation_id_set(&a),
            relation_id_set(&b),
            "relation IDs must not depend on the absolute checkout location"
        );
    }

    #[test]
    fn reconcile_relative_matches_init_content_ids() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let blob_store = BlobStore::new(root.join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let abs = write_repo_file(root, "src/foo.rs", REL_RUST_SRC);

        // reconcile path: absolute path on disk, normalized against the root.
        let reconcile = pipeline
            .index_file_relative(&abs, &blob_store, root)
            .unwrap();

        // init path: already-loaded content addressed by the relative file_id.
        let content = std::fs::read(&abs).unwrap();
        let blob_hash = blob_store.write(&content).unwrap();
        let init = pipeline
            .index_file_content_with_tests(&FilePathId::new("src/foo.rs"), &content, blob_hash)
            .unwrap()
            .indexed_file;

        assert_eq!(
            entity_id_set(&reconcile),
            entity_id_set(&init),
            "reconcile must produce the same entity IDs as init"
        );
        assert_eq!(
            relation_id_set(&reconcile),
            relation_id_set(&init),
            "reconcile must produce the same relation IDs as init"
        );
    }

    #[test]
    fn relative_index_relations_reference_local_entities() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let blob_store = BlobStore::new(root.join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let abs = write_repo_file(root, "src/foo.rs", REL_RUST_SRC);
        let indexed = pipeline
            .index_file_relative(&abs, &blob_store, root)
            .unwrap();

        let ids = entity_id_set(&indexed);
        for rel in &indexed.relations {
            if let kin_model::GraphNodeId::Entity(src) = &rel.src {
                assert!(
                    ids.contains(src),
                    "relation src {src:?} is not a local entity"
                );
            }
            if let kin_model::GraphNodeId::Entity(dst) = &rel.dst {
                assert!(
                    ids.contains(dst),
                    "relation dst {dst:?} is not a local entity"
                );
            }
        }
        for unresolved in &indexed.unresolved_relations {
            assert!(
                ids.contains(&unresolved.src_entity_id),
                "unresolved relation src {:?} is not a local entity",
                unresolved.src_entity_id
            );
        }
    }

    #[test]
    fn relative_hint_index_matches_non_hint_relative_ids() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let blob_store = BlobStore::new(root.join("blobs")).unwrap();
        let pipeline = IndexPipeline::new();

        let abs = write_repo_file(root, "src/foo.rs", REL_RUST_SRC);

        let full = pipeline
            .index_file_relative(&abs, &blob_store, root)
            .unwrap();
        let (hinted, _tree) = pipeline
            .index_file_relative_with_hint(&abs, &blob_store, root, None, None)
            .unwrap();

        assert_eq!(hinted.file_id.0, "src/foo.rs");
        assert_eq!(
            entity_id_set(&full),
            entity_id_set(&hinted),
            "incremental and full relative indexing must agree on entity IDs"
        );
    }
}
