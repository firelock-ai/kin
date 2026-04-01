// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::Path;

use tracing::debug;

use kin_blobs::BlobStore;
use kin_model::{
    Entity, FileLayout, FilePathId, GraphStore, Hash256, LanguageId, OpaqueArtifact,
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
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .ok_or_else(|| IndexError::UnsupportedFile(path.display().to_string()))?;

        let adapter = self
            .registry
            .get_by_extension(ext)
            .ok_or_else(|| IndexError::UnsupportedFile(ext.to_string()))?;

        let source =
            std::fs::read(path).map_err(|e| IndexError::io(path.display().to_string(), e))?;

        // Store the raw source as a blob
        let blob_hash = blob_store.write(&source)?;
        debug!(path = %path.display(), hash = %blob_hash, "stored source blob");

        let file_id = FilePathId::new(path.display().to_string());
        let language = adapter.language_id();

        // Parse
        let tree = adapter.parse(&source)?;
        let output = adapter.extract(&tree, &source, &file_id)?;

        // Convert extracted entities to model entities
        let mut entities: Vec<Entity> = output
            .entities
            .into_iter()
            .map(|e| e.into_entity_with_source(language, &file_id, Some(&source)))
            .collect();
        attach_file_context_metadata(&mut entities, &file_id, &output.imports);

        // Resolve extracted relations to model relations using entity name mapping
        let (relations, unresolved_relations) = resolve_relations(&output.relations, &entities);
        let file_layout = build_layout(
            &file_id,
            &entities,
            source.len(),
            &[],
            ParseCompleteness::from_parse_state(&output.parse_state),
        );

        debug!(
            path = %path.display(),
            entities = entities.len(),
            resolved_relations = relations.len(),
            unresolved_relations = unresolved_relations.len(),
            "indexed file"
        );

        Ok(IndexedFile {
            file_id,
            language,
            entities,
            relations,
            unresolved_relations,
            file_layout,
            parse_state: output.parse_state,
            blob_hash,
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
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .ok_or_else(|| IndexError::UnsupportedFile(path.display().to_string()))?;

        let adapter = self
            .registry
            .get_by_extension(ext)
            .ok_or_else(|| IndexError::UnsupportedFile(ext.to_string()))?;

        let source =
            std::fs::read(path).map_err(|e| IndexError::io(path.display().to_string(), e))?;

        // Store the raw source as a blob
        let blob_hash = blob_store.write(&source)?;
        debug!(path = %path.display(), hash = %blob_hash, "stored source blob");

        let file_id = FilePathId::new(path.display().to_string());
        let language = adapter.language_id();

        // Parse: incremental when hints are available, full otherwise
        let tree = match (old_tree, edit_hint) {
            (Some(old), Some(hint)) => {
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
        let output = adapter.extract(&tree, &source, &file_id)?;

        // Convert extracted entities to model entities
        let mut entities: Vec<Entity> = output
            .entities
            .into_iter()
            .map(|e| e.into_entity_with_source(language, &file_id, Some(&source)))
            .collect();
        attach_file_context_metadata(&mut entities, &file_id, &output.imports);

        // Resolve extracted relations to model relations using entity name mapping
        let (relations, unresolved_relations) = resolve_relations(&output.relations, &entities);
        let file_layout = build_layout(
            &file_id,
            &entities,
            source.len(),
            &[],
            ParseCompleteness::from_parse_state(&output.parse_state),
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
            IndexedFile {
                file_id,
                language,
                entities,
                relations,
                unresolved_relations,
                file_layout,
                parse_state: output.parse_state,
                blob_hash,
            },
            tree,
        ))
    }

    /// Index a file with hint, normalizing its `FilePathId` relative to the given root.
    ///
    /// Same as `index_file_with_hint` but strips the `root` prefix from the
    /// file path for a stable cross-platform `FilePathId`.
    pub fn index_file_relative_with_hint(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        root: &Path,
        old_tree: Option<&tree_sitter::Tree>,
        edit_hint: Option<&kin_parser::EditHint>,
    ) -> Result<(IndexedFile, tree_sitter::Tree)> {
        let (mut indexed, tree) =
            self.index_file_with_hint(path, blob_store, old_tree, edit_hint)?;
        let normalized = normalize_file_path_id(path, root);
        indexed.file_id = normalized.clone();
        indexed.file_layout.file_id = normalized.clone();
        for entity in &mut indexed.entities {
            entity.file_origin = Some(normalized.clone());
            if let Some(ref mut span) = entity.span {
                span.file = normalized.clone();
            }
        }
        Ok((indexed, tree))
    }

    /// Index a file, normalizing its `FilePathId` relative to the given root.
    ///
    /// This strips the `root` prefix from the file path and normalizes path
    /// separators to forward slashes, producing a stable cross-platform
    /// `FilePathId` regardless of whether the caller passes an absolute or
    /// relative path.
    pub fn index_file_relative(
        &self,
        path: &Path,
        blob_store: &BlobStore,
        root: &Path,
    ) -> Result<IndexedFile> {
        let mut indexed = self.index_file(path, blob_store)?;
        let normalized = normalize_file_path_id(path, root);
        // Re-assign file_id and file_origin on all entities.
        indexed.file_id = normalized.clone();
        indexed.file_layout.file_id = normalized.clone();
        for entity in &mut indexed.entities {
            entity.file_origin = Some(normalized.clone());
            if let Some(ref mut span) = entity.span {
                span.file = normalized.clone();
            }
        }
        Ok(indexed)
    }

    /// Index any file by classifying it first, then routing to the right handler.
    ///
    /// - EntitySource files go through the tree-sitter parser pipeline.
    /// - StructuredArtifact files go through the artifact extractor.
    /// - OpaqueArtifact files are stored as blobs with an optional MIME hint.
    pub fn index_any_file(&self, path: &Path, blob_store: &BlobStore) -> Result<IndexedAny> {
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
                    id: RelationId::new(),
                    kind: rel.kind,
                    src: kin_model::GraphNodeId::Entity(s.id),
                    dst: kin_model::GraphNodeId::Entity(d.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: rel.import_source.clone(),
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
        assert_eq!(result.entities.len(), 1);
        assert_eq!(result.entities[0].name, "greet");
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
}
