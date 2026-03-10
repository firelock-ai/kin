use std::path::Path;

use tracing::debug;

use kin_blobs::BlobStore;
use kin_model::{
    Entity, FilePathId, GraphStore, LanguageId, ParseState, Relation, RelationId, RelationOrigin,
};
use kin_parser::AdapterRegistry;

use crate::error::{IndexError, Result};

/// Result of indexing a single file.
#[derive(Debug)]
pub struct IndexedFile {
    pub file_id: FilePathId,
    pub language: LanguageId,
    pub entities: Vec<Entity>,
    pub relations: Vec<Relation>,
    pub parse_state: ParseState,
    pub blob_hash: kin_blobs::Hash256,
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
    pub fn index_file(
        &self,
        path: &Path,
        blob_store: &BlobStore,
    ) -> Result<IndexedFile> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .ok_or_else(|| IndexError::UnsupportedFile(path.display().to_string()))?;

        let adapter = self
            .registry
            .get_by_extension(ext)
            .ok_or_else(|| IndexError::UnsupportedFile(ext.to_string()))?;

        let source = std::fs::read(path).map_err(|e| IndexError::io(path.display().to_string(), e))?;

        // Store the raw source as a blob
        let blob_hash = blob_store.write(&source)?;
        debug!(path = %path.display(), hash = %blob_hash, "stored source blob");

        let file_id = FilePathId::new(path.display().to_string());
        let language = adapter.language_id();

        // Parse
        let tree = adapter.parse(&source)?;
        let output = adapter.extract(&tree, &source, &file_id)?;

        // Convert extracted entities to model entities
        let entities: Vec<Entity> = output
            .entities
            .into_iter()
            .map(|e| e.into_entity(language, &file_id))
            .collect();

        // Resolve extracted relations to model relations using entity name mapping
        let relations = resolve_relations(&output.relations, &entities);

        debug!(
            path = %path.display(),
            entities = entities.len(),
            relations = relations.len(),
            "indexed file"
        );

        Ok(IndexedFile {
            file_id,
            language,
            entities,
            relations,
            parse_state: output.parse_state,
            blob_hash,
        })
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

/// Resolve extracted name-based relations to entity-ID-based relations.
fn resolve_relations(
    extracted: &[kin_parser::ExtractedRelation],
    entities: &[Entity],
) -> Vec<Relation> {
    let mut relations = Vec::new();
    for rel in extracted {
        let src = entities.iter().find(|e| e.name == rel.src_name);
        let dst = entities.iter().find(|e| e.name == rel.dst_name);

        match (src, dst) {
            (Some(s), Some(d)) => {
                relations.push(Relation {
                    id: RelationId::new(),
                    kind: rel.kind,
                    src: s.id,
                    dst: d.id,
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                });
            }
            _ => {
                // Cross-file or unresolved relations are skipped for now;
                // they'll be resolved during the reconciliation phase.
                debug!(
                    src = %rel.src_name,
                    dst = %rel.dst_name,
                    kind = ?rel.kind,
                    "unresolved relation, deferring to reconciliation"
                );
            }
        }
    }
    relations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_pipeline_creates() {
        let pipeline = IndexPipeline::new();
        let langs = pipeline.registry().supported_languages();
        assert_eq!(langs.len(), 6);
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
