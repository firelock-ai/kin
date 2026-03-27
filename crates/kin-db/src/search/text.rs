// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::PathBuf;

use parking_lot::RwLock;
use tantivy::collector::TopDocs;
use tantivy::directory::MmapDirectory;
use tantivy::query::QueryParser;
use tantivy::schema::Value;
use tantivy::schema::{Field, Schema, STORED, STRING, TEXT};
use tantivy::{doc, Index, IndexWriter, ReloadPolicy};

use crate::error::KinDbError;
use crate::types::{Entity, EntityId};

struct TextIndexInner {
    index: Index,
    writer: IndexWriter,
    reader: tantivy::IndexReader,
    // Schema fields
    f_id: Field,
    f_name: Field,
    f_signature: Field,
    f_file_path: Field,
    f_kind: Field,
    // Entity ID mapping: tantivy stores the UUID string, we parse it back
}

/// Full-text search index over entity names, signatures, and file paths.
///
/// Uses tantivy with either a persistent MmapDirectory (for production) or
/// an in-memory RAM directory (for tests). Persistent mode avoids full
/// index rebuilds on cold start.
pub struct TextIndex {
    inner: RwLock<TextIndexInner>,
    schema: Schema,
}

impl TextIndex {
    /// Create a new in-memory text search index (for tests and ephemeral use).
    pub fn new() -> Result<Self, KinDbError> {
        Self::open(None)
    }

    /// Open or create a text search index.
    ///
    /// - `Some(path)` → persistent MmapDirectory at the given path.
    ///   If the directory already contains a valid index, it is reopened.
    ///   If the directory is empty or corrupt, a fresh index is created.
    /// - `None` → in-memory RAM directory (for tests).
    pub fn open(path: Option<&PathBuf>) -> Result<Self, KinDbError> {
        let mut schema_builder = Schema::builder();
        let f_id = schema_builder.add_text_field("id", STRING | STORED);
        let f_name = schema_builder.add_text_field("name", TEXT | STORED);
        let f_signature = schema_builder.add_text_field("signature", TEXT);
        let f_file_path = schema_builder.add_text_field("file_path", TEXT | STORED);
        let f_kind = schema_builder.add_text_field("kind", TEXT | STORED);
        let schema = schema_builder.build();

        let index = match path {
            Some(dir) => {
                std::fs::create_dir_all(dir).map_err(|e| {
                    KinDbError::IndexError(format!(
                        "failed to create text index directory {}: {e}",
                        dir.display()
                    ))
                })?;
                let mmap_dir = MmapDirectory::open(dir).map_err(|e| {
                    KinDbError::IndexError(format!(
                        "failed to open MmapDirectory at {}: {e}",
                        dir.display()
                    ))
                })?;
                Index::open_or_create(mmap_dir, schema.clone()).map_err(|e| {
                    KinDbError::IndexError(format!(
                        "failed to open or create persistent text index at {}: {e}",
                        dir.display()
                    ))
                })?
            }
            None => Index::create_in_ram(schema.clone()),
        };

        let writer = index
            .writer(15_000_000)
            .map_err(|e| KinDbError::IndexError(format!("failed to create tantivy writer: {e}")))?;

        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()
            .map_err(|e| KinDbError::IndexError(format!("failed to create reader: {e}")))?;

        Ok(Self {
            inner: RwLock::new(TextIndexInner {
                index,
                writer,
                reader,
                f_id,
                f_name,
                f_signature,
                f_file_path,
                f_kind,
            }),
            schema,
        })
    }

    /// Index or re-index an entity for text search.
    pub fn upsert(&self, entity: &Entity) -> Result<(), KinDbError> {
        let inner = self.inner.write();

        // Delete old doc if it exists (by entity ID term)
        let id_str = entity.id.0.to_string();
        let id_term = tantivy::Term::from_field_text(inner.f_id, &id_str);
        inner.writer.delete_term(id_term);

        let file_path = entity
            .file_origin
            .as_ref()
            .map(|f| f.0.as_str())
            .unwrap_or("");

        let kind_str = format!("{:?}", entity.kind);

        inner
            .writer
            .add_document(doc!(
                inner.f_id => id_str,
                inner.f_name => entity.name.as_str(),
                inner.f_signature => entity.signature.as_str(),
                inner.f_file_path => file_path,
                inner.f_kind => kind_str.as_str(),
            ))
            .map_err(|e| KinDbError::IndexError(format!("failed to add document: {e}")))?;

        Ok(())
    }

    /// Remove an entity from the text index.
    pub fn remove(&self, entity_id: &EntityId) -> Result<(), KinDbError> {
        let inner = self.inner.write();
        let id_str = entity_id.0.to_string();
        let id_term = tantivy::Term::from_field_text(inner.f_id, &id_str);
        inner.writer.delete_term(id_term);
        Ok(())
    }

    /// Commit all pending writes and reload the reader.
    ///
    /// Call this after bulk operations (e.g., `from_snapshot()`) rather than
    /// committing per entity.
    pub fn commit(&self) -> Result<(), KinDbError> {
        let mut inner = self.inner.write();
        inner
            .writer
            .commit()
            .map_err(|e| KinDbError::IndexError(format!("failed to commit: {e}")))?;
        inner
            .reader
            .reload()
            .map_err(|e| KinDbError::IndexError(format!("failed to reload reader: {e}")))?;
        Ok(())
    }

    /// Fuzzy search across entity names, signatures, and file paths.
    ///
    /// Returns up to `limit` matching entity IDs with their search scores.
    pub fn fuzzy_search(
        &self,
        query_str: &str,
        limit: usize,
    ) -> Result<Vec<(EntityId, f32)>, KinDbError> {
        let inner = self.inner.read();

        let searcher = inner.reader.searcher();
        let query_parser = QueryParser::for_index(
            &inner.index,
            vec![inner.f_name, inner.f_signature, inner.f_file_path],
        );

        let query = query_parser.parse_query(query_str).map_err(|e| {
            KinDbError::IndexError(format!("failed to parse query '{query_str}': {e}"))
        })?;

        let top_docs: Vec<(f32, tantivy::DocAddress)> = searcher
            .search(&query, &TopDocs::with_limit(limit))
            .map_err(|e| KinDbError::IndexError(format!("search failed: {e}")))?;

        let mut results = Vec::with_capacity(top_docs.len());
        for (score, doc_address) in top_docs {
            let doc = searcher
                .doc::<tantivy::TantivyDocument>(doc_address)
                .map_err(|e| KinDbError::IndexError(format!("failed to retrieve doc: {e}")))?;

            if let Some(id_value) = doc.get_first(inner.f_id) {
                if let Some(id_str) = id_value.as_str() {
                    if let Ok(uuid) = uuid::Uuid::parse_str(id_str) {
                        results.push((EntityId(uuid), score));
                    }
                }
            }
        }

        Ok(results)
    }
}

impl std::fmt::Debug for TextIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextIndex")
            .field("fields", &self.schema.num_fields())
            .finish()
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
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
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
        assert_eq!(results[0].0, id1);
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
        assert_eq!(results[0].0, id1);
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
        let mut e1 = make_entity("oldName", "src/lib.rs", EntityKind::Function);
        let id1 = e1.id;

        idx.upsert(&e1).unwrap();
        idx.commit().unwrap();

        // Update name
        e1.name = "newName".to_string();
        e1.signature = "fn newName()".to_string();
        idx.upsert(&e1).unwrap();
        idx.commit().unwrap();

        // Old name should not find it
        let results = idx.fuzzy_search("oldName", 10).unwrap();
        assert!(results.is_empty());

        // New name should
        let results = idx.fuzzy_search("newName", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, id1);
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
        let e1 = make_entity("persistMe", "src/persist.rs", EntityKind::Function);
        let id1 = e1.id;

        // Create index, write, commit, then drop
        {
            let idx = TextIndex::open(Some(&path)).unwrap();
            idx.upsert(&e1).unwrap();
            idx.commit().unwrap();

            let results = idx.fuzzy_search("persistMe", 10).unwrap();
            assert!(!results.is_empty());
        }

        // Reopen from same path — data should survive
        {
            let idx = TextIndex::open(Some(&path)).unwrap();
            let results = idx.fuzzy_search("persistMe", 10).unwrap();
            assert!(!results.is_empty());
            assert_eq!(results[0].0, id1);
        }
    }
}
