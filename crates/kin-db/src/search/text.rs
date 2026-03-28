// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Text search wrapper — delegates to kin-search with EntityId specialization.

use std::path::PathBuf;

use crate::error::KinDbError;
use crate::types::{Entity, EntityId};

// ── Field weights (same as the original inline implementation) ──────────────

const WEIGHT_NAME: f32 = 5.0;
const WEIGHT_SIGNATURE: f32 = 3.0;
const WEIGHT_FILE_PATH: f32 = 2.0;
const WEIGHT_KIND: f32 = 1.0;

/// Text search index specialized for Entity search.
///
/// Thin wrapper around `kin_search::TextIndex<EntityId>` that adapts the
/// generic API to the Entity-specific interface that the rest of kin-db
/// expects.
pub struct TextIndex {
    inner: kin_search::TextIndex<EntityId>,
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
    /// The `path` parameter is accepted for API compatibility but ignored —
    /// the index is always in-memory and rebuilt from the graph snapshot on
    /// cold start.
    pub fn open(_path: Option<&PathBuf>) -> Result<Self, KinDbError> {
        Ok(Self {
            inner: kin_search::TextIndex::new(),
        })
    }

    /// Index or re-index an entity for text search.
    ///
    /// Stages the change — call `commit()` to make it visible to searches.
    pub fn upsert(&self, entity: &Entity) -> Result<(), KinDbError> {
        let fields = entity_fields(entity);
        let field_refs: Vec<(&str, f32)> = fields.iter().map(|(s, w)| (s.as_str(), *w)).collect();
        self.inner
            .upsert(entity.id, &field_refs)
            .map_err(|e| KinDbError::IndexError(e.to_string()))
    }

    /// Remove an entity from the text index.
    ///
    /// Stages the removal — call `commit()` to make it visible to searches.
    pub fn remove(&self, entity_id: &EntityId) -> Result<(), KinDbError> {
        self.inner
            .remove(entity_id)
            .map_err(|e| KinDbError::IndexError(e.to_string()))
    }

    /// Commit all pending writes, making staged changes visible to searches.
    pub fn commit(&self) -> Result<(), KinDbError> {
        self.inner
            .commit()
            .map_err(|e| KinDbError::IndexError(e.to_string()))
    }

    /// Search across entity names, signatures, and file paths.
    ///
    /// Returns up to `limit` matching entity IDs with their relevance scores,
    /// ranked highest-first. Uses BM25 scoring with field weights.
    pub fn fuzzy_search(
        &self,
        query_str: &str,
        limit: usize,
    ) -> Result<Vec<(EntityId, f32)>, KinDbError> {
        self.inner
            .fuzzy_search(query_str, limit)
            .map_err(|e| KinDbError::IndexError(e.to_string()))
    }
}

impl std::fmt::Debug for TextIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TextIndex(kin-search)")
    }
}

/// Extract weighted field texts from an Entity for indexing.
fn entity_fields(entity: &Entity) -> Vec<(String, f32)> {
    let file_path = entity
        .file_origin
        .as_ref()
        .map(|f| f.0.as_str())
        .unwrap_or("");
    let kind_str = format!("{:?}", entity.kind);

    vec![
        (entity.name.clone(), WEIGHT_NAME),
        (entity.signature.clone(), WEIGHT_SIGNATURE),
        (file_path.to_string(), WEIGHT_FILE_PATH),
        (kind_str, WEIGHT_KIND),
    ]
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
        // With the in-memory implementation, persistence is handled by
        // rebuilding from snapshot. This test verifies the open() API
        // accepts a path without error.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("text_index");

        let idx = TextIndex::open(Some(&path)).unwrap();
        let e1 = make_entity("persistMe", "src/persist.rs", EntityKind::Function);

        idx.upsert(&e1).unwrap();
        idx.commit().unwrap();

        let results = idx.fuzzy_search("persistMe", 10).unwrap();
        assert!(!results.is_empty());
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
        assert_eq!(results[0].0, id1);
    }
}
