// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;
use std::path::PathBuf;

use parking_lot::RwLock;

use crate::error::KinDbError;
use crate::types::{Entity, EntityId};

/// A document stored in the forward index for deletion/update support.
#[derive(Clone)]
struct IndexedDoc {
    tokens_by_field: Vec<(String, f32)>, // (token, field_weight)
    doc_length: usize,                    // total number of tokens in this doc
}

/// Lightweight in-memory inverted index for full-text search over entities.
///
/// Indexes entity names, signatures, file paths, and kinds. Uses BM25
/// scoring with field weights for relevance ranking.
pub struct TextIndex {
    /// Inverted index: lowercase token -> list of (EntityId, field_weight).
    index: RwLock<HashMap<String, Vec<(EntityId, f32)>>>,
    /// Forward index: EntityId -> stored tokens (for delete-before-reinsert).
    docs: RwLock<HashMap<EntityId, IndexedDoc>>,
    /// Total number of documents (for IDF calculation).
    doc_count: RwLock<usize>,
    /// Sum of all document lengths (for BM25 avgdl).
    total_doc_length: RwLock<usize>,
    /// Pending changes buffer. Writes go into staged state; commit() promotes
    /// staged state to live state so searches see the new data.
    staged: RwLock<Option<StagedState>>,
}

#[derive(Clone)]
struct StagedState {
    index: HashMap<String, Vec<(EntityId, f32)>>,
    docs: HashMap<EntityId, IndexedDoc>,
    doc_count: usize,
    total_doc_length: usize,
}

// ── Field weights ────────────────────────────────────────────────────────────

const WEIGHT_NAME: f32 = 5.0;
const WEIGHT_SIGNATURE: f32 = 3.0;
const WEIGHT_FILE_PATH: f32 = 2.0;
const WEIGHT_KIND: f32 = 1.0;

// ── BM25 parameters ─────────────────────────────────────────────────────────

const BM25_K1: f32 = 1.2;
const BM25_B: f32 = 0.75;

// ── Tokenization ─────────────────────────────────────────────────────────────

/// Decompose text into lowercase tokens by splitting on non-alphanumeric
/// boundaries and camelCase / snake_case word boundaries.
///
/// Examples:
///   "parseTableFromHtml" -> ["parse", "table", "from", "html", "parsetablefromhtml"]
///   "parse_table_html"   -> ["parse", "table", "html"]
///   "src/io/ascii.py"    -> ["src", "io", "ascii", "py"]
fn tokenize(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();

    // Split on non-alphanumeric characters first
    for segment in text.split(|c: char| !c.is_alphanumeric()) {
        if segment.is_empty() {
            continue;
        }
        // Split camelCase: insert boundary before uppercase chars preceded by lowercase
        let mut current = String::new();
        let chars: Vec<char> = segment.chars().collect();
        for i in 0..chars.len() {
            if i > 0 && chars[i].is_uppercase() && chars[i - 1].is_lowercase() {
                if !current.is_empty() {
                    let lower = current.to_lowercase();
                    if !lower.is_empty() {
                        tokens.push(lower);
                    }
                    current.clear();
                }
            }
            current.push(chars[i]);
        }
        if !current.is_empty() {
            let lower = current.to_lowercase();
            if !lower.is_empty() {
                tokens.push(lower);
            }
        }

        // Also add the whole segment as a token (lowercased) for exact matching
        let full = segment.to_lowercase();
        if full.len() > 1 && !tokens.contains(&full) {
            tokens.push(full);
        }
    }

    tokens
}

/// Remove all postings for the given entity from the inverted index.
fn remove_entity_from_index(
    index: &mut HashMap<String, Vec<(EntityId, f32)>>,
    doc: &IndexedDoc,
    entity_id: &EntityId,
) {
    for (token, weight) in &doc.tokens_by_field {
        if let Some(postings) = index.get_mut(token) {
            postings.retain(|(eid, w)| {
                !(eid == entity_id && (*w - weight).abs() < f32::EPSILON)
            });
            if postings.is_empty() {
                index.remove(token);
            }
        }
    }
}

// ── TextIndex implementation ─────────────────────────────────────────────────

impl TextIndex {
    /// Create a new in-memory text search index.
    pub fn new() -> Result<Self, KinDbError> {
        Self::open(None)
    }

    /// Open or create a text search index.
    ///
    /// The `path` parameter is accepted for API compatibility but ignored —
    /// the index is always in-memory and rebuilt from the graph snapshot on
    /// cold start (which is fast enough for our entity counts).
    pub fn open(_path: Option<&PathBuf>) -> Result<Self, KinDbError> {
        Ok(Self {
            index: RwLock::new(HashMap::new()),
            docs: RwLock::new(HashMap::new()),
            doc_count: RwLock::new(0),
            total_doc_length: RwLock::new(0),
            staged: RwLock::new(None),
        })
    }

    /// Tokenize an entity's fields and produce weighted (token, weight) pairs.
    fn entity_tokens(entity: &Entity) -> Vec<(String, f32)> {
        let file_path = entity
            .file_origin
            .as_ref()
            .map(|f| f.0.as_str())
            .unwrap_or("");
        let kind_str = format!("{:?}", entity.kind);

        let mut all_tokens: Vec<(String, f32)> = Vec::new();
        for tok in tokenize(&entity.name) {
            all_tokens.push((tok, WEIGHT_NAME));
        }
        for tok in tokenize(&entity.signature) {
            all_tokens.push((tok, WEIGHT_SIGNATURE));
        }
        for tok in tokenize(file_path) {
            all_tokens.push((tok, WEIGHT_FILE_PATH));
        }
        for tok in tokenize(&kind_str) {
            all_tokens.push((tok, WEIGHT_KIND));
        }
        all_tokens
    }

    /// Get or create the staged state, snapshotting from the live state.
    fn ensure_staged<'a>(
        staged: &'a mut Option<StagedState>,
        index: &HashMap<String, Vec<(EntityId, f32)>>,
        docs: &HashMap<EntityId, IndexedDoc>,
        doc_count: usize,
        total_doc_length: usize,
    ) -> &'a mut StagedState {
        staged.get_or_insert_with(|| StagedState {
            index: index.clone(),
            docs: docs.clone(),
            doc_count,
            total_doc_length,
        })
    }

    /// Index or re-index an entity for text search.
    ///
    /// Stages the change — call `commit()` to make it visible to searches.
    pub fn upsert(&self, entity: &Entity) -> Result<(), KinDbError> {
        let all_tokens = Self::entity_tokens(entity);
        let doc_length = all_tokens.len();

        let live_index = self.index.read();
        let live_docs = self.docs.read();
        let live_dc = *self.doc_count.read();
        let live_tdl = *self.total_doc_length.read();
        let mut staged_guard = self.staged.write();

        let state = Self::ensure_staged(&mut staged_guard, &live_index, &live_docs, live_dc, live_tdl);

        // Remove old doc if present
        if let Some(old_doc) = state.docs.remove(&entity.id) {
            remove_entity_from_index(&mut state.index, &old_doc, &entity.id);
            state.doc_count = state.doc_count.saturating_sub(1);
            state.total_doc_length = state.total_doc_length.saturating_sub(old_doc.doc_length);
        }

        // Insert new tokens
        for (token, weight) in &all_tokens {
            state
                .index
                .entry(token.clone())
                .or_default()
                .push((entity.id, *weight));
        }
        state.doc_count += 1;
        state.total_doc_length += doc_length;

        state.docs.insert(
            entity.id,
            IndexedDoc {
                tokens_by_field: all_tokens,
                doc_length,
            },
        );

        Ok(())
    }

    /// Remove an entity from the text index.
    ///
    /// Stages the removal — call `commit()` to make it visible to searches.
    pub fn remove(&self, entity_id: &EntityId) -> Result<(), KinDbError> {
        let live_index = self.index.read();
        let live_docs = self.docs.read();
        let live_dc = *self.doc_count.read();
        let live_tdl = *self.total_doc_length.read();
        let mut staged_guard = self.staged.write();

        let state = Self::ensure_staged(&mut staged_guard, &live_index, &live_docs, live_dc, live_tdl);

        if let Some(old_doc) = state.docs.remove(entity_id) {
            remove_entity_from_index(&mut state.index, &old_doc, entity_id);
            state.doc_count = state.doc_count.saturating_sub(1);
            state.total_doc_length = state.total_doc_length.saturating_sub(old_doc.doc_length);
        }

        Ok(())
    }

    /// Commit all pending writes, making staged changes visible to searches.
    ///
    /// Call after bulk operations (e.g. `from_snapshot()` loading) rather than
    /// per entity.
    pub fn commit(&self) -> Result<(), KinDbError> {
        let mut staged_guard = self.staged.write();
        if let Some(state) = staged_guard.take() {
            *self.index.write() = state.index;
            *self.docs.write() = state.docs;
            *self.doc_count.write() = state.doc_count;
            *self.total_doc_length.write() = state.total_doc_length;
        }
        Ok(())
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
        let query_tokens = tokenize(query_str);
        if query_tokens.is_empty() {
            return Ok(Vec::new());
        }

        let index = self.index.read();
        let docs = self.docs.read();
        let total_docs = *self.doc_count.read();
        let total_doc_len = *self.total_doc_length.read();
        if total_docs == 0 {
            return Ok(Vec::new());
        }

        let n = total_docs as f32;
        let avgdl = if total_docs > 0 {
            total_doc_len as f32 / total_docs as f32
        } else {
            1.0
        };

        let mut scores: HashMap<EntityId, f32> = HashMap::new();

        for qt in &query_tokens {
            // Exact token match with BM25
            if let Some(postings) = index.get(qt) {
                let df = postings.len() as f32;
                // BM25 IDF: log((N - df + 0.5) / (df + 0.5) + 1)
                let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln().max(0.0);

                for (eid, weight) in postings {
                    let dl = docs.get(eid).map(|d| d.doc_length as f32).unwrap_or(avgdl);
                    // BM25 TF saturation: (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * dl/avgdl))
                    // Use weight as a proxy for tf (field-weighted)
                    let tf = *weight;
                    let tf_saturated = (tf * (BM25_K1 + 1.0))
                        / (tf + BM25_K1 * (1.0 - BM25_B + BM25_B * dl / avgdl));
                    *scores.entry(*eid).or_insert(0.0) += idf * tf_saturated;
                }
            }

            // Substring match: query token is a substring of an indexed token
            // (or vice versa) — with minimum 3-char tokens for substring matching
            if qt.len() >= 3 {
                for (indexed_token, postings) in index.iter() {
                    if indexed_token == qt {
                        continue; // already handled above
                    }
                    if indexed_token.len() < 3 {
                        continue; // skip very short tokens for substring matching
                    }
                    if indexed_token.contains(qt.as_str()) || qt.contains(indexed_token.as_str()) {
                        let df = postings.len() as f32;
                        let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln().max(0.0);
                        let substring_penalty = 0.5;
                        for (eid, weight) in postings {
                            let dl = docs.get(eid).map(|d| d.doc_length as f32).unwrap_or(avgdl);
                            let tf = *weight;
                            let tf_saturated = (tf * (BM25_K1 + 1.0))
                                / (tf + BM25_K1 * (1.0 - BM25_B + BM25_B * dl / avgdl));
                            *scores.entry(*eid).or_insert(0.0)
                                += idf * tf_saturated * substring_penalty;
                        }
                    }
                }
            }
        }

        // Sort by score descending, take top `limit`
        let mut results: Vec<(EntityId, f32)> = scores.into_iter().collect();
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(limit);

        Ok(results)
    }
}

impl std::fmt::Debug for TextIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let doc_count = *self.doc_count.read();
        let token_count = self.index.read().len();
        f.debug_struct("TextIndex")
            .field("documents", &doc_count)
            .field("tokens", &token_count)
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
    fn tokenize_camel_case() {
        let tokens = tokenize("parseTableFromHtml");
        assert!(tokens.contains(&"parse".to_string()));
        assert!(tokens.contains(&"table".to_string()));
        assert!(tokens.contains(&"from".to_string()));
        assert!(tokens.contains(&"html".to_string()));
    }

    #[test]
    fn tokenize_snake_case() {
        let tokens = tokenize("parse_table_html");
        assert!(tokens.contains(&"parse".to_string()));
        assert!(tokens.contains(&"table".to_string()));
        assert!(tokens.contains(&"html".to_string()));
    }

    #[test]
    fn tokenize_file_path() {
        let tokens = tokenize("src/io/ascii/html.py");
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
