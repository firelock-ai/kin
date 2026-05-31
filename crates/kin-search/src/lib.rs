// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::path::{Path, PathBuf};

use parking_lot::RwLock;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SearchError {
    #[error("search error: {0}")]
    IndexError(String),
}

// ── DocId trait ─────────────────────────────────────────────────────────────

/// Trait bound for document IDs used as keys in the index.
///
/// Blanket-implemented for any type that meets the bounds, so you never need
/// to impl this manually — just use `u64`, `Uuid`, or your own newtype.
pub trait DocId: Copy + Eq + Hash + Send + Sync + fmt::Debug + 'static {}

/// Blanket implementation: anything that meets the bounds is a DocId.
impl<T: Copy + Eq + Hash + Send + Sync + fmt::Debug + 'static> DocId for T {}

// ── Searchable trait ────────────────────────────────────────────────────────

/// A document that can be indexed for text search.
///
/// Implement this for your types to use the convenience `upsert_searchable()`
/// method. Each field text is paired with a weight that controls how much
/// matches in that field contribute to the relevance score.
///
/// # Example
///
/// ```ignore
/// impl Searchable for CodeEntity {
///     fn search_fields(&self) -> Vec<(&str, f32)> {
///         vec![
///             (&self.name, 5.0),       // name matches weighted highest
///             (&self.signature, 3.0),  // signature matches
///             (&self.file_path, 2.0),  // file path matches
///         ]
///     }
/// }
/// ```
pub trait Searchable {
    /// Produce weighted (field_text, weight) pairs for indexing.
    fn search_fields(&self) -> Vec<(&str, f32)>;
}

// ── Internal types ──────────────────────────────────────────────────────────

/// A document stored in the forward index for deletion/update support.
#[derive(Clone, Serialize, Deserialize)]
struct IndexedDoc {
    tokens_by_field: Vec<(String, f32)>, // (token, field_weight)
    doc_length: usize,                   // total number of tokens in this doc
}

#[derive(Clone, Serialize, Deserialize)]
struct StagedState<Id: DocId> {
    index: HashMap<String, Vec<(Id, f32)>>,
    docs: HashMap<Id, IndexedDoc>,
    doc_count: usize,
    total_doc_length: usize,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistedIndex<Id: DocId> {
    version: u32,
    index: HashMap<String, Vec<(Id, f32)>>,
    docs: HashMap<Id, IndexedDoc>,
    doc_count: usize,
    total_doc_length: usize,
    graph_root_hash: Option<[u8; 32]>,
}

#[derive(Serialize)]
struct PersistedIndexRef<'a, Id: DocId> {
    version: u32,
    index: &'a HashMap<String, Vec<(Id, f32)>>,
    docs: &'a HashMap<Id, IndexedDoc>,
    doc_count: usize,
    total_doc_length: usize,
    graph_root_hash: Option<[u8; 32]>,
}

pub const TEXT_INDEX_FORMAT_VERSION: u32 = 1;

impl<Id: DocId> PersistedIndex<Id> {
    const VERSION: u32 = TEXT_INDEX_FORMAT_VERSION;
}

// ── BM25 parameters ────────────────────────────────────────────────────────

const BM25_K1: f32 = 1.2;
const BM25_B: f32 = 0.75;

// ── Tokenization ────────────────────────────────────────────────────────────

/// Decompose text into lowercase tokens by splitting on non-alphanumeric
/// boundaries and camelCase / snake_case word boundaries.
///
/// # Examples
///
/// ```
/// # use kin_search::tokenize;
/// let tokens = tokenize("parseTableFromHtml");
/// assert!(tokens.contains(&"parse".to_string()));
/// assert!(tokens.contains(&"table".to_string()));
/// assert!(tokens.contains(&"from".to_string()));
/// assert!(tokens.contains(&"html".to_string()));
/// assert!(tokens.contains(&"parsetablefromhtml".to_string()));
/// ```
///
/// ```
/// # use kin_search::tokenize;
/// let tokens = tokenize("src/io/ascii.py");
/// assert!(tokens.contains(&"src".to_string()));
/// assert!(tokens.contains(&"io".to_string()));
/// assert!(tokens.contains(&"ascii".to_string()));
/// assert!(tokens.contains(&"py".to_string()));
/// ```
pub fn tokenize(text: &str) -> Vec<String> {
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

// ── Helper ──────────────────────────────────────────────────────────────────

/// Remove all postings for the given document from the inverted index.
fn remove_doc_from_index<Id: DocId>(
    index: &mut HashMap<String, Vec<(Id, f32)>>,
    doc: &IndexedDoc,
    doc_id: &Id,
) {
    for (token, weight) in &doc.tokens_by_field {
        if let Some(postings) = index.get_mut(token) {
            postings.retain(|(eid, w)| !(eid == doc_id && (*w - weight).abs() < f32::EPSILON));
            if postings.is_empty() {
                index.remove(token);
            }
        }
    }
}

// ── TextIndex ───────────────────────────────────────────────────────────────

/// Lightweight in-memory inverted index for full-text search.
///
/// Uses BM25 scoring with field weights for relevance ranking. Generic over
/// the document ID type — use any `Copy + Eq + Hash + Send + Sync + Debug`
/// type as your key.
///
/// Writes are staged: call [`upsert`](Self::upsert) or
/// [`upsert_searchable`](Self::upsert_searchable) to stage changes, then
/// [`commit`](Self::commit) to make them visible to searches.
pub struct TextIndex<Id: DocId = u64> {
    /// Inverted index: lowercase token -> list of (Id, field_weight).
    index: RwLock<HashMap<String, Vec<(Id, f32)>>>,
    /// Forward index: Id -> stored tokens (for delete-before-reinsert).
    docs: RwLock<HashMap<Id, IndexedDoc>>,
    /// Total number of documents (for IDF calculation).
    doc_count: RwLock<usize>,
    /// Sum of all document lengths (for BM25 avgdl).
    total_doc_length: RwLock<usize>,
    /// Pending changes buffer. Writes go into staged state; commit() promotes
    /// staged state to live state so searches see the new data.
    staged: RwLock<Option<StagedState<Id>>>,
    /// Optional on-disk storage path for the persisted index.
    path: Option<PathBuf>,
    /// Optional graph-root hash stamp used to validate this index against
    /// the persisted graph snapshot.
    graph_root_hash: RwLock<Option<[u8; 32]>>,
}

impl<Id: DocId> TextIndex<Id> {
    /// Create a new in-memory text search index.
    pub fn new() -> Self {
        Self {
            index: RwLock::new(HashMap::new()),
            docs: RwLock::new(HashMap::new()),
            doc_count: RwLock::new(0),
            total_doc_length: RwLock::new(0),
            staged: RwLock::new(None),
            path: None,
            graph_root_hash: RwLock::new(None),
        }
    }

    /// Get or create the staged state, snapshotting from the live state.
    fn ensure_staged<'a>(
        staged: &'a mut Option<StagedState<Id>>,
        index: &HashMap<String, Vec<(Id, f32)>>,
        docs: &HashMap<Id, IndexedDoc>,
        doc_count: usize,
        total_doc_length: usize,
    ) -> &'a mut StagedState<Id> {
        staged.get_or_insert_with(|| StagedState {
            index: index.clone(),
            docs: docs.clone(),
            doc_count,
            total_doc_length,
        })
    }

    pub fn graph_root_hash(&self) -> Option<[u8; 32]> {
        *self.graph_root_hash.read()
    }

    pub fn set_graph_root_hash(&self, graph_root_hash: [u8; 32]) {
        *self.graph_root_hash.write() = Some(graph_root_hash);
    }

    /// Return the number of committed documents currently visible to search.
    pub fn live_document_count(&self) -> usize {
        *self.doc_count.read()
    }

    /// Whether a committed document with this ID is currently visible to search.
    pub fn contains(&self, doc_id: &Id) -> bool {
        self.docs.read().contains_key(doc_id)
    }

    /// Document frequency of a query `term`: the number of committed documents
    /// containing the term's RAREST token. This is exactly the per-token posting
    /// count BM25 search uses to compute IDF (see [`fuzzy_search`](Self::fuzzy_search)),
    /// exposed so callers can derive a term-discrimination weight WITHOUT
    /// re-implementing IDF. A multi-token identifier (e.g. `depthwise_conv` ->
    /// `[depthwise, conv]`) is only as specific as its rarest token, so we take
    /// the minimum across tokens. Returns 0 when no token of the term is indexed
    /// (the caller treats 0 as "unknown" and falls back to its default weight).
    pub fn doc_frequency(&self, term: &str) -> usize {
        let index = self.index.read();
        let mut min_df: Option<usize> = None;
        for tok in tokenize(term) {
            if let Some(postings) = index.get(&tok) {
                let df = postings.len();
                min_df = Some(min_df.map_or(df, |m| m.min(df)));
            }
        }
        min_df.unwrap_or(0)
    }

    fn with_path(path: Option<PathBuf>) -> Self {
        Self {
            index: RwLock::new(HashMap::new()),
            docs: RwLock::new(HashMap::new()),
            doc_count: RwLock::new(0),
            total_doc_length: RwLock::new(0),
            staged: RwLock::new(None),
            path,
            graph_root_hash: RwLock::new(None),
        }
    }

    fn storage_file_path(path: &Path) -> PathBuf {
        if path.extension().is_some() {
            path.to_path_buf()
        } else {
            path.join("index.bin")
        }
    }

    /// Index or re-index a document with pre-tokenized weighted fields.
    ///
    /// Each entry in `fields` is `(field_text, weight)`. The text is tokenized
    /// using the code-aware [`tokenize`] function, and each resulting token is
    /// stored with the given weight.
    ///
    /// Stages the change — call [`commit`](Self::commit) to make it visible to
    /// searches.
    pub fn upsert(&self, id: Id, fields: &[(&str, f32)]) -> Result<(), SearchError> {
        let _span = tracing::info_span!(
            "kin_search.upsert",
            id = ?id,
            fields = fields.len()
        )
        .entered();
        let mut all_tokens: Vec<(String, f32)> = Vec::new();
        for (text, weight) in fields {
            for tok in tokenize(text) {
                all_tokens.push((tok, *weight));
            }
        }
        let doc_length = all_tokens.len();

        let live_index = self.index.read();
        let live_docs = self.docs.read();
        let live_dc = *self.doc_count.read();
        let live_tdl = *self.total_doc_length.read();
        let mut staged_guard = self.staged.write();

        let state = Self::ensure_staged(
            &mut staged_guard,
            &live_index,
            &live_docs,
            live_dc,
            live_tdl,
        );

        // Remove old doc if present
        if let Some(old_doc) = state.docs.remove(&id) {
            remove_doc_from_index(&mut state.index, &old_doc, &id);
            state.doc_count = state.doc_count.saturating_sub(1);
            state.total_doc_length = state.total_doc_length.saturating_sub(old_doc.doc_length);
        }

        // Insert new tokens
        for (token, weight) in &all_tokens {
            state
                .index
                .entry(token.clone())
                .or_default()
                .push((id, *weight));
        }
        state.doc_count += 1;
        state.total_doc_length += doc_length;

        state.docs.insert(
            id,
            IndexedDoc {
                tokens_by_field: all_tokens,
                doc_length,
            },
        );

        Ok(())
    }

    /// Convenience: index a document that implements [`Searchable`].
    ///
    /// Extracts fields via [`Searchable::search_fields`] and delegates to
    /// [`upsert`](Self::upsert).
    pub fn upsert_searchable(&self, id: Id, doc: &impl Searchable) -> Result<(), SearchError> {
        let fields = doc.search_fields();
        self.upsert(id, &fields)
    }

    /// Remove a document from the text index.
    ///
    /// Stages the removal — call [`commit`](Self::commit) to make it visible
    /// to searches.
    pub fn remove(&self, id: &Id) -> Result<(), SearchError> {
        let _span = tracing::info_span!("kin_search.remove", id = ?id).entered();
        let live_index = self.index.read();
        let live_docs = self.docs.read();
        let live_dc = *self.doc_count.read();
        let live_tdl = *self.total_doc_length.read();
        let mut staged_guard = self.staged.write();

        let state = Self::ensure_staged(
            &mut staged_guard,
            &live_index,
            &live_docs,
            live_dc,
            live_tdl,
        );

        if let Some(old_doc) = state.docs.remove(id) {
            remove_doc_from_index(&mut state.index, &old_doc, id);
            state.doc_count = state.doc_count.saturating_sub(1);
            state.total_doc_length = state.total_doc_length.saturating_sub(old_doc.doc_length);
        }

        Ok(())
    }

    /// Rebuild the entire index from scratch with a batch of documents.
    ///
    /// Unlike repeated `upsert` calls, this avoids the clone-on-write overhead
    /// of `ensure_staged` by building the inverted index directly from empty
    /// state. For 20K+ entity rebuilds this is ~100x faster than individual
    /// upserts because it skips the full index clone on first write.
    ///
    /// Each document is `(id, fields)` where fields are `(text, weight)` pairs.
    pub fn rebuild_all(&self, documents: &[(Id, Vec<(&str, f32)>)]) -> Result<(), SearchError> {
        let _span =
            tracing::info_span!("kin_search.rebuild_all", documents = documents.len()).entered();
        let mut index: HashMap<String, Vec<(Id, f32)>> = HashMap::new();
        let mut docs: HashMap<Id, IndexedDoc> = HashMap::with_capacity(documents.len());
        let mut doc_count = 0usize;
        let mut total_doc_length = 0usize;

        for (id, fields) in documents {
            let mut all_tokens: Vec<(String, f32)> = Vec::new();
            for (text, weight) in fields {
                for tok in tokenize(text) {
                    all_tokens.push((tok, *weight));
                }
            }
            let doc_length = all_tokens.len();

            for (token, weight) in &all_tokens {
                index.entry(token.clone()).or_default().push((*id, *weight));
            }
            doc_count += 1;
            total_doc_length += doc_length;

            docs.insert(
                *id,
                IndexedDoc {
                    tokens_by_field: all_tokens,
                    doc_length,
                },
            );
        }

        // Replace live state directly, no staging needed.
        *self.index.write() = index;
        *self.docs.write() = docs;
        *self.doc_count.write() = doc_count;
        *self.total_doc_length.write() = total_doc_length;
        // Clear any pending staged state.
        *self.staged.write() = None;

        Ok(())
    }

    /// Rebuild the entire index from owned documents without first materializing
    /// a second borrowed view of the full corpus.
    ///
    /// This is intended for very large rebuilds driven by higher-level graph
    /// state. It keeps peak memory lower by consuming owned field vectors one
    /// document at a time instead of building additional full-corpus `Vec`s of
    /// borrowed field refs.
    pub fn rebuild_all_owned<I>(&self, documents: I) -> Result<(), SearchError>
    where
        I: IntoIterator<Item = (Id, Vec<(String, f32)>)>,
    {
        let iter = documents.into_iter();
        let (lower_bound, _) = iter.size_hint();
        let _span = tracing::info_span!("kin_search.rebuild_all_owned", lower_bound = lower_bound)
            .entered();

        let mut index: HashMap<String, Vec<(Id, f32)>> = HashMap::new();
        let mut docs: HashMap<Id, IndexedDoc> = HashMap::with_capacity(lower_bound);
        let mut doc_count = 0usize;
        let mut total_doc_length = 0usize;

        for (id, fields) in iter {
            let mut all_tokens: Vec<(String, f32)> = Vec::new();
            for (text, weight) in fields {
                for tok in tokenize(&text) {
                    all_tokens.push((tok, weight));
                }
            }
            let doc_length = all_tokens.len();

            for (token, weight) in &all_tokens {
                index.entry(token.clone()).or_default().push((id, *weight));
            }
            doc_count += 1;
            total_doc_length += doc_length;

            docs.insert(
                id,
                IndexedDoc {
                    tokens_by_field: all_tokens,
                    doc_length,
                },
            );
        }

        *self.index.write() = index;
        *self.docs.write() = docs;
        *self.doc_count.write() = doc_count;
        *self.total_doc_length.write() = total_doc_length;
        *self.staged.write() = None;

        Ok(())
    }

    /// Commit all pending writes, making staged changes visible to searches.
    ///
    /// Call after bulk operations rather than per document for best performance.
    pub fn commit(&self) -> Result<(), SearchError>
    where
        Id: Serialize + DeserializeOwned,
    {
        let _span = tracing::info_span!("kin_search.commit", staged = self.staged.read().is_some())
            .entered();
        let mut staged_guard = self.staged.write();
        if let Some(state) = staged_guard.take() {
            *self.index.write() = state.index;
            *self.docs.write() = state.docs;
            *self.doc_count.write() = state.doc_count;
            *self.total_doc_length.write() = state.total_doc_length;
        }
        self.persist_to_disk()?;
        Ok(())
    }

    /// Search across indexed documents.
    ///
    /// Returns up to `limit` matching document IDs with their relevance scores,
    /// ranked highest-first. Uses BM25 scoring with field weights.
    pub fn fuzzy_search(
        &self,
        query_str: &str,
        limit: usize,
    ) -> Result<Vec<(Id, f32)>, SearchError> {
        let _span = tracing::info_span!(
            "kin_search.fuzzy_search",
            query = %query_str,
            limit = limit
        )
        .entered();
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

        let mut scores: HashMap<Id, f32> = HashMap::new();

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
            // (or vice versa) — with minimum 3-char tokens for substring matching.
            // Iterate matching tokens in sorted order: `index` is a HashMap with
            // process-randomized iteration, and the per-entity score below is a
            // float `+=` accumulation. Float addition is non-associative, so an
            // unordered walk yields low-bit-different scores run to run, which
            // turns genuine ties into spurious orderings and makes the downstream
            // `truncate(limit)` keep different docs each run. Sorting the matched
            // tokens makes the accumulation order — and the result — deterministic.
            if qt.len() >= 3 {
                let mut matched_tokens: Vec<&String> = index
                    .keys()
                    .filter(|indexed_token| {
                        indexed_token.as_str() != qt.as_str()
                            && indexed_token.len() >= 3
                            && (indexed_token.contains(qt.as_str())
                                || qt.contains(indexed_token.as_str()))
                    })
                    .collect();
                matched_tokens.sort_unstable();
                for indexed_token in matched_tokens {
                    let postings = &index[indexed_token];
                    let df = postings.len() as f32;
                    let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln().max(0.0);
                    let substring_penalty = 0.5;
                    for (eid, weight) in postings {
                        let dl = docs.get(eid).map(|d| d.doc_length as f32).unwrap_or(avgdl);
                        let tf = *weight;
                        let tf_saturated = (tf * (BM25_K1 + 1.0))
                            / (tf + BM25_K1 * (1.0 - BM25_B + BM25_B * dl / avgdl));
                        *scores.entry(*eid).or_insert(0.0) +=
                            idf * tf_saturated * substring_penalty;
                    }
                }
            }
        }

        // Sort by score descending, then by a stable id tie-break so results are
        // deterministic regardless of the HashMap's process-randomized iteration
        // order (otherwise tied scores at the `truncate(limit)` cutoff vary run to
        // run). DocId guarantees Debug but not Ord, so tie-break on the Debug repr,
        // precomputed once to keep the comparator allocation-free.
        let mut keyed: Vec<(String, Id, f32)> = scores
            .into_iter()
            .map(|(id, score)| (format!("{id:?}"), id, score))
            .collect();
        keyed.sort_by(|a, b| {
            let a_score = if a.2.is_nan() { 0.0 } else { a.2 };
            let b_score = if b.2.is_nan() { 0.0 } else { b.2 };
            b_score
                .partial_cmp(&a_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        keyed.truncate(limit);
        let results: Vec<(Id, f32)> = keyed.into_iter().map(|(_, id, s)| (id, s)).collect();

        Ok(results)
    }
}

impl<Id> TextIndex<Id>
where
    Id: DocId + Serialize + DeserializeOwned,
{
    /// Open or create a persisted text search index.
    pub fn open(path: Option<&PathBuf>) -> Result<Self, SearchError> {
        Self::open_with_persistence(path, true)
    }

    /// Open a persisted text search index without allowing write-through.
    pub fn open_read_only(path: Option<&PathBuf>) -> Result<Self, SearchError> {
        Self::open_with_persistence(path, false)
    }

    fn open_with_persistence(
        path: Option<&PathBuf>,
        persist_changes: bool,
    ) -> Result<Self, SearchError> {
        let _span = tracing::info_span!(
            "kin_search.open",
            path = ?path,
            persist_changes = persist_changes
        )
        .entered();
        let Some(path) = path else {
            return Ok(Self::new());
        };

        let storage_path = Self::storage_file_path(path);
        let persisted = Self::load_persisted(&storage_path)?;
        let index = Self::with_path(if persist_changes {
            Some(storage_path.clone())
        } else {
            None
        });

        if let Some(persisted) = persisted {
            *index.index.write() = persisted.index;
            *index.docs.write() = persisted.docs;
            *index.doc_count.write() = persisted.doc_count;
            *index.total_doc_length.write() = persisted.total_doc_length;
            *index.graph_root_hash.write() = persisted.graph_root_hash;
        }

        Ok(index)
    }

    fn load_persisted(storage_path: &Path) -> Result<Option<PersistedIndex<Id>>, SearchError> {
        if !storage_path.exists() {
            return Ok(None);
        }

        let bytes = {
            let _span = tracing::info_span!(
                "kin_search.load_persisted.read_bytes",
                path = %storage_path.display()
            )
            .entered();
            std::fs::read(storage_path).map_err(|err| {
                SearchError::IndexError(format!(
                    "failed to read text index {}: {err}",
                    storage_path.display()
                ))
            })?
        };
        let persisted: PersistedIndex<Id> = {
            let _span = tracing::info_span!(
                "kin_search.load_persisted.deserialize",
                bytes = bytes.len()
            )
            .entered();
            bincode::deserialize(&bytes).map_err(|err| {
                SearchError::IndexError(format!(
                    "failed to decode text index {}: {err}",
                    storage_path.display()
                ))
            })?
        };
        if persisted.version != PersistedIndex::<Id>::VERSION {
            return Err(SearchError::IndexError(format!(
                "unsupported text index version {} in {}",
                persisted.version,
                storage_path.display()
            )));
        }

        Ok(Some(persisted))
    }

    fn persist_to_disk(&self) -> Result<(), SearchError> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                SearchError::IndexError(format!(
                    "failed to create text index directory {}: {err}",
                    parent.display()
                ))
            })?;
        }

        let index = self.index.read();
        let docs = self.docs.read();
        let doc_count = *self.doc_count.read();
        let total_doc_length = *self.total_doc_length.read();
        let graph_root_hash = *self.graph_root_hash.read();
        let persisted = PersistedIndexRef {
            version: PersistedIndex::<Id>::VERSION,
            index: &index,
            docs: &docs,
            doc_count,
            total_doc_length,
            graph_root_hash,
        };

        let encoded = bincode::serialize(&persisted).map_err(|err| {
            SearchError::IndexError(format!("failed to encode text index: {err}"))
        })?;
        let tmp_path = path.with_extension("tmp");
        std::fs::write(&tmp_path, &encoded).map_err(|err| {
            SearchError::IndexError(format!(
                "failed to write text index {}: {err}",
                tmp_path.display()
            ))
        })?;
        std::fs::rename(&tmp_path, path).map_err(|err| {
            SearchError::IndexError(format!(
                "failed to promote text index {} -> {}: {err}",
                tmp_path.display(),
                path.display()
            ))
        })?;
        Ok(())
    }
}

impl<Id: DocId> fmt::Debug for TextIndex<Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    struct TestId(u64);

    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

    fn next_id() -> TestId {
        TestId(NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }

    struct TestDoc {
        name: String,
        signature: String,
        file_path: String,
        kind: String,
    }

    impl Searchable for TestDoc {
        fn search_fields(&self) -> Vec<(&str, f32)> {
            vec![
                (&self.name, 5.0),
                (&self.signature, 3.0),
                (&self.file_path, 2.0),
                (&self.kind, 1.0),
            ]
        }
    }

    fn make_doc(name: &str, file: &str, kind: &str) -> (TestId, TestDoc) {
        let id = next_id();
        let doc = TestDoc {
            name: name.to_string(),
            signature: format!("fn {name}()"),
            file_path: file.to_string(),
            kind: kind.to_string(),
        };
        (id, doc)
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
        let idx = TextIndex::<TestId>::new();
        let (id1, doc1) = make_doc("getUserById", "src/users.rs", "Function");
        let (_, doc2) = make_doc("deletePost", "src/posts.rs", "Function");

        idx.upsert_searchable(id1, &doc1).unwrap();
        idx.upsert_searchable(next_id(), &doc2).unwrap();
        idx.commit().unwrap();

        let results = idx.fuzzy_search("getUserById", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, id1);
    }

    #[test]
    fn search_by_file_path() {
        let idx = TextIndex::<TestId>::new();
        let (id1, doc1) = make_doc("foo", "src/auth/login.rs", "Function");

        idx.upsert_searchable(id1, &doc1).unwrap();
        idx.commit().unwrap();

        let results = idx.fuzzy_search("auth", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, id1);
    }

    #[test]
    fn remove_from_index() {
        let idx = TextIndex::<TestId>::new();
        let (id1, doc1) = make_doc("myFunction", "src/lib.rs", "Function");

        idx.upsert_searchable(id1, &doc1).unwrap();
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
        let idx = TextIndex::<TestId>::new();
        let (id1, doc1) = make_doc("alphaHandler", "src/lib.rs", "Function");

        idx.upsert_searchable(id1, &doc1).unwrap();
        idx.commit().unwrap();

        // Update name to something with completely different tokens
        let updated_doc = TestDoc {
            name: "betaProcessor".to_string(),
            signature: "fn betaProcessor()".to_string(),
            file_path: "src/lib.rs".to_string(),
            kind: "Function".to_string(),
        };
        idx.upsert_searchable(id1, &updated_doc).unwrap();
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
        let idx = TextIndex::<TestId>::new();
        let results = idx.fuzzy_search("anything", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn live_document_count_tracks_committed_docs_only() {
        let idx = TextIndex::<TestId>::new();
        let (id1, doc1) = make_doc("alpha", "src/alpha.rs", "Function");
        let (id2, doc2) = make_doc("beta", "src/beta.rs", "Function");

        assert_eq!(idx.live_document_count(), 0);

        idx.upsert_searchable(id1, &doc1).unwrap();
        assert_eq!(idx.live_document_count(), 0);

        idx.commit().unwrap();
        assert_eq!(idx.live_document_count(), 1);

        idx.upsert_searchable(id2, &doc2).unwrap();
        assert_eq!(idx.live_document_count(), 1);

        idx.commit().unwrap();
        assert_eq!(idx.live_document_count(), 2);

        idx.remove(&id1).unwrap();
        assert_eq!(idx.live_document_count(), 2);

        idx.commit().unwrap();
        assert_eq!(idx.live_document_count(), 1);
    }

    #[test]
    fn persistent_index_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("text_index");

        let idx = TextIndex::<TestId>::open(Some(&path)).unwrap();
        let (id1, doc1) = make_doc("persistMe", "src/persist.rs", "Function");

        idx.upsert_searchable(id1, &doc1).unwrap();
        idx.set_graph_root_hash([7; 32]);
        idx.commit().unwrap();

        let reopened = TextIndex::<TestId>::open(Some(&path)).unwrap();
        let results = reopened.fuzzy_search("persistMe", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, id1);
        assert_eq!(reopened.graph_root_hash(), Some([7; 32]));
    }

    #[test]
    fn substring_fuzzy_match() {
        let idx = TextIndex::<TestId>::new();
        let (id1, doc1) = make_doc("QdpReader", "src/io/qdp.py", "Function");

        idx.upsert_searchable(id1, &doc1).unwrap();
        idx.commit().unwrap();

        // "qdp" should match "QdpReader" via substring
        let results = idx.fuzzy_search("qdp", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, id1);
    }

    #[test]
    fn raw_upsert_api() {
        let idx = TextIndex::<TestId>::new();
        let id = next_id();

        idx.upsert(id, &[("myGreatFunction", 5.0), ("src/great.rs", 2.0)])
            .unwrap();
        idx.commit().unwrap();

        let results = idx.fuzzy_search("great", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, id);
    }

    #[test]
    fn debug_format() {
        let idx = TextIndex::<TestId>::new();
        let (id1, doc1) = make_doc("debugMe", "src/debug.rs", "Function");
        idx.upsert_searchable(id1, &doc1).unwrap();
        idx.commit().unwrap();

        let debug_str = format!("{:?}", idx);
        assert!(debug_str.contains("TextIndex"));
        assert!(debug_str.contains("documents"));
        assert!(debug_str.contains("tokens"));
    }
}
