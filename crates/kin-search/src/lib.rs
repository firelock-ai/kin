// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;
use rayon::prelude::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum SearchError {
    #[error("search error: {0}")]
    IndexError(String),

    /// The persisted index on disk could not be loaded because it is corrupt:
    /// truncated, undecodable, or an unsupported format version.
    ///
    /// The text index is a *derived* view over graph-owned truth, so the correct
    /// recovery is to rebuild it from the graph — never to fail hard and brick
    /// the daemon. The corrupt file has been archived best-effort (`archived` is
    /// `Some` when the rename succeeded), preserving it as evidence and clearing
    /// the way for a clean reopen. Callers should treat this as "rebuild needed"
    /// and repopulate via `rebuild_all`/`upsert` + `commit`. This is exactly how
    /// the existing kin-db consumer already reacts to an `open` error (warn, fall
    /// back to an empty index, rebuild on the next root-hash mismatch), so the
    /// load contract is unchanged — only now the bad file is moved aside and the
    /// reason is typed rather than a bare string.
    #[error("corrupt text index at {}: {reason} (rebuild needed)", path.display())]
    CorruptIndex {
        path: PathBuf,
        archived: Option<PathBuf>,
        reason: String,
    },
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

/// Posting list for a single token.
///
/// Maps each document to the per-occurrence field weights it contributed for
/// this token (a token can occur in several weighted fields, and several times
/// within a field). Keying by document id makes removing a document
/// `O(occurrences-in-that-doc)` instead of a linear `retain` over every posting
/// for the token. The flat-`Vec` layout it replaces turned bulk re-index
/// (remove-then-reinsert on the daemon reconcile path) into O(n²) churn,
/// because each removal scanned the entire — and for hot tokens, corpus-sized —
/// posting list.
#[derive(Clone, Serialize, Deserialize)]
struct Postings<Id: DocId> {
    /// doc id -> field weights, one entry per token occurrence in that doc.
    by_doc: HashMap<Id, Vec<f32>>,
    /// Total occurrences across all docs. This is the posting count the legacy
    /// flat-`Vec` exposed via `len()` and used as the BM25 document-frequency
    /// proxy; tracked explicitly so scoring is bit-for-bit preserved.
    occurrences: usize,
}

// Manual `Default` so we do not impose a spurious `Id: Default` bound (which
// `#[derive(Default)]` would add); `HashMap::new()` needs no such bound.
impl<Id: DocId> Default for Postings<Id> {
    fn default() -> Self {
        Self {
            by_doc: HashMap::new(),
            occurrences: 0,
        }
    }
}

impl<Id: DocId> Postings<Id> {
    /// Record one token occurrence for `id` with the given field `weight`.
    fn add(&mut self, id: Id, weight: f32) {
        self.by_doc.entry(id).or_default().push(weight);
        self.occurrences += 1;
    }

    /// Remove every occurrence contributed by `id`. Returns the number of
    /// postings removed (the doc's occurrence count for this token), which is
    /// independent of the total posting-list length — the property that keeps
    /// bulk re-index linear instead of quadratic.
    fn remove(&mut self, id: &Id) -> usize {
        match self.by_doc.remove(id) {
            Some(weights) => {
                let removed = weights.len();
                self.occurrences -= removed;
                removed
            }
            None => 0,
        }
    }

    /// Total postings (token occurrences across all docs).
    ///
    /// Used as a work-size estimate for the parallel-vs-serial scoring threshold.
    /// NOT used as the BM25 document-frequency; use `by_doc.len()` for that.
    fn len(&self) -> usize {
        self.occurrences
    }

    /// Number of distinct documents containing this token — the correct BM25
    /// document-frequency value for IDF computation.
    fn doc_count(&self) -> usize {
        self.by_doc.len()
    }

    fn is_empty(&self) -> bool {
        self.by_doc.is_empty()
    }

    /// Iterate `(doc_id, field_weight)` over every occurrence. A document's own
    /// occurrences are yielded in insertion (field) order; the order across
    /// documents is unspecified, which is safe because every posting updates a
    /// distinct document's score accumulator, so the final per-document score is
    /// invariant to the cross-document walk order.
    fn iter(&self) -> impl Iterator<Item = (&Id, &f32)> {
        self.by_doc
            .iter()
            .flat_map(|(id, weights)| weights.iter().map(move |w| (id, w)))
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct StagedState<Id: DocId> {
    index: HashMap<String, Postings<Id>>,
    docs: HashMap<Id, IndexedDoc>,
    doc_count: usize,
    total_doc_length: usize,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistedIndex<Id: DocId> {
    version: u32,
    index: HashMap<String, Postings<Id>>,
    docs: HashMap<Id, IndexedDoc>,
    doc_count: usize,
    total_doc_length: usize,
    graph_root_hash: Option<[u8; 32]>,
}

#[derive(Serialize)]
struct PersistedIndexRef<'a, Id: DocId> {
    version: u32,
    index: &'a HashMap<String, Postings<Id>>,
    docs: &'a HashMap<Id, IndexedDoc>,
    doc_count: usize,
    total_doc_length: usize,
    graph_root_hash: Option<[u8; 32]>,
}

/// On-disk layout for format version 1: posting lists as flat `Vec<(Id, f32)>`.
/// Retained only so older persisted indexes migrate forward transparently on
/// load (see [`TextIndex::load_persisted`]); never written.
#[derive(Deserialize)]
struct PersistedIndexV1<Id: DocId> {
    version: u32,
    index: HashMap<String, Vec<(Id, f32)>>,
    docs: HashMap<Id, IndexedDoc>,
    doc_count: usize,
    total_doc_length: usize,
    graph_root_hash: Option<[u8; 32]>,
}

/// Convert a format-v1 flat posting map into the doc-keyed [`Postings`] layout.
/// Occurrence counts are preserved exactly (`occurrences == entries.len()`),
/// so the BM25 document-frequency proxy — and therefore every score — is
/// identical to what the v1 index produced.
fn migrate_v1_index<Id: DocId>(
    old: HashMap<String, Vec<(Id, f32)>>,
) -> HashMap<String, Postings<Id>> {
    old.into_iter()
        .map(|(token, entries)| {
            let mut postings = Postings::default();
            for (id, weight) in entries {
                postings.add(id, weight);
            }
            (token, postings)
        })
        .collect()
}

/// Bumped from 1 to 2 when posting lists moved from a flat `Vec<(Id, f32)>` to
/// the doc-keyed [`Postings`] layout. v1 files are migrated forward on load.
pub const TEXT_INDEX_FORMAT_VERSION: u32 = 2;

impl<Id: DocId> PersistedIndex<Id> {
    const VERSION: u32 = TEXT_INDEX_FORMAT_VERSION;
}

// ── Segmented (incremental) on-disk format ───────────────────────────────────

/// Format version for the segmented on-disk layout (a small `manifest` file plus
/// one immutable `seg-<k>-<gen>` file per non-empty segment). Distinct from the
/// monolithic [`TEXT_INDEX_FORMAT_VERSION`] because it is a different file set;
/// the manifest is the single versioned, atomically-swapped commit point.
pub const SEGMENTED_FORMAT_VERSION: u32 = 3;

/// Default number of segments a doc set is partitioned into when the segmented
/// persistence path is active. Each segment is an independent, immutable file;
/// a commit re-serializes only the segments whose docs changed, so the cost of a
/// persist scales with the churn, not the whole index. Overridable (only when a
/// fresh segmented index is first established) via `KIN_SEARCH_SEGMENT_COUNT`.
const DEFAULT_SEGMENT_COUNT: usize = 64;

/// Env flag that can opt a handle out of segmented/incremental persistence.
/// Default ON: unset or truthy/non-falsey values use the segmented path, while
/// `0`, `false`, `no`, or `off` keep the monolithic full-rewrite path. The flag
/// governs only the *write* strategy and dirty-tracking — load always
/// auto-detects the on-disk format, so toggling it is safe in both directions.
const INCREMENTAL_PERSIST_ENV: &str = "KIN_SEARCH_INCREMENTAL_PERSIST";

/// Env override for the segment count of a *newly established* segmented index.
const SEGMENT_COUNT_ENV: &str = "KIN_SEARCH_SEGMENT_COUNT";

fn incremental_persist_enabled_from_env(value: Option<&str>) -> bool {
    let Some(value) = value.map(str::trim) else {
        return true;
    };
    !(value == "0"
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("off"))
}

fn incremental_persist_enabled() -> bool {
    incremental_persist_enabled_from_env(std::env::var(INCREMENTAL_PERSIST_ENV).ok().as_deref())
}

fn resolve_default_segment_count() -> usize {
    std::env::var(SEGMENT_COUNT_ENV)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(DEFAULT_SEGMENT_COUNT)
}

/// A fully-specified FNV-1a 64-bit hasher. Used to assign a document to a
/// segment deterministically and *stably across binary versions* — unlike
/// `std::collections::hash_map::DefaultHasher`, whose algorithm the standard
/// library explicitly reserves the right to change between releases. A stable
/// assignment is what makes incremental dirty-tracking sound: the same id must
/// always map to the same segment, or a doc could be written into one segment
/// while a stale copy lingers in another. (A drift is still caught safely on
/// load by the duplicate-id check, which downgrades it to a clean rebuild.)
struct FnvHasher(u64);

impl FnvHasher {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    fn new() -> Self {
        Self(Self::OFFSET_BASIS)
    }
}

impl std::hash::Hasher for FnvHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut hash = self.0;
        for &byte in bytes {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(Self::PRIME);
        }
        self.0 = hash;
    }
}

/// Compute the segment index for a document id under a given segment count.
fn segment_of<Id: DocId>(id: &Id, segment_count: usize) -> usize {
    let mut hasher = FnvHasher::new();
    id.hash(&mut hasher);
    (hasher.finish() % segment_count as u64) as usize
}

/// One segment's self-contained slice of the index: the postings and forward
/// docs for the subset of documents assigned to this segment. Merging every
/// segment's slice reconstructs exactly the monolithic in-memory state (doc sets
/// are disjoint across segments, so the union is exact and the merge order does
/// not affect any per-document score).
#[derive(Serialize, Deserialize)]
struct SegmentData<Id: DocId> {
    index: HashMap<String, Postings<Id>>,
    docs: HashMap<Id, IndexedDoc>,
    doc_count: usize,
    total_doc_length: usize,
}

/// The fully-merged in-memory state reconstructed from a segmented on-disk
/// index, plus the baseline bookkeeping the handle needs to do future
/// incremental persists. Carries exactly the same fields a monolithic load
/// produces, so the two load paths converge on identical live state.
struct LoadedSegmented<Id: DocId> {
    index: HashMap<String, Postings<Id>>,
    docs: HashMap<Id, IndexedDoc>,
    doc_count: usize,
    total_doc_length: usize,
    graph_root_hash: Option<[u8; 32]>,
    segment_count: usize,
    baseline_gens: Vec<Option<u64>>,
    segment_docs: Vec<HashSet<Id>>,
}

/// The segmented-format commit point. Small (one entry per segment), so it is
/// cheap to rewrite on every commit. Written durably and atomically renamed into
/// place *after* all referenced segment files are fsynced — so a crash either
/// leaves the previous manifest (old segments) or the new one (all new/kept
/// segments present), never a torn half-applied set.
#[derive(Serialize, Deserialize)]
struct SegmentManifest {
    version: u32,
    segment_count: usize,
    /// Per-segment generation: `Some(gen)` names the live `seg-<k>-<gen>` file;
    /// `None` means the segment is empty and has no file.
    segment_gens: Vec<Option<u64>>,
    doc_count: usize,
    total_doc_length: usize,
    graph_root_hash: Option<[u8; 32]>,
}

/// Tracks which segments have changed since the last segmented persist.
enum SegmentDirty {
    /// Every segment must be (re)written — used before a baseline exists (fresh
    /// index, or one loaded from the monolithic format) and after `rebuild_all`.
    All,
    /// Only these segment indices changed and need re-serialization; the rest
    /// keep their existing on-disk generation.
    Tracked(HashSet<usize>),
}

/// In-memory bookkeeping for the segmented persistence path.
struct SegmentPersistState<Id: DocId> {
    /// Segment count this index is partitioned into. Fixed once a baseline
    /// exists so a doc never migrates between segments mid-life.
    segment_count: usize,
    /// On-disk generation per segment, or `None` if the canonical on-disk format
    /// is currently monolithic / absent (no segmented baseline to do delta from).
    baseline_gens: Option<Vec<Option<u64>>>,
    /// Doc ids currently assigned to each segment once a segmented baseline
    /// exists. Incremental persists use this to visit only dirty segments instead
    /// of rebucketing the full corpus every commit.
    segment_docs: Option<Vec<HashSet<Id>>>,
    dirty: SegmentDirty,
}

impl<Id: DocId> SegmentPersistState<Id> {
    fn new(segment_count: usize) -> Self {
        Self {
            segment_count,
            baseline_gens: None,
            segment_docs: None,
            dirty: SegmentDirty::All,
        }
    }

    fn mark_dirty(&mut self, segment: usize) {
        if let SegmentDirty::Tracked(set) = &mut self.dirty {
            set.insert(segment);
        }
    }

    fn mark_all_dirty(&mut self) {
        self.dirty = SegmentDirty::All;
    }
}

// ── BM25 parameters ────────────────────────────────────────────────────────

const BM25_K1: f32 = 1.2;
const BM25_B: f32 = 0.75;

// ── Durable-persistence helpers ──────────────────────────────────────────────

/// Monotonic counter so concurrently-persisting handles get distinct temp and
/// archive file names within a process (a fixed `.tmp` name would let two
/// commits clobber each other's in-flight write).
static PERSIST_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Build a unique sibling temp path for `path`, e.g. `index.bin.tmp-<pid>-<seq>`.
fn unique_tmp_path(path: &Path, seq: u64) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!(".tmp-{}-{}", std::process::id(), seq));
    path.with_file_name(name)
}

/// Write `bytes` to `path` and `fsync` the file so its contents are durable on
/// disk before the caller renames it into place — without this, a crash after
/// `rename` can publish a zero-length or torn index.
fn write_file_durably(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Best-effort `fsync` of a path's parent directory so a `rename`/`create`
/// within it is durable. Directory fsync is unsupported on some platforms;
/// failures are non-fatal because the file itself was already fsynced.
fn sync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

/// Move a corrupt index file aside, preserving it as evidence and clearing the
/// canonical path so the next reopen starts clean. Best-effort: returns `None`
/// (and logs) when the rename fails — e.g. a read-only filesystem — in which
/// case the caller still surfaces a typed [`SearchError::CorruptIndex`].
fn archive_corrupt_index(storage_path: &Path) -> Option<PathBuf> {
    let seq = PERSIST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = storage_path.file_name().map(|n| n.to_os_string())?;
    name.push(format!(".corrupt-{}-{}", std::process::id(), seq));
    let dest = storage_path.with_file_name(name);
    match std::fs::rename(storage_path, &dest) {
        Ok(()) => {
            sync_parent_dir(storage_path);
            tracing::warn!(
                from = %storage_path.display(),
                to = %dest.display(),
                "archived corrupt text index; rebuild needed"
            );
            Some(dest)
        }
        Err(err) => {
            tracing::warn!(
                path = %storage_path.display(),
                error = %err,
                "failed to archive corrupt text index; leaving in place"
            );
            None
        }
    }
}

/// Build a typed [`SearchError::CorruptIndex`].
///
/// When `archive` is true, moves the corrupt file aside first so the bytes
/// are preserved as evidence and a clean reopen is possible. Pass `false` when
/// opening in read-only mode — the caller must not rename files on disk.
fn corrupt_index_error(storage_path: &Path, reason: String, archive: bool) -> SearchError {
    let archived = if archive {
        archive_corrupt_index(storage_path)
    } else {
        None
    };
    SearchError::CorruptIndex {
        path: storage_path.to_path_buf(),
        archived,
        reason,
    }
}

/// Suffix appended to the storage file name to derive segmented-format siblings,
/// e.g. `index.bin` -> `index.bin.kinseg-manifest`, `index.bin.kinseg-3-7`.
const KINSEG_PREFIX: &str = ".kinseg-";

/// Path of the segmented manifest, a sibling of the monolithic storage file.
fn manifest_path(storage_path: &Path) -> PathBuf {
    let mut name = storage_path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!("{KINSEG_PREFIX}manifest"));
    storage_path.with_file_name(name)
}

/// Path of the file holding segment `k` at generation `gen`.
fn segment_path(storage_path: &Path, segment: usize, gen: u64) -> PathBuf {
    let mut name = storage_path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!("{KINSEG_PREFIX}{segment}-{gen}"));
    storage_path.with_file_name(name)
}

/// Best-effort enumeration of every segmented sibling file (manifest + segment
/// files) so they can be cleaned up when reverting to the monolithic format.
fn kinseg_sibling_files(storage_path: &Path) -> Vec<PathBuf> {
    let Some(file_name) = storage_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
    else {
        return Vec::new();
    };
    let needle = format!("{file_name}{KINSEG_PREFIX}");
    let Some(parent) = storage_path.parent() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(&needle))
        .map(|e| e.path())
        .collect()
}

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
    // Mirrors the contents of `tokens` so the per-segment whole-segment token can
    // be de-duplicated against the whole output in O(1) instead of re-scanning the
    // growing `tokens` vector (which is quadratic in the token count on long
    // inputs). camelCase parts are still emitted unconditionally — only the
    // whole-segment token is gated — so the resulting sequence is byte-for-byte
    // identical to the former linear `tokens.contains` dedup.
    let mut seen: HashSet<String> = HashSet::new();

    // Split on non-alphanumeric characters first
    for segment in text.split(|c: char| !c.is_alphanumeric()) {
        if segment.is_empty() {
            continue;
        }
        // Split camelCase: insert boundary before uppercase chars preceded by lowercase
        let mut current = String::new();
        let chars: Vec<char> = segment.chars().collect();
        for i in 0..chars.len() {
            if i > 0
                && chars[i].is_uppercase()
                && chars[i - 1].is_lowercase()
                && !current.is_empty()
            {
                let lower = current.to_lowercase();
                if !lower.is_empty() {
                    seen.insert(lower.clone());
                    tokens.push(lower);
                }
                current.clear();
            }
            current.push(chars[i]);
        }
        if !current.is_empty() {
            let lower = current.to_lowercase();
            if !lower.is_empty() {
                seen.insert(lower.clone());
                tokens.push(lower);
            }
        }

        // Also add the whole segment as a token (lowercased) for exact matching.
        // `seen.insert` reports whether it was absent, reproducing the former
        // `!tokens.contains(&full)` guard against every token emitted so far.
        let full = segment.to_lowercase();
        if full.len() > 1 && seen.insert(full.clone()) {
            tokens.push(full);
        }
    }

    tokens
}

// ── Helper ──────────────────────────────────────────────────────────────────

/// Remove all postings for the given document from the inverted index.
///
/// Touches only the posting lists for the document's own tokens, and within
/// each list removes only that document's entries in `O(occurrences-in-doc)`
/// via the keyed [`Postings`] map — never a linear scan of the whole list.
/// Returns the number of postings removed (the document's total occurrence
/// count), which is independent of corpus size.
fn remove_doc_from_index<Id: DocId>(
    index: &mut HashMap<String, Postings<Id>>,
    doc: &IndexedDoc,
    doc_id: &Id,
) -> usize {
    let mut unique_tokens = HashSet::new();
    for (token, _) in &doc.tokens_by_field {
        unique_tokens.insert(token);
    }
    let mut removed = 0usize;
    for token in unique_tokens {
        if let Some(postings) = index.get_mut(token) {
            removed += postings.remove(doc_id);
            if postings.is_empty() {
                index.remove(token);
            }
        }
    }
    removed
}

// ── Trigram candidate index ──────────────────────────────────────────────────

/// Minimum token length (in bytes) eligible for substring/fuzzy matching. A
/// query token shorter than this never enters the substring branch, and an
/// indexed token shorter than this is never a substring candidate — so the
/// trigram index only needs to hold tokens of at least this length.
const MIN_SUBSTRING_LEN: usize = 3;

/// Total scored token occurrences at or above which BM25 scoring fans out across
/// the ambient rayon pool. Below it, the serial single-pass path avoids both the
/// candidate-set collection and the parallel dispatch overhead, which dominate at
/// small/medium result sets. The two paths are bit-for-bit identical, so this
/// only trades latency, never results.
const PARALLEL_SCORE_THRESHOLD: usize = 32_768;

/// A byte trigram: three consecutive bytes of a token. Substring matching keys
/// on raw bytes (not chars) so it stays exactly consistent with `str::contains`,
/// which is itself a byte-substring test.
type Trigram = [u8; 3];

/// Inverted trigram index over the live vocabulary, used to generate substring
/// match candidates without scanning every key.
///
/// The substring branch of [`TextIndex::fuzzy_search`] matches an indexed token
/// `t` against a query token `q` when either contains the other (both at least
/// [`MIN_SUBSTRING_LEN`] bytes). Either direction implies `t` and `q` share at
/// least one byte trigram: if `t` contains `q`, every trigram of `q` is in `t`;
/// if `q` contains `t`, every trigram of `t` is in `q`. So the union of the
/// posting lists for `q`'s trigrams is a *complete* superset of `q`'s substring
/// matches — never missing one — and the exact `contains` predicate is then
/// applied to that small candidate set to drop false positives. The matched set,
/// and therefore every score, is identical to a full vocabulary scan.
struct TrigramIndex {
    /// Live-index generation this was built for; rebuilt when it falls behind.
    epoch: u64,
    /// Vocabulary tokens of at least [`MIN_SUBSTRING_LEN`] bytes, addressed by
    /// the `u32` ids stored in `postings`.
    tokens: Vec<Box<str>>,
    /// Trigram -> sorted, de-duplicated token ids containing that trigram.
    postings: HashMap<Trigram, Vec<u32>>,
}

impl TrigramIndex {
    /// Build the trigram index from the current inverted-index vocabulary.
    fn build<Id: DocId>(index: &HashMap<String, Postings<Id>>, epoch: u64) -> Self {
        let mut tokens: Vec<Box<str>> = Vec::new();
        let mut postings: HashMap<Trigram, Vec<u32>> = HashMap::new();
        let mut seen: HashSet<Trigram> = HashSet::new();
        for token in index.keys() {
            let bytes = token.as_bytes();
            if bytes.len() < MIN_SUBSTRING_LEN {
                continue;
            }
            let token_id = tokens.len() as u32;
            tokens.push(token.as_str().into());
            seen.clear();
            for window in bytes.windows(MIN_SUBSTRING_LEN) {
                let tri: Trigram = [window[0], window[1], window[2]];
                // Skip a trigram already recorded for this token so each posting
                // list holds a token at most once.
                if seen.insert(tri) {
                    postings.entry(tri).or_default().push(token_id);
                }
            }
        }
        Self {
            epoch,
            tokens,
            postings,
        }
    }

    /// Collect the token ids that share at least one trigram with `query_token`.
    /// A complete superset of the query's substring matches (see type docs); the
    /// caller still applies the exact `contains` predicate to each candidate.
    fn candidate_ids(&self, query_token: &str) -> HashSet<u32> {
        let mut candidates: HashSet<u32> = HashSet::new();
        for window in query_token.as_bytes().windows(MIN_SUBSTRING_LEN) {
            let tri: Trigram = [window[0], window[1], window[2]];
            if let Some(ids) = self.postings.get(&tri) {
                candidates.extend(ids.iter().copied());
            }
        }
        candidates
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
    /// Inverted index: lowercase token -> [`Postings`] keyed by document id.
    index: RwLock<HashMap<String, Postings<Id>>>,
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
    /// Whether this handle writes via the segmented/incremental path. Cached at
    /// construction from [`INCREMENTAL_PERSIST_ENV`]; default ON unless
    /// explicitly disabled. Governs only the write strategy and dirty-tracking
    /// — load auto-detects the format.
    incremental_enabled: bool,
    /// Segmented-persistence bookkeeping (segment count, on-disk generations,
    /// dirty set). Only consulted on the segmented write/load paths.
    seg: RwLock<SegmentPersistState<Id>>,
    /// Monotonic generation of the live inverted index, bumped on every wholesale
    /// replacement (commit/rebuild/load). Stamps `trigram` so a stale candidate
    /// index is detected and rebuilt lazily on the next fuzzy query.
    index_epoch: AtomicU64,
    /// Lazily-built trigram candidate index over the live vocabulary, used to
    /// keep substring matching sublinear in vocabulary size. Rebuilt on demand
    /// whenever its stamped epoch falls behind `index_epoch`.
    trigram: RwLock<Option<TrigramIndex>>,
}

impl<Id: DocId> Default for TextIndex<Id> {
    fn default() -> Self {
        Self::new()
    }
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
            incremental_enabled: incremental_persist_enabled(),
            seg: RwLock::new(SegmentPersistState::new(resolve_default_segment_count())),
            index_epoch: AtomicU64::new(0),
            trigram: RwLock::new(None),
        }
    }

    /// Get or create the staged state, snapshotting from the live state on first
    /// use.
    ///
    /// # Lock ordering
    ///
    /// The caller MUST already hold the `staged` write guard (passed in as
    /// `staged`). Only when the staging buffer is empty does this acquire the
    /// four live-state read guards to clone a snapshot — and it does so *while
    /// `staged` is held*, i.e. strictly **nested inside** `staged`. This is the
    /// canonical lock order for the whole type: `staged` is the outermost lock,
    /// and `index`/`docs`/`doc_count`/`total_doc_length` are only ever taken
    /// after it. [`commit`](Self::commit) follows the same order (it takes
    /// `staged` first, then the live-state write guards), so a writer and a
    /// committer can never acquire the two locks in conflicting order — which is
    /// what eliminates the lock-order-inversion deadlock. Each live
    /// read guard is released the instant its clone completes, so this never
    /// holds more than `staged` + one live guard at a time.
    fn ensure_staged<'a>(
        &self,
        staged: &'a mut Option<StagedState<Id>>,
    ) -> &'a mut StagedState<Id> {
        staged.get_or_insert_with(|| StagedState {
            index: self.index.read().clone(),
            docs: self.docs.read().clone(),
            doc_count: *self.doc_count.read(),
            total_doc_length: *self.total_doc_length.read(),
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
                let df = postings.doc_count();
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
            incremental_enabled: incremental_persist_enabled(),
            seg: RwLock::new(SegmentPersistState::new(resolve_default_segment_count())),
            index_epoch: AtomicU64::new(0),
            trigram: RwLock::new(None),
        }
    }

    fn storage_file_path(path: &Path) -> PathBuf {
        if path.extension().is_some() {
            path.to_path_buf()
        } else {
            path.join("index.bin")
        }
    }

    /// Record that the segment owning `id` changed, so the next segmented
    /// persist re-serializes it. A no-op only when incremental persistence is
    /// explicitly disabled.
    fn mark_doc_changed(&self, id: &Id, present: bool) {
        if !self.incremental_enabled {
            return;
        }
        let mut seg = self.seg.write();
        let segment_count = seg.segment_count;
        let segment = segment_of(id, segment_count);
        seg.mark_dirty(segment);

        let reset_membership = matches!(
            seg.segment_docs.as_ref(),
            Some(segment_docs) if segment_docs.len() != segment_count
        );
        if reset_membership {
            seg.segment_docs = None;
            seg.mark_all_dirty();
        } else if let Some(segment_docs) = seg.segment_docs.as_mut() {
            if present {
                segment_docs[segment].insert(*id);
            } else {
                segment_docs[segment].remove(id);
            }
        }
    }

    fn mark_doc_upserted(&self, id: &Id) {
        self.mark_doc_changed(id, true);
    }

    fn mark_doc_removed(&self, id: &Id) {
        self.mark_doc_changed(id, false);
    }

    /// Mark every segment dirty (a full rewrite is required). Used by the
    /// `rebuild_all*` paths, which replace the entire corpus.
    fn mark_all_segments_dirty(&self) {
        if !self.incremental_enabled {
            return;
        }
        let mut seg = self.seg.write();
        seg.segment_docs = None;
        seg.mark_all_dirty();
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

        // Canonical lock order: take `staged` first; `ensure_staged` acquires the
        // live-state read guards only if it needs to clone a snapshot, strictly
        // nested under `staged`. `commit` takes the same locks in the same order
        // (`staged` then the live-state guards), so no writer/committer pair can
        // ever invert them.
        let mut staged_guard = self.staged.write();
        let state = self.ensure_staged(&mut staged_guard);

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
                .add(id, *weight);
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
        self.mark_doc_upserted(&id);
        drop(staged_guard);
        Ok(())
    }

    /// Stage a batch of documents in one call, tokenizing them in parallel.
    ///
    /// Each `(id, fields)` entry is indexed exactly as a standalone
    /// [`upsert`](Self::upsert) would index it — same tokenization, same
    /// per-occurrence postings, same term frequencies. Only the CPU-bound
    /// tokenization runs across the rayon thread pool; the inverted-index merge
    /// then runs serially in batch order. `par_iter` over a slice is
    /// index-ordered, so `collect` restores batch order exactly and the staged
    /// index is identical to applying `upsert` to each entry in sequence,
    /// independent of thread scheduling. A repeated `id` within the batch is
    /// applied in order, so the last entry for that `id` wins, matching serial
    /// upserts.
    ///
    /// Stages the change — call [`commit`](Self::commit) to make it visible to
    /// searches.
    pub fn upsert_batch(&self, batch: &[(Id, Vec<(&str, f32)>)]) -> Result<(), SearchError> {
        let _span =
            tracing::info_span!("kin_search.upsert_batch", batch_size = batch.len()).entered();

        let tokenized: Vec<(Id, Vec<(String, f32)>)> = batch
            .par_iter()
            .map(|(id, fields)| {
                let mut all_tokens: Vec<(String, f32)> = Vec::new();
                for (text, weight) in fields {
                    for tok in tokenize(text) {
                        all_tokens.push((tok, *weight));
                    }
                }
                (*id, all_tokens)
            })
            .collect();

        // Canonical lock order matches `upsert`: `staged` first, then the
        // live-state guards (only if `ensure_staged` clones a snapshot), strictly
        // nested under `staged`, so no writer/committer pair can invert them.
        let mut staged_guard = self.staged.write();
        let state = self.ensure_staged(&mut staged_guard);

        for (id, all_tokens) in tokenized {
            let doc_length = all_tokens.len();

            if let Some(old_doc) = state.docs.remove(&id) {
                remove_doc_from_index(&mut state.index, &old_doc, &id);
                state.doc_count = state.doc_count.saturating_sub(1);
                state.total_doc_length = state.total_doc_length.saturating_sub(old_doc.doc_length);
            }

            for (token, weight) in &all_tokens {
                state
                    .index
                    .entry(token.clone())
                    .or_default()
                    .add(id, *weight);
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
            self.mark_doc_upserted(&id);
        }

        drop(staged_guard);
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
        // Canonical lock order: `staged` first, live-state guards nested inside
        // `ensure_staged` (matches `commit`).
        let mut staged_guard = self.staged.write();
        let state = self.ensure_staged(&mut staged_guard);

        if let Some(old_doc) = state.docs.remove(id) {
            remove_doc_from_index(&mut state.index, &old_doc, id);
            state.doc_count = state.doc_count.saturating_sub(1);
            state.total_doc_length = state.total_doc_length.saturating_sub(old_doc.doc_length);
        }
        self.mark_doc_removed(id);
        drop(staged_guard);
        Ok(())
    }

    /// Remove a batch of documents from the text index.
    ///
    /// Stages the removals — call [`commit`](Self::commit) to make them visible
    /// to searches.
    pub fn remove_batch(&self, ids: &[Id]) -> Result<(), SearchError> {
        let _span = tracing::info_span!("kin_search.remove_batch", count = ids.len()).entered();
        if ids.is_empty() {
            return Ok(());
        }
        // Canonical lock order: `staged` first, live-state guards nested inside
        // `ensure_staged` (matches `commit`).
        let mut staged_guard = self.staged.write();
        let state = self.ensure_staged(&mut staged_guard);

        for id in ids {
            if let Some(old_doc) = state.docs.remove(id) {
                remove_doc_from_index(&mut state.index, &old_doc, id);
                state.doc_count = state.doc_count.saturating_sub(1);
                state.total_doc_length = state.total_doc_length.saturating_sub(old_doc.doc_length);
            }
        }
        for id in ids {
            self.mark_doc_removed(id);
        }
        drop(staged_guard);
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
        let mut index: HashMap<String, Postings<Id>> = HashMap::new();
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
                index.entry(token.clone()).or_default().add(*id, *weight);
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

        // Replace live state directly, no staging needed. The epoch is bumped
        // while the index write guard is held so a fuzzy reader observes a
        // consistent (index, epoch) pair and rebuilds its trigram candidate
        // index against this vocabulary.
        {
            let mut live = self.index.write();
            *live = index;
            self.index_epoch.fetch_add(1, Ordering::Relaxed);
        }
        *self.docs.write() = docs;
        *self.doc_count.write() = doc_count;
        *self.total_doc_length.write() = total_doc_length;
        // Clear any pending staged state.
        *self.staged.write() = None;
        self.mark_all_segments_dirty();

        Ok(())
    }

    /// Rebuild the entire index from owned documents.
    ///
    /// Intended for very large rebuilds driven by higher-level graph state.
    /// Per-document tokenization — the CPU-dominant work — runs in parallel
    /// across the rayon thread pool; the inverted-index merge then runs serially
    /// over the documents in their original order. The merge order, posting
    /// contents, term frequencies, and BM25 inputs are therefore identical to a
    /// fully serial rebuild regardless of thread scheduling.
    pub fn rebuild_all_owned<I>(&self, documents: I) -> Result<(), SearchError>
    where
        I: IntoIterator<Item = (Id, Vec<(String, f32)>)>,
    {
        let inputs: Vec<(Id, Vec<(String, f32)>)> = documents.into_iter().collect();
        let _span =
            tracing::info_span!("kin_search.rebuild_all_owned", documents = inputs.len()).entered();

        // Tokenize each document independently and in parallel. `par_iter` over a
        // `Vec` is index-ordered, so `collect` restores the source order exactly,
        // making the result independent of how work was scheduled across threads.
        let tokenized: Vec<(Vec<(String, f32)>, usize)> = inputs
            .par_iter()
            .map(|(_, fields)| {
                let mut all_tokens: Vec<(String, f32)> = Vec::new();
                for (text, weight) in fields {
                    for tok in tokenize(text) {
                        all_tokens.push((tok, *weight));
                    }
                }
                let doc_length = all_tokens.len();
                (all_tokens, doc_length)
            })
            .collect();

        // Merge serially in the original document order so postings, per-doc token
        // ordering, and term frequencies match a serial rebuild byte-for-byte.
        let mut index: HashMap<String, Postings<Id>> = HashMap::new();
        let mut docs: HashMap<Id, IndexedDoc> = HashMap::with_capacity(inputs.len());
        let mut doc_count = 0usize;
        let mut total_doc_length = 0usize;

        for ((id, _fields), (all_tokens, doc_length)) in inputs.into_iter().zip(tokenized) {
            for (token, weight) in &all_tokens {
                index.entry(token.clone()).or_default().add(id, *weight);
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

        {
            let mut live = self.index.write();
            *live = index;
            self.index_epoch.fetch_add(1, Ordering::Relaxed);
        }
        *self.docs.write() = docs;
        *self.doc_count.write() = doc_count;
        *self.total_doc_length.write() = total_doc_length;
        *self.staged.write() = None;
        self.mark_all_segments_dirty();

        Ok(())
    }

    /// Commit all pending writes, making staged changes visible to searches.
    ///
    /// Call after bulk operations rather than per document for best performance.
    ///
    /// # Lock ordering
    ///
    /// Acquires `staged` first, then the live-state write guards to publish the
    /// snapshot — the **same** canonical order the writer paths use
    /// ([`upsert`](Self::upsert)/[`remove`](Self::remove) take `staged` then the
    /// live guards via [`ensure_staged`](Self::ensure_staged)). Because both
    /// directions agree that `staged` is the outermost lock, a writer and a
    /// committer can never request the two locks in opposite order, so the
    /// lock-order-inversion deadlock cannot occur.
    ///
    /// `staged` is deliberately held across `persist_to_disk` as well. All live
    /// state is mutated only under `staged` (here, and in the writer paths via
    /// [`ensure_staged`](Self::ensure_staged)), so holding it for the duration of
    /// the persist is what gives the persist a *consistent snapshot* of the four
    /// live-state fields. Without it, two concurrent committers (or a persist
    /// racing a publish) could serialize segment bytes from one moment but stamp
    /// the manifest `doc_count`/`total_doc_length` from another, and the
    /// load-time segment-sum check would (correctly) reject the torn index as
    /// corrupt. Serializing commits on `staged` is the price of a
    /// crash-consistent on-disk image; it stays within the canonical order
    /// (`staged` -> live-state -> `seg`), so it introduces no new inversion.
    pub fn commit(&self) -> Result<(), SearchError>
    where
        Id: Serialize + DeserializeOwned,
    {
        let _span = tracing::info_span!("kin_search.commit", staged = self.staged.read().is_some())
            .entered();
        let mut staged_guard = self.staged.write();
        if let Some(state) = staged_guard.take() {
            {
                let mut live = self.index.write();
                *live = state.index;
                self.index_epoch.fetch_add(1, Ordering::Relaxed);
            }
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

        // Substring/fuzzy matching is sublinear in vocabulary size: a trigram
        // candidate index (built lazily, reused until the live index changes)
        // replaces the former full vocabulary scan. It is consulted only for
        // query tokens long enough to take the substring branch, so a query of
        // purely short tokens skips the build entirely.
        let needs_substring = query_tokens.iter().any(|qt| qt.len() >= MIN_SUBSTRING_LEN);
        let trigram_guard = if needs_substring {
            let epoch = self.index_epoch.load(Ordering::Relaxed);
            let current = {
                let cache = self.trigram.read();
                matches!(cache.as_ref(), Some(t) if t.epoch == epoch)
            };
            if !current {
                let built = TrigramIndex::build(&index, epoch);
                let mut cache = self.trigram.write();
                // The epoch cannot advance while this read guard on `index` is
                // held, so any entry already present for this epoch (rebuilt by a
                // concurrent query) is equivalent — only install ours if absent.
                if !matches!(cache.as_ref(), Some(t) if t.epoch == epoch) {
                    *cache = Some(built);
                }
            }
            Some(self.trigram.read())
        } else {
            None
        };

        let idf_of = |postings: &Postings<Id>| -> f32 {
            let df = postings.doc_count() as f32;
            // BM25 IDF: log((N - df + 0.5) / (df + 0.5) + 1)
            ((n - df + 0.5) / (df + 0.5) + 1.0).ln().max(0.0)
        };

        // Assemble scoring terms in the exact order a serial scan would visit
        // them: for each query token, the exact-match posting first, then each
        // substring match in sorted-token order. Float addition is
        // non-associative, so fixing this order is what lets the per-entity
        // reduction below fan out across threads yet stay bit-identical to a
        // serial accumulation. `penalty` is 1.0 for an exact match and 0.5 for a
        // substring match; multiplying by 1.0 is exact, so the unified form
        // reproduces the former exact-match score bit-for-bit.
        let mut scoring_terms: Vec<(f32, f32, &Postings<Id>)> = Vec::new();
        for qt in &query_tokens {
            if let Some(postings) = index.get(qt) {
                scoring_terms.push((idf_of(postings), 1.0, postings));
            }

            if qt.len() >= MIN_SUBSTRING_LEN {
                let trigram = trigram_guard
                    .as_ref()
                    .and_then(|g| g.as_ref())
                    .expect("trigram index populated for substring query");
                let candidates = trigram.candidate_ids(qt);
                // Identical predicate to a full vocabulary scan; every cached
                // token already satisfies the minimum-length bound. The trigram
                // candidate set is a complete superset of the matches, so the
                // resulting set — sorted for deterministic accumulation — is
                // exactly what a full scan would produce.
                let mut matched: Vec<&str> = candidates
                    .iter()
                    .filter_map(|&token_id| {
                        let token = trigram.tokens[token_id as usize].as_ref();
                        (token != qt.as_str()
                            && (token.contains(qt.as_str()) || qt.contains(token)))
                        .then_some(token)
                    })
                    .collect();
                matched.sort_unstable();
                for token in matched {
                    if let Some(postings) = index.get(token) {
                        scoring_terms.push((idf_of(postings), 0.5, postings));
                    }
                }
            }
        }

        // The trigram arena is no longer referenced once terms are assembled
        // (terms borrow `index`, not the arena), so release it before scoring.
        drop(trigram_guard);

        // Score each matched entity by summing its term contributions in
        // canonical order (term order, then field order within a term). Float
        // addition is non-associative, so both paths below fix that order and
        // give one entity a single private accumulator — never a cross-thread
        // reduction — which makes them bit-for-bit identical to each other and to
        // a fully serial scan. The parallel path is taken only when there is
        // enough scoring work to outweigh dispatch cost and the ambient pool has
        // more than one worker, so it trades latency only, never results.
        let total_occurrences: usize = scoring_terms.iter().map(|(_, _, p)| p.len()).sum();
        let scored: Vec<(Id, f32)> =
            if total_occurrences >= PARALLEL_SCORE_THRESHOLD && rayon::current_num_threads() > 1 {
                // Collect the distinct candidate entities, then score each by probing
                // every term. No per-entity allocation: each worker reads shared
                // posting maps and owns only its own running sum.
                let mut candidates: HashSet<Id> = HashSet::new();
                for (_, _, postings) in &scoring_terms {
                    candidates.extend(postings.by_doc.keys().copied());
                }
                let candidates: Vec<Id> = candidates.into_iter().collect();
                let docs_ref: &HashMap<Id, IndexedDoc> = &docs;
                let terms_ref = &scoring_terms;
                candidates
                    .par_iter()
                    .map(|eid| {
                        let dl = docs_ref
                            .get(eid)
                            .map(|d| d.doc_length as f32)
                            .unwrap_or(avgdl);
                        // The document-length factor depends only on this entity's
                        // `dl`, constant across its terms, so hoist it once.
                        let length_norm = BM25_K1 * (1.0 - BM25_B + BM25_B * dl / avgdl);
                        let mut score = 0.0f32;
                        for (idf, penalty, postings) in terms_ref {
                            if let Some(weights) = postings.by_doc.get(eid) {
                                for weight in weights {
                                    let tf = *weight;
                                    let tf_saturated = (tf * (BM25_K1 + 1.0)) / (tf + length_norm);
                                    score += (idf * tf_saturated) * penalty;
                                }
                            }
                        }
                        (*eid, score)
                    })
                    .collect()
            } else {
                // Serial single-pass accumulation in the same canonical order.
                let mut scores: HashMap<Id, f32> = HashMap::new();
                for (idf, penalty, postings) in &scoring_terms {
                    for (eid, weight) in postings.iter() {
                        let dl = docs.get(eid).map(|d| d.doc_length as f32).unwrap_or(avgdl);
                        let tf = *weight;
                        let tf_saturated = (tf * (BM25_K1 + 1.0))
                            / (tf + BM25_K1 * (1.0 - BM25_B + BM25_B * dl / avgdl));
                        *scores.entry(*eid).or_insert(0.0) += (idf * tf_saturated) * penalty;
                    }
                }
                scores.into_iter().collect()
            };

        // Sort by score descending, then by a stable id tie-break so results are
        // deterministic regardless of the HashMap's process-randomized iteration
        // order (otherwise tied scores at the `truncate(limit)` cutoff vary run to
        // run). DocId guarantees Debug but not Ord, so tie-break on the Debug repr,
        // precomputed once to keep the comparator allocation-free.
        let mut keyed: Vec<(String, Id, f32)> = scored
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
        let index = Self::with_path(if persist_changes {
            Some(storage_path.clone())
        } else {
            None
        });

        // Auto-detect the on-disk format independently of the write-side flag, so
        // toggling `KIN_SEARCH_INCREMENTAL_PERSIST` is safe in both directions: a
        // segmented index opened with the flag off still loads (and the next
        // monolithic commit retires it), and vice-versa.
        if manifest_path(&storage_path).exists() {
            let loaded = Self::load_segmented(&storage_path, persist_changes)?;
            *index.index.write() = loaded.index;
            index.index_epoch.fetch_add(1, Ordering::Relaxed);
            *index.docs.write() = loaded.docs;
            *index.doc_count.write() = loaded.doc_count;
            *index.total_doc_length.write() = loaded.total_doc_length;
            *index.graph_root_hash.write() = loaded.graph_root_hash;
            let mut seg = index.seg.write();
            seg.segment_count = loaded.segment_count;
            seg.baseline_gens = Some(loaded.baseline_gens);
            seg.segment_docs = Some(loaded.segment_docs);
            seg.dirty = SegmentDirty::Tracked(HashSet::new());
        } else if let Some(persisted) = Self::load_persisted(&storage_path, persist_changes)? {
            *index.index.write() = persisted.index;
            index.index_epoch.fetch_add(1, Ordering::Relaxed);
            *index.docs.write() = persisted.docs;
            *index.doc_count.write() = persisted.doc_count;
            *index.total_doc_length.write() = persisted.total_doc_length;
            *index.graph_root_hash.write() = persisted.graph_root_hash;
            // Monolithic on disk: no segmented baseline, so a first segmented
            // persist (if the flag is on) performs a full establishing rewrite.
        }

        Ok(index)
    }

    fn load_persisted(
        storage_path: &Path,
        archive_corrupt: bool,
    ) -> Result<Option<PersistedIndex<Id>>, SearchError> {
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

        // `bincode`'s default (fixint, little-endian) encoding writes the
        // leading `version: u32` field as the first four bytes, so we can read
        // the format version without first committing to a struct layout. That
        // is what lets older (v1) indexes be migrated forward instead of being
        // rejected as "unsupported".
        if bytes.len() < 4 {
            return Err(corrupt_index_error(
                storage_path,
                format!("truncated ({} bytes)", bytes.len()),
                archive_corrupt,
            ));
        }
        let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

        let _span = tracing::info_span!(
            "kin_search.load_persisted.deserialize",
            bytes = bytes.len(),
            version = version
        )
        .entered();

        if version == PersistedIndex::<Id>::VERSION {
            let persisted: PersistedIndex<Id> = match bincode::deserialize(&bytes) {
                Ok(persisted) => persisted,
                Err(err) => {
                    return Err(corrupt_index_error(
                        storage_path,
                        format!("undecodable (declared v{version}): {err}"),
                        archive_corrupt,
                    ));
                }
            };
            if persisted.version != PersistedIndex::<Id>::VERSION {
                return Err(corrupt_index_error(
                    storage_path,
                    format!(
                        "declared version {version} but decoded version {}",
                        persisted.version
                    ),
                    archive_corrupt,
                ));
            }
            Ok(Some(persisted))
        } else if version == 1 {
            // Migrate the legacy flat-`Vec` posting layout forward in memory.
            // The next `commit()` re-persists in the current (v2) format.
            let v1: PersistedIndexV1<Id> = match bincode::deserialize(&bytes) {
                Ok(v1) => v1,
                Err(err) => {
                    return Err(corrupt_index_error(
                        storage_path,
                        format!("undecodable (declared v1): {err}"),
                        archive_corrupt,
                    ));
                }
            };
            if v1.version != 1 {
                return Err(corrupt_index_error(
                    storage_path,
                    format!("declared version 1 but decoded version {}", v1.version),
                    archive_corrupt,
                ));
            }
            tracing::info!(
                path = %storage_path.display(),
                "migrating text index from format v1 to v{}",
                PersistedIndex::<Id>::VERSION
            );
            Ok(Some(PersistedIndex {
                version: PersistedIndex::<Id>::VERSION,
                index: migrate_v1_index(v1.index),
                docs: v1.docs,
                doc_count: v1.doc_count,
                total_doc_length: v1.total_doc_length,
                graph_root_hash: v1.graph_root_hash,
            }))
        } else {
            // An unknown version is unloadable by this build. Because the index
            // is fully derived from graph-owned truth, archiving the foreign file
            // and signalling rebuild-needed is safe and avoids bricking the
            // daemon on a format it cannot parse.
            Err(corrupt_index_error(
                storage_path,
                format!("unsupported version {version}"),
                archive_corrupt,
            ))
        }
    }

    /// Persist the live index to disk.
    ///
    /// Dispatches on the cached write-strategy flag: by default, the segmented
    /// path rewrites only changed segments; when `KIN_SEARCH_INCREMENTAL_PERSIST`
    /// explicitly disables it, the legacy monolithic path rewrites the full
    /// bincode file.
    fn persist_to_disk(&self) -> Result<(), SearchError> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };

        if self.incremental_enabled {
            self.persist_segmented(path)
        } else {
            self.persist_monolithic(path)?;
            // Transition safety: if this index was previously segmented, the
            // monolithic file we just wrote is now the truth — retire the stale
            // manifest so load stops preferring the (now-orphaned) segments.
            self.retire_segmented_artifacts(path);
            Ok(())
        }
    }

    /// The original full-index persist: serialize the entire index with
    /// `bincode` and publish it via a fsynced temp + atomic rename. O(full index)
    /// per call — the scaling cost the segmented path exists to avoid — but a
    /// simple crash-safe fallback when incremental persistence is disabled.
    fn persist_monolithic(&self, path: &Path) -> Result<(), SearchError> {
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
        // Atomic-durable write: encode to a unique temp file, fsync its bytes,
        // rename it into place, then fsync the directory so the rename itself
        // survives a crash. A fixed `.tmp` name plus a non-fsynced write is the
        // torn-write class this guards against.
        let seq = PERSIST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = unique_tmp_path(path, seq);
        write_file_durably(&tmp_path, &encoded).map_err(|err| {
            let _ = std::fs::remove_file(&tmp_path);
            SearchError::IndexError(format!(
                "failed to write text index {}: {err}",
                tmp_path.display()
            ))
        })?;
        std::fs::rename(&tmp_path, path).map_err(|err| {
            let _ = std::fs::remove_file(&tmp_path);
            SearchError::IndexError(format!(
                "failed to promote text index {} -> {}: {err}",
                tmp_path.display(),
                path.display()
            ))
        })?;
        sync_parent_dir(path);
        Ok(())
    }

    /// Segmented/incremental persist: after the first segmented baseline is
    /// established, visit only changed segments, re-serialize and durably write
    /// them, and finally swap in a small manifest. The manifest is the single
    /// atomic commit point: every referenced segment file is fsynced before it
    /// is named, so a crash leaves either the old manifest (old segments) or the
    /// new one (all new/kept segments present) — never a torn, half-applied set.
    fn persist_segmented(&self, path: &Path) -> Result<(), SearchError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                SearchError::IndexError(format!(
                    "failed to create text index directory {}: {err}",
                    parent.display()
                ))
            })?;
        }

        let docs = self.docs.read();
        let doc_count = *self.doc_count.read();
        let total_doc_length = *self.total_doc_length.read();
        let graph_root_hash = *self.graph_root_hash.read();

        let mut seg = self.seg.write();
        let segment_count = match &seg.baseline_gens {
            Some(gens) => gens.len().max(1),
            None => seg.segment_count.max(1),
        };
        // A full rewrite is required when there is no segmented baseline to delta
        // from (fresh index, or one just loaded from the monolithic format) or
        // after a `rebuild_all` marked every segment dirty.
        let rewrite_all = seg.baseline_gens.is_none() || matches!(seg.dirty, SegmentDirty::All);
        let dirty: Vec<usize> = if rewrite_all {
            (0..segment_count).collect()
        } else {
            match &seg.dirty {
                SegmentDirty::Tracked(set) => set.iter().copied().collect(),
                SegmentDirty::All => (0..segment_count).collect(),
            }
        };

        let rebuild_segment_docs = rewrite_all || seg.segment_docs.is_none();
        let mut buckets: Vec<Vec<Id>> = vec![Vec::new(); segment_count];
        if rebuild_segment_docs {
            // First segmented establishment and full rebuilds intentionally walk
            // the whole corpus because every segment is the changed set.
            for id in docs.keys() {
                buckets[segment_of(id, segment_count)].push(*id);
            }
        } else {
            // Once a segmented baseline exists, segment membership lets small
            // commits walk only the dirty segments instead of rebucketing every
            // live doc id on each persist.
            let segment_docs = seg
                .segment_docs
                .as_ref()
                .expect("checked by rebuild_segment_docs");
            for &s in &dirty {
                for id in &segment_docs[s] {
                    if docs.contains_key(id) {
                        buckets[s].push(*id);
                    }
                }
            }
        }

        let old_gens: Vec<Option<u64>> = match &seg.baseline_gens {
            Some(gens) => gens.clone(),
            None => vec![None; segment_count],
        };
        let mut new_gens = old_gens.clone();

        // Re-serialize and durably write each dirty segment under a fresh
        // generation (an immutable new file — never an in-place overwrite).
        for &s in &dirty {
            let ids = &buckets[s];
            if ids.is_empty() {
                // The segment is now empty: it gets no file and a `None` gen.
                new_gens[s] = None;
                continue;
            }
            let mut seg_index: HashMap<String, Postings<Id>> = HashMap::new();
            let mut seg_docs: HashMap<Id, IndexedDoc> = HashMap::with_capacity(ids.len());
            let mut seg_doc_count = 0usize;
            let mut seg_total_len = 0usize;
            for id in ids {
                let doc = &docs[id];
                // Reconstruct this doc's postings from its stored tokens in the
                // exact same order `upsert`/`rebuild_all` built the global index,
                // so the merged-on-load result is byte-for-byte the same index.
                for (token, weight) in &doc.tokens_by_field {
                    seg_index
                        .entry(token.clone())
                        .or_default()
                        .add(*id, *weight);
                }
                seg_doc_count += 1;
                seg_total_len += doc.doc_length;
                seg_docs.insert(*id, doc.clone());
            }
            let seg_data = SegmentData {
                index: seg_index,
                docs: seg_docs,
                doc_count: seg_doc_count,
                total_doc_length: seg_total_len,
            };
            let encoded = bincode::serialize(&seg_data).map_err(|err| {
                SearchError::IndexError(format!("failed to encode text index segment {s}: {err}"))
            })?;
            let new_gen = old_gens[s].map(|g| g.wrapping_add(1)).unwrap_or(0);
            let seg_file = segment_path(path, s, new_gen);
            let seq = PERSIST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let tmp = unique_tmp_path(&seg_file, seq);
            write_file_durably(&tmp, &encoded).map_err(|err| {
                let _ = std::fs::remove_file(&tmp);
                SearchError::IndexError(format!(
                    "failed to write text index segment {}: {err}",
                    tmp.display()
                ))
            })?;
            std::fs::rename(&tmp, &seg_file).map_err(|err| {
                let _ = std::fs::remove_file(&tmp);
                SearchError::IndexError(format!(
                    "failed to promote text index segment {} -> {}: {err}",
                    tmp.display(),
                    seg_file.display()
                ))
            })?;
            sync_parent_dir(&seg_file);
            new_gens[s] = Some(new_gen);
        }

        // Publish the manifest — the atomic commit point.
        let manifest = SegmentManifest {
            version: SEGMENTED_FORMAT_VERSION,
            segment_count,
            segment_gens: new_gens.clone(),
            doc_count,
            total_doc_length,
            graph_root_hash,
        };
        let m_encoded = bincode::serialize(&manifest).map_err(|err| {
            SearchError::IndexError(format!("failed to encode text index manifest: {err}"))
        })?;
        let m_path = manifest_path(path);
        let seq = PERSIST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let m_tmp = unique_tmp_path(&m_path, seq);
        write_file_durably(&m_tmp, &m_encoded).map_err(|err| {
            let _ = std::fs::remove_file(&m_tmp);
            SearchError::IndexError(format!(
                "failed to write text index manifest {}: {err}",
                m_tmp.display()
            ))
        })?;
        std::fs::rename(&m_tmp, &m_path).map_err(|err| {
            let _ = std::fs::remove_file(&m_tmp);
            SearchError::IndexError(format!(
                "failed to promote text index manifest {} -> {}: {err}",
                m_tmp.display(),
                m_path.display()
            ))
        })?;
        sync_parent_dir(&m_path);

        let mut new_segment_docs = if rebuild_segment_docs {
            let mut rebuilt = vec![HashSet::new(); segment_count];
            for (s, ids) in buckets.iter().enumerate() {
                rebuilt[s].extend(ids.iter().copied());
            }
            rebuilt
        } else {
            let mut kept = seg
                .segment_docs
                .clone()
                .unwrap_or_else(|| vec![HashSet::new(); segment_count]);
            for &s in &dirty {
                kept[s].clear();
                kept[s].extend(buckets[s].iter().copied());
            }
            kept
        };
        new_segment_docs.truncate(segment_count);
        while new_segment_docs.len() < segment_count {
            new_segment_docs.push(HashSet::new());
        }

        // Committed. Adopt the new generations as the baseline and clear dirt.
        seg.baseline_gens = Some(new_gens.clone());
        seg.segment_count = segment_count;
        seg.segment_docs = Some(new_segment_docs);
        seg.dirty = SegmentDirty::Tracked(HashSet::new());
        drop(seg);
        drop(docs);

        // Best-effort GC of files the new manifest no longer references: prior
        // generations of rewritten segments, and any stale monolithic file this
        // segmented index supersedes. Orphans are harmless (load only follows the
        // manifest); this just reclaims space.
        for s in 0..segment_count {
            if let Some(old) = old_gens[s] {
                if new_gens[s] != Some(old) {
                    let _ = std::fs::remove_file(segment_path(path, s, old));
                }
            }
        }
        let _ = std::fs::remove_file(path);
        Ok(())
    }

    /// Load a segmented index: read the manifest (the version gate), then read
    /// and merge every referenced segment into a single in-memory index that is
    /// identical to what a monolithic load of the same data would produce. A
    /// missing/undecodable manifest or segment, or any cross-segment duplicate
    /// doc id, is reported as a typed [`SearchError::CorruptIndex`] (the manifest
    /// is archived) so the consumer rebuilds rather than serving a partial index.
    fn load_segmented(
        storage_path: &Path,
        archive_corrupt: bool,
    ) -> Result<LoadedSegmented<Id>, SearchError> {
        let m_path = manifest_path(storage_path);
        let bytes = std::fs::read(&m_path).map_err(|err| {
            SearchError::IndexError(format!(
                "failed to read text index manifest {}: {err}",
                m_path.display()
            ))
        })?;
        if bytes.len() < 4 {
            return Err(corrupt_index_error(
                &m_path,
                format!("truncated manifest ({} bytes)", bytes.len()),
                archive_corrupt,
            ));
        }
        let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if version != SEGMENTED_FORMAT_VERSION {
            return Err(corrupt_index_error(
                &m_path,
                format!("unsupported segmented manifest version {version}"),
                archive_corrupt,
            ));
        }
        let manifest: SegmentManifest = bincode::deserialize(&bytes).map_err(|err| {
            corrupt_index_error(
                &m_path,
                format!("undecodable manifest: {err}"),
                archive_corrupt,
            )
        })?;
        if manifest.version != SEGMENTED_FORMAT_VERSION {
            return Err(corrupt_index_error(
                &m_path,
                format!(
                    "declared version {version} but decoded version {}",
                    manifest.version
                ),
                archive_corrupt,
            ));
        }
        if manifest.segment_gens.len() != manifest.segment_count {
            return Err(corrupt_index_error(
                &m_path,
                format!(
                    "manifest segment_count {} disagrees with {} gen entries",
                    manifest.segment_count,
                    manifest.segment_gens.len()
                ),
                archive_corrupt,
            ));
        }

        let mut index: HashMap<String, Postings<Id>> = HashMap::new();
        let mut docs: HashMap<Id, IndexedDoc> = HashMap::new();
        let mut segment_docs: Vec<HashSet<Id>> = vec![HashSet::new(); manifest.segment_count];
        let mut doc_count = 0usize;
        let mut total_doc_length = 0usize;

        for (s, gen_opt) in manifest.segment_gens.iter().enumerate() {
            let Some(gen) = gen_opt else {
                continue;
            };
            let seg_file = segment_path(storage_path, s, *gen);
            let seg_bytes = std::fs::read(&seg_file).map_err(|err| {
                corrupt_index_error(
                    &m_path,
                    format!("missing/unreadable segment {s} gen {gen}: {err}"),
                    archive_corrupt,
                )
            })?;
            let seg_data: SegmentData<Id> = bincode::deserialize(&seg_bytes).map_err(|err| {
                corrupt_index_error(
                    &m_path,
                    format!("undecodable segment {s} gen {gen}: {err}"),
                    archive_corrupt,
                )
            })?;

            // Merge this segment's postings. Doc sets are disjoint across
            // segments, so this is a pure union; a collision means the on-disk
            // segmentation drifted (e.g. a hash-impl change) — surface it as
            // corruption rather than silently double-counting.
            for (token, postings) in seg_data.index {
                let entry = index.entry(token).or_default();
                for (id, weights) in postings.by_doc {
                    let occ = weights.len();
                    if entry.by_doc.insert(id, weights).is_some() {
                        return Err(corrupt_index_error(
                            &m_path,
                            format!("duplicate doc id in postings (segment {s})"),
                            archive_corrupt,
                        ));
                    }
                    entry.occurrences += occ;
                }
            }
            for (id, doc) in seg_data.docs {
                segment_docs[s].insert(id);
                if docs.insert(id, doc).is_some() {
                    return Err(corrupt_index_error(
                        &m_path,
                        format!("duplicate doc id across segments (segment {s})"),
                        archive_corrupt,
                    ));
                }
            }
            doc_count += seg_data.doc_count;
            total_doc_length += seg_data.total_doc_length;
        }

        if doc_count != manifest.doc_count || total_doc_length != manifest.total_doc_length {
            return Err(corrupt_index_error(
                &m_path,
                format!(
                    "segment sums ({doc_count} docs / {total_doc_length} len) disagree with manifest ({} / {})",
                    manifest.doc_count, manifest.total_doc_length
                ),
                archive_corrupt,
            ));
        }

        Ok(LoadedSegmented {
            index,
            docs,
            doc_count,
            total_doc_length,
            graph_root_hash: manifest.graph_root_hash,
            segment_count: manifest.segment_count,
            baseline_gens: manifest.segment_gens,
            segment_docs,
        })
    }

    /// Remove a stale segmented manifest (and orphaned segment files) when the
    /// canonical on-disk format reverts to monolithic. The manifest unlink is the
    /// transition commit point: before it, load follows the old segments; after
    /// it, load follows the freshly-written `index.bin`. Best-effort.
    fn retire_segmented_artifacts(&self, path: &Path) {
        let m_path = manifest_path(path);
        if !m_path.exists() {
            return;
        }
        let _ = std::fs::remove_file(&m_path);
        sync_parent_dir(&m_path);
        for file in kinseg_sibling_files(path) {
            let _ = std::fs::remove_file(file);
        }
        let mut seg = self.seg.write();
        seg.baseline_gens = None;
        seg.segment_docs = None;
        seg.dirty = SegmentDirty::All;
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

    /// Reference tokenizer using the original linear `tokens.contains` dedup. The
    /// production [`tokenize`] replaces that O(n^2) per-segment scan with an O(1)
    /// `seen` set and must reproduce this output token-for-token, order included.
    fn tokenize_linear_scan_ref(text: &str) -> Vec<String> {
        let mut tokens: Vec<String> = Vec::new();
        for segment in text.split(|c: char| !c.is_alphanumeric()) {
            if segment.is_empty() {
                continue;
            }
            let mut current = String::new();
            let chars: Vec<char> = segment.chars().collect();
            for i in 0..chars.len() {
                if i > 0
                    && chars[i].is_uppercase()
                    && chars[i - 1].is_lowercase()
                    && !current.is_empty()
                {
                    let lower = current.to_lowercase();
                    if !lower.is_empty() {
                        tokens.push(lower);
                    }
                    current.clear();
                }
                current.push(chars[i]);
            }
            if !current.is_empty() {
                let lower = current.to_lowercase();
                if !lower.is_empty() {
                    tokens.push(lower);
                }
            }
            let full = segment.to_lowercase();
            if full.len() > 1 && !tokens.contains(&full) {
                tokens.push(full);
            }
        }
        tokens
    }

    #[test]
    fn tokenize_dedup_matches_linear_scan() {
        let long_mixed = "segABCdefGHIjkl ".repeat(64);
        let long_repeat = "repeat ".repeat(512);
        let cases: &[&str] = &[
            "",
            "x",
            "ab",
            "parse",
            "parseTableFromHtml",
            "parse_table_html",
            "src/io/ascii/html.py",
            "foo foo foo",
            "foobar fooBar",
            "fooBar foobar",
            "renderWidget widgetFactory render render",
            "caféMenu CaféMenu café_menu",
            "ALLCAPS allCaps all_caps ALLCAPS",
            "a ab abc abcd abcde",
            "one_two_three_four_five_six_seven",
            &long_mixed,
            &long_repeat,
        ];
        for case in cases {
            assert_eq!(
                tokenize(case),
                tokenize_linear_scan_ref(case),
                "tokenize diverged from linear-scan reference for {case:?}"
            );
        }
    }

    #[test]
    fn tokenize_dedup_drops_full_segment_already_emitted() {
        // A single-word segment's whole-segment token equals its only camelCase
        // part, so it is emitted exactly once.
        assert_eq!(tokenize("parse"), vec!["parse".to_string()]);
        // A multi-word segment whose lowercased whole form already appeared as an
        // earlier token is de-duplicated — `foobar` is not repeated — while the
        // first-occurrence order of every distinct token is preserved.
        assert_eq!(
            tokenize("foobar fooBar"),
            vec!["foobar".to_string(), "foo".to_string(), "bar".to_string()]
        );
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

    /// Removing a document must cost work proportional ONLY to that document's
    /// own occurrences — never to the (corpus-sized) length of a hot token's
    /// posting list. This is the property that keeps bulk re-index linear; the
    /// old flat-`Vec` `retain` made it O(corpus) per removal, i.e. O(n²) overall.
    /// Operation-count based (not timing) so it is deterministic and not flaky.
    #[test]
    fn removal_touches_only_the_docs_own_postings() {
        fn removal_work(corpus: usize) -> usize {
            let mut index: HashMap<String, Postings<TestId>> = HashMap::new();
            let mut docs: HashMap<TestId, IndexedDoc> = HashMap::new();
            for i in 0..corpus {
                let id = TestId(i as u64);
                // Every doc shares the high-frequency token "shared" (its posting
                // list grows to `corpus`) plus one unique token.
                let tokens = vec![("shared".to_string(), 1.0), (format!("uniq{i}"), 1.0)];
                for (tok, w) in &tokens {
                    index.entry(tok.clone()).or_default().add(id, *w);
                }
                docs.insert(
                    id,
                    IndexedDoc {
                        tokens_by_field: tokens,
                        doc_length: 2,
                    },
                );
            }
            let target = TestId(0);
            let doc = docs.get(&target).cloned().unwrap();
            remove_doc_from_index(&mut index, &doc, &target)
        }

        let small = removal_work(100);
        let large = removal_work(10_000);
        // 100x larger corpus (and 100x longer "shared" posting list) must not
        // change the removal cost for a single document.
        assert_eq!(
            small, large,
            "removal work must be independent of corpus size (was {small} vs {large})"
        );
        // And that cost is exactly the doc's own occurrences: shared + unique.
        assert_eq!(large, 2, "removal must touch only the doc's own postings");
    }

    /// Re-upserting the same document repeatedly must not let stale postings
    /// accumulate: the keyed map replaces, it does not append. Guards BM25 df.
    #[test]
    fn reupsert_does_not_bloat_posting_lists() {
        let idx = TextIndex::<TestId>::new();
        let id = next_id();
        for _ in 0..50 {
            idx.upsert(id, &[("stableToken", 5.0), ("src/file.rs", 2.0)])
                .unwrap();
        }
        idx.commit().unwrap();
        // Exactly one live document, regardless of how many times it was upserted.
        assert_eq!(idx.live_document_count(), 1);
        let token_count = {
            let index = idx.index.read();
            index.get("stable").map(|p| p.len()).unwrap_or(0)
        };
        // "stable" occurs once per upsert of the single doc — re-upsert replaces
        // rather than appends, so the posting count stays at 1 (not 50).
        assert_eq!(
            token_count, 1,
            "re-upsert must not accumulate stale postings"
        );
    }

    /// BM25 IDF uses the number of *unique documents* containing a token, not the
    /// total occurrence count.  When one document repeats a token many times the
    /// occurrence count diverges from the unique-doc count; `doc_frequency` must
    /// report unique-doc count and IDF must be computed from that.
    #[test]
    fn bm25_df_counts_unique_documents_not_occurrences() {
        let idx = TextIndex::<TestId>::new();
        let single_doc = next_id();
        // Index one document with "sparseToken" appearing 10 times (via 10 fields).
        let fields: Vec<(&str, f32)> = vec![
            ("sparseToken", 1.0),
            ("sparseToken", 1.0),
            ("sparseToken", 1.0),
            ("sparseToken", 1.0),
            ("sparseToken", 1.0),
            ("sparseToken", 1.0),
            ("sparseToken", 1.0),
            ("sparseToken", 1.0),
            ("sparseToken", 1.0),
            ("sparseToken", 1.0),
        ];
        idx.upsert(single_doc, &fields).unwrap();
        idx.commit().unwrap();

        let df = idx.doc_frequency("sparseToken");
        assert_eq!(
            df, 1,
            "doc_frequency must count distinct documents (1), not total occurrences (10)"
        );

        // IDF-derived ranking: add a second document with the token once; both
        // docs should score the same since IDF is identical for them.
        let second_doc = next_id();
        idx.upsert(second_doc, &[("sparseToken", 1.0)]).unwrap();
        idx.commit().unwrap();

        let df2 = idx.doc_frequency("sparseToken");
        assert_eq!(
            df2, 2,
            "df must be 2 after two distinct documents contain the token"
        );
    }

    /// A format-v1 index on disk (flat `Vec` posting lists) must load, migrate
    /// forward, and keep serving searches; the next commit re-persists as v2.
    #[test]
    fn migrates_v1_format_index_on_open() {
        #[derive(Serialize)]
        struct V1Mirror {
            version: u32,
            index: HashMap<String, Vec<(TestId, f32)>>,
            docs: HashMap<TestId, IndexedDoc>,
            doc_count: usize,
            total_doc_length: usize,
            graph_root_hash: Option<[u8; 32]>,
        }

        fn build_v1_bytes(id: TestId, doc: &TestDoc) -> Vec<u8> {
            // Mirror exactly what `upsert` would have produced under v1.
            let mut all_tokens: Vec<(String, f32)> = Vec::new();
            for (text, weight) in doc.search_fields() {
                for tok in tokenize(text) {
                    all_tokens.push((tok, weight));
                }
            }
            let doc_length = all_tokens.len();
            let mut index: HashMap<String, Vec<(TestId, f32)>> = HashMap::new();
            for (token, weight) in &all_tokens {
                index.entry(token.clone()).or_default().push((id, *weight));
            }
            let mut docs = HashMap::new();
            docs.insert(
                id,
                IndexedDoc {
                    tokens_by_field: all_tokens,
                    doc_length,
                },
            );
            let v1 = V1Mirror {
                version: 1,
                index,
                docs,
                doc_count: 1,
                total_doc_length: doc_length,
                graph_root_hash: Some([9; 32]),
            };
            bincode::serialize(&v1).unwrap()
        }

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("ti");
        std::fs::create_dir_all(&dir).unwrap();
        let (id, doc) = make_doc("persistMe", "src/persist.rs", "Function");
        std::fs::write(dir.join("index.bin"), build_v1_bytes(id, &doc)).unwrap();

        let mut idx = TextIndex::<TestId>::open(Some(&dir)).unwrap();
        let results = idx.fuzzy_search("persistMe", 10).unwrap();
        assert!(
            !results.is_empty(),
            "migrated v1 index must still be searchable"
        );
        assert_eq!(results[0].0, id);
        assert_eq!(idx.graph_root_hash(), Some([9; 32]));

        // Re-commit through the legacy monolithic path to verify the current
        // single-file format version.
        idx.incremental_enabled = false;
        idx.commit().unwrap();
        let raw = std::fs::read(dir.join("index.bin")).unwrap();
        let on_disk_version = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        assert_eq!(on_disk_version, TEXT_INDEX_FORMAT_VERSION);

        let reopened = TextIndex::<TestId>::open(Some(&dir)).unwrap();
        let results = reopened.fuzzy_search("persistMe", 10).unwrap();
        assert_eq!(results[0].0, id);
    }

    // -----------------------------------------------------------------------
    // Crash / corruption durability tests
    // -----------------------------------------------------------------------

    /// Build a legacy monolithic persisted index directory holding one
    /// searchable doc and return (tempdir guard, index dir, storage-file-path).
    fn make_persisted_index() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("ti");
        std::fs::create_dir_all(&dir).unwrap();
        let mut idx = TextIndex::<TestId>::open(Some(&dir)).unwrap();
        idx.incremental_enabled = false;
        let (id, doc) = make_doc("persistMe", "src/persist.rs", "Function");
        idx.upsert_searchable(id, &doc).unwrap();
        idx.commit().unwrap();
        let storage = TextIndex::<TestId>::storage_file_path(&dir);
        assert!(storage.exists());
        (tmp, dir, storage)
    }

    fn corrupt_sibling_count(storage: &Path) -> usize {
        let parent = storage.parent().unwrap();
        std::fs::read_dir(parent)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".corrupt-"))
            .count()
    }

    /// A commit must leave no temporary file behind: the temp is fsynced then
    /// renamed atomically into place.
    #[test]
    fn persist_leaves_no_temp_file() {
        let (_tmp, _dir, storage) = make_persisted_index();
        let parent = storage.parent().unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(parent)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "stray temp files remain: {leftovers:?}"
        );
    }

    /// An undecodable index (valid version prefix, garbage body) is reported as
    /// a typed `CorruptIndex`, the bad file is archived as evidence, and the
    /// canonical path is cleared for a clean reopen.
    #[test]
    fn corrupt_index_is_archived_and_typed() {
        let (_tmp, dir, storage) = make_persisted_index();

        let mut bytes = TEXT_INDEX_FORMAT_VERSION.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"this is not a valid bincode index payload");
        std::fs::write(&storage, &bytes).unwrap();

        let err = TextIndex::<TestId>::open(Some(&dir)).err().unwrap();
        match err {
            SearchError::CorruptIndex {
                archived, reason, ..
            } => {
                assert!(reason.contains("undecodable"), "reason was: {reason}");
                assert!(archived.is_some(), "corrupt file should be archived");
            }
            other => panic!("expected CorruptIndex, got {other:?}"),
        }
        // Canonical path cleared, evidence preserved alongside it.
        assert!(
            !storage.exists(),
            "corrupt file must be moved off the canonical path"
        );
        assert_eq!(corrupt_sibling_count(&storage), 1);
    }

    /// A truncated index (fewer than the 4-byte version prefix) is corrupt.
    #[test]
    fn truncated_index_is_corrupt() {
        let (_tmp, dir, storage) = make_persisted_index();
        std::fs::write(&storage, b"ab").unwrap(); // 2 bytes < 4

        let err = TextIndex::<TestId>::open(Some(&dir)).err().unwrap();
        assert!(
            matches!(err, SearchError::CorruptIndex { ref reason, .. } if reason.contains("truncated")),
            "expected truncated CorruptIndex, got {err:?}"
        );
    }

    /// A partially-written index (valid version, body cut short) is corrupt:
    /// this is the torn-write class the fsync-before-rename guards against, and
    /// even if a torn file does land it must be caught on load, not served.
    #[test]
    fn torn_body_is_corrupt() {
        let (_tmp, dir, storage) = make_persisted_index();
        let mut bytes = std::fs::read(&storage).unwrap();
        assert!(bytes.len() > 8);
        bytes.truncate(8); // keep version, drop the rest of the payload
        std::fs::write(&storage, &bytes).unwrap();

        let err = TextIndex::<TestId>::open(Some(&dir)).err().unwrap();
        assert!(
            matches!(err, SearchError::CorruptIndex { .. }),
            "expected CorruptIndex, got {err:?}"
        );
    }

    /// An index written by an unknown (future) format version is unloadable by
    /// this build; it is archived and reported rebuild-needed rather than
    /// bricking the open.
    #[test]
    fn unsupported_version_is_corrupt() {
        let (_tmp, dir, storage) = make_persisted_index();
        let mut bytes = 999u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"future format payload");
        std::fs::write(&storage, &bytes).unwrap();

        let err = TextIndex::<TestId>::open(Some(&dir)).err().unwrap();
        assert!(
            matches!(err, SearchError::CorruptIndex { ref reason, .. } if reason.contains("unsupported version")),
            "expected unsupported-version CorruptIndex, got {err:?}"
        );
    }

    /// After corruption is detected and archived, the store self-heals: because
    /// the bad file was moved aside, a reopen finds a clean (empty) index, and a
    /// rebuild + commit re-persists a valid index that reopens successfully —
    /// mirroring how the kin-db consumer recovers (fall back to empty, rebuild).
    #[test]
    fn reopen_after_corruption_is_clean_and_rebuildable() {
        let (_tmp, dir, storage) = make_persisted_index();

        // Corrupt, then the first open surfaces the typed error + archives it.
        std::fs::write(&storage, b"xy").unwrap();
        let err = TextIndex::<TestId>::open(Some(&dir)).err().unwrap();
        assert!(matches!(err, SearchError::CorruptIndex { .. }));
        assert!(!storage.exists());

        // The next open is clean (no recurrence): the archived file no longer
        // blocks load, so we get a fresh empty index that rebuilds + persists.
        let healed = TextIndex::<TestId>::open(Some(&dir)).unwrap();
        let (id, doc) = make_doc("rebuiltDoc", "src/rebuilt.rs", "Function");
        healed.upsert_searchable(id, &doc).unwrap();
        healed.commit().unwrap();

        let reopened = TextIndex::<TestId>::open(Some(&dir)).unwrap();
        let results = reopened.fuzzy_search("rebuiltDoc", 10).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, id);
    }

    // -----------------------------------------------------------------------
    // Segmented / incremental persistence (KIN_SEARCH_INCREMENTAL_PERSIST)
    //
    // The env flag is read once at construction; tests flip the cached field
    // directly (same-module access) instead of mutating process env, which would
    // race across the parallel test runner.
    // -----------------------------------------------------------------------

    #[test]
    fn incremental_persist_env_defaults_on_and_falsey_values_disable() {
        assert!(incremental_persist_enabled_from_env(None));
        assert!(incremental_persist_enabled_from_env(Some("")));
        assert!(incremental_persist_enabled_from_env(Some("1")));
        assert!(incremental_persist_enabled_from_env(Some("true")));
        assert!(incremental_persist_enabled_from_env(Some("TRUE")));
        assert!(incremental_persist_enabled_from_env(Some("yes")));
        assert!(incremental_persist_enabled_from_env(Some("on")));
        assert!(incremental_persist_enabled_from_env(Some("unexpected")));

        assert!(!incremental_persist_enabled_from_env(Some("0")));
        assert!(!incremental_persist_enabled_from_env(Some("false")));
        assert!(!incremental_persist_enabled_from_env(Some("FALSE")));
        assert!(!incremental_persist_enabled_from_env(Some("no")));
        assert!(!incremental_persist_enabled_from_env(Some("off")));
        assert!(!incremental_persist_enabled_from_env(Some("  off  ")));
    }

    /// A fixed fixture corpus with stable ids, so a monolithic build and a
    /// segmented build over the same data are directly comparable.
    fn fixture_docs() -> Vec<(TestId, TestDoc)> {
        let specs = [
            ("getUserById", "src/users/lookup.rs", "Function"),
            ("deletePost", "src/posts/admin.rs", "Function"),
            ("parseTableFromHtml", "src/io/ascii/html.py", "Function"),
            ("QdpReader", "src/io/qdp.py", "Struct"),
            ("alphaHandler", "src/handlers/alpha.rs", "Function"),
            ("betaProcessor", "src/handlers/beta.rs", "Function"),
            ("computeChecksum", "src/util/hash.rs", "Function"),
            ("renderTemplate", "src/render/template.rs", "Function"),
            ("loadConfig", "src/config/loader.rs", "Function"),
            ("authenticateUser", "src/auth/login.rs", "Function"),
            ("serializeGraph", "src/graph/serialize.rs", "Function"),
            ("tokenizeInput", "src/search/tokenize.rs", "Function"),
            ("mergeSegments", "src/storage/segment.rs", "Function"),
            ("validateSchema", "src/schema/validate.rs", "Function"),
            ("buildIndex", "src/index/builder.rs", "Function"),
            ("queryPlanner", "src/query/planner.rs", "Struct"),
            ("cacheEviction", "src/cache/lru.rs", "Function"),
            ("retryPolicy", "src/net/retry.rs", "Struct"),
            ("decodePayload", "src/net/codec.rs", "Function"),
            ("flushBuffer", "src/io/buffer.rs", "Function"),
        ];
        specs
            .iter()
            .enumerate()
            .map(|(i, (name, file, kind))| {
                let id = TestId(10_000 + i as u64);
                let doc = TestDoc {
                    name: name.to_string(),
                    signature: format!("fn {name}()"),
                    file_path: file.to_string(),
                    kind: kind.to_string(),
                };
                (id, doc)
            })
            .collect()
    }

    const FIXTURE_QUERIES: &[&str] = &[
        "user",
        "parse",
        "table",
        "html",
        "reader",
        "handler",
        "processor",
        "checksum",
        "render",
        "config",
        "auth",
        "graph",
        "tokenize",
        "segment",
        "schema",
        "index",
        "query",
        "cache",
        "retry",
        "decode",
        "buffer",
        "src",
        "rs",
        "py",
        "function",
        "struct",
        "qdp",
        "getUserById",
        "zzz_no_match",
    ];

    /// Build the fixture corpus into `dir` via either the monolithic (default) or
    /// the segmented write path. A small segment count makes the fixtures span
    /// several segments so merge-on-load is genuinely exercised.
    fn build_into(dir: &PathBuf, segmented: bool) -> TextIndex<TestId> {
        let mut idx = TextIndex::<TestId>::open(Some(dir)).unwrap();
        idx.incremental_enabled = segmented;
        if segmented {
            idx.seg.write().segment_count = 8;
        }
        for (id, doc) in fixture_docs() {
            idx.upsert_searchable(id, &doc).unwrap();
        }
        idx.set_graph_root_hash([42; 32]);
        idx.commit().unwrap();
        idx
    }

    fn all_query_results(idx: &TextIndex<TestId>) -> Vec<Vec<(TestId, f32)>> {
        FIXTURE_QUERIES
            .iter()
            .map(|q| idx.fuzzy_search(q, 20).unwrap())
            .collect()
    }

    fn read_manifest_gens(storage: &Path) -> Vec<Option<u64>> {
        let bytes = std::fs::read(manifest_path(storage)).unwrap();
        let manifest: SegmentManifest = bincode::deserialize(&bytes).unwrap();
        manifest.segment_gens
    }

    fn first_present_segment(storage: &Path) -> usize {
        read_manifest_gens(storage)
            .iter()
            .position(|g| g.is_some())
            .expect("at least one present segment")
    }

    /// GOLDEN TEST: a segmented persist + reload yields byte-for-byte identical
    /// retrieval to a monolithic persist + reload over the same corpus. This is
    /// the storage-layer-only guarantee — only *how* the bytes hit disk changes,
    /// never what a query returns.
    #[test]
    fn segmented_persist_is_retrieval_identical_to_monolithic() {
        let tmp = tempfile::tempdir().unwrap();
        let mono_dir = tmp.path().join("mono");
        let seg_dir = tmp.path().join("seg");

        let mono = build_into(&mono_dir, false);
        let seg = build_into(&seg_dir, true);

        // Same data, different write path → identical in-memory results.
        assert_eq!(all_query_results(&mono), all_query_results(&seg));

        // The segmented dir is actually segmented: manifest present, and no
        // monolithic index.bin lingering.
        let seg_storage = TextIndex::<TestId>::storage_file_path(&seg_dir);
        assert!(
            manifest_path(&seg_storage).exists(),
            "segmented manifest must exist"
        );
        assert!(
            !seg_storage.exists(),
            "segmented index must not leave a monolithic index.bin"
        );

        // Reload from each on-disk format (both reopens auto-detect) and compare.
        let mono_reopened = TextIndex::<TestId>::open(Some(&mono_dir)).unwrap();
        let seg_reopened = TextIndex::<TestId>::open(Some(&seg_dir)).unwrap();
        assert_eq!(
            all_query_results(&mono_reopened),
            all_query_results(&seg_reopened)
        );
        assert_eq!(seg_reopened.graph_root_hash(), Some([42; 32]));
        assert_eq!(seg_reopened.live_document_count(), fixture_docs().len());
    }

    /// Incremental persist re-serializes ONLY the segments whose documents
    /// changed: adding one doc bumps exactly its segment's generation and leaves
    /// every other segment file untouched. This is the scaling-cliff fix.
    #[test]
    fn incremental_persist_rewrites_only_the_dirty_segment() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("seg");
        let idx = build_into(&dir, true);
        let storage = TextIndex::<TestId>::storage_file_path(&dir);

        let gens_before = read_manifest_gens(&storage);
        let segment_count = gens_before.len();
        let members_before = idx.seg.read().segment_docs.as_ref().unwrap().clone();
        assert_eq!(members_before.len(), segment_count);

        let new_id = TestId(99_999);
        let new_doc = TestDoc {
            name: "freshlyAddedSymbol".to_string(),
            signature: "fn freshlyAddedSymbol()".to_string(),
            file_path: "src/new/added.rs".to_string(),
            kind: "Function".to_string(),
        };
        idx.upsert_searchable(new_id, &new_doc).unwrap();
        idx.commit().unwrap();

        let gens_after = read_manifest_gens(&storage);
        assert_eq!(gens_after.len(), segment_count);

        let touched = segment_of(&new_id, segment_count);
        let changed: Vec<usize> = (0..segment_count)
            .filter(|&s| gens_before[s] != gens_after[s])
            .collect();
        assert_eq!(
            changed,
            vec![touched],
            "exactly the touched segment must be rewritten (the cliff fix)"
        );
        let members_after = idx.seg.read().segment_docs.as_ref().unwrap().clone();
        assert_eq!(members_after.len(), segment_count);
        for s in 0..segment_count {
            if s == touched {
                assert!(members_after[s].contains(&new_id));
                assert_eq!(members_after[s].len(), members_before[s].len() + 1);
            } else {
                assert_eq!(members_after[s], members_before[s]);
            }
        }

        let reopened = TextIndex::<TestId>::open(Some(&dir)).unwrap();
        let hits = reopened.fuzzy_search("freshlyAddedSymbol", 10).unwrap();
        assert_eq!(hits[0].0, new_id);
        assert_eq!(reopened.live_document_count(), fixture_docs().len() + 1);
    }

    /// Truncating a referenced segment file is caught on load as a typed
    /// `CorruptIndex` (manifest archived for a clean reopen), NEVER served as a
    /// partial/garbled index. The torn-segment crash-consistency contract.
    #[test]
    fn truncated_segment_is_corrupt_not_served() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("seg");
        let _idx = build_into(&dir, true);
        let storage = TextIndex::<TestId>::storage_file_path(&dir);

        let target = first_present_segment(&storage);
        let gen = read_manifest_gens(&storage)[target].unwrap();
        let seg_file = segment_path(&storage, target, gen);
        let mut bytes = std::fs::read(&seg_file).unwrap();
        assert!(bytes.len() > 4);
        bytes.truncate(3);
        std::fs::write(&seg_file, &bytes).unwrap();

        let err = TextIndex::<TestId>::open(Some(&dir)).err().unwrap();
        assert!(
            matches!(err, SearchError::CorruptIndex { .. }),
            "expected CorruptIndex, got {err:?}"
        );
        assert!(
            !manifest_path(&storage).exists(),
            "corrupt manifest must be archived off the canonical path"
        );

        // Self-heals: the next reopen is clean (empty, ready to rebuild).
        let healed = TextIndex::<TestId>::open(Some(&dir)).unwrap();
        assert_eq!(healed.live_document_count(), 0);
    }

    /// A manifest referencing a segment file that no longer exists is corrupt.
    #[test]
    fn missing_segment_is_corrupt() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("seg");
        let _idx = build_into(&dir, true);
        let storage = TextIndex::<TestId>::storage_file_path(&dir);

        let target = first_present_segment(&storage);
        let gen = read_manifest_gens(&storage)[target].unwrap();
        std::fs::remove_file(segment_path(&storage, target, gen)).unwrap();

        let err = TextIndex::<TestId>::open(Some(&dir)).err().unwrap();
        assert!(
            matches!(err, SearchError::CorruptIndex { ref reason, .. } if reason.contains("missing/unreadable segment")),
            "expected missing-segment CorruptIndex, got {err:?}"
        );
    }

    /// A manifest with a valid version prefix but an undecodable body is corrupt
    /// and archived, just like the monolithic equivalent.
    #[test]
    fn corrupt_manifest_is_archived() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("seg");
        let _idx = build_into(&dir, true);
        let storage = TextIndex::<TestId>::storage_file_path(&dir);
        let manifest = manifest_path(&storage);

        let mut bytes = SEGMENTED_FORMAT_VERSION.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"this is not a valid manifest payload");
        std::fs::write(&manifest, &bytes).unwrap();

        let err = TextIndex::<TestId>::open(Some(&dir)).err().unwrap();
        assert!(
            matches!(err, SearchError::CorruptIndex { ref reason, .. } if reason.contains("undecodable manifest")),
            "expected undecodable-manifest CorruptIndex, got {err:?}"
        );
        assert!(!manifest.exists(), "corrupt manifest must be archived");
    }

    /// Toggling the flag OFF on a segmented index: it still loads, and the next
    /// (monolithic) commit retires the manifest. Results are stable throughout.
    #[test]
    fn segmented_to_monolithic_toggle_preserves_results() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("idx");
        let seg = build_into(&dir, true);
        let before = all_query_results(&seg);
        let storage = TextIndex::<TestId>::storage_file_path(&dir);
        assert!(manifest_path(&storage).exists());

        // Reopen with the flag off (auto-detects + loads the segmented index).
        let mut idx = TextIndex::<TestId>::open(Some(&dir)).unwrap();
        idx.incremental_enabled = false;
        assert_eq!(all_query_results(&idx), before);

        // A commit now writes monolithic and retires the stale manifest.
        idx.commit().unwrap();
        assert!(
            !manifest_path(&storage).exists(),
            "manifest must be retired"
        );
        assert!(storage.exists(), "monolithic index.bin must be written");

        let reopened = TextIndex::<TestId>::open(Some(&dir)).unwrap();
        assert_eq!(all_query_results(&reopened), before);
    }

    /// Toggling the flag ON over a monolithic index converts it to segmented on
    /// the next commit. Results are stable throughout.
    #[test]
    fn monolithic_to_segmented_toggle_preserves_results() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("idx");
        let mono = build_into(&dir, false);
        let before = all_query_results(&mono);
        let storage = TextIndex::<TestId>::storage_file_path(&dir);
        assert!(storage.exists());
        assert!(!manifest_path(&storage).exists());

        let mut idx = TextIndex::<TestId>::open(Some(&dir)).unwrap();
        idx.incremental_enabled = true;
        idx.commit().unwrap();
        assert!(manifest_path(&storage).exists(), "manifest must be created");

        let reopened = TextIndex::<TestId>::open(Some(&dir)).unwrap();
        assert_eq!(all_query_results(&reopened), before);
    }

    /// Emptying every document in a segment drops its file and records a `None`
    /// generation; the index still reloads cleanly with the remaining docs.
    #[test]
    fn emptying_a_segment_removes_its_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("seg");
        let idx = build_into(&dir, true);
        let storage = TextIndex::<TestId>::storage_file_path(&dir);

        let gens_before = read_manifest_gens(&storage);
        let segment_count = gens_before.len();
        let target = first_present_segment(&storage);

        let to_remove: Vec<TestId> = fixture_docs()
            .into_iter()
            .map(|(id, _)| id)
            .filter(|id| segment_of(id, segment_count) == target)
            .collect();
        assert!(!to_remove.is_empty());
        for id in &to_remove {
            idx.remove(id).unwrap();
        }
        idx.commit().unwrap();

        let gens_after = read_manifest_gens(&storage);
        assert_eq!(
            gens_after[target], None,
            "emptied segment must have no file"
        );
        if let Some(old) = gens_before[target] {
            assert!(
                !segment_path(&storage, target, old).exists(),
                "old segment file must be GC'd"
            );
        }

        let reopened = TextIndex::<TestId>::open(Some(&dir)).unwrap();
        assert_eq!(
            reopened.live_document_count(),
            fixture_docs().len() - to_remove.len()
        );
    }

    // -----------------------------------------------------------------------
    // Concurrency: lock-order-inversion deadlock regression
    //
    // The writer paths (`upsert`/`remove`/`remove_batch`) and the `commit` path
    // both touch the `staged` lock and the four live-state locks
    // (`index`/`docs`/`doc_count`/`total_doc_length`). Before the fix, writers
    // acquired a live-state read guard BEFORE `staged.write()`, while `commit`
    // acquired `staged.write()` BEFORE the live-state write guards — an inverted
    // order that lets a writer thread (holding `index.read()`, waiting on
    // `staged.write()`) and a committer thread (holding `staged.write()`, waiting
    // on `index.write()`) wedge into a permanent deadlock. The canonical order is
    // now `staged` first in BOTH paths, so the cycle is impossible.
    //
    // These tests run the concurrent workload on helper threads and gate
    // completion behind a wall-clock timeout: a regression re-introduces the
    // deadlock, the workload never signals done, and the test FAILS LOUDLY at the
    // timeout instead of hanging CI forever.
    // -----------------------------------------------------------------------

    /// Run `workload` on a dedicated coordinator thread and fail if it does not
    /// finish within `timeout`. On timeout we `panic!` (failing the test) rather
    /// than block forever: a deadlock regression must surface as a red test, not
    /// a hung runner. The wedged worker threads stay parked, but the test binary
    /// still exits non-zero, so CI reports the failure.
    fn run_with_deadlock_timeout(
        label: &str,
        timeout: std::time::Duration,
        workload: impl FnOnce() + Send + 'static,
    ) {
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let coordinator = std::thread::spawn(move || {
            workload();
            // Ignore send errors: if the receiver already timed out and went
            // away, the test has already failed and there is nothing to report.
            let _ = done_tx.send(());
        });

        match done_rx.recv_timeout(timeout) {
            Ok(()) => {
                coordinator
                    .join()
                    .expect("coordinator thread panicked (a worker assertion failed)");
            }
            Err(_) => panic!(
                "{label}: concurrent workload did not complete within {timeout:?} — \
                 lock-order-inversion deadlock has regressed"
            ),
        }
    }

    /// Concurrent writers + committers against a shared in-memory index must make
    /// progress and never deadlock. This is the tight reproduction of the
    /// `upsert`-vs-`commit` lock-order inversion: many threads hammer both paths
    /// at once so the interleaving window (writer holding a live read guard while
    /// reaching for `staged`; committer holding `staged` while reaching for the
    /// live write guards) is hit almost immediately under the buggy ordering.
    #[test]
    fn concurrent_upsert_and_commit_do_not_deadlock() {
        use std::sync::Arc;

        run_with_deadlock_timeout(
            "concurrent_upsert_and_commit",
            std::time::Duration::from_secs(30),
            || {
                let idx = Arc::new(TextIndex::<TestId>::new());
                let writer_threads = 4;
                let committer_threads = 2;
                let iters = 2_000;

                let mut handles = Vec::new();

                // Writers: each owns a disjoint id range so upserts/removes never
                // collide on document identity — the deadlock is about lock order,
                // not data contention, and disjoint ids keep the final state
                // exactly checkable.
                for w in 0..writer_threads {
                    let idx = Arc::clone(&idx);
                    handles.push(std::thread::spawn(move || {
                        let base = (w as u64 + 1) * 1_000_000;
                        for i in 0..iters {
                            let id = TestId(base + (i % 64) as u64);
                            idx.upsert(
                                id,
                                &[("concurrentSymbol", 5.0), ("src/concurrent/mod.rs", 2.0)],
                            )
                            .unwrap();
                            // Exercise the remove writer path too (same lock order).
                            if i % 3 == 0 {
                                idx.remove(&id).unwrap();
                            }
                        }
                    }));
                }

                // Committers: race the writers, repeatedly publishing staged state.
                for _ in 0..committer_threads {
                    let idx = Arc::clone(&idx);
                    handles.push(std::thread::spawn(move || {
                        for _ in 0..iters {
                            idx.commit().unwrap();
                            // Reads must keep working under contention as well.
                            let _ = idx.fuzzy_search("concurrent", 5).unwrap();
                        }
                    }));
                }

                for h in handles {
                    h.join().expect("worker thread panicked");
                }

                // A final commit flushes any still-staged writes, then the index
                // must be internally consistent: live_document_count equals the
                // number of distinct doc ids actually present. This proves the
                // lock-order fix did not introduce a data race that corrupts the
                // staged/live bookkeeping — "doesn't hang" AND "stays correct".
                idx.commit().unwrap();
                let live = idx.live_document_count();
                let present = (0..writer_threads)
                    .flat_map(|w| {
                        let base = (w as u64 + 1) * 1_000_000;
                        (0..64u64).map(move |k| TestId(base + k))
                    })
                    .filter(|id| idx.contains(id))
                    .count();
                assert_eq!(
                    live, present,
                    "live document count ({live}) must match the docs actually present ({present})"
                );
            },
        );
    }

    /// The same concurrency guarantee through the durable persist path: a shared
    /// persisted index under concurrent writers + committers must not deadlock
    /// (the committer now holds `staged` strictly before the live-state locks, and
    /// releases `staged` before the fsync-bound persist) and must reload to a
    /// consistent state afterwards.
    #[test]
    fn concurrent_writes_with_persistence_do_not_deadlock() {
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("concurrent");
        std::fs::create_dir_all(&dir).unwrap();

        run_with_deadlock_timeout(
            "concurrent_writes_with_persistence",
            std::time::Duration::from_secs(45),
            {
                let dir = dir.clone();
                move || {
                    let idx = Arc::new(TextIndex::<TestId>::open(Some(&dir)).unwrap());
                    let writer_threads = 3;
                    let iters = 500;

                    let mut handles = Vec::new();
                    for w in 0..writer_threads {
                        let idx = Arc::clone(&idx);
                        handles.push(std::thread::spawn(move || {
                            let base = (w as u64 + 1) * 100_000;
                            for i in 0..iters {
                                let id = TestId(base + i as u64);
                                idx.upsert(id, &[("persistedConcurrent", 5.0)]).unwrap();
                                if i % 10 == 0 {
                                    idx.commit().unwrap();
                                }
                            }
                        }));
                    }
                    // A dedicated committer that also persists on every commit.
                    {
                        let idx = Arc::clone(&idx);
                        handles.push(std::thread::spawn(move || {
                            for _ in 0..iters {
                                idx.commit().unwrap();
                            }
                        }));
                    }

                    for h in handles {
                        h.join().expect("worker thread panicked");
                    }
                    idx.commit().unwrap();
                }
            },
        );

        // Reopen from disk: the persisted state must load cleanly (not corrupt)
        // and expose exactly the docs every writer inserted.
        let reopened = TextIndex::<TestId>::open(Some(&dir)).unwrap();
        let writer_threads = 3u64;
        let iters = 500u64;
        let expected = (writer_threads * iters) as usize;
        assert_eq!(
            reopened.live_document_count(),
            expected,
            "every concurrently-inserted doc must survive persistence"
        );
    }

    // postings: term -> (occurrences, sorted [(doc_id, weight vec)])
    type PostingRows = Vec<(String, usize, Vec<(u64, Vec<f32>)>)>;
    // forward docs: id -> (doc_length, tokens_by_field)
    type DocRows = Vec<(u64, usize, Vec<(String, f32)>)>;
    // (postings, forward docs, doc_count, total_doc_length)
    type Canon = (PostingRows, DocRows, usize, usize);

    /// Lower a `TextIndex` to a canonical (term-sorted, doc-id-sorted) form.
    /// Posting lists live in `HashMap`s whose iteration order is seed-randomized
    /// per instance, so equality of this form — and of its serialized bytes —
    /// proves identical postings, per-term doc sets, per-doc weight vectors, term
    /// frequencies, and BM25 aggregates regardless of `HashMap` iteration order.
    fn canonical(idx: &TextIndex<TestId>) -> Canon {
        let index = idx.index.read();
        let docs = idx.docs.read();

        let mut postings: PostingRows = index
            .iter()
            .map(|(term, p)| {
                let mut by_doc: Vec<(u64, Vec<f32>)> =
                    p.by_doc.iter().map(|(id, ws)| (id.0, ws.clone())).collect();
                by_doc.sort_by_key(|(id, _)| *id);
                (term.clone(), p.occurrences, by_doc)
            })
            .collect();
        postings.sort_by(|a, b| a.0.cmp(&b.0));

        let mut doc_rows: DocRows = docs
            .iter()
            .map(|(id, d)| (id.0, d.doc_length, d.tokens_by_field.clone()))
            .collect();
        doc_rows.sort_by_key(|(id, _, _)| *id);

        (
            postings,
            doc_rows,
            *idx.doc_count.read(),
            *idx.total_doc_length.read(),
        )
    }

    /// Gate: the parallel `rebuild_all_owned` must produce an index that is
    /// byte-identical to the serial `rebuild_all` on the same corpus.
    #[test]
    fn rebuild_all_owned_parallel_matches_serial_byte_for_byte() {
        // Code-like corpus with cross-document token overlap and tokens that
        // repeat within a single document, so postings carry multi-doc entries
        // and multi-occurrence weight vectors.
        let n = 300usize;
        let mut owned: Vec<(TestId, Vec<(String, f32)>)> = Vec::with_capacity(n);
        for i in 0..n {
            let id = TestId(i as u64 + 1);
            let name = format!("parseTableFromHtml_{}", i % 17);
            let signature = format!(
                "fn parse_table_{}(row: usize) -> Result<Html_{}>",
                i % 11,
                i % 5
            );
            let file_path = format!("src/io/ascii/html_{}.rs", i % 23);
            let kind = if i % 2 == 0 { "Function" } else { "Method" }.to_string();
            owned.push((
                id,
                vec![(name, 5.0), (signature, 3.0), (file_path, 2.0), (kind, 1.0)],
            ));
        }

        let borrowed: Vec<(TestId, Vec<(&str, f32)>)> = owned
            .iter()
            .map(|(id, fields)| {
                (
                    *id,
                    fields
                        .iter()
                        .map(|(t, w)| (t.as_str(), *w))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();

        let serial = TextIndex::<TestId>::new();
        serial.rebuild_all(&borrowed).unwrap();

        let parallel = TextIndex::<TestId>::new();
        parallel.rebuild_all_owned(owned.clone()).unwrap();

        let canon_serial = canonical(&serial);
        let canon_parallel = canonical(&parallel);

        assert_eq!(
            canon_serial, canon_parallel,
            "parallel rebuild produced a different index than the serial rebuild"
        );

        let bytes_serial = bincode::serialize(&canon_serial).unwrap();
        let bytes_parallel = bincode::serialize(&canon_parallel).unwrap();
        assert_eq!(
            bytes_serial, bytes_parallel,
            "serialized index bytes differ between serial and parallel rebuild"
        );

        // Confirm the corpus actually exercised multi-doc and multi-occurrence
        // postings, so the equality above is meaningful rather than vacuous.
        assert!(
            canon_serial.0.iter().any(|(_, _, by_doc)| by_doc.len() > 1),
            "corpus should produce at least one term spanning multiple docs"
        );
        assert!(
            canon_serial
                .0
                .iter()
                .any(|(_, _, by_doc)| by_doc.iter().any(|(_, ws)| ws.len() > 1)),
            "corpus should produce at least one term with repeated occurrences in a doc"
        );
    }

    /// Gate: the parallel `upsert_batch` must stage an index byte-identical to
    /// applying `upsert` to each document serially in batch order — same
    /// canonical-form and serialized-byte comparison as the rebuild gate.
    #[test]
    fn upsert_batch_matches_serial_upsert() {
        // Corpus with cross-document token overlap and within-document repeats,
        // plus a trailing re-upsert of an already-present id so the
        // remove-then-reinsert path is exercised identically in both arms.
        let n = 200usize;
        let mut docs: Vec<(TestId, Vec<(String, f32)>)> = Vec::with_capacity(n + 1);
        for i in 0..n {
            let id = TestId(i as u64 + 1);
            let name = format!("renderWidgetTree_{}", i % 13);
            let signature = format!("fn render_widget_{}(depth: usize) -> Node_{}", i % 7, i % 5);
            let file_path = format!("src/ui/widgets/tree_{}.rs", i % 19);
            let kind = if i % 2 == 0 { "Function" } else { "Method" }.to_string();
            docs.push((
                id,
                vec![(name, 5.0), (signature, 3.0), (file_path, 2.0), (kind, 1.0)],
            ));
        }
        docs.push((
            TestId(1),
            vec![("renderWidgetTree_overwrite".to_string(), 4.0)],
        ));

        let borrowed: Vec<(TestId, Vec<(&str, f32)>)> = docs
            .iter()
            .map(|(id, fields)| {
                (
                    *id,
                    fields
                        .iter()
                        .map(|(t, w)| (t.as_str(), *w))
                        .collect::<Vec<_>>(),
                )
            })
            .collect();

        let serial = TextIndex::<TestId>::new();
        for (id, fields) in &borrowed {
            serial.upsert(*id, fields).unwrap();
        }
        serial.commit().unwrap();

        let batched = TextIndex::<TestId>::new();
        batched.upsert_batch(&borrowed).unwrap();
        batched.commit().unwrap();

        let canon_serial = canonical(&serial);
        let canon_batched = canonical(&batched);

        assert_eq!(
            canon_serial, canon_batched,
            "upsert_batch produced a different index than serial upsert"
        );

        let bytes_serial = bincode::serialize(&canon_serial).unwrap();
        let bytes_batched = bincode::serialize(&canon_batched).unwrap();
        assert_eq!(
            bytes_serial, bytes_batched,
            "serialized index bytes differ between serial upsert and upsert_batch"
        );

        // Non-vacuous: the corpus must exercise multi-doc and multi-occurrence
        // postings, and the re-upserted id must collapse to a single live doc.
        assert!(
            canon_serial.0.iter().any(|(_, _, by_doc)| by_doc.len() > 1),
            "corpus should produce at least one term spanning multiple docs"
        );
        assert!(
            canon_serial
                .0
                .iter()
                .any(|(_, _, by_doc)| by_doc.iter().any(|(_, ws)| ws.len() > 1)),
            "corpus should produce at least one term with repeated occurrences in a doc"
        );
        assert_eq!(
            canon_serial.1.len(),
            n,
            "the trailing re-upsert of an existing id must not add a new live doc"
        );
    }

    /// Reference search: the original full-vocabulary-scan substring match with a
    /// fully serial BM25 accumulation. The production [`TextIndex::fuzzy_search`]
    /// — which uses the trigram candidate index and a parallel score reduction —
    /// must reproduce this bit-for-bit.
    fn brute_force_fuzzy(idx: &TextIndex<TestId>, query: &str, limit: usize) -> Vec<(TestId, f32)> {
        let query_tokens = tokenize(query);
        if query_tokens.is_empty() {
            return Vec::new();
        }
        let index = idx.index.read();
        let docs = idx.docs.read();
        let total_docs = *idx.doc_count.read();
        let total_doc_len = *idx.total_doc_length.read();
        if total_docs == 0 {
            return Vec::new();
        }
        let n = total_docs as f32;
        let avgdl = total_doc_len as f32 / total_docs as f32;

        let mut scores: HashMap<TestId, f32> = HashMap::new();
        for qt in &query_tokens {
            if let Some(postings) = index.get(qt) {
                let df = postings.doc_count() as f32;
                let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln().max(0.0);
                for (eid, weight) in postings.iter() {
                    let dl = docs.get(eid).map(|d| d.doc_length as f32).unwrap_or(avgdl);
                    let tf = *weight;
                    let tf_saturated = (tf * (BM25_K1 + 1.0))
                        / (tf + BM25_K1 * (1.0 - BM25_B + BM25_B * dl / avgdl));
                    *scores.entry(*eid).or_insert(0.0) += idf * tf_saturated;
                }
            }
            if qt.len() >= 3 {
                let mut matched: Vec<&String> = index
                    .keys()
                    .filter(|t| {
                        t.as_str() != qt.as_str()
                            && t.len() >= 3
                            && (t.contains(qt.as_str()) || qt.contains(t.as_str()))
                    })
                    .collect();
                matched.sort_unstable();
                for t in matched {
                    let postings = &index[t];
                    let df = postings.doc_count() as f32;
                    let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln().max(0.0);
                    for (eid, weight) in postings.iter() {
                        let dl = docs.get(eid).map(|d| d.doc_length as f32).unwrap_or(avgdl);
                        let tf = *weight;
                        let tf_saturated = (tf * (BM25_K1 + 1.0))
                            / (tf + BM25_K1 * (1.0 - BM25_B + BM25_B * dl / avgdl));
                        *scores.entry(*eid).or_insert(0.0) += idf * tf_saturated * 0.5;
                    }
                }
            }
        }

        let mut keyed: Vec<(String, TestId, f32)> = scores
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
        keyed.into_iter().map(|(_, id, s)| (id, s)).collect()
    }

    /// Assert two result lists are identical in id order and bit-for-bit in score
    /// (compared on raw bits so no float rounding slips through).
    fn assert_identical(label: &str, got: &[(TestId, f32)], want: &[(TestId, f32)]) {
        assert_eq!(
            got.len(),
            want.len(),
            "{label}: result count {} != reference {}",
            got.len(),
            want.len()
        );
        for (rank, (g, w)) in got.iter().zip(want.iter()).enumerate() {
            assert_eq!(g.0, w.0, "{label}: id mismatch at rank {rank}");
            assert_eq!(
                g.1.to_bits(),
                w.1.to_bits(),
                "{label}: score bits differ at rank {rank} ({} vs {})",
                g.1,
                w.1
            );
        }
    }

    /// Gate: trigram-candidate substring matching must return exactly what the
    /// full vocabulary scan returns — same ids, same bit-for-bit scores — across
    /// both substring directions, multibyte tokens, and queries with no match.
    #[test]
    fn trigram_fuzzy_matches_full_scan() {
        let idx = TextIndex::<TestId>::new();
        let names = [
            "renderWidget",
            "widgetFactory",
            "WidgetTreeBuilder",
            "parseTable",
            "tableParser",
            "htmlParser",
            "parse",
            "table",
            "renderer",
            "lexicalSearch",
            "searchIndex",
            "reindex",
            "caféMenu",
        ];
        for (i, name) in names.iter().cycle().take(150).enumerate() {
            let (id, doc) = make_doc(name, &format!("src/mod{}/{}.rs", i % 9, i), "Function");
            idx.upsert_searchable(id, &doc).unwrap();
        }
        idx.commit().unwrap();

        for q in [
            "widget",     // matched by WidgetTreeBuilder, widgetfactory (dir A) + own token
            "table",      // exact + parsetable/tableparser substrings
            "parse",      // exact + parser substrings
            "parser",     // query contains "parse" (dir B) + htmlparser (dir A)
            "search",     // substring of lexicalsearch/searchindex
            "index",      // substring of searchindex/reindex
            "render",     // substring of renderwidget/renderer
            "café",       // multibyte token: byte-trigram correctness
            "WidgetTree", // multi-token query
            "table parser",
            "zzznomatch", // no candidates
            "ab",         // short token: skips the substring branch entirely
        ] {
            let got = idx.fuzzy_search(q, 50).unwrap();
            let want = brute_force_fuzzy(&idx, q, 50);
            assert_identical(q, &got, &want);
        }
    }

    /// Gate: the parallel BM25 score reduction must equal a fully serial
    /// accumulation bit-for-bit. The corpus is sized past
    /// [`PARALLEL_SCORE_THRESHOLD`] and the query is run inside a multi-thread
    /// rayon pool so the parallel path is taken regardless of host core count.
    /// Every entity accumulates across multiple terms (exact "widget", a
    /// within-document repeat, and the substring sibling "widgets"), which is the
    /// float-associativity-sensitive case the canonical ordering must preserve.
    #[test]
    fn parallel_bm25_scoring_matches_serial() {
        let idx = TextIndex::<TestId>::new();
        // Each doc contributes three scored occurrences for query "widget" (the
        // exact token in two fields plus the substring sibling "widgets"), so the
        // corpus is sized so total occurrences (3 * n) clears the parallel
        // threshold and the fan-out path is actually taken.
        let n = 15_000usize;
        let occurrences_per_doc = 3usize;
        assert!(
            n * occurrences_per_doc >= PARALLEL_SCORE_THRESHOLD,
            "corpus must be sized to exercise the parallel scoring path"
        );
        let doc_names: Vec<String> = (0..n).map(|i| format!("doc{i}")).collect();
        let mut batch: Vec<(TestId, Vec<(&str, f32)>)> = Vec::with_capacity(n);
        for (i, doc_name) in doc_names.iter().enumerate() {
            batch.push((
                TestId(i as u64 + 1),
                vec![
                    ("widget widgets rendering", 5.0),
                    ("widget core", 3.0),
                    (doc_name.as_str(), 2.0),
                ],
            ));
        }
        idx.upsert_batch(&batch).unwrap();
        idx.commit().unwrap();

        let want = brute_force_fuzzy(&idx, "widget", n);

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        let got = pool.install(|| idx.fuzzy_search("widget", n).unwrap());

        assert_eq!(
            got.len(),
            n,
            "every document carrying the query token scores"
        );
        assert_identical("widget(parallel)", &got, &want);

        // The same query off the default pool must also match the reference.
        let got_default = idx.fuzzy_search("widget", n).unwrap();
        assert_identical("widget(default)", &got_default, &want);
    }

    /// Determinism: a fuzzy query that mixes exact and substring matches must
    /// return byte-identical results across repeated runs, even though the
    /// underlying inverted index and trigram candidate sets iterate in
    /// process-randomized HashMap order.
    #[test]
    fn fuzzy_search_is_run_to_run_deterministic() {
        let idx = TextIndex::<TestId>::new();
        let names = [
            "renderWidget",
            "widgetFactory",
            "parseTable",
            "tableParser",
            "searchIndex",
            "reindex",
        ];
        for (i, name) in names.iter().cycle().take(200).enumerate() {
            let (id, doc) = make_doc(name, &format!("src/{}/{}.rs", i % 5, i), "Function");
            idx.upsert_searchable(id, &doc).unwrap();
        }
        idx.commit().unwrap();

        let baseline = idx.fuzzy_search("widget table index", 40).unwrap();
        for _ in 0..16 {
            let again = idx.fuzzy_search("widget table index", 40).unwrap();
            assert_identical("repeat", &again, &baseline);
        }
    }
}
