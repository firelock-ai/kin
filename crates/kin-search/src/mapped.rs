// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! # The text index served from a mapping
//!
//! The heap index holds a `String` per distinct token, a `HashMap<Id, Vec<f32>>`
//! per token, a forward map naming every occurrence, a vocabulary, and a trigram
//! index rebuilt on the first fuzzy query after every commit. On a VS Code tree
//! that is gigabytes of resident memory whose only job is to answer questions
//! that a file could answer.
//!
//! This module is the format that answers them from a file instead. A segment is
//! one immutable file holding an FST term dictionary, block-compressed postings
//! and a document table. The reader maps it, and what it retains is the mapping
//! handle, a few counters and one bit per document. The term dictionary, the
//! postings and the document table are pages, never allocations.
//!
//! ## What the format has to preserve, and why it is not negotiable
//!
//! The scorer this crate ships is not BM25 over term frequencies. It saturates
//! the FIELD WEIGHT once per token OCCURRENCE and sums those, which is why a
//! posting carries a document's weights as a sequence rather than a count:
//!
//! ```text
//! for weight in weights {
//!     score += idf * (weight * (K1 + 1)) / (weight + K1 * (1 - B + B * dl / avgdl)) * penalty
//! }
//! ```
//!
//! Float addition is not associative, so `n` additions of `saturate(w)` is not
//! `n * saturate(w)`, and the run-length encoding below expands a run back into
//! that many additions rather than collapsing it into a multiply. Everything
//! else that fixes the result is preserved verbatim: BM25 k1 1.2 and b 0.75, an
//! IDF whose `df` counts distinct live documents, a substring penalty of 0.5,
//! substring matches visited in sorted token order, and the final tie-break on
//! `format!("{id:?}")`. A guard asserts the mapped reader's results are
//! bit-identical to the heap index's on the same corpus, for exact and fuzzy
//! queries alike.
//!
//! ## Deletes without a forward map
//!
//! The heap index keeps a forward map for one reason: to remove a document you
//! have to know which tokens it contributed. That map is where most of the
//! memory went. Here a delete sets one bit in a tombstone bitset carried in the
//! manifest, which is rewritten on every commit anyway, and every posting walk
//! skips tombstoned ordinals. A term's `df` is the stored count when its segment
//! has no tombstones and a counted walk when it does, so IDF stays exact rather
//! than drifting as documents are removed.
//!
//! ## Substring matching without a trigram index
//!
//! The two substring directions are not the same query and they do not want the
//! same machinery.
//!
//! - `token.contains(qt)`, the ordinary direction, is one traversal of the
//!   mapped FST under a `.*qt.*` automaton. It allocates nothing.
//! - `qt.contains(token)`, the reverse direction, is a bounded enumeration of
//!   the only substrings of `qt` that can match, each one exact lookup. The
//!   floor is `ceil(3 * qt.len() / 4)` bytes and at least [`MIN_SUBSTRING_LEN`],
//!   so the count is quadratic in the quarter above the floor rather than in the
//!   query: 21 candidates for a 20-byte token, 66 for 40 bytes, 1,326 for 200.
//!   Long query tokens are ordinary input, because `tokenize` emits whole path
//!   and identifier segments, so the loop is bounded by the floor rather than
//!   scanning every start and end pair.
//!
//! Against that, the trigram index costs a full vocabulary walk allocating a
//! `Box<str>` per token, on the first fuzzy query after every commit, load or
//! rebuild, and then holds a second copy of the vocabulary for the life of the
//! epoch.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fst::{Automaton, IntoStreamer, Streamer};
use memmap2::Mmap;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    corrupt_index_error, manifest_path, reverse_substring_admits, segment_path, tokenize, DocId,
    Postings, SearchError, BM25_B, BM25_K1, MIN_SUBSTRING_LEN,
};

// ── Format constants ─────────────────────────────────────────────────────────

/// Segmented format version for the mapped layout: an FST term dictionary, block
/// postings and a document table, in one immutable file per segment.
///
/// Reading is a range and writing is a point, the same split the v3-to-v4 move
/// established. This build READS 3 through 5 and its default commit still WRITES
/// 4; a v5 image is produced only by an explicit
/// [`persist_mapped`](crate::TextIndex::persist_mapped).
pub const MAPPED_SEGMENT_VERSION: u32 = 5;

/// Magic at the head of every mapped segment file. Read before anything else, so
/// a file that is not a mapped segment is refused by identity rather than by a
/// nonsense offset.
const MAGIC: [u8; 8] = *b"KINSEG05";

/// Fixed header size. Every section is addressed by an absolute (offset, len)
/// pair recorded here, so a later version can append a section without moving
/// the ones before it.
const HEADER_LEN: usize = 96;

/// The writer's point has to lie inside the reader's range, in both directions.
///
/// A compile-time assertion rather than a test, because the failure it prevents
/// is a build that writes an index it cannot read back. It survives the cutover
/// that moves the default commit onto the mapped layout, where the writer's
/// point becomes equal to the reader's ceiling rather than below it.
const _: () = assert!(
    crate::MIN_SEGMENTED_FORMAT_VERSION <= crate::SEGMENTED_FORMAT_VERSION
        && crate::SEGMENTED_FORMAT_VERSION <= MAPPED_SEGMENT_VERSION,
    "the segmented writer's version must lie inside the range the loader reads"
);

// ── Varints ──────────────────────────────────────────────────────────────────

/// Append `value` as an unsigned LEB128 varint.
fn put_uvarint(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push((value as u8) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

/// Read an unsigned LEB128 varint, advancing `pos`.
///
/// `None` on a truncated or over-long encoding rather than a panic, because the
/// bytes come from a file that a crash may have torn and the caller turns that
/// into a typed corruption error.
fn get_uvarint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        let byte = *data.get(*pos)?;
        *pos += 1;
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            // A canonical encoding never ENDS in a zero byte unless it is the
            // single byte `00`. Rejecting only the lossy over-long form left
            // `81 00` and `80 80 ... 00` decoding happily, so two byte strings
            // still mapped to one value and the doc comment was broader than
            // the code.
            if shift > 0 && byte == 0 {
                return None;
            }
            return Some(result);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
        // The tenth byte can carry only one payload bit. Anything above that is
        // a non-canonical encoding whose upper bits this shift would drop, and
        // two different byte strings decoding to one value is a corruption
        // signal thrown away.
        if shift == 63 && *data.get(*pos)? > 1 {
            return None;
        }
    }
}

fn read_u32(data: &[u8], at: usize) -> Option<u32> {
    let slice = data.get(at..at + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(data: &[u8], at: usize) -> Option<u64> {
    let slice = data.get(at..at + 8)?;
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(slice);
    Some(u64::from_le_bytes(bytes))
}

// ── Tombstones ───────────────────────────────────────────────────────────────

/// One bit per document ordinal in a segment: set means removed.
///
/// This is the whole of delete support, and it is why no forward map exists. It
/// lives in the manifest rather than beside the segment because the manifest is
/// already the atomic commit point and is already rewritten on every commit; a
/// bitset is 1 bit per document, so a corpus of three million documents costs
/// 375 KB there.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Tombstones {
    words: Vec<u64>,
    set_count: usize,
}

impl Tombstones {
    /// Recompute the cached count from the bits, discarding whatever the file
    /// claimed.
    ///
    /// The two are read by different decisions and a disagreement between them
    /// is the exact failure the delete guard exists to catch, reached through
    /// the one path that guard cannot see. `any()` reads the count and gates
    /// both the load-time reconciliation and the fast path that trusts a
    /// stored `df`; `is_set` reads the bits and gates the posting walk. A
    /// manifest with a bit set and a count of zero therefore hides a document
    /// from results while still counting it in `N`, in `avgdl` and in every
    /// term's `df`. Deriving the count removes the class rather than checking
    /// for it.
    fn rebuild_count(&mut self) {
        self.set_count = self
            .words
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum();
    }
}

impl Tombstones {
    fn for_docs(doc_count: usize) -> Self {
        Self {
            words: vec![0u64; doc_count.div_ceil(64)],
            set_count: 0,
        }
    }

    fn is_set(&self, ordinal: u32) -> bool {
        let index = ordinal as usize;
        match self.words.get(index / 64) {
            Some(word) => (word >> (index % 64)) & 1 == 1,
            None => false,
        }
    }

    /// Mark `ordinal` removed. Returns whether this call was the one that set
    /// it, so the caller adjusts its live counters exactly once.
    fn set(&mut self, ordinal: u32) -> bool {
        let index = ordinal as usize;
        let word = index / 64;
        if word >= self.words.len() {
            self.words.resize(word + 1, 0);
        }
        let mask = 1u64 << (index % 64);
        if self.words[word] & mask != 0 {
            return false;
        }
        self.words[word] |= mask;
        self.set_count += 1;
        true
    }

    fn any(&self) -> bool {
        self.set_count > 0
    }

    /// The highest ordinal with its bit set, if any.
    ///
    /// Used to refuse a bit no read can reach, which is a removal that does not
    /// remove anything and yet costs every `df` in that segment a counted walk.
    fn highest_set(&self) -> Option<usize> {
        for (index, word) in self.words.iter().enumerate().rev() {
            if *word != 0 {
                let top = 63 - word.leading_zeros() as usize;
                return Some(index * 64 + top);
            }
        }
        None
    }
}

// ── A mapped byte range ──────────────────────────────────────────────────────

/// A sub-slice of a memory mapping, owned by reference count.
///
/// `fst::Map` takes ownership of whatever it reads from, and the FST occupies
/// one section of the segment file rather than the whole of it, so it is handed
/// this instead of the mapping itself. Cloning is a refcount bump; nothing is
/// copied and nothing is resident beyond the mapping's own handle.
#[derive(Clone)]
struct MmapRange {
    map: Arc<Mmap>,
    start: usize,
    end: usize,
}

impl AsRef<[u8]> for MmapRange {
    fn as_ref(&self) -> &[u8] {
        &self.map[self.start..self.end]
    }
}

// ── The substring automaton ──────────────────────────────────────────────────

/// Accepts every key containing `needle`, for a traversal of the term dictionary
/// that yields exactly what `token.contains(qt)` would over a full scan.
///
/// The state is the number of needle bytes currently matched, advanced through a
/// KMP failure table so a transition is O(1) amortized rather than a rescan. The
/// accepting state is sticky: once a key contains the needle, every extension of
/// it does too.
///
/// `will_always_match` reports that stickiness but buys nothing here, because
/// fst 0.4.7's raw stream consults only `start`, `is_match`, `can_match`,
/// `accept` and `accept_eof` (`fst/src/raw/mod.rs`, `Stream::next_with`). It is
/// implemented anyway because it is part of the trait's contract and a later
/// version may use it; no subtree is skipped today.
///
/// It deliberately does NOT prune: from the start state every byte is a legal
/// transition, so this is a full traversal of the mapped FST. That is the honest
/// cost of substring search on a term dictionary, and it is paid per query
/// against pages rather than once per epoch against the heap.
struct Contains<'a> {
    needle: &'a [u8],
    failure: Vec<usize>,
}

impl<'a> Contains<'a> {
    fn new(needle: &'a [u8]) -> Self {
        let mut failure = vec![0usize; needle.len()];
        let mut k = 0usize;
        for i in 1..needle.len() {
            while k > 0 && needle[k] != needle[i] {
                k = failure[k - 1];
            }
            if needle[k] == needle[i] {
                k += 1;
            }
            failure[i] = k;
        }
        Self { needle, failure }
    }
}

impl Automaton for Contains<'_> {
    type State = usize;

    fn start(&self) -> usize {
        0
    }

    fn is_match(&self, state: &usize) -> bool {
        *state >= self.needle.len()
    }

    fn can_match(&self, _state: &usize) -> bool {
        true
    }

    fn will_always_match(&self, state: &usize) -> bool {
        *state >= self.needle.len()
    }

    fn accept(&self, state: &usize, byte: u8) -> usize {
        let mut k = *state;
        if k >= self.needle.len() {
            return k;
        }
        while k > 0 && self.needle[k] != byte {
            k = self.failure[k - 1];
        }
        if self.needle[k] == byte {
            k += 1;
        }
        k
    }
}

// ── The manifest ─────────────────────────────────────────────────────────────

/// The mapped format's commit point.
///
/// Distinct from the bincode format's `SegmentManifest` because it carries the
/// tombstones, and read only after the leading `version: u32` has already been
/// inspected as raw little-endian bytes. That is the same dispatch the
/// monolithic loader uses to migrate a v1 file, and it is what lets two manifest
/// shapes share one path without either one guessing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct MappedManifest {
    pub(crate) version: u32,
    pub(crate) segment_count: usize,
    pub(crate) segment_gens: Vec<Option<u64>>,
    pub(crate) doc_count: usize,
    pub(crate) total_doc_length: usize,
    pub(crate) graph_root_hash: Option<[u8; 32]>,
    pub(crate) tombstones: Vec<Tombstones>,
}

// ── The writer ───────────────────────────────────────────────────────────────

/// One segment's documents and the postings restricted to them.
struct SegmentBuild<'a, Id: DocId> {
    /// Sorted by token bytes, which is the order an FST demands and the order
    /// the reader's substring walk yields.
    terms: BTreeMap<&'a str, Vec<(Id, &'a [f32])>>,
    /// Sorted by the document id's encoded bytes, which fixes the ordinals.
    docs: Vec<(Id, Vec<u8>, usize)>,
    total_doc_length: usize,
}

/// Encode one mapped segment.
///
/// Returns `None` when the segment holds no documents, because an empty segment
/// gets no file and a `None` generation in the manifest, exactly as the bincode
/// format already does.
fn encode_segment<Id: DocId + Serialize>(
    build: &SegmentBuild<'_, Id>,
) -> Result<Option<Vec<u8>>, SearchError> {
    if build.docs.is_empty() {
        return Ok(None);
    }

    // Ordinals are positions in the id-sorted document list, so `ordinal -> id`
    // is a slice of the mapped blob and `id -> ordinal` is a binary search over
    // it. Neither needs a resident map.
    let mut ordinal_of: HashMap<Id, u32> = HashMap::with_capacity(build.docs.len());
    for (ordinal, (id, _, _)) in build.docs.iter().enumerate() {
        let ordinal = u32::try_from(ordinal).map_err(|_| {
            SearchError::IndexError("a mapped segment holds over 4 billion documents".to_string())
        })?;
        ordinal_of.insert(*id, ordinal);
    }

    // The weight table interns the field weights, of which kin-db supplies
    // fourteen. Ordered by the f32's bit pattern rather than by value: that is a
    // total order even across NaN, and it is identical in every process.
    let mut weight_bits: BTreeSet<u32> = BTreeSet::new();
    for postings in build.terms.values() {
        for (_, weights) in postings {
            for weight in weights.iter() {
                weight_bits.insert(weight.to_bits());
            }
        }
    }
    let weight_table: Vec<u32> = weight_bits.into_iter().collect();
    let weight_code: HashMap<u32, u64> = weight_table
        .iter()
        .enumerate()
        .map(|(code, bits)| (*bits, code as u64))
        .collect();

    let mut postings_buf: Vec<u8> = Vec::new();
    put_uvarint(&mut postings_buf, weight_table.len() as u64);
    for bits in &weight_table {
        postings_buf.extend_from_slice(&bits.to_le_bytes());
    }

    let mut fst_builder = fst::MapBuilder::memory();
    for (token, entries) in &build.terms {
        let offset = postings_buf.len() as u64;

        // Ordinal order, so the deltas below are non-negative and the reader
        // walks a segment's postings in one forward pass.
        let mut ordered: Vec<(u32, &[f32])> = entries
            .iter()
            .map(|(id, weights)| {
                let ordinal = *ordinal_of
                    .get(id)
                    .expect("a posting names a document of its own segment");
                (ordinal, *weights)
            })
            .collect();
        ordered.sort_unstable_by_key(|(ordinal, _)| *ordinal);

        let occurrences: usize = ordered.iter().map(|(_, weights)| weights.len()).sum();
        put_uvarint(&mut postings_buf, ordered.len() as u64);
        put_uvarint(&mut postings_buf, occurrences as u64);

        let mut previous: i64 = -1;
        for (ordinal, weights) in ordered {
            put_uvarint(
                &mut postings_buf,
                (i64::from(ordinal) - previous - 1) as u64,
            );
            previous = i64::from(ordinal);

            // Run-length over CONSECUTIVE equal weights, never over the whole
            // list. `upsert` emits a document's tokens field by field, so equal
            // weights arrive adjacent, and expanding a run replays the same
            // sequence of float additions the heap index performs. Collapsing a
            // run into a multiply would not: float addition is not associative.
            let mut runs: Vec<(u64, u64)> = Vec::new();
            for weight in weights {
                let code = *weight_code
                    .get(&weight.to_bits())
                    .expect("every weight was interned above");
                match runs.last_mut() {
                    Some((last_code, count)) if *last_code == code => *count += 1,
                    _ => runs.push((code, 1)),
                }
            }
            put_uvarint(&mut postings_buf, runs.len() as u64);
            for (code, count) in runs {
                put_uvarint(&mut postings_buf, code);
                put_uvarint(&mut postings_buf, count);
            }
        }

        fst_builder
            .insert(token.as_bytes(), offset)
            .map_err(|err| {
                SearchError::IndexError(format!("failed to build the term dictionary: {err}"))
            })?;
    }
    let terms_bytes = fst_builder.into_inner().map_err(|err| {
        SearchError::IndexError(format!("failed to finish the term dictionary: {err}"))
    })?;

    // DOCS: n, then n+1 offsets into the id blob, then n document lengths, then
    // the blob. Fixed-stride tables addressed by ordinal, and a blob ordered so
    // that finding a document is a binary search over mapped bytes.
    let doc_count = build.docs.len();
    let mut id_blob: Vec<u8> = Vec::new();
    let mut id_offsets: Vec<u32> = Vec::with_capacity(doc_count + 1);
    let mut doc_lengths: Vec<u32> = Vec::with_capacity(doc_count);
    for (_, encoded, doc_length) in &build.docs {
        id_offsets.push(u32::try_from(id_blob.len()).map_err(|_| {
            SearchError::IndexError(
                "a mapped segment's document ids exceed 4 GiB; lower KIN_SEARCH_SEGMENT_COUNT"
                    .to_string(),
            )
        })?);
        id_blob.extend_from_slice(encoded);
        doc_lengths.push(u32::try_from(*doc_length).map_err(|_| {
            SearchError::IndexError(format!(
                "a document of {doc_length} tokens does not fit the mapped document table"
            ))
        })?);
    }
    id_offsets.push(u32::try_from(id_blob.len()).map_err(|_| {
        SearchError::IndexError(
            "a mapped segment's document ids exceed 4 GiB; lower KIN_SEARCH_SEGMENT_COUNT"
                .to_string(),
        )
    })?);

    let mut docs_bytes: Vec<u8> = Vec::with_capacity(8 + 8 * doc_count + id_blob.len());
    docs_bytes.extend_from_slice(&(doc_count as u64).to_le_bytes());
    for offset in &id_offsets {
        docs_bytes.extend_from_slice(&offset.to_le_bytes());
    }
    for length in &doc_lengths {
        docs_bytes.extend_from_slice(&length.to_le_bytes());
    }
    docs_bytes.extend_from_slice(&id_blob);

    let terms_off = HEADER_LEN;
    let post_off = terms_off + terms_bytes.len();
    let docs_off = post_off + postings_buf.len();

    let mut out: Vec<u8> = Vec::with_capacity(docs_off + docs_bytes.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&MAPPED_SEGMENT_VERSION.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // flags
    out.extend_from_slice(&(doc_count as u64).to_le_bytes());
    out.extend_from_slice(&(build.total_doc_length as u64).to_le_bytes());
    out.extend_from_slice(&(build.terms.len() as u64).to_le_bytes());
    out.extend_from_slice(&(terms_off as u64).to_le_bytes());
    out.extend_from_slice(&(terms_bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(&(post_off as u64).to_le_bytes());
    out.extend_from_slice(&(postings_buf.len() as u64).to_le_bytes());
    out.extend_from_slice(&(docs_off as u64).to_le_bytes());
    out.extend_from_slice(&(docs_bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // reserved
    debug_assert_eq!(out.len(), HEADER_LEN);
    out.extend_from_slice(&terms_bytes);
    out.extend_from_slice(&postings_buf);
    out.extend_from_slice(&docs_bytes);

    Ok(Some(out))
}

/// Bucket the live index into per-segment builds.
///
/// Documents are assigned by the same `segment_of` the bincode format uses, so a
/// document keeps its segment across a format change and an incremental commit
/// still knows which segments a change touched.
fn bucket<'a, Id: DocId + Serialize>(
    index: &'a HashMap<String, Postings<Id>>,
    doc_lengths: &HashMap<Id, usize>,
    segment_count: usize,
) -> Result<Vec<SegmentBuild<'a, Id>>, SearchError> {
    let mut builds: Vec<SegmentBuild<'a, Id>> = (0..segment_count)
        .map(|_| SegmentBuild {
            terms: BTreeMap::new(),
            docs: Vec::new(),
            total_doc_length: 0,
        })
        .collect();

    for (id, doc_length) in doc_lengths {
        let segment = crate::segment_of(id, segment_count);
        let encoded = bincode::serialize(id).map_err(|err| {
            SearchError::IndexError(format!("failed to encode a document id: {err}"))
        })?;
        builds[segment].docs.push((*id, encoded, *doc_length));
        builds[segment].total_doc_length += *doc_length;
    }
    for build in builds.iter_mut() {
        // The encoded bytes are the ordering key, so a lookup can binary-search
        // the blob without decoding anything. `bincode` is injective for a given
        // type, so equal bytes mean equal ids.
        build.docs.sort_unstable_by(|a, b| a.1.cmp(&b.1));
    }

    for (token, postings) in index {
        for (id, weights) in &postings.by_doc {
            if !doc_lengths.contains_key(id) {
                continue;
            }
            let segment = crate::segment_of(id, segment_count);
            builds[segment]
                .terms
                .entry(token.as_str())
                .or_default()
                .push((*id, weights.as_slice()));
        }
    }

    Ok(builds)
}

/// Write the whole live index as a mapped image: one file per non-empty segment
/// plus the manifest, which is renamed into place after every segment it names
/// is fsynced.
pub(crate) fn write_mapped<Id: DocId + Serialize>(
    storage_path: &Path,
    index: &HashMap<String, Postings<Id>>,
    doc_lengths: &HashMap<Id, usize>,
    segment_count: usize,
    doc_count: usize,
    total_doc_length: usize,
    graph_root_hash: Option<[u8; 32]>,
) -> Result<(), SearchError> {
    if let Some(parent) = storage_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            SearchError::IndexError(format!(
                "failed to create text index directory {}: {err}",
                parent.display()
            ))
        })?;
    }

    // Generations, and why a fixed 0 was a crash-safety defect rather than a
    // simplification.
    //
    // A segment is published by renaming a temp file over its name, so an
    // already-open mapping keeps its own inode and a reader in flight sees a
    // consistent snapshot. But a SECOND write at the same generation renames
    // over the very file the CURRENT manifest names, and a crash between that
    // rename and the manifest's leaves the old manifest naming a mixture of old
    // and new segments. The load-time sums would probably catch that, which is
    // luck rather than design.
    //
    // Bumping past whatever the live manifest names is what makes the manifest
    // the only commit point: until it is renamed into place, every file it names
    // is untouched, so a crash leaves the previous image entirely intact.
    let previous = read_manifest_gens(storage_path);
    let builds = bucket(index, doc_lengths, segment_count)?;
    let mut gens: Vec<Option<u64>> = vec![None; segment_count];
    let mut tombstones: Vec<Tombstones> = Vec::with_capacity(segment_count);

    for (segment, build) in builds.iter().enumerate() {
        tombstones.push(Tombstones::for_docs(build.docs.len()));
        let Some(encoded) = encode_segment(build)? else {
            continue;
        };
        let gen = previous
            .get(segment)
            .and_then(|gen| *gen)
            .map(|gen| gen.wrapping_add(1))
            .unwrap_or(0);
        let file = segment_path(storage_path, segment, gen);
        crate::write_and_promote(&file, &encoded)?;
        gens[segment] = Some(gen);
    }

    let manifest = MappedManifest {
        version: MAPPED_SEGMENT_VERSION,
        segment_count,
        segment_gens: gens,
        doc_count,
        total_doc_length,
        graph_root_hash,
        tombstones,
    };
    let encoded = bincode::serialize(&manifest).map_err(|err| {
        SearchError::IndexError(format!("failed to encode the mapped manifest: {err}"))
    })?;
    crate::write_and_promote(&manifest_path(storage_path), &encoded)?;

    // Committed. Reclaim the generations the new manifest no longer names.
    // Best-effort on purpose: an orphan is harmless because load only follows
    // the manifest, and on Windows a file another process still has mapped
    // cannot be unlinked at all.
    for (segment, old_gen) in previous.iter().enumerate() {
        let Some(old_gen) = old_gen else { continue };
        if manifest.segment_gens.get(segment).copied().flatten() != Some(*old_gen) {
            let _ = std::fs::remove_file(segment_path(storage_path, segment, *old_gen));
        }
    }
    Ok(())
}

/// The generations the manifest on disk names, whichever shape it is, or an
/// empty list when there is no readable manifest there.
///
/// Shared by BOTH writers, and that is the point rather than a convenience. A
/// writer that derives generations only from its own in-memory baseline will
/// pick 0 whenever that baseline is absent, and 0 is exactly what the other
/// writer picks on an empty directory. The two then rename onto the same names
/// while a manifest still points at them, which is the window either writer's
/// generation scheme exists to close.
///
/// Read as raw little-endian bytes for the version first, because a v3 or v4
/// manifest is a different struct and `bincode` allows trailing bytes: decoding
/// one as a `MappedManifest` would yield plausible generations rather than fail.
/// A non-mapped or unreadable manifest yields no generations, so the write below
/// starts at 0 and cannot collide with a file this format never wrote.
pub(crate) fn read_manifest_gens(storage_path: &Path) -> Vec<Option<u64>> {
    let Ok(bytes) = std::fs::read(manifest_path(storage_path)) else {
        return Vec::new();
    };
    if bytes.len() < 4 {
        return Vec::new();
    }
    let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if version == MAPPED_SEGMENT_VERSION {
        return match bincode::deserialize::<MappedManifest>(&bytes) {
            Ok(manifest) if manifest.version == MAPPED_SEGMENT_VERSION => manifest.segment_gens,
            _ => Vec::new(),
        };
    }
    // A v3 or v4 manifest's generations count too, because `segment_path` is one
    // namespace shared by both formats. Ignoring them let a mapped write rename
    // over the very files a live bincode manifest named, which destroys the
    // previous image before the new manifest is published: a crash in that
    // window leaves the old manifest pointing at a mixture.
    if (crate::MIN_SEGMENTED_FORMAT_VERSION..MAPPED_SEGMENT_VERSION).contains(&version) {
        return match bincode::deserialize::<crate::SegmentManifest>(&bytes) {
            Ok(manifest) if manifest.version == version => manifest.segment_gens,
            _ => Vec::new(),
        };
    }
    Vec::new()
}

// ── The reader ───────────────────────────────────────────────────────────────

/// One mapped segment file.
///
/// Holds the mapping and the section bounds it read out of the header. Nothing
/// in the file is copied onto the heap: the term dictionary is an `fst::Map`
/// over a refcounted sub-slice of the mapping, and the postings and document
/// table are read straight out of it.
struct MappedSegment {
    map: Arc<Mmap>,
    terms: fst::Map<MmapRange>,
    post: (usize, usize),
    docs: (usize, usize),
    doc_count: usize,
    total_doc_length: usize,
}

/// A term's postings, positioned for a forward walk.
///
/// It borrows the segment rather than just its postings bytes, so a posting's
/// ordinal is checked against the document table as it is read and a run is
/// bounded by that document's own token count. Both come from the same file, so
/// a torn postings section is caught by the part of the file that disagrees with
/// it rather than by an allocator.
struct TermCursor<'a> {
    segment: &'a MappedSegment,
    pos: usize,
    remaining: u64,
    previous: i64,
    /// Occurrences the term declared and the walk has not yet spent. Two bounds
    /// rather than one: this caps the term as a whole, `doc_length` caps each
    /// document, and neither alone is enough because a file can inflate either
    /// side on its own.
    budget: u64,
}

impl TermCursor<'_> {
    /// The next posting: the document ordinal and its length, with the
    /// document's weights appended to `weights` in the order it contributed
    /// them.
    ///
    /// `weights` is cleared first and reused across calls, so a walk over a hot
    /// term allocates once rather than once per document.
    fn next(
        &mut self,
        weight_table: &[f32],
        weights: &mut Vec<f32>,
    ) -> Result<Option<(u32, usize)>, String> {
        if self.remaining == 0 {
            return Ok(None);
        }
        self.remaining -= 1;
        let data = self.segment.postings_section();
        let delta = get_uvarint(data, &mut self.pos).ok_or("truncated posting delta")?;
        let ordinal_i64 = self
            .previous
            .checked_add(1)
            .and_then(|base| i64::try_from(delta).ok().and_then(|d| base.checked_add(d)))
            .ok_or("posting ordinal overflows")?;
        let ordinal = u32::try_from(ordinal_i64).map_err(|_| "posting ordinal out of range")?;
        self.previous = ordinal_i64;

        // The document's own token count is the bound on how many times it can
        // hold one token, and it is the only bound that means anything. Without
        // it a torn run length of `u64::MAX` pushes four bytes per iteration
        // until the allocator gives up: a hang and an abort rather than a typed
        // corruption error. It doubles as the check that every posting names an
        // ordinal the document table actually holds, which otherwise fell
        // through to scoring the document at `avgdl`.
        let doc_length = self
            .segment
            .doc_length(ordinal)
            .ok_or("a posting names an ordinal the document table does not hold")?;

        let run_count = get_uvarint(data, &mut self.pos).ok_or("truncated run count")?;
        weights.clear();
        for _ in 0..run_count {
            let code = get_uvarint(data, &mut self.pos).ok_or("truncated weight code")?;
            let repeat = get_uvarint(data, &mut self.pos).ok_or("truncated run length")?;
            let repeat = usize::try_from(repeat).map_err(|_| "run length out of range")?;
            let weight = *weight_table
                .get(usize::try_from(code).map_err(|_| "weight code out of range")?)
                .ok_or("a posting names a weight the segment never interned")?;
            if weights.len().saturating_add(repeat) > doc_length {
                return Err(format!(
                    "a posting claims more than {doc_length} occurrences of one token in a \
                     document of {doc_length} tokens"
                ));
            }
            let spend = u64::try_from(repeat).map_err(|_| "run length out of range")?;
            self.budget = self
                .budget
                .checked_sub(spend)
                .ok_or("a term's runs claim more occurrences than the term declares")?;
            for _ in 0..repeat {
                weights.push(weight);
            }
        }
        Ok(Some((ordinal, doc_length)))
    }
}

impl MappedSegment {
    fn open(path: &Path) -> Result<Self, String> {
        let file = std::fs::File::open(path).map_err(|err| format!("unreadable: {err}"))?;
        // Safety, stated as what actually holds rather than as what would be
        // convenient. Every writer in this crate publishes a segment by renaming
        // a freshly written temp file over the name, so the inode behind an
        // existing mapping is never modified, whatever generation the name
        // carries; and the best-effort unlink of a superseded generation is safe
        // under POSIX because the inode outlives the mapping. What this does NOT
        // survive is a foreign process truncating a segment file, which faults
        // the pages past the new end; that is inherent to serving an index from
        // a mapping and every mmap-backed index carries it.
        let map = unsafe { Mmap::map(&file) }.map_err(|err| format!("unmappable: {err}"))?;
        let data = &map[..];
        if data.len() < HEADER_LEN {
            return Err(format!("truncated header ({} bytes)", data.len()));
        }
        if data[0..8] != MAGIC {
            return Err("not a mapped segment (bad magic)".to_string());
        }
        let version = read_u32(data, 8).ok_or("truncated version")?;
        if version != MAPPED_SEGMENT_VERSION {
            return Err(format!(
                "mapped segment version {version}, this build writes {MAPPED_SEGMENT_VERSION}"
            ));
        }
        let doc_count = read_u64(data, 16).ok_or("truncated doc count")? as usize;
        let total_doc_length = read_u64(data, 24).ok_or("truncated total doc length")? as usize;
        let terms_off = read_u64(data, 40).ok_or("truncated terms offset")? as usize;
        let terms_len = read_u64(data, 48).ok_or("truncated terms length")? as usize;
        let post_off = read_u64(data, 56).ok_or("truncated postings offset")? as usize;
        let post_len = read_u64(data, 64).ok_or("truncated postings length")? as usize;
        let docs_off = read_u64(data, 72).ok_or("truncated docs offset")? as usize;
        let docs_len = read_u64(data, 80).ok_or("truncated docs length")? as usize;

        let end = data.len();
        for (name, off, len) in [
            ("terms", terms_off, terms_len),
            ("postings", post_off, post_len),
            ("docs", docs_off, docs_len),
        ] {
            if off > end || len > end - off {
                return Err(format!(
                    "section {name} at {off}+{len} runs past the {end}-byte file"
                ));
            }
        }

        // Bound `doc_count` against the section that has to hold its tables
        // before any offset is computed from it. Without this, a torn header
        // declaring four billion documents makes the fixed-stride arithmetic
        // below overflow, and a daemon panics on a file it should have refused.
        let tables = doc_count
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(4))
            .and_then(|n| n.checked_add(8));
        match tables {
            Some(needed) if needed <= docs_len => {}
            _ => {
                return Err(format!(
                    "a {doc_count}-document table does not fit the {docs_len}-byte docs section"
                ));
            }
        }

        let map = Arc::new(map);
        let terms = fst::Map::new(MmapRange {
            map: Arc::clone(&map),
            start: terms_off,
            end: terms_off + terms_len,
        })
        .map_err(|err| format!("undecodable term dictionary: {err}"))?;

        // `fst::Map::new` is not validation. It checks the length, the version
        // word and one root-address plausibility test, and never the CRC32 it
        // wrote; fst's own comment on that cheap check says a false positive
        // means "the program will probably panic" or "the FST will operate but
        // be subtly wrong". A traversal over a corrupt transition table can
        // panic on an out-of-bounds node or fail to terminate, so the checksum
        // is computed here instead.
        //
        // It costs one sequential pass over the term dictionary per segment at
        // open, which is the section that scales with vocabulary rather than
        // with occurrences. If that ever becomes material on a large corpus the
        // answer is to move it off the open path, not to drop it: an unverified
        // FST is a query that hangs or lies.
        terms
            .as_fst()
            .verify()
            .map_err(|err| format!("the term dictionary fails its own checksum: {err}"))?;

        let segment = Self {
            map,
            terms,
            post: (post_off, post_len),
            docs: (docs_off, docs_len),
            doc_count,
            total_doc_length,
        };
        segment.validate_document_table()?;
        Ok(segment)
    }

    /// Check the document table once, so every read against it afterwards is
    /// sound rather than trusting.
    ///
    /// Two properties, and both are load-bearing. The offsets must be
    /// CONTIGUOUS and end at the blob's length, because `encoded_id` slices
    /// `start..end` from a neighbouring pair and `bincode` ignores trailing
    /// bytes: shift one offset back and an over-long slice decodes fine, so a
    /// document's score comes back under a DIFFERENT live document's id and the
    /// same id appears twice in one result list. And the ids must be STRICTLY
    /// INCREASING in their encoded bytes, because `ordinal_of` binary-searches
    /// them; on an unsorted blob it answers `None`, so `contains` says a present
    /// document is absent and `remove` silently removes nothing and reports
    /// nothing.
    fn validate_document_table(&self) -> Result<(), String> {
        let data = self.docs_section();
        let stored = read_u64(data, 0).ok_or("truncated document count")? as usize;
        if stored != self.doc_count {
            return Err(format!(
                "the header declares {} documents and the document table {stored}",
                self.doc_count
            ));
        }
        let blob_at = 8 + 4 * (self.doc_count + 1) + 4 * self.doc_count;
        let blob_len = data.len().saturating_sub(blob_at);

        // The offset array, walked over its own n+1 entries.
        //
        // The first version of this compared each document's start against the
        // PREVIOUS document's end, which reads the same slot twice and is
        // therefore an identity for every ordinal above zero. What actually
        // needs to hold is that the array is non-decreasing, starts at 0 and
        // ends at the blob's length: that makes every `blob[offsets[i]..
        // offsets[i+1]]` slice well formed, which is what `encoded_id` assumes
        // and what `bincode`'s trailing-byte tolerance otherwise turns into one
        // document's score under another's id.
        let mut previous = 0usize;
        for ordinal in 0..=self.doc_count {
            let offset = read_u32(data, 8 + 4 * ordinal).ok_or("truncated id offset")? as usize;
            if ordinal == 0 && offset != 0 {
                return Err(format!("the first document id starts at {offset}, not 0"));
            }
            if offset < previous {
                return Err(format!(
                    "the id offset for document {ordinal} goes backwards, {previous} to {offset}"
                ));
            }
            if ordinal > 0 && offset == previous {
                return Err(format!("document {} has a zero-length id", ordinal - 1));
            }
            previous = offset;
        }
        if previous != blob_len {
            return Err(format!(
                "the document ids end at {previous} and the blob is {blob_len} bytes"
            ));
        }

        // The ids, which must be STRICTLY increasing because `ordinal_of`
        // binary-searches them; and the LENGTHS, which nothing checked before.
        // `doc_length` is the bound the posting walk refuses runs against, so an
        // unvalidated one made that bound only as strong as a u32 out of a torn
        // file: one length of `0xFFFF_FFFF` let a single run ask for 17.2 GiB.
        let mut previous_id: &[u8] = &[];
        let mut length_sum = 0usize;
        for ordinal in 0..self.doc_count {
            let ordinal = u32::try_from(ordinal).map_err(|_| "ordinal out of range")?;
            let id = self
                .encoded_id(ordinal)
                .ok_or("a document id runs past the table")?;
            if ordinal > 0 && id <= previous_id {
                return Err(format!(
                    "document {ordinal} does not sort after {}, so the table is not searchable",
                    ordinal - 1
                ));
            }
            let doc_length = self
                .doc_length(ordinal)
                .ok_or("a document length runs past the table")?;
            length_sum = length_sum
                .checked_add(doc_length)
                .ok_or("the document lengths overflow")?;
            previous_id = id;
        }

        // Two sections of one file have to agree about how many occurrences it
        // holds. Every occurrence belongs to exactly one document, so the
        // lengths sum to the header's total, and a torn file breaks that
        // agreement rather than quietly widening the run bound.
        if length_sum != self.total_doc_length {
            return Err(format!(
                "the document lengths sum to {length_sum} and the header declares {}",
                self.total_doc_length
            ));
        }
        Ok(())
    }

    fn postings_section(&self) -> &[u8] {
        &self.map[self.post.0..self.post.0 + self.post.1]
    }

    fn docs_section(&self) -> &[u8] {
        &self.map[self.docs.0..self.docs.0 + self.docs.1]
    }

    /// The segment's weight table, decoded from the head of POSTINGS.
    ///
    /// Small by construction: kin-db supplies fourteen field weights, and this
    /// store's segments carry nine each. Decoded per query rather than held,
    /// because holding it would be the only per-term resident byte in the design.
    fn weight_table(&self) -> Result<(Vec<f32>, usize), String> {
        let data = self.postings_section();
        let mut pos = 0usize;
        let count = get_uvarint(data, &mut pos).ok_or("truncated weight table")?;
        let count = usize::try_from(count).map_err(|_| "weight table too large")?;
        // Bounded against the section BEFORE the allocation, not after. The
        // count is a varint out of a file a crash may have torn, and reserving
        // from it first turns a corrupt segment into a capacity overflow or an
        // allocator abort inside a query rather than a typed error: the varint
        // `80 80 80 80 80 80 80 80 80 01` asks for 2^63 entries and the
        // per-entry read that would have caught it never runs.
        let available = data.len().saturating_sub(pos) / 4;
        if count > available {
            return Err(format!(
                "a weight table of {count} entries does not fit the {available} that remain in \
                 the postings section"
            ));
        }
        let mut table = Vec::with_capacity(count);
        for _ in 0..count {
            let bits = read_u32(data, pos).ok_or("truncated weight")?;
            pos += 4;
            table.push(f32::from_bits(bits));
        }
        Ok((table, pos))
    }

    fn cursor_at(&self, offset: u64) -> Result<(TermCursor<'_>, u64), String> {
        let data = self.postings_section();
        let mut pos = usize::try_from(offset).map_err(|_| "term offset out of range")?;
        if pos > data.len() {
            return Err("term offset runs past the postings section".to_string());
        }
        let df = get_uvarint(data, &mut pos).ok_or("truncated document frequency")?;
        let occurrences = get_uvarint(data, &mut pos).ok_or("truncated occurrence count")?;
        // `df` is not bounded here and does not need to be: every iteration of
        // the walk consumes at least one byte of a bounded section, so an
        // inflated count terminates in a truncation error rather than looping.
        //
        // `occurrences` IS bounded, against the same total the document lengths
        // are validated to sum to. It was read and discarded before, which
        // wasted the one value in the format that ties a term's postings to the
        // document table, and the cursor now spends it as a budget.
        let total = u64::try_from(self.total_doc_length).map_err(|_| "segment total too large")?;
        if occurrences > total {
            return Err(format!(
                "a term declares {occurrences} occurrences in a segment of {total}"
            ));
        }
        Ok((
            TermCursor {
                segment: self,
                pos,
                remaining: df,
                previous: -1,
                budget: occurrences,
            },
            occurrences,
        ))
    }

    fn stored_df(&self, offset: u64) -> Result<u64, String> {
        let data = self.postings_section();
        let mut pos = usize::try_from(offset).map_err(|_| "term offset out of range")?;
        get_uvarint(data, &mut pos).ok_or_else(|| "truncated document frequency".to_string())
    }

    fn doc_length(&self, ordinal: u32) -> Option<usize> {
        let data = self.docs_section();
        let index = ordinal as usize;
        if index >= self.doc_count {
            return None;
        }
        let at = 8 + 4 * (self.doc_count + 1) + 4 * index;
        read_u32(data, at).map(|length| length as usize)
    }

    fn encoded_id(&self, ordinal: u32) -> Option<&[u8]> {
        let data = self.docs_section();
        let index = ordinal as usize;
        if index >= self.doc_count {
            return None;
        }
        let offsets_at = 8;
        let blob_at = 8 + 4 * (self.doc_count + 1) + 4 * self.doc_count;
        let start = read_u32(data, offsets_at + 4 * index)? as usize;
        let end = read_u32(data, offsets_at + 4 * (index + 1))? as usize;
        data.get(blob_at + start..blob_at + end)
    }

    /// The ordinal of a document, by binary search over the id blob.
    ///
    /// The blob is ordered by the encoded bytes, so this needs no decode and no
    /// resident map: a lookup touches about `log2(n)` pages.
    fn ordinal_of(&self, encoded: &[u8]) -> Option<u32> {
        let mut low = 0usize;
        let mut high = self.doc_count;
        while low < high {
            let mid = low + (high - low) / 2;
            match self.encoded_id(mid as u32)?.cmp(encoded) {
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => high = mid,
                std::cmp::Ordering::Equal => return Some(mid as u32),
            }
        }
        None
    }
}

/// Where one segment holds a term.
struct TermSlot {
    segment: usize,
    offset: u64,
}

/// One entry of the scoring plan: a term, its IDF, its penalty, and where its
/// postings live.
struct ScoringTerm {
    idf: f32,
    penalty: f32,
    slots: Vec<TermSlot>,
}

/// Map every segment the manifest names.
fn open_segments(
    storage_path: &Path,
    manifest: &MappedManifest,
    m_path: &Path,
    archive_corrupt: bool,
) -> Result<Vec<Option<MappedSegment>>, SearchError> {
    let mut segments: Vec<Option<MappedSegment>> = Vec::with_capacity(manifest.segment_count);
    for (segment, gen) in manifest.segment_gens.iter().enumerate() {
        let Some(gen) = gen else {
            segments.push(None);
            continue;
        };
        let file = segment_path(storage_path, segment, *gen);
        match MappedSegment::open(&file) {
            Ok(mapped) => segments.push(Some(mapped)),
            Err(reason) => {
                return Err(corrupt_index_error(
                    m_path,
                    format!("segment {segment} gen {gen}: {reason}"),
                    archive_corrupt,
                ));
            }
        }
    }
    Ok(segments)
}

/// Make the manifest agree with the segments it names, or refuse.
///
/// Shared by both readers of a mapped image, and that is the point rather than a
/// tidy-up. The hardening lived only in the mapped reader, while the ordinary
/// load path is the one `TextIndex::open` actually calls, so the exact bytes one
/// reader refused the other served: a manifest with a tombstone bit and a count
/// of zero came back with one document fewer, no error, and the graph-root stamp
/// still trusted, so a consumer keying freshness on that hash would keep a short
/// index forever. Two readers of one image disagreeing about whether it is
/// corrupt is worse than either verdict.
///
/// Three things, in order:
///
/// 1. Every tombstone count is recomputed from its own bits. The count and the
///    bits gate different decisions, so a disagreement hides a document from
///    results while still counting it in `N`, in `avgdl` and in every `df`.
/// 2. A bit at or beyond a segment's document count is refused. It is
///    unreachable by every read, so it cannot remove anything, but it makes
///    `any()` true and drops every `live_df` for that segment off the O(1)
///    stored count onto a full counted walk, for a removal that does not exist.
/// 3. The documents and the token totals the segments hold, less what is
///    tombstoned, must be what the manifest claims.
fn reconcile(
    m_path: &Path,
    manifest: &mut MappedManifest,
    segments: &[Option<MappedSegment>],
    archive_corrupt: bool,
) -> Result<(), SearchError> {
    for tombstones in manifest.tombstones.iter_mut() {
        tombstones.rebuild_count();
    }

    let mut mapped_docs = 0usize;
    let mut mapped_length = 0usize;
    let mut removed = 0usize;
    let mut removed_length = 0usize;
    for (segment, mapped) in segments.iter().enumerate() {
        let Some(mapped) = mapped else { continue };
        mapped_docs += mapped.doc_count;
        mapped_length += mapped.total_doc_length;
        let tombstones = &manifest.tombstones[segment];
        if !tombstones.any() {
            continue;
        }
        let reachable = tombstones.highest_set().unwrap_or(0);
        if reachable >= mapped.doc_count {
            return Err(corrupt_index_error(
                m_path,
                format!(
                    "segment {segment} has a tombstone at ordinal {reachable} in a segment of {} \
                     documents, which no read can reach",
                    mapped.doc_count
                ),
                archive_corrupt,
            ));
        }
        // Walked rather than taken from a stored count, so the check stays right
        // once a commit starts publishing tombstones: a removed document's
        // LENGTH has to come out of the total as well as its count, or `avgdl`
        // drifts and every score in the corpus moves. One pass per removed
        // ordinal, and zero for an image this build writes.
        for ordinal in 0..mapped.doc_count {
            let Ok(ordinal) = u32::try_from(ordinal) else {
                break;
            };
            if !tombstones.is_set(ordinal) {
                continue;
            }
            removed += 1;
            removed_length += mapped.doc_length(ordinal).unwrap_or(0);
        }
    }
    let expected_docs = mapped_docs.saturating_sub(removed);
    let expected_length = mapped_length.saturating_sub(removed_length);
    if expected_docs != manifest.doc_count || expected_length != manifest.total_doc_length {
        return Err(corrupt_index_error(
            m_path,
            format!(
                "the segments hold {mapped_docs} documents of {mapped_length} tokens with \
                 {removed} documents of {removed_length} tokens tombstoned, which is \
                 {expected_docs} of {expected_length}, and the manifest claims {} of {}",
                manifest.doc_count, manifest.total_doc_length
            ),
            archive_corrupt,
        ));
    }
    Ok(())
}

/// A text index answered from mapped segment files.
///
/// What it retains is the mapping handles, the section bounds, one bit per
/// document and three counters. The term dictionary, the postings and the
/// document table are pages.
pub struct MappedIndex<Id: DocId> {
    segments: Vec<Option<MappedSegment>>,
    tombstones: Vec<Tombstones>,
    doc_count: usize,
    total_doc_length: usize,
    graph_root_hash: Option<[u8; 32]>,
    storage_path: PathBuf,
    marker: PhantomData<fn() -> Id>,
}

impl<Id: DocId> std::fmt::Debug for MappedIndex<Id> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MappedIndex")
            .field("documents", &self.doc_count)
            .field("segments", &self.segments.iter().flatten().count())
            .finish()
    }
}

impl<Id: DocId + Serialize + DeserializeOwned> MappedIndex<Id> {
    /// Open a mapped index written by [`write_mapped`].
    ///
    /// `path` is the same storage path the bincode formats use; the manifest and
    /// the segment files are its siblings.
    pub fn open(path: &Path) -> Result<Self, SearchError> {
        let storage_path = crate::storage_file_path_for(path);
        let m_path = manifest_path(&storage_path);
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
                false,
            ));
        }
        // The leading `version: u32` is read as raw little-endian bytes before
        // committing to a struct layout, which is what lets one manifest path
        // carry two shapes.
        let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if version != MAPPED_SEGMENT_VERSION {
            return Err(corrupt_index_error(
                &m_path,
                format!(
                    "manifest version {version} is not the mapped layout; \
                     the mapped reader serves version {MAPPED_SEGMENT_VERSION} only"
                ),
                false,
            ));
        }
        let manifest: MappedManifest = bincode::deserialize(&bytes).map_err(|err| {
            corrupt_index_error(&m_path, format!("undecodable manifest: {err}"), false)
        })?;
        if manifest.version != version {
            return Err(corrupt_index_error(
                &m_path,
                format!(
                    "declared version {version} but decoded version {}",
                    manifest.version
                ),
                false,
            ));
        }
        if manifest.segment_gens.len() != manifest.segment_count
            || manifest.tombstones.len() != manifest.segment_count
        {
            return Err(corrupt_index_error(
                &m_path,
                format!(
                    "manifest segment_count {} disagrees with {} generations and {} tombstone sets",
                    manifest.segment_count,
                    manifest.segment_gens.len(),
                    manifest.tombstones.len()
                ),
                false,
            ));
        }

        let mut manifest = manifest;
        let segments = open_segments(&storage_path, &manifest, &m_path, false)?;
        reconcile(&m_path, &mut manifest, &segments, false)?;

        Ok(Self {
            segments,
            tombstones: manifest.tombstones,
            doc_count: manifest.doc_count,
            total_doc_length: manifest.total_doc_length,
            graph_root_hash: manifest.graph_root_hash,
            storage_path,
            marker: PhantomData,
        })
    }

    /// Documents currently visible to search.
    pub fn live_document_count(&self) -> usize {
        self.doc_count
    }

    /// The graph-root stamp the manifest carries.
    pub fn graph_root_hash(&self) -> Option<[u8; 32]> {
        self.graph_root_hash
    }

    /// The storage path this index was opened from.
    pub fn storage_path(&self) -> &Path {
        &self.storage_path
    }

    fn segment_and_ordinal(&self, id: &Id) -> Option<(usize, u32)> {
        let encoded = bincode::serialize(id).ok()?;
        let segment_count = self.segments.len();
        if segment_count == 0 {
            return None;
        }
        let segment = crate::segment_of(id, segment_count);
        let mapped = self.segments.get(segment)?.as_ref()?;
        let ordinal = mapped.ordinal_of(&encoded)?;
        Some((segment, ordinal))
    }

    /// Whether a live document with this id is visible to search.
    pub fn contains(&self, id: &Id) -> bool {
        match self.segment_and_ordinal(id) {
            Some((segment, ordinal)) => !self.tombstones[segment].is_set(ordinal),
            None => false,
        }
    }

    /// Remove a document. Returns whether this call removed it.
    ///
    /// No forward map is consulted, because none exists: the ordinal's bit is
    /// set and every posting walk skips it from here on. The document's postings
    /// leave the file only when its segment is next rewritten.
    ///
    /// **The bit is not persisted by this call.** Tombstones live in the
    /// manifest, and the manifest is written by [`write_mapped`], so a removal
    /// made through this reader is visible to this handle and is lost when it is
    /// dropped. That is the reader's contract until the commit path moves onto
    /// this layout, and it is stated rather than implied because a delete that
    /// silently does not survive a reopen is the worst shape this could take.
    pub fn remove(&mut self, id: &Id) -> bool {
        let Some((segment, ordinal)) = self.segment_and_ordinal(id) else {
            return false;
        };
        let doc_length = self.segments[segment]
            .as_ref()
            .and_then(|mapped| mapped.doc_length(ordinal))
            .unwrap_or(0);
        if !self.tombstones[segment].set(ordinal) {
            return false;
        }
        self.doc_count = self.doc_count.saturating_sub(1);
        self.total_doc_length = self.total_doc_length.saturating_sub(doc_length);
        true
    }

    /// Every segment holding `token`, with the offset of its postings.
    fn slots_for(&self, token: &str) -> Vec<TermSlot> {
        let mut slots = Vec::new();
        for (segment, mapped) in self.segments.iter().enumerate() {
            let Some(mapped) = mapped else { continue };
            if let Some(offset) = mapped.terms.get(token.as_bytes()) {
                slots.push(TermSlot { segment, offset });
            }
        }
        slots
    }

    /// The number of LIVE documents holding a term, across every segment.
    ///
    /// Reads the stored count when a segment carries no tombstones, and counts
    /// the walk when it does. IDF therefore stays exact as documents are
    /// removed, rather than drifting toward a corpus that no longer exists.
    fn live_df(&self, slots: &[TermSlot]) -> Result<u64, SearchError> {
        let mut total = 0u64;
        for slot in slots {
            let mapped = self.segments[slot.segment]
                .as_ref()
                .expect("a slot names a mapped segment");
            if !self.tombstones[slot.segment].any() {
                total += mapped.stored_df(slot.offset).map_err(|reason| {
                    SearchError::IndexError(format!("segment {}: {reason}", slot.segment))
                })?;
                continue;
            }
            let (table, _) = mapped.weight_table().map_err(|reason| {
                SearchError::IndexError(format!("segment {}: {reason}", slot.segment))
            })?;
            let (mut cursor, _) = mapped.cursor_at(slot.offset).map_err(|reason| {
                SearchError::IndexError(format!("segment {}: {reason}", slot.segment))
            })?;
            let mut weights: Vec<f32> = Vec::new();
            while let Some((ordinal, _)) = cursor.next(&table, &mut weights).map_err(|reason| {
                SearchError::IndexError(format!("segment {}: {reason}", slot.segment))
            })? {
                if !self.tombstones[slot.segment].is_set(ordinal) {
                    total += 1;
                }
            }
        }
        Ok(total)
    }

    /// Document frequency of a query term: the count for its rarest token.
    ///
    /// The same contract [`TextIndex::doc_frequency`](crate::TextIndex::doc_frequency)
    /// offers, so a caller deriving a term-discrimination weight gets the same
    /// number from either index.
    pub fn doc_frequency(&self, term: &str) -> usize {
        let mut minimum: Option<usize> = None;
        for token in tokenize(term) {
            let slots = self.slots_for(&token);
            if slots.is_empty() {
                continue;
            }
            let df = match self.live_df(&slots) {
                Ok(df) => df as usize,
                Err(error) => {
                    // This returns a `usize` to match the heap index's
                    // signature, so a corrupt term cannot be reported to the
                    // caller. It is reported here instead of being treated as an
                    // absent token, because "absent" is a legitimate answer and
                    // corruption silently wearing its costume is how a search
                    // that quietly stops matching gets shipped.
                    tracing::error!(
                        token = %token,
                        error = %error,
                        "a mapped term could not be counted; treating it as absent for \
                         doc_frequency"
                    );
                    continue;
                }
            };
            // A live count of zero means this term is NOT indexed, and skipping
            // it is the whole of matching the heap index here.
            //
            // The heap index drops a posting list the moment it empties, so a
            // term whose every document was removed is simply not a key it
            // holds, and `min` never sees it. A mapped segment keeps the key in
            // its FST until the segment is rewritten, so counting it would drag
            // the minimum to zero and hand the caller a term-discrimination
            // weight for a token nothing holds. Concretely: remove the only
            // document containing `renderwidget`, then ask for
            // `"renderwidget shared"`; the heap answers with `shared`'s count
            // and this would have answered 0.
            if df == 0 {
                continue;
            }
            minimum = Some(minimum.map_or(df, |m: usize| m.min(df)));
        }
        minimum.unwrap_or(0)
    }

    /// Indexed tokens containing `query_token`, globally sorted and deduplicated.
    ///
    /// One traversal per segment under the `.*qt.*` automaton, merged through a
    /// `BTreeSet` so the order is exactly the sorted order the heap index visits
    /// its substring matches in. That order is part of the result: it fixes the
    /// sequence of float additions per document.
    fn forward_substring_matches(&self, query_token: &str) -> BTreeSet<Vec<u8>> {
        let mut matched: BTreeSet<Vec<u8>> = BTreeSet::new();
        let automaton = Contains::new(query_token.as_bytes());
        for mapped in self.segments.iter().flatten() {
            let mut stream = mapped.terms.search(&automaton).into_stream();
            while let Some((key, _)) = stream.next() {
                if key != query_token.as_bytes() {
                    matched.insert(key.to_vec());
                }
            }
        }
        matched
    }

    /// Tokens that could sit INSIDE `query_token` and carry enough of it.
    ///
    /// Candidates, not matches: presence in the term dictionary is the caller's
    /// filter, and it is applied there anyway.
    ///
    /// Enumerated rather than searched. Only a substring of the query can match
    /// this direction, and [`reverse_substring_admits`] floors its length at
    /// three quarters of the query's, so the loop starts at that floor rather
    /// than at [`MIN_SUBSTRING_LEN`]. That matters because `tokenize` emits
    /// whole path and identifier segments, so a long query token is ordinary
    /// input: scanning every start and end pair is 19,900 iterations for a
    /// 200-byte token against the 1,326 candidates that can actually clear the
    /// floor.
    fn reverse_substring_candidates(&self, query_token: &str) -> BTreeSet<Vec<u8>> {
        let mut matched: BTreeSet<Vec<u8>> = BTreeSet::new();
        let bytes = query_token.as_bytes();
        // The floor as integer arithmetic. `reverse_substring_admits` accepts a
        // candidate when `len * DEN >= |qt| * NUM`, so the shortest acceptable
        // length is `ceil(|qt| * NUM / DEN)`, which is `(|qt| * 3).div_ceil(4)`
        // and NOT `|qt|.div_ceil(4) * 3`: the second is larger for two lengths
        // in every four (a 5-byte query needs 4, not 6) and would silently drop
        // candidates the predicate accepts. A table over both forms is what
        // caught that, and the predicate is still called on every candidate, so
        // this only skips lengths it could never accept.
        let floor = crate::MIN_SUBSTRING_LEN.max((bytes.len() * 3).div_ceil(4));
        if floor > bytes.len() {
            return matched;
        }
        for start in 0..=(bytes.len() - floor) {
            for end in (start + floor)..=bytes.len() {
                let candidate = &bytes[start..end];
                if candidate == bytes {
                    continue;
                }
                // The same integer predicate the heap path applies, called
                // rather than restated, so the two cannot drift apart.
                let Ok(candidate_str) = std::str::from_utf8(candidate) else {
                    continue;
                };
                if !reverse_substring_admits(query_token, candidate_str) {
                    continue;
                }
                // Deliberately NOT probed for presence here. The caller's own
                // empty-slots check drops a candidate no segment holds, and
                // dropping elements from a sorted sequence leaves the order of
                // the rest alone, so the matched set and its visit order are
                // identical either way. Probing here would double the term
                // dictionary lookups a fuzzy query pays.
                matched.insert(candidate.to_vec());
            }
        }
        matched
    }

    /// Build the scoring plan in the order a serial scan of the heap index
    /// would: for each query token, its exact posting at penalty 1.0, then each
    /// substring match in sorted token order at penalty 0.5.
    fn scoring_terms(&self, query_tokens: &[String]) -> Result<Vec<ScoringTerm>, SearchError> {
        let n = self.doc_count as f32;
        let idf_of = |df: u64| -> f32 {
            let df = df as f32;
            ((n - df + 0.5) / (df + 0.5) + 1.0).ln().max(0.0)
        };

        let mut terms: Vec<ScoringTerm> = Vec::new();
        for query_token in query_tokens {
            let slots = self.slots_for(query_token);
            if !slots.is_empty() {
                let df = self.live_df(&slots)?;
                // A term with no live documents is not a key the heap index
                // holds, so it contributes no scoring term there either. It
                // would contribute nothing here as well, having no live postings
                // to walk, but skipping keeps the two paths the same shape and
                // saves the walk.
                if df > 0 {
                    terms.push(ScoringTerm {
                        idf: idf_of(df),
                        penalty: 1.0,
                        slots,
                    });
                }
            }

            if query_token.len() >= MIN_SUBSTRING_LEN {
                let mut matched = self.forward_substring_matches(query_token);
                matched.extend(self.reverse_substring_candidates(query_token));
                for token in matched {
                    let Ok(token) = std::str::from_utf8(&token) else {
                        continue;
                    };
                    let slots = self.slots_for(token);
                    if slots.is_empty() {
                        continue;
                    }
                    let df = self.live_df(&slots)?;
                    if df == 0 {
                        continue;
                    }
                    terms.push(ScoringTerm {
                        idf: idf_of(df),
                        penalty: 0.5,
                        slots,
                    });
                }
            }
        }
        Ok(terms)
    }

    /// Search, returning up to `limit` documents ranked highest first.
    ///
    /// Bit-identical to [`TextIndex::fuzzy_search`](crate::TextIndex::fuzzy_search)
    /// on the same corpus, which is asserted by a guard rather than asserted
    /// here.
    ///
    /// **The identity holds only for an `Id` whose `Debug` is injective.** The
    /// tie-break is `format!("{id:?}")`, on both sides, and a `Debug` that
    /// renders two distinct ids the same leaves the order of a score tie to
    /// whichever process-randomized `HashMap` iteration each side happened to
    /// produce, so the two disagree with each other and each disagrees run to
    /// run. That is inherited from the heap index rather than introduced here,
    /// and kin-db's `RetrievalKey` derives `Debug`, which is injective; a caller
    /// with a hand-written `Debug` is the case to watch. What makes it hold: the same BM25 constants, the same IDF over
    /// distinct live documents, the same per-occurrence saturation of the field
    /// weight, terms visited in the same order, a document's occurrences replayed
    /// in the order it contributed them, and the same tie-break on the id's
    /// `Debug` representation.
    pub fn fuzzy_search(
        &self,
        query_str: &str,
        limit: usize,
    ) -> Result<Vec<(Id, f32)>, SearchError> {
        let _span = tracing::info_span!(
            "kin_search.mapped.fuzzy_search",
            query = %query_str,
            limit = limit
        )
        .entered();
        let query_tokens = tokenize(query_str);
        if query_tokens.is_empty() || self.doc_count == 0 {
            return Ok(Vec::new());
        }

        let avgdl = self.total_doc_length as f32 / self.doc_count as f32;
        let terms = self.scoring_terms(&query_tokens)?;

        // Accumulate per document in canonical order: term order outside, and
        // within a term the document's own occurrence order. A document lives in
        // exactly one segment, so the order segments are visited in cannot reach
        // a document's accumulator, and the sum is invariant to it.
        // Keyed by (segment, ordinal) packed into a u64 rather than by the
        // document id, so a score accumulates without decoding an id. The decode
        // happens once per candidate at the end.
        let mut scores: HashMap<u64, f32> = HashMap::new();
        let mut weights: Vec<f32> = Vec::new();
        for term in &terms {
            for slot in &term.slots {
                let segment = slot.segment;
                let mapped = self.segments[segment]
                    .as_ref()
                    .expect("a slot names a mapped segment");
                let (table, _) = mapped.weight_table().map_err(|reason| {
                    SearchError::IndexError(format!("segment {segment}: {reason}"))
                })?;
                let (mut cursor, _) = mapped.cursor_at(slot.offset).map_err(|reason| {
                    SearchError::IndexError(format!("segment {segment}: {reason}"))
                })?;
                while let Some((ordinal, doc_length)) =
                    cursor.next(&table, &mut weights).map_err(|reason| {
                        SearchError::IndexError(format!("segment {segment}: {reason}"))
                    })?
                {
                    if self.tombstones[segment].is_set(ordinal) {
                        continue;
                    }
                    let key = ((segment as u64) << 32) | u64::from(ordinal);
                    // The cursor already resolved this against the document
                    // table, so there is no ordinal here that it does not hold.
                    // The heap index's `unwrap_or(avgdl)` fallback for a missing
                    // document has no counterpart because the case is refused
                    // rather than scored.
                    let dl = doc_length as f32;
                    let length_norm = BM25_K1 * (1.0 - BM25_B + BM25_B * dl / avgdl);
                    let accumulator = scores.entry(key).or_insert(0.0);
                    for weight in weights.iter() {
                        let tf = *weight;
                        let tf_saturated = (tf * (BM25_K1 + 1.0)) / (tf + length_norm);
                        *accumulator += (term.idf * tf_saturated) * term.penalty;
                    }
                }
            }
        }

        // Decode an id only for a document that scored, so a wide query costs
        // one decode per candidate rather than one per document in the corpus.
        let mut keyed: Vec<(String, Id, f32)> = Vec::with_capacity(scores.len());
        for (key, score) in scores {
            let segment = (key >> 32) as usize;
            let ordinal = (key & 0xffff_ffff) as u32;
            let mapped = self.segments[segment]
                .as_ref()
                .expect("a scored key names a mapped segment");
            let encoded = mapped.encoded_id(ordinal).ok_or_else(|| {
                SearchError::IndexError(format!(
                    "segment {segment} scored ordinal {ordinal}, which its document table does not hold"
                ))
            })?;
            let id: Id = bincode::deserialize(encoded).map_err(|err| {
                SearchError::IndexError(format!(
                    "segment {segment} holds an undecodable document id at ordinal {ordinal}: {err}"
                ))
            })?;
            keyed.push((format!("{id:?}"), id, score));
        }

        // The same comparator the heap index uses, for the same reason: a
        // `HashMap`'s iteration order is randomized per process, so tied scores
        // at the `truncate` cutoff would otherwise vary run to run.
        keyed.sort_by(|a, b| {
            let a_score = if a.2.is_nan() { 0.0 } else { a.2 };
            let b_score = if b.2.is_nan() { 0.0 } else { b.2 };
            b_score
                .partial_cmp(&a_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        keyed.truncate(limit);
        Ok(keyed
            .into_iter()
            .map(|(_, id, score)| (id, score))
            .collect())
    }
}

// ── Reading a mapped image back into the heap shapes ─────────────────────────

/// Materialize a v5 image into the in-memory shapes the bincode formats produce.
///
/// This is the compatibility direction, not the point of the format. It exists
/// so a store written with the mapped writer still opens on the ordinary load
/// path, and so a guard can compare the two representations of one set of bytes.
///
/// The forward map it rebuilds is grouped by token rather than by field, because
/// the mapped image is grouped that way and the original field interleaving is
/// not in it. Nothing reads that order: a delete resolves a document's tokens
/// into a set, and the segmented persist replays a document's occurrences of one
/// token contiguously, so it reconstructs the same weight sequence per posting
/// either way. The occurrence order WITHIN a token is preserved exactly, and
/// that is the order scores depend on.
pub(crate) fn rehydrate<Id: DocId + Serialize + DeserializeOwned>(
    storage_path: &Path,
    manifest_bytes: &[u8],
    archive_corrupt: bool,
) -> Result<crate::LoadedSegmented<Id>, SearchError> {
    let m_path = manifest_path(storage_path);
    let mut manifest: MappedManifest = bincode::deserialize(manifest_bytes).map_err(|err| {
        corrupt_index_error(
            &m_path,
            format!("undecodable mapped manifest: {err}"),
            archive_corrupt,
        )
    })?;
    if manifest.version != MAPPED_SEGMENT_VERSION {
        return Err(corrupt_index_error(
            &m_path,
            format!(
                "declared version {MAPPED_SEGMENT_VERSION} but decoded version {}",
                manifest.version
            ),
            archive_corrupt,
        ));
    }
    if manifest.segment_gens.len() != manifest.segment_count
        || manifest.tombstones.len() != manifest.segment_count
    {
        return Err(corrupt_index_error(
            &m_path,
            format!(
                "manifest segment_count {} disagrees with {} generations and {} tombstone sets",
                manifest.segment_count,
                manifest.segment_gens.len(),
                manifest.tombstones.len()
            ),
            archive_corrupt,
        ));
    }

    // The SAME reconciliation the mapped reader runs, on the same image. This
    // path is the one `TextIndex::open` actually calls, so leaving the
    // hardening on the other side of the fork meant the load-bearing reader was
    // the unhardened one.
    let segments = open_segments(storage_path, &manifest, &m_path, archive_corrupt)?;
    reconcile(&m_path, &mut manifest, &segments, archive_corrupt)?;

    let mut index: HashMap<String, Postings<Id>> = HashMap::new();
    let mut docs: HashMap<Id, crate::IndexedDoc> = HashMap::new();
    let mut vocab = crate::Vocabulary::default();
    let mut segment_docs: Vec<std::collections::HashSet<Id>> =
        vec![std::collections::HashSet::new(); manifest.segment_count];
    let mut doc_count = 0usize;
    let mut total_doc_length = 0usize;

    for (segment, mapped) in segments.iter().enumerate() {
        let Some(mapped) = mapped else { continue };
        let fail = |reason: String| {
            corrupt_index_error(
                &m_path,
                format!("segment {segment}: {reason}"),
                archive_corrupt,
            )
        };
        let tombstones = &manifest.tombstones[segment];

        // Live documents first, so a posting naming a tombstoned ordinal is
        // dropped rather than resurrected.
        let mut live: HashMap<u32, Id> = HashMap::new();
        for ordinal in 0..mapped.doc_count {
            let ordinal = u32::try_from(ordinal)
                .map_err(|_| fail("a segment holds over 4 billion documents".to_string()))?;
            if tombstones.is_set(ordinal) {
                continue;
            }
            let encoded = mapped
                .encoded_id(ordinal)
                .ok_or_else(|| fail(format!("no document id at ordinal {ordinal}")))?;
            let id: Id = bincode::deserialize(encoded)
                .map_err(|err| fail(format!("undecodable document id: {err}")))?;
            let doc_length = mapped
                .doc_length(ordinal)
                .ok_or_else(|| fail(format!("no document length at ordinal {ordinal}")))?;
            live.insert(ordinal, id);
            if docs
                .insert(
                    id,
                    crate::IndexedDoc {
                        tokens_by_field: Vec::new(),
                        doc_length,
                    },
                )
                .is_some()
            {
                return Err(fail("duplicate document id across segments".to_string()));
            }
            segment_docs[segment].insert(id);
            doc_count += 1;
            total_doc_length += doc_length;
        }

        let (table, _) = mapped.weight_table().map_err(fail)?;
        let mut stream = mapped.terms.stream();
        let mut weights: Vec<f32> = Vec::new();
        while let Some((key, offset)) = stream.next() {
            let token = std::str::from_utf8(key)
                .map_err(|err| fail(format!("a term is not UTF-8: {err}")))?
                .to_owned();
            let token_id = vocab.intern(&token);
            let (mut cursor, _) = mapped.cursor_at(offset).map_err(fail)?;
            while let Some((ordinal, _)) = cursor.next(&table, &mut weights).map_err(fail)? {
                let Some(id) = live.get(&ordinal) else {
                    continue;
                };
                // The entry is created only for a LIVE posting, so a term whose
                // every document was tombstoned leaves no empty posting list
                // behind for the scorer to divide by.
                let postings = index.entry(token.clone()).or_default();
                let doc = docs
                    .get_mut(id)
                    .expect("a live ordinal names a document just inserted");
                for weight in weights.iter() {
                    postings.add(*id, *weight);
                    doc.tokens_by_field.push((token_id, *weight));
                }
            }
        }
    }

    // The reconciliation above proved these against the segments, so the
    // manifest's are the ones to carry. Recomputing them here and returning the
    // recomputation is how this path silently repaired a disagreement the other
    // reader refuses.
    if doc_count != manifest.doc_count || total_doc_length != manifest.total_doc_length {
        return Err(corrupt_index_error(
            &m_path,
            format!(
                "the walk found {doc_count} live documents of {total_doc_length} tokens and the \
                 reconciled manifest says {} of {}",
                manifest.doc_count, manifest.total_doc_length
            ),
            archive_corrupt,
        ));
    }

    Ok(crate::LoadedSegmented {
        index,
        docs,
        vocab,
        doc_count,
        total_doc_length,
        graph_root_hash: manifest.graph_root_hash,
        segment_count: manifest.segment_count,
        // No reusable baseline: the bincode writer cannot delta a mapped image,
        // so the next commit rewrites every segment in the format it writes.
        baseline_gens: None,
        segment_docs,
    })
}

// ── Guards ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Searchable, TextIndex};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    struct Key(u64);

    struct Doc {
        name: String,
        signature: String,
        body: String,
        kind: String,
    }

    impl Searchable for Doc {
        fn search_fields(&self) -> Vec<(&str, f32)> {
            vec![
                (&self.name, 5.0),
                (&self.signature, 3.0),
                (&self.body, 1.5),
                (&self.kind, 1.0),
            ]
        }
    }

    /// Names chosen so the corpus exercises every shape the format has to carry:
    /// camelCase splits that put a token in several fields of one document,
    /// morphological pairs (`user`/`users`, `present`/`presentation`) that only
    /// the reverse substring direction retrieves, the FIR-2968 coincidence pair
    /// (`definitely`/`def`) that the 3/4 floor must refuse, and a multibyte token
    /// so the byte-keyed term dictionary and the substring automaton are tested
    /// off the ASCII path.
    const NAMES: &[&str] = &[
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
        "user",
        "users",
        "username",
        "usernames",
        "getUserById",
        "present",
        "presentation",
        "definitely",
        "rebuiltDoc",
        "doc",
        "persistMe",
        "debugMe",
        "deletePost",
        "alpha",
        "alphaHandler",
        "beta",
        "foo",
        "QdpReader",
        "naiveCase",
        "日本語トークン",
    ];

    /// Documents that tokenize IDENTICALLY, so a query on their shared token
    /// scores them exactly equally.
    ///
    /// Without a forced tie the tie-break is unreachable and a mutant that
    /// changed it would leave every guard here green. With one, the tie-break
    /// decides both their order and which of them survives `truncate(limit)`.
    const TWINS: usize = 6;

    /// Every query the identity guard runs. Exact hits, both substring
    /// directions, a query with no match at all, a query of only short tokens
    /// (which must skip the substring branch entirely), a multibyte query, the
    /// universal token every document holds, and the forced tie.
    const QUERIES: &[&str] = &[
        "shared",
        "handler",
        "twin",
        "parse",
        "parseTable",
        "widget",
        "render",
        "users",
        "usernames",
        "definitelyNoSuchSymbol",
        "presentation",
        "pres",
        "doc",
        "rebuilt",
        "id",
        "getUserById",
        "日本語",
        "トークン",
        "zzzznotathing",
        "search index",
        "",
    ];

    fn corpus() -> Vec<(Key, Doc)> {
        let mut docs: Vec<(Key, Doc)> = NAMES
            .iter()
            .enumerate()
            .map(|(index, name)| {
                // The body repeats the name and a shared word, so a document
                // contributes the same token several times in one field and in
                // several fields. That is what makes the run-length encoding
                // carry runs longer than one and what makes a posting's weight
                // sequence hold more than one distinct value.
                //
                // `shared` and `handler` land in EVERY body on purpose: a query
                // for either has to return the whole corpus, which is a floor
                // the fixture proves rather than one picked to pass.
                let body = format!(
                    "{name} {name} shared shared shared handler for {name} in module {index}"
                );
                (
                    Key(index as u64 + 1),
                    Doc {
                        name: (*name).to_string(),
                        signature: format!("fn {name}(input: &str) -> Result<(), Error>"),
                        body,
                        kind: if index % 2 == 0 { "Function" } else { "Method" }.to_string(),
                    },
                )
            })
            .collect();
        for twin in 0..TWINS {
            docs.push((
                Key(NAMES.len() as u64 + twin as u64 + 1),
                Doc {
                    name: "twin".to_string(),
                    signature: "fn twin(input: &str) -> Result<(), Error>".to_string(),
                    body: "twin twin shared shared shared handler for twin in module twin"
                        .to_string(),
                    kind: "Function".to_string(),
                },
            ));
        }
        docs
    }

    /// The floor the fixture proves rather than one chosen to pass.
    ///
    /// Every document's body holds `shared`, so a query for it must return the
    /// whole live corpus. An assertion about a count nobody can pick is what
    /// keeps the identity comparisons from being a comparison of two indexes
    /// that both answered nothing.
    fn assert_reaches_every_document(label: &str, results: &[(Key, f32)], live: usize) {
        assert_eq!(
            results.len(),
            live,
            "{label}: `shared` is in every document's body, so it must return all {live} of them"
        );
    }

    fn heap_index(docs: &[(Key, Doc)]) -> TextIndex<Key> {
        let index: TextIndex<Key> = TextIndex::new();
        for (id, doc) in docs {
            index.upsert_searchable(*id, doc).expect("upsert");
        }
        index.commit().expect("commit");
        index
    }

    /// Identical in id order and bit-for-bit in score. Compared on raw bits so
    /// no float rounding slips through a tolerance.
    fn assert_identical(label: &str, got: &[(Key, f32)], want: &[(Key, f32)]) {
        assert_eq!(
            got.len(),
            want.len(),
            "{label}: result count {} != reference {}\n got  {got:?}\n want {want:?}",
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

    /// THE guard this format exists to pass.
    ///
    /// The mapped reader must rank a corpus exactly as the heap index ranks it,
    /// for exact and fuzzy queries alike, at every segment count. Not "close":
    /// the same ids in the same order with the same score bits.
    ///
    /// Run at three segment counts on purpose. One segment puts every document
    /// in one file, so the posting deltas are large and the document table's
    /// binary search is deep. Four packs several documents per segment, so a term
    /// is split across segments and the global `df` is a sum. Sixty-four is the
    /// shipping default, where most segments are empty and get no file at all.
    #[test]
    fn the_mapped_reader_ranks_identically_to_the_heap_index() {
        let docs = corpus();
        let heap = heap_index(&docs);

        for segment_count in [1usize, 4, 64] {
            heap.seg.write().segment_count = segment_count;
            let dir = tempfile::tempdir().expect("tempdir");
            heap.persist_mapped(dir.path()).expect("persist_mapped");
            let mapped: MappedIndex<Key> = MappedIndex::open(dir.path()).expect("open mapped");

            assert_eq!(
                mapped.live_document_count(),
                heap.live_document_count(),
                "segments={segment_count}: document count"
            );

            let mut answered = 0usize;
            for query in QUERIES {
                // 3 lands the truncate cutoff inside the six-way tie, where
                // which documents survive is decided by the tie-break alone.
                for limit in [1usize, 3, 5, 100] {
                    let want = heap.fuzzy_search(query, limit).expect("heap search");
                    let got = mapped.fuzzy_search(query, limit).expect("mapped search");
                    assert_identical(
                        &format!("segments={segment_count} query={query:?} limit={limit}"),
                        &got,
                        &want,
                    );
                    answered += want.len();
                }
            }
            // Without this the assertions above would pass on two indexes that
            // both return nothing, which is the shape of a comparison about
            // nothing.
            assert_reaches_every_document(
                &format!("segments={segment_count}, mapped"),
                &mapped
                    .fuzzy_search("shared", docs.len() * 2)
                    .expect("mapped"),
                docs.len(),
            );
            assert_reaches_every_document(
                &format!("segments={segment_count}, heap"),
                &heap.fuzzy_search("shared", docs.len() * 2).expect("heap"),
                docs.len(),
            );
            assert!(
                answered > 3 * docs.len(),
                "segments={segment_count}: the queries produced only {answered} results, so the \
                 comparison above proves little"
            );

            for (id, _) in &docs {
                assert!(
                    mapped.contains(id),
                    "segments={segment_count}: {id:?} is missing from the mapped index"
                );
            }
            for term in ["parse", "widget", "shared", "user", "zzzznotathing"] {
                assert_eq!(
                    mapped.doc_frequency(term),
                    heap.doc_frequency(term),
                    "segments={segment_count}: doc_frequency({term:?})"
                );
            }
        }
    }

    /// A delete needs no forward map, and it must leave the index scoring as if
    /// the document had never been admitted.
    ///
    /// The assertion is against a heap index built from the SURVIVORS, not
    /// against the same index before the delete. That is the strong form: it
    /// catches a tombstone that hides a document from results while still
    /// counting it in `N`, in `avgdl`, or in a term's `df`, each of which would
    /// shift every score in the corpus by a little.
    #[test]
    fn a_tombstone_delete_ranks_as_if_the_document_was_never_admitted() {
        let docs = corpus();
        // One of them is a twin, so the deletes change the tie set as well as
        // the corpus statistics.
        let removed: Vec<Key> = vec![Key(1), Key(4), Key(13), Key(14), Key(35)];

        let full = heap_index(&docs);
        full.seg.write().segment_count = 4;
        let dir = tempfile::tempdir().expect("tempdir");
        full.persist_mapped(dir.path()).expect("persist_mapped");
        let mut mapped: MappedIndex<Key> = MappedIndex::open(dir.path()).expect("open mapped");

        for id in &removed {
            assert!(mapped.remove(id), "{id:?} should have been removed");
            assert!(!mapped.remove(id), "{id:?} should not remove twice");
        }

        let survivors: Vec<(Key, Doc)> = corpus()
            .into_iter()
            .filter(|(id, _)| !removed.contains(id))
            .collect();
        let reference = heap_index(&survivors);

        assert_eq!(
            mapped.live_document_count(),
            reference.live_document_count(),
            "live document count after the deletes"
        );
        for id in &removed {
            assert!(
                !mapped.contains(id),
                "{id:?} is still visible after removal"
            );
        }

        let mut answered = 0usize;
        for query in QUERIES {
            let want = reference.fuzzy_search(query, 100).expect("heap search");
            let got = mapped.fuzzy_search(query, 100).expect("mapped search");
            assert_identical(&format!("after delete, query={query:?}"), &got, &want);
            answered += want.len();
            for id in &removed {
                assert!(
                    !got.iter().any(|(hit, _)| hit == id),
                    "removed {id:?} came back for {query:?}"
                );
            }
        }
        assert_reaches_every_document(
            "after delete, mapped",
            &mapped
                .fuzzy_search("shared", docs.len() * 2)
                .expect("mapped"),
            docs.len() - removed.len(),
        );
        assert!(
            answered > docs.len(),
            "the queries produced only {answered} results after the deletes"
        );
        for term in ["parse", "user", "shared", "render"] {
            assert_eq!(
                mapped.doc_frequency(term),
                reference.doc_frequency(term),
                "doc_frequency({term:?}) must exclude tombstoned documents"
            );
        }
    }

    /// A v5 image must open on the ORDINARY load path too, so a store written by
    /// a build with the mapped writer is not unreadable to the query path that
    /// has not been cut over yet.
    #[test]
    fn a_mapped_image_round_trips_through_the_ordinary_load_path() {
        let docs = corpus();
        let heap = heap_index(&docs);
        heap.seg.write().segment_count = 8;

        let dir = tempfile::tempdir().expect("tempdir");
        let storage = dir.path().to_path_buf();
        heap.persist_mapped(&storage).expect("persist_mapped");

        let reopened: TextIndex<Key> = TextIndex::open(Some(&storage)).expect("open");
        assert_eq!(
            reopened.live_document_count(),
            heap.live_document_count(),
            "the rehydrated index holds a different number of documents"
        );

        let mut answered = 0usize;
        for query in QUERIES {
            let want = heap.fuzzy_search(query, 100).expect("heap search");
            let got = reopened
                .fuzzy_search(query, 100)
                .expect("rehydrated search");
            assert_identical(&format!("rehydrated, query={query:?}"), &got, &want);
            answered += want.len();
        }
        assert_reaches_every_document(
            "rehydrated",
            &reopened
                .fuzzy_search("shared", docs.len() * 2)
                .expect("rehydrated"),
            docs.len(),
        );
        assert!(
            answered > docs.len(),
            "only {answered} results, so this proves little"
        );

        // A rehydrated index must still be able to DELETE, which is the one
        // thing a mapped image drops on the floor: the forward map it rebuilds
        // has to name the right tokens or a removal takes the wrong postings.
        reopened.remove(&Key(1)).expect("remove");
        reopened.commit().expect("commit");
        assert!(!reopened.contains(&Key(1)));
        let survivors: Vec<(Key, Doc)> = corpus().into_iter().filter(|(id, _)| id.0 != 1).collect();
        let reference = heap_index(&survivors);
        for query in QUERIES {
            let want = reference.fuzzy_search(query, 100).expect("heap search");
            let got = reopened
                .fuzzy_search(query, 100)
                .expect("rehydrated search");
            assert_identical(&format!("rehydrated delete, query={query:?}"), &got, &want);
        }
    }

    fn poke_manifest_version(storage: &Path, version: u32) {
        let path = manifest_path(&crate::storage_file_path_for(storage));
        let mut bytes = std::fs::read(&path).expect("read manifest");
        bytes[0..4].copy_from_slice(&version.to_le_bytes());
        std::fs::write(&path, &bytes).expect("write manifest");
    }

    /// Reading is a range and writing is a point, and both ends of the range are
    /// controls rather than assumptions.
    ///
    /// The intact arm must be GREEN, or the refusals below prove only that
    /// something is broken. A version above the range and a version below the
    /// mapped layout must both be refused, and the mapped reader must refuse a
    /// bincode manifest by name rather than by decoding it into nonsense.
    #[test]
    fn the_reader_takes_a_range_and_the_writer_takes_a_point() {
        assert_eq!(
            MAPPED_SEGMENT_VERSION,
            crate::MAX_SEGMENTED_FORMAT_VERSION,
            "the mapped layout must be the newest version the loader reads"
        );
        let docs = corpus();
        let heap = heap_index(&docs);
        heap.seg.write().segment_count = 4;

        // Intact: the control that the refusals below mean something.
        let good = tempfile::tempdir().expect("tempdir");
        heap.persist_mapped(good.path()).expect("persist_mapped");
        let mapped: MappedIndex<Key> = MappedIndex::open(good.path()).expect("open intact");
        assert_eq!(mapped.live_document_count(), docs.len());
        assert!(!mapped
            .fuzzy_search("parse", 5)
            .expect("intact search")
            .is_empty());
        let heap_reopen: TextIndex<Key> =
            TextIndex::open(Some(&good.path().to_path_buf())).expect("intact heap reopen");
        assert_eq!(heap_reopen.live_document_count(), docs.len());

        // Above the range, on both readers.
        let future = tempfile::tempdir().expect("tempdir");
        heap.persist_mapped(future.path()).expect("persist_mapped");
        poke_manifest_version(future.path(), MAPPED_SEGMENT_VERSION + 1);
        assert!(
            MappedIndex::<Key>::open(future.path()).is_err(),
            "the mapped reader must refuse a version it does not write"
        );
        assert!(
            TextIndex::<Key>::open(Some(&future.path().to_path_buf())).is_err(),
            "the load path must refuse a segmented manifest above its range"
        );

        // Below the mapped layout: a bincode manifest is not a mapped one, and
        // the mapped reader has to say so rather than decode it. `bincode`
        // allows trailing bytes, so a version check is the only thing standing
        // between two manifest shapes and a silently wrong index.
        let bincode_dir = tempfile::tempdir().expect("tempdir");
        let bincode_storage = bincode_dir.path().join("index.bin");
        let persisted: TextIndex<Key> =
            TextIndex::open(Some(&bincode_storage)).expect("open for write");
        for (id, doc) in &docs {
            persisted.upsert_searchable(*id, doc).expect("upsert");
        }
        persisted.commit().expect("commit");
        let error = MappedIndex::<Key>::open(&bincode_storage)
            .expect_err("the mapped reader must refuse a bincode manifest");
        assert!(
            format!("{error}").contains("not the mapped layout"),
            "the refusal must name the reason, got: {error}"
        );
    }

    /// Neither writer may rename onto a name the live manifest holds.
    ///
    /// The mapped writer learned to read the live manifest's generations and
    /// write past them; the bincode writer was not taught anything, and its
    /// `unwrap_or(0)` for a missing baseline picks exactly the generation the
    /// mapped writer picks on an empty directory. So a commit with no baseline
    /// renamed v4 bytes onto the very names a live v5 manifest held, before the
    /// v4 manifest replaced it. A crash or a concurrent reader in that window
    /// finds a manifest naming files of the other format, and because the index
    /// is derived the recovery is to archive it and rebuild.
    ///
    /// Two ways in, and both are reached through a baseline THIS build clears on
    /// purpose, so both arms are here. Asserted as path disjointness rather than
    /// by simulating a crash, because disjointness is the property that makes
    /// the manifest the only commit point.
    #[test]
    fn no_writer_renames_onto_a_name_the_live_manifest_holds() {
        let docs = corpus();

        // Arm one: a mapped image, loaded on the ordinary path, then committed.
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = dir.path().join("index.bin");
        let heap = heap_index(&docs);
        heap.seg.write().segment_count = 4;
        heap.persist_mapped(&storage).expect("persist_mapped");
        let live = paths_named(&storage);
        assert!(!live.is_empty(), "the mapped write must name some segments");

        let reopened: TextIndex<Key> = TextIndex::open(Some(&storage)).expect("open");
        reopened
            .upsert_searchable(Key(8_001), &after_doc("armOne"))
            .expect("upsert");
        reopened.commit().expect("commit");
        let after = paths_named(&storage);
        assert!(!after.is_empty(), "the commit must name some segments");
        for path in &after {
            assert!(
                !live.contains(path),
                "arm one: the commit published {}, which the live mapped manifest already named",
                path.display()
            );
        }
        let back: TextIndex<Key> = TextIndex::open(Some(&storage)).expect("reopen");
        assert_eq!(back.live_document_count(), docs.len() + 1);

        // Arm two: no v5 file at this path at all. A mapped write to a DIFFERENT
        // path clears this one's baseline, and the next commit here must still
        // not land on its own live names.
        let dir_a = tempfile::tempdir().expect("tempdir");
        let dir_b = tempfile::tempdir().expect("tempdir");
        let a = dir_a.path().join("index.bin");
        let index: TextIndex<Key> = TextIndex::open(Some(&a)).expect("open a");
        index.seg.write().segment_count = 4;
        for (id, doc) in docs.iter().take(16) {
            index.upsert_searchable(*id, doc).expect("upsert");
        }
        index.commit().expect("commit a");
        let live_a = paths_named(&a);
        assert!(
            !live_a.is_empty(),
            "the bincode commit must name some segments"
        );

        index
            .persist_mapped(dir_b.path())
            .expect("persist_mapped b");
        index
            .upsert_searchable(Key(8_002), &after_doc("armTwo"))
            .expect("upsert");
        index.commit().expect("second commit a");
        let after_a = paths_named(&a);
        assert!(
            !after_a.is_empty(),
            "the second commit must name some segments"
        );
        for path in &after_a {
            assert!(
                !live_a.contains(path),
                "arm two: the commit published {}, which its own live manifest already named",
                path.display()
            );
        }
        let back_a: TextIndex<Key> = TextIndex::open(Some(&a)).expect("reopen a");
        assert_eq!(back_a.live_document_count(), 17);
    }

    /// The segment files a manifest at `storage` names, whichever shape it is.
    fn paths_named(storage: &Path) -> Vec<PathBuf> {
        let resolved = crate::storage_file_path_for(storage);
        read_manifest_gens(&resolved)
            .iter()
            .enumerate()
            .filter_map(|(segment, gen)| gen.map(|gen| segment_path(&resolved, segment, gen)))
            .collect()
    }

    fn after_doc(name: &str) -> Doc {
        Doc {
            name: name.to_string(),
            signature: format!("fn {name}(input: &str) -> Result<(), Error>"),
            body: format!("{name} shared shared shared handler for {name} in module after"),
            kind: "Function".to_string(),
        }
    }

    /// A mapped write over a bincode baseline must not leave the next ordinary
    /// commit able to publish a manifest that names files of the other format.
    ///
    /// The sequence that lost a corpus: a v4 commit establishes a baseline at
    /// generation 0 and leaves `dirty` tracked-empty; a mapped write lands v5
    /// bytes and a v5 manifest; the next ordinary commit is then a DELTA, so it
    /// rewrites one segment in v4 and publishes a v4 manifest still naming the
    /// old generation for every other segment, which now hold `KINSEG05` files.
    /// The following open decodes that magic as a bincode map length, fails,
    /// archives the manifest as corrupt, and the index is gone with the
    /// monolithic fallback already unlinked.
    ///
    /// The guards above could not see it, because they all build their heap
    /// index with `TextIndex::new()`, whose `commit` persists nothing.
    #[test]
    fn a_mapped_write_over_a_bincode_baseline_survives_the_next_commit() {
        let docs = corpus();
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = dir.path().join("index.bin");

        let index: TextIndex<Key> = TextIndex::open(Some(&storage)).expect("open");
        index.seg.write().segment_count = 4;
        for (id, doc) in docs.iter().take(20) {
            index.upsert_searchable(*id, doc).expect("upsert");
        }
        // A v4 baseline on disk, with the delta bookkeeping the next commit
        // would use.
        index.commit().expect("first commit");
        assert!(
            index.seg.read().baseline_gens.is_some(),
            "the control: the bincode commit must leave a delta baseline, or the sequence this \
             guards cannot arise"
        );

        // The mapped image over it.
        index.persist_mapped(&storage).expect("persist_mapped");

        // One more document, committed the ordinary way.
        let extra = Doc {
            name: "afterMapped".to_string(),
            signature: "fn afterMapped(input: &str) -> Result<(), Error>".to_string(),
            body: "afterMapped shared shared shared handler for afterMapped in module extra"
                .to_string(),
            kind: "Function".to_string(),
        };
        let extra_id = Key(9_999);
        index.upsert_searchable(extra_id, &extra).expect("upsert");
        index.commit().expect("second commit");

        // And it must still open, hold everything, and answer.
        let reopened: TextIndex<Key> = TextIndex::open(Some(&storage)).expect("reopen");
        assert_eq!(
            reopened.live_document_count(),
            21,
            "the reopened index lost documents, so a commit published a manifest naming files of \
             the other format"
        );
        assert!(reopened.contains(&extra_id), "the last document is missing");
        for (id, _) in docs.iter().take(20) {
            assert!(reopened.contains(id), "{id:?} is missing after the reopen");
        }
        let hits = reopened
            .fuzzy_search("shared", 100)
            .expect("reopened search");
        assert_eq!(
            hits.len(),
            21,
            "`shared` is in every body, so it must return all 21 documents"
        );
        let want = index.fuzzy_search("shared", 100).expect("live search");
        assert_identical("across a mapped write and a commit", &hits, &want);
    }

    /// A tombstone bit the manifest's own count does not admit must be refused.
    ///
    /// The count and the bits gate different decisions: the count gates the
    /// load-time reconciliation and the fast path that trusts a stored `df`,
    /// the bits gate the posting walk. A manifest with a bit set and a count of
    /// zero therefore hid a document from results while still counting it in
    /// `N`, in `avgdl` and in every term's `df` — precisely what the delete
    /// guard says it catches, reached through the one path that guard cannot
    /// see. The count is now derived from the bits, so the reconciliation runs
    /// and refuses.
    #[test]
    fn a_tombstone_bit_the_manifests_count_denies_is_refused() {
        let docs = corpus();
        let heap = heap_index(&docs);
        heap.seg.write().segment_count = 4;
        let dir = tempfile::tempdir().expect("tempdir");
        heap.persist_mapped(dir.path()).expect("persist_mapped");
        let storage = crate::storage_file_path_for(dir.path());

        // The control: intact, it opens.
        assert!(MappedIndex::<Key>::open(dir.path()).is_ok());

        let m_path = manifest_path(&storage);
        let bytes = std::fs::read(&m_path).expect("read manifest");
        let mut manifest: MappedManifest = bincode::deserialize(&bytes).expect("decode manifest");
        let segment = manifest
            .segment_gens
            .iter()
            .position(Option::is_some)
            .expect("some segment has a file");
        manifest.tombstones[segment].words[0] |= 1;
        assert_eq!(
            manifest.tombstones[segment].set_count, 0,
            "the count must be left claiming nothing was removed, or this tests something else"
        );
        std::fs::write(&m_path, bincode::serialize(&manifest).expect("encode")).expect("write");

        let error = MappedIndex::<Key>::open(dir.path())
            .expect_err("a bit the count denies must be refused");
        assert!(
            format!("{error}").contains("tombstoned"),
            "the refusal must name the reconciliation, got: {error}"
        );

        // The SAME bytes must be refused on the ordinary load path, which is
        // the one `TextIndex::open` actually calls. The hardening lived only in
        // the mapped reader for a round, so this exact image opened there with
        // one document fewer, no error, and the graph-root stamp still trusted.
        //
        // This is LAST on this image on purpose: the ordinary path archives a
        // corrupt manifest as its designed recovery, so the file is gone
        // afterwards and any further arm here would fail on a missing manifest
        // rather than on what it meant to test. The first run of this test
        // failed exactly that way.
        assert!(
            TextIndex::<Key>::open(Some(&storage)).is_err(),
            "the ordinary load path must refuse what the mapped reader refuses"
        );
        assert!(
            !m_path.exists(),
            "the ordinary path's recovery is to archive the manifest, so it must be gone"
        );

        // A bit PAST the segment's document count, on its own image. It is
        // unreachable by every read, so it removes nothing, and yet it makes
        // `any()` true and drops every `df` in that segment off the O(1) stored
        // count onto a full counted walk.
        let far = tempfile::tempdir().expect("tempdir");
        heap.persist_mapped(far.path()).expect("persist_mapped");
        let far_storage = crate::storage_file_path_for(far.path());
        let far_manifest = manifest_path(&far_storage);
        let bytes = std::fs::read(&far_manifest).expect("read manifest");
        let mut manifest: MappedManifest = bincode::deserialize(&bytes).expect("decode manifest");
        let segment = manifest
            .segment_gens
            .iter()
            .position(Option::is_some)
            .expect("some segment has a file");
        manifest.tombstones[segment] = Tombstones::for_docs(4096);
        assert!(
            manifest.tombstones[segment].set(4095),
            "the control: the bit must actually be set"
        );
        std::fs::write(
            &far_manifest,
            bincode::serialize(&manifest).expect("encode"),
        )
        .expect("write");
        let error = MappedIndex::<Key>::open(far.path())
            .expect_err("an unreachable tombstone must be refused");
        assert!(
            format!("{error}").contains("no read can reach"),
            "the refusal must name it, got: {error}"
        );

        // And through the ORDINARY load path, which is the arm that makes the
        // shared reconciliation load-bearing there.
        //
        // The tombstone-count case above is caught on that path anyway, by
        // rehydrate's own walk disagreeing with the manifest, so removing the
        // reconciliation left every assertion green: the falsification run
        // reported `rehydrate-unreconciled` as a SURVIVOR. Reachability is the
        // one thing the reconciliation uniquely adds there, because the walk
        // only ever visits ordinals below the document count and so cannot see
        // a bit above it. Last on this image, because the refusal archives the
        // manifest.
        assert!(
            TextIndex::<Key>::open(Some(&far_storage)).is_err(),
            "the ordinary load path must refuse an unreachable tombstone too"
        );
    }

    /// The reverse direction's length floor must be the predicate's own floor.
    ///
    /// The enumeration skips lengths `reverse_substring_admits` could never
    /// accept, and getting that arithmetic wrong drops candidates silently:
    /// `ceil(n*3/4)` and `ceil(n/4)*3` agree on half of all lengths and differ
    /// on the rest, so a fixture would have to hold a token at exactly one of
    /// the differing lengths for a set comparison to notice. Written after the
    /// wrong form went in and a table caught it.
    #[test]
    fn the_reverse_floor_is_the_predicates_own_floor() {
        // The enumeration itself, first. The arithmetic comparison below is a
        // check on `reverse_substring_admits`, which this round did not touch,
        // so on its own it stayed green with the floor reverted: no byte in it
        // reached `reverse_substring_candidates`. This half does.
        let docs = corpus();
        let heap = heap_index(&docs);
        heap.seg.write().segment_count = 2;
        let dir = tempfile::tempdir().expect("tempdir");
        heap.persist_mapped(dir.path()).expect("persist_mapped");
        let mapped: MappedIndex<Key> = MappedIndex::open(dir.path()).expect("open mapped");

        let mut exercised_differing = 0usize;
        for query in [
            "users",
            "userna",
            "usernames",
            "definitely",
            "renderwidget",
            "abcde",
            "abcdef",
            "abcdefghi",
            "abcdefghij",
            "abcdefghijklm",
            "abcdefghijklmn",
        ] {
            let correct = MIN_SUBSTRING_LEN.max((query.len() * 3).div_ceil(4));
            let wrong = MIN_SUBSTRING_LEN.max(query.len().div_ceil(4) * 3);
            if wrong != correct {
                exercised_differing += 1;
            }
            // Brute force over EVERY start and end pair with the predicate
            // applied. That is the set the bound must not change, so a bound
            // that skips a length the predicate accepts makes the real answer a
            // strict subset of this and the assertion fails.
            let bytes = query.as_bytes();
            let mut want: BTreeSet<Vec<u8>> = BTreeSet::new();
            for start in 0..bytes.len() {
                for end in (start + 1)..=bytes.len() {
                    let candidate = &bytes[start..end];
                    if candidate == bytes || candidate.len() < MIN_SUBSTRING_LEN {
                        continue;
                    }
                    let Ok(text) = std::str::from_utf8(candidate) else {
                        continue;
                    };
                    if reverse_substring_admits(query, text) {
                        want.insert(candidate.to_vec());
                    }
                }
            }
            assert_eq!(
                mapped.reverse_substring_candidates(query),
                want,
                "the bounded enumeration for {query:?} differs from a full start-and-end scan"
            );
            assert!(
                !want.is_empty(),
                "{query:?} produced no candidates at all, so it tests nothing"
            );
        }
        assert!(
            exercised_differing >= 4,
            "only {exercised_differing} of the queries sit at a length where the two floor forms \
             differ, so the enumeration half proves little"
        );

        let mut differing = 0usize;
        for query_len in MIN_SUBSTRING_LEN..200usize {
            let floor = MIN_SUBSTRING_LEN.max((query_len * 3).div_ceil(4));
            let wrong = MIN_SUBSTRING_LEN.max(query_len.div_ceil(4) * 3);
            if wrong != floor {
                differing += 1;
            }
            let query = "a".repeat(query_len);
            for candidate_len in MIN_SUBSTRING_LEN..=query_len {
                let candidate = "a".repeat(candidate_len);
                assert_eq!(
                    reverse_substring_admits(&query, &candidate),
                    candidate_len >= floor,
                    "query {query_len} bytes, candidate {candidate_len}: the predicate and the \
                     floor disagree"
                );
            }
        }
        // The control that the two forms are not the same expression, so the
        // assertion above is about something.
        assert!(
            differing > 50,
            "only {differing} lengths distinguish the two floor forms, so this proves little"
        );
    }

    /// A second write must not touch a file the live manifest names.
    ///
    /// The manifest is the only commit point, and that holds only while every
    /// segment it names is untouched until it is replaced. A writer that reused
    /// one generation renamed over the very file the current manifest pointed
    /// at, so a crash between that rename and the manifest's would leave the old
    /// manifest naming a mixture of old and new segments. The load-time sums
    /// would probably have caught it, which is luck rather than design.
    ///
    /// Asserted as the mechanism rather than by simulating a crash: the paths
    /// the new manifest names must be disjoint from the ones the old manifest
    /// named, and an index opened before the second write must still answer.
    #[test]
    fn a_second_write_does_not_overwrite_the_live_manifests_segments() {
        let docs = corpus();
        let heap = heap_index(&docs);
        heap.seg.write().segment_count = 4;
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = crate::storage_file_path_for(dir.path());

        heap.persist_mapped(dir.path()).expect("first persist");
        let first = read_manifest_gens(&storage);
        assert!(
            first.iter().any(|gen| gen.is_some()),
            "the first write must name at least one segment"
        );
        let first_paths: Vec<PathBuf> = first
            .iter()
            .enumerate()
            .filter_map(|(segment, gen)| gen.map(|gen| segment_path(&storage, segment, gen)))
            .collect();

        // Open BEFORE the second write, and keep it open across it.
        let before: MappedIndex<Key> = MappedIndex::open(dir.path()).expect("open first image");
        let want = before
            .fuzzy_search("shared", docs.len() * 2)
            .expect("search");
        assert_reaches_every_document("before the second write", &want, docs.len());

        heap.persist_mapped(dir.path()).expect("second persist");
        let second = read_manifest_gens(&storage);
        let second_paths: Vec<PathBuf> = second
            .iter()
            .enumerate()
            .filter_map(|(segment, gen)| gen.map(|gen| segment_path(&storage, segment, gen)))
            .collect();

        assert_eq!(
            first_paths.len(),
            second_paths.len(),
            "the same segments should be populated by both writes"
        );
        for path in &second_paths {
            assert!(
                !first_paths.contains(path),
                "the second write published {} , which the first manifest already named",
                path.display()
            );
        }
        for (segment, (old, new)) in first.iter().zip(second.iter()).enumerate() {
            if let (Some(old), Some(new)) = (old, new) {
                assert!(
                    new > old,
                    "segment {segment}: generation must advance, {old} to {new}"
                );
            }
        }

        // The handle opened before the second write still answers, which is what
        // a rename rather than an in-place rewrite buys.
        let after = before
            .fuzzy_search("shared", docs.len() * 2)
            .expect("search");
        assert_identical("across a second write", &after, &want);

        // And the new image opens and answers too.
        let reopened: MappedIndex<Key> = MappedIndex::open(dir.path()).expect("open second image");
        let got = reopened
            .fuzzy_search("shared", docs.len() * 2)
            .expect("search");
        assert_identical("the second image", &got, &want);
    }

    /// A term whose every document was removed is not a term the index holds.
    ///
    /// The heap index drops a posting list the moment it empties, so such a term
    /// is not a key it has and `min` over a multi-token term never sees it. A
    /// mapped segment keeps the key in its FST until the segment is rewritten,
    /// so counting it would drag that minimum to zero and hand the caller a
    /// term-discrimination weight for a token nothing holds. Found by reading
    /// the two implementations against each other rather than by a red test,
    /// which is why the guard exists now.
    #[test]
    fn a_term_whose_documents_are_all_removed_is_not_indexed() {
        let docs = corpus();
        let heap = heap_index(&docs);
        heap.seg.write().segment_count = 4;
        let dir = tempfile::tempdir().expect("tempdir");
        heap.persist_mapped(dir.path()).expect("persist_mapped");
        let mut mapped: MappedIndex<Key> = MappedIndex::open(dir.path()).expect("open mapped");

        // The control. `renderwidget` has to be held by exactly ONE document,
        // or removing that document does not empty the term and this test
        // measures nothing. Asserted rather than assumed.
        assert_eq!(
            mapped.doc_frequency("renderwidget"),
            1,
            "the fixture must give `renderwidget` exactly one document"
        );
        assert!(mapped.remove(&Key(1)), "Key(1) holds `renderwidget`");

        let survivors: Vec<(Key, Doc)> = corpus().into_iter().filter(|(id, _)| id.0 != 1).collect();
        let reference = heap_index(&survivors);

        for term in ["renderwidget", "renderwidget shared", "shared renderwidget"] {
            assert_eq!(
                mapped.doc_frequency(term),
                reference.doc_frequency(term),
                "doc_frequency({term:?}) after the only holder of `renderwidget` was removed"
            );
        }
        // And the value itself, so a change making both wrong the same way is
        // still caught: `shared` is in every surviving document's body.
        assert_eq!(
            mapped.doc_frequency("renderwidget shared"),
            survivors.len(),
            "the answer must be `shared`'s count, not zero"
        );

        // Search must not admit the emptied term either.
        let got = mapped
            .fuzzy_search("renderwidget", 10)
            .expect("mapped search");
        let want = reference
            .fuzzy_search("renderwidget", 10)
            .expect("heap search");
        assert!(
            got.is_empty(),
            "an emptied term must retrieve nothing, got {got:?}"
        );
        assert_identical("emptied term", &got, &want);
    }

    /// A tie is broken by the id, and the tie is real.
    ///
    /// The second half is why this test exists. A tie-break is only reachable
    /// when scores actually tie, so a guard that assumes a tie without asserting
    /// one would stay green under a mutant that changed the tie-break. This
    /// asserts the six twins score EXACTLY equally, then asserts how that tie is
    /// broken, then asserts the `truncate(limit)` cutoff follows the same order,
    /// which is where a tie-break change becomes a different answer rather than
    /// a different ordering of the same one.
    #[test]
    fn a_forced_tie_is_broken_by_the_id_and_the_tie_is_real() {
        let docs = corpus();
        let heap = heap_index(&docs);
        heap.seg.write().segment_count = 4;
        let dir = tempfile::tempdir().expect("tempdir");
        heap.persist_mapped(dir.path()).expect("persist_mapped");
        let mapped: MappedIndex<Key> = MappedIndex::open(dir.path()).expect("open mapped");

        let all = mapped.fuzzy_search("twin", docs.len()).expect("search");
        assert_eq!(
            all.len(),
            TWINS,
            "the twin documents are the only holders of `twin`, so the tie is exactly {TWINS} wide"
        );
        let first = all[0].1.to_bits();
        assert!(
            all.iter().all(|(_, score)| score.to_bits() == first),
            "the twins must score EXACTLY equally, or the tie-break below is unreachable: {all:?}"
        );

        let order: Vec<String> = all.iter().map(|(id, _)| format!("{id:?}")).collect();
        let mut ascending = order.clone();
        ascending.sort();
        assert_eq!(
            order, ascending,
            "a tie must be broken by the id's Debug representation, ascending"
        );

        for limit in 1..=TWINS {
            let got = mapped.fuzzy_search("twin", limit).expect("mapped search");
            let want = heap.fuzzy_search("twin", limit).expect("heap search");
            assert_identical(&format!("tie at limit {limit}"), &got, &want);
            assert_eq!(got.len(), limit, "limit {limit} must truncate to {limit}");
            assert_eq!(
                got.iter().map(|(id, _)| *id).collect::<Vec<Key>>(),
                all[..limit].iter().map(|(id, _)| *id).collect::<Vec<Key>>(),
                "which twins survive the truncate must follow the tie-break order"
            );
        }
    }

    /// The substring automaton must find exactly what a full scan of the term
    /// dictionary finds, in both directions, or the identity guard above would
    /// be comparing two wrong answers.
    #[test]
    fn the_substring_automaton_matches_a_full_term_scan() {
        let docs = corpus();
        let heap = heap_index(&docs);
        heap.seg.write().segment_count = 4;
        let dir = tempfile::tempdir().expect("tempdir");
        heap.persist_mapped(dir.path()).expect("persist_mapped");
        let mapped: MappedIndex<Key> = MappedIndex::open(dir.path()).expect("open mapped");

        let vocabulary: BTreeSet<String> = heap.index.read().keys().cloned().collect();
        assert!(
            vocabulary.len() > 40,
            "the vocabulary is only {} tokens, too small to compare over",
            vocabulary.len()
        );

        let mut compared = 0usize;
        for query_token in QUERIES
            .iter()
            .flat_map(|query| tokenize(query))
            .collect::<BTreeSet<String>>()
        {
            if query_token.len() < MIN_SUBSTRING_LEN {
                continue;
            }
            // The reference is the predicate the heap path applies, called
            // rather than restated, so the two cannot drift apart.
            let want: BTreeSet<Vec<u8>> = vocabulary
                .iter()
                .filter(|token| {
                    token.as_str() != query_token.as_str()
                        && token.len() >= MIN_SUBSTRING_LEN
                        && (token.contains(query_token.as_str())
                            || reverse_substring_admits(query_token.as_str(), token.as_str()))
                })
                .map(|token| token.as_bytes().to_vec())
                .collect();

            // The set under test is the one the SCORER visits: the union of
            // both directions, filtered by presence in the term dictionary,
            // exactly as `scoring_terms` filters it. The reverse direction
            // returns candidates rather than matches, because probing them here
            // would only double the lookups the caller already performs.
            let mut union = mapped.forward_substring_matches(&query_token);
            union.extend(mapped.reverse_substring_candidates(&query_token));
            let got: BTreeSet<Vec<u8>> = union
                .into_iter()
                .filter(|token| match std::str::from_utf8(token) {
                    Ok(token) => !mapped.slots_for(token).is_empty(),
                    Err(_) => false,
                })
                .collect();
            assert_eq!(
                got, want,
                "substring matches for {query_token:?} differ from a full term scan"
            );
            compared += want.len();
        }
        assert!(
            compared > 20,
            "only {compared} substring matches were compared, so this proves little"
        );
    }

    /// The run-length encoding must expand back into the SAME sequence of
    /// occurrences, not into an equivalent count.
    ///
    /// Float addition is not associative, so a run collapsed into a multiply
    /// would score differently in the low bits. This asserts the shape directly
    /// rather than through a score, so a failure names the cause.
    #[test]
    fn a_run_expands_back_into_the_occurrences_it_encoded() {
        let docs = corpus();
        let heap = heap_index(&docs);
        heap.seg.write().segment_count = 1;
        let dir = tempfile::tempdir().expect("tempdir");
        heap.persist_mapped(dir.path()).expect("persist_mapped");
        let mapped: MappedIndex<Key> = MappedIndex::open(dir.path()).expect("open mapped");

        let segment = mapped.segments[0]
            .as_ref()
            .expect("a single-segment image has segment 0");
        let (table, _) = segment.weight_table().expect("weight table");

        let heap_index_guard = heap.index.read();
        let mut checked_runs = 0usize;
        for (token, postings) in heap_index_guard.iter() {
            let offset = segment
                .terms
                .get(token.as_bytes())
                .unwrap_or_else(|| panic!("the mapped term dictionary is missing {token:?}"));
            let (mut cursor, occurrences) = segment.cursor_at(offset).expect("cursor");
            let mut seen: HashMap<Key, Vec<f32>> = HashMap::new();
            let mut weights: Vec<f32> = Vec::new();
            let mut total = 0usize;
            while let Some((ordinal, _)) = cursor.next(&table, &mut weights).expect("posting") {
                let encoded = segment.encoded_id(ordinal).expect("id");
                let id: Key = bincode::deserialize(encoded).expect("decode id");
                total += weights.len();
                if weights.len() > 1 {
                    checked_runs += 1;
                }
                seen.insert(id, weights.clone());
            }
            assert_eq!(
                total, occurrences as usize,
                "the stored occurrence count for {token:?} disagrees with the walk"
            );
            for (id, want) in &postings.by_doc {
                let got = seen
                    .get(id)
                    .unwrap_or_else(|| panic!("{token:?} lost {id:?} in the mapped image"));
                assert_eq!(
                    got.iter().map(|w| w.to_bits()).collect::<Vec<u32>>(),
                    want.iter().map(|w| w.to_bits()).collect::<Vec<u32>>(),
                    "{token:?} for {id:?} came back as a different occurrence sequence"
                );
            }
            assert_eq!(
                seen.len(),
                postings.by_doc.len(),
                "{token:?} gained or lost documents in the mapped image"
            );
        }
        assert!(
            checked_runs > 20,
            "only {checked_runs} postings carried more than one occurrence, so the run encoding \
             was barely exercised"
        );
    }

    /// The varint encoding has to survive its own boundaries, which is where an
    /// off-by-one in a hand-rolled LEB128 lives.
    #[test]
    fn varints_round_trip_across_their_boundaries() {
        let mut values: Vec<u64> = vec![0, 1, 2, 126, 127, 128, 129, u64::MAX];
        for shift in 0..64u32 {
            let base = 1u64 << shift;
            values.push(base);
            values.push(base.wrapping_sub(1));
            values.push(base.wrapping_add(1));
        }
        for value in values {
            let mut buf = Vec::new();
            put_uvarint(&mut buf, value);
            let mut pos = 0usize;
            assert_eq!(
                get_uvarint(&buf, &mut pos),
                Some(value),
                "{value} did not round trip"
            );
            assert_eq!(
                pos,
                buf.len(),
                "{value} left {} bytes unread",
                buf.len() - pos
            );
            // A non-canonical encoding of the SAME value must be refused, or
            // two byte strings map to one and a corruption signal is thrown
            // away. Setting the continuation bit on the last byte and appending
            // a zero is the general over-long form.
            let mut over_long = buf.clone();
            let last = over_long.len() - 1;
            over_long[last] |= 0x80;
            over_long.push(0x00);
            let mut pos = 0usize;
            assert_eq!(
                get_uvarint(&over_long, &mut pos),
                None,
                "the over-long encoding of {value} decoded anyway"
            );
            // Truncation must report itself rather than return a short value.
            if buf.len() > 1 {
                let mut pos = 0usize;
                assert_eq!(
                    get_uvarint(&buf[..buf.len() - 1], &mut pos),
                    None,
                    "a truncated encoding of {value} decoded anyway"
                );
            }
        }
    }

    /// A segment file that is not one must be refused by identity, and a torn
    /// one must be refused rather than served.
    #[test]
    fn a_torn_or_foreign_segment_is_refused() {
        let docs = corpus();
        let heap = heap_index(&docs);
        heap.seg.write().segment_count = 1;

        let dir = tempfile::tempdir().expect("tempdir");
        heap.persist_mapped(dir.path()).expect("persist_mapped");
        let storage = crate::storage_file_path_for(dir.path());
        let seg_file = segment_path(&storage, 0, 0);

        // The control: intact, it opens.
        assert!(MappedIndex::<Key>::open(dir.path()).is_ok());

        let intact = std::fs::read(&seg_file).expect("read segment");

        let mut wrong_magic = intact.clone();
        wrong_magic[0..8].copy_from_slice(b"NOTASEG!");
        std::fs::write(&seg_file, &wrong_magic).expect("write");
        let error = MappedIndex::<Key>::open(dir.path()).expect_err("bad magic must be refused");
        assert!(
            format!("{error}").contains("bad magic"),
            "the refusal must name the reason, got: {error}"
        );

        std::fs::write(&seg_file, &intact[..intact.len() / 2]).expect("write");
        assert!(
            MappedIndex::<Key>::open(dir.path()).is_err(),
            "a truncated segment must be refused"
        );

        std::fs::write(&seg_file, &intact[..HEADER_LEN - 1]).expect("write");
        let error =
            MappedIndex::<Key>::open(dir.path()).expect_err("a torn header must be refused");
        assert!(
            format!("{error}").contains("truncated header"),
            "the refusal must name the reason, got: {error}"
        );

        // Section offsets, so the arms below poke the right bytes rather than
        // guessing at them.
        let terms_off = read_u64(&intact, 40).expect("terms offset") as usize;
        let terms_len = read_u64(&intact, 48).expect("terms length") as usize;
        let post_off = read_u64(&intact, 56).expect("postings offset") as usize;
        let docs_off = read_u64(&intact, 72).expect("docs offset") as usize;
        assert!(
            terms_len > 64,
            "the term dictionary must be big enough to corrupt in the middle"
        );

        // A byte flipped in the MIDDLE of the term dictionary, with the tail
        // left intact so fst's own cheap length-and-root check still passes.
        // Only the checksum catches this, and without it a traversal panics on
        // an out-of-bounds node, fails to terminate on a cycle, or quietly
        // yields a wrong term set and wrong postings offsets.
        let mut bad_fst = intact.clone();
        bad_fst[terms_off + terms_len / 2] ^= 0xff;
        std::fs::write(&seg_file, &bad_fst).expect("write");
        let error = MappedIndex::<Key>::open(dir.path())
            .expect_err("a corrupt term dictionary must be refused");
        assert!(
            format!("{error}").contains("checksum"),
            "the refusal must name the checksum, got: {error}"
        );

        // One document-id offset shifted back. `bincode` ignores trailing
        // bytes, so an over-long slice decodes fine and one document's score
        // comes back under ANOTHER live document's id, with the same id twice in
        // one result list. Nothing but validating the table catches it.
        let mut bad_docs = intact.clone();
        let at = docs_off + 8 + 4 * 3;
        let shifted = read_u32(&intact, at).expect("id offset").saturating_sub(4);
        bad_docs[at..at + 4].copy_from_slice(&shifted.to_le_bytes());
        std::fs::write(&seg_file, &bad_docs).expect("write");
        let error = MappedIndex::<Key>::open(dir.path())
            .expect_err("a shifted document-id offset must be refused");
        let message = format!("{error}");
        assert!(
            message.contains("gap or an overlap")
                || message.contains("inconsistent id length")
                || message.contains("does not sort after"),
            "the refusal must name the table, got: {message}"
        );

        // The document table, poked one field at a time. Every check in
        // `validate_document_table` gets an arm, because the first version of
        // that pass had a contiguity check that read the same slot twice and was
        // therefore an identity for every ordinal above zero.
        let doc_count = read_u64(&intact, 16).expect("doc count") as usize;
        assert!(
            doc_count > 4,
            "the fixture segment must hold enough documents to poke the middle of the table"
        );
        let offsets_at = docs_off + 8;
        let lengths_at = docs_off + 8 + 4 * (doc_count + 1);

        for (label, at, value, expect) in [
            (
                "offsets going backwards",
                offsets_at + 4 * 3,
                read_u32(&intact, offsets_at + 4 * 2).expect("offset") - 1,
                "goes backwards",
            ),
            (
                "the first offset not zero",
                offsets_at,
                4u32,
                "starts at 4, not 0",
            ),
            (
                "a terminal offset short of the blob",
                offsets_at + 4 * doc_count,
                read_u32(&intact, offsets_at + 4 * doc_count).expect("offset") - 4,
                "and the blob is",
            ),
            (
                "a zero-length id",
                offsets_at + 4 * 3,
                read_u32(&intact, offsets_at + 4 * 2).expect("offset"),
                "zero-length id",
            ),
            (
                "a document length the header's total denies",
                lengths_at,
                read_u32(&intact, lengths_at).expect("length") + 7,
                "the document lengths sum to",
            ),
        ] {
            let mut torn = intact.clone();
            torn[at..at + 4].copy_from_slice(&value.to_le_bytes());
            std::fs::write(&seg_file, &torn).expect("write");
            let error = MappedIndex::<Key>::open(dir.path()).expect_err(label);
            assert!(
                format!("{error}").contains(expect),
                "{label}: the refusal must name it, got: {error}"
            );
        }

        // A weight count of 2^63 at the head of the postings section. The
        // postings are not validated at open, deliberately, so this is refused
        // at QUERY time: without the bound the reservation runs before the
        // per-entry read that would have caught it, and the query dies of a
        // capacity overflow instead of returning an error.
        let mut bad_weights = intact.clone();
        bad_weights[post_off..post_off + 10]
            .copy_from_slice(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01]);
        std::fs::write(&seg_file, &bad_weights).expect("write");
        let mapped: MappedIndex<Key> =
            MappedIndex::open(dir.path()).expect("the header and tables are still intact");
        let error = mapped
            .fuzzy_search("shared", 10)
            .expect_err("an impossible weight count must be refused");
        assert!(
            format!("{error}").contains("weight table"),
            "the refusal must name the weight table, got: {error}"
        );
        drop(mapped);

        // And the control again, so none of the above passed because the
        // fixture was broken from the start.
        std::fs::write(&seg_file, &intact).expect("write");
        let mapped: MappedIndex<Key> =
            MappedIndex::open(dir.path()).expect("the intact bytes must open");
        assert_reaches_every_document(
            "restored",
            &mapped
                .fuzzy_search("shared", docs.len() * 2)
                .expect("restored search"),
            docs.len(),
        );
    }
}
