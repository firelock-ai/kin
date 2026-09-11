// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What the mapped reader retains, per document, at rest.
//!
//! The heap index holds a `String` per distinct token, a posting list keyed by
//! document id, a forward map naming every token occurrence, a vocabulary and a
//! trigram index. Measured on a full VS Code tree that was 3.30 GiB after the
//! forward index moved to vocabulary ids, and 5.54 GiB before it (FIR-3064).
//! None of it is memory the answer needs; it is memory a file could hold.
//!
//! The mapped reader holds the mapping handles, the section bounds it read out
//! of each header, one bit per document, and three counters. The term
//! dictionary, the postings and the document table are pages. So the number this
//! guards is per DOCUMENT and it is small: the resident cost no longer scales
//! with occurrences at all.
//!
//! Live heap rather than resident set, for the reason the sibling guards give:
//! resident set keeps counting memory the allocator has freed and not returned,
//! so it moves with the platform, while live heap moves when and only when the
//! code holds differently.
//!
//! The fixture is large enough that the per-segment fixed cost is not the
//! answer. Sixty-four segments cost the same whether the corpus is a hundred
//! documents or a million, so a small corpus would measure the segment count and
//! call it a per-document cost.
//!
//! This file is its own test binary and holds one test on purpose. The counters
//! below are process-global, so a second test running beside this one would be
//! measured into it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use kin_search::{MappedIndex, Searchable, TextIndex};

// --- the instrument -------------------------------------------------------

static LIVE: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, layout) }
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(p, layout, new_size) };
        if !moved.is_null() {
            if new_size >= layout.size() {
                LIVE.fetch_add(new_size - layout.size(), Ordering::Relaxed);
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

// --- the fixture ----------------------------------------------------------

/// Documents in the corpus. Large enough that the fixed per-segment cost of the
/// default sixty-four segments is a small share of the total, so the number
/// below is about the per-document term and not about the segment count.
const DOCUMENTS: usize = 8_000;

/// Bytes the mapped reader may retain per document, at rest.
///
/// Pre-registered from the layout before it was measured. What is resident is
/// one mapping handle, one `fst::Map` over a refcounted sub-slice, and two
/// section bounds per segment, plus one bit per document and three counters.
/// At sixty-four segments that projects to roughly 13 KB regardless of corpus
/// size, so about 1.7 bytes per document here.
///
/// The control below proves the ceiling can fail: the heap index holding the
/// same corpus is measured first, on its own, and a ceiling this far under it is
/// one the heap shape misses by two orders of magnitude.
const BYTES_PER_DOCUMENT: usize = 8;

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

fn corpus() -> Vec<Doc> {
    (0..DOCUMENTS)
        .map(|index| {
            let name = format!("renderWidget{index}");
            Doc {
                // The body repeats a shared word so a posting carries a run
                // longer than one occurrence, and repeats the name so the same
                // token lands in several weighted fields of one document.
                body: format!(
                    "{name} {name} shared shared shared handler builder for module {index}"
                ),
                signature: format!("fn {name}(input: &str) -> Result<(), Error>"),
                kind: if index % 2 == 0 { "Function" } else { "Method" }.to_string(),
                name,
            }
        })
        .collect()
}

// --- the guard ------------------------------------------------------------

/// The mapped reader must not hold the index it serves.
#[test]
fn the_mapped_reader_retains_almost_nothing_per_document() {
    let docs = corpus();
    let dir = tempfile::tempdir().expect("tempdir");
    let storage = dir.path().to_path_buf();

    // The positive control on the ceiling, taken first and on its own: what the
    // heap index holds for exactly this corpus. Without it the ceiling could be
    // any number and the assertion would prove nothing about what changed.
    let control_floor = live();
    let heap: TextIndex<u64> = TextIndex::new();
    for (id, doc) in docs.iter().enumerate() {
        heap.upsert_searchable(id as u64, doc).expect("upsert");
    }
    heap.commit().expect("commit");
    let heap_held = live().saturating_sub(control_floor);
    let heap_per_document = heap_held as f64 / DOCUMENTS as f64;
    let heap_hits = heap.fuzzy_search("shared", 10).expect("heap search");
    assert!(
        !heap_hits.is_empty(),
        "the heap index must answer, or the control above is about nothing"
    );

    heap.persist_mapped(&storage).expect("persist_mapped");
    drop(heap);
    drop(docs);

    let floor = live();
    let mapped: MappedIndex<u64> = MappedIndex::open(&storage).expect("open mapped");
    let mapped_held = live().saturating_sub(floor);
    let mapped_per_document = mapped_held as f64 / DOCUMENTS as f64;

    // It answers, or this measured a structure that was never built.
    assert_eq!(
        mapped.live_document_count(),
        DOCUMENTS,
        "the mapped index lost documents"
    );
    let hits = mapped.fuzzy_search("shared", 10).expect("mapped search");
    assert!(
        !hits.is_empty(),
        "the mapped index must be searchable, or the number above is about nothing"
    );
    assert!(
        mapped.contains(&0) && mapped.contains(&(DOCUMENTS as u64 - 1)),
        "the mapped index must find its own first and last document"
    );

    println!(
        "{DOCUMENTS} documents\n\
         heap index holds   {heap_held} bytes, {heap_per_document:.1} per document\n\
         mapped reader holds {mapped_held} bytes, {mapped_per_document:.2} per document\n\
         ratio {:.0}x",
        heap_per_document / mapped_per_document.max(f64::MIN_POSITIVE)
    );

    assert!(
        heap_per_document > BYTES_PER_DOCUMENT as f64,
        "the ceiling of {BYTES_PER_DOCUMENT} must sit below what the heap index costs \
         ({heap_per_document:.1}), or it is a ceiling nothing could fail"
    );
    assert!(
        mapped_per_document <= BYTES_PER_DOCUMENT as f64,
        "the mapped reader holds {mapped_per_document:.2} bytes per document, at or over the \
         {BYTES_PER_DOCUMENT}-byte ceiling, so it is holding part of the index rather than \
         serving it from the mapping"
    );
}
