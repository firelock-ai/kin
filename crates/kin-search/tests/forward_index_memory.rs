// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What the forward index costs per token occurrence.
//!
//! The forward map exists for deletion and update support: to remove a document
//! from the inverted index you have to know which tokens it contributed. It
//! used to answer that with an owned `String` per token OCCURRENCE.
//!
//! Measured on the persisted index of a full VS Code tree, that is 79,217,768
//! occurrences of 2,535,522 distinct tokens, 31.2 copies of each, and
//! 1,160,975,877 bytes of a 2,679,660,206-byte index. In memory a
//! `(String, f32)` costs about 48 bytes, a 24-byte `String` header plus a heap
//! allocation rounded to about 16 for a seven-byte token plus 8 for the weight
//! and padding, against the 8 an inline `(u32, f32)` costs. So the projection
//! this guards is about 3.17 GB removed from a 5.95 GB index (FIR-3064).
//!
//! Live heap rather than resident set, for the reason kin-db's sibling guards
//! give: resident set keeps counting memory the allocator has freed and not
//! returned, so it moves with the platform, while live heap moves when and only
//! when the code holds differently.
//!
//! The fixture is shaped so the FORWARD index is what the number is about. Its
//! documents repeat a small vocabulary many times each, so the inverted index
//! holds few entries while the occurrence count is large, and a per-occurrence
//! cost is dominated by the map under test.
//!
//! This file is its own test binary and holds one test on purpose. The counters
//! below are process-global, so a second test running beside this one would be
//! measured into it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use kin_search::{Searchable, TextIndex};

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

/// Documents in the corpus.
const DOCUMENTS: usize = 2_000;

/// Distinct tokens each document draws from. Small on purpose: the inverted
/// index holds one entry per distinct token, so a narrow vocabulary keeps it
/// out of the number while the occurrence count stays large.
const VOCABULARY: usize = 8;

/// Times each document repeats each of its tokens.
const REPEATS: usize = 25;

/// Token occurrences the corpus produces, which is what the forward index
/// stores one entry per.
const OCCURRENCES: usize = DOCUMENTS * VOCABULARY * REPEATS;

/// Bytes per token occurrence the whole index may hold.
///
/// Set from measurement, not from taste, and the control below proves it can
/// fail: an owned `(String, f32)` per occurrence costs about 48 bytes on its
/// own, before the index holds anything else, so a ceiling under that is a
/// ceiling the previous shape could not have met.
const BYTES_PER_OCCURRENCE: usize = 32;

struct Doc {
    body: String,
}

impl Searchable for Doc {
    fn search_fields(&self) -> Vec<(&str, f32)> {
        vec![(&self.body, 1.0)]
    }
}

fn corpus() -> Vec<Doc> {
    (0..DOCUMENTS)
        .map(|document| {
            let mut body = String::new();
            for token in 0..VOCABULARY {
                for _ in 0..REPEATS {
                    body.push_str(&format!("tok{token} "));
                }
            }
            // One unique token per document, so the documents are not identical
            // and the inverted index is not degenerate.
            body.push_str(&format!("only{document}"));
            Doc { body }
        })
        .collect()
}

// --- the guard ------------------------------------------------------------

/// The index must not hold an owned copy of every token occurrence.
#[test]
fn the_forward_index_does_not_hold_a_string_per_token_occurrence() {
    let docs = corpus();

    let floor = live();
    let index: TextIndex<u64> = TextIndex::new();
    for (id, doc) in docs.iter().enumerate() {
        index.upsert_searchable(id as u64, doc).expect("upsert");
    }
    index.commit().expect("commit");
    let held = live().saturating_sub(floor);

    // The index answers queries, or this measured a structure that was never
    // built.
    let hits = index.fuzzy_search("tok3", 10).expect("search");
    assert!(
        !hits.is_empty(),
        "the fixture must be searchable, or the number above is about nothing"
    );

    let per_occurrence = held as f64 / OCCURRENCES as f64;
    println!(
        "{DOCUMENTS} documents, {OCCURRENCES} token occurrences\n\
         index holds {held} bytes, {per_occurrence:.1} per occurrence"
    );

    // The positive control on the ceiling. An owned `(String, f32)` per
    // occurrence costs this much on its own, with no index around it, so a
    // ceiling below it is one the previous shape could not have met. Without
    // this the ceiling could be any number and the assertion would prove
    // nothing about what changed.
    let control_floor = live();
    let owned: Vec<(String, f32)> = (0..OCCURRENCES)
        .map(|i| (format!("tok{}", i % VOCABULARY), 1.0))
        .collect();
    let owned_bytes = live().saturating_sub(control_floor);
    let owned_per_occurrence = owned_bytes as f64 / OCCURRENCES as f64;
    assert_eq!(owned.len(), OCCURRENCES);
    drop(owned);
    println!(
        "an owned (String, f32) per occurrence costs {owned_bytes} bytes, \
         {owned_per_occurrence:.1} per occurrence, on its own"
    );
    assert!(
        owned_per_occurrence > BYTES_PER_OCCURRENCE as f64,
        "the ceiling of {BYTES_PER_OCCURRENCE} must sit below what the previous shape cost \
         ({owned_per_occurrence:.1}), or it is a ceiling nothing could fail"
    );

    assert!(
        per_occurrence <= BYTES_PER_OCCURRENCE as f64,
        "the index holds {per_occurrence:.1} bytes per token occurrence, at or over the \
         {BYTES_PER_OCCURRENCE}-byte ceiling, so it is holding more than an id per occurrence"
    );
}
