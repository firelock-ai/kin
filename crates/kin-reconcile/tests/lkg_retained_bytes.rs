// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What the reconciler's last-known-good store keeps, counted rather than
//! asserted.
//!
//! A serving daemon seeds one LKG entry per entity in the repository at open and
//! holds the store for its life. On this machine's `torvalds__linux` store that
//! is 264,615 entries, and while the entry held a whole owned `Entity` it was a
//! second complete copy of every entity's name, signature, doc summary and file
//! path, none of which any reader ever looked at. The entry now holds the
//! fingerprint that `LkgStore::has_changed` compares, so what it keeps must not
//! move when the strings on the entities it was seeded from get longer.
//!
//! This is its own test binary on purpose. The counter below is process global,
//! so a second test running beside it would be measured into it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use kin_model::{
    Entity, EntityId, EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm,
    Hash256, LanguageId, SemanticFingerprint, SourceSpan, Visibility,
};
use kin_reconcile::lkg::LkgStore;

static LIVE: AtomicUsize = AtomicUsize::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let out = System.realloc(ptr, layout, new_size);
        if !out.is_null() {
            LIVE.fetch_add(new_size, Ordering::Relaxed);
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        out
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

const ENTITIES: usize = 256;

/// One entity carrying strings of a stated size, so the arms below differ in
/// exactly one thing.
fn entity(index: usize, doc_bytes: usize) -> Entity {
    let path = format!("src/vs/workbench/services/generated/module_{index:05}.ts");
    Entity {
        id: EntityId::new(),
        kind: EntityKind::Function,
        name: format!("resolveConfigurationForWorkspaceFolder_{index:05}"),
        language: LanguageId::TypeScript,
        fingerprint: SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([index as u8; 32]),
            signature_hash: Hash256::from_bytes([(index >> 8) as u8; 32]),
            behavior_hash: Hash256::from_bytes([0xcc; 32]),
            equivalence_hash: Hash256::from_bytes([0; 32]),
            stability_score: 0.95,
        },
        file_origin: Some(FilePathId::new(&path)),
        span: Some(SourceSpan {
            file: FilePathId::new(&path),
            start_byte: 0,
            end_byte: 128,
            start_line: 1,
            start_col: 0,
            end_line: 9,
            end_col: 1,
        }),
        signature: format!("export function resolveConfigurationForWorkspaceFolder_{index:05}(folder: IWorkspaceFolder, section: string): IConfigurationValue"),
        visibility: Visibility::Public,
        role: EntityRole::Source,
        doc_summary: Some("d".repeat(doc_bytes)),
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

/// Seed a store from entities carrying `doc_bytes` of doc summary and return
/// the bytes the store still holds once the entities it was seeded from are
/// gone, which is the daemon's own shape: `list_all_entities` hands over an
/// owned vector, the seed walks it, and the vector is dropped.
fn retained_for(doc_bytes: usize) -> usize {
    let entities: Vec<Entity> = (0..ENTITIES).map(|i| entity(i, doc_bytes)).collect();

    let before = live();
    let mut store = LkgStore::new();
    for e in &entities {
        store.record(e);
    }
    let after = live();

    assert_eq!(
        store.len(),
        ENTITIES,
        "the store must hold every entity, or the byte count above is about nothing"
    );

    drop(entities);
    drop(store);

    after.saturating_sub(before)
}

#[test]
fn the_lkg_retains_nothing_that_scales_with_an_entity_s_strings() {
    // Positive control on the instrument itself. A counter that never moves
    // makes every assertion below pass for the wrong reason.
    let control_before = live();
    let ballast = vec![0u8; 4 << 20];
    let control_after = live();
    assert!(
        control_after - control_before >= ballast.len(),
        "the counting allocator did not observe a {} byte allocation, so it \
         cannot observe the store either",
        ballast.len()
    );
    drop(ballast);

    let small_doc = 64usize;
    let large_doc = 8192usize;

    let small = retained_for(small_doc);
    let large = retained_for(large_doc);

    // The doc summaries alone differ by two megabytes between the arms. An
    // entry that reaches the entity carries that difference; one that holds a
    // fingerprint does not.
    let string_difference = ENTITIES * (large_doc - small_doc);
    let tolerance = ENTITIES * 64;
    assert!(
        large.abs_diff(small) < tolerance,
        "what the store retains moved by {} bytes when the entities' doc \
         summaries grew by {} bytes; an entry must not reach the entity it was \
         recorded from (small arm {} bytes, large arm {} bytes)",
        large.abs_diff(small),
        string_difference,
        small,
        large
    );

    // And an absolute ceiling, so an entry that shrank but still copies cannot
    // pass on the scale-free test alone. A fingerprint is 132 bytes and a map
    // entry adds an id and a control byte, so 512 per entity is roughly three
    // times the true cost and well under the 4,288 bytes of string an entity
    // carries in the large arm.
    let ceiling = ENTITIES * 512;
    assert!(
        large < ceiling,
        "the store retains {} bytes for {} entities, over the {} byte ceiling",
        large,
        ENTITIES,
        ceiling
    );
}
