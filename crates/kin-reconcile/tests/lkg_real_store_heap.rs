// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What the last-known-good store costs on a REAL repository, measured as live
//! heap in this process rather than as a resident set read through the kernel.
//!
//! Resident set could not answer this. The four reads a daemon arm takes inside
//! twelve seconds of its serving line land on the open's transient, which moves
//! by 2.6 GiB, and the effect being measured is 0.19 to 0.23 GiB. That is a
//! property of the instrument rather than of any particular machine: the
//! endpoint is published while the open's peak is still draining, so the reads
//! sit on a curve. A counting allocator inside one process cannot be reached by
//! the kernel's reclaim, and both shapes are measured over the identical entity
//! set in the same run, so there is no cross-binary comparison at all.
//!
//! Ignored by default: it needs a real store, named by three environment
//! variables, and it holds two maps over every entity in that store at once.
//!
//! ```text
//! KIN_LKG_STORE=<repo>/.kin/kindb \
//! KIN_LKG_REPO=<repository uuid> \
//! KIN_LKG_WORKSPACE=<workspace uuid> \
//!   cargo test -p kin-reconcile --release --test lkg_real_store_heap -- --ignored --nocapture
//! ```
//!
//! Its own test binary, because the counter below is process global.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::{Entity, EntityId, Relation, RepositoryId, WorkspaceId};
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

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = System.realloc(ptr, layout, new_size);
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
static ALLOCATOR: Counting = Counting;

fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// The entry as it was before this change, reproduced verbatim from the diff so
/// both shapes can be priced in one process over one entity set.
#[allow(dead_code)]
struct BeforeEntry {
    entity: Entity,
    relations: Vec<Relation>,
}

/// The bytes an entity's own strings occupy, which is what the before entry
/// reaches and the after entry does not. Measured independently so the heap half
/// of the prediction is checkable against something other than itself.
fn string_census(entities: &[Entity]) -> usize {
    entities
        .iter()
        .map(|e| {
            e.name.len()
                + e.signature.len()
                + e.file_origin.as_ref().map_or(0, |f| f.0.len())
                + e.span.as_ref().map_or(0, |s| s.file.0.len())
                + e.doc_summary.as_ref().map_or(0, |d| d.len())
        })
        .sum()
}

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

#[test]
#[ignore = "needs KIN_LKG_STORE, KIN_LKG_REPO and KIN_LKG_WORKSPACE naming a real store"]
fn the_lkg_costs_on_a_real_store_what_the_registration_says() {
    let store =
        std::env::var("KIN_LKG_STORE").expect("set KIN_LKG_STORE to a .kin/kindb directory");
    let repo = std::env::var("KIN_LKG_REPO").expect("set KIN_LKG_REPO to the repository uuid");
    let workspace =
        std::env::var("KIN_LKG_WORKSPACE").expect("set KIN_LKG_WORKSPACE to the workspace uuid");

    // Positive control on the instrument. A counter that never moves makes every
    // number below true for the wrong reason.
    let control_floor = live();
    let ballast = vec![0u8; 64 << 20];
    assert!(
        live() - control_floor >= ballast.len(),
        "the counting allocator did not observe a {} byte allocation",
        ballast.len()
    );
    drop(ballast);

    let repository_id = RepositoryId::new(repo.as_str()).expect("repository id");
    let workspace_id: WorkspaceId =
        serde_json::from_str(&format!("\"{workspace}\"")).expect("workspace uuid");

    let entities: Vec<Entity> = {
        let backend = Arc::new(LocalFileBackend::new(&store));
        let manager = RepositoryAuthorityManager::open(repository_id.clone(), backend)
            .expect("the store opens");
        let snapshot = manager
            .workspace_graph_snapshot(&repository_id, &workspace_id)
            .expect("the workspace materializes")
            .expect("the authority carries this workspace");
        snapshot.entities.values().cloned().collect()
        // snapshot, lease and manager all drop here, so what follows is measured
        // against the entities alone rather than against the store beside them.
    };

    let count = entities.len();
    assert!(
        count > 100_000,
        "this is meant to run on a real repository, got {count} entities"
    );
    let census = string_census(&entities);

    // The before shape.
    let floor = live();
    let before: HashMap<EntityId, BeforeEntry> = entities
        .iter()
        .map(|e| {
            (
                e.id,
                BeforeEntry {
                    entity: e.clone(),
                    relations: Vec::new(),
                },
            )
        })
        .collect();
    let before_bytes = live().saturating_sub(floor);
    assert_eq!(before.len(), count, "the before map must hold every entity");
    drop(before);

    // The after shape, through the real store and the real record path.
    let floor = live();
    let mut after = LkgStore::new();
    for e in &entities {
        after.record(e);
    }
    let after_bytes = live().saturating_sub(floor);
    assert_eq!(after.len(), count, "the after store must hold every entity");
    drop(after);

    let delta = before_bytes.saturating_sub(after_bytes);
    println!(
        "\n\
         store            {store}\n\
         entities         {count}\n\
         string census    {census} bytes, {:.1} MiB, {:.1} B per entity\n\
         before retained  {before_bytes} bytes, {:.1} MiB, {:.1} B per entity\n\
         after retained   {after_bytes} bytes, {:.1} MiB, {:.1} B per entity\n\
         SAVING           {delta} bytes, {:.1} MiB, {:.1} B per entity\n",
        mib(census),
        census as f64 / count as f64,
        mib(before_bytes),
        before_bytes as f64 / count as f64,
        mib(after_bytes),
        after_bytes as f64 / count as f64,
        mib(delta),
        delta as f64 / count as f64,
    );

    // Registered refutations, in the order section 7e states them.
    let structural_floor = 316 * count;
    assert!(
        delta >= structural_floor,
        "the saving is {delta} bytes, under the {structural_floor} byte structural floor of 316 \
         per entity; the entry did not shrink the way the diff says, or something else still \
         holds the entities"
    );
    assert!(
        after_bytes / count < 512,
        "the after store retains {} bytes per entity, over the 512 byte ceiling; the entry is \
         still reaching the entity it was recorded from",
        after_bytes / count
    );
    assert!(
        delta >= census,
        "the saving {delta} is under the {census} bytes of entity strings the before entry \
         reaches; the heap half of the mechanism is not what this lane has claimed"
    );
}
