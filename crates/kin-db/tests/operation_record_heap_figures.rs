// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What one persisted operation record costs in memory, on a real store.
//!
//! Two numbers the region walk could not produce, because a walk reads bytes at
//! rest and this asks what those bytes weigh once decoded and once hashed.
//!
//! **The receipts figure.** FIR-3064's retrim stopped a rewrite carrying every
//! inherited fat receipt forward, worth a MEASURED 411,771,106 bytes on the
//! wire on a converted Linux subtree. The wire number is exact; what a serving
//! process actually stops holding is the DECODED size of that record, and a
//! decoded delta payload is larger than its encoding because a Rust enum is
//! sized by its largest variant and strings cost more decoded than
//! length-prefixed. Registered before this harness existed: **700 to 850 MB**.
//!
//! **The identity figure.** `RepositoryOperationRecord::identity_hash` calls
//! `canonicalized()`, which CLONES the whole record in order to sort three of
//! its collections, and then serializes the copy;
//! `identity_payload()` allocates nothing, because it is a borrowed view. So a
//! single identity on that record costs a clone of it plus a canonical
//! serialization of it. Registered before this harness existed: **1.3 to
//! 1.9 GB** of transient live heap for ONE call.
//!
//! **Why this is not measured as process peak**, which is the trap this file
//! exists to avoid. Peak resident is a maximum over a whole run, so on a
//! harness whose first fold is cold the clone sets the maximum whatever any
//! memo does downstream, and a peak reading would show no movement while the
//! mechanism was exactly right. Live heap around a single call is the
//! instrument that can actually answer the question, which is why this is an
//! allocator and not a resident-set reading.
//!
//! Ignored by default and driven by `MEMHISTORY_STORE`, because it needs a real
//! converted store and a builder slot. Run:
//!
//! ```text
//! MEMHISTORY_STORE=<.kin/kindb dir> cargo test -p kin-db --release \
//!   --test operation_record_heap_figures -- --ignored --nocapture
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::RepositoryId;

// --- the instrument, the same shape `authority_open_memory` uses ----------

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct CountingAllocator;

fn record_allocation(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            if new_size >= layout.size() {
                record_allocation(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn live_bytes() -> usize {
    LIVE.load(Ordering::Relaxed)
}

fn arm_peak() -> usize {
    let floor = LIVE.load(Ordering::Relaxed);
    PEAK.store(floor, Ordering::Relaxed);
    floor
}

fn peak_growth_since(floor: usize) -> usize {
    PEAK.load(Ordering::Relaxed).saturating_sub(floor)
}

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

// --- the measurement ------------------------------------------------------

#[test]
#[ignore = "needs a real converted store named by MEMHISTORY_STORE, and a builder slot"]
fn one_operation_record_costs_this_much_decoded_and_this_much_to_identify() {
    let Ok(root) = std::env::var("MEMHISTORY_STORE") else {
        panic!("set MEMHISTORY_STORE to the .kin/kindb directory of a converted store");
    };
    let repo_id = std::fs::read_dir(&root)
        .expect("the store directory reads")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.join("snapshots").is_dir())
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .expect("a repository namespace carrying a snapshots directory");
    println!("STORE {root}");
    println!("REPO  {repo_id}");

    let repository = RepositoryId::new(&repo_id).expect("the namespace is a repository id");
    let backend = Arc::new(LocalFileBackend::new(&root));
    let manager = RepositoryAuthorityManager::open(repository, backend).expect("the store opens");
    let lease = manager.read_authority();
    let envelope = lease.metadata();

    println!("OPERATION_LOG {}", envelope.operation_log.len());
    println!("RECEIPTS {}", envelope.receipts.len());
    let operation = envelope
        .operation_log
        .first()
        .expect("a converted store carries at least one operation");

    // Figure zero, and it decides what a separate change is worth: does a REAL
    // record take the borrowing path?
    //
    // kin-model's clone-free identity makes `canonicalized()` borrow instead of
    // cloning when `ref_mutations` and `tree_deltas` are already in canonical
    // order. The semantic delta is always already ordered, because
    // `validate` enforces exactly the order `sort_canonical` imposes, so those
    // two small collections are the whole question. It is asked HERE because
    // the only fixture kin-model's own tests have is deliberately
    // non-canonical (`canonicalizable_transaction` says so in its source) and
    // therefore cannot answer it. A guess would have been worse than a gap.
    let refs_sorted = operation
        .ref_mutations
        .windows(2)
        .all(|pair| pair[0].name <= pair[1].name);
    let tree_deltas = operation
        .workspace_mutation
        .as_ref()
        .map_or(0, |workspace| workspace.tree_deltas.len());
    let tree_sorted = operation
        .workspace_mutation
        .as_ref()
        .is_none_or(|workspace| {
            workspace
                .tree_deltas
                .windows(2)
                .all(|pair| pair[0].artifact_id() <= pair[1].artifact_id())
        });
    println!("REF_MUTATIONS {}", operation.ref_mutations.len());
    println!("REF_MUTATIONS_ALREADY_SORTED {refs_sorted}");
    println!("TREE_DELTAS {tree_deltas}");
    println!("TREE_DELTAS_ALREADY_SORTED {tree_sorted}");
    println!("BORROW_PATH_WOULD_FIRE {}", refs_sorted && tree_sorted);

    // Figure one: what a fat receipt's embedded copy weighs DECODED.
    //
    // Measured as the live-heap growth of cloning the record, which is exactly
    // the allocation a second decoded copy costs, and exactly what the retrim
    // stops a rewrite from carrying forward.
    let floor = arm_peak();
    let clone = operation.clone();
    let decoded_bytes = live_bytes().saturating_sub(floor);
    println!(
        "DECODED_OPERATION_RECORD_BYTES {decoded_bytes}  ({:.1} MiB)",
        mib(decoded_bytes)
    );
    drop(clone);
    let after_drop = live_bytes();
    println!("LIVE_AFTER_DROP_DELTA {}", after_drop.saturating_sub(floor));
    assert!(
        decoded_bytes > 0,
        "the control: cloning a record must allocate, or this instrument is not wired"
    );

    // Figure two: what ONE identity costs, which is the clone plus the
    // canonical serialization of the copy.
    let floor = arm_peak();
    let identity = operation.identity_hash().expect("the identity hashes");
    let identity_transient = peak_growth_since(floor);
    let identity_retained = live_bytes().saturating_sub(floor);
    println!(
        "IDENTITY_HASH_TRANSIENT_BYTES {identity_transient}  ({:.1} MiB)",
        mib(identity_transient)
    );
    println!("IDENTITY_HASH_RETAINED_BYTES {identity_retained}");
    println!("IDENTITY {identity:?}");
    assert!(
        identity_transient > decoded_bytes,
        "the control: one identity must cost MORE than the clone alone, because it clones AND \
         serializes the copy; transient {identity_transient} against a clone of {decoded_bytes}"
    );

    // A second call, to show a memo is not what makes this expensive: the cost
    // is per call and identical, which is what the clone-free fix removes.
    let floor = arm_peak();
    let again = operation
        .identity_hash()
        .expect("the identity hashes again");
    let second_transient = peak_growth_since(floor);
    println!("IDENTITY_HASH_SECOND_TRANSIENT_BYTES {second_transient}");
    assert_eq!(
        again, identity,
        "the control: the identity must be stable, or these two readings are of different work"
    );
}
