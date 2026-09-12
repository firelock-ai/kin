// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Measure what walking every entity costs against a real store on disk.
//!
//! ```text
//! cargo run --release --example walk_store -- <.kin/kindb dir> <clone|visit>
//! ```
//!
//! `clone` runs the walk through [`EntityStore::list_all_entities`], which
//! materializes a `Vec<Entity>` cloned out of the live map. `visit` runs the
//! same walk through `InMemoryGraph::for_each_entity`, which borrows each
//! entity under one read lock. The workload either way is the read-only tally
//! `ReadIndex::from_graph` performs, so the only difference between the two
//! numbers is the copy.
//!
//! One arm per process on purpose. `ru_maxrss` is a high-water mark, so running
//! both arms in one process would charge the second with the first's peak and
//! report the clone as free.
//!
//! Resident size is reported twice at each checkpoint. The peak is the
//! high-water mark since the process started, and it is dominated by decoding
//! and folding the store, so a walk cheaper than that fold moves it not at all.
//! Live resident size is what the walk itself holds while it runs, which is the
//! number the clone actually changes.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use kin_db::{InMemoryGraph, LocalFileBackend, RepositoryAuthorityManager};
use kin_model::{EntityStore, RepositoryId};

/// Global allocator that counts live bytes and their high-water mark.
///
/// Resident set size is the wrong instrument for this question and the first
/// run of this harness showed why: the fold that materializes the graph grows
/// the heap far past what the walk needs, so a clone of every entity is served
/// from pages `malloc` already holds and moves RSS by less than the run-to-run
/// drift of the baseline itself. Live allocated bytes are exact, deterministic,
/// and attributable to the call under test.
struct Counting;

static LIVE: AtomicI64 = AtomicI64::new(0);
static PEAK: AtomicI64 = AtomicI64::new(0);

impl Counting {
    fn add(bytes: usize) {
        let live = LIVE.fetch_add(bytes as i64, Ordering::Relaxed) + bytes as i64;
        PEAK.fetch_max(live, Ordering::Relaxed);
    }

    fn sub(bytes: usize) {
        LIVE.fetch_sub(bytes as i64, Ordering::Relaxed);
    }

    fn live() -> i64 {
        LIVE.load(Ordering::Relaxed)
    }

    fn peak() -> i64 {
        PEAK.load(Ordering::Relaxed)
    }

    fn reset_peak_to_live() {
        PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

// SAFETY: every method forwards to the system allocator with the same layout it
// was given and only adds bookkeeping around it.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            Self::add(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        Self::sub(layout.size());
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            Self::add(layout.size());
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let out = unsafe { System.realloc(ptr, layout, new_size) };
        if !out.is_null() {
            Self::sub(layout.size());
            Self::add(new_size);
        }
        out
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Peak resident set size of this process so far, in bytes.
///
/// `ru_maxrss` is bytes on macOS and kilobytes on Linux; the scale is part of
/// the platform's ABI, not something to normalize away silently.
fn peak_rss_bytes() -> u64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is a zeroed `rusage` this call only writes to.
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    if rc != 0 {
        return 0;
    }
    let raw = usage.ru_maxrss as u64;
    if cfg!(target_os = "macos") {
        raw
    } else {
        raw.saturating_mul(1024)
    }
}

/// Resident set size right now, in bytes, or 0 when it cannot be read.
#[cfg(target_os = "macos")]
fn live_rss_bytes() -> u64 {
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let want = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    // SAFETY: `info` is a zeroed `proc_taskinfo` and `want` is its exact size.
    let got = unsafe {
        libc::proc_pidinfo(
            std::process::id() as libc::c_int,
            libc::PROC_PIDTASKINFO,
            0,
            std::ptr::addr_of_mut!(info).cast::<libc::c_void>(),
            want,
        )
    };
    if got == want {
        info.pti_resident_size
    } else {
        0
    }
}

/// Resident set size right now, in bytes, or 0 when it cannot be read.
#[cfg(not(target_os = "macos"))]
fn live_rss_bytes() -> u64 {
    let Ok(statm) = std::fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    let Some(resident_pages) = statm.split_whitespace().nth(1) else {
        return 0;
    };
    let Ok(resident_pages) = resident_pages.parse::<u64>() else {
        return 0;
    };
    // SAFETY: `sysconf` reads a static system value and takes no pointer.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page <= 0 {
        return 0;
    }
    resident_pages.saturating_mul(page as u64)
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn mib_i(bytes: i64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// The one repository namespace under a `.kin/kindb` directory.
fn only_repository_id(kindb: &Path) -> Option<String> {
    let mut found = None;
    for entry in std::fs::read_dir(kindb).ok()? {
        let entry = entry.ok()?;
        if !entry.path().join("authority.json").is_file() {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(entry.file_name().to_string_lossy().into_owned());
    }
    found
}

fn fail(message: String) -> ! {
    eprintln!("walk_store: {message}");
    std::process::exit(1);
}

/// Hydrate the graph a reader of this store actually holds.
///
/// A repository envelope's top-level query domains are empty; the entities live
/// in the change map, and the workspace graph snapshot is the fold that
/// resolves them. Opening the envelope alone reports zero entities, which is
/// how this harness first reported a store of 1062 admitted files as empty.
fn open_graph(kindb: &Path) -> InMemoryGraph {
    let Some(repository_id) = only_repository_id(kindb) else {
        fail(format!(
            "{} holds no single repository namespace",
            kindb.display()
        ));
    };
    let repository_id = RepositoryId::new(repository_id)
        .unwrap_or_else(|err| fail(format!("bad repository id: {err}")));

    let backend = Arc::new(LocalFileBackend::new(kindb));
    let manager = RepositoryAuthorityManager::open(repository_id.clone(), backend)
        .unwrap_or_else(|err| fail(format!("cannot open {repository_id}: {err}")));

    let lease = manager.read_authority();
    let Some(workspace) = lease.metadata().workspaces.first() else {
        fail(format!("repository {repository_id} has no workspace"));
    };
    let snapshot = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .unwrap_or_else(|err| fail(format!("cannot materialize workspace graph: {err}")))
        .unwrap_or_else(|| fail("workspace vanished between listing and read".to_string()));
    drop(lease);

    InMemoryGraph::from_snapshot_without_text_index(snapshot)
        .unwrap_or_else(|err| fail(format!("cannot hydrate {repository_id}: {err}")))
}

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(kindb) = args.next() else {
        eprintln!("usage: walk_store <.kin/kindb dir> <clone|visit>");
        std::process::exit(2);
    };
    let arm = args.next().unwrap_or_else(|| "clone".to_string());

    let kindb = Path::new(&kindb);
    let graph = open_graph(kindb);

    let entities = graph.entity_count();
    let relations = graph.relation_count();
    let loaded_peak_rss = peak_rss_bytes();
    let loaded_live_rss = live_rss_bytes();
    let loaded_heap = Counting::live();
    Counting::reset_peak_to_live();
    println!("store                 {}", kindb.display());
    println!("entities              {entities}");
    println!("relations             {relations}");
    println!("heap after load       {:.1} MiB", mib_i(loaded_heap));
    println!("peak RSS after load   {:.1} MiB", mib(loaded_peak_rss));
    println!("live RSS after load   {:.1} MiB", mib(loaded_live_rss));

    // The tally `ReadIndex::from_graph` builds: every entity read once, nothing
    // kept. Summing the name bytes keeps the compiler from eliding the walk.
    let mut kinds = [0u64; 256];
    let mut languages = [0u64; 256];
    let mut name_bytes = 0u64;
    let mut seen = 0u64;

    let started = Instant::now();
    match arm.as_str() {
        "clone" => {
            let all = graph.list_all_entities().expect("list entities");
            for entity in &all {
                kinds[entity.kind as usize] += 1;
                languages[entity.language as usize] += 1;
                name_bytes += entity.name.len() as u64;
                seen += 1;
            }
        }
        "visit" => {
            graph.for_each_entity(|entity| {
                kinds[entity.kind as usize] += 1;
                languages[entity.language as usize] += 1;
                name_bytes += entity.name.len() as u64;
                seen += 1;
            });
        }
        other => {
            eprintln!("walk_store: unknown arm {other:?}, expected clone or visit");
            std::process::exit(2);
        }
    }
    let elapsed = started.elapsed();
    let walk_peak_heap = Counting::peak();
    let walked_peak_rss = peak_rss_bytes();
    let walked_live_rss = live_rss_bytes();

    let distinct_kinds = kinds.iter().filter(|count| **count > 0).count();
    let distinct_languages = languages.iter().filter(|count| **count > 0).count();

    println!("arm                   {arm}");
    println!("walked                {seen}");
    println!("distinct kinds        {distinct_kinds}");
    println!("distinct languages    {distinct_languages}");
    println!("name bytes            {name_bytes}");
    println!(
        "wall time             {:.3} ms",
        elapsed.as_secs_f64() * 1000.0
    );
    println!("peak heap during walk {:.1} MiB", mib_i(walk_peak_heap));
    println!(
        "HEAP THE WALK ADDED   {:.1} MiB",
        mib_i(walk_peak_heap - loaded_heap)
    );
    println!("peak RSS after walk   {:.1} MiB", mib(walked_peak_rss));
    println!("live RSS after walk   {:.1} MiB", mib(walked_live_rss));
}
