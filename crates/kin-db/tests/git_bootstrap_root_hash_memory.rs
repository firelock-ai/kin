// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//! What hashing a repository's replication root holds while it does it.
//!
//! Every authority root folds its inputs through one canonical encoding, and
//! `replication_root` hands that encoding a single leaf carrying the entire Git
//! object closure. The encoding was produced by building a `serde_json::Value`
//! tree of the leaf and walking it, and the tree costs many times the bytes it
//! exists to produce: measured on a synthetic Git bootstrap of 1,200 commits
//! and 3,647 objects, the tree for one repository transaction grew the live
//! heap's high-water mark by 282,848,867 bytes to emit 18,396,132 bytes of
//! canonical payload, a factor of 15.4 (FIR-2665).
//!
//! A conversion is where that stops being free, because a bootstrap commits the
//! whole repository in one transaction and hands the whole closure to one leaf.
//!
//! Live heap rather than resident set, for the reason the sibling guards give:
//! resident set keeps counting memory the allocator has freed and not returned,
//! so it moves with the platform, while live heap moves when and only when the
//! code holds differently.
//!
//! ## Why the peak is armed per phase and not read off the running mark
//!
//! This is the trap that would have made this guard unable to fail. Peak growth
//! measured against a single running high-water mark reports what a phase added
//! to the tallest thing seen so far, so a phase that allocates a gigabyte reads
//! as zero whenever something earlier in the same run already stood taller. The
//! commit this guard runs inside contains exactly such a term, and it is larger
//! than the one measured here, so the naive reading would have been a confident
//! zero no matter what `replication_root` did. The sampler below therefore arms
//! the mark at each span's own entry and restores the outer mark on its exit.
//!
//! This file is its own test binary and holds one test on purpose. The
//! allocator counters and the span sampler below are process-global, so a
//! second test running beside this one would be measured into it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use kin_db::{LocalFileBackend, RepositoryAuthorityManager, VersionedAuthorityState};
use kin_model::{
    compute_semantic_change_id, ArtifactId, AuthorId, ChangeOrigin, ExternalChangeAlias,
    ExternalObjectKind, ExternalObjectRecord, GitExternalAuthority, GitExternalAuthorityDelta,
    GitObjectBodyLoader, GitObjectFormat, GitObjectId, GitRawRef, GitRawTarget, Hash256,
    LocatedEntry, OperationId, RefName, RepoPath, RepositoryId, RepositoryTransaction,
    SemanticChange, SemanticChangeId, Timestamp, TreeDelta, TreeEntry,
    REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
use uuid::Uuid;

// --- the instrument -------------------------------------------------------

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

fn peak_bytes() -> usize {
    PEAK.load(Ordering::Relaxed)
}

fn retained_by<T>(build: impl FnOnce() -> T) -> (T, usize) {
    let before = live_bytes();
    let value = build();
    (value, live_bytes().saturating_sub(before))
}

/// Peak live heap `build` reaches above the heap it started from, measured the
/// same way the sampler measures a span so the control and the reading are
/// commensurable.
fn peak_of<T>(build: impl FnOnce() -> T) -> (T, usize) {
    let floor = live_bytes();
    let outer = PEAK.swap(floor, Ordering::Relaxed);
    let value = build();
    let within = PEAK.load(Ordering::Relaxed).saturating_sub(floor);
    PEAK.fetch_max(outer, Ordering::Relaxed);
    (value, within)
}

// --- the span sampler -----------------------------------------------------

const PHASE_PREFIX: &str = "kindb.";

#[derive(Debug, Clone, Copy)]
struct PhaseSample {
    phase: &'static str,
    entering: bool,
    live: usize,
    peak: usize,
}

/// One span's entry state, so its exit can read a mark armed at its own entry
/// and then hand the outer span back the taller of the two.
#[derive(Debug, Clone, Copy)]
struct OpenSpan {
    id: u64,
    outer_peak: usize,
}

static OPEN: Mutex<Vec<OpenSpan>> = Mutex::new(Vec::new());
static SAMPLES: Mutex<Vec<PhaseSample>> = Mutex::new(Vec::new());
static SPAN_NAMES: Mutex<Option<HashMap<u64, &'static str>>> = Mutex::new(None);
static NEXT_SPAN_ID: AtomicU64 = AtomicU64::new(1);

struct PhaseSampler;

fn phase_name(id: &tracing::span::Id) -> Option<&'static str> {
    SPAN_NAMES
        .lock()
        .expect("span names poisoned")
        .as_ref()
        .and_then(|names| names.get(&id.into_u64()).copied())
}

fn record(sample: PhaseSample) {
    SAMPLES.lock().expect("samples poisoned").push(sample);
}

impl tracing::Subscriber for PhaseSampler {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.is_span() && metadata.name().starts_with(PHASE_PREFIX)
    }

    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let id = NEXT_SPAN_ID.fetch_add(1, Ordering::Relaxed);
        SPAN_NAMES
            .lock()
            .expect("span names poisoned")
            .get_or_insert_with(HashMap::new)
            .insert(id, span.metadata().name());
        tracing::span::Id::from_u64(id)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn event(&self, _event: &tracing::Event<'_>) {}

    fn enter(&self, id: &tracing::span::Id) {
        let Some(phase) = phase_name(id) else {
            return;
        };
        let live = live_bytes();
        let outer_peak = PEAK.swap(live, Ordering::Relaxed);
        OPEN.lock().expect("open spans poisoned").push(OpenSpan {
            id: id.into_u64(),
            outer_peak,
        });
        record(PhaseSample {
            phase,
            entering: true,
            live,
            peak: live,
        });
    }

    fn exit(&self, id: &tracing::span::Id) {
        let Some(phase) = phase_name(id) else {
            return;
        };
        let within = PEAK.load(Ordering::Relaxed);
        let mut open = OPEN.lock().expect("open spans poisoned");
        let entry = open
            .iter()
            .rposition(|span| span.id == id.into_u64())
            .map(|position| open.remove(position));
        drop(open);
        if let Some(entry) = entry {
            // The outer span's mark stands again, raised by whatever this one
            // reached, so a parent still sees its children's cost.
            PEAK.fetch_max(entry.outer_peak, Ordering::Relaxed);
            record(PhaseSample {
                phase,
                entering: false,
                live: live_bytes(),
                peak: within,
            });
        }
    }
}

/// The worst peak live heap one phase reached above its own entry, over every
/// time it ran.
///
/// The worst rather than the first, and this is the second trap this guard
/// walked into. The replication root is computed once when an empty authority
/// is opened and again when the bootstrap commits, and the first of those runs
/// against nothing at all. Reading the first occurrence reported 320 bytes and
/// 0.00 copies while the run that mattered was reaching 25.7, which is a guard
/// that passes no matter what the code does.
///
/// `None` when the phase never opened, which is a different answer from zero
/// and is treated as one: a guard whose span name went stale must fail rather
/// than report that the holder it was written for holds nothing.
fn peak_of_phase(phase: &str) -> Option<usize> {
    let samples = SAMPLES.lock().expect("samples poisoned").clone();
    let mut open: Vec<usize> = Vec::new();
    let mut worst: Option<usize> = None;
    for sample in &samples {
        if sample.phase != phase {
            continue;
        }
        if sample.entering {
            open.push(sample.live);
        } else if let Some(live) = open.pop() {
            let within = sample.peak.saturating_sub(live);
            worst = Some(worst.map_or(within, |seen: usize| seen.max(within)));
        }
    }
    worst
}

/// Every distinct phase the run opened, for a failure message that can be acted on.
fn observed_phases() -> Vec<&'static str> {
    let mut phases: Vec<&'static str> = SAMPLES
        .lock()
        .expect("samples poisoned")
        .iter()
        .map(|sample| sample.phase)
        .collect();
    phases.sort_unstable();
    phases.dedup();
    phases
}

/// Print every phase in the order it ran, with the peak it reached above its
/// own entry and what it still held when it exited.
fn print_phase_table() {
    let samples = SAMPLES.lock().expect("samples poisoned").clone();
    let mut open: Vec<(usize, PhaseSample)> = Vec::new();
    let mut rows: Vec<(usize, &'static str, usize, i64, usize)> = Vec::new();
    for sample in &samples {
        if sample.entering {
            open.push((open.len(), *sample));
        } else if let Some(position) = open.iter().rposition(|(_, s)| s.phase == sample.phase) {
            let (depth, entered) = open.remove(position);
            rows.push((
                depth,
                sample.phase,
                sample.peak.saturating_sub(entered.live),
                sample.live as i64 - entered.live as i64,
                entered.live,
            ));
        }
    }
    println!(
        "\n{:<44} {:>13} {:>13} {:>13} {:>13}",
        "phase", "peak growth", "ABS PEAK", "retained", "live at enter"
    );
    for (depth, phase, peak_growth, retained, live_in) in &rows {
        if *peak_growth == 0 && *retained == 0 {
            continue;
        }
        println!(
            "{:<44} {:>13} {:>13} {:>13} {:>13}",
            format!("{}{}", "  ".repeat(*depth), phase),
            peak_growth,
            live_in + peak_growth,
            retained,
            live_in
        );
    }
    println!("\nall-time peak live heap: {} bytes", peak_bytes());
}

// --- the synthetic Git conversion -----------------------------------------

const COMMITS: usize = 400;
const FILES: usize = 32;
const FILE_BODY_BYTES: usize = 512;

#[derive(Default, Clone)]
struct Bodies(BTreeMap<Hash256, Vec<u8>>);

impl GitObjectBodyLoader for Bodies {
    type Error = std::convert::Infallible;

    fn load_body(&mut self, body_hash: &Hash256) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.0.get(body_hash).cloned())
    }
}

/// The real Git object id of `body` under `kind`, which the record constructor
/// recomputes and refuses to take on trust.
fn git_oid(kind: ExternalObjectKind, body: &[u8]) -> GitObjectId {
    use sha1::{Digest, Sha1};
    let header: &[u8] = match kind {
        ExternalObjectKind::Blob => b"blob",
        ExternalObjectKind::Tree => b"tree",
        ExternalObjectKind::Commit => b"commit",
        ExternalObjectKind::Tag => b"tag",
    };
    let mut hasher = Sha1::new();
    hasher.update(header);
    hasher.update(b" ");
    hasher.update(body.len().to_string().as_bytes());
    hasher.update([0]);
    hasher.update(body);
    let mut bytes = [0_u8; 20];
    bytes.copy_from_slice(&hasher.finalize());
    GitObjectId::sha1(bytes)
}

fn tree_body(entries: &[(Vec<u8>, GitObjectId)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, target) in entries {
        body.extend_from_slice(b"100644");
        body.push(b' ');
        body.extend_from_slice(name);
        body.push(0);
        body.extend_from_slice(target.as_bytes());
    }
    body
}

fn commit_body(tree: GitObjectId, parents: &[GitObjectId], message: &[u8]) -> Vec<u8> {
    let mut body = format!("tree {tree}\n").into_bytes();
    for parent in parents {
        body.extend_from_slice(format!("parent {parent}\n").as_bytes());
    }
    body.extend_from_slice(
        b"author Kin <kin@example.com> 1700000000 +0000\n\
          committer Kin <kin@example.com> 1700000000 +0000\n\n",
    );
    body.extend_from_slice(message);
    body
}

fn parent_slice(parent: &Option<GitObjectId>) -> &[GitObjectId] {
    match parent {
        Some(value) => std::slice::from_ref(value),
        None => &[],
    }
}

fn file_name(index: usize) -> Vec<u8> {
    format!("f{index:05}.rs").into_bytes()
}

fn file_body(index: usize, revision: usize) -> Vec<u8> {
    let mut body = format!("// file {index} revision {revision}\n").into_bytes();
    body.resize(FILE_BODY_BYTES, b'x');
    body
}

struct Fixture {
    records: Vec<ExternalObjectRecord>,
    bodies: Bodies,
    changes: Vec<SemanticChange>,
    aliases: Vec<ExternalChangeAlias>,
    head_commit: GitObjectId,
}

/// A Git history of `COMMITS` commits over `FILES` files, one file rewritten per
/// commit, with a full object closure and a matching semantic change per commit.
fn build_fixture(repository: &RepositoryId) -> Fixture {
    let mut bodies = Bodies::default();
    let mut records: Vec<ExternalObjectRecord> = Vec::new();
    let admit = |kind: ExternalObjectKind,
                 body: Vec<u8>,
                 bodies: &mut Bodies,
                 records: &mut Vec<ExternalObjectRecord>| {
        let record = ExternalObjectRecord::from_raw(kind, git_oid(kind, &body), &body)
            .expect("synthetic Git object records");
        bodies.0.insert(record.body_hash, body);
        records.push(record.clone());
        record
    };

    // Commit 0 adds every file; each later commit rewrites one of them.
    let mut current: Vec<(Vec<u8>, GitObjectId, Hash256)> = Vec::with_capacity(FILES);
    for file in 0..FILES {
        let body = file_body(file, 0);
        let blob = admit(ExternalObjectKind::Blob, body, &mut bodies, &mut records);
        current.push((file_name(file), blob.object.oid, blob.body_hash));
    }

    let mut changes: Vec<SemanticChange> = Vec::with_capacity(COMMITS);
    let mut aliases: Vec<ExternalChangeAlias> = Vec::with_capacity(COMMITS);
    let mut parent_commit: Option<GitObjectId> = None;
    let mut parent_change: Option<SemanticChangeId> = None;
    let mut head_commit = GitObjectId::sha1([0; 20]);

    for index in 0..COMMITS {
        let tree_deltas = if index == 0 {
            current
                .iter()
                .enumerate()
                .map(|(file, (name, _, body_hash))| TreeDelta::Added {
                    artifact_id: ArtifactId(Uuid::from_u128(1_000_000 + file as u128)),
                    new: LocatedEntry::new(
                        RepoPath::from_bytes(name.clone()).expect("synthetic path"),
                        TreeEntry::blob(*body_hash, false),
                    ),
                })
                .collect::<Vec<_>>()
        } else {
            let file = index % FILES;
            let old_hash = current[file].2;
            let body = file_body(file, index);
            let blob = admit(ExternalObjectKind::Blob, body, &mut bodies, &mut records);
            let name = current[file].0.clone();
            current[file].1 = blob.object.oid;
            current[file].2 = blob.body_hash;
            vec![TreeDelta::Updated {
                artifact_id: ArtifactId(Uuid::from_u128(1_000_000 + file as u128)),
                old: LocatedEntry::new(
                    RepoPath::from_bytes(name.clone()).expect("synthetic path"),
                    TreeEntry::blob(old_hash, false),
                ),
                new: LocatedEntry::new(
                    RepoPath::from_bytes(name).expect("synthetic path"),
                    TreeEntry::blob(blob.body_hash, false),
                ),
            }]
        };

        let entries = current
            .iter()
            .map(|(name, object_id, _)| (name.clone(), *object_id))
            .collect::<Vec<_>>();
        let tree = admit(
            ExternalObjectKind::Tree,
            tree_body(&entries),
            &mut bodies,
            &mut records,
        );
        let commit = admit(
            ExternalObjectKind::Commit,
            commit_body(
                tree.object.oid,
                parent_slice(&parent_commit),
                format!("synthetic commit {index}").as_bytes(),
            ),
            &mut bodies,
            &mut records,
        );

        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::GitCommit {
                oid: commit.object.oid,
            },
            parents: parent_change.into_iter().collect(),
            timestamp: Timestamp(
                chrono::DateTime::parse_from_rfc3339("2026-08-25T00:00:00Z")
                    .expect("fixed timestamp")
                    .with_timezone(&chrono::Utc),
            ),
            author: AuthorId::new("fir2665-step13-measurement"),
            message: format!("synthetic commit {index}"),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        };
        change.id = compute_semantic_change_id(&change).expect("change id computes");
        aliases.push(ExternalChangeAlias::new(
            repository.clone(),
            commit.object.oid,
            change.id,
        ));
        parent_change = Some(change.id);
        parent_commit = Some(commit.object.oid);
        head_commit = commit.object.oid;
        changes.push(change);
    }

    Fixture {
        records,
        bodies,
        changes,
        aliases,
        head_commit,
    }
}

/// Share of the `serde_json::Value` tree's own peak that hashing the
/// replication root may reach.
///
/// The tree is the denominator on purpose. The canonical encoding is verbose in
/// its own right, because it renders a byte string as an array of numbers, so
/// one Git object id costs far more encoded than it costs in memory and a
/// ceiling counting copies of the authority would be measuring that verbosity
/// rather than this change. What this guard is about is whether hashing builds
/// a picture of the value first, and the honest denominator for that is the
/// picture.
///
/// Set from measurement on this fixture, not from taste. The shape that hashed
/// by walking a tree it had just built measures at or just above 1.0, because
/// the tree IS the control. The shape that writes the canonical bytes straight
/// out of `Serialize` measures 0.42 on this fixture. A ceiling of 0.6 fails the
/// first and passes the second, and it is a ratio of two live-heap readings
/// taken in one process, so it is profile- and host-independent.
const REPLICATION_ROOT_TREE_SHARE: f64 = 0.6;

/// Copies of the authority the control must itself reach, so a fixture too
/// small to show the cost fails here rather than passing the ceiling for the
/// wrong reason.
const CONTROL_MINIMUM_AUTHORITY_COPIES: f64 = 10.0;

/// Hashing the replication root must not build a picture of the authority.
#[test]
fn hashing_the_replication_root_does_not_materialize_the_authority() {
    tracing::subscriber::set_global_default(PhaseSampler).expect("this binary holds one test");

    let directory = tempfile::tempdir().expect("tempdir");
    let backend = Arc::new(LocalFileBackend::new(directory.path()));
    let repository = RepositoryId::new("fir2665-step13-measurement").expect("repository id");
    let manager =
        RepositoryAuthorityManager::open(repository.clone(), backend).expect("open authority");

    let (fixture, fixture_bytes) = retained_by(|| build_fixture(&repository));
    println!(
        "fixture: {} commits, {} objects, {} bytes retained",
        fixture.changes.len(),
        fixture.records.len(),
        fixture_bytes
    );

    for (hash, body) in &fixture.bodies.0 {
        manager.save_source_blob(*hash, body).expect("save body");
    }

    let main = RefName::branch(b"main").expect("branch name");
    let mut loader = fixture.bodies.clone();
    let (authority, authority_bytes) = retained_by(|| {
        GitExternalAuthority::from_raw_parts(
            repository.clone(),
            GitObjectFormat::Sha1,
            vec![GitRawRef {
                name: main.clone(),
                target: GitRawTarget::Direct {
                    object: kin_model::ExternalObjectId::new(
                        ExternalObjectKind::Commit,
                        fixture.head_commit,
                    ),
                },
            }],
            GitRawTarget::Symbolic {
                target: main.clone(),
            },
            fixture.records.clone(),
            &mut loader,
        )
        .expect("synthetic authority builds")
    });
    println!("authority: {authority_bytes} bytes retained");
    assert!(
        authority_bytes > 1_000_000,
        "the fixture authority must be large enough to price a copy of it, got {authority_bytes} bytes"
    );

    // The control, and the reason this guard exists: the tree the canonical
    // encoding used to be built from. Taken before the commit so it is the
    // tree's own cost and not the commit's.
    let (control, control_peak) =
        peak_of(|| serde_json::to_value(&authority).expect("the authority serializes"));
    drop(control);

    let lease = manager.read_authority();
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: OperationId::from_uuid(Uuid::from_u128(1)),
        repository_id: repository.clone(),
        expected_generation: lease.generation(),
        expected_roots: lease.roots().clone(),
        actor: AuthorId::new("fir2665-step13-measurement"),
        reason: "synthetic Git whole-history bootstrap".to_string(),
        external_objects: fixture.records.clone(),
        git_authority_delta: Some(GitExternalAuthorityDelta::initialize(authority)),
        changes: fixture.changes.clone(),
        aliases: fixture.aliases.clone(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: None,
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
    };
    drop(lease);

    // Split the two ceiling terms so the next rewrite is aimed rather than
    // guessed. Both take &self, so nothing is cloned to measure them.
    let (_, validate_peak) = peak_of(|| transaction.validate().expect("the fixture validates"));
    let (_, hash_peak) = peak_of(|| {
        transaction
            .transaction_hash()
            .expect("the fixture transaction hashes")
    });
    println!(
        "transaction terms:\n  \
         validate() alone:        {validate_peak} bytes of peak above entry\n  \
         transaction_hash():      {hash_peak} bytes (validate + canonical_hash)"
    );

    let before_commit = live_bytes();
    println!("live heap before commit: {before_commit} bytes");
    let receipt = manager
        .commit_repository_transaction(transaction)
        .expect("the synthetic Git bootstrap commits");
    assert_eq!(receipt.generation, 1);

    print_phase_table();

    // A positive control on the sampler itself. A span name that went stale
    // would make every reading below describe a phase that was never observed,
    // and reporting zero bytes held would be the most flattering possible way
    // to be wrong.
    let replication = peak_of_phase("kindb.roots.replication").unwrap_or_else(|| {
        panic!(
            "the sampler never saw the replication root, so this guard is measuring nothing; \
             phases seen: {:?}",
            observed_phases()
        )
    });

    let control_copies = control_peak as f64 / authority_bytes as f64;
    let share = replication as f64 / control_peak as f64;
    println!(
        "one authority copy: {authority_bytes} bytes\n\
         a serde_json tree of it reached: {control_peak} bytes, {control_copies:.2} copies \
         of the authority\n\
         kindb.roots.replication reached: {replication} bytes, {share:.2} of the tree"
    );

    assert!(
        control_copies > CONTROL_MINIMUM_AUTHORITY_COPIES,
        "the control must show the cost this guard is about; a serde_json tree of the \
         authority reached only {control_copies:.2} copies of it, under the \
         {CONTROL_MINIMUM_AUTHORITY_COPIES} this fixture needs to demonstrate the \
         difference, so the ceiling below would pass for the wrong reason"
    );
    assert!(
        share <= REPLICATION_ROOT_TREE_SHARE,
        "hashing the replication root reached {replication} bytes, {share:.2} of the \
         {control_peak} bytes a serde_json tree of the same authority reaches, at or over \
         the {REPLICATION_ROOT_TREE_SHARE} ceiling; hashing is building a picture of the \
         value again"
    );
}
