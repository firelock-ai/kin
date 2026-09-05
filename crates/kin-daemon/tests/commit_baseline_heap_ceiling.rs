// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Live-heap ceiling for resolving a commit's baseline out of authority.
//!
//! Planning a native commit needs the parent change's entities, relations and
//! tree. It used to get them by cloning the authority snapshot, constructing a
//! whole `InMemoryGraph` from it, calling `resolve_graph_at` once, and dropping
//! the graph. That construction is not free and none of its cost reaches the
//! delta: it rebuilds a lexical index over every entity that nothing here
//! searches, and because an authority snapshot always arrives with
//! `entity_revisions` cleared, it also derives entity revisions across the
//! entire history, which kin-db's own comment calls the largest thing a
//! conversion's workspace lap does.
//!
//! The guard measures live heap rather than resident set, following
//! `kin-core/tests/init_peak_heap_ceiling.rs`: RSS keeps counting pages the
//! allocator has not returned to the OS, so it is reproducible only within one
//! allocator and one platform, while live heap moves when and only when the
//! code allocates differently.
//!
//! The ceiling is evidence only because the same binary measures the path it
//! replaced. A bare "stays under N bytes" assertion would pass for reasons
//! unrelated to this change and would keep passing if the throwaway graph came
//! back. So the graph-building path runs here too, on the same fixture, and
//! must exceed the ceiling. If that control ever stops exceeding it, the
//! ceiling has stopped meaning anything and this test says so rather than
//! reporting a pass.
//!
//! This binary installs a counting global allocator, so it holds exactly one
//! test on purpose: the counters are process-wide and a second test running
//! beside it would charge its allocations here.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use kin_daemon::commit_deltas::resolve_authority_baseline;
use kin_db::{GraphSnapshot, InMemoryGraph};
use kin_model::{
    ChangeStore, Entity, EntityDelta, EntityKind, EntityMetadata, EntityStore,
    FingerprintAlgorithm, FilePathId, Hash256, LanguageId, SemanticChangeId, SemanticFingerprint,
    Timestamp, Visibility,
};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn live() -> usize {
    LIVE.load(Ordering::SeqCst)
}

fn peak() -> usize {
    PEAK.load(Ordering::SeqCst)
}

/// Drop the high-water mark to what is live now, so the fixture's own
/// allocation is not charged to the path under measurement.
fn reset_peak() {
    PEAK.store(LIVE.load(Ordering::SeqCst), Ordering::SeqCst);
}

struct Counting;

fn charge(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: every branch forwards to the system allocator with the same pointer
// and layout it was given, and only adjusts counters around that call.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            charge(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            charge(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let fresh = unsafe { System.realloc(ptr, layout, new_size) };
        if !fresh.is_null() {
            if new_size >= layout.size() {
                charge(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        fresh
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Changes in the fixture history.
///
/// The cost this guards is changes multiplied by entity deltas per change, so
/// the fixture buys both: every change here carries an entity delta, which is
/// the shape a real repository has and the shape a churn-only history does not.
/// Measured on four local fixtures, a history whose changes carry no entity
/// deltas costs materially less than one of a fifth the depth whose changes do.
const CHANGES: usize = 400;

/// Distinct entities the history advances, rotating.
///
/// 224 and 400 are not round numbers picked for size. They are the shape of the
/// local fixture that convicted this cost in the first place, whose commit ran
/// 4.79 s at 178.4 MiB of daemon resident set while a fixture of the same graph
/// at five changes ran 0.43 s at 52.2 MiB. Matching that shape keeps the guard
/// measuring the case that was actually observed rather than one tuned to make
/// the gap look wide.
const ENTITIES: usize = 224;

fn entity(name: &str) -> Entity {
    Entity {
        id: kin_model::EntityId::new(),
        kind: EntityKind::Function,
        name: name.to_string(),
        language: LanguageId::Rust,
        fingerprint: SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([1; 32]),
            signature_hash: Hash256::from_bytes([2; 32]),
            behavior_hash: Hash256::from_bytes([3; 32]),
            equivalence_hash: Hash256::from_bytes([0; 32]),
            stability_score: 1.0,
        },
        file_origin: Some(FilePathId::new("src/lib.rs")),
        span: None,
        signature: format!("fn {name}()"),
        visibility: Visibility::Public,
        role: kin_model::EntityRole::Source,
        doc_summary: None,
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

fn change(
    parent: Option<SemanticChangeId>,
    entity_deltas: Vec<EntityDelta>,
) -> kin_model::SemanticChange {
    let mut change = kin_model::SemanticChange {
        id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
        origin: kin_model::ChangeOrigin::Native,
        parents: parent.into_iter().collect(),
        timestamp: Timestamp::from(
            chrono::DateTime::parse_from_rfc3339("2026-09-05T12:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        ),
        author: kin_model::AuthorId::new("relchurn"),
        message: "heap fixture".to_string(),
        entity_deltas,
        relation_deltas: Vec::new(),
        tree_deltas: Vec::new(),
        admission_policy_delta: None,
        projected_files: Vec::new(),
        spec_link: None,
        evidence: Vec::new(),
        risk_summary: None,
        external_reference_deltas: Vec::new(),
    };
    change.id = kin_model::compute_semantic_change_id(&change).expect("fixture change id");
    change
}

/// A snapshot shaped like the one a commit holds: a linear history whose every
/// change carries an entity delta, with `entity_revisions` cleared, which is
/// what repository authority always does to them and is the condition that
/// selects the expensive branch in `InMemoryGraph::from_snapshot`.
fn authority_like_snapshot() -> (GraphSnapshot, SemanticChangeId) {
    let graph = InMemoryGraph::new();
    let mut live: Vec<Entity> = (0..ENTITIES).map(|i| entity(&format!("seed_{i}"))).collect();

    let seeded = change(
        None,
        live.iter()
            .cloned()
            .map(|new| EntityDelta::Added { new })
            .collect(),
    );
    graph.create_change(&seeded).expect("seed change");
    let mut head = Some(seeded.id);

    for step in 1..CHANGES {
        let slot = step % ENTITIES;
        let old = live[slot].clone();
        let mut new = old.clone();
        new.signature = format!("fn seed_{slot}_r{step}()");
        live[slot] = new.clone();
        let advanced = change(head, vec![EntityDelta::Modified { old, new }]);
        graph.create_change(&advanced).expect("advancing change");
        head = Some(advanced.id);
    }

    for entity in &live {
        graph.upsert_entity(entity).expect("live entity");
    }
    let mut snapshot = graph.to_snapshot();
    snapshot.repository_authority = None;
    snapshot.entity_revisions.clear();
    (snapshot, head.expect("the fixture has a head"))
}

/// The path this change replaced, kept as the control the ceiling is read
/// against.
fn baseline_by_building_a_graph(snapshot: &GraphSnapshot, head: &SemanticChangeId) -> usize {
    let mut owned = snapshot.clone();
    owned.repository_authority = None;
    let resolved = InMemoryGraph::from_snapshot(owned)
        .expect("control graph")
        .resolve_graph_at(head)
        .expect("control resolution");
    resolved.entities.len()
}

#[test]
fn resolving_a_commit_baseline_does_not_pay_for_a_graph_it_drops() {
    let (snapshot, head) = authority_like_snapshot();

    reset_peak();
    let before = live();
    let folded = resolve_authority_baseline(&snapshot, &head).expect("baseline");
    let borrowed_peak = peak() - before;
    assert_eq!(
        folded.entities.len(),
        ENTITIES,
        "the fixture must resolve every live entity, or the measurement is of nothing"
    );
    drop(folded);

    reset_peak();
    let before = live();
    let control_entities = baseline_by_building_a_graph(&snapshot, &head);
    let graph_peak = peak() - before;
    assert_eq!(
        control_entities, ENTITIES,
        "the control must resolve the same graph, or it is not a control"
    );

    eprintln!("borrowed_peak_bytes={borrowed_peak} graph_peak_bytes={graph_peak}");

    assert!(
        borrowed_peak < PEAK_HEAP_CEILING,
        "resolving the baseline allocated {borrowed_peak} bytes, over the {PEAK_HEAP_CEILING} \
         ceiling; the throwaway graph, its lexical index or the whole-history revision \
         derivation is being paid for again"
    );
    assert!(
        graph_peak > PEAK_HEAP_CEILING,
        "the control allocated {graph_peak} bytes, which does not exceed the {PEAK_HEAP_CEILING} \
         ceiling, so this ceiling no longer separates the two paths and is not evidence; \
         re-measure both and reset it rather than trusting the pass above"
    );
}

/// Ceiling on live heap for resolving one commit's baseline.
///
/// Measured on this fixture, both arms in the same process on the same host:
/// resolving the baseline peaked at 1_610_386 bytes and the graph-building path
/// it replaced peaked at 2_808_080. The ceiling sits between them with roughly
/// symmetric margin, about 30 percent of headroom under it and about 34 percent
/// of overshoot above it, so neither side is one allocation away from flipping.
///
/// Be precise about what this catches and what it does not. It is a floor under
/// gross regressions, not proof that no copy came back. The gap it reads is
/// 1.2 MB on a 400-change, 224-entity fixture, so a change that reintroduced a
/// copy materially smaller than the whole graph build would pass it, and any
/// change to this path still needs its own measurement rather than a green tick
/// here. The number is also from one host and one allocator; it is set this wide
/// partly because that determinism has only been observed on macOS while this
/// suite also runs on Linux and Windows.
const PEAK_HEAP_CEILING: usize = 2_100_000;
