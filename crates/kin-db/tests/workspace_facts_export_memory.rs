// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Workspace comparisons must not copy unrelated graph stores.
//!
//! The fixture includes decoded history and annotation payloads. Snapshot
//! exports share immutable history, so the annotations keep a real whole-store
//! copy measurable without requiring the history to become expensive again.
//!
//! Live heap, not resident set: resident set keeps counting memory the
//! allocator has freed and not returned, so it moves with the allocator and the
//! platform, while live heap moves when and only when the code allocates
//! differently.
//!
//! Its own test binary holding one test, because the counters are process
//! global and a second test beside this one would be measured into it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use kin_db::{GraphSnapshot, InMemoryGraph};
use kin_model::{
    compute_semantic_change_id, Annotation, AnnotationId, AnnotationKind, AuthorId, ChangeOrigin,
    Entity, EntityId, EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm,
    GraphNodeId, Hash256, IdentityRef, LanguageId, Relation, RelationId, RelationKind,
    RelationOrigin, SemanticChange, SemanticChangeId, SemanticFingerprint, StalenessState,
    Timestamp, Visibility, WorkScope,
};

// --- the instrument -------------------------------------------------------

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

fn charge(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            charge(layout.size());
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            charge(layout.size());
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
                charge(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        moved
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live() -> usize {
    LIVE.load(Ordering::SeqCst)
}

/// Peak live heap reached inside `work`, above what was live on entry.
///
/// The high-water mark is what an OOM killer sees, so it is what this charges,
/// and the value is dropped inside so a retained result cannot flatter it.
fn grown<T>(work: impl FnOnce() -> T) -> usize {
    let before = live();
    PEAK.store(before, Ordering::SeqCst);
    let value = work();
    let peak = PEAK.load(Ordering::SeqCst);
    drop(value);
    peak.saturating_sub(before)
}

// --- the fixture ----------------------------------------------------------

/// Roughly psf/requests: a few thousand changes over about a thousand entities.
const ENTITIES: usize = 1_058;
const RELATIONS: usize = 2_213;
const CHANGES: usize = 6_733;
/// Payload per change, so the change map is a real cost and not a map of stubs.
const CHANGE_MESSAGE_BYTES: usize = 512;
const ANNOTATIONS: usize = 32;
const ANNOTATION_BODY_BYTES: usize = 512 * 1024;

fn entity(index: usize) -> Entity {
    let path = format!("src/module_{index}.rs");
    let name = format!("kin_{index}");
    let byte = (index % 251) as u8;
    Entity {
        id: EntityId::from_content(&path, &name, "function", 1),
        kind: EntityKind::Function,
        name: name.clone(),
        language: LanguageId::Rust,
        fingerprint: SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([byte; 32]),
            signature_hash: Hash256::from_bytes([byte.wrapping_add(1); 32]),
            behavior_hash: Hash256::from_bytes([byte.wrapping_add(2); 32]),
            equivalence_hash: Hash256::from_bytes([byte.wrapping_add(3); 32]),
            stability_score: 1.0,
        },
        file_origin: Some(FilePathId::new(&path)),
        span: None,
        signature: format!("fn {name}()"),
        visibility: Visibility::Public,
        role: EntityRole::Source,
        doc_summary: None,
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        superseded_by: None,
        created_in: None,
    }
}

/// A relation between two fixture entities.
///
/// Relations are half of what the planner's semantic diff compares, so a
/// fixture without them cannot tell an export that carries relations from one
/// that drops them.
fn relation(index: usize) -> (RelationId, Relation) {
    let src = entity(index % ENTITIES).id;
    let dst = entity((index + 1) % ENTITIES).id;
    let id = RelationId::new();
    (
        id,
        Relation {
            id,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            kind: RelationKind::Calls,
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        },
    )
}

fn fixed_timestamp() -> Timestamp {
    Timestamp(
        chrono::DateTime::parse_from_rfc3339("2026-08-27T00:00:00Z")
            .expect("fixed timestamp parses")
            .with_timezone(&chrono::Utc),
    )
}

fn change(index: usize) -> (SemanticChangeId, SemanticChange) {
    let mut change = SemanticChange {
        // Replaced below. kin-db refuses a change whose declared identity does
        // not recompute from its content, which is the store telling the truth
        // about itself and is why this cannot be a stub.
        id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
        origin: ChangeOrigin::Native,
        parents: Vec::new(),
        timestamp: fixed_timestamp(),
        author: AuthorId::new("fir2782-measurement"),
        message: format!("{index} {}", "x".repeat(CHANGE_MESSAGE_BYTES)),
        entity_deltas: Vec::new(),
        relation_deltas: Vec::new(),
        tree_deltas: Vec::new(),
        admission_policy_delta: None,
        external_reference_deltas: Vec::new(),
        projected_files: Vec::new(),
        spec_link: None,
        evidence: Vec::new(),
        risk_summary: None,
    };
    change.id = compute_semantic_change_id(&change).expect("synthetic change identifies");
    (change.id, change)
}

fn fixture() -> GraphSnapshot {
    let mut snapshot = GraphSnapshot::empty();
    for index in 0..ENTITIES {
        let entity = entity(index);
        snapshot.entities.insert(entity.id, entity);
    }
    for index in 0..RELATIONS {
        let (id, relation) = relation(index);
        snapshot.relations.insert(id, relation);
    }
    for index in 0..CHANGES {
        let (id, change) = change(index);
        snapshot.changes.insert(id, change);
    }
    for index in 0..ANNOTATIONS {
        let annotation_id = AnnotationId::new();
        snapshot.annotations.insert(
            annotation_id,
            Annotation {
                annotation_id,
                kind: AnnotationKind::Comment,
                body: "annotation payload ".repeat(ANNOTATION_BODY_BYTES / 19 + 1),
                scopes: vec![WorkScope::Entity(entity(index % ENTITIES).id)],
                anchored_fingerprint: None,
                authored_by: IdentityRef::human("fixture-author"),
                created_at: fixed_timestamp(),
                staleness: StalenessState::default(),
            },
        );
    }
    // A fixture that silently collapsed to one change would make the whole
    // export cheap and the ratio below meaningless.
    assert_eq!(
        snapshot.changes.len(),
        CHANGES,
        "every synthetic change must be distinct or this fixture prices nothing"
    );
    // And one that collapsed its relations would let an export that drops the
    // second compared domain pass the survival assertions below.
    assert_eq!(
        snapshot.entities.len(),
        ENTITIES,
        "every synthetic entity must be distinct or the survival check grades nothing"
    );
    assert_eq!(
        snapshot.relations.len(),
        RELATIONS,
        "every synthetic relation must be distinct or the survival check grades nothing"
    );
    assert_eq!(snapshot.annotations.len(), ANNOTATIONS);
    snapshot
}

/// The narrow export must stay a small fraction of the whole one.
///
/// Not a tight bound, deliberately. What it has to separate is a narrow export
/// from one that quietly copies unrelated stores. A regression through the
/// whole snapshot pays for the annotation payloads and lands near 100 percent.
const MAX_FACTS_SHARE_OF_SNAPSHOT: f64 = 0.25;

#[test]
fn exporting_the_compared_domains_does_not_pay_for_the_change_map() {
    let graph = InMemoryGraph::from_snapshot_without_text_index(fixture())
        .expect("build the fixture graph");

    // Warm both paths once so neither is charged for a first-touch allocation
    // the other already paid, then measure each on its own mark.
    drop(graph.workspace_graph_facts());
    drop(graph.to_snapshot());

    let whole = grown(|| graph.to_snapshot());
    let narrow = grown(|| graph.workspace_graph_facts());

    // Positive control first. A whole export that measured near nothing would
    // make any ratio below it pass, and that is the shape where this check
    // grades an instrument rather than the code.
    assert!(
        whole > ANNOTATIONS * ANNOTATION_BODY_BYTES,
        "the whole export must cost something measurable or this check grades \
         nothing: whole={whole} bytes"
    );
    assert!(
        narrow > 0,
        "the narrow export must allocate, or it is not exporting: narrow={narrow} bytes"
    );

    let share = narrow as f64 / whole as f64;
    println!(
        "whole export {:.1} MiB, narrow export {:.1} MiB, share {:.2}%",
        whole as f64 / 1_048_576.0,
        narrow as f64 / 1_048_576.0,
        share * 100.0,
    );
    assert!(
        share <= MAX_FACTS_SHARE_OF_SNAPSHOT,
        "workspace_graph_facts must not pay for the sub-stores a workspace \
         comparison never reads: narrow {:.1} MiB is {:.1}% of the whole export's \
         {:.1} MiB, over the {:.0}% line",
        narrow as f64 / 1_048_576.0,
        share * 100.0,
        whole as f64 / 1_048_576.0,
        MAX_FACTS_SHARE_OF_SNAPSHOT * 100.0,
    );

    // The facts must still carry what the comparison reads, or a narrow export
    // could pass the line above by exporting nothing at all. Both compared
    // domains are asserted, not just the first: an export that dropped
    // relations would satisfy a ratio bound and an entity count together while
    // silently handing the planner half a diff.
    let facts = graph.workspace_graph_facts();
    assert_eq!(
        facts.entities.len(),
        ENTITIES,
        "every entity the diff compares must survive the narrow export"
    );
    assert_eq!(
        facts.relations.len(),
        RELATIONS,
        "every relation the diff compares must survive the narrow export"
    );

    // The borrowing export must agree with the whole one on both domains, or
    // it is exporting a different graph rather than a cheaper view of the same
    // one. Counts alone cannot see a wrong-but-same-sized map.
    let whole_snapshot = graph.to_snapshot();
    assert_eq!(whole_snapshot.annotations.len(), ANNOTATIONS);
    assert!(whole_snapshot
        .annotations
        .values()
        .all(|annotation| annotation.body.len() >= ANNOTATION_BODY_BYTES));
    assert_eq!(
        facts.entities, whole_snapshot.entities,
        "the narrow export must agree with the whole export on entities"
    );
    assert_eq!(
        facts.relations, whole_snapshot.relations,
        "the narrow export must agree with the whole export on relations"
    );
}
