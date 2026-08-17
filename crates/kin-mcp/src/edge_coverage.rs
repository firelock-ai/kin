// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-file edge-class coverage: the substrate fact an absence claim needs.
//!
//! A reference query answers from typed `Calls`/`Imports`/`References` edges
//! that cross a file boundary. When the graph holds none of those for the
//! focal's language, the query is structurally unable to find anything, and an
//! empty result is a fact about the graph rather than about the code. Nothing in
//! the freshness/degraded signals reports that: a graph can be initialized,
//! loaded, fully embedded, undegraded, and still hold only intra-file edges.
//! That combination is what let `find_references` certify a symbol as unused
//! while a sibling file imported and called it.
//!
//! This module observes the fact directly and publishes it into the retrieval
//! payload under [`EDGE_COVERAGE_KEY`], where [`crate::negative`] consumes it as
//! a gate on `safe_to_conclude_absent`. The observation is a witness search, not
//! a census: proving a class of cross-file edge EXISTS needs one example, so a
//! healthy graph exits after a handful of lookups. A graph that holds none pays
//! a bounded scan and the budget is reported, because a scan cut short cannot
//! tell "absent" from "not reached" and must not be read as either.
//!
//! ## Published shape
//!
//! ```json
//! "edge_coverage": {
//!   "scope": "language",
//!   "language": "Python",
//!   "requested_classes": ["calls", "imports", "references"],
//!   "classes": { "calls": "present", "imports": "present", "references": "absent" },
//!   "cross_file_classes": ["calls", "imports"],
//!   "budget_exhausted": false,
//!   "entities_examined": 3
//! }
//! ```
//!
//! `classes` is the load-bearing field: `present` means a cross-file edge of
//! that class was observed for the focal's language, `absent` means the scan
//! completed and found none, `unknown` means the scan stopped on its budget
//! before it could say. A consumer that cannot find this object must treat
//! coverage as unknown rather than assuming either verdict.

use serde_json::{json, Map, Value};

use kin_model::entity::Entity;
use kin_model::graph::{EntityFilter, EntityStore};
use kin_model::ids::{EntityId, FilePathId};
use kin_model::relation::RelationKind;

/// Reserved, additive payload key carrying the cross-file edge-class
/// observation. Read by [`crate::negative`]; additive to every payload it is
/// attached to.
pub const EDGE_COVERAGE_KEY: &str = "edge_coverage";

/// How many entities may have their relations read while looking for a witness.
///
/// A healthy graph answers in single digits, so this bound is only reached on a
/// graph that holds no cross-file edges of the requested classes at all — the
/// case this module exists to detect. Reaching it reports `unknown` rather than
/// `absent`, so a truncated scan is never published as a verdict.
const WITNESS_BUDGET: usize = 4096;

/// One class's observed cross-file state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClassState {
    /// A cross-file edge of this class was observed for the focal's language.
    Present,
    /// The scan completed over the language's entities and observed none.
    Absent,
    /// The scan stopped on its budget before it could observe one.
    Unknown,
}

impl ClassState {
    fn as_str(self) -> &'static str {
        match self {
            ClassState::Present => "present",
            ClassState::Absent => "absent",
            ClassState::Unknown => "unknown",
        }
    }
}

/// The stable wire name for a relation kind.
///
/// Deliberately the same lowercase vocabulary the reference tools already
/// publish under `relation_kinds`, so a reader matching a class against the
/// query's own scope never has to case-fold between two spellings of one fact.
fn class_name(kind: RelationKind) -> &'static str {
    match kind {
        RelationKind::Calls => "calls",
        RelationKind::Imports => "imports",
        RelationKind::References => "references",
        _ => "other",
    }
}

/// Observe whether the graph holds cross-file edges of `kinds` for `focal`'s
/// language, as the additive object documented on this module.
///
/// The scan is scoped to the focal's language because extraction and enrichment
/// gaps are per-language: a store that links Rust calls cross-file and Python
/// calls not at all must not lend its Rust coverage to a Python absence. It is
/// not scoped to the focal's file, because a leaf file legitimately has no
/// cross-file edges and reading that as an extraction gap would make every
/// genuine absence inconclusive.
///
/// Errors are not propagated: a store that cannot answer leaves the classes
/// `unknown`, which is the conservative reading and the one a consumer already
/// has to handle. Failing the whole retrieval because a trust annotation could
/// not be computed would trade a qualified answer for no answer.
pub fn observe_cross_file_reference_coverage<S: EntityStore>(
    store: &S,
    focal: &Entity,
    kinds: &[RelationKind],
) -> Value {
    observe_cross_file_reference_coverage_for_languages(store, &[focal.language], kinds)
}

/// Observe cross-file coverage across every language a batch of focals spans.
///
/// A batch verdict covers all of them, so the weakest language governs: a class
/// counts as present only when it is present for every language in the batch.
/// Merging the other way would let one well-linked language certify absences for
/// a language whose edges were never produced, which is the same borrowed
/// authority the per-language scope exists to prevent.
pub fn observe_cross_file_reference_coverage_for_languages<S: EntityStore>(
    store: &S,
    languages: &[kin_model::ids::LanguageId],
    kinds: &[RelationKind],
) -> Value {
    let requested = requested_classes(kinds);
    let mut merged: Vec<(RelationKind, ClassState)> = requested
        .iter()
        .copied()
        .map(|kind| (kind, ClassState::Unknown))
        .collect();
    let mut examined_total = 0usize;
    let mut any_budget_exhausted = false;
    let mut observed_languages: Vec<kin_model::ids::LanguageId> = Vec::new();
    for language in languages {
        if observed_languages.contains(language) {
            continue;
        }
        observed_languages.push(*language);
    }

    for (index, language) in observed_languages.iter().enumerate() {
        let (states, examined, budget_exhausted) =
            observe_language(store, *language, &requested);
        examined_total += examined;
        any_budget_exhausted |= budget_exhausted;
        for (slot, (_, state)) in merged.iter_mut().zip(states.iter()) {
            slot.1 = if index == 0 {
                *state
            } else {
                weakest(slot.1, *state)
            };
        }
    }

    let mut classes = Map::new();
    for (kind, state) in &merged {
        classes.insert(class_name(*kind).to_string(), json!(state.as_str()));
    }
    let cross_file: Vec<&str> = merged
        .iter()
        .filter(|(_, state)| *state == ClassState::Present)
        .map(|(kind, _)| class_name(*kind))
        .collect();

    json!({
        "scope": "language",
        "language": observed_languages
            .iter()
            .map(|language| format!("{language:?}"))
            .collect::<Vec<_>>()
            .join(", "),
        "requested_classes": merged
            .iter()
            .map(|(kind, _)| class_name(*kind))
            .collect::<Vec<_>>(),
        "classes": Value::Object(classes),
        "cross_file_classes": cross_file,
        "budget_exhausted": any_budget_exhausted,
        "entities_examined": examined_total,
    })
}

/// The reference classes among `kinds`, in the order given. Other relation kinds
/// are dropped: containment and definition edges never cross a file boundary, so
/// including them would let an intra-file fact stand in for a cross-file one.
fn requested_classes(kinds: &[RelationKind]) -> Vec<RelationKind> {
    kinds
        .iter()
        .copied()
        .filter(|kind| {
            matches!(
                kind,
                RelationKind::Calls | RelationKind::Imports | RelationKind::References
            )
        })
        .collect()
}

/// The less-authoritative of two observations. `present` only survives when both
/// agree, and `absent` outranks `unknown` because a completed scan that found
/// nothing is a stronger statement than one that never finished.
fn weakest(left: ClassState, right: ClassState) -> ClassState {
    match (left, right) {
        (ClassState::Absent, _) | (_, ClassState::Absent) => ClassState::Absent,
        (ClassState::Unknown, _) | (_, ClassState::Unknown) => ClassState::Unknown,
        _ => ClassState::Present,
    }
}

/// Witness-search one language, returning each requested class's state, how many
/// entities were examined, and whether the search stopped on its budget.
fn observe_language<S: EntityStore>(
    store: &S,
    language: kin_model::ids::LanguageId,
    requested: &[RelationKind],
) -> (Vec<(RelationKind, ClassState)>, usize, bool) {
    let mut states: Vec<(RelationKind, ClassState)> = requested
        .iter()
        .copied()
        .map(|kind| (kind, ClassState::Unknown))
        .collect();

    let mut examined = 0usize;
    let mut budget_exhausted = false;

    if !states.is_empty() {
        match store.query_entities(&EntityFilter {
            languages: Some(vec![language]),
            ..EntityFilter::default()
        }) {
            Ok(candidates) => {
                let files: std::collections::HashMap<EntityId, Option<FilePathId>> = candidates
                    .iter()
                    .map(|entity| (entity.id, entity.file_origin.clone()))
                    .collect();
                for entity in &candidates {
                    if states
                        .iter()
                        .all(|(_, state)| *state == ClassState::Present)
                    {
                        break;
                    }
                    if examined >= WITNESS_BUDGET {
                        budget_exhausted = true;
                        break;
                    }
                    examined += 1;
                    let Ok(relations) = store.get_all_relations_for_entity(&entity.id) else {
                        continue;
                    };
                    for relation in relations {
                        let Some(state) = states
                            .iter_mut()
                            .find(|(kind, _)| *kind == relation.kind)
                            .map(|(_, state)| state)
                        else {
                            continue;
                        };
                        if *state == ClassState::Present {
                            continue;
                        }
                        let Some(source) = relation.src.as_entity() else {
                            continue;
                        };
                        let Some(destination) = relation.dst.as_entity() else {
                            continue;
                        };
                        let source_file = endpoint_file(store, &files, &source);
                        let destination_file = endpoint_file(store, &files, &destination);
                        if let (Some(source_file), Some(destination_file)) =
                            (source_file, destination_file)
                        {
                            if source_file != destination_file {
                                *state = ClassState::Present;
                            }
                        }
                    }
                }
                if !budget_exhausted {
                    for (_, state) in states.iter_mut() {
                        if *state == ClassState::Unknown {
                            *state = ClassState::Absent;
                        }
                    }
                }
            }
            // The store could not enumerate the language at all, so every class
            // stays unknown rather than being reported absent from a scan that
            // never ran.
            Err(_) => budget_exhausted = true,
        }
    }

    (states, examined, budget_exhausted)
}

/// The file an endpoint belongs to, preferring the language-scoped entities
/// already in hand and falling back to a direct lookup for an endpoint outside
/// that set (a cross-language edge still crosses a file boundary).
fn endpoint_file<S: EntityStore>(
    store: &S,
    files: &std::collections::HashMap<EntityId, Option<FilePathId>>,
    id: &EntityId,
) -> Option<FilePathId> {
    if let Some(file) = files.get(id) {
        return file.clone();
    }
    store.get_entity(id).ok().flatten().and_then(|entity| entity.file_origin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_model::entity::{
        EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        Visibility,
    };
    use kin_model::ids::{Hash256, LanguageId, RelationId};
    use kin_model::relation::{GraphNodeId, Relation, RelationOrigin};

    fn entity(name: &str, file: &str, language: LanguageId) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: None,
            signature: format!("def {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn relation(src: EntityId, dst: EntityId, kind: RelationKind) -> Relation {
        Relation {
            id: RelationId::new(),
            kind,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    /// The FIR-2353 shape: entities and intra-file edges only. Every requested
    /// class reads `absent`, which is what makes the absence claim unearned.
    #[test]
    fn an_intra_file_only_graph_reports_every_class_absent() {
        let store = InMemoryGraph::new();
        let caller = entity("save_note", "nk/storage.py", LanguageId::Python);
        let target = entity("parse_note", "nk/parsing.py", LanguageId::Python);
        let sibling = entity("helper", "nk/storage.py", LanguageId::Python);
        store.upsert_entity(&caller).unwrap();
        store.upsert_entity(&target).unwrap();
        store.upsert_entity(&sibling).unwrap();
        store
            .upsert_relation(&relation(caller.id, sibling.id, RelationKind::Calls))
            .unwrap();

        let coverage = observe_cross_file_reference_coverage(
            &store,
            &target,
            &[
                RelationKind::Calls,
                RelationKind::Imports,
                RelationKind::References,
            ],
        );
        assert_eq!(coverage["classes"]["calls"], json!("absent"));
        assert_eq!(coverage["classes"]["imports"], json!("absent"));
        assert_eq!(coverage["classes"]["references"], json!("absent"));
        assert_eq!(coverage["cross_file_classes"], json!([]));
        assert_eq!(coverage["budget_exhausted"], json!(false));
    }

    /// One cross-file witness of a class is enough to report it present, and the
    /// classes without one stay separately reported rather than being lifted by
    /// their sibling.
    #[test]
    fn a_cross_file_witness_reports_only_its_own_class_present() {
        let store = InMemoryGraph::new();
        let caller = entity("save_note", "nk/storage.py", LanguageId::Python);
        let target = entity("parse_note", "nk/parsing.py", LanguageId::Python);
        store.upsert_entity(&caller).unwrap();
        store.upsert_entity(&target).unwrap();
        store
            .upsert_relation(&relation(caller.id, target.id, RelationKind::Calls))
            .unwrap();

        let coverage = observe_cross_file_reference_coverage(
            &store,
            &target,
            &[RelationKind::Calls, RelationKind::Imports],
        );
        assert_eq!(coverage["classes"]["calls"], json!("present"));
        assert_eq!(coverage["classes"]["imports"], json!("absent"));
        assert_eq!(coverage["cross_file_classes"], json!(["calls"]));
    }

    /// Coverage is language-scoped: a store that links one language's calls
    /// cross-file must not lend that coverage to a focal of another language,
    /// which is exactly the per-language enrichment gap the ticket describes.
    #[test]
    fn coverage_does_not_cross_the_language_boundary() {
        let store = InMemoryGraph::new();
        let rust_caller = entity("dispatch", "src/a.rs", LanguageId::Rust);
        let rust_callee = entity("handle", "src/b.rs", LanguageId::Rust);
        let python_target = entity("parse_note", "nk/parsing.py", LanguageId::Python);
        store.upsert_entity(&rust_caller).unwrap();
        store.upsert_entity(&rust_callee).unwrap();
        store.upsert_entity(&python_target).unwrap();
        store
            .upsert_relation(&relation(
                rust_caller.id,
                rust_callee.id,
                RelationKind::Calls,
            ))
            .unwrap();

        let rust = observe_cross_file_reference_coverage(
            &store,
            &rust_callee,
            &[RelationKind::Calls],
        );
        assert_eq!(rust["classes"]["calls"], json!("present"));

        let python = observe_cross_file_reference_coverage(
            &store,
            &python_target,
            &[RelationKind::Calls],
        );
        assert_eq!(python["classes"]["calls"], json!("absent"));
    }

    /// An intra-file edge is not a witness. Without this the FIR-2353 graph,
    /// whose only Calls edges sat inside one file, would have reported the class
    /// present and re-certified the absence it was meant to disqualify.
    #[test]
    fn an_intra_file_edge_is_not_a_cross_file_witness() {
        let store = InMemoryGraph::new();
        let first = entity("outer", "nk/parsing.py", LanguageId::Python);
        let second = entity("inner", "nk/parsing.py", LanguageId::Python);
        store.upsert_entity(&first).unwrap();
        store.upsert_entity(&second).unwrap();
        store
            .upsert_relation(&relation(first.id, second.id, RelationKind::Calls))
            .unwrap();

        let coverage =
            observe_cross_file_reference_coverage(&store, &first, &[RelationKind::Calls]);
        assert_eq!(coverage["classes"]["calls"], json!("absent"));
    }
}
