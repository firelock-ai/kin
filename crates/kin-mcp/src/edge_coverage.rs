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
//!   "reference_enrichment": "unknown",
//!   "budget_exhausted": false,
//!   "entities_examined": 3,
//!   "limits": ["completeness:inconclusive"]
//! }
//! ```
//!
//! `limits` names the inputs that stop this block licensing a certification on
//! its own, in the same vocabulary `_kin.completeness.limits` uses, and is
//! absent when it licenses on its own. A block can report every requested class
//! as present while the answer around it is not whole, and reading the classes
//! without the limits is how one response comes to carry two verdicts. The list
//! is stamped by the one verdict computation, which is the only place holding
//! every input, so this block and the verdict cannot drift.
//!
//! `classes` is the load-bearing field: `present` means a cross-file edge of
//! that class was observed for the focal's language, `absent` means the scan
//! completed and found none, `unknown` means the scan stopped on its budget
//! before it could say, and `unproduced` means the scan completed, observed no
//! entity-rooted edge of that class at all, and the language's own parse side
//! shows sites of the class the linker resolved into no entity-level edge, so
//! the gap is in the build rather than in the code. Every state but `present`
//! makes the response's one verdict inconclusive (FIR-2672): a class the answer
//! could not have read is a class its counts cannot be whole over, whatever the
//! reason. A consumer that cannot find this object must treat coverage as
//! unknown rather than assuming either verdict.
//!
//! `reference_enrichment` carries the one fact the scan cannot observe from the
//! graph: whether this BUILD can produce reference edges for the language at
//! all. See [`reference_enrichment`].
//!
//! The single-focal tools attach it to an EMPTY answer only, since that is the
//! only answer whose trust depends on it: one that returned rows proved the
//! edges exist by returning them. The batch tool attaches it always, because its
//! per-entity `has_references: false` rows are absences inside a populated
//! response.

use serde_json::{json, Map, Value};

use kin_core::reference_coverage::{
    reference_enrichment_for, LanguageServerReadinessMap, ReferenceEnrichment, ENRICHABLE_LANGUAGES,
};
use kin_model::entity::Entity;
use kin_model::graph::{EntityFilter, EntityStore};
use kin_model::ids::{EntityId, FilePathId, LanguageId};
use kin_model::relation::RelationKind;

/// Reserved, additive payload key carrying the cross-file edge-class
/// observation. Read by [`crate::negative`]; additive to every payload it is
/// attached to.
pub const EDGE_COVERAGE_KEY: &str = "edge_coverage";

/// Key inside the observation carrying the parsed-versus-resolved reading for
/// the focal's language, when one could be measured. Read by
/// [`crate::envelope::Completeness`] so a partial answer can say "1 of 5"
/// instead of an unqualified "1".
pub const REFERENCE_RESOLUTION_KEY: &str = "reference_resolution";

/// Key inside the observation carrying what the query's NAME FILTER selected on
/// its own, for an answer whose narrowing filters could have emptied it. Read by
/// [`crate::negative`].
pub const NAME_FILTER_KEY: &str = "name_filter";

/// What the `language` field reads when the answer resolved no entity to take a
/// language from, so the observation names the absence rather than guessing one.
///
/// Shared with [`crate::negative`], which has to be able to tell an observation
/// about a real language from one about none: a gap sentence naming a language's
/// extractor coverage answers a question nobody asked when no language was
/// named, and displaces the reason the reader actually needs.
pub const NO_RESOLVED_LANGUAGE: &str = "no resolved language";

/// How many entities may have their relations read while looking for a witness.
///
/// A healthy graph answers in single digits, so this bound is only reached on a
/// graph that holds no cross-file edges of the requested classes at all, which is
/// the case this module exists to detect. Reaching it reports `unknown` rather than
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
    /// The scan completed, observed no entity-rooted edge of this class at all,
    /// and the language's parse side shows sites of the class that the linker
    /// resolved into no entity-level edge.
    ///
    /// Not `Absent`, because `Absent` reads as a completed observation about the
    /// code, and this is a completed observation about the build: the sites are
    /// in the source, the linker saw them (an import it resolved at the artifact
    /// level, a call site it counted), and no entity-level edge came out. The
    /// rc0552s stranger's account of FIR-2672 rests on Kin having called that
    /// `absent` for import sites no build had ever emitted an edge for. Not
    /// `Unknown` either, because nothing was left unread; the scan finished.
    Unproduced,
}

impl ClassState {
    fn as_str(self) -> &'static str {
        match self {
            ClassState::Present => "present",
            ClassState::Absent => "absent",
            ClassState::Unknown => "unknown",
            ClassState::Unproduced => "unproduced",
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
    observe_cross_file_reference_coverage_witnessed(store, focal, kinds, &[])
}

/// [`observe_cross_file_reference_coverage`], told which classes the ANSWER
/// itself already proved.
///
/// The observation is now attached to populated answers too (FIR-2357 item 1),
/// because an answer that returned one row proved one edge exists and proved
/// nothing about the class a missing caller would have come through. That is
/// the founding case exactly: a single intra-file caller came back for a symbol
/// five call sites reached, and the classes carrying the other four were absent.
///
/// Paying a full language scan on every populated answer would be a real cost
/// for a fact the answer often already carries, so a caller that holds a
/// cross-file row of class K passes K here and the scan is spared. A witness
/// only ever raises a class from `unknown` to `present`; it never overturns a
/// completed scan that observed one absent, so a witness the caller scoped
/// wrongly can slow this down but cannot make it certify anything.
///
/// The caller's contract: pass a class only for an edge whose two endpoints sit
/// in different files and whose source entity carries the focal's language,
/// which is the same thing the scan below looks for.
pub fn observe_cross_file_reference_coverage_witnessed<S: EntityStore>(
    store: &S,
    focal: &Entity,
    kinds: &[RelationKind],
    witnessed: &[RelationKind],
) -> Value {
    let mut observation = observe_cross_file_reference_coverage_for_languages_witnessed(
        store,
        &[focal.language],
        kinds,
        witnessed,
    );
    attach_reference_resolution(store, focal.language, &mut observation);
    observation
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
    observe_cross_file_reference_coverage_for_languages_witnessed(store, languages, kinds, &[])
}

/// [`observe_cross_file_reference_coverage_for_languages`] with the answer's own
/// witnesses, as documented on
/// [`observe_cross_file_reference_coverage_witnessed`].
pub fn observe_cross_file_reference_coverage_for_languages_witnessed<S: EntityStore>(
    store: &S,
    languages: &[kin_model::ids::LanguageId],
    kinds: &[RelationKind],
    witnessed: &[RelationKind],
) -> Value {
    let requested = requested_classes(kinds);
    let witnessed: Vec<RelationKind> = requested
        .iter()
        .copied()
        .filter(|kind| witnessed.contains(kind))
        .collect();
    let mut merged: Vec<(RelationKind, ClassState)> = requested
        .iter()
        .copied()
        .map(|kind| {
            let state = if witnessed.contains(&kind) {
                ClassState::Present
            } else {
                ClassState::Unknown
            };
            (kind, state)
        })
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

    // Computed before the skip decision, because it is one of the two facts that
    // decides which classes the verdict rests on. It is reused verbatim below,
    // so the state the skip reasoned about and the state the payload publishes
    // can never be two different readings.
    let enrichment = reference_enrichment(&observed_languages);
    let references_producible = enrichment.as_str() == Some("available");

    // The scan exists to decide the classes the verdict rests on. When the
    // answer already carried a witness for every one of them, running it buys a
    // disclosure about classes nothing decides and costs a language-wide relation
    // walk on the populated path, where there was no scan at all before.
    //
    // `references` joins that deciding set exactly when this host could have
    // produced it, which is the same condition
    // [`crate::negative::absence_coverage_gap`] now gates a certification on.
    // Leaving it out here would have left that gate a bypass on one of the two
    // surfaces it was written for: `get_context_pack` passes the witnesses its
    // own rows carry, so a pack whose dependents group witnessed one cross-file
    // `Calls` edge skipped the scan, published `references: unknown` instead of
    // `absent`, and certified on a class nothing had measured. A gate that only
    // fires when a scan happened to run is not a gate.
    let scan_needed = !deciding_classes_all_present(&merged, references_producible);
    let mut unproduced_evidence = Map::new();
    if scan_needed {
        let mut scans: Vec<LanguageScan> = Vec::new();
        for (index, language) in observed_languages.iter().enumerate() {
            let scan = observe_language(store, *language, &requested);
            examined_total += scan.examined;
            any_budget_exhausted |= scan.budget_exhausted;
            for (slot, (_, state)) in merged.iter_mut().zip(scan.states.iter()) {
                slot.1 = if index == 0 {
                    *state
                } else {
                    weakest(slot.1, *state)
                };
            }
            scans.push(scan);
        }
        // A witness raises `unknown` to `present` and stops there. A scan that
        // ran to completion and observed a class absent is a stronger statement
        // than one row's provenance, so a caller that scoped its witness wrongly
        // can cost this a scan it did not need but can never buy an absence a
        // certification would rest on.
        for (kind, state) in merged.iter_mut() {
            if *state == ClassState::Unknown && witnessed.contains(kind) {
                *state = ClassState::Present;
            }
        }
        // A class every scan completed empty on, with no entity-rooted edge of
        // it seen anywhere, is `unproduced` rather than `absent` when the parse
        // side shows the linker had sites of that class to resolve. The two must
        // not share a word: `absent` is a statement about the code and this is
        // a statement about the build (FIR-2672).
        for (kind, state) in merged.iter_mut() {
            if *state != ClassState::Absent {
                continue;
            }
            if let Some(evidence) = unproduced_evidence_for(*kind, &scans) {
                *state = ClassState::Unproduced;
                unproduced_evidence.insert(class_name(*kind).to_string(), evidence);
            }
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

    // A batch that resolved no entity has no language to scope an observation to,
    // and an empty string would read as one. Naming the absence keeps the reason
    // it produces readable.
    let language = if observed_languages.is_empty() {
        NO_RESOLVED_LANGUAGE.to_string()
    } else {
        observed_languages
            .iter()
            .map(|language| format!("{language:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    };

    json!({
        "scope": "language",
        "language": language,
        "requested_classes": merged
            .iter()
            .map(|(kind, _)| class_name(*kind))
            .collect::<Vec<_>>(),
        "classes": Value::Object(classes),
        "cross_file_classes": cross_file,
        "reference_enrichment": enrichment,
        "budget_exhausted": any_budget_exhausted,
        "entities_examined": examined_total,
        // How each verdict was reached, because "present" from a witness the
        // answer carried and "present" from a completed scan are the same word
        // for two different amounts of evidence.
        "witnessed_by_answer": witnessed
            .iter()
            .map(|kind| class_name(*kind))
            .collect::<Vec<_>>(),
        "scan": if scan_needed {
            "ran"
        } else {
            "skipped_answer_witnessed"
        },
        // Why a class reads `unproduced`: the parse-side and artifact-level
        // counts that separate a build gap from an unused feature of the code.
        // Absent when no class was raised, so a reader never sees evidence for a
        // verdict that was not reached.
        "unproduced_evidence": if unproduced_evidence.is_empty() {
            Value::Null
        } else {
            Value::Object(unproduced_evidence)
        },
    })
}

/// The evidence that raises one class every language's scan completed empty on
/// from `absent` to `unproduced`, or `None` when the code simply carries no such
/// sites.
///
/// `imports`: no entity-rooted `Imports` relation was seen in any scan, and the
/// linker demonstrably had import statements to resolve, either because it
/// resolved some at the artifact level (the only level the linker emitted at
/// before the entity-level emitter existed) or because the parse side counted
/// statements naming modules inside this repository. A language whose specifier
/// syntax cannot settle externality counts only the first, so a repository that
/// imports nothing but its standard library is not called a build gap.
///
/// `calls`: no entity-rooted `Calls` relation was seen in any scan, and every
/// file of the language recorded a call-site count whose sum is above zero. A
/// partial measurement is not evidence, for the reason
/// [`kin_core::reference_coverage::CallSiteMeasurement`] spells out.
///
/// `references` is never raised here: whether this build can produce that class
/// is a fact about the language server, and `reference_enrichment` already
/// carries it.
fn unproduced_evidence_for(kind: RelationKind, scans: &[LanguageScan]) -> Option<Value> {
    if scans.is_empty()
        || scans
            .iter()
            .any(|scan| scan.budget_exhausted || scan.seen_any(kind))
    {
        return None;
    }
    match kind {
        RelationKind::Imports => {
            let artifact_edges: u64 = scans.iter().map(|scan| scan.artifact_import_edges).sum();
            let parsed: u64 = scans
                .iter()
                .filter_map(|scan| scan.parsed_import_statements)
                .sum();
            let internal: u64 = scans
                .iter()
                .filter_map(|scan| scan.parsed_internal_import_statements())
                .sum();
            if artifact_edges == 0 && internal == 0 {
                return None;
            }
            Some(json!({
                "parsed_import_statements": parsed,
                "parsed_internal_import_statements": internal,
                "artifact_level_import_edges": artifact_edges,
                "entity_level_import_edges": 0,
            }))
        }
        RelationKind::Calls => {
            let complete = scans.iter().all(|scan| scan.call_sites_complete);
            let parsed: u64 = scans.iter().filter_map(|scan| scan.parsed_call_sites).sum();
            if !complete || parsed == 0 {
                return None;
            }
            Some(json!({
                "parsed_call_sites": parsed,
                "entity_level_call_edges": 0,
            }))
        }
        _ => None,
    }
}

/// Observe the language scope an absence claim covers, for a tool that
/// traverses no edge to make it.
///
/// `semantic_search`, `find_dead_code_seeded` and `graph_neighborhood` answer
/// from the entity index and the walk, not from a cross-file reference class, so
/// the witness scan above measures nothing their verdict rests on. What their
/// verdict does rest on is which languages the claim spans and whether this
/// build can resolve their programs, which is the one fact
/// [`reference_enrichment`] already answers. Publishing it under the same key
/// the reference tools publish means one gate reads one observation rather than
/// two shapes drifting apart.
///
/// `classes` is deliberately empty rather than absent: this observation asserts
/// nothing about cross-file edges, and a class map full of `unknown` would read
/// as a scan that failed instead of one that was never the question.
///
/// `scope_entities` is the count of entities the query's own filter selects with
/// its name pattern removed, so a kind-filtered absence can state the coverage
/// of that kind. `None` leaves it out entirely, because a region nothing counted
/// is unknown rather than empty. A resolved count of zero says the filter
/// selected a region the index never populated, which is a fact about the index.
pub fn observe_absence_scope(languages: &[LanguageId], scope_entities: Option<usize>) -> Value {
    let mut observed: Vec<LanguageId> = Vec::new();
    for language in languages {
        if !observed.contains(language) {
            observed.push(*language);
        }
    }
    let language = if observed.is_empty() {
        NO_RESOLVED_LANGUAGE.to_string()
    } else {
        observed
            .iter()
            .map(|language| format!("{language:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut observation = json!({
        "scope": "absence_scope",
        "language": language,
        "requested_classes": Vec::<&str>::new(),
        "classes": Map::new(),
        "cross_file_classes": Vec::<&str>::new(),
        "reference_enrichment": reference_enrichment(&observed),
        "budget_exhausted": false,
        "entities_examined": 0,
        "scan": "skipped_no_edge_dependency",
    });
    if let Some(count) = scope_entities {
        observation["scope_entities"] = json!(count);
    }
    observation
}

/// Record what the query's NAME FILTER selected on its own, beside the scope
/// [`observe_absence_scope`] already measured.
///
/// The two counts answer different questions and an absence needs both. The
/// scope count removes the NAME and keeps the narrowing filters, so it says
/// whether the region the caller asked about is populated at all. This one
/// removes the NARROWING FILTERS and keeps the name, so it says whether the name
/// resolved to anything before those filters were applied.
///
/// Only the second can see the case FIR-2452 was filed for. On psf/requests,
/// `semantic_search(query: "request", kind: "method")` answered zero while the
/// scope held every method in the repository and Python is a language this build
/// enriches, so every gate that existed read healthy and the answer certified
/// `safe_to_conclude_absent: true` about a name the graph resolves. What
/// actually happened is visible only from the name's own side: the store's
/// pattern index returns its exact-name and token hits and returns EARLY on any
/// hit, never reaching its substring fallback, and the kind predicate then
/// removed every candidate it had returned. That is absence of a MATCH, and the
/// observation has to carry it before the gate can refuse to call it absence of
/// a THING.
///
/// `narrowed_by` names the filters that were applied, so the verdict can say
/// which ones removed the candidates rather than reporting an unattributed miss.
/// Attached only when a narrowing filter was actually applied: with none, this
/// query IS the name query and a second count would restate the first.
pub fn attach_name_filter_scope(observation: &mut Value, narrowed_by: &[&str], candidates: usize) {
    observation[NAME_FILTER_KEY] = json!({
        "narrowed_by": narrowed_by,
        "candidates": candidates,
    });
}

/// The distinct languages a resolved entity set spans, in first-seen order.
pub fn languages_of(entities: &[Entity]) -> Vec<LanguageId> {
    let mut languages: Vec<LanguageId> = Vec::new();
    for entity in entities {
        if !languages.contains(&entity.language) {
            languages.push(entity.language);
        }
    }
    languages
}

/// Whether every class the absence verdict rests on is already `present`.
///
/// Every requested class, through [`crate::negative::deciding_classes`]. This
/// used to be narrowed to `calls` on the grounds that Kin minted no entity-level
/// `Imports` edge and a rule waiting for every class would never skip a scan.
/// That narrowing is what let the verdict certify over `imports: absent`
/// (FIR-2672); a scan that runs whenever a requested class is unwitnessed is
/// the price of a verdict that means what it says, and it is bounded by
/// [`WITNESS_BUDGET`].
/// [`deciding_classes_all_present`], asked of a PUBLISHED observation.
///
/// The private form above reads the scan's own working state and decides
/// whether a scan is still needed. This form reads the object that scan
/// published, so a producer that has to state a per-hop fact ("is this empty
/// read a leaf, or a graph that could not have held the hop") reaches the same
/// verdict [`crate::negative::absence_coverage_gap`] will reach over the same
/// payload. Two rules for one question is exactly how a chain came to say
/// `truncated: false` beside an envelope saying coverage was never reported.
///
/// A missing or malformed observation is `false`: unmeasured coverage is the
/// unknown case, not the healthy one, which is the reading the whole module
/// already takes.
pub fn deciding_classes_observed_present(observation: &Value) -> bool {
    let Some(observation) = observation.as_object() else {
        return false;
    };
    let requested: Vec<String> = observation
        .get("requested_classes")
        .and_then(Value::as_array)
        .map(|classes| {
            classes
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let references_producible = observation
        .get("reference_enrichment")
        .and_then(Value::as_str)
        == Some("available");
    let deciding = crate::negative::deciding_classes(&requested, references_producible);
    if deciding.is_empty() {
        return false;
    }
    let states = observation.get("classes").and_then(Value::as_object);
    deciding.iter().all(|class| {
        states
            .and_then(|states| states.get(class.as_str()))
            .and_then(Value::as_str)
            == Some("present")
    })
}

fn deciding_classes_all_present(
    merged: &[(RelationKind, ClassState)],
    references_producible: bool,
) -> bool {
    let requested: Vec<String> = merged
        .iter()
        .map(|(kind, _)| class_name(*kind).to_string())
        .collect();
    let deciding = crate::negative::deciding_classes(&requested, references_producible);
    if deciding.is_empty() {
        return false;
    }
    deciding.iter().all(|class| {
        merged
            .iter()
            .any(|(kind, state)| class_name(*kind) == class && *state == ClassState::Present)
    })
}

/// Attach the parsed-versus-resolved reading for `language` when the observation
/// says a deciding class was not available (FIR-2357 item 2).
///
/// This is the count side of the completeness contract. `kin graph status`
/// already reports it per language through
/// [`kin_core::reference_coverage`], and that shipped measurement is reused here
/// rather than re-derived, because two counters for one fact is precisely how a
/// coverage figure and a coverage verdict come to disagree inside one response.
///
/// Scoped to the focal's language, which makes exactly the fields this reads
/// exact: `parsed_call_sites` and `parsed_import_statements` are tallied off
/// entities of that language, `resolved_call_edges` off their outgoing
/// relations, and `resolved_import_statements` off each file's coverage
/// certificate, which is the only place a statement count exists. The
/// cross-file, intra-file and external split is
/// NOT read here, because classifying a target requires the target's own entity
/// and a language-scoped list does not carry targets in other languages, which
/// would report a cross-language edge as external.
///
/// Attached only when `calls` or `references` is short, so a healthy answer pays
/// nothing for a ratio it does not need, and a shortfall gets the number that
/// says how big it is. An `imports` shortfall alone does not trigger the whole
/// language walk this costs: the scan already published the import counts that
/// decided it under `unproduced_evidence`, and until the entity-level import
/// emitter lands that shortfall is every populated answer on every language.
fn attach_reference_resolution<S: EntityStore>(
    store: &S,
    language: LanguageId,
    observation: &mut Value,
) {
    let already_covered = observation
        .get("classes")
        .and_then(Value::as_object)
        .map(|classes| {
            classes
                .iter()
                .filter(|(class, _)| class.as_str() != "imports")
                .all(|(_, state)| state.as_str() == Some(ClassState::Present.as_str()))
        })
        .unwrap_or(false);
    if already_covered {
        return;
    }

    let Ok(entities) = store.query_entities(&EntityFilter {
        languages: Some(vec![language]),
        ..EntityFilter::default()
    }) else {
        return;
    };
    let Ok(coverage) =
        kin_core::reference_coverage::collect_reference_edge_coverage_from(store, &entities)
    else {
        return;
    };
    let Some(measured) = coverage
        .languages
        .into_iter()
        .find(|entry| entry.language == language.to_string())
    else {
        return;
    };

    // No `language` key here on purpose. The observation names the language one
    // level up, and `kin_core` spells it lowercase where this object spells it
    // capitalised, so carrying both would put two spellings of one fact inside
    // one response for a reader to reconcile.
    observation[REFERENCE_RESOLUTION_KEY] = json!({
        "files": measured.files,
        "files_measured": measured.files_measured,
        // `null` when no file of this language carries a parse-side count. An
        // unmeasured parse side is not a zero, and publishing it as one would
        // turn "nothing counted the source" into "the source had no calls".
        "parsed_call_sites": measured.parsed_call_sites,
        "resolved_call_edges": measured.resolved_call_edges,
        "call_percent": measured.call_percent(),
        "parsed_import_statements": measured.parsed_import_statements,
        // `null` when no file of this language carried a coverage certificate,
        // which is the only place the resolved-statement count exists. An
        // unmeasured resolution is not a zero, and the wire says so rather than
        // publishing a number drawn from a different population.
        "resolved_import_statements": measured.resolved_import_statements,
        "resolution": measured.resolution.label(),
    });
}

/// Whether this build can produce cross-file reference and override edges for
/// the observed languages at all.
///
/// `Calls` and `Imports` fall out of a single-file parse plus the linker, so the
/// witness scan above can say whether this graph holds them. `References` cannot
/// be derived that way: it needs a resolved program from a language server, and
/// this build wires an adapter for exactly [`ENRICHABLE_LANGUAGES`]. For every
/// other language the class can never exist no matter what the host has
/// installed, which is a different fact from "the scan found none" and one the
/// trust gate has to be able to read: an absence over a language whose reference
/// edges are unproducible cannot be certified by any amount of scanning.
///
/// A wired adapter is only half of it, and this used to publish only that half.
/// Whether a server is actually installed is a HOST fact, and it decides the
/// same question: on a host with none, nothing resolves the program behind the
/// declarations, exactly as on a build that wires no adapter. Publishing
/// `Unknown` for every wired language made the trust gate read "nobody checked"
/// as "fine", so a Python absence was certified as authoritative on a host that
/// could not have produced a single reference edge.
///
/// That was survivable only because the wired set was small and the gate's other
/// half happened to catch the case people hit. It stopped being survivable when
/// JavaScript and TypeScript were wired: the express-shaped absence FIR-2430
/// blocked, with the advice "safe to treat the target as genuinely absent", went
/// straight back to certifying because the build limit had lifted while the host
/// limit had not.
///
/// So the host is not probed here at all; the readiness a process with the right
/// to spawn already established is read instead. The weakest language governs,
/// matching how the class states above merge: one unsupported language in a
/// batch makes the batch's reference evidence unproducible, and one missing or
/// unusable server makes it unproduced.
fn reference_enrichment(languages: &[LanguageId]) -> Value {
    let Some(servers) = published_language_servers() else {
        // Nobody published the host state, so nothing is established about any
        // language's server. Still report the build limit, which is knowable
        // from this process alone and is what makes an unwired language's
        // absence uncertifiable.
        return json!(build_only_reference_enrichment(languages));
    };
    json!(weakest_reference_enrichment(languages, &servers))
}

/// What is knowable without the host: whether this build wires an adapter.
fn build_only_reference_enrichment(languages: &[LanguageId]) -> ReferenceEnrichment {
    if languages
        .iter()
        .any(|language| !ENRICHABLE_LANGUAGES.contains(language))
    {
        ReferenceEnrichment::Unsupported
    } else {
        ReferenceEnrichment::Unknown
    }
}

/// [`reference_enrichment`] with the host state given rather than probed.
///
/// Split out so a test states the whole environment it is asserting against. A
/// test that inherited the developer's `PATH` would assert something different
/// on a laptop with pyright than on a runner without it, and the version that
/// silently stops checking is the one that runs in CI.
fn weakest_reference_enrichment(
    languages: &[LanguageId],
    readiness: &LanguageServerReadinessMap,
) -> ReferenceEnrichment {
    languages
        .iter()
        .map(|language| reference_enrichment_for(*language, readiness))
        .min_by_key(|state| match state {
            // Weakest first: an unproducible class outranks an unproduced one,
            // which outranks an unread one, which outranks a working server.
            ReferenceEnrichment::Unsupported => 0,
            ReferenceEnrichment::NoLanguageServer => 1,
            // A server that is present and cannot start produces exactly as
            // many edges as one that is absent, so it ranks beside it and well
            // below "nobody looked".
            ReferenceEnrichment::LanguageServerUnusable => 2,
            ReferenceEnrichment::Unknown => 3,
            ReferenceEnrichment::Available => 4,
        })
        .unwrap_or(ReferenceEnrichment::Unknown)
}

/// Which languages have an enrichment server on this host, as PUBLISHED by the
/// process that knows, or `None` when nobody published it.
///
/// Deliberately not a `PATH` probe taken here. Reading the host from inside a
/// query function makes every answer, and every test of one, depend on the
/// machine it runs on: the same assertion passes on a laptop carrying pyright
/// and fails on a runner without it, and a local gate goes green for a reason
/// that has nothing to do with the change under test. That is not hypothetical.
/// It is how `daemon_mcp_bulk_reachability_uses_exact_federated_authority`
/// passed here and failed in CI on the first attempt at this.
///
/// The daemon publishes it once at startup, which is the same moment it decides
/// whether to open its enrichment channel at all, so the value a query reads is
/// the same fact the enrichment path acted on. Unpublished reads as unknown, and
/// unknown establishes nothing, which is the conservative reading this module
/// takes everywhere else.
fn published_language_servers() -> Option<LanguageServerReadinessMap> {
    #[cfg(test)]
    if let Some(servers) = test_support::server_override() {
        return Some(servers);
    }
    PUBLISHED_SERVERS
        .read()
        .ok()
        .and_then(|servers| servers.clone())
}

static PUBLISHED_SERVERS: std::sync::RwLock<Option<LanguageServerReadinessMap>> =
    std::sync::RwLock::new(None);

/// Publish what each language's enrichment server can actually do on this host.
///
/// Published by the process that probed, because deciding this needs a server
/// started and a query path must not spawn subprocesses. Until it is called,
/// every observation reports its languages' enrichment as unknown and the
/// absence-trust gate stays silent about it, which is the behaviour a process
/// that never looked should have, and is also the honest state while a probe is
/// still in flight.
///
/// Readiness rather than a set of installed binaries: a binary on `PATH` is not
/// a working language server, and publishing presence as though it were is how
/// an absence came to be certified on evidence the host could not gather.
/// The readiness a process with the right to spawn already established, or
/// `None` when nobody has published yet.
///
/// Exposed so a query path can READ the verdict instead of probing the host
/// itself. `None` is not an empty host: it means nothing looked, and a caller
/// must leave its rows unknown rather than reporting servers missing.
pub fn published_language_server_readiness() -> Option<LanguageServerReadinessMap> {
    published_language_servers()
}

pub fn publish_language_server_readiness(readiness: LanguageServerReadinessMap) {
    if let Ok(mut slot) = PUBLISHED_SERVERS.write() {
        *slot = Some(readiness);
    }
}

/// Lets a test state which language servers its host has.
///
/// Without this every assertion about enrichment would inherit the developer's
/// `PATH`: the same test would assert one thing on a laptop carrying pyright and
/// another on a runner without it, and the version that quietly stops checking
/// is the one that runs in CI. The override is thread-local, so it holds for the
/// test that set it whether the suite runs threaded under `cargo test` or one
/// process per test under nextest.
#[cfg(test)]
pub(crate) mod test_support {
    use super::{LanguageId, LanguageServerReadinessMap};
    use kin_core::reference_coverage::LanguageServerReadiness;
    use std::cell::RefCell;

    thread_local! {
        static SERVERS: RefCell<Option<LanguageServerReadinessMap>> = const { RefCell::new(None) };
    }

    pub(crate) fn server_override() -> Option<LanguageServerReadinessMap> {
        SERVERS.with(|servers| servers.borrow().clone())
    }

    /// Restores the previous host on drop, including on unwind, so one test's
    /// environment never leaks into the next on a reused thread.
    pub(crate) struct HostGuard(Option<LanguageServerReadinessMap>);

    impl Drop for HostGuard {
        fn drop(&mut self) {
            SERVERS.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }

    /// Declare, for the rest of this scope, that the host carries exactly
    /// `servers`, all of them usable. Bind the guard: dropping it immediately
    /// restores the host.
    #[must_use = "binding the guard is what keeps the declared host in force"]
    pub(crate) fn scoped_language_servers(servers: &[LanguageId]) -> HostGuard {
        scoped_language_server_readiness(
            &servers
                .iter()
                .map(|language| (*language, LanguageServerReadiness::Usable))
                .collect::<Vec<_>>(),
        )
    }

    /// Declare a host in the three-state vocabulary, so a test can state that a
    /// server is PRESENT AND UNUSABLE rather than only present or absent.
    ///
    /// That case is the one this whole area exists for and the one a
    /// presence-only override could not express, which meant no test could fail
    /// when a broken server was reported as serving.
    #[must_use = "binding the guard is what keeps the declared host in force"]
    pub(crate) fn scoped_language_server_readiness(
        readiness: &[(LanguageId, LanguageServerReadiness)],
    ) -> HostGuard {
        HostGuard(SERVERS.with(|slot| {
            slot.borrow_mut()
                .replace(readiness.iter().cloned().collect())
        }))
    }

    /// Run `body` on a host carrying exactly `servers`.
    pub(crate) fn with_language_servers<T>(servers: &[LanguageId], body: impl FnOnce() -> T) -> T {
        let _guard = scoped_language_servers(servers);
        body()
    }
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
/// agree; `unproduced` outranks `absent`, which outranks `unknown`, because each
/// is a stronger statement than the next: a completed scan with parse-side
/// evidence of sites, then a completed scan that found nothing, then a scan that
/// never finished.
fn weakest(left: ClassState, right: ClassState) -> ClassState {
    match (left, right) {
        (ClassState::Unproduced, _) | (_, ClassState::Unproduced) => ClassState::Unproduced,
        (ClassState::Absent, _) | (_, ClassState::Absent) => ClassState::Absent,
        (ClassState::Unknown, _) | (_, ClassState::Unknown) => ClassState::Unknown,
        _ => ClassState::Present,
    }
}

/// What one language's witness search established, beyond the class states:
/// the evidence [`unproduced_evidence_for`] reads to tell a build gap from an
/// unused feature of the code.
struct LanguageScan {
    states: Vec<(RelationKind, ClassState)>,
    examined: usize,
    budget_exhausted: bool,
    /// Classes an entity-rooted relation was seen for at all, cross-file or not.
    /// A class seen intra-file only is producible and merely unused across
    /// files, which is `absent` and not a build gap.
    seen_any: Vec<RelationKind>,
    /// Import statements the parser counted across the language's files, or
    /// `None` when no file carries the count.
    parsed_import_statements: Option<u64>,
    /// Of those, how many name a module outside the repository, when the
    /// language's specifier syntax settles it.
    external_module_imports: Option<u64>,
    /// Call sites the parser counted, or `None` when no file carries the count.
    parsed_call_sites: Option<u64>,
    /// Whether every file with entities carried a call-site count, so the sum
    /// above is a measurement rather than a partial one.
    call_sites_complete: bool,
    /// `Imports` and `Includes` edges rooted at the language's files' artifacts,
    /// counted only when the scan saw no entity-rooted import edge, because that
    /// is the one case the count decides anything.
    artifact_import_edges: u64,
}

impl LanguageScan {
    fn seen_any(&self, kind: RelationKind) -> bool {
        self.seen_any.contains(&kind)
    }

    /// Parsed import statements that name a module this repository could hold,
    /// or `None` when the language cannot settle which ones those are.
    fn parsed_internal_import_statements(&self) -> Option<u64> {
        let parsed = self.parsed_import_statements?;
        let external = self.external_module_imports?;
        Some(parsed.saturating_sub(external))
    }
}

/// Witness-search one language, returning each requested class's state, how many
/// entities were examined, whether the search stopped on its budget, and the
/// parse-side and artifact-level facts a completed empty scan is read against.
fn observe_language<S: EntityStore>(
    store: &S,
    language: kin_model::ids::LanguageId,
    requested: &[RelationKind],
) -> LanguageScan {
    let mut states: Vec<(RelationKind, ClassState)> = requested
        .iter()
        .copied()
        .map(|kind| (kind, ClassState::Unknown))
        .collect();

    let mut examined = 0usize;
    let mut budget_exhausted = false;
    let mut seen_any: Vec<RelationKind> = Vec::new();
    let mut parsed_import_statements: Option<u64> = None;
    let mut external_module_imports: Option<u64> = None;
    let mut parsed_call_sites: Option<u64> = None;
    let mut files_with_entities = 0usize;
    let mut files_with_call_counts = 0usize;
    let mut artifact_import_edges = 0u64;

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
                // The parse side, one entity per file: the extractor stamps the
                // same per-file counts on every entity of the file.
                let mut counted_files: std::collections::HashSet<&FilePathId> =
                    std::collections::HashSet::new();
                for entity in &candidates {
                    let Some(file) = entity.file_origin.as_ref() else {
                        continue;
                    };
                    if !counted_files.insert(file) {
                        continue;
                    }
                    files_with_entities += 1;
                    if let Some(count) =
                        parsed_count(entity, kin_parser::FILE_PARSED_CALL_SITES_KEY)
                    {
                        parsed_call_sites = Some(parsed_call_sites.unwrap_or(0) + count);
                        files_with_call_counts += 1;
                    }
                    if let Some(count) =
                        parsed_count(entity, kin_parser::FILE_PARSED_IMPORT_STATEMENTS_KEY)
                    {
                        parsed_import_statements =
                            Some(parsed_import_statements.unwrap_or(0) + count);
                    }
                    if let Some(count) =
                        parsed_count(entity, kin_parser::FILE_PARSED_EXTERNAL_MODULE_IMPORTS_KEY)
                    {
                        external_module_imports =
                            Some(external_module_imports.unwrap_or(0) + count);
                    }
                }
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
                        if !seen_any.contains(&relation.kind) {
                            seen_any.push(relation.kind);
                        }
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
                // Artifact-level import edges, counted only when the scan
                // finished without seeing an entity-rooted import, which is the
                // one case the count decides anything: the linker resolved
                // these files' imports and emitted no entity-level edge for
                // them.
                let imports_requested = states
                    .iter()
                    .any(|(kind, _)| *kind == RelationKind::Imports);
                if imports_requested
                    && !budget_exhausted
                    && !seen_any.contains(&RelationKind::Imports)
                {
                    artifact_import_edges =
                        artifact_import_edge_count(store, counted_files.into_iter());
                }
            }
            // The store could not enumerate the language at all, so every class
            // stays unknown rather than being reported absent from a scan that
            // never ran.
            Err(_) => budget_exhausted = true,
        }
    }

    LanguageScan {
        states,
        examined,
        budget_exhausted,
        seen_any,
        parsed_import_statements,
        external_module_imports,
        parsed_call_sites,
        call_sites_complete: files_with_entities > 0
            && files_with_call_counts == files_with_entities,
        artifact_import_edges,
    }
}

/// A per-file count the extractor stamped on the entity, when it did.
fn parsed_count(entity: &Entity, key: &str) -> Option<u64> {
    entity.metadata.extra.get(key).and_then(Value::as_u64)
}

/// `Imports` and `Includes` edges rooted at the artifacts of `files`, the level
/// the linker emitted import edges at before it emitted entity-level ones.
///
/// One bounded traversal per file. A file the store cannot map to an artifact
/// contributes nothing, which errs towards `absent` rather than `unproduced`.
fn artifact_import_edge_count<'a, S: EntityStore>(
    store: &S,
    files: impl Iterator<Item = &'a FilePathId>,
) -> u64 {
    const ARTIFACT_IMPORT_KINDS: [RelationKind; 2] =
        [RelationKind::Imports, RelationKind::Includes];
    let mut counted: std::collections::HashSet<kin_model::RelationId> =
        std::collections::HashSet::new();
    for file in files {
        let Ok(path) = kin_model::RepoPath::from_bytes(file.0.as_bytes().to_vec()) else {
            continue;
        };
        let Some(artifact) = store.artifact_id_at_path(&path) else {
            continue;
        };
        let node = kin_model::GraphNodeId::Artifact(artifact);
        let Ok(neighborhood) = store.traverse(&node, &ARTIFACT_IMPORT_KINDS, 1) else {
            continue;
        };
        for relation in neighborhood.relations {
            if relation.src == node && ARTIFACT_IMPORT_KINDS.contains(&relation.kind) {
                counted.insert(relation.id);
            }
        }
    }
    counted.len() as u64
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
    store
        .get_entity(id)
        .ok()
        .flatten()
        .and_then(|entity| entity.file_origin)
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

    /// Stamp the per-file counts the extractor writes, on every entity of a file.
    fn with_parse_counts(
        mut entity: Entity,
        imports: u64,
        external: Option<u64>,
        calls: Option<u64>,
    ) -> Entity {
        entity.metadata.extra.insert(
            kin_parser::FILE_PARSED_IMPORT_STATEMENTS_KEY.to_string(),
            json!(imports),
        );
        if let Some(external) = external {
            entity.metadata.extra.insert(
                kin_parser::FILE_PARSED_EXTERNAL_MODULE_IMPORTS_KEY.to_string(),
                json!(external),
            );
        }
        if let Some(calls) = calls {
            entity.metadata.extra.insert(
                kin_parser::FILE_PARSED_CALL_SITES_KEY.to_string(),
                json!(calls),
            );
        }
        entity
    }

    /// FIR-2672. A class the linker had sites for and produced no entity-level
    /// edge of is `unproduced`, not `absent`: the parse side counted import
    /// statements naming modules inside the repository, no entity-rooted import
    /// edge exists anywhere in the language, and the scan finished. `absent`
    /// would say the code has no such site, which is what 0.5.52 said about
    /// import sites no build had ever emitted an edge for.
    #[test]
    fn an_import_class_the_linker_produced_nothing_for_reads_unproduced() {
        let store = InMemoryGraph::new();
        let caller = with_parse_counts(
            entity("index_note", "pkg/search.py", LanguageId::Python),
            2,
            Some(1),
            None,
        );
        let target = with_parse_counts(
            entity("blank_code", "pkg/parsing.py", LanguageId::Python),
            1,
            Some(1),
            None,
        );
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
        assert_eq!(coverage["classes"]["calls"], json!("present"), "{coverage}");
        assert_eq!(
            coverage["classes"]["imports"],
            json!("unproduced"),
            "{coverage}"
        );
        let evidence = &coverage["unproduced_evidence"]["imports"];
        assert_eq!(evidence["parsed_import_statements"], json!(3), "{coverage}");
        assert_eq!(
            evidence["parsed_internal_import_statements"],
            json!(1),
            "{coverage}"
        );
        assert_eq!(
            evidence["entity_level_import_edges"],
            json!(0),
            "{coverage}"
        );
        assert_eq!(coverage["cross_file_classes"], json!(["calls"]));
    }

    /// The same graph with nothing to resolve stays `absent`. No file carries an
    /// import count, so the code has no import site the build could have
    /// missed, and calling that a build gap would make every leaf module read
    /// as one.
    #[test]
    fn an_import_class_with_no_sites_to_resolve_stays_absent() {
        let store = InMemoryGraph::new();
        let caller = entity("index_note", "pkg/search.py", LanguageId::Python);
        let target = entity("blank_code", "pkg/parsing.py", LanguageId::Python);
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
        assert_eq!(
            coverage["classes"]["imports"],
            json!("absent"),
            "{coverage}"
        );
        assert_eq!(coverage["unproduced_evidence"], Value::Null, "{coverage}");
    }

    /// A class seen intra-file is one the build produces, so a graph that merely
    /// uses no cross-file import stays `absent`, whatever the parse side counted.
    #[test]
    fn a_class_seen_intra_file_is_producible_and_stays_absent() {
        let store = InMemoryGraph::new();
        let caller = with_parse_counts(
            entity("index_note", "pkg/search.py", LanguageId::Python),
            2,
            Some(0),
            None,
        );
        let sibling = with_parse_counts(
            entity("helper", "pkg/search.py", LanguageId::Python),
            2,
            Some(0),
            None,
        );
        let target = entity("blank_code", "pkg/parsing.py", LanguageId::Python);
        store.upsert_entity(&caller).unwrap();
        store.upsert_entity(&sibling).unwrap();
        store.upsert_entity(&target).unwrap();
        store
            .upsert_relation(&relation(caller.id, sibling.id, RelationKind::Imports))
            .unwrap();
        store
            .upsert_relation(&relation(caller.id, target.id, RelationKind::Calls))
            .unwrap();

        let coverage = observe_cross_file_reference_coverage(
            &store,
            &target,
            &[RelationKind::Calls, RelationKind::Imports],
        );
        assert_eq!(
            coverage["classes"]["imports"],
            json!("absent"),
            "{coverage}"
        );
        assert_eq!(coverage["unproduced_evidence"], Value::Null, "{coverage}");
    }

    /// The call class reads the same way off a complete call-site measurement:
    /// every file counted its sites, the sum is above zero, and no entity-rooted
    /// call edge exists at all. A partial measurement is not evidence and stays
    /// `absent`.
    #[test]
    fn a_call_class_with_counted_sites_and_no_edge_reads_unproduced_only_off_a_complete_count() {
        for (complete, expected) in [(true, "unproduced"), (false, "absent")] {
            let store = InMemoryGraph::new();
            let first = with_parse_counts(
                entity("index_note", "pkg/search.py", LanguageId::Python),
                0,
                None,
                Some(3),
            );
            let second = with_parse_counts(
                entity("blank_code", "pkg/parsing.py", LanguageId::Python),
                0,
                None,
                if complete { Some(1) } else { None },
            );
            store.upsert_entity(&first).unwrap();
            store.upsert_entity(&second).unwrap();

            let coverage =
                observe_cross_file_reference_coverage(&store, &second, &[RelationKind::Calls]);
            assert_eq!(
                coverage["classes"]["calls"],
                json!(expected),
                "complete={complete}: {coverage}"
            );
        }
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

        let rust =
            observe_cross_file_reference_coverage(&store, &rust_callee, &[RelationKind::Calls]);
        assert_eq!(rust["classes"]["calls"], json!("present"));

        let python =
            observe_cross_file_reference_coverage(&store, &python_target, &[RelationKind::Calls]);
        assert_eq!(python["classes"]["calls"], json!("absent"));
    }

    /// The build fact the scan cannot see. Ruby has no language-server adapter
    /// in this build, so its reference edges are unproducible rather than merely
    /// unobserved, and the observation has to say so or the trust gate reads an
    /// unproducible class as a scanned-and-empty one.
    ///
    /// This case used to be written with JavaScript, which was true until
    /// JavaScript and TypeScript were wired: kin-lsp already carried a working
    /// adapter for both, so an express-shaped repository was told its reference
    /// edges could never exist while the only thing missing was a server on the
    /// host. `Unsupported` is deliberately not an actionable gap, so the
    /// difference is what a reader is told to do about it.
    #[test]
    fn a_language_with_no_adapter_reports_reference_enrichment_unsupported() {
        // Stated rather than inherited: on a host carrying every server, the
        // only thing that can still report `unsupported` is a build limit.
        test_support::with_language_servers(
            &[
                LanguageId::Rust,
                LanguageId::Python,
                LanguageId::TypeScript,
                LanguageId::JavaScript,
            ],
            || {
                let store = InMemoryGraph::new();
                let target = entity("render_note", "app/notes.rb", LanguageId::Ruby);
                store.upsert_entity(&target).unwrap();

                let coverage = observe_cross_file_reference_coverage(
                    &store,
                    &target,
                    &[RelationKind::References],
                );
                assert_eq!(coverage["reference_enrichment"], json!("unsupported"));

                // Positive control: a language this build DOES wire an adapter
                // for, whose server is installed, must not be reported
                // unsupported, or the field says the same thing about every
                // language and gates nothing.
                let python = entity("parse_note", "nk/parsing.py", LanguageId::Python);
                store.upsert_entity(&python).unwrap();
                let coverage = observe_cross_file_reference_coverage(
                    &store,
                    &python,
                    &[RelationKind::References],
                );
                assert_eq!(coverage["reference_enrichment"], json!("available"));
            },
        );
    }

    /// The host half, which decides the same question the build half does.
    ///
    /// A wired language whose server is missing produces no reference edge
    /// either, and until this was published the observation said `unknown` and
    /// the trust gate read that as fine.
    #[test]
    fn a_wired_language_with_no_server_installed_reports_no_language_server() {
        test_support::with_language_servers(&[], || {
            let store = InMemoryGraph::new();
            let target = entity("parse_note", "nk/parsing.py", LanguageId::Python);
            store.upsert_entity(&target).unwrap();
            let coverage =
                observe_cross_file_reference_coverage(&store, &target, &[RelationKind::References]);
            assert_eq!(
                coverage["reference_enrichment"],
                json!("no_language_server")
            );
        });
    }

    /// The weakest language governs, so one unresolvable language in a batch
    /// cannot be lifted by a resolvable sibling.
    #[test]
    fn the_weakest_language_governs_a_batch() {
        use super::weakest_reference_enrichment;
        use kin_core::reference_coverage::{LanguageServerReadiness, LanguageServerReadinessMap};
        let all: LanguageServerReadinessMap = [
            LanguageId::Rust,
            LanguageId::Python,
            LanguageId::TypeScript,
            LanguageId::JavaScript,
        ]
        .into_iter()
        .map(|language| (language, LanguageServerReadiness::Usable))
        .collect();
        let none: LanguageServerReadinessMap = LanguageServerReadinessMap::new();

        assert_eq!(
            weakest_reference_enrichment(&[LanguageId::Python, LanguageId::Ruby], &all),
            ReferenceEnrichment::Unsupported,
            "an unwired language drags the batch down"
        );
        assert_eq!(
            weakest_reference_enrichment(&[LanguageId::Python, LanguageId::JavaScript], &none),
            ReferenceEnrichment::NoLanguageServer
        );
        assert_eq!(
            weakest_reference_enrichment(&[LanguageId::Python, LanguageId::JavaScript], &all),
            ReferenceEnrichment::Available
        );

        // The state a presence-only host could not express: JavaScript's server
        // is installed and cannot start, so the batch is unproduced rather than
        // available, and it is NOT reported as a missing install.
        let javascript_broken: LanguageServerReadinessMap = [
            (LanguageId::Python, LanguageServerReadiness::Usable),
            (
                LanguageId::JavaScript,
                LanguageServerReadiness::Unusable {
                    reason: "Could not find a valid TypeScript installation".to_string(),
                },
            ),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            weakest_reference_enrichment(
                &[LanguageId::Python, LanguageId::JavaScript],
                &javascript_broken
            ),
            ReferenceEnrichment::LanguageServerUnusable,
            "a usable sibling must not lift a batch whose other server cannot start"
        );
        assert_eq!(
            weakest_reference_enrichment(&[], &all),
            ReferenceEnrichment::Unknown,
            "no language observed establishes nothing"
        );
    }

    /// FIR-2505 / FIR-2492. The scan may not skip the one class the certification
    /// gate now rests on.
    ///
    /// `get_context_pack` passes the witnesses its own rows carry, so a pack
    /// whose dependents group held a cross-file `Calls` edge used to satisfy the
    /// deciding set on the spot, skip the language scan, and publish
    /// `references: unknown`. An `unknown` is not a finding, so
    /// [`crate::negative::absence_coverage_gap`] had nothing to gate on and
    /// certified anyway. That is the same false clean the gate was written to
    /// stop, reached by never measuring instead of by measuring and ignoring.
    #[test]
    fn a_producible_reference_class_is_measured_even_when_the_answer_witnessed_calls() {
        let store = InMemoryGraph::new();
        let caller = entity("consumer", "lib/consumer.js", LanguageId::JavaScript);
        let target = entity("Router", "lib/express.js", LanguageId::JavaScript);
        store.upsert_entity(&caller).unwrap();
        store.upsert_entity(&target).unwrap();
        store
            .upsert_relation(&relation(caller.id, target.id, RelationKind::Calls))
            .unwrap();
        let kinds = [
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::References,
        ];

        // A host that can produce reference edges: the class is load-bearing, so
        // it gets measured and the graph's silence is recorded as a finding.
        test_support::with_language_servers(&[LanguageId::JavaScript], || {
            let coverage = observe_cross_file_reference_coverage_witnessed(
                &store,
                &target,
                &kinds,
                &[RelationKind::Calls],
            );
            assert_eq!(coverage["reference_enrichment"], json!("available"));
            assert_eq!(
                coverage["scan"], "ran",
                "the class the verdict rests on must be measured: {coverage}"
            );
            assert_eq!(
                coverage["classes"]["references"],
                json!("absent"),
                "a completed scan over a graph holding no cross-file references reports a \
                 finding, not an unknown: {coverage}"
            );
        });

        // With no server installed the reference class was never producible
        // and `reference_enrichment` refuses by name. The scan still runs,
        // because since FIR-2672 every requested class decides and `imports`
        // was not witnessed by the answer; it is bounded by `WITNESS_BUDGET`,
        // and what it finds is published rather than guessed.
        test_support::with_language_servers(&[], || {
            let coverage = observe_cross_file_reference_coverage_witnessed(
                &store,
                &target,
                &kinds,
                &[RelationKind::Calls],
            );
            assert_eq!(
                coverage["reference_enrichment"],
                json!("no_language_server")
            );
            assert_eq!(coverage["scan"], "ran", "{coverage}");
            assert_eq!(coverage["classes"]["calls"], json!("present"), "{coverage}");
            assert_eq!(
                coverage["classes"]["imports"],
                json!("absent"),
                "{coverage}"
            );
        });
    }

    /// JavaScript is wired now, so an express-shaped repository must no longer
    /// read `unsupported` here.
    ///
    /// Pinned as its own case rather than folded into the control above,
    /// because this exact string on this exact shape of repository is what the
    /// npm-0541 verdict recorded, and a regression would restore a state that
    /// tells a reader there is nothing to be done.
    #[test]
    fn an_express_shaped_repository_no_longer_reports_reference_enrichment_unsupported() {
        test_support::with_language_servers(
            &[LanguageId::TypeScript, LanguageId::JavaScript],
            || {
                let store = InMemoryGraph::new();
                for (name, path, language) in [
                    (
                        "createApplication",
                        "lib/express.js",
                        LanguageId::JavaScript,
                    ),
                    ("Router", "lib/router/index.ts", LanguageId::TypeScript),
                ] {
                    let target = entity(name, path, language);
                    store.upsert_entity(&target).unwrap();
                    let coverage = observe_cross_file_reference_coverage(
                        &store,
                        &target,
                        &[RelationKind::References],
                    );
                    assert_eq!(
                        coverage["reference_enrichment"],
                        json!("available"),
                        "{language} is wired and its server is installed here, so nothing about \
                         this build or host stops its reference edges existing"
                    );
                }
            },
        );
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

    /// The published form and the private form must reach the same verdict over
    /// the same store, or a per-hop terminal and the response-level gate can
    /// disagree inside one payload.
    #[test]
    fn the_published_verdict_matches_the_scan_that_produced_it() {
        let store = InMemoryGraph::new();
        let caller = entity("outer", "nk/a.py", LanguageId::Python);
        let callee = entity("inner", "nk/b.py", LanguageId::Python);
        store.upsert_entity(&caller).unwrap();
        store.upsert_entity(&callee).unwrap();
        // Every requested class, across files. Since FIR-2672 every requested
        // class decides, so a graph that links only its calls cannot certify a
        // hop absent; this fixture links all three.
        for kind in [
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::References,
        ] {
            store
                .upsert_relation(&relation(caller.id, callee.id, kind))
                .unwrap();
        }

        let linked = observe_cross_file_reference_coverage(
            &store,
            &caller,
            &[
                RelationKind::Calls,
                RelationKind::Imports,
                RelationKind::References,
            ],
        );
        assert_eq!(linked["classes"]["calls"], json!("present"));
        assert_eq!(linked["classes"]["imports"], json!("present"));
        assert!(
            deciding_classes_observed_present(&linked),
            "every requested class present decides a trace absence: {linked}"
        );

        let unlinked = InMemoryGraph::new();
        let lone = entity("outer", "nk/a.py", LanguageId::Python);
        unlinked.upsert_entity(&lone).unwrap();
        let empty = observe_cross_file_reference_coverage(
            &unlinked,
            &lone,
            &[
                RelationKind::Calls,
                RelationKind::Imports,
                RelationKind::References,
            ],
        );
        assert_eq!(empty["classes"]["calls"], json!("absent"));
        assert!(
            !deciding_classes_observed_present(&empty),
            "a graph with no cross-file calls cannot certify that a hop is absent: {empty}"
        );
    }

    /// An unmeasured observation is the unknown case. A producer that read a
    /// missing object as healthy would publish exactly the confident terminal
    /// this gate exists to withhold.
    #[test]
    fn an_unreported_observation_never_certifies() {
        assert!(!deciding_classes_observed_present(&Value::Null));
        assert!(!deciding_classes_observed_present(&json!({})));
        assert!(!deciding_classes_observed_present(&json!({
            "requested_classes": ["calls"],
        })));
        assert!(!deciding_classes_observed_present(&json!({
            "requested_classes": [],
            "classes": {},
        })));
        assert!(!deciding_classes_observed_present(&json!({
            "requested_classes": ["calls"],
            "classes": {"calls": "unknown"},
        })));
        assert!(deciding_classes_observed_present(&json!({
            "requested_classes": ["calls"],
            "classes": {"calls": "present"},
        })));
    }
}
