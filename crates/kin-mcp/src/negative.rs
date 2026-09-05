// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Confidence-qualified negatives (Track C trust contract).
//!
//! For an agent, the epistemics of a "no result" matter as much as the result
//! itself: a bare empty array cannot tell "this symbol genuinely has no
//! references" (safe to delete) from "the graph has not finished indexing"
//! (absolutely not safe to delete). Retrieval tools used to return those two
//! cases identically.
//!
//! This module turns an empty (or, for batch reachability, a verdict-bearing)
//! retrieval response into an explicit, additive `negative` object that carries
//! the freshness and coverage context lifted onto the [`Envelope`], plus a
//! single derived verdict — `safe_to_conclude_absent` — so an agent can
//! calibrate trust in one read.
//!
//! ## Single source of truth
//!
//! [`spec_for`] is the one registry of which tools are negative-capable and how
//! each expresses "no result". [`negative_for`] is folded into
//! `envelope::finalize`, the single annotation chokepoint, so the contract is
//! identical on the offline and daemon paths — no per-handler edits, no shape
//! drift.
//!
//! ## Honesty contract (CLAUDE.md)
//!
//! Every value in the negative is derived from what the envelope actually
//! observed. Unknown freshness/coverage is `null` and forces
//! `safe_to_conclude_absent = false` — absence is never certified on data the
//! envelope did not see.
//!
//! ## What an absence claim depends on
//!
//! Freshness and degraded signals describe the daemon, not the substrate a
//! particular query reads. A graph can be initialized, loaded, fully embedded and
//! undegraded while holding no cross-file `calls`/`imports`/`references` edges at
//! all, and every reference query against it returns an empty array for reasons
//! that have nothing to do with the code. [`absence_cross_file_classes`] is the
//! per-tool map of which edge classes each tool's absence claim depends on, and
//! [`edge_coverage_gap`] is the gate that reads the observation
//! [`crate::edge_coverage`] publishes into the payload. A tool that declares a
//! dependency and publishes no observation is inconclusive by construction, so
//! authority cannot be inherited by a tool that has not earned it. Which classes
//! decide is [`load_bearing_classes`]: a present sibling class is not coverage
//! for the class a focal is actually reached through.
//!
//! Gaps accumulate through [`push_gap`] in limiting-factor-first order rather
//! than overwriting one another. Order matters as much as the verdict: a correct
//! `inconclusive` beside an unrelated reason teaches readers to skip the reason,
//! which is how a missing-cross-file-edge absence came back explained as a
//! cross-repo spine mismatch.

use serde_json::{json, Map, Value};

use crate::envelope::{Envelope, NegativeClass};

/// Reserved, additive top-level key under which a retrieval tool's
/// confidence-qualified negative is attached, beside the `_kin` envelope.
/// Distinctive enough not to collide with any tool payload's own fields.
pub const NEGATIVE_KEY: &str = "negative";

/// The file-enumeration tool, named once here so the spec, the gate and the
/// dependency declaration below cannot drift from the registry that serves it.
const FILE_ENTITIES_TOOL: &str = crate::handlers::file_entities::TOOL_NAME;
/// The route query, named from the handler that defines it for the same reason.
const TRACE_PATH_TOOL: &str = crate::handlers::path::TOOL_NAME;

/// Why a file enumeration cannot be certified as the file's whole entity set,
/// or `None` when nothing stops it.
///
/// Read from the tool's own `file_coverage` observation rather than from the
/// envelope, because the question is about one file and every envelope signal is
/// about the store. A completely embedded, fully loaded, undegraded graph
/// carries no entities at all for a file no language adapter parsed, and every
/// store-level gate reads healthy while it says so.
///
/// Four things can stop the certification and each is named separately, because
/// the remediation differs: a file nothing parsed needs an adapter, a partial
/// parse needs the syntax fixed, a page needs its cursor followed, and a shifted
/// enumeration needs re-walking from the start.
fn file_enumeration_gap(payload: &Value) -> Option<String> {
    let Some(coverage) = payload
        .get(crate::handlers::file_entities::FILE_COVERAGE_KEY)
        .and_then(Value::as_object)
    else {
        return Some(
            "file_coverage_unreported: this answer did not report whether a language adapter \
             parsed the file, so an empty enumeration cannot be distinguished from a file \
             nothing ever extracted entities from"
                .to_string(),
        );
    };

    let parsed = coverage
        .get("parsed")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let detail = coverage
        .get("parse_detail")
        .and_then(Value::as_str)
        .map(|detail| format!(" ({detail})"))
        .unwrap_or_default();
    // Provenance first: a full parse of other bytes is a stronger disqualifier
    // than any parse state, because every row it produced describes a file that
    // is no longer at this path.
    if coverage.get("span_provenance").and_then(Value::as_str) == Some("stale") {
        let stale = coverage
            .get("stale_spans")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        return Some(format!(
            "file_spans_stale: {stale} entity span(s) in this file were derived from bytes the \
             repository tree no longer holds at this path, so the enumeration describes an \
             earlier state of the file; the graph has admitted the new source and not yet \
             re-derived these entities"
        ));
    }
    match parsed {
        "full" => {}
        "absent" => {
            return Some(
                "file_not_parsed: no language adapter produced a layout for this file, so the \
                 graph holds no entity set for it to be missing from. An empty enumeration here \
                 is a fact about Kin's extraction coverage, not about the file's contents"
                    .to_string(),
            )
        }
        "partial" => {
            return Some(format!(
                "file_parsed_partially: the adapter hit parse errors in this file{detail}, so the \
                 entities it produced are a floor and the enumeration may be short"
            ))
        }
        "failed" => {
            return Some(format!(
                "file_parse_failed: the adapter could not parse this file{detail}, so whatever \
                 entities the graph still carries for it describe an earlier state"
            ))
        }
        other => {
            return Some(format!(
                "file_parse_state_unknown: this answer reported the parse state as {other:?}, \
                 which is not a state that licenses reading the enumeration as whole"
            ))
        }
    }

    if coverage.get("enumeration_shifted").and_then(Value::as_bool) == Some(true) {
        return Some(
            "enumeration_shifted: the file gained or lost entities between the page that minted \
             this cursor and the page it served, so these pages do not assemble into one state of \
             the repository. Re-walk from the start"
                .to_string(),
        );
    }

    if coverage
        .get("whole_file_in_response")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Some(
            "page_bounded: this response holds one page of the file rather than all of it, so its \
             rows are a floor. Follow `next_cursor` to the end before reading the set as whole"
                .to_string(),
        );
    }

    None
}

/// How one tool's payload expresses "no result", and how to frame the resulting
/// negative. One row per negative-capable tool — the single source of truth.
struct RetrievalSpec {
    /// Object key holding the result collection. `""` means the payload is a
    /// bare JSON array (wrapped under `result` by the envelope annotator).
    field: &'static str,
    /// Machine-readable negative kind.
    kind: &'static str,
    /// One-line, tool-specific framing of what the empty/negative result means.
    subject: &'static str,
    /// When true, the qualifier is attached even if the collection is non-empty
    /// — e.g. batch reachability, whose `has_references: false` rows are
    /// themselves the negatives an agent must calibrate before deleting.
    always: bool,
    /// Which substrate's completeness gates this tool's absence-trust: embeddings
    /// (`Semantic`) or graph structure (`Structural`). See [`NegativeClass`].
    class: NegativeClass,
}

/// The registry of negative-capable retrieval tools. Returns `None` for any tool
/// that is not retrieval/negative-capable (mutations, session/work/review ops,
/// and tools whose payload is always populated), so no negative is synthesized.
fn spec_for(tool: &str) -> Option<RetrievalSpec> {
    let spec = match tool {
        // Structural rather than semantic on purpose. This tool filters
        // declarations by name pattern, kind, language, and role; it never
        // consults the vector index, which is why the daemon deliberately does
        // not attach embedding coverage to its payload. Gating its absence on
        // embedding coverage made every empty search report
        // `coverage_unknown` and advise "re-check after embedding is complete"
        // — on a store whose embeddings were complete, about a lookup that
        // never read one. The substrate it actually reads is the graph, so the
        // graph gate is the one that can answer for it.
        "semantic_search" => RetrievalSpec {
            field: "results",
            kind: "no_entity_match",
            subject: "no entity declaration matched the search",
            always: false,
            class: NegativeClass::Structural,
        },
        // Daemon-only: offline returns an error (no payload), so this fires only
        // on the daemon path. `field` is the cosine arm's collection; the fused
        // arm answers under a different key and is resolved by
        // [`locate_result_count`], which this spec defers to.
        "semantic_locate" => RetrievalSpec {
            field: "results",
            kind: "no_ranked_match",
            subject: "no entity ranked above threshold for the query",
            always: false,
            class: NegativeClass::Semantic,
        },
        "find_references" => RetrievalSpec {
            field: "references",
            kind: "no_references",
            subject: "no references to the focal entity were found",
            always: false,
            class: NegativeClass::Structural,
        },
        // A pack's `dependents` group is the reference surface's answer,
        // assembled by the same collector on the same store (FIR-2474), so the
        // absence it can claim is the same absence and it is qualified by the
        // same gates. `dependencies` is not the field here: an empty one says
        // the focal calls nothing, which is an ordinary fact about a leaf and
        // not a claim any agent acts on. The claim that decides whether a
        // contract is safe to change is "nothing depends on this", and that is
        // the one a pack used to publish as a bare `[]`.
        "get_context_pack" => RetrievalSpec {
            field: "dependents",
            kind: "no_dependents",
            subject: "nothing was found depending on the focal entity",
            always: false,
            class: NegativeClass::Structural,
        },
        // The neighborhood always returns the focal itself, so an empty
        // `entities` says the focal is not in the graph rather than that it has
        // no neighbors, and for an indexed entity the list is never empty at
        // all. Every neighbor is discovered by traversing an edge, so the
        // emitted edge set is what "no neighbors" actually reads. `subject` and
        // `kind` here are the merged-walk defaults; [`negative_for`] narrows
        // both to the direction the traversal was asked for.
        "graph_neighborhood" => RetrievalSpec {
            field: "relations",
            kind: "no_neighbors",
            subject: "the entity has no graph neighbors at the requested depth",
            always: false,
            class: NegativeClass::Structural,
        },
        // The enumeration surface. Its absence claim is the sharpest one any
        // retrieval tool here makes -- "this file holds no entities" -- and it
        // is also the one with a decisive per-file fact behind it, so it is
        // gated on that fact rather than on store-wide health. `Structural`
        // because it reads the entity index; no embedding is consulted, and
        // gating it on embedding coverage would report a complete answer as
        // uncertain for a substrate it never touched.
        FILE_ENTITIES_TOOL => RetrievalSpec {
            field: "entities",
            kind: "no_file_entities",
            subject: "the graph holds no entities for this file",
            always: false,
            class: NegativeClass::Structural,
        },
        "find_dead_code_seeded" => RetrievalSpec {
            field: "candidates",
            kind: "no_seed_match",
            subject: "no entities matched the seed query",
            always: false,
            class: NegativeClass::Structural,
        },
        "trace_data_flow" => RetrievalSpec {
            field: "chain",
            kind: "no_flow",
            subject: "no data-flow chain was found from the focal entity",
            always: false,
            class: NegativeClass::Structural,
        },
        // The route query. Its empty answer is the sharpest absence a graph
        // walk can claim, "A never reaches B", and it rests on the same typed
        // reference edges the walkers above read, so it is gated by the same
        // coverage facts plus the two-ended resolution gaps `path_gaps` adds.
        TRACE_PATH_TOOL => RetrievalSpec {
            field: "routes",
            kind: "no_route",
            subject: "no route was found between the two entities that were named",
            always: false,
            class: NegativeClass::Structural,
        },
        // Bare-array payloads (wrapped under `result` by the annotator).
        "dead_code" => RetrievalSpec {
            field: "",
            kind: "no_dead_code",
            subject: "no unreachable entities were found in the scanned set",
            always: false,
            class: NegativeClass::Structural,
        },
        "entity_history" => RetrievalSpec {
            field: "",
            kind: "no_history",
            subject: "no change history was found for the entity",
            always: false,
            class: NegativeClass::Structural,
        },
        // The whole output is used/unused verdicts, so like the batch below it
        // always qualifies rather than qualifying an empty page. An
        // `entity_impacts` row carrying `consumer_count: 0` IS the verdict a
        // caller reads before changing or deleting something, and it is read off
        // the same cross-file reference edges `find_references` reads, so it can
        // be wrong for the same reason and now says so.
        //
        // This was the last retrieval surface without the rail, which put the
        // tool with the highest blast radius per wrong absence outside the gate
        // every smaller one passes. Its declarations in
        // [`absence_cross_file_classes`] and [`absence_is_language_scoped`] were
        // already written and were waiting for this row.
        "impact_analysis" => RetrievalSpec {
            field: "entity_impacts",
            kind: "impact_verdicts",
            subject: "per-changed-entity downstream impact verdicts",
            always: true,
            class: NegativeClass::Structural,
        },
        // Batch reachability never returns an empty `results` on success (it
        // errors on empty input), but its `has_references: false` rows ARE the
        // negatives a "safe to delete?" sweep depends on — so always qualify.
        "bulk_check_references" => RetrievalSpec {
            field: "results",
            kind: "reachability_verdicts",
            subject: "per-entity reachability verdicts",
            always: true,
            class: NegativeClass::Structural,
        },
        _ => return None,
    };
    Some(spec)
}

/// Which substrate's completeness gates this tool, or `None` for a tool that is
/// not negative-capable retrieval.
///
/// The one reader outside this module is [`crate::envelope::Completeness`],
/// which needs the same per-tool substrate answer to say what "complete" means
/// for an answer. Serving it from [`spec_for`] keeps one registry: a retrieval
/// tool declares what it reads once and both the absence verdict and the
/// completeness signal follow from that declaration.
pub(crate) fn negative_class_for(tool: &str) -> Option<NegativeClass> {
    spec_for(tool).map(|spec| spec.class)
}

/// The cross-file edge classes each tool's ABSENCE claim depends on: the
/// per-tool dependency map, in code, so authority can only be granted for a
/// substrate the tool actually reads.
///
/// A tool's absence is a claim about edges, and the only edges that can carry a
/// reference from one file to another are cross-file `calls`/`imports`/
/// `references`. A graph that holds none of them for the focal's language
/// answers every reference query with an empty array no matter how healthy it
/// is, which is why membership in this map, and not the freshness signals,
/// decides whether an absence can be certified.
///
/// | tool | classes an absence depends on | why |
/// |---|---|---|
/// | `find_references` | the query's own `relation_kinds` (default calls, imports, references) | its rows ARE those edges |
/// | `bulk_check_references` | the query's own `relation_kinds` | one `has_references: false` row per entity, read off the same edges |
/// | `trace_data_flow` | calls, imports, references | the walk expands exactly those kinds |
/// | `impact_analysis` | calls, imports, references | downstream impact is those edges transitively, and every `consumer_count: 0` verdict is read off them |
/// | `graph_neighborhood` | none | the merged walk includes containment edges, which are intra-file by construction, so an empty neighborhood is not evidence about cross-file coverage; its absence is gated instead by focal-not-in-graph and depth-zero |
/// | `semantic_locate` | none | ranks entities from embeddings and never traverses an edge |
/// | `semantic_search` | none | filters declarations by name/kind/language and never traverses an edge |
/// | `dead_code`, `find_dead_code_seeded` | none | their empty result is the INVERSE claim ("nothing unreachable"), and missing edges produce more candidates rather than fewer, so absence there is not endangered by a coverage gap |
/// | `entity_history` | none | reads change history, not relations |
///
/// A tool absent from the map contributes no classes, so a new retrieval tool
/// starts with no edge-derived authority to inherit and has to declare what it
/// reads to earn one.
pub(crate) fn absence_cross_file_classes(tool: &str, payload: &Value) -> Vec<String> {
    match tool {
        "find_references" | "bulk_check_references" => payload
            .get("relation_kinds")
            .and_then(Value::as_array)
            .map(|kinds| {
                kinds
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_ascii_lowercase)
                    .filter(|kind| matches!(kind.as_str(), "calls" | "imports" | "references"))
                    .collect()
            })
            .unwrap_or_else(reference_classes),
        "trace_data_flow" | "impact_analysis" | "get_context_pack" | TRACE_PATH_TOOL => {
            reference_classes()
        }
        _ => Vec::new(),
    }
}

/// Whether `tool`'s ABSENCE claim is a statement about one language's extracted
/// graph, and so cannot outrun what this build can resolve for that language.
///
/// Separate from [`absence_cross_file_classes`] because the two facts are
/// independent: a tool can traverse no edge at all and still be claiming
/// something about a language's graph. `semantic_search` is exactly that shape,
/// and it is why FIR-2430 happened. It filters declarations by name, kind,
/// language and role, declares no edge class, and therefore cleared the whole
/// gate `find_references` had just refused to clear on the same repository in
/// the same session: `semantic_search(query: "utils", kind: "module")` on
/// expressjs/express certified `safe_to_conclude_absent: true` while
/// `lib/utils.js` sat in the tree holding nine entities.
///
/// | tool | language-scoped | why |
/// |---|---|---|
/// | `semantic_search` | yes | "no declaration carries this name/kind" is a claim about what the extractor admitted as an entity for that language |
/// | `find_dead_code_seeded` | yes | its seed match is the same name/kind filter over the same entity index |
/// | `graph_neighborhood` | yes | an empty neighborhood for a focal that IS in the graph claims nothing reaches it, which is a claim about that language's edges |
/// | `find_references`, `bulk_check_references`, `trace_data_flow`, `impact_analysis` | yes | already gated this way by FIR-2404; the flag records the fact rather than changing it |
/// | `semantic_locate` | no | its payload is built by the daemon's own locate route and publishes no observation, so declaring a dependency here would make every empty ranking inconclusive on evidence nothing collected; its absence stays gated on complete embedding coverage, and its unnamed-ranking arm is never certifiable at all |
/// | `dead_code` | no | its empty result is the INVERSE claim ("nothing unreachable"), and a language this build cannot resolve produces MORE candidates rather than fewer |
/// | `entity_history` | no | reads change history, which no language server contributes to |
///
/// A tool absent from this list is not language-scoped, so a new retrieval tool
/// starts with no authority to inherit and has to declare what it reads.
fn absence_is_language_scoped(tool: &str) -> bool {
    matches!(
        tool,
        "find_references"
            | "bulk_check_references"
            | "trace_data_flow"
            | "impact_analysis"
            | "semantic_search"
            | "find_dead_code_seeded"
            | "graph_neighborhood"
            | "get_context_pack"
            | TRACE_PATH_TOOL
    )
}

/// The default reference edge classes, matching `default_reference_kinds` on the
/// handler side. Kept as the fallback for a payload that does not report the
/// scope it ran with, because assuming a narrower scope than the query used
/// would let an unreported union query pass a gate only its narrowest arm earned.
fn reference_classes() -> Vec<String> {
    vec![
        "calls".to_string(),
        "imports".to_string(),
        "references".to_string(),
    ]
}

/// The requested classes an absence claim has to be able to SEE before it can
/// be certified, as opposed to the ones whose absence is ordinary on a healthy
/// graph and therefore proves nothing.
///
/// Only `calls` qualifies, and the reason is measured rather than assumed. Kin's
/// linker resolves an import statement to a cross-file `Calls` edge between the
/// importing entity and the imported one, plus an artifact-level import edge that
/// entity queries never reach. It mints no entity-level `Imports` edge at all: a
/// converted Python repository whose imports resolve cleanly reports
/// `Entity-to-entity relation kinds: Calls, Contains` and `imports 0/2 (0%)` on
/// `kin graph status`, with `Cross-file entity relations: 4 of 9`. So `imports`
/// reads `absent` on every language including the ones that work, and requiring
/// it would report every absence on every real graph as inconclusive, which is
/// the failure mode opposite to FIR-2353 and no more useful. `references` is the
/// same story for a different reason: it needs a resolved program from a language
/// server and is legitimately absent wherever one has not run.
///
/// What stops a JavaScript `module.exports` being certified is therefore not a
/// missing `imports` witness, which Python lacks identically, but the
/// enrichment gate below: this build wires no language-server adapter for
/// JavaScript, so no reference edge can exist for it at any coverage. Both absent
/// classes are still disclosed through [`edge_coverage_degradation_labels`], so a
/// reader sees what the verdict rests on either way.
///
/// Every class the query asked for. This used to narrow to `calls`, on the
/// reasoning above, and the narrowing is what FIR-2672 is: the verdict rested on
/// `calls` alone, published `imports: absent` beside it as a limit nobody
/// weighed, and certified an answer as the whole set while its own completeness
/// block recorded the class it could not have read. A class the answer could not
/// have read is a class its counts cannot be whole over, whatever the reason,
/// so every requested class decides. What the narrowing was protecting against,
/// every Python answer reading inconclusive because Kin minted no entity-level
/// `Imports` edge, is now said in those words: the scan reports such a class
/// `unproduced` rather than `absent`, and the verdict names the build gap as its
/// limiting factor instead of hiding it.
pub(crate) fn load_bearing_classes(requested: &[String]) -> Vec<String> {
    requested.to_vec()
}

/// Whether this answer's own observation says cross-file reference edges were
/// producible where it ran: this build wires an adapter for the language AND the
/// host carries the server.
///
/// `unsupported` and `no_language_server` are the two ways the class could never
/// have existed, and [`absence_coverage_gap`] already refuses both by name.
/// `unknown` is an unread host, and unmeasured is not a finding anywhere else in
/// this module either.
pub(crate) fn references_producible(payload: &Value) -> bool {
    payload
        .get(crate::edge_coverage::EDGE_COVERAGE_KEY)
        .and_then(|coverage| coverage.get("reference_enrichment"))
        .and_then(Value::as_str)
        == Some("available")
}

/// The classes this answer's verdict actually rests on: [`load_bearing_classes`]
/// plus `references` wherever this host could have produced it.
///
/// Deliberately NOT public. `kin impact` needs to know which classes the gate
/// rested on so it does not name one the gate never weighed, and it gets that by
/// reading `_kin.completeness.decided_by`, the record this set produces, rather
/// than by importing this function (FIR-2524). Reading the published record beats
/// importing the producer: one of them can drift from the verdict and the other
/// cannot.
///
/// One definition, because three consumers ask the same question and a fourth
/// answer would only be somewhere for them to drift. [`absence_coverage_gap`]
/// decides whether an absence may be certified, `deciding_classes_all_present`
/// in [`crate::edge_coverage`] decides whether the language scan may be skipped,
/// and `edge_class_states` in [`crate::envelope`] publishes `decided_by` and the
/// completeness `status` computed from it. Before FIR-2505 all three read
/// [`load_bearing_classes`] and all three were wrong together, which is how
/// shipped v0.5.43 answered `status: "complete"`, `bound: "exact"` and "so the
/// counts here are the whole set" about a graph holding no cross-file reference
/// edge at all, while listing that very absence one field away under `limits`.
///
/// [`load_bearing_classes`] answers the question that holds on any host, and its
/// narrowing to `calls` is measured rather than assumed. This adds the one fact
/// that changes the answer: on a host that CAN produce reference edges, their
/// absence is a finding rather than the ordinary silence of a language server
/// that never ran.
pub(crate) fn deciding_classes(requested: &[String], references_producible: bool) -> Vec<String> {
    // Every requested class decides (FIR-2672). `references` no longer joins
    // conditionally: when this host cannot produce it, `reference_enrichment`
    // refuses by name before any class is read, and when nobody established
    // whether it can, an unread class is the unknown case the whole module
    // refuses on rather than the healthy one.
    let _ = references_producible;
    load_bearing_classes(requested)
}

/// Why the graph cannot certify this absence, or `None` when every substrate the
/// claim actually rests on is demonstrably present.
///
/// This is the one gate. Every negative-capable tool passes through it and is
/// checked against what it DECLARES it reads: [`absence_cross_file_classes`] for
/// the edges an absence is read off, and [`absence_is_language_scoped`] for
/// whether the claim is about a language's extracted graph at all. A tool that
/// declares either and publishes no observation is inconclusive by construction,
/// so authority can never be inherited by a tool that has not earned it. Before
/// FIR-2430 the whole gate was skipped for any tool declaring no edge class,
/// which is how `semantic_search` reached `structural_authoritative` from daemon
/// health alone, minutes after `find_references` refused the same absence on the
/// same repository.
///
/// Three gates, and an answer has to clear all of them. Every load-bearing
/// requested class must be observed present ([`load_bearing_classes`] says which,
/// and why the set is narrower than it looks); a filter must have selected a
/// region the index actually populated; and the language must be one this build
/// can resolve at all.
///
/// The second gate is what FIR-2404 added. A witness proves the extractor links
/// SOME class across files for the language; it never proved the language's
/// reference surface is producible in the first place. On JavaScript, where
/// same-name bare calls resolve and this build wires no language-server adapter,
/// a present `calls` class certified an absence over `createApplication`,
/// express's `module.exports`, which every consuming file reaches through a
/// `require` this graph cannot represent. The measured classes could not separate
/// that from a healthy Python graph, because both report `imports: absent`; the
/// adapter fact separates them and is true independent of coverage.
///
/// A payload carrying no observation at all is the unknown case, not the healthy
/// one. That is the reading the module's honesty contract already takes for
/// unknown coverage, and it is the reading that makes a tool declare its
/// dependency in [`absence_cross_file_classes`] and publish the observation
/// before it can certify anything.
///
/// The extraction side grew a richer statement of the same fact under FIR-2354:
/// `kin_core::reference_coverage::ReferenceEdgeCoverage`, whole-graph counts plus a
/// per-language entry carrying `reference_enrichment`, which knows something a
/// witness scan cannot observe from the graph alone. Half of that now reaches
/// this gate: [`crate::edge_coverage`] publishes `reference_enrichment`, and the
/// build half of it (a language this build wires no adapter for, so its reference
/// edges are unproducible rather than unobserved) is read below. The host half (a
/// wired adapter whose server is not installed) still reaches the CLI surfaces
/// only, because probing it costs a filesystem lookup per query, so it publishes
/// as `unknown` and gates nothing. When a payload carries the whole-graph object,
/// this gate should prefer it, mapping zero cross-file entity relations to
/// `absent` for every class and a language's zero to `absent` for that language;
/// [`crate::edge_coverage`] can then be retired, since it is called from exactly
/// three payload builders.
pub(crate) fn absence_coverage_gap(tool: &str, payload: &Value) -> Option<String> {
    let clauses = absence_coverage_clauses(tool, payload);
    (!clauses.is_empty()).then(|| clauses.join(crate::verdict::CLAUSE_SEPARATOR))
}

/// The same gaps as [`absence_coverage_gap`], as the list they are built as.
///
/// The verdict takes this and never the joined string. The two used to be one
/// function returning `Option<String>`, and `compose_limiting_factor` split it
/// back apart on the same `"; "` this file joins with, which made the separator
/// carry two jobs at once: the boundary between clauses, and ordinary
/// punctuation inside one clause's prose. Two gap texts contain a semicolon,
/// `cross_file_edges_absent` and `name_filter_narrowed_to_zero`, so each was cut
/// into a labelled clause and a bare fragment with no label at all, and the
/// fragment reached the reader inside `limiting_factor`.
///
/// A joined string is a rendering. `negative.trust_reason` is a string on the
/// wire and takes one; the verdict composes from the list, so no boundary is
/// ever inferred from text a human wrote.
pub(crate) fn absence_coverage_clauses(tool: &str, payload: &Value) -> Vec<String> {
    let requested = absence_cross_file_classes(tool, payload);
    let language_scoped = absence_is_language_scoped(tool);
    if requested.is_empty() && !language_scoped {
        return Vec::new();
    }
    let named = requested.join(", ");
    let claims_absence = answer_claims_absence(tool, payload);

    let Some(coverage) = payload
        .get(crate::edge_coverage::EDGE_COVERAGE_KEY)
        .and_then(Value::as_object)
    else {
        return vec![if !requested.is_empty() {
            format!(
                "edge_coverage_unreported: this answer did not report whether the graph holds \
                 cross-file {named} edges, so an empty result cannot be distinguished from a graph \
                 that could not have found a reference in the first place"
            )
        } else if claims_absence {
            "absence_coverage_unreported: this answer did not report which languages the absence \
             claim spans or whether this build can resolve their programs, so an empty result \
             cannot be distinguished from a scope the extractor never populated"
                .to_string()
        } else {
            // FIR-2496. The same missing observation, read against the claim the
            // answer actually made. A response holding rows asserts no absence,
            // and handing it the sentence above put the one caveat about
            // absences on the one call that was not making one: on the v0.5.43
            // stranger run three empty searches certified byte-identically while
            // `notes_with_tag`, which returned a row, was the response that read
            // `limiting_factor: absence_coverage_unreported`. The limit is real
            // either way, and what it limits is different, so it says so.
            "answer_coverage_unreported: this answer did not report which languages its rows \
             span or whether this build can resolve their programs, so the rows here are a floor \
             and a declaration the extractor never admitted could not be among them"
                .to_string()
        }];
    };
    let language = coverage
        .get("language")
        .and_then(Value::as_str)
        .filter(|language| !language.trim().is_empty())
        .unwrap_or("an unreported language");
    let states = coverage.get("classes").and_then(Value::as_object);

    let mut gaps: Vec<String> = Vec::new();

    if !requested.is_empty() {
        let required = deciding_classes(&requested, references_producible(payload));
        let unproduced = classes_in_state(&required, states, "unproduced");
        let absent = classes_in_state(&required, states, "absent");
        let unknown = classes_in_state(&required, states, "unknown");
        let present = classes_in_state(&requested, states, "present");

        if !unproduced.is_empty() {
            // The build, not the code. The scan completed, saw no entity-rooted
            // edge of the class at all, and the parse side shows sites the
            // linker had to resolve, so no scan of this graph could have found a
            // use that reaches the target through it (FIR-2672).
            let missing = unproduced.join(", ");
            gaps.push(format!(
                "cross_file_edges_unproduced: this build produced no entity-level {missing} edge \
                 for {language} although the source carries {missing} sites the linker \
                 resolved, so a use that reaches the target through {missing} could not have \
                 been found, and the gap is in the linker, not in the code"
            ));
        }
        if !absent.is_empty() {
            let missing = absent.join(", ");
            // Naming what IS present matters as much as naming what is missing. The
            // reader's next question after "no imports edges" is "then what did the
            // 258 entities this scan examined prove", and leaving that unanswered is
            // how a present sibling class came to look like coverage for the absent
            // one in the first place.
            let observed = if present.is_empty() {
                String::new()
            } else {
                format!(
                    " (cross-file {} edges are present and do not stand in for {missing}: an \
                     entity other files reach only through {missing} is invisible to a graph \
                     holding none)",
                    present.join(", ")
                )
            };
            // Which half of "extraction/enrichment" it is, whenever the answer's
            // own observation can say. A missing `references` class on a host
            // that wires an adapter AND carries the server is not a capability
            // the reader has to go install: the edges were producible here and
            // were not produced, so the sweep is the thing to look at. Saying
            // only "the gap is in enrichment" sends a reader off to check a
            // language server already sitting on their PATH.
            let producible = if absent.iter().any(|class| *class == "references")
                && references_producible(payload)
            {
                format!(
                    " (a language server for {language} is installed on this host and this build \
                     wires an adapter for it, so those edges were producible here and were not \
                     produced; the enrichment sweep is what to look at, not the build's \
                     capability)"
                )
            } else {
                String::new()
            };
            gaps.push(format!(
                "cross_file_edges_absent: the graph holds no cross-file {missing} edges for \
                 {language}{observed}, so a use that reaches the target through {missing} could \
                 not have been found and an empty result says nothing about whether the target is \
                 used, and the gap is in extraction/enrichment for that language rather than in \
                 the code{producible}"
            ));
        } else if !unknown.is_empty()
            || coverage.get("budget_exhausted").and_then(Value::as_bool) == Some(true)
        {
            gaps.push(format!(
                "edge_coverage_unknown: whether the graph holds cross-file {named} edges for \
                 {language} could not be established, so an empty result may mean the query had \
                 no edges to answer from rather than that the target is unused"
            ));
        }
    }

    // A filter that selected a region the graph does not populate answers every
    // query in that region identically, so its empty result is a fact about the
    // index. This is the gate the `kind` filter needed: certifying "no module
    // named utils" is a statement about the modules the extractor admitted, and
    // it cannot be read as one about the repository until the region holds
    // something. Reported only when the answer measured it, because an
    // unmeasured region is unknown rather than empty.
    if coverage.get("scope_entities").and_then(Value::as_u64) == Some(0) {
        gaps.push(format!(
            "absence_scope_empty: the graph holds no entity at all under the filter this query \
             applied for {language}, so an empty result describes the region the index populated \
             rather than the code"
        ));
    }

    // The name filter's own side, and the one gate that can see a match the
    // narrowing filters removed. Every other gate here reads the substrate, so
    // on a healthy store they all correctly report nothing, which is exactly how
    // `semantic_search(query: "request", kind: "method")` on psf/requests
    // certified `safe_to_conclude_absent: true` about a name the graph resolves.
    // A nonzero candidate count is proof the name matched declarations, so what
    // this answer observed is absence of a MATCH under those filters and never
    // absence of the thing.
    //
    // Reported only when the answer measured it. A query that applied no
    // narrowing filter carries no observation here and is unaffected, which is
    // what keeps a genuinely absent name on a healthy store certifiable.
    if let Some(name_filter) = coverage
        .get(crate::edge_coverage::NAME_FILTER_KEY)
        .and_then(Value::as_object)
    {
        let candidates = name_filter
            .get("candidates")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if candidates > 0 {
            let narrowed = name_filter
                .get("narrowed_by")
                .and_then(Value::as_array)
                .map(|applied| {
                    applied
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|narrowed| !narrowed.is_empty())
                .unwrap_or_else(|| "the filters".to_string());
            let declarations = if candidates == 1 {
                "1 declaration".to_string()
            } else {
                format!("{candidates} declarations")
            };
            gaps.push(format!(
                "name_filter_narrowed_to_zero: this query's name pattern selects {declarations} \
                 on its own and the {narrowed} filter removed every one of them, so this answer \
                 observed that no candidate survived those filters rather than that the \
                 repository holds no such declaration. The name resolves, so do not read this as \
                 the target being absent, and re-run without the narrowing filter to see what it \
                 matched"
            ));
        }
    }

    // Independent of what any scan measured. A language this build cannot
    // resolve is not one that happened to come back empty, and no amount of
    // scanning or re-indexing will ever move it.
    //
    // The wording splits on what the tool actually claimed, because a correct
    // verdict beside an unrelated reason is the failure this module exists to
    // prevent. For a tool reading reference edges the limit is that those edges
    // cannot exist; for a tool reading the entity index the limit is that
    // nothing resolved the program behind the declarations it filtered, so a
    // name-and-kind miss cannot separate a declaration the repository lacks from
    // one the extractor never admitted as an entity of that kind.
    // Two ways the program can be unresolved, and the gate blocks on both.
    //
    // It used to key on `unsupported` alone, which is the BUILD limit. That was
    // the same reason with only one of its causes: a wired adapter with no
    // server installed leaves the program exactly as unresolved, and reading
    // that state as fine is how a Python absence was certified as authoritative
    // on a host that could not have produced a single reference edge. Wiring
    // JavaScript and TypeScript made it visible rather than introducing it: the
    // express-shaped absence FIR-2430 blocked went straight back to "safe to
    // treat the target as genuinely absent" the moment the build limit lifted,
    // because nothing was looking at the host.
    //
    // The wording splits three ways, because a correct verdict beside an
    // unrelated reason is the failure this module exists to prevent. What the
    // tool claimed decides the first split; whether an operator can DO anything
    // decides the second. A build limit no amount of installing will move reads
    // differently from a host gap one command closes.
    // Fires only on a POSITIVE finding about a real language. `available` means
    // the program was resolved, and `unknown` means the observation named no
    // language at all, which is what a focal that never resolved reports. A gate
    // that fired on `unknown` would answer a question nobody asked, in the words
    // "nothing established that a language server resolved no resolved language
    // on this host", and it would displace the real limiting factor a reader
    // needs. Unmeasured is not a finding anywhere else in this module either.
    let cause = match coverage.get("reference_enrichment").and_then(Value::as_str) {
        Some("unsupported") => Some(format!(
            "this build wires no language-server adapter for {language}"
        )),
        Some("no_language_server") => Some(format!(
            "no language server for {language} is installed on this host, so no cross-file \
             reference or override edge was ever produced for it"
        )),
        _ => None,
    };
    if let Some(cause) = cause {
        // At the head of the list, not the tail. Since FIR-2672 every requested
        // class refuses on its own, so a language whose reference edges could
        // never exist reports the class gap and this one, and this is the
        // sharper of the two: nothing a reader does about coverage moves a
        // class the build or the host cannot produce.
        gaps.insert(
            0,
            if requested.is_empty() {
                format!(
                    "entity_index_unresolved: {cause}, so nothing resolves the program behind its \
                 parsed declarations, and an empty name/kind filter cannot separate a declaration \
                 the repository does not have from one the extractor did not admit as an entity \
                 of that kind"
                )
            } else {
                format!(
                "reference_enrichment_unsupported: {cause}, so an empty result cannot separate a \
                 symbol nothing uses from one this graph could never have linked"
            )
            },
        );
    }

    // FIR-2496, and the gate every other one in this function was standing in
    // for. An observation that measured no coverage class states nothing about
    // what the extractor admitted, and nothing observed is not the same fact as
    // every input agreeing. Until FIR-2496 an empty class map read as the
    // second: on the v0.5.43 stranger run `semantic_search("SCHEMA")` and
    // `semantic_search("build_match_query")` both returned zero over
    // `"classes": {}` and both certified `safe_to_conclude_absent: true`,
    // `trust: "authoritative"`, `limiting_factor: null`. `SCHEMA` was a
    // module-level constant at `storage.py:24` that the Python extractor skips
    // because it is a triple-quoted string, sitting between two one-line
    // constants the same file's parse admitted (FIR-2509), and
    // `build_match_query` was a function in a file the graph had not admitted at
    // all. Neither was absent from the repository. Both were absent from the
    // index, which is the one thing an unmeasured class map cannot tell apart.
    //
    // It reads the observation rather than the tool name, so it is not a
    // blocklist: a producer that measures a class for this scope lifts the
    // refusal by publishing the measurement, and no producer does today. The
    // requested-class tools are excluded because the block above already reports
    // their unmeasured classes by name, and one fact stated twice in one reason
    // is not stated better.
    //
    // Last in the list on purpose. Every gap above is a positive finding about a
    // measured thing, and a sharper reason has to lead a composed one; this is
    // the reason that applies when nothing sharper was observed.
    //
    // Fires only on a real language, for the reason the enrichment gate above
    // fires only on a positive finding: an answer that resolved no language has
    // no language's extractor coverage to be missing, and a sentence about one
    // would displace the reason such an answer actually carries, which is that
    // its focal is not in the graph or that its filter selected an empty region.
    // Both of those are reported by name, so nothing here is left ungated.
    if coverage_classes_unmeasured(coverage, &requested) {
        gaps.push(if claims_absence {
            format!(
                "absence_coverage_unmeasured: no coverage class was measured for {language}, so \
                 nothing established what the extractor admitted for it, and an empty result \
                 cannot be separated from a declaration the extractor never admitted as an entity \
                 or from a file the graph does not hold yet"
            )
        } else {
            format!(
                "answer_coverage_unmeasured: no coverage class was measured for {language}, so \
                 the rows here are a floor and a declaration the extractor never admitted could \
                 not be among them"
            )
        });
    }

    gaps
}

/// Whether this response asserts that something is NOT there, as opposed to
/// returning rows and leaving the question of how complete they are.
///
/// One definition, read by [`absence_coverage_gap`] so a coverage limit is
/// stated against the claim the answer actually made, and by [`negative_for`] so
/// the two cannot drift. Before FIR-2496 the gate had no idea which it was
/// looking at, so an answer with rows was handed a sentence about what an empty
/// result cannot be distinguished from, and three empty answers beside it were
/// handed nothing at all.
///
/// The reading is the spec's: a tool whose spec `always` qualifies is making a
/// per-row verdict claim (`bulk_check_references`, `impact_analysis`), a locate
/// page whose ranking names nothing is claiming the name is not there, and every
/// other tool claims an absence exactly when its answer group came back empty. A
/// tool with no spec claims nothing, because this module does not qualify it.
///
/// An answer group the payload does not carry reads as an absence claim, which
/// is [`negative_for`]'s own reading of the same shape: an omitted group makes
/// the same claim as an empty one and is the more dangerous of the two, since a
/// missing key reads as a question the tool does not answer. Only a group that
/// is present and populated makes this false, so the rows phrasing is reached
/// from evidence of rows rather than from the absence of evidence.
fn answer_claims_absence(tool: &str, payload: &Value) -> bool {
    let Some(spec) = spec_for(tool) else {
        return false;
    };
    // A walk that expanded edges is reporting what it found, whatever its
    // entity collection reads: `graph_neighborhood` returns the focal itself in
    // that collection, so the count alone cannot tell a populated walk from an
    // isolated focal. `relation_count` can.
    if tool == "graph_neighborhood"
        && payload
            .get("relation_count")
            .and_then(Value::as_u64)
            .is_some_and(|total| total > 0)
    {
        return false;
    }
    if spec.always {
        return true;
    }
    if tool == "semantic_locate" {
        if locate_empty_window_over_nonempty_ranking(payload) {
            return false;
        }
        return locate_result_count(payload).is_none_or(|count| count == 0)
            || locate_ranking_names_nothing(payload);
    }
    collection_len(payload, spec.field).is_none_or(|count| count == 0)
}

/// Whether a POPULATED answer from `tool` carries the response's verdict too,
/// or only its empty answers do.
///
/// FIR-2463 asked for one verdict on every retrieval response, and the default
/// here is yes: an answer that returned rows and says nothing about how far they
/// can be trusted is the shape that let `graph_neighborhood` frame two inbound
/// edges as the whole set while `find_references` refused to certify the same
/// entity over the same edges. An answer with no epistemic claim is not
/// agreement with the tool beside it, it is a missing claim.
///
/// The exemptions are listed rather than left to whichever handler was edited
/// last, because an accidental exemption is exactly how that shape shipped.
///
/// | tool | qualifies a populated answer | why |
/// |---|---|---|
/// | `find_references`, `bulk_check_references`, `trace_data_flow`, `graph_neighborhood`, `semantic_search`, `find_dead_code_seeded`, `get_context_pack` | yes | each answers from the graph, and whether its rows are the whole set is exactly the question a caller acts on |
/// | `semantic_locate` | NO | its page is a bounded ranking rather than an enumeration, so its verdict can never be authoritative at any coverage, and the module already refuses to certify one. Attaching a verdict to every page is the defect FIR-2430 found wearing the opposite costume: a real symbol and a fabricated one came back under the IDENTICAL envelope, so a qualifier there teaches a reader to read a page as a graph claim when it is not one |
/// | `entity_history` | NO | reads recorded change history, where a populated answer is the history and there is no whole-set question about the graph to answer |
/// | `dead_code` | NO | its result is the INVERSE claim, and rows are candidates to check rather than an answer whose completeness licenses an action |
///
/// An exemption bars the verdict from `negative` only. `_kin.verdict` is still
/// computed and published for these tools when any input spoke, so the one
/// verdict is never absent, only carried in one place instead of two.
fn qualifies_populated_answers(tool: &str) -> bool {
    !matches!(tool, "semantic_locate" | "entity_history" | "dead_code")
}

/// Whether `tool` declares anything [`absence_coverage_gap`] can gate, so a
/// `None` from that gate means "every dependency it declared was observed
/// present" rather than "it declared none".
///
/// The distinction is what stops [`crate::verdict`] certifying a response on no
/// evidence. A tool that reads neither cross-file edges nor a language's
/// extracted graph has nothing for this gate to say, and silence is not
/// agreement.
pub(crate) fn declares_absence_dependency(tool: &str, payload: &Value) -> bool {
    !absence_cross_file_classes(tool, payload).is_empty()
        || absence_is_language_scoped(tool)
        || tool == FILE_ENTITIES_TOOL
}

/// Whether this observation measured no coverage class at all for a language it
/// named, which is the state FIR-2496 found certifying absences.
///
/// Three readers ask the same question and one answer serves them:
/// [`absence_coverage_gap`] refuses the certification,
/// [`edge_coverage_degradation_labels`] discloses the shortfall beside it, and
/// [`crate::verdict`] records the coverage input's own reading. A reason with no
/// signal beside it, or a signal with no reason, is the drift this module keeps
/// catching, so the three read one function rather than three copies of a
/// condition.
///
/// Scoped to an observation that named a language and declared no edge class.
/// The class-declaring tools report their unmeasured classes by name one gate
/// above, and an answer that resolved no language has no language's extractor
/// coverage to be missing.
pub(crate) fn coverage_classes_unmeasured(
    coverage: &Map<String, Value>,
    requested: &[String],
) -> bool {
    if !requested.is_empty() {
        return false;
    }
    let named = coverage
        .get("language")
        .and_then(Value::as_str)
        .map(str::trim)
        .is_some_and(|language| {
            !language.is_empty() && language != crate::edge_coverage::NO_RESOLVED_LANGUAGE
        });
    named
        && coverage
            .get("classes")
            .and_then(Value::as_object)
            .is_none_or(Map::is_empty)
}

/// One class's observed state, defaulting to `unknown` for a class the
/// observation does not mention. An unmentioned class is one nothing was
/// established about, which is the conservative reading and the one the module's
/// honesty contract already takes for unknown coverage.
fn class_state<'a>(states: Option<&'a Map<String, Value>>, class: &str) -> &'a str {
    states
        .and_then(|states| states.get(class))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
}

/// The classes among `classes` observed in `state`, in the order the query asked
/// for them.
fn classes_in_state<'a>(
    classes: &'a [String],
    states: Option<&Map<String, Value>>,
    state: &str,
) -> Vec<&'a str> {
    classes
        .iter()
        .filter(|class| class_state(states, class) == state)
        .map(String::as_str)
        .collect()
}

/// Every coverage shortfall this answer's own `edge_coverage` names, as
/// `component:reason` labels for [`degraded_signals`].
///
/// The verdict consumes the load-bearing classes; this consumes all of them. A
/// negative reading "no degraded signals" beside an `edge_coverage` naming two
/// absent classes is the contradiction the whole module exists to prevent, and
/// it does not stop being one because the classes that were absent happened not
/// to be the ones that decided the verdict. An authoritative absence with
/// `edge_coverage:references_absent` beside it is saying something exact: the
/// graph links calls and imports across files, it holds no reference edges, and
/// the claim rests on the first fact rather than the second.
pub(crate) fn edge_coverage_degradation_labels(tool: &str, payload: &Value) -> Vec<String> {
    let requested = absence_cross_file_classes(tool, payload);
    let language_scoped = absence_is_language_scoped(tool);
    if requested.is_empty() && !language_scoped {
        return Vec::new();
    }
    let Some(coverage) = payload
        .get(crate::edge_coverage::EDGE_COVERAGE_KEY)
        .and_then(Value::as_object)
    else {
        return vec![if requested.is_empty() {
            "absence_coverage:unreported".to_string()
        } else {
            "edge_coverage:unreported".to_string()
        }];
    };
    let states = coverage.get("classes").and_then(Value::as_object);
    let mut labels: Vec<String> = requested
        .iter()
        .filter_map(|class| match class_state(states, class) {
            "present" => None,
            state => Some(format!("edge_coverage:{class}_{state}")),
        })
        .collect();
    if coverage_classes_unmeasured(coverage, &requested) {
        labels.push("absence_coverage:classes_unmeasured".to_string());
    }
    if coverage.get("scope_entities").and_then(Value::as_u64) == Some(0) {
        labels.push("absence_coverage:scope_empty".to_string());
    }
    if matches!(
        coverage.get("reference_enrichment").and_then(Value::as_str),
        Some("unsupported") | Some("no_language_server")
    ) {
        labels.push("edge_coverage:reference_enrichment_unsupported".to_string());
    }
    // Disclosed on the same terms as the two above: what the verdict rests on is
    // named in the signals beside it, so a reader never has to parse the reason
    // sentence to learn that the name matched and a narrowing filter is what
    // emptied the answer.
    if coverage
        .get(crate::edge_coverage::NAME_FILTER_KEY)
        .and_then(Value::as_object)
        .and_then(|name_filter| name_filter.get("candidates"))
        .and_then(Value::as_u64)
        .is_some_and(|candidates| candidates > 0)
    {
        labels.push("absence_coverage:name_filter_narrowed".to_string());
    }
    labels
}

/// Add one gap to the running verdict: the reason a gap names replaces a
/// substrate reason that certified authority, and follows one that already
/// reported a gap, so the composed reason reads limiting-factor-first and never
/// drops a fact that was already true.
///
/// Every gate in [`negative_for`] goes through this rather than assigning
/// `trust_reason` directly. Direct assignment is how a cross-repo topology note
/// came to overwrite the reason an absence was actually limited by, leaving a
/// correct verdict beside an unrelated explanation.
/// Host content on disk that no admission has taken, which no absence claim can
/// see past.
///
/// The store answered from graph truth, and graph truth does not carry these
/// paths at all. A symbol defined only inside one of them is missing from every
/// index the query reads, so the answer is right about the graph and wrong about
/// the repository. That is how `semantic_search` returned
/// `safe_to_conclude_absent: true` for a function sitting in a 140-line module
/// on disk, with `durability` in the same payload reading "0 uncommitted"
/// (FIR-2499).
///
/// Silence here is the absence of a reading, never an all-clear: the envelope
/// carries this object only when the runtime reported that the store is behind,
/// and a runtime that reported no reconcile block at all is already refused by
/// the runtime gates above.
fn unadmitted_host_content_gap(envelope: &Envelope) -> Option<String> {
    Some(envelope.behind.as_ref()?.limiting_factor())
}

fn push_gap(trustworthy: &mut bool, trust_reason: &mut String, gap: String) {
    *trust_reason = if *trustworthy {
        gap
    } else {
        format!("{trust_reason}; {gap}")
    };
    *trustworthy = false;
}

/// Number of items in the tool's result collection within `payload`, or `None`
/// when the expected collection is absent or not an array (in which case no
/// negative is synthesized — we never guess emptiness).
/// Whether `payload` is a real answer from `tool` that simply left its answer
/// group out, as opposed to a payload this module has no business qualifying.
///
/// Absence of the key is not enough on its own: an error object is also missing
/// it, and qualifying one would report a verdict about a graph nobody queried.
/// The gate is the marker that the tool did produce an answer. For a context
/// pack that is `focal_entity`, which is the pack's whole reason to exist and is
/// present in every mode.
fn omits_its_answer_group(tool: &str, payload: &Value) -> bool {
    match tool {
        "get_context_pack" => payload
            .get("focal_entity")
            .is_some_and(|focal| !focal.is_null()),
        _ => false,
    }
}

fn collection_len(payload: &Value, field: &str) -> Option<usize> {
    if field.is_empty() {
        payload.as_array().map(Vec::len)
    } else {
        payload.get(field).and_then(Value::as_array).map(Vec::len)
    }
}

/// Rows a `semantic_locate` page actually returned, whichever arm answered.
///
/// The two arms publish their hits under different keys, and the negative
/// contract used to be written against the cosine arm's alone. The fused arm
/// serializes a `LocateResult`, whose `entities` field is skipped when empty, so
/// the exact page that most needs qualifying — a fused answer with nothing in it
/// — carried neither an `entities` key nor a `results` one. [`collection_len`]
/// therefore returned `None` and the whole payload was skipped, leaving an empty
/// fused page reading as a bare, unqualified negative on the arm that serves
/// every code-bearing store by default.
///
/// `files` is the discriminator rather than `entities`: `LocateResult`
/// serializes it unconditionally, so its presence as an array is what proves a
/// fused locate payload is in hand and an absent `entities` means "empty" rather
/// than "not this shape". Absence is still never guessed — a payload carrying
/// neither key returns `None` exactly as before.
///
/// The declared granularity selects the primary collection. A file page counts
/// `files` on either arm; an entity page counts `entities` on fused and
/// `results` on cosine. Secondary roll-ups do not turn an empty primary page
/// into a non-empty answer.
fn locate_result_count(payload: &Value) -> Option<usize> {
    let count = locate_primary_count(payload)?;

    // A continuation page cannot prove absence from a non-empty held ranking.
    // Cache-backed daemon paths reject this shape before serialization, but the
    // response envelope remains defensive because older daemons and alternate
    // producers can still hand it an empty window with a positive total. Treat
    // that contradiction as unknown rather than stamping `no_ranked_match`.
    (!locate_empty_window_over_nonempty_ranking(payload)).then_some(count)
}

/// Rows in the response's declared primary locate collection, before applying
/// cross-field consistency checks.
fn locate_primary_count(payload: &Value) -> Option<usize> {
    // Which collection is the answer is decided in one place, by the budget's
    // own rule, and read here. This block and the response budget's ladder used
    // to derive it separately, from slightly different rules, so a payload
    // existed for which the ladder cut one collection while this counted
    // another.
    let primary = crate::budget::primary_collection_for(payload, "semantic_locate")?;
    match collection_len(payload, primary) {
        Some(count) => Some(count),
        // A producer that omitted its empty primary still proves the locate
        // shape through `files`, which `LocateResult` serializes whatever it
        // holds. An absent primary there is zero rows. A payload carrying
        // neither is not a locate response, and its count stays unknown rather
        // than being guessed at zero.
        None => collection_len(payload, "files").map(|_| 0),
    }
}

fn locate_empty_window_over_nonempty_ranking(payload: &Value) -> bool {
    locate_primary_count(payload) == Some(0)
        && payload
            .get("total_ranked")
            .and_then(Value::as_u64)
            .is_some_and(|total| total > 0)
}

/// True when a query token is identifier-shaped: the caller named a symbol
/// rather than describing one in prose.
///
/// Deliberately narrower than the `is_symbolic_search_term` rule `kin-cli` uses
/// to distill retrieval variants, and deliberately a separate copy: this one
/// gates a claim in the response, never a ranking input, so it must not be able
/// to drift into retrieval by being shared with it. Hyphens are excluded because
/// ordinary prose hyphenates, and a rule that reads `graph-native` as a symbol
/// name would qualify half of all English queries.
///
/// Capitals alone are excluded for the same reason, and that exclusion is the
/// difference between this gate covering real questions and exempting most of
/// them. Counting capitals alone made `JSON` a named symbol, so "send a JSON
/// response body to the client" was routed to the symbol gate beside this one,
/// which asks a different question and fires only on the whole-ranking
/// `all_fallback` flag that a paged answer often does not carry. The measured
/// consequence was that the identical page of fallback neighbours certified
/// under that phrasing, and HTTP, API, URL, SQL, HTML, XML, UUID, DNS and TLS
/// did it too. Mixed case is what separates a name from an abbreviation, and a
/// token carrying an underscore, a dot or a path separator stays a symbol
/// whatever its case, so `MAX_RETRIES`, `README.md`, `IOError` and
/// `HTTPServer` are all still symbol lookups.
fn query_names_a_symbol(query: &str) -> bool {
    query.split_whitespace().any(|token| {
        let core = token.trim_matches(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'));
        core.len() >= 3
            && (core.contains('_')
                || core.contains("::")
                || core.contains('.')
                || (core.chars().filter(|ch| ch.is_ascii_uppercase()).count() >= 2
                    && core.chars().any(|ch| ch.is_ascii_lowercase())))
    })
}

/// True when the query named a symbol and nothing in the ranking carries that
/// name — a populated page that is not the answer it looks like.
///
/// Cosine ranking always returns its best candidates, so a query for a symbol
/// that exists nowhere comes back as a full page of confidently-scored hits that
/// is indistinguishable, field for field, from a page that found the symbol. The
/// scores cannot separate them: they are ranks within a result set, not evidence
/// that anything matched.
///
/// The verdict is read from what the answer publishes about its FULL ranking,
/// never from the page alone, because a page is a window: an exact name match
/// sitting on page two would otherwise be reported as absent from the whole
/// ranking.
///
/// `all_fallback` IS that published verdict. Both arms compute it over the whole
/// retained ranking before the daemon windows a page, with the same rule, and
/// both omit the field when it is false, so its presence is authoritative and
/// routing does not enter into it.
///
/// A payload carrying no `all_fallback` at all is an older daemon that never
/// published one, and only there is the fact inferred from the page: every row's
/// `match_evidence.name_match` is inspected, and only when the page holds the
/// entire ranking. A row that reports no `match_evidence` leaves the question
/// unanswered, so nothing is qualified, which is the same refusal to guess the
/// rest of the module makes.
///
/// The inference cannot be the primary reading, because the condition it needs
/// is one a real store almost never meets. `total_ranked` grows with the
/// requested limit, so the page covers the ranking only when the ranking
/// collapses to a degenerate row or two. A fabricated symbol measured at limit 8
/// ranked 1 and carried the disclosure; the same symbol at limit 50 ranked 56
/// and carried none. Asking for more results removed the honesty envelope, which
/// left the guard present in the one case nobody queries and absent in every
/// case they do.
fn locate_ranking_names_nothing(payload: &Value) -> bool {
    if !payload
        .get("query")
        .and_then(Value::as_str)
        .is_some_and(query_names_a_symbol)
    {
        return false;
    }
    if let Some(all_fallback) = payload.get("all_fallback").and_then(Value::as_bool) {
        return all_fallback;
    }
    if payload.get("routing").and_then(Value::as_str) == Some("fused-v1") {
        return false;
    }
    let Some(rows) = payload.get("results").and_then(Value::as_array) else {
        return false;
    };
    let whole_ranking = payload
        .get("total_ranked")
        .and_then(Value::as_u64)
        .is_some_and(|total| total <= rows.len() as u64);
    whole_ranking
        && !rows.is_empty()
        && rows.iter().all(|row| {
            row.get("match_evidence")
                .and_then(|evidence| evidence.get("name_match"))
                .and_then(Value::as_str)
                .is_some_and(|name_match| name_match != "exact")
        })
}

/// True when locate returned only fallback neighbours for a prose query.
///
/// Two triggers, and neither guesses. `all_fallback` is the producer's verdict
/// over the full retained ranking, computed before the daemon windows a page.
/// [`locate_returned_rows_are_all_fallback`] asks the same question of the rows
/// this response actually returned, which is the only surface the caller can
/// check, and it is what stops one name hit ranked off the page from certifying
/// a page of neighbours. A prose query does not name a symbol whose absence can
/// be checked. The relevant fact is instead that the ranking has no calibrated
/// floor saying any returned row answers the concept the caller described.
///
/// This gate replaced one that deliberately said the opposite, and that
/// argument is answered rather than dropped. It held that `all_fallback` fires
/// on prose queries whose top hits are correct, so a qualifier there is one an
/// agent learns to ignore. True of the [`locate_ranking_names_nothing`] wording
/// beside it, which asserts a named symbol was not found and would be a false
/// statement over a correct hit. It is not true of this one, which asserts only
/// that the ranking publishes no measured relevance threshold. That sentence is
/// exactly as true over a correct top hit as over a wrong one, which is the
/// whole reason the answer cannot be certified: nothing in the response can
/// tell the two apart. So the block says `relevance_unverified` and
/// `nearest_neighbors_only`, never that the concept is absent.
///
/// Answered HERE, at the absence gate, and not by folding the producer's
/// `query_shape` degradation into the run-quality verdict. That exemption is
/// correct and stays: the run lost no capability, embeddings ranked, and
/// [`describes_advice_not_run_quality`] keeps a query's shape out of a verdict
/// about how well the query ran. How far the returned rows can be trusted is
/// this gate's question, not that one's.
fn locate_relevance_unverified(payload: &Value) -> bool {
    let Some(query) = payload.get("query").and_then(Value::as_str) else {
        return false;
    };
    if query_names_a_symbol(query) {
        return false;
    }
    payload.get("all_fallback").and_then(Value::as_bool) == Some(true)
        || locate_returned_rows_are_all_fallback(payload)
}

/// True when every row THIS RESPONSE returned is a fallback neighbour.
///
/// The second trigger, and it exists because `all_fallback` answers a different
/// question than the one this gate asks. That flag is a verdict over the WHOLE
/// retained ranking, which is right for [`locate_ranking_names_nothing`]: an
/// exact name sitting on page two means the ranking did carry the symbol, so
/// claiming it names nothing would be false. This gate asks how far the rows the
/// caller RECEIVED can be trusted, and a row the caller never saw establishes
/// nothing about them.
///
/// Measured on express at 798 of 798 embedded. "attach an encoding label to a
/// media type string" returned eight rows, every one of them a lexical fallback
/// neighbour scoring 52.05 down to 52.02, and `setCharset`, which does exactly
/// what the query describes, was not in the ranking at limit 8 or limit 40. The
/// response certified with a null limiting factor, because one row of the 31 the
/// ranking held did carry `match_kind: name` (the kinds over that ranking were
/// text_fallback 28, name 1, semantic 2), so the producer omitted `all_fallback`
/// and both locate gates read `None`. In the same session a concept query whose
/// rows were all VECTOR neighbours, scoring 96.28 down to 94.41, was correctly
/// inconclusive. The answer with the higher scores was qualified and the
/// 52-point lexical one was certified.
///
/// A strict widening: it adds a trigger and removes none, so nothing that fires
/// today stops firing.
///
/// A name match is NOT discounted for resting on an ordinary English word, even
/// though the row that silenced this gate on express was one. Two of the tool's
/// best answers are that shape: `app.render` for "render a view template with a
/// layout" and `res.json` for "send a JSON response body to the client" are both
/// name matches on a plain lowercase token, both first row, both right. A
/// returned name row IS the calibrated floor a locate response publishes, and
/// the defect is that a name row the caller cannot see was allowed to stand in
/// for one. Telling `app.render` from a question's stray word is a ranking
/// judgment and belongs where ranking is decided.
fn locate_returned_rows_are_all_fallback(payload: &Value) -> bool {
    let Some(primary) = crate::budget::primary_collection_for(payload, "semantic_locate") else {
        return false;
    };
    let Some(rows) = payload.get(primary).and_then(Value::as_array) else {
        return false;
    };
    // An empty page is not all-fallback: nothing was returned, so there is
    // nothing to mistake for an answer, and the empty-window and no-ranked-match
    // gates are what speak to it. Both `all_fallback` producers state the same
    // rule, and stating it differently here is how two readings of one question
    // start disagreeing.
    !rows.is_empty()
        && rows
            .iter()
            .all(|row| locate_row_names_the_query(row) == Some(false))
}

/// Whether one returned row carries a name the query used: `None` when the row
/// reports nothing that answers the question.
///
/// Three spellings, one fact. `match_kind` is what the full fused surface and
/// the cosine arm write, `matched` is what the compact projection writes, and
/// the compact surface is the one an agent actually receives, so a rule reading
/// only the first would be absent from every response that matters. Both carry
/// `LocateMatchKind`'s own serialization, so the two spellings cannot disagree
/// about a word. `match_evidence.name_match` is the cosine evidence object,
/// which reports the same fact under its own name and whose `exact` is the value
/// [`locate_ranking_names_nothing`] already reads.
///
/// `None` is a third answer and not a shade of either. A record from a daemon
/// predating these fields, and a file-granularity row, which carries no match
/// kind at all because `files[]` is a path roll-up, both land here, and the
/// caller treats an unanswered row as reason to qualify nothing. That is the
/// same refusal to guess the page inference above makes, and it is what keeps a
/// successful file answer out of a gate about entity naming.
fn locate_row_names_the_query(row: &Value) -> Option<bool> {
    if let Some(kind) = row
        .get("match_kind")
        .or_else(|| row.get("matched"))
        .and_then(Value::as_str)
    {
        return Some(kind == "name");
    }
    row.get("match_evidence")
        .and_then(|evidence| evidence.get("name_match"))
        .and_then(Value::as_str)
        .map(|name_match| name_match == "exact")
}

/// The wire word for the one embedding verdict, so the absence object and the
/// completeness block publish the same vocabulary for the same fact.
fn embedding_state_word(coverage: &crate::envelope::SemanticCoverage) -> &'static str {
    use crate::envelope::EmbeddingState;
    match coverage.embedding_state() {
        EmbeddingState::Present => "present",
        EmbeddingState::Partial => "partial",
        EmbeddingState::Absent => "absent",
        EmbeddingState::Unknown => "unknown",
    }
}

/// Render the envelope's embedding coverage as a compact, agent-readable object
/// (with a rounded percentage), or `Value::Null` when coverage is unknown.
fn coverage_value(envelope: &Envelope) -> Value {
    match &envelope.semantic_coverage {
        Some(coverage) => {
            let percent = if coverage.total == 0 {
                100.0
            } else {
                (coverage.indexed as f64 / coverage.total as f64) * 100.0
            };
            let mut rendered = json!({
                "indexed": coverage.indexed,
                "total": coverage.total,
                "pending": coverage.pending,
                "complete": coverage.complete,
                // The one embedding verdict, beside the counters a reader would
                // otherwise have to derive one from. `complete` is a
                // conjunction and a reader deriving an embedding state from it
                // gets `absent` on a fully embedded store (FIR-2543).
                "embedding_state": embedding_state_word(coverage),
                "percent": (percent * 10.0).round() / 10.0,
            });
            // Never fabricated: absent stays absent, so a reader can tell a
            // producer that did not report a read time from one that did.
            if let Some(read_at) = coverage.read_at.as_ref() {
                rendered["read_at"] = json!(read_at);
            }
            rendered
        }
        None => Value::Null,
    }
}

/// What an empty neighborhood means for the side that was actually walked.
/// Direction became a parameter when the traversal stopped being outgoing-only,
/// and an absence inherits it: an incoming-only walk that comes back empty is
/// evidence about dependents and says nothing about the focal's dependencies.
/// A payload without a direction gets the unnarrowed wording rather than a
/// guess.
fn neighborhood_absence_subject(payload: &Value) -> Option<&'static str> {
    match payload.get("direction").and_then(Value::as_str)? {
        "in" => Some(
            "the entity has no dependents at the requested depth; its dependencies were not walked",
        ),
        "out" => Some(
            "the entity has no dependencies at the requested depth; its dependents were not walked",
        ),
        "both" => {
            Some("the entity has no graph neighbors in either direction at the requested depth")
        }
        _ => None,
    }
}

/// What an empty chain means for the side of the flow that was actually
/// walked. A callers-only walk that comes back empty is evidence about what
/// reaches the focal and says nothing about what the focal reaches, so the
/// merged wording would claim a direction the traversal never followed. A
/// payload without a direction keeps the unnarrowed wording rather than a guess.
fn trace_absence_subject(payload: &Value) -> Option<&'static str> {
    match payload.get("direction").and_then(Value::as_str)? {
        "calls" => Some(
            "no data-flow chain was found from the focal entity to anything it calls; its callers were not walked",
        ),
        "callers" => Some(
            "no data-flow chain was found into the focal entity from anything that calls it; its callees were not walked",
        ),
        "both" => Some(
            "no data-flow chain was found from the focal entity in either direction",
        ),
        _ => None,
    }
}

/// Every reason an empty trace chain is unsafe to read as "nothing flows here",
/// in a stable order. All that apply are reported: an absence with two causes
/// has two, and naming only the first hands back a narrower explanation than
/// the evidence supports.
///
/// The gates mirror the ones `find_references` already applies, because both
/// tools answer from the same typed `Calls`/`Imports`/`References` edges and an
/// absence over those edges is trustworthy under the same conditions for both.
/// `trace_data_flow` used to skip all of them and certify absence on nothing but
/// the substrate gate, which is how an entity with a live caller came back
/// authoritative-absent.
/// The gap a response's own `focal_resolution` names, phrased for the shape of
/// answer that carries it.
///
/// Shared, because two tools resolve a focal the same way and must not qualify
/// it differently. `trace_data_flow` has always refused to certify a walk whose
/// focal name the graph holds twice; `find_references` published the identical
/// resolution block and read nothing from it, so on pallets/flask it stamped an
/// answer describing one of three same-named methods as complete and exact
/// (FIR-2475). One resolution, one verdict about it.
///
/// `subject` names what the answer is, so the sentence reads about a chain or a
/// reference list rather than about "the answer" in both.
fn focal_resolution_gap(payload: &Value, subject: &str) -> Option<String> {
    // A missing block is the `None` arm, not an exemption. Both tools publish
    // one on every answer, so its absence means the resolution went unreported
    // rather than that this response has no focal to resolve, and reading it as
    // an exemption would let exactly the answers that say least certify most.
    let resolution = payload.get("focal_resolution").unwrap_or(&Value::Null);
    match resolution
        .get("same_name_candidates")
        .and_then(Value::as_u64)
    {
        None => Some(format!(
            "focal_resolution_unreported: this answer did not report how many entities the \
             focal could have been resolved from, so {subject} may describe a same-named \
             sibling rather than the entity that was asked about"
        )),
        Some(candidates) if candidates > 1 => {
            // A focal the caller pinned to one entity was not resolved from
            // anything, so there is no resolution to qualify. See
            // [`focal_pinned_to_one_entity`] for why both halves of that are
            // required and what this deliberately stops claiming.
            if focal_pinned_to_one_entity(resolution) {
                return None;
            }
            // Which rule produced the count decides what the gap is ABOUT: a
            // query that matched several entities is an ambiguous question,
            // while several entities carrying one exact name is an ambiguous
            // graph. Reporting either as the other sends a reader to fix the
            // wrong end.
            let counted = resolution
                .get("matched")
                .and_then(Value::as_str)
                .unwrap_or("exact_focal_name");
            // A pattern match and a name collision are different situations and
            // the old wording described the milder one in the vocabulary of the
            // worse. `find_references("slugify")` reported "3 entities match the
            // name that was queried" where one entity is NAMED slugify and two
            // are tests whose names merely contain it, which reads as three
            // same-named definitions: a much scarier thing than what happened
            // (FIR-3037). The response already carries the distinction in
            // `matched`; this says it.
            let clause = if counted == "query_name_pattern" {
                "matched the queried name as a pattern, which includes entities whose names \
                 merely contain it,"
            } else {
                "share the focal's name exactly, and"
            };
            Some(format!(
                "focal_resolution_ambiguous: {candidates} entities {clause} only one was \
                 answered for, so {subject} is not evidence about the others"
            ))
        }
        Some(_) => None,
    }
}

/// True when the caller pinned the focal to one entity by id AND the resolution
/// REPORTED, rather than omitted, that it had no other candidate.
///
/// Both halves are load-bearing. `addressed_by: "entity_id"` says the caller
/// named one UUID and the tool answered for that UUID: nothing was chosen, so
/// there is no choice to qualify, and "not evidence about the others" describes
/// a question nobody asked. A stranger addressing eleven exports by id got that
/// downgrade on seven of them because some other entity in the graph happened
/// to share the string `request`.
///
/// The reported-empty half is what says the producer LOOKED. A payload that
/// omits `other_candidates` made no claim about them, and reading a missing
/// field as an empty one is exactly the substitution the `unreported` arm above
/// exists to refuse. `trace_data_flow` publishes such a block, so the omission
/// is a live shape rather than a hypothetical, and it keeps the gap.
///
/// What this stops claiming, said plainly: a name the graph holds twice can
/// still cost a pinned focal an edge the extractor could not attribute to
/// either twin, so a pinned reference list is not thereby proven complete. That
/// is a bound on completeness, and it stays readable as
/// `focal_resolution.same_name_candidates` on the response. It is not
/// ambiguity, and the one verdict must not report it as ambiguity.
fn focal_pinned_to_one_entity(resolution: &Value) -> bool {
    resolution.get("addressed_by").and_then(Value::as_str) == Some("entity_id")
        && resolution
            .get("other_candidates")
            .and_then(Value::as_array)
            .is_some_and(|others| others.is_empty())
}

/// The limiting-factor id a spine-clipped trace reports under.
///
/// Spelled once so the gate, the clause and every test key on one string, the
/// way `caller_arrival` spells its own.
pub(crate) const TRACE_SPINE_CLIPPED_LIMITING_FACTOR: &str = "trace_spine_clipped";

fn trace_flow_gaps(payload: &Value) -> Vec<String> {
    let mut gaps = Vec::new();

    // Receiver-method calls (`x.method()`) are linked by bare name while method
    // entities are keyed by their qualified name, so a method's incoming `Calls`
    // edges are frequently dropped, which is the gate `find_references` already
    // applies. It bears on the walk only when the walk read incoming edges at
    // all, which an unreported direction cannot rule out.
    let direction = payload.get("direction").and_then(Value::as_str);
    let walked_callers = !matches!(direction, Some("calls"));
    if walked_callers && focal_is_method(payload) {
        gaps.push(kin_core::reference_coverage::method_absence_limiting_factor("an empty chain"));
    }

    // A name the graph holds more than once (the cfg-twin shape: two arms of the
    // same declaration admitted as distinct entities) means the walk followed
    // one of them, and an edge the extractor could not attribute to a single
    // candidate sits on neither. Certifying that as absence answers for every
    // twin a question that was asked of one.
    if let Some(gap) = focal_resolution_gap(payload, "an empty chain") {
        gaps.push(gap);
    }

    // Spine clipping supersedes the two general cap clauses below, and this is
    // the whole subject of FIR-2781. A cap at the end of a branch costs breadth
    // a reader can see missing; a cap the walk went on BENEATH hands back a route
    // that reads like the route while the neighbours it dropped were never
    // followed. Only the second makes "this chain does not contain X" mean
    // nothing at all, and it is the state in which a stranger walked `verify`
    // from `requests.get`, never reached `HTTPAdapter.send`, and would have
    // written that `verify` ends at `Session.send` had they trusted the answer.
    //
    // The walker already discloses this precisely, as a `fanout_cap` /
    // `spine_clipped` degradation whose detail says the absence proves nothing.
    // That sentence never reached the verdict: `trace_data_flow` is excluded by
    // name from the `retrieval_degraded` gap, on the correct ground that it
    // states its gaps in walk vocabulary here instead, and this function had no
    // spine clause. So the right sentence existed in a channel the verdict does
    // not read for this tool, and what a caller saw in `limiting_factor` was a
    // cap notice they could reasonably hear as a lower bound.
    let spine_clipped = payload
        .get("spine_clipped_steps")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if spine_clipped > 0 {
        gaps.push(spine_clipping_gap(payload, spine_clipped));
        return gaps;
    }

    // A walk cut short by its own caps or work ceilings stopped before it could
    // observe what it is being read as having ruled out.
    if payload.get("truncated").and_then(Value::as_bool) == Some(true) {
        gaps.push(
            "trace_walk_truncated: the walk hit a per-step or total cap, so it stopped before \
             examining everything an empty chain would have to rule out"
                .to_string(),
        );
    }
    if payload
        .get("degradations")
        .and_then(Value::as_array)
        .is_some_and(|degradations| !degradations.is_empty())
    {
        gaps.push(
            "trace_walk_degraded: the walk reported degradations, so it did not complete under \
             its own work bounds"
                .to_string(),
        );
    }

    gaps
}

/// The limiting factor for a chain the walk continued beneath a clipped node.
///
/// It ABSORBS the two clauses it supersedes rather than replacing them away: the
/// cap numbers `trace_walk_truncated` would have carried and the fact that the
/// walk ran degraded are both stated here, so no information dies with them. It
/// then adds the part neither could say, which is that the dropped set is drawn
/// from the same neighbourhood the question is about, so this chain not
/// containing a hop is not evidence that no such hop exists.
///
/// One clause, never several. Three sentences about one cap teach a reader to
/// skim all three, which is the flooring argument moved down to the clause
/// level: a caller reading one precise sentence acts on it, and a caller reading
/// two hedges tunes both out.
///
/// Every list inside this clause joins on ", " and never on "; ", which is
/// [`crate::verdict::CLAUSE_SEPARATOR`]. The vec this returns into is joined on
/// the separator by its caller, and that is correct, because those elements ARE
/// clauses; a separator INSIDE one clause is what reaches a reader as a labelled
/// clause plus an unlabelled fragment.
fn spine_clipping_gap(payload: &Value, spine_clipped: u64) -> String {
    let nodes = if spine_clipped == 1 { "node" } else { "nodes" };
    // The two facts the superseded clauses carried, absorbed rather than lost.
    let mut absorbed: Vec<String> = Vec::new();
    if let Some(dropped) = payload.get("steps_omitted").and_then(Value::as_u64) {
        if dropped > 0 {
            absorbed.push(format!("{dropped} step(s) were omitted from the response"));
        }
    }
    if payload.get("truncated").and_then(Value::as_bool) == Some(true) {
        absorbed.push("the walk hit a per-step or total cap".to_string());
    }
    if payload
        .get("degradations")
        .and_then(Value::as_array)
        .is_some_and(|degradations| !degradations.is_empty())
    {
        absorbed.push("the walk ran degraded under its own work bounds".to_string());
    }
    let carried = if absorbed.is_empty() {
        String::new()
    } else {
        format!(" ({})", absorbed.join(", "))
    };
    let crossing = match payload
        .get("spine_dropped_crossing_file")
        .and_then(Value::as_u64)
    {
        Some(count) if count > 0 => {
            format!(", {count} of the dropped neighbours lived outside the file that offered them")
        }
        _ => String::new(),
    };
    format!(
        "{TRACE_SPINE_CLIPPED_LIMITING_FACTOR}: the walk continued beneath {spine_clipped} \
         {nodes} whose fan-out the per-step cap had already cut{carried}{crossing}, so the \
         neighbours it dropped were never followed and this chain is one route among the ones \
         the cap happened to keep. It is NOT a lower bound on a complete search: a hop missing \
         from it was not looked for, so its absence is no evidence that the focal cannot reach \
         it, and no conclusion of the form \"X never reaches Y\" may be drawn from this answer. \
         Name the symbol you are after as `target` so the cap ranks toward it, or re-query the \
         clipped node with a larger `limit_per_step`"
    )
}

/// Stable label for guidance about a description-shaped query.
///
/// The names live here rather than at the surface that writes them because the
/// exemption below is what makes them meaningful, and a name that moved without
/// its exemption would silently start blocking absence claims.
pub const QUERY_SHAPE_COMPONENT: &str = "query_shape";
/// See [`QUERY_SHAPE_COMPONENT`].
pub const DESCRIPTION_ENTITY_RANKING_REASON: &str = "description_entity_ranking";

/// Whether a `component:reason` label advises how to read the result without
/// reporting that the run lost a capability.
///
/// Description-query guidance says no returned entity was literally named by
/// the query and points at file granularity. Every signal may still have run,
/// and rows marked `semantic` still prove vector evidence participated. Folding
/// this advice into the run-quality verdict would manufacture a degraded input
/// from a query shape while weakening no existing verdict input.
///
/// It stays in the payload's own `degradations[]`, where a caller reads it. This
/// only keeps it out of the run-quality verdicts below.
fn describes_advice_not_run_quality(label: &str) -> bool {
    label.split_once(':').is_some_and(|(component, reason)| {
        component == QUERY_SHAPE_COMPONENT && reason == DESCRIPTION_ENTITY_RANKING_REASON
    })
}

/// The degradations a retrieval payload reported about its OWN run, as stable
/// `component:reason` labels.
///
/// Query-shape guidance is excluded: it advises how to read the result and does
/// not report a capability failure. See [`describes_advice_not_run_quality`].
///
/// The envelope's [`Degraded`] flags describe the daemon; this array describes
/// the query that just ran, and the two are not the same fact. A locate page
/// that dropped forty ranked keys because the graph no longer holds the
/// entities behind them has degraded in a way no daemon flag reports, and
/// reading only the daemon flags is how a negative came to print "no degraded
/// signals" one field away from a populated `degradations[]` in the same
/// response.
///
/// An entry missing either half of its identity is skipped rather than
/// half-named: a label is a claim about what degraded, and `unknown:partial`
/// is not one.
///
/// [`Degraded`]: crate::envelope::Degraded
pub(crate) fn payload_degradation_labels(payload: &Value) -> Vec<String> {
    let Some(entries) = payload.get("degradations").and_then(Value::as_array) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(|entry| {
            let component = entry.get("component").and_then(Value::as_str)?;
            let reason = entry.get("reason").and_then(Value::as_str)?;
            Some(format!("{component}:{reason}"))
        })
        .filter(|label| !describes_advice_not_run_quality(label))
        .collect()
}

/// Every degraded signal that bears on this answer: the daemon's own flags
/// first, then the ones the payload reported about this query, then the coverage
/// shortfalls its own `edge_coverage` names, deduplicated and in a stable order.
///
/// The last group is why this takes the tool: which edge classes an answer
/// depends on is a per-tool fact, and a signal array that omitted them let a
/// negative say "no degraded signals" beside an observation naming two absent
/// classes (FIR-2404).
fn degraded_signals(tool: &str, payload: &Value, envelope: &Envelope) -> Vec<String> {
    let mut labels: Vec<String> = envelope
        .degraded
        .active_labels()
        .into_iter()
        .map(str::to_string)
        .collect();
    for label in payload_degradation_labels(payload)
        .into_iter()
        .chain(edge_coverage_degradation_labels(tool, payload))
    {
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    labels
}

/// Which substrate's completeness this verdict actually rests on.
///
/// Published beside the verdict because the pairing FIR-2430 objected to was a
/// true statement of the wrong fact: the express negative certified an absence
/// in the same sentence that read "semantic coverage unknown", and both halves
/// were accurate. Embedding coverage was never what backed that claim. A
/// negative that names its basis and recites THAT can no longer put an unknown
/// coverage beside a certification the coverage did not back.
fn coverage_basis(class: NegativeClass) -> &'static str {
    match class {
        NegativeClass::Semantic => "embeddings",
        NegativeClass::Structural => "graph_structure",
    }
}

/// The coverage the verdict rests on, as the clause [`build_advice`] recites.
///
/// The embedding wording is unchanged for the tools embedding coverage actually
/// gates. A structural claim recites the observation its own gate read, and when
/// no observation is in hand it recites the graph state the structural gate
/// checked, which is exactly as much as that verdict knows.
fn coverage_clause(class: NegativeClass, payload: &Value, envelope: &Envelope) -> String {
    match class {
        // A percentage recited off counters nobody could read is the structural
        // zero in prose: with no vector index attached, `embedding_status`
        // answers zero indexed for every retrievable object, and this clause
        // used to recite that as "semantic coverage 0.0%", which is a
        // measurement of a store nothing measured. The unknown state says so
        // instead (FIR-2543).
        NegativeClass::Semantic => match &envelope.semantic_coverage {
            Some(coverage)
                if coverage.embedding_state() == crate::envelope::EmbeddingState::Unknown =>
            {
                "semantic coverage unknown".to_string()
            }
            Some(coverage) if coverage.total > 0 => {
                let percent = (coverage.indexed as f64 / coverage.total as f64) * 100.0;
                format!("semantic coverage {percent:.1}%")
            }
            Some(_) => "semantic coverage complete".to_string(),
            None => "semantic coverage unknown".to_string(),
        },
        NegativeClass::Structural => structural_coverage_clause(payload, envelope),
    }
}

/// What a structural absence observed about the graph it is claiming over.
fn structural_coverage_clause(payload: &Value, envelope: &Envelope) -> String {
    if let Some(coverage) = payload
        .get(crate::edge_coverage::EDGE_COVERAGE_KEY)
        .and_then(Value::as_object)
    {
        let language = coverage
            .get("language")
            .and_then(Value::as_str)
            .filter(|language| !language.trim().is_empty())
            .unwrap_or("an unreported language");
        let classes = coverage
            .get("classes")
            .and_then(Value::as_object)
            .map(|states| {
                states
                    .iter()
                    .map(|(class, state)| {
                        format!("{class} {}", state.as_str().unwrap_or("unknown"))
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .filter(|rendered| !rendered.is_empty())
            .unwrap_or_else(|| "this answer reads no edge class".to_string());
        let enrichment = match coverage.get("reference_enrichment").and_then(Value::as_str) {
            Some("unsupported") => "no language-server adapter for it in this build",
            Some("available") => "a language server available for it",
            Some("no_language_server") => {
                "an adapter wired for it but no language server installed"
            }
            _ => "its language-server availability unprobed",
        };
        return format!("graph coverage for {language} ({classes}; {enrichment})");
    }
    match (
        envelope.graph_state.initialized,
        envelope.graph_state.loaded,
    ) {
        (Some(true), Some(true)) => "a graph reported initialized and loaded".to_string(),
        _ => "an unconfirmed graph state".to_string(),
    }
}

/// Finish a clean substrate reason by naming the degraded signals this response
/// actually publishes.
///
/// [`crate::envelope::Envelope::negative_trust`] can only see the daemon's own
/// flags, so it states the substrate verdict and stops. [`degraded_signals`]
/// publishes a wider set beside it: those flags, plus the payload's own
/// `degradations[]`, plus the coverage shortfalls the answer's `edge_coverage`
/// names. Letting the reason claim the wider silence shipped in v0.5.43 as
/// `trust_reason: "structural_authoritative: daemon graph initialized and loaded
/// with no degraded signals"` sitting one field away from
/// `degraded_signals: ["edge_coverage:imports_absent", "edge_coverage:references_absent"]`
/// on the same object (FIR-2505). That string was not a summary of the field
/// beside it, it contradicted it.
///
/// So the clause is computed from the published array rather than asserted
/// independently of it, which is the treatment [`build_advice`] already gives
/// the same fact in its own sentence. A verdict that recites its own disclosures
/// cannot be read as claiming there were none, and a reader who sees a
/// non-empty array is told in words why it did not move the verdict.
///
/// Applied only to a reason that survived every gate. Once a gap has fired,
/// [`push_gap`] has replaced the reason with the gap, and appending a silence
/// clause to a gap would qualify the wrong sentence.
fn qualify_clean_trust_reason(trust_reason: String, degraded_signals: &[String]) -> String {
    if degraded_signals.is_empty() {
        format!("{trust_reason}, with no degraded signals")
    } else {
        format!(
            "{trust_reason}; the disclosed signals [{}] were considered and are not load-bearing \
             for this claim",
            degraded_signals.join(", ")
        )
    }
}

/// A human sentence spelling out "absent as-of X, coverage Y%, degraded Z" and
/// the actionable consequence, so the negative is legible without cross-reading
/// the envelope. `subject` and `consequence` are passed rather than read off a
/// spec because a tool may narrow its own framing before the advice is built,
/// and because a name that never resolved carries a different consequence than
/// a lookup that ran and found nothing. `degraded` is passed for the same
/// reason: the payload's own degradations belong in the sentence, and only the
/// caller has the payload.
fn build_advice(
    subject: &str,
    consequence: &str,
    coverage: &str,
    envelope: &Envelope,
    degraded: &[String],
) -> String {
    let as_of = match &envelope.graph_as_of {
        Some(value) => format!("graph as-of {value}"),
        None => "an unversioned graph snapshot".to_string(),
    };
    let degraded = if degraded.is_empty() {
        "no degraded signals".to_string()
    } else {
        format!("degraded signals [{}]", degraded.join(", "))
    };

    format!("{subject}, against {as_of} with {coverage} and {degraded}. {consequence}")
}

/// The consequence sentence for a retrieval tool that ran and came back empty.
///
/// The untrustworthy arms prescribe nothing specific, because the advice is
/// finished by naming the gap that actually held (see
/// [`absence_advice_consequence`]). They
/// used to end with "re-check after embedding is complete", which is the wrong
/// instruction for every structural gap: a missing cross-file call edge is not
/// waiting on an embedding, and a reader who follows that advice re-runs the
/// query unchanged and gets the identical unusable answer.
fn absence_consequence(tool: &str, always: bool, trustworthy: bool) -> &'static str {
    // A certified name/kind filter is a statement about DECLARATIONS, and this
    // tool reads the entity index and traverses no edge at all
    // ([`absence_cross_file_classes`] gives it no class for exactly that
    // reason), so it has no basis for the word "unused". The generic sentence
    // supplied one anyway, and a stranger run quoted it back verbatim as the
    // thing it believed. Scoping it costs no authority: the verdict stays
    // authoritative and the fixture that must keep certifying still does.
    if tool == "semantic_search" && !always && trustworthy {
        return "Absence is authoritative for this filter: no declaration in the index carries \
                this name under it. That is a statement about declarations, not about use, \
                because this filter reads the entity index and traverses no edge; settle whether \
                anything references the name with find_references.";
    }
    match (always, trustworthy) {
        (true, true) => {
            "A `has_references: false` row here is an authoritative negative — safe to treat that entity as unreferenced."
        }
        (true, false) => {
            "Do NOT treat a `has_references: false` row as proof of disuse: a false verdict here may mean the batch could not observe what it was asked about."
        }
        (false, true) => "Absence is authoritative: safe to treat the target as genuinely absent/unused.",
        (false, false) => {
            "Absence is NOT authoritative: do not conclude the target is unused or deletable, because an empty result here may mean the query could not observe what it was asked about."
        }
    }
}

/// The consequence an absence carries, with the limiting factor named when there
/// is one.
///
/// A verdict and its cause belong in the same sentence a reader acts on. The
/// isolated-install report quoted the advice line verbatim as the thing it
/// believed, so an advice line that states the consequence and leaves the cause
/// in a neighbouring field is one field away from being acted on blind.
fn absence_advice_consequence(
    tool: &str,
    always: bool,
    trustworthy: bool,
    trust_reason: &str,
) -> String {
    let consequence = absence_consequence(tool, always, trustworthy);
    if trustworthy {
        consequence.to_string()
    } else {
        format!("{consequence} Limiting factor: {trust_reason}")
    }
}

/// The consequence an answer that RETURNED rows carries.
///
/// Separate from [`absence_advice_consequence`] because the two say opposite
/// things about the same verdict. On an empty answer an authoritative verdict
/// licenses concluding absence; on a populated one it licenses treating the rows
/// as the whole set and licenses no absence claim at all. Reusing the absence
/// wording here would put "safe to treat the target as genuinely absent" on an
/// answer holding results, which is the contradiction one field over.
fn populated_advice_consequence(trustworthy: bool, trust_reason: &str) -> String {
    if trustworthy {
        "These rows are the whole set: every input that could qualify this answer agreed. That \
         says nothing about anything absent from it."
            .to_string()
    } else {
        format!(
            "Treat these rows as a lower bound rather than the whole set, and do not conclude \
             anything from what is missing from them. Limiting factor: {trust_reason}"
        )
    }
}

/// The consequence sentence for a locate page that ranked hits but none the
/// query named. Distinct from [`absence_consequence`], which speaks about an
/// empty result: here the rows are real and stay ranked, and what is absent is
/// the NAME, so the advice has to separate "these are neighbors" from "the
/// symbol does not exist" instead of collapsing them into one verdict.
fn unnamed_ranking_consequence() -> &'static str {
    "These hits are neighbors, not the symbol: no ranked entity carries the name the query \
     asked for. That is a fact about this ranking, not about the graph, because a ranking is \
     a bounded candidate set and the name may belong to an entity it never considered. Do not \
     treat the top hit as the requested symbol, and do not conclude the symbol does not exist: \
     settle that with find_references or semantic_search, which resolve a name directly."
}

/// The consequence for a prose locate page containing fallback neighbours.
fn unverified_relevance_consequence() -> &'static str {
    "Inspect the returned code before treating these nearest neighbours as relevant. The ranking \
     has no calibrated relevance floor and returns candidates from any non-empty index, so do not \
     conclude the concept is absent or present from this page alone. Refine the query or confirm \
     the behavior through a graph surface that answers a concrete entity or relation question."
}

/// The kind the payload reports for its focal entity, whichever shape carries
/// it: `find_references` nests the focal under `focal_entity`, `trace_data_flow`
/// reports it flat as `focal_kind`.
fn focal_kind(payload: &Value) -> Option<&str> {
    payload
        .get("focal_entity")
        .and_then(|focal| focal.get("kind"))
        .or_else(|| payload.get("focal_kind"))
        .and_then(Value::as_str)
}

/// True when the payload's focal is a kind whose incoming call edges the linker
/// under-resolves, so absence must not be certified as authoritative.
///
/// The extraction above is payload plumbing, because two tools nest the focal
/// differently. The judgement itself is
/// [`kin_core::reference_coverage::kind_under_resolves_incoming_calls`], shared
/// with `kin dead-code`, which printed a delete list this gate would have
/// refused while the rule sat here where a CLI command could not read it
/// (FIR-2550).
fn focal_is_method(payload: &Value) -> bool {
    focal_kind(payload)
        .is_some_and(kin_core::reference_coverage::kind_name_under_resolves_incoming_calls)
}

/// What a cross-repo authority report says about the answer beside it.
///
/// A spine that is configured and did not answer limits the answer. A spine that
/// was never configured for this repository does not, and the two shared one
/// channel until FIR-2633: a single-repo install pushed a gap whose own producer
/// text ends "this is the ordinary single-repo state and says nothing about
/// references inside this repository", and that sentence was then quoted back as
/// the limiting factor that made the answer inconclusive. A limit the reader
/// cannot act on, describing a state the response already reports in full under
/// `cross_repo`, teaches the reader to discount every limit including the real
/// ones.
pub(crate) enum CrossRepoQualifier {
    /// The spine answered completely. Nothing to report.
    Complete,
    /// A configured spine failed, went stale, or answered incompletely. The
    /// answer is limited and the verdict follows.
    Gap(String),
    /// No spine is configured for this repository. Reported so a reader can see
    /// cross-repo authority was considered, and never as a limit.
    Note(String),
}

/// The qualifier an unavailable cross-repo answer earns, carrying the code of the
/// condition that held beside its human detail.
///
/// The producer names the condition that held under `code`, so the label is that
/// name rather than one catch-all. `cross_repo_unavailable` remains the label for
/// an answer carrying no code, because a reason with no computed condition behind
/// it must not be dressed up as one.
///
/// [`SPINE_REPO_UNREGISTERED`](crate::handlers::entities::SPINE_REPO_UNREGISTERED)
/// is the one code that is not a gap. The producer already separates it from
/// `SPINE_ROOT_STALE` at its own source (FIR-2353), so this reads a distinction
/// that exists rather than inventing one: an unregistered repository is the
/// ordinary state of a single-repo install, while every other code describes a
/// spine that IS configured and did not answer.
fn cross_repo_unavailable_qualifier(cross_repo: &Value) -> CrossRepoQualifier {
    let code = cross_repo.get("code").and_then(Value::as_str);
    let reason = cross_repo
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("the cross-repo spine could not answer");
    let qualifier = format!("{}: {reason}", code.unwrap_or("cross_repo_unavailable"));
    if code == Some(crate::handlers::entities::SPINE_REPO_UNREGISTERED) {
        CrossRepoQualifier::Note(qualifier)
    } else {
        CrossRepoQualifier::Gap(qualifier)
    }
}

/// The note a repository with no cross-repo spine configured earns.
///
/// Kept identical for both tools: it is one fact about the install, not about the
/// query, and two spellings of it would read as two conditions.
fn cross_repo_not_configured_note() -> CrossRepoQualifier {
    CrossRepoQualifier::Note(
        "cross_repo_not_configured: no cross-repo spine is configured, so this answer is \
         scoped to this repository"
            .to_string(),
    )
}

/// Route a cross-repo qualifier to the channel it belongs in.
///
/// A gap flips the verdict; a note never does. A note that could move the verdict
/// is a gap, and belongs in `trust_reason` instead.
fn apply_cross_repo_qualifier(
    qualifier: CrossRepoQualifier,
    trustworthy: &mut bool,
    trust_reason: &mut String,
    notes: &mut Vec<String>,
) {
    match qualifier {
        CrossRepoQualifier::Gap(reason) => push_gap(trustworthy, trust_reason, reason),
        CrossRepoQualifier::Note(note) => notes.push(note),
        CrossRepoQualifier::Complete => {}
    }
}

/// The cross-repo qualifier this response earns, for the callers that need it
/// outside this gate.
///
/// Exposed because [`crate::verdict`] must weigh the same fact, and a second
/// implementation of "is cross-repo authority a gap" would drift from this one.
/// The rule lives here once; the verdict maps it onto a reading.
///
/// `None` means the payload carries no cross-repo accounting at all, which is
/// not the same as reporting that nothing was missed. This gate treats an absent
/// block as a gap when an absence is being claimed, because an answer that says
/// "nothing references this" while silently reporting no cross-repo authority is
/// the exact shape it exists to refuse. A populated answer claims no absence, so
/// there the honest reading is that the concept is not carried.
pub(crate) fn cross_repo_qualifier(tool: &str, payload: &Value) -> Option<CrossRepoQualifier> {
    payload.get("cross_repo")?;
    match tool {
        "find_references" => Some(cross_repo_references_qualifier(payload)),
        "bulk_check_references" => Some(cross_repo_bulk_qualifier(payload)),
        _ => None,
    }
}

fn cross_repo_references_qualifier(payload: &Value) -> CrossRepoQualifier {
    let Some(cross_repo) = payload.get("cross_repo") else {
        return CrossRepoQualifier::Gap(
            "cross_repo_authority_missing: find_references did not report cross-repo authority"
                .to_string(),
        );
    };
    match cross_repo.get("status").and_then(Value::as_str) {
        Some("unavailable") => cross_repo_unavailable_qualifier(cross_repo),
        Some("available") => {
            let authority_complete = cross_repo
                .get("authority_complete")
                .and_then(Value::as_bool)
                == Some(true);
            let revision = cross_repo
                .get("authority_revision")
                .and_then(Value::as_str)
                .filter(|revision| !revision.is_empty());
            let roots = cross_repo.get("authority_roots").and_then(Value::as_object);
            let anchor = cross_repo
                .get("authority_anchor")
                .and_then(Value::as_object);
            let anchor_repo = anchor
                .and_then(|anchor| anchor.get("repo_id"))
                .and_then(Value::as_str)
                .filter(|repo_id| !repo_id.is_empty());
            let anchor_entity = anchor
                .and_then(|anchor| anchor.get("entity_id"))
                .and_then(Value::as_str)
                .filter(|entity_id| !entity_id.is_empty());
            let focal_entity = payload
                .get("focal_entity")
                .and_then(|focal| focal.get("id"))
                .and_then(Value::as_str);
            let anchor_is_bound = anchor_repo
                .is_some_and(|repo_id| roots.is_some_and(|roots| roots.contains_key(repo_id)))
                && anchor_entity == focal_entity;
            let relation_subtype_complete = cross_repo
                .get("relation_subtype_complete")
                .and_then(Value::as_bool)
                != Some(false);
            if authority_complete
                && revision.is_some()
                && anchor_is_bound
                && relation_subtype_complete
            {
                CrossRepoQualifier::Complete
            } else {
                CrossRepoQualifier::Gap(format!(
                    "cross_repo_authority_incomplete: spine topology or requested relation subtype is incomplete at revision {}",
                    revision.unwrap_or("unwatermarked")
                ))
            }
        }
        // Not a gap. No spine is configured, so there is no cross-repo authority
        // to have failed, and nothing about this repository's own graph is in
        // question (FIR-2633).
        Some("not_configured") => cross_repo_not_configured_note(),
        Some(status) => CrossRepoQualifier::Gap(format!(
            "cross_repo_authority_unknown: unrecognized cross-repo authority status '{status}'"
        )),
        None => CrossRepoQualifier::Gap(
            "cross_repo_authority_missing: cross-repo authority status is missing".to_string(),
        ),
    }
}

fn cross_repo_bulk_qualifier(payload: &Value) -> CrossRepoQualifier {
    let Some(cross_repo) = payload.get("cross_repo") else {
        return CrossRepoQualifier::Gap(
            "cross_repo_authority_missing: bulk reachability did not report cross-repo authority"
                .to_string(),
        );
    };
    match cross_repo.get("status").and_then(Value::as_str) {
        Some("unavailable") => cross_repo_unavailable_qualifier(cross_repo),
        Some("available") => {
            let authority_complete = cross_repo
                .get("authority_complete")
                .and_then(Value::as_bool)
                == Some(true);
            let revision = cross_repo
                .get("authority_revision")
                .and_then(Value::as_str)
                .filter(|revision| !revision.is_empty());
            let roots_complete = cross_repo
                .get("authority_roots")
                .and_then(Value::as_object)
                .is_some_and(|roots| !roots.is_empty());
            let subtype_complete = cross_repo
                .get("relation_subtype_complete")
                .and_then(Value::as_bool)
                == Some(true);
            let verdicts_complete =
                cross_repo.get("verdicts_complete").and_then(Value::as_bool) == Some(true);
            if authority_complete
                && revision.is_some()
                && roots_complete
                && subtype_complete
                && verdicts_complete
            {
                CrossRepoQualifier::Complete
            } else {
                CrossRepoQualifier::Gap(format!(
                    "cross_repo_authority_incomplete: bulk topology or requested relation subtype is incomplete at revision {}",
                    revision.unwrap_or("unwatermarked")
                ))
            }
        }
        // Not a gap. No spine is configured, so there is no cross-repo authority
        // to have failed, and nothing about this repository's own graph is in
        // question (FIR-2633).
        Some("not_configured") => cross_repo_not_configured_note(),
        Some(status) => CrossRepoQualifier::Gap(format!(
            "cross_repo_authority_unknown: unrecognized cross-repo authority status '{status}'"
        )),
        None => CrossRepoQualifier::Gap(
            "cross_repo_authority_missing: cross-repo authority status is missing".to_string(),
        ),
    }
}

/// Build the trust qualifier for `tool`'s `payload`, enriched from `envelope`,
/// or `None` when the tool is not retrieval.
///
/// The returned object is additive: callers attach it under [`NEGATIVE_KEY`]
/// beside the existing payload keys, never replacing them.
///
/// ## Every retrieval answer carries one, not only the empty ones (FIR-2463)
///
/// This used to return `None` the moment a collection came back non-empty, on
/// the reasoning that there was no absence to qualify. The consequence is that
/// an answer with rows reached an agent with no epistemic claim attached at all,
/// and a reader cannot tell "this answer is whole" from "nobody said". On
/// psf/requests, `graph_neighborhood` walked two inbound edges of
/// `HTTPAdapter.send` and framed them as complete with no qualifier, in the same
/// session where `find_references` refused to certify the same entity over the
/// same edges. Whichever tool you reached for first decided what you believed.
///
/// So the split is now between what is CLAIMED, not whether an object exists.
/// `trust` is the response's one verdict either way. `safe_to_conclude_absent`
/// answers the narrower question and is false whenever the answer returned rows,
/// because no absence is being claimed there and a reader must never be able to
/// read one out of a populated answer.
pub fn negative_for(
    tool: &str,
    payload: &Value,
    envelope: &Envelope,
    response_gaps: &[String],
) -> Option<Value> {
    let spec = spec_for(tool)?;
    let count = if tool == "semantic_locate" {
        locate_result_count(payload)?
    } else {
        match collection_len(payload, spec.field) {
            Some(count) => count,
            // An omitted group makes the same claim as an empty one, and it is
            // the more dangerous of the two: `[]` at least names the question,
            // while a missing key reads as a question the tool does not answer.
            // Bailing out here would leave the shape with no verdict at all,
            // which is the defect this module exists to prevent wearing its
            // sharpest costume. `get_context_pack` shipped exactly that in
            // 0.5.42, where the pack carried no `dependents` key, and nothing
            // qualified it.
            None if omits_its_answer_group(tool, payload) => 0,
            None => return None,
        }
    };
    // A locate page has a second way of being a negative: it came back full, and
    // not one hit is the symbol the query named. Qualifying that page is the
    // whole point — the rows are real neighbors and stay exactly as ranked, so
    // this reports rather than filters, and a weak-but-real hit is never dropped
    // to hide a wrong one.
    let ranking_names_nothing = tool == "semantic_locate" && locate_ranking_names_nothing(payload);
    let relevance_unverified = tool == "semantic_locate" && locate_relevance_unverified(payload);
    // Whether this response asserts that something is NOT there. An answer with
    // rows asserts nothing of the kind, and still gets qualified: the gates
    // below decide how far its rows can be trusted as the whole set, which is
    // the question `graph_neighborhood` used to leave unanswered.
    //
    // Read from [`answer_claims_absence`] rather than recomputed, because
    // [`absence_coverage_gap`] states its limit against the same claim and two
    // readings of one question are how a caveat about absences came to ride on
    // an answer with rows (FIR-2496).
    let claims_absence = answer_claims_absence(tool, payload);
    if !claims_absence && !qualifies_populated_answers(tool) && !relevance_unverified {
        return None;
    }

    let (mut trustworthy, trust_reason) = envelope.negative_trust(spec.class);
    let mut trust_reason = trust_reason.to_string();

    // The coverage gate leads every other gap because it is the one that can
    // make the query structurally unable to answer. A graph holding no
    // cross-file edges of the class a reference query reads, or no resolved
    // program behind the declarations a name filter reads, returns an empty
    // answer for every symbol in it, healthy or not, so no later gap is the
    // limiting factor when this one applies and none of them may be reported as
    // if it were.
    if let Some(gap) = absence_coverage_gap(tool, payload) {
        push_gap(&mut trustworthy, &mut trust_reason, gap);
    }

    // Scoped to answers that actually claim an absence, for the same reason the
    // cross-repo gate below is. A store being behind bounds what "nothing is
    // there" can mean; it says nothing about whether the rows a populated answer
    // did return are real, and applying it there would put a floor under every
    // answer on every working copy holding one untracked file.
    if claims_absence {
        if let Some(gap) = unadmitted_host_content_gap(envelope) {
            push_gap(&mut trustworthy, &mut trust_reason, gap);
        }
    }

    // Gaps the response carries that this function cannot observe from the
    // payload's collections alone, contributed by [`crate::verdict`] so the one
    // verdict and the advice a reader acts on are built from the same list.
    // Threading them in here rather than patching the finished object is what
    // keeps `trust`, `trust_reason` and `advice` one consistent sentence.
    for gap in response_gaps {
        push_gap(&mut trustworthy, &mut trust_reason, gap.clone());
    }

    // Receiver-method calls (`x.method()`) are resolved by bare name in
    // the linker while method entities are keyed by their qualified name, so a
    // method's incoming `Calls` edges are frequently dropped. An empty
    // `find_references` for a method is therefore NOT an authoritative "unused"
    // verdict — the calls may simply never have been linked. Never let an agent
    // read "safe to delete" off an incomplete call graph: downgrade to
    // inconclusive so the absence is flagged as possibly-unresolved, not certain.
    //
    // A pack's `dependents` group is built by the same collector over the same
    // edges (FIR-2474), so the gap it inherits is the same one and it has to be
    // reported the same way. Gating this on the tool name alone was how the two
    // surfaces were able to disagree about one entity in one store: the tool
    // that refused to certify and the tool that published `[]` were reading the
    // identical incomplete call graph.
    //
    // The resolution the answer rode in on. `find_references` published a
    // `focal_resolution` block and never read it back, so an answer describing
    // one of several same-named entities was certified as the whole set
    // (FIR-2475).
    //
    // Scoped to `find_references` on purpose, and the asymmetry with the method
    // gate below is the point rather than an oversight: `get_context_pack` is
    // addressed by `entity_id` and resolves no name, so it publishes no
    // `focal_resolution` and has no resolution to qualify. Extending this to it
    // would report `focal_resolution_unreported` on every pack, which is a gap
    // about a step that tool never takes. The method gate is shared because both
    // tools read the same edges; this one is not because only one of them
    // resolves a name.
    if tool == "find_references" {
        if let Some(gap) = focal_resolution_gap(payload, "this reference list") {
            push_gap(&mut trustworthy, &mut trust_reason, gap);
        }
    }

    // Whether a caller could have arrived through a call the graph does not hold
    // (FIR-2775). Scoped to answers that claim an absence, like the cross-repo
    // gate below and for the same reason: a shortfall in the arrival paths
    // bounds what "nothing calls this" can mean, and says nothing about whether
    // the rows a populated answer did return are real.
    //
    // This is the gap that had no input at all. `storage.note_body` was called
    // once, from a test that reached the module through `from notekeeper import
    // storage`, and the linker declined to bind the call. Every other gate here
    // read a healthy store and agreed, so the answer certified: state
    // `certified`, `absence_claim: authoritative`, `safe_to_conclude_absent:
    // true`, `limiting_factor: null`, about a function one grep proves is used.
    // The file that called it had produced 15 entities, so the
    // file-produced-nothing warning did not apply, and no other signal in the
    // envelope could see a call site that became no edge.
    // Shared with `get_context_pack` on purpose, exactly like the method gate
    // below. A pack's `dependents` group is built by the same collector over the
    // same edges, so it inherits the same gap; gating this on `find_references`
    // alone would let the tool that refuses to certify and the tool that
    // publishes `[]` read one incomplete call graph and answer opposite things,
    // which is the disagreement the method gate was widened to end.
    if matches!(tool, "find_references" | "get_context_pack") && claims_absence {
        if let Some(gap) = crate::caller_arrival::arrival_gap(payload) {
            push_gap(&mut trustworthy, &mut trust_reason, gap);
        }
    }

    // The enumeration's own gate, and the only one that can certify it. Every
    // other signal here describes the store; this describes the file, and a
    // file no adapter parsed holds no entities in a graph of any health at all.
    // Reading store health as licence for that absence is exactly the
    // substitution FIR-2430 made on the language axis.
    if tool == FILE_ENTITIES_TOOL {
        if let Some(gap) = file_enumeration_gap(payload) {
            push_gap(&mut trustworthy, &mut trust_reason, gap);
        }
    }

    if matches!(tool, "find_references" | "get_context_pack") && focal_is_method(payload) {
        push_gap(
            &mut trustworthy,
            &mut trust_reason,
            kin_core::reference_coverage::method_absence_limiting_factor("an empty result"),
        );
    }

    // A healthy local graph is not enough to certify "no references" when the
    // configured cross-repo authority failed or returned an invalid payload.
    // Keep the local rows, but make the negative verdict explicitly
    // inconclusive so agents cannot read the gap as safe-to-delete proof.
    //
    // It follows the gates above rather than replacing them. A spine that cannot
    // answer for a repository is a real gap, but it is a gap about OTHER
    // repositories, so it is never the reason a local absence could not be
    // certified. Reporting it as that reason is how a miss inside one file came
    // back explained as a cross-repo root mismatch.
    //
    // Scoped to answers that actually claim an absence. The gate exists to stop
    // "nothing references this" being read as safe-to-delete proof when the
    // spine could not answer for other repositories. A populated answer claims
    // no such thing, and applying it there would report every answer on every
    // repository with no spine configured as a floor forever, which is the
    // "mark everything uncertain" regression arriving through a side door.
    // Conditions this answer weighed and ruled out as limits. They are reported
    // so a reader can see cross-repo authority was considered, and they never
    // reach `trust`.
    let mut notes: Vec<String> = Vec::new();

    if tool == "find_references" && claims_absence {
        apply_cross_repo_qualifier(
            cross_repo_references_qualifier(payload),
            &mut trustworthy,
            &mut trust_reason,
            &mut notes,
        );
    }

    if tool == "bulk_check_references" && claims_absence {
        apply_cross_repo_qualifier(
            cross_repo_bulk_qualifier(payload),
            &mut trustworthy,
            &mut trust_reason,
            &mut notes,
        );
    }

    // An empty edge set has two readings with opposite consequences: a focal
    // that is in the graph and genuinely has nothing on the side that was
    // walked, and a focal the walk never found. Only the first is evidence
    // about the entity — certifying the second as isolation answers a question
    // the traversal never reached.
    let mut kind = spec.kind;
    let mut subject = spec.subject;
    if ranking_names_nothing {
        kind = "no_named_match";
        subject = "the query named a symbol and no ranked entity carries that name; \
                   every hit was surfaced by content or embedding similarity";
        // A ranking is a bounded candidate set, so this verdict can never be
        // authoritative no matter how complete the index is.
        //
        // Certifying it was a false statement about the graph, not a strict
        // reading of a true one. A dogfood on the shipped artifact asked for
        // `prune_orphaned_vectors` on a fully covered store and got ten wrong
        // rows carrying `safe_to_conclude_absent: true`, `trust: authoritative`,
        // and advice reading "on a complete graph that means no entity carries
        // it at all". `find_references` resolved that exact name to a real
        // method 1.9 seconds later in the same run. The fabricated control
        // returned the IDENTICAL envelope, so the verdict could not separate a
        // symbol retrieval missed from one that does not exist, and stamped both
        // authoritative.
        //
        // Coverage completeness licenses nothing here. It says every entity has
        // an embedding, not that the ranker considered every entity, and the
        // name absent from a window says nothing about the rows outside it. The
        // surfaces that CAN answer existence resolve a name directly, so the
        // advice sends the caller to those instead.
        trustworthy = false;
        // The substrate reason is kept after the gap rather than replaced. It is
        // still true and still useful, and on a complete index it reads
        // "the substrate is fine, the ranking is the limit", which is exactly
        // the distinction that was being collapsed.
        trust_reason = format!(
            "ranking_is_bounded: no ranked entity carries the name, and a ranking is a bounded \
             candidate set rather than an enumeration of the graph, so the name may belong to an \
             entity this query never ranked; observed substrate state: {trust_reason}"
        );
    } else if relevance_unverified {
        kind = "relevance_unverified";
        subject = "the query described a concept and every returned row is a nearest neighbour; \
                   this ranking publishes no measured relevance floor";
        trustworthy = false;
        trust_reason = format!(
            "relevance_floor_unmeasured: every row this response returned was a fallback \
             neighbour and the response publishes no calibrated threshold establishing that any \
             of them answers the concept; observed substrate state: {trust_reason}"
        );
    }
    if tool == "graph_neighborhood" {
        // The emitted edge array is capped by the caller's `limit`, and a
        // `limit` of zero empties it while the walk still found neighbors. The
        // pre-truncation total is what decides whether anything was there, so a
        // truncated answer is never dressed up as an absence. That reading lives
        // in [`answer_claims_absence`] since FIR-2496, so the gate reads the same
        // one rather than a second copy of it.
        //
        // It stops the ABSENCE framing and no longer stops the qualifier. This
        // returned `None` until FIR-2463, which is why a neighborhood that walked
        // 16 entities over 15 relations reached an agent carrying no epistemic
        // claim at all, in the same session where `find_references` refused to
        // certify the same entity over the same edges. Whichever tool you reached
        // for first decided what you believed.
        let neighborhood_gap = if payload.get("entity_count").and_then(Value::as_u64) == Some(0) {
            kind = "focal_not_in_graph";
            subject = "the focal entity is not in the graph, so no neighborhood was walked";
            Some(
                "focal_not_in_graph: the focal entity was not found, so an empty \
                 neighborhood is not evidence that it is isolated",
            )
        } else if payload.get("depth").and_then(Value::as_u64) == Some(0) {
            // A depth of zero expands no edges at all, so the empty result is a
            // fact about the request and not about the entity. Certifying that
            // as isolation would answer, from a walk that examined nothing, the
            // question a caller asks before deleting code.
            kind = "no_traversal";
            subject = "no traversal was performed at depth 0, so nothing was examined \
                 about the entity's neighbors";
            Some(
                "depth_zero: the walk expanded no edges, so an empty neighborhood \
                 is not evidence of isolation",
            )
        } else {
            if let Some(directional) = neighborhood_absence_subject(payload) {
                subject = directional;
            }
            None
        };

        // A neighborhood gap describes this request or this focal; the
        // envelope's gap describes the substrate underneath both. When the
        // substrate was already untrustworthy it is the reason everything looks
        // absent, so it leads and the specific gap follows rather than being
        // overwritten by it.
        if let Some(gap) = neighborhood_gap {
            push_gap(&mut trustworthy, &mut trust_reason, gap.to_string());
        }
    }

    // The same split the neighborhood makes: the substrate reason describes what
    // is underneath every answer, the walk's own gaps describe this one, and a
    // reader needs both to know whether to re-run or to stop trusting the graph.
    if tool == "trace_data_flow" {
        if let Some(directional) = trace_absence_subject(payload) {
            subject = directional;
        }
        let gaps = trace_flow_gaps(payload);
        if !gaps.is_empty() {
            push_gap(&mut trustworthy, &mut trust_reason, gaps.join("; "));
        }
    }

    // A route has two ends and a bound, and each is a way an empty answer can
    // be true of something other than what was asked: a twin that was never
    // walked, or a depth the walk stopped at before its frontier emptied.
    if tool == TRACE_PATH_TOOL {
        let gaps = path_gaps(payload);
        if !gaps.is_empty() {
            push_gap(&mut trustworthy, &mut trust_reason, gaps.join("; "));
        }
    }

    // The payload's own `degradations[]` is a report about THIS query, and the
    // verdict has to consume it or contradict it. A page that names an active
    // degradation beside a negative claiming none is the shape this whole
    // module exists to prevent. `trace_data_flow` is skipped because it states
    // the same fact above in walk vocabulary, and saying it twice in one reason
    // is not saying it better.
    let degradations = payload_degradation_labels(payload);
    if !degradations.is_empty() && tool != "trace_data_flow" {
        push_gap(
            &mut trustworthy,
            &mut trust_reason,
            format!(
                "retrieval_degraded: this query reported degradations [{}], so it did not run at \
                 full capability",
                degradations.join(", ")
            ),
        );
    }

    // A graph holding no entities answers every query identically, so an empty
    // result there describes the graph and not the code. This is the same gate
    // [`resolution_miss_for`] applies to a name that never resolved: the two
    // ways of reporting "nothing" have to agree about an empty graph, or an
    // agent learns which phrasing to trust rather than which answer.
    if envelope.graph_state.entity_count == Some(0) {
        push_gap(
            &mut trustworthy,
            &mut trust_reason,
            "graph_empty: the graph holds no entities at all, so an empty result says \
             nothing about whether the target exists"
                .to_string(),
        );
    }

    let interpretation = if ranking_names_nothing {
        "unnamed_ranking"
    } else if relevance_unverified {
        "nearest_neighbors_only"
    } else if spec.always {
        "qualified_verdicts"
    } else if claims_absence {
        "absent_as_indexed"
    } else {
        "qualified_answer"
    };
    if !claims_absence && !relevance_unverified {
        kind = "qualified_answer";
        subject = "this answer returned rows, so it asserts no absence; the verdict below says \
                   how far those rows can be trusted as the whole set";
    }
    let consequence = if ranking_names_nothing {
        unnamed_ranking_consequence().to_string()
    } else if relevance_unverified {
        unverified_relevance_consequence().to_string()
    } else if claims_absence {
        absence_advice_consequence(tool, spec.always, trustworthy, &trust_reason)
    } else {
        populated_advice_consequence(trustworthy, &trust_reason)
    };

    let degraded_signals = degraded_signals(tool, payload, envelope);
    let coverage_clause = coverage_clause(spec.class, payload, envelope);
    let trust_reason = if trustworthy {
        qualify_clean_trust_reason(trust_reason, &degraded_signals)
    } else {
        trust_reason
    };

    let mut negative = Map::new();
    negative.insert("kind".to_string(), json!(kind));
    negative.insert("subject".to_string(), json!(subject));
    negative.insert("result_count".to_string(), json!(count));
    negative.insert("interpretation".to_string(), json!(interpretation));
    // Never true on a populated answer. The verdict can be authoritative there,
    // meaning the rows are the whole set, and that is still not a licence to
    // conclude anything is absent, so the two fields are computed apart.
    negative.insert(
        "safe_to_conclude_absent".to_string(),
        json!(trustworthy && claims_absence),
    );
    negative.insert(
        "trust".to_string(),
        json!(if trustworthy {
            "authoritative"
        } else {
            "inconclusive"
        }),
    );
    negative.insert("trust_reason".to_string(), json!(trust_reason));
    negative.insert(
        "graph_as_of".to_string(),
        envelope.graph_as_of.clone().unwrap_or(Value::Null),
    );
    negative.insert("semantic_coverage".to_string(), coverage_value(envelope));
    // Which coverage the verdict rests on. `semantic_coverage` above stays what
    // it always was, the envelope's embedding reading, and this says whether it
    // is the reading that decided anything here.
    negative.insert(
        "coverage_basis".to_string(),
        json!(coverage_basis(spec.class)),
    );
    negative.insert(
        "advice".to_string(),
        json!(build_advice(
            subject,
            &consequence,
            &coverage_clause,
            envelope,
            &degraded_signals
        )),
    );
    negative.insert("degraded_signals".to_string(), json!(degraded_signals));
    // Stated conditions that are NOT limits, kept in their own key so nothing
    // downstream can read one as a gap. `trust`, `trust_reason` and `advice` are
    // computed above and none of them sees this array.
    if !notes.is_empty() {
        negative.insert("notes".to_string(), json!(notes));
    }
    Some(Value::Object(negative))
}

/// How one tool frames "I could not resolve what you named". These answers are
/// a human message rather than an empty collection, so [`negative_for`] cannot
/// see them at all: there is no payload to count, and the response used to
/// arrive as a bare `{"message": ...}` with the envelope but no negative beside
/// it, which is the one shape an agent cannot calibrate.
/// Every reason an empty route set is unsafe to read as "A never reaches B",
/// in a stable order.
///
/// The walker publishes both ends with `addressed_by` and the count of entities
/// carrying the same exact name. An end the caller pinned (by id or by file)
/// was chosen by the caller and is no gap whatever the count says; an end the
/// ranking chose among several is, because the walk ran from one twin and the
/// others were never seeds or goals. The stop reason is the other half: a walk
/// that emptied its frontier explored everything reachable inside `max_depth`,
/// while one that stopped at the bound or at a work ceiling did not.
fn path_gaps(payload: &Value) -> Vec<String> {
    let mut gaps = Vec::new();
    for which in ["from", "to"] {
        let end = payload.get(which).unwrap_or(&Value::Null);
        let pinned = matches!(
            end.get("addressed_by").and_then(Value::as_str),
            Some("entity_id") | Some("name_and_file")
        );
        match end.get("same_name_candidates").and_then(Value::as_u64) {
            None => gaps.push(format!(
                "{which}_resolution_unreported: this answer did not report how many entities its \
                 '{which}' end could have been resolved from, so an empty route set may describe \
                 a same-named sibling rather than the entity that was asked about"
            )),
            Some(candidates) if candidates > 1 && !pinned => gaps.push(format!(
                "{which}_ambiguous: {candidates} entities carry the name '{}' and the walk used one \
                 of them, so no route from or to the others was looked for; pin the one you mean \
                 with name@file or its entity id",
                end.get("name").and_then(Value::as_str).unwrap_or("?")
            )),
            _ => {}
        }
    }
    match payload
        .get("gap")
        .and_then(|gap| gap.get("reason"))
        .and_then(Value::as_str)
    {
        Some("depth_bound") => gaps.push(
            "walk_depth_bounded: the walk stopped at max_depth before its frontier emptied, so a \
             longer route may exist; raise max_depth"
                .to_string(),
        ),
        Some(reason @ ("edge_ceiling" | "time_budget" | "cancelled")) => gaps.push(format!(
            "walk_bounded: the walk stopped at its {reason} before its frontier emptied, so a route \
             may exist beyond what was explored"
        )),
        _ => {}
    }
    gaps
}

fn resolution_miss_spec(tool: &str) -> Option<(&'static str, &'static str)> {
    match tool {
        // The review family's files mode resolves each named path to the
        // entities the graph holds for it. When none resolve, nothing was
        // compared, and that is a fact about the paths rather than about a diff.
        // All three tools share one `resolve_diff`, so all three report the same
        // miss; a spec for only the tool it was found on would leave its
        // siblings failing loudly with no negative beside them.
        "impact_analysis" | "semantic_diff" | "semantic_review" => Some((
            "scope_not_resolved",
            "the files that were named resolved to no entities, so nothing was diffed or analyzed",
        )),
        "find_references" => Some((
            "focal_not_resolved",
            "the entity that was asked about could not be resolved, so no references were looked up",
        )),
        "trace_data_flow" => Some((
            "focal_not_resolved",
            "the focal that was asked about could not be resolved, so no data-flow chain was walked",
        )),
        TRACE_PATH_TOOL => Some((
            "endpoint_not_resolved",
            "one of the two entities that were named could not be resolved, so no route was walked",
        )),
        // An unknown id and an entity with no recorded history are the same
        // shape on this tool's success path — change_count 0, latest_change
        // null, empty approvals and events — so the miss has to be reported as a
        // miss or an agent reads a resolution failure as "no provenance
        // recorded" and treats unaccountable code as accounted for.
        "kin_provenance_query" => Some((
            "entity_not_resolved",
            "the entity that was asked about could not be resolved, so no provenance was looked up",
        )),
        _ => None,
    }
}

/// True when an error message reports that the thing the caller named was not
/// found, rather than a malformed request or a transport failure.
///
/// Matched on the family rather than one exact sentence. Three producers word
/// this differently today: `Entity not found` from the references handler,
/// `trace_data_flow: no entity matches focal 'X'` from the in-process trace
/// handler, and `no entity found matching 'X'` from the daemon's trace route. A
/// qualifier that only fires for the wording it was written against would go
/// quiet the moment one of them is reworded, which looks exactly like the tool
/// having no miss to qualify.
fn is_resolution_miss(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("no entity") || message.contains("entity not found")
}

/// Build a confidence-qualified negative for a resolution miss reported as
/// `message`, or `None` when the tool has no miss framing or the message is
/// some other failure (bad parameters, an unreachable daemon) that says nothing
/// about whether the named symbol exists.
///
/// Trust is computed from the same structural gate a resolved-but-empty answer
/// uses: on a daemon graph that is initialized, loaded, and undegraded, "the
/// graph holds no entity under that name" is a real answer; on anything less it
/// may only mean the name is not indexed yet.
pub fn resolution_miss_for(tool: &str, message: &str, envelope: &Envelope) -> Option<Value> {
    let (kind, subject) = resolution_miss_spec(tool)?;
    if !is_resolution_miss(message) {
        return None;
    }

    let (mut trustworthy, trust_reason) = envelope.negative_trust(NegativeClass::Structural);
    let mut trust_reason = trust_reason.to_string();

    // A graph holding no entities answers every name identically, so a miss
    // there describes the graph and not the code. That is the shape that made a
    // bare "not found" dangerous: an agent reads it as proof the symbol does not
    // exist and acts on it.
    if envelope.graph_state.entity_count == Some(0) {
        push_gap(
            &mut trustworthy,
            &mut trust_reason,
            "graph_empty: the graph holds no entities at all, so a name that resolves to \
             nothing says nothing about whether the symbol exists"
                .to_string(),
        );
    }

    // Host content the graph never met answers every name inside it identically,
    // for the same reason an empty graph does one gate up. This is the purest
    // absence claim the product makes, and it was the one that never asked: the
    // retrieval builder scopes this gap to answers that claim an absence, which
    // is every answer here, and a focal miss took a different route and skipped
    // it. So a constant declared and used in an unadmitted module came back
    // `safe_to_conclude_absent: true`, `structural_authoritative`, beside a
    // `behind` object in the same envelope naming the file it was in (FIR-2820).
    if let Some(gap) = unadmitted_host_content_gap(envelope) {
        push_gap(&mut trustworthy, &mut trust_reason, gap);
    }

    let consequence = if trustworthy {
        "The name is authoritatively absent from this graph: no entity carries it. That is a fact about the name and not about the symbol's usage, because nothing was looked up.".to_string()
    } else {
        format!(
            "Absence is NOT authoritative: the name may simply not be indexed yet, so do not \
             conclude the symbol does not exist. Limiting factor: {trust_reason}"
        )
    };

    // A miss carries no payload, so the daemon's own flags are the whole
    // degraded picture here.
    let degraded_signals: Vec<String> = envelope
        .degraded
        .active_labels()
        .into_iter()
        .map(str::to_string)
        .collect();

    // Same treatment as the retrieval builder, so one surface cannot word this
    // fact differently from the other. On this path the two sets coincide (a
    // miss carries no payload, and `negative_trust` is already untrustworthy
    // whenever a daemon flag is up), so a trustworthy miss reads exactly as it
    // always did and only the retrieval path's contradiction is repaired.
    let trust_reason = if trustworthy {
        qualify_clean_trust_reason(trust_reason, &degraded_signals)
    } else {
        trust_reason
    };

    let mut negative = Map::new();
    negative.insert("kind".to_string(), json!(kind));
    negative.insert("subject".to_string(), json!(subject));
    negative.insert("result_count".to_string(), json!(0));
    negative.insert("interpretation".to_string(), json!("name_not_resolved"));
    negative.insert("safe_to_conclude_absent".to_string(), json!(trustworthy));
    negative.insert(
        "trust".to_string(),
        json!(if trustworthy {
            "authoritative"
        } else {
            "inconclusive"
        }),
    );
    negative.insert("trust_reason".to_string(), json!(trust_reason));
    negative.insert(
        "graph_as_of".to_string(),
        envelope.graph_as_of.clone().unwrap_or(Value::Null),
    );
    negative.insert("semantic_coverage".to_string(), coverage_value(envelope));
    negative.insert(
        "coverage_basis".to_string(),
        json!(coverage_basis(NegativeClass::Structural)),
    );
    negative.insert(
        "advice".to_string(),
        json!(build_advice(
            subject,
            &consequence,
            &coverage_clause(NegativeClass::Structural, &Value::Null, envelope),
            envelope,
            &degraded_signals
        )),
    );
    negative.insert("degraded_signals".to_string(), json!(degraded_signals));
    Some(Value::Object(negative))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Degraded, Envelope, SemanticCoverage};

    /// The absence object for a response carrying no gaps beyond the ones this
    /// module computes for itself.
    ///
    /// Shadows [`super::negative_for`] so the cases below keep asserting on the
    /// gates that live here. The response-scoped gaps the real signature takes
    /// are contributed by [`crate::verdict`] and are exercised where they are
    /// computed; passing an empty list here is what makes a failure in this
    /// module a failure of this module.
    fn negative_for(tool: &str, payload: &Value, envelope: &Envelope) -> Option<Value> {
        super::negative_for(tool, payload, envelope, &[])
    }

    /// A daemon envelope whose SEMANTIC substrate is complete — full embedding
    /// coverage, no degraded signals: the only state in which a *semantic* tool's
    /// absent result is authoritative.
    fn semantic_authoritative_envelope() -> Envelope {
        let mut env = Envelope::daemon();
        env.semantic_coverage = Some(SemanticCoverage {
            indexed: 100,
            total: 100,
            pending: 0,
            complete: true,
            embedding_state_reported: Some("present".to_string()),
            limited_by: Vec::new(),
            read_at: None,
            note: None,
            graph_body_gap_paths: None,
        });
        env.graph_as_of = Some(json!("change:deadbeef"));
        env
    }

    /// A daemon envelope whose GRAPH substrate is complete — initialized + loaded
    /// (folded honestly from `/health`), no degraded signals, and crucially NO
    /// embedding coverage reported. *Structural* tools are authoritative here;
    /// semantic tools are not (they still need coverage).
    fn structural_ready_envelope() -> Envelope {
        Envelope::daemon().with_health(&json!({
            "graph_loaded": true,
            "initialized": true,
            "graph_generation": 12,
        }))
    }

    /// A graph that demonstrably links references across files for the focal's
    /// language: one observed cross-file `calls` witness, the rest scanned and
    /// reported absent. Without this object in the payload an absence claim has
    /// no evidence that the query could have found anything, which is the whole
    /// FIR-2353 failure, so every fixture asserting authoritative absence carries
    /// it.
    ///
    /// The absent `imports` is not a weakness of the fixture, it is what a real
    /// graph reports: Kin resolves an import to a cross-file `Calls` edge and an
    /// artifact-level edge, and mints no entity-level `Imports` edge for any
    /// language. A converted Python repository whose imports resolve cleanly
    /// reports exactly this shape.
    /// A graph whose enrichment actually delivered, which is the only shape in
    /// which Kin certifies a deletion.
    ///
    /// This fixture read `references: absent` beside `reference_enrichment:
    /// available` until FIR-2505, and that combination is not a healthy graph.
    /// It is the express failure shape exactly: a host that could produce
    /// reference edges, and a graph holding none. The suite's own idea of
    /// "healthy" was the defect, which is why every gate here passed while
    /// shipped v0.5.43 certified the deletion of ten live exports.
    ///
    /// The numbers come from the enriched arm of the same stranger run that
    /// caught it. psf/requests, sweep converged: `Entity-to-entity relation
    /// kinds: Calls: 945, Contains: 483, References: 438, ...` with
    /// `Cross-file entity relations: 699 of 1943`. The broken express arm on the
    /// same binary read `Calls: 254, Contains: 75` and no References at all.
    /// `imports` stays absent because Kin's linker mints no entity-level
    /// `Imports` relation on any language, healthy or not.
    fn cross_file_edges_observed() -> Value {
        // Every requested class present. This fixture used to read `imports:
        // absent` and still stand for a healthy graph, because the verdict
        // weighed `calls` alone; since FIR-2672 every requested class decides,
        // so "healthy" means what it says.
        json!({
            "scope": "language",
            "language": "Rust",
            "requested_classes": ["calls", "imports", "references"],
            "classes": { "calls": "present", "imports": "present", "references": "present" },
            "cross_file_classes": ["calls", "imports", "references"],
            "reference_enrichment": "available",
            "budget_exhausted": false,
            "entities_examined": 2,
        })
    }

    /// The scope observation a tool that traverses no edge publishes for an
    /// absence, over a language that IS resolved on this host: the build wires
    /// an adapter for it and a language server is installed. Both halves have to
    /// hold, which is why the fixture states the second one rather than leaving
    /// it unknown; "nobody checked" is not evidence that anything resolved.
    ///
    /// The shape is the one [`crate::edge_coverage::observe_absence_scope`]
    /// emits: no edge classes, because this claim is not about edges, and the
    /// one fact the verdict rests on. Without it in the payload an absence has
    /// no evidence that the query could have found anything, which is the
    /// FIR-2430 failure, so every fixture asserting an authoritative absence for
    /// one of these tools carries it.
    fn resolvable_language_scope(scope_entities: Option<usize>) -> Value {
        let mut observation = json!({
            "scope": "absence_scope",
            "language": "Python",
            "requested_classes": [],
            "classes": {},
            "cross_file_classes": [],
            "reference_enrichment": "available",
            "budget_exhausted": false,
            "entities_examined": 0,
            "scan": "skipped_no_edge_dependency",
        });
        if let Some(count) = scope_entities {
            observation["scope_entities"] = json!(count);
        }
        observation
    }

    /// The same scope observation with one coverage class actually measured for
    /// the language, which is the shape that lifts the FIR-2496 refusal.
    ///
    /// It exists because the refusal reads the observation and not the tool
    /// name, and every case below that asserts a certification has to be able to
    /// prove that. A rule that refused these tools by name would pass every test
    /// that only ever shows it an unmeasured map, and would go on refusing after
    /// the measurement arrived. It is also what keeps those cases falsifiable:
    /// with no payload that can certify, a control asserting "the gate can still
    /// pass" is a check that cannot pass, which is no more evidence than one
    /// that cannot fail.
    ///
    /// No producer emits this today. `observe_absence_scope` measures no class
    /// on purpose, so every `semantic_search`, `find_dead_code_seeded` and
    /// `graph_neighborhood` absence this build produces is inconclusive, and
    /// FIR-2509's extractor-coverage measurement is the work that would change
    /// that.
    fn scope_with_a_measured_class(scope_entities: Option<usize>) -> Value {
        let mut observation = resolvable_language_scope(scope_entities);
        observation["classes"] = json!({ "calls": "present" });
        observation["cross_file_classes"] = json!(["calls"]);
        observation
    }

    /// The same observation over a language nothing resolved: the express
    /// shape, where `imports` and `references` were never produced.
    ///
    /// It reports `no_language_server` rather than `unsupported` now. This build
    /// DOES wire a JavaScript adapter, so what leaves express unresolved is the
    /// host having no `typescript-language-server`, which is exactly the state
    /// the container behind the v0.5.42 stranger run was in. Both states block
    /// certification and they are different facts: one an operator can close
    /// with a command, the other only a new build can.
    fn unresolvable_language_scope(scope_entities: Option<usize>) -> Value {
        let mut observation = resolvable_language_scope(scope_entities);
        observation["language"] = json!("JavaScript");
        observation["reference_enrichment"] = json!("no_language_server");
        observation
    }

    /// An empty `semantic_search` page over `scope`, the payload shape the
    /// handler builds for a filter that matched no declaration.
    fn empty_search_page(scope: Value) -> Value {
        json!({
            "query": "utils",
            "limit": 20,
            "total_matches": 0,
            "truncated": false,
            "results": [],
            "edge_coverage": scope,
        })
    }

    fn authoritative_empty_references(kind: &str) -> Value {
        json!({
            "focal_entity": {
                "id": "00000000-0000-0000-0000-000000000001",
                "kind": kind,
                "name": "do_work",
            },
            "total_upstream": 0,
            "references": [],
            "cross_repo": {
                "status": "available",
                "authority_complete": true,
                "authority_anchor": {
                    "repo_id": "provider",
                    "entity_id": "00000000-0000-0000-0000-000000000001",
                },
                "authority_revision": "sha256:complete",
                "authority_roots": { "provider": "provider-root" },
            },
            "edge_coverage": cross_file_edges_observed(),
            // Every real find_references answer carries this block, so a
            // fixture without one is not a smaller response, it is a shape the
            // handler cannot produce. Leaving it out exercised the absence
            // gates against a payload that never says how it resolved its
            // focal, which is the gap FIR-2475 found unread.
            "focal_resolution": {
                "addressed_by": "entity_id",
                "same_name_candidates": 1,
                "matched": "exact_focal_name",
                "other_candidates": [],
            },
            // Every real answer carries this block too (FIR-2775), for the same
            // reason the resolution block above is here: a fixture without one
            // is not a smaller response, it is a shape the handler cannot
            // produce, and leaving it out would exercise the absence gates
            // against a payload that never says whether a caller could have
            // arrived through an edge the graph does not hold.
            //
            // Healthy by default, which is what makes this fixture a control:
            // the gate below has to leave an accounted arrival alone, or every
            // absence in this module goes inconclusive and the envelope stops
            // meaning anything.
            crate::caller_arrival::CALLER_ARRIVAL_KEY: {
                "state": "accounted",
                "family_files": 2,
                "family_measured": 2,
                "unaccounted_files": [],
                "unmeasured_reason": null,
            },
        })
    }

    /// FIR-2775, the reproduction. A Python package under `src/` whose test
    /// reached a module through `from notekeeper import storage` and called
    /// `storage.note_body(db, note.id)`. The parser read the call, the linker
    /// declined to bind it, and nothing recorded the decline, so this answer
    /// came back `certified` / `safe_to_conclude_absent: true` about a function
    /// one grep proves is used. Every other gate in this module read a healthy
    /// store and agreed, which is why the reading had to be added rather than
    /// tightened.
    #[test]
    fn find_references_absence_is_inconclusive_when_a_caller_could_arrive_unaccounted() {
        let mut payload = authoritative_empty_references("function");
        payload[crate::caller_arrival::CALLER_ARRIVAL_KEY] = json!({
            "state": "unaccounted",
            "family_files": 1,
            "family_measured": 0,
            "unaccounted_files": [{
                "file": "tests/test_storage.py",
                "parsed_call_sites": null,
                "resolved_call_edges": 2,
                "unaccounted_call_sites": null,
            }],
            "unmeasured_reason": null,
        });
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("empty references yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert_eq!(negative["trust"], json!("inconclusive"));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.starts_with(crate::caller_arrival::UNRESOLVED_ARRIVAL_LIMITING_FACTOR),
            "the limiting factor must lead the reason: {reason}"
        );
        assert!(
            reason.contains("tests/test_storage.py"),
            "the reason names the file whose calls became no edge: {reason}"
        );
    }

    /// The control the ticket demands beside it. Flooring every absence destroys
    /// the envelope's value in the other direction, so the accounted arrival the
    /// shared fixture carries must leave an authoritative absence alone.
    #[test]
    fn find_references_absence_stays_authoritative_when_every_arrival_is_accounted() {
        let payload = authoritative_empty_references("function");
        assert_eq!(
            payload[crate::caller_arrival::CALLER_ARRIVAL_KEY]["state"],
            json!("accounted"),
            "the control is only a control while the fixture is healthy"
        );
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("empty references yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
        assert_eq!(negative["trust"], json!("authoritative"));
    }

    /// An arrival the reading could not take is not an arrival it cleared. The
    /// two states are one word apart in the payload and opposite in consequence,
    /// so each gets its own arm.
    #[test]
    fn find_references_absence_is_inconclusive_when_arrival_could_not_be_measured() {
        let mut payload = authoritative_empty_references("function");
        payload[crate::caller_arrival::CALLER_ARRIVAL_KEY] = json!({
            "state": "unmeasured",
            "family_files": 0,
            "family_measured": 0,
            "unaccounted_files": [],
            "unmeasured_reason": "the graph holds no import or include edge into this file",
        });
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("empty references yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.starts_with(crate::caller_arrival::UNMEASURED_ARRIVAL_LIMITING_FACTOR),
            "an unmeasured arrival names itself rather than borrowing the unresolved id: {reason}"
        );
    }

    /// The gate is scoped to answers that claim an absence, like the cross-repo
    /// one below it. An answer holding rows asserts nothing about what is not
    /// there, and putting a floor under it would report every populated answer
    /// on every repository with one unresolvable call as limited.
    #[test]
    fn an_answer_with_rows_is_not_limited_by_an_unaccounted_arrival() {
        let mut payload = authoritative_empty_references("function");
        payload["total_upstream"] = json!(1);
        payload["references"] = json!([{ "name": "caller", "file_path": "app.py" }]);
        payload[crate::caller_arrival::CALLER_ARRIVAL_KEY] = json!({
            "state": "unaccounted",
            "family_files": 1,
            "family_measured": 1,
            "unaccounted_files": [{
                "file": "tests/test_storage.py",
                "parsed_call_sites": 3,
                "resolved_call_edges": 2,
                "unaccounted_call_sites": 1,
            }],
            "unmeasured_reason": null,
        });
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("a populated reference answer is still qualified");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(false),
            "no absence is claimed by an answer with rows"
        );
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            !reason.contains(crate::caller_arrival::UNRESOLVED_ARRIVAL_LIMITING_FACTOR),
            "the arrival gate must not fire on an answer that claims no absence: {reason}"
        );
    }

    /// FIR-2475, the verdict half. `find_references` published a
    /// `focal_resolution` block on every answer and read nothing back from it,
    /// so an answer describing one of several same-named entities was stamped
    /// complete and exact. `trace_data_flow` has refused to certify that shape
    /// since it was built; one resolution deserves one verdict whichever tool
    /// carries it.
    #[test]
    fn find_references_absence_is_inconclusive_when_the_query_matched_several_entities() {
        let mut payload = authoritative_empty_references("function");
        payload["focal_resolution"] = json!({
            "addressed_by": "name",
            "same_name_candidates": 3,
            "matched": "query_name_pattern",
            "other_candidates": [
                {"id": "00000000-0000-0000-0000-000000000002", "name": "View.dispatch_request"},
                {"id": "00000000-0000-0000-0000-000000000003", "name": "MethodView.dispatch_request"},
            ],
        });
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("an empty reference list yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.contains("focal_resolution_ambiguous"),
            "the ambiguous resolution must be named: {reason}"
        );
        assert!(
            reason.contains("matched the queried name as a pattern"),
            "an ambiguous QUERY and an ambiguous graph send a reader to different \
             places, so the gap must say which one this is: {reason}"
        );
        assert!(
            reason.contains("names merely contain it"),
            "a pattern match is not a name collision, and saying so is the fix: {reason}"
        );
        assert!(
            !reason.contains("share the focal's name"),
            "the collision wording belongs to the other arm: {reason}"
        );
    }

    /// The control for the pattern-match wording: a GENUINE collision, two
    /// definitions carrying one name, where the collision wording must still
    /// appear.
    ///
    /// Without this, the fix above is satisfied by a message that never says
    /// "share the focal's name" at all, which would trade a message that
    /// overstates for one that cannot state the real case.
    #[test]
    fn a_real_name_collision_still_reads_as_a_collision() {
        let mut payload = authoritative_empty_references("function");
        payload["focal_resolution"] = json!({
            "addressed_by": "name",
            "same_name_candidates": 2,
            "matched": "exact_focal_name",
            "other_candidates": [
                {"id": "00000000-0000-0000-0000-000000000002", "name": "resolve"},
            ],
        });
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("an empty reference list yields a negative");
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.contains("focal_resolution_ambiguous"),
            "a real collision is still an ambiguity: {reason}"
        );
        assert!(
            reason.contains("share the focal's name exactly"),
            "two definitions of one name is the case the collision wording is for: {reason}"
        );
        assert!(
            !reason.contains("names merely contain it"),
            "and it must not borrow the pattern-match wording: {reason}"
        );
    }

    /// A caller that supplied one entity id made no ambiguous choice, even if
    /// the graph holds other entities with the same display name. The producer
    /// must explicitly report an empty candidate list; omission stays
    /// inconclusive because it proves nothing was checked.
    #[test]
    fn an_id_pinned_focal_is_not_downgraded_for_same_named_entities() {
        let mut pinned = authoritative_empty_references("function");
        pinned["focal_resolution"] = json!({
            "addressed_by": "entity_id",
            "same_name_candidates": 3,
            "matched": "exact_focal_name",
            "other_candidates": [],
        });
        let negative = negative_for("find_references", &pinned, &structural_ready_envelope())
            .expect("an empty reference list yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
        assert!(
            !negative["trust_reason"]
                .as_str()
                .unwrap_or_default()
                .contains("focal_resolution_ambiguous"),
            "a pinned id was never selected from the same-named entities: {negative}"
        );

        let mut omitted = pinned;
        omitted["focal_resolution"]
            .as_object_mut()
            .unwrap()
            .remove("other_candidates");
        let negative = negative_for("find_references", &omitted, &structural_ready_envelope())
            .expect("an empty reference list yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(
            negative["trust_reason"]
                .as_str()
                .unwrap_or_default()
                .contains("focal_resolution_ambiguous"),
            "an omitted candidate report made no completeness claim: {negative}"
        );
    }

    /// The control. The gate must not fire on an unambiguous resolution, or it
    /// would mark every answer uncertain and say nothing at all.
    #[test]
    fn find_references_absence_stays_authoritative_when_its_resolution_was_exact() {
        let payload = authoritative_empty_references("function");
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("an empty reference list yields a negative");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(true),
            "one candidate is not an ambiguity: {negative}"
        );
    }

    /// An answer that does not report its resolution at all is the shape that
    /// let this through: absent said nothing, and nothing read as fine.
    #[test]
    fn find_references_absence_is_inconclusive_when_the_resolution_went_unreported() {
        let mut payload = authoritative_empty_references("function");
        payload
            .as_object_mut()
            .unwrap()
            .remove("focal_resolution")
            .expect("the fixture carries the block to remove");
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("an empty reference list yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("focal_resolution_unreported"));
    }

    #[test]
    fn non_retrieval_tool_gets_no_negative() {
        let payload = json!({ "ok": true });
        assert!(negative_for("kin_work_create", &payload, &Envelope::daemon()).is_none());
    }

    #[test]
    fn non_empty_result_gets_no_negative() {
        // FIR-2463: a populated answer is qualified rather than unqualified, and
        // what it must never do is claim an absence. The qualifier says how far
        // the rows can be trusted; it does not say anything is missing.
        let payload = json!({ "results": [{ "id": "x" }] });
        let negative = negative_for("semantic_search", &payload, &Envelope::daemon())
            .expect("every retrieval answer carries the response verdict");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert_eq!(negative["interpretation"], json!("qualified_answer"));
        assert_eq!(negative["result_count"], json!(1));
    }

    #[test]
    fn missing_collection_field_yields_no_negative() {
        // Honesty: if the expected field is absent, we cannot tell it was empty.
        let payload = json!({ "unexpected": 1 });
        assert!(negative_for("semantic_search", &payload, &Envelope::daemon()).is_none());
    }

    #[test]
    fn empty_search_offline_is_inconclusive() {
        let payload = json!({ "query": "auth", "results": [] });
        let negative = negative_for("semantic_search", &payload, &Envelope::offline())
            .expect("empty retrieval yields a negative");
        assert_eq!(negative["kind"], json!("no_entity_match"));
        assert_eq!(negative["result_count"], json!(0));
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert_eq!(negative["trust"], json!("inconclusive"));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("offline_fallback"));
        // Offline observes no coverage/freshness — honest nulls, not fabricated.
        assert_eq!(negative["graph_as_of"], Value::Null);
        assert_eq!(negative["semantic_coverage"], Value::Null);
    }

    // ---- semantic class: absence gated on EMBEDDING coverage ----

    #[test]
    fn semantic_locate_complete_coverage_is_authoritative() {
        let payload = json!({ "query": "auth", "results": [], "total_ranked": 0 });
        let negative = negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope(),
        )
        .expect("empty results yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
        assert_eq!(negative["trust"], json!("authoritative"));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("semantic_authoritative"));
        assert_eq!(negative["semantic_coverage"]["percent"], json!(100.0));
    }

    #[test]
    fn semantic_locate_partial_coverage_is_inconclusive() {
        let mut env = Envelope::daemon();
        env.semantic_coverage = Some(SemanticCoverage {
            indexed: 40,
            total: 100,
            pending: 60,
            complete: false,
            embedding_state_reported: Some("partial".to_string()),
            limited_by: vec!["embeddings_incomplete".to_string()],
            read_at: None,
            note: Some("indexing".to_string()),
            graph_body_gap_paths: None,
        });
        let payload = json!({ "query": "auth", "results": [], "total_ranked": 0 });
        let negative = negative_for("semantic_locate", &payload, &env).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("coverage_partial"));
        assert_eq!(negative["semantic_coverage"]["percent"], json!(40.0));
    }

    /// A body gap is not an embedding shortfall, and the reason must say so.
    ///
    /// This is the state the ticket reported: 1644/1644 embedded, so every
    /// embedding-derived number reads healthy, while the paths retrieval needs
    /// carry no graph-owned body. Sending that caller to `kin embed` would be
    /// advice against a counter that is already whole, so the limiting factor is
    /// named separately from the embedding one.
    #[test]
    fn a_fully_embedded_store_with_a_body_gap_names_the_body_gap_not_the_index() {
        let mut env = Envelope::daemon();
        env.semantic_coverage = Some(SemanticCoverage {
            indexed: 1644,
            total: 1644,
            pending: 0,
            complete: false,
            embedding_state_reported: Some("present".to_string()),
            limited_by: vec!["graph_body_gap".to_string()],
            read_at: None,
            note: Some("graph body gap: 111 of 777 …".to_string()),
            graph_body_gap_paths: Some(111),
        });
        env.graph_as_of = Some(json!("change:deadbeef"));

        let payload = json!({ "query": "Session", "results": [], "total_ranked": 0 });
        let negative = negative_for("semantic_locate", &payload, &env).unwrap();

        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.contains("coverage_graph_body_gap"),
            "the limiting factor must be the body gap: {reason}"
        );
        assert!(
            !reason.contains("coverage_partial"),
            "a whole embedding index must not be reported as incomplete: {reason}"
        );
    }

    #[test]
    fn semantic_locate_coverage_unknown_even_on_ready_graph_is_inconclusive() {
        // The class boundary: a fully initialized + loaded graph does NOT make a
        // ranked-retrieval absence authoritative — embeddings can still be
        // incomplete, so an empty locate page may mean "not indexed".
        let payload = json!({ "query": "auth", "results": [], "total_ranked": 0 });
        let negative =
            negative_for("semantic_locate", &payload, &structural_ready_envelope()).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("coverage_unknown"));
    }

    #[test]
    fn semantic_search_absence_is_gated_on_the_graph_not_on_embeddings() {
        // FIR-2216. semantic_search filters the entity index by name/kind/
        // language and never reads a vector, so gating it on embedding coverage
        // made every empty search report `coverage_unknown` and advise
        // "re-check after embedding is complete" — including on a store whose
        // embeddings were complete. It answers to the graph gate instead, which
        // is the substrate it actually reads. Since FIR-2430 that substrate has
        // to be OBSERVED rather than assumed, so the page carries the scope its
        // filter selected, and since FIR-2496 that observation has to have
        // measured something; embedding coverage is still not what decides
        // either way.
        let payload = empty_search_page(scope_with_a_measured_class(Some(12)));
        let negative = negative_for("semantic_search", &payload, &structural_ready_envelope())
            .expect("empty results yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
        assert_eq!(negative["trust"], json!("authoritative"));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("structural_authoritative"));
        assert_eq!(negative["semantic_coverage"], Value::Null);
        assert_eq!(negative["coverage_basis"], json!("graph_structure"));
        // Negative control on the same tool: an unloaded graph must still be
        // inconclusive, so the gate is one that can fail.
        let unloaded = Envelope::daemon().with_health(&json!({ "graph_loaded": false }));
        let negative = negative_for("semantic_search", &payload, &unloaded).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
    }

    #[test]
    fn a_javascript_search_absence_is_not_certified_without_reference_enrichment() {
        // FIR-2430, the reported payload. `semantic_search(query: "utils",
        // kind: "module")` on expressjs/express came back
        // `safe_to_conclude_absent: true`, `trust: "authoritative"` while
        // `lib/utils.js` sat in the tree holding nine entities. Minutes earlier
        // `find_references` had refused to certify an absence on the same
        // repository in the same session, because this build wires no
        // language-server adapter for JavaScript. The gate reached one tool and
        // not its sibling.
        let payload = empty_search_page(unresolvable_language_scope(Some(29)));
        let negative = negative_for("semantic_search", &payload, &structural_ready_envelope())
            .expect("empty results yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert_eq!(negative["trust"], json!("inconclusive"));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.starts_with("entity_index_unresolved"),
            "the limiting factor leads the reason: {reason}"
        );
        assert!(
            reason.contains("JavaScript"),
            "the reason names the language it is about: {reason}"
        );
        // The reason has to be about what this tool actually read. A name/kind
        // filter traverses no reference edge, so borrowing the sibling's
        // sentence would hand back a correct verdict beside an explanation of a
        // mechanism this query never used.
        assert!(
            !reason.contains("cross-file reference and override edges"),
            "semantic_search reads no edge, so its reason must not claim one: {reason}"
        );
        let advice = negative["advice"].as_str().unwrap();
        assert!(advice.contains("Absence is NOT authoritative"), "{advice}");
        assert!(
            advice.contains("Limiting factor: entity_index_unresolved"),
            "{advice}"
        );
        assert!(
            negative["degraded_signals"]
                .as_array()
                .unwrap()
                .contains(&json!("edge_coverage:reference_enrichment_unsupported")),
            "the shortfall the verdict rests on is disclosed: {negative}"
        );
    }

    #[test]
    fn a_measured_scope_still_certifies_a_genuinely_absent_declaration() {
        // The other direction, and the regression bar FIR-2404 set: the fix must
        // not degrade into marking everything inconclusive. Python is a language
        // this build wires an adapter for, and this answer's observation measured
        // a class over it, so an empty name filter over a populated region is
        // still a certifiable absence.
        //
        // The measurement is what carries it since FIR-2496, and the pair below
        // is the whole rule in two readings: the same payload with the same
        // language, the same populated region and the same healthy envelope
        // certifies when a class was measured and refuses when none was.
        let payload = empty_search_page(scope_with_a_measured_class(Some(29)));
        let negative = negative_for("semantic_search", &payload, &structural_ready_envelope())
            .expect("empty results yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
        assert_eq!(negative["trust"], json!("authoritative"));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("structural_authoritative"));

        let unmeasured = empty_search_page(resolvable_language_scope(Some(29)));
        let negative = negative_for("semantic_search", &unmeasured, &structural_ready_envelope())
            .expect("empty results yields a negative");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(false),
            "an unmeasured class map is the FIR-2496 shape and cannot certify: {negative}"
        );
    }

    /// FIR-2496, the reported shape. Three empty searches in one session on a
    /// green store certified byte-identical verdicts over `"classes": {}`, and
    /// two of them were wrong: `SCHEMA` is a module-level constant at
    /// `storage.py:24` that the Python extractor skips because it is
    /// triple-quoted, sitting between two one-line constants the same parse
    /// admitted, and `build_match_query` is a function in a file the graph had
    /// not admitted at all. Neither was absent from the repository. Both were
    /// absent from the index, and an unmeasured class map is exactly the
    /// observation that cannot tell those apart.
    #[test]
    fn an_unmeasured_class_map_cannot_certify_an_absence() {
        let payload = empty_search_page(resolvable_language_scope(Some(51)));
        let negative = negative_for("semantic_search", &payload, &structural_ready_envelope())
            .expect("empty results yields a negative");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(false),
            "nothing observed is not every input agreeing: {negative}"
        );
        assert_eq!(negative["trust"], json!("inconclusive"));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.starts_with("absence_coverage_unmeasured"),
            "the limiting factor names the measurement nothing took: {reason}"
        );
        assert!(
            reason.contains("for Python"),
            "it names the language whose coverage went unmeasured: {reason}"
        );
        assert!(
            reason.contains("never admitted"),
            "and what that leaves indistinguishable from a true absence: {reason}"
        );
        let advice = negative["advice"].as_str().unwrap();
        assert!(
            !advice.contains("Absence is authoritative"),
            "the advice a reader acts on follows the verdict: {advice}"
        );
        assert!(
            negative["degraded_signals"]
                .as_array()
                .unwrap()
                .contains(&json!("absence_coverage:classes_unmeasured")),
            "the shortfall the verdict rests on is disclosed beside it, so a reader never has \
             to parse the reason sentence to find it: {negative}"
        );

        // Every other gate reads healthy on this payload, which is why it
        // certified for four releases: the region holds 51 entities, the
        // language resolves on this host, and no narrowing filter removed a
        // candidate. Asserted so a later change cannot make this case pass for
        // one of those reasons instead.
        assert!(
            !reason.contains("absence_scope_empty") && !reason.contains("entity_index_unresolved"),
            "no other gate fired here, so this one is doing the work: {reason}"
        );
    }

    /// The other half of FIR-2496, and the one the stranger noticed first: the
    /// caveat about absences was riding the one call that asserted none. Of four
    /// searches in that session, `notes_with_tag` returned a row and was the
    /// response that read `limiting_factor: absence_coverage_unreported`, while
    /// the three empty ones carried nothing. A limit stated against a claim the
    /// answer never made teaches a reader to skip the limit.
    #[test]
    fn a_search_that_returned_rows_is_not_qualified_by_a_caveat_about_absences() {
        let populated = json!({
            "query": "notes_with_tag",
            "limit": 10,
            "total_matches": 1,
            "truncated": false,
            "results": [{ "name": "notes_with_tag", "kind": "Function" }],
        });
        let negative = negative_for("semantic_search", &populated, &structural_ready_envelope())
            .expect("every retrieval answer carries the response verdict");
        assert_eq!(negative["interpretation"], json!("qualified_answer"));
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            !reason.contains("absence_coverage_unreported"),
            "an answer with rows asserts no absence and must not be limited by one: {negative}"
        );
        assert!(
            reason.starts_with("answer_coverage_unreported"),
            "the same missing observation, stated against the claim this answer made: {reason}"
        );
        assert!(
            reason.contains("rows here are a floor"),
            "which is that its rows may be short, not that an absence is unsafe: {reason}"
        );

        // The empty answer from the same tool keeps the absence wording, so the
        // split is between the two claims rather than a rename of one of them.
        let empty = json!({
            "query": "notes_with_tag",
            "limit": 10,
            "total_matches": 0,
            "truncated": false,
            "results": [],
        });
        let negative = negative_for("semantic_search", &empty, &structural_ready_envelope())
            .expect("empty results yields a negative");
        assert!(
            negative["trust_reason"]
                .as_str()
                .unwrap()
                .starts_with("absence_coverage_unreported"),
            "{negative}"
        );
    }

    /// The regression bar in the other direction, on the surface that measures
    /// what it reads. A tool whose observation carries a class map is judged on
    /// that map, so a fully enriched store still certifies a true absence and
    /// FIR-2496 has not degraded into marking every answer uncertain.
    #[test]
    fn a_healthy_enriched_store_still_certifies_a_true_absence() {
        let payload = authoritative_empty_references("function");
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("an empty reference list carries a negative");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(true),
            "a measured class map certifies exactly as it did before: {negative}"
        );
        assert_eq!(negative["trust"], json!("authoritative"));
        assert_eq!(
            payload[crate::edge_coverage::EDGE_COVERAGE_KEY]["classes"]["calls"],
            json!("present"),
            "and the measurement it rests on is in the payload: {payload}"
        );
    }

    /// A narrowing filter that removed every candidate the name DID match
    /// (FIR-2452). This is the residual kin#935 left: every gate that existed
    /// reads the substrate, and on this payload the substrate is healthy, so all
    /// of them correctly report nothing and the answer certified.
    #[test]
    fn a_name_filter_narrowed_to_zero_certifies_nothing() {
        // The shape the stranger run hit on psf/requests, which is a fully
        // enriched Python store: `semantic_search(query: "request", kind:
        // "method")` answered zero and reported `safe_to_conclude_absent: true`
        // with "safe to treat the target as genuinely absent/unused", about a
        // name the graph resolves. The scope held every method in the
        // repository, Python is a language this build enriches, and the tool
        // traverses no edge, so the class gate, the scope gate and the
        // enrichment gate all read healthy. Only the name's own side can see it.
        let mut scope = resolvable_language_scope(Some(256));
        scope["name_filter"] = json!({ "narrowed_by": ["kind"], "candidates": 1 });
        let payload = empty_search_page(scope);

        let negative = negative_for("semantic_search", &payload, &structural_ready_envelope())
            .expect("empty results yields a negative");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(false),
            "the name matched a declaration and a kind filter removed it, so this \
             observed absence of a match: {negative}"
        );
        assert_eq!(negative["trust"], json!("inconclusive"));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.starts_with("name_filter_narrowed_to_zero"),
            "{reason}"
        );
        assert!(
            reason.contains("selects 1 declaration on its own"),
            "the count it measured is in the reason: {reason}"
        );
        assert!(
            reason.contains("kind filter removed every one of them"),
            "the filter that emptied it is named rather than left unattributed: {reason}"
        );
        assert!(
            negative["degraded_signals"]
                .as_array()
                .unwrap()
                .contains(&json!("absence_coverage:name_filter_narrowed")),
            "the shortfall the verdict rests on is disclosed: {negative}"
        );

        // Positive control on the same payload shape: the name matched nothing
        // on its own, so the narrowing filter removed nothing and the absence is
        // the name's, not the filter's. The gate reads the count. It carries a
        // measured class since FIR-2496, or the control could not pass whatever
        // this gate did.
        let mut matched_nothing = scope_with_a_measured_class(Some(256));
        matched_nothing["name_filter"] = json!({ "narrowed_by": ["kind"], "candidates": 0 });
        let negative = negative_for(
            "semantic_search",
            &empty_search_page(matched_nothing),
            &structural_ready_envelope(),
        )
        .expect("empty results yields a negative");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(true),
            "a kind-filtered query whose name matched nothing at all still certifies: {negative}"
        );
    }

    /// The other half of the FIR-2452 rule, on the answer that still certifies.
    /// A tool that traverses no edge cannot speak about use, and the generic
    /// sentence supplied the word anyway.
    #[test]
    fn a_certified_search_absence_states_no_verdict_about_use() {
        let payload = empty_search_page(scope_with_a_measured_class(Some(29)));
        let negative = negative_for("semantic_search", &payload, &structural_ready_envelope())
            .expect("empty results yields a negative");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(true),
            "the authority is unchanged: {negative}"
        );
        let advice = negative["advice"].as_str().unwrap();
        assert!(
            !advice.contains("genuinely absent/unused"),
            "a name filter reads the entity index and traverses no edge, so it has no \
             basis for a verdict about use: {advice}"
        );
        assert!(
            advice.contains("Absence is authoritative for this filter"),
            "{advice}"
        );
        assert!(
            advice.contains("not about use"),
            "it says which question it answered: {advice}"
        );

        // The sibling that DOES read those edges keeps the sentence, so scoping
        // one tool did not quietly disarm the others.
        let references = negative_for(
            "find_references",
            &authoritative_empty_references("function"),
            &structural_ready_envelope(),
        )
        .expect("empty references yields a negative");
        assert!(
            references["advice"]
                .as_str()
                .unwrap()
                .contains("genuinely absent/unused"),
            "find_references reads the edges, so its verdict about use stands: {references}"
        );
    }

    /// FIR-2452 clause 2. The tool whose entire output is used/unused verdicts
    /// was the only retrieval surface with no `negative` object at all, so the
    /// one with the highest blast radius per wrong absence sat outside the gate
    /// every smaller one passes.
    #[test]
    fn impact_verdicts_carry_the_rail_and_pass_the_same_gate() {
        // Populated, and still qualified: like batch reachability, an impact
        // report's rows ARE the negatives, so a zero consumer count beside a
        // full blast radius is exactly the verdict that needs calibrating.
        let mut payload = json!({
            "changed_ids": ["00000000-0000-0000-0000-000000000001"],
            "affected_callers": [],
            "entity_impacts": [{
                "entity_id": "00000000-0000-0000-0000-000000000001",
                "consumer_count": 0,
                "proven_consumer_count": 0,
            }],
        });
        payload["edge_coverage"] = cross_file_edges_observed();

        let negative = negative_for("impact_analysis", &payload, &structural_ready_envelope())
            .expect("impact verdicts are always qualified");
        assert_eq!(negative["kind"], json!("impact_verdicts"));
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(true),
            "a graph that links calls across files for this language can certify: {negative}"
        );

        // The same gate the sibling reference surfaces pass. A graph holding no
        // cross-file calls answers every impact query with an empty blast radius
        // no matter how healthy it looks, so the verdict cannot be certified.
        let mut absent = payload.clone();
        absent["edge_coverage"]["classes"]["calls"] = json!("absent");
        let negative = negative_for("impact_analysis", &absent, &structural_ready_envelope())
            .expect("impact verdicts are always qualified");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(
            negative["trust_reason"]
                .as_str()
                .unwrap()
                .starts_with("cross_file_edges_absent"),
            "{negative}"
        );

        // And an answer that published no observation at all is the unknown
        // case, never the healthy one.
        let mut unreported = payload.clone();
        unreported.as_object_mut().unwrap().remove("edge_coverage");
        let negative = negative_for("impact_analysis", &unreported, &structural_ready_envelope())
            .expect("impact verdicts are always qualified");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(
            negative["trust_reason"]
                .as_str()
                .unwrap()
                .starts_with("edge_coverage_unreported"),
            "{negative}"
        );
    }

    #[test]
    fn a_kind_filter_that_selected_an_empty_region_certifies_nothing() {
        // The second half of the FIR-2430 contract: a kind-filtered absence is a
        // statement about the kind the index holds. Certifying "no schema named
        // X" against a graph the extractor admitted no schema entity into at all
        // answers for the index and not for the repository, and the language
        // being one this build resolves does not change that.
        let payload = empty_search_page(resolvable_language_scope(Some(0)));
        let negative = negative_for("semantic_search", &payload, &structural_ready_envelope())
            .expect("empty results yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(reason.starts_with("absence_scope_empty"), "{reason}");
        assert!(negative["degraded_signals"]
            .as_array()
            .unwrap()
            .contains(&json!("absence_coverage:scope_empty")));
        // Positive control on the same payload shape: one entity in the region
        // and the same absence certifies, so the gate reads the count. It carries
        // a measured class since FIR-2496, which is the other input a
        // certification needs.
        let populated = empty_search_page(scope_with_a_measured_class(Some(1)));
        let negative = negative_for("semantic_search", &populated, &structural_ready_envelope())
            .expect("empty results yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
    }

    /// FIR-2499. An absence over a store the working copy has outrun is
    /// unknown, not absent.
    ///
    /// The reported case: `semantic_search("build_match_query")` returned zero
    /// rows with `safe_to_conclude_absent: true` while the function sat in a
    /// 140-line module on disk that no admission had taken. The graph answered
    /// correctly and the claim made from it was wrong, because the module was in
    /// no index the query reads.
    #[test]
    fn an_absence_over_unadmitted_host_content_certifies_nothing() {
        // The scope carries a measured coverage class, which is what lets this
        // payload certify at all. Without it the FIR-2496 refusal answers first
        // and the control below asserts a certification no payload of this shape
        // can make, which would leave this case unable to tell a working gate
        // from a broken one.
        let payload = empty_search_page(scope_with_a_measured_class(Some(29)));

        // The positive control first, so a failure below cannot be the payload
        // simply never certifying.
        let certified = negative_for("semantic_search", &payload, &structural_ready_envelope())
            .expect("empty results yields a negative");
        assert_eq!(
            certified["safe_to_conclude_absent"],
            json!(true),
            "the control this test rests on: the same payload certifies when the store is level"
        );

        let negative = negative_for("semantic_search", &payload, &behind_envelope(1))
            .expect("empty results yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert_eq!(negative["trust"], json!("inconclusive"));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.contains("graph_behind_working_tree"),
            "the factor names the store being behind: {reason}"
        );
        assert!(
            reason.contains("host path(s) on disk have never been admitted"),
            "and says what that means for the claim: {reason}"
        );
    }

    /// The scope of the gate. A populated answer asserts no absence, so a store
    /// being behind is not a limit on it; applying it there would put a floor
    /// under every answer on every working copy holding one untracked file.
    #[test]
    fn a_populated_answer_is_not_qualified_by_unadmitted_host_content() {
        let mut payload = empty_search_page(resolvable_language_scope(Some(29)));
        payload["results"] = json!([{ "entity_id": "e1", "name": "build_match_query" }]);
        payload["total_matches"] = json!(1);

        let level = negative_for("semantic_search", &payload, &structural_ready_envelope());
        let behind = negative_for("semantic_search", &payload, &behind_envelope(1));
        let reason_of = |value: &Option<Value>| {
            value
                .as_ref()
                .and_then(|negative| negative["trust_reason"].as_str().map(str::to_string))
        };
        assert_eq!(
            reason_of(&behind),
            reason_of(&level),
            "a populated answer reads the same either way; this gate speaks only about absences"
        );
    }

    /// A daemon envelope that is otherwise authoritative over a store holding
    /// host paths no admission has taken.
    fn behind_envelope(unadmitted_paths: u64) -> Envelope {
        Envelope::daemon().with_health(&json!({
            "graph_loaded": true,
            "initialized": true,
            "graph_generation": 12,
            "reconcile": {
                "untracked_path_count": unadmitted_paths,
                "untracked_paths_sample": ["notekeeper/search.py"],
                "untracked_observed_age_seconds": 0,
                "last_admission_success_at": "2026-08-20T13:00:00Z",
            },
        }))
    }

    #[test]
    fn an_authoritative_absence_never_recites_a_coverage_it_did_not_rest_on() {
        // FIR-2430 contract item 3. The express envelope certified an absence in
        // the same sentence that read "semantic coverage unknown". Both halves
        // were true and the pairing was still wrong, because embedding coverage
        // was never what backed a structural claim. A negative names the basis
        // its verdict rests on and recites THAT, so an unknown coverage can no
        // longer sit beside a certification it did not back.
        let payload = empty_search_page(scope_with_a_measured_class(Some(29)));
        let negative = negative_for("semantic_search", &payload, &structural_ready_envelope())
            .expect("empty results yields a negative");
        assert_eq!(negative["trust"], json!("authoritative"));
        assert_eq!(negative["semantic_coverage"], Value::Null);
        assert_eq!(negative["coverage_basis"], json!("graph_structure"));
        let advice = negative["advice"].as_str().unwrap();
        assert!(
            !advice.contains("semantic coverage"),
            "a structural verdict must not recite embedding coverage: {advice}"
        );
        assert!(
            advice.contains("graph coverage for Python"),
            "it recites the observation its own gate read: {advice}"
        );

        // The embedding-backed tools keep reciting embedding coverage, because
        // for them it IS the basis.
        let ranked = json!({ "query": "auth", "results": [], "total_ranked": 0 });
        let negative = negative_for(
            "semantic_locate",
            &ranked,
            &semantic_authoritative_envelope(),
        )
        .expect("empty results yields a negative");
        assert_eq!(negative["coverage_basis"], json!("embeddings"));
        assert!(negative["advice"]
            .as_str()
            .unwrap()
            .contains("semantic coverage 100.0%"));
    }

    #[test]
    fn the_neighborhood_and_the_seeded_scan_answer_to_the_same_gate() {
        // The two siblings the same audit found. An empty neighborhood claims
        // nothing reaches the focal, which for an incoming walk is the claim
        // `find_references` makes; an empty seed match is the same name filter
        // over the same entity index `semantic_search` reads. Both were
        // certifying from daemon health alone.
        let mut neighborhood = neighborhood_payload("in", 0);
        neighborhood["edge_coverage"] = unresolvable_language_scope(None);
        let negative = negative_for(
            "graph_neighborhood",
            &neighborhood,
            &structural_ready_envelope(),
        )
        .expect("an indexed focal with no neighbors carries a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .starts_with("entity_index_unresolved"));

        let seeded = json!({
            "query": "utils",
            "total_searched": 0,
            "candidates": [],
            "edge_coverage": unresolvable_language_scope(Some(29)),
        });
        let negative = negative_for(
            "find_dead_code_seeded",
            &seeded,
            &structural_ready_envelope(),
        )
        .expect("an empty seed match carries a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .starts_with("entity_index_unresolved"));

        // Positive control for both: a resolvable language whose observation
        // measured a class certifies, so neither gate is one that always fires.
        let mut neighborhood = neighborhood_payload("in", 0);
        neighborhood["edge_coverage"] = scope_with_a_measured_class(None);
        assert_eq!(
            negative_for(
                "graph_neighborhood",
                &neighborhood,
                &structural_ready_envelope()
            )
            .unwrap()["safe_to_conclude_absent"],
            json!(true)
        );
        let seeded = json!({
            "query": "utils",
            "total_searched": 0,
            "candidates": [],
            "edge_coverage": scope_with_a_measured_class(Some(29)),
        });
        assert_eq!(
            negative_for(
                "find_dead_code_seeded",
                &seeded,
                &structural_ready_envelope()
            )
            .unwrap()["safe_to_conclude_absent"],
            json!(true)
        );
    }

    #[test]
    fn payload_degradations_are_named_beside_the_verdict() {
        // FIR-2216. A locate page that reported an active degradation carried a
        // negative saying `degraded_signals: []` and advice reading "no degraded
        // signals", one field away from the degradation itself. The envelope's
        // flags describe the daemon; this array describes the query, and the
        // verdict has to consume both.
        let degraded = json!({
            "query": "auth",
            "results": [],
            "total_ranked": 0,
            "degradations": [{
                "component": "vector_sidecar",
                "reason": "retired_entity_keys",
                "detail": "40 ranked vector key(s) resolved to entities the graph no longer holds",
                "remediation": "run 'kin embed'",
            }],
        });
        let negative = negative_for(
            "semantic_locate",
            &degraded,
            &semantic_authoritative_envelope(),
        )
        .expect("empty results yields a negative");
        assert_eq!(
            negative["degraded_signals"],
            json!(["vector_sidecar:retired_entity_keys"])
        );
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert_eq!(negative["trust"], json!("inconclusive"));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("retrieval_degraded"));
        let advice = negative["advice"].as_str().unwrap();
        assert!(advice.contains("vector_sidecar:retired_entity_keys"));
        assert!(!advice.contains("no degraded signals"));

        // Positive control: the same page with nothing degraded stays
        // authoritative and still says so, so the signal is one that can be
        // absent.
        let clean = json!({ "query": "auth", "results": [], "total_ranked": 0 });
        let negative = negative_for(
            "semantic_locate",
            &clean,
            &semantic_authoritative_envelope(),
        )
        .unwrap();
        assert_eq!(negative["degraded_signals"], json!([]));
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
        assert!(negative["advice"]
            .as_str()
            .unwrap()
            .contains("no degraded signals"));
    }

    /// Description-query guidance is advice about how to read a ranking, not a
    /// report that any capability failed. It must not manufacture a degraded
    /// verdict, and the control below proves every real degradation still does.
    #[test]
    fn description_query_guidance_does_not_make_an_absence_inconclusive() {
        let advised = json!({
            "query": "where do notes get written to disk",
            "results": [],
            "total_ranked": 0,
            "degradations": [{
                "component": QUERY_SHAPE_COMPONENT,
                "reason": DESCRIPTION_ENTITY_RANKING_REASON,
                "detail": "no ranked entity was literally named by this query",
                "remediation": "try file granularity",
            }],
        });
        let negative = negative_for(
            "semantic_locate",
            &advised,
            &semantic_authoritative_envelope(),
        )
        .expect("empty results yields a negative");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(true),
            "query-shape advice is not a degraded run: {negative}"
        );
        assert_eq!(
            negative["degraded_signals"],
            json!([]),
            "no signal degraded; every one of them ran: {negative}"
        );
        assert!(
            !negative["trust_reason"]
                .as_str()
                .unwrap_or_default()
                .contains("retrieval_degraded"),
            "the query shape is not a reason to distrust this run: {negative}"
        );

        // The control that keeps the exemption from swallowing real
        // degradations: one genuine run degradation beside it still blocks.
        let mut mixed = advised.clone();
        mixed["degradations"] = json!([
            {
                "component": QUERY_SHAPE_COMPONENT,
                "reason": DESCRIPTION_ENTITY_RANKING_REASON,
                "detail": "description",
                "remediation": "use file granularity",
            },
            {
                "component": "vector_sidecar",
                "reason": "retired_entity_keys",
                "detail": "40 ranked vector key(s) resolved to entities the graph no longer holds",
                "remediation": "run 'kin embed'",
            },
        ]);
        let negative = negative_for(
            "semantic_locate",
            &mixed,
            &semantic_authoritative_envelope(),
        )
        .unwrap();
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(false),
            "a real degradation must still block, exemption or not: {negative}"
        );
        assert_eq!(
            negative["degraded_signals"],
            json!(["vector_sidecar:retired_entity_keys"]),
            "the exempt label is the only one dropped: {negative}"
        );
    }

    #[test]
    fn a_degradation_missing_half_its_identity_is_not_half_named() {
        // Honesty: a label is a claim about what degraded. An entry with no
        // reason is dropped rather than published as `vector_sidecar:unknown`.
        let payload = json!({
            "query": "auth",
            "results": [],
            "total_ranked": 0,
            "degradations": [{ "component": "vector_sidecar" }],
        });
        let negative = negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope(),
        )
        .unwrap();
        assert_eq!(negative["degraded_signals"], json!([]));
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
    }

    #[test]
    fn an_empty_graph_downgrades_an_empty_result() {
        // FIR-2216. A graph holding no entities answers every query with
        // nothing, so an empty result there is a fact about the graph. The
        // resolution-miss path already refused to certify absence on an empty
        // graph; the resolved-but-empty path has to agree, or an agent learns
        // which phrasing to trust rather than which answer.
        let empty_graph = Envelope::daemon().with_health(&json!({
            "graph_loaded": true,
            "initialized": true,
            "graph_entity_count": 0,
        }));
        let payload = empty_search_page(scope_with_a_measured_class(Some(12)));
        let negative = negative_for("semantic_search", &payload, &empty_graph)
            .expect("empty results yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("graph_empty"));

        // Positive control: the same loaded graph holding entities certifies the
        // absence, so the gate reads the count rather than always firing.
        let populated = Envelope::daemon().with_health(&json!({
            "graph_loaded": true,
            "initialized": true,
            "graph_entity_count": 5,
        }));
        let negative = negative_for("semantic_search", &payload, &populated).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
    }

    // ---- structural class: absence gated on GRAPH initialized + loaded ----

    #[test]
    fn find_references_on_loaded_graph_is_authoritative_without_coverage() {
        // The headline structural lift: an empty find_references is authoritative
        // on an initialized + loaded graph even with NO embedding coverage —
        // structural tools read typed relations, not embeddings.
        let payload = authoritative_empty_references("function");
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("empty references yields a negative");
        assert_eq!(negative["kind"], json!("no_references"));
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
        assert_eq!(negative["trust"], json!("authoritative"));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("structural_authoritative"));
        // graph_as_of was lifted from the /health generation marker.
        assert_eq!(negative["graph_as_of"], json!({ "generation": 12 }));
        // No embedding coverage observed — honest null, not fabricated.
        assert_eq!(negative["semantic_coverage"], Value::Null);
        assert!(negative["advice"]
            .as_str()
            .unwrap()
            .contains("authoritative"));
    }

    /// FIR-2353, the reproduction: a graph the daemon reports as initialized,
    /// loaded and undegraded, holding entities and intra-file edges only. Every
    /// freshness signal is green and the answer is still worthless, because no
    /// cross-file reference edge exists for the language to be found. The verdict
    /// must be inconclusive and the reason must name the edge gap.
    #[test]
    fn find_references_absence_is_inconclusive_when_no_cross_file_edges_exist() {
        let mut payload = authoritative_empty_references("function");
        payload["edge_coverage"] = json!({
            "scope": "language",
            "language": "Python",
            "requested_classes": ["calls", "imports", "references"],
            "classes": { "calls": "absent", "imports": "absent", "references": "absent" },
            "cross_file_classes": [],
            "budget_exhausted": false,
            "entities_examined": 26,
        });
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("empty references yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert_eq!(negative["trust"], json!("inconclusive"));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.starts_with("cross_file_edges_absent"),
            "the limiting factor must lead the reason: {reason}"
        );
        assert!(
            reason.contains("Python"),
            "the reason names the language whose edges are missing: {reason}"
        );
        // The advice an agent acts on has to agree with the verdict, or the
        // envelope contradicts itself one field apart.
        let advice = negative["advice"].as_str().unwrap();
        assert!(advice.contains("NOT authoritative"));
        // And it has to name the gap rather than prescribe an unrelated remedy.
        // The old wording told the reader to re-check after embedding was
        // complete, which no amount of embedding would ever satisfy here.
        assert!(
            advice.contains("Limiting factor: cross_file_edges_absent"),
            "the advice names the gap it is about: {advice}"
        );
        assert!(
            !advice.contains("after embedding is complete"),
            "embedding completeness is not the remedy for a missing edge class: {advice}"
        );
    }

    /// A context pack with an empty `dependents` group, over `coverage`.
    ///
    /// The group is the reference surface's answer (FIR-2474), so the payload
    /// carries the same observation `find_references` publishes beside its own
    /// empty list. A pack that shipped the group without it would be claiming an
    /// absence with no evidence the query could have found anything, which is
    /// the FIR-2353 failure arriving through a second tool.
    fn empty_pack_dependents(kind: &str, coverage: Value) -> Value {
        json!({
            "focal_entity": {
                "id": "00000000-0000-0000-0000-000000000001",
                "kind": kind,
                "name": "sendFile",
            },
            "dependencies": [{ "id": "00000000-0000-0000-0000-000000000002" }],
            "dependents": [],
            "dependency_selection": {
                "source": "dependency_edges",
                "returned": 1,
                "dependents_returned": 0,
                "certified_dependents": 0,
                "dependents_withheld": 0,
                "same_file_candidates": 0,
                "same_file_dropped": 0,
            },
            "edge_coverage": coverage,
        })
    }

    /// FIR-2775's two-surface arm. The gate that refuses to certify a reference
    /// absence a dropped call could be hiding in has to reach `get_context_pack`
    /// too, because a pack's `dependents` group is built by the same collector
    /// over the same edges. Gating a shared gap on the tool name alone is how
    /// two surfaces over one graph came to answer opposite things about one
    /// entity: the tool that refused to certify and the tool that published `[]`
    /// were reading the identical incomplete call graph.
    ///
    /// So this asserts the AGREEMENT rather than each end separately. One block,
    /// both tools, one verdict, and the healthy control beside it in the same
    /// test so a fix that floors both surfaces cannot pass either.
    #[test]
    fn both_reference_surfaces_reach_one_verdict_on_one_arrival_reading() {
        let unaccounted = json!({
            "state": "unaccounted",
            "family_files": 1,
            "family_measured": 0,
            "unaccounted_file_count": 1,
            "unaccounted_files": [{
                "file": "tests/test_storage.py",
                "parsed_call_sites": null,
                "resolved_call_edges": 2,
                "unaccounted_call_sites": null,
            }],
            "unaccounted_files_truncated": false,
            "unmeasured_reason": null,
        });
        let accounted = json!({
            "state": "accounted",
            "family_files": 2,
            "family_measured": 2,
            "unaccounted_file_count": 0,
            "unaccounted_files": [],
            "unaccounted_files_truncated": false,
            "unmeasured_reason": null,
        });

        for (block, expected, label) in [
            (&unaccounted, false, "an unaccounted arrival"),
            (&accounted, true, "an accounted arrival"),
        ] {
            let mut references = authoritative_empty_references("function");
            references[crate::caller_arrival::CALLER_ARRIVAL_KEY] = block.clone();
            let mut pack = empty_pack_dependents("function", cross_file_edges_observed());
            pack[crate::caller_arrival::CALLER_ARRIVAL_KEY] = block.clone();

            let from_references =
                negative_for("find_references", &references, &structural_ready_envelope())
                    .expect("empty references yields a negative");
            let from_pack = negative_for("get_context_pack", &pack, &structural_ready_envelope())
                .expect("an empty dependents group yields a negative");

            assert_eq!(
                from_references["safe_to_conclude_absent"],
                json!(expected),
                "{label}: find_references answered the wrong way"
            );
            assert_eq!(
                from_pack["safe_to_conclude_absent"],
                json!(expected),
                "{label}: get_context_pack answered the wrong way"
            );
            assert_eq!(
                from_references["safe_to_conclude_absent"], from_pack["safe_to_conclude_absent"],
                "{label}: the two surfaces disagreed over one reading, which is the exact \
                 failure this gate is shared to prevent"
            );
        }
    }

    /// FIR-2474, the half an agent acts on. `get_context_pack` published
    /// `dependents: []` with no verdict of any kind, so "nothing depends on
    /// this" and "this graph links none of this language's edges across files"
    /// serialized identically, and the empty list was the readable one.
    ///
    /// The express shape is the case: JavaScript, no cross-file class produced.
    #[test]
    fn a_pack_with_no_dependents_is_inconclusive_when_the_language_links_no_edges() {
        let payload = empty_pack_dependents(
            "function",
            json!({
                "scope": "language",
                "language": "JavaScript",
                "requested_classes": ["calls", "imports", "references"],
                "classes": { "calls": "absent", "imports": "absent", "references": "absent" },
                "cross_file_classes": [],
                "budget_exhausted": false,
                "entities_examined": 66,
            }),
        );
        let negative = negative_for("get_context_pack", &payload, &structural_ready_envelope())
            .expect("an empty dependents group yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert_eq!(negative["trust"], json!("inconclusive"));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.starts_with("cross_file_edges_absent"),
            "the limiting factor must lead the reason: {reason}"
        );
        assert!(
            reason.contains("JavaScript"),
            "the reason names the language whose edges are missing: {reason}"
        );
    }

    /// The control that makes the case above mean something. A gate that
    /// answered "inconclusive" for every pack would pass it and would be just as
    /// useless: an empty group on a graph that demonstrably links this
    /// language's calls across files IS an answer, and it has to read as one.
    #[test]
    fn a_pack_with_no_dependents_is_authoritative_when_the_graph_links_them() {
        let payload = empty_pack_dependents("function", cross_file_edges_observed());
        let negative = negative_for("get_context_pack", &payload, &structural_ready_envelope())
            .expect("an empty dependents group yields a negative");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(true),
            "a graph that links this language's calls across files can answer: {negative}"
        );
        assert_eq!(negative["trust"], json!("authoritative"));
    }

    /// The pack inherits the reference surface's gap along with its authority.
    /// A receiver-method call is linked by bare name, so a method's incoming
    /// edges are routinely unresolved, and `find_references` has always refused
    /// to certify an empty answer for one. A pack reading the same edges must
    /// refuse identically, or the two tools disagree about one entity in one
    /// store, which is the defect this ticket is.
    #[test]
    fn a_pack_with_no_dependents_is_inconclusive_for_a_method_focal() {
        let payload = empty_pack_dependents("method", cross_file_edges_observed());
        let negative = negative_for("get_context_pack", &payload, &structural_ready_envelope())
            .expect("an empty dependents group yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(
            negative["trust_reason"]
                .as_str()
                .unwrap()
                .contains("method_call_resolution_incomplete"),
            "the method gap must be named: {negative}"
        );
    }

    /// The shipped 0.5.42 pack carried NO `dependents` key at all, not an empty
    /// one, and the agentadopt lane hit that shape on flask. A missing key is the
    /// worse of the two: `[]` at least names the question and can be qualified,
    /// while an absent key reads as a question this tool does not answer, and the
    /// gate that would have refused to certify it never ran.
    ///
    /// The two-group split has since made the key unconditional, so this is a
    /// regression guard rather than a live bug. It is worth its cost because the
    /// regression is invisible: dropping the key silently disables the verdict
    /// instead of failing anything.
    #[test]
    fn a_pack_that_omits_its_dependents_group_is_qualified_like_an_empty_one() {
        let mut payload = empty_pack_dependents("function", cross_file_edges_observed());
        payload
            .as_object_mut()
            .unwrap()
            .remove("dependents")
            .expect("the fixture carries the group to remove");
        let negative = negative_for("get_context_pack", &payload, &structural_ready_envelope())
            .expect("an omitted dependents group is still an absence claim");
        assert_eq!(negative["kind"], json!("no_dependents"));
        assert_eq!(negative["result_count"], json!(0));
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(true),
            "the omitted shape must be qualified exactly as the empty one is: {negative}"
        );
    }

    /// The control that keeps the case above from swallowing payloads it has no
    /// business judging. A pack that failed before producing a focal has no
    /// answer to qualify, and inventing a verdict for it would report on a graph
    /// nobody queried.
    #[test]
    fn a_pack_payload_with_no_focal_gets_no_verdict() {
        let mut payload = empty_pack_dependents("function", cross_file_edges_observed());
        let map = payload.as_object_mut().unwrap();
        map.remove("dependents");
        map.remove("focal_entity");
        assert!(
            negative_for("get_context_pack", &payload, &structural_ready_envelope()).is_none(),
            "a payload carrying no answer must not be handed a verdict about one"
        );
    }

    /// A pack that returned dependents is qualified too, because FIR-2463 asks
    /// every retrieval answer for one verdict rather than only the empty ones.
    /// What it must never do is claim an absence it is not making.
    #[test]
    fn a_populated_pack_is_qualified_without_claiming_an_absence() {
        let mut payload = empty_pack_dependents("function", cross_file_edges_observed());
        payload["dependents"] = json!([{ "id": "00000000-0000-0000-0000-000000000003" }]);
        payload["dependency_selection"]["dependents_returned"] = json!(1);
        payload["dependency_selection"]["certified_dependents"] = json!(1);
        let negative = negative_for("get_context_pack", &payload, &structural_ready_envelope())
            .expect("a populated pack still carries the response's one verdict");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(false),
            "an answer with rows claims no absence: {negative}"
        );
    }

    /// A payload that reports no observation at all is the unknown case. This is
    /// the shape every retrieval tool had before FIR-2353, and reading it as
    /// healthy is precisely how absence was certified on a graph that could not
    /// answer.
    #[test]
    fn find_references_absence_is_inconclusive_when_coverage_is_unreported() {
        let mut payload = authoritative_empty_references("function");
        payload
            .as_object_mut()
            .unwrap()
            .remove("edge_coverage")
            .expect("the fixture carries an observation to remove");
        let negative =
            negative_for("find_references", &payload, &structural_ready_envelope()).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .starts_with("edge_coverage_unreported"));
    }

    /// A scan that stopped on its budget knows nothing, and "nothing" is not
    /// "absent". Reporting the truncated scan as a completed one would hand back
    /// the same false authority through a different door.
    #[test]
    fn find_references_absence_is_inconclusive_when_the_scan_was_truncated() {
        let mut payload = authoritative_empty_references("function");
        payload["edge_coverage"] = json!({
            "scope": "language",
            "language": "Rust",
            "requested_classes": ["calls"],
            "classes": { "calls": "unknown" },
            "cross_file_classes": [],
            "budget_exhausted": true,
            "entities_examined": 4096,
        });
        let negative =
            negative_for("find_references", &payload, &structural_ready_envelope()).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .starts_with("edge_coverage_unknown"));
    }

    /// The gate is scoped to the classes the QUERY asked for. A calls-only query
    /// against a graph whose only cross-file edges are imports has no coverage
    /// for what it read, and borrowing the sibling class's witness would certify
    /// an absence over edges that were never produced.
    #[test]
    fn the_edge_gate_reads_the_classes_the_query_asked_for() {
        let mut payload = authoritative_empty_references("function");
        payload["relation_kinds"] = json!(["calls"]);
        payload["edge_coverage"] = json!({
            "scope": "language",
            "language": "Python",
            "requested_classes": ["calls", "imports"],
            "classes": { "calls": "absent", "imports": "present" },
            "cross_file_classes": ["imports"],
            "budget_exhausted": false,
            "entities_examined": 12,
        });
        let negative =
            negative_for("find_references", &payload, &structural_ready_envelope()).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(reason.starts_with("cross_file_edges_absent"), "{reason}");
        assert!(
            reason.contains("calls") && !reason.contains("imports"),
            "the reason names the class the query read, not the one it did not: {reason}"
        );

        // The same graph answering the imports arm keeps its authority, so the
        // gate narrows the claim rather than blanket-denying it.
        payload["relation_kinds"] = json!(["imports"]);
        let negative =
            negative_for("find_references", &payload, &structural_ready_envelope()).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
    }

    /// The regression the fix must not become: making every absence inconclusive
    /// would satisfy FIR-2353 and destroy the tool. A graph that demonstrably
    /// links references across files still certifies a genuinely unused symbol.
    #[test]
    fn a_graph_with_cross_file_edges_still_certifies_a_genuinely_unused_symbol() {
        let payload = authoritative_empty_references("function");
        let negative =
            negative_for("find_references", &payload, &structural_ready_envelope()).unwrap();
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(true),
            "the class this graph resolves cross-file uses into is witnessed"
        );
        assert_eq!(negative["trust"], json!("authoritative"));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("structural_authoritative"));
    }

    /// FIR-2404, the reproduction: express's `createApplication`, verbatim from
    /// the payload the isolated stranger run captured on the v0.5.38 candidate.
    /// Same-name bare calls resolve on JavaScript so `calls` reads present, while
    /// nothing resolves the `require` every consuming file reaches the focal
    /// through, and the graph could not certify the absence it certified.
    ///
    /// The measured classes here are IDENTICAL to the healthy Python fixture
    /// below, which is why the verdict cannot come from them: what separates the
    /// two is that this build wires no language-server adapter for JavaScript, so
    /// its reference surface is unproducible rather than merely unobserved.
    ///
    /// "If you deleted what Kin called safe to delete here, you would delete
    /// express."
    #[test]
    fn a_javascript_module_export_is_not_certified_absent_without_reference_enrichment() {
        let mut payload = authoritative_empty_references("function");
        payload["focal_entity"]["name"] = json!("createApplication");
        payload["focal_entity"]["file_path"] = json!("lib/express.js");
        payload["edge_coverage"] = json!({
            "scope": "language",
            "language": "JavaScript",
            "requested_classes": ["calls", "imports", "references"],
            "classes": { "calls": "present", "imports": "absent", "references": "absent" },
            "cross_file_classes": ["calls"],
            "reference_enrichment": "unsupported",
            "budget_exhausted": false,
            "entities_examined": 258,
        });
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("empty references yields a negative");

        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(false),
            "a present calls class must not certify an absence in a language whose \
             reference edges cannot exist: {}",
            negative
        );
        assert_eq!(negative["trust"], json!("inconclusive"));

        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.starts_with("reference_enrichment_unsupported"),
            "the limiting factor leads the reason: {reason}"
        );
        assert!(
            reason.contains("JavaScript"),
            "and names the language it holds for: {reason}"
        );

        // The negative may not report a clean bill beside an observation naming
        // two absent classes. That contradiction is what let the advice line be
        // read as a green light.
        let signals = negative["degraded_signals"].as_array().unwrap();
        assert!(
            signals.contains(&json!("edge_coverage:imports_absent"))
                && signals.contains(&json!("edge_coverage:references_absent")),
            "both absent classes are disclosed as degraded signals: {}",
            negative["degraded_signals"]
        );
        let advice = negative["advice"].as_str().unwrap();
        assert!(
            !advice.contains("no degraded signals"),
            "the advice cannot read clean beside two absent classes: {advice}"
        );
        assert!(advice.contains("NOT authoritative"), "{advice}");
    }

    /// The other half of the same claim, and the falsification target: a gate
    /// that answered "inconclusive" unconditionally would pass the express test
    /// above and fail this one.
    ///
    /// The coverage object is copied from a real run: a converted Python
    /// repository whose `from .parsing import ...` statements resolve cleanly
    /// still reports `imports: absent`, because Kin resolves an import to a
    /// cross-file `Calls` edge and an artifact-level edge and mints no
    /// entity-level `Imports` edge at all. A gate that demanded one would report
    /// every Python absence inconclusive while looking principled.
    ///
    /// It carries `reference_enrichment: available` because that is what makes
    /// the sentence "whose cross-file uses resolve" true. Something has to have
    /// resolved them, and on Python that something is pyright. The same fixture
    /// with no server installed is the express case wearing a different
    /// language, and it must not certify.
    ///
    /// It also carries `references: present`, because the sentence above is not
    /// true without it. A pyright that resolved this repository's cross-file
    /// uses left reference edges behind: the enriched arm of stranger run
    /// npm0543 read `References: 438` on psf/requests with 699 of 1943 relations
    /// cross-file. This fixture claimed the resolution and denied the edges
    /// until FIR-2505, which is the same contradiction the express payload
    /// shipped, and it is why nothing here failed while a deletion was certified.
    /// FIR-2672. This case used to assert that the shape certified, under the
    /// reasoning that Kin minted no entity-level `Imports` edge and a gate on
    /// the class would refuse every Python answer. It is the shape the rc0552s
    /// stranger received, verbatim in every field that decides: `calls` and
    /// `references` present, a language server available, `imports: absent`
    /// disclosed one field away, and a certification over it. The rename it
    /// made on the certified sites broke on the import sites Kin never read.
    #[test]
    fn a_python_graph_whose_import_edges_were_never_produced_does_not_certify_an_unused_symbol() {
        let mut payload = authoritative_empty_references("function");
        payload["focal_entity"]["name"] = json!("never_used_anywhere");
        payload["focal_entity"]["file_path"] = json!("pkg/parsing.py");
        payload["edge_coverage"] = json!({
            "scope": "language",
            "language": "Python",
            "requested_classes": ["calls", "imports", "references"],
            "classes": { "calls": "present", "imports": "absent", "references": "present" },
            "cross_file_classes": ["calls", "references"],
            "reference_enrichment": "available",
            "budget_exhausted": false,
            "entities_examined": 12,
        });
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("empty references yields a negative");

        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(false),
            "a class the answer could not read is a class its absence cannot be certified \
             over: {negative}"
        );
        assert_eq!(negative["trust"], json!("inconclusive"));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.starts_with("cross_file_edges_absent") && reason.contains("imports"),
            "the reason leads with the class and its state: {reason}"
        );
        assert_eq!(
            negative["degraded_signals"],
            json!(["edge_coverage:imports_absent"]),
            "and the class is still disclosed as the signal it always was"
        );

        // The inverse: the same answer over a graph whose import edges exist
        // certifies, so the refusal is the class and nothing else.
        payload["edge_coverage"]["classes"]["imports"] = json!("present");
        payload["edge_coverage"]["cross_file_classes"] = json!(["calls", "imports", "references"]);
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("empty references yields a negative");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(true),
            "{negative}"
        );
        assert_eq!(negative["trust"], json!("authoritative"));
        assert_eq!(negative["degraded_signals"], json!([]));
    }

    /// The one gate reads two independent declarations, and a tool that
    /// traverses no edge is still gated when its absence is a claim about a
    /// language's extracted graph (FIR-2430). Before this, declaring no edge
    /// class skipped the gate entirely, which is how `semantic_search` reached
    /// `structural_authoritative` from daemon health alone.
    #[test]
    fn a_tool_that_traverses_no_edges_is_still_gated_on_its_language_scope() {
        // Language-scoped and publishing nothing: inconclusive by construction,
        // and the reason names the missing observation rather than an edge class
        // the tool never reads.
        for tool in [
            "semantic_search",
            "find_dead_code_seeded",
            "graph_neighborhood",
        ] {
            let gap = absence_coverage_gap(tool, &json!({ "results": [] }))
                .unwrap_or_else(|| panic!("{tool} is language-scoped and must be gated"));
            assert!(
                gap.starts_with("absence_coverage_unreported"),
                "{tool} names the missing scope observation: {gap}"
            );
            assert!(
                !gap.contains("cross-file"),
                "{tool} reads no edge class, so the reason must not name one: {gap}"
            );
        }
        // Not language-scoped: `semantic_locate` publishes no observation from
        // the daemon's own locate route and answers to embedding coverage;
        // `dead_code`'s empty result is the inverse claim; `entity_history`
        // reads change history. None of them may be gated on evidence nothing
        // collected.
        assert!(absence_coverage_gap("semantic_locate", &json!({ "results": [] })).is_none());
        assert!(absence_coverage_gap("entity_history", &json!([])).is_none());
        assert!(absence_coverage_gap("dead_code", &json!([])).is_none());
        // And an unknown tool inherits nothing: it declares no dependency, so it
        // is neither gated nor granted authority by this map.
        assert!(absence_coverage_gap("some_future_tool", &json!({})).is_none());
    }

    /// The `edge_coverage` object shipped v0.5.43 certified a deletion on, copied
    /// verbatim from the isolated stranger run npm0543 against expressjs/express
    /// at `a3714473feb3`: `impact_analysis` tool_use_id
    /// `toolu_01VAw8NSCfq74ABm42DAFABu` and `get_context_pack` tool_use_id
    /// `toolu_011vdWNY8ogtbHfPpec732AR` carry byte-identical `edge_coverage` and
    /// `_kin.completeness` blocks, which is the evidence that one decision served
    /// both surfaces (FIR-2505, FIR-2492).
    fn express_deletion_coverage(references: &str, enrichment: &str) -> Value {
        json!({
            "budget_exhausted": false,
            "classes": { "calls": "present", "imports": "absent", "references": references },
            "cross_file_classes": ["calls"],
            "entities_examined": 371,
            "language": "JavaScript",
            "reference_enrichment": enrichment,
            "requested_classes": ["calls", "imports", "references"],
            "scan": "ran",
            "scope": "language",
            "witnessed_by_answer": []
        })
    }

    /// FIR-2505 and FIR-2492, the reported direction. All ten exports of
    /// `lib/express.js` came back `consumer_count: 0`, `safe_to_conclude_absent:
    /// true` and "safe to treat that entity as unreferenced", on a payload whose
    /// own `edge_coverage` read `references: absent` beside a language server
    /// that was available. `express.Router` is referenced 32 times in that
    /// repository and `express.static` 26 times.
    #[test]
    fn a_producible_reference_class_that_produced_nothing_blocks_the_deletion_verdict() {
        let mut payload = json!({
            "entity_impacts": [],
            "dependents": [],
            "edge_coverage": express_deletion_coverage("absent", "available")
        });
        // Isolate the class under test. The express shape carries `imports:
        // absent` too, and since FIR-2672 that refuses on its own, so it would
        // lead the sentence this case reads for `references`.
        payload["edge_coverage"]["classes"]["imports"] = json!("present");
        for tool in ["impact_analysis", "get_context_pack"] {
            let gap = absence_coverage_gap(tool, &payload)
                .unwrap_or_else(|| panic!("{tool} must not certify the express deletion shape"));
            assert!(
                gap.starts_with("cross_file_edges_absent"),
                "{tool} names the absent class the verdict rested on: {gap}"
            );
            assert!(
                gap.contains("no cross-file references edges for JavaScript"),
                "{tool} names the class and the language: {gap}"
            );
            // The diagnosis a reader acts on: the server is already installed,
            // so this is the sweep rather than a missing capability.
            assert!(
                gap.contains("were producible here and were not produced"),
                "{tool} separates an unproduced class from an unproducible one: {gap}"
            );
        }
        // One verdict. The completeness block is computed from the same deciding
        // set, so it can no longer call the counts whole while the gate calls the
        // answer inconclusive. That pair is quoted inside FIR-2492.
        let negative = negative_for("impact_analysis", &payload, &structural_ready_envelope())
            .expect("impact_analysis always qualifies");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert_eq!(negative["trust"], json!("inconclusive"));
        let advice = negative["advice"].as_str().unwrap();
        assert!(
            !advice.contains("authoritative negative"),
            "the advice must stop telling a caller the row licenses a deletion: {advice}"
        );
        assert!(
            advice.contains("were producible here and were not produced"),
            "the advice carries the limiting factor a reader acts on: {advice}"
        );
    }

    /// The control FIR-2404's descendants exist to protect: the gate must not
    /// answer "uncertain" to everything. The identical question on a graph whose
    /// enrichment actually delivered, and whose every requested class is
    /// present, still certifies, so a genuinely dead entity stays deletable and
    /// the verdict keeps its ability to say yes. This is also FIR-2672's
    /// inverse: the fix must not trade a false certification for a false
    /// refusal.
    #[test]
    fn an_enriched_graph_still_certifies_the_same_deletion_question() {
        let mut payload = json!({
            "entity_impacts": [],
            "dependents": [],
            "edge_coverage": express_deletion_coverage("present", "available")
        });
        payload["edge_coverage"]["classes"]["imports"] = json!("present");
        for tool in ["impact_analysis", "get_context_pack"] {
            assert_eq!(
                absence_coverage_gap(tool, &payload),
                None,
                "{tool} must still certify when every requested class is present"
            );
        }
    }

    /// FIR-2672. This used to assert the opposite, under the reasoning that Kin
    /// minted no entity-level `Imports` edge on any language, so gating on the
    /// class would report every answer everywhere as inconclusive. That is
    /// exactly what happened to the rc0552s stranger: the express payload named
    /// `imports_absent` as a limit, the verdict weighed `calls` alone, and a
    /// deletion was certified over a class the answer could never have read.
    /// A class the answer could not read is a class its counts cannot be whole
    /// over, whatever the reason, and the gap says which reason it was.
    #[test]
    fn imports_absent_alone_blocks_a_verdict_and_names_itself() {
        let payload = json!({
            "entity_impacts": [],
            "edge_coverage": express_deletion_coverage("present", "available")
        });
        assert_eq!(
            payload["edge_coverage"]["classes"]["imports"],
            json!("absent")
        );
        let gap = absence_coverage_gap("impact_analysis", &payload)
            .expect("an absent requested class refuses on its own");
        assert!(
            gap.starts_with("cross_file_edges_absent"),
            "the gap leads with the class's state: {gap}"
        );
        assert!(
            gap.contains("no cross-file imports edges for JavaScript"),
            "and names the class and the language: {gap}"
        );

        // The build-gap reading of the same class, when the scan could say so.
        let mut unproduced = payload.clone();
        unproduced["edge_coverage"]["classes"]["imports"] = json!("unproduced");
        let gap = absence_coverage_gap("impact_analysis", &unproduced)
            .expect("an unproduced requested class refuses on its own");
        assert!(
            gap.starts_with("cross_file_edges_unproduced"),
            "the gap leads with the class's state: {gap}"
        );
        assert!(
            gap.contains("the gap is in the linker, not in the code"),
            "and says where the gap is: {gap}"
        );
    }

    /// A host that could never have produced the class keeps its own reason. The
    /// new gate is about a class that WAS producible here and was not produced,
    /// so it must not displace the build-limit and host-limit findings that
    /// already name a cause an operator can act on.
    #[test]
    fn an_unproducible_reference_class_keeps_its_existing_reason() {
        for (enrichment, expected) in [
            ("unsupported", "reference_enrichment_unsupported"),
            ("no_language_server", "reference_enrichment_unsupported"),
        ] {
            let payload = json!({
                "entity_impacts": [],
                "edge_coverage": express_deletion_coverage("absent", enrichment)
            });
            let gap = absence_coverage_gap("impact_analysis", &payload)
                .unwrap_or_else(|| panic!("{enrichment} must still be gated"));
            assert!(gap.contains(expected), "{enrichment}: {gap}");
            assert!(
                !gap.contains("were producible here and were not produced"),
                "{enrichment} was never producible here, so nothing may claim it was: {gap}"
            );
        }
    }

    /// FIR-2505's second half. `trust_reason` ended "with no degraded signals" in
    /// the same object whose `degraded_signals` array held two entries. The
    /// string was not a summary of the field beside it, it contradicted it.
    ///
    /// Asserted on the shape that still certifies, because that is the one where
    /// the contradiction survives: once a gap fires the reason is the gap and
    /// makes no claim about silence.
    #[test]
    fn a_certified_verdict_recites_its_disclosed_signals_instead_of_denying_them() {
        // FIR-2672 closed the shape this case was written on: a coverage signal
        // disclosed beside an authoritative verdict. Every disclosed coverage
        // shortfall now refuses, so the invariant this case guards, that the
        // reason sentence agrees with the `degraded_signals` beside it, is
        // asserted on both arms it can still take: a verdict with nothing
        // disclosed says so, and a verdict with a class disclosed short recites
        // that class in its refusal rather than claiming there was nothing.
        let mut payload = json!({
            "entity_impacts": [],
            "edge_coverage": express_deletion_coverage("present", "available")
        });
        payload["edge_coverage"]["classes"]["imports"] = json!("present");
        let negative = negative_for("impact_analysis", &payload, &structural_ready_envelope())
            .expect("impact_analysis always qualifies");
        assert_eq!(negative["trust"], json!("authoritative"), "{negative}");
        assert_eq!(negative["degraded_signals"], json!([]), "{negative}");
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.contains("no degraded signals"),
            "a verdict with nothing disclosed says so: {reason}"
        );
        assert!(
            reason.contains("structural_authoritative"),
            "the substrate verdict is kept, not replaced: {reason}"
        );

        payload["edge_coverage"]["classes"]["imports"] = json!("absent");
        let negative = negative_for("impact_analysis", &payload, &structural_ready_envelope())
            .expect("impact_analysis always qualifies");
        assert_eq!(negative["trust"], json!("inconclusive"), "{negative}");
        let signals = negative["degraded_signals"].as_array().unwrap().clone();
        assert!(
            signals.contains(&json!("edge_coverage:imports_absent")),
            "the short class is disclosed as a signal: {negative}"
        );
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            !reason.contains("no degraded signals"),
            "a verdict publishing {signals:?} must not claim there were none: {reason}"
        );
        assert!(
            reason.contains("imports"),
            "the reason recites the class it disclosed: {reason}"
        );
    }

    /// And the other direction: a response with nothing to disclose still says
    /// so, so the repair adds a fact rather than removing one.
    #[test]
    fn a_verdict_with_no_signals_still_says_it_has_none() {
        let payload = empty_search_page(scope_with_a_measured_class(Some(12)));
        let negative = negative_for("semantic_search", &payload, &structural_ready_envelope())
            .expect("empty results yields a negative");
        assert_eq!(negative["degraded_signals"], json!([]));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("no degraded signals"));
    }

    /// The language-scope map is the contract, asserted directly rather than
    /// only through the tools that consume it today.
    #[test]
    fn the_language_scope_map_names_every_absence_that_claims_over_a_language() {
        for tool in [
            "find_references",
            "bulk_check_references",
            "trace_data_flow",
            "impact_analysis",
            "semantic_search",
            "find_dead_code_seeded",
            "graph_neighborhood",
        ] {
            assert!(
                absence_is_language_scoped(tool),
                "{tool}'s absence is a claim about one language's extracted graph"
            );
        }
        for tool in [
            "semantic_locate",
            "dead_code",
            "entity_history",
            "some_future_tool",
        ] {
            assert!(
                !absence_is_language_scoped(tool),
                "{tool} must not be gated on a language scope it never claims over"
            );
        }
    }

    /// The map is the contract, so it is asserted directly rather than only
    /// through the tools that happen to consume it today. `impact_analysis` has
    /// no absence spec yet; its entry is what stops one inheriting authority.
    #[test]
    fn the_per_tool_dependency_map_names_what_each_absence_reads() {
        let all = vec![
            "calls".to_string(),
            "imports".to_string(),
            "references".to_string(),
        ];
        assert_eq!(
            absence_cross_file_classes("find_references", &json!({})),
            all
        );
        assert_eq!(
            absence_cross_file_classes("bulk_check_references", &json!({})),
            all
        );
        assert_eq!(
            absence_cross_file_classes("trace_data_flow", &json!({})),
            all
        );
        assert_eq!(
            absence_cross_file_classes("impact_analysis", &json!({})),
            all,
            "an absence spec added to impact_analysis must arrive already gated"
        );
        assert_eq!(
            absence_cross_file_classes(
                "find_references",
                &json!({ "relation_kinds": ["Calls", "other"] })
            ),
            vec!["calls".to_string()],
            "the query's own scope narrows the dependency, case-insensitively"
        );
        for tool in [
            "semantic_locate",
            "semantic_search",
            "graph_neighborhood",
            "dead_code",
            "find_dead_code_seeded",
            "entity_history",
        ] {
            assert!(
                absence_cross_file_classes(tool, &json!({})).is_empty(),
                "{tool} traverses no cross-file reference edge for its absence claim"
            );
        }
    }

    #[test]
    fn find_references_on_method_is_inconclusive_despite_loaded_graph() {
        // Receiver-method call edges are under-resolved by the linker
        // (method entities are keyed by qualified name; calls arrive bare), so an
        // empty find_references for a method must NOT be certified authoritative
        // ("safe to delete") even on a healthy, loaded graph.
        let payload = authoritative_empty_references("method");
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("empty references yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert_eq!(negative["trust"], json!("inconclusive"));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("method_call_resolution_incomplete"));
    }

    #[test]
    fn find_references_on_function_stays_authoritative() {
        // The gate is method-specific: a free function's incoming call edges
        // resolve, so its empty find_references remains an authoritative absence.
        let payload = authoritative_empty_references("function");
        let negative =
            negative_for("find_references", &payload, &structural_ready_envelope()).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
        assert_eq!(negative["trust"], json!("authoritative"));
    }

    /// The one substrate reason the suite could not produce before: a daemon
    /// that finished first reconciliation and reports no graph loaded. An
    /// unreachable reason is indistinguishable from a wrong one, since nothing
    /// shows it follows from the condition it names.
    #[test]
    fn find_references_on_an_unloaded_graph_names_the_load_gate() {
        let env = Envelope::daemon().with_health(&json!({
            "initialized": true,
            "graph_loaded": false,
        }));
        let payload = authoritative_empty_references("function");
        let negative = negative_for("find_references", &payload, &env).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .starts_with("graph_not_loaded"));
    }

    #[test]
    fn find_references_graph_uninitialized_is_inconclusive() {
        // graph_loaded but first reconciliation not confirmed: a structural
        // absence is not authoritative, and the reason names the GRAPH gate — not
        // coverage (find_references does not depend on embeddings).
        let env = Envelope::daemon().with_health(&json!({
            "reconciliation_status": "reconciling",
            "graph_loaded": true,
        }));
        let payload = authoritative_empty_references("function");
        let negative = negative_for("find_references", &payload, &env).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("graph_uninitialized"));
    }

    #[test]
    fn find_references_degraded_is_inconclusive() {
        // The degraded gate is class-independent: it short-circuits before the
        // structural graph check.
        let mut env = structural_ready_envelope();
        env.degraded = Degraded {
            embed_worker_failed: Some(true),
            ..Degraded::default()
        };
        // One coverage shortfall on purpose, so the second half of the
        // assertion below has something to keep: the healthy fixture carries
        // none since FIR-2672 made every class decide.
        let mut payload = authoritative_empty_references("function");
        payload["edge_coverage"]["classes"]["imports"] = json!("absent");
        let negative = negative_for("find_references", &payload, &env).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("degraded"));
        assert_eq!(
            negative["degraded_signals"],
            json!(["embed_worker_failed", "edge_coverage:imports_absent"]),
            "the daemon's flag leads, and the answer's own coverage shortfalls follow \
             it rather than being dropped"
        );
    }

    #[test]
    fn find_references_cross_repo_gap_is_inconclusive_despite_loaded_graph() {
        let payload = json!({
            "focal_entity": { "kind": "function", "name": "do_work" },
            "relation_kinds": ["calls"],
            "references": [],
            "cross_repo": {
                "status": "unavailable",
                "reason": "malformed spine xref response: missing field `src_repo`",
            },
        });
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("empty references yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert_eq!(negative["trust"], json!("inconclusive"));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("cross_repo_unavailable"));
        assert!(negative["advice"]
            .as_str()
            .unwrap()
            .contains("NOT authoritative"));
    }

    #[test]
    fn find_references_incomplete_cross_repo_authority_is_inconclusive() {
        let payload = json!({
            "focal_entity": { "kind": "function", "name": "do_work" },
            "relation_kinds": ["imports"],
            "references": [],
            "cross_repo": {
                "status": "available",
                "authority_complete": false,
                "authority_revision": "sha256:dirty",
                "authority_roots": { "provider": "provider-root" },
            },
        });
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("empty references yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert_eq!(negative["trust"], json!("inconclusive"));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("cross_repo_authority_incomplete"));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("sha256:dirty"));
    }

    #[test]
    fn find_references_legacy_unwatermarked_cross_repo_is_inconclusive() {
        let payload = json!({
            "focal_entity": { "kind": "function", "name": "do_work" },
            "references": [],
            "cross_repo": {
                "status": "available",
                "payload_version": 1,
                "reference_count": 0,
            },
        });
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("empty references yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("unwatermarked"));
    }

    #[test]
    fn find_references_complete_cross_repo_authority_remains_authoritative() {
        let payload = authoritative_empty_references("function");
        let negative = negative_for("find_references", &payload, &structural_ready_envelope())
            .expect("empty references yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
        assert_eq!(negative["trust"], json!("authoritative"));
    }

    /// FIR-2353, generation 7: the same miss came back inconclusive with
    /// "cross_repo_unavailable: spine root mismatch" as the reason. The verdict
    /// was right and the explanation belonged to another repository, which trains
    /// a reader to ignore the reason text. The edge gap is the limiting factor and
    /// has to lead; the spine note may follow but must never stand in for it.
    #[test]
    fn a_spine_gap_never_stands_in_for_the_edge_gap_that_actually_limited_the_answer() {
        let mut payload = authoritative_empty_references("function");
        payload["edge_coverage"] = json!({
            "scope": "language",
            "language": "Python",
            "requested_classes": ["calls", "imports", "references"],
            "classes": { "calls": "absent", "imports": "absent", "references": "absent" },
            "cross_file_classes": [],
            "budget_exhausted": false,
            "entities_examined": 26,
        });
        payload["cross_repo"] = json!({
            "status": "unavailable",
            "code": "spine_root_stale",
            "reason": "spine root mismatch for repository nk: live/session graph root b2 has \
                       advanced past the registered spine root a1",
        });
        let negative =
            negative_for("find_references", &payload, &structural_ready_envelope()).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.starts_with("cross_file_edges_absent"),
            "the edge gap is the limiting factor and leads: {reason}"
        );
        let edge_position = reason.find("cross_file_edges_absent").unwrap();
        let spine_position = reason.find("spine_root_stale").unwrap();
        assert!(
            edge_position < spine_position,
            "a cross-repo note must follow the local limiting factor, not precede it: {reason}"
        );
    }

    /// The spine reason survives where it IS the limiting factor: cross-file
    /// coverage present, local graph healthy, and only the cross-repo watermark
    /// stale. A fix that simply suppressed the spine gap would lose a real one.
    #[test]
    fn the_spine_reason_leads_when_the_spine_is_the_only_gap() {
        let mut payload = authoritative_empty_references("function");
        payload["cross_repo"] = json!({
            "status": "unavailable",
            "code": "spine_root_stale",
            "reason": "spine root mismatch for repository nk: live/session graph root b2 has \
                       advanced past the registered spine root a1",
        });
        let negative =
            negative_for("find_references", &payload, &structural_ready_envelope()).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .starts_with("spine_root_stale"));
    }

    /// An unregistered repository is the ordinary single-repo state. It must not
    /// be reported as a mismatch of anything, and it must not be reported as the
    /// limit that stopped this answer being trusted.
    ///
    /// The producer's own sentence ends "says nothing about references inside
    /// this repository", and that sentence was being handed back as the limiting
    /// factor for an answer about this repository (FIR-2633). A reader cannot act
    /// on it, and the response already reports the state in full under
    /// `cross_repo`. It is stated as a note instead, which is the channel a
    /// condition that limits nothing belongs in.
    #[test]
    fn an_unregistered_repository_is_stated_as_a_note_and_never_as_a_limit() {
        let mut payload = authoritative_empty_references("function");
        payload["cross_repo"] = json!({
            "status": "unavailable",
            "code": "spine_repo_unregistered",
            "reason": "repository nk has no registered spine root, so cross-repo authority \
                       cannot answer for it",
        });
        let negative =
            negative_for("find_references", &payload, &structural_ready_envelope()).unwrap();
        assert_eq!(negative["trust"], json!("authoritative"), "{negative}");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(true),
            "{negative}"
        );
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            !reason.contains("spine_repo_unregistered"),
            "a spine that was never configured limited nothing: {reason}"
        );
        assert!(!reason.contains("mismatch"), "nothing mismatched: {reason}");
        assert!(
            !negative["advice"]
                .as_str()
                .unwrap_or_default()
                .contains("spine_repo_unregistered"),
            "and the advice must not instruct the reader to act on it: {negative}"
        );
        assert!(
            note_matching(&negative, "spine_repo_unregistered").is_some(),
            "the condition is still stated, in the channel that limits nothing: {negative}"
        );
    }

    /// The note channel, read the way every assertion below reads it.
    fn note_matching(negative: &Value, prefix: &str) -> Option<String> {
        negative
            .get("notes")?
            .as_array()?
            .iter()
            .filter_map(Value::as_str)
            .find(|note| note.starts_with(prefix))
            .map(str::to_string)
    }

    /// A single-repo install has no cross-repo authority to have failed, so
    /// `not_configured` states itself and leaves the verdict alone.
    ///
    /// This is the case FIR-2633 is about at its most common: every absent
    /// `find_references` on every install with no spine came back inconclusive,
    /// naming a limit about other repositories as the reason an answer about this
    /// one could not be trusted.
    #[test]
    fn a_spine_that_was_never_configured_does_not_limit_a_single_repo_answer() {
        let mut payload = authoritative_empty_references("function");
        payload["cross_repo"] = json!({ "status": "not_configured" });
        let negative =
            negative_for("find_references", &payload, &structural_ready_envelope()).unwrap();
        assert_eq!(negative["trust"], json!("authoritative"), "{negative}");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(true),
            "{negative}"
        );
        assert!(
            !negative["trust_reason"]
                .as_str()
                .unwrap()
                .contains("cross_repo_not_configured"),
            "{negative}"
        );
        let note = note_matching(&negative, "cross_repo_not_configured")
            .unwrap_or_else(|| panic!("the state is still reported: {negative}"));
        assert!(
            note.contains("scoped to this repository"),
            "and it says what it means rather than naming a failure: {note}"
        );
    }

    /// The control that stops this fix becoming "never report cross-repo", for
    /// both tools and every code that describes a spine which IS configured.
    ///
    /// Suppressing all cross-repo gaps would pass every assertion above and lose
    /// a real one. These are the qualifiers that must stay gaps.
    #[test]
    fn a_configured_spine_that_did_not_answer_still_limits_the_answer() {
        for status in [
            json!({ "status": "unavailable", "code": "spine_root_stale", "reason": "root has advanced" }),
            json!({ "status": "unavailable", "reason": "malformed spine xref response" }),
            json!({ "status": "mystery" }),
            json!({}),
        ] {
            for qualifier in [
                cross_repo_references_qualifier(&json!({ "cross_repo": status.clone() })),
                cross_repo_bulk_qualifier(&json!({ "cross_repo": status.clone() })),
            ] {
                assert!(
                    matches!(qualifier, CrossRepoQualifier::Gap(_)),
                    "a configured spine that did not answer is a real gap: {status}"
                );
            }
        }
    }

    /// The same table from the other side: the two states that are NOT gaps, on
    /// both tools. The bulk twin shares the classification and is asserted here
    /// rather than left to be assumed from the `find_references` cases above.
    #[test]
    fn an_unconfigured_spine_is_a_note_on_both_reference_tools() {
        for status in [
            json!({ "status": "not_configured" }),
            json!({
                "status": "unavailable",
                "code": "spine_repo_unregistered",
                "reason": "no registered spine root",
            }),
        ] {
            for qualifier in [
                cross_repo_references_qualifier(&json!({ "cross_repo": status.clone() })),
                cross_repo_bulk_qualifier(&json!({ "cross_repo": status.clone() })),
            ] {
                assert!(
                    matches!(qualifier, CrossRepoQualifier::Note(_)),
                    "an unconfigured spine states itself and limits nothing: {status}"
                );
            }
        }
    }

    /// A reason with no computed code behind it keeps the catch-all label rather
    /// than being promoted into a condition the producer never named.
    #[test]
    fn an_uncoded_cross_repo_reason_keeps_the_generic_label() {
        let mut payload = authoritative_empty_references("function");
        payload["cross_repo"] = json!({
            "status": "unavailable",
            "reason": "KIN_REPO_ID is empty",
        });
        let negative =
            negative_for("find_references", &payload, &structural_ready_envelope()).unwrap();
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .starts_with("cross_repo_unavailable: KIN_REPO_ID is empty"));
    }

    #[test]
    fn find_references_missing_or_unknown_cross_repo_authority_is_inconclusive() {
        for (cross_repo, expected_reason) in [
            (None, "cross_repo_authority_missing"),
            // `not_configured` is deliberately absent here: it is the one
            // status that reports a spine which was never configured, so it is
            // a note rather than a gap and is asserted as one above (FIR-2633).
            (
                Some(json!({ "status": "mystery" })),
                "cross_repo_authority_unknown",
            ),
            (Some(json!({})), "cross_repo_authority_missing"),
        ] {
            let mut payload = json!({
                "focal_entity": {
                    "id": "00000000-0000-0000-0000-000000000001",
                    "kind": "function",
                    "name": "do_work",
                },
                "references": [],
            });
            if let Some(cross_repo) = cross_repo {
                payload["cross_repo"] = cross_repo;
            }
            let negative =
                negative_for("find_references", &payload, &structural_ready_envelope()).unwrap();
            assert_eq!(negative["safe_to_conclude_absent"], json!(false));
            assert!(negative["trust_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains(expected_reason)));
        }
    }

    #[test]
    fn bare_array_dead_code_empty_yields_negative() {
        // dead_code returns a bare array; empty means "nothing dead" but its
        // completeness still hinges on coverage/freshness.
        let payload = json!([]);
        let negative = negative_for("dead_code", &payload, &Envelope::offline()).unwrap();
        assert_eq!(negative["kind"], json!("no_dead_code"));
        assert_eq!(negative["result_count"], json!(0));
    }

    #[test]
    fn bare_array_entity_history_nonempty_yields_no_negative() {
        let payload = json!([{ "change_id": "c1" }]);
        assert!(negative_for("entity_history", &payload, &Envelope::daemon()).is_none());
    }

    #[test]
    fn bulk_check_always_qualifies_even_when_populated() {
        let payload = json!({
            "results": [
                { "entity_id": "a", "has_references": false },
                { "entity_id": "b", "has_references": true },
            ]
        });
        let negative = negative_for("bulk_check_references", &payload, &Envelope::offline())
            .expect("bulk always qualifies");
        assert_eq!(negative["kind"], json!("reachability_verdicts"));
        assert_eq!(negative["interpretation"], json!("qualified_verdicts"));
        assert_eq!(negative["result_count"], json!(2));
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["advice"]
            .as_str()
            .unwrap()
            .contains("has_references: false"));
    }

    /// A neighborhood payload for a focal that was found, carrying `count`
    /// neighbors reached over `count` edges in `direction`.
    fn neighborhood_payload(direction: &str, count: usize) -> Value {
        let focal = "00000000-0000-0000-0000-000000000001";
        let mut entities = vec![json!({ "id": focal, "name": "focal" })];
        let mut relations = Vec::new();
        for index in 0..count {
            entities.push(json!({ "id": focal, "name": format!("neighbor{index}") }));
            relations.push(json!({ "src": focal, "dst": focal, "direction": "outgoing" }));
        }
        let mut payload = json!({
            "focal_id": focal,
            "direction": direction,
            "depth": 2,
            "entity_count": entities.len(),
            "relation_count": relations.len(),
            "entities": entities,
            "relations": relations,
        });
        // The handler observes the focal's language on every walk that expanded
        // no edge, so the fixture does too. Scoped without a count: a walk
        // measures no region, and a count it did not take must not be published
        // as a zero.
        if relations.is_empty() {
            payload["edge_coverage"] = resolvable_language_scope(None);
        }
        payload
    }

    /// The neighborhood always returns the focal itself, so keying its absence
    /// on the entity list meant the qualifier the tool's own description
    /// promises never fired for an entity that is in the graph, the only case
    /// an agent asks "is this really isolated?" about.
    #[test]
    fn neighborhood_with_no_neighbors_is_qualified() {
        let payload = neighborhood_payload("both", 0);
        let negative = negative_for("graph_neighborhood", &payload, &structural_ready_envelope())
            .expect("an indexed focal with no neighbors must carry a negative");
        assert_eq!(negative["kind"], json!("no_neighbors"));
        assert_eq!(negative["result_count"], json!(0));
        // The qualifier arriving is what this case is about, and since FIR-2496
        // what it says is that the walk cannot certify isolation: the handler's
        // observation measures no coverage class, so an entity nothing reaches
        // and an entity whose incoming edges were never linked read the same
        // here. The same payload with a class measured certifies, which is the
        // control in
        // `the_neighborhood_and_the_seeded_scan_answer_to_the_same_gate`.
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(
            negative["trust_reason"]
                .as_str()
                .unwrap()
                .contains("absence_coverage_unmeasured"),
            "the reason names the measurement nothing took: {negative}"
        );
    }

    /// One neighbor is not an absence, whichever side it sits on.
    #[test]
    fn neighborhood_with_a_neighbor_gets_no_negative() {
        let payload = neighborhood_payload("both", 1);
        let negative = negative_for("graph_neighborhood", &payload, &structural_ready_envelope())
            .expect("every retrieval answer carries the response verdict");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert_eq!(negative["interpretation"], json!("qualified_answer"));
    }

    /// Since the traversal became directional, an empty walk is empty only on
    /// the side that was walked: an entity with forty dependencies and no
    /// dependents must not be handed back as having no neighbors at all.
    #[test]
    fn neighborhood_absence_names_the_direction_that_was_walked() {
        let dependents = neighborhood_payload("in", 0);
        let negative = negative_for(
            "graph_neighborhood",
            &dependents,
            &structural_ready_envelope(),
        )
        .unwrap();
        let subject = negative["subject"].as_str().unwrap().to_string();
        assert!(
            subject.contains("dependents") && !subject.contains("no graph neighbors"),
            "an incoming-only walk must claim only dependents: {subject}"
        );
        assert!(
            negative["advice"].as_str().unwrap().contains("dependents"),
            "the advice sentence carries the same framing"
        );

        let dependencies = neighborhood_payload("out", 0);
        let negative = negative_for(
            "graph_neighborhood",
            &dependencies,
            &structural_ready_envelope(),
        )
        .unwrap();
        let subject = negative["subject"].as_str().unwrap().to_string();
        assert!(
            subject.contains("dependencies") && !subject.contains("no graph neighbors"),
            "an outgoing-only walk must claim only dependencies: {subject}"
        );

        let both = neighborhood_payload("both", 0);
        let negative =
            negative_for("graph_neighborhood", &both, &structural_ready_envelope()).unwrap();
        assert!(
            negative["subject"]
                .as_str()
                .unwrap()
                .contains("either direction"),
            "only a merged walk may claim both sides are empty"
        );
    }

    /// `depth: 0` expands no edges at all, so the empty result describes the
    /// request rather than the entity. Reading it as authoritative isolation
    /// would answer, off a walk that examined nothing, the question a caller
    /// asks before deleting code.
    #[test]
    fn neighborhood_at_depth_zero_never_certifies_absence() {
        let mut payload = neighborhood_payload("both", 0);
        payload["depth"] = json!(0);
        let negative = negative_for("graph_neighborhood", &payload, &structural_ready_envelope())
            .expect("depth zero must still be qualified rather than left bare");
        assert_eq!(negative["kind"], json!("no_traversal"));
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(false),
            "a walk that expanded no edges cannot certify isolation"
        );
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("depth_zero"));
    }

    /// A degraded substrate is the reason every entity looks absent, so it is
    /// the reason that explains the neighborhood's own. Reporting only the
    /// specific gap would name a fact about the graph's contents where the
    /// truth is that the graph could not be trusted to answer at all.
    #[test]
    fn neighborhood_gap_keeps_the_substrate_reason_beside_it() {
        let mut env = structural_ready_envelope();
        env.degraded = Degraded {
            embed_worker_failed: Some(true),
            ..Degraded::default()
        };
        let mut payload = neighborhood_payload("both", 0);
        payload["entity_count"] = json!(0);
        let negative = negative_for("graph_neighborhood", &payload, &env)
            .expect("a focal the walk never found must still be qualified");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.contains("degraded"),
            "the substrate gap that explains the absence must survive: {reason}"
        );
        assert!(
            reason.contains("focal_not_in_graph"),
            "the neighborhood's own gap must still be reported: {reason}"
        );
    }

    /// `limit: 0` empties the edge array of a neighborhood that really has
    /// neighbors. A truncated answer is not an absence, and the pre-truncation
    /// total is the only thing that can tell them apart.
    #[test]
    fn neighborhood_truncated_to_nothing_is_not_an_absence() {
        let mut payload = neighborhood_payload("both", 3);
        payload["entities"] = json!([]);
        payload["relations"] = json!([]);
        let negative = negative_for("graph_neighborhood", &payload, &structural_ready_envelope())
            .expect("every retrieval answer carries the response verdict");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(false),
            "a walk that found three edges must not report an absence when the caller capped \
             the output: {negative}"
        );
        assert_eq!(negative["interpretation"], json!("qualified_answer"));
    }

    /// A focal that is not in the graph produces the same empty edge set as an
    /// isolated one. Certifying that as authoritative isolation answers a
    /// question the walk never reached, so report the gap instead.
    #[test]
    fn neighborhood_absent_focal_is_a_gap_not_certified_isolation() {
        let payload = json!({
            "focal_id": "00000000-0000-0000-0000-000000000001",
            "direction": "both",
            "entity_count": 0,
            "relation_count": 0,
            "entities": [],
            "relations": [],
        });
        let negative = negative_for("graph_neighborhood", &payload, &structural_ready_envelope())
            .expect("a missing focal must still be qualified");
        assert_eq!(negative["kind"], json!("focal_not_in_graph"));
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(false),
            "a graph that never held the focal cannot certify that it is isolated"
        );
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("focal_not_in_graph"));
    }

    /// A resolved trace chain that came back empty, reporting everything the
    /// in-process handler reports: a unique, non-method focal and a walk that
    /// finished inside its bounds.
    fn clean_empty_trace(direction: &str) -> Value {
        json!({
            "focal_id": "00000000-0000-0000-0000-000000000001",
            "focal_name": "do_work",
            "focal_kind": "Function",
            "direction": direction,
            "depth": 3,
            "chain": [],
            "total_steps": 0,
            "truncated": false,
            "focal_resolution": {
                "addressed_by": "name",
                "same_name_candidates": 1,
            },
            "edge_coverage": cross_file_edges_observed(),
        })
    }

    #[test]
    fn trace_on_loaded_graph_is_authoritative_when_the_walk_reports_no_gap() {
        let negative = negative_for(
            "trace_data_flow",
            &clean_empty_trace("both"),
            &structural_ready_envelope(),
        )
        .expect("an empty chain yields a negative");
        assert_eq!(negative["kind"], json!("no_flow"));
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("structural_authoritative"));
    }

    /// The reported defect: the walk never reported how the focal resolved, and
    /// the qualifier certified absence anyway. A count it cannot see is unknown,
    /// and unknown never certifies.
    #[test]
    fn trace_without_a_resolution_report_is_inconclusive() {
        let mut payload = clean_empty_trace("callers");
        payload.as_object_mut().unwrap().remove("focal_resolution");
        let negative = negative_for("trace_data_flow", &payload, &structural_ready_envelope())
            .expect("an empty chain yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("focal_resolution_unreported"));
        assert!(negative["advice"]
            .as_str()
            .unwrap()
            .contains("NOT authoritative"));
    }

    #[test]
    fn trace_with_same_named_twins_is_inconclusive() {
        let mut payload = clean_empty_trace("callers");
        payload["focal_resolution"]["same_name_candidates"] = json!(2);
        let negative = negative_for("trace_data_flow", &payload, &structural_ready_envelope())
            .expect("an empty chain yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(reason.contains("focal_resolution_ambiguous"), "{reason}");
        assert!(reason.contains('2'), "the count must be named: {reason}");
    }

    /// The method gate is the one `find_references` already applies, and it
    /// bears on a walk that read incoming edges. An outgoing-only walk never
    /// looked at them, so the gate does not apply and the absence stands.
    #[test]
    fn trace_method_gate_follows_the_direction_that_was_walked() {
        for direction in ["callers", "both"] {
            let mut payload = clean_empty_trace(direction);
            payload["focal_kind"] = json!("Method");
            let negative =
                negative_for("trace_data_flow", &payload, &structural_ready_envelope()).unwrap();
            assert_eq!(
                negative["safe_to_conclude_absent"],
                json!(false),
                "a {direction} walk reads incoming edges: {negative}"
            );
            assert!(negative["trust_reason"]
                .as_str()
                .unwrap()
                .contains("method_call_resolution_incomplete"));
        }

        let mut outgoing = clean_empty_trace("calls");
        outgoing["focal_kind"] = json!("Method");
        let negative =
            negative_for("trace_data_flow", &outgoing, &structural_ready_envelope()).unwrap();
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(true),
            "an outgoing-only walk never read the under-resolved edges: {negative}"
        );
    }

    /// The requests-shaped fixture, FIR-2781's own case. A POPULATED chain whose
    /// spine was clipped: the stranger walked `verify` from `requests.get`,
    /// `limit_per_step` threw away 11 of `Session.send`'s 15 callees before
    /// relevance was consulted, `HTTPAdapter.send` never appeared, and the
    /// answer read as a lower bound. Had they trusted it they would have written
    /// that `verify` ends at `Session.send`.
    fn spine_clipped_trace() -> Value {
        let mut payload = clean_empty_trace("calls");
        // Populated, which is the point: this defect does not need an empty
        // answer, and the gate must fire on a chain that returned rows.
        payload["chain"] = json!([
            { "entity_name": "get", "parent_step": null, "step": 0 },
            { "entity_name": "request", "parent_step": 0, "step": 1 },
            { "entity_name": "Session.request", "parent_step": 1, "step": 2 },
            { "entity_name": "Session.send", "parent_step": 2, "step": 3 },
            { "entity_name": "resolve_redirects", "parent_step": 3, "step": 4 },
        ]);
        payload["total_steps"] = json!(5);
        payload["truncated"] = json!(true);
        payload["steps_omitted"] = json!(126);
        payload["spine_clipped_steps"] = json!(1);
        payload["spine_dropped_crossing_file"] = json!(11);
        payload["degradations"] = json!([
            { "component": "fanout_cap", "reason": "spine_clipped" }
        ]);
        payload
    }

    /// The refusal itself: a spine-clipped answer may not be read as evidence
    /// that the focal cannot reach something, and the sentence has to say so in
    /// words a caller cannot hear as a mere lower bound.
    #[test]
    fn a_spine_clipped_chain_refuses_the_never_reaches_conclusion() {
        let negative = negative_for(
            "trace_data_flow",
            &spine_clipped_trace(),
            &structural_ready_envelope(),
        )
        .expect("a qualified trace answer yields a negative");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.contains(TRACE_SPINE_CLIPPED_LIMITING_FACTOR),
            "the spine clause must be in the factor: {reason}"
        );
        // The three things the acceptance asks the sentence to say, each checked
        // rather than assumed from the id being present.
        assert!(
            reason.contains("NOT a lower bound"),
            "the sentence must refuse the lower-bound reading outright: {reason}"
        );
        assert!(
            reason.contains("was not looked for"),
            "it must say the missing hop was never searched, not merely not found: {reason}"
        );
        assert!(
            reason.contains("X never reaches Y"),
            "it must name the conclusion it forbids: {reason}"
        );
    }

    /// The captain's first condition: the specific clause ABSORBS the two it
    /// supersedes rather than replacing them away, so no information dies with
    /// them.
    #[test]
    fn the_spine_clause_carries_what_the_clauses_it_supersedes_would_have_said() {
        let negative = negative_for(
            "trace_data_flow",
            &spine_clipped_trace(),
            &structural_ready_envelope(),
        )
        .unwrap();
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.contains("126 step(s) were omitted"),
            "the omitted count trace_walk_truncated would have implied must survive: {reason}"
        );
        assert!(
            reason.contains("hit a per-step or total cap"),
            "the cap fact must survive: {reason}"
        );
        assert!(
            reason.contains("ran degraded"),
            "the degraded fact trace_walk_degraded carried must survive: {reason}"
        );
        assert!(
            reason.contains("11 of the dropped neighbours lived outside the file"),
            "the cross-file count must survive: {reason}"
        );
    }

    /// The captain's second condition, pinned as a property rather than left an
    /// implementation detail: a spine-clipped answer carries EXACTLY ONE cap
    /// clause. Goes red if anyone re-adds a general clause beside the specific
    /// one, or breaks the supersession so both fire.
    ///
    /// Its controls sit in the same test, because a supersession assertion with
    /// no control is satisfied by a gate that emits nothing at all: a non-spine
    /// truncation must still get `trace_walk_truncated`, and a non-spine
    /// degradation must still get `trace_walk_degraded`, each untouched.
    #[test]
    fn a_spine_clipped_answer_carries_exactly_one_cap_clause() {
        let negative = negative_for(
            "trace_data_flow",
            &spine_clipped_trace(),
            &structural_ready_envelope(),
        )
        .unwrap();
        let reason = negative["trust_reason"].as_str().unwrap();
        let cap_clauses = [
            TRACE_SPINE_CLIPPED_LIMITING_FACTOR,
            "trace_walk_truncated",
            "trace_walk_degraded",
        ]
        .iter()
        .filter(|id| reason.contains(**id))
        .count();
        assert_eq!(
            cap_clauses, 1,
            "one cap, one sentence: three sentences about one cap teach a reader to skim all \
             three. Got {cap_clauses} in: {reason}"
        );
        assert!(reason.contains(TRACE_SPINE_CLIPPED_LIMITING_FACTOR));

        // Control one: truncation that did NOT clip the spine keeps the general
        // clause, untouched.
        let mut truncated = clean_empty_trace("both");
        truncated["truncated"] = json!(true);
        let general =
            negative_for("trace_data_flow", &truncated, &structural_ready_envelope()).unwrap();
        let general_reason = general["trust_reason"].as_str().unwrap();
        assert!(
            general_reason.contains("trace_walk_truncated"),
            "a non-spine truncation must still get the general clause: {general_reason}"
        );
        assert!(
            !general_reason.contains(TRACE_SPINE_CLIPPED_LIMITING_FACTOR),
            "and must not get the spine clause: {general_reason}"
        );

        // Control two: a degradation that did NOT clip the spine likewise.
        let mut degraded = clean_empty_trace("both");
        degraded["degradations"] = json!([{ "component": "entity_bodies", "reason": "budget" }]);
        let general =
            negative_for("trace_data_flow", &degraded, &structural_ready_envelope()).unwrap();
        let general_reason = general["trust_reason"].as_str().unwrap();
        assert!(
            general_reason.contains("trace_walk_degraded"),
            "a non-spine degradation must still get the general clause: {general_reason}"
        );
        assert!(
            !general_reason.contains(TRACE_SPINE_CLIPPED_LIMITING_FACTOR),
            "and must not get the spine clause: {general_reason}"
        );
    }

    /// The other half of the control the ticket demands: an unclipped trace
    /// still certifies. A gate that refused every trace would pass every
    /// assertion above and be worthless.
    #[test]
    fn an_unclipped_trace_still_certifies() {
        let negative = negative_for(
            "trace_data_flow",
            &clean_empty_trace("both"),
            &structural_ready_envelope(),
        )
        .unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            !reason.contains(TRACE_SPINE_CLIPPED_LIMITING_FACTOR),
            "{reason}"
        );

        // And clipping that is NOT on the spine is not spine clipping. A clip at
        // the end of a branch costs breadth a reader can see missing; only a clip
        // the walk continued BENEATH makes the chain read like the route while
        // hiding the hop. This is the sharper control, because a gate keyed on
        // `clipped_steps` rather than on `spine_clipped_steps` passes every other
        // arm here and fails this one.
        let mut off_spine = clean_empty_trace("both");
        off_spine["clipped_steps"] = json!([
            { "entity_name": "leaf", "step": 9, "continued_below": false, "dropped_callees": 4 }
        ]);
        let negative =
            negative_for("trace_data_flow", &off_spine, &structural_ready_envelope()).unwrap();
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            !reason.contains(TRACE_SPINE_CLIPPED_LIMITING_FACTOR),
            "a clip the walk did not continue beneath is not spine clipping: {reason}"
        );
    }

    /// The join rule, asserted on this producer rather than trusted to the guard
    /// that drives a different one by name.
    ///
    /// The clause names a list of absorbed facts, and the vec it returns into is
    /// joined on `CLAUSE_SEPARATOR` by its caller. Joining CLAUSES on the
    /// separator is correct; a separator INSIDE one clause reaches a reader as a
    /// labelled clause plus an unlabelled fragment.
    #[test]
    fn the_spine_clause_never_carries_the_clause_separator() {
        let mut seen = 0;
        for (label, payload) in [
            ("all facts absorbed", spine_clipped_trace()),
            ("no cross-file drops", {
                let mut p = spine_clipped_trace();
                p.as_object_mut()
                    .unwrap()
                    .remove("spine_dropped_crossing_file");
                p
            }),
            ("clipped but neither truncated nor degraded", {
                let mut p = spine_clipped_trace();
                p["truncated"] = json!(false);
                p.as_object_mut().unwrap().remove("steps_omitted");
                p["degradations"] = json!([]);
                p
            }),
            ("several spine nodes", {
                let mut p = spine_clipped_trace();
                p["spine_clipped_steps"] = json!(4);
                p
            }),
        ] {
            let clause = spine_clipping_gap(
                &payload,
                payload["spine_clipped_steps"].as_u64().unwrap_or(1),
            );
            seen += 1;
            assert!(
                !clause.contains(crate::verdict::CLAUSE_SEPARATOR),
                "{label}: the clause carries the separator, so any reader that splits the \
                 rendered factor cuts it into a labelled clause and an unlabelled fragment: \
                 {clause}"
            );
        }
        assert!(seen > 0, "no clause was produced, so this asserted nothing");
    }

    /// A walk stopped by its own caps or work bounds did not examine what an
    /// empty chain is read as having ruled out. `degradations` is the daemon
    /// route's name for the same fact.
    #[test]
    fn trace_cut_short_by_its_own_bounds_is_inconclusive() {
        let mut truncated = clean_empty_trace("both");
        truncated["truncated"] = json!(true);
        let negative =
            negative_for("trace_data_flow", &truncated, &structural_ready_envelope()).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("trace_walk_truncated"));

        let mut degraded = clean_empty_trace("both");
        degraded["degradations"] = json!([{ "component": "entity_bodies", "reason": "budget" }]);
        let negative =
            negative_for("trace_data_flow", &degraded, &structural_ready_envelope()).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("trace_walk_degraded"));
    }

    /// An absence with two causes has two, and a reader deciding whether to
    /// re-run or to stop trusting the graph needs both.
    #[test]
    fn trace_reports_every_gap_beside_the_substrate_reason() {
        let mut payload = clean_empty_trace("callers");
        payload["focal_kind"] = json!("Method");
        payload.as_object_mut().unwrap().remove("focal_resolution");
        let negative = negative_for("trace_data_flow", &payload, &Envelope::offline()).unwrap();
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(reason.contains("offline_fallback"), "{reason}");
        assert!(
            reason.contains("method_call_resolution_incomplete"),
            "{reason}"
        );
        assert!(reason.contains("focal_resolution_unreported"), "{reason}");
    }

    #[test]
    fn trace_absence_names_the_direction_that_was_walked() {
        let outgoing = negative_for(
            "trace_data_flow",
            &clean_empty_trace("calls"),
            &Envelope::offline(),
        )
        .unwrap();
        let subject = outgoing["subject"].as_str().unwrap();
        assert!(
            subject.contains("anything it calls") && !subject.contains("either direction"),
            "{subject}"
        );
        assert!(outgoing["advice"]
            .as_str()
            .unwrap()
            .contains("callers were not walked"));

        let incoming = negative_for(
            "trace_data_flow",
            &clean_empty_trace("callers"),
            &Envelope::offline(),
        )
        .unwrap();
        assert!(incoming["subject"]
            .as_str()
            .unwrap()
            .contains("anything that calls it"));

        let merged = negative_for(
            "trace_data_flow",
            &clean_empty_trace("both"),
            &Envelope::offline(),
        )
        .unwrap();
        assert!(merged["subject"]
            .as_str()
            .unwrap()
            .contains("either direction"));
    }

    #[test]
    fn a_populated_chain_still_gets_no_negative() {
        let mut payload = clean_empty_trace("both");
        payload["chain"] = json!([{ "step": 1, "entity_name": "caller" }]);
        let negative = negative_for("trace_data_flow", &payload, &structural_ready_envelope())
            .expect("every retrieval answer carries the response verdict");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert_eq!(negative["interpretation"], json!("qualified_answer"));
    }

    // ---- resolution misses: the answer with no collection to count ----

    #[test]
    fn resolution_miss_is_authoritative_on_a_populated_ready_graph() {
        let envelope = Envelope::daemon().with_health(&json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_entity_count": 3,
        }));
        for (tool, message) in [
            ("find_references", "Entity not found"),
            ("trace_data_flow", "no entity found matching 'embed_batch'"),
            (
                "trace_data_flow",
                "trace_data_flow: no entity matches focal 'embed_batch'",
            ),
        ] {
            let negative = resolution_miss_for(tool, message, &envelope)
                .unwrap_or_else(|| panic!("{tool} must qualify its miss: {message}"));
            assert_eq!(negative["kind"], json!("focal_not_resolved"));
            assert_eq!(negative["interpretation"], json!("name_not_resolved"));
            assert_eq!(negative["result_count"], json!(0));
            assert_eq!(negative["safe_to_conclude_absent"], json!(true));
            assert_eq!(negative["trust"], json!("authoritative"));
        }
    }

    /// FIR-2820. The purest absence claim the product makes, over a store the
    /// working copy has outrun.
    ///
    /// The v0.6.1 yardstick run asked `find_references` about a constant
    /// declared and used twice in a module on disk that no admission had taken.
    /// It came back `safe_to_conclude_absent: true`, `structural_authoritative`,
    /// beside a `behind` object in the same envelope naming that very file. The
    /// retrieval builder had this gate and scopes it to answers claiming an
    /// absence, which is every answer on this path; a focal miss took a
    /// different route and never asked.
    #[test]
    fn resolution_miss_over_unadmitted_host_content_is_inconclusive() {
        let envelope = Envelope::daemon().with_health(&json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_entity_count": 38,
            "reconcile": {
                "untracked_path_count": 1,
                "untracked_paths_sample": ["notekeeper/linkgraph.py"],
                "last_admission_success_at": "2026-08-27T03:14:08Z",
            },
        }));
        let negative = resolution_miss_for("find_references", "Entity not found", &envelope)
            .expect("a miss is still qualified");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(false),
            "a name may be absent from the graph and present in the repository while a module \
             the graph never read sits on disk"
        );
        assert_eq!(negative["trust"], json!("inconclusive"));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.contains("graph_behind_working_tree"),
            "an answer withheld for an unnamed reason sends the reader to the wrong lever: \
             {reason}"
        );
        let advice = negative["advice"].as_str().unwrap();
        assert!(
            !advice.contains("authoritatively absent"),
            "the advice cannot still read as settled: {advice}"
        );
    }

    /// The control for the case above, on the same builder. A store with nothing
    /// unadmitted certifies exactly as it did, because a gate that fires on
    /// every working copy is one an agent learns to skip.
    #[test]
    fn resolution_miss_over_a_level_working_copy_still_certifies() {
        let envelope = Envelope::daemon().with_health(&json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_entity_count": 38,
            // Stamped. An unstamped zero is a different fact and the two tests
            // below this one are what separate them.
            "reconcile": {
                "untracked_path_count": 0,
                "untracked_observed_age_seconds": 0,
            },
        }));
        let negative = resolution_miss_for("find_references", "Entity not found", &envelope)
            .expect("a miss is still qualified");
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
        assert_eq!(negative["trust"], json!("authoritative"));
        assert!(!negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("graph_behind_working_tree"));
    }

    /// FIR-2820, the review's second finding, on the surface a caller acts on.
    ///
    /// A walk that errored is logged at debug and swallowed, and a daemon that
    /// has not walked yet has taken no reading at all. Both leave the count at
    /// its `u64` default with no stamp, and `kin status` on the same daemon at
    /// the same instant says "not measured" while this builder certified.
    #[test]
    fn resolution_miss_over_an_unmeasured_working_copy_is_inconclusive() {
        let envelope = Envelope::daemon().with_health(&json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_entity_count": 38,
            "reconcile": { "untracked_path_count": 0 },
        }));
        let negative = resolution_miss_for("find_references", "Entity not found", &envelope)
            .expect("a miss is still qualified");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(false),
            "a zero nobody measured is not a zero, and certifying on it is the whole ticket"
        );
        assert_eq!(negative["trust"], json!("inconclusive"));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.contains("working_copy_unmeasured"),
            "the reason has to name the lever, and it is not `kin admit` here: {reason}"
        );
    }

    /// The control for the case above. A daemon that admits nothing from the
    /// filesystem has no walk to miss, so a gate keyed on the stamp alone would
    /// refuse every absence it ever answers.
    #[test]
    fn resolution_miss_over_a_daemon_that_admits_nothing_from_disk_certifies() {
        let envelope = Envelope::daemon().with_health(&json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_entity_count": 38,
            "reconcile": {
                "untracked_path_count": 0,
                "untracked_observation_not_applicable": true,
            },
        }));
        let negative = resolution_miss_for("find_references", "Entity not found", &envelope)
            .expect("a miss is still qualified");
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
        assert_eq!(negative["trust"], json!("authoritative"));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            !reason.contains("working_copy_unmeasured"),
            "there is no working copy to measure here: {reason}"
        );
    }

    #[test]
    fn resolution_miss_on_an_empty_graph_is_inconclusive() {
        let envelope = Envelope::daemon().with_health(&json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_entity_count": 0,
        }));
        let negative =
            resolution_miss_for("trace_data_flow", "no entity found matching 'x'", &envelope)
                .expect("a miss is still qualified");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("graph_empty"));
    }

    #[test]
    fn resolution_miss_offline_is_inconclusive() {
        let negative =
            resolution_miss_for("find_references", "Entity not found", &Envelope::offline())
                .expect("a miss is still qualified");
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("offline_fallback"));
        assert!(negative["advice"]
            .as_str()
            .unwrap()
            .contains("NOT authoritative"));
    }

    /// The guard has to be able to say no. A malformed request or an
    /// unreachable daemon never looked anything up, so dressing either as an
    /// absence would invent the very verdict this module exists to qualify.
    #[test]
    fn a_request_or_transport_failure_is_not_a_resolution_miss() {
        for message in [
            "missing required parameter: focal",
            "invalid direction 'sideways': expected calls, callers, or both",
            "unsupported relation kind 'sideways': use calls, imports, or references",
            "kin-mcp has no Kin repository bound for 'trace_data_flow': not inside a kin repository",
            "daemon is unreachable",
        ] {
            assert!(
                resolution_miss_for("trace_data_flow", message, &structural_ready_envelope())
                    .is_none(),
                "must not be read as an absence: {message}"
            );
        }
    }

    #[test]
    fn a_tool_with_no_miss_framing_gets_no_resolution_negative() {
        assert!(
            resolution_miss_for("semantic_search", "Entity not found", &Envelope::daemon())
                .is_none()
        );
    }

    #[test]
    fn dead_code_on_loaded_graph_is_authoritative() {
        // dead_code is structural and returns a bare array: an empty result is
        // authoritative on an initialized + loaded graph, regardless of embedding
        // coverage. Mirrors find_references through a different payload shape.
        let payload = json!([]);
        let negative = negative_for("dead_code", &payload, &structural_ready_envelope()).unwrap();
        assert_eq!(negative["kind"], json!("no_dead_code"));
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("structural_authoritative"));
    }

    /// An empty fused `semantic_locate` page exactly as the daemon serializes
    /// it: `LocateResult` skips `entities` when the vector is empty, so the key
    /// is ABSENT rather than an empty array, and `files` is the only collection
    /// on the wire.
    fn empty_fused_locate_page(query: &str) -> Value {
        json!({
            "query": query,
            "granularity": "entity",
            "routing": "fused-v1",
            "page": 0,
            "files": [],
        })
    }

    fn fused_locate_hit(name: &str) -> Value {
        json!({
            "entity_id": "00000000-0000-0000-0000-0000000000aa",
            "kind": "function",
            "name": name,
            "score": 0.42,
            "definition": true,
            "provenance": { "file": "src/lib.rs" },
        })
    }

    fn cosine_locate_hit(name: &str, name_match: &str) -> Value {
        json!({
            "kind": "function",
            "name": name,
            "score": 0.31,
            "id_space": "entity",
            "entity_id": "00000000-0000-0000-0000-0000000000bb",
            "provenance": { "file": "src/lib.rs" },
            "match_evidence": {
                "ranker": "cosine-v0",
                "score_source": "vector_cosine",
                "name_match": name_match,
                "reranked": false,
            },
        })
    }

    #[test]
    fn empty_fused_locate_page_carries_the_negative() {
        // The fused arm is the default for code-bearing stores, and its empty
        // page used to reach an agent as a bare `files: []` with no
        // qualification at all — an honest-looking negative that had qualified
        // nothing.
        let payload = empty_fused_locate_page("where does the daemon start");
        let negative = negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope(),
        )
        .unwrap();
        assert_eq!(negative["kind"], json!("no_ranked_match"));
        assert_eq!(negative["result_count"], json!(0));
        assert_eq!(negative["interpretation"], json!("absent_as_indexed"));
        assert_eq!(negative["trust"], json!("authoritative"));
    }

    #[test]
    fn empty_cosine_locate_page_keeps_its_negative() {
        // The control the fix must not break: the arm that already qualified.
        let payload = json!({
            "query": "where does the daemon start",
            "routing": "cosine-v0",
            "page": 0,
            "total_ranked": 0,
            "results": [],
        });
        let negative = negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope(),
        )
        .unwrap();
        assert_eq!(negative["kind"], json!("no_ranked_match"));
        assert_eq!(negative["result_count"], json!(0));
    }

    #[test]
    fn empty_window_over_nonempty_locate_ranking_cannot_certify_absence() {
        // Current daemon cache paths fail these cursors before serializing a
        // page. The envelope still refuses the contradictory shape so an older
        // daemon or alternate producer cannot turn an out-of-range window into
        // an authoritative `no_ranked_match`.
        for payload in [
            json!({
                "query": "where does the daemon start",
                "routing": "cosine-v0",
                "page": 4,
                "total_ranked": 3,
                "results": [],
            }),
            json!({
                "query": "where does the daemon start",
                "routing": "fused-v1",
                "granularity": "entity",
                "page": 4,
                "total_ranked": 3,
                "files": [],
            }),
        ] {
            assert!(
                negative_for(
                    "semantic_locate",
                    &payload,
                    &semantic_authoritative_envelope(),
                )
                .is_none(),
                "a positive held total contradicts an empty continuation: {payload}"
            );
        }

        let truly_empty = json!({
            "query": "where does the daemon start",
            "routing": "cosine-v0",
            "page": 0,
            "total_ranked": 0,
            "results": [],
        });
        assert_eq!(
            negative_for(
                "semantic_locate",
                &truly_empty,
                &semantic_authoritative_envelope(),
            )
            .unwrap()["kind"],
            json!("no_ranked_match"),
            "a genuinely empty ranking keeps its negative"
        );
    }

    #[test]
    fn populated_fused_locate_page_carries_no_negative() {
        // The other control: a page that answered is not qualified at all.
        let mut payload = empty_fused_locate_page("run_fused_locate_for_state");
        payload["entities"] = json!([fused_locate_hit("run_fused_locate_for_state")]);
        payload["total_ranked"] = json!(1);
        assert!(negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope()
        )
        .is_none());
    }

    #[test]
    fn fused_secondary_files_do_not_make_an_empty_entity_primary_populated() {
        // The declared entity ranking answered with no entities. A secondary
        // file roll-up is provenance for that ranking, not a second primary
        // whose presence can turn the empty entity answer into a populated one.
        let mut payload = empty_fused_locate_page("where does the daemon start");
        payload["files"] = json!([{ "path": "src/lib.rs", "score": 0.5 }]);
        let negative = negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope(),
        )
        .expect("secondary files cannot hide an empty entity primary");
        assert_eq!(negative["kind"], json!("no_ranked_match"));
        assert_eq!(negative["result_count"], json!(0));
    }

    #[test]
    fn locate_payload_carrying_neither_collection_yields_no_negative() {
        // Absence is never guessed: without `results` and without the `files`
        // that proves a fused page, emptiness is unknown, not zero.
        let payload = json!({ "query": "x", "routing": "fused-v1", "page": 0 });
        assert!(negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope()
        )
        .is_none());
    }

    #[test]
    fn fabricated_symbol_gets_a_full_fused_page_qualified_as_unnamed() {
        // Five confidently-scored hits for a symbol that exists nowhere. The
        // page is real and stays whole; what it is NOT is the
        // symbol that was asked for, and that is now stated.
        let mut payload = empty_fused_locate_page("zzqqxx_nonexistent_symbol_9f3a");
        payload["entities"] = json!((0..5)
            .map(|index| fused_locate_hit(&format!("neighbor_{index}")))
            .collect::<Vec<_>>());
        payload["total_ranked"] = json!(9);
        payload["all_fallback"] = json!(true);
        let negative = negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope(),
        )
        .unwrap();
        assert_eq!(negative["kind"], json!("no_named_match"));
        assert_eq!(negative["interpretation"], json!("unnamed_ranking"));
        // Qualification, never filtering: every row served is still counted.
        assert_eq!(negative["result_count"], json!(5));
        assert!(negative["advice"]
            .as_str()
            .unwrap()
            .contains("neighbors, not the symbol"));
    }

    #[test]
    fn an_unnamed_ranking_never_certifies_that_the_symbol_is_absent() {
        // A dogfood on the shipped artifact asked a fully covered store for
        // `prune_orphaned_vectors`, got ten wrong rows, and the envelope stamped
        // them `safe_to_conclude_absent: true`, `trust: authoritative`, advising
        // that "on a complete graph that means no entity carries it at all".
        // `find_references` resolved that exact name to a real method 1.9
        // seconds later in the same run.
        //
        // A ranking is a bounded candidate set. Complete coverage says every
        // entity has an embedding, not that the ranker considered every entity,
        // so absence from a ranking can never license absence from the graph.
        // Certifying it turned a silent miss into a confident false statement.
        let mut existing = empty_fused_locate_page("prune_orphaned_vectors");
        existing["entities"] = json!((0..10)
            .map(|index| fused_locate_hit(&format!("neighbor_{index}")))
            .collect::<Vec<_>>());
        existing["total_ranked"] = json!(10);
        existing["all_fallback"] = json!(true);
        let negative = negative_for(
            "semantic_locate",
            &existing,
            &semantic_authoritative_envelope(),
        )
        .expect("an unnamed ranking is qualified");

        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert_eq!(negative["trust"], json!("inconclusive"));
        assert!(
            negative["trust_reason"]
                .as_str()
                .unwrap()
                .contains("ranking_is_bounded"),
            "the reason must name the bound: {}",
            negative["trust_reason"]
        );
        // The substrate observation is kept rather than replaced: on a complete
        // index the honest reading is "the substrate is fine, the ranking is the
        // limit", which is the distinction that was being collapsed.
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("semantic_authoritative"));
        let advice = negative["advice"].as_str().unwrap();
        assert!(
            !advice.contains("no entity carries it at all"),
            "the advice must not assert graph-wide absence: {advice}"
        );
        assert!(
            advice.contains("find_references") || advice.contains("semantic_search"),
            "the advice must send the caller to a surface that resolves a name: {advice}"
        );

        // The control from the dogfood that makes this matter: a FABRICATED
        // symbol produced the identical envelope, so the verdict could not
        // separate a symbol retrieval missed from one that does not exist. Both
        // are still inconclusive here, which is the honest answer for both,
        // because this surface cannot tell them apart and must not pretend to.
        let mut fabricated = empty_fused_locate_page("zzqqxx_nonexistent_symbol_9f3a");
        fabricated["entities"] = json!((0..10)
            .map(|index| fused_locate_hit(&format!("neighbor_{index}")))
            .collect::<Vec<_>>());
        fabricated["total_ranked"] = json!(10);
        fabricated["all_fallback"] = json!(true);
        let fabricated = negative_for(
            "semantic_locate",
            &fabricated,
            &semantic_authoritative_envelope(),
        )
        .unwrap();
        assert_eq!(fabricated["safe_to_conclude_absent"], json!(false));

        // And the gate that still works: an EMPTY page on the same envelope is a
        // real absence and stays authoritative. The bound applies to a populated
        // ranking that missed a name, not to a query that ranked nothing, so
        // this fix removes no verdict it was entitled to make.
        let empty = json!({ "query": "auth", "results": [], "total_ranked": 0 });
        let empty = negative_for(
            "semantic_locate",
            &empty,
            &semantic_authoritative_envelope(),
        )
        .unwrap();
        assert_eq!(empty["safe_to_conclude_absent"], json!(true));
        assert_eq!(empty["kind"], json!("no_ranked_match"));
    }

    #[test]
    fn real_symbol_page_stays_unqualified() {
        // The control that keeps the qualifier meaningful: a query naming a
        // symbol the ranking holds gets no negative at all.
        let mut payload = empty_fused_locate_page("run_fused_locate_for_state");
        payload["entities"] = json!([fused_locate_hit("run_fused_locate_for_state")]);
        payload["total_ranked"] = json!(4);
        assert!(negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope()
        )
        .is_none());
    }

    #[test]
    fn prose_query_over_fallback_hits_refuses_to_certify_relevance() {
        // The exact first-contact shape: a natural-language concept the
        // repository does not contain still gets a full page because locate is
        // a nearest-neighbour ranking. Complete embedding coverage says every
        // candidate could rank. It does not provide a calibrated relevance
        // floor, so it cannot turn the neighbours into a certified answer.
        let mut payload = empty_fused_locate_page("password hashing and session token expiry");
        payload["entities"] = json!([
            fused_locate_hit("Hit"),
            fused_locate_hit("Link"),
            fused_locate_hit("build_match_query"),
            fused_locate_hit("SearchError"),
        ]);
        payload["total_ranked"] = json!(40);
        payload["all_fallback"] = json!(true);
        let negative = negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope(),
        )
        .expect("fallback-only prose rankings must qualify their relevance");
        assert_eq!(negative["kind"], json!("relevance_unverified"));
        assert_eq!(negative["interpretation"], json!("nearest_neighbors_only"));
        assert_eq!(negative["trust"], json!("inconclusive"));
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(reason.contains("relevance_floor_unmeasured"), "{reason}");
        let advice = negative["advice"].as_str().unwrap();
        assert!(
            advice.contains("Inspect the returned code")
                && advice.contains("do not conclude the concept is absent"),
            "{advice}"
        );
    }
    /// One compact fused page in the shape an agent actually receives:
    /// `project_for_mcp` writes `matched` per row, omits `results` entirely, and
    /// omits `all_fallback` unless the producer set it.
    fn compact_fused_page(query: &str, entities: Value, total_ranked: u64) -> Value {
        json!({
            "query": query,
            "granularity": "entity",
            "routing": "fused-v1",
            "page": 0,
            "surface": "compact",
            "entities": entities,
            "files": ["lib/application.js", "lib/view.js"],
            "total_ranked": total_ranked,
            "next_cursor": "eyJrZXkiOiJsb2NhdGUtcmFua2luZyJ9",
            "ranked_by": "vector, lexical and graph signals",
            "semantic_coverage": {
                "indexed": 798,
                "total": 798,
                "pending": 0,
                "complete": true,
            },
        })
    }

    /// One row of that page. `matched` is `None` for a record from a daemon
    /// predating the field, which is a state this module must not read as either
    /// answer.
    fn compact_locate_row(name: &str, file: &str, score: f64, matched: Option<&str>) -> Value {
        let mut row = json!({
            "id": "00000000-0000-0000-0000-0000000000ac",
            "name": name,
            "kind": "function",
            "file": file,
            "line": 190,
            "score": score,
        });
        if let Some(matched) = matched {
            row["matched"] = json!(matched);
        }
        row
    }

    /// The eight rows express returned for the concept query, kinds and scores
    /// as measured.
    fn gap_f_fallback_rows() -> Value {
        json!([
            compact_locate_row(
                "app.use",
                "lib/application.js",
                52.05,
                Some("text_fallback")
            ),
            compact_locate_row(
                "app.render",
                "lib/application.js",
                52.05,
                Some("text_fallback")
            ),
            compact_locate_row(
                "app.defaultConfiguration",
                "lib/application.js",
                52.05,
                Some("text_fallback"),
            ),
            compact_locate_row("View.render", "lib/view.js", 52.03, Some("text_fallback")),
            compact_locate_row("View.lookup", "lib/view.js", 52.02, Some("text_fallback")),
            compact_locate_row("View.resolve", "lib/view.js", 52.02, Some("text_fallback")),
            compact_locate_row(
                "app.listen",
                "lib/application.js",
                52.02,
                Some("text_fallback")
            ),
            compact_locate_row(
                "app.path",
                "lib/application.js",
                52.02,
                Some("text_fallback")
            ),
        ])
    }

    #[test]
    fn a_prose_page_of_lexical_neighbours_is_qualified_when_the_named_row_is_off_the_page() {
        // Measured on express with the vector index complete at 798 of
        // 798. The caller asked "attach an encoding label to a media type
        // string" and received eight lexical neighbours at scores 52.05 down to
        // 52.02, none of them `setCharset`, which was not in the ranking at any
        // limit. The response carried NO `all_fallback`, because one row of the
        // 31 the ranking held did carry `matched: name` (the kinds at limit 40
        // were text_fallback 28, name 1, semantic 2) and the producer computes
        // that flag over the whole ranking. So the flag reported a name hit the
        // caller never saw, both locate gates read `None`, and the answer
        // certified.
        //
        // The rows the caller DID receive publish no calibrated threshold saying
        // any of them answers the concept, which is the same sentence the
        // vector-neighbour case below is qualified with.
        let payload = compact_fused_page(
            "attach an encoding label to a media type string",
            gap_f_fallback_rows(),
            31,
        );
        assert!(
            payload.get("all_fallback").is_none(),
            "the measured response carried no all_fallback: {payload}"
        );
        let negative = negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope(),
        )
        .expect("a returned page of fallback neighbours may not certify a concept answer");
        assert_eq!(negative["kind"], json!("relevance_unverified"));
        assert_eq!(negative["interpretation"], json!("nearest_neighbors_only"));
        assert_eq!(negative["trust"], json!("inconclusive"));
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(reason.contains("relevance_floor_unmeasured"), "{reason}");
    }

    #[test]
    fn a_prose_page_whose_returned_rows_name_the_query_stays_unqualified() {
        // The control that pins the repair's scope, and the reason this gate
        // must not discount a plain-word name match. All three questions are
        // prose by this module's own rule, all three answered first row on the
        // same store, and the first two are named by an ordinary English token,
        // so a rule that demanded a symbol-shaped one would refuse to certify
        // the tool's best answers. The second reaches this gate at all only
        // because an acronym is not a symbol the caller named: while `JSON`
        // counted as one, `query_names_a_symbol` returned true and the row
        // classifier below was never consulted for that question.
        for (query, name, file, score) in [
            (
                "render a view template with a layout",
                "app.render",
                "lib/application.js",
                427.00,
            ),
            (
                "send a JSON response body to the client",
                "res.json",
                "lib/response.js",
                453.10,
            ),
            ("setCharset", "setCharset", "lib/utils.js", 480.00),
        ] {
            let payload = compact_fused_page(
                query,
                json!([
                    compact_locate_row(name, file, score, Some("name")),
                    compact_locate_row("View.render", "lib/view.js", 52.03, Some("text_fallback")),
                ]),
                31,
            );
            assert!(
                negative_for(
                    "semantic_locate",
                    &payload,
                    &semantic_authoritative_envelope()
                )
                .is_none(),
                "a page whose first row carries the name the query used needs no relevance \
                 caveat: {query}"
            );
        }
    }

    #[test]
    fn a_prose_page_of_vector_neighbours_stays_qualified() {
        // The other half of the same measurement: "decide which
        // proxy addresses may be believed" returned eight rows all
        // `matched: semantic` at 96.28 down to 94.41, with `all_fallback` set,
        // and was correctly inconclusive. Widening the gate to read the returned
        // page may not cost that case its qualifier.
        let mut payload = compact_fused_page(
            "decide which proxy addresses may be believed",
            json!([
                compact_locate_row("compileTrust", "lib/utils.js", 96.28, Some("semantic")),
                compact_locate_row("proxyaddr", "lib/utils.js", 94.41, Some("semantic")),
            ]),
            2,
        );
        payload["all_fallback"] = json!(true);
        let negative = negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope(),
        )
        .expect("a vector-neighbour page keeps the qualifier it already had");
        assert_eq!(negative["kind"], json!("relevance_unverified"));
        assert_eq!(negative["trust"], json!("inconclusive"));
    }

    #[test]
    fn a_prose_page_whose_rows_report_no_match_kind_is_left_alone() {
        // The refusal to guess, in the one shape that can still produce it: a
        // daemon predating `matched` publishes rows carrying no kind at all, and
        // its absent `all_fallback` is then the only statement the response
        // makes about whether anything was named. Reading those rows as fallback
        // would qualify an answer on evidence nobody produced, which is the same
        // refusal the cosine page inference beside it already makes.
        let payload = compact_fused_page(
            "attach an encoding label to a media type string",
            json!([
                compact_locate_row("app.use", "lib/application.js", 52.05, None),
                compact_locate_row("View.render", "lib/view.js", 52.03, None),
            ]),
            31,
        );
        assert!(
            negative_for(
                "semantic_locate",
                &payload,
                &semantic_authoritative_envelope()
            )
            .is_none(),
            "rows that report no match kind answer nothing about naming: {payload}"
        );
    }

    #[test]
    fn a_prose_file_answer_is_not_qualified_by_the_relevance_gate() {
        // The symmetry `fused_semantic_locate_payload` built deliberately, kept
        // here by the refusal to guess rather than by a special case. A file
        // answer IS the `files[]` roll-up, its rows carry no match kind at all,
        // and labelling a successful file answer with an entity-naming caveat is
        // exactly what clearing `all_fallback` at file granularity exists to
        // prevent.
        let payload = json!({
            "query": "attach an encoding label to a media type string",
            "granularity": "file",
            "routing": "fused-v1",
            "page": 0,
            "total_ranked": 2,
            "files": [
                {"path": "lib/utils.js", "score": 52.05, "signals": ["lexical"]},
                {"path": "lib/response.js", "score": 52.02, "signals": ["lexical"]},
            ],
        });
        assert!(
            negative_for(
                "semantic_locate",
                &payload,
                &semantic_authoritative_envelope()
            )
            .is_none(),
            "a file answer carries no entity match kinds and must not be read as fallback: \
             {payload}"
        );
    }

    /// One page on the FULL fused surface, which serializes `LocateEntity`
    /// verbatim: `match_kind` per row and no compact `matched` key.
    fn full_fused_page(query: &str, entities: Value, total_ranked: u64) -> Value {
        json!({
            "query": query,
            "granularity": "entity",
            "routing": "fused-v1",
            "page": 0,
            "entities": entities,
            "files": [{"path": "lib/response.js", "score": 52.05}],
            "total_ranked": total_ranked,
        })
    }

    fn full_fused_row(name: &str, match_kind: &str) -> Value {
        json!({
            "entity_id": "00000000-0000-0000-0000-0000000000ba",
            "kind": "function",
            "name": name,
            "score": 52.05,
            "definition": true,
            "match_kind": match_kind,
            "provenance": { "file": "lib/response.js" },
        })
    }

    #[test]
    fn a_prose_page_of_fallback_rows_is_qualified_on_the_full_fused_surface() {
        // The compact projection is not the only surface this gate has to read.
        // `fused_semantic_locate_payload` serializes the reused `LocateResult`
        // types when the caller asks for the full shape, and there a row's kind
        // is `match_kind` rather than `matched`. A classifier reading only the
        // compact spelling would let every full-surface page certify, and no
        // fixture would notice: swapping the `match_kind` read for a second
        // `matched` read leaves the rest of this suite green.
        let payload = full_fused_page(
            "attach an encoding label to a media type string",
            json!([
                full_fused_row("res.send", "text_fallback"),
                full_fused_row("res.sendFile", "text_fallback"),
            ]),
            31,
        );
        // A real full-fused row carries a `match_evidence` object beside its
        // `match_kind` (`crates/kin-daemon/src/api.rs:11642`). This one omits it
        // for the same reason the cosine fixture below omits `match_kind`: with
        // one spelling present, the arm under test is the only thing that can
        // classify the row, and a mutation to it cannot hide behind a sibling.
        assert!(
            payload["entities"][0].get("matched").is_none(),
            "this fixture omits the compact spelling so match_kind is the only classifier: \
             {payload}"
        );
        let negative = negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope(),
        )
        .expect("a full-surface page of fallback rows may not certify a concept answer");
        assert_eq!(negative["kind"], json!("relevance_unverified"));
        assert_eq!(negative["trust"], json!("inconclusive"));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(reason.contains("relevance_floor_unmeasured"), "{reason}");

        // The control on the same surface: one returned row carrying the name
        // the query used is the calibrated floor, and it is read through the
        // same spelling.
        let named = full_fused_page(
            "attach an encoding label to a media type string",
            json!([
                full_fused_row("type", "name"),
                full_fused_row("res.sendFile", "text_fallback"),
            ]),
            31,
        );
        assert!(
            negative_for(
                "semantic_locate",
                &named,
                &semantic_authoritative_envelope()
            )
            .is_none(),
            "a full-surface page whose row names the query needs no caveat: {named}"
        );
    }

    #[test]
    fn a_prose_page_of_fallback_rows_is_qualified_on_the_cosine_surface() {
        // The third spelling: `match_evidence.name_match`, the cosine arm's own
        // word for the fact the other two surfaces spell `name`.
        //
        // A stock daemon's cosine entity row carries BOTH keys. It has emitted
        // `match_kind` on every entity-granularity hit since `917bf1d3b`
        // (2026-08-12), at `crates/kin-daemon/src/api.rs:11248`, derived from
        // the same predicate the evidence object reports so the two cannot
        // disagree. This fixture is therefore not a sample of what that arm
        // sends today. It is the compatibility read, for a producer that
        // publishes the evidence object and no `match_kind`, and it omits the
        // sibling key on purpose so that the arm under test is the only thing
        // that can classify the row. Without that arm every row here reports an
        // unknown kind, the gate never fires, and a prose page of neighbours
        // certifies.
        let payload = json!({
            "query": "attach an encoding label to a media type string",
            "routing": "cosine-v0",
            "page": 0,
            "total_ranked": 31,
            "results": [
                cosine_locate_hit("res_send", "none"),
                cosine_locate_hit("res_send_file", "partial"),
            ],
        });
        assert!(
            payload["results"][0].get("match_kind").is_none(),
            "this fixture omits match_kind so the evidence arm is the only classifier: {payload}"
        );
        let negative = negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope(),
        )
        .expect("a cosine page of neighbours may not certify a concept answer");
        assert_eq!(negative["kind"], json!("relevance_unverified"));
        assert_eq!(negative["trust"], json!("inconclusive"));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(reason.contains("relevance_floor_unmeasured"), "{reason}");

        // The control: `exact` is the cosine arm's own word for the fact the
        // other two surfaces spell `name`.
        let named = json!({
            "query": "attach an encoding label to a media type string",
            "routing": "cosine-v0",
            "page": 0,
            "total_ranked": 31,
            "results": [
                cosine_locate_hit("type", "exact"),
                cosine_locate_hit("res_send_file", "partial"),
            ],
        });
        assert!(
            negative_for(
                "semantic_locate",
                &named,
                &semantic_authoritative_envelope()
            )
            .is_none(),
            "an exact name match is the floor on this surface too: {named}"
        );
    }

    #[test]
    fn an_acronym_in_a_question_does_not_exempt_it_from_the_relevance_gate() {
        // The same eight-row all-fallback page, asked with an acronym in the
        // sentence. `query_names_a_symbol` used to read any three-character
        // token with two capitals as a named symbol, so `JSON` alone sent the
        // question to the symbol gate, which needs the whole-ranking
        // `all_fallback` flag this page does not carry, and the page certified.
        // That exempted the most common shape of real question there is: HTTP,
        // API, URL, SQL, HTML, XML, UUID, DNS and TLS all did it too.
        let payload = compact_fused_page(
            "send a JSON response body to the client",
            gap_f_fallback_rows(),
            31,
        );
        let negative = negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope(),
        )
        .expect("an acronym in the sentence is not a symbol the caller named");
        assert_eq!(negative["kind"], json!("relevance_unverified"));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(reason.contains("relevance_floor_unmeasured"), "{reason}");

        // The control that keeps the symbol gate's own territory: a token that
        // mixes case IS a symbol name, and a query naming one is answered by
        // the gate beside this one rather than by this one.
        assert!(query_names_a_symbol("how does HTTPServer parse a header"));
        assert!(query_names_a_symbol("IOError"));
        assert!(query_names_a_symbol("MAX_RETRIES"));
    }

    #[test]
    fn cosine_page_naming_nothing_is_qualified() {
        let payload = json!({
            "query": "zzqqxx_nonexistent_symbol_9f3a",
            "routing": "cosine-v0",
            "page": 0,
            "total_ranked": 2,
            "results": [
                cosine_locate_hit("neighbor_one", "none"),
                cosine_locate_hit("neighbor_two", "partial"),
            ],
        });
        let negative = negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope(),
        )
        .unwrap();
        assert_eq!(negative["kind"], json!("no_named_match"));
        assert_eq!(negative["result_count"], json!(2));
    }

    #[test]
    fn cosine_page_holding_an_exact_name_match_is_not_qualified() {
        let payload = json!({
            "query": "locate_result_count",
            "routing": "cosine-v0",
            "page": 0,
            "total_ranked": 2,
            "results": [
                cosine_locate_hit("locate_result_count", "exact"),
                cosine_locate_hit("neighbor_two", "none"),
            ],
        });
        assert!(negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope()
        )
        .is_none());
    }

    #[test]
    fn cosine_file_granularity_counts_its_file_primary_for_empty_and_populated_pages() {
        let empty = json!({
            "query": "where redirects are resolved",
            "routing": "cosine-v0",
            "granularity": "file",
            "page": 0,
            "total_ranked": 0,
            "files": [],
        });
        let negative = negative_for(
            "semantic_locate",
            &empty,
            &semantic_authoritative_envelope(),
        )
        .expect("an empty file page is still an attributable empty locate");
        assert_eq!(negative["kind"], json!("no_ranked_match"));
        assert_eq!(negative["result_count"], json!(0));

        let populated = json!({
            "query": "where redirects are resolved",
            "routing": "cosine-v0",
            "granularity": "file",
            "page": 0,
            "total_ranked": 1,
            "files": [{ "path": "src/redirects.rs", "score": 0.9 }],
        });
        assert!(negative_for(
            "semantic_locate",
            &populated,
            &semantic_authoritative_envelope(),
        )
        .is_none());
    }

    /// The join, not the two endpoints.
    ///
    /// This block's row count and the response budget's ladder have to name one
    /// collection on every locate shape the daemon produces. Two tests each
    /// hardcoding the same key string would both stay green while the two sides
    /// drifted apart, because neither can see the agreement. So this reads what
    /// the budget chose and requires this block to have counted THAT array,
    /// which no renaming on either side can satisfy by accident.
    #[test]
    fn the_negative_count_and_the_budget_primary_name_one_collection() {
        let shapes = [
            (
                "fused entity page",
                json!({
                    "query": "q", "granularity": "entity", "routing": "fused-v1",
                    "page": 0, "total_ranked": 2, "files": [],
                    "entities": [{ "name": "a" }, { "name": "b" }],
                }),
            ),
            (
                "fused entity page that ranked nothing",
                json!({
                    "query": "q", "granularity": "entity", "routing": "fused-v1",
                    "page": 0, "total_ranked": 0,
                    "files": [{ "path": "src/secondary.rs", "score": 0.4 }],
                }),
            ),
            (
                "fused entity page that ships its empty primary",
                json!({
                    "query": "q", "granularity": "entity", "routing": "fused-v1",
                    "page": 0, "total_ranked": 0, "entities": [],
                    "files": [{ "path": "src/secondary.rs", "score": 0.4 }],
                }),
            ),
            (
                "cosine entity page",
                json!({
                    "query": "q", "granularity": "entity", "routing": "cosine-v0",
                    "page": 0, "total_ranked": 1, "files": [],
                    "results": [{ "name": "a" }],
                }),
            ),
            (
                "cosine file page",
                json!({
                    "query": "q", "granularity": "file", "routing": "cosine-v0",
                    "page": 0, "total_ranked": 2,
                    "files": [{ "path": "a.rs" }, { "path": "b.rs" }],
                }),
            ),
            (
                "fused file page",
                json!({
                    "query": "q", "granularity": "file", "routing": "fused-v1",
                    "page": 0, "total_ranked": 1, "entities": [],
                    "files": [{ "path": "a.rs" }],
                }),
            ),
        ];
        for (label, payload) in shapes {
            let primary = crate::budget::primary_collection_for(&payload, "semantic_locate")
                .unwrap_or_else(|| panic!("{label}: the budget named no primary collection"));
            let counted = locate_primary_count(&payload)
                .unwrap_or_else(|| panic!("{label}: the negative block counted nothing"));
            let rows = payload
                .get(primary)
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            assert_eq!(
                counted, rows,
                "{label}: the negative counted {counted} rows while the budget's primary \
                 `{primary}` carries {rows}"
            );
        }
    }

    #[test]
    fn fused_entity_granularity_does_not_count_secondary_files_as_primary_rows() {
        let payload = json!({
            "query": "missing_symbol",
            "routing": "fused-v1",
            "granularity": "entity",
            "page": 0,
            "total_ranked": 0,
            "files": [{ "path": "src/secondary.rs", "score": 0.4 }],
        });
        let negative = negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope(),
        )
        .expect("a secondary roll-up cannot hide an empty entity answer");
        assert_eq!(negative["kind"], json!("no_ranked_match"));
        assert_eq!(negative["result_count"], json!(0));
    }

    #[test]
    fn cosine_page_shorter_than_its_ranking_is_not_qualified() {
        // A page is a window. An exact name match on page two must not be
        // reported as absent from the whole ranking.
        let payload = json!({
            "query": "zzqqxx_nonexistent_symbol_9f3a",
            "routing": "cosine-v0",
            "page": 0,
            "total_ranked": 9,
            "results": [cosine_locate_hit("neighbor_one", "none")],
        });
        assert!(negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope()
        )
        .is_none());
    }

    #[test]
    fn cosine_row_without_match_evidence_leaves_the_page_unqualified() {
        let payload = json!({
            "query": "zzqqxx_nonexistent_symbol_9f3a",
            "routing": "cosine-v0",
            "page": 0,
            "total_ranked": 1,
            "results": [{ "name": "neighbor_one", "score": 0.2 }],
        });
        assert!(negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope()
        )
        .is_none());
    }

    /// The measured pair, as one query at two limits against one daemon.
    ///
    /// `total_ranked` is not a fixed property of a query; it grows with the
    /// requested limit. On a fresh fully embedded store a fabricated symbol
    /// ranked 1 at limit 8 and 56 at limit 50, so the page covered the ranking
    /// in the first case and not the second, and the disclosure that fired on
    /// the small page vanished on the large one. Asking for more results removed
    /// the honesty envelope, and the guard survived only because it was always
    /// tested on a ranking small enough to satisfy it.
    #[test]
    fn a_cosine_page_wider_than_its_window_still_carries_the_unnamed_verdict() {
        let page_of = |served: usize, total: u64| {
            json!({
                "query": "qqzz_fabricated_method_7k2b",
                "granularity": "entity",
                "routing": "cosine-v0",
                "page": 0,
                "total_ranked": total,
                "all_fallback": true,
                "results": (0..served)
                    .map(|index| cosine_locate_hit(&format!("neighbor_{index}"), "none"))
                    .collect::<Vec<_>>(),
            })
        };

        // Limit 8: one ranked row, the page holds the whole ranking. This is the
        // only shape that ever produced a negative.
        let small = negative_for(
            "semantic_locate",
            &page_of(1, 1),
            &semantic_authoritative_envelope(),
        )
        .expect("a whole-ranking page has always been qualified");
        assert_eq!(small["kind"], json!("no_named_match"));

        // Limit 50: fifty rows served out of fifty-six ranked. Same daemon, same
        // query, seconds apart, and this page carried no negative at all.
        let wide = negative_for(
            "semantic_locate",
            &page_of(50, 56),
            &semantic_authoritative_envelope(),
        )
        .expect("a wider page is still a ranking that named nothing");
        assert_eq!(wide["kind"], json!("no_named_match"));
        assert_eq!(wide["interpretation"], json!("unnamed_ranking"));
        // Qualification, never filtering: every row served is still counted.
        assert_eq!(wide["result_count"], json!(50));
        // The verdict is widened only in the safe direction. It says the ranking
        // named nothing, never that the graph holds nothing.
        assert_eq!(wide["safe_to_conclude_absent"], json!(false));
        assert_eq!(wide["trust"], json!("inconclusive"));
    }

    /// The control that keeps the widened verdict honest: a published
    /// `all_fallback` of false means a name hit is somewhere in the ranking, and
    /// that is true of a windowed page exactly as it is of a whole one.
    #[test]
    fn a_cosine_page_whose_ranking_holds_a_name_hit_is_never_qualified() {
        for (served, total) in [(50_usize, 56_u64), (2, 2)] {
            // The daemon omits `all_fallback` when the ranking holds a name hit,
            // so an ordinary answer carries no such key and one row reports the
            // exact match.
            let mut rows: Vec<Value> = (0..served.saturating_sub(1))
                .map(|index| cosine_locate_hit(&format!("neighbor_{index}"), "none"))
                .collect();
            rows.insert(0, cosine_locate_hit("locate_result_count", "exact"));
            let payload = json!({
                "query": "locate_result_count",
                "granularity": "entity",
                "routing": "cosine-v0",
                "page": 0,
                "total_ranked": total,
                "results": rows,
            });
            assert!(
                negative_for(
                    "semantic_locate",
                    &payload,
                    &semantic_authoritative_envelope()
                )
                .is_none(),
                "a ranking holding the named symbol is not an unnamed ranking \
                 ({served} of {total})"
            );
        }
    }

    /// An older daemon publishes no `all_fallback`, and its verdict must not
    /// change. Everything the widened branch adds is read off a field that
    /// daemon never sends, so the inference is exactly what still answers here.
    #[test]
    fn a_payload_without_all_fallback_keeps_the_inferred_verdict() {
        let whole_ranking = json!({
            "query": "zzqqxx_nonexistent_symbol_9f3a",
            "routing": "cosine-v0",
            "page": 0,
            "total_ranked": 2,
            "results": [
                cosine_locate_hit("neighbor_one", "none"),
                cosine_locate_hit("neighbor_two", "partial"),
            ],
        });
        assert!(
            negative_for(
                "semantic_locate",
                &whole_ranking,
                &semantic_authoritative_envelope()
            )
            .is_some(),
            "the inference still qualifies a page that holds its whole ranking"
        );

        let windowed = json!({
            "query": "zzqqxx_nonexistent_symbol_9f3a",
            "routing": "cosine-v0",
            "page": 0,
            "total_ranked": 9,
            "results": [cosine_locate_hit("neighbor_one", "none")],
        });
        assert!(
            negative_for(
                "semantic_locate",
                &windowed,
                &semantic_authoritative_envelope()
            )
            .is_none(),
            "without a published verdict a window is still unguessable"
        );
    }

    #[test]
    fn symbol_shape_rule_separates_identifiers_from_prose() {
        assert!(query_names_a_symbol("zzqqxx_nonexistent_symbol_9f3a"));
        assert!(query_names_a_symbol("where is semantic_locate defined"));
        assert!(query_names_a_symbol("LocateResult"));
        assert!(query_names_a_symbol("kin_mcp::negative"));
        assert!(query_names_a_symbol("AGENTS.md"));
        assert!(!query_names_a_symbol(
            "merge queue captain lane arbitration"
        ));
        assert!(!query_names_a_symbol("Checks That Cannot Fail"));
        assert!(!query_names_a_symbol("graph-native repo substrate"));
        assert!(!query_names_a_symbol(""));
        // An all-capital token is an acronym English prose is full of, not a
        // symbol the caller named. Mixed case is what separates the two, and a
        // token carrying an underscore, a dot or a path separator stays a
        // symbol whatever its case.
        assert!(!query_names_a_symbol(
            "send a JSON response body to the client"
        ));
        assert!(!query_names_a_symbol(
            "which HTTP status does a redirect use"
        ));
        assert!(!query_names_a_symbol("parse the URL and the DNS name"));
        assert!(query_names_a_symbol("how does HTTPServer parse a header"));
        assert!(query_names_a_symbol("IOError"));
        assert!(query_names_a_symbol("MAX_RETRIES"));
        assert!(query_names_a_symbol("README.md"));
    }

    /// FIR-2542's second half. `edge_coverage_unreported` reached every
    /// `trace_data_flow` response, complete ones included, because the daemon
    /// route published no observation at all. A limit that is always set
    /// distinguishes nothing, so the fix is the walk publishing what it
    /// measured; this asserts the gate reacts to that and still refuses when
    /// the measurement says the graph could not have answered.
    #[test]
    fn a_trace_that_publishes_its_coverage_stops_reporting_it_as_unreported() {
        let chain = json!({
            "chain": [{"step": 1, "terminal": "leaf"}],
            "total_steps": 1,
            "truncated": false,
        });

        // Before: no observation, so every walk carried the same limit.
        let unreported =
            absence_coverage_gap("trace_data_flow", &chain).expect("an unmeasured walk is unknown");
        assert!(
            unreported.starts_with("edge_coverage_unreported"),
            "{unreported}"
        );
        assert!(edge_coverage_degradation_labels("trace_data_flow", &chain)
            .contains(&"edge_coverage:unreported".to_string()));

        // After: the walk publishes what it measured, and a graph that links
        // calls across files leaves the gate with nothing to say.
        let mut measured = chain.clone();
        measured["edge_coverage"] = json!({
            "scope": "language",
            "language": "Python",
            "requested_classes": ["calls", "imports", "references"],
            "classes": {"calls": "present", "imports": "present", "references": "present"},
            "reference_enrichment": "unknown",
            "budget_exhausted": false,
        });
        assert_eq!(
            absence_coverage_gap("trace_data_flow", &measured),
            None,
            "a complete walk over a linked graph must carry no coverage limit"
        );
        let labels = edge_coverage_degradation_labels("trace_data_flow", &measured);
        assert!(
            !labels.contains(&"edge_coverage:unreported".to_string()),
            "the limit that distinguished nothing must be gone: {labels:?}"
        );

        // And the gate still fires on the graph shape it exists for, so the fix
        // is not simply a way of never reporting a gap.
        let mut unlinked = measured.clone();
        unlinked["edge_coverage"]["classes"]["calls"] = json!("absent");
        let gap = absence_coverage_gap("trace_data_flow", &unlinked)
            .expect("a graph holding no cross-file calls cannot complete a call chain");
        assert!(gap.starts_with("cross_file_edges_absent"), "{gap}");
    }

    /// A route query's empty answer is a claim about two names. A twin the
    /// ranking chose among makes it inconclusive; a twin the caller pinned by
    /// file does not, because the caller chose.
    #[test]
    fn a_no_route_answer_across_an_unpinned_twin_is_inconclusive() {
        let payload = json!({
            "from": {"name": "run", "addressed_by": "name", "same_name_candidates": 2},
            "to": {"name": "target", "addressed_by": "name", "same_name_candidates": 1},
            "found": false,
            "routes": [],
            "routes_total": 0,
            "gap": {"reason": "frontier_exhausted", "detail": "", "remediation": ""},
            "degradations": [],
        });
        let negative = negative_for(
            crate::handlers::path::TOOL_NAME,
            &payload,
            &structural_ready_envelope(),
        )
        .expect("a route query is negative-capable");
        assert_eq!(negative["kind"], json!("no_route"));
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(reason.contains("from_ambiguous"), "{reason}");
        assert!(!reason.contains("to_ambiguous"), "{reason}");

        let mut pinned = payload.clone();
        pinned["from"]["addressed_by"] = json!("name_and_file");
        let negative = negative_for(
            crate::handlers::path::TOOL_NAME,
            &pinned,
            &structural_ready_envelope(),
        )
        .unwrap();
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(!reason.contains("from_ambiguous"), "{reason}");
    }

    /// A walk that stopped at its depth bound did not explore the graph it
    /// claims nothing about, and the verdict says so.
    #[test]
    fn a_depth_bounded_no_route_answer_is_inconclusive() {
        let payload = json!({
            "from": {"name": "a", "addressed_by": "entity_id", "same_name_candidates": 1},
            "to": {"name": "b", "addressed_by": "entity_id", "same_name_candidates": 1},
            "found": false,
            "routes": [],
            "routes_total": 0,
            "gap": {"reason": "depth_bound", "detail": "", "remediation": ""},
            "degradations": [],
        });
        let negative = negative_for(
            crate::handlers::path::TOOL_NAME,
            &payload,
            &structural_ready_envelope(),
        )
        .unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(reason.contains("walk_depth_bounded"), "{reason}");

        let mut exhausted = payload.clone();
        exhausted["gap"]["reason"] = json!("frontier_exhausted");
        let negative = negative_for(
            crate::handlers::path::TOOL_NAME,
            &exhausted,
            &structural_ready_envelope(),
        )
        .unwrap();
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(!reason.contains("walk_depth_bounded"), "{reason}");
    }
}
