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

use serde_json::{json, Map, Value};

use crate::envelope::{Envelope, NegativeClass};

/// Reserved, additive top-level key under which a retrieval tool's
/// confidence-qualified negative is attached, beside the `_kin` envelope.
/// Distinctive enough not to collide with any tool payload's own fields.
pub const NEGATIVE_KEY: &str = "negative";

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
        "semantic_search" => RetrievalSpec {
            field: "results",
            kind: "no_entity_match",
            subject: "no entity declaration matched the search",
            always: false,
            class: NegativeClass::Semantic,
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

/// Number of items in the tool's result collection within `payload`, or `None`
/// when the expected collection is absent or not an array (in which case no
/// negative is synthesized — we never guess emptiness).
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
/// Both surfaces count toward the total because both are answers: a store whose
/// files rank but whose entities do not project has returned rows, and calling
/// that an absence would certify a gap the ranking did not report.
fn locate_result_count(payload: &Value) -> Option<usize> {
    if payload.get("routing").and_then(Value::as_str) == Some("fused-v1") {
        let files = payload
            .get("files")
            .and_then(Value::as_array)
            .map(Vec::len)?;
        let entities = payload
            .get("entities")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        return Some(files + entities);
    }
    collection_len(payload, "results")
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
fn query_names_a_symbol(query: &str) -> bool {
    query.split_whitespace().any(|token| {
        let core = token.trim_matches(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'));
        core.len() >= 3
            && (core.contains('_')
                || core.contains("::")
                || core.contains('.')
                || core.chars().filter(|ch| ch.is_ascii_uppercase()).count() >= 2)
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
/// The verdict is read from what each arm already publishes about its FULL
/// ranking, never from the page alone, because a page is a window: an exact name
/// match sitting on page two would otherwise be reported as absent from the
/// whole ranking.
///
/// - Fused arm: `all_fallback` is computed over the full ranking before paging
///   and means precisely this, so it is used verbatim.
/// - Cosine arm: every row's `match_evidence.name_match` is inspected, and only
///   when the page holds the entire ranking. A row that reports no
///   `match_evidence` at all leaves the question unanswered, so nothing is
///   qualified — the same refusal to guess the rest of the module makes.
fn locate_ranking_names_nothing(payload: &Value) -> bool {
    if !payload
        .get("query")
        .and_then(Value::as_str)
        .is_some_and(query_names_a_symbol)
    {
        return false;
    }
    if payload.get("routing").and_then(Value::as_str) == Some("fused-v1") {
        return payload.get("all_fallback").and_then(Value::as_bool) == Some(true);
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
            json!({
                "indexed": coverage.indexed,
                "total": coverage.total,
                "pending": coverage.pending,
                "complete": coverage.complete,
                "percent": (percent * 10.0).round() / 10.0,
            })
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
        gaps.push(
            "method_call_resolution_incomplete: receiver-method calls are linked by bare name \
             and may be unresolved, so an empty chain is not an authoritative absence for a method"
                .to_string(),
        );
    }

    // A name the graph holds more than once (the cfg-twin shape: two arms of the
    // same declaration admitted as distinct entities) means the walk followed
    // one of them, and an edge the extractor could not attribute to a single
    // candidate sits on neither. Certifying that as absence answers for every
    // twin a question that was asked of one.
    match payload
        .get("focal_resolution")
        .and_then(|resolution| resolution.get("same_name_candidates"))
        .and_then(Value::as_u64)
    {
        None => gaps.push(
            "focal_resolution_unreported: the walk did not report how many entities share the \
             focal's name, so an empty chain may describe a same-named sibling rather than the \
             entity that was asked about"
                .to_string(),
        ),
        Some(candidates) if candidates > 1 => gaps.push(format!(
            "focal_resolution_ambiguous: {candidates} entities share the focal's name and only \
             one was walked, so an empty chain is not evidence about the others"
        )),
        Some(_) => {}
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

/// A human sentence spelling out "absent as-of X, coverage Y%, degraded Z" and
/// the actionable consequence, so the negative is legible without cross-reading
/// the envelope. `subject` and `consequence` are passed rather than read off a
/// spec because a tool may narrow its own framing before the advice is built,
/// and because a name that never resolved carries a different consequence than
/// a lookup that ran and found nothing.
fn build_advice(subject: &str, consequence: &str, envelope: &Envelope) -> String {
    let as_of = match &envelope.graph_as_of {
        Some(value) => format!("graph as-of {value}"),
        None => "an unversioned graph snapshot".to_string(),
    };
    let coverage = match &envelope.semantic_coverage {
        Some(coverage) if coverage.total > 0 => {
            let percent = (coverage.indexed as f64 / coverage.total as f64) * 100.0;
            format!("semantic coverage {percent:.1}%")
        }
        Some(_) => "semantic coverage complete".to_string(),
        None => "semantic coverage unknown".to_string(),
    };
    let degraded = envelope.degraded.active_labels();
    let degraded = if degraded.is_empty() {
        "no degraded signals".to_string()
    } else {
        format!("degraded signals [{}]", degraded.join(", "))
    };

    format!("{subject}, against {as_of} with {coverage} and {degraded}. {consequence}")
}

/// The consequence sentence for a retrieval tool that ran and came back empty.
fn absence_consequence(always: bool, trustworthy: bool) -> &'static str {
    match (always, trustworthy) {
        (true, true) => {
            "A `has_references: false` row here is an authoritative negative — safe to treat that entity as unreferenced."
        }
        (true, false) => {
            "Do NOT treat a `has_references: false` row as proof of disuse: the index is not authoritative yet, so a false verdict may simply mean 'not indexed'. Re-check once trust is authoritative."
        }
        (false, true) => "Absence is authoritative: safe to treat the target as genuinely absent/unused.",
        (false, false) => {
            "Absence is NOT authoritative: do not conclude the target is unused or deletable — an empty result may mean 'not indexed'. Re-check after embedding is complete and the daemon is healthy."
        }
    }
}

/// The consequence sentence for a locate page that ranked hits but none the
/// query named. Distinct from [`absence_consequence`], which speaks about an
/// empty result: here the rows are real and stay ranked, and what is absent is
/// the NAME, so the advice has to separate "these are neighbors" from "the
/// symbol does not exist" instead of collapsing them into one verdict.
fn unnamed_ranking_consequence(trustworthy: bool) -> &'static str {
    if trustworthy {
        "These hits are neighbors, not the symbol: no ranked entity carries the name the query asked for, and on a complete graph that means no entity carries it at all. Do not treat the top hit as the requested symbol."
    } else {
        "These hits are neighbors, not the symbol: no ranked entity carries the name the query asked for. The name's absence is NOT authoritative — it may simply not be indexed yet — so do not conclude the symbol does not exist. Re-check after embedding is complete and the daemon is healthy."
    }
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

/// True when the payload's focal is a method, the entity kind whose call edges
/// the linker under-resolves, so absence must not be certified as authoritative.
fn focal_is_method(payload: &Value) -> bool {
    focal_kind(payload).is_some_and(|kind| kind.eq_ignore_ascii_case("method"))
}

fn cross_repo_references_gap(payload: &Value) -> Option<String> {
    let Some(cross_repo) = payload.get("cross_repo") else {
        return Some(
            "cross_repo_authority_missing: find_references did not report cross-repo authority"
                .to_string(),
        );
    };
    match cross_repo.get("status").and_then(Value::as_str) {
        Some("unavailable") => {
            let reason = cross_repo
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("the cross-repo spine could not answer");
            Some(format!("cross_repo_unavailable: {reason}"))
        }
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
                None
            } else {
                Some(format!(
                    "cross_repo_authority_incomplete: spine topology or requested relation subtype is incomplete at revision {}",
                    revision.unwrap_or("unwatermarked")
                ))
            }
        }
        Some("not_configured") => {
            Some("cross_repo_not_configured: cross-repo authority did not answer".to_string())
        }
        Some(status) => Some(format!(
            "cross_repo_authority_unknown: unrecognized cross-repo authority status '{status}'"
        )),
        None => {
            Some("cross_repo_authority_missing: cross-repo authority status is missing".to_string())
        }
    }
}

fn cross_repo_bulk_gap(payload: &Value) -> Option<String> {
    let Some(cross_repo) = payload.get("cross_repo") else {
        return Some(
            "cross_repo_authority_missing: bulk reachability did not report cross-repo authority"
                .to_string(),
        );
    };
    match cross_repo.get("status").and_then(Value::as_str) {
        Some("unavailable") => Some(format!(
            "cross_repo_unavailable: {}",
            cross_repo
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("the cross-repo spine could not answer")
        )),
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
                None
            } else {
                Some(format!(
                    "cross_repo_authority_incomplete: bulk topology or requested relation subtype is incomplete at revision {}",
                    revision.unwrap_or("unwatermarked")
                ))
            }
        }
        Some("not_configured") => {
            Some("cross_repo_not_configured: cross-repo authority did not answer".to_string())
        }
        Some(status) => Some(format!(
            "cross_repo_authority_unknown: unrecognized cross-repo authority status '{status}'"
        )),
        None => {
            Some("cross_repo_authority_missing: cross-repo authority status is missing".to_string())
        }
    }
}

/// Build a confidence-qualified negative for `tool`'s `payload`, enriched from
/// `envelope`, or `None` when the tool is not negative-capable or it returned a
/// non-empty result (and is not an `always`-qualify tool).
///
/// The returned object is additive: callers attach it under [`NEGATIVE_KEY`]
/// beside the existing payload keys, never replacing them.
pub fn negative_for(tool: &str, payload: &Value, envelope: &Envelope) -> Option<Value> {
    let spec = spec_for(tool)?;
    let count = if tool == "semantic_locate" {
        locate_result_count(payload)?
    } else {
        collection_len(payload, spec.field)?
    };
    // A locate page has a second way of being a negative: it came back full, and
    // not one hit is the symbol the query named. Qualifying that page is the
    // whole point — the rows are real neighbors and stay exactly as ranked, so
    // this reports rather than filters, and a weak-but-real hit is never dropped
    // to hide a wrong one.
    let ranking_names_nothing = tool == "semantic_locate" && locate_ranking_names_nothing(payload);
    if count != 0 && !spec.always && !ranking_names_nothing {
        return None;
    }

    let (mut trustworthy, trust_reason) = envelope.negative_trust(spec.class);
    let mut trust_reason = trust_reason.to_string();

    // Receiver-method calls (`x.method()`) are resolved by bare name in
    // the linker while method entities are keyed by their qualified name, so a
    // method's incoming `Calls` edges are frequently dropped. An empty
    // `find_references` for a method is therefore NOT an authoritative "unused"
    // verdict — the calls may simply never have been linked. Never let an agent
    // read "safe to delete" off an incomplete call graph: downgrade to
    // inconclusive so the absence is flagged as possibly-unresolved, not certain.
    if tool == "find_references" && focal_is_method(payload) {
        trustworthy = false;
        trust_reason = "method_call_resolution_incomplete: receiver-method calls are \
             linked by bare name and may be unresolved, so an empty result is not an \
             authoritative absence for a method"
            .to_string();
    }

    // A healthy local graph is not enough to certify "no references" when the
    // configured cross-repo authority failed or returned an invalid payload.
    // Keep the local rows, but make the negative verdict explicitly
    // inconclusive so agents cannot read the gap as safe-to-delete proof.
    if tool == "find_references" {
        if let Some(reason) = cross_repo_references_gap(payload) {
            trustworthy = false;
            trust_reason = reason;
        }
    }

    if tool == "bulk_check_references" {
        if let Some(reason) = cross_repo_bulk_gap(payload) {
            trustworthy = false;
            trust_reason = reason;
        }
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
    }
    if tool == "graph_neighborhood" {
        // The emitted edge array is capped by the caller's `limit`, and a
        // `limit` of zero empties it while the walk still found neighbors. The
        // pre-truncation total is what decides whether anything was there, so a
        // truncated answer is never dressed up as an absence.
        if payload
            .get("relation_count")
            .and_then(Value::as_u64)
            .is_some_and(|total| total > 0)
        {
            return None;
        }
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
            trust_reason = if trustworthy {
                gap.to_string()
            } else {
                format!("{trust_reason}; {gap}")
            };
            trustworthy = false;
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
            let gaps = gaps.join("; ");
            trust_reason = if trustworthy {
                gaps
            } else {
                format!("{trust_reason}; {gaps}")
            };
            trustworthy = false;
        }
    }

    let interpretation = if ranking_names_nothing {
        "unnamed_ranking"
    } else if spec.always {
        "qualified_verdicts"
    } else {
        "absent_as_indexed"
    };
    let consequence = if ranking_names_nothing {
        unnamed_ranking_consequence(trustworthy)
    } else {
        absence_consequence(spec.always, trustworthy)
    };

    let mut negative = Map::new();
    negative.insert("kind".to_string(), json!(kind));
    negative.insert("subject".to_string(), json!(subject));
    negative.insert("result_count".to_string(), json!(count));
    negative.insert("interpretation".to_string(), json!(interpretation));
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
        "degraded_signals".to_string(),
        json!(envelope.degraded.active_labels()),
    );
    negative.insert(
        "advice".to_string(),
        json!(build_advice(subject, consequence, envelope)),
    );
    Some(Value::Object(negative))
}

/// How one tool frames "I could not resolve what you named". These answers are
/// a human message rather than an empty collection, so [`negative_for`] cannot
/// see them at all: there is no payload to count, and the response used to
/// arrive as a bare `{"message": ...}` with the envelope but no negative beside
/// it, which is the one shape an agent cannot calibrate.
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
        let gap = "graph_empty: the graph holds no entities at all, so a name that resolves to \
                   nothing says nothing about whether the symbol exists";
        trust_reason = if trustworthy {
            gap.to_string()
        } else {
            format!("{trust_reason}; {gap}")
        };
        trustworthy = false;
    }

    let consequence = if trustworthy {
        "The name is authoritatively absent from this graph: no entity carries it. That is a fact about the name and not about the symbol's usage, because nothing was looked up."
    } else {
        "Absence is NOT authoritative: the name may simply not be indexed yet, so do not conclude the symbol does not exist. Re-check once the graph is complete and the daemon is healthy."
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
        "degraded_signals".to_string(),
        json!(envelope.degraded.active_labels()),
    );
    negative.insert(
        "advice".to_string(),
        json!(build_advice(subject, consequence, envelope)),
    );
    Some(Value::Object(negative))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Degraded, Envelope, SemanticCoverage};

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
            note: None,
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
        })
    }

    #[test]
    fn non_retrieval_tool_gets_no_negative() {
        let payload = json!({ "ok": true });
        assert!(negative_for("kin_work_create", &payload, &Envelope::daemon()).is_none());
    }

    #[test]
    fn non_empty_result_gets_no_negative() {
        let payload = json!({ "results": [{ "id": "x" }] });
        assert!(negative_for("semantic_search", &payload, &Envelope::daemon()).is_none());
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
    fn semantic_search_complete_coverage_is_authoritative() {
        let payload = json!({ "results": [] });
        let negative = negative_for(
            "semantic_search",
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
    fn semantic_search_partial_coverage_is_inconclusive() {
        let mut env = Envelope::daemon();
        env.semantic_coverage = Some(SemanticCoverage {
            indexed: 40,
            total: 100,
            pending: 60,
            complete: false,
            note: Some("indexing".to_string()),
        });
        let payload = json!({ "results": [] });
        let negative = negative_for("semantic_search", &payload, &env).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("coverage_partial"));
        assert_eq!(negative["semantic_coverage"]["percent"], json!(40.0));
    }

    #[test]
    fn semantic_search_coverage_unknown_even_on_ready_graph_is_inconclusive() {
        // The class boundary: a fully initialized + loaded graph does NOT make a
        // semantic absence authoritative — embeddings can still be incomplete, so
        // an empty semantic result may mean "not indexed".
        let payload = json!({ "results": [] });
        let negative =
            negative_for("semantic_search", &payload, &structural_ready_envelope()).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("coverage_unknown"));
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
        let payload = authoritative_empty_references("function");
        let negative = negative_for("find_references", &payload, &env).unwrap();
        assert_eq!(negative["safe_to_conclude_absent"], json!(false));
        assert!(negative["trust_reason"]
            .as_str()
            .unwrap()
            .contains("degraded"));
        assert_eq!(negative["degraded_signals"], json!(["embed_worker_failed"]));
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

    #[test]
    fn find_references_missing_or_unknown_cross_repo_authority_is_inconclusive() {
        for (cross_repo, expected_reason) in [
            (None, "cross_repo_authority_missing"),
            (
                Some(json!({ "status": "not_configured" })),
                "cross_repo_not_configured",
            ),
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
        json!({
            "focal_id": focal,
            "direction": direction,
            "depth": 2,
            "entity_count": entities.len(),
            "relation_count": relations.len(),
            "entities": entities,
            "relations": relations,
        })
    }

    /// The neighborhood always returns the focal itself, so keying its absence
    /// on the entity list meant the qualifier the tool's own description
    /// promises never fired for an entity that is in the graph — the only case
    /// an agent asks "is this really isolated?" about.
    #[test]
    fn neighborhood_with_no_neighbors_is_qualified() {
        let payload = neighborhood_payload("both", 0);
        let negative = negative_for("graph_neighborhood", &payload, &structural_ready_envelope())
            .expect("an indexed focal with no neighbors must carry a negative");
        assert_eq!(negative["kind"], json!("no_neighbors"));
        assert_eq!(negative["result_count"], json!(0));
        assert_eq!(negative["safe_to_conclude_absent"], json!(true));
    }

    /// One neighbor is not an absence, whichever side it sits on.
    #[test]
    fn neighborhood_with_a_neighbor_gets_no_negative() {
        let payload = neighborhood_payload("both", 1);
        assert!(
            negative_for("graph_neighborhood", &payload, &structural_ready_envelope()).is_none()
        );
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
        assert!(
            negative_for("graph_neighborhood", &payload, &structural_ready_envelope()).is_none(),
            "a walk that found three edges must not report an absence when the caller capped the output"
        );
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
        assert!(negative_for("trace_data_flow", &payload, &structural_ready_envelope()).is_none());
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
        // FIR-2170: the fused arm is the default for code-bearing stores, and
        // its empty page used to reach an agent as a bare `files: []` with no
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
    fn fused_page_with_ranked_files_but_no_entities_is_not_an_absence() {
        // Rows came back. Calling that an absence would certify a gap the
        // ranking never reported.
        let mut payload = empty_fused_locate_page("where does the daemon start");
        payload["files"] = json!([{ "path": "src/lib.rs", "score": 0.5 }]);
        assert!(negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope()
        )
        .is_none());
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
        // FIR-2178: five confidently-scored hits for a symbol that exists
        // nowhere. The page is real and stays whole; what it is NOT is the
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
    fn prose_query_over_fallback_hits_is_not_qualified_as_unnamed() {
        // `all_fallback` fires on natural-language queries whose top hits are
        // correct, so it cannot be the whole rule. A qualifier that fired there
        // too is one an agent learns to ignore.
        let mut payload = empty_fused_locate_page("merge queue captain lane arbitration");
        payload["entities"] = json!([fused_locate_hit("submit_to_queue")]);
        payload["total_ranked"] = json!(3);
        payload["all_fallback"] = json!(true);
        assert!(negative_for(
            "semantic_locate",
            &payload,
            &semantic_authoritative_envelope()
        )
        .is_none());
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
    }
}
