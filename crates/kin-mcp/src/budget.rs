// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! One response-size budget for every retrieval tool.
//!
//! A tool result the client refuses is worse than a short one: the caller gets
//! neither the answer nor a way to ask for less. Claude Code, the agent client
//! this server is most often driven by, refuses an over-size result and spills
//! it to a temp file the agent then has to `Read` with an offset, which is the
//! file-read fallback the product exists to remove, plus a round trip. The MCP
//! protocol carries no field for the client's ceiling, so the server has to pick
//! a default that fits the clients that matter and make size a first-class,
//! reportable property of the response.
//!
//! Two measured payloads are what this module is sized against. On the v0.5.38
//! release-candidate bytes a `semantic_locate` with three query variants at
//! `limit: 10` returned 80,571 characters and a `trace_data_flow` at depth 4
//! with `include_body: false` returned 79,278; both were refused. Neither was
//! bodies: they were per-signal breakdowns, per-file explanation, duplicated hit
//! shapes, and envelopes.
//!
//! The ladder cuts in priority order, and every cut is disclosed through the
//! `degradations` channel the retrieval tools already use, so a caller can tell
//! a whole answer from a bounded one and knows which parameter recovers the
//! rest.

use std::collections::HashMap;

use serde_json::{json, Map, Value};

/// Serialized characters one retrieval response may occupy by default.
///
/// Sized against **Claude Code**, the primary agent client for this server. Its
/// shipped default caps one MCP tool result at 25,000 tokens, read out of the
/// 2.1.239 binary as `MAX_MCP_OUTPUT_TOKENS` falling back to 25000, and over
/// that it refuses the result and writes it to a file the agent then has to
/// `Read` with an offset.
///
/// The band around that cap is measured, not guessed. On the v0.5.47 candidate
/// a `trace_data_flow` at `depth: 5, include_body: false` produced 117,313
/// characters and the client refused them outright, while `impact_analysis`
/// responses at 50,000 and 55,000 characters in the same session came back
/// whole. So the refusal threshold sits above 55,000 and at or below 117,313.
///
/// 45,000 characters is three quarters of [`RESPONSE_MAX_MAX_CHARS`], which
/// leaves a caller room to raise the bound on the same call. It is not a promise
/// that every walk fits: the same run still withheld `impact_analysis` rows at
/// 50,000. What it buys is a default that keeps roughly half again as much of a
/// chain as 30,000 did, on a store where 30,000 dropped 170 of 200 steps, and
/// every list the budget still cuts now says what it cut rather than rendering
/// empty.
pub const RESPONSE_DEFAULT_MAX_CHARS: usize = 45_000;

/// Floor for a caller-supplied budget. Below this the envelope and the
/// disclosure alone do not fit, so a smaller number could only be honoured by
/// returning nothing.
pub const RESPONSE_MIN_MAX_CHARS: usize = 2_000;

/// Ceiling for a caller-supplied budget. A caller with a larger window may raise
/// the bound, but not past what a real client will accept: the daemon serving
/// this has other callers, and a response nothing can read is not worth
/// building.
///
/// 400,000 sat here and was roughly four times what any measurement supports, so
/// the tool advertised a ceiling that guaranteed a refusal to any caller who
/// took it at its word, and one did: it asked for 120,000, got 117,313, and the
/// client threw the whole result away.
///
/// 60,000 is just above the largest payload that run proved a client accepts and
/// roughly half the smallest it proved refused. The token arithmetic agrees:
/// 60,000 characters stays under a 25,000-token cap for any payload averaging
/// more than 2.4 characters per token, and the refusal at 117,313 puts this
/// JSON's own average below 4.69.
pub const RESPONSE_MAX_MAX_CHARS: usize = 60_000;

/// Characters held back from the budget for the disclosure a cut adds.
///
/// A response cut to exactly its ceiling and then told to explain the cut is
/// over its ceiling again, by the length of the explanation. Reserving the room
/// first is what makes the bound hold for the payload that actually ships.
pub const RESPONSE_DISCLOSURE_RESERVE_CHARS: usize = 1_500;

/// Characters the daemon's raw `/mcp/tools/call` route holds back so the MCP
/// path's wrapper still fits.
///
/// The raw route returns the tool payload alone; the stdio MCP path then adds
/// the `_kin` envelope and, on an empty or all-fallback result, the `negative`
/// object. Both ride inside the same JSON the client counts. Bounding the raw
/// payload to the full budget would put every enveloped response a few hundred
/// characters over it, and the stdio pass would then trim a response that had
/// already been cut to fit. The bound has to hold for the bytes the client
/// actually receives, so the room is reserved once, up front, by the arm that
/// cuts first.
pub const RESPONSE_ENVELOPE_RESERVE_CHARS: usize = 2_000;

/// The size contract one tool call is served under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseBudget {
    /// Serialized characters the response may occupy, already clamped.
    pub max_chars: usize,
    /// Whether ranking explanation and per-signal breakdowns are shed before
    /// anything else. On by default: the breakdowns are diagnostics, and a
    /// caller that wants them asks with `explain` or `compact: false`.
    pub compact: bool,
    /// True when the caller named a budget rather than taking the default.
    pub explicit_max_chars: bool,
    /// Characters [`ResponseBudget::less_envelope_reserve`] took off a default
    /// budget, or 0 when nothing was reserved.
    ///
    /// A cut discloses the ceiling it actually enforced, and on the default that
    /// ceiling is not the published one. Carrying the difference lets the
    /// disclosure name both and the reserve between them, so one response stops
    /// reporting two budgets and explaining neither. Both strangers on the
    /// v0.5.40 candidate spent attention deciding which of the published default
    /// and the reduced one was real; the arithmetic joining them was in this file
    /// the whole time.
    pub envelope_reserve: usize,
}

impl Default for ResponseBudget {
    fn default() -> Self {
        Self {
            max_chars: RESPONSE_DEFAULT_MAX_CHARS,
            compact: true,
            explicit_max_chars: false,
            envelope_reserve: 0,
        }
    }
}

impl ResponseBudget {
    /// Read the budget a call asks for.
    ///
    /// `max_chars` is the documented spelling; `max_response_chars` is the
    /// spelling `trace_data_flow` shipped first and keeps working, because an
    /// agent that learned it from that tool must not be handed an unbounded
    /// response for using it. Either is clamped to what this server will serve.
    ///
    /// `compact` defaults on. An explicit `compact` wins; failing that,
    /// `explain: true` turns it off, because a caller asking for the ranking
    /// explanation is asking for the very fields compaction sheds.
    pub fn from_arguments(args: &HashMap<String, Value>) -> Self {
        let requested = ["max_chars", "max_response_chars"]
            .into_iter()
            .find_map(|key| args.get(key).and_then(Value::as_u64));
        let explain = args
            .get("explain")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        Self {
            max_chars: requested
                .map(|value| value as usize)
                .unwrap_or(RESPONSE_DEFAULT_MAX_CHARS)
                .clamp(RESPONSE_MIN_MAX_CHARS, RESPONSE_MAX_MAX_CHARS),
            compact: args
                .get("compact")
                .and_then(Value::as_bool)
                .unwrap_or(!explain),
            explicit_max_chars: requested.is_some(),
            envelope_reserve: 0,
        }
    }

    /// The same budget, reduced by the room the MCP path's envelope and negative
    /// need. Used by the arm that cuts first so the later one has nothing left
    /// to cut.
    ///
    /// A budget the CALLER named is returned unchanged. The reserve is this
    /// server's own arithmetic about its own default, and quietly enforcing
    /// something smaller than the number a caller passed would make two arms
    /// answer one call under two ceilings: the tool would report the cut it made
    /// at the requested budget, and a later pass would cut again to a number the
    /// caller never asked for and the response never names.
    pub fn less_envelope_reserve(self) -> Self {
        if self.explicit_max_chars {
            return self;
        }
        let reduced = self
            .max_chars
            .saturating_sub(RESPONSE_ENVELOPE_RESERVE_CHARS)
            .max(RESPONSE_MIN_MAX_CHARS);
        Self {
            max_chars: reduced,
            envelope_reserve: self.max_chars.saturating_sub(reduced),
            ..self
        }
    }
}

/// What the budget did to one response. Carried on the `_kin` envelope under
/// `response`, so a caller can see that an answer was bounded and by how much
/// without having to compare it against an unbounded run it cannot make.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BudgetAccounting {
    /// The budget that was applied, after clamping.
    pub max_chars: usize,
    /// What the payload measured BEFORE the budget touched it.
    #[serde(rename = "chars_before_budget")]
    pub chars_before: usize,
    /// True when something was actually removed.
    pub bounded: bool,
    /// True when explanation and per-signal breakdowns were shed.
    pub compact: bool,
}

impl BudgetAccounting {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

/// The reason code a budget elision carries, so a caller keying on it never has
/// to parse prose.
pub const ELISION_REASON_BUDGET: &str = "response_budget";

/// Where a payload publishes what its lists lost.
pub const ELISIONS_KEY: &str = "elisions";

/// What one list lost to the response budget.
///
/// A list the budget cut must never render as an empty array. An empty array is
/// the shape a caller reads as "the walk saw none", and no counter elsewhere in
/// the response outranks it: two `impact_analysis` answers in one stranger
/// session carried `"affected_tests": []` beside a `covering_tests: 16` that
/// contradicted it, and both times the empty array won and the reader drew the
/// wrong conclusion. A sibling `affected_tests_withheld: 15` was right there in
/// the second one and did not save it either.
///
/// So a cut list keeps at least one entry and publishes this record beside it,
/// and an empty array afterward means one thing only.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Elision {
    /// Entries the budget withheld from this list.
    pub elided: usize,
    /// Entries the response still carries. Never zero when the walk found any.
    pub kept: usize,
    /// Entries the walk actually found, which is `kept + elided`.
    pub total: usize,
    /// Why they were withheld. [`ELISION_REASON_BUDGET`] today, named rather
    /// than assumed, so a cut made later for a different reason cannot be read
    /// as this one.
    pub reason: String,
}

impl Elision {
    /// One list's loss, from what survived and what did not.
    pub fn budget(kept: usize, elided: usize) -> Self {
        Self {
            elided,
            kept,
            total: kept.saturating_add(elided),
            reason: ELISION_REASON_BUDGET.to_string(),
        }
    }
}

/// Record one list's elision on the payload, under the top-level `elisions`
/// map, keyed by the field that was cut.
///
/// One map rather than a sibling key per list: a caller asking "did this
/// response lose anything" reads one key, and the answer has the same shape for
/// `chain` as it has for `affected_tests`. The older `<field>_withheld` scalars
/// stay beside it, because a client already reading them must not lose its
/// counter to this change.
pub fn record_elision(payload: &mut Value, field: &str, kept: usize, elided: usize) {
    if elided == 0 {
        return;
    }
    let entry = serde_json::to_value(Elision::budget(kept, elided)).unwrap_or(Value::Null);
    match payload.get_mut(ELISIONS_KEY).and_then(Value::as_object_mut) {
        Some(map) => {
            map.insert(field.to_string(), entry);
        }
        None => {
            let mut map = Map::new();
            map.insert(field.to_string(), entry);
            payload[ELISIONS_KEY] = Value::Object(map);
        }
    }
}

/// Serialized size of a payload, measured the way every emitter on both
/// surfaces renders it. Measuring a compact form nobody sends would charge the
/// budget for a payload no caller receives.
pub fn measure(value: &Value) -> usize {
    serde_json::to_string_pretty(value).map_or(usize::MAX, |json| json.len())
}

/// One tool's payload shape, in the terms the budget acts on.
struct ResponseShape {
    /// Arrays holding one entry per hit, most important FIRST. The ladder trims
    /// from the last, because the last is the one whose content another array in
    /// the same response already carries.
    collections: &'static [&'static str],
    /// Per-hit keys holding source text.
    body_keys: &'static [&'static str],
    /// Per-hit keys holding ranking explanation or per-signal breakdowns.
    explain_keys: &'static [&'static str],
    /// Top-level keys holding explanation blocks.
    top_explain_keys: &'static [&'static str],
    /// Per-hit keys holding a nested repeat of hits another collection already
    /// reports in full.
    duplicate_keys: &'static [&'static str],
    /// Per-hit keys holding bulk identity or retrieval-internal state that no
    /// reader of this tool's answer consumes.
    ///
    /// Separate from `explain_keys` because it is not an explanation of a hit:
    /// it is machinery that rides along on a serialized entity. `impact_analysis`
    /// returned 416,567 characters for one method on a 37-file repository, and
    /// 78.5% of it was four 32-element hash arrays per row plus embedding and
    /// import previews. None of it answers "what breaks if I change this", and
    /// a caller who wants an entity in full has `get_entity_source`.
    bulk_keys: &'static [&'static str],
    /// The parameter a caller narrows to avoid a trim.
    narrow_param: &'static str,
}

/// The retrieval tools this budget governs, and the shape of what each returns.
///
/// Membership is deliberately not "every tool". A tool whose whole purpose is to
/// hand back requested source (`get_entity_source`, `get_entity_sources`,
/// `kin_artifact_read`) would be answering a different question if it silently
/// returned less code than was asked for; those carry their own explicit line
/// and byte caps instead. What is listed here is the retrieval family, where the
/// answer is a ranking or a walk and the caller can always ask for the rest.
fn shape_for(tool: &str) -> Option<ResponseShape> {
    let shape = match tool {
        "semantic_locate" => ResponseShape {
            collections: &["entities", "files"],
            body_keys: &["body", "snippet"],
            explain_keys: &[
                "match_evidence",
                "explain",
                "signal_scores",
                "score_breakdown",
            ],
            top_explain_keys: &["debug"],
            // Every symbol in `files[].symbols[]` is a hit `entities[]` already
            // reports with more fields, so the roll-up is the redundant copy.
            duplicate_keys: &["symbols"],
            bulk_keys: &[],
            narrow_param: "limit",
        },
        // The enumeration surface. `narrow_param` is `page_size` rather than a
        // limit, because this tool's answer to "too large" is a smaller page
        // plus a cursor to the rest, never a smaller answer. Nothing is listed
        // under `body_keys`: the rows carry a signature and a span and no source
        // body at all, so there is no body layer to shed before rows are.
        FILE_ENTITIES_TOOL => ResponseShape {
            collections: &["entities"],
            body_keys: &["doc_summary"],
            explain_keys: &[],
            top_explain_keys: &[],
            duplicate_keys: &[],
            bulk_keys: &[],
            narrow_param: "page_size",
        },
        "semantic_search" => ResponseShape {
            collections: &["results"],
            body_keys: &["doc_summary"],
            explain_keys: &[],
            top_explain_keys: &[],
            duplicate_keys: &[],
            bulk_keys: &[],
            narrow_param: "limit",
        },
        "trace_data_flow" => ResponseShape {
            collections: &["chain"],
            body_keys: &["body"],
            explain_keys: &[],
            top_explain_keys: &[],
            duplicate_keys: &[],
            bulk_keys: &[],
            narrow_param: "depth",
        },
        "get_context_pack" | "trace_computation" => ResponseShape {
            // `dependents` sheds beside `dependencies`: it is the same section
            // split by direction, and a group the budget cannot trim is a group
            // that can push a response past its cap on its own.
            collections: &[
                "dependencies",
                "dependents",
                "transitive_deps",
                "tests",
                "contracts",
            ],
            body_keys: &["body"],
            explain_keys: &["projection"],
            top_explain_keys: &[],
            duplicate_keys: &[],
            bulk_keys: &[],
            narrow_param: "depth",
        },
        "find_references" => ResponseShape {
            collections: &["references"],
            body_keys: &["body", "snippet"],
            explain_keys: &[],
            top_explain_keys: &[],
            duplicate_keys: &[],
            bulk_keys: &[],
            narrow_param: "relation_kinds",
        },
        "graph_neighborhood" => ResponseShape {
            collections: &["entities", "relations"],
            body_keys: &["body", "signature"],
            explain_keys: &[],
            top_explain_keys: &[],
            duplicate_keys: &[],
            bulk_keys: &[],
            narrow_param: "depth",
        },
        // The four buckets an `ImpactReport` serializes as arrays of raw
        // entities, most important first. `impacted_entities` was never a key
        // this response carries, so naming it here left every rung of the ladder
        // walking an array that does not exist: nothing was stripped and nothing
        // was trimmed on a 416,567-character answer. `entity_impacts` is
        // deliberately absent, because its per-entity counts ARE the answer and
        // they are small.
        "impact_analysis" => ResponseShape {
            collections: &[
                "affected_callers",
                "affected_dependents",
                "affected_contract_consumers",
                "affected_tests",
            ],
            body_keys: &["body"],
            explain_keys: &[],
            top_explain_keys: &[],
            duplicate_keys: &[],
            bulk_keys: &["fingerprint", "metadata"],
            narrow_param: "depth",
        },
        "find_dead_code_seeded" => ResponseShape {
            collections: &["candidates"],
            body_keys: &["body"],
            explain_keys: &[],
            top_explain_keys: &[],
            duplicate_keys: &[],
            bulk_keys: &[],
            narrow_param: "limit",
        },
        "bulk_check_references" => ResponseShape {
            collections: &["results"],
            body_keys: &[],
            explain_keys: &[],
            top_explain_keys: &[],
            duplicate_keys: &[],
            bulk_keys: &[],
            narrow_param: "entity_ids",
        },
        _ => return None,
    };
    Some(shape)
}

/// Whether this tool's response is governed by the budget.
/// The file-enumeration tool, named from the handler that defines it so this
/// table cannot come to describe a tool under a name the registry stopped using.
const FILE_ENTITIES_TOOL: &str = crate::handlers::file_entities::TOOL_NAME;

pub fn is_budgeted(tool: &str) -> bool {
    shape_for(tool).is_some()
}

/// Compact and bound one retrieval payload in place, disclosing every cut.
///
/// Returns `None` for a tool the budget does not govern, so a caller can tell
/// "not budgeted" from "budgeted and untouched" rather than reading an absent
/// accounting as either.
///
/// The ladder is ordered by what a caller loses. Explanation and per-signal
/// breakdowns go first: they are diagnostics about a hit, not the hit. A nested
/// repeat of hits another array already carries goes next, because dropping it
/// costs nothing at all. Source bodies go next, recoverable one call at a time
/// through `get_entity_source`. Only then are hits themselves withheld, from the
/// tail of the least important array first, which is the only cut that removes
/// an answer rather than a description of one.
pub fn enforce(
    payload: &mut Value,
    tool: &str,
    budget: &ResponseBudget,
) -> Option<BudgetAccounting> {
    let shape = shape_for(tool)?;
    let chars_before = measure(payload);
    let mut accounting = BudgetAccounting {
        max_chars: budget.max_chars,
        chars_before,
        bounded: false,
        compact: budget.compact,
    };
    let mut cuts: Vec<String> = Vec::new();
    let mut remediations: Vec<String> = Vec::new();

    // Compact by default, whether or not the payload is over budget: the
    // breakdowns are diagnostics a caller did not ask for, and shipping them
    // unasked is what made a ten-result ranking an 80,000-character response.
    // This one is not disclosed as a cut, because it is the documented default
    // shape rather than something the budget took away under pressure.
    if budget.compact {
        strip_keys(payload, &shape, shape.explain_keys, shape.top_explain_keys);
        strip_keys(payload, &shape, shape.bulk_keys, &[]);
    }

    if measure(payload) <= budget.max_chars {
        return Some(accounting);
    }

    // The reserve holds room for the disclosure the cut adds, but it can never
    // be a fixed number: at the floor of the clamp a flat 1,500 characters would
    // leave a few hundred for the answer, and the ladder would strip a response
    // down to nothing to make room for the note explaining that it had. It
    // scales with the budget instead.
    let reserve = RESPONSE_DISCLOSURE_RESERVE_CHARS.min(budget.max_chars / 4);
    let target = budget.max_chars.saturating_sub(reserve);

    // A caller that explicitly turned compaction off still cannot be served a
    // response its client refuses, so the diagnostics go under pressure anyway.
    // The disclosure names what happened; silence would leave the caller reading
    // an explain-less response it had explicitly asked to explain.
    if !budget.compact {
        let stripped = strip_keys(payload, &shape, shape.explain_keys, shape.top_explain_keys);
        if stripped > 0 {
            accounting.bounded = true;
            cuts.push(format!(
                "ranking explanation and per-signal breakdowns dropped from {stripped} entries"
            ));
        }
        // Bulk identity is shed here too. A caller that turned compaction off
        // asked to see the ranking, not to be served a response its client
        // refuses because every row carries four hash arrays.
        let stripped = strip_keys(payload, &shape, shape.bulk_keys, &[]);
        if stripped > 0 {
            accounting.bounded = true;
            cuts.push(format!(
                "identity fingerprints and retrieval metadata dropped from {stripped} entries, \
                 each of which still carries its name, location, and span"
            ));
        }
        if measure(payload) <= target {
            disclose(payload, budget, &cuts, &remediations);
            return Some(accounting);
        }
    }

    if !shape.duplicate_keys.is_empty() {
        let stripped = strip_keys(payload, &shape, shape.duplicate_keys, &[]);
        if stripped > 0 {
            accounting.bounded = true;
            cuts.push(format!(
                "the per-file symbol roll-up dropped from {stripped} entries, every symbol of \
                 which is still reported in full under `{}`",
                shape.collections.first().copied().unwrap_or("entities")
            ));
        }
        if measure(payload) <= target {
            disclose(payload, budget, &cuts, &remediations);
            return Some(accounting);
        }
    }

    if !shape.body_keys.is_empty() {
        let stripped = strip_keys(payload, &shape, shape.body_keys, &[]);
        if stripped > 0 {
            accounting.bounded = true;
            cuts.push(format!(
                "inline source dropped from {stripped} hits, each of which still carries its \
                 identity, location, and span"
            ));
            remediations.push("read one body with get_entity_source".to_string());
        }
        if measure(payload) <= target {
            disclose(payload, budget, &cuts, &remediations);
            return Some(accounting);
        }
    }

    // Last resort: withhold hits, from the tail of the least important array
    // first. This is the only stage that removes an answer, so it reports the
    // count withheld and the parameter that recovers them.
    //
    // Every collection keeps at least one entry, not just the primary one. A
    // bound is not a refusal: a caller handed an empty array cannot tell it from
    // "nothing matched", which is the one reading a size cut must never produce,
    // and the reading does not get safer further down the response. The floor
    // used to be the primary alone, so the last bucket of an `impact_analysis`
    // emptied first and `"affected_tests": []` shipped beside a
    // `covering_tests: 16` that said sixteen tests cover it.
    let primary = shape.collections.first().copied();
    let mut withheld_any = false;
    for key in shape.collections.iter().rev() {
        let found = payload
            .get(*key)
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        let withheld = trim_collection(payload, key, target, 1);
        if withheld > 0 {
            accounting.bounded = true;
            withheld_any = true;
            cuts.push(format!(
                "{withheld} of {found} entries withheld from the end of `{key}`"
            ));
            record_elision(payload, key, found.saturating_sub(withheld), withheld);
            payload["truncated"] = Value::Bool(true);
        }
        if measure(payload) <= target {
            break;
        }
    }
    if withheld_any {
        let kept = primary
            .and_then(|key| payload.get(key))
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        if payload.get("next_cursor").is_some() && kept > 0 {
            remediations.push(format!(
                "re-issue with `page_size: {kept}` and follow `next_cursor`"
            ));
        } else {
            remediations.push(format!("narrow the request with `{}`", shape.narrow_param));
        }
    }

    disclose(payload, budget, &cuts, &remediations);
    Some(accounting)
}

/// Remove `keys` from every hit in every collection, and `top_keys` from the
/// payload itself. Returns how many entries lost at least one key, which is the
/// number the disclosure reports.
fn strip_keys(
    payload: &mut Value,
    shape: &ResponseShape,
    keys: &[&str],
    top_keys: &[&str],
) -> usize {
    let mut stripped = 0usize;
    for key in top_keys {
        if let Some(map) = payload.as_object_mut() {
            if map.remove(*key).is_some() {
                stripped += 1;
            }
        }
    }
    if keys.is_empty() {
        return stripped;
    }
    for collection in shape.collections {
        let Some(entries) = payload.get_mut(*collection).and_then(Value::as_array_mut) else {
            continue;
        };
        for entry in entries.iter_mut() {
            let Some(map) = entry.as_object_mut() else {
                continue;
            };
            let mut touched = false;
            for key in keys {
                if remove_present(map, key) {
                    touched = true;
                }
            }
            if touched {
                stripped += 1;
            }
        }
    }
    // A focal record is reported in the same shape as a hit and carries the same
    // keys, so it is charged the same cuts. Leaving it whole would keep the
    // largest single body in a response that just dropped every other one.
    for focal in ["focal_entity", "focal"] {
        if let Some(map) = payload.get_mut(focal).and_then(Value::as_object_mut) {
            let mut touched = false;
            for key in keys {
                if remove_present(map, key) {
                    touched = true;
                }
            }
            if touched {
                stripped += 1;
            }
        }
    }
    stripped
}

/// Remove one key when it carries something. A key already absent, or already
/// explicitly null, is not a cut and must not be counted as one: a disclosure
/// naming entries nothing was taken from is a false report of loss.
fn remove_present(map: &mut Map<String, Value>, key: &str) -> bool {
    match map.get(key) {
        None | Some(Value::Null) => false,
        Some(_) => {
            map.remove(key);
            true
        }
    }
}

/// Withhold entries from the tail of one collection until the payload fits,
/// returning how many were withheld.
///
/// Bisected rather than popped one at a time: the same answer, in a handful of
/// serializations instead of one per withheld entry. A suffix is what makes the
/// cut safe for a walk whose entries reference earlier ones by index, because
/// removing the end never orphans a surviving entry's parent.
fn trim_collection(payload: &mut Value, key: &str, target: usize, min_keep: usize) -> usize {
    let Some(full) = payload.get(key).and_then(Value::as_array).cloned() else {
        return 0;
    };
    if full.len() <= min_keep || measure(payload) <= target {
        return 0;
    }
    let mut kept = min_keep;
    let mut low = min_keep;
    let mut high = full.len();
    while low <= high {
        let mid = (low + high) / 2;
        payload[key] = Value::Array(full[..mid].to_vec());
        if measure(payload) <= target {
            kept = mid;
            low = mid + 1;
        } else if mid == min_keep {
            break;
        } else {
            high = mid - 1;
        }
    }
    payload[key] = Value::Array(full[..kept].to_vec());
    let withheld = full.len() - kept;
    if withheld > 0 {
        payload[format!("{key}_withheld")] = Value::from(withheld);
    }
    withheld
}

/// Append the cuts to the `degradations` channel the retrieval tools already
/// use, so a bounded response is attributable rather than merely short.
///
/// One entry for the whole ladder rather than one per stage. Four separate
/// notes, each restating the budget and its own remediation, ran to more
/// characters than a small budget has to spend, so the disclosure competed with
/// the answer it was describing and the ladder emptied the ranking to make room
/// for it.
///
/// Appended rather than assigned: the pipeline may already have disclosed
/// something about this same answer, and overwriting that would trade one silent
/// degradation for another.
/// Record one bounded response as a degradation, naming the ceiling that was
/// actually enforced.
///
/// On a caller-named budget that ceiling is the number the caller passed and
/// there is nothing more to say. On the default it is the published default
/// less the envelope reserve, and a disclosure that names only the enforced
/// number leaves the response reporting two budgets with no arithmetic between
/// them. So the default case names all three: what was enforced, what was
/// reserved, and the published number both come from.
fn disclose(
    payload: &mut Value,
    budget: &ResponseBudget,
    cuts: &[String],
    remediations: &[String],
) {
    if cuts.is_empty() {
        return;
    }
    let max_chars = budget.max_chars;
    let ceiling = if budget.envelope_reserve == 0 {
        format!("{max_chars}-character budget")
    } else {
        format!(
            "{max_chars}-character budget (the {}-character default less a {}-character \
             envelope reserve)",
            max_chars + budget.envelope_reserve,
            budget.envelope_reserve
        )
    };
    let mut remediation = remediations.join("; ");
    if !remediation.is_empty() {
        remediation.push_str("; ");
    }
    remediation.push_str(&format!(
        "or raise max_chars, up to the {RESPONSE_MAX_MAX_CHARS} this server will build, if the \
         caller's own result limit accepts a larger payload"
    ));
    let entry = json!({
        "component": "response_budget",
        "reason": "response_bounded",
        "detail": format!("the response exceeded its {ceiling}, so {}", cuts.join("; ")),
        "remediation": remediation,
        "max_chars": max_chars,
    });
    match payload
        .get_mut("degradations")
        .and_then(Value::as_array_mut)
    {
        Some(existing) => existing.push(entry),
        None => payload["degradations"] = Value::Array(vec![entry]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locate_payload(hits: usize, body_chars: usize) -> Value {
        let entities: Vec<Value> = (0..hits)
            .map(|index| {
                json!({
                    "entity_id": format!("00000000-0000-0000-0000-{index:012}"),
                    "name": format!("handler_{index}"),
                    "kind": "function",
                    "score": 0.5,
                    "definition": true,
                    "body": "x".repeat(body_chars),
                    "match_evidence": {
                        "ranker": "fused-v1",
                        "signals": ["vector", "lexical", "graph"],
                        "matched_variant_indexes": [0, 1, 2],
                    },
                    "provenance": { "file": format!("src/f{index}.rs") },
                })
            })
            .collect();
        let files: Vec<Value> = (0..hits)
            .map(|index| {
                json!({
                    "path": format!("src/f{index}.rs"),
                    "score": 0.5,
                    "signals": ["vector", "lexical"],
                    "symbols": (0..8).map(|s| json!({
                        "name": format!("sym_{index}_{s}"),
                        "kind": "function",
                        "score": 0.4,
                        "span": [1, 40],
                    })).collect::<Vec<_>>(),
                    "explain": ["ranked by vector similarity 0.81", "lexical hit on token"],
                })
            })
            .collect();
        json!({
            "query": "where redirects are resolved",
            "entities": entities,
            "files": files,
            "total_ranked": hits,
            "next_cursor": "deadbeefdeadbeef.1",
        })
    }

    #[test]
    fn unbudgeted_tool_is_left_alone() {
        let mut payload = json!({ "anything": "at all" });
        assert!(enforce(&mut payload, "kin_work_create", &ResponseBudget::default()).is_none());
        assert_eq!(payload, json!({ "anything": "at all" }));
    }

    #[test]
    fn compact_sheds_breakdowns_without_touching_the_hits() {
        let mut payload = locate_payload(4, 20);
        let before = measure(&payload);
        let accounting = enforce(&mut payload, "semantic_locate", &ResponseBudget::default())
            .expect("semantic_locate is budgeted");
        assert_eq!(accounting.chars_before, before);
        assert_eq!(payload["entities"].as_array().unwrap().len(), 4);
        for hit in payload["entities"].as_array().unwrap() {
            assert!(
                hit.get("match_evidence").is_none(),
                "breakdown survived: {hit}"
            );
            assert!(
                hit.get("body").is_some(),
                "a compact pass must keep the answer"
            );
        }
        for file in payload["files"].as_array().unwrap() {
            assert!(file.get("explain").is_none());
        }
    }

    #[test]
    fn an_oversized_response_is_cut_to_its_budget_and_says_so() {
        const BUDGET: usize = 6_000;
        let mut payload = locate_payload(30, 400);
        let before = measure(&payload);
        assert!(before > BUDGET, "the fixture must overflow: {before}");
        let budget = ResponseBudget {
            max_chars: BUDGET,
            ..ResponseBudget::default()
        };
        let accounting =
            enforce(&mut payload, "semantic_locate", &budget).expect("semantic_locate is budgeted");
        let after = measure(&payload);
        assert!(
            after <= BUDGET,
            "the tool must return what it promised: {after}"
        );
        assert!(accounting.bounded);
        assert_eq!(accounting.chars_before, before);
        assert_eq!(accounting.max_chars, BUDGET);
        let cuts = payload["degradations"]
            .as_array()
            .expect("a cut is disclosed");
        assert!(cuts
            .iter()
            .all(|cut| cut["component"] == json!("response_budget")));
    }

    /// At the floor of the clamp the disclosure is a large fraction of the whole
    /// budget, which is exactly where a ladder that cuts to make room for its own
    /// explanation returns an empty ranking. An empty ranking is indistinguishable
    /// from "nothing matched", so the primary collection always keeps one hit.
    #[test]
    fn a_bound_is_not_a_refusal() {
        let mut payload = locate_payload(60, 2_000);
        let budget = ResponseBudget {
            max_chars: RESPONSE_MIN_MAX_CHARS,
            ..ResponseBudget::default()
        };
        enforce(&mut payload, "semantic_locate", &budget).expect("budgeted");
        assert!(
            !payload["entities"].as_array().unwrap().is_empty(),
            "a budget must still answer: {payload}"
        );
        assert_eq!(payload["truncated"], json!(true));
        assert_eq!(payload["total_ranked"], json!(60));
    }

    #[test]
    fn withheld_hits_are_counted_and_flagged() {
        let mut payload = locate_payload(40, 300);
        let budget = ResponseBudget {
            max_chars: 4_000,
            ..ResponseBudget::default()
        };
        enforce(&mut payload, "semantic_locate", &budget).expect("budgeted");
        let kept = payload["entities"].as_array().unwrap().len();
        if kept < 40 {
            assert_eq!(
                payload["entities_withheld"].as_u64().unwrap() as usize + kept,
                40
            );
            assert_eq!(payload["truncated"], json!(true));
        }
        assert_eq!(
            payload["total_ranked"],
            json!(40),
            "the full ranking size is still reported"
        );
    }

    #[test]
    fn a_response_inside_its_budget_keeps_every_hit() {
        let mut payload = locate_payload(3, 50);
        let accounting =
            enforce(&mut payload, "semantic_locate", &ResponseBudget::default()).expect("budgeted");
        assert_eq!(payload["entities"].as_array().unwrap().len(), 3);
        assert!(payload.get("entities_withheld").is_none());
        assert!(payload.get("truncated").is_none());
        assert!(accounting.chars_before > 0);
    }

    #[test]
    fn caller_budget_is_clamped_and_both_spellings_are_read() {
        let mut args = HashMap::new();
        args.insert("max_chars".to_string(), json!(10));
        assert_eq!(
            ResponseBudget::from_arguments(&args).max_chars,
            RESPONSE_MIN_MAX_CHARS
        );
        args.insert("max_chars".to_string(), json!(9_000_000u64));
        assert_eq!(
            ResponseBudget::from_arguments(&args).max_chars,
            RESPONSE_MAX_MAX_CHARS
        );
        let mut legacy = HashMap::new();
        legacy.insert("max_response_chars".to_string(), json!(50_000));
        assert_eq!(ResponseBudget::from_arguments(&legacy).max_chars, 50_000);
        assert!(ResponseBudget::from_arguments(&legacy).explicit_max_chars);
        assert!(!ResponseBudget::from_arguments(&HashMap::new()).explicit_max_chars);
    }

    #[test]
    fn explain_turns_compaction_off_and_an_explicit_compact_wins() {
        let mut explaining = HashMap::new();
        explaining.insert("explain".to_string(), json!(true));
        assert!(!ResponseBudget::from_arguments(&explaining).compact);
        explaining.insert("compact".to_string(), json!(true));
        assert!(ResponseBudget::from_arguments(&explaining).compact);
        assert!(ResponseBudget::from_arguments(&HashMap::new()).compact);
    }

    /// An impact row as the daemon serializes it: a raw entity, most of whose
    /// bytes are four 32-element hash arrays and two retrieval previews.
    fn impact_row(index: usize) -> Value {
        let hash = |seed: usize| -> Vec<u64> {
            (0..32).map(|i| ((seed + i) * 7919 % 256) as u64).collect()
        };
        json!({
            "id": format!("9b9f577c-2cb3-43fd-a59b-ced58218{index:04}"),
            "name": format!("consumer_{index}"),
            "file_origin": "src/requests/sessions.py",
            "span": [10, 40],
            "fingerprint": {
                "ast_hash": hash(index),
                "behavior_hash": hash(index + 1),
                "equivalence_hash": hash(index + 2),
                "signature_hash": hash(index + 3),
            },
            "metadata": {
                "embedding_body_preview": "def send(self, request, **kwargs): ".repeat(12),
                "file_import_context": "module requests.adapters; module requests.sessions; "
                    .repeat(8),
            },
        })
    }

    fn impact_payload(rows: usize) -> Value {
        json!({
            "affected_callers": (0..rows).map(impact_row).collect::<Vec<_>>(),
            "affected_dependents": (0..rows).map(impact_row).collect::<Vec<_>>(),
            "affected_contract_consumers": (0..rows / 4).map(impact_row).collect::<Vec<_>>(),
            "affected_tests": (0..rows).map(impact_row).collect::<Vec<_>>(),
            "entity_impacts": [{
                "entity_id": "9b9f577c-2cb3-43fd-a59b-ced5821a4887",
                "consumer_count": 2,
                "proven_consumer_count": 0,
                "consumer_files": ["src/requests/auth.py", "src/requests/sessions.py"],
            }],
        })
    }

    /// `impact_analysis` returned 416,567 characters for one method because the
    /// shape named a collection the response does not carry, so every rung of
    /// the ladder walked an absent array and cut nothing. The buckets are the
    /// ones an `ImpactReport` actually serializes.
    #[test]
    fn impact_analysis_is_bounded_on_a_large_fan_in_entity() {
        let mut payload = impact_payload(33);
        let unbounded = measure(&payload);
        assert!(
            unbounded > RESPONSE_DEFAULT_MAX_CHARS,
            "fixture must start over budget, measured {unbounded}"
        );
        let budget = ResponseBudget::default();
        enforce(&mut payload, "impact_analysis", &budget).expect("budgeted");
        let after = measure(&payload);
        assert!(
            after <= budget.max_chars,
            "impact_analysis stayed at {after} characters against a {} budget",
            budget.max_chars
        );
        // The answer survives the cut.
        assert_eq!(payload["entity_impacts"][0]["consumer_count"], json!(2));
    }

    /// Compact mode is the default, and on this tool it is what sheds the bulk.
    #[test]
    fn compact_mode_sheds_impact_fingerprints_and_retrieval_metadata() {
        let mut payload = impact_payload(4);
        enforce(&mut payload, "impact_analysis", &ResponseBudget::default()).expect("budgeted");
        let row = &payload["affected_callers"][0];
        assert!(
            row.get("fingerprint").is_none(),
            "fingerprint survived: {row}"
        );
        assert!(row.get("metadata").is_none(), "metadata survived: {row}");
        assert_eq!(row["name"], json!("consumer_0"), "identity must survive");
    }

    /// One response named two budgets and explained neither: the envelope
    /// published the default while the arm that cut disclosed the default less
    /// the reserve. The disclosure now carries the arithmetic joining them.
    ///
    /// Every number here is read off the constants rather than written out, so
    /// moving the default moves the test with it instead of leaving a green
    /// assertion about a budget nothing serves.
    #[test]
    fn a_default_budget_discloses_the_envelope_reserve_it_was_cut_by() {
        let enforced = RESPONSE_DEFAULT_MAX_CHARS - RESPONSE_ENVELOPE_RESERVE_CHARS;
        let mut payload = locate_payload(120, 900);
        let budget = ResponseBudget::default().less_envelope_reserve();
        enforce(&mut payload, "semantic_locate", &budget).expect("budgeted");
        let detail = payload["degradations"][0]["detail"]
            .as_str()
            .expect("a cut was disclosed")
            .to_string();
        assert!(
            detail.contains(&format!("{enforced}-character budget")),
            "must name what it enforced: {detail}"
        );
        assert!(
            detail.contains(&format!("{RESPONSE_DEFAULT_MAX_CHARS}-character default"))
                && detail.contains(&format!(
                    "{RESPONSE_ENVELOPE_RESERVE_CHARS}-character envelope reserve"
                )),
            "must name the published default and the reserve between them: {detail}"
        );
        assert_eq!(payload["degradations"][0]["max_chars"], json!(enforced));
    }

    /// A caller who named a ceiling is told that ceiling and nothing else: there
    /// is no reserve on a caller-named budget, so naming one would invent a
    /// number.
    #[test]
    fn a_caller_named_budget_discloses_one_number() {
        let mut args = HashMap::new();
        args.insert("max_chars".to_string(), json!(9_000));
        let budget = ResponseBudget::from_arguments(&args).less_envelope_reserve();
        assert_eq!(budget.envelope_reserve, 0);
        let mut payload = locate_payload(40, 900);
        enforce(&mut payload, "semantic_locate", &budget).expect("budgeted");
        let detail = payload["degradations"][0]["detail"]
            .as_str()
            .expect("a cut was disclosed")
            .to_string();
        assert!(detail.contains("9000-character budget"), "{detail}");
        assert!(!detail.contains("envelope reserve"), "{detail}");
    }

    /// The reserve is this server's arithmetic about its own default. A caller
    /// that names a ceiling gets that ceiling on every arm, so one call is
    /// bounded once, at a number the response names.
    #[test]
    fn an_explicit_budget_is_enforced_exactly_and_the_default_reserves_room() {
        let mut named = HashMap::new();
        named.insert("max_chars".to_string(), json!(6_000));
        let named = ResponseBudget::from_arguments(&named);
        assert_eq!(named.less_envelope_reserve().max_chars, 6_000);

        let defaulted = ResponseBudget::from_arguments(&HashMap::new());
        assert_eq!(
            defaulted.less_envelope_reserve().max_chars,
            RESPONSE_DEFAULT_MAX_CHARS - RESPONSE_ENVELOPE_RESERVE_CHARS
        );
    }

    /// The defect the v0.5.47 stranger run named twice in one session:
    /// `"affected_tests": []` shipped beside a `covering_tests: 16` that
    /// contradicted it, and the empty array won both times. `affected_tests` is
    /// the last bucket, so the ladder emptied it first, and a sibling
    /// `affected_tests_withheld: 15` sat right there and saved nobody.
    ///
    /// Every list the budget cuts now keeps an entry and publishes what it lost.
    #[test]
    fn a_budget_never_empties_a_list_it_cut() {
        const BUCKETS: [&str; 4] = [
            "affected_callers",
            "affected_dependents",
            "affected_contract_consumers",
            "affected_tests",
        ];
        let mut payload = impact_payload(40);
        let found: Vec<usize> = BUCKETS
            .iter()
            .map(|key| payload[*key].as_array().expect("bucket").len())
            .collect();
        assert!(
            found.iter().all(|count| *count > 0),
            "the fixture must fill every bucket or this proves nothing: {found:?}"
        );
        let budget = ResponseBudget {
            max_chars: 4_000,
            ..ResponseBudget::default()
        };
        let accounting = enforce(&mut payload, "impact_analysis", &budget).expect("budgeted");
        assert!(accounting.bounded, "the fixture must overflow: {payload}");

        let mut cut_any = false;
        for (key, before) in BUCKETS.iter().zip(found) {
            let kept = payload[*key].as_array().expect("bucket survives").len();
            assert!(
                kept > 0,
                "`{key}` was emptied by the budget, which reads as \"the walk found none\": \
                 {payload}"
            );
            if kept == before {
                assert!(
                    payload["elisions"].get(*key).is_none(),
                    "`{key}` lost nothing and must claim nothing: {payload}"
                );
                continue;
            }
            cut_any = true;
            let elision = &payload["elisions"][*key];
            assert_eq!(elision["kept"], json!(kept), "{payload}");
            assert_eq!(elision["elided"], json!(before - kept), "{payload}");
            assert_eq!(elision["total"], json!(before), "{payload}");
            assert_eq!(elision["reason"], json!(ELISION_REASON_BUDGET), "{payload}");
            assert_eq!(
                payload[format!("{key}_withheld")],
                json!(before - kept),
                "the older counter must still agree with the elision: {payload}"
            );
        }
        assert!(
            cut_any,
            "a budget this small must have cut something: {payload}"
        );
    }

    /// The other direction, which is what makes the first test worth anything: a
    /// list the walk genuinely found nothing for stays empty and claims no
    /// elision. Without this, "never empty" could be satisfied by inventing an
    /// entry, and an empty array would still mean two things.
    #[test]
    fn an_empty_list_stays_empty_and_claims_no_elision() {
        let mut payload = impact_payload(40);
        payload["affected_tests"] = json!([]);
        let budget = ResponseBudget {
            max_chars: 4_000,
            ..ResponseBudget::default()
        };
        enforce(&mut payload, "impact_analysis", &budget).expect("budgeted");
        assert_eq!(
            payload["affected_tests"],
            json!([]),
            "a walk that found none must still report none: {payload}"
        );
        assert!(
            payload["elisions"].get("affected_tests").is_none(),
            "nothing was withheld, so nothing may be claimed: {payload}"
        );
        assert!(
            payload.get("affected_tests_withheld").is_none(),
            "nothing was withheld: {payload}"
        );
    }

    /// The ceiling has to be a number a real MCP client accepts, and 400,000 was
    /// not: Claude Code caps one tool result at 25,000 tokens by default, and on
    /// the v0.5.47 candidate a caller who took the advertised ceiling at its word
    /// asked for 120,000, got 117,313 characters, and had the whole result thrown
    /// away. Responses of 50,000 and 55,000 characters in the same session came
    /// back whole.
    #[test]
    fn the_advertised_ceiling_is_one_a_client_accepts() {
        const REFUSED_BY_A_REAL_CLIENT: usize = 117_313;
        const ACCEPTED_BY_A_REAL_CLIENT: usize = 55_000;
        assert!(
            RESPONSE_MAX_MAX_CHARS < REFUSED_BY_A_REAL_CLIENT,
            "the ceiling advertises a size a client refused: {RESPONSE_MAX_MAX_CHARS}"
        );
        assert!(
            RESPONSE_MAX_MAX_CHARS >= ACCEPTED_BY_A_REAL_CLIENT,
            "the ceiling sits under a size a client already took: {RESPONSE_MAX_MAX_CHARS}"
        );
        assert!(
            RESPONSE_MIN_MAX_CHARS < RESPONSE_DEFAULT_MAX_CHARS
                && RESPONSE_DEFAULT_MAX_CHARS <= RESPONSE_MAX_MAX_CHARS,
            "the default must sit inside its own clamp"
        );
        // The old 30,000 default dropped 170 of 200 steps on the 783-entity store
        // the same run measured, and still withheld impact rows at 50,000.
        assert!(
            RESPONSE_DEFAULT_MAX_CHARS > 30_000,
            "the default is back at a size the measured store overflowed"
        );
    }

    /// A cut names the ceiling a caller may raise to, on the response that got
    /// cut. The raw daemon route carries no `_kin` envelope, so this in-band line
    /// is the only place that number reaches a caller there.
    #[test]
    fn a_cut_discloses_the_ceiling_a_caller_may_raise_to() {
        let mut payload = locate_payload(40, 900);
        let budget = ResponseBudget {
            max_chars: 4_000,
            ..ResponseBudget::default()
        };
        enforce(&mut payload, "semantic_locate", &budget).expect("budgeted");
        let remediation = payload["degradations"][0]["remediation"]
            .as_str()
            .expect("a cut was disclosed")
            .to_string();
        assert!(
            remediation.contains(&RESPONSE_MAX_MAX_CHARS.to_string()),
            "the response must name the ceiling it will serve: {remediation}"
        );
    }

    #[test]
    fn an_absent_key_is_never_reported_as_a_cut() {
        let mut payload = json!({
            "references": [ { "name": "a", "body": null }, { "name": "b" } ],
        });
        let accounting =
            enforce(&mut payload, "find_references", &ResponseBudget::default()).expect("budgeted");
        assert!(
            !accounting.bounded,
            "nothing was carried, so nothing was cut: {payload}"
        );
    }
}
