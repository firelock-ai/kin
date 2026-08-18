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
/// Sized against **Claude Code**, the primary agent client for this server: it
/// rejects a tool result above roughly 25,000 tokens and writes it to a file
/// instead. JSON-wrapped source runs around 3.5 characters per token, so the
/// refusal threshold sits near 87,000 characters, which is why the two measured
/// payloads above (80,571 and 79,278) both tripped it while sitting inside the
/// 80,000-character trace budget that was supposed to prevent exactly this.
///
/// 30,000 characters is roughly 8,500 tokens: about a third of that ceiling. The
/// margin is deliberate and is not a guess about tokenization. A response is
/// counted by the client after its own JSON-RPC framing, an agent typically
/// holds several tool results in one context window, and a budget chosen to
/// *just* fit one client's limit becomes the next overflow the moment any client
/// counts slightly differently. A caller with a larger window raises it per call
/// with `max_chars`.
pub const RESPONSE_DEFAULT_MAX_CHARS: usize = 30_000;

/// Floor for a caller-supplied budget. Below this the envelope and the
/// disclosure alone do not fit, so a smaller number could only be honoured by
/// returning nothing.
pub const RESPONSE_MIN_MAX_CHARS: usize = 2_000;

/// Ceiling for a caller-supplied budget. A caller with a larger window may raise
/// the bound, but not to unbounded: the daemon serving this has other callers,
/// and a response nothing can read is not worth building.
pub const RESPONSE_MAX_MAX_CHARS: usize = 400_000;

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
}

impl Default for ResponseBudget {
    fn default() -> Self {
        Self {
            max_chars: RESPONSE_DEFAULT_MAX_CHARS,
            compact: true,
            explicit_max_chars: false,
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
        Self {
            max_chars: self
                .max_chars
                .saturating_sub(RESPONSE_ENVELOPE_RESERVE_CHARS)
                .max(RESPONSE_MIN_MAX_CHARS),
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
            narrow_param: "limit",
        },
        "semantic_search" => ResponseShape {
            collections: &["results"],
            body_keys: &["doc_summary"],
            explain_keys: &[],
            top_explain_keys: &[],
            duplicate_keys: &[],
            narrow_param: "limit",
        },
        "trace_data_flow" => ResponseShape {
            collections: &["chain"],
            body_keys: &["body"],
            explain_keys: &[],
            top_explain_keys: &[],
            duplicate_keys: &[],
            narrow_param: "depth",
        },
        "get_context_pack" | "trace_computation" => ResponseShape {
            collections: &["dependencies", "transitive_deps", "tests", "contracts"],
            body_keys: &["body"],
            explain_keys: &["projection"],
            top_explain_keys: &[],
            duplicate_keys: &[],
            narrow_param: "depth",
        },
        "find_references" => ResponseShape {
            collections: &["references"],
            body_keys: &["body", "snippet"],
            explain_keys: &[],
            top_explain_keys: &[],
            duplicate_keys: &[],
            narrow_param: "relation_kinds",
        },
        "graph_neighborhood" => ResponseShape {
            collections: &["entities", "relations"],
            body_keys: &["body", "signature"],
            explain_keys: &[],
            top_explain_keys: &[],
            duplicate_keys: &[],
            narrow_param: "depth",
        },
        "impact_analysis" => ResponseShape {
            collections: &["impacted_entities", "affected_tests"],
            body_keys: &["body"],
            explain_keys: &[],
            top_explain_keys: &[],
            duplicate_keys: &[],
            narrow_param: "depth",
        },
        "find_dead_code_seeded" => ResponseShape {
            collections: &["candidates"],
            body_keys: &["body"],
            explain_keys: &[],
            top_explain_keys: &[],
            duplicate_keys: &[],
            narrow_param: "limit",
        },
        "bulk_check_references" => ResponseShape {
            collections: &["results"],
            body_keys: &[],
            explain_keys: &[],
            top_explain_keys: &[],
            duplicate_keys: &[],
            narrow_param: "entity_ids",
        },
        _ => return None,
    };
    Some(shape)
}

/// Whether this tool's response is governed by the budget.
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
        if measure(payload) <= target {
            disclose(payload, budget.max_chars, &cuts, &remediations);
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
            disclose(payload, budget.max_chars, &cuts, &remediations);
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
            disclose(payload, budget.max_chars, &cuts, &remediations);
            return Some(accounting);
        }
    }

    // Last resort: withhold hits, from the tail of the least important array
    // first. This is the only stage that removes an answer, so it reports the
    // count withheld and the parameter that recovers them.
    //
    // The first collection is the primary one and always keeps at least one
    // entry. A bound is not a refusal: a caller handed an empty ranking cannot
    // tell it from "nothing matched", which is the one reading a size cut must
    // never produce.
    let primary = shape.collections.first().copied();
    let mut withheld_any = false;
    for key in shape.collections.iter().rev() {
        let floor = usize::from(Some(*key) == primary);
        let withheld = trim_collection(payload, key, target, floor);
        if withheld > 0 {
            accounting.bounded = true;
            withheld_any = true;
            cuts.push(format!(
                "{withheld} entries withheld from the end of `{key}`"
            ));
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

    disclose(payload, budget.max_chars, &cuts, &remediations);
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
fn disclose(payload: &mut Value, max_chars: usize, cuts: &[String], remediations: &[String]) {
    if cuts.is_empty() {
        return;
    }
    let mut remediation = remediations.join("; ");
    if !remediation.is_empty() {
        remediation.push_str("; ");
    }
    remediation
        .push_str("or raise max_chars if the caller's own result limit accepts a larger payload");
    let entry = json!({
        "component": "response_budget",
        "reason": "response_bounded",
        "detail": format!(
            "the response exceeded its {max_chars}-character budget, so {}",
            cuts.join("; ")
        ),
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
                        "matched_variants": ["a", "b", "c"],
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
