// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! One verdict per response (FIR-2463).
//!
//! A retrieval response used to carry up to three verdict-shaped claims that
//! were computed independently and could disagree with each other. The
//! `negative` object certified or refused an absence, `edge_coverage` reported
//! whether the graph could hold the edges the answer was read off, and
//! `_kin.completeness` reported `status`, `bound` and `counted.exact`. Which one
//! an agent acted on depended on which key it happened to read.
//!
//! The shape is not hypothetical. A shipped v0.5.42 `find_references` response
//! carried `completeness.status: "complete"`, `bound: "exact"`,
//! `counted.exact: true` and a note reading "the counts here are the whole set"
//! directly above `classes: {"imports": "absent", "references": "absent"}` and
//! `negative.safe_to_conclude_absent: false`. In the same session on the same
//! repository, `graph_neighborhood` walked the same two inbound edges and framed
//! them as `"complete"` with no `negative` object at all, because a non-empty
//! answer synthesizes none.
//!
//! ## The contract
//!
//! [`Verdict::compute`] is the one authority. Every block that publishes a
//! verdict-shaped claim is an INPUT to it, the most pessimistic input wins, and
//! certification requires every input that spoke to agree. The blocks keep
//! publishing their raw observations, because those are the evidence a reader
//! needs to act, but the fields a reader acts ON are projections of this one
//! verdict:
//!
//! - `negative.safe_to_conclude_absent` / `negative.trust` / `negative.advice`
//!   are built from the gap list this module contributes to, so they are correct
//!   by construction rather than patched afterwards.
//! - `_kin.completeness.bound`, `counted.exact` and `note` are capped by
//!   [`Verdict::project_onto_completeness`].
//! - `_kin.completeness.status`, `classes`, `decided_by` and `limits` stay raw
//!   observation. `status` answers "was the substrate whole", which is a
//!   different question from "can this answer be acted on", and collapsing the
//!   two would throw away the evidence rather than reconcile it.
//!
//! [`disagreements`] is the invariant that holds this together. It scans a fully
//! built response for any block whose verdict language contradicts
//! `_kin.verdict`, and it runs under `debug_assert!` on every annotated response
//! so a future block cannot reintroduce a second verdict silently.

use serde_json::{json, Map, Value};

use crate::envelope::Envelope;

/// Reserved key under `_kin` holding the single verdict for the response.
pub const VERDICT_KEY: &str = "verdict";

/// Wire words for a verdict state and for one input's reading.
const CERTIFIED: &str = "certified";
const INCONCLUSIVE: &str = "inconclusive";
const NOT_APPLICABLE: &str = "not_applicable";

/// Machine-stable label recorded in `_kin.completeness.limits` when the single
/// verdict, rather than this answer's own substrate reading, is what stopped the
/// counts being called whole.
const VERDICT_LIMIT: &str = "verdict_inconclusive";

/// The limiting factor a response bounded by the size budget carries.
const RESPONSE_BOUNDED_FACTOR: &str = "response_bounded: the response budget withheld part of \
                                       this answer, so its counts are a lower bound and its \
                                       absence claims are not authoritative";

/// One input's reading of the same answer.
enum Reading {
    /// The input observed nothing that stops this answer being acted on.
    Certified,
    /// The input refuses, and says why in the reason it carries.
    Inconclusive(String),
    /// The input has nothing to say about this response, which is different from
    /// saying it is fine. A silent input never certifies anything.
    Silent,
}

impl Reading {
    fn state(&self) -> &'static str {
        match self {
            Reading::Certified => CERTIFIED,
            Reading::Inconclusive(_) => INCONCLUSIVE,
            Reading::Silent => NOT_APPLICABLE,
        }
    }
}

/// The single verdict for one response, plus the inputs it was computed from.
pub struct Verdict {
    certified: bool,
    safe_to_conclude_absent: bool,
    limiting_factor: Option<String>,
    inputs: Map<String, Value>,
}

impl Verdict {
    /// Compute the response's one verdict, or `None` for a response no input
    /// spoke about (a mutation, a session call, anything that is not retrieval).
    ///
    /// `negative` is the already-built absence object when one was synthesized.
    /// It is an input rather than the authority: it exists only for an answer
    /// that came back empty, and the contradiction this module exists to end was
    /// found on a NON-empty answer whose only verdict-shaped claim was
    /// `completeness`.
    ///
    /// Certification requires every input that spoke to agree, and an input that
    /// stayed silent never contributes agreement. A response where no input
    /// spoke returns `None` rather than a certified verdict on no evidence.
    pub fn compute(
        tool: &str,
        payload: &Value,
        envelope: &Envelope,
        negative: Option<&Value>,
    ) -> Option<Self> {
        let makes_absence_claim = negative.is_some();
        let readings = [
            (
                "absence_gate",
                absence_gate_reading(tool, payload, negative),
            ),
            ("edge_coverage", edge_coverage_reading(tool, payload)),
            ("withheld_candidates", withheld_candidates_reading(payload)),
            ("degradations", degradations_reading(payload)),
            ("completeness", completeness_reading(envelope)),
        ];

        if readings
            .iter()
            .all(|(_, reading)| matches!(reading, Reading::Silent))
        {
            return None;
        }

        let limiting_factor = readings.iter().find_map(|(_, reading)| match reading {
            Reading::Inconclusive(reason) => Some(reason.clone()),
            _ => None,
        });
        let certified = limiting_factor.is_none();
        let inputs = readings
            .iter()
            .map(|(name, reading)| ((*name).to_string(), json!(reading.state())))
            .collect();

        Some(Verdict {
            certified,
            safe_to_conclude_absent: certified && makes_absence_claim,
            limiting_factor,
            inputs,
        })
    }

    /// Gaps this response carries that [`crate::negative::negative_for`] cannot
    /// observe on its own, in the order they should lead the composed reason.
    ///
    /// These are threaded INTO the absence object rather than patched onto it
    /// afterwards, so its `trust`, `trust_reason` and `advice` are one
    /// consistent sentence. Patching a built advice string is how a verdict and
    /// the reason a reader acts on come apart again.
    ///
    /// Only gaps the absence gates structurally cannot reach are listed here.
    /// Withheld same-name candidates are already disclosed as a payload
    /// degradation by every tool that withholds them today, and the absence gate
    /// consumes `degradations`, so repeating them would put the same fact in one
    /// reason twice.
    pub fn pre_negative_gaps(payload: &Value) -> Vec<String> {
        let mut gaps = Vec::new();
        if payload.get("truncated").and_then(Value::as_bool) == Some(true) {
            gaps.push(
                "answer_truncated: this answer stopped early and returned part of what it \
                 found, so its counts are a floor and an absence in it is a fact about where \
                 the walk stopped"
                    .to_string(),
            );
        }
        if withheld_candidate_count(payload) > 0 && !discloses_withheld_candidates(payload) {
            gaps.push(
                "withheld_candidates: same-name candidates were held out of the counts here, \
                 so the headline is a floor and the withheld rows may belong in it"
                    .to_string(),
            );
        }
        gaps
    }

    /// Cap the completeness signal's verdict-shaped fields at this verdict.
    ///
    /// Only ever downgrades. `bound`, `counted.exact` and `note` are what a
    /// reader acts on, so they follow the one verdict; `status`, `classes`,
    /// `decided_by` and `limits` are the observation the verdict was computed
    /// from and stay exactly as measured.
    pub fn project_onto_completeness(
        &self,
        completeness: &mut Option<crate::envelope::Completeness>,
    ) {
        if self.certified {
            return;
        }
        let Some(completeness) = completeness else {
            return;
        };
        completeness.bound = "at_least".to_string();
        if let Some(counted) = completeness.counted.as_mut().and_then(Value::as_object_mut) {
            counted.insert("exact".to_string(), json!(false));
        }
        if !completeness
            .limits
            .iter()
            .any(|limit| limit == VERDICT_LIMIT)
        {
            completeness.limits.push(VERDICT_LIMIT.to_string());
        }
        completeness.note = format!(
            "The counts here are a lower bound, because this response's one verdict is \
             inconclusive. Limiting factor: {}.",
            self.limiting_factor.as_deref().unwrap_or("unreported")
        );
    }

    /// Serialize for embedding under `_kin.verdict`.
    pub fn to_value(&self) -> Value {
        let note = if self.certified {
            "Every input that could qualify this answer agreed, so the counts here are the whole \
             set and an absence in it is authoritative."
                .to_string()
        } else {
            format!(
                "Treat this answer as a lower bound and do not act on an absence in it. Limiting \
                 factor: {}.",
                self.limiting_factor.as_deref().unwrap_or("unreported")
            )
        };
        json!({
            "state": if self.certified { CERTIFIED } else { INCONCLUSIVE },
            "safe_to_conclude_absent": self.safe_to_conclude_absent,
            "limiting_factor": self.limiting_factor.clone().map(Value::String).unwrap_or(Value::Null),
            "inputs": Value::Object(self.inputs.clone()),
            "note": note,
        })
    }
}

/// The absence gate's reading: the composed verdict
/// [`crate::negative::negative_for`] already reached, when it built one.
///
/// When it did not, the gate is run here against the same payload rather than
/// skipped. That is the whole point of computing this once: a non-empty answer
/// and a tool with no absence spec are exactly the routes that used to reach a
/// reader with no gate applied at all, and the missing dependency that stops an
/// absence being certified is the same missing dependency that makes a
/// non-empty answer a floor.
fn absence_gate_reading(tool: &str, payload: &Value, negative: Option<&Value>) -> Reading {
    if let Some(negative) = negative {
        return match negative
            .get("safe_to_conclude_absent")
            .and_then(Value::as_bool)
        {
            Some(true) => Reading::Certified,
            Some(false) => Reading::Inconclusive(
                negative
                    .get("trust_reason")
                    .and_then(Value::as_str)
                    .unwrap_or("the absence gate refused and reported no reason")
                    .to_string(),
            ),
            None => Reading::Silent,
        };
    }
    match crate::negative::absence_coverage_gap(tool, payload) {
        Some(gap) => Reading::Inconclusive(gap),
        None if crate::negative::declares_absence_dependency(tool, payload) => Reading::Certified,
        None => Reading::Silent,
    }
}

/// The raw `edge_coverage` observation's own reading, independent of whichever
/// route consumed it.
///
/// It repeats what the absence gate reads on the tools that declare edge
/// classes, and that repetition is deliberate: recording both as named inputs is
/// what makes the verdict auditable, and the two come apart exactly where the
/// contradiction lived. A tool that declares no edge class still publishes this
/// observation, and `reference_enrichment: "unsupported"` is a fact about what
/// the build can resolve that no coverage number can override.
fn edge_coverage_reading(tool: &str, payload: &Value) -> Reading {
    let Some(coverage) = payload
        .get(crate::edge_coverage::EDGE_COVERAGE_KEY)
        .and_then(Value::as_object)
    else {
        return Reading::Silent;
    };
    let language = coverage
        .get("language")
        .and_then(Value::as_str)
        .filter(|language| !language.trim().is_empty())
        .unwrap_or("an unreported language");

    if coverage.get("reference_enrichment").and_then(Value::as_str) == Some("unsupported") {
        return Reading::Inconclusive(format!(
            "reference_enrichment_unsupported: this build wires no language-server adapter for \
             {language}, so cross-file reference and override edges cannot exist for it at all"
        ));
    }
    if coverage.get("scope_entities").and_then(Value::as_u64) == Some(0) {
        return Reading::Inconclusive(format!(
            "absence_scope_empty: the graph holds no entity at all under the filter this query \
             applied for {language}"
        ));
    }
    if coverage.get("budget_exhausted").and_then(Value::as_bool) == Some(true) {
        return Reading::Inconclusive(format!(
            "edge_coverage_budget_exhausted: the coverage scan for {language} stopped before it \
             could establish what the graph holds"
        ));
    }

    let requested = crate::negative::absence_cross_file_classes(tool, payload);
    if requested.is_empty() {
        return Reading::Certified;
    }
    let states = coverage.get("classes").and_then(Value::as_object);
    let deciding = crate::negative::load_bearing_classes(&requested);
    let unhealthy: Vec<&str> = deciding
        .iter()
        .filter(|class| {
            states
                .and_then(|states| states.get(class.as_str()))
                .and_then(Value::as_str)
                != Some("present")
        })
        .map(String::as_str)
        .collect();
    if unhealthy.is_empty() {
        Reading::Certified
    } else {
        Reading::Inconclusive(format!(
            "cross_file_edges_not_present: the graph was not observed to hold cross-file {} \
             edges for {language}, so a use that reaches the target through {} could not have \
             been found",
            unhealthy.join(", "),
            unhealthy.join(", ")
        ))
    }
}

/// Same-name candidates this answer held out of its headline.
///
/// A withheld row is evidence the answer already has and did not count, which is
/// the one shape where the count and the payload beside it disagree about the
/// same repository. `find_references(HTTPAdapter.send)` on psf/requests answered
/// `total_upstream: 0` while carrying `Session.send` at `sessions.py:784` in
/// `candidates`, and a reader of the headline deletes code a reader of the array
/// keeps.
fn withheld_candidates_reading(payload: &Value) -> Reading {
    match withheld_candidate_count(payload) {
        0 => Reading::Certified,
        withheld => Reading::Inconclusive(format!(
            "withheld_candidates: {withheld} same-name candidate(s) are carried in `candidates` \
             and are not in the counts here, so the headline is a floor and each withheld row \
             may belong in it"
        )),
    }
}

/// This query's own reported degradations.
fn degradations_reading(payload: &Value) -> Reading {
    let labels = crate::negative::payload_degradation_labels(payload);
    if labels.is_empty() {
        Reading::Certified
    } else {
        Reading::Inconclusive(format!(
            "retrieval_degraded: this query reported degradations [{}], so it did not run at \
             full capability",
            labels.join(", ")
        ))
    }
}

/// The completeness signal's own reading of the substrate and the numbers.
fn completeness_reading(envelope: &Envelope) -> Reading {
    let Some(completeness) = &envelope.completeness else {
        return Reading::Silent;
    };
    if completeness.status != "complete" {
        return Reading::Inconclusive(format!(
            "substrate_{}: the coverage classes this answer depended on were not all observed \
             present ({})",
            completeness.status,
            completeness.decided_by.join(", ")
        ));
    }
    if completeness.bound != "exact" {
        return Reading::Inconclusive(
            "counts_are_a_floor: this answer's own accounting reports its numbers as a lower \
             bound"
                .to_string(),
        );
    }
    Reading::Certified
}

/// How many same-name candidates the payload held out of its counts, read from
/// the one number the withheld plumbing already publishes.
fn withheld_candidate_count(payload: &Value) -> u64 {
    payload
        .get("counts")
        .and_then(|counts| counts.get("receiver_name_candidates"))
        .and_then(Value::as_u64)
        .or_else(|| {
            payload
                .get("candidates")
                .and_then(Value::as_array)
                .map(|rows| rows.len() as u64)
        })
        .unwrap_or(0)
}

/// Whether the payload already names its withheld candidates as a degradation,
/// which the absence gate consumes on its own.
fn discloses_withheld_candidates(payload: &Value) -> bool {
    crate::negative::payload_degradation_labels(payload)
        .iter()
        .any(|label| label.ends_with(":receiver_name_candidates"))
}

/// Downgrade every verdict surface on an already-built response that the size
/// budget then shortened.
///
/// The budget runs after the verdict is serialized, so the cut cannot be known
/// when the verdict is computed. Downgrading only `_kin.completeness` here, as
/// this path used to, would leave `_kin.verdict` and `negative` certifying an
/// answer whose rows were removed on purpose.
pub fn mark_response_bounded(annotated: &mut Value) {
    if let Some(verdict) = annotated
        .get_mut(crate::envelope::ENVELOPE_KEY)
        .and_then(Value::as_object_mut)
        .and_then(|envelope| envelope.get_mut(VERDICT_KEY))
        .and_then(Value::as_object_mut)
    {
        verdict.insert("state".to_string(), json!(INCONCLUSIVE));
        verdict.insert("safe_to_conclude_absent".to_string(), json!(false));
        verdict.insert(
            "limiting_factor".to_string(),
            json!(RESPONSE_BOUNDED_FACTOR),
        );
        verdict.insert(
            "note".to_string(),
            json!(format!(
                "Treat this answer as a lower bound and do not act on an absence in it. Limiting \
                 factor: {RESPONSE_BOUNDED_FACTOR}."
            )),
        );
        if let Some(inputs) = verdict.get_mut("inputs").and_then(Value::as_object_mut) {
            inputs.insert("response_budget".to_string(), json!(INCONCLUSIVE));
        }
    }
    if let Some(negative) = annotated
        .get_mut(crate::negative::NEGATIVE_KEY)
        .and_then(Value::as_object_mut)
    {
        negative.insert("safe_to_conclude_absent".to_string(), json!(false));
        negative.insert("trust".to_string(), json!(INCONCLUSIVE));
        let reason = match negative.get("trust_reason").and_then(Value::as_str) {
            Some(existing) if !existing.is_empty() => {
                format!("{RESPONSE_BOUNDED_FACTOR}; {existing}")
            }
            _ => RESPONSE_BOUNDED_FACTOR.to_string(),
        };
        negative.insert("trust_reason".to_string(), json!(reason.clone()));
        if let Some(advice) = negative.get("advice").and_then(Value::as_str) {
            let head = advice.split(". Limiting factor:").next().unwrap_or(advice);
            negative.insert(
                "advice".to_string(),
                json!(format!("{head}. Limiting factor: {reason}")),
            );
        }
    }
}

/// Every way a built response contradicts its own single verdict, as one message
/// per disagreement.
///
/// This is the guard that keeps the collapse from being undone one block at a
/// time. It reads the fully built response, so it sees what a client sees rather
/// than what any producer intended, and an empty result is the only shape that
/// may ship.
///
/// Only fields a reader ACTS on are checked. `_kin.completeness.status` and
/// `classes` are raw observation and may legitimately read `complete` and
/// `present` under an inconclusive verdict, because the substrate being whole is
/// not the same claim as the answer being whole.
pub fn disagreements(response: &Value) -> Vec<String> {
    let Some(verdict) = response
        .get(crate::envelope::ENVELOPE_KEY)
        .and_then(|envelope| envelope.get(VERDICT_KEY))
    else {
        return Vec::new();
    };
    let certified = verdict.get("state").and_then(Value::as_str) == Some(CERTIFIED);
    let verdict_absent = verdict
        .get("safe_to_conclude_absent")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut found = Vec::new();

    if let Some(negative) = response.get(crate::negative::NEGATIVE_KEY) {
        let negative_absent = negative
            .get("safe_to_conclude_absent")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if negative_absent != verdict_absent {
            found.push(format!(
                "negative.safe_to_conclude_absent is {negative_absent} while \
                 _kin.verdict.safe_to_conclude_absent is {verdict_absent}"
            ));
        }
        if negative.get("trust").and_then(Value::as_str) == Some("authoritative") && !certified {
            found.push(
                "negative.trust reads authoritative under an inconclusive _kin.verdict".to_string(),
            );
        }
        if let Some(advice) = negative.get("advice").and_then(Value::as_str) {
            if advice.contains("Absence is authoritative") && !certified {
                found.push(
                    "negative.advice certifies an absence under an inconclusive _kin.verdict"
                        .to_string(),
                );
            }
        }
    }

    if let Some(completeness) = response
        .get(crate::envelope::ENVELOPE_KEY)
        .and_then(|envelope| envelope.get("completeness"))
    {
        if completeness.get("bound").and_then(Value::as_str) == Some("exact") && !certified {
            found.push(
                "_kin.completeness.bound reads exact under an inconclusive _kin.verdict"
                    .to_string(),
            );
        }
        if completeness
            .get("counted")
            .and_then(|counted| counted.get("exact"))
            .and_then(Value::as_bool)
            == Some(true)
            && !certified
        {
            found.push(
                "_kin.completeness.counted.exact is true under an inconclusive _kin.verdict"
                    .to_string(),
            );
        }
        if let Some(note) = completeness.get("note").and_then(Value::as_str) {
            if note.contains("the whole set") && !certified {
                found.push(
                    "_kin.completeness.note claims the whole set under an inconclusive \
                     _kin.verdict"
                        .to_string(),
                );
            }
        }
    }

    found.extend(headline_count_disagreements(response));
    found
}

/// Where a headline count a reader acts on contradicts evidence the same
/// response is holding.
///
/// The count and the withheld rows are one accounting with one source, so the
/// three places it surfaces have to carry the same number. A `total_upstream` of
/// zero beside a populated `candidates` array is the exact shape that made a
/// reader delete working code, and it may not ship without
/// `unconfirmed_candidates` naming the held rows at the count.
fn headline_count_disagreements(response: &Value) -> Vec<String> {
    let Some(candidates) = response.get("candidates").and_then(Value::as_array) else {
        return Vec::new();
    };
    let withheld = candidates.len() as u64;
    if withheld == 0 {
        return Vec::new();
    }
    let mut found = Vec::new();
    match response
        .get("unconfirmed_candidates")
        .and_then(Value::as_u64)
    {
        None => found.push(format!(
            "the response carries {withheld} candidate row(s) and no unconfirmed_candidates \
             beside its headline count"
        )),
        Some(reported) if reported != withheld => found.push(format!(
            "unconfirmed_candidates reads {reported} against {withheld} candidate row(s)"
        )),
        Some(_) => {}
    }
    if let Some(counted) = response
        .get("counts")
        .and_then(|counts| counts.get("receiver_name_candidates"))
        .and_then(Value::as_u64)
    {
        if counted != withheld {
            found.push(format!(
                "counts.receiver_name_candidates reads {counted} against {withheld} candidate \
                 row(s)"
            ));
        }
    }
    if let Some(reported) = response
        .get(crate::envelope::ENVELOPE_KEY)
        .and_then(|envelope| envelope.get("completeness"))
        .and_then(|completeness| completeness.get("counted"))
        .and_then(|counted| counted.get("withheld_candidates"))
        .and_then(Value::as_u64)
    {
        if reported != withheld {
            found.push(format!(
                "_kin.completeness.counted.withheld_candidates reads {reported} against \
                 {withheld} candidate row(s)"
            ));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A response whose blocks all agree with a certified verdict.
    fn agreeing_response() -> Value {
        json!({
            "total_upstream": 2,
            "unconfirmed_candidates": 0,
            "candidates": [],
            "_kin": {
                "verdict": {
                    "state": CERTIFIED,
                    "safe_to_conclude_absent": true,
                    "limiting_factor": Value::Null,
                },
                "completeness": {
                    "status": "complete",
                    "bound": "exact",
                    "counted": {"reported": 2, "exact": true},
                    "note": "the counts here are the whole set.",
                },
            },
            "negative": {
                "safe_to_conclude_absent": true,
                "trust": "authoritative",
                "advice": "Absence is authoritative: safe to treat the target as genuinely absent/unused.",
            },
        })
    }

    /// The scanner must be able to say "no disagreement", or every assertion
    /// built on it passes for the wrong reason.
    #[test]
    fn an_agreeing_response_reports_no_disagreement() {
        assert!(
            disagreements(&agreeing_response()).is_empty(),
            "{:?}",
            disagreements(&agreeing_response())
        );
    }

    /// A response with no verdict at all is not a disagreement: mutations,
    /// session calls and everything else that is not retrieval carry none.
    #[test]
    fn a_response_without_a_verdict_is_not_scanned() {
        assert!(disagreements(&json!({"committed": true})).is_empty());
    }

    /// FIR-2463 case (c). The old two-verdict shape, verbatim from the shipped
    /// v0.5.42 payload the stranger quoted: `completeness` calling an answer
    /// complete, exact and "the whole set" while `negative` on the same object
    /// refuses to certify it. Forcing that shape back has to be caught at every
    /// field a reader acts on, not just the first.
    #[test]
    fn the_old_two_verdict_shape_cannot_serialize() {
        let mut response = agreeing_response();
        response["_kin"]["verdict"]["state"] = json!(INCONCLUSIVE);
        response["_kin"]["verdict"]["safe_to_conclude_absent"] = json!(false);

        let found = disagreements(&response);
        for expected in [
            "negative.safe_to_conclude_absent is true while _kin.verdict.safe_to_conclude_absent \
             is false",
            "negative.trust reads authoritative under an inconclusive _kin.verdict",
            "negative.advice certifies an absence under an inconclusive _kin.verdict",
            "_kin.completeness.bound reads exact under an inconclusive _kin.verdict",
            "_kin.completeness.counted.exact is true under an inconclusive _kin.verdict",
            "_kin.completeness.note claims the whole set under an inconclusive _kin.verdict",
        ] {
            assert!(
                found.iter().any(|message| message == expected),
                "the scanner missed `{expected}`: {found:?}"
            );
        }
    }

    /// The headline-count half of the same invariant. A zero beside a populated
    /// `candidates` array may not ship without `unconfirmed_candidates` naming
    /// the held rows at the count.
    #[test]
    fn a_headline_that_hides_its_held_rows_cannot_serialize() {
        let mut response = agreeing_response();
        response["total_upstream"] = json!(0);
        response["candidates"] = json!([{"name": "Session.send", "reference_lines": [784]}]);
        response
            .as_object_mut()
            .unwrap()
            .remove("unconfirmed_candidates");

        let missing = disagreements(&response);
        assert!(
            missing.iter().any(|message| message
                == "the response carries 1 candidate row(s) and no unconfirmed_candidates beside \
                    its headline count"),
            "{missing:?}"
        );

        // Present but wrong is caught too, at each of the three placements the
        // one withheld number surfaces at.
        response["unconfirmed_candidates"] = json!(0);
        response["counts"] = json!({"receiver_name_candidates": 0});
        response["_kin"]["completeness"]["counted"]["withheld_candidates"] = json!(4);
        let skewed = disagreements(&response);
        for expected in [
            "unconfirmed_candidates reads 0 against 1 candidate row(s)",
            "counts.receiver_name_candidates reads 0 against 1 candidate row(s)",
            "_kin.completeness.counted.withheld_candidates reads 4 against 1 candidate row(s)",
        ] {
            assert!(
                skewed.iter().any(|message| message == expected),
                "the scanner missed `{expected}`: {skewed:?}"
            );
        }

        // And the agreeing form clears, so the check is not simply always-on.
        response["unconfirmed_candidates"] = json!(1);
        response["counts"] = json!({"receiver_name_candidates": 1});
        response["_kin"]["completeness"]["counted"]["withheld_candidates"] = json!(1);
        assert!(
            headline_count_disagreements(&response).is_empty(),
            "{:?}",
            headline_count_disagreements(&response)
        );
    }

    /// The substrate reading stays raw. `status: "complete"` and a `classes` map
    /// are the evidence the verdict was computed FROM, so an inconclusive
    /// verdict beside them is the intended shape rather than a contradiction.
    /// Scanning them would force the fix to throw the evidence away.
    #[test]
    fn a_raw_substrate_observation_is_not_a_competing_verdict() {
        let mut response = agreeing_response();
        response["_kin"]["verdict"]["state"] = json!(INCONCLUSIVE);
        response["_kin"]["verdict"]["safe_to_conclude_absent"] = json!(false);
        response["negative"] = json!({
            "safe_to_conclude_absent": false,
            "trust": INCONCLUSIVE,
            "advice": "Absence is NOT authoritative: do not conclude the target is unused.",
        });
        response["_kin"]["completeness"] = json!({
            "status": "complete",
            "classes": {"calls": "present", "imports": "absent"},
            "bound": "at_least",
            "counted": {"reported": 2, "exact": false},
            "note": "The counts here are a lower bound.",
        });
        assert!(
            disagreements(&response).is_empty(),
            "{:?}",
            disagreements(&response)
        );
    }

    /// The budget path downgrades every verdict surface together. Leaving
    /// `negative` or `_kin.verdict` certifying an answer whose rows were removed
    /// is the same defect arriving through the one path that removes answers on
    /// purpose.
    #[test]
    fn a_budget_cut_downgrades_the_verdict_and_the_absence_together() {
        let mut response = agreeing_response();
        response["negative"]["trust_reason"] = json!("structural_authoritative");
        mark_response_bounded(&mut response);

        assert_eq!(response["_kin"]["verdict"]["state"], json!(INCONCLUSIVE));
        assert_eq!(
            response["_kin"]["verdict"]["safe_to_conclude_absent"],
            json!(false)
        );
        assert_eq!(
            response["negative"]["safe_to_conclude_absent"],
            json!(false)
        );
        assert_eq!(response["negative"]["trust"], json!(INCONCLUSIVE));
        assert!(response["negative"]["trust_reason"]
            .as_str()
            .unwrap()
            .starts_with("response_bounded"));
        assert!(response["negative"]["advice"]
            .as_str()
            .unwrap()
            .contains("Limiting factor: response_bounded"));
    }
}
