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

/// What separates two clauses when the factor is rendered as one sentence.
///
/// The rendering only. Nothing parses it back: clauses are carried as a list
/// from the reading that produced them to the single join at serialization,
/// because this string is also ordinary punctuation inside a clause's prose and
/// a boundary inferred from it is a boundary a human never chose.
pub(crate) const CLAUSE_SEPARATOR: &str = "; ";

/// The limiting factor a response bounded by the size budget carries.
const RESPONSE_BOUNDED_FACTOR: &str = "response_bounded: the response budget withheld part of \
                                       this answer, so its counts are a lower bound and its \
                                       absence claims are not authoritative";

/// The one sentence a reader acts on, carrying every reason the inputs gave.
///
/// The most pessimistic input decides the STATE; it does not make the other
/// inputs vanish. When the coverage reading and the run's own degradations both
/// refused, a factor that kept only the first sent a reader to fix the edge gap
/// and never told them the embedding worker had died, which is a second thing
/// wrong with the same answer (FIR-2672). So the factor is one sentence of
/// clauses, one per reason, in the readings' order: the absence gate's own
/// composition first, then the coverage observation, withheld rows, the run's
/// degradations and the completeness signal. Each clause is `label: text` and a
/// label appears once, because the absence gate already composes the class gap
/// and the degradations that the later readings repeat as named inputs.
fn compose_limiting_factor(readings: &[(&str, Reading)]) -> Option<String> {
    Some(compose_clauses(readings))
        .filter(|clauses| !clauses.is_empty())
        .map(|clauses| clauses.join(CLAUSE_SEPARATOR))
}

/// The factor's clauses, deduplicated by label, in the readings' order.
///
/// Each refusing reading hands over the clauses it built. Nothing is split back
/// out of a joined string here, which is the whole change: the separator is also
/// ordinary punctuation inside a clause's prose, so a boundary parsed from it is
/// a boundary no author chose. `cross_file_edges_absent` and
/// `name_filter_narrowed_to_zero` both carry one, and each used to arrive as a
/// labelled clause plus a bare fragment that reached the reader with no label at
/// all.
fn compose_clauses(readings: &[(&str, Reading)]) -> Vec<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut clauses: Vec<String> = Vec::new();
    for (_, reading) in readings {
        let Reading::Inconclusive(reasons) = reading else {
            continue;
        };
        for clause in reasons.iter().map(|clause| clause.trim()) {
            if clause.is_empty() {
                continue;
            }
            let label = clause_label(clause);
            if labels.contains(&label) {
                continue;
            }
            labels.push(label);
            clauses.push(clause.to_string());
        }
    }
    clauses
}

/// The gap a clause names, which is the text before its first colon.
///
/// Two readings that notice the same gap say it once (FIR-2672), and this is
/// how they are recognised as the same. It is still inferred rather than stated,
/// which is a known limit recorded on FIR-2723: nothing enforces that two
/// readings sharing a prefix describe the same gap. What it no longer does is
/// invent clause boundaries, so a label is always a label an author wrote.
fn clause_label(clause: &str) -> String {
    clause
        .split(':')
        .next()
        .unwrap_or(clause)
        .trim()
        .to_string()
}

/// What this response says about absence, which is not what it says about trust.
///
/// One bool answered two questions and a reader could not branch on it
/// (FIR-2673 finding 1). `safe_to_conclude_absent: false` meant either "this
/// absence is not trustworthy" or "absence is not a concept for this call", and
/// the second is the common case: a qualifier rides every retrieval answer, so
/// the field is false on every answer that returned rows. A stranger read one
/// `list_file_entities` response carrying `state: certified`, a note saying an
/// absence in it is authoritative, and `safe_to_conclude_absent: false`, all in
/// one object, and reported that the boolean gives the opposite of the verdict.
///
/// Three states, because there were always three cases.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum AbsenceClaim {
    /// This answer returned rows and asserts no absence, so there is nothing to
    /// conclude absent and nothing to distrust. The case that used to be
    /// indistinguishable from a refusal.
    NotApplicable,
    /// An absence is claimed and every input that could qualify it agreed.
    Authoritative,
    /// An absence is claimed and at least one input refuses, so it may not be
    /// acted on.
    NotAuthoritative,
}

impl AbsenceClaim {
    fn as_str(self) -> &'static str {
        match self {
            AbsenceClaim::NotApplicable => "not_applicable",
            AbsenceClaim::Authoritative => "authoritative",
            AbsenceClaim::NotAuthoritative => "not_authoritative",
        }
    }

    /// The legacy boolean, defined FROM the tri-state so the two can never
    /// disagree.
    ///
    /// Kept because ten shipped tool descriptions name the field, `kin-bench`
    /// branches on its negative-side twin, and two kinlab launch-copy strings
    /// and a published blog post describe it. It is bit-identical to what
    /// `certified && makes_absence_claim` produced.
    fn legacy_bool(self) -> bool {
        matches!(self, AbsenceClaim::Authoritative)
    }
}

/// One input's reading of the same answer.
enum Reading {
    /// The input observed nothing that stops this answer being acted on.
    Certified,
    /// The input refuses, and says why in the clauses it carries.
    ///
    /// A list rather than one string, so the factor is never parsed back out of
    /// a joined sentence. Most readings build exactly one clause; the absence
    /// gate composes several, and it is the one whose prose contains the same
    /// separator the renderer uses.
    Inconclusive(Vec<String>),
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
    absence_claim: AbsenceClaim,
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
        // A qualifier now rides every retrieval answer, so its presence no longer
        // means an absence is being claimed. The object says which it is, and
        // reading that rather than its existence is what keeps
        // `safe_to_conclude_absent` false on a populated answer.
        let makes_absence_claim = negative.is_some_and(|negative| {
            negative.get("interpretation").and_then(Value::as_str) != Some("qualified_answer")
        });
        let readings = [
            (
                "absence_gate",
                absence_gate_reading(tool, payload, negative),
            ),
            ("edge_coverage", edge_coverage_reading(tool, payload)),
            ("withheld_candidates", withheld_candidates_reading(payload)),
            ("degradations", degradations_reading(payload)),
            ("cross_repo", cross_repo_reading(tool, payload)),
            ("completeness", completeness_reading(envelope)),
            ("graph_freshness", graph_freshness_reading(envelope)),
        ];

        if readings
            .iter()
            .all(|(_, reading)| matches!(reading, Reading::Silent))
        {
            return None;
        }

        let limiting_factor = compose_limiting_factor(&readings);
        let certified = limiting_factor.is_none();
        let inputs = readings
            .iter()
            .map(|(name, reading)| ((*name).to_string(), json!(reading.state())))
            .collect();

        Some(Verdict {
            certified,
            absence_claim: match (makes_absence_claim, certified) {
                (false, _) => AbsenceClaim::NotApplicable,
                (true, true) => AbsenceClaim::Authoritative,
                (true, false) => AbsenceClaim::NotAuthoritative,
            },
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
        if withheld_candidate_count(payload).is_some_and(|withheld| withheld > 0)
            && !discloses_withheld_candidates(payload)
        {
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
    /// The qualifiers that stop the `edge_coverage` block licensing a
    /// certification on its own, named by the input that limits it.
    ///
    /// The block reports what a scan observed. It does not, and must not, report
    /// whether the answer around it can be trusted as whole, and a reader with
    /// only the block in hand cannot tell those apart: "every requested class is
    /// present" and "this answer's completeness is unknown" are both true at
    /// once, and the block renders only the first. A suite reading it alone
    /// therefore graded it as certifying beside a completeness that refused, and
    /// that is one response with two verdicts.
    ///
    /// This never re-derives another block's state. It reads the states this
    /// verdict already computed, which is why it lives here: `compute` is the
    /// one place holding every input, so the block's self-presentation and the
    /// verdict cannot drift. An empty list means the block licenses on its own.
    ///
    /// The class states themselves are left alone. A class that is present IS
    /// present, and reporting it otherwise to settle a disagreement would make a
    /// true fact read false, which is the failure this envelope exists to stop.
    /// The list is DERIVED from `self.inputs` rather than written out, because
    /// "every input except `edge_coverage`" spelled as four names is only
    /// correct until a fifth arrives. A name this function has never heard of
    /// yields a shorter list, not an error, so the block would go on presenting
    /// itself as licensing on its own while a reading nobody enumerated here
    /// refused. That is the edge-class trap in its other form: the hazard is not
    /// a consumer that counts a class, it is a producer that enumerates the
    /// classes it knows.
    ///
    /// Sorted so the stamp is byte-stable. `Map` is a `BTreeMap` unless
    /// serde_json's `preserve_order` is enabled, and a wire field's order should
    /// not depend on a feature flag in a transitive dependency.
    pub fn edge_coverage_limits(&self) -> Vec<String> {
        if self.inputs.get("edge_coverage").and_then(Value::as_str) != Some(CERTIFIED) {
            // The block already qualifies itself; nothing to add.
            return Vec::new();
        }
        let mut limits: Vec<String> = self
            .inputs
            .iter()
            .filter(|(name, state)| {
                name.as_str() != "edge_coverage" && state.as_str() == Some(INCONCLUSIVE)
            })
            .map(|(name, _)| format!("{name}:inconclusive"))
            .collect();
        limits.sort();
        limits
    }

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
        // `status` follows the verdict too. It reads as a claim that the answer
        // is whole, whatever it was derived from, and the stranger's report named
        // it first: `status: "complete"` sat directly above a `classes` map
        // marking two of three entries absent, and above a `negative` refusing
        // the same zero. The evidence it was computed from is not lost, because
        // `classes`, `decided_by` and `limits` are published unchanged beside it;
        // what changes is that the one-word summary can no longer say "whole"
        // while the response's verdict says otherwise.
        //
        // `partial` when something was actually observed absent, `unknown`
        // otherwise, because a verdict refused for a reason no class captures is
        // not evidence that a class was missing.
        completeness.status = if completeness
            .classes
            .values()
            .any(|state| matches!(state.as_str(), Some("absent") | Some("unproduced")))
        {
            "partial".to_string()
        } else {
            "unknown".to_string()
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
        // The note says the same thing the tri-state says, because it used to
        // say something else. It promised "an absence in it is authoritative"
        // on `certified` alone, so a caller whose answer carried five rows and
        // claimed no absence read that promise beside a `false` flag in the
        // same object, which is the contradiction FIR-2673 opens with. Each
        // case now gets the sentence that is true for it.
        let note = match (self.certified, self.absence_claim) {
            (true, AbsenceClaim::NotApplicable) => "Every input that could qualify this answer \
                 agreed, so the counts here are the whole set. This answer returned rows and \
                 claims no absence, so there is no absence in it to conclude anything from."
                .to_string(),
            (true, _) => "Every input that could qualify this answer agreed, so the counts here \
                 are the whole set and an absence in it is authoritative."
                .to_string(),
            (false, AbsenceClaim::NotApplicable) => format!(
                "Treat this answer as a lower bound. It returned rows and claims no absence, so \
                 the limit is on how many, not on whether something is missing. Limiting factor: \
                 {}.",
                self.limiting_factor.as_deref().unwrap_or("unreported")
            ),
            (false, _) => format!(
                "Treat this answer as a lower bound and do not act on an absence in it. Limiting \
                 factor: {}.",
                self.limiting_factor.as_deref().unwrap_or("unreported")
            ),
        };
        json!({
            "state": if self.certified { CERTIFIED } else { INCONCLUSIVE },
            "absence_claim": self.absence_claim.as_str(),
            "safe_to_conclude_absent": self.absence_claim.legacy_bool(),
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
        // `trust`, not `safe_to_conclude_absent`. The two answer different
        // questions and only the first is this response's verdict: a populated
        // answer sets `safe_to_conclude_absent` false because it claims no
        // absence, and reading that as the gate refusing made every answer with
        // rows inconclusive on its own success.
        return match negative.get("trust").and_then(Value::as_str) {
            Some("authoritative") => Reading::Certified,
            // `trust_reason` arrives as one string off the wire, and it is a
            // JOIN of clauses: `push_gap` builds it by repeated
            // `format!("{trust_reason}; {gap}")` across seven call sites. So it
            // is split back into clauses here, and that is NOT the boundary
            // inference this change removed elsewhere.
            //
            // The difference is which side owns the string. Splitting a factor
            // Kin had just joined itself was inventing a boundary; splitting a
            // wire string that IS a join recovers one, and it is safe now
            // because no clause carries the separator, which
            // `no_clause_carries_the_separator_that_divides_clauses` asserts on
            // the producer.
            //
            // Taking it as one clause instead was a real regression, caught by
            // the `two_reasons` acceptance check on a live payload rather than
            // by any unit test: `trust_reason` carries a `retrieval_degraded`
            // clause of its own, and as one opaque blob it stopped deduplicating
            // against the `degradations` reading's, so one answer named that gap
            // twice. The dedupe was doing real work on this path.
            Some(_) => Reading::Inconclusive(
                negative
                    .get("trust_reason")
                    .and_then(Value::as_str)
                    .unwrap_or("the absence gate refused and reported no reason")
                    .split(CLAUSE_SEPARATOR)
                    .map(str::trim)
                    .filter(|clause| !clause.is_empty())
                    .map(str::to_string)
                    .collect(),
            ),
            None => Reading::Silent,
        };
    }
    // The clauses, never the joined rendering. This is the path the probe on
    // FIR-2723 caught: `cross_file_edges_absent`'s text carries a semicolon, so
    // joining here and splitting in the composer cut it into a labelled clause
    // and a bare fragment that reached the reader with no label at all.
    let clauses = crate::negative::absence_coverage_clauses(tool, payload);
    if !clauses.is_empty() {
        return Reading::Inconclusive(clauses);
    }
    if crate::negative::declares_absence_dependency(tool, payload) {
        return Reading::Certified;
    }
    Reading::Silent
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

    // The same reading [`crate::negative::absence_coverage_gap`] takes, on
    // purpose. `available` is the only enrichment state that licenses a
    // certification; every other state means nothing established that this host
    // can produce reference edges for the language, and two inputs that read one
    // observation differently are the disagreement this module exists to end.
    match coverage
        .get("reference_enrichment")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
    {
        "available" => {}
        "unsupported" => {
            return Reading::Inconclusive(vec![format!(
                "reference_enrichment_unsupported: this build wires no language-server adapter \
                 for {language}, so cross-file reference and override edges cannot exist for it \
                 at all"
            )])
        }
        "no_language_server" => {
            return Reading::Inconclusive(vec![format!(
                "reference_enrichment_no_language_server: an adapter is wired for {language} but \
                 no language server for it is installed on this host"
            )])
        }
        _ => {}
    }
    if coverage.get("scope_entities").and_then(Value::as_u64) == Some(0) {
        return Reading::Inconclusive(vec![format!(
            "absence_scope_empty: the graph holds no entity at all under the filter this query \
             applied for {language}"
        )]);
    }
    if coverage.get("budget_exhausted").and_then(Value::as_bool) == Some(true) {
        return Reading::Inconclusive(vec![format!(
            "edge_coverage_budget_exhausted: the coverage scan for {language} stopped before it \
             could establish what the graph holds"
        )]);
    }

    let requested = crate::negative::absence_cross_file_classes(tool, payload);
    let states = coverage.get("classes").and_then(Value::as_object);
    if requested.is_empty() {
        // FIR-2496. This input used to answer `certified` for any observation
        // that named no class to check, which is every observation a tool
        // traversing no edge publishes. That is agreement inferred from silence:
        // the shipped verdict block read `"inputs": {"edge_coverage":
        // "certified"}` over `"classes": {}` on the two searches that were wrong
        // and on the one that was right, with nothing separating them. An
        // observation that measured nothing licenses nothing, and the absence
        // gate leads with the sharper wording when both refuse.
        //
        // On a real language only, matching the gate: an answer that resolved
        // none has no language's coverage to be missing, and it carries its own
        // sharper reason. Read from the gate's own function so the input's
        // reading and the refusal can never disagree about one observation.
        if crate::negative::coverage_classes_unmeasured(coverage, &requested) {
            return Reading::Inconclusive(vec![format!(
                "absence_coverage_unmeasured: this answer measured no coverage class for \
                 {language}, so nothing established what the extractor admitted for it"
            )]);
        }
        return Reading::Certified;
    }
    // Every requested class, and the most specific reason first (FIR-2672). A
    // class this answer could not have read is a class its counts cannot be
    // whole over, whatever kept it from being read, so the reading refuses on
    // any state but `present` and says which state it was.
    let deciding = crate::negative::load_bearing_classes(&requested);
    let state_of = |class: &String| {
        states
            .and_then(|states| states.get(class.as_str()))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    };
    let in_state = |wanted: &str| -> Vec<&str> {
        deciding
            .iter()
            .filter(|class| state_of(class) == wanted)
            .map(String::as_str)
            .collect()
    };
    let unproduced = in_state("unproduced");
    if !unproduced.is_empty() {
        let missing = unproduced.join(", ");
        return Reading::Inconclusive(vec![format!(
            "cross_file_edges_unproduced: this build produced no entity-level {missing} edge for \
             {language} although the source carries {missing} sites the linker resolved, so a \
             use that reaches the target through {missing} could not have been found, and the gap \
             is in the linker, not in the code"
        )]);
    }
    let absent = in_state("absent");
    if !absent.is_empty() {
        let missing = absent.join(", ");
        return Reading::Inconclusive(vec![format!(
            "cross_file_edges_absent: the graph was not observed to hold cross-file \
             {missing} edges for {language}, so a use that reaches the target through {missing} \
             could not have been found"
        )]);
    }
    let unhealthy: Vec<&str> = deciding
        .iter()
        .filter(|class| state_of(class) != "present")
        .map(String::as_str)
        .collect();
    if unhealthy.is_empty() {
        Reading::Certified
    } else {
        let missing = unhealthy.join(", ");
        Reading::Inconclusive(vec![format!(
            "edge_coverage_unknown: whether the graph holds cross-file {missing} edges for \
             {language} could not be established, so a use that reaches the target through \
             {missing} may not have been found"
        )])
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
        // A payload carrying no candidate accounting at all has nothing to say
        // here, which is not the same as saying nothing was withheld. Answering
        // `certified` for a concept the payload does not carry is how a mutation
        // response, whose every other input is silent, came to ship a certified
        // verdict about nothing.
        None => Reading::Silent,
        Some(0) => Reading::Certified,
        Some(withheld) => Reading::Inconclusive(vec![format!(
            "withheld_candidates: {withheld} same-name candidate(s) are carried in `candidates` \
             and are not in the counts here, so the headline is a floor and each withheld row \
             may belong in it"
        )]),
    }
}

/// Whether the configured cross-repo authority could answer for this response.
///
/// The absence gate already weighs this, and weighs it well, but only on an
/// answer that CLAIMS an absence. That scoping is deliberate and it is right for
/// what it was written for: a populated answer claims nothing is missing, so
/// refusing there on a store with no spine would put a floor under every answer
/// forever.
///
/// What it leaves uncovered is the case this input exists for. A populated
/// answer is presented as the reference set, and when a configured spine went
/// stale or answered incompletely, every cross-repo row is missing from a set
/// nothing marks as partial. That is `find_references` certifying an answer as
/// the whole set while recording that a class is absent, one level up: the class
/// here is every other repository. The gap belongs in the verdict on both
/// shapes of answer, and only the absence claim differs.
///
/// The rule itself is not restated here. [`crate::negative::cross_repo_qualifier`]
/// owns it, so this reading and the absence gate can never disagree about what
/// counts as a gap, and the clause text is identical, which is what makes the
/// composer's label dedupe collapse them to one on an answer where both speak.
///
/// Silent, never refusing, in the states that are facts about an install rather
/// than limits on an answer: no spine configured, and a repository the spine has
/// not registered. Both already travel as notes on the absence path, and both
/// are the ordinary state of a healthy single-repo store, so refusing on either
/// is the "mark everything uncertain" regression arriving by a side door.
///
/// Silent on a third, which the absence path does treat as a gap and this one
/// deliberately does not. An `unavailable` carrying no `code` is a caller that
/// never bound to a repository at all, not a spine that failed:
/// the absence gate's own unavailable-qualifier states the principle
/// itself, that every code "describes a spine that IS configured and did not
/// answer", and an uncoded reason reaches the gap branch only through the
/// catch-all label. `kin refs` is such a caller on every invocation, since it
/// resolves its binding from `KIN_REPO_ID` and that is an override rather than
/// something an install sets, so weighing it here would mark every CLI reference
/// answer on every machine a lower bound. The absence path keeps its stricter
/// reading, because an answer asserting that nothing references a symbol while
/// reporting no cross-repo authority is exactly what that gate exists to refuse,
/// and a populated answer asserts no such thing.
fn cross_repo_reading(tool: &str, payload: &Value) -> Reading {
    use crate::negative::CrossRepoQualifier;
    let unbound_caller = payload.get("cross_repo").is_some_and(|cross_repo| {
        cross_repo.get("status").and_then(Value::as_str) == Some("unavailable")
            && cross_repo.get("code").and_then(Value::as_str).is_none()
    });
    if unbound_caller {
        return Reading::Silent;
    }
    match crate::negative::cross_repo_qualifier(tool, payload) {
        None => Reading::Silent,
        Some(CrossRepoQualifier::Complete) => Reading::Certified,
        Some(CrossRepoQualifier::Note(_)) => Reading::Silent,
        Some(CrossRepoQualifier::Gap(reason)) => Reading::Inconclusive(vec![reason]),
    }
}

/// This query's own reported degradations.
fn degradations_reading(payload: &Value) -> Reading {
    if payload.get("degradations").is_none() {
        return Reading::Silent;
    }
    let labels = crate::negative::payload_degradation_labels(payload);
    if labels.is_empty() {
        Reading::Certified
    } else {
        Reading::Inconclusive(vec![format!(
            "retrieval_degraded: this query reported degradations [{}], so it did not run at \
             full capability",
            labels.join(", ")
        )])
    }
}

/// The completeness signal's own reading of the substrate and the numbers.
/// Graph freshness as a verdict input: wired, and deliberately weighing nothing
/// until the durable marker reaches the health wire.
///
/// The clock reaches the envelope now (see [`crate::envelope::GraphFreshness`]),
/// which is the half of FIR-2226 that could be done honestly here. This is the
/// seam that will carry it into the verdict, and it reports [`Reading::Silent`]
/// in every state on purpose, contributing neither agreement nor refusal.
///
/// **Why not refuse when no admission is recorded.** The wire's clock is the
/// daemon's in-memory record, set only by a completed exact-tree admission pass,
/// so a freshly initialized store whose daemon has not yet run one carries
/// nothing. Absence is therefore the ordinary state of a healthy new store, not
/// evidence of staleness, and refusing on it puts a floor under every answer on
/// every such store. That is the regression `crate::negative`'s own gate comment
/// warns about, and the acceptance suite's anti-vacuity control caught this
/// module doing it.
///
/// **Why not certify when one IS recorded.** A present clock proves an admission
/// completed at some time. It does not prove the store is current, and the
/// verdict's note asserts agreement of every input, so certifying here would
/// state exactly the false all-clear for the case this cannot see: a months-stale
/// store under a daemon that has been up the whole time and admitted once.
///
/// Both halves need the same missing fact, a reading the daemon does not
/// publish: the durable last-admission marker, which survives a restart and
/// carries `tracked_artifacts` beside its timestamp. With it, absence and
/// staleness separate and this becomes a real input. Until then, silence is the
/// only honest reading, and a silent input never contributes agreement, so
/// nothing here can license an answer either.
fn graph_freshness_reading(envelope: &Envelope) -> Reading {
    // Read so the field is provably consumed and the seam is not decorative.
    let _ = envelope.freshness.as_ref();
    Reading::Silent
}

fn completeness_reading(envelope: &Envelope) -> Reading {
    let Some(completeness) = &envelope.completeness else {
        return Reading::Silent;
    };
    if completeness.status != "complete" {
        return Reading::Inconclusive(vec![format!(
            "substrate_{}: the coverage classes this answer depended on were not all observed \
             present ({})",
            completeness.status,
            completeness.decided_by.join(", ")
        )]);
    }
    if completeness.bound != "exact" {
        return Reading::Inconclusive(vec![
            "counts_are_a_floor: this answer's own accounting reports its numbers as a lower \
             bound"
                .to_string(),
        ]);
    }
    Reading::Certified
}

/// How many same-name candidates the payload held out of its counts, read from
/// the one number the withheld plumbing already publishes.
fn withheld_candidate_count(payload: &Value) -> Option<u64> {
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
        // The budget cut leads the sentence and the reasons already in it
        // follow, the same way the absence object below keeps its own; a factor
        // that was replaced outright lost every other reason the answer had.
        let factor = match verdict.get("limiting_factor").and_then(Value::as_str) {
            Some(existing) if !existing.is_empty() => {
                format!("{RESPONSE_BOUNDED_FACTOR}; {existing}")
            }
            _ => RESPONSE_BOUNDED_FACTOR.to_string(),
        };
        verdict.insert("limiting_factor".to_string(), json!(factor.clone()));
        verdict.insert(
            "note".to_string(),
            json!(format!(
                "Treat this answer as a lower bound and do not act on an absence in it. Limiting \
                 factor: {factor}."
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

    // The five arms above all read one direction: a surface claiming
    // certification under an inconclusive verdict. Nothing read the other way,
    // which is why a shipped envelope could carry a CERTIFIED verdict over a
    // completeness that refused and still grade clean. A contradiction does not
    // care which side is the optimistic one.
    if certified {
        if let Some(completeness) = response
            .get(crate::envelope::ENVELOPE_KEY)
            .and_then(|envelope| envelope.get("completeness"))
        {
            let bound = completeness.get("bound").and_then(Value::as_str);
            if matches!(bound, Some("at_least")) {
                found.push(
                    "_kin.completeness.bound reads at_least under a certified _kin.verdict"
                        .to_string(),
                );
            }
            if completeness.get("status").and_then(Value::as_str) == Some("unknown") {
                found.push(
                    "_kin.completeness.status reads unknown under a certified _kin.verdict"
                        .to_string(),
                );
            }
        }
        if let Some(negative) = response.get(crate::negative::NEGATIVE_KEY) {
            if matches!(
                negative.get("trust").and_then(Value::as_str),
                Some("inconclusive") | Some("unreliable")
            ) {
                found.push("negative.trust refuses under a certified _kin.verdict".to_string());
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

    /// FIR-2226 step 1. The clock reaches the envelope; the verdict seam is
    /// wired and deliberately weighs nothing yet.
    ///
    /// The arms below assert exactly that and no more. An earlier version of
    /// this change refused when no admission was recorded, and the acceptance
    /// suite's anti-vacuity control caught it certifying nothing: absence of the
    /// in-memory clock is the ordinary state of a healthy fresh store, so
    /// refusing on it floors every answer on every such store. The arms are
    /// written against what this can honestly claim rather than against what it
    /// was hoped to do.
    ///
    /// Driven through `with_health` using the producer's own field names, and
    /// both are `skip_serializing_if = "Option::is_none"` there, which is why the
    /// no-clock arm omits the key rather than setting it null.
    mod graph_freshness {
        use super::*;

        fn envelope_with(reconcile: Value) -> Envelope {
            Envelope::daemon().with_health(&json!({
                "graph_loaded": true,
                "initialized": true,
                "reconcile": reconcile,
            }))
        }

        fn with_clock() -> Envelope {
            envelope_with(json!({
                "untracked_path_count": 0,
                "last_admission_success_at": "2026-08-26T00:00:00Z",
                "last_admission_success_age_seconds": 12,
            }))
        }

        fn without_clock() -> Envelope {
            envelope_with(json!({ "untracked_path_count": 0 }))
        }

        /// The disclosure, which is what step 1 actually delivers. Both stores
        /// below hold zero unadmitted paths, so `behind` is silent by design and
        /// used to take the clock down with it.
        #[test]
        fn the_clock_is_published_even_when_nothing_is_unadmitted() {
            let recorded = with_clock();
            assert!(
                recorded.behind.is_none(),
                "the count gate is what used to discard this: {:?}",
                recorded.behind
            );
            assert!(
                matches!(
                    recorded.freshness,
                    Some(crate::envelope::GraphFreshness::Recorded { .. })
                ),
                "a clean working copy must not hide a clock the daemon sent: {:?}",
                recorded.freshness
            );
            assert!(
                matches!(
                    without_clock().freshness,
                    Some(crate::envelope::GraphFreshness::NoAdmissionRecorded)
                ),
                "and the absence of one is itself a reading, not a parse failure"
            );
        }

        /// A runtime that reported no reconcile block has nothing to publish.
        /// Distinct from a block that carries no clock, and the two must not
        /// collapse.
        #[test]
        fn a_runtime_reporting_no_reconcile_block_publishes_nothing() {
            let envelope = Envelope::daemon().with_health(&json!({ "graph_loaded": true }));
            assert!(envelope.freshness.is_none());
        }

        /// The seam weighs nothing, with a clock. Certifying here would state
        /// agreement this cannot support: a present clock proves an admission
        /// happened at some time, not that the store is current, and the
        /// verdict's note asserts every input agreed.
        #[test]
        fn a_recorded_clock_does_not_certify() {
            assert!(matches!(
                graph_freshness_reading(&with_clock()),
                Reading::Silent
            ));
        }

        /// The seam weighs nothing, without one. Refusing here floors every
        /// answer on every freshly initialized store, because the wire's clock is
        /// the daemon's in-memory record and a daemon that has not yet completed
        /// an admission pass carries none. This arm is the one the acceptance
        /// control already proved can fail.
        #[test]
        fn an_unrecorded_clock_does_not_refuse() {
            assert!(matches!(
                graph_freshness_reading(&without_clock()),
                Reading::Silent
            ));
        }

        /// The readings array and the stamp's derivation agree on every name,
        /// which neither side can prove on its own.
        ///
        /// kin#1123 asserts `edge_coverage_limits` picks up an input the
        /// function was never told about, and it happens to use
        /// `graph_freshness` as that unknown name, with the map built by hand.
        /// The arms above assert `compute` puts `graph_freshness` into the map.
        /// Both hardcode the string, so renaming the reading leaves both green
        /// while the real behaviour breaks: the stamp would go on naming a key
        /// nothing emits, and the emitted key would be one nothing names.
        ///
        /// So this asserts the join rather than either end. It reads the names
        /// `compute` actually produced and requires the stamp to name each one
        /// when that input refuses, which is a property over the real input set
        /// and cannot be satisfied by a string written twice.
        #[test]
        fn every_input_compute_emits_is_one_the_stamp_can_name() {
            let verdict = Verdict::compute(
                "find_references",
                &json!({ "references": [] }),
                &with_clock(),
                None,
            )
            .expect("the readings are not all silent");
            let names: Vec<String> = verdict.inputs.keys().cloned().collect();
            assert!(
                names.iter().any(|name| name == "graph_freshness"),
                "the seam must be in the stamp's input set at all: {names:?}"
            );

            for name in names {
                if name == "edge_coverage" {
                    continue;
                }
                let mut inputs = Map::new();
                inputs.insert("edge_coverage".to_string(), json!(CERTIFIED));
                inputs.insert(name.clone(), json!(INCONCLUSIVE));
                let refusing = Verdict {
                    certified: false,
                    absence_claim: AbsenceClaim::NotAuthoritative,
                    limiting_factor: Some(format!("{name}: refusing")),
                    inputs,
                };
                assert!(
                    refusing
                        .edge_coverage_limits()
                        .contains(&format!("{name}:inconclusive")),
                    "the stamp must name {name}, which compute emits, without being told about it"
                );
            }
        }

        /// End to end: neither store may pick up a freshness clause, and the
        /// input is present in the stamp as `not_applicable` rather than absent,
        /// so the seam is visible to a reader and to the next reading added.
        #[test]
        fn neither_store_puts_a_freshness_clause_in_the_verdict() {
            for envelope in [with_clock(), without_clock()] {
                let verdict = Verdict::compute(
                    "find_references",
                    &json!({ "references": [] }),
                    &envelope,
                    None,
                );
                let Some(verdict) = verdict else { continue };
                assert_eq!(
                    verdict
                        .inputs
                        .get("graph_freshness")
                        .and_then(Value::as_str),
                    Some(NOT_APPLICABLE),
                    "the seam is wired and weighs nothing: {:?}",
                    verdict.inputs
                );
                assert!(
                    !verdict
                        .limiting_factor
                        .as_deref()
                        .unwrap_or_default()
                        .contains("graph_admission"),
                    "no freshness clause may reach the factor yet: {:?}",
                    verdict.limiting_factor
                );
            }
        }
    }

    /// FIR-2673 finding 1, the case the stranger read as a refusal.
    ///
    /// A populated answer, every input clean, verdict certified. The old bool
    /// was FALSE here, correctly, because no absence is claimed, and the note
    /// beside it promised that an absence in the answer was authoritative. A
    /// consumer branching on the bool got the opposite of the verdict, and the
    /// one object said both things at once.
    #[test]
    fn a_populated_certified_answer_claims_no_absence_and_promises_none() {
        let payload = populated_reference_payload("present");
        let negative = json!({ "interpretation": "qualified_answer", "trust": "authoritative" });
        let verdict = Verdict::compute(
            "find_references",
            &payload,
            &Envelope::daemon(),
            Some(&negative),
        )
        .expect("a retrieval payload carries a verdict")
        .to_value();

        assert_eq!(verdict["state"], json!(CERTIFIED), "{verdict}");
        assert_eq!(
            verdict["absence_claim"],
            json!("not_applicable"),
            "a populated answer claims no absence: {verdict}"
        );
        let note = verdict["note"].as_str().expect("a note");
        assert!(
            !note.contains("absence in it is authoritative"),
            "the note promised an authoritative absence to an answer claiming none: {note}"
        );
        assert!(
            note.contains("claims no absence"),
            "and it should say which case this is: {note}"
        );
        // The legacy bool stays false here, and that is correct rather than a
        // bug: it is now DEFINED from the tri-state, so it can no longer
        // contradict the note beside it.
        assert_eq!(
            verdict["safe_to_conclude_absent"],
            json!(false),
            "{verdict}"
        );
    }

    /// The inverse, and the half that stops the split trading a false certify
    /// for a field that never says yes.
    ///
    /// An empty answer with every requested class present must still certify
    /// its absence, or a fix that answers `not_applicable` to everything would
    /// pass the check above and say nothing.
    #[test]
    fn an_empty_certified_answer_still_certifies_its_absence() {
        let mut payload = populated_reference_payload("present");
        payload["references"] = json!([]);
        payload["total_upstream"] = json!(0);
        let negative = json!({ "interpretation": "absence_claimed", "trust": "authoritative" });
        let verdict = Verdict::compute(
            "find_references",
            &payload,
            &Envelope::daemon(),
            Some(&negative),
        )
        .expect("a retrieval payload carries a verdict")
        .to_value();

        assert_eq!(verdict["state"], json!(CERTIFIED), "{verdict}");
        assert_eq!(
            verdict["absence_claim"],
            json!("authoritative"),
            "an empty certified answer's absence is authoritative: {verdict}"
        );
        assert_eq!(verdict["limiting_factor"], Value::Null, "{verdict}");
        assert_eq!(verdict["safe_to_conclude_absent"], json!(true), "{verdict}");
        assert!(
            verdict["note"]
                .as_str()
                .expect("a note")
                .contains("absence in it is authoritative"),
            "{verdict}"
        );
    }

    /// The absence gate's `trust_reason` is a JOIN, and its clauses must
    /// deduplicate against the later readings' like any others.
    ///
    /// This is the regression a unit test did not have. Taking `trust_reason`
    /// as one opaque clause looked conservative and was not: the negative block
    /// composes it by repeated concatenation, so it carries a
    /// `retrieval_degraded` clause of its own, and as one blob that clause
    /// stopped matching the `degradations` reading's. One live answer then named
    /// the same gap twice, and the `two_reasons` acceptance check caught it on a
    /// real payload after every unit test here passed.
    ///
    /// Splitting a wire string that IS a join recovers a boundary; splitting a
    /// factor Kin had just joined itself invented one. Same operation, opposite
    /// sides of the same seam, and only one of them is parsing prose.
    #[test]
    fn a_trust_reason_that_repeats_a_later_reading_says_that_gap_once() {
        let negative = json!({
            "trust": "inconclusive",
            "trust_reason": "response_bounded: the response budget withheld part of this answer; \
                             retrieval_degraded: this query reported degradations \
                             [embed_worker:failed], so it did not run at full capability",
        });
        let readings = [
            (
                "absence_gate",
                absence_gate_reading("find_references", &json!({}), Some(&negative)),
            ),
            (
                "degradations",
                Reading::Inconclusive(vec![
                    "retrieval_degraded: this query reported degradations \
                                            [embed_worker:failed], so it did not run at full \
                                            capability"
                        .to_string(),
                ]),
            ),
        ];
        let factor = compose_limiting_factor(&readings).expect("two inputs refused");
        assert_eq!(
            factor.matches("retrieval_degraded:").count(),
            1,
            "the gap the trust_reason and the degradations reading both carry is said once: \
             {factor}"
        );
        assert!(
            factor.contains("response_bounded:"),
            "and the trust_reason's other clause survives rather than being swallowed: {factor}"
        );
    }

    /// No clause may contain the string that separates clauses.
    ///
    /// The invariant the FIR-2723 fix rests on, asserted rather than assumed.
    /// Clauses are carried as a list now, so Kin no longer mis-parses its own
    /// factor, but the rendered sentence is still one string, and any reader
    /// that splits it on the separator sees whatever the prose contains. Two
    /// gap texts used to carry one, `cross_file_edges_absent` and
    /// `name_filter_narrowed_to_zero`, and each arrived at the reader as a
    /// labelled clause plus a bare fragment with no label at all.
    ///
    /// This drives the real producer over the shapes that reach it rather than
    /// re-listing the texts, because a test that restates the strings is a
    /// second copy of them and goes stale the day one is edited.
    #[test]
    fn no_clause_carries_the_separator_that_divides_clauses() {
        let shapes = [
            ("find_references", populated_reference_payload("absent")),
            ("find_references", populated_reference_payload("unproduced")),
            ("find_references", populated_reference_payload("unknown")),
            ("impact_analysis", populated_reference_payload("absent")),
            ("trace_data_flow", populated_reference_payload("absent")),
        ];
        let mut seen = 0;
        for (tool, payload) in &shapes {
            for clause in crate::negative::absence_coverage_clauses(tool, payload) {
                seen += 1;
                assert!(
                    !clause.contains(CLAUSE_SEPARATOR),
                    "{tool}: a clause carries the separator, so any reader that splits the \
                     rendered factor will cut it into a labelled clause and an unlabelled \
                     fragment: {clause}"
                );
            }
        }
        assert!(
            seen > 0,
            "no clause was produced by any shape, so this asserted nothing"
        );
    }

    /// FIR-2672, second finding. A verdict with two independent reasons names
    /// both: the class gap decided the state and the failed embedding worker
    /// stayed in the sentence after it, and the gap the absence gate and the
    /// coverage reading both carry is said once. Remove a clause and the
    /// reader loses one of the two things wrong with the answer.
    #[test]
    fn every_refusing_input_keeps_its_clause_in_the_factor() {
        let readings = [
            (
                "absence_gate",
                Reading::Inconclusive(vec![
                    "cross_file_edges_absent: the graph holds no cross-file imports edges for \
                     python"
                        .to_string(),
                ]),
            ),
            (
                "edge_coverage",
                Reading::Inconclusive(vec![
                    "cross_file_edges_absent: the graph was not observed to hold imports edges"
                        .to_string(),
                ]),
            ),
            ("withheld_candidates", Reading::Certified),
            (
                "degradations",
                Reading::Inconclusive(vec![
                    "retrieval_degraded: this query reported degradations [embed_worker_failed], \
                     so it did not run at full capability"
                        .to_string(),
                ]),
            ),
            ("completeness", Reading::Silent),
        ];
        let factor = compose_limiting_factor(&readings).expect("two inputs refused");
        assert_eq!(
            factor,
            "cross_file_edges_absent: the graph holds no cross-file imports edges for python; \
             retrieval_degraded: this query reported degradations [embed_worker_failed], so it \
             did not run at full capability"
        );
        assert!(
            compose_limiting_factor(&[
                ("absence_gate", Reading::Certified),
                ("degradations", Reading::Silent),
            ])
            .is_none(),
            "no refusing input, no factor"
        );
    }

    /// The same two reasons through `Verdict::compute` itself: a short class
    /// and a run degradation on one populated answer. The class gap decides
    /// and leads, the degradation follows in the same sentence, and the class
    /// gap the absence gate and the coverage reading both carry is said once.
    #[test]
    fn a_verdict_with_two_refusing_inputs_names_both_in_order() {
        let mut payload = populated_reference_payload("absent");
        payload["degradations"] = json!([{"component": "embed_worker", "reason": "failed"}]);
        let verdict = Verdict::compute("find_references", &payload, &Envelope::daemon(), None)
            .expect("a retrieval payload carries a verdict")
            .to_value();
        assert_eq!(verdict["state"], json!(INCONCLUSIVE), "{verdict}");
        assert_eq!(
            verdict["inputs"]["edge_coverage"],
            json!(INCONCLUSIVE),
            "{verdict}"
        );
        assert_eq!(
            verdict["inputs"]["degradations"],
            json!(INCONCLUSIVE),
            "{verdict}"
        );
        let factor = verdict["limiting_factor"].as_str().expect("named");
        let class_gap = factor
            .find("cross_file_edges_absent:")
            .unwrap_or_else(|| panic!("the class gap is named: {factor}"));
        let degraded = factor
            .find("retrieval_degraded:")
            .unwrap_or_else(|| panic!("the degradation stays named beside it: {factor}"));
        assert!(class_gap < degraded, "the structural gap leads: {factor}");
        assert_eq!(
            factor.matches("cross_file_edges_absent:").count(),
            1,
            "one fact, one clause: {factor}"
        );
        // WHICH of the two clauses survives is decided by the readings array's
        // order, not by the dedupe rule, and nothing else asserts it. The
        // absence gate precedes the coverage reading, and its clause is the
        // specific one: it names the language and says which classes do not
        // stand in for the missing one. Swap the two in `compute` and both the
        // assertion above and `every_refusing_input_keeps_its_clause_in_the_factor`
        // stay green while every real reader quietly gets the shorter clause.
        // Both clauses name the language, so that is not the difference. The
        // absence gate's says where the gap IS, in extraction rather than in
        // the caller's code, and why the classes that ARE present do not stand
        // in for the missing one. The coverage reading's says only that the
        // edges were not observed. A reader who acts on the first does not go
        // looking through their own source; a reader who acts on the second
        // might.
        assert!(
            factor.contains("rather than in the code"),
            "the surviving clause is the absence gate's, which tells the reader the gap is not \
             in their code. Which of the two survives is decided by the readings array's ORDER, \
             not by the dedupe rule, so reordering `compute` silently downgrades what every \
             reader sees while every other assertion here stays green: {factor}"
        );
        assert!(
            factor.contains("do not stand in for"),
            "and why the classes that are present do not compensate: {factor}"
        );
        assert!(factor.contains("embed_worker:failed"), "{factor}");
    }

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

    /// A response no retrieval input spoke about must carry no verdict at all.
    ///
    /// Certification on no evidence is the failure this module would otherwise
    /// introduce. A mutation payload has no absence gate, no edge coverage and
    /// no completeness signal, so an input that answers `certified` for a
    /// concept the payload does not carry would put a certified verdict on every
    /// commit response. Both remaining inputs stay silent instead.
    #[test]
    fn a_non_retrieval_payload_carries_no_verdict() {
        let payload = json!({"committed": true, "change_id": "abc"});
        let envelope = Envelope::daemon();
        assert!(
            Verdict::compute("kin_transaction_commit", &payload, &envelope, None).is_none(),
            "a payload no input spoke about must not be certified"
        );
    }

    /// The other direction: a retrieval payload that genuinely withheld nothing
    /// and reported no degradation still certifies, so the silence above is not
    /// a blanket refusal.
    #[test]
    fn a_clean_retrieval_payload_still_certifies() {
        let payload = json!({
            "references": [{"name": "caller"}],
            "relation_kinds": ["calls"],
            "counts": {"receiver_name_candidates": 0},
            "degradations": [],
            "edge_coverage": {
                "language": "Rust",
                "classes": {"calls": "present"},
                "reference_enrichment": "supported",
            },
        });
        let verdict = Verdict::compute("find_references", &payload, &Envelope::daemon(), None)
            .expect("a retrieval payload carries a verdict");
        assert_eq!(
            verdict.to_value()["state"],
            json!(CERTIFIED),
            "{}",
            verdict.to_value()
        );
    }

    /// FIR-2496. The `edge_coverage` input used to answer `certified` for an
    /// observation that named no class to check, which is every observation a
    /// tool traversing no edge publishes. The shipped v0.5.43 verdict block read
    /// `"inputs": {"edge_coverage": "certified"}` over `"classes": {}` on three
    /// searches, two of which were wrong: `SCHEMA` was a module constant the
    /// Python extractor skips and `build_match_query` sat in a file the graph
    /// had not admitted. Agreement inferred from silence is not agreement.
    #[test]
    fn an_unmeasured_class_map_is_not_an_agreeing_input() {
        let payload = json!({
            "results": [],
            "total_matches": 0,
            "edge_coverage": {
                "scope": "absence_scope",
                "language": "Python",
                "requested_classes": [],
                "classes": {},
                "reference_enrichment": "available",
                "scope_entities": 51,
            },
        });
        let verdict = Verdict::compute("semantic_search", &payload, &Envelope::daemon(), None)
            .expect("a retrieval payload carries a verdict");
        let value = verdict.to_value();
        assert_eq!(value["state"], json!(INCONCLUSIVE), "{value}");
        assert_eq!(
            value["inputs"]["edge_coverage"],
            json!(INCONCLUSIVE),
            "{value}"
        );
        assert!(
            value["limiting_factor"]
                .as_str()
                .expect("an inconclusive verdict names its limiting factor")
                .contains("absence_coverage_unmeasured"),
            "{value}"
        );

        // The control that makes it a reading of the observation rather than of
        // the tool name: one measured class over the same language, same filter,
        // same store, and the same answer certifies.
        let mut measured = payload.clone();
        measured["edge_coverage"]["classes"] = json!({"calls": "present"});
        let verdict = Verdict::compute("semantic_search", &measured, &Envelope::daemon(), None)
            .expect("a retrieval payload carries a verdict");
        assert_eq!(
            verdict.to_value()["inputs"]["edge_coverage"],
            json!(CERTIFIED),
            "{}",
            verdict.to_value()
        );
    }

    /// The other half of the same rule. An answer that resolved no language has
    /// no language's extractor coverage to be missing, and this input must not
    /// invent one: the tools that produce that observation carry their own
    /// sharper reason (an unresolved focal, an empty filtered region), and a
    /// correct refusal beside an unrelated reason is what this module exists to
    /// prevent.
    #[test]
    fn an_observation_that_resolved_no_language_is_not_refused_for_one() {
        let payload = json!({
            "entities": [],
            "relations": [],
            "relation_count": 0,
            "entity_count": 0,
            "edge_coverage": {
                "scope": "absence_scope",
                "language": crate::edge_coverage::NO_RESOLVED_LANGUAGE,
                "requested_classes": [],
                "classes": {},
                "reference_enrichment": "unknown",
            },
        });
        let verdict = Verdict::compute("graph_neighborhood", &payload, &Envelope::daemon(), None)
            .expect("a retrieval payload carries a verdict");
        assert_eq!(
            verdict.to_value()["inputs"]["edge_coverage"],
            json!(CERTIFIED),
            "the coverage input says nothing about an answer with no language: {}",
            verdict.to_value()
        );
    }

    /// A populated reference answer whose every other input is clean, with one
    /// requested class in the state given.
    /// One focal id for the fixture, named once so the payload's `focal_entity`
    /// and the cross-repo anchor cannot drift apart into a response that would
    /// never be produced.
    const FIXTURE_FOCAL_ID: &str = "0195f2a1-0000-7000-8000-00000000f0ca";

    fn populated_reference_payload(imports: &str) -> Value {
        json!({
            "references": [{"name": "index_note"}, {"name": "test_blank_code_masks_fences"}],
            "total_upstream": 2,
            "relation_kinds": ["calls", "imports", "references"],
            "counts": {"receiver_name_candidates": 0},
            "degradations": [],
            // Complete the way a real answer is complete. The producer always
            // writes an anchor beside the roots and always writes `focal_entity`,
            // and the absence gate has always required the anchor to name the
            // focal this query asked about. A fixture carrying roots and no
            // anchor describes a response the handler cannot emit.
            "focal_entity": {"id": FIXTURE_FOCAL_ID},
            "cross_repo": {
                "status": "available",
                "authority_complete": true,
                "authority_revision": "sha256:complete",
                "authority_roots": {"local": "local-root"},
                "authority_anchor": {"repo_id": "local", "entity_id": FIXTURE_FOCAL_ID},
            },
            "focal_resolution": {
                "addressed_by": "entity_id",
                "same_name_candidates": 1,
                "matched": "exact_focal_name",
                "other_candidates": [],
            },
            "edge_coverage": {
                "scope": "language",
                "language": "Python",
                "requested_classes": ["calls", "imports", "references"],
                "classes": {"calls": "present", "imports": imports, "references": "present"},
                "reference_enrichment": "available",
                "budget_exhausted": false,
            },
        })
    }

    /// FIR-2764. A populated answer whose configured spine answered incompletely
    /// is a lower bound, and the verdict has to say so.
    ///
    /// The absence gate already weighs cross-repo authority, and weighs it well,
    /// but only on an answer that claims an absence. A populated answer is
    /// presented as the reference set, so a spine that could not answer means
    /// every cross-repo row is missing from a set nothing marks as partial.
    /// Before this input the verdict read six other blocks, none of which can
    /// see the spine, and certified.
    #[test]
    fn a_populated_answer_over_an_incomplete_spine_is_a_lower_bound() {
        let mut payload = populated_reference_payload("present");
        payload["cross_repo"]["authority_complete"] = json!(false);
        let negative = json!({ "interpretation": "qualified_answer", "trust": "authoritative" });
        let verdict = Verdict::compute(
            "find_references",
            &payload,
            &Envelope::daemon(),
            Some(&negative),
        )
        .expect("a retrieval payload carries a verdict")
        .to_value();

        assert_eq!(
            verdict["state"],
            json!(INCONCLUSIVE),
            "a set presented as whole while the spine could not answer: {verdict}"
        );
        assert_eq!(
            verdict["inputs"]["cross_repo"],
            json!(INCONCLUSIVE),
            "{verdict}"
        );
        let factor = verdict["limiting_factor"].as_str().expect("a factor");
        assert!(
            factor.contains("cross_repo_authority_incomplete"),
            "the factor must name the spine rather than something else: {factor}"
        );
    }

    /// The same shape with an `unavailable` spine that named its condition.
    #[test]
    fn a_populated_answer_over_a_stale_spine_is_a_lower_bound() {
        let mut payload = populated_reference_payload("present");
        payload["cross_repo"] = json!({
            "status": "unavailable",
            "code": "spine_root_stale",
            "reason": "spine root mismatch for repository local",
        });
        let negative = json!({ "interpretation": "qualified_answer", "trust": "authoritative" });
        let verdict = Verdict::compute(
            "find_references",
            &payload,
            &Envelope::daemon(),
            Some(&negative),
        )
        .expect("a retrieval payload carries a verdict")
        .to_value();

        assert_eq!(verdict["state"], json!(INCONCLUSIVE), "{verdict}");
        let factor = verdict["limiting_factor"].as_str().expect("a factor");
        assert!(
            factor.contains("spine_root_stale"),
            "the producer's own code names the condition: {factor}"
        );
    }

    /// The controls that keep this input from becoming a floor under every
    /// answer, which is the regression the absence gate's own scoping comment
    /// warns about. Each of these is an ordinary state of a healthy install, and
    /// each must leave the verdict certified with no factor at all.
    ///
    /// `unavailable` with no code is `kin refs` on every invocation: it resolves
    /// its binding from `KIN_REPO_ID`, which is an override rather than
    /// something an install sets. Weighing it would mark every CLI reference
    /// answer on every machine a lower bound.
    #[test]
    fn the_ordinary_states_of_a_healthy_install_limit_nothing() {
        let mut broken: Vec<String> = Vec::new();
        for (case, cross_repo) in [
            ("no spine configured", json!({ "status": "not_configured" })),
            (
                "a repository the spine has not registered",
                json!({
                    "status": "unavailable",
                    "code": "spine_repo_unregistered",
                    "reason": "repository local has no registered spine authority",
                }),
            ),
            (
                "a caller that never bound to a repository",
                json!({
                    "status": "unavailable",
                    "reason": "KIN_REPO_ID is missing or blank; cross-repo authority cannot \
                               bind this graph to a repository",
                }),
            ),
        ] {
            let mut payload = populated_reference_payload("present");
            payload["cross_repo"] = cross_repo;
            let negative =
                json!({ "interpretation": "qualified_answer", "trust": "authoritative" });
            let verdict = Verdict::compute(
                "find_references",
                &payload,
                &Envelope::daemon(),
                Some(&negative),
            )
            .expect("a retrieval payload carries a verdict")
            .to_value();

            // Collected rather than asserted in place. A bare assert aborts the
            // loop on the first case, so a break confined to a later one is
            // invisible behind an earlier one failing first, and the mutation
            // written for it reads as covered while proving nothing.
            if verdict["state"] != json!(CERTIFIED) {
                broken.push(format!(
                    "{case} is a fact about the install, not a limit on the answer: {verdict}"
                ));
            }
            if verdict["limiting_factor"] != Value::Null {
                broken.push(format!("{case} must contribute no clause: {verdict}"));
            }
            if verdict["inputs"]["cross_repo"] != json!(NOT_APPLICABLE) {
                broken.push(format!(
                    "{case} must read silent rather than certifying: {verdict}"
                ));
            }
        }
        assert!(
            broken.is_empty(),
            "{} of the ordinary install states limited an answer:\n{}",
            broken.len(),
            broken.join("\n")
        );
    }

    /// A complete spine certifies rather than staying silent, so the input
    /// contributes agreement on the healthy path instead of merely not refusing.
    #[test]
    fn a_complete_spine_certifies_as_its_own_named_input() {
        let payload = populated_reference_payload("present");
        let negative = json!({ "interpretation": "qualified_answer", "trust": "authoritative" });
        let verdict = Verdict::compute(
            "find_references",
            &payload,
            &Envelope::daemon(),
            Some(&negative),
        )
        .expect("a retrieval payload carries a verdict")
        .to_value();

        assert_eq!(verdict["state"], json!(CERTIFIED), "{verdict}");
        assert_eq!(
            verdict["inputs"]["cross_repo"],
            json!(CERTIFIED),
            "{verdict}"
        );
        assert_eq!(verdict["limiting_factor"], Value::Null, "{verdict}");
    }

    /// The same gap seen by two readings is named once.
    ///
    /// On an answer that claims an absence, the gate puts the cross-repo clause
    /// in `trust_reason` and the absence-gate reading splits it back out, while
    /// this input builds the same clause directly. Both speak, and the composer
    /// dedupes by label, so the reader gets one clause rather than the same
    /// sentence twice. That is the FIR-2672 rule this input has to obey rather
    /// than re-break.
    #[test]
    fn one_gap_seen_by_two_readings_is_named_once() {
        let mut payload = populated_reference_payload("present");
        payload["cross_repo"]["authority_complete"] = json!(false);
        let negative = json!({
            "interpretation": "absence_claim",
            "trust": "inconclusive",
            "trust_reason": "cross_repo_authority_incomplete: spine topology or requested \
                             relation subtype is incomplete at revision sha256:complete",
        });
        let verdict = Verdict::compute(
            "find_references",
            &payload,
            &Envelope::daemon(),
            Some(&negative),
        )
        .expect("a retrieval payload carries a verdict")
        .to_value();

        let factor = verdict["limiting_factor"].as_str().expect("a factor");
        assert_eq!(
            factor.matches("cross_repo_authority_incomplete").count(),
            1,
            "the gap is one gap however many readings noticed it: {factor}"
        );
    }

    /// The other tool that carries a cross-repo block reaches the same input.
    ///
    /// The dispatch names two tools, and the absence gate names the same two, so
    /// the strings are written twice in one file. A rename that moved one and not
    /// the other would leave this arm matching nothing, and nothing about a
    /// find_references test can see that: the verdict would simply stop weighing
    /// cross-repo authority on bulk answers and no assertion anywhere would go
    /// red.
    ///
    /// So the arm gets its own case, with the healthy direction beside the
    /// refusing one. A dispatch that stopped matching would certify both.
    #[test]
    fn the_bulk_tool_reaches_the_same_cross_repo_input() {
        let complete = json!({
            "status": "available",
            "authority_complete": true,
            "authority_revision": "sha256:complete",
            "authority_roots": {"local": "local-root"},
            "relation_subtype_complete": true,
            "verdicts_complete": true,
        });
        let mut incomplete = complete.clone();
        incomplete["authority_complete"] = json!(false);

        for (case, cross_repo, expected_state, expected_input) in [
            ("a complete bulk authority", complete, CERTIFIED, CERTIFIED),
            (
                "a bulk authority that answered incompletely",
                incomplete,
                INCONCLUSIVE,
                INCONCLUSIVE,
            ),
        ] {
            let payload = json!({
                "results": [{"name": "index_note", "has_references": true}],
                "degradations": [],
                "cross_repo": cross_repo,
            });
            let negative =
                json!({ "interpretation": "qualified_answer", "trust": "authoritative" });
            let verdict = Verdict::compute(
                "bulk_check_references",
                &payload,
                &Envelope::daemon(),
                Some(&negative),
            )
            .expect("a retrieval payload carries a verdict")
            .to_value();

            assert_eq!(
                verdict["inputs"]["cross_repo"],
                json!(expected_input),
                "{case}: the bulk dispatch arm must be reached: {verdict}"
            );
            assert_eq!(verdict["state"], json!(expected_state), "{case}: {verdict}");
        }
    }

    /// FIR-2672, the sole-cause case. Every input is clean except one requested
    /// class the answer could not read, and that alone makes the verdict
    /// inconclusive and names the class, for each of the three states a class
    /// can be short in. The shipped 0.5.52 verdict certified this exact shape
    /// with `imports: absent`, because the reading weighed `calls` alone.
    #[test]
    fn a_requested_class_the_answer_could_not_read_is_the_sole_cause_of_an_inconclusive_verdict() {
        for (state, leading) in [
            ("absent", "cross_file_edges_absent"),
            ("unproduced", "cross_file_edges_unproduced"),
            ("unknown", "edge_coverage_unknown"),
        ] {
            let verdict = Verdict::compute(
                "find_references",
                &populated_reference_payload(state),
                &Envelope::daemon(),
                None,
            )
            .expect("a retrieval payload carries a verdict")
            .to_value();
            assert_eq!(verdict["state"], json!(INCONCLUSIVE), "{state}: {verdict}");
            assert_eq!(
                verdict["inputs"]["edge_coverage"],
                json!(INCONCLUSIVE),
                "{state}: the coverage input itself refuses: {verdict}"
            );
            let factor = verdict["limiting_factor"]
                .as_str()
                .expect("an inconclusive verdict names its limiting factor");
            assert!(
                factor.starts_with(leading) && factor.contains("imports"),
                "{state}: the factor leads with the class's own state and names the class: \
                 {factor}"
            );
            for input in ["withheld_candidates", "degradations"] {
                assert_ne!(
                    verdict["inputs"][input],
                    json!(INCONCLUSIVE),
                    "{state}: {input} was clean and must not be what refused: {verdict}"
                );
            }
        }
    }

    /// The inverse of the case above, and the half that keeps the fix from
    /// trading a false certification for a false refusal: the same answer with
    /// every requested class present certifies, with no limiting factor.
    #[test]
    fn the_same_answer_with_every_class_present_still_certifies() {
        let verdict = Verdict::compute(
            "find_references",
            &populated_reference_payload("present"),
            &Envelope::daemon(),
            None,
        )
        .expect("a retrieval payload carries a verdict")
        .to_value();
        assert_eq!(verdict["state"], json!(CERTIFIED), "{verdict}");
        assert_eq!(verdict["limiting_factor"], Value::Null, "{verdict}");
        assert_eq!(verdict["inputs"]["edge_coverage"], json!(CERTIFIED));
        assert_eq!(verdict["inputs"]["absence_gate"], json!(CERTIFIED));
    }

    /// The budget path downgrades every verdict surface together. Leaving
    /// `negative` or `_kin.verdict` certifying an answer whose rows were removed
    /// is the same defect arriving through the one path that removes answers on
    /// purpose.
    /// An input this function never heard of still limits the stamp.
    ///
    /// The list used to be four names written out, which is "every input except
    /// `edge_coverage`" in a five-input world and silently wrong in a six-input
    /// one. A reading added later would not appear, and the failure is the
    /// quiet kind: a missing name yields a SHORTER list, never an error, so the
    /// block goes on presenting itself as licensing on its own beside an input
    /// that refuses.
    ///
    /// This test is shaped like the mutation that catches it. The name is
    /// deliberately one no code in this file mentions, so it cannot pass by
    /// being enumerated somewhere; the hardcoded version fails it, and any
    /// future hardcoded version will fail it too. The pair of assertions is the
    /// point: an unknown input that REFUSES must appear, and an unknown input
    /// that certifies must not, or a function returning every input it sees
    /// would pass the first assertion alone.
    #[test]
    fn an_input_this_function_has_never_heard_of_still_limits_the_stamp() {
        let build = |unknown_state: &str| {
            let mut inputs = Map::new();
            inputs.insert("edge_coverage".to_string(), json!(CERTIFIED));
            inputs.insert("completeness".to_string(), json!(CERTIFIED));
            inputs.insert("graph_freshness".to_string(), json!(unknown_state));
            Verdict {
                certified: false,
                absence_claim: AbsenceClaim::NotAuthoritative,
                limiting_factor: Some("graph_freshness: the store is stale".to_string()),
                inputs,
            }
        };

        let limits = build(INCONCLUSIVE).edge_coverage_limits();
        assert!(
            limits.contains(&"graph_freshness:inconclusive".to_string()),
            "an input added after this function was written must still limit the block: {limits:?}"
        );

        assert!(
            build(CERTIFIED).edge_coverage_limits().is_empty(),
            "an unknown input that certifies limits nothing, or the function is just \
             listing its inputs"
        );
    }

    /// `edge_coverage` never limits itself, whatever the derivation does.
    ///
    /// The old hardcoded list excluded it by not mentioning it. Deriving from
    /// the map means the exclusion is now a filter clause, which is a line
    /// someone can delete, so it gets an assertion rather than a comment.
    #[test]
    fn the_edge_coverage_input_is_never_one_of_its_own_limits() {
        let mut inputs = Map::new();
        inputs.insert("edge_coverage".to_string(), json!(CERTIFIED));
        inputs.insert("completeness".to_string(), json!(INCONCLUSIVE));
        let verdict = Verdict {
            certified: false,
            absence_claim: AbsenceClaim::NotAuthoritative,
            limiting_factor: Some("completeness: unknown".to_string()),
            inputs,
        };

        let limits = verdict.edge_coverage_limits();
        assert_eq!(limits, vec!["completeness:inconclusive".to_string()]);
        assert!(
            !limits
                .iter()
                .any(|limit| limit.starts_with("edge_coverage")),
            "the block cannot cite itself as the reason it does not license: {limits:?}"
        );
    }

    /// A CERTIFIED verdict over a completeness that refuses is a contradiction,
    /// and until now nothing looked for it.
    ///
    /// The five arms that existed all read one direction: a surface claiming
    /// certification under an inconclusive verdict. None read the reverse, so an
    /// envelope whose verdict certified while its own completeness reported
    /// `status: unknown` or `bound: at_least` graded clean.
    ///
    /// This is the only shape that can falsify the arm. Deleting a detector
    /// cannot make anything go red, because a detector's absence is silence, so
    /// the proof has to give it something to detect and confirm it speaks. The
    /// end-to-end suite cannot do it either: `disagreements` is reached from a
    /// `debug_assert!`, which a release build compiles out.
    #[test]
    fn a_certified_verdict_over_a_refusing_completeness_is_a_disagreement() {
        let mut response = agreeing_response();
        // Everything else still agrees; only completeness refuses.
        response["_kin"]["completeness"]["status"] = json!("unknown");
        response["_kin"]["completeness"]["bound"] = json!("at_least");

        let found = disagreements(&response);
        assert!(
            found
                .iter()
                .any(|line| line.contains("bound reads at_least under a certified")),
            "a certified verdict over an at_least bound must be reported: {found:?}"
        );
        assert!(
            found
                .iter()
                .any(|line| line.contains("status reads unknown under a certified")),
            "a certified verdict over an unknown status must be reported: {found:?}"
        );
    }

    /// The same arm on the negative block, and the control beside it.
    ///
    /// The control is the half that matters: an untouched agreeing response must
    /// report NOTHING. Without it this pair would pass just as happily if the
    /// arm reported a disagreement on every response it was handed, which is a
    /// detector that fires always and is no more useful than one that never
    /// fires.
    #[test]
    fn a_certified_verdict_over_a_refusing_negative_is_a_disagreement() {
        let mut response = agreeing_response();
        response["negative"]["trust"] = json!("inconclusive");
        response["negative"]["safe_to_conclude_absent"] = json!(true);

        let found = disagreements(&response);
        assert!(
            found
                .iter()
                .any(|line| line.contains("negative.trust refuses under a certified")),
            "a certified verdict over a refusing negative must be reported: {found:?}"
        );

        assert!(
            disagreements(&agreeing_response()).is_empty(),
            "control: an agreeing response must report no disagreement at all"
        );
    }

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
