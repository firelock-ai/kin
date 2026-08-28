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

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use kin_core::LocateCursor;
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
    /// What the payload measured when the ladder finished with it, which is the
    /// size the response ships at.
    ///
    /// `chars_before` alone cannot say whether the bound held. An
    /// `impact_analysis` answer reported `bounded: false` beside a
    /// `chars_before_budget` of 50,354 against a 2,000-character ceiling and
    /// shipped all 50,354, and nothing in the accounting distinguished that from
    /// a response whose diagnostics were compacted away and which then fit.
    /// Publishing the size the response actually shipped at is what separates
    /// them, and it is the number a caller compares against `max_chars`.
    ///
    /// Reconciled after the envelope, budget downgrade, residual disclosure and
    /// self-check have reached their final shape, so it is the exact serialized
    /// size of the JSON response that carries this field.
    #[serde(rename = "chars_after_budget", default)]
    pub chars_after: usize,
    /// True when the budget removed hits, bodies or breakdowns under pressure.
    ///
    /// False does not by itself mean the response is whole: compaction is the
    /// documented default shape and is reported by `compact`, not here. What
    /// false does mean, always, is that the response fits `max_chars`; read
    /// `chars_after_budget` for the size it fits at.
    pub bounded: bool,
    /// True when explanation and per-signal breakdowns were shed.
    pub compact: bool,
    /// The literal key of the collection this response answers with: the one a
    /// `next_cursor` advances and the one a reader counts. `entities` on a
    /// fused locate page, `results` on a cosine one, `files` at file
    /// granularity, and the tool's own ranked list everywhere else.
    ///
    /// Published because presence cannot identify it. `LocateResult` skips its
    /// `entities` array when empty while the secondary `files` roll-up
    /// serializes whatever it holds, so on the one page that most needs
    /// qualifying the first present array is the wrong one. A reader that has
    /// to re-derive this from `granularity` and `routing` is a second copy of
    /// the rule, and two copies is how the block beside this one came to count
    /// a different collection from the one the ladder cut.
    ///
    /// Absent only on a response whose shape declares no primary and carries
    /// none, because naming a collection that is not there would be worse than
    /// saying nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_collection: Option<String>,
    /// Rows the response ships in [`Self::primary_collection`].
    ///
    /// Zero is an answer here, not a missing field: it says the primary is
    /// empty, which no secondary collection beside it can soften.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_rows: Option<usize>,
}

impl BudgetAccounting {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

/// The reason code a budget elision carries, so a caller keying on it never has
/// to parse prose.
pub const ELISION_REASON_BUDGET: &str = "response_budget";

/// The reason code a row cut by a pack's own token budget carries.
///
/// Deliberately not [`ELISION_REASON_BUDGET`]. The two budgets cut at different
/// times, for different reasons, and are raised by different parameters: a
/// caller widens the response budget with `max_chars` and the pack's with
/// `token_budget`. A caller told only that something was withheld cannot act,
/// and one told the wrong lever acts and gets the same answer back.
pub const ELISION_REASON_TOKEN_BUDGET: &str = "token_budget";

/// The reason code a dependent withheld by the certified-dependents cap
/// carries. A cap is not a budget: no budget parameter recovers it, so reading
/// it as one would send a caller to a lever that cannot help.
pub const ELISION_REASON_DEPENDENTS_CAP: &str = "dependents_cap";

/// Where a payload publishes what its lists lost.
pub const ELISIONS_KEY: &str = "elisions";

/// Per-row marker naming the budget that took this row's inline source.
///
/// A row that simply loses its `body` key is byte-identical to a row from a
/// `compact: true` call, and sits beside the context pack's own `body: null`
/// plus `body_unavailable`, which is its vocabulary for source the graph does
/// not have. Both readings are wrong about a row the budget cut, and neither is
/// corrected by a count elsewhere in the response: the reader looks at the row.
pub const BODY_ELIDED_KEY: &str = "body_elided";

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
    /// One list's loss to the response budget.
    pub fn budget(kept: usize, elided: usize) -> Self {
        Self::for_reason(kept, elided, ELISION_REASON_BUDGET)
    }

    /// One list's loss, from what survived, what did not, and what took it.
    pub fn for_reason(kept: usize, elided: usize, reason: &str) -> Self {
        Self {
            elided,
            kept,
            total: kept.saturating_add(elided),
            reason: reason.to_string(),
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
    record_elision_for(payload, field, kept, elided, ELISION_REASON_BUDGET);
}

/// Record one list's elision under a named cause, merging with any already
/// standing against that field.
///
/// One list can be cut twice. A context pack's own token budget refuses rows
/// before the response budget ever sees the payload, and the daemon's raw route
/// cuts once before the stdio path envelopes the result and cuts again. An
/// entry that overwrote its predecessor would report only the last cut, so
/// `total` would describe what the second cutter was handed rather than what
/// the walk found, and the first cause would vanish. The counts add and the
/// causes are kept in the order they happened.
pub fn record_elision_for(
    payload: &mut Value,
    field: &str,
    kept: usize,
    elided: usize,
    reason: &str,
) {
    if elided == 0 {
        return;
    }
    let prior = payload
        .get(ELISIONS_KEY)
        .and_then(|map| map.get(field))
        .and_then(|entry| serde_json::from_value::<Elision>(entry.clone()).ok());
    let entry = match prior {
        Some(prior) => {
            let mut merged =
                Elision::for_reason(kept, prior.elided.saturating_add(elided), &prior.reason);
            if !merged.reason.split(", ").any(|already| already == reason) {
                merged.reason.push_str(", ");
                merged.reason.push_str(reason);
            }
            merged
        }
        None => Elision::for_reason(kept, elided, reason),
    };
    let entry = serde_json::to_value(entry).unwrap_or(Value::Null);
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

/// Give up a chain's least load-bearing branches until it fits, and hand back
/// what survived.
///
/// ## Why a suffix cut alone produced a wrong answer
///
/// A budgeted chain used to be cut as a prefix: keep `chain[..k]` and drop the
/// rest. That is safe, because a discovery-ordered chain lists children after
/// their parents and removing the end never orphans a surviving `parent_step`.
/// It is also what produced a wrong answer. Discovery order is breadth-first,
/// so the tail of the chain is its DEEPEST steps, and a suffix cut therefore
/// spends the whole budget on the shallow fan-out and amputates the far end,
/// which is where a trace stops being a list of neighbours and becomes an
/// answer.
///
/// Measured on a converted `psf/requests` at the documented cheap settings
/// (`depth: 3`, `limit_per_step: 12`, `include_body: false`): 67 of 117 steps
/// went, and `_urllib3_request_context` was not among the survivors. Read
/// alone, the response said `verify` reaches TLS at `cert_verify` and stopped,
/// missing the half that governs connection reuse. The edge was in the graph
/// the whole time.
///
/// ## What this does instead
///
/// A branch is one child of one node, taken with everything below it. Wide nodes
/// are shaved first, because a wide fan-out is where the budget actually went,
/// and narrowing a node from twelve children to eight costs a caller far less
/// than losing the end of every chain. Every node keeps one child, so narrowing
/// can thin a walk and can never sever it, and a dropped branch takes its
/// descendants with it, so no surviving step names a parent the caller no longer
/// has.
///
/// Within a node, the SHALLOWEST branches go first, and the one it keeps is the
/// one that reaches deepest. Relevance breaks ties, which is what children
/// arrive ordered by. Keeping merely the first child was not enough and the
/// difference is the whole defect: on the measured `psf/requests` walk the hop
/// that carries the answer hangs off the focal's FIFTH child, so a rule that
/// preserves the leftmost spine preserved a branch that ends at depth one and
/// gave up the branch that reaches depth three. That made the answer depend on
/// how large the walk happened to be, which is luck rather than a rule: the same
/// query returned the hop at 129 discovered steps and lost it at 200.
///
/// ## Why it lives here
///
/// `trace_data_flow` has two implementations: the CLI one the daemon route
/// serves and the MCP one the in-process arm serves. A budget rule that
/// differed by whether a daemon happened to be up is the two-surface divergence
/// class this codebase keeps paying for, so the rule is written once, generically
/// over the step type, and both arms call it.
///
/// ## Why the question outranks relevance
///
/// Relevance orders the children of a node. It does not know what was asked.
/// `trace_data_flow` takes a `target`, and before this the target governed the
/// per-step fan-out cap and nothing else, so a branch could be walked BECAUSE
/// the caller named it and then given up here as "least relevant", which is the
/// worst of both: the work was done and the result was thrown away.
///
/// Measured on the converted `psf/requests` by the rc061y stranger, focal
/// `Session.send`, `depth: 3`, `limit_per_step: 25`, `target: "cert_verify"`:
/// `HTTPAdapter.send` was walked and continued beneath, and the answer came back
/// holding `RequestsCookieJar.items` and `Response.iter_content` with the named
/// branch gone. Their words: "the relevance ordering used for elision does not
/// appear to consult `target` at all, even though the fan-out cap's own
/// remediation text tells you to set `target` for exactly this purpose."
///
/// So `must_keep` names the steps the question asked for, and neither they nor
/// any step between them and the root is ever offered up. Everything else sheds
/// first, in the same order as before. When the caller names nothing, or names
/// something the walk never reached, no step is protected and this behaves
/// exactly as it did: a rule that could never drop anything would be no rule.
///
/// The protection is a preference, not a refusal. If holding the named branch
/// leaves nothing that fits, the drop order is rebuilt without it and the
/// narrowing runs again, because a shorter answer that loses the target still
/// beats falling through to the suffix cut that loses the depth of every branch.
///
/// `fits` is called on candidate survivor sets, bisected over the drop order, so
/// a caller pays a handful of serializations rather than one per branch. It may
/// mutate whatever it needs to measure and is not required to leave it restored:
/// callers install the returned chain themselves.
///
/// Returns `None` when there is nothing to narrow or when no amount of narrowing
/// fits, which is the caller's signal to fall back to the suffix cut so a
/// pathological walk is still answered rather than refused. `Some(kept)` is
/// always strictly shorter than `steps`.
pub fn narrow_fanout_to_fit<T: Clone>(
    steps: &[T],
    id_of: &dyn Fn(&T) -> u64,
    parent_of: &dyn Fn(&T) -> Option<u64>,
    must_keep: &dyn Fn(&T) -> bool,
    fits: &mut dyn FnMut(&[T]) -> bool,
) -> Option<Vec<T>> {
    // Children in the order they were discovered, which is the order relevance
    // put them in. A step that names itself as its own parent is skipped rather
    // than trusted: it would make the descendant walk below cyclic.
    let mut children: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    let mut parent_of_id: BTreeMap<u64, u64> = BTreeMap::new();
    for step in steps {
        if let Some(parent) = parent_of(step) {
            let id = id_of(step);
            if id != parent {
                children.entry(parent).or_default().push(id);
                parent_of_id.insert(id, parent);
            }
        }
    }

    // How far below each node the walk reached. Computed bottom-up over the
    // children map, memoized, and cycle-safe, because a chain is a tree only by
    // construction and a malformed one must not hang the bounder.
    let mut reach: BTreeMap<u64, usize> = BTreeMap::new();
    let mut order: Vec<u64> = children.keys().copied().collect();
    for kids in children.values() {
        order.extend(kids.iter().copied());
    }
    for _ in 0..=children.len() {
        let mut changed = false;
        for node in &order {
            let deepest = children
                .get(node)
                .map(|kids| {
                    kids.iter()
                        .map(|kid| 1 + reach.get(kid).copied().unwrap_or(0))
                        .max()
                        .unwrap_or(0)
                })
                .unwrap_or(0);
            if reach.get(node).copied().unwrap_or(0) < deepest {
                reach.insert(*node, deepest);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // The steps the question named, and every step between each of them and the
    // root. Ancestors are protected too because a dropped branch takes its
    // descendants with it: protecting the target alone and then giving up the
    // node above it would drop the target anyway, silently, one level up.
    //
    // The insert-or-break walk is what makes this cycle-safe. A chain is a tree
    // by construction, and a malformed one must not hang the bounder.
    let mut protected: BTreeSet<u64> = BTreeSet::new();
    for step in steps.iter().filter(|step| must_keep(step)) {
        let mut at = Some(id_of(step));
        while let Some(id) = at {
            if !protected.insert(id) {
                break;
            }
            at = parent_of_id.get(&id).copied();
        }
    }

    let mut drop_order = fanout_drop_order(&children, &reach, &protected);
    let mut chosen = bisect_narrowing(steps, id_of, &children, &drop_order, fits);
    if chosen.is_none() && !protected.is_empty() {
        // Holding the named branch left nothing that fits. Give it up rather
        // than fall through to the suffix cut, which would amputate the far end
        // of every branch including this one.
        drop_order = fanout_drop_order(&children, &reach, &BTreeSet::new());
        chosen = bisect_narrowing(steps, id_of, &children, &drop_order, fits);
    }
    chosen
}

/// Which branches to give up, in the order to give them up.
///
/// Within a node, shallowest branch first and least relevant among equals, so
/// the branch it keeps is the one that reaches deepest. Across nodes, widest
/// first, so the budget is reclaimed where it was spent. Ties broken by parent
/// id so the order is deterministic.
///
/// A protected child is never offered, and it also satisfies the keep-one-child
/// floor on its own: a node with a protected child among six may give up the
/// other five, because the protection is already keeping one. A node with no
/// protected child keeps its deepest, exactly as before, which is why an
/// unprotected walk narrows identically to how it did before protection existed
/// (`giveups.len()` is then `kids.len() - 1` for every node, and subtracting one
/// from every width leaves the widest-first order unchanged).
fn fanout_drop_order(
    children: &BTreeMap<u64, Vec<u64>>,
    reach: &BTreeMap<u64, usize>,
    protected: &BTreeSet<u64>,
) -> Vec<u64> {
    let mut by_width: Vec<(u64, Vec<u64>)> = children
        .iter()
        .filter_map(|(parent, kids)| {
            // Sorted into GIVE-UP order: shallowest first, and among equally
            // deep branches the one relevance put last.
            let rank: BTreeMap<u64, usize> = kids
                .iter()
                .enumerate()
                .map(|(at, kid)| (*kid, at))
                .collect();
            let mut ordered: Vec<u64> = kids.clone();
            ordered.sort_by(|left, right| {
                reach
                    .get(left)
                    .copied()
                    .unwrap_or(0)
                    .cmp(&reach.get(right).copied().unwrap_or(0))
                    .then_with(|| rank[right].cmp(&rank[left]))
            });
            let mut giveups: Vec<u64> = ordered
                .into_iter()
                .filter(|kid| !protected.contains(kid))
                .collect();
            if giveups.len() == kids.len() {
                // Nothing here is protected, so one child still has to survive,
                // and it is the last in give-up order: the deepest.
                giveups.pop();
            }
            (!giveups.is_empty()).then_some((*parent, giveups))
        })
        .collect();
    by_width.sort_by(|left, right| {
        right
            .1
            .len()
            .cmp(&left.1.len())
            .then_with(|| left.0.cmp(&right.0))
    });
    let mut drop_order: Vec<u64> = Vec::new();
    let mut round = 0usize;
    loop {
        let mut moved = false;
        for (_parent, giveups) in &by_width {
            if round < giveups.len() {
                drop_order.push(giveups[round]);
                moved = true;
            }
        }
        if !moved {
            break;
        }
        round += 1;
    }
    drop_order
}

/// The fewest drops off the front of `drop_order` that fit, or `None` when no
/// prefix of it does.
///
/// One drop is the floor: zero drops is the input, and the input is why this was
/// called.
fn bisect_narrowing<T: Clone>(
    steps: &[T],
    id_of: &dyn Fn(&T) -> u64,
    children: &BTreeMap<u64, Vec<u64>>,
    drop_order: &[u64],
    fits: &mut dyn FnMut(&[T]) -> bool,
) -> Option<Vec<T>> {
    if drop_order.is_empty() {
        return None;
    }
    let retained = |dropped: usize| -> Vec<T> {
        let mut condemned: BTreeSet<u64> = drop_order[..dropped].iter().copied().collect();
        // Breadth-first over the children map rather than one pass over
        // `steps`, so the closure does not silently depend on children being
        // listed after their parents.
        let mut queue: VecDeque<u64> = condemned.iter().copied().collect();
        while let Some(id) = queue.pop_front() {
            for kid in children.get(&id).into_iter().flatten() {
                if condemned.insert(*kid) {
                    queue.push_back(*kid);
                }
            }
        }
        steps
            .iter()
            .filter(|step| !condemned.contains(&id_of(step)))
            .cloned()
            .collect()
    };

    let mut low = 1usize;
    let mut high = drop_order.len();
    let mut chosen: Option<Vec<T>> = None;
    while low <= high {
        let mid = low + (high - low) / 2;
        let kept = retained(mid);
        if fits(&kept) {
            chosen = Some(kept);
            high = mid - 1;
        } else {
            low = mid + 1;
        }
    }
    chosen
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
    /// Per-hit keys holding a secondary nested roll-up. These normally repeat
    /// primary hits, but can carry detail when entity projection is empty; they
    /// are still lower authority than the declared primary and are never shed
    /// when their parent collection itself is primary.
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
            // Fused publishes its primary ranking as `entities`; cosine uses
            // `results`. Both precede the secondary `files` rollup so the first
            // present array is the page whose cursor advances.
            collections: &["entities", "results", "files"],
            body_keys: &["body", "snippet"],
            explain_keys: &[
                "match_evidence",
                "explain",
                "signal_scores",
                "score_breakdown",
            ],
            top_explain_keys: &["debug"],
            // Every symbol in `files[].symbols[]` is a hit the primary ranking
            // already reports with more fields (`entities[]` when fused,
            // `results[]` when cosine), so the roll-up is the redundant copy.
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
        // Every array an `impact_analysis` response carries, ranked by what a
        // caller loses when it goes, because the ladder trims from the end.
        //
        // Naming only the four blast-radius buckets is what FIR-2602 was: a
        // report over a wide diff can leave all four genuinely empty and still
        // run to tens of thousands of characters, because `entity_impacts`
        // carries a row per changed entity and the changed-id and attribution
        // echoes carry one entry each. The ladder walked its four arrays, found
        // nothing to cut, and returned 50,354 characters against a 2,000
        // ceiling while reporting itself unbounded. A key the table does not
        // name is a key the bounder cannot count, so the table names them all.
        //
        // The ranking, most important first:
        //
        // `entity_impacts` is the verdict. `proven_consumer_count` and
        // `covering_tests` are what a caller reads to decide whether something
        // is safe to change, and they were once left out on the grounds that
        // they are small, which is true per row and false per report.
        //
        // The four blast-radius buckets come next, in the order kin#1062 fixed
        // them in: callers before dependents, dependents before contract
        // consumers, tests last of the four.
        //
        // Then the governance and input echoes. `unreviewed_agent_changes` is a
        // judgment a caller cannot reconstruct; `changed_ids` is the target the
        // caller named, so it is the one list the caller already holds.
        //
        // Then provenance and side channels: `actor_attribution` is answered in
        // full by `kin_provenance_query`, and work items and annotations are
        // adjacent records rather than blast radius.
        //
        // Ambient context sheds first. `cross_repo_impact` and `active_traffic`
        // answer "who else is nearby", and `active_traffic` is already optional
        // on the call.
        "impact_analysis" => ResponseShape {
            collections: &[
                "entity_impacts",
                "affected_callers",
                "affected_dependents",
                "affected_contract_consumers",
                "affected_tests",
                "unreviewed_agent_changes",
                "changed_ids",
                "actor_attribution",
                "affected_work_items",
                "affected_annotations",
                "cross_repo_impact",
                "active_traffic",
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

/// The collection a semantic-locate cursor advances.
///
/// Presence is not enough to identify it. Empty `LocateResult.entities` is
/// omitted from JSON while the secondary `files` roll-up is always serialized,
/// so choosing the first present array relabels an empty entity answer as file
/// granularity. Prefer the response's declared arm and granularity; retain the
/// presence fallback for older/test payloads that predate those fields.
fn primary_collection(payload: &Value, tool: &str, shape: &ResponseShape) -> Option<&'static str> {
    declared_primary_collection(payload, tool).or_else(|| {
        shape
            .collections
            .iter()
            .copied()
            .find(|key| payload.get(*key).is_some_and(Value::is_array))
    })
}

/// The primary a response DECLARES, from the fields it publishes about itself,
/// with no appeal to which arrays happen to be present.
///
/// Split out from the presence fallback because the two answer different
/// questions. This one asks what the response said it is; the fallback guesses
/// from what it carries, and a guess is exactly what relabels an empty entity
/// page as a file one.
///
/// The last arm is the one worth reading twice. A response that echoed a
/// granularity other than `file` has already ruled the secondary roll-up out,
/// whether or not it named an arm: an entity answer's primary is `results` when
/// it carries that array and `entities` otherwise, and a page carrying neither
/// is an empty entity page rather than a file one. Only a payload that named no
/// granularity at all is left to the fallback.
fn declared_primary_collection(payload: &Value, tool: &str) -> Option<&'static str> {
    if tool != "semantic_locate" {
        return None;
    }
    let granularity = payload.get("granularity").and_then(Value::as_str);
    if granularity == Some("file") {
        return Some("files");
    }
    match payload.get("routing").and_then(Value::as_str) {
        Some("cosine-v0") => Some("results"),
        Some("fused-v1") => Some("entities"),
        _ => granularity.map(|_| {
            if payload.get("results").is_some_and(Value::is_array) {
                "results"
            } else {
                "entities"
            }
        }),
    }
}

/// The collection one budgeted response answers with, for a caller outside this
/// module.
///
/// Public because it is the ONE rule. [`crate::negative`] counts a locate page's
/// rows through this function rather than through a copy of it: two derivations
/// of "which array is the answer" is how one response came to carry a ladder
/// that cut `entities` beside a negative block that had counted `files`.
pub fn primary_collection_for(payload: &Value, tool: &str) -> Option<&'static str> {
    let shape = shape_for(tool)?;
    primary_collection(payload, tool, &shape)
}

/// Name this response's primary collection, and make the response carry it.
///
/// A declared primary the producer omitted is materialized as an empty array.
/// That is the whole of the disguise this fixes: `LocateResult` skips an empty
/// `entities` while the secondary `files` roll-up serializes whatever it holds,
/// so a fused entity page that ranked nothing shipped no primary key at all
/// beside a populated roll-up, and a reader taking the first present array read
/// an empty answer as a file answer.
///
/// Materialized only for a primary the response DECLARED. Inventing a key from
/// the presence fallback would fabricate a collection rather than disclose an
/// empty one, and a key that was never absent needs nothing done to it.
fn declare_primary_collection(
    payload: &mut Value,
    tool: &str,
    shape: &ResponseShape,
) -> Option<&'static str> {
    let Some(declared) = declared_primary_collection(payload, tool) else {
        return primary_collection(payload, tool, shape);
    };
    if payload.get(declared).is_none() {
        if let Some(map) = payload.as_object_mut() {
            map.insert(declared.to_string(), Value::Array(Vec::new()));
        }
    }
    Some(declared)
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
/// secondary roll-up goes next while the declared primary remains unchanged.
/// Source bodies go next, recoverable one call at a time
/// through `get_entity_source`. Only then are hits themselves withheld, from the
/// tail of the least important array first, which is the only cut that removes
/// an answer rather than a description of one.
pub fn enforce(
    payload: &mut Value,
    tool: &str,
    budget: &ResponseBudget,
) -> Option<BudgetAccounting> {
    let shape = shape_for(tool)?;
    // Named and materialized BEFORE anything is measured. Adding an omitted
    // empty primary changes the size the accounting reports, and the accounting
    // has to describe the response that ships.
    let primary = declare_primary_collection(payload, tool, &shape);
    let chars_before = measure(payload);

    // Two arms bound one response. The daemon's `/mcp/tools/call` route cuts
    // first, under the budget less the envelope reserve, and the stdio path then
    // envelopes what it gets back and cuts again. The second arm sees an already
    // cut payload: it measures a size the first arm produced, usually finds
    // nothing left to trim, and its accounting is the one that lands in `_kin`.
    // So a response the budget had already cut to its floor reported
    // `bounded: false`, which is FIR-2602's symptom reached by its second route.
    //
    // The accounting describes the response, not this pass over it. What the
    // first arm did is readable off the payload it handed over, because a cut
    // discloses itself, so this reads that record rather than inventing a
    // channel to carry it.
    let prior = prior_bound(payload);
    let mut accounting = BudgetAccounting {
        max_chars: budget.max_chars,
        chars_before: chars_before.max(prior.unwrap_or(0)),
        chars_after: chars_before,
        bounded: prior.is_some(),
        compact: budget.compact,
        primary_collection: primary.map(str::to_string),
        // Solved after the ladder, which is the only thing that can change it.
        primary_rows: None,
    };
    run_ladder(payload, tool, &shape, budget, primary, &mut accounting);
    accounting.chars_after = measure(payload);

    // A response the ladder could not bring under its ceiling is the case
    // FIR-2602 shipped silently: every rung ran, nothing was left to cut, and
    // the accounting reported a whole answer. The ceiling is not always
    // reachable, because a bound is not a refusal and every list keeps an entry,
    // but the caller has to be told which of the two it is holding.
    reconcile_residual(payload, budget);
    accounting.chars_after = measure(payload);
    accounting.primary_rows = primary.map(|key| collection_rows(payload, key));
    Some(accounting)
}

/// Rows one collection carries in a payload. A key that is absent or is not an
/// array carries none, which is the same reading a caller gets from the JSON.
fn collection_rows(payload: &Value, key: &str) -> usize {
    payload
        .get(key)
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

/// Run the ladder over one payload, recording what it cost in `accounting`.
///
/// Split from [`enforce`] so the size the response ships at is measured on one
/// path rather than on each of the ladder's several exits, which is what let a
/// rung return early without anything measuring the result.
fn run_ladder(
    payload: &mut Value,
    tool: &str,
    shape: &ResponseShape,
    budget: &ResponseBudget,
    // Resolved once by [`enforce`] and passed in rather than derived again
    // here. The ladder and the accounting must name the same collection, and a
    // second derivation is what would let them drift apart.
    primary: Option<&'static str>,
    accounting: &mut BudgetAccounting,
) {
    let started_at = measure(payload);
    let mut cuts: Vec<String> = Vec::new();
    let mut remediations: Vec<String> = Vec::new();

    // Compact by default, whether or not the payload is over budget: the
    // breakdowns are diagnostics a caller did not ask for, and shipping them
    // unasked is what made a ten-result ranking an 80,000-character response.
    // This one is not disclosed as a cut, because it is the documented default
    // shape rather than something the budget took away under pressure.
    if budget.compact {
        strip_keys(payload, shape, shape.explain_keys, shape.top_explain_keys);
        strip_keys(payload, shape, shape.bulk_keys, &[]);
    }

    if measure(payload) <= budget.max_chars {
        return;
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
        let stripped = strip_keys(payload, shape, shape.explain_keys, shape.top_explain_keys);
        if stripped > 0 {
            accounting.bounded = true;
            cuts.push(format!(
                "ranking explanation and per-signal breakdowns dropped from {stripped} entries"
            ));
        }
        // Bulk identity is shed here too. A caller that turned compaction off
        // asked to see the ranking, not to be served a response its client
        // refuses because every row carries four hash arrays.
        let stripped = strip_keys(payload, shape, shape.bulk_keys, &[]);
        if stripped > 0 {
            accounting.bounded = true;
            cuts.push(format!(
                "identity fingerprints and retrieval metadata dropped from {stripped} entries, \
                 each of which still carries its name, location, and span"
            ));
        }
        if measure(payload) <= target {
            disclose(payload, budget, started_at, &cuts, &remediations);
            return;
        }
    }

    // `files[].symbols` is a duplicate roll-up only when entities/results are
    // the primary answer. Under `granularity: "file"`, `files[]` is the only
    // primary collection and those symbols are its unique detail. Stripping
    // them there would erase answer content while falsely claiming it remained
    // under the same collection.
    if !shape.duplicate_keys.is_empty() && primary != Some("files") {
        let stripped = strip_keys(payload, shape, shape.duplicate_keys, &[]);
        if stripped > 0 {
            accounting.bounded = true;
            cuts.push(format!(
                "the secondary per-file symbol roll-up dropped from {stripped} entries; the \
                 primary `{}` ranking remains unchanged",
                primary.unwrap_or("the primary result collection")
            ));
        }
        if measure(payload) <= target {
            disclose(payload, budget, started_at, &cuts, &remediations);
            return;
        }
    }

    if !shape.body_keys.is_empty() {
        let carrying = rows_carrying(payload, shape, shape.body_keys);
        let stripped = strip_keys_marking(payload, shape, shape.body_keys, &[], true);
        if stripped > 0 {
            accounting.bounded = true;
            cuts.push(format!(
                "inline source dropped from {stripped} hits, each of which still carries its \
                 identity, location, and span"
            ));
            remediations.push("read one body with get_entity_source".to_string());
            // The prose above has said this since the rung existed, and prose is
            // not what a caller keys on. `elisions` is the one map that answers
            // "did this response lose anything", and until now inline source
            // could go without appearing in it at all.
            record_elision(payload, "body", carrying.saturating_sub(stripped), stripped);
        }
        if measure(payload) <= target {
            disclose(payload, budget, started_at, &cuts, &remediations);
            return;
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
    let primary_found = primary
        .and_then(|key| payload.get(key))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let mut locate_cursor = (tool == "semantic_locate")
        .then(|| {
            payload
                .get("next_cursor")
                .and_then(Value::as_str)
                .filter(|cursor| !cursor.is_empty())
                .and_then(LocateCursor::decode)
        })
        .flatten()
        .filter(|cursor| {
            cursor
                .next_offset
                .is_some_and(|offset| offset >= primary_found)
        });
    let mut withheld_any = false;
    let mut primary_withheld = 0usize;
    let mut cursor_rebased = false;
    for key in shape.collections.iter().rev() {
        let found = payload
            .get(*key)
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        // Every collection is cut, including a final page's primary one.
        // `max_chars` is the caller's context budget rather than a preference,
        // so nothing licenses exceeding it, and a page with no cursor is not an
        // exception: it is the case where the caller cannot page to the rest and
        // therefore most needs to be told what was withheld and how to reach it.
        // The floor of one entry per list is what keeps this from producing the
        // empty array FIR-2600 exists to prevent, and the remediation below says
        // `max_chars` rather than `next_cursor` when there is no cursor to
        // follow. Retaining rows here instead shipped a response over the
        // ceiling and published no elision at all, which is what took
        // `response_budget:3` to UNREADABLE on main.
        let (withheld, cut_shape) = trim_collection(payload, key, target, 1);
        if withheld > 0 {
            accounting.bounded = true;
            withheld_any = true;
            // Which cut, not just how much. A list narrowed by branch still
            // reaches as deep as the walk did; one cut from the end does not,
            // and a reader who cannot tell them apart cannot tell whether the
            // far end of the answer is missing. A cut that held the named target
            // says so too, because "the branch you asked for is still here" is
            // the one thing a caller who named a target needs to read.
            let how = cut_shape.phrase();
            cuts.push(format!(
                "{withheld} of {found} entries withheld from `{key}`, {how}"
            ));
            record_elision(payload, key, found.saturating_sub(withheld), withheld);
            payload["truncated"] = Value::Bool(true);
            if Some(*key) == primary {
                primary_withheld = withheld;
                let kept = found.saturating_sub(withheld);
                if let Some(cursor) = locate_cursor.as_mut() {
                    if cursor.rebase_after_withheld(withheld, kept) {
                        payload["next_cursor"] = Value::String(cursor.encode());
                        cursor_rebased = true;
                    }
                }
            }
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
        if primary_withheld > 0 && cursor_rebased && kept > 0 {
            remediations.push(format!(
                "re-issue with `page_size: {kept}` and follow `next_cursor`"
            ));
        } else if tool == "semantic_locate" && primary_withheld > 0 && locate_cursor.is_none() {
            // Naming a cursor here would be a recovery the response cannot
            // provide. The two things that do reach the withheld rows are a
            // larger ceiling and a narrower question, and the caller owns both.
            remediations.push(format!(
                "raise `max_chars`, or narrow the request with `{}`; this page has no \
                 `next_cursor`, so the withheld entries cannot be reached by paging",
                shape.narrow_param
            ));
        } else {
            remediations.push(format!("narrow the request with `{}`", shape.narrow_param));
        }
    }

    disclose(payload, budget, started_at, &cuts, &remediations);
}

/// The reason code a response the budget cut carries.
pub const BOUNDED_REASON: &str = "response_bounded";

/// The reason code a response that stayed over its ceiling carries.
pub const OVER_BUDGET_REASON: &str = "response_over_budget";

/// What an earlier arm recorded cutting this payload from, if one did.
///
/// A cut discloses itself in the `degradations` channel, and the first such
/// entry is the earliest arm's, because disclosures are appended. Reading it is
/// what lets the second arm report the size the answer was built at instead of
/// the size it inherited.
fn prior_bound(payload: &Value) -> Option<usize> {
    payload
        .get("degradations")?
        .as_array()?
        .iter()
        .find(|entry| {
            entry.get("component").and_then(Value::as_str) == Some("response_budget")
                && entry.get("reason").and_then(Value::as_str) == Some(BOUNDED_REASON)
        })
        .map(|entry| {
            entry
                .get("chars_before_budget")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize
        })
}

/// Record that the ladder finished with the payload still over its ceiling.
///
/// Every list the budget cuts keeps at least one entry, so a response whose
/// surviving entries alone exceed the budget cannot be cut further without
/// producing the empty array FIR-2600 exists to prevent. That case is rare and
/// it is real, and the only wrong answer is a quiet one: FIR-2602 shipped
/// 50,354 characters against a 2,000-character ceiling and reported nothing at
/// all. This says so in the channel the other cuts already use.
///
/// The note carries no size of its own. Appending it changes the size it would
/// be reporting, so any number written here is stale the moment it is written;
/// the accounting's `chars_after_budget` is measured after this note lands and
/// is the one that holds.
fn disclose_residual(payload: &mut Value, budget: &ResponseBudget) {
    let max_chars = budget.max_chars;
    let entry = json!({
        "component": "response_budget",
        "reason": OVER_BUDGET_REASON,
        "detail": format!(
            "the response did not reach its {max_chars}-character budget: every list the budget \
             cuts keeps at least one entry, and what survived does not fit. Read the size it \
             ships at from `_kin.response.chars_after_budget`, or from the bytes received"
        ),
        "remediation": "narrow the request, or raise max_chars if the caller's own result \
                        limit accepts a larger payload",
        "max_chars": max_chars,
    });
    // One note per response. Both arms can reach this, and two copies of the
    // same sentence spend the budget they are complaining about.
    match payload
        .get_mut("degradations")
        .and_then(Value::as_array_mut)
    {
        Some(existing) => {
            existing.retain(|prior| {
                prior.get("reason").and_then(Value::as_str) != Some(OVER_BUDGET_REASON)
            });
            existing.push(entry);
        }
        None => payload["degradations"] = Value::Array(vec![entry]),
    }
}

/// Withdraw a residual note an earlier arm left on a response that now fits.
fn clear_residual(payload: &mut Value) {
    let Some(entries) = payload
        .get_mut("degradations")
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    entries.retain(|entry| entry.get("reason").and_then(Value::as_str) != Some(OVER_BUDGET_REASON));
    if entries.is_empty() {
        if let Some(map) = payload.as_object_mut() {
            map.remove("degradations");
        }
    }
}

/// Make the residual-over-budget disclosure agree with the bytes currently in
/// the response.
///
/// The envelope finalizer calls this again after its epistemic downgrade,
/// accounting stanza and optional self-check have landed. Those fields are not
/// answer rows and must never be trimmed, but they still count against the
/// caller's ceiling. A final response that cannot fit therefore says so, while
/// one that now fits must not retain a stale warning from an earlier pass.
pub(crate) fn reconcile_residual(payload: &mut Value, budget: &ResponseBudget) {
    if measure(payload) > budget.max_chars {
        disclose_residual(payload, budget);
    } else {
        // The other direction, and it is reachable: the first arm cuts under
        // the budget less the envelope reserve, so it can miss a ceiling this
        // arm clears once the reserve it was holding back turns out to be
        // larger than the envelope that landed. A note saying the response did
        // not fit, on a response that does, is the same false report in
        // reverse.
        clear_residual(payload);
    }
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
    strip_keys_marking(payload, shape, keys, top_keys, false)
}

/// Remove `keys` from every hit, optionally leaving each stripped row a marker
/// naming what went.
///
/// `mark` is what separates a row the budget cut from a row that never had the
/// field. Diagnostics and duplicate roll-ups do not need it: a caller reads
/// those as description, and their absence claims nothing about the code. A
/// missing `body` does claim something, twice over, because it is also the
/// shape of a `compact` call and of source the graph does not hold.
fn strip_keys_marking(
    payload: &mut Value,
    shape: &ResponseShape,
    keys: &[&str],
    top_keys: &[&str],
    mark: bool,
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
    let strip_row = |map: &mut Map<String, Value>| -> bool {
        let mut taken: Vec<Value> = Vec::new();
        for key in keys {
            if remove_present(map, key) {
                taken.push(Value::from(*key));
                // `body` keeps its place as an explicit null rather than
                // vanishing, so a typed reader still finds the field and finds
                // it empty, and the marker beside it says who emptied it.
                if *key == "body" {
                    map.insert((*key).to_string(), Value::Null);
                }
            }
        }
        if taken.is_empty() {
            return false;
        }
        if mark {
            map.insert(BODY_ELIDED_KEY.to_string(), Value::Array(taken));
        }
        true
    };
    for collection in shape.collections {
        let Some(entries) = payload.get_mut(*collection).and_then(Value::as_array_mut) else {
            continue;
        };
        for entry in entries.iter_mut() {
            let Some(map) = entry.as_object_mut() else {
                continue;
            };
            if strip_row(map) {
                stripped += 1;
            }
        }
    }
    // A focal record is reported in the same shape as a hit and carries the same
    // keys, so it is charged the same cuts. Leaving it whole would keep the
    // largest single body in a response that just dropped every other one.
    for focal in ["focal_entity", "focal"] {
        if let Some(map) = payload.get_mut(focal).and_then(Value::as_object_mut) {
            if strip_row(map) {
                stripped += 1;
            }
        }
    }
    stripped
}

/// How many rows carry at least one of `keys`, counted before a rung takes
/// them, so the elision it publishes can say what the response held.
fn rows_carrying(payload: &Value, shape: &ResponseShape, keys: &[&str]) -> usize {
    let carries = |value: &Value| -> bool {
        value.as_object().is_some_and(|map| {
            keys.iter()
                .any(|key| !matches!(map.get(*key), None | Some(Value::Null)))
        })
    };
    let in_collections: usize = shape
        .collections
        .iter()
        .filter_map(|collection| payload.get(*collection))
        .filter_map(Value::as_array)
        .map(|entries| entries.iter().filter(|entry| carries(entry)).count())
        .sum();
    let in_focal = ["focal_entity", "focal"]
        .iter()
        .filter_map(|focal| payload.get(*focal))
        .filter(|value| carries(value))
        .count();
    in_collections + in_focal
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

/// Narrow a collection whose entries name a parent, when every entry does.
///
/// `None` means this is not a parented collection, or that no amount of
/// narrowing fits inside `target` and `min_keep`, which is the caller's signal
/// to take the suffix cut instead. `Some(withheld)` leaves the narrowed array
/// installed and the withheld counter updated exactly as the suffix path does.
///
/// Every entry must carry both keys before this fires. A collection where only
/// some do is one this rule cannot reason about, and guessing at the rest would
/// be a cut nobody could predict.
///
/// The question the response echoes is what the narrowing protects. A walk that
/// resolved a `target` reports it as `target_name`, and an entry standing for
/// that symbol carries the same string in `entity_name` (verified against the
/// rc061y transcript, where a surviving target read
/// `"SessionRedirectMixin.resolve_redirects"` in both fields). A payload with no
/// `target_name`, or one no entry matches, protects nothing and narrows exactly
/// as it did before.
fn trim_parented_collection(
    payload: &mut Value,
    key: &str,
    target: usize,
    min_keep: usize,
    full: &[Value],
) -> Option<(usize, bool)> {
    let parented = full.iter().all(|entry| {
        entry.get("step").and_then(Value::as_u64).is_some()
            && entry.get("parent_step").and_then(Value::as_u64).is_some()
    });
    if !parented {
        return None;
    }
    // Read before the `fits` closure borrows the payload, and owned because that
    // closure rewrites the very array these names came from.
    let named = payload
        .get("target_name")
        .and_then(Value::as_str)
        .map(str::to_string);
    let reached = named.as_deref().is_some_and(|name| {
        full.iter()
            .any(|entry| entry.get("entity_name").and_then(Value::as_str) == Some(name))
    });
    let kept = narrow_fanout_to_fit(
        full,
        &|entry: &Value| entry["step"].as_u64().unwrap_or(0),
        &|entry: &Value| entry["parent_step"].as_u64(),
        &|entry: &Value| {
            named
                .as_deref()
                .is_some_and(|name| entry.get("entity_name").and_then(Value::as_str) == Some(name))
        },
        &mut |candidate: &[Value]| {
            payload[key] = Value::Array(candidate.to_vec());
            measure(payload) <= target
        },
    )?;
    if kept.len() < min_keep {
        return None;
    }
    // Claimed only when the target is still there. Protection is a preference
    // the second pass gives up, and a sentence saying the named branch was kept
    // must not outlive the branch it describes.
    let held = reached
        && kept
            .iter()
            .any(|entry| entry.get("entity_name").and_then(Value::as_str) == named.as_deref());
    let withheld = full.len() - kept.len();
    payload[key] = Value::Array(kept);
    if withheld > 0 {
        let prior = payload
            .get(format!("{key}_withheld"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        payload[format!("{key}_withheld")] = Value::from(prior.saturating_add(withheld));
    }
    Some((withheld, held))
}

/// Which cut a reader of a bounded collection actually received.
///
/// Reported rather than inferred because the three read differently and a reader
/// who cannot tell them apart cannot tell what is missing: a suffix cut has lost
/// the far end of every branch, a branch cut has not, and a branch cut that held
/// the named target has not lost the thing that was asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CutShape {
    Suffix,
    Branches,
    BranchesKeepingTarget,
}

impl CutShape {
    /// How this cut describes itself inside the disclosure sentence.
    ///
    /// No semicolons: these clauses are joined with `"; "` downstream, and a
    /// clause carrying the separator its own join uses is the composed-string
    /// defect this codebase has already paid for once.
    fn phrase(self) -> &'static str {
        match self {
            CutShape::Suffix => "from the end of the list",
            CutShape::Branches => "as whole branches, least relevant first",
            CutShape::BranchesKeepingTarget => {
                "as whole branches, least relevant first, keeping the branch that reaches the \
                 named target"
            }
        }
    }
}

/// Withhold entries from one collection until the payload fits, returning how
/// many were withheld.
///
/// Bisected rather than popped one at a time: the same answer, in a handful of
/// serializations instead of one per withheld entry.
///
/// A suffix is what makes the cut safe for a collection whose entries reference
/// earlier ones by index, because removing the end never orphans a surviving
/// entry's parent. It is also what makes it wrong for such a collection, and the
/// two are the same fact: entries that name a parent are a TREE listed
/// breadth-first, so its tail is its deepest entries and a suffix cut amputates
/// the far end of every branch. A `trace_data_flow` chain is exactly that, and
/// on a converted `psf/requests` this stage took the last eight of a chain the
/// walk's own budget had already shortened, on top of the walk's cut, both from
/// the deep end.
///
/// So a parented collection is narrowed by [`narrow_fanout_to_fit`] first, which
/// gives up whole branches least relevant first and leaves the depth intact. A
/// collection that names no parents, or that no amount of narrowing fits, takes
/// the suffix cut as before.
///
/// Returns the count withheld and whether it was narrowed, so the caller can say
/// which cut a reader received rather than reporting every cut as an end-of-list
/// one.
fn trim_collection(
    payload: &mut Value,
    key: &str,
    target: usize,
    min_keep: usize,
) -> (usize, CutShape) {
    let Some(full) = payload.get(key).and_then(Value::as_array).cloned() else {
        return (0, CutShape::Suffix);
    };
    if full.len() <= min_keep || measure(payload) <= target {
        return (0, CutShape::Suffix);
    }
    if let Some((withheld, held)) = trim_parented_collection(payload, key, target, min_keep, &full)
    {
        return (
            withheld,
            if held {
                CutShape::BranchesKeepingTarget
            } else {
                CutShape::Branches
            },
        );
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
        // Added to, not overwritten. Two arms bound one response and a pack's
        // own token budget cuts before either, so a list can arrive here having
        // already lost rows. Assigning would make this scalar describe the last
        // cut while `elisions` described them all, and the two channels are
        // asserted against each other.
        let prior = payload
            .get(format!("{key}_withheld"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        payload[format!("{key}_withheld")] = Value::from(prior.saturating_add(withheld));
    }
    (withheld, CutShape::Suffix)
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
    chars_before: usize,
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
        "reason": BOUNDED_REASON,
        "detail": format!("the response exceeded its {ceiling}, so {}", cuts.join("; ")),
        "remediation": remediation,
        "max_chars": max_chars,
        // The size this arm started from, so the arm that cuts second can report
        // what the answer was built at rather than what it inherited.
        "chars_before_budget": chars_before,
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

    /// The measured shape, in miniature: a focal with a WIDE fan-out and one
    /// narrow deep branch hanging off its first child.
    ///
    /// Steps are numbered in discovery order, which is breadth-first, so the
    /// deep steps are last. That is the whole reason a suffix cut removes the
    /// answer: `psf/requests` gave `HTTPAdapter.send` twelve depth-1 children
    /// and put `_urllib3_request_context` at depth 3, where the tail is.
    ///
    /// Returns `(step, parent_step)` pairs. `parent 0` is the focal.
    fn breadth_first_walk(width: usize, deep: usize) -> Vec<(u64, u64)> {
        let mut steps: Vec<(u64, u64)> = (1..=width as u64).map(|step| (step, 0)).collect();
        let mut parent = 1u64;
        for _ in 0..deep {
            let step = steps.len() as u64 + 1;
            steps.push((step, parent));
            parent = step;
        }
        steps
    }

    fn narrowed(steps: &[(u64, u64)], budget: usize) -> Option<Vec<(u64, u64)>> {
        narrow_fanout_to_fit(
            steps,
            &|step: &(u64, u64)| step.0,
            &|step: &(u64, u64)| Some(step.1),
            &|_step: &(u64, u64)| false,
            &mut |kept: &[(u64, u64)]| kept.len() <= budget,
        )
    }

    /// The same narrowing with one step named as the question's answer.
    fn narrowed_keeping(steps: &[(u64, u64)], keep: u64, budget: usize) -> Option<Vec<(u64, u64)>> {
        narrow_fanout_to_fit(
            steps,
            &|step: &(u64, u64)| step.0,
            &|step: &(u64, u64)| Some(step.1),
            &|step: &(u64, u64)| step.0 == keep,
            &mut |kept: &[(u64, u64)]| kept.len() <= budget,
        )
    }

    /// FIR-2642, the defect itself. A budget that holds six of fourteen steps
    /// must spend them on the answer's depth rather than on the focal's widest
    /// neighbours, because the deep end is where a trace stops being a list of
    /// neighbours and becomes an answer.
    #[test]
    fn narrowing_keeps_the_deep_step_a_suffix_cut_amputates() {
        let steps = breadth_first_walk(12, 2);
        let deepest = steps.last().expect("the walk has a deep end").0;

        // The premise, stated as an assertion so the test cannot pass on a
        // fixture that never had the problem: the suffix cut of the same size
        // loses the deep step.
        let suffix: Vec<u64> = steps[..6].iter().map(|step| step.0).collect();
        assert!(
            !suffix.contains(&deepest),
            "the fixture must reproduce the amputation or this proves nothing: {suffix:?}"
        );

        let kept = narrowed(&steps, 6).expect("narrowing fits inside six steps");
        let names: Vec<u64> = kept.iter().map(|step| step.0).collect();
        assert!(
            names.contains(&deepest),
            "the budget amputated the deep end instead of narrowing the fan-out: {names:?}"
        );
        assert!(kept.len() <= 6, "{names:?}");
    }

    /// Every surviving step must name a parent the caller still has, or a
    /// consumer walking `parent_step` lands on a step that is not in the array.
    #[test]
    fn a_dropped_branch_takes_its_descendants_with_it() {
        let mut steps = breadth_first_walk(8, 1);
        // A SECOND deep branch, off the last depth-1 step. Two branches reach
        // equally far, so relevance decides which is given up, and the one that
        // goes has a descendant that must go with it.
        steps.push((100, 8));
        let kept = narrowed(&steps, 2).expect("two steps is the floor, and it fits");
        let present: BTreeSet<u64> = kept.iter().map(|step| step.0).collect();
        for (step, parent) in &kept {
            assert!(
                *parent == 0 || present.contains(parent),
                "step {step} names parent {parent}, which the cut removed: {present:?}"
            );
        }
        assert!(
            !present.contains(&8),
            "the fixture must give up the less relevant of the two deep \
             branches or nothing is being tested: {present:?}"
        );
        assert!(
            !present.contains(&100),
            "the orphan outlived the branch it hung off: {present:?}"
        );
    }

    /// FIR-2642, the rule that makes the fix a rule rather than luck. The branch
    /// a node keeps is the one that reaches deepest, not the one relevance
    /// happened to list first.
    ///
    /// On the measured `psf/requests` walk the hop that carries the answer hangs
    /// off `HTTPAdapter.send`'s FIFTH child, so keeping the first child kept a
    /// branch ending at depth one and gave up the branch reaching depth three.
    /// The same query returned the hop at 129 discovered steps and lost it at
    /// 200, which is a result that depends on how big the walk happened to be.
    #[test]
    fn the_branch_a_node_keeps_is_the_one_that_reaches_deepest() {
        // Six shallow children first, then a seventh whose branch goes two
        // deeper. Relevance order puts the deep one last on purpose.
        let mut steps: Vec<(u64, u64)> = (1..=7).map(|step| (step, 0)).collect();
        steps.push((8, 7));
        steps.push((9, 8));

        let kept = narrowed(&steps, 3).expect("three steps fit");
        let present: BTreeSet<u64> = kept.iter().map(|step| step.0).collect();
        assert_eq!(
            present,
            BTreeSet::from([7, 8, 9]),
            "the node kept its shallowest branch and amputated its deepest: \
             {present:?}"
        );
    }

    /// Narrowing thins a walk; it never severs one. Asked for a budget no
    /// amount of narrowing can meet, it answers `None` so the caller falls back
    /// to the suffix cut rather than receiving a walk with no first child.
    #[test]
    fn narrowing_refuses_rather_than_severing_a_walk_it_cannot_fit() {
        let steps = breadth_first_walk(12, 2);
        // The narrowest survivor is the focal's first child and the deep branch
        // below it: three steps. One is below that floor.
        assert!(narrowed(&steps, 1).is_none(), "a walk was severed to fit");
        let floor = narrowed(&steps, 3).expect("three steps is the floor, and it fits");
        assert_eq!(
            floor.iter().map(|step| step.0).collect::<Vec<_>>(),
            vec![1, 13, 14],
            "the survivor at the floor is the first child and its descendants"
        );
    }

    /// A walk with nothing to narrow reports that, rather than returning a
    /// no-op the caller would read as a cut it did not make.
    #[test]
    fn a_walk_with_no_node_wider_than_one_child_has_nothing_to_narrow() {
        let steps = breadth_first_walk(1, 4);
        assert!(
            narrow_fanout_to_fit(
                &steps,
                &|step: &(u64, u64)| step.0,
                &|step: &(u64, u64)| Some(step.1),
                &|_step: &(u64, u64)| false,
                &mut |_kept: &[(u64, u64)]| false,
            )
            .is_none(),
            "a spine has no branch to give up"
        );
    }

    /// A branch the caller named survives the trim
    /// that gives up "least relevant" branches, and the arm beside it is what
    /// makes that mean anything: the SAME walk at the SAME budget loses that
    /// branch when nothing names it.
    ///
    /// Two branches off the focal, the second reaching deeper, so relevance
    /// order and depth order disagree and the give-up rule has a real choice to
    /// make.
    #[test]
    fn a_named_branch_survives_a_trim_that_drops_it_unnamed() {
        // Focal 0 with three children; the FIRST is a leaf, so the give-up rule
        // sheds it first, and the target hangs under it.
        let steps: Vec<(u64, u64)> = vec![
            (1, 0),
            (2, 0),
            (3, 0),
            (4, 1), // the target, under the shallowest child
            (5, 2),
            (6, 5),
            (7, 3),
            (8, 7),
        ];

        // The premise, asserted rather than assumed: unnamed, this budget loses
        // the step. A fixture that never lost it would make the named half pass
        // against a tool that does nothing.
        let unnamed = narrowed(&steps, 5).expect("the unnamed walk narrows");
        let unnamed_ids: Vec<u64> = unnamed.iter().map(|step| step.0).collect();
        assert!(
            !unnamed_ids.contains(&4),
            "the fixture no longer drops step 4 unnamed, so naming it proves nothing: \
             {unnamed_ids:?}"
        );

        let named = narrowed_keeping(&steps, 4, 5).expect("the named walk narrows");
        let named_ids: Vec<u64> = named.iter().map(|step| step.0).collect();
        assert!(
            named_ids.contains(&4),
            "the named step was given up as least relevant: {named_ids:?}"
        );
        assert!(
            named_ids.contains(&1),
            "the named step survived without the step that introduced it, so its \
             parent_step names a step the caller no longer has: {named_ids:?}"
        );
        assert!(
            named.len() < steps.len(),
            "protecting one branch stopped the trim from cutting anything at all, \
             which is an elision that can never fire: {named_ids:?}"
        );
    }

    /// Protection is a preference, not a refusal. A budget too small to hold the
    /// named branch still gets an answer rather than falling through to the
    /// suffix cut, which loses the far end of every branch including that one.
    #[test]
    fn a_budget_too_small_for_the_named_branch_still_narrows() {
        let steps: Vec<(u64, u64)> = vec![(1, 0), (2, 0), (3, 0), (4, 1), (5, 2), (6, 5)];
        let named = narrowed_keeping(&steps, 4, 2)
            .expect("a budget that cannot hold the named branch must still narrow, not refuse");
        assert!(
            named.len() <= 2,
            "protecting the named branch still left an answer inside the budget: {named:?}"
        );
    }

    /// The give-up fallback, on the only shape that reaches it.
    ///
    /// The test above cannot reach it, and its old message claimed otherwise.
    /// Protecting a target protects its ancestry, and when what fits is counted
    /// in STEPS that ancestry is never larger than the deepest spine the
    /// keep-one-child floor would hold anyway, so the first pass always has an
    /// answer and the second pass is unreachable. Deleting the fallback leaves
    /// every count-based test green.
    ///
    /// A real budget is not a count. It is serialized size, and a shallow
    /// branch of fat steps can cost more than a deeper branch of thin ones. So
    /// depth decides which branch the floor holds and cost decides what fits,
    /// and here the two disagree on purpose: the named target sits in the
    /// shallow expensive branch, and holding it cannot fit at any price the
    /// first pass can pay.
    #[test]
    fn a_protected_branch_too_expensive_to_hold_is_given_up_rather_than_refused() {
        // Two branches under the focal: `1 -> 2` is shallow and expensive and
        // holds the target, `5 -> 6 -> 7` is deeper and cheap.
        let steps: Vec<(u64, u64)> = vec![(1, 0), (2, 1), (5, 0), (6, 5), (7, 6)];
        const TARGET: u64 = 2;
        const BUDGET: usize = 5;
        let weight = |id: u64| -> usize {
            if id == 1 || id == TARGET {
                10
            } else {
                1
            }
        };
        let cost = |kept: &[(u64, u64)]| -> usize { kept.iter().map(|step| weight(step.0)).sum() };

        // The premise, asserted rather than assumed: the protected branch alone
        // is already over budget, so the first pass has nothing it can return.
        // Without this the test would pass on a fixture that never reached the
        // second pass at all, which is exactly how the sibling above read as
        // covered.
        assert!(
            weight(1) + weight(TARGET) > BUDGET,
            "the protected branch must not fit, or the first pass answers and this grades nothing"
        );

        let narrowed = narrow_fanout_to_fit(
            &steps,
            &|step: &(u64, u64)| step.0,
            &|step: &(u64, u64)| Some(step.1),
            &|step: &(u64, u64)| step.0 == TARGET,
            &mut |kept: &[(u64, u64)]| cost(kept) <= BUDGET,
        );

        // Read as an assertion rather than an expect, so deleting the fallback
        // fails HERE by name instead of panicking somewhere downstream.
        assert!(
            narrowed.is_some(),
            "protection is a preference, not a refusal: a budget too small to hold the named \
             branch must still come back with a narrowed answer"
        );
        let kept = narrowed.expect("asserted present above");
        let ids: Vec<u64> = kept.iter().map(|step| step.0).collect();
        assert!(
            cost(&kept) <= BUDGET,
            "the answer must fit the budget it was given: {ids:?} costs {}",
            cost(&kept)
        );
        assert!(
            !ids.contains(&TARGET),
            "the second pass gives the protection up, so the target cannot still be here: {ids:?}"
        );
    }

    /// The fewest drops that fit, not the first that does. A caller who raises
    /// `max_response_chars` by a little must get back more of the chain, and a
    /// greedy cut that overshot would hand back the same short answer.
    #[test]
    fn narrowing_gives_up_the_fewest_branches_that_fit() {
        let steps = breadth_first_walk(12, 2);
        let roomy = narrowed(&steps, 13).expect("thirteen of fourteen steps fit");
        assert_eq!(
            roomy.len(),
            13,
            "one branch was enough, so only one may go: {roomy:?}"
        );
    }

    /// The generic trimmer's own half of FIR-2642. A collection whose entries
    /// name a parent is a tree, and this stage used to take its tail, which on
    /// a real response landed on top of the walk's own cut and took the deep
    /// end twice.
    #[test]
    fn the_trimmer_narrows_a_parented_collection_and_keeps_its_deep_entry() {
        let steps = breadth_first_walk(12, 2);
        let deepest = steps.last().expect("a deep end").0;
        let entries: Vec<Value> = steps
            .iter()
            .map(|(step, parent)| {
                json!({"step": step, "parent_step": parent, "pad": "p".repeat(400)})
            })
            .collect();
        let mut payload = json!({"chain": entries});
        let target = measure(&payload) / 2;

        let (withheld, shape) = trim_collection(&mut payload, "chain", target, 1);

        assert_eq!(
            shape,
            CutShape::Branches,
            "a parented collection must be narrowed, not cut"
        );
        assert!(withheld > 0, "the fixture must reach the cut");
        let kept: Vec<u64> = payload["chain"]
            .as_array()
            .expect("chain survives")
            .iter()
            .map(|entry| entry["step"].as_u64().unwrap_or(0))
            .collect();
        assert!(
            kept.contains(&deepest),
            "the trimmer amputated the deep end instead of narrowing: {kept:?}"
        );
        assert!(measure(&payload) <= target, "{kept:?}");
        assert_eq!(payload["chain_withheld"], json!(withheld));
    }

    /// The direction that keeps the branch meaningful: a flat collection has no
    /// parents to reason about, so it still takes the suffix cut and still says
    /// so.
    #[test]
    fn the_trimmer_still_cuts_a_flat_collection_from_its_tail() {
        let entries: Vec<Value> = (0..40)
            .map(|index| json!({"name": format!("hit_{index}"), "pad": "p".repeat(400)}))
            .collect();
        let mut payload = json!({"entities": entries});
        let target = measure(&payload) / 2;

        let (withheld, shape) = trim_collection(&mut payload, "entities", target, 1);

        assert!(withheld > 0, "the fixture must reach the cut");
        assert_eq!(
            shape,
            CutShape::Suffix,
            "a collection with no parents cannot be narrowed by branch"
        );
        let kept = payload["entities"].as_array().expect("entities survive");
        assert_eq!(
            kept.first().and_then(|entry| entry["name"].as_str()),
            Some("hit_0"),
            "a suffix cut keeps the front"
        );
    }

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
        let next_cursor = LocateCursor {
            key: "deadbeefdeadbeef".to_string(),
            page: 1,
            next_offset: Some(hits),
            page_size: Some(hits.max(1)),
        }
        .encode();
        json!({
            "query": "where redirects are resolved",
            "entities": entities,
            "files": files,
            "total_ranked": hits,
            "next_cursor": next_cursor,
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

    /// One `trace_data_flow` chain, wide and shallow, with `target_name` echoing
    /// a step the walk reached. Named after the shape the rc061y stranger hit.
    fn targeted_chain_payload(width: usize, target_step: usize) -> Value {
        let chain: Vec<Value> = (1..=width)
            .map(|step| {
                json!({
                    "step": step,
                    "parent_step": 0,
                    "depth": 1,
                    "entity_id": format!("id-{step}"),
                    "entity_name": format!("Neighbour.call_{step}"),
                    "relation_kind": "Calls",
                    "resolution": "type_resolved",
                    "file_path": format!("src/module_{step}.py"),
                    "signature": "def call(self, request, stream=False, timeout=None): ...",
                    "fanout_truncated": false,
                    "fanout_dropped": 0,
                    "terminal": null,
                })
            })
            .collect();
        json!({
            "focal_name": "Session.send",
            "target_name": format!("Neighbour.call_{target_step}"),
            "total_steps": width,
            "chain": chain,
        })
    }

    /// At the surface a caller reads, the sentence is COMPOSED from
    /// clauses and joined, so it is probed rather than reasoned about: reading
    /// the code says what each clause holds, and only printing the join says
    /// what a caller receives.
    #[test]
    fn a_bounded_trace_says_it_kept_the_branch_the_caller_named() {
        const BUDGET: usize = 4_000;
        // The target sits LAST, which is where relevance order puts the branch
        // it is most willing to give up.
        let mut payload = targeted_chain_payload(40, 40);
        assert!(
            measure(&payload) > BUDGET,
            "the fixture must overflow or nothing is trimmed"
        );
        let budget = ResponseBudget {
            max_chars: BUDGET,
            ..ResponseBudget::default()
        };
        enforce(&mut payload, "trace_data_flow", &budget).expect("trace_data_flow is budgeted");

        let kept: Vec<String> = payload["chain"]
            .as_array()
            .expect("chain survives")
            .iter()
            .filter_map(|entry| entry["entity_name"].as_str().map(str::to_string))
            .collect();
        assert!(
            kept.contains(&"Neighbour.call_40".to_string()),
            "the trim gave up the branch the caller named: {kept:?}"
        );
        assert!(
            kept.len() < 40,
            "nothing was trimmed, so this grades an elision that never fired: {kept:?}"
        );

        let detail = payload["degradations"]
            .as_array()
            .expect("a cut is disclosed")
            .iter()
            .filter(|cut| cut["reason"] == json!(BOUNDED_REASON))
            .filter_map(|cut| cut["detail"].as_str())
            .next()
            .expect("the bounded cut carries a detail")
            .to_string();
        // Printed, not merely asserted: the composed sentence is the artifact.
        println!("composed disclosure: {detail}");
        assert!(
            detail.contains("keeping the branch that reaches the named target"),
            "the disclosure does not say the named branch was held: {detail}"
        );
        assert!(
            !CutShape::BranchesKeepingTarget.phrase().contains("; "),
            "a clause carrying the separator its own join uses splits itself apart"
        );
    }

    /// The control, and the half that makes the test above mean anything. The
    /// same chain at the same budget, with no target named, still gives up its
    /// last branch and says so in the words it always did. An elision that can
    /// never drop anything is a check that cannot fail.
    #[test]
    fn an_unnamed_trace_still_elides_least_relevant_first() {
        const BUDGET: usize = 4_000;
        let mut payload = targeted_chain_payload(40, 40);
        payload
            .as_object_mut()
            .expect("payload is an object")
            .remove("target_name");
        let budget = ResponseBudget {
            max_chars: BUDGET,
            ..ResponseBudget::default()
        };
        enforce(&mut payload, "trace_data_flow", &budget).expect("trace_data_flow is budgeted");

        let kept: Vec<String> = payload["chain"]
            .as_array()
            .expect("chain survives")
            .iter()
            .filter_map(|entry| entry["entity_name"].as_str().map(str::to_string))
            .collect();
        assert!(
            !kept.contains(&"Neighbour.call_40".to_string()),
            "the unnamed walk kept the last branch anyway, so the named half above \
             proves nothing: {kept:?}"
        );
        let detail = payload["degradations"]
            .as_array()
            .expect("a cut is disclosed")
            .iter()
            .filter(|cut| cut["reason"] == json!(BOUNDED_REASON))
            .filter_map(|cut| cut["detail"].as_str())
            .next()
            .expect("the bounded cut carries a detail")
            .to_string();
        assert!(
            !detail.contains("keeping the branch that reaches the named target"),
            "a walk that named no target claims to have held one: {detail}"
        );
    }

    /// A target the walk never reached protects nothing, which is the case that
    /// separates "the question steered the trim" from "the trim stopped
    /// trimming". Named but absent, the chain sheds exactly as the unnamed one
    /// does.
    #[test]
    fn a_target_the_walk_never_reached_protects_nothing() {
        const BUDGET: usize = 4_000;
        let mut payload = targeted_chain_payload(40, 40);
        payload["target_name"] = json!("HTTPAdapter.never_walked");
        let budget = ResponseBudget {
            max_chars: BUDGET,
            ..ResponseBudget::default()
        };
        enforce(&mut payload, "trace_data_flow", &budget).expect("trace_data_flow is budgeted");
        let kept: Vec<String> = payload["chain"]
            .as_array()
            .expect("chain survives")
            .iter()
            .filter_map(|entry| entry["entity_name"].as_str().map(str::to_string))
            .collect();
        assert!(
            !kept.contains(&"Neighbour.call_40".to_string()),
            "an unreached target changed what the trim kept: {kept:?}"
        );
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
            let cursor = LocateCursor::decode(payload["next_cursor"].as_str().unwrap())
                .expect("a fused locate cut keeps a followable cursor");
            assert_eq!(cursor.next_offset, Some(kept));
            assert_eq!(cursor.page_size, Some(kept));
        }
        assert_eq!(
            payload["total_ranked"],
            json!(40),
            "the full ranking size is still reported"
        );
    }

    fn cosine_locate_payload(hits: usize) -> Value {
        let cursor = LocateCursor {
            key: "cosine-ranking".to_string(),
            page: 1,
            next_offset: Some(hits),
            page_size: Some(hits.max(1)),
        }
        .encode();
        json!({
            "query": "where redirects are resolved",
            "routing": "cosine-v0",
            "results": (0..hits).map(|index| json!({
                "entity_id": format!("00000000-0000-0000-0000-{index:012}"),
                "name": format!("handler_{index}_{}", "x".repeat(500)),
                "kind": "function",
                "score": 0.5,
                "provenance": { "file": format!("src/f{index}.rs") },
            })).collect::<Vec<_>>(),
            "files": [],
            "total_ranked": hits,
            "next_cursor": cursor,
        })
    }

    fn file_locate_payload(files: usize, symbols_per_file: usize) -> Value {
        let cursor = LocateCursor {
            key: "file-ranking".to_string(),
            page: 1,
            next_offset: Some(files),
            page_size: Some(files.max(1)),
        }
        .encode();
        json!({
            "query": "where redirects are resolved",
            "granularity": "file",
            "routing": "fused-v1",
            "files": (0..files).map(|index| json!({
                "path": format!("src/f{index}.rs"),
                "score": 0.5,
                "signals": ["vector", "lexical"],
                "symbols": (0..symbols_per_file).map(|symbol| json!({
                    "name": format!("symbol_{index}_{symbol}_{}", "x".repeat(80)),
                    "kind": "function",
                    "score": 0.4,
                    "span": [1, 40],
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "total_ranked": files,
            "next_cursor": cursor,
        })
    }

    #[test]
    fn file_primary_budget_keeps_unique_symbol_detail_and_rebases_files() {
        let found = 12usize;
        let mut payload = file_locate_payload(found, 8);
        let budget = ResponseBudget {
            max_chars: 7_000,
            ..ResponseBudget::default()
        };
        enforce(&mut payload, "semantic_locate", &budget).expect("budgeted");

        let kept = payload["files"].as_array().unwrap().len();
        assert!(
            kept > 0 && kept < found,
            "fixture must trim file rows: {payload}"
        );
        assert!(
            payload["files"].as_array().unwrap().iter().all(|file| file
                .get("symbols")
                .and_then(Value::as_array)
                .is_some_and(|symbols| !symbols.is_empty())),
            "file-primary symbols are answer detail, not a duplicate roll-up: {payload}"
        );
        let cursor = LocateCursor::decode(payload["next_cursor"].as_str().unwrap())
            .expect("file cursor remains followable");
        assert_eq!(cursor.next_offset, Some(kept));
        assert_eq!(cursor.page_size, Some(kept));
        assert!(payload["degradations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| !entry["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("per-file symbol roll-up dropped")));
    }

    #[test]
    fn empty_fused_entity_primary_does_not_relabel_secondary_files_as_primary() {
        let mut payload = json!({
            "query": "where redirects are resolved",
            "routing": "fused-v1",
            "granularity": "entity",
            // LocateResult omits its empty entities array, while this secondary
            // roll-up remains present.
            "files": [{
                "path": "src/lib.rs",
                "score": 0.9,
                "symbols": (0..120).map(|index| json!({
                    "name": format!("secondary_symbol_{index}_{}", "x".repeat(80)),
                    "kind": "function",
                    "score": 0.8,
                    "span": [1, 20],
                })).collect::<Vec<_>>(),
            }],
            "total_ranked": 0,
            "next_cursor": Value::Null,
        });
        let without_symbols = {
            let mut candidate = payload.clone();
            candidate["files"][0]
                .as_object_mut()
                .unwrap()
                .remove("symbols");
            measure(&candidate)
        };
        let budget = ResponseBudget {
            max_chars: without_symbols + RESPONSE_DISCLOSURE_RESERVE_CHARS,
            ..ResponseBudget::default()
        };
        assert!(measure(&payload) > budget.max_chars);

        enforce(&mut payload, "semantic_locate", &budget).expect("budgeted");

        assert!(
            payload["files"][0].get("symbols").is_none(),
            "entity granularity may shed its secondary roll-up: {payload}"
        );
        let disclosure = payload["degradations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["reason"] == BOUNDED_REASON)
            .and_then(|entry| entry["detail"].as_str())
            .expect("secondary cut is disclosed");
        assert!(
            disclosure.contains("primary `entities` ranking remains unchanged"),
            "{disclosure}"
        );
    }

    #[test]
    fn cosine_rows_are_budgeted_and_rebase_the_followable_cursor() {
        let found = 30usize;
        let mut payload = cosine_locate_payload(found);
        let budget = ResponseBudget {
            max_chars: 4_000,
            ..ResponseBudget::default()
        };
        enforce(&mut payload, "semantic_locate", &budget).expect("budgeted");
        let kept = payload["results"].as_array().unwrap().len();
        assert!(
            kept > 0 && kept < found,
            "fixture must force a row cut: {payload}"
        );
        let cursor = LocateCursor::decode(payload["next_cursor"].as_str().unwrap())
            .expect("budget leaves a valid cursor");
        assert_eq!(cursor.next_offset, Some(kept));
        assert_eq!(cursor.page_size, Some(kept));
        let emitted = payload["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["entity_id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        let resumed = (kept..(kept + kept).min(found))
            .map(|index| format!("00000000-0000-0000-0000-{index:012}"))
            .collect::<Vec<_>>();
        assert!(
            emitted.iter().all(|id| !resumed.contains(id)),
            "the rebased continuation must not repeat a row already emitted"
        );
        assert_eq!(
            emitted
                .iter()
                .chain(resumed.iter())
                .cloned()
                .collect::<Vec<_>>(),
            (0..(kept + kept).min(found))
                .map(|index| format!("00000000-0000-0000-0000-{index:012}"))
                .collect::<Vec<_>>(),
            "budget trimming and continuation must cover one contiguous prefix without gaps"
        );
        assert_eq!(payload["elisions"]["results"]["kept"], json!(kept));
        assert!(payload["degradations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["remediation"]
                .as_str()
                .is_some_and(|text| text.contains("follow `next_cursor`"))));
    }

    #[test]
    fn a_second_budget_pass_rebases_from_the_first_pass_offset() {
        let mut payload = cosine_locate_payload(40);
        let first_budget = ResponseBudget {
            max_chars: 8_000,
            ..ResponseBudget::default()
        };
        enforce(&mut payload, "semantic_locate", &first_budget).expect("first pass");
        let first_kept = payload["results"].as_array().unwrap().len();
        let first_cursor = LocateCursor::decode(payload["next_cursor"].as_str().unwrap()).unwrap();
        assert_eq!(first_cursor.next_offset, Some(first_kept));

        let second_budget = ResponseBudget {
            max_chars: 3_000,
            ..ResponseBudget::default()
        };
        enforce(&mut payload, "semantic_locate", &second_budget).expect("second pass");
        let second_kept = payload["results"].as_array().unwrap().len();
        assert!(
            second_kept < first_kept,
            "second pass must cut again: {payload}"
        );
        let second_cursor = LocateCursor::decode(payload["next_cursor"].as_str().unwrap()).unwrap();
        assert_eq!(second_cursor.next_offset, Some(second_kept));
        assert_eq!(second_cursor.page_size, Some(second_kept));
    }

    #[test]
    fn cosine_duplicate_rollup_disclosure_names_results_not_absent_entities() {
        let mut payload = cosine_locate_payload(2);
        payload["files"] = json!([{
            "path": "src/lib.rs",
            "score": 0.9,
            "symbols": (0..120).map(|index| json!({
                "name": format!("duplicate_symbol_{index}_{}", "x".repeat(80)),
                "kind": "function",
                "score": 0.8,
                "span": [1, 20],
            })).collect::<Vec<_>>(),
        }]);
        let without_symbols = {
            let mut candidate = payload.clone();
            candidate["files"][0]
                .as_object_mut()
                .unwrap()
                .remove("symbols");
            measure(&candidate)
        };
        let budget = ResponseBudget {
            max_chars: without_symbols + RESPONSE_DISCLOSURE_RESERVE_CHARS,
            ..ResponseBudget::default()
        };
        assert!(measure(&payload) > budget.max_chars);
        enforce(&mut payload, "semantic_locate", &budget).expect("budgeted");
        let disclosure = payload["degradations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["reason"] == BOUNDED_REASON)
            .and_then(|entry| entry["detail"].as_str())
            .expect("duplicate rollup cut is disclosed");
        assert!(
            disclosure.contains("primary `results` ranking remains unchanged"),
            "{disclosure}"
        );
        assert!(!disclosure.contains("primary `entities`"), "{disclosure}");
    }

    /// A final page is still bound by the ceiling, and says what it withheld.
    ///
    /// `max_chars` is the caller's context budget, so a page with no cursor does
    /// not get to exceed it. What a final page owes instead is honesty about the
    /// cut: at least one entry survives per list, the elision is published, and
    /// the remedy names the ceiling rather than a `next_cursor` it does not
    /// have. The earlier contract kept the rows and shipped over budget, which
    /// took `response_budget:3` to UNREADABLE on main because nothing was cut.
    #[test]
    fn a_final_page_is_cut_to_its_ceiling_and_names_no_cursor_recovery() {
        let mut payload = cosine_locate_payload(20);
        payload["next_cursor"] = Value::Null;
        let before = payload["results"].as_array().unwrap().len();
        let budget = ResponseBudget {
            max_chars: RESPONSE_MIN_MAX_CHARS,
            ..ResponseBudget::default()
        };
        let accounting = enforce(&mut payload, "semantic_locate", &budget).expect("budgeted");
        let kept = payload["results"].as_array().unwrap().len();
        assert!(
            kept < before,
            "a final page over its ceiling must still be cut: kept {kept} of {before}"
        );
        assert!(
            kept >= 1,
            "the cut must leave an entry rather than an empty array"
        );
        assert!(
            accounting.chars_after <= budget.max_chars,
            "a final page must not ship over its ceiling: {} against {}",
            accounting.chars_after,
            budget.max_chars
        );
        let elisions = payload["elisions"]["results"]
            .as_object()
            .expect("the cut list publishes its elision");
        assert_eq!(elisions["kept"].as_u64().unwrap() as usize, kept);
        assert_eq!(elisions["elided"].as_u64().unwrap() as usize, before - kept);
        let remediations = payload["degradations"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|entry| entry["remediation"].as_str())
            .collect::<Vec<_>>();
        assert!(
            remediations
                .iter()
                .all(|remedy| !remedy.contains("follow `next_cursor`")),
            "a final page cannot offer cursor recovery: {remediations:?}"
        );
        // `max_chars` alone is not evidence this branch ran. The residual
        // disclosure names it too, so a bare substring test is satisfied by a
        // producer this assertion is not about, and the mutation that deletes
        // the branch survived exactly that test. Key on the clause only the cut
        // disclosure writes.
        assert!(
            remediations.iter().any(|remedy| {
                remedy.contains("raise `max_chars`")
                    && remedy.contains("cannot be reached by paging")
            }),
            "the cut disclosure itself must name the ceiling and say why paging cannot reach \
             the withheld rows: {remediations:?}"
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

    /// An impact response shaped the way the measured one was: every
    /// `affected_*` bucket genuinely empty, and every byte of the payload in the
    /// per-entity attribution, the changed-id echo and the actor attribution.
    ///
    /// That shape is what an `impact_analysis` over a wide diff returns. The
    /// blast-radius buckets can be empty and the report still runs to tens of
    /// thousands of characters, because `entity_impacts` carries one row per
    /// changed entity and each row carries its consumer files.
    fn impact_payload_bulk_outside_the_buckets(rows: usize) -> Value {
        let entity_id = |index: usize| format!("9b9f577c-2cb3-43fd-a59b-ced58218{index:04}");
        json!({
            "affected_callers": [],
            "affected_dependents": [],
            "affected_contract_consumers": [],
            "affected_tests": [],
            "affected_work_items": [],
            "affected_annotations": [],
            "changed_ids": (0..rows).map(entity_id).collect::<Vec<_>>(),
            "unreviewed_agent_changes": (0..rows / 2).map(entity_id).collect::<Vec<_>>(),
            "actor_attribution": (0..rows)
                .map(|index| json!([entity_id(index), "Assistant"]))
                .collect::<Vec<_>>(),
            "entity_impacts": (0..rows)
                .map(|index| json!({
                    "entity_id": entity_id(index),
                    "consumer_count": index % 7,
                    "strong_consumer_count": index % 5,
                    "proven_consumer_count": index % 3,
                    "contract_consumer_count": 0,
                    "consumer_files": (0..6)
                        .map(|file| format!(
                            "src/requests/adapters/session_{index}_{file}.py"
                        ))
                        .collect::<Vec<_>>(),
                    "covering_tests": index % 4,
                    "consumers_migrated_in_diff": 0,
                    "call_shapes": {
                        "caller_keyword_names": ["stream", "timeout", "verify"],
                        "any_var_keyword_caller": false,
                        "all_consumers_shaped_calls": true,
                    },
                }))
                .collect::<Vec<_>>(),
        })
    }

    /// FIR-2602. The shape table listed only the four blast-radius buckets, so a
    /// report whose bulk sits anywhere else walked every rung of the ladder
    /// untouched: nothing was stripped, nothing was trimmed, and the accounting
    /// reported `bounded: false` on a payload 25 times over its ceiling. Measured
    /// through MCP on a build carrying kin#1062 as `{"bounded": false,
    /// "chars_before_budget": 50354, "max_chars": 2000}` with all four buckets
    /// genuinely empty.
    ///
    /// Both ceilings are asserted, because they prove different halves. At the
    /// 2,000 the measured call used, twelve lists each keeping their floor entry
    /// cannot fit and the response says so rather than shipping quiet. At a
    /// ceiling a real call gets, the same report fits inside it.
    #[test]
    fn impact_bulk_outside_the_blast_radius_buckets_is_counted_and_bounded() {
        const FLOOR: usize = RESPONSE_MIN_MAX_CHARS;
        let mut payload = impact_payload_bulk_outside_the_buckets(60);
        let before = measure(&payload);
        assert!(
            before > FLOOR * 10,
            "the fixture must reproduce the measured overrun, not a near miss: {before}"
        );
        for bucket in [
            "affected_callers",
            "affected_dependents",
            "affected_contract_consumers",
            "affected_tests",
        ] {
            assert!(
                payload[bucket].as_array().expect("bucket").is_empty(),
                "the measured response had every blast-radius bucket empty"
            );
        }

        let budget = ResponseBudget {
            max_chars: FLOOR,
            ..ResponseBudget::default()
        };
        let accounting = enforce(&mut payload, "impact_analysis", &budget).expect("budgeted");
        assert_eq!(accounting.chars_before, before);
        assert_eq!(
            accounting.chars_after,
            measure(&payload),
            "the accounting must report the size the response actually shipped at"
        );
        assert!(
            accounting.bounded,
            "a response the budget had to cut cannot report itself unbounded: {payload}"
        );
        assert!(
            accounting.chars_after < before / 10,
            "the widened table must count the bulk it could not see before: \
             {before} to {}",
            accounting.chars_after
        );
        // Twelve lists at their floor plus the disclosure do not fit 2,000, and
        // that is the one outcome that must never be silent.
        assert!(
            accounting.chars_after > budget.max_chars,
            "this assertion guards the branch below; a fit here means the fixture changed"
        );
        let residual = payload["degradations"]
            .as_array()
            .expect("a cut is disclosed")
            .iter()
            .find(|entry| entry["reason"] == json!(OVER_BUDGET_REASON));
        assert!(
            residual.is_some(),
            "a response still over its ceiling must say so: {payload}"
        );

        // The same report at a ceiling a real call gets fits inside it.
        let mut payload = impact_payload_bulk_outside_the_buckets(60);
        let budget = ResponseBudget::default();
        let accounting = enforce(&mut payload, "impact_analysis", &budget).expect("budgeted");
        assert!(
            accounting.chars_after <= budget.max_chars,
            "the response shipped {} characters against a {} ceiling: {payload}",
            accounting.chars_after,
            budget.max_chars
        );
        assert!(
            payload["degradations"]
                .as_array()
                .map_or(true, |entries| entries
                    .iter()
                    .all(|entry| entry["reason"] != json!(OVER_BUDGET_REASON))),
            "a response that reached its ceiling must not claim it did not: {payload}"
        );
    }

    /// Two arms bound one response. The daemon's raw route cuts first and the
    /// stdio path cuts again, and only the second arm's accounting reaches
    /// `_kin.response`. Measured on the release binary at `max_chars: 2000`: the
    /// first arm cut the report to its floor, the second found nothing left to
    /// trim, and the response shipped `bounded: false` at 13,232 characters with
    /// a fully populated `elisions` map sitting beside it.
    ///
    /// The accounting is about the response, not about one pass over it.
    #[test]
    fn a_second_pass_reports_the_cut_the_first_pass_made() {
        const FIRST: usize = 6_000;
        const SECOND: usize = 8_000;
        let mut payload = impact_payload(40);
        let built_at = measure(&payload);

        let first = ResponseBudget {
            max_chars: FIRST,
            ..ResponseBudget::default()
        };
        let cut = enforce(&mut payload, "impact_analysis", &first).expect("budgeted");
        assert!(
            cut.bounded,
            "the first arm must cut, or this proves nothing"
        );
        assert_eq!(cut.chars_before, built_at);

        // The second arm's ceiling is looser than what the first already
        // enforced, so it has nothing of its own to do. That is exactly the
        // shape that reported a whole answer.
        let second = ResponseBudget {
            max_chars: SECOND,
            ..ResponseBudget::default()
        };
        let again = enforce(&mut payload, "impact_analysis", &second).expect("budgeted");
        assert!(
            again.chars_after <= SECOND,
            "the second arm found nothing to cut, or this proves nothing"
        );
        assert!(
            again.bounded,
            "a response the first arm cut cannot report itself whole: {payload}"
        );
        assert_eq!(
            again.chars_before, built_at,
            "the second arm must report the size the answer was built at, not the size \
             it inherited"
        );
        assert!(
            payload["elisions"]
                .as_object()
                .is_some_and(|map| !map.is_empty()),
            "the cut the first arm disclosed must still be readable: {payload}"
        );
    }

    /// A response still over its ceiling says so once, however many arms reach
    /// that conclusion. Two copies of the same sentence spend the budget they
    /// are complaining about, and the release binary published two.
    #[test]
    fn a_response_over_its_ceiling_says_so_once() {
        const FLOOR: usize = RESPONSE_MIN_MAX_CHARS;
        let budget = ResponseBudget {
            max_chars: FLOOR,
            ..ResponseBudget::default()
        };
        let mut payload = impact_payload_bulk_outside_the_buckets(60);
        for pass in 0..3 {
            let accounting = enforce(&mut payload, "impact_analysis", &budget).expect("budgeted");
            assert!(
                accounting.chars_after > FLOOR,
                "pass {pass} must stay over the ceiling, or this proves nothing"
            );
            let notes = payload["degradations"]
                .as_array()
                .expect("a cut is disclosed")
                .iter()
                .filter(|entry| entry["reason"] == json!(OVER_BUDGET_REASON))
                .count();
            assert_eq!(notes, 1, "pass {pass} left {notes} copies: {payload}");
        }
    }

    /// The residual note is withdrawn when a later arm clears the ceiling the
    /// earlier one missed. The first arm cuts under the budget less the envelope
    /// reserve, so it can miss a ceiling the second arm clears once the envelope
    /// that lands is smaller than the reserve held back for it. A note saying
    /// the response did not fit, on a response that does, is the same false
    /// report in reverse.
    #[test]
    fn a_residual_note_is_withdrawn_by_an_arm_that_fits() {
        let mut payload = impact_payload_bulk_outside_the_buckets(60);
        let tight = ResponseBudget {
            max_chars: RESPONSE_MIN_MAX_CHARS,
            ..ResponseBudget::default()
        };
        let cut = enforce(&mut payload, "impact_analysis", &tight).expect("budgeted");
        assert!(
            cut.chars_after > tight.max_chars,
            "the first arm must miss its ceiling, or this proves nothing"
        );
        assert!(
            has_residual(&payload),
            "the first arm must have left a note: {payload}"
        );

        let loose = ResponseBudget {
            max_chars: 20_000,
            ..ResponseBudget::default()
        };
        let again = enforce(&mut payload, "impact_analysis", &loose).expect("budgeted");
        assert!(
            again.chars_after <= loose.max_chars,
            "the second arm must clear its ceiling, or this proves nothing"
        );
        assert!(
            !has_residual(&payload),
            "a response that fits must not claim it does not: {payload}"
        );
        assert!(
            again.bounded,
            "the cut the first arm made is still a cut: {payload}"
        );
    }

    fn has_residual(payload: &Value) -> bool {
        payload
            .get("degradations")
            .and_then(Value::as_array)
            .is_some_and(|entries| {
                entries
                    .iter()
                    .any(|entry| entry["reason"] == json!(OVER_BUDGET_REASON))
            })
    }

    /// The elision half of the same case: the widened table must cut with counts
    /// rather than by emptying, on every list it newly reaches.
    #[test]
    fn a_widened_impact_table_elides_with_counts_and_empties_nothing() {
        const BUDGET: usize = 2_000;
        let mut payload = impact_payload_bulk_outside_the_buckets(60);
        let found: Vec<(String, usize)> = payload
            .as_object()
            .expect("object")
            .iter()
            .filter_map(|(key, value)| {
                value
                    .as_array()
                    .filter(|rows| !rows.is_empty())
                    .map(|rows| (key.clone(), rows.len()))
            })
            .collect();
        assert!(
            found.len() >= 3,
            "the fixture must fill several lists or this proves nothing: {found:?}"
        );
        let budget = ResponseBudget {
            max_chars: BUDGET,
            ..ResponseBudget::default()
        };
        enforce(&mut payload, "impact_analysis", &budget).expect("budgeted");

        let mut cut_any = false;
        for (key, before) in found {
            let kept = payload[&key].as_array().expect("list survives").len();
            assert!(
                kept > 0,
                "`{key}` was emptied by the budget, which reads as \"the walk found none\": \
                 {payload}"
            );
            if kept == before {
                continue;
            }
            cut_any = true;
            let elision = &payload["elisions"][&key];
            assert_eq!(elision["kept"], json!(kept), "{payload}");
            assert_eq!(elision["elided"], json!(before - kept), "{payload}");
            assert_eq!(elision["total"], json!(before), "{payload}");
            assert_eq!(elision["reason"], json!(ELISION_REASON_BUDGET), "{payload}");
        }
        assert!(
            cut_any,
            "a 2000-character ceiling must have cut something: {payload}"
        );
    }

    /// The invariant the two tests above are instances of, held across every
    /// budgeted tool rather than on one fixture: an accounting that reports
    /// `bounded: false` is asserting the response fits, so it must fit.
    ///
    /// This is the check that would have caught FIR-2602 in any tool, because
    /// the defect was never about impact reports. It was about a shape table
    /// that could fall behind the payload it describes without anything saying
    /// so.
    #[test]
    fn an_unbounded_accounting_always_describes_a_response_that_fits() {
        const BUDGET: usize = 2_000;
        let budget = ResponseBudget {
            max_chars: BUDGET,
            ..ResponseBudget::default()
        };
        let cases: Vec<(&str, Value)> = vec![
            (
                "impact_analysis",
                impact_payload_bulk_outside_the_buckets(60),
            ),
            ("impact_analysis", impact_payload(33)),
            ("semantic_locate", locate_payload(30, 400)),
            ("semantic_locate", locate_payload(1, 4)),
        ];
        for (tool, mut payload) in cases {
            let accounting = enforce(&mut payload, tool, &budget).expect("budgeted");
            assert_eq!(accounting.chars_after, measure(&payload), "{tool}");
            assert!(
                accounting.bounded || accounting.chars_after <= BUDGET,
                "{tool} reported bounded false at {} characters against a {BUDGET} ceiling",
                accounting.chars_after
            );
        }
    }

    // ── The body a budget takes says so on the row (FIR-2482) ───────────

    /// A context pack of `rows` dependencies, each carrying a body, plus a
    /// focal that carries one too.
    fn pack_payload(rows: usize, body_chars: usize) -> Value {
        let dep = |index: usize| {
            json!({
                "id": format!("00000000-0000-0000-0000-{index:012}"),
                "name": format!("dep_{index}"),
                "kind": "function",
                "signature": format!("fn dep_{index}()"),
                "file_path": format!("src/f{index}.rs"),
                "start_line": 1,
                "end_line": 40,
                "body": "x".repeat(body_chars),
            })
        };
        json!({
            "focal_entity": {
                "id": "00000000-0000-0000-0000-ffffffffffff",
                "name": "focal",
                "body": "y".repeat(body_chars),
            },
            "dependencies": (0..rows).map(dep).collect::<Vec<_>>(),
            "dependents": [],
            "token_budget": 16000,
        })
    }

    /// Every row of every listed collection, plus the focal, as objects.
    fn rows_of(payload: &Value, keys: &[&str]) -> Vec<Map<String, Value>> {
        let mut rows: Vec<Map<String, Value>> = keys
            .iter()
            .filter_map(|key| payload.get(*key))
            .filter_map(Value::as_array)
            .flat_map(|entries| entries.iter().filter_map(Value::as_object).cloned())
            .collect();
        if let Some(focal) = payload.get("focal_entity").and_then(Value::as_object) {
            rows.push(focal.clone());
        }
        rows
    }

    #[test]
    fn a_row_whose_body_the_budget_took_says_so() {
        let mut payload = pack_payload(24, 900);
        // Sized so shedding the bodies alone brings the response under, and the
        // ladder never reaches the rung that withholds rows. Both cuts are real
        // and both are disclosed, but mixing them here would leave the row
        // count and the body count describing different populations, and this
        // test is about the rows that stayed.
        let budget = ResponseBudget {
            max_chars: 12_000,
            ..ResponseBudget::default()
        };
        enforce(&mut payload, "get_context_pack", &budget).expect("get_context_pack is budgeted");
        assert_eq!(
            payload["dependencies"].as_array().map(Vec::len),
            Some(24),
            "the body rung alone must have sufficed: {payload}"
        );

        let rows = rows_of(&payload, &["dependencies"]);
        assert_eq!(rows.len(), 25, "24 dependencies and the focal: {payload}");
        for row in &rows {
            // Removing the key outright is the shape of a `compact: true` call
            // and of an entity whose source the graph does not hold. A row that
            // lost its body to the budget must read as neither.
            assert_eq!(
                row.get("body"),
                Some(&Value::Null),
                "a stripped body keeps its field: {payload}"
            );
            assert_eq!(
                row.get(BODY_ELIDED_KEY),
                Some(&json!(["body"])),
                "a stripped row names what the budget took: {payload}"
            );
            assert!(
                row.get("body_unavailable").is_none(),
                "a budget cut is not a graph gap, and one row cannot be both: {payload}"
            );
        }
        let elision = payload["elisions"]["body"].clone();
        assert_eq!(elision["elided"], json!(rows.len()), "{payload}");
        assert_eq!(elision["kept"], json!(0), "{payload}");
        assert_eq!(elision["reason"], json!(ELISION_REASON_BUDGET), "{payload}");
    }

    #[test]
    fn a_row_that_never_had_a_body_is_neither_marked_nor_counted() {
        let mut payload = pack_payload(24, 900);
        // One row whose source the graph genuinely does not hold, in the
        // vocabulary the pack handler uses for it.
        payload["dependencies"][0]["body"] = Value::Null;
        payload["dependencies"][0]["body_unavailable"] = json!("generated at build time");
        let budget = ResponseBudget {
            max_chars: 4_000,
            ..ResponseBudget::default()
        };
        enforce(&mut payload, "get_context_pack", &budget).expect("get_context_pack is budgeted");

        let gap = payload["dependencies"][0].clone();
        assert!(
            gap.get(BODY_ELIDED_KEY).is_none(),
            "the budget took nothing from this row and must claim nothing: {payload}"
        );
        assert_eq!(
            gap["body_unavailable"],
            json!("generated at build time"),
            "the graph gap's own reason survives: {payload}"
        );
    }

    #[test]
    fn a_whole_response_claims_no_body_elision() {
        let mut payload = pack_payload(2, 40);
        let budget = ResponseBudget {
            max_chars: RESPONSE_MAX_MAX_CHARS,
            ..ResponseBudget::default()
        };
        enforce(&mut payload, "get_context_pack", &budget).expect("get_context_pack is budgeted");
        assert!(
            payload.get(ELISIONS_KEY).is_none(),
            "nothing was withheld, so nothing may be claimed: {payload}"
        );
        assert_eq!(
            payload["dependencies"][0]["body"],
            json!("x".repeat(40)),
            "an untouched body is still its source: {payload}"
        );
    }

    #[test]
    fn two_cuts_on_one_list_add_up_rather_than_replacing_each_other() {
        // What a pack's own token budget already recorded before the response
        // budget ever sees the payload, in the shape the handler writes it.
        let mut payload = pack_payload(24, 40);
        record_elision_for(
            &mut payload,
            "dependencies",
            24,
            6,
            ELISION_REASON_TOKEN_BUDGET,
        );
        payload["dependencies_withheld"] = json!(6);

        let budget = ResponseBudget {
            max_chars: 2_500,
            ..ResponseBudget::default()
        };
        enforce(&mut payload, "get_context_pack", &budget).expect("get_context_pack is budgeted");

        let kept = payload["dependencies"].as_array().unwrap().len();
        let elision = payload["elisions"]["dependencies"].clone();
        let withheld = payload["dependencies_withheld"].as_u64().unwrap() as usize;
        assert!(
            kept < 24,
            "the response budget must cut for this test to mean anything: {payload}"
        );
        // 30 candidates existed: the 24 that reached the response and the 6 the
        // token budget already refused. Overwriting would report `total` as 24
        // and lose the earlier cause entirely.
        assert_eq!(elision["total"], json!(30), "{payload}");
        assert_eq!(elision["kept"], json!(kept), "{payload}");
        assert_eq!(elision["elided"], json!(30 - kept), "{payload}");
        assert_eq!(
            withheld,
            30 - kept,
            "the scalar and the map must agree: {payload}"
        );
        let reason = elision["reason"].as_str().unwrap();
        assert!(
            reason.contains(ELISION_REASON_TOKEN_BUDGET) && reason.contains(ELISION_REASON_BUDGET),
            "both causes survive the merge, got {reason}: {payload}"
        );
    }

    /// A list nothing was taken from must not grow an elision, whatever calls
    /// the recorder. The ladder guards this at its call site; this guards the
    /// recorder itself, so a second producer added later cannot publish a loss
    /// of zero.
    #[test]
    fn recording_a_loss_of_nothing_writes_nothing() {
        let mut payload = json!({ "entities": [] });
        record_elision(&mut payload, "entities", 0, 0);
        assert_eq!(payload, json!({ "entities": [] }), "{payload}");
        record_elision(&mut payload, "entities", 1, 2);
        assert_eq!(
            payload["elisions"]["entities"]["elided"],
            json!(2),
            "{payload}"
        );
        assert_eq!(
            payload["elisions"]["entities"]["total"],
            json!(3),
            "{payload}"
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
        const OVERFLOWED_THE_MEASURED_STORE: usize = 30_000;

        // Read through the clamp rather than off the constants, because what a
        // caller is served is the only number that can refuse their result.
        let served = |requested: Option<u64>| {
            let mut args = HashMap::new();
            if let Some(value) = requested {
                args.insert("max_chars".to_string(), json!(value));
            }
            ResponseBudget::from_arguments(&args).max_chars
        };
        let ceiling = served(Some(u64::MAX));
        let floor = served(Some(1));
        let default = served(None);

        assert!(
            ceiling < REFUSED_BY_A_REAL_CLIENT,
            "the ceiling serves a size a real client refused: {ceiling}"
        );
        assert!(
            ceiling >= ACCEPTED_BY_A_REAL_CLIENT,
            "the ceiling sits under a size a real client already took: {ceiling}"
        );
        assert!(
            floor < default && default <= ceiling,
            "the default {default} must sit inside its own clamp {floor}..{ceiling}"
        );
        // The old 30,000 default dropped 170 of 200 steps on the 783-entity store
        // the same run measured, and still withheld impact rows at 50,000.
        assert!(
            default > OVERFLOWED_THE_MEASURED_STORE,
            "the default is back at a size the measured store overflowed: {default}"
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

    /// One fused entity page in the shape the daemon's serializer produces:
    /// `entities` omitted when the ranking held none, `files` present whatever
    /// it holds. That asymmetry is where the relabelling lives, so the fixture
    /// reproduces it rather than writing both keys out.
    fn fused_entity_page(entities: usize, files: usize) -> Value {
        let mut payload = json!({
            "query": "where redirects are resolved",
            "granularity": "entity",
            "routing": "fused-v1",
            "page": 0,
            "files": (0..files)
                .map(|index| json!({ "path": format!("src/f{index}.rs"), "score": 0.5 }))
                .collect::<Vec<_>>(),
        });
        if entities > 0 {
            payload["entities"] = json!((0..entities)
                .map(|index| json!({
                    "entity_id": format!("00000000-0000-0000-0000-{index:012}"),
                    "name": format!("handler_{index}"),
                    "kind": "function",
                    "score": 0.5,
                }))
                .collect::<Vec<_>>());
        }
        payload
    }

    #[test]
    fn entity_and_file_granularity_each_name_their_literal_primary() {
        let budget = ResponseBudget::default();

        let mut entity = fused_entity_page(3, 2);
        let fused = enforce(&mut entity, "semantic_locate", &budget).expect("budgeted");
        assert_eq!(fused.primary_collection.as_deref(), Some("entities"));
        assert_eq!(fused.primary_rows, Some(3));

        let mut cosine_payload = cosine_locate_payload(4);
        let cosine = enforce(&mut cosine_payload, "semantic_locate", &budget).expect("budgeted");
        assert_eq!(cosine.primary_collection.as_deref(), Some("results"));
        assert_eq!(cosine.primary_rows, Some(4));

        let mut file_payload = file_locate_payload(5, 2);
        let files = enforce(&mut file_payload, "semantic_locate", &budget).expect("budgeted");
        assert_eq!(files.primary_collection.as_deref(), Some("files"));
        assert_eq!(files.primary_rows, Some(5));

        // The three together, because a rule answering `files` to everything
        // satisfies the file case on its own and one answering `entities` to
        // everything satisfies the entity case on its own.
        assert_ne!(fused.primary_collection, files.primary_collection);
        assert_ne!(fused.primary_collection, cosine.primary_collection);
    }

    #[test]
    fn an_empty_entity_page_ships_its_primary_rather_than_a_file_roll_up() {
        let mut payload = fused_entity_page(0, 3);
        assert!(
            payload.get("entities").is_none(),
            "the fixture must reproduce the omission this fixes: {payload}"
        );

        let accounting =
            enforce(&mut payload, "semantic_locate", &ResponseBudget::default()).expect("budgeted");

        assert_eq!(accounting.primary_collection.as_deref(), Some("entities"));
        assert_eq!(accounting.primary_rows, Some(0));
        assert_eq!(
            payload.get("entities"),
            Some(&json!([])),
            "an empty primary is disclosed as empty, never omitted: {payload}"
        );
        assert_eq!(
            payload["files"].as_array().map(Vec::len),
            Some(3),
            "the secondary roll-up is untouched; it is only no longer the answer: {payload}"
        );
    }

    #[test]
    fn an_entity_page_that_named_no_arm_never_names_the_file_roll_up() {
        // Older and hand-built payloads carry a granularity and no routing. The
        // presence fallback would pick `files` here, which is the exact
        // relabelling the declared rule exists to refuse.
        let mut payload = json!({
            "query": "where redirects are resolved",
            "granularity": "entity",
            "files": [{ "path": "src/secondary.rs", "score": 0.4 }],
        });
        let accounting =
            enforce(&mut payload, "semantic_locate", &ResponseBudget::default()).expect("budgeted");
        assert_eq!(accounting.primary_collection.as_deref(), Some("entities"));
        assert_eq!(accounting.primary_rows, Some(0));
        assert_eq!(payload.get("entities"), Some(&json!([])));
        assert_eq!(payload["files"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn a_response_that_declares_no_primary_has_none_invented_for_it() {
        // The known-absent control. `semantic_search` declares nothing about its
        // collection, so a response carrying none must be reported as naming
        // none rather than having `results` fabricated for it.
        let mut absent = json!({ "query": "where redirects are resolved" });
        let accounting =
            enforce(&mut absent, "semantic_search", &ResponseBudget::default()).expect("budgeted");
        assert_eq!(accounting.primary_collection, None);
        assert_eq!(accounting.primary_rows, None);
        assert_eq!(
            absent.get("results"),
            None,
            "no collection was invented: {absent}"
        );

        // The positive control beside it, so the assertion above cannot pass by
        // the accounting never naming anything at all.
        let mut present = json!({ "query": "q", "results": [{ "name": "a" }] });
        let accounting =
            enforce(&mut present, "semantic_search", &ResponseBudget::default()).expect("budgeted");
        assert_eq!(accounting.primary_collection.as_deref(), Some("results"));
        assert_eq!(accounting.primary_rows, Some(1));
    }

    #[test]
    fn the_primary_row_count_is_what_the_response_ships_after_a_cut() {
        // `primary_rows` describes the response, not the ranking behind it. A
        // count taken before the ladder would tell a caller it holds rows the
        // budget had already withheld, which is the reading `total_ranked` is
        // for.
        let mut payload = locate_payload(60, 2_000);
        let budget = ResponseBudget {
            max_chars: RESPONSE_MIN_MAX_CHARS,
            ..ResponseBudget::default()
        };
        let accounting = enforce(&mut payload, "semantic_locate", &budget).expect("budgeted");
        assert!(accounting.bounded, "the fixture must be cut: {payload}");
        let shipped = payload["entities"].as_array().expect("entities").len();
        assert!(
            shipped < 60,
            "the fixture must lose rows: shipped {shipped}"
        );
        assert_eq!(accounting.primary_rows, Some(shipped));
        assert_eq!(payload["total_ranked"], json!(60));
    }
}
