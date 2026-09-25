// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Remediation text built from the bounds the schema publishes.
//!
//! A degradation exists to hand the caller a lever. Naming a lever the call
//! then refuses is worse than naming none: the caller spends a round trip
//! learning that the advice was wrong, and the answer they were told they could
//! recover is still missing. A stranger on the v0.7.0 candidate hit both shapes
//! of that in one session. `trace_data_flow` told them to "re-query with
//! `limit_per_step` above 25" while the schema declares `"maximum": 25`, and two
//! `response_bounded` degradations told them to raise `max_chars` "up to the
//! 60000 this server will build" on answers that measured 294,086 and 1,630,149
//! characters, where the whole 60,000 closes neither gap.
//!
//! Both strings were correct on the inputs their authors had in mind and wrong
//! at the edge, because each was a literal written in one file about a bound
//! declared in another. This module is the one place that joins them: the
//! ceiling a knob is checked against and the sentence that talks about the knob
//! are the same constant, and every string below asks where the caller already
//! is before recommending a move.
//!
//! The rule, stated once so a new producer can be held to it: a remediation may
//! name a parameter value only when the call would accept that value, and may
//! promise recovery only when a value that recovers exists. When neither holds,
//! it says so and names the alternative, or says there is none.

use crate::budget::RESPONSE_MAX_MAX_CHARS;

/// The largest `limit_per_step` any trace surface accepts.
///
/// Read by the MCP schema (`crate::tools`), by the hosted repo-scoped validator
/// in `kin-daemon`, by the CLI's own clamp, and by the spine-clip remediation
/// below, so the number the advice quotes cannot drift from the number the call
/// enforces. It was three separate literals when
/// [`spine_clipped`] first recommended a value past it.
pub const TRACE_MAX_LIMIT_PER_STEP: usize = 25;

/// The `limit_per_step` a trace surface walks with when the caller names none.
///
/// One constant for the same reason as the ceiling above: `trace_data_flow` has
/// two walkers, the generic-`GraphStore` arm in `crate::handlers::entities` and
/// the CLI arm that a live daemon routes to, and a default fixed in one of them
/// reads as fixed on both while only one is. The MCP schema advertises this
/// number, and both arms take it.
///
/// Five was below what the answer costs. Measured on a 714-commit slice of
/// `cli/cli`: `apiRun` has 45 callees, `httpRequest` -- the hop "how does
/// `gh api` send the request" is about -- ranks eighth of them, and a five-wide
/// default reported `dropped_callees: 40` and never named it. Twelve is what
/// the 24,576-byte per-result ceiling an agent reads a tool answer under
/// allows at this tool's default depth: on that store at `depth: 3` with the
/// belt's own `include_body: false`, the rendered response is 16,327
/// characters at twelve and 22,988 at sixteen, so twelve leaves the envelope
/// its room and sixteen does not.
pub const TRACE_DEFAULT_LIMIT_PER_STEP: usize = 12;

/// The largest `max_depth` a `trace_path` call accepts.
///
/// Read by the MCP schema (`crate::tools`), by the handler's clamp
/// (`crate::handlers::path`) and by [`raise_bounded_knob`]'s caller there, for
/// the same reason as the constant above: the number the gap quotes and the
/// number the call refuses past were two literals in two files.
pub const PATH_MAX_MAX_DEPTH: usize = 12;

/// Advice for one bounded integer knob, or the reason raising it cannot help.
///
/// `in_force` is the value that produced this answer and `ceiling` is the
/// largest the call accepts. At the ceiling there is no larger value to name, so
/// the caller is told that rather than sent to try one.
pub fn raise_bounded_knob(param: &str, in_force: usize, ceiling: usize) -> String {
    if in_force < ceiling {
        format!("raise {param} (now {in_force}, ceiling {ceiling})")
    } else {
        format!(
            "{param} is already at its {ceiling} ceiling, which is the largest value this call \
             accepts, so raising it recovers nothing"
        )
    }
}

/// What to say about a node whose fan-out the per-step cap clipped.
///
/// Under the cap the fix is the one it always was, now stated with the ceiling
/// so the caller picks a value the call takes. At the cap there is no such
/// value, so the sentence says the dropped neighbors are not reachable by
/// widening this walk and names the tool that does enumerate them:
/// `graph_neighborhood` reads its own `limit` with no declared maximum
/// (`crate::handlers::entities::handle_graph_neighborhood`), so the per-step cap
/// that clipped this node does not bind it.
///
/// `target` leads in both branches because it is the recovery designed for this
/// case: naming the symbol makes the cap rank toward it, so the hop survives a
/// walk that stayed narrow.
pub fn spine_clipped(
    entity_name: &str,
    entity_id: &str,
    limit_per_step: usize,
    dropped: usize,
) -> String {
    if limit_per_step < TRACE_MAX_LIMIT_PER_STEP {
        format!(
            "name the symbol you are looking for as `target` so the cap ranks toward it, or \
             re-query '{entity_name}' with limit_per_step above {limit_per_step} and at most \
             {TRACE_MAX_LIMIT_PER_STEP}"
        )
    } else {
        format!(
            "name the symbol you are looking for as `target` so the cap ranks toward it; \
             limit_per_step is already at its {TRACE_MAX_LIMIT_PER_STEP} ceiling, which is the \
             largest value this call accepts, so no re-query of '{entity_name}' recovers the \
             {dropped} neighbor(s) the cap dropped there. List them with graph_neighborhood on \
             entity_id {entity_id} at depth 1, whose own `limit` this per-step cap does not bind"
        )
    }
}

/// One node a trace's chain continues beneath after the per-step cap cut the
/// node's fan-out, as the spine-clipping disclosure counts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpineNode {
    pub entity_id: String,
    pub entity_name: String,
    /// Neighbors the cap dropped at this node.
    pub dropped: usize,
    /// How many of them lived outside this node's own file, or `None` when no
    /// clip record says.
    pub dropped_crossing_file: Option<usize>,
    /// The cap that clipped this node, so the remediation names the value the
    /// caller would raise.
    pub limit_per_step: usize,
}

/// The `fanout_cap` / `spine_clipped` disclosure for the nodes a trace's chain
/// continues beneath, given in walk order: its detail and its remediation, or
/// `None` when there are none.
///
/// One producer for both walks and for the response-budget pass, which
/// restates the disclosure after it cuts the chain further, so the three word
/// one fact one way. The widest node is the first with the most dropped
/// neighbors. How many of the dropped neighbors crossed a file is stated only
/// when every node's count is known, so the number always covers the same
/// nodes as the total beside it.
pub fn spine_clipped_disclosure(nodes: &[SpineNode]) -> Option<(String, String)> {
    let widest = nodes
        .iter()
        .fold(None, |widest: Option<&SpineNode>, node| match widest {
            Some(widest) if widest.dropped >= node.dropped => Some(widest),
            _ => Some(node),
        })?;
    let dropped: usize = nodes.iter().map(|node| node.dropped).sum();
    let crossing = nodes
        .iter()
        .map(|node| node.dropped_crossing_file)
        .sum::<Option<usize>>()
        .filter(|crossing| *crossing > 0)
        .map(|crossing| {
            format!(", {crossing} of which lived outside the file of the node that offered them")
        })
        .unwrap_or_default();
    let detail = format!(
        "the walk continued beneath {} node(s) whose fan-out limit_per_step {} had already cut, \
         dropping {dropped} neighbor(s) that were never followed{crossing}; the widest was '{}', \
         which offered {} more than the cap kept. This chain is one route among the ones the cap \
         left, so a hop it does not contain was not looked for and its absence proves nothing",
        nodes.len(),
        widest.limit_per_step,
        widest.entity_name,
        widest.dropped,
    );
    let remediation = spine_clipped(
        &widest.entity_name,
        &widest.entity_id,
        widest.limit_per_step,
        widest.dropped,
    );
    Some((detail, remediation))
}

/// The clause a bounded response ends with, about the budget knob itself.
///
/// Three cases, and only the first is what shipped before this module existed.
///
/// `in_force` is the ceiling this answer was actually built under, from the
/// caller's point of view: the number they passed, or the published default that
/// the envelope reserve was taken out of. `needed` is what the answer measures
/// with every diagnostic, roll-up and inline body the ladder can shed already
/// gone: with every entry still present on the ladder's own disclosure, or
/// cut to the one-entry floor and still over budget on the residual one. Both
/// are lower bounds on what the whole answer needs, which is what makes the
/// sentence safe. `None` where no entry was at risk and the question does not
/// arise.
///
/// A `needed` over the ceiling is the case the stranger hit twice. It is a
/// measured lower bound rather than an estimate, so the sentence it produces is
/// checkable against `chars_before_withholding` on the same degradation.
///
/// It says "this response", not "the answer", and the difference is not
/// pedantry. `needed` is the whole payload, and on a tool whose payload is
/// mostly qualification the two are nowhere near the same number: a
/// `find_references` reply that withheld reference rows reported that "the
/// answer still measures 94836 characters" while the answer it had returned was
/// 434 of them. A caller who reads that stops looking for a lever that exists.
pub fn response_budget_clause(param: &str, in_force: usize, needed: Option<usize>) -> String {
    if let Some(needed) = needed {
        if needed > RESPONSE_MAX_MAX_CHARS {
            return format!(
                "raising {param} cannot reach the withheld entries: with every diagnostic, \
                 roll-up and inline body this budget can shed already dropped, this response \
                 still measures {needed} characters against the {RESPONSE_MAX_MAX_CHARS} this \
                 server will build, so no budget this call accepts returns them"
            );
        }
    }
    if in_force >= RESPONSE_MAX_MAX_CHARS {
        return format!(
            "{param} is already at the {RESPONSE_MAX_MAX_CHARS} this server will build, which is \
             the largest budget this call accepts, so there is no larger one to ask for"
        );
    }
    format!(
        "or raise {param}, up to the {RESPONSE_MAX_MAX_CHARS} this server will build, if the \
         caller's own result limit accepts a larger payload"
    )
}

/// The detail and remediation a trace discloses when the `target` it was asked
/// to rank toward names no entity.
///
/// One producer for both walks. The CLI walk's copy of this sentence had lost
/// its line continuations and carried runs of spaces where they had been,
/// while the in-process walk's read cleanly, so the two worded one fact two
/// ways.
pub fn trace_target_not_resolved(target: &str) -> (String, String) {
    (
        format!(
            "no entity matches target '{target}', so this walk ranked its fan-out by relevance \
             alone and the question had no vote in what the cap kept"
        ),
        "check the target's spelling, or find it first with semantic_locate".to_string(),
    )
}

/// `count` and the noun it counts, singular for exactly one: "1 step",
/// "6 steps".
///
/// A budget disclosure states each count in a sentence, and "1 steps" reads as
/// a typo that makes a reader doubt the number beside it.
pub fn counted(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stranger's exact input: a node clipped at the schema ceiling.
    ///
    /// The assertion is on the NUMBER, not on the prose. "above 25" is the
    /// string the tool refuses, and any rewording that reintroduces a value past
    /// the ceiling has to reintroduce a number past it.
    #[test]
    fn a_clip_at_the_cap_never_names_a_value_the_schema_rejects() {
        let advice = spine_clipped("HTTPAdapter.send", "abc-123", TRACE_MAX_LIMIT_PER_STEP, 3);
        assert!(
            !advice.contains("above 25"),
            "the cap's own advice still names a value the schema rejects: {advice}"
        );
        assert!(
            advice.contains("already at its 25 ceiling"),
            "a clip at the cap must say the cap is the ceiling: {advice}"
        );
        assert!(
            advice.contains("3 neighbor(s)"),
            "a clip at the cap must say what was dropped: {advice}"
        );
        assert!(
            advice.contains("graph_neighborhood") && advice.contains("abc-123"),
            "a clip at the cap must name the alternative that exists, addressably: {advice}"
        );
    }

    /// The positive control for the clip path: under the cap the advice still
    /// tells the caller to widen, because widening still works.
    ///
    /// Without this a fix could satisfy the test above by never recommending
    /// `limit_per_step` again, which would delete a working lever.
    #[test]
    fn a_clip_under_the_cap_still_says_to_widen_the_step() {
        let advice = spine_clipped("HTTPAdapter.send", "abc-123", 12, 3);
        assert!(
            advice.contains("limit_per_step above 12"),
            "a clip under the cap must still name the knob that recovers it: {advice}"
        );
        assert!(
            advice.contains("at most 25"),
            "a clip under the cap must bound the value it recommends: {advice}"
        );
    }

    /// Every value this producer can be handed, checked against the bound.
    ///
    /// One clip per accepted `limit_per_step`, so a future edit that reads the
    /// cap off by one is caught by the case it is off at rather than by luck.
    #[test]
    fn no_clip_advice_at_any_cap_recommends_a_rejected_value() {
        for limit in 1..=TRACE_MAX_LIMIT_PER_STEP {
            let advice = spine_clipped("f", "id", limit, 1);
            for rejected in TRACE_MAX_LIMIT_PER_STEP..=(TRACE_MAX_LIMIT_PER_STEP + 4) {
                assert!(
                    !advice.contains(&format!("above {rejected}")),
                    "at limit_per_step {limit} the advice recommends above {rejected}, which the \
                     schema rejects: {advice}"
                );
            }
        }
    }

    /// The stranger's two `impact_analysis` answers: 294,086 and 1,630,149
    /// characters against a 60,000 ceiling.
    #[test]
    fn an_answer_over_the_ceiling_says_no_budget_reaches_it() {
        for needed in [294_086, 1_630_149] {
            let clause = response_budget_clause("max_chars", 18_000, Some(needed));
            assert!(
                !clause.contains("or raise max_chars"),
                "an unreachable answer still points at the budget knob: {clause}"
            );
            assert!(
                clause.contains("no budget this call accepts returns them"),
                "an unreachable answer must say so: {clause}"
            );
            assert!(
                clause.contains(&needed.to_string()),
                "the claim must carry the number it rests on: {clause}"
            );
        }
    }

    /// The positive control the brief names: under the ceiling, the advice is
    /// still to raise `max_chars`, in the words it always used.
    #[test]
    fn an_answer_under_the_ceiling_still_says_to_raise_the_budget() {
        let clause = response_budget_clause("max_chars", 45_000, Some(52_000));
        assert_eq!(
            clause,
            format!(
                "or raise max_chars, up to the {RESPONSE_MAX_MAX_CHARS} this server will build, \
                 if the caller's own result limit accepts a larger payload"
            ),
            "the working advice must survive the fix unchanged"
        );
    }

    /// A caller already at the ceiling is told the knob is spent rather than
    /// told to set the value it already holds.
    #[test]
    fn a_caller_at_the_ceiling_is_never_told_to_raise_the_budget() {
        let clause = response_budget_clause("max_chars", RESPONSE_MAX_MAX_CHARS, None);
        assert!(
            !clause.contains("or raise max_chars"),
            "a caller at the ceiling was told to raise past it: {clause}"
        );
        assert!(
            clause.contains("no larger one to ask for"),
            "a caller at the ceiling must be told the knob is spent: {clause}"
        );
    }

    /// A knob below its ceiling still gets the raise, and one at it does not.
    #[test]
    fn a_bounded_knob_is_only_raised_while_a_larger_value_exists() {
        let below = raise_bounded_knob("max_depth", 6, 12);
        assert!(below.starts_with("raise max_depth"), "{below}");
        assert!(below.contains("ceiling 12"), "{below}");

        let at = raise_bounded_knob("max_depth", 12, 12);
        assert!(
            !at.contains("raise max_depth"),
            "a knob at its ceiling was told to rise: {at}"
        );
        assert!(at.contains("already at its 12 ceiling"), "{at}");
    }

    fn spine_node(name: &str, dropped: usize, crossing: Option<usize>) -> SpineNode {
        SpineNode {
            entity_id: format!("{name}-id"),
            entity_name: name.to_string(),
            dropped,
            dropped_crossing_file: crossing,
            limit_per_step: 3,
        }
    }

    /// The disclosure counts the nodes it is given, totals what they dropped,
    /// names the first widest one in the detail and the remediation alike, and
    /// states the crossing count only when it knows every node's.
    #[test]
    fn the_spine_disclosure_describes_exactly_the_nodes_it_is_given() {
        assert!(spine_clipped_disclosure(&[]).is_none());

        let nodes = [
            spine_node("root", 2, Some(1)),
            spine_node("branch_0", 2, Some(0)),
            spine_node("branch_1", 1, Some(2)),
        ];
        let (detail, remediation) = spine_clipped_disclosure(&nodes).expect("three nodes");
        assert!(
            detail.starts_with(
                "the walk continued beneath 3 node(s) whose fan-out limit_per_step 3 had already \
                 cut, dropping 5 neighbor(s) that were never followed, 3 of which lived outside"
            ),
            "{detail}"
        );
        assert!(
            detail.contains("the widest was 'root', which offered 2 more"),
            "a tie goes to the first node in walk order: {detail}"
        );
        assert!(detail.ends_with("absence proves nothing"), "{detail}");
        assert!(!detail.contains("  "), "no run of spaces: {detail}");
        assert!(
            remediation.contains("re-query 'root'"),
            "the remediation names the node the detail names: {remediation}"
        );

        let (unknown, _) = spine_clipped_disclosure(&[
            spine_node("root", 2, Some(1)),
            spine_node("branch_0", 2, None),
        ])
        .expect("two nodes");
        assert!(
            !unknown.contains("of which lived outside"),
            "a crossing count missing one node's share is not stated: {unknown}"
        );
        assert!(unknown.contains("dropping 4 neighbor(s)"), "{unknown}");
    }

    /// One takes the singular and every other count the plural.
    #[test]
    fn a_count_of_one_takes_the_singular() {
        assert_eq!(counted(1, "step", "steps"), "1 step");
        assert_eq!(counted(0, "step", "steps"), "0 steps");
        assert_eq!(
            counted(6, "inlined body", "inlined bodies"),
            "6 inlined bodies"
        );
        assert_eq!(
            counted(1, "inlined body", "inlined bodies"),
            "1 inlined body"
        );
    }
}
