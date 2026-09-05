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
pub fn response_budget_clause(param: &str, in_force: usize, needed: Option<usize>) -> String {
    if let Some(needed) = needed {
        if needed > RESPONSE_MAX_MAX_CHARS {
            return format!(
                "raising {param} cannot reach the withheld entries: with every diagnostic, \
                 roll-up and inline body this budget can shed already dropped, the answer \
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
}
