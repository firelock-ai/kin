// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Directional statement-delta change-shape classifier.
//!
//! # What this is
//!
//! A body-only public change that reaches two or more distinct consumers fires
//! `consumer_fanout` (see [`crate::inline`]) and lands the review at
//! `needs_attention`. The gate that fires it sees only the entity's signature
//! (unchanged), visibility (unchanged), and consumer counts — it has **no view
//! of what changed inside the body**. This module types the *shape* of that
//! body delta so a reviewer can be told *why* the fanout fired, without the gate
//! ever having to read source.
//!
//! It answers exactly one graph-native question: given the old and new
//! statement structure of an entity body, is the delta a **pure added
//! narrowing guard** (new early-exit / exclusion conditionals whose taken
//! branch only raises or returns an error, mainline preserved), a **removed /
//! widened guard** (the mirror), or **some other behavior change**?
//!
//! # The soundness boundary (why this never downgrades the gate)
//!
//! Direction — added-guard vs removed-guard — *is* graph-computable from the
//! statement delta, and it cleanly separates the risk-reducing benign rows
//! (which ADD narrowing guards) from the revert/reintroduce true positives
//! (which REMOVE fallbacks/guards). What it **cannot** compute is whether the
//! newly-excluded input subdomain was ever *valid*:
//!
//! ```text
//!   django  build_filter:  if not conditional: raise TypeError   (narrows an INVALID domain — hardening)
//!   sphinx  safe_getattr:  if len(defargs) > 1: raise TypeError  (narrows an INVALID domain — hardening)
//!   adversarial account:   if user == "admin": raise             (narrows a  VALID  domain — breakage)
//! ```
//!
//! All three are, at the graph level, the *same shape*: a pure added early-exit
//! guard, mainline untouched. Distinguishing "narrows invalid input" (safe)
//! from "narrows valid input" (an adversarial lock-out / DoS) requires knowing
//! the intended input contract — a semantic domain-validity fact the graph does
//! not hold. Any rule that downgraded `AddedNarrowingGuard` to `pass` would
//! therefore wave an adversarial guard straight through.
//!
//! Consequently [`gate_action_for`] returns [`GateAction::EnrichEvidenceOnly`]
//! for `AddedNarrowingGuard` — never [`GateAction::Downgrade`]. The classifier
//! is a *review-evidence* enricher, not a gate lever. The
//! [`tests`] module proves this in code: the benign guard and the adversarial
//! `admin` guard produce an identical [`ChangeShape`], and the only shape that
//! is ever permitted to downgrade is [`ChangeShape::Equivalent`] (which is the
//! behavior-equivalence channel's job, not this one's).
//!
//! # Consumption (not yet wired)
//!
//! The classifier operates on [`BodyShape`] — an ordered, canonicalized
//! statement structure that an ingest-time pass would emit from the already
//! parsed tree (the same graph-native channel the behavior-equivalence class
//! uses), because the review-time `Entity` carries only opaque body hashes, not
//! statement structure. Until that ingest channel exists the classifier stands
//! as a verified primitive; its intended consumption point is the
//! `consumer_fanout` emit in [`crate::inline`], where [`evidence_note`] would be
//! appended to the finding's message. It must attach at `info`/`warning`
//! severity and must not alter `blocking`.

/// Disposition of a conditional statement's taken branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Branch {
    /// The branch does nothing but `raise` / `return` an error value: a pure
    /// early exit. No calls with observable effects, no mutation of state read
    /// after the branch, no fall-through work.
    ExitOnly,
    /// The branch performs observable work: calls, sends, mutation, logging —
    /// anything that is not a pure early exit. A guard that *does something*
    /// is not a narrowing guard.
    Effectful,
    /// The branch guards a block of mainline work (an ordinary guarded block,
    /// e.g. `if ready: <do the work>`). `body` is the canonical hash of the
    /// guarded block so a predicate change with an unchanged block is
    /// detectable.
    Guards { body: u64 },
}

/// Structural kind of a single canonical statement in an entity body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatementKind {
    /// A conditional. `predicate` is the set of hashes of its ANDed predicate
    /// atoms (so a strictly-more-restrictive predicate is a superset), and
    /// `branch` is what the taken branch does.
    Conditional { predicate: Vec<u64>, branch: Branch },
    /// An ordinary straight-line statement (assignment, call, return-of-value).
    Plain,
}

/// One canonical statement: a content hash (comment/whitespace/docstring
/// insensitive, so cosmetic edits do not register) plus its structural kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// Canonical content hash of the whole statement. Two statements are "the
    /// same statement" iff their hashes are equal.
    pub hash: u64,
    /// Structural kind, used to type the delta.
    pub kind: StatementKind,
}

impl Statement {
    /// A pure early-exit guard `if <predicate>: raise/return-error`.
    pub fn exit_guard(hash: u64, predicate: Vec<u64>) -> Self {
        Statement {
            hash,
            kind: StatementKind::Conditional {
                predicate,
                branch: Branch::ExitOnly,
            },
        }
    }

    /// A conditional guarding a block of real work.
    pub fn guarded_block(hash: u64, predicate: Vec<u64>, body: u64) -> Self {
        Statement {
            hash,
            kind: StatementKind::Conditional {
                predicate,
                branch: Branch::Guards { body },
            },
        }
    }

    /// A conditional whose branch performs observable work (not a pure exit).
    pub fn effectful_conditional(hash: u64, predicate: Vec<u64>) -> Self {
        Statement {
            hash,
            kind: StatementKind::Conditional {
                predicate,
                branch: Branch::Effectful,
            },
        }
    }

    /// An ordinary straight-line statement.
    pub fn plain(hash: u64) -> Self {
        Statement {
            hash,
            kind: StatementKind::Plain,
        }
    }

    fn is_exit_guard(&self) -> bool {
        matches!(
            self.kind,
            StatementKind::Conditional {
                branch: Branch::ExitOnly,
                ..
            }
        )
    }

    fn as_guarded(&self) -> Option<(&[u64], u64)> {
        match &self.kind {
            StatementKind::Conditional {
                predicate,
                branch: Branch::Guards { body },
            } => Some((predicate.as_slice(), *body)),
            _ => None,
        }
    }
}

/// The ordered, canonical statement sequence of one version of an entity body.
///
/// An ingest-time pass emits this from the parsed tree; review compares the old
/// and new `BodyShape` of a changed entity. Order matters: mainline preservation
/// is checked as subsequence containment, not as a set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BodyShape {
    /// Top-level statements, in source order.
    pub statements: Vec<Statement>,
}

impl BodyShape {
    /// Build from a statement vector.
    pub fn new(statements: Vec<Statement>) -> Self {
        BodyShape { statements }
    }
}

/// The typed shape of an old → new body delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeShape {
    /// No material statement delta (the two bodies are structurally identical).
    Equivalent,
    /// The delta ADDS only narrowing guards — pure early-exit guards and/or
    /// strictly-more-restrictive predicate conjuncts on unchanged blocks — with
    /// the pre-existing mainline preserved and nothing removed. Domain is
    /// narrowed. **Whether that narrowing is safe is not graph-decidable.**
    AddedNarrowingGuard { guards_added: usize },
    /// The delta REMOVES guards / fallbacks / statements, or otherwise widens
    /// the accepted domain, without a compensating narrowing. The mirror image
    /// of `AddedNarrowingGuard`; the shape of a reintroduce/revert true
    /// positive.
    RemovedGuardOrWidened { statements_removed: usize },
    /// Anything else: added straight-line work, effectful branches, method or
    /// feature additions, or a restructure that both removes and adds — a
    /// genuine behavior change the graph cannot type as a pure narrowing.
    OtherBehaviorChange,
}

/// The gate action a [`ChangeShape`] is permitted to license.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateAction {
    /// Lower the finding out of the gate (turn attention into pass). Reserved
    /// for provably behavior-preserving change; never granted to a narrowing
    /// guard.
    Downgrade,
    /// Keep the finding at its current attention level, but attach a
    /// change-shape note so the reviewer sees why the fanout fired.
    EnrichEvidenceOnly,
    /// Neither downgrade nor annotate.
    NoChange,
}

/// Multiset removal: remove one occurrence of each `remove`d hash from `pool`.
/// Returns the statements of `pool` whose hash was not consumed.
fn multiset_minus(pool: &[Statement], remove: &[u64]) -> Vec<Statement> {
    let mut counts: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for h in remove {
        *counts.entry(*h).or_insert(0) += 1;
    }
    let mut out = Vec::new();
    for s in pool {
        match counts.get_mut(&s.hash) {
            Some(c) if *c > 0 => *c -= 1,
            _ => out.push(s.clone()),
        }
    }
    out
}

/// Classify the shape of an old → new body delta.
///
/// The classification is conservative: any structure the model cannot prove to
/// be a pure narrowing falls to [`ChangeShape::OtherBehaviorChange`], and only
/// a structurally identical body is [`ChangeShape::Equivalent`]. Neither of
/// those, nor [`ChangeShape::RemovedGuardOrWidened`], is ever downgraded.
pub fn classify_change_shape(old: &BodyShape, new: &BodyShape) -> ChangeShape {
    if old.statements == new.statements {
        return ChangeShape::Equivalent;
    }

    let old_hashes: Vec<u64> = old.statements.iter().map(|s| s.hash).collect();
    let new_hashes: Vec<u64> = new.statements.iter().map(|s| s.hash).collect();

    // Statements present only in old / only in new, as multisets.
    let mut removed = multiset_minus(&old.statements, &new_hashes);
    let mut added = multiset_minus(&new.statements, &old_hashes);

    // Pair narrowing predicate modifications: an old guarded block replaced by
    // a guarded block over the SAME body whose predicate is a strict superset
    // (strictly more restrictive) is a narrowing, not a widening removal. This
    // is the `if p: work` -> `if p and q: work` shape (e.g. a symlink-exclusion
    // conjunct added to a file-match predicate).
    let mut narrowing_mods = 0usize;
    let mut i = 0;
    while i < removed.len() {
        let paired = removed[i].as_guarded().and_then(|(old_pred, old_body)| {
            added.iter().position(|a| {
                a.as_guarded().is_some_and(|(new_pred, new_body)| {
                    new_body == old_body && is_strict_superset(new_pred, old_pred)
                })
            })
        });
        match paired {
            Some(added_idx) => {
                added.remove(added_idx);
                removed.remove(i);
                narrowing_mods += 1;
            }
            None => i += 1,
        }
    }

    let added_exit_guards = added.iter().filter(|s| s.is_exit_guard()).count();
    let added_non_guard = added.len() - added_exit_guards;
    let narrowings = narrowing_mods + added_exit_guards;

    if !removed.is_empty() {
        // A genuine (unpaired) removal survives.
        if added_exit_guards > 0 {
            // Removal PLUS an added early-exit guard: a restructure whose net
            // reachability the model cannot prove (e.g. splitting `if a and b:
            // work` into `if a: (if not b: raise) work`). Conservatively a
            // general behavior change — which is gate-neutral, so the finding
            // stays exactly as it is.
            ChangeShape::OtherBehaviorChange
        } else {
            // Removal with no compensating narrowing guard — direct-call
            // replacements included: a removal / widening, the reintroduce
            // /revert mirror (e.g. deleting a fallback, or lifting an `if`
            // guard off a block so it runs unconditionally).
            ChangeShape::RemovedGuardOrWidened {
                statements_removed: removed.len(),
            }
        }
    } else if added_non_guard > 0 {
        // Nothing removed, but straight-line work, an effectful branch, or a
        // new feature/guarded block was added: a genuine behavior change.
        ChangeShape::OtherBehaviorChange
    } else if narrowings > 0 {
        // Nothing removed and every addition is a narrowing guard: a pure added
        // narrowing guard.
        ChangeShape::AddedNarrowingGuard {
            guards_added: narrowings,
        }
    } else {
        // Nothing removed, nothing non-guard added, no narrowing: reached only
        // when the sole change was cosmetic under the canonical hash.
        ChangeShape::Equivalent
    }
}

/// `a` strictly contains every atom of `b` and has at least one more.
fn is_strict_superset(a: &[u64], b: &[u64]) -> bool {
    b.iter().all(|x| a.contains(x)) && a.len() > b.len()
}

/// The gate action a shape may license. This is the enforced soundness
/// boundary: a narrowing guard may only enrich evidence, never downgrade.
pub fn gate_action_for(shape: &ChangeShape) -> GateAction {
    match shape {
        ChangeShape::Equivalent => GateAction::Downgrade,
        ChangeShape::AddedNarrowingGuard { .. } => GateAction::EnrichEvidenceOnly,
        ChangeShape::RemovedGuardOrWidened { .. } => GateAction::NoChange,
        ChangeShape::OtherBehaviorChange => GateAction::NoChange,
    }
}

/// A neutral, non-risk-asserting reviewer note describing the change shape.
///
/// The wording describes the *shape* of the edit, never its risk polarity: a
/// narrowing guard is reported as domain-narrowing whose safety is not
/// graph-verifiable, precisely because the classifier cannot tell a safe
/// hardening from an adversarial lock-out.
pub fn evidence_note(shape: &ChangeShape) -> Option<String> {
    match shape {
        ChangeShape::AddedNarrowingGuard { guards_added } => Some(format!(
            "body added {guards_added} narrowing guard(s) (early-exit/exclusion) with the \
             pre-existing mainline preserved; this narrows the accepted input domain — whether \
             the excluded inputs were valid is not graph-verifiable, so review the guarded domain"
        )),
        ChangeShape::RemovedGuardOrWidened { statements_removed } => Some(format!(
            "body removed {statements_removed} guard/fallback statement(s), widening the accepted \
             domain or execution path; confirm the removed handling is no longer needed"
        )),
        ChangeShape::Equivalent | ChangeShape::OtherBehaviorChange => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Canonical statement-hash constants standing in for real body statements.
    const MAINLINE: u64 = 1; // e.g. `condition = self.build_lookup(...)` / `return getattr(...)`
    const APPEND: u64 = 2; // e.g. `results = append(results, ...)`
    const PRED_MD: u64 = 10; // `strings.HasSuffix(tf.Name(), ".md")`
    const PRED_NOTDIR: u64 = 11; // `!file.IsDir()`
    const PRED_NOTSYMLINK: u64 = 12; // `file.Type() != fs.ModeSymlink`
    const PRED_ARGS: u64 = 13; // `len(defargs) > 1`
    const PRED_ADMIN: u64 = 14; // `user == "admin"`
    const PRED_READY: u64 = 15; // `updated_docnames`

    fn body(stmts: Vec<Statement>) -> BodyShape {
        BodyShape::new(stmts)
    }

    // --- The three real P2 benign rows -------------------------------------

    /// `883faaa568` sphinx `safe_getattr`: prepend `if len(defargs) > 1: raise`
    /// before the untouched `try/return getattr(...)` mainline. The cleanest
    /// pure-prepend added guard.
    #[test]
    fn sphinx_safe_getattr_is_added_narrowing_guard() {
        let old = body(vec![Statement::plain(MAINLINE)]);
        let new = body(vec![
            Statement::exit_guard(100, vec![PRED_ARGS]),
            Statement::plain(MAINLINE),
        ]);
        assert_eq!(
            classify_change_shape(&old, &new),
            ChangeShape::AddedNarrowingGuard { guards_added: 1 }
        );
        assert_eq!(
            gate_action_for(&classify_change_shape(&old, &new)),
            GateAction::EnrichEvidenceOnly
        );
    }

    /// `b9cacbc347` cli: `if HasSuffix(.md): append` becomes
    /// `if HasSuffix(.md) && Type()!=symlink: append` — a strictly tighter
    /// predicate over the same guarded block (monotone narrowing).
    #[test]
    fn cli_symlink_exclusion_is_added_narrowing_guard() {
        let old = body(vec![Statement::guarded_block(200, vec![PRED_MD], APPEND)]);
        let new = body(vec![Statement::guarded_block(
            201,
            vec![PRED_MD, PRED_NOTSYMLINK],
            APPEND,
        )]);
        assert_eq!(
            classify_change_shape(&old, &new),
            ChangeShape::AddedNarrowingGuard { guards_added: 1 }
        );
    }

    /// A second monotone-narrowing conjunct case (the `FindLegacy` predicate in
    /// the same commit gains `&& Type()!=symlink` on top of two existing atoms).
    #[test]
    fn added_conjunct_to_multi_atom_predicate_is_narrowing() {
        let old = body(vec![Statement::guarded_block(
            300,
            vec![PRED_MD, PRED_NOTDIR],
            APPEND,
        )]);
        let new = body(vec![Statement::guarded_block(
            301,
            vec![PRED_MD, PRED_NOTDIR, PRED_NOTSYMLINK],
            APPEND,
        )]);
        assert_eq!(
            classify_change_shape(&old, &new),
            ChangeShape::AddedNarrowingGuard { guards_added: 1 }
        );
    }

    /// `f97a6123c0` django `build_filter`: `if A and B: work` is split into
    /// `if A: (if not B: raise) work`. The mainline `work` is preserved and an
    /// exit-guard is added, but the outer predicate is also restructured. The
    /// model cannot prove reachability is preserved, so it conservatively types
    /// this as a general behavior change — which is gate-neutral (`NoChange`),
    /// so the row stays flagged either way. Documented, not downgraded.
    #[test]
    fn django_build_filter_restructure_is_conservative_not_downgraded() {
        // old: `if A and B: work`
        let old = body(vec![Statement::guarded_block(
            400,
            vec![1000, 1001],
            MAINLINE,
        )]);
        // new: `if A: <exit-guard on not B> work`  (outer predicate now just A,
        // an inner raise added, `work` preserved as a top-level guarded block)
        let new = body(vec![
            Statement::guarded_block(401, vec![1000], MAINLINE),
            Statement::exit_guard(402, vec![1002]),
        ]);
        let shape = classify_change_shape(&old, &new);
        assert_eq!(shape, ChangeShape::OtherBehaviorChange);
        // The load-bearing property: a restructure is NEVER auto-passed.
        assert_ne!(gate_action_for(&shape), GateAction::Downgrade);
    }

    // --- The decisive adversarial proof (soundness boundary) ---------------

    /// THE PROOF. An adversarial `if user == "admin": raise` is a pure added
    /// early-exit guard — structurally IDENTICAL to the benign `safe_getattr`
    /// guard — yet it breaks legitimate admin access. The classifier cannot and
    /// does not distinguish them: both are `AddedNarrowingGuard`. Therefore the
    /// shape must never license a downgrade; it may only enrich evidence.
    #[test]
    fn adversarial_admin_lockout_is_indistinguishable_from_benign_guard() {
        // Benign: sphinx safe_getattr arg-count guard.
        let benign_old = body(vec![Statement::plain(MAINLINE)]);
        let benign_new = body(vec![
            Statement::exit_guard(500, vec![PRED_ARGS]),
            Statement::plain(MAINLINE),
        ]);
        // Adversarial: lock admins out of an account operation.
        let evil_old = body(vec![Statement::plain(MAINLINE)]);
        let evil_new = body(vec![
            Statement::exit_guard(501, vec![PRED_ADMIN]),
            Statement::plain(MAINLINE),
        ]);

        let benign = classify_change_shape(&benign_old, &benign_new);
        let evil = classify_change_shape(&evil_old, &evil_new);

        // Same class — the graph sees no difference.
        assert!(matches!(benign, ChangeShape::AddedNarrowingGuard { .. }));
        assert!(matches!(evil, ChangeShape::AddedNarrowingGuard { .. }));

        // Hence neither may downgrade; both may only enrich evidence.
        assert_eq!(gate_action_for(&benign), GateAction::EnrichEvidenceOnly);
        assert_eq!(gate_action_for(&evil), GateAction::EnrichEvidenceOnly);
        assert_ne!(gate_action_for(&evil), GateAction::Downgrade);
    }

    /// Adversarial case 2: a guard whose branch performs work (a call / send /
    /// mutation) masquerading as a guard is NOT a pure narrowing guard. It must
    /// not even reach the narrowing class.
    #[test]
    fn effectful_branch_is_not_a_narrowing_guard() {
        let old = body(vec![Statement::plain(MAINLINE)]);
        let new = body(vec![
            Statement::effectful_conditional(600, vec![PRED_ADMIN]),
            Statement::plain(MAINLINE),
        ]);
        let shape = classify_change_shape(&old, &new);
        assert_eq!(shape, ChangeShape::OtherBehaviorChange);
        assert_eq!(gate_action_for(&shape), GateAction::NoChange);
    }

    // --- Direction check: the mirror TPs must stay flagged -----------------

    /// Adversarial case 3 / `b55526f4e8`: removing the `_parse_expression_fallback`
    /// method and stripping its call sites is a REMOVAL — the opposite
    /// direction — and must never be typed as a narrowing guard.
    #[test]
    fn sphinx_fallback_removal_mirror_stays_flagged() {
        // old: the fallback method (plain def) plus a call to it.
        let old = body(vec![Statement::plain(700), Statement::plain(701)]);
        // new: both gone, replaced by a direct call.
        let new = body(vec![Statement::plain(702)]);
        let shape = classify_change_shape(&old, &new);
        assert_eq!(
            shape,
            ChangeShape::RemovedGuardOrWidened {
                statements_removed: 2
            }
        );
        assert_ne!(gate_action_for(&shape), GateAction::Downgrade);
    }

    /// `20f625b4d3` sphinx `Builder.build`: the `if updated_docnames:` guard is
    /// lifted off the env-save block, making the save unconditional — a guard
    /// REMOVAL / widening. Same direction as the fallback-removal mirror; stays
    /// flagged.
    #[test]
    fn sphinx_builder_build_guard_removal_stays_flagged() {
        // old: `if updated: save`  then  `if updated: global`
        let old = body(vec![
            Statement::guarded_block(800, vec![PRED_READY], 8001),
            Statement::guarded_block(801, vec![PRED_READY], 8002),
        ]);
        // new: `save` (now unconditional)  then  `if updated: global`
        let new = body(vec![
            Statement::plain(8001),
            Statement::guarded_block(801, vec![PRED_READY], 8002),
        ]);
        let shape = classify_change_shape(&old, &new);
        assert!(matches!(shape, ChangeShape::RemovedGuardOrWidened { .. }));
        assert_ne!(gate_action_for(&shape), GateAction::Downgrade);
    }

    // --- Genuine changes and equivalence -----------------------------------

    /// A genuine feature addition (new straight-line work, not a guard) is a
    /// behavior change, not a narrowing.
    #[test]
    fn feature_addition_is_other_behavior_change() {
        let old = body(vec![Statement::plain(MAINLINE)]);
        let new = body(vec![
            Statement::plain(MAINLINE),
            Statement::plain(900), // new feature statement
        ]);
        assert_eq!(
            classify_change_shape(&old, &new),
            ChangeShape::OtherBehaviorChange
        );
    }

    /// Structurally identical bodies are the only shape allowed to downgrade —
    /// and that is the behavior-equivalence channel's job, included here only
    /// for completeness of the action table.
    #[test]
    fn identical_body_is_equivalent_and_only_it_may_downgrade() {
        let b = body(vec![
            Statement::exit_guard(1, vec![PRED_ARGS]),
            Statement::plain(MAINLINE),
        ]);
        assert_eq!(classify_change_shape(&b, &b), ChangeShape::Equivalent);
        assert_eq!(
            gate_action_for(&ChangeShape::Equivalent),
            GateAction::Downgrade
        );
    }

    /// The universal invariant: across every shape this classifier can emit, the
    /// ONLY one that ever downgrades is `Equivalent`. No genuine behavior change
    /// — narrowing guard, widening removal, or otherwise — is ever auto-passed.
    #[test]
    fn no_behavior_change_shape_ever_downgrades() {
        let shapes = [
            ChangeShape::AddedNarrowingGuard { guards_added: 1 },
            ChangeShape::AddedNarrowingGuard { guards_added: 9 },
            ChangeShape::RemovedGuardOrWidened {
                statements_removed: 1,
            },
            ChangeShape::OtherBehaviorChange,
        ];
        for shape in shapes {
            assert_ne!(
                gate_action_for(&shape),
                GateAction::Downgrade,
                "shape {shape:?} must never downgrade the gate"
            );
        }
    }

    /// The narrowing evidence note describes the shape, never asserts safety.
    #[test]
    fn narrowing_evidence_note_is_neutral_about_safety() {
        let note = evidence_note(&ChangeShape::AddedNarrowingGuard { guards_added: 2 })
            .expect("narrowing has a note");
        assert!(note.contains("narrowing guard"));
        assert!(note.contains("not graph-verifiable"));
        // It must not claim the change is safe.
        assert!(!note.to_lowercase().contains("safe to merge"));
        assert!(evidence_note(&ChangeShape::OtherBehaviorChange).is_none());
    }
}
