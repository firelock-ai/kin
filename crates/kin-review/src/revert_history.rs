// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Revert-history evidence channel for shadow review.
//!
//! A change that RE-INTRODUCES an entity removed in the recent past, or that
//! REMOVES an entity introduced in the recent past, is revert-shaped: its risk
//! evidence is temporal, not structural. Structurally such a change reads as an
//! ordinary addition or removal — additions in particular carry no gating
//! signal at all — so without this channel the gate is blind to exactly the
//! class regression-fix and revert commits fall into.
//!
//! The channel walks a bounded window of the BASE ref's ancestry — including
//! the base change itself, whose deltas are part of the state the head builds
//! on (reverting the immediately-preceding change is the most common revert
//! shape). Only evidence available at review time is consulted; whether a
//! commit will be reverted LATER is future information and never enters. It
//! matches:
//!
//! - head-side ADDED entities against entities removed inside the window —
//!   a behavior-fingerprint match means the added body restores removed
//!   content verbatim (strong); a name+kind match means the same surface is
//!   reintroduced with modified content (weak). Both are review-worthy.
//! - head-side REMOVED entities against entities added inside the window —
//!   deleting something that only just landed is the shape of a revert of a
//!   recent feature.
//!
//! Strong matches feed the gate as ordinary warning findings through the
//! inline-comment channel (the same shape as the command-effect and
//! toolchain-surface channels), never through evidence-gap demotion. Weaker
//! temporal evidence is still reported but stays informational: the benign-60
//! sweep showed that deleting a recent addition is common cleanup unless an
//! independent review signal also says the change is risky. When the base has
//! less history than the window can meaningfully scan, or when the graph cannot
//! resolve an ancestry reference the DAG declares, the channel reports an
//! honest evidence gap instead of silently passing: a window built from an
//! incomplete DAG must never be presented as a complete one.
//!
//! Matching is computed at review time exclusively from the base's ancestry
//! window — the graph may hold changes outside the reviewed lineage (other
//! branches, other reviews' hydrations, states newer than the head), and none
//! of those may serve as evidence. Persisting the same evidence as graph
//! relations (Reverts/RegressedBy edges written by an ingest-time miner) is
//! the durable follow-on; the review-time computation here is the channel's
//! semantic contract and stays the oracle for that miner.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use kin_model::change::{EntityDelta, SemanticChange};
use kin_model::graph::GraphStore;
use kin_model::{Entity, EntityId, EntityKind, Hash256, SemanticChangeId, Visibility};

use crate::error::ReviewError;
use crate::inline::{InlineComment, InlineCommentKind};
use crate::shadow::ShadowEvidenceGap;

/// How many ancestry changes before the base the channel scans. Deep enough to
/// catch release-cycle reverts and regression fixes; bounded so review cost
/// stays flat on large histories.
const REVERT_HISTORY_WINDOW: usize = 250;

/// Below this much available ancestry the scan cannot say anything meaningful
/// about revert history, so the channel reports a gap rather than certifying
/// silence.
const REVERT_HISTORY_MIN_DEPTH: usize = 25;

/// One removed-entity occurrence inside the scanned window.
struct WindowRemoval {
    entity_id: EntityId,
    /// 1-based distance from the base (1 = the change immediately before base).
    distance: usize,
}

/// Revert-history findings plus the honesty gaps for the scanned base.
pub(crate) fn collect_revert_history_findings<G: GraphStore>(
    store: &G,
    resolved_base: &SemanticChangeId,
    range_changes: &[SemanticChange],
) -> Result<(Vec<InlineComment>, Vec<ShadowEvidenceGap>), ReviewError> {
    let window = walk_base_window(store, resolved_base)?;

    let mut gaps = Vec::new();

    // An ancestry reference the graph cannot resolve truncates the walk twice
    // over: the unresolved change contributes no deltas, and its own parents
    // are never enqueued, so an arbitrarily large subtree of the base's causal
    // past is absent from the window. Scanning fewer changes than the DAG
    // declares makes the channel's silence unfalsifiable — indistinguishable
    // from "no revert evidence exists" — so the deficit is reported rather than
    // absorbed. This is a graph gap, not a shallow history: the count below can
    // clear REVERT_HISTORY_MIN_DEPTH while the window is still incomplete.
    if !window.unresolved_ancestry.is_empty() {
        let (first_id, first_distance) = window.unresolved_ancestry[0];
        let where_phrase = if first_distance == 0 {
            "the resolved base itself".to_string()
        } else {
            format!("{} change(s) before the base", first_distance)
        };
        gaps.push(ShadowEvidenceGap {
            kind: "revert_history_incomplete_ancestry".to_string(),
            subject: "blast_radius.revert_history".to_string(),
            detail: format!(
                "{} ancestry reference(s) of the base do not resolve to a change in the \
                 graph (first: {} at {}); the walk terminated at each, so their deltas \
                 and their own ancestry are absent from the {} change(s) actually \
                 scanned. Revert/reintroduction evidence was assessed against an \
                 INCOMPLETE ancestry DAG, and the absence of a finding is NOT proof \
                 that no revert exists",
                window.unresolved_ancestry.len(),
                first_id,
                where_phrase,
                window.changes_scanned
            ),
        });
    }

    if window.changes_scanned < REVERT_HISTORY_MIN_DEPTH {
        gaps.push(ShadowEvidenceGap {
            kind: "revert_history_shallow".to_string(),
            subject: "blast_radius.revert_history".to_string(),
            detail: format!(
                "only {} change(s) of history exist before the base (window {}); \
                 revert/reintroduction evidence cannot be assessed and is NOT part \
                 of this verdict",
                window.changes_scanned, REVERT_HISTORY_WINDOW
            ),
        });
    }

    // Head-side deltas for the reviewed range, deduplicated and order-stable.
    let mut head_added: BTreeMap<(String, String), Entity> = BTreeMap::new();
    let mut head_removed: Vec<EntityId> = Vec::new();
    let mut seen_removed: HashSet<EntityId> = HashSet::new();
    let mut head_modified: BTreeMap<String, (Entity, Entity)> = BTreeMap::new();
    for change in range_changes {
        for delta in &change.entity_deltas {
            match delta {
                EntityDelta::Added(entity) => {
                    head_added
                        .entry((kind_key(entity.kind), entity.name.clone()))
                        .or_insert_with(|| entity.clone());
                }
                EntityDelta::Removed(id) => {
                    if seen_removed.insert(*id) {
                        head_removed.push(*id);
                    }
                }
                EntityDelta::Modified { old, new } => {
                    // Multiple range changes touching one entity collapse to
                    // the net old→new pair: earliest old, latest new.
                    head_modified
                        .entry(new.name.clone())
                        .and_modify(|(_, latest)| *latest = new.clone())
                        .or_insert_with(|| (old.clone(), new.clone()));
                }
            }
        }
    }

    let mut findings = Vec::new();

    // Body reversions: a modified entity whose NEW body equals a body it
    // carried at an OLDER revision — the head un-does a later edit. This is
    // the dominant real-world revert shape (git revert of a body change
    // produces a Modified delta, not add/remove). Hash equality on the
    // behavior fingerprint makes the match exact, so this cannot fire on an
    // ordinary edit.
    //
    // Candidate bodies come ONLY from the base's ancestry window: each
    // in-window change's pre-state for the entity (restoring it un-does that
    // change). The graph at review time may also hold changes OUTSIDE this
    // lineage — head-side commits, other branches, other reviews' hydrations,
    // states newer than the head. A change made after the head trivially has
    // the head's result as its pre-state, so consulting it would flag every
    // entity that is ever edited again: evidence must never leave the base's
    // causal past.
    //
    // Matches are grouped by the SEMANTIC CHANGE whose delta carried the
    // matching old body. A true revert restores a coherent snapshot: several
    // of the head's entities return to bodies from the same historical change.
    // An isolated single-entity match is usually incidental — small bodies
    // recur naturally over long histories — so only COHERENT groups (two or
    // more entities reverting to the same change) gate the verdict; singleton
    // matches are still reported, at info severity, for the reviewer.
    let mut reversion_matches: Vec<(Entity, String, SemanticChangeId, usize)> = Vec::new();
    for (name, (old, new)) in &head_modified {
        if new.fingerprint.behavior_hash == old.fingerprint.behavior_hash {
            continue;
        }
        let Some(prior_bodies) = window.prior_bodies.get(&old.id) else {
            continue;
        };
        if let Some((distance, _, undone_change)) = prior_bodies
            .iter()
            .find(|(_, hash, _)| *hash == new.fingerprint.behavior_hash)
        {
            reversion_matches.push((new.clone(), name.clone(), *undone_change, *distance));
        }
    }

    // A coordinated revert (>=2 entities restoring bodies from the same change)
    // gates only the public contract leaves it touches. Module/class aggregates
    // co-revert for free (a module mirrors its file), and private-helper or test
    // reversions are ordinary churn — those stay informational. A singleton
    // match is incidental (small bodies recur over long histories) and never
    // gates.
    let mut undone_counts: HashMap<SemanticChangeId, usize> = HashMap::new();
    for (_, _, undone, _) in &reversion_matches {
        *undone_counts.entry(*undone).or_insert(0) += 1;
    }
    for (entity, name, undone, distance) in &reversion_matches {
        let coherent = undone_counts.get(undone).copied().unwrap_or(0) >= 2;
        let gates = coherent && is_public_contract_leaf(entity);
        let undone_phrase = if *distance == 0 {
            "the base change".to_string()
        } else {
            format!("the change {} change(s) before the base", distance)
        };
        let message = format!(
            "Modified `{}` restores the exact body it had before {}{} — \
             revert-shaped body reversion",
            name,
            undone_phrase,
            if coherent {
                ", together with other entities un-doing the same change"
            } else {
                ""
            },
        );
        let mut finding = inline_finding(entity, message);
        finding.kind = if gates {
            InlineCommentKind::RevertHistory
        } else {
            InlineCommentKind::RevertHistoryIncidental
        };
        findings.push(finding);
    }

    // Reintroductions: an added entity matching a window removal. Removed
    // deltas carry only the id, so each candidate resolves to the value the
    // entity last carried inside the window — never a value from outside the
    // base's lineage.
    if !head_added.is_empty() && !window.removals.is_empty() {
        let mut by_hash: HashMap<Hash256, (String, usize)> = HashMap::new();
        let mut by_name: HashMap<(String, String), usize> = HashMap::new();
        for removal in &window.removals {
            let Some(entity) = window.values.get(&removal.entity_id) else {
                continue;
            };
            by_hash
                .entry(entity.fingerprint.behavior_hash)
                .or_insert((entity.name.clone(), removal.distance));
            by_name
                .entry((kind_key(entity.kind), entity.name.clone()))
                .or_insert(removal.distance);
        }

        // An exact behavior-fingerprint restore is strong evidence: it gates as
        // a warning on a public contract, informational otherwise. A bare
        // name+kind match with modified content is weak temporal evidence — a
        // same-named surface recurs naturally over a long history, and the
        // namesake may be an unrelated entity in another file — so it is
        // reported but never gates, like the other weak revert shapes.
        for ((kind, name), added) in &head_added {
            let comment = if let Some((removed_name, distance)) =
                by_hash.get(&added.fingerprint.behavior_hash)
            {
                let message = format!(
                    "Added `{}` restores the exact content of `{}`, removed {} — \
                     revert-shaped reintroduction",
                    name,
                    removed_name,
                    distance_phrase(*distance)
                );
                let mut comment = inline_finding(added, message);
                if !is_public_contract(added) {
                    comment.kind = InlineCommentKind::RevertHistoryIncidental;
                }
                Some(comment)
            } else if let Some(distance) = by_name.get(&(kind.clone(), name.clone())) {
                let message = format!(
                    "Added `{}` reintroduces a same-named {} removed {}, with \
                     modified content — revert-shaped surface",
                    name,
                    kind_label(added.kind),
                    distance_phrase(*distance)
                );
                let mut comment = inline_finding(added, message);
                comment.kind = InlineCommentKind::RevertHistoryIncidental;
                Some(comment)
            } else {
                None
            };
            if let Some(comment) = comment {
                findings.push(comment);
            }
        }
    }

    // Recent-addition removals: a removed entity whose id was introduced
    // inside the window. Ids are location-keyed, so this matches the common
    // revert shape where the added lines are deleted in place.
    for removed_id in &head_removed {
        if let Some(distance) = window.added_ids.get(removed_id) {
            let removed = window.values.get(removed_id);
            let name = removed
                .map(|e| e.name.clone())
                .unwrap_or_else(|| "entity".to_string());
            findings.push(InlineComment {
                file: String::new(),
                start_line: 0,
                end_line: 0,
                kind: InlineCommentKind::RevertHistoryIncidental,
                message: format!(
                    "Removed `{}` was introduced only {} — revert-shaped removal \
                     of a recent addition",
                    name,
                    distance_phrase(*distance)
                ),
            });
        }
    }

    Ok((findings, gaps))
}

/// Everything the channel learned from scanning the base's ancestry window.
/// This is the channel's ONLY evidence source: nothing outside the base's
/// causal past may influence a finding.
struct BaseWindow {
    changes_scanned: usize,
    /// Ancestry references the graph could not resolve, in the walk's
    /// deterministic discovery order, each with the distance it was reached at.
    /// Non-empty means the window is a strict subset of the declared ancestry
    /// and the channel's silence cannot be trusted.
    unresolved_ancestry: Vec<(SemanticChangeId, usize)>,
    removals: Vec<WindowRemoval>,
    /// Entity ids ADDED inside the window, with their distance from the base.
    added_ids: HashMap<EntityId, usize>,
    /// Per entity, the body it had BEFORE each in-window change that modified
    /// it, in ascending distance from the base. Restoring one of these bodies
    /// un-does the tagged change.
    prior_bodies: HashMap<EntityId, Vec<(usize, Hash256, SemanticChangeId)>>,
    /// The nearest-to-base full value each entity carried inside the window.
    values: HashMap<EntityId, Entity>,
}

/// Bounded, deterministic walk of the base's ancestry: breadth-first from the
/// base's parents, parents visited in their declared order, capped at
/// [`REVERT_HISTORY_WINDOW`] changes. Distance is the BFS depth, so "N
/// change(s) before the base" reads naturally on linear history and stays
/// deterministic across merges.
fn walk_base_window<G: GraphStore>(
    store: &G,
    resolved_base: &SemanticChangeId,
) -> Result<BaseWindow, ReviewError> {
    let mut removals = Vec::new();
    let mut added_ids = HashMap::new();
    let mut prior_bodies: HashMap<EntityId, Vec<(usize, Hash256, SemanticChangeId)>> =
        HashMap::new();
    let mut values: HashMap<EntityId, Entity> = HashMap::new();
    let mut visited: HashSet<SemanticChangeId> = HashSet::new();
    let mut unresolved_ancestry: Vec<(SemanticChangeId, usize)> = Vec::new();
    let mut queue: VecDeque<(SemanticChangeId, usize)> = VecDeque::new();

    // The base change itself is scanned at distance 0: its deltas are part of
    // the state the head builds on, and reverting the immediately-preceding
    // change is the most common revert shape.
    queue.push_back((*resolved_base, 0));

    let mut scanned = 0usize;
    while let Some((id, distance)) = queue.pop_front() {
        if scanned >= REVERT_HISTORY_WINDOW {
            break;
        }
        if !visited.insert(id) {
            continue;
        }
        // A declared ancestor the graph cannot produce is a graph gap, not an
        // end of history: its deltas and its own ancestry silently leave the
        // window. Record it so the caller can report the deficit; continuing
        // the walk still surfaces whatever evidence the reachable ancestry
        // does hold, which is strictly more useful than abandoning the scan.
        let Some(change) = store.get_change(&id).map_err(ReviewError::graph)? else {
            unresolved_ancestry.push((id, distance));
            continue;
        };
        scanned += 1;
        for delta in &change.entity_deltas {
            match delta {
                EntityDelta::Removed(entity_id) => removals.push(WindowRemoval {
                    entity_id: *entity_id,
                    distance,
                }),
                EntityDelta::Added(entity) => {
                    added_ids.entry(entity.id).or_insert(distance);
                    values.entry(entity.id).or_insert_with(|| entity.clone());
                }
                EntityDelta::Modified { old, new } => {
                    // The old body is the entity's state BEFORE this change;
                    // a head restoring it un-does this change.
                    let record = (distance, old.fingerprint.behavior_hash, change.id);
                    prior_bodies.entry(new.id).or_default().push(record);
                    if old.id != new.id {
                        prior_bodies.entry(old.id).or_default().push(record);
                    }
                    values.entry(new.id).or_insert_with(|| new.clone());
                }
            }
        }
        for parent in &change.parents {
            queue.push_back((*parent, distance + 1));
        }
    }

    Ok(BaseWindow {
        changes_scanned: scanned,
        unresolved_ancestry,
        removals,
        added_ids,
        prior_bodies,
        values,
    })
}

// A public, non-test/generated/vendored entity — a real contract surface whose
// revert is worth gating on, as opposed to private-helper or test churn.
fn is_public_contract(entity: &Entity) -> bool {
    entity.visibility == Visibility::Public
        && !crate::inline::is_non_contract_surface_role(entity.role)
}

// Body-reversion coherence gates only on leaves (functions/methods): a module or
// class aggregates its members, so it co-reverts for free and inflates coherence.
fn is_public_contract_leaf(entity: &Entity) -> bool {
    is_public_contract(entity) && matches!(entity.kind, EntityKind::Function | EntityKind::Method)
}

fn inline_finding(entity: &Entity, message: String) -> InlineComment {
    let (file, start_line, end_line) = match (&entity.file_origin, &entity.span) {
        (Some(file), Some(span)) => (file.0.clone(), span.start_line, span.end_line),
        (Some(file), None) => (file.0.clone(), 0, 0),
        _ => (String::new(), 0, 0),
    };
    InlineComment {
        file,
        start_line,
        end_line,
        kind: InlineCommentKind::RevertHistory,
        message,
    }
}

/// Stable string key for an entity kind (EntityKind carries no Ord).
fn kind_key(kind: EntityKind) -> String {
    format!("{:?}", kind)
}

/// Human phrase for a window distance: the base change itself is distance 0.
fn distance_phrase(distance: usize) -> String {
    if distance == 0 {
        "in the base change itself".to_string()
    } else {
        format!("{} change(s) before the base", distance)
    }
}

fn kind_label(kind: EntityKind) -> &'static str {
    match kind {
        EntityKind::Function => "function",
        EntityKind::Method => "method",
        EntityKind::Class => "class",
        EntityKind::Interface => "interface",
        EntityKind::TraitDef => "trait",
        EntityKind::Module => "module",
        EntityKind::Constant => "constant",
        _ => "entity",
    }
}
