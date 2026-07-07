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
//! Findings feed the gate as ordinary warning findings through the
//! inline-comment channel (the same shape as the command-effect and
//! toolchain-surface channels), never through evidence-gap demotion. When the
//! base has less history than the window can meaningfully scan, the channel
//! reports an honest evidence gap instead of silently passing.
//!
//! Matching is computed at review time from the change DAG and the entity
//! revision store. Persisting the same evidence as graph relations
//! (Reverts/RegressedBy edges written by an ingest-time miner) is the durable
//! follow-on; the review-time computation here is the channel's semantic
//! contract and stays the oracle for that miner.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use kin_model::change::{EntityDelta, SemanticChange};
use kin_model::graph::GraphStore;
use kin_model::{Entity, EntityId, EntityKind, Hash256, SemanticChangeId};

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

/// Upper bound on removed-entity resolutions per review. Each resolution is a
/// revision-history lookup; windows are small in practice and this cap only
/// guards pathological histories.
const MAX_REMOVED_RESOLUTIONS: usize = 512;

/// One removed-entity occurrence inside the scanned window.
struct WindowRemoval {
    entity_id: EntityId,
    /// 1-based distance from the base (1 = the change immediately before base).
    distance: usize,
}

/// Revert-history findings plus an optional honesty gap for the scanned base.
pub(crate) fn collect_revert_history_findings<G: GraphStore>(
    store: &G,
    resolved_base: &SemanticChangeId,
    range_changes: &[SemanticChange],
) -> Result<(Vec<InlineComment>, Option<ShadowEvidenceGap>), ReviewError> {
    let window = walk_base_window(store, resolved_base)?;

    let gap = if window.changes_scanned < REVERT_HISTORY_MIN_DEPTH {
        Some(ShadowEvidenceGap {
            kind: "revert_history_shallow".to_string(),
            subject: "blast_radius.revert_history".to_string(),
            detail: format!(
                "only {} change(s) of history exist before the base (window {}); \
                 revert/reintroduction evidence cannot be assessed and is NOT part \
                 of this verdict",
                window.changes_scanned, REVERT_HISTORY_WINDOW
            ),
        })
    } else {
        None
    };

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
    // produces a Modified delta, not add/remove). The immediately-previous
    // body is skipped: every edit trivially differs from its predecessor;
    // only a return to DEEPER history is revert-shaped. Hash equality on the
    // behavior fingerprint makes the match exact, so this cannot fire on an
    // ordinary edit.
    for (name, (old, new)) in &head_modified {
        if new.fingerprint.behavior_hash == old.fingerprint.behavior_hash {
            continue;
        }
        let history = match store.get_entity_history(&old.id) {
            Ok(h) => h,
            Err(_) => continue,
        };
        // Bodies this entity carried before the range, newest-first, capped by
        // the window. Position 0 is the body the range started from (old) —
        // matching it would be a no-op edit, so matches start at depth 1.
        let mut prior_bodies: Vec<Hash256> = Vec::new();
        for change in history.iter().rev() {
            if prior_bodies.len() > REVERT_HISTORY_WINDOW {
                break;
            }
            for delta in &change.entity_deltas {
                match delta {
                    EntityDelta::Modified { old: o, new: n } if n.id == old.id => {
                        if prior_bodies.is_empty() {
                            prior_bodies.push(n.fingerprint.behavior_hash);
                        }
                        prior_bodies.push(o.fingerprint.behavior_hash);
                    }
                    EntityDelta::Added(e) if e.id == old.id => {
                        if prior_bodies.is_empty() {
                            prior_bodies.push(e.fingerprint.behavior_hash);
                        }
                    }
                    _ => {}
                }
            }
        }
        if let Some(depth) = prior_bodies
            .iter()
            .skip(1)
            .position(|h| *h == new.fingerprint.behavior_hash)
        {
            findings.push(inline_finding(
                new,
                format!(
                    "Modified `{}` restores the exact body it had {} revision(s) ago — \
                     revert-shaped body reversion",
                    name,
                    depth + 1
                ),
            ));
        }
    }

    // Reintroductions: an added entity matching a window removal. Removed
    // deltas carry only the id, so each candidate is resolved to its last full
    // value through the revision history — lazily, nearest-first, and cached,
    // so cost tracks matches rather than window size.
    if !head_added.is_empty() && !window.removals.is_empty() {
        let mut resolved: HashMap<EntityId, Option<Entity>> = HashMap::new();
        let mut by_hash: HashMap<Hash256, (String, usize)> = HashMap::new();
        let mut by_name: HashMap<(String, String), usize> = HashMap::new();
        let budget = window.removals.len().min(MAX_REMOVED_RESOLUTIONS);
        for removal in window.removals.iter().take(budget) {
            let entity = resolved
                .entry(removal.entity_id)
                .or_insert_with(|| last_known_entity(store, &removal.entity_id));
            let Some(entity) = entity else { continue };
            by_hash
                .entry(entity.fingerprint.behavior_hash)
                .or_insert((entity.name.clone(), removal.distance));
            by_name
                .entry((kind_key(entity.kind), entity.name.clone()))
                .or_insert(removal.distance);
        }

        for ((kind, name), added) in &head_added {
            let finding = if let Some((removed_name, distance)) =
                by_hash.get(&added.fingerprint.behavior_hash)
            {
                Some(format!(
                    "Added `{}` restores the exact content of `{}`, removed {} — \
                     revert-shaped reintroduction",
                    name,
                    removed_name,
                    distance_phrase(*distance)
                ))
            } else {
                by_name.get(&(kind.clone(), name.clone())).map(|distance| {
                    format!(
                        "Added `{}` reintroduces a same-named {} removed {}, with \
                         modified content — revert-shaped surface",
                        name,
                        kind_label(added.kind),
                        distance_phrase(*distance)
                    )
                })
            };
            if let Some(message) = finding {
                findings.push(inline_finding(added, message));
            }
        }
    }

    // Recent-addition removals: a removed entity whose id was introduced
    // inside the window. Ids are location-keyed, so this matches the common
    // revert shape where the added lines are deleted in place.
    for removed_id in &head_removed {
        if let Some(distance) = window.added_ids.get(removed_id) {
            let name = last_known_entity(store, removed_id)
                .map(|e| e.name)
                .unwrap_or_else(|| "entity".to_string());
            findings.push(InlineComment {
                file: String::new(),
                start_line: 0,
                end_line: 0,
                kind: InlineCommentKind::RevertHistory,
                message: format!(
                    "Removed `{}` was introduced only {} — revert-shaped removal \
                     of a recent addition",
                    name,
                    distance_phrase(*distance)
                ),
            });
        }
    }

    Ok((findings, gap))
}

/// Everything the channel learned from scanning the base's ancestry window.
struct BaseWindow {
    changes_scanned: usize,
    removals: Vec<WindowRemoval>,
    /// Entity ids ADDED inside the window, with their distance from the base.
    added_ids: HashMap<EntityId, usize>,
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
    let mut visited: HashSet<SemanticChangeId> = HashSet::new();
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
        let Some(change) = store.get_change(&id).map_err(ReviewError::graph)? else {
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
                }
                EntityDelta::Modified { .. } => {}
            }
        }
        for parent in &change.parents {
            queue.push_back((*parent, distance + 1));
        }
    }

    Ok(BaseWindow {
        changes_scanned: scanned,
        removals,
        added_ids,
    })
}

/// The last full value an entity carried before disappearing, recovered from
/// the changes that touched it: the most recent Added or Modified delta whose
/// entity matches the id.
fn last_known_entity<G: GraphStore>(store: &G, id: &EntityId) -> Option<Entity> {
    let history = store.get_entity_history(id).ok()?;
    history.iter().rev().find_map(|change| {
        change.entity_deltas.iter().find_map(|delta| match delta {
            EntityDelta::Added(e) if e.id == *id => Some(e.clone()),
            EntityDelta::Modified { new, .. } if new.id == *id => Some(new.clone()),
            _ => None,
        })
    })
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
