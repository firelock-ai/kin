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
//! The channel walks a bounded window of the BASE ref's ancestry (evidence
//! available at review time; whether a commit will be reverted LATER is future
//! information and is never consulted) and matches:
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
                EntityDelta::Modified { .. } => {}
            }
        }
    }

    let mut findings = Vec::new();

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
                    "Added `{}` restores the exact content of `{}`, removed {} change(s) \
                     before the base — revert-shaped reintroduction",
                    name, removed_name, distance
                ))
            } else {
                by_name.get(&(kind.clone(), name.clone())).map(|distance| {
                    format!(
                        "Added `{}` reintroduces a same-named {} removed {} change(s) \
                         before the base, with modified content — revert-shaped surface",
                        name,
                        kind_label(added.kind),
                        distance
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
                    "Removed `{}` was introduced only {} change(s) before the base — \
                     revert-shaped removal of a recent addition",
                    name, distance
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

    if let Some(base) = store
        .get_change(resolved_base)
        .map_err(ReviewError::graph)?
    {
        for parent in &base.parents {
            queue.push_back((*parent, 1));
        }
    }
    visited.insert(*resolved_base);

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
