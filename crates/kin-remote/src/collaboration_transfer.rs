// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Review records on the repository transfer seam.
//!
//! Review state is replicated collaboration authority, so a push and a pull carry
//! it after the ref phase, in a pack that moves no history. The exporting side
//! offers its review domain: every review, its decision and assignment histories,
//! its notes, the copy of each discussion it serves, and the actors and review
//! audit events those writes recorded. The side that sends to a holder sends only
//! what the holder lacks, merged so the holder never loses a record, and names
//! every record it cannot settle instead of overwriting it.
//!
//! What decides a conflict is always a history one side can prove, never a clock
//! alone. A review's state moves only when a decision is recorded, and authority
//! keeps each review's decisions, so the review whose decisions contain the
//! other's is the newer one. A discussion's copies are kept in authority in the
//! order they were admitted, so a copy that appears in a replica's own history is
//! older than that replica's current copy. Where neither holds, the record is a
//! named gap.

use std::cmp::Ordering;
use std::collections::HashMap;

use kin_db::GraphSnapshot;
use kin_model::provenance::{Actor, ActorId, AuditEvent, AuditEventId};
use kin_model::review::{
    Review, ReviewAssignment, ReviewComment, ReviewDecision, ReviewDiscussion, ReviewDiscussionId,
    ReviewId, ReviewNote, ReviewNoteId,
};
use kin_model::{CollaborationDelta, Keyed};
use serde::{Deserialize, Serialize};

use crate::repository_transfer::RepositoryTransferReceipt;
use crate::repository_transfer_negotiation::RepositoryTransferDirection;

/// The most review-domain records one collaboration pack carries.
///
/// A count, not a byte size: review records are small and bounded by what a
/// person or an agent writes, so the count is what grows with a repository's
/// review history. Past it a transfer refuses by name rather than sending a
/// partial set.
pub const MAX_COLLABORATION_RECORDS: usize = 20_000;

/// The audit actions a review write records, and so the audit events that travel
/// with review state.
const REVIEW_AUDIT_PREFIX: &str = "review.";

/// A record two replicas hold differently that the merge cannot settle, named
/// rather than overwritten.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollaborationGap {
    /// What the record is, such as `review 1f0c...`.
    pub record: String,
    /// Both versions, and why neither can be preferred.
    pub detail: String,
}

/// What the review phase of a push or a pull did.
///
/// The review phase runs after the ref phase, so by the time it reports, the
/// history the transfer moved is already durable. That is why a review phase
/// that cannot complete is an outcome rather than an error: failing the
/// transfer would tell the caller a publication that happened did not.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CollaborationTransfer {
    /// Both replicas' collaboration roots already agree, so nothing was compared
    /// and nothing was sent.
    InSync,
    /// The peer does not advertise `collaboration-v1`, so no review record
    /// travelled. `local_records` is how many this replica holds that stayed
    /// here on a push; a pull cannot count what the peer holds.
    PeerUnsupported { local_records: Option<usize> },
    /// There was nothing to anchor review records to, such as a ref neither
    /// replica publishes yet.
    Skipped { reason: String },
    /// The two replicas' review records were compared. `carried` records were
    /// published on the receiving replica, none when it already held them all,
    /// and `gaps` names every record the merge could not settle.
    Exchanged {
        carried: usize,
        gaps: Vec<CollaborationGap>,
        receipt: Option<RepositoryTransferReceipt>,
    },
    /// The review phase did not complete and published nothing.
    Refused { reason: String },
}

/// What one side of a transfer sends to a holder, and what it names instead.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CollaborationMerge {
    /// The records the holder lacks, in the order kin-model accepts, or `None`
    /// when there is nothing to send.
    pub delta: Option<CollaborationDelta>,
    /// Records the merge could not settle.
    pub gaps: Vec<CollaborationGap>,
}

/// One replica's review domain, as the transfer seam exchanges it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReviewDomain {
    reviews: HashMap<ReviewId, Review>,
    decisions: HashMap<ReviewId, Vec<ReviewDecision>>,
    notes: HashMap<ReviewNoteId, ReviewNote>,
    /// The copy of each discussion this replica serves.
    discussions: HashMap<ReviewDiscussionId, ReviewDiscussion>,
    /// Every copy of each discussion this replica holds, in admission order.
    /// Present for a replica's own domain; a peer's export carries only the copy
    /// it serves, which is all a canonically ordered delta can say.
    discussion_history: HashMap<ReviewDiscussionId, Vec<ReviewDiscussion>>,
    assignments: HashMap<ReviewId, Vec<ReviewAssignment>>,
    actors: HashMap<ActorId, Actor>,
    audit_events: HashMap<AuditEventId, AuditEvent>,
}

impl ReviewDomain {
    /// This replica's own review domain, read from its authority snapshot.
    ///
    /// The snapshot keeps discussion copies in the order they were admitted, and
    /// the graph serves the last one, so the last copy per discussion is the
    /// current one and the rest are its history.
    pub fn from_snapshot(snapshot: &GraphSnapshot) -> Self {
        let mut domain = Self {
            reviews: snapshot.reviews.clone(),
            decisions: snapshot.review_decisions.clone(),
            notes: snapshot
                .review_notes
                .iter()
                .map(|note| (note.note_id, note.clone()))
                .collect(),
            assignments: snapshot.review_assignments.clone(),
            ..Self::default()
        };
        for discussion in &snapshot.review_discussions {
            domain
                .discussion_history
                .entry(discussion.discussion_id)
                .or_default()
                .push(discussion.clone());
            domain
                .discussions
                .insert(discussion.discussion_id, discussion.clone());
        }
        domain.adopt_provenance(&snapshot.audit_events, &snapshot.actors);
        domain
    }

    /// A peer's review domain, from the collaboration records it exported.
    pub fn from_delta(delta: &CollaborationDelta) -> Self {
        let mut domain = Self {
            reviews: delta
                .reviews
                .iter()
                .map(|entry| (entry.key, entry.value.clone()))
                .collect(),
            decisions: delta
                .review_decisions
                .iter()
                .map(|entry| (entry.key, entry.value.clone()))
                .collect(),
            notes: delta
                .review_notes
                .iter()
                .map(|note| (note.note_id, note.clone()))
                .collect(),
            discussions: delta
                .review_discussions
                .iter()
                .map(|discussion| (discussion.discussion_id, discussion.clone()))
                .collect(),
            assignments: delta
                .review_assignments
                .iter()
                .map(|entry| (entry.key, entry.value.clone()))
                .collect(),
            ..Self::default()
        };
        let actors: HashMap<ActorId, Actor> = delta
            .actors
            .iter()
            .map(|entry| (entry.key, entry.value.clone()))
            .collect();
        domain.adopt_provenance(&delta.audit_events, &actors);
        domain
    }

    /// Keep the review audit events and the actors they name.
    ///
    /// The `review.unassign` events among them are what records a reviewer's
    /// removal, so carrying them is what carries removals between replicas.
    fn adopt_provenance(&mut self, events: &[AuditEvent], actors: &HashMap<ActorId, Actor>) {
        for event in events {
            if event.action.starts_with(REVIEW_AUDIT_PREFIX) {
                if let Some(actor) = actors.get(&event.actor_id) {
                    self.actors.insert(event.actor_id, actor.clone());
                }
                self.audit_events.insert(event.event_id, event.clone());
            }
        }
    }

    /// How many records this domain holds, counting a history as one record.
    pub fn record_count(&self) -> usize {
        self.reviews.len()
            + self.decisions.len()
            + self.notes.len()
            + self.discussions.len()
            + self.assignments.len()
            + self.actors.len()
            + self.audit_events.len()
    }

    /// The whole domain as a delta, one current copy per discussion: what an
    /// exporter offers. `None` when the domain is empty.
    pub fn to_delta(&self) -> Option<CollaborationDelta> {
        let mut delta = CollaborationDelta {
            reviews: keyed(&self.reviews),
            review_decisions: keyed(&self.decisions),
            review_notes: self.notes.values().cloned().collect(),
            review_discussions: self.discussions.values().cloned().collect(),
            review_assignments: keyed(&self.assignments),
            actors: keyed(&self.actors),
            audit_events: self.audit_events.values().cloned().collect(),
            ..CollaborationDelta::default()
        };
        finish(&mut delta)
    }

    /// What `self` sends to `holder` so the holder ends up with both sides'
    /// records, and the records it names instead of sending.
    ///
    /// `direction` is the transfer this merge serves, which is only how its
    /// gaps name the two replicas: on a push this replica sends, on a pull the
    /// remote does.
    pub fn merge_into(
        &self,
        holder: &ReviewDomain,
        direction: RepositoryTransferDirection,
    ) -> CollaborationMerge {
        let sides = Sides::of(direction);
        let mut delta = CollaborationDelta::default();
        let mut gaps = Vec::new();

        for (id, review) in &self.reviews {
            match holder.reviews.get(id) {
                None => delta.reviews.push(Keyed::new(*id, review.clone())),
                Some(held) if held == review => {}
                Some(held) => {
                    if let Some(gap) =
                        self.settle_review(holder, sides, id, review, held, &mut delta)
                    {
                        gaps.push(gap);
                    }
                }
            }
        }
        for (id, ours) in &self.decisions {
            let theirs = holder.decisions.get(id).cloned().unwrap_or_default();
            let merged = appended(&theirs, ours);
            if merged != theirs {
                delta.review_decisions.push(Keyed::new(*id, merged));
            }
        }
        for (id, note) in &self.notes {
            match holder.notes.get(id) {
                None => delta.review_notes.push(note.clone()),
                Some(held) if held == note => {}
                Some(_) => gaps.push(CollaborationGap {
                    record: format!("review note {id}"),
                    detail:
                        "the two replicas hold different contents under one note id, and notes \
                             are never edited, so neither copy can be preferred"
                            .to_string(),
                }),
            }
        }
        for (id, ours) in &self.discussions {
            match holder.discussions.get(id) {
                None => delta.review_discussions.push(ours.clone()),
                Some(theirs) if theirs == ours => {}
                Some(theirs) => {
                    if let Some(gap) =
                        self.settle_discussion(holder, sides, id, ours, theirs, &mut delta)
                    {
                        gaps.push(gap);
                    }
                }
            }
        }
        // A review's assignment set only ever grows: a removal is recorded as a
        // `review.unassign` audit event, which travels with the events below,
        // and each replica derives its reviewers from the set and those events.
        // So merging the sets is appending, and no reviewer is taken off here.
        for (id, ours) in &self.assignments {
            let theirs = holder.assignments.get(id).cloned().unwrap_or_default();
            let merged = appended(&theirs, ours);
            if merged != theirs {
                delta.review_assignments.push(Keyed::new(*id, merged));
            }
            let held_only: Vec<&str> = theirs
                .iter()
                .filter(|assignment| !ours.contains(assignment))
                .map(|assignment| assignment.reviewer.name.as_str())
                .collect();
            if !held_only.is_empty() {
                gaps.push(CollaborationGap {
                    record: format!("assignments of review {id}"),
                    detail: format!(
                        "{} holds {} that {} does not; an assignment set only grows, and a removal \
                         travels as its own record, so this is a set written before removals were \
                         recorded and the difference cannot be read as either one",
                        sides.holder,
                        held_only.join(", "),
                        sides.sender
                    ),
                });
            }
        }
        for (id, actor) in &self.actors {
            match holder.actors.get(id) {
                None => delta.actors.push(Keyed::new(*id, actor.clone())),
                Some(held) if held == actor => {}
                Some(_) => gaps.push(CollaborationGap {
                    record: format!("actor {id}"),
                    detail: "the two replicas describe one actor id differently".to_string(),
                }),
            }
        }
        for (id, event) in &self.audit_events {
            if !holder.audit_events.contains_key(id) {
                delta.audit_events.push(event.clone());
            }
        }

        CollaborationMerge {
            delta: finish(&mut delta),
            gaps,
        }
    }

    /// A review both sides hold with different contents.
    ///
    /// Its decisions are the causal record: a review's state moves only when a
    /// decision is recorded, so the side whose decisions contain the other's
    /// holds the newer review. `updated_at` decides only where neither side holds
    /// a decision, and that choice is disclosed, because two machines' clocks can
    /// disagree.
    fn settle_review(
        &self,
        holder: &ReviewDomain,
        sides: Sides,
        id: &ReviewId,
        ours: &Review,
        held: &Review,
        delta: &mut CollaborationDelta,
    ) -> Option<CollaborationGap> {
        let our_decisions = self.decisions.get(id).map(Vec::as_slice).unwrap_or(&[]);
        let their_decisions = holder.decisions.get(id).map(Vec::as_slice).unwrap_or(&[]);
        let we_contain = their_decisions.iter().all(|d| our_decisions.contains(d));
        let they_contain = our_decisions.iter().all(|d| their_decisions.contains(d));
        let record = format!("review {id}");
        if our_decisions.is_empty() && their_decisions.is_empty() {
            return match ours.updated_at.0.cmp(&held.updated_at.0) {
                Ordering::Greater => {
                    delta.reviews.push(Keyed::new(*id, ours.clone()));
                    Some(CollaborationGap {
                        record,
                        detail: format!(
                            "neither replica holds a decision for it, so the later updated_at \
                             decided: {} {} over {} {}; clocks on two machines can disagree",
                            sides.sender, ours.updated_at, sides.holder, held.updated_at
                        ),
                    })
                }
                Ordering::Less => None,
                Ordering::Equal => Some(CollaborationGap {
                    record,
                    detail:
                        "the two replicas hold different contents with the same updated_at and \
                             no decision to order them"
                            .to_string(),
                }),
            };
        }
        if we_contain && our_decisions.len() > their_decisions.len() {
            delta.reviews.push(Keyed::new(*id, ours.clone()));
            return None;
        }
        if they_contain && their_decisions.len() > our_decisions.len() {
            return None;
        }
        Some(CollaborationGap {
            record,
            detail: format!(
                "both replicas decided it independently: {} holds it {} after {} decision(s), {} \
                 holds it {} after {}; the decisions merge, and it stays {} on {} until a new \
                 decision settles it",
                sides.sender,
                ours.state,
                our_decisions.len(),
                sides.holder,
                held.state,
                their_decisions.len(),
                held.state,
                sides.holder
            ),
        })
    }

    /// A discussion both sides serve with different copies.
    ///
    /// A copy in a replica's own admission history is older than that
    /// replica's current copy. Failing that, a copy whose comments strictly
    /// extend the other's, in the same state, is the newer one. Anything else is
    /// a named gap.
    fn settle_discussion(
        &self,
        holder: &ReviewDomain,
        sides: Sides,
        id: &ReviewDiscussionId,
        ours: &ReviewDiscussion,
        theirs: &ReviewDiscussion,
        delta: &mut CollaborationDelta,
    ) -> Option<CollaborationGap> {
        let theirs_is_our_past = self
            .discussion_history
            .get(id)
            .is_some_and(|history| history.contains(theirs));
        let ours_is_their_past = holder
            .discussion_history
            .get(id)
            .is_some_and(|history| history.contains(ours));
        if theirs_is_our_past && !ours_is_their_past {
            delta.review_discussions.push(ours.clone());
            return None;
        }
        if ours_is_their_past && !theirs_is_our_past {
            return None;
        }
        if ours.state == theirs.state && extends(&ours.comments, &theirs.comments) {
            delta.review_discussions.push(ours.clone());
            return None;
        }
        if ours.state == theirs.state && extends(&theirs.comments, &ours.comments) {
            return None;
        }
        Some(CollaborationGap {
            record: format!("review discussion {id}"),
            detail: format!(
                "{} serves it {} with {} comment(s), {} serves it {} with {}, and neither copy is \
                 in the other's history",
                sides.sender,
                ours.state,
                ours.comments.len(),
                sides.holder,
                theirs.state,
                theirs.comments.len()
            ),
        })
    }
}

/// How a merge's gaps name its two replicas, which depends on which one sends.
#[derive(Debug, Clone, Copy)]
struct Sides {
    sender: &'static str,
    holder: &'static str,
}

impl Sides {
    fn of(direction: RepositoryTransferDirection) -> Self {
        match direction {
            RepositoryTransferDirection::Push => Self {
                sender: "this replica",
                holder: "the remote",
            },
            RepositoryTransferDirection::Pull => Self {
                sender: "the remote",
                holder: "this replica",
            },
        }
    }
}

/// Why `delta` carries something other than review records, or `None` when it
/// carries only those.
///
/// Review records are all a transfer exchanges, so a pack carrying anything else
/// is refused whole rather than admitted in part.
pub fn outside_review_domain(delta: &CollaborationDelta) -> Option<String> {
    let others = [
        ("work items", delta.work_items.len()),
        ("annotations", delta.annotations.len()),
        ("work links", delta.work_links.len()),
        ("test cases", delta.test_cases.len()),
        ("assertions", delta.assertions.len()),
        ("verification runs", delta.verification_runs.len()),
        ("mock hints", delta.mock_hints.len()),
        ("contracts", delta.contracts.len()),
        ("delegations", delta.delegations.len()),
        ("approvals", delta.approvals.len()),
    ];
    if let Some((name, count)) = others.iter().find(|(_, count)| *count > 0) {
        return Some(format!(
            "it carries {count} {name}, and a transfer exchanges review records only"
        ));
    }
    delta
        .audit_events
        .iter()
        .find(|event| !event.action.starts_with(REVIEW_AUDIT_PREFIX))
        .map(|event| {
            format!(
                "it carries audit event {} for {}, which no review write records",
                event.event_id, event.action
            )
        })
}

/// The records in `incoming` that would overwrite or drop something `held`
/// holds, which a receiver refuses rather than admits.
///
/// This is the merge rule enforced where the records land. A sender that merged
/// against this replica's records sends nothing this names. A pack built
/// without that merge, or against records this replica has since moved past, is
/// refused here record by record instead of overwriting them. Actors and audit
/// events are checked against everything `held` holds, not only the review
/// domain, because an id is one record whichever write recorded it.
pub fn admission_refusals(
    held: &GraphSnapshot,
    incoming: &CollaborationDelta,
) -> Vec<CollaborationGap> {
    let domain = ReviewDomain::from_snapshot(held);
    let mut refusals = Vec::new();
    let arriving_decisions: HashMap<ReviewId, &[ReviewDecision]> = incoming
        .review_decisions
        .iter()
        .map(|entry| (entry.key, entry.value.as_slice()))
        .collect();

    for entry in &incoming.reviews {
        let Some(current) = domain.reviews.get(&entry.key) else {
            continue;
        };
        if current == &entry.value {
            continue;
        }
        let decided = domain
            .decisions
            .get(&entry.key)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let arriving = arriving_decisions
            .get(&entry.key)
            .copied()
            .unwrap_or(decided);
        let supersedes = if decided.is_empty() && arriving.is_empty() {
            entry.value.updated_at.0 > current.updated_at.0
        } else {
            arriving.len() > decided.len() && decided.iter().all(|d| arriving.contains(d))
        };
        if !supersedes {
            refusals.push(CollaborationGap {
                record: format!("review {}", entry.key),
                detail: format!(
                    "this replica holds it {} after {} decision(s) and the pack carries it {} after \
                     {}; the pack's decisions do not extend this replica's, so admitting it would \
                     overwrite a state decided here",
                    current.state,
                    decided.len(),
                    entry.value.state,
                    arriving.len()
                ),
            });
        }
    }
    for entry in &incoming.review_decisions {
        let current = domain
            .decisions
            .get(&entry.key)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if !entry.value.starts_with(current) {
            refusals.push(CollaborationGap {
                record: format!("decision history of review {}", entry.key),
                detail: format!(
                    "this replica holds {} decision(s) the pack's {} do not begin with, so admitting \
                     it would drop or reorder decisions",
                    current.len(),
                    entry.value.len()
                ),
            });
        }
    }
    for entry in &incoming.review_assignments {
        let current = domain
            .assignments
            .get(&entry.key)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if !entry.value.starts_with(current) {
            refusals.push(CollaborationGap {
                record: format!("assignments of review {}", entry.key),
                detail: format!(
                    "this replica holds {} assignment(s) the pack's {} do not begin with, so admitting \
                     it would remove a reviewer",
                    current.len(),
                    entry.value.len()
                ),
            });
        }
    }
    for note in &incoming.review_notes {
        if domain
            .notes
            .get(&note.note_id)
            .is_some_and(|current| current != note)
        {
            refusals.push(CollaborationGap {
                record: format!("review note {}", note.note_id),
                detail: "this replica holds different contents under the same note id".to_string(),
            });
        }
    }
    for discussion in &incoming.review_discussions {
        let id = discussion.discussion_id;
        let Some(current) = domain.discussions.get(&id) else {
            continue;
        };
        if current == discussion {
            continue;
        }
        let is_past = domain
            .discussion_history
            .get(&id)
            .is_some_and(|history| history.contains(discussion));
        let is_behind =
            current.state == discussion.state && extends(&current.comments, &discussion.comments);
        if is_past || is_behind {
            refusals.push(CollaborationGap {
                record: format!("review discussion {id}"),
                detail: format!(
                    "this replica serves a newer copy, {} with {} comment(s), than the pack's {} \
                     with {}",
                    current.state,
                    current.comments.len(),
                    discussion.state,
                    discussion.comments.len()
                ),
            });
        }
    }
    for entry in &incoming.actors {
        if held
            .actors
            .get(&entry.key)
            .is_some_and(|current| current != &entry.value)
        {
            refusals.push(CollaborationGap {
                record: format!("actor {}", entry.key),
                detail: "this replica describes the same actor id differently".to_string(),
            });
        }
    }
    for event in &incoming.audit_events {
        if held
            .audit_events
            .iter()
            .any(|current| current.event_id == event.event_id && current != event)
        {
            refusals.push(CollaborationGap {
                record: format!("audit event {}", event.event_id),
                detail: "this replica holds a different event under the same id".to_string(),
            });
        }
    }
    refusals
}

/// `base` followed by every entry of `extra` it lacks, in `extra`'s order.
fn appended<T: Clone + PartialEq>(base: &[T], extra: &[T]) -> Vec<T> {
    let mut merged = base.to_vec();
    for entry in extra {
        if !merged.contains(entry) {
            merged.push(entry.clone());
        }
    }
    merged
}

/// Whether `longer` is `shorter` with at least one more comment after it.
fn extends(longer: &[ReviewComment], shorter: &[ReviewComment]) -> bool {
    longer.len() > shorter.len() && longer[..shorter.len()] == *shorter
}

fn keyed<K: Copy + Eq + std::hash::Hash, V: Clone>(map: &HashMap<K, V>) -> Vec<Keyed<K, V>> {
    map.iter()
        .map(|(key, value)| Keyed::new(*key, value.clone()))
        .collect()
}

/// Order `delta` the one way kin-model accepts, and answer `None` for an empty
/// one, which kin-model refuses as a delta.
fn finish(delta: &mut CollaborationDelta) -> Option<CollaborationDelta> {
    if delta.is_empty() {
        return None;
    }
    canonical_sort(&mut delta.reviews, |reviews| CollaborationDelta {
        reviews,
        ..CollaborationDelta::default()
    });
    canonical_sort(&mut delta.review_decisions, |review_decisions| {
        CollaborationDelta {
            review_decisions,
            ..CollaborationDelta::default()
        }
    });
    canonical_sort(&mut delta.review_notes, |review_notes| CollaborationDelta {
        review_notes,
        ..CollaborationDelta::default()
    });
    canonical_sort(&mut delta.review_discussions, |review_discussions| {
        CollaborationDelta {
            review_discussions,
            ..CollaborationDelta::default()
        }
    });
    canonical_sort(&mut delta.review_assignments, |review_assignments| {
        CollaborationDelta {
            review_assignments,
            ..CollaborationDelta::default()
        }
    });
    canonical_sort(&mut delta.actors, |actors| CollaborationDelta {
        actors,
        ..CollaborationDelta::default()
    });
    canonical_sort(&mut delta.audit_events, |audit_events| CollaborationDelta {
        audit_events,
        ..CollaborationDelta::default()
    });
    Some(delta.clone())
}

/// Sort into the order kin-model's delta validation accepts by asking it: two
/// entries are in order exactly when a delta holding just those two, in that
/// order, validates. kin-model keeps its canonical encoder private, and this is
/// the same comparator `kin_review::write` uses for a single event.
fn canonical_sort<T: Clone + PartialEq>(
    records: &mut Vec<T>,
    place: impl Fn(Vec<T>) -> CollaborationDelta,
) {
    if records.len() < 2 {
        return;
    }
    let in_order = |first: &T, second: &T| {
        place(vec![first.clone(), second.clone()])
            .validate()
            .is_ok()
    };
    records.sort_by(|first, second| {
        if in_order(first, second) {
            Ordering::Less
        } else if in_order(second, first) {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    });
    records.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::review::{ReviewCompletionState, ReviewDecisionState, ReviewDiscussionState};
    use kin_model::{IdentityRef, Timestamp};

    const PUSH: RepositoryTransferDirection = RepositoryTransferDirection::Push;

    fn at(seconds: u32) -> Timestamp {
        serde_json::from_value(serde_json::Value::String(format!(
            "2023-11-14T22:13:{seconds:02}Z"
        )))
        .unwrap()
    }

    fn review(id: ReviewId, state: ReviewDecisionState, updated: u32) -> Review {
        Review {
            review_id: id,
            title: "Fix login".to_string(),
            base_ref: "main".to_string(),
            head_ref: "feature/login".to_string(),
            state,
            completion: ReviewCompletionState::InReview,
            created_by: IdentityRef::human("troy"),
            created_at: at(0),
            updated_at: at(updated),
            scopes: vec![],
        }
    }

    fn decision(name: &str, state: ReviewDecisionState, seconds: u32) -> ReviewDecision {
        ReviewDecision {
            reviewer: IdentityRef::human(name),
            state,
            comment: None,
            decided_at: at(seconds),
        }
    }

    fn comment(body: &str, seconds: u32) -> ReviewComment {
        ReviewComment {
            authored_by: IdentityRef::human("troy"),
            body: body.to_string(),
            created_at: at(seconds),
        }
    }

    fn domain(reviews: Vec<(Review, Vec<ReviewDecision>)>) -> ReviewDomain {
        let mut domain = ReviewDomain::default();
        for (review, decisions) in reviews {
            if !decisions.is_empty() {
                domain.decisions.insert(review.review_id, decisions);
            }
            domain.reviews.insert(review.review_id, review);
        }
        domain
    }

    /// A holder missing exactly one record receives exactly that record, and a
    /// holder that already has everything receives nothing.
    #[test]
    fn a_holder_missing_one_record_gets_exactly_that_record() {
        let shared = review(ReviewId::new(), ReviewDecisionState::Pending, 1);
        let missing = review(ReviewId::new(), ReviewDecisionState::Pending, 2);
        let ours = domain(vec![(shared.clone(), vec![]), (missing.clone(), vec![])]);
        let holder = domain(vec![(shared, vec![])]);

        let merge = ours.merge_into(&holder, PUSH);
        let delta = merge.delta.expect("the missing review must travel");
        assert_eq!(delta.record_count(), 1, "exactly one record: {delta:?}");
        assert_eq!(delta.reviews[0].key, missing.review_id);
        assert!(merge.gaps.is_empty(), "{:?}", merge.gaps);

        assert_eq!(
            ours.merge_into(&ours.clone(), PUSH),
            CollaborationMerge::default()
        );
    }

    /// The review whose decisions contain the other's is the newer one; a review
    /// both sides decided independently is a named gap and its decisions merge.
    ///
    /// Falsify by deciding on `updated_at` instead: the stale holder copy below
    /// carries the later timestamp and would win.
    #[test]
    fn decision_history_decides_a_review_and_divergence_is_named() {
        let id = ReviewId::new();
        let first = decision("alice", ReviewDecisionState::NeedsWork, 5);
        let second = decision("bob", ReviewDecisionState::Approved, 9);
        let ours = domain(vec![(
            review(id, ReviewDecisionState::Approved, 9),
            vec![first.clone(), second.clone()],
        )]);
        // A skewed clock: the holder's copy is older by history but newer by time.
        let behind = domain(vec![(
            review(id, ReviewDecisionState::NeedsWork, 50),
            vec![first.clone()],
        )]);
        let merge = ours.merge_into(&behind, PUSH);
        let delta = merge.delta.expect("the newer review must travel");
        assert_eq!(delta.reviews[0].value.state, ReviewDecisionState::Approved);
        assert_eq!(
            delta.review_decisions[0].value,
            vec![first.clone(), second.clone()]
        );
        assert!(merge.gaps.is_empty(), "{:?}", merge.gaps);

        let diverged = domain(vec![(
            review(id, ReviewDecisionState::Blocked, 7),
            vec![
                first.clone(),
                decision("carol", ReviewDecisionState::Blocked, 7),
            ],
        )]);
        let merge = ours.merge_into(&diverged, PUSH);
        let delta = merge.delta.expect("the decisions still merge");
        assert!(
            delta.reviews.is_empty(),
            "a divergent review must not be sent"
        );
        assert_eq!(delta.review_decisions[0].value.len(), 3);
        assert_eq!(merge.gaps.len(), 1);
        assert!(merge.gaps[0].detail.contains("decided it independently"));
    }

    /// A discussion copy in our own history is superseded by our current copy;
    /// copies neither side can order are a named gap.
    #[test]
    fn discussion_history_decides_a_copy_and_the_rest_is_named() {
        let review_id = ReviewId::new();
        let discussion_id = ReviewDiscussionId::new();
        let open = ReviewDiscussion {
            discussion_id,
            review_id,
            scope: None,
            state: ReviewDiscussionState::Open,
            comments: vec![comment("why?", 1)],
            created_at: at(1),
        };
        let mut resolved = open.clone();
        resolved.state = ReviewDiscussionState::Resolved;

        let mut ours = ReviewDomain::default();
        ours.discussion_history
            .insert(discussion_id, vec![open.clone(), resolved.clone()]);
        ours.discussions.insert(discussion_id, resolved.clone());
        let mut holder = ReviewDomain::default();
        holder.discussions.insert(discussion_id, open.clone());

        let merge = ours.merge_into(&holder, PUSH);
        assert_eq!(
            merge.delta.unwrap().review_discussions,
            vec![resolved.clone()]
        );
        assert!(merge.gaps.is_empty());

        // With no history on either side, a copy that extends the other's
        // comments in the same state is the newer one: the holder is ahead, so
        // nothing travels and nothing is named.
        let mut extended = resolved.clone();
        extended.comments.push(comment("a reply made elsewhere", 3));
        let mut ahead = ReviewDomain::default();
        ahead.discussions.insert(discussion_id, extended.clone());
        let mut behind = ReviewDomain::default();
        behind.discussions.insert(discussion_id, resolved);
        assert_eq!(
            behind.merge_into(&ahead, PUSH),
            CollaborationMerge::default()
        );

        // Each side holds a reply the other lacks: neither copy can be preferred.
        let mut ours_diverged = open.clone();
        ours_diverged.comments.push(comment("a reply made here", 3));
        let mut theirs_diverged = open;
        theirs_diverged
            .comments
            .push(comment("a reply made elsewhere", 3));
        let mut mine = ReviewDomain::default();
        mine.discussions.insert(discussion_id, ours_diverged);
        let mut stranger = ReviewDomain::default();
        stranger.discussions.insert(discussion_id, theirs_diverged);
        let merge = mine.merge_into(&stranger, PUSH);
        assert!(merge.delta.is_none(), "a divergent copy must not travel");
        assert_eq!(merge.gaps.len(), 1, "{:?}", merge.gaps);
        assert!(merge.gaps[0].detail.contains("neither copy"));
    }

    /// An assignment only the holder has is disclosed, not silently kept or
    /// dropped.
    #[test]
    fn a_holder_only_assignment_is_disclosed() {
        let id = ReviewId::new();
        let assignment = |name: &str| ReviewAssignment {
            review_id: id,
            reviewer: IdentityRef::human(name),
            assigned_at: at(1),
            assigned_by: IdentityRef::human("troy"),
        };
        let mut ours = ReviewDomain::default();
        ours.assignments.insert(id, vec![assignment("alice")]);
        let mut holder = ReviewDomain::default();
        holder
            .assignments
            .insert(id, vec![assignment("alice"), assignment("bob")]);

        let merge = ours.merge_into(&holder, PUSH);
        assert!(merge.delta.is_none());
        assert_eq!(merge.gaps.len(), 1);
        assert!(merge.gaps[0].detail.contains("bob"));
    }

    /// The exported delta is one kin-model accepts, whatever order the maps
    /// yielded.
    #[test]
    fn an_export_is_a_valid_delta() {
        let ours = domain(
            (0..12)
                .map(|n| {
                    (
                        review(ReviewId::new(), ReviewDecisionState::Pending, n),
                        vec![],
                    )
                })
                .collect(),
        );
        let delta = ours.to_delta().expect("twelve reviews export");
        delta.validate().expect("an export must validate");
        assert_eq!(delta.reviews.len(), 12);
        assert!(ReviewDomain::default().to_delta().is_none());
    }
}
