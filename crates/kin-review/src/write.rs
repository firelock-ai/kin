// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! One review event as the exact records it writes into repository authority.
//!
//! A review mutation is planned against the live graph, committed to repository
//! authority as one collaboration-only transaction, and only then applied to the
//! live graph. [`ReviewWrite`] is what passes between those steps: the records the
//! event leaves behind, each one whole, so one value builds the transaction's
//! [`CollaborationDelta`] and levels the live graph to exactly what authority
//! holds after the commit.
//!
//! Whole records rather than operations, because that is what the delta carries.
//! kin-model's collaboration delta upserts a review, its decision history and its
//! assignment set by key, and admits notes and discussions by value, so a decision
//! is written as the review's whole history after the append and a reply as the
//! discussion's whole new copy. The live graph offers only appends and removals
//! by name for the two grouped collections, which is why [`ReviewWrite::apply_to`]
//! levels a group by appending what it lacks and reports a live group it cannot
//! reach that way instead of guessing.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use kin_model::provenance::{Actor, AuditEvent};
use kin_model::review::{
    Review, ReviewAssignment, ReviewDecision, ReviewDiscussion, ReviewId, ReviewNote,
};
use kin_model::{CollaborationDelta, GraphStore, Keyed};

/// A review's decision history or assignment set as it stands after one event.
#[derive(Debug, Clone, PartialEq)]
pub struct ReviewGroup<T> {
    pub review_id: ReviewId,
    pub entries: Vec<T>,
}

/// Every record one review event writes, as authority holds it afterwards.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReviewWrite {
    /// The review after the event: newly created, or with its state moved by a
    /// decision.
    pub review: Option<Review>,
    /// The review's whole decision history after the event.
    pub decisions: Option<ReviewGroup<ReviewDecision>>,
    pub notes: Vec<ReviewNote>,
    /// Each discussion the event touched, as its whole new copy.
    pub discussions: Vec<ReviewDiscussion>,
    /// The review's whole assignment set after the event.
    pub assignments: Option<ReviewGroup<ReviewAssignment>>,
    /// Actors an audit event below names that the store does not hold yet.
    pub actors: Vec<Actor>,
    pub audit_events: Vec<AuditEvent>,
}

#[derive(Debug, thiserror::Error)]
pub enum ReviewWriteError {
    /// kin-model refused the collaboration delta this write builds.
    #[error("review write is not a valid collaboration delta: {0}")]
    Invalid(String),
    /// The store refused one of the records.
    #[error("review store refused the write: {0}")]
    Store(String),
    /// The live group holds entries the written group does not start with, so
    /// appending cannot make the two equal.
    #[error(
        "the live {collection} of review {review_id} is not a prefix of the one this write \
         holds, so the live graph cannot be leveled to it by appending"
    )]
    Diverged {
        collection: &'static str,
        review_id: ReviewId,
    },
}

/// A review, discussion or other target an event names that the store does not
/// hold.
///
/// Its own type so a caller can answer it as a missing resource rather than as a
/// failure of the store.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ReviewTargetMissing(pub String);

/// One review event planned against the live graph and not yet written anywhere.
///
/// The planner states what it can from the request and the graph alone. The
/// writer that commits it adds what only it holds, such as the session and the
/// changes the review's refs resolve to at commit time, to the audit event it
/// records for the actions that carry one.
#[derive(Debug, Clone)]
pub struct PlannedReviewEvent<A> {
    pub write: ReviewWrite,
    /// The audit action this event is, such as `review.create`.
    pub action: &'static str,
    pub review_id: ReviewId,
    /// Audit details the planner can state from the request alone.
    pub details: String,
    /// The identity this event acts as, by label.
    pub actor_label: String,
    /// The base and head refs a created review names.
    pub refs: Option<(String, String)>,
    /// What the caller answers once the write is durable.
    pub answer: A,
}

impl<A> PlannedReviewEvent<A> {
    /// Whether the writer records an audit event for this action. Creating a
    /// review and deciding one do; notes and comments carry their own author and
    /// time.
    pub fn records_audit_event(&self) -> bool {
        matches!(self.action, "review.create" | "review.decide")
    }
}

impl ReviewWrite {
    /// Whether this write records nothing, which is what an event that changes
    /// nothing plans, such as resolving a discussion that is already resolved.
    pub fn is_empty(&self) -> bool {
        self.review.is_none()
            && self.decisions.is_none()
            && self.notes.is_empty()
            && self.discussions.is_empty()
            && self.assignments.is_none()
            && self.actors.is_empty()
            && self.audit_events.is_empty()
    }

    /// The collaboration delta that admits these records into repository
    /// authority, in the one order kin-model accepts.
    pub fn to_delta(&self) -> Result<CollaborationDelta, ReviewWriteError> {
        let mut delta = CollaborationDelta {
            reviews: self
                .review
                .iter()
                .map(|review| Keyed::new(review.review_id, review.clone()))
                .collect(),
            review_decisions: self
                .decisions
                .iter()
                .map(|group| Keyed::new(group.review_id, group.entries.clone()))
                .collect(),
            review_notes: self.notes.clone(),
            review_discussions: self.discussions.clone(),
            review_assignments: self
                .assignments
                .iter()
                .map(|group| Keyed::new(group.review_id, group.entries.clone()))
                .collect(),
            actors: self
                .actors
                .iter()
                .map(|actor| Keyed::new(actor.actor_id, actor.clone()))
                .collect(),
            audit_events: self.audit_events.clone(),
            ..CollaborationDelta::default()
        };
        canonicalize(&mut delta);
        delta
            .validate()
            .map_err(|error| ReviewWriteError::Invalid(error.to_string()))?;
        Ok(delta)
    }

    /// Level `store` to hold exactly these records.
    ///
    /// Keyed records and whole copies replace what the store holds under the same
    /// id; a group gains the entries the store lacks. Actors are created only when
    /// absent, and audit events are appended.
    pub fn apply_to<G: GraphStore>(&self, store: &G) -> Result<(), ReviewWriteError> {
        fn refused(error: impl std::fmt::Display) -> ReviewWriteError {
            ReviewWriteError::Store(error.to_string())
        }

        for actor in &self.actors {
            if store.get_actor(&actor.actor_id).map_err(refused)?.is_none() {
                store.create_actor(actor).map_err(refused)?;
            }
        }
        if let Some(review) = &self.review {
            store.create_review(review).map_err(refused)?;
        }
        if let Some(group) = &self.decisions {
            let live = store
                .get_review_decisions(&group.review_id)
                .map_err(refused)?;
            for decision in missing_suffix(&live, group, "decision history")? {
                store
                    .add_review_decision(&group.review_id, decision)
                    .map_err(refused)?;
            }
        }
        for note in &self.notes {
            store.add_review_note(note).map_err(refused)?;
        }
        for discussion in &self.discussions {
            store
                .create_review_discussion(discussion)
                .map_err(refused)?;
        }
        if let Some(group) = &self.assignments {
            let mut live = store
                .get_review_assignments(&group.review_id)
                .map_err(refused)?;
            // A removal leaves reviewers live that the group no longer names, and
            // the store removes by reviewer name.
            let kept: BTreeSet<&str> = group
                .entries
                .iter()
                .map(|assignment| assignment.reviewer.name.as_str())
                .collect();
            let removed: BTreeSet<String> = live
                .iter()
                .filter(|assignment| !kept.contains(assignment.reviewer.name.as_str()))
                .map(|assignment| assignment.reviewer.name.clone())
                .collect();
            if !removed.is_empty() {
                for name in &removed {
                    store
                        .remove_reviewer(&group.review_id, name)
                        .map_err(refused)?;
                }
                live = store
                    .get_review_assignments(&group.review_id)
                    .map_err(refused)?;
            }
            for assignment in missing_suffix(&live, group, "assignment set")? {
                store.assign_reviewer(assignment).map_err(refused)?;
            }
        }
        for event in &self.audit_events {
            store.record_audit_event(event).map_err(refused)?;
        }
        Ok(())
    }
}

/// The entries of `written` after the prefix `live` already holds.
fn missing_suffix<'a, T: PartialEq>(
    live: &[T],
    written: &'a ReviewGroup<T>,
    collection: &'static str,
) -> Result<&'a [T], ReviewWriteError> {
    let entries = &written.entries;
    if entries.len() >= live.len() && entries[..live.len()] == *live {
        Ok(&entries[live.len()..])
    } else {
        Err(ReviewWriteError::Diverged {
            collection,
            review_id: written.review_id,
        })
    }
}

/// Put every collection the review domain writes into kin-model's canonical
/// order.
fn canonicalize(delta: &mut CollaborationDelta) {
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
}

/// Sort `records` into the one order kin-model's delta validation accepts, and
/// drop exact duplicates.
///
/// kin-model refuses a collection that is not strictly increasing by the
/// canonical encoding of each entry's key, or of the entry itself when the
/// collection is unkeyed, and keeps that encoder private. So the comparator asks
/// kin-model directly: two entries are in order exactly when a delta holding just
/// those two, in that order, validates. Anything this sorts is therefore in the
/// order the same crate will check, with no second copy of the encoding here to
/// drift from it.
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
    use kin_model::review::{
        ReviewCompletionState, ReviewDecisionState, ReviewDiscussionId, ReviewDiscussionState,
        ReviewNoteId,
    };
    use kin_model::{IdentityRef, ReviewStore, Timestamp};

    /// A fixed instant, so records built twice compare equal.
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

    fn decision(state: ReviewDecisionState, seconds: u32) -> ReviewDecision {
        ReviewDecision {
            reviewer: IdentityRef::human("reviewer"),
            state,
            comment: None,
            decided_at: at(seconds),
        }
    }

    fn assignment(id: ReviewId, name: &str) -> ReviewAssignment {
        ReviewAssignment {
            review_id: id,
            reviewer: IdentityRef::human(name),
            assigned_at: at(1),
            assigned_by: IdentityRef::human("troy"),
        }
    }

    fn note(id: ReviewId, body: &str) -> ReviewNote {
        ReviewNote {
            note_id: ReviewNoteId::new(),
            review_id: id,
            body: body.to_string(),
            scope: None,
            authored_by: IdentityRef::human("troy"),
            created_at: at(2),
        }
    }

    /// A decision is the review's whole history after the append plus the review
    /// with its state moved, and applying it to a store holding the history before
    /// the append leaves the store equal to both.
    #[test]
    fn a_decision_writes_the_whole_history_and_moves_the_review() {
        let id = ReviewId::new();
        let store = kin_db::InMemoryGraph::new();
        store
            .create_review(&review(id, ReviewDecisionState::Pending, 0))
            .unwrap();
        let first = decision(ReviewDecisionState::NeedsWork, 5);
        store.add_review_decision(&id, &first).unwrap();

        let second = decision(ReviewDecisionState::Approved, 9);
        let write = ReviewWrite {
            review: Some(review(id, ReviewDecisionState::Approved, 9)),
            decisions: Some(ReviewGroup {
                review_id: id,
                entries: vec![first.clone(), second.clone()],
            }),
            ..ReviewWrite::default()
        };

        let delta = write.to_delta().unwrap();
        assert_eq!(delta.reviews.len(), 1);
        assert_eq!(delta.review_decisions.len(), 1);
        assert_eq!(
            delta.review_decisions[0].value,
            vec![first.clone(), second.clone()]
        );

        write.apply_to(&store).unwrap();
        assert_eq!(
            store.get_review_decisions(&id).unwrap(),
            vec![first, second]
        );
        assert_eq!(
            store.get_review(&id).unwrap().unwrap().state,
            ReviewDecisionState::Approved
        );
    }

    /// Records assembled in any order build the one delta kin-model accepts.
    ///
    /// Falsify by returning early from `canonical_sort`: the reversed input then
    /// fails validation, because kin-model refuses a collection out of its
    /// canonical order rather than sorting it.
    #[test]
    fn records_in_any_order_build_one_valid_delta() {
        let id = ReviewId::new();
        let notes = vec![note(id, "a"), note(id, "b"), note(id, "c"), note(id, "d")];
        let forward = ReviewWrite {
            notes: notes.clone(),
            ..ReviewWrite::default()
        };
        let mut reversed_notes = notes;
        reversed_notes.reverse();
        let reversed = ReviewWrite {
            notes: reversed_notes,
            ..ReviewWrite::default()
        };

        let first = forward.to_delta().expect("forward order must validate");
        let second = reversed.to_delta().expect("reversed order must validate");
        assert_eq!(first, second, "assembly order must not change the delta");
    }

    /// A live group the write does not extend is reported, not overwritten.
    #[test]
    fn a_live_history_the_write_does_not_extend_is_reported() {
        let id = ReviewId::new();
        let store = kin_db::InMemoryGraph::new();
        store
            .create_review(&review(id, ReviewDecisionState::Pending, 0))
            .unwrap();
        store
            .add_review_decision(&id, &decision(ReviewDecisionState::Blocked, 3))
            .unwrap();

        let write = ReviewWrite {
            decisions: Some(ReviewGroup {
                review_id: id,
                entries: vec![decision(ReviewDecisionState::Approved, 4)],
            }),
            ..ReviewWrite::default()
        };
        let error = write.apply_to(&store).unwrap_err();
        assert!(
            matches!(
                error,
                ReviewWriteError::Diverged {
                    collection: "decision history",
                    ..
                }
            ),
            "{error}"
        );
    }

    /// An assignment set that lost a reviewer levels the store by removing that
    /// reviewer, and one that gained a reviewer by appending.
    #[test]
    fn an_assignment_set_levels_removals_and_additions() {
        let id = ReviewId::new();
        let store = kin_db::InMemoryGraph::new();
        store
            .create_review(&review(id, ReviewDecisionState::Pending, 0))
            .unwrap();
        store.assign_reviewer(&assignment(id, "alice")).unwrap();
        store.assign_reviewer(&assignment(id, "bob")).unwrap();

        ReviewWrite {
            assignments: Some(ReviewGroup {
                review_id: id,
                entries: vec![assignment(id, "alice")],
            }),
            ..ReviewWrite::default()
        }
        .apply_to(&store)
        .unwrap();
        assert_eq!(
            store.get_review_assignments(&id).unwrap(),
            vec![assignment(id, "alice")]
        );

        ReviewWrite {
            assignments: Some(ReviewGroup {
                review_id: id,
                entries: vec![assignment(id, "alice"), assignment(id, "carol")],
            }),
            ..ReviewWrite::default()
        }
        .apply_to(&store)
        .unwrap();
        assert_eq!(
            store.get_review_assignments(&id).unwrap(),
            vec![assignment(id, "alice"), assignment(id, "carol")]
        );
    }

    /// A reply is the discussion's whole new copy, and applying it replaces the
    /// copy the store held.
    #[test]
    fn a_reply_replaces_the_discussion_copy() {
        let id = ReviewId::new();
        let store = kin_db::InMemoryGraph::new();
        store
            .create_review(&review(id, ReviewDecisionState::Pending, 0))
            .unwrap();
        let mut discussion = ReviewDiscussion {
            discussion_id: ReviewDiscussionId::new(),
            review_id: id,
            scope: None,
            state: ReviewDiscussionState::Open,
            comments: vec![],
            created_at: at(1),
        };
        store.create_review_discussion(&discussion).unwrap();

        discussion.comments.push(kin_model::review::ReviewComment {
            authored_by: IdentityRef::human("reviewer"),
            body: "why this shape?".to_string(),
            created_at: at(2),
        });
        discussion.state = ReviewDiscussionState::Resolved;
        let write = ReviewWrite {
            discussions: vec![discussion.clone()],
            ..ReviewWrite::default()
        };
        write.to_delta().unwrap();
        write.apply_to(&store).unwrap();
        assert_eq!(store.get_review_discussions(&id).unwrap(), vec![discussion]);
    }

    /// An empty write is refused as a delta, which is why a planner that changes
    /// nothing must not reach a commit.
    #[test]
    fn an_empty_write_is_not_a_delta() {
        let write = ReviewWrite::default();
        assert!(write.is_empty());
        assert!(matches!(
            write.to_delta().unwrap_err(),
            ReviewWriteError::Invalid(_)
        ));
    }
}
