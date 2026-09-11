// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Who a review's reviewers are, derived from its assignment records and the
//! removals recorded against them.
//!
//! A collaboration delta upserts a review's whole assignment set and refuses an
//! empty one, so a removal cannot be written as the set that is left. Removing a
//! review's last reviewer would have no durable form at all, and a set compared
//! by state cannot tell a removal from an addition, which is how a reviewer
//! removed on one replica came back from a replica that still held the
//! assignment.
//!
//! So a removal is recorded as history. A `review.unassign` audit event names
//! each assignment it removes, by reviewer and the instant that assignment was
//! made, and a review's reviewers are its stored assignments minus every pair a
//! removal names. The events are the truth and the set is a view, so every
//! surface that shows or plans reviewers reads them through this module rather
//! than reading the stored set.

use std::collections::HashSet;

use kin_model::graph::{GraphStore, ProvenanceStore, ReviewStore};
use kin_model::provenance::AuditEvent;
use kin_model::review::{ReviewAssignment, ReviewId};
use kin_model::Timestamp;
use serde::{Deserialize, Serialize};

/// The audit action that assigning a reviewer records.
pub const ASSIGN_ACTION: &str = "review.assign";
/// The audit action that removing a reviewer records, and the only durable
/// record that the removal happened.
pub const UNASSIGN_ACTION: &str = "review.unassign";

/// The key an assign or unassign event carries its pairs under, inside the
/// `key=value; key=value` details every review event already writes.
const ASSIGNMENTS_KEY: &str = "assignments=";

/// One assignment, as an event names it.
///
/// `assigned_at` is what separates one assignment of a reviewer from a later
/// one, so a removal names the assignment it actually saw and never a
/// re-assignment made after it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssignmentTag {
    pub reviewer: String,
    pub assigned_at: Timestamp,
}

impl AssignmentTag {
    pub fn of(assignment: &ReviewAssignment) -> Self {
        Self {
            reviewer: assignment.reviewer.name.clone(),
            assigned_at: assignment.assigned_at.clone(),
        }
    }
}

/// The `assignments=` fragment an event's details carry `tags` in.
///
/// JSON rather than the `key=value` spelling around it, because a reviewer name
/// is free text: JSON escapes what a hand-rolled separator would not. The reader
/// takes the one JSON value that follows the key, so the provenance the daemon's
/// writer appends after it is untouched.
pub fn tag_details(tags: &[AssignmentTag]) -> String {
    let encoded = serde_json::to_string(tags).unwrap_or_else(|_| "[]".to_string());
    format!("{ASSIGNMENTS_KEY}{encoded}")
}

/// The pairs `details` names, and none when it names none.
pub fn tags_in_details(details: &str) -> Vec<AssignmentTag> {
    let Some(start) = details.find(ASSIGNMENTS_KEY) else {
        return Vec::new();
    };
    let rest = &details[start + ASSIGNMENTS_KEY.len()..];
    serde_json::Deserializer::from_str(rest)
        .into_iter::<Vec<AssignmentTag>>()
        .next()
        .and_then(Result::ok)
        .unwrap_or_default()
}

/// Every assignment a removal in `events` names.
pub fn removed_tags<'a>(
    events: impl IntoIterator<Item = &'a AuditEvent>,
) -> HashSet<AssignmentTag> {
    events
        .into_iter()
        .filter(|event| event.action == UNASSIGN_ACTION)
        .flat_map(|event| tags_in_details(event.details.as_deref().unwrap_or_default()))
        .collect()
}

/// Every assignment a removal recorded in `store` names.
///
/// The whole audit log, because a removal is proven by an event of any age and
/// the store's query filters on actor rather than on action. `usize::MAX` is
/// how that query spells "all of it".
pub fn removed_tags_in<S: GraphStore + ?Sized>(
    store: &S,
) -> Result<HashSet<AssignmentTag>, <S as GraphStore>::Error> {
    let events = ProvenanceStore::query_audit_events(store, None, usize::MAX)?;
    Ok(removed_tags(events.iter()))
}

/// The reviewers `review_id` has: its stored assignments, minus every pair a
/// removal names.
pub fn current_assignments<S: GraphStore + ?Sized>(
    store: &S,
    review_id: &ReviewId,
) -> Result<Vec<ReviewAssignment>, <S as GraphStore>::Error> {
    let removed = removed_tags_in(store)?;
    let mut assignments = ReviewStore::get_review_assignments(store, review_id)?;
    retain_current(&mut assignments, &removed);
    Ok(assignments)
}

/// Drop from `assignments` every pair `removed` names.
pub fn retain_current(assignments: &mut Vec<ReviewAssignment>, removed: &HashSet<AssignmentTag>) {
    assignments.retain(|assignment| !removed.contains(&AssignmentTag::of(assignment)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::provenance::{ActorId, AuditEventId};
    use kin_model::review::ReviewId;
    use kin_model::IdentityRef;

    fn assignment(reviewer: &str, at: Timestamp) -> ReviewAssignment {
        ReviewAssignment {
            review_id: ReviewId::new(),
            reviewer: IdentityRef::human(reviewer),
            assigned_at: at,
            assigned_by: IdentityRef::human("troy"),
        }
    }

    fn event(action: &str, details: String) -> AuditEvent {
        AuditEvent {
            event_id: AuditEventId::new(),
            actor_id: ActorId::new(),
            action: action.to_string(),
            target_scope: None,
            timestamp: Timestamp::now(),
            details: Some(details),
        }
    }

    /// A removal names the assignment it saw, and the reader finds it whatever
    /// the writer appended afterwards.
    ///
    /// Falsify by writing the pairs as bare text instead of JSON: the reviewer
    /// holding a semicolon below comes back parsed as two names and the
    /// round-trip assertion goes red.
    #[test]
    fn a_removal_names_the_assignment_it_removed() {
        let at = Timestamp::now();
        let awkward = assignment("ana; assigned_at=1970", at.clone());
        let details = format!(
            "review_id={}; reviewer={}; {}; authority_generation=7; session=abc",
            awkward.review_id,
            awkward.reviewer.name,
            tag_details(&[AssignmentTag::of(&awkward)])
        );

        assert_eq!(tags_in_details(&details), vec![AssignmentTag::of(&awkward)]);
        assert!(tags_in_details("review_id=1; reviewer=bob").is_empty());
    }

    /// The reviewers a review has are its assignments minus what removals name,
    /// and a re-assignment after a removal is a different pair, so it stays.
    ///
    /// Falsify by matching a removal on the reviewer's name alone: the
    /// re-assigned bob disappears and the last assertion goes red.
    #[test]
    fn a_removal_hides_the_assignment_it_names_and_no_later_one() {
        let first = Timestamp::now();
        let later = Timestamp::now();
        let removed = assignment("bob", first);
        let again = assignment("bob", later);
        let kept = assignment("alice", Timestamp::now());
        let removal = event(UNASSIGN_ACTION, tag_details(&[AssignmentTag::of(&removed)]));
        let noise = event(ASSIGN_ACTION, tag_details(&[AssignmentTag::of(&again)]));

        let removals = removed_tags([&removal, &noise]);
        assert_eq!(removals.len(), 1, "only an unassign removes: {removals:?}");

        let mut live = vec![removed.clone(), kept.clone(), again.clone()];
        retain_current(&mut live, &removals);
        assert_eq!(live, vec![kept, again]);
    }
}
