// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Stored review records, read once for every surface that shows them.
//!
//! Three surfaces read a stored review: `kin review list` and `kin review show`
//! on the CLI, the `kin_review_list` and `kin_review_get` MCP tools, and the
//! daemon's repo-scoped review routes. They read the same records, so they read
//! them here: one set of store calls, one ordering, and one JSON shape for the
//! surfaces that answer in JSON. A review is graph authority like any other
//! record, so nothing here reads a file.

use kin_model::graph::{GraphStore, ReviewStore};
use kin_model::review::{
    Review, ReviewAssignment, ReviewDecision, ReviewDecisionState, ReviewDiscussion, ReviewFilter,
    ReviewId, ReviewNote,
};
use serde::{Deserialize, Serialize};

/// One stored review and everything recorded against it.
#[derive(Debug, Clone, PartialEq)]
pub struct ReviewRecord {
    pub review: Review,
    pub decisions: Vec<ReviewDecision>,
    pub notes: Vec<ReviewNote>,
    pub discussions: Vec<ReviewDiscussion>,
    pub assignments: Vec<ReviewAssignment>,
}

/// Parse a decision-state filter in any spelling a review read accepts.
///
/// `None` for anything else, so each surface refuses in its own words: the
/// caller knows whether it was a flag, a tool argument or a query parameter.
pub fn parse_review_decision_state(value: &str) -> Option<ReviewDecisionState> {
    match value.to_lowercase().as_str() {
        "pending" => Some(ReviewDecisionState::Pending),
        "approved" | "approve" => Some(ReviewDecisionState::Approved),
        "needs_work" | "needs-work" | "needswork" => Some(ReviewDecisionState::NeedsWork),
        "blocked" | "block" => Some(ReviewDecisionState::Blocked),
        _ => None,
    }
}

/// Every review the store holds, narrowed to one decision state when asked,
/// newest first.
///
/// The store answers in its own map order, which is not stable from one
/// process to the next. A listing that reorders itself between two reads looks
/// like a listing that changed, so the order is fixed here: creation time,
/// newest first, then the review id to separate two created in one instant.
pub fn list_stored_reviews<S: ReviewStore + ?Sized>(
    store: &S,
    state: Option<ReviewDecisionState>,
) -> Result<Vec<Review>, S::Error> {
    let filter = ReviewFilter {
        states: state.map(|state| vec![state]),
        reviewer: None,
    };
    let mut reviews = store.list_reviews(&filter)?;
    reviews.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| left.review_id.0.cmp(&right.review_id.0))
    });
    Ok(reviews)
}

/// One review and its history, or `None` when the store holds no review under
/// that id.
/// The reviewers come from [`crate::assignments::current_assignments`] rather
/// than from the stored set, because a removal is recorded as an event and the
/// set it leaves behind cannot express one. Every surface that shows a review
/// reads it here, so they all show the same reviewers.
pub fn read_review_record<S: GraphStore + ?Sized>(
    store: &S,
    review_id: &ReviewId,
) -> Result<Option<ReviewRecord>, <S as GraphStore>::Error> {
    let Some(review) = ReviewStore::get_review(store, review_id)? else {
        return Ok(None);
    };
    Ok(Some(ReviewRecord {
        decisions: ReviewStore::get_review_decisions(store, review_id)?,
        notes: ReviewStore::get_review_notes(store, review_id)?,
        discussions: ReviewStore::get_review_discussions(store, review_id)?,
        assignments: crate::assignments::current_assignments(store, review_id)?,
        review,
    }))
}

/// A decision state as the JSON review reads spell it.
///
/// This is the lowercased variant name, so `NeedsWork` reads `needswork`,
/// which is what `kin_review_list` has always answered. It is not the model's
/// `Display` spelling (`needs-work`), and moving to that here would change a
/// published tool answer under every caller that already parses it.
pub fn review_state_label(state: ReviewDecisionState) -> String {
    format!("{state:?}").to_lowercase()
}

/// One row of a review listing.
///
/// Field order is the key order `kin_review_list` has always printed wherever
/// serde_json keeps key order, and a test pins it, so a reordering here is a
/// visible change to a published tool answer rather than a silent one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewSummaryView {
    pub review_id: String,
    pub title: String,
    pub state: String,
    pub base_ref: String,
    pub head_ref: String,
}

impl From<&Review> for ReviewSummaryView {
    fn from(review: &Review) -> Self {
        Self {
            review_id: review.review_id.to_string(),
            title: review.title.clone(),
            state: review_state_label(review.state),
            base_ref: review.base_ref.clone(),
            head_ref: review.head_ref.clone(),
        }
    }
}

/// One decision in a review's history.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewDecisionView {
    pub state: String,
    pub comment: Option<String>,
    pub reviewer: String,
}

/// One note on a review.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewNoteView {
    pub note_id: String,
    pub body: String,
    pub scope: Option<String>,
    pub author: String,
}

/// One comment in a discussion thread.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewCommentView {
    pub body: String,
    pub author: String,
}

/// One discussion thread on a review.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewDiscussionView {
    pub discussion_id: String,
    pub state: String,
    pub scope: Option<String>,
    pub comments: Vec<ReviewCommentView>,
}

/// One reviewer assignment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewAssignmentView {
    pub reviewer: String,
}

/// One review in full, as the JSON review reads answer it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewRecordView {
    pub review_id: String,
    pub title: String,
    pub state: String,
    pub base_ref: String,
    pub head_ref: String,
    pub scopes: Vec<String>,
    pub decisions: Vec<ReviewDecisionView>,
    pub notes: Vec<ReviewNoteView>,
    pub discussions: Vec<ReviewDiscussionView>,
    pub assignments: Vec<ReviewAssignmentView>,
}

impl From<&ReviewRecord> for ReviewRecordView {
    fn from(record: &ReviewRecord) -> Self {
        let review = &record.review;
        Self {
            review_id: review.review_id.to_string(),
            title: review.title.clone(),
            state: review_state_label(review.state),
            base_ref: review.base_ref.clone(),
            head_ref: review.head_ref.clone(),
            scopes: review.scopes.iter().map(ToString::to_string).collect(),
            decisions: record
                .decisions
                .iter()
                .map(|decision| ReviewDecisionView {
                    state: review_state_label(decision.state),
                    comment: decision.comment.clone(),
                    reviewer: decision.reviewer.name.clone(),
                })
                .collect(),
            notes: record
                .notes
                .iter()
                .map(|note| ReviewNoteView {
                    note_id: note.note_id.to_string(),
                    body: note.body.clone(),
                    scope: note.scope.as_ref().map(ToString::to_string),
                    author: note.authored_by.name.clone(),
                })
                .collect(),
            discussions: record
                .discussions
                .iter()
                .map(|discussion| ReviewDiscussionView {
                    discussion_id: discussion.discussion_id.to_string(),
                    state: format!("{:?}", discussion.state).to_lowercase(),
                    scope: discussion.scope.as_ref().map(ToString::to_string),
                    comments: discussion
                        .comments
                        .iter()
                        .map(|comment| ReviewCommentView {
                            body: comment.body.clone(),
                            author: comment.authored_by.name.clone(),
                        })
                        .collect(),
                })
                .collect(),
            assignments: record
                .assignments
                .iter()
                .map(|assignment| ReviewAssignmentView {
                    reviewer: assignment.reviewer.name.clone(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_model::review::{
        ReviewComment, ReviewCompletionState, ReviewDiscussionId, ReviewDiscussionState,
        ReviewNoteId,
    };
    use kin_model::timestamp::Timestamp;
    use kin_model::IdentityRef;

    fn review_at(title: &str, seconds: u32, state: ReviewDecisionState) -> Review {
        // Built from its wire form so the test needs no clock crate of its own.
        let at: Timestamp = serde_json::from_value(serde_json::json!(format!(
            "2026-09-11T00:{:02}:{:02}Z",
            seconds / 60,
            seconds % 60
        )))
        .expect("an RFC 3339 instant");
        Review {
            review_id: ReviewId::new(),
            title: title.to_string(),
            base_ref: "main".to_string(),
            head_ref: format!("feature/{title}"),
            state,
            completion: ReviewCompletionState::InReview,
            created_by: IdentityRef::human("reviewer"),
            created_at: at.clone(),
            updated_at: at,
            scopes: vec![],
        }
    }

    #[test]
    fn a_listing_is_newest_first_whatever_order_the_store_holds() {
        let graph = InMemoryGraph::new();
        // Inserted oldest, newest, middle: neither insertion order nor its
        // reverse is the answer, so a sort that is missing or backwards fails.
        let oldest = review_at("oldest", 0, ReviewDecisionState::Pending);
        let newest = review_at("newest", 200, ReviewDecisionState::Pending);
        let middle = review_at("middle", 100, ReviewDecisionState::Approved);
        for review in [&oldest, &newest, &middle] {
            graph.create_review(review).unwrap();
        }

        let titles: Vec<String> = list_stored_reviews(&graph, None)
            .unwrap()
            .into_iter()
            .map(|review| review.title)
            .collect();
        assert_eq!(titles, vec!["newest", "middle", "oldest"]);

        let approved: Vec<String> =
            list_stored_reviews(&graph, Some(ReviewDecisionState::Approved))
                .unwrap()
                .into_iter()
                .map(|review| review.title)
                .collect();
        assert_eq!(approved, vec!["middle"], "the state filter must narrow");
    }

    #[test]
    fn a_record_carries_its_history_and_an_absent_id_reads_none() {
        let graph = InMemoryGraph::new();
        let review = review_at("record", 0, ReviewDecisionState::Pending);
        graph.create_review(&review).unwrap();
        graph
            .add_review_decision(
                &review.review_id,
                &ReviewDecision {
                    reviewer: IdentityRef::human("ada"),
                    state: ReviewDecisionState::NeedsWork,
                    comment: Some("split the parser change".to_string()),
                    decided_at: Timestamp::now(),
                },
            )
            .unwrap();
        graph
            .add_review_note(&ReviewNote {
                note_id: ReviewNoteId::new(),
                review_id: review.review_id,
                body: "checked the call sites".to_string(),
                scope: None,
                authored_by: IdentityRef::human("ada"),
                created_at: Timestamp::now(),
            })
            .unwrap();

        let record = read_review_record(&graph, &review.review_id)
            .unwrap()
            .expect("the stored review reads back");
        assert_eq!(record.review, review);
        assert_eq!(record.decisions.len(), 1);
        assert_eq!(record.notes.len(), 1);
        assert!(record.discussions.is_empty());
        assert!(record.assignments.is_empty());

        assert!(
            read_review_record(&graph, &ReviewId::new())
                .unwrap()
                .is_none(),
            "an id the store does not hold is None, not an empty record"
        );
    }

    /// A review shows the reviewers it has, which is its assignments minus
    /// every one a removal names. Every surface reads a review here, so they
    /// all show the same reviewers.
    ///
    /// Falsify by reading the stored set instead of deriving: the removed
    /// reviewer comes back and the first assertion goes red.
    #[test]
    fn a_removed_reviewer_is_no_longer_a_reviewer() {
        use crate::assignments::{tag_details, AssignmentTag, UNASSIGN_ACTION};
        use kin_model::graph::ProvenanceStore;
        use kin_model::provenance::{ActorId, AuditEvent, AuditEventId};
        use kin_model::review::ReviewAssignment;

        let graph = InMemoryGraph::new();
        let review = review_at("assigned", 0, ReviewDecisionState::Pending);
        graph.create_review(&review).unwrap();
        let assignment = |name: &str| ReviewAssignment {
            review_id: review.review_id,
            reviewer: IdentityRef::human(name),
            assigned_at: Timestamp::now(),
            assigned_by: IdentityRef::human("troy"),
        };
        let bob = assignment("bob");
        let alice = assignment("alice");
        for entry in [&bob, &alice] {
            graph.assign_reviewer(entry).unwrap();
        }
        graph
            .record_audit_event(&AuditEvent {
                event_id: AuditEventId::new(),
                actor_id: ActorId::new(),
                action: UNASSIGN_ACTION.to_string(),
                target_scope: None,
                timestamp: Timestamp::now(),
                details: Some(format!(
                    "review_id={}; reviewer=bob; {}",
                    review.review_id,
                    tag_details(&[AssignmentTag::of(&bob)])
                )),
            })
            .unwrap();

        let record = read_review_record(&graph, &review.review_id)
            .unwrap()
            .expect("the stored review reads back");
        assert_eq!(
            record.assignments,
            vec![alice],
            "a reviewer a removal names is not a reviewer any more"
        );
        assert_eq!(
            graph
                .get_review_assignments(&review.review_id)
                .unwrap()
                .len(),
            2,
            "and the stored set still holds both, because it is an add log"
        );
    }

    /// The views are the JSON the MCP tools have always printed, byte for byte.
    ///
    /// The expected text is built the way `kin_review_get` built it before the
    /// read moved here: a `json!` object per row. Key order is part of what an
    /// MCP client sees, so the comparison is on the printed text, not on the
    /// parsed value, which would pass with the keys in any order.
    #[test]
    fn the_record_view_prints_exactly_what_kin_review_get_printed() {
        let review = review_at("record", 0, ReviewDecisionState::NeedsWork);
        let discussion_id = ReviewDiscussionId::new();
        let record = ReviewRecord {
            decisions: vec![ReviewDecision {
                reviewer: IdentityRef::human("ada"),
                state: ReviewDecisionState::NeedsWork,
                comment: None,
                decided_at: Timestamp::now(),
            }],
            notes: vec![],
            discussions: vec![ReviewDiscussion {
                discussion_id,
                review_id: review.review_id,
                scope: None,
                state: ReviewDiscussionState::Open,
                comments: vec![ReviewComment {
                    authored_by: IdentityRef::human("lin"),
                    body: "why here".to_string(),
                    created_at: Timestamp::now(),
                }],
                created_at: Timestamp::now(),
            }],
            assignments: vec![],
            review: review.clone(),
        };

        let legacy = serde_json::json!({
            "review_id": review.review_id.to_string(),
            "title": review.title,
            "state": "needswork",
            "base_ref": review.base_ref,
            "head_ref": review.head_ref,
            "scopes": Vec::<String>::new(),
            "decisions": [{
                "state": "needswork",
                "comment": serde_json::Value::Null,
                "reviewer": "ada",
            }],
            "notes": Vec::<serde_json::Value>::new(),
            "discussions": [{
                "discussion_id": discussion_id.to_string(),
                "state": "open",
                "scope": serde_json::Value::Null,
                "comments": [{ "body": "why here", "author": "lin" }],
            }],
            "assignments": Vec::<serde_json::Value>::new(),
        });
        let view = serde_json::to_value(ReviewRecordView::from(&record)).unwrap();
        assert_eq!(
            serde_json::to_string_pretty(&view).unwrap(),
            serde_json::to_string_pretty(&legacy).unwrap()
        );

        let legacy_row = serde_json::json!({
            "review_id": review.review_id.to_string(),
            "title": review.title,
            "state": "needswork",
            "base_ref": review.base_ref,
            "head_ref": review.head_ref,
        });
        let row = serde_json::to_value(ReviewSummaryView::from(&review)).unwrap();
        assert_eq!(
            serde_json::to_string_pretty(&row).unwrap(),
            serde_json::to_string_pretty(&legacy_row).unwrap()
        );

        // The comparison above goes through a `serde_json::Value`, whose key
        // order is serde_json's `preserve_order` feature: sorted without it,
        // insertion order with it. A build with the feature off prints both
        // sides sorted and cannot see the fields reordered, which is how a
        // swapped pair survived here once. Printing the view directly always
        // follows declaration order, so the order `kin_review_get` has printed
        // wherever key order is kept is pinned in every build.
        assert_keys_in_order(
            &serde_json::to_string(&ReviewSummaryView::from(&review)).unwrap(),
            &["review_id", "title", "state", "base_ref", "head_ref"],
        );
        assert_keys_in_order(
            &serde_json::to_string(&ReviewRecordView::from(&record)).unwrap(),
            &[
                "review_id",
                "title",
                "state",
                "base_ref",
                "head_ref",
                "scopes",
                "decisions",
                "notes",
                "discussions",
                "assignments",
            ],
        );
    }

    /// Each key's first appearance comes after the one before it.
    fn assert_keys_in_order(printed: &str, keys: &[&str]) {
        let positions: Vec<usize> = keys
            .iter()
            .map(|key| {
                printed
                    .find(&format!("\"{key}\":"))
                    .unwrap_or_else(|| panic!("{key} missing from {printed}"))
            })
            .collect();
        assert!(
            positions.windows(2).all(|pair| pair[0] < pair[1]),
            "keys out of order, expected {keys:?} in {printed}"
        );
    }

    #[test]
    fn every_spelling_a_review_read_accepted_still_parses() {
        for (spelling, state) in [
            ("pending", ReviewDecisionState::Pending),
            ("approved", ReviewDecisionState::Approved),
            ("approve", ReviewDecisionState::Approved),
            ("needs_work", ReviewDecisionState::NeedsWork),
            ("needs-work", ReviewDecisionState::NeedsWork),
            ("needswork", ReviewDecisionState::NeedsWork),
            ("BLOCKED", ReviewDecisionState::Blocked),
            ("block", ReviewDecisionState::Blocked),
        ] {
            assert_eq!(
                parse_review_decision_state(spelling),
                Some(state),
                "{spelling}"
            );
        }
        assert_eq!(parse_review_decision_state("merged"), None);
    }
}
