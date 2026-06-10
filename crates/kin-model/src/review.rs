// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use crate::timestamp::Timestamp;
use crate::work::{IdentityRef, WorkScope};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Summary of risk associated with a semantic change.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RiskSummary {
    pub overall_risk: RiskLevel,
    pub breaking_changes: Vec<String>,
    pub test_coverage_gaps: Vec<String>,
    pub contract_violations: Vec<String>,
    /// Risks related to in-progress work items affected by changes.
    pub work_risks: Vec<String>,
    pub notes: Vec<String>,
}

/// Risk classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

// ---------------------------------------------------------------------------
// Review IDs
// ---------------------------------------------------------------------------

/// Unique identifier for a Review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ReviewId(pub uuid::Uuid);

impl ReviewId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl Default for ReviewId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ReviewId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a ReviewNote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ReviewNoteId(pub uuid::Uuid);

impl ReviewNoteId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl Default for ReviewNoteId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ReviewNoteId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a ReviewDiscussion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ReviewDiscussionId(pub uuid::Uuid);

impl ReviewDiscussionId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl Default for ReviewDiscussionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ReviewDiscussionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Review enums
// ---------------------------------------------------------------------------

/// Decision state for a review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum ReviewDecisionState {
    Pending,
    Approved,
    NeedsWork,
    Blocked,
}

impl std::fmt::Display for ReviewDecisionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReviewDecisionState::Pending => write!(f, "pending"),
            ReviewDecisionState::Approved => write!(f, "approved"),
            ReviewDecisionState::NeedsWork => write!(f, "needs-work"),
            ReviewDecisionState::Blocked => write!(f, "blocked"),
        }
    }
}

impl std::str::FromStr for ReviewDecisionState {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(ReviewDecisionState::Pending),
            "approved" => Ok(ReviewDecisionState::Approved),
            "needs-work" | "needs_work" | "needswork" => Ok(ReviewDecisionState::NeedsWork),
            "blocked" => Ok(ReviewDecisionState::Blocked),
            _ => Err(format!("unknown review decision state: {}", s)),
        }
    }
}

/// Completion state for a review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum ReviewCompletionState {
    InReview,
    Ready,
    Blocked,
}

impl std::fmt::Display for ReviewCompletionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReviewCompletionState::InReview => write!(f, "in-review"),
            ReviewCompletionState::Ready => write!(f, "ready"),
            ReviewCompletionState::Blocked => write!(f, "blocked"),
        }
    }
}

impl std::str::FromStr for ReviewCompletionState {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "in-review" | "in_review" | "inreview" => Ok(ReviewCompletionState::InReview),
            "ready" => Ok(ReviewCompletionState::Ready),
            "blocked" => Ok(ReviewCompletionState::Blocked),
            _ => Err(format!("unknown review completion state: {}", s)),
        }
    }
}

/// State of a review discussion thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum ReviewDiscussionState {
    Open,
    Resolved,
}

impl std::fmt::Display for ReviewDiscussionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReviewDiscussionState::Open => write!(f, "open"),
            ReviewDiscussionState::Resolved => write!(f, "resolved"),
        }
    }
}

impl std::str::FromStr for ReviewDiscussionState {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "open" => Ok(ReviewDiscussionState::Open),
            "resolved" => Ok(ReviewDiscussionState::Resolved),
            _ => Err(format!("unknown review discussion state: {}", s)),
        }
    }
}

// ---------------------------------------------------------------------------
// Review structs
// ---------------------------------------------------------------------------

/// A review scoped to semantic changes between two points.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Review {
    pub review_id: ReviewId,
    pub title: String,
    /// Base branch or commit reference.
    pub base_ref: String,
    /// Head branch or commit reference.
    pub head_ref: String,
    pub state: ReviewDecisionState,
    pub completion: ReviewCompletionState,
    pub created_by: IdentityRef,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    /// Entities/changes being reviewed.
    pub scopes: Vec<WorkScope>,
}

/// A record of a review decision (part of decision history).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReviewDecision {
    pub reviewer: IdentityRef,
    pub state: ReviewDecisionState,
    pub comment: Option<String>,
    pub decided_at: Timestamp,
}

/// A note attached to a review.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReviewNote {
    pub note_id: ReviewNoteId,
    pub review_id: ReviewId,
    pub body: String,
    /// Optionally anchored to a specific entity/file/change.
    pub scope: Option<WorkScope>,
    pub authored_by: IdentityRef,
    pub created_at: Timestamp,
}

/// A discussion thread on a review.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReviewDiscussion {
    pub discussion_id: ReviewDiscussionId,
    pub review_id: ReviewId,
    pub scope: Option<WorkScope>,
    pub state: ReviewDiscussionState,
    pub comments: Vec<ReviewComment>,
    pub created_at: Timestamp,
}

/// A single comment within a review discussion.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReviewComment {
    pub authored_by: IdentityRef,
    pub body: String,
    pub created_at: Timestamp,
}

/// A reviewer assignment on a review.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReviewAssignment {
    pub review_id: ReviewId,
    pub reviewer: IdentityRef,
    pub assigned_at: Timestamp,
    pub assigned_by: IdentityRef,
}

// ---------------------------------------------------------------------------
// Review filter
// ---------------------------------------------------------------------------

/// Filter for querying reviews.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ReviewFilter {
    pub states: Option<Vec<ReviewDecisionState>>,
    pub reviewer: Option<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_level_roundtrip() {
        let level = RiskLevel::High;
        let json = serde_json::to_string(&level).unwrap();
        let parsed: RiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, level);
    }

    #[test]
    fn review_decision_state_roundtrip() {
        for state in [
            ReviewDecisionState::Pending,
            ReviewDecisionState::Approved,
            ReviewDecisionState::NeedsWork,
            ReviewDecisionState::Blocked,
        ] {
            let s = state.to_string();
            let parsed: ReviewDecisionState = s.parse().unwrap();
            assert_eq!(state, parsed);
        }
    }

    #[test]
    fn review_completion_state_roundtrip() {
        for state in [
            ReviewCompletionState::InReview,
            ReviewCompletionState::Ready,
            ReviewCompletionState::Blocked,
        ] {
            let s = state.to_string();
            let parsed: ReviewCompletionState = s.parse().unwrap();
            assert_eq!(state, parsed);
        }
    }

    #[test]
    fn review_discussion_state_roundtrip() {
        for state in [ReviewDiscussionState::Open, ReviewDiscussionState::Resolved] {
            let s = state.to_string();
            let parsed: ReviewDiscussionState = s.parse().unwrap();
            assert_eq!(state, parsed);
        }
    }

    #[test]
    fn review_id_serialization() {
        let id = ReviewId::new();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: ReviewId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn review_serialization() {
        let review = Review {
            review_id: ReviewId::new(),
            title: "Add checkout flow".into(),
            base_ref: "main".into(),
            head_ref: "feat/checkout".into(),
            state: ReviewDecisionState::Pending,
            completion: ReviewCompletionState::InReview,
            created_by: IdentityRef::human("alice"),
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
            scopes: vec![],
        };

        let json = serde_json::to_string(&review).unwrap();
        let parsed: Review = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.review_id, review.review_id);
        assert_eq!(parsed.title, review.title);
        assert_eq!(parsed.state, ReviewDecisionState::Pending);
    }

    #[test]
    fn review_note_serialization() {
        let note = ReviewNote {
            note_id: ReviewNoteId::new(),
            review_id: ReviewId::new(),
            body: "Consider extracting this into a helper".into(),
            scope: None,
            authored_by: IdentityRef::human("bob"),
            created_at: Timestamp::now(),
        };

        let json = serde_json::to_string(&note).unwrap();
        let parsed: ReviewNote = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.note_id, note.note_id);
        assert_eq!(parsed.body, note.body);
    }

    #[test]
    fn review_discussion_serialization() {
        let discussion = ReviewDiscussion {
            discussion_id: ReviewDiscussionId::new(),
            review_id: ReviewId::new(),
            scope: None,
            state: ReviewDiscussionState::Open,
            comments: vec![ReviewComment {
                authored_by: IdentityRef::human("alice"),
                body: "Should we use a different approach?".into(),
                created_at: Timestamp::now(),
            }],
            created_at: Timestamp::now(),
        };

        let json = serde_json::to_string(&discussion).unwrap();
        let parsed: ReviewDiscussion = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.discussion_id, discussion.discussion_id);
        assert_eq!(parsed.state, ReviewDiscussionState::Open);
        assert_eq!(parsed.comments.len(), 1);
    }
}
