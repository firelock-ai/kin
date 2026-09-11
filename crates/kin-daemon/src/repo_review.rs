// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Repo-scoped review reads, and the entity-level diff between two refs.
//!
//! A hosted repository could list its entities, files, refs and history and
//! compare two refs file by file, but it could not answer the two questions a
//! review screen asks first: which reviews exist, and what changed at the level
//! of functions and types. `GET /repos/{repo_id}/reviews`,
//! `GET /repos/{repo_id}/reviews/{review_id}` and
//! `GET /repos/{repo_id}/semantic-diff?base=&head=` answer them from the same
//! graph authority `GET /repos/{repo_id}/entities` reads. Nothing on these paths
//! reads a file: a review is a graph record, and a diff is a fold over the
//! changes graph authority holds.
//!
//! One read serves every surface. The rows and the full record come from
//! `kin_review::records`, which `kin review list`, `kin review show` and the
//! `kin_review_list` and `kin_review_get` MCP tools read through too, so a
//! caller maps one shape whether it asked a local tool or a hosted daemon.
//!
//! Refs resolve exactly as `/compare` and `/blob` resolve them, and the range is
//! the one `/compare` measures: everything the head reaches that the base does
//! not, reviewed from their merge base. That is the range a review of a branch
//! means. It is not what `kin_review::compute_diff` walks, because the store's
//! backward walk stops only at the literal base node and crosses a merge into
//! the base's own history.
//!
//! Risk is asked for, not assumed. Measured on a 3,014-change store, the diff
//! answers in milliseconds while risk, which needs impact read at the head's own
//! graph state, replays the whole history and took over a minute. So the diff is
//! the default, `risk=assess` is the one way to a risk level, and an unassessed
//! risk says `not_assessed` wherever a level would otherwise show, never a blank
//! and never a default level. The record reads never compute a range at all.
//!
//! Refusals are the design. A ref that does not resolve names its side, an id
//! that is not a review id or names no review says which, and a head whose
//! history the graph cannot replay refuses rather than answering a diff without
//! its risk. An empty answer is a real zero with its evidence beside it: how
//! many reviews the store holds, how many changes the range holds.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use kin_model::review::{Review, ReviewId, RiskLevel};
use kin_model::{ChangeStore, Entity, SemanticChangeId};
use kin_review::records::{ReviewRecordView, ReviewSummaryView};
use kin_review::{EntityChange, EntityChangeKind, RangeReview, ReviewError, SemanticDiff};
use serde::{Deserialize, Serialize};

use crate::api::RepositoryReadView;
use crate::repo_blob::{RepoBlobError, RepoBlobRefusal};
use crate::repo_compare::{Distance, RepoCompareError, RepoCompareRefusal};
use crate::state::DaemonState;

/// The header every refusal from these routes carries, naming which refusal.
pub const REPO_REVIEW_REFUSAL_HEADER: &str = "x-kin-review-refusal";

/// What a risk field says when risk was not assessed.
///
/// A word rather than a null or a default level: a reader told nothing and a
/// reader told "low" look the same on a page, and only one of them is true.
pub const RISK_NOT_ASSESSED: &str = "not_assessed";

/// Which refusal, in a closed set a caller can branch on without reading English.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoReviewRefusal {
    /// The request itself could not be understood, so nothing was resolved.
    BadRequest,
    /// This daemon does not serve a repository by that id.
    UnknownRepository,
    /// It serves the id and could not read it as a repository.
    RepositoryUnreadable,
    /// A side named neither a ref this repository carries nor a change id.
    UnknownRef,
    /// A side is a short alias more than one ref answers to.
    AmbiguousRef,
    /// The two histories share no ancestor, so there is no range between them.
    NoCommonAncestor,
    /// A side's history ran past the walk's bound before an ancestor was found.
    HistoryTooDeep,
    /// Several best common ancestors exist and none descends from another.
    AmbiguousMergeBase,
    /// The review id is not an id at all.
    InvalidReviewId,
    /// The review id is well formed and this repository holds no such review.
    UnknownReview,
    /// The graph cannot replay the history a side names, so neither the diff
    /// nor its risk can be established.
    RefStateUnavailable,
}

impl RepoReviewRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad-request",
            Self::UnknownRepository => "unknown-repository",
            Self::RepositoryUnreadable => "repository-unreadable",
            Self::UnknownRef => "unknown-ref",
            Self::AmbiguousRef => "ambiguous-ref",
            Self::NoCommonAncestor => "no-common-ancestor",
            Self::HistoryTooDeep => "history-too-deep",
            Self::AmbiguousMergeBase => "ambiguous-merge-base",
            Self::InvalidReviewId => "invalid-review-id",
            Self::UnknownReview => "unknown-review",
            Self::RefStateUnavailable => "ref-state-unavailable",
        }
    }
}

/// A refusal from these routes: a status, a kind, and a sentence for a person.
#[derive(Debug, Clone)]
pub struct RepoReviewError {
    pub status: StatusCode,
    pub kind: RepoReviewRefusal,
    pub message: String,
}

impl RepoReviewError {
    fn new(status: StatusCode, kind: RepoReviewRefusal, message: impl Into<String>) -> Self {
        Self {
            status,
            kind,
            message: message.into(),
        }
    }

    /// A repository-addressed failure from the shared `/repos` helpers, which
    /// already decided between "not served here" (404) and "served and broken".
    fn from_repository(parts: (StatusCode, String)) -> Self {
        let kind = if parts.0 == StatusCode::NOT_FOUND {
            RepoReviewRefusal::UnknownRepository
        } else {
            RepoReviewRefusal::RepositoryUnreadable
        };
        Self::new(parts.0, kind, parts.1)
    }

    /// A side that did not resolve, under the blob route's own rule. The side
    /// leads the sentence because the status cannot say which one it was.
    fn from_read_point(side: &str, error: RepoBlobError) -> Self {
        let kind = match error.kind {
            RepoBlobRefusal::UnknownRef => RepoReviewRefusal::UnknownRef,
            RepoBlobRefusal::AmbiguousRef => RepoReviewRefusal::AmbiguousRef,
            RepoBlobRefusal::UnknownRepository => RepoReviewRefusal::UnknownRepository,
            _ => RepoReviewRefusal::RepositoryUnreadable,
        };
        Self::new(error.status, kind, format!("{side}: {}", error.message))
    }

    /// A merge-base refusal from `/compare`'s own measurement.
    fn from_distance(error: RepoCompareError) -> Self {
        let kind = match error.kind {
            RepoCompareRefusal::BadRequest => RepoReviewRefusal::BadRequest,
            RepoCompareRefusal::UnknownRepository => RepoReviewRefusal::UnknownRepository,
            RepoCompareRefusal::UnknownRef => RepoReviewRefusal::UnknownRef,
            RepoCompareRefusal::AmbiguousRef => RepoReviewRefusal::AmbiguousRef,
            RepoCompareRefusal::NoCommonAncestor => RepoReviewRefusal::NoCommonAncestor,
            RepoCompareRefusal::HistoryTooDeep => RepoReviewRefusal::HistoryTooDeep,
            RepoCompareRefusal::AmbiguousMergeBase => RepoReviewRefusal::AmbiguousMergeBase,
            RepoCompareRefusal::RepositoryUnreadable | RepoCompareRefusal::PathNotRepresentable => {
                RepoReviewRefusal::RepositoryUnreadable
            }
        };
        Self::new(error.status, kind, error.message)
    }

    fn from_review(error: ReviewError) -> Self {
        match error {
            ReviewError::RefStateUnavailable { at, missing } => Self::new(
                StatusCode::FAILED_DEPENDENCY,
                RepoReviewRefusal::RefStateUnavailable,
                format!(
                    "the graph cannot replay the history of {at}: change {missing} in its \
                     ancestry is not in this repository's graph, so no diff and no risk were \
                     computed"
                ),
            ),
            other => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                RepoReviewRefusal::RepositoryUnreadable,
                format!("the review of this range failed: {other}"),
            ),
        }
    }

    fn unreadable(context: impl std::fmt::Display, error: impl std::fmt::Display) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            RepoReviewRefusal::RepositoryUnreadable,
            format!("{context}: {error}"),
        )
    }
}

impl IntoResponse for RepoReviewError {
    fn into_response(self) -> axum::response::Response {
        let mut response = (self.status, self.message).into_response();
        response.headers_mut().insert(
            HeaderName::from_static(REPO_REVIEW_REFUSAL_HEADER),
            HeaderValue::from_static(self.kind.as_str()),
        );
        response
    }
}

/// A risk level as these routes and the boundary contract spell it.
pub fn risk_label(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}

// ---------------------------------------------------------------------------
// Response shapes
// ---------------------------------------------------------------------------

/// What a stored review's refs resolve to, and why nothing more is here.
///
/// The record reads never compute a range: that is the semantic diff's job and
/// its cost. `state` is `not_computed` when both stored refs resolved, and
/// `unresolved` when `gap` names the refusal one of them met. The count and the
/// merge base are then null, and `risk` is `not_assessed`, never a level.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewChangeSummary {
    pub state: String,
    pub base_change_id: Option<String>,
    pub head_change_id: Option<String>,
    pub merge_base_change_id: Option<String>,
    pub changed_entity_count: Option<usize>,
    pub risk: String,
    pub gap: Option<ReviewSummaryGap>,
}

/// Why a review's change summary holds what it holds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReviewSummaryGap {
    /// `not_computed`, or one of the refusal kinds [`REPO_REVIEW_REFUSAL_HEADER`]
    /// carries.
    pub kind: String,
    pub message: String,
}

/// One row of `GET /repos/{repo_id}/reviews`.
///
/// The first five fields are `kin_review_list`'s row, unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoReviewRow {
    #[serde(flatten)]
    pub summary: ReviewSummaryView,
    pub completion: String,
    pub scopes: Vec<String>,
    pub created_at: kin_model::Timestamp,
    pub updated_at: kin_model::Timestamp,
    pub change_summary: ReviewChangeSummary,
}

/// The evidence beside a review listing, so an empty one is a real zero.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoReviewsEvidence {
    /// Every review record this repository's graph holds, before any filter.
    pub review_records: usize,
    /// The decision state the listing was narrowed to, if any.
    pub state_filter: Option<String>,
}

/// `GET /repos/{repo_id}/reviews`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoReviewsResponse {
    pub repo_id: String,
    pub reviews: Vec<RepoReviewRow>,
    pub evidence: RepoReviewsEvidence,
}

/// `GET /repos/{repo_id}/reviews/{review_id}`.
///
/// The flattened fields are `kin_review_get`'s object, unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoReviewDetailResponse {
    #[serde(flatten)]
    pub review: ReviewRecordView,
    pub repo_id: String,
    pub completion: String,
    pub created_at: kin_model::Timestamp,
    pub updated_at: kin_model::Timestamp,
    pub change_summary: ReviewChangeSummary,
}

/// One field that moved between an entity's base and head records.
///
/// `old` and `new` are both null for `body` and `fingerprint`: the graph holds
/// a fingerprint for them rather than text, so the row says the field changed
/// and claims no values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticDiffFieldChange {
    pub field: String,
    pub old: Option<String>,
    pub new: Option<String>,
}

/// One changed entity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticDiffEntityRow {
    pub id: String,
    /// Null only for a removal whose base-side record is unrecoverable, which
    /// `evidence.unresolved_removals` counts; a bare id is never offered as a
    /// name.
    pub name: Option<String>,
    pub kind: Option<String>,
    /// `added`, `modified` or `removed`.
    pub change_type: String,
    /// `low`, `medium`, `high` or `critical` from this entity's own findings
    /// under `risk=assess`, never above `overall_risk`; otherwise
    /// [`RISK_NOT_ASSESSED`].
    pub risk_level: String,
    pub changes: Vec<SemanticDiffFieldChange>,
    pub before_signature: Option<String>,
    pub after_signature: Option<String>,
    pub file: Option<String>,
    /// The 1-based line an editor shows, not the graph's 0-based row.
    pub start_line: Option<u32>,
}

/// The review engine's findings for the range, as `kin review` reports them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SemanticDiffRiskFindings {
    pub breaking_changes: Vec<String>,
    pub test_coverage_gaps: Vec<String>,
    pub contract_violations: Vec<String>,
    pub work_risks: Vec<String>,
    pub notes: Vec<String>,
}

/// What the diff was computed from, so an empty entity list is a real zero.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticDiffEvidence {
    /// Changes the head reaches that the base does not.
    pub changes_in_range: usize,
    pub entity_changes: usize,
    pub relation_changes: usize,
    /// Recorded modifications that moved only span or source-blob provenance,
    /// counted rather than listed.
    pub provenance_only_entity_changes: usize,
    pub unresolved_removals: usize,
    /// `assessed` or [`RISK_NOT_ASSESSED`].
    pub risk: String,
    /// How the merge base was established: `closed_walks` or `full_walk`.
    pub merge_base_path: String,
}

/// `GET /repos/{repo_id}/semantic-diff`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoSemanticDiffResponse {
    pub repo_id: String,
    /// Each side as the caller sent it.
    pub base_ref: String,
    pub head_ref: String,
    /// Each side as it resolved.
    pub base_change_id: String,
    pub head_change_id: String,
    pub merge_base_change_id: String,
    pub ahead: usize,
    pub behind: usize,
    /// A level under `risk=assess`, otherwise [`RISK_NOT_ASSESSED`].
    pub overall_risk: String,
    pub entities: Vec<SemanticDiffEntityRow>,
    /// Present only when risk was assessed.
    pub risk_findings: Option<SemanticDiffRiskFindings>,
    pub evidence: SemanticDiffEvidence,
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RepoReviewsQuery {
    #[serde(default)]
    state: Option<String>,
}

/// GET /repos/{repo_id}/reviews: every review record, newest first.
pub async fn repo_reviews(
    Path(repo_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
    // Fallible so a malformed query still carries the refusal header.
    query: Result<Query<RepoReviewsQuery>, QueryRejection>,
) -> Result<Json<RepoReviewsResponse>, RepoReviewError> {
    let Query(query) = query.map_err(|rejection| {
        RepoReviewError::new(
            rejection.status(),
            RepoReviewRefusal::BadRequest,
            rejection.body_text(),
        )
    })?;
    let state_filter = query
        .state
        .as_deref()
        .map(|value| {
            kin_review::records::parse_review_decision_state(value.trim()).ok_or_else(|| {
                RepoReviewError::new(
                    StatusCode::BAD_REQUEST,
                    RepoReviewRefusal::BadRequest,
                    format!(
                        "state {value:?} is not a review decision state; this listing filters \
                         on pending, approved, needs_work or blocked"
                    ),
                )
            })
        })
        .transpose()?;

    let pair = open_pair(&state, &repo_id).await?;
    let response = blocking(move || {
        let graph = pair.graph.as_ref();
        // One read of the whole set, narrowed here, so the count beside the
        // rows describes the same read the rows came from.
        let held = kin_review::records::list_stored_reviews(graph, None)
            .map_err(|error| RepoReviewError::unreadable("listing review records", error))?;
        let reviews = held
            .iter()
            .filter(|review| state_filter.is_none_or(|wanted| review.state == wanted))
            .map(|review| RepoReviewRow {
                summary: ReviewSummaryView::from(review),
                completion: review.completion.to_string(),
                scopes: review.scopes.iter().map(ToString::to_string).collect(),
                created_at: review.created_at.clone(),
                updated_at: review.updated_at.clone(),
                change_summary: change_summary(&pair.authority, &repo_id, review),
            })
            .collect();
        Ok(RepoReviewsResponse {
            evidence: RepoReviewsEvidence {
                review_records: held.len(),
                state_filter: state_filter.map(kin_review::records::review_state_label),
            },
            repo_id,
            reviews,
        })
    })
    .await?;
    Ok(Json(response))
}

/// GET /repos/{repo_id}/reviews/{review_id}: one stored review in full.
pub async fn repo_review_detail(
    Path((repo_id, review_id)): Path<(String, String)>,
    State(state): State<Arc<DaemonState>>,
) -> Result<Json<RepoReviewDetailResponse>, RepoReviewError> {
    // Checked before anything is opened: an id that cannot name a review is
    // the caller's to fix, and no repository state changes that.
    let parsed = uuid::Uuid::parse_str(review_id.trim())
        .map(ReviewId)
        .map_err(|_| {
            RepoReviewError::new(
                StatusCode::BAD_REQUEST,
                RepoReviewRefusal::InvalidReviewId,
                format!(
                    "{review_id:?} is not a review id; a review id is the UUID \
                     GET /repos/{repo_id}/reviews lists as review_id"
                ),
            )
        })?;

    let pair = open_pair(&state, &repo_id).await?;
    let response = blocking(move || {
        let graph = pair.graph.as_ref();
        let record = kin_review::records::read_review_record(graph, &parsed)
            .map_err(|error| {
                RepoReviewError::unreadable(format!("reading review {parsed}"), error)
            })?
            .ok_or_else(|| {
                RepoReviewError::new(
                    StatusCode::NOT_FOUND,
                    RepoReviewRefusal::UnknownReview,
                    format!(
                        "repository {repo_id} holds no review {parsed}; \
                         GET /repos/{repo_id}/reviews lists the reviews it holds"
                    ),
                )
            })?;
        Ok(RepoReviewDetailResponse {
            review: ReviewRecordView::from(&record),
            completion: record.review.completion.to_string(),
            created_at: record.review.created_at.clone(),
            updated_at: record.review.updated_at.clone(),
            change_summary: change_summary(&pair.authority, &repo_id, &record.review),
            repo_id,
        })
    })
    .await?;
    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
pub struct RepoSemanticDiffQuery {
    /// A ref name or a canonical change id. Required: this route has no default.
    base: String,
    head: String,
    /// `assess` to add risk; absent for the diff alone.
    #[serde(default)]
    risk: Option<String>,
}

/// GET /repos/{repo_id}/semantic-diff: what the head changes, entity by entity.
pub async fn repo_semantic_diff(
    Path(repo_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
    query: Result<Query<RepoSemanticDiffQuery>, QueryRejection>,
) -> Result<Json<RepoSemanticDiffResponse>, RepoReviewError> {
    let Query(query) = query.map_err(|rejection| {
        RepoReviewError::new(
            rejection.status(),
            RepoReviewRefusal::BadRequest,
            rejection.body_text(),
        )
    })?;
    // Both sides are required and neither may be blank, checked before
    // anything is opened; see `nonblank_ref`.
    let base_ref = nonblank_ref("base", &query.base)?.to_string();
    let head_ref = nonblank_ref("head", &query.head)?.to_string();
    let assess = match query.risk.as_deref() {
        None => false,
        Some("assess") => true,
        Some(other) => {
            return Err(RepoReviewError::new(
                StatusCode::BAD_REQUEST,
                RepoReviewRefusal::BadRequest,
                format!(
                    "risk={other:?} is not a mode of this read; send risk=assess to assess \
                     risk, or leave risk out for the diff alone"
                ),
            ));
        }
    };

    let pair = open_pair(&state, &repo_id).await?;
    let base = resolve_side("base", &pair.authority, &base_ref, &repo_id)?;
    let head = resolve_side("head", &pair.authority, &head_ref, &repo_id)?;
    let graph = Arc::clone(&pair.graph);
    let (shape, answer) = blocking(move || review_range(&graph, base, head, assess)).await?;
    Ok(Json(semantic_diff_response(
        repo_id,
        base_ref,
        head_ref,
        (base, head),
        &shape,
        &answer,
        assess,
    )?))
}

// ---------------------------------------------------------------------------
// Shared reads
// ---------------------------------------------------------------------------

/// One repository generation's graph and the authority envelope naming its refs.
///
/// A hosted daemon takes both out of one cached generation, so a publication
/// landing mid-request cannot pair one generation's refs with another's graph
/// (FIR-2924). A local daemon serves its own repository: its live graph and
/// the publication-keyed ref envelope, without the whole-snapshot clone the
/// local read view makes to resolve trees, since nothing here resolves one.
/// That clone is not a small thing: one local `/compare` call on a 9.4 GiB
/// store grew its daemon past 19 GB while it ran.
struct RepoReadPair {
    graph: Arc<kin_db::InMemoryGraph>,
    authority: Arc<kin_db::PersistedRepositoryAuthority>,
}

async fn open_pair(state: &DaemonState, repo_id: &str) -> Result<RepoReadPair, RepoReviewError> {
    if state.storage_backend.is_some() {
        return match crate::api::repository_read_view(state, repo_id)
            .await
            .map_err(RepoReviewError::from_repository)?
        {
            RepositoryReadView::Hosted {
                generation,
                metadata,
            } => Ok(RepoReadPair {
                graph: Arc::clone(generation.graph()),
                authority: metadata,
            }),
            RepositoryReadView::Local { .. } => Err(RepoReviewError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                RepoReviewRefusal::RepositoryUnreadable,
                "a daemon with a storage backend answered with a local read view",
            )),
        };
    }
    let graph = crate::api::repo_scoped_graph(state, repo_id)
        .await
        .map_err(RepoReviewError::from_repository)?;
    let authority = crate::api::repository_ref_metadata(state, repo_id)
        .await
        .map_err(RepoReviewError::from_repository)?;
    Ok(RepoReadPair { graph, authority })
}

/// Run graph work off the async runtime, keeping a worker failure a refusal.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, RepoReviewError> + Send + 'static,
) -> Result<T, RepoReviewError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| RepoReviewError::unreadable("the review worker failed", error))?
}

/// One side of a range, refused when it names nothing.
///
/// The shared resolver reads a blank reference as no reference and answers
/// the repository's default ref. A route with no default must not inherit
/// that: a blank base would quietly become the default branch, and a stored
/// review whose ref was saved blank would be summarized against a range its
/// author never named.
fn nonblank_ref<'a>(side: &str, value: &'a str) -> Result<&'a str, RepoReviewError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(RepoReviewError::new(
            StatusCode::BAD_REQUEST,
            RepoReviewRefusal::BadRequest,
            format!(
                "{side} must name a ref or a change id, and it is blank. A range read has no \
                 default for either side."
            ),
        ));
    }
    Ok(trimmed)
}

fn resolve_side(
    side: &str,
    authority: &kin_db::PersistedRepositoryAuthority,
    reference: &str,
    repo_id: &str,
) -> Result<SemanticChangeId, RepoReviewError> {
    let reference = nonblank_ref(side, reference)?;
    crate::repo_blob::resolve_read_point_in(authority, Some(reference), repo_id)
        .map(|(change_id, _)| change_id)
        .map_err(|error| RepoReviewError::from_read_point(side, error))
}

/// A stored review's refs, resolved, and nothing computed from them.
fn change_summary(
    authority: &kin_db::PersistedRepositoryAuthority,
    repo_id: &str,
    review: &Review,
) -> ReviewChangeSummary {
    let unresolved = |base: Option<SemanticChangeId>, error: RepoReviewError| ReviewChangeSummary {
        state: "unresolved".to_string(),
        base_change_id: base.map(|id| id.to_string()),
        head_change_id: None,
        merge_base_change_id: None,
        changed_entity_count: None,
        risk: RISK_NOT_ASSESSED.to_string(),
        gap: Some(ReviewSummaryGap {
            kind: error.kind.as_str().to_string(),
            message: error.message,
        }),
    };
    let base = match resolve_side("base", authority, &review.base_ref, repo_id) {
        Ok(change_id) => change_id,
        Err(error) => return unresolved(None, error),
    };
    let head = match resolve_side("head", authority, &review.head_ref, repo_id) {
        Ok(change_id) => change_id,
        Err(error) => return unresolved(Some(base), error),
    };
    ReviewChangeSummary {
        state: "not_computed".to_string(),
        base_change_id: Some(base.to_string()),
        head_change_id: Some(head.to_string()),
        merge_base_change_id: None,
        changed_entity_count: None,
        risk: RISK_NOT_ASSESSED.to_string(),
        gap: Some(ReviewSummaryGap {
            kind: "not_computed".to_string(),
            message: format!(
                "the review reads do not compute a range; GET /repos/{repo_id}/semantic-diff \
                 with base={} and head={} answers its changed entities, and adds their risk with \
                 risk=assess",
                review.base_ref, review.head_ref
            ),
        }),
    }
}

/// How a range's merge base was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MergeBasePath {
    /// kin-db's parents-only candidate, proven by two closed, disjoint walks.
    ClosedWalks,
    /// The exact walk over both full ancestries.
    FullWalk,
}

impl MergeBasePath {
    fn as_str(self) -> &'static str {
        match self {
            Self::ClosedWalks => "closed_walks",
            Self::FullWalk => "full_walk",
        }
    }
}

/// Where a range starts, how far apart its tips are, and the head's own side.
#[derive(Debug)]
struct RangeShape {
    merge_base: SemanticChangeId,
    ahead: usize,
    behind: usize,
    /// Every change the head reaches that the base does not, when the closed
    /// walks already hold it; `None` after the full walk, which keeps no set.
    head_side: Option<HashSet<SemanticChangeId>>,
    path: MergeBasePath,
}

/// The merge base, the distance, and the head's side, as cheaply as is exact.
///
/// kin-db answers merge base candidates from parents alone, so it never decodes
/// a change body, but it keeps the common ancestors nearest the head by depth,
/// which in a history with merges can be an ancestor of the best one. So its
/// answer is used only when [`closed_sides`] proves it, and anything else takes
/// the exact walk `/compare` uses, which decodes every change on both full
/// ancestries and refuses what it cannot settle.
fn range_shape(
    graph: &kin_db::InMemoryGraph,
    base: SemanticChangeId,
    head: SemanticChangeId,
) -> Result<RangeShape, RepoReviewError> {
    let candidates = graph
        .find_merge_bases(&base, &head)
        .map_err(|error| RepoReviewError::unreadable("finding the merge base", error))?;
    if candidates.is_empty() {
        // kin-db walks one side's whole ancestry and the other's until each
        // path meets it, so an empty answer is exact.
        return Err(RepoReviewError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            RepoReviewRefusal::NoCommonAncestor,
            format!("{base} and {head} share no ancestor, so there is no range between them"),
        ));
    }
    if let [merge_base] = candidates.as_slice() {
        if let Some((head_side, base_side)) = closed_sides(graph, *merge_base, base, head)? {
            return Ok(RangeShape {
                merge_base: *merge_base,
                ahead: head_side.len(),
                behind: base_side.len(),
                head_side: Some(head_side),
                path: MergeBasePath::ClosedWalks,
            });
        }
    }
    let exact = distance(graph, &base, &head)?;
    Ok(RangeShape {
        merge_base: exact.merge_base,
        ahead: exact.ahead,
        behind: exact.behind,
        head_side: None,
        path: MergeBasePath::FullWalk,
    })
}

/// Each tip's walk down to `merge_base`, when both close on it and share nothing.
///
/// A walk closes when every path from its tip ends at `merge_base`. Two closed
/// walks that share no change prove `merge_base` is the one best common
/// ancestor, and each walk is then exactly what its tip reaches that the other
/// tip does not, so the distance and the head's side come from them. The proof:
/// a change in a closed walk descends from `merge_base`, so the other tip could
/// reach it only without passing `merge_base`, which would put it in the other
/// walk too; and any other common ancestor either descends from `merge_base`,
/// and so sits in both walks, or is an ancestor of it. Disjointness rules out
/// the first case, and the second is not better.
///
/// Cost is the walks' length, the range rather than the history. A walk that
/// does not close reaches past `merge_base` to a root, and the caller then pays
/// for the exact walk.
fn closed_sides(
    graph: &kin_db::InMemoryGraph,
    merge_base: SemanticChangeId,
    base: SemanticChangeId,
    head: SemanticChangeId,
) -> Result<Option<(HashSet<SemanticChangeId>, HashSet<SemanticChangeId>)>, RepoReviewError> {
    let Some(head_side) = closed_walk(graph, merge_base, head)? else {
        return Ok(None);
    };
    let Some(base_side) = closed_walk(graph, merge_base, base)? else {
        return Ok(None);
    };
    if head_side.intersection(&base_side).next().is_some() {
        return Ok(None);
    }
    Ok(Some((head_side, base_side)))
}

/// The changes `tip` reaches without passing `merge_base`, if every one of
/// those paths ends at `merge_base`.
///
/// The store's walk stops only at `merge_base` itself, so a path around it runs
/// on to a root. A root in the walk, or a parent the walk could not read, means
/// the walk did not close.
fn closed_walk(
    graph: &kin_db::InMemoryGraph,
    merge_base: SemanticChangeId,
    tip: SemanticChangeId,
) -> Result<Option<HashSet<SemanticChangeId>>, RepoReviewError> {
    let changes = graph
        .get_changes_since(&merge_base, &tip)
        .map_err(|error| RepoReviewError::unreadable("walking the range", error))?;
    let ids: HashSet<SemanticChangeId> = changes.iter().map(|change| change.id).collect();
    let closed = changes.iter().all(|change| {
        !change.parents.is_empty()
            && change
                .parents
                .iter()
                .all(|parent| *parent == merge_base || ids.contains(parent))
    });
    Ok(closed.then_some(ids))
}

/// The merge base and the distance by `/compare`'s own exact walk over the
/// graph's full change history.
fn distance(
    graph: &kin_db::InMemoryGraph,
    base: &SemanticChangeId,
    head: &SemanticChangeId,
) -> Result<Distance, RepoReviewError> {
    let mut cache: HashMap<SemanticChangeId, Vec<SemanticChangeId>> = HashMap::new();
    let mut parents_of =
        |change_id: &SemanticChangeId| -> Result<Vec<SemanticChangeId>, RepoCompareError> {
            if let Some(parents) = cache.get(change_id) {
                return Ok(parents.clone());
            }
            let change = graph
                .get_change(change_id)
                .map_err(|error| RepoCompareError {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    kind: RepoCompareRefusal::RepositoryUnreadable,
                    message: format!("reading change {change_id}: {error}"),
                })?
                .ok_or_else(|| RepoCompareError {
                    status: StatusCode::FAILED_DEPENDENCY,
                    kind: RepoCompareRefusal::RepositoryUnreadable,
                    message: format!("history references missing change {change_id}"),
                })?;
            let parents = change.parents.clone();
            cache.insert(*change_id, parents.clone());
            Ok(parents)
        };
    crate::repo_compare::measure_distance_with(base, head, &mut parents_of)
        .map_err(RepoReviewError::from_distance)
}

/// The head's side of a range by two exact ancestry walks, for a range the
/// closed walks could not answer.
fn exact_head_side(
    graph: &kin_db::InMemoryGraph,
    base: &SemanticChangeId,
    head: &SemanticChangeId,
) -> Result<HashSet<SemanticChangeId>, RepoReviewError> {
    let head_ancestry = kin_review::ref_graph::collect_ancestry(graph, head)
        .map_err(RepoReviewError::from_review)?;
    let base_ancestry = kin_review::ref_graph::collect_ancestry(graph, base)
        .map_err(RepoReviewError::from_review)?;
    Ok(head_ancestry.difference(&base_ancestry).copied().collect())
}

/// What a range read answered.
#[derive(Debug)]
enum RangeAnswer {
    /// The head adds nothing the base lacks.
    Empty,
    /// The diff alone.
    Diff(SemanticDiff),
    /// The diff and its risk, from the review engine.
    Assessed(Box<RangeReview>),
}

/// Read everything `head` reaches that `base` does not: the diff always, its
/// risk only when asked.
fn review_range(
    graph: &kin_db::InMemoryGraph,
    base: SemanticChangeId,
    head: SemanticChangeId,
    assess: bool,
) -> Result<(RangeShape, RangeAnswer), RepoReviewError> {
    let mut shape = range_shape(graph, base, head)?;
    if shape.ahead == 0 {
        return Ok((shape, RangeAnswer::Empty));
    }
    if assess {
        let range =
            kin_review::SemanticReview::create_range_review(graph, &shape.merge_base, &head)
                .map_err(RepoReviewError::from_review)?;
        return Ok((shape, RangeAnswer::Assessed(Box::new(range))));
    }
    let head_side = match shape.head_side.take() {
        Some(side) => side,
        None => exact_head_side(graph, &base, &head)?,
    };
    let diff = kin_review::diff::compute_diff_scoped(graph, &shape.merge_base, &head, |id| {
        head_side.contains(id)
    })
    .map_err(RepoReviewError::from_review)?;
    Ok((shape, RangeAnswer::Diff(diff)))
}

/// The response for one range read.
///
/// `assess` is the request's own mode, carried in because an empty range holds
/// no review to say it: an empty range read under `risk=assess` is assessed,
/// nothing changed, and nothing is what the engine ranks low.
fn semantic_diff_response(
    repo_id: String,
    base_ref: String,
    head_ref: String,
    (base, head): (SemanticChangeId, SemanticChangeId),
    shape: &RangeShape,
    answer: &RangeAnswer,
    assess: bool,
) -> Result<RepoSemanticDiffResponse, RepoReviewError> {
    let empty_diff = SemanticDiff::default();
    let (diff, changes_in_range, assessed): (&SemanticDiff, usize, Option<&RangeReview>) =
        match answer {
            RangeAnswer::Empty => (&empty_diff, 0, None),
            RangeAnswer::Diff(diff) => (diff, shape.ahead, None),
            RangeAnswer::Assessed(range) => (
                &range.review.diff,
                range.changes_in_range,
                Some(range.as_ref()),
            ),
        };

    let mut entities = Vec::with_capacity(diff.entity_changes.len());
    let mut unresolved_removals = 0;
    for change in &diff.entity_changes {
        let level = match assessed {
            // Every changed entity has a level by construction. A missing one
            // is a defect to report, not a gap to fill with a default.
            Some(range) => Some(
                range
                    .entity_risk
                    .get(&change.entity_id)
                    .copied()
                    .ok_or_else(|| {
                        RepoReviewError::unreadable(
                            "assembling the semantic diff",
                            format!(
                                "no risk level was computed for changed entity {}",
                                change.entity_id
                            ),
                        )
                    })?,
            ),
            None => None,
        };
        if matches!(change.kind, EntityChangeKind::Removed { old: None }) {
            unresolved_removals += 1;
        }
        entities.push(entity_row(change, level));
    }

    let (overall_risk, risk_findings) = match (assessed, assess) {
        (Some(range), _) => (
            risk_label(range.review.risk.overall_risk).to_string(),
            Some(SemanticDiffRiskFindings {
                breaking_changes: range.review.risk.breaking_changes.clone(),
                test_coverage_gaps: range.review.risk.test_coverage_gaps.clone(),
                contract_violations: range.review.risk.contract_violations.clone(),
                work_risks: range.review.risk.work_risks.clone(),
                notes: range.review.risk.notes.clone(),
            }),
        ),
        (None, true) => (
            risk_label(RiskLevel::Low).to_string(),
            Some(SemanticDiffRiskFindings::default()),
        ),
        (None, false) => (RISK_NOT_ASSESSED.to_string(), None),
    };

    Ok(RepoSemanticDiffResponse {
        repo_id,
        base_ref,
        head_ref,
        base_change_id: base.to_string(),
        head_change_id: head.to_string(),
        merge_base_change_id: shape.merge_base.to_string(),
        ahead: shape.ahead,
        behind: shape.behind,
        overall_risk,
        entities,
        risk_findings,
        evidence: SemanticDiffEvidence {
            changes_in_range,
            entity_changes: diff.entity_changes.len(),
            relation_changes: diff.relation_changes.len(),
            provenance_only_entity_changes: diff.provenance_only_entity_changes,
            unresolved_removals,
            risk: if assess {
                "assessed".to_string()
            } else {
                RISK_NOT_ASSESSED.to_string()
            },
            merge_base_path: shape.path.as_str().to_string(),
        },
    })
}

fn entity_row(change: &EntityChange, level: Option<RiskLevel>) -> SemanticDiffEntityRow {
    let (change_type, subject, changes, before_signature, after_signature) = match &change.kind {
        EntityChangeKind::Added(entity) => (
            "added",
            Some(entity),
            Vec::new(),
            None,
            Some(entity.signature.clone()),
        ),
        EntityChangeKind::Modified { old, new } => (
            "modified",
            Some(new),
            field_changes(old, new),
            Some(old.signature.clone()),
            Some(new.signature.clone()),
        ),
        EntityChangeKind::Removed { old } => (
            "removed",
            old.as_ref(),
            Vec::new(),
            old.as_ref().map(|entity| entity.signature.clone()),
            None,
        ),
    };
    let (file, start_line) = subject.map_or((None, None), location);
    SemanticDiffEntityRow {
        id: change.entity_id.to_string(),
        name: subject.map(|entity| entity.name.clone()),
        kind: subject.map(|entity| format!("{:?}", entity.kind)),
        change_type: change_type.to_string(),
        risk_level: level.map_or(RISK_NOT_ASSESSED, risk_label).to_string(),
        changes,
        before_signature,
        after_signature,
        file,
        start_line,
    }
}

fn location(entity: &Entity) -> (Option<String>, Option<u32>) {
    match &entity.span {
        Some(span) => (
            Some(span.file.to_string()),
            Some(span.start_line.saturating_add(1)),
        ),
        None => (entity.file_origin.as_ref().map(ToString::to_string), None),
    }
}

/// The fields that moved between a modified entity's base and head records.
///
/// Never empty. kin-review keeps a modification only when the entity changed
/// beyond its span and provenance, so when none of the named fields moved,
/// what moved is the fingerprint itself, and saying so beats an empty list a
/// reader would take for "nothing changed".
fn field_changes(old: &Entity, new: &Entity) -> Vec<SemanticDiffFieldChange> {
    let mut changes = Vec::new();
    let mut compare = |field: &str, before: Option<String>, after: Option<String>| {
        if before != after {
            changes.push(SemanticDiffFieldChange {
                field: field.to_string(),
                old: before,
                new: after,
            });
        }
    };
    compare("name", Some(old.name.clone()), Some(new.name.clone()));
    compare(
        "kind",
        Some(format!("{:?}", old.kind)),
        Some(format!("{:?}", new.kind)),
    );
    compare(
        "signature",
        Some(old.signature.clone()),
        Some(new.signature.clone()),
    );
    compare(
        "visibility",
        Some(format!("{:?}", old.visibility)),
        Some(format!("{:?}", new.visibility)),
    );
    compare(
        "role",
        Some(format!("{:?}", old.role)),
        Some(format!("{:?}", new.role)),
    );
    compare(
        "file",
        old.file_origin.as_ref().map(ToString::to_string),
        new.file_origin.as_ref().map(ToString::to_string),
    );
    compare(
        "doc_summary",
        old.doc_summary.clone(),
        new.doc_summary.clone(),
    );
    // The graph holds the body's behavior hash rather than its text, so the
    // row names the field and claims no values.
    if old.fingerprint.behavior_hash != new.fingerprint.behavior_hash {
        changes.push(SemanticDiffFieldChange {
            field: "body".to_string(),
            old: None,
            new: None,
        });
    }
    if changes.is_empty() {
        changes.push(SemanticDiffFieldChange {
            field: "fingerprint".to_string(),
            old: None,
            new: None,
        });
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::entity::{
        EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        SourceSpan, Visibility,
    };
    use kin_model::ids::{EntityId, FilePathId, LanguageId};
    use kin_model::Hash256;

    fn entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: Hash256::from_bytes([4; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    /// One committed change adding `added`, with its id computed from its
    /// content, so every change in a fixture DAG is distinct.
    fn change(parents: Vec<SemanticChangeId>, added: &[&Entity]) -> kin_model::SemanticChange {
        let mut change = kin_model::SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            parents,
            timestamp: kin_model::Timestamp::now(),
            author: kin_model::AuthorId::new("repo-review-test"),
            message: "range fixture".to_string(),
            entity_deltas: added
                .iter()
                .map(|entity| kin_model::EntityDelta::Added {
                    new: (*entity).clone(),
                })
                .collect(),
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };
        change.id = kin_model::compute_semantic_change_id(&change).unwrap();
        change
    }

    fn graph_of(changes: &[&kin_model::SemanticChange]) -> kin_db::InMemoryGraph {
        let graph = kin_db::InMemoryGraph::new();
        for change in changes {
            graph.create_change(change).unwrap();
        }
        graph
    }

    fn field(name: &str, old: Option<&str>, new: Option<&str>) -> SemanticDiffFieldChange {
        SemanticDiffFieldChange {
            field: name.to_string(),
            old: old.map(str::to_string),
            new: new.map(str::to_string),
        }
    }

    /// root, then the base on one side and two changes on the head's side.
    #[test]
    fn a_linear_range_answers_from_two_closed_walks() {
        let root = change(vec![], &[&entity("root_fn")]);
        let base = change(vec![root.id], &[&entity("only_on_base")]);
        let head_one = change(vec![root.id], &[&entity("head_one")]);
        let head_two = change(vec![head_one.id], &[&entity("head_two")]);
        let graph = graph_of(&[&root, &base, &head_one, &head_two]);

        let shape = range_shape(&graph, base.id, head_two.id).unwrap();
        assert_eq!(shape.path, MergeBasePath::ClosedWalks);
        assert_eq!(shape.merge_base, root.id);
        assert_eq!((shape.ahead, shape.behind), (2, 1));
        assert_eq!(
            shape.head_side,
            Some([head_one.id, head_two.id].into_iter().collect())
        );
    }

    /// The head merges a side branch and the base, so its walk runs around the
    /// base down to the root: the closed walks cannot answer, the exact one can.
    #[test]
    fn a_merge_that_reaches_past_the_base_takes_the_exact_walk() {
        let root = change(vec![], &[&entity("root_fn")]);
        let base = change(vec![root.id], &[&entity("on_base")]);
        let side = change(vec![root.id], &[&entity("on_side")]);
        let head = change(vec![side.id, base.id], &[&entity("merge_fn")]);
        let graph = graph_of(&[&root, &base, &side, &head]);

        let shape = range_shape(&graph, base.id, head.id).unwrap();
        assert_eq!(shape.path, MergeBasePath::FullWalk);
        assert_eq!(shape.merge_base, base.id);
        assert_eq!((shape.ahead, shape.behind), (2, 0));
    }

    /// kin-db's nearest-by-depth candidate here is the root, one hop from the
    /// head through its second parent, while the best common ancestor is the
    /// change the base and the head's first line both grew from. Both walks
    /// down to the root close; they share that change, and only the
    /// disjointness check refuses the near candidate.
    #[test]
    fn a_nearer_but_older_candidate_is_refused_by_the_change_both_walks_share() {
        let root = change(vec![], &[&entity("root_fn")]);
        let shared = change(vec![root.id], &[&entity("shared_fn")]);
        let base = change(vec![shared.id], &[&entity("on_base")]);
        let line = change(vec![shared.id], &[&entity("on_head")]);
        let head = change(vec![line.id, root.id], &[&entity("merge_fn")]);
        let graph = graph_of(&[&root, &shared, &base, &line, &head]);
        assert_eq!(
            graph.find_merge_bases(&base.id, &head.id).unwrap(),
            vec![root.id],
            "the fixture must present the near, older candidate"
        );

        let shape = range_shape(&graph, base.id, head.id).unwrap();
        assert_eq!(shape.path, MergeBasePath::FullWalk);
        assert_eq!(shape.merge_base, shared.id);
        assert_eq!((shape.ahead, shape.behind), (2, 1));
    }

    /// The diff alone says not_assessed everywhere a level would show, and
    /// risk=assess is what turns the same range into levels.
    #[test]
    fn risk_is_not_assessed_unless_asked_and_a_level_only_when_asked() {
        let root = change(vec![], &[&entity("root_fn")]);
        let base = change(vec![root.id], &[&entity("only_on_base")]);
        let head_one = change(vec![root.id], &[&entity("head_one")]);
        let head_two = change(vec![head_one.id], &[&entity("head_two")]);
        let graph = graph_of(&[&root, &base, &head_one, &head_two]);
        let respond = |assess: bool| {
            let (shape, answer) = review_range(&graph, base.id, head_two.id, assess).unwrap();
            semantic_diff_response(
                "repo".to_string(),
                "base".to_string(),
                "head".to_string(),
                (base.id, head_two.id),
                &shape,
                &answer,
                assess,
            )
            .unwrap()
        };

        let plain = respond(false);
        let names: HashSet<String> = plain
            .entities
            .iter()
            .filter_map(|row| row.name.clone())
            .collect();
        assert_eq!(
            names,
            ["head_one", "head_two"]
                .map(String::from)
                .into_iter()
                .collect(),
            "the base's own change is outside the range"
        );
        assert_eq!(plain.overall_risk, RISK_NOT_ASSESSED);
        assert!(plain
            .entities
            .iter()
            .all(|row| row.risk_level == RISK_NOT_ASSESSED));
        assert_eq!(plain.risk_findings, None);
        assert_eq!(plain.evidence.risk, RISK_NOT_ASSESSED);
        assert_eq!(plain.evidence.merge_base_path, "closed_walks");
        assert_eq!(plain.evidence.changes_in_range, 2);

        let assessed = respond(true);
        assert_eq!(assessed.overall_risk, "low");
        assert!(assessed.entities.iter().all(|row| row.risk_level == "low"));
        assert!(assessed.risk_findings.is_some());
        assert_eq!(assessed.evidence.risk, "assessed");
        assert_eq!(assessed.entities.len(), plain.entities.len());

        // An empty range: a real zero either way, and only the asked-for one
        // carries a level.
        let (shape, answer) = review_range(&graph, head_two.id, head_two.id, false).unwrap();
        assert!(matches!(answer, RangeAnswer::Empty));
        let empty = semantic_diff_response(
            "repo".to_string(),
            "head".to_string(),
            "head".to_string(),
            (head_two.id, head_two.id),
            &shape,
            &answer,
            false,
        )
        .unwrap();
        assert!(empty.entities.is_empty());
        assert_eq!(empty.overall_risk, RISK_NOT_ASSESSED);
        assert_eq!(empty.evidence.changes_in_range, 0);
    }

    #[test]
    fn a_signature_change_names_the_signature_and_nothing_it_did_not_change() {
        let old = entity("parse");
        let mut new = old.clone();
        new.signature = "fn parse(strict: bool)".to_string();
        assert_eq!(
            field_changes(&old, &new),
            vec![field(
                "signature",
                Some("fn parse()"),
                Some("fn parse(strict: bool)")
            )]
        );
    }

    #[test]
    fn a_body_change_is_named_without_inventing_its_text() {
        let old = entity("render");
        let mut new = old.clone();
        new.fingerprint.behavior_hash = Hash256::from_bytes([9; 32]);
        assert_eq!(field_changes(&old, &new), vec![field("body", None, None)]);
    }

    #[test]
    fn a_modification_no_named_field_explains_still_names_what_moved() {
        // An empty list would read as "nothing changed" on a row that says
        // modified, which is the one reading the row exists to rule out.
        let old = entity("stable");
        let mut new = old.clone();
        new.fingerprint.stability_score = 0.5;
        assert_eq!(
            field_changes(&old, &new),
            vec![field("fingerprint", None, None)]
        );
    }

    #[test]
    fn a_removal_with_no_base_record_offers_no_name() {
        let change = EntityChange {
            entity_id: EntityId::new(),
            kind: EntityChangeKind::Removed { old: None },
        };
        let row = entity_row(&change, None);
        assert_eq!(row.id, change.entity_id.to_string());
        assert_eq!(row.name, None, "a bare id is never offered as a name");
        assert_eq!(row.kind, None);
        assert_eq!(row.change_type, "removed");
        assert_eq!(row.risk_level, RISK_NOT_ASSESSED);
        assert_eq!(row.before_signature, None);
        assert_eq!(row.file, None);
    }

    #[test]
    fn a_placed_entity_reports_the_line_an_editor_shows() {
        let mut added = entity("placed");
        added.span = Some(SourceSpan {
            file: FilePathId::new("src/lib.rs"),
            start_byte: 0,
            end_byte: 1,
            start_line: 41,
            start_col: 0,
            end_line: 42,
            end_col: 0,
        });
        let row = entity_row(
            &EntityChange {
                entity_id: added.id,
                kind: EntityChangeKind::Added(added.clone()),
            },
            Some(RiskLevel::Critical),
        );
        assert_eq!(row.file.as_deref(), Some("src/lib.rs"));
        assert_eq!(row.start_line, Some(42), "graph row 41 is editor line 42");
        assert_eq!(row.risk_level, "critical");
        assert_eq!(row.after_signature.as_deref(), Some("fn placed()"));
        assert_eq!(row.before_signature, None);
    }

    #[test]
    fn every_refusal_kind_has_a_distinct_stable_spelling() {
        let kinds = [
            RepoReviewRefusal::BadRequest,
            RepoReviewRefusal::UnknownRepository,
            RepoReviewRefusal::RepositoryUnreadable,
            RepoReviewRefusal::UnknownRef,
            RepoReviewRefusal::AmbiguousRef,
            RepoReviewRefusal::NoCommonAncestor,
            RepoReviewRefusal::HistoryTooDeep,
            RepoReviewRefusal::AmbiguousMergeBase,
            RepoReviewRefusal::InvalidReviewId,
            RepoReviewRefusal::UnknownReview,
            RepoReviewRefusal::RefStateUnavailable,
        ];
        let spellings: std::collections::BTreeSet<&str> =
            kinds.iter().map(|kind| kind.as_str()).collect();
        assert_eq!(spellings.len(), kinds.len(), "two kinds share a spelling");
        assert!(
            spellings
                .iter()
                .all(|spelling| HeaderValue::from_str(spelling).is_ok()),
            "every spelling has to survive the header it travels in"
        );
    }
}
