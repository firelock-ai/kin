// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The repo-scoped review reads and semantic diff, over the router.
//!
//! The hosted fixture is the store the routes exist for: two generations on
//! `main`, a second ref `legacy` at the first, and one review record of
//! `legacy..main` committed into graph authority the way a transfer carries
//! one. Every arm reads it through the router, so the route table, the
//! extractors and the refusal header are under test with the logic.

use super::*;
use crate::repo_review::{
    RepoReviewDetailResponse, RepoReviewsResponse, RepoSemanticDiffResponse,
    REPO_REVIEW_REFUSAL_HEADER, RISK_NOT_ASSESSED,
};
use kin_model::review::{
    Review, ReviewCompletionState, ReviewDecisionState, ReviewId as StoredReviewId,
};

/// GET one path: the status, the refusal header, and the body.
async fn read(state: Arc<DaemonState>, path: &str) -> (StatusCode, Option<String>, Vec<u8>) {
    let response = router(state)
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let refusal = response
        .headers()
        .get(REPO_REVIEW_REFUSAL_HEADER)
        .map(|value| value.to_str().unwrap().to_string());
    let body = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (status, refusal, body.to_vec())
}

/// Commit one review record into hosted authority, alone, the way a transfer
/// pack carries collaboration: a transaction whose only mutation is the record.
fn publish_hosted_review(
    storage: &FsPath,
    repository_id: &RepositoryId,
    operation: u128,
    review: &Review,
) {
    use kin_model::{RepositoryTransaction, REPOSITORY_TRANSACTION_SCHEMA_VERSION};

    let manager = RepositoryAuthorityManager::open(
        repository_id.clone(),
        Arc::new(kin_db::LocalFileBackend::new(storage.to_path_buf())),
    )
    .unwrap();
    let lease = manager.read_authority();
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: kin_model::OperationId::from_uuid(Uuid::from_u128(operation)),
        repository_id: repository_id.clone(),
        expected_generation: lease.roots().generation,
        expected_roots: lease.roots().clone(),
        actor: AuthorId::new("repo-review-test"),
        reason: format!("record review {}", review.review_id),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: None,
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: Some(kin_model::CollaborationDelta {
            reviews: vec![kin_model::Keyed::new(review.review_id, review.clone())],
            ..kin_model::CollaborationDelta::default()
        }),
    };
    drop(lease);
    manager.commit_repository_transaction(transaction).unwrap();
}

struct ReviewFixture {
    state: Arc<DaemonState>,
    repo_id: String,
    first: SemanticChangeId,
    second: SemanticChangeId,
    review: Review,
    _working: tempfile::TempDir,
    _storage: tempfile::TempDir,
}

/// One review record and two refs: `main` at the second generation, `legacy`
/// at the first, and the review asks what `legacy..main` changed.
async fn review_fixture() -> ReviewFixture {
    let repo_id = format!("hostedreview-{}", Uuid::new_v4());
    let (state, working, storage) = replica_state(&repo_id);
    let repository_id = RepositoryId::new(&repo_id).unwrap();
    let (first, _entities) = publish_hosted_semantic_change(
        storage.path(),
        &repository_id,
        None,
        0x5245_5601,
        "publish the first generation",
        &[(
            "only_in_first",
            "src/only_in_first.rs",
            "fn only_in_first() {}\n",
        )],
    );
    let (second, _entities) = publish_hosted_semantic_change(
        storage.path(),
        &repository_id,
        Some(first),
        0x5245_5602,
        "publish the second generation",
        &[(
            "only_in_second",
            "src/only_in_second.rs",
            "fn only_in_second() {}\n",
        )],
    );
    add_hosted_ref(
        storage.path(),
        &repository_id,
        0x5245_5603,
        kin_model::RefName::branch(b"legacy").unwrap(),
        first,
    );
    let now = kin_model::Timestamp::now();
    let review = Review {
        review_id: StoredReviewId::new(),
        title: "Review the second generation".to_string(),
        base_ref: "legacy".to_string(),
        head_ref: "main".to_string(),
        state: ReviewDecisionState::Pending,
        completion: ReviewCompletionState::InReview,
        created_by: kin_model::IdentityRef::human("reviewer"),
        created_at: now.clone(),
        updated_at: now,
        scopes: Vec::new(),
    };
    publish_hosted_review(storage.path(), &repository_id, 0x5245_5604, &review);
    state.evict_repo_cache_for_test(&repo_id).await;
    ReviewFixture {
        state,
        repo_id,
        first,
        second,
        review,
        _working: working,
        _storage: storage,
    }
}

/// A record read resolves the review's refs and computes nothing from them.
fn assert_not_computed(summary: &crate::repo_review::ReviewChangeSummary, fixture: &ReviewFixture) {
    assert_eq!(summary.state, "not_computed", "{summary:?}");
    assert_eq!(
        summary.base_change_id.as_deref(),
        Some(fixture.first.to_string().as_str())
    );
    assert_eq!(
        summary.head_change_id.as_deref(),
        Some(fixture.second.to_string().as_str())
    );
    assert_eq!(summary.merge_base_change_id, None);
    assert_eq!(
        summary.changed_entity_count, None,
        "a count nobody computed is null, never zero"
    );
    assert_eq!(summary.risk, RISK_NOT_ASSESSED);
    let gap = summary.gap.as_ref().expect("not_computed says why");
    assert_eq!(gap.kind, "not_computed");
    assert!(gap.message.contains("semantic-diff"), "{gap:?}");
}

/// The listing serves the stored record, with its refs resolved and its range
/// left to the semantic diff.
#[tokio::test]
async fn the_review_listing_serves_the_stored_record_with_its_refs_resolved() {
    let fixture = review_fixture().await;
    let (status, refusal, body) = read(
        Arc::clone(&fixture.state),
        &format!("/repos/{}/reviews", fixture.repo_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(refusal, None);
    let listing: RepoReviewsResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(listing.repo_id, fixture.repo_id);
    assert_eq!(listing.evidence.review_records, 1);
    assert_eq!(listing.reviews.len(), 1, "one stored review, one row");

    let row = &listing.reviews[0];
    assert_eq!(row.summary.review_id, fixture.review.review_id.to_string());
    assert_eq!(row.summary.title, fixture.review.title);
    assert_eq!(row.summary.state, "pending");
    assert_eq!(row.summary.base_ref, "legacy");
    assert_eq!(row.summary.head_ref, "main");
    assert_eq!(row.completion, "in-review");
    assert_not_computed(&row.change_summary, &fixture);

    // A filter that excludes the one record answers an empty list beside the
    // count that proves the store was read and holds a review.
    let (status, _, body) = read(
        Arc::clone(&fixture.state),
        &format!("/repos/{}/reviews?state=approved", fixture.repo_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let narrowed: RepoReviewsResponse = serde_json::from_slice(&body).unwrap();
    assert!(narrowed.reviews.is_empty());
    assert_eq!(narrowed.evidence.review_records, 1);
    assert_eq!(narrowed.evidence.state_filter.as_deref(), Some("approved"));

    let (status, refusal, body) = read(
        Arc::clone(&fixture.state),
        &format!("/repos/{}/reviews?state=merged", fixture.repo_id),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(refusal.as_deref(), Some("bad-request"));
    assert!(String::from_utf8_lossy(&body).contains("merged"));
}

/// The detail is the stored record, and each way of not naming one refuses
/// in its own words.
#[tokio::test]
async fn the_review_detail_serves_the_record_and_refuses_what_names_no_review() {
    let fixture = review_fixture().await;
    let review_id = fixture.review.review_id;
    let (status, refusal, body) = read(
        Arc::clone(&fixture.state),
        &format!("/repos/{}/reviews/{review_id}", fixture.repo_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(refusal, None);
    let detail: RepoReviewDetailResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(detail.review.review_id, review_id.to_string());
    assert_eq!(detail.review.title, fixture.review.title);
    assert_eq!(detail.review.base_ref, "legacy");
    assert_eq!(detail.review.head_ref, "main");
    assert!(detail.review.decisions.is_empty());
    assert_not_computed(&detail.change_summary, &fixture);

    // The detail is kin_review_get's object at the top level, so a client
    // mapping the MCP tool's answer maps this one.
    let raw: serde_json::Value = serde_json::from_slice(&body).unwrap();
    for key in [
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
    ] {
        assert!(
            raw.get(key).is_some(),
            "the detail must carry {key} at the top level"
        );
    }

    let absent = StoredReviewId::new();
    let (status, refusal, body) = read(
        Arc::clone(&fixture.state),
        &format!("/repos/{}/reviews/{absent}", fixture.repo_id),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(refusal.as_deref(), Some("unknown-review"));
    assert!(
        String::from_utf8_lossy(&body).contains(&absent.to_string()),
        "the refusal must name the review it could not find"
    );

    let (status, refusal, _) = read(
        Arc::clone(&fixture.state),
        &format!("/repos/{}/reviews/not-a-review", fixture.repo_id),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(refusal.as_deref(), Some("invalid-review-id"));

    let (status, refusal, _) = read(
        Arc::clone(&fixture.state),
        &format!("/repos/{}-elsewhere/reviews/{review_id}", fixture.repo_id),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(refusal.as_deref(), Some("unknown-repository"));
}

/// The semantic diff answers the range with risk not assessed, adds risk only
/// under risk=assess, and refuses a side that names nothing.
///
/// Forward, `legacy..main` adds one function. Reversed, the head adds nothing
/// the base lacks, which is the empty answer, and it has to arrive with the
/// zero in its evidence and the distance beside it rather than as a bare empty
/// list a failed computation could also produce.
#[tokio::test]
async fn the_semantic_diff_answers_the_range_and_assesses_risk_only_when_asked() {
    let fixture = review_fixture().await;
    let (status, refusal, body) = read(
        Arc::clone(&fixture.state),
        &format!(
            "/repos/{}/semantic-diff?base=legacy&head=main",
            fixture.repo_id
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(refusal, None);
    let diff: RepoSemanticDiffResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(diff.base_ref, "legacy");
    assert_eq!(diff.head_ref, "main");
    assert_eq!(diff.base_change_id, fixture.first.to_string());
    assert_eq!(diff.head_change_id, fixture.second.to_string());
    assert_eq!(diff.merge_base_change_id, fixture.first.to_string());
    assert_eq!((diff.ahead, diff.behind), (1, 0));
    assert_eq!(diff.evidence.changes_in_range, 1);
    assert_eq!(diff.evidence.entity_changes, 1);
    assert_eq!(diff.evidence.unresolved_removals, 0);
    assert_eq!(diff.evidence.merge_base_path, "closed_walks");
    assert_eq!(diff.overall_risk, RISK_NOT_ASSESSED);
    assert_eq!(diff.evidence.risk, RISK_NOT_ASSESSED);
    assert_eq!(diff.risk_findings, None);
    assert_eq!(diff.entities.len(), 1, "{:?}", diff.entities);
    let entity = &diff.entities[0];
    assert_eq!(entity.name.as_deref(), Some("only_in_second"));
    assert_eq!(entity.kind.as_deref(), Some("Function"));
    assert_eq!(entity.change_type, "added");
    assert_eq!(entity.risk_level, RISK_NOT_ASSESSED);
    assert_eq!(entity.before_signature, None);
    assert_eq!(
        entity.after_signature.as_deref(),
        Some("fn only_in_second() {}")
    );
    assert_eq!(entity.file.as_deref(), Some("src/only_in_second.rs"));
    assert_eq!(
        entity.start_line,
        Some(1),
        "the 1-based line an editor shows"
    );
    assert!(entity.changes.is_empty());

    let (status, _, body) = read(
        Arc::clone(&fixture.state),
        &format!(
            "/repos/{}/semantic-diff?base=legacy&head=main&risk=assess",
            fixture.repo_id
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let assessed: RepoSemanticDiffResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(assessed.overall_risk, "low");
    assert_eq!(assessed.evidence.risk, "assessed");
    assert!(assessed.risk_findings.is_some());
    assert_eq!(assessed.entities.len(), 1);
    assert_eq!(assessed.entities[0].risk_level, "low");

    let (status, _, body) = read(
        Arc::clone(&fixture.state),
        &format!(
            "/repos/{}/semantic-diff?base=main&head=legacy",
            fixture.repo_id
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let reversed: RepoSemanticDiffResponse = serde_json::from_slice(&body).unwrap();
    assert!(reversed.entities.is_empty());
    assert_eq!((reversed.ahead, reversed.behind), (0, 1));
    assert_eq!(reversed.evidence.changes_in_range, 0);
    assert_eq!(reversed.merge_base_change_id, fixture.first.to_string());
    assert_eq!(reversed.overall_risk, RISK_NOT_ASSESSED);

    let (status, refusal, body) = read(
        Arc::clone(&fixture.state),
        &format!(
            "/repos/{}/semantic-diff?base=no-such-branch&head=main",
            fixture.repo_id
        ),
    )
    .await;
    let message = String::from_utf8_lossy(&body);
    assert_eq!(status, StatusCode::NOT_FOUND, "{message}");
    assert_eq!(refusal.as_deref(), Some("unknown-ref"));
    assert!(
        message.starts_with("base:") && message.contains("no-such-branch"),
        "the refusal must name the side and the ref: {message}"
    );

    for query in [
        "base=&head=main",
        "head=main",
        "base=legacy&head=main&risk=maybe",
    ] {
        let (status, refusal, _) = read(
            Arc::clone(&fixture.state),
            &format!("/repos/{}/semantic-diff?{query}", fixture.repo_id),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(refusal.as_deref(), Some("bad-request"), "{query}");
    }
}

/// A caller probes the capability list before it calls the routes.
#[tokio::test]
async fn repo_health_advertises_the_review_and_semantic_diff_reads() {
    let fixture = review_fixture().await;
    let (status, _, body) = read(
        Arc::clone(&fixture.state),
        &format!("/repos/{}/health", fixture.repo_id),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let health: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let capabilities: Vec<&str> = health["semantic_capabilities"]
        .as_array()
        .expect("semantic_capabilities is a list")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    for capability in ["repo_reviews_v1", "repo_semantic_diff_v1"] {
        assert!(
            capabilities.contains(&capability),
            "{capability} must be advertised: {capabilities:?}"
        );
    }
}

/// On a local daemon the repo-scoped listing reads the graph `POST /review`
/// writes, and a stored ref that resolves to nothing is an explicit gap.
///
/// The review is created through the single-repo route and read back through
/// the repo-scoped one, so the two cannot be reading different stores. Its
/// refs name nothing in a fresh store, and the row says so under a refusal
/// kind rather than reporting zero changed entities.
#[tokio::test]
async fn a_local_listing_reads_what_post_review_wrote_and_names_an_unresolved_ref() {
    let state = test_state();
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let response = router(Arc::clone(&state))
        .oneshot(
            Request::post("/review")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "op": "create",
                        "title": "Local review",
                        "base": "main",
                        "head": "feature/nowhere",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let repo_id = state.cached_repo_id.clone();
    let (status, _, body) = read(Arc::clone(&state), &format!("/repos/{repo_id}/reviews")).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let listing: RepoReviewsResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(listing.reviews.len(), 1);
    assert_eq!(listing.reviews[0].summary.title, "Local review");
    let summary = &listing.reviews[0].change_summary;
    assert_eq!(summary.state, "unresolved", "{summary:?}");
    assert_eq!(
        summary.changed_entity_count, None,
        "an unresolved range is never reported as zero changed entities"
    );
    assert_eq!(summary.risk, RISK_NOT_ASSESSED);
    let gap = summary
        .gap
        .as_ref()
        .expect("an unresolved summary names its gap");
    assert_eq!(gap.kind, "unknown-ref", "{gap:?}");
    assert!(gap.message.starts_with("base:"), "{gap:?}");
}

/// `POST /review` show of an id the store holds no review under answers 404.
///
/// It answered 500, which a caller reads as a daemon fault and retries. The
/// missing record is the caller's answer, and the status now says so.
#[tokio::test]
async fn post_review_show_of_a_missing_review_answers_404() {
    let state = test_state();
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let absent = StoredReviewId::new();
    let response = router(Arc::clone(&state))
        .oneshot(
            Request::post("/review")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "op": "show", "review_id": absent.to_string() })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let message = String::from_utf8_lossy(&body);
    assert_eq!(status, StatusCode::NOT_FOUND, "{message}");
    assert!(
        message.contains(&absent.to_string()),
        "the refusal must name the review: {message}"
    );
}
