// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A merge after a commit whose language-server enrichment landed later.
//!
//! After a commit the daemon's background pass derives relations from the
//! committed tree and publishes them into the workspace's semantic overlay, so
//! they survive a restart. `kin merge` used to read that overlay as uncommitted
//! work and refuse with 409, and the only way past it was a commit holding no
//! entity and no file, which stays in history. Two stranger runs hit it three
//! times in an hour.

use super::*;

const DECLARATIONS: &[u8] =
    b"def caller():\n    return callee()\n\n\ndef callee():\n    return 2\n";

fn workspace_of(state: &DaemonState) -> kin_model::WorkspaceState {
    let authority = ActiveApiRepositoryAuthority::open(state).unwrap();
    let lease = authority.manager.read_authority();
    lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == authority.workspace_id)
        .cloned()
        .unwrap()
}

fn change_of(state: &DaemonState, id: &SemanticChangeId) -> kin_model::SemanticChange {
    let authority = ActiveApiRepositoryAuthority::open(state).unwrap();
    let lease = authority.manager.read_authority();
    lease
        .snapshot()
        .changes
        .values()
        .find(|change| change.id == *id)
        .cloned()
        .unwrap_or_else(|| panic!("change {id} is not in repository authority"))
}

fn declared(state: &DaemonState, name: &str) -> kin_model::Entity {
    state
        .graph
        .query_entities(&kin_model::EntityFilter {
            name_pattern: Some(name.to_string()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|entity| entity.name == name)
        .unwrap_or_else(|| panic!("the fixture commit did not publish {name}"))
}

/// Do what the enrichment pass does: install a language-server edge from
/// `caller` to `callee` in the live graph and flush it into the workspace's
/// semantic overlay. Returns the edge's id.
fn enrich_caller_to_callee(state: &Arc<DaemonState>) -> kin_model::RelationId {
    let edge = kin_model::Relation {
        id: kin_model::RelationId::new(),
        kind: kin_model::RelationKind::Calls,
        src: GraphNodeId::Entity(declared(state, "caller").id),
        dst: GraphNodeId::Entity(declared(state, "callee").id),
        confidence: 1.0,
        origin: kin_model::RelationOrigin::Lsp,
        created_in: None,
        import_source: None,
        evidence: Vec::new(),
    };
    let relations_before = state.graph.relation_count();
    let written = crate::daemon::install_lsp_relations(state, std::slice::from_ref(&edge));
    assert_eq!(
        state.graph.relation_count(),
        relations_before + 1,
        "the live graph must take the edge: {written:?}"
    );
    assert_eq!(
        state.save_snapshot_reporting_enrichment().unwrap(),
        crate::state::EnrichmentFlush::Proceeded
    );

    // The exact shape the merge used to refuse. Without it this test would
    // grade a clean workspace and pass on the old gate too.
    let enriched = workspace_of(state);
    assert!(
        enriched
            .semantic_overlay
            .is_language_server_enrichment_only(),
        "the flush must publish the edge into the overlay: {:?}",
        enriched.semantic_overlay
    );
    assert!(
        enriched
            .semantic_overlay
            .relation_deltas()
            .iter()
            .any(|delta| delta.target_id() == edge.id),
        "the overlay must hold this edge: {:?}",
        enriched.semantic_overlay
    );
    assert_eq!(
        enriched.base_tree_hash,
        Some(enriched.tree_hash),
        "enrichment moves no file"
    );
    assert!(enriched.is_dirty());
    assert!(!enriched.holds_uncommitted_work());
    edge.id
}

/// Commit two declarations, then enrich them the way the pass does after a
/// commit.
async fn commit_then_enrich(
    state: &Arc<DaemonState>,
    repository: &std::path::Path,
) -> SemanticChangeId {
    let app = router(Arc::clone(state));
    std::fs::write(repository.join("enriched.py"), DECLARATIONS).unwrap();
    let committed = commit_through_api(
        &app,
        kin_model::OperationId::new(),
        "add two declarations a language server relates",
    )
    .await;
    assert!(
        workspace_of(state).semantic_overlay.is_empty(),
        "the commit itself must leave nothing pending, or this grades the wrong state"
    );
    enrich_caller_to_callee(state);
    committed
}

async fn merge_through_api(
    state: &Arc<DaemonState>,
    source: &[u8],
) -> (StatusCode, serde_json::Value) {
    let request = kin_cli::commands::merge::MergeRequest {
        source: kin_model::RefName::branch(source).unwrap(),
        operation_id: kin_model::OperationId::new(),
        actor: AuthorId::new("merge-after-enrichment"),
    };
    let response = router(Arc::clone(state))
        .oneshot(
            Request::post("/commands/merge")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) })),
    )
}

#[tokio::test]
#[serial_test::serial(repository_commit)]
async fn a_merge_after_post_commit_enrichment_publishes_and_records_no_content_free_change() {
    let (state, layout, repository, main_change, feature_change) =
        universal_branch_test_state("merge-after-enrichment");
    // Reopened as a daemon that can enrich, with a channel this test reads the
    // merge's sweep request off.
    drop(state);
    let (sweep_tx, mut sweep_rx) = tokio::sync::mpsc::channel(64);
    let mut state = DaemonState::open(layout).unwrap();
    state.lsp_enrichment_tx = Some(sweep_tx);
    let state = Arc::new(state);
    let committed = commit_then_enrich(&state, &repository).await;
    // The pass that published the edge also records the file as enriched, and
    // a sweep skips a file it has recorded.
    crate::daemon::mark_files_enriched(
        &state,
        &["enriched.py".to_string()],
        crate::daemon::current_marker_epoch(&state),
    );
    assert!(crate::daemon::file_already_enriched(&state, "enriched.py"));
    while sweep_rx.try_recv().is_ok() {}

    let (status, body) = merge_through_api(&state, b"feature").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a merge must not refuse on the enrichment Kin published after a commit: {body}"
    );
    let merged: kin_cli::commands::merge::MergeResponse = serde_json::from_value(body).unwrap();
    let report = merged.report.unwrap();
    assert_eq!(
        report.outcome,
        kin_cli::commands::merge::MergeOutcome::Merged
    );
    let merge_change = report.merge_change.unwrap();

    // History is the commit, then the merge of it with the feature head. No
    // change sits between them, so nothing in history records the enrichment
    // on its own: the old remedy put a change there holding no entity and no
    // file.
    assert_eq!(branch_change(&state), merge_change);
    let merge = change_of(&state, &merge_change);
    assert_eq!(merge.parents, vec![committed, feature_change]);
    let commit = change_of(&state, &committed);
    assert_eq!(commit.parents, vec![main_change]);
    for change in [&commit, &merge] {
        assert!(
            !change.entity_deltas.is_empty() || !change.tree_deltas.is_empty(),
            "change {} records neither an entity nor a file",
            change.id
        );
    }

    // The workspace sits on the merge with nothing left over. The enrichment
    // the overlay held belonged to the pre-merge tree; the merge queues the
    // pass that derives it again for the merged one.
    let after = workspace_of(&state);
    assert_eq!(
        after.base_target,
        Some(kin_model::RefTarget::change(merge_change))
    );
    assert!(
        after.semantic_overlay.is_empty(),
        "{:?}",
        after.semantic_overlay
    );
    assert!(!after.is_dirty());
    assert_eq!(
        std::fs::read(repository.join("selected/Dockerfile")).unwrap(),
        b"FROM scratch\n",
        "the feature branch's files must reach the working copy"
    );
    assert_eq!(
        std::fs::read(repository.join("enriched.py")).unwrap(),
        DECLARATIONS
    );

    // The edge is rebuilt, not lost. The merge asked for a sweep and retired
    // the marker that would have made the sweep skip the file.
    let mut asked_for_a_sweep = false;
    while let Ok(message) = sweep_rx.try_recv() {
        asked_for_a_sweep |= matches!(message, crate::state::LspEnrichmentMessage::Sweep);
    }
    assert!(asked_for_a_sweep, "the merge must queue the sweep");
    assert!(
        !crate::daemon::file_already_enriched(&state, "enriched.py"),
        "the merge must retire the marker, or the sweep skips the file"
    );
    // What that sweep writes when it runs lands as derived state again, and
    // the next merge still reads the workspace as holding no uncommitted work.
    enrich_caller_to_callee(&state);
}

/// The control. Work nobody has committed still refuses, and the refusal names
/// committing, the one remedy that carries the work through the merge.
#[tokio::test]
#[serial_test::serial(repository_commit)]
async fn a_merge_still_refuses_uncommitted_work_beside_the_enrichment() {
    let (state, _layout, repository, _main_change, _feature_change) =
        universal_branch_test_state("merge-refuses-real-work");
    commit_then_enrich(&state, &repository).await;
    let edited = b"def caller():\n    return callee() + 1\n\n\ndef callee():\n    return 2\n";
    std::fs::write(repository.join("enriched.py"), edited).unwrap();
    admit_through_api(&router(Arc::clone(&state))).await;
    let pending = workspace_of(&state);
    assert!(
        pending.holds_uncommitted_work(),
        "the edit must be admitted"
    );
    let generation = pending.generation;

    let (status, body) = merge_through_api(&state, b"feature").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["refused_before_write"], true, "{body}");
    let message = body.to_string();
    assert!(
        message.contains("a working tree that has moved off its base change"),
        "{message}"
    );
    // The guidance names what the workspace holds: "it" for a moved tree
    // alone, "them" once the edit's parse is also a pending semantic overlay,
    // as it is when the edit's parse publishes with its bytes.
    assert!(
        message.contains("commit it with `kin commit`")
            || message.contains("commit them with `kin commit`"),
        "{message}"
    );
    assert_eq!(
        workspace_of(&state),
        pending,
        "a refused merge moves no authority"
    );
    assert_eq!(
        std::fs::read(repository.join("enriched.py")).unwrap(),
        edited,
        "a refused merge leaves the working tree alone"
    );
    assert!(
        !message.contains("kin stash"),
        "a stash taken to clear the way cannot be popped onto the merged base: {message}"
    );
    assert_eq!(
        workspace_of(&state).generation,
        generation,
        "a refused merge moves nothing"
    );
}
