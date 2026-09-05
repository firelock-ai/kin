// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#![cfg(unix)]

use super::*;
use anyhow::Result;
use kin_cli::commands::reconcile::{observe_session_workspace, SessionReconcileObservation};
use kin_cli::commands::session_workspace::SessionWorkspaceBase;
use kin_model::TreeDelta;

async fn retained_fixture() -> (
    tempfile::TempDir,
    Arc<DaemonState>,
    PathBuf,
    SessionWorkspaceBase,
) {
    let repo = tempfile::tempdir().unwrap();
    let layout = kin_core::init(repo.path()).unwrap().layout;
    let state = Arc::new(DaemonState::open(layout).unwrap());
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    std::fs::write(repo.path().join("old.rs"), b"pub fn moved() {}\n").unwrap();
    std::fs::write(repo.path().join("keep.rs"), b"pub fn keep() {}\n").unwrap();
    let app = router(Arc::clone(&state));
    commit_through_api(
        &app,
        kin_model::OperationId::new(),
        "admit identity fixture",
    )
    .await;
    let session = state.layout.runs_dir().join("session-identity");
    materialize_session_through_api(&app, &session).await;
    let base =
        serde_json::from_slice(&std::fs::read(session.join(".kin-session/base.json")).unwrap())
            .unwrap();
    (repo, state, session, base)
}

fn observe(state: &DaemonState, session: &std::path::Path) -> Result<SessionReconcileObservation> {
    let binding = state.local_repository_authority_binding()?;
    observe_session_workspace(
        &state.layout,
        &binding,
        session,
        state.blobs.as_ref(),
        false,
    )
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn session_identity_matches_unique_move_and_preserves_unchanged_path() {
    let (_repo, layout, session, base) = retained_fixture().await;
    std::fs::rename(session.join("old.rs"), session.join("new.rs")).unwrap();
    let observation = observe(&layout, &session).unwrap();
    let before = base
        .source_workspace
        .tree
        .artifact_at_path(&RepoPath::from_utf8("old.rs").unwrap())
        .unwrap();
    let moved = observation
        .desired_tree()
        .artifact_at_path(&RepoPath::from_utf8("new.rs").unwrap())
        .unwrap();
    assert_eq!(
        moved.artifact_id, before.artifact_id,
        "a retained-scanner move must keep identity"
    );
    assert!(matches!(observation.deltas(), [TreeDelta::Updated { .. }]));
    let keep = RepoPath::from_utf8("keep.rs").unwrap();
    assert_eq!(
        observation.desired_tree().artifact_at_path(&keep),
        base.source_workspace.tree.artifact_at_path(&keep)
    );
    assert_eq!(
        observe(&layout, &session).unwrap().desired_tree(),
        observation.desired_tree()
    );
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn session_identity_refuses_ambiguous_duplicate_destinations() {
    let (_repo, layout, session, _base) = retained_fixture().await;
    std::fs::rename(session.join("old.rs"), session.join("new.rs")).unwrap();
    std::fs::copy(session.join("new.rs"), session.join("duplicate.rs")).unwrap();
    let error = observe(&layout, &session)
        .err()
        .expect("two identical destinations must not guess a moved identity");
    assert!(
        error
            .to_string()
            .contains("ambiguous repository identity transition"),
        "{error:#}"
    );
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn session_identity_preserves_changed_path_and_keeps_unmatched_addition_distinct() {
    let (_repo, layout, session, base) = retained_fixture().await;
    std::fs::write(
        session.join("keep.rs"),
        b"pub fn keep() { let edited = 1; }\n",
    )
    .unwrap();
    std::fs::remove_file(session.join("old.rs")).unwrap();
    std::fs::write(session.join("new.rs"), b"pub fn different() {}\n").unwrap();
    let observation = observe(&layout, &session).unwrap();
    let keep = RepoPath::from_utf8("keep.rs").unwrap();
    assert_eq!(
        observation
            .desired_tree()
            .artifact_at_path(&keep)
            .unwrap()
            .artifact_id,
        base.source_workspace
            .tree
            .artifact_at_path(&keep)
            .unwrap()
            .artifact_id
    );
    let old = base
        .source_workspace
        .tree
        .artifact_at_path(&RepoPath::from_utf8("old.rs").unwrap())
        .unwrap();
    assert!(
        observation.desired_tree().get(&old.artifact_id).is_none(),
        "unmatched deletion must not become a guessed move"
    );
    let new_path = RepoPath::from_utf8("new.rs").unwrap();
    assert_ne!(
        observation
            .desired_tree()
            .artifact_at_path(&new_path)
            .unwrap()
            .artifact_id,
        old.artifact_id
    );
    assert_eq!(
        observe(&layout, &session).unwrap().desired_tree(),
        observation.desired_tree(),
        "additions must remain retry-stable"
    );
}
