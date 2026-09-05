// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;

fn sole_entity(state: &DaemonState, path: &str) -> Entity {
    let entities = state
        .graph
        .query_entities(&kin_db::EntityFilter {
            file_path: Some(FilePathId::new(path)),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        entities.len(),
        1,
        "one parsed entity at {path}: {entities:?}"
    );
    entities[0].clone()
}

fn assert_moved_identity(
    state: &DaemonState,
    entity: &Entity,
    artifact: kin_model::ArtifactId,
    incoming: &kin_model::Relation,
    deleted: &Entity,
) {
    let moved = state
        .graph
        .get_entity(&entity.id)
        .unwrap()
        .expect("session move must preserve the original entity identity");
    assert_eq!(moved.file_origin, Some(FilePathId::new("new.rs")));
    assert_eq!(moved.span.as_ref().unwrap().file, FilePathId::new("new.rs"));
    assert_eq!(sole_entity(state, "new.rs").id, entity.id);
    assert_eq!(
        state
            .graph
            .resolved_tree()
            .artifact_at_path(&RepoPath::from_utf8("new.rs").unwrap())
            .unwrap()
            .artifact_id,
        artifact,
        "the move must preserve artifact identity"
    );
    assert!(state
        .graph
        .resolved_tree()
        .artifact_at_path(&RepoPath::from_utf8("old.rs").unwrap())
        .is_none());
    assert!(
        state.graph.get_entity(&deleted.id).unwrap().is_none(),
        "a true deletion must still retire its entity"
    );
    assert!(
        state
            .graph
            .resolved_tree()
            .artifact_at_path(&RepoPath::from_utf8("earlier.rs").unwrap())
            .is_none(),
        "replay must not resurrect a deletion already in the retained overlay"
    );
    assert_eq!(
        state
            .graph
            .get_all_relations_for_node(&incoming.dst)
            .unwrap()
            .iter()
            .find(|edge| edge.id == incoming.id),
        Some(incoming),
        "the incoming edge must keep its identity and endpoints"
    );
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn session_move_preserves_path_named_module_identity() {
    let repo = tempfile::tempdir().unwrap();
    let layout = kin_core::init(repo.path()).unwrap().layout;
    let state = Arc::new(DaemonState::open(layout.clone()).unwrap());
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    std::fs::write(repo.path().join("old.py"), "def moved():\n    return 7\n").unwrap();
    let app = router(Arc::clone(&state));
    commit_through_api(&app, kin_model::OperationId::new(), "publish Python module").await;
    let before = state
        .graph
        .query_entities(&kin_db::EntityFilter {
            file_path: Some(FilePathId::new("old.py")),
            ..Default::default()
        })
        .unwrap();
    assert!(
        before
            .iter()
            .any(|entity| entity.kind == EntityKind::Module),
        "the fixture must include the path-named module"
    );
    assert!(before
        .iter()
        .any(|entity| entity.kind == EntityKind::Function));
    let session = layout.runs_dir().join("session-module-identity");
    materialize_session_through_api(&app, &session).await;
    std::fs::rename(session.join("old.py"), session.join("new.py")).unwrap();
    reconcile_session_through_api(&app, &session).await;
    for original in &before {
        let moved = state
            .graph
            .get_entity(&original.id)
            .unwrap()
            .unwrap_or_else(|| panic!("the move lost {:?} {}", original.kind, original.name));
        assert_eq!(moved.file_origin, Some(FilePathId::new("new.py")));
    }
    reconcile_session_through_api(&app, &session).await;
    drop(app);
    drop(state);
    let state = Arc::new(DaemonState::open(layout.clone()).unwrap());
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    crate::loop_runner::drain_semantic_debt(&state)
        .await
        .unwrap();
    let app = router(Arc::clone(&state));
    commit_through_api(&app, kin_model::OperationId::new(), "publish module move").await;
    drop(app);
    drop(state);
    let cold = DaemonState::open(layout).unwrap();
    for original in &before {
        let moved = cold
            .graph
            .get_entity(&original.id)
            .unwrap()
            .expect("module identity must survive cold commit history");
        assert_eq!(moved.file_origin, Some(FilePathId::new("new.py")));
        assert_eq!(moved.span.as_ref().unwrap().file, FilePathId::new("new.py"));
        if original.kind == EntityKind::Module {
            assert_eq!(
                moved.name, "new",
                "the module name must follow the real parser"
            );
        }
    }
}

async fn assert_session_refused_without_advancing(
    state: &Arc<DaemonState>,
    app: &axum::Router,
    session: &PathBuf,
) {
    let roots = ActiveApiRepositoryAuthority::open(state)
        .unwrap()
        .manager
        .read_authority()
        .roots()
        .clone();
    let response = app
        .clone()
        .oneshot(
            Request::post("/reconcile")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"session_dir": session, "confirm_mass_deletion": false}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 128 * 1024)
        .await
        .unwrap();
    assert!(
        status.is_client_error(),
        "changed or superseded session must be refused: {status} {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        ActiveApiRepositoryAuthority::open(state)
            .unwrap()
            .manager
            .read_authority()
            .roots(),
        &roots
    );
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn session_move_preserves_identity_through_admission_commit_and_two_cold_reopens() {
    let repo = tempfile::tempdir().unwrap();
    let layout = kin_core::init(repo.path()).unwrap().layout;
    let state = Arc::new(DaemonState::open(layout.clone()).unwrap());
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    for (path, body) in [
        ("caller.rs", "pub fn caller() -> u32 { 1 }\n"),
        ("old.rs", "pub fn moved() -> u32 { 2 }\n"),
        ("deleted.rs", "pub fn deleted() -> u32 { 3 }\n"),
        ("earlier.rs", "pub fn earlier() -> u32 { 4 }\n"),
    ] {
        std::fs::write(repo.path().join(path), body).unwrap();
    }
    let app = router(Arc::clone(&state));
    commit_through_api(&app, kin_model::OperationId::new(), "publish source").await;
    let original = sole_entity(&state, "old.rs");
    let caller = sole_entity(&state, "caller.rs");
    let deleted = sole_entity(&state, "deleted.rs");
    let artifact = state
        .graph
        .resolved_tree()
        .artifact_at_path(&RepoPath::from_utf8("old.rs").unwrap())
        .unwrap()
        .artifact_id;
    let incoming = kin_model::Relation {
        id: kin_model::RelationId::new(),
        kind: RelationKind::Calls,
        src: kin_model::GraphNodeId::Entity(caller.id),
        dst: kin_model::GraphNodeId::Entity(original.id),
        confidence: 1.0,
        origin: kin_model::RelationOrigin::Manual,
        created_in: None,
        import_source: None,
        evidence: Vec::new(),
    };
    state
        .graph
        .apply_transaction_delta(&TransactionDelta {
            relation_deltas: vec![kin_model::RelationDelta::Added {
                new: incoming.clone(),
            }],
            ..Default::default()
        })
        .unwrap();
    commit_through_api(&app, kin_model::OperationId::new(), "publish incoming edge").await;
    assert!(state
        .graph
        .get_all_relations_for_node(&incoming.dst)
        .unwrap()
        .contains(&incoming));

    let earlier = layout.runs_dir().join("session-prior-deletion");
    materialize_session_through_api(&app, &earlier).await;
    std::fs::remove_file(earlier.join("earlier.rs")).unwrap();
    reconcile_session_through_api(&app, &earlier).await;

    let session_dir = layout.root().join("runs/session-move-identity");
    materialize_session_through_api(&app, &session_dir).await;
    std::fs::rename(session_dir.join("old.rs"), session_dir.join("new.rs")).unwrap();
    std::fs::remove_file(session_dir.join("deleted.rs")).unwrap();
    let summary = reconcile_session_through_api(&app, &session_dir).await;
    eprintln!(
        "real session move: added={} modified={} removed={}",
        summary.added, summary.modified, summary.removed
    );
    assert_moved_identity(&state, &original, artifact, &incoming, &deleted);

    let original_body = std::fs::read(session_dir.join("new.rs")).unwrap();
    std::fs::write(session_dir.join("new.rs"), b"pub fn moved() -> u32 { 9 }\n").unwrap();
    assert_session_refused_without_advancing(&state, &app, &session_dir).await;
    std::fs::write(session_dir.join("new.rs"), original_body).unwrap();
    assert_eq!(
        (summary.added, summary.modified, summary.removed),
        (0, 1, 1)
    );
    assert_eq!(sole_entity(&state, "caller.rs").id, caller.id);

    let replay = reconcile_session_through_api(&app, &session_dir).await;
    assert!(
        replay.idempotent_replay,
        "the identical retained move must recover its original receipt"
    );
    assert_eq!(replay.authority_generation, summary.authority_generation);
    assert_moved_identity(&state, &original, artifact, &incoming, &deleted);

    drop(app);
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout.clone()).unwrap());
    reopened
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert_moved_identity(&reopened, &original, artifact, &incoming, &deleted);
    crate::loop_runner::drain_semantic_debt(&reopened)
        .await
        .unwrap();
    assert_moved_identity(&reopened, &original, artifact, &incoming, &deleted);
    let app = router(Arc::clone(&reopened));
    commit_through_api(&app, kin_model::OperationId::new(), "commit session move").await;
    assert_moved_identity(&reopened, &original, artifact, &incoming, &deleted);
    assert_session_refused_without_advancing(&reopened, &app, &session_dir).await;
    drop(app);
    drop(reopened);
    let cold = Arc::new(DaemonState::open(layout).unwrap());
    assert_moved_identity(&cold, &original, artifact, &incoming, &deleted);
}
