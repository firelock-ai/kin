// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Closing an unchanged session after repository authority moved on.
//
// A session projection is a copy. When a session's only change lands through a
// guarded entity mutation, or another writer commits while the projection sits
// untouched, the projection holds nothing to admit and its base is authentic
// history that is no longer current. Closing it is a no-op: success, and no
// commit, generation, prepared publication or live graph rewrite.

/// Current roots and workspace, read through a fresh open so a commit made
/// through any other manager is visible.
fn closeout_authority(state: &DaemonState) -> (kin_model::RootBundle, kin_model::WorkspaceState) {
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)
            .unwrap();
    let authority = context.open().unwrap();
    let lease = authority.read_authority();
    let roots = lease.roots().clone();
    let workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == context.workspace_id())
        .unwrap()
        .clone();
    (roots, workspace)
}

async fn closeout_reconcile(
    state: &Arc<DaemonState>,
    session_dir: &std::path::Path,
) -> (StatusCode, Vec<u8>) {
    let response = router(Arc::clone(state))
        .oneshot(
            Request::post("/reconcile")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "session_dir": session_dir.display().to_string(),
                        "confirm_mass_deletion": false
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 128 * 1024)
        .await
        .unwrap()
        .to_vec();
    (status, body)
}

/// The accepted half of `reconcile_rejects_control_aliases_special_members_and_stale_bases`:
/// the same fixture, with the projection left unchanged while other writers
/// advance authority, now closes as a no-op instead of refusing with 409.
///
/// An operation that never touches the workspace lands first, so the history
/// proof has to walk past it to the first operation that does. The summary
/// reports current generations, claims no change and no replay, and authority,
/// the live graph and prepared publication state stay exactly as the other
/// writers left them.
#[tokio::test]
async fn reconcile_closes_an_unchanged_session_after_other_writers_as_a_no_op() {
    let state = test_state();
    install_repository_file(&state, "README.md", b"exact base\n");
    // Fixture setup committed directly; use the real reopened authority
    // cursor before entering the guarded session materialization route.
    let state = waiting_cold_start(state.layout.clone()).await;
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let singleton = session_runtime_lock(&state);
    let _runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();

    let base = session_capture_materialize(&state, "unchanged-after-writers").await;
    let session = state
        .layout
        .runs_dir()
        .join("session-unchanged-after-writers");
    let projected = std::fs::read(session.join("README.md")).unwrap();

    let tag = kin_cli::commands::tag::TagRequest {
        name: kin_model::RefName::tag("closeout-unrelated").unwrap(),
        require_proof: false,
        require_approval: false,
        force: false,
        snapshot: false,
        operation_id: kin_model::OperationId::new(),
        actor: kin_model::AuthorId::new("closeout-test"),
    };
    let tagged = router(Arc::clone(&state))
        .oneshot(
            Request::post("/commands/tag")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&tag).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = tagged.status();
    let body = axum::body::to_bytes(tagged.into_body(), 128 * 1024)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    install_repository_file(&state, "new-authority.txt", b"authority moved\n");

    {
        let context =
            crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(&state)
                .unwrap();
        let authority = context.open().unwrap();
        let lease = authority.read_authority();
        let log = &lease.metadata().operation_log;
        let first_later = log
            .iter()
            .position(|operation| operation.roots_before == base.authority_roots)
            .expect("the session base roots are in operation history");
        assert!(
            log[first_later].workspace_mutation.is_none(),
            "an operation that leaves the workspace alone must come first"
        );
        assert!(
            log[first_later + 1..].iter().any(|operation| operation
                .workspace_mutation
                .as_ref()
                .is_some_and(
                    |mutation| mutation.workspace_id == base.source_workspace.workspace_id
                )),
            "a later operation must move the session's workspace"
        );
    }
    let (roots, workspace) = closeout_authority(&state);
    assert_ne!(
        workspace, base.source_workspace,
        "another writer must have moved the workspace"
    );
    let live_tree = state.graph.resolved_tree();

    let (status, body) = closeout_reconcile(&state, &session).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let summary: kin_cli::commands::reconcile::ReconcileSummary =
        serde_json::from_slice(&body).unwrap();
    assert!(!summary.changed);
    assert!(!summary.idempotent_replay);
    assert_eq!(
        (summary.added, summary.modified, summary.removed),
        (0, 0, 0)
    );
    assert!(summary.changes.is_empty());
    assert_eq!(summary.operation_id, base.reconcile_operation_id);
    assert_eq!(
        summary.authority_generation, roots.generation,
        "an unchanged close reports current authority, not the session's snapshot"
    );
    assert_eq!(summary.workspace_generation, workspace.generation);

    assert_eq!(
        closeout_authority(&state),
        (roots, workspace),
        "an unchanged close commits nothing"
    );
    assert_eq!(
        state.graph.resolved_tree(),
        live_tree,
        "an unchanged close rewrites no live graph"
    );
    let authority =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(&state)
            .unwrap()
            .open()
            .unwrap();
    assert!(authority
        .active_prepared_session_publication()
        .unwrap()
        .is_none());
    assert!(authority
        .load_prepared_session_publication(base.reconcile_operation_id)
        .unwrap()
        .is_none());
    assert!(!authority
        .read_authority()
        .metadata()
        .receipts
        .iter()
        .any(|receipt| receipt.operation_id == base.reconcile_operation_id));
    assert_eq!(
        std::fs::read(session.join("README.md")).unwrap(),
        projected,
        "the daemon neither writes nor disposes the projection; the closing client disposes it"
    );
}

/// `kin with --semantic-only` changes code only through guarded entity
/// mutation, which commits straight to repository authority and never writes
/// the session projection. Closing that session through the real `kin with`
/// closeout succeeds, disposes the projection, and leaves the mutation
/// authoritative with nothing further committed. Before, closeout refused with
/// 409 and kept the unchanged projection.
#[tokio::test]
#[serial_test::serial]
async fn kin_with_closes_a_session_whose_only_change_landed_through_kin_mutate() {
    let (_dir, state, source) = source_base_fixture().await;
    let singleton = session_runtime_lock(&state);
    let _runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(state.clone());
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let _daemon_url =
        kin_core::test_env::EnvVarGuard::set("KIN_DAEMON_URL", format!("http://{addr}"));

    let projection = kin_cli::commands::session_run::materialize(state.layout.clone(), None, None)
        .await
        .expect("materialize a session projection through the daemon");
    let session_dir = state.layout.runs_dir().join(projection.name());
    let projected_path = projection.root().join("src/value.rs");
    let projected = std::fs::read_to_string(&projected_path).unwrap();
    assert!(
        projected.contains("pub fn value() -> u8 { 1 }"),
        "{projected}"
    );

    let session = mcp_test_session(&state);
    let mutated = mutate_http(
        &state,
        "kin_mutate",
        serde_json::json!({
            "session_id": session,
            "request_id": "closeout-guarded-edit",
            "operations": [source_base_operation(&source)],
            "summary": "Change the value through Kin rather than the projection"
        }),
        &session,
    )
    .await;
    assert_eq!(mutation_receipt(&mutated)["ops_applied"], 1);
    assert_eq!(
        std::fs::read_to_string(&projected_path).unwrap(),
        projected,
        "a guarded mutation never writes the session projection"
    );
    let (roots, workspace) = closeout_authority(&state);
    let live_tree = state.graph.resolved_tree();

    kin_cli::commands::session_run::close(
        &projection,
        kin_cli::commands::session_run::SessionExit { code: 0 },
        kin_cli::commands::session_run::SessionCloseout::Reconcile,
    )
    .await
    .expect("close an unchanged session after its own guarded mutation");

    assert!(
        !session_dir.exists(),
        "a closed unchanged session projection is disposed"
    );
    assert_eq!(
        closeout_authority(&state),
        (roots, workspace),
        "closing commits nothing further"
    );
    assert_eq!(
        state.graph.resolved_tree(),
        live_tree,
        "closing rewrites no live graph"
    );
    let current = mcp_call(
        router(Arc::clone(&state)),
        "get_entity_source",
        serde_json::json!({ "entity_id": source["id"] }),
    )
    .await;
    assert_eq!(
        tool_result_payload(&current)["body"],
        SOURCE_BASE_EDIT,
        "the guarded edit stays authoritative"
    );

    server.abort();
    let _ = server.await;
}
