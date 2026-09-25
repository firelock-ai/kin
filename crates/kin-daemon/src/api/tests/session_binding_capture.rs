// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

async fn session_capture_materialize(
    state: &Arc<DaemonState>,
    name: &str,
) -> kin_cli::commands::session_workspace::SessionWorkspaceBase {
    let session = state.layout.runs_dir().join(format!("session-{name}"));
    let response = router(Arc::clone(state))
        .oneshot(
            Request::post("/commands/session-workspace")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"session_dir":session,"strategy":null,"scope":null}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 32 * 1024)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let base: kin_cli::commands::session_workspace::SessionWorkspaceBase =
        serde_json::from_slice(&std::fs::read(session.join(".kin-session/base.json")).unwrap())
            .unwrap();
    base.validate().unwrap();
    base
}

#[tokio::test]
async fn session_binding_capture_materialization_retains_uncommitted_call_before_reconcile() {
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    waiting_admit(&state, "session capture target").await;
    // Settle this source before admitting the caller; a coherent admission
    // would already publish the dependency under test. The caller's parse is
    // refused while its bytes land and derived by the drain after, so the call
    // is live and never durable, as production leaves it until the next commit
    // or tree-moving admission.
    waiting_commit(&state, "Commit target before session capture caller").await;
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    admit_parse_live_only(&state, "caller.py", "session capture caller").await;
    let caller = waiting_entity(&state, "caller.py", "run").id;
    assert_eq!(
        live_and_durable_calls_from(&state, caller),
        (true, false),
        "the call must be live and absent from persisted authority"
    );
    let source = GraphNodeId::Entity(caller);
    let live_call = state
        .graph
        .get_all_relations_for_node(&source)
        .unwrap()
        .into_iter()
        .find(|relation| relation.src == source && relation.kind == RelationKind::Calls)
        .unwrap();
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(&state)
            .unwrap();
    let authority = context.open().unwrap();
    let lease = authority.read_authority();
    let before = lease
        .workspace_graph_snapshot(&context.workspace_id())
        .unwrap()
        .unwrap();
    assert!(
        !before.relations.contains_key(&live_call.id),
        "must be a real never-committed binding"
    );
    let roots_before = lease.roots().clone();
    let changes_before = lease.snapshot().changes.len();
    drop(lease);
    drop(authority);

    let base = session_capture_materialize(&state, "retained-binding").await;
    let authority = context.open().unwrap();
    let lease = authority.read_authority();
    let captured = lease
        .workspace_graph_snapshot(&context.workspace_id())
        .unwrap()
        .unwrap();
    assert_eq!(
        captured.relations.get(&live_call.id),
        Some(&live_call),
        "session materialization must durably capture the actual live call"
    );
    assert_eq!(
        captured.resolved_tree, before.resolved_tree,
        "capture cannot change source tree"
    );
    assert_eq!(
        lease.snapshot().changes.len(),
        changes_before,
        "capture is not a native source commit"
    );
    assert_eq!(lease.roots().generation, roots_before.generation + 1);
    assert_eq!(&base.authority_roots, lease.roots());
    assert_eq!(
        &base.source_workspace,
        lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == context.workspace_id())
            .unwrap()
    );
    let captured_roots = lease.roots().clone();
    drop(lease);
    drop(authority);
    binding_disclosure_impact(&state, caller, false, "session capture warm").await;

    let second = session_capture_materialize(&state, "already-captured").await;
    assert_eq!(
        second.authority_roots, captured_roots,
        "no redundant publication once semantics and qualification match"
    );
    assert_ne!(second.reconcile_operation_id, base.reconcile_operation_id);
    let layout = state.layout.clone();
    drop(state); // No reconcile or source commit occurs before the actual cold startup.
    let reopened = waiting_cold_start(layout).await;
    binding_disclosure_impact(
        &reopened,
        caller,
        false,
        "session capture cold before reconcile",
    )
    .await;
    let authority = context.open().unwrap();
    let lease = authority.read_authority();
    assert_eq!(lease.roots(), &captured_roots);
    let cold = lease
        .workspace_graph_snapshot(&context.workspace_id())
        .unwrap()
        .unwrap();
    assert_eq!(cold.relations.get(&live_call.id), Some(&live_call));
    assert_eq!(
        std::fs::read(repo.path().join("caller.py")).unwrap(),
        WAITING_CALLER.as_bytes()
    );
}

#[tokio::test]
async fn session_binding_capture_unknown_interval_is_durable_and_equal_unknown_is_noop() {
    for lead in [false, true] {
        let (repo, state) = mcp_lifecycle_fixture();
        std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
        waiting_admit(&state, "unknown capture target").await;
        waiting_commit(&state, "Commit target before unknown capture caller").await;
        std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
        // The caller's parse is refused while its bytes land and derived by the
        // drain after, so the call is live and never durable until the commit
        // the control makes.
        admit_parse_live_only(&state, "caller.py", "unknown capture caller").await;
        if !lead {
            waiting_commit(&state, "Establish exact durable checked source").await;
        }
        let caller = waiting_entity(&state, "caller.py", "run").id;
        assert_eq!(
            live_and_durable_calls_from(&state, caller),
            (true, !lead),
            "the call is live, and durable only once the control commits it"
        );
        let context =
            crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(&state)
                .unwrap();
        let authority = context.open().unwrap();
        let lease = authority.read_authority();
        let roots = lease.roots().clone();
        let changes = lease.snapshot().changes.len();
        let selected = lease
            .workspace_graph_snapshot(&context.workspace_id())
            .unwrap()
            .unwrap();
        assert!(selected.verified_binding_history.is_some());
        if lead {
            assert_ne!(
                selected.relations,
                state.graph.semantic_observation().relations,
                "the live-leading case must retain an actual unpublished relation"
            );
        } else {
            assert_eq!(
                selected.entities,
                state.graph.semantic_observation().entities
            );
            assert_eq!(
                selected.relations,
                state.graph.semantic_observation().relations
            );
        }
        drop(lease);
        drop(authority);
        // Model an actually unobserved interval without changing current maps.
        // Materialization must not reconstruct qualification from equal bytes.
        state.graph.invalidate_binding_history();
        let first = session_capture_materialize(&state, "unknown-captured").await;
        assert_eq!(first.authority_roots.generation, roots.generation + 1);
        assert_eq!(first.source_workspace.tree, selected.resolved_tree);
        let authority = context.open().unwrap();
        let lease = authority.read_authority();
        assert_eq!(lease.snapshot().changes.len(), changes);
        let captured = lease
            .workspace_graph_snapshot(&context.workspace_id())
            .unwrap()
            .unwrap();
        assert!(captured.verified_binding_history.is_none());
        if !lead {
            let loss = lease
                .snapshot()
                .audit_events
                .iter()
                .find(|event| event.action == "session_materialization_history_unproven")
                .expect("actual qualification-loss audit record");
            let details: serde_json::Value =
                serde_json::from_str(loss.details.as_deref().unwrap()).unwrap();
            assert_eq!(
                details["authority_roots"],
                serde_json::to_value(&roots).unwrap()
            );
            assert_eq!(
                details["workspace_id"],
                serde_json::to_value(context.workspace_id()).unwrap()
            );
            assert!(
                lease.snapshot().reviews.is_empty(),
                "materialization may not fabricate a review"
            );
        }
        assert_eq!(
            captured.entities,
            state.graph.semantic_observation().entities
        );
        assert_eq!(
            captured.relations,
            state.graph.semantic_observation().relations
        );
        drop(lease);
        drop(authority);
        let repeated = session_capture_materialize(&state, "unknown-noop").await;
        assert_eq!(repeated.authority_roots, first.authority_roots);
        let layout = state.layout.clone();
        drop(state);
        let cold = waiting_cold_start(layout).await;
        assert_eq!(
            cold.graph.binding_history_observation(),
            kin_model::BindingHistoryObservation::Unproven
        );
        let report = binding_review_call(
            &cold,
            "impact_analysis",
            json!({"entity_ids":[caller.to_string()],"include_traffic":false}),
        )
        .await;
        assert_eq!(
            report["source_derivation"]["report"]["prior_local_binding"],
            "unproven"
        );
        assert!(
            report["source_derivation"]["report"]["outstanding_local_binding_obligations"]
                .is_null()
        );
        assert_eq!(
            report["source_derivation"]["report"]["body_binding"],
            "current"
        );
        let after_cold = session_capture_materialize(&cold, "unknown-cold-noop").await;
        assert_eq!(after_cold.authority_roots, first.authority_roots);
    }
}

#[tokio::test]
async fn session_binding_capture_rejects_invalid_request_and_stale_authority_without_session() {
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "request capture source").await;
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(&state)
            .unwrap();
    let roots = context.open().unwrap().read_authority().roots().clone();
    for (name, strategy, scope) in [
        ("invalid-scope", None, Some("artifact:caller.py")),
        ("invalid-strategy", Some("symlink"), None),
    ] {
        let session = state.layout.runs_dir().join(format!("session-{name}"));
        let response = router(Arc::clone(&state))
            .oneshot(
                Request::post("/commands/session-workspace")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"session_dir":session,"strategy":strategy,"scope":scope})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!session.exists());
        assert_eq!(context.open().unwrap().read_authority().roots(), &roots);
    }
    // A real durable writer advances authority without this daemon applying it.
    let (pending, _) = binding_review_plan(&state, "intervening authority");
    let authority =
        crate::local_repository_authority::ActiveLocalRepositoryAuthority::open(&state).unwrap();
    let committed = pending.commit(&authority).unwrap();
    let session = state.layout.runs_dir().join("session-stale-capture");
    let response = router(Arc::clone(&state))
        .oneshot(
            Request::post("/commands/session-workspace")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"session_dir":session,"strategy":null,"scope":null}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(!session.exists());
    assert_eq!(
        context.open().unwrap().read_authority().roots(),
        &committed.roots_after
    );

    let request = kin_cli::commands::session_workspace::SessionWorkspaceRequest {
        session_dir: session.to_string_lossy().into_owned(),
        strategy: None,
        scope: None,
    };
    let error = kin_cli::commands::session_workspace::materialize_session_workspace_at_roots(
        &state.layout,
        &state.local_repository_authority_binding().unwrap(),
        &request,
        Some(&roots),
    )
    .unwrap_err();
    assert!(error.to_string().contains("authority changed"), "{error}");
    assert!(!session.exists());
}

#[tokio::test]
async fn session_binding_capture_transferred_equal_authority_materializes_without_upgrade() {
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "transferred capture source").await;
    waiting_commit(&state, "Commit transfer source").await;
    let authority =
        crate::local_repository_authority::ActiveLocalRepositoryAuthority::open(&state).unwrap();
    let roots = authority.manager.read_authority().roots().clone();
    let receipt = authority
        .manager
        .commit_transferred_repository_transaction(
            kin_model::RepositoryTransaction {
                schema_version: kin_model::REPOSITORY_TRANSACTION_SCHEMA_VERSION,
                operation_id: kin_model::OperationId::new(),
                repository_id: authority.repository_id.clone(),
                expected_generation: roots.generation,
                expected_roots: roots,
                actor: AuthorId::new("transferred-control"),
                reason: "unqualified transferred operation before materialization".into(),
                external_objects: vec![],
                git_authority_delta: None,
                changes: vec![],
                aliases: vec![],
                ref_mutations: vec![kin_model::RefMutation {
                    name: kin_model::RefName::branch(b"transferred-session-reference").unwrap(),
                    expected: kin_model::RefExpectation::MustNotExist,
                    new_target: Some(kin_model::RefTarget::symbolic(
                        kin_model::RefName::branch(b"main").unwrap(),
                    )),
                    policy: kin_model::RefUpdatePolicy::FastForwardOnly,
                }],
                default_ref_mutation: None,
                workspace_mutation: None,
                local_overlay_delta: None,
                merge_transaction_delta: None,
                sealed_observation: None,
                collaboration_delta: None,
            },
            None,
        )
        .unwrap();
    let layout = state.layout.clone();
    drop(authority);
    drop(state);
    let cold = waiting_cold_start(layout).await;
    assert_eq!(
        cold.graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Unproven
    );
    let base = session_capture_materialize(&cold, "transferred-equal").await;
    assert_eq!(base.authority_roots, receipt.roots_after);
    assert_eq!(
        cold.graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Unproven
    );
    let session = cold.layout.runs_dir().join("session-transferred-equal");
    assert_eq!(
        std::fs::read(session.join("caller.py")).unwrap(),
        WAITING_CALLER.as_bytes()
    );
}
