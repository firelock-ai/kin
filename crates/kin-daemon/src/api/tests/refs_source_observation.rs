// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

async fn refs_source_observation_fixture() -> (tempfile::TempDir, Arc<DaemonState>) {
    let (repo, state) = mcp_lifecycle_fixture();
    state.set_spine_disabled_for_test(true);
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    std::fs::write(
        repo.path().join("unused.py"),
        "def unused_probe():\n    return 0\n",
    )
    .unwrap();
    waiting_admit(&state, "refs targets").await;
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "refs caller").await;
    waiting_commit(&state, "Commit refs source fixture").await;
    (repo, state)
}

async fn refs_calls_through_route(
    state: &Arc<DaemonState>,
    entity: &str,
) -> kin_cli::commands::refs::RefsResponse {
    let response = router(Arc::clone(state))
        .oneshot(
            Request::post("/commands/refs")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"entity": entity, "kind": "calls"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    serde_json::from_slice(&body).unwrap()
}

async fn assert_refs_source_verdict_parity(
    state: &Arc<DaemonState>,
    expected_reason: Option<&str>,
) {
    let focal = waiting_entity(state, "unused.py", "unused_probe");
    let cli = refs_calls_through_route(state, &focal.id.to_string()).await;
    let cli_negative = cli.negative.expect("empty refs carry an absence verdict");
    let mcp = mcp_call(
        router(Arc::clone(state)),
        "find_references",
        json!({"entity_id": focal.id.to_string(), "relation_kinds": ["calls"], "answer_only": false}),
    )
    .await;
    assert_ne!(mcp.is_error, Some(true), "{}", mcp_result_text(&mcp));
    let envelope = kin_mcp::Envelope::daemon().with_health(&daemon_health_snapshot(state).await);
    let mcp = tool_result_payload(&kin_mcp::envelope::finalize(
        mcp,
        envelope,
        "find_references",
    ));
    for negative in [&cli_negative, &mcp["negative"]] {
        assert_eq!(
            negative["safe_to_conclude_absent"],
            expected_reason.is_none(),
            "CLI: {cli_negative}; MCP: {mcp}"
        );
        if let Some(reason) = expected_reason {
            assert!(
                negative["trust_reason"].as_str().unwrap().contains(reason),
                "{negative}"
            );
        }
    }
    assert_eq!(
        cli.lines.join("\n").contains("Kin cannot rule out"),
        expected_reason.is_some(),
        "{:?}",
        cli.lines
    );
}

#[tokio::test]
async fn refs_endpoint_qualifies_local_binding_like_mcp_through_enrichment() {
    let _readiness = kin_mcp::edge_coverage::test_support::scoped_language_servers(&[
        kin_model::LanguageId::Python,
    ]);
    let (repo, state) = refs_source_observation_fixture().await;
    assert_refs_source_verdict_parity(&state, None).await;

    std::fs::remove_file(repo.path().join("local.py")).unwrap();
    waiting_admit(&state, "refs remove local target").await;
    assert_refs_source_verdict_parity(&state, Some("local_binding_outstanding")).await;

    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    waiting_admit(&state, "refs restore local target").await;
    waiting_commit(&state, "Commit restored refs target").await;
    assert_refs_source_verdict_parity(&state, None).await;

    let caller = waiting_entity(&state, "caller.py", "run");
    let target = waiting_entity(&state, "local.py", "work");
    crate::daemon::install_lsp_relations(
        &state,
        &[kin_model::Relation {
            id: kin_model::RelationId::new(),
            kind: kin_model::RelationKind::References,
            src: kin_model::GraphNodeId::Entity(caller.id),
            dst: kin_model::GraphNodeId::Entity(target.id),
            confidence: 1.0,
            origin: kin_model::relation::RelationOrigin::Lsp,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }],
    );
    assert_eq!(binding_observation_label(&state), "unproven");
    // No wait for enrichment to settle: both clients must refuse immediately.
    assert_refs_source_verdict_parity(&state, Some("local_binding_unproven")).await;
    let populated = refs_calls_through_route(&state, &target.id.to_string()).await;
    assert!(populated.negative.is_none());
    assert!(populated.lines.join("\n").contains("run"));
}
