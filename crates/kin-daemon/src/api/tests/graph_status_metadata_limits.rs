// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[tokio::test]
async fn enrichment_status_detail_limit_preserves_fenced_counters_and_targeted_rows() {
    let mut state = test_state();
    let mut snapshot = state.graph.to_snapshot();
    // This synthetic larger inventory is not the authority snapshot whose
    // exact runtime binding-history capability the fixture opened with.
    snapshot.verified_binding_history = None;
    let entity = test_entity("status_target", "src/target.py");
    snapshot.entities.insert(entity.id, entity);
    snapshot.resolved_tree = kin_model::ResolvedTree::from_artifacts(
        std::iter::once("src/target.py".to_owned())
            .chain((0..10_000).map(|index| format!("unrelated/{index:05}.py")))
            .map(|path| {
                kin_model::ResolvedArtifact::new(
                    kin_model::ArtifactId::new(),
                    kin_model::RepoPath::from_utf8(path).unwrap(),
                    kin_model::TreeEntry::blob(kin_model::Hash256::from_bytes([3; 32]), false),
                )
            }),
    )
    .unwrap();
    Arc::get_mut(&mut state).unwrap().graph =
        Arc::new(kin_db::InMemoryGraph::from_snapshot_without_text_index(snapshot).unwrap());
    let graph = Arc::clone(&state.graph);
    let calls = std::cell::Cell::new(0);
    let result = mcp_graph_status_snapshot_after_capture(
        &state,
        None,
        &graph,
        RequestGraphAuthority::Head,
        kin_mcp::handlers::entities::GraphStatusScope::Head,
        &kin_mcp::status_pages::StatusRequest::default(),
        |_| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                graph
                    .upsert_entity(&test_entity("later", "src/later.py"))
                    .unwrap();
            }
        },
    )
    .await
    .unwrap();
    assert!(
        calls.get() >= 2,
        "limit disclosure must still cross the truth fence"
    );
    let report = parse_graph_status(&result);
    assert_eq!(report.entity_count, graph.entity_count());
    assert_eq!(report.entity_count, 2);
    assert!(!report.completion_attested);
    assert!(
        report.call_sites.is_none(),
        "no partial global tally on a failed scan"
    );
    let detail = report.enrichment.unwrap();
    assert_eq!(detail["unavailable"]["limit_kind"], "bytes");
    assert_eq!(detail["unavailable"]["limit"], 8 * 1024 * 1024);
    assert_eq!(detail["truth_epoch"], graph.truth_epoch());
    assert!(detail.get("page").is_none());

    let app = router(Arc::clone(&state));
    let raw = mcp_call(app.clone(), "kin_graph_status", json!({"max_chars":60000})).await;
    assert_ne!(raw.is_error, Some(true));
    let body: serde_json::Value = serde_json::from_str(&mcp_result_text(&raw)).unwrap();
    assert_eq!(body["entity_count"], 2);
    assert_eq!(body["enrichment"]["status"], "bounded");
    // The daemon owns this selected report; stdio adds the safety envelope
    // through the shared finalizer. Qualify the actual routed payload there.
    let finalized = kin_mcp::envelope::finalize(
        raw,
        kin_mcp::envelope::Envelope::daemon(),
        "kin_graph_status",
    );
    let body: serde_json::Value = serde_json::from_str(&mcp_result_text(&finalized)).unwrap();
    assert_eq!(body["_kin"]["verdict"]["state"], "inconclusive");
    assert_eq!(
        body["_kin"]["verdict"]["inputs"]["enrichment"],
        "inconclusive"
    );
    assert_eq!(body["_kin"]["verdict"]["safe_to_conclude_absent"], false);
    assert!(body["enrichment"].get("page").is_none());
    assert!(
        body.get("source_derivation").is_some(),
        "the independent source reading survives"
    );

    let selected = mcp_call(
        app,
        "kin_graph_status",
        json!({
            "dependencies":["src/target.py","missing.py"], "max_chars":60000,
        }),
    )
    .await;
    let selected = parse_graph_status(&selected);
    assert_eq!(selected.entity_count, 2);
    let detail = selected.enrichment.unwrap();
    assert!(detail.get("unavailable").is_none());
    assert_eq!(detail["files"].as_array().unwrap().len(), 2);
    assert_eq!(detail["page"]["total"], 2);
    assert!(detail["files"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["admitted"] == false));
}

#[tokio::test]
async fn enrichment_status_cache_never_replays_a_different_dependency_selection() {
    let state = test_state_with_committed_sources(&[
        ("src/a.py", "def alpha():\n    return 1\n"),
        ("src/b.py", "def beta():\n    return 2\n"),
    ]);
    let graph = Arc::clone(&state.graph);
    let request = kin_mcp::status_pages::StatusRequest {
        dependencies: vec!["src/a.py".into()],
        ..Default::default()
    };
    let captured = mcp_graph_status_snapshot(
        &state,
        None,
        &graph,
        RequestGraphAuthority::Head,
        kin_mcp::handlers::entities::GraphStatusScope::Head,
        &request,
    )
    .await
    .unwrap();
    assert_eq!(
        parse_graph_status(&captured).enrichment.unwrap()["files"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let _guard = state.embedding_work.lock().unwrap();
    let same = mcp_graph_status_snapshot(
        &state,
        None,
        &graph,
        RequestGraphAuthority::Head,
        kin_mcp::handlers::entities::GraphStatusScope::Head,
        &request,
    )
    .await
    .unwrap();
    assert!(parse_graph_status(&same).stale.is_some());
    for dependencies in [vec![], vec!["src/b.py".into()]] {
        let other = kin_mcp::status_pages::StatusRequest {
            dependencies,
            ..Default::default()
        };
        let refused = mcp_graph_status_snapshot(
            &state,
            None,
            &graph,
            RequestGraphAuthority::Head,
            kin_mcp::handlers::entities::GraphStatusScope::Head,
            &other,
        )
        .await
        .unwrap();
        assert_eq!(
            refused.is_error,
            Some(true),
            "a different query has no matching settled detail"
        );
    }
}
