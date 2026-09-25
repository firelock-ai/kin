// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[tokio::test]
async fn hard_index_failure_does_not_certify_current_call_shapes() {
    let (repo, state) = mcp_lifecycle_fixture();
    let app = router(Arc::clone(&state));
    let file = "calls.py";
    let original = b"def target(value):\n    return value\n\ndef caller():\n    return target(1)\n";
    std::fs::write(repo.path().join(file), original).unwrap();
    commit_through_api(&app, kin_model::OperationId::new(), "initial call graph").await;
    let target = state
        .graph
        .query_entities(&kin_db::EntityFilter {
            file_path: Some(kin_model::FilePathId::new(file)),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|entity| entity.name == "target")
        .unwrap();
    let impact_args = json!({"entity_ids":[target.id.to_string()], "include_traffic":false});
    let before = mcp_call(app.clone(), "impact_analysis", impact_args.clone()).await;
    assert_ne!(before.is_error, Some(true), "{}", mcp_result_text(&before));
    let before_payload = tool_result_payload(&before);
    let before_shape = &before_payload["entity_impacts"][0]["call_shapes"];
    assert_eq!(
        before_shape["all_consumers_shaped_calls"], true,
        "{before_payload}"
    );
    assert_eq!(
        before_shape["caller_keyword_names"],
        json!([]),
        "{before_payload}"
    );

    let current =
        b"def target(value):\n    return value\n\ndef caller():\n    return target(value=1)\n";
    std::fs::write(repo.path().join(file), current).unwrap();
    *state.readmission_index_failure.lock().unwrap() = Some(kin_model::FilePathId::new(file));
    let admission = app.clone().oneshot(admit_request()).await.unwrap();
    let admission_status = admission.status();
    let admission_body = axum::body::to_bytes(admission.into_body(), 256 * 1024)
        .await
        .unwrap();
    println!(
        "hard-index admission: {admission_status} {}",
        String::from_utf8_lossy(&admission_body)
    );
    assert_eq!(admission_status, StatusCode::OK);
    let admission_payload: serde_json::Value = serde_json::from_slice(&admission_body).unwrap();
    assert_eq!(admission_payload["report"]["admitted"], false);
    assert!(String::from_utf8_lossy(&admission_body).contains("semantics could not be"));
    let path = kin_model::RepoPath::from_utf8(file).unwrap();
    let tree = state.graph.resolved_tree();
    let entry = &tree.artifact_at_path(&path).unwrap().entry;
    assert_eq!(
        entry,
        &kin_model::TreeEntry::blob(
            kin_model::Hash256::from_bytes(kin_blobs::digest(current).0),
            false
        )
    );
    assert_eq!(
        state
            .graph
            .get_entity(&target.id)
            .unwrap()
            .unwrap()
            .metadata
            .extra["blob_hash"],
        kin_blobs::digest(original).to_string()
    );

    let commit = app.clone().oneshot(Request::post("/commands/commit")
        .header("content-type", "application/json")
        .body(Body::from(json!({"operation_id":kin_model::OperationId::new(), "timestamp":Timestamp::now(), "author":"Test Author <test@example.invalid>", "message":"must refuse unpaid semantics"}).to_string())).unwrap()).await.unwrap();
    let commit_status = commit.status();
    let commit_body = axum::body::to_bytes(commit.into_body(), 256 * 1024)
        .await
        .unwrap();
    println!(
        "hard-index commit: {commit_status} {}",
        String::from_utf8_lossy(&commit_body)
    );
    assert!(!commit_status.is_success());
    assert!(String::from_utf8_lossy(&commit_body).contains("semantics could not be"));

    let after = mcp_call(app.clone(), "impact_analysis", impact_args.clone()).await;
    println!(
        "hard-index complete impact result: {}",
        serde_json::to_string(&after).unwrap()
    );
    let health = app
        .clone()
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let health_body = axum::body::to_bytes(health.into_body(), 1024 * 1024)
        .await
        .unwrap();
    println!(
        "hard-index complete health: {}",
        String::from_utf8_lossy(&health_body)
    );
    assert_ne!(after.is_error, Some(true), "{}", mcp_result_text(&after));
    let payload = tool_result_payload(&after);
    assert_eq!(payload["entity_impacts"][0]["call_shapes"]["all_consumers_shaped_calls"], false,
        "a current exact-tree body whose indexing failed cannot certify every current caller from the previous body: {payload}");

    // Reopen durable authority before any successful repair. Last-good semantic
    // history can replay, but it cannot certify the newer admitted body.
    let layout = state.layout.clone();
    drop(app);
    drop(state);
    let state = Arc::new(DaemonState::open(layout.clone()).unwrap());
    use kin_review::ImpactGraph;
    assert!(!kin_review::impact::LiveGraph(state.graph.as_ref())
        .call_shape_parse_coverage_complete()
        .unwrap());
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    *state.readmission_index_failure.lock().unwrap() = Some(kin_model::FilePathId::new(file));
    let app = router(Arc::clone(&state));
    let (_, admission) = admit_through_api(&app).await;
    assert_eq!(admission["report"]["admitted"], false);
    let cold = mcp_call(app.clone(), "impact_analysis", impact_args.clone()).await;
    let cold = tool_result_payload(&cold);
    println!("hard-index cold impact: {cold}");
    assert_eq!(
        cold["entity_impacts"][0]["call_shapes"]["all_consumers_shaped_calls"],
        false
    );

    *state.readmission_index_failure.lock().unwrap() = None;
    let (_, admission) = admit_through_api(&app).await;
    assert_eq!(admission["report"]["admitted"], true, "{admission}");
    commit_through_api(
        &app,
        kin_model::OperationId::new(),
        "repair exact admitted call graph",
    )
    .await;
    let repaired = mcp_call(app.clone(), "impact_analysis", impact_args).await;
    let repaired = tool_result_payload(&repaired);
    println!("hard-index repaired impact: {repaired}");
    assert_eq!(
        repaired["entity_impacts"][0]["call_shapes"]["all_consumers_shaped_calls"],
        true
    );
    assert_eq!(
        repaired["entity_impacts"][0]["call_shapes"]["caller_keyword_names"],
        json!(["value"])
    );
    drop(app);
    drop(state);
    let reopened = DaemonState::open(layout).unwrap();
    assert!(kin_review::impact::LiveGraph(reopened.graph.as_ref())
        .call_shape_parse_coverage_complete()
        .unwrap());
}

#[tokio::test]
async fn hard_index_failure_for_new_empty_source_remains_incomplete_until_repaired() {
    use kin_review::ImpactGraph;
    let (repo, state) = mcp_lifecycle_fixture();
    let app = router(Arc::clone(&state));
    std::fs::write(
        repo.path().join("value.py"),
        b"def value():\n    return 1\n",
    )
    .unwrap();
    commit_through_api(&app, kin_model::OperationId::new(), "initial value").await;
    assert!(kin_review::impact::LiveGraph(state.graph.as_ref())
        .call_shape_parse_coverage_complete()
        .unwrap());
    std::fs::write(repo.path().join("empty.py"), b"").unwrap();
    *state.readmission_index_failure.lock().unwrap() = Some(kin_model::FilePathId::new("empty.py"));
    let (_, admission) = admit_through_api(&app).await;
    assert_eq!(admission["report"]["admitted"], false, "{admission}");
    assert!(state
        .graph
        .get_tree_entry(&kin_model::FilePathId::new("empty.py"))
        .unwrap()
        .is_some());
    assert!(!kin_review::impact::LiveGraph(state.graph.as_ref())
        .call_shape_parse_coverage_complete()
        .unwrap());
    let empty_observation = observe_live_head_sources(
        &state,
        &state.graph,
        Some(&[kin_model::RepoPath::from_utf8("empty.py").unwrap()]),
    );
    assert_eq!(
        serde_json::to_value(empty_observation).unwrap()["report"]["body_binding"],
        "unproven"
    );
    let raw = mcp_call(app.clone(), "kin_graph_status", json!({})).await;
    assert_eq!(
        tool_result_payload(&raw)["source_derivation"]["report"]["body_binding"],
        "unproven"
    );
    let layout = state.layout.clone();
    drop(app);
    drop(state);
    let state = Arc::new(DaemonState::open(layout.clone()).unwrap());
    assert!(!kin_review::impact::LiveGraph(state.graph.as_ref())
        .call_shape_parse_coverage_complete()
        .unwrap());
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let app = router(Arc::clone(&state));
    let empty_observation = observe_live_head_sources(
        &state,
        &state.graph,
        Some(&[kin_model::RepoPath::from_utf8("empty.py").unwrap()]),
    );
    assert_eq!(
        serde_json::to_value(empty_observation).unwrap()["report"]["body_binding"],
        "unproven"
    );
    let raw = mcp_call(app.clone(), "kin_graph_status", json!({})).await;
    assert_eq!(
        tool_result_payload(&raw)["source_derivation"]["report"]["body_binding"],
        "unproven"
    );
    let (_, admission) = admit_through_api(&app).await;
    assert_eq!(admission["report"]["admitted"], true, "{admission}");
    let empty_observation = observe_live_head_sources(
        &state,
        &state.graph,
        Some(&[kin_model::RepoPath::from_utf8("empty.py").unwrap()]),
    );
    assert_eq!(
        serde_json::to_value(empty_observation).unwrap()["report"]["body_binding"],
        "current"
    );
    let raw = mcp_call(app.clone(), "kin_graph_status", json!({})).await;
    assert_eq!(
        tool_result_payload(&raw)["source_derivation"]["report"]["body_binding"],
        "current"
    );
    commit_through_api(
        &app,
        kin_model::OperationId::new(),
        "parse admitted empty source",
    )
    .await;
    assert!(kin_review::impact::LiveGraph(state.graph.as_ref())
        .call_shape_parse_coverage_complete()
        .unwrap());
    drop(app);
    drop(state);
    let reopened = DaemonState::open(layout).unwrap();
    assert!(kin_review::impact::LiveGraph(reopened.graph.as_ref())
        .call_shape_parse_coverage_complete()
        .unwrap());
}

// Diagnostic causal control: only the canonical index error is injected; the
// admissions, raw MCP calls, health, reopening and finalization are real paths.
#[tokio::test]
async fn readmission_disclosure_causal_routes() {
    async fn observe(
        app: &axum::Router,
        phase: &str,
        target: kin_model::EntityId,
    ) -> serde_json::Value {
        let response = app
            .clone()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let health: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let mut calls = serde_json::Map::new();
        for (tool, args) in [
            (
                "impact_analysis",
                json!({"entity_ids":[target.to_string()],"include_traffic":false}),
            ),
            ("semantic_search", json!({"query":"newly_added"})),
            (
                "graph_neighborhood",
                json!({"entity_id":target.to_string(), "depth":1}),
            ),
        ] {
            let raw = mcp_call(app.clone(), tool, args).await;
            assert_ne!(
                raw.is_error,
                Some(true),
                "{tool}: {}",
                mcp_result_text(&raw)
            );
            let finalized = kin_mcp::envelope::finalize_bounded(
                raw.clone(),
                kin_mcp::Envelope::daemon().with_health(&health),
                tool,
                &kin_mcp::budget::ResponseBudget::default(),
            );
            calls.insert(
                tool.into(),
                json!({"raw":raw,"stdio_finalization":finalized}),
            );
        }
        let observation = json!({"phase":phase,"health":health,"calls":calls});
        println!("readmission-disclosure-observation: {observation}");
        observation
    }
    let (repo, state) = mcp_lifecycle_fixture();
    let app = router(Arc::clone(&state));
    let original = b"def target(value):\n    return value\n\ndef caller():\n    return target(1)\n";
    std::fs::write(repo.path().join("calls.py"), original).unwrap();
    let initial_head = commit_through_api(
        &app,
        kin_model::OperationId::new(),
        "initial disclosure graph",
    )
    .await;
    let target = state
        .graph
        .query_entities(&kin_db::EntityFilter {
            file_path: Some(kin_model::FilePathId::new("calls.py")),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|e| e.name == "target")
        .unwrap()
        .id;
    let before = observe(&app, "before", target).await;
    let current = b"def target(value):\n    return value\n\ndef caller():\n    return target(value=1)\n\ndef newly_added():\n    return 2\n";
    std::fs::write(repo.path().join("calls.py"), current).unwrap();
    *state.readmission_index_failure.lock().unwrap() = Some(kin_model::FilePathId::new("calls.py"));
    let (_, admission) = admit_through_api(&app).await;
    assert_eq!(admission["report"]["admitted"], false, "{admission}");
    let failed = observe(&app, "failed", target).await;
    assert!(
        failed["health"]["reconcile"]["admission_failure_streak"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(failed["health"]["reconcile"]["untracked_path_count"], 0);
    assert!(failed["health"]["reconcile"]["last_admission_success_at"].is_string());
    let historical_diff = mcp_call(
        app.clone(),
        "semantic_diff",
        json!({"change_ids":[initial_head.to_string()]}),
    )
    .await;
    assert_ne!(historical_diff.is_error, Some(true));
    assert!(!mcp_result_text(&historical_diff).contains("source_derivation"));
    let authority = projection_repository_authority(&state).unwrap();
    let historical =
        Arc::new(kin_core::build_graph_at_ref(&authority.manager, &initial_head).unwrap());
    let session = SessionId::new();
    state
        .set_session_scope(&session, initial_head.to_string(), initial_head, historical)
        .await;
    for (tool, args) in [
        (
            "impact_analysis",
            json!({"entity_ids":[target.to_string()],"include_traffic":false}),
        ),
        ("kin_graph_status", json!({})),
    ] {
        let raw = mcp_call_as(app.clone(), tool, args, session).await;
        let raw_value = tool_result_payload(&raw);
        assert_eq!(
            raw_value["source_derivation"]["scope"], "selected_historical",
            "{raw_value}"
        );
        assert!(raw_value["source_derivation"].get("report").is_none());
        assert!(raw_value["source_derivation"]
            .get("admission_failure")
            .is_none());
        if tool == "kin_graph_status" {
            let _: kin_mcp::handlers::entities::GraphStatusReport =
                serde_json::from_value(raw_value).unwrap();
        } else {
            let finalized = kin_mcp::envelope::finalize(
                raw,
                kin_mcp::Envelope::daemon().with_health(&failed["health"]),
                tool,
            );
            let value = tool_result_payload(&finalized);
            let reason = value["_kin"]["verdict"]["limiting_factor"]
                .as_str()
                .unwrap_or_default();
            assert!(!reason.contains("semantic_readmission_failed"), "{value}");
            assert!(!reason.contains("derived_source_stale"), "{value}");
        }
    }
    let layout = state.layout.clone();
    drop(app);
    drop(state);
    let state = Arc::new(DaemonState::open(layout).unwrap());
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let app = router(Arc::clone(&state));
    let cold = observe(&app, "cold_without_retry", target).await;
    assert_eq!(cold["health"]["reconcile"]["admission_failure_streak"], 0);
    let (_, admission) = admit_through_api(&app).await;
    assert_eq!(admission["report"]["admitted"], true, "{admission}");
    let rederived = observe(&app, "rederived_before_commit", target).await;
    commit_through_api(
        &app,
        kin_model::OperationId::new(),
        "repair disclosure graph",
    )
    .await;
    let repaired = observe(&app, "repaired", target).await;
    assert_eq!(
        repaired["health"]["reconcile"]["admission_failure_streak"],
        0
    );
    for (observation, binding) in [
        (&before, "current"),
        (&failed, "stale"),
        (&cold, "stale"),
        (&repaired, "current"),
        (&rederived, "current"),
    ] {
        for call in observation["calls"].as_object().unwrap().values() {
            let raw: kin_mcp::ToolCallResult = serde_json::from_value(call["raw"].clone()).unwrap();
            let raw = tool_result_payload(&raw);
            assert_eq!(
                raw["source_derivation"]["report"]["body_binding"], binding,
                "{raw}"
            );
            let result: kin_mcp::ToolCallResult =
                serde_json::from_value(call["stdio_finalization"].clone()).unwrap();
            let value = tool_result_payload(&result);
            assert_eq!(
                value["_kin"]["source_derivation"]["report"]["body_binding"], binding,
                "{value}"
            );
            assert!(
                !value["_kin"]["verdict"]["limiting_factor"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("unlisted_clause"),
                "{value}"
            );
            if binding == "stale" {
                assert_eq!(value["_kin"]["verdict"]["state"], "inconclusive", "{value}");
                assert!(
                    value["_kin"]["verdict"]["limiting_factor"]
                        .as_str()
                        .unwrap()
                        .contains(if observation["phase"] == "failed" {
                            "semantic_readmission_failed"
                        } else {
                            "derived_source_stale"
                        }),
                    "{value}"
                );
            }
        }
    }
}

// ── Cross-repo authority while spine initialization is deferred ──────────
//
// The same promise as the cases above, about a different index. The daemon
// builds its cross-repo spine on first use, and a pass that finds a writer
// holding graph authority steps aside and leaves the spine unbuilt for the next
// read. A reference read in that window consulted no cross-repo authority at
// all. It reported that the way a daemon with the spine switched off does, as
// `not_configured`, which the verdict reads as a fact about the install rather
// than a gap in the answer, so the answer certified.

/// Releases a graph-authority writer on the warning a spine initialization
/// pass logs when it steps aside for that writer.
///
/// The pass logs it after recording why and before it returns, so the writer
/// it saw is gone before the reference read takes its first graph snapshot.
/// That keeps the read itself uncontended. An answer that had to retry would
/// carry a disclosure that refuses it on another ground, and the case below
/// would then pass whatever its cross-repo block said. The layer is installed
/// as the test thread's default subscriber, and a current-thread runtime runs
/// the pass's blocking hand-off inline, so the pass logs on this thread.
struct ReleaseWriterAtSpineDeferral {
    writer: Arc<std::sync::Mutex<Option<crate::state::GraphAuthorityMutationGuard>>>,
    released: Arc<std::sync::atomic::AtomicUsize>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for ReleaseWriterAtSpineDeferral {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct Message(Option<String>);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = Some(format!("{value:?}"));
                }
            }
        }
        let mut message = Message(None);
        event.record(&mut message);
        if message.0.as_deref()
            == Some("spine initialization deferred until primary graph authority is stable")
            && self
                .writer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .is_some()
        {
            self.released
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// Make the next spine initialization pass on `state` meet a writer and step
/// aside, and release that writer when the pass says it did.
///
/// Only the first pass is held. Every later pass meets no writer, which is what
/// lets it build the spine. Returns how many writers were released, one once
/// the first pass has stepped aside, and the guard that keeps the releasing
/// layer installed on this thread.
fn defer_the_next_spine_pass(
    state: &Arc<DaemonState>,
) -> (
    Arc<std::sync::atomic::AtomicUsize>,
    tracing::subscriber::DefaultGuard,
) {
    let writer = Arc::new(std::sync::Mutex::new(None));
    let released = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let armed = std::sync::atomic::AtomicBool::new(true);
    let hook_state = Arc::downgrade(state);
    let hook_writer = Arc::clone(&writer);
    state.set_spine_initialization_test_hook(Some(Arc::new(move || {
        if armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            if let Some(state) = hook_state.upgrade() {
                *hook_writer
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Some(state.begin_graph_authority_mutation());
            }
        }
    })));
    let release_layer =
        tracing::subscriber::set_default(tracing_subscriber::layer::SubscriberExt::with(
            tracing_subscriber::registry(),
            ReleaseWriterAtSpineDeferral {
                writer,
                released: Arc::clone(&released),
            },
        ));
    (released, release_layer)
}

/// A reference read served while spine initialization was deferred for a
/// writer must not certify, and must name the deferral. The next read, once the
/// writer has gone, must build the spine and certify.
///
/// The second half keeps the first honest. A deferral lasts only as long as
/// its writer, and an answer that kept refusing after the writer drained would
/// turn a moment of contention into a verdict that lasted as long as the daemon.
#[tokio::test]
async fn a_reference_read_while_spine_initialization_is_deferred_does_not_certify() {
    let (state, target) = reference_fixture();
    // The case is a spine that is switched on and not built yet, whatever the
    // environment this test runs in says about the switch.
    state.set_spine_disabled_for_test(false);
    let arguments = find_references_arguments(&target);
    let (released, _release_layer) = defer_the_next_spine_pass(&state);

    let deferred = mcp_find_references_with_stable_authority(
        &state,
        None,
        Arc::clone(&state.graph),
        RequestGraphAuthority::Head,
        &arguments,
        |_| {},
    )
    .await
    .expect("a reference read is served while spine initialization is deferred");
    assert_eq!(
        released.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the first pass must meet the writer and step aside for it, or this read never saw a \
         deferred spine"
    );
    assert!(
        state.spine().is_none(),
        "the pass that stepped aside must leave the spine unbuilt"
    );
    let body: serde_json::Value = serde_json::from_str(&mcp_result_text(&deferred)).unwrap();
    assert!(
        degradation_labels(&body).is_empty(),
        "the writer was gone before the read, so nothing but the spine may qualify this answer: {}",
        body["degradations"]
    );
    let finalized = finalized_payload(deferred, "find_references");
    let verdict = &finalized["_kin"]["verdict"];
    assert_ne!(
        verdict["state"], "certified",
        "no cross-repo authority stood behind this answer, so it must not certify: {finalized}"
    );
    assert_eq!(
        finalized["cross_repo"]["status"], "unavailable",
        "a deferred spine is not a spine nobody configured: {}",
        finalized["cross_repo"]
    );
    assert_eq!(
        finalized["cross_repo"]["code"], "spine_initialization_deferred",
        "{}",
        finalized["cross_repo"]
    );
    assert_eq!(verdict["inputs"]["cross_repo"], "inconclusive", "{verdict}");
    assert_eq!(
        verdict["limiting_factor"], "spine_initialization_deferred",
        "the deferral is the one thing wrong with this answer, and the factor must name it: \
         {verdict}"
    );

    // The writer has gone. The next read builds the spine, and certifies.
    let settled = mcp_find_references_with_stable_authority(
        &state,
        None,
        Arc::clone(&state.graph),
        RequestGraphAuthority::Head,
        &arguments,
        |_| {},
    )
    .await
    .expect("a reference read is served once the writer has gone");
    assert!(
        state.spine().is_some(),
        "the next read must build the spine"
    );
    let finalized = finalized_payload(settled, "find_references");
    assert_eq!(
        finalized["cross_repo"]["status"], "available",
        "{}",
        finalized["cross_repo"]
    );
    assert_eq!(
        finalized["_kin"]["verdict"]["state"], "certified",
        "a deferral must not outlive its writer: {finalized}"
    );
    state.set_spine_initialization_test_hook(None);
}

/// A deferral cleared by another request is still a gap in the read that met it.
///
/// Request A's pass steps aside for a writer. Before A reads why, request B's
/// pass builds the spine, and a pass that succeeds clears the recorded reason.
/// A read the graph without the spine all the same, so its answer has no
/// cross-repo authority behind it. The record A finds empty at that moment must
/// read as a gap, never as a spine nobody configured.
#[tokio::test]
async fn a_deferral_another_request_clears_still_keeps_this_read_from_certifying() {
    let (state, target) = reference_fixture();
    state.set_spine_disabled_for_test(false);
    let arguments = find_references_arguments(&target);
    let (released, _release_layer) = defer_the_next_spine_pass(&state);

    // B, run between A's pass and A's reading of the slot.
    let b_built = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let b_state = Arc::downgrade(&state);
        let b_built = Arc::clone(&b_built);
        crate::state::DaemonState::run_before_next_spine_deferral_read(Box::new(move || {
            if let Some(state) = b_state.upgrade() {
                b_built.store(
                    state.ensure_spine().is_some(),
                    std::sync::atomic::Ordering::SeqCst,
                );
            }
        }));
    }

    let a = mcp_find_references_with_stable_authority(
        &state,
        None,
        Arc::clone(&state.graph),
        RequestGraphAuthority::Head,
        &arguments,
        |_| {},
    )
    .await
    .expect("request A is served");
    assert_eq!(
        released.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "A's pass must meet the writer and step aside for it"
    );
    assert!(
        b_built.load(std::sync::atomic::Ordering::SeqCst),
        "B must build the spine between A's pass and A's reading of the slot"
    );
    let body: serde_json::Value = serde_json::from_str(&mcp_result_text(&a)).unwrap();
    assert!(
        degradation_labels(&body).is_empty(),
        "A's own read met no writer, so nothing but the spine may qualify it: {}",
        body["degradations"]
    );
    let finalized = finalized_payload(a, "find_references");
    assert_ne!(
        finalized["cross_repo"]["status"], "not_configured",
        "an empty record after another request cleared it is not a spine nobody configured: \
         {finalized}"
    );
    assert_ne!(
        finalized["_kin"]["verdict"]["state"], "certified",
        "A read the graph without the spine, so its answer must not certify: {finalized}"
    );
    assert_eq!(
        finalized["cross_repo"]["code"], "spine_initialization_deferred",
        "{}",
        finalized["cross_repo"]
    );
    state.set_spine_initialization_test_hook(None);
}

/// The control: a daemon whose spine is switched off reports `not_configured`
/// and still certifies. Cross-repo authority does not apply to it, so nothing
/// is missing from its answer.
#[tokio::test]
async fn a_reference_read_with_the_spine_switched_off_still_certifies() {
    let (state, target) = reference_fixture();
    state.set_spine_disabled_for_test(true);

    let answer = mcp_find_references_with_stable_authority(
        &state,
        None,
        Arc::clone(&state.graph),
        RequestGraphAuthority::Head,
        &find_references_arguments(&target),
        |_| {},
    )
    .await
    .expect("a reference read is served with the spine switched off");
    let finalized = finalized_payload(answer, "find_references");
    assert_eq!(
        finalized["cross_repo"]["status"], "not_configured",
        "{}",
        finalized["cross_repo"]
    );
    assert_eq!(
        finalized["_kin"]["verdict"]["inputs"]["cross_repo"], "not_applicable",
        "{finalized}"
    );
    assert_eq!(
        finalized["_kin"]["verdict"]["state"], "certified",
        "a spine that is switched off is a fact about the install, not a gap in the answer: \
         {finalized}"
    );
}

/// A derived-member refusal is a standing gap in the answer, neither a deferral
/// nor a spine nobody configured.
///
/// The spine is on, and it refuses a graph that holds an inferred member
/// because its format cannot carry candidate authority. A drained writer does
/// not change that, so the refusal must not travel under the deferral's code,
/// which tells a reader that a later read will build the spine. Nor may it read
/// as not configured: for as long as the graph holds the member, no cross-repo
/// authority stands behind an answer read from it.
#[tokio::test]
async fn a_derived_member_refusal_is_not_reported_as_a_deferred_spine() {
    let (state, target) = reference_fixture();
    state.set_spine_disabled_for_test(false);
    let mut inferred = test_entity("inferred_member", "src/generated.py");
    inferred.metadata.extra.insert(
        kin_model::derivation::ENTITY_DERIVATION_KEY.to_string(),
        serde_json::json!({}),
    );
    state.graph.upsert_entity(&inferred).unwrap();

    let answer = mcp_find_references_with_stable_authority(
        &state,
        None,
        Arc::clone(&state.graph),
        RequestGraphAuthority::Head,
        &find_references_arguments(&target),
        |_| {},
    )
    .await
    .expect("a reference read is served while the spine refuses the graph");
    assert!(
        state.spine().is_none(),
        "the spine must refuse a graph that holds an inferred member"
    );
    assert!(
        state
            .spine_unavailable_reason()
            .starts_with("spine_candidate_representation_gap"),
        "the fixture must reach the derived-member refusal: {}",
        state.spine_unavailable_reason()
    );
    let finalized = finalized_payload(answer, "find_references");
    let cross_repo = &finalized["cross_repo"];
    let verdict = &finalized["_kin"]["verdict"];
    assert_eq!(
        cross_repo["status"], "unavailable",
        "the spine is on and refused this graph, which is not a spine nobody configured: \
         {cross_repo}"
    );
    assert_eq!(
        cross_repo["code"], "spine_candidate_representation_gap",
        "the refusal names its own standing condition, not the deferral's: {cross_repo}"
    );
    assert!(
        cross_repo["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("inferred member")),
        "{cross_repo}"
    );
    assert_eq!(verdict["inputs"]["cross_repo"], "inconclusive", "{verdict}");
    assert_eq!(
        verdict["state"], "inconclusive",
        "no cross-repo authority stands behind this answer, so it must not certify: {verdict}"
    );
    assert_eq!(
        verdict["limiting_factor"], "spine_candidate_representation_gap",
        "the refusal is the one thing wrong with this answer, and the factor must name it: \
         {verdict}"
    );
}

// ── `kin refs` and cross-repo authority ───────────────────────────────────
//
// `kin refs` answers from this repository's graph, and it grades an empty
// answer through the `find_references` gate. That gate weighs cross-repo
// authority, and the route handed it a payload that said no spine was
// configured, whatever the daemon's spine held. A reference from another
// repository into the focal was invisible to it, and the absence certified.

/// One `kin refs` request for `entity` through this daemon's route.
async fn refs_through_route(
    state: &Arc<DaemonState>,
    entity: &str,
) -> kin_cli::commands::refs::RefsResponse {
    let response = router(Arc::clone(state))
        .oneshot(
            Request::post("/commands/refs")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "entity": entity, "kind": "all" }).to_string(),
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
    serde_json::from_slice(&body).expect("the route answers a refs response")
}

/// A focal nothing in this repository references, on a store whose own
/// coverage would certify that absence.
fn unreached_focal_fixture() -> (Arc<DaemonState>, Entity) {
    let (state, _target) = reference_fixture();
    state.set_spine_disabled_for_test(false);
    let focal = install_trace_fixture_file(&state, "sweep_unreached", "src/unreached.py");
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Relaxed);
    (state, focal)
}

/// Register a sibling repository whose one function calls `focal`, and bring
/// every registered repository's edges current, the way the blast-radius
/// fixture does.
fn register_a_sibling_that_calls(state: &DaemonState, focal: &Entity) {
    let spine = state.ensure_spine().expect("spine enabled in test");
    let consumer = parse_consumer_source(
        "src/app.rs",
        &format!(
            "use provider::{name};\n\npub fn run_task() {{\n    {name}();\n}}\n",
            name = focal.name
        ),
    );
    let consumer_entities = consumer.entities.clone();
    let consumer_relations = link_admitted_consumer_files(&[consumer]);
    spine.register_repo(
        "consumer",
        consumer_entities
            .iter()
            .map(|entity| spine_test_entry("consumer", entity))
            .collect(),
        "consumer-root",
    );
    let mut registry = spine.registered_repo_ids().into_iter().collect::<Vec<_>>();
    registry.sort();
    for repo in &registry {
        if repo == "consumer" {
            spine.refresh_cross_repo_edges(
                repo,
                &consumer_entities,
                &consumer_relations,
                &registry,
            );
        } else {
            spine.refresh_cross_repo_edges(repo, &[], &[], &registry);
        }
    }
    let xref = spine.cross_repo_xref_response(&state.cached_repo_id, &focal.id);
    assert!(
        xref.edges
            .iter()
            .any(|edge| edge.src_repo == "consumer" && edge.dst_entity == focal.id),
        "the fixture must hold the sibling's edge into the focal: {:?}",
        xref.edges
    );
}

/// A sibling holds the only reference into the focal, so `kin refs` must not
/// certify its absence, and must say that a reference from another repository
/// reaches it.
#[tokio::test]
async fn kin_refs_does_not_certify_an_absence_a_sibling_reference_disproves() {
    let (state, focal) = unreached_focal_fixture();
    register_a_sibling_that_calls(&state, &focal);

    let response = refs_through_route(&state, &focal.id.to_string()).await;
    let negative = response
        .negative
        .clone()
        .expect("an empty local answer carries a verdict");
    assert_ne!(
        negative["safe_to_conclude_absent"], true,
        "a sibling's call reaches this focal, so no absence may be certified: {negative}\n{:#?}",
        response.lines
    );
    assert!(
        response
            .lines
            .iter()
            .any(|line| line.contains("other repositor")),
        "the answer must say that a reference from another repository reaches the focal: {:#?}",
        response.lines
    );
}

/// The control: the same store with no sibling. The absence is real, and
/// `kin refs` certifies it as it always has.
#[tokio::test]
async fn kin_refs_still_certifies_an_absence_nothing_disproves() {
    let (state, focal) = unreached_focal_fixture();

    let response = refs_through_route(&state, &focal.id.to_string()).await;
    let negative = response
        .negative
        .clone()
        .expect("an empty local answer carries a verdict");
    assert_eq!(
        negative["safe_to_conclude_absent"], true,
        "an absence nothing disproves must still certify: {negative}\n{:#?}",
        response.lines
    );
}

/// A spine whose initialization was deferred, and one that refused the graph,
/// are gaps in `kin refs` too, each under its own code.
///
/// The control is the same answer built with no spine at all, which certifies,
/// so the refusals below come from the spine state and from nothing else.
#[tokio::test]
async fn kin_refs_reads_a_deferred_or_refusing_spine_as_a_gap() {
    let (state, focal) = unreached_focal_fixture();
    let envelope = kin_mcp::Envelope::daemon().with_health(&daemon_health_snapshot(&state).await);
    let request = kin_cli::commands::refs::RefsRequest {
        entity: focal.id.to_string(),
        kind: "all".to_string(),
    };
    let answer = |spine: kin_spine::DaemonSpine<'_>| {
        kin_cli::commands::refs::build_refs_response_with_spine(
            &state.layout,
            state.graph.as_ref(),
            &request,
            &envelope,
            kin_cli::commands::refs::RefsSpine {
                repo_id: &state.cached_repo_id,
                spine,
            },
        )
        .expect("kin refs answers")
    };

    let control = answer(kin_spine::DaemonSpine::Absent)
        .negative
        .expect("an empty answer carries a verdict");
    assert_eq!(
        control["safe_to_conclude_absent"], true,
        "the control must certify, or the refusals below discriminate nothing: {control}"
    );

    for (spine, code) in [
        (
            kin_spine::DaemonSpine::Deferred(
                "could not capture stable spine authority for repo r after 3 attempts: primary \
                 graph has an active authority writer",
            ),
            "spine_initialization_deferred",
        ),
        (
            kin_spine::DaemonSpine::Refused(
                "spine_candidate_representation_gap: repo r contains inferred member m; the \
                 current spine format cannot preserve candidate authority",
            ),
            "spine_candidate_representation_gap",
        ),
    ] {
        let negative = answer(spine)
            .negative
            .expect("an empty answer carries a verdict");
        assert_eq!(
            negative["safe_to_conclude_absent"], false,
            "{code}: no cross-repo authority stood behind this absence: {negative}"
        );
        assert!(
            negative["trust_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains(code)),
            "{code}: the refusal must name the spine state: {negative}"
        );
    }
}
