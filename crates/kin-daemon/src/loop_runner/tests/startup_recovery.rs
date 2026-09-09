fn startup_diagnostic_trace(stage: &str, state: &DaemonState) {
    let file_id = FilePathId::new("orphan.py");
    let layout = state.graph.get_file_layout(&file_id).unwrap();
    let marker = std::fs::read(unpublished_enrichment_marker_path(state))
        .ok()
        .map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).unwrap());
    println!(
        "STARTUP_DIAGNOSTIC {}",
        serde_json::json!({
            "stage": stage,
            "live_entities": state.graph.entity_count(),
            "durable_entities": state.durable_entity_count(),
            "artifact_admitted": state.graph.artifact_id_at_path(&test_repo_path("orphan.py")).is_some(),
            "marker": marker,
            "semantic_debt_count": crate::semantic_debt::outstanding(state).len(),
            "initialized": state.is_initialized.load(Ordering::Relaxed),
            "reconciliation_status": state.reconciliation_status_str(),
            "layout_completeness": layout.map(|layout| format!("{:?}", layout.parse_completeness)),
        })
    );
}

async fn startup_diagnostic_query(state: Arc<DaemonState>) -> serde_json::Value {
    let request = axum::http::Request::post("/mcp/tools/call")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({
                "name": "list_file_entities",
                "arguments": {"path": "orphan.py"}
            })
            .to_string(),
        ))
        .unwrap();
    let response = tower::ServiceExt::oneshot(crate::api::router(state), request)
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let result: kin_mcp::ToolCallResult = serde_json::from_slice(&body).unwrap();
    assert_ne!(result.is_error, Some(true), "{result:?}");
    let kin_mcp::ContentBlock::Text { text } = &result.content[0];
    serde_json::from_str(text).unwrap()
}

fn startup_diagnostic_admit_without_consuming_semantics(state: &Arc<DaemonState>) -> usize {
    std::fs::write(
        state.layout.working_dir().join("orphan.py"),
        b"def orphan():\n    return 7\n",
    )
    .unwrap();
    let observation = BTreeSet::from([test_repo_path("orphan.py")]);
    let admitted =
        exact_tree_admission(state, Some(&observation), TreePublication::Standalone).unwrap();
    assert!(!admitted.deltas.is_empty());
    assert_eq!(admitted.semantic_events.len(), 1);
    assert!(
        matches!(&admitted.semantic_events[0], FileEvent::Changed(path) if path.ends_with("orphan.py"))
    );
    assert_eq!(state.graph.entity_count(), 0);
    assert!(!unpublished_enrichment_marker_path(state).exists());
    crate::background_work::record_durable_admission(
        &state.layout,
        state.graph.resolved_tree().len() as u64,
    );
    let since = startup_catch_up_window(state).expect("completed admission records its time");
    assert!(
        plan_catch_up_events(state, since).unwrap().is_empty(),
        "the admitted fixture must predate its complete-admission marker"
    );
    let hash = state
        .graph
        .get_tree_entry(&FilePathId::new("orphan.py"))
        .unwrap()
        .unwrap()
        .blob_identity()
        .unwrap();
    let body_hash = kin_blobs::Hash256::from_bytes(*hash.as_bytes());
    let bytes = state.blobs.read(&body_hash).unwrap();
    let parsed = IndexPipeline::new()
        .index_file_content_with_tests(&FilePathId::new("orphan.py"), &bytes, body_hash)
        .unwrap()
        .indexed_file;
    assert!(parsed.entities.iter().any(|entity| entity.name == "orphan"));
    startup_diagnostic_trace("tree_published_semantic_event_unconsumed", state);
    parsed.entities.len()
}

#[test]
fn startup_diagnostic_admission_gap_must_schedule_recovery_after_reopen() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    let fresh_count = startup_diagnostic_admit_without_consuming_semantics(&state);
    startup_diagnostic_legacy_without_debt(&state);
    drop(state);
    let restarted =
        Arc::new(DaemonState::open(kin_core::KinLayout::discover(repo.path()).unwrap()).unwrap());
    startup_diagnostic_trace("reopened_before_repair_planning", &restarted);
    assert!(restarted
        .graph
        .artifact_id_at_path(&test_repo_path("orphan.py"))
        .is_some());
    assert_eq!(restarted.graph.entity_count(), 0);
    assert_eq!(restarted.durable_entity_count(), Some(0));
    assert!(
        plan_catch_up_events(&restarted, startup_catch_up_window(&restarted).unwrap())
            .unwrap()
            .is_empty()
    );
    let marker_repair = plan_unpublished_enrichment_repair(&restarted).unwrap();
    let layout_repair = backfill_missing_file_layouts(&restarted).unwrap();
    startup_diagnostic_trace("after_both_startup_repair_planners", &restarted);
    println!(
        "STARTUP_DIAGNOSTIC {}",
        serde_json::json!({
            "fresh_parse_entities": fresh_count,
            "marker_repair_events": marker_repair.len(),
            "layout_repair_events": layout_repair.rederive.len(),
            "layout_published": layout_repair.published,
            "layout_stale": layout_repair.stale,
        })
    );
    assert!(
        !marker_repair.is_empty() || !layout_repair.rederive.is_empty(),
        "admitted source with a known function and no graph entities must retain a startup recovery path"
    );
}

#[cfg(unix)]
#[test]
fn startup_diagnostic_marker_positive_control_recovers_the_known_function() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    startup_diagnostic_admit_without_consuming_semantics(&state);
    startup_diagnostic_legacy_without_debt(&state);
    mark_enrichment_unpublished(&state, &FilePathId::new("orphan.py"));
    drop(state);
    let restarted =
        Arc::new(DaemonState::open(kin_core::KinLayout::discover(repo.path()).unwrap()).unwrap());
    startup_diagnostic_trace("marked_reopen_before_planning", &restarted);
    let repair = plan_unpublished_enrichment_repair(&restarted).unwrap();
    assert_eq!(repair.len(), 1);
    assert!(matches!(&repair[0], FileEvent::Changed(path) if path.ends_with("orphan.py")));
    derive_semantics(&restarted, "orphan.py");
    startup_diagnostic_trace("marked_positive_control_after_real_reconcile", &restarted);
    assert!(restarted
        .graph
        .query_entities(&EntityFilter::default())
        .unwrap()
        .iter()
        .any(|entity| entity.name == "orphan"));
    assert_eq!(restarted.durable_entity_count(), Some(0));
}

#[tokio::test]
async fn startup_diagnostic_watch_arms_before_marked_repair_is_live() {
    let repo = tempfile::tempdir().unwrap();
    let first = open_test_state(&repo);
    startup_diagnostic_admit_without_consuming_semantics(&first);
    startup_diagnostic_legacy_without_debt(&first);
    mark_enrichment_unpublished(&first, &FilePathId::new("orphan.py"));
    drop(first);
    let state =
        Arc::new(DaemonState::open(kin_core::KinLayout::discover(repo.path()).unwrap()).unwrap());
    let held_gate = state.coordination_gate.lock().await;
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
    let mut runner = tokio::spawn(run_loop_armed(
        Arc::clone(&state),
        LoopConfig {
            poll_interval_ms: 10,
            batch_size: 64,
        },
        cancel_rx,
        Some(WatchArmed::new(armed_tx)),
    ));
    let arming = crate::daemon::await_watch_armed(armed_rx, Duration::from_secs(5)).await;
    let live_at_arm = state.graph.entity_count();
    let durable_at_arm = state.durable_entity_count();
    startup_diagnostic_trace("watch_armed_while_startup_gate_held", &state);
    let query_at_arm = tokio::time::timeout(
        Duration::from_secs(2),
        startup_diagnostic_query(Arc::clone(&state)),
    )
    .await;
    println!(
        "STARTUP_DIAGNOSTIC {}",
        serde_json::json!({
            "stage": "http_query_while_startup_gate_held",
            "response": query_at_arm.as_ref().ok(),
        })
    );
    drop(held_gate);

    let recovered = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if state
                .graph
                .query_entities(&EntityFilter::default())
                .unwrap()
                .iter()
                .any(|entity| entity.name == "orphan")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    startup_diagnostic_trace("watch_control_after_releasing_startup_gate", &state);
    cancel_tx.send(true).ok();
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut runner).await;
    if joined.is_err() {
        runner.abort();
        let _ = runner.await;
    }
    assert!(
        joined.is_ok(),
        "the owned loop must stop after cancellation"
    );
    joined.unwrap().unwrap().unwrap();
    assert_eq!(arming, crate::daemon::WatchArming::Armed);
    assert_eq!(live_at_arm, 0);
    assert_eq!(durable_at_arm, Some(0));
    let answer = query_at_arm.expect("HTTP query must complete while the startup gate is held");
    assert!(answer["entities"].as_array().unwrap().is_empty());
    assert_eq!(
        answer["file_coverage"]["certifies_enumeration"],
        serde_json::json!(false)
    );
    recovered.expect("releasing the gate must let the real startup loop recover the function");
    assert!(state.graph.entity_count() > 0);
    assert_eq!(state.durable_entity_count(), Some(0));
}

#[tokio::test]
async fn startup_diagnostic_full_loop_must_not_certify_the_missing_function() {
    let repo = tempfile::tempdir().unwrap();
    let first = open_test_state(&repo);
    startup_diagnostic_admit_without_consuming_semantics(&first);
    startup_diagnostic_legacy_without_debt(&first);
    drop(first);
    let state =
        Arc::new(DaemonState::open(kin_core::KinLayout::discover(repo.path()).unwrap()).unwrap());
    assert!(state
        .graph
        .artifact_id_at_path(&test_repo_path("orphan.py"))
        .is_some());
    assert_eq!(state.graph.entity_count(), 0);
    assert_eq!(state.durable_entity_count(), Some(0));
    assert!(!unpublished_enrichment_marker_path(&state).exists());
    assert!(crate::semantic_debt::outstanding(&state).is_empty());
    assert!(
        plan_catch_up_events(&state, startup_catch_up_window(&state).unwrap())
            .unwrap()
            .is_empty()
    );
    startup_diagnostic_trace("full_loop_reopened_before_startup", &state);
    // The readiness control must already belong to the admitted tree before
    // watcher construction; later events only change this tracked source.
    std::fs::write(
        repo.path().join("sentinel.py"),
        b"# tracked readiness control\n",
    )
    .unwrap();
    let sentinel = BTreeSet::from([test_repo_path("sentinel.py")]);
    let admitted =
        exact_tree_admission(&state, Some(&sentinel), TreePublication::Standalone).unwrap();
    assert!(!admitted.deltas.is_empty());
    assert!(state
        .graph
        .artifact_id_at_path(&test_repo_path("sentinel.py"))
        .is_some());
    assert_eq!(state.graph.entity_count(), 0);
    crate::background_work::record_durable_admission(
        &state.layout,
        state.graph.resolved_tree().len() as u64,
    );
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
    let mut runner = tokio::spawn(run_loop_armed(
        Arc::clone(&state),
        LoopConfig {
            poll_interval_ms: 10,
            batch_size: 64,
        },
        cancel_rx,
        Some(WatchArmed::new(armed_tx)),
    ));
    let arming = crate::daemon::await_watch_armed(armed_rx, Duration::from_secs(5)).await;
    let completed = tokio::time::timeout(Duration::from_secs(30), async {
        while state
            .graph
            .get_file_layout(&FilePathId::new("orphan.py"))
            .unwrap()
            .is_none()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        startup_diagnostic_trace("full_loop_startup_layout_published", &state);
        while !state
            .graph
            .query_entities(&EntityFilter::default())
            .unwrap()
            .iter()
            .any(|entity| entity.name == "orphan")
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    startup_diagnostic_trace("full_loop_before_cancellation", &state);
    let answer = tokio::time::timeout(
        Duration::from_secs(2),
        startup_diagnostic_query(Arc::clone(&state)),
    )
    .await;
    cancel_tx.send(true).ok();
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut runner).await;
    if joined.is_err() {
        runner.abort();
        let _ = runner.await;
    }
    assert!(
        joined.is_ok(),
        "the owned loop must stop after cancellation"
    );
    joined.unwrap().unwrap().unwrap();
    assert_eq!(arming, crate::daemon::WatchArming::Armed);
    startup_diagnostic_trace("full_loop_after_shutdown", &state);
    let answer = answer.expect("HTTP query must complete while the real loop is running");
    println!(
        "STARTUP_DIAGNOSTIC {}",
        serde_json::json!({
            "stage": "full_loop_http_result",
            "response": answer,
        })
    );
    assert!(
        !answer["entities"].as_array().unwrap().is_empty()
            || answer["file_coverage"]["certifies_enumeration"] != serde_json::json!(true),
        "the full startup loop must not certify an empty enumeration for a known admitted function"
    );
    completed.expect("the full loop must recover the known function from its startup queue");
    assert!(answer["entities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entity| entity["name"] == "orphan"));
    assert_eq!(
        answer["file_coverage"]["certifies_enumeration"],
        serde_json::json!(true)
    );
}

fn startup_diagnostic_legacy_without_debt(state: &DaemonState) {
    // Older admissions left no recovery record. Reproduce that retained-store
    // state independently of the admission path's current recording behavior.
    match std::fs::remove_file(state.layout.root().join("semantic-debt.json")) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("cannot prepare legacy recovery fixture: {error}"),
    }
}

#[test]
fn startup_diagnostic_standalone_admission_retains_exact_body_debt() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    assert_eq!(
        startup_diagnostic_admit_without_consuming_semantics(&state),
        2
    );
    let recorded = crate::semantic_debt::outstanding(&state);
    let (owed, _) = crate::semantic_debt::partition_against_tree(&state, &recorded);
    assert!(
        owed.contains(&test_repo_path("orphan.py")),
        "published source must retain exact-body recovery debt: {recorded:?}"
    );
    drop(state);
    let restarted =
        Arc::new(DaemonState::open(kin_core::KinLayout::discover(repo.path()).unwrap()).unwrap());
    let (owed, _) = crate::semantic_debt::partition_against_tree(
        &restarted,
        &crate::semantic_debt::outstanding(&restarted),
    );
    assert!(
        owed.contains(&test_repo_path("orphan.py")),
        "recovery debt must survive a genuine reopen"
    );
}

#[test]
fn startup_diagnostic_unwritable_debt_refuses_before_authority_moves() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    let before = authority_tree(&state);
    let generation = authority_generation(&state);
    std::fs::write(
        repo.path().join("orphan.py"),
        b"def orphan():\n    return 7\n",
    )
    .unwrap();
    std::fs::create_dir(state.layout.root().join("semantic-debt.json")).unwrap();
    let observation = BTreeSet::from([test_repo_path("orphan.py")]);
    let result = exact_tree_admission(&state, Some(&observation), TreePublication::Standalone);
    assert!(
        result.is_err(),
        "admission must refuse when its recovery record cannot be prepared"
    );
    assert_eq!(
        authority_tree(&state),
        before,
        "failed recovery recording must not move repository authority"
    );
    assert_eq!(authority_generation(&state), generation);
    assert!(state.layout.root().join("semantic-debt.json").is_dir());
    assert_eq!(
        std::fs::read(repo.path().join("orphan.py")).unwrap(),
        b"def orphan():\n    return 7\n"
    );
    assert!(state
        .graph
        .artifact_id_at_path(&test_repo_path("orphan.py"))
        .is_none());
}

#[tokio::test]
async fn startup_diagnostic_spent_proposal_does_not_settle_older_owed_body() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    startup_diagnostic_admit_without_consuming_semantics(&state);
    let hash = state
        .graph
        .get_tree_entry(&FilePathId::new("orphan.py"))
        .unwrap()
        .unwrap()
        .blob_identity()
        .unwrap();
    let old = crate::semantic_debt::SemanticDebt {
        path: "orphan.py".into(),
        body: hash.to_string(),
    };
    let proposed = crate::semantic_debt::SemanticDebt {
        path: "orphan.py".into(),
        body: "0".repeat(64),
    };
    assert_ne!(old.body, proposed.body);
    crate::semantic_debt::record(&state, &[old.clone(), proposed]);
    assert_eq!(crate::semantic_debt::outstanding(&state).len(), 2);
    drain_semantic_debt(&state).await.unwrap();
    assert!(state
        .graph
        .query_entities(&EntityFilter::default())
        .unwrap()
        .iter()
        .any(|entity| entity.name == "orphan"));
    assert!(
        crate::semantic_debt::outstanding(&state).contains(&old),
        "a spent proposal must not erase the debt whose current-body parse is still not durable"
    );
}

#[test]
fn startup_diagnostic_corrupt_debt_is_preserved_before_publication() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    let before = authority_tree(&state);
    let generation = authority_generation(&state);
    let marker = state.layout.root().join("semantic-debt.json");
    let corrupt = b"[{unknown recovery work";
    std::fs::write(&marker, corrupt).unwrap();
    std::fs::write(
        repo.path().join("orphan.py"),
        b"def orphan():\n    return 7\n",
    )
    .unwrap();
    let observation = BTreeSet::from([test_repo_path("orphan.py")]);
    assert!(exact_tree_admission(&state, Some(&observation), TreePublication::Standalone).is_err());
    assert_eq!(authority_tree(&state), before);
    assert_eq!(authority_generation(&state), generation);
    assert_eq!(std::fs::read(marker).unwrap(), corrupt);
    assert_eq!(
        std::fs::read(repo.path().join("orphan.py")).unwrap(),
        b"def orphan():\n    return 7\n"
    );
}

#[test]
fn startup_diagnostic_prepublication_keeps_current_and_proposed_bodies() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    startup_diagnostic_admit_without_consuming_semantics(&state);
    let old = crate::semantic_debt::outstanding(&state)
        .into_iter()
        .find(|entry| entry.path == "orphan.py")
        .unwrap();
    let unrelated = crate::semantic_debt::SemanticDebt {
        path: "other.py".into(),
        body: "1".repeat(64),
    };
    crate::semantic_debt::record(&state, std::slice::from_ref(&unrelated));
    let proposed = crate::semantic_debt::SemanticDebt {
        path: "orphan.py".into(),
        body: "0".repeat(64),
    };
    assert_ne!(old.body, proposed.body);
    let concurrent = crate::semantic_debt::SemanticDebt {
        path: "orphan.py".into(),
        body: "2".repeat(64),
    };
    let mut outstanding = crate::semantic_debt::outstanding(&state);
    outstanding.push(concurrent.clone());
    std::fs::write(
        state.layout.root().join("semantic-debt.json"),
        serde_json::to_vec(&outstanding).unwrap(),
    )
    .unwrap();
    let generation = authority_generation(&state);
    crate::semantic_debt::record_before_standalone_publication(
        &state,
        std::slice::from_ref(&proposed),
    )
    .unwrap();
    let recorded = crate::semantic_debt::outstanding(&state);
    assert!(
        recorded.contains(&old),
        "preparing a new body must retain the currently owed body"
    );
    assert!(recorded.contains(&proposed));
    assert!(recorded.contains(&unrelated));
    assert!(
        recorded.contains(&concurrent),
        "prepublication must retain a body a concurrent publication could make authoritative"
    );
    assert_eq!(recorded.len(), 4);
    assert_eq!(authority_generation(&state), generation);
    crate::semantic_debt::record_before_standalone_publication(
        &state,
        std::slice::from_ref(&proposed),
    )
    .unwrap();
    assert_eq!(
        crate::semantic_debt::outstanding(&state),
        recorded,
        "preparing the same body must not duplicate debt"
    );
}

#[test]
fn startup_diagnostic_legitimate_empty_parse_still_certifies_from_cas() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    let path = "empty.pyi";
    let content = b"# type stub only\n";
    std::fs::write(repo.path().join(path), content).unwrap();
    let observation = BTreeSet::from([test_repo_path(path)]);
    exact_tree_admission(&state, Some(&observation), TreePublication::Standalone).unwrap();
    let hash = state
        .graph
        .get_tree_entry(&FilePathId::new(path))
        .unwrap()
        .unwrap()
        .blob_identity()
        .unwrap();
    let body_hash = kin_blobs::Hash256::from_bytes(*hash.as_bytes());
    let bytes = state.blobs.read(&body_hash).unwrap();
    let parsed = IndexPipeline::new()
        .index_file_content_with_tests(&FilePathId::new(path), &bytes, body_hash)
        .unwrap()
        .indexed_file;
    assert!(
        parsed.entities.is_empty(),
        "the real adapter must produce a legitimate empty enumeration"
    );
    assert_eq!(
        parsed.file_layout.parse_completeness,
        ParseCompleteness::Full
    );
    std::fs::write(repo.path().join(path), b"def host_only():\n    return 3\n").unwrap();
    let report = backfill_missing_file_layouts(&state).unwrap();
    assert_eq!(report.published, 1);
    assert!(report.rederive.is_empty());
    let layout = state
        .graph
        .get_file_layout(&FilePathId::new(path))
        .unwrap()
        .unwrap();
    assert_eq!(layout.parse_completeness, ParseCompleteness::Full);
    assert_eq!(state.graph.entity_count(), 0);
    assert_eq!(
        file_coverage(&state, path)["certifies_enumeration"],
        serde_json::json!(true)
    );
}

#[test]
fn startup_diagnostic_deferred_admission_keeps_recovery_with_its_caller() {
    let repo = tempfile::tempdir().unwrap();
    let state = open_test_state(&repo);
    std::fs::write(
        repo.path().join("orphan.py"),
        b"def orphan():\n    return 7\n",
    )
    .unwrap();
    let generation = authority_generation(&state);
    let admitted = exact_tree_admission(&state, None, TreePublication::DeferredToCaller).unwrap();
    assert!(admitted.deferred_tree.is_some());
    assert!(!admitted.deltas.is_empty());
    assert_eq!(authority_generation(&state), generation);
    assert!(
        crate::semantic_debt::outstanding(&state).is_empty(),
        "a caller-owned transaction must not create standalone recovery debt before it publishes"
    );
}

async fn startup_diagnostic_commit(state: &Arc<DaemonState>) -> (axum::http::StatusCode, String) {
    let request = axum::http::Request::post("/commands/commit")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({
                "operation_id": kin_model::OperationId::new(),
                "timestamp": kin_model::Timestamp::now(),
                "author": "Test Author <test@example.invalid>",
                "message": "record the source change",
            })
            .to_string(),
        ))
        .unwrap();
    let response = tower::ServiceExt::oneshot(crate::api::router(Arc::clone(state)), request)
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

fn startup_diagnostic_orphan(state: &DaemonState) -> kin_model::Entity {
    state
        .graph
        .query_entities(&EntityFilter::default())
        .unwrap()
        .into_iter()
        .find(|entity| entity.name == "orphan" && entity.kind == kin_model::EntityKind::Function)
        .expect("the fixture must contain the function, not only its module")
}

async fn startup_diagnostic_committed_orphan(repo: &tempfile::TempDir) -> Arc<DaemonState> {
    let state = open_test_state(repo);
    std::fs::write(
        repo.path().join("orphan.py"),
        b"def orphan():\n    return 7\n",
    )
    .unwrap();
    let (status, body) = startup_diagnostic_commit(&state).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(crate::semantic_debt::outstanding(&state).is_empty());
    state
}

fn startup_diagnostic_lease_orphan(state: &DaemonState) {
    let entity = startup_diagnostic_orphan(state);
    let session = state
        .coordinator
        .register_session(
            "test",
            "lease owner",
            kin_model::SessionTransport::Mcp,
            None,
            state.layout.working_dir().to_path_buf(),
            kin_model::SessionCapabilities {
                can_write: true,
                can_commit: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(matches!(
        state
            .coordinator
            .register_intent(
                &session,
                vec![kin_model::session::IntentScope::Entity(entity.id)],
                kin_model::session::LockType::Hard,
                "protected function",
                None,
            )
            .unwrap(),
        crate::session_registry::IntentRegistrationResult::Registered { .. }
    ));
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn startup_diagnostic_refused_commit_retains_fallback_debt_and_recovers_after_reopen() {
    let repo = tempfile::tempdir().unwrap();
    let state = startup_diagnostic_committed_orphan(&repo).await;
    let original_line = startup_diagnostic_orphan(&state).span.unwrap().start_line;
    let original_changes = state.graph.to_snapshot().changes.len();
    let generation = authority_generation(&state);
    startup_diagnostic_lease_orphan(&state);
    std::fs::write(
        repo.path().join("orphan.py"),
        format!("{}def orphan():\n    return 8\n", "\n".repeat(17)),
    )
    .unwrap();
    let (status, refusal) = startup_diagnostic_commit(&state).await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{refusal}");
    assert!(refusal.contains("semantics_behind_tree"), "{refusal}");
    assert_eq!(
        authority_generation(&state),
        generation + 1,
        "the fallback must actually publish"
    );
    assert_eq!(state.graph.resolved_tree(), authority_tree(&state));
    assert_eq!(
        state.graph.to_snapshot().changes.len(),
        original_changes,
        "the refused commit must not create a semantic change"
    );
    let body = state
        .graph
        .get_tree_entry(&FilePathId::new("orphan.py"))
        .unwrap()
        .unwrap()
        .blob_identity()
        .unwrap()
        .to_string();
    let layout = state.layout.clone();
    drop(state);
    let restarted = Arc::new(DaemonState::open(layout).unwrap());
    let before = startup_diagnostic_orphan(&restarted)
        .span
        .unwrap()
        .start_line;
    assert_eq!(before, original_line, "the derived parse was not committed");
    drain_semantic_debt(&restarted).await.unwrap();
    let after = startup_diagnostic_orphan(&restarted)
        .span
        .unwrap()
        .start_line;
    let recorded = crate::semantic_debt::outstanding(&restarted);
    let owes_exact_body = recorded
        .iter()
        .any(|entry| entry.path == "orphan.py" && entry.body == body);
    println!(
        "STARTUP_FALLBACK {}",
        serde_json::json!({"before": before, "after": after, "expected": original_line + 17, "debt": recorded})
    );
    assert_eq!(
        (owes_exact_body, after),
        (true, original_line + 17),
        "a successful fallback must retain and recover its exact uncommitted parse"
    );
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn startup_diagnostic_refused_commit_resets_when_fallback_debt_cannot_be_written() {
    let repo = tempfile::tempdir().unwrap();
    let state = startup_diagnostic_committed_orphan(&repo).await;
    let previous = authority_tree(&state);
    let generation = authority_generation(&state);
    startup_diagnostic_lease_orphan(&state);
    let content = b"\n\ndef orphan():\n    return 8\n";
    std::fs::write(repo.path().join("orphan.py"), content).unwrap();
    let marker = state.layout.root().join("semantic-debt.json");
    std::fs::create_dir(&marker).unwrap();
    let (status, refusal) = startup_diagnostic_commit(&state).await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{refusal}");
    assert!(refusal.contains("semantics_behind_tree"), "{refusal}");
    assert_eq!(
        authority_generation(&state),
        generation,
        "unrecorded fallback bytes must not reach authority"
    );
    assert_eq!(authority_tree(&state), previous);
    assert_eq!(
        state.graph.resolved_tree(),
        previous,
        "the refused fallback must reset the derived tree"
    );
    assert!(marker.is_dir());
    assert_eq!(
        std::fs::read(repo.path().join("orphan.py")).unwrap(),
        content
    );
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn startup_diagnostic_deferred_drain_keeps_the_previous_authority_body_owed() {
    let repo = tempfile::tempdir().unwrap();
    let state = startup_diagnostic_committed_orphan(&repo).await;
    std::fs::write(
        repo.path().join("orphan.py"),
        b"\ndef orphan():\n    return 8\n",
    )
    .unwrap();
    exact_tree_admission(&state, None, TreePublication::Standalone).unwrap();
    let previous = authority_tree(&state);
    let old = crate::semantic_debt::outstanding(&state)
        .into_iter()
        .find(|entry| entry.path == "orphan.py")
        .unwrap();
    std::fs::write(
        repo.path().join("orphan.py"),
        b"\n\ndef orphan():\n    return 9\n",
    )
    .unwrap();
    let deferred = sync_filesystem_with_graph_deferring_tree_publication(&state)
        .await
        .unwrap();
    assert!(deferred.is_some());
    assert_eq!(authority_tree(&state), previous);
    assert_ne!(state.graph.resolved_tree(), previous);
    assert!(
        crate::semantic_debt::outstanding(&state).contains(&old),
        "a deferred drain must not retire the body authority still owes"
    );
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn startup_diagnostic_refused_publication_retains_both_bodies() {
    let repo = tempfile::tempdir().unwrap();
    let state = startup_diagnostic_committed_orphan(&repo).await;
    std::fs::write(
        repo.path().join("orphan.py"),
        b"\ndef orphan():\n    return 8\n",
    )
    .unwrap();
    exact_tree_admission(&state, None, TreePublication::Standalone).unwrap();
    let previous = authority_tree(&state);
    let generation = authority_generation(&state);
    let old = crate::semantic_debt::outstanding(&state)
        .into_iter()
        .find(|e| e.path == "orphan.py")
        .unwrap();
    std::fs::write(
        repo.path().join("orphan.py"),
        b"\n\ndef orphan():\n    return 9\n",
    )
    .unwrap();
    std::fs::write(
        repo.path().join("secret.py"),
        br#"def connect():
    password = "s3cret-notekeeper-value"
    return password
"#,
    )
    .unwrap();
    let deferred = sync_filesystem_with_graph_deferring_tree_publication(&state)
        .await
        .unwrap()
        .unwrap();
    let proposed = crate::semantic_debt::SemanticDebt {
        path: "orphan.py".into(),
        body: state
            .graph
            .get_tree_entry(&FilePathId::new("orphan.py"))
            .unwrap()
            .unwrap()
            .blob_identity()
            .unwrap()
            .to_string(),
    };
    assert_ne!(old, proposed);
    let error = publish_exact_workspace_tree(&state, &deferred).unwrap_err();
    assert!(
        error.to_string().contains("CredentialAssignment"),
        "{error}"
    );
    publish_deferred_tree_after_failure(&state, &deferred);
    assert_eq!(authority_generation(&state), generation);
    assert_eq!(authority_tree(&state), previous);
    assert_eq!(state.graph.resolved_tree(), previous);
    let recorded = crate::semantic_debt::outstanding(&state);
    assert!(
        recorded.contains(&old) && recorded.contains(&proposed),
        "a refused publication retains both authority and proposed debt: {recorded:?}"
    );
    let error = drain_semantic_debt(&state)
        .await
        .expect_err("the host still holds the refused proposal, so re-admission must wait");
    assert!(matches!(error, DaemonError::SemanticReadmissionFailed(_)));
    let remaining = crate::semantic_debt::outstanding(&state);
    assert!(remaining.contains(&old));
    assert!(!remaining.contains(&proposed));
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn startup_diagnostic_deferred_drain_still_repairs_unrelated_owed_paths() {
    let repo = tempfile::tempdir().unwrap();
    let state = startup_diagnostic_committed_orphan(&repo).await;
    let original_line = startup_diagnostic_orphan(&state).span.unwrap().start_line;
    std::fs::write(
        repo.path().join("orphan.py"),
        b"\n\ndef orphan():\n    return 8\n",
    )
    .unwrap();
    exact_tree_admission(&state, None, TreePublication::Standalone).unwrap();
    assert_eq!(
        startup_diagnostic_orphan(&state).span.unwrap().start_line,
        original_line
    );
    std::fs::write(
        repo.path().join("target.py"),
        b"def target():\n    return 1\n",
    )
    .unwrap();
    let deferred = sync_filesystem_with_graph_deferring_tree_publication(&state)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        startup_diagnostic_orphan(&state).span.unwrap().start_line,
        original_line + 2,
        "a deferral must still drain unrelated owed paths"
    );
    publish_deferred_tree_after_failure(&state, &deferred);
}

async fn startup_diagnostic_purge(state: &Arc<DaemonState>) -> (axum::http::StatusCode, String) {
    use tower::ServiceExt;
    let response = crate::api::router(Arc::clone(state))
        .oneshot(
            axum::http::Request::post("/commands/purge-ignored")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    serde_json::json!({
                        "confirm": true,
                        "confirm_mass_deletion": true,
                        "operation_id": kin_model::OperationId::new(),
                        "actor": "test",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn startup_diagnostic_purge_fixture(repo: &tempfile::TempDir) -> Arc<DaemonState> {
    let state = startup_diagnostic_committed_orphan(repo).await;
    std::fs::write(
        repo.path().join("retired.py"),
        b"def retired():\n    return 1\n",
    )
    .unwrap();
    let (status, body) = startup_diagnostic_commit(&state).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(crate::semantic_debt::outstanding(&state).is_empty());
    std::fs::write(repo.path().join(".kinignore"), b"retired.py\n").unwrap();
    std::fs::write(
        repo.path().join("orphan.py"),
        format!("{}def orphan():\n    return 8\n", "\n".repeat(17)),
    )
    .unwrap();
    state
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn startup_diagnostic_purge_records_changed_body_for_reopen() {
    let repo = tempfile::tempdir().unwrap();
    let state = startup_diagnostic_purge_fixture(&repo).await;
    let original_line = startup_diagnostic_orphan(&state).span.unwrap().start_line;
    let generation = authority_generation(&state);
    let (status, body) = startup_diagnostic_purge(&state).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let response: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(response["mutated"], serde_json::json!(true));
    assert_eq!(authority_generation(&state), generation + 1);
    assert!(authority_tree(&state)
        .artifact_at_path(&test_repo_path("retired.py"))
        .is_none());
    let hash = state
        .graph
        .get_tree_entry(&FilePathId::new("orphan.py"))
        .unwrap()
        .unwrap()
        .blob_identity()
        .unwrap()
        .to_string();
    let layout = state.layout.clone();
    drop(state);
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    assert_eq!(
        startup_diagnostic_orphan(&reopened)
            .span
            .unwrap()
            .start_line,
        original_line
    );
    drain_semantic_debt(&reopened).await.unwrap();
    let owed = crate::semantic_debt::outstanding(&reopened)
        .iter()
        .any(|entry| entry.path == "orphan.py" && entry.body == hash);
    let after = startup_diagnostic_orphan(&reopened)
        .span
        .unwrap()
        .start_line;
    assert_eq!(
        (owed, after),
        (true, original_line + 17),
        "purge must retain and recover the changed body its complete observation published"
    );
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn startup_diagnostic_purge_refuses_unrecorded_changed_body() {
    let repo = tempfile::tempdir().unwrap();
    let state = startup_diagnostic_purge_fixture(&repo).await;
    let previous = authority_tree(&state);
    let generation = authority_generation(&state);
    let marker = state.layout.root().join("semantic-debt.json");
    assert!(!marker.exists());
    std::fs::create_dir(&marker).unwrap();
    let (status, body) = startup_diagnostic_purge(&state).await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{body}");
    assert_eq!(
        authority_generation(&state),
        generation,
        "purge cannot publish a changed body without durable recovery debt"
    );
    assert_eq!(authority_tree(&state), previous);
    assert_eq!(state.graph.resolved_tree(), previous);
    assert!(marker.is_dir());
}
