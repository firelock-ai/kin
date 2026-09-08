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
        // A distinct later event proves this real loop processes work after
        // all startup planners have run; it does not modify the stranded file.
        let mut attempt = 0;
        loop {
            attempt += 1;
            std::fs::write(
                repo.path().join("sentinel.py"),
                format!("def sentinel_ready():\n    return {attempt}\n"),
            )
            .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            if state
                .graph
                .query_entities(&EntityFilter::default())
                .unwrap()
                .iter()
                .any(|entity| entity.name == "sentinel_ready")
            {
                break;
            }
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
    completed.expect("the full loop must recover orphan and process the later sentinel event");
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
    assert_eq!(recorded.len(), 3);
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
