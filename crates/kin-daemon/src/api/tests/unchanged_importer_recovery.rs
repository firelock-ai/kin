// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

const WAITING_CALLER: &str = "from local import work\n\ndef run():\n    return work(value=1)\n";
const WAITING_TARGET: &str = "def work(value):\n    return value\n";

fn waiting_entity(state: &DaemonState, file: &str, name: &str) -> kin_model::Entity {
    state
        .graph
        .query_entities(&kin_db::EntityFilter {
            file_path: Some(kin_model::FilePathId::new(file)),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .find(|entity| entity.name == name)
        .unwrap()
}

async fn waiting_admit(state: &Arc<DaemonState>, label: &str) {
    let (_, report) = admit_through_api(&router(Arc::clone(state))).await;
    println!("waiting admission {label}: {report}");
    assert_eq!(report["report"]["admitted"], true, "{label}: {report}");
}

async fn waiting_commit(state: &Arc<DaemonState>, label: &str) {
    commit_through_api(
        &router(Arc::clone(state)),
        kin_model::OperationId::new(),
        label,
    )
    .await;
}

// Complete the real canonical startup path before admitting any target changes.
// With host watching disabled, its readiness channel closes only after CAS
// repair finishes. This is admission-route coverage, not watcher coverage.
async fn waiting_cold_start(layout: kin_core::KinLayout) -> Arc<DaemonState> {
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    let state = Arc::new(DaemonState::open(layout).unwrap());
    state
        .filesystem_reconcile_disabled
        .store(true, Ordering::Relaxed);
    let (cancel, receiver) = tokio::sync::watch::channel(false);
    let (armed, ready) = tokio::sync::oneshot::channel();
    let mut task = tokio::spawn(crate::loop_runner::run_loop_armed(
        Arc::clone(&state),
        crate::loop_runner::LoopConfig::default(),
        receiver,
        Some(crate::loop_runner::WatchArmed::new(armed)),
    ));
    let outcome = crate::daemon::await_watch_armed(ready, Duration::from_secs(10)).await;
    let _ = cancel.send(true);
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut task).await;
    if joined.is_err() {
        task.abort();
        let _ = task.await;
    }
    assert_eq!(outcome, crate::daemon::WatchArming::LoopGone);
    joined
        .expect("owned canonical startup stops")
        .expect("owned task joins")
        .expect("canonical startup succeeds");
    state
        .filesystem_reconcile_disabled
        .store(false, Ordering::Relaxed);
    state.is_initialized.store(true, Ordering::Relaxed);
    state
}

fn waiting_assert_unchanged(
    state: &DaemonState,
    file: &str,
    body: &str,
    caller: kin_model::EntityId,
) {
    assert_eq!(
        std::fs::read(state.layout.working_dir().join(file)).unwrap(),
        body.as_bytes()
    );
    assert_eq!(waiting_entity(state, file, "run").id, caller);
    let expected = kin_model::Hash256::from_bytes(kin_blobs::digest(body.as_bytes()).0);
    assert_eq!(
        state
            .graph
            .get_tree_entry(&kin_model::FilePathId::new(file))
            .unwrap(),
        Some(kin_model::TreeEntry::blob(expected, false))
    );
    assert_eq!(
        waiting_entity(state, file, "run").metadata.extra["blob_hash"],
        expected.to_string()
    );
}

async fn waiting_assert_recovered(
    state: &Arc<DaemonState>,
    file: &str,
    body: &str,
    caller: kin_model::EntityId,
    target_file: &str,
    keywords: serde_json::Value,
    label: &str,
) {
    waiting_assert_unchanged(state, file, body, caller);
    let target = waiting_entity(state, target_file, "work");
    let calls = state
        .graph
        .get_relations(&caller, &[kin_model::RelationKind::Calls])
        .unwrap();
    let local: Vec<_> = calls
        .iter()
        .filter(|r| r.dst.as_entity() == Some(target.id))
        .collect();
    let result = mcp_call(
        router(Arc::clone(state)),
        "impact_analysis",
        json!({"entity_ids":[target.id.to_string()], "include_traffic":false}),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "{}", mcp_result_text(&result));
    let impact = tool_result_payload(&result);
    println!(
        "waiting recovery {label}: {}",
        json!({"caller_id":caller,"target_id":target.id,
        "calls":calls,"impact":impact})
    );
    let shape = &impact["entity_impacts"][0]["call_shapes"];
    assert!(
        !local.is_empty() || shape["all_consumers_shaped_calls"] == false,
        "missing unchanged caller must not certify a complete consumer set: {label}: {impact}"
    );
    assert_eq!(
        local.len(),
        1,
        "target-only recovery must restore exactly one local call: {label}: {calls:?}"
    );
    assert!(
        !calls.iter().any(kin_index::is_external_import_placeholder),
        "stale external call: {calls:?}"
    );
    assert_eq!(shape["caller_keyword_names"], keywords, "{label}: {impact}");
    // These Python fixtures have one fully shaped call; JavaScript's current
    // extractor does not certify argument shapes, even when binding succeeds.
    assert_eq!(
        shape["all_consumers_shaped_calls"],
        json!(file.ends_with(".py")),
        "{label}: {impact}"
    );
    assert!(
        impact["affected_callers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entity| entity["id"] == caller.to_string()),
        "caller missing from real impact: {label}: {impact}"
    );
}

async fn waiting_arrival(cold: bool) {
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "caller only").await;
    waiting_commit(&state, "Commit unchanged waiting caller").await;
    let caller = waiting_entity(&state, "caller.py", "run").id;
    let state = if cold {
        let layout = state.layout.clone();
        drop(state);
        waiting_cold_start(layout).await
    } else {
        state
    };
    waiting_assert_unchanged(&state, "caller.py", WAITING_CALLER, caller);
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    waiting_admit(&state, "target arrives").await;
    waiting_assert_recovered(
        &state,
        "caller.py",
        WAITING_CALLER,
        caller,
        "local.py",
        json!(["value"]),
        if cold { "cold arrival" } else { "warm arrival" },
    )
    .await;
    waiting_commit(&state, "Commit target-only arrival").await;
    let layout = state.layout.clone();
    drop(state);
    let state = waiting_cold_start(layout).await;
    waiting_assert_recovered(
        &state,
        "caller.py",
        WAITING_CALLER,
        caller,
        "local.py",
        json!(["value"]),
        "persisted recovery",
    )
    .await;
}

#[tokio::test]
async fn unchanged_importer_warm_target_only_arrival_recovers_impact() {
    waiting_arrival(false).await;
}

#[tokio::test]
async fn unchanged_importer_cold_target_only_arrival_recovers_impact() {
    waiting_arrival(true).await;
}

async fn waiting_recreation(cold: bool, distract_during_missing: bool) {
    let (repo, state) = mcp_lifecycle_fixture();
    // Target first ensures this caller begins resolved rather than obtaining
    // an unresolved entry that would accidentally mask deletion recovery.
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    waiting_admit(&state, "target first").await;
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "resolved caller").await;
    waiting_commit(&state, "Commit resolved import").await;
    let caller = waiting_entity(&state, "caller.py", "run").id;
    let old_target = waiting_entity(&state, "local.py", "work").id;
    waiting_assert_recovered(
        &state,
        "caller.py",
        WAITING_CALLER,
        caller,
        "local.py",
        json!(["value"]),
        "before deletion",
    )
    .await;
    std::fs::remove_file(repo.path().join("local.py")).unwrap();
    waiting_admit(&state, "target deleted").await;
    waiting_assert_unchanged(&state, "caller.py", WAITING_CALLER, caller);
    let calls = state
        .graph
        .get_relations(&caller, &[kin_model::RelationKind::Calls])
        .unwrap();
    println!(
        "waiting after target deletion: {}",
        json!({"old_target":old_target,"calls":calls})
    );
    assert!(state.graph.get_entity(&old_target).unwrap().is_none());
    assert!(calls
        .iter()
        .all(|relation| relation.dst.as_entity() != Some(old_target)));
    waiting_assert_missing_target_incomplete(&state, caller, "after deletion").await;
    waiting_commit(&state, "Commit target-only deletion").await;
    waiting_assert_missing_target_incomplete(&state, caller, "committed deletion").await;
    let state = if cold {
        let layout = state.layout.clone();
        drop(state);
        waiting_cold_start(layout).await
    } else {
        state
    };
    if distract_during_missing {
        std::fs::write(
            repo.path().join("unrelated.py"),
            "def work(value):\n    return value + 100\n",
        )
        .unwrap();
        waiting_admit(&state, "same-name distractor while target remains missing").await;
        let distractor = waiting_entity(&state, "unrelated.py", "work").id;
        let calls = state
            .graph
            .get_relations(&caller, &[kin_model::RelationKind::Calls])
            .unwrap();
        println!("waiting missing-interval distractor calls: {calls:?}");
        waiting_assert_unchanged(&state, "caller.py", WAITING_CALLER, caller);
        waiting_assert_missing_target_incomplete(
            &state,
            caller,
            "after unrelated same-name arrival",
        )
        .await;
        assert!(calls
            .iter()
            .all(|relation| relation.dst.as_entity() != Some(distractor)));
        waiting_commit(&state, "Commit unrelated arrival while target missing").await;
        waiting_assert_missing_target_incomplete(&state, caller, "after committed distraction")
            .await;
    }
    waiting_assert_missing_target_incomplete(&state, caller, "before recreation").await;
    waiting_assert_unchanged(&state, "caller.py", WAITING_CALLER, caller);
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    waiting_admit(&state, "target recreated").await;
    waiting_assert_recovered(
        &state,
        "caller.py",
        WAITING_CALLER,
        caller,
        "local.py",
        json!(["value"]),
        if cold {
            "cold recreation"
        } else {
            "warm recreation"
        },
    )
    .await;
    waiting_commit(&state, "Commit target-only recreation").await;
    let layout = state.layout.clone();
    drop(state);
    let state = waiting_cold_start(layout).await;
    waiting_assert_recovered(
        &state,
        "caller.py",
        WAITING_CALLER,
        caller,
        "local.py",
        json!(["value"]),
        "persisted recreation",
    )
    .await;
}

async fn waiting_assert_missing_target_incomplete(
    state: &Arc<DaemonState>,
    caller: kin_model::EntityId,
    stage: &str,
) {
    let result = mcp_call(
        router(Arc::clone(state)),
        "impact_analysis",
        json!({"entity_ids":[caller.to_string()],"include_traffic":false}),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "{}", mcp_result_text(&result));
    let payload = tool_result_payload(&result);
    println!("waiting missing-target {stage}: {payload}");
    assert_eq!(
        payload["entity_impacts"][0]["call_shapes"]["all_consumers_shaped_calls"], false,
        "withdrawn resolution knowledge must survive commit and startup: {stage}: {payload}"
    );
}

#[tokio::test]
async fn unchanged_importer_warm_target_only_recreation_recovers_impact() {
    waiting_recreation(false, false).await;
}

#[tokio::test]
async fn unchanged_importer_cold_target_only_recreation_recovers_impact() {
    waiting_recreation(true, false).await;
}

#[tokio::test]
async fn unchanged_importer_warm_alias_target_arrival_recovers_impact() {
    let (repo, state) = mcp_lifecycle_fixture();
    let body = "from local import work as invoke\n\ndef run():\n    return invoke(value=1)\n";
    std::fs::write(repo.path().join("caller.py"), body).unwrap();
    waiting_admit(&state, "alias caller only").await;
    waiting_commit(&state, "Commit waiting alias caller").await;
    let caller = waiting_entity(&state, "caller.py", "run").id;
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    waiting_admit(&state, "alias target arrives").await;
    waiting_assert_recovered(
        &state,
        "caller.py",
        body,
        caller,
        "local.py",
        json!(["value"]),
        "alias arrival",
    )
    .await;
}

async fn waiting_javascript_arrival(distractor: bool) {
    let (repo, state) = mcp_lifecycle_fixture();
    let body = "import { work } from './local.js';\nexport function run() { return work(1); }\n";
    let distractor_id = if distractor {
        std::fs::write(
            repo.path().join("unrelated.js"),
            "export function work(value) { return value + 10; }\n",
        )
        .unwrap();
        waiting_admit(&state, "unrelated same-name target").await;
        Some(waiting_entity(&state, "unrelated.js", "work").id)
    } else {
        None
    };
    std::fs::write(repo.path().join("caller.js"), body).unwrap();
    waiting_admit(&state, "relative JS caller only").await;
    waiting_commit(&state, "Commit waiting relative import").await;
    let caller = waiting_entity(&state, "caller.js", "run").id;
    let calls = state
        .graph
        .get_relations(&caller, &[kin_model::RelationKind::Calls])
        .unwrap();
    println!(
        "waiting JS before target arrival: {}",
        json!({"distractor_id":distractor_id,"calls":calls})
    );
    if let Some(id) = distractor_id {
        assert!(
            calls
                .iter()
                .all(|relation| relation.dst.as_entity() != Some(id)),
            "the unrelated same-name declaration must not bind this pinned import: {calls:?}"
        );
    }
    std::fs::write(
        repo.path().join("local.js"),
        "export function work(value) { return value; }\n",
    )
    .unwrap();
    waiting_admit(&state, "relative JS target arrives").await;
    waiting_assert_recovered(
        &state,
        "caller.js",
        body,
        caller,
        "local.js",
        json!([]),
        if distractor {
            "JS arrival with distractor"
        } else {
            "JS arrival control"
        },
    )
    .await;
}

#[tokio::test]
async fn unchanged_importer_warm_relative_js_arrival_recovers_impact() {
    waiting_javascript_arrival(false).await;
}

#[tokio::test]
async fn unchanged_importer_same_name_distractor_does_not_suppress_arrival() {
    waiting_javascript_arrival(true).await;
}

#[tokio::test]
async fn unchanged_importer_dependent_proof_failure_preserves_boundary_and_retry_recovers() {
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "failure-control caller").await;
    waiting_commit(&state, "Commit failure-control waiting caller").await;
    let caller = waiting_entity(&state, "caller.py", "run");
    let original_edges = state
        .graph
        .get_relations(&caller.id, &[kin_model::RelationKind::Calls])
        .unwrap();
    assert_eq!(original_edges.len(), 1);
    assert!(kin_index::is_external_import_placeholder(
        &original_edges[0]
    ));
    assert!(matches!(
        kin_model::EntityStore::binding_history_observation(state.graph.as_ref()),
        kin_model::BindingHistoryObservation::Checked { .. }
    ));
    // Make only the owned local source cache unavailable. Repository authority,
    // graph truth, caller bytes and the dependency cache remain unchanged.
    let hash =
        kin_blobs::Hash256::from_hex(caller.metadata.extra["blob_hash"].as_str().unwrap()).unwrap();
    let source = state.blobs.read(&hash).unwrap();
    assert_eq!(source, WAITING_CALLER.as_bytes());
    state.blobs.delete(&hash).unwrap();
    assert!(state.blobs.read(&hash).is_err());
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    let (_, refused) = admit_through_api(&router(Arc::clone(&state))).await;
    println!("waiting dependent proof refusal: {refused}");
    assert_eq!(refused["report"]["admitted"], false, "{refused}");
    assert_eq!(
        state
            .graph
            .get_relations(&caller.id, &[kin_model::RelationKind::Calls])
            .unwrap(),
        original_edges
    );
    assert!(state
        .graph
        .query_entities(&kin_db::EntityFilter {
            file_path: Some(kin_model::FilePathId::new("local.py")),
            ..Default::default()
        })
        .unwrap()
        .is_empty());
    use kin_review::ImpactGraph;
    assert!(!kin_review::impact::LiveGraph(state.graph.as_ref())
        .call_shape_parse_coverage_complete()
        .unwrap());
    assert_eq!(
        state.graph.get_entity(&caller.id).unwrap(),
        Some(caller.clone())
    );
    assert_eq!(state.blobs.write(&source).unwrap(), hash);
    assert_eq!(state.blobs.read(&hash).unwrap(), source);
    waiting_admit(&state, "dependent proof retry without another host edit").await;
    waiting_assert_recovered(
        &state,
        "caller.py",
        WAITING_CALLER,
        caller.id,
        "local.py",
        json!(["value"]),
        "proof retry",
    )
    .await;
    waiting_commit(
        &state,
        "Commit recovered binding after transient source unavailability",
    )
    .await;
    let layout = state.layout.clone();
    drop(state);
    let state = waiting_cold_start(layout).await;
    waiting_assert_recovered(
        &state,
        "caller.py",
        WAITING_CALLER,
        caller.id,
        "local.py",
        json!(["value"]),
        "cold CAS proof retry",
    )
    .await;
}

#[tokio::test]
async fn unchanged_importer_metadata_proof_failure_recovers_binding_without_blessing_history() {
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "failure-control caller").await;
    waiting_commit(&state, "Commit failure-control waiting caller").await;
    let caller = waiting_entity(&state, "caller.py", "run");
    let original_edges = state
        .graph
        .get_relations(&caller.id, &[kin_model::RelationKind::Calls])
        .unwrap();
    assert_eq!(original_edges.len(), 1);
    assert!(kin_index::is_external_import_placeholder(
        &original_edges[0]
    ));
    // Fault injection changes proof metadata, never the caller text or pending
    // cache. The real admission must reject dependent authority before staging
    // a replacement edge or publishing the target's complete certificate.
    let mut corrupt = caller.clone();
    corrupt
        .metadata
        .extra
        .insert("blob_hash".into(), json!("00".repeat(32)));
    state.graph.upsert_entity(&corrupt).unwrap();
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    let (_, refused) = admit_through_api(&router(Arc::clone(&state))).await;
    println!("waiting dependent proof refusal: {refused}");
    assert_eq!(refused["report"]["admitted"], false, "{refused}");
    assert_eq!(
        state
            .graph
            .get_relations(&caller.id, &[kin_model::RelationKind::Calls])
            .unwrap(),
        original_edges
    );
    assert!(state
        .graph
        .query_entities(&kin_db::EntityFilter {
            file_path: Some(kin_model::FilePathId::new("local.py")),
            ..Default::default()
        })
        .unwrap()
        .is_empty());
    use kin_review::ImpactGraph;
    assert!(!kin_review::impact::LiveGraph(state.graph.as_ref())
        .call_shape_parse_coverage_complete()
        .unwrap());
    state.graph.upsert_entity(&caller).unwrap();
    waiting_admit(&state, "dependent proof retry without another host edit").await;
    waiting_assert_proof_retry_is_unproven(&state, caller.id, "metadata proof retry").await;
    waiting_commit(
        &state,
        "Commit recovered binding with unknown prior history",
    )
    .await;
    let layout = state.layout.clone();
    drop(state);
    let state = waiting_cold_start(layout).await;
    waiting_assert_proof_retry_is_unproven(&state, caller.id, "cold metadata proof retry").await;
}

async fn waiting_assert_proof_retry_is_unproven(
    state: &Arc<DaemonState>,
    caller: kin_model::EntityId,
    label: &str,
) {
    waiting_assert_unchanged(state, "caller.py", WAITING_CALLER, caller);
    let target = waiting_entity(state, "local.py", "work");
    let calls = state
        .graph
        .get_relations(&caller, &[kin_model::RelationKind::Calls])
        .unwrap();
    let local: Vec<_> = calls
        .iter()
        .filter(|r| r.dst.as_entity() == Some(target.id))
        .collect();
    assert_eq!(local.len(), 1, "{label}: {calls:?}");
    assert!(
        !calls.iter().any(kin_index::is_external_import_placeholder),
        "{label}: {calls:?}"
    );
    let result = mcp_call(
        router(Arc::clone(state)),
        "impact_analysis",
        json!({"entity_ids":[target.id.to_string()],"include_traffic":false}),
    )
    .await;
    assert_ne!(result.is_error, Some(true), "{}", mcp_result_text(&result));
    let impact = tool_result_payload(&result);
    println!("waiting unknown recovery {label}: {impact}");
    let shape = &impact["entity_impacts"][0]["call_shapes"];
    assert_eq!(
        shape["caller_keyword_names"],
        json!(["value"]),
        "{label}: {impact}"
    );
    assert_eq!(
        shape["all_consumers_shaped_calls"], false,
        "{label}: {impact}"
    );
    assert!(
        impact["affected_callers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entity| entity["id"] == caller.to_string()),
        "{label}: {impact}"
    );
    let report = &impact["source_derivation"]["report"];
    assert_eq!(report["body_binding"], "current", "{label}: {impact}");
    assert_eq!(report["parse_coverage"], "complete", "{label}: {impact}");
    assert_eq!(report["call_extraction"], "complete", "{label}: {impact}");
    assert_eq!(report["import_resolution"], "complete", "{label}: {impact}");
    assert_eq!(
        report["prior_local_binding"], "unproven",
        "{label}: {impact}"
    );
    assert!(
        report["outstanding_local_binding_obligations"].is_null(),
        "{label}: {impact}"
    );
    assert_eq!(
        kin_model::EntityStore::binding_history_observation(state.graph.as_ref()),
        kin_model::BindingHistoryObservation::Unproven
    );
}

#[tokio::test]
async fn unchanged_importer_cold_watcher_target_arrival_recovers_without_admit() {
    use std::time::Duration;
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "watcher waiting caller").await;
    waiting_commit(&state, "Commit caller before watcher restart").await;
    let caller = waiting_entity(&state, "caller.py", "run").id;
    let layout = state.layout.clone();
    drop(state);
    let state = Arc::new(DaemonState::open(layout).unwrap());
    let (cancel, receiver) = tokio::sync::watch::channel(false);
    let (armed, ready) = tokio::sync::oneshot::channel();
    let mut task = tokio::spawn(crate::loop_runner::run_loop_armed(
        Arc::clone(&state),
        crate::loop_runner::LoopConfig {
            poll_interval_ms: 20,
            batch_size: 64,
        },
        receiver,
        Some(crate::loop_runner::WatchArmed::new(armed)),
    ));
    let outcome = crate::daemon::await_watch_armed(ready, crate::daemon::WATCH_ARMING_BOUND).await;
    let mut recovered = false;
    if outcome == crate::daemon::WatchArming::Armed {
        std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
        // No admission endpoint or caller rewrite: actual watcher/catch-up and
        // canonical startup own both target arrival and dependency recovery.
        recovered = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let target = state
                    .graph
                    .query_entities(&kin_db::EntityFilter {
                        file_path: Some(kin_model::FilePathId::new("local.py")),
                        ..Default::default()
                    })
                    .unwrap()
                    .into_iter()
                    .find(|entity| entity.name == "work");
                if let Some(target) = target {
                    if state
                        .graph
                        .get_relations(&caller, &[kin_model::RelationKind::Calls])
                        .unwrap()
                        .iter()
                        .any(|relation| relation.dst.as_entity() == Some(target.id))
                    {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .is_ok();
    }
    let _ = cancel.send(true);
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut task).await;
    if joined.is_err() {
        task.abort();
        let _ = task.await;
    }
    assert_eq!(outcome, crate::daemon::WatchArming::Armed);
    joined
        .expect("owned watcher stops")
        .expect("watcher task joins")
        .expect("watcher succeeds");
    assert!(recovered, "watcher never recovered unchanged caller");
    waiting_assert_recovered(
        &state,
        "caller.py",
        WAITING_CALLER,
        caller,
        "local.py",
        json!(["value"]),
        "cold watcher arrival",
    )
    .await;
}

#[tokio::test]
async fn unchanged_importer_refused_tree_publication_preserves_call_and_coverage() {
    use kin_review::ImpactGraph;
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    waiting_admit(&state, "publication refusal control").await;
    waiting_commit(&state, "Commit resolved pair before refused removal").await;
    let caller = waiting_entity(&state, "caller.py", "run").id;
    let before = state.graph.to_snapshot();
    assert!(kin_review::impact::LiveGraph(state.graph.as_ref())
        .call_shape_parse_coverage_complete()
        .unwrap());
    std::fs::remove_file(repo.path().join("local.py")).unwrap();
    // The repository's existing synthetic credential scanner fixture refuses
    // the complete prospective tree before any semantic eviction may publish.
    std::fs::write(
        repo.path().join("blocked.py"),
        "API_TOKEN = \"sk-proj-abcd1234efgh5678ijkl\"\n",
    )
    .unwrap();
    let (_, refusal) = admit_through_api(&router(Arc::clone(&state))).await;
    println!("waiting prospective refusal: {refusal}");
    assert_eq!(refusal["report"]["admitted"], false, "{refusal}");
    assert_eq!(refusal["report"]["tree_moved"], false, "{refusal}");
    assert!(refusal.to_string().contains("blocked.py"), "{refusal}");
    let after = state.graph.to_snapshot();
    assert_eq!(after.entities, before.entities);
    assert_eq!(after.relations, before.relations);
    assert_eq!(after.resolved_tree, before.resolved_tree);
    assert!(kin_review::impact::LiveGraph(state.graph.as_ref())
        .call_shape_parse_coverage_complete()
        .unwrap());
    waiting_assert_unchanged(&state, "caller.py", WAITING_CALLER, caller);
    let layout = state.layout.clone();
    drop(state);
    let state = Arc::new(DaemonState::open(layout).unwrap());
    let reopened = state.graph.to_snapshot();
    assert_eq!(reopened.relations, before.relations);
    assert_eq!(reopened.resolved_tree, before.resolved_tree);
    std::fs::remove_file(repo.path().join("blocked.py")).unwrap();
    waiting_admit(&state, "retry removal after policy refusal").await;
    waiting_assert_missing_target_incomplete(&state, caller, "accepted removal retry").await;
}

#[tokio::test]
async fn unchanged_importer_missing_target_distraction_cannot_restore_completeness() {
    waiting_recreation(true, true).await;
}

fn waiting_binding_debt(
    state: &DaemonState,
    file: &str,
) -> Option<kin_index::binding_debt::LocalBindingDebt> {
    let file = kin_model::FilePathId::new(file);
    let artifact = state
        .graph
        .artifact_id_at_path(&kin_model::RepoPath::from_utf8(file.0.clone()).unwrap())
        .unwrap();
    let Some(kin_model::TreeEntry::Blob { hash, .. }) = state.graph.get_tree_entry(&file).unwrap()
    else {
        panic!("admitted blob")
    };
    let relations = state
        .graph
        .get_all_relations_for_node(&kin_model::GraphNodeId::Artifact(artifact))
        .unwrap();
    kin_index::binding_debt::inspect_local_binding_debt(
        &file,
        artifact,
        hash,
        &relations.iter().collect::<Vec<_>>(),
    )
    .unwrap()
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn unchanged_importer_session_target_move_preserves_missing_binding_obligation() {
    let (repo, state) = mcp_lifecycle_fixture();
    let singleton = crate::lifecycle::acquire_singleton_lock(state.layout.root())
        .unwrap()
        .expect("fixture owns the real daemon singleton");
    let runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    waiting_admit(&state, "target before move").await;
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "resolved source before move").await;
    waiting_commit(&state, "Commit before target module move").await;
    let caller = waiting_entity(&state, "caller.py", "run").id;
    let session = state.layout.runs_dir().join("session-waiting-target-move");
    let app = router(Arc::clone(&state));
    materialize_session_through_api(&app, &session).await;
    std::fs::rename(session.join("local.py"), session.join("moved.py")).unwrap();
    reconcile_session_through_api(&app, &session).await;
    waiting_assert_unchanged(&state, "caller.py", WAITING_CALLER, caller);
    let moved = waiting_entity(&state, "moved.py", "work");
    let calls = state
        .graph
        .get_relations(&caller, &[kin_model::RelationKind::Calls])
        .unwrap();
    let impact = mcp_call(
        router(Arc::clone(&state)),
        "impact_analysis",
        json!({"entity_ids":[moved.id.to_string()], "include_traffic":false}),
    )
    .await;
    println!(
        "waiting moved-target actual impact: {}",
        mcp_result_text(&impact)
    );
    println!(
        "waiting after session target move: {}",
        json!({"calls":calls,"debt":waiting_binding_debt(&state, "caller.py")})
    );
    assert!(
        calls
            .iter()
            .all(|relation| relation.dst.as_entity() != Some(moved.id)),
        "an unchanged from-local import must not follow a module path move"
    );
    assert!(waiting_binding_debt(&state, "caller.py").is_some());
    waiting_assert_missing_target_incomplete(&state, caller, "after target session move").await;
    waiting_commit(&state, "Commit moved target missing old module").await;
    let layout = state.layout.clone();
    drop(app);
    drop(runtime);
    drop(state);
    drop(singleton);
    let singleton = crate::lifecycle::acquire_singleton_lock(layout.root())
        .unwrap()
        .expect("fixture owns the real daemon singleton");
    let state = waiting_cold_start(layout).await;
    assert!(waiting_binding_debt(&state, "caller.py").is_some());
    waiting_assert_missing_target_incomplete(&state, caller, "cold moved-target interval").await;
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    let roots_before_copy = ActiveApiRepositoryAuthority::open(&state)
        .unwrap()
        .manager
        .read_authority()
        .roots()
        .clone();
    let (_, ambiguous) = admit_through_api(&router(Arc::clone(&state))).await;
    assert_eq!(ambiguous["report"]["admitted"], false);
    assert!(ambiguous.to_string().contains("identity-underdetermined"));
    assert_eq!(
        ActiveApiRepositoryAuthority::open(&state)
            .unwrap()
            .manager
            .read_authority()
            .roots(),
        &roots_before_copy
    );
    assert!(waiting_binding_debt(&state, "caller.py").is_some());
    // Distinct body makes the new artifact's identity unambiguous while the
    // moved declaration remains admitted and the unchanged import is repaired.
    std::fs::write(
        repo.path().join("local.py"),
        "def work(value):\n    return value + 1\n",
    )
    .unwrap();
    let (_, repaired) = admit_through_api(&router(Arc::clone(&state))).await;
    assert_eq!(
        repaired["report"]["admitted"], true,
        "target recreation: {repaired}"
    );
    assert_eq!(waiting_entity(&state, "moved.py", "work").id, moved.id);
    assert_ne!(waiting_entity(&state, "local.py", "work").id, moved.id);
    waiting_assert_recovered(
        &state,
        "caller.py",
        WAITING_CALLER,
        caller,
        "local.py",
        json!(["value"]),
        "post-move original-module recreation",
    )
    .await;
    assert!(waiting_binding_debt(&state, "caller.py").is_none());
    let recreated = waiting_entity(&state, "local.py", "work").id;
    waiting_commit(&state, "Commit restored module beside moved identity").await;
    let layout = state.layout.clone();
    drop(state);
    drop(singleton);
    let _singleton = crate::lifecycle::acquire_singleton_lock(layout.root())
        .unwrap()
        .expect("fixture owns the real daemon singleton");
    let state = waiting_cold_start(layout).await;
    assert_eq!(waiting_entity(&state, "moved.py", "work").id, moved.id);
    assert_eq!(waiting_entity(&state, "local.py", "work").id, recreated);
    assert!(waiting_binding_debt(&state, "caller.py").is_none());
    waiting_assert_recovered(
        &state,
        "caller.py",
        WAITING_CALLER,
        caller,
        "local.py",
        json!(["value"]),
        "cold repair preserves moved and recreated identities",
    )
    .await;
}

#[tokio::test]
async fn unchanged_importer_typed_obligation_survives_real_commit_and_cold_repair() {
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    waiting_admit(&state, "typed debt target").await;
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "typed debt caller").await;
    waiting_commit(&state, "Commit typed-debt resolved source").await;
    let caller = waiting_entity(&state, "caller.py", "run").id;
    std::fs::remove_file(repo.path().join("local.py")).unwrap();
    waiting_admit(&state, "typed debt target removed").await;
    let debt =
        waiting_binding_debt(&state, "caller.py").expect("real removal retains prior binding");
    println!("typed binding debt before commit: {}", json!(debt));
    waiting_commit(&state, "Commit missing local binding").await;
    assert_eq!(
        waiting_binding_debt(&state, "caller.py"),
        Some(debt.clone())
    );
    let layout = state.layout.clone();
    drop(state);
    let state = waiting_cold_start(layout).await;
    assert_eq!(
        waiting_binding_debt(&state, "caller.py"),
        Some(debt.clone())
    );
    std::fs::write(
        repo.path().join("unrelated.py"),
        "def work(value):\n    return value + 100\n",
    )
    .unwrap();
    waiting_admit(&state, "typed debt distractor").await;
    assert_eq!(waiting_binding_debt(&state, "caller.py"), Some(debt));
    waiting_commit(&state, "Commit retained binding debt after distraction").await;
    waiting_assert_unchanged(&state, "caller.py", WAITING_CALLER, caller);
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    waiting_admit(&state, "typed debt genuine repair").await;
    assert!(waiting_binding_debt(&state, "caller.py").is_none());
    waiting_assert_recovered(
        &state,
        "caller.py",
        WAITING_CALLER,
        caller,
        "local.py",
        json!(["value"]),
        "typed debt repaired",
    )
    .await;
    waiting_commit(&state, "Commit discharged binding debt").await;
    let layout = state.layout.clone();
    drop(state);
    let state = waiting_cold_start(layout).await;
    assert!(waiting_binding_debt(&state, "caller.py").is_none());
    waiting_assert_recovered(
        &state,
        "caller.py",
        WAITING_CALLER,
        caller,
        "local.py",
        json!(["value"]),
        "cold typed debt repair",
    )
    .await;
}

async fn waiting_debt_identity_collision(authority: bool) {
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    std::fs::write(
        repo.path().join("unrelated.py"),
        "def unrelated():\n    return 0\n",
    )
    .unwrap();
    waiting_admit(&state, "collision-control admitted sources").await;
    let source_artifact = state
        .graph
        .artifact_id_at_path(&kin_model::RepoPath::from_utf8("caller.py").unwrap())
        .unwrap();
    let foreign = kin_model::Relation {
        id: kin_index::binding_debt::local_binding_debt_id(source_artifact),
        kind: kin_model::RelationKind::References,
        src: kin_model::GraphNodeId::Entity(waiting_entity(&state, "unrelated.py", "unrelated").id),
        dst: kin_model::GraphNodeId::Entity(waiting_entity(&state, "caller.py", "run").id),
        confidence: 1.0,
        origin: kin_model::RelationOrigin::Manual,
        created_in: None,
        import_source: None,
        evidence: vec![],
    };
    state
        .graph
        .apply_transaction_delta(&kin_model::TransactionDelta {
            relation_deltas: vec![kin_model::RelationDelta::Added {
                new: foreign.clone(),
            }],
            ..Default::default()
        })
        .unwrap();
    let path = kin_model::RepoPath::from_utf8("local.py").unwrap();
    let artifact = state.graph.artifact_id_at_path(&path).unwrap();
    let entry = state
        .graph
        .get_tree_entry(&kin_model::FilePathId::new("local.py"))
        .unwrap()
        .unwrap();
    let vacated =
        crate::repository_commit::VacatedPaths::from_deltas(&[kin_model::TreeDelta::Removed {
            artifact_id: artifact,
            old: kin_model::LocatedEntry::new(path, entry),
        }]);
    let result = if authority {
        crate::repository_commit::retire_semantics_on_vacated(&state.graph.to_snapshot(), &vacated)
            .map(|delta| delta.relation_deltas().to_vec())
    } else {
        crate::repository_commit::retire_live_semantics_on_vacated(state.graph.as_ref(), &vacated)
            .map(|(_, relations)| relations)
    };
    println!("foreign debt identity authority={authority}: {result:?}");
    assert!(
        result.is_err(),
        "reserved debt identity occupied by unrelated endpoints must refuse before publication"
    );
    assert_eq!(
        state
            .graph
            .get_all_relations_for_node(&foreign.src)
            .unwrap()
            .into_iter()
            .find(|r| r.id == foreign.id),
        Some(foreign)
    );
    assert!(state
        .graph
        .get_entity(&waiting_entity(&state, "local.py", "work").id)
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn unchanged_importer_authority_debt_collision_refuses_without_overwriting_foreign_fact() {
    waiting_debt_identity_collision(true).await;
}

#[tokio::test]
async fn unchanged_importer_live_debt_collision_refuses_before_publication() {
    waiting_debt_identity_collision(false).await;
}

async fn waiting_live_collision_route(session_route: bool, move_target: bool) {
    let (repo, state) = mcp_lifecycle_fixture();
    let singleton = session_route.then(|| {
        crate::lifecycle::acquire_singleton_lock(state.layout.root())
            .unwrap()
            .expect("session fixture owns the real daemon singleton")
    });
    let _runtime = singleton.as_ref().map(|singleton| {
        state
            .prepared_publication
            .register(singleton, state.layout.root())
            .unwrap()
    });
    for (path, body) in [
        ("local.py", WAITING_TARGET),
        ("caller.py", WAITING_CALLER),
        ("unrelated.py", "def unrelated():\n    return 0\n"),
    ] {
        std::fs::write(repo.path().join(path), body).unwrap();
    }
    waiting_admit(&state, "served collision sources").await;
    waiting_commit(&state, "Commit authority without live collision").await;
    let app = router(Arc::clone(&state));
    let session = state.layout.runs_dir().join("session-live-debt-collision");
    if session_route {
        materialize_session_through_api(&app, &session).await;
    }
    let source_artifact = state
        .graph
        .artifact_id_at_path(&kin_model::RepoPath::from_utf8("caller.py").unwrap())
        .unwrap();
    let foreign = kin_model::Relation {
        id: kin_index::binding_debt::local_binding_debt_id(source_artifact),
        kind: kin_model::RelationKind::References,
        src: kin_model::GraphNodeId::Entity(waiting_entity(&state, "unrelated.py", "unrelated").id),
        dst: kin_model::GraphNodeId::Entity(waiting_entity(&state, "caller.py", "run").id),
        confidence: 1.0,
        origin: kin_model::RelationOrigin::Manual,
        created_in: None,
        import_source: None,
        evidence: vec![],
    };
    state
        .graph
        .apply_transaction_delta(&kin_model::TransactionDelta {
            relation_deltas: vec![kin_model::RelationDelta::Added {
                new: foreign.clone(),
            }],
            ..Default::default()
        })
        .unwrap();
    let before = state.graph.to_snapshot();
    let roots = ActiveApiRepositoryAuthority::open(&state)
        .unwrap()
        .manager
        .read_authority()
        .roots()
        .clone();
    let changed_root = if session_route {
        session.as_path()
    } else {
        repo.path()
    };
    if move_target {
        std::fs::rename(changed_root.join("local.py"), changed_root.join("moved.py")).unwrap();
    } else {
        std::fs::remove_file(changed_root.join("local.py")).unwrap();
    }
    let request = if session_route {
        Request::post("/reconcile")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"session_dir": session, "confirm_mass_deletion": false}).to_string(),
            ))
            .unwrap()
    } else {
        admit_request()
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body);
    let after_roots = ActiveApiRepositoryAuthority::open(&state)
        .unwrap()
        .manager
        .read_authority()
        .roots()
        .clone();
    println!("live-only debt collision session={session_route}: status={status} body={body} roots_before={roots:?} roots_after={after_roots:?}");
    assert!(
        body.contains("malformed binding debt evidence"),
        "must reach binding collision refusal: {body}"
    );
    if !session_route {
        let report: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            report["report"]["repository_authority_moved"],
            json!(after_roots != roots)
        );
        assert_eq!(report["mutated"], json!(after_roots != roots));
        assert_eq!(report["report"]["tree_moved"], false);
        assert_eq!(report["report"]["admitted"], false);
        assert!(!body.contains("Graph authority is unchanged"));
    }
    assert_eq!(
        after_roots, roots,
        "live-only refusal must precede authority publication"
    );
    let after = state.graph.to_snapshot();
    assert_eq!(after.resolved_tree, before.resolved_tree);
    assert_eq!(after.entities, before.entities);
    assert_eq!(after.relations, before.relations);
    assert_eq!(
        state.graph.get_relation_by_id(&foreign.id),
        Some(foreign.clone())
    );
    assert_eq!(
        std::fs::read(repo.path().join("caller.py")).unwrap(),
        WAITING_CALLER.as_bytes()
    );
    if session_route {
        assert!(
            repo.path().join("local.py").exists(),
            "refused session must not change primary projection"
        );
        assert_eq!(
            std::fs::read(repo.path().join("local.py")).unwrap(),
            WAITING_TARGET.as_bytes()
        );
    } else {
        assert!(!repo.path().join("local.py").exists());
    }
    // Correct only the deliberately injected live corruption, then retry the
    // identical source observation through the same product route.
    state
        .graph
        .apply_transaction_delta(&kin_model::TransactionDelta {
            relation_deltas: vec![kin_model::RelationDelta::Removed { old: foreign }],
            ..Default::default()
        })
        .unwrap();
    if session_route {
        reconcile_session_through_api(&app, &session).await;
    } else {
        waiting_admit(&state, "retry after removing live collision").await;
    }
    assert!(waiting_binding_debt(&state, "caller.py").is_some());
    assert!(state
        .graph
        .resolved_tree()
        .artifact_at_path(&kin_model::RepoPath::from_utf8("local.py").unwrap())
        .is_none());
    assert!(!repo.path().join("local.py").exists());
    assert_eq!(
        std::fs::read(repo.path().join("caller.py")).unwrap(),
        WAITING_CALLER.as_bytes()
    );
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn unchanged_importer_live_collision_served_session_refuses_before_authority() {
    waiting_live_collision_route(true, false).await;
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn unchanged_importer_live_collision_canonical_admit_refuses_before_authority() {
    waiting_live_collision_route(false, false).await;
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn unchanged_importer_session_source_move_preserves_binding_debt_and_repairs() {
    let (repo, state) = mcp_lifecycle_fixture();
    let singleton = crate::lifecycle::acquire_singleton_lock(state.layout.root())
        .unwrap()
        .expect("fixture owns the real daemon singleton");
    let runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "source move resolved pair").await;
    waiting_commit(&state, "Commit pair before source move").await;
    std::fs::remove_file(repo.path().join("local.py")).unwrap();
    waiting_admit(&state, "source move missing target").await;
    waiting_commit(&state, "Commit source binding obligation before move").await;
    let debt = waiting_binding_debt(&state, "caller.py").unwrap();
    let caller = waiting_entity(&state, "caller.py", "run").id;
    let artifact = state
        .graph
        .artifact_id_at_path(&RepoPath::from_utf8("caller.py").unwrap())
        .unwrap();
    let debt_id = kin_index::binding_debt::local_binding_debt_id(artifact);
    let app = router(Arc::clone(&state));
    let session = state
        .layout
        .runs_dir()
        .join("session-move-held-source-debt");
    materialize_session_through_api(&app, &session).await;
    std::fs::rename(session.join("caller.py"), session.join("renamed.py")).unwrap();
    let roots = ActiveApiRepositoryAuthority::open(&state)
        .unwrap()
        .manager
        .read_authority()
        .roots()
        .clone();
    let response = app
        .oneshot(
            Request::post("/reconcile")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"session_dir":session,"confirm_mass_deletion":false}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .unwrap();
    let after_roots = ActiveApiRepositoryAuthority::open(&state)
        .unwrap()
        .manager
        .read_authority()
        .roots()
        .clone();
    println!("source-owned debt move status={status} body={} roots_before={roots:?} roots_after={after_roots:?} held_debt={:?}", String::from_utf8_lossy(&body), state.graph.get_relation_by_id(&debt_id));
    assert!(status.is_success(), "{}", String::from_utf8_lossy(&body));
    let relocated = waiting_binding_debt(&state, "renamed.py")
        .expect("successful source move keeps canonical binding obligation");
    assert_eq!(
        relocated.source_file,
        kin_model::FilePathId::new("renamed.py")
    );
    assert_eq!(relocated.obligations.len(), debt.obligations.len());
    for (new, old) in relocated.obligations.iter().zip(&debt.obligations) {
        assert_eq!(new.retired_relation, old.retired_relation);
        assert_eq!(new.source_digest, old.source_digest);
        assert_eq!(
            new.prior_source_file,
            Some(kin_model::FilePathId::new("caller.py"))
        );
    }
    waiting_assert_unchanged(&state, "renamed.py", WAITING_CALLER, caller);
    waiting_commit(&state, "Commit relocated source obligation").await;
    let layout = state.layout.clone();
    drop(runtime);
    drop(state);
    drop(singleton);
    let _singleton = crate::lifecycle::acquire_singleton_lock(layout.root())
        .unwrap()
        .expect("fixture owns the real daemon singleton");
    let state = waiting_cold_start(layout).await;
    assert_eq!(waiting_binding_debt(&state, "renamed.py"), Some(relocated));
    waiting_assert_unchanged(&state, "renamed.py", WAITING_CALLER, caller);
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    waiting_admit(&state, "repair after source obligation move").await;
    waiting_assert_recovered(
        &state,
        "renamed.py",
        WAITING_CALLER,
        caller,
        "local.py",
        json!(["value"]),
        "relocated debt repair",
    )
    .await;
    assert!(waiting_binding_debt(&state, "renamed.py").is_none());
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn unchanged_importer_move_collision_session_refuses_and_retries() {
    waiting_live_collision_route(true, true).await;
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn unchanged_importer_move_collision_canonical_refuses_and_retries() {
    waiting_live_collision_route(false, true).await;
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn unchanged_importer_session_source_move_keeps_valid_local_binding() {
    let (repo, state) = mcp_lifecycle_fixture();
    let singleton = crate::lifecycle::acquire_singleton_lock(state.layout.root())
        .unwrap()
        .expect("fixture owns the real daemon singleton");
    let runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    std::fs::write(repo.path().join("local.py"), WAITING_TARGET).unwrap();
    std::fs::write(repo.path().join("caller.py"), WAITING_CALLER).unwrap();
    waiting_admit(&state, "valid source move pair").await;
    waiting_commit(&state, "Commit valid source move pair").await;
    let caller = waiting_entity(&state, "caller.py", "run").id;
    let target = waiting_entity(&state, "local.py", "work").id;
    let relation = state
        .graph
        .get_relations(&caller, &[kin_model::RelationKind::Calls])
        .unwrap()
        .into_iter()
        .find(|r| r.dst.as_entity() == Some(target))
        .unwrap();
    let session = state.layout.runs_dir().join("session-valid-source-move");
    let app = router(Arc::clone(&state));
    materialize_session_through_api(&app, &session).await;
    std::fs::rename(session.join("caller.py"), session.join("renamed.py")).unwrap();
    reconcile_session_through_api(&app, &session).await;
    waiting_assert_recovered(
        &state,
        "renamed.py",
        WAITING_CALLER,
        caller,
        "local.py",
        json!(["value"]),
        "valid moved source",
    )
    .await;
    assert!(waiting_binding_debt(&state, "renamed.py").is_none());
    let updated = state.graph.get_relation_by_id(&relation.id).unwrap();
    assert_eq!(updated.src, relation.src);
    assert_eq!(updated.dst, relation.dst);
    assert!(updated
        .evidence
        .iter()
        .filter_map(|e| e.source_span.as_ref())
        .all(|s| s.file.0 == "renamed.py"));
    waiting_commit(&state, "Commit valid moved source binding").await;
    let layout = state.layout.clone();
    drop(app);
    drop(runtime);
    drop(state);
    drop(singleton);
    let _singleton = crate::lifecycle::acquire_singleton_lock(layout.root())
        .unwrap()
        .expect("fixture owns the real daemon singleton");
    let state = waiting_cold_start(layout).await;
    waiting_assert_recovered(
        &state,
        "renamed.py",
        WAITING_CALLER,
        caller,
        "local.py",
        json!(["value"]),
        "cold valid source move",
    )
    .await;
    assert!(waiting_binding_debt(&state, "renamed.py").is_none());
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn unchanged_importer_session_directory_move_keeps_relative_alias_binding() {
    const BODY: &str =
        "from .local import work as invoke\n\ndef run():\n    return invoke(value=1)\n";
    let (repo, state) = mcp_lifecycle_fixture();
    let singleton = crate::lifecycle::acquire_singleton_lock(state.layout.root())
        .unwrap()
        .expect("fixture owns the real daemon singleton");
    let runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    std::fs::create_dir(repo.path().join("pkg")).unwrap();
    std::fs::write(repo.path().join("pkg/local.py"), WAITING_TARGET).unwrap();
    std::fs::write(repo.path().join("pkg/caller.py"), BODY).unwrap();
    waiting_admit(&state, "relative alias pair").await;
    waiting_commit(&state, "Commit relative alias pair").await;
    let caller = waiting_entity(&state, "pkg/caller.py", "run").id;
    let target = waiting_entity(&state, "pkg/local.py", "work").id;
    waiting_assert_recovered(
        &state,
        "pkg/caller.py",
        BODY,
        caller,
        "pkg/local.py",
        json!(["value"]),
        "before directory move",
    )
    .await;
    let session = state.layout.runs_dir().join("session-valid-directory-move");
    let app = router(Arc::clone(&state));
    materialize_session_through_api(&app, &session).await;
    std::fs::rename(session.join("pkg"), session.join("moved")).unwrap();
    reconcile_session_through_api(&app, &session).await;
    assert_eq!(waiting_entity(&state, "moved/local.py", "work").id, target);
    waiting_assert_recovered(
        &state,
        "moved/caller.py",
        BODY,
        caller,
        "moved/local.py",
        json!(["value"]),
        "valid directory move",
    )
    .await;
    assert!(waiting_binding_debt(&state, "moved/caller.py").is_none());
    waiting_commit(&state, "Commit valid moved directory binding").await;
    let layout = state.layout.clone();
    drop(app);
    drop(runtime);
    drop(state);
    drop(singleton);
    let _singleton = crate::lifecycle::acquire_singleton_lock(layout.root())
        .unwrap()
        .expect("fixture owns the real daemon singleton");
    let state = waiting_cold_start(layout).await;
    waiting_assert_recovered(
        &state,
        "moved/caller.py",
        BODY,
        caller,
        "moved/local.py",
        json!(["value"]),
        "cold valid directory move",
    )
    .await;
    assert!(waiting_binding_debt(&state, "moved/caller.py").is_none());
}

#[tokio::test]
#[serial_test::serial(commit_phase_capture)]
async fn unchanged_importer_session_source_only_relative_move_rebinds_current_module() {
    const BODY: &str =
        "from .local import work as invoke\n\ndef run():\n    return invoke(value=1)\n";
    let (repo, state) = mcp_lifecycle_fixture();
    let singleton = crate::lifecycle::acquire_singleton_lock(state.layout.root())
        .unwrap()
        .expect("fixture owns the real daemon singleton");
    let runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    std::fs::create_dir(repo.path().join("pkg")).unwrap();
    std::fs::write(repo.path().join("pkg/local.py"), WAITING_TARGET).unwrap();
    std::fs::write(repo.path().join("pkg/caller.py"), BODY).unwrap();
    waiting_admit(&state, "source-only relative pair").await;
    waiting_commit(&state, "Commit source-only relative pair").await;
    let caller = waiting_entity(&state, "pkg/caller.py", "run").id;
    let old_target = waiting_entity(&state, "pkg/local.py", "work").id;
    waiting_assert_recovered(
        &state,
        "pkg/caller.py",
        BODY,
        caller,
        "pkg/local.py",
        json!(["value"]),
        "before source-only move",
    )
    .await;
    let session = state
        .layout
        .runs_dir()
        .join("session-source-only-relative-move");
    let app = router(Arc::clone(&state));
    materialize_session_through_api(&app, &session).await;
    std::fs::create_dir(session.join("other")).unwrap();
    std::fs::rename(
        session.join("pkg/caller.py"),
        session.join("other/caller.py"),
    )
    .unwrap();
    reconcile_session_through_api(&app, &session).await;
    waiting_assert_unchanged(&state, "other/caller.py", BODY, caller);
    assert!(state
        .graph
        .get_relations(&caller, &[kin_model::RelationKind::Calls])
        .unwrap()
        .iter()
        .all(|r| r.dst.as_entity() != Some(old_target)));
    let debt = waiting_binding_debt(&state, "other/caller.py")
        .expect("source-relative move retains unresolved binding");
    assert!(debt.obligations.iter().all(
        |o| o.prior_source_file.as_ref() == Some(&kin_model::FilePathId::new("pkg/caller.py"))
    ));
    waiting_assert_missing_target_incomplete(&state, caller, "source-only relative move").await;
    waiting_commit(&state, "Commit source-only moved obligation").await;
    let layout = state.layout.clone();
    drop(app);
    drop(runtime);
    drop(state);
    drop(singleton);
    let singleton = crate::lifecycle::acquire_singleton_lock(layout.root())
        .unwrap()
        .expect("fixture owns the real daemon singleton");
    let state = waiting_cold_start(layout).await;
    assert_eq!(waiting_binding_debt(&state, "other/caller.py"), Some(debt));
    waiting_assert_missing_target_incomplete(&state, caller, "cold source-only relative move")
        .await;
    std::fs::write(
        repo.path().join("other/unrelated.py"),
        "def work(value):\n    return value + 2\n",
    )
    .unwrap();
    waiting_admit(&state, "unrelated same-name target after source move").await;
    let distraction = waiting_entity(&state, "other/unrelated.py", "work").id;
    assert!(state
        .graph
        .get_relations(&caller, &[kin_model::RelationKind::Calls])
        .unwrap()
        .iter()
        .all(|r| r.dst.as_entity() != Some(distraction)));
    assert!(waiting_binding_debt(&state, "other/caller.py").is_some());
    waiting_assert_missing_target_incomplete(&state, caller, "unrelated same-name relative target")
        .await;
    std::fs::write(
        repo.path().join("other/local.py"),
        "def work(value):\n    return value + 1\n",
    )
    .unwrap();
    waiting_admit(&state, "new source-relative module arrives").await;
    println!(
        "source-relative repair remaining debt: {:?}",
        waiting_binding_debt(&state, "other/caller.py")
    );
    assert_eq!(
        waiting_entity(&state, "pkg/local.py", "work").id,
        old_target
    );
    waiting_assert_recovered(
        &state,
        "other/caller.py",
        BODY,
        caller,
        "other/local.py",
        json!(["value"]),
        "source-only relative repair",
    )
    .await;
    assert!(waiting_binding_debt(&state, "other/caller.py").is_none());
    let repaired_target = waiting_entity(&state, "other/local.py", "work").id;
    waiting_commit(&state, "Commit relocated source binding repair").await;
    let layout = state.layout.clone();
    drop(state);
    drop(singleton);
    let _singleton = crate::lifecycle::acquire_singleton_lock(layout.root())
        .unwrap()
        .expect("fixture owns the real daemon singleton");
    let state = waiting_cold_start(layout).await;
    assert_eq!(
        waiting_entity(&state, "pkg/local.py", "work").id,
        old_target
    );
    assert_eq!(
        waiting_entity(&state, "other/local.py", "work").id,
        repaired_target
    );
    assert!(waiting_binding_debt(&state, "other/caller.py").is_none());
    waiting_assert_recovered(
        &state,
        "other/caller.py",
        BODY,
        caller,
        "other/local.py",
        json!(["value"]),
        "cold source-only relative repair",
    )
    .await;
}
