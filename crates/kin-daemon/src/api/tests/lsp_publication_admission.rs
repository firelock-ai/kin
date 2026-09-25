// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Regression controls for daemon::lsp_publication.
// Inputs are controlled LSP results over actual parsed/admitted declarations;
// these tests do not start an external language server.

const LSP_PUBLICATION_CALLER: &str = "def run(callback):\n    return callback()\n";

async fn lsp_publication_fixture() -> (tempfile::TempDir, Arc<DaemonState>) {
    let (repo, state) = mcp_lifecycle_fixture();
    for (file, body) in [
        ("target.py", "def work():\n    return 7\n"),
        ("caller.py", LSP_PUBLICATION_CALLER),
        ("first.py", "def first():\n    return 1\n"),
        ("second.py", "def second():\n    return 2\n"),
    ] {
        std::fs::write(repo.path().join(file), body).unwrap();
        waiting_admit(&state, file).await;
    }
    waiting_commit(&state, "LSP publication parsed baseline").await;
    (repo, state)
}

fn lsp_publication_call(
    caller: kin_model::EntityId,
    target: kin_model::EntityId,
) -> kin_model::Relation {
    kin_model::Relation {
        id: kin_model::RelationId::new(),
        kind: RelationKind::Calls,
        src: GraphNodeId::Entity(caller),
        dst: GraphNodeId::Entity(target),
        confidence: 0.95,
        origin: kin_model::RelationOrigin::Lsp,
        created_in: None,
        import_source: None,
        evidence: vec![kin_model::RelationEvidence {
            source_span: Some(kin_model::SourceSpan {
                file: kin_model::FilePathId::new("caller.py"),
                start_byte: 0,
                end_byte: 0,
                start_line: 1,
                start_col: 11,
                end_line: 1,
                end_col: 19,
            }),
            parser_rule: Some("lsp_call_hierarchy".to_owned()),
            ..Default::default()
        }],
    }
}

fn lsp_publication_durable(state: &DaemonState) -> kin_db::GraphSnapshot {
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)
            .unwrap();
    let authority = context.open().unwrap();
    authority
        .read_authority()
        .workspace_graph_snapshot(&context.workspace_id())
        .unwrap()
        .unwrap()
}

fn lsp_publication_same_semantics(left: &kin_db::GraphSnapshot, right: &kin_db::GraphSnapshot) {
    assert_eq!(left.resolved_tree, right.resolved_tree);
    assert_eq!(left.entities, right.entities);
    assert_eq!(left.relations, right.relations);
    assert_eq!(left.external_references, right.external_references);
}

#[tokio::test]
async fn lsp_publication_fence_late_atomic_admit_answer_is_stale_without_warm_cold_split() {
    use crate::daemon::lsp_publication::{QueryInputs, Refused};
    use kin_model::EntityStore as _;
    let (repo, state) = lsp_publication_fixture().await;
    let caller = waiting_entity(&state, "caller.py", "run");
    let target = waiting_entity(&state, "target.py", "work");
    let late = lsp_publication_call(caller.id, target.id);
    let inputs = QueryInputs::capture(&state).await.unwrap();
    assert_eq!(
        inputs.document("caller.py").as_deref(),
        Some(LSP_PUBLICATION_CALLER)
    );
    let owned = Arc::clone(&state);
    let offered = late.clone();
    let (queued, launched) = tokio::sync::oneshot::channel();
    let runtime = tokio::runtime::Handle::current();
    crate::loop_runner::set_admission_capture_hook_for_test(
        &state,
        Box::new(move |state| {
            assert!(state.coordination_gate.try_lock().is_err());
            // Queue the answer at the causal seam. Never wait synchronously for
            // the gate this very admission holds: publication must be free to
            // finish, after which the old query must refuse its answer as stale.
            let mut install = Box::pin(tokio::task::unconstrained(async move {
                let mut pending = crate::daemon::PendingEnrichment::default();
                inputs.absorb(&owned, &mut pending, vec![offered]).await
            }));
            {
                let _entered = runtime.enter();
                let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
                assert!(
                    std::future::Future::poll(install.as_mut(), &mut cx).is_pending(),
                    "installation must wait while admission holds coordination"
                );
            }
            let task = runtime.spawn(install);
            assert!(queued.send(task).is_ok());
        }),
    );
    std::fs::remove_file(repo.path().join("target.py")).unwrap();
    std::fs::write(
        repo.path().join("first.py"),
        "def first():\n    return 11\n",
    )
    .unwrap();
    std::fs::write(
        repo.path().join("second.py"),
        "def second():\n    return 22\n",
    )
    .unwrap();
    let (_, report) = admit_through_api(&router(Arc::clone(&state))).await;
    let task = launched
        .await
        .expect("the exact post-capture seam was reached");
    let installed = tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(installed, Err(Refused::Stale));
    assert_eq!(report["report"]["admitted"], true, "{report}");
    let warm = state.graph.semantic_observation();
    let durable = lsp_publication_durable(&state);
    assert!(!warm.entities.contains_key(&target.id));
    assert!(!warm.relations.contains_key(&late.id));
    assert!(
        !warm
            .relations
            .values()
            .any(kin_index::binding_debt::claims_local_binding_debt),
        "a stale, never-accepted answer cannot invent a historical binding"
    );
    lsp_publication_same_semantics(&warm, &durable);
    assert!(matches!(
        state.graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Checked { .. }
    ));
    let durable_graph =
        kin_db::InMemoryGraph::from_snapshot_without_text_index(durable.clone()).unwrap();
    assert!(matches!(
        durable_graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Checked { .. }
    ));
    println!(
        "LSP fenced admission warm/durable: {}",
        json!({"report":report,"stale_relation_id":late.id,
        "warm_history":format!("{:?}",state.graph.binding_history_observation()),
        "durable_history":format!("{:?}",durable_graph.binding_history_observation())})
    );
    let layout = state.layout.clone();
    drop(state);
    let cold = waiting_cold_start(layout).await;
    let reopened = cold.graph.semantic_observation();
    lsp_publication_same_semantics(&warm, &reopened);
    assert!(matches!(
        cold.graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Checked { .. }
    ));
    binding_disclosure_impact(
        &cold,
        caller.id,
        false,
        "LSP stale answer after canonical cold startup",
    )
    .await;
    assert_eq!(
        std::fs::read_to_string(repo.path().join("caller.py")).unwrap(),
        LSP_PUBLICATION_CALLER
    );
}

#[tokio::test]
async fn lsp_publication_fence_fresh_actual_sources_accept_more_than_one_batch() {
    use crate::daemon::lsp_publication::QueryInputs;
    let (repo, state) = mcp_lifecycle_fixture();
    let targets: String = (0..257)
        .map(|i| format!("def target_{i}():\n    return {i}\n\n"))
        .collect();
    std::fs::write(repo.path().join("caller.py"), LSP_PUBLICATION_CALLER).unwrap();
    waiting_admit(&state, "fresh LSP caller").await;
    std::fs::write(repo.path().join("targets.py"), &targets).unwrap();
    waiting_admit(&state, "fresh LSP targets").await;
    waiting_commit(&state, "fresh LSP source baseline").await;
    let caller = waiting_entity(&state, "caller.py", "run");
    let relations: Vec<_> = (0..257)
        .map(|i| {
            let target = waiting_entity(&state, "targets.py", &format!("target_{i}"));
            lsp_publication_call(caller.id, target.id)
        })
        .collect();
    let inputs = QueryInputs::capture(&state).await.unwrap();
    assert_eq!(
        inputs.document("targets.py").as_deref(),
        Some(targets.as_str())
    );
    let mut pending = crate::daemon::PendingEnrichment::default();
    inputs
        .absorb(&state, &mut pending, relations.clone())
        .await
        .unwrap();
    inputs.current(&state).await.unwrap();
    inputs.flush(&state, &mut pending).await.unwrap();
    inputs.current(&state).await.unwrap();
    let held = state
        .graph
        .get_relations(&caller.id, &[RelationKind::Calls])
        .unwrap();
    assert_eq!(held.len(), 257);
    assert!(relations.iter().all(|relation| held.contains(relation)));
}

#[tokio::test]
async fn lsp_publication_fence_same_identity_body_change_refuses_empty_and_nonempty_answers() {
    use crate::daemon::lsp_publication::{QueryInputs, Refused};
    let (repo, state) = lsp_publication_fixture().await;
    let caller = waiting_entity(&state, "caller.py", "run");
    let target = waiting_entity(&state, "target.py", "work");
    let late = lsp_publication_call(caller.id, target.id);
    let inputs = QueryInputs::capture(&state).await.unwrap();
    std::fs::write(
        repo.path().join("caller.py"),
        "def run(callback):\n    return callback() + 1\n",
    )
    .unwrap();
    waiting_admit(&state, "same entity identity, changed admitted body").await;
    let changed = waiting_entity(&state, "caller.py", "run");
    assert_eq!(
        changed.id, caller.id,
        "identity alone cannot prove a query's source generation"
    );
    assert_ne!(
        changed.metadata.extra["blob_hash"],
        caller.metadata.extra["blob_hash"]
    );
    let mut pending = crate::daemon::PendingEnrichment::default();
    assert_eq!(
        inputs
            .absorb(&state, &mut pending, vec![late.clone()])
            .await,
        Err(Refused::Stale)
    );
    assert_eq!(
        inputs.absorb(&state, &mut pending, vec![]).await,
        Err(Refused::Stale)
    );
    assert_eq!(
        inputs.flush(&state, &mut pending).await,
        Err(Refused::Stale)
    );
    assert_eq!(inputs.current(&state).await, Err(Refused::Stale));
    assert_eq!(
        inputs
            .mark_completed(
                &state,
                &["caller.py".to_owned()],
                crate::daemon::EnrichmentWrite::default(),
                true
            )
            .await,
        Err(Refused::Stale)
    );
    assert!(
        !state
            .lsp_enriched_files
            .lock()
            .unwrap()
            .contains("caller.py"),
        "an empty stale answer cannot mark the edited source complete"
    );
    assert!(!state
        .graph
        .semantic_observation()
        .relations
        .contains_key(&late.id));
}

#[tokio::test]
async fn lsp_publication_fence_actual_parsed_entity_missing_blob_seal_refuses_capture() {
    use crate::daemon::lsp_publication::{QueryInputs, Refused};
    use kin_model::EntityStore as _;
    let (_repo, state) = lsp_publication_fixture().await;
    let mut caller = waiting_entity(&state, "caller.py", "run");
    assert!(caller.metadata.extra.remove("blob_hash").is_some());
    // Explicit corruption control of one real parsed record; no positive
    // source proof is fabricated by this direct negative-fixture mutation.
    let mutation = state.begin_graph_authority_mutation();
    state.graph.upsert_entity(&caller).unwrap();
    drop(mutation);
    assert!(matches!(
        QueryInputs::capture(&state).await,
        Err(Refused::UnprovenSource)
    ));
}

#[tokio::test]
async fn lsp_publication_fence_fresh_empty_answer_can_mark_actual_source_complete() {
    use crate::daemon::lsp_publication::QueryInputs;
    let (_repo, state) = lsp_publication_fixture().await;
    let inputs = QueryInputs::capture(&state).await.unwrap();
    assert_eq!(
        inputs.document("caller.py").as_deref(),
        Some(LSP_PUBLICATION_CALLER)
    );
    let mut pending = crate::daemon::PendingEnrichment::default();
    inputs.absorb(&state, &mut pending, vec![]).await.unwrap();
    inputs.flush(&state, &mut pending).await.unwrap();
    assert!(inputs
        .mark_completed(
            &state,
            &["caller.py".to_owned()],
            crate::daemon::EnrichmentWrite::default(),
            true
        )
        .await
        .unwrap());
    assert!(state
        .lsp_enriched_files
        .lock()
        .unwrap()
        .contains("caller.py"));
    inputs.current(&state).await.unwrap();
}
