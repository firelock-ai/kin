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
async fn lsp_publication_retires_old_contexts_and_restores_exact_binding_witness() {
    use crate::daemon::lsp_publication::{QueryInputs, Refused};
    use kin_model::EntityStore as _;
    let (repo, state) = lsp_publication_fixture().await;
    let caller = waiting_entity(&state, "caller.py", "run");
    assert!(matches!(
        state.graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Checked { .. }
    ));
    let context = |version: &str| kin_model::ProofContext {
        language: kin_model::LanguageId::Python,
        resolver: "lsp:pyright".to_owned(),
        resolver_version: version.to_owned(),
        configuration_hash: kin_model::Hash256::from_bytes([1; 32]),
        environment_hash: kin_model::Hash256::from_bytes([2; 32]),
        environment_summary: String::new(),
    };
    let mut previous_ledger = None;
    let mut previous_validation = None;
    let mut previous_context = None;
    for version in ["1", "2"] {
        let context = context(version);
        let proof = kin_model::ResolutionRecord::ProofContext(context.clone());
        let span = caller.span.as_ref().unwrap();
        let ledger = kin_model::ResolutionRecord::CallSites(kin_model::CallSiteLedger {
            caller: caller.id,
            behavior_hash: caller.fingerprint.behavior_hash,
            body_hash: kin_model::Hash256::from_bytes(kin_blobs::digest_bytes(
                LSP_PUBLICATION_CALLER.as_bytes(),
            )),
            context: proof.id(),
            census: 1,
            sites: vec![kin_model::CallSite {
                offset: (LSP_PUBLICATION_CALLER.find("callback()").unwrap() - span.start_byte)
                    .try_into()
                    .unwrap(),
                length: "callback".len().try_into().unwrap(),
                state: kin_model::CallSiteState::Unresolved {
                    reason: kin_model::UnresolvedReason::NoAnswer,
                },
            }],
        });
        let validation =
            kin_model::ResolutionRecord::ContextValidation(kin_model::ContextValidation {
                language: kin_model::LanguageId::Python,
                state: kin_model::ContextValidationState::Validated { context },
            });
        let replace = |old, new| match old {
            None => kin_model::ResolutionRecordDelta::Added { new },
            Some(old) => kin_model::ResolutionRecordDelta::Modified { old, new },
        };
        state
            .graph
            .apply_resolution_record_deltas(&[
                kin_model::ResolutionRecordDelta::Added { new: proof.clone() },
                replace(previous_ledger, ledger.clone()),
                replace(previous_validation, validation.clone()),
            ])
            .unwrap();
        assert_eq!(
            state.graph.binding_history_observation(),
            kin_model::BindingHistoryObservation::Unproven
        );
        let inputs = QueryInputs::capture(&state).await.unwrap();
        state.save_snapshot().unwrap();
        inputs
            .current(&state)
            .await
            .expect("collecting unused nodes at a checkpoint must not invalidate the next file");
        let live = state.graph.semantic_observation();
        let durable = lsp_publication_durable(&state);
        lsp_publication_same_semantics(&live, &durable);
        assert_eq!(
            live.resolution_records, durable.resolution_records,
            "a retired proof context must leave the live graph as well as authority"
        );
        if let Some(old_context) = previous_context {
            assert!(!live.resolution_records.contains_key(&old_context));
        }
        assert!(matches!(
            state.graph.binding_history_observation(),
            kin_model::BindingHistoryObservation::Checked { .. }
        ));
        if version == "2" {
            assert_eq!(
                inputs.document("second.py").as_deref(),
                Some("def second():\n    return 2\n")
            );
            let mut pending = crate::daemon::PendingEnrichment::default();
            inputs.absorb(&state, &mut pending, vec![]).await.unwrap();
            inputs.flush(&state, &mut pending).await.unwrap();
            assert!(inputs
                .record_file_completed(&state, "second.py")
                .await
                .unwrap());
            std::fs::write(
                repo.path().join("second.py"),
                "def second():\n    return 22\n",
            )
            .unwrap();
            waiting_admit(&state, "external source edit after context collection").await;
            assert_eq!(
                inputs.current(&state).await,
                Err(Refused::Stale),
                "the checkpoint must not weaken the intervening source-writer fence"
            );
        }
        previous_ledger = Some(ledger);
        previous_validation = Some(validation);
        previous_context = Some(proof.id());
    }
    let layout = state.layout.clone();
    drop(state);
    let cold = waiting_cold_start(layout).await;
    assert!(matches!(
        cold.graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Checked { .. }
    ));
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

#[tokio::test]
async fn lsp_publication_records_exact_withdrawals_and_keeps_checked_history() {
    use crate::daemon::lsp_publication::QueryInputs;
    use kin_index::binding_debt::{claims_local_binding_debt, decode_local_binding_debt};
    use kin_model::EntityStore as _;
    let (repo, state) = lsp_publication_fixture().await;
    let body = "from target import work\n\ndef run():\n    return work()\n";
    std::fs::write(repo.path().join("caller.py"), body).unwrap();
    waiting_admit(&state, "admit a real parser binding").await;
    waiting_commit(&state, "record parser binding baseline").await;
    let caller = waiting_entity(&state, "caller.py", "run");
    let target = waiting_entity(&state, "target.py", "work");
    let replacement = waiting_entity(&state, "first.py", "first");
    let parsed = state
        .graph
        .semantic_observation()
        .relations
        .values()
        .find(|edge| {
            edge.kind == RelationKind::Calls
                && edge.src == GraphNodeId::Entity(caller.id)
                && edge.dst == GraphNodeId::Entity(target.id)
                && kin_index::binding_debt::parser_owns_binding(edge)
        })
        .expect("the admitted parser resolves the imported call")
        .clone();
    assert!(matches!(
        state.graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Checked { .. }
    ));

    // A previously accepted LSP reference is a separate obligation from the
    // parser call, even though both cite this same occurrence.
    let start = body.rfind("work()").unwrap();
    let mut reference = lsp_publication_call(caller.id, target.id);
    reference.kind = RelationKind::References;
    reference.evidence[0].parser_rule = Some("lsp_references".into());
    reference.evidence[0].source_span = Some(kin_model::SourceSpan {
        file: kin_model::FilePathId::new("caller.py"),
        start_byte: start,
        end_byte: start + 4,
        start_line: 3,
        start_col: 11,
        end_line: 3,
        end_col: 15,
    });
    state.graph.upsert_relation(&reference).unwrap();
    state.save_snapshot().unwrap();
    assert!(matches!(
        state.graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Checked { .. }
    ));

    let mut answer = reference.clone();
    answer.id =
        kin_model::language_server_relation_id(RelationKind::Calls, caller.id, replacement.id);
    answer.kind = RelationKind::Calls;
    answer.dst = GraphNodeId::Entity(replacement.id);
    answer.evidence[0].parser_rule = Some("lsp_call_hierarchy".into());
    state.graph.remove_relation(&parsed.id).unwrap();
    state.lsp_settled_guesses.lock().unwrap().insert(parsed.id);
    state.graph.upsert_relation(&answer).unwrap();
    let inputs = QueryInputs::capture(&state).await.unwrap();
    state.save_snapshot().unwrap();
    let first_debts: Vec<_> = state
        .graph
        .semantic_observation()
        .relations
        .into_values()
        .filter(claims_local_binding_debt)
        .collect();
    assert_eq!(first_debts.len(), 1);
    assert!(matches!(
        state.graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Checked { .. }
    ));
    let previously_recorded_counts = (
        state.durable_entity_count().unwrap(),
        state.durable_relation_count().unwrap(),
    );
    // A later withdrawal must merge with the first exact obligation and may
    // replace that live debt only because the durable successor contains it.
    state.graph.remove_relation(&reference.id).unwrap();
    state
        .lsp_settled_guesses
        .lock()
        .unwrap()
        .insert(reference.id);
    state.save_snapshot().unwrap();
    inputs
        .current(&state)
        .await
        .expect("own artifact bookkeeping does not stale the next LSP document");
    let durable = lsp_publication_durable(&state);
    let live = state.graph.semantic_observation();
    lsp_publication_same_semantics(&live, &durable);
    assert!(matches!(
        state.graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Checked { .. }
    ));
    assert!(!durable.relations.contains_key(&parsed.id));
    assert!(!durable.relations.contains_key(&reference.id));
    assert_eq!(durable.relations.get(&answer.id), Some(&answer));
    assert_ne!(
        previously_recorded_counts.1,
        durable.relations.len() as u64,
        "withdrawals and their merged debt must change the recorded relation count"
    );
    let recorded = durability_block(&state).await;
    assert_eq!(recorded.state, "recorded", "{recorded:?}");
    assert_eq!(
        recorded.durable_entities,
        Some(durable.entities.len() as u64)
    );
    assert_eq!(
        recorded.durable_relations,
        Some(durable.relations.len() as u64)
    );
    assert_eq!(recorded.live_only_entities, Some(0));
    assert_eq!(recorded.live_only_relations, Some(0));

    // Retry finalization with the prior observed counts, as after a checkpoint
    // whose artifacts had not finished. A separate live write must prevent
    // levelling those counters against even this valid held authority.
    let authority_graph = kin_db::InMemoryGraph::from_snapshot(durable.clone()).unwrap();
    let generation = state
        .snapshot_generation
        .load(std::sync::atomic::Ordering::SeqCst);
    state.record_durable_entity_count(previously_recorded_counts.0);
    state.record_durable_relation_count(previously_recorded_counts.1);
    let mut independent = reference.clone();
    independent.id = kin_model::RelationId::new();
    state.graph.upsert_relation(&independent).unwrap();
    state
        .finalize_held_generation_for_test(generation, &authority_graph)
        .unwrap();
    assert_eq!(
        state.durable_entity_count(),
        Some(previously_recorded_counts.0)
    );
    assert_eq!(
        state.durable_relation_count(),
        Some(previously_recorded_counts.1)
    );
    assert_eq!(
        state.graph.get_relation_by_id(&independent.id),
        Some(independent.clone())
    );
    assert!(!durable.relations.contains_key(&independent.id));
    assert!(matches!(
        state.graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Unproven
    ));
    // Removing only that independent write permits the same held authority to
    // restore its exact witness and counts, without another publication.
    state.graph.remove_relation(&independent.id).unwrap();
    state
        .finalize_held_generation_for_test(generation, &authority_graph)
        .unwrap();
    assert_eq!(
        state.durable_entity_count(),
        Some(durable.entities.len() as u64)
    );
    assert_eq!(
        state.durable_relation_count(),
        Some(durable.relations.len() as u64)
    );
    assert_eq!(
        state
            .snapshot_generation
            .load(std::sync::atomic::Ordering::SeqCst),
        generation
    );
    let recorded = durability_block(&state).await;
    assert_eq!(recorded.state, "recorded", "{recorded:?}");
    let debts: Vec<_> = durable
        .relations
        .values()
        .filter(|edge| claims_local_binding_debt(edge))
        .collect();
    assert_eq!(
        debts.len(),
        1,
        "one source owns the two exact prior obligations"
    );
    let debt_relation = debts[0].clone();
    let kin_model::GraphNodeId::Artifact(artifact) = debt_relation.src else {
        panic!("artifact debt")
    };
    let debt = decode_local_binding_debt(
        &kin_model::FilePathId::new("caller.py"),
        artifact,
        &debt_relation,
    )
    .unwrap()
    .unwrap();
    assert_eq!(debt.obligations.len(), 2);
    for old in [&parsed, &reference] {
        assert!(debt
            .obligations
            .iter()
            .any(|entry| &entry.retired_relation == old));
    }

    // A later positive answer did not discharge either contradictory prior
    // target. Removing their debt must still fail the unchanged verifier.
    use kin_db::storage::binding_history::BindingHistoryVerifier as _;
    let mut erased = durable.clone();
    erased.relations.remove(&debt_relation.id);
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(&state)
            .unwrap();
    let authority = context.open().unwrap();
    assert!(!kin_index::binding_history::LocalBindingHistoryVerifier
        .verify_graph_transition(&durable, &erased, &|hash| authority.load_source_blob(hash))
        .unwrap());
    drop(authority);

    // Simulate an admitted debt whose live mirror has not landed. The next
    // publication has an empty new semantic delta and must recover it from
    // authority, without a new operation or silently dropping the witness.
    let generation = state
        .snapshot_generation
        .load(std::sync::atomic::Ordering::SeqCst);
    state.graph.remove_relation(&debt_relation.id).unwrap();
    state.save_snapshot().unwrap();
    assert_eq!(
        state
            .snapshot_generation
            .load(std::sync::atomic::Ordering::SeqCst),
        generation
    );
    assert_eq!(
        state.graph.get_relation_by_id(&debt_relation.id),
        Some(debt_relation.clone())
    );
    assert!(matches!(
        state.graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Checked { .. }
    ));
    // A retry that captures a newer, divergent payload must not overwrite
    // it with the older durable debt, even though the relation ID is equal.
    let mut divergent = debt.clone();
    divergent.obligations[0].retired_relation.confidence = 0.8;
    let mut divergent_relation =
        kin_index::binding_debt::build_local_binding_debt(artifact, divergent).unwrap();
    divergent_relation.created_in = debt_relation.created_in;
    assert_ne!(divergent_relation, debt_relation);
    state.graph.upsert_relation(&divergent_relation).unwrap();
    let refused = state.save_snapshot().unwrap_err().to_string();
    assert!(
        refused.contains("does not retain every current live obligation"),
        "{refused}"
    );
    assert_eq!(
        state.graph.get_relation_by_id(&debt_relation.id),
        Some(divergent_relation)
    );
    assert_eq!(
        lsp_publication_durable(&state)
            .relations
            .get(&debt_relation.id),
        Some(&debt_relation)
    );
    assert_eq!(
        state
            .snapshot_generation
            .load(std::sync::atomic::Ordering::SeqCst),
        generation
    );
    let layout = state.layout.clone();
    drop(state);
    let cold = waiting_cold_start(layout).await;
    assert_eq!(
        cold.graph.get_relation_by_id(&debt_relation.id),
        Some(debt_relation)
    );
    assert!(matches!(
        cold.graph.binding_history_observation(),
        kin_model::BindingHistoryObservation::Checked { .. }
    ));
}
