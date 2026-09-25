// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#![cfg(unix)]

use super::*;
use axum::{body::Body, http::Request};
use kin_model::{Entity, EntityFilter, EntityKind, Relation, RelationKind};
use serde_json::json;
use std::sync::{atomic::Ordering, Arc};
use tower::ServiceExt;

struct Fixture {
    repo: tempfile::TempDir,
    state: Arc<DaemonState>,
    session: std::path::PathBuf,
    authority: Authority,
}

impl Fixture {
    async fn new(files: &[(&str, &str)]) -> Self {
        let repo = tempfile::tempdir().unwrap();
        let layout = kin_core::init(repo.path()).unwrap().layout;
        let state = Arc::new(DaemonState::open(layout).unwrap());
        state.is_initialized.store(true, Ordering::Release);
        for (file, body) in files {
            std::fs::write(repo.path().join(file), body).unwrap();
        }
        let response = crate::api::router(Arc::clone(&state)).oneshot(
            Request::post("/commands/commit").header("host", "localhost")
                .header("content-type", "application/json").body(Body::from(json!({
                    "operation_id":kin_model::OperationId::new(), "timestamp":kin_model::Timestamp::now(),
                    "author":"Planner Test <planner@example.invalid>","message":"exact source baseline"
                }).to_string())).unwrap(),
        ).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert!(
            status.is_success(),
            "baseline: {}",
            String::from_utf8_lossy(&bytes)
        );
        let binding = state.local_repository_authority_binding().unwrap();
        let session = state.layout.runs_dir().join("session-planner ü");
        kin_cli::commands::session_workspace::create_session_workspace_from_authority(
            &state.layout,
            &binding,
            &session,
            None,
            None,
        )
        .unwrap();
        let authority = binding.open_manager().unwrap();
        Self {
            repo,
            state,
            session,
            authority,
        }
    }
    fn observe(&self) -> kin_cli::commands::reconcile::SessionReconcileObservation {
        kin_cli::commands::reconcile::observe_session_workspace(
            &self.state.layout,
            &self.state.local_repository_authority_binding().unwrap(),
            &self.session,
            &self.state.blobs,
            false,
        )
        .unwrap()
    }
    fn entity(&self, file: &str, name: &str) -> Entity {
        self.state
            .graph
            .query_entities(&EntityFilter {
                file_path: Some(FilePathId::new(file)),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .find(|e| e.kind == EntityKind::Function && e.name == name)
            .unwrap()
    }
    async fn plan(
        &self,
    ) -> (
        PreparedSessionPlan,
        kin_cli::commands::reconcile::SessionReconcileObservation,
    ) {
        let _coordination = self.state.coordination_gate.lock().await;
        let _mutation = self.state.begin_graph_authority_mutation();
        let reconciler = self.state.reconciler.write().await;
        let observation = self.observe();
        let before = self.state.graph.semantic_observation();
        let roots = self.authority.read_authority().roots().clone();
        let plan = prepare(
            &self.state,
            &reconciler,
            &self.authority,
            &observation,
            before.clone(),
        )
        .unwrap();
        assert!(same_observation(
            &before,
            &self.state.graph.semantic_observation()
        ));
        assert_eq!(self.authority.read_authority().roots(), &roots);
        (plan, observation)
    }
    fn acknowledge_and_commit(
        &self,
        plan: &PreparedSessionPlan,
        observation: &kin_cli::commands::reconcile::SessionReconcileObservation,
    ) -> GraphSnapshot {
        let binding = observation.publication_binding().unwrap();
        let prepared = self
            .authority
            .prepare_session_publication_with_locator(
                plan.transaction().clone(),
                observation.base().source_workspace.workspace_id,
                binding.binding().clone(),
                binding.locator().clone(),
                plan.observed(),
                &kin_index::binding_history::LocalBindingHistoryVerifier,
            )
            .unwrap();
        assert_eq!(
            prepared.operation_id(),
            observation.base().reconcile_operation_id
        );
        let (receipt, freeze) = self
            .authority
            .commit_prepared_session_publication(&prepared)
            .unwrap();
        assert_eq!(
            receipt.operation_id,
            observation.base().reconcile_operation_id
        );
        let selected = freeze
            .authority()
            .workspace_graph_snapshot(&observation.base().source_workspace.workspace_id)
            .unwrap()
            .unwrap();
        assert_eq!(selected.entities, plan.successor().entities);
        assert_eq!(selected.relations, plan.successor().relations);
        assert_eq!(
            selected.external_references,
            plan.successor().external_references
        );
        assert_eq!(selected.resolved_tree, *observation.desired_tree());
        drop(freeze);
        let reopened = self
            .state
            .local_repository_authority_binding()
            .unwrap()
            .open_manager()
            .unwrap();
        let cold = reopened
            .read_authority()
            .workspace_graph_snapshot(&observation.base().source_workspace.workspace_id)
            .unwrap()
            .unwrap();
        assert_eq!(cold.entities, selected.entities);
        assert_eq!(cold.relations, selected.relations);
        assert_eq!(cold.external_references, selected.external_references);
        assert_eq!(
            cold.verified_binding_history,
            selected.verified_binding_history
        );
        cold
    }
}

const CALLER: &str = "from local import work\ndef run():\n    return work(value=1)\n";
const TARGET: &str = "def work(value):\n    return value\n";

fn debt(snapshot: &GraphSnapshot, file: &str) -> kin_index::binding_debt::LocalBindingDebt {
    let artifact = snapshot
        .resolved_tree
        .artifact_at_path(&RepoPath::from_utf8(file).unwrap())
        .unwrap();
    let relation =
        &snapshot.relations[&kin_index::binding_debt::local_binding_debt_id(artifact.artifact_id)];
    kin_index::binding_debt::decode_local_binding_debt(
        &FilePathId::new(file),
        artifact.artifact_id,
        relation,
    )
    .unwrap()
    .unwrap()
}
fn local_call(state: &DaemonState, caller: &Entity, target: &Entity) -> Relation {
    state
        .graph
        .get_all_relations_for_entity(&caller.id)
        .unwrap()
        .into_iter()
        .find(|r| {
            r.kind == RelationKind::Calls
                && r.src.as_entity() == Some(caller.id)
                && r.dst.as_entity() == Some(target.id)
        })
        .unwrap()
}

#[tokio::test]
async fn prepared_session_plan_single_source_edit_prepares_before_acknowledgement() {
    let fixture = Fixture::new(&[("local.py", TARGET)]).await;
    let old = fixture.entity("local.py", "work");
    std::fs::write(
        fixture.session.join("local.py"),
        "def work(value):\n    return value + 1\n",
    )
    .unwrap();
    let (plan, observation) = fixture.plan().await;
    assert_eq!(plan.source_state().sources().len(), 1);
    assert_ne!(
        plan.successor().entities[&old.id].fingerprint,
        old.fingerprint
    );
    assert_eq!(
        plan.successor().entities[&old.id].file_origin,
        old.file_origin
    );
    assert_eq!(
        std::fs::read_to_string(fixture.repo.path().join("local.py")).unwrap(),
        TARGET
    );
    let cold = fixture.acknowledge_and_commit(&plan, &observation);
    assert!(cold.entities.contains_key(&old.id));
    assert!(cold.verified_binding_history.is_some());
}

#[tokio::test]
async fn prepared_session_plan_delete_retains_exact_binding_and_original_caller() {
    let fixture = Fixture::new(&[("caller.py", CALLER), ("local.py", TARGET)]).await;
    let caller = fixture.entity("caller.py", "run");
    let target = fixture.entity("local.py", "work");
    let prior = local_call(&fixture.state, &caller, &target);
    std::fs::remove_file(fixture.session.join("local.py")).unwrap();
    let (plan, observation) = fixture.plan().await;
    assert!(!plan.successor().entities.contains_key(&target.id));
    assert!(plan.successor().entities.contains_key(&caller.id));
    assert!(debt(plan.successor(), "caller.py")
        .obligations
        .iter()
        .any(|o| o.retired_relation == prior));
    let cold = fixture.acknowledge_and_commit(&plan, &observation);
    assert_eq!(
        debt(&cold, "caller.py"),
        debt(plan.successor(), "caller.py")
    );
    assert!(cold.verified_binding_history.is_some());
}

#[tokio::test]
async fn prepared_session_plan_move_preserves_entity_and_artifact_with_prior_debt() {
    let fixture = Fixture::new(&[("caller.py", CALLER), ("local.py", TARGET)]).await;
    let caller = fixture.entity("caller.py", "run");
    let target = fixture.entity("local.py", "work");
    let prior = local_call(&fixture.state, &caller, &target);
    let artifact = fixture
        .state
        .graph
        .resolved_tree()
        .artifact_at_path(&RepoPath::from_utf8("local.py").unwrap())
        .unwrap()
        .artifact_id;
    std::fs::rename(
        fixture.session.join("local.py"),
        fixture.session.join("renamed.py"),
    )
    .unwrap();
    let (plan, observation) = fixture.plan().await;
    assert_eq!(
        plan.successor().entities[&target.id].file_origin,
        Some(FilePathId::new("renamed.py"))
    );
    assert_eq!(
        plan.successor()
            .resolved_tree
            .artifact_at_path(&RepoPath::from_utf8("renamed.py").unwrap())
            .unwrap()
            .artifact_id,
        artifact
    );
    assert!(debt(plan.successor(), "caller.py")
        .obligations
        .iter()
        .any(|o| o.retired_relation == prior));
    fixture.acknowledge_and_commit(&plan, &observation);
}

#[tokio::test]
async fn prepared_session_plan_partial_source_refuses_without_primary_live_or_authority_mutation() {
    let fixture = Fixture::new(&[("local.py", TARGET)]).await;
    std::fs::write(
        fixture.session.join("local.py"),
        "def work(value):\n    return (\n",
    )
    .unwrap();
    let observation = fixture.observe();
    let before = fixture.state.graph.semantic_observation();
    let roots = fixture.authority.read_authority().roots().clone();
    let reconciler = fixture.state.reconciler.write().await;
    let error = prepare(
        &fixture.state,
        &reconciler,
        &fixture.authority,
        &observation,
        before.clone(),
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("partial"), "{error}");
    assert!(same_observation(
        &before,
        &fixture.state.graph.semantic_observation()
    ));
    assert_eq!(fixture.authority.read_authority().roots(), &roots);
    assert_eq!(
        std::fs::read_to_string(fixture.repo.path().join("local.py")).unwrap(),
        TARGET
    );
    assert!(fixture
        .authority
        .load_prepared_session_publication(observation.base().reconcile_operation_id)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn prepared_session_plan_nonsemantic_change_does_not_claim_source_completeness() {
    let fixture = Fixture::new(&[("local.py", TARGET), ("note.txt", "before")]).await;
    std::fs::write(fixture.session.join("note.txt"), "after").unwrap();
    let (plan, observation) = fixture.plan().await;
    assert!(plan.source_state().sources().is_empty());
    assert_eq!(
        plan.source_state().nonsemantic_paths(),
        &[RepoPath::from_utf8("note.txt").unwrap()]
    );
    fixture.acknowledge_and_commit(&plan, &observation);
}

#[tokio::test]
async fn prepared_session_plan_changed_capture_refuses_even_with_identical_source_bytes() {
    let fixture = Fixture::new(&[("local.py", TARGET)]).await;
    std::fs::write(
        fixture.session.join("local.py"),
        "def work(value):\n    return value + 1\n",
    )
    .unwrap();
    let observation = fixture.observe();
    let before = fixture.state.graph.semantic_observation();
    assert!(before.verified_binding_history.is_some());
    fixture.state.graph.invalidate_binding_history();
    let reconciler = fixture.state.reconciler.write().await;
    let error = prepare(
        &fixture.state,
        &reconciler,
        &fixture.authority,
        &observation,
        before,
    )
    .err()
    .unwrap();
    assert!(
        error.to_string().contains("captured session predecessor"),
        "{error}"
    );
}

#[tokio::test]
async fn prepared_session_plan_retains_captured_external_endpoint_without_minting_checked_history()
{
    let fixture = Fixture::new(&[("local.py", TARGET)]).await;
    // A controlled resolver coordinate exercises endpoint custody, not remote
    // resolution quality. It arrives after materialization and is not durable.
    let endpoint = kin_model::ExternalReference::new_resolved(
        "planner-fixture-v1",
        "registry.example.invalid/package@1",
        "work",
    )
    .unwrap();
    fixture
        .state
        .graph
        .apply_transaction_delta(&TransactionDelta {
            external_reference_deltas: vec![kin_model::ExternalReferenceDelta::Added {
                new: endpoint.clone(),
            }],
            ..Default::default()
        })
        .unwrap();
    assert!(fixture
        .authority
        .read_authority()
        .workspace_graph_snapshot(&fixture.state.local_repository_workspace_id().unwrap())
        .unwrap()
        .unwrap()
        .external_references
        .is_empty());
    std::fs::write(
        fixture.session.join("local.py"),
        "def work(value):\n    return value + 1\n",
    )
    .unwrap();
    let (plan, observation) = fixture.plan().await;
    assert_eq!(
        plan.observed().external_references.get(&endpoint.id),
        Some(&endpoint)
    );
    assert_eq!(
        plan.successor().external_references.get(&endpoint.id),
        Some(&endpoint)
    );
    assert_eq!(
        plan.transaction()
            .workspace_mutation
            .as_ref()
            .unwrap()
            .semantic_delta
            .external_reference_deltas(),
        &[kin_model::ExternalReferenceDelta::Added {
            new: endpoint.clone()
        }]
    );
    assert!(plan.observed().verified_binding_history.is_none());
    let cold = fixture.acknowledge_and_commit(&plan, &observation);
    assert_eq!(cold.external_references.get(&endpoint.id), Some(&endpoint));
    assert!(cold.verified_binding_history.is_none());
}

// Scripted protocol peer, not an installed LSP or proof of runtime dispatch.
const PEER: &str = r#"
import json,sys
responses=json.loads(sys.argv[1])
while True:
    headers={}
    while True:
        line=sys.stdin.buffer.readline()
        if not line: sys.exit(0)
        if line in (b'\n',b'\r\n'): break
        k,v=line.decode().split(':',1);headers[k.lower()]=v.strip()
    msg=json.loads(sys.stdin.buffer.read(int(headers['content-length'])))
    if 'id' not in msg: continue
    data=json.dumps({'jsonrpc':'2.0','id':msg['id'],'result':responses.get(msg['method'])}).encode()
    sys.stdout.buffer.write(f'Content-Length: {len(data)}\r\n\r\n'.encode()+data);sys.stdout.buffer.flush()
"#;

#[tokio::test]
async fn prepared_session_plan_captures_late_fresh_lsp_call_into_durable_unknown_debt() {
    use crate::daemon::lsp_publication::QueryInputs;
    const CALLBACK: &str = "def run(callback):\r\n    marker = \"😀\"; return callback()\r\n";
    let fixture = Fixture::new(&[
        ("caller.py", CALLBACK),
        ("target.py", "def work():\n    return 7\n"),
    ])
    .await;
    let caller = fixture.entity("caller.py", "run");
    let target = fixture.entity("target.py", "work");
    let entity_ref = |entity: &Entity| {
        let span = entity.span.as_ref().unwrap();
        kin_lsp::EntityRef {
            id: entity.id,
            name: entity.name.clone(),
            file_path: entity.file_origin.as_ref().unwrap().0.clone(),
            start_line: span.start_line,
            start_col: span.start_col,
            end_line: span.end_line,
            name_line: span.start_line,
            name_col: 4,
            declares_name: true,
            kind: kin_model::EntityKind::Function,
        }
    };
    let caller_ref = entity_ref(&caller);
    let target_ref = entity_ref(&target);
    let item = |entity: &kin_lsp::EntityRef| {
        json!({
            "name":entity.name,"kind":12,"uri":kin_lsp::protocol::path_to_uri(&fixture.repo.path().join(&entity.file_path)),
            "range":{"start":{"line":entity.start_line,"character":0},"end":{"line":entity.end_line,"character":0}},
            "selectionRange":{"start":{"line":entity.name_line,"character":4},"end":{"line":entity.name_line,"character":4+entity.name.len() as u32}}
        })
    };
    let line = CALLBACK.lines().nth(1).unwrap();
    let col = line[..line.find("callback").unwrap()]
        .encode_utf16()
        .count();
    let responses = json!({
        "initialize":{"capabilities":{"callHierarchyProvider":true,"positionEncoding":"utf-16"}},
        "textDocument/prepareCallHierarchy":[item(&caller_ref)],
        "callHierarchy/outgoingCalls":[{"to":item(&target_ref),"fromRanges":[{
            "start":{"line":1,"character":col},"end":{"line":1,"character":col+8}
        }]}]
    })
    .to_string();
    let inputs = QueryInputs::capture(&fixture.state).await.unwrap();
    let server = kin_lsp::lifecycle::LspServer::start(
        "python3",
        &["-u", "-c", PEER, &responses],
        fixture.repo.path(),
        None,
        None,
    )
    .await
    .unwrap();
    let generated = kin_lsp::enrichment::enrich_entity_calls(
        &server,
        &caller_ref,
        &kin_lsp::EntityIndex::new(vec![caller_ref.clone(), target_ref], fixture.repo.path()),
        fixture.repo.path(),
        Some(&|path| inputs.document(path)),
    )
    .await
    .unwrap();
    server.shutdown().await.unwrap();
    assert_eq!(generated.len(), 1);
    let prior = generated[0].clone();
    let span = prior.evidence[0].source_span.as_ref().unwrap();
    assert_eq!(&CALLBACK[span.start_byte..span.end_byte], "callback");
    let mut pending = crate::daemon::PendingEnrichment::default();
    inputs
        .absorb(&fixture.state, &mut pending, generated)
        .await
        .unwrap();
    inputs.flush(&fixture.state, &mut pending).await.unwrap();
    assert_eq!(
        fixture
            .state
            .graph
            .semantic_observation()
            .relations
            .get(&prior.id),
        Some(&prior)
    );
    assert!(!fixture
        .authority
        .read_authority()
        .workspace_graph_snapshot(&fixture.state.local_repository_workspace_id().unwrap())
        .unwrap()
        .unwrap()
        .relations
        .contains_key(&prior.id));
    std::fs::remove_file(fixture.session.join("target.py")).unwrap();
    let (plan, observation) = fixture.plan().await;
    assert_eq!(plan.observed().relations.get(&prior.id), Some(&prior));
    assert!(plan.observed().verified_binding_history.is_none());
    let owed = debt(plan.successor(), "caller.py");
    assert!(owed
        .obligations
        .iter()
        .any(|o| o.retired_relation == prior && o.target_file.0 == "target.py"));
    assert_eq!(plan.successor().entities[&caller.id].id, caller.id);
    let cold = fixture.acknowledge_and_commit(&plan, &observation);
    assert_eq!(debt(&cold, "caller.py"), owed);
    assert!(
        cold.verified_binding_history.is_none(),
        "late accepted enrichment is preserved without inventing checked interval history"
    );
}

#[tokio::test]
async fn prepared_session_plan_source_to_symlink_refuses_before_acknowledgement() {
    let fixture = Fixture::new(&[("caller.py", CALLER), ("local.py", TARGET)]).await;
    let target = fixture.entity("local.py", "work");
    std::fs::remove_file(fixture.session.join("local.py")).unwrap();
    std::os::unix::fs::symlink("caller.py", fixture.session.join("local.py")).unwrap();
    let observation = fixture.observe();
    let before = fixture.state.graph.semantic_observation();
    let roots = fixture.authority.read_authority().roots().clone();
    let _coordination = fixture.state.coordination_gate.lock().await;
    let _mutation = fixture.state.begin_graph_authority_mutation();
    let reconciler = fixture.state.reconciler.write().await;
    let result = prepare(
        &fixture.state,
        &reconciler,
        &fixture.authority,
        &observation,
        before.clone(),
    );
    let error = match result {
        Ok(plan) => panic!(
            "non-Blob replacement was prepared with old declaration: {}",
            plan.successor().entities.contains_key(&target.id)
        ),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("lost complete semantic extraction"),
        "{error}"
    );
    assert!(same_observation(
        &before,
        &fixture.state.graph.semantic_observation()
    ));
    assert_eq!(fixture.authority.read_authority().roots(), &roots);
    assert_eq!(
        std::fs::read_to_string(fixture.repo.path().join("local.py")).unwrap(),
        TARGET
    );
    assert!(fixture
        .authority
        .load_prepared_session_publication(observation.base().reconcile_operation_id)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn prepared_session_plan_source_to_opaque_move_refuses_before_acknowledgement() {
    let fixture = Fixture::new(&[("caller.py", CALLER), ("local.py", TARGET)]).await;
    let target = fixture.entity("local.py", "work");
    std::fs::rename(
        fixture.session.join("local.py"),
        fixture.session.join("note.txt"),
    )
    .unwrap();
    let observation = fixture.observe();
    let before = fixture.state.graph.semantic_observation();
    let roots = fixture.authority.read_authority().roots().clone();
    let _coordination = fixture.state.coordination_gate.lock().await;
    let _mutation = fixture.state.begin_graph_authority_mutation();
    let reconciler = fixture.state.reconciler.write().await;
    let result = prepare(
        &fixture.state,
        &reconciler,
        &fixture.authority,
        &observation,
        before.clone(),
    );
    let error = match result {
        Ok(plan) => panic!(
            "opaque move was prepared with relocated declaration: {}",
            plan.successor().entities.contains_key(&target.id)
        ),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("lost complete semantic extraction"),
        "{error}"
    );
    assert!(same_observation(
        &before,
        &fixture.state.graph.semantic_observation()
    ));
    assert_eq!(fixture.authority.read_authority().roots(), &roots);
    assert_eq!(
        std::fs::read_to_string(fixture.repo.path().join("local.py")).unwrap(),
        TARGET
    );
    assert!(!fixture.repo.path().join("note.txt").exists());
}

#[tokio::test]
async fn prepared_session_plan_entity_free_source_to_symlink_refuses() {
    let fixture = Fixture::new(&[
        ("empty.c", "// entity-free parser source\n"),
        ("local.py", TARGET),
    ])
    .await;
    assert!(fixture
        .state
        .graph
        .query_entities(&EntityFilter {
            file_path: Some(FilePathId::new("empty.c")),
            ..Default::default()
        })
        .unwrap()
        .is_empty());
    std::fs::remove_file(fixture.session.join("empty.c")).unwrap();
    std::os::unix::fs::symlink("local.py", fixture.session.join("empty.c")).unwrap();
    let observation = fixture.observe();
    let before = fixture.state.graph.semantic_observation();
    let roots = fixture.authority.read_authority().roots().clone();
    let _coordination = fixture.state.coordination_gate.lock().await;
    let _mutation = fixture.state.begin_graph_authority_mutation();
    let reconciler = fixture.state.reconciler.write().await;
    let error = prepare(
        &fixture.state,
        &reconciler,
        &fixture.authority,
        &observation,
        before.clone(),
    )
    .err()
    .unwrap();
    assert!(
        error
            .to_string()
            .contains("lost complete semantic extraction"),
        "{error}"
    );
    assert!(same_observation(
        &before,
        &fixture.state.graph.semantic_observation()
    ));
    assert_eq!(fixture.authority.read_authority().roots(), &roots);
    assert_eq!(
        std::fs::read_to_string(fixture.repo.path().join("empty.c")).unwrap(),
        "// entity-free parser source\n"
    );
}

#[cfg(target_os = "linux")] // macOS rejects this pathname before Kin can observe it.
#[tokio::test]
async fn prepared_session_plan_entity_free_source_to_byte_path_refuses() {
    use std::os::unix::ffi::OsStringExt;
    let fixture = Fixture::new(&[
        ("empty.c", "// entity-free parser source\n"),
        ("local.py", TARGET),
    ])
    .await;
    assert!(fixture
        .state
        .graph
        .query_entities(&EntityFilter {
            file_path: Some(FilePathId::new("empty.c")),
            ..Default::default()
        })
        .unwrap()
        .is_empty());
    // The destination carries no C suffix. A `.c` byte path is a current
    // C source the project invalidation cannot name, and that helper refuses
    // the batch on its own before the plan reaches the guard this test grades,
    // so the plan would refuse for a reason this case is not about. That
    // refusal has its own check beside the helper.
    let destination = fixture
        .session
        .join(std::ffi::OsString::from_vec(b"opaque-\xff".to_vec()));
    std::fs::rename(fixture.session.join("empty.c"), destination).unwrap();
    let observation = fixture.observe();
    let before = fixture.state.graph.semantic_observation();
    let roots = fixture.authority.read_authority().roots().clone();
    let _coordination = fixture.state.coordination_gate.lock().await;
    let _mutation = fixture.state.begin_graph_authority_mutation();
    let reconciler = fixture.state.reconciler.write().await;
    let error = prepare(
        &fixture.state,
        &reconciler,
        &fixture.authority,
        &observation,
        before.clone(),
    )
    .err()
    .unwrap();
    assert!(
        error
            .to_string()
            .contains("lost complete semantic extraction"),
        "{error}"
    );
    assert!(same_observation(
        &before,
        &fixture.state.graph.semantic_observation()
    ));
    assert_eq!(fixture.authority.read_authority().roots(), &roots);
    assert_eq!(
        std::fs::read_to_string(fixture.repo.path().join("empty.c")).unwrap(),
        "// entity-free parser source\n"
    );
}
