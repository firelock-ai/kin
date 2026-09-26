// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Canonical admission must retire cached importers with their source artifact.

use std::sync::{atomic::Ordering, Arc};

use axum::{body::Body, http::Request};
use kin_daemon::DaemonState;
use kin_model::{Entity, EntityFilter, EntityStore, FilePathId, RelationKind, RepoPath};
use serde_json::{json, Value};
use tower::ServiceExt;

fn entity(state: &DaemonState, file: &str, name: &str) -> Entity {
    let matches: Vec<_> = state
        .graph
        .query_entities(&EntityFilter {
            file_path: Some(FilePathId::new(file)),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .filter(|entity| entity.name == name && entity.kind == kin_model::EntityKind::Function)
        .collect();
    assert_eq!(matches.len(), 1, "{file}::{name}: {matches:?}");
    matches[0].clone()
}

async fn admit(app: &axum::Router, phase: &str) {
    let response = app
        .clone()
        .oneshot(
            Request::post("/commands/admit")
                .header("host", "localhost")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "operation_id": kin_model::OperationId::new(),
                        "actor": "dependency-cache-regression"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    eprintln!("ADMISSION {phase}: {status} {body}");
    assert!(status.is_success(), "{phase}: {body}");
    assert_eq!(body["report"]["admitted"], true, "{phase}: {body}");
}

async fn commit(app: &axum::Router, message: &str) {
    let response = app
        .clone()
        .oneshot(
            Request::post("/commands/commit")
                .header("host", "localhost")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "operation_id": kin_model::OperationId::new(),
                        "timestamp": kin_model::Timestamp::now(),
                        "author": "Cache Test <cache@example.invalid>",
                        "message": message
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .unwrap();
    assert!(
        status.is_success(),
        "{message}: {status} {}",
        String::from_utf8_lossy(&body)
    );
}

async fn removed_importer_does_not_poison_surviving_source(ignore: bool) {
    let repo = tempfile::tempdir().unwrap();
    let init = kin_core::init(repo.path()).unwrap();
    let state = Arc::new(DaemonState::open(init.layout).unwrap());
    state.is_initialized.store(true, Ordering::Release);
    let app = kin_daemon::api::router(Arc::clone(&state));
    std::fs::write(repo.path().join("keep.py"), b"def kept():\n    return 1\n").unwrap();
    let gone_body = b"from keep import kept\ndef departed():\n    return kept()\n";
    std::fs::write(repo.path().join("gone.py"), gone_body).unwrap();
    admit(&app, "initial two-source admission").await;
    let kept = entity(&state, "keep.py", "kept");
    let departed = entity(&state, "gone.py", "departed");
    let calls = state
        .graph
        .get_all_relations_for_entity(&departed.id)
        .unwrap();
    assert!(
        calls.iter().any(|call| {
            call.kind == RelationKind::Calls
                && call.src.as_entity() == Some(departed.id)
                && call.dst.as_entity() == Some(kept.id)
        }),
        "initial admitted imported call missing: {calls:?}"
    );

    if ignore {
        std::fs::write(repo.path().join(".kinignore"), b"gone.py\n").unwrap();
    } else {
        std::fs::remove_file(repo.path().join("gone.py")).unwrap();
    }
    admit(&app, "remove importer with one current Python source").await;
    assert!(state
        .graph
        .resolved_tree()
        .artifact_at_path(&RepoPath::from_utf8("gone.py").unwrap())
        .is_none());
    assert!(state.graph.get_entity(&departed.id).unwrap().is_none());
    assert_eq!(entity(&state, "keep.py", "kept").id, kept.id);
    if ignore {
        assert_eq!(
            std::fs::read(repo.path().join("gone.py")).unwrap(),
            gone_body
        );
    }
    std::fs::write(repo.path().join("keep.py"), b"def kept():\n    return 2\n").unwrap();
    admit(&app, "later surviving-source edit").await;
    assert_eq!(entity(&state, "keep.py", "kept").id, kept.id);
}

#[tokio::test]
async fn ignoring_a_python_importer_retires_its_cached_dependency() {
    removed_importer_does_not_poison_surviving_source(true).await;
}

#[tokio::test]
async fn deleting_a_python_importer_retires_its_cached_dependency() {
    removed_importer_does_not_poison_surviving_source(false).await;
}

#[tokio::test]
async fn complete_batch_does_not_carry_a_removed_importer_into_a_later_edit() {
    let repo = tempfile::tempdir().unwrap();
    let init = kin_core::init(repo.path()).unwrap();
    let state = Arc::new(DaemonState::open(init.layout).unwrap());
    state.is_initialized.store(true, Ordering::Release);
    let app = kin_daemon::api::router(Arc::clone(&state));
    for (file, body) in [
        ("keep.py", "def kept():\n    return 1\n"),
        (
            "gone.py",
            "from keep import kept\ndef departed():\n    return kept()\n",
        ),
        ("spare.py", "def spare():\n    return 1\n"),
    ] {
        std::fs::write(repo.path().join(file), body).unwrap();
    }
    admit(&app, "initial three-source batch").await;
    let kept = entity(&state, "keep.py", "kept");
    let departed = entity(&state, "gone.py", "departed");
    assert!(state
        .graph
        .get_all_relations_for_entity(&departed.id)
        .unwrap()
        .iter()
        .any(|r| r.kind == RelationKind::Calls && r.dst.as_entity() == Some(kept.id)));
    commit(&app, "settle initial sources").await;
    std::fs::remove_file(repo.path().join("gone.py")).unwrap();
    std::fs::write(repo.path().join("keep.py"), "def kept():\n    return 2\n").unwrap();
    std::fs::write(repo.path().join("spare.py"), "def spare():\n    return 2\n").unwrap();
    admit(&app, "remove importer alongside complete two-source batch").await;
    assert!(state.graph.get_entity(&departed.id).unwrap().is_none());
    commit(&app, "settle removal batch").await;
    std::fs::write(repo.path().join("keep.py"), "def kept():\n    return 3\n").unwrap();
    admit(&app, "single edit after removal batch").await;
    assert_eq!(entity(&state, "keep.py", "kept").id, kept.id);
}

fn debt(state: &DaemonState, file: &str) -> Option<kin_index::binding_debt::LocalBindingDebt> {
    let snapshot = state.graph.to_snapshot();
    let artifact = snapshot
        .resolved_tree
        .artifact_at_path(&RepoPath::from_utf8(file).unwrap())
        .unwrap();
    let kin_model::TreeEntry::Blob { hash, .. } = artifact.entry else {
        panic!("source body")
    };
    let relations: Vec<_> = snapshot
        .relations
        .values()
        .filter(|r| r.src == kin_model::GraphNodeId::Artifact(artifact.artifact_id))
        .collect();
    kin_index::binding_debt::inspect_local_binding_debt(
        &FilePathId::new(file),
        artifact.artifact_id,
        hash,
        &relations,
    )
    .unwrap()
}

#[tokio::test]
async fn deleted_target_retains_prior_binding_debt_through_commit_and_cold_recovery() {
    let repo = tempfile::tempdir().unwrap();
    let init = kin_core::init(repo.path()).unwrap();
    let layout = init.layout;
    let state = Arc::new(DaemonState::open(layout.clone()).unwrap());
    state.is_initialized.store(true, Ordering::Release);
    let app = kin_daemon::api::router(Arc::clone(&state));
    let caller_body = b"from keep import kept\ndef caller():\n    return kept()\n";
    std::fs::write(repo.path().join("caller.py"), caller_body).unwrap();
    std::fs::write(repo.path().join("keep.py"), b"def kept():\n    return 1\n").unwrap();
    admit(&app, "initial caller and target").await;
    let caller = entity(&state, "caller.py", "caller");
    let target = entity(&state, "keep.py", "kept");
    let old = state
        .graph
        .get_all_relations_for_entity(&caller.id)
        .unwrap()
        .into_iter()
        .find(|r| r.kind == RelationKind::Calls && r.dst.as_entity() == Some(target.id))
        .unwrap();
    commit(&app, "record real prior local binding").await;
    std::fs::remove_file(repo.path().join("keep.py")).unwrap();
    admit(&app, "delete target while retaining caller").await;
    let owed = debt(&state, "caller.py").expect("prior local target must remain owed");
    assert!(owed
        .obligations
        .iter()
        .any(|obligation| obligation.retired_relation == old));
    assert!(state.graph.get_entity(&target.id).unwrap().is_none());
    assert_eq!(entity(&state, "caller.py", "caller").id, caller.id);
    assert_eq!(
        std::fs::read(repo.path().join("caller.py")).unwrap(),
        caller_body
    );
    commit(&app, "record target retirement with exact debt").await;
    state.save_snapshot().unwrap();
    drop(app);
    drop(state);
    let state = Arc::new(DaemonState::open(layout).unwrap());
    state.is_initialized.store(true, Ordering::Release);
    let app = kin_daemon::api::router(Arc::clone(&state));
    assert_eq!(debt(&state, "caller.py"), Some(owed.clone()));
    std::fs::write(
        repo.path().join("decoy.py"),
        b"def kept():\n    return 99\n",
    )
    .unwrap();
    admit(&app, "unrelated same-name destination").await;
    assert_eq!(debt(&state, "caller.py"), Some(owed));
    let decoy = entity(&state, "decoy.py", "kept");
    assert!(!state
        .graph
        .get_all_relations_for_entity(&caller.id)
        .unwrap()
        .iter()
        .any(|r| r.kind == RelationKind::Calls && r.dst.as_entity() == Some(decoy.id)));
    std::fs::write(repo.path().join("keep.py"), b"def kept():\n    return 1\n").unwrap();
    admit(&app, "readmit the actual target").await;
    let restored = entity(&state, "keep.py", "kept");
    assert!(debt(&state, "caller.py").is_none());
    assert!(state
        .graph
        .get_all_relations_for_entity(&caller.id)
        .unwrap()
        .iter()
        .any(|r| r.kind == RelationKind::Calls && r.dst.as_entity() == Some(restored.id)));
    assert_eq!(entity(&state, "caller.py", "caller").id, caller.id);
    commit(&app, "settle restored target").await;
}
