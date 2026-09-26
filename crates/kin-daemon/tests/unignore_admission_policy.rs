// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! One observed root-policy edit recovers exact prior local bindings.

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

async fn ignored_target_recovery(
    cold: bool,
    delete_rule: bool,
    deferred: bool,
    proposed: Option<&[u8]>,
) {
    let repo = tempfile::tempdir().unwrap();
    let init = kin_core::init(repo.path()).unwrap();
    let layout = init.layout;
    let state = Arc::new(DaemonState::open(layout.clone()).unwrap());
    state.is_initialized.store(true, Ordering::Release);
    let app = kin_daemon::api::router(Arc::clone(&state));
    let caller_body = b"from keep import kept\ndef caller():\n    return kept()\n";
    std::fs::write(repo.path().join(".gitignore"), b"private.py\n").unwrap();
    admit(&app, "establish unchanged shared policy").await;
    std::fs::write(repo.path().join("private.py"), b"def private(): return 9\n").unwrap();
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
    std::fs::write(repo.path().join(".kinignore"), b"keep.py\n").unwrap();
    admit(&app, "ignore target while retaining caller").await;
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
    drop(app);
    let state = if cold {
        state.save_snapshot().unwrap();
        drop(state);
        let reopened = Arc::new(DaemonState::open(layout.clone()).unwrap());
        reopened.is_initialized.store(true, Ordering::Release);
        reopened
    } else {
        state
    };
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
    if delete_rule {
        std::fs::remove_file(repo.path().join(".kinignore")).unwrap();
    } else {
        std::fs::write(repo.path().join(".kinignore"), proposed.unwrap_or(b"")).unwrap();
    }
    if deferred {
        commit(
            &app,
            "first commit directly restores the root policy and target",
        )
        .await;
    } else {
        admit(&app, "first admission after restoring the root policy").await;
    }
    let restored = entity(&state, "keep.py", "kept");
    assert_eq!(
        restored.id, target.id,
        "the exact original declaration is restored"
    );
    assert!(
        state
            .graph
            .resolved_tree()
            .artifact_at_path(&RepoPath::from_utf8("private.py").unwrap())
            .is_none(),
        "unchanged shared policy must remain in force"
    );
    assert_eq!(
        std::fs::read(repo.path().join("caller.py")).unwrap(),
        caller_body
    );
    assert!(debt(&state, "caller.py").is_none());
    assert!(state
        .graph
        .get_all_relations_for_entity(&caller.id)
        .unwrap()
        .iter()
        .any(|r| r.kind == RelationKind::Calls && r.dst.as_entity() == Some(restored.id)));
    assert_eq!(entity(&state, "caller.py", "caller").id, caller.id);
    if !deferred {
        commit(&app, "settle restored target").await;
    }
    let private_id = if proposed.is_some() {
        assert!(
            state
                .graph
                .resolved_tree()
                .artifact_at_path(&RepoPath::from_utf8("private.py").unwrap())
                .is_none(),
            "first Native generation must not bypass its parent's unrelated deny"
        );
        // Only the committed rule generation can now authorize this new path.
        commit(
            &app,
            "next committed rule generation admits its newly allowed path",
        )
        .await;
        Some(entity(&state, "private.py", "private").id)
    } else {
        None
    };
    state.save_snapshot().unwrap();
    drop(app);
    drop(state);
    let reopened = DaemonState::open(layout).unwrap();
    if let Some(id) = private_id {
        assert_eq!(entity(&reopened, "private.py", "private").id, id);
    }
    assert_eq!(entity(&reopened, "keep.py", "kept").id, restored.id);
    assert_eq!(entity(&reopened, "caller.py", "caller").id, caller.id);
    assert!(debt(&reopened, "caller.py").is_none());
    assert!(reopened
        .graph
        .get_all_relations_for_entity(&caller.id)
        .unwrap()
        .iter()
        .any(|r| r.kind == RelationKind::Calls && r.dst.as_entity() == Some(restored.id)));
}

#[tokio::test]
async fn ignored_target_retains_prior_binding_debt_through_commit_and_cold_recovery() {
    ignored_target_recovery(true, false, false, None).await;
}

#[tokio::test]
async fn clearing_root_rule_readmits_target_in_one_warm_admission() {
    ignored_target_recovery(false, false, false, None).await;
}

#[tokio::test]
async fn deleting_root_rule_readmits_target_in_one_cold_admission() {
    ignored_target_recovery(true, true, false, None).await;
}

#[tokio::test]
async fn clearing_root_rule_and_target_publish_in_one_deferred_commit() {
    ignored_target_recovery(false, false, true, None).await;
}

#[tokio::test]
async fn deleting_root_rule_and_target_publish_in_one_cold_deferred_commit() {
    ignored_target_recovery(true, true, true, None).await;
}

#[tokio::test]
async fn root_negation_cannot_nominate_an_unrelated_shared_exclusion() {
    ignored_target_recovery(false, false, false, Some(b"!private.py\n")).await;
}

#[tokio::test]
async fn root_negation_deferred_commits_obey_parent_then_new_generation() {
    ignored_target_recovery(true, false, true, Some(b"!private.py\n")).await;
}

#[tokio::test]
async fn root_negation_preserves_a_previously_allowed_untracked_path() {
    let repo = tempfile::tempdir().unwrap();
    let init = kin_core::init(repo.path()).unwrap();
    let state = Arc::new(DaemonState::open(init.layout).unwrap());
    state.is_initialized.store(true, Ordering::Release);
    let app = kin_daemon::api::router(Arc::clone(&state));
    std::fs::write(repo.path().join(".gitignore"), b"private.py\n").unwrap();
    std::fs::write(repo.path().join(".kinignore"), b"!private.py\nrestore.py\n").unwrap();
    admit(&app, "establish a standing root negation").await;
    std::fs::write(repo.path().join("private.py"), b"def private(): return 1\n").unwrap();
    std::fs::write(
        repo.path().join("restore.py"),
        b"def restored(): return 2\n",
    )
    .unwrap();
    std::fs::write(repo.path().join(".kinignore"), b"!private.py\n").unwrap();
    admit(
        &app,
        "preserve prior allowance while unignoring another path",
    )
    .await;
    entity(&state, "private.py", "private");
    entity(&state, "restore.py", "restored");
}
