// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;

const CORE_BASE: &[u8] =
    b"def summarize(rows):\n    return len(rows)\n\n\ndef helper(x):\n    return x + 1\n";
const CORE_OURS: &[u8] =
    b"def summarize(rows):\n    return len(rows) + 100\n\n\ndef helper(x):\n    return x + 1\n";
const CORE_THEIRS: &[u8] =
    b"def summarize(rows):\n    return len(rows) * 2\n\n\ndef helper(x):\n    return x + 1\n";

async fn post(
    state: &Arc<DaemonState>,
    route: &str,
    payload: &impl serde::Serialize,
) -> (StatusCode, serde_json::Value) {
    let response = router(Arc::clone(state))
        .oneshot(
            Request::post(route)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"raw": String::from_utf8_lossy(&bytes)})),
    )
}

fn fixture(genuine_removal: bool) -> (tempfile::TempDir, kin_core::KinLayout, Arc<DaemonState>) {
    install_test_registry_override();
    let repository = tempfile::tempdir().unwrap();
    let root = repository.path();
    std::fs::create_dir(root.join("pkg")).unwrap();
    run_test_git(root, ["init", "--initial-branch=main"]);
    run_test_git(root, ["config", "user.email", "merge@example.invalid"]);
    run_test_git(root, ["config", "user.name", "Merge Coverage Test"]);
    std::fs::write(root.join("pkg/core.py"), CORE_BASE).unwrap();
    for name in ["a", "b", "c"] {
        std::fs::write(root.join(format!("pkg/mod_{name}.py")), format!("from pkg.core import summarize, helper\n\n\ndef use_{name}(rows):\n    return summarize(rows) + helper(1)\n")).unwrap();
    }
    if genuine_removal {
        std::fs::write(
            root.join("pkg/mod_a.py"),
            b"from pkg.core import summarize\n\ndef use_a(rows):\n    return summarize(rows)\n",
        )
        .unwrap();
    }
    run_test_git(root, ["add", "--all"]);
    run_test_git(root, ["commit", "-m", "base"]);
    run_test_git(root, ["switch", "-c", "feature"]);
    std::fs::write(
        root.join("pkg/core.py"),
        if genuine_removal {
            CORE_BASE
        } else {
            CORE_THEIRS
        },
    )
    .unwrap();
    if genuine_removal {
        std::fs::write(root.join("pkg/mod_a.py"), b"from pkg.core import summarize, helper\n\ndef use_a(rows):\n    return summarize(rows) + helper(1)\n").unwrap();
    }
    run_test_git(root, ["add", "--all"]);
    run_test_git(root, ["commit", "-m", "feature"]);
    run_test_git(root, ["switch", "main"]);
    std::fs::write(
        root.join("pkg/core.py"),
        if genuine_removal {
            b"def summarize(rows):\n    return len(rows)\n"
        } else {
            CORE_OURS
        },
    )
    .unwrap();
    run_test_git(root, ["add", "--all"]);
    run_test_git(root, ["commit", "-m", "main"]);
    let layout = kin_core::init_from_git(root).unwrap().layout;
    let state = Arc::new(DaemonState::open(layout.clone()).unwrap());
    (repository, layout, state)
}

#[tokio::test]
#[serial_test::serial(repository_commit)]
async fn body_bound_parse_certificates_do_not_become_authored_merge_conflicts() {
    for side in [kin_model::MergeSide::Ours, kin_model::MergeSide::Theirs] {
        let (repository, layout, state) = fixture(false);
        let _ = post(
            &state,
            "/commands/commit",
            &json!({
                "operation_id": kin_model::OperationId::new(), "timestamp": Timestamp::now(),
                "author": "merge test", "message": "settle post-import overlay"
            }),
        )
        .await;
        let previous = state
            .graph
            .resolve_graph_at(&branch_change(&state))
            .unwrap();
        let inherited: std::collections::HashMap<_, _> = previous
            .relations
            .values()
            .filter(|relation| {
                !relation.evidence.iter().any(|e| {
                    e.parser_rule
                        .as_deref()
                        .is_some_and(|rule| rule.contains("coverage"))
                })
            })
            .map(|relation| (relation.id, relation.clone()))
            .collect();
        assert!(
            !inherited.is_empty(),
            "real imported caller edges are part of this fixture"
        );
        let request = kin_cli::commands::merge::MergeRequest {
            source: kin_model::RefName::branch(b"feature").unwrap(),
            operation_id: kin_model::OperationId::new(),
            actor: AuthorId::new("merge coverage test"),
        };
        let (status, body) = post(&state, "/commands/merge", &request).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let merged: kin_cli::commands::merge::MergeResponse = serde_json::from_value(body).unwrap();
        assert_eq!(
            merged.report.unwrap().outcome,
            kin_cli::commands::merge::MergeOutcome::Conflicted
        );
        let (status, body) = post(
            &state,
            "/commands/conflicts",
            &kin_cli::commands::conflicts::ConflictsRequest::default(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let response: kin_cli::commands::conflicts::ConflictsResponse =
            serde_json::from_value(body).unwrap();
        let entries = response.report.unwrap().record.unwrap().entries;
        assert!(
            entries.iter().any(|entry| matches!(
                entry.subject,
                kin_model::MergeConflictSubject::Entity { .. }
            )),
            "actual body conflict stays visible"
        );
        assert!(
            entries.iter().any(|entry| matches!(
                entry.subject,
                kin_model::MergeConflictSubject::Artifact { .. }
            )),
            "actual file conflict stays visible"
        );
        assert!(entries.iter().all(|entry| !matches!(entry.subject, kin_model::MergeConflictSubject::Relation { .. })), "derived source certificates must not become independently authored conflicts: {entries:#?}");
        for action in [
            kin_cli::commands::resolve::ResolveAction::Settle {
                directives: vec![],
                all: Some(side),
            },
            kin_cli::commands::resolve::ResolveAction::Continue,
        ] {
            let request = kin_cli::commands::resolve::ResolveRequest {
                operation_id: kin_model::OperationId::new(),
                actor: AuthorId::new("merge coverage test"),
                action,
                expected_record: None,
            };
            let (status, body) = post(&state, "/commands/resolve", &request).await;
            assert_eq!(status, StatusCode::OK, "{body}");
        }
        let expected = if side == kin_model::MergeSide::Ours {
            CORE_OURS
        } else {
            CORE_THEIRS
        };
        assert_eq!(
            std::fs::read(repository.path().join("pkg/core.py")).unwrap(),
            expected
        );
        let head = branch_change(&state);
        for graph in [state.graph.resolve_graph_at(&head).unwrap(), {
            drop(state);
            let reopened = DaemonState::open(layout).unwrap();
            reopened.graph.resolve_graph_at(&head).unwrap()
        }] {
            let artifact = graph
                .tree
                .artifact_at_path(&kin_model::RepoPath::from_utf8("pkg/core.py").unwrap())
                .unwrap();
            let held: Vec<_> = graph
                .relations
                .values()
                .filter(|relation| {
                    kin_index::is_parse_coverage_relation(
                        relation,
                        "pkg/core.py",
                        artifact.artifact_id,
                    )
                })
                .collect();
            assert_eq!(held.len(), 1);
            assert_eq!(
                kin_index::parse_coverage_source_digest(held[0]),
                Some(kin_model::Hash256::from_bytes(
                    kin_blobs::digest(expected).0
                ))
            );
            assert_eq!(
                held[0].evidence[0].parser_rule.as_deref(),
                Some(kin_index::CALL_SHAPE_PARSE_COVERAGE_FULL_V1)
            );
            for (id, relation) in &inherited {
                assert_eq!(
                    graph.relations.get(id),
                    Some(relation),
                    "unrelated relation identity, evidence and provenance survive merge/reopen"
                );
            }
            println!(
                "MERGE_COVERAGE_OBSERVATION {}",
                json!({
                    "selected_side": side, "source_digest": kin_index::parse_coverage_source_digest(held[0]).unwrap().to_string(),
                    "certificate_id": held[0].id, "certificate": held[0],
                    "unchanged_noncoverage_relations": inherited.values().collect::<Vec<_>>(),
                    "scope": "real Git-import merge and cold replay; these inherited edges are parser/import evidence, authored/debt preservation is separately unit-tested"
                })
            );
        }
    }
}

#[tokio::test]
#[serial_test::serial(repository_commit)]
async fn a_real_removed_endpoint_still_creates_a_relation_conflict() {
    let (_repository, _layout, state) = fixture(true);
    let _ = post(
        &state,
        "/commands/commit",
        &json!({
            "operation_id": kin_model::OperationId::new(), "timestamp": Timestamp::now(),
            "author": "merge test", "message": "settle post-import overlay"
        }),
    )
    .await;
    let request = kin_cli::commands::merge::MergeRequest {
        source: kin_model::RefName::branch(b"feature").unwrap(),
        operation_id: kin_model::OperationId::new(),
        actor: AuthorId::new("merge coverage test"),
    };
    let (status, body) = post(&state, "/commands/merge", &request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body) = post(
        &state,
        "/commands/conflicts",
        &kin_cli::commands::conflicts::ConflictsRequest::default(),
    )
    .await;
    let response: kin_cli::commands::conflicts::ConflictsResponse =
        serde_json::from_value(body).unwrap();
    assert!(
        response
            .report
            .unwrap()
            .record
            .unwrap()
            .entries
            .iter()
            .any(|entry| matches!(
                entry.divergence,
                kin_model::MergeDivergence::DanglingEndpoint { .. }
            )),
        "real added calls to a removed helper must remain visible"
    );
}
