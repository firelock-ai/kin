// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{BindingHistoryObservation, EntityStore};
use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
#[test]
fn kin_process_group_guardian_worker() {
    let requested = std::env::var_os(kin_daemon_spawn::PROCESS_GROUP_GUARDIAN_MODE_ENV).is_some();
    let dispatched = kin_daemon_spawn::run_process_group_guardian_if_requested()
        .expect("dispatch owned Git fixture guardian");
    assert_eq!(dispatched, requested);
}

fn git(root: &Path, args: &[&str]) {
    let output = kin_git::test_support::fixture_git_in(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn observe(result: &kin_core::InitResult) -> (BindingHistoryObservation, usize) {
    let manager = kin_db::RepositoryAuthorityManager::open(
        result.repository_id.clone(),
        Arc::new(kin_db::LocalFileBackend::new(result.layout.kindb_dir())),
    )
    .unwrap();
    let lease = manager.read_authority();
    let snapshot = lease
        .workspace_graph_snapshot(&result.workspace_id)
        .unwrap()
        .unwrap();
    let calls = snapshot
        .relations
        .values()
        .filter(|r| r.kind == kin_model::RelationKind::Calls)
        .count();
    let graph = kin_db::InMemoryGraph::from_snapshot_without_text_index(snapshot).unwrap();
    (graph.binding_history_observation(), calls)
}

#[test]
fn binding_history_actual_native_genesis_is_checked_on_cold_read() {
    let root = tempfile::tempdir().unwrap();
    let initialized = kin_core::init(root.path()).unwrap();
    assert!(matches!(
        observe(&initialized).0,
        BindingHistoryObservation::Checked { .. }
    ));
}

#[test]
fn binding_history_actual_git_healthy_history_is_checked_but_unaccounted_withdrawal_is_not() {
    for removed in [false, true] {
        let root = tempfile::tempdir().unwrap();
        git(root.path(), &["init", "--initial-branch=main"]);
        git(
            root.path(),
            &["config", "user.email", "binding-history@example.invalid"],
        );
        git(
            root.path(),
            &["config", "user.name", "Binding History Test"],
        );
        let excludes = root.path().join(".git/fixture-excludes");
        std::fs::write(&excludes, "").unwrap();
        git(
            root.path(),
            &["config", "core.excludesFile", excludes.to_str().unwrap()],
        );
        let hooks = root.path().join(".git/hooks");
        git(
            root.path(),
            &["config", "core.hooksPath", hooks.to_str().unwrap()],
        );
        std::fs::write(
            root.path().join("caller.py"),
            "from local import work\ndef run():\n    return work(value=1)\n",
        )
        .unwrap();
        std::fs::write(
            root.path().join("local.py"),
            "def work(value):\n    return value\n",
        )
        .unwrap();
        git(root.path(), &["add", "."]);
        git(
            root.path(),
            &["commit", "-m", "Actual initial local binding"],
        );
        if removed {
            std::fs::remove_file(root.path().join("local.py")).unwrap();
        } else {
            std::fs::write(
                root.path().join("README.md"),
                "Healthy retained local binding.\n",
            )
            .unwrap();
        }
        git(root.path(), &["add", "-A"]);
        git(
            root.path(),
            &["commit", "-m", "Second historical observation"],
        );
        let initialized = kin_core::init_from_git(root.path()).unwrap();
        let (observation, calls) = observe(&initialized);
        if removed {
            assert_eq!(observation, BindingHistoryObservation::Unproven);
        } else {
            assert!(calls > 0, "fixture must contain a real admitted call");
            assert!(
                matches!(observation, BindingHistoryObservation::Checked { .. }),
                "{observation:?}"
            );
            let manager = kin_db::RepositoryAuthorityManager::open(
                initialized.repository_id.clone(),
                Arc::new(kin_db::LocalFileBackend::new(
                    initialized.layout.kindb_dir(),
                )),
            )
            .unwrap();
            let before = manager
                .read_authority()
                .workspace_graph_snapshot(&initialized.workspace_id)
                .unwrap()
                .unwrap();
            let call = before
                .relations
                .values()
                .find(|relation| relation.kind == kin_model::RelationKind::Calls)
                .unwrap()
                .clone();
            let graph =
                kin_db::InMemoryGraph::from_snapshot_without_text_index(before.clone()).unwrap();
            graph.remove_relation(&call.id).unwrap();
            assert_eq!(
                graph.binding_history_observation(),
                BindingHistoryObservation::Unproven
            );
            assert!(!graph.qualify_binding_history_derivation(&before,
                &kin_index::binding_history::LocalBindingHistoryVerifier, &|digest| manager.load_source_blob(digest)).unwrap(),
                "removing an actual call without an obligation or semantic discharge must remain Unknown");
            let mut unqualified = before.clone();
            unqualified.verified_binding_history = None;
            graph.upsert_relation(&call).unwrap();
            assert!(
                !graph
                    .qualify_binding_history_derivation(
                        &unqualified,
                        &kin_index::binding_history::LocalBindingHistoryVerifier,
                        &|digest| manager.load_source_blob(digest)
                    )
                    .unwrap(),
                "current body and positive edges cannot launder unknown prior history"
            );
        }
    }
}
