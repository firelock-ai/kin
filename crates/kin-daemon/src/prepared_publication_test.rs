// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;
use axum::routing::get;
use futures_util::future::poll_fn;
use http_body::Body as _;
use std::time::{Duration, Instant};
use tower::ServiceExt;

fn fixture() -> (tempfile::TempDir, Arc<DaemonState>, DaemonLock) {
    let repo = tempfile::tempdir().unwrap();
    let init = kin_core::init(repo.path()).unwrap();
    let state = Arc::new(DaemonState::open(init.layout).unwrap());
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Release);
    let lock = crate::lifecycle::acquire_singleton_lock(state.layout.root())
        .unwrap()
        .unwrap();
    (repo, state, lock)
}

#[test]
fn prepared_guard_requires_supervisor_and_reversible_preflight_releases_cleanly() {
    let (_repo, state, singleton) = fixture();
    let fence = &state.prepared_publication;
    assert!(matches!(
        fence.begin(OperationId::new(), ()),
        Err(Refused::NoSupervisor)
    ));
    let _runtime = fence.register(&singleton, state.layout.root()).unwrap();
    let before = fence.observe().unwrap();
    let preflight = fence.begin(OperationId::new(), ()).unwrap();
    assert!(fence.pending());
    assert!(matches!(
        fence.begin(OperationId::new(), ()),
        Err(Refused::Busy)
    ));
    drop(preflight);
    assert!(!fence.pending());
    assert!(
        !before.current(),
        "a full pending interval must remain observable"
    );
    fence
        .begin(OperationId::new(), ())
        .unwrap()
        .arm()
        .verified_no_acknowledgement_or_mutation();
    assert!(!fence.pending());
    fence.shutdown();
    assert!(matches!(
        fence.begin(OperationId::new(), ()),
        Err(Refused::Closing)
    ));
}

#[tokio::test]
async fn prepared_guard_refuses_semantic_readiness_and_direct_mutator_routes() {
    let (_repo, state, singleton) = fixture();
    let _runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    let app = crate::api::router(Arc::clone(&state));
    let coordinator = state.coordination_gate.lock().await;
    let guard = state
        .prepared_publication
        .begin(OperationId::new(), coordinator)
        .unwrap();
    let before = state.graph.to_snapshot();
    for (method, path, body) in [
        ("GET", "/ready", ""),
        ("GET", "/readiness", ""),
        ("GET", "/health", ""),
        ("GET", "/search?q=anything", ""),
        ("GET", "/graph/events", ""),
        ("GET", "/vfs/subscribe", ""),
        ("POST", "/mcp/tools/call", "{}"),
        ("POST", "/graph/mutations", "{}"),
        ("POST", "/work", "{}"),
        ("POST", "/note", "{}"),
        ("GET", "/v2/ready", ""),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("host", "localhost")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["semantic_ready"], false, "{path}");
    }
    assert_eq!(
        serde_json::to_value(state.graph.to_snapshot()).unwrap(),
        serde_json::to_value(before).unwrap()
    );
    drop(guard);
}

#[tokio::test]
async fn prepared_guard_rejects_inflight_read_even_if_operation_already_completed() {
    let (_repo, state, singleton) = fixture();
    let _runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let handler_entered = Arc::clone(&entered);
    let handler_release = Arc::clone(&release);
    let app = axum::Router::new()
        .route(
            "/query",
            get(move || async move {
                handler_entered.notify_one();
                handler_release.notified().await;
                "current semantic answer"
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            serving,
        ));
    let task = tokio::spawn(app.oneshot(Request::get("/query").body(Body::empty()).unwrap()));
    entered.notified().await;
    drop(
        state
            .prepared_publication
            .begin(OperationId::new(), ())
            .unwrap(),
    );
    release.notify_one();
    assert_eq!(
        task.await.unwrap().unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn prepared_guard_preserves_only_opaque_finalized_owner_receipt() {
    let (_repo, state, singleton) = fixture();
    let _runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    let handler_state = Arc::clone(&state);
    let app = axum::Router::new()
        .route(
            "/owner",
            get(move || async move {
                let operation = OperationId::new();
                let (_, permit) = handler_state
                    .prepared_publication
                    .begin(operation, ())
                    .unwrap()
                    .arm()
                    .verified_finalized();
                assert_eq!(permit.operation, operation);
                let mut response =
                    Json(serde_json::json!({"operation": operation})).into_response();
                response.extensions_mut().insert(permit);
                response
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            serving,
        ));
    let response = app
        .oneshot(Request::get("/owner").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let later = state
        .prepared_publication
        .begin(OperationId::new(), ())
        .unwrap();
    assert!(
        !axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap()
            .is_empty(),
        "the original receipt is immutable, not a claim about the later operation"
    );
    drop(later);
}

#[tokio::test]
async fn prepared_guard_terminates_existing_graph_and_vfs_streams_on_epoch_change() {
    let (_repo, state, singleton) = fixture();
    let _runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    let app = crate::api::router(Arc::clone(&state));
    for path in ["/graph/events", "/vfs/subscribe"] {
        let response = app
            .clone()
            .oneshot(
                Request::get(path)
                    .header("host", "localhost")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        assert!(poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .unwrap()
            .is_ok());
        let waiting =
            tokio::spawn(async move { poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await });
        let preflight = state
            .prepared_publication
            .begin(OperationId::new(), ())
            .unwrap();
        drop(preflight); // Still close: Boolean-only tests would miss this interval.
        let frame = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
        assert!(
            frame.unwrap().is_err(),
            "{path} emitted a frame across a pending epoch"
        );
    }
}

#[tokio::test]
async fn prepared_guard_refuses_unpolled_response_body_after_arm() {
    let (_repo, state, singleton) = fixture();
    let _runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    let app = axum::Router::new()
        .route("/query", get(|| async { "current answer" }))
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            serving,
        ));
    let response = app
        .oneshot(Request::get("/query").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let guard = state
        .prepared_publication
        .begin(OperationId::new(), ())
        .unwrap();
    assert!(axum::body::to_bytes(response.into_body(), 4096)
        .await
        .is_err());
    drop(guard);
}

const CHILD_REPO: &str = "KINTEST_PREPARED_PUBLICATION_REPO";
const CHILD_MODE: &str = "KINTEST_PREPARED_PUBLICATION_MODE";
const UNSAVED_ACTION: &str = "prepared-publication-controlled-unsaved";

/// Only installed in the actual daemon run's test build. All inputs are local
/// synthetic publication lifecycle signals; no fake DB acknowledgement exists.
pub(crate) fn install_actual_daemon_control(state: Arc<DaemonState>, cancel: watch::Sender<bool>) {
    let Ok(mode) = std::env::var(CHILD_MODE) else {
        return;
    };
    let runtime = tokio::runtime::Handle::current();
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !state
            .is_initialized
            .load(std::sync::atomic::Ordering::Acquire)
        {
            assert!(
                Instant::now() < deadline,
                "actual daemon initialization timeout"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let coordinated = runtime.block_on(state.coordination_gate.lock());
        let persisted = state.persist_lock.lock().unwrap();
        kin_cli::provenance::record_cli_audit_event(
            state.graph.as_ref(),
            UNSAVED_ACTION,
            None,
            None,
        )
        .unwrap();
        state.mark_dirty();
        let _ = std::fs::remove_file(state.layout.root().join("prepared-normal-save-observed"));
        if mode == "healthy" {
            drop(persisted);
            drop(coordinated);
            cancel.send(true).unwrap();
            return;
        }
        struct CustodyDrop(PathBuf);
        impl Drop for CustodyDrop {
            fn drop(&mut self) {
                std::fs::write(&self.0, b"released").unwrap();
            }
        }
        let custody = (
            coordinated,
            persisted,
            CustodyDrop(state.layout.root().join("prepared-custody-released")),
        );
        let armed = state
            .prepared_publication
            .begin(OperationId::new(), custody)
            .unwrap()
            .arm();
        match mode.as_str() {
            "drop" => drop(armed),
            "panic" => {
                let _armed = armed;
                panic!("controlled armed-owner unwind");
            }
            "shutdown" => {
                let _armed = armed;
                cancel.send(true).unwrap();
                loop {
                    std::thread::park();
                }
            }
            other => panic!("unknown controlled mode {other}"),
        }
        panic!("unresolved armed drop returned");
    });
}

#[test]
fn prepared_guard_actual_daemon_child() {
    let Some(repo) = std::env::var_os(CHILD_REPO) else {
        return;
    };
    let init = kin_core::init(Path::new(&repo)).unwrap();
    let singleton = crate::lifecycle::acquire_singleton_lock(init.layout.root())
        .unwrap()
        .unwrap();
    let state = DaemonState::open(init.layout).unwrap();
    let config = crate::daemon::DaemonConfig {
        api_port: 0,
        lsp_enabled: false,
        sweep_interval: Duration::from_secs(3600),
        embed_interval: Duration::from_secs(3600),
        ..Default::default()
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(crate::daemon::run_with_authority(state, config, singleton))
        .unwrap();
    assert_eq!(
        std::env::var(CHILD_MODE).unwrap(),
        "healthy",
        "protected child returned normally"
    );
}

/// One owned daemon child. Dropping it stops the process it started and
/// nothing else; no controlled harness signals a process it did not spawn.
pub(crate) struct Child(pub(crate) std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// Spawn this test binary again as one controlled daemon child running exactly
/// one test against `repo`, under the runtime isolation every child control
/// needs: its own registry and home, no auto embedding and no language server.
///
/// The interruption controls share this spawner rather than each growing one,
/// so a child's isolation is defined once and every control inherits it.
pub(crate) fn spawn_child_test(
    test_path: &str,
    repo: &Path,
    extra_env: &[(&str, std::ffi::OsString)],
) -> Child {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test_path, "--nocapture", "--test-threads=1"])
        .env(
            "KIN_REGISTRY_PATH",
            repo.join(".controlled-runtime/registry.toml"),
        )
        .env("KIN_HOME", repo.join(".controlled-runtime/managed"))
        .env("KINTEST_PAUSE_BEFORE_EXIT_MS", "1800")
        .env("KIN_DAEMON_AUTO_EMBED", "0")
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_EMBED_BACKEND", "cpu");
    for (key, value) in extra_env {
        command.env(key, value);
    }
    Child(command.spawn().unwrap())
}

fn child(mode: &str, repo: &Path) -> Child {
    spawn_child_test(
        "prepared_publication::tests::prepared_guard_actual_daemon_child",
        repo,
        &[
            (CHILD_REPO, repo.as_os_str().to_owned()),
            (CHILD_MODE, std::ffi::OsString::from(mode)),
        ],
    )
}

#[test]
fn prepared_guard_actual_daemon_drop_panic_and_shutdown_hold_singleton_until_exit_without_save() {
    for mode in ["drop", "panic", "shutdown"] {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path().join(".kin");
        let mut worker = child(mode, repo.path());
        let deadline = Instant::now() + Duration::from_secs(45);
        let note = loop {
            if let Some(note) = kin_daemon_spawn::read_daemon_death_note(&root) {
                break note;
            }
            assert!(
                worker.0.try_wait().unwrap().is_none(),
                "{mode} child exited without diagnostic"
            );
            assert!(
                Instant::now() < deadline,
                "{mode} child did not protected-stop"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(note.killed_by, "kin-daemon prepared publication");
        let until = Instant::now() + Duration::from_millis(500);
        while Instant::now() < until {
            assert!(worker.0.try_wait().unwrap().is_none());
            assert!(
                crate::lifecycle::acquire_singleton_lock_within(&root, Duration::ZERO)
                    .unwrap()
                    .is_none()
            );
            assert!(!root.join("prepared-custody-released").exists());
            std::thread::sleep(Duration::from_millis(10));
        }
        let status = loop {
            if let Some(status) = worker.0.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.code(), Some(70));
        let singleton = crate::lifecycle::acquire_singleton_lock_within(&root, Duration::ZERO)
            .unwrap()
            .unwrap();
        let state = DaemonState::open(kin_core::KinLayout::new(repo.path().join(".kin"))).unwrap();
        assert!(
            !state
                .graph
                .to_snapshot()
                .audit_events
                .iter()
                .any(|event| event.action == UNSAVED_ACTION),
            "{mode}: ordinary shutdown saved unresolved live state"
        );
        assert!(
            !root.join("prepared-normal-save-observed").exists(),
            "{mode}: actual save entered after protected custody was acquired"
        );
        assert!(!root.join("prepared-custody-released").exists());
        drop(singleton);
    }
}

#[test]
fn prepared_guard_actual_daemon_healthy_shutdown_still_enters_save() {
    let repo = tempfile::tempdir().unwrap();
    let mut worker = child("healthy", repo.path());
    let deadline = Instant::now() + Duration::from_secs(45);
    let status = loop {
        if let Some(status) = worker.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "healthy shutdown did not finish");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success());
    let state = DaemonState::open(kin_core::KinLayout::new(repo.path().join(".kin"))).unwrap();
    assert!(
        state
            .layout
            .root()
            .join("prepared-normal-save-observed")
            .exists(),
        "healthy shutdown must enter the real snapshot save under its persistence lock"
    );
}

pub(crate) fn record_actual_save_entry(state: &DaemonState) {
    if std::env::var_os(CHILD_REPO).is_some() && state.prepared_publication.lock().runtime.is_some()
    {
        std::fs::write(
            state.layout.root().join("prepared-normal-save-observed"),
            b"actual supervised save entered under persistence lock",
        )
        .unwrap();
    }
}
