// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Native clone and retry against two real repository daemons.

use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::process::Output;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tempfile::tempdir;

mod common;

struct AdvertiseOnceProxy {
    endpoint: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl AdvertiseOnceProxy {
    fn new(upstream: String, advertisement: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let advertisement = Arc::new(Mutex::new(Some(advertisement)));
        let worker = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let client = reqwest::Client::builder()
                        .timeout(Duration::from_secs(10))
                        .build()
                        .unwrap();
                    let router =
                        axum::Router::new().fallback(move |request: axum::extract::Request| {
                            let client = client.clone();
                            let upstream = upstream.clone();
                            let advertisement = advertisement.clone();
                            async move {
                                let captured =
                                    if request.uri().path().ends_with("/transfer/advertise") {
                                        advertisement.lock().unwrap().take()
                                    } else {
                                        None
                                    };
                                if let Some(captured) = captured {
                                    return axum::response::Response::new(axum::body::Body::from(
                                        captured,
                                    ));
                                }
                                let (parts, body) = request.into_parts();
                                let body =
                                    axum::body::to_bytes(body, 16 * 1024 * 1024).await.unwrap();
                                let mut headers = parts.headers;
                                headers.remove(axum::http::header::HOST);
                                let response = client
                                    .request(parts.method, format!("{upstream}{}", parts.uri))
                                    .headers(headers)
                                    .body(body)
                                    .send()
                                    .await
                                    .unwrap();
                                let code = response.status();
                                axum::response::Response::builder()
                                    .status(code)
                                    .body(axum::body::Body::from(response.bytes().await.unwrap()))
                                    .unwrap()
                            }
                        });
                    axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), router)
                        .with_graceful_shutdown(async {
                            let _ = stopped.await;
                        })
                        .await
                        .unwrap();
                });
        });
        Self {
            endpoint,
            shutdown: Some(shutdown),
            worker: Some(worker),
        }
    }
}

impl Drop for AdvertiseOnceProxy {
    fn drop(&mut self) {
        let _ = self.shutdown.take().unwrap().send(());
        self.worker
            .take()
            .unwrap()
            .join()
            .expect("join fixture proxy");
    }
}

fn require_success(output: Output) -> Output {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn run(runtime: &common::IsolatedDaemonRuntime, repo: &Path, args: &[&str]) -> Output {
    runtime
        .kin_command()
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_EMBED_BACKEND", "cpu")
        .current_dir(repo)
        .args(args)
        .output()
        .expect("run isolated Kin command")
}

fn status(runtime: &common::IsolatedDaemonRuntime, repo: &Path) -> Value {
    serde_json::from_slice(&require_success(run(runtime, repo, &["status", "--json"])).stdout)
        .expect("status JSON")
}

fn history(runtime: &common::IsolatedDaemonRuntime, repo: &Path) -> Value {
    serde_json::from_slice(
        &require_success(run(runtime, repo, &["log", "--json", "--count", "100"])).stdout,
    )
    .expect("history JSON")
}

fn configure_author(repo: &Path) {
    let path = repo.join(".kin/config.toml");
    let mut config = kin_core::KinConfig::load_or_default(&path).unwrap();
    config.default_author = Some("Native Clone Test <native-clone@example.invalid>".to_string());
    config.save(&path).unwrap();
}

fn initialize_source(runtime: &common::IsolatedDaemonRuntime, source: &Path) -> (String, String) {
    fs::create_dir(source).unwrap();
    let initialized = kin_core::init_replica(source, "trunk").unwrap();
    let repository = initialized.repository_id.to_string();
    drop(initialized);
    configure_author(source);
    fs::create_dir(source.join("src")).unwrap();
    fs::write(source.join("src/lib.rs"), b"pub fn answer() -> u8 { 42 }\n").unwrap();
    fs::write(source.join("payload.bin"), [0, 255, 128, 10, 0]).unwrap();
    require_success(run(
        runtime,
        source,
        &["commit", "-m", "Add native source bodies"],
    ));
    let port = fs::read_to_string(source.join(".kin/daemon.port")).unwrap();
    (repository, format!("http://127.0.0.1:{}", port.trim()))
}

fn clone_command(
    runtime: &common::IsolatedDaemonRuntime,
    parent: &Path,
    destination: &Path,
    source: &Path,
    endpoint: &str,
    repository: &str,
    unavailable_daemon: Option<&str>,
) -> Output {
    let token = fs::read_to_string(source.join(".kin/daemon.token")).unwrap();
    let mut command = runtime.kin_command();
    command
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_EMBED_BACKEND", "cpu")
        .fixture_remote_bearer_token(token.trim())
        .current_dir(parent)
        .args(["clone", endpoint, "--repository", repository])
        .arg(destination);
    if let Some(endpoint) = unavailable_daemon {
        command.fixture_daemon_url(endpoint);
    }
    command.output().expect("clone native repository")
}

fn pull(runtime: &common::IsolatedDaemonRuntime, destination: &Path, source: &Path) {
    transfer(runtime, destination, source, "pull");
}

fn transfer(
    runtime: &common::IsolatedDaemonRuntime,
    destination: &Path,
    source: &Path,
    verb: &str,
) {
    let token = fs::read_to_string(source.join(".kin/daemon.token")).unwrap();
    require_success(
        runtime
            .kin_command()
            .env("KIN_DAEMON_BIN", runtime.daemon_bin())
            .env("KIN_DAEMON_DISABLE_LSP", "1")
            .env("KIN_EMBED_BACKEND", "cpu")
            .fixture_remote_bearer_token(token.trim())
            .current_dir(destination)
            .arg(verb)
            .output()
            .expect("transfer native repository"),
    );
}

fn assert_exact_replicas(
    source_runtime: &common::IsolatedDaemonRuntime,
    source: &Path,
    clone_runtime: &common::IsolatedDaemonRuntime,
    destination: &Path,
    paths: &[&str],
) {
    let source_status = status(source_runtime, source);
    let clone_status = status(clone_runtime, destination);
    let source_repository = &source_status["repository"];
    let clone_repository = &clone_status["repository"];
    assert!(!source_repository["repository_id"].is_null());
    assert_eq!(
        source_repository["repository_id"],
        clone_repository["repository_id"]
    );
    assert_eq!(
        source_repository["default_ref"],
        clone_repository["default_ref"]
    );
    assert_eq!(clone_repository["source_cas_verified"], true);
    assert_eq!(clone_status["workspace"]["dirty"], false);
    assert!(!source_status["workspace"]["tree_hash"].is_null());
    assert_eq!(
        source_status["workspace"]["tree_hash"],
        clone_status["workspace"]["tree_hash"]
    );
    assert_ne!(
        source_status["workspace"]["workspace_id"],
        clone_status["workspace"]["workspace_id"]
    );
    let source_history = history(source_runtime, source);
    let clone_history = history(clone_runtime, destination);
    assert!(!source_history["start_change"].is_null());
    assert_eq!(
        source_history["start_change"],
        clone_history["start_change"]
    );
    let ids = |report: &Value| {
        report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["change_id"].clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(&source_history), ids(&clone_history));
    for path in paths {
        assert_eq!(
            fs::read(source.join(path)).unwrap(),
            fs::read(destination.join(path)).unwrap(),
            "projected bytes for {path}"
        );
    }
    assert!(!destination.join(".git").exists());
    let config_text = fs::read_to_string(destination.join(".kin/config.toml")).unwrap();
    let token = fs::read_to_string(source.join(".kin/daemon.token")).unwrap();
    assert!(
        !config_text.contains(token.trim()),
        "origin must not persist the peer token"
    );
    let token = fs::read_to_string(destination.join(".kin/daemon.token")).unwrap();
    assert!(
        !config_text.contains(token.trim()),
        "origin must not persist the local token"
    );
    let config =
        kin_core::KinConfig::load_or_default(&destination.join(".kin/config.toml")).unwrap();
    assert_eq!(config.remote.default.as_deref(), Some("origin"));
    assert_eq!(config.remote.refs[0].host, kin_core::RemoteHostKind::Peer);
}

#[test]
fn native_clone_adopts_history_projects_bodies_and_pulls_new_paths_and_edits() {
    let scratch = tempdir().unwrap();
    let source = scratch.path().join("source");
    let destination = scratch.path().join("replica");
    let source_runtime = common::IsolatedDaemonRuntime::new(&source);
    let clone_runtime = common::IsolatedDaemonRuntime::new(&destination);
    let (repository, endpoint) = initialize_source(&source_runtime, &source);
    let token = fs::read_to_string(source.join(".kin/daemon.token")).unwrap();
    let advertisement = reqwest::blocking::Client::new()
        .get(format!("{endpoint}/repos/{repository}/transfer/advertise"))
        .bearer_auth(token.trim())
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .bytes()
        .unwrap();
    fs::write(source.join("src/lib.rs"), b"pub fn answer() -> u8 { 41 }\n").unwrap();
    require_success(run(
        &source_runtime,
        &source,
        &["commit", "-m", "Advance after captured advertisement"],
    ));
    let proxy = AdvertiseOnceProxy::new(endpoint, advertisement.to_vec());
    let output = require_success(clone_command(
        &clone_runtime,
        scratch.path(),
        &destination,
        &source,
        &proxy.endpoint,
        &repository,
        None,
    ));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Cloned native Kin repository authority")
    );
    assert_exact_replicas(
        &source_runtime,
        &source,
        &clone_runtime,
        &destination,
        &["src/lib.rs", "payload.bin"],
    );
    fs::write(source.join("src/lib.rs"), b"pub fn answer() -> u8 { 43 }\n").unwrap();
    fs::write(
        source.join("src/added.rs"),
        b"pub fn introduced() -> bool { true }\n",
    )
    .unwrap();
    require_success(run(
        &source_runtime,
        &source,
        &["commit", "-m", "Edit and extend native source"],
    ));
    pull(&clone_runtime, &destination, &source);
    assert_exact_replicas(
        &source_runtime,
        &source,
        &clone_runtime,
        &destination,
        &["src/lib.rs", "src/added.rs", "payload.bin"],
    );
    configure_author(&destination);
    fs::write(
        destination.join("from-client.bin"),
        b"\0native client artifact\xff\n",
    )
    .unwrap();
    require_success(run(
        &clone_runtime,
        &destination,
        &[
            "commit",
            "-m",
            "Publish a native artifact from cloned client",
        ],
    ));
    transfer(&clone_runtime, &destination, &source, "push");
    let fetched = scratch.path().join("fetched");
    let fetched_runtime = common::IsolatedDaemonRuntime::new(&fetched);
    require_success(clone_command(
        &fetched_runtime,
        scratch.path(),
        &fetched,
        &source,
        &proxy.endpoint,
        &repository,
        None,
    ));
    assert_exact_replicas(
        &clone_runtime,
        &destination,
        &fetched_runtime,
        &fetched,
        &[
            "src/lib.rs",
            "src/added.rs",
            "payload.bin",
            "from-client.bin",
        ],
    );
    assert_eq!(
        fs::read(fetched.join("from-client.bin")).unwrap(),
        b"\0native client artifact\xff\n"
    );
}

#[test]
fn native_clone_preserves_an_empty_repository_without_inventing_history() {
    let scratch = tempdir().unwrap();
    let source = scratch.path().join("source");
    let destination = scratch.path().join("replica");
    fs::create_dir(&source).unwrap();
    let initialized = kin_core::init_replica(&source, "trunk").unwrap();
    let repository = initialized.repository_id.to_string();
    drop(initialized);
    configure_author(&source);
    let source_runtime = common::IsolatedDaemonRuntime::new(&source);
    let clone_runtime = common::IsolatedDaemonRuntime::new(&destination);
    require_success(run(&source_runtime, &source, &["admit"]));
    let source_status = status(&source_runtime, &source);
    let port = fs::read_to_string(source.join(".kin/daemon.port")).unwrap();
    require_success(clone_command(
        &clone_runtime,
        scratch.path(),
        &destination,
        &source,
        &format!("http://127.0.0.1:{}", port.trim()),
        &repository,
        None,
    ));
    let replica_status = status(&clone_runtime, &destination);
    assert_eq!(
        replica_status["repository"]["repository_id"],
        source_status["repository"]["repository_id"]
    );
    assert_eq!(
        replica_status["repository"]["default_ref"],
        source_status["repository"]["default_ref"]
    );
    assert_eq!(
        replica_status["workspace"]["tree_hash"],
        source_status["workspace"]["tree_hash"]
    );
    assert_eq!(replica_status["workspace"]["dirty"], false);
    let history = history(&clone_runtime, &destination);
    assert!(history["start_change"].is_null());
    assert!(history["entries"].as_array().unwrap().is_empty());
    assert!(!destination.join(".git").exists());
    fs::write(
        source.join("first.rs"),
        b"pub fn first() -> bool { true }\n",
    )
    .unwrap();
    require_success(run(
        &source_runtime,
        &source,
        &["commit", "-m", "Publish the first native path"],
    ));
    pull(&clone_runtime, &destination, &source);
    assert_exact_replicas(
        &source_runtime,
        &source,
        &clone_runtime,
        &destination,
        &["first.rs"],
    );
}

#[test]
fn native_clone_bootstraps_git_history_and_then_pulls_a_native_new_path() {
    let scratch = tempdir().unwrap();
    let source = scratch.path().join("source");
    let destination = scratch.path().join("replica");
    fs::create_dir(&source).unwrap();
    let git = |args: &[&str]| {
        require_success(
            common::Command::new("git")
                .current_dir(&source)
                .args(args)
                .output()
                .unwrap(),
        )
    };
    git(&["init", "--initial-branch=trunk"]);
    git(&["config", "user.name", "Native Clone Test"]);
    git(&["config", "user.email", "native-clone@example.invalid"]);
    git(&["config", "commit.gpgsign", "false"]);
    fs::create_dir(source.join("src")).unwrap();
    let old_source = b"pub fn imported() -> u8 { 1 }\n";
    let old_payload = [0, 1, 255];
    fs::write(source.join("src/lib.rs"), old_source).unwrap();
    fs::write(source.join("payload.bin"), old_payload).unwrap();
    git(&["add", "--all"]);
    git(&["commit", "-m", "First imported tree"]);
    fs::write(
        source.join("src/lib.rs"),
        b"pub fn imported() -> u8 { 2 }\n",
    )
    .unwrap();
    fs::write(source.join("payload.bin"), [0, 2, 254]).unwrap();
    git(&["add", "--all"]);
    git(&["commit", "-m", "Second imported tree"]);
    let source_runtime = common::IsolatedDaemonRuntime::new(&source);
    let clone_runtime = common::IsolatedDaemonRuntime::new(&destination);
    require_success(run(&source_runtime, &source, &["init", ".", "--json"]));
    configure_author(&source);
    require_success(run(&source_runtime, &source, &["admit"]));
    let source_status = status(&source_runtime, &source);
    let repository = source_status["repository"]["repository_id"]
        .as_str()
        .unwrap();
    let port = fs::read_to_string(source.join(".kin/daemon.port")).unwrap();
    require_success(clone_command(
        &clone_runtime,
        scratch.path(),
        &destination,
        &source,
        &format!("http://127.0.0.1:{}", port.trim()),
        repository,
        None,
    ));
    assert_exact_replicas(
        &source_runtime,
        &source,
        &clone_runtime,
        &destination,
        &["src/lib.rs", "payload.bin"],
    );
    configure_author(&destination);
    let source_history = history(&source_runtime, &source);
    let entries = source_history["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    let change = |entry: &Value| {
        serde_json::from_value::<kin_model::SemanticChangeId>(entry["change_id"].clone())
            .unwrap()
            .to_string()
    };
    let head = change(&entries[0]);
    let base = change(&entries[1]);
    let diff = |runtime: &common::IsolatedDaemonRuntime, repo: &Path| {
        serde_json::from_slice::<Value>(
            &require_success(run(
                runtime,
                repo,
                &["diff", &base, &head, "--json", "--full-bodies"],
            ))
            .stdout,
        )
        .unwrap()
    };
    let source_diff = diff(&source_runtime, &source);
    let replica_diff = diff(&clone_runtime, &destination);
    assert_eq!(source_diff["artifact_deltas"].as_array().unwrap().len(), 2);
    assert_eq!(source_diff["artifact_content"].as_array().unwrap().len(), 2);
    for endpoint in ["base", "head"] {
        assert!(!source_diff[endpoint]["tree_hash"].is_null());
        assert_eq!(
            source_diff[endpoint]["tree_hash"],
            replica_diff[endpoint]["tree_hash"]
        );
    }
    assert_eq!(
        source_diff["artifact_deltas"],
        replica_diff["artifact_deltas"]
    );
    assert_eq!(
        source_diff["artifact_content"],
        replica_diff["artifact_content"]
    );
    for path in ["src/lib.rs", "payload.bin"] {
        require_success(run(
            &clone_runtime,
            &destination,
            &["checkout", path, "--change", &base],
        ));
    }
    assert_eq!(
        fs::read(destination.join("src/lib.rs")).unwrap(),
        old_source
    );
    assert_eq!(
        fs::read(destination.join("payload.bin")).unwrap(),
        old_payload
    );
    for path in ["src/lib.rs", "payload.bin"] {
        require_success(run(
            &clone_runtime,
            &destination,
            &["checkout", path, "--change", &head],
        ));
    }
    assert_exact_replicas(
        &source_runtime,
        &source,
        &clone_runtime,
        &destination,
        &["src/lib.rs", "payload.bin"],
    );
    fs::write(
        source.join("src/native.rs"),
        b"pub fn born_in_kin() -> bool { true }\n",
    )
    .unwrap();
    require_success(run(
        &source_runtime,
        &source,
        &["commit", "-m", "Introduce a native path after Git import"],
    ));
    pull(&clone_runtime, &destination, &source);
    assert_exact_replicas(
        &source_runtime,
        &source,
        &clone_runtime,
        &destination,
        &["src/lib.rs", "src/native.rs", "payload.bin"],
    );
}

#[test]
fn native_clone_refuses_clobber_and_retains_identity_for_retry_after_startup_failure() {
    let scratch = tempdir().unwrap();
    let source = scratch.path().join("source");
    let destination = scratch.path().join("replica");
    let source_runtime = common::IsolatedDaemonRuntime::new(&source);
    let clone_runtime = common::IsolatedDaemonRuntime::new(&destination);
    let (repository, endpoint) = initialize_source(&source_runtime, &source);
    let unavailable = TcpListener::bind("127.0.0.1:0").unwrap();
    let unavailable_endpoint = format!("http://{}", unavailable.local_addr().unwrap());
    drop(unavailable);
    let output = clone_command(
        &clone_runtime,
        scratch.path(),
        &destination,
        &source,
        &endpoint,
        &repository,
        Some(&unavailable_endpoint),
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("durably adopted repository"), "{stderr}");
    assert!(stderr.contains("kin pull"), "{stderr}");
    let manifest_before = fs::read(destination.join(".kin/manifest.json")).unwrap();
    let refused = clone_command(
        &clone_runtime,
        scratch.path(),
        &destination,
        &source,
        &endpoint,
        &repository,
        None,
    );
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("not empty"));
    assert_eq!(
        manifest_before,
        fs::read(destination.join(".kin/manifest.json")).unwrap()
    );
    pull(&clone_runtime, &destination, &source);
    assert_exact_replicas(
        &source_runtime,
        &source,
        &clone_runtime,
        &destination,
        &["src/lib.rs", "payload.bin"],
    );
    let occupied = scratch.path().join("occupied");
    fs::create_dir(&occupied).unwrap();
    fs::write(occupied.join("keep"), b"owned bytes").unwrap();
    assert!(!clone_command(
        &clone_runtime,
        scratch.path(),
        &occupied,
        &source,
        &endpoint,
        &repository,
        None
    )
    .status
    .success());
    assert_eq!(fs::read(occupied.join("keep")).unwrap(), b"owned bytes");
    assert!(!occupied.join(".kin").exists());
    #[cfg(unix)]
    {
        let link = scratch.path().join("symlink");
        std::os::unix::fs::symlink(&occupied, &link).unwrap();
        assert!(!clone_command(
            &clone_runtime,
            scratch.path(),
            &link,
            &source,
            &endpoint,
            &repository,
            None
        )
        .status
        .success());
        assert_eq!(fs::read_link(link).unwrap(), occupied);
    }
    let uncreated = scratch.path().join("uncreated");
    let refused = clone_command(
        &clone_runtime,
        scratch.path(),
        &uncreated,
        &source,
        &unavailable_endpoint,
        &repository,
        None,
    );
    assert!(!refused.status.success());
    assert!(
        !uncreated.exists(),
        "identity negotiation failure must not initialize a destination"
    );
}
