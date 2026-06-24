// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::net::TcpListener;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use kin_daemon::api::HealthResponse;
use tokio::net::TcpStream;
use tokio::process::{Child, Command};

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn init_repo(root: &Path) {
    kin_core::init(root).unwrap();
}

fn spawn_daemon(repo_root: &Path, port: u16) -> Child {
    spawn_daemon_with_env(repo_root, port, &[])
}

fn spawn_daemon_with_env(repo_root: &Path, port: u16, envs: &[(&str, &str)]) -> Child {
    let bin = env!("CARGO_BIN_EXE_kin-daemon");
    let mut cmd = Command::new(bin);
    cmd.arg("--repo")
        .arg(repo_root)
        .arg("--port")
        .arg(port.to_string())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.spawn().expect("failed to spawn kin-daemon")
}

async fn wait_for_health(port: u16) -> HealthResponse {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/health");
    let deadline = Instant::now() + Duration::from_secs(60);

    loop {
        if let Ok(response) = client.get(&url).send().await {
            if response.status().is_success() {
                let health = response.json::<HealthResponse>().await.unwrap();
                if health.status == "ok" {
                    return health;
                }
            }
        }

        if Instant::now() >= deadline {
            panic!("daemon on port {port} never became healthy");
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_serving(port: u16) {
    let addr = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut observations = Vec::new();

    loop {
        match TcpStream::connect(&addr).await {
            Ok(_) => return,
            Err(error) => {
                observations.push(error.to_string());
            }
        }

        if Instant::now() >= deadline {
            let last_observation = observations
                .last()
                .cloned()
                .unwrap_or_else(|| "no response".to_string());
            panic!("daemon on port {port} never served health: {last_observation}");
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_path(path: &Path, what: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if path.exists() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("{what}: {} never appeared", path.display());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_path_removed(path: &Path, what: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if !path.exists() {
            return;
        }
        if Instant::now() >= deadline {
            panic!("{what}: {} was never removed", path.display());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn create_branch(port: u16, name: &str) {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/graph/branches");
    let deadline = Instant::now() + Duration::from_secs(10);

    loop {
        let result = client
            .post(&url)
            .json(&serde_json::json!({
                "name": name,
                "head": "0000000000000000000000000000000000000000000000000000000000000001"
            }))
            .send()
            .await
            .and_then(|response| response.error_for_status());
        if result.is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            result.expect("create branch request failed");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_recovers_after_process_kill_and_restart() {
    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());

    let port = free_port();
    let mut child = spawn_daemon(repo.path(), port);

    let first = wait_for_health(port).await;
    assert_eq!(first.status, "ok");
    assert!(first.uptime_seconds < 20);

    child.start_kill().expect("failed to kill kin-daemon");
    let exit = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("kin-daemon did not exit after kill")
        .expect("kin-daemon wait failed");
    assert!(
        !exit.success(),
        "killed kin-daemon should not report success"
    );

    let mut restarted = spawn_daemon(repo.path(), port);
    let second = wait_for_health(port).await;
    assert_eq!(second.status, "ok");
    assert!(second.uptime_seconds < 20);

    restarted
        .start_kill()
        .expect("failed to stop restarted kin-daemon");
    let _ = restarted.wait().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_exits_after_idle_timeout_and_removes_endpoint_files() {
    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());

    // A generous idle window (rather than a few seconds) keeps the daemon alive
    // long enough to deterministically observe the endpoint files on a loaded CI
    // runner before the idle timer fires and removes them.
    let idle_timeout = Duration::from_secs(15);
    let idle_secs = idle_timeout.as_secs().to_string();

    let port = free_port();
    let mut child = spawn_daemon_with_env(
        repo.path(),
        port,
        &[
            ("KIN_DAEMON_DISABLE_LSP", "1"),
            ("KIN_DAEMON_IDLE_TIMEOUT_SECS", idle_secs.as_str()),
        ],
    );

    wait_for_serving(port).await;

    let daemon_port = repo.path().join(".kin/daemon.port");
    let daemon_pid = repo.path().join(".kin/daemon.pid");
    // Poll for the endpoint files instead of asserting they are present the
    // instant the socket accepts: observing them can lag the socket becoming
    // connectable on a loaded runner, and they must still be there before the
    // idle timer removes them.
    wait_for_path(
        &daemon_port,
        "daemon did not write port file",
        Duration::from_secs(10),
    )
    .await;
    wait_for_path(
        &daemon_pid,
        "daemon did not write pid file",
        Duration::from_secs(10),
    )
    .await;

    // Wait for the idle timer to fire and the process to exit. The budget is far
    // larger than the idle window so a slow runner's shutdown still fits.
    let exit = match tokio::time::timeout(Duration::from_secs(90), child.wait()).await {
        Ok(result) => result.expect("kin-daemon wait failed"),
        Err(_) => {
            let _ = child.start_kill();
            panic!("kin-daemon did not exit after idle timeout");
        }
    };
    assert!(exit.success(), "idle shutdown should be graceful: {exit}");

    // Graceful shutdown removes the endpoint files before the process exits; poll
    // for their removal to tolerate any cleanup-vs-exit ordering gap.
    wait_for_path_removed(
        &daemon_port,
        "idle daemon left daemon.port behind",
        Duration::from_secs(10),
    )
    .await;
    wait_for_path_removed(
        &daemon_pid,
        "idle daemon left daemon.pid behind",
        Duration::from_secs(10),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_exits_after_dirty_repo_control_dir_is_removed() {
    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());

    let port = free_port();
    let mut child = spawn_daemon_with_env(
        repo.path(),
        port,
        &[
            ("KIN_DAEMON_DISABLE_LSP", "1"),
            ("KIN_DAEMON_IDLE_TIMEOUT_SECS", "30"),
        ],
    );

    wait_for_serving(port).await;
    create_branch(port, "dirty-before-delete").await;

    std::fs::remove_dir_all(repo.path().join(".kin")).unwrap();

    let exit = match tokio::time::timeout(Duration::from_secs(15), child.wait()).await {
        Ok(result) => result.expect("kin-daemon wait failed"),
        Err(_) => {
            let _ = child.start_kill();
            panic!("kin-daemon did not exit after deleted control directory");
        }
    };
    assert!(
        exit.success(),
        "deleted-control-dir idle shutdown should be graceful: {exit}"
    );
}
