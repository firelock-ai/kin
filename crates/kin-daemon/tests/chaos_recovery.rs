// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::net::TcpListener;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use kin_daemon::api::HealthResponse;
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
    let bin = env!("CARGO_BIN_EXE_kin-daemon");
    Command::new(bin)
        .arg("--repo")
        .arg(repo_root)
        .arg("--port")
        .arg(port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn kin-daemon")
}

async fn wait_for_health(port: u16) -> HealthResponse {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/health");
    let deadline = Instant::now() + Duration::from_secs(20);

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

    restarted.start_kill().expect("failed to stop restarted kin-daemon");
    let _ = restarted.wait().await;
}
