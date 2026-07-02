// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end proof of the daemon-owned port handshake.
//!
//! The daemon binds an OS-assigned ephemeral port (`--port 0`) and publishes the
//! *actual* bound port to `.kin/daemon.port`. The CLI reads the port from that
//! file instead of reserving a port and releasing it before the daemon re-binds
//! — the reserve-release-rebind window a sibling process could steal, killing
//! the daemon during startup under parallel load.
//!
//! Because the daemon owns port selection, this test needs no `#[serial]` and no
//! reserved port to collide on: it spins up its own daemon against a scratch
//! tempdir store on an ephemeral port and never touches the shared runtime or
//! `~/.kin`.

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::process::{Child, Command};

/// Readiness budget for the daemon to bind and serve. Generous so two CI runs
/// sharing a runner can both come up under load without a false timeout; a
/// daemon that dies during startup is detected eagerly via its child handle, so
/// this only ever bounds a slow-but-live startup, never a dead one.
const READINESS_TIMEOUT: Duration = Duration::from_secs(180);

fn spawn_daemon_ephemeral(repo_root: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_kin-daemon"))
        .arg("--repo")
        .arg(repo_root)
        // The feature under test: the daemon, not the launcher, picks the port.
        .arg("--port")
        .arg("0")
        // Keep the test hermetic and light: no LSP discovery on the host.
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("failed to spawn kin-daemon")
}

fn read_port_file(kin_root: &Path) -> Option<u16> {
    std::fs::read_to_string(kin_root.join("daemon.port"))
        .ok()
        .and_then(|value| value.trim().parse().ok())
}

/// Fail loudly the instant the daemon child exits before it is ready, instead of
/// polling a dead process until the deadline.
fn assert_child_alive(child: &mut Child, what: &str) {
    if let Ok(Some(status)) = child.try_wait() {
        panic!("daemon exited before it became {what}: {status}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_binds_ephemeral_port_and_publishes_it() {
    let repo = tempfile::TempDir::new().expect("tempdir");
    kin_core::init(repo.path()).expect("init scratch repo");
    let kin_root = repo.path().join(".kin");

    let mut child = spawn_daemon_ephemeral(repo.path());
    let deadline = Instant::now() + READINESS_TIMEOUT;

    // Handshake half 1: the daemon must publish a real, non-zero bound port —
    // never the sentinel 0 we passed on the command line.
    let port = loop {
        assert_child_alive(&mut child, "bound");
        if let Some(port) = read_port_file(&kin_root) {
            assert_ne!(port, 0, "daemon must publish its real bound port, not 0");
            break port;
        }
        if Instant::now() >= deadline {
            let _ = child.kill().await;
            panic!("daemon never wrote its bound port to daemon.port");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    // Handshake half 2: the published port must actually serve — /health
    // responds on exactly the port the daemon reported.
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/health");
    let mut healthy = false;
    while Instant::now() < deadline {
        assert_child_alive(&mut child, "healthy");
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                healthy = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Shut the daemon down before asserting so a failure never leaks a process.
    let _ = child.kill().await;
    let _ = child.wait().await;

    assert!(
        healthy,
        "daemon did not serve /health on its published port {port}"
    );
}
