// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! An MCP session keeps the daemon it attached to alive, and hands the daemon
//! back its own idle policy when it ends.
//!
//! The shape this reproduces: a daemon started by an ordinary CLI command runs
//! with the short CLI idle window. An MCP session attaches to it afterwards and
//! makes tool calls spaced further apart than that window. Before sessions held
//! an idle floor, the daemon exited on its own window between two calls, and
//! the next call found nothing listening.
//!
//! The window here is compressed to a few seconds so the test runs in well
//! under a minute; everything else is the production path: a real daemon
//! process, and tool calls forwarded through the same `kin_mcp` delegate a
//! `kin mcp start` session uses, which holds and renews the floor itself.

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::process::Command;

mod common;

use common::{
    isolate_daemon_test_command, spawn_daemon_test_command, terminate_daemon, DaemonChild,
};

const READINESS_TIMEOUT: Duration = Duration::from_secs(180);

/// The daemon's own window: the stand-in for the CLI's sixty seconds.
const OWN_WINDOW: Duration = Duration::from_secs(3);

/// The gap between two tool calls, longer than the daemon's own window by
/// more than the idle monitor's check interval, so a daemon holding only its
/// own window provably exits inside every gap.
const CALL_GAP: Duration = Duration::from_secs(6);

const TOKEN: &str = "mcp-session-idle-floor-test-token";

fn spawn_daemon(repo_root: &Path) -> DaemonChild {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kin-daemon"));
    isolate_daemon_test_command(&mut cmd);
    cmd.arg("--repo")
        .arg(repo_root)
        .arg("--port")
        .arg("0")
        .env(
            "KIN_REGISTRY_PATH",
            repo_root.join(".kin/test-runtime/registry.toml"),
        )
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_AUTO_EMBED", "0")
        .env(
            "KIN_DAEMON_IDLE_TIMEOUT_SECS",
            OWN_WINDOW.as_secs().to_string(),
        )
        .env("KIN_DAEMON_AUTH_TOKEN", TOKEN)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    spawn_daemon_test_command(cmd, "mcp session idle floor daemon")
        .expect("failed to spawn contained kin-daemon")
}

async fn published_port(child: &mut DaemonChild, repo_root: &Path) -> u16 {
    let port_file = repo_root.join(".kin/daemon.port");
    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        if let Some(port) = std::fs::read_to_string(&port_file)
            .ok()
            .and_then(|contents| contents.trim().parse::<u16>().ok())
            .filter(|port| *port != 0)
        {
            return port;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("daemon exited before publishing its port: {status}");
        }
        assert!(Instant::now() < deadline, "daemon never published a port");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_until_ready(child: &mut DaemonChild, base: &str) {
    let client = reqwest::Client::new();
    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        if let Ok(response) = client.get(format!("{base}/readiness")).send().await {
            if response.status().is_success() {
                return;
            }
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("daemon exited before it became ready: {status}");
        }
        assert!(Instant::now() < deadline, "daemon never became ready");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn idle_window(base: &str) -> serde_json::Value {
    reqwest::Client::new()
        .get(format!("{base}/idle-timeout"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .expect("idle-timeout answers")
        .json()
        .await
        .expect("idle-timeout body")
}

async fn graph_status_call() -> Result<(), String> {
    let result = kin_mcp::daemon_delegate::forward_tool_call(
        "kin_graph_status",
        &std::collections::HashMap::new(),
    )
    .await?
    .ok_or_else(|| "no daemon delegate is configured".to_string())?;
    if result.is_error == Some(true) {
        return Err(format!("{:?}", result.content));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn an_attached_mcp_session_keeps_a_short_window_daemon_alive_until_it_ends() {
    let repo = tempfile::tempdir().unwrap();
    kin_core::init(repo.path()).unwrap();
    let mut child = spawn_daemon(repo.path());
    let port = published_port(&mut child, repo.path()).await;
    let base = format!("http://127.0.0.1:{port}");
    wait_until_ready(&mut child, &base).await;

    // This test binary is the MCP session. The environment is what `kin mcp
    // start` leaves behind once it binds a daemon: the delegate URL and the
    // bearer token. `KIN_NO_DAEMON` keeps a failed call from reviving a
    // replacement, so a daemon that idled out stays visibly dead rather than
    // being papered over by a fresh one.
    // Held for the whole test, so the writes are serialized with every other
    // environment-mutating test and restored when it ends.
    let _environment = kin_core::test_env::EnvVarGuard::new()
        .with("KIN_DAEMON_URL", &base)
        .with("KIN_DAEMON_AUTH_TOKEN", TOKEN)
        .with("KIN_NO_DAEMON", "1")
        .without("KIN_DAEMON_IDLE_TIMEOUT_SECS");
    kin_mcp::session_idle_floor::enable();

    let outcome =
        async {
            // The first call is what attaches the session's floor. The session asks
            // nothing of its own; the delegate holds the floor on the way out.
            graph_status_call().await?;

            // Calls spaced past the daemon's own window. Each gap alone would
            // have let the daemon exit, which is the defect: the next call then
            // found nothing listening.
            for call in 2..=4 {
                tokio::time::sleep(CALL_GAP).await;
                if let Ok(Some(status)) = child.try_wait() {
                    return Err(format!(
                        "the daemon exited under an active session before call {call}: {status}"
                    ));
                }
                graph_status_call()
                    .await
                    .map_err(|error| format!("call {call} failed: {error}"))?;
            }

            // What kept it alive was the session's floor, held over the daemon's
            // own window rather than replacing it.
            let window = idle_window(&base).await;
            if window["own_secs"] != OWN_WINDOW.as_secs()
                || window["effective_secs"].as_u64() <= Some(OWN_WINDOW.as_secs())
                || window["floor_leases"] != 1
            {
                return Err(format!(
                    "the session did not hold a floor over the daemon's own window: {window}"
                ));
            }

            // Ending the session hands the daemon back its own policy: it idles
            // out on its own short window rather than on the session's floor.
            kin_mcp::session_idle_floor::release().await;
            let window = idle_window(&base).await;
            if window["effective_secs"] != OWN_WINDOW.as_secs() || window["floor_leases"] != 0 {
                return Err(format!(
                    "releasing the session did not return the daemon to its own window: {window}"
                ));
            }
            match tokio::time::timeout(Duration::from_secs(90), child.wait()).await {
            Ok(Ok(status)) if status.success() => Ok(()),
            Ok(Ok(status)) => Err(format!("idle exit after the session was not clean: {status}")),
            Ok(Err(error)) => Err(format!("waiting on the daemon failed: {error}")),
            Err(_) => Err(
                "the daemon kept running long after the session ended and its own window passed"
                    .to_string(),
            ),
        }
        }
        .await;

    if let Ok(None) = child.try_wait() {
        let _ = terminate_daemon(&mut child, "mcp session idle floor daemon").await;
    }
    if let Err(error) = outcome {
        panic!("{error}");
    }
}
