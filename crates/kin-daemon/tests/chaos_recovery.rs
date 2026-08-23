// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use kin_daemon::api::HealthResponse;
use tokio::net::TcpStream;
use tokio::process::Command;

mod common;

use common::{
    isolate_daemon_test_command, spawn_daemon_test_command, terminate_daemon, DaemonChild,
};

/// Readiness budget for a daemon to come up. Generous enough that two CI runs
/// sharing a runner (a push build and a pull_request build on the same commit)
/// can both bring a daemon up under load without a false timeout. A daemon that
/// dies during startup is detected eagerly via its child handle, so this budget
/// only ever bounds a slow-but-live startup, never a dead one.
const READINESS_TIMEOUT: Duration = Duration::from_secs(180);

/// Capped exponential backoff for readiness polling: responsive at first, then
/// it stops hammering a saturated runner once the wait stretches out.
fn backoff_after(current: Duration) -> Duration {
    (current * 2).min(Duration::from_millis(1000))
}

/// Fail loudly the instant a daemon child exits before it is ready instead of
/// polling a dead process until the readiness deadline. This turns a bind
/// collision or a startup crash into an immediate, legible failure rather than
/// a multi-minute "never became healthy" hang.
fn assert_child_alive(child: &mut DaemonChild, port: u16, what: &str) {
    if let Ok(Some(status)) = child.try_wait() {
        panic!("daemon on port {port} exited before it became {what}: {status}");
    }
}

/// Wait for the daemon to publish its OS-assigned port to `.kin/daemon.port`
/// and return it. Spawning with `--port 0` lets the daemon own port selection
/// and advertise the real bound port here — the same handshake the CLI uses —
/// so a kill/restart never depends on reusing one port's teardown timing.
async fn read_published_port(child: &mut DaemonChild, repo_root: &Path) -> u16 {
    let port_file = repo_root.join(".kin/daemon.port");
    // Share the readiness budget rather than keeping a tighter one of its own.
    // Publishing the port is part of the same startup this file already grants
    // READINESS_TIMEOUT for, and a 30s cap here made a healthy daemon on a
    // loaded machine indistinguishable from a broken one. A daemon that dies is
    // still caught eagerly through its child handle, so a generous budget only
    // ever bounds a slow-but-live startup.
    let deadline = Instant::now() + READINESS_TIMEOUT;
    let mut backoff = Duration::from_millis(20);

    loop {
        if let Ok(contents) = std::fs::read_to_string(&port_file) {
            if let Ok(port) = contents.trim().parse::<u16>() {
                if port != 0 {
                    return port;
                }
            }
        }

        if let Ok(Some(status)) = child.try_wait() {
            panic!("daemon exited before publishing its port: {status}");
        }
        if Instant::now() >= deadline {
            // Say which of the two it is. A deadline measures this test's
            // patience, not the daemon's health, and reporting "never
            // published" for a process that is still running sends the reader
            // hunting a startup bug that is not there. This is the same
            // distinction the production spawn contract draws between
            // `ChildExited` and `StillStarting`.
            let fate = match child.try_wait() {
                Ok(Some(status)) => format!("it exited with {status}"),
                Ok(None) => {
                    "it is still running, so this is a slow start rather than a failed one \
                     (the machine is likely loaded)"
                        .to_string()
                }
                Err(error) => format!("its state could not be read: {error}"),
            };
            panic!(
                "daemon did not publish a port to {} within {:.0}s; {fate}",
                port_file.display(),
                READINESS_TIMEOUT.as_secs_f64()
            );
        }

        tokio::time::sleep(backoff).await;
        backoff = backoff_after(backoff);
    }
}

fn init_repo(root: &Path) {
    kin_core::init(root).unwrap();
}

fn spawn_daemon(repo_root: &Path, port: u16) -> DaemonChild {
    spawn_daemon_with_env(repo_root, port, &[])
}

fn spawn_daemon_with_env(repo_root: &Path, port: u16, envs: &[(&str, &str)]) -> DaemonChild {
    let bin = env!("CARGO_BIN_EXE_kin-daemon");
    let mut cmd = Command::new(bin);
    isolate_daemon_test_command(&mut cmd);
    cmd.arg("--repo")
        .arg(repo_root)
        .arg("--port")
        .arg(port.to_string())
        // Daemon startup inspects the registry to pin sibling repository
        // authority. A scratch daemon must never enumerate the developer's
        // real registry while doing so.
        .env(
            "KIN_REGISTRY_PATH",
            repo_root.join(".kin/test-runtime/registry.toml"),
        )
        // These recovery tests exercise daemon lifecycle and graph durability,
        // not host language-server discovery.
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for (key, value) in envs {
        cmd.env(key, value);
    }
    spawn_daemon_test_command(cmd, "chaos-recovery daemon")
        .expect("failed to spawn contained kin-daemon")
}

async fn wait_for_health(child: &mut DaemonChild, port: u16) -> HealthResponse {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/health");
    let deadline = Instant::now() + READINESS_TIMEOUT;
    let mut backoff = Duration::from_millis(50);

    loop {
        if let Ok(response) = client.get(&url).send().await {
            if response.status().is_success() {
                let health = response.json::<HealthResponse>().await.unwrap();
                if health.status == "ok" {
                    return health;
                }
            }
        }

        assert_child_alive(child, port, "healthy");
        if Instant::now() >= deadline {
            panic!("daemon on port {port} never became healthy");
        }

        tokio::time::sleep(backoff).await;
        backoff = backoff_after(backoff);
    }
}

async fn wait_for_serving(child: &mut DaemonChild, port: u16) {
    let addr = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + READINESS_TIMEOUT;
    let mut backoff = Duration::from_millis(50);
    let mut observations = Vec::new();

    loop {
        match TcpStream::connect(&addr).await {
            Ok(_) => return,
            Err(error) => {
                observations.push(error.to_string());
            }
        }

        assert_child_alive(child, port, "reachable");
        if Instant::now() >= deadline {
            let last_observation = observations
                .last()
                .cloned()
                .unwrap_or_else(|| "no response".to_string());
            panic!("daemon on port {port} never served health: {last_observation}");
        }

        tokio::time::sleep(backoff).await;
        backoff = backoff_after(backoff);
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

async fn record_graph_mutation(repo_root: &Path, port: u16, action: &str) {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/graph/mutations");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut backoff = Duration::from_millis(50);

    loop {
        // Re-read on every attempt rather than once before the loop: this
        // closes over the daemon's own startup ordering (listener bind vs.
        // token provisioning) instead of assuming one happens before the
        // other, and self-heals if the file is not there yet on an early
        // retry.
        let token = std::fs::read_to_string(repo_root.join(".kin/daemon.token"))
            .ok()
            .map(|contents| contents.trim().to_string())
            .filter(|token| !token.is_empty());
        let mut request = client.post(&url).json(&serde_json::json!({
            "audit_events": [{
                "action": action,
                "target_scope": null,
                "details": "chaos recovery dirty-state fixture"
            }]
        }));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let result = request
            .send()
            .await
            .and_then(|response| response.error_for_status());
        if result.is_ok() {
            return;
        }
        if Instant::now() >= deadline {
            result.expect("create branch request failed");
        }
        tokio::time::sleep(backoff).await;
        backoff = backoff_after(backoff);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_recovers_after_process_kill_and_restart() {
    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());

    // Bind an OS-assigned port (`--port 0`) and discover it from the handshake
    // file the daemon publishes, rather than pre-reserving an explicit port.
    // This asserts recovery semantics — the daemon comes back and serves on the
    // same repo — without depending on reusing the same port across the
    // kill/restart, which races the kernel's socket teardown on macOS
    // (EADDRINUSE). The product bind path additionally retries EADDRINUSE, so a
    // real same-port restart also recovers.
    let mut child = spawn_daemon(repo.path(), 0);
    let port = read_published_port(&mut child, repo.path()).await;

    let first = wait_for_health(&mut child, port).await;
    assert_eq!(first.status, "ok");
    assert!(first.uptime_seconds < 20);

    let exit = terminate_daemon(&mut child, "initial recovery daemon")
        .await
        .expect("terminate and reap initial recovery daemon");
    assert!(
        !exit.success(),
        "killed kin-daemon should not report success"
    );

    // A SIGKILL leaves the dead daemon's port file behind; remove it so the read
    // below observes the restarted daemon's freshly published port.
    let _ = std::fs::remove_file(repo.path().join(".kin/daemon.port"));

    let mut restarted = spawn_daemon(repo.path(), 0);
    let restarted_port = read_published_port(&mut restarted, repo.path()).await;
    let second = wait_for_health(&mut restarted, restarted_port).await;
    assert_eq!(second.status, "ok");
    assert!(second.uptime_seconds < 20);

    terminate_daemon(&mut restarted, "restarted recovery daemon")
        .await
        .expect("terminate and reap restarted recovery daemon");
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

    // Keep port selection atomic with the daemon's bind. Pre-selecting a free
    // port and releasing it creates a TOCTOU window under parallel CI load.
    let mut child = spawn_daemon_with_env(
        repo.path(),
        0,
        &[
            ("KIN_DAEMON_DISABLE_LSP", "1"),
            ("KIN_DAEMON_IDLE_TIMEOUT_SECS", idle_secs.as_str()),
        ],
    );
    let port = read_published_port(&mut child, repo.path()).await;

    wait_for_serving(&mut child, port).await;

    let daemon_port = repo.path().join(".kin/daemon.port");
    let daemon_pid = repo.path().join(".kin/daemon.pid");
    // read_published_port already observed daemon.port. Poll both endpoint
    // files here so this test keeps asserting the complete publication contract
    // before the idle timer removes them.
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
            let cleanup = terminate_daemon(&mut child, "idle-timeout daemon").await;
            panic!("kin-daemon did not exit after idle timeout; cleanup={cleanup:?}");
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

/// Delete a control directory out from under a daemon that is still running.
///
/// `remove_dir_all` unlinks what it enumerated and then removes the directory,
/// so a live daemon writing one new file into `.kin` between those two steps
/// makes the final step fail with `DirectoryNotEmpty` and nothing about the
/// behaviour under test has gone wrong. The daemon publishes into its own
/// control directory on a cadence, most recently the memory-footprint standing
/// FIR-2614 P2 added, so the window is real and it is not this test's subject:
/// what is under test is that the daemon exits once the directory is gone.
///
/// Retrying is therefore the fix rather than serializing against the daemon,
/// which no caller of `kin eject` can do either. A caller deleting this
/// directory races the same way and retries the same way.
///
/// The final failure names the entries that survived. An `ENOTEMPTY` on its own
/// says a writer won the race and not which one, and the next person to see
/// this deserves better than the errno.
fn remove_live_control_dir(kin_dir: &std::path::Path) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::remove_dir_all(kin_dir) {
            Ok(()) => return,
            Err(error)
                if error.kind() == std::io::ErrorKind::DirectoryNotEmpty
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                let survivors = std::fs::read_dir(kin_dir)
                    .map(|entries| {
                        entries
                            .flatten()
                            .map(|entry| entry.file_name().to_string_lossy().into_owned())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                panic!(
                    "could not remove {}: {error}. Entries a live daemon rewrote while this \
                     ran: {survivors:?}",
                    kin_dir.display()
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_exits_after_dirty_repo_control_dir_is_removed() {
    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());

    // Keep port selection atomic with the daemon's bind. The published-port
    // handshake identifies this child, so readiness cannot be satisfied by an
    // unrelated listener that won a pre-selected port.
    let mut child = spawn_daemon_with_env(
        repo.path(),
        0,
        &[
            ("KIN_DAEMON_DISABLE_LSP", "1"),
            ("KIN_DAEMON_IDLE_TIMEOUT_SECS", "30"),
        ],
    );
    let port = read_published_port(&mut child, repo.path()).await;

    wait_for_serving(&mut child, port).await;
    record_graph_mutation(repo.path(), port, "dirty-before-delete").await;

    remove_live_control_dir(&repo.path().join(".kin"));

    let exit = match tokio::time::timeout(Duration::from_secs(15), child.wait()).await {
        Ok(result) => result.expect("kin-daemon wait failed"),
        Err(_) => {
            let cleanup = terminate_daemon(&mut child, "deleted-control-dir daemon").await;
            panic!("kin-daemon did not exit after deleted control directory; cleanup={cleanup:?}");
        }
    };
    assert!(
        exit.success(),
        "deleted-control-dir idle shutdown should be graceful: {exit}"
    );
}

/// Every component of a repo's published endpoint, read as raw bytes.
///
/// Compared whole so a test can assert that a file was not merely present
/// afterwards but untouched: a refusing starter that rewrote the incumbent's
/// port with its own would leave both paths existing.
fn endpoint_snapshot(repo_root: &Path) -> Vec<(String, Option<Vec<u8>>)> {
    ["daemon.pid", "daemon.port", "daemon.owner"]
        .into_iter()
        .map(|name| {
            (
                name.to_string(),
                std::fs::read(repo_root.join(".kin").join(name)).ok(),
            )
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_second_daemon_leaves_the_incumbent_serving() {
    // The reported sequence: an MCP retry revived a daemon, the revived daemon
    // lost the repo singleton and refused, and the incumbent it lost to died
    // moments later with its endpoint files gone. A refusal must be inert.
    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());

    let mut incumbent = spawn_daemon_with_env(
        repo.path(),
        0,
        &[
            ("KIN_DAEMON_DISABLE_LSP", "1"),
            ("KIN_DAEMON_IDLE_TIMEOUT_SECS", "600"),
        ],
    );
    let port = read_published_port(&mut incumbent, repo.path()).await;
    assert_eq!(wait_for_health(&mut incumbent, port).await.status, "ok");

    let before = endpoint_snapshot(repo.path());
    assert!(
        before.iter().all(|(_, bytes)| bytes.is_some()),
        "the incumbent must have published an attributed endpoint: {before:?}"
    );

    let mut refused = spawn_daemon_with_env(repo.path(), 0, &[("KIN_DAEMON_DISABLE_LSP", "1")]);
    let exit = match tokio::time::timeout(Duration::from_secs(120), refused.wait()).await {
        Ok(result) => result.expect("second kin-daemon wait failed"),
        Err(_) => {
            let _ = refused.start_kill();
            panic!("the second kin-daemon neither started nor refused");
        }
    };
    assert!(
        !exit.success(),
        "losing the repo singleton must be reported as a failure: {exit}"
    );

    assert_eq!(
        endpoint_snapshot(repo.path()),
        before,
        "a refused start must leave the incumbent's endpoint byte-identical"
    );
    assert_child_alive(&mut incumbent, port, "alive after a refused second start");
    assert_eq!(
        wait_for_health(&mut incumbent, port).await.status,
        "ok",
        "the incumbent must still be serving the repo it owns"
    );

    incumbent.start_kill().expect("failed to stop kin-daemon");
    let _ = incumbent.wait().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deleted_endpoint_is_republished_instead_of_ending_the_daemon() {
    // The other half of the same failure: the incumbent keyed its own liveness
    // on endpoint files it did not verify it owned. Deleting them must be
    // repaired by the daemon that still holds the repo, not obeyed.
    let repo = tempfile::tempdir().unwrap();
    init_repo(repo.path());

    let mut child = spawn_daemon_with_env(
        repo.path(),
        0,
        &[
            ("KIN_DAEMON_DISABLE_LSP", "1"),
            ("KIN_DAEMON_IDLE_TIMEOUT_SECS", "600"),
        ],
    );
    let port = read_published_port(&mut child, repo.path()).await;
    wait_for_serving(&mut child, port).await;

    let daemon_pid = repo.path().join(".kin/daemon.pid");
    let daemon_port = repo.path().join(".kin/daemon.port");
    wait_for_path(
        &daemon_pid,
        "daemon did not write pid file",
        Duration::from_secs(10),
    )
    .await;
    std::fs::remove_file(&daemon_pid).unwrap();
    std::fs::remove_file(&daemon_port).unwrap();

    wait_for_path(
        &daemon_pid,
        "daemon never republished its pid file",
        Duration::from_secs(60),
    )
    .await;
    wait_for_path(
        &daemon_port,
        "daemon never republished its port file",
        Duration::from_secs(60),
    )
    .await;

    assert_child_alive(&mut child, port, "alive after its endpoint was deleted");
    assert_eq!(
        std::fs::read_to_string(&daemon_port)
            .unwrap()
            .trim()
            .parse::<u16>()
            .unwrap(),
        port,
        "republication must restore the port the daemon actually bound"
    );
    assert_eq!(wait_for_health(&mut child, port).await.status, "ok");

    child.start_kill().expect("failed to stop kin-daemon");
    let _ = child.wait().await;
}
