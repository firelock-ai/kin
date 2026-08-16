// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The MCP stdio contract with no daemon anywhere (FIR-2316).
//!
//! `kin mcp start` used to await its repo daemon binding before reading a
//! byte of stdio, so a cold flagship-scale start meant minutes of complete
//! silence against handshake probes budgeted in seconds, without even the
//! `initialize` response. These tests drive the real binary with the update
//! watchdog's exact four-frame session and no daemon at all (`KIN_NO_DAEMON`
//! plus an isolated registry guarantee nothing can be spawned or found), and
//! require every frame answered under a tight bound. The slow-bind case, a
//! binding that stays pending while frames arrive, is covered
//! deterministically in `kin-mcp`'s server tests; what this binary-level test
//! pins is that the served transport never needs a daemon to hold the
//! handshake contract.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

mod common;

/// Wall-clock bound for the whole four-frame session. Orders of magnitude
/// above the millisecond-scale expectation, and far below the minutes a
/// daemon-coupled handshake stalls for: a regression to the pre-loop await
/// shape fails this bound, it does not merely slow the suite.
const FOUR_FRAME_BOUND: Duration = Duration::from_secs(30);

/// The update watchdog's probe session: initialize, the initialized
/// notification, tools/list, and one graph-backed tools/call.
fn probe_frames() -> String {
    [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"kin-mcp-contract-test","version":"0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"kin_graph_status","arguments":{}}}"#,
    ]
    .join("\n")
        + "\n"
}

struct McpRun {
    responses: Vec<serde_json::Value>,
    stderr: String,
    elapsed: Duration,
}

/// Run `kin mcp start` in `dir` with a fully controlled environment, feed it
/// the probe session, and collect every stdout response under the bound.
///
/// The environment is cleared and rebuilt rather than scrubbed: an inherited
/// `KIN_DAEMON_URL` or `KIN_MCP_REPO` from the developer's shell would change
/// what this test proves, and `KIN_NO_DAEMON=1` plus an isolated registry and
/// HOME guarantee no daemon can be spawned or discovered.
fn run_probe_session(dir: &Path, home: &Path) -> McpRun {
    run_configured_probe_session(dir, home, &[], &[("KIN_NO_DAEMON", "1".into())])
}

/// [`run_probe_session`] with the no-spawn contract carried explicitly by the
/// caller (as `--no-spawn`, as `KIN_NO_DAEMON`, or deliberately as neither),
/// plus whatever extra environment the fixture needs (`KIN_DAEMON_URL`,
/// `KIN_DAEMON_BIN`). The spawn-control tests need all three shapes, and a
/// helper that always injected the env var could never run its own positive
/// control.
fn run_configured_probe_session(
    dir: &Path,
    home: &Path,
    extra_args: &[&str],
    extra_env: &[(&str, std::ffi::OsString)],
) -> McpRun {
    let started = Instant::now();
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_kin"));
    command
        .args(["mcp", "start"])
        .args(extra_args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("TMPDIR", std::env::temp_dir())
        .env("KIN_VFS_DISABLE", "1")
        .env("KIN_REGISTRY_PATH", home.join("registry.toml"));
    for (name, value) in extra_env {
        command.env(name, value);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kin mcp start");

    // Write the whole session and close stdin, exactly as the watchdog's
    // heredoc does; the server answers each frame and exits at EOF.
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(probe_frames().as_bytes())
        .expect("write probe frames");

    // Drain both pipes concurrently: tools/list alone can exceed the pipe
    // buffer, and a reader that waits for exit first deadlocks against a
    // writer blocked on a full pipe.
    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let stdout_reader = std::thread::spawn(move || {
        let mut collected = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut collected);
        collected
    });
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    let stderr_reader = std::thread::spawn(move || {
        let mut collected = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut collected);
        collected
    });

    let status = wait_bounded(&mut child, started + FOUR_FRAME_BOUND);
    let stdout = stdout_reader.join().expect("join stdout reader");
    let stderr =
        String::from_utf8_lossy(&stderr_reader.join().expect("join stderr reader")).into_owned();
    let elapsed = started.elapsed();

    let status = status.unwrap_or_else(|| {
        panic!(
            "kin mcp start answered nothing within {FOUR_FRAME_BOUND:?}: the stdio loop is \
             blocked behind the daemon binding again (FIR-2316); stderr:\n{stderr}"
        )
    });
    assert!(
        status.success(),
        "kin mcp start exited with {status}; stderr:\n{stderr}"
    );

    let responses = String::from_utf8(stdout)
        .expect("stdout is UTF-8")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("stdout lines are JSON-RPC"))
        .collect();
    McpRun {
        responses,
        stderr,
        elapsed,
    }
}

/// Wait for the child under a deadline; kill it at expiry and return `None`.
fn wait_bounded(child: &mut Child, deadline: Instant) -> Option<std::process::ExitStatus> {
    loop {
        if let Some(status) = child.try_wait().expect("poll kin mcp start") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn response_with_id(run: &McpRun, id: u64) -> &serde_json::Value {
    run.responses
        .iter()
        .find(|value| value.get("id").and_then(|v| v.as_u64()) == Some(id))
        .unwrap_or_else(|| {
            panic!(
                "no response with id {id}; got {:#?}; stderr:\n{}",
                run.responses, run.stderr
            )
        })
}

fn assert_four_frame_contract(run: &McpRun) {
    assert!(
        run.elapsed < FOUR_FRAME_BOUND,
        "the probe session took {:?} against a {FOUR_FRAME_BOUND:?} bound",
        run.elapsed
    );
    let initialize = response_with_id(run, 1);
    assert!(
        initialize.pointer("/result/serverInfo/name").is_some(),
        "initialize must answer with server info: {initialize:#?}"
    );
    let tools = response_with_id(run, 2);
    let tool_count = tools
        .pointer("/result/tools")
        .and_then(|tools| tools.as_array())
        .map(|tools| tools.len())
        .unwrap_or(0);
    assert!(
        tool_count > 0,
        "tools/list must serve the tool surface with no daemon: {tools:#?}"
    );

    // The graph-backed call is answered with a structured error naming the
    // situation, never with silence or a dead process.
    let call = response_with_id(run, 3);
    let content = call
        .pointer("/result/content/0/text")
        .and_then(|text| text.as_str())
        .unwrap_or_else(|| panic!("tools/call must carry a content block: {call:#?}"));
    assert_eq!(
        call.pointer("/result/isError").and_then(|v| v.as_bool()),
        Some(true),
        "with no daemon anywhere the graph call is an error result: {call:#?}"
    );
    assert!(
        content.contains("daemon") || content.contains("repository"),
        "the error must name what is missing: {content}"
    );
}

/// The global-entry shape: launched from a directory that is no repository.
#[test]
fn the_four_frame_probe_is_answered_with_no_repository_and_no_daemon() {
    let root = tempfile::tempdir().expect("temp root");
    let home = root.path().join("home");
    std::fs::create_dir_all(&home).expect("create home");
    let plain = root.path().join("not-a-repo");
    std::fs::create_dir_all(&plain).expect("create launch dir");

    let run = run_probe_session(&plain, &home);
    assert_four_frame_contract(&run);
}

/// The watchdog-probe shape: launched inside a real Kin repository whose
/// daemon does not exist and may not be spawned.
#[test]
fn the_four_frame_probe_is_answered_inside_a_repository_whose_daemon_is_absent() {
    let root = tempfile::tempdir().expect("temp root");
    let home = root.path().join("home");
    std::fs::create_dir_all(&home).expect("create home");
    // Kin-native init requires an empty directory; it will not derive
    // authority from pre-existing filesystem contents.
    let repo = root.path().join("repo");
    std::fs::create_dir_all(&repo).expect("create repo dir");

    let init = common::Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(&repo)
        .env("HOME", &home)
        .env("KIN_NO_DAEMON", "1")
        .env("KIN_REGISTRY_PATH", home.join("registry.toml"))
        .output()
        .expect("run kin init");
    assert!(
        init.status.success(),
        "kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    let run = run_probe_session(&repo, &home);
    assert_four_frame_contract(&run);
}

/// The boot-incident shape (FIR-2341), replayed: a repository whose daemon
/// died with its pid/port record left behind, probed by a session bound to the
/// dead daemon's URL. Before the no-spawn contract covered revival, this exact
/// session started a fresh daemon from inside the probe, the mechanism behind
/// the 2026-08-15 boot spawn storm.
///
/// The spawn detector is a stub `kin-daemon` injected through `KIN_DAEMON_BIN`
/// that records every invocation to a marker file. The positive control runs
/// the identical session without `--no-spawn` and requires the marker to
/// appear, which is what proves the detector can see a spawn at all; only then
/// does the absent marker under `--no-spawn` mean zero daemon processes rather
/// than a check that cannot fail. Unix-only because the stub is a shell script.
#[cfg(unix)]
#[test]
fn a_no_spawn_probe_over_a_dead_daemon_record_spawns_nothing() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().expect("temp root");
    let home = root.path().join("home");
    std::fs::create_dir_all(&home).expect("create home");
    let repo = root.path().join("repo");
    std::fs::create_dir_all(&repo).expect("create repo dir");

    let init = common::Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("init")
        .arg(&repo)
        .env("HOME", &home)
        .env("KIN_NO_DAEMON", "1")
        .env("KIN_REGISTRY_PATH", home.join("registry.toml"))
        .output()
        .expect("run kin init");
    assert!(
        init.status.success(),
        "kin init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&init.stdout),
        String::from_utf8_lossy(&init.stderr)
    );

    // A pid that provably belonged to a real process and provably no longer
    // does: reap a child and record its pid.
    let dead_pid = {
        let mut child = std::process::Command::new("/usr/bin/true")
            .spawn()
            .or_else(|_| std::process::Command::new("/bin/true").spawn())
            .expect("spawn short-lived child");
        let pid = child.id();
        child.wait().expect("reap short-lived child");
        pid
    };
    // A loopback port that was free at selection time: bind, read, release.
    let dead_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a loopback port");
        listener.local_addr().expect("read reserved port").port()
    };
    let kin_dir = repo.join(".kin");
    std::fs::write(
        kin_dir.join(kin_daemon_spawn::PID_FILE_NAME),
        dead_pid.to_string(),
    )
    .expect("plant stale pid record");
    std::fs::write(
        kin_dir.join(kin_daemon_spawn::PORT_FILE_NAME),
        dead_port.to_string(),
    )
    .expect("plant stale port record");

    // The stub daemon: records its invocation and exits, so a run that spawns
    // leaves evidence and leaves no process behind.
    let marker = root.path().join("daemon-spawned.marker");
    let stub = root.path().join("kin-daemon-stub");
    std::fs::write(
        &stub,
        format!("#!/bin/sh\necho \"$@\" >> '{}'\nexit 7\n", marker.display()),
    )
    .expect("write stub daemon");
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755))
        .expect("mark stub executable");

    let fixture_env = |ready_timeout: Option<&str>| {
        let mut env: Vec<(&str, std::ffi::OsString)> = vec![
            (
                "KIN_DAEMON_URL",
                format!("http://127.0.0.1:{dead_port}").into(),
            ),
            ("KIN_DAEMON_BIN", stub.clone().into_os_string()),
        ];
        if let Some(secs) = ready_timeout {
            env.push(("KIN_DAEMON_READY_TIMEOUT_SECS", secs.into()));
        }
        env
    };

    // The claim: under --no-spawn the whole session answers and nothing is
    // started. The tools/call error must name KIN_NO_DAEMON, which proves the
    // binding settled, the dead daemon was observed, and revival was consulted
    // and refused. Without that assertion, an early failure anywhere on the
    // path would also leave the marker absent and the test would prove nothing.
    let no_spawn = run_configured_probe_session(&repo, &home, &["--no-spawn"], &fixture_env(None));
    assert_four_frame_contract(&no_spawn);
    let refusal = response_with_id(&no_spawn, 3)
        .pointer("/result/content/0/text")
        .and_then(|text| text.as_str())
        .expect("tools/call carries a content block")
        .to_string();
    assert!(
        refusal.contains("KIN_NO_DAEMON"),
        "the no-spawn refusal must reach the tool answer: {refusal}"
    );
    assert!(
        !marker.exists(),
        "--no-spawn probe invoked the daemon binary: {}",
        std::fs::read_to_string(&marker).unwrap_or_default()
    );

    // Positive control: the identical session without --no-spawn must reach
    // the stub, proving the marker detects spawns. The short ready timeout
    // bounds the supervisor-spawn arm should binary validation ever start
    // accepting the stub.
    let unrestricted = run_configured_probe_session(&repo, &home, &[], &fixture_env(Some("2")));
    assert_four_frame_contract(&unrestricted);
    assert!(
        marker.exists(),
        "the control run must spawn the stub daemon, or the marker check cannot fail; stderr:\n{}",
        unrestricted.stderr
    );
}
