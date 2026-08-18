// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Every MCP answer says whether the graph behind it survives the daemon
//! (FIR-2421).
//!
//! The transcript this replays: an agent wrote a source file, called
//! `kin_graph_status`, read `entity_count: 14`, located a class it had just
//! written and got a real entity id back, wrote in its own log that its work
//! was in the graph, and never committed. Every one of those payloads was
//! true. The daemon admits host content into its live query graph
//! continuously, so the entities and the id were real; nothing in any of them
//! said the entity layer is rebuilt from zero on the next open. After the
//! session `kin log` held one change carrying `entities=0` and a fresh open
//! read the files back with no entities at all.
//!
//! So these cases drive the real stdio MCP surface against a real daemon over
//! a real working copy, and assert on the disclosure rather than on the
//! counts: a status and a locate taken while the work is uncommitted must both
//! say so, and the same two calls after a commit must say the opposite. Both
//! directions matter. A disclosure that always warns is noise an agent learns
//! to skip, which is the failure mode that would make this fix worthless
//! without ever failing a test.

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::tempdir;

mod common;

use common::Command;

/// Wall-clock bound for one four-frame stdio session against a live daemon.
const SESSION_BOUND: Duration = Duration::from_secs(60);

/// How long ambient admission gets to pick up a host write before the fixture
/// gives up. The loop polls at 100ms and the file is three functions.
const ADMISSION_BOUND: Duration = Duration::from_secs(60);

struct IsolatedDaemon {
    child: Option<common::RuntimeOwnedChild>,
}

impl IsolatedDaemon {
    fn spawn(repo: &Path, runtime: &common::IsolatedDaemonRuntime) -> Self {
        let mut command = runtime.daemon_command();
        let child = command
            .arg("--repo")
            .arg(repo)
            .arg("--port")
            .arg("0")
            .env("KIN_DAEMON_DISABLE_LSP", "1")
            .env("KIN_DAEMON_IDLE_TIMEOUT_SECS", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn_owned()
            .expect("spawn isolated kin-daemon");
        Self { child: Some(child) }
    }

    fn wait_until_serving(&mut self, kin_root: &Path) -> u16 {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let child = self.child.as_mut().expect("daemon child exists");
            if let Some(status) = child.try_wait().expect("inspect daemon child") {
                panic!("isolated daemon exited before readiness: {status}");
            }
            if let Some(port) = fs::read_to_string(kin_root.join("daemon.port"))
                .ok()
                .and_then(|value| value.trim().parse::<u16>().ok())
            {
                let address = SocketAddr::from(([127, 0, 0, 1], port));
                if TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok() {
                    return port;
                }
            }
            assert!(
                Instant::now() < deadline,
                "isolated daemon did not become ready"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn stop(mut self) {
        let mut child = self.child.take().expect("daemon child exists");
        let _ = child.kill();
        let _ = child.wait();
    }
}

impl Drop for IsolatedDaemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn run_git(path: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .current_dir(path)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A committed repository with entity source, so durable authority carries a
/// nonzero entity count before anything uncommitted is written.
///
/// A repository whose durable count is zero would let a broken derivation pass
/// by accident: with `durable == 0` the live-only count is just the live count,
/// so a disclosure that ignored durable authority entirely would still print
/// the right number.
fn seed_repository(repo: &Path) {
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    run_git(repo, &["init", "--initial-branch=main"]);
    run_git(repo, &["config", "user.email", "kin@example.invalid"]);
    run_git(repo, &["config", "user.name", "Kin"]);
    fs::write(
        repo.join("src/storage.rs"),
        b"pub fn open_store() -> u32 {\n    7\n}\n\npub fn close_store() -> u32 {\n    open_store() + 1\n}\n",
    )
    .expect("write entity source");
    run_git(repo, &["add", "--all"]);
    run_git(repo, &["commit", "-m", "storage"]);
}

/// The file the agent wrote and then located. Named for the transcript's
/// `link_graph.py`, which is the write whose entities the second locate found
/// seven seconds later.
const UNCOMMITTED_SOURCE: &[u8] =
    b"pub fn build_link_graph() -> u32 {\n    3\n}\n\npub fn walk_link_graph() -> u32 {\n    build_link_graph() + 1\n}\n\npub fn render_link_graph() -> u32 {\n    walk_link_graph() + 1\n}\n";

fn kin(repo: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("KIN_DAEMON_URL")
        .current_dir(repo)
        .output()
        .expect("run kin")
}

fn kin_against_daemon(repo: &Path, home: &Path, port: u16, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("KIN_DAEMON_URL", format!("http://127.0.0.1:{port}"))
        .current_dir(repo)
        .output()
        .expect("run kin against the isolated daemon")
}

fn stdout_of(output: &std::process::Output, what: &str) -> String {
    assert!(
        output.status.success(),
        "{what} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// One `kin mcp start` session: handshake, then status, then locate.
///
/// The order is the transcript's. Both calls are made in one session because
/// the claim is about every envelope rather than about the status tool alone:
/// the locate is the call the agent actually believed, and it reaches its
/// envelope through the generic `/health` lift rather than through graph
/// status's own selected-graph observation, so the two exercise different
/// code even though they must agree.
fn session_frames() -> String {
    [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"kin-durability-test","version":"0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"kin_graph_status","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"semantic_locate","arguments":{"query":"build_link_graph"}}}"#,
    ]
    .join("\n")
        + "\n"
}

/// Drive the real stdio MCP binary against the running daemon and return the
/// parsed payload of each `tools/call` response, keyed by request id.
fn run_mcp_session(repo: &Path, home: &Path, port: u16) -> Vec<(u64, serde_json::Value)> {
    let started = Instant::now();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["mcp", "start"])
        .current_dir(repo)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("TMPDIR", std::env::temp_dir())
        .env("KIN_VFS_DISABLE", "1")
        .env("KIN_REGISTRY_PATH", home.join("registry.toml"))
        .env("KIN_DAEMON_URL", format!("http://127.0.0.1:{port}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kin mcp start");

    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(session_frames().as_bytes())
        .expect("write session frames");

    // Both pipes drain concurrently: a locate payload alone can exceed the
    // pipe buffer, and a reader that waits for exit first deadlocks against a
    // writer blocked on a full pipe.
    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let stdout_reader = thread::spawn(move || {
        let mut collected = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut collected);
        collected
    });
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    let stderr_reader = thread::spawn(move || {
        let mut collected = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut collected);
        collected
    });

    let deadline = started + SESSION_BOUND;
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll kin mcp start") {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        thread::sleep(Duration::from_millis(25));
    };
    let stdout = stdout_reader.join().expect("join stdout reader");
    let stderr =
        String::from_utf8_lossy(&stderr_reader.join().expect("join stderr reader")).into_owned();
    let status =
        status.unwrap_or_else(|| panic!("kin mcp start did not finish; stderr:\n{stderr}"));
    assert!(
        status.success(),
        "kin mcp start exited with {status}; stderr:\n{stderr}"
    );

    String::from_utf8(stdout)
        .expect("stdout is UTF-8")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let frame: serde_json::Value =
                serde_json::from_str(line).expect("stdout lines are JSON-RPC");
            let id = frame.get("id")?.as_u64()?;
            let text = frame
                .get("result")?
                .get("content")?
                .get(0)?
                .get("text")?
                .as_str()?;
            Some((
                id,
                serde_json::from_str(text).expect("tool payload is JSON"),
            ))
        })
        .collect()
}

fn payload(session: &[(u64, serde_json::Value)], id: u64, what: &str) -> serde_json::Value {
    session
        .iter()
        .find(|(frame_id, _)| *frame_id == id)
        .unwrap_or_else(|| panic!("session carried no {what} response: {session:?}"))
        .1
        .clone()
}

/// The live entity count the daemon reports, read through `kin graph status`
/// so the poll below does not have to spawn a whole MCP session per tick.
fn live_entity_count(repo: &Path, home: &Path, port: u16) -> u64 {
    let text = stdout_of(
        &kin_against_daemon(repo, home, port, &["graph", "status"]),
        "kin graph status",
    );
    let line = text
        .lines()
        .find(|line| line.contains("Entities:"))
        .unwrap_or_else(|| panic!("graph status printed no entity line:\n{text}"));
    let after = line
        .split("Entities:")
        .nth(1)
        .expect("the entity line carries a count");
    after
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("could not read an entity count from {line:?}"))
}

/// Wait until ambient admission has taken the host write into the live graph.
fn wait_for_live_growth(repo: &Path, home: &Path, port: u16, above: u64) -> u64 {
    let deadline = Instant::now() + ADMISSION_BOUND;
    loop {
        let live = live_entity_count(repo, home, port);
        if live > above {
            return live;
        }
        assert!(
            Instant::now() < deadline,
            "ambient admission never took the host write: live entity count stayed at {live}, \
             above={above}; graph status said:\n{}",
            stdout_of(
                &kin_against_daemon(repo, home, port, &["graph", "status"]),
                "kin graph status"
            )
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn durability(payload: &serde_json::Value) -> serde_json::Value {
    payload
        .get("_kin")
        .unwrap_or_else(|| panic!("payload carries no _kin envelope: {payload}"))
        .get("durability")
        .unwrap_or_else(|| panic!("envelope carries no durability object: {payload}"))
        .clone()
}

#[test]
fn mcp_status_and_locate_disclose_live_only_entities_and_then_stop_once_a_commit_records_them() {
    let root = tempdir().expect("temp root");
    let home = root.path().join("home");
    let repo = root.path().join("repo");
    fs::create_dir_all(&home).expect("create home");
    fs::create_dir_all(&repo).expect("create repo");
    // Canonicalized before anything binds it. On macOS a temporary directory
    // is reached through `/var`, which is a symlink to `/private/var`, and the
    // daemon's file watcher reports host events under the resolved path. A
    // repository bound to the unresolved one therefore never matches its own
    // watcher events, and ambient admission silently takes nothing: the
    // fixture would sit at the committed entity count with no error anywhere.
    let repo = repo.canonicalize().expect("resolve the repository path");
    let home = home.canonicalize().expect("resolve the home path");
    seed_repository(&repo);

    let init = kin(&repo, &home, &["init", ".", "--json"]);
    let init_payload: serde_json::Value =
        serde_json::from_slice(&stdout_of(&init, "kin init").into_bytes())
            .expect("init emits JSON");
    let durable_at_init = init_payload["semantic_enrichment"]["entity_count"]
        .as_u64()
        .expect("init reports a durable entity count");
    assert!(
        durable_at_init > 0,
        "the fixture needs durable entities before the uncommitted write, got \
         {durable_at_init}: {init_payload}"
    );

    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    let mut daemon = IsolatedDaemon::spawn(&repo, &runtime);
    let port = daemon.wait_until_serving(&repo.join(".kin"));

    // The transcript's first move: write a file, through nothing but the
    // filesystem, exactly as an agent's `write_file` tool does.
    fs::write(repo.join("src/link_graph.rs"), UNCOMMITTED_SOURCE)
        .expect("write the uncommitted source");
    let live = wait_for_live_growth(&repo, &home, port, durable_at_init);

    let uncommitted = run_mcp_session(&repo, &home, port);
    let status = payload(&uncommitted, 2, "kin_graph_status");
    let locate = payload(&uncommitted, 3, "semantic_locate");

    assert_eq!(
        status["entity_count"].as_u64(),
        Some(live),
        "the fixture and the status tool must be looking at one graph: {status}"
    );
    assert_eq!(
        status["durable_entity_count"].as_u64(),
        Some(durable_at_init),
        "graph status must report the durable count `kin init` published, beside the live one \
         it already reported: {status}"
    );

    let status_durability = durability(&status);
    assert_eq!(
        status_durability["state"], "live_uncommitted",
        "the graph holds {live} entities against {durable_at_init} durable, so status must say \
         the work is unrecorded: {status_durability}"
    );
    assert_eq!(
        status_durability["live_only_entities"].as_u64(),
        Some(live - durable_at_init),
        "and must say how much of it: {status_durability}"
    );
    let note = status_durability["note"]
        .as_str()
        .expect("a durability object always carries a note");
    assert!(
        note.contains("uncommitted") && note.contains("Commit to record it"),
        "the note is what an agent reads instead of the counts: {note:?}"
    );

    // The call the agent actually believed. It reaches its envelope through
    // the generic `/health` lift rather than through graph status's own
    // observation, so it is separate code that has to agree.
    assert!(
        locate["entities"]
            .as_array()
            .is_some_and(|found| !found.is_empty()),
        "the fixture needs locate to find the uncommitted entity, or the disclosure beside it \
         proves nothing: {locate}"
    );
    let locate_durability = durability(&locate);
    assert_eq!(
        locate_durability["state"], "live_uncommitted",
        "locate returned an entity id for source no committed change carries, and must say so \
         in the same envelope: {locate_durability}"
    );
    assert_eq!(
        locate_durability["live_only_entities"].as_u64(),
        Some(live - durable_at_init),
        "and must count it the same way status does: {locate_durability}"
    );

    // The other direction. A disclosure that cannot go quiet is not a
    // disclosure, and the commit is what the agent should have run.
    let commit = kin_against_daemon(
        &repo,
        &home,
        port,
        &["commit", "-m", "record the link graph"],
    );
    stdout_of(&commit, "kin commit");

    let recorded = run_mcp_session(&repo, &home, port);
    let status_after = payload(&recorded, 2, "kin_graph_status");
    let locate_after = payload(&recorded, 3, "semantic_locate");

    let status_after_durability = durability(&status_after);
    assert_eq!(
        status_after_durability["state"], "recorded",
        "after the commit durable authority carries the graph, so status must stop warning: \
         {status_after_durability}"
    );
    assert_eq!(
        status_after_durability["live_only_entities"].as_u64(),
        Some(0),
        "with nothing left uncommitted: {status_after_durability}"
    );
    assert_eq!(
        status_after["durable_entity_count"].as_u64(),
        status_after["entity_count"].as_u64(),
        "and the two counts it reports must now agree: {status_after}"
    );
    assert_eq!(
        durability(&locate_after)["state"],
        "recorded",
        "and every other envelope must agree with it: {locate_after}"
    );

    daemon.stop();
}
