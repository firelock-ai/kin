// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Tracked files edited or deleted while no daemon runs, through the real
//! binaries.
//!
//! An idle daemon exits on its own, the person keeps editing, and the next
//! command starts a fresh daemon. Before this, that daemon's startup catch-up
//! declined every path graph truth already tracked, so an edit to a tracked
//! file made in between was never admitted: the graph kept serving the file's
//! old bytes, found a renamed function only under its old name, certified the
//! new name absent although a one-line grep found it, and kept serving a
//! deleted file's entities.
//!
//! Both halves of the product are driven here. With no daemon running,
//! `kin status` measures the working copy itself and names the two files. Then
//! an ordinary query starts the daemon, which must admit both before the answer
//! comes back, and the MCP surface must agree: the new name resolves, the old
//! name and the deleted file are gone, and no answer certified an absence the
//! working copy refutes.

use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

mod common;

use common::Command;

const LIB_BEFORE: &str = "pub mod doomed;\n\npub fn old_name(value: u32) -> u32 {\n    value + 1\n}\n\npub fn caller() -> u32 {\n    old_name(41)\n}\n";
const LIB_AFTER: &str = "pub fn new_name(value: u32) -> u32 {\n    value + 1\n}\n\npub fn caller() -> u32 {\n    new_name(41)\n}\n";
const DOOMED: &str = "pub fn doomed_helper() -> u32 {\n    7\n}\n";

fn require_git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .current_dir(repo)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn kin_command<'a>(runtime: &'a common::IsolatedDaemonRuntime, repo: &Path) -> Command<'a> {
    let mut command = runtime.kin_command();
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_AUTO_EMBED", "0")
        .env("KIN_EMBED_BACKEND", "cpu")
        .current_dir(repo);
    command
}

fn run_kin(
    runtime: &common::IsolatedDaemonRuntime,
    repo: &Path,
    args: &[&str],
) -> std::process::Output {
    kin_command(runtime, repo)
        .args(args)
        .output()
        .expect("run kin")
}

fn require_kin(
    runtime: &common::IsolatedDaemonRuntime,
    repo: &Path,
    args: &[&str],
) -> std::process::Output {
    let output = run_kin(runtime, repo, args);
    assert!(
        output.status.success(),
        "kin {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// Every entity `kin locate --json` returns for `query`, as (name, path).
fn located(
    runtime: &common::IsolatedDaemonRuntime,
    repo: &Path,
    query: &str,
) -> Vec<(String, String)> {
    let output = require_kin(runtime, repo, &["locate", "--json", query]);
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("kin locate --json emits JSON");
    report["entities"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|entity| {
            let path = entity["provenance"]["file"]
                .as_str()
                .or_else(|| entity["path"].as_str())
                .unwrap_or_default();
            (
                entity["name"].as_str().unwrap_or_default().to_string(),
                path.to_string(),
            )
        })
        .collect()
}

/// One `kin mcp start` session over stdio against the daemon serving `repo`,
/// returning each tool payload in the order the calls were made.
///
/// Spawned directly rather than through the runtime's bounded runner, which
/// closes stdin, and pointed at the running daemon the way the durability
/// suite drives the same surface.
fn mcp_answers(
    runtime: &common::IsolatedDaemonRuntime,
    repo: &Path,
    home: &Path,
    calls: &[(&str, Value)],
) -> Vec<Value> {
    let port = fs::read_to_string(repo.join(".kin/daemon.port"))
        .expect("a daemon serves the repository")
        .trim()
        .parse::<u16>()
        .expect("the port record is a port");
    let mut frames = vec![
        serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "offline-tracked-changes", "version": "0"}
            }
        }),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    ];
    for (index, (name, arguments)) in calls.iter().enumerate() {
        frames.push(serde_json::json!({
            "jsonrpc": "2.0", "id": index + 2, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}
        }));
    }
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_kin"))
        .args(["mcp", "start"])
        .current_dir(repo)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("TMPDIR", std::env::temp_dir())
        .env("KIN_VFS_DISABLE", "1")
        .env("KIN_REGISTRY_PATH", runtime.registry_path())
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
        .write_all(
            (frames
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n")
                + "\n")
                .as_bytes(),
        )
        .expect("write the session frames");
    // Both pipes drain while the session runs: a payload can exceed a pipe
    // buffer, and waiting for exit first would deadlock against it.
    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let stdout = thread::spawn(move || {
        let mut collected = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut collected);
        collected
    });
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    let stderr = thread::spawn(move || {
        let mut collected = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut collected);
        collected
    });
    let deadline = Instant::now() + Duration::from_secs(180);
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
    let stdout = stdout.join().expect("join stdout");
    let stderr = String::from_utf8_lossy(&stderr.join().expect("join stderr")).into_owned();
    assert!(
        status.is_some_and(|status| status.success()),
        "kin mcp start did not finish cleanly ({status:?}); stderr:\n{stderr}"
    );
    let mut answers = vec![Value::Null; calls.len()];
    for line in String::from_utf8_lossy(&stdout).lines() {
        let Ok(frame) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(id) = frame["id"].as_u64().filter(|id| *id >= 2) else {
            continue;
        };
        let text = frame["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        answers[(id - 2) as usize] =
            serde_json::from_str(text).unwrap_or_else(|_| serde_json::json!({ "raw": text }));
    }
    answers
}

/// Falsify by restoring the startup catch-up's decline of tracked paths (an
/// early `continue` for a tracked leaf in the changes walk): the daemon never
/// admits either file, `kin locate` keeps finding `old_name` and the deleted
/// file, and `find_references` on `new_name` misses a name a grep finds.
#[test]
fn a_tracked_edit_and_a_deletion_made_while_no_daemon_ran_reach_the_next_answer() {
    let root = tempdir().expect("temp root");
    let repo = root.path().join("repo");
    fs::create_dir_all(repo.join("src")).expect("create source directory");
    let repo = repo.canonicalize().expect("resolve the repository path");
    let runtime = common::IsolatedDaemonRuntime::new(&repo);
    require_git(&repo, &["init", "--initial-branch=main"]);
    require_git(&repo, &["config", "commit.gpgsign", "false"]);
    require_git(&repo, &["config", "user.name", "Ada Lovelace"]);
    require_git(&repo, &["config", "user.email", "ada@example.com"]);
    fs::write(repo.join("src/lib.rs"), LIB_BEFORE).expect("write lib.rs");
    fs::write(repo.join("src/doomed.rs"), DOOMED).expect("write doomed.rs");
    require_git(&repo, &["add", "--all"]);
    require_git(&repo, &["commit", "-m", "first commit"]);
    require_kin(&runtime, &repo, &["init", ".", "--json"]);

    // A daemon serves the store, and the watched graph knows both files.
    let before = located(&runtime, &repo, "old_name");
    assert!(
        before.iter().any(|(name, _)| name == "old_name"),
        "the fixture needs the old name served before the daemon stops: {before:?}"
    );
    require_kin(&runtime, &repo, &["daemon", "stop"]);

    // The edits nothing watches.
    fs::write(repo.join("src/lib.rs"), LIB_AFTER).expect("rename the function");
    fs::remove_file(repo.join("src/doomed.rs")).expect("delete the file");

    // With no daemon running, status measures the working copy itself. It
    // names both files and does not read current.
    let status = run_kin(&runtime, &repo, &["status"]);
    let text = String::from_utf8_lossy(&status.stdout).into_owned();
    assert_eq!(
        status.status.code(),
        Some(9),
        "no daemon admitted the working copy, so the report is not about it: {text}"
    );
    let line = text
        .lines()
        .find(|line| line.starts_with("Tracked changes since the last admission:"))
        .unwrap_or_else(|| panic!("status must name tracked changes nothing took:\n{text}"));
    assert!(
        line.contains("2 tracked path(s)")
            && line.contains("src/lib.rs (changed)")
            && line.contains("src/doomed.rs (removed)"),
        "{line}"
    );
    assert!(
        !text.contains("matching its base change as admitted"),
        "status must not read current over edits nothing admitted:\n{text}"
    );

    // An ordinary query starts the daemon, which takes both files before the
    // answer comes back.
    let after = located(&runtime, &repo, "new_name");
    assert!(
        after
            .iter()
            .any(|(name, path)| name == "new_name" && path == "src/lib.rs"),
        "the renamed function is found under its new name: {after:?}"
    );
    let old = located(&runtime, &repo, "old_name");
    assert!(
        !old.iter().any(|(name, _)| name == "old_name"),
        "the old name is gone: {old:?}"
    );
    let doomed = located(&runtime, &repo, "doomed_helper");
    assert!(
        !doomed.iter().any(|(_, path)| path == "src/doomed.rs"),
        "the deleted file serves nothing: {doomed:?}"
    );

    // The agent surface agrees, and no answer certified an absence the working
    // copy refutes.
    let mcp_home = root.path().join("mcp-home");
    fs::create_dir_all(&mcp_home).expect("create the MCP client home");
    let answers = mcp_answers(
        &runtime,
        &repo,
        &mcp_home,
        &[
            (
                "find_references",
                serde_json::json!({"query": "new_name", "answer_only": false}),
            ),
            (
                "list_file_entities",
                serde_json::json!({"path": "src/doomed.rs"}),
            ),
        ],
    );
    let new_name = &answers[0];
    assert_eq!(
        new_name["focal_entity"]["name"], "new_name",
        "find_references resolves the new name rather than certifying it absent: {new_name}"
    );
    let listed = &answers[1];
    assert!(
        listed["entities"]
            .as_array()
            .is_none_or(|entities| entities.is_empty()),
        "the deleted file lists no entities: {listed}"
    );

    require_kin(&runtime, &repo, &["daemon", "stop"]);
}
