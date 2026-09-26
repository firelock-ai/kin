// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-repo authority after a commit that moves the graph root, with a
//! second repository registered, through the real binaries.
//!
//! A daemon whose registry holds another repository registers both in its
//! cross-repo spine, and a commit that moves its own repository's graph root
//! registers that repository again. A registration marks every registered
//! repository's cross-repo edges stale, because any of them may call into the
//! entity set that just changed, and only the committing repository's edges
//! used to be refreshed afterwards. The daemon keeps no sibling graph once the
//! spine is built, so from then on every `find_references` read
//! `cross_repo_authority_incomplete` until the daemon restarted.

use std::fs;
use std::path::Path;
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::tempdir;

mod common;

use common::IsolatedDaemonRuntime;

fn git(repo: &Path, args: &[&str]) {
    let output = common::Command::new("git")
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

fn kin(runtime: &IsolatedDaemonRuntime, repo: &Path, args: &[&str]) -> Output {
    runtime
        .kin_command()
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config())
        .env("KIN_EMBED_BACKEND", "cpu")
        .env("KIN_DAEMON_AUTO_EMBED", "0")
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "180")
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .current_dir(repo)
        .output()
        .expect("run kin")
}

fn succeed(runtime: &IsolatedDaemonRuntime, repo: &Path, args: &[&str]) {
    let output = kin(runtime, repo, args);
    assert!(
        output.status.success(),
        "kin {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A Git repository holding `files`, converted with `kin init`, which also
/// records it in the runtime's registry.
fn initialize(runtime: &IsolatedDaemonRuntime, repo: &Path, files: &[(&str, &str)]) {
    fs::create_dir_all(repo).expect("create repo");
    git(repo, &["init", "--initial-branch=main"]);
    git(repo, &["config", "commit.gpgsign", "false"]);
    git(repo, &["config", "user.name", "Ada Lovelace"]);
    git(repo, &["config", "user.email", "ada@example.com"]);
    for (path, contents) in files {
        fs::write(repo.join(path), contents).expect("write source");
    }
    git(repo, &["add", "--all"]);
    git(repo, &["commit", "-m", "first commit"]);
    succeed(runtime, repo, &["init", ".", "--json"]);
}

/// One `find_references` call through `kin mcp start`, answered by the
/// repository's daemon.
fn find_references(
    runtime: &IsolatedDaemonRuntime,
    repo: &Path,
    name: &str,
    relation_kinds: &[&str],
) -> Value {
    let frames = repo.parent().unwrap().join(format!("mcp-{name}.jsonl"));
    fs::write(
        &frames,
        [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"kin-sibling-refresh-test","version":"0"}}}"#.to_string(),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "find_references",
                    "arguments": {
                        "query": name,
                        "relation_kinds": relation_kinds,
                        "answer_only": false
                    }
                }
            })
            .to_string(),
        ]
        .join("\n")
            + "\n",
    )
    .expect("write MCP frames");
    let repo_arg = repo.to_str().expect("UTF-8 path");
    let stdout_path = frames.with_extension("stdout");
    let stderr_path = frames.with_extension("stderr");
    let mut child = runtime
        .kin_command()
        .args(["mcp", "start", "--repo", repo_arg])
        .env("KIN_MCP_REPO", repo_arg)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("KIN_EMBED_BACKEND", "cpu")
        .env("KIN_DAEMON_AUTO_EMBED", "0")
        .env("KIN_DAEMON_DISABLE_LSP", "1")
        .env("KIN_DAEMON_READY_TIMEOUT_SECS", "180")
        .env("KIN_DAEMON_BIN", runtime.daemon_bin())
        .current_dir(repo)
        .stdin(Stdio::from(fs::File::open(&frames).expect("open frames")))
        .stdout(Stdio::from(
            fs::File::create(&stdout_path).expect("create the MCP stdout capture"),
        ))
        .stderr(Stdio::from(
            fs::File::create(&stderr_path).expect("create the MCP stderr capture"),
        ))
        .spawn_owned()
        .expect("spawn kin mcp start");
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        if child.try_wait().expect("poll kin mcp start").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "kin mcp start did not finish within 300s: stderr={}",
                fs::read_to_string(&stderr_path).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let stdout = fs::read_to_string(&stdout_path).expect("read the MCP stdout capture");
    let frame = stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .find(|frame| frame["id"] == 2)
        .unwrap_or_else(|| {
            panic!(
                "no find_references response: stdout={stdout} stderr={}",
                fs::read_to_string(&stderr_path).unwrap_or_default()
            )
        });
    serde_json::from_str(
        frame["result"]["content"][0]["text"]
            .as_str()
            .expect("tool text"),
    )
    .expect("tool payload is JSON")
}

fn verdict(payload: &Value) -> (String, Option<String>) {
    let verdict = &payload["_kin"]["verdict"];
    (
        verdict["state"].as_str().unwrap_or_default().to_string(),
        verdict["limiting_factor"].as_str().map(str::to_string),
    )
}

/// The factor's codes, less `call_sites_unproven_no_resolver` when this
/// daemon's switched-off language-server enrichment is the whole reason for it.
///
/// A daemon started with `KIN_DAEMON_DISABLE_LSP=1` sweeps nothing and so
/// writes no call-site ledger, and every caller in an answer's scope reads as
/// unproven because enrichment is switched off: no resolver will ever prove
/// it, so it is not owed. That says nothing about what this file tests. It is
/// excused only while the block holds no site at all and names no other
/// reason: a caller a ledger does describe, any unsettled site it holds, and
/// a caller owed a sweep still limit the answer.
fn codes_past_unswept_call_sites<'f>(answer: &Value, factor: &'f str) -> Vec<&'f str> {
    let block = &answer["call_sites"];
    let callers = block["callers_unproven_no_resolver"].as_u64().unwrap_or(0);
    let switched_off = block["no_resolver"].as_object().is_some_and(|reasons| {
        !reasons.is_empty()
            && reasons
                .keys()
                .all(|reason| reason.ends_with("language-server enrichment is switched off"))
    });
    let unswept = block["sites"] == 0
        && callers > 0
        && block["callers_unproven_no_resolver"] == block["callers"]
        && switched_off;
    factor
        .split("; ")
        .filter(|code| !(unswept && *code == "call_sites_unproven_no_resolver"))
        .collect()
}

/// The last lines of a repository's daemon log, for a failure message.
fn daemon_log_tail(repo: &Path) -> String {
    let log = fs::read(repo.join(".kin/daemon.log")).unwrap_or_default();
    let log = String::from_utf8_lossy(&log);
    let lines: Vec<&str> = log
        .lines()
        .filter(|line| !line.contains("kin_core::env_registry"))
        .collect();
    lines[lines.len().saturating_sub(80)..].join("\n")
}

/// A `find_references` answer that certifies.
///
/// A daemon that has just started, or has just admitted a change, publishes
/// its repository to the spine after it begins answering, and an answer inside
/// that window reads `cross_repo_authority_incomplete`. The call is asked again
/// while that factor is the whole of it, for at most a minute. The defect this
/// file covers held that factor for the rest of the daemon's life, so it fails
/// here at the deadline. Any other factor fails at once, except
/// `call_sites_unproven_no_resolver` over a scope holding no site, which is
/// what this daemon's switched-off enrichment leaves (see [`codes_past_unswept_call_sites`]).
fn certified_references(
    runtime: &IsolatedDaemonRuntime,
    repo: &Path,
    name: &str,
    relation_kinds: &[&str],
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let answer = find_references(runtime, repo, name, relation_kinds);
        match verdict(&answer) {
            (state, None) if state == "certified" => return answer,
            (_, Some(factor)) if codes_past_unswept_call_sites(&answer, &factor).is_empty() => {
                return answer
            }
            (_, Some(factor))
                if codes_past_unswept_call_sites(&answer, &factor)
                    == ["cross_repo_authority_incomplete"]
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_secs(1));
            }
            _ => panic!(
                "the answer did not certify: {answer}\nthe daemon log's last lines:\n{}",
                daemon_log_tail(repo)
            ),
        }
    }
}

/// A `find_references` answer whose cross-repo authority certifies, asked
/// again through the same window as [`certified_references`].
///
/// This reads the verdict's cross-repo input rather than its state, because a
/// reference from another repository is a spine edge, which carries no relation
/// kind: it is counted only when every default kind is asked for, and whether
/// the whole verdict then certifies also turns on this repository's own
/// coverage of each of those kinds, which is not what this file tests.
fn cross_repo_certified_references(
    runtime: &IsolatedDaemonRuntime,
    repo: &Path,
    name: &str,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let answer = find_references(runtime, repo, name, &["calls", "imports", "references"]);
        let cross_repo = answer["_kin"]["verdict"]["inputs"]["cross_repo"].as_str();
        if cross_repo == Some("certified") {
            return answer;
        }
        assert!(
            Instant::now() < deadline,
            "cross-repo authority did not certify: {answer}\nthe daemon log's last lines:\n{}",
            daemon_log_tail(repo)
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// How many references the answer carries from other registered
/// repositories.
fn federated_references(answer: &Value) -> u64 {
    answer["cross_repo"]["federated_reference_count"]
        .as_u64()
        .unwrap_or_else(|| panic!("the answer carries no cross-repo accounting: {answer}"))
}

/// Two registered repositories, a commit in one of them that moves its graph
/// root, and `find_references` in that repository certifying afterwards
/// without a restart, still carrying the other repository's call.
///
/// `local_helper` has a caller in another file of its own repository and none
/// elsewhere, so its answer certifies on the whole: that is the answer the
/// defect held at `cross_repo_authority_incomplete`. `shared_target` is called
/// from the sibling, and its answer shows that call arriving through the spine
/// both before the commit and after it.
///
/// Falsify by removing the `refresh_stale_sibling_cross_repo_edges` call from
/// `reregister_primary_at_current_root` in kin-daemon: the `local_helper`
/// answer after the commit then reads `cross_repo_authority_incomplete` until
/// the deadline.
#[test]
fn a_root_moving_commit_keeps_references_from_a_registered_sibling_certified() {
    let root = tempdir().expect("temp root");
    let sibling = root.path().join("sibling");
    let primary = root.path().join("primary");
    let runtime = IsolatedDaemonRuntime::new(&primary);
    // The sibling first, so it is registered before the primary's daemon
    // starts and pins its registered siblings.
    initialize(
        &runtime,
        &sibling,
        &[(
            "consumer.py",
            "from primary_lib import shared_target\n\n\ndef sibling_caller():\n    return shared_target()\n",
        )],
    );
    initialize(
        &runtime,
        &primary,
        &[
            (
                "primary_lib.py",
                "def shared_target():\n    return 1\n\n\ndef local_helper():\n    return 2\n",
            ),
            (
                "app.py",
                "from primary_lib import local_helper\n\n\ndef main():\n    return local_helper()\n",
            ),
        ],
    );

    certified_references(&runtime, &primary, "local_helper", &["calls"]);
    let before = cross_repo_certified_references(&runtime, &primary, "shared_target");
    assert_eq!(
        federated_references(&before),
        1,
        "the control: the sibling's call must reach the primary through the spine: {before}"
    );

    fs::write(
        primary.join("added.py"),
        "def added_by_the_commit():\n    return 3\n",
    )
    .expect("write the added source");
    succeed(&runtime, &primary, &["commit", "-m", "add a function"]);

    certified_references(&runtime, &primary, "local_helper", &["calls"]);
    let after = cross_repo_certified_references(&runtime, &primary, "shared_target");
    assert_eq!(
        after["cross_repo"]["authority_complete"],
        Value::Bool(true),
        "{after}"
    );
    assert_eq!(
        federated_references(&after),
        1,
        "the sibling's call must still reach the primary after the commit: {after}"
    );
}
