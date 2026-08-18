// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Binary-level tests for `kin agent`.
//!
//! Every other test for this feature calls the library directly, which never enters the
//! CLI's tokio runtime. That is exactly where the first shipped bug lived: a blocking HTTP
//! client built inside `block_on` panicked on drop and the process exited 101 before the
//! model was ever called. Only running the built binary can see it, and the run must not go
//! through a pipe, because a trailing pipeline stage replaces the status with its own and a
//! 101 reads as a 0.

use serde_json::Value;
use std::path::Path;
use std::process::Command;

fn kin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_kin"))
}

/// A loopback port nothing can be listening on: port 1 is privileged and unused.
const DEAD_ENDPOINT: &str = "http://127.0.0.1:1/v1";

#[test]
fn doctor_reports_an_unreachable_endpoint_rather_than_panicking() {
    let dir = tempfile::tempdir().unwrap();
    let output = kin()
        .args([
            "agent",
            "doctor",
            "--base-url",
            DEAD_ENDPOINT,
            "--repo",
            &dir.path().display().to_string(),
            "--mcp-command",
            "kin-agent-no-such-server",
        ])
        .output()
        .expect("the binary runs");

    let code = output.status.code();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_ne!(
        code,
        Some(101),
        "101 is the tokio runtime-drop panic this test exists to catch: {stderr}"
    );
    assert!(
        !stderr.contains("Cannot drop a runtime"),
        "the runtime-drop panic is back: {stderr}"
    );
    // The endpoint is checked before the MCP server, so an unreachable endpoint wins.
    assert_eq!(
        code,
        Some(4),
        "an unreachable endpoint must exit 4. stderr: {stderr}"
    );
}

#[test]
fn doctor_reports_a_missing_mcp_server_when_the_endpoint_answers() {
    // A control for the test above: with a reachable endpoint the exit code must move to
    // the MCP failure, or a hardcoded 4 would pass the first test for the wrong reason.
    let dir = tempfile::tempdir().unwrap();
    let server = tiny_models_endpoint();
    let output = kin()
        .args([
            "agent",
            "doctor",
            "--base-url",
            &server.base_url,
            "--repo",
            &dir.path().display().to_string(),
            "--mcp-command",
            "kin-agent-no-such-server",
        ])
        .output()
        .expect("the binary runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_ne!(output.status.code(), Some(101), "panicked: {stderr}");
    assert_eq!(
        output.status.code(),
        Some(5),
        "a reachable endpoint plus a missing MCP server must exit 5. stderr: {stderr}"
    );
}

#[test]
fn a_failed_run_still_closes_its_transcript_with_a_result_record() {
    // The contract promises a terminal `result` record on every exit code 2 through 5. A
    // run whose transcript stops after the init record is unmeasurable in the way that
    // matters: it looks like a run that never started rather than one that died.
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let server = tiny_models_endpoint();
    let output = kin()
        .args([
            "agent",
            "run",
            "--task",
            "find anything",
            "--model",
            "whatever",
            "--base-url",
            &server.base_url,
            "--repo",
            &dir.path().display().to_string(),
            "--out",
            &out.display().to_string(),
            "--mcp-command",
            "kin-agent-no-such-server",
        ])
        .output()
        .expect("the binary runs");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_ne!(output.status.code(), Some(101), "panicked: {stderr}");
    assert_eq!(
        output.status.code(),
        Some(5),
        "a missing MCP server must exit 5. stderr: {stderr}"
    );

    let records = read_jsonl(&out.join("transcript.jsonl"));
    assert!(!records.is_empty(), "a transcript must exist even on failure");
    let last = records.last().unwrap();
    assert_eq!(
        last["type"], "result",
        "the transcript must close with a result record: {last}"
    );
    assert_eq!(last["subtype"], "mcp_error");
    assert_eq!(last["is_error"], true);
    assert_eq!(last["kin_agent"]["exit_code"], 5);
    assert!(
        out.join("result.json").is_file(),
        "result.json must exist even on failure"
    );
}

#[test]
fn mcp_command_is_repeatable_and_names_each_server_separately() {
    // Two servers must both be attempted and both named, so a brownfield task spanning two
    // repositories cannot silently cover only one of them.
    let dir = tempfile::tempdir().unwrap();
    let server = tiny_models_endpoint();
    let output = kin()
        .args([
            "agent",
            "doctor",
            "--base-url",
            &server.base_url,
            "--repo",
            &dir.path().display().to_string(),
            "--mcp-command",
            "kin-agent-no-such-server-one",
            "--mcp-command",
            "kin-agent-no-such-server-two",
        ])
        .output()
        .expect("the binary runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("kin-agent-no-such-server-one"),
        "the first server must be probed: {stdout}"
    );
    assert!(
        stdout.contains("kin-agent-no-such-server-two"),
        "the second server must be probed too, not just the first: {stdout}"
    );
    assert_eq!(output.status.code(), Some(5));
}

fn read_jsonl(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("every transcript line is JSON"))
        .collect()
}

/// The smallest endpoint that satisfies `GET /v1/models`, so a test can separate "the
/// endpoint is not there" from "the MCP server is not there".
struct TinyEndpoint {
    base_url: String,
}

fn tiny_models_endpoint() -> TinyEndpoint {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) if line.trim().is_empty() => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            let body = br#"{"data":[{"id":"whatever","object":"model"}],"object":"list"}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body);
            let _ = stream.flush();
        }
    });
    TinyEndpoint {
        base_url: format!("http://127.0.0.1:{port}/v1"),
    }
}
