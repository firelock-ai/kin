// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A run whose Kin session disappears mid-run opens a new one and lands its change, but
//! only when the refusal proves nothing was started.
//!
//! Sessions live in the daemon, so a daemon that restarts during a run no longer holds
//! the session the run opened. When the begin of a `kin_mutate` is refused for that,
//! kin-mcp puts a `kin_mutate_not_started` marker on the refusal's first line, and that
//! is the only answer a run may resend on. The words "Session not found" can also arrive
//! after a commit that never answered, in the note about an abort that found the session
//! gone, and that change may have been published. The model is scripted, and so is the
//! graph server, which answers the run's first mutation in the way the test names and
//! logs every call it answered.

use kin_agent::{AgentConfig, ExitStatus, ProviderConfig};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A scripted chat endpoint: each request is answered with the next scripted completion.
fn start_endpoint(script: Vec<Value>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for response in script {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let line = line.trim_end();
                if line.is_empty() {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        length = value.trim().parse().unwrap_or(0);
                    }
                }
            }
            let mut body = vec![0u8; length];
            let _ = reader.read_exact(&mut body);
            let payload = response.to_string();
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{payload}",
                    payload.len()
                )
                .as_bytes(),
            );
        }
    });
    format!("http://127.0.0.1:{port}/v1")
}

fn completion(content: &str, call: Option<(&str, Value)>) -> Value {
    let mut message = json!({ "role": "assistant", "content": content });
    let finish = match call {
        Some((name, arguments)) => {
            message["tool_calls"] = json!([{
                "id": "call_1",
                "type": "function",
                "function": { "name": name, "arguments": arguments.to_string() }
            }]);
            "tool_calls"
        }
        None => "stop",
    };
    json!({
        "id": "chatcmpl-test",
        "choices": [{ "index": 0, "message": message, "finish_reason": finish }],
        "usage": { "prompt_tokens": 10, "completion_tokens": 5 }
    })
}

/// A graph server whose first session is gone by the time the first mutation arrives,
/// and which accepts a mutation under any later one. The refusal under the first session
/// is chosen by the second argument:
/// - `marker`: a begin refused for this session, marked not started, as kin-mcp answers;
/// - `note`: a commit that never answered, with the abort's "Session not found" in the
///   open-transaction note after it;
/// - `other`: the marker, naming a session this run never sent;
/// - `enveloped` and `enveloped_note`: the `marker` and `note` refusals as a Kin server
///   delivers them, inside the envelope as `{"_kin": ..., "message": <text>}`.
const SERVER: &str = r#"#!/usr/bin/env python3
import json, sys

LOG = sys.argv[1]
MODE = sys.argv[2]
SESSIONS = []
GONE = ("Session not found: sess-1. It was ended or expired after its idle timeout or the "
        "daemon restarted.")


def marker(session):
    return "kin_mutate_not_started: " + json.dumps(
        {"stage": "begin", "refusal": "session_not_found", "session_id": session})


def enveloped(text):
    return {"_kin": {"envelope_version": 2, "runtime": "repo-daemon"}, "message": text}


NOTE = ("connection reset by peer\n\nkin_mutate could not abort transaction txn-1 after its "
        "commit failed (" + GONE + "), so that transaction is still open.")
TOOLS = [
    {"name": "kin_mutate", "description": "Change entities.",
     "inputSchema": {"type": "object", "properties": {"operations": {"type": "array"}},
                     "required": ["operations"]}},
    {"name": "kin_session_start", "description": "Start a session.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "kin_session_end", "description": "End a session.",
     "inputSchema": {"type": "object", "properties": {}}},
]


def payload(obj, is_error=False):
    return {"content": [{"type": "text", "text": json.dumps(obj) if isinstance(obj, dict)
                         else obj}], "isError": is_error}


def call(name, args):
    with open(LOG, "a") as fh:
        fh.write(json.dumps({"tool": name, "args": args}) + "\n")
    if name == "kin_session_start":
        SESSIONS.append("sess-%d" % (len(SESSIONS) + 1))
        return payload({"session_id": SESSIONS[-1]})
    if name == "kin_session_end":
        return payload({"ended": True})
    if name == "kin_mutate":
        session = args.get("session_id")
        if session == "sess-1":
            if MODE == "marker":
                return payload(marker("sess-1") + "\n" + GONE, is_error=True)
            if MODE == "note":
                return payload(NOTE, is_error=True)
            if MODE == "other":
                return payload(marker("sess-9") + "\n" + GONE, is_error=True)
            if MODE == "enveloped":
                return payload(enveloped(marker("sess-1") + "\n" + GONE), is_error=True)
            if MODE == "enveloped_note":
                return payload(enveloped(NOTE), is_error=True)
        return payload({"transaction_id": "txn-1", "ops_applied": 1, "session_id": session})
    return payload("unknown tool " + name, is_error=True)


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method = msg.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "fake-kin", "version": "0"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        params = msg.get("params", {})
        result = call(params.get("name", ""), params.get("arguments", {}))
    else:
        result = {}
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    repo: PathBuf,
    out: PathBuf,
    log: PathBuf,
    server: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let server = dir.path().join("server.py");
    std::fs::write(&server, SERVER).unwrap();
    Fixture {
        repo,
        out: dir.path().join("out"),
        log: dir.path().join("calls.jsonl"),
        server,
        _dir: dir,
    }
}

fn config(fixture: &Fixture, base_url: &str, mode: &str) -> AgentConfig {
    AgentConfig {
        task: "Change greet.".into(),
        system_prompt: Some("You are a test agent.".into()),
        repo: fixture.repo.clone(),
        out_dir: fixture.out.clone(),
        provider: ProviderConfig {
            base_url: ProviderConfig::normalize_base_url(base_url),
            model: "fixture-model".into(),
            api_key: None,
            temperature: None,
            request_timeout: Duration::from_secs(20),
        },
        mcp_command: vec![
            "python3".into(),
            fixture.server.display().to_string(),
            fixture.log.display().to_string(),
            mode.to_string(),
        ],
        extra_servers: Vec::new(),
        mcp_timeout: Duration::from_secs(60),
        max_tool_calls: 4,
        deadline: Duration::from_secs(120),
        context: kin_agent::ContextWindow {
            tokens: 131_072,
            source: kin_agent::ContextSource::Flag,
        },
        max_result_bytes: None,
        tool_profile: None,
    }
}

fn read_jsonl(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn mutation(extra: Value) -> Value {
    let mut arguments = json!({
        "operations": [{ "verb": "update", "target": "greet", "body": "def greet():\n    return 2",
                         "description": "raise greet" }],
        "summary": "Raise greet"
    });
    if let (Some(into), Some(from)) = (arguments.as_object_mut(), extra.as_object()) {
        into.extend(from.clone());
    }
    arguments
}

/// Run one scripted conversation against a server in `mode`: one mutation, then an answer.
fn run_once(fixture: &Fixture, mode: &str, arguments: Value) -> kin_agent::RunOutcome {
    let base_url = start_endpoint(vec![
        completion("Raising greet.", Some(("mcp__kin__kin_mutate", arguments))),
        completion("greet now returns 2.", None),
    ]);
    kin_agent::run(config(fixture, &base_url, mode)).expect("the run completes")
}

fn sessions_started(log: &Path) -> usize {
    read_jsonl(log)
        .into_iter()
        .filter(|row| row["tool"] == "kin_session_start")
        .count()
}

fn mutations(log: &Path) -> Vec<Value> {
    read_jsonl(log)
        .into_iter()
        .filter(|row| row["tool"] == "kin_mutate")
        .collect()
}

#[test]
fn a_mutation_whose_begin_was_refused_for_a_gone_session_lands_under_a_fresh_one() {
    let fixture = fixture();
    let outcome = run_once(&fixture, "marker", mutation(json!({})));
    assert_eq!(outcome.status, ExitStatus::Success);

    // Two sends of the one call the model made: refused under the run's first session,
    // then accepted under the session the run opened in its place.
    let sent = mutations(&fixture.log);
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert_eq!(sent[0]["args"]["session_id"], "sess-1");
    assert_eq!(sent[1]["args"]["session_id"], "sess-2");
    assert_eq!(sent[0]["args"]["operations"], sent[1]["args"]["operations"]);
    assert_eq!(
        sessions_started(&fixture.log),
        2,
        "the run opened exactly one replacement session"
    );

    // The model saw one call and its one clean result, and the run records the change.
    let agent = &outcome.result["kin_agent"];
    assert_eq!(agent["tool_calls"], 1);
    assert_eq!(agent["kin_calls"], 1);
    assert_eq!(agent["entities_changed"], json!(["greet"]));

    // The trace keeps the refusal and the reopening, so a reader can see both.
    let trace = read_jsonl(&outcome.trace_path);
    let gone = trace
        .iter()
        .find(|row| row["event"] == "session_gone")
        .expect("the refused send is traced");
    assert_eq!(gone["args"]["session_id"], "sess-1");
    assert!(gone["detail"]
        .as_str()
        .unwrap()
        .starts_with("kin_mutate_not_started: "));
    let landed = trace
        .iter()
        .rev()
        .find(|row| row["tool"] == "kin_mutate" && row["policy"] == "allowed")
        .expect("the landed send is traced");
    assert_eq!(landed["is_error"], false);
    assert_eq!(landed["args"]["session_id"], "sess-2");
}

/// A gone session found only after the commit was sent is never resent: the commit may
/// have published before the daemon restarted, so the words "Session not found" in the
/// abort's note are not a license to try again. The model sees the refusal as it came.
#[test]
fn a_gone_session_named_only_in_the_abort_note_is_not_resent() {
    let fixture = fixture();
    let outcome = run_once(&fixture, "note", mutation(json!({})));
    let sent = mutations(&fixture.log);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sessions_started(&fixture.log), 1, "no replacement session");
    let trace = read_jsonl(&outcome.trace_path);
    assert!(!trace.iter().any(|row| row["event"] == "session_gone"));
    let refused = trace
        .iter()
        .find(|row| row["tool"] == "kin_mutate" && row["policy"] == "allowed")
        .expect("the one send is traced");
    assert_eq!(refused["is_error"], true);
    assert_eq!(outcome.result["kin_agent"]["entities_changed"], json!([]));
}

/// A marker that names a session this run never sent is not this run's to act on.
#[test]
fn a_not_started_marker_for_another_session_is_not_resent() {
    let fixture = fixture();
    let outcome = run_once(&fixture, "other", mutation(json!({})));
    assert_eq!(mutations(&fixture.log).len(), 1);
    assert_eq!(sessions_started(&fixture.log), 1, "no replacement session");
    assert!(!read_jsonl(&outcome.trace_path)
        .iter()
        .any(|row| row["event"] == "session_gone"));
}

/// The controls: a call that names its own session, or carries a request id, is not
/// sent again even on the marker. The model's own session is the model's to correct, and
/// a keyed call is retried by the durable protocol under its own identity.
#[test]
fn a_mutation_the_harness_did_not_session_or_that_is_keyed_is_not_retried() {
    for extra in [
        json!({ "session_id": "sess-1" }),
        json!({ "request_id": "req-1" }),
    ] {
        let fixture = fixture();
        let outcome = run_once(&fixture, "marker", mutation(extra.clone()));
        let sent = mutations(&fixture.log);
        assert_eq!(sent.len(), 1, "{extra}: {sent:?}");
        assert_eq!(
            sessions_started(&fixture.log),
            1,
            "{extra}: no replacement session is opened"
        );
        assert!(
            !read_jsonl(&outcome.trace_path)
                .iter()
                .any(|row| row["event"] == "session_gone"),
            "{extra}"
        );
    }
}

/// A Kin server delivers the begin refusal inside the envelope, with the marker as the
/// first line of `message`, and that is how it reached a run after a real daemon restart.
/// The run reads it there and lands the change under one replacement session.
#[test]
fn a_begin_refusal_delivered_inside_the_envelope_lands_under_a_fresh_session() {
    let fixture = fixture();
    let outcome = run_once(&fixture, "enveloped", mutation(json!({})));
    assert_eq!(outcome.status, ExitStatus::Success);
    let sent = mutations(&fixture.log);
    assert_eq!(sent.len(), 2, "{sent:?}");
    assert_eq!(sent[0]["args"]["session_id"], "sess-1");
    assert_eq!(sent[1]["args"]["session_id"], "sess-2");
    assert_eq!(sessions_started(&fixture.log), 2);
    assert_eq!(
        outcome.result["kin_agent"]["entities_changed"],
        json!(["greet"])
    );
    let trace = read_jsonl(&outcome.trace_path);
    let gone = trace
        .iter()
        .find(|row| row["event"] == "session_gone")
        .expect("the refused send is traced");
    assert!(gone["detail"]
        .as_str()
        .unwrap()
        .starts_with("kin_mutate_not_started: "));
}

/// The abort note inside the envelope is still not a license to resend: the commit it
/// follows may have published.
#[test]
fn an_abort_note_delivered_inside_the_envelope_is_not_resent() {
    let fixture = fixture();
    let outcome = run_once(&fixture, "enveloped_note", mutation(json!({})));
    assert_eq!(mutations(&fixture.log).len(), 1);
    assert_eq!(sessions_started(&fixture.log), 1, "no replacement session");
    assert!(!read_jsonl(&outcome.trace_path)
        .iter()
        .any(|row| row["event"] == "session_gone"));
    assert_eq!(outcome.result["kin_agent"]["entities_changed"], json!([]));
}
