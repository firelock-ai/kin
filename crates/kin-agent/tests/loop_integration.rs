// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! End-to-end tests for the loop.
//!
//! The model is a scripted OpenAI-compatible responder on a loopback socket, so a turn
//! sequence is exact rather than sampled. The graph server is a scripted MCP stdio server
//! for the hermetic tests and a real `kin mcp start` for the ignored one, so the wire
//! contract is proven against the product rather than only against a stand-in.

use kin_agent::{AgentConfig, ExitStatus, ProviderConfig};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A scripted chat endpoint. Each request pops the next response off the script, so a
/// test asserts on a fixed turn sequence instead of a model's mood.
struct FakeEndpoint {
    base_url: String,
    handle: Option<std::thread::JoinHandle<Vec<Value>>>,
}

impl FakeEndpoint {
    fn start(script: Vec<Value>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for response in script.into_iter() {
                let Ok((stream, _)) = listener.accept() else {
                    break;
                };
                match serve_one(stream, &response) {
                    Some(request) => seen.push(request),
                    None => break,
                }
            }
            seen
        });
        FakeEndpoint {
            base_url: format!("http://127.0.0.1:{port}/v1"),
            handle: Some(handle),
        }
    }

    /// Every request body the endpoint received, in order.
    fn requests(mut self) -> Vec<Value> {
        self.handle
            .take()
            .expect("started")
            .join()
            .expect("endpoint thread")
    }
}

fn serve_one(mut stream: TcpStream, response: &Value) -> Option<Value> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some(value) = trimmed
            .strip_prefix("Content-Length:")
            .or_else(|| trimmed.strip_prefix("content-length:"))
        {
            content_length = value.trim().parse().ok()?;
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).ok()?;
    let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);

    let payload = response.to_string();
    let http = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload.len(),
        payload
    );
    stream.write_all(http.as_bytes()).ok()?;
    stream.flush().ok()?;
    Some(request)
}

/// A scripted endpoint that holds each answer for its own delay after the request arrives,
/// the way a local model prefilling a long prompt does. It returns the base URL and a handle
/// that yields, per request, the wall-clock seconds it arrived and was answered.
fn start_paced_endpoint(
    script: Vec<(Duration, Value)>,
) -> (String, std::thread::JoinHandle<Vec<(f64, f64)>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let mut in_flight = Vec::new();
        for (delay, response) in script {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            let arrived = wall_now();
            std::thread::sleep(delay);
            if serve_one(stream, &response).is_none() {
                break;
            }
            in_flight.push((arrived, wall_now()));
        }
        in_flight
    });
    (format!("http://127.0.0.1:{port}/v1"), handle)
}

/// Seconds since the Unix epoch, the clock the scripted MCP server stamps its calls with.
fn wall_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

fn completion(content: &str, tool_calls: Option<Value>) -> Value {
    let mut message = json!({ "role": "assistant", "content": content });
    let finish = if tool_calls.is_some() {
        "tool_calls"
    } else {
        "stop"
    };
    if let Some(calls) = tool_calls {
        message["tool_calls"] = calls;
    }
    json!({
        "id": "chatcmpl-test",
        "choices": [{ "index": 0, "message": message, "finish_reason": finish }],
        "usage": { "prompt_tokens": 100, "completion_tokens": 20 }
    })
}

fn tool_call(id: &str, name: &str, arguments: Value) -> Value {
    json!([{
        "id": id,
        "type": "function",
        "function": { "name": name, "arguments": arguments.to_string() }
    }])
}

/// A completion whose usage is the endpoint's own count, for driving the context budget.
fn completion_with_usage(
    content: &str,
    tool_calls: Option<Value>,
    prompt_tokens: u64,
    completion_tokens: u64,
) -> Value {
    let mut response = completion(content, tool_calls);
    response["usage"] = json!({
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
    });
    response
}

/// Answer one GET by path from a fixed table, 404 for anything else, and record the path,
/// the way a server that keeps its own API beside the compatible one answers.
fn serve_route(
    mut stream: TcpStream,
    routes: &[(String, Value)],
    seen: &std::sync::Mutex<Vec<String>>,
) {
    let Ok(clone) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(clone);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim_end().is_empty() {
            break;
        }
    }
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    seen.lock().unwrap().push(path.clone());
    let (status, body) = match routes.iter().find(|(route, _)| *route == path) {
        Some((_, body)) => ("200 OK", body.to_string()),
        None => ("404 Not Found", "{}".to_string()),
    };
    let http = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(http.as_bytes());
}

/// Write a scripted MCP stdio server that speaks the real wire shapes: an `initialize`
/// reply, a `tools/list` carrying the session and transaction tools, and tool results
/// whose payload sits inside `content[0].text` with a `_kin` envelope.
fn write_fake_mcp_server(dir: &Path) -> PathBuf {
    let path = dir.join("fake_mcp_server.py");
    std::fs::write(&path, FAKE_SERVER).expect("write fake server");
    path
}

/// Search-only profiles and incomplete transaction surfaces must never turn a local
/// writing tool into an untracked filesystem edit.
#[test]
fn incomplete_publication_surface_refuses_edit_and_create_without_changing_files() {
    for missing in [
        "all",
        "kin_session_start",
        "kin_transaction_begin",
        "kin_transaction_stage",
        "kin_transaction_commit",
        "kin_transaction_abort",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let repo = fixture_repo(dir.path());
        let original = std::fs::read(repo.join("src/greet.py")).unwrap();
        let server = dir.path().join("incomplete_mcp.py");
        let filter = if missing == "all" {
            "TOOLS = [t for t in TOOLS if not t['name'].startswith('kin_')]".to_string()
        } else {
            format!("TOOLS = [t for t in TOOLS if t['name'] != '{missing}']")
        };
        std::fs::write(
            &server,
            FAKE_SERVER.replace("ENVELOPE =", &format!("{filter}\n\nENVELOPE =")),
        )
        .unwrap();
        let log = dir.path().join("mcp-calls.jsonl");
        let endpoint = FakeEndpoint::start(vec![
            completion(
                "Editing.",
                Some(tool_call(
                    "e1",
                    "edit_file",
                    json!({
                        "path": "src/greet.py", "find": "hello", "replace": "goodbye"
                    }),
                )),
            ),
            completion(
                "Creating.",
                Some(tool_call(
                    "w1",
                    "write_file",
                    json!({
                        "path": "src/new.py", "content": "def created():\n    return 1\n"
                    }),
                )),
            ),
            completion("Both changes landed.", None),
        ]);
        let outcome = kin_agent::run(config(
            &repo,
            &dir.path().join("out"),
            &endpoint.base_url,
            mcp_command(&server, &log),
        ))
        .unwrap();
        assert_eq!(
            std::fs::read(repo.join("src/greet.py")).unwrap(),
            original,
            "missing {missing}"
        );
        assert!(!repo.join("src/new.py").exists(), "missing {missing}");
        assert_eq!(
            outcome.status,
            ExitStatus::ChangesUnpublished,
            "missing {missing}"
        );
        assert_eq!(outcome.result["kin_agent"]["unpublished_changes"], 2);
        let analyzed = analyze(&read_jsonl(&outcome.transcript_path));
        assert_eq!(analyzed.tool_results.len(), 2);
        assert!(analyzed
            .tool_results
            .iter()
            .all(|(_, text, error)| *error && text.contains("was not changed")));
        assert!(
            !mcp_log(&log)
                .iter()
                .any(|row| row["tool"] == "kin_transaction_begin"),
            "an incomplete surface must not open a transaction: missing {missing}"
        );
    }
}

const FAKE_SERVER: &str = r#"#!/usr/bin/env python3
import json, os, sys, time

LOG = sys.argv[1]

# An idle window in whole seconds, when a test names one. The session is then reaped once no
# call has reached it for that long, the way the daemon reaps a PID-less session, every later
# call is refused saying so, and each call is logged with the wall clock it arrived at.
TTL = int(sys.argv[2]) if len(sys.argv) > 2 else None
SESSION = {"last": None, "reaped": False}

# Staged operations per transaction, so a commit publishes what was staged rather than
# answering yes to anything. The server runs with the repository as its cwd.
STAGED = {}
# Every session this server has opened, in order.
SESSIONS = []

TOOLS = [
    {"name": "semantic_locate", "description": "Find entities by meaning.",
     "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}},
                     "required": ["query"]}},
    {"name": "get_entity_source", "description": "Read exact source.",
     "inputSchema": {"type": "object", "properties": {"entity": {"type": "string"}},
                     "required": ["entity"]}},
    {"name": "kin_session_start", "description": "Start a session.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "kin_session_end", "description": "End a session.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "kin_session_heartbeat", "description": "Keep a session alive.",
     "inputSchema": {"type": "object", "properties": {"session_id": {"type": "string"}}}},
    {"name": "kin_transaction_begin", "description": "Begin a transaction.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "kin_transaction_stage", "description": "Stage transaction operations.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "kin_transaction_commit", "description": "Commit a transaction.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "kin_transaction_abort", "description": "Abort a transaction.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "kin_artifact_list", "description": "List repository artifacts.",
     "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer"},
                                                     "offset": {"type": "integer"}}}},
]

ENVELOPE = {"envelope_version": "1", "runtime": "RepoDaemon",
            "graph_as_of": "2026-08-18T00:00:00Z",
            "semantic_coverage": 0.91, "degraded": []}


def payload(obj, is_error=False, indent=None):
    return {"content": [{"type": "text", "text": json.dumps(obj, indent=indent)}],
            "isError": is_error}


def disk_snapshot(operations):
    # What the working copy holds, at the moment of this call, at every path the call's
    # operations name. The real daemon reads the working copy at commit to decide whether it
    # may project over it, so the order a harness writes in is part of the contract, and a
    # test has to be able to see it.
    seen = {}
    for op in operations:
        target = op.get("target")
        if target and os.path.isfile(target):
            with open(target) as fh:
                seen[target] = fh.read()
    return seen


def call(name, args):
    operations = args.get("operations", [])
    if name == "kin_transaction_commit":
        operations = STAGED.get(args.get("transaction_id"), [])
    row = {"tool": name, "args": args, "disk": disk_snapshot(operations)}
    if TTL is not None:
        now = time.monotonic()
        if SESSION["last"] is not None and now - SESSION["last"] > TTL:
            SESSION["reaped"] = True
        if not SESSION["reaped"]:
            SESSION["last"] = now
        row["wall"] = time.time()
        row["reaped"] = SESSION["reaped"]
    with open(LOG, "a") as fh:
        fh.write(json.dumps(row) + "\n")
    if TTL is not None and SESSION["reaped"]:
        return payload({"error": "session sess-fixture-1 was reaped after %d s idle; call "
                                 "kin_session_start for a new one" % TTL,
                        "_kin": ENVELOPE}, is_error=True)
    if name == "kin_artifact_list":
        # Pretty-printed with one row per artifact, like the real server, so a listing
        # asked for a large limit is large for the same reason the real one is.
        limit = int(args.get("limit", 200))
        rows = [{"artifact_id": "00000000-0000-4000-8000-%012d" % i,
                 "path_label": "crates/module_%04d/src/file_%04d.rs" % (i, i),
                 "path_label_lossy": False} for i in range(limit)]
        return payload({"artifact_count": 5000, "offset": 0, "returned": limit,
                        "artifacts": rows, "_kin": ENVELOPE}, indent=2)
    if name == "semantic_locate":
        if args.get("query") == "nothing at all":
            return payload({"results": [], "_kin": ENVELOPE,
                            "negative": {"safe_to_conclude_absent": False,
                                         "trust_reason": "coverage_partial: markdown bodies are not indexed"}})
        return payload({"results": [{"name": "greet", "path": "src/greet.py", "line": 1}],
                        "_kin": ENVELOPE})
    if name == "get_entity_source":
        return payload({"source": "def greet(name):\n    return name\n", "_kin": ENVELOPE})
    if name == "kin_session_start":
        # Numbered, so a harness that re-opens its session gets a new id, as it does from
        # a daemon that was started again.
        SESSIONS.append(len(SESSIONS) + 1)
        reply = {"session_id": "sess-fixture-%d" % SESSIONS[-1], "_kin": ENVELOPE}
        if TTL is not None:
            reply["idle_timeout_secs"] = TTL
        return payload(reply)
    if name == "kin_session_heartbeat":
        return payload({"session_id": args.get("session_id"), "status": "alive",
                        "_kin": ENVELOPE})
    if name == "kin_transaction_begin":
        # src/stale.py: the first session is gone, as after a daemon restart; a re-opened
        # session is accepted. src/nobegin.py: every begin is refused the same way.
        scope, session = args.get("scope"), args.get("session_id")
        gone = {"error": "Session not found: " + str(session) + ". It was ended or expired "
                         "after its idle timeout.", "_kin": ENVELOPE}
        if scope == "src/nobegin.py" or (scope == "src/stale.py" and session == "sess-fixture-1"):
            return payload(gone, is_error=True)
    if name == "kin_session_end":
        return payload({"ended": True, "_kin": ENVELOPE})
    if name == "kin_transaction_begin":
        return payload({"transaction_id": "txn-fixture-1", "_kin": ENVELOPE})
    if name == "kin_transaction_stage":
        # The daemon refuses a create whose path repository authority already tracks, and
        # the mirror of it: a replace whose path authority does not track. TRACKED stands
        # for the fixture graph's contents, so both refusals are the graph's answer rather
        # than a look at the working tree.
        TRACKED = ("src/greet.py", "README.md", "src/dirty.py", "src/stale.py")
        for op in args.get("operations", []):
            verb = op.get("verb")
            target = op.get("target")
            if verb in ("replace", "overwrite"):
                if target not in TRACKED:
                    return payload({"error": "path " + str(target) + " is not tracked by "
                                             "repository authority, so there is nothing to "
                                             "replace", "_kin": ENVELOPE}, is_error=True)
                continue
            if target in TRACKED:
                return payload({"error": "path " + str(target) + " is already tracked",
                                "_kin": ENVELOPE}, is_error=True)
        STAGED.setdefault(args.get("transaction_id"), []).extend(args.get("operations", []))
        return payload({"staged": len(args.get("operations", [])),
                        "transaction_id": "txn-fixture-1", "_kin": ENVELOPE})
    if name == "kin_transaction_commit":
        # The real daemon refuses to publish onto an untracked working-copy path, and
        # materialises the file itself when it does publish. A stand-in that always
        # answers "committed" cannot fail the way the product fails, which is how
        # FIR-2624 shipped: the harness wrote the file first and every real commit was
        # refused while this suite stayed green.
        operations = STAGED.pop(args.get("transaction_id"), [])
        # Real authority validates tree cleanliness at COMMIT, not at stage, so a rewrite
        # can stage cleanly and still be refused when the working copy drifted. A stand-in
        # that only ever refuses at stage cannot produce the state this test is about.
        for op in operations:
            if op.get("verb") in ("replace", "overwrite") and op.get("target") == "src/dirty.py":
                return payload({"message": "repository authority refused the rewrite of "
                                           "src/dirty.py: the working copy is not clean",
                                "_kin": ENVELOPE}, is_error=True)
        # A create that stages cleanly and is refused when it commits, the create twin of the
        # rewrite above, so a harness's behaviour after a refused commit is observable.
        for op in operations:
            if op.get("verb") in ("create", "add", "insert") and op.get("target") == "src/refused.py":
                return payload({"message": "repository authority refused the create of "
                                           "src/refused.py: its directory is not admitted",
                                "_kin": ENVELOPE}, is_error=True)
        for op in operations:
            target = op.get("target")
            if op.get("verb") in ("create", "add", "insert") and os.path.exists(target):
                return payload({"message": "repository projection conflict: untracked "
                                           "working-copy path " + os.path.abspath(target) +
                                           " conflicts with exact workspace target " + target,
                                "_kin": ENVELOPE}, is_error=True)
        for op in operations:
            target = op.get("target")
            if op.get("verb") in ("create", "add", "insert", "replace", "overwrite"):
                parent = os.path.dirname(target)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                with open(target, "w") as fh:
                    fh.write(op.get("body", ""))
        return payload({"committed": True, "published": len(operations),
                        "transaction_id": "txn-fixture-1", "_kin": ENVELOPE})
    if name == "kin_transaction_abort":
        STAGED.pop(args.get("transaction_id"), None)
        return payload({"aborted": True, "_kin": ENVELOPE})
    return payload({"error": "unknown tool " + name}, is_error=True)


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    method = msg.get("method")
    if "id" not in msg:
        continue
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

fn fixture_repo(dir: &Path) -> PathBuf {
    let repo = dir.join("repo");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(
        repo.join("src/greet.py"),
        "def greet(name):\n    return f\"hello {name}\"\n",
    )
    .unwrap();
    std::fs::write(repo.join("README.md"), "# fixture\n").unwrap();
    // Tracked in the fixture graph and refused at COMMIT by the scripted server, which is
    // how a rewrite fails in the product: authority validates tree cleanliness when it
    // commits, not when it stages, so a replace can stage cleanly and still not land.
    std::fs::write(
        repo.join("src/dirty.py"),
        "def stale(name):\n    return name\n",
    )
    .unwrap();
    // The scripted server refuses begin for these two by path: src/stale.py only under the
    // first session, as after a daemon restart, and src/nobegin.py under every session.
    std::fs::write(
        repo.join("src/stale.py"),
        "def later(name):\n    return name\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("src/nobegin.py"),
        "def never(name):\n    return name\n",
    )
    .unwrap();
    repo
}

fn config(repo: &Path, out: &Path, base_url: &str, mcp_command: Vec<String>) -> AgentConfig {
    AgentConfig {
        task: "Find where greet is defined and add a one-line docstring.".into(),
        system_prompt: Some("You are a test agent.".into()),
        repo: repo.to_path_buf(),
        out_dir: out.to_path_buf(),
        provider: ProviderConfig {
            base_url: ProviderConfig::normalize_base_url(base_url),
            model: "fixture-model".into(),
            api_key: None,
            temperature: None,
            request_timeout: Duration::from_secs(20),
        },
        mcp_command,
        extra_servers: Vec::new(),
        mcp_timeout: Duration::from_secs(60),
        max_tool_calls: 10,
        deadline: Duration::from_secs(120),
        context: kin_agent::ContextWindow {
            tokens: 131_072,
            source: kin_agent::ContextSource::Flag,
        },
        max_result_bytes: None,
        tool_profile: None,
    }
}

/// A fixture repository at a named directory, so two attached repositories carry
/// different labels and their tool prefixes are told apart by name rather than by index.
fn fixture_repo_named(dir: &Path, name: &str) -> PathBuf {
    let repo = dir.join(name);
    std::fs::create_dir_all(repo.join("src")).unwrap();
    std::fs::write(
        repo.join("src/greet.py"),
        "def greet(name):\n    return f\"hello {name}\"\n",
    )
    .unwrap();
    std::fs::write(repo.join("README.md"), "# fixture\n").unwrap();
    repo
}

fn read_jsonl(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("every transcript line is JSON"))
        .collect()
}

/// A reader that mirrors what `usage.py` and `analyze.py` take off a transcript, so the
/// shape is asserted against the fields the fleet's analyzers actually read.
struct AnalyzerView {
    init: Value,
    result: Value,
    tool_uses: Vec<(String, String, Value)>,
    tool_results: Vec<(String, String, bool)>,
    assistant_text: String,
}

fn analyze(records: &[Value]) -> AnalyzerView {
    let mut init = Value::Null;
    let mut result = Value::Null;
    let mut tool_uses = Vec::new();
    let mut tool_results = Vec::new();
    let mut assistant_text = String::new();
    for record in records {
        // Every record must carry a timestamp or the analyzers lose their latency.
        assert!(
            record.get("timestamp").and_then(Value::as_str).is_some(),
            "record without a timestamp: {record}"
        );
        match record.get("type").and_then(Value::as_str) {
            Some("system") => init = record.clone(),
            Some("result") => result = record.clone(),
            Some("assistant") => {
                for block in record
                    .pointer("/message/content")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
                {
                    match block.get("type").and_then(Value::as_str) {
                        Some("tool_use") => tool_uses.push((
                            block["id"].as_str().unwrap().to_string(),
                            block["name"].as_str().unwrap().to_string(),
                            block["input"].clone(),
                        )),
                        Some("text") => {
                            assistant_text.push_str(block["text"].as_str().unwrap_or_default())
                        }
                        _ => {}
                    }
                }
            }
            Some("user") => {
                for block in record
                    .pointer("/message/content")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
                {
                    if block.get("type").and_then(Value::as_str) == Some("tool_result") {
                        tool_results.push((
                            block["tool_use_id"].as_str().unwrap().to_string(),
                            block["content"].as_str().unwrap_or_default().to_string(),
                            block["is_error"].as_bool().unwrap_or(false),
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    AnalyzerView {
        init,
        result,
        tool_uses,
        tool_results,
        assistant_text,
    }
}

/// The log path travels as an argument rather than an environment variable, because the
/// test binary runs its tests as threads in one process and a shared variable would race.
fn mcp_command(server: &Path, log: &Path) -> Vec<String> {
    vec![
        "python3".to_string(),
        server.display().to_string(),
        log.display().to_string(),
    ]
}

fn mcp_log(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn a_tool_call_reaches_kin_and_an_in_place_edit_is_staged_as_a_replace() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");

    let endpoint = FakeEndpoint::start(vec![
        completion(
            "Let me find it.",
            Some(tool_call(
                "c1",
                "mcp__kin__semantic_locate",
                json!({ "query": "greet" }),
            )),
        ),
        completion(
            "Now the edit.",
            Some(tool_call(
                "c2",
                "edit_file",
                json!({
                    "path": "src/greet.py",
                    "find": "def greet(name):",
                    "replace": "def greet(name):\n    \"\"\"Return a greeting for name.\"\"\""
                }),
            )),
        ),
        completion(
            "greet is in src/greet.py and now carries a docstring.",
            None,
        ),
    ]);
    let base_url = endpoint.base_url.clone();

    let outcome = kin_agent::run(config(&repo, &out, &base_url, mcp_command(&server, &log)))
        .expect("the run completes");

    assert_eq!(outcome.status, ExitStatus::Success);
    assert_eq!(
        outcome.final_text,
        "greet is in src/greet.py and now carries a docstring."
    );

    // The edit landed on disk.
    let edited = std::fs::read_to_string(repo.join("src/greet.py")).unwrap();
    assert!(
        edited.contains("\"\"\"Return a greeting for name.\"\"\""),
        "the docstring must be in the file: {edited}"
    );

    // The call reached the graph server, and the edit was bracketed and published: the
    // stage surface's `replace` shape is keyed on a repository-relative path plus the
    // file's complete new text, which is exactly what an edit leaves the harness holding.
    let calls = mcp_log(&log);
    let names: Vec<&str> = calls
        .iter()
        .map(|call| call["tool"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![
            "kin_session_start",
            "semantic_locate",
            "kin_transaction_begin",
            "kin_transaction_stage",
            "kin_transaction_commit",
            "kin_session_end"
        ],
        "an edit must be staged as a replace and committed, not left unbracketed"
    );
    assert_eq!(calls[1]["args"]["query"], "greet");

    // The staged operation carries the file's WHOLE new text, not the fragment the model
    // sent as `replace`. A body built from the fragment would satisfy every assertion
    // above and destroy the file at commit, so the untouched line is asserted too.
    let staged_op = &calls
        .iter()
        .find(|call| call["tool"] == "kin_transaction_stage")
        .expect("the edit is staged")["args"]["operations"][0];
    assert_eq!(staged_op["verb"], "replace");
    assert_eq!(staged_op["target"], "src/greet.py");
    let staged_body = staged_op["body"]
        .as_str()
        .expect("the replace carries a body");
    assert!(
        staged_body.contains("\"\"\"Return a greeting for name.\"\"\""),
        "the staged body must carry the edit: {staged_body}"
    );
    assert!(
        staged_body.contains("return f\"hello {name}\""),
        "the staged body must be the file's complete new text, keeping the lines the edit \
         did not touch: {staged_body}"
    );

    // The transcript records it in the shape the analyzers read.
    let records = read_jsonl(&outcome.transcript_path);
    let view = analyze(&records);
    assert_eq!(view.init["subtype"], "init");
    assert_eq!(view.init["model"], "fixture-model");
    assert_eq!(view.init["mcp_servers"][0]["status"], "connected");
    assert_eq!(view.init["mcp_server_errors"].as_array().unwrap().len(), 0);
    let tools: Vec<&str> = view.init["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    assert!(tools.contains(&"mcp__kin__semantic_locate"));
    assert!(tools.contains(&"edit_file"));
    // The session and transaction tools are the harness's, never the model's.
    assert!(!tools.iter().any(|name| name.contains("kin_transaction")));
    assert!(!tools.iter().any(|name| name.contains("kin_session")));

    assert_eq!(view.tool_uses.len(), 2);
    assert_eq!(view.tool_uses[0].1, "mcp__kin__semantic_locate");
    assert_eq!(view.tool_uses[1].1, "edit_file");
    assert_eq!(view.tool_results.len(), 2);
    // Each result is joinable to its call, which is how latency is derived.
    assert_eq!(view.tool_uses[0].0, view.tool_results[0].0);
    assert_eq!(view.tool_uses[1].0, view.tool_results[1].0);
    assert!(!view.tool_results[0].2 && !view.tool_results[1].2);
    assert!(view.assistant_text.contains("Let me find it."));

    assert_eq!(view.result["subtype"], "success");
    assert_eq!(view.result["kin_agent"]["exit_code"], 0);
    assert_eq!(view.result["kin_agent"]["tool_calls"], 2);
    assert_eq!(view.result["kin_agent"]["kin_calls"], 1);
    assert_eq!(view.result["kin_agent"]["local_calls"], 1);
    assert_eq!(view.result["kin_agent"]["files_changed"][0], "src/greet.py");
    // Usage is carried through from the endpoint rather than defaulted.
    assert_eq!(view.result["usage"]["input_tokens"], 300);

    // The sidecar carries the envelope and the provenance, joinable on tool_use_id.
    let trace = read_jsonl(&outcome.trace_path);
    let locate = trace
        .iter()
        .find(|row| row["tool"] == "semantic_locate" && row["surface"] == "kin")
        .expect("the Kin call is traced");
    assert_eq!(locate["tool_use_id"], view.tool_uses[0].0);
    assert_eq!(locate["envelope"]["runtime"], "RepoDaemon");
    assert_eq!(locate["envelope"]["semantic_coverage"], 0.91);
    assert_eq!(locate["policy"], "allowed");
    let edit = trace
        .iter()
        .find(|row| row["surface"] == "local" && row["tool"] == "edit_file")
        .expect("the local edit is traced");
    assert_eq!(edit["provenance"]["bracketed"], true);
    assert_eq!(edit["provenance"]["staged"]["verb"], "replace");
    assert_eq!(edit["provenance"]["staged"]["target"], "src/greet.py");
    assert_eq!(edit["provenance"]["staged"]["accepted"], true);
    assert_eq!(
        edit["provenance"]["closed_with"], "kin_transaction_commit",
        "a staged edit is committed, never aborted"
    );
    assert_eq!(edit["provenance"]["closed_cleanly"], true);
    // The stage row is in the sidecar under the verb it actually used.
    let staged_row = trace
        .iter()
        .find(|row| row["tool"] == "kin_transaction_stage")
        .expect("the stage call is traced");
    assert_eq!(staged_row["verb"], "replace");
    assert_eq!(staged_row["target"], "src/greet.py");
    assert_eq!(staged_row["is_error"], false);
    assert!(staged_row["body_bytes"].as_u64().unwrap() > 0);
    // The whole written body stays out of the trace row; the transcript already has it.
    assert!(edit["args"]["replace"]
        .as_str()
        .unwrap()
        .ends_with(" bytes>"));

    let requests = endpoint.requests();
    assert_eq!(requests.len(), 3);
    // The belt reached the model, and the shell never did.
    let sent: Vec<&str> = requests[0]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|spec| spec["function"]["name"].as_str().unwrap())
        .collect();
    assert!(sent.contains(&"mcp__kin__semantic_locate"));
    assert!(sent.contains(&"edit_file"));
    assert!(!sent.iter().any(|name| name.contains("bash")));
    // The observation went back as a tool message keyed on the same id.
    assert_eq!(
        requests[1]["messages"].as_array().unwrap().last().unwrap()["role"],
        "tool"
    );
}

/// A staged edit the daemon refuses to commit must not read to the model as a success.
///
/// The create path has amended its own result since kin#1082. The edit path could not: until
/// an edit could stage, nothing reached this branch, so it incremented `unpublished_changes`
/// and handed the model "Edited `src/dirty.py`: replaced 1 occurrence" with no hint that the
/// transaction aborted. The trace recorded the refusal, which does not help a model that
/// only reads its own tool result and goes on believing the graph has its change.
#[test]
fn a_staged_edit_the_daemon_refuses_tells_the_model_it_did_not_land() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");

    let endpoint = FakeEndpoint::start(vec![
        completion(
            "Fixing it.",
            Some(tool_call(
                "c1",
                "edit_file",
                json!({
                    "path": "src/dirty.py",
                    "find": "return name",
                    "replace": "return name.strip()"
                }),
            )),
        ),
        completion("Fixed.", None),
    ]);
    let base_url = endpoint.base_url.clone();

    let outcome = kin_agent::run(config(&repo, &out, &base_url, mcp_command(&server, &log)))
        .expect("the run completes");

    // The stage was taken and the commit was refused, so the run is downgraded.
    assert_eq!(outcome.status, ExitStatus::ChangesUnpublished);
    assert_eq!(outcome.result["kin_agent"]["unpublished_changes"], 1);

    let calls = mcp_log(&log);
    let staged = calls
        .iter()
        .find(|call| call["tool"] == "kin_transaction_stage")
        .expect("the edit is staged");
    assert_eq!(staged["args"]["operations"][0]["verb"], "replace");

    // Authority is the only writer, so a refusal leaves the working copy exactly as it was.
    // A harness that wrote first stranded the edit on disk here while the graph kept the old
    // text, which is the split FIR-3550 found on a real store.
    assert_eq!(
        std::fs::read_to_string(repo.join("src/dirty.py")).unwrap(),
        "def stale(name):\n    return name\n",
        "a refused edit must leave the file untouched"
    );

    // The refused transaction is released rather than left open. Each refusal would
    // otherwise hold one of the session's unfinished-transaction slots until the session
    // ends, and a model that keeps retrying would be refused a bracket altogether.
    let names: Vec<&str> = calls
        .iter()
        .map(|call| call["tool"].as_str().unwrap())
        .collect();
    let commit_at = names
        .iter()
        .position(|name| *name == "kin_transaction_commit")
        .expect("the edit reached the commit");
    assert_eq!(
        names.get(commit_at + 1),
        Some(&"kin_transaction_abort"),
        "a refused commit must be followed by an abort: {names:?}"
    );
    let trace = read_jsonl(&outcome.trace_path);
    let edit = trace
        .iter()
        .find(|row| row["surface"] == "local" && row["tool"] == "edit_file")
        .expect("the local edit is traced");
    assert_eq!(edit["provenance"]["closed_with"], "kin_transaction_commit");
    assert_eq!(edit["provenance"]["closed_cleanly"], false);
    assert_eq!(
        edit["provenance"]["aborted_after_refusal"]["closed_cleanly"],
        true
    );

    // The assertion this test exists for. The model's own tool result, which is the only
    // thing it reads, has to say the change did not land.
    let records = read_jsonl(&outcome.transcript_path);
    let view = analyze(&records);
    let (_, result, is_error) = view
        .tool_results
        .iter()
        .find(|(id, _, _)| id == &view.tool_uses[0].0)
        .expect("the edit has a result");
    assert!(
        result.contains("did not publish it"),
        "the model must be told its edit did not land, got: {result}"
    );
    assert!(
        result.contains("working copy is not clean"),
        "the model must be told WHY, in the server's own words, got: {result}"
    );
    assert!(
        result.contains("unchanged on disk and in the graph"),
        "the model must be told where things stand, got: {result}"
    );
    assert!(*is_error, "an edit that did not land is a failed call");
}

/// FIR-3550: an in-place edit is published through repository authority before the working
/// copy changes, and the commit is what writes the file.
///
/// Staged after a local write, the edit reached the real daemon holding a working copy that
/// already carried the new bytes, and the commit refused it as drift from the prior tree. So
/// the order is asserted directly, from what the server saw on disk when each call arrived:
/// the old text at the stage, and the old text still at the commit.
#[test]
fn an_in_place_edit_is_published_by_authority_before_the_file_changes() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");
    let original = std::fs::read_to_string(repo.join("src/greet.py")).unwrap();

    let endpoint = FakeEndpoint::start(vec![
        completion(
            "Documenting greet.",
            Some(tool_call(
                "c1",
                "edit_file",
                json!({
                    "path": "src/greet.py",
                    "find": "def greet(name):",
                    "replace": "def greet(name):\n    \"\"\"Return a greeting for name.\"\"\""
                }),
            )),
        ),
        completion("greet carries a docstring.", None),
    ]);
    let base_url = endpoint.base_url.clone();

    let outcome = kin_agent::run(config(&repo, &out, &base_url, mcp_command(&server, &log)))
        .expect("the run completes");
    assert_eq!(outcome.status, ExitStatus::Success, "{:?}", outcome.result);
    assert_eq!(outcome.result["kin_agent"]["unpublished_changes"], 0);

    let calls = mcp_log(&log);
    let stage = calls
        .iter()
        .find(|call| call["tool"] == "kin_transaction_stage")
        .expect("the edit is staged");
    assert_eq!(
        stage["disk"]["src/greet.py"], original,
        "the working copy must still hold the old text when the edit is staged"
    );
    let commit = calls
        .iter()
        .find(|call| call["tool"] == "kin_transaction_commit")
        .expect("the edit is committed");
    assert_eq!(
        commit["disk"]["src/greet.py"], original,
        "the working copy must still hold the old text when the commit arrives, because the \
         commit is what writes it"
    );
    let staged_body = stage["args"]["operations"][0]["body"].as_str().unwrap();
    assert!(
        staged_body.contains("\"\"\"Return a greeting for name.\"\"\""),
        "the staged body carries the edit: {staged_body}"
    );

    // The file holds what the commit published, and the model is told authority wrote it.
    assert_eq!(
        std::fs::read_to_string(repo.join("src/greet.py")).unwrap(),
        staged_body
    );
    let requests = endpoint.requests();
    let observation = requests[1]["messages"].as_array().unwrap().last().unwrap()["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        observation.contains("published it through repository authority"),
        "the model must be told the edit landed: {observation}"
    );
}

/// The end-to-end shape FIR-2586 is about: a new file the model writes is staged as the
/// `create` operation and committed, so the run lands something rather than opening a
/// transaction it never fills.
#[test]
fn a_new_file_is_staged_as_a_create_and_then_committed() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");
    let body = "def farewell(name):\n    return f\"bye {name}\"\n";

    let endpoint = FakeEndpoint::start(vec![
        completion(
            "Writing the new module.",
            Some(tool_call(
                "c1",
                "write_file",
                json!({ "path": "src/farewell.py", "content": body }),
            )),
        ),
        completion("src/farewell.py now holds farewell.", None),
    ]);
    let base_url = endpoint.base_url.clone();

    let outcome = kin_agent::run(config(&repo, &out, &base_url, mcp_command(&server, &log)))
        .expect("the run completes");
    assert_eq!(outcome.status, ExitStatus::Success);

    // The file landed on disk.
    assert_eq!(
        std::fs::read_to_string(repo.join("src/farewell.py")).unwrap(),
        body
    );

    // The write was bracketed, staged, and committed, in that order.
    let calls = mcp_log(&log);
    let names: Vec<&str> = calls
        .iter()
        .map(|call| call["tool"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![
            "kin_session_start",
            "kin_transaction_begin",
            "kin_transaction_stage",
            "kin_transaction_commit",
            "kin_session_end"
        ],
        "a new file must be staged inside the bracket before the commit"
    );

    // The staged operation is the FIR-2417 create shape: a repository-relative target and
    // the full body, carried in the call rather than read off disk by the daemon.
    let stage = calls
        .iter()
        .find(|call| call["tool"] == "kin_transaction_stage")
        .expect("the create is staged");
    assert_eq!(stage["args"]["transaction_id"], "txn-fixture-1");
    assert_eq!(stage["args"]["session_id"], "sess-fixture-1");
    let operations = stage["args"]["operations"].as_array().unwrap();
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0]["verb"], "create");
    assert_eq!(operations[0]["target"], "src/farewell.py");
    assert_eq!(operations[0]["body"], body);
    assert!(operations[0]["description"]
        .as_str()
        .unwrap()
        .contains("src/farewell.py"));

    // The commit carries the daemon's own accepted answer into the trace, so the evidence
    // is what the server said rather than the harness's summary of it.
    let trace = read_jsonl(&outcome.trace_path);
    let write = trace
        .iter()
        .find(|row| row["surface"] == "local" && row["tool"] == "write_file")
        .expect("the local write is traced");
    assert_eq!(write["provenance"]["bracketed"], true);
    assert_eq!(write["provenance"]["staged"]["verb"], "create");
    assert_eq!(write["provenance"]["staged"]["target"], "src/farewell.py");
    assert_eq!(write["provenance"]["staged"]["accepted"], true);
    assert_eq!(write["provenance"]["closed_with"], "kin_transaction_commit");
    assert_eq!(write["provenance"]["closed_cleanly"], true);
    let response = write["provenance"]["response"].as_str().unwrap();
    assert!(
        response.contains("committed"),
        "the commit response must be the daemon's own: {response}"
    );

    // The stage call is traced in its own right, joinable with the transaction.
    let staged = trace
        .iter()
        .find(|row| row["tool"] == "kin_transaction_stage")
        .expect("the stage call is traced");
    assert_eq!(staged["event"], "transaction_stage");
    assert_eq!(staged["transaction_id"], "txn-fixture-1");
    assert_eq!(staged["is_error"], false);
    assert_eq!(staged["body_bytes"], body.len());
}

/// FIR-2624: a created file must be published by repository authority, not written to the
/// working copy ahead of the commit.
///
/// The daemon refuses to publish onto an untracked working-copy path sitting on its exact
/// workspace target, so a harness that writes first turns every commit into a refusal and
/// lands nothing. The scripted server refuses on the same ground, which is what makes this
/// test able to fail: restore the old ordering and the run ends `ChangesUnpublished` with
/// the projection conflict in its trace.
#[test]
fn a_created_file_is_published_by_authority_rather_than_written_before_the_commit() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");
    let body = "def shout(text):\n    return text.upper()\n";

    let endpoint = FakeEndpoint::start(vec![
        completion(
            "Adding the helper.",
            Some(tool_call(
                "c1",
                "write_file",
                json!({ "path": "src/shout.py", "content": body }),
            )),
        ),
        completion("src/shout.py now holds shout.", None),
    ]);
    let base_url = endpoint.base_url.clone();

    let outcome = kin_agent::run(config(&repo, &out, &base_url, mcp_command(&server, &log)))
        .expect("the run completes");

    assert_eq!(outcome.status, ExitStatus::Success);
    assert_eq!(outcome.result["kin_agent"]["unpublished_changes"], 0);
    // The bytes are on disk, and the only writer was the commit.
    assert_eq!(
        std::fs::read_to_string(repo.join("src/shout.py")).unwrap(),
        body
    );

    let calls = mcp_log(&log);
    let names: Vec<&str> = calls
        .iter()
        .map(|call| call["tool"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"kin_transaction_commit"),
        "the create must be committed, not aborted: {names:?}"
    );
    assert!(
        !names.contains(&"kin_transaction_abort"),
        "a create the daemon can publish must never abort: {names:?}"
    );

    let trace = read_jsonl(&outcome.trace_path);
    let write = trace
        .iter()
        .find(|row| row["tool"] == "write_file")
        .expect("the local write is traced");
    assert_eq!(write["provenance"]["bracketed"], true);
    assert_eq!(
        write["provenance"]["closed_with"], "kin_transaction_commit",
        "the bracket must close by committing"
    );
    assert_eq!(
        write["provenance"]["closed_cleanly"], true,
        "the commit must be accepted, not refused on the harness's own file"
    );

    // The model is told publication happened, so it can tell a landed change from a file
    // left sitting on disk.
    let requests = endpoint.requests();
    let observation = requests[1]["messages"].as_array().unwrap().last().unwrap()["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        observation.contains("published it through repository authority"),
        "the model must be told the change landed: {observation}"
    );
}

/// FIR-2625: a run whose change repository authority never published must not report
/// success, and the reason must survive into the trace instead of being spent on the
/// `_kin` envelope.
#[test]
fn a_refused_commit_downgrades_the_run_and_keeps_its_reason_in_the_trace() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");

    // README.md is tracked in the fixture graph, so the scripted server refuses the stage
    // by name, exactly as the daemon does.
    let endpoint = FakeEndpoint::start(vec![
        completion(
            "Rewriting the readme.",
            Some(tool_call(
                "c1",
                "write_file",
                json!({ "path": "README.md", "content": "# again\n" }),
            )),
        ),
        completion("Readme rewritten.", None),
    ]);
    let base_url = endpoint.base_url.clone();

    let outcome = kin_agent::run(config(&repo, &out, &base_url, mcp_command(&server, &log)))
        .expect("the run completes");

    // The model's closing paragraph reads like a success. The run does not.
    assert_eq!(outcome.status, ExitStatus::ChangesUnpublished);
    assert_eq!(outcome.status.code(), 6);
    assert_eq!(outcome.result["subtype"], "changes_unpublished");
    assert_eq!(outcome.result["is_error"], true);
    assert_eq!(outcome.result["kin_agent"]["unpublished_changes"], 1);

    // The reason reaches the trace. The `_kin` envelope alone is longer than the 300
    // character budget, so truncating the raw answer dropped the message entirely.
    let trace = read_jsonl(&outcome.trace_path);
    let staged = trace
        .iter()
        .find(|row| row["tool"] == "kin_transaction_stage")
        .expect("the stage call is traced");
    assert_eq!(staged["is_error"], true);
    let detail = staged["detail"].as_str().unwrap();
    assert!(
        detail.contains("already tracked"),
        "the refusal reason must survive truncation, got: {detail}"
    );
    assert!(
        !detail.contains("envelope_version"),
        "the envelope must not be what the budget was spent on: {detail}"
    );

    // Nothing was written, so the tracked file keeps its text. The model's work comes back
    // in its own tool result rather than as a file the graph does not hold, and the model
    // is told it did not land.
    assert_eq!(
        std::fs::read_to_string(repo.join("README.md")).unwrap(),
        "# fixture\n"
    );
    let requests = endpoint.requests();
    let observation = requests[1]["messages"].as_array().unwrap().last().unwrap()["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        observation.contains("did not publish it"),
        "the model must be told the change did not land: {observation}"
    );
    assert!(
        observation.contains("# again"),
        "the refused content must come back to the model: {observation}"
    );
}

/// FIR-3550, the create half: a `write_file` repository authority refuses at commit leaves
/// no file behind.
///
/// The harness used to write the file locally after the refusal so the model kept its
/// work, which left a file on disk the graph did not hold, the same split a refused edit
/// left. The work now travels back in the tool result, the refused transaction is
/// released, and the path stays absent.
#[test]
fn a_create_authority_refuses_leaves_no_file_and_hands_the_content_back() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");
    let body = "def refused(name):\n    return name\n";

    let endpoint = FakeEndpoint::start(vec![
        completion(
            "Adding the module.",
            Some(tool_call(
                "c1",
                "write_file",
                json!({ "path": "src/refused.py", "content": body }),
            )),
        ),
        completion("src/refused.py is in place.", None),
    ]);
    let base_url = endpoint.base_url.clone();

    let outcome = kin_agent::run(config(&repo, &out, &base_url, mcp_command(&server, &log)))
        .expect("the run completes");
    assert_eq!(outcome.status, ExitStatus::ChangesUnpublished);
    assert_eq!(outcome.result["kin_agent"]["unpublished_changes"], 1);
    assert!(
        !repo.join("src/refused.py").exists(),
        "a refused create must leave no file behind"
    );

    let calls = mcp_log(&log);
    let names: Vec<&str> = calls
        .iter()
        .map(|call| call["tool"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![
            "kin_session_start",
            "kin_transaction_begin",
            "kin_transaction_stage",
            "kin_transaction_commit",
            "kin_transaction_abort",
            "kin_session_end"
        ],
        "a create refused at commit must be released with an abort"
    );

    let requests = endpoint.requests();
    let observation = requests[1]["messages"].as_array().unwrap().last().unwrap()["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        observation.contains("did not publish it"),
        "the model must be told the create did not land: {observation}"
    );
    assert!(
        observation.contains("its directory is not admitted"),
        "the model must be told WHY, in the server's own words: {observation}"
    );
    assert!(
        observation.contains(body),
        "the refused content must come back to the model: {observation}"
    );
}

/// When the session is gone, as after the daemon that held it was stopped and started again,
/// the edit re-opens the session once, begins again under the new one, and lands.
#[test]
fn an_edit_after_the_session_is_gone_reopens_it_and_publishes() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");
    let endpoint = FakeEndpoint::start(vec![
        completion(
            "Fixing it.",
            Some(tool_call(
                "c1",
                "edit_file",
                json!({ "path": "src/stale.py", "find": "return name", "replace": "return name.strip()" }),
            )),
        ),
        completion("Fixed.", None),
    ]);
    let base_url = endpoint.base_url.clone();

    let outcome = kin_agent::run(config(&repo, &out, &base_url, mcp_command(&server, &log)))
        .expect("the run completes");
    assert_eq!(outcome.status, ExitStatus::Success, "{:?}", outcome.result);
    assert_eq!(outcome.result["kin_agent"]["unpublished_changes"], 0);

    let calls = mcp_log(&log);
    let names: Vec<&str> = calls
        .iter()
        .map(|call| call["tool"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![
            "kin_session_start",
            "kin_transaction_begin",
            "kin_session_start",
            "kin_transaction_begin",
            "kin_transaction_stage",
            "kin_transaction_commit",
            "kin_session_end"
        ],
        "a gone session is re-opened once and the begin retried: {names:?}"
    );
    let stage = calls
        .iter()
        .find(|call| call["tool"] == "kin_transaction_stage")
        .expect("the edit is staged");
    assert_eq!(
        stage["args"]["session_id"], "sess-fixture-2",
        "the stage names the re-opened session"
    );
    assert_eq!(
        std::fs::read_to_string(repo.join("src/stale.py")).unwrap(),
        "def later(name):\n    return name.strip()\n"
    );
}

/// When Kin is attached but no transaction opens, the edit writes nothing and the model is
/// told why, in the server's own words with the envelope stripped.
///
/// The harness used to fall back to a local write and report "Edited", which is how a real
/// run left ten lines on disk that repository authority never saw.
#[test]
fn an_edit_kin_cannot_open_a_transaction_for_writes_nothing_and_says_why() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");
    let endpoint = FakeEndpoint::start(vec![
        completion(
            "Fixing it.",
            Some(tool_call(
                "c1",
                "edit_file",
                json!({ "path": "src/nobegin.py", "find": "return name", "replace": "return name.strip()" }),
            )),
        ),
        completion("Fixed.", None),
    ]);
    let base_url = endpoint.base_url.clone();

    let outcome = kin_agent::run(config(&repo, &out, &base_url, mcp_command(&server, &log)))
        .expect("the run completes");
    assert_eq!(outcome.status, ExitStatus::ChangesUnpublished);
    assert_eq!(outcome.result["kin_agent"]["unpublished_changes"], 1);
    assert_eq!(
        std::fs::read_to_string(repo.join("src/nobegin.py")).unwrap(),
        "def never(name):\n    return name\n",
        "nothing may be written without a transaction"
    );

    let calls = mcp_log(&log);
    let names: Vec<&str> = calls
        .iter()
        .map(|call| call["tool"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![
            "kin_session_start",
            "kin_transaction_begin",
            "kin_session_start",
            "kin_transaction_begin",
            "kin_session_end"
        ],
        "begin is retried once and nothing is staged: {names:?}"
    );

    // The refusal's own words reach the trace, not the envelope that comes first.
    let trace = read_jsonl(&outcome.trace_path);
    let begin = trace
        .iter()
        .rev()
        .find(|row| row["tool"] == "kin_transaction_begin")
        .expect("the refused begin is traced");
    let detail = begin["detail"].as_str().unwrap();
    assert!(detail.contains("Session not found"), "{detail}");
    assert!(!detail.contains("envelope_version"), "{detail}");

    let requests = endpoint.requests();
    let observation = requests[1]["messages"].as_array().unwrap().last().unwrap()["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        observation.contains("was not changed")
            && observation.contains("Session not found")
            && observation.contains("unchanged on disk and in the graph"),
        "the model must be told nothing changed and why: {observation}"
    );
}

/// A `write_file` over a path the graph already tracks is refused by repository authority
/// rather than by the harness looking at the disk, and the refusal aborts the transaction.
#[test]
fn a_write_over_a_tracked_path_is_refused_by_the_graph_and_aborts() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");

    let endpoint = FakeEndpoint::start(vec![
        completion(
            "Rewriting the readme.",
            Some(tool_call(
                "c1",
                "write_file",
                json!({ "path": "README.md", "content": "# rewritten\n" }),
            )),
        ),
        completion("README.md rewritten.", None),
    ]);
    let base_url = endpoint.base_url.clone();

    let outcome = kin_agent::run(config(&repo, &out, &base_url, mcp_command(&server, &log)))
        .expect("the run completes");
    // Nothing was published, so the run does not get to call itself a success, and nothing
    // was written: the tracked file keeps its text and the model's content comes back in
    // its tool result.
    assert_eq!(outcome.status, ExitStatus::ChangesUnpublished);
    assert_eq!(outcome.result["kin_agent"]["unpublished_changes"], 1);
    assert_eq!(
        std::fs::read_to_string(repo.join("README.md")).unwrap(),
        "# fixture\n"
    );

    // Repository authority refuses the create by name, so the transaction aborts rather
    // than committing, and the harness never claims a provenance it did not get.
    let calls = mcp_log(&log);
    let names: Vec<&str> = calls
        .iter()
        .map(|call| call["tool"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![
            "kin_session_start",
            "kin_transaction_begin",
            "kin_transaction_stage",
            "kin_transaction_abort",
            "kin_session_end"
        ],
        "a refused stage must abort rather than commit an empty transaction"
    );

    let trace = read_jsonl(&outcome.trace_path);
    let write = trace
        .iter()
        .find(|row| row["surface"] == "local" && row["tool"] == "write_file")
        .expect("the local write is traced");
    assert_eq!(write["provenance"]["bracketed"], true);
    assert_eq!(write["provenance"]["staged"]["accepted"], false);
    assert_eq!(write["provenance"]["closed_with"], "kin_transaction_abort");
    let detail = write["provenance"]["staged"]["detail"].as_str().unwrap();
    assert!(
        detail.contains("already tracked"),
        "the graph's refusal must survive into the provenance: {detail}"
    );
}

/// Two repositories, two servers, two graphs. Each write is staged and committed into the
/// graph of the repository that owns its path, and a Kin call reaches only the server whose
/// prefix the model used.
#[test]
fn two_repositories_each_get_their_own_server_session_and_commits() {
    let dir = tempfile::tempdir().unwrap();
    let alpha = fixture_repo_named(dir.path(), "alpha");
    let beta = fixture_repo_named(dir.path(), "beta");
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let alpha_log = dir.path().join("alpha-calls.jsonl");
    let beta_log = dir.path().join("beta-calls.jsonl");
    let beta_file = beta.join("src/new_b.py");

    let endpoint = FakeEndpoint::start(vec![
        completion(
            "Looking in beta.",
            Some(tool_call(
                "c1",
                "mcp__kin_beta__semantic_locate",
                json!({ "query": "greet" }),
            )),
        ),
        completion(
            "Writing into the primary.",
            Some(tool_call(
                "c2",
                "write_file",
                json!({ "path": "src/new_a.py", "content": "a = 1\n" }),
            )),
        ),
        completion(
            "Writing into beta.",
            Some(tool_call(
                "c3",
                "write_file",
                json!({ "path": beta_file.display().to_string(), "content": "b = 2\n" }),
            )),
        ),
        completion("Both files are written.", None),
    ]);
    let base_url = endpoint.base_url.clone();

    let mut cfg = config(&alpha, &out, &base_url, mcp_command(&server, &alpha_log));
    cfg.extra_servers = vec![kin_agent::ServerSpec {
        repo: beta.clone(),
        mcp_command: mcp_command(&server, &beta_log),
    }];

    let outcome = kin_agent::run(cfg).expect("the run completes");
    assert_eq!(outcome.status, ExitStatus::Success);

    // Both files landed, each in its own tree.
    assert_eq!(
        std::fs::read_to_string(alpha.join("src/new_a.py")).unwrap(),
        "a = 1\n"
    );
    assert!(
        beta_file.exists(),
        "the absolute-path write must land in the second repository at {}",
        beta_file.display()
    );
    assert_eq!(std::fs::read_to_string(&beta_file).unwrap(), "b = 2\n");

    // The primary server saw its own session, its own transaction, and no beta work.
    let alpha_names: Vec<String> = mcp_log(&alpha_log)
        .iter()
        .map(|call| call["tool"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        alpha_names,
        vec![
            "kin_session_start",
            "kin_transaction_begin",
            "kin_transaction_stage",
            "kin_transaction_commit",
            "kin_session_end"
        ],
        "the primary must carry only its own relative-path write"
    );

    // The second server saw the model's Kin call and its own absolute-path write.
    let beta_calls = mcp_log(&beta_log);
    let beta_names: Vec<String> = beta_calls
        .iter()
        .map(|call| call["tool"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        beta_names,
        vec![
            "kin_session_start",
            "semantic_locate",
            "kin_transaction_begin",
            "kin_transaction_stage",
            "kin_transaction_commit",
            "kin_session_end"
        ],
        "the prefixed Kin call and the absolute-path write must both reach beta"
    );

    // Each staged create names the path relative to its OWN repository, never the other's.
    let staged_target = |calls: &[Value]| -> String {
        calls
            .iter()
            .find(|call| call["tool"] == "kin_transaction_stage")
            .expect("a create is staged")["args"]["operations"][0]["target"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(staged_target(&mcp_log(&alpha_log)), "src/new_a.py");
    assert_eq!(staged_target(&beta_calls), "src/new_b.py");

    // The trace attributes every call to the server that served it.
    let trace = read_jsonl(&outcome.trace_path);
    let locate = trace
        .iter()
        .find(|row| row["tool"] == "semantic_locate")
        .expect("the Kin call is traced");
    assert_eq!(locate["server"], "kin_beta");
    let writes: Vec<&Value> = trace
        .iter()
        .filter(|row| row["surface"] == "local" && row["tool"] == "write_file")
        .collect();
    assert_eq!(writes.len(), 2);
    assert_eq!(writes[0]["server"], "kin_alpha");
    assert_eq!(writes[0]["repo"], alpha.display().to_string());
    assert_eq!(writes[1]["server"], "kin_beta");
    assert_eq!(writes[1]["repo"], beta.display().to_string());
    for write in &writes {
        assert_eq!(write["provenance"]["staged"]["accepted"], true);
        assert_eq!(write["provenance"]["closed_with"], "kin_transaction_commit");
    }

    // The belt the model was given namespaces each repository's tools, and carries no
    // ambiguous bare Kin name.
    let requests = endpoint.requests();
    let sent: Vec<String> = requests[0]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|spec| spec["function"]["name"].as_str().unwrap().to_string())
        .collect();
    assert!(sent
        .iter()
        .any(|name| name == "mcp__kin_alpha__semantic_locate"));
    assert!(sent
        .iter()
        .any(|name| name == "mcp__kin_beta__semantic_locate"));
    assert!(
        !sent.iter().any(|name| name == "mcp__kin__semantic_locate"),
        "a multi-repository run must not expose an unqualified Kin tool: {sent:?}"
    );

    // Files changed are recorded absolutely, because the same relative path exists in both.
    let changed: Vec<String> = outcome.result["kin_agent"]["files_changed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect();
    assert!(changed
        .iter()
        .any(|path| path.ends_with("alpha/src/new_a.py")));
    assert!(changed
        .iter()
        .any(|path| path.ends_with("beta/src/new_b.py")));
}

/// A path in no attached repository runs nothing at all, and the refusal names the roots.
#[test]
fn a_path_outside_every_attached_repository_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let alpha = fixture_repo_named(dir.path(), "alpha");
    let beta = fixture_repo_named(dir.path(), "beta");
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let alpha_log = dir.path().join("alpha-calls.jsonl");
    let beta_log = dir.path().join("beta-calls.jsonl");
    let stray = dir.path().join("elsewhere/escaped.py");

    let endpoint = FakeEndpoint::start(vec![
        completion(
            "Writing outside.",
            Some(tool_call(
                "c1",
                "write_file",
                json!({ "path": stray.display().to_string(), "content": "x = 1\n" }),
            )),
        ),
        completion("I could not write there.", None),
    ]);
    let base_url = endpoint.base_url.clone();

    let mut cfg = config(&alpha, &out, &base_url, mcp_command(&server, &alpha_log));
    cfg.extra_servers = vec![kin_agent::ServerSpec {
        repo: beta.clone(),
        mcp_command: mcp_command(&server, &beta_log),
    }];

    let outcome = kin_agent::run(cfg).expect("the run completes");
    assert_eq!(outcome.status, ExitStatus::Success);
    assert!(
        !stray.exists(),
        "nothing may be written outside the repositories"
    );

    // Neither server opened a transaction for it.
    for log in [&alpha_log, &beta_log] {
        let names: Vec<String> = mcp_log(log)
            .iter()
            .map(|call| call["tool"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["kin_session_start", "kin_session_end"]);
    }

    let trace = read_jsonl(&outcome.trace_path);
    let write = trace
        .iter()
        .find(|row| row["surface"] == "local" && row["tool"] == "write_file")
        .expect("the refused write is traced");
    assert_eq!(write["is_error"], true);
    let problem = write["problem"].as_str().unwrap();
    assert!(
        problem.contains("outside every repository")
            && problem.contains(&alpha.display().to_string())
            && problem.contains(&beta.display().to_string()),
        "the refusal must name every root: {problem}"
    );
}

#[test]
fn an_untrusted_absence_is_handed_to_the_model_as_unknown_with_the_named_gap() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");

    let endpoint = FakeEndpoint::start(vec![
        completion(
            "",
            Some(tool_call(
                "c1",
                "mcp__kin__semantic_locate",
                json!({ "query": "nothing at all" }),
            )),
        ),
        completion(
            "I do not know; the graph does not index markdown bodies.",
            None,
        ),
    ]);
    let base_url = endpoint.base_url.clone();

    let outcome = kin_agent::run(config(&repo, &out, &base_url, mcp_command(&server, &log)))
        .expect("the run completes");
    assert_eq!(outcome.status, ExitStatus::Success);

    let records = read_jsonl(&outcome.transcript_path);
    let view = analyze(&records);
    let (_, observation, _) = &view.tool_results[0];
    assert!(
        observation.contains("CANNOT be trusted"),
        "the model must be told the absence is untrusted: {observation}"
    );
    assert!(
        observation.contains("markdown bodies are not indexed"),
        "the named gap must be handed through: {observation}"
    );
    assert!(
        observation.contains("unknown"),
        "the model must be told to treat it as unknown: {observation}"
    );
    assert_eq!(view.result["kin_agent"]["unsafe_absence_events"], 1);

    let trace = read_jsonl(&outcome.trace_path);
    let row = trace
        .iter()
        .find(|row| row["tool"] == "semantic_locate")
        .unwrap();
    assert_eq!(row["negative"]["safe_to_conclude_absent"], false);
    assert_eq!(
        row["negative"]["limiting_factor"],
        "coverage_partial: markdown bodies are not indexed"
    );
}

#[test]
fn an_off_belt_tool_is_refused_and_never_runs() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");
    let canary = repo.join("canary.txt");

    let endpoint = FakeEndpoint::start(vec![
        completion(
            "",
            Some(tool_call(
                "c1",
                "bash",
                json!({ "command": format!("touch {}", canary.display()) }),
            )),
        ),
        completion("There is no shell, so I used Kin instead.", None),
    ]);
    let base_url = endpoint.base_url.clone();

    let outcome = kin_agent::run(config(&repo, &out, &base_url, mcp_command(&server, &log)))
        .expect("the run completes");

    assert!(
        !canary.exists(),
        "a refused shell call must not have run anything"
    );
    let view = analyze(&read_jsonl(&outcome.transcript_path));
    let (_, observation, is_error) = &view.tool_results[0];
    assert!(*is_error, "a refusal is an error result");
    assert!(
        observation.contains("no shell"),
        "the refusal must say why: {observation}"
    );
    assert_eq!(view.result["kin_agent"]["refused_calls"], 1);
    // Nothing reached the graph server except the session bracket.
    let names: Vec<String> = mcp_log(&log)
        .iter()
        .map(|call| call["tool"].as_str().unwrap().to_string())
        .collect();
    assert!(
        !names.iter().any(|name| name == "bash"),
        "the refused call must not reach Kin: {names:?}"
    );
}

#[test]
fn malformed_arguments_get_one_repair_turn_and_the_call_does_not_run() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");

    let endpoint = FakeEndpoint::start(vec![
        // A missing required argument, which is the failure small local models actually
        // produce, rather than an invented one.
        completion(
            "",
            Some(tool_call("c1", "mcp__kin__semantic_locate", json!({}))),
        ),
        completion(
            "",
            Some(tool_call(
                "c2",
                "mcp__kin__semantic_locate",
                json!({ "query": "greet" }),
            )),
        ),
        completion("Found it.", None),
    ]);
    let base_url = endpoint.base_url.clone();

    let outcome = kin_agent::run(config(&repo, &out, &base_url, mcp_command(&server, &log)))
        .expect("the run completes");

    let view = analyze(&read_jsonl(&outcome.transcript_path));
    let (_, first, is_error) = &view.tool_results[0];
    assert!(*is_error);
    assert!(
        first.contains("`query`") && first.contains("was missing"),
        "the repair must name the field: {first}"
    );
    assert_eq!(view.result["kin_agent"]["repairs"], 1);
    // The bad call never reached the graph; the corrected one did.
    let names: Vec<String> = mcp_log(&log)
        .iter()
        .map(|call| call["tool"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        names
            .iter()
            .filter(|name| *name == "semantic_locate")
            .count(),
        1,
        "only the corrected call runs: {names:?}"
    );
}

#[test]
fn the_tool_call_cap_forces_a_tool_free_final_answer_and_exits_two() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");

    let mut script = Vec::new();
    for index in 0..3 {
        script.push(completion(
            "",
            Some(tool_call(
                &format!("c{index}"),
                "mcp__kin__semantic_locate",
                json!({ "query": "greet" }),
            )),
        ));
    }
    script.push(completion(
        "I ran out of budget; greet is in src/greet.py.",
        None,
    ));
    let endpoint = FakeEndpoint::start(script);
    let base_url = endpoint.base_url.clone();

    let mut cfg = config(&repo, &out, &base_url, mcp_command(&server, &log));
    cfg.max_tool_calls = 3;
    let outcome = kin_agent::run(cfg).expect("the run completes");

    assert_eq!(outcome.status, ExitStatus::CapReached);
    assert_eq!(outcome.status.code(), 2);
    assert_eq!(
        outcome.final_text,
        "I ran out of budget; greet is in src/greet.py."
    );
    let view = analyze(&read_jsonl(&outcome.transcript_path));
    assert_eq!(view.result["subtype"], "cap_reached");
    assert_eq!(view.result["kin_agent"]["stop_reason"], "tool_call_cap");
    assert_eq!(view.result["kin_agent"]["tool_calls"], 3);
    // The forced turn was asked with nothing to call.
    let requests = endpoint.requests();
    let last = requests.last().unwrap();
    assert!(
        last.get("tools").is_none(),
        "the forced final turn must offer no tools"
    );
}

/// A batch that crosses the tool-call budget runs only what the budget allows. The rest are
/// answered as not run, so the conversation stays well formed, and the run ends on the cap.
#[test]
fn a_batch_that_crosses_the_tool_call_budget_runs_only_what_the_budget_allows() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");

    let three = json!(["a", "b", "c"]
        .iter()
        .enumerate()
        .map(|(index, query)| json!({
            "id": format!("c{index}"),
            "type": "function",
            "function": {
                "name": "mcp__kin__semantic_locate",
                "arguments": json!({ "query": query }).to_string(),
            }
        }))
        .collect::<Vec<_>>());
    let endpoint = FakeEndpoint::start(vec![
        completion("", Some(three)),
        completion("Two lookups were enough.", None),
    ]);
    let base_url = endpoint.base_url.clone();

    let mut cfg = config(&repo, &out, &base_url, mcp_command(&server, &log));
    cfg.max_tool_calls = 2;
    let outcome = kin_agent::run(cfg).expect("the run completes");

    assert_eq!(outcome.status, ExitStatus::CapReached);
    let locates = mcp_log(&log)
        .iter()
        .filter(|call| call["tool"] == "semantic_locate")
        .count();
    assert_eq!(locates, 2, "only the calls inside the budget may reach Kin");

    let view = analyze(&read_jsonl(&outcome.transcript_path));
    assert_eq!(
        view.tool_results.len(),
        3,
        "every call in the batch is answered"
    );
    let (_, skipped, is_error) = &view.tool_results[2];
    assert!(*is_error, "a call that never ran is not a result");
    assert!(
        skipped.contains("was not run") && skipped.contains("budget of 2 tool calls"),
        "the model must be told why the call did not run: {skipped}"
    );
    assert_eq!(view.result["kin_agent"]["tool_calls"], 2);
    assert_eq!(view.result["kin_agent"]["skipped_calls"], 1);
    assert_eq!(view.result["kin_agent"]["stop_reason"], "tool_call_cap");
    let requests = endpoint.requests();
    assert!(
        requests.last().unwrap().get("tools").is_none(),
        "the forced final turn must offer no tools"
    );
}

/// A result larger than the per-result ceiling reaches the model cut, with a note that names
/// its size, the ceiling and the arguments that page it, and the transcript records what the
/// model saw.
#[test]
fn an_oversized_result_is_cut_to_the_ceiling_with_a_note_naming_size_ceiling_and_paging() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");

    let endpoint = FakeEndpoint::start(vec![
        completion(
            "Listing everything.",
            Some(tool_call(
                "c1",
                "mcp__kin__kin_artifact_list",
                json!({ "limit": 1000 }),
            )),
        ),
        completion("There are many artifacts.", None),
    ]);
    let base_url = endpoint.base_url.clone();

    let mut cfg = config(&repo, &out, &base_url, mcp_command(&server, &log));
    cfg.max_result_bytes = Some(8_192);
    let outcome = kin_agent::run(cfg).expect("the run completes");
    assert_eq!(outcome.status, ExitStatus::Success);

    let trace = read_jsonl(&outcome.trace_path);
    let row = trace
        .iter()
        .find(|row| row["tool"] == "kin_artifact_list" && row["surface"] == "kin")
        .expect("the Kin call is traced");
    let result_bytes = row["result_bytes"].as_u64().unwrap();
    let shown_bytes = row["shown_bytes"].as_u64().unwrap();
    assert!(
        result_bytes > 100_000,
        "the fixture listing must be large: {result_bytes}"
    );
    assert!(
        shown_bytes <= 8_192,
        "no more than the ceiling may be shown: {shown_bytes}"
    );

    // What the model received is what the next request carried.
    let requests = endpoint.requests();
    let observation = requests[1]["messages"].as_array().unwrap().last().unwrap()["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        observation.len() < 8_192 + 1_024,
        "the observation must be the cut text, not {} bytes",
        observation.len()
    );
    let tail = &observation[observation.len().saturating_sub(700)..];
    for needle in [
        format!("It is {result_bytes} bytes"),
        "at most 8192 bytes".to_string(),
        "smaller `limit`".to_string(),
        "with `offset`".to_string(),
    ] {
        assert!(
            observation.contains(&needle),
            "the note must say {needle:?}: {tail}"
        );
    }

    let view = analyze(&read_jsonl(&outcome.transcript_path));
    assert_eq!(
        view.tool_results[0].1, observation,
        "the transcript records what the model saw, not what the tool produced"
    );
    assert_eq!(view.result["kin_agent"]["clipped_results"], 1);
    assert_eq!(view.result["kin_agent"]["max_result_bytes"], 8_192);
}

/// A result the conversation cannot hold is withheld with a note, and the run asks for its
/// final answer with nothing to call instead of sending a request larger than the window.
#[test]
fn a_result_the_window_cannot_hold_is_withheld_and_the_run_ends_on_its_context_budget() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");

    // The endpoint counts 3,020 tokens after the first turn, so in a 4,096-token window with
    // 1,024 kept for the answer no listing of any size fits.
    let endpoint = FakeEndpoint::start(vec![
        completion_with_usage(
            "Listing.",
            Some(tool_call(
                "c1",
                "mcp__kin__kin_artifact_list",
                json!({ "limit": 50 }),
            )),
            3_000,
            20,
        ),
        completion("Answering from what I have.", None),
    ]);
    let base_url = endpoint.base_url.clone();

    let mut cfg = config(&repo, &out, &base_url, mcp_command(&server, &log));
    cfg.context = kin_agent::ContextWindow {
        tokens: 4_096,
        source: kin_agent::ContextSource::Flag,
    };
    let outcome = kin_agent::run(cfg).expect("the run completes");

    assert_eq!(outcome.status, ExitStatus::ContextBudget);
    assert_eq!(outcome.status.code(), 7);
    assert_eq!(outcome.final_text, "Answering from what I have.");

    let view = analyze(&read_jsonl(&outcome.transcript_path));
    assert_eq!(view.result["subtype"], "context_budget");
    assert_eq!(view.result["kin_agent"]["stop_reason"], "context_budget");
    let detail = view.result["kin_agent"]["stop_detail"].as_str().unwrap();
    assert!(
        detail.contains("withheld") && detail.contains("4096-token window"),
        "the stop must say what was withheld and against which window: {detail}"
    );
    assert_eq!(view.result["kin_agent"]["withheld_results"], 1);
    assert_eq!(view.result["kin_agent"]["context"]["window_tokens"], 4_096);
    assert_eq!(
        view.result["kin_agent"]["context"]["anchored_on_endpoint_count"],
        true
    );

    let requests = endpoint.requests();
    assert_eq!(requests.len(), 2);
    let last = &requests[1];
    assert!(
        last.get("tools").is_none(),
        "the final request offers nothing to call"
    );
    let tool_message = last["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["role"] == "tool")
        .expect("the withheld call is still answered");
    let content = tool_message["content"].as_str().unwrap();
    assert!(content.contains("was not sent"), "{content}");
    assert!(
        !content.contains("path_label"),
        "no withheld row may reach the model: {content}"
    );
}

/// A window too small for even the first request stops the run before anything is sent,
/// and says how many tokens that request needs.
#[test]
fn a_window_too_small_for_the_first_request_stops_before_anything_is_sent() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");

    let endpoint = FakeEndpoint::start(Vec::new());
    let base_url = endpoint.base_url.clone();

    let mut cfg = config(&repo, &out, &base_url, mcp_command(&server, &log));
    cfg.context = kin_agent::ContextWindow {
        tokens: 1_100,
        source: kin_agent::ContextSource::Default,
    };
    let outcome = kin_agent::run(cfg).expect("the run completes");

    assert_eq!(outcome.status, ExitStatus::ContextBudget);
    let detail = outcome.result["kin_agent"]["stop_detail"].as_str().unwrap();
    assert!(
        detail.contains("the first request needs about") && detail.contains("(default)"),
        "the stop must say the first request does not fit, and whose window it was: {detail}"
    );
    assert!(
        endpoint.requests().is_empty(),
        "nothing may be sent that cannot fit the window"
    );
}

/// An endpoint slower than the run's deadline is abandoned at the deadline, and the run says
/// so, rather than holding the run for a full request timeout.
#[test]
fn a_slow_endpoint_is_abandoned_at_the_deadline_and_the_run_says_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");

    // It answers, but only after the run's deadline and well inside its request timeout, the
    // way a local model re-reading a long prompt does.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            std::thread::sleep(Duration::from_secs(15));
            let _ = serve_one(stream, &completion("Too late.", None));
        }
    });

    let mut cfg = config(
        &repo,
        &out,
        &format!("http://127.0.0.1:{port}/v1"),
        mcp_command(&server, &log),
    );
    cfg.deadline = Duration::from_secs(2);
    let began = std::time::Instant::now();
    let outcome = kin_agent::run(cfg).expect("the run returns");
    let elapsed = began.elapsed();

    assert_eq!(outcome.status, ExitStatus::Deadline);
    assert!(
        elapsed < Duration::from_secs(10),
        "the wait must end at the deadline, not after {elapsed:?}"
    );
    let view = analyze(&read_jsonl(&outcome.transcript_path));
    assert_eq!(view.result["subtype"], "deadline");
    assert_eq!(view.result["kin_agent"]["stop_reason"], "deadline");
    let detail = view.result["kin_agent"]["stop_detail"].as_str().unwrap();
    assert!(
        detail.contains("2 s deadline") && detail.contains("on the endpoint"),
        "the stop must say the deadline cut an endpoint wait: {detail}"
    );
}

/// A model turn longer than the session's idle window does not cost the run its session. The
/// runner heartbeats at a third of the window the session reply named while the request is
/// in flight, and only then, so the Kin call after the long turn is still served.
#[test]
fn a_model_turn_longer_than_the_idle_window_keeps_the_session_alive() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");

    // The scripted session is reaped after two idle seconds, and the second turn takes five.
    let window_secs = 2u64;
    let (base_url, endpoint) = start_paced_endpoint(vec![
        (
            Duration::ZERO,
            completion(
                "Let me look.",
                Some(tool_call(
                    "c1",
                    "mcp__kin__semantic_locate",
                    json!({ "query": "greet" }),
                )),
            ),
        ),
        (
            Duration::from_secs(5),
            completion(
                "Reading it.",
                Some(tool_call(
                    "c2",
                    "mcp__kin__get_entity_source",
                    json!({ "entity": "greet" }),
                )),
            ),
        ),
        (
            Duration::ZERO,
            completion("greet returns a greeting.", None),
        ),
    ]);
    let mut command = mcp_command(&server, &log);
    command.push(window_secs.to_string());
    let outcome = kin_agent::run(config(&repo, &out, &base_url, command)).expect("the run returns");
    let in_flight = endpoint.join().expect("endpoint thread");

    assert_eq!(outcome.status, ExitStatus::Success);
    let calls = mcp_log(&log);
    let tools: Vec<&str> = calls
        .iter()
        .map(|call| call["tool"].as_str().unwrap())
        .collect();
    assert!(
        calls.iter().all(|call| call["reaped"] == json!(false)),
        "no call may find the session reaped: {tools:?}"
    );
    let view = analyze(&read_jsonl(&outcome.transcript_path));
    let read_id = view
        .tool_uses
        .iter()
        .find(|(_, name, _)| name == "mcp__kin__get_entity_source")
        .map(|(id, _, _)| id.clone())
        .expect("the model asked for the source after the long turn");
    let (_, _, read_failed) = view
        .tool_results
        .iter()
        .find(|(id, _, _)| *id == read_id)
        .expect("the read has a result");
    assert!(
        !read_failed,
        "the Kin call after the long turn must be served"
    );

    let locate = tools
        .iter()
        .position(|tool| *tool == "semantic_locate")
        .unwrap();
    let read = tools
        .iter()
        .position(|tool| *tool == "get_entity_source")
        .unwrap();
    let inside = calls[locate..read]
        .iter()
        .filter(|call| call["tool"] == "kin_session_heartbeat")
        .count();
    assert!(
        inside >= 3,
        "a five-second turn against a two-second window needs heartbeats inside it: {tools:?}"
    );
    let beats: Vec<&Value> = calls
        .iter()
        .filter(|call| call["tool"] == "kin_session_heartbeat")
        .collect();
    for beat in &beats {
        assert_eq!(beat["args"]["session_id"], "sess-fixture-1");
        let at = beat["wall"].as_f64().unwrap();
        assert!(
            in_flight
                .iter()
                .any(|(arrived, answered)| *arrived <= at && at <= answered + 0.25),
            "a heartbeat at {at} was sent while no request was in flight: {in_flight:?}"
        );
    }
    let gaps: Vec<f64> = calls
        .windows(2)
        .map(|pair| pair[1]["wall"].as_f64().unwrap() - pair[0]["wall"].as_f64().unwrap())
        .collect();
    assert!(
        gaps.iter().all(|gap| *gap < window_secs as f64),
        "no idle gap may reach the window: {gaps:?}"
    );
    assert_eq!(
        view.result["kin_agent"]["session_heartbeats"].as_u64(),
        Some(beats.len() as u64),
        "the result record counts every heartbeat"
    );
}

/// The window a run budgets for is the one LM Studio reports for the LOADED model, read off
/// its own API when the compatible model list names none, and never the model's maximum.
#[test]
fn the_context_window_is_discovered_from_lm_studio_s_own_api() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let routes: Vec<(String, Value)> = vec![
        (
            "/v1/models".to_string(),
            json!({ "object": "list", "data": [{ "id": "qwen/qwen3.8-27b", "object": "model" }] }),
        ),
        (
            "/api/v1/models".to_string(),
            json!({ "models": [{
                "key": "qwen/qwen3.8-27b",
                "max_context_length": 262144,
                "loaded_instances": [
                    { "id": "qwen/qwen3.8-27b", "config": { "context_length": 131072 } }
                ]
            }]}),
        ),
    ];
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_by_server = seen.clone();
    std::thread::spawn(move || {
        for _ in 0..3 {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            serve_route(stream, &routes, &seen_by_server);
        }
    });

    let provider = kin_agent::Provider::new(ProviderConfig {
        base_url: format!("http://127.0.0.1:{port}/v1"),
        model: "qwen/qwen3.8-27b".into(),
        api_key: None,
        temperature: None,
        request_timeout: Duration::from_secs(5),
    })
    .unwrap();
    assert_eq!(provider.discover_context_window(), Some(131_072));
    assert_eq!(
        *seen.lock().unwrap(),
        vec!["/v1/models".to_string(), "/api/v1/models".to_string()],
        "the compatible list is asked first and the loaded window ends the search"
    );
}

#[test]
fn a_dead_endpoint_exits_four_and_still_closes_the_transcript() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");
    let server = write_fake_mcp_server(dir.path());
    let log = dir.path().join("mcp-calls.jsonl");

    // A port nothing is listening on.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let outcome = kin_agent::run(config(
        &repo,
        &out,
        &format!("http://127.0.0.1:{port}/v1"),
        mcp_command(&server, &log),
    ))
    .expect("the run returns rather than panicking");

    assert_eq!(outcome.status, ExitStatus::EndpointError);
    assert_eq!(outcome.status.code(), 4);
    let view = analyze(&read_jsonl(&outcome.transcript_path));
    assert_eq!(view.result["subtype"], "endpoint_error");
    assert_eq!(view.result["is_error"], true);
}

#[test]
fn a_missing_mcp_server_exits_five_and_says_kin_never_attached() {
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");

    let endpoint = FakeEndpoint::start(vec![completion("unreachable", None)]);
    let base_url = endpoint.base_url.clone();
    let outcome = kin_agent::run(config(
        &repo,
        &out,
        &base_url,
        vec!["kin-agent-no-such-binary".to_string()],
    ))
    .expect("the run returns rather than panicking");

    assert_eq!(outcome.status, ExitStatus::McpError);
    assert_eq!(outcome.status.code(), 5);
    let view = analyze(&read_jsonl(&outcome.transcript_path));
    assert_eq!(view.init["mcp_servers"][0]["status"], "failed");
    assert!(
        !view.init["mcp_server_errors"]
            .as_array()
            .unwrap()
            .is_empty(),
        "a run where Kin never attached must be loud"
    );
    assert_eq!(view.result["subtype"], "mcp_error");
}

/// The same loop against a real `kin mcp start` on a two-file fixture repository.
///
/// Ignored by default because it builds a real graph and starts a real daemon, which the
/// default suite must never trigger. Run it with the binary named:
///
/// ```text
/// KIN_AGENT_TEST_KIN_BIN=/path/to/kin cargo test -p kin-agent -- --ignored
/// ```
#[test]
#[ignore = "starts a real daemon and builds a real graph"]
fn the_loop_drives_a_real_kin_mcp_server() {
    let binary = std::env::var("KIN_AGENT_TEST_KIN_BIN").expect(
        "KIN_AGENT_TEST_KIN_BIN must name the kin binary; the test refuses to pass without one",
    );
    let dir = tempfile::tempdir().unwrap();
    let repo = fixture_repo(dir.path());
    let out = dir.path().join("out");

    let init = std::process::Command::new(&binary)
        .args(["init"])
        .current_dir(&repo)
        .output()
        .expect("kin init runs");
    assert!(
        init.status.success(),
        "kin init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let endpoint = FakeEndpoint::start(vec![
        completion(
            "",
            Some(tool_call(
                "c1",
                "mcp__kin__semantic_locate",
                json!({ "query": "greet" }),
            )),
        ),
        completion("greet is defined in src/greet.py.", None),
    ]);
    let base_url = endpoint.base_url.clone();

    let mut cfg = config(
        &repo,
        &out,
        &base_url,
        vec![
            binary,
            "mcp".into(),
            "start".into(),
            "--repo".into(),
            repo.display().to_string(),
        ],
    );
    cfg.mcp_timeout = Duration::from_secs(300);
    cfg.deadline = Duration::from_secs(600);
    let outcome = kin_agent::run(cfg).expect("the run completes");

    assert_eq!(outcome.status, ExitStatus::Success, "{:?}", outcome.result);
    let view = analyze(&read_jsonl(&outcome.transcript_path));
    assert_eq!(view.init["mcp_servers"][0]["status"], "connected");
    assert_eq!(view.result["kin_agent"]["kin_calls"], 1);
    // The real server's envelope reached the sidecar, which is the whole point of
    // speaking MCP rather than a translated CLI bridge.
    let trace = read_jsonl(&outcome.trace_path);
    let row = trace
        .iter()
        .find(|row| row["tool"] == "semantic_locate")
        .expect("the Kin call is traced");
    assert!(
        row["envelope"].is_object(),
        "the real server must carry a _kin envelope: {row}"
    );
}
