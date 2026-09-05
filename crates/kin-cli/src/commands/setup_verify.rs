// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Proving a written MCP client config can actually reach Kin (FIR-1882).
//!
//! `kin setup` used to finish at the file level: the right JSON landed in the
//! right config, the install ledger recorded it, and setup reported the client
//! configured. Nothing ever exercised the entry. A recorded `command` that a
//! `brew upgrade` moved out from under, or a server that cannot complete a
//! handshake, leaves a config file that still reads as perfectly valid on disk
//! while every tool call the agent makes fails. A stranger's first minute with
//! Kin is setup, so a setup that claims wiring it never tried costs the whole
//! session.
//!
//! What runs here is the client's own launch: the recorded `command`, `args`
//! and `env` from the file setup just wrote, started from the directory the
//! client was bound to, driven through `initialize`, `tools/list` and one real
//! `tools/call`, and reported by the tool's own answer.
//!
//! Three properties this check is built around, each of which a check written
//! the obvious way would lose:
//!
//! * **It reads the file, not the intent.** The entry is parsed back out of the
//!   config setup wrote rather than rebuilt from the same code that wrote it, so
//!   the launcher path actually recorded is the one exercised. That is the whole
//!   of the brew-upgrade failure mode: the value on disk is the defect.
//! * **It pierces the tool-result envelope.** A `tools/call` answer carries its
//!   real payload as a JSON *string* inside `content[0].text`. Reading payload
//!   keys off the top level returns nothing for every key, and defaulting that
//!   nothing to zero turns an unreadable answer into a confident one. An answer
//!   that cannot be read is reported as unreadable, never as empty.
//! * **It is bounded and reaps its children.** Every launch runs under a
//!   per-client deadline inside a total budget, and a child that has not
//!   finished by its deadline is killed and waited on. Setup completes in about
//!   two seconds non-interactively today, and a verification step that could
//!   hang would be worse than the gap it closes.

use std::collections::BTreeMap;
#[cfg(test)]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use console::style;
use serde_json::Value;

/// The tool one round trip calls.
///
/// `kin_graph_status` is the cheapest real tool in the agent-default profile:
/// it answers from the repo daemon the same way every other graph-backed tool
/// does, over the same `/mcp/tools/call` route, and its successful payload is
/// contract-validated before it crosses the stdio boundary. Calling it proves
/// the transport and the tool surface at once, and its answer is a number a
/// person can read.
pub(crate) const ROUND_TRIP_TOOL: &str = "kin_graph_status";

/// How long one client's launch may take before it is killed.
///
/// The server answers `initialize` and `tools/list` immediately by design, and
/// bounds a `tools/call` that races its startup daemon binding before answering
/// that the daemon is still starting. This leaves room for that grace plus
/// process start and exit, and nothing more.
///
/// Derived from the server's own constant rather than restated, because the two
/// cannot be allowed to drift: a budget shorter than the grace kills the client
/// mid-wait, and the run then reports a deadline where the server was about to
/// hand back an accurate account of a daemon that was still coming up.
pub(crate) const PER_CLIENT_BUDGET: Duration =
    kin_mcp::FIRST_TOOLS_CALL_STARTUP_BIND_GRACE.saturating_add(Duration::from_secs(10));

/// How long the whole verification step may take across every client.
///
/// One client can pay a cold daemon start and the rest cannot: the first
/// client's tool call is what starts the daemon, so every client after it binds
/// a daemon that is already serving and answers in well under a second. So the
/// budget covers one cold client plus the warm ones behind it, rather than the
/// per-client bound multiplied by however many clients are configured. Clients
/// are checked in order and whatever the budget does not reach is reported
/// skipped by name, which is slower to read than a green tick and far better
/// than a setup run that stalls.
pub(crate) const TOTAL_BUDGET: Duration = PER_CLIENT_BUDGET.saturating_add(Duration::from_secs(35));

/// How long to wait for a drained pipe after the child is gone.
///
/// The reader threads end when every writer closes the pipe. Kin's daemon
/// launcher gives its children null stdio precisely so a grandchild cannot hold
/// one open, but a bounded collect costs nothing and means a future launcher
/// that got that wrong would degrade this check rather than hang setup.
const PIPE_COLLECT_GRACE: Duration = Duration::from_secs(2);

/// How much of an unreadable payload or a captured stderr is quoted back.
///
/// Enough to carry the sentence a reader has to act on, short enough that one
/// line per configured client stays a report rather than a wall.
const EVIDENCE_CHARS: usize = 200;

/// Where a round trip stopped when it did not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProofStage {
    /// The recorded entry could not be read or does not name a launchable
    /// command.
    Config,
    /// The recorded command could not be started at all.
    Spawn,
    /// The server started but did not complete `initialize`.
    Handshake,
    /// The server initialized but did not serve a usable tool list.
    ToolList,
    /// The tool list was served but the call did not come back.
    ToolCall,
    /// The launch outlived its deadline and was killed.
    Deadline,
}

impl ProofStage {
    fn label(self) -> &'static str {
        match self {
            Self::Config => "reading the recorded entry",
            Self::Spawn => "starting the recorded command",
            Self::Handshake => "the initialize handshake",
            Self::ToolList => "the served tool list",
            Self::ToolCall => "the tool call",
            Self::Deadline => "the round-trip deadline",
        }
    }
}

/// What one client's configuration was actually shown to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum McpProof {
    /// The round trip completed and the tool answered with a payload that could
    /// be read.
    Proven { answer: String },
    /// The round trip completed, the tool answered, and the answer was that no
    /// repo daemon is serving this repository yet.
    ///
    /// The entry is exercised and working: a launcher that could not run, or a
    /// server that could not handshake, never reaches a tool result at all. The
    /// graph behind it is simply not up, which a freshly initialized repository
    /// legitimately is at setup time.
    NotServing,
    /// The round trip completed and the tool answered with an error. The
    /// transport is proven; the tool declined, and its own words are carried.
    Refused { error: String },
    /// The round trip completed and the answer could not be read. Not an empty
    /// answer and not a zero: an answer whose contract did not hold.
    Unreadable { detail: String },
    /// The round trip did not complete.
    Failed { stage: ProofStage, error: String },
    /// The check did not run, and why.
    Skipped { reason: String },
}

/// One client's verdict, named so a failure says which client failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientProof {
    pub(crate) client: String,
    pub(crate) proof: McpProof,
}

/// A launch, exactly as the recorded entry describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct McpLaunch {
    command: OsString,
    args: Vec<OsString>,
    env: BTreeMap<String, OsString>,
}

impl McpLaunch {
    /// The command line, for an error a reader has to act on.
    ///
    /// A spawn failure is almost always about the path itself, so the message
    /// that reports it has to show the path.
    fn display_command(&self) -> String {
        let mut rendered = Path::new(&self.command).display().to_string();
        for arg in &self.args {
            rendered.push(' ');
            rendered.push_str(&Path::new(arg).display().to_string());
        }
        rendered
    }
}

/// Read the launch an MCP config file records for Kin.
///
/// Both config shapes setup writes are handled by the shared reader, so a
/// Codex `config.toml` entry is exercised the same way a JSON one is.
pub(crate) fn recorded_launch(path: &Path) -> Result<McpLaunch, String> {
    // A plain read, the way `kin doctor` reads the same files. The managed
    // private reader would be the obvious choice and is the wrong one: it
    // refuses any file that is not mode 0600, and a client's own config
    // predates setup and is routinely 0644. Refusing to read it would report a
    // perfectly working entry as a broken one, which is the failure this whole
    // module exists to stop, pointed the other way.
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
                "{} does not exist, though setup just wrote it",
                path.display()
            ))
        }
        Err(error) => return Err(format!("{} could not be read: {error}", path.display())),
    };
    let entry = super::setup::read_kin_mcp_entry_from_bytes(path, &bytes).ok_or_else(|| {
        format!(
            "{} carries no kin MCP server entry, though setup just wrote one",
            path.display()
        )
    })?;
    launch_from_entry(&entry)
}

/// Turn a recorded MCP server entry into the launch it describes.
pub(crate) fn launch_from_entry(entry: &Value) -> Result<McpLaunch, String> {
    let command = entry
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| "the recorded entry names no `command`".to_string())?;
    if command.trim().is_empty() {
        return Err("the recorded entry's `command` is empty".to_string());
    }

    let args = match entry.get("args") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => {
            let mut collected = Vec::with_capacity(items.len());
            for item in items {
                let arg = item.as_str().ok_or_else(|| {
                    format!("the recorded entry's `args` carries a non-string value: {item}")
                })?;
                collected.push(OsString::from(arg));
            }
            collected
        }
        Some(other) => {
            return Err(format!(
                "the recorded entry's `args` is not an array: {other}"
            ))
        }
    };

    let mut env = BTreeMap::new();
    match entry.get("env") {
        None | Some(Value::Null) => {}
        Some(Value::Object(pairs)) => {
            for (name, value) in pairs {
                let value = value.as_str().ok_or_else(|| {
                    format!("the recorded entry's `env` value for {name} is not a string: {value}")
                })?;
                env.insert(name.clone(), OsString::from(value));
            }
        }
        Some(other) => {
            return Err(format!(
                "the recorded entry's `env` is not an object: {other}"
            ))
        }
    }

    Ok(McpLaunch {
        command: OsString::from(command),
        args,
        env,
    })
}

/// The session one round trip drives: initialize, the initialized
/// notification, the tool list, and one real tool call.
///
/// No `roots` capability is advertised. A client that offers one is asked for
/// its workspace roots by the server, and answering that is a conversation this
/// check has no reason to hold: the launch directory is the repository under
/// test, which is what a bare launch binds from anyway.
fn probe_frames() -> String {
    let client = serde_json::json!({
        "name": "kin-setup-round-trip",
        "version": env!("CARGO_PKG_VERSION"),
    });
    let frames = [
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": client,
            },
        }),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": ROUND_TRIP_TOOL, "arguments": {}},
        }),
    ];
    let mut session = String::new();
    for frame in frames {
        session.push_str(&frame.to_string());
        session.push('\n');
    }
    session
}

/// Everything one launch said, on both pipes.
#[derive(Debug, Default)]
struct SessionOutput {
    responses: Vec<Value>,
    /// Stdout lines that were not JSON-RPC at all. A server that prints to
    /// stdout corrupts the transport, and a silent skip would hide that.
    noise: Vec<String>,
    stderr: String,
}

/// Launch the recorded entry, drive the probe session, and collect what came
/// back, under `budget`.
///
/// Both pipes are drained on their own threads from the moment the child
/// starts. A reader that waits for exit first deadlocks against a server
/// blocked writing a tool list larger than the pipe buffer, which `tools/list`
/// alone can be.
fn run_session(
    launch: &McpLaunch,
    working_dir: &Path,
    budget: Duration,
) -> Result<SessionOutput, (ProofStage, String)> {
    let started = Instant::now();
    let mut command = Command::new(&launch.command);
    command
        .args(&launch.args)
        .current_dir(working_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in &launch.env {
        command.env(name, value);
    }

    let mut child = command.spawn().map_err(|error| {
        (
            ProofStage::Spawn,
            format!("{error} (command: {})", launch.display_command()),
        )
    })?;

    let stdout = collect_pipe(child.stdout.take());
    let stderr = collect_pipe(child.stderr.take());

    let written = match child.stdin.take() {
        Some(mut stdin) => stdin
            .write_all(probe_frames().as_bytes())
            .and_then(|()| stdin.flush()),
        None => Ok(()),
    };
    if let Err(error) = written {
        kill_and_reap(&mut child);
        return Err((
            ProofStage::Handshake,
            format!("the probe session could not be written to the server's stdin: {error}"),
        ));
    }

    let exited = wait_bounded(&mut child, started + budget);
    // One grace across both pipes, not one each. A killed launch whose own
    // child inherited the pipes leaves both readers blocked, and waiting the
    // full grace twice doubles what a hung server costs setup.
    let collect_by = Instant::now() + PIPE_COLLECT_GRACE;
    let stderr = collect_by_deadline(stderr, collect_by);
    let stderr = String::from_utf8_lossy(&stderr).into_owned();
    let stdout = collect_by_deadline(stdout, collect_by);

    if exited.is_none() {
        return Err((
            ProofStage::Deadline,
            format!(
                "{} did not finish the round trip within {}s and was killed{}",
                launch.display_command(),
                budget.as_secs(),
                evidence_suffix("stderr", &stderr),
            ),
        ));
    }

    let mut session = SessionOutput {
        responses: Vec::new(),
        noise: Vec::new(),
        stderr,
    };
    for line in String::from_utf8_lossy(&stdout).lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(value) => session.responses.push(value),
            Err(_) => session.noise.push(line.to_string()),
        }
    }
    Ok(session)
}

/// Drain one pipe on its own thread, handing the bytes back over a channel.
///
/// A channel rather than a join handle so the collect is bounded: a thread
/// still blocked on a pipe some other process holds open is abandoned with its
/// output reported missing, never waited on forever.
fn collect_pipe<R: Read + Send + 'static>(pipe: Option<R>) -> mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    if let Some(mut pipe) = pipe {
        std::thread::spawn(move || {
            let mut collected = Vec::new();
            let _ = pipe.read_to_end(&mut collected);
            let _ = sender.send(collected);
        });
    } else {
        let _ = sender.send(Vec::new());
    }
    receiver
}

/// Take one drained pipe, or give up on it at `deadline` and report nothing.
fn collect_by_deadline(pipe: mpsc::Receiver<Vec<u8>>, deadline: Instant) -> Vec<u8> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    pipe.recv_timeout(remaining).unwrap_or_default()
}

/// Wait for the child under a deadline; kill and reap it at expiry.
fn wait_bounded(child: &mut Child, deadline: Instant) -> Option<std::process::ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => {
                kill_and_reap(child);
                return None;
            }
        }
        if Instant::now() >= deadline {
            kill_and_reap(child);
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Kill a child and wait on it, so no launch leaves a zombie behind.
///
/// The direct child only. A server that detached a grandchild keeps it, which
/// is deliberate for Kin's own launcher: it starts the repo daemon with null
/// stdio in its own session precisely so it outlives the process that asked for
/// it. What bounds this side is the pipe-collect grace, not the kill.
fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Classify one completed session into a verdict.
fn classify(session: &SessionOutput) -> McpProof {
    let Some(initialize) = response_with_id(session, 1) else {
        return McpProof::Failed {
            stage: ProofStage::Handshake,
            error: format!(
                "the server answered no initialize response{}",
                describe_session(session)
            ),
        };
    };
    if let Some(error) = rpc_error(initialize) {
        return McpProof::Failed {
            stage: ProofStage::Handshake,
            error,
        };
    }
    if initialize.pointer("/result/serverInfo/name").is_none() {
        return McpProof::Failed {
            stage: ProofStage::Handshake,
            error: format!("the initialize response carried no serverInfo.name: {initialize}"),
        };
    }

    let Some(listed) = response_with_id(session, 2) else {
        return McpProof::Failed {
            stage: ProofStage::ToolList,
            error: format!(
                "the server answered no tools/list response{}",
                describe_session(session)
            ),
        };
    };
    if let Some(error) = rpc_error(listed) {
        return McpProof::Failed {
            stage: ProofStage::ToolList,
            error,
        };
    }
    let served: Vec<&str> = listed
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .map(|tools| {
            tools
                .iter()
                .filter_map(|tool| tool.get("name").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    if served.is_empty() {
        return McpProof::Failed {
            stage: ProofStage::ToolList,
            error: format!("tools/list served no named tools: {listed}"),
        };
    }
    if !served.contains(&ROUND_TRIP_TOOL) {
        return McpProof::Failed {
            stage: ProofStage::ToolList,
            error: format!(
                "the served tool list does not carry {ROUND_TRIP_TOOL}, so this client's agent \
                 cannot call it; served: {}",
                served.join(", ")
            ),
        };
    }

    let Some(called) = response_with_id(session, 3) else {
        return McpProof::Failed {
            stage: ProofStage::ToolCall,
            error: format!(
                "the server answered no tools/call response for {ROUND_TRIP_TOOL}{}",
                describe_session(session)
            ),
        };
    };
    if let Some(error) = rpc_error(called) {
        return McpProof::Failed {
            stage: ProofStage::ToolCall,
            error,
        };
    }
    classify_tool_result(called)
}

/// Classify the `tools/call` response, piercing the result envelope.
///
/// The payload a Kin tool answers with is a JSON *string* carried in
/// `content[0].text`, so every payload key read off the top level of `result`
/// is absent. That absence is indistinguishable from a real empty answer until
/// the envelope is pierced, and a default applied to it manufactures a number
/// nothing measured.
fn classify_tool_result(called: &Value) -> McpProof {
    let Some(text) = called
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
    else {
        return McpProof::Unreadable {
            detail: format!(
                "the {ROUND_TRIP_TOOL} result carried no content[0].text block: {called}"
            ),
        };
    };
    if called.pointer("/result/isError").and_then(Value::as_bool) == Some(true) {
        // Read the reason off the response envelope's own degraded flag rather
        // than off the words of the message. A missing daemon and a tool that
        // genuinely refused are different verdicts, and the difference is
        // carried structurally; matching on prose would make this check depend
        // on remedy text that is rewritten whenever it is improved.
        if serde_json::from_str::<Value>(text)
            .ok()
            .and_then(|annotated| {
                annotated
                    .pointer("/_kin/degraded/daemon_unreachable")
                    .and_then(Value::as_bool)
            })
            == Some(true)
        {
            return McpProof::NotServing;
        }
        return McpProof::Refused {
            error: refusal_message(text),
        };
    }
    let payload: Value = match serde_json::from_str(text) {
        Ok(payload) => payload,
        Err(error) => {
            return McpProof::Unreadable {
                detail: format!(
                    "content[0].text is not the JSON payload {ROUND_TRIP_TOOL} contracts to \
                     return ({error}); it begins: {}",
                    truncate(text)
                ),
            }
        }
    };
    let entities = payload.get("entity_count").and_then(Value::as_u64);
    let relations = payload.get("relation_count").and_then(Value::as_u64);
    match (entities, relations) {
        (Some(entities), Some(relations)) => McpProof::Proven {
            answer: format!("{entities} entities, {relations} relations"),
        },
        (Some(entities), None) => McpProof::Proven {
            answer: format!("{entities} entities; the payload named no relation_count"),
        },
        (None, Some(relations)) => McpProof::Proven {
            answer: format!("{relations} relations; the payload named no entity_count"),
        },
        (None, None) => McpProof::Unreadable {
            detail: format!(
                "the {ROUND_TRIP_TOOL} payload parsed as JSON but named neither entity_count nor \
                 relation_count, so it counts nothing rather than counting zero; it begins: {}",
                truncate(text)
            ),
        },
    }
}

/// The human half of an error result.
///
/// A failed tool call is annotated exactly the way a successful one is: the
/// sentence the tool wrote is wrapped into a JSON object beside the response
/// envelope, under `message`, and pretty-printed across a dozen lines. Carrying
/// that blob into setup's output verbatim would bury the one line a person has
/// to act on inside the envelope that framed it, so the message is lifted out
/// when it is there and the whole text is carried when it is not.
fn refusal_message(text: &str) -> String {
    let lifted = serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|value| {
            value
                .get("message")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| text.to_string());
    collapse(&lifted)
}

fn response_with_id(session: &SessionOutput, id: u64) -> Option<&Value> {
    session
        .responses
        .iter()
        .find(|value| value.get("id").and_then(Value::as_u64) == Some(id))
}

/// The JSON-RPC transport error on a response, if it carries one.
fn rpc_error(response: &Value) -> Option<String> {
    let error = response.get("error")?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("(no message)");
    match error.get("code").and_then(Value::as_i64) {
        Some(code) => Some(format!("JSON-RPC error {code}: {message}")),
        None => Some(format!("JSON-RPC error: {message}")),
    }
}

/// What a session actually produced, for a message about what it did not.
fn describe_session(session: &SessionOutput) -> String {
    let mut described = format!(
        " ({} JSON-RPC response(s) received",
        session.responses.len()
    );
    if !session.noise.is_empty() {
        described.push_str(&format!(
            ", {} non-JSON stdout line(s) such as {}",
            session.noise.len(),
            truncate(&session.noise[0])
        ));
    }
    described.push(')');
    described.push_str(&evidence_suffix("stderr", &session.stderr));
    described
}

fn evidence_suffix(label: &str, text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    format!("; {label}: {}", truncate(trimmed))
}

/// Fold evidence onto one bounded line, so a multi-line payload or a whole
/// captured log cannot take setup's output over with it.
fn collapse(text: &str) -> String {
    let collapsed: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= EVIDENCE_CHARS {
        return collapsed;
    }
    let mut head: String = collapsed.chars().take(EVIDENCE_CHARS).collect();
    head.push_str("...");
    head
}

/// Quote evidence back, so an empty or whitespace-only capture is visible as
/// itself rather than as a gap in the sentence carrying it.
fn truncate(text: &str) -> String {
    format!("{:?}", collapse(text))
}

/// Prove one recorded entry by launching it and calling one tool.
pub(crate) fn prove_launch(launch: &McpLaunch, working_dir: &Path, budget: Duration) -> McpProof {
    match run_session(launch, working_dir, budget) {
        Ok(session) => classify(&session),
        Err((stage, error)) => McpProof::Failed { stage, error },
    }
}

/// The repository a round trip would be answered from, if there is one.
///
/// `kin mcp start` resolves its repository by walking up from its working
/// directory, so a setup run outside an initialized repository has nothing for
/// a tool call to answer about. That is not a broken config, and reporting it
/// as one would teach a stranger to distrust a check that was right.
fn round_trip_repo() -> Option<PathBuf> {
    let root = super::managed_config_scope::discover_repo_root()?;
    root.join(".kin").is_dir().then_some(root)
}

/// Prove every client this run registered, in order, under one shared budget.
///
/// `registered` carries only the clients whose config setup actually wrote this
/// run, so a client that was never configured is never claimed either way.
pub(crate) fn prove_registered_clients(
    registered: &[(String, PathBuf)],
    verify: bool,
) -> Vec<ClientProof> {
    let mut proofs = Vec::with_capacity(registered.len());
    if registered.is_empty() {
        return proofs;
    }

    if !verify {
        return skip_all(
            registered,
            "--skip-mcp-check was passed, so nothing exercised these entries".to_string(),
        );
    }

    let Some(repo) = round_trip_repo() else {
        let here = std::env::current_dir()
            .map(|dir| dir.display().to_string())
            .unwrap_or_else(|_| "the current directory".to_string());
        return skip_all(
            registered,
            format!(
                "no initialized Kin repository at or above {here}, so there is nothing for a tool \
                 call to answer about; run `kin init` there and re-run `kin setup`"
            ),
        );
    };

    let started = Instant::now();
    for (client, path) in registered {
        let spent = started.elapsed();
        let budget = TOTAL_BUDGET
            .checked_sub(spent)
            .unwrap_or_default()
            .min(PER_CLIENT_BUDGET);
        if budget.is_zero() {
            proofs.push(ClientProof {
                client: client.clone(),
                proof: McpProof::Skipped {
                    reason: format!(
                        "the {}s round-trip budget was already spent on the clients before it",
                        TOTAL_BUDGET.as_secs()
                    ),
                },
            });
            continue;
        }
        let proof = match recorded_launch(path) {
            Ok(launch) => prove_launch(&launch, &repo, budget),
            Err(error) => McpProof::Failed {
                stage: ProofStage::Config,
                error,
            },
        };
        proofs.push(ClientProof {
            client: client.clone(),
            proof,
        });
    }
    proofs
}

fn skip_all(registered: &[(String, PathBuf)], reason: String) -> Vec<ClientProof> {
    registered
        .iter()
        .map(|(client, _)| ClientProof {
            client: client.clone(),
            proof: McpProof::Skipped {
                reason: reason.clone(),
            },
        })
        .collect()
}

/// Print what each client's configuration was shown to do.
///
/// A skip is printed, never swallowed: a scripted install that turned the check
/// off has to say so in the same place a pass would have appeared, or the
/// output reads exactly like a run that proved something.
pub(crate) fn print_proofs(proofs: &[ClientProof]) {
    if proofs.is_empty() {
        return;
    }
    println!("MCP round trip (launching each configured client's own entry):");
    for ClientProof { client, proof } in proofs {
        match proof {
            McpProof::Proven { answer } => println!(
                "  {} {client}: {ROUND_TRIP_TOOL} answered {answer}",
                style("✓").green()
            ),
            McpProof::NotServing => println!(
                "  {} {client}: the entry answered, and {ROUND_TRIP_TOOL} reports no repo daemon \
                 is serving this repository yet",
                style("→").cyan()
            ),
            McpProof::Refused { error } => println!(
                "  {} {client}: the round trip completed and {ROUND_TRIP_TOOL} declined to \
                 answer: {error}",
                style("!").yellow()
            ),
            McpProof::Unreadable { detail } => println!(
                "  {} {client}: the round trip completed and its answer could not be read: \
                 {detail}",
                style("✗").red()
            ),
            McpProof::Failed { stage, error } => println!(
                "  {} {client}: the round trip failed at {} -- {error}",
                style("✗").red(),
                stage.label()
            ),
            McpProof::Skipped { reason } => {
                println!(
                    "  {} {client}: not exercised -- {reason}",
                    style("→").cyan()
                )
            }
        }
    }
    if proofs
        .iter()
        .any(|entry| entry.proof == McpProof::NotServing)
    {
        println!(
            "  {} Those entries are wired. Start the repo daemon with any kin command in this \
             repository, `kin status` for instance, and the same call answers from the graph.",
            style("→").cyan()
        );
    }
    if proofs.iter().any(|entry| {
        matches!(
            entry.proof,
            McpProof::Failed { .. } | McpProof::Unreadable { .. }
        )
    }) {
        println!(
            "  {} Setup wrote these config files, but the entries above were not shown to work. \
             Fix the reported cause and re-run `kin setup`; `kin setup doctor` re-checks the \
             installation.",
            style("!").yellow()
        );
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client budget has to outlast the wait the server it launches is
    /// entitled to take.
    ///
    /// This is the whole reason the constant is derived rather than written
    /// down twice. A budget at or under the grace kills the client while the
    /// server is still waiting, and the run reports a deadline instead of the
    /// accurate still-starting account the server was about to hand back. The
    /// same reading applies to the whole-step budget: it has to fit at least one
    /// client that pays a cold daemon start, because the first client's tool
    /// call is what starts the daemon.
    #[test]
    fn the_client_budget_outlasts_the_wait_the_mcp_server_is_allowed_to_take() {
        assert!(
            PER_CLIENT_BUDGET > kin_mcp::FIRST_TOOLS_CALL_STARTUP_BIND_GRACE,
            "a per-client budget inside the server's own grace kills the client mid-wait"
        );
        assert!(
            TOTAL_BUDGET >= PER_CLIENT_BUDGET,
            "a total budget under one client's budget can never let a cold client finish"
        );
    }

    /// Build a session out of raw JSON-RPC responses, as the reader would have
    /// parsed them off the server's stdout.
    fn session(responses: Vec<Value>) -> SessionOutput {
        SessionOutput {
            responses,
            noise: Vec::new(),
            stderr: String::new(),
        }
    }

    fn initialize_response() -> Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"serverInfo": {"name": "kin-mcp", "version": "0"}},
        })
    }

    fn tools_response(names: &[&str]) -> Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "tools": names
                    .iter()
                    .map(|name| serde_json::json!({"name": name}))
                    .collect::<Vec<_>>(),
            },
        })
    }

    /// A `tools/call` answer in the shape the server actually writes: the real
    /// payload is a JSON *string* inside the first content block.
    fn call_response(payload: &str, is_error: bool) -> Value {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {
                "content": [{"type": "text", "text": payload}],
                "isError": is_error,
            },
        })
    }

    fn graph_status_payload(entities: u64, relations: u64) -> String {
        serde_json::json!({
            "schema": "kin.graph_status.v1",
            "entity_count": entities,
            "relation_count": relations,
        })
        .to_string()
    }

    #[test]
    fn the_entry_setup_writes_parses_into_the_launch_it_describes() {
        let launch = launch_from_entry(&serde_json::json!({
            "command": "/opt/homebrew/Cellar/kin/0.5.39/bin/kin",
            "args": ["mcp", "start"],
            "env": {"KIN_MCP_TOOL_PROFILE": "agent-default"},
        }))
        .expect("the entry setup writes must parse");
        assert_eq!(
            launch.command,
            OsString::from("/opt/homebrew/Cellar/kin/0.5.39/bin/kin")
        );
        assert_eq!(
            launch.args,
            vec![OsString::from("mcp"), OsString::from("start")]
        );
        assert_eq!(
            launch
                .env
                .get("KIN_MCP_TOOL_PROFILE")
                .map(OsString::as_os_str),
            Some(OsStr::new("agent-default"))
        );
    }

    #[test]
    fn an_entry_that_names_no_launchable_command_is_refused_rather_than_launched() {
        for (entry, expected) in [
            (serde_json::json!({"args": ["mcp"]}), "names no `command`"),
            (serde_json::json!({"command": "   "}), "`command` is empty"),
            (
                serde_json::json!({"command": "kin", "args": "mcp start"}),
                "`args` is not an array",
            ),
            (
                serde_json::json!({"command": "kin", "args": [1]}),
                "non-string value",
            ),
            (
                serde_json::json!({"command": "kin", "env": []}),
                "`env` is not an object",
            ),
            (
                serde_json::json!({"command": "kin", "env": {"KIN_MCP_TOOL_PROFILE": 1}}),
                "is not a string",
            ),
        ] {
            let error = launch_from_entry(&entry).expect_err(&format!("{entry} must be refused"));
            assert!(
                error.contains(expected),
                "{entry} was refused with {error:?}, expected it to name {expected:?}"
            );
        }
    }

    /// The failure the whole check exists for: a recorded launcher that a
    /// version upgrade moved out from under the config. The file on disk is
    /// still perfectly well formed, and nothing but launching it can tell.
    #[test]
    fn a_recorded_command_that_cannot_be_started_fails_loud_with_the_path_and_the_os_error() {
        let root = tempfile::tempdir().expect("temp root");
        let missing = root
            .path()
            .join("Cellar")
            .join("kin")
            .join("bin")
            .join("kin");
        let launch = launch_from_entry(&serde_json::json!({
            "command": missing.to_string_lossy(),
            "args": ["mcp", "start"],
        }))
        .expect("a well-formed entry parses even when its command is gone");

        let proof = prove_launch(&launch, root.path(), PER_CLIENT_BUDGET);
        let McpProof::Failed { stage, error } = proof else {
            panic!("a command that does not exist must not be reported as proven: {proof:?}");
        };
        assert_eq!(stage, ProofStage::Spawn);
        assert!(
            error.contains(&missing.to_string_lossy().into_owned()),
            "the failure must name the command it could not start: {error}"
        );
        assert!(
            error.contains("No such file")
                || error.contains("cannot find")
                || error.contains("os error"),
            "the failure must carry the literal operating-system error: {error}"
        );
    }

    /// The same failure reached the way setup reaches it: through the config
    /// file, not through an entry the test handed over.
    #[test]
    fn a_config_file_recording_a_broken_command_fails_at_spawn() {
        let root = tempfile::tempdir().expect("temp root");
        let config = root.path().join("claude.json");
        let broken = root.path().join("gone").join("kin");
        std::fs::write(
            &config,
            serde_json::json!({
                "mcpServers": {
                    "kin": {"command": broken.to_string_lossy(), "args": ["mcp", "start"]},
                },
            })
            .to_string(),
        )
        .expect("write the client config");

        let launch = recorded_launch(&config).expect("the recorded entry must be readable");
        let proof = prove_launch(&launch, root.path(), PER_CLIENT_BUDGET);
        assert!(
            matches!(
                &proof,
                McpProof::Failed {
                    stage: ProofStage::Spawn,
                    error,
                } if error.contains(&broken.to_string_lossy().into_owned())
            ),
            "a config recording a command that cannot run must fail loud: {proof:?}"
        );
    }

    #[test]
    fn a_config_file_with_no_kin_entry_is_reported_against_the_file() {
        let root = tempfile::tempdir().expect("temp root");
        let config = root.path().join("claude.json");
        std::fs::write(&config, r#"{"mcpServers":{}}"#).expect("write the client config");
        let error = recorded_launch(&config).expect_err("an entryless config must be refused");
        assert!(
            error.contains("carries no kin MCP server entry"),
            "the failure must say what the file lacks: {error}"
        );
    }

    /// A hung server must cost setup its deadline and nothing more, and the
    /// child must actually be killed rather than left running behind it.
    #[cfg(unix)]
    #[test]
    fn a_launch_that_outlives_its_deadline_is_killed_rather_than_waited_on() {
        let root = tempfile::tempdir().expect("temp root");
        let marker = root.path().join("the-child-outlived-its-kill");
        let launch = launch_from_entry(&serde_json::json!({
            "command": "/bin/sh",
            "args": ["-c", format!("sleep 5; : > {}", marker.display())],
        }))
        .expect("the launch parses");

        let started = Instant::now();
        let proof = prove_launch(&launch, root.path(), Duration::from_millis(200));
        let elapsed = started.elapsed();

        let McpProof::Failed { stage, error } = proof else {
            panic!("a server that never answers must not be reported as proven: {proof:?}");
        };
        assert_eq!(stage, ProofStage::Deadline);
        assert!(
            error.contains("did not finish the round trip within"),
            "the failure must name the deadline it broke: {error}"
        );
        assert!(
            elapsed < Duration::from_secs(4),
            "the deadline must bound the wait; waited {elapsed:?}"
        );

        std::thread::sleep(Duration::from_secs(6));
        assert!(
            !marker.exists(),
            "the child ran to completion after its deadline, so it was never killed"
        );
    }

    /// The envelope trap. The payload is a JSON string inside the first content
    /// block; a reader that takes payload keys off the top level of `result`
    /// finds nothing for every key, and a default applied to that nothing
    /// reports a count nobody measured.
    #[test]
    fn an_answer_read_off_the_result_top_level_is_unreadable_never_a_count() {
        let called = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "result": {"entity_count": 5289, "relation_count": 18211},
        });
        let proof = classify_tool_result(&called);
        assert!(
            matches!(&proof, McpProof::Unreadable { detail } if detail.contains("content[0].text")),
            "a result with no content block is unreadable, not an answer: {proof:?}"
        );
    }

    #[test]
    fn the_answer_comes_from_the_content_block_not_from_the_result_top_level() {
        let mut called = call_response(&graph_status_payload(4242, 9), false);
        called["result"]["entity_count"] = serde_json::json!(1);
        called["result"]["relation_count"] = serde_json::json!(1);
        assert_eq!(
            classify_tool_result(&called),
            McpProof::Proven {
                answer: "4242 entities, 9 relations".to_string(),
            }
        );
    }

    #[test]
    fn a_payload_naming_no_counter_is_unreadable_rather_than_zero() {
        let called = call_response(r#"{"schema":"kin.graph_status.v1"}"#, false);
        let proof = classify_tool_result(&called);
        assert!(
            matches!(
                &proof,
                McpProof::Unreadable { detail }
                    if detail.contains("counts nothing rather than counting zero")
            ),
            "a payload with no counter must not become a zero: {proof:?}"
        );
    }

    #[test]
    fn a_measured_zero_is_an_answer_and_not_an_unreadable_one() {
        assert_eq!(
            classify_tool_result(&call_response(&graph_status_payload(0, 0), false)),
            McpProof::Proven {
                answer: "0 entities, 0 relations".to_string(),
            }
        );
    }

    #[test]
    fn a_content_block_that_is_not_json_is_unreadable_and_quotes_what_arrived() {
        let called = call_response("<!DOCTYPE html><html>proxy error</html>", false);
        let proof = classify_tool_result(&called);
        assert!(
            matches!(
                &proof,
                McpProof::Unreadable { detail } if detail.contains("proxy error")
            ),
            "an unreadable answer must quote what arrived: {proof:?}"
        );
    }

    #[test]
    fn an_error_result_is_reported_in_the_tool_s_own_words() {
        let called = call_response(
            "kin-mcp could not reach the repo daemon for this repository.",
            true,
        );
        assert_eq!(
            classify_tool_result(&called),
            McpProof::Refused {
                error: "kin-mcp could not reach the repo daemon for this repository.".to_string(),
            }
        );
    }

    /// A daemon that is not serving is not a broken entry, and the difference
    /// is carried on the response envelope rather than in the message. This is
    /// the exact annotated body `kin mcp start` writes for a repository with no
    /// daemon behind it.
    #[test]
    fn a_daemon_that_is_not_serving_is_reported_as_wiring_that_works() {
        let annotated = serde_json::json!({
            "_kin": {
                "degraded": {"daemon_unreachable": true},
                "envelope_version": 1,
                "runtime": "repo-daemon",
            },
            "message": "kin-mcp cannot answer 'kin_graph_status': /repo is a Kin repository, but \
                        no daemon is serving it right now.",
        })
        .to_string();
        assert_eq!(
            classify_tool_result(&call_response(&annotated, true)),
            McpProof::NotServing
        );
    }

    /// A tool error that is not the daemon being down stays a refusal, carrying
    /// the tool's own words, so the two never collapse into one verdict.
    #[test]
    fn a_tool_error_that_is_not_a_missing_daemon_stays_a_refusal() {
        let annotated = serde_json::json!({
            "_kin": {"degraded": {}, "envelope_version": 1, "runtime": "repo-daemon"},
            "message": "kin_graph_status rejected its arguments",
        })
        .to_string();
        assert_eq!(
            classify_tool_result(&call_response(&annotated, true)),
            McpProof::Refused {
                error: "kin_graph_status rejected its arguments".to_string(),
            }
        );
    }

    /// The shape the server actually sends: a failed call's message is wrapped
    /// into a JSON object beside the response envelope and pretty-printed, so
    /// reporting the content block verbatim would put a dozen lines of envelope
    /// into setup's output and bury the sentence a person has to act on.
    #[test]
    fn an_annotated_error_result_is_reported_by_its_message_not_its_envelope() {
        let annotated = serde_json::to_string_pretty(&serde_json::json!({
            "_kin": {"envelope_version": 1, "degraded": {"embed_worker_failed": true}},
            "message": "kin-mcp could not reach the repo daemon for this repository.",
        }))
        .expect("render the annotated error");
        assert!(
            annotated.contains('\n'),
            "the fixture must carry the multi-line shape the server sends"
        );
        assert_eq!(
            classify_tool_result(&call_response(&annotated, true)),
            McpProof::Refused {
                error: "kin-mcp could not reach the repo daemon for this repository.".to_string(),
            }
        );
    }

    #[test]
    fn a_session_with_no_initialize_response_fails_at_the_handshake() {
        let proof = classify(&session(vec![tools_response(&[ROUND_TRIP_TOOL])]));
        assert!(
            matches!(
                &proof,
                McpProof::Failed {
                    stage: ProofStage::Handshake,
                    error,
                } if error.contains("no initialize response")
            ),
            "a server that never initialized is not configured: {proof:?}"
        );
    }

    #[test]
    fn a_transport_error_response_is_carried_verbatim() {
        let proof = classify(&session(vec![serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32601, "message": "method not found"},
        })]));
        assert!(
            matches!(
                &proof,
                McpProof::Failed {
                    stage: ProofStage::Handshake,
                    error,
                } if error.contains("-32601") && error.contains("method not found")
            ),
            "a JSON-RPC error must be reported as itself: {proof:?}"
        );
    }

    #[test]
    fn a_tool_list_without_the_round_trip_tool_fails_instead_of_calling_it() {
        let proof = classify(&session(vec![
            initialize_response(),
            tools_response(&["semantic_locate"]),
            call_response(&graph_status_payload(1, 1), false),
        ]));
        assert!(
            matches!(
                &proof,
                McpProof::Failed {
                    stage: ProofStage::ToolList,
                    error,
                } if error.contains(ROUND_TRIP_TOOL) && error.contains("semantic_locate")
            ),
            "a tool list missing the tool an agent needs is a failure: {proof:?}"
        );
    }

    #[test]
    fn a_complete_session_is_proven_with_the_tool_s_own_counts() {
        assert_eq!(
            classify(&session(vec![
                initialize_response(),
                tools_response(&[ROUND_TRIP_TOOL, "semantic_locate"]),
                call_response(&graph_status_payload(5289, 18211), false),
            ])),
            McpProof::Proven {
                answer: "5289 entities, 18211 relations".to_string(),
            }
        );
    }

    #[test]
    fn a_session_that_never_answered_the_call_reports_what_it_did_answer() {
        let proof = classify(&session(vec![
            initialize_response(),
            tools_response(&[ROUND_TRIP_TOOL]),
        ]));
        assert!(
            matches!(
                &proof,
                McpProof::Failed {
                    stage: ProofStage::ToolCall,
                    error,
                } if error.contains("2 JSON-RPC response(s) received")
            ),
            "a missing tool answer must report the session it came from: {proof:?}"
        );
    }

    #[test]
    fn a_probe_session_advertises_no_roots_so_the_server_never_asks_for_them() {
        let frames: Vec<Value> = probe_frames()
            .lines()
            .map(|line| serde_json::from_str(line).expect("every probe frame is JSON"))
            .collect();
        assert_eq!(frames.len(), 4, "the session is four frames: {frames:?}");
        assert_eq!(
            frames[0].pointer("/params/capabilities"),
            Some(&serde_json::json!({})),
            "advertising roots would start a conversation this check cannot answer"
        );
        assert_eq!(
            frames[3].pointer("/params/name").and_then(Value::as_str),
            Some(ROUND_TRIP_TOOL)
        );
    }

    #[test]
    fn nothing_is_claimed_for_a_client_whose_check_was_skipped() {
        let registered = vec![("Claude Code".to_string(), PathBuf::from("/dev/null"))];
        let proofs = prove_registered_clients(&registered, false);
        assert!(
            matches!(
                proofs.as_slice(),
                [ClientProof { client, proof: McpProof::Skipped { reason } }]
                    if client == "Claude Code" && reason.contains("--skip-mcp-check")
            ),
            "a skipped check must say so per client: {proofs:?}"
        );
    }
}
