// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A minimal MCP stdio client, enough to drive `kin mcp start`.
//!
//! One request is in flight at a time, every read is bounded by a timeout that fails the
//! run rather than hanging it, and the child's stderr is drained on its own thread so a
//! chatty server cannot deadlock on a full pipe. Tool results are unwrapped through
//! `content[0].text`, which is where the real payload lives, and the `_kin` envelope and
//! `negative` verdict are read off that payload rather than off the wrapper. A payload
//! that cannot be read is reported as unreadable and never collapsed to a default, because
//! "the graph said zero" and "we could not read what the graph said" are different answers.

use serde_json::{json, Map, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;

/// The MCP protocol revision this client declares at initialize.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

#[derive(Debug, thiserror::Error)]
pub enum McpError {
    #[error("could not start the MCP server ({command}): {source}")]
    Spawn {
        command: String,
        source: std::io::Error,
    },
    #[error("the MCP server did not answer {method} within {timeout_s}s")]
    Timeout { method: String, timeout_s: u64 },
    #[error("the MCP server closed its output during {method}")]
    Closed { method: String },
    #[error("the MCP server rejected {method}: {message}")]
    Rejected { method: String, message: String },
    #[error("could not write to the MCP server during {method}: {source}")]
    Write {
        method: String,
        source: std::io::Error,
    },
}

/// A tool the server declares, carried through unchanged so its schema is the server's.
#[derive(Debug, Clone)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// What one `tools/call` produced.
#[derive(Debug, Clone)]
pub struct ToolOutcome {
    /// The text the model will see.
    pub text: String,
    /// The server's own error flag. An MCP error is a successful JSON-RPC response, so
    /// this must be read off the result rather than inferred from transport success.
    pub is_error: bool,
    /// The `_kin` envelope, when the payload carried one.
    pub envelope: Option<Value>,
    /// The `negative` object, when the payload carried one.
    pub negative: Option<Value>,
    /// True when the payload could not be parsed, so envelope and negative say nothing.
    pub unreadable: bool,
    pub wall_ms: u128,
}

impl ToolOutcome {
    /// The verdict on an empty retrieval: `Some(false)` means Kin says the absence cannot
    /// be trusted. `None` means the result carried no verdict, which is not the same thing.
    pub fn safe_to_conclude_absent(&self) -> Option<bool> {
        self.negative
            .as_ref()?
            .get("safe_to_conclude_absent")?
            .as_bool()
    }

    /// The named reason an absence cannot be trusted, when the server named one.
    pub fn limiting_factor(&self) -> Option<String> {
        let negative = self.negative.as_ref()?;
        for key in ["limiting_factor", "reason", "why", "explanation"] {
            if let Some(text) = negative.get(key).and_then(Value::as_str) {
                return Some(text.to_string());
            }
        }
        // Some shapes name the gap as a list of missing edge classes.
        for key in ["missing_edge_classes", "gaps", "missing"] {
            if let Some(items) = negative.get(key).and_then(Value::as_array) {
                let named: Vec<String> = items
                    .iter()
                    .filter_map(|item| item.as_str().map(ToString::to_string))
                    .collect();
                if !named.is_empty() {
                    return Some(named.join(", "));
                }
            }
        }
        None
    }

    /// Degraded components the envelope named, empty when it named none.
    pub fn degraded(&self) -> Vec<String> {
        let Some(envelope) = self.envelope.as_ref() else {
            return Vec::new();
        };
        match envelope.get("degraded") {
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| match item {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect(),
            Some(Value::Bool(true)) => vec!["degraded".to_string()],
            Some(Value::Object(map)) => map
                .iter()
                .filter(|(_, value)| value.as_bool().unwrap_or(false))
                .map(|(key, _)| key.clone())
                .collect(),
            _ => Vec::new(),
        }
    }

    /// A compact envelope summary for the trace sidecar.
    pub fn envelope_summary(&self) -> Option<Value> {
        let envelope = self.envelope.as_ref()?;
        let mut summary = Map::new();
        for key in [
            "envelope_version",
            "runtime",
            "graph_as_of",
            "graph_state",
            "semantic_coverage",
        ] {
            if let Some(value) = envelope.get(key) {
                summary.insert(key.to_string(), value.clone());
            }
        }
        let degraded = self.degraded();
        if !degraded.is_empty() {
            summary.insert(
                "degraded".to_string(),
                Value::Array(degraded.into_iter().map(Value::String).collect()),
            );
        }
        Some(Value::Object(summary))
    }
}

/// A live MCP server subprocess.
pub struct McpClient {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<std::io::Result<String>>,
    next_id: u64,
    timeout: Duration,
    command: String,
}

impl McpClient {
    /// The default command for a repository: the server this product already ships.
    pub fn default_command(repo: &Path) -> Vec<String> {
        vec![
            "kin".to_string(),
            "mcp".to_string(),
            "start".to_string(),
            "--repo".to_string(),
            repo.display().to_string(),
        ]
    }

    /// Spawn the server and complete `initialize`.
    pub fn start(argv: &[String], cwd: &Path, timeout: Duration) -> Result<Self, McpError> {
        let command = argv.join(" ");
        let (program, args) = argv
            .split_first()
            .ok_or_else(|| McpError::Spawn {
                command: command.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "the MCP command was empty",
                ),
            })?;
        let mut child = Command::new(program)
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| McpError::Spawn {
                command: command.clone(),
                source,
            })?;

        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");
        // Drain stderr so a server that logs heavily cannot block on a full pipe.
        if let Some(stderr) = child.stderr.take() {
            thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines() {
                    if line.is_err() {
                        break;
                    }
                }
            });
        }
        let lines = spawn_line_reader(stdout);

        let mut client = McpClient {
            child,
            stdin,
            lines,
            next_id: 0,
            timeout,
            command,
        };
        client.request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "kin-agent", "version": env!("CARGO_PKG_VERSION") },
            }),
        )?;
        client.notify("notifications/initialized", json!({}))?;
        Ok(client)
    }

    pub fn command(&self) -> &str {
        &self.command
    }

    /// Every tool the server declares.
    pub fn list_tools(&mut self) -> Result<Vec<McpTool>, McpError> {
        let result = self.request("tools/list", json!({}))?;
        let mut tools = Vec::new();
        for tool in result
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let Some(name) = tool.get("name").and_then(Value::as_str) else {
                continue;
            };
            tools.push(McpTool {
                name: name.to_string(),
                description: tool
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                input_schema: tool
                    .get("inputSchema")
                    .or_else(|| tool.get("input_schema"))
                    .cloned()
                    .unwrap_or_else(|| json!({ "type": "object" })),
            });
        }
        Ok(tools)
    }

    /// Call a tool and unwrap what came back.
    pub fn call_tool(&mut self, name: &str, arguments: &Value) -> Result<ToolOutcome, McpError> {
        let started = std::time::Instant::now();
        let result = self.request(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        )?;
        let wall_ms = started.elapsed().as_millis();
        Ok(unwrap_tool_result(&result, wall_ms))
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), McpError> {
        let line = json!({ "jsonrpc": "2.0", "method": method, "params": params }).to_string();
        writeln!(self.stdin, "{line}").map_err(|source| McpError::Write {
            method: method.to_string(),
            source,
        })?;
        self.stdin.flush().map_err(|source| McpError::Write {
            method: method.to_string(),
            source,
        })
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, McpError> {
        self.next_id += 1;
        let id = self.next_id;
        let line = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        })
        .to_string();
        writeln!(self.stdin, "{line}").map_err(|source| McpError::Write {
            method: method.to_string(),
            source,
        })?;
        self.stdin.flush().map_err(|source| McpError::Write {
            method: method.to_string(),
            source,
        })?;

        let deadline = std::time::Instant::now() + self.timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(McpError::Timeout {
                    method: method.to_string(),
                    timeout_s: self.timeout.as_secs(),
                });
            }
            let line = match self.lines.recv_timeout(remaining) {
                Ok(Ok(line)) => line,
                Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => {
                    return Err(McpError::Closed {
                        method: method.to_string(),
                    })
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(McpError::Timeout {
                        method: method.to_string(),
                        timeout_s: self.timeout.as_secs(),
                    })
                }
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(message) = serde_json::from_str::<Value>(trimmed) else {
                // A server that prints a banner on stdout is not a protocol error yet.
                continue;
            };
            if message.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(error) = message.get("error") {
                let text = error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("no message")
                    .to_string();
                return Err(McpError::Rejected {
                    method: method.to_string(),
                    message: text,
                });
            }
            return Ok(message.get("result").cloned().unwrap_or(Value::Null));
        }
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_line_reader(stdout: ChildStdout) -> Receiver<std::io::Result<String>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// Unwrap `{content:[{type:"text",text:"<payload>"}],isError:bool}` into what the loop needs.
pub fn unwrap_tool_result(result: &Value, wall_ms: u128) -> ToolOutcome {
    let is_error = result
        .get("isError")
        .and_then(Value::as_bool)
        .or_else(|| result.get("is_error").and_then(Value::as_bool))
        .unwrap_or(false);

    let mut text = String::new();
    if let Some(blocks) = result.get("content").and_then(Value::as_array) {
        for block in blocks {
            if let Some(part) = block.get("text").and_then(Value::as_str) {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(part);
            }
        }
    }
    if text.is_empty() {
        if let Some(structured) = result.get("structuredContent") {
            text = serde_json::to_string(structured).unwrap_or_default();
        }
    }

    // The payload lives inside the text block. Read the envelope off the payload, not off
    // the wrapper, because the wrapper never carries it.
    let payload = serde_json::from_str::<Value>(text.trim()).ok();
    let (envelope, negative, unreadable) = match payload.as_ref() {
        Some(Value::Object(map)) => (
            map.get("_kin").cloned(),
            map.get("negative").cloned(),
            false,
        ),
        Some(_) => (None, None, false),
        // Non-JSON text is a legitimate tool result shape, so it is only unreadable when
        // the result also claims to be structured. Plain prose is simply prose.
        None => (None, None, text.trim_start().starts_with('{')),
    };

    ToolOutcome {
        text,
        is_error,
        envelope,
        negative,
        unreadable,
        wall_ms,
    }
}
