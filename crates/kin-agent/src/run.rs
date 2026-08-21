// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The agent loop.

use crate::belt::{self, Belt, LocalTool, Route};
use crate::mcp::{McpClient, ToolOutcome};
use crate::parse::{self, Turn};
use crate::provider::{Provider, ProviderError, Usage};
use crate::transcript::{now_iso, TranscriptWriter};
use crate::{AgentConfig, ExitStatus, RunOutcome};
use serde_json::{json, Map, Value};
use std::path::Path;
use std::time::{Duration, Instant};

/// How many consecutive turns the model may fail to produce a usable call before the run
/// stops. Two, so a single bad turn is repaired and a model that cannot hold the protocol
/// is not allowed to burn the whole budget saying nothing.
const MAX_CONSECUTIVE_UNUSABLE: u32 = 2;
/// Bounded retries for a transport hiccup on the chat endpoint.
const ENDPOINT_ATTEMPTS: u32 = 3;

pub const DEFAULT_SYSTEM_PROMPT: &str = "\
You are a software engineering agent working in a repository through Kin, a semantic graph \
of the code. Kin is your only way to look at the repository.

You have no shell, no grep, no find and no file-reading tool. This is deliberate. Every \
question about where code lives, what calls what, or what a symbol does is answered from \
the graph with the mcp__kin__ tools. Start with mcp__kin__semantic_locate or \
mcp__kin__semantic_search to find things by meaning, use mcp__kin__get_context_pack or \
mcp__kin__get_entity_source to read exact source, and use mcp__kin__find_references or \
mcp__kin__trace_data_flow to follow relationships.

When a Kin result is empty, read what Kin says about that emptiness. If it reports the \
absence cannot be trusted, the honest answer is that you do not know, and you should say \
what the gap is. Never turn an untrusted absence into a claim that something does not exist.

To change code, use edit_file for a surgical change to an existing file and write_file to \
create a new one. Read the exact current text through Kin first so your edit matches byte \
for byte. You never open, stage or commit a transaction yourself, and those tools are not \
on your belt on purpose. The harness does it around every call you make: a file you create \
with write_file is staged as Kin's create operation, carrying the repository-relative path \
and the full body, and committed with provenance naming this agent. An edit to a file Kin \
already tracks lands in the working tree and is recorded in this run's trace, and the \
harness does not yet admit that edit to the graph in the same step.

Your tools are the mcp__kin__ ones named above plus edit_file and write_file. You have no \
others.

Work in small steps. Call one or two tools, read what came back, then decide. When you have \
the answer, say it in plain text without calling a tool.";

struct Counters {
    tool_calls: u32,
    kin_calls: u32,
    local_calls: u32,
    refused_calls: u32,
    repairs: u32,
    unsafe_absence_events: u32,
    unreadable_results: u32,
    turns: u32,
    input_tokens: u64,
    output_tokens: u64,
    saw_usage: bool,
    api_ms: u128,
    edits: Vec<String>,
}

impl Counters {
    fn new() -> Self {
        Counters {
            tool_calls: 0,
            kin_calls: 0,
            local_calls: 0,
            refused_calls: 0,
            repairs: 0,
            unsafe_absence_events: 0,
            unreadable_results: 0,
            turns: 0,
            input_tokens: 0,
            output_tokens: 0,
            saw_usage: false,
            api_ms: 0,
            edits: Vec::new(),
        }
    }

    fn absorb(&mut self, usage: &Usage) {
        if let Some(value) = usage.input_tokens {
            self.input_tokens += value;
            self.saw_usage = true;
        }
        if let Some(value) = usage.output_tokens {
            self.output_tokens += value;
            self.saw_usage = true;
        }
    }

    fn usage_json(&self) -> Option<Value> {
        if !self.saw_usage {
            return None;
        }
        Some(json!({
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
        }))
    }

    fn to_json(&self, exit_code: i32, stop_reason: &str) -> Value {
        json!({
            "exit_code": exit_code,
            "stop_reason": stop_reason,
            "tool_calls": self.tool_calls,
            "kin_calls": self.kin_calls,
            "local_calls": self.local_calls,
            "refused_calls": self.refused_calls,
            "repairs": self.repairs,
            "unsafe_absence_events": self.unsafe_absence_events,
            "unreadable_results": self.unreadable_results,
            "files_changed": self.edits,
        })
    }
}

/// Run one task to completion.
pub fn run(config: AgentConfig) -> anyhow::Result<RunOutcome> {
    let started = Instant::now();
    let session_id = uuid::Uuid::new_v4().to_string();
    let mut writer = TranscriptWriter::create(&config.out_dir, &session_id)?;
    let mut counters = Counters::new();

    let agent_meta = json!({
        "base_url": config.provider.base_url,
        "max_tool_calls": config.max_tool_calls,
        "deadline_s": config.deadline.as_secs(),
        "tool_profile": config.tool_profile.clone().unwrap_or_else(|| "server-default".into()),
        "policy": "no-shell-no-file-search",
        "mcp_command": config.mcp_command.join(" "),
    });

    // Connect to Kin first. A run that could not attach must be loud, not quietly scored.
    let mut mcp = match McpClient::start(&config.mcp_command, &config.repo, config.mcp_timeout) {
        Ok(client) => client,
        Err(err) => {
            let message = err.to_string();
            writer.init(
                &config.provider.model,
                &config.repo,
                &[],
                "failed",
                std::slice::from_ref(&message),
                agent_meta,
            )?;
            return finish(
                writer,
                &config,
                ExitStatus::McpError,
                "the MCP server did not start",
                &message,
                counters,
                started,
                None,
            );
        }
    };

    let declared = match mcp.list_tools() {
        Ok(tools) => tools,
        Err(err) => {
            let message = err.to_string();
            writer.init(
                &config.provider.model,
                &config.repo,
                &[],
                "failed",
                std::slice::from_ref(&message),
                agent_meta,
            )?;
            return finish(
                writer,
                &config,
                ExitStatus::McpError,
                "the MCP server did not list its tools",
                &message,
                counters,
                started,
                None,
            );
        }
    };

    let server_tool_names: Vec<String> = declared.iter().map(|tool| tool.name.clone()).collect();
    let exposed: Vec<_> = declared
        .iter()
        .filter(|tool| !belt::is_harness_owned(&tool.name))
        .collect();
    let belt = Belt::new(
        exposed
            .iter()
            .map(|tool| (tool.name.clone(), tool.input_schema.clone()))
            .collect(),
    );
    let descriptions: Vec<(String, String)> = exposed
        .iter()
        .map(|tool| (tool.name.clone(), tool.description.clone()))
        .collect();
    let specs = belt.to_specs(&descriptions);
    let tool_names: Vec<String> = belt.names().iter().cloned().collect();

    writer.init(
        &config.provider.model,
        &config.repo,
        &tool_names,
        "connected",
        &[],
        agent_meta,
    )?;

    let provider = Provider::new(config.provider.clone())?;

    // Open a Kin session so every mutation this run makes names this agent rather than an
    // anonymous file write. A server without the tool is not an error; it just means the
    // provenance bracket is unavailable and the trace says so.
    let kin_session = start_kin_session(&mut mcp, &config, &server_tool_names, &mut writer)?;

    let system_prompt = config
        .system_prompt
        .clone()
        .unwrap_or_else(|| DEFAULT_SYSTEM_PROMPT.to_string());
    let mut messages = vec![
        json!({ "role": "system", "content": system_prompt }),
        json!({ "role": "user", "content": config.task }),
    ];

    let mut next_tool_id = 0u64;
    let mut consecutive_unusable = 0u32;
    let mut surfaced_degraded = false;
    let mut final_text = String::new();
    let mut status = ExitStatus::Success;
    let mut stop_reason = "final_answer".to_string();

    loop {
        if started.elapsed() >= config.deadline {
            status = ExitStatus::Deadline;
            stop_reason = "wall_deadline".into();
            break;
        }
        if counters.tool_calls >= config.max_tool_calls {
            // The budget is spent. Ask for an answer with nothing to call, so the run ends
            // with what the model actually learned rather than with silence.
            messages.push(json!({
                "role": "user",
                "content": format!(
                    "You have used your budget of {} tool calls. Do not call any more tools. \
                     Answer now in plain text with what you have learned, and say plainly what \
                     you were not able to determine.",
                    config.max_tool_calls
                ),
            }));
            match complete_with_retry(&provider, &messages, &[], &mut counters) {
                Ok(completion) => {
                    counters.absorb(&completion.usage);
                    let turn = parse::parse_choice(&completion.choice, belt.names());
                    let text = match turn {
                        Turn::Final { text } => text,
                        Turn::ToolCalls { text, .. } => text,
                        Turn::Unusable { text, .. } => text,
                    };
                    counters.turns += 1;
                    writer.assistant(
                        &config.provider.model,
                        &format!("msg_{:08}", counters.turns),
                        &text,
                        &[],
                        completion.usage.to_json(),
                    )?;
                    final_text = text;
                }
                Err(err) => {
                    final_text = format!("(no final answer: {err})");
                }
            }
            status = ExitStatus::CapReached;
            stop_reason = "tool_call_cap".into();
            break;
        }

        let completion = match complete_with_retry(&provider, &messages, &specs, &mut counters) {
            Ok(completion) => completion,
            Err(err) => {
                status = ExitStatus::EndpointError;
                stop_reason = "endpoint_unreachable".into();
                final_text = err.to_string();
                break;
            }
        };
        counters.absorb(&completion.usage);
        counters.turns += 1;
        let turn = parse::parse_choice(&completion.choice, belt.names());

        match turn {
            Turn::Final { text } => {
                writer.assistant(
                    &config.provider.model,
                    &format!("msg_{:08}", counters.turns),
                    &text,
                    &[],
                    completion.usage.to_json(),
                )?;
                final_text = text;
                status = ExitStatus::Success;
                stop_reason = "final_answer".into();
                break;
            }
            Turn::Unusable { reason, text } => {
                consecutive_unusable += 1;
                writer.assistant(
                    &config.provider.model,
                    &format!("msg_{:08}", counters.turns),
                    &text,
                    &[],
                    completion.usage.to_json(),
                )?;
                writer.trace(json!({
                    "surface": "policy",
                    "policy": "unparsed",
                    "reason": reason,
                    "attempt": consecutive_unusable,
                }))?;
                if consecutive_unusable >= MAX_CONSECUTIVE_UNUSABLE {
                    status = ExitStatus::EndpointError;
                    // Named apart from an unreachable endpoint on purpose: a model that
                    // cannot hold the tool protocol is a model failure, and a run that
                    // died this way must never be scored as a task the toolset failed.
                    stop_reason = "model_format_failure".into();
                    final_text = text;
                    break;
                }
                counters.repairs += 1;
                messages.push(json!({ "role": "assistant", "content": text }));
                messages.push(json!({
                    "role": "user",
                    "content": format!(
                        "That turn could not be used: {reason}. Either call one tool using the \
                         tool-calling format, or answer in plain text. Do not describe a tool \
                         call in prose."
                    ),
                }));
                continue;
            }
            Turn::ToolCalls { text, mut calls } => {
                consecutive_unusable = 0;
                // Canonical ids, used in the transcript and echoed back to the model, so a
                // trace row and a conversation entry name the same call.
                for call in calls.iter_mut() {
                    next_tool_id += 1;
                    call.id = format!("toolu_{next_tool_id:08}");
                }
                let tool_uses: Vec<(String, String, Value)> = calls
                    .iter()
                    .map(|call| (call.id.clone(), call.name.clone(), call.arguments.clone()))
                    .collect();
                writer.assistant(
                    &config.provider.model,
                    &format!("msg_{:08}", counters.turns),
                    &text,
                    &tool_uses,
                    completion.usage.to_json(),
                )?;
                messages.push(json!({
                    "role": "assistant",
                    "content": text,
                    "tool_calls": calls.iter().map(|call| json!({
                        "id": call.id,
                        "type": "function",
                        "function": {
                            "name": call.name,
                            "arguments": call.arguments.to_string(),
                        }
                    })).collect::<Vec<_>>(),
                }));

                for call in &calls {
                    counters.tool_calls += 1;
                    let route = belt.route(&call.name);
                    let (result_text, is_error) = match route {
                        Route::Refused(message) => {
                            counters.refused_calls += 1;
                            writer.trace(json!({
                                "tool_use_id": call.id,
                                "surface": "policy",
                                "tool": call.name,
                                "args": call.arguments,
                                "policy": "refused",
                                "call_shape": call.shape.as_str(),
                                "is_error": true,
                            }))?;
                            (message, true)
                        }
                        Route::Kin(name) => {
                            match check_arguments(&belt, &call.name, &call.arguments) {
                                Err(problem) => {
                                    counters.repairs += 1;
                                    writer.trace(json!({
                                        "tool_use_id": call.id,
                                        "surface": "kin",
                                        "tool": name,
                                        "args": call.arguments,
                                        "policy": "repaired",
                                        "call_shape": call.shape.as_str(),
                                        "problem": problem,
                                        "is_error": true,
                                    }))?;
                                    (
                                        format!(
                                            "The call was not run because its arguments were \
                                             rejected: {problem}. Send the call again with that \
                                             corrected."
                                        ),
                                        true,
                                    )
                                }
                                Ok(()) => {
                                    let outcome = mcp.call_tool(&name, &call.arguments);
                                    match outcome {
                                        Err(err) => {
                                            // The server died or stopped answering. Nothing
                                            // downstream can be trusted, so stop here.
                                            writer.trace(json!({
                                                "tool_use_id": call.id,
                                                "surface": "kin",
                                                "tool": name,
                                                "args": call.arguments,
                                                "policy": "allowed",
                                                "is_error": true,
                                                "transport_error": err.to_string(),
                                            }))?;
                                            writer.tool_result(&call.id, &err.to_string(), true)?;
                                            status = ExitStatus::McpError;
                                            stop_reason = "mcp_transport".into();
                                            final_text = err.to_string();
                                            return finish(
                                                writer,
                                                &config,
                                                status,
                                                &stop_reason,
                                                &final_text,
                                                counters,
                                                started,
                                                None,
                                            );
                                        }
                                        Ok(outcome) => {
                                            counters.kin_calls += 1;
                                            if outcome.unreadable {
                                                counters.unreadable_results += 1;
                                            }
                                            let annotated = annotate(
                                                &outcome,
                                                &mut counters,
                                                &mut surfaced_degraded,
                                            );
                                            writer.trace(json!({
                                                "tool_use_id": call.id,
                                                "surface": "kin",
                                                "tool": name,
                                                "args": call.arguments,
                                                "wall_ms": outcome.wall_ms as u64,
                                                "is_error": outcome.is_error,
                                                "policy": "allowed",
                                                "call_shape": call.shape.as_str(),
                                                "envelope": outcome.envelope_summary(),
                                                "negative": negative_summary(&outcome),
                                                "unreadable": outcome.unreadable,
                                            }))?;
                                            (annotated, outcome.is_error)
                                        }
                                    }
                                }
                            }
                        }
                        Route::Local(tool) => {
                            match check_arguments(&belt, &call.name, &call.arguments) {
                                Err(problem) => {
                                    counters.repairs += 1;
                                    writer.trace(json!({
                                        "tool_use_id": call.id,
                                        "surface": "local",
                                        "tool": call.name,
                                        "args": redact_content(&call.arguments),
                                        "policy": "repaired",
                                        "problem": problem,
                                        "is_error": true,
                                    }))?;
                                    (
                                        format!(
                                            "The call was not run because its arguments were \
                                             rejected: {problem}. Send the call again with that \
                                             corrected."
                                        ),
                                        true,
                                    )
                                }
                                Ok(()) => {
                                    counters.local_calls += 1;
                                    let started_call = Instant::now();
                                    // The plan is made before the tool runs, because
                                    // `write_file` is what makes a new path exist and
                                    // afterwards nothing can tell a create from an
                                    // overwrite.
                                    let plan = plan_stage(&config.repo, tool, &call.arguments);
                                    let mut bracket = begin_transaction(
                                        &mut mcp,
                                        kin_session.as_deref(),
                                        &server_tool_names,
                                        &call.arguments,
                                        &plan,
                                        &mut writer,
                                    )?;
                                    let outcome = match tool {
                                        LocalTool::Edit => {
                                            belt::run_edit(&config.repo, &call.arguments)
                                        }
                                        LocalTool::Write => {
                                            belt::run_write(&config.repo, &call.arguments)
                                        }
                                    };
                                    // Stage what the harness just did, inside the open
                                    // bracket, so the commit below has something to
                                    // publish. An empty transaction is refused by design.
                                    let staged = if outcome.is_error {
                                        false
                                    } else {
                                        stage_planned_operation(
                                            &mut mcp,
                                            &mut bracket,
                                            kin_session.as_deref(),
                                            &plan,
                                            &mut writer,
                                        )?
                                    };
                                    let provenance = close_transaction(
                                        &mut mcp,
                                        bracket,
                                        !outcome.is_error && staged,
                                        &mut writer,
                                    )?;
                                    if let Some(path) = outcome.changed.clone() {
                                        if !counters.edits.contains(&path) {
                                            counters.edits.push(path);
                                        }
                                    }
                                    writer.trace(json!({
                                        "tool_use_id": call.id,
                                        "surface": "local",
                                        "tool": call.name,
                                        "args": redact_content(&call.arguments),
                                        "wall_ms": started_call.elapsed().as_millis() as u64,
                                        "is_error": outcome.is_error,
                                        "policy": "allowed",
                                        "call_shape": call.shape.as_str(),
                                        "changed": outcome.changed,
                                        "provenance": provenance,
                                    }))?;
                                    (outcome.text, outcome.is_error)
                                }
                            }
                        }
                    };

                    writer.tool_result(&call.id, &result_text, is_error)?;
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": result_text,
                    }));

                    if started.elapsed() >= config.deadline {
                        status = ExitStatus::Deadline;
                        stop_reason = "wall_deadline".into();
                        break;
                    }
                }
                if matches!(status, ExitStatus::Deadline) {
                    break;
                }
            }
        }
    }

    end_kin_session(
        &mut mcp,
        kin_session.as_deref(),
        &server_tool_names,
        &mut writer,
    )?;
    finish(
        writer,
        &config,
        status,
        &stop_reason,
        &final_text,
        counters,
        started,
        None,
    )
}

/// Append what Kin said about its own answer, so an untrusted absence cannot be read as
/// an absence and a degraded graph is stated once rather than silently.
fn annotate(
    outcome: &ToolOutcome,
    counters: &mut Counters,
    surfaced_degraded: &mut bool,
) -> String {
    let mut text = outcome.text.clone();
    if outcome.safe_to_conclude_absent() == Some(false) {
        counters.unsafe_absence_events += 1;
        let gap = outcome
            .limiting_factor()
            .unwrap_or_else(|| "Kin did not name the limiting factor".to_string());
        text.push_str(&format!(
            "\n\n[kin] This result is empty and Kin reports the absence CANNOT be trusted: {gap}. \
             Treat this as unknown rather than absent. Say what is unknown and name the gap. Do \
             not conclude the thing does not exist, and do not try to answer it another way."
        ));
    }
    if !*surfaced_degraded {
        let degraded = outcome.degraded();
        if !degraded.is_empty() {
            *surfaced_degraded = true;
            text.push_str(&format!(
                "\n\n[kin] Coverage note, reported once for this run: {}. Answers may be \
                 incomplete; say so where it matters.",
                degraded.join(", ")
            ));
        }
    }
    if outcome.unreadable {
        text.push_str(
            "\n\n[kin] The response payload could not be parsed, so no coverage or absence \
             verdict is available for this call. Treat it as unread rather than empty.",
        );
    }
    text
}

fn negative_summary(outcome: &ToolOutcome) -> Value {
    match outcome.negative.as_ref() {
        None => Value::Null,
        Some(_) => {
            let mut map = Map::new();
            map.insert("present".into(), Value::Bool(true));
            map.insert(
                "safe_to_conclude_absent".into(),
                match outcome.safe_to_conclude_absent() {
                    Some(value) => Value::Bool(value),
                    None => Value::Null,
                },
            );
            if let Some(factor) = outcome.limiting_factor() {
                map.insert("limiting_factor".into(), Value::String(factor));
            }
            Value::Object(map)
        }
    }
}

/// Keep a whole written file out of the trace row; the transcript already carries it.
fn redact_content(arguments: &Value) -> Value {
    let Some(object) = arguments.as_object() else {
        return arguments.clone();
    };
    let mut copy = object.clone();
    for key in ["content", "replace", "find"] {
        if let Some(Value::String(text)) = copy.get(key) {
            let len = text.len();
            copy.insert(key.into(), Value::String(format!("<{len} bytes>")));
        }
    }
    Value::Object(copy)
}

fn check_arguments(belt: &Belt, name: &str, arguments: &Value) -> Result<(), String> {
    if let Some(problem) = parse::arguments_are_malformed(arguments) {
        return Err(problem);
    }
    match belt.schema_for(name) {
        Some(schema) => belt::validate_arguments(&schema, arguments),
        None => Ok(()),
    }
}

fn complete_with_retry(
    provider: &Provider,
    messages: &[Value],
    tools: &[Value],
    counters: &mut Counters,
) -> Result<crate::provider::Completion, ProviderError> {
    let mut last: Option<ProviderError> = None;
    for attempt in 0..ENDPOINT_ATTEMPTS {
        match provider.complete(messages, tools) {
            Ok(completion) => {
                counters.api_ms += completion.api_ms;
                return Ok(completion);
            }
            Err(err) => {
                // A rejected request will be rejected again; only a transport hiccup is
                // worth a second try.
                let retryable = matches!(err, ProviderError::Transport { .. });
                last = Some(err);
                if !retryable || attempt + 1 == ENDPOINT_ATTEMPTS {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500 * (attempt as u64 + 1)));
            }
        }
    }
    Err(last.expect("at least one attempt was made"))
}

fn start_kin_session(
    mcp: &mut McpClient,
    config: &AgentConfig,
    server_tools: &[String],
    writer: &mut TranscriptWriter,
) -> anyhow::Result<Option<String>> {
    if !server_tools.iter().any(|name| name == "kin_session_start") {
        writer.trace(json!({
            "surface": "policy",
            "policy": "allowed",
            "event": "session_unavailable",
            "detail": "the server does not expose kin_session_start; edits will carry no session provenance",
        }))?;
        return Ok(None);
    }
    let arguments = json!({
        "vendor": "kin-agent",
        "client_name": format!("kin-agent ({})", config.provider.model),
        "transport": "mcp",
        "pid": std::process::id(),
        "cwd": config.repo.display().to_string(),
        "capabilities": { "can_read": true, "can_write": true, "can_commit": true },
    });
    match mcp.call_tool("kin_session_start", &arguments) {
        Ok(outcome) => {
            let session = extract_id(&outcome, &["session_id", "id"]);
            writer.trace(json!({
                "surface": "kin",
                "tool": "kin_session_start",
                "policy": "allowed",
                "event": "session_start",
                "wall_ms": outcome.wall_ms as u64,
                "is_error": outcome.is_error,
                "kin_session_id": session.clone(),
            }))?;
            Ok(if outcome.is_error { None } else { session })
        }
        Err(err) => {
            writer.trace(json!({
                "surface": "kin",
                "tool": "kin_session_start",
                "policy": "allowed",
                "event": "session_start",
                "is_error": true,
                "transport_error": err.to_string(),
            }))?;
            Ok(None)
        }
    }
}

fn end_kin_session(
    mcp: &mut McpClient,
    session: Option<&str>,
    server_tools: &[String],
    writer: &mut TranscriptWriter,
) -> anyhow::Result<()> {
    let Some(session) = session else {
        return Ok(());
    };
    if !server_tools.iter().any(|name| name == "kin_session_end") {
        return Ok(());
    }
    let outcome = mcp.call_tool("kin_session_end", &json!({ "session_id": session }));
    writer.trace(json!({
        "surface": "kin",
        "tool": "kin_session_end",
        "policy": "allowed",
        "event": "session_end",
        "is_error": outcome.as_ref().map(|o| o.is_error).unwrap_or(true),
        "transport_error": outcome.as_ref().err().map(|e| e.to_string()),
    }))?;
    Ok(())
}

/// What the harness will stage inside the bracket for one local tool call.
///
/// `kin_transaction_stage` admits five disjoint shapes (`crates/kin-mcp/src/tools.rs`),
/// and exactly one of them is keyed on a repository-relative path plus a body: the new
/// source file, verb `create`. The in-place edit shape resolves its target against
/// repository authority as an entity uuid or an exact entity name
/// (`kin_mcp::handlers::sessions::resolve_target_entity`), which a text splice does not
/// know, so the harness plans nothing for an edit rather than staging a shape the daemon
/// would refuse at commit. A transaction with nothing in it is refused too, by design, so
/// an unstageable call opens no transaction at all and the trace says why.
enum StagePlan {
    /// Admit the file at this repository-relative path with this body. Repository
    /// authority refuses it by name if it already tracks the path.
    Create { target: String, body: String },
    /// Nothing the stage surface admits fits this call, and this is the reason.
    Unstageable { reason: String },
}

/// Decide what to stage for one local tool call.
///
/// Whether the path is new is repository authority's question, not the filesystem's, and
/// the two answers differ: a path can sit on disk untracked, or be tracked with nothing on
/// disk yet. So the harness plans the create and lets the daemon refuse it by name if the
/// graph already holds that path, which is the rule `create` documents. Probing the disk
/// here would put a filesystem heuristic on the runtime path to answer a question the
/// graph owns.
fn plan_stage(repo: &Path, tool: LocalTool, arguments: &Value) -> StagePlan {
    let raw_path = arguments.get("path").and_then(Value::as_str).unwrap_or("");
    match tool {
        LocalTool::Edit => StagePlan::Unstageable {
            reason: "an in-place edit has no stage shape keyed on a path; the update \
                     operation names an entity uuid or an exact entity name"
                .into(),
        },
        LocalTool::Write => {
            let content = arguments
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or("");
            if content.trim().is_empty() {
                return StagePlan::Unstageable {
                    reason: "the create operation requires a non-empty body".into(),
                };
            }
            let path = match belt::resolve_in_repo(repo, raw_path) {
                Ok(path) => path,
                Err(problem) => return StagePlan::Unstageable { reason: problem },
            };
            match repository_relative(repo, &path) {
                Some(target) => StagePlan::Create {
                    target,
                    body: content.to_string(),
                },
                None => StagePlan::Unstageable {
                    reason: "the path did not reduce to a repository-relative target".into(),
                },
            }
        }
    }
}

/// The repository-relative form of a resolved path, with `/` separators on every platform
/// because that is what repository authority stores.
fn repository_relative(repo: &Path, resolved: &Path) -> Option<String> {
    let relative = resolved.strip_prefix(repo).ok()?;
    let parts: Vec<String> = relative
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// An open provenance bracket around one local edit.
struct Bracket {
    transaction_id: Option<String>,
    reason: Option<String>,
    /// What the harness staged into this transaction, and whether the server took it.
    staged: Option<Value>,
}

impl Bracket {
    fn unopened(reason: impl Into<String>) -> Self {
        Bracket {
            transaction_id: None,
            reason: Some(reason.into()),
            staged: None,
        }
    }
}

fn begin_transaction(
    mcp: &mut McpClient,
    session: Option<&str>,
    server_tools: &[String],
    arguments: &Value,
    plan: &StagePlan,
    writer: &mut TranscriptWriter,
) -> anyhow::Result<Bracket> {
    // A transaction the harness cannot stage into can only end in the daemon's refusal of
    // an empty commit, so it is not opened. The reason travels into the provenance record.
    if let StagePlan::Unstageable { reason } = plan {
        return Ok(Bracket::unopened(reason.clone()));
    }
    let Some(session) = session else {
        return Ok(Bracket::unopened("no Kin session was open"));
    };
    for required in ["kin_transaction_begin", "kin_transaction_stage"] {
        if !server_tools.iter().any(|name| name == required) {
            return Ok(Bracket::unopened(format!(
                "the server does not expose {required}"
            )));
        }
    }
    let scope = arguments
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("repository")
        .to_string();
    match mcp.call_tool(
        "kin_transaction_begin",
        &json!({ "session_id": session, "scope": scope }),
    ) {
        Ok(outcome) if !outcome.is_error => {
            let transaction_id = extract_id(&outcome, &["transaction_id", "id"]);
            writer.trace(json!({
                "surface": "kin",
                "tool": "kin_transaction_begin",
                "policy": "allowed",
                "event": "transaction_begin",
                "scope": scope,
                "wall_ms": outcome.wall_ms as u64,
                "is_error": false,
                "transaction_id": transaction_id.clone(),
            }))?;
            Ok(Bracket {
                reason: transaction_id
                    .is_none()
                    .then(|| "the server returned no transaction id".to_string()),
                transaction_id,
                staged: None,
            })
        }
        Ok(outcome) => {
            writer.trace(json!({
                "surface": "kin",
                "tool": "kin_transaction_begin",
                "policy": "allowed",
                "event": "transaction_begin",
                "scope": scope,
                "is_error": true,
                "detail": truncate(&outcome.text, 300),
            }))?;
            Ok(Bracket::unopened(truncate(&outcome.text, 200)))
        }
        Err(err) => Ok(Bracket::unopened(err.to_string())),
    }
}

/// Stage the operation the harness just performed, inside the open bracket.
///
/// Returns whether the transaction now holds something committable. A bracket that was
/// never opened, or a plan with nothing the stage surface admits, stages nothing and says
/// so, which is what keeps the commit below from claiming a provenance it did not get.
fn stage_planned_operation(
    mcp: &mut McpClient,
    bracket: &mut Bracket,
    session: Option<&str>,
    plan: &StagePlan,
    writer: &mut TranscriptWriter,
) -> anyhow::Result<bool> {
    let (Some(transaction_id), StagePlan::Create { target, body }) =
        (bracket.transaction_id.clone(), plan)
    else {
        return Ok(false);
    };
    let operation = json!({
        "verb": "create",
        "target": target,
        "body": body,
        "description": format!("kin agent created {target}"),
    });
    let mut arguments = json!({
        "transaction_id": transaction_id,
        "operations": [operation],
    });
    if let Some(session) = session {
        arguments["session_id"] = Value::String(session.to_string());
    }
    let outcome = mcp.call_tool("kin_transaction_stage", &arguments);
    let (is_error, detail) = match &outcome {
        Ok(outcome) => (outcome.is_error, truncate(&outcome.text, 300)),
        Err(err) => (true, err.to_string()),
    };
    writer.trace(json!({
        "surface": "kin",
        "tool": "kin_transaction_stage",
        "policy": "allowed",
        "event": "transaction_stage",
        "transaction_id": transaction_id,
        "verb": "create",
        "target": target,
        "body_bytes": body.len(),
        "is_error": is_error,
        "detail": detail,
    }))?;
    bracket.staged = Some(json!({
        "verb": "create",
        "target": target,
        "body_bytes": body.len(),
        "accepted": !is_error,
        "detail": if is_error { Value::String(detail) } else { Value::Null },
    }));
    Ok(!is_error)
}

/// Close the bracket. The recorded provenance says what actually happened, including a
/// refusal, so a run never claims a provenance it did not get.
fn close_transaction(
    mcp: &mut McpClient,
    bracket: Bracket,
    succeeded: bool,
    writer: &mut TranscriptWriter,
) -> anyhow::Result<Value> {
    let Some(transaction_id) = bracket.transaction_id else {
        return Ok(json!({
            "bracketed": false,
            "staged": bracket.staged,
            "reason": bracket.reason,
        }));
    };
    let tool = if succeeded {
        "kin_transaction_commit"
    } else {
        "kin_transaction_abort"
    };
    let outcome = mcp.call_tool(tool, &json!({ "transaction_id": transaction_id }));
    let (is_error, detail) = match &outcome {
        Ok(outcome) => (outcome.is_error, truncate(&outcome.text, 300)),
        Err(err) => (true, err.to_string()),
    };
    writer.trace(json!({
        "surface": "kin",
        "tool": tool,
        "policy": "allowed",
        "event": if succeeded { "transaction_commit" } else { "transaction_abort" },
        "transaction_id": transaction_id,
        "is_error": is_error,
        "detail": detail,
    }))?;
    Ok(json!({
        "bracketed": true,
        "staged": bracket.staged,
        "transaction_id": transaction_id,
        "closed_with": tool,
        "closed_cleanly": !is_error,
        // The server's own answer to the close, kept whether it accepted or refused, so a
        // run's evidence is what the daemon said rather than the harness's summary of it.
        "response": detail.clone(),
        "detail": if is_error { Value::String(detail) } else { Value::Null },
    }))
}

fn extract_id(outcome: &ToolOutcome, keys: &[&str]) -> Option<String> {
    let payload: Value = serde_json::from_str(outcome.text.trim()).ok()?;
    let object = payload.as_object()?;
    for key in keys {
        if let Some(Value::String(value)) = object.get(*key) {
            return Some(value.clone());
        }
    }
    // Some handlers nest the identity one level down.
    for nested in ["session", "transaction", "result"] {
        if let Some(inner) = object.get(nested).and_then(Value::as_object) {
            for key in keys {
                if let Some(Value::String(value)) = inner.get(*key) {
                    return Some(value.clone());
                }
            }
        }
    }
    None
}

fn truncate(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    text.chars().take(limit).collect::<String>() + "..."
}

#[allow(clippy::too_many_arguments)]
fn finish(
    mut writer: TranscriptWriter,
    config: &AgentConfig,
    status: ExitStatus,
    stop_reason: &str,
    final_text: &str,
    counters: Counters,
    started: Instant,
    _reserved: Option<()>,
) -> anyhow::Result<RunOutcome> {
    let record = writer.result(
        status.subtype(),
        status != ExitStatus::Success,
        counters.turns,
        started.elapsed().as_millis(),
        counters.api_ms,
        final_text,
        counters.usage_json(),
        counters.to_json(status.code(), stop_reason),
    )?;
    std::fs::write(
        config.out_dir.join("result.json"),
        serde_json::to_string_pretty(&record)?,
    )?;
    Ok(RunOutcome {
        status,
        final_text: final_text.to_string(),
        transcript_path: config.out_dir.join("transcript.jsonl"),
        trace_path: config.out_dir.join("kin-trace.jsonl"),
        result: record,
    })
}

/// Used by `kin agent doctor` to prove the MCP side answers.
pub fn probe_mcp(
    argv: &[String],
    repo: &Path,
    timeout: Duration,
) -> Result<Vec<String>, crate::mcp::McpError> {
    let mut client = McpClient::start(argv, repo, timeout)?;
    Ok(client
        .list_tools()?
        .into_iter()
        .map(|tool| tool.name)
        .collect())
}

/// Timestamp helper re-exported so callers can stamp their own records the same way.
pub fn timestamp() -> String {
    now_iso()
}
