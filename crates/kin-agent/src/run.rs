// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The agent loop.

use crate::belt::{self, Belt, LocalTool, Route};
use crate::context::{self, ContextMeter};
use crate::mcp::{McpClient, McpError, McpTool, ToolOutcome};
use crate::parse::{self, Turn};
use crate::provider::{Completion, Provider, ProviderError, Usage};
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
already tracks is staged as Kin's replace operation, carrying that path and the file's \
complete new text as your edit left it, and committed the same way.

Your tools are the mcp__kin__ ones named above plus edit_file and write_file. You have no \
others.

Work in small steps. Call one or two tools, read what came back, then decide. When you have \
the answer, say it in plain text without calling a tool.";

/// One attached graph server and the repository it serves.
///
/// A run holds one of these per repository. Everything that has to reach a particular
/// graph goes through the server that owns the path, which is what keeps a two-repository
/// run from committing one repository's change into the other's graph.
struct Server {
    /// `None` for a single-server run, whose tools keep the historical `mcp__kin__`
    /// prefix. `Some(label)` once several are attached and they must be told apart.
    label: Option<String>,
    repo: std::path::PathBuf,
    client: McpClient,
    declared: Vec<McpTool>,
    session: Option<String>,
}

impl Server {
    /// How this server is named in the trace.
    fn name(&self) -> String {
        match &self.label {
            None => "kin".to_string(),
            Some(label) => format!("kin_{label}"),
        }
    }

    /// Whether this server declares a tool by that exact name.
    fn declares(&self, tool: &str) -> bool {
        self.declared.iter().any(|declared| declared.name == tool)
    }
}

/// What the model is told about paths once a run attaches several repositories.
fn repo_path_note(repos: &[std::path::PathBuf]) -> String {
    let primary = repos
        .first()
        .map(|repo| repo.display().to_string())
        .unwrap_or_default();
    let others: Vec<String> = repos
        .iter()
        .skip(1)
        .map(|repo| repo.display().to_string())
        .collect();
    format!(
        "This run has {} repositories attached. A relative path is read inside the primary \
         repository at {primary}. To change a file in {}, give its absolute path.",
        repos.len(),
        others.join(" or ")
    )
}

struct Counters {
    tool_calls: u32,
    kin_calls: u32,
    local_calls: u32,
    refused_calls: u32,
    /// Local edits whose transaction the daemon refused to publish. A run holding one of
    /// these wrote files and landed nothing, which must not read as a success.
    unpublished_changes: u32,
    repairs: u32,
    unsafe_absence_events: u32,
    unreadable_results: u32,
    /// Results cut to the per-result ceiling before the model saw them.
    clipped_results: u32,
    /// Results the conversation could not hold, replaced by a note saying so.
    withheld_results: u32,
    /// Calls in a turn's batch that were never run because a budget was spent part way.
    skipped_calls: u32,
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
            unpublished_changes: 0,
            repairs: 0,
            unsafe_absence_events: 0,
            unreadable_results: 0,
            clipped_results: 0,
            withheld_results: 0,
            skipped_calls: 0,
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

    fn to_json(&self, exit_code: i32, stop: &Stop) -> Value {
        json!({
            "exit_code": exit_code,
            "stop_reason": stop.reason,
            "stop_detail": stop.detail,
            "tool_calls": self.tool_calls,
            "kin_calls": self.kin_calls,
            "local_calls": self.local_calls,
            "refused_calls": self.refused_calls,
            "unpublished_changes": self.unpublished_changes,
            "repairs": self.repairs,
            "unsafe_absence_events": self.unsafe_absence_events,
            "unreadable_results": self.unreadable_results,
            "clipped_results": self.clipped_results,
            "withheld_results": self.withheld_results,
            "skipped_calls": self.skipped_calls,
            "files_changed": self.edits,
        })
    }
}

/// Why a run stopped, as the result record states it.
struct Stop {
    status: ExitStatus,
    /// A short stable token an analyzer can match on.
    reason: String,
    /// The same reason in a sentence, with the numbers that decided it.
    detail: Option<String>,
}

impl Stop {
    fn new(status: ExitStatus, reason: &str, detail: Option<String>) -> Self {
        Stop {
            status,
            reason: reason.to_string(),
            detail,
        }
    }

    fn deadline(config: &AgentConfig, when: &str) -> Self {
        Stop::new(
            ExitStatus::Deadline,
            "deadline",
            Some(format!(
                "the run reached its {} s deadline {when}",
                config.deadline.as_secs()
            )),
        )
    }
}

/// The budgets that end a run with a forced, tool-free final answer.
#[derive(Clone, Copy)]
enum Spent {
    ToolCalls,
    Context,
}

/// Why a turn got no completion.
enum EndpointStop {
    /// The run's deadline passed before the endpoint answered.
    Deadline { waited: Duration },
    /// The endpoint failed in its own right.
    Failed(ProviderError),
}

/// Run one task to completion.
pub fn run(config: AgentConfig) -> anyhow::Result<RunOutcome> {
    let started = Instant::now();
    let session_id = uuid::Uuid::new_v4().to_string();
    let mut writer = TranscriptWriter::create(&config.out_dir, &session_id)?;
    let mut counters = Counters::new();

    // Every wait in the run, the endpoint's included, is measured against this one instant.
    let deadline_at = started + config.deadline;
    let result_ceiling = config.result_ceiling();

    let agent_meta = json!({
        "base_url": config.provider.base_url,
        "max_tool_calls": config.max_tool_calls,
        "deadline_s": config.deadline.as_secs(),
        "context_tokens": config.context.tokens,
        "context_source": config.context.source.label(),
        "max_result_bytes": result_ceiling,
        "tool_profile": config.tool_profile.clone().unwrap_or_else(|| "server-default".into()),
        "policy": "no-shell-no-file-search",
        "mcp_command": config.mcp_command.join(" "),
    });

    // Connect to Kin first. A run that could not attach must be loud, not quietly scored.
    // One server per repository, primary first, each spawned in the tree it serves.
    let wanted = config.servers();
    let multi = wanted.len() > 1;
    let mut servers: Vec<Server> = Vec::new();
    let mut taken: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for spec in &wanted {
        let attach = |err: McpError| {
            if multi {
                format!("{err} (serving {})", spec.repo.display())
            } else {
                err.to_string()
            }
        };
        let mut client = match McpClient::start(&spec.mcp_command, &spec.repo, config.mcp_timeout) {
            Ok(client) => client,
            Err(err) => {
                let message = attach(err);
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
                    Stop::new(ExitStatus::McpError, "the MCP server did not start", None),
                    &message,
                    counters,
                    started,
                    None,
                );
            }
        };
        let declared = match client.list_tools() {
            Ok(tools) => tools,
            Err(err) => {
                let message = attach(err);
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
                    Stop::new(
                        ExitStatus::McpError,
                        "the MCP server did not list its tools",
                        None,
                    ),
                    &message,
                    counters,
                    started,
                    None,
                );
            }
        };
        // A single-server run carries no label, so its tools keep the historical
        // `mcp__kin__` prefix and its transcript stays what the analyzers already read.
        let label = if multi {
            let label = belt::server_label(&spec.repo, &taken);
            taken.insert(label.clone());
            Some(label)
        } else {
            None
        };
        servers.push(Server {
            label,
            repo: spec.repo.clone(),
            client,
            declared,
            session: None,
        });
    }

    let mut kin_tools: Vec<belt::KinTool> = Vec::new();
    for (index, server) in servers.iter().enumerate() {
        let prefix = belt::tool_prefix(server.label.as_deref());
        for tool in &server.declared {
            if belt::is_harness_owned(&tool.name) {
                continue;
            }
            kin_tools.push(belt::KinTool {
                server: index,
                bare: tool.name.clone(),
                exposed: format!("{prefix}{}", tool.name),
                description: tool.description.clone(),
                schema: tool.input_schema.clone(),
            });
        }
    }
    let belt = Belt::new(kin_tools);
    let repo_roots: Vec<std::path::PathBuf> =
        servers.iter().map(|server| server.repo.clone()).collect();
    let repo_note = multi.then(|| repo_path_note(&repo_roots));
    let specs = belt.to_specs(repo_note.as_deref());
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

    // Open a Kin session per server, so every mutation this run makes names this agent
    // rather than an anonymous file write. A server without the tool is not an error; it
    // just means the provenance bracket is unavailable there and the trace says so.
    for server in servers.iter_mut() {
        let session = start_kin_session(server, &config, &mut writer)?;
        server.session = session;
    }

    let mut system_prompt = config
        .system_prompt
        .clone()
        .unwrap_or_else(|| DEFAULT_SYSTEM_PROMPT.to_string());
    // The repository roots are a fact about this run that the model cannot infer, and
    // without them it cannot address the second repository at all, so the note is appended
    // to an operator-supplied prompt as well as to the built-in one.
    if let Some(note) = repo_note.as_deref() {
        let roots = repo_roots
            .iter()
            .map(|repo| repo.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        system_prompt.push_str(&format!(
            "\n\nThe repositories attached to this run are: {roots}. Each has its own Kin \
             graph, and its tools carry that repository's own prefix, so read the tool names \
             you were given and call the one belonging to the repository you mean. {note}"
        ));
    }
    // The first request carries the system prompt, the task and every tool spec, and the
    // meter reads their size until the endpoint reports a count of its own.
    let baseline_bytes = system_prompt.len()
        + config.task.len()
        + serde_json::to_vec(&specs).map_or(0, |bytes| bytes.len());
    let mut meter = ContextMeter::new(config.context, baseline_bytes as u64);
    let mut messages = vec![
        json!({ "role": "system", "content": system_prompt }),
        json!({ "role": "user", "content": config.task }),
    ];

    let mut next_tool_id = 0u64;
    let mut consecutive_unusable = 0u32;
    let mut surfaced_degraded = false;
    // Set when a result was withheld because the conversation could not hold it.
    let mut context_note: Option<String> = None;
    let mut final_text = String::new();
    let mut stop = Stop::new(ExitStatus::Success, "final_answer", None);

    loop {
        if Instant::now() >= deadline_at {
            stop = Stop::deadline(&config, "before the next turn");
            break;
        }
        let spent = if counters.tool_calls >= config.max_tool_calls {
            Some(Spent::ToolCalls)
        } else if context_note.is_some() || !meter.has_room_for_a_turn() {
            Some(Spent::Context)
        } else {
            None
        };
        if let Some(spent) = spent {
            // A budget is spent. Ask for an answer with nothing to call, so the run ends
            // with what the model actually learned rather than with silence.
            let (spent_stop, prompt) = budget_stop(
                spent,
                &config,
                &meter,
                context_note.as_deref(),
                counters.turns,
            );
            stop = spent_stop;
            if matches!(spent, Spent::Context) && counters.turns == 0 {
                // The first request alone does not fit, so nothing was learned to ask for.
                break;
            }
            if !meter.fits_a_final_request(prompt.len() as u64) {
                final_text = "(no final answer: the conversation no longer fits the model's \
                              context window)"
                    .to_string();
                break;
            }
            meter.add(prompt.len() as u64);
            messages.push(json!({ "role": "user", "content": prompt }));
            match complete_with_retry(&provider, &messages, &[], &mut counters, deadline_at) {
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
                Err(EndpointStop::Deadline { waited }) => {
                    stop = Stop::deadline(
                        &config,
                        &format!("while waiting {} s for the final answer", waited.as_secs()),
                    );
                }
                Err(EndpointStop::Failed(err)) => {
                    final_text = format!("(no final answer: {err})");
                }
            }
            break;
        }

        let completion =
            match complete_with_retry(&provider, &messages, &specs, &mut counters, deadline_at) {
                Ok(completion) => completion,
                Err(EndpointStop::Deadline { waited }) => {
                    stop = Stop::deadline(
                        &config,
                        &format!("while waiting {} s on the endpoint", waited.as_secs()),
                    );
                    break;
                }
                Err(EndpointStop::Failed(err)) => {
                    stop = Stop::new(
                        ExitStatus::EndpointError,
                        "endpoint_unreachable",
                        Some(err.to_string()),
                    );
                    final_text = err.to_string();
                    break;
                }
            };
        counters.absorb(&completion.usage);
        counters.turns += 1;
        meter.anchor(&completion.usage, message_bytes(&completion.choice));
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
                stop = Stop::new(ExitStatus::Success, "final_answer", None);
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
                    // Named apart from an unreachable endpoint on purpose: a model that
                    // cannot hold the tool protocol is a model failure, and a run that
                    // died this way must never be scored as a task the toolset failed.
                    stop = Stop::new(
                        ExitStatus::EndpointError,
                        "model_format_failure",
                        Some(reason.clone()),
                    );
                    final_text = text;
                    break;
                }
                counters.repairs += 1;
                let repair = format!(
                    "That turn could not be used: {reason}. Either call one tool using the \
                     tool-calling format, or answer in plain text. Do not describe a tool \
                     call in prose."
                );
                meter.add(repair.len() as u64);
                messages.push(json!({ "role": "assistant", "content": text }));
                messages.push(json!({ "role": "user", "content": repair }));
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
                    // A budget spent part way through a batch runs nothing more of it, and
                    // every call still gets an answer so the conversation stays well formed.
                    let skipped_because = if counters.tool_calls >= config.max_tool_calls {
                        Some(format!(
                            "this run's budget of {} tool calls is spent",
                            config.max_tool_calls
                        ))
                    } else if context_note.is_some() {
                        Some("the conversation has reached the model's context window".to_string())
                    } else {
                        None
                    };
                    if let Some(why) = skipped_because {
                        counters.skipped_calls += 1;
                        let text = format!(
                            "[kin agent] This call was not run: {why}. Answer with what you \
                             have learned."
                        );
                        writer.trace(json!({
                            "tool_use_id": call.id,
                            "surface": "policy",
                            "tool": call.name,
                            "args": redact_content(&call.arguments),
                            "policy": "skipped",
                            "reason": why,
                            "is_error": true,
                        }))?;
                        writer.tool_result(&call.id, &text, true)?;
                        meter.add(text.len() as u64);
                        messages.push(json!({
                            "role": "tool",
                            "tool_call_id": call.id,
                            "content": text,
                        }));
                        continue;
                    }
                    counters.tool_calls += 1;
                    let route = belt.route(&call.name);
                    // A local tool's answer says whether a change landed, which the model must
                    // hear, and it is small; only a Kin answer is ever withheld for size.
                    let from_kin = matches!(route, Route::Kin { .. });
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
                        Route::Kin {
                            server: server_index,
                            tool: name,
                        } => {
                            let server_name = servers[server_index].name();
                            match check_arguments(&belt, &call.name, &call.arguments) {
                                Err(problem) => {
                                    counters.repairs += 1;
                                    writer.trace(json!({
                                        "tool_use_id": call.id,
                                        "surface": "kin",
                                        "server": server_name,
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
                                    let outcome = servers[server_index]
                                        .client
                                        .call_tool(&name, &call.arguments);
                                    match outcome {
                                        Err(err) => {
                                            // The server died or stopped answering. Nothing
                                            // downstream can be trusted, so stop here.
                                            writer.trace(json!({
                                                "tool_use_id": call.id,
                                                "surface": "kin",
                                                "server": server_name,
                                                "tool": name,
                                                "args": call.arguments,
                                                "policy": "allowed",
                                                "is_error": true,
                                                "transport_error": err.to_string(),
                                            }))?;
                                            writer.tool_result(&call.id, &err.to_string(), true)?;
                                            final_text = err.to_string();
                                            return finish(
                                                writer,
                                                &config,
                                                Stop::new(
                                                    ExitStatus::McpError,
                                                    "mcp_transport",
                                                    Some(err.to_string()),
                                                ),
                                                &final_text,
                                                counters,
                                                started,
                                                Some(&meter),
                                            );
                                        }
                                        Ok(mut outcome) => {
                                            counters.kin_calls += 1;
                                            if outcome.unreadable {
                                                counters.unreadable_results += 1;
                                            }
                                            // Cut before the notes are appended, so what Kin
                                            // said about its own answer is never the part cut.
                                            let result_bytes = outcome.text.len();
                                            let mut shown_bytes = result_bytes;
                                            if result_bytes > result_ceiling {
                                                counters.clipped_results += 1;
                                                let advice = context::how_to_ask_for_less(
                                                    belt.schema_for(&call.name).as_ref(),
                                                );
                                                let shown = context::clip_result(
                                                    std::mem::take(&mut outcome.text),
                                                    result_ceiling,
                                                    &advice,
                                                );
                                                shown_bytes = shown.shown_bytes;
                                                outcome.text = shown.text;
                                            }
                                            let annotated = annotate(
                                                &outcome,
                                                &mut counters,
                                                &mut surfaced_degraded,
                                            );
                                            writer.trace(json!({
                                                "tool_use_id": call.id,
                                                "surface": "kin",
                                                "server": server_name,
                                                "tool": name,
                                                "args": call.arguments,
                                                "wall_ms": outcome.wall_ms as u64,
                                                "is_error": outcome.is_error,
                                                "policy": "allowed",
                                                "call_shape": call.shape.as_str(),
                                                "envelope": outcome.envelope_summary(),
                                                "negative": negative_summary(&outcome),
                                                "unreadable": outcome.unreadable,
                                                "result_bytes": result_bytes,
                                                "shown_bytes": shown_bytes,
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
                                    // Which repository owns the path decides which graph
                                    // the change is staged into, so it is resolved before
                                    // anything is written. A path that belongs to no
                                    // attached repository runs nothing at all.
                                    let raw_path = call
                                        .arguments
                                        .get("path")
                                        .and_then(Value::as_str)
                                        .unwrap_or("");
                                    match belt::resolve_across_repos(&repo_roots, raw_path) {
                                        Err(problem) => {
                                            writer.trace(json!({
                                                "tool_use_id": call.id,
                                                "surface": "local",
                                                "tool": call.name,
                                                "args": redact_content(&call.arguments),
                                                "policy": "allowed",
                                                "call_shape": call.shape.as_str(),
                                                "problem": problem,
                                                "is_error": true,
                                            }))?;
                                            (problem, true)
                                        }
                                        Ok((index, resolved)) => {
                                            let repo = servers[index].repo.clone();
                                            let session = servers[index].session.clone();
                                            let server_name = servers[index].name();
                                            // The plan is made before the tool runs,
                                            // because `write_file` is what makes a new
                                            // path exist and afterwards nothing can tell a
                                            // create from an overwrite.
                                            let plan = plan_stage(&repo, tool, &call.arguments);
                                            let mut bracket = begin_transaction(
                                                &mut servers[index],
                                                session.as_deref(),
                                                &call.arguments,
                                                &plan,
                                                &mut writer,
                                            )?;
                                            // Repository authority writes a created file
                                            // itself as part of publishing the change. So
                                            // a create is published FIRST and the local
                                            // write is the fallback: writing it here
                                            // first leaves an untracked path sitting on
                                            // the exact workspace target, which
                                            // `validate_reconciliation_targets` refuses,
                                            // and every commit fails on the harness's own
                                            // file.
                                            let publish_first = bracket.transaction_id.is_some()
                                                && matches!(plan, StagePlan::Create { .. });
                                            let (outcome, provenance) = if publish_first {
                                                let staged = stage_planned_operation(
                                                    &mut servers[index],
                                                    &mut bracket,
                                                    session.as_deref(),
                                                    &plan,
                                                    None,
                                                    &mut writer,
                                                )?;
                                                let provenance = close_transaction(
                                                    &mut servers[index],
                                                    bracket,
                                                    staged,
                                                    &mut writer,
                                                )?;
                                                if published_by_authority(&provenance) {
                                                    (
                                                        belt::published_create(&call.arguments),
                                                        provenance,
                                                    )
                                                } else {
                                                    // Nothing was published, so the file
                                                    // does not exist yet. Write it, so the
                                                    // model keeps its work, and tell the
                                                    // model the change did not land rather
                                                    // than reporting a bare success.
                                                    counters.unpublished_changes += 1;
                                                    let mut outcome =
                                                        belt::run_write(&repo, &call.arguments);
                                                    if !outcome.is_error {
                                                        outcome.text = format!(
                                                            "{} Repository authority did \
                                                             not publish it: {}. The file \
                                                             is on disk and uncommitted.",
                                                            outcome.text,
                                                            unpublished_reason(&provenance),
                                                        );
                                                    }
                                                    (outcome, provenance)
                                                }
                                            } else {
                                                let mut outcome = match tool {
                                                    LocalTool::Edit => {
                                                        belt::run_edit(&repo, &call.arguments)
                                                    }
                                                    LocalTool::Write => {
                                                        belt::run_write(&repo, &call.arguments)
                                                    }
                                                };
                                                // Stage what the harness just did, inside
                                                // the open bracket, so the commit below
                                                // has something to publish. An empty
                                                // transaction is refused by design.
                                                let staged = if outcome.is_error {
                                                    false
                                                } else {
                                                    stage_planned_operation(
                                                        &mut servers[index],
                                                        &mut bracket,
                                                        session.as_deref(),
                                                        &plan,
                                                        outcome.body.as_deref(),
                                                        &mut writer,
                                                    )?
                                                };
                                                let wanted_publication =
                                                    !outcome.is_error && staged;
                                                let provenance = close_transaction(
                                                    &mut servers[index],
                                                    bracket,
                                                    wanted_publication,
                                                    &mut writer,
                                                )?;
                                                if wanted_publication
                                                    && !published_by_authority(&provenance)
                                                {
                                                    counters.unpublished_changes += 1;
                                                    // The model has to hear this. A bare
                                                    // success reads as "the edit reached
                                                    // the graph", and it did not: the
                                                    // change is on disk and the
                                                    // transaction aborted. The create
                                                    // branch has said so since kin#1082,
                                                    // and this branch had no traffic at
                                                    // all until an edit could stage.
                                                    if !outcome.is_error {
                                                        outcome.text = format!(
                                                            "{} Repository authority did \
                                                             not publish it: {}. The \
                                                             change is on disk and \
                                                             uncommitted.",
                                                            outcome.text,
                                                            unpublished_reason(&provenance),
                                                        );
                                                    }
                                                }
                                                (outcome, provenance)
                                            };
                                            if let Some(path) = outcome.changed.clone() {
                                                // With several repositories attached the
                                                // same relative path exists in more than
                                                // one, so the record is absolute or it
                                                // names nothing in particular.
                                                let recorded = if multi {
                                                    resolved.display().to_string()
                                                } else {
                                                    path
                                                };
                                                if !counters.edits.contains(&recorded) {
                                                    counters.edits.push(recorded);
                                                }
                                            }
                                            writer.trace(json!({
                                                "tool_use_id": call.id,
                                                "surface": "local",
                                                "server": server_name,
                                                "repo": repo.display().to_string(),
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
                            }
                        }
                    };

                    // A result the conversation cannot hold is withheld and the model told so,
                    // rather than sent for the endpoint to cut the conversation to fit.
                    let (result_text, is_error) =
                        if from_kin && !meter.fits(result_text.len() as u64) {
                            counters.withheld_results += 1;
                            let window = meter.window();
                            context_note = Some(format!(
                                "a {}-byte result from {} would have left less than the {} \
                                 tokens kept for the answer in the model's {}-token window \
                                 ({}), so it was withheld",
                                result_text.len(),
                                call.name,
                                meter.reserve(),
                                window.tokens,
                                window.source.label()
                            ));
                            writer.trace(json!({
                                "tool_use_id": call.id,
                                "surface": "policy",
                                "tool": call.name,
                                "policy": "withheld",
                                "result_bytes": result_text.len(),
                                "context": meter.to_json(),
                                "is_error": true,
                            }))?;
                            (context::withheld_note(result_text.len(), &meter), true)
                        } else {
                            (result_text, is_error)
                        };
                    writer.tool_result(&call.id, &result_text, is_error)?;
                    meter.add(result_text.len() as u64);
                    messages.push(json!({
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": result_text,
                    }));

                    if Instant::now() >= deadline_at {
                        stop = Stop::deadline(&config, "after a tool call");
                        break;
                    }
                }
                if stop.status == ExitStatus::Deadline {
                    break;
                }
            }
        }
    }

    for server in servers.iter_mut() {
        end_kin_session(server, &mut writer)?;
    }
    finish(
        writer,
        &config,
        stop,
        &final_text,
        counters,
        started,
        Some(&meter),
    )
}

/// The stop a spent budget ends the run with, and the message that asks for the answer.
fn budget_stop(
    spent: Spent,
    config: &AgentConfig,
    meter: &ContextMeter,
    withheld: Option<&str>,
    turns: u32,
) -> (Stop, String) {
    const ASK: &str = "Do not call any more tools. Answer now in plain text with what you have \
                       learned, and say plainly what you were not able to determine.";
    match spent {
        Spent::ToolCalls => (
            Stop::new(
                ExitStatus::CapReached,
                "tool_call_cap",
                Some(format!(
                    "the run used its budget of {} tool calls",
                    config.max_tool_calls
                )),
            ),
            format!(
                "You have used your budget of {} tool calls. {ASK}",
                config.max_tool_calls
            ),
        ),
        Spent::Context => {
            let window = meter.window();
            let detail = match withheld {
                Some(withheld) => withheld.to_string(),
                None if turns == 0 => format!(
                    "the first request needs about {} tokens, which leaves less than the {} kept \
                     for the answer in the model's {}-token window ({})",
                    meter.used(),
                    meter.reserve(),
                    window.tokens,
                    window.source.label()
                ),
                None => format!(
                    "the conversation holds about {} of the model's {} tokens ({}), which \
                     leaves less than the {} kept for the answer",
                    meter.used(),
                    window.tokens,
                    window.source.label(),
                    meter.reserve()
                ),
            };
            (
                Stop::new(ExitStatus::ContextBudget, "context_budget", Some(detail)),
                format!(
                    "This conversation has reached the model's context window: it holds about \
                     {} of {} tokens. {ASK}",
                    meter.used(),
                    window.tokens
                ),
            )
        }
    }
}

/// What one answer adds to the conversation, in bytes, for the budget.
fn message_bytes(choice: &Value) -> u64 {
    choice
        .get("message")
        .map_or(0, |message| message.to_string().len()) as u64
}

/// Append what Kin said about its own answer, so an untrusted absence cannot be read as
/// an absence and a degraded graph is stated once rather than silently.
fn annotate(
    outcome: &ToolOutcome,
    counters: &mut Counters,
    surfaced_degraded: &mut bool,
) -> String {
    let mut text = outcome.text.clone();
    // `claims_absence` first, and it is not a refinement. `safe_to_conclude_absent`
    // is false on every POPULATED answer, because no absence is being claimed
    // there, so this branch alone appended "This result is empty" to answers
    // carrying rows, told the model to treat them as unknown, and counted each
    // one as an unsafe absence event (FIR-2673 finding 1).
    if outcome.claims_absence() && outcome.safe_to_conclude_absent() == Some(false) {
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

/// Ask the endpoint for one turn, inside what is left of the run's deadline.
///
/// Every attempt carries the remaining budget as its timeout, and a retry never starts once
/// the budget is gone, so a slow endpoint ends the wait at the deadline rather than
/// stretching the run by a full request timeout per attempt. A failure that lands after the
/// deadline is the deadline's, whatever the transport said.
fn complete_with_retry(
    provider: &Provider,
    messages: &[Value],
    tools: &[Value],
    counters: &mut Counters,
    deadline_at: Instant,
) -> Result<Completion, EndpointStop> {
    let began = Instant::now();
    let mut last: Option<ProviderError> = None;
    for attempt in 0..ENDPOINT_ATTEMPTS {
        let remaining = deadline_at.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(EndpointStop::Deadline {
                waited: began.elapsed(),
            });
        }
        let limit = remaining.min(provider.config().request_timeout);
        let asked = Instant::now();
        let outcome = provider.complete_within(messages, tools, limit);
        // Time spent waiting is endpoint time whether or not an answer came back.
        counters.api_ms += asked.elapsed().as_millis();
        match outcome {
            Ok(completion) => return Ok(completion),
            Err(err) => {
                if Instant::now() >= deadline_at {
                    return Err(EndpointStop::Deadline {
                        waited: began.elapsed(),
                    });
                }
                // A rejected request will be rejected again; only a transport hiccup is
                // worth a second try.
                let retryable = matches!(err, ProviderError::Transport { .. });
                last = Some(err);
                if !retryable || attempt + 1 == ENDPOINT_ATTEMPTS {
                    break;
                }
                let pause = Duration::from_millis(500 * (attempt as u64 + 1))
                    .min(deadline_at.saturating_duration_since(Instant::now()));
                std::thread::sleep(pause);
            }
        }
    }
    Err(EndpointStop::Failed(
        last.expect("at least one attempt was made"),
    ))
}

fn start_kin_session(
    server: &mut Server,
    config: &AgentConfig,
    writer: &mut TranscriptWriter,
) -> anyhow::Result<Option<String>> {
    let server_name = server.name();
    if !server.declares("kin_session_start") {
        writer.trace(json!({
            "surface": "policy",
            "server": server_name,
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
        "cwd": server.repo.display().to_string(),
        "capabilities": { "can_read": true, "can_write": true, "can_commit": true },
    });
    match server.client.call_tool("kin_session_start", &arguments) {
        Ok(outcome) => {
            let session = extract_id(&outcome, &["session_id", "id"]);
            writer.trace(json!({
                "surface": "kin",
                "server": server_name,
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
                "server": server_name,
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

fn end_kin_session(server: &mut Server, writer: &mut TranscriptWriter) -> anyhow::Result<()> {
    let Some(session) = server.session.clone() else {
        return Ok(());
    };
    if !server.declares("kin_session_end") {
        return Ok(());
    }
    let server_name = server.name();
    let outcome = server
        .client
        .call_tool("kin_session_end", &json!({ "session_id": session }));
    writer.trace(json!({
        "surface": "kin",
        "server": server_name,
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
/// `kin_transaction_stage` admits several disjoint shapes (`crates/kin-mcp/src/tools.rs`),
/// and two of them are keyed on a repository-relative path plus the file's whole text: the
/// new source file, verb `create`, and the rewritten one, verb `replace`. Between them they
/// cover both local tools, because a path and a complete body is exactly what a local write
/// or edit leaves the harness holding. The entity-keyed `update` shape resolves its target
/// against repository authority as an entity uuid or an exact entity name
/// (`kin_mcp::handlers::sessions::resolve_target_entity`), which a text splice does not
/// know, so the harness never plans that one. A transaction with nothing in it is refused
/// by design, so an unstageable call opens no transaction at all and the trace says why.
enum StagePlan {
    /// Admit the file at this repository-relative path with this body. Repository
    /// authority refuses it by name if it already tracks the path.
    Create { target: String, body: String },
    /// Rewrite the tracked file at this repository-relative path from its complete new
    /// text. The body is deliberately not carried here: an edit's new text does not exist
    /// until the edit has run, and this plan is made before it, so the body is read from
    /// the file the harness just wrote. Repository authority refuses the operation by name
    /// if it does not already track the path.
    Replace { target: String },
    /// Nothing the stage surface admits fits this call, and this is the reason.
    Unstageable { reason: String },
}

/// Decide what to stage for one local tool call.
///
/// Whether the path is new is repository authority's question, not the filesystem's, and
/// the two answers differ: a path can sit on disk untracked, or be tracked with nothing on
/// disk yet. So the harness plans the create for a write and the replace for an edit, and
/// lets the daemon refuse either by name when the graph disagrees about whether it holds
/// that path, which is the rule both verbs document. Probing the disk here would put a
/// filesystem heuristic on the runtime path to answer a question the graph owns.
fn plan_stage(repo: &Path, tool: LocalTool, arguments: &Value) -> StagePlan {
    let raw_path = arguments.get("path").and_then(Value::as_str).unwrap_or("");
    match tool {
        LocalTool::Edit => {
            let path = match belt::resolve_in_repo(repo, raw_path) {
                Ok(path) => path,
                Err(problem) => return StagePlan::Unstageable { reason: problem },
            };
            match repository_relative(repo, &path) {
                Some(target) => StagePlan::Replace { target },
                None => StagePlan::Unstageable {
                    reason: "the path did not reduce to a repository-relative target".into(),
                },
            }
        }
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
    server: &mut Server,
    session: Option<&str>,
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
        if !server.declares(required) {
            return Ok(Bracket::unopened(format!(
                "the server does not expose {required}"
            )));
        }
    }
    let server_name = server.name();
    let scope = arguments
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("repository")
        .to_string();
    match server.client.call_tool(
        "kin_transaction_begin",
        &json!({ "session_id": session, "scope": scope }),
    ) {
        Ok(outcome) if !outcome.is_error => {
            let transaction_id = extract_id(&outcome, &["transaction_id", "id"]);
            writer.trace(json!({
                "surface": "kin",
                "server": server_name,
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
                "server": server_name,
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
    server: &mut Server,
    bracket: &mut Bracket,
    session: Option<&str>,
    plan: &StagePlan,
    produced: Option<&str>,
    writer: &mut TranscriptWriter,
) -> anyhow::Result<bool> {
    let server_name = server.name();
    let Some(transaction_id) = bracket.transaction_id.clone() else {
        return Ok(false);
    };
    // A create carries the body the model sent, because the file does not exist yet and
    // repository authority is what writes it. A replace carries the file's complete new
    // text, which only exists once the edit has run, so it comes from the tool that just
    // ran rather than from the plan that was made before it.
    let (verb, target, body) = match plan {
        StagePlan::Create { target, body } => ("create", target.clone(), body.clone()),
        StagePlan::Replace { target } => match produced {
            Some(body) if !body.is_empty() => ("replace", target.clone(), body.to_string()),
            _ => {
                // Nothing is staged, so the bracket aborts rather than committing an empty
                // transaction, and the provenance says so instead of going quiet.
                let detail = format!("the edit of {target} produced no text to admit to the graph");
                writer.trace(json!({
                    "surface": "kin",
                    "server": server_name,
                    "tool": "kin_transaction_stage",
                    "policy": "allowed",
                    "event": "transaction_stage",
                    "transaction_id": transaction_id,
                    "verb": "replace",
                    "target": target,
                    "is_error": true,
                    "detail": detail.clone(),
                }))?;
                bracket.staged = Some(json!({
                    "verb": "replace",
                    "target": target,
                    "accepted": false,
                    "detail": detail,
                }));
                return Ok(false);
            }
        },
        StagePlan::Unstageable { .. } => return Ok(false),
    };
    let operation = json!({
        "verb": verb,
        "target": target,
        "body": body,
        "description": match verb {
            "replace" => format!("kin agent rewrote {target}"),
            _ => format!("kin agent created {target}"),
        },
    });
    let mut arguments = json!({
        "transaction_id": transaction_id,
        "operations": [operation],
    });
    if let Some(session) = session {
        arguments["session_id"] = Value::String(session.to_string());
    }
    let outcome = server.client.call_tool("kin_transaction_stage", &arguments);
    let (is_error, detail) = match &outcome {
        Ok(outcome) => (outcome.is_error, close_detail(&outcome.text)),
        Err(err) => (true, err.to_string()),
    };
    writer.trace(json!({
        "surface": "kin",
        "server": server_name,
        "tool": "kin_transaction_stage",
        "policy": "allowed",
        "event": "transaction_stage",
        "transaction_id": transaction_id,
        "verb": verb,
        "target": target,
        "body_bytes": body.len(),
        "is_error": is_error,
        "detail": detail,
    }))?;
    bracket.staged = Some(json!({
        "verb": verb,
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
    server: &mut Server,
    bracket: Bracket,
    succeeded: bool,
    writer: &mut TranscriptWriter,
) -> anyhow::Result<Value> {
    let server_name = server.name();
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
    let outcome = server
        .client
        .call_tool(tool, &json!({ "transaction_id": transaction_id }));
    let (is_error, detail) = match &outcome {
        Ok(outcome) => (outcome.is_error, close_detail(&outcome.text)),
        Err(err) => (true, err.to_string()),
    };
    writer.trace(json!({
        "surface": "kin",
        "server": server_name,
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

/// Whether repository authority actually published this bracket.
///
/// A clean close is not enough on its own: an abort closes cleanly too, and a run that
/// read `closed_cleanly` alone would score an aborted transaction as a landed change.
fn published_by_authority(provenance: &Value) -> bool {
    provenance["closed_with"] == json!("kin_transaction_commit")
        && provenance["closed_cleanly"] == json!(true)
}

/// What the server said when it declined to publish, in one line fit for the model.
fn unpublished_reason(provenance: &Value) -> String {
    for key in ["detail", "response", "reason"] {
        if let Some(text) = provenance.get(key).and_then(Value::as_str) {
            if !text.trim().is_empty() {
                return text.to_string();
            }
        }
    }
    "the server gave no reason".to_string()
}

/// Truncate a server answer for the trace, keeping the part that says what happened.
///
/// Every Kin answer carries a `_kin` envelope longer than the old 300-character budget, so
/// truncating the raw text spent the whole budget on the envelope and dropped the `message`
/// key entirely. The envelope is graph freshness, which the trace records elsewhere; the
/// failure reason is the thing a reader cannot reconstruct.
fn close_detail(text: &str) -> String {
    match serde_json::from_str::<Value>(text.trim()) {
        Ok(Value::Object(mut payload)) => {
            payload.remove("_kin");
            truncate(&Value::Object(payload).to_string(), 300)
        }
        _ => truncate(text, 300),
    }
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

fn finish(
    mut writer: TranscriptWriter,
    config: &AgentConfig,
    stop: Stop,
    final_text: &str,
    counters: Counters,
    started: Instant,
    meter: Option<&ContextMeter>,
) -> anyhow::Result<RunOutcome> {
    // A run that wrote files repository authority never published landed nothing, whatever
    // the model's closing paragraph says. Downgrading here rather than at each exit path
    // means no future exit can forget it. A run that stopped for its own reason keeps that
    // reason, which is more specific than this one.
    let status = if stop.status == ExitStatus::Success && counters.unpublished_changes > 0 {
        ExitStatus::ChangesUnpublished
    } else {
        stop.status
    };
    let mut agent = counters.to_json(status.code(), &stop);
    agent["max_result_bytes"] = json!(config.result_ceiling());
    // The budget as it stood when the run stopped, so a context stop can be read against
    // the numbers that decided it.
    agent["context"] = meter.map_or(Value::Null, ContextMeter::to_json);
    let record = writer.result(
        status.subtype(),
        status != ExitStatus::Success,
        counters.turns,
        started.elapsed().as_millis(),
        counters.api_ms,
        final_text,
        counters.usage_json(),
        agent,
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

#[cfg(test)]
mod annotate_tests {
    use super::*;
    use crate::mcp::ToolOutcome;

    fn outcome(text: &str, negative: Value) -> ToolOutcome {
        ToolOutcome {
            text: text.to_string(),
            is_error: false,
            envelope: None,
            negative: Some(negative),
            unreadable: false,
            wall_ms: 1,
        }
    }

    const EMPTY_WARNING: &str = "This result is empty";

    /// FIR-2673 finding 1. A populated answer is not an absence claim, and the
    /// warning that says it is must not reach the model.
    ///
    /// `safe_to_conclude_absent` is false here, and that is CORRECT: no absence
    /// is being claimed, so none can be concluded. Reading that `false` as "the
    /// absence cannot be trusted" appended "This result is empty" to an answer
    /// carrying rows, told the model to treat it as unknown and not to answer
    /// another way, and counted it as an unsafe absence event.
    #[test]
    fn a_populated_answer_is_never_told_it_is_empty() {
        let mut counters = Counters::new();
        let mut surfaced = false;
        let annotated = annotate(
            &outcome(
                "3 rows",
                json!({
                    "safe_to_conclude_absent": false,
                    "interpretation": "qualified_answer",
                    "result_count": 3,
                    "limiting_factor": "python bodies are not indexed",
                }),
            ),
            &mut counters,
            &mut surfaced,
        );
        assert!(
            !annotated.contains(EMPTY_WARNING),
            "a populated answer was told it was empty: {annotated}"
        );
        assert_eq!(
            counters.unsafe_absence_events, 0,
            "a populated answer counted as an unsafe absence"
        );
    }

    /// The control, and the half that stops the fix being "warn about nothing".
    /// A genuinely empty answer whose absence Kin refuses to trust must still
    /// get the warning and still be counted.
    #[test]
    fn an_untrusted_empty_answer_still_gets_the_warning() {
        let mut counters = Counters::new();
        let mut surfaced = false;
        let annotated = annotate(
            &outcome(
                "no rows",
                json!({
                    "safe_to_conclude_absent": false,
                    "interpretation": "absence_claimed",
                    "result_count": 0,
                    "limiting_factor": "python bodies are not indexed",
                }),
            ),
            &mut counters,
            &mut surfaced,
        );
        assert!(
            annotated.contains(EMPTY_WARNING),
            "an untrusted absence lost its warning: {annotated}"
        );
        assert!(
            annotated.contains("python bodies are not indexed"),
            "the warning must name the gap it was given: {annotated}"
        );
        assert_eq!(counters.unsafe_absence_events, 1);
    }
}
